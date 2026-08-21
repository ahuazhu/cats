//! Installed physical adapter for the checkpoint-first atomic `StartCat` machine.
//!
//! The shared Start handler journals [`InstalledAtomicStartPlatformPlan`] bytes
//! before this module may touch the Host.  Those bytes contain every random
//! identity, pathname, process unit, frontend, network reservation and VMM
//! launch coordinate used by one phase.  Recovery consequently discovers or
//! completes the same effect; it never replans from mutable Host state.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse, DurabilityStatus};
use cats_api::guest::{
    FilesystemControlOperationV1, FilesystemControlOutcomeV1, FilesystemControlRequestV1,
    FilesystemControlResponseV1, FilesystemIdentityV1, RuntimeReadyRequestV1,
    RuntimeReadyResponseV1, FILESYSTEM_CONTROL_MAX_TIMEOUT_MS_V1,
    GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1, GUEST_HOST_CONTROL_VSOCK_PORT_V1,
};
use cats_api::object_write_gateway::{
    encode_object_write_credential_registered_artifact, object_write_credential_id,
};
use cats_api::runtime_lifecycle::{
    DiskRole, LifecycleCommand, LifecycleCommandEnvelope, RuntimeNetworkConfig,
    RuntimeVolumeConfig, RuntimeVolumeGuestBinding, StartSource, VolumeTerminalReceipt,
};
use cats_api::runtime_lifecycle_volume::{
    validate_lifecycle_persistent_initialization_binding,
    validate_lifecycle_persistent_initialization_commit, LifecyclePersistentGuestFilesystemState,
    LifecyclePersistentInitializationBinding, LifecyclePersistentInitializationCommitRequest,
    LifecyclePersistentInitializationFlushDrainReceipt,
    LifecyclePersistentInitializationGuestProbe, LifecyclePersistentInitializationInspectRequest,
    LifecyclePersistentInitializationInspection, LifecyclePersistentInitializationState,
    LifecycleStoredPersistentInitializationCommit, LifecycleStoredStartVolumeGrant,
    LifecycleVolumeCommandScope, LifecycleVolumeDurabilityProof, LifecycleVolumeTarget,
};
use cats_api::runtime_reconciliation::{
    encode_provision_root_image_request, AcquireOrigin, AsciiText, ContractVersion,
    DirectAuthorizedAttachmentIdentity, DirectAuthorizedAttachmentPurpose, DiskKind,
    FilesystemInitialization, Generation, GuestDeviceIdentity, HostPath, Id, IsolatedIpv4Kind,
    MountAccess, NetworkConfig, PersistentFilesystemBinding, PrepareDeviceFrontend,
    PreparedDeviceInput, ProcessState, ProvisionRootImageRequest, ProvisionRootImageResult,
    RandomId128, RemoteHead, RuntimeLaunchArtifact, RuntimeLaunchIdentity, RuntimeNetworkIdentity,
    ServingAuthorityProvenance, ServingBlockdIdentity, SessionBinding, Sha256Digest, UnixMillis,
    VmmBootProvenance, WireU64,
};
use cats_storage::authority::{
    authorized_serving_attachment_from_start_volume_grant, remote_head_is_same_or_later,
    validate_authorized_serving_attachment, validate_volume_owner_binding, validate_volume_record,
    AttachmentLineageIdentity, AuthorizedServingAttachment,
};
use cats_storage::{
    encode_image_manifest, read_image_manifest_until, AdapterSelection, BlobStore,
    ImageManifestReadError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::admission_registry::LifecycleAdmissionRegistry;
use crate::agent_registration::AgentRegistrationConfig;
use crate::cat_execution_scope::{cat_execution_slice_id, cat_service_cgroup_path};
use crate::ch::{self, BlockPath, ChConfig, ChNetwork, ReservedHostNetworkState};
use crate::guest_client::GuestClient;
use crate::lifecycle_volume_client::{LifecycleVolumeClientError, LifecycleVolumeHttpClient};
use crate::object_write_credential::{self, NodeObjectWriteCredentials, ObjectWriteCredentialPort};
use crate::physical_read::{PhysicalEffectContext, PhysicalReadContext};
use crate::runtime_inventory::{inspect_installed_vmm_api, InstalledVmmApiInspection};
use crate::vmm_launcher::{
    encode_atomic_vmm_launch_spec, AtomicVmmLaunchMode, AtomicVmmLaunchSpec,
    AtomicVmmMemoryFileIdentity, AtomicVmmWarmRestoreSourceIdentity,
    ATOMIC_VMM_LAUNCH_SPEC_FD_NAME, RUNTIME_INCARNATION_ENVIRONMENT,
    VMM_LAUNCHER_CONTRACT_ARGUMENT, VMM_PROCESS_TOKEN_ENVIRONMENT,
};

use super::super::journal::ExactBytes;
use super::start::{
    atomic_start_launch_volume_id, atomic_start_platform_receipt_digest,
    atomic_start_session_rebind_receipt_digest, runtime_context_has_monotonic_lease_budget,
    AtomicStartDefiniteFailure, AtomicStartRuntimeContext, AtomicStartRuntimeEffectOutcome,
    AtomicStartRuntimeEffectPhase, AtomicStartRuntimeEffectRequest, AtomicStartRuntimePort,
    AtomicStartRuntimeReadyEvidence, AtomicStartVolumeGrant, InstalledRuntimeBlockFrontend,
    InstalledRuntimeManifest, InstalledRuntimeNetworkManifest, InstalledRuntimeProcessIdentity,
    InstalledRuntimeProgressManifest, InstalledRuntimeProgressVolumeManifest,
    InstalledRuntimeVmmManifest, InstalledRuntimeVolumeManifest,
    START_VOLUME_LEASE_SAFETY_MARGIN_MS,
};
use super::suspend_warm::{
    InstalledSuspendWarmPlatform, SameNodeOwnedPredecessorPhysical, SameNodeOwnedPredecessorSource,
    WarmSnapshotCleanupAttempt, WarmSnapshotCleanupCompletion, WarmSnapshotCleanupMode,
};
use super::InstalledPhysicalInspectionConfig;

const PLATFORM_PLAN_DOMAIN: &[u8] = b"cats.atomic-lifecycle.installed-start-platform-plan.v1";
const CONFIG_DIGEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.installed-start-config.v1";
const NETWORK_RESERVATION_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-network-reservation.v1";
const BLOCKD_SOCKET_OWNER_DOMAIN: &[u8] = b"cats.atomic-lifecycle.blockd-socket-owner.v1";
const DEVICE_ATTRIBUTION_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-device-attribution.v1";
const GUEST_READY_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.guest-ready-receipt.v1";
const RUNTIME_EXECUTION_RECEIPT_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.runtime-execution-receipt.v1";
const SESSION_ZERO_USE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.start-session-zero-use.v1";
const GUEST_FILESYSTEM_RESPONSE_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.guest-filesystem-response.v1";
const BLOCKD_DRAIN_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.blockd-drain-receipt.v1";
const PLAN_VERSION: ContractVersion = ContractVersion::V1;
const PLATFORM_PLAN_MAX_BYTES: usize = 128 * 1024;
const ARTIFACT_READ_BUFFER_BYTES: usize = 128 * 1024;
const INSTALLED_VMM_SOCKET_ROOT: &str = "/run/cats/vmm-v1";
const VMM_LAUNCH_FILE_NAMESPACE: &str = "vmm-launch-v1";
pub(crate) const START_NETWORK_RESERVATION_NAMESPACE: &str = "atomic-start-network-v1";

/// Installed blockd coordinates and resource limits sampled into every device
/// plan.  No value is recovered from PATH or an environment default.
#[derive(Debug, Clone)]
pub struct InstalledAtomicStartBlockdConfig {
    pub blockd_binary: PathBuf,
    pub metadata_store: AdapterSelection,
    pub object_store: AdapterSelection,
    pub lease_ttl_ms: i64,
    pub max_staged_bytes: u64,
    pub max_staged_packs: usize,
    pub max_local_bytes: u64,
}

/// Closed publication mode.  Gateway mode constructs the real attachment
/// credential state machine inside this crate, where the A19 signer remains
/// private. `DirectProvider` is an explicit installed choice, never the
/// accidental absence of a credential dependency.
#[derive(Clone)]
pub enum InstalledAtomicStartObjectWriteMode {
    Gateway {
        gateway_origin: String,
        control_plane_origin: String,
        registration: Arc<AgentRegistrationConfig>,
    },
    DirectProvider,
}

impl std::fmt::Debug for InstalledAtomicStartObjectWriteMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gateway {
                gateway_origin,
                control_plane_origin,
                ..
            } => formatter
                .debug_struct("Gateway")
                .field("gateway_origin", gateway_origin)
                .field("control_plane_origin", control_plane_origin)
                .finish_non_exhaustive(),
            Self::DirectProvider => formatter.write_str("DirectProvider"),
        }
    }
}

/// Complete production composition for the installed Start runtime half.
#[derive(Clone)]
pub struct InstalledAtomicStartRuntimeConfig {
    pub physical: InstalledPhysicalInspectionConfig,
    pub admission_registry: Arc<LifecycleAdmissionRegistry>,
    /// The exact same wrapper supplied to Suspend/Warm command handling.
    pub suspend_warm_platform: InstalledSuspendWarmPlatform,
    pub ch: ChConfig,
    pub systemd_run_binary: PathBuf,
    pub blockd: InstalledAtomicStartBlockdConfig,
    pub root_image_store: Arc<dyn BlobStore>,
    pub object_write_mode: InstalledAtomicStartObjectWriteMode,
    /// The same signed A22 transport used for acquire/renew. Persistent init
    /// inspect/commit uses its command/session-bound wire, not another
    /// authority implementation.
    pub persistent_initialization_control: Arc<LifecycleVolumeHttpClient>,
    pub effect_timeout: Duration,
    pub guest_ready_timeout: Duration,
}

/// Compose the real installed runtime port.  Validation happens before a
/// lifecycle runner can accept work, so a missing executable/backend mode is
/// a startup failure rather than a per-Cat downgrade.
pub fn installed_atomic_start_runtime_port(
    config: InstalledAtomicStartRuntimeConfig,
) -> Result<Arc<dyn AtomicStartRuntimePort>> {
    Ok(Arc::new(InstalledAtomicStartRuntimePort::new(config)?))
}

struct InstalledAtomicStartRuntimePort {
    config: InstalledAtomicStartRuntimeConfig,
    config_digest: Sha256Digest,
    object_write_credentials: Option<Arc<dyn ObjectWriteCredentialPort>>,
    warm_platform: InstalledSuspendWarmPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledAtomicStartPlatformPlan {
    version: ContractVersion,
    phase: AtomicStartRuntimeEffectPhase,
    node_id: Id,
    cat_id: Id,
    placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    runtime_config_id: Id,
    runtime_config_digest: Sha256Digest,
    runtime_incarnation: RandomId128,
    source: StartSource,
    effect_deadline_unix_ms: UnixMillis,
    volume_grant_sequence: WireU64,
    volume_grant_receipt_digests: Vec<Sha256Digest>,
    completed_platform_plan_digests: Vec<Sha256Digest>,
    installed_config_digest: Sha256Digest,
    body: InstalledAtomicStartPlanBody,
    plan_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum InstalledAtomicStartPlanBody {
    /// A bounded, side-effect-free planning read produced a closed negative.
    /// Persisting the result before returning `Failed` keeps a missing/corrupt
    /// immutable input from becoming an unjournaled infinite retry.
    DefiniteFailure {
        reason: cats_api::runtime_lifecycle::CommandFailureReason,
    },
    PrepareRoot {
        image_manifest: ExactBytes,
        image_manifest_digest: Sha256Digest,
        image_target: RemoteHead,
        object_write: PlannedObjectWriteMode,
        volumes: Vec<PlannedRootVolume>,
        same_node_restart_source: Option<PlannedSameNodeRestartSource>,
    },
    PrepareSuspendedRoot {
        source: Box<PlannedSameNodeRestartSource>,
    },
    PrepareDevices {
        prepare_root_plan_digest: Sha256Digest,
        blockd: PlannedBlockdLaunchConfig,
        volumes: Vec<PlannedDevice>,
    },
    PrepareSuspendedDevices {
        prepare_root_plan_digest: Sha256Digest,
        source_physical_manifest_digest: Sha256Digest,
    },
    PrepareNetwork {
        prepare_devices_plan_digest: Sha256Digest,
        reservation: PlannedNetworkReservation,
    },
    PrepareSuspendedNetwork {
        prepare_devices_plan_digest: Sha256Digest,
        source_physical_manifest_digest: Sha256Digest,
    },
    ActivateRuntime {
        prepare_network_plan_digest: Sha256Digest,
        launch: Box<RuntimeLaunchIdentity>,
        mode: AtomicVmmLaunchMode,
    },
    ResumeSuspendedRuntime {
        prepare_network_plan_digest: Sha256Digest,
        source_physical_manifest_digest: Sha256Digest,
    },
    FormatPersistentVolumes {
        activate_runtime_plan_digest: Sha256Digest,
        volumes: Vec<PlannedPersistentInitialization>,
    },
    CommitPersistentInitialized {
        format_plan_digest: Sha256Digest,
        /// Frozen as exact signed A22 request bytes once the shared wire is
        /// available. Empty is valid only when there are no Persistent disks.
        commit_requests: Vec<ExactBytes>,
    },
    GuestReadyAndAdmission {
        commit_plan_digest: Sha256Digest,
        runtime_ready_challenge: RandomId128,
        filesystems: Vec<PlannedPersistentMount>,
        same_node_restart_source: Option<PlannedSameNodeRestartSource>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedRootVolume {
    volume: RuntimeVolumeConfig,
    attachment_id: Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    acquire_origin: AcquireOrigin,
    authority_head: RemoteHead,
    authority_receipt_digest: Sha256Digest,
    lineage_data_directory: HostPath,
    provision_transition_id: Option<RandomId128>,
    provision_process_identity_token: Option<RandomId128>,
    provision_service_id: Option<Id>,
    provision_control_socket_path: Option<HostPath>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedDevice {
    volume: RuntimeVolumeConfig,
    attachment_id: Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    acquire_origin: AcquireOrigin,
    launch_head: RemoteHead,
    authority_receipt_digest: Sha256Digest,
    lineage_data_directory: HostPath,
    serving_service_id: Id,
    kernel_nbd_client_service_id: Option<Id>,
    serving_process_identity_token: RandomId128,
    device_ownership_token: RandomId128,
    control_socket_path: HostPath,
    frontend: PrepareDeviceFrontend,
    authorized_serving_artifact_path: HostPath,
    command_attribution_path: HostPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PlannedObjectWriteMode {
    Gateway {
        session: SessionBinding,
        gateway_origin: String,
        credential_directory: HostPath,
        expected_credential_ids: Vec<Id>,
    },
    DirectProvider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedBlockdLaunchConfig {
    executable: HostPath,
    metadata_store_adapter: String,
    metadata_store_options: Vec<String>,
    object_store_adapter: String,
    object_store_options: Vec<String>,
    lease_ttl_ms: WireU64,
    max_staged_bytes: WireU64,
    max_staged_packs: WireU64,
    max_local_bytes: WireU64,
}

/// Canonical enumerable attribution for a TAP reservation. This artifact is
/// published before TAP creation; therefore a crash after the physical link
/// but before the command successor still leaves the link attributable to the
/// exact executing plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledAtomicStartNetworkReservation {
    pub(crate) version: ContractVersion,
    pub(crate) node_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    pub(crate) operation_id: Id,
    pub(crate) request_fingerprint: Sha256Digest,
    pub(crate) runtime_config_id: Id,
    pub(crate) runtime_config_digest: Sha256Digest,
    pub(crate) runtime_incarnation: RandomId128,
    pub(crate) platform_plan_digest: Sha256Digest,
    pub(crate) identity: Box<RuntimeNetworkIdentity>,
    pub(crate) reservation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AtomicStartBlockdSocketRole {
    RootProvision,
    Serving,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledAtomicStartBlockdSocketOwner {
    version: ContractVersion,
    node_id: Id,
    cat_id: Id,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    runtime_incarnation: RandomId128,
    platform_plan_digest: Sha256Digest,
    role: AtomicStartBlockdSocketRole,
    owner_token: RandomId128,
    service_id: Id,
    control_socket_path: HostPath,
    io_socket_path: Option<HostPath>,
    owner_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledAtomicStartDeviceAttribution {
    version: ContractVersion,
    node_id: Id,
    cat_id: Id,
    placement_identity: cats_api::runtime_lifecycle::PlacementIdentity,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    runtime_config_id: Id,
    runtime_config_digest: Sha256Digest,
    runtime_incarnation: RandomId128,
    platform_plan_digest: Sha256Digest,
    authority_receipt_digest: Sha256Digest,
    authorized_serving_artifact_digest: Sha256Digest,
    prepared_device: Box<PreparedDeviceInput>,
    attribution_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedNetworkReservation {
    identity: Box<RuntimeNetworkIdentity>,
    artifact_path: HostPath,
    predecessor_artifact: Option<ExactBytes>,
    replacement_path: HostPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedPersistentFilesystem {
    volume_id: Id,
    disk_id: Id,
    attachment_id: Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    guest_device: GuestDeviceIdentity,
    filesystem_uuid: RandomId128,
    mount_path: AsciiText,
}

/// Authority-only product state and every Guest request identity are frozen
/// before the first possible mkfs.  The inspection itself is not mutation
/// authority; apply still joins it to the current grant and a fresh local
/// Volume row immediately before touching the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedPersistentInitialization {
    filesystem: PlannedPersistentFilesystem,
    inspection: LifecyclePersistentInitializationInspection,
    probe_challenge: RandomId128,
    format_challenge: RandomId128,
    post_format_probe_challenge: RandomId128,
    flush_challenge: RandomId128,
    guest_timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedPersistentMount {
    filesystem: PlannedPersistentFilesystem,
    initialization_token: RandomId128,
    expected_blank_head: RemoteHead,
    initialized_head: RemoteHead,
    probe_challenge: RandomId128,
    mount_challenge: RandomId128,
    guest_timeout_ms: u32,
}

/// The format phase either proves the Disk was already initialized before
/// this Start, or carries the complete one-way commit request assembled from
/// Guest and R=L evidence.  These bytes are copied into the next durable plan
/// unchanged, so a lost commit response can only replay the same tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum InstalledPersistentFormatReceipt {
    AlreadyInitialized {
        inspection: Box<LifecyclePersistentInitializationInspection>,
    },
    CommitRequired {
        commit: Box<LifecyclePersistentInitializationCommitRequest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum InstalledPersistentCommitReceipt {
    AlreadyInitialized {
        inspection: Box<LifecyclePersistentInitializationInspection>,
    },
    Committed {
        committed: Box<LifecycleStoredPersistentInitializationCommit>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournaledPersistentCommitObservation {
    UninitializedExact,
    InitializedExact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistentMountLeaseLossDisposition {
    RefreshSamePlan,
    FailClosed,
}

fn persistent_mount_lease_loss_disposition(
    mounted_any: bool,
) -> PersistentMountLeaseLossDisposition {
    if mounted_any {
        PersistentMountLeaseLossDisposition::FailClosed
    } else {
        PersistentMountLeaseLossDisposition::RefreshSamePlan
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BlockdDrainReceiptInput<'a> {
    operation_id: &'a Id,
    request_fingerprint: &'a Sha256Digest,
    volume_id: &'a Id,
    attachment_id: &'a Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    blockd: &'a InstalledRuntimeProcessIdentity,
    status: &'a DurabilityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedSameNodeRestartSource {
    physical: Box<SameNodeOwnedPredecessorPhysical>,
}

enum SameNodeRestartPlanning {
    NotApplicable,
    Exact(PlannedSameNodeRestartSource),
    DefiniteInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannedRuntimeActivationKind {
    Fresh,
    WarmRestore,
    ResumeSuspended,
}

fn activation_kind_is_exact_for_source(
    source: StartSource,
    has_exact_warm_restart_source: bool,
    activation: PlannedRuntimeActivationKind,
) -> bool {
    match source {
        StartSource::SameNodeSuspended => {
            !has_exact_warm_restart_source
                && activation == PlannedRuntimeActivationKind::ResumeSuspended
        }
        StartSource::SameNodeWarm => {
            has_exact_warm_restart_source && activation == PlannedRuntimeActivationKind::WarmRestore
        }
        StartSource::SameNodeRetry if has_exact_warm_restart_source => {
            activation == PlannedRuntimeActivationKind::WarmRestore
        }
        StartSource::Genesis
        | StartSource::SameNodeCold
        | StartSource::SameNodeStopped
        | StartSource::SameNodeRetry
        | StartSource::ColdHandoff
        | StartSource::HostFenceRecovery => {
            !has_exact_warm_restart_source && activation == PlannedRuntimeActivationKind::Fresh
        }
    }
}

fn lease_session_and_budget_are_current(
    current: &SessionBinding,
    planned: &SessionBinding,
    monotonic_budget_is_live: bool,
) -> bool {
    current == planned && monotonic_budget_is_live
}

fn object_write_session_is_current(
    object_write: &PlannedObjectWriteMode,
    context_session: &SessionBinding,
    current_session: &SessionBinding,
) -> bool {
    match object_write {
        PlannedObjectWriteMode::DirectProvider => true,
        PlannedObjectWriteMode::Gateway { session, .. } => {
            session == context_session && session == current_session
        }
    }
}

/// A lease refresh may replace only a plan whose exact inspection closed all
/// of its mutation boundaries as absent. Once any artifact/process may have
/// been published, loss of the process-local witness keeps the same plan in
/// discovery; it never authorizes a fresh plan or another mutation.
fn lease_loss_allows_same_plan_refresh(exact_zero_mutation: bool) -> bool {
    exact_zero_mutation
}

fn bounded_physical_discovery_budget(
    command_wall_remaining: Duration,
    installed_effect_timeout: Duration,
) -> Duration {
    if command_wall_remaining.is_zero() {
        installed_effect_timeout
    } else {
        command_wall_remaining.min(installed_effect_timeout)
    }
}

fn phase_and_command_deadlines_are_live(
    monotonic_now: Instant,
    phase_deadline: Instant,
    wall_now: UnixMillis,
    command_deadline: UnixMillis,
) -> bool {
    monotonic_now < phase_deadline && wall_now < command_deadline
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournaledEffectDiscoveryState {
    ZeroMutation,
    ExactPostcondition,
    PartialMutation,
}

fn deadline_expired_failure_reason(
    state: JournaledEffectDiscoveryState,
) -> Option<cats_api::runtime_lifecycle::CommandFailureReason> {
    match state {
        JournaledEffectDiscoveryState::ExactPostcondition => None,
        JournaledEffectDiscoveryState::ZeroMutation
        | JournaledEffectDiscoveryState::PartialMutation => {
            Some(cats_api::runtime_lifecycle::CommandFailureReason::InvalidLocalPrecondition)
        }
    }
}

fn record_exact_root_lineage_failure_progress(
    installed: &mut InstalledRuntimeProgressVolumeManifest,
    planned: &PlannedRootVolume,
    current_head: RemoteHead,
) -> Result<()> {
    anyhow::ensure!(
        installed.volume_id == planned.volume.volume_id
            && installed.disk_id == planned.volume.disk_id
            && installed.disk_role == planned.volume.disk_role
            && installed.attachment_id == planned.attachment_id
            && installed.attachment_epoch == planned.attachment_epoch
            && installed.acquire_origin == planned.acquire_origin
            && remote_head_is_same_or_later(&current_head, &installed.authority_head),
        "PrepareRoot failure discovery changed or regressed a Volume lineage"
    );
    installed.authority_head = current_head;
    installed.local_lineage_data_directory = Some(planned.lineage_data_directory.clone());
    Ok(())
}

fn validate_exact_persistent_commit_response(
    expected: &LifecyclePersistentInitializationCommitRequest,
    stored: &LifecycleStoredPersistentInitializationCommit,
) -> Result<()> {
    anyhow::ensure!(
        stored.receipt.request.as_ref() == expected,
        "Persistent initialization commit response changed its exact request"
    );
    Ok(())
}

fn journal_persistent_commit_plan(
    format_plan_digest: Sha256Digest,
    format_receipts: Vec<ExactBytes>,
) -> Result<InstalledAtomicStartPlanBody> {
    for receipt in &format_receipts {
        let receipt: InstalledPersistentFormatReceipt = decode_exact_json(
            receipt,
            "decode Persistent format receipt before commit planning",
        )?;
        if let InstalledPersistentFormatReceipt::CommitRequired { commit } = receipt {
            anyhow::ensure!(
                commit.format_plan_digest == format_plan_digest,
                "Persistent commit request is not bound to its preceding Format plan"
            );
        }
    }
    Ok(InstalledAtomicStartPlanBody::CommitPersistentInitialized {
        format_plan_digest,
        commit_requests: format_receipts,
    })
}

fn classify_journaled_persistent_commit_inspection(
    commit: &LifecyclePersistentInitializationCommitRequest,
    inspection: &LifecyclePersistentInitializationInspection,
) -> Result<JournaledPersistentCommitObservation> {
    match &inspection.initialization {
        LifecyclePersistentInitializationState::Initialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
            initialized_head,
            ..
        } if initialization_token == &commit.initialization_token
            && filesystem_uuid == &commit.filesystem_uuid
            && expected_blank_head == &commit.expected_blank_head
            && initialized_head == &commit.initialized_head
            && remote_head_is_same_or_later(&inspection.current_head, initialized_head) =>
        {
            Ok(JournaledPersistentCommitObservation::InitializedExact)
        }
        LifecyclePersistentInitializationState::Uninitialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
        } if initialization_token == &commit.initialization_token
            && filesystem_uuid == &commit.filesystem_uuid
            && expected_blank_head == &commit.expected_blank_head
            && inspection.current_head == commit.expected_blank_head =>
        {
            Ok(JournaledPersistentCommitObservation::UninitializedExact)
        }
        _ => anyhow::bail!("Persistent commit discovery changed initialization evidence"),
    }
}

fn validate_journaled_persistent_commit_binding(
    commit: &LifecyclePersistentInitializationCommitRequest,
    inspection: &LifecyclePersistentInitializationInspection,
    current_binding: &LifecyclePersistentInitializationBinding,
    current_attachment_id: &Id,
    current_attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
) -> Result<()> {
    anyhow::ensure!(
        inspection.binding == commit.binding
            && inspection.binding.as_ref() == current_binding
            && &inspection.attachment_id == current_attachment_id
            && inspection.attachment_epoch == current_attachment_epoch,
        "Persistent commit discovery changed its exact latest StartGrant binding"
    );
    Ok(())
}

fn persistent_initialization_inspection_rebinds_plan(
    planned: &LifecyclePersistentInitializationInspection,
    current: &LifecyclePersistentInitializationInspection,
) -> bool {
    let planned_binding = planned.binding.as_ref();
    let current_binding = current.binding.as_ref();
    let head_is_valid = match &planned.initialization {
        LifecyclePersistentInitializationState::Uninitialized { .. } => {
            current.current_head == planned.current_head
        }
        LifecyclePersistentInitializationState::Initialized { .. } => {
            remote_head_is_same_or_later(&current.current_head, &planned.current_head)
        }
    };
    planned_binding.scope == current_binding.scope
        && planned_binding.runtime_config_id == current_binding.runtime_config_id
        && planned_binding.runtime_config_digest == current_binding.runtime_config_digest
        && planned_binding.volume == current_binding.volume
        && planned.attachment_id == current.attachment_id
        && planned.attachment_epoch == current.attachment_epoch
        && planned.initialization == current.initialization
        && head_is_valid
}

/// Both exact observations submit the same journaled request. `Initialized`
/// is response-loss discovery, not permission to synthesize a new receipt;
/// Control must compare the full nested request and return the stored result.
fn submit_journaled_persistent_commit<T, E>(
    runtime_incarnation: &RandomId128,
    format_plan_digest: &Sha256Digest,
    commit: &LifecyclePersistentInitializationCommitRequest,
    _observation: JournaledPersistentCommitObservation,
    submit: impl FnOnce(
        &RandomId128,
        &Sha256Digest,
        LifecyclePersistentInitializationCommitRequest,
    ) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    submit(runtime_incarnation, format_plan_digest, commit.clone())
}

/// Exact per-phase provider receipt carried by the shared Start successor.
/// Sidecars remain independently discoverable physical evidence, but later
/// phases never need to reconstruct their identity from a digest alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledAtomicStartPlatformReceipt {
    version: ContractVersion,
    phase: AtomicStartRuntimeEffectPhase,
    node_id: Id,
    cat_id: Id,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    runtime_incarnation: RandomId128,
    platform_plan_digest: Sha256Digest,
    body: InstalledAtomicStartReceiptBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum InstalledAtomicStartReceiptBody {
    PrepareRoot {
        volumes: Vec<InstalledRootVolumeReceipt>,
        same_node_restart_source: Option<PlannedSameNodeRestartSource>,
    },
    PrepareSuspendedRoot {
        source_physical_manifest_digest: Sha256Digest,
    },
    PrepareDevices {
        devices: Vec<PreparedDeviceInput>,
        progress_volumes: Vec<InstalledRuntimeProgressVolumeManifest>,
    },
    PrepareNetwork {
        reservation: Box<InstalledAtomicStartNetworkReservation>,
    },
    PrepareSuspendedNetwork {
        network: Box<InstalledRuntimeNetworkManifest>,
    },
    ActivateRuntime {
        vmm: Box<InstalledRuntimeVmmManifest>,
    },
    FormatPersistentVolumes {
        format_receipts: Vec<ExactBytes>,
    },
    CommitPersistentInitialized {
        commit_receipts: Vec<ExactBytes>,
    },
    GuestReadyAndAdmission {
        guest_ready_receipt_digest: Sha256Digest,
        retired_restart_source_absence_digest: Option<Sha256Digest>,
        manifest: Box<InstalledRuntimeManifest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledRootVolumeReceipt {
    volume_id: Id,
    authority_head: RemoteHead,
    authorized_serving_attachment: ExactBytes,
    authorized_serving_artifact_digest: Sha256Digest,
    object_write_registered_artifact: Option<ExactBytes>,
    object_write_registered_artifact_digest: Option<Sha256Digest>,
    lineage_identity_digest: Sha256Digest,
    root_provision_receipt: Option<ExactBytes>,
}

/// Domain-separated join input for the final physical execution receipt.
///
/// The receipt deliberately embeds the complete installed identities and the
/// command's final per-Volume projection.  A digest of the Guest challenge by
/// itself would not prove that the challenged transport still belonged to the
/// exact VMM, frontends and authority rows inspected on either side of it.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InstalledRuntimeExecutionReceiptInput<'a> {
    operation_id: &'a Id,
    request_fingerprint: &'a Sha256Digest,
    runtime_incarnation: &'a RandomId128,
    platform_plan_digest: &'a Sha256Digest,
    vmm: &'a InstalledRuntimeVmmManifest,
    network: &'a InstalledRuntimeNetworkManifest,
    volumes: &'a [InstalledRuntimeVolumeManifest],
    volume_receipts: &'a [VolumeTerminalReceipt],
    guest_ready_receipt_digest: &'a Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledAtomicStartSessionRebindCleanupReceipt {
    version: ContractVersion,
    phase: AtomicStartRuntimeEffectPhase,
    node_id: Id,
    cat_id: Id,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
    runtime_incarnation: RandomId128,
    old_platform_plan_digest: Sha256Digest,
    old_session: SessionBinding,
    observed_current_session: SessionBinding,
    retired_credential_ids: Vec<Id>,
    exact_zero_use_digest: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InstalledAtomicStartSessionZeroUseInput<'a> {
    operation_id: &'a Id,
    request_fingerprint: &'a Sha256Digest,
    runtime_incarnation: &'a RandomId128,
    old_platform_plan_digest: &'a Sha256Digest,
    old_session: &'a SessionBinding,
    volumes: &'a [PlannedRootVolume],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InstalledConfigDigestInput<'a> {
    version: ContractVersion,
    node_id: &'a Id,
    state_directory: &'a str,
    systemctl_binary: &'a str,
    systemd_run_binary: &'a str,
    cgroup_root: &'a str,
    proc_root: &'a str,
    ip_binary: &'a str,
    network_class_root: &'a str,
    vmm_launcher_binary: &'a str,
    cloud_hypervisor_binary: &'a str,
    kernel: &'a str,
    initramfs: Option<&'a str>,
    kernel_cmdline: &'a str,
    block_path: &'static str,
    block_direct: bool,
    vhost_user_queues: usize,
    vhost_user_queue_size: u16,
    nbd_client_binary: &'a str,
    nbd_devices: u32,
    blockd_binary: &'a str,
    metadata_store_adapter: &'a str,
    metadata_store_options: Vec<String>,
    object_store_adapter: &'a str,
    object_store_options: Vec<String>,
    blockd_lease_ttl_ms: i64,
    max_staged_bytes: u64,
    max_staged_packs: usize,
    max_local_bytes: u64,
    object_write_mode: &'static str,
    effect_timeout_ms: u64,
    guest_ready_timeout_ms: u64,
}

impl InstalledAtomicStartRuntimePort {
    fn new(mut config: InstalledAtomicStartRuntimeConfig) -> Result<Self> {
        config.physical.include_provider_process_binaries();
        validate_production_config(&config)?;
        let config_digest = installed_config_digest(&config)?;
        let object_write_credentials: Option<Arc<dyn ObjectWriteCredentialPort>> =
            match &config.object_write_mode {
                InstalledAtomicStartObjectWriteMode::Gateway {
                    gateway_origin,
                    control_plane_origin,
                    registration,
                } => {
                    anyhow::ensure!(
                        registration.identity().node_id == config.physical.node_id
                            && registration.runtime_state_directory().path()
                                == config.physical.state_directory.path(),
                        "atomic Start ObjectWrite registration differs from physical Node identity"
                    );
                    Some(Arc::new(
                        NodeObjectWriteCredentials::for_agent_registration(
                            gateway_origin,
                            control_plane_origin,
                            registration,
                        )?,
                    ))
                }
                InstalledAtomicStartObjectWriteMode::DirectProvider => None,
            };
        let warm_platform = config.suspend_warm_platform.clone();
        Ok(Self {
            config,
            config_digest,
            object_write_credentials,
            warm_platform,
        })
    }
}

fn phase_index(phase: AtomicStartRuntimeEffectPhase) -> usize {
    match phase {
        AtomicStartRuntimeEffectPhase::PrepareRoot => 0,
        AtomicStartRuntimeEffectPhase::PrepareDevices => 1,
        AtomicStartRuntimeEffectPhase::PrepareNetwork => 2,
        AtomicStartRuntimeEffectPhase::ActivateRuntime => 3,
        AtomicStartRuntimeEffectPhase::FormatPersistentVolumes => 4,
        AtomicStartRuntimeEffectPhase::CommitPersistentInitialized => 5,
        AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission => 6,
    }
}

fn phase_at(index: usize) -> Option<AtomicStartRuntimeEffectPhase> {
    [
        AtomicStartRuntimeEffectPhase::PrepareRoot,
        AtomicStartRuntimeEffectPhase::PrepareDevices,
        AtomicStartRuntimeEffectPhase::PrepareNetwork,
        AtomicStartRuntimeEffectPhase::ActivateRuntime,
        AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
        AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
        AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission,
    ]
    .get(index)
    .copied()
}

fn validate_grant(
    command: &LifecycleCommandEnvelope,
    context: &AtomicStartRuntimeContext,
    grant: &AtomicStartVolumeGrant,
    volume: &RuntimeVolumeConfig,
) -> Result<()> {
    anyhow::ensure!(
        grant.volume.volume_id == volume.volume_id
            && grant.volume.disk_id == volume.disk_id
            && grant.volume.disk_role == volume.disk_role
            && grant.authority_receipt.volume == *volume
            && grant.authority_receipt.grant_sequence == context.volume_grant_sequence
            && grant.authority_receipt.scope.operation_id == command.operation_id
            && grant.authority_receipt.scope.request_fingerprint == command.request_fingerprint
            && grant.authority_receipt.scope.cat_id == command.cat_id
            && grant.authority_receipt.scope.node_id == command.node_id
            && grant.authority_receipt.scope.placement_identity == command.placement_identity
            && grant.volume.authority_receipt_digest.as_ref() == Some(&grant.grant_receipt_digest),
        "atomic Start runtime grant is not the exact command Volume projection"
    );
    Ok(())
}

fn encode_platform_plan(
    command: &LifecycleCommandEnvelope,
    phase: AtomicStartRuntimeEffectPhase,
    context: &AtomicStartRuntimeContext,
    installed_config_digest: &Sha256Digest,
    body: InstalledAtomicStartPlanBody,
) -> Result<ExactBytes> {
    let mut plan = InstalledAtomicStartPlatformPlan {
        version: PLAN_VERSION,
        phase,
        node_id: command.node_id.clone(),
        cat_id: command.cat_id.clone(),
        placement_identity: command.placement_identity.clone(),
        operation_id: command.operation_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        runtime_config_id: command.runtime_config.config_id.clone(),
        runtime_config_digest: command.runtime_config.config_digest.clone(),
        runtime_incarnation: context.runtime_incarnation.clone(),
        source: context.source,
        effect_deadline_unix_ms: context.effect_deadline_unix_ms,
        volume_grant_sequence: context.volume_grant_sequence,
        volume_grant_receipt_digests: context
            .volume_grants
            .iter()
            .map(|grant| grant.grant_receipt_digest.clone())
            .collect(),
        completed_platform_plan_digests: context
            .completed_effects
            .iter()
            .map(|receipt| receipt.platform_plan_digest.clone())
            .collect(),
        installed_config_digest: installed_config_digest.clone(),
        body,
        plan_digest: zero_digest(),
    };
    plan.plan_digest = platform_plan_digest(&plan)?;
    let bytes = serde_json::to_vec(&plan).context("encode installed atomic Start platform plan")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= PLATFORM_PLAN_MAX_BYTES,
        "installed atomic Start platform plan exceeds its byte cap"
    );
    Ok(ExactBytes::new(bytes))
}

fn decode_platform_plan(bytes: &ExactBytes) -> Result<InstalledAtomicStartPlatformPlan> {
    anyhow::ensure!(
        !bytes.as_slice().is_empty() && bytes.as_slice().len() <= PLATFORM_PLAN_MAX_BYTES,
        "installed atomic Start platform plan has an invalid length"
    );
    let plan: InstalledAtomicStartPlatformPlan = serde_json::from_slice(bytes.as_slice())
        .context("decode installed atomic Start platform plan")?;
    anyhow::ensure!(
        serde_json::to_vec(&plan)? == bytes.as_slice(),
        "installed atomic Start platform plan is not canonical JSON"
    );
    anyhow::ensure!(
        plan.version == PLAN_VERSION && platform_plan_digest(&plan)? == plan.plan_digest,
        "installed atomic Start platform plan version or digest is invalid"
    );
    Ok(plan)
}

fn platform_plan_digest(plan: &InstalledAtomicStartPlatformPlan) -> Result<Sha256Digest> {
    let mut preimage = plan.clone();
    preimage.plan_digest = zero_digest();
    digest_serialized(PLATFORM_PLAN_DOMAIN, &preimage)
}

fn validate_platform_plan_binding(
    plan: &InstalledAtomicStartPlatformPlan,
    command: &LifecycleCommandEnvelope,
    phase: AtomicStartRuntimeEffectPhase,
    context: &AtomicStartRuntimeContext,
    config_digest: &Sha256Digest,
) -> Result<()> {
    let completed_plan_prefix = context
        .completed_effects
        .iter()
        .take(phase_index(phase))
        .map(|receipt| receipt.platform_plan_digest.clone())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        plan.version == PLAN_VERSION
            && plan.phase == phase
            && plan.node_id == command.node_id
            && plan.cat_id == command.cat_id
            && plan.placement_identity == command.placement_identity
            && plan.operation_id == command.operation_id
            && plan.request_fingerprint == command.request_fingerprint
            && plan.runtime_config_id == command.runtime_config.config_id
            && plan.runtime_config_digest == command.runtime_config.config_digest
            && plan.runtime_incarnation == context.runtime_incarnation
            && plan.source == context.source
            && plan.effect_deadline_unix_ms == context.effect_deadline_unix_ms
            && plan.installed_config_digest == *config_digest
            && plan.completed_platform_plan_digests.len() == phase_index(phase)
            && plan.completed_platform_plan_digests == completed_plan_prefix
            && plan.volume_grant_receipt_digests.len() == context.volume_grants.len()
            && plan.volume_grant_sequence.get() <= context.volume_grant_sequence.get()
            && platform_plan_digest(plan)? == plan.plan_digest,
        "installed atomic Start platform plan changed command/config binding"
    );
    if plan.volume_grant_sequence == context.volume_grant_sequence {
        anyhow::ensure!(
            plan.volume_grant_receipt_digests
                == context
                    .volume_grants
                    .iter()
                    .map(|grant| grant.grant_receipt_digest.clone())
                    .collect::<Vec<_>>(),
            "atomic Start platform plan changed grants within one grant sequence"
        );
    }
    validate_platform_plan_volume_rebind(plan, context)?;
    Ok(())
}

/// A zero-mutation lease refresh deliberately resumes the byte-identical
/// platform plan.  Its transport receipts therefore remain the lower-bound
/// authority sampled before the refresh, while the current context carries a
/// strictly later receipt.  Only the mutable lease/head projection may move:
/// volume, attachment, epoch, acquisition lineage and local lineage path are
/// immutable across every refresh.
fn validate_platform_plan_volume_rebind(
    plan: &InstalledAtomicStartPlatformPlan,
    context: &AtomicStartRuntimeContext,
) -> Result<()> {
    match &plan.body {
        InstalledAtomicStartPlanBody::PrepareRoot { volumes, .. } => {
            anyhow::ensure!(
                volumes.len() == context.volume_grants.len(),
                "PrepareRoot plan changed the refreshed Volume set"
            );
            for (planned, current) in volumes.iter().zip(&context.volume_grants) {
                anyhow::ensure!(
                    planned.volume == current.authority_receipt.volume
                        && planned.attachment_id == current.volume.attachment_id
                        && planned.attachment_epoch == current.volume.attachment_epoch
                        && planned.acquire_origin == current.acquire_origin
                        && planned.lineage_data_directory
                            == current.planned_local_lineage_data_directory
                        && remote_head_is_same_or_later(
                            &current.authoritative_head,
                            &planned.authority_head,
                        ),
                    "PrepareRoot refresh changed immutable Volume lineage or regressed its head"
                );
            }
        }
        InstalledAtomicStartPlanBody::PrepareDevices { volumes, .. } => {
            anyhow::ensure!(
                volumes.len() == context.volume_grants.len(),
                "PrepareDevices plan changed the refreshed Volume set"
            );
            for (planned, current) in volumes.iter().zip(&context.volume_grants) {
                anyhow::ensure!(
                    planned.volume == current.authority_receipt.volume
                        && planned.attachment_id == current.volume.attachment_id
                        && planned.attachment_epoch == current.volume.attachment_epoch
                        && planned.acquire_origin == current.acquire_origin
                        && planned.lineage_data_directory
                            == current.planned_local_lineage_data_directory
                        && remote_head_is_same_or_later(
                            &current.authoritative_head,
                            &planned.launch_head,
                        ),
                    "PrepareDevices refresh changed immutable Volume lineage or regressed its head"
                );
            }
        }
        _ => {
            anyhow::ensure!(
                context.runtime_progress.volumes.len() == context.volume_grants.len(),
                "atomic Start refreshed progress changed the Volume set"
            );
            for (progress, current) in context
                .runtime_progress
                .volumes
                .iter()
                .zip(&context.volume_grants)
            {
                anyhow::ensure!(
                    progress.volume_id == current.volume.volume_id
                        && progress.disk_id == current.volume.disk_id
                        && progress.attachment_id == current.volume.attachment_id
                        && progress.attachment_epoch == current.volume.attachment_epoch
                        && progress.acquire_origin == current.acquire_origin
                        && remote_head_is_same_or_later(
                            &current.authoritative_head,
                            &progress.authority_head,
                        ),
                    "atomic Start refresh changed progress lineage or regressed its head"
                );
            }
        }
    }
    Ok(())
}

fn decode_platform_receipt(bytes: &ExactBytes) -> Result<InstalledAtomicStartPlatformReceipt> {
    anyhow::ensure!(
        !bytes.as_slice().is_empty() && bytes.as_slice().len() <= PLATFORM_PLAN_MAX_BYTES,
        "installed atomic Start platform receipt has an invalid length"
    );
    let receipt: InstalledAtomicStartPlatformReceipt = serde_json::from_slice(bytes.as_slice())
        .context("decode installed atomic Start platform receipt")?;
    anyhow::ensure!(
        serde_json::to_vec(&receipt)? == bytes.as_slice(),
        "installed atomic Start platform receipt is not canonical JSON"
    );
    Ok(receipt)
}

fn validate_platform_receipt_binding(
    receipt: &InstalledAtomicStartPlatformReceipt,
    command: &LifecycleCommandEnvelope,
    phase: AtomicStartRuntimeEffectPhase,
    runtime_incarnation: &RandomId128,
    platform_plan_digest: &Sha256Digest,
) -> Result<()> {
    anyhow::ensure!(
        receipt.version == PLAN_VERSION
            && receipt.phase == phase
            && receipt.node_id == command.node_id
            && receipt.cat_id == command.cat_id
            && receipt.operation_id == command.operation_id
            && receipt.request_fingerprint == command.request_fingerprint
            && receipt.runtime_incarnation == *runtime_incarnation
            && receipt.platform_plan_digest == *platform_plan_digest,
        "installed atomic Start platform receipt changed command/plan binding"
    );
    Ok(())
}

fn completed_plan(
    context: &AtomicStartRuntimeContext,
    phase: AtomicStartRuntimeEffectPhase,
) -> Result<InstalledAtomicStartPlatformPlan> {
    let completed = context
        .completed_effects
        .get(phase_index(phase))
        .context("atomic Start phase lacks its completed platform plan")?;
    anyhow::ensure!(completed.phase == phase, "completed platform phase changed");
    decode_platform_plan(&completed.platform_plan)
}

fn completed_receipt(
    context: &AtomicStartRuntimeContext,
    phase: AtomicStartRuntimeEffectPhase,
) -> Result<InstalledAtomicStartPlatformReceipt> {
    let completed = context
        .completed_effects
        .get(phase_index(phase))
        .context("atomic Start phase lacks its completed platform receipt")?;
    anyhow::ensure!(completed.phase == phase, "completed platform phase changed");
    decode_platform_receipt(&completed.platform_receipt)
}

fn planned_blockd_config(
    config: &InstalledAtomicStartBlockdConfig,
) -> Result<PlannedBlockdLaunchConfig> {
    Ok(PlannedBlockdLaunchConfig {
        executable: host_path(config.blockd_binary.clone())?,
        metadata_store_adapter: config.metadata_store.name.clone(),
        metadata_store_options: config.metadata_store.config.to_cli(),
        object_store_adapter: config.object_store.name.clone(),
        object_store_options: config.object_store.config.to_cli(),
        lease_ttl_ms: WireU64::new(
            u64::try_from(config.lease_ttl_ms).context("blockd lease TTL is negative")?,
        )
        .context("blockd lease TTL is outside wire domain")?,
        max_staged_bytes: WireU64::new(config.max_staged_bytes)
            .context("blockd staged byte cap is outside wire domain")?,
        max_staged_packs: WireU64::new(
            u64::try_from(config.max_staged_packs).context("blockd pack cap overflows u64")?,
        )
        .context("blockd pack cap is outside wire domain")?,
        max_local_bytes: WireU64::new(config.max_local_bytes)
            .context("blockd local byte cap is outside wire domain")?,
    })
}

fn legacy_network_config(network: &RuntimeNetworkConfig) -> NetworkConfig {
    match network {
        RuntimeNetworkConfig::IsolatedIpv4 {
            network_id,
            guest_mac,
            guest_ipv4,
            prefix_length,
            gateway_ipv4,
        } => NetworkConfig {
            kind: IsolatedIpv4Kind::IsolatedIpv4,
            network_id: network_id.clone(),
            guest_mac: guest_mac.clone(),
            guest_ipv4: guest_ipv4.clone(),
            prefix_length: *prefix_length,
            gateway_ipv4: gateway_ipv4.clone(),
        },
    }
}

fn persistent_filesystems(
    command: &LifecycleCommandEnvelope,
    context: &AtomicStartRuntimeContext,
) -> Result<Vec<PlannedPersistentFilesystem>> {
    command
        .runtime_config
        .volumes
        .iter()
        .zip(&context.volume_grants)
        .filter_map(|(volume, grant)| match &volume.guest_binding {
            RuntimeVolumeGuestBinding::PersistentExt4 {
                filesystem_uuid,
                mount_path,
            } => Some(Ok(PlannedPersistentFilesystem {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                attachment_id: grant.volume.attachment_id.clone(),
                attachment_epoch: grant.volume.attachment_epoch,
                guest_device: GuestDeviceIdentity {
                    serial: volume.guest_device_serial.clone(),
                    slot: volume.guest_device_slot,
                },
                filesystem_uuid: filesystem_uuid.clone(),
                mount_path: mount_path.clone(),
            })),
            RuntimeVolumeGuestBinding::RootBoot => None,
        })
        .collect()
}

fn persistent_initialization_binding(
    command: &LifecycleCommandEnvelope,
    volume: &RuntimeVolumeConfig,
    grant: &AtomicStartVolumeGrant,
) -> Result<LifecyclePersistentInitializationBinding> {
    let binding = LifecyclePersistentInitializationBinding {
        scope: LifecycleVolumeCommandScope {
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            cat_id: command.cat_id.clone(),
            node_id: command.node_id.clone(),
            placement_identity: command.placement_identity.clone(),
        },
        runtime_config_id: command.runtime_config.config_id.clone(),
        runtime_config_digest: command.runtime_config.config_digest.clone(),
        volume: volume.clone(),
        start_grant: LifecycleStoredStartVolumeGrant {
            receipt: grant.authority_receipt.clone(),
            receipt_digest: grant.grant_receipt_digest.clone(),
        },
    };
    validate_lifecycle_persistent_initialization_binding(&binding)
        .map_err(|_| anyhow::anyhow!("Persistent initialization binding is not canonical"))?;
    Ok(binding)
}

fn artifact_from_release_member(
    path: &Path,
    member: &cats_api::runtime_artifacts::GuestRuntimeReleaseMember,
) -> Result<RuntimeLaunchArtifact> {
    anyhow::ensure!(
        path.file_name().and_then(|name| name.to_str()) == Some(member.path.as_str()),
        "installed Guest boot path differs from signed release member"
    );
    Ok(RuntimeLaunchArtifact {
        path: host_path(path.to_path_buf())?,
        length: member.size_bytes,
        content_sha256: member.sha256.clone(),
    })
}

fn artifact_from_path(path: &Path, deadline: Instant) -> Result<RuntimeLaunchArtifact> {
    let mut file = File::open(path).with_context(|| format!("open artifact {}", path.display()))?;
    let before = file.metadata()?;
    anyhow::ensure!(
        before.is_file() && before.nlink() == 1 && before.len() > 0,
        "installed artifact is not one nonempty single-link regular file"
    );
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; ARTIFACT_READ_BUFFER_BYTES];
    loop {
        anyhow::ensure!(Instant::now() < deadline, "artifact hash deadline elapsed");
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    anyhow::ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "installed artifact changed while hashing"
    );
    Ok(RuntimeLaunchArtifact {
        path: host_path(path.to_path_buf())?,
        length: WireU64::new(before.len()).context("artifact length is outside wire domain")?,
        content_sha256: Sha256Digest::from_bytes(digest.finalize().into()),
    })
}

fn service_id(prefix: &str, identity: &RandomId128) -> Result<Id> {
    Id::new(format!("{prefix}-{}.service", identity.as_str()))
        .context("atomic Start service identity is outside wire domain")
}

fn fresh_random() -> Result<RandomId128> {
    RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .context("generate atomic Start physical identity")
}

fn guest_filesystem_timeout_ms(configured: Duration) -> Result<u32> {
    let millis = configured
        .as_millis()
        .clamp(1, u128::from(FILESYSTEM_CONTROL_MAX_TIMEOUT_MS_V1));
    u32::try_from(millis).context("Guest filesystem timeout exceeds u32")
}

fn unique_random(seen: &mut BTreeSet<RandomId128>) -> Result<RandomId128> {
    for _ in 0..4 {
        let value = fresh_random()?;
        if seen.insert(value.clone()) {
            return Ok(value);
        }
    }
    anyhow::bail!("atomic Start physical identity generator repeatedly collided")
}

fn nbd_candidate_index(identity: &RandomId128, count: u32) -> u32 {
    let digest = Sha256::digest(identity.as_str().as_bytes());
    u32::from_be_bytes(
        digest[..4]
            .try_into()
            .expect("SHA-256 prefix has four bytes"),
    ) % count
}

fn guest_cid_from_identity(identity: &RandomId128) -> u32 {
    let digest = Sha256::digest(identity.as_str().as_bytes());
    let raw = u32::from_be_bytes(
        digest[..4]
            .try_into()
            .expect("SHA-256 prefix has four bytes"),
    );
    3 + raw % (u32::MAX - 3)
}

fn host_path(path: PathBuf) -> Result<HostPath> {
    HostPath::new(
        path.to_str()
            .context("atomic Start Host path is not UTF-8")?
            .to_owned(),
    )
    .context("atomic Start Host path is outside wire domain")
}

fn current_unix_millis() -> Result<UnixMillis> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Host wall clock precedes Unix epoch")?;
    let millis = u64::try_from(elapsed.as_millis()).context("Host wall clock overflows u64")?;
    UnixMillis::new(millis).context("Host wall clock is outside wire domain")
}

fn digest_serialized(domain: &[u8], value: &impl Serialize) -> Result<Sha256Digest> {
    let canonical = serde_json::to_vec(value).context("encode atomic Start digest preimage")?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update((canonical.len() as u64).to_be_bytes());
    digest.update(canonical);
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn sha256_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn zero_digest() -> Sha256Digest {
    Sha256Digest::from_bytes([0; 32])
}

fn validate_production_config(config: &InstalledAtomicStartRuntimeConfig) -> Result<()> {
    for (label, path) in [
        ("StateDirectory", config.physical.state_directory.path()),
        ("systemctl", config.physical.systemctl_binary.as_path()),
        ("systemd-run", config.systemd_run_binary.as_path()),
        ("cgroup root", config.physical.cgroup_root.as_path()),
        ("proc root", config.physical.proc_root.as_path()),
        ("ip", config.physical.ip_binary.as_path()),
        (
            "network reservation root",
            config.physical.network_class_root.as_path(),
        ),
        ("VMM launcher", config.ch.vmm_launcher_bin.as_path()),
        ("Cloud Hypervisor", config.ch.ch_bin.as_path()),
        ("Guest kernel", config.ch.kernel.as_path()),
        ("blockd", config.blockd.blockd_binary.as_path()),
    ] {
        anyhow::ensure!(
            path.is_absolute(),
            "atomic Start {label} path is not absolute"
        );
    }
    if let Some(initramfs) = &config.ch.initramfs {
        anyhow::ensure!(
            initramfs.is_absolute(),
            "atomic Start initramfs is not absolute"
        );
    }
    anyhow::ensure!(
        !config.effect_timeout.is_zero()
            && !config.guest_ready_timeout.is_zero()
            && duration_millis(config.effect_timeout).is_some()
            && duration_millis(config.guest_ready_timeout).is_some(),
        "atomic Start deadlines are zero or outside the wire integer domain"
    );
    anyhow::ensure!(
        config.blockd.metadata_store.name == "postgres"
            && !config.blockd.object_store.name.is_empty()
            && config.blockd.lease_ttl_ms > 0
            && config.blockd.max_staged_bytes > 0
            && config.blockd.max_staged_packs > 0
            && config.blockd.max_local_bytes > 0,
        "atomic Start blockd adapter or resource limits are invalid"
    );
    anyhow::ensure!(
        config.ch.vhost_user_queues > 0
            && config.ch.vhost_user_queue_size.is_power_of_two()
            && config.ch.vhost_user_queue_size >= 2,
        "atomic Start vhost-user queue shape is invalid"
    );
    match config.ch.block_path {
        BlockPath::KernelNbd => anyhow::ensure!(
            config.ch.nbd_client_bin.is_absolute()
                && config.ch.nbd_devices > 0
                && config.physical.kernel_nbd.is_some(),
            "atomic Start kernel-NBD coordinates are incomplete"
        ),
        BlockPath::VhostUser => anyhow::ensure!(
            config.physical.kernel_nbd.is_none(),
            "atomic Start vhost-user composition unexpectedly owns a kernel-NBD pool"
        ),
    }
    config
        .physical
        .state_directory
        .try_clone_directory()
        .context("retain atomic Start StateDirectory")?;
    anyhow::ensure!(
        config.ch.boot_contract.is_some(),
        "production atomic Start requires the signed Guest boot contract"
    );
    match &config.object_write_mode {
        InstalledAtomicStartObjectWriteMode::Gateway {
            gateway_origin,
            control_plane_origin,
            ..
        } => anyhow::ensure!(
            gateway_origin.starts_with("https://") && control_plane_origin.starts_with("https://"),
            "atomic Start Gateway mode requires HTTPS origins"
        ),
        InstalledAtomicStartObjectWriteMode::DirectProvider => anyhow::ensure!(
            config.blockd.object_store.name == "file",
            "DirectProvider is closed to the installed file adapter; remote providers require Gateway credentials"
        ),
    }
    Ok(())
}

fn installed_config_digest(config: &InstalledAtomicStartRuntimeConfig) -> Result<Sha256Digest> {
    let input = InstalledConfigDigestInput {
        version: PLAN_VERSION,
        node_id: &config.physical.node_id,
        state_directory: path_text(config.physical.state_directory.path())?,
        systemctl_binary: path_text(&config.physical.systemctl_binary)?,
        systemd_run_binary: path_text(&config.systemd_run_binary)?,
        cgroup_root: path_text(&config.physical.cgroup_root)?,
        proc_root: path_text(&config.physical.proc_root)?,
        ip_binary: path_text(&config.physical.ip_binary)?,
        network_class_root: path_text(&config.physical.network_class_root)?,
        vmm_launcher_binary: path_text(&config.ch.vmm_launcher_bin)?,
        cloud_hypervisor_binary: path_text(&config.ch.ch_bin)?,
        kernel: path_text(&config.ch.kernel)?,
        initramfs: config.ch.initramfs.as_deref().map(path_text).transpose()?,
        kernel_cmdline: &config.ch.cmdline,
        block_path: config.ch.block_path.as_str(),
        block_direct: config.ch.block_direct,
        vhost_user_queues: config.ch.vhost_user_queues,
        vhost_user_queue_size: config.ch.vhost_user_queue_size,
        nbd_client_binary: path_text(&config.ch.nbd_client_bin)?,
        nbd_devices: config.ch.nbd_devices,
        blockd_binary: path_text(&config.blockd.blockd_binary)?,
        metadata_store_adapter: &config.blockd.metadata_store.name,
        metadata_store_options: config.blockd.metadata_store.config.to_cli(),
        object_store_adapter: &config.blockd.object_store.name,
        object_store_options: config.blockd.object_store.config.to_cli(),
        blockd_lease_ttl_ms: config.blockd.lease_ttl_ms,
        max_staged_bytes: config.blockd.max_staged_bytes,
        max_staged_packs: config.blockd.max_staged_packs,
        max_local_bytes: config.blockd.max_local_bytes,
        object_write_mode: match config.object_write_mode {
            InstalledAtomicStartObjectWriteMode::Gateway { .. } => "gateway",
            InstalledAtomicStartObjectWriteMode::DirectProvider => "direct_provider",
        },
        effect_timeout_ms: duration_millis(config.effect_timeout)
            .context("atomic Start effect timeout overflows wire")?,
        guest_ready_timeout_ms: duration_millis(config.guest_ready_timeout)
            .context("atomic Start Guest timeout overflows wire")?,
    };
    digest_serialized(CONFIG_DIGEST_DOMAIN, &input)
}

fn duration_millis(duration: Duration) -> Option<u64> {
    u64::try_from(duration.as_millis())
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .context("installed atomic Start path is not UTF-8")
}

impl AtomicStartRuntimePort for InstalledAtomicStartRuntimePort {
    fn configured_effect_timeout_ms(&self) -> WireU64 {
        WireU64::new(
            duration_millis(self.config.effect_timeout)
                .expect("validated installed atomic Start effect timeout"),
        )
        .expect("validated installed atomic Start effect timeout is nonzero")
    }

    fn plan_start_effect(
        &self,
        command: &LifecycleCommandEnvelope,
        phase: AtomicStartRuntimeEffectPhase,
        context: &AtomicStartRuntimeContext,
    ) -> Result<ExactBytes> {
        self.validate_context(command, phase, context)?;
        let body = match phase {
            AtomicStartRuntimeEffectPhase::PrepareRoot => {
                self.plan_prepare_root(command, context)?
            }
            AtomicStartRuntimeEffectPhase::PrepareDevices => {
                self.plan_prepare_devices(command, context)?
            }
            AtomicStartRuntimeEffectPhase::PrepareNetwork => {
                self.plan_prepare_network(command, context)?
            }
            AtomicStartRuntimeEffectPhase::ActivateRuntime => {
                self.plan_activate_runtime(command, context)?
            }
            AtomicStartRuntimeEffectPhase::FormatPersistentVolumes => {
                self.plan_format_persistent(command, context)?
            }
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized => {
                self.plan_commit_persistent(command, context)?
            }
            AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission => {
                self.plan_guest_ready(command, context)?
            }
        };
        encode_platform_plan(command, phase, context, &self.config_digest, body)
    }

    fn inspect_or_apply_start_effect(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let plan = decode_platform_plan(&request.platform_plan)?;
        validate_platform_plan_binding(
            &plan,
            command,
            request.phase,
            &request.context,
            &self.config_digest,
        )?;
        let deadline = self.effect_deadline(command, &request.context)?;
        let outcome = if request.phase != AtomicStartRuntimeEffectPhase::PrepareRoot
            && !self.completed_root_object_write_session_is_current(request)?
        {
            // Once PrepareRoot has published its authorization/credential
            // evidence, replacing the AgentSession is no longer a provable
            // zero-use edge.  In particular, PrepareDevices must not start a
            // blockd with the old session's credential and discover the
            // mismatch only after the process exists.  The only legal
            // SessionRebindRequired path is the PrepareRoot cleanup routine,
            // which proves that no consumer or authorization was created.
            definite_runtime_failure(
                request,
                cats_api::runtime_lifecycle::CommandFailureReason::InvalidLocalPrecondition,
            )
        } else {
            self.inspect_or_apply(command, request, &plan, deadline)
        };
        match outcome {
            Ok(AtomicStartRuntimeEffectOutcome::Failed(mut failure)) => {
                failure.runtime_progress = Some(self.discover_failed_runtime_progress(
                    command,
                    request,
                    &plan,
                    self.failure_discovery_deadline(deadline)?,
                )?);
                Ok(AtomicStartRuntimeEffectOutcome::Failed(failure))
            }
            Err(error) => match error.downcast_ref::<DefinitePhysicalFailure>() {
                Some(failure) => definite_runtime_failure_with_progress(
                    request,
                    failure.reason,
                    self.discover_failed_runtime_progress(
                        command,
                        request,
                        &plan,
                        self.failure_discovery_deadline(deadline)?,
                    )?,
                ),
                None => Err(error),
            },
            outcome => outcome,
        }
    }
}

impl InstalledAtomicStartRuntimePort {
    fn failure_discovery_deadline(&self, phase_deadline: Instant) -> Result<Instant> {
        let now = Instant::now();
        if now < phase_deadline {
            return Ok(phase_deadline);
        }
        now.checked_add(self.config.effect_timeout)
            .context("atomic Start failure discovery deadline overflow")
    }

    fn completed_root_object_write_session_is_current(
        &self,
        request: &AtomicStartRuntimeEffectRequest,
    ) -> Result<bool> {
        let root = completed_plan(&request.context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let object_write = match &root.body {
            InstalledAtomicStartPlanBody::PrepareRoot { object_write, .. } => object_write,
            InstalledAtomicStartPlanBody::PrepareSuspendedRoot { .. } => return Ok(true),
            InstalledAtomicStartPlanBody::DefiniteFailure { .. } => {
                anyhow::bail!("completed PrepareRoot plan contains a definite failure")
            }
            _ => anyhow::bail!("completed PrepareRoot plan has another schema"),
        };
        let current = self
            .config
            .admission_registry
            .current_agent_session()
            .context("read current AgentSession before consuming Root ObjectWrite evidence")?;
        Ok(object_write_session_is_current(
            object_write,
            &request.context.volume_lease_session,
            &current,
        ))
    }

    fn discover_failed_runtime_progress(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        deadline: Instant,
    ) -> Result<InstalledRuntimeProgressManifest> {
        let mut progress = request.context.runtime_progress.clone();
        let effect = StartPhysicalEffectContext { deadline };
        match &plan.body {
            InstalledAtomicStartPlanBody::PrepareRoot { volumes, .. } => {
                anyhow::ensure!(
                    progress.volumes.len() == volumes.len(),
                    "PrepareRoot failure discovery changed the Volume set"
                );
                for (planned, installed) in volumes.iter().zip(&mut progress.volumes) {
                    let lineage = AttachmentLineageIdentity {
                        volume_id: planned.volume.volume_id.clone(),
                        attachment_id: planned.attachment_id.clone(),
                        attachment_epoch: planned.attachment_epoch,
                        acquire_origin: planned.acquire_origin.clone(),
                        node_id: command.node_id.clone(),
                        placement_epoch: command.placement_identity.placement_epoch,
                    };
                    let lineage_path =
                        Path::new(planned.lineage_data_directory.as_str()).join("identity.json");
                    if inspect_exact_managed_file(
                        self.config.physical.state_directory.path(),
                        &lineage_path,
                        &canonical_json(&lineage)?,
                        0o600,
                    )? == ManagedFileInspection::Exact
                    {
                        let current_head = self.inspect_exact_volume_head(command, planned)?;
                        record_exact_root_lineage_failure_progress(
                            installed,
                            planned,
                            current_head,
                        )?;
                    }
                }
            }
            InstalledAtomicStartPlanBody::PrepareDevices {
                blockd, volumes, ..
            } => {
                self.discover_failed_device_progress(
                    command,
                    request,
                    blockd,
                    volumes,
                    &effect,
                    &mut progress,
                )?;
            }
            InstalledAtomicStartPlanBody::PrepareNetwork { reservation, .. } => {
                let expected =
                    InstalledAtomicStartNetworkReservation::new(command, plan, reservation)?;
                let artifact = inspect_exact_managed_file(
                    &self.config.physical.network_class_root,
                    Path::new(reservation.artifact_path.as_str()),
                    &canonical_json(&expected)?,
                    0o600,
                )?;
                let snapshot =
                    ch::inspect_host_network_snapshot(&self.config.physical.ip_binary, &effect)?;
                if artifact == ManagedFileInspection::Exact
                    && snapshot.reserved_network_state(&reservation.identity)?
                        == ReservedHostNetworkState::Exact
                {
                    progress.network = Some(InstalledRuntimeNetworkManifest {
                        identity: reservation.identity.clone(),
                    });
                }
            }
            InstalledAtomicStartPlanBody::ActivateRuntime { launch, mode, .. } => {
                let spec = AtomicVmmLaunchSpec::new(
                    command.node_id.clone(),
                    command.cat_id.clone(),
                    command.operation_id.clone(),
                    command.request_fingerprint.clone(),
                    plan.plan_digest.clone(),
                    host_path(self.config.physical.state_directory.path().to_path_buf())?,
                    launch.as_ref().clone(),
                    mode.clone(),
                )?;
                let process = match inspect_atomic_vmm_service(
                    &self.config,
                    &command.cat_id,
                    &spec,
                    &effect,
                )? {
                    AtomicVmmServiceInspection::Exact(process)
                    | AtomicVmmServiceInspection::Paused(process) => Some(process),
                    AtomicVmmServiceInspection::Absent
                    | AtomicVmmServiceInspection::Starting
                    | AtomicVmmServiceInspection::Conflict => None,
                };
                if let Some(process) = process {
                    progress.vmm = Some(InstalledRuntimeVmmManifest {
                        process,
                        parent_slice_id: cat_execution_slice_id(&command.cat_id),
                        systemd_unit_id: launch.scope_id.clone(),
                        api_socket_path: launch.api_socket_path.clone(),
                        vsock_socket_path: launch.vsock_socket_path.clone(),
                        memory_file_path: launch.memory_file_path.clone(),
                        launch_identity: launch.clone(),
                    });
                }
            }
            InstalledAtomicStartPlanBody::DefiniteFailure { .. }
            | InstalledAtomicStartPlanBody::PrepareSuspendedRoot { .. }
            | InstalledAtomicStartPlanBody::PrepareSuspendedDevices { .. }
            | InstalledAtomicStartPlanBody::PrepareSuspendedNetwork { .. }
            | InstalledAtomicStartPlanBody::ResumeSuspendedRuntime { .. }
            | InstalledAtomicStartPlanBody::FormatPersistentVolumes { .. }
            | InstalledAtomicStartPlanBody::CommitPersistentInitialized { .. }
            | InstalledAtomicStartPlanBody::GuestReadyAndAdmission { .. } => {}
        }
        InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            progress.vmm,
            progress.network,
            progress.volumes,
            progress.artifact_classifications,
        )
    }

    fn discover_failed_device_progress(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        blockd: &PlannedBlockdLaunchConfig,
        volumes: &[PlannedDevice],
        effect: &StartPhysicalEffectContext,
        progress: &mut InstalledRuntimeProgressManifest,
    ) -> Result<()> {
        anyhow::ensure!(
            progress.volumes.len() == volumes.len(),
            "PrepareDevices failure discovery changed the Volume set"
        );
        let root = completed_plan(&request.context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let object_write = match &root.body {
            InstalledAtomicStartPlanBody::PrepareRoot { object_write, .. } => object_write,
            _ => return Ok(()),
        };
        for ((planned, installed), grant) in volumes
            .iter()
            .zip(&mut progress.volumes)
            .zip(&request.context.volume_grants)
        {
            anyhow::ensure!(
                planned.volume.volume_id == installed.volume_id,
                "PrepareDevices failure discovery reordered Volumes"
            );
            let launch = SystemdServiceLaunch {
                unit_id: planned.serving_service_id.clone(),
                executable: PathBuf::from(blockd.executable.as_str()),
                arguments: serving_blockd_arguments(blockd, planned, object_write)?,
            };
            let process = match inspect_systemd_service(
                &self.config.physical,
                &command.cat_id,
                &launch,
                effect,
            ) {
                Ok(SystemdServiceInspection::Exact(process)) => Some(process),
                // This is enrichment of an already-definite failure.  A
                // non-exact/temporarily unreadable process must not be claimed
                // as this Start; the StrongStop complete scan remains the
                // cleanup oracle for anything not attributed here.
                Ok(SystemdServiceInspection::Absent | SystemdServiceInspection::Starting)
                | Err(_) => None,
            };
            let Some(process) = process else {
                continue;
            };
            let exact_status = blockd_status(
                Path::new(planned.control_socket_path.as_str()),
                process.pid,
                effect,
            )
            .and_then(|status| validate_serving_blockd_status(command, planned, grant, &status))
            .is_ok();
            if !exact_status {
                continue;
            }
            installed.blockd = Some(process);
            installed.blockd_control_socket_path = Some(planned.control_socket_path.clone());
            installed.frontend = match &planned.frontend {
                PrepareDeviceFrontend::VhostUserBlk { socket_path, .. }
                    if inspect_exact_socket(Path::new(socket_path.as_str())).is_ok() =>
                {
                    Some(InstalledRuntimeBlockFrontend::VhostUserBlk {
                        socket_path: socket_path.clone(),
                    })
                }
                PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    device_path,
                    ..
                } => {
                    let Some(kernel) = self.config.physical.kernel_nbd.as_ref() else {
                        continue;
                    };
                    let Some(unit_id) = planned.kernel_nbd_client_service_id.as_ref() else {
                        continue;
                    };
                    let expectation = KernelNbdClientExpectation::new(
                        kernel,
                        &command.cat_id,
                        unit_id,
                        listener_socket_path,
                        device_path,
                        planned.volume.size_bytes,
                    )?;
                    match inspect_exact_kernel_nbd_client(&self.config.physical, &expectation) {
                        Ok(Some(client))
                            if validate_kernel_nbd_systemd_unit(
                                &self.config.physical,
                                &expectation,
                                effect,
                            )
                            .is_ok() =>
                        {
                            Some(InstalledRuntimeBlockFrontend::KernelNbd {
                                device_path: device_path.clone(),
                                client,
                            })
                        }
                        Ok(Some(_) | None) | Err(_) => None,
                    }
                }
                PrepareDeviceFrontend::VhostUserBlk { .. } => None,
            };
        }
        Ok(())
    }

    fn validate_context(
        &self,
        command: &LifecycleCommandEnvelope,
        phase: AtomicStartRuntimeEffectPhase,
        context: &AtomicStartRuntimeContext,
    ) -> Result<()> {
        let LifecycleCommand::Start(start) = &command.command else {
            anyhow::bail!("atomic Start runtime port received another command kind")
        };
        anyhow::ensure!(
            command.node_id == self.config.physical.node_id
                && context.source == start.source
                && context.effect_deadline_unix_ms == start.effect_deadline_unix_ms
                && context.volume_grants.len() == command.runtime_config.volumes.len()
                && context.completed_effects.len() == phase_index(phase),
            "atomic Start runtime context does not name the exact next command phase"
        );
        let mut grant_volumes = BTreeSet::new();
        for (grant, volume) in context
            .volume_grants
            .iter()
            .zip(&command.runtime_config.volumes)
        {
            validate_grant(command, context, grant, volume)?;
            anyhow::ensure!(
                Path::new(grant.planned_local_lineage_data_directory.as_str())
                    .starts_with(self.config.physical.state_directory.path()),
                "atomic Start Volume lineage is outside StateDirectory"
            );
            anyhow::ensure!(
                grant_volumes.insert(grant.volume.volume_id.clone()),
                "atomic Start runtime context repeats a Volume grant"
            );
        }
        for (index, completed) in context.completed_effects.iter().enumerate() {
            let expected = phase_at(index).context("too many completed atomic Start effects")?;
            anyhow::ensure!(
                completed.phase == expected,
                "atomic Start completed effects are not a contiguous prefix"
            );
            let prior_plan = decode_platform_plan(&completed.platform_plan)?;
            validate_platform_plan_binding(
                &prior_plan,
                command,
                expected,
                // The receipt's original context is itself inside its plan.
                // Current grants may have advanced by renewal, so the closed
                // plan validator below checks command/incarnation and its own
                // saved grant sequence rather than substituting this context.
                context,
                &self.config_digest,
            )?;
            anyhow::ensure!(
                prior_plan.plan_digest == completed.platform_plan_digest,
                "completed atomic Start platform plan digest changed"
            );
            let receipt = decode_platform_receipt(&completed.platform_receipt)?;
            validate_platform_receipt_binding(
                &receipt,
                command,
                expected,
                &context.runtime_incarnation,
                &completed.platform_plan_digest,
            )?;
            anyhow::ensure!(
                completed.receipt_digest
                    == atomic_start_platform_receipt_digest(
                        command,
                        expected,
                        &completed.platform_plan_digest,
                        &completed.platform_receipt,
                    )?,
                "completed atomic Start platform receipt digest changed"
            );
        }
        let now = current_unix_millis()?;
        anyhow::ensure!(
            now < context.effect_deadline_unix_ms,
            "atomic Start effect deadline elapsed before planning"
        );
        Ok(())
    }

    fn effect_deadline(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<Instant> {
        let LifecycleCommand::Start(start) = &command.command else {
            anyhow::bail!("atomic Start effect received another command kind")
        };
        anyhow::ensure!(
            start.effect_deadline_unix_ms == context.effect_deadline_unix_ms,
            "atomic Start effect deadline changed"
        );
        let now = current_unix_millis()?;
        let wall_remaining = Duration::from_millis(
            context
                .effect_deadline_unix_ms
                .get()
                .saturating_sub(now.get()),
        );
        // Planning already rejects an elapsed command deadline. Apply/replay
        // must still get one bounded read-only discovery window after that
        // wall deadline, otherwise an exact postcondition (including a lost
        // response) could remain Executing forever. Mutation authority below
        // independently rejects the elapsed persisted deadline.
        let budget = bounded_physical_discovery_budget(wall_remaining, self.config.effect_timeout);
        Instant::now()
            .checked_add(budget)
            .context("atomic Start monotonic deadline overflow")
    }

    /// A wire Unix expiry is useful only for protocol validation. Physical
    /// mutation authority comes from the process-local grant-receipt budget;
    /// an Agent restart therefore returns false until the same durable plan
    /// has been renewed in the new process.
    fn effect_authority_has_budget(
        &self,
        request: &AtomicStartRuntimeEffectRequest,
        deadline: Instant,
    ) -> Result<bool> {
        let now = Instant::now();
        if !phase_and_command_deadlines_are_live(
            now,
            deadline,
            current_unix_millis()?,
            request.context.effect_deadline_unix_ms,
        ) {
            return Ok(false);
        }
        let current_session = self
            .config
            .admission_registry
            .current_agent_session()
            .context("read current AgentSession for Start mutation authority")?;
        if current_session != request.context.volume_lease_session {
            return Ok(false);
        }
        let required = deadline
            .saturating_duration_since(now)
            .checked_add(Duration::from_millis(START_VOLUME_LEASE_SAFETY_MARGIN_MS))
            .context("atomic Start lease phase budget overflows")?;
        let budget = runtime_context_has_monotonic_lease_budget(&request.context, required)?;
        Ok(lease_session_and_budget_are_current(
            &current_session,
            &request.context.volume_lease_session,
            budget,
        ))
    }

    fn ensure_fresh_effect_authority(
        &self,
        request: &AtomicStartRuntimeEffectRequest,
        deadline: Instant,
    ) -> Result<()> {
        if self.effect_authority_has_budget(request, deadline)? {
            return Ok(());
        }
        if !phase_and_command_deadlines_are_live(
            Instant::now(),
            deadline,
            current_unix_millis()?,
            request.context.effect_deadline_unix_ms,
        ) {
            return Err(definite_physical_failure(
                cats_api::runtime_lifecycle::CommandFailureReason::InvalidLocalPrecondition,
            ));
        }
        anyhow::bail!("atomic Start lacks a process-local lease budget for this mutation")
    }

    fn publish_exact_with_authority(
        &self,
        request: &AtomicStartRuntimeEffectRequest,
        effect: &StartPhysicalEffectContext,
        managed_root: &Path,
        target: &Path,
        bytes: &[u8],
        mode: u32,
    ) -> Result<()> {
        match inspect_exact_managed_file(managed_root, target, bytes, mode)? {
            ManagedFileInspection::Exact => Ok(()),
            ManagedFileInspection::Conflict => Err(definite_physical_failure(
                cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
            )),
            ManagedFileInspection::Absent => {
                self.ensure_fresh_effect_authority(request, effect.deadline())?;
                publish_exact_managed_file(managed_root, target, bytes, mode)
            }
        }
    }

    fn publish_blockd_socket_owner_with_authority(
        &self,
        request: &AtomicStartRuntimeEffectRequest,
        effect: &StartPhysicalEffectContext,
        owner: &InstalledAtomicStartBlockdSocketOwner,
    ) -> Result<()> {
        anyhow::ensure!(
            owner.owner_digest == blockd_socket_owner_digest(owner)?,
            "blockd socket owner digest is invalid"
        );
        let marker = blockd_owner_directory(owner)?
            .join(cats_blockd::runtime_socket_namespace::BLOCKD_SOCKET_OWNER_MARKER_BASENAME);
        let installed = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed();
        self.publish_exact_with_authority(
            request,
            effect,
            Path::new(installed.path().as_str()),
            &marker,
            &canonical_json(owner)?,
            0o600,
        )
    }

    fn plan_prepare_root(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<InstalledAtomicStartPlanBody> {
        let same_node_restart_source = match self.plan_same_node_restart_source(command, context)? {
            SameNodeRestartPlanning::NotApplicable => None,
            SameNodeRestartPlanning::Exact(source) => Some(source),
            SameNodeRestartPlanning::DefiniteInvalid => {
                return Ok(InstalledAtomicStartPlanBody::DefiniteFailure {
                    reason: cats_api::runtime_lifecycle::CommandFailureReason::SnapshotInvalid,
                })
            }
        };
        if let Some(source) = same_node_restart_source.as_ref() {
            if matches!(
                source.physical.source,
                SameNodeOwnedPredecessorSource::Suspended { .. }
            ) {
                anyhow::ensure!(
                    context.source == StartSource::SameNodeSuspended,
                    "Suspended physical carrier belongs to another Start source"
                );
                return Ok(InstalledAtomicStartPlanBody::PrepareSuspendedRoot {
                    source: Box::new(source.clone()),
                });
            }
        }
        let deadline = self.effect_deadline(command, context)?;
        let manifest = match read_image_manifest_until(
            self.config.root_image_store.as_ref(),
            &command.runtime_config.boot_image_digest,
            deadline,
        ) {
            Ok(manifest) => manifest,
            Err(ImageManifestReadError::BackendUnavailable { .. }) => {
                anyhow::bail!("immutable Root image manifest read is ambiguous")
            }
            Err(
                ImageManifestReadError::NotFound { .. }
                | ImageManifestReadError::TooLarge { .. }
                | ImageManifestReadError::Corrupt { .. },
            ) => {
                return Ok(InstalledAtomicStartPlanBody::DefiniteFailure {
                    reason: cats_api::runtime_lifecycle::CommandFailureReason::ImageUnavailable,
                })
            }
        };
        let image_manifest = encode_image_manifest(&manifest).map_err(|problem| {
            anyhow::anyhow!("encode exact immutable Root image manifest: {problem:?}")
        })?;
        let image_manifest_digest = sha256_bytes(&image_manifest);
        let root = command
            .runtime_config
            .volumes
            .iter()
            .find(|volume| volume.disk_role == DiskRole::Root)
            .context("atomic Start config has no Root volume")?;
        if manifest.size_bytes > root.size_bytes {
            return Ok(InstalledAtomicStartPlanBody::DefiniteFailure {
                reason: cats_api::runtime_lifecycle::CommandFailureReason::ImageUnavailable,
            });
        }
        let image_identity = cats_blockd::format::image_root_identity(&manifest, root.size_bytes)
            .context("derive exact generation-one Root image target")?;
        let image_target = RemoteHead {
            generation: Generation::new(1).context("generation one is outside wire domain")?,
            root_hash: Some(Sha256Digest::from_bytes(image_identity.root_hash)),
            root_object_id: Some(
                AsciiText::new(image_identity.root_object_id)
                    .context("image Root object ID is outside wire domain")?,
            ),
        };
        let mut identities = BTreeSet::new();
        let mut volumes = Vec::with_capacity(context.volume_grants.len());
        for (volume, grant) in command
            .runtime_config
            .volumes
            .iter()
            .cloned()
            .zip(&context.volume_grants)
        {
            let needs_provision = volume.disk_role == DiskRole::Root
                && grant.authoritative_head.generation.get() == 0;
            if needs_provision {
                anyhow::ensure!(
                    grant.authoritative_head.root_hash.is_none()
                        && grant.authoritative_head.root_object_id.is_none(),
                    "generation-zero Root authority is not the exact blank head"
                );
            }
            let provision_transition_id = needs_provision
                .then(|| unique_random(&mut identities))
                .transpose()?;
            let provision_process_identity_token = needs_provision
                .then(|| unique_random(&mut identities))
                .transpose()?;
            let provision_service_id = provision_transition_id
                .as_ref()
                .map(|identity| service_id("cats-root", identity))
                .transpose()?;
            let provision_control_socket_path = provision_transition_id
                .as_ref()
                .map(|identity| {
                    cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                        .root_paths(identity)
                        .map(|paths| paths.control_socket().clone())
                })
                .transpose()
                .context("derive managed Root control socket")?;
            volumes.push(PlannedRootVolume {
                volume,
                attachment_id: grant.volume.attachment_id.clone(),
                attachment_epoch: grant.volume.attachment_epoch,
                acquire_origin: grant.acquire_origin.clone(),
                authority_head: grant.authoritative_head.clone(),
                authority_receipt_digest: grant.grant_receipt_digest.clone(),
                lineage_data_directory: grant.planned_local_lineage_data_directory.clone(),
                provision_transition_id,
                provision_process_identity_token,
                provision_service_id,
                provision_control_socket_path,
            });
        }
        Ok(InstalledAtomicStartPlanBody::PrepareRoot {
            image_manifest: ExactBytes::new(image_manifest),
            image_manifest_digest,
            image_target,
            object_write: self.planned_object_write_mode(command, context)?,
            volumes,
            same_node_restart_source,
        })
    }

    fn plan_same_node_restart_source(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<SameNodeRestartPlanning> {
        let physical = match (context.source, context.warm_restart_source.as_ref()) {
            (StartSource::SameNodeSuspended, None) => {
                let predecessor = context
                    .local_predecessor
                    .as_ref()
                    .context("same-Node Suspended Start lacks its exact predecessor response")?;
                self.warm_platform
                    .inspect_same_node_owned_predecessor(command, predecessor)
                    .context("inspect exact same-Node Suspended physical predecessor")?
            }
            (StartSource::SameNodeWarm, Some(expected)) => {
                let predecessor = context
                    .local_predecessor
                    .as_ref()
                    .context("same-Node Warm Start lacks its exact predecessor response")?;
                let physical = self
                    .warm_platform
                    .inspect_same_node_owned_predecessor(command, predecessor)
                    .context("inspect exact same-Node Warm physical predecessor")?;
                if physical.physical_manifest_digest != expected.physical_manifest_digest
                    || physical.warm_cleanup_authority() != Some(&expected.cleanup_authority)
                    || !matches!(physical.source, SameNodeOwnedPredecessorSource::Warm { .. })
                {
                    return Ok(SameNodeRestartPlanning::DefiniteInvalid);
                }
                physical
            }
            (StartSource::SameNodeRetry, Some(expected)) => {
                let predecessor = context
                    .local_predecessor
                    .as_ref()
                    .context("retained Warm retry lacks its exact StartFailed predecessor")?;
                if !matches!(
                    predecessor.result,
                    cats_api::runtime_lifecycle::NodeResult::StartFailed(_)
                ) {
                    return Ok(SameNodeRestartPlanning::DefiniteInvalid);
                }
                let physical = self
                    .warm_platform
                    .inspect_rebound_warm_retry_source(command, &expected.cleanup_authority)
                    .context("inspect exact retained Warm retry physical source")?;
                if physical.physical_manifest_digest != expected.physical_manifest_digest
                    || physical.warm_cleanup_authority() != Some(&expected.cleanup_authority)
                    || !matches!(
                        physical.source,
                        SameNodeOwnedPredecessorSource::RetainedWarm { .. }
                    )
                {
                    return Ok(SameNodeRestartPlanning::DefiniteInvalid);
                }
                physical
            }
            (StartSource::SameNodeSuspended, Some(_)) | (StartSource::SameNodeWarm, None) => {
                return Ok(SameNodeRestartPlanning::DefiniteInvalid)
            }
            (_, Some(_)) => return Ok(SameNodeRestartPlanning::DefiniteInvalid),
            (_, None) => {
                anyhow::ensure!(
                    context.local_predecessor.as_ref().is_none_or(|response| {
                        !matches!(
                            response.result,
                            cats_api::runtime_lifecycle::NodeResult::Warm(_)
                                | cats_api::runtime_lifecycle::NodeResult::Suspended(_)
                        )
                    }),
                    "non-retained Start carries an executable same-Node predecessor"
                );
                return Ok(SameNodeRestartPlanning::NotApplicable);
            }
        };
        let exact_kind = matches!(
            (&physical.source, context.source),
            (
                SameNodeOwnedPredecessorSource::Suspended { .. },
                StartSource::SameNodeSuspended
            ) | (
                SameNodeOwnedPredecessorSource::Warm { .. },
                StartSource::SameNodeWarm
            ) | (
                SameNodeOwnedPredecessorSource::RetainedWarm { .. },
                StartSource::SameNodeRetry
            )
        );
        if !exact_kind {
            return Ok(SameNodeRestartPlanning::DefiniteInvalid);
        }
        Ok(SameNodeRestartPlanning::Exact(
            PlannedSameNodeRestartSource {
                physical: Box::new(physical),
            },
        ))
    }

    fn plan_prepare_devices(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<InstalledAtomicStartPlanBody> {
        let prepare_root = completed_plan(context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        if let InstalledAtomicStartPlanBody::PrepareSuspendedRoot { source } = &prepare_root.body {
            anyhow::ensure!(
                context.source == StartSource::SameNodeSuspended
                    && matches!(
                        source.physical.source,
                        SameNodeOwnedPredecessorSource::Suspended { .. }
                    ),
                "retained PrepareRoot plan is not a Suspended predecessor"
            );
            return Ok(InstalledAtomicStartPlanBody::PrepareSuspendedDevices {
                prepare_root_plan_digest: prepare_root.plan_digest,
                source_physical_manifest_digest: source.physical.physical_manifest_digest.clone(),
            });
        }
        let warm_installed = match &prepare_root.body {
            InstalledAtomicStartPlanBody::PrepareRoot {
                same_node_restart_source: Some(source),
                ..
            } => match &source.physical.source {
                SameNodeOwnedPredecessorSource::Warm { .. }
                | SameNodeOwnedPredecessorSource::RetainedWarm { .. } => {
                    Some(source.physical.installed_runtime()?.clone())
                }
                _ => None,
            },
            _ => None,
        };
        let root_receipt = completed_receipt(context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let InstalledAtomicStartReceiptBody::PrepareRoot {
            volumes: root_volumes,
            ..
        } = root_receipt.body
        else {
            anyhow::bail!("PrepareRoot platform receipt has another schema")
        };
        anyhow::ensure!(
            root_volumes.len() == command.runtime_config.volumes.len(),
            "PrepareRoot platform receipt changed the Volume set"
        );
        let blockd = planned_blockd_config(&self.config.blockd)?;
        let mut identities = BTreeSet::new();
        let mut devices = Vec::with_capacity(context.volume_grants.len());
        for (device_index, ((volume, grant), root_receipt)) in command
            .runtime_config
            .volumes
            .iter()
            .cloned()
            .zip(&context.volume_grants)
            .zip(root_volumes)
            .enumerate()
        {
            anyhow::ensure!(
                root_receipt.volume_id == volume.volume_id,
                "PrepareRoot receipt reordered Volumes"
            );
            let process_token = unique_random(&mut identities)?;
            let ownership_token = match &warm_installed {
                Some(installed) => installed
                    .vmm
                    .launch_identity
                    .devices
                    .get(device_index)
                    .context("Warm source launch omitted a device")?
                    .ownership_token
                    .clone(),
                None => unique_random(&mut identities)?,
            };
            let serving_service_id = service_id("cats-blockd", &process_token)?;
            let sockets =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .serving_paths(&ownership_token)
                    .context("derive managed serving blockd socket paths")?;
            let (frontend, kernel_nbd_client_service_id) = match &warm_installed {
                Some(installed) => {
                    let source = installed
                        .vmm
                        .launch_identity
                        .devices
                        .get(device_index)
                        .context("Warm source launch omitted a device")?;
                    anyhow::ensure!(
                        source.volume_id == volume.volume_id
                            && source.disk_id == volume.disk_id
                            && source.attachment_id == grant.volume.attachment_id
                            && source.attachment_epoch == grant.volume.attachment_epoch
                            && source.size_bytes == volume.size_bytes
                            && source.guest_device.serial == volume.guest_device_serial
                            && source.guest_device.slot == volume.guest_device_slot
                            && source.ownership_token == ownership_token
                            && source.serving_process.control_socket_path
                                == sockets.control_socket().clone(),
                        "Warm source device changed immutable snapshot identity"
                    );
                    let kernel_unit =
                        matches!(source.frontend, PrepareDeviceFrontend::KernelNbd { .. })
                            .then(|| service_id("cats-nbd-client", &ownership_token))
                            .transpose()?;
                    (source.frontend.clone(), kernel_unit)
                }
                None => match self.config.ch.block_path {
                    BlockPath::VhostUser => (
                        PrepareDeviceFrontend::VhostUserBlk {
                            socket_path: sockets.io_socket().clone(),
                            queues: u16::try_from(ch::vhost_user_queues_for(
                                &self.config.ch,
                                command.runtime_config.vcpus,
                            ))
                            .context("vhost-user queue count overflows u16")?,
                            queue_size: self.config.ch.vhost_user_queue_size,
                        },
                        None,
                    ),
                    BlockPath::KernelNbd => {
                        let kernel = self
                            .config
                            .physical
                            .kernel_nbd
                            .as_ref()
                            .context("kernel-NBD Start lacks installed pool")?;
                        let index = nbd_candidate_index(&ownership_token, kernel.device_count);
                        (
                            PrepareDeviceFrontend::KernelNbd {
                                listener_socket_path: sockets.io_socket().clone(),
                                device_path: host_path(
                                    kernel.device_root.join(format!("nbd{index}")),
                                )?,
                                direct: self.config.ch.block_direct,
                            },
                            Some(service_id("cats-nbd-client", &ownership_token)?),
                        )
                    }
                },
            };
            let lineage = Path::new(grant.planned_local_lineage_data_directory.as_str());
            let authorized_serving_artifact_path = host_path(lineage.join(format!(
                "authorized-serving.atomic-start.{}.v1.json",
                process_token.as_str()
            )))?;
            let command_attribution_path = host_path(lineage.join(format!(
                "atomic-start-command-attribution.{}.v1.json",
                process_token.as_str()
            )))?;
            devices.push(PlannedDevice {
                volume,
                attachment_id: grant.volume.attachment_id.clone(),
                attachment_epoch: grant.volume.attachment_epoch,
                acquire_origin: grant.acquire_origin.clone(),
                launch_head: root_receipt.authority_head,
                authority_receipt_digest: grant.grant_receipt_digest.clone(),
                lineage_data_directory: grant.planned_local_lineage_data_directory.clone(),
                serving_service_id,
                kernel_nbd_client_service_id,
                serving_process_identity_token: process_token,
                device_ownership_token: ownership_token,
                control_socket_path: sockets.control_socket().clone(),
                frontend,
                authorized_serving_artifact_path,
                command_attribution_path,
            });
        }
        Ok(InstalledAtomicStartPlanBody::PrepareDevices {
            prepare_root_plan_digest: prepare_root.plan_digest,
            blockd,
            volumes: devices,
        })
    }

    fn planned_object_write_mode(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<PlannedObjectWriteMode> {
        match &self.object_write_credentials {
            Some(credentials) => {
                let session = self
                    .config
                    .admission_registry
                    .current_agent_session()
                    .context("read AgentSession for object-write plan")?;
                anyhow::ensure!(
                    session.node_id == command.node_id,
                    "object-write AgentSession belongs to another Node"
                );
                let directory = host_path(credentials.credential_directory())?;
                let expected_credential_ids = context
                    .volume_grants
                    .iter()
                    .map(|grant| {
                        object_write_credential_id(
                            &session,
                            &grant.volume.volume_id,
                            &grant.volume.attachment_id,
                            grant.volume.attachment_epoch,
                        )
                    })
                    .collect();
                Ok(PlannedObjectWriteMode::Gateway {
                    session,
                    gateway_origin: credentials.gateway_origin().to_owned(),
                    credential_directory: directory,
                    expected_credential_ids,
                })
            }
            None => Ok(PlannedObjectWriteMode::DirectProvider),
        }
    }

    fn plan_prepare_network(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<InstalledAtomicStartPlanBody> {
        let devices = completed_plan(context, AtomicStartRuntimeEffectPhase::PrepareDevices)?;
        if let InstalledAtomicStartPlanBody::PrepareSuspendedDevices {
            source_physical_manifest_digest,
            ..
        } = &devices.body
        {
            return Ok(InstalledAtomicStartPlanBody::PrepareSuspendedNetwork {
                prepare_devices_plan_digest: devices.plan_digest,
                source_physical_manifest_digest: source_physical_manifest_digest.clone(),
            });
        }
        let desired = legacy_network_config(&command.runtime_config.network_config);
        let artifact_path = host_path(
            self.config
                .physical
                .network_class_root
                .join(START_NETWORK_RESERVATION_NAMESPACE)
                .join(format!("{}.reservation.json", command.cat_id)),
        )?;
        let root_plan = completed_plan(context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let (identity, predecessor_artifact) = match &root_plan.body {
            InstalledAtomicStartPlanBody::PrepareRoot {
                same_node_restart_source: Some(source),
                ..
            } if matches!(
                source.physical.source,
                SameNodeOwnedPredecessorSource::Warm { .. }
                    | SameNodeOwnedPredecessorSource::RetainedWarm { .. }
            ) =>
            {
                anyhow::ensure!(
                    matches!(
                        (&source.physical.source, context.source),
                        (
                            SameNodeOwnedPredecessorSource::Warm { .. },
                            StartSource::SameNodeWarm
                        ) | (
                            SameNodeOwnedPredecessorSource::RetainedWarm { .. },
                            StartSource::SameNodeRetry
                        )
                    ) && context
                        .warm_restart_source
                        .as_ref()
                        .is_some_and(|expected| {
                            source.physical.physical_manifest_digest
                                == expected.physical_manifest_digest
                                && source.physical.warm_cleanup_authority()
                                    == Some(expected.cleanup_authority.as_ref())
                        }),
                    "Warm network predecessor changed its exact direct/retry carrier"
                );
                let installed = source.physical.installed_runtime()?;
                anyhow::ensure!(
                    installed.network.identity.network_config == desired,
                    "Warm source network differs from immutable runtime config"
                );
                let bytes = fs::read(Path::new(artifact_path.as_str()))
                    .context("read exact Warm predecessor network reservation")?;
                let predecessor = decode_installed_atomic_start_network_reservation(&bytes)?;
                let direct_source = matches!(
                    source.physical.source,
                    SameNodeOwnedPredecessorSource::Warm { .. }
                );
                let failed_start_source =
                    context.local_predecessor.as_ref().is_some_and(|failed| {
                        predecessor.operation_id == failed.operation_id
                            && predecessor.request_fingerprint == failed.request_fingerprint
                    });
                anyhow::ensure!(
                    predecessor.node_id == command.node_id
                        && predecessor.cat_id == command.cat_id
                        && predecessor.placement_identity == command.placement_identity
                        && predecessor.runtime_config_id == installed.runtime_config_id
                        && predecessor.runtime_config_digest == installed.runtime_config_digest
                        && predecessor.identity == installed.network.identity
                        && ((direct_source
                            && predecessor.runtime_incarnation == installed.runtime_incarnation)
                            || (!direct_source
                                && (failed_start_source
                                    || predecessor.runtime_incarnation
                                        == installed.runtime_incarnation))),
                    "Warm predecessor network reservation changed retained identity"
                );
                (
                    installed.network.identity.as_ref().clone(),
                    Some(ExactBytes::new(bytes)),
                )
            }
            _ => {
                let network =
                    ch::plan_network(&desired).context("plan exact Host network reservation")?;
                (
                    RuntimeNetworkIdentity {
                        network_config: network.config,
                        tap_name: Id::new(network.tap)
                            .context("planned TAP name is not a canonical Id")?,
                        ownership_token: network.ownership_token,
                    },
                    None,
                )
            }
        };
        let replacement_path = host_path(PathBuf::from(artifact_path.as_str()).with_extension(
            format!("replacement-{}.json", command.operation_id.as_str()),
        ))?;
        Ok(InstalledAtomicStartPlanBody::PrepareNetwork {
            prepare_devices_plan_digest: devices.plan_digest,
            reservation: PlannedNetworkReservation {
                identity: Box::new(identity),
                artifact_path,
                predecessor_artifact,
                replacement_path,
            },
        })
    }

    fn plan_activate_runtime(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<InstalledAtomicStartPlanBody> {
        let network_plan = completed_plan(context, AtomicStartRuntimeEffectPhase::PrepareNetwork)?;
        if let InstalledAtomicStartPlanBody::PrepareSuspendedNetwork {
            source_physical_manifest_digest,
            ..
        } = &network_plan.body
        {
            anyhow::ensure!(
                activation_kind_is_exact_for_source(
                    context.source,
                    false,
                    PlannedRuntimeActivationKind::ResumeSuspended,
                ),
                "Suspended Start cannot select a fresh VMM activation"
            );
            return Ok(InstalledAtomicStartPlanBody::ResumeSuspendedRuntime {
                prepare_network_plan_digest: network_plan.plan_digest,
                source_physical_manifest_digest: source_physical_manifest_digest.clone(),
            });
        }
        let network_receipt =
            completed_receipt(context, AtomicStartRuntimeEffectPhase::PrepareNetwork)?;
        let InstalledAtomicStartReceiptBody::PrepareNetwork { reservation } = network_receipt.body
        else {
            anyhow::bail!("PrepareNetwork platform receipt has another schema")
        };
        let reservation = *reservation;
        let device_receipt =
            completed_receipt(context, AtomicStartRuntimeEffectPhase::PrepareDevices)?;
        let InstalledAtomicStartReceiptBody::PrepareDevices { devices, .. } = device_receipt.body
        else {
            anyhow::bail!("PrepareDevices platform receipt has another schema")
        };
        anyhow::ensure!(
            devices.len() == command.runtime_config.volumes.len(),
            "PrepareDevices platform receipt changed the Volume set"
        );
        let deadline = self.effect_deadline(command, context)?;
        let launcher_executable = artifact_from_path(&self.config.ch.vmm_launcher_bin, deadline)
            .context("retain exact VMM launcher artifact")?;
        let vmm_executable = artifact_from_path(&self.config.ch.ch_bin, deadline)
            .context("retain exact Cloud Hypervisor artifact")?;
        let boot_contract = self
            .config
            .ch
            .boot_contract
            .as_ref()
            .context("atomic Start lost the signed Guest boot contract")?;
        let kernel = artifact_from_release_member(&self.config.ch.kernel, boot_contract.kernel())?;
        let initramfs = match (&self.config.ch.initramfs, boot_contract.initramfs()) {
            (Some(path), Some(member)) => Some(artifact_from_release_member(path, member)?),
            (None, None) => None,
            _ => anyhow::bail!("installed initramfs differs from signed Guest boot contract"),
        };
        let boot = VmmBootProvenance {
            vmm_executable,
            kernel,
            initramfs,
            kernel_cmdline: AsciiText::new(self.config.ch.cmdline.clone())
                .context("installed kernel command line is outside wire domain")?,
        };
        let scope_id = service_id("cats-vmm", &context.runtime_incarnation)?;
        let process_identity_token = fresh_random()?;
        anyhow::ensure!(
            process_identity_token != context.runtime_incarnation,
            "VMM process token collided with runtime incarnation"
        );
        let socket_root = Path::new(INSTALLED_VMM_SOCKET_ROOT)
            .join(format!("p-{}", context.runtime_incarnation.as_str()));
        let api_socket_path = host_path(socket_root.join("api.sock"))?;
        let vsock_socket_path = host_path(socket_root.join("vsock.sock"))?;
        let launch_root = self
            .config
            .physical
            .state_directory
            .path()
            .join(VMM_LAUNCH_FILE_NAMESPACE)
            .join(format!("p-{}", context.runtime_incarnation.as_str()));
        let root_plan = completed_plan(context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let (memory_file_path, mode, restored_transport) = match &root_plan.body {
            InstalledAtomicStartPlanBody::PrepareRoot {
                same_node_restart_source: Some(source),
                ..
            } => {
                let cleanup_authority = match &source.physical.source {
                    SameNodeOwnedPredecessorSource::Warm { cleanup_authority }
                        if context.source == StartSource::SameNodeWarm =>
                    {
                        cleanup_authority
                    }
                    SameNodeOwnedPredecessorSource::RetainedWarm { cleanup_authority }
                        if context.source == StartSource::SameNodeRetry =>
                    {
                        cleanup_authority
                    }
                    _ => {
                        anyhow::bail!(
                            "retained restart source reached a different activation contract"
                        )
                    }
                };
                let source_launch = &source.physical.installed_runtime()?.vmm.launch_identity;
                anyhow::ensure!(
                    context
                        .warm_restart_source
                        .as_ref()
                        .is_some_and(|expected| {
                            source.physical.physical_manifest_digest
                                == expected.physical_manifest_digest
                                && cleanup_authority.as_ref() == expected.cleanup_authority.as_ref()
                        })
                        && cleanup_authority.mode() == WarmSnapshotCleanupMode::TransferToRuntime
                        && cleanup_authority.memory_file().size_bytes
                            == command.runtime_config.memory_bytes,
                    "Warm restore memory proof changed its source or runtime size"
                );
                let memory = cleanup_authority.memory_file();
                (
                    memory.path.clone(),
                    AtomicVmmLaunchMode::WarmRestore {
                        snapshot_directory: cleanup_authority.snapshot_directory().clone(),
                        memory_file: AtomicVmmMemoryFileIdentity {
                            path: memory.path.clone(),
                            device: memory.device,
                            inode: memory.inode,
                            length: memory.size_bytes,
                            content_sha256: memory.digest.clone(),
                        },
                        source: Box::new(AtomicVmmWarmRestoreSourceIdentity::from_launch(
                            source_launch,
                        )),
                    },
                    Some((
                        source_launch.vsock_socket_path.clone(),
                        source_launch.guest_cid,
                    )),
                )
            }
            InstalledAtomicStartPlanBody::PrepareRoot {
                same_node_restart_source: None,
                ..
            } => {
                anyhow::ensure!(
                    context.source != StartSource::SameNodeWarm
                        && context.warm_restart_source.is_none(),
                    "same-Node Warm Start lost its exact restart source"
                );
                (
                    host_path(launch_root.join("memory.bin"))?,
                    AtomicVmmLaunchMode::Fresh,
                    None,
                )
            }
            _ => anyhow::bail!("PrepareRoot platform plan has another schema"),
        };
        let serial_log_path = host_path(launch_root.join("serial.log"))?;
        let vmm_log_path = host_path(launch_root.join("vmm.log"))?;
        let (vsock_socket_path, guest_cid) = restored_transport.unwrap_or_else(|| {
            (
                vsock_socket_path,
                guest_cid_from_identity(&process_identity_token),
            )
        });
        let launch = RuntimeLaunchIdentity {
            runtime_incarnation: context.runtime_incarnation.clone(),
            scope_id,
            launcher_executable: Box::new(launcher_executable),
            boot: Box::new(boot),
            process_identity_token,
            vcpus: command.runtime_config.vcpus,
            memory_bytes: command.runtime_config.memory_bytes,
            boot_image_digest: command.runtime_config.boot_image_digest.clone(),
            guest_config_digest: command.runtime_config.guest_runtime_profile_digest.clone(),
            api_socket_path,
            vsock_socket_path,
            guest_cid,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            network: reservation.identity,
            devices,
        };
        let activation = match &mode {
            AtomicVmmLaunchMode::Fresh => PlannedRuntimeActivationKind::Fresh,
            AtomicVmmLaunchMode::WarmRestore { .. } => PlannedRuntimeActivationKind::WarmRestore,
        };
        anyhow::ensure!(
            activation_kind_is_exact_for_source(
                context.source,
                context.warm_restart_source.is_some(),
                activation,
            ),
            "Start source cannot fall back to another VMM activation mode"
        );
        Ok(InstalledAtomicStartPlanBody::ActivateRuntime {
            prepare_network_plan_digest: network_plan.plan_digest,
            launch: Box::new(launch),
            mode,
        })
    }

    fn plan_format_persistent(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<InstalledAtomicStartPlanBody> {
        let activate = completed_plan(context, AtomicStartRuntimeEffectPhase::ActivateRuntime)?;
        let deadline = self.effect_deadline(command, context)?;
        let session = self
            .config
            .admission_registry
            .current_agent_session()
            .context("read AgentSession for Persistent initialization inspect")?;
        anyhow::ensure!(
            session.node_id == command.node_id,
            "Persistent initialization AgentSession belongs to another Node"
        );
        let static_filesystems = persistent_filesystems(command, context)?;
        let mut static_by_volume = static_filesystems
            .into_iter()
            .map(|filesystem| (filesystem.volume_id.clone(), filesystem))
            .collect::<BTreeMap<_, _>>();
        let mut identities = BTreeSet::new();
        let guest_timeout_ms = guest_filesystem_timeout_ms(self.config.guest_ready_timeout)?;
        let mut volumes = Vec::with_capacity(static_by_volume.len());
        for (volume, grant) in command
            .runtime_config
            .volumes
            .iter()
            .zip(&context.volume_grants)
        {
            let Some(filesystem) = static_by_volume.remove(&volume.volume_id) else {
                anyhow::ensure!(
                    volume.disk_role == DiskRole::Root,
                    "non-Root volume omitted its Persistent filesystem binding"
                );
                continue;
            };
            let binding = persistent_initialization_binding(command, volume, grant)?;
            let inspect = LifecyclePersistentInitializationInspectRequest {
                binding: Box::new(binding.clone()),
            };
            let inspection = match self
                .config
                .persistent_initialization_control
                .inspect_persistent_initialization(session.clone(), inspect, deadline)
            {
                Ok(inspection) => inspection,
                Err(LifecycleVolumeClientError::Rejected(_)) => {
                    return Ok(InstalledAtomicStartPlanBody::DefiniteFailure {
                        reason: cats_api::runtime_lifecycle::CommandFailureReason::VolumeAuthorityRejected,
                    })
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(error))
                        .context("Persistent initialization inspect result is ambiguous")
                }
            };
            anyhow::ensure!(
                inspection.binding.as_ref() == &binding
                    && inspection.attachment_id == filesystem.attachment_id
                    && inspection.attachment_epoch == filesystem.attachment_epoch
                    && remote_head_is_same_or_later(
                        &inspection.current_head,
                        &grant.authoritative_head,
                    ),
                "Persistent initialization inspection changed Start authority"
            );
            volumes.push(PlannedPersistentInitialization {
                filesystem,
                inspection,
                probe_challenge: unique_random(&mut identities)?,
                format_challenge: unique_random(&mut identities)?,
                post_format_probe_challenge: unique_random(&mut identities)?,
                flush_challenge: unique_random(&mut identities)?,
                guest_timeout_ms,
            });
        }
        anyhow::ensure!(
            static_by_volume.is_empty(),
            "Persistent filesystem set was not consumed in config order"
        );
        Ok(InstalledAtomicStartPlanBody::FormatPersistentVolumes {
            activate_runtime_plan_digest: activate.plan_digest,
            volumes,
        })
    }

    fn plan_commit_persistent(
        &self,
        _command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<InstalledAtomicStartPlanBody> {
        let format = completed_plan(
            context,
            AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
        )?;
        let format_receipt = completed_receipt(
            context,
            AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
        )?;
        let InstalledAtomicStartReceiptBody::FormatPersistentVolumes { format_receipts } =
            format_receipt.body
        else {
            anyhow::bail!("FormatPersistentVolumes receipt has another schema")
        };
        journal_persistent_commit_plan(format.plan_digest, format_receipts)
    }

    fn plan_guest_ready(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
    ) -> Result<InstalledAtomicStartPlanBody> {
        let commit = completed_plan(
            context,
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
        )?;
        let root_plan = completed_plan(context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let same_node_restart_source = match root_plan.body {
            InstalledAtomicStartPlanBody::PrepareRoot {
                same_node_restart_source,
                ..
            } => same_node_restart_source,
            InstalledAtomicStartPlanBody::PrepareSuspendedRoot { source } => Some(*source),
            _ => anyhow::bail!("PrepareRoot platform plan has another schema"),
        };
        let commit_receipt = completed_receipt(
            context,
            AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
        )?;
        let InstalledAtomicStartReceiptBody::CommitPersistentInitialized { commit_receipts } =
            commit_receipt.body
        else {
            anyhow::bail!("CommitPersistentInitialized receipt has another schema")
        };
        let static_filesystems = persistent_filesystems(command, context)?;
        anyhow::ensure!(
            static_filesystems.len() == commit_receipts.len(),
            "Persistent commit receipt changed the filesystem set"
        );
        let mut identities = BTreeSet::new();
        let mut filesystems = Vec::with_capacity(static_filesystems.len());
        for (filesystem, receipt) in static_filesystems.into_iter().zip(&commit_receipts) {
            let receipt: InstalledPersistentCommitReceipt = decode_exact_json(
                receipt,
                "decode Persistent commit receipt before mount planning",
            )?;
            let (initialization_token, expected_blank_head, initialized_head, volume_id) =
                match receipt {
                    InstalledPersistentCommitReceipt::AlreadyInitialized { inspection } => {
                        let LifecyclePersistentInitializationState::Initialized {
                            initialization_token,
                            expected_blank_head,
                            initialized_head,
                            ..
                        } = inspection.initialization
                        else {
                            anyhow::bail!(
                                "already-initialized receipt contains an uninitialized Disk"
                            )
                        };
                        (
                            initialization_token,
                            expected_blank_head,
                            initialized_head,
                            inspection.binding.volume.volume_id.clone(),
                        )
                    }
                    InstalledPersistentCommitReceipt::Committed { committed } => (
                        committed.receipt.request.initialization_token.clone(),
                        committed.receipt.request.expected_blank_head.clone(),
                        committed.receipt.request.initialized_head.clone(),
                        committed.receipt.request.binding.volume.volume_id.clone(),
                    ),
                };
            anyhow::ensure!(
                filesystem.volume_id == volume_id,
                "Persistent commit receipt reordered volumes"
            );
            filesystems.push(PlannedPersistentMount {
                filesystem,
                initialization_token,
                expected_blank_head,
                initialized_head,
                probe_challenge: unique_random(&mut identities)?,
                mount_challenge: unique_random(&mut identities)?,
                guest_timeout_ms: guest_filesystem_timeout_ms(self.config.guest_ready_timeout)?,
            });
        }
        Ok(InstalledAtomicStartPlanBody::GuestReadyAndAdmission {
            commit_plan_digest: commit.plan_digest,
            runtime_ready_challenge: fresh_random()?,
            filesystems,
            same_node_restart_source,
        })
    }

    fn inspect_or_apply(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        deadline: Instant,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let effect = StartPhysicalEffectContext { deadline };
        match (&plan.phase, &plan.body) {
            (_, InstalledAtomicStartPlanBody::DefiniteFailure { reason }) => {
                definite_runtime_failure(request, *reason)
            }
            (
                AtomicStartRuntimeEffectPhase::PrepareRoot,
                InstalledAtomicStartPlanBody::PrepareRoot {
                    image_manifest_digest,
                    image_target,
                    object_write,
                    volumes,
                    same_node_restart_source,
                    ..
                },
            ) => self.inspect_or_apply_root(
                command,
                request,
                plan,
                image_manifest_digest,
                image_target,
                object_write,
                volumes,
                same_node_restart_source,
                &effect,
            ),
            (
                AtomicStartRuntimeEffectPhase::PrepareRoot,
                InstalledAtomicStartPlanBody::PrepareSuspendedRoot { source },
            ) => self.inspect_suspended_root(command, request, plan, source, &effect),
            (
                AtomicStartRuntimeEffectPhase::PrepareDevices,
                InstalledAtomicStartPlanBody::PrepareDevices {
                    blockd, volumes, ..
                },
            ) => self.inspect_or_apply_devices(command, request, plan, blockd, volumes, &effect),
            (
                AtomicStartRuntimeEffectPhase::PrepareDevices,
                InstalledAtomicStartPlanBody::PrepareSuspendedDevices {
                    source_physical_manifest_digest,
                    ..
                },
            ) => self.inspect_suspended_devices(
                command,
                request,
                plan,
                source_physical_manifest_digest,
                &effect,
            ),
            (
                AtomicStartRuntimeEffectPhase::PrepareNetwork,
                InstalledAtomicStartPlanBody::PrepareNetwork { reservation, .. },
            ) => self.inspect_or_apply_network(command, request, plan, reservation, &effect),
            (
                AtomicStartRuntimeEffectPhase::PrepareNetwork,
                InstalledAtomicStartPlanBody::PrepareSuspendedNetwork {
                    source_physical_manifest_digest,
                    ..
                },
            ) => self.inspect_suspended_network(
                command,
                request,
                plan,
                source_physical_manifest_digest,
                &effect,
            ),
            (
                AtomicStartRuntimeEffectPhase::ActivateRuntime,
                InstalledAtomicStartPlanBody::ActivateRuntime { launch, mode, .. },
            ) => self
                .inspect_or_apply_activate_runtime(command, request, plan, launch, mode, &effect),
            (
                AtomicStartRuntimeEffectPhase::ActivateRuntime,
                InstalledAtomicStartPlanBody::ResumeSuspendedRuntime {
                    source_physical_manifest_digest,
                    ..
                },
            ) => self.inspect_or_resume_suspended_runtime(
                command,
                request,
                plan,
                source_physical_manifest_digest,
                &effect,
            ),
            (
                AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
                InstalledAtomicStartPlanBody::FormatPersistentVolumes { volumes, .. },
            ) => self.inspect_or_apply_format_persistent(command, request, plan, volumes, &effect),
            (
                AtomicStartRuntimeEffectPhase::CommitPersistentInitialized,
                InstalledAtomicStartPlanBody::CommitPersistentInitialized {
                    format_plan_digest,
                    commit_requests,
                },
            ) => self.inspect_or_apply_commit_persistent(
                command,
                request,
                plan,
                format_plan_digest,
                commit_requests,
                &effect,
            ),
            (
                AtomicStartRuntimeEffectPhase::GuestReadyAndAdmission,
                InstalledAtomicStartPlanBody::GuestReadyAndAdmission {
                    runtime_ready_challenge,
                    filesystems,
                    same_node_restart_source,
                    ..
                },
            ) => self.inspect_or_apply_guest_ready(
                command,
                request,
                plan,
                runtime_ready_challenge,
                filesystems,
                same_node_restart_source,
                &effect,
            ),
            _ => anyhow::bail!(
                "atomic Start installed {:?} phase/body schema mismatch",
                plan.phase
            ),
        }
    }

    fn suspended_restart_source(
        &self,
        command: &LifecycleCommandEnvelope,
        context: &AtomicStartRuntimeContext,
        expected_physical_manifest_digest: Option<&Sha256Digest>,
    ) -> Result<PlannedSameNodeRestartSource> {
        let root = completed_plan(context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let InstalledAtomicStartPlanBody::PrepareSuspendedRoot { source } = root.body else {
            anyhow::bail!("Suspended Start lost its retained PrepareRoot source")
        };
        let SameNodeOwnedPredecessorSource::Suspended {
            installed_runtime, ..
        } = &source.physical.source
        else {
            anyhow::bail!("retained Start source is not Suspended")
        };
        anyhow::ensure!(
            context.source == StartSource::SameNodeSuspended
                && source.physical.physical_manifest_digest == installed_runtime.manifest_digest
                && expected_physical_manifest_digest.is_none_or(|expected| {
                    source.physical.physical_manifest_digest == *expected
                })
                && source.physical.runtime_incarnation.as_ref()
                    == Some(&context.runtime_incarnation)
                && installed_runtime.node_id == command.node_id
                && installed_runtime.cat_id == command.cat_id
                && installed_runtime.placement_identity == command.placement_identity
                && installed_runtime.runtime_config_id == command.runtime_config.config_id
                && installed_runtime.runtime_config_digest == command.runtime_config.config_digest
                && installed_runtime.runtime_incarnation == context.runtime_incarnation
                && source.physical.volumes.len() == context.volume_grants.len()
                && installed_runtime.volumes.len() == context.volume_grants.len(),
            "Suspended restart source changed immutable runtime identity"
        );
        for (((physical, installed), grant), configured) in source
            .physical
            .volumes
            .iter()
            .zip(&installed_runtime.volumes)
            .zip(&context.volume_grants)
            .zip(&command.runtime_config.volumes)
        {
            anyhow::ensure!(
                physical.volume_id == configured.volume_id
                    && physical.disk_id == configured.disk_id
                    && physical.disk_role == configured.disk_role
                    && physical.attachment_id == grant.volume.attachment_id
                    && physical.attachment_epoch == grant.volume.attachment_epoch
                    && physical.acquire_origin == grant.acquire_origin
                    && installed.volume_id == configured.volume_id
                    && installed.disk_id == configured.disk_id
                    && installed.attachment_id == grant.volume.attachment_id
                    && installed.attachment_epoch == grant.volume.attachment_epoch
                    && installed.acquire_origin == grant.acquire_origin
                    && physical.local_lineage_data_directory.as_ref()
                        == Some(&installed.local_lineage_data_directory)
                    && remote_head_is_same_or_later(
                        &grant.authoritative_head,
                        &physical.authoritative_head,
                    ),
                "Suspended restart source changed a retained Volume"
            );
        }
        Ok(*source)
    }

    fn inspect_suspended_root(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        source: &PlannedSameNodeRestartSource,
        _effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let exact = self.suspended_restart_source(command, &request.context, None)?;
        anyhow::ensure!(
            &exact == source,
            "Suspended PrepareRoot plan changed its physical carrier"
        );
        let installed = source.physical.installed_runtime()?;
        let mut volumes = Vec::with_capacity(installed.volumes.len());
        for ((source_volume, grant), configured) in installed
            .volumes
            .iter()
            .zip(&request.context.volume_grants)
            .zip(&command.runtime_config.volumes)
        {
            let current = self.inspect_current_persistent_head(command, configured, grant)?;
            volumes.push(InstalledRuntimeProgressVolumeManifest {
                volume_id: source_volume.volume_id.clone(),
                disk_id: source_volume.disk_id.clone(),
                disk_role: source_volume.disk_role,
                attachment_id: source_volume.attachment_id.clone(),
                attachment_epoch: source_volume.attachment_epoch,
                acquire_origin: source_volume.acquire_origin.clone(),
                authority_head: current,
                authority_receipt_digest: Some(grant.grant_receipt_digest.clone()),
                local_lineage_data_directory: Some(
                    source_volume.local_lineage_data_directory.clone(),
                ),
                blockd: None,
                blockd_control_socket_path: None,
                frontend: None,
            });
        }
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            None,
            None,
            volumes,
            request.context.artifact_classifications.clone(),
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::PrepareSuspendedRoot {
                source_physical_manifest_digest: source.physical.physical_manifest_digest.clone(),
            },
            progress,
        )
    }

    fn inspect_suspended_devices(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        source_physical_manifest_digest: &Sha256Digest,
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let source = self.suspended_restart_source(
            command,
            &request.context,
            Some(source_physical_manifest_digest),
        )?;
        let installed = source.physical.installed_runtime()?;
        let mut progress = previous_progress(request)?.clone();
        let mut prepared = Vec::with_capacity(installed.volumes.len());
        for (index, (((volume, launch_device), configured), grant)) in installed
            .volumes
            .iter()
            .zip(&installed.vmm.launch_identity.devices)
            .zip(&command.runtime_config.volumes)
            .zip(&request.context.volume_grants)
            .enumerate()
        {
            let current = self.inspect_current_persistent_head(command, configured, grant)?;
            let planned = planned_device_from_retained_source(
                command,
                configured,
                launch_device,
                volume,
                grant,
            )?;
            inspect_retained_systemd_process(
                &self.config.physical,
                &command.cat_id,
                &launch_device.serving_process.scope_id,
                Path::new(launch_device.serving_process.executable_path.as_str()),
                &volume.blockd,
                effect,
            )
            .map_err(|error| {
                if is_exact_process_conflict(&error) {
                    definite_physical_failure(
                        cats_api::runtime_lifecycle::CommandFailureReason::DevicePrepareFailed,
                    )
                } else {
                    error
                }
            })?;
            let status = blockd_status(
                Path::new(volume.blockd_control_socket_path.as_str()),
                volume.blockd.pid,
                effect,
            )?;
            validate_guest_ready_blockd_status(command, &planned, &current, &status).map_err(
                |_| {
                    definite_physical_failure(
                        cats_api::runtime_lifecycle::CommandFailureReason::DevicePrepareFailed,
                    )
                },
            )?;
            inspect_guest_ready_frontend(
                &self.config.physical,
                &command.cat_id,
                &planned,
                &volume.frontend,
                effect,
            )?;
            let target = progress
                .volumes
                .get_mut(index)
                .context("Suspended device progress omitted a volume")?;
            target.authority_head = current;
            target.authority_receipt_digest = Some(grant.grant_receipt_digest.clone());
            target.local_lineage_data_directory = Some(volume.local_lineage_data_directory.clone());
            target.blockd = Some(volume.blockd.clone());
            target.blockd_control_socket_path = Some(volume.blockd_control_socket_path.clone());
            target.frontend = Some(volume.frontend.clone());
            prepared.push(launch_device.clone());
        }
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            progress.vmm,
            progress.network,
            progress.volumes,
            progress.artifact_classifications,
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::PrepareDevices {
                devices: prepared,
                progress_volumes: progress.volumes.clone(),
            },
            progress,
        )
    }

    fn inspect_suspended_network(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        source_physical_manifest_digest: &Sha256Digest,
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let source = self.suspended_restart_source(
            command,
            &request.context,
            Some(source_physical_manifest_digest),
        )?;
        let installed = source.physical.installed_runtime()?;
        let snapshot = ch::inspect_host_network_snapshot(&self.config.physical.ip_binary, effect)?;
        anyhow::ensure!(
            snapshot.reserved_network_state(&installed.network.identity)?
                == ReservedHostNetworkState::Exact,
            "Suspended Host network changed from its retained physical identity"
        );
        let previous = previous_progress(request)?;
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            previous.vmm.clone(),
            Some(installed.network.clone()),
            previous.volumes.clone(),
            previous.artifact_classifications.clone(),
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::PrepareSuspendedNetwork {
                network: Box::new(installed.network.clone()),
            },
            progress,
        )
    }

    fn inspect_or_resume_suspended_runtime(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        source_physical_manifest_digest: &Sha256Digest,
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let source = self.suspended_restart_source(
            command,
            &request.context,
            Some(source_physical_manifest_digest),
        )?;
        let installed = source.physical.installed_runtime()?;
        let state = inspect_retained_vmm(&self.config, &command.cat_id, &installed.vmm, effect)?;
        match state {
            ProcessState::Paused => {
                if !self.effect_authority_has_budget(request, effect.deadline())? {
                    return volume_refresh_required(request, plan, effect.deadline());
                }
                match ch::resume_exact_vmm_until(
                    Path::new(installed.vmm.api_socket_path.as_str()),
                    installed.vmm.process.pid,
                    effect.deadline(),
                )
                .context("resume exact Suspended VMM")?
                {
                    ch::ExactVmEffectOutcome::Exact => {}
                    ch::ExactVmEffectOutcome::DefiniteFailure => {
                        return definite_runtime_failure(
                            request,
                            cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
                        )
                    }
                    ch::ExactVmEffectOutcome::Ambiguous => {
                        anyhow::bail!("Suspended VMM resume completion is ambiguous")
                    }
                }
            }
            ProcessState::Running => {}
        }
        anyhow::ensure!(
            inspect_retained_vmm(&self.config, &command.cat_id, &installed.vmm, effect,)?
                == ProcessState::Running,
            "Suspended VMM did not reach exact executing state"
        );
        let previous = previous_progress(request)?;
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            Some(installed.vmm.clone()),
            previous.network.clone(),
            previous.volumes.clone(),
            previous.artifact_classifications.clone(),
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::ActivateRuntime {
                vmm: Box::new(installed.vmm.clone()),
            },
            progress,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_or_apply_root(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        image_manifest_digest: &Sha256Digest,
        image_target: &RemoteHead,
        object_write: &PlannedObjectWriteMode,
        volumes: &[PlannedRootVolume],
        same_node_restart_source: &Option<PlannedSameNodeRestartSource>,
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        anyhow::ensure!(
            volumes.len() == request.context.volume_grants.len(),
            "PrepareRoot plan changed the Volume set"
        );
        let planned_session = match object_write {
            PlannedObjectWriteMode::Gateway { session, .. } => {
                let current = self.config.admission_registry.current_agent_session()?;
                if &current != session {
                    return self.inspect_or_cleanup_obsolete_prepare_root_session(
                        command, request, plan, session, &current, volumes, effect,
                    );
                }
                Some(session)
            }
            PlannedObjectWriteMode::DirectProvider => None,
        };
        let mut zero_mutation = true;
        for volume in volumes {
            zero_mutation &= path_is_absent(
                &Path::new(volume.lineage_data_directory.as_str()).join("identity.json"),
            )? && self.inspect_exact_volume_head(command, volume)?
                == volume.authority_head;
        }
        if lease_loss_allows_same_plan_refresh(zero_mutation)
            && !self.effect_authority_has_budget(request, effect.deadline())?
        {
            return volume_refresh_required(request, plan, effect.deadline());
        }

        let mut receipts = Vec::with_capacity(volumes.len());
        let mut progress_volumes = Vec::with_capacity(volumes.len());
        for ((planned, grant), expected_credential_id) in volumes
            .iter()
            .zip(&request.context.volume_grants)
            .zip(planned_credential_ids(object_write, volumes.len())?)
        {
            anyhow::ensure!(
                planned.volume == grant.authority_receipt.volume
                    && planned.attachment_id == grant.volume.attachment_id
                    && planned.attachment_epoch == grant.volume.attachment_epoch
                    && remote_head_is_same_or_later(
                        &grant.authoritative_head,
                        &planned.authority_head,
                    )
                    && planned.lineage_data_directory == grant.planned_local_lineage_data_directory,
                "PrepareRoot plan changed an authoritative Volume grant"
            );
            let lineage = AttachmentLineageIdentity {
                volume_id: planned.volume.volume_id.clone(),
                attachment_id: planned.attachment_id.clone(),
                attachment_epoch: planned.attachment_epoch,
                acquire_origin: planned.acquire_origin.clone(),
                node_id: command.node_id.clone(),
                placement_epoch: command.placement_identity.placement_epoch,
            };
            let lineage_bytes = canonical_json(&lineage)?;
            let lineage_path =
                Path::new(planned.lineage_data_directory.as_str()).join("identity.json");
            self.publish_exact_with_authority(
                request,
                effect,
                self.config.physical.state_directory.path(),
                &lineage_path,
                &lineage_bytes,
                0o600,
            )
            .context("publish exact atomic Start attachment lineage")?;
            let lineage_identity_digest = sha256_bytes(&lineage_bytes);

            let (credential, registered_bytes) = match (
                planned_session,
                expected_credential_id,
                self.object_write_credentials.as_ref(),
            ) {
                (Some(session), Some(expected), Some(credentials)) => {
                    let load = || {
                        object_write_credential::load(
                            self.config.physical.state_directory.path(),
                            &planned.volume.volume_id,
                            &planned.attachment_id,
                            planned.attachment_epoch,
                        )
                    };
                    let loaded = match load() {
                        Ok(loaded) => loaded,
                        Err(object_write_credential::ObjectWriteCredentialError::NotRegistered) => {
                            self.ensure_fresh_effect_authority(request, effect.deadline())?;
                            let credential = credentials
                                .establish(
                                    session,
                                    &planned.volume.volume_id,
                                    &planned.attachment_id,
                                    planned.attachment_epoch,
                                    effect.deadline(),
                                )
                                .context("establish exact attachment ObjectWrite credential")?;
                            anyhow::ensure!(
                                credential.credential_id == expected,
                                "ObjectWrite registration returned another credential"
                            );
                            load().context("reload registered ObjectWrite credential artifact")?
                        }
                        Err(error) => {
                            return Err(anyhow::anyhow!(error))
                                .context("inspect registered ObjectWrite credential artifact")
                        }
                    };
                    anyhow::ensure!(
                        loaded.credential().credential_id == expected
                            && self.config.admission_registry.current_agent_session()? == *session,
                        "registered ObjectWrite artifact or AgentSession changed"
                    );
                    let registered = encode_object_write_credential_registered_artifact(
                        loaded.registered_artifact(),
                    )
                    .context("encode exact ObjectWrite registered artifact")?;
                    (Some(loaded.credential().clone()), Some(registered))
                }
                (None, None, None) => (None, None),
                _ => anyhow::bail!("PrepareRoot ObjectWrite composition is incomplete"),
            };

            let mut current_head = planned.authority_head.clone();
            let mut root_provision_receipt = None;
            let needs_provision = planned.provision_transition_id.is_some();
            let control_attachment = authorized_serving_attachment(
                grant,
                &lineage,
                credential.clone(),
                current_head.clone(),
            )?;
            if needs_provision {
                let control_path = Path::new(planned.lineage_data_directory.as_str())
                    .join("authorized-control.atomic-start.v1.json");
                let control_bytes = canonical_json(&control_attachment)?;
                self.publish_exact_with_authority(
                    request,
                    effect,
                    self.config.physical.state_directory.path(),
                    &control_path,
                    &control_bytes,
                    0o600,
                )
                .context("publish exact Root control authorization")?;
                let result = self.inspect_or_apply_root_provision(
                    command,
                    request,
                    plan,
                    planned,
                    image_manifest_digest,
                    image_target,
                    object_write,
                    &control_path,
                    effect,
                )?;
                current_head = result.resulting_head.clone();
                root_provision_receipt = Some(ExactBytes::new(
                    cats_api::runtime_reconciliation::encode_provision_root_image_result(&result)
                        .context("encode exact Root provision result")?,
                ));
            }

            let serving_attachment =
                authorized_serving_attachment(grant, &lineage, credential, current_head.clone())?;
            let authorized_serving_attachment =
                ExactBytes::new(canonical_json(&serving_attachment)?);
            let authorized_serving_artifact_path =
                Path::new(planned.lineage_data_directory.as_str())
                    .join("authorized-serving.atomic-start.v1.json");
            self.publish_exact_with_authority(
                request,
                effect,
                self.config.physical.state_directory.path(),
                &authorized_serving_artifact_path,
                authorized_serving_attachment.as_slice(),
                0o600,
            )
            .context("publish exact serving attachment")?;

            let registered_bytes = registered_bytes.map(ExactBytes::new);
            receipts.push(InstalledRootVolumeReceipt {
                volume_id: planned.volume.volume_id.clone(),
                authority_head: current_head.clone(),
                authorized_serving_artifact_digest: sha256_bytes(
                    authorized_serving_attachment.as_slice(),
                ),
                authorized_serving_attachment,
                object_write_registered_artifact_digest: registered_bytes
                    .as_ref()
                    .map(|artifact| sha256_bytes(artifact.as_slice())),
                object_write_registered_artifact: registered_bytes,
                lineage_identity_digest,
                root_provision_receipt,
            });
            progress_volumes.push(InstalledRuntimeProgressVolumeManifest {
                volume_id: planned.volume.volume_id.clone(),
                disk_id: planned.volume.disk_id.clone(),
                disk_role: planned.volume.disk_role,
                attachment_id: planned.attachment_id.clone(),
                attachment_epoch: planned.attachment_epoch,
                acquire_origin: planned.acquire_origin.clone(),
                authority_head: current_head,
                authority_receipt_digest: Some(grant.grant_receipt_digest.clone()),
                local_lineage_data_directory: Some(planned.lineage_data_directory.clone()),
                blockd: None,
                blockd_control_socket_path: None,
                frontend: None,
            });
        }
        if let Some(session) = planned_session {
            anyhow::ensure!(
                self.config.admission_registry.current_agent_session()? == *session,
                "AgentSession changed during PrepareRoot physical effect"
            );
        }
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            None,
            None,
            progress_volumes,
            request
                .context
                .runtime_progress
                .artifact_classifications
                .clone(),
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::PrepareRoot {
                volumes: receipts,
                same_node_restart_source: same_node_restart_source.clone(),
            },
            progress,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_or_cleanup_obsolete_prepare_root_session(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        old_session: &SessionBinding,
        observed_current_session: &SessionBinding,
        volumes: &[PlannedRootVolume],
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        anyhow::ensure!(
            observed_current_session.node_id == command.node_id
                && matches!(
                    request.context.source,
                    StartSource::Genesis
                        | StartSource::SameNodeCold
                        | StartSource::ColdHandoff
                        | StartSource::HostFenceRecovery
                )
                && request.context.completed_effects.is_empty()
                && request.context.runtime_progress.vmm.is_none()
                && request.context.runtime_progress.network.is_none()
                && request
                    .context
                    .runtime_progress
                    .volumes
                    .iter()
                    .all(|volume| {
                        volume.local_lineage_data_directory.is_none()
                            && volume.blockd.is_none()
                            && volume.blockd_control_socket_path.is_none()
                            && volume.frontend.is_none()
                    }),
            "obsolete PrepareRoot AgentSession is not on a provable zero-use Start edge"
        );
        let Some(credentials) = self.object_write_credentials.as_ref() else {
            anyhow::bail!("obsolete ObjectWrite plan lacks its credential owner")
        };

        // A credential is not a physical-use proof by itself: registration is
        // deliberately durable before a process can consume it.  Conversely,
        // any authorization artifact, provision unit/socket, or socket-owner
        // directory proves that the old plan crossed its zero-use boundary.
        for volume in volumes {
            effect.check_active()?;
            let lineage = Path::new(volume.lineage_data_directory.as_str());
            let identity_path = lineage.join("identity.json");
            let identity = match fs::read(&identity_path) {
                Ok(actual) => Some(actual),
                Err(error) if error.kind() == ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error).context("inspect obsolete-session lineage identity")
                }
            };
            if let Some(actual) = identity {
                let expected = canonical_json(&AttachmentLineageIdentity {
                    volume_id: volume.volume.volume_id.clone(),
                    attachment_id: volume.attachment_id.clone(),
                    attachment_epoch: volume.attachment_epoch,
                    acquire_origin: volume.acquire_origin.clone(),
                    node_id: command.node_id.clone(),
                    placement_epoch: command.placement_identity.placement_epoch,
                })?;
                if actual != expected {
                    return definite_runtime_failure(
                        request,
                        cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                    );
                }
            }
            for materialized in [
                lineage.join("authorized-control.atomic-start.v1.json"),
                lineage.join("authorized-serving.atomic-start.v1.json"),
            ] {
                if !path_is_absent(&materialized)? {
                    return definite_runtime_failure(
                        request,
                        cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                    );
                }
            }
            if let (Some(service_id), Some(control_socket)) = (
                &volume.provision_service_id,
                &volume.provision_control_socket_path,
            ) {
                let unit = inspect_systemd_unit(&self.config.physical, service_id, effect)?;
                let unit_absent = unit.load_state == "not-found"
                    || unit.main_pid == 0 && unit.active_state == "inactive";
                let socket_directory = Path::new(control_socket.as_str())
                    .parent()
                    .context("Root provision control socket has no parent")?;
                if !unit_absent || !path_is_absent(socket_directory)? {
                    return definite_runtime_failure(
                        request,
                        cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                    );
                }
            }
        }

        let mut retired_credential_ids = Vec::with_capacity(volumes.len());
        for volume in volumes {
            credentials
                .retire(
                    &volume.volume.volume_id,
                    &volume.attachment_id,
                    volume.attachment_epoch,
                )
                .context("retire unused obsolete-session ObjectWrite credential")?;
            match object_write_credential::load(
                self.config.physical.state_directory.path(),
                &volume.volume.volume_id,
                &volume.attachment_id,
                volume.attachment_epoch,
            ) {
                Err(object_write_credential::ObjectWriteCredentialError::NotRegistered) => {}
                Ok(_) => anyhow::bail!("retired obsolete-session credential remained loadable"),
                Err(error) => {
                    return Err(error).context("prove obsolete-session credential absence")
                }
            }
            retired_credential_ids.push(object_write_credential_id(
                old_session,
                &volume.volume.volume_id,
                &volume.attachment_id,
                volume.attachment_epoch,
            ));
        }
        let current_session = self.config.admission_registry.current_agent_session()?;
        anyhow::ensure!(
            current_session.node_id == command.node_id && current_session != *old_session,
            "AgentSession changed back while cleaning an obsolete Start plan"
        );
        let exact_zero_use_digest = digest_serialized(
            SESSION_ZERO_USE_DOMAIN,
            &InstalledAtomicStartSessionZeroUseInput {
                operation_id: &command.operation_id,
                request_fingerprint: &command.request_fingerprint,
                runtime_incarnation: &request.context.runtime_incarnation,
                old_platform_plan_digest: &plan.plan_digest,
                old_session,
                volumes,
            },
        )?;
        let cleanup_receipt = ExactBytes::new(canonical_json(
            &InstalledAtomicStartSessionRebindCleanupReceipt {
                version: PLAN_VERSION,
                phase: plan.phase,
                node_id: command.node_id.clone(),
                cat_id: command.cat_id.clone(),
                operation_id: command.operation_id.clone(),
                request_fingerprint: command.request_fingerprint.clone(),
                runtime_incarnation: request.context.runtime_incarnation.clone(),
                old_platform_plan_digest: plan.plan_digest.clone(),
                old_session: old_session.clone(),
                observed_current_session: current_session,
                retired_credential_ids,
                exact_zero_use_digest,
            },
        )?);
        let cleanup_receipt_digest = atomic_start_session_rebind_receipt_digest(
            command,
            plan.phase,
            request.context.volume_grant_sequence,
            &plan.plan_digest,
            &cleanup_receipt,
        )?;
        Ok(AtomicStartRuntimeEffectOutcome::SessionRebindRequired {
            old_platform_plan_digest: plan.plan_digest.clone(),
            cleanup_receipt,
            cleanup_receipt_digest,
            runtime_progress: request.context.runtime_progress.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_or_apply_root_provision(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        volume: &PlannedRootVolume,
        image_manifest_digest: &Sha256Digest,
        image_target: &RemoteHead,
        object_write: &PlannedObjectWriteMode,
        control_authorization_path: &Path,
        effect: &StartPhysicalEffectContext,
    ) -> Result<ProvisionRootImageResult> {
        let transition = volume
            .provision_transition_id
            .as_ref()
            .context("Root provision plan lacks its transition ID")?;
        let process_token = volume
            .provision_process_identity_token
            .as_ref()
            .context("Root provision plan lacks its process token")?;
        let service_id = volume
            .provision_service_id
            .as_ref()
            .context("Root provision plan lacks its service ID")?;
        let control_socket = volume
            .provision_control_socket_path
            .as_ref()
            .context("Root provision plan lacks its control socket")?;
        let provision_request = ProvisionRootImageRequest {
            provision_transition_id: transition.clone(),
            volume_id: volume.volume.volume_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            attachment_epoch: volume.attachment_epoch,
            size_bytes: volume.volume.size_bytes,
            boot_image_digest: command.runtime_config.boot_image_digest.clone(),
            expected_blank_head: volume.authority_head.clone(),
            expected_provisioned_head: image_target.clone(),
        };
        anyhow::ensure!(
            provision_request.expected_blank_head.generation.get() == 0
                && provision_request.expected_blank_head.root_hash.is_none()
                && provision_request
                    .expected_blank_head
                    .root_object_id
                    .is_none()
                && image_manifest_digest != &zero_digest(),
            "Root provision plan is not an exact blank-to-generation-one edge"
        );

        let current = self.inspect_exact_volume_head(command, volume)?;
        if current == *image_target {
            self.stop_and_retire_root_process_if_present(command, plan, volume, effect)?;
            return Ok(ProvisionRootImageResult {
                provision_transition_id: transition.clone(),
                volume_id: volume.volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: volume.attachment_epoch,
                resulting_head: image_target.clone(),
            });
        }
        anyhow::ensure!(
            current == volume.authority_head,
            "Root authority is neither the planned blank head nor exact provision target"
        );
        self.ensure_fresh_effect_authority(request, effect.deadline())?;

        let owner = InstalledAtomicStartBlockdSocketOwner::new(
            command,
            plan,
            AtomicStartBlockdSocketRole::RootProvision,
            transition.clone(),
            service_id.clone(),
            control_socket.clone(),
            None,
        )?;
        self.publish_blockd_socket_owner_with_authority(request, effect, &owner)?;
        let blockd = planned_blockd_config(&self.config.blockd)?;
        let arguments =
            root_blockd_arguments(&blockd, volume, control_authorization_path, object_write)?;
        let launch = SystemdServiceLaunch {
            unit_id: service_id.clone(),
            executable: PathBuf::from(blockd.executable.as_str()),
            arguments,
        };
        let process = ensure_systemd_service(&self.config, &command.cat_id, &launch, effect)
            .context("launch or adopt exact Root control blockd")?;
        let status = blockd_status(Path::new(control_socket.as_str()), process.pid, effect)
            .context("verify Root control blockd handshake")?;
        anyhow::ensure!(
            status.volume_id == volume.volume.volume_id.as_str()
                && status.attachment_id == volume.attachment_id.as_str()
                && status.attachment_epoch == Some(volume.attachment_epoch)
                && status.node_id.as_ref() == Some(&command.node_id)
                && status.placement_epoch == Some(command.placement_identity.placement_epoch)
                && status.size_bytes == Some(volume.volume.size_bytes)
                && status.scope_id.as_ref() == Some(service_id)
                && status.process_identity_token.as_ref() == Some(process_token)
                && status.control_only == Some(true)
                && status.guest_io_enabled == Some(false)
                && status.remote_head.as_ref() == Some(&volume.authority_head)
                && status.remote_durable_generation == 0
                && status.local_durable_generation == 0
                && !status.fenced,
            "Root control blockd handshake changed command, authority, or process identity"
        );
        anyhow::ensure!(
            inspect_systemd_service(&self.config.physical, &command.cat_id, &launch, effect,)?
                == SystemdServiceInspection::Exact(process.clone()),
            "Root control blockd changed during handshake"
        );

        self.ensure_fresh_effect_authority(request, effect.deadline())?;
        let exchanged = exchange_root_provision(
            Path::new(control_socket.as_str()),
            process.pid,
            &provision_request,
            effect,
        );
        let result = match exchanged {
            Ok(result) => result,
            Err(exchange_error) => {
                let discovered = self.inspect_exact_volume_head(command, volume)?;
                if discovered != *image_target {
                    return Err(exchange_error)
                        .context("Root provision response was ambiguous and target is absent");
                }
                ProvisionRootImageResult {
                    provision_transition_id: transition.clone(),
                    volume_id: volume.volume.volume_id.clone(),
                    attachment_id: volume.attachment_id.clone(),
                    attachment_epoch: volume.attachment_epoch,
                    resulting_head: image_target.clone(),
                }
            }
        };
        anyhow::ensure!(
            result.provision_transition_id == *transition
                && result.volume_id == volume.volume.volume_id
                && result.attachment_id == volume.attachment_id
                && result.attachment_epoch == volume.attachment_epoch
                && result.resulting_head == *image_target
                && self.inspect_exact_volume_head(command, volume)? == *image_target,
            "Root provision result or authoritative postcondition changed"
        );
        stop_exact_systemd_service(&self.config, &command.cat_id, &launch, &process, effect)
            .context("stop exact completed Root control blockd")?;
        retire_blockd_socket_owner(&owner).context("retire exact completed Root socket owner")?;
        Ok(result)
    }

    fn inspect_exact_volume_head(
        &self,
        command: &LifecycleCommandEnvelope,
        planned: &PlannedRootVolume,
    ) -> Result<RemoteHead> {
        let candidates = BTreeSet::from([planned.volume.volume_id.clone()]);
        let snapshot = self
            .config
            .physical
            .volume_inventory_authority
            .load_node_volume_inventory(&command.node_id, &candidates)
            .context("reload exact Root Volume authority")?;
        anyhow::ensure!(
            snapshot.node_id == command.node_id,
            "Root authority snapshot belongs to another Node"
        );
        let record = snapshot
            .records
            .iter()
            .find(|record| record.volume.volume_id == planned.volume.volume_id)
            .context("Root authority snapshot omitted the candidate")?;
        let binding = record
            .binding
            .as_ref()
            .context("Root authority candidate is no longer Owned")?;
        anyhow::ensure!(
            binding.owner_node_id == command.node_id
                && binding.attachment_id == planned.attachment_id
                && binding.attachment_epoch == planned.attachment_epoch
                && record.volume.size_bytes == planned.volume.size_bytes
                && record.volume.durability == planned.volume.durability,
            "Root authority snapshot changed its owner or immutable shape"
        );
        Ok(record.volume.head.clone())
    }

    fn stop_and_retire_root_process_if_present(
        &self,
        command: &LifecycleCommandEnvelope,
        plan: &InstalledAtomicStartPlatformPlan,
        volume: &PlannedRootVolume,
        effect: &StartPhysicalEffectContext,
    ) -> Result<()> {
        let (Some(transition), Some(service_id), Some(control_socket)) = (
            &volume.provision_transition_id,
            &volume.provision_service_id,
            &volume.provision_control_socket_path,
        ) else {
            anyhow::bail!("Root cleanup plan is incomplete")
        };
        let blockd = planned_blockd_config(&self.config.blockd)?;
        let control_path = Path::new(volume.lineage_data_directory.as_str())
            .join("authorized-control.atomic-start.v1.json");
        let root_plan_object_write = match &plan.body {
            InstalledAtomicStartPlanBody::PrepareRoot { object_write, .. } => object_write,
            _ => anyhow::bail!("Root cleanup received another phase plan"),
        };
        let launch = SystemdServiceLaunch {
            unit_id: service_id.clone(),
            executable: PathBuf::from(blockd.executable.as_str()),
            arguments: root_blockd_arguments(
                &blockd,
                volume,
                &control_path,
                root_plan_object_write,
            )?,
        };
        match inspect_systemd_service(&self.config.physical, &command.cat_id, &launch, effect)? {
            SystemdServiceInspection::Absent => {}
            SystemdServiceInspection::Exact(process) => stop_exact_systemd_service(
                &self.config,
                &command.cat_id,
                &launch,
                &process,
                effect,
            )?,
            SystemdServiceInspection::Starting => {
                anyhow::bail!("Root provision unit is still in an ambiguous starting state")
            }
        }
        let owner = InstalledAtomicStartBlockdSocketOwner::new(
            command,
            plan,
            AtomicStartBlockdSocketRole::RootProvision,
            transition.clone(),
            service_id.clone(),
            control_socket.clone(),
            None,
        )?;
        retire_blockd_socket_owner_if_present(&owner)?;
        Ok(())
    }

    fn inspect_or_apply_devices(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        blockd: &PlannedBlockdLaunchConfig,
        volumes: &[PlannedDevice],
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        anyhow::ensure!(
            volumes.len() == request.context.volume_grants.len()
                && volumes.len() == command.runtime_config.volumes.len(),
            "PrepareDevices plan changed the Volume set"
        );
        let root_receipt =
            completed_receipt(&request.context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let InstalledAtomicStartReceiptBody::PrepareRoot {
            volumes: root_receipts,
            ..
        } = root_receipt.body
        else {
            anyhow::bail!("PrepareRoot platform receipt has another schema")
        };
        anyhow::ensure!(
            root_receipts.len() == volumes.len(),
            "PrepareRoot receipt changed the PrepareDevices Volume set"
        );
        let root_plan =
            completed_plan(&request.context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let object_write = match &root_plan.body {
            InstalledAtomicStartPlanBody::PrepareRoot { object_write, .. } => object_write,
            _ => anyhow::bail!("PrepareRoot plan has another schema"),
        };

        let zero_mutation = volumes.iter().try_fold(true, |zero, volume| {
            Ok::<_, anyhow::Error>(
                zero && path_is_absent(Path::new(
                    volume.authorized_serving_artifact_path.as_str(),
                ))?,
            )
        })?;
        if lease_loss_allows_same_plan_refresh(zero_mutation)
            && !self.effect_authority_has_budget(request, effect.deadline())?
        {
            return volume_refresh_required(request, plan, effect.deadline());
        }
        let mut prepared_devices = Vec::with_capacity(volumes.len());
        let mut progress = previous_progress(request)?.clone();
        anyhow::ensure!(
            progress.volumes.len() == volumes.len(),
            "PrepareDevices progress changed the Volume set"
        );
        for (index, ((planned, grant), root)) in volumes
            .iter()
            .zip(&request.context.volume_grants)
            .zip(&root_receipts)
            .enumerate()
        {
            anyhow::ensure!(
                planned.volume == grant.authority_receipt.volume
                    && planned.attachment_id == grant.volume.attachment_id
                    && planned.attachment_epoch == grant.volume.attachment_epoch
                    && planned.acquire_origin == grant.acquire_origin
                    && planned.lineage_data_directory == grant.planned_local_lineage_data_directory
                    && root.volume_id == planned.volume.volume_id
                    && remote_head_is_same_or_later(
                        &grant.authoritative_head,
                        &planned.launch_head,
                    )
                    && remote_head_is_same_or_later(
                        &grant.authoritative_head,
                        &root.authority_head,
                    ),
                "PrepareDevices plan, Root receipt, and current grant changed lineage"
            );
            let root_attachment = decode_authorized_serving_attachment(
                &root.authorized_serving_attachment,
                &root.authorized_serving_artifact_digest,
            )?;
            let attachment = authorized_serving_attachment(
                grant,
                &root_attachment.identity,
                root_attachment.object_write_credential.clone(),
                grant.authoritative_head.clone(),
            )?;
            let authorization_bytes = canonical_json(&attachment)?;
            self.publish_exact_with_authority(
                request,
                effect,
                self.config.physical.state_directory.path(),
                Path::new(planned.authorized_serving_artifact_path.as_str()),
                &authorization_bytes,
                0o600,
            )
            .context("publish exact PrepareDevices serving authorization")?;
            let authorization = inspect_direct_authorization_identity(
                self.config.physical.state_directory.path(),
                &planned.authorized_serving_artifact_path,
                &authorization_bytes,
            )?;
            let disk_kind = match planned.volume.disk_role {
                DiskRole::Root => DiskKind::Root,
                DiskRole::Persistent => DiskKind::Persistent,
            };
            let purpose = match (
                planned.volume.disk_role,
                planned.launch_head.generation.get(),
            ) {
                (DiskRole::Root, _) => DirectAuthorizedAttachmentPurpose::ExistingRoot,
                (DiskRole::Persistent, 0) => {
                    DirectAuthorizedAttachmentPurpose::PersistentUninitialized
                }
                (DiskRole::Persistent, _) => {
                    DirectAuthorizedAttachmentPurpose::PersistentInitialized
                }
            };
            let prepared = PreparedDeviceInput {
                volume_intent_id: atomic_start_launch_volume_id(command, &planned.volume)?,
                disk_id: planned.volume.disk_id.clone(),
                volume_id: planned.volume.volume_id.clone(),
                disk_kind,
                attachment_id: planned.attachment_id.clone(),
                attachment_epoch: planned.attachment_epoch,
                acquire_origin: planned.acquire_origin.clone(),
                expected_head: grant.authoritative_head.clone(),
                size_bytes: planned.volume.size_bytes,
                durability: planned.volume.durability,
                guest_device: GuestDeviceIdentity {
                    serial: planned.volume.guest_device_serial.clone(),
                    slot: planned.volume.guest_device_slot,
                },
                ownership_token: planned.device_ownership_token.clone(),
                serving_authority: Box::new(
                    ServingAuthorityProvenance::DirectAuthorizedAttachment {
                        authorization,
                        purpose,
                    },
                ),
                serving_process: ServingBlockdIdentity {
                    scope_id: planned.serving_service_id.clone(),
                    control_socket_path: planned.control_socket_path.clone(),
                    data_directory: planned.lineage_data_directory.clone(),
                    executable_path: blockd.executable.clone(),
                    process_identity_token: planned.serving_process_identity_token.clone(),
                },
                frontend: planned.frontend.clone(),
            };
            let attribution = InstalledAtomicStartDeviceAttribution::new(
                command,
                plan,
                grant.grant_receipt_digest.clone(),
                sha256_bytes(&authorization_bytes),
                prepared.clone(),
            )?;
            self.publish_exact_with_authority(
                request,
                effect,
                self.config.physical.state_directory.path(),
                Path::new(planned.command_attribution_path.as_str()),
                &canonical_json(&attribution)?,
                0o600,
            )
            .context("publish exact command-bound PrepareDevices attribution")?;

            let frontend_socket = match &planned.frontend {
                PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    ..
                } => listener_socket_path.clone(),
                PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => socket_path.clone(),
            };
            let owner = InstalledAtomicStartBlockdSocketOwner::new(
                command,
                plan,
                AtomicStartBlockdSocketRole::Serving,
                planned.device_ownership_token.clone(),
                planned.serving_service_id.clone(),
                planned.control_socket_path.clone(),
                Some(frontend_socket),
            )?;
            self.publish_blockd_socket_owner_with_authority(request, effect, &owner)?;
            let arguments = serving_blockd_arguments(blockd, planned, object_write)?;
            let launch = SystemdServiceLaunch {
                unit_id: planned.serving_service_id.clone(),
                executable: PathBuf::from(blockd.executable.as_str()),
                arguments,
            };
            let blockd_process = match inspect_systemd_service(
                &self.config.physical,
                &command.cat_id,
                &launch,
                effect,
            )? {
                SystemdServiceInspection::Exact(process) => process,
                SystemdServiceInspection::Starting => wait_for_exact_systemd_service(
                    &self.config.physical,
                    &command.cat_id,
                    &launch,
                    effect,
                )?,
                SystemdServiceInspection::Absent => {
                    self.ensure_fresh_effect_authority(request, effect.deadline())?;
                    ensure_systemd_service(&self.config, &command.cat_id, &launch, effect)
                        .context("launch exact serving blockd")?
                }
            };
            let status = blockd_status(
                Path::new(planned.control_socket_path.as_str()),
                blockd_process.pid,
                effect,
            )
            .context("verify serving blockd handshake")?;
            validate_serving_blockd_status(command, planned, grant, &status).map_err(|_| {
                definite_physical_failure(
                    cats_api::runtime_lifecycle::CommandFailureReason::DevicePrepareFailed,
                )
            })?;
            anyhow::ensure!(
                inspect_systemd_service(&self.config.physical, &command.cat_id, &launch, effect,)?
                    == SystemdServiceInspection::Exact(blockd_process.clone()),
                "serving blockd changed during exact handshake"
            );

            let installed_frontend = match &planned.frontend {
                PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => {
                    inspect_exact_socket(Path::new(socket_path.as_str()))?;
                    InstalledRuntimeBlockFrontend::VhostUserBlk {
                        socket_path: socket_path.clone(),
                    }
                }
                PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    device_path,
                    ..
                } => {
                    inspect_exact_socket(Path::new(listener_socket_path.as_str()))?;
                    let client = self.inspect_or_apply_kernel_nbd(
                        command,
                        request,
                        planned,
                        listener_socket_path,
                        device_path,
                        effect,
                    )?;
                    InstalledRuntimeBlockFrontend::KernelNbd {
                        device_path: device_path.clone(),
                        client,
                    }
                }
            };
            let progress_volume = progress
                .volumes
                .get_mut(index)
                .context("PrepareDevices progress omitted a Volume")?;
            anyhow::ensure!(
                progress_volume.volume_id == planned.volume.volume_id,
                "PrepareDevices progress reordered Volumes"
            );
            progress_volume.authority_head = grant.authoritative_head.clone();
            progress_volume.authority_receipt_digest = Some(grant.grant_receipt_digest.clone());
            progress_volume.local_lineage_data_directory =
                Some(planned.lineage_data_directory.clone());
            progress_volume.blockd = Some(blockd_process);
            progress_volume.blockd_control_socket_path = Some(planned.control_socket_path.clone());
            progress_volume.frontend = Some(installed_frontend);
            prepared_devices.push(prepared);
        }
        if let PlannedObjectWriteMode::Gateway { session, .. } = object_write {
            anyhow::ensure!(
                self.config.admission_registry.current_agent_session()? == *session,
                "AgentSession changed during PrepareDevices physical effect"
            );
        }
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            progress.vmm,
            progress.network,
            progress.volumes,
            progress.artifact_classifications,
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::PrepareDevices {
                devices: prepared_devices,
                progress_volumes: progress.volumes.clone(),
            },
            progress,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_or_apply_kernel_nbd(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        planned: &PlannedDevice,
        listener_socket_path: &HostPath,
        device_path: &HostPath,
        effect: &StartPhysicalEffectContext,
    ) -> Result<InstalledRuntimeProcessIdentity> {
        let kernel = self
            .config
            .physical
            .kernel_nbd
            .as_ref()
            .context("kernel-NBD effect lacks installed pool configuration")?;
        let unit_id = planned
            .kernel_nbd_client_service_id
            .as_ref()
            .context("kernel-NBD plan lacks its exact transient unit")?;
        let expected = KernelNbdClientExpectation::new(
            kernel,
            &command.cat_id,
            unit_id,
            listener_socket_path,
            device_path,
            planned.volume.size_bytes,
        )?;
        if let Some(process) = inspect_exact_kernel_nbd_client(&self.config.physical, &expected)? {
            validate_kernel_nbd_systemd_unit(&self.config.physical, &expected, effect)?;
            return Ok(process);
        }

        // The serving blockd already exists, so an expired lease cannot take
        // the zero-mutation refresh edge. It must fail closed and let the
        // command's StrongStop clean the exact retained progress instead.
        self.ensure_fresh_effect_authority(request, effect.deadline())?;
        let unit = inspect_systemd_unit(&self.config.physical, unit_id, effect)?;
        let absent =
            unit.load_state == "not-found" || unit.main_pid == 0 && unit.active_state == "inactive";
        if absent {
            let slice = cat_execution_slice_id(&command.cat_id);
            let mut submission = Command::new(&self.config.systemd_run_binary);
            sanitize_host_command(&mut submission);
            submission
                .arg("--system")
                .arg("--quiet")
                .arg("--no-ask-password")
                .arg(format!("--unit={unit_id}"))
                .arg("--service-type=oneshot")
                .arg(format!("--slice={slice}"))
                .arg(format!("--property=Slice={slice}"))
                .arg("--property=RemainAfterExit=yes")
                .arg("--property=KillMode=control-group")
                .arg("--property=Restart=no")
                .arg("--property=UMask=0077")
                .arg("--property=TimeoutStopSec=2s")
                .arg("--property=Environment=")
                .arg("--property=EnvironmentFile=")
                .arg("--property=PassEnvironment=")
                .arg("--property=UnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL CATS_CRASH_POINT")
                .arg("--")
                .arg(&kernel.nbd_client_binary)
                .arg("-nonetlink")
                .arg("-unix")
                .arg(listener_socket_path.as_str())
                .arg(device_path.as_str())
                .args(["-b", "512", "-N", ""]);
            // Submission and helper exit are ambiguous. The strict sysfs,
            // process, argv, cgroup, and unit join below is the only success
            // oracle, so this effect never blindly submits a second client.
            let _submission = run_bounded_output(submission, effect.deadline());
        } else {
            anyhow::ensure!(
                unit.load_state == "loaded"
                    && matches!(unit.active_state.as_str(), "activating" | "active")
                    && unit.control_group
                        == crate::cat_execution_scope::cat_service_control_group(
                            &command.cat_id,
                            unit_id,
                        ),
                "kernel-NBD transient unit conflicts with its durable plan"
            );
        }
        loop {
            effect.check_active()?;
            if let Some(process) =
                inspect_exact_kernel_nbd_client(&self.config.physical, &expected)?
            {
                validate_kernel_nbd_systemd_unit(&self.config.physical, &expected, effect)?;
                return Ok(process);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn inspect_or_apply_network(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        planned: &PlannedNetworkReservation,
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        effect.check_active()?;
        let reservation = InstalledAtomicStartNetworkReservation::new(command, plan, planned)?;
        let bytes = canonical_json(&reservation)?;
        let artifact_path = Path::new(planned.artifact_path.as_str());
        let mut artifact = inspect_exact_managed_file(
            &self.config.physical.network_class_root,
            artifact_path,
            &bytes,
            0o600,
        )?;
        let predecessor_is_exact = match &planned.predecessor_artifact {
            Some(old) => {
                inspect_exact_managed_file(
                    &self.config.physical.network_class_root,
                    artifact_path,
                    old.as_slice(),
                    0o600,
                )? == ManagedFileInspection::Exact
            }
            None => false,
        };
        if artifact == ManagedFileInspection::Conflict && !predecessor_is_exact {
            return definite_runtime_failure(
                request,
                cats_api::runtime_lifecycle::CommandFailureReason::NetworkPrepareFailed,
            );
        }

        let network = ChNetwork {
            tap: planned.identity.tap_name.as_str().to_owned(),
            ownership_token: planned.identity.ownership_token.clone(),
            config: planned.identity.network_config.clone(),
        };
        let before = ch::inspect_host_network_snapshot(&self.config.physical.ip_binary, effect)
            .context("inspect Host network before atomic Start reservation")?;
        let network_state = before.reserved_network_state(&planned.identity)?;
        if predecessor_is_exact && network_state != ReservedHostNetworkState::Exact {
            return definite_runtime_failure(
                request,
                cats_api::runtime_lifecycle::CommandFailureReason::NetworkPrepareFailed,
            );
        }
        if predecessor_is_exact {
            let replacement_path = Path::new(planned.replacement_path.as_str());
            let replacement = inspect_exact_managed_file(
                &self.config.physical.network_class_root,
                replacement_path,
                &bytes,
                0o600,
            )?;
            if replacement == ManagedFileInspection::Conflict {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::NetworkPrepareFailed,
                );
            }
            if !self.effect_authority_has_budget(request, effect.deadline())? {
                return if replacement == ManagedFileInspection::Absent {
                    volume_refresh_required(request, plan, effect.deadline())
                } else {
                    materialized_plan_without_mutation_authority(
                        request,
                        effect.deadline(),
                        "Warm network replacement was materialized but its lease budget is unavailable",
                    )
                };
            }
            if replacement == ManagedFileInspection::Absent {
                publish_exact_managed_file(
                    &self.config.physical.network_class_root,
                    replacement_path,
                    &bytes,
                    0o600,
                )?;
            }
            let old = planned
                .predecessor_artifact
                .as_ref()
                .context("Warm network replacement lost predecessor bytes")?;
            replace_exact_managed_file(
                &self.config.physical.network_class_root,
                artifact_path,
                old.as_slice(),
                replacement_path,
                &bytes,
                0o600,
            )?;
            artifact = ManagedFileInspection::Exact;
        }
        if network_state == ReservedHostNetworkState::Exact
            && artifact == ManagedFileInspection::Absent
        {
            return definite_runtime_failure(
                request,
                cats_api::runtime_lifecycle::CommandFailureReason::NetworkPrepareFailed,
            );
        }
        if artifact == ManagedFileInspection::Absent
            && network_state == ReservedHostNetworkState::Absent
            && !self.effect_authority_has_budget(request, effect.deadline())?
        {
            return volume_refresh_required(request, plan, effect.deadline());
        }
        if artifact == ManagedFileInspection::Absent {
            self.ensure_fresh_effect_authority(request, effect.deadline())?;
            publish_exact_managed_file(
                &self.config.physical.network_class_root,
                artifact_path,
                &bytes,
                0o600,
            )
            .context("publish exact atomic Start network reservation")?;
        }

        match network_state {
            ReservedHostNetworkState::Exact => {}
            ReservedHostNetworkState::Absent => {
                before
                    .ensure_candidate_available(&network)
                    .context("prove atomic Start TAP candidate is globally available")?;
                self.ensure_fresh_effect_authority(request, effect.deadline())?;
                ch::prepare_network(&self.config.ch, &network, effect)
                    .context("create exact atomic Start TAP")?;
                let after =
                    ch::inspect_host_network_snapshot(&self.config.physical.ip_binary, effect)
                        .context("inspect Host network after atomic Start reservation")?;
                anyhow::ensure!(
                    before.unchanged_except_reserved_tap(&after, &planned.identity)
                        && after.reserved_network_state(&planned.identity)?
                            == ReservedHostNetworkState::Exact,
                    "atomic Start network effect changed sibling Host state or produced a partial TAP"
                );
            }
        }
        let previous = previous_progress(request)?;
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            previous.vmm.clone(),
            Some(InstalledRuntimeNetworkManifest {
                identity: planned.identity.clone(),
            }),
            previous.volumes.clone(),
            previous.artifact_classifications.clone(),
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::PrepareNetwork {
                reservation: Box::new(reservation),
            },
            progress,
        )
    }

    fn inspect_or_apply_activate_runtime(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        launch: &RuntimeLaunchIdentity,
        mode: &AtomicVmmLaunchMode,
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        anyhow::ensure!(
            launch.runtime_incarnation == request.context.runtime_incarnation
                && launch.scope_id == service_id("cats-vmm", &launch.runtime_incarnation)?,
            "ActivateRuntime launch changed incarnation or systemd unit"
        );
        let spec = AtomicVmmLaunchSpec::new(
            command.node_id.clone(),
            command.cat_id.clone(),
            command.operation_id.clone(),
            command.request_fingerprint.clone(),
            plan.plan_digest.clone(),
            host_path(self.config.physical.state_directory.path().to_path_buf())?,
            launch.clone(),
            mode.clone(),
        )?;
        let spec_bytes = encode_atomic_vmm_launch_spec(&spec)?;
        let spec_path = self
            .config
            .physical
            .state_directory
            .path()
            .join(VMM_LAUNCH_FILE_NAMESPACE)
            .join(format!("p-{}", launch.runtime_incarnation.as_str()))
            .join("launch-spec.atomic-start.v1.json");

        match inspect_atomic_vmm_service(&self.config, &command.cat_id, &spec, effect)? {
            AtomicVmmServiceInspection::Exact(process) => {
                return self.complete_activate_runtime(command, request, plan, launch, process);
            }
            AtomicVmmServiceInspection::Starting | AtomicVmmServiceInspection::Paused(_) => {
                let process = wait_for_atomic_vmm_service(
                    &self.config,
                    &command.cat_id,
                    &spec,
                    effect,
                    &|| self.effect_authority_has_budget(request, effect.deadline()),
                )?;
                return self.complete_activate_runtime(command, request, plan, launch, process);
            }
            AtomicVmmServiceInspection::Absent => {}
            AtomicVmmServiceInspection::Conflict => {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
                );
            }
        }

        let spec_state = inspect_exact_managed_file(
            self.config.physical.state_directory.path(),
            &spec_path,
            &spec_bytes,
            0o600,
        )?;
        if spec_state == ManagedFileInspection::Conflict {
            return definite_runtime_failure(
                request,
                cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
            );
        }
        if !self.effect_authority_has_budget(request, effect.deadline())? {
            return if lease_loss_allows_same_plan_refresh(
                spec_state == ManagedFileInspection::Absent,
            ) {
                volume_refresh_required(request, plan, effect.deadline())
            } else {
                materialized_plan_without_mutation_authority(
                    request,
                    effect.deadline(),
                    "atomic VMM launch spec was materialized but the process is absent and the lease budget is unavailable",
                )
            };
        }
        if spec_state == ManagedFileInspection::Absent {
            publish_exact_managed_file(
                self.config.physical.state_directory.path(),
                &spec_path,
                &spec_bytes,
                0o600,
            )
            .context("publish exact atomic VMM launch spec")?;
        }
        self.ensure_fresh_effect_authority(request, effect.deadline())?;
        submit_atomic_vmm_service(&self.config, &command.cat_id, &spec, &spec_path, effect)?;
        let process =
            wait_for_atomic_vmm_service(&self.config, &command.cat_id, &spec, effect, &|| {
                self.effect_authority_has_budget(request, effect.deadline())
            })?;
        self.complete_activate_runtime(command, request, plan, launch, process)
    }

    fn complete_activate_runtime(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        launch: &RuntimeLaunchIdentity,
        process: InstalledRuntimeProcessIdentity,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let vmm = InstalledRuntimeVmmManifest {
            process,
            parent_slice_id: cat_execution_slice_id(&command.cat_id),
            systemd_unit_id: launch.scope_id.clone(),
            api_socket_path: launch.api_socket_path.clone(),
            vsock_socket_path: launch.vsock_socket_path.clone(),
            memory_file_path: launch.memory_file_path.clone(),
            launch_identity: Box::new(launch.clone()),
        };
        let previous = previous_progress(request)?;
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            Some(vmm.clone()),
            previous.network.clone(),
            previous.volumes.clone(),
            previous.artifact_classifications.clone(),
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::ActivateRuntime { vmm: Box::new(vmm) },
            progress,
        )
    }

    fn inspect_or_apply_format_persistent(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        volumes: &[PlannedPersistentInitialization],
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let expected_filesystems = persistent_filesystems(command, &request.context)?;
        anyhow::ensure!(
            volumes
                .iter()
                .map(|volume| &volume.filesystem)
                .eq(expected_filesystems.iter()),
            "FormatPersistentVolumes plan changed the Persistent set"
        );
        if volumes.is_empty() {
            return self.complete_without_physical_change(
                command,
                request,
                plan,
                InstalledAtomicStartReceiptBody::FormatPersistentVolumes {
                    format_receipts: Vec::new(),
                },
            );
        }
        let (launch, vmm_process) = self.inspect_activated_vmm(command, request, effect, true)?;
        let device_plan = completed_plan(
            &request.context,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
        )?;
        let InstalledAtomicStartPlanBody::PrepareDevices {
            volumes: planned_devices,
            ..
        } = &device_plan.body
        else {
            anyhow::bail!("PrepareDevices platform plan has another schema")
        };

        let mut format_receipts = Vec::with_capacity(volumes.len());
        let mut progress = previous_progress(request)?.clone();
        let mut mutated = false;
        for planned in volumes {
            effect.check_active()?;
            let filesystem = &planned.filesystem;
            let config_index = command
                .runtime_config
                .volumes
                .iter()
                .position(|volume| volume.volume_id == filesystem.volume_id)
                .context("Persistent plan references a volume outside config")?;
            let config_volume = &command.runtime_config.volumes[config_index];
            let grant = &request.context.volume_grants[config_index];
            let planned_device = &planned_devices[config_index];
            let progress_volume = &request.context.runtime_progress.volumes[config_index];
            anyhow::ensure!(
                planned.inspection.binding.volume == *config_volume
                    && planned.inspection.attachment_id == filesystem.attachment_id
                    && planned.inspection.attachment_epoch == filesystem.attachment_epoch
                    && planned_device.volume == *config_volume
                    && progress_volume.volume_id == filesystem.volume_id,
                "Persistent format plan changed config, grant, or device order"
            );
            let current_binding = persistent_initialization_binding(command, config_volume, grant)?;
            let inspection = match self
                .config
                .persistent_initialization_control
                .inspect_persistent_initialization(
                    self.config
                        .admission_registry
                        .current_agent_session()
                        .context("read AgentSession for Persistent format rebind")?,
                    LifecyclePersistentInitializationInspectRequest {
                        binding: Box::new(current_binding.clone()),
                    },
                    effect.deadline(),
                ) {
                Ok(inspection) => inspection,
                Err(LifecycleVolumeClientError::Rejected(_)) => {
                    return definite_runtime_failure(
                        request,
                        cats_api::runtime_lifecycle::CommandFailureReason::VolumeAuthorityRejected,
                    )
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(error))
                        .context("Persistent initialization format rebind is ambiguous")
                }
            };
            if inspection.binding.as_ref() != &current_binding
                || !persistent_initialization_inspection_rebinds_plan(
                    &planned.inspection,
                    &inspection,
                )
            {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                );
            }

            match &inspection.initialization {
                LifecyclePersistentInitializationState::Initialized {
                    filesystem_uuid,
                    initialized_head,
                    ..
                } => {
                    anyhow::ensure!(
                        filesystem_uuid == &filesystem.filesystem_uuid
                            && initialized_head.generation.get() > 0,
                        "initialized Persistent inspection changed UUID or head"
                    );
                    format_receipts.push(encode_exact_json(
                        &InstalledPersistentFormatReceipt::AlreadyInitialized {
                            inspection: Box::new(inspection.clone()),
                        },
                        "encode already-initialized Persistent format receipt",
                    )?);
                    continue;
                }
                LifecyclePersistentInitializationState::Uninitialized { .. } => {}
            }

            let LifecyclePersistentInitializationState::Uninitialized {
                initialization_token,
                filesystem_uuid,
                expected_blank_head,
            } = &inspection.initialization
            else {
                unreachable!("initialized branch continued")
            };
            anyhow::ensure!(
                filesystem_uuid == &filesystem.filesystem_uuid
                    && inspection.current_head == *expected_blank_head,
                "uninitialized Persistent inspection changed create-time lineage"
            );
            let initialization = FilesystemInitialization::Initialize {
                initialization_token: initialization_token.clone(),
                expected_blank_head: expected_blank_head.clone(),
            };
            let guest_binding = persistent_guest_binding(
                &request.context.runtime_incarnation,
                filesystem,
                config_volume.size_bytes,
                initialization,
            )?;
            let probe = FilesystemControlRequestV1 {
                version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
                challenge: planned.probe_challenge.clone(),
                timeout_ms: planned.guest_timeout_ms,
                operation: FilesystemControlOperationV1::Probe,
                filesystem: Box::new(guest_binding.clone()),
                expected_head: expected_blank_head.clone(),
            };
            let observed =
                execute_guest_filesystem(&launch, vmm_process.pid, probe, effect.deadline())?;
            if observed.outcome == FilesystemControlOutcomeV1::Conflict {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                );
            }
            let authoritative_before =
                self.inspect_current_persistent_head(command, config_volume, grant)?;
            match &observed.observation.filesystem {
                FilesystemIdentityV1::Blank => {
                    if authoritative_before != *expected_blank_head {
                        return definite_runtime_failure(
                            request,
                            cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                        );
                    }
                    if !self.effect_authority_has_budget(request, effect.deadline())? {
                        return if mutated {
                            definite_runtime_failure(
                                request,
                                cats_api::runtime_lifecycle::CommandFailureReason::DurabilityConvergenceTimeout,
                            )
                        } else {
                            volume_refresh_required(request, plan, effect.deadline())
                        };
                    }
                    let format = FilesystemControlRequestV1 {
                        version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
                        challenge: planned.format_challenge.clone(),
                        timeout_ms: planned.guest_timeout_ms,
                        operation: FilesystemControlOperationV1::FormatExt4,
                        filesystem: Box::new(guest_binding.clone()),
                        expected_head: expected_blank_head.clone(),
                    };
                    let response = execute_guest_filesystem(
                        &launch,
                        vmm_process.pid,
                        format,
                        effect.deadline(),
                    )?;
                    if response.outcome == FilesystemControlOutcomeV1::Conflict {
                        return definite_runtime_failure(
                            request,
                            cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                        );
                    }
                    mutated = true;
                }
                FilesystemIdentityV1::Ext4 {
                    filesystem_uuid: observed_uuid,
                } if observed_uuid == filesystem_uuid => {
                    // Exact crash recovery after mkfs but before the phase
                    // receipt: never format a second time.
                    mutated = true;
                }
                FilesystemIdentityV1::Ext4 { .. } | FilesystemIdentityV1::Foreign => {
                    return definite_runtime_failure(
                        request,
                        cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                    )
                }
            }

            let post_probe_request = FilesystemControlRequestV1 {
                version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
                challenge: planned.post_format_probe_challenge.clone(),
                timeout_ms: planned.guest_timeout_ms,
                operation: FilesystemControlOperationV1::Probe,
                filesystem: Box::new(guest_binding.clone()),
                expected_head: expected_blank_head.clone(),
            };
            let post_probe = execute_guest_filesystem(
                &launch,
                vmm_process.pid,
                post_probe_request,
                effect.deadline(),
            )?;
            if post_probe.outcome != FilesystemControlOutcomeV1::Exact {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                );
            }
            if !self.effect_authority_has_budget(request, effect.deadline())? {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::DurabilityConvergenceTimeout,
                );
            }
            let flush_request = FilesystemControlRequestV1 {
                version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
                challenge: planned.flush_challenge.clone(),
                timeout_ms: planned.guest_timeout_ms,
                operation: FilesystemControlOperationV1::FlushDevice,
                filesystem: Box::new(guest_binding),
                expected_head: expected_blank_head.clone(),
            };
            let flush = execute_guest_filesystem(
                &launch,
                vmm_process.pid,
                flush_request,
                effect.deadline(),
            )?;
            if flush.outcome != FilesystemControlOutcomeV1::Exact {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::GuestNotReady,
                );
            }
            let blockd_process = progress_volume
                .blockd
                .as_ref()
                .context("Persistent format progress lacks serving blockd")?;
            send_exact_blockd_drain(
                Path::new(
                    progress_volume
                        .blockd_control_socket_path
                        .as_ref()
                        .context("Persistent format progress lacks blockd control socket")?
                        .as_str(),
                ),
                blockd_process.pid,
                effect,
            )?;
            let status = blockd_status(
                Path::new(planned_device.control_socket_path.as_str()),
                blockd_process.pid,
                effect,
            )?;
            let initialized_head =
                self.inspect_current_persistent_head(command, config_volume, grant)?;
            validate_guest_ready_blockd_status(command, planned_device, &initialized_head, &status)
                .map_err(|_| {
                    definite_physical_failure(
                        cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                    )
                })?;
            let initialized_generation = i64::try_from(initialized_head.generation.get())
                .context("Persistent initialized generation exceeds blockd status domain")?;
            if initialized_head.generation.get() == 0
                || status.local_durable_generation != initialized_generation
                || status.remote_durable_generation != initialized_generation
                || status.unpublished_generations != 0
            {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::DurabilityConvergenceTimeout,
                );
            }
            let guest_probe = LifecyclePersistentInitializationGuestProbe {
                challenge: post_probe.request.challenge.clone(),
                runtime_incarnation: request.context.runtime_incarnation.clone(),
                guest_device_serial: filesystem.guest_device.serial.clone(),
                guest_device_slot: filesystem.guest_device.slot,
                device_major: post_probe.observation.device_major,
                device_minor: post_probe.observation.device_minor,
                size_bytes: config_volume.size_bytes,
                filesystem_uuid: filesystem.filesystem_uuid.clone(),
                filesystem_state: LifecyclePersistentGuestFilesystemState::ExactExt4Unmounted,
                guest_response_digest: digest_serialized(
                    GUEST_FILESYSTEM_RESPONSE_DOMAIN,
                    &post_probe,
                )?,
            };
            let target = LifecycleVolumeTarget {
                disk_id: filesystem.disk_id.clone(),
                disk_role: DiskRole::Persistent,
                volume_id: filesystem.volume_id.clone(),
                attachment_id: filesystem.attachment_id.clone(),
                attachment_epoch: filesystem.attachment_epoch,
            };
            let drain_receipt_digest = digest_serialized(
                BLOCKD_DRAIN_RECEIPT_DOMAIN,
                &BlockdDrainReceiptInput {
                    operation_id: &command.operation_id,
                    request_fingerprint: &command.request_fingerprint,
                    volume_id: &filesystem.volume_id,
                    attachment_id: &filesystem.attachment_id,
                    attachment_epoch: filesystem.attachment_epoch,
                    blockd: blockd_process,
                    status: &status,
                },
            )?;
            let commit = LifecyclePersistentInitializationCommitRequest {
                binding: inspection.binding.clone(),
                format_plan_digest: plan.plan_digest.clone(),
                initialization_token: initialization_token.clone(),
                filesystem_uuid: filesystem_uuid.clone(),
                expected_blank_head: expected_blank_head.clone(),
                initialized_head: initialized_head.clone(),
                guest_probe: Box::new(guest_probe),
                flush_drain: Box::new(LifecyclePersistentInitializationFlushDrainReceipt {
                    guest_flush_challenge: flush.request.challenge.clone(),
                    guest_flush_response_digest: digest_serialized(
                        GUEST_FILESYSTEM_RESPONSE_DOMAIN,
                        &flush,
                    )?,
                    blockd_drain_receipt_digest: drain_receipt_digest,
                    durability: LifecycleVolumeDurabilityProof {
                        scope: inspection.binding.scope.clone(),
                        volume: target,
                        remote_head: initialized_head.clone(),
                        local_durable_generation: initialized_head.generation,
                        remote_durable_generation: initialized_head.generation,
                        pending_pack_count: WireU64::new(0)
                            .context("zero pending-pack count is outside wire domain")?,
                    },
                }),
            };
            validate_lifecycle_persistent_initialization_commit(&commit).map_err(|_| {
                anyhow::anyhow!("Persistent initialization commit request is not canonical")
            })?;
            progress.volumes[config_index].authority_head = initialized_head;
            format_receipts.push(encode_exact_json(
                &InstalledPersistentFormatReceipt::CommitRequired {
                    commit: Box::new(commit),
                },
                "encode Persistent initialization format receipt",
            )?);
        }
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            progress.vmm,
            progress.network,
            progress.volumes,
            progress.artifact_classifications,
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::FormatPersistentVolumes { format_receipts },
            progress,
        )
    }

    fn inspect_or_apply_commit_persistent(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        format_plan_digest: &Sha256Digest,
        commit_requests: &[ExactBytes],
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let filesystems = persistent_filesystems(command, &request.context)?;
        anyhow::ensure!(
            filesystems.len() == commit_requests.len(),
            "Persistent commit plan changed the filesystem set"
        );
        if commit_requests.is_empty() {
            return self.complete_without_physical_change(
                command,
                request,
                plan,
                InstalledAtomicStartReceiptBody::CommitPersistentInitialized {
                    commit_receipts: Vec::new(),
                },
            );
        }
        let session = self
            .config
            .admission_registry
            .current_agent_session()
            .context("read AgentSession for Persistent initialization commit")?;
        anyhow::ensure!(
            session.node_id == command.node_id,
            "Persistent initialization commit session belongs to another Node"
        );
        let mut receipts = Vec::with_capacity(commit_requests.len());
        let mut progress = previous_progress(request)?.clone();
        for (filesystem, exact) in filesystems.iter().zip(commit_requests) {
            effect.check_active()?;
            let config_index = command
                .runtime_config
                .volumes
                .iter()
                .position(|volume| volume.volume_id == filesystem.volume_id)
                .context("Persistent commit references an unknown volume")?;
            let configured = &command.runtime_config.volumes[config_index];
            let grant = &request.context.volume_grants[config_index];
            let expected_binding = persistent_initialization_binding(command, configured, grant)?;
            let format: InstalledPersistentFormatReceipt =
                decode_exact_json(exact, "decode Persistent format receipt during commit")?;
            let receipt = match format {
                InstalledPersistentFormatReceipt::AlreadyInitialized { inspection } => {
                    anyhow::ensure!(
                        inspection.binding.volume.volume_id == filesystem.volume_id
                            && matches!(
                                inspection.initialization,
                                LifecyclePersistentInitializationState::Initialized { .. }
                            ),
                        "already-initialized receipt changed volume or state"
                    );
                    InstalledPersistentCommitReceipt::AlreadyInitialized { inspection }
                }
                InstalledPersistentFormatReceipt::CommitRequired { commit } => {
                    anyhow::ensure!(
                        commit.binding.volume.volume_id == filesystem.volume_id
                            && commit.format_plan_digest == *format_plan_digest,
                        "Persistent commit request reordered volumes or changed its format plan"
                    );
                    let inspection = match self
                        .config
                        .persistent_initialization_control
                        .inspect_persistent_initialization(
                            session.clone(),
                            LifecyclePersistentInitializationInspectRequest {
                                binding: commit.binding.clone(),
                            },
                            effect.deadline(),
                        ) {
                        Ok(inspection) => inspection,
                        Err(LifecycleVolumeClientError::Rejected(_)) => {
                            return definite_runtime_failure(
                                request,
                                cats_api::runtime_lifecycle::CommandFailureReason::VolumeAuthorityRejected,
                            )
                        }
                        Err(error) => {
                            return Err(anyhow::anyhow!(error)).context(
                                "Persistent initialization commit discovery is ambiguous",
                            )
                        }
                    };
                    if validate_journaled_persistent_commit_binding(
                        &commit,
                        &inspection,
                        &expected_binding,
                        &grant.volume.attachment_id,
                        grant.volume.attachment_epoch,
                    )
                    .is_err()
                    {
                        return definite_runtime_failure(
                            request,
                            cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                        );
                    }
                    let observation =
                        match classify_journaled_persistent_commit_inspection(&commit, &inspection)
                        {
                            Ok(observation) => observation,
                            Err(_) => {
                                return definite_runtime_failure(
                                    request,
                                    cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                                )
                            }
                        };
                    // Format already completed Guest mkfs, flush, blockd
                    // drain and R=L. This phase is now a pure Control CAS and
                    // must not renew away the exact latest StartGrant frozen
                    // in `commit`; Control rejects a concurrently newer grant.
                    let committed = match submit_journaled_persistent_commit(
                        &request.context.runtime_incarnation,
                        format_plan_digest,
                        commit.as_ref(),
                        observation,
                        |runtime_incarnation, expected_format_plan_digest, exact_commit| {
                            self.config
                                .persistent_initialization_control
                                .commit_persistent_initialization(
                                    session.clone(),
                                    runtime_incarnation,
                                    expected_format_plan_digest,
                                    exact_commit,
                                    effect.deadline(),
                                )
                        },
                    ) {
                        Ok(committed) => committed,
                        Err(LifecycleVolumeClientError::Rejected(_)) => {
                            return definite_runtime_failure(
                                request,
                                cats_api::runtime_lifecycle::CommandFailureReason::VolumeAuthorityRejected,
                            )
                        }
                        Err(error) => {
                            return Err(anyhow::anyhow!(error)).context(
                                "Persistent initialization commit result is ambiguous",
                            )
                        }
                    };
                    validate_exact_persistent_commit_response(commit.as_ref(), &committed)?;
                    let index = progress
                        .volumes
                        .iter()
                        .position(|volume| volume.volume_id == filesystem.volume_id)
                        .context("Persistent commit progress omitted volume")?;
                    progress.volumes[index].authority_head = commit.initialized_head.clone();
                    InstalledPersistentCommitReceipt::Committed {
                        committed: Box::new(committed),
                    }
                }
            };
            receipts.push(encode_exact_json(
                &receipt,
                "encode Persistent initialization commit receipt",
            )?);
        }
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            progress.vmm,
            progress.network,
            progress.volumes,
            progress.artifact_classifications,
        )?;
        complete_effect(
            command,
            request,
            plan,
            InstalledAtomicStartReceiptBody::CommitPersistentInitialized {
                commit_receipts: receipts,
            },
            progress,
        )
    }

    fn inspect_activated_vmm(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        effect: &StartPhysicalEffectContext,
        require_running: bool,
    ) -> Result<(RuntimeLaunchIdentity, InstalledRuntimeProcessIdentity)> {
        let activate = completed_plan(
            &request.context,
            AtomicStartRuntimeEffectPhase::ActivateRuntime,
        )?;
        let (launch, process) = match &activate.body {
            InstalledAtomicStartPlanBody::ActivateRuntime { launch, mode, .. } => {
                let spec = AtomicVmmLaunchSpec::new(
                    command.node_id.clone(),
                    command.cat_id.clone(),
                    command.operation_id.clone(),
                    command.request_fingerprint.clone(),
                    activate.plan_digest,
                    host_path(self.config.physical.state_directory.path().to_path_buf())?,
                    launch.as_ref().clone(),
                    mode.clone(),
                )?;
                let process =
                    match inspect_atomic_vmm_service(&self.config, &command.cat_id, &spec, effect)?
                    {
                        AtomicVmmServiceInspection::Exact(process) => process,
                        AtomicVmmServiceInspection::Paused(process) if !require_running => process,
                        AtomicVmmServiceInspection::Starting
                        | AtomicVmmServiceInspection::Paused(_) => {
                            anyhow::bail!("activated VMM is not yet executing")
                        }
                        AtomicVmmServiceInspection::Absent
                        | AtomicVmmServiceInspection::Conflict => {
                            anyhow::bail!("activated VMM no longer has its exact physical identity")
                        }
                    };
                (launch.as_ref().clone(), process)
            }
            InstalledAtomicStartPlanBody::ResumeSuspendedRuntime {
                source_physical_manifest_digest,
                ..
            } => {
                let source = self.suspended_restart_source(
                    command,
                    &request.context,
                    Some(source_physical_manifest_digest),
                )?;
                let installed = source.physical.installed_runtime()?;
                let state =
                    inspect_retained_vmm(&self.config, &command.cat_id, &installed.vmm, effect)?;
                anyhow::ensure!(
                    state == ProcessState::Running || !require_running,
                    "retained Suspended VMM is not executing"
                );
                (
                    installed.vmm.launch_identity.as_ref().clone(),
                    installed.vmm.process.clone(),
                )
            }
            _ => anyhow::bail!("ActivateRuntime platform plan has another schema"),
        };
        let expected = request
            .context
            .runtime_progress
            .vmm
            .as_ref()
            .context("activated progress lacks VMM")?;
        anyhow::ensure!(
            expected.process == process && expected.launch_identity.as_ref() == &launch,
            "activated VMM changed from durable progress"
        );
        Ok((launch, process))
    }

    fn inspect_current_persistent_head(
        &self,
        command: &LifecycleCommandEnvelope,
        volume: &RuntimeVolumeConfig,
        grant: &AtomicStartVolumeGrant,
    ) -> Result<RemoteHead> {
        let candidates = BTreeSet::from([volume.volume_id.clone()]);
        let snapshot = self
            .config
            .physical
            .volume_inventory_authority
            .load_node_volume_inventory(&command.node_id, &candidates)
            .context("load fresh Persistent Volume authority")?;
        anyhow::ensure!(
            snapshot.node_id == command.node_id && snapshot.records.len() == 1,
            "Persistent authority snapshot changed Node or candidate cardinality"
        );
        let record = &snapshot.records[0];
        validate_volume_record(&record.volume)?;
        let binding = record
            .binding
            .as_ref()
            .context("Persistent Volume is no longer Owned")?;
        validate_volume_owner_binding(binding, &record.volume)?;
        anyhow::ensure!(
            record.volume.volume_id == volume.volume_id
                && record.volume.size_bytes == volume.size_bytes
                && record.volume.durability == volume.durability
                && binding.owner_node_id == command.node_id
                && binding.attachment_id == grant.volume.attachment_id
                && binding.attachment_epoch == grant.volume.attachment_epoch
                && super::authority_acquire_origin(&record.volume)? == grant.acquire_origin
                && remote_head_is_same_or_later(&record.volume.head, &grant.authoritative_head,),
            "Persistent authority changed owner, immutable shape, or lineage"
        );
        Ok(record.volume.head.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_or_apply_guest_ready(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        runtime_ready_challenge: &RandomId128,
        filesystems: &[PlannedPersistentMount],
        same_node_restart_source: &Option<PlannedSameNodeRestartSource>,
        effect: &StartPhysicalEffectContext,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        anyhow::ensure!(
            filesystems
                .iter()
                .map(|filesystem| &filesystem.filesystem)
                .eq(persistent_filesystems(command, &request.context)?.iter()),
            "GuestReady plan changed the Persistent filesystem set"
        );
        let (launch, vmm_process) = self.inspect_activated_vmm(command, request, effect, true)?;
        let expected_vmm = request
            .context
            .runtime_progress
            .vmm
            .as_ref()
            .context("GuestReady progress lacks activated VMM")?;
        anyhow::ensure!(
            expected_vmm.process == vmm_process && expected_vmm.launch_identity.as_ref() == &launch,
            "GuestReady VMM differs from durable activated progress"
        );
        let network = request
            .context
            .runtime_progress
            .network
            .clone()
            .context("GuestReady progress lacks Host network")?;
        let host_network =
            ch::inspect_host_network_snapshot(&self.config.physical.ip_binary, effect)
                .context("freshly inspect GuestReady Host network")?;
        anyhow::ensure!(
            host_network.reserved_network_state(&network.identity)?
                == ReservedHostNetworkState::Exact,
            "GuestReady Host network changed from its durable reservation"
        );

        let session = self
            .config
            .admission_registry
            .current_agent_session()
            .context("read AgentSession for Persistent mount")?;
        anyhow::ensure!(
            session.node_id == command.node_id,
            "Persistent mount AgentSession belongs to another Node"
        );
        let mut mounted_any = false;
        for planned in filesystems {
            let filesystem = &planned.filesystem;
            let index = command
                .runtime_config
                .volumes
                .iter()
                .position(|volume| volume.volume_id == filesystem.volume_id)
                .context("Persistent mount plan references an unknown volume")?;
            let config_volume = &command.runtime_config.volumes[index];
            let grant = &request.context.volume_grants[index];
            let binding = persistent_initialization_binding(command, config_volume, grant)?;
            let inspection = match self
                .config
                .persistent_initialization_control
                .inspect_persistent_initialization(
                    session.clone(),
                    LifecyclePersistentInitializationInspectRequest {
                        binding: Box::new(binding),
                    },
                    effect.deadline(),
                ) {
                Ok(inspection) => inspection,
                Err(LifecycleVolumeClientError::Rejected(_)) => {
                    return definite_runtime_failure(
                        request,
                        cats_api::runtime_lifecycle::CommandFailureReason::VolumeAuthorityRejected,
                    )
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(error))
                        .context("Persistent mount initialization inspect is ambiguous")
                }
            };
            let LifecyclePersistentInitializationState::Initialized {
                initialization_token,
                expected_blank_head,
                initialized_head,
                ..
            } = &inspection.initialization
            else {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
                );
            };
            anyhow::ensure!(
                inspection.attachment_id == filesystem.attachment_id
                    && inspection.attachment_epoch == filesystem.attachment_epoch
                    && initialization_token == &planned.initialization_token
                    && expected_blank_head == &planned.expected_blank_head
                    && initialized_head == &planned.initialized_head,
                "Persistent mount inspection changed initialization lineage"
            );
            let current_head =
                self.inspect_current_persistent_head(command, config_volume, grant)?;
            anyhow::ensure!(
                current_head == inspection.current_head
                    && remote_head_is_same_or_later(&current_head, &planned.initialized_head),
                "Persistent mount did not use one fresh exact authority head"
            );
            let guest_binding = persistent_guest_binding(
                &request.context.runtime_incarnation,
                filesystem,
                config_volume.size_bytes,
                FilesystemInitialization::Existing,
            )?;
            let probe = execute_guest_filesystem(
                &launch,
                vmm_process.pid,
                FilesystemControlRequestV1 {
                    version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
                    challenge: planned.probe_challenge.clone(),
                    timeout_ms: planned.guest_timeout_ms,
                    operation: FilesystemControlOperationV1::Probe,
                    filesystem: Box::new(guest_binding.clone()),
                    expected_head: current_head.clone(),
                },
                effect.deadline(),
            )?;
            if probe.outcome == FilesystemControlOutcomeV1::Conflict {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::GuestNotReady,
                );
            }
            if !probe.observation.mounts.is_empty() {
                // Probe's frozen response validator admits exactly the one
                // requested rw ext4 mount here. This is response-loss
                // discovery; never issue MountExt4 a second time.
                mounted_any = true;
                continue;
            }
            if !self.effect_authority_has_budget(request, effect.deadline())? {
                return match persistent_mount_lease_loss_disposition(mounted_any) {
                    PersistentMountLeaseLossDisposition::FailClosed => definite_runtime_failure(
                        request,
                        cats_api::runtime_lifecycle::CommandFailureReason::GuestNotReady,
                    ),
                    PersistentMountLeaseLossDisposition::RefreshSamePlan => {
                        volume_refresh_required(request, plan, effect.deadline())
                    }
                };
            }
            let response = execute_guest_filesystem(
                &launch,
                vmm_process.pid,
                FilesystemControlRequestV1 {
                    version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
                    challenge: planned.mount_challenge.clone(),
                    timeout_ms: planned.guest_timeout_ms,
                    operation: FilesystemControlOperationV1::MountExt4,
                    filesystem: Box::new(guest_binding),
                    expected_head: current_head,
                },
                effect.deadline(),
            )?;
            if response.outcome != FilesystemControlOutcomeV1::Exact {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::GuestNotReady,
                );
            }
            mounted_any = true;
        }

        let guest_request = RuntimeReadyRequestV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            challenge: runtime_ready_challenge.clone(),
            runtime_incarnation: request.context.runtime_incarnation.clone(),
            expected_guest_cid: launch.guest_cid,
            expected_guest_port: GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            expected_guest_agent_protocol_version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        };
        let guest = match probe_guest_runtime_ready(
            &launch,
            vmm_process.pid,
            guest_request,
            effect.deadline().min(
                Instant::now()
                    .checked_add(self.config.guest_ready_timeout)
                    .context("GuestReady timeout overflow")?,
            ),
        ) {
            Ok(guest) => guest,
            Err(error) if Instant::now() < effect.deadline() => return Err(error),
            Err(_) => {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::GuestNotReady,
                )
            }
        };
        validate_guest_runtime_ready(command, &launch, &guest)?;

        let (installed_volumes, volume_receipts) =
            self.join_guest_ready_volumes(command, request, &launch, effect)?;
        anyhow::ensure!(
            self.inspect_activated_vmm(command, request, effect, true)?
                == (launch.clone(), vmm_process.clone()),
            "VMM changed during GuestReady physical join"
        );
        let guest_ready_receipt_digest = digest_serialized(GUEST_READY_RECEIPT_DOMAIN, &guest)?;
        let execution_receipt_digest = digest_serialized(
            RUNTIME_EXECUTION_RECEIPT_DOMAIN,
            &InstalledRuntimeExecutionReceiptInput {
                operation_id: &command.operation_id,
                request_fingerprint: &command.request_fingerprint,
                runtime_incarnation: &request.context.runtime_incarnation,
                platform_plan_digest: &plan.plan_digest,
                vmm: expected_vmm,
                network: &network,
                volumes: &installed_volumes,
                volume_receipts: &volume_receipts,
                guest_ready_receipt_digest: &guest_ready_receipt_digest,
            },
        )?;

        let retired_restart_source_absence_digest = match same_node_restart_source {
            Some(source)
                if matches!(
                    source.physical.source,
                    SameNodeOwnedPredecessorSource::Warm { .. }
                        | SameNodeOwnedPredecessorSource::RetainedWarm { .. }
                ) =>
            {
                let cleanup_authority = match &source.physical.source {
                    SameNodeOwnedPredecessorSource::Warm { cleanup_authority }
                        if request.context.source == StartSource::SameNodeWarm =>
                    {
                        cleanup_authority
                    }
                    SameNodeOwnedPredecessorSource::RetainedWarm { cleanup_authority }
                        if request.context.source == StartSource::SameNodeRetry =>
                    {
                        cleanup_authority
                    }
                    _ => {
                        return definite_runtime_failure(
                            request,
                            cats_api::runtime_lifecycle::CommandFailureReason::SnapshotInvalid,
                        )
                    }
                };
                anyhow::ensure!(
                    request
                        .context
                        .warm_restart_source
                        .as_ref()
                        .is_some_and(|expected| {
                            source.physical.physical_manifest_digest
                                == expected.physical_manifest_digest
                                && cleanup_authority.as_ref() == expected.cleanup_authority.as_ref()
                        })
                        && cleanup_authority.mode() == WarmSnapshotCleanupMode::TransferToRuntime,
                    "GuestReady Warm cleanup authority changed mode or source"
                );
                if !path_is_absent(Path::new(cleanup_authority.snapshot_directory().as_str()))?
                    && !self.effect_authority_has_budget(request, effect.deadline())?
                {
                    return match persistent_mount_lease_loss_disposition(mounted_any) {
                        PersistentMountLeaseLossDisposition::FailClosed => {
                            definite_runtime_failure(
                                request,
                                cats_api::runtime_lifecycle::CommandFailureReason::GuestNotReady,
                            )
                        }
                        PersistentMountLeaseLossDisposition::RefreshSamePlan => {
                            volume_refresh_required(request, plan, effect.deadline())
                        }
                    };
                }
                let completion = WarmSnapshotCleanupCompletion::TransferToRuntime {
                    runtime_incarnation: request.context.runtime_incarnation.clone(),
                    runtime_progress_manifest_digest: request
                        .context
                        .runtime_progress
                        .manifest_digest
                        .clone(),
                };
                match self.warm_platform.inspect_or_remove_warm_snapshot(
                    command,
                    cleanup_authority,
                    &completion,
                )? {
                    WarmSnapshotCleanupAttempt::Exact(digest) => Some(digest),
                    WarmSnapshotCleanupAttempt::Blocked => {
                        return definite_runtime_failure(
                            request,
                            cats_api::runtime_lifecycle::CommandFailureReason::SnapshotInvalid,
                        )
                    }
                }
            }
            Some(source)
                if matches!(
                    source.physical.source,
                    SameNodeOwnedPredecessorSource::Suspended { .. }
                ) =>
            {
                anyhow::ensure!(
                    request.context.source == StartSource::SameNodeSuspended
                        && self.suspended_restart_source(
                            command,
                            &request.context,
                            Some(&source.physical.physical_manifest_digest),
                        )? == *source,
                    "GuestReady Suspended source changed its retained runtime"
                );
                None
            }
            Some(_) => {
                return definite_runtime_failure(
                    request,
                    cats_api::runtime_lifecycle::CommandFailureReason::SnapshotInvalid,
                )
            }
            None => {
                anyhow::ensure!(
                    !matches!(
                        request.context.source,
                        StartSource::SameNodeWarm | StartSource::SameNodeSuspended
                    ) && request.context.warm_restart_source.is_none(),
                    "same-Node GuestReady lost restart-source authority"
                );
                None
            }
        };
        let manifest = InstalledRuntimeManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            execution_receipt_digest.clone(),
            guest_ready_receipt_digest.clone(),
            retired_restart_source_absence_digest.clone(),
            expected_vmm.clone(),
            network,
            installed_volumes,
        )?;
        let receipt = InstalledAtomicStartPlatformReceipt {
            version: PLAN_VERSION,
            phase: plan.phase,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_incarnation: request.context.runtime_incarnation.clone(),
            platform_plan_digest: plan.plan_digest.clone(),
            body: InstalledAtomicStartReceiptBody::GuestReadyAndAdmission {
                guest_ready_receipt_digest: guest_ready_receipt_digest.clone(),
                retired_restart_source_absence_digest: retired_restart_source_absence_digest
                    .clone(),
                manifest: Box::new(manifest.clone()),
            },
        };
        let platform_receipt = ExactBytes::new(canonical_json(&receipt)?);
        let platform_receipt_digest = atomic_start_platform_receipt_digest(
            command,
            plan.phase,
            &plan.plan_digest,
            &platform_receipt,
        )?;
        Ok(AtomicStartRuntimeEffectOutcome::RuntimeReady(
            AtomicStartRuntimeReadyEvidence {
                platform_plan_digest: plan.plan_digest.clone(),
                platform_receipt,
                platform_receipt_digest,
                execution_receipt_digest,
                guest_ready_receipt_digest,
                retired_restart_source_absence_digest,
                volume_receipts,
                artifact_classifications: request.context.artifact_classifications.clone(),
                installed_runtime_manifest: Box::new(manifest),
            },
        ))
    }

    fn join_guest_ready_volumes(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        launch: &RuntimeLaunchIdentity,
        effect: &StartPhysicalEffectContext,
    ) -> Result<(
        Vec<InstalledRuntimeVolumeManifest>,
        Vec<VolumeTerminalReceipt>,
    )> {
        let device_plan = completed_plan(
            &request.context,
            AtomicStartRuntimeEffectPhase::PrepareDevices,
        )?;
        let InstalledAtomicStartPlanBody::PrepareDevices {
            blockd,
            volumes: planned_devices,
            ..
        } = &device_plan.body
        else {
            anyhow::bail!("PrepareDevices platform plan has another schema")
        };
        let root_plan =
            completed_plan(&request.context, AtomicStartRuntimeEffectPhase::PrepareRoot)?;
        let object_write = match &root_plan.body {
            InstalledAtomicStartPlanBody::PrepareRoot { object_write, .. } => object_write,
            _ => anyhow::bail!("PrepareRoot platform plan has another schema"),
        };
        anyhow::ensure!(
            planned_devices.len() == launch.devices.len()
                && planned_devices.len() == request.context.runtime_progress.volumes.len()
                && planned_devices.len() == request.context.volume_grants.len(),
            "GuestReady device/progress/grant sets differ"
        );
        let candidates = planned_devices
            .iter()
            .map(|device| device.volume.volume_id.clone())
            .collect::<BTreeSet<_>>();
        let snapshot = self
            .config
            .physical
            .volume_inventory_authority
            .load_node_volume_inventory(&command.node_id, &candidates)
            .context("load GuestReady Volume authority snapshot")?;
        anyhow::ensure!(
            snapshot.node_id == command.node_id,
            "GuestReady Volume authority belongs to another Node"
        );
        let mut authority = BTreeMap::new();
        for record in snapshot.records {
            validate_volume_record(&record.volume)?;
            if let Some(binding) = &record.binding {
                validate_volume_owner_binding(binding, &record.volume)?;
            }
            anyhow::ensure!(
                authority
                    .insert(record.volume.volume_id.clone(), record)
                    .is_none(),
                "GuestReady Volume authority repeats a row"
            );
        }
        let mut installed = Vec::with_capacity(planned_devices.len());
        let mut receipts = Vec::with_capacity(planned_devices.len());
        for ((((planned, prepared), progress), grant), config_volume) in planned_devices
            .iter()
            .zip(&launch.devices)
            .zip(&request.context.runtime_progress.volumes)
            .zip(&request.context.volume_grants)
            .zip(&command.runtime_config.volumes)
        {
            anyhow::ensure!(
                planned.volume == *config_volume
                    && prepared.volume_id == planned.volume.volume_id
                    && progress.volume_id == planned.volume.volume_id
                    && grant.volume.volume_id == planned.volume.volume_id,
                "GuestReady reordered a Volume"
            );
            let record = authority
                .get(&planned.volume.volume_id)
                .context("GuestReady authority omitted a Volume")?;
            let binding = record
                .binding
                .as_ref()
                .context("GuestReady Volume is no longer Owned")?;
            anyhow::ensure!(
                binding.owner_node_id == command.node_id
                    && binding.attachment_id == planned.attachment_id
                    && binding.attachment_epoch == planned.attachment_epoch
                    && super::authority_acquire_origin(&record.volume)? == planned.acquire_origin
                    && remote_head_is_same_or_later(&record.volume.head, &grant.authoritative_head,),
                "GuestReady Volume authority changed owner, lineage, or regressed"
            );
            let blockd_process = progress
                .blockd
                .clone()
                .context("GuestReady progress lacks serving blockd")?;
            let launch_service = SystemdServiceLaunch {
                unit_id: planned.serving_service_id.clone(),
                executable: PathBuf::from(blockd.executable.as_str()),
                arguments: serving_blockd_arguments(blockd, planned, object_write)?,
            };
            if inspect_systemd_service(
                &self.config.physical,
                &command.cat_id,
                &launch_service,
                effect,
            )? != SystemdServiceInspection::Exact(blockd_process.clone())
            {
                return Err(definite_physical_failure(
                    cats_api::runtime_lifecycle::CommandFailureReason::GuestNotReady,
                ));
            }
            let status = blockd_status(
                Path::new(planned.control_socket_path.as_str()),
                blockd_process.pid,
                effect,
            )?;
            validate_guest_ready_blockd_status(command, planned, &record.volume.head, &status)
                .map_err(|_| {
                    definite_physical_failure(
                        cats_api::runtime_lifecycle::CommandFailureReason::GuestNotReady,
                    )
                })?;
            let local = Generation::new(
                u64::try_from(status.local_durable_generation)
                    .context("GuestReady local durability is negative")?,
            )
            .context("GuestReady local durability exceeds Generation")?;
            let remote = Generation::new(
                u64::try_from(status.remote_durable_generation)
                    .context("GuestReady remote durability is negative")?,
            )
            .context("GuestReady remote durability exceeds Generation")?;
            let frontend = progress
                .frontend
                .clone()
                .context("GuestReady progress lacks block frontend")?;
            inspect_guest_ready_frontend(
                &self.config.physical,
                &command.cat_id,
                planned,
                &frontend,
                effect,
            )?;
            installed.push(InstalledRuntimeVolumeManifest {
                volume_id: planned.volume.volume_id.clone(),
                disk_id: planned.volume.disk_id.clone(),
                disk_role: planned.volume.disk_role,
                attachment_id: planned.attachment_id.clone(),
                attachment_epoch: planned.attachment_epoch,
                acquire_origin: planned.acquire_origin.clone(),
                launch_head: planned.launch_head.clone(),
                current_authority_head: record.volume.head.clone(),
                authority_receipt_digest: Some(grant.grant_receipt_digest.clone()),
                local_lineage_data_directory: planned.lineage_data_directory.clone(),
                blockd: blockd_process,
                blockd_control_socket_path: planned.control_socket_path.clone(),
                frontend,
            });
            receipts.push(VolumeTerminalReceipt {
                volume_id: planned.volume.volume_id.clone(),
                disk_id: planned.volume.disk_id.clone(),
                disk_role: planned.volume.disk_role,
                attachment_id: planned.attachment_id.clone(),
                attachment_epoch: planned.attachment_epoch,
                local_durable_generation: local,
                remote_durable_generation: remote,
                authority_receipt_digest: Some(grant.grant_receipt_digest.clone()),
            });
        }
        Ok((installed, receipts))
    }

    fn complete_without_physical_change(
        &self,
        command: &LifecycleCommandEnvelope,
        request: &AtomicStartRuntimeEffectRequest,
        plan: &InstalledAtomicStartPlatformPlan,
        body: InstalledAtomicStartReceiptBody,
    ) -> Result<AtomicStartRuntimeEffectOutcome> {
        let previous = previous_progress(request)?;
        let progress = InstalledRuntimeProgressManifest::new(
            command,
            request.context.runtime_incarnation.clone(),
            previous.vmm.clone(),
            previous.network.clone(),
            previous.volumes.clone(),
            previous.artifact_classifications.clone(),
        )?;
        complete_effect(command, request, plan, body, progress)
    }
}

#[derive(Debug, Clone, Copy)]
struct StartPhysicalEffectContext {
    deadline: Instant,
}

impl PhysicalReadContext for StartPhysicalEffectContext {
    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn check_active(&self) -> Result<()> {
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "atomic Start physical effect deadline elapsed"
        );
        Ok(())
    }
}

impl PhysicalEffectContext for StartPhysicalEffectContext {}

#[derive(Debug)]
struct DefinitePhysicalFailure {
    reason: cats_api::runtime_lifecycle::CommandFailureReason,
}

impl std::fmt::Display for DefinitePhysicalFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "atomic Start physical evidence closed with {:?}",
            self.reason
        )
    }
}

impl std::error::Error for DefinitePhysicalFailure {}

fn definite_physical_failure(
    reason: cats_api::runtime_lifecycle::CommandFailureReason,
) -> anyhow::Error {
    anyhow::Error::new(DefinitePhysicalFailure { reason })
}

#[derive(Debug)]
struct ExactProcessConflict(&'static str);

impl std::fmt::Display for ExactProcessConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ExactProcessConflict {}

fn exact_process_conflict(message: &'static str) -> anyhow::Error {
    anyhow::Error::new(ExactProcessConflict(message))
}

fn is_exact_process_conflict(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ExactProcessConflict>().is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AtomicVmmServiceInspection {
    Absent,
    Starting,
    Paused(InstalledRuntimeProcessIdentity),
    Exact(InstalledRuntimeProcessIdentity),
    Conflict,
}

fn inspect_atomic_vmm_service(
    config: &InstalledAtomicStartRuntimeConfig,
    cat_id: &Id,
    spec: &AtomicVmmLaunchSpec,
    effect: &StartPhysicalEffectContext,
) -> Result<AtomicVmmServiceInspection> {
    let launch = spec.launch.as_ref();
    let unit = inspect_systemd_unit(&config.physical, &launch.scope_id, effect)?;
    if unit.load_state == "not-found" || unit.main_pid == 0 && unit.active_state == "inactive" {
        return Ok(AtomicVmmServiceInspection::Absent);
    }
    if unit.active_state == "activating" || unit.sub_state == "start" {
        return Ok(AtomicVmmServiceInspection::Starting);
    }
    if unit.load_state != "loaded"
        || unit.active_state != "active"
        || unit.sub_state != "running"
        || unit.main_pid == 0
        || unit.control_group
            != crate::cat_execution_scope::cat_service_control_group(cat_id, &launch.scope_id)
    {
        return Ok(AtomicVmmServiceInspection::Conflict);
    }

    let process_root = config.physical.proc_root.join(unit.main_pid.to_string());
    let executable = match fs::read_link(process_root.join("exe")) {
        Ok(executable) => executable,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(AtomicVmmServiceInspection::Starting)
        }
        Err(error) => return Err(error).context("read atomic VMM process executable"),
    };
    if executable == Path::new(launch.launcher_executable.path.as_str()) {
        let launcher = SystemdServiceLaunch {
            unit_id: launch.scope_id.clone(),
            executable,
            arguments: vec![VMM_LAUNCHER_CONTRACT_ARGUMENT.into()],
        };
        return match inspect_exact_process(&config.physical, cat_id, &launcher, unit.main_pid) {
            Ok(_) => Ok(AtomicVmmServiceInspection::Starting),
            Err(error) if is_exact_process_conflict(&error) => {
                Ok(AtomicVmmServiceInspection::Conflict)
            }
            Err(error) => Err(error),
        };
    }
    if executable != Path::new(launch.boot.vmm_executable.path.as_str()) {
        return Ok(AtomicVmmServiceInspection::Conflict);
    }
    let vmm_launch = SystemdServiceLaunch {
        unit_id: launch.scope_id.clone(),
        executable,
        arguments: crate::vmm_launcher::cloud_hypervisor_arguments_for_launch(launch, &spec.mode)?
            .to_vec(),
    };
    let process = match inspect_exact_process(&config.physical, cat_id, &vmm_launch, unit.main_pid)
    {
        Ok(process) => process,
        Err(error) if is_exact_process_conflict(&error) => {
            return Ok(AtomicVmmServiceInspection::Conflict)
        }
        Err(error) => return Err(error),
    };
    for validation in [
        validate_atomic_vmm_environment(&config.physical, unit.main_pid, launch),
        validate_atomic_vmm_retained_descriptors(&config.physical, unit.main_pid, spec),
    ] {
        match validation {
            Ok(()) => {}
            Err(error) if is_exact_process_conflict(&error) => {
                return Ok(AtomicVmmServiceInspection::Conflict)
            }
            Err(error) => return Err(error),
        }
    }
    Ok(
        match inspect_installed_vmm_api(launch, unit.main_pid, effect)? {
            InstalledVmmApiInspection::Exact {
                state: ProcessState::Running,
            } => AtomicVmmServiceInspection::Exact(process),
            InstalledVmmApiInspection::Exact {
                state: ProcessState::Paused,
            } => AtomicVmmServiceInspection::Paused(process),
            InstalledVmmApiInspection::Unavailable => AtomicVmmServiceInspection::Starting,
            InstalledVmmApiInspection::Conflict => AtomicVmmServiceInspection::Conflict,
        },
    )
}

fn wait_for_atomic_vmm_service(
    config: &InstalledAtomicStartRuntimeConfig,
    cat_id: &Id,
    spec: &AtomicVmmLaunchSpec,
    effect: &StartPhysicalEffectContext,
    resume_authorized: &dyn Fn() -> Result<bool>,
) -> Result<InstalledRuntimeProcessIdentity> {
    loop {
        effect.check_active()?;
        match inspect_atomic_vmm_service(config, cat_id, spec, effect)? {
            AtomicVmmServiceInspection::Exact(process) => return Ok(process),
            AtomicVmmServiceInspection::Paused(process) => {
                if !matches!(spec.mode, AtomicVmmLaunchMode::WarmRestore { .. }) {
                    return Err(definite_physical_failure(
                        cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
                    ));
                }
                anyhow::ensure!(
                    resume_authorized()?,
                    "restored Warm VMM is Paused but this process lacks exact resume authority"
                );
                match ch::resume_exact_vmm_until(
                    Path::new(spec.launch.api_socket_path.as_str()),
                    process.pid,
                    effect.deadline(),
                )
                .context("resume exact restored Warm VMM")?
                {
                    ch::ExactVmEffectOutcome::Exact => {}
                    ch::ExactVmEffectOutcome::DefiniteFailure => {
                        return Err(definite_physical_failure(
                            cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
                        ))
                    }
                    ch::ExactVmEffectOutcome::Ambiguous => {
                        anyhow::bail!("restored Warm VMM resume completion is ambiguous")
                    }
                }
                match inspect_atomic_vmm_service(config, cat_id, spec, effect)? {
                    AtomicVmmServiceInspection::Exact(current) if current == process => {
                        return Ok(current)
                    }
                    AtomicVmmServiceInspection::Starting
                    | AtomicVmmServiceInspection::Paused(_) => {}
                    AtomicVmmServiceInspection::Absent
                    | AtomicVmmServiceInspection::Exact(_)
                    | AtomicVmmServiceInspection::Conflict => {
                        return Err(definite_physical_failure(
                            cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
                        ))
                    }
                }
            }
            AtomicVmmServiceInspection::Starting => {}
            AtomicVmmServiceInspection::Absent => {
                anyhow::bail!("atomic VMM systemd submission has no discoverable unit")
            }
            AtomicVmmServiceInspection::Conflict => {
                return Err(definite_physical_failure(
                    cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
                ))
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn submit_atomic_vmm_service(
    config: &InstalledAtomicStartRuntimeConfig,
    cat_id: &Id,
    spec: &AtomicVmmLaunchSpec,
    spec_path: &Path,
    effect: &StartPhysicalEffectContext,
) -> Result<()> {
    let launch = spec.launch.as_ref();
    let spec_file = open_exact_launch_bytes(spec_path, &encode_atomic_vmm_launch_spec(spec)?)?;
    let vmm = open_exact_launch_artifact(&launch.boot.vmm_executable)?;
    let kernel = open_exact_launch_artifact(&launch.boot.kernel)?;
    let initramfs = launch
        .boot
        .initramfs
        .as_ref()
        .map(open_exact_launch_artifact)
        .transpose()?;
    let mut descriptors = vec![
        (ATOMIC_VMM_LAUNCH_SPEC_FD_NAME, spec_file.as_raw_fd()),
        ("cats-vmm-v1", vmm.as_raw_fd()),
        ("cats-kernel-v1", kernel.as_raw_fd()),
    ];
    if let Some(initramfs) = &initramfs {
        descriptors.push(("cats-initramfs-v1", initramfs.as_raw_fd()));
    }
    descriptors.sort_unstable_by_key(|(_, descriptor)| *descriptor);
    anyhow::ensure!(
        descriptors.iter().all(|(_, descriptor)| *descriptor >= 3)
            && descriptors.windows(2).all(|pair| pair[0].1 != pair[1].1),
        "atomic VMM descriptor transfer is invalid"
    );

    let slice = cat_execution_slice_id(cat_id);
    let mut command = Command::new(&config.systemd_run_binary);
    sanitize_host_command(&mut command);
    command
        .arg("--system")
        .arg("--quiet")
        .arg("--no-ask-password")
        .arg("--collect")
        .arg(format!("--unit={}", launch.scope_id))
        .arg("--service-type=exec")
        .arg(format!("--slice={slice}"))
        .arg(format!("--property=Slice={slice}"))
        .arg("--property=KillMode=control-group")
        .arg("--property=Restart=no")
        .arg("--property=UMask=0077")
        .arg("--property=TimeoutStopSec=2s")
        .arg("--property=Environment=")
        .arg("--property=EnvironmentFile=")
        .arg("--property=PassEnvironment=")
        .arg("--property=UnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL CATS_CRASH_POINT")
        .arg(format!(
            "--setenv={RUNTIME_INCARNATION_ENVIRONMENT}={}",
            launch.runtime_incarnation
        ))
        .arg(format!(
            "--setenv={VMM_PROCESS_TOKEN_ENVIRONMENT}={}",
            launch.process_identity_token
        ));
    let process_id = std::process::id();
    for (name, descriptor) in descriptors {
        command.arg(format!(
            "--property=OpenFile=/proc/{process_id}/fd/{descriptor}:{name}:read-only"
        ));
    }
    command
        .arg("--")
        .arg(launch.launcher_executable.path.as_str())
        .arg(VMM_LAUNCHER_CONTRACT_ARGUMENT);
    // Submission is ambiguous. The caller's fresh systemd/process/API join is
    // the sole success oracle and the exact unit ID prevents a second VMM.
    let _submission = run_bounded_output(command, effect.deadline());
    Ok(())
}

fn open_exact_launch_bytes(path: &Path, expected: &[u8]) -> Result<File> {
    let file = open_nofollow_file(path, libc::O_RDONLY | libc::O_CLOEXEC)?;
    let before = file.metadata().context("stat atomic VMM launch spec")?;
    anyhow::ensure!(
        before.file_type().is_file()
            && before.nlink() == 1
            && before.len() == expected.len() as u64,
        "atomic VMM launch spec file identity is invalid"
    );
    let mut actual = Vec::with_capacity(expected.len());
    (&file).read_to_end(&mut actual)?;
    let after = file.metadata().context("re-stat atomic VMM launch spec")?;
    anyhow::ensure!(
        actual == expected
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len(),
        "atomic VMM launch spec pathname or bytes changed"
    );
    Ok(file)
}

fn open_exact_launch_artifact(expected: &RuntimeLaunchArtifact) -> Result<File> {
    let path = Path::new(expected.path.as_str());
    let file = open_nofollow_file(path, libc::O_RDONLY | libc::O_CLOEXEC)?;
    let before = file.metadata().context("stat atomic VMM launch artifact")?;
    anyhow::ensure!(
        before.file_type().is_file()
            && before.nlink() == 1
            && before.len() == expected.length.get(),
        "atomic VMM launch artifact identity changed"
    );
    let mut reader = &file;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; ARTIFACT_READ_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .context("re-stat atomic VMM launch artifact")?;
    anyhow::ensure!(
        Sha256Digest::from_bytes(digest.finalize().into()) == expected.content_sha256
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len(),
        "atomic VMM launch artifact bytes changed"
    );
    Ok(file)
}

fn open_nofollow_file(path: &Path, flags: i32) -> Result<File> {
    anyhow::ensure!(path.is_absolute(), "atomic VMM file path is not absolute");
    let path = CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: path is a live NUL-terminated absolute path and no pointer is
    // retained; successful open returns one descriptor immediately owned.
    let descriptor = unsafe { libc::open(path.as_ptr(), flags | libc::O_NOFOLLOW) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).context("open nofollow atomic VMM file");
    }
    // SAFETY: successful open returned one uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_atomic_vmm_environment(
    physical: &InstalledPhysicalInspectionConfig,
    pid: u32,
    launch: &RuntimeLaunchIdentity,
) -> Result<()> {
    let bytes = fs::read(physical.proc_root.join(pid.to_string()).join("environ"))
        .context("read atomic VMM environment")?;
    if bytes.len() > 64 * 1024 {
        return Err(exact_process_conflict(
            "atomic VMM environment exceeds bound",
        ));
    }
    let mut cats = BTreeMap::new();
    for entry in bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        if entry.starts_with(b"CATS_") {
            let separator = entry.iter().position(|byte| *byte == b'=').ok_or_else(|| {
                exact_process_conflict("atomic VMM CATS environment entry is malformed")
            })?;
            let (name, value_with_separator) = entry.split_at(separator);
            let value = &value_with_separator[1..];
            if cats.insert(name.to_vec(), value.to_vec()).is_some() {
                return Err(exact_process_conflict(
                    "atomic VMM repeats a CATS environment entry",
                ));
            }
        }
    }
    if cats.len() != 2
        || cats
            .get(RUNTIME_INCARNATION_ENVIRONMENT.as_bytes())
            .map(Vec::as_slice)
            != Some(launch.runtime_incarnation.as_str().as_bytes())
        || cats
            .get(VMM_PROCESS_TOKEN_ENVIRONMENT.as_bytes())
            .map(Vec::as_slice)
            != Some(launch.process_identity_token.as_str().as_bytes())
    {
        return Err(exact_process_conflict(
            "atomic VMM environment changed launch identity or leaked CATS authority",
        ));
    }
    Ok(())
}

fn validate_atomic_vmm_retained_descriptors(
    physical: &InstalledPhysicalInspectionConfig,
    pid: u32,
    spec: &AtomicVmmLaunchSpec,
) -> Result<()> {
    let fd_root = physical.proc_root.join(pid.to_string()).join("fd");
    let expected = [
        (64, "launch-spec.atomic-start.v1.json"),
        (
            65,
            Path::new(spec.launch.boot.vmm_executable.path.as_str())
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| exact_process_conflict("atomic VMM executable has no basename"))?,
        ),
        (70, "vmm.log"),
    ];
    for (descriptor, basename) in expected {
        let target = fs::read_link(fd_root.join(descriptor.to_string()))
            .with_context(|| format!("read atomic VMM fixed FD {descriptor}"))?;
        if target.file_name().and_then(|name| name.to_str()) != Some(basename) {
            return Err(exact_process_conflict(
                "atomic VMM fixed descriptor names another artifact",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemdServiceLaunch {
    unit_id: Id,
    executable: PathBuf,
    arguments: Vec<std::ffi::OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SystemdServiceInspection {
    Absent,
    Starting,
    Exact(InstalledRuntimeProcessIdentity),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemdUnitSnapshot {
    load_state: String,
    active_state: String,
    sub_state: String,
    main_pid: u32,
    control_group: String,
}

fn planned_device_from_retained_source(
    command: &LifecycleCommandEnvelope,
    configured: &RuntimeVolumeConfig,
    launch: &PreparedDeviceInput,
    installed: &InstalledRuntimeVolumeManifest,
    grant: &AtomicStartVolumeGrant,
) -> Result<PlannedDevice> {
    let disk_kind = match configured.disk_role {
        DiskRole::Root => DiskKind::Root,
        DiskRole::Persistent => DiskKind::Persistent,
    };
    anyhow::ensure!(
        launch.volume_intent_id == atomic_start_launch_volume_id(command, configured)?
            && launch.disk_id == configured.disk_id
            && launch.volume_id == configured.volume_id
            && launch.disk_kind == disk_kind
            && launch.attachment_id == grant.volume.attachment_id
            && launch.attachment_epoch == grant.volume.attachment_epoch
            && launch.acquire_origin == grant.acquire_origin
            && launch.size_bytes == configured.size_bytes
            && launch.durability == configured.durability
            && launch.guest_device.serial == configured.guest_device_serial
            && launch.guest_device.slot == configured.guest_device_slot
            && installed.volume_id == configured.volume_id
            && installed.disk_id == configured.disk_id
            && installed.disk_role == configured.disk_role
            && installed.attachment_id == grant.volume.attachment_id
            && installed.attachment_epoch == grant.volume.attachment_epoch
            && installed.acquire_origin == grant.acquire_origin
            && installed.launch_head == launch.expected_head
            && installed.local_lineage_data_directory == launch.serving_process.data_directory
            && installed.blockd_control_socket_path == launch.serving_process.control_socket_path,
        "retained device changed immutable launch, attachment, or lineage identity"
    );
    let kernel_nbd_client_service_id =
        matches!(launch.frontend, PrepareDeviceFrontend::KernelNbd { .. })
            .then(|| service_id("cats-nbd-client", &launch.ownership_token))
            .transpose()?;
    let lineage = Path::new(installed.local_lineage_data_directory.as_str());
    Ok(PlannedDevice {
        volume: configured.clone(),
        attachment_id: grant.volume.attachment_id.clone(),
        attachment_epoch: grant.volume.attachment_epoch,
        acquire_origin: grant.acquire_origin.clone(),
        launch_head: installed.launch_head.clone(),
        authority_receipt_digest: grant.grant_receipt_digest.clone(),
        lineage_data_directory: installed.local_lineage_data_directory.clone(),
        serving_service_id: launch.serving_process.scope_id.clone(),
        kernel_nbd_client_service_id,
        serving_process_identity_token: launch.serving_process.process_identity_token.clone(),
        device_ownership_token: launch.ownership_token.clone(),
        control_socket_path: launch.serving_process.control_socket_path.clone(),
        frontend: launch.frontend.clone(),
        authorized_serving_artifact_path: host_path(lineage.join(format!(
            "authorized-serving.atomic-start.{}.v1.json",
            launch.serving_process.process_identity_token.as_str()
        )))?,
        command_attribution_path: host_path(lineage.join(format!(
            "atomic-start-command-attribution.{}.v1.json",
            launch.serving_process.process_identity_token.as_str()
        )))?,
    })
}

/// Revalidate continuity of a process whose complete descriptor/argv proof
/// was captured in the journaled same-node predecessor carrier.  PID plus
/// start ticks closes reuse; executable, unit and the singleton Cat cgroup
/// close replacement or sibling injection after planning.
fn inspect_retained_systemd_process(
    physical: &InstalledPhysicalInspectionConfig,
    cat_id: &Id,
    unit_id: &Id,
    executable: &Path,
    expected: &InstalledRuntimeProcessIdentity,
    effect: &StartPhysicalEffectContext,
) -> Result<()> {
    let first = inspect_systemd_unit(physical, unit_id, effect)?;
    let expected_control_group =
        crate::cat_execution_scope::cat_service_control_group(cat_id, unit_id);
    if first.load_state != "loaded"
        || first.active_state != "active"
        || first.sub_state != "running"
        || first.main_pid != expected.pid
        || first.control_group != expected_control_group
    {
        return Err(exact_process_conflict(
            "retained systemd service changed unit state, PID, or Cat cgroup",
        ));
    }
    let process_root = physical.proc_root.join(expected.pid.to_string());
    let stat = fs::read_to_string(process_root.join("stat"))
        .context("read retained systemd process stat")?;
    let start_time_ticks = crate::proc::parse_start_ticks(&stat)
        .ok_or_else(|| exact_process_conflict("retained process stat is malformed"))?;
    if expected.start_time_ticks.get() != start_time_ticks {
        return Err(exact_process_conflict("retained process PID was reused"));
    }
    if fs::read_link(process_root.join("exe")).context("read retained process executable")?
        != executable
    {
        return Err(exact_process_conflict(
            "retained process executable changed",
        ));
    }
    if read_process_cgroup(&process_root.join("cgroup"))? != expected_control_group {
        return Err(exact_process_conflict(
            "retained process left its exact Cat cgroup",
        ));
    }
    let cgroup_path =
        Path::new(cat_service_cgroup_path(&physical.cgroup_root, cat_id, unit_id)?.as_str())
            .join("cgroup.procs");
    let process_text =
        fs::read_to_string(cgroup_path).context("read retained service cgroup.procs")?;
    let mut processes = Vec::new();
    for line in process_text.lines() {
        processes.push(
            line.parse::<u32>()
                .map_err(|_| exact_process_conflict("retained cgroup PID is invalid"))?,
        );
    }
    if processes != [expected.pid] {
        return Err(exact_process_conflict(
            "retained service cgroup contains sibling processes",
        ));
    }
    anyhow::ensure!(
        inspect_systemd_unit(physical, unit_id, effect)? == first,
        "retained systemd service changed during inspection"
    );
    Ok(())
}

fn inspect_retained_vmm(
    config: &InstalledAtomicStartRuntimeConfig,
    cat_id: &Id,
    installed: &InstalledRuntimeVmmManifest,
    effect: &StartPhysicalEffectContext,
) -> Result<ProcessState> {
    let launch = installed.launch_identity.as_ref();
    if installed.parent_slice_id != cat_execution_slice_id(cat_id)
        || installed.systemd_unit_id != launch.scope_id
        || installed.api_socket_path != launch.api_socket_path
        || installed.vsock_socket_path != launch.vsock_socket_path
        || installed.memory_file_path != launch.memory_file_path
    {
        return Err(definite_physical_failure(
            cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
        ));
    }
    inspect_retained_systemd_process(
        &config.physical,
        cat_id,
        &installed.systemd_unit_id,
        Path::new(launch.boot.vmm_executable.path.as_str()),
        &installed.process,
        effect,
    )
    .map_err(|error| {
        if is_exact_process_conflict(&error) {
            definite_physical_failure(cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed)
        } else {
            error
        }
    })?;
    match inspect_installed_vmm_api(launch, installed.process.pid, effect)? {
        InstalledVmmApiInspection::Exact { state } => Ok(state),
        InstalledVmmApiInspection::Unavailable => {
            anyhow::bail!("retained VMM API is not presently discoverable")
        }
        InstalledVmmApiInspection::Conflict => Err(definite_physical_failure(
            cats_api::runtime_lifecycle::CommandFailureReason::VmmFailed,
        )),
    }
}

#[derive(Debug, Clone)]
struct KernelNbdClientExpectation {
    sys_slot: PathBuf,
    executable: PathBuf,
    cat_id: Id,
    unit_id: Id,
    listener_socket_path: HostPath,
    device_path: HostPath,
    expected_size_sectors: u64,
}

impl KernelNbdClientExpectation {
    fn new(
        config: &super::InstalledLifecycleKernelNbdConfig,
        cat_id: &Id,
        unit_id: &Id,
        listener_socket_path: &HostPath,
        device_path: &HostPath,
        size_bytes: u64,
    ) -> Result<Self> {
        anyhow::ensure!(
            size_bytes > 0 && size_bytes.is_multiple_of(512),
            "kernel-NBD Volume size is not a positive sector multiple"
        );
        let lexical_device = Path::new(device_path.as_str());
        anyhow::ensure!(
            lexical_device.parent() == Some(config.device_root.as_path()),
            "kernel-NBD device escaped the installed pool"
        );
        let basename = lexical_device
            .file_name()
            .and_then(|name| name.to_str())
            .context("kernel-NBD device basename is not UTF-8")?;
        let index = basename
            .strip_prefix("nbd")
            .context("kernel-NBD device has an unknown basename")?
            .parse::<u32>()
            .context("kernel-NBD device index is malformed")?;
        anyhow::ensure!(
            index < config.device_count,
            "kernel-NBD device is outside pool"
        );
        Ok(Self {
            sys_slot: config.sys_block_root.join(basename),
            executable: config.nbd_client_binary.clone(),
            cat_id: cat_id.clone(),
            unit_id: unit_id.clone(),
            listener_socket_path: listener_socket_path.clone(),
            device_path: device_path.clone(),
            expected_size_sectors: size_bytes / 512,
        })
    }
}

fn inspect_exact_kernel_nbd_client(
    physical: &InstalledPhysicalInspectionConfig,
    expected: &KernelNbdClientExpectation,
) -> Result<Option<InstalledRuntimeProcessIdentity>> {
    let before = read_kernel_nbd_tuple(&expected.sys_slot)?;
    let Some(pid) = before.0 else {
        anyhow::ensure!(
            before.1 == 0,
            "kernel-NBD slot has capacity without a client"
        );
        return Ok(None);
    };
    anyhow::ensure!(
        before.1 == expected.expected_size_sectors,
        "kernel-NBD slot capacity changed"
    );
    let process_root = physical.proc_root.join(pid.to_string());
    let executable = fs::read_link(process_root.join("exe"))
        .context("read exact kernel-NBD client executable")?;
    anyhow::ensure!(
        executable == expected.executable,
        "kernel-NBD slot belongs to a foreign executable"
    );
    let command_line =
        fs::read(process_root.join("cmdline")).context("read exact kernel-NBD client argv")?;
    anyhow::ensure!(
        !command_line.is_empty()
            && command_line.len() <= 64 * 1024
            && command_line.last() == Some(&0),
        "kernel-NBD client argv is not bounded NUL framing"
    );
    let arguments = command_line[..command_line.len() - 1]
        .split(|byte| *byte == 0)
        .map(|argument| std::ffi::OsString::from_vec(argument.to_vec()))
        .collect::<Vec<_>>();
    let exact_arguments = vec![
        expected.executable.as_os_str().to_owned(),
        "-nonetlink".into(),
        "-unix".into(),
        expected.listener_socket_path.as_str().into(),
        expected.device_path.as_str().into(),
        "-b".into(),
        "512".into(),
        "-N".into(),
        "".into(),
    ];
    anyhow::ensure!(
        arguments == exact_arguments,
        "kernel-NBD client argv changed"
    );
    let stat = fs::read_to_string(process_root.join("stat"))
        .context("read exact kernel-NBD client stat")?;
    let start_time_ticks =
        crate::proc::parse_start_ticks(&stat).context("kernel-NBD client stat is malformed")?;
    let cgroup = read_process_cgroup(&process_root.join("cgroup"))?;
    let expected_cgroup =
        crate::cat_execution_scope::cat_service_control_group(&expected.cat_id, &expected.unit_id);
    anyhow::ensure!(
        cgroup == expected_cgroup,
        "kernel-NBD client is outside its exact Cat child cgroup"
    );
    let cgroup_procs = Path::new(
        cat_service_cgroup_path(&physical.cgroup_root, &expected.cat_id, &expected.unit_id)?
            .as_str(),
    )
    .join("cgroup.procs");
    let ids = fs::read_to_string(cgroup_procs)
        .context("read kernel-NBD service cgroup.procs")?
        .lines()
        .map(|line| {
            line.parse::<u32>()
                .context("kernel-NBD cgroup PID is invalid")
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(ids == [pid], "kernel-NBD child cgroup contains siblings");
    let after = read_kernel_nbd_tuple(&expected.sys_slot)?;
    anyhow::ensure!(before == after, "kernel-NBD slot changed during inspection");
    Ok(Some(InstalledRuntimeProcessIdentity {
        pid,
        start_time_ticks: WireU64::new(start_time_ticks)
            .context("kernel-NBD start ticks exceed wire domain")?,
    }))
}

fn read_kernel_nbd_tuple(slot: &Path) -> Result<(Option<u32>, u64)> {
    let size_bytes = fs::read(slot.join("size")).context("read kernel-NBD size")?;
    anyhow::ensure!(size_bytes.len() <= 64, "kernel-NBD size exceeds bound");
    let size = std::str::from_utf8(&size_bytes)
        .context("kernel-NBD size is not UTF-8")?
        .trim()
        .parse::<u64>()
        .context("kernel-NBD size is malformed")?;
    let pid = match fs::read(slot.join("pid")) {
        Ok(bytes) => {
            anyhow::ensure!(bytes.len() <= 64, "kernel-NBD pid exceeds bound");
            let value = std::str::from_utf8(&bytes)
                .context("kernel-NBD pid is not UTF-8")?
                .trim()
                .parse::<u32>()
                .context("kernel-NBD pid is malformed")?;
            (value > 0).then_some(value)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("read kernel-NBD pid"),
    };
    Ok((pid, size))
}

fn validate_kernel_nbd_systemd_unit(
    physical: &InstalledPhysicalInspectionConfig,
    expected: &KernelNbdClientExpectation,
    effect: &StartPhysicalEffectContext,
) -> Result<()> {
    let first = inspect_systemd_unit(physical, &expected.unit_id, effect)?;
    anyhow::ensure!(
        first.load_state == "loaded"
            && first.active_state == "active"
            && first.sub_state == "exited"
            && first.main_pid == 0
            && first.control_group
                == crate::cat_execution_scope::cat_service_control_group(
                    &expected.cat_id,
                    &expected.unit_id,
                ),
        "kernel-NBD transient unit is not the exact retained oneshot"
    );
    let second = inspect_systemd_unit(physical, &expected.unit_id, effect)?;
    anyhow::ensure!(first == second, "kernel-NBD transient unit changed");
    Ok(())
}

fn ensure_systemd_service(
    config: &InstalledAtomicStartRuntimeConfig,
    cat_id: &Id,
    launch: &SystemdServiceLaunch,
    effect: &StartPhysicalEffectContext,
) -> Result<InstalledRuntimeProcessIdentity> {
    match inspect_systemd_service(&config.physical, cat_id, launch, effect)? {
        SystemdServiceInspection::Exact(process) => return Ok(process),
        SystemdServiceInspection::Starting => {
            return wait_for_exact_systemd_service(&config.physical, cat_id, launch, effect)
        }
        SystemdServiceInspection::Absent => {}
    }
    effect.check_active()?;
    let slice = cat_execution_slice_id(cat_id);
    let mut command = Command::new(&config.systemd_run_binary);
    sanitize_host_command(&mut command);
    command
        .arg("--system")
        .arg("--quiet")
        .arg("--no-ask-password")
        .arg("--collect")
        .arg(format!("--unit={}", launch.unit_id))
        .arg("--service-type=exec")
        .arg(format!("--slice={slice}"))
        .arg(format!("--property=Slice={slice}"))
        .arg("--property=KillMode=control-group")
        .arg("--property=Restart=no")
        .arg("--property=UMask=0077")
        .arg("--property=TimeoutStopSec=2s")
        .arg("--property=Environment=")
        .arg("--property=EnvironmentFile=")
        .arg("--property=PassEnvironment=")
        .arg("--property=UnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE CATS_POSTGRES_URL CATS_CRASH_POINT")
        .arg("--")
        .arg(&launch.executable)
        .args(&launch.arguments);
    // Every outcome is ambiguous until the exact unit/process/cgroup/socket
    // join below. Never submit a second transient service from this call.
    let _submission = run_bounded_output(command, effect.deadline());
    wait_for_exact_systemd_service(&config.physical, cat_id, launch, effect)
}

fn wait_for_exact_systemd_service(
    physical: &InstalledPhysicalInspectionConfig,
    cat_id: &Id,
    launch: &SystemdServiceLaunch,
    effect: &StartPhysicalEffectContext,
) -> Result<InstalledRuntimeProcessIdentity> {
    loop {
        effect.check_active()?;
        match inspect_systemd_service(physical, cat_id, launch, effect)? {
            SystemdServiceInspection::Exact(process) => return Ok(process),
            SystemdServiceInspection::Starting => {
                thread::sleep(Duration::from_millis(10));
            }
            SystemdServiceInspection::Absent => {
                anyhow::bail!("systemd submission has no exact discoverable service")
            }
        }
    }
}

fn inspect_systemd_service(
    physical: &InstalledPhysicalInspectionConfig,
    cat_id: &Id,
    launch: &SystemdServiceLaunch,
    effect: &StartPhysicalEffectContext,
) -> Result<SystemdServiceInspection> {
    let first = inspect_systemd_unit(physical, &launch.unit_id, effect)?;
    if first.load_state == "not-found" || first.main_pid == 0 && first.active_state == "inactive" {
        return Ok(SystemdServiceInspection::Absent);
    }
    if first.active_state == "activating" || first.sub_state == "start" {
        return Ok(SystemdServiceInspection::Starting);
    }
    if first.load_state != "loaded"
        || first.active_state != "active"
        || first.sub_state != "running"
        || first.main_pid == 0
        || first.control_group
            != crate::cat_execution_scope::cat_service_control_group(cat_id, &launch.unit_id)
    {
        return Err(definite_physical_failure(
            cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
        ));
    }
    let process = match inspect_exact_process(physical, cat_id, launch, first.main_pid) {
        Ok(process) => process,
        Err(error) if is_exact_process_conflict(&error) => {
            return Err(definite_physical_failure(
                cats_api::runtime_lifecycle::CommandFailureReason::StoredEvidenceConflict,
            ))
        }
        Err(error) => return Err(error),
    };
    let second = inspect_systemd_unit(physical, &launch.unit_id, effect)?;
    anyhow::ensure!(
        first == second,
        "systemd service changed during exact inspection"
    );
    Ok(SystemdServiceInspection::Exact(process))
}

fn inspect_systemd_unit(
    physical: &InstalledPhysicalInspectionConfig,
    unit_id: &Id,
    effect: &StartPhysicalEffectContext,
) -> Result<SystemdUnitSnapshot> {
    let mut command = Command::new(&physical.systemctl_binary);
    sanitize_host_command(&mut command);
    command
        .arg("show")
        .arg("--no-pager")
        .arg("--property=LoadState")
        .arg("--property=ActiveState")
        .arg("--property=SubState")
        .arg("--property=MainPID")
        .arg("--property=ControlGroup")
        .arg(unit_id.as_str());
    let output = run_bounded_output(command, effect.deadline())?;
    anyhow::ensure!(
        output.stdout.len() <= 64 * 1024 && output.stderr.len() <= 64 * 1024,
        "systemctl unit response exceeds its bound"
    );
    let text = std::str::from_utf8(&output.stdout).context("systemctl output is not UTF-8")?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .context("systemctl output line is malformed")?;
        anyhow::ensure!(
            fields.insert(key, value).is_none(),
            "systemctl output repeats a property"
        );
    }
    let load_state = fields
        .remove("LoadState")
        .context("systemctl omitted LoadState")?
        .to_owned();
    if !output.status.success() && load_state != "not-found" {
        anyhow::bail!(
            "systemctl unit inspection failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    let snapshot = SystemdUnitSnapshot {
        load_state,
        active_state: fields
            .remove("ActiveState")
            .context("systemctl omitted ActiveState")?
            .to_owned(),
        sub_state: fields
            .remove("SubState")
            .context("systemctl omitted SubState")?
            .to_owned(),
        main_pid: fields
            .remove("MainPID")
            .context("systemctl omitted MainPID")?
            .parse()
            .context("systemctl MainPID is invalid")?,
        control_group: fields
            .remove("ControlGroup")
            .context("systemctl omitted ControlGroup")?
            .to_owned(),
    };
    anyhow::ensure!(fields.is_empty(), "systemctl returned an unknown property");
    Ok(snapshot)
}

fn inspect_exact_process(
    physical: &InstalledPhysicalInspectionConfig,
    cat_id: &Id,
    launch: &SystemdServiceLaunch,
    pid: u32,
) -> Result<InstalledRuntimeProcessIdentity> {
    let process_root = physical.proc_root.join(pid.to_string());
    let stat =
        fs::read_to_string(process_root.join("stat")).context("read exact systemd process stat")?;
    let start_time_ticks = crate::proc::parse_start_ticks(&stat)
        .ok_or_else(|| exact_process_conflict("systemd process stat is malformed"))?;
    let executable =
        fs::read_link(process_root.join("exe")).context("read exact systemd process executable")?;
    if executable != launch.executable {
        return Err(exact_process_conflict("systemd process executable changed"));
    }
    let command_line = fs::read(process_root.join("cmdline"))
        .context("read exact systemd process command line")?;
    let observed = command_line
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
        .map(|item| std::ffi::OsString::from_vec(item.to_vec()))
        .collect::<Vec<_>>();
    let expected = std::iter::once(launch.executable.as_os_str().to_owned())
        .chain(launch.arguments.iter().cloned())
        .collect::<Vec<_>>();
    if observed != expected {
        return Err(exact_process_conflict("systemd process argv changed"));
    }
    let cgroup = read_process_cgroup(&process_root.join("cgroup"))?;
    let expected_control_group =
        crate::cat_execution_scope::cat_service_control_group(cat_id, &launch.unit_id);
    if cgroup != expected_control_group {
        return Err(exact_process_conflict(
            "systemd process is outside its exact Cat child cgroup",
        ));
    }
    let cgroup_path = Path::new(
        cat_service_cgroup_path(&physical.cgroup_root, cat_id, &launch.unit_id)?.as_str(),
    )
    .join("cgroup.procs");
    let processes = fs::read_to_string(cgroup_path).context("read exact service cgroup.procs")?;
    let mut ids = Vec::new();
    for line in processes.lines() {
        let id = line
            .parse::<u32>()
            .map_err(|_| exact_process_conflict("cgroup.procs PID is invalid"))?;
        ids.push(id);
    }
    if ids != [pid] {
        return Err(exact_process_conflict(
            "systemd child cgroup contains sibling processes",
        ));
    }
    Ok(InstalledRuntimeProcessIdentity {
        pid,
        start_time_ticks: WireU64::new(start_time_ticks).ok_or_else(|| {
            exact_process_conflict("process start time is outside the wire domain")
        })?,
    })
}

fn read_process_cgroup(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).context("read process cgroup")?;
    let mut lines = text.lines();
    let line = lines
        .next()
        .ok_or_else(|| exact_process_conflict("process cgroup is empty"))?;
    if lines.next().is_some() {
        return Err(exact_process_conflict(
            "process has multiple cgroup memberships",
        ));
    }
    let mut fields = line.splitn(3, ':');
    if fields.next() != Some("") || fields.next() != Some("") || fields.clone().count() != 1 {
        return Err(exact_process_conflict(
            "process is not in one unified cgroup",
        ));
    }
    Ok(fields.next().expect("count proved one field").to_owned())
}

fn stop_exact_systemd_service(
    config: &InstalledAtomicStartRuntimeConfig,
    cat_id: &Id,
    launch: &SystemdServiceLaunch,
    process: &InstalledRuntimeProcessIdentity,
    effect: &StartPhysicalEffectContext,
) -> Result<()> {
    anyhow::ensure!(
        inspect_systemd_service(&config.physical, cat_id, launch, effect)?
            == SystemdServiceInspection::Exact(process.clone()),
        "refuse to stop a changed systemd service"
    );
    let mut command = Command::new(&config.physical.systemctl_binary);
    sanitize_host_command(&mut command);
    command.arg("stop").arg(launch.unit_id.as_str());
    let _submission = run_bounded_output(command, effect.deadline());
    loop {
        effect.check_active()?;
        match inspect_systemd_service(&config.physical, cat_id, launch, effect)? {
            SystemdServiceInspection::Absent => return Ok(()),
            SystemdServiceInspection::Starting | SystemdServiceInspection::Exact(_) => {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn sanitize_host_command(command: &mut Command) {
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir("/");
}

fn run_bounded_output(mut command: Command, deadline: Instant) -> Result<Output> {
    anyhow::ensure!(Instant::now() < deadline, "Host command deadline elapsed");
    let mut child = command.spawn().context("spawn bounded Host command")?;
    loop {
        if child.try_wait()?.is_some() {
            return child
                .wait_with_output()
                .context("collect bounded Host command");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("bounded Host command deadline elapsed")
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn blockd_status(
    socket_path: &Path,
    expected_peer_pid: u32,
    effect: &StartPhysicalEffectContext,
) -> Result<DurabilityStatus> {
    let before = fs::symlink_metadata(socket_path).context("inspect blockd control socket")?;
    anyhow::ensure!(
        before.file_type().is_socket() && !before.file_type().is_symlink(),
        "blockd control path is not an exact Unix socket"
    );
    let mut stream = UnixStream::connect(socket_path).context("connect blockd control socket")?;
    ensure_peer_process(&stream, expected_peer_pid)?;
    set_stream_deadlines(&stream, effect.deadline())?;
    stream.write_all(BlockdControlCommand::Status.as_wire().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let line = read_bounded_line(&mut stream, 64 * 1024, effect)?;
    ensure_peer_process(&stream, expected_peer_pid)?;
    let after = fs::symlink_metadata(socket_path).context("reinspect blockd control socket")?;
    anyhow::ensure!(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "blockd control socket changed during status"
    );
    let line = std::str::from_utf8(&line).context("blockd response is not UTF-8")?;
    let payload = match BlockdControlResponse::parse_wire(line)? {
        BlockdControlResponse::Ok(payload) => payload,
        BlockdControlResponse::Error(error) => anyhow::bail!("blockd status rejected: {error}"),
    };
    serde_json::from_str(&payload).context("decode bounded blockd status")
}

fn send_exact_blockd_drain(
    socket_path: &Path,
    expected_peer_pid: u32,
    effect: &StartPhysicalEffectContext,
) -> Result<()> {
    let before = fs::symlink_metadata(socket_path).context("inspect blockd drain socket")?;
    anyhow::ensure!(
        before.file_type().is_socket() && !before.file_type().is_symlink(),
        "blockd drain path is not an exact Unix socket"
    );
    let mut stream = UnixStream::connect(socket_path).context("connect blockd drain socket")?;
    ensure_peer_process(&stream, expected_peer_pid)?;
    set_stream_deadlines(&stream, effect.deadline())?;
    stream.write_all(BlockdControlCommand::Drain.as_wire().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let line = read_bounded_line(&mut stream, 64 * 1024, effect)?;
    ensure_peer_process(&stream, expected_peer_pid)?;
    let after = fs::symlink_metadata(socket_path).context("reinspect blockd drain socket")?;
    anyhow::ensure!(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "blockd drain socket changed during effect"
    );
    let line = std::str::from_utf8(&line).context("blockd drain response is not UTF-8")?;
    match BlockdControlResponse::parse_wire(line)? {
        BlockdControlResponse::Ok(_) => Ok(()),
        BlockdControlResponse::Error(error) => anyhow::bail!("blockd drain rejected: {error}"),
    }
}

fn exchange_root_provision(
    socket_path: &Path,
    expected_peer_pid: u32,
    request: &ProvisionRootImageRequest,
    effect: &StartPhysicalEffectContext,
) -> Result<ProvisionRootImageResult> {
    let before = fs::symlink_metadata(socket_path).context("inspect Root control socket")?;
    anyhow::ensure!(
        before.file_type().is_socket(),
        "Root control path is not a socket"
    );
    let mut stream = UnixStream::connect(socket_path).context("connect Root control socket")?;
    ensure_peer_process(&stream, expected_peer_pid)?;
    set_stream_deadlines(&stream, effect.deadline())?;
    let mut frame = b"provision_root_image ".to_vec();
    frame.extend(
        encode_provision_root_image_request(request)
            .context("encode exact Root provision request")?,
    );
    frame.push(b'\n');
    stream.write_all(&frame)?;
    stream.flush()?;
    let line = read_bounded_line(&mut stream, 128 * 1024, effect)?;
    ensure_peer_process(&stream, expected_peer_pid)?;
    let after = fs::symlink_metadata(socket_path).context("reinspect Root control socket")?;
    anyhow::ensure!(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "Root control socket changed during provision"
    );
    if let Some(payload) = line.strip_prefix(b"OK ") {
        return cats_api::runtime_reconciliation::decode_provision_root_image_result(payload)
            .context("decode Root provision success");
    }
    if let Some(payload) = line.strip_prefix(b"ERR ") {
        let error = cats_api::runtime_reconciliation::decode_provision_root_image_error(payload)
            .context("decode Root provision failure")?;
        anyhow::bail!("Root provision was rejected: {error:?}")
    }
    anyhow::bail!("Root provision response has an unknown prefix")
}

fn set_stream_deadlines(stream: &UnixStream, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("Unix control deadline elapsed")?;
    let timeout = remaining.min(Duration::from_millis(200));
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(())
}

fn read_bounded_line(
    stream: &mut UnixStream,
    maximum: usize,
    effect: &StartPhysicalEffectContext,
) -> Result<Vec<u8>> {
    let mut line = Vec::with_capacity(maximum.min(4096));
    let mut byte = [0_u8; 1];
    loop {
        effect.check_active()?;
        anyhow::ensure!(
            line.len() < maximum,
            "Unix control response exceeds its bound"
        );
        match stream.read(&mut byte) {
            Ok(0) => anyhow::bail!("Unix control response ended before newline"),
            Ok(_) if byte[0] == b'\n' => return Ok(line),
            Ok(_) => line.push(byte[0]),
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {}
            Err(error) => return Err(error).context("read Unix control response"),
        }
    }
}

#[cfg(target_os = "linux")]
fn ensure_peer_process(stream: &UnixStream, expected_pid: u32) -> Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: both output buffers are valid for the supplied lengths; the
    // stream descriptor remains live and getsockopt retains no pointer.
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
            && u32::try_from(credentials.pid).ok() == Some(expected_pid),
        "Unix control peer is not the exact expected process"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_peer_process(_stream: &UnixStream, _expected_pid: u32) -> Result<()> {
    anyhow::bail!("exact Unix peer credentials require Linux")
}

fn blockd_owner_directory(owner: &InstalledAtomicStartBlockdSocketOwner) -> Result<PathBuf> {
    let control = Path::new(owner.control_socket_path.as_str());
    let public = control
        .parent()
        .context("blockd control socket has no parent")?;
    if let Some(io) = &owner.io_socket_path {
        anyhow::ensure!(
            Path::new(io.as_str()).parent() == Some(public),
            "blockd socket owner paths have different parents"
        );
    }
    let installed = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed();
    let root = Path::new(installed.path().as_str());
    anyhow::ensure!(
        public.parent() == Some(root),
        "blockd socket owner is outside the installed namespace"
    );
    Ok(public.to_path_buf())
}

fn retire_blockd_socket_owner(owner: &InstalledAtomicStartBlockdSocketOwner) -> Result<()> {
    anyhow::ensure!(
        retire_blockd_socket_owner_if_present(owner)?,
        "completed blockd socket owner directory was absent"
    );
    Ok(())
}

fn retire_blockd_socket_owner_if_present(
    owner: &InstalledAtomicStartBlockdSocketOwner,
) -> Result<bool> {
    let public = blockd_owner_directory(owner)?;
    let root_path = public.parent().expect("owner directory has checked parent");
    let root = open_absolute_directory(root_path)?;
    let public_name = CString::new(
        public
            .file_name()
            .expect("owner directory has checked basename")
            .as_encoded_bytes(),
    )?;
    let directory = match openat(
        &root,
        &public_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(directory) => directory,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == ErrorKind::NotFound) =>
        {
            return Ok(false)
        }
        Err(error) => return Err(error),
    };
    let marker =
        CString::new(cats_blockd::runtime_socket_namespace::BLOCKD_SOCKET_OWNER_MARKER_BASENAME)?;
    let expected = canonical_json(owner)?;
    anyhow::ensure!(
        read_exact_at_optional(&directory, &marker, expected.len())?.as_deref()
            == Some(expected.as_slice()),
        "blockd socket owner marker changed"
    );
    unlink_socket_if_present(&directory, Path::new(owner.control_socket_path.as_str()))?;
    if let Some(io) = &owner.io_socket_path {
        unlink_socket_if_present(&directory, Path::new(io.as_str()))?;
    }
    unlinkat_if_exists(&directory, &marker)?;
    directory
        .sync_all()
        .context("fsync retired blockd owner directory")?;
    loop {
        // SAFETY: root/public_name remain live; the checked directory is a
        // direct child and unlinkat retains neither value.
        let result =
            unsafe { libc::unlinkat(root.as_raw_fd(), public_name.as_ptr(), libc::AT_REMOVEDIR) };
        if result == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(error).context("remove retired blockd owner directory");
    }
    root.sync_all()
        .context("fsync blockd socket root retirement")?;
    Ok(true)
}

fn unlink_socket_if_present(directory: &File, path: &Path) -> Result<()> {
    let name = CString::new(
        path.file_name()
            .context("blockd socket path has no basename")?
            .as_encoded_bytes(),
    )?;
    // SAFETY: zero is a valid initial representation for stat; fstatat fills
    // it before any field is read.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: directory/name/stat remain live; fstatat retains none.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error).context("inspect retired blockd socket");
    }
    anyhow::ensure!(
        stat.st_mode & libc::S_IFMT == libc::S_IFSOCK,
        "blockd socket owner contains a non-socket listener"
    );
    unlinkat_if_exists(directory, &name)
}

impl InstalledAtomicStartNetworkReservation {
    fn new(
        command: &LifecycleCommandEnvelope,
        plan: &InstalledAtomicStartPlatformPlan,
        planned: &PlannedNetworkReservation,
    ) -> Result<Self> {
        let mut reservation = Self {
            version: PLAN_VERSION,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation: plan.runtime_incarnation.clone(),
            platform_plan_digest: plan.plan_digest.clone(),
            identity: planned.identity.clone(),
            reservation_digest: zero_digest(),
        };
        reservation.reservation_digest = network_reservation_digest(&reservation)?;
        Ok(reservation)
    }
}

/// Decodes one enumerable Start network reservation without accepting a
/// semantically equivalent alternate byte representation. Host-global
/// inventory uses this at the managed namespace boundary, where accepting
/// non-canonical or self-inconsistent attribution would turn an unknown TAP
/// into a known Cat artifact.
pub(crate) fn decode_installed_atomic_start_network_reservation(
    bytes: &[u8],
) -> Result<InstalledAtomicStartNetworkReservation> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= PLATFORM_PLAN_MAX_BYTES,
        "installed atomic Start network reservation has an invalid length"
    );
    let reservation: InstalledAtomicStartNetworkReservation = serde_json::from_slice(bytes)
        .context("decode installed atomic Start network reservation")?;
    anyhow::ensure!(
        reservation.version == PLAN_VERSION
            && canonical_json(&reservation)? == bytes
            && network_reservation_digest(&reservation)? == reservation.reservation_digest,
        "installed atomic Start network reservation is non-canonical or has an invalid digest"
    );
    Ok(reservation)
}

impl InstalledAtomicStartBlockdSocketOwner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        command: &LifecycleCommandEnvelope,
        plan: &InstalledAtomicStartPlatformPlan,
        role: AtomicStartBlockdSocketRole,
        owner_token: RandomId128,
        service_id: Id,
        control_socket_path: HostPath,
        io_socket_path: Option<HostPath>,
    ) -> Result<Self> {
        let mut owner = Self {
            version: PLAN_VERSION,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_incarnation: plan.runtime_incarnation.clone(),
            platform_plan_digest: plan.plan_digest.clone(),
            role,
            owner_token,
            service_id,
            control_socket_path,
            io_socket_path,
            owner_digest: zero_digest(),
        };
        owner.owner_digest = blockd_socket_owner_digest(&owner)?;
        Ok(owner)
    }
}

impl InstalledAtomicStartDeviceAttribution {
    fn new(
        command: &LifecycleCommandEnvelope,
        plan: &InstalledAtomicStartPlatformPlan,
        authority_receipt_digest: Sha256Digest,
        authorized_serving_artifact_digest: Sha256Digest,
        prepared_device: PreparedDeviceInput,
    ) -> Result<Self> {
        let mut attribution = Self {
            version: PLAN_VERSION,
            node_id: command.node_id.clone(),
            cat_id: command.cat_id.clone(),
            placement_identity: command.placement_identity.clone(),
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
            runtime_config_id: command.runtime_config.config_id.clone(),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            runtime_incarnation: plan.runtime_incarnation.clone(),
            platform_plan_digest: plan.plan_digest.clone(),
            authority_receipt_digest,
            authorized_serving_artifact_digest,
            prepared_device: Box::new(prepared_device),
            attribution_digest: zero_digest(),
        };
        attribution.attribution_digest = device_attribution_digest(&attribution)?;
        Ok(attribution)
    }
}

fn device_attribution_digest(
    attribution: &InstalledAtomicStartDeviceAttribution,
) -> Result<Sha256Digest> {
    let mut preimage = attribution.clone();
    preimage.attribution_digest = zero_digest();
    digest_serialized(DEVICE_ATTRIBUTION_DOMAIN, &preimage)
}

fn blockd_socket_owner_digest(
    owner: &InstalledAtomicStartBlockdSocketOwner,
) -> Result<Sha256Digest> {
    let mut preimage = owner.clone();
    preimage.owner_digest = zero_digest();
    digest_serialized(BLOCKD_SOCKET_OWNER_DOMAIN, &preimage)
}

fn planned_credential_ids(
    mode: &PlannedObjectWriteMode,
    volume_count: usize,
) -> Result<Vec<Option<Id>>> {
    match mode {
        PlannedObjectWriteMode::Gateway {
            expected_credential_ids,
            ..
        } => {
            anyhow::ensure!(
                expected_credential_ids.len() == volume_count,
                "ObjectWrite plan changed its Volume count"
            );
            Ok(expected_credential_ids.iter().cloned().map(Some).collect())
        }
        PlannedObjectWriteMode::DirectProvider => Ok(vec![None; volume_count]),
    }
}

fn authorized_serving_attachment(
    grant: &AtomicStartVolumeGrant,
    identity: &AttachmentLineageIdentity,
    object_write_credential: Option<cats_api::object_write_gateway::ObjectWriteCredentialReference>,
    head: RemoteHead,
) -> Result<AuthorizedServingAttachment> {
    let mut attachment = authorized_serving_attachment_from_start_volume_grant(
        &grant.authority_receipt,
        &grant.grant_receipt_digest,
        object_write_credential,
    )
    .map_err(|error| anyhow::anyhow!("project canonical Start serving attachment: {error}"))?;
    anyhow::ensure!(
        attachment.identity == *identity,
        "canonical Start serving projection changed local lineage"
    );
    // Root provisioning is the one permitted same-owner/head advancement
    // between acquire and serving. The canonical conversion freezes the full
    // current lease proof first; only the freshly discovered authoritative
    // head may advance within that exact attachment epoch.
    attachment.head = head;
    validate_authorized_serving_attachment(&attachment)
        .map_err(|error| anyhow::anyhow!("validate exact serving attachment: {error}"))?;
    Ok(attachment)
}

fn decode_authorized_serving_attachment(
    bytes: &ExactBytes,
    expected_digest: &Sha256Digest,
) -> Result<AuthorizedServingAttachment> {
    anyhow::ensure!(
        !bytes.as_slice().is_empty()
            && bytes.as_slice().len() <= PLATFORM_PLAN_MAX_BYTES
            && sha256_bytes(bytes.as_slice()) == *expected_digest,
        "authorized serving attachment bytes changed"
    );
    let attachment: AuthorizedServingAttachment = serde_json::from_slice(bytes.as_slice())
        .context("decode exact authorized serving attachment")?;
    anyhow::ensure!(
        canonical_json(&attachment)? == bytes.as_slice(),
        "authorized serving attachment is not canonical JSON"
    );
    validate_authorized_serving_attachment(&attachment)
        .map_err(|error| anyhow::anyhow!("validate retained serving attachment: {error}"))?;
    Ok(attachment)
}

fn inspect_direct_authorization_identity(
    managed_root: &Path,
    path: &HostPath,
    expected_bytes: &[u8],
) -> Result<DirectAuthorizedAttachmentIdentity> {
    let lexical = Path::new(path.as_str());
    anyhow::ensure!(
        lexical.starts_with(managed_root) && lexical.is_absolute(),
        "serving authorization is outside StateDirectory"
    );
    let relative = lexical
        .strip_prefix(managed_root)
        .context("strip serving authorization root")?;
    let basename = relative
        .file_name()
        .context("serving authorization has no basename")?;
    let parent = open_existing_relative_directories(
        &open_absolute_directory(managed_root)?,
        relative
            .parent()
            .context("serving authorization has no parent")?,
    )?;
    let name = CString::new(basename.as_encoded_bytes())?;
    let mut retained = openat(
        &parent,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )?;
    let metadata = retained.metadata().context("stat serving authorization")?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() == expected_bytes.len() as u64,
        "serving authorization has an unsafe physical identity"
    );
    let mut observed = Vec::with_capacity(expected_bytes.len());
    retained
        .read_to_end(&mut observed)
        .context("read serving authorization")?;
    anyhow::ensure!(
        observed == expected_bytes,
        "serving authorization content changed"
    );
    let reopened = openat(
        &parent,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )?;
    let current = reopened
        .metadata()
        .context("reinspect serving authorization")?;
    anyhow::ensure!(
        current.dev() == metadata.dev()
            && current.ino() == metadata.ino()
            && current.len() == metadata.len(),
        "serving authorization pathname changed during retention"
    );
    Ok(DirectAuthorizedAttachmentIdentity {
        path: path.clone(),
        device: WireU64::new(metadata.dev()).context("authorization device overflows wire")?,
        inode: WireU64::new(metadata.ino()).context("authorization inode overflows wire")?,
        length: WireU64::new(metadata.len()).context("authorization length overflows wire")?,
        content_sha256: sha256_bytes(expected_bytes),
    })
}

fn serving_blockd_arguments(
    blockd: &PlannedBlockdLaunchConfig,
    volume: &PlannedDevice,
    object_write: &PlannedObjectWriteMode,
) -> Result<Vec<std::ffi::OsString>> {
    let mut arguments = vec![
        "--volume-id".into(),
        volume.volume.volume_id.as_str().into(),
        "--data-dir".into(),
        volume.lineage_data_directory.as_str().into(),
        "--attachment-id".into(),
        volume.attachment_id.as_str().into(),
        "--authorized-serving-spec".into(),
        volume.authorized_serving_artifact_path.as_str().into(),
        "--runtime-scope-id".into(),
        volume.serving_service_id.as_str().into(),
        "--process-identity-token".into(),
        volume.serving_process_identity_token.as_str().into(),
        "--device-ownership-token".into(),
        volume.device_ownership_token.as_str().into(),
        "--guest-device-serial".into(),
        volume.volume.guest_device_serial.as_str().into(),
        "--metadata-store-adapter".into(),
        blockd.metadata_store_adapter.as_str().into(),
        "--object-store-adapter".into(),
        blockd.object_store_adapter.as_str().into(),
        "--lease-ttl-ms".into(),
        blockd.lease_ttl_ms.get().to_string().into(),
        "--max-staged-bytes".into(),
        blockd.max_staged_bytes.get().to_string().into(),
        "--max-staged-packs".into(),
        blockd.max_staged_packs.get().to_string().into(),
        "--max-local-bytes".into(),
        blockd.max_local_bytes.get().to_string().into(),
        "--durability".into(),
        match volume.volume.durability {
            cats_api::runtime_reconciliation::Durability::Strict => "strict".into(),
            cats_api::runtime_reconciliation::Durability::Relaxed => "relaxed".into(),
        },
        "--listen-control".into(),
        volume.control_socket_path.as_str().into(),
    ];
    match &volume.frontend {
        PrepareDeviceFrontend::KernelNbd {
            listener_socket_path,
            ..
        } => arguments.extend(["--listen-unix".into(), listener_socket_path.as_str().into()]),
        PrepareDeviceFrontend::VhostUserBlk {
            socket_path,
            queues,
            queue_size,
        } => arguments.extend([
            "--listen-vhost-user".into(),
            socket_path.as_str().into(),
            "--vhost-user-queues".into(),
            queues.to_string().into(),
            "--vhost-user-queue-size".into(),
            queue_size.to_string().into(),
        ]),
    }
    append_adapter_options(
        &mut arguments,
        "--metadata-store-option",
        &blockd.metadata_store_options,
    );
    append_adapter_options(
        &mut arguments,
        "--object-store-option",
        &blockd.object_store_options,
    );
    if let PlannedObjectWriteMode::Gateway {
        gateway_origin,
        credential_directory,
        ..
    } = object_write
    {
        arguments.extend([
            "--object-write-gateway-url".into(),
            gateway_origin.as_str().into(),
            "--object-write-credential-directory".into(),
            credential_directory.as_str().into(),
        ]);
    }
    Ok(arguments)
}

fn probe_guest_runtime_ready(
    launch: &RuntimeLaunchIdentity,
    expected_vmm_pid: u32,
    request: RuntimeReadyRequestV1,
    deadline: Instant,
) -> Result<RuntimeReadyResponseV1> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("GuestReady transport deadline elapsed")?;
    let mut client = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
        Path::new(launch.vsock_socket_path.as_str()),
        GUEST_HOST_CONTROL_VSOCK_PORT_V1,
        remaining,
        expected_vmm_pid,
    )
    .context("connect to exact installed VMM Guest transport")?;
    let response = client
        .runtime_ready(request)
        .context("execute bounded Guest RuntimeReady challenge")?;
    anyhow::ensure!(
        client.hybrid_assigned_port().is_some(),
        "GuestReady transport omitted Cloud Hypervisor's assigned Host port"
    );
    Ok(response)
}

fn persistent_guest_binding(
    runtime_incarnation: &RandomId128,
    planned: &PlannedPersistentFilesystem,
    size_bytes: u64,
    initialization: FilesystemInitialization,
) -> Result<PersistentFilesystemBinding> {
    Ok(PersistentFilesystemBinding {
        runtime_incarnation: runtime_incarnation.clone(),
        // The atomic runtime config intentionally has no independent volume
        // intent identity.  The frozen Guest V1 field therefore uses the
        // immutable Volume ID; it remains an attribution echo, never Volume
        // Authority.
        volume_intent_id: planned.volume_id.clone(),
        disk_id: planned.disk_id.clone(),
        volume_id: planned.volume_id.clone(),
        attachment_id: planned.attachment_id.clone(),
        attachment_epoch: planned.attachment_epoch,
        size_bytes,
        guest_device: planned.guest_device.clone(),
        filesystem_uuid: planned.filesystem_uuid.clone(),
        mount_path: HostPath::new(planned.mount_path.as_str().to_owned())
            .context("Persistent mount path is outside Guest HostPath domain")?,
        initialization,
    })
}

fn execute_guest_filesystem(
    launch: &RuntimeLaunchIdentity,
    expected_vmm_pid: u32,
    request: FilesystemControlRequestV1,
    deadline: Instant,
) -> Result<FilesystemControlResponseV1> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("Guest filesystem transport deadline elapsed")?;
    let mut client = GuestClient::connect_hybrid_vsock_bounded_exact_peer(
        Path::new(launch.vsock_socket_path.as_str()),
        GUEST_HOST_CONTROL_VSOCK_PORT_V1,
        remaining,
        expected_vmm_pid,
    )
    .context("connect exact VMM for Guest filesystem control")?;
    let response = client
        .filesystem_control_bounded(request, remaining)
        .context("execute bounded Guest filesystem control")?;
    anyhow::ensure!(
        client.hybrid_assigned_port().is_some(),
        "Guest filesystem transport omitted Cloud Hypervisor assigned port"
    );
    Ok(response)
}

fn validate_guest_runtime_ready(
    command: &LifecycleCommandEnvelope,
    launch: &RuntimeLaunchIdentity,
    response: &RuntimeReadyResponseV1,
) -> Result<()> {
    anyhow::ensure!(
        launch.runtime_incarnation == response.runtime_incarnation
            && launch.guest_cid == response.actual_guest_cid
            && launch.devices.len() == command.runtime_config.volumes.len()
            && response.devices.len() == launch.devices.len()
            && response.mounts.len() == launch.devices.len(),
        "GuestReady response changed the runtime or complete device/mount set"
    );

    for ((configured, launched), observed) in command
        .runtime_config
        .volumes
        .iter()
        .zip(&launch.devices)
        .zip(&response.devices)
    {
        anyhow::ensure!(
            launched.volume_id == configured.volume_id
                && launched.disk_id == configured.disk_id
                && launched.size_bytes == configured.size_bytes
                && launched.guest_device.serial == configured.guest_device_serial
                && launched.guest_device.slot == configured.guest_device_slot
                && observed.guest_device == launched.guest_device
                && observed.size_bytes == launched.size_bytes,
            "GuestReady device changed immutable launch identity"
        );
        let mounts = response
            .mounts
            .iter()
            .filter(|mount| {
                mount.device_major == observed.device_major
                    && mount.device_minor == observed.device_minor
                    && mount.source_path == observed.device_path
                    && mount.filesystem_uuid == observed.filesystem_uuid
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            mounts.len() == 1,
            "GuestReady device does not have exactly one canonical mount"
        );
        let mount = mounts[0];
        anyhow::ensure!(
            mount.filesystem_type.as_str() == "ext4"
                && mount.access == MountAccess::ReadWrite
                && mount.mount_root.as_str() == "/",
            "GuestReady filesystem is not a read-write ext4 root mount"
        );
        match &configured.guest_binding {
            RuntimeVolumeGuestBinding::RootBoot => anyhow::ensure!(
                configured.disk_role == DiskRole::Root
                    && configured.guest_device_slot == 0
                    && mount.mount_path.as_str() == "/",
                "GuestReady Root is not the exact slot-zero / mount"
            ),
            RuntimeVolumeGuestBinding::PersistentExt4 {
                filesystem_uuid,
                mount_path,
            } => anyhow::ensure!(
                configured.disk_role == DiskRole::Persistent
                    && observed.filesystem_uuid == *filesystem_uuid
                    && mount.mount_path.as_str() == mount_path.as_str(),
                "GuestReady Persistent filesystem UUID or mount path changed"
            ),
        }
    }
    Ok(())
}

fn validate_guest_ready_blockd_status(
    command: &LifecycleCommandEnvelope,
    planned: &PlannedDevice,
    current_head: &RemoteHead,
    status: &DurabilityStatus,
) -> Result<()> {
    let remote_generation = i64::try_from(current_head.generation.get())
        .context("GuestReady authority generation exceeds blockd status domain")?;
    anyhow::ensure!(
        status.volume_id == planned.volume.volume_id.as_str()
            && status.attachment_id == planned.attachment_id.as_str()
            && status.attachment_epoch == Some(planned.attachment_epoch)
            && status.acquire_origin.as_ref() == Some(&planned.acquire_origin)
            && status.node_id.as_ref() == Some(&command.node_id)
            && status.placement_epoch == Some(command.placement_identity.placement_epoch)
            && status.size_bytes == Some(planned.volume.size_bytes)
            && status.scope_id.as_ref() == Some(&planned.serving_service_id)
            && status.process_identity_token.as_ref()
                == Some(&planned.serving_process_identity_token)
            && status.device_ownership_token.as_ref() == Some(&planned.device_ownership_token)
            && status.guest_device_serial.as_ref() == Some(&planned.volume.guest_device_serial)
            && status.control_only == Some(false)
            && status.guest_io_enabled == Some(true)
            && status.remote_head.as_ref() == Some(current_head)
            && status.remote_durable_generation == remote_generation
            && status.local_durable_generation >= status.remote_durable_generation
            && !status.fenced,
        "GuestReady blockd changed command, authority, durability, or device identity"
    );
    Ok(())
}

fn inspect_guest_ready_frontend(
    physical: &InstalledPhysicalInspectionConfig,
    cat_id: &Id,
    planned: &PlannedDevice,
    installed: &InstalledRuntimeBlockFrontend,
    effect: &StartPhysicalEffectContext,
) -> Result<()> {
    match (&planned.frontend, installed) {
        (
            PrepareDeviceFrontend::VhostUserBlk {
                socket_path: expected,
                ..
            },
            InstalledRuntimeBlockFrontend::VhostUserBlk { socket_path },
        ) => {
            anyhow::ensure!(
                socket_path == expected,
                "GuestReady vhost-user frontend changed its planned socket"
            );
            inspect_exact_socket(Path::new(socket_path.as_str()))
        }
        (
            PrepareDeviceFrontend::KernelNbd {
                listener_socket_path,
                device_path,
                ..
            },
            InstalledRuntimeBlockFrontend::KernelNbd {
                device_path: installed_device,
                client,
            },
        ) => {
            anyhow::ensure!(
                installed_device == device_path,
                "GuestReady kernel-NBD frontend changed its planned device"
            );
            inspect_exact_socket(Path::new(listener_socket_path.as_str()))?;
            let kernel = physical
                .kernel_nbd
                .as_ref()
                .context("GuestReady kernel-NBD lacks installed pool configuration")?;
            let unit_id = planned
                .kernel_nbd_client_service_id
                .as_ref()
                .context("GuestReady kernel-NBD plan lacks its transient unit")?;
            let expected = KernelNbdClientExpectation::new(
                kernel,
                cat_id,
                unit_id,
                listener_socket_path,
                device_path,
                planned.volume.size_bytes,
            )?;
            anyhow::ensure!(
                inspect_exact_kernel_nbd_client(physical, &expected)?.as_ref() == Some(client),
                "GuestReady kernel-NBD client changed physical identity"
            );
            validate_kernel_nbd_systemd_unit(physical, &expected, effect)
        }
        _ => anyhow::bail!("GuestReady frontend kind changed from its durable device plan"),
    }
}

fn validate_serving_blockd_status(
    command: &LifecycleCommandEnvelope,
    planned: &PlannedDevice,
    grant: &AtomicStartVolumeGrant,
    status: &DurabilityStatus,
) -> Result<()> {
    let remote_generation = i64::try_from(grant.authoritative_head.generation.get())
        .context("authority generation exceeds blockd status domain")?;
    anyhow::ensure!(
        status.volume_id == planned.volume.volume_id.as_str()
            && status.attachment_id == planned.attachment_id.as_str()
            && status.attachment_epoch == Some(planned.attachment_epoch)
            && status.acquire_origin.as_ref() == Some(&planned.acquire_origin)
            && status.node_id.as_ref() == Some(&command.node_id)
            && status.placement_epoch == Some(command.placement_identity.placement_epoch)
            && status.size_bytes == Some(planned.volume.size_bytes)
            && status.scope_id.as_ref() == Some(&planned.serving_service_id)
            && status.process_identity_token.as_ref()
                == Some(&planned.serving_process_identity_token)
            && status.device_ownership_token.as_ref() == Some(&planned.device_ownership_token)
            && status.guest_device_serial.as_ref() == Some(&planned.volume.guest_device_serial)
            && status.control_only == Some(false)
            && status.guest_io_enabled == Some(true)
            && status.remote_head.as_ref() == Some(&grant.authoritative_head)
            && status.remote_durable_generation == remote_generation
            && status.local_durable_generation >= status.remote_durable_generation
            && !status.fenced,
        "serving blockd handshake changed command, authority, or device identity"
    );
    Ok(())
}

fn inspect_exact_socket(path: &Path) -> Result<()> {
    let before = fs::symlink_metadata(path).context("inspect exact managed socket")?;
    anyhow::ensure!(
        before.file_type().is_socket() && !before.file_type().is_symlink(),
        "managed frontend path is not a Unix socket"
    );
    let after = fs::symlink_metadata(path).context("reinspect exact managed socket")?;
    anyhow::ensure!(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "managed frontend socket changed during inspection"
    );
    Ok(())
}

fn path_is_absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {} absence", path.display())),
    }
}

fn root_blockd_arguments(
    blockd: &PlannedBlockdLaunchConfig,
    volume: &PlannedRootVolume,
    control_authorization_path: &Path,
    object_write: &PlannedObjectWriteMode,
) -> Result<Vec<std::ffi::OsString>> {
    let transition = volume
        .provision_transition_id
        .as_ref()
        .context("Root blockd plan lacks provision transition")?;
    let service = volume
        .provision_service_id
        .as_ref()
        .context("Root blockd plan lacks service ID")?;
    let process_token = volume
        .provision_process_identity_token
        .as_ref()
        .context("Root blockd plan lacks process token")?;
    let control_socket = volume
        .provision_control_socket_path
        .as_ref()
        .context("Root blockd plan lacks control socket")?;
    let mut arguments = vec![
        "--volume-id".into(),
        volume.volume.volume_id.as_str().into(),
        "--data-dir".into(),
        volume.lineage_data_directory.as_str().into(),
        "--attachment-id".into(),
        volume.attachment_id.as_str().into(),
        "--control-only".into(),
        "--authorized-control-spec".into(),
        control_authorization_path.as_os_str().to_owned(),
        "--provision-transition-id".into(),
        transition.as_str().into(),
        "--runtime-scope-id".into(),
        service.as_str().into(),
        "--process-identity-token".into(),
        process_token.as_str().into(),
        "--metadata-store-adapter".into(),
        blockd.metadata_store_adapter.as_str().into(),
        "--object-store-adapter".into(),
        blockd.object_store_adapter.as_str().into(),
        "--lease-ttl-ms".into(),
        blockd.lease_ttl_ms.get().to_string().into(),
        "--max-staged-bytes".into(),
        blockd.max_staged_bytes.get().to_string().into(),
        "--max-staged-packs".into(),
        blockd.max_staged_packs.get().to_string().into(),
        "--max-local-bytes".into(),
        blockd.max_local_bytes.get().to_string().into(),
        "--durability".into(),
        match volume.volume.durability {
            cats_api::runtime_reconciliation::Durability::Strict => "strict".into(),
            cats_api::runtime_reconciliation::Durability::Relaxed => "relaxed".into(),
        },
        "--listen-control".into(),
        control_socket.as_str().into(),
    ];
    append_adapter_options(
        &mut arguments,
        "--metadata-store-option",
        &blockd.metadata_store_options,
    );
    append_adapter_options(
        &mut arguments,
        "--object-store-option",
        &blockd.object_store_options,
    );
    if let PlannedObjectWriteMode::Gateway {
        gateway_origin,
        credential_directory,
        ..
    } = object_write
    {
        arguments.extend([
            "--object-write-gateway-url".into(),
            gateway_origin.as_str().into(),
            "--object-write-credential-directory".into(),
            credential_directory.as_str().into(),
        ]);
    }
    Ok(arguments)
}

fn append_adapter_options(arguments: &mut Vec<std::ffi::OsString>, flag: &str, options: &[String]) {
    for option in options {
        arguments.push(flag.into());
        arguments.push(option.into());
    }
}

fn network_reservation_digest(
    reservation: &InstalledAtomicStartNetworkReservation,
) -> Result<Sha256Digest> {
    let mut preimage = reservation.clone();
    preimage.reservation_digest = zero_digest();
    digest_serialized(NETWORK_RESERVATION_DOMAIN, &preimage)
}

fn complete_effect(
    command: &LifecycleCommandEnvelope,
    request: &AtomicStartRuntimeEffectRequest,
    plan: &InstalledAtomicStartPlatformPlan,
    body: InstalledAtomicStartReceiptBody,
    progress: InstalledRuntimeProgressManifest,
) -> Result<AtomicStartRuntimeEffectOutcome> {
    anyhow::ensure!(
        deadline_expired_failure_reason(JournaledEffectDiscoveryState::ExactPostcondition)
            .is_none(),
        "an exact atomic Start postcondition became deadline-dependent"
    );
    let receipt = InstalledAtomicStartPlatformReceipt {
        version: PLAN_VERSION,
        phase: plan.phase,
        node_id: command.node_id.clone(),
        cat_id: command.cat_id.clone(),
        operation_id: command.operation_id.clone(),
        request_fingerprint: command.request_fingerprint.clone(),
        runtime_incarnation: request.context.runtime_incarnation.clone(),
        platform_plan_digest: plan.plan_digest.clone(),
        body,
    };
    let platform_receipt = ExactBytes::new(canonical_json(&receipt)?);
    anyhow::ensure!(
        !platform_receipt.as_slice().is_empty()
            && platform_receipt.as_slice().len() <= PLATFORM_PLAN_MAX_BYTES,
        "installed atomic Start platform receipt exceeds its byte cap"
    );
    let receipt_digest = atomic_start_platform_receipt_digest(
        command,
        plan.phase,
        &plan.plan_digest,
        &platform_receipt,
    )?;
    Ok(AtomicStartRuntimeEffectOutcome::Completed(
        super::start::AtomicStartRuntimeEffectReceipt {
            phase: plan.phase,
            platform_plan: request.platform_plan.clone(),
            platform_plan_digest: plan.plan_digest.clone(),
            platform_receipt,
            receipt_digest,
            artifact_classifications: Vec::new(),
            runtime_progress: progress,
        },
    ))
}

fn volume_refresh_required(
    request: &AtomicStartRuntimeEffectRequest,
    plan: &InstalledAtomicStartPlatformPlan,
    phase_deadline: Instant,
) -> Result<AtomicStartRuntimeEffectOutcome> {
    if !phase_and_command_deadlines_are_live(
        Instant::now(),
        phase_deadline,
        current_unix_millis()?,
        request.context.effect_deadline_unix_ms,
    ) {
        let reason = deadline_expired_failure_reason(JournaledEffectDiscoveryState::ZeroMutation)
            .expect("zero-mutation expired discovery has a definite failure reason");
        return definite_runtime_failure(request, reason);
    }
    Ok(AtomicStartRuntimeEffectOutcome::VolumeRefreshRequired {
        platform_plan_digest: plan.plan_digest.clone(),
        runtime_progress: Some(request.context.runtime_progress.clone()),
    })
}

fn materialized_plan_without_mutation_authority(
    request: &AtomicStartRuntimeEffectRequest,
    phase_deadline: Instant,
    live_error: &'static str,
) -> Result<AtomicStartRuntimeEffectOutcome> {
    if !phase_and_command_deadlines_are_live(
        Instant::now(),
        phase_deadline,
        current_unix_millis()?,
        request.context.effect_deadline_unix_ms,
    ) {
        let reason =
            deadline_expired_failure_reason(JournaledEffectDiscoveryState::PartialMutation)
                .expect("partial expired discovery has a definite failure reason");
        return definite_runtime_failure(request, reason);
    }
    Err(anyhow::anyhow!(live_error))
}

fn definite_runtime_failure(
    request: &AtomicStartRuntimeEffectRequest,
    reason: cats_api::runtime_lifecycle::CommandFailureReason,
) -> Result<AtomicStartRuntimeEffectOutcome> {
    definite_runtime_failure_with_progress(
        request,
        reason,
        request.context.runtime_progress.clone(),
    )
}

fn definite_runtime_failure_with_progress(
    request: &AtomicStartRuntimeEffectRequest,
    reason: cats_api::runtime_lifecycle::CommandFailureReason,
    runtime_progress: InstalledRuntimeProgressManifest,
) -> Result<AtomicStartRuntimeEffectOutcome> {
    Ok(AtomicStartRuntimeEffectOutcome::Failed(
        AtomicStartDefiniteFailure {
            reason,
            artifact_classifications: request.context.artifact_classifications.clone(),
            runtime_progress: Some(runtime_progress),
        },
    ))
}

fn previous_progress(
    request: &AtomicStartRuntimeEffectRequest,
) -> Result<&InstalledRuntimeProgressManifest> {
    if let Some(completed) = request.context.completed_effects.last() {
        anyhow::ensure!(
            completed.runtime_progress == request.context.runtime_progress,
            "atomic Start context and latest completed progress differ"
        );
    }
    Ok(&request.context.runtime_progress)
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).context("encode canonical atomic Start JSON")?;
    Ok(cats_api::runtime_reconciliation::canonical_json_value_bytes(&value))
}

fn encode_exact_json(value: &impl Serialize, context: &'static str) -> Result<ExactBytes> {
    Ok(ExactBytes::new(canonical_json(value).context(context)?))
}

fn decode_exact_json<T>(bytes: &ExactBytes, context: &'static str) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes.as_slice()).context(context)?;
    anyhow::ensure!(
        canonical_json(&value)? == bytes.as_slice(),
        "exact JSON receipt is not canonical"
    );
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedFileInspection {
    Absent,
    Exact,
    Conflict,
}

/// Side-effect-free preflight for a journal-named artifact.  Publication
/// repeats the descriptor-relative checks below; this probe exists only to
/// distinguish a provable zero-use lease-refresh edge from a prior attempt
/// which already crossed its first physical mutation.
fn inspect_exact_managed_file(
    managed_root: &Path,
    target: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<ManagedFileInspection> {
    anyhow::ensure!(
        managed_root.is_absolute()
            && target.is_absolute()
            && target.starts_with(managed_root)
            && !bytes.is_empty()
            && target
                .strip_prefix(managed_root)?
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "managed artifact inspection escaped its configured root"
    );
    let before = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(ManagedFileInspection::Absent)
        }
        Err(error) => return Err(error).context("inspect managed artifact metadata"),
    };
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.nlink() != 1
        || before.mode() & 0o7777 != mode
        || before.len() != bytes.len() as u64
    {
        return Ok(ManagedFileInspection::Conflict);
    }
    let observed = fs::read(target).context("read managed artifact during preflight")?;
    let after = fs::symlink_metadata(target).context("reinspect managed artifact metadata")?;
    Ok(
        if observed == bytes && before.dev() == after.dev() && before.ino() == after.ino() {
            ManagedFileInspection::Exact
        } else {
            ManagedFileInspection::Conflict
        },
    )
}

/// Publish one exact file below a configured managed root. Existing exact
/// bytes are an idempotent replay; an unknown entry or symlink fails closed.
fn publish_exact_managed_file(
    managed_root: &Path,
    target: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    anyhow::ensure!(
        target.is_absolute() && target.starts_with(managed_root) && !bytes.is_empty(),
        "managed atomic Start artifact path is outside its configured root"
    );
    let relative = target
        .strip_prefix(managed_root)
        .context("strip managed atomic Start artifact root")?;
    let basename = relative
        .file_name()
        .context("managed atomic Start artifact has no basename")?;
    let parent_relative = relative
        .parent()
        .context("managed atomic Start artifact has no parent")?;
    let root = open_absolute_directory(managed_root)?;
    let parent = open_or_create_relative_directories(&root, parent_relative, 0o700)?;
    publish_exact_at(&parent, basename, bytes, mode)
}

fn replace_exact_managed_file(
    managed_root: &Path,
    target: &Path,
    expected_old: &[u8],
    replacement: &Path,
    replacement_bytes: &[u8],
    mode: u32,
) -> Result<()> {
    anyhow::ensure!(
        target.parent() == replacement.parent()
            && inspect_exact_managed_file(managed_root, target, expected_old, mode)?
                == ManagedFileInspection::Exact
            && inspect_exact_managed_file(managed_root, replacement, replacement_bytes, mode,)?
                == ManagedFileInspection::Exact,
        "managed replacement lost its exact old or new artifact"
    );
    let parent_path = target
        .parent()
        .context("managed replacement has no parent")?;
    let parent_relative = parent_path
        .strip_prefix(managed_root)
        .context("managed replacement parent escaped root")?;
    let parent = open_existing_relative_directories(
        &open_absolute_directory(managed_root)?,
        parent_relative,
    )?;
    let old_name = CString::new(
        target
            .file_name()
            .context("managed replacement target has no basename")?
            .as_encoded_bytes(),
    )?;
    let new_name = CString::new(
        replacement
            .file_name()
            .context("managed replacement source has no basename")?
            .as_encoded_bytes(),
    )?;
    loop {
        // SAFETY: both names and the retained directory descriptor remain
        // live. renameat atomically installs the already-fsynced replacement
        // over the just-revalidated predecessor artifact.
        let result = unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                new_name.as_ptr(),
                parent.as_raw_fd(),
                old_name.as_ptr(),
            )
        };
        if result == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error).context("atomically replace managed artifact");
        }
    }
    parent
        .sync_all()
        .context("fsync managed replacement directory")?;
    anyhow::ensure!(
        inspect_exact_managed_file(managed_root, target, replacement_bytes, mode)?
            == ManagedFileInspection::Exact,
        "managed replacement did not install exact bytes"
    );
    Ok(())
}

fn open_absolute_directory(path: &Path) -> Result<File> {
    anyhow::ensure!(path.is_absolute(), "managed directory is not absolute");
    let text = CString::new(path.as_os_str().as_encoded_bytes())
        .context("managed directory path contains NUL")?;
    // SAFETY: `text` is a live NUL-terminated absolute path. On success the
    // returned descriptor is immediately owned by `File`.
    let descriptor = unsafe {
        libc::open(
            text.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).context("open managed artifact root");
    }
    // SAFETY: successful `open` returned one newly-owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_or_create_relative_directories(root: &File, relative: &Path, mode: u32) -> Result<File> {
    anyhow::ensure!(!relative.is_absolute(), "managed relative path is absolute");
    let mut current = root.try_clone().context("clone managed root descriptor")?;
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            anyhow::bail!("managed relative path contains a non-normal component")
        };
        let name = CString::new(component.as_encoded_bytes())
            .context("managed directory component contains NUL")?;
        loop {
            // SAFETY: current/name remain live; mkdirat retains neither.
            let result =
                unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
            if result == 0 {
                current.sync_all().context("fsync new managed directory")?;
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                break;
            }
            return Err(error).context("create managed directory component");
        }
        let next = openat(
            &current,
            &name,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0,
        )?;
        current = next;
    }
    Ok(current)
}

fn open_existing_relative_directories(root: &File, relative: &Path) -> Result<File> {
    anyhow::ensure!(!relative.is_absolute(), "managed relative path is absolute");
    let mut current = root.try_clone().context("clone managed root descriptor")?;
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            anyhow::bail!("managed relative path contains a non-normal component")
        };
        let name = CString::new(component.as_encoded_bytes())
            .context("managed directory component contains NUL")?;
        current = openat(
            &current,
            &name,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0,
        )?;
    }
    Ok(current)
}

fn publish_exact_at(
    directory: &File,
    basename: &std::ffi::OsStr,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    let target = CString::new(basename.as_encoded_bytes())
        .context("managed artifact basename contains NUL")?;
    if let Some(existing) = read_exact_at_optional(directory, &target, bytes.len())? {
        anyhow::ensure!(
            existing == bytes,
            "managed artifact conflicts with durable plan"
        );
        return Ok(());
    }
    let temporary = CString::new(format!(".{}.atomic-start.tmp", basename.to_string_lossy()))
        .context("managed artifact temporary basename contains NUL")?;
    unlinkat_if_exists(directory, &temporary)?;
    let mut file = openat(
        directory,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        mode,
    )?;
    file.write_all(bytes).context("write managed artifact")?;
    file.sync_all().context("fsync managed artifact")?;
    let metadata = file.metadata().context("stat managed artifact")?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.len() == bytes.len() as u64
            && metadata.mode() & 0o7777 == mode,
        "managed artifact has an unsafe physical identity"
    );
    renameat(directory, &temporary, &target)?;
    directory
        .sync_all()
        .context("fsync managed artifact directory")?;
    let reloaded = read_exact_at_optional(directory, &target, bytes.len())?
        .context("published managed artifact disappeared")?;
    anyhow::ensure!(reloaded == bytes, "published managed artifact changed");
    Ok(())
}

fn read_exact_at_optional(
    directory: &File,
    name: &CStr,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let mut file = match openat(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata().context("stat managed artifact")?;
    anyhow::ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.len() as usize <= maximum,
        "managed artifact is unsafe or oversized"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .context("read managed artifact")?;
    anyhow::ensure!(
        bytes.len() == metadata.len() as usize,
        "managed artifact changed"
    );
    Ok(Some(bytes))
}

fn openat(directory: &File, name: &CStr, flags: libc::c_int, mode: u32) -> Result<File> {
    // SAFETY: directory/name remain live and openat retains neither. A
    // successful descriptor is immediately owned by File.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).context("open managed artifact entry");
    }
    // SAFETY: successful openat returned one newly-owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn renameat(directory: &File, source: &CStr, target: &CStr) -> Result<()> {
    loop {
        // SAFETY: directory and both names remain live; renameat retains none.
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
            return Err(error).context("publish managed artifact");
        }
    }
}

fn unlinkat_if_exists(directory: &File, name: &CStr) -> Result<()> {
    loop {
        // SAFETY: directory/name remain live and unlinkat retains neither.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error).context("remove managed artifact temporary entry");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_lifecycle::{PlacementIdentity, RuntimeVolumeGuestBinding};
    use cats_api::runtime_lifecycle_volume::{
        LifecycleCommandStartVolumeGrantReceipt, LifecyclePersistentInitializationCommitReceipt,
        LifecycleStartVolumeGrantAuthority,
    };
    use cats_api::runtime_reconciliation::{
        Durability, Epoch, FenceEpoch, NodeBootId, NormalAcquireRequest, NormalAcquireResult,
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

    fn blank_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }

    fn initialized_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(digest(30)),
            root_object_id: Some(AsciiText::new("roots/one").unwrap()),
        }
    }

    fn session(epoch: u64) -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
            agent_instance_id: random(2),
            agent_session_epoch: Epoch::new(epoch).unwrap(),
        }
    }

    fn plan_fixture() -> InstalledAtomicStartPlatformPlan {
        let mut plan = InstalledAtomicStartPlatformPlan {
            version: PLAN_VERSION,
            phase: AtomicStartRuntimeEffectPhase::PrepareRoot,
            node_id: id("node_a"),
            cat_id: id("cat_a"),
            placement_identity: PlacementIdentity {
                node_id: id("node_a"),
                placement_epoch: Epoch::new(3).unwrap(),
            },
            operation_id: id("operation_a"),
            request_fingerprint: digest(4),
            runtime_config_id: id("config_a"),
            runtime_config_digest: digest(5),
            runtime_incarnation: random(6),
            source: StartSource::Genesis,
            effect_deadline_unix_ms: UnixMillis::new(10_000).unwrap(),
            volume_grant_sequence: WireU64::new(0).unwrap(),
            volume_grant_receipt_digests: Vec::new(),
            completed_platform_plan_digests: Vec::new(),
            installed_config_digest: digest(7),
            body: InstalledAtomicStartPlanBody::DefiniteFailure {
                reason: cats_api::runtime_lifecycle::CommandFailureReason::ImageUnavailable,
            },
            plan_digest: zero_digest(),
        };
        plan.plan_digest = platform_plan_digest(&plan).unwrap();
        plan
    }

    fn persistent_commit_fixture() -> LifecyclePersistentInitializationCommitRequest {
        let scope = LifecycleVolumeCommandScope {
            operation_id: id("operation_a"),
            request_fingerprint: digest(8),
            cat_id: id("cat_a"),
            node_id: id("node_a"),
            placement_identity: PlacementIdentity {
                node_id: id("node_a"),
                placement_epoch: Epoch::new(3).unwrap(),
            },
        };
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
        let acquire = NormalAcquireRequest {
            volume_id: volume.volume_id.clone(),
            transition_id: random(41),
            attachment_id: id("attachment_persistent"),
            expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
            placement_epoch: scope.placement_identity.placement_epoch,
            lease_duration_ms: 30_000,
        };
        let acquired = NormalAcquireResult {
            volume_id: volume.volume_id.clone(),
            transition_id: acquire.transition_id.clone(),
            attachment_id: acquire.attachment_id.clone(),
            resulting_epoch: FenceEpoch::new(1).unwrap(),
            resulting_head: blank_head(),
            lease_expires_at: UnixMillis::new(60_000).unwrap(),
        };
        let binding = LifecyclePersistentInitializationBinding {
            scope: scope.clone(),
            runtime_config_id: id("config_a"),
            runtime_config_digest: digest(42),
            volume: volume.clone(),
            start_grant: LifecycleStoredStartVolumeGrant {
                receipt: LifecycleCommandStartVolumeGrantReceipt {
                    scope: scope.clone(),
                    grant_sequence: WireU64::new(0).unwrap(),
                    volume: volume.clone(),
                    authority: LifecycleStartVolumeGrantAuthority::NormalAcquire {
                        request: acquire,
                        result: acquired,
                    },
                },
                receipt_digest: digest(43),
            },
        };
        let initialized = initialized_head();
        LifecyclePersistentInitializationCommitRequest {
            binding: Box::new(binding),
            format_plan_digest: digest(51),
            initialization_token: random(44),
            filesystem_uuid: random(40),
            expected_blank_head: blank_head(),
            initialized_head: initialized.clone(),
            guest_probe: Box::new(LifecyclePersistentInitializationGuestProbe {
                challenge: random(45),
                runtime_incarnation: random(46),
                guest_device_serial: volume.guest_device_serial.clone(),
                guest_device_slot: volume.guest_device_slot,
                device_major: 252,
                device_minor: 1,
                size_bytes: volume.size_bytes,
                filesystem_uuid: random(40),
                filesystem_state: LifecyclePersistentGuestFilesystemState::ExactExt4Unmounted,
                guest_response_digest: digest(47),
            }),
            flush_drain: Box::new(LifecyclePersistentInitializationFlushDrainReceipt {
                guest_flush_challenge: random(48),
                guest_flush_response_digest: digest(49),
                blockd_drain_receipt_digest: digest(50),
                durability: LifecycleVolumeDurabilityProof {
                    scope: scope.clone(),
                    volume: LifecycleVolumeTarget {
                        disk_id: volume.disk_id,
                        disk_role: DiskRole::Persistent,
                        volume_id: volume.volume_id,
                        attachment_id: id("attachment_persistent"),
                        attachment_epoch: FenceEpoch::new(1).unwrap(),
                    },
                    remote_head: initialized.clone(),
                    local_durable_generation: initialized.generation,
                    remote_durable_generation: initialized.generation,
                    pending_pack_count: WireU64::new(0).unwrap(),
                },
            }),
        }
    }

    #[test]
    fn platform_plan_and_receipt_round_trip_reject_tamper() {
        let plan = plan_fixture();
        let encoded = ExactBytes::new(serde_json::to_vec(&plan).unwrap());
        assert_eq!(decode_platform_plan(&encoded).unwrap(), plan);

        let mut tampered = plan.clone();
        tampered.operation_id = id("operation_other");
        assert!(
            decode_platform_plan(&ExactBytes::new(serde_json::to_vec(&tampered).unwrap())).is_err()
        );

        let receipt = InstalledAtomicStartPlatformReceipt {
            version: PLAN_VERSION,
            phase: AtomicStartRuntimeEffectPhase::FormatPersistentVolumes,
            node_id: id("node_a"),
            cat_id: id("cat_a"),
            operation_id: id("operation_a"),
            request_fingerprint: digest(4),
            runtime_incarnation: random(6),
            platform_plan_digest: plan.plan_digest,
            body: InstalledAtomicStartReceiptBody::FormatPersistentVolumes {
                format_receipts: Vec::new(),
            },
        };
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert_eq!(
            decode_platform_receipt(&ExactBytes::new(bytes.clone())).unwrap(),
            receipt
        );
        let mut noncanonical = bytes;
        noncanonical.push(b' ');
        assert!(decode_platform_receipt(&ExactBytes::new(noncanonical)).is_err());
    }

    #[test]
    fn response_loss_discovery_does_not_duplicate_managed_mutation() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("nested/exact.json");
        publish_exact_managed_file(root.path(), &target, b"exact", 0o600).unwrap();
        let before = fs::symlink_metadata(&target).unwrap();
        publish_exact_managed_file(root.path(), &target, b"exact", 0o600).unwrap();
        let after = fs::symlink_metadata(&target).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(
            inspect_exact_managed_file(root.path(), &target, b"exact", 0o600).unwrap(),
            ManagedFileInspection::Exact
        );
    }

    #[test]
    fn lease_and_session_are_a_double_mutation_gate() {
        let planned = session(7);
        assert!(lease_session_and_budget_are_current(
            &planned, &planned, true
        ));
        assert!(!lease_session_and_budget_are_current(
            &planned, &planned, false
        ));
        assert!(!lease_session_and_budget_are_current(
            &session(8),
            &planned,
            true
        ));
    }

    #[test]
    fn completed_root_gateway_session_must_remain_current_before_later_phases() {
        let original = session(7);
        let replacement = session(8);
        let gateway = PlannedObjectWriteMode::Gateway {
            session: original.clone(),
            gateway_origin: "http://127.0.0.1:9000".to_owned(),
            credential_directory: HostPath::new("/run/cats/object-write".to_owned()).unwrap(),
            expected_credential_ids: vec![id("credential_a")],
        };
        assert!(object_write_session_is_current(
            &gateway, &original, &original,
        ));
        assert!(!object_write_session_is_current(
            &gateway,
            &replacement,
            &replacement,
        ));
        assert!(!object_write_session_is_current(
            &gateway,
            &original,
            &replacement,
        ));
        assert!(object_write_session_is_current(
            &PlannedObjectWriteMode::DirectProvider,
            &replacement,
            &replacement,
        ));
    }

    #[test]
    fn definite_root_failure_retains_per_volume_partial_lineage() {
        let mut first_volume = persistent_commit_fixture().binding.volume.clone();
        first_volume.volume_id = id("volume_first");
        first_volume.disk_id = id("disk_first");
        let mut second_volume = first_volume.clone();
        second_volume.volume_id = id("volume_second");
        second_volume.disk_id = id("disk_second");
        let origin = AcquireOrigin::Normal {
            transition_id: random(70),
        };
        let planned = PlannedRootVolume {
            volume: first_volume.clone(),
            attachment_id: id("attachment_first"),
            attachment_epoch: FenceEpoch::new(1).unwrap(),
            acquire_origin: origin.clone(),
            authority_head: blank_head(),
            authority_receipt_digest: digest(71),
            lineage_data_directory: HostPath::new("/var/lib/cats/lineage/first".to_owned())
                .unwrap(),
            provision_transition_id: None,
            provision_process_identity_token: None,
            provision_service_id: None,
            provision_control_socket_path: None,
        };
        let mut slots = [
            InstalledRuntimeProgressVolumeManifest {
                volume_id: first_volume.volume_id,
                disk_id: first_volume.disk_id,
                disk_role: first_volume.disk_role,
                attachment_id: planned.attachment_id.clone(),
                attachment_epoch: planned.attachment_epoch,
                acquire_origin: origin.clone(),
                authority_head: blank_head(),
                authority_receipt_digest: Some(digest(71)),
                local_lineage_data_directory: None,
                blockd: None,
                blockd_control_socket_path: None,
                frontend: None,
            },
            InstalledRuntimeProgressVolumeManifest {
                volume_id: second_volume.volume_id,
                disk_id: second_volume.disk_id,
                disk_role: second_volume.disk_role,
                attachment_id: id("attachment_second"),
                attachment_epoch: FenceEpoch::new(1).unwrap(),
                acquire_origin: origin,
                authority_head: blank_head(),
                authority_receipt_digest: Some(digest(72)),
                local_lineage_data_directory: None,
                blockd: None,
                blockd_control_socket_path: None,
                frontend: None,
            },
        ];

        record_exact_root_lineage_failure_progress(&mut slots[0], &planned, initialized_head())
            .unwrap();
        assert_eq!(
            slots[0].local_lineage_data_directory.as_ref(),
            Some(&planned.lineage_data_directory)
        );
        assert_eq!(slots[0].authority_head, initialized_head());
        assert!(slots[1].local_lineage_data_directory.is_none());
    }

    #[test]
    fn deterministic_process_identity_conflict_is_not_transport_ambiguity() {
        let conflict = exact_process_conflict("fixture argv conflict");
        assert!(is_exact_process_conflict(&conflict));

        let unavailable = anyhow::Error::new(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "fixture procfs unavailable",
        ));
        assert!(!is_exact_process_conflict(&unavailable));
    }

    #[test]
    fn lease_expiry_during_root_device_or_vmm_keeps_any_materialized_plan() {
        let effect_timeout = Duration::from_secs(30);
        assert_eq!(
            bounded_physical_discovery_budget(Duration::ZERO, effect_timeout),
            effect_timeout,
            "an elapsed command must retain a bounded read-only discovery window"
        );
        let now = Instant::now();
        let live_phase = now.checked_add(Duration::from_secs(1)).unwrap();
        let elapsed_phase = now.checked_sub(Duration::from_secs(1)).unwrap();
        let wall_now = UnixMillis::new(20).unwrap();
        assert!(phase_and_command_deadlines_are_live(
            now,
            live_phase,
            wall_now,
            UnixMillis::new(21).unwrap(),
        ));
        assert!(!phase_and_command_deadlines_are_live(
            now, live_phase, wall_now, wall_now,
        ));
        assert!(!phase_and_command_deadlines_are_live(
            now,
            elapsed_phase,
            wall_now,
            UnixMillis::new(21).unwrap(),
        ));
        assert_eq!(
            deadline_expired_failure_reason(JournaledEffectDiscoveryState::ZeroMutation),
            Some(cats_api::runtime_lifecycle::CommandFailureReason::InvalidLocalPrecondition)
        );
        assert_eq!(
            deadline_expired_failure_reason(JournaledEffectDiscoveryState::ExactPostcondition),
            None,
            "an exact lost-response postcondition remains completable after deadline"
        );
        assert_eq!(
            deadline_expired_failure_reason(JournaledEffectDiscoveryState::PartialMutation),
            Some(cats_api::runtime_lifecycle::CommandFailureReason::InvalidLocalPrecondition)
        );

        // Before the first Root lineage, device authorization, or VMM launch
        // spec is published, the identical durable plan may renew its grants.
        assert!(lease_loss_allows_same_plan_refresh(true));

        // After any of those exact boundaries may exist, loss of the
        // process-local witness cannot replan or start another publisher/VMM;
        // production retains the same Executing plan for discovery.
        for phase in ["prepare_root", "prepare_devices", "activate_runtime"] {
            assert!(
                !lease_loss_allows_same_plan_refresh(false),
                "{phase} incorrectly allowed refresh after mutation"
            );
        }
    }

    #[test]
    fn persistent_commit_response_loss_replays_exact_and_rejects_nested_tamper() {
        let expected = persistent_commit_fixture();
        validate_lifecycle_persistent_initialization_commit(&expected).unwrap();
        let format_receipt = encode_exact_json(
            &InstalledPersistentFormatReceipt::CommitRequired {
                commit: Box::new(expected.clone()),
            },
            "encode test format receipt",
        )
        .unwrap();
        let commit_body = journal_persistent_commit_plan(
            expected.format_plan_digest.clone(),
            vec![format_receipt.clone()],
        )
        .unwrap();
        let InstalledAtomicStartPlanBody::CommitPersistentInitialized {
            format_plan_digest,
            commit_requests,
        } = commit_body
        else {
            panic!("format receipt did not produce a Commit plan")
        };
        assert_eq!(format_plan_digest, expected.format_plan_digest);
        assert_eq!(
            commit_requests.as_slice(),
            std::slice::from_ref(&format_receipt)
        );
        assert!(journal_persistent_commit_plan(digest(62), vec![format_receipt]).is_err());

        let later_head = RemoteHead {
            generation: Generation::new(2).unwrap(),
            root_hash: Some(digest(63)),
            root_object_id: Some(AsciiText::new("roots/two").unwrap()),
        };
        let inspection = LifecyclePersistentInitializationInspection {
            binding: expected.binding.clone(),
            attachment_id: id("attachment_persistent"),
            attachment_epoch: FenceEpoch::new(1).unwrap(),
            current_head: later_head,
            initialization: LifecyclePersistentInitializationState::Initialized {
                initialization_token: expected.initialization_token.clone(),
                filesystem_uuid: expected.filesystem_uuid.clone(),
                expected_blank_head: expected.expected_blank_head.clone(),
                initialized_head: expected.initialized_head.clone(),
                initialized_at: UnixMillis::new(70_000).unwrap(),
            },
        };
        let observation =
            classify_journaled_persistent_commit_inspection(&expected, &inspection).unwrap();
        assert_eq!(
            observation,
            JournaledPersistentCommitObservation::InitializedExact
        );
        validate_journaled_persistent_commit_binding(
            &expected,
            &inspection,
            &expected.binding,
            &inspection.attachment_id,
            inspection.attachment_epoch,
        )
        .unwrap();
        let mut newer_binding = expected.binding.as_ref().clone();
        newer_binding.start_grant.receipt_digest = digest(64);
        assert!(validate_journaled_persistent_commit_binding(
            &expected,
            &inspection,
            &newer_binding,
            &inspection.attachment_id,
            inspection.attachment_epoch,
        )
        .is_err());
        let mut planned_inspection = inspection.clone();
        planned_inspection.current_head = expected.initialized_head.clone();
        let mut renewed_inspection = inspection.clone();
        renewed_inspection.binding.start_grant.receipt_digest = digest(65);
        assert!(persistent_initialization_inspection_rebinds_plan(
            &planned_inspection,
            &renewed_inspection,
        ));
        renewed_inspection.initialization = LifecyclePersistentInitializationState::Uninitialized {
            initialization_token: expected.initialization_token.clone(),
            filesystem_uuid: expected.filesystem_uuid.clone(),
            expected_blank_head: expected.expected_blank_head.clone(),
        };
        assert!(!persistent_initialization_inspection_rebinds_plan(
            &planned_inspection,
            &renewed_inspection,
        ));
        let exact = LifecycleStoredPersistentInitializationCommit {
            receipt: LifecyclePersistentInitializationCommitReceipt {
                request: Box::new(expected.clone()),
                initialized_at: UnixMillis::new(70_000).unwrap(),
            },
            receipt_digest: digest(60),
        };
        let monotonic_physical_lease_budget_is_live = false;
        assert!(!monotonic_physical_lease_budget_is_live);
        let calls = std::cell::Cell::new(0);
        let replayed = submit_journaled_persistent_commit(
            &expected.guest_probe.runtime_incarnation,
            &expected.format_plan_digest,
            &expected,
            observation,
            |runtime_incarnation, format_plan_digest, commit| {
                calls.set(calls.get() + 1);
                assert_eq!(
                    runtime_incarnation,
                    &expected.guest_probe.runtime_incarnation
                );
                assert_eq!(format_plan_digest, &expected.format_plan_digest);
                assert_eq!(commit, expected);
                Ok::<_, ()>(exact.clone())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        validate_exact_persistent_commit_response(&expected, &replayed).unwrap();

        let mut tampered = replayed;
        tampered.receipt.request.guest_probe.guest_response_digest = digest(61);
        assert!(validate_exact_persistent_commit_response(&expected, &tampered).is_err());

        assert_eq!(
            persistent_mount_lease_loss_disposition(false),
            PersistentMountLeaseLossDisposition::RefreshSamePlan
        );
        assert_eq!(
            persistent_mount_lease_loss_disposition(true),
            PersistentMountLeaseLossDisposition::FailClosed
        );
    }

    #[test]
    fn same_node_sources_never_select_fresh_fallback() {
        assert!(activation_kind_is_exact_for_source(
            StartSource::SameNodeSuspended,
            false,
            PlannedRuntimeActivationKind::ResumeSuspended,
        ));
        assert!(!activation_kind_is_exact_for_source(
            StartSource::SameNodeSuspended,
            false,
            PlannedRuntimeActivationKind::Fresh,
        ));
        assert!(activation_kind_is_exact_for_source(
            StartSource::SameNodeWarm,
            true,
            PlannedRuntimeActivationKind::WarmRestore,
        ));
        assert!(!activation_kind_is_exact_for_source(
            StartSource::SameNodeWarm,
            true,
            PlannedRuntimeActivationKind::Fresh,
        ));
        assert!(activation_kind_is_exact_for_source(
            StartSource::SameNodeRetry,
            true,
            PlannedRuntimeActivationKind::WarmRestore,
        ));
        assert!(!activation_kind_is_exact_for_source(
            StartSource::SameNodeRetry,
            true,
            PlannedRuntimeActivationKind::Fresh,
        ));
        assert!(activation_kind_is_exact_for_source(
            StartSource::SameNodeRetry,
            false,
            PlannedRuntimeActivationKind::Fresh,
        ));
    }

    #[test]
    fn managed_identity_conflict_does_not_touch_sibling() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("network/reservation.json");
        let sibling = root.path().join("network/sibling.json");
        publish_exact_managed_file(root.path(), &target, b"old", 0o600).unwrap();
        publish_exact_managed_file(root.path(), &sibling, b"sibling", 0o600).unwrap();
        assert_eq!(
            inspect_exact_managed_file(root.path(), &target, b"new", 0o600).unwrap(),
            ManagedFileInspection::Conflict
        );
        assert_eq!(fs::read(&sibling).unwrap(), b"sibling");
    }

    #[test]
    fn network_predecessor_replacement_is_atomic_and_response_loss_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("network/reservation.json");
        let replacement = root.path().join("network/replacement.json");
        let sibling = root.path().join("network/sibling.json");
        publish_exact_managed_file(root.path(), &target, b"predecessor", 0o600).unwrap();
        publish_exact_managed_file(root.path(), &replacement, b"successor", 0o600).unwrap();
        publish_exact_managed_file(root.path(), &sibling, b"sibling", 0o600).unwrap();

        replace_exact_managed_file(
            root.path(),
            &target,
            b"predecessor",
            &replacement,
            b"successor",
            0o600,
        )
        .unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"successor");
        assert!(!replacement.exists());
        assert_eq!(fs::read(&sibling).unwrap(), b"sibling");
        assert_eq!(
            inspect_exact_managed_file(root.path(), &target, b"successor", 0o600).unwrap(),
            ManagedFileInspection::Exact
        );

        let conflicting_target = root.path().join("network/conflicting.json");
        let conflicting_replacement = root.path().join("network/conflicting-replacement.json");
        publish_exact_managed_file(root.path(), &conflicting_target, b"predecessor", 0o600)
            .unwrap();
        publish_exact_managed_file(root.path(), &conflicting_replacement, b"foreign", 0o600)
            .unwrap();
        assert!(replace_exact_managed_file(
            root.path(),
            &conflicting_target,
            b"predecessor",
            &conflicting_replacement,
            b"successor",
            0o600,
        )
        .is_err());
        assert_eq!(fs::read(&conflicting_target).unwrap(), b"predecessor");
        assert_eq!(fs::read(&sibling).unwrap(), b"sibling");
    }
}
