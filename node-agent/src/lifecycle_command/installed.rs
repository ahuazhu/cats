//! Installed atomic-lifecycle effects.
//!
//! This adapter owns real Host effects.  It never converts an unavailable or
//! ambiguous probe into success: every successful Stop is backed by the
//! durable journal fence, the shared lifecycle/Route admission cell, exact
//! absence of the deterministic Cat parent slice, and a fresh frontend
//! postcondition.  The remaining lifecycle commands use the same
//! checkpoint-first step vocabulary; transitions whose volume/VMM evidence is
//! not yet sufficient remain durably unresolved instead of manufacturing a
//! terminal result.

mod cold_delete;
mod common;
mod inventory;
mod start;
mod start_adapter;
mod start_platform;
mod strong_stop;
mod suspend_warm;

pub use cold_delete::{
    AtomicColdDeleteLocalPort, AtomicColdDeletePort, InstalledAtomicColdDeletePort,
    InstalledColdDeleteLocalPort,
};
pub use start::{
    atomic_start_launch_volume_id, atomic_start_platform_receipt_digest,
    AtomicStartDefiniteFailure, AtomicStartRuntimeContext, AtomicStartRuntimeEffectOutcome,
    AtomicStartRuntimeEffectPhase, AtomicStartRuntimeEffectReceipt,
    AtomicStartRuntimeEffectRequest, AtomicStartRuntimePort, AtomicStartRuntimeReadyEvidence,
    AtomicStartVolumeAction, AtomicStartVolumeBatchReceipt, AtomicStartVolumeBatchRequest,
    AtomicStartVolumeGrant, AtomicStartVolumeOutcome, AtomicStartVolumePort,
    InstalledRuntimeBlockFrontend, InstalledRuntimeManifest, InstalledRuntimeNetworkManifest,
    InstalledRuntimeProcessIdentity, InstalledRuntimeProgressManifest,
    InstalledRuntimeProgressVolumeManifest, InstalledRuntimeVmmManifest,
    InstalledRuntimeVolumeManifest,
};
pub use start_adapter::InstalledAtomicStartVolumePort;
pub use start_platform::{
    installed_atomic_start_runtime_port, InstalledAtomicStartBlockdConfig,
    InstalledAtomicStartObjectWriteMode, InstalledAtomicStartRuntimeConfig,
};
pub use suspend_warm::{
    InstalledSuspendWarmPlatform, WarmMemoryFileProof, WarmSnapshotCleanupAttempt,
    WarmSnapshotCleanupAuthority, WarmSnapshotCleanupCompletion, WarmSnapshotCleanupMode,
    WarmSnapshotCleanupRequest,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::runtime_inventory::{
    ObservedArtifactClassification, ObservedCatRuntimeTelemetry, ObservedRuntimeCondition,
    ObservedRuntimeConditionKind, ObservedRuntimePhysicalState, ObservedVolumeAttachment,
    ObservedVolumeWatermark,
};
use cats_api::runtime_lifecycle::{
    lifecycle_terminal_result_digest, validate_lifecycle_successor,
    EffectiveRuntimeReady as WireEffectiveRuntimeReady, ExecutionAbsenceProof, KilledResult,
    LifecycleCommand, LifecycleCommandEnvelope, LifecycleCommandKind, LifecycleCommandResponse,
    LifecyclePredecessor, LifecycleTerminalResult, NodeResult, PlacementIdentity, RetainedEvidence,
    RuntimeNetworkConfig, RuntimeReadyResult, TerminalResultKind, VolumeTerminalReceipt,
};
use cats_api::runtime_reconciliation::{
    AcquireOrigin, HostPath, Id, LastVolumeTransition, RandomId128, RemoteHead, SessionBinding,
    Sha256Digest, UnixMillis,
};
use cats_storage::authority::{
    validate_volume_owner_binding, validate_volume_record, AttachmentLineageIdentity,
    RuntimeVolumeInventoryAuthority,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::admission::EffectiveRuntimeReady as AdmissionRuntimeReady;
use crate::admission::LifecycleCloseOutcome;
use crate::admission_registry::LifecycleAdmissionRegistry;
use crate::cat_execution_scope::{cat_execution_slice_control_group, cat_execution_slice_id};
use crate::runtime_inventory::{
    observed_command_journal_record, RuntimeFullInventoryScan, RuntimeInventoryCollectionPort,
    RuntimeInventoryForceFullCoordinator, RuntimePartialInventoryContext,
    RuntimePartialInventoryScan, StartupInventoryCache,
};
use crate::state_directory::StateDirectory;

use super::executor::{
    AtomicLifecycleEffectPort, AtomicLifecycleExecutor, LifecycleEffectAuthority,
    LifecycleEffectProgress, LifecyclePhysicalInventoryPort, PlannedLifecycleEffect,
};
use super::journal::{
    enumerate_startup_in_state_directory, ExactBytes, ExecutionStep, LifecycleJournalRecord,
    LifecycleJournalStartupInventory, QuarantinedStartupJournalEntry,
    QuarantinedTerminalStartupCat, StartupPhysicalInventory,
};
use super::runner::LifecycleCommandExecutor;
use super::runner::LifecyclePhysicalInventorySnapshot;
use super::strong_stop::{
    DedicatedCatExecutionScope, DedicatedExecutionScopePort, ExecutionScopeAbsenceReceipt,
    ExecutionScopeInventory, FrontendAbsenceReceipt, FrontendInventory, GracefulShutdownPort,
    GuestFrontendPort, ObservedExecutionScope, StrongStopPortError, StrongStopPorts,
};

const STEP_STRONG_STOP: &str = "atomic_strong_stop";
const STOP_FENCE_DOMAIN: &[u8] = b"cats.atomic-lifecycle.installed-stop-fence.v1";
const STOP_FENCE_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.stop-fence-receipt.v1";
const ADMISSION_CLOSE_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.admission-close-receipt.v1";
const SCOPE_ABSENCE_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.scope-absence-receipt.v1";
const FRONTEND_ABSENCE_RECEIPT_DOMAIN: &[u8] = b"cats.atomic-lifecycle.frontend-absence-receipt.v1";
const INVENTORY_DIGEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.physical-inventory.v1";
const STOP_PREDECESSOR_PHYSICAL_DOMAIN: &[u8] =
    b"cats.atomic-lifecycle.stop-predecessor-physical.v1";
const COMMAND_OUTPUT_MAX_BYTES: usize = 64 * 1024;
const STOP_STEP_MAX_BYTES: usize = 4 * 1024 * 1024;
const CGROUP_ENTRY_LIMIT: usize = 65_536;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Installed kernel-NBD coordinates.  The configured pool is always scanned
/// completely; a configured device with no attributable live client is
/// ambiguous residue, never a free slot or another Cat's frontend.
#[derive(Debug, Clone)]
pub struct InstalledLifecycleKernelNbdConfig {
    pub sys_block_root: PathBuf,
    pub device_root: PathBuf,
    pub nbd_client_binary: PathBuf,
    pub device_count: u32,
}

/// Immutable Host coordinates shared by every installed physical inspector.
///
/// This is deliberately separate from the lifecycle effect ports: inventory,
/// Suspend/Warm, and Start postcondition discovery may retain the same clone
/// without depending on the full executor composition or constructing a
/// second authority registry.
#[derive(Clone)]
pub struct InstalledPhysicalInspectionConfig {
    pub state_directory: StateDirectory,
    pub node_id: Id,
    pub volume_inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority>,
    pub systemctl_binary: PathBuf,
    pub cgroup_root: PathBuf,
    pub proc_root: PathBuf,
    pub ip_binary: PathBuf,
    pub network_class_root: PathBuf,
    pub managed_socket_roots: Vec<PathBuf>,
    pub managed_process_binaries: BTreeSet<PathBuf>,
    pub kernel_nbd: Option<InstalledLifecycleKernelNbdConfig>,
    pub inventory_timeout: Duration,
    pub physical_probe_timeout: Duration,
}

impl InstalledPhysicalInspectionConfig {
    /// Close the configured process allow-set over provider-selected helper
    /// binaries. Every production consumer calls this on its own retained
    /// clone so inventory, Suspend/Warm, Start, and strong Stop cannot disagree
    /// about whether a kernel-NBD client belongs in a Cat parent slice.
    pub(crate) fn include_provider_process_binaries(&mut self) {
        if let Some(kernel) = &self.kernel_nbd {
            self.managed_process_binaries
                .insert(kernel.nbd_client_binary.clone());
        }
    }
}

/// Fixed Host coordinates needed by the production lifecycle adapter.
/// Callers obtain these from the installed release/Node configuration; the
/// adapter does not infer binaries or mutable roots from PATH/environment.
#[derive(Clone)]
pub struct InstalledAtomicLifecycleConfig {
    pub physical: InstalledPhysicalInspectionConfig,
    pub admission_registry: Arc<LifecycleAdmissionRegistry>,
    pub startup_inventory_cache: Arc<StartupInventoryCache>,
    pub start_volume_port: Arc<dyn AtomicStartVolumePort>,
    pub start_runtime_port: Arc<dyn AtomicStartRuntimePort>,
    pub suspend_warm_platform: InstalledSuspendWarmPlatform,
    pub cold_delete_port: Arc<dyn AtomicColdDeletePort>,
    /// The exact coordinator also owned by the sole RuntimeInventoryRunner.
    /// Cold/Delete may synchronously request a post-Stop Full through this
    /// handle; no lifecycle adapter constructs or posts telemetry itself.
    pub runtime_inventory_force_full: Arc<RuntimeInventoryForceFullCoordinator>,
}

impl std::ops::Deref for InstalledAtomicLifecycleConfig {
    type Target = InstalledPhysicalInspectionConfig;

    fn deref(&self) -> &Self::Target {
        &self.physical
    }
}

/// Exact installed composition shared by lifecycle startup, Route admission,
/// and the independent observation-only inventory sender.
pub struct InstalledAtomicLifecycle {
    pub executor: Arc<dyn LifecycleCommandExecutor>,
    pub inventory_collection: Arc<dyn RuntimeInventoryCollectionPort>,
    pub startup_inventory_cache: Arc<StartupInventoryCache>,
    pub admission_registry: Arc<LifecycleAdmissionRegistry>,
    pub runtime_inventory_force_full: Arc<RuntimeInventoryForceFullCoordinator>,
}

/// Compose the concrete complete-inventory and physical-effect ports used by
/// `LifecycleCommandRunner`.  The registry Arc is caller-owned and is the
/// exact same value later supplied to Route v2.
pub fn installed_atomic_lifecycle_executor(
    mut config: InstalledAtomicLifecycleConfig,
) -> Result<InstalledAtomicLifecycle> {
    config.physical.include_provider_process_binaries();
    validate_config(&config)?;
    let observed_frontends = Arc::new(Mutex::new(BTreeMap::new()));
    let scope = Arc::new(InstalledCatExecutionScopePort {
        systemctl_binary: config.systemctl_binary.clone(),
        cgroup_root: config.cgroup_root.clone(),
        proc_root: config.proc_root.clone(),
        managed_process_binaries: config.managed_process_binaries.clone(),
        kernel_nbd: config.kernel_nbd.clone(),
        observed_frontends: Arc::clone(&observed_frontends),
        probe_timeout: config.physical_probe_timeout,
    });
    let frontends = Arc::new(InstalledGuestFrontendPort {
        scope: Arc::clone(&scope),
        kernel_nbd: config.kernel_nbd.clone(),
        observed_frontends: Arc::clone(&observed_frontends),
        probe_timeout: config.physical_probe_timeout,
    });
    let ports = StrongStopPorts::new(
        Arc::clone(&scope) as Arc<dyn GracefulShutdownPort>,
        Arc::clone(&scope) as Arc<dyn DedicatedExecutionScopePort>,
        frontends as Arc<dyn GuestFrontendPort>,
    );
    let startup_inventory_cache = Arc::clone(&config.startup_inventory_cache);
    let admission_registry = Arc::clone(&config.admission_registry);
    let runtime_inventory_force_full = Arc::clone(&config.runtime_inventory_force_full);
    let context =
        common::InstalledLifecycleContext::new(config.clone(), ports.clone(), observed_frontends);
    let adapter = Arc::new(InstalledAtomicLifecycleAdapter { config, context });
    let executor = AtomicLifecycleExecutor::new(
        Arc::clone(&adapter) as Arc<dyn LifecyclePhysicalInventoryPort>,
        Arc::clone(&adapter) as Arc<dyn AtomicLifecycleEffectPort>,
    );
    Ok(InstalledAtomicLifecycle {
        executor,
        inventory_collection: adapter as Arc<dyn RuntimeInventoryCollectionPort>,
        startup_inventory_cache,
        admission_registry,
        runtime_inventory_force_full,
    })
}

fn validate_config(config: &InstalledAtomicLifecycleConfig) -> Result<()> {
    for (label, path) in [
        ("state directory", config.state_directory.path()),
        ("systemctl binary", config.systemctl_binary.as_path()),
        ("cgroup root", config.cgroup_root.as_path()),
        ("proc root", config.proc_root.as_path()),
        ("ip binary", config.ip_binary.as_path()),
        ("network class root", config.network_class_root.as_path()),
    ] {
        anyhow::ensure!(
            path.is_absolute(),
            "installed lifecycle {label} is not absolute"
        );
    }
    anyhow::ensure!(
        !config.inventory_timeout.is_zero() && !config.physical_probe_timeout.is_zero(),
        "installed lifecycle deadlines must be positive"
    );
    anyhow::ensure!(
        !config.managed_process_binaries.is_empty()
            && config
                .managed_process_binaries
                .iter()
                .all(|path| path.is_absolute()),
        "installed lifecycle managed binaries must be a nonempty absolute set"
    );
    anyhow::ensure!(
        !config.managed_socket_roots.is_empty()
            && config
                .managed_socket_roots
                .iter()
                .all(|path| path.is_absolute() && path.components().count() > 1),
        "installed lifecycle managed socket roots must be nonempty narrow absolute paths"
    );
    if let Some(kernel) = &config.kernel_nbd {
        anyhow::ensure!(
            kernel.sys_block_root.is_absolute()
                && kernel.device_root.is_absolute()
                && kernel.nbd_client_binary.is_absolute()
                && kernel.device_count > 0,
            "installed lifecycle kernel-NBD configuration is invalid"
        );
    }
    Ok(())
}

struct InstalledAtomicLifecycleAdapter {
    config: InstalledAtomicLifecycleConfig,
    context: common::InstalledLifecycleContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservedFrontend {
    KernelNbd { device_path: PathBuf },
    VhostUserBlk { socket_path: PathBuf },
}

struct InstalledCatExecutionScopePort {
    systemctl_binary: PathBuf,
    cgroup_root: PathBuf,
    proc_root: PathBuf,
    managed_process_binaries: BTreeSet<PathBuf>,
    kernel_nbd: Option<InstalledLifecycleKernelNbdConfig>,
    observed_frontends: Arc<Mutex<BTreeMap<Id, Vec<ObservedFrontend>>>>,
    probe_timeout: Duration,
}

struct InstalledGuestFrontendPort {
    scope: Arc<InstalledCatExecutionScopePort>,
    kernel_nbd: Option<InstalledLifecycleKernelNbdConfig>,
    observed_frontends: Arc<Mutex<BTreeMap<Id, Vec<ObservedFrontend>>>>,
    probe_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledStepPayload {
    version: u64,
    command_kind: LifecycleCommandKind,
    operation_id: Id,
    request_fingerprint: Sha256Digest,
}

/// Exact predecessor-owned physical attribution frozen in the Stop journal
/// before the fence can authorize any Host mutation. The source carrier is
/// retained as well as its flat Volume projection so replay can purely
/// revalidate every field without rediscovering a predecessor that StrongStop
/// may already have destroyed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopPredecessorPhysical {
    version: u64,
    target_operation_id: Id,
    target_request_fingerprint: Sha256Digest,
    target_runtime_config_id: Id,
    target_runtime_config_digest: Sha256Digest,
    predecessor_operation_id: Id,
    predecessor_request_fingerprint: Sha256Digest,
    predecessor_terminal_result_kind: TerminalResultKind,
    predecessor_terminal_result_digest: Sha256Digest,
    physical_manifest_digest: Sha256Digest,
    runtime_incarnation: Option<RandomId128>,
    volumes: Vec<StopPredecessorVolume>,
    source: StopPredecessorSource,
    carrier_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopPredecessorVolume {
    volume_id: Id,
    disk_id: Id,
    disk_role: cats_api::runtime_lifecycle::DiskRole,
    attachment_id: Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    acquire_origin: AcquireOrigin,
    authoritative_head: RemoteHead,
    immutable_start_grant_receipt_digest: Sha256Digest,
    local_lineage_data_directory: Option<HostPath>,
    predecessor_receipt: VolumeTerminalReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum StopPredecessorSource {
    SuspendWarm(Box<suspend_warm::SameNodeOwnedPredecessorPhysical>),
    StartFailed {
        manifest: Box<start::TerminalRetainedRuntimeManifest>,
        retained_warm_cleanup_authority: Option<Box<suspend_warm::WarmSnapshotCleanupAuthority>>,
    },
    RetainedTerminal {
        retained_evidence: RetainedEvidence,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledStopStepPayload {
    binding: InstalledStepPayload,
    predecessor_physical: StopPredecessorPhysical,
}

impl InstalledStepPayload {
    fn from_command(command: &LifecycleCommandEnvelope) -> Self {
        Self {
            version: 1,
            command_kind: command.command_kind(),
            operation_id: command.operation_id.clone(),
            request_fingerprint: command.request_fingerprint.clone(),
        }
    }

    fn validate(&self, command: &LifecycleCommandEnvelope) -> Result<()> {
        anyhow::ensure!(
            self.version == 1
                && self.command_kind == command.command_kind()
                && self.operation_id == command.operation_id
                && self.request_fingerprint == command.request_fingerprint,
            "installed lifecycle durable step belongs to another command"
        );
        Ok(())
    }
}

fn execution_step(
    name: &str,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    predecessor_physical: StopPredecessorPhysical,
) -> Result<ExecutionStep> {
    validate_stop_predecessor_physical(command, predecessor, &predecessor_physical)?;
    let value = serde_json::to_value(&InstalledStopStepPayload {
        binding: InstalledStepPayload::from_command(command),
        predecessor_physical,
    })
    .context("encode installed lifecycle recovery step")?;
    let payload = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    anyhow::ensure!(
        !payload.is_empty() && payload.len() <= STOP_STEP_MAX_BYTES,
        "installed Stop durable step exceeds its byte cap"
    );
    Ok(ExecutionStep {
        name: Id::new(name).context("installed lifecycle step name is invalid")?,
        recovery_payload: ExactBytes::new(payload),
    })
}

fn decode_step(
    step: &ExecutionStep,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
) -> Result<StopPredecessorPhysical> {
    anyhow::ensure!(
        !step.recovery_payload.as_slice().is_empty()
            && step.recovery_payload.as_slice().len() <= STOP_STEP_MAX_BYTES,
        "installed Stop durable step has an invalid size"
    );
    let value: serde_json::Value = serde_json::from_slice(step.recovery_payload.as_slice())
        .context("decode installed lifecycle recovery step JSON")?;
    anyhow::ensure!(
        cats_api::runtime_reconciliation::canonical_json_value_bytes(&value)
            == step.recovery_payload.as_slice(),
        "installed Stop durable step is not canonical JSON"
    );
    let payload: InstalledStopStepPayload =
        serde_json::from_value(value).context("decode installed lifecycle recovery step")?;
    payload.binding.validate(command)?;
    validate_stop_predecessor_physical(command, predecessor, &payload.predecessor_physical)?;
    Ok(payload.predecessor_physical)
}

fn stop_fence_payload(command: &LifecycleCommandEnvelope) -> Result<ExactBytes> {
    let canonical = serde_json::to_vec(&InstalledStepPayload::from_command(command))
        .context("encode installed Stop fence binding")?;
    let mut bytes = Vec::with_capacity(STOP_FENCE_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(STOP_FENCE_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(ExactBytes::new(bytes))
}

fn inspect_stop_predecessor_physical(
    ctx: &common::InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
) -> Result<StopPredecessorPhysical> {
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(predecessor.clone()),
    };
    validate_lifecycle_successor(Some(&terminal), command)
        .context("validate Stop predecessor before physical inspection")?;
    anyhow::ensure!(
        matches!(command.command, LifecycleCommand::Stop(_)),
        "predecessor carrier may be frozen only for Stop"
    );
    let terminal_result_digest = lifecycle_terminal_result_digest(&terminal)
        .context("digest exact Stop predecessor terminal result")?;

    let (physical_manifest_digest, runtime_incarnation, volumes, source) = match &predecessor.result
    {
        NodeResult::RuntimeReady(_)
        | NodeResult::SuspendDeclined(_)
        | NodeResult::Suspended(_)
        | NodeResult::Warm(_)
        | NodeResult::SuspendFailed(_)
        | NodeResult::WarmFailed(_) => {
            let physical = ctx
                .config()
                .suspend_warm_platform
                .inspect_same_node_owned_predecessor(command, predecessor)
                .context("inspect exact Suspend/Warm-family Stop predecessor")?;
            suspend_warm::validate_same_node_owned_predecessor_physical(
                command,
                predecessor,
                &physical,
            )?;
            let volumes = stop_volumes_from_suspend_warm(&physical)?;
            (
                physical.physical_manifest_digest.clone(),
                physical.runtime_incarnation.clone(),
                volumes,
                StopPredecessorSource::SuspendWarm(Box::new(physical)),
            )
        }
        NodeResult::StartFailed(failed) => {
            let mut manifests =
                start::enumerate_terminal_retained_runtime_manifests(ctx.state_directory())?
                    .into_iter()
                    .filter(|manifest| {
                        manifest.cat_id == command.cat_id
                            && manifest.source_lifecycle_operation_id == predecessor.operation_id
                    })
                    .collect::<Vec<_>>();
            anyhow::ensure!(
                manifests.len() == 1,
                "Stop lacks one exact terminal-retained StartFailed carrier"
            );
            let manifest = manifests
                .pop()
                .context("terminal-retained StartFailed carrier disappeared")?;
            start::validate_terminal_retained_runtime_manifest(&manifest, None)?;
            anyhow::ensure!(
                manifest.manifest_digest == failed.retained_evidence.artifact_manifest_digest
                    && manifest.source_lifecycle_operation_id == predecessor.operation_id
                    && manifest.request_fingerprint == predecessor.request_fingerprint
                    && manifest.node_id == command.node_id
                    && manifest.cat_id == command.cat_id
                    && manifest.placement_identity == command.placement_identity
                    && manifest.runtime_config_id == command.runtime_config.config_id
                    && manifest.runtime_config_digest == command.runtime_config.config_digest,
                "Stop StartFailed carrier changed terminal or immutable runtime identity"
            );
            let volumes = stop_volumes_from_start_retained(&manifest)?;
            let runtime_incarnation = match &manifest.retention_mode {
                start::TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } => {
                    evidence.predecessor_runtime_incarnation.clone()
                }
                start::TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
                | start::TerminalRetainedRuntimeMode::MaterializedOrAmbiguous => {
                    Some(manifest.runtime_incarnation.clone())
                }
            };
            let retained_warm_cleanup_authority = manifest
                .retained_warm_restart_source
                .as_deref()
                .map(|carrier| {
                    suspend_warm::rebind_retained_warm_for_removal(
                        command,
                        predecessor,
                        &manifest.manifest_digest,
                        Some(carrier),
                    )
                    .and_then(|authority| {
                        validate_start_failed_warm_stop_cleanup_authority(
                            command,
                            predecessor,
                            &manifest.manifest_digest,
                            carrier,
                            &authority,
                        )?;
                        Ok(Box::new(authority))
                    })
                })
                .transpose()?;
            (
                manifest.manifest_digest.clone(),
                runtime_incarnation,
                volumes,
                StopPredecessorSource::StartFailed {
                    manifest: Box::new(manifest),
                    retained_warm_cleanup_authority,
                },
            )
        }
        NodeResult::Killed(killed) => {
            let volumes = inspect_retained_terminal_stop_volumes(
                ctx.config(),
                command,
                &killed.retained_volume_receipts,
                &killed.retained_evidence,
            )?;
            (
                killed.retained_evidence.artifact_manifest_digest.clone(),
                killed.stopped_runtime_incarnation.clone(),
                volumes,
                StopPredecessorSource::RetainedTerminal {
                    retained_evidence: killed.retained_evidence.clone(),
                },
            )
        }
        NodeResult::NeedsIntervention(intervention) => {
            let volumes = inspect_retained_terminal_stop_volumes(
                ctx.config(),
                command,
                &intervention.retained_volume_receipts,
                &intervention.retained_evidence,
            )?;
            (
                intervention
                    .retained_evidence
                    .artifact_manifest_digest
                    .clone(),
                None,
                volumes,
                StopPredecessorSource::RetainedTerminal {
                    retained_evidence: intervention.retained_evidence.clone(),
                },
            )
        }
        NodeResult::Cold(_) | NodeResult::Deleted(_) => {
            anyhow::bail!("Stop predecessor has no reachable exact retained carrier")
        }
    };
    let mut carrier = StopPredecessorPhysical {
        version: 1,
        target_operation_id: command.operation_id.clone(),
        target_request_fingerprint: command.request_fingerprint.clone(),
        target_runtime_config_id: command.runtime_config.config_id.clone(),
        target_runtime_config_digest: command.runtime_config.config_digest.clone(),
        predecessor_operation_id: predecessor.operation_id.clone(),
        predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
        predecessor_terminal_result_kind: predecessor.result.kind(),
        predecessor_terminal_result_digest: terminal_result_digest,
        physical_manifest_digest,
        runtime_incarnation,
        volumes,
        source,
        carrier_digest: Sha256Digest::from_bytes([0; 32]),
    };
    carrier.carrier_digest = stop_predecessor_physical_digest(&carrier)?;
    validate_stop_predecessor_physical(command, predecessor, &carrier)?;
    Ok(carrier)
}

fn stop_volumes_from_suspend_warm(
    physical: &suspend_warm::SameNodeOwnedPredecessorPhysical,
) -> Result<Vec<StopPredecessorVolume>> {
    let receipts = physical.volume_receipts();
    anyhow::ensure!(
        receipts.len() == physical.volumes.len(),
        "Suspend/Warm Stop carrier changed its complete Volume receipt set"
    );
    physical
        .volumes
        .iter()
        .zip(receipts)
        .map(|(volume, receipt)| {
            anyhow::ensure!(
                receipt.volume_id == volume.volume_id
                    && receipt.disk_id == volume.disk_id
                    && receipt.disk_role == volume.disk_role
                    && receipt.attachment_id == volume.attachment_id
                    && receipt.attachment_epoch == volume.attachment_epoch
                    && receipt.authority_receipt_digest.as_ref()
                        == Some(&volume.immutable_start_grant_receipt_digest),
                "Suspend/Warm Stop carrier Volume receipt changed identity or StartGrant"
            );
            Ok(StopPredecessorVolume {
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
                local_lineage_data_directory: volume.local_lineage_data_directory.clone(),
                predecessor_receipt: receipt.clone(),
            })
        })
        .collect()
}

fn stop_volumes_from_start_retained(
    manifest: &start::TerminalRetainedRuntimeManifest,
) -> Result<Vec<StopPredecessorVolume>> {
    let physical = start::terminal_retained_physical_volumes(manifest)?;
    anyhow::ensure!(
        physical.len() == manifest.retained_volume_receipts.len(),
        "StartFailed Stop carrier changed its retained Volume set"
    );
    physical
        .into_iter()
        .zip(&manifest.retained_volume_receipts)
        .map(|(volume, receipt)| {
            anyhow::ensure!(
                receipt.volume_id == volume.volume_id
                    && receipt.disk_id == volume.disk_id
                    && receipt.disk_role == volume.disk_role
                    && receipt.attachment_id == volume.attachment_id
                    && receipt.attachment_epoch == volume.attachment_epoch
                    && receipt.authority_receipt_digest.as_ref()
                        == Some(&volume.immutable_start_grant_receipt_digest),
                "StartFailed Stop carrier Volume changed identity or immutable StartGrant"
            );
            Ok(StopPredecessorVolume {
                volume_id: volume.volume_id,
                disk_id: volume.disk_id,
                disk_role: volume.disk_role,
                attachment_id: volume.attachment_id,
                attachment_epoch: volume.attachment_epoch,
                acquire_origin: volume.acquire_origin,
                authoritative_head: volume.authoritative_head,
                immutable_start_grant_receipt_digest: volume.immutable_start_grant_receipt_digest,
                local_lineage_data_directory: volume.local_lineage_data_directory,
                predecessor_receipt: receipt.clone(),
            })
        })
        .collect()
}

fn inspect_retained_terminal_stop_volumes(
    config: &InstalledAtomicLifecycleConfig,
    command: &LifecycleCommandEnvelope,
    predecessor_receipts: &[VolumeTerminalReceipt],
    predecessor_evidence: &RetainedEvidence,
) -> Result<Vec<StopPredecessorVolume>> {
    anyhow::ensure!(
        predecessor_receipts
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "retained terminal Stop predecessor receipts are not strictly sorted"
    );
    let physical_scan = scan_startup_inventory(config)
        .context("scan exact retained terminal before planning Stop")?;
    // This proof is discarded here, but computing it enforces that the
    // predecessor has no executable/adoptable restart source before its
    // journal carrier is accepted.
    inventory::installed_restart_source_absence_receipt_digest(
        command,
        &command.request_fingerprint,
        &physical_scan,
    )?;
    let (fresh_evidence, _) =
        strong_stop::retained_inventory_evidence(command, &physical_scan, false)?;
    anyhow::ensure!(
        &fresh_evidence == predecessor_evidence,
        "retained terminal physical artifacts changed since the immediate predecessor"
    );

    let candidates = command
        .runtime_config
        .volumes
        .iter()
        .map(|volume| volume.volume_id.clone())
        .collect::<BTreeSet<_>>();
    let snapshot = config
        .volume_inventory_authority
        .load_node_volume_inventory(&config.node_id, &candidates)
        .context("load exact retained terminal Volume authority")?;
    anyhow::ensure!(
        snapshot.node_id == config.node_id,
        "retained terminal Volume authority belongs to another Node"
    );
    let physical = retained_volume_physical_evidence(config, command)?;
    let expected = predecessor_receipts
        .iter()
        .map(|receipt| (receipt.volume_id.clone(), receipt))
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        expected.len() == predecessor_receipts.len(),
        "retained terminal Stop predecessor repeats a Volume receipt"
    );
    let mut seen = BTreeSet::new();
    let mut volumes = Vec::new();
    for row in &snapshot.records {
        validate_volume_record(&row.volume)
            .context("validate retained terminal Stop Volume authority")?;
        anyhow::ensure!(
            seen.insert(row.volume.volume_id.clone()),
            "retained terminal Stop Volume authority repeats a row"
        );
        if !candidates.contains(&row.volume.volume_id) {
            continue;
        }
        let Some(binding) = row.binding.as_ref() else {
            anyhow::ensure!(
                !expected.contains_key(&row.volume.volume_id)
                    && row.volume.lease_owner.is_none()
                    && row.volume.lease_expires_at.is_none(),
                "retained terminal predecessor attachment became ambiguously Unowned"
            );
            continue;
        };
        validate_volume_owner_binding(binding, &row.volume)?;
        let receipt = expected
            .get(&row.volume.volume_id)
            .context("current Owned Volume is absent from immediate predecessor receipts")?;
        let installed = physical
            .get(&row.volume.volume_id)
            .context("retained terminal predecessor Volume lacks exact installed lineage")?;
        let configured = command
            .runtime_config
            .volumes
            .iter()
            .find(|volume| volume.volume_id == row.volume.volume_id)
            .context("retained terminal Volume is outside immutable config")?;
        let grant_digest = receipt
            .authority_receipt_digest
            .as_ref()
            .context("retained terminal predecessor receipt lacks immutable StartGrant")?;
        anyhow::ensure!(
            binding.owner_node_id == command.node_id
                && binding.attachment_id == receipt.attachment_id
                && binding.attachment_epoch == receipt.attachment_epoch
                && installed.disk_id == configured.disk_id
                && installed.disk_role == configured.disk_role
                && installed.attachment_id == receipt.attachment_id
                && installed.attachment_epoch == receipt.attachment_epoch
                && installed.authority_receipt_digest == *grant_digest
                && installed.acquire_origin == authority_acquire_origin(&row.volume)?
                && receipt.disk_id == configured.disk_id
                && receipt.disk_role == configured.disk_role
                && receipt.remote_durable_generation <= row.volume.head.generation
                && row.volume.head.generation <= receipt.local_durable_generation,
            "retained terminal predecessor changed config, owner, grant, origin, or head"
        );
        volumes.push(StopPredecessorVolume {
            volume_id: receipt.volume_id.clone(),
            disk_id: receipt.disk_id.clone(),
            disk_role: receipt.disk_role,
            attachment_id: receipt.attachment_id.clone(),
            attachment_epoch: receipt.attachment_epoch,
            acquire_origin: installed.acquire_origin.clone(),
            authoritative_head: row.volume.head.clone(),
            immutable_start_grant_receipt_digest: grant_digest.clone(),
            local_lineage_data_directory: Some(
                HostPath::new(installed.local_lineage_data_directory.to_string_lossy())
                    .context("retained terminal lineage path is not a valid HostPath")?,
            ),
            predecessor_receipt: (*receipt).clone(),
        });
    }
    anyhow::ensure!(
        candidates.iter().all(|volume_id| seen.contains(volume_id))
            && volumes.len() == predecessor_receipts.len(),
        "retained terminal Stop authority omitted a configured or predecessor Volume"
    );
    volumes.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    Ok(volumes)
}

fn validate_stop_predecessor_physical(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    carrier: &StopPredecessorPhysical,
) -> Result<()> {
    let terminal = LifecycleTerminalResult::NodeResult {
        response: Box::new(predecessor.clone()),
    };
    validate_lifecycle_successor(Some(&terminal), command)
        .context("validate persisted Stop predecessor")?;
    let actual_terminal_digest = lifecycle_terminal_result_digest(&terminal)?;
    let LifecyclePredecessor::SameNode {
        operation_id,
        terminal_result_kind,
        terminal_result_digest,
        node_id,
        placement_identity,
    } = &command.predecessor
    else {
        anyhow::bail!("Stop predecessor physical carrier is not same-Node")
    };
    anyhow::ensure!(
        matches!(command.command, LifecycleCommand::Stop(_))
            && carrier.version == 1
            && carrier.target_operation_id == command.operation_id
            && carrier.target_request_fingerprint == command.request_fingerprint
            && carrier.target_runtime_config_id == command.runtime_config.config_id
            && carrier.target_runtime_config_digest == command.runtime_config.config_digest
            && carrier.predecessor_operation_id == predecessor.operation_id
            && carrier.predecessor_operation_id == *operation_id
            && carrier.predecessor_request_fingerprint == predecessor.request_fingerprint
            && carrier.predecessor_terminal_result_kind == predecessor.result.kind()
            && carrier.predecessor_terminal_result_kind == *terminal_result_kind
            && carrier.predecessor_terminal_result_digest == actual_terminal_digest
            && carrier.predecessor_terminal_result_digest == *terminal_result_digest
            && predecessor.node_id == *node_id
            && predecessor.node_id == command.node_id
            && predecessor.placement_identity == *placement_identity
            && predecessor.placement_identity == command.placement_identity
            && carrier.physical_manifest_digest.as_bytes() != &[0; 32]
            && carrier.carrier_digest == stop_predecessor_physical_digest(carrier)?
            && carrier
                .volumes
                .windows(2)
                .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "persisted Stop predecessor carrier changed command or terminal identity"
    );

    let (expected_manifest_digest, expected_incarnation, expected_volumes) = match &carrier.source {
        StopPredecessorSource::SuspendWarm(physical) => {
            suspend_warm::validate_same_node_owned_predecessor_physical(
                command,
                predecessor,
                physical,
            )?;
            (
                physical.physical_manifest_digest.clone(),
                physical.runtime_incarnation.clone(),
                stop_volumes_from_suspend_warm(physical)?,
            )
        }
        StopPredecessorSource::StartFailed {
            manifest,
            retained_warm_cleanup_authority,
        } => {
            let NodeResult::StartFailed(failed) = &predecessor.result else {
                anyhow::bail!("persisted StartFailed carrier belongs to another terminal kind")
            };
            start::validate_terminal_retained_runtime_manifest(manifest, None)?;
            anyhow::ensure!(
                manifest.source_lifecycle_operation_id == predecessor.operation_id
                    && manifest.request_fingerprint == predecessor.request_fingerprint
                    && manifest.manifest_digest
                        == failed.retained_evidence.artifact_manifest_digest
                    && manifest.node_id == command.node_id
                    && manifest.cat_id == command.cat_id
                    && manifest.placement_identity == command.placement_identity
                    && manifest.runtime_config_id == command.runtime_config.config_id
                    && manifest.runtime_config_digest == command.runtime_config.config_digest,
                "persisted StartFailed carrier changed terminal or runtime identity"
            );
            match (
                manifest.retained_warm_restart_source.as_deref(),
                retained_warm_cleanup_authority.as_deref(),
            ) {
                (Some(carrier), Some(authority)) => {
                    validate_start_failed_warm_stop_cleanup_authority(
                        command,
                        predecessor,
                        &manifest.manifest_digest,
                        carrier,
                        authority,
                    )?;
                }
                (None, None) => {}
                _ => {
                    anyhow::bail!("persisted StartFailed Warm carrier and removal authority differ")
                }
            }
            let incarnation = match &manifest.retention_mode {
                start::TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } => {
                    evidence.predecessor_runtime_incarnation.clone()
                }
                start::TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation { .. }
                | start::TerminalRetainedRuntimeMode::MaterializedOrAmbiguous => {
                    Some(manifest.runtime_incarnation.clone())
                }
            };
            (
                manifest.manifest_digest.clone(),
                incarnation,
                stop_volumes_from_start_retained(manifest)?,
            )
        }
        StopPredecessorSource::RetainedTerminal { retained_evidence } => {
            let (expected_evidence, expected_incarnation, receipts) = match &predecessor.result {
                NodeResult::Killed(killed) => (
                    &killed.retained_evidence,
                    killed.stopped_runtime_incarnation.clone(),
                    killed.retained_volume_receipts.as_slice(),
                ),
                NodeResult::NeedsIntervention(intervention) => (
                    &intervention.retained_evidence,
                    None,
                    intervention.retained_volume_receipts.as_slice(),
                ),
                _ => anyhow::bail!(
                    "persisted retained-terminal Stop carrier belongs to another terminal kind"
                ),
            };
            anyhow::ensure!(
                retained_evidence == expected_evidence
                    && receipts.iter().eq(carrier
                        .volumes
                        .iter()
                        .map(|volume| &volume.predecessor_receipt)),
                "persisted retained-terminal Stop carrier changed evidence or receipts"
            );
            (
                retained_evidence.artifact_manifest_digest.clone(),
                expected_incarnation,
                carrier.volumes.clone(),
            )
        }
    };
    anyhow::ensure!(
        carrier.physical_manifest_digest == expected_manifest_digest
            && carrier.runtime_incarnation == expected_incarnation
            && carrier.volumes == expected_volumes,
        "persisted Stop predecessor flat projection differs from its exact source carrier"
    );
    for volume in &carrier.volumes {
        let configured = command
            .runtime_config
            .volumes
            .iter()
            .find(|configured| configured.volume_id == volume.volume_id)
            .context("Stop predecessor carrier Volume is outside immutable config")?;
        anyhow::ensure!(
            volume.disk_id == configured.disk_id
                && volume.disk_role == configured.disk_role
                && volume.predecessor_receipt.volume_id == volume.volume_id
                && volume.predecessor_receipt.disk_id == volume.disk_id
                && volume.predecessor_receipt.disk_role == volume.disk_role
                && volume.predecessor_receipt.attachment_id == volume.attachment_id
                && volume.predecessor_receipt.attachment_epoch == volume.attachment_epoch
                && volume.predecessor_receipt.authority_receipt_digest.as_ref()
                    == Some(&volume.immutable_start_grant_receipt_digest)
                && stop_remote_head_valid(&volume.authoritative_head)
                && volume.predecessor_receipt.remote_durable_generation
                    <= volume.authoritative_head.generation
                && volume.authoritative_head.generation
                    <= volume.predecessor_receipt.local_durable_generation
                && (volume.local_lineage_data_directory.is_some()
                    || (volume.predecessor_receipt.local_durable_generation
                        == volume.authoritative_head.generation
                        && volume.predecessor_receipt.remote_durable_generation
                            == volume.authoritative_head.generation)),
            "Stop predecessor carrier Volume changed config, grant, path, or durability"
        );
    }
    Ok(())
}

fn validate_start_failed_warm_stop_cleanup_authority(
    command: &LifecycleCommandEnvelope,
    predecessor: &LifecycleCommandResponse,
    retained_manifest_digest: &Sha256Digest,
    carrier: &suspend_warm::RetainedWarmRestartSourceCarrier,
    authority: &suspend_warm::WarmSnapshotCleanupAuthority,
) -> Result<()> {
    anyhow::ensure!(
        matches!(command.command, LifecycleCommand::Stop(_))
            && matches!(predecessor.result, NodeResult::StartFailed(_)),
        "retained Warm Stop cleanup belongs to another lifecycle edge"
    );
    suspend_warm::validate_retained_warm_removal_authority(
        command,
        predecessor,
        retained_manifest_digest,
        Some(carrier),
        authority,
    )
}

fn stop_predecessor_physical_digest(carrier: &StopPredecessorPhysical) -> Result<Sha256Digest> {
    let mut value = serde_json::to_value(carrier)
        .context("encode Stop predecessor physical carrier for digest")?;
    value
        .as_object_mut()
        .context("Stop predecessor physical carrier is not an object")?
        .remove("carrier_digest");
    let canonical = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    Ok(digest_parts(
        STOP_PREDECESSOR_PHYSICAL_DOMAIN,
        &[&canonical],
    ))
}

impl LifecyclePhysicalInventoryPort for InstalledAtomicLifecycleAdapter {
    fn scan_complete(&self) -> Result<LifecyclePhysicalInventorySnapshot> {
        match inventory::scan_startup_inventory(&self.config) {
            Ok((physical, evidence)) => {
                Ok(LifecyclePhysicalInventorySnapshot::new(physical, evidence))
            }
            Err(error) => Ok(LifecyclePhysicalInventorySnapshot::physical_only(
                StartupPhysicalInventory::Incomplete {
                    reason: format!(
                        "installed atomic lifecycle inventory is incomplete: {error:#}"
                    ),
                },
            )),
        }
    }
}

impl RuntimeInventoryCollectionPort for InstalledAtomicLifecycleAdapter {
    fn collect_full(&self) -> Result<RuntimeFullInventoryScan> {
        collect_joined_full_inventory(&self.config)
    }

    fn collect_partial(
        &self,
        context: &RuntimePartialInventoryContext,
    ) -> Result<RuntimePartialInventoryScan> {
        anyhow::ensure!(
            context
                .full_cat_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "accepted Full Cat identities are not strictly sorted and unique"
        );
        let accepted = context
            .full_cat_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let full = collect_joined_full_inventory(&self.config)?;
        let cats = full
            .cats
            .into_iter()
            .filter(|cat| accepted.contains(&cat.cat_id))
            .collect::<Vec<_>>();
        Ok(RuntimePartialInventoryScan {
            collected_at_unix_ms: full.collected_at_unix_ms,
            cats,
        })
    }
}

impl AtomicLifecycleEffectPort for InstalledAtomicLifecycleAdapter {
    fn bind_startup_inventory(
        &self,
        startup: LifecycleJournalStartupInventory,
        snapshot: &LifecyclePhysicalInventorySnapshot,
    ) -> Result<LifecycleJournalStartupInventory> {
        let evidence = snapshot
            .provider_evidence::<inventory::InstalledStartupPhysicalEvidence>()
            .context("installed startup inventory lost its same-scan provider evidence")?;
        let StartupPhysicalInventory::Complete { scan_id, .. } = snapshot.physical() else {
            anyhow::bail!("installed startup binding requires a complete physical inventory")
        };
        anyhow::ensure!(
            scan_id == &evidence.scan_id,
            "installed startup evidence belongs to another physical scan"
        );

        bind_installed_startup_inventory(startup, &evidence.start_physical)
    }

    fn recover_terminal_admission(
        &self,
        session: &SessionBinding,
        current: &super::journal::StoredLifecycleJournal,
        startup_inventory: &StartupPhysicalInventory,
    ) -> Result<()> {
        let (command, response, terminal_result_digest) = match current.record() {
            LifecycleJournalRecord::Command {
                command,
                state: super::journal::CommandJournalState::Terminal { result, .. },
                ..
            } => (
                command
                    .decode_api()
                    .context("decode terminal command for admission recovery")?,
                result
                    .decode_api()
                    .context("decode terminal result for admission recovery")?,
                result.result_digest().clone(),
            ),
            LifecycleJournalRecord::Command { .. }
            | LifecycleJournalRecord::CompletedDeleteReceipt { .. } => {
                anyhow::bail!("terminal admission recovery lacks an executable terminal journal")
            }
        };
        let physical = exact_recovered_running_projection(&command, &response, startup_inventory)?;
        let (source_operation_id, runtime_incarnation) = match &response.result {
            NodeResult::RuntimeReady(ready) => {
                verify_runtime_ready_physical(physical, ready)?;
                (
                    command.operation_id.clone(),
                    ready.runtime_incarnation.clone(),
                )
            }
            NodeResult::SuspendDeclined(declined) => {
                verify_effective_runtime_ready_physical(
                    physical,
                    &declined.effective_runtime_ready,
                )?;
                (
                    declined
                        .effective_runtime_ready
                        .source_lifecycle_operation_id
                        .clone(),
                    declined.effective_runtime_ready.runtime_incarnation.clone(),
                )
            }
            _ => anyhow::bail!("terminal result cannot reopen RuntimeReady admission"),
        };
        let guest_ipv4 = match &command.runtime_config.network_config {
            RuntimeNetworkConfig::IsolatedIpv4 { guest_ipv4, .. } => guest_ipv4.clone(),
        };
        let ready =
            AdmissionRuntimeReady::new(source_operation_id, runtime_incarnation, guest_ipv4);
        self.config
            .admission_registry
            .recover_verified_runtime_ready(
                session,
                &command.cat_id,
                &command.operation_id,
                &command.request_fingerprint,
                &terminal_result_digest,
                ready,
            )
            .context("publish physically verified recovered RuntimeReady admission")?;
        Ok(())
    }

    fn plan_initial(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor_command: Option<&LifecycleCommandEnvelope>,
        predecessor: Option<&LifecycleCommandResponse>,
        inherited_stop_fence: bool,
    ) -> Result<PlannedLifecycleEffect> {
        match command.command {
            LifecycleCommand::Start(_) => {
                return start::plan(
                    &self.context,
                    command,
                    predecessor_command,
                    predecessor,
                    inherited_stop_fence,
                )
            }
            LifecycleCommand::Suspend(_) | LifecycleCommand::Warm(_) => {
                return suspend_warm::plan(
                    &self.context,
                    command,
                    predecessor,
                    inherited_stop_fence,
                )
            }
            LifecycleCommand::Cold(_) | LifecycleCommand::Delete(_) => {
                return cold_delete::plan(&self.context, command, predecessor, inherited_stop_fence)
            }
            LifecycleCommand::Stop(_) => {}
        }
        let step_name = match command.command {
            LifecycleCommand::Stop(_) => STEP_STRONG_STOP,
            LifecycleCommand::Start(_)
            | LifecycleCommand::Suspend(_)
            | LifecycleCommand::Warm(_)
            | LifecycleCommand::Cold(_)
            | LifecycleCommand::Delete(_) => {
                unreachable!("dedicated installed handler returned above")
            }
        };
        let predecessor = predecessor.context("Stop lacks its exact same-Node predecessor")?;
        let predecessor_physical =
            inspect_stop_predecessor_physical(&self.context, command, predecessor)?;
        let step = execution_step(step_name, command, predecessor, predecessor_physical)?;
        if inherited_stop_fence {
            anyhow::ensure!(
                matches!(command.command, LifecycleCommand::Stop(_)),
                "an inherited Stop fence cannot authorize Start or Suspend"
            );
            return Ok(PlannedLifecycleEffect::inherit_stop_fence(step));
        }
        match command.command {
            LifecycleCommand::Stop(_) => Ok(PlannedLifecycleEffect::install_stop_fence(
                step,
                stop_fence_payload(command)?,
            )),
            LifecycleCommand::Start(_)
            | LifecycleCommand::Suspend(_)
            | LifecycleCommand::Warm(_)
            | LifecycleCommand::Cold(_)
            | LifecycleCommand::Delete(_) => {
                unreachable!("dedicated installed handler returned above")
            }
        }
    }

    fn apply(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor_command: Option<&LifecycleCommandEnvelope>,
        predecessor: Option<&LifecycleCommandResponse>,
        step: &ExecutionStep,
        authority: LifecycleEffectAuthority<'_>,
    ) -> Result<LifecycleEffectProgress> {
        match command.command {
            LifecycleCommand::Start(_) => start::apply(
                &self.context,
                command,
                predecessor_command,
                predecessor,
                step,
                authority,
            ),
            LifecycleCommand::Suspend(_) | LifecycleCommand::Warm(_) => {
                suspend_warm::apply(&self.context, command, predecessor, step, authority)
            }
            LifecycleCommand::Cold(_) | LifecycleCommand::Delete(_) => {
                cold_delete::apply(&self.context, command, predecessor, step, authority)
            }
            LifecycleCommand::Stop(_) => {
                let predecessor =
                    predecessor.context("Stop durable step lost its exact predecessor")?;
                let predecessor_physical = decode_step(step, command, predecessor)?;
                match step.name.as_str() {
                    STEP_STRONG_STOP => self.apply_strong_stop(
                        command,
                        predecessor,
                        &predecessor_physical,
                        authority,
                    ),
                    _ => anyhow::bail!("unknown installed atomic lifecycle durable step"),
                }
            }
        }
    }
}

fn bind_installed_startup_inventory(
    mut startup: LifecycleJournalStartupInventory,
    start_physical: &[start::InstalledStartPhysicalInventoryEntry],
) -> Result<LifecycleJournalStartupInventory> {
    let mut physical_by_cat = BTreeMap::new();
    for entry in start_physical {
        physical_by_cat
            .entry(start_physical_key(entry).0.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }
    let mut recoverable = Vec::with_capacity(startup.recoverable.len());
    for entry in startup.recoverable.drain(..) {
        let physical = physical_by_cat
            .get(&entry.cat_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let binding = bind_startup_entry(&entry.record, physical);
        match binding {
            Ok(()) => recoverable.push(entry),
            Err(error) if startup_record_is_terminal(&entry.record) => {
                if !startup
                    .quarantined_terminals
                    .iter()
                    .any(|terminal| terminal.cat_id == entry.cat_id)
                {
                    startup
                        .quarantined_terminals
                        .push(QuarantinedTerminalStartupCat {
                            cat_id: entry.cat_id.clone(),
                            reason: format!(
                                "installed terminal physical/journal mismatch: {error:#}"
                            ),
                        });
                }
                recoverable.push(entry);
            }
            Err(error) => startup
                .quarantined_commands
                .push(QuarantinedStartupJournalEntry {
                    entry,
                    reason: format!("installed startup physical/journal binding failed: {error:#}"),
                }),
        }
    }
    startup.recoverable = recoverable;
    startup
        .blocked
        .sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
    startup
        .quarantined_commands
        .sort_by(|left, right| left.entry.cat_id.cmp(&right.entry.cat_id));
    startup
        .quarantined_terminals
        .sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
    anyhow::ensure!(
        startup
            .recoverable
            .windows(2)
            .all(|pair| pair[0].cat_id < pair[1].cat_id)
            && startup
                .blocked
                .windows(2)
                .all(|pair| pair[0].cat_id < pair[1].cat_id)
            && startup
                .quarantined_commands
                .windows(2)
                .all(|pair| pair[0].entry.cat_id < pair[1].entry.cat_id)
            && startup.recoverable.iter().all(|recoverable| !startup
                .blocked
                .iter()
                .any(|blocked| blocked.cat_id == recoverable.cat_id))
            && startup.recoverable.iter().all(|recoverable| !startup
                .quarantined_commands
                .iter()
                .any(|quarantined| quarantined.entry.cat_id == recoverable.cat_id))
            && startup.blocked.iter().all(|blocked| !startup
                .quarantined_commands
                .iter()
                .any(|quarantined| quarantined.entry.cat_id == blocked.cat_id))
            && startup
                .quarantined_terminals
                .windows(2)
                .all(|pair| pair[0].cat_id < pair[1].cat_id)
            && startup.quarantined_terminals.iter().all(|terminal| startup
                .recoverable
                .iter()
                .any(|recoverable| recoverable.cat_id == terminal.cat_id)),
        "installed startup binding produced duplicate or overlapping Cats"
    );
    let represented = startup
        .recoverable
        .iter()
        .map(|entry| &entry.cat_id)
        .chain(startup.blocked.iter().map(|entry| &entry.cat_id))
        .chain(
            startup
                .quarantined_commands
                .iter()
                .map(|entry| &entry.entry.cat_id),
        )
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        physical_by_cat
            .keys()
            .all(|cat_id| represented.contains(cat_id)),
        "installed Start physical evidence escaped journal recovery or quarantine"
    );
    Ok(startup)
}

fn start_physical_key(entry: &start::InstalledStartPhysicalInventoryEntry) -> (&Id, &Id) {
    match entry {
        start::InstalledStartPhysicalInventoryEntry::Executing(manifest) => {
            (&manifest.cat_id, &manifest.source_lifecycle_operation_id)
        }
        start::InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest) => {
            (&manifest.cat_id, &manifest.source_lifecycle_operation_id)
        }
    }
}

fn bind_startup_entry(
    record: &LifecycleJournalRecord,
    physical: &[&start::InstalledStartPhysicalInventoryEntry],
) -> Result<()> {
    let LifecycleJournalRecord::Command { command, state, .. } = record else {
        anyhow::ensure!(
            physical.is_empty(),
            "completed Delete receipt still has atomic Start physical evidence"
        );
        return Ok(());
    };
    let command = command
        .decode_api()
        .context("decode startup lifecycle command for physical binding")?;
    let (current, predecessor) = physical
        .iter()
        .copied()
        .partition::<Vec<_>, _>(|entry| start_physical_key(entry).1 == &command.operation_id);
    validate_predecessor_start_physical(record, &command, &predecessor)?;
    if !matches!(command.command, LifecycleCommand::Start(_)) {
        anyhow::ensure!(
            current.is_empty(),
            "non-Start lifecycle command has current-operation atomic Start physical evidence"
        );
        return Ok(());
    }
    let owned = current
        .into_iter()
        .cloned()
        .collect::<Vec<start::InstalledStartPhysicalInventoryEntry>>();
    start::bind_installed_start_physical_to_journal(&command, state, &owned)
        .map(|_| ())
        .context("bind atomic Start physical evidence to exact journal state")
}

fn startup_record_is_terminal(record: &LifecycleJournalRecord) -> bool {
    matches!(
        record,
        LifecycleJournalRecord::Command {
            state: super::journal::CommandJournalState::Terminal { .. },
            ..
        } | LifecycleJournalRecord::CompletedDeleteReceipt { .. }
    )
}

fn validate_predecessor_start_physical(
    record: &LifecycleJournalRecord,
    command: &LifecycleCommandEnvelope,
    physical: &[&start::InstalledStartPhysicalInventoryEntry],
) -> Result<()> {
    if physical.is_empty() {
        return Ok(());
    }
    let predecessor = record
        .decode_predecessor_response()
        .context("decode startup predecessor for retained Start binding")?
        .context("atomic Start physical evidence belongs to no retained predecessor")?;
    let [start::InstalledStartPhysicalInventoryEntry::TerminalRetained(manifest)] = physical else {
        anyhow::bail!(
            "predecessor atomic Start evidence is not one exact non-executable retained manifest"
        )
    };
    let NodeResult::StartFailed(failed) = &predecessor.result else {
        anyhow::bail!("retained atomic Start manifest belongs to a non-StartFailed predecessor")
    };
    start::validate_terminal_retained_runtime_manifest(manifest, None)?;
    anyhow::ensure!(
        predecessor.operation_id == manifest.source_lifecycle_operation_id
            && predecessor.request_fingerprint == manifest.request_fingerprint
            && predecessor.cat_id == manifest.cat_id
            && predecessor.node_id == manifest.node_id
            && predecessor.placement_identity == manifest.placement_identity
            && command.cat_id == manifest.cat_id
            && command.node_id == manifest.node_id
            && command.placement_identity == manifest.placement_identity
            && command.runtime_config.config_id == manifest.runtime_config_id
            && command.runtime_config.config_digest == manifest.runtime_config_digest
            && failed.retained_evidence.artifact_manifest_digest == manifest.manifest_digest,
        "retained predecessor Start manifest changed terminal, placement, or runtime identity"
    );
    Ok(())
}

impl InstalledAtomicLifecycleAdapter {
    fn apply_strong_stop(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor: &LifecycleCommandResponse,
        predecessor_physical: &StopPredecessorPhysical,
        authority: LifecycleEffectAuthority<'_>,
    ) -> Result<LifecycleEffectProgress> {
        let evidence = strong_stop::execute_command_strong_stop_with_stop_predecessor(
            &self.context,
            command,
            predecessor,
            predecessor_physical,
            authority,
        )?;

        if matches!(command.command, LifecycleCommand::Stop(_)) {
            let stop_fence_receipt_digest =
                evidence.execution_absence.stop_fence_receipt_digest.clone();
            return Ok(LifecycleEffectProgress::Terminal(NodeResult::Killed(
                Box::new(KilledResult {
                    stopped_runtime_incarnation: evidence.stopped_runtime_incarnation,
                    execution_absence: evidence.execution_absence,
                    stop_fence_receipt_digest,
                    retained_volume_receipts: evidence.retained_volume_receipts,
                    retained_evidence: evidence.retained_evidence,
                }),
            )));
        }
        anyhow::bail!("strong Stop helper returned without a Stop terminal result")
    }
}

/// Build the exact current Owned/retained subset after execution absence.
/// Unowned slots are omitted. An Owned slot needs installed lineage plus its
/// immutable StartGrant digest. A sequence-zero authority-only StartFailed is
/// the closed exception: its sealed complete-scan proof supplies a real
/// `L=R=current head` receipt even though no lineage directory exists.
fn safe_stop_volume_receipts(
    config: &InstalledAtomicLifecycleConfig,
    command: &LifecycleCommandEnvelope,
    predecessor_physical: &StopPredecessorPhysical,
) -> Result<Vec<VolumeTerminalReceipt>> {
    anyhow::ensure!(
        matches!(command.command, LifecycleCommand::Stop(_)),
        "exact Stop receipt derivation received another command"
    );
    let candidates = command
        .runtime_config
        .volumes
        .iter()
        .map(|volume| volume.volume_id.clone())
        .collect::<BTreeSet<_>>();
    let snapshot = config
        .volume_inventory_authority
        .load_node_volume_inventory(&config.node_id, &candidates)
        .context("load exact Node Volume inventory for Killed result")?;
    anyhow::ensure!(
        snapshot.node_id == config.node_id,
        "Volume inventory belongs to another Node"
    );
    let retained_evidence = retained_volume_physical_evidence(config, command)?;
    let predecessor_volumes = predecessor_physical
        .volumes
        .iter()
        .map(|volume| (volume.volume_id.clone(), volume))
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        predecessor_volumes.len() == predecessor_physical.volumes.len(),
        "journaled Stop predecessor repeats a Volume"
    );
    let mut seen = BTreeSet::new();
    let mut receipts = Vec::new();
    for entry in &snapshot.records {
        validate_volume_record(&entry.volume).context("validate Killed Volume authority record")?;
        anyhow::ensure!(
            seen.insert(entry.volume.volume_id.clone()),
            "Killed Volume inventory contains a duplicate row"
        );
        if !candidates.contains(&entry.volume.volume_id) {
            continue;
        }
        if let Some(binding) = &entry.binding {
            validate_volume_owner_binding(binding, &entry.volume)
                .context("validate Killed Volume owner binding")?;
            anyhow::ensure!(
                binding.owner_node_id == command.node_id,
                "Killed Volume owner binding belongs to another Node"
            );
            let configured = command
                .runtime_config
                .volumes
                .iter()
                .find(|volume| volume.volume_id == entry.volume.volume_id)
                .context("retained Stop Volume is outside immutable config")?;
            let predecessor = predecessor_volumes
                .get(&entry.volume.volume_id)
                .context("current Owned Volume is absent from journaled Stop predecessor")?;
            anyhow::ensure!(
                predecessor.disk_id == configured.disk_id
                    && predecessor.disk_role == configured.disk_role
                    && predecessor.attachment_id == binding.attachment_id
                    && predecessor.attachment_epoch == binding.attachment_epoch
                    && predecessor.acquire_origin == authority_acquire_origin(&entry.volume)?
                    && stop_remote_head_is_unchanged_or_advanced(
                        &predecessor.authoritative_head,
                        &entry.volume.head,
                    ),
                "Killed current authority changed journaled config, owner, origin, or head"
            );
            let local = if let Some(path) = &predecessor.local_lineage_data_directory {
                let physical = retained_evidence
                    .get(&entry.volume.volume_id)
                    .context("journaled Stop lineage disappeared after strong Stop")?;
                anyhow::ensure!(
                    physical.disk_id == predecessor.disk_id
                        && physical.disk_role == predecessor.disk_role
                        && physical.attachment_id == predecessor.attachment_id
                        && physical.attachment_epoch == predecessor.attachment_epoch
                        && physical.acquire_origin == predecessor.acquire_origin
                        && physical.authority_receipt_digest
                            == predecessor.immutable_start_grant_receipt_digest
                        && physical.local_lineage_data_directory.as_path()
                            == Path::new(path.as_str()),
                    "post-Stop installed lineage differs from the journaled predecessor carrier"
                );
                let identity = AttachmentLineageIdentity {
                    volume_id: entry.volume.volume_id.clone(),
                    attachment_id: predecessor.attachment_id.clone(),
                    attachment_epoch: predecessor.attachment_epoch,
                    acquire_origin: predecessor.acquire_origin.clone(),
                    node_id: command.node_id.clone(),
                    placement_epoch: command.placement_identity.placement_epoch,
                };
                cold_delete::inspect_lineage_durability_read_only(
                    &physical.local_lineage_data_directory,
                    &identity,
                    &entry.volume.head,
                )
                .context("inspect journaled retained Volume lineage after strong Stop")?
                .0
            } else {
                anyhow::ensure!(
                    !retained_evidence.contains_key(&entry.volume.volume_id)
                        && entry.volume.head == predecessor.authoritative_head
                        && predecessor.predecessor_receipt.local_durable_generation
                            == entry.volume.head.generation
                        && predecessor.predecessor_receipt.remote_durable_generation
                            == entry.volume.head.generation,
                    "authority-only Stop predecessor gained a path or changed its exact L=R head"
                );
                entry.volume.head.generation
            };
            anyhow::ensure!(
                local >= entry.volume.head.generation,
                "post-Stop local lineage is behind current remote authority"
            );
            receipts.push(VolumeTerminalReceipt {
                volume_id: entry.volume.volume_id.clone(),
                disk_id: predecessor.disk_id.clone(),
                disk_role: predecessor.disk_role,
                attachment_id: predecessor.attachment_id.clone(),
                attachment_epoch: predecessor.attachment_epoch,
                local_durable_generation: local,
                remote_durable_generation: entry.volume.head.generation,
                authority_receipt_digest: Some(
                    predecessor.immutable_start_grant_receipt_digest.clone(),
                ),
            });
            continue;
        }
        anyhow::ensure!(
            entry.volume.lease_owner.is_none()
                && entry.volume.lease_expires_at.is_none()
                && !predecessor_volumes.contains_key(&entry.volume.volume_id)
                && !retained_evidence.contains_key(&entry.volume.volume_id),
            "Killed Unowned Volume conflicts with journaled predecessor or installed lineage"
        );
    }
    anyhow::ensure!(
        candidates.iter().all(|volume_id| seen.contains(volume_id))
            && receipts.len() == predecessor_physical.volumes.len(),
        "Killed Volume inventory omitted a configured or predecessor attachment"
    );
    receipts.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    anyhow::ensure!(
        receipts
            .windows(2)
            .all(|pair| pair[0].volume_id < pair[1].volume_id),
        "Killed retained Volume receipts repeat an identity"
    );
    Ok(receipts)
}

fn stop_remote_head_is_unchanged_or_advanced(before: &RemoteHead, after: &RemoteHead) -> bool {
    if !stop_remote_head_valid(before) || !stop_remote_head_valid(after) {
        return false;
    }
    if after.generation < before.generation {
        return false;
    }
    if after.generation == before.generation {
        return after == before;
    }
    after.root_hash.is_some() && after.root_object_id.is_some()
}

fn stop_remote_head_valid(head: &RemoteHead) -> bool {
    if head.generation.get() == 0 {
        head.root_hash.is_none() && head.root_object_id.is_none()
    } else {
        head.root_hash.is_some() && head.root_object_id.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedVolumePhysicalEvidence {
    disk_id: Id,
    disk_role: cats_api::runtime_lifecycle::DiskRole,
    attachment_id: Id,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    acquire_origin: AcquireOrigin,
    authority_receipt_digest: Sha256Digest,
    local_lineage_data_directory: PathBuf,
}

fn retained_volume_physical_evidence(
    config: &InstalledAtomicLifecycleConfig,
    command: &LifecycleCommandEnvelope,
) -> Result<BTreeMap<Id, RetainedVolumePhysicalEvidence>> {
    let mut evidence = BTreeMap::new();
    for manifest in start::enumerate_installed_runtime_manifests(&config.state_directory)? {
        if manifest.cat_id != command.cat_id {
            continue;
        }
        anyhow::ensure!(
            manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity
                && manifest.runtime_config_id == command.runtime_config.config_id
                && manifest.runtime_config_digest == command.runtime_config.config_digest,
            "Killed installed runtime manifest belongs to another immutable runtime"
        );
        for volume in manifest.volumes {
            let digest = volume
                .authority_receipt_digest
                .context("Killed installed runtime Volume lacks its StartGrant digest")?;
            insert_retained_volume_evidence(
                &mut evidence,
                volume.volume_id,
                RetainedVolumePhysicalEvidence {
                    disk_id: volume.disk_id,
                    disk_role: volume.disk_role,
                    attachment_id: volume.attachment_id,
                    attachment_epoch: volume.attachment_epoch,
                    acquire_origin: volume.acquire_origin,
                    authority_receipt_digest: digest,
                    local_lineage_data_directory: PathBuf::from(
                        volume.local_lineage_data_directory.as_str(),
                    ),
                },
            )?;
        }
    }
    for entry in start::enumerate_installed_start_physical_manifests(&config.state_directory)? {
        let (manifest, inherited) = match entry {
            start::InstalledStartPhysicalInventoryEntry::Executing(manifest) => {
                (Some(*manifest), None)
            }
            start::InstalledStartPhysicalInventoryEntry::TerminalRetained(retained) => {
                let inherited = match retained.retention_mode {
                    start::TerminalRetainedRuntimeMode::InheritedPredecessorOwned { evidence } => {
                        Some(evidence)
                    }
                    start::TerminalRetainedRuntimeMode::AuthorityOnlyOwnedZeroMutation {
                        ..
                    }
                    | start::TerminalRetainedRuntimeMode::MaterializedOrAmbiguous => None,
                };
                (retained.runtime_progress, inherited)
            }
        };
        if let Some(inherited) = inherited {
            for volume in inherited.volumes {
                let Some(path) = volume.local_lineage_data_directory else {
                    continue;
                };
                let receipt = volume.retained_receipt;
                insert_retained_volume_evidence(
                    &mut evidence,
                    receipt.volume_id.clone(),
                    RetainedVolumePhysicalEvidence {
                        disk_id: receipt.disk_id,
                        disk_role: receipt.disk_role,
                        attachment_id: receipt.attachment_id,
                        attachment_epoch: receipt.attachment_epoch,
                        acquire_origin: volume.acquire_origin,
                        authority_receipt_digest: volume.immutable_start_grant_receipt_digest,
                        local_lineage_data_directory: PathBuf::from(path.as_str()),
                    },
                )?;
            }
        }
        let Some(manifest) = manifest else {
            continue;
        };
        if manifest.cat_id != command.cat_id {
            continue;
        }
        anyhow::ensure!(
            manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity
                && manifest.runtime_config_id == command.runtime_config.config_id
                && manifest.runtime_config_digest == command.runtime_config.config_digest,
            "Killed Start progress belongs to another immutable runtime"
        );
        for volume in manifest.volumes {
            let (Some(path), Some(digest)) = (
                volume.local_lineage_data_directory,
                volume.authority_receipt_digest,
            ) else {
                continue;
            };
            insert_retained_volume_evidence(
                &mut evidence,
                volume.volume_id,
                RetainedVolumePhysicalEvidence {
                    disk_id: volume.disk_id,
                    disk_role: volume.disk_role,
                    attachment_id: volume.attachment_id,
                    attachment_epoch: volume.attachment_epoch,
                    acquire_origin: volume.acquire_origin,
                    authority_receipt_digest: digest,
                    local_lineage_data_directory: PathBuf::from(path.as_str()),
                },
            )?;
        }
    }
    Ok(evidence)
}

fn insert_retained_volume_evidence(
    evidence: &mut BTreeMap<Id, RetainedVolumePhysicalEvidence>,
    volume_id: Id,
    physical: RetainedVolumePhysicalEvidence,
) -> Result<()> {
    if let Some(previous) = evidence.insert(volume_id, physical.clone()) {
        anyhow::ensure!(
            previous == physical,
            "Killed retained Volume has conflicting installed lineage evidence"
        );
    }
    Ok(())
}

fn predecessor_retained_volume_receipts(
    predecessor: &LifecycleCommandResponse,
) -> &[VolumeTerminalReceipt] {
    match &predecessor.result {
        NodeResult::RuntimeReady(result) => &result.volume_receipts,
        NodeResult::Suspended(result) => &result.local_durability_receipts,
        NodeResult::Warm(result) => &result.volume_receipts,
        NodeResult::Killed(result) => &result.retained_volume_receipts,
        NodeResult::NeedsIntervention(result) => &result.retained_volume_receipts,
        NodeResult::SuspendDeclined(_)
        | NodeResult::StartFailed(_)
        | NodeResult::SuspendFailed(_)
        | NodeResult::WarmFailed(_)
        | NodeResult::Cold(_)
        | NodeResult::Deleted(_) => &[],
    }
}

fn authority_acquire_origin(
    volume: &cats_api::runtime_reconciliation::VolumeRecord,
) -> Result<AcquireOrigin> {
    match volume.last_transition.as_ref() {
        Some(LastVolumeTransition::NormalAcquire { request, .. }) => Ok(AcquireOrigin::Normal {
            transition_id: request.transition_id.clone(),
        }),
        Some(LastVolumeTransition::Takeover {
            authorization_id, ..
        }) => Ok(AcquireOrigin::Takeover {
            authorization_id: authorization_id.clone(),
        }),
        _ => anyhow::bail!("retained Volume authority lost its acquire lineage"),
    }
}

/// Reconstruct the exact Guest-facing frontend target set from descriptor-
/// safe final/progress manifests before entering the barrier. The retained
/// map survives the kill inside this process; every retry reconstructs it
/// again, so a crash after scope exit but before detach cannot turn a leaked
/// NBD device or stale vhost-user socket into false absence.
fn seed_frontend_expectations(
    ctx: &common::InstalledLifecycleContext,
    command: &LifecycleCommandEnvelope,
) -> Result<()> {
    let mut by_path = BTreeMap::<PathBuf, ObservedFrontend>::new();
    for manifest in start::enumerate_installed_runtime_manifests(ctx.state_directory())? {
        if manifest.cat_id != command.cat_id {
            continue;
        }
        anyhow::ensure!(
            manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity,
            "installed RuntimeReady manifest belongs to another placement"
        );
        for volume in &manifest.volumes {
            insert_expected_frontend(ctx.config(), &mut by_path, &volume.frontend)?;
        }
    }
    for entry in start::enumerate_installed_start_physical_manifests(ctx.state_directory())? {
        let manifest = match entry {
            start::InstalledStartPhysicalInventoryEntry::Executing(manifest) => Some(*manifest),
            start::InstalledStartPhysicalInventoryEntry::TerminalRetained(retained) => {
                retained.runtime_progress
            }
        };
        let Some(manifest) = manifest else {
            // Inherited-predecessor archives cannot name a current frontend.
            // Their referenced predecessor manifest remains separately
            // enumerable and supplies the exact frontend target.
            continue;
        };
        if manifest.cat_id != command.cat_id {
            continue;
        }
        anyhow::ensure!(
            manifest.node_id == command.node_id
                && manifest.placement_identity == command.placement_identity
                && (manifest.source_lifecycle_operation_id == command.operation_id
                    || command.expected_predecessor_operation_id.as_ref()
                        == Some(&manifest.source_lifecycle_operation_id)),
            "installed Start progress manifest belongs to another command or placement"
        );
        for volume in &manifest.volumes {
            if let Some(frontend) = &volume.frontend {
                insert_expected_frontend(ctx.config(), &mut by_path, frontend)?;
            }
        }
    }
    let expected = by_path.into_values().collect::<Vec<_>>();
    let mut retained = ctx
        .frontend_expectations()
        .lock()
        .map_err(|_| anyhow::anyhow!("frontend expectation mutex is unavailable"))?;
    if expected.is_empty() {
        retained.remove(&command.cat_id);
    } else {
        retained.insert(command.cat_id.clone(), expected);
    }
    Ok(())
}

fn insert_expected_frontend(
    config: &InstalledAtomicLifecycleConfig,
    by_path: &mut BTreeMap<PathBuf, ObservedFrontend>,
    frontend: &start::InstalledRuntimeBlockFrontend,
) -> Result<()> {
    let observed = match frontend {
        start::InstalledRuntimeBlockFrontend::KernelNbd { device_path, .. } => {
            let kernel = config
                .kernel_nbd
                .as_ref()
                .context("Runtime manifest names kernel-NBD without installed pool")?;
            let path = PathBuf::from(device_path.as_str());
            anyhow::ensure!(
                (0..kernel.device_count)
                    .map(|index| kernel.device_root.join(format!("nbd{index}")))
                    .any(|candidate| candidate == path),
                "Runtime manifest kernel-NBD device is outside installed pool"
            );
            ObservedFrontend::KernelNbd { device_path: path }
        }
        start::InstalledRuntimeBlockFrontend::VhostUserBlk { socket_path } => {
            let path = PathBuf::from(socket_path.as_str());
            anyhow::ensure!(
                config
                    .managed_socket_roots
                    .iter()
                    .any(|root| path.starts_with(root) && path != *root),
                "Runtime manifest vhost-user socket is outside managed namespaces"
            );
            ObservedFrontend::VhostUserBlk { socket_path: path }
        }
    };
    let path = frontend_path(&observed).to_path_buf();
    if let Some(previous) = by_path.insert(path, observed.clone()) {
        anyhow::ensure!(
            previous == observed,
            "Runtime manifests assign one Host frontend path to different types"
        );
    }
    Ok(())
}

fn closed_admission_anchor(
    command: &LifecycleCommandEnvelope,
    predecessor: Option<&LifecycleCommandResponse>,
) -> Result<Id> {
    if let Some(predecessor) = predecessor {
        anyhow::ensure!(
            predecessor.cat_id == command.cat_id
                && predecessor.node_id == command.node_id
                && command.expected_predecessor_operation_id.as_ref()
                    == Some(&predecessor.operation_id),
            "closed admission predecessor response does not bind the command"
        );
        return Ok(predecessor.operation_id.clone());
    }
    Ok(match &command.predecessor {
        cats_api::runtime_lifecycle::LifecyclePredecessor::Genesis {
            cat_creation_id, ..
        } => cat_creation_id.clone(),
        cats_api::runtime_lifecycle::LifecyclePredecessor::SameNode { operation_id, .. } => {
            operation_id.clone()
        }
        cats_api::runtime_lifecycle::LifecyclePredecessor::CrossNodeColdHandoff {
            cold_operation_id,
            ..
        } => cold_operation_id.clone(),
        cats_api::runtime_lifecycle::LifecyclePredecessor::HostFenceRecovery {
            interrupted_operation_id,
            ..
        } => interrupted_operation_id.clone(),
    })
}

fn dedicated_scope(cat_id: &Id) -> Result<DedicatedCatExecutionScope> {
    Ok(DedicatedCatExecutionScope::new(
        cat_id.clone(),
        cat_execution_slice_id(cat_id),
    ))
}

fn command_grace_deadline(command: &LifecycleCommandEnvelope) -> Result<Instant> {
    let absolute = match &command.command {
        LifecycleCommand::Suspend(spec) => spec.grace_deadline_unix_ms,
        LifecycleCommand::Warm(spec) => spec.grace_deadline_unix_ms,
        LifecycleCommand::Cold(spec) => spec.grace_deadline_unix_ms,
        LifecycleCommand::Stop(spec) => spec.grace_deadline_unix_ms,
        LifecycleCommand::Delete(spec) => spec.grace_deadline_unix_ms,
        LifecycleCommand::Start(spec) => spec.effect_deadline_unix_ms,
    };
    unix_deadline_to_instant(absolute)
}

fn unix_deadline_to_instant(deadline: UnixMillis) -> Result<Instant> {
    let now_system = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Host wall clock precedes the Unix epoch")?;
    let now_ms = u64::try_from(now_system.as_millis()).context("Host wall clock overflows u64")?;
    // A durable command may be recovered after its wall-clock grace window.
    // Expiry means graceful time is exhausted, not that Stop authority was
    // lost: clamp to now so the barrier immediately reaches the force path.
    let remaining_ms = deadline.get().saturating_sub(now_ms);
    Instant::now()
        .checked_add(Duration::from_millis(remaining_ms))
        .context("lifecycle grace deadline overflows monotonic time")
}

fn execution_absence_proof(
    command: &LifecycleCommandEnvelope,
    fence: &super::journal::CurrentStopFenceGuard<'_>,
    receipt: &super::strong_stop::StrongStopReceipt,
    restart_source_absence_receipt_digest: Sha256Digest,
) -> Result<ExecutionAbsenceProof> {
    anyhow::ensure!(
        receipt.operation_id() == &command.operation_id,
        "strong Stop receipt belongs to another operation"
    );
    let stop_fence_receipt_digest = digest_parts(
        STOP_FENCE_RECEIPT_DOMAIN,
        &[
            command.cat_id.as_str().as_bytes(),
            command.operation_id.as_str().as_bytes(),
            fence.fence_payload(),
        ],
    );
    let admission_bytes = encode_lifecycle_close(receipt.lifecycle_close());
    let admission_closed_receipt_digest = digest_parts(
        ADMISSION_CLOSE_RECEIPT_DOMAIN,
        &[
            command.cat_id.as_str().as_bytes(),
            command.operation_id.as_str().as_bytes(),
            &admission_bytes,
        ],
    );
    let dedicated_scope_absence_receipt_digest =
        receipt.execution_scope_absence().proof_digest().clone();
    let frontend_absence_receipt_digest = receipt.frontend_absence().proof_digest().clone();
    Ok(ExecutionAbsenceProof {
        stop_fence_receipt_digest,
        admission_closed_receipt_digest,
        dedicated_scope_absence_receipt_digest,
        frontend_absence_receipt_digest,
        restart_source_absence_receipt_digest,
    })
}

fn encode_lifecycle_close(outcome: &LifecycleCloseOutcome) -> Vec<u8> {
    let mut bytes = Vec::new();
    match outcome {
        LifecycleCloseOutcome::Replay => bytes.extend_from_slice(b"replay"),
        LifecycleCloseOutcome::Closed {
            closed_route_epochs,
        } => {
            bytes.extend_from_slice(b"closed");
            let mut routes = closed_route_epochs.clone();
            routes.sort_by(|left, right| {
                left.endpoint_id
                    .cmp(&right.endpoint_id)
                    .then_with(|| left.route_epoch.cmp(&right.route_epoch))
            });
            for route in routes {
                push_digest_part(&mut bytes, route.endpoint_id.as_str().as_bytes());
                push_digest_part(&mut bytes, &route.route_epoch.get().to_be_bytes());
            }
        }
    }
    bytes
}

pub(super) fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn push_digest_part(target: &mut Vec<u8>, part: &[u8]) {
    target.extend_from_slice(&(part.len() as u64).to_be_bytes());
    target.extend_from_slice(part);
}

impl GracefulShutdownPort for InstalledCatExecutionScopePort {
    fn request_graceful_shutdown(
        &self,
        scope: &DedicatedCatExecutionScope,
        deadline: Instant,
        fence: &super::journal::CurrentStopFenceGuard<'_>,
    ) -> Result<(), StrongStopPortError> {
        validate_scope_binding(scope, fence)?;
        let result = run_bounded_command(
            &self.systemctl_binary,
            ["stop", "--no-block", scope.scope_id().as_str()],
            deadline,
        )
        .map_err(|error| stop_port_error("request graceful systemd shutdown", error))?;
        if result.timed_out {
            return Err(StrongStopPortError::new(
                "request graceful systemd shutdown",
                "systemctl did not return before the command deadline",
            ));
        }
        if !result.status.success() {
            return Err(StrongStopPortError::new(
                "request graceful systemd shutdown",
                command_failure_detail(&result),
            ));
        }
        Ok(())
    }
}

impl DedicatedExecutionScopePort for InstalledCatExecutionScopePort {
    fn inspect_scope(
        &self,
        expected: &DedicatedCatExecutionScope,
        fence: &super::journal::CurrentStopFenceGuard<'_>,
    ) -> Result<ExecutionScopeInventory, StrongStopPortError> {
        validate_scope_binding(expected, fence)?;
        let expected_slice = cat_execution_slice_id(expected.cat_id());
        if &expected_slice != expected.scope_id() {
            return Err(StrongStopPortError::new(
                "inspect dedicated execution scope",
                "scope identity is not the canonical Cat parent slice",
            ));
        }
        let scan = scan_exact_cgroup_tree(
            &self.cgroup_root,
            &self.proc_root,
            expected.cat_id(),
            &self.managed_process_binaries,
        )
        .map_err(|error| stop_port_error("inspect dedicated execution scope", error))?;
        let frontends = self
            .scan_attributed_kernel_frontends(expected.cat_id())
            .map_err(|error| stop_port_error("inspect kernel-NBD Cat attribution", error))?;
        if !frontends.is_empty() {
            let mut observed = self.observed_frontends.lock().map_err(|_| {
                StrongStopPortError::new(
                    "retain frontend inventory",
                    "frontend inventory mutex is unavailable",
                )
            })?;
            let retained = observed.entry(expected.cat_id().clone()).or_default();
            retained.extend(frontends);
            retained.sort_by(|left, right| frontend_path(left).cmp(frontend_path(right)));
            retained.dedup();
        }
        if !scan.slice_present {
            let proof = digest_parts(
                SCOPE_ABSENCE_RECEIPT_DOMAIN,
                &[
                    expected.cat_id().as_str().as_bytes(),
                    expected.scope_id().as_str().as_bytes(),
                    scan.canonical_digest.as_bytes(),
                ],
            );
            Ok(ExecutionScopeInventory::Absent(
                ExecutionScopeAbsenceReceipt::new(
                    expected.cat_id().clone(),
                    expected.scope_id().clone(),
                    proof,
                ),
            ))
        } else {
            Ok(ExecutionScopeInventory::Present(
                ObservedExecutionScope::new(expected.cat_id().clone(), expected.scope_id().clone()),
            ))
        }
    }

    fn wait_for_absence_until(
        &self,
        expected: &DedicatedCatExecutionScope,
        deadline: Instant,
        fence: &super::journal::CurrentStopFenceGuard<'_>,
    ) -> Result<ExecutionScopeInventory, StrongStopPortError> {
        loop {
            let inventory = self.inspect_scope(expected, fence)?;
            if matches!(inventory, ExecutionScopeInventory::Absent(_)) || Instant::now() >= deadline
            {
                return Ok(inventory);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(std::cmp::min(POLL_INTERVAL, remaining));
        }
    }

    fn force_kill_scope(
        &self,
        expected: &DedicatedCatExecutionScope,
        fence: &super::journal::CurrentStopFenceGuard<'_>,
    ) -> Result<(), StrongStopPortError> {
        validate_scope_binding(expected, fence)?;
        let deadline = Instant::now()
            .checked_add(self.probe_timeout)
            .ok_or_else(|| {
                StrongStopPortError::new(
                    "force-kill dedicated execution scope",
                    "probe deadline overflow",
                )
            })?;
        let kill_result = run_bounded_command(
            &self.systemctl_binary,
            [
                "kill",
                "--kill-who=all",
                "--signal=SIGKILL",
                expected.scope_id().as_str(),
            ],
            deadline,
        )
        .map_err(|error| stop_port_error("force-kill dedicated execution scope", error))?;

        // `systemctl kill` can leave an empty but installed slice behind.
        // Execution absence requires the exact parent cgroup itself to
        // disappear, so request a stop after the kill and wait only for the
        // filesystem postcondition. Either command response may be lost; the
        // final barrier inventory remains the success oracle.
        let cleanup_deadline = Instant::now()
            .checked_add(self.probe_timeout)
            .ok_or_else(|| {
                StrongStopPortError::new(
                    "stop force-killed execution scope",
                    "cleanup deadline overflow",
                )
            })?;
        let stop_result = run_bounded_command(
            &self.systemctl_binary,
            ["stop", "--no-block", expected.scope_id().as_str()],
            cleanup_deadline,
        );
        let slice_path = self.cgroup_root.join(expected.scope_id().as_str());
        while Instant::now() < cleanup_deadline {
            match fs::symlink_metadata(&slice_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Ok(_) => std::thread::sleep(std::cmp::min(
                    POLL_INTERVAL,
                    cleanup_deadline.saturating_duration_since(Instant::now()),
                )),
                Err(error) => {
                    return Err(stop_port_error(
                        "inspect force-stopped execution scope",
                        error,
                    ))
                }
            }
        }
        if kill_result.timed_out || !kill_result.status.success() {
            return Err(StrongStopPortError::new(
                "force-kill dedicated execution scope",
                command_failure_detail(&kill_result),
            ));
        }
        if let Ok(stop_result) = stop_result {
            if stop_result.timed_out || !stop_result.status.success() {
                return Err(StrongStopPortError::new(
                    "stop force-killed execution scope",
                    command_failure_detail(&stop_result),
                ));
            }
        }
        Err(StrongStopPortError::new(
            "verify force-killed execution scope",
            "Cat parent slice still exists after the bounded force path",
        ))
    }
}

impl InstalledCatExecutionScopePort {
    fn scan_attributed_kernel_frontends(&self, cat_id: &Id) -> Result<Vec<ObservedFrontend>> {
        let Some(config) = &self.kernel_nbd else {
            return Ok(Vec::new());
        };
        let expected = cat_execution_slice_control_group(cat_id);
        let mut frontends = Vec::new();
        for slot in scan_kernel_nbd_pool(config, &self.proc_root)? {
            let KernelNbdSlot::Serving {
                device_path,
                process_id,
            } = slot
            else {
                continue;
            };
            let cgroup = read_unified_process_cgroup(&self.proc_root, process_id)?;
            if cgroup == expected || cgroup.starts_with(&(expected.clone() + "/")) {
                frontends.push(ObservedFrontend::KernelNbd { device_path });
            }
        }
        frontends.sort_by(|left, right| frontend_path(left).cmp(frontend_path(right)));
        frontends.dedup();
        Ok(frontends)
    }
}

impl GuestFrontendPort for InstalledGuestFrontendPort {
    fn close_frontends(
        &self,
        cat_id: &Id,
        fence: &super::journal::CurrentStopFenceGuard<'_>,
    ) -> Result<(), StrongStopPortError> {
        if fence.cat_id() != cat_id {
            return Err(StrongStopPortError::new(
                "close Guest frontends",
                "Stop fence belongs to another Cat",
            ));
        }
        let frontends = self
            .observed_frontends
            .lock()
            .map_err(|_| {
                StrongStopPortError::new(
                    "close Guest frontends",
                    "frontend inventory mutex is unavailable",
                )
            })?
            .get(cat_id)
            .cloned()
            .unwrap_or_default();
        for frontend in frontends {
            match frontend {
                ObservedFrontend::KernelNbd { device_path } => {
                    let Some(config) = &self.kernel_nbd else {
                        return Err(StrongStopPortError::new(
                            "close Guest frontends",
                            "kernel-NBD frontend has no installed detach adapter",
                        ));
                    };
                    let pool =
                        scan_kernel_nbd_pool(config, &self.scope.proc_root).map_err(|error| {
                            stop_port_error("inspect kernel-NBD before detach", error)
                        })?;
                    let slot = pool
                        .iter()
                        .find(|slot| slot.device_path() == &device_path)
                        .ok_or_else(|| {
                            StrongStopPortError::new(
                                "detach kernel-NBD frontend",
                                "manifest device is outside the installed pool",
                            )
                        })?;
                    if let KernelNbdSlot::Serving { process_id, .. } = slot {
                        let cgroup =
                            read_unified_process_cgroup(&self.scope.proc_root, *process_id)
                                .map_err(|error| {
                                    stop_port_error(
                                        "revalidate kernel-NBD owner before detach",
                                        error,
                                    )
                                })?;
                        let expected = cat_execution_slice_control_group(cat_id);
                        if cgroup != expected && !cgroup.starts_with(&(expected + "/")) {
                            return Err(StrongStopPortError::new(
                                "detach kernel-NBD frontend",
                                "manifest device is currently served by another cgroup",
                            ));
                        }
                    }
                    if slot.is_live() {
                        let deadline =
                            Instant::now()
                                .checked_add(self.probe_timeout)
                                .ok_or_else(|| {
                                    StrongStopPortError::new(
                                        "detach kernel-NBD frontend",
                                        "deadline overflow",
                                    )
                                })?;
                        // The response is intentionally not interpreted as
                        // success. The full pool scan below is the oracle.
                        let _ = run_bounded_command(
                            &config.nbd_client_binary,
                            [
                                std::ffi::OsString::from("-d"),
                                device_path.as_os_str().to_owned(),
                            ],
                            deadline,
                        );
                    }
                }
                ObservedFrontend::VhostUserBlk { socket_path } => {
                    let metadata = match fs::symlink_metadata(&socket_path) {
                        Ok(metadata) => metadata,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => {
                            return Err(stop_port_error(
                                "inspect vhost-user frontend before removal",
                                error,
                            ))
                        }
                    };
                    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                        return Err(StrongStopPortError::new(
                            "close vhost-user frontend",
                            "manifest path is not an exact Unix socket",
                        ));
                    }
                    fs::remove_file(&socket_path).map_err(|error| {
                        stop_port_error("remove stopped vhost-user frontend socket", error)
                    })?;
                }
            }
        }
        Ok(())
    }

    fn inspect_frontends(
        &self,
        cat_id: &Id,
        fence: &super::journal::CurrentStopFenceGuard<'_>,
    ) -> Result<FrontendInventory, StrongStopPortError> {
        if fence.cat_id() != cat_id {
            return Err(StrongStopPortError::new(
                "inspect Guest frontends",
                "Stop fence belongs to another Cat",
            ));
        }
        let still_attributed = self
            .scope
            .scan_attributed_kernel_frontends(cat_id)
            .map_err(|error| stop_port_error("inspect kernel-NBD frontends", error))?;
        let remembered = self
            .observed_frontends
            .lock()
            .map_err(|_| {
                StrongStopPortError::new(
                    "inspect Guest frontends",
                    "frontend inventory mutex is unavailable",
                )
            })?
            .get(cat_id)
            .cloned()
            .unwrap_or_default();
        let mut present = still_attributed;
        if let Some(config) = &self.kernel_nbd {
            let pool = scan_kernel_nbd_pool(config, &self.scope.proc_root)
                .map_err(|error| stop_port_error("inspect complete kernel-NBD pool", error))?;
            for expected in &remembered {
                if let ObservedFrontend::KernelNbd { device_path } = expected {
                    if pool
                        .iter()
                        .any(|slot| slot.device_path() == device_path && slot.is_live())
                    {
                        present.push(expected.clone());
                    }
                }
            }
        }
        for expected in remembered {
            let ObservedFrontend::VhostUserBlk { socket_path } = expected else {
                continue;
            };
            match fs::symlink_metadata(&socket_path) {
                Ok(_) => present.push(ObservedFrontend::VhostUserBlk { socket_path }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(stop_port_error(
                        "inspect exact vhost-user frontend socket",
                        error,
                    ))
                }
            }
        }
        present.sort_by(|left, right| frontend_path(left).cmp(frontend_path(right)));
        present.dedup();
        if !present.is_empty() {
            let ids = present
                .iter()
                .map(frontend_id)
                .collect::<Result<Vec<_>>>()
                .map_err(|error| stop_port_error("encode live frontend identity", error))?;
            return Ok(FrontendInventory::Present { frontend_ids: ids });
        }
        let proof = digest_parts(
            FRONTEND_ABSENCE_RECEIPT_DOMAIN,
            &[
                cat_id.as_str().as_bytes(),
                cat_execution_slice_id(cat_id).as_str().as_bytes(),
            ],
        );
        Ok(FrontendInventory::Absent(FrontendAbsenceReceipt::new(
            cat_id.clone(),
            proof,
        )))
    }
}

fn validate_scope_binding(
    scope: &DedicatedCatExecutionScope,
    fence: &super::journal::CurrentStopFenceGuard<'_>,
) -> Result<(), StrongStopPortError> {
    if scope.cat_id() != fence.cat_id() {
        return Err(StrongStopPortError::new(
            "validate dedicated execution scope",
            "scope and Stop fence name different Cats",
        ));
    }
    if scope.scope_id() != &cat_execution_slice_id(scope.cat_id()) {
        return Err(StrongStopPortError::new(
            "validate dedicated execution scope",
            "scope is not the canonical Cat parent slice",
        ));
    }
    fence
        .assert_current()
        .map_err(|error| StrongStopPortError::new("validate durable Stop fence", error.to_string()))
}

fn stop_port_error(operation: &'static str, error: impl std::fmt::Display) -> StrongStopPortError {
    StrongStopPortError::new(operation, error.to_string())
}

#[derive(Debug)]
pub(super) struct CgroupTreeScan {
    /// `false` is the only execution-scope absence postcondition. An empty
    /// but still installed slice remains Present until systemd removes its
    /// cgroup; otherwise a force-kill response race could become false Killed.
    pub(super) slice_present: bool,
    pub(super) process_ids: Vec<u32>,
    pub(super) canonical_digest: Sha256Digest,
}

pub(super) fn scan_exact_cgroup_tree(
    cgroup_root: &Path,
    proc_root: &Path,
    cat_id: &Id,
    managed_process_binaries: &BTreeSet<PathBuf>,
) -> Result<CgroupTreeScan> {
    let slice_id = cat_execution_slice_id(cat_id);
    let slice_path = cgroup_root.join(slice_id.as_str());
    let metadata = match fs::symlink_metadata(&slice_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CgroupTreeScan {
                slice_present: false,
                process_ids: Vec::new(),
                canonical_digest: digest_parts(
                    INVENTORY_DIGEST_DOMAIN,
                    &[cat_id.as_str().as_bytes(), b"slice-absent"],
                ),
            })
        }
        Err(error) => return Err(error).context("inspect deterministic Cat cgroup"),
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "deterministic Cat cgroup is not an ordinary directory"
    );
    let expected_prefix = cat_execution_slice_control_group(cat_id);
    let mut directories = vec![slice_path];
    let mut cursor = 0;
    let mut process_ids = BTreeSet::new();
    let mut canonical = Vec::new();
    while cursor < directories.len() {
        anyhow::ensure!(
            directories.len() <= CGROUP_ENTRY_LIMIT,
            "Cat cgroup tree exceeds the closed entry bound"
        );
        let directory = directories[cursor].clone();
        cursor += 1;
        let relative = directory
            .strip_prefix(cgroup_root)
            .context("Cat cgroup escaped the configured root")?;
        push_digest_part(&mut canonical, relative.as_os_str().as_encoded_bytes());
        let procs_path = directory.join("cgroup.procs");
        let procs = match fs::read_to_string(&procs_path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error).context("read Cat cgroup.procs"),
        };
        anyhow::ensure!(
            procs.len() <= COMMAND_OUTPUT_MAX_BYTES,
            "Cat cgroup.procs exceeds the closed byte bound"
        );
        for line in procs.lines() {
            let pid = line
                .parse::<u32>()
                .context("Cat cgroup.procs contains a non-process identity")?;
            anyhow::ensure!(pid > 0, "Cat cgroup contains process zero");
            let cgroup = read_unified_process_cgroup(proc_root, pid)?;
            anyhow::ensure!(
                cgroup == expected_prefix || cgroup.starts_with(&(expected_prefix.clone() + "/")),
                "Cat cgroup membership and /proc process identity disagree"
            );
            let executable = fs::read_link(proc_root.join(pid.to_string()).join("exe"))
                .context("read Cat process executable")?;
            let mut accepted = managed_process_binaries.contains(&executable);
            if !accepted {
                // Deleted-but-running executables retain the kernel suffix;
                // they are residue, never an authorized managed process.
                accepted = false;
            }
            anyhow::ensure!(
                accepted,
                "Cat parent slice contains an unrecognized executable {}",
                executable.display()
            );
            process_ids.insert(pid);
            push_digest_part(&mut canonical, &pid.to_be_bytes());
            push_digest_part(&mut canonical, executable.as_os_str().as_encoded_bytes());
            push_digest_part(&mut canonical, cgroup.as_bytes());
        }
        for entry in fs::read_dir(&directory).context("enumerate Cat cgroup tree")? {
            let entry = entry.context("read Cat cgroup entry")?;
            let file_type = entry.file_type().context("inspect Cat cgroup entry")?;
            if file_type.is_symlink() {
                anyhow::bail!("Cat cgroup tree contains a symbolic link");
            }
            if file_type.is_dir() {
                directories.push(entry.path());
            }
        }
    }
    let process_ids = process_ids.into_iter().collect::<Vec<_>>();
    Ok(CgroupTreeScan {
        slice_present: true,
        process_ids,
        canonical_digest: digest_parts(
            INVENTORY_DIGEST_DOMAIN,
            &[cat_id.as_str().as_bytes(), &canonical],
        ),
    })
}

pub(super) fn read_unified_process_cgroup(proc_root: &Path, process_id: u32) -> Result<String> {
    let path = proc_root.join(process_id.to_string()).join("cgroup");
    let bytes = fs::read(&path).context("read process cgroup identity")?;
    anyhow::ensure!(
        bytes.len() <= COMMAND_OUTPUT_MAX_BYTES,
        "process cgroup identity exceeds the closed byte bound"
    );
    let text = std::str::from_utf8(&bytes).context("process cgroup identity is not UTF-8")?;
    let mut unified = text.lines().filter_map(|line| line.strip_prefix("0::"));
    let cgroup = unified
        .next()
        .context("process has no unified cgroup-v2 identity")?;
    anyhow::ensure!(
        unified.next().is_none() && cgroup.starts_with('/') && !cgroup.contains("//"),
        "process has an ambiguous unified cgroup-v2 identity"
    );
    Ok(cgroup.to_owned())
}

#[derive(Debug, Clone)]
pub(super) enum KernelNbdSlot {
    Free {
        device_path: PathBuf,
    },
    Serving {
        device_path: PathBuf,
        process_id: u32,
    },
    Leaked {
        device_path: PathBuf,
    },
}

impl KernelNbdSlot {
    pub(super) fn device_path(&self) -> &PathBuf {
        match self {
            Self::Free { device_path }
            | Self::Serving { device_path, .. }
            | Self::Leaked { device_path } => device_path,
        }
    }

    pub(super) fn is_live(&self) -> bool {
        !matches!(self, Self::Free { .. })
    }
}

pub(super) fn scan_kernel_nbd_pool(
    config: &InstalledLifecycleKernelNbdConfig,
    proc_root: &Path,
) -> Result<Vec<KernelNbdSlot>> {
    let mut slots = Vec::with_capacity(config.device_count as usize);
    for index in 0..config.device_count {
        let name = format!("nbd{index}");
        let sys = config.sys_block_root.join(&name);
        let device_path = config.device_root.join(&name);
        let size = read_small_unsigned(&sys.join("size"))?;
        if size == 0 {
            slots.push(KernelNbdSlot::Free { device_path });
            continue;
        }
        let process_id = match read_small_unsigned(&sys.join("pid")) {
            Ok(value) if value > 0 => u32::try_from(value).ok(),
            Ok(_) => None,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(error) => return Err(error).context("read active kernel-NBD process identity"),
        };
        if let Some(process_id) = process_id {
            let executable = fs::read_link(proc_root.join(process_id.to_string()).join("exe"));
            if executable
                .as_ref()
                .is_ok_and(|path| path == &config.nbd_client_binary)
            {
                slots.push(KernelNbdSlot::Serving {
                    device_path,
                    process_id,
                });
                continue;
            }
        }
        slots.push(KernelNbdSlot::Leaked { device_path });
    }
    Ok(slots)
}

fn read_small_unsigned(path: &Path) -> Result<u64> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= 64,
        "numeric sysfs attribute exceeds the closed byte bound"
    );
    let text = std::str::from_utf8(&bytes)
        .context("numeric sysfs attribute is not UTF-8")?
        .trim();
    text.parse::<u64>()
        .context("numeric sysfs attribute is malformed")
}

fn frontend_path(frontend: &ObservedFrontend) -> &Path {
    match frontend {
        ObservedFrontend::KernelNbd { device_path } => device_path,
        ObservedFrontend::VhostUserBlk { socket_path } => socket_path,
    }
}

fn frontend_id(frontend: &ObservedFrontend) -> Result<Id> {
    let path = frontend_path(frontend);
    let digest = digest_parts(
        FRONTEND_ABSENCE_RECEIPT_DOMAIN,
        &[path.as_os_str().as_encoded_bytes()],
    );
    let prefix = match frontend {
        ObservedFrontend::KernelNbd { .. } => "kernel-nbd",
        ObservedFrontend::VhostUserBlk { .. } => "vhost-user-blk",
    };
    Id::new(format!(
        "{prefix}-{}",
        digest
            .as_str()
            .strip_prefix("sha256:")
            .context("SHA-256 wire prefix is absent")?
    ))
    .context("Guest frontend identity is invalid")
}

struct BoundedCommandResult {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    output_overflow: bool,
    timed_out: bool,
}

fn run_bounded_command<I, S>(
    executable: &Path,
    arguments: I,
    deadline: Instant,
) -> Result<BoundedCommandResult>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    anyhow::ensure!(
        executable.is_absolute(),
        "command executable is not absolute"
    );
    let mut child = Command::new(executable)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(arguments)
        .spawn()
        .with_context(|| format!("spawn bounded command {}", executable.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("capture bounded command stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("capture bounded command stderr")?;
    let stdout_reader = std::thread::Builder::new()
        .name("cats-lifecycle-stdout".into())
        .spawn(move || read_bounded_stream(stdout))
        .context("spawn bounded stdout reader")?;
    let stderr_reader = std::thread::Builder::new()
        .name("cats-lifecycle-stderr".into())
        .spawn(move || read_bounded_stream(stderr))
        .context("spawn bounded stderr reader")?;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().context("poll bounded command")? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break child.wait().context("reap timed-out bounded command")?;
        }
        std::thread::sleep(std::cmp::min(
            POLL_INTERVAL,
            deadline.saturating_duration_since(Instant::now()),
        ));
    };
    let (stdout, stdout_overflow) = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("bounded stdout reader panicked"))??;
    let (stderr, stderr_overflow) = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("bounded stderr reader panicked"))??;
    Ok(BoundedCommandResult {
        status,
        stdout,
        stderr,
        output_overflow: stdout_overflow || stderr_overflow,
        timed_out,
    })
}

fn read_bounded_stream(mut stream: impl Read) -> Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream
            .read(&mut buffer)
            .context("read bounded command stream")?;
        if count == 0 {
            return Ok((retained, overflow));
        }
        let available = COMMAND_OUTPUT_MAX_BYTES.saturating_sub(retained.len());
        let keep = std::cmp::min(available, count);
        retained.extend_from_slice(&buffer[..keep]);
        overflow |= keep != count;
    }
}

fn command_failure_detail(result: &BoundedCommandResult) -> String {
    if result.timed_out {
        return "command timed out".into();
    }
    if result.output_overflow {
        return format!("command exited {} with over-limit output", result.status);
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    format!(
        "command exited {}; stderr={:?}; stdout={:?}",
        result.status,
        stderr.trim(),
        stdout.trim()
    )
}

fn scan_startup_inventory(
    config: &InstalledAtomicLifecycleConfig,
) -> Result<StartupPhysicalInventory> {
    inventory::scan_startup_inventory(config).map(|(physical, _)| physical)
}

fn collect_joined_full_inventory(
    config: &InstalledAtomicLifecycleConfig,
) -> Result<RuntimeFullInventoryScan> {
    let physical = scan_startup_inventory(config)?;
    let StartupPhysicalInventory::Complete {
        scan_id,
        collected_at_unix_ms,
        cats,
        mut unattributed_artifacts,
    } = physical
    else {
        anyhow::bail!("installed Full inventory returned an incomplete physical scan")
    };
    let startup = enumerate_startup_in_state_directory(
        &config.state_directory,
        &StartupPhysicalInventory::Complete {
            scan_id: scan_id.clone(),
            collected_at_unix_ms,
            cats: cats.clone(),
            unattributed_artifacts: unattributed_artifacts.clone(),
        },
    )
    .context("enumerate lifecycle journals for refreshed Full inventory")?;
    let mut joined = cats
        .into_iter()
        .map(|cat| (cat.cat_id.clone(), cat))
        .collect::<BTreeMap<_, _>>();
    for entry in startup.recoverable {
        let journal = observed_command_journal_record(&entry.record, &entry.journal_digest)
            .context("project lifecycle journal into refreshed Full inventory")?;
        if let Some(cat) = joined.get_mut(&entry.cat_id) {
            cat.observed_command_journal = Some(journal);
            continue;
        }
        let placement = journal_record_placement(&entry.record)?;
        anyhow::ensure!(
            placement.node_id == config.node_id,
            "lifecycle journal belongs to another Node placement"
        );
        joined.insert(
            entry.cat_id.clone(),
            ObservedCatRuntimeTelemetry {
                cat_id: entry.cat_id,
                observed_placement: placement,
                observed_command_journal: Some(journal),
                observed_physical_state: ObservedRuntimePhysicalState::Absent,
                observed_runtime_incarnation: None,
                observed_artifact_manifest_digest: digest_parts(
                    INVENTORY_DIGEST_DOMAIN,
                    &[b"journal-only-physical-absence"],
                ),
                observed_artifact_classifications: Vec::new(),
                observed_volumes: Vec::new(),
                observed_conditions: Vec::new(),
            },
        );
    }
    for blocked in startup.blocked {
        let evidence = digest_parts(
            INVENTORY_DIGEST_DOMAIN,
            &[
                blocked.cat_id.as_str().as_bytes(),
                blocked.reason.as_bytes(),
            ],
        );
        if let Some(cat) = joined.get_mut(&blocked.cat_id) {
            cat.observed_conditions.push(ObservedRuntimeCondition {
                kind: ObservedRuntimeConditionKind::Quarantined,
                evidence_digest: evidence,
            });
            cat.observed_conditions
                .sort_by_key(|condition| condition.kind);
        } else {
            unattributed_artifacts.push(
                ObservedArtifactClassification::QuarantinedForeignOrAmbiguous {
                    artifact_id: artifact_id(
                        "blocked-lifecycle-journal",
                        blocked.cat_id.as_str().as_bytes(),
                    )?,
                    evidence_digest: evidence,
                },
            );
        }
    }
    unattributed_artifacts.sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
    unattributed_artifacts.dedup_by(|left, right| left.artifact_id() == right.artifact_id());
    let cats = joined.into_values().collect::<Vec<_>>();
    inventory::ensure_no_installed_gc_candidates(&cats, &unattributed_artifacts)?;
    Ok(RuntimeFullInventoryScan {
        scan_id,
        collected_at_unix_ms,
        cats,
        unattributed_artifacts,
    })
}

fn journal_record_placement(record: &LifecycleJournalRecord) -> Result<PlacementIdentity> {
    match record {
        LifecycleJournalRecord::Command { command, .. } => command
            .decode_api()
            .map(|command| command.placement_identity)
            .context("decode lifecycle journal placement"),
        LifecycleJournalRecord::CompletedDeleteReceipt { receipt, .. } => {
            Ok(receipt.terminal_response.placement_identity.clone())
        }
    }
}

fn exact_recovered_running_projection<'a>(
    command: &LifecycleCommandEnvelope,
    response: &LifecycleCommandResponse,
    startup_inventory: &'a StartupPhysicalInventory,
) -> Result<&'a ObservedCatRuntimeTelemetry> {
    anyhow::ensure!(
        response.operation_id == command.operation_id
            && response.cat_id == command.cat_id
            && response.node_id == command.node_id
            && response.placement_identity == command.placement_identity
            && response.request_fingerprint == command.request_fingerprint,
        "terminal admission recovery response does not bind its exact command"
    );
    let StartupPhysicalInventory::Complete {
        cats,
        unattributed_artifacts,
        ..
    } = startup_inventory
    else {
        anyhow::bail!("terminal admission recovery requires a complete startup inventory")
    };
    anyhow::ensure!(
        unattributed_artifacts.is_empty(),
        "terminal admission recovery is blocked by unattributed physical artifacts"
    );
    let matches = cats
        .iter()
        .filter(|cat| cat.cat_id == command.cat_id)
        .collect::<Vec<_>>();
    let [physical] = matches.as_slice() else {
        anyhow::bail!("terminal admission recovery lacks one exact physical Cat projection")
    };
    anyhow::ensure!(
        physical.observed_command_journal.is_none()
            && physical.observed_placement == command.placement_identity
            && physical.observed_physical_state == ObservedRuntimePhysicalState::Executing,
        "terminal admission recovery physical placement/state is not exact Running"
    );
    Ok(*physical)
}

fn verify_runtime_ready_physical(
    physical: &ObservedCatRuntimeTelemetry,
    ready: &RuntimeReadyResult,
) -> Result<()> {
    anyhow::ensure!(
        physical.observed_runtime_incarnation.as_ref() == Some(&ready.runtime_incarnation),
        "RuntimeReady incarnation is not the fresh physical incarnation"
    );
    require_physical_evidence_digest(physical, &ready.runtime_config_digest, "runtime config")?;
    require_physical_evidence_digest(
        physical,
        &ready.execution_receipt_digest,
        "execution receipt",
    )?;
    require_physical_evidence_digest(
        physical,
        &ready.guest_ready_receipt_digest,
        "Guest readiness receipt",
    )?;
    verify_volume_receipts(physical, &ready.volume_receipts)
}

fn verify_effective_runtime_ready_physical(
    physical: &ObservedCatRuntimeTelemetry,
    ready: &WireEffectiveRuntimeReady,
) -> Result<()> {
    anyhow::ensure!(
        physical.observed_runtime_incarnation.as_ref() == Some(&ready.runtime_incarnation),
        "effective RuntimeReady incarnation is not the fresh physical incarnation"
    );
    require_physical_evidence_digest(physical, &ready.runtime_config_digest, "runtime config")?;
    require_physical_evidence_digest(
        physical,
        &ready.runtime_ready_receipt_digest,
        "effective RuntimeReady receipt",
    )
}

fn require_physical_evidence_digest(
    physical: &ObservedCatRuntimeTelemetry,
    expected: &Sha256Digest,
    label: &'static str,
) -> Result<()> {
    anyhow::ensure!(
        physical
            .observed_artifact_classifications
            .iter()
            .any(|artifact| match artifact {
                ObservedArtifactClassification::AdoptableCatState {
                    ownership_digest, ..
                } => ownership_digest == expected,
                ObservedArtifactClassification::CatOwnedGcCandidate { .. }
                | ObservedArtifactClassification::RetainedAuthorityOrData { .. }
                | ObservedArtifactClassification::QuarantinedForeignOrAmbiguous { .. } => false,
            }),
        "terminal admission recovery lacks exact {label} physical evidence"
    );
    Ok(())
}

fn verify_volume_receipts(
    physical: &ObservedCatRuntimeTelemetry,
    expected: &[VolumeTerminalReceipt],
) -> Result<()> {
    anyhow::ensure!(
        physical.observed_volumes.len() == expected.len(),
        "terminal Volume receipt set differs from fresh physical inventory"
    );
    for receipt in expected {
        let authority_receipt_digest = receipt
            .authority_receipt_digest
            .as_ref()
            .context("terminal Volume receipt lacks its immutable StartGrant digest")?;
        require_physical_evidence_digest(
            physical,
            authority_receipt_digest,
            "Volume StartGrant receipt",
        )?;
        let observed = physical
            .observed_volumes
            .iter()
            .find(|volume| {
                volume.volume_id == receipt.volume_id
                    && volume.disk_id == receipt.disk_id
                    && volume.disk_role == receipt.disk_role
            })
            .context("terminal Volume receipt is absent from fresh physical inventory")?;
        anyhow::ensure!(
            matches!(
                &observed.observed_attachment,
                ObservedVolumeAttachment::Owned {
                    owner_node_id,
                    attachment_id,
                    attachment_epoch,
                } if owner_node_id == &physical.observed_placement.node_id
                    && attachment_id == &receipt.attachment_id
                    && attachment_epoch == &receipt.attachment_epoch
            ),
            "terminal Volume attachment differs from fresh physical inventory"
        );
        anyhow::ensure!(
            matches!(
                observed.observed_watermark,
                ObservedVolumeWatermark::Known {
                    local_durable_generation,
                    remote_durable_generation,
                } if local_durable_generation >= receipt.local_durable_generation
                    && remote_durable_generation >= receipt.remote_durable_generation
                    && remote_durable_generation <= local_durable_generation
            ),
            "fresh physical Volume watermarks regress or contradict the terminal receipt"
        );
    }
    Ok(())
}

pub(super) fn quarantined_artifact(
    label: &str,
    evidence: &[u8],
) -> Result<ObservedArtifactClassification> {
    Ok(
        ObservedArtifactClassification::QuarantinedForeignOrAmbiguous {
            artifact_id: artifact_id(label, evidence)?,
            evidence_digest: digest_parts(INVENTORY_DIGEST_DOMAIN, &[label.as_bytes(), evidence]),
        },
    )
}

pub(super) fn artifact_id(label: &str, evidence: &[u8]) -> Result<Id> {
    let digest = digest_parts(INVENTORY_DIGEST_DOMAIN, &[label.as_bytes(), evidence]);
    Id::new(format!(
        "{}-{}",
        label,
        digest
            .as_str()
            .strip_prefix("sha256:")
            .context("SHA-256 wire prefix is absent")?
    ))
    .context("physical artifact identity is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    use cats_api::runtime_lifecycle::{
        CommandFailedResult, CommandFailureReason, DiskRole, ImmutableRuntimeConfig,
        LifecyclePredecessor, RetainedEvidence, RuntimeVolumeAuthorityInput, RuntimeVolumeConfig,
        RuntimeVolumeGuestBinding, StartSource, StartSpec, StartVolumeAuthority, StopSpec,
    };
    use cats_api::runtime_reconciliation::{
        ContractVersion, Durability, Epoch, FenceEpoch, Generation, Ipv4Address, MacAddress,
        RandomId128, RemoteHead,
    };

    use crate::lifecycle_command::journal::{
        CommandJournalState, ExactCommandResult, JournalCommandProjection, StartupJournalEntry,
    };

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn random(byte: u8) -> RandomId128 {
        RandomId128::new(format!("{byte:02x}").repeat(16)).unwrap()
    }

    fn startup_start_command(operation: &str, cat: &str) -> LifecycleCommandEnvelope {
        let placement = PlacementIdentity {
            node_id: id("node_startup_binding"),
            placement_epoch: Epoch::new(1).unwrap(),
        };
        let volume_id = id(&format!("volume_{cat}"));
        let disk_id = id(&format!("disk_{cat}"));
        let runtime_config = ImmutableRuntimeConfig::new(
            id(&format!("config_{cat}")),
            digest(1),
            2,
            512 * 1024 * 1024,
            digest(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id(&format!("network_{cat}")),
                guest_mac: MacAddress::new("02:00:00:00:00:31").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
            },
            vec![RuntimeVolumeConfig {
                volume_id: volume_id.clone(),
                disk_id: disk_id.clone(),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                // The production ABI caps virtio serials at 20 bytes; Cat
                // identity is already carried independently by the command.
                guest_device_serial: id("serial_root"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .unwrap();
        LifecycleCommandEnvelope::new(
            id(operation),
            id("workspace_startup_binding"),
            id(cat),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config,
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id(&format!("creation_{cat}")),
                target_placement: placement,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id,
                    disk_id,
                    authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                        transition_id: random(3),
                    },
                }],
                source: StartSource::Genesis,
                effect_deadline_unix_ms: UnixMillis::new(9_000_000).unwrap(),
            })),
        )
        .unwrap()
    }

    fn startup_record(
        command: &LifecycleCommandEnvelope,
        terminal: bool,
    ) -> LifecycleJournalRecord {
        let state = if terminal {
            let response = LifecycleCommandResponse::new(
                command,
                NodeResult::StartFailed(Box::new(CommandFailedResult {
                    reason: CommandFailureReason::VmmFailed,
                    not_running: ExecutionAbsenceProof {
                        stop_fence_receipt_digest: digest(4),
                        admission_closed_receipt_digest: digest(5),
                        dedicated_scope_absence_receipt_digest: digest(6),
                        frontend_absence_receipt_digest: digest(7),
                        restart_source_absence_receipt_digest: digest(8),
                    },
                    retained_evidence: RetainedEvidence {
                        artifact_manifest_digest: digest(9),
                        adoptable_count: 0,
                        gc_candidate_count: 0,
                        retained_authority_or_data_count: 0,
                        quarantined_count: 0,
                    },
                    retained_volume_receipts: Vec::new(),
                })),
            )
            .unwrap();
            CommandJournalState::Terminal {
                result: ExactCommandResult::from_api(&response).unwrap(),
                stop_fence: None,
            }
        } else {
            CommandJournalState::Accepted { stop_fence: None }
        };
        LifecycleJournalRecord::Command {
            version: 1,
            command: Box::new(JournalCommandProjection::from_api(command).unwrap()),
            superseded_predecessor: None,
            state,
        }
    }

    fn malformed_start_progress(
        command: &LifecycleCommandEnvelope,
    ) -> start::InstalledStartPhysicalInventoryEntry {
        start::InstalledStartPhysicalInventoryEntry::Executing(Box::new(
            start::InstalledRuntimeProgressManifest {
                version: ContractVersion::V1,
                node_id: command.node_id.clone(),
                cat_id: command.cat_id.clone(),
                placement_identity: command.placement_identity.clone(),
                source_lifecycle_operation_id: command.operation_id.clone(),
                request_fingerprint: command.request_fingerprint.clone(),
                runtime_config_id: command.runtime_config.config_id.clone(),
                runtime_config_digest: command.runtime_config.config_digest.clone(),
                runtime_incarnation: random(10),
                vmm: None,
                network: None,
                volumes: Vec::new(),
                artifact_classifications: Vec::new(),
                manifest_digest: digest(11),
            },
        ))
    }

    fn startup_entry(command: &LifecycleCommandEnvelope, terminal: bool) -> StartupJournalEntry {
        StartupJournalEntry {
            cat_id: command.cat_id.clone(),
            record: startup_record(command, terminal),
            journal_digest: digest(if terminal { 12 } else { 13 }),
        }
    }

    fn stop_carrier_fixture() -> (
        LifecycleCommandEnvelope,
        LifecycleCommandResponse,
        StopPredecessorPhysical,
    ) {
        let start = startup_start_command("operation_stop_fixture_start", "cat_stop_fixture");
        let receipt = VolumeTerminalReceipt {
            volume_id: start.runtime_config.volumes[0].volume_id.clone(),
            disk_id: start.runtime_config.volumes[0].disk_id.clone(),
            disk_role: DiskRole::Root,
            attachment_id: id("attachment_stop_fixture"),
            attachment_epoch: FenceEpoch::new(4).unwrap(),
            local_durable_generation: Generation::new(0).unwrap(),
            remote_durable_generation: Generation::new(0).unwrap(),
            authority_receipt_digest: Some(digest(50)),
        };
        let retained_evidence = RetainedEvidence {
            artifact_manifest_digest: digest(51),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: 1,
            quarantined_count: 0,
        };
        let predecessor = LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: id("operation_stop_fixture_predecessor"),
            workspace_id: start.workspace_id.clone(),
            cat_id: start.cat_id.clone(),
            node_id: start.node_id.clone(),
            placement_identity: start.placement_identity.clone(),
            request_fingerprint: digest(52),
            result: NodeResult::NeedsIntervention(Box::new(
                cats_api::runtime_lifecycle::NeedsInterventionResult {
                    attempted_target: cats_api::runtime_lifecycle::InterventionTarget::Warm,
                    reason:
                        cats_api::runtime_lifecycle::InterventionReason::ForeignOrAmbiguousResidue,
                    not_running: ExecutionAbsenceProof {
                        stop_fence_receipt_digest: digest(54),
                        admission_closed_receipt_digest: digest(55),
                        dedicated_scope_absence_receipt_digest: digest(56),
                        frontend_absence_receipt_digest: digest(57),
                        restart_source_absence_receipt_digest: digest(58),
                    },
                    retained_volume_receipts: vec![receipt.clone()],
                    retained_evidence: retained_evidence.clone(),
                },
            )),
        };
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        };
        let terminal_digest = lifecycle_terminal_result_digest(&terminal).unwrap();
        let command = LifecycleCommandEnvelope::new(
            id("operation_stop_fixture_current"),
            start.workspace_id,
            start.cat_id,
            start.node_id.clone(),
            start.placement_identity.clone(),
            start.runtime_config.as_ref().clone(),
            Some(predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: predecessor.operation_id.clone(),
                terminal_result_kind: predecessor.result.kind(),
                terminal_result_digest: terminal_digest.clone(),
                node_id: predecessor.node_id.clone(),
                placement_identity: predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(9_000_000).unwrap(),
            }),
        )
        .unwrap();
        let volume = StopPredecessorVolume {
            volume_id: receipt.volume_id.clone(),
            disk_id: receipt.disk_id.clone(),
            disk_role: receipt.disk_role,
            attachment_id: receipt.attachment_id.clone(),
            attachment_epoch: receipt.attachment_epoch,
            acquire_origin: AcquireOrigin::Normal {
                transition_id: random(59),
            },
            authoritative_head: RemoteHead {
                generation: Generation::new(0).unwrap(),
                root_hash: None,
                root_object_id: None,
            },
            immutable_start_grant_receipt_digest: digest(50),
            local_lineage_data_directory: Some(
                HostPath::new("/var/lib/cats/stop-fixture-lineage").unwrap(),
            ),
            predecessor_receipt: receipt,
        };
        let mut carrier = StopPredecessorPhysical {
            version: 1,
            target_operation_id: command.operation_id.clone(),
            target_request_fingerprint: command.request_fingerprint.clone(),
            target_runtime_config_id: command.runtime_config.config_id.clone(),
            target_runtime_config_digest: command.runtime_config.config_digest.clone(),
            predecessor_operation_id: predecessor.operation_id.clone(),
            predecessor_request_fingerprint: predecessor.request_fingerprint.clone(),
            predecessor_terminal_result_kind: predecessor.result.kind(),
            predecessor_terminal_result_digest: terminal_digest,
            physical_manifest_digest: retained_evidence.artifact_manifest_digest.clone(),
            runtime_incarnation: None,
            volumes: vec![volume],
            source: StopPredecessorSource::RetainedTerminal { retained_evidence },
            carrier_digest: Sha256Digest::from_bytes([0; 32]),
        };
        carrier.carrier_digest = stop_predecessor_physical_digest(&carrier).unwrap();
        (command, predecessor, carrier)
    }

    fn stop_after_start_failed_fixture() -> (LifecycleCommandEnvelope, LifecycleCommandResponse) {
        let start = startup_start_command("operation_warm_failed", "warmstop");
        let configured = &start.runtime_config.volumes[0];
        let retained_volume_receipt = VolumeTerminalReceipt {
            volume_id: configured.volume_id.clone(),
            disk_id: configured.disk_id.clone(),
            disk_role: configured.disk_role,
            attachment_id: id("attachment_suspend_warm_root"),
            attachment_epoch: FenceEpoch::new(3).unwrap(),
            local_durable_generation: Generation::new(7).unwrap(),
            remote_durable_generation: Generation::new(7).unwrap(),
            authority_receipt_digest: Some(digest(16)),
        };
        let predecessor = LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: start.operation_id.clone(),
            workspace_id: start.workspace_id.clone(),
            cat_id: start.cat_id.clone(),
            node_id: start.node_id.clone(),
            placement_identity: start.placement_identity.clone(),
            request_fingerprint: start.request_fingerprint.clone(),
            result: NodeResult::StartFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::VmmFailed,
                not_running: ExecutionAbsenceProof {
                    stop_fence_receipt_digest: digest(61),
                    admission_closed_receipt_digest: digest(62),
                    dedicated_scope_absence_receipt_digest: digest(63),
                    frontend_absence_receipt_digest: digest(64),
                    restart_source_absence_receipt_digest: digest(65),
                },
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: digest(66),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 1,
                    quarantined_count: 0,
                },
                retained_volume_receipts: vec![retained_volume_receipt],
            })),
        };
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(predecessor.clone()),
        };
        let command = LifecycleCommandEnvelope::new(
            id("operation_stop_after_warm_start_failed"),
            start.workspace_id,
            start.cat_id,
            start.node_id.clone(),
            start.placement_identity.clone(),
            start.runtime_config.as_ref().clone(),
            Some(predecessor.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: predecessor.operation_id.clone(),
                terminal_result_kind: predecessor.result.kind(),
                terminal_result_digest: lifecycle_terminal_result_digest(&terminal).unwrap(),
                node_id: predecessor.node_id.clone(),
                placement_identity: predecessor.placement_identity.clone(),
            },
            LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(9_000_000).unwrap(),
            }),
        )
        .unwrap();
        (command, predecessor)
    }

    #[test]
    fn stop_step_replays_only_its_exact_immediate_predecessor_carrier() {
        let (command, predecessor, carrier) = stop_carrier_fixture();
        validate_stop_predecessor_physical(&command, &predecessor, &carrier).unwrap();
        let step =
            execution_step(STEP_STRONG_STOP, &command, &predecessor, carrier.clone()).unwrap();
        assert_eq!(decode_step(&step, &command, &predecessor).unwrap(), carrier);

        let mut stale_operation = carrier.clone();
        stale_operation.predecessor_operation_id = id("operation_stop_fixture_stale");
        assert!(
            validate_stop_predecessor_physical(&command, &predecessor, &stale_operation).is_err()
        );
        let mut changed_manifest = carrier.clone();
        changed_manifest.physical_manifest_digest = digest(60);
        assert!(
            validate_stop_predecessor_physical(&command, &predecessor, &changed_manifest).is_err()
        );
        let mut changed_grant = carrier;
        changed_grant.volumes[0].immutable_start_grant_receipt_digest = digest(61);
        assert!(
            validate_stop_predecessor_physical(&command, &predecessor, &changed_grant).is_err()
        );
        let (_, _, mut changed_path) = stop_carrier_fixture();
        changed_path.volumes[0].local_lineage_data_directory =
            Some(HostPath::new("/var/lib/cats/stale-stop-lineage").unwrap());
        assert!(validate_stop_predecessor_physical(&command, &predecessor, &changed_path).is_err());
    }

    #[test]
    fn retained_warm_start_failed_stop_cleanup_is_exact_replay_and_tamper_closed() {
        let (command, predecessor) = stop_after_start_failed_fixture();
        let (_, carrier, authority) =
            suspend_warm::retained_warm_restart_source_chain_for_test(&command, &predecessor)
                .unwrap();
        let NodeResult::StartFailed(failed) = &predecessor.result else {
            unreachable!()
        };
        let retained_manifest_digest = &failed.retained_evidence.artifact_manifest_digest;

        validate_start_failed_warm_stop_cleanup_authority(
            &command,
            &predecessor,
            retained_manifest_digest,
            &carrier,
            &authority,
        )
        .unwrap();
        validate_start_failed_warm_stop_cleanup_authority(
            &command,
            &predecessor,
            retained_manifest_digest,
            &carrier,
            &authority,
        )
        .unwrap();

        let mut changed_authority = serde_json::to_value(&authority).unwrap();
        changed_authority["cleanup_operation_id"] = serde_json::json!("operation_stale");
        let changed_authority = serde_json::from_value(changed_authority).unwrap();
        assert!(validate_start_failed_warm_stop_cleanup_authority(
            &command,
            &predecessor,
            retained_manifest_digest,
            &carrier,
            &changed_authority,
        )
        .is_err());

        let mut changed_carrier = serde_json::to_value(&carrier).unwrap();
        changed_carrier["revocation_receipt_digest"] = serde_json::to_value(digest(67)).unwrap();
        let changed_carrier = serde_json::from_value(changed_carrier).unwrap();
        assert!(validate_start_failed_warm_stop_cleanup_authority(
            &command,
            &predecessor,
            retained_manifest_digest,
            &changed_carrier,
            &authority,
        )
        .is_err());
        assert!(validate_start_failed_warm_stop_cleanup_authority(
            &command,
            &predecessor,
            &digest(68),
            &carrier,
            &authority,
        )
        .is_err());
    }

    #[test]
    fn expired_durable_grace_deadline_clamps_to_now_for_restart_force_path() {
        let before = Instant::now();
        let deadline = unix_deadline_to_instant(UnixMillis::new(1).unwrap()).unwrap();
        let after = Instant::now();
        assert!(deadline >= before);
        assert!(deadline <= after);
    }

    #[test]
    fn startup_binding_quarantines_only_the_conflicting_nonterminal_cat() {
        let bad = startup_start_command("operation_startup_bad", "cat_startup_a");
        let good = startup_start_command("operation_startup_good", "cat_startup_b");
        let startup = LifecycleJournalStartupInventory {
            recoverable: vec![startup_entry(&bad, false), startup_entry(&good, false)],
            ..LifecycleJournalStartupInventory::default()
        };

        let bound =
            bind_installed_startup_inventory(startup, &[malformed_start_progress(&bad)]).unwrap();

        assert_eq!(bound.recoverable.len(), 1);
        assert_eq!(bound.recoverable[0].cat_id, good.cat_id);
        assert!(bound.blocked.is_empty());
        assert_eq!(bound.quarantined_commands.len(), 1);
        assert_eq!(bound.quarantined_commands[0].entry.cat_id, bad.cat_id);
        assert!(bound.quarantined_terminals.is_empty());
    }

    #[test]
    fn startup_terminal_physical_conflict_remains_recoverable_for_exact_repost() {
        let terminal = startup_start_command("operation_startup_terminal", "cat_startup_a");
        let sibling = startup_start_command("operation_startup_sibling", "cat_startup_b");
        let startup = LifecycleJournalStartupInventory {
            recoverable: vec![
                startup_entry(&terminal, true),
                startup_entry(&sibling, false),
            ],
            ..LifecycleJournalStartupInventory::default()
        };

        let bound =
            bind_installed_startup_inventory(startup, &[malformed_start_progress(&terminal)])
                .unwrap();

        assert_eq!(bound.recoverable.len(), 2);
        assert_eq!(bound.recoverable[0].cat_id, terminal.cat_id);
        assert_eq!(bound.recoverable[1].cat_id, sibling.cat_id);
        assert!(bound.blocked.is_empty());
        assert!(bound.quarantined_commands.is_empty());
        assert_eq!(bound.quarantined_terminals.len(), 1);
        assert_eq!(bound.quarantined_terminals[0].cat_id, terminal.cat_id);
    }

    #[test]
    fn exact_cat_tree_includes_children_but_not_sibling_slice() {
        let temporary = tempfile::tempdir().unwrap();
        let cgroup = temporary.path().join("cgroup");
        let proc = temporary.path().join("proc");
        fs::create_dir_all(&cgroup).unwrap();
        fs::create_dir_all(&proc).unwrap();
        let cat = id("cat_a");
        let sibling = id("cat_b");
        let service = cgroup
            .join(cat_execution_slice_id(&cat).as_str())
            .join("cats-vmm.service");
        let sibling_service = cgroup
            .join(cat_execution_slice_id(&sibling).as_str())
            .join("cats-vmm.service");
        fs::create_dir_all(&service).unwrap();
        fs::create_dir_all(&sibling_service).unwrap();
        fs::write(service.join("cgroup.procs"), b"4242\n").unwrap();
        fs::write(sibling_service.join("cgroup.procs"), b"4343\n").unwrap();
        let binary = temporary.path().join("cloud-hypervisor");
        fs::write(&binary, b"").unwrap();
        for (pid, owner) in [(4242_u32, &cat), (4343_u32, &sibling)] {
            let process = proc.join(pid.to_string());
            fs::create_dir_all(&process).unwrap();
            symlink(&binary, process.join("exe")).unwrap();
            fs::write(
                process.join("cgroup"),
                format!("0::/{}/cats-vmm.service\n", cat_execution_slice_id(owner)),
            )
            .unwrap();
        }
        let scan = scan_exact_cgroup_tree(&cgroup, &proc, &cat, &BTreeSet::from([binary])).unwrap();
        assert!(scan.slice_present);
        assert_eq!(scan.process_ids, vec![4242]);
    }

    #[test]
    fn empty_existing_cat_slice_is_not_execution_scope_absence() {
        let temporary = tempfile::tempdir().unwrap();
        let cgroup = temporary.path().join("cgroup");
        let proc = temporary.path().join("proc");
        let cat = id("cat_a");
        let slice = cgroup.join(cat_execution_slice_id(&cat).as_str());
        fs::create_dir_all(&slice).unwrap();
        fs::create_dir_all(&proc).unwrap();
        fs::write(slice.join("cgroup.procs"), b"").unwrap();
        let present = scan_exact_cgroup_tree(&cgroup, &proc, &cat, &BTreeSet::new()).unwrap();
        assert!(present.slice_present);
        assert!(present.process_ids.is_empty());

        fs::remove_file(slice.join("cgroup.procs")).unwrap();
        fs::remove_dir(slice).unwrap();
        let absent = scan_exact_cgroup_tree(&cgroup, &proc, &cat, &BTreeSet::new()).unwrap();
        assert!(!absent.slice_present);
        assert!(absent.process_ids.is_empty());
    }

    #[test]
    fn active_kernel_nbd_without_exact_client_is_leaked_not_free() {
        let temporary = tempfile::tempdir().unwrap();
        let sys = temporary.path().join("sys");
        let devices = temporary.path().join("dev");
        let proc = temporary.path().join("proc");
        fs::create_dir_all(sys.join("nbd0")).unwrap();
        fs::create_dir_all(&devices).unwrap();
        fs::create_dir_all(&proc).unwrap();
        fs::write(sys.join("nbd0/size"), b"8192\n").unwrap();
        fs::write(sys.join("nbd0/pid"), b"4242\n").unwrap();
        let config = InstalledLifecycleKernelNbdConfig {
            sys_block_root: sys,
            device_root: devices.clone(),
            nbd_client_binary: temporary.path().join("nbd-client"),
            device_count: 1,
        };
        let pool = scan_kernel_nbd_pool(&config, &proc).unwrap();
        assert!(matches!(
            pool.as_slice(),
            [KernelNbdSlot::Leaked { device_path }] if device_path == &devices.join("nbd0")
        ));
    }
}
