//! One-step execution of a current signed `ProvisionRootImage` checkpoint.
//!
//! This module is deliberately narrower than the complete root transition.
//! It can start/adopt the exact blank-head control-only process or send one
//! checkpointed provision request after a fresh full inventory proves that
//! process. Every mutation returns `RefreshInventory`; target-control reload,
//! serving handoff, and `PrepareDevice` remain separate later effects.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AppliedDesiredEvidence, CheckpointEvidence, Condition,
    ContractVersion, ControlHandshakeEvidence, DesiredRuntimeSpec, DiskKind,
    GuestTransportEvidence, HostPath, LifecycleAdmission, LocalLineageState, ObservedDiskKind,
    ObservedNetwork, ObservedRuntimeStatus, OwnershipTokenEvidence, ProcessRole, ProcessState,
    ProgressingReason, ProvisionRootImageError, RandomId128, ReconcileStep, RuntimeTarget,
    RuntimeTransition, VolumeAccess, VolumeAuthorityEvidence, VolumeDisposition, VolumeIntent,
    WarmSnapshotEvidence,
};
use cats_blockd::target_control::provision_root_image_request;
use cats_storage::authority::{AttachmentLineageIdentity, VolumeDataAuthority, VolumeRecord};
use cats_storage::BlobStore;

use crate::proc::ProcIdentity;
use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
    RuntimeDesiredEffectStopReason,
};
use crate::state_directory::StateDirectory;

use super::authorized_blockd::{
    RootProvisionStopReceipt, StopReceiptPublication, StopReceiptSettlement,
};
use super::blockd_socket_namespace::ManagedBlockdSocketOwnerRetirement;
use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::kernel_nbd::{
    KernelNbdAttachEffect, KernelNbdClientCleanupOwner, KernelNbdInventoryConfig,
};
use super::network::PrepareNetworkReservationEffect;
use super::prepare_device_retirement::PrepareDeviceTargetRetirementEffect;
use super::root_provision_process::{
    inspect_exact_root_provision_process, prove_exact_root_provision_process_absence,
    RootProvisionAbsencePurpose, RootProvisionManagedStopInspection,
    RootProvisionProcessGlobalPort, RootProvisionRetirementAdmission,
};
use super::serving_blockd_process::{ServingBlockdProcessGlobalPort, ServingBlockdStartEffect};
use super::serving_handoff::{
    target_control_process_launch_identity, ReopenedTargetControlAuthorization,
    ServingAuthorityTargetEvidence, ServingHandoffStore, TargetControlAuthorizationReady,
};
use super::serving_handoff_effect::{
    checkpoint_is_current_exact, ServingHandoffEffect, ServingHandoffEffectProgress,
    ServingPrepareDeviceEffect, ServingPrepareFrontend,
};
use super::signed_running::{
    expected_provision_heads, provision_checkpoint_is_bound, ProvisionHeadRead,
};
use super::vmm_process::VmmProcessGlobalPort;
use super::vmm_start_runtime_effect::{StartRuntimePhysicalEffect, StartRuntimeReservationEffect};
use super::{
    ensure_root_provision_process_from_persisted_checkpoint_with_socket_absence,
    AuthorizedBlockdStore, FileCheckpointStore, PersistentFilesystemEffect,
    PlatformRootProvisionProcessIdentityPort, PlatformSystemdRootProvisionProcessPort,
    RootProvisionProcessConflict, RootProvisionProcessInspection, RootProvisionProcessOutcome,
    RootProvisionProcessPort, RootProvisionProcessRetirementPort, RootProvisionProcessStop,
    RootProvisionResponseHint, RootProvisionSystemdConfig, RunningLaunchAuthorityRevalidator,
    UnixRootProvisionClient, VmmCidInventoryPort, VmmLaunchArtifactPaths,
};
use super::{AdmissionCellRegistry, RunningAdmissionEffect, SignedRunningAcquireEffect};

pub(crate) mod request_sealed {
    pub(crate) trait Sealed {}
}

trait RootProvisionRequestPort: request_sealed::Sealed + Send + Sync {
    fn execute(
        &self,
        socket_path: &HostPath,
        expected_peer_process: &ProcIdentity,
        request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionResponseHint>;
}

#[cfg(test)]
type BeforeStopReceiptPublishHook = Arc<dyn Fn() + Send + Sync>;

#[derive(Debug, Clone, Copy)]
struct PlatformRootProvisionRequestPort;

impl request_sealed::Sealed for PlatformRootProvisionRequestPort {}

impl RootProvisionRequestPort for PlatformRootProvisionRequestPort {
    fn execute(
        &self,
        socket_path: &HostPath,
        expected_peer_process: &ProcIdentity,
        request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionResponseHint> {
        context.check_active()?;
        let remaining = context
            .deadline()
            .checked_duration_since(Instant::now())
            .context("root provision effect deadline expired before control request")?;
        let client =
            UnixRootProvisionClient::new(Path::new(socket_path.as_str()), remaining, remaining);
        let reread = client
            .execute_with_context_for_peer(
                request,
                expected_peer_process,
                &PlatformRootProvisionProcessIdentityPort,
                context,
            )
            .context("send exact root provision request")?;
        Ok(reread.hint().clone())
    }
}

/// Current `ProvisionRootImage` effect. It does not handle acquisition or any
/// later serving/device step; callers dispatch here only for an exact current
/// provision checkpoint from a newly accepted full inventory.
pub(crate) struct SignedRootProvisionEffect {
    authority: Arc<dyn VolumeDataAuthority>,
    blob: Arc<dyn BlobStore>,
    process: Arc<dyn RootProvisionProcessPort>,
    retirement: Arc<dyn RootProvisionProcessRetirementPort>,
    request: Arc<dyn RootProvisionRequestPort>,
    executable_path: HostPath,
    #[cfg(test)]
    before_stop_receipt_publish: Option<BeforeStopReceiptPublishHook>,
}

/// Production dispatcher for the implemented Running prefix and the sealed
/// admission tail. The tail remains inert unless the accepted full scan owns
/// its opaque live-runtime plus Guest Ready proof. The old target-control
/// retirement stage runs first so an already-complete absence can fall
/// through, while a submitted stop consumes this full scan. A current
/// provision checkpoint remains exclusively owned by `provision`; every
/// earlier state stays with the acquire/stale planner.
pub(crate) struct SignedRunningEffect {
    running_admission: Option<RunningAdmissionEffect>,
    acquire: SignedRunningAcquireEffect,
    provision: SignedRootProvisionEffect,
    handoff: ServingHandoffEffect,
    prepare_device: ServingPrepareDeviceEffect,
    prepare_device_retirement: Option<PrepareDeviceTargetRetirementEffect>,
    serving_process: Option<ServingBlockdStartEffect>,
    kernel_nbd_attach: Option<KernelNbdAttachEffect>,
    prepare_network: Option<Arc<PrepareNetworkReservationEffect>>,
    start_runtime: Option<StartRuntimeReservationEffect>,
    persistent_filesystem: Option<PersistentFilesystemEffect>,
    physical_start_runtime: Option<StartRuntimePhysicalEffect>,
}

pub(crate) struct SignedRunningProcessPorts {
    retirement: Arc<dyn RootProvisionProcessRetirementPort>,
    root_global: Arc<dyn RootProvisionProcessGlobalPort>,
    serving_global: Arc<dyn ServingBlockdProcessGlobalPort>,
    vmm_global: Arc<dyn VmmProcessGlobalPort>,
    vmm_cid: Arc<dyn VmmCidInventoryPort>,
}

pub(crate) struct SignedRunningHostConfig {
    systemd: RootProvisionSystemdConfig,
    state_directory: StateDirectory,
    network_ip_binary: PathBuf,
    kernel_nbd_inventory: Option<KernelNbdInventoryConfig>,
    kernel_nbd_cleanup_owner: Arc<KernelNbdClientCleanupOwner>,
    vmm_launch_artifacts: VmmLaunchArtifactPaths,
}

impl SignedRunningHostConfig {
    pub(crate) fn new(
        systemd: RootProvisionSystemdConfig,
        state_directory: StateDirectory,
        network_ip_binary: PathBuf,
        kernel_nbd_inventory: Option<KernelNbdInventoryConfig>,
        kernel_nbd_cleanup_owner: Arc<KernelNbdClientCleanupOwner>,
        vmm_launch_artifacts: VmmLaunchArtifactPaths,
    ) -> Self {
        Self {
            systemd,
            state_directory,
            network_ip_binary,
            kernel_nbd_inventory,
            kernel_nbd_cleanup_owner,
            vmm_launch_artifacts,
        }
    }
}

impl SignedRunningProcessPorts {
    pub(crate) fn new(
        retirement: Arc<dyn RootProvisionProcessRetirementPort>,
        root_global: Arc<dyn RootProvisionProcessGlobalPort>,
        serving_global: Arc<dyn ServingBlockdProcessGlobalPort>,
        vmm_global: Arc<dyn VmmProcessGlobalPort>,
        vmm_cid: Arc<dyn VmmCidInventoryPort>,
    ) -> Self {
        Self {
            retirement,
            root_global,
            serving_global,
            vmm_global,
            vmm_cid,
        }
    }
}

impl SignedRunningEffect {
    pub(crate) fn platform(
        acquire: SignedRunningAcquireEffect,
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        host: SignedRunningHostConfig,
        process_ports: SignedRunningProcessPorts,
        prepare_frontend: ServingPrepareFrontend,
        admission_registry: Arc<AdmissionCellRegistry>,
    ) -> anyhow::Result<Self> {
        let SignedRunningHostConfig {
            systemd,
            state_directory,
            network_ip_binary,
            kernel_nbd_inventory,
            kernel_nbd_cleanup_owner,
            vmm_launch_artifacts,
        } = host;
        let executable = systemd
            .blockd_binary()
            .to_str()
            .context("serving handoff blockd binary is not UTF-8")?;
        let executable_path = HostPath::new(executable.to_owned())
            .context("serving handoff blockd binary is not a canonical HostPath")?;
        let target_process = Arc::new(PlatformSystemdRootProvisionProcessPort::platform(
            systemd.clone(),
            state_directory.clone(),
        ));
        let prepare_device_retirement = PrepareDeviceTargetRetirementEffect::platform(
            Arc::clone(&authority),
            Arc::clone(&process_ports.root_global),
            systemd.clone(),
            state_directory.clone(),
        );
        let serving_process_effect = ServingBlockdStartEffect::new(
            Arc::clone(&authority),
            systemd.clone(),
            Arc::clone(&process_ports.serving_global),
        );
        let kernel_nbd_attach = kernel_nbd_inventory.clone().map(|config| {
            KernelNbdAttachEffect::platform(
                Arc::clone(&authority),
                config,
                kernel_nbd_cleanup_owner,
            )
        });
        let prepare_network = Arc::new(PrepareNetworkReservationEffect::new(
            state_directory.clone(),
            network_ip_binary,
            Arc::clone(&authority),
            Arc::clone(&process_ports.serving_global),
        )?);
        let running_launch_authority = Arc::new(RunningLaunchAuthorityRevalidator::platform_parts(
            state_directory.clone(),
            systemd.clone(),
            Arc::clone(&prepare_network),
            Arc::clone(&authority),
            Arc::clone(&process_ports.serving_global),
            Arc::clone(&process_ports.vmm_global),
            kernel_nbd_inventory.clone(),
        ));
        let persistent_filesystem = PersistentFilesystemEffect::platform(
            Arc::clone(&authority),
            acquire.volume_transition_port(),
            Arc::clone(&running_launch_authority),
        );
        let running_admission = RunningAdmissionEffect::with_launch_authority(
            admission_registry,
            Arc::clone(&running_launch_authority),
        );
        let start_runtime = StartRuntimeReservationEffect::platform(
            state_directory.clone(),
            vmm_launch_artifacts.clone(),
            Arc::clone(&prepare_network),
            Arc::clone(&authority),
            Arc::clone(&process_ports.serving_global),
            process_ports.vmm_cid,
            kernel_nbd_inventory.clone(),
        );
        let physical_start_runtime = StartRuntimePhysicalEffect::platform(
            state_directory.clone(),
            vmm_launch_artifacts,
            Arc::clone(&prepare_network),
            Arc::clone(&authority),
            Arc::clone(&process_ports.serving_global),
            Arc::clone(&process_ports.vmm_global),
            kernel_nbd_inventory,
        )?;
        Ok(Self {
            running_admission: Some(running_admission),
            acquire,
            provision: SignedRootProvisionEffect::platform(
                Arc::clone(&authority),
                Arc::clone(&blob),
                systemd,
                state_directory,
                process_ports.retirement,
            )?,
            handoff: ServingHandoffEffect::new(
                Arc::clone(&authority),
                blob,
                process_ports.root_global,
                target_process,
                executable_path.clone(),
            )?,
            prepare_device: ServingPrepareDeviceEffect::new(prepare_frontend, executable_path)?
                .with_volume_authority(Arc::clone(&authority)),
            prepare_device_retirement: Some(prepare_device_retirement),
            serving_process: Some(serving_process_effect),
            kernel_nbd_attach,
            prepare_network: Some(prepare_network),
            start_runtime: Some(start_runtime),
            persistent_filesystem: Some(persistent_filesystem),
            physical_start_runtime: Some(physical_start_runtime),
        })
    }
}

impl RuntimeDesiredEffect for SignedRunningEffect {
    fn apply(
        &self,
        context: RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        if let Some(running_admission) = &self.running_admission {
            if let Some(outcome) = running_admission.try_retire(&context, desired)? {
                return Ok(outcome);
            }
            if let Some(outcome) = running_admission.try_apply(&context, desired)? {
                return Ok(outcome);
            }
        }
        if let Some(prepare_device_retirement) = &self.prepare_device_retirement {
            if let Some(outcome) = prepare_device_retirement.try_apply(&context, desired)? {
                return Ok(outcome);
            }
        }
        if let Some(serving_process) = &self.serving_process {
            if let Some(outcome) = serving_process.try_apply(&context, desired)? {
                return Ok(outcome);
            }
        }
        if let Some(kernel_nbd_attach) = &self.kernel_nbd_attach {
            if let Some(outcome) = kernel_nbd_attach.try_apply(&context, desired)? {
                return Ok(outcome);
            }
        }
        if let Some(prepare_network) = &self.prepare_network {
            if let Some(outcome) = prepare_network.try_apply(&context, desired)? {
                return Ok(outcome);
            }
        }
        if let Some(start_runtime) = &self.start_runtime {
            if let Some(outcome) = start_runtime.try_apply(&context, desired)? {
                return Ok(outcome);
            }
        }
        if let Some(persistent_filesystem) = &self.persistent_filesystem {
            if let Some(outcome) = persistent_filesystem.try_apply(&context, desired)? {
                return Ok(outcome);
            }
        }
        if let Some(physical_start_runtime) = &self.physical_start_runtime {
            if let Some(outcome) = physical_start_runtime.try_apply(&context, desired)? {
                return Ok(outcome);
            }
        }
        if let Some(outcome) = self
            .prepare_device
            .try_persist_direct_existing(&context, desired)?
        {
            return Ok(outcome);
        }
        match self.handoff.try_apply(&context, desired)? {
            ServingHandoffEffectProgress::NotApplicable => {}
            ServingHandoffEffectProgress::RefreshInventory => {
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            ServingHandoffEffectProgress::Ready(ready) => {
                self.prepare_device.persist(&context, desired, &ready)?;
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
            }
        }
        if let Some(outcome) = self.provision.try_apply(&context, desired)? {
            return Ok(outcome);
        }
        if current_prelaunch_waits_for_later_effect(&context, desired)? {
            // The remaining PrepareDevice/PrepareNetwork/StartRuntime suffix
            // is checkpoint-first. Preserve any exact current later step and
            // demand a fresh full inventory instead of falling into the
            // pre-acquire planner, which correctly rejects later phases.
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }
        self.acquire.apply(context, desired)
    }
}

fn current_prelaunch_waits_for_later_effect(
    context: &RuntimeDesiredEffectContext,
    desired: &DesiredRuntimeSpec,
) -> anyhow::Result<bool> {
    let accepted = context.accepted_full()?;
    let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired) else {
        return Ok(false);
    };
    Ok(matches!(
        runtime.step,
        ReconcileStep::PrepareDevice { .. }
            | ReconcileStep::PrepareNetwork { .. }
            | ReconcileStep::StartRuntime { .. }
    ) && signed_inventory_admission_is_exact(accepted, desired, runtime)
        && checkpoint_is_current_exact(desired, runtime))
}

impl SignedRootProvisionEffect {
    pub(crate) fn platform(
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        systemd: RootProvisionSystemdConfig,
        state_directory: StateDirectory,
        retirement: Arc<dyn RootProvisionProcessRetirementPort>,
    ) -> anyhow::Result<Self> {
        let executable = systemd
            .blockd_binary()
            .to_str()
            .context("root provision blockd binary is not UTF-8")?;
        let executable_path = HostPath::new(executable.to_owned())
            .context("root provision blockd binary is not a canonical HostPath")?;
        let process = Arc::new(PlatformSystemdRootProvisionProcessPort::platform(
            systemd,
            state_directory,
        ));
        Ok(Self {
            authority,
            blob,
            process,
            retirement,
            request: Arc::new(PlatformRootProvisionRequestPort),
            executable_path,
            #[cfg(test)]
            before_stop_receipt_publish: None,
        })
    }

    #[cfg(test)]
    fn for_test(
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        process: Arc<dyn RootProvisionProcessPort>,
        retirement: Arc<dyn RootProvisionProcessRetirementPort>,
        request: Arc<dyn RootProvisionRequestPort>,
        executable_path: HostPath,
    ) -> Self {
        Self {
            authority,
            blob,
            process,
            retirement,
            request,
            executable_path,
            before_stop_receipt_publish: None,
        }
    }

    #[cfg(test)]
    fn with_before_stop_receipt_publish(mut self, hook: BeforeStopReceiptPublishHook) -> Self {
        self.before_stop_receipt_publish = Some(hook);
        self
    }

    /// Returns `None` when the accepted current Cat is not at
    /// `ProvisionRootImage`; the acquisition/stale planner remains the sole
    /// owner of those states.
    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        context.check_active()?;
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(accepted.observation().runtimes.as_slice(), desired)
        else {
            return Ok(None);
        };
        if !matches!(runtime.step, ReconcileStep::ProvisionRootImage { .. }) {
            return Ok(None);
        }
        if !signed_inventory_admission_is_exact(accepted, desired, runtime) {
            return Ok(Some(stop_local()));
        }

        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(Some(stop_local()));
        };
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id)
            .context("open root provision checkpoint store")?;
        if checkpoint_path.as_str() != store.path().to_str().unwrap_or_default() {
            return Ok(Some(stop_local()));
        }
        let Some(stored) = store.load().context("load root provision checkpoint")? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        if stored.checkpoint().desired_revision != desired.desired_revision
            || stored.checkpoint().spec_digest != desired.spec_digest
            || stored.checkpoint().placement_epoch != desired.placement.placement_epoch
        {
            // The stale planner may replace this checkpoint only after the old
            // control-only process is absent in a later accepted full scan.
            // Retiring a live exact incarnation is one bounded physical
            // effect and never mutates the checkpoint or volume authority.
            let _node_global_effect = context.lock_node_global_effect()?;
            return if runtime.processes.is_empty() {
                self.finish_superseded_retirement(context, runtime, &store, &stored)
            } else {
                self.retire_superseded_process(context, runtime, &stored)
                    .map(Some)
            };
        }

        if !current_provision_admission_is_exact(desired, runtime) {
            return Ok(Some(stop_local()));
        }

        let Some(volume) = desired
            .volumes
            .first()
            .filter(|volume| volume.disk_kind == DiskKind::Root && volume.guest_device.slot == 0)
        else {
            return Ok(Some(stop_local()));
        };
        let (blank, target) =
            match expected_provision_heads(self.blob.as_ref(), desired, volume, context.deadline())
            {
                ProvisionHeadRead::Ready { blank, target } => (blank, target),
                ProvisionHeadRead::Retry => {
                    return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
                }
                ProvisionHeadRead::Invalid => return Ok(Some(stop_local())),
            };
        if !provision_checkpoint_is_bound(
            stored.checkpoint(),
            desired,
            volume,
            context.state_directory().path(),
            &blank,
            &target,
        ) {
            return Ok(Some(stop_local()));
        }

        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &stored.checkpoint().step
        else {
            return Ok(Some(stop_local()));
        };
        let Some((identity, observed_head)) = observed_lineage(runtime, volume, data_directory)
        else {
            return Ok(Some(stop_local()));
        };
        let prepared = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .reopen_adopted(desired, volume, &identity)
        {
            Ok(prepared) => prepared,
            Err(_) => return Ok(Some(stop_local())),
        };
        let attachment = prepared.checkpoint().attachment.clone();
        let record = match self.authority.load_volume(&volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
        };
        let expectation = match super::RootProvisionProcessExpectation::from_checkpoint(
            stored.checkpoint(),
            super::RootProvisionAuthoritySnapshot {
                attachment: attachment.clone(),
                volume: &record,
            },
            self.executable_path.clone(),
        ) {
            Ok(expectation) => expectation,
            Err(_) => return Ok(Some(stop_local())),
        };
        if record.head != observed_head || !observed_processes_are_exact(runtime, &expectation) {
            return Ok(Some(stop_local()));
        }

        if runtime.processes.is_empty() {
            let Some(socket_absence) = self
                .retirement
                .retain_start_socket_absence(&expectation, context)?
            else {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
            };
            let outcome =
                ensure_root_provision_process_from_persisted_checkpoint_with_socket_absence(
                    &store,
                    &stored,
                    super::RootProvisionAuthoritySnapshot {
                        attachment,
                        volume: &record,
                    },
                    self.executable_path.clone(),
                    socket_absence,
                    self.process.as_ref(),
                    context,
                )?;
            return Ok(Some(match outcome {
                RootProvisionProcessOutcome::Started(_)
                | RootProvisionProcessOutcome::Adopted(_)
                | RootProvisionProcessOutcome::RecoveredAfterAmbiguousStart(_)
                | RootProvisionProcessOutcome::AbsentAfterAmbiguousStart
                | RootProvisionProcessOutcome::CancelledClean
                | RootProvisionProcessOutcome::Unavailable => {
                    RuntimeDesiredEffectOutcome::RefreshInventory
                }
                RootProvisionProcessOutcome::Conflict(
                    RootProvisionProcessConflict::DuplicateIdentity
                    | RootProvisionProcessConflict::IdentityMismatch,
                )
                | RootProvisionProcessOutcome::TargetControlArtifactRequired => stop_local(),
            }));
        }

        // A target head means the data effect is already complete. The next
        // accepted scan is owned by the target-control/handoff slice; never
        // send the provision request again.
        if record.head == target {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        if record.head != blank {
            return Ok(Some(stop_local()));
        }

        let request = provision_root_image_request(stored.checkpoint())
            .context("project exact root provision request")?;
        context.check_active()?;
        let [_accepted_process] = runtime.processes.as_slice() else {
            return Ok(Some(stop_local()));
        };
        // Complete status/socket/systemd reinspection happens before the
        // provision connection is opened. The production control listener is
        // serial, so retaining the request stream while opening a second
        // status stream would deadlock both sides.
        let exact_process = match inspect_exact_root_provision_process(
            self.process.as_ref(),
            &expectation,
            context,
        )
        .context("reinspect exact root-provision process before request connect")?
        {
            RootProvisionProcessInspection::Exact(evidence)
                if accepted_process_matches_reinspection(runtime, &evidence) =>
            {
                evidence
            }
            RootProvisionProcessInspection::Exact(_)
            | RootProvisionProcessInspection::Conflict(_) => return Ok(Some(stop_local())),
            RootProvisionProcessInspection::Absent
            | RootProvisionProcessInspection::Unavailable => {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
        };
        let expected_peer_process = ProcIdentity {
            pid: exact_process.process_id,
            start_ticks: Some(exact_process.process_start_time_ticks.get()),
            exe: Some(Path::new(exact_process.executable_path.as_str()).to_path_buf()),
        };
        let hint = self.request.execute(
            &expectation.control_socket_path,
            &expected_peer_process,
            &request,
            context,
        )?;
        if matches!(
            hint,
            RootProvisionResponseHint::Unknown(
                super::RootProvisionUnknownReason::PeerIdentityMismatch
            )
        ) {
            return Ok(Some(stop_local()));
        }
        // Every non-peer outcome may follow a complete or partial request
        // write. Cancellation while waiting for the response is therefore not
        // authority to skip the mandatory point read: the remote data effect
        // may already have committed before cancellation was observed.
        let current = match self.authority.load_volume(&volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
        };
        if !same_owner_and_marker(&record, &current) {
            return Ok(Some(stop_local()));
        }
        if current.head == target {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        if current.head != blank {
            return Ok(Some(stop_local()));
        }
        if matches!(
            hint,
            RootProvisionResponseHint::Closed(ProvisionRootImageError::DefiniteConflict { .. })
        ) {
            return Ok(Some(stop_local()));
        }
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }

    fn retire_superseded_process(
        &self,
        context: &RuntimeDesiredEffectContext,
        runtime: &ObservedRuntimeStatus,
        stored: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &stored.checkpoint().step
        else {
            return Ok(stop_local());
        };
        let mut prepared = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .retain_exact_runtime_checkpoint(stored.checkpoint())
        {
            Ok(prepared) => prepared,
            Err(_) => return Ok(stop_local()),
        };
        let settlement = match prepared.settle_stop_receipt() {
            Ok(settlement) => settlement,
            Err(_) => return Ok(stop_local()),
        };
        let existing_receipt = match settlement {
            StopReceiptSettlement::Absent => None,
            StopReceiptSettlement::Recovered(_) => {
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            StopReceiptSettlement::Stable(receipt) => {
                if receipt.checkpoint_content_digest() != stored.content_digest()
                    || receipt
                        .binds_retained_values(stored.checkpoint(), prepared.checkpoint())
                        .is_err()
                {
                    return Ok(stop_local());
                }
                Some(receipt)
            }
        };
        let old_volume = &prepared.checkpoint().volume;
        let attachment = prepared.checkpoint().attachment.clone();
        let Some((identity, observed_head)) = observed_lineage(runtime, old_volume, data_directory)
        else {
            return Ok(stop_local());
        };
        if identity != attachment.identity {
            return Ok(stop_local());
        }
        context.check_active()?;
        let record = match self.authority.load_volume(&old_volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        let target_authorization = match self
            .reopen_superseded_target_authorization(context, stored, &prepared, &record)
        {
            Ok(target) => target,
            Err(_) => return Ok(stop_local()),
        };
        let expectation = match existing_receipt.as_ref() {
            Some(receipt) => receipt.expectation_for_current_authority(
                stored.checkpoint(),
                prepared.checkpoint(),
                &record,
            ),
            None => {
                if !matches!(
                    record.lease_expires_at,
                    Some(current) if current >= attachment.lease_expires_at
                ) {
                    return Ok(stop_local());
                }
                super::RootProvisionProcessExpectation::from_checkpoint(
                    stored.checkpoint(),
                    super::RootProvisionAuthoritySnapshot {
                        attachment,
                        volume: &record,
                    },
                    self.executable_path.clone(),
                )
            }
        };
        let expectation = match expectation {
            Ok(expectation) => match target_authorization.as_ref() {
                Some(target) => expectation.with_target_control_launch(
                    target_control_process_launch_identity(target.identity()),
                ),
                None => Ok(expectation),
            },
            Err(_) => return Ok(stop_local()),
        };
        let expectation = match expectation {
            Ok(expectation) => expectation,
            Err(_) => return Ok(stop_local()),
        };
        if record.head != observed_head || !observed_processes_are_exact(runtime, &expectation) {
            return Ok(stop_local());
        }
        context.check_active()?;
        let _node_global_effect = context.lock_node_global_effect()?;
        let (evidence, socket_owner) = match self
            .retirement
            .inspect_exact_stop_owner_after_node_global_sweep(&expectation, context)?
        {
            RootProvisionManagedStopInspection::Exact { process, owner }
                if accepted_process_matches_reinspection(runtime, &process) =>
            {
                (process, owner)
            }
            RootProvisionManagedStopInspection::Exact { .. }
            | RootProvisionManagedStopInspection::Conflict(_) => return Ok(stop_local()),
            RootProvisionManagedStopInspection::Absent
            | RootProvisionManagedStopInspection::Unavailable => {
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
        };
        let receipt = match RootProvisionStopReceipt::new(
            stored.checkpoint(),
            prepared.checkpoint(),
            record,
            evidence.as_ref().clone(),
            socket_owner,
            root_provision_retirement_admission(context)?,
        ) {
            Ok(receipt) => receipt,
            Err(_) => return Ok(stop_local()),
        };
        #[cfg(test)]
        let publication_result = match self.before_stop_receipt_publish.as_ref() {
            Some(hook) => prepared.persist_or_reopen_stop_receipt_with_hook(&receipt, || hook()),
            None => prepared.persist_or_reopen_stop_receipt(&receipt),
        };
        #[cfg(not(test))]
        let publication_result = prepared.persist_or_reopen_stop_receipt(&receipt);
        let publication = match publication_result {
            Ok(publication) => publication,
            Err(_) => return Ok(stop_local()),
        };
        match publication {
            StopReceiptPublication::Recovered(recovered) => {
                anyhow::ensure!(
                    recovered.process() == receipt.process(),
                    "recovered root-provision stop receipt changed process identity"
                );
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
            }
            StopReceiptPublication::Stable(existing)
            | StopReceiptPublication::Published(existing) => {
                anyhow::ensure!(
                    existing.process() == receipt.process(),
                    "stable root-provision stop receipt changed process identity"
                );
            }
        }
        let proof = match expectation.prove_exact_process(*evidence) {
            Ok(proof) => proof,
            Err(_) => return Ok(stop_local()),
        };
        prepared
            .assert_current()
            .context("revalidate retained old launch inputs before exact stop")?;
        context.check_active()?;
        Ok(match self.process.stop_exact(proof, context)? {
            RootProvisionProcessStop::Submitted
            | RootProvisionProcessStop::AlreadyAbsent
            | RootProvisionProcessStop::Unavailable => {
                RuntimeDesiredEffectOutcome::RefreshInventory
            }
            RootProvisionProcessStop::Conflict(_) => stop_local(),
        })
    }

    fn finish_superseded_retirement(
        &self,
        context: &RuntimeDesiredEffectContext,
        runtime: &ObservedRuntimeStatus,
        store: &FileCheckpointStore,
        stored: &super::StoredCheckpoint,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &stored.checkpoint().step
        else {
            return Ok(Some(stop_local()));
        };
        let retained = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .retain_exact_runtime_checkpoint(stored.checkpoint())
        {
            Ok(retained) => retained,
            Err(_) => return Ok(Some(stop_local())),
        };
        let receipt = match retained
            .settle_stop_receipt()
            .context("settle superseded root-provision stop receipt")?
        {
            StopReceiptSettlement::Absent => return Ok(None),
            StopReceiptSettlement::Recovered(_) => {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
            StopReceiptSettlement::Stable(receipt) => receipt,
        };
        if receipt.checkpoint_content_digest() != stored.content_digest()
            || receipt
                .binds_retained_values(stored.checkpoint(), retained.checkpoint())
                .is_err()
        {
            return Ok(Some(stop_local()));
        }
        let old_volume = &retained.checkpoint().volume;
        let Some((identity, observed_head)) = observed_lineage(runtime, old_volume, data_directory)
        else {
            return Ok(Some(stop_local()));
        };
        if identity != retained.checkpoint().attachment.identity {
            return Ok(Some(stop_local()));
        }
        context.check_active()?;
        let current = match self.authority.load_volume(&old_volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
        };
        if current.head != observed_head
            || receipt
                .expectation_for_current_authority(
                    stored.checkpoint(),
                    retained.checkpoint(),
                    &current,
                )
                .is_err()
        {
            return Ok(Some(stop_local()));
        }
        let target_authorization = match self
            .reopen_superseded_target_authorization(context, stored, &retained, &current)
        {
            Ok(target) => target,
            Err(_) => return Ok(Some(stop_local())),
        };
        let target_control_launch = target_authorization
            .as_ref()
            .map(|target| target_control_process_launch_identity(target.identity()));
        let _node_global_effect = context.lock_node_global_effect()?;
        let absence = match prove_exact_root_provision_process_absence(
            store,
            stored,
            super::RootProvisionAuthoritySnapshot {
                attachment: retained.checkpoint().attachment.clone(),
                volume: &current,
            },
            self.executable_path.clone(),
            RootProvisionAbsencePurpose::AdmittedStopReceipt(target_control_launch),
            self.retirement.as_ref(),
            context,
        ) {
            Ok(absence) => absence,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
        };
        if !retirement_admission_strictly_succeeds(receipt.admission(), absence.admission()) {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let expectation = receipt.expectation_for_current_authority(
            stored.checkpoint(),
            retained.checkpoint(),
            &current,
        )?;
        let retirement = self
            .retirement
            .retire_absent_socket_owner(&expectation, context)?;
        if retirement == ManagedBlockdSocketOwnerRetirement::Retired {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        retained
            .remove_stop_receipt(&receipt)
            .context("remove exact settled root-provision stop receipt")?;
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }

    fn reopen_superseded_target_authorization(
        &self,
        context: &RuntimeDesiredEffectContext,
        stored: &super::StoredCheckpoint,
        retained: &super::authorized_blockd::RetainedAuthorizedBlockd,
        current: &VolumeRecord,
    ) -> anyhow::Result<Option<Box<TargetControlAuthorizationReady>>> {
        let ReconcileStep::ProvisionRootImage {
            provision_transition_id,
            expected_blank_head,
            expected_provisioned_head,
            ..
        } = &stored.checkpoint().step
        else {
            anyhow::bail!("superseded target authorization requires provision_root_image")
        };
        if current.head == *expected_blank_head {
            return Ok(None);
        }
        anyhow::ensure!(
            current.head == *expected_provisioned_head,
            "superseded provision authority is neither its blank nor target head"
        );
        context.check_active()?;
        let authority =
            ServingAuthorityTargetEvidence::new(provision_transition_id.clone(), current.clone());
        let handoff = ServingHandoffStore::new(context.state_directory().clone());
        let reopened = handoff.reopen_target_control_authorization_from_retained(
            stored,
            retained.checkpoint(),
            &authority,
            retained,
        )?;
        context.check_active()?;
        Ok(match reopened {
            ReopenedTargetControlAuthorization::Absent => None,
            ReopenedTargetControlAuthorization::Exact(ready) => Some(ready),
        })
    }
}

fn root_provision_retirement_admission(
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<RootProvisionRetirementAdmission> {
    let accepted = context.accepted_full()?;
    let observation = accepted.observation();
    let attestation = accepted.attestation();
    Ok(RootProvisionRetirementAdmission {
        node_boot_id: observation.node_boot_id.clone(),
        agent_instance_id: observation.agent_instance_id.clone(),
        agent_session_epoch: observation.agent_session_epoch,
        inventory_epoch: observation.inventory_epoch,
        inventory_digest: attestation.inventory_digest.clone(),
        inventory_read_position: attestation.inventory_read_position,
    })
}

fn retirement_admission_strictly_succeeds(
    old: &RootProvisionRetirementAdmission,
    new: &RootProvisionRetirementAdmission,
) -> bool {
    let session_advances = new.agent_session_epoch > old.agent_session_epoch;
    let same_session_advances = new.agent_session_epoch == old.agent_session_epoch
        && new.node_boot_id == old.node_boot_id
        && new.agent_instance_id == old.agent_instance_id
        && new.inventory_epoch > old.inventory_epoch;
    (session_advances || same_session_advances)
        && new.inventory_read_position > old.inventory_read_position
}

fn unique_runtime<'a>(
    runtimes: &'a [ObservedRuntimeStatus],
    desired: &DesiredRuntimeSpec,
) -> Option<&'a ObservedRuntimeStatus> {
    let mut matching = runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let runtime = matching.next()?;
    matching.next().is_none().then_some(runtime)
}

fn signed_inventory_admission_is_exact(
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
) -> bool {
    signed_inventory_admission_is_exact_with_networks(accepted, desired, runtime, &[])
}

pub(super) fn signed_inventory_admission_is_exact_with_networks(
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    expected_networks: &[ObservedNetwork],
) -> bool {
    signed_inventory_admission_is_exact_inner(accepted, desired, runtime, expected_networks, None)
}

#[cfg(target_os = "linux")]
pub(super) fn signed_start_runtime_inventory_admission_is_exact_with_networks(
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    expected_networks: &[ObservedNetwork],
    runtime_incarnation: &RandomId128,
) -> bool {
    signed_inventory_admission_is_exact_inner(
        accepted,
        desired,
        runtime,
        expected_networks,
        Some(runtime_incarnation),
    )
}

fn signed_inventory_admission_is_exact_inner(
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    expected_networks: &[ObservedNetwork],
    runtime_incarnation: Option<&RandomId128>,
) -> bool {
    let observation = accepted.observation();
    let expected_applied = AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: desired.target,
    };
    encode_desired_runtime_spec(desired).is_ok()
        && desired.version == ContractVersion::V1
        && desired.placement.node_id == accepted.session().node_id
        && observation.complete_inventory
        && observation.node_id == accepted.session().node_id
        && observation.node_boot_id == accepted.session().node_boot_id
        && observation.agent_instance_id == accepted.session().agent_instance_id
        && observation.agent_session_epoch == accepted.session().agent_session_epoch
        && observation.inventory_epoch == accepted.attestation().inventory_epoch
        && observation.inventory_digest.as_ref() == Some(&accepted.attestation().inventory_digest)
        && observation.inventory_read_position
            == Some(accepted.attestation().inventory_read_position)
        && accepted.attestation().node_id == accepted.session().node_id
        && accepted.attestation().agent_session_epoch == accepted.session().agent_session_epoch
        && accepted.attestation().accepted_at_unix_ms < accepted.session().lease_deadline_unix_ms
        && runtime.applied_desired.as_ref() == Some(&expected_applied)
        && runtime.runtime_incarnation.as_ref() == runtime_incarnation
        && runtime.stable_state.is_none()
        && runtime.mounts.is_empty()
        && runtime.networks == expected_networks
        && matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable)
        && matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
        && runtime.lifecycle_admission == LifecycleAdmission::Closed
        && runtime.routes.is_empty()
        && runtime.platform_guards == 0
        && runtime.conditions
            == [Condition::Progressing {
                reason: ProgressingReason::ReconcileStep {
                    step: runtime.step.clone(),
                },
            }]
}

fn current_provision_admission_is_exact(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
) -> bool {
    desired.target == RuntimeTarget::Running
        && matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        && (1..=64).contains(&desired.volumes.len())
        && desired.volumes.iter().enumerate().all(|(index, volume)| {
            volume.access == VolumeAccess::ReadWriteOnce
                && matches!(volume.disposition, VolumeDisposition::Retain)
                && usize::from(volume.guest_device.slot) == index
                && match index {
                    0 => volume.disk_kind == DiskKind::Root && volume.mount.is_none(),
                    _ => volume.disk_kind == DiskKind::Persistent && volume.mount.is_some(),
                }
        })
        && runtime.processes.len() <= 1
        && runtime.volumes.len() == desired.volumes.len()
}

fn observed_lineage(
    runtime: &ObservedRuntimeStatus,
    volume: &VolumeIntent,
    expected_data_directory: &HostPath,
) -> Option<(
    AttachmentLineageIdentity,
    cats_api::runtime_reconciliation::RemoteHead,
)> {
    let observed = runtime
        .volumes
        .iter()
        .find(|observed| observed.volume_id == volume.volume_id)?;
    let [lineage] = observed.local_lineages.as_slice() else {
        return None;
    };
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return None;
    };
    (observed.volume_intent_id.as_ref() == Some(&volume.volume_intent_id)
        && observed.disk_id.as_ref() == Some(&volume.disk_id)
        && observed.volume_id == volume.volume_id
        && observed.disk_kind == ObservedDiskKind::Root
        && observed.size_bytes == Some(volume.size_bytes)
        && observed.durability == Some(volume.durability)
        && observed.devices.is_empty()
        && lineage.attachment_id == *attachment_id
        && lineage.attachment_epoch == *attachment_epoch
        && lineage.local_durable_generation == head.generation
        && lineage.remote_durable_generation == head.generation
        && lineage.pending_pack_count.get() == 0
        && lineage.data_directory == *expected_data_directory
        && !lineage.fenced
        && lineage.state == LocalLineageState::Active)
        .then(|| {
            (
                AttachmentLineageIdentity {
                    volume_id: observed.volume_id.clone(),
                    attachment_id: attachment_id.clone(),
                    attachment_epoch: *attachment_epoch,
                    acquire_origin: lineage.acquire_origin.clone(),
                    node_id: lineage.node_id.clone(),
                    placement_epoch: lineage.placement_epoch,
                },
                head.clone(),
            )
        })
}

fn observed_processes_are_exact(
    runtime: &ObservedRuntimeStatus,
    expected: &super::RootProvisionProcessExpectation,
) -> bool {
    match runtime.processes.as_slice() {
        [] => true,
        [process] => {
            matches!(
                &process.role,
                ProcessRole::Blockd {
                    volume_id,
                    attachment_id,
                    attachment_epoch,
                } if volume_id == &expected.volume_id
                    && attachment_id == &expected.attachment_id
                    && *attachment_epoch == expected.attachment_epoch
            ) && process.process_id > 0
                && process.process_start_time_ticks.get() > 0
                && process.executable_path == expected.executable_path
                && process.scope_id == expected.scope_id
                && process.control_socket_path == expected.control_socket_path
                && process.state == ProcessState::Running
                && process.ownership_token
                    == (OwnershipTokenEvidence::Valid {
                        ownership_token: expected.process_identity_token.clone(),
                    })
                && process.control_handshake == ControlHandshakeEvidence::Verified
                && process.observed_vm_shape.is_none()
        }
        _ => false,
    }
}

fn accepted_process_matches_reinspection(
    runtime: &ObservedRuntimeStatus,
    current: &super::RootProvisionProcessEvidence,
) -> bool {
    let [accepted] = runtime.processes.as_slice() else {
        return false;
    };
    accepted.process_id == current.process_id
        && accepted.process_start_time_ticks == current.process_start_time_ticks
}

fn same_owner_and_marker(before: &VolumeRecord, after: &VolumeRecord) -> bool {
    before.volume_id == after.volume_id
        && before.size_bytes == after.size_bytes
        && before.durability == after.durability
        && before.admin_state == after.admin_state
        && before.lease_owner == after.lease_owner
        && before.lease_epoch == after.lease_epoch
        && before.last_transition == after.last_transition
}

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Mutex};
    use std::time::Duration;

    use cats_api::runtime_reconciliation::{
        checkpoint_content_digest, encode_provision_root_image_request,
        encode_provision_root_image_result, inventory_digest, spec_digest, AcquireOrigin,
        AdmissionInventoryAttestation, AgentSession, AssignedKind, AssignedPlacement,
        DesiredReadSnapshot, Durability, EndpointIntent, Epoch, Ext4MountIntent, FenceEpoch,
        FilesystemInitialization, GuestDeviceIdentity, Hostname, HttpProtocol, Id, Ipv4Address,
        IsolatedIpv4Kind, LocalVolumeLineage, MacAddress, NetworkConfig, NodeBootId,
        NodeObservation, NormalAcquireRequest, NormalAcquireResult, ObservedRuntimeStatus,
        ObservedVolume, ProcessEvidence, ProvisionRootImageResult, RandomId128, RemoteHead,
        Revision, RuntimeCheckpoint, RuntimeConfig, RuntimeVolumeTransitionRequest, Sequence,
        SessionBinding, Sha256Digest, UnixMillis, VolumeAcquire, VolumeRecord, WireU64,
    };
    use cats_storage::authority::{
        AuthorityError, AuthorizedServingAttachment, LastVolumeTransition, RenewLeaseRequest,
        RenewLeaseResult, VolumeAdminState, VolumeHeadCasRequest, VolumeHeadCasResult,
    };
    use cats_storage::{
        encode_image_manifest, BlobError, ImageManifestChunkV1, ImageManifestV1, LowerHexSha256,
    };

    use crate::runtime_spine::{
        RuntimeDesiredEffectAdmission, RuntimeDesiredEffectContext, RuntimePreScanRecovery,
        RuntimePreScanRecoveryContext, RuntimePreScanRecoveryOutcome, RuntimeSpineFullScan,
    };
    use crate::state_directory::StateDirectory;

    use super::super::authorized_blockd::authorized_blockd_data_directory;
    use super::super::blockd_socket_namespace::{
        BlockdSocketIntentStore, BlockdSocketOwnershipIntentV1, CurrentBlockdSocketBoot,
        ExactManagedBlockdSocketOwnerStartAbsence, RetainedManagedBlockdSocketRoot,
    };
    use super::super::root_provision::RootProvisionProcessIdentityPort;
    use super::super::root_provision_process::{
        CheckpointedRootProvisionProcess, CheckpointedTargetControlProcess,
        RootProvisionBlockdHandshake, RootProvisionProcessEvidence, RootProvisionProcessInspection,
        RootProvisionProcessStart, TargetControlProcessPort,
    };
    use super::super::signed_running::{SignedNormalAcquirePort, SignedRunningPublicationRecovery};
    use super::super::{
        NormalAcquireAcceptedContext, NormalAcquireAttempt, NormalAcquireClientError,
        NormalReleaseAttempt,
    };
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).unwrap()
    }

    fn fence(value: u64) -> FenceEpoch {
        FenceEpoch::new(value).unwrap()
    }

    fn unix_ms(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    fn managed_test_node_boot_id() -> NodeBootId {
        NodeBootId::new("33333333333333333333333333333333").unwrap()
    }

    fn desired() -> DesiredRuntimeSpec {
        let volume = VolumeIntent {
            volume_intent_id: id("vint_root"),
            disk_id: id("disk_root"),
            volume_id: id("vol_root"),
            attachment_id: id("att_root"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-root"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: random('2'),
                expected_unowned_epoch: fence(0),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        };
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: id("ws_01"),
            cat_id: id("cat_01"),
            desired_revision: Revision::new(1).unwrap(),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: id("node_a"),
                placement_epoch: epoch(3),
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("net_01"),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: vec![volume],
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([9; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    }

    struct ExactBlob(Vec<u8>);

    impl ExactBlob {
        fn new(desired: &DesiredRuntimeSpec) -> Self {
            let manifest = ImageManifestV1 {
                version: 1,
                image_id: LowerHexSha256::from_digest(&desired.runtime.boot_image_digest),
                size_bytes: desired.volumes[0].size_bytes,
                chunks: Vec::new(),
            };
            Self(encode_image_manifest(&manifest).unwrap())
        }

        fn with_chunk(desired: &DesiredRuntimeSpec, byte: char) -> Self {
            let manifest = ImageManifestV1 {
                version: 1,
                image_id: LowerHexSha256::from_digest(&desired.runtime.boot_image_digest),
                size_bytes: desired.volumes[0].size_bytes,
                chunks: vec![ImageManifestChunkV1 {
                    chunk_idx: 0,
                    len: u32::try_from(desired.volumes[0].size_bytes).unwrap(),
                    object_id: LowerHexSha256::new(
                        std::iter::repeat_n(byte, 64).collect::<String>(),
                    )
                    .unwrap(),
                }],
            };
            Self(encode_image_manifest(&manifest).unwrap())
        }
    }

    impl BlobStore for ExactBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> Result<(), BlobError> {
            unreachable!("root provision planning never writes the image namespace")
        }

        fn get(&self, _key: &str) -> Result<Vec<u8>, BlobError> {
            Ok(self.0.clone())
        }

        fn get_bounded_until(
            &self,
            _key: &str,
            maximum: usize,
            deadline: Instant,
        ) -> Result<Vec<u8>, BlobError> {
            if Instant::now() >= deadline {
                return Err(BlobError::Backend {
                    key: "manifest".to_owned(),
                    message: "deadline".to_owned(),
                });
            }
            if self.0.len() > maximum {
                return Err(BlobError::TooLarge {
                    key: "manifest".to_owned(),
                    maximum,
                    observed_at_least: self.0.len(),
                });
            }
            Ok(self.0.clone())
        }

        fn exists(&self, _key: &str) -> Result<bool, BlobError> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> Result<(), BlobError> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> Result<Vec<String>, BlobError> {
            unreachable!()
        }
    }

    struct FakeAuthority {
        record: Mutex<VolumeRecord>,
        loads: AtomicUsize,
    }

    impl FakeAuthority {
        fn new(record: VolumeRecord) -> Self {
            Self {
                record: Mutex::new(record),
                loads: AtomicUsize::new(0),
            }
        }

        fn set_head(&self, head: cats_api::runtime_reconciliation::RemoteHead) {
            self.record.lock().unwrap().head = head;
        }

        fn set_owner(&self, owner: Id) {
            self.record.lock().unwrap().lease_owner = Some(owner);
        }

        fn set_lease_expiry(&self, expires_at: UnixMillis) {
            self.record.lock().unwrap().lease_expires_at = Some(expires_at);
        }

        fn clear_transition_marker(&self) {
            self.record.lock().unwrap().last_transition = None;
        }

        fn record(&self) -> VolumeRecord {
            self.record.lock().unwrap().clone()
        }
    }

    impl VolumeDataAuthority for FakeAuthority {
        fn load_volume(&self, volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            let record = self.record();
            (record.volume_id == *volume_id)
                .then_some(record)
                .ok_or(AuthorityError::NotFound)
        }

        fn renew_lease(
            &self,
            _request: &RenewLeaseRequest,
        ) -> Result<RenewLeaseResult, AuthorityError> {
            unreachable!()
        }

        fn compare_and_swap_head(
            &self,
            _request: &VolumeHeadCasRequest,
        ) -> Result<VolumeHeadCasResult, AuthorityError> {
            unreachable!()
        }
    }

    struct FakeProcessPort {
        inspections: AtomicUsize,
        starts: AtomicUsize,
        stops: AtomicUsize,
        inspected_identity: Option<(u32, u64)>,
        stop: RootProvisionProcessStop,
    }

    impl Default for FakeProcessPort {
        fn default() -> Self {
            Self {
                inspections: AtomicUsize::new(0),
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                inspected_identity: None,
                stop: RootProvisionProcessStop::Submitted,
            }
        }
    }

    impl FakeProcessPort {
        fn exact(process_id: u32, start_time_ticks: u64) -> Self {
            Self {
                inspections: AtomicUsize::new(0),
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                inspected_identity: Some((process_id, start_time_ticks)),
                stop: RootProvisionProcessStop::Submitted,
            }
        }
    }

    impl super::super::root_provision_process::sealed::Sealed for FakeProcessPort {}

    impl RootProvisionProcessPort for FakeProcessPort {
        fn inspect(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.inspections.fetch_add(1, Ordering::SeqCst);
            Ok(match self.inspected_identity {
                Some((process_id, start_time_ticks)) => {
                    let mut evidence = exact_process(expected);
                    evidence.process_id = process_id;
                    evidence.unit_main_process_id = process_id;
                    evidence.process_start_time_ticks = WireU64::new(start_time_ticks).unwrap();
                    evidence.cgroup_process_ids = vec![process_id];
                    evidence.handshake.peer_process_id = process_id;
                    RootProvisionProcessInspection::Exact(Box::new(evidence))
                }
                None => RootProvisionProcessInspection::Absent,
            })
        }

        fn start_checkpointed(
            &self,
            checkpointed: CheckpointedRootProvisionProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessStart> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(RootProvisionProcessStart::Started(Box::new(exact_process(
                checkpointed.expected(),
            ))))
        }

        fn stop_exact(
            &self,
            exact: super::super::root_provision_process::ExactRootProvisionProcessProof,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessStop> {
            assert_eq!(exact.evidence().process_id, 41);
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(self.stop)
        }
    }

    impl super::super::root_provision_process::target_start_sealed::Sealed for FakeProcessPort {}

    impl TargetControlProcessPort for FakeProcessPort {
        fn start_target_checkpointed(
            &self,
            checkpointed: CheckpointedTargetControlProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessStart> {
            checkpointed.assert_current()?;
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(RootProvisionProcessStart::Started(Box::new(exact_process(
                checkpointed.expected(),
            ))))
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum FakeRetirementInspection {
        Exact,
        Absent,
        Duplicate,
        Drift,
        Unavailable,
    }

    struct FakeRetirementPort {
        calls: AtomicUsize,
        inspection: FakeRetirementInspection,
        managed_boot: NodeBootId,
        after_exact_inspection: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    }

    struct AutomatonRetirementPort {
        managed: Arc<IsolatedManagedRootOwner>,
        start_absences: AtomicUsize,
        inspections: AtomicUsize,
        retirements: AtomicUsize,
    }

    fn assert_test_absent_root_admission(
        expected: &super::super::RootProvisionProcessExpectation,
        context: &RuntimeDesiredEffectContext,
        managed_boot: Option<&NodeBootId>,
    ) -> anyhow::Result<()> {
        let observation = context.accepted_full()?.observation();
        let admission = context.node_global_process()?;
        anyhow::ensure!(
            admission.matches_observation(observation),
            "test Root absence proof is bound to another accepted observation"
        );
        if let Some(managed_boot) = managed_boot {
            anyhow::ensure!(
                admission.node_boot_id() == managed_boot,
                "test Root absence proof changed its managed namespace boot"
            );
        }
        let Some((admitted, exact)) = admission.root_control(&expected.cat_id) else {
            anyhow::bail!("test Root absence proof lacks its admitted target")
        };
        anyhow::ensure!(
            admitted == expected && exact.is_none(),
            "test Root absence proof is not bound to the exact admitted absent target"
        );
        Ok(())
    }

    impl super::super::root_provision_process::retirement_sealed::Sealed for AutomatonRetirementPort {}

    impl RootProvisionProcessRetirementPort for AutomatonRetirementPort {
        fn inspect_exact_stop_owner_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionManagedStopInspection> {
            self.managed.assert_same_owner(expected)?;
            self.inspections.fetch_add(1, Ordering::SeqCst);
            Ok(RootProvisionManagedStopInspection::Exact {
                process: Box::new(exact_process(expected)),
                owner: super::super::blockd_socket_namespace::ManagedBlockdRootStopOwnerEvidence::for_test(
                    expected,
                    context.accepted_full()?.observation().node_boot_id.clone(),
                )?,
            })
        }

        fn retire_absent_socket_owner(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<ManagedBlockdSocketOwnerRetirement> {
            self.managed.assert_same_owner(expected)?;
            assert_test_absent_root_admission(
                expected,
                context,
                Some(self.managed.boot.node_boot_id()),
            )?;
            let absence = self.managed.sealed_absence(context);
            let retired = self.managed.root.retire_absent_owner(
                &self.managed.intents,
                &self.managed.intent,
                &self.managed.boot,
                absence,
            )?;
            self.retirements.fetch_add(1, Ordering::SeqCst);
            Ok(retired)
        }

        fn inspect_absent_with_admitted_stop_receipt(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.managed.assert_same_owner(expected)?;
            assert_test_absent_root_admission(
                expected,
                context,
                Some(self.managed.boot.node_boot_id()),
            )?;
            self.inspections.fetch_add(1, Ordering::SeqCst);
            Ok(RootProvisionProcessInspection::Absent)
        }

        fn retain_start_socket_absence(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<Option<ExactManagedBlockdSocketOwnerStartAbsence>> {
            self.managed.assert_same_owner(expected)?;
            assert_test_absent_root_admission(
                expected,
                context,
                Some(self.managed.boot.node_boot_id()),
            )?;
            self.start_absences.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.managed.sealed_absence(context)))
        }

        fn inspect_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.managed.assert_same_owner(expected)?;
            assert_test_absent_root_admission(
                expected,
                context,
                Some(self.managed.boot.node_boot_id()),
            )?;
            self.inspections.fetch_add(1, Ordering::SeqCst);
            Ok(RootProvisionProcessInspection::Absent)
        }
    }

    impl FakeRetirementPort {
        fn with_inspection(inspection: FakeRetirementInspection) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                inspection,
                managed_boot: managed_test_node_boot_id(),
                after_exact_inspection: Mutex::new(None),
            }
        }

        fn exact() -> Self {
            Self::with_inspection(FakeRetirementInspection::Exact)
        }

        fn absent() -> Self {
            Self::with_inspection(FakeRetirementInspection::Absent)
        }

        fn unavailable() -> Self {
            Self::with_inspection(FakeRetirementInspection::Unavailable)
        }

        fn exact_with_hook(hook: Arc<dyn Fn() + Send + Sync>) -> Self {
            let port = Self::exact();
            *port.after_exact_inspection.lock().unwrap() = Some(hook);
            port
        }

        fn inspection(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
        ) -> RootProvisionProcessInspection {
            match self.inspection {
                FakeRetirementInspection::Exact => {
                    RootProvisionProcessInspection::Exact(Box::new(exact_process(expected)))
                }
                FakeRetirementInspection::Absent => RootProvisionProcessInspection::Absent,
                FakeRetirementInspection::Duplicate => RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::DuplicateIdentity,
                ),
                FakeRetirementInspection::Drift => {
                    let mut evidence = exact_process(expected);
                    evidence.process_start_time_ticks = WireU64::new(43).unwrap();
                    RootProvisionProcessInspection::Exact(Box::new(evidence))
                }
                FakeRetirementInspection::Unavailable => {
                    RootProvisionProcessInspection::Unavailable
                }
            }
        }
    }

    impl super::super::root_provision_process::retirement_sealed::Sealed for FakeRetirementPort {}
    impl super::super::root_provision_process::global_sealed::Sealed for FakeRetirementPort {}

    impl RootProvisionProcessGlobalPort for FakeRetirementPort {
        fn inspect_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            _context: &crate::runtime_spine::RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.inspection(expected))
        }
    }

    impl RootProvisionProcessRetirementPort for FakeRetirementPort {
        fn inspect_exact_stop_owner_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionManagedStopInspection> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let inspection = self.inspection(expected);
            if let Some(hook) = self.after_exact_inspection.lock().unwrap().take() {
                hook();
            }
            Ok(match inspection {
                RootProvisionProcessInspection::Exact(process) => {
                    let node_boot_id = context.accepted_full()?.observation().node_boot_id.clone();
                    RootProvisionManagedStopInspection::Exact {
                        process,
                        owner: super::super::blockd_socket_namespace::ManagedBlockdRootStopOwnerEvidence::for_test(
                            expected,
                            node_boot_id,
                        )?,
                    }
                }
                RootProvisionProcessInspection::Absent => {
                    RootProvisionManagedStopInspection::Absent
                }
                RootProvisionProcessInspection::Conflict(conflict) => {
                    RootProvisionManagedStopInspection::Conflict(conflict)
                }
                RootProvisionProcessInspection::Unavailable => {
                    RootProvisionManagedStopInspection::Unavailable
                }
            })
        }

        fn retire_absent_socket_owner(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<ManagedBlockdSocketOwnerRetirement> {
            anyhow::ensure!(
                matches!(self.inspection, FakeRetirementInspection::Absent),
                "test retirement may report AlreadyAbsent only after an absent process inspection"
            );
            let installed =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .root_paths(&expected.provision_transition_id)?;
            anyhow::ensure!(
                installed.control_socket() == &expected.control_socket_path,
                "test retirement expectation changed its installed managed socket mapping"
            );
            assert_test_absent_root_admission(expected, context, Some(&self.managed_boot))?;
            Ok(ManagedBlockdSocketOwnerRetirement::AlreadyAbsent)
        }

        fn inspect_exact_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let inspection = self.inspection(expected);
            if let Some(hook) = self.after_exact_inspection.lock().unwrap().take() {
                hook();
            }
            Ok(inspection)
        }

        fn inspect_absent_with_admitted_stop_receipt(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            if matches!(self.inspection, FakeRetirementInspection::Absent) {
                assert_test_absent_root_admission(expected, context, Some(&self.managed_boot))?;
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.inspection(expected))
        }

        fn inspect_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            if matches!(self.inspection, FakeRetirementInspection::Absent) {
                assert_test_absent_root_admission(expected, context, Some(&self.managed_boot))?;
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.inspection(expected))
        }
    }

    #[derive(Default)]
    struct TargetLaunchRetirementPort {
        calls: AtomicUsize,
    }

    impl super::super::root_provision_process::retirement_sealed::Sealed
        for TargetLaunchRetirementPort
    {
    }

    impl RootProvisionProcessRetirementPort for TargetLaunchRetirementPort {
        fn inspect_exact_stop_owner_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionManagedStopInspection> {
            anyhow::ensure!(
                expected.target_control_launch().is_some(),
                "target-wrapper retirement lost its sealed launch identity"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(RootProvisionManagedStopInspection::Exact {
                process: Box::new(exact_process(expected)),
                owner: super::super::blockd_socket_namespace::ManagedBlockdRootStopOwnerEvidence::for_test(
                    expected,
                    context.accepted_full()?.observation().node_boot_id.clone(),
                )?,
            })
        }

        fn inspect_exact_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            anyhow::ensure!(
                expected.target_control_launch().is_some(),
                "target-wrapper retirement lost its sealed launch identity"
            );
            Ok(RootProvisionProcessInspection::Exact(Box::new(
                exact_process(expected),
            )))
        }

        fn inspect_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.inspect_exact_after_node_global_sweep(expected, context)
        }
    }

    struct FakeRequestPort {
        authority: Arc<FakeAuthority>,
        calls: AtomicUsize,
        conflict: bool,
        mutate_owner: bool,
        connect_failure: bool,
        identity_mismatch: bool,
    }

    #[derive(Default)]
    struct NoSignedMutationPort {
        calls: AtomicUsize,
    }

    impl SignedNormalAcquirePort for NoSignedMutationPort {
        fn acquire(
            &self,
            _request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _accepted: &NormalAcquireAcceptedContext,
            _deadline: Instant,
        ) -> Result<NormalAcquireAttempt, NormalAcquireClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(NormalAcquireAttempt::RefreshInventory)
        }

        fn release(
            &self,
            _request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _expected_head: &RemoteHead,
            _accepted: &NormalAcquireAcceptedContext,
            _deadline: Instant,
        ) -> Result<NormalReleaseAttempt, NormalAcquireClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(NormalReleaseAttempt::RefreshInventory)
        }
    }

    impl request_sealed::Sealed for FakeRequestPort {}

    impl RootProvisionRequestPort for FakeRequestPort {
        fn execute(
            &self,
            _socket_path: &HostPath,
            expected_peer_process: &ProcIdentity,
            request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionResponseHint> {
            context.check_active()?;
            assert_eq!(
                expected_peer_process,
                &ProcIdentity {
                    pid: 41,
                    start_ticks: Some(42),
                    exe: Some(Path::new("/usr/bin/cats-blockd").to_path_buf()),
                }
            );
            if self.connect_failure {
                return Ok(RootProvisionResponseHint::Unknown(
                    super::super::RootProvisionUnknownReason::Connect,
                ));
            }
            if self.identity_mismatch {
                return Ok(RootProvisionResponseHint::Unknown(
                    super::super::RootProvisionUnknownReason::PeerIdentityMismatch,
                ));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.conflict {
                return Ok(RootProvisionResponseHint::Closed(
                    ProvisionRootImageError::DefiniteConflict {
                        provision_transition_id: request.provision_transition_id.clone(),
                        volume_id: request.volume_id.clone(),
                        attachment_id: request.attachment_id.clone(),
                        attachment_epoch: request.attachment_epoch,
                        problem: cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::RequestBinding,
                    },
                ));
            }
            self.authority
                .set_head(request.expected_provisioned_head.clone());
            if self.mutate_owner {
                self.authority.set_owner(id("foreign_owner"));
            }
            Ok(RootProvisionResponseHint::Unknown(
                super::super::RootProvisionUnknownReason::Eof,
            ))
        }
    }

    struct SerialStatusProcessPort {
        inspections: AtomicUsize,
        process_id: u32,
        start_time_ticks: u64,
        socket_path: PathBuf,
    }

    impl super::super::root_provision_process::sealed::Sealed for SerialStatusProcessPort {}

    impl RootProvisionProcessPort for SerialStatusProcessPort {
        fn inspect(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            context.check_active()?;
            self.inspections.fetch_add(1, Ordering::SeqCst);
            let mut stream = UnixStream::connect(&self.socket_path)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            stream.write_all(b"status\n")?;
            let mut response = [0_u8; 10];
            stream.read_exact(&mut response)?;
            anyhow::ensure!(
                &response == b"status-ok\n",
                "serial status calibration failed"
            );

            let mut evidence = exact_process(expected);
            evidence.process_id = self.process_id;
            evidence.unit_main_process_id = self.process_id;
            evidence.process_start_time_ticks = WireU64::new(self.start_time_ticks).unwrap();
            evidence.cgroup_process_ids = vec![self.process_id];
            evidence.handshake.peer_process_id = self.process_id;
            Ok(RootProvisionProcessInspection::Exact(Box::new(evidence)))
        }

        fn start_checkpointed(
            &self,
            _checkpointed: CheckpointedRootProvisionProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessStart> {
            unreachable!("serial-listener regression starts with an accepted live process")
        }
    }

    #[derive(Clone)]
    struct FixedProcessIdentity(ProcIdentity);

    impl RootProvisionProcessIdentityPort for FixedProcessIdentity {
        fn sample(&self, process_id: u32) -> ProcIdentity {
            assert_eq!(process_id, self.0.pid);
            self.0.clone()
        }
    }

    struct SerialRequestPort {
        process_identity: FixedProcessIdentity,
        socket_path: PathBuf,
        calls: AtomicUsize,
    }

    impl request_sealed::Sealed for SerialRequestPort {}

    impl RootProvisionRequestPort for SerialRequestPort {
        fn execute(
            &self,
            _socket_path: &HostPath,
            expected_peer_process: &ProcIdentity,
            request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionResponseHint> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let remaining = context.deadline().saturating_duration_since(Instant::now());
            Ok(
                UnixRootProvisionClient::new(&self.socket_path, remaining, remaining)
                    .execute_with_context_for_peer(
                        request,
                        expected_peer_process,
                        &self.process_identity,
                        context,
                    )?
                    .hint()
                    .clone(),
            )
        }
    }

    fn accept_before(listener: &UnixListener, deadline: Instant) -> UnixStream {
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "serial listener accept timed out"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("serial listener accept failed: {error}"),
            }
        }
    }

    struct Fixture {
        _root: tempfile::TempDir,
        state: StateDirectory,
        desired: DesiredRuntimeSpec,
        checkpoint: RuntimeCheckpoint,
        attachment: AuthorizedServingAttachment,
        authority: Arc<FakeAuthority>,
        blob: Arc<ExactBlob>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::new_with_desired(desired())
        }

        fn new_with_desired(desired: DesiredRuntimeSpec) -> Self {
            let root = tempfile::Builder::new()
                .prefix("rp-")
                .tempdir_in("/tmp")
                .unwrap();
            let state = StateDirectory::unanchored(root.path().to_path_buf());
            let blob = Arc::new(ExactBlob::new(&desired));
            let ProvisionHeadRead::Ready { blank, target } = expected_provision_heads(
                blob.as_ref(),
                &desired,
                &desired.volumes[0],
                Instant::now() + Duration::from_secs(2),
            ) else {
                panic!("fixed manifest must produce exact provision heads")
            };
            let volume = &desired.volumes[0];
            let VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            } = &volume.acquire
            else {
                unreachable!()
            };
            let identity = AttachmentLineageIdentity {
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: fence(1),
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: transition_id.clone(),
                },
                node_id: desired.placement.node_id.clone(),
                placement_epoch: desired.placement.placement_epoch,
            };
            let request = NormalAcquireRequest {
                volume_id: volume.volume_id.clone(),
                transition_id: transition_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                expected_unowned_epoch: *expected_unowned_epoch,
                desired_revision: desired.desired_revision,
                placement_epoch: desired.placement.placement_epoch,
                lease_duration_ms: 60_000,
            };
            let result = NormalAcquireResult {
                volume_id: volume.volume_id.clone(),
                transition_id: transition_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                resulting_epoch: identity.attachment_epoch,
                resulting_head: blank.clone(),
                lease_expires_at: unix_ms(1_900_000_060_000),
            };
            let attachment = AuthorizedServingAttachment {
                identity: identity.clone(),
                size_bytes: volume.size_bytes,
                durability: volume.durability,
                head: blank.clone(),
                lease_expires_at: result.lease_expires_at,
                acquire: cats_storage::authority::AuthorizedServingAcquire::Normal {
                    request: request.clone(),
                    result: result.clone(),
                },
            };
            drop(
                AuthorizedBlockdStore::new(state.clone())
                    .prepare(&desired, volume, &attachment)
                    .unwrap(),
            );
            let data_directory =
                authorized_blockd_data_directory(state.path(), &desired, &attachment.identity);
            let data_directory =
                HostPath::new(data_directory.to_str().unwrap().to_owned()).unwrap();
            let process_token = random('4');
            let provision_transition_id = random('3');
            let control_socket_path =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .root_paths(&provision_transition_id)
                    .unwrap()
                    .control_socket()
                    .clone();
            let step = ReconcileStep::ProvisionRootImage {
                provision_transition_id,
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                scope_id: id(&format!("cats-root-{}.service", process_token.as_str())),
                control_socket_path,
                data_directory: data_directory.clone(),
                process_identity_token: process_token,
                size_bytes: volume.size_bytes,
                boot_image_digest: desired.runtime.boot_image_digest.clone(),
                expected_blank_head: blank.clone(),
                expected_provisioned_head: target,
            };
            let checkpoint = RuntimeCheckpoint {
                version: ContractVersion::V1,
                cat_id: desired.cat_id.clone(),
                node_id: desired.placement.node_id.clone(),
                placement_epoch: desired.placement.placement_epoch,
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                runtime_incarnation: None,
                runtime_launch: cats_api::runtime_reconciliation::RuntimeLaunch::Absent,
                stable_state: None,
                step,
                processes: Vec::new(),
                volumes: vec![observed_volume(
                    &desired,
                    &attachment,
                    &blank,
                    &data_directory,
                )],
                mounts: Vec::new(),
                networks: Vec::new(),
                guest_transport: GuestTransportEvidence::Unavailable,
                warm_snapshot: WarmSnapshotEvidence::Absent,
                lifecycle_admission: LifecycleAdmission::Closed,
                route_gates: Vec::new(),
                require_idle:
                    cats_api::runtime_reconciliation::RequireIdleCheckpoint::NotApplicable,
                updated_at_unix_ms: unix_ms(1_900_000_000_000),
            };
            let checkpoint_directory = state.path().join(CHECKPOINT_NAMESPACE);
            std::fs::create_dir(&checkpoint_directory).unwrap();
            let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id).unwrap();
            store.create(&checkpoint).unwrap();
            drop(store);
            let authority = Arc::new(FakeAuthority::new(VolumeRecord {
                volume_id: volume.volume_id.clone(),
                size_bytes: volume.size_bytes,
                durability: volume.durability,
                admin_state: VolumeAdminState::Active,
                head: blank,
                lease_owner: Some(volume.attachment_id.clone()),
                lease_epoch: attachment.identity.attachment_epoch,
                lease_expires_at: Some(attachment.lease_expires_at),
                last_transition: Some(LastVolumeTransition::NormalAcquire { request, result }),
            }));
            Self {
                _root: root,
                state,
                desired,
                checkpoint,
                attachment,
                authority,
                blob,
            }
        }

        fn context(&self, processes: Vec<ProcessEvidence>) -> RuntimeDesiredEffectContext {
            self.context_at(processes, 4, 12)
        }

        fn context_at(
            &self,
            processes: Vec<ProcessEvidence>,
            inventory_epoch: u64,
            inventory_read_position: u64,
        ) -> RuntimeDesiredEffectContext {
            self.context_with_lineage_path_at(
                processes,
                None,
                inventory_epoch,
                inventory_read_position,
            )
        }

        fn context_at_with_stop_receipt(
            &self,
            physical_paths: impl IntoIterator<Item = HostPath>,
            inventory_epoch: u64,
            inventory_read_position: u64,
        ) -> RuntimeDesiredEffectContext {
            let expectation = super::super::RootProvisionProcessExpectation::from_checkpoint(
                &self.checkpoint,
                super::super::root_provision_process::RootProvisionAuthoritySnapshot {
                    attachment: self.attachment.clone(),
                    volume: &self.authority.record(),
                },
                HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
            )
            .unwrap();
            let cat_id = expectation.cat_id.clone();
            let receipt_socket = expectation.control_socket_path.clone();
            let admission = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
                std::collections::BTreeMap::from([(cat_id.clone(), expectation)]),
                std::collections::BTreeMap::new(),
            )
            .unwrap()
            .with_stop_receipt_sockets(std::collections::BTreeMap::from([(
                cat_id,
                super::super::root_provision_process::StopReceiptSocketAdmission::new(
                    receipt_socket,
                    physical_paths.into_iter().collect(),
                )
                .unwrap(),
            )]))
            .unwrap()
            .into_admission_for_test();
            let context = self.context_at(Vec::new(), inventory_epoch, inventory_read_position);
            let admission = admission
                .rebind_for_test(context.accepted_full().unwrap().observation())
                .unwrap();
            context.with_node_global_process_for_test(admission)
        }

        fn context_at_with_absent_root(
            &self,
            expectation: super::super::RootProvisionProcessExpectation,
            inventory_epoch: u64,
            inventory_read_position: u64,
        ) -> RuntimeDesiredEffectContext {
            let cat_id = expectation.cat_id.clone();
            let admission = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
                std::collections::BTreeMap::from([(cat_id, expectation)]),
                std::collections::BTreeMap::new(),
            )
            .unwrap()
            .into_admission_for_test();
            let context = self.context_at(Vec::new(), inventory_epoch, inventory_read_position);
            let admission = admission
                .rebind_for_test(context.accepted_full().unwrap().observation())
                .unwrap();
            context.with_node_global_process_for_test(admission)
        }

        fn context_at_with_managed_stop_receipt_evidence(
            &self,
            expectation: super::super::RootProvisionProcessExpectation,
            receipt: &RootProvisionStopReceipt,
            inventory_epoch: u64,
            inventory_read_position: u64,
        ) -> RuntimeDesiredEffectContext {
            let cat_id = expectation.cat_id.clone();
            let socket =
                super::super::root_provision_process::StopReceiptSocketAdmission::from_managed(
                    receipt.socket_owner().clone(),
                );
            let admission = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
                std::collections::BTreeMap::from([(cat_id.clone(), expectation)]),
                std::collections::BTreeMap::new(),
            )
            .unwrap()
            .with_stop_receipt_sockets(std::collections::BTreeMap::from([(cat_id, socket)]))
            .unwrap()
            .into_admission_for_test();
            let context = self.context_at(Vec::new(), inventory_epoch, inventory_read_position);
            let admission = admission
                .rebind_for_test(context.accepted_full().unwrap().observation())
                .unwrap();
            context.with_node_global_process_for_test(admission)
        }

        fn context_with_lineage_path(
            &self,
            processes: Vec<ProcessEvidence>,
            lineage_path: Option<HostPath>,
        ) -> RuntimeDesiredEffectContext {
            self.context_with_lineage_path_at(processes, lineage_path, 4, 12)
        }

        fn context_with_lineage_path_at(
            &self,
            processes: Vec<ProcessEvidence>,
            lineage_path: Option<HostPath>,
            inventory_epoch: u64,
            inventory_read_position: u64,
        ) -> RuntimeDesiredEffectContext {
            let mut runtime = ObservedRuntimeStatus {
                cat_id: self.desired.cat_id.clone(),
                applied_desired: Some(AppliedDesiredEvidence {
                    desired_revision: self.desired.desired_revision,
                    spec_digest: self.desired.spec_digest.clone(),
                    placement: self.desired.placement.clone(),
                    target: self.desired.target,
                }),
                runtime_incarnation: None,
                stable_state: None,
                step: self.checkpoint.step.clone(),
                checkpoint: CheckpointEvidence::Valid {
                    checkpoint_path: HostPath::new(
                        super::super::runtime_checkpoint_path(
                            &self.state.path().join(CHECKPOINT_NAMESPACE),
                            &self.desired.cat_id,
                        )
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    )
                    .unwrap(),
                    content_digest: checkpoint_content_digest(&self.checkpoint).unwrap(),
                    version: self.checkpoint.version,
                    cat_id: self.checkpoint.cat_id.clone(),
                    node_id: self.checkpoint.node_id.clone(),
                    desired_revision: self.checkpoint.desired_revision,
                    spec_digest: self.checkpoint.spec_digest.clone(),
                    placement_epoch: self.checkpoint.placement_epoch,
                    runtime_incarnation: None,
                    runtime_launch: Box::new(self.checkpoint.runtime_launch.clone()),
                    stable_state: None,
                    step: Box::new(self.checkpoint.step.clone()),
                    require_idle: Box::new(self.checkpoint.require_idle.clone()),
                    updated_at_unix_ms: self.checkpoint.updated_at_unix_ms,
                },
                processes,
                volumes: vec![observed_volume(
                    &self.desired,
                    &self.attachment,
                    &self.authority.record().head,
                    match &self.checkpoint.step {
                        ReconcileStep::ProvisionRootImage { data_directory, .. } => data_directory,
                        ReconcileStep::PrepareDevice { devices } => {
                            &devices[0].serving_process.data_directory
                        }
                        _ => unreachable!(),
                    },
                )],
                mounts: Vec::new(),
                networks: Vec::new(),
                guest_transport: GuestTransportEvidence::Unavailable,
                warm_snapshot: WarmSnapshotEvidence::Absent,
                lifecycle_admission: LifecycleAdmission::Closed,
                routes: Vec::new(),
                platform_guards: 0,
                conditions: vec![Condition::Progressing {
                    reason: ProgressingReason::ReconcileStep {
                        step: self.checkpoint.step.clone(),
                    },
                }],
            };
            if let Some(lineage_path) = lineage_path {
                runtime.volumes[0].local_lineages[0].data_directory = lineage_path;
            }
            let session = AgentSession {
                version: ContractVersion::V1,
                node_id: self.desired.placement.node_id.clone(),
                immutable_host_id: id("host_a"),
                node_boot_id: managed_test_node_boot_id(),
                agent_instance_id: random('5'),
                agent_session_epoch: epoch(2),
                registration_attempt_id: random('6'),
                guest_config_digest: self.desired.runtime.guest_config_digest.clone(),
                lease_deadline_unix_ms: unix_ms(1_900_000_120_000),
            };
            let digest = Sha256Digest::from_bytes([7; 32]);
            let attestation = AdmissionInventoryAttestation {
                version: ContractVersion::V1,
                node_id: session.node_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
                inventory_epoch: epoch(inventory_epoch),
                inventory_digest: digest.clone(),
                inventory_read_position: Sequence::new(inventory_read_position).unwrap(),
                accepted_at_unix_ms: unix_ms(1_900_000_000_000),
            };
            let mut observation = NodeObservation {
                version: ContractVersion::V1,
                observation_id: random('7'),
                node_id: session.node_id.clone(),
                node_boot_id: session.node_boot_id.clone(),
                agent_instance_id: session.agent_instance_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
                heartbeat_sequence: Sequence::new(9).unwrap(),
                observed_at_unix_ms: unix_ms(1_899_999_999_000),
                complete_inventory: true,
                inventory_epoch: attestation.inventory_epoch,
                inventory_digest: Some(digest),
                inventory_read_position: Some(attestation.inventory_read_position),
                key_ring_version: None,
                key_ring_digest: None,
                loaded_kids: Vec::new(),
                runtimes: vec![runtime],
                residue: Vec::new(),
            };
            // The admission constructor only requires equality with its
            // attestation, but use the real digest to keep this a valid wire
            // observation rather than a synthetic bypass.
            let digest = inventory_digest(&observation).unwrap();
            observation.inventory_digest = Some(digest.clone());
            let mut attestation = attestation;
            attestation.inventory_digest = digest;
            RuntimeDesiredEffectContext::for_test_with_admission(
                self.state.clone(),
                Instant::now() + Duration::from_secs(10),
                RuntimeDesiredEffectAdmission::for_test(session, observation, attestation),
            )
        }

        fn public_process(&self) -> ProcessEvidence {
            let ReconcileStep::ProvisionRootImage {
                volume_id,
                attachment_id,
                attachment_epoch,
                scope_id,
                control_socket_path,
                process_identity_token,
                ..
            } = &self.checkpoint.step
            else {
                unreachable!()
            };
            ProcessEvidence {
                role: ProcessRole::Blockd {
                    volume_id: volume_id.clone(),
                    attachment_id: attachment_id.clone(),
                    attachment_epoch: *attachment_epoch,
                },
                process_id: 41,
                process_start_time_ticks: WireU64::new(42).unwrap(),
                executable_path: HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
                scope_id: scope_id.clone(),
                control_socket_path: control_socket_path.clone(),
                state: ProcessState::Running,
                ownership_token: OwnershipTokenEvidence::Valid {
                    ownership_token: process_identity_token.clone(),
                },
                control_handshake: ControlHandshakeEvidence::Verified,
                observed_vm_shape: None,
            }
        }

        fn stop_receipt_path(&self) -> PathBuf {
            let ReconcileStep::ProvisionRootImage { data_directory, .. } = &self.checkpoint.step
            else {
                unreachable!()
            };
            Path::new(data_directory.as_str())
                .join(super::super::authorized_blockd::ROOT_PROVISION_STOP_RECEIPT_FILE)
        }

        fn root_process_expectation(&self) -> super::super::RootProvisionProcessExpectation {
            super::super::RootProvisionProcessExpectation::from_checkpoint(
                &self.checkpoint,
                super::super::root_provision_process::RootProvisionAuthoritySnapshot {
                    attachment: self.attachment.clone(),
                    volume: &self.authority.record(),
                },
                HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
            )
            .unwrap()
        }

        fn effect(
            &self,
            process: Arc<FakeProcessPort>,
            request: Arc<FakeRequestPort>,
        ) -> SignedRootProvisionEffect {
            self.effect_with_ports(
                process,
                Arc::new(FakeRetirementPort::unavailable()),
                request,
            )
        }

        fn effect_with_ports(
            &self,
            process: Arc<dyn RootProvisionProcessPort>,
            retirement: Arc<dyn RootProvisionProcessRetirementPort>,
            request: Arc<dyn RootProvisionRequestPort>,
        ) -> SignedRootProvisionEffect {
            SignedRootProvisionEffect::for_test(
                Arc::clone(&self.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&self.blob) as Arc<dyn BlobStore>,
                process,
                retirement,
                request,
                HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
            )
        }

        fn dispatcher(
            &self,
            process: Arc<FakeProcessPort>,
            request: Arc<FakeRequestPort>,
            mutations: Arc<NoSignedMutationPort>,
        ) -> SignedRunningEffect {
            self.dispatcher_with_retirement(
                process,
                Arc::new(FakeRetirementPort::unavailable()),
                request,
                mutations,
            )
        }

        fn dispatcher_with_retirement(
            &self,
            process: Arc<FakeProcessPort>,
            retirement: Arc<FakeRetirementPort>,
            request: Arc<FakeRequestPort>,
            mutations: Arc<NoSignedMutationPort>,
        ) -> SignedRunningEffect {
            let acquire = SignedRunningAcquireEffect::new(
                mutations,
                Arc::clone(&self.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&self.blob) as Arc<dyn BlobStore>,
                60_000,
            )
            .unwrap();
            let executable_path = HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap();
            let handoff = ServingHandoffEffect::new(
                Arc::clone(&self.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&self.blob) as Arc<dyn BlobStore>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessGlobalPort>,
                Arc::clone(&process) as Arc<dyn TargetControlProcessPort>,
                executable_path.clone(),
            )
            .unwrap();
            let prepare_device = ServingPrepareDeviceEffect::new(
                ServingPrepareFrontend::vhost_user_blk(64, 256).unwrap(),
                executable_path,
            )
            .unwrap();
            SignedRunningEffect {
                running_admission: None,
                acquire,
                provision: self.effect_with_ports(process, retirement, request),
                handoff,
                prepare_device,
                prepare_device_retirement: None,
                serving_process: None,
                kernel_nbd_attach: None,
                prepare_network: None,
                start_runtime: None,
                persistent_filesystem: None,
                physical_start_runtime: None,
            }
        }
    }

    fn recovery_context(fixture: &Fixture) -> RuntimePreScanRecoveryContext {
        let session = SessionBinding {
            node_id: fixture.desired.placement.node_id.clone(),
            node_boot_id: managed_test_node_boot_id(),
            agent_instance_id: random('5'),
            agent_session_epoch: epoch(2),
        };
        RuntimePreScanRecoveryContext::for_test(
            fixture.state.clone(),
            RuntimeSpineFullScan {
                session: session.clone(),
                heartbeat_sequence: Sequence::new(10).unwrap(),
                inventory_epoch: epoch(5),
                desired: DesiredReadSnapshot {
                    version: ContractVersion::V1,
                    session,
                    request_sequence: Sequence::new(20).unwrap(),
                    read_position: Sequence::new(21).unwrap(),
                    issued_at_unix_ms: unix_ms(1_900_000_005_000),
                    expires_at_unix_ms: unix_ms(1_900_000_035_000),
                    desired_specs: vec![fixture.desired.clone()],
                },
            },
            Instant::now() + Duration::from_secs(10),
        )
    }

    fn same_image_superseded_fixture() -> Fixture {
        let mut fixture = Fixture::new();
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::new(&fixture.desired));
        fixture
    }

    fn stopped_receipt_fixture() -> (Fixture, Arc<FakeProcessPort>, Arc<FakeRequestPort>) {
        let fixture = same_image_superseded_fixture();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::new(FakeRetirementPort::exact()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert!(fixture.stop_receipt_path().exists());
        (fixture, process, request)
    }

    fn observed_volume(
        desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
        head: &cats_api::runtime_reconciliation::RemoteHead,
        data_directory: &HostPath,
    ) -> ObservedVolume {
        ObservedVolume {
            volume_intent_id: Some(desired.volumes[0].volume_intent_id.clone()),
            disk_id: Some(desired.volumes[0].disk_id.clone()),
            volume_id: desired.volumes[0].volume_id.clone(),
            disk_kind: ObservedDiskKind::Root,
            size_bytes: Some(desired.volumes[0].size_bytes),
            durability: Some(desired.volumes[0].durability),
            authority: VolumeAuthorityEvidence::Owned {
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                head: head.clone(),
            },
            local_lineages: vec![LocalVolumeLineage {
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                acquire_origin: attachment.identity.acquire_origin.clone(),
                node_id: attachment.identity.node_id.clone(),
                placement_epoch: attachment.identity.placement_epoch,
                local_durable_generation: head.generation,
                remote_durable_generation: head.generation,
                data_directory: data_directory.clone(),
                pending_pack_count: WireU64::new(0).unwrap(),
                fenced: false,
                state: LocalLineageState::Active,
            }],
            devices: Vec::new(),
        }
    }

    fn exact_process(
        expected: &super::super::RootProvisionProcessExpectation,
    ) -> RootProvisionProcessEvidence {
        RootProvisionProcessEvidence {
            process_id: 41,
            unit_main_process_id: 41,
            process_start_time_ticks: WireU64::new(42).unwrap(),
            executable_path: expected.executable_path.clone(),
            scope_id: expected.scope_id.clone(),
            cgroup_path: expected.cgroup_path.clone(),
            cgroup_process_ids: vec![41],
            control_socket_path: expected.control_socket_path.clone(),
            data_directory: expected.data_directory.clone(),
            ownership_token: expected.process_identity_token.clone(),
            handshake: RootProvisionBlockdHandshake {
                peer_process_id: 41,
                identity: expected.attachment.identity.clone(),
                size_bytes: expected.size_bytes,
                durability: expected.attachment.durability,
                remote_head: expected.expected_remote_head().clone(),
                process_identity_token: expected.process_identity_token.clone(),
                control_only: true,
                guest_io_enabled: false,
            },
        }
    }

    #[test]
    fn managed_root_stop_journal_survives_owner_retirement_then_is_removed() {
        let mut fixture = Fixture::new();
        let managed = IsolatedManagedRootOwner::new(&mut fixture);
        let prepared = managed.prepare();
        let socket_path = PathBuf::from(prepared.control_socket_path().as_str());
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket_owner = prepared
            .retain_root_stop_owner_evidence(&managed.boot)
            .unwrap();
        drop(prepared);
        let process = exact_process(&managed.expectation);
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.desired.cat_id,
        )
        .unwrap();
        let stored = checkpoint_store.load().unwrap().unwrap();
        let mut authorized = AuthorizedBlockdStore::new(fixture.state.clone())
            .retain_exact_runtime_checkpoint(&fixture.checkpoint)
            .unwrap();
        let admission = RootProvisionRetirementAdmission {
            node_boot_id: managed.boot.node_boot_id().clone(),
            agent_instance_id: random('9'),
            agent_session_epoch: epoch(2),
            inventory_epoch: epoch(1),
            inventory_digest: Sha256Digest::from_bytes([8; 32]),
            inventory_read_position: Sequence::new(1).unwrap(),
        };
        let receipt = RootProvisionStopReceipt::new_for_isolated_socket_root_test(
            stored.checkpoint(),
            authorized.checkpoint(),
            fixture.authority.record(),
            &managed.expectation,
            process,
            socket_owner,
            admission,
        )
        .unwrap();
        assert!(matches!(
            authorized.persist_or_reopen_stop_receipt(&receipt).unwrap(),
            StopReceiptPublication::Published(_)
        ));
        assert!(fixture.stop_receipt_path().exists());
        assert!(!Path::new(managed.expectation.data_directory.as_str())
            .join("root-provision.sock")
            .exists());

        // Exact stop has completed, but a Unix listener leaves its pathname
        // behind. Only the accepted-full/global absence capability may move
        // the complete managed owner to quarantine and retire its intent.
        drop(listener);
        assert!(socket_path.exists());
        let context = fixture.context_at(Vec::new(), 5, 13);
        let absence = managed.sealed_absence(&context);
        assert_eq!(
            managed
                .root
                .retire_absent_owner(&managed.intents, &managed.intent, &managed.boot, absence)
                .unwrap(),
            ManagedBlockdSocketOwnerRetirement::Retired
        );
        assert!(!socket_path.exists());
        assert!(fixture.stop_receipt_path().exists());

        // A fresh complete whole-root snapshot now joins the still-durable
        // semantic journal to no physical paths. Only this later round may
        // remove the journal.
        let empty = managed
            .root
            .capture_closed_whole_root(&managed.intents, &[managed.intent.clone()])
            .unwrap();
        assert!(empty
            .bind_root_stop_owner(receipt.socket_owner())
            .unwrap()
            .is_empty());
        authorized.remove_stop_receipt(&receipt).unwrap();
        assert!(!fixture.stop_receipt_path().exists());
        assert!(
            std::fs::read_dir(Path::new(managed.expectation.data_directory.as_str()))
                .unwrap()
                .all(|entry| !entry.unwrap().file_type().unwrap().is_socket())
        );
    }

    #[test]
    fn superseded_effect_retires_managed_owner_before_semantic_stop_journal() {
        let mut fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            provision_transition_id,
            control_socket_path,
            ..
        } = &mut fixture.checkpoint.step
        else {
            unreachable!()
        };
        *control_socket_path =
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                .root_paths(provision_transition_id)
                .unwrap()
                .control_socket()
                .clone();
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.desired.cat_id,
        )
        .unwrap();
        let predecessor = checkpoint_store.load().unwrap().unwrap();
        checkpoint_store
            .replace(&predecessor, &fixture.checkpoint)
            .unwrap();
        drop(checkpoint_store);
        let expectation = super::super::RootProvisionProcessExpectation::from_checkpoint(
            &fixture.checkpoint,
            super::super::root_provision_process::RootProvisionAuthoritySnapshot {
                attachment: fixture.attachment.clone(),
                volume: &fixture.authority.record(),
            },
            HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
        )
        .unwrap();
        let managed = Arc::new(IsolatedManagedRootOwner::from_installed_expectation(
            &expectation,
        ));
        let prepared = managed.prepare();
        let isolated_socket = PathBuf::from(prepared.control_socket_path().as_str());
        let listener = UnixListener::bind(&isolated_socket).unwrap();
        std::fs::set_permissions(&isolated_socket, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(prepared);
        drop(listener);

        let process = exact_process(&expectation);
        let socket_owner =
            super::super::blockd_socket_namespace::ManagedBlockdRootStopOwnerEvidence::for_test(
                &expectation,
                managed.boot.node_boot_id().clone(),
            )
            .unwrap();
        let admission = RootProvisionRetirementAdmission {
            node_boot_id: managed.boot.node_boot_id().clone(),
            agent_instance_id: random('5'),
            agent_session_epoch: epoch(2),
            inventory_epoch: epoch(1),
            inventory_digest: Sha256Digest::from_bytes([8; 32]),
            inventory_read_position: Sequence::new(1).unwrap(),
        };
        let mut authorized = AuthorizedBlockdStore::new(fixture.state.clone())
            .retain_exact_runtime_checkpoint(&fixture.checkpoint)
            .unwrap();
        let receipt = RootProvisionStopReceipt::new(
            &fixture.checkpoint,
            authorized.checkpoint(),
            fixture.authority.record(),
            process,
            socket_owner,
            admission,
        )
        .unwrap();
        authorized.persist_or_reopen_stop_receipt(&receipt).unwrap();
        drop(authorized);

        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        let retirement = Arc::new(AutomatonRetirementPort {
            managed: Arc::clone(&managed),
            start_absences: AtomicUsize::new(0),
            inspections: AtomicUsize::new(0),
            retirements: AtomicUsize::new(0),
        });
        let process_port = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            process_port,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        let first_context = fixture.context_at_with_managed_stop_receipt_evidence(
            expectation.clone(),
            &receipt,
            5,
            13,
        );
        let accepted = first_context.accepted_full().unwrap();
        assert_eq!(accepted.observation().runtimes[0].processes, Vec::new());
        assert!(first_context
            .node_global_process()
            .unwrap()
            .stop_receipt_socket(&fixture.desired.cat_id)
            .is_some());
        assert_eq!(
            effect.try_apply(&first_context, &fixture.desired).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            (
                retirement.inspections.load(Ordering::SeqCst),
                retirement.start_absences.load(Ordering::SeqCst),
                retirement.retirements.load(Ordering::SeqCst),
            ),
            (1, 0, 1)
        );
        assert!(
            !isolated_socket.exists(),
            "first effect round must consume the real managed-owner retirement automaton"
        );
        assert!(fixture.stop_receipt_path().exists());

        let second_context =
            fixture.context_at_with_managed_stop_receipt_evidence(expectation, &receipt, 6, 14);
        assert_eq!(
            effect.try_apply(&second_context, &fixture.desired).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(retirement.retirements.load(Ordering::SeqCst), 2);
        assert!(!fixture.stop_receipt_path().exists());
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    /// Isolated physical fixture for the managed Root socket owner. The
    /// semantic stop journal remains in AuthorizedBlockd state; this object
    /// owns only the boot-local `/run` analogue and its durable namespace
    /// intent store.
    struct IsolatedManagedRootOwner {
        _temporary: tempfile::TempDir,
        root: Arc<RetainedManagedBlockdSocketRoot>,
        intents: Arc<BlockdSocketIntentStore>,
        boot: CurrentBlockdSocketBoot,
        intent: BlockdSocketOwnershipIntentV1,
        expectation: super::super::RootProvisionProcessExpectation,
    }

    impl IsolatedManagedRootOwner {
        fn new(fixture: &mut Fixture) -> Self {
            let temporary = tempfile::Builder::new()
                .prefix("signed-root-managed-")
                .tempdir_in("/private/tmp")
                .or_else(|_| {
                    tempfile::Builder::new()
                        .prefix("signed-root-managed-")
                        .tempdir_in("/tmp")
                })
                .unwrap();
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let root = Arc::new(
                RetainedManagedBlockdSocketRoot::provision_for_test(&temporary.path().join("s"))
                    .unwrap(),
            );
            let intent_state = temporary.path().join("state");
            std::fs::create_dir(&intent_state).unwrap();
            std::fs::set_permissions(&intent_state, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let intents = Arc::new(
                BlockdSocketIntentStore::provision_for_test(StateDirectory::unanchored(
                    intent_state,
                ))
                .unwrap(),
            );
            let node_boot_id = managed_test_node_boot_id();
            let boot = CurrentBlockdSocketBoot::for_test(node_boot_id);
            let provision_transition_id = match &fixture.checkpoint.step {
                ReconcileStep::ProvisionRootImage {
                    provision_transition_id,
                    ..
                } => provision_transition_id.clone(),
                _ => unreachable!(),
            };
            let paths = root.planner().root_paths(&provision_transition_id).unwrap();
            let ReconcileStep::ProvisionRootImage {
                control_socket_path,
                ..
            } = &mut fixture.checkpoint.step
            else {
                unreachable!()
            };
            *control_socket_path = paths.control_socket().clone();
            let socket_owner_authority_digest =
                cats_blockd::target_control::provision_root_authorization_context_digest(
                    &fixture.checkpoint,
                )
                .unwrap()
                .as_sha256_digest()
                .clone();
            let mut installed_checkpoint = fixture.checkpoint.clone();
            let ReconcileStep::ProvisionRootImage {
                control_socket_path,
                ..
            } = &mut installed_checkpoint.step
            else {
                unreachable!()
            };
            *control_socket_path =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .root_paths(&provision_transition_id)
                    .unwrap()
                    .control_socket()
                    .clone();
            let base = super::super::RootProvisionProcessExpectation::from_checkpoint(
                &installed_checkpoint,
                super::super::root_provision_process::RootProvisionAuthoritySnapshot {
                    attachment: fixture.attachment.clone(),
                    volume: &fixture.authority.record(),
                },
                HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
            )
            .unwrap();
            let mut expectation = base;
            expectation.control_socket_path = paths.control_socket().clone();
            expectation.socket_owner_authority_digest = socket_owner_authority_digest.clone();
            let checkpoint_store = FileCheckpointStore::open(
                &fixture.state.path().join(CHECKPOINT_NAMESPACE),
                &fixture.desired.cat_id,
            )
            .unwrap();
            let previous = checkpoint_store.load().unwrap().unwrap();
            checkpoint_store
                .replace(&previous, &fixture.checkpoint)
                .unwrap();
            let intent = BlockdSocketOwnershipIntentV1::root(
                &root,
                &boot,
                provision_transition_id,
                socket_owner_authority_digest,
            )
            .unwrap();
            Self {
                _temporary: temporary,
                root,
                intents,
                boot,
                intent,
                expectation,
            }
        }

        fn from_installed_expectation(
            expectation: &super::super::RootProvisionProcessExpectation,
        ) -> Self {
            let temporary = tempfile::Builder::new()
                .prefix("signed-root-effect-managed-")
                .tempdir_in("/private/tmp")
                .or_else(|_| {
                    tempfile::Builder::new()
                        .prefix("signed-root-effect-managed-")
                        .tempdir_in("/tmp")
                })
                .unwrap();
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let root = Arc::new(
                RetainedManagedBlockdSocketRoot::provision_for_test(&temporary.path().join("s"))
                    .unwrap(),
            );
            let intent_state = temporary.path().join("state");
            std::fs::create_dir(&intent_state).unwrap();
            std::fs::set_permissions(&intent_state, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let intents = Arc::new(
                BlockdSocketIntentStore::provision_for_test(StateDirectory::unanchored(
                    intent_state,
                ))
                .unwrap(),
            );
            let boot = CurrentBlockdSocketBoot::for_test(managed_test_node_boot_id());
            let paths = root
                .planner()
                .root_paths(&expectation.provision_transition_id)
                .unwrap();
            let mut isolated = expectation.clone();
            isolated.control_socket_path = paths.control_socket().clone();
            let intent = BlockdSocketOwnershipIntentV1::root(
                &root,
                &boot,
                expectation.provision_transition_id.clone(),
                expectation.socket_owner_authority_digest.clone(),
            )
            .unwrap();
            Self {
                _temporary: temporary,
                root,
                intents,
                boot,
                intent,
                expectation: isolated,
            }
        }

        fn assert_same_owner(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(
                expected.provision_transition_id == self.expectation.provision_transition_id
                    && expected.socket_owner_authority_digest
                        == self.expectation.socket_owner_authority_digest,
                "automaton retirement test changed its stable Root owner generation"
            );
            Ok(())
        }

        fn prepare(
            &self,
        ) -> super::super::blockd_socket_namespace::PreparedManagedBlockdSocketOwner<'_> {
            self.intents
                .publish(&self.intent, &self.root, &self.boot)
                .unwrap();
            self.root
                .prepare_existing_intent(&self.intents, &self.intent, &self.boot)
                .unwrap()
        }

        fn sealed_absence(
            &self,
            context: &RuntimeDesiredEffectContext,
        ) -> ExactManagedBlockdSocketOwnerStartAbsence {
            let node_global = context.lock_node_global_effect().unwrap();
            let capture = self
                .root
                .capture_start_absence(&self.intents, &self.intent, &self.boot)
                .unwrap();
            let expected = [self.intent.clone()];
            let before = self
                .root
                .capture_closed_whole_root(&self.intents, &expected)
                .unwrap();
            let after = self
                .root
                .capture_closed_whole_root(&self.intents, &expected)
                .unwrap();
            ExactManagedBlockdSocketOwnerStartAbsence::seal_after_node_global_sweep(
                capture,
                before,
                after,
                &self.boot,
                node_global,
            )
            .unwrap()
        }
    }

    #[test]
    fn blank_full_inventory_starts_one_exact_control_process_and_rescans() {
        let fixture = Fixture::new();
        let managed = Arc::new(IsolatedManagedRootOwner::from_installed_expectation(
            &fixture.root_process_expectation(),
        ));
        let retirement = Arc::new(AutomatonRetirementPort {
            managed,
            start_absences: AtomicUsize::new(0),
            inspections: AtomicUsize::new(0),
            retirements: AtomicUsize::new(0),
        });
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        let context =
            fixture.context_at_with_absent_root(fixture.root_process_expectation(), 4, 12);
        let outcome = effect.try_apply(&context, &fixture.desired).unwrap();
        assert_eq!(outcome, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(process.starts.load(Ordering::SeqCst), 1);
        assert_eq!(retirement.start_absences.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn managed_absence_rejects_foreign_boot_and_predecessor_observation_without_retirement() {
        let (fixture, _process, _request) = stopped_receipt_fixture();
        let expected = fixture.root_process_expectation();
        let managed = Arc::new(IsolatedManagedRootOwner::from_installed_expectation(
            &expected,
        ));
        let prepared = managed.prepare();
        let public_directory = PathBuf::from(prepared.public_directory().as_str());
        let public_inode = std::fs::symlink_metadata(&public_directory).unwrap().ino();
        drop(prepared);
        let receipt_before = std::fs::read(fixture.stop_receipt_path()).unwrap();
        let retirement = AutomatonRetirementPort {
            managed: Arc::clone(&managed),
            start_absences: AtomicUsize::new(0),
            inspections: AtomicUsize::new(0),
            retirements: AtomicUsize::new(0),
        };

        let predecessor = fixture.context_at_with_absent_root(expected.clone(), 5, 13);
        let predecessor_process_admission = predecessor.node_global_process().unwrap().clone();
        let accepted = predecessor.accepted_full().unwrap();
        let mut foreign_session = accepted.session().clone();
        let mut foreign_observation = accepted.observation().clone();
        let mut foreign_attestation = accepted.attestation().clone();
        let foreign_boot = NodeBootId::new("44444444444444444444444444444444").unwrap();
        foreign_session.node_boot_id = foreign_boot.clone();
        foreign_observation.node_boot_id = foreign_boot;
        let foreign_digest = inventory_digest(&foreign_observation).unwrap();
        foreign_observation.inventory_digest = Some(foreign_digest.clone());
        foreign_attestation.inventory_digest = foreign_digest;
        let foreign_process_admission = predecessor_process_admission
            .rebind_for_test(&foreign_observation)
            .unwrap();
        let foreign_context = RuntimeDesiredEffectContext::for_test_with_admission(
            fixture.state.clone(),
            Instant::now() + Duration::from_secs(10),
            RuntimeDesiredEffectAdmission::for_test(
                foreign_session,
                foreign_observation,
                foreign_attestation,
            ),
        )
        .with_node_global_process_for_test(foreign_process_admission);
        let error = retirement
            .retire_absent_socket_owner(&expected, &foreign_context)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("changed its managed namespace boot"));
        let fake = FakeRetirementPort::absent();
        let error = fake
            .retire_absent_socket_owner(&expected, &foreign_context)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("changed its managed namespace boot"));

        let successor = fixture
            .context_at(Vec::new(), 6, 14)
            .with_node_global_process_for_test(predecessor_process_admission);
        let error = retirement
            .retire_absent_socket_owner(&expected, &successor)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("bound to another accepted observation"));
        let error = fake
            .retire_absent_socket_owner(&expected, &successor)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("bound to another accepted observation"));

        assert_eq!(retirement.retirements.load(Ordering::SeqCst), 0);
        assert!(public_directory.is_dir());
        assert_eq!(
            std::fs::symlink_metadata(&public_directory).unwrap().ino(),
            public_inode
        );
        assert_eq!(
            managed.intents.load(managed.intent.owner()).unwrap(),
            Some(managed.intent.clone())
        );
        assert_eq!(
            std::fs::read(fixture.stop_receipt_path()).unwrap(),
            receipt_before
        );
    }

    #[test]
    fn current_provision_gate_accepts_an_exact_mixed_takeover_volume_set() {
        let fixture = Fixture::new();
        let context = fixture.context(Vec::new());
        let mut runtime = context.accepted_full().unwrap().observation().runtimes[0].clone();
        let mut desired = fixture.desired.clone();
        let root_authorization_id = id("auth_root_takeover");
        desired.volumes[0].acquire = VolumeAcquire::Takeover {
            authorization_id: root_authorization_id.clone(),
        };
        runtime.volumes[0].local_lineages[0].acquire_origin = AcquireOrigin::Takeover {
            authorization_id: root_authorization_id,
        };

        let mut persistent = desired.volumes[0].clone();
        persistent.volume_intent_id = id("vint_z_persistent");
        persistent.disk_id = id("disk_z_persistent");
        persistent.volume_id = id("vol_z_persistent");
        persistent.attachment_id = id("att_z_persistent");
        persistent.disk_kind = DiskKind::Persistent;
        persistent.guest_device = GuestDeviceIdentity {
            serial: id("cats-persistent"),
            slot: 1,
        };
        let persistent_authorization_id = id("auth_persistent_takeover");
        persistent.acquire = VolumeAcquire::Takeover {
            authorization_id: persistent_authorization_id.clone(),
        };
        persistent.mount = Some(Ext4MountIntent {
            filesystem_uuid: random('e'),
            mount_path: HostPath::new("/srv/persistent").unwrap(),
            initialization: FilesystemInitialization::Existing,
        });
        desired.volumes.push(persistent.clone());
        desired.spec_digest = spec_digest(&desired).unwrap();

        let mut observed_persistent = runtime.volumes[0].clone();
        observed_persistent.volume_intent_id = Some(persistent.volume_intent_id.clone());
        observed_persistent.disk_id = Some(persistent.disk_id.clone());
        observed_persistent.volume_id = persistent.volume_id.clone();
        observed_persistent.disk_kind = ObservedDiskKind::Persistent;
        let VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            ..
        } = &mut observed_persistent.authority
        else {
            unreachable!("provision fixture owns its Root")
        };
        *attachment_id = persistent.attachment_id.clone();
        let lineage = &mut observed_persistent.local_lineages[0];
        lineage.attachment_id = persistent.attachment_id.clone();
        lineage.attachment_epoch = *attachment_epoch;
        lineage.acquire_origin = AcquireOrigin::Takeover {
            authorization_id: persistent_authorization_id,
        };
        runtime.volumes.push(observed_persistent);

        assert!(current_provision_admission_is_exact(&desired, &runtime));
    }

    #[test]
    fn exact_process_sends_once_then_authority_target_prevents_replay() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        let outcome = effect
            .try_apply(
                &fixture.context(vec![fixture.public_process()]),
                &fixture.desired,
            )
            .unwrap();
        assert_eq!(outcome, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(process.starts.load(Ordering::SeqCst), 0);

        // A new accepted full inventory observes the target head. Replaying
        // the same persisted transition performs no second control request.
        let outcome = effect
            .try_apply(
                &fixture.context(vec![fixture.public_process()]),
                &fixture.desired,
            )
            .unwrap();
        assert_eq!(outcome, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn production_dispatcher_handoffs_target_then_cas_without_reentering_provision() {
        let mut fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            provision_transition_id,
            expected_provisioned_head,
            data_directory,
            ..
        } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        fixture
            .authority
            .set_head(expected_provisioned_head.clone());
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let retirement = Arc::new(FakeRetirementPort::exact());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let mutations = Arc::new(NoSignedMutationPort::default());
        let dispatcher = fixture.dispatcher_with_retirement(
            Arc::clone(&process),
            Arc::clone(&retirement),
            Arc::clone(&request),
            Arc::clone(&mutations),
        );
        let target_path = Path::new(data_directory.as_str()).join(
            cats_blockd::target_control::target_control_authorization_file_name(
                provision_transition_id,
            ),
        );
        let record_path = Path::new(data_directory.as_str())
            .join(super::super::serving_handoff::SERVING_HANDOFF_RECORD_FILE);

        assert_eq!(
            dispatcher
                .apply(
                    fixture.context_at(vec![fixture.public_process()], 4, 12),
                    &fixture.desired,
                )
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(target_path.exists());
        assert!(!record_path.exists());
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(process.starts.load(Ordering::SeqCst), 0);

        assert_eq!(
            dispatcher
                .apply(
                    fixture.context_at(vec![fixture.public_process()], 5, 13),
                    &fixture.desired,
                )
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(record_path.exists());
        let still_provision = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.desired.cat_id,
        )
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
        assert!(matches!(
            still_provision.checkpoint().step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
        drop(still_provision);

        assert_eq!(
            dispatcher
                .apply(
                    fixture.context_at(vec![fixture.public_process()], 6, 14),
                    &fixture.desired,
                )
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let prepared = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.desired.cat_id,
        )
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
        let ReconcileStep::PrepareDevice { devices } = &prepared.checkpoint().step else {
            panic!("third fresh target admission must perform only the Ready CAS")
        };
        let [device] = devices.as_slice() else {
            panic!("single-Root fixture must prepare one device")
        };
        assert_ne!(
            &device.ownership_token,
            &device.serving_process.process_identity_token
        );
        assert!(matches!(
            device.serving_authority.as_ref(),
            cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
        ));
        let cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk {
            queues,
            queue_size,
            ..
        } = &device.frontend
        else {
            panic!("production PrepareDevice must select vhost-user-blk")
        };
        assert_eq!(*queues, fixture.desired.runtime.vcpus as u16);
        assert_eq!(*queue_size, 256);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(process.starts.load(Ordering::SeqCst), 0);
        assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 2);

        // A later fresh scan that proves the old target-control process absent
        // leaves this checkpoint with the serving/device suffix.  Until that
        // suffix is composed, it must refresh rather than fall back into the
        // pre-acquire planner and StopLocal.
        let prepared_checkpoint = prepared.checkpoint().clone();
        drop(prepared);
        fixture.checkpoint = prepared_checkpoint;
        assert_eq!(
            dispatcher
                .apply(fixture.context_at(Vec::new(), 7, 15), &fixture.desired)
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(process.starts.load(Ordering::SeqCst), 0);
        assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn vhost_queue_maximum_obeys_the_shared_one_through_sixty_four_contract() {
        assert!(ServingPrepareFrontend::vhost_user_blk(0, 256).is_err());
        assert!(ServingPrepareFrontend::vhost_user_blk(65, 256).is_err());
        assert!(ServingPrepareFrontend::vhost_user_blk(64, 256).is_ok());
    }

    #[test]
    fn vhost_prepare_device_rejects_checkpoint_namespace_aba_before_and_after_publication() {
        for after_publication in [false, true] {
            let fixture = Fixture::new();
            let ReconcileStep::ProvisionRootImage {
                expected_provisioned_head,
                ..
            } = &fixture.checkpoint.step
            else {
                unreachable!()
            };
            fixture
                .authority
                .set_head(expected_provisioned_head.clone());
            let process = Arc::new(FakeProcessPort::exact(41, 42));
            let retirement = Arc::new(FakeRetirementPort::exact());
            let request = Arc::new(FakeRequestPort {
                authority: Arc::clone(&fixture.authority),
                calls: AtomicUsize::new(0),
                conflict: false,
                mutate_owner: false,
                connect_failure: false,
                identity_mismatch: false,
            });
            let mutations = Arc::new(NoSignedMutationPort::default());
            let mut dispatcher = fixture.dispatcher_with_retirement(
                Arc::clone(&process),
                Arc::clone(&retirement),
                Arc::clone(&request),
                Arc::clone(&mutations),
            );

            // Publish the target-control wrapper and sealed handoff in their
            // own two accepted full-inventory rounds.
            for (inventory_epoch, read_position) in [(4, 12), (5, 13)] {
                assert_eq!(
                    dispatcher
                        .apply(
                            fixture.context_at(
                                vec![fixture.public_process()],
                                inventory_epoch,
                                read_position,
                            ),
                            &fixture.desired,
                        )
                        .unwrap(),
                    RuntimeDesiredEffectOutcome::RefreshInventory
                );
            }

            let checkpoint_directory = fixture.state.path().join(CHECKPOINT_NAMESPACE);
            let detached_directory = fixture.state.path().join(if after_publication {
                "checkpoints-post-publication-detached"
            } else {
                "checkpoints-pre-publication-detached"
            });
            let mode = std::fs::metadata(&checkpoint_directory)
                .unwrap()
                .permissions()
                .mode();
            let hook_checkpoint_directory = checkpoint_directory.clone();
            let hook_detached_directory = detached_directory.clone();
            let hook = Arc::new(move || {
                std::fs::rename(&hook_checkpoint_directory, &hook_detached_directory).unwrap();
                std::fs::create_dir(&hook_checkpoint_directory).unwrap();
                std::fs::set_permissions(
                    &hook_checkpoint_directory,
                    std::fs::Permissions::from_mode(mode),
                )
                .unwrap();
            });
            let executable = HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap();
            let prepare = ServingPrepareDeviceEffect::new(
                ServingPrepareFrontend::vhost_user_blk(64, 256).unwrap(),
                executable,
            )
            .unwrap();
            dispatcher.prepare_device = if after_publication {
                prepare.with_after_replace(hook)
            } else {
                prepare.with_before_replace(hook)
            };

            let error = dispatcher
                .apply(
                    fixture.context_at(vec![fixture.public_process()], 6, 14),
                    &fixture.desired,
                )
                .unwrap_err();
            assert!(
                format!("{error:#}").contains(
                    "retained checkpoint namespace is no longer the current lexical directory"
                ),
                "unexpected error: {error:#}"
            );
            let detached = FileCheckpointStore::open(&detached_directory, &fixture.desired.cat_id)
                .unwrap()
                .load()
                .unwrap()
                .unwrap();
            assert_eq!(
                matches!(detached.checkpoint().step, ReconcileStep::PrepareDevice { .. }),
                after_publication,
                "pre-publication ABA must retain the predecessor; post-publication ABA may durably publish only in the detached directory but must not return success"
            );
            assert!(!super::super::runtime_checkpoint_path(
                &checkpoint_directory,
                &fixture.desired.cat_id,
            )
            .exists());
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
            assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn superseded_target_wrapper_retirement_reopens_exact_launch_identity() {
        let mut fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head,
            ..
        } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        fixture
            .authority
            .set_head(expected_provisioned_head.clone());
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let dispatcher = fixture.dispatcher_with_retirement(
            Arc::clone(&process),
            Arc::new(FakeRetirementPort::exact()),
            Arc::clone(&request),
            Arc::new(NoSignedMutationPort::default()),
        );
        assert_eq!(
            dispatcher
                .apply(
                    fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );

        // The target authorization now binds the target-wrapper CLI. Make the
        // same durable checkpoint stale and prove retirement cannot fall back
        // to the blank-control argv expectation.
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::new(&fixture.desired));
        let retirement = Arc::new(TargetLaunchRetirementPort::default());
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert!(fixture.stop_receipt_path().exists());
    }

    #[test]
    fn serial_control_listener_completes_status_before_receiving_provision_request() {
        let fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head,
            ..
        } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        let socket_root = tempfile::Builder::new()
            .prefix("cats-rp-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket_path = socket_root.path().join("control.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let expected_request = provision_root_image_request(&fixture.checkpoint).unwrap();
        let mut expected_request_frame = b"provision_root_image ".to_vec();
        expected_request_frame
            .extend(encode_provision_root_image_request(&expected_request).unwrap());
        expected_request_frame.push(b'\n');
        let result = ProvisionRootImageResult {
            provision_transition_id: expected_request.provision_transition_id.clone(),
            volume_id: expected_request.volume_id.clone(),
            attachment_id: expected_request.attachment_id.clone(),
            attachment_epoch: expected_request.attachment_epoch,
            resulting_head: expected_request.expected_provisioned_head.clone(),
        };
        let mut response = b"OK ".to_vec();
        response.extend(encode_provision_root_image_result(&result).unwrap());
        response.push(b'\n');
        let authority = Arc::clone(&fixture.authority);
        let target = expected_provisioned_head.clone();
        let (events_tx, events_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut status = accept_before(&listener, deadline);
            status
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut status_line = Vec::new();
            BufReader::new(&mut status)
                .read_until(b'\n', &mut status_line)
                .unwrap();
            events_tx.send(status_line).unwrap();
            status.write_all(b"status-ok\n").unwrap();
            drop(status);

            let mut provision = accept_before(&listener, deadline);
            provision
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut provision_line = Vec::new();
            BufReader::new(&mut provision)
                .read_until(b'\n', &mut provision_line)
                .unwrap();
            events_tx.send(provision_line).unwrap();
            authority.set_head(target);
            provision.write_all(&response).unwrap();
        });

        let process_id = std::process::id();
        let start_time_ticks = 42;
        let expected_identity = ProcIdentity {
            pid: process_id,
            start_ticks: Some(start_time_ticks),
            exe: Some(Path::new("/usr/bin/cats-blockd").to_path_buf()),
        };
        let process = Arc::new(SerialStatusProcessPort {
            inspections: AtomicUsize::new(0),
            process_id,
            start_time_ticks,
            socket_path: socket_path.clone(),
        });
        let request = Arc::new(SerialRequestPort {
            process_identity: FixedProcessIdentity(expected_identity),
            socket_path,
            calls: AtomicUsize::new(0),
        });
        let effect = SignedRootProvisionEffect::for_test(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&fixture.blob) as Arc<dyn BlobStore>,
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::new(FakeRetirementPort::unavailable()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
        );
        let mut accepted_process = fixture.public_process();
        accepted_process.process_id = process_id;
        accepted_process.process_start_time_ticks = WireU64::new(start_time_ticks).unwrap();
        assert_eq!(
            effect
                .try_apply(&fixture.context(vec![accepted_process]), &fixture.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );

        assert_eq!(
            events_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            b"status\n",
            "positive calibration: the full status reinspection reached the serial listener"
        );
        assert_eq!(
            events_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            expected_request_frame,
            "the provision request must reach the same one-at-a-time listener after status closes"
        );
        server.join().unwrap();
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.authority.record().head, result.resulting_head);
    }

    #[test]
    fn real_request_with_mismatched_response_rereads_target_or_keeps_blank_unconfirmed() {
        for authority_reaches_target in [true, false] {
            let fixture = Fixture::new();
            let ReconcileStep::ProvisionRootImage {
                expected_provisioned_head,
                ..
            } = &fixture.checkpoint.step
            else {
                unreachable!()
            };
            let expected_request = provision_root_image_request(&fixture.checkpoint).unwrap();
            let mut expected_request_frame = b"provision_root_image ".to_vec();
            expected_request_frame
                .extend(encode_provision_root_image_request(&expected_request).unwrap());
            expected_request_frame.push(b'\n');

            let mut wrong_result = ProvisionRootImageResult {
                provision_transition_id: expected_request.provision_transition_id.clone(),
                volume_id: expected_request.volume_id.clone(),
                attachment_id: expected_request.attachment_id.clone(),
                attachment_epoch: expected_request.attachment_epoch,
                resulting_head: expected_request.expected_provisioned_head.clone(),
            };
            wrong_result.provision_transition_id = random('9');
            let mut wrong_response = b"OK ".to_vec();
            wrong_response.extend(encode_provision_root_image_result(&wrong_result).unwrap());
            wrong_response.push(b'\n');

            let socket_root = tempfile::Builder::new()
                .prefix("cats-rp-wrong-")
                .tempdir_in("/tmp")
                .unwrap();
            let socket_path = socket_root.path().join("control.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let authority = Arc::clone(&fixture.authority);
            let target = expected_provisioned_head.clone();
            let (request_tx, request_rx) = mpsc::channel();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request_frame = Vec::new();
                BufReader::new(&mut stream)
                    .read_until(b'\n', &mut request_frame)
                    .unwrap();
                request_tx.send(request_frame).unwrap();
                if authority_reaches_target {
                    authority.set_head(target);
                }
                stream.write_all(&wrong_response).unwrap();
            });

            let process_id = std::process::id();
            let start_time_ticks = 42;
            let process = Arc::new(FakeProcessPort::exact(process_id, start_time_ticks));
            let request = Arc::new(SerialRequestPort {
                process_identity: FixedProcessIdentity(ProcIdentity {
                    pid: process_id,
                    start_ticks: Some(start_time_ticks),
                    exe: Some(Path::new("/usr/bin/cats-blockd").to_path_buf()),
                }),
                socket_path,
                calls: AtomicUsize::new(0),
            });
            let effect = SignedRootProvisionEffect::for_test(
                Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&fixture.blob) as Arc<dyn BlobStore>,
                process,
                Arc::new(FakeRetirementPort::unavailable()),
                Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
                HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
            );
            let mut accepted_process = fixture.public_process();
            accepted_process.process_id = process_id;
            accepted_process.process_start_time_ticks = WireU64::new(start_time_ticks).unwrap();
            assert_eq!(
                effect
                    .try_apply(&fixture.context(vec![accepted_process]), &fixture.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory),
                "a post-send response mismatch remains authority-reread ambiguity"
            );
            assert_eq!(
                request_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                expected_request_frame,
                "positive calibration: the exact provision request reached the real socket"
            );
            server.join().unwrap();
            assert_eq!(request.calls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.authority.loads.load(Ordering::SeqCst), 2);
            assert_eq!(
                fixture.authority.record().head,
                if authority_reaches_target {
                    expected_request.expected_provisioned_head.clone()
                } else {
                    fixture.attachment.head.clone()
                },
                "a mismatched response cannot manufacture a target head or hide an authoritative one"
            );
        }
    }

    #[test]
    fn cancellation_after_real_request_rereads_target_before_refresh_and_never_resends() {
        let fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head,
            ..
        } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        let expected_request = provision_root_image_request(&fixture.checkpoint).unwrap();
        let mut expected_request_frame = b"provision_root_image ".to_vec();
        expected_request_frame
            .extend(encode_provision_root_image_request(&expected_request).unwrap());
        expected_request_frame.push(b'\n');

        let socket_root = tempfile::Builder::new()
            .prefix("cats-rp-cancel-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket_path = socket_root.path().join("control.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let authority = Arc::clone(&fixture.authority);
        let target = expected_provisioned_head.clone();
        let (request_tx, request_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request_frame = Vec::new();
            BufReader::new(&mut stream)
                .read_until(b'\n', &mut request_frame)
                .unwrap();
            authority.set_head(target);
            request_tx.send(request_frame).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        });

        let process_id = std::process::id();
        let start_time_ticks = 42;
        let process = Arc::new(FakeProcessPort::exact(process_id, start_time_ticks));
        let request = Arc::new(SerialRequestPort {
            process_identity: FixedProcessIdentity(ProcIdentity {
                pid: process_id,
                start_ticks: Some(start_time_ticks),
                exe: Some(Path::new("/usr/bin/cats-blockd").to_path_buf()),
            }),
            socket_path,
            calls: AtomicUsize::new(0),
        });
        let effect = Arc::new(SignedRootProvisionEffect::for_test(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&fixture.blob) as Arc<dyn BlobStore>,
            process,
            Arc::new(FakeRetirementPort::unavailable()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
        ));
        let mut accepted_process = fixture.public_process();
        accepted_process.process_id = process_id;
        accepted_process.process_start_time_ticks = WireU64::new(start_time_ticks).unwrap();
        let context = Arc::new(fixture.context(vec![accepted_process.clone()]));
        let desired = fixture.desired.clone();
        let worker_effect = Arc::clone(&effect);
        let worker_context = Arc::clone(&context);
        let worker =
            std::thread::spawn(move || worker_effect.try_apply(worker_context.as_ref(), &desired));

        assert_eq!(
            request_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            expected_request_frame,
            "positive calibration: the complete provision frame reached the real serial socket"
        );
        context.cancel_for_test();
        assert_eq!(
            worker.join().unwrap().unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory),
            "post-request cancellation must not suppress the mandatory authority reread"
        );
        assert_eq!(fixture.authority.loads.load(Ordering::SeqCst), 2);
        assert_eq!(
            fixture.authority.record().head,
            expected_provisioned_head.clone()
        );
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        server.join().unwrap();

        assert_eq!(
            effect
                .try_apply(&fixture.context(vec![accepted_process]), &fixture.desired,)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            request.calls.load(Ordering::SeqCst),
            1,
            "the authoritative target prevents a replay on the next fresh admission"
        );
    }

    #[test]
    fn exact_closed_conflict_with_blank_authority_stops_without_retry() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: true,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(process, Arc::clone(&request));
        let outcome = effect
            .try_apply(
                &fixture.context(vec![fixture.public_process()]),
                &fixture.desired,
            )
            .unwrap();
        assert_eq!(outcome, Some(stop_local()));
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.authority.loads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn foreign_lineage_path_stops_before_process_or_request_io() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        let context = fixture.context_with_lineage_path(
            Vec::new(),
            Some(HostPath::new("/var/lib/cats/foreign".to_owned()).unwrap()),
        );
        assert_eq!(
            effect.try_apply(&context, &fixture.desired).unwrap(),
            Some(stop_local())
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(process.starts.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authority_owner_drift_after_request_stops_despite_target_head() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: true,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(process, Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn process_replacement_after_accepted_scan_stops_without_request() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(43, 44));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.authority.record().head,
            fixture.attachment.head,
            "a replaced process must not receive the provision mutation"
        );
    }

    #[test]
    fn connected_process_identity_drift_stops_without_request_bytes() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: true,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authority.record().head, fixture.attachment.head);
    }

    #[test]
    fn unavailable_connection_refreshes_after_full_process_reinspection() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: true,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authority.record().head, fixture.attachment.head);
    }

    #[test]
    fn superseded_provision_falls_through_to_existing_stale_planner() {
        let mut fixture = Fixture::new();
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();

        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(&fixture.context(Vec::new()), &fixture.desired)
                .unwrap(),
            None,
            "the SignedRunningAcquireEffect stale planner must own this checkpoint"
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn live_superseded_process_is_receipted_stopped_cleaned_then_rebound_or_released() {
        for changed_image in [false, true] {
            let mut fixture = Fixture::new();
            if changed_image {
                let ReconcileStep::ProvisionRootImage {
                    expected_provisioned_head,
                    ..
                } = &fixture.checkpoint.step
                else {
                    unreachable!()
                };
                fixture
                    .authority
                    .set_head(expected_provisioned_head.clone());
            }
            fixture.desired.desired_revision = Revision::new(2).unwrap();
            if changed_image {
                fixture.desired.runtime.boot_image_digest = Sha256Digest::from_bytes([3; 32]);
            } else {
                fixture.desired.runtime.memory_bytes += 4096;
            }
            fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
            fixture.blob = if changed_image {
                Arc::new(ExactBlob::with_chunk(&fixture.desired, '4'))
            } else {
                Arc::new(ExactBlob::new(&fixture.desired))
            };

            let checkpoint_store = FileCheckpointStore::open(
                &fixture.state.path().join(CHECKPOINT_NAMESPACE),
                &fixture.desired.cat_id,
            )
            .unwrap();
            let checkpoint_path = checkpoint_store.path().to_path_buf();
            drop(checkpoint_store);
            let checkpoint_before = std::fs::read(&checkpoint_path).unwrap();
            let authority_before = fixture.authority.record();
            let managed = Arc::new(IsolatedManagedRootOwner::from_installed_expectation(
                &fixture.root_process_expectation(),
            ));
            let prepared = managed.prepare();
            let socket_path = PathBuf::from(prepared.control_socket_path().as_str());
            let listener = UnixListener::bind(&socket_path).unwrap();
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
            drop(prepared);

            let process = Arc::new(FakeProcessPort::exact(41, 42));
            let retirement = Arc::new(AutomatonRetirementPort {
                managed,
                start_absences: AtomicUsize::new(0),
                inspections: AtomicUsize::new(0),
                retirements: AtomicUsize::new(0),
            });
            let request = Arc::new(FakeRequestPort {
                authority: Arc::clone(&fixture.authority),
                calls: AtomicUsize::new(0),
                conflict: false,
                mutate_owner: false,
                connect_failure: false,
                identity_mismatch: false,
            });
            let mutations = Arc::new(NoSignedMutationPort::default());
            let effect = fixture.effect_with_ports(
                Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
                Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            );
            let first = effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap();
            assert_eq!(
                first,
                Some(RuntimeDesiredEffectOutcome::RefreshInventory),
                "stops={}, inspections={}, receipt={}",
                process.stops.load(Ordering::SeqCst),
                retirement.inspections.load(Ordering::SeqCst),
                fixture.stop_receipt_path().exists(),
            );
            assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            assert_eq!(retirement.inspections.load(Ordering::SeqCst), 1);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
            assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.authority.record(), authority_before);
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);
            assert!(fixture.stop_receipt_path().exists());

            // A real listener leaves its pathname behind when the owner exits.
            // Restart recovery must remove only that receipted refused inode.
            drop(listener);
            assert!(socket_path.exists());
            let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
                Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            );
            assert_eq!(
                recovery.recover_one(recovery_context(&fixture)).unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange
            );
            assert!(socket_path.exists());
            assert!(fixture.stop_receipt_path().exists());
            assert_eq!(retirement.retirements.load(Ordering::SeqCst), 0);
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);

            // Only a strictly newer full admission may unlink the typed
            // receipted inode. A still newer full then retires the receipt.
            let finish = fixture.effect_with_ports(
                Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
                Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            );
            assert_eq!(
                finish
                    .try_apply(
                        &fixture.context_at_with_stop_receipt(
                            [fixture.root_process_expectation().control_socket_path],
                            5,
                            13,
                        ),
                        &fixture.desired,
                    )
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
            assert!(!socket_path.exists());
            assert!(
                fixture.stop_receipt_path().exists(),
                "the stop-authorizing admission cannot also remove its receipt"
            );
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);
            assert_eq!(
                finish
                    .try_apply(
                        &fixture.context_at_with_stop_receipt([], 6, 14),
                        &fixture.desired,
                    )
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
            assert!(!fixture.stop_receipt_path().exists());
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);

            // A third accepted full owns the existing stale planner. Same
            // image rebinds; changed image writes CleanupRelease, and neither
            // disposition performs A22 or root-process I/O in this round.
            let stale = fixture.dispatcher_with_retirement(
                Arc::clone(&process),
                Arc::new(FakeRetirementPort::absent()),
                Arc::clone(&request),
                Arc::clone(&mutations),
            );
            assert_eq!(
                stale
                    .apply(fixture.context_at(Vec::new(), 7, 15), &fixture.desired)
                    .unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory
            );
            let successor_store = FileCheckpointStore::open(
                &fixture.state.path().join(CHECKPOINT_NAMESPACE),
                &fixture.desired.cat_id,
            )
            .unwrap();
            let successor = successor_store.load().unwrap().unwrap();
            if changed_image {
                assert!(matches!(
                    successor.checkpoint().step,
                    ReconcileStep::CleanupRelease { .. }
                ));
            } else {
                assert_eq!(
                    successor.checkpoint().desired_revision,
                    fixture.desired.desired_revision
                );
                assert_eq!(
                    successor.checkpoint().spec_digest,
                    fixture.desired.spec_digest
                );
                assert!(matches!(
                    successor.checkpoint().step,
                    ReconcileStep::ProvisionRootImage { .. }
                ));
            }
            assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
            assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.authority.record(), authority_before);
        }
    }

    #[test]
    fn receipt_cleanup_allows_lease_renewal_but_preserves_on_authority_drift() {
        let (fixture, process, request) = stopped_receipt_fixture();
        fixture
            .authority
            .set_lease_expiry(unix_ms(1_900_000_120_000));
        let retirement = Arc::new(FakeRetirementPort::absent());
        let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
        );
        assert_eq!(
            recovery.recover_one(recovery_context(&fixture)).unwrap(),
            RuntimePreScanRecoveryOutcome::NoChange
        );
        assert!(fixture.stop_receipt_path().exists());
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 0);
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context_at_with_stop_receipt([], 5, 13),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert!(!fixture.stop_receipt_path().exists());
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);

        for drift in ["owner", "head", "marker", "lease_rollback"] {
            let (fixture, process, request) = stopped_receipt_fixture();
            match drift {
                "owner" => fixture.authority.set_owner(id("att_foreign")),
                "head" => {
                    let ReconcileStep::ProvisionRootImage {
                        expected_provisioned_head,
                        ..
                    } = &fixture.checkpoint.step
                    else {
                        unreachable!()
                    };
                    fixture
                        .authority
                        .set_head(expected_provisioned_head.clone());
                }
                "marker" => fixture.authority.clear_transition_marker(),
                "lease_rollback" => {
                    let current = fixture.authority.record().lease_expires_at.unwrap().get();
                    fixture.authority.set_lease_expiry(unix_ms(current - 1));
                }
                _ => unreachable!(),
            }
            let retirement = Arc::new(FakeRetirementPort::absent());
            let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
                Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            );
            assert_eq!(
                recovery.recover_one(recovery_context(&fixture)).unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange,
                "{drift} drift must preserve the receipted managed owner"
            );
            assert!(fixture.stop_receipt_path().exists());
            assert_eq!(
                retirement.calls.load(Ordering::SeqCst),
                0,
                "authority drift must stop before physical absence inspection"
            );
            assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn lease_expiry_must_not_move_back_from_artifact_or_receipted_attempt() {
        // First calibrate that a renewal after the retained launch grant can
        // authorize one durable receipt and exact stop.
        let fixture = same_image_superseded_fixture();
        let artifact_expiry = fixture.authority.record().lease_expires_at.unwrap().get();
        let receipted_expiry = artifact_expiry + 60_000;
        fixture
            .authority
            .set_lease_expiry(unix_ms(receipted_expiry));
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let retirement = Arc::new(FakeRetirementPort::exact());
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        let receipt_before = std::fs::read(fixture.stop_receipt_path()).unwrap();

        // This point read is still newer than the launch artifact, but older
        // than the durable receipt. Replay must stop before even the sealed
        // retirement inspection, and cleanup must preserve both artifacts.
        fixture
            .authority
            .set_lease_expiry(unix_ms(receipted_expiry - 1));
        let replay_retirement = Arc::new(FakeRetirementPort::exact());
        let replay = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&replay_retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            replay
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(replay_retirement.calls.load(Ordering::SeqCst), 0);
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::fs::read(fixture.stop_receipt_path()).unwrap(),
            receipt_before
        );

        let cleanup_retirement = Arc::new(FakeRetirementPort::absent());
        let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&cleanup_retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
        );
        assert_eq!(
            recovery.recover_one(recovery_context(&fixture)).unwrap(),
            RuntimePreScanRecoveryOutcome::NoChange
        );
        assert_eq!(cleanup_retirement.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            std::fs::read(fixture.stop_receipt_path()).unwrap(),
            receipt_before
        );

        // A rollback behind the retained launch artifact is rejected before
        // the first receipt or any retirement inspection as well.
        let artifact_fixture = same_image_superseded_fixture();
        let artifact_expiry = artifact_fixture
            .authority
            .record()
            .lease_expires_at
            .unwrap()
            .get();
        artifact_fixture
            .authority
            .set_lease_expiry(unix_ms(artifact_expiry - 1));
        let artifact_process = Arc::new(FakeProcessPort::exact(41, 42));
        let artifact_retirement = Arc::new(FakeRetirementPort::exact());
        let artifact_request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&artifact_fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        assert_eq!(
            artifact_fixture
                .effect_with_ports(
                    Arc::clone(&artifact_process) as Arc<dyn RootProvisionProcessPort>,
                    Arc::clone(&artifact_retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
                    Arc::clone(&artifact_request) as Arc<dyn RootProvisionRequestPort>,
                )
                .try_apply(
                    &artifact_fixture.context(vec![artifact_fixture.public_process()]),
                    &artifact_fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(artifact_retirement.calls.load(Ordering::SeqCst), 0);
        assert_eq!(artifact_process.stops.load(Ordering::SeqCst), 0);
        assert!(!artifact_fixture.stop_receipt_path().exists());
    }

    #[test]
    fn receipt_publication_atomically_preserves_conflict_and_recovers_exact_eexist() {
        for exact_replay in [false, true] {
            let fixture = same_image_superseded_fixture();
            let process = Arc::new(FakeProcessPort::exact(41, 42));
            let retirement = Arc::new(FakeRetirementPort::exact());
            let request = Arc::new(FakeRequestPort {
                authority: Arc::clone(&fixture.authority),
                calls: AtomicUsize::new(0),
                conflict: false,
                mutate_owner: false,
                connect_failure: false,
                identity_mismatch: false,
            });
            let target = fixture.stop_receipt_path();
            let temporary = target
                .with_file_name(super::super::authorized_blockd::ROOT_PROVISION_STOP_RECEIPT_TEMP);
            let target_for_hook = target.clone();
            let temporary_for_hook = temporary.clone();
            let hook = Arc::new(move || {
                if exact_replay {
                    std::fs::copy(&temporary_for_hook, &target_for_hook).unwrap();
                } else {
                    std::fs::write(&target_for_hook, b"foreign receipt").unwrap();
                }
                std::fs::set_permissions(&target_for_hook, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            });
            let effect = fixture
                .effect_with_ports(
                    Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
                    Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
                    Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
                )
                .with_before_stop_receipt_publish(hook);
            let first = effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap();
            assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
            assert_eq!(process.stops.load(Ordering::SeqCst), 0);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
            if exact_replay {
                assert_eq!(first, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
                assert!(target.exists());
                assert!(!temporary.exists());
                let replay = fixture.effect_with_ports(
                    Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
                    Arc::new(FakeRetirementPort::exact()),
                    Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
                );
                assert_eq!(
                    replay
                        .try_apply(
                            &fixture.context(vec![fixture.public_process()]),
                            &fixture.desired,
                        )
                        .unwrap(),
                    Some(RuntimeDesiredEffectOutcome::RefreshInventory)
                );
                assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            } else {
                assert_eq!(first, Some(stop_local()));
                assert_eq!(std::fs::read(&target).unwrap(), b"foreign receipt");
                assert!(temporary.exists());
            }
        }
    }

    #[test]
    fn maximum_endpoint_checkpoint_is_digest_bound_without_inflating_stop_receipt() {
        let mut old_desired = desired();
        old_desired.endpoints = (0..256)
            .map(|index| {
                let first_label = format!("e{index:03}{}", "a".repeat(59));
                EndpointIntent {
                    endpoint_id: id(&format!("e{index:03}{}", "x".repeat(124))),
                    hostname: Hostname::new(format!(
                        "{first_label}.{}.{}.{}",
                        "b".repeat(63),
                        "c".repeat(63),
                        "d".repeat(61)
                    ))
                    .unwrap(),
                    route_epoch: epoch(1),
                    protocol: HttpProtocol::Http,
                    target_port: 8080,
                }
            })
            .collect();
        old_desired.spec_digest = spec_digest(&old_desired).unwrap();
        let desired_bytes = encode_desired_runtime_spec(&old_desired).unwrap();
        assert_eq!(old_desired.endpoints.len(), 256);
        assert!(
            desired_bytes.len() > 100 * 1024,
            "maximum endpoint fixture did not calibrate a large valid Desired: {} bytes",
            desired_bytes.len()
        );

        let mut fixture = Fixture::new_with_desired(old_desired);
        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        let launch_checkpoint_path = Path::new(data_directory.as_str())
            .join(super::super::authorized_blockd::LAUNCH_CHECKPOINT_FILE);
        let launch_checkpoint_bytes = std::fs::read(&launch_checkpoint_path).unwrap();
        assert!(launch_checkpoint_bytes.len() > desired_bytes.len());
        assert!(
            launch_checkpoint_bytes.len()
                <= super::super::authorized_blockd::MAX_LAUNCH_CHECKPOINT_BYTES
        );

        // Supersede the old checkpoint without changing its Volume lineage.
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::new(&fixture.desired));
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::new(FakeRetirementPort::exact()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let receipt_bytes = std::fs::read(fixture.stop_receipt_path()).unwrap();
        let receipt =
            super::super::authorized_blockd::decode_root_provision_stop_receipt(&receipt_bytes)
                .unwrap();
        assert_eq!(
            receipt.authorized_checkpoint_content_digest(),
            &super::super::authorized_blockd::authorized_blockd_checkpoint_content_digest(
                &serde_json::from_slice(&launch_checkpoint_bytes).unwrap(),
            )
            .unwrap()
        );
        assert!(
            receipt_bytes.len() * 1024 <= 16 * 1024 * 1024,
            "1,024 maximum-bound checkpoints produced an excessive receipt scan budget: {} bytes each",
            receipt_bytes.len()
        );
        assert!(receipt_bytes.len() < launch_checkpoint_bytes.len() / 10);
        assert!(!receipt_bytes
            .windows(b"e000xxxxxxxxxxxxxxxx".len())
            .any(|window| window == b"e000xxxxxxxxxxxxxxxx"));
        assert!(
            super::super::authorized_blockd::decode_root_provision_stop_receipt(&vec![
                b' ';
                super::super::authorized_blockd::ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES
                    + 1
            ])
            .is_err(),
            "oversize receipt input must fail before JSON decoding"
        );
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn late_live_socket_with_new_inode_is_never_removed_by_old_receipt() {
        let (fixture, process, request) = stopped_receipt_fixture();
        let managed = IsolatedManagedRootOwner::from_installed_expectation(
            &fixture.root_process_expectation(),
        );
        let prepared = managed.prepare();
        let socket_path = PathBuf::from(prepared.control_socket_path().as_str());
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let receipted_owner = prepared
            .retain_root_stop_owner_evidence(&managed.boot)
            .unwrap();
        drop(prepared);
        let old_inode = std::fs::symlink_metadata(&socket_path).unwrap().ino();
        drop(listener);
        let external = tempfile::Builder::new()
            .prefix("rp-old-socket-")
            .tempdir_in("/tmp")
            .unwrap();
        let retained_old_path = external.path().join("old.sock");
        std::fs::rename(&socket_path, &retained_old_path).unwrap();
        let replacement = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let new_inode = std::fs::symlink_metadata(&socket_path).unwrap().ino();
        assert_ne!(
            old_inode, new_inode,
            "positive calibration requires a new inode"
        );
        std::fs::remove_file(retained_old_path).unwrap();

        let snapshot = managed
            .root
            .capture_closed_whole_root(&managed.intents, &[managed.intent.clone()])
            .unwrap();
        snapshot
            .bind_root_stop_owner(&receipted_owner)
            .expect_err("a replacement inode must conflict with the durable receipt");
        assert!(socket_path.exists());
        assert_eq!(
            std::fs::symlink_metadata(&socket_path).unwrap().ino(),
            new_inode
        );
        assert!(fixture.stop_receipt_path().exists());
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        drop(replacement);
    }

    #[test]
    fn duplicate_drift_special_bits_and_component_aba_stop_before_signal_or_receipt() {
        for inspection in [
            FakeRetirementInspection::Duplicate,
            FakeRetirementInspection::Drift,
        ] {
            let fixture = same_image_superseded_fixture();
            let checkpoint_path = fixture
                .state
                .path()
                .join(CHECKPOINT_NAMESPACE)
                .join(format!("cat-{}.checkpoint.json", fixture.desired.cat_id));
            let checkpoint_before = std::fs::read(&checkpoint_path).unwrap();
            let authority_before = fixture.authority.record();
            let process = Arc::new(FakeProcessPort::exact(41, 42));
            let retirement = Arc::new(FakeRetirementPort::with_inspection(inspection));
            let request = Arc::new(FakeRequestPort {
                authority: Arc::clone(&fixture.authority),
                calls: AtomicUsize::new(0),
                conflict: false,
                mutate_owner: false,
                connect_failure: false,
                identity_mismatch: false,
            });
            let effect = fixture.effect_with_ports(
                Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
                Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            );
            assert_eq!(
                effect
                    .try_apply(
                        &fixture.context(vec![fixture.public_process()]),
                        &fixture.desired,
                    )
                    .unwrap(),
                Some(stop_local())
            );
            assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
            assert_eq!(process.stops.load(Ordering::SeqCst), 0);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
            assert!(!fixture.stop_receipt_path().exists());
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);
            assert_eq!(fixture.authority.record(), authority_before);
        }

        let fixture = same_image_superseded_fixture();
        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        let data_directory = Path::new(data_directory.as_str());
        std::fs::set_permissions(data_directory, std::fs::Permissions::from_mode(0o4700)).unwrap();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let retirement = Arc::new(FakeRetirementPort::exact());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 0);
        assert_eq!(process.stops.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert!(!fixture.stop_receipt_path().exists());
        std::fs::set_permissions(data_directory, std::fs::Permissions::from_mode(0o700)).unwrap();

        let fixture = same_image_superseded_fixture();
        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        let volume_directory = Path::new(data_directory.as_str())
            .parent()
            .expect("authorized data directory has a retained Volume parent")
            .to_path_buf();
        let moved_directory = volume_directory.with_file_name("volume-moved");
        let current_directory = volume_directory.clone();
        let hook = Arc::new(move || {
            std::fs::rename(&current_directory, &moved_directory).unwrap();
            std::fs::create_dir(&current_directory).unwrap();
            std::fs::set_permissions(&current_directory, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        });
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let retirement = Arc::new(FakeRetirementPort::exact_with_hook(hook));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stops.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert!(!fixture.stop_receipt_path().exists());
    }

    #[test]
    fn receipt_publication_and_socket_unlink_response_loss_recover_one_effect_per_round() {
        for target_also_exists in [false, true] {
            let (fixture, process, request) = stopped_receipt_fixture();
            let target = fixture.stop_receipt_path();
            let temporary = target
                .with_file_name(super::super::authorized_blockd::ROOT_PROVISION_STOP_RECEIPT_TEMP);
            if target_also_exists {
                std::fs::copy(&target, &temporary).unwrap();
                std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            } else {
                std::fs::rename(&target, &temporary).unwrap();
            }
            let retirement = Arc::new(FakeRetirementPort::absent());
            let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
                Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            );
            assert_eq!(
                recovery.recover_one(recovery_context(&fixture)).unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: fixture.desired.cat_id.clone(),
                }
            );
            assert!(target.exists());
            assert!(!temporary.exists());
            assert_eq!(
                retirement.calls.load(Ordering::SeqCst),
                0,
                "settling receipt publication is the only recovery effect in this round"
            );
            assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);

            assert_eq!(
                recovery.recover_one(recovery_context(&fixture)).unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange
            );
            assert!(target.exists());
            assert_eq!(retirement.calls.load(Ordering::SeqCst), 0);
            let effect = fixture.effect_with_ports(
                Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
                Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            );
            assert_eq!(
                effect
                    .try_apply(
                        &fixture.context_at_with_stop_receipt([], 5, 13),
                        &fixture.desired,
                    )
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
            assert!(!target.exists());
            assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        }

        let (fixture, process, request) = stopped_receipt_fixture();
        let retirement = Arc::new(FakeRetirementPort::absent());
        let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
        );
        assert_eq!(
            recovery.recover_one(recovery_context(&fixture)).unwrap(),
            RuntimePreScanRecoveryOutcome::NoChange,
            "an acknowledgement-lost owner retirement remains effect work for a fresh full scan"
        );
        assert!(fixture.stop_receipt_path().exists());
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 0);

        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::new(FakeRetirementPort::absent()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context_at_with_stop_receipt([], 5, 13),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert!(!fixture.stop_receipt_path().exists());
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dispatcher_rebinds_same_image_superseded_provision_without_process_or_request_io() {
        let mut fixture = Fixture::new();
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::new(&fixture.desired));
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let mutations = Arc::new(NoSignedMutationPort::default());
        let dispatcher = fixture.dispatcher(
            Arc::clone(&process),
            Arc::clone(&request),
            Arc::clone(&mutations),
        );
        assert_eq!(
            dispatcher
                .apply(fixture.context(Vec::new()), &fixture.desired)
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let store = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.desired.cat_id,
        )
        .unwrap();
        let rebound = store.load().unwrap().unwrap();
        assert_eq!(
            rebound.checkpoint().desired_revision,
            fixture.desired.desired_revision
        );
        assert_eq!(
            rebound.checkpoint().spec_digest,
            fixture.desired.spec_digest
        );
        assert!(matches!(
            rebound.checkpoint().step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dispatcher_checkpoints_release_for_changed_image_without_process_or_request_io() {
        let mut fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head: old_target,
            ..
        } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        fixture.authority.set_head(old_target.clone());
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.boot_image_digest = Sha256Digest::from_bytes([3; 32]);
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::with_chunk(&fixture.desired, '4'));
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let mutations = Arc::new(NoSignedMutationPort::default());
        let dispatcher = fixture.dispatcher(
            Arc::clone(&process),
            Arc::clone(&request),
            Arc::clone(&mutations),
        );
        assert_eq!(
            dispatcher
                .apply(fixture.context(Vec::new()), &fixture.desired)
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let store = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.desired.cat_id,
        )
        .unwrap();
        let cleanup = store.load().unwrap().unwrap();
        assert!(
            matches!(
                cleanup.checkpoint().step,
                ReconcileStep::CleanupRelease { .. }
            ),
            "unexpected checkpoint: {:?}",
            cleanup.checkpoint().step
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
    }
}
