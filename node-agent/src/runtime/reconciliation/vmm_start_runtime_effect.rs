//! Production checkpoint-only `PrepareNetwork -> StartRuntime` reservation.
//!
//! An exact TAP is only the fallthrough admission to this effect. The effect
//! reopens the complete network, serving, device, Volume and installed-file
//! authorities on both sides of the Node-global Guest-CID critical section,
//! then performs exactly one checkpoint replacement. It never creates a
//! socket, launch file, systemd unit or VMM.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    CheckpointEvidence, DesiredRuntimeSpec, PrepareDeviceFrontend, RandomId128, ReconcileStep,
    RuntimeLaunchArtifact, UnixMillis, VmmBootProvenance,
};
#[cfg(target_os = "linux")]
use cats_api::runtime_reconciliation::{HostPath, ObservedRuntimeStatus};
use cats_storage::authority::{VolumeDataAuthority, VolumeRecord};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
};
use crate::state_directory::StateDirectory;

use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::kernel_nbd::{
    ExactKernelNbdDeviceProof, KernelNbdInventoryConfig, KernelNbdInventoryPort,
};
use super::network::{
    prepare_network_volume_admission_is_exact, prepared_device_set_is_exact,
    PrepareNetworkReservationEffect,
};
use super::prepare_device_retirement::{
    prepared_device_input_is_exact, retirement_authority_lease_is_monotonic, unique_runtime,
};
use super::serving_blockd_process::{
    ExactServingBlockdProcessProof, ServingBlockdExpectation, ServingBlockdProcessGlobalPort,
    ServingBlockdProcessInspection,
};
use super::serving_handoff_effect::checkpoint_is_current_exact;
use super::signed_root_provision::signed_inventory_admission_is_exact_with_networks;
#[cfg(target_os = "linux")]
use super::signed_root_provision::signed_start_runtime_inventory_admission_is_exact_with_networks;
use super::vmm_launch_artifacts::{RetainedVmmLaunchArtifacts, VmmLaunchArtifactPaths};
use super::vmm_process::VmmProcessGlobalPort;
#[cfg(target_os = "linux")]
use super::vmm_process::{CheckpointedVmmProcess, VmmProcessGlobalInspection};
#[cfg(target_os = "linux")]
use super::vmm_runtime_paths::{ManagedVmmLaunchPreparation, RetainedManagedVmmLaunchRoot};
#[cfg(target_os = "linux")]
use super::vmm_socket_namespace::{
    RetainedManagedVmmSocketRoot, VmmSocketOwnershipReceiptV1, VmmSocketReceiptStore,
};
use super::vmm_start_runtime::{build_start_runtime_successor, StartRuntimeCheckpointAuthority};
#[cfg(test)]
use super::PlatformExactVmmCidInventoryPort;
use super::{
    FileCheckpointStore, ManagedVmmLaunchFilePaths, ManagedVmmSocketRoot, StoredCheckpoint,
    VmmCidAllocationPort, VmmCidInventoryPort,
};

pub(crate) trait RetainedLaunchArtifactAuthority: Send + Sync {
    fn launcher_executable(&self) -> RuntimeLaunchArtifact;
    fn boot(&self) -> VmmBootProvenance;
    fn assert_current(&self) -> Result<()>;
}

pub(crate) trait LaunchArtifactAuthorityPort: Send + Sync {
    fn retain(&self) -> Result<Box<dyn RetainedLaunchArtifactAuthority>>;
}

#[cfg(test)]
type AfterCidReplaceHook = Arc<dyn Fn(&RuntimeDesiredEffectContext) -> Result<()> + Send + Sync>;

#[derive(Debug, Clone)]
struct InstalledLaunchArtifactAuthorityPort {
    paths: VmmLaunchArtifactPaths,
}

impl LaunchArtifactAuthorityPort for InstalledLaunchArtifactAuthorityPort {
    fn retain(&self) -> Result<Box<dyn RetainedLaunchArtifactAuthority>> {
        Ok(Box::new(RetainedVmmLaunchArtifacts::open(&self.paths)?))
    }
}

impl RetainedLaunchArtifactAuthority for RetainedVmmLaunchArtifacts {
    fn launcher_executable(&self) -> RuntimeLaunchArtifact {
        RetainedVmmLaunchArtifacts::launcher_executable(self).clone()
    }

    fn boot(&self) -> VmmBootProvenance {
        RetainedVmmLaunchArtifacts::boot(self)
    }

    fn assert_current(&self) -> Result<()> {
        RetainedVmmLaunchArtifacts::assert_current(self)
    }
}

pub(crate) struct StartRuntimeReservationEffect {
    state_directory: StateDirectory,
    cid: VmmCidAllocationPort,
    network: Arc<PrepareNetworkReservationEffect>,
    authority: Arc<dyn VolumeDataAuthority>,
    serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
    kernel_nbd: Option<KernelNbdInventoryPort>,
    artifacts: Arc<dyn LaunchArtifactAuthorityPort>,
    socket_root: ManagedVmmSocketRoot,
}

/// The fresh accepted-full `StartRuntime` owner. It adopts an exact VMM, or
/// consumes one sealed global-absence round to publish/recover durable launch
/// intent and submit systemd exactly once. It never advances into Guest work
/// in the same admission.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "production VMM mutation fields are intentionally inert on non-Linux hosts"
    )
)]
pub(crate) struct StartRuntimePhysicalEffect {
    state_directory: StateDirectory,
    network: Arc<PrepareNetworkReservationEffect>,
    authority: Arc<dyn VolumeDataAuthority>,
    serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
    vmm_process: Arc<dyn VmmProcessGlobalPort>,
    kernel_nbd: Option<KernelNbdInventoryPort>,
    artifact_paths: VmmLaunchArtifactPaths,
    #[cfg(test)]
    artifact_test_root: Option<std::path::PathBuf>,
    #[cfg(target_os = "linux")]
    socket_root: Arc<RetainedManagedVmmSocketRoot>,
    #[cfg(target_os = "linux")]
    launch_root: Arc<RetainedManagedVmmLaunchRoot>,
    #[cfg(target_os = "linux")]
    receipts: Arc<VmmSocketReceiptStore>,
    #[cfg(target_os = "linux")]
    submitted_admission: Mutex<Option<RandomId128>>,
}

struct AdmittedServingDevice<'a> {
    expectation: &'a ServingBlockdExpectation,
    serving: &'a ExactServingBlockdProcessProof,
    kernel_nbd: Option<&'a ExactKernelNbdDeviceProof>,
    first_authority: VolumeRecord,
    first_lease_expiry: UnixMillis,
}

impl StartRuntimeReservationEffect {
    pub(crate) fn platform(
        state_directory: StateDirectory,
        artifact_paths: VmmLaunchArtifactPaths,
        network: Arc<PrepareNetworkReservationEffect>,
        authority: Arc<dyn VolumeDataAuthority>,
        serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
        vmm_cid_inventory: Arc<dyn VmmCidInventoryPort>,
        kernel_nbd: Option<KernelNbdInventoryConfig>,
    ) -> Self {
        Self {
            state_directory: state_directory.clone(),
            cid: VmmCidAllocationPort::new(state_directory, vmm_cid_inventory),
            network,
            authority,
            serving_process,
            kernel_nbd: kernel_nbd.map(KernelNbdInventoryPort::new),
            artifacts: Arc::new(InstalledLaunchArtifactAuthorityPort {
                paths: artifact_paths,
            }),
            socket_root: ManagedVmmSocketRoot::installed(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        state_directory: StateDirectory,
        network: Arc<PrepareNetworkReservationEffect>,
        authority: Arc<dyn VolumeDataAuthority>,
        serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
        artifacts: Arc<dyn LaunchArtifactAuthorityPort>,
    ) -> Self {
        Self {
            state_directory: state_directory.clone(),
            cid: VmmCidAllocationPort::new(
                state_directory,
                Arc::new(PlatformExactVmmCidInventoryPort),
            ),
            network,
            authority,
            serving_process,
            kernel_nbd: None,
            artifacts,
            socket_root: ManagedVmmSocketRoot::installed(),
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn with_socket_root_for_test(mut self, socket_root: ManagedVmmSocketRoot) -> Self {
        self.socket_root = socket_root;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_after_cid_replace(mut self, hook: AfterCidReplaceHook) -> Self {
        self.cid = self.cid.with_after_replace(hook);
        self
    }

    /// Returns `None` for every phase except an exact current PrepareNetwork.
    /// A current StartRuntime therefore cannot be re-CASed after a successful
    /// publication or an ambiguous/cancelled response.
    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> Result<Option<RuntimeDesiredEffectOutcome>> {
        context.check_active()?;
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired)? else {
            return Ok(None);
        };
        let ReconcileStep::PrepareNetwork { network, devices } = &runtime.step else {
            return Ok(None);
        };
        let _node_global_effect = context.lock_node_global_effect()?;
        if devices.is_empty() || !prepared_device_set_is_exact(desired, devices) {
            return Ok(Some(local_contract_stop()));
        }
        let network_admission = context.node_global_network()?;
        let Some(expected_networks) = network_admission.expected_networks(&desired.cat_id, network)
        else {
            return Ok(Some(local_contract_stop()));
        };
        let [network_projection] = expected_networks.as_slice() else {
            // Absent TAP remains exclusively owned by the physical network
            // effect and must force another accepted full scan.
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if !signed_inventory_admission_is_exact_with_networks(
            accepted,
            desired,
            runtime,
            &expected_networks,
        ) || !checkpoint_is_current_exact(desired, runtime)
            || runtime.volumes.len() != devices.len()
            || !devices.iter().all(|device| {
                runtime
                    .volumes
                    .iter()
                    .find(|volume| volume.volume_id == device.volume_id)
                    .is_some_and(|volume| prepared_device_input_is_exact(device, desired, volume))
            })
        {
            return Ok(Some(local_contract_stop()));
        }
        let process_admission = context.node_global_process()?;
        anyhow::ensure!(
            process_admission.matches_observation(accepted.observation()),
            "StartRuntime process admission is not bound to the accepted full observation"
        );
        if process_admission.serving_blockd_count(&desired.cat_id) != devices.len() {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        }
        let mut serving_devices = Vec::with_capacity(devices.len());
        for device in devices {
            let Some((expectation, Some(serving))) =
                process_admission.serving_blockd(&desired.cat_id, &device.volume_id)
            else {
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
            };
            if !expectation.matches_device_contract(&desired.cat_id, device) {
                return Ok(Some(local_contract_stop()));
            }
            let (volume_id, observed_device, kernel_nbd_proof) = match &device.frontend {
                PrepareDeviceFrontend::VhostUserBlk { .. } => {
                    let Some((volume_id, observed)) = serving.vhost_device_projection() else {
                        return Ok(Some(local_contract_stop()));
                    };
                    (volume_id, observed, None)
                }
                PrepareDeviceFrontend::KernelNbd { .. } => {
                    let pool = context.kernel_nbd_pool()?;
                    anyhow::ensure!(
                        pool.matches_observation(accepted.observation()),
                        "StartRuntime kernel-NBD admission is not bound to the accepted full observation"
                    );
                    let exact = pool
                        .exact_device(&desired.cat_id, &device.volume_id)
                        .context("StartRuntime lacks an exact kernel-NBD device proof")?;
                    if exact.listener().expectation() != expectation
                        || !exact.matches_prepared_device(&desired.cat_id, device)
                    {
                        return Ok(Some(local_contract_stop()));
                    }
                    let (volume_id, observed) = exact.projection();
                    (volume_id, observed, Some(exact))
                }
            };
            if !prepare_network_volume_admission_is_exact(
                desired,
                runtime,
                device,
                &volume_id,
                Some(&observed_device),
            ) {
                return Ok(Some(local_contract_stop()));
            }
            let first_authority = self
                .authority
                .load_volume(expectation.volume_id())
                .context("load StartRuntime Volume authority")?;
            anyhow::ensure!(
                expectation.matches_current_authority(&first_authority),
                "StartRuntime Volume authority conflicts with serving admission"
            );
            let first_lease_expiry = first_authority
                .lease_expires_at
                .context("StartRuntime Volume authority lacks a serving lease")?;
            serving_devices.push(AdmittedServingDevice {
                expectation,
                serving,
                kernel_nbd: kernel_nbd_proof,
                first_authority,
                first_lease_expiry,
            });
        }
        if runtime.processes.len() != serving_devices.len()
            || !serving_devices.iter().all(|admitted| {
                runtime
                    .processes
                    .iter()
                    .filter(|process| admitted.serving.matches_public_process(process))
                    .count()
                    == 1
            })
        {
            return Ok(Some(local_contract_stop()));
        }
        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(Some(local_contract_stop()));
        };
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .context("open StartRuntime predecessor checkpoint")?;
        anyhow::ensure!(
            store.path() == Path::new(checkpoint_path.as_str()),
            "StartRuntime admission names another checkpoint path"
        );
        let Some(stored) = store.load().context("load StartRuntime predecessor")? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        }

        let retained_artifacts = match self.artifacts.retain() {
            Ok(artifacts) => artifacts,
            Err(_) => {
                return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::DeploymentMismatch,
                )))
            }
        };
        retained_artifacts.assert_current()?;
        let (runtime_incarnation, process_identity_token) =
            fresh_runtime_identities(network, devices)?;
        let socket_paths = self.socket_root.paths_for(&runtime_incarnation)?;
        let launch_file_paths = ManagedVmmLaunchFilePaths::for_incarnation(
            &self.state_directory,
            &runtime_incarnation,
        )?;
        let updated_at_unix_ms = monotonic_wall_clock(&stored)?;
        let launcher_executable = retained_artifacts.launcher_executable();
        let boot = retained_artifacts.boot();
        let network_projection = network_projection.clone();

        self.cid.reserve_and_replace(
            context,
            &store,
            &stored,
            || {
                self.revalidate_launch_authority(
                    context,
                    &store,
                    &stored,
                    &serving_devices,
                    retained_artifacts.as_ref(),
                )
            },
            |guest_cid| {
                build_start_runtime_successor(
                    stored.checkpoint(),
                    desired,
                    runtime_incarnation,
                    process_identity_token,
                    guest_cid,
                    StartRuntimeCheckpointAuthority {
                        launcher_executable,
                        boot,
                        network_projection,
                        socket_paths: &socket_paths,
                        launch_file_paths: &launch_file_paths,
                    },
                    updated_at_unix_ms,
                )
            },
        )?;
        Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the retained arguments are the exact cross-provider authority tuple revalidated as one CAS guard"
    )]
    fn revalidate_launch_authority(
        &self,
        context: &RuntimeDesiredEffectContext,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        serving_devices: &[AdmittedServingDevice<'_>],
        artifacts: &dyn RetainedLaunchArtifactAuthority,
    ) -> Result<()> {
        context.check_active()?;
        self.network
            .revalidate_exact_reserved(context, store, stored)?;
        for admitted in serving_devices {
            let current_process = match self
                .serving_process
                .inspect_serving_exact_or_absent_after_node_global_sweep(
                    admitted.expectation,
                    context,
                )
                .context("reinspect StartRuntime serving authority")?
            {
                ServingBlockdProcessInspection::Exact(evidence) => evidence,
                ServingBlockdProcessInspection::Absent
                | ServingBlockdProcessInspection::Conflict(_)
                | ServingBlockdProcessInspection::Unavailable => {
                    anyhow::bail!("StartRuntime serving authority is no longer exact")
                }
            };
            anyhow::ensure!(
                current_process.exactly_matches(admitted.expectation)
                    && current_process.as_ref() == admitted.serving.evidence(),
                "StartRuntime serving process/status authority drifted"
            );
            let current_authority = self
                .authority
                .load_volume(admitted.expectation.volume_id())
                .context("reread StartRuntime Volume authority")?;
            anyhow::ensure!(
                admitted
                    .expectation
                    .matches_current_authority(&current_authority)
                    && retirement_authority_lease_is_monotonic(
                        &admitted.first_authority,
                        &current_authority,
                        admitted.first_lease_expiry,
                    ),
                "StartRuntime Volume authority changed before CID publication"
            );
            match (admitted.kernel_nbd, &self.kernel_nbd) {
                (Some(admitted), Some(inventory)) => {
                    inventory.revalidate_exact_device(context, store, stored, admitted)?
                }
                (None, _) => {}
                (Some(_), None) => anyhow::bail!(
                    "StartRuntime kernel-NBD checkpoint lacks a production inventory port"
                ),
            }
        }
        artifacts
            .assert_current()
            .context("StartRuntime installed launch artifacts changed")?;
        context.check_active()
    }
}

impl StartRuntimePhysicalEffect {
    #[allow(
        clippy::too_many_arguments,
        reason = "production composition passes the already-sealed process and device authorities"
    )]
    pub(crate) fn platform(
        state_directory: StateDirectory,
        artifact_paths: VmmLaunchArtifactPaths,
        network: Arc<PrepareNetworkReservationEffect>,
        authority: Arc<dyn VolumeDataAuthority>,
        serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
        vmm_process: Arc<dyn VmmProcessGlobalPort>,
        kernel_nbd: Option<KernelNbdInventoryConfig>,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        let socket_root = Arc::new(
            RetainedManagedVmmSocketRoot::open_installed()
                .context("open installed physical StartRuntime socket root")?,
        );
        #[cfg(target_os = "linux")]
        let launch_root = Arc::new(
            RetainedManagedVmmLaunchRoot::open_existing(state_directory.clone())
                .context("open installed physical StartRuntime launch root")?,
        );
        #[cfg(target_os = "linux")]
        let receipts = Arc::new(
            VmmSocketReceiptStore::open_existing(state_directory.clone())
                .context("open installed physical StartRuntime receipt root")?,
        );
        Ok(Self {
            state_directory,
            network,
            authority,
            serving_process,
            vmm_process,
            kernel_nbd: kernel_nbd.map(KernelNbdInventoryPort::new),
            artifact_paths,
            #[cfg(test)]
            artifact_test_root: None,
            #[cfg(target_os = "linux")]
            socket_root,
            #[cfg(target_os = "linux")]
            launch_root,
            #[cfg(target_os = "linux")]
            receipts,
            #[cfg(target_os = "linux")]
            submitted_admission: Mutex::new(None),
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "tests inject each sealed physical authority independently"
    )]
    pub(crate) fn for_test(
        state_directory: StateDirectory,
        artifact_paths: VmmLaunchArtifactPaths,
        artifact_test_root: std::path::PathBuf,
        network: Arc<PrepareNetworkReservationEffect>,
        authority: Arc<dyn VolumeDataAuthority>,
        serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
        vmm_process: Arc<dyn VmmProcessGlobalPort>,
        socket_root: Arc<RetainedManagedVmmSocketRoot>,
        launch_root: Arc<RetainedManagedVmmLaunchRoot>,
        receipts: Arc<VmmSocketReceiptStore>,
    ) -> Self {
        Self {
            state_directory,
            network,
            authority,
            serving_process,
            vmm_process,
            kernel_nbd: None,
            artifact_paths,
            artifact_test_root: Some(artifact_test_root),
            socket_root,
            launch_root,
            receipts,
            submitted_admission: Mutex::new(None),
        }
    }

    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> Result<Option<RuntimeDesiredEffectOutcome>> {
        context.check_active()?;
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired)? else {
            return Ok(None);
        };
        if !matches!(runtime.step, ReconcileStep::StartRuntime { .. }) {
            return Ok(None);
        }
        let _node_global_effect = context.lock_node_global_effect()?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                &self.state_directory,
                &self.artifact_paths,
                context,
                desired,
                runtime,
            );
            Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()))
        }
        #[cfg(target_os = "linux")]
        self.try_apply_linux(context, desired, runtime)
    }

    #[cfg(target_os = "linux")]
    fn try_apply_linux(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        runtime: &ObservedRuntimeStatus,
    ) -> Result<Option<RuntimeDesiredEffectOutcome>> {
        let accepted = context.accepted_full()?;
        let ReconcileStep::StartRuntime {
            network,
            devices,
            runtime_incarnation,
            process_identity_token,
            ..
        } = &runtime.step
        else {
            unreachable!("caller selected StartRuntime")
        };
        if devices.is_empty() || !prepared_device_set_is_exact(desired, devices) {
            return Ok(Some(local_contract_stop()));
        }
        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(Some(local_contract_stop()));
        };
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .context("open physical StartRuntime checkpoint")?;
        anyhow::ensure!(
            store.path() == Path::new(checkpoint_path.as_str()),
            "physical StartRuntime admission names another checkpoint path"
        );
        let Some(stored) = store
            .load()
            .context("load physical StartRuntime checkpoint")?
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if stored.content_digest() != content_digest
            || !physical_start_runtime_checkpoint_evidence_is_exact(desired, runtime, &stored)
        {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        }
        let expectation = physical_vmm_expectation(&stored, checkpoint_path.clone())?;
        let process_admission = context.node_global_process()?;
        anyhow::ensure!(
            process_admission.matches_observation(accepted.observation()),
            "physical StartRuntime process admission is not bound to accepted full"
        );
        let Some((admitted_vmm_expectation, admitted_vmm)) = process_admission.vmm(&desired.cat_id)
        else {
            return Ok(Some(local_contract_stop()));
        };
        if admitted_vmm_expectation != &expectation {
            return Ok(Some(local_contract_stop()));
        }
        if let Some(admitted_vmm) = admitted_vmm {
            return Ok(Some(
                match self
                    .vmm_process
                    .inspect_vmm_exact_or_absent_after_node_global_sweep(&expectation, context)
                    .context("reinspect admitted physical VMM")?
                {
                    VmmProcessGlobalInspection::Exact(current)
                        if current.as_ref() == admitted_vmm =>
                    {
                        RuntimeDesiredEffectOutcome::refresh_inventory()
                    }
                    VmmProcessGlobalInspection::Exact(_)
                    | VmmProcessGlobalInspection::Conflict(_) => local_contract_stop(),
                    VmmProcessGlobalInspection::Absent(_)
                    | VmmProcessGlobalInspection::Unavailable => {
                        RuntimeDesiredEffectOutcome::refresh_inventory()
                    }
                },
            ));
        }

        let network_admission = context.node_global_network()?;
        let Some(expected_networks) = network_admission.expected_networks(&desired.cat_id, network)
        else {
            return Ok(Some(local_contract_stop()));
        };
        let [_expected_network] = expected_networks.as_slice() else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if !signed_start_runtime_inventory_admission_is_exact_with_networks(
            accepted,
            desired,
            runtime,
            &expected_networks,
            runtime_incarnation,
        ) {
            return Ok(Some(local_contract_stop()));
        }
        if process_admission.serving_blockd_count(&desired.cat_id) != devices.len() {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        }
        let mut serving_devices = Vec::with_capacity(devices.len());
        for device in devices {
            let Some((serving_expectation, Some(serving))) =
                process_admission.serving_blockd(&desired.cat_id, &device.volume_id)
            else {
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
            };
            if !serving_expectation.matches_device_contract(&desired.cat_id, device) {
                return Ok(Some(local_contract_stop()));
            }
            let (volume_id, observed_device, kernel_nbd_proof) = match &device.frontend {
                PrepareDeviceFrontend::VhostUserBlk { .. } => {
                    let Some((volume_id, observed)) = serving.vhost_device_projection() else {
                        return Ok(Some(local_contract_stop()));
                    };
                    (volume_id, observed, None)
                }
                PrepareDeviceFrontend::KernelNbd { .. } => {
                    let pool = context.kernel_nbd_pool()?;
                    anyhow::ensure!(
                        pool.matches_observation(accepted.observation()),
                        "physical StartRuntime kernel-NBD proof is not admission-bound"
                    );
                    let exact = pool
                        .exact_device(&desired.cat_id, &device.volume_id)
                        .context("physical StartRuntime lacks exact kernel-NBD device")?;
                    if exact.listener().expectation() != serving_expectation
                        || !exact.matches_prepared_device(&desired.cat_id, device)
                    {
                        return Ok(Some(local_contract_stop()));
                    }
                    let (volume_id, observed) = exact.projection();
                    (volume_id, observed, Some(exact))
                }
            };
            if !prepare_network_volume_admission_is_exact(
                desired,
                runtime,
                device,
                &volume_id,
                Some(&observed_device),
            ) {
                return Ok(Some(local_contract_stop()));
            }
            let first_authority = self
                .authority
                .load_volume(serving_expectation.volume_id())
                .context("load physical StartRuntime Volume authority")?;
            anyhow::ensure!(
                serving_expectation.matches_current_authority(&first_authority),
                "physical StartRuntime Volume authority conflicts with admission"
            );
            let first_lease_expiry = first_authority
                .lease_expires_at
                .context("physical StartRuntime Volume authority lacks serving lease")?;
            serving_devices.push(AdmittedServingDevice {
                expectation: serving_expectation,
                serving,
                kernel_nbd: kernel_nbd_proof,
                first_authority,
                first_lease_expiry,
            });
        }
        if runtime.processes.len() != serving_devices.len()
            || !serving_devices.iter().all(|admitted| {
                runtime
                    .processes
                    .iter()
                    .filter(|process| admitted.serving.matches_public_process(process))
                    .count()
                    == 1
            })
        {
            return Ok(Some(local_contract_stop()));
        }
        let artifacts = self
            .retain_physical_artifacts()
            .context("retain physical StartRuntime launch artifacts")?;
        CheckpointedVmmProcess::prepare(&expectation, &store, &stored, &artifacts)
            .context("validate physical StartRuntime checkpoint and artifacts")?;
        let socket_paths = self
            .socket_root
            .planner()
            .paths_from_checkpoint(stored.checkpoint())?;
        let launch_paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            &self.state_directory,
            stored.checkpoint(),
        )?;
        anyhow::ensure!(
            socket_paths.api_socket_path() == expectation.api_socket_path()
                && socket_paths.vsock_socket_path() == expectation.vsock_socket_path()
                && launch_paths.memory_file_path() == expectation.memory_file_path()
                && launch_paths.serial_log_path() == expectation.serial_log_path()
                && launch_paths.vmm_log_path() == expectation.vmm_log_path(),
            "physical StartRuntime managed path authority changed"
        );

        // Holding the exclusive namespace guard closes every supported late
        // launcher while the global absence proof is refreshed and consumed.
        let Some(namespace_guard) = self.launch_root.try_lock_effect_namespace()? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        let _initial_authority = namespace_guard.bind_fresh_absence(
            self.revalidate_absent_physical_authority(
                context,
                &store,
                &stored,
                &expectation,
                &serving_devices,
                &artifacts,
            )?,
            stored.checkpoint(),
        )?;

        let receipt = match self.receipts.load(runtime_incarnation)? {
            Some(receipt) => {
                receipt.validate_against(
                    stored.checkpoint(),
                    &self.state_directory,
                    &self.socket_root,
                )?;
                receipt
            }
            None => {
                let nonce =
                    fresh_receipt_nonce(runtime_incarnation, process_identity_token, devices)?;
                let receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
                    stored.checkpoint(),
                    &self.state_directory,
                    &self.socket_root,
                    accepted.session().node_boot_id.clone(),
                    nonce,
                )?;
                // Receipt publication is itself a mutation boundary.
                let receipt_authority = namespace_guard.bind_fresh_absence(
                    self.revalidate_absent_physical_authority(
                        context,
                        &store,
                        &stored,
                        &expectation,
                        &serving_devices,
                        &artifacts,
                    )?,
                    stored.checkpoint(),
                )?;
                receipt_authority.assert_for(&self.launch_root, stored.checkpoint())?;
                self.receipts.publish(&receipt)?;
                self.receipts
                    .load(runtime_incarnation)?
                    .context("published physical StartRuntime receipt disappeared")?
            }
        };
        receipt.validate_against(
            stored.checkpoint(),
            &self.state_directory,
            &self.socket_root,
        )?;

        let launch_authority = namespace_guard.bind_fresh_absence(
            self.revalidate_absent_physical_authority(
                context,
                &store,
                &stored,
                &expectation,
                &serving_devices,
                &artifacts,
            )?,
            stored.checkpoint(),
        )?;
        let preparation = self.launch_root.prepare_existing_receipt(
            &launch_authority,
            stored.checkpoint(),
            &receipt,
        )?;
        // Publishing the receipt-owned attempt marker is only the first
        // filesystem mutation. Close that boundary with another fresh global
        // sweep under the same exclusive namespace guard, then continue to
        // the one submit in this admission when the exact attempt is ready.
        let preparation = match preparation {
            ManagedVmmLaunchPreparation::PublishedIntent => {
                let published_authority = namespace_guard.bind_fresh_absence(
                    self.revalidate_absent_physical_authority(
                        context,
                        &store,
                        &stored,
                        &expectation,
                        &serving_devices,
                        &artifacts,
                    )?,
                    stored.checkpoint(),
                )?;
                self.launch_root.prepare_existing_receipt(
                    &published_authority,
                    stored.checkpoint(),
                    &receipt,
                )?
            }
            other => other,
        };
        let ready = match preparation {
            ManagedVmmLaunchPreparation::PublishedIntent => {
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
            }
            ManagedVmmLaunchPreparation::Residue(residue) => {
                let cleanup_authority = namespace_guard.bind_fresh_absence(
                    self.revalidate_absent_physical_authority(
                        context,
                        &store,
                        &stored,
                        &expectation,
                        &serving_devices,
                        &artifacts,
                    )?,
                    stored.checkpoint(),
                )?;
                residue.recover(&cleanup_authority, stored.checkpoint())?;
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
            }
            ManagedVmmLaunchPreparation::Ready(ready) => ready,
        };
        ready.assert_ready()?;
        let submit_authority = namespace_guard.bind_fresh_absence(
            self.revalidate_absent_physical_authority(
                context,
                &store,
                &stored,
                &expectation,
                &serving_devices,
                &artifacts,
            )?,
            stored.checkpoint(),
        )?;
        submit_authority.assert_for(&self.launch_root, stored.checkpoint())?;
        ready.assert_ready()?;
        self.receipts.assert_current()?;

        // This is the sole submission call in the admission. Every result,
        // including definite local exec failure or response loss, requires a
        // new accepted full scan before another attempt.
        self.revalidate_physical_dependencies(
            context,
            &store,
            &stored,
            &serving_devices,
            &artifacts,
        )?;
        ready.assert_ready()?;
        let current_receipt = self
            .receipts
            .load(runtime_incarnation)?
            .context("physical StartRuntime receipt disappeared before submit")?;
        anyhow::ensure!(
            current_receipt == receipt,
            "physical StartRuntime receipt changed before submit"
        );
        let checkpointed =
            CheckpointedVmmProcess::prepare(&expectation, &store, &stored, &artifacts)?;
        let observation_id = &context.accepted_full()?.observation().observation_id;
        let mut submitted = self
            .submitted_admission
            .lock()
            .map_err(|_| anyhow::anyhow!("physical StartRuntime submission gate poisoned"))?;
        if submitted.as_ref() == Some(observation_id) {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        }
        *submitted = Some(observation_id.clone());
        drop(submitted);
        self.vmm_process.start_checkpointed(checkpointed, context)?;
        // Keep the same exclusive launch namespace coordinate alive from the
        // final fresh global absence sweep through the systemd submission.
        // The launcher takes the corresponding shared lock before touching
        // any leaf, so it cannot race this proof or its final revalidations.
        drop(submit_authority);
        drop(namespace_guard);
        Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()))
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_arguments,
        reason = "the complete cross-provider physical launch authority is revalidated as one tuple"
    )]
    fn revalidate_absent_physical_authority(
        &self,
        context: &RuntimeDesiredEffectContext,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        expectation: &super::vmm_process::VmmProcessExpectation,
        serving_devices: &[AdmittedServingDevice<'_>],
        artifacts: &RetainedVmmLaunchArtifacts,
    ) -> Result<super::vmm_process::ExactVmmProcessAbsenceProof> {
        self.revalidate_physical_dependencies(context, store, stored, serving_devices, artifacts)?;
        match self
            .vmm_process
            .inspect_vmm_exact_or_absent_after_node_global_sweep(expectation, context)?
        {
            VmmProcessGlobalInspection::Absent(absence) => Ok(*absence),
            VmmProcessGlobalInspection::Exact(_) => {
                anyhow::bail!("physical StartRuntime VMM appeared before mutation")
            }
            VmmProcessGlobalInspection::Conflict(problem) => {
                anyhow::bail!("physical StartRuntime VMM conflicts ({problem:?})")
            }
            VmmProcessGlobalInspection::Unavailable => {
                anyhow::bail!("physical StartRuntime VMM inventory is unavailable")
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_arguments,
        reason = "all non-VMM launch dependencies are revalidated immediately before each mutation or submit"
    )]
    fn revalidate_physical_dependencies(
        &self,
        context: &RuntimeDesiredEffectContext,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        serving_devices: &[AdmittedServingDevice<'_>],
        artifacts: &RetainedVmmLaunchArtifacts,
    ) -> Result<()> {
        context.check_active()?;
        let current_checkpoint = store
            .load()
            .context("reread physical StartRuntime checkpoint")?
            .context("physical StartRuntime checkpoint disappeared")?;
        anyhow::ensure!(
            current_checkpoint.content_digest() == stored.content_digest()
                && current_checkpoint.checkpoint() == stored.checkpoint(),
            "physical StartRuntime checkpoint changed"
        );
        self.network
            .revalidate_exact_reserved(context, store, stored)?;
        for admitted in serving_devices {
            let current_serving = match self
                .serving_process
                .inspect_serving_exact_or_absent_after_node_global_sweep(
                    admitted.expectation,
                    context,
                )? {
                ServingBlockdProcessInspection::Exact(evidence) => evidence,
                ServingBlockdProcessInspection::Absent
                | ServingBlockdProcessInspection::Conflict(_)
                | ServingBlockdProcessInspection::Unavailable => {
                    anyhow::bail!("physical StartRuntime serving authority is no longer exact")
                }
            };
            anyhow::ensure!(
                current_serving.as_ref() == admitted.serving.evidence()
                    && current_serving.exactly_matches(admitted.expectation),
                "physical StartRuntime serving authority drifted"
            );
            let current_authority = self
                .authority
                .load_volume(admitted.expectation.volume_id())?;
            anyhow::ensure!(
                admitted
                    .expectation
                    .matches_current_authority(&current_authority)
                    && retirement_authority_lease_is_monotonic(
                        &admitted.first_authority,
                        &current_authority,
                        admitted.first_lease_expiry,
                    ),
                "physical StartRuntime Volume authority changed"
            );
            match (admitted.kernel_nbd, &self.kernel_nbd) {
                (Some(admitted), Some(inventory)) => {
                    inventory.revalidate_exact_device(context, store, stored, admitted)?
                }
                (None, _) => {}
                (Some(_), None) => anyhow::bail!(
                    "physical StartRuntime kernel-NBD checkpoint lacks production inventory"
                ),
            }
        }
        artifacts.assert_current()?;
        self.socket_root.assert_current()?;
        self.launch_root.assert_current()?;
        self.receipts.assert_current()?;
        context.check_active()
    }

    #[cfg(target_os = "linux")]
    fn retain_physical_artifacts(&self) -> Result<RetainedVmmLaunchArtifacts> {
        #[cfg(test)]
        if let Some(root) = &self.artifact_test_root {
            return RetainedVmmLaunchArtifacts::open_for_test(root, &self.artifact_paths);
        }
        RetainedVmmLaunchArtifacts::open(&self.artifact_paths)
    }
}

#[cfg(target_os = "linux")]
fn physical_vmm_expectation(
    stored: &StoredCheckpoint,
    checkpoint_path: HostPath,
) -> Result<super::vmm_process::VmmProcessExpectation> {
    super::retained_runtime_launch::RetainedRuntimeLaunchAuthority::from_start_runtime_checkpoint(
        stored.checkpoint(),
    )?;
    super::vmm_process::VmmProcessExpectation::from_checkpoint(stored.checkpoint().clone())?
        .with_checkpoint_path(checkpoint_path)
}

#[cfg(target_os = "linux")]
fn physical_start_runtime_checkpoint_evidence_is_exact(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    stored: &StoredCheckpoint,
) -> bool {
    let checkpoint = stored.checkpoint();
    matches!(
        &runtime.checkpoint,
        CheckpointEvidence::Valid {
            content_digest,
            version,
            cat_id,
            node_id,
            desired_revision,
            spec_digest,
            placement_epoch,
            runtime_incarnation,
            runtime_launch,
            stable_state,
            step,
            require_idle,
            updated_at_unix_ms,
            ..
        } if content_digest == stored.content_digest()
            && *version == checkpoint.version
            && cat_id == &checkpoint.cat_id
            && cat_id == &desired.cat_id
            && node_id == &checkpoint.node_id
            && node_id == &desired.placement.node_id
            && *desired_revision == checkpoint.desired_revision
            && *desired_revision == desired.desired_revision
            && spec_digest == &checkpoint.spec_digest
            && spec_digest == &desired.spec_digest
            && *placement_epoch == checkpoint.placement_epoch
            && *placement_epoch == desired.placement.placement_epoch
            && runtime_incarnation == &checkpoint.runtime_incarnation
            && runtime_launch.as_ref() == &checkpoint.runtime_launch
            && *stable_state == checkpoint.stable_state
            && step.as_ref() == &checkpoint.step
            && runtime.step == checkpoint.step
            && require_idle.as_ref() == &checkpoint.require_idle
            && *updated_at_unix_ms == checkpoint.updated_at_unix_ms
            && super::retained_runtime_launch::RetainedRuntimeLaunchAuthority::from_start_runtime_checkpoint(checkpoint).is_ok()
    )
}

#[cfg(target_os = "linux")]
fn fresh_receipt_nonce(
    runtime_incarnation: &RandomId128,
    process_identity_token: &RandomId128,
    devices: &[cats_api::runtime_reconciliation::PreparedDeviceInput],
) -> Result<RandomId128> {
    let mut occupied =
        BTreeSet::from([runtime_incarnation.clone(), process_identity_token.clone()]);
    for device in devices {
        occupied.insert(device.ownership_token.clone());
        occupied.insert(device.serving_process.process_identity_token.clone());
    }
    fresh_random_id(&occupied)
}

fn fresh_runtime_identities(
    network: &cats_api::runtime_reconciliation::RuntimeNetworkIdentity,
    devices: &[cats_api::runtime_reconciliation::PreparedDeviceInput],
) -> Result<(RandomId128, RandomId128)> {
    let mut occupied = BTreeSet::from([network.ownership_token.clone()]);
    for device in devices {
        occupied.insert(device.ownership_token.clone());
        occupied.insert(device.serving_process.process_identity_token.clone());
    }
    let runtime_incarnation = fresh_random_id(&occupied)?;
    occupied.insert(runtime_incarnation.clone());
    let process_identity_token = fresh_random_id(&occupied)?;
    Ok((runtime_incarnation, process_identity_token))
}

fn fresh_random_id(occupied: &BTreeSet<RandomId128>) -> Result<RandomId128> {
    for _ in 0..16 {
        let candidate = RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .context("generate StartRuntime identity entropy")?;
        if !occupied.contains(&candidate) {
            return Ok(candidate);
        }
    }
    anyhow::bail!("StartRuntime identity entropy repeatedly collided")
}

fn monotonic_wall_clock(stored: &StoredCheckpoint) -> Result<UnixMillis> {
    let wall_clock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis();
    let wall_clock_ms = u64::try_from(wall_clock_ms).context("system time exceeds wire range")?;
    let minimum = stored
        .checkpoint()
        .updated_at_unix_ms
        .get()
        .checked_add(1)
        .context("StartRuntime checkpoint timestamp exhausted")?;
    UnixMillis::new(wall_clock_ms.max(minimum))
        .context("StartRuntime checkpoint timestamp is outside wire range")
}

fn local_contract_stop() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}
