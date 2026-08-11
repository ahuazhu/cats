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
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    CheckpointEvidence, DesiredRuntimeSpec, PrepareDeviceFrontend, RandomId128, ReconcileStep,
    RuntimeLaunchArtifact, UnixMillis, VmmBootProvenance,
};
use cats_storage::authority::{VolumeDataAuthority, VolumeRecord};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
};
use crate::state_directory::StateDirectory;

use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::kernel_nbd::{
    ExactKernelNbdDeviceProof, KernelNbdInventoryConfig, KernelNbdInventoryPort,
};
use super::network::{prepare_network_volume_admission_is_exact, PrepareNetworkReservationEffect};
use super::prepare_device_retirement::{
    prepared_device_input_is_exact, retirement_authority_lease_is_monotonic, unique_runtime,
};
use super::serving_blockd_process::{
    ExactServingBlockdProcessProof, ServingBlockdExpectation, ServingBlockdProcessGlobalPort,
    ServingBlockdProcessInspection,
};
use super::serving_handoff_effect::checkpoint_is_current_exact;
use super::signed_root_provision::signed_inventory_admission_is_exact_with_networks;
use super::vmm_launch_artifacts::{RetainedVmmLaunchArtifacts, VmmLaunchArtifactPaths};
use super::vmm_start_runtime::{build_start_runtime_successor, StartRuntimeCheckpointAuthority};
use super::{
    FileCheckpointStore, ManagedVmmLaunchFilePaths, ManagedVmmSocketRoot,
    PlatformExactVmmCidInventoryPort, StoredCheckpoint, VmmCidAllocationPort,
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

impl StartRuntimeReservationEffect {
    pub(crate) fn platform(
        state_directory: StateDirectory,
        artifact_paths: VmmLaunchArtifactPaths,
        network: Arc<PrepareNetworkReservationEffect>,
        authority: Arc<dyn VolumeDataAuthority>,
        serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
        kernel_nbd: Option<KernelNbdInventoryConfig>,
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
        let [device] = devices.as_slice() else {
            return Ok(Some(local_contract_stop()));
        };
        let network_admission = context.node_global_network()?;
        let Some(expected_networks) = network_admission.expected_networks(&desired.cat_id, network)
        else {
            return Ok(Some(local_contract_stop()));
        };
        let [network_projection] = expected_networks.as_slice() else {
            // Absent TAP remains exclusively owned by the physical network
            // effect and must force another accepted full scan.
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        let [observed_volume] = runtime.volumes.as_slice() else {
            return Ok(Some(local_contract_stop()));
        };
        if !signed_inventory_admission_is_exact_with_networks(
            accepted,
            desired,
            runtime,
            &expected_networks,
        ) || !checkpoint_is_current_exact(desired, runtime)
            || !prepared_device_input_is_exact(device, desired, observed_volume)
        {
            return Ok(Some(local_contract_stop()));
        }
        let process_admission = context.node_global_process()?;
        anyhow::ensure!(
            process_admission.matches_observation(accepted.observation()),
            "StartRuntime process admission is not bound to the accepted full observation"
        );
        let Some((expectation, Some(serving))) = process_admission.serving_blockd(&desired.cat_id)
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
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
                    .exact_device(&desired.cat_id)
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
        ) || !matches!(
            runtime.processes.as_slice(),
            [process] if serving.matches_public_process(process)
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
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
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
            fresh_runtime_identities(network, device)?;
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
                    expectation,
                    serving,
                    kernel_nbd_proof,
                    &first_authority,
                    first_lease_expiry,
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
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
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
        expectation: &ServingBlockdExpectation,
        admitted_serving: &ExactServingBlockdProcessProof,
        admitted_kernel_nbd: Option<&ExactKernelNbdDeviceProof>,
        first_authority: &VolumeRecord,
        first_lease_expiry: UnixMillis,
        artifacts: &dyn RetainedLaunchArtifactAuthority,
    ) -> Result<()> {
        context.check_active()?;
        self.network
            .revalidate_exact_reserved(context, store, stored)?;
        let current_process = match self
            .serving_process
            .inspect_serving_exact_or_absent_after_node_global_sweep(expectation, context)
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
            current_process.exactly_matches(expectation)
                && current_process.as_ref() == admitted_serving.evidence(),
            "StartRuntime serving process/status authority drifted"
        );
        let current_authority = self
            .authority
            .load_volume(expectation.volume_id())
            .context("reread StartRuntime Volume authority")?;
        anyhow::ensure!(
            expectation.matches_current_authority(&current_authority)
                && retirement_authority_lease_is_monotonic(
                    first_authority,
                    &current_authority,
                    first_lease_expiry,
                ),
            "StartRuntime Volume authority changed before CID publication"
        );
        match (admitted_kernel_nbd, &self.kernel_nbd) {
            (Some(admitted), Some(inventory)) => {
                inventory.revalidate_exact_device(context, store, stored, admitted)?
            }
            (None, _) => {}
            (Some(_), None) => anyhow::bail!(
                "StartRuntime kernel-NBD checkpoint lacks a production inventory port"
            ),
        }
        artifacts
            .assert_current()
            .context("StartRuntime installed launch artifacts changed")?;
        context.check_active()
    }
}

fn fresh_runtime_identities(
    network: &cats_api::runtime_reconciliation::RuntimeNetworkIdentity,
    device: &cats_api::runtime_reconciliation::PreparedDeviceInput,
) -> Result<(RandomId128, RandomId128)> {
    let mut occupied = BTreeSet::from([
        network.ownership_token.clone(),
        device.ownership_token.clone(),
        device.serving_process.process_identity_token.clone(),
    ]);
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
