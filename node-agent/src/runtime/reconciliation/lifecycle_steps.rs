//! Checkpoint-first dispatch for the closed lifecycle/cleanup suffix.
//!
//! This module deliberately owns the complete N1 step set.  A step which has
//! no installed exact physical adapter is still consumed here and returns a
//! fresh-inventory decision; it must never fall through to the Running
//! acquire planner or to a legacy teardown path.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use cats_api::guest::GUEST_HOST_CONTROL_VSOCK_PORT_V1;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, encode_runtime_checkpoint, AuthorizationConsumedReceipt,
    AuthorizationState, CheckpointEvidence, CleanupRelease, CleanupTarget, ContractVersion,
    DesiredRuntimeSpec, DiskKind, FenceEpoch, FilesystemInitialization, Generation,
    GuestTransportEvidence, HostPath, Id, LastVolumeTransition, LifecycleAdmission, NodeResidue,
    ObservedDevice, ObservedDiskKind, ObservedRuntimeStatus, ObservedVolume,
    OwnershipTokenEvidence, ProcessEvidence, ProcessRole, RandomId128, ReconcileStep,
    RequireIdleCheckpoint, RuntimeCheckpoint, RuntimeLaunch, RuntimeTarget,
    RuntimeVolumeTransition, RuntimeVolumeTransitionEvidenceRequest,
    RuntimeVolumeTransitionRequest, SessionBinding, StableState, VolumeAcquire, VolumeAdminState,
    VolumeAuthorityEvidence, VolumeAuthorization, VolumeDisposition, VolumeIntent,
    VolumeReleaseReplay, WarmSnapshotEvidence,
};
use cats_storage::authority::{validate_volume_record, VolumeDataAuthority, VolumeRecord};

use crate::guest_client::GuestClient;
use crate::object_write_credential::ObjectWriteCredentialPort;
use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
};

use super::blockd_socket_namespace::ManagedBlockdSocketOwnerRetirement;
use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::kernel_nbd::{KernelNbdDetachPort, KernelNbdDetachResult};
use super::persistent_filesystem::{
    post_drain_authority_is_same_attachment, status_generation, PersistentBlockdControlPort,
    PlatformPersistentBlockdControlPort,
};
use super::prepare_device_retirement::unique_runtime;
use super::serving_blockd_process::{
    ServingBlockdProcessGlobalPort, ServingBlockdProcessInspection,
};
use super::signed_running::SignedLifecycleVolumePort;
use super::vmm_process::{VmmProcessGlobalInspection, VmmProcessGlobalPort};
#[cfg(target_os = "linux")]
use super::vmm_runtime_paths::RetainedManagedVmmLaunchRoot;
#[cfg(target_os = "linux")]
use super::vmm_socket_namespace::{RetainedManagedVmmSocketRoot, VmmSocketReceiptStore};
use super::{
    recover_lifecycle_release_from_authority, DisposableRootDeleteAttempt, FileCheckpointStore,
    NormalAcquireAcceptedContext, NormalReleaseAttempt, NormalReleaseAuthorityRecovery,
    StoredCheckpoint, VolumeEvidenceRecovery, VolumeEvidenceRecoveryDecision,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecyclePhysicalAttempt {
    /// One bounded effect may have reached the external target.  Response
    /// loss and cancellation intentionally share this result: only a fresh
    /// full inventory can settle it.
    SubmittedOrAmbiguous,
    /// The adapter proved the exact postcondition without mutating anything.
    /// The planner still waits for a fresh accepted projection before it
    /// publishes a successor checkpoint.
    ExactPostcondition,
    /// This release does not yet install a safe adapter for the selected
    /// physical boundary.  Retain the checkpoint and report progress.
    Unavailable,
    /// The physical identity is no longer the one named by the checkpoint.
    Conflict,
    /// Guest quiesce and the exact attachment's remote drain both completed
    /// under the retained checkpoint, and an independent authority read plus
    /// exact serving status proved the final durable generation.
    VerifiedDrain(DrainPublishReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DrainPublishReceipt {
    volumes: Vec<DrainedVolumeReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DrainedVolumeReceipt {
    volume_id: Id,
    attachment_epoch: FenceEpoch,
    local_generation: Generation,
    remote_generation: Generation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisposableEvidenceContext {
    ObservedDeleting,
    AmbiguousOwnedAttempt,
}

/// Opaque, current-checkpoint permit passed to one sealed lifecycle adapter.
/// Public observations cannot construct this value.
pub(crate) struct LifecycleEffectPermit<'a> {
    desired: &'a DesiredRuntimeSpec,
    runtime: &'a ObservedRuntimeStatus,
    store: &'a FileCheckpointStore,
    stored: &'a StoredCheckpoint,
}

impl LifecycleEffectPermit<'_> {
    pub(crate) fn desired(&self) -> &DesiredRuntimeSpec {
        self.desired
    }

    pub(crate) fn runtime(&self) -> &ObservedRuntimeStatus {
        self.runtime
    }

    pub(crate) fn checkpoint(&self) -> &RuntimeCheckpoint {
        self.stored.checkpoint()
    }

    fn store(&self) -> &FileCheckpointStore {
        self.store
    }

    fn stored(&self) -> &StoredCheckpoint {
        self.stored
    }
}

/// One bounded physical effect.  The closed trait is intentionally narrow:
/// it cannot publish a checkpoint successor or reinterpret a cleanup target.
pub(crate) trait LifecyclePhysicalPort: Send + Sync {
    fn apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        permit: LifecycleEffectPermit<'_>,
    ) -> anyhow::Result<LifecyclePhysicalAttempt>;
}

struct PlatformLifecyclePhysicalPort {
    network_ip_binary: PathBuf,
    serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
    vmm_process: Arc<dyn VmmProcessGlobalPort>,
    kernel_nbd_detach: Option<Arc<dyn KernelNbdDetachPort>>,
    blockd: PlatformPersistentBlockdControlPort,
    volume_authority: Arc<dyn VolumeDataAuthority>,
}

struct ExactDrainVolume<'a> {
    volume_id: Id,
    attachment_epoch: FenceEpoch,
    local_generation: Generation,
    remote_generation: Generation,
    serving: &'a super::serving_blockd_process::ExactServingBlockdProcessProof,
    authority: VolumeRecord,
}

impl LifecyclePhysicalPort for PlatformLifecyclePhysicalPort {
    fn apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        permit: LifecycleEffectPermit<'_>,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        let _accepted_projection = permit.runtime();
        if let ReconcileStep::CleanupRelease { cleanup } = &permit.checkpoint().step {
            return match &cleanup.target {
                CleanupTarget::Network {
                    network_id,
                    ownership_token,
                } => self.remove_exact_network(context, &permit, network_id, ownership_token),
                CleanupTarget::Device {
                    volume_id,
                    ownership_token,
                } => self.detach_exact_device(context, &permit, volume_id, ownership_token),
                CleanupTarget::Scope {
                    scope_id,
                    process_start_time_ticks,
                } => self.stop_exact_scope(context, &permit, scope_id, *process_start_time_ticks),
                target => classify_unadapted_cleanup(context, &permit, target),
            };
        }
        if let ReconcileStep::DrainPublish {
            volume_id,
            attachment_epoch,
            local_generation,
            remote_generation,
        } = &permit.checkpoint().step
        {
            return self.drain_exact_volume(
                context,
                &permit,
                volume_id,
                *attachment_epoch,
                *local_generation,
                *remote_generation,
            );
        }
        let (runtime_incarnation, process_start_time_ticks, stop_scope) =
            match &permit.checkpoint().step {
                ReconcileStep::PauseRuntime {
                    runtime_incarnation,
                    process_start_time_ticks,
                } => (runtime_incarnation, *process_start_time_ticks, None),
                ReconcileStep::StopRuntime {
                    runtime_incarnation,
                    process_start_time_ticks,
                    scope_id,
                } => (
                    runtime_incarnation,
                    *process_start_time_ticks,
                    Some(scope_id),
                ),
                // Snapshot requires its own descriptor-retained durable
                // publication owner and is not approximated by an
                // unjournaled request here.
                _ => return Ok(LifecyclePhysicalAttempt::Unavailable),
            };
        let accepted = context.accepted_full()?;
        let processes = context.node_global_process()?;
        if !processes.matches_observation(accepted.observation()) {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let Some((expected, admitted_exact)) = processes.vmm(&permit.desired().cat_id) else {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        };
        if expected.checkpoint() != permit.checkpoint()
            || expected.runtime_incarnation() != runtime_incarnation
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let Some(exact) = admitted_exact else {
            return if stop_scope.is_some()
                && !permit.runtime().processes.iter().any(|process| {
                    matches!(
                        &process.role,
                        ProcessRole::Vmm { runtime_incarnation: observed }
                            if observed == runtime_incarnation
                    )
                }) {
                self.retire_stopped_vmm_private_state(context, expected, permit.checkpoint())
            } else {
                Ok(LifecyclePhysicalAttempt::Conflict)
            };
        };
        if exact.evidence().process_start_time_ticks() != process_start_time_ticks
            || stop_scope.is_some_and(|scope| exact.evidence().unit_id() != scope)
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        if stop_scope.is_some() {
            return self.stop_exact_vmm(context, expected, exact);
        }
        match exact.evidence().state() {
            cats_api::runtime_reconciliation::ProcessState::Paused => {
                Ok(LifecyclePhysicalAttempt::ExactPostcondition)
            }
            cats_api::runtime_reconciliation::ProcessState::Running => {
                let Some(launch) = permit.checkpoint().runtime_launch.identity() else {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                };
                if permit.runtime().guest_transport != permit.checkpoint().guest_transport
                    || !guest_transport_matches_launch(permit.runtime(), launch)
                {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                }
                let guest = match ExactGuestQuiesce::prepare(context, launch, exact) {
                    Ok(guest) => guest,
                    Err(_) => return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous),
                };
                if guest.revalidate(context, exact).is_err() {
                    return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous);
                }
                exact.assert_current(context)?;
                context.check_active()?;
                // Any return after connecting to the VMM is an ambiguous
                // external outcome.  A fresh full scan is the only oracle.
                let _ = crate::ch::pause_bounded(
                    Path::new(exact.evidence().api_socket_path().as_str()),
                    context,
                );
                Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous)
            }
        }
    }
}

impl PlatformLifecyclePhysicalPort {
    #[allow(clippy::too_many_arguments)]
    fn drain_exact_volume(
        &self,
        context: &RuntimeDesiredEffectContext,
        permit: &LifecycleEffectPermit<'_>,
        volume_id: &Id,
        attachment_epoch: FenceEpoch,
        local_generation: Generation,
        remote_generation: Generation,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        let accepted = context.accepted_full()?;
        let processes = context.node_global_process()?;
        if !processes.matches_observation(accepted.observation()) {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let Some(launch) = permit.checkpoint().runtime_launch.identity() else {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        };
        if permit.checkpoint().runtime_incarnation.as_ref() != Some(&launch.runtime_incarnation)
            || permit.runtime().runtime_incarnation.as_ref() != Some(&launch.runtime_incarnation)
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }

        let mut ordered = permit.desired().volumes.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|intent| intent.guest_device.slot);
        if ordered.first().map(|intent| &intent.volume_id) != Some(volume_id)
            || ordered.len() != permit.runtime().volumes.len()
            || ordered
                .windows(2)
                .any(|pair| pair[0].guest_device.slot == pair[1].guest_device.slot)
            || processes.serving_blockd_count(&permit.desired().cat_id) != ordered.len()
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let mut drains = Vec::with_capacity(ordered.len());
        for (index, intent) in ordered.iter().enumerate() {
            let mut observed = permit
                .runtime()
                .volumes
                .iter()
                .filter(|volume| volume.volume_id == intent.volume_id);
            let Some(volume) = observed.next() else {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            };
            if observed.next().is_some()
                || volume.volume_intent_id.as_ref() != Some(&intent.volume_intent_id)
                || volume.disk_id.as_ref() != Some(&intent.disk_id)
            {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            let VolumeAuthorityEvidence::Owned {
                attachment_id,
                attachment_epoch: observed_epoch,
                head,
            } = &volume.authority
            else {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            };
            if attachment_id != &intent.attachment_id
                || (index == 0 && *observed_epoch != attachment_epoch)
            {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            let mut lineages = volume.local_lineages.iter().filter(|lineage| {
                lineage.attachment_id == *attachment_id
                    && lineage.attachment_epoch == *observed_epoch
                    && lineage.node_id == permit.desired().placement.node_id
                    && lineage.placement_epoch == permit.desired().placement.placement_epoch
            });
            let Some(lineage) = lineages.next() else {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            };
            if lineages.next().is_some()
                || lineage.local_durable_generation < lineage.remote_durable_generation
                || lineage.remote_durable_generation != head.generation
                || (index == 0
                    && (lineage.local_durable_generation < local_generation
                        || lineage.remote_durable_generation < remote_generation))
            {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            let Some((serving_expectation, Some(serving))) =
                processes.serving_blockd(&permit.desired().cat_id, &intent.volume_id)
            else {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            };
            if serving.expectation() != serving_expectation
                || permit
                    .runtime()
                    .processes
                    .iter()
                    .filter(|process| serving.matches_public_process(process))
                    .count()
                    != 1
                || serving.assert_listener_current(context).is_err()
            {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            let authority = match self.volume_authority.load_volume(&intent.volume_id) {
                Ok(authority) => authority,
                Err(_) => return Ok(LifecyclePhysicalAttempt::Unavailable),
            };
            if !serving_expectation.matches_current_authority(&authority)
                || authority.lease_epoch != *observed_epoch
                || authority.head != *head
            {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            drains.push(ExactDrainVolume {
                volume_id: intent.volume_id.clone(),
                attachment_epoch: *observed_epoch,
                local_generation: lineage.local_durable_generation,
                remote_generation: lineage.remote_durable_generation,
                serving,
                authority,
            });
        }

        let Some((vmm_expectation, admitted_vmm)) = processes.vmm(&permit.desired().cat_id) else {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        };
        if vmm_expectation.checkpoint() != permit.checkpoint()
            || vmm_expectation.runtime_incarnation() != &launch.runtime_incarnation
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let guest = if let Some(vmm) = admitted_vmm {
            let Ok(public_vmm) = exact_vmm_process(permit.runtime()) else {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            };
            if vmm.clone().into_process_evidence() != *public_vmm
                || vmm.evidence().state() != cats_api::runtime_reconciliation::ProcessState::Running
                || permit.runtime().guest_transport != permit.checkpoint().guest_transport
                || !guest_transport_matches_launch(permit.runtime(), launch)
            {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            match ExactGuestQuiesce::prepare(context, launch, vmm) {
                Ok(guest) => Some(guest),
                Err(_) => return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous),
            }
        } else if permit
            .runtime()
            .processes
            .iter()
            .any(|process| matches!(process.role, ProcessRole::Vmm { .. }))
            || !matches!(
                permit.runtime().guest_transport,
                GuestTransportEvidence::Unavailable
            )
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        } else {
            None
        };

        let mut receipts = Vec::with_capacity(drains.len());
        for drain in drains {
            if drain.serving.assert_listener_current(context).is_err() {
                return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous);
            }
            let status = match self.blockd.drain(context, drain.serving) {
                Ok(status) => status,
                Err(_) => return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous),
            };
            context.check_active()?;
            let after = match self.volume_authority.load_volume(&drain.volume_id) {
                Ok(authority) => authority,
                Err(_) => return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous),
            };
            if !post_drain_authority_is_same_attachment(&drain.authority, &after)
                || !drain
                    .serving
                    .validates_fully_drained_status_at_head(&status, &after.head)
            {
                return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous);
            }
            let drained_local = match status_generation(status.local_durable_generation) {
                Ok(generation) => generation,
                Err(_) => return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous),
            };
            let drained_remote = match status_generation(status.remote_durable_generation) {
                Ok(generation) => generation,
                Err(_) => return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous),
            };
            if drained_local != drained_remote
                || drained_remote != after.head.generation
                || drained_local < drain.local_generation
                || drained_remote < drain.remote_generation
            {
                return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous);
            }
            receipts.push(DrainedVolumeReceipt {
                volume_id: drain.volume_id,
                attachment_epoch: drain.attachment_epoch,
                local_generation: drained_local,
                remote_generation: drained_remote,
            });
        }
        if guest.is_some_and(|guest| guest.revalidate(context, admitted_vmm.unwrap()).is_err())
            || admitted_vmm.is_some_and(|vmm| vmm.assert_current(context).is_err())
        {
            return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous);
        }
        Ok(LifecyclePhysicalAttempt::VerifiedDrain(
            DrainPublishReceipt { volumes: receipts },
        ))
    }

    fn detach_exact_device(
        &self,
        context: &RuntimeDesiredEffectContext,
        permit: &LifecycleEffectPermit<'_>,
        volume_id: &Id,
        ownership_token: &RandomId128,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        let vhost = permit
            .checkpoint()
            .runtime_launch
            .identity()
            .and_then(|launch| {
                let mut matching = launch.devices.iter().filter(|device| {
                    &device.volume_id == volume_id && &device.ownership_token == ownership_token
                });
                let prepared = matching.next()?;
                matching.next().is_none().then_some(prepared)
            })
            .filter(|prepared| {
                matches!(
                    &prepared.frontend,
                    cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk { .. }
                )
            });
        match vhost {
            Some(prepared) => self.retire_exact_serving_device(context, permit, prepared),
            None => {
                let detached = detach_exact_kernel_nbd_device(
                    self.kernel_nbd_detach.as_deref(),
                    context,
                    permit,
                    volume_id,
                    ownership_token,
                )?;
                if detached != LifecyclePhysicalAttempt::ExactPostcondition {
                    return Ok(detached);
                }
                let prepared = permit
                    .checkpoint()
                    .runtime_launch
                    .identity()
                    .and_then(|launch| {
                        let mut matching = launch.devices.iter().filter(|device| {
                            &device.volume_id == volume_id
                                && &device.ownership_token == ownership_token
                        });
                        let prepared = matching.next()?;
                        matching.next().is_none().then_some(prepared)
                    })
                    .context("exact kernel-NBD postcondition lost its prepared device")?;
                self.retire_exact_serving_device(context, permit, prepared)
            }
        }
    }

    fn retire_exact_serving_device(
        &self,
        context: &RuntimeDesiredEffectContext,
        permit: &LifecycleEffectPermit<'_>,
        prepared: &cats_api::runtime_reconciliation::PreparedDeviceInput,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        if permit
            .runtime()
            .processes
            .iter()
            .any(|process| matches!(process.role, ProcessRole::Vmm { .. }))
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let accepted = context.accepted_full()?;
        let processes = context.node_global_process()?;
        if !processes.matches_observation(accepted.observation()) {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let Some((expected, admitted)) =
            processes.serving_blockd(&permit.desired().cat_id, &prepared.volume_id)
        else {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        };
        if !expected.matches_device_contract(&permit.desired().cat_id, prepared) {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        match admitted {
            Some(admitted) => self.stop_exact_serving(context, expected, admitted),
            None => {
                match self
                    .serving_process
                    .inspect_serving_exact_or_absent_after_node_global_sweep(expected, context)?
                {
                    ServingBlockdProcessInspection::Absent => {
                        match self
                            .serving_process
                            .retire_absent_socket_owner(expected, context)?
                        {
                            ManagedBlockdSocketOwnerRetirement::Retired => {
                                Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous)
                            }
                            ManagedBlockdSocketOwnerRetirement::AlreadyAbsent => {
                                Ok(LifecyclePhysicalAttempt::ExactPostcondition)
                            }
                        }
                    }
                    ServingBlockdProcessInspection::Unavailable => {
                        Ok(LifecyclePhysicalAttempt::Unavailable)
                    }
                    ServingBlockdProcessInspection::Exact(_)
                    | ServingBlockdProcessInspection::Conflict(_) => {
                        Ok(LifecyclePhysicalAttempt::Conflict)
                    }
                }
            }
        }
    }

    fn stop_exact_serving(
        &self,
        context: &RuntimeDesiredEffectContext,
        expected: &super::serving_blockd_process::ServingBlockdExpectation,
        admitted: &super::serving_blockd_process::ExactServingBlockdProcessProof,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        match self
            .serving_process
            .inspect_serving_exact_or_absent_after_node_global_sweep(expected, context)?
        {
            ServingBlockdProcessInspection::Absent => {
                Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous)
            }
            ServingBlockdProcessInspection::Exact(fresh)
                if fresh.stable_identity_eq(admitted.evidence()) =>
            {
                if admitted.assert_listener_current(context).is_err() {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                }
                signal_exact_process_bounded(
                    context,
                    fresh.as_ref().clone().into_process_evidence(),
                )
            }
            ServingBlockdProcessInspection::Unavailable => {
                Ok(LifecyclePhysicalAttempt::Unavailable)
            }
            ServingBlockdProcessInspection::Exact(_)
            | ServingBlockdProcessInspection::Conflict(_) => Ok(LifecyclePhysicalAttempt::Conflict),
        }
    }

    fn remove_exact_network(
        &self,
        context: &RuntimeDesiredEffectContext,
        permit: &LifecycleEffectPermit<'_>,
        network_id: &Id,
        ownership_token: &RandomId128,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        let Some(launch) = permit.checkpoint().runtime_launch.identity() else {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        };
        let identity = launch.network.as_ref();
        if &identity.network_config.network_id != network_id
            || &identity.ownership_token != ownership_token
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let accepted = context.accepted_full()?;
        let admitted = context.node_global_network()?;
        if !admitted.matches_observation(accepted.observation()) {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let Some(expected) = admitted.expected_networks(&permit.desired().cat_id, identity) else {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        };
        if permit.runtime().networks != expected {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let NetworkCleanupPlan::Remove(network) = plan_network_cleanup(identity, &expected) else {
            return Ok(LifecyclePhysicalAttempt::ExactPostcondition);
        };
        let _node_global = context.lock_node_global_effect()?;
        let admitted = context.node_global_network()?;
        if !admitted.matches_observation(accepted.observation())
            || !admitted.has_exact_network(&permit.desired().cat_id, identity)
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        context.check_active()?;
        let _ = crate::ch::remove_network_bounded(&self.network_ip_binary, &network, context);
        Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous)
    }

    fn stop_exact_vmm(
        &self,
        context: &RuntimeDesiredEffectContext,
        expected: &super::vmm_process::VmmProcessExpectation,
        admitted: &super::vmm_process::ExactVmmProcessProof,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        match self
            .vmm_process
            .inspect_vmm_exact_or_absent_after_node_global_sweep(expected, context)?
        {
            VmmProcessGlobalInspection::Absent(_) => {
                self.retire_stopped_vmm_private_state(context, expected, expected.checkpoint())
            }
            VmmProcessGlobalInspection::Exact(fresh)
                if fresh.expectation() == admitted.expectation()
                    && fresh.evidence() == admitted.evidence() =>
            {
                if fresh.assert_current(context).is_err() {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                }
                signal_exact_process_bounded(
                    context,
                    fresh.evidence().clone().into_process_evidence(),
                )
            }
            VmmProcessGlobalInspection::Unavailable => Ok(LifecyclePhysicalAttempt::Unavailable),
            VmmProcessGlobalInspection::Exact(_) | VmmProcessGlobalInspection::Conflict(_) => {
                Ok(LifecyclePhysicalAttempt::Conflict)
            }
        }
    }

    fn retire_stopped_vmm_private_state(
        &self,
        context: &RuntimeDesiredEffectContext,
        expected: &super::vmm_process::VmmProcessExpectation,
        checkpoint: &RuntimeCheckpoint,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (context, expected, checkpoint);
            return Ok(LifecyclePhysicalAttempt::Unavailable);
        }
        #[cfg(target_os = "linux")]
        {
            anyhow::ensure!(
                expected.checkpoint() == checkpoint,
                "StopRuntime private retirement names another checkpoint"
            );
            let socket_root = RetainedManagedVmmSocketRoot::open_installed()
                .context("open StopRuntime VMM socket root")?;
            let state = context.state_directory().clone();
            let launch_root = Arc::new(
                RetainedManagedVmmLaunchRoot::open_existing(state.clone())
                    .context("open StopRuntime VMM launch root")?,
            );
            let receipts = VmmSocketReceiptStore::open_existing(state)
                .context("open StopRuntime VMM receipt store")?;
            let retired = launch_root.retire_current_boot_stop(
                &socket_root,
                &receipts,
                checkpoint,
                context,
                |_| {
                    Ok(
                        match self
                            .vmm_process
                            .inspect_vmm_exact_or_absent_after_node_global_sweep(
                                expected, context,
                            )? {
                            VmmProcessGlobalInspection::Absent(absence) => Some(*absence),
                            VmmProcessGlobalInspection::Exact(_)
                            | VmmProcessGlobalInspection::Conflict(_)
                            | VmmProcessGlobalInspection::Unavailable => None,
                        },
                    )
                },
            )?;
            Ok(if retired {
                LifecyclePhysicalAttempt::ExactPostcondition
            } else {
                LifecyclePhysicalAttempt::SubmittedOrAmbiguous
            })
        }
    }

    fn stop_exact_scope(
        &self,
        context: &RuntimeDesiredEffectContext,
        permit: &LifecycleEffectPermit<'_>,
        scope_id: &Id,
        process_start_time_ticks: cats_api::runtime_reconciliation::WireU64,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        let classified = classify_unadapted_cleanup(
            context,
            permit,
            &CleanupTarget::Scope {
                scope_id: scope_id.clone(),
                process_start_time_ticks,
            },
        )?;
        if classified != LifecyclePhysicalAttempt::Unavailable {
            return Ok(classified);
        }
        let accepted = context.accepted_full()?;
        let processes = context.node_global_process()?;
        if !processes.matches_observation(accepted.observation()) {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let mut matches = permit.runtime().processes.iter().filter(|process| {
            &process.scope_id == scope_id
                && process.process_start_time_ticks == process_start_time_ticks
        });
        let Some(public) = matches.next() else {
            return Ok(LifecyclePhysicalAttempt::ExactPostcondition);
        };
        if matches.next().is_some() {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        match &public.role {
            ProcessRole::Vmm {
                runtime_incarnation,
            } => {
                let Some((expected, Some(admitted))) = processes.vmm(&permit.desired().cat_id)
                else {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                };
                if expected.checkpoint() != permit.checkpoint()
                    || expected.runtime_incarnation() != runtime_incarnation
                    || admitted.clone().into_process_evidence() != *public
                {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                }
                self.stop_exact_vmm(context, expected, admitted)
            }
            ProcessRole::Blockd { volume_id, .. } => {
                let Some((expected, Some(admitted))) =
                    processes.serving_blockd(&permit.desired().cat_id, volume_id)
                else {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                };
                if !admitted.matches_public_process(public) {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                }
                self.stop_exact_serving(context, expected, admitted)
            }
        }
    }
}

fn guest_transport_matches_launch(
    runtime: &ObservedRuntimeStatus,
    launch: &cats_api::runtime_reconciliation::RuntimeLaunchIdentity,
) -> bool {
    matches!(
        &runtime.guest_transport,
        GuestTransportEvidence::VsockReady {
            runtime_incarnation,
            guest_cid,
            guest_port,
            guest_agent_protocol_version: ContractVersion::V1,
            ..
        } if runtime_incarnation == &launch.runtime_incarnation
            && *guest_cid == launch.guest_cid
            && u32::from(*guest_port) == GUEST_HOST_CONTROL_VSOCK_PORT_V1
    )
}

struct ExactGuestQuiesce {
    client: GuestClient,
    source_epoch: String,
    lease_sequence: u64,
}

impl ExactGuestQuiesce {
    fn prepare(
        context: &RuntimeDesiredEffectContext,
        launch: &cats_api::runtime_reconciliation::RuntimeLaunchIdentity,
        vmm: &super::vmm_process::ExactVmmProcessProof,
    ) -> anyhow::Result<Self> {
        context.check_active()?;
        anyhow::ensure!(
            vmm.expectation().launch_identity() == launch,
            "Guest quiesce VMM differs from retained launch"
        );
        vmm.assert_current(context)?;
        let remaining = context
            .deadline()
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("Guest quiesce deadline expired")?;
        let mut client = GuestClient::connect_hybrid_vsock_bounded(
            Path::new(launch.vsock_socket_path.as_str()),
            GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            remaining,
        )?;
        let shutdown = client.try_clone_transport()?;
        let guard = std::thread::scope(|scope| -> anyhow::Result<Self> {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            scope.spawn(move || {
                let result = (|| -> anyhow::Result<Self> {
                    let before = client
                        .work_status(None, 0)
                        .context("read Guest work fence before quiesce")?;
                    let (source_epoch, lease_sequence) = client
                        .prepare_suspend(before.lease_sequence)
                        .context("close Guest work gate")?;
                    anyhow::ensure!(
                        source_epoch == before.source_epoch
                            && lease_sequence == before.lease_sequence
                            && before.leases.is_empty(),
                        "Guest quiesce response changed the accepted work fence"
                    );
                    client.syncfs().context("flush Guest filesystems")?;
                    let after = client
                        .work_status(None, 0)
                        .context("revalidate Guest work fence after syncfs")?;
                    anyhow::ensure!(
                        after.source_epoch == source_epoch
                            && after.lease_sequence == lease_sequence
                            && after.quiescing
                            && after.leases.is_empty(),
                        "Guest work changed across quiesce and syncfs"
                    );
                    Ok(Self {
                        client,
                        source_epoch,
                        lease_sequence,
                    })
                })();
                let _ = sender.send(result);
            });
            receive_guest_result(context, &shutdown, receiver)
        })?;
        context.check_active()?;
        vmm.assert_current(context)?;
        Ok(guard)
    }

    fn revalidate(
        mut self,
        context: &RuntimeDesiredEffectContext,
        vmm: &super::vmm_process::ExactVmmProcessProof,
    ) -> anyhow::Result<()> {
        context.check_active()?;
        vmm.assert_current(context)?;
        let shutdown = self.client.try_clone_transport()?;
        let source_epoch = self.source_epoch;
        let lease_sequence = self.lease_sequence;
        std::thread::scope(|scope| -> anyhow::Result<()> {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            scope.spawn(move || {
                let result = (|| -> anyhow::Result<()> {
                    let status = self
                        .client
                        .work_status(None, 0)
                        .context("revalidate Guest work fence after all Volume drains")?;
                    anyhow::ensure!(
                        status.source_epoch == source_epoch
                            && status.lease_sequence == lease_sequence
                            && status.quiescing
                            && status.leases.is_empty(),
                        "Guest work fence changed across all Volume drains"
                    );
                    Ok(())
                })();
                let _ = sender.send(result);
            });
            receive_guest_result(context, &shutdown, receiver)
        })?;
        context.check_active()?;
        vmm.assert_current(context)
    }
}

fn receive_guest_result<T>(
    context: &RuntimeDesiredEffectContext,
    shutdown: &std::os::unix::net::UnixStream,
    receiver: std::sync::mpsc::Receiver<anyhow::Result<T>>,
) -> anyhow::Result<T> {
    loop {
        match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("Guest control worker exited without a result")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Err(error) = context.check_active() {
                    let _ = shutdown.shutdown(std::net::Shutdown::Both);
                    return Err(error);
                }
            }
        }
    }
}

fn detach_exact_kernel_nbd_device(
    detach: Option<&dyn KernelNbdDetachPort>,
    context: &RuntimeDesiredEffectContext,
    permit: &LifecycleEffectPermit<'_>,
    volume_id: &Id,
    ownership_token: &RandomId128,
) -> anyhow::Result<LifecyclePhysicalAttempt> {
    if permit
        .runtime()
        .processes
        .iter()
        .any(|process| matches!(process.role, ProcessRole::Vmm { .. }))
    {
        return Ok(LifecyclePhysicalAttempt::Conflict);
    }
    let Some(launch) = permit.checkpoint().runtime_launch.identity() else {
        return Ok(LifecyclePhysicalAttempt::Conflict);
    };
    let mut prepared_matches = launch
        .devices
        .iter()
        .filter(|prepared| &prepared.volume_id == volume_id);
    let Some(prepared) = prepared_matches.next() else {
        return Ok(LifecyclePhysicalAttempt::Conflict);
    };
    if prepared_matches.next().is_some() || &prepared.ownership_token != ownership_token {
        return Ok(LifecyclePhysicalAttempt::Conflict);
    }
    match &prepared.frontend {
        cats_api::runtime_reconciliation::PrepareDeviceFrontend::KernelNbd {
            device_path: expected_path,
            ..
        } => {
            let matching_devices = permit
                .runtime()
                .volumes
                .iter()
                .filter(|volume| &volume.volume_id == volume_id)
                .flat_map(|volume| &volume.devices)
                .collect::<Vec<_>>();
            if matching_devices.len() > 1
                || matching_devices.first().is_some_and(|device| {
                    !matches!(
                        device,
                        ObservedDevice::KernelNbd {
                            guest_device,
                            device_path,
                            ownership_token: observed_token,
                        } if guest_device == &prepared.guest_device
                            && device_path == expected_path
                            && valid_token(observed_token) == Some(ownership_token)
                    )
                })
            {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }

            let mut matching_residue = context
                .accepted_full()?
                .observation()
                .residue
                .iter()
                .filter(|residue| matches!(
                    residue,
                    NodeResidue::KernelNbd {
                        volume_id_hint,
                        device_path,
                        ..
                    } if volume_id_hint.as_ref() == Some(volume_id) || device_path == expected_path
                ));
            let residue_count = match matching_residue.next() {
                None => 0,
                Some(NodeResidue::KernelNbd {
                    volume_id_hint: Some(observed_volume),
                    guest_device: Some(observed_guest),
                    device_path,
                    ownership_token: OwnershipTokenEvidence::Missing,
                }) if observed_volume == volume_id
                    && observed_guest == &prepared.guest_device
                    && device_path == expected_path
                    && matching_residue.next().is_none() =>
                {
                    1
                }
                Some(_) => return Ok(LifecyclePhysicalAttempt::Conflict),
            };
            match (matching_devices.len(), residue_count) {
                (0, 0) => return Ok(LifecyclePhysicalAttempt::ExactPostcondition),
                (1, 0) | (0, 1) => {}
                _ => return Ok(LifecyclePhysicalAttempt::Conflict),
            }
        }
        cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk {
            socket_path: expected_path,
            ..
        } => {
            let classified = classify_unadapted_cleanup(
                context,
                permit,
                &CleanupTarget::Device {
                    volume_id: volume_id.clone(),
                    ownership_token: ownership_token.clone(),
                },
            )?;
            if classified != LifecyclePhysicalAttempt::Unavailable {
                return Ok(classified);
            }
            let mut matching = permit
                .runtime()
                .volumes
                .iter()
                .filter(|volume| &volume.volume_id == volume_id)
                .flat_map(|volume| &volume.devices)
                .filter(|device| device_token(device) == Some(ownership_token));
            let Some(device) = matching.next() else {
                return Ok(LifecyclePhysicalAttempt::ExactPostcondition);
            };
            if matching.next().is_some()
                || !matches!(device, ObservedDevice::VhostUserBlk {
                    guest_device,
                    socket_path,
                    ..
                } if socket_path == expected_path && guest_device == &prepared.guest_device)
            {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            return Ok(LifecyclePhysicalAttempt::Unavailable);
        }
    }
    let Some(detach) = detach else {
        return Ok(LifecyclePhysicalAttempt::Unavailable);
    };
    Ok(
        match detach.detach_checkpointed(
            volume_id,
            ownership_token,
            permit.store(),
            permit.stored(),
            context,
        )? {
            KernelNbdDetachResult::SubmittedOrAmbiguous => {
                LifecyclePhysicalAttempt::SubmittedOrAmbiguous
            }
            KernelNbdDetachResult::Conflict => LifecyclePhysicalAttempt::Conflict,
            KernelNbdDetachResult::Unavailable => LifecyclePhysicalAttempt::Unavailable,
        },
    )
}

#[cfg(target_os = "linux")]
fn signal_exact_process_bounded(
    context: &RuntimeDesiredEffectContext,
    process: ProcessEvidence,
) -> anyhow::Result<LifecyclePhysicalAttempt> {
    use crate::proc::{ExactPidFd, ExactPidFdOpen, PidFdSignal, ProcIdentity};

    context.check_active()?;
    let expected = ProcIdentity {
        pid: process.process_id,
        start_ticks: Some(process.process_start_time_ticks.get()),
        exe: Some(PathBuf::from(process.executable_path.as_str())),
    };
    let pidfd = match ExactPidFd::open_exact(&expected)? {
        ExactPidFdOpen::Exact(pidfd) => pidfd,
        ExactPidFdOpen::Absent => return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous),
        ExactPidFdOpen::IdentityMismatch => return Ok(LifecyclePhysicalAttempt::Conflict),
        ExactPidFdOpen::Unsupported => return Ok(LifecyclePhysicalAttempt::Unavailable),
    };
    context.check_active()?;
    match pidfd.signal(libc::SIGTERM)? {
        PidFdSignal::Submitted | PidFdSignal::AlreadyExited => {}
        PidFdSignal::Unsupported => return Ok(LifecyclePhysicalAttempt::Unavailable),
    }
    let graceful_deadline = context
        .deadline()
        .min(Instant::now() + Duration::from_secs(2));
    while Instant::now() < graceful_deadline {
        if pidfd.exited()? || context.check_active().is_err() {
            return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if context.check_active().is_ok() {
        match pidfd.signal(libc::SIGKILL)? {
            PidFdSignal::Submitted | PidFdSignal::AlreadyExited => {}
            PidFdSignal::Unsupported => return Ok(LifecyclePhysicalAttempt::Unavailable),
        }
    }
    Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous)
}

#[cfg(not(target_os = "linux"))]
fn signal_exact_process_bounded(
    _context: &RuntimeDesiredEffectContext,
    _process: ProcessEvidence,
) -> anyhow::Result<LifecyclePhysicalAttempt> {
    Ok(LifecyclePhysicalAttempt::Unavailable)
}

enum NetworkCleanupPlan {
    ExactPostcondition,
    Remove(crate::ch::ChNetwork),
}

fn plan_network_cleanup(
    identity: &cats_api::runtime_reconciliation::RuntimeNetworkIdentity,
    expected: &[cats_api::runtime_reconciliation::ObservedNetwork],
) -> NetworkCleanupPlan {
    if expected.is_empty() {
        return NetworkCleanupPlan::ExactPostcondition;
    }
    NetworkCleanupPlan::Remove(crate::ch::ChNetwork {
        tap: identity.tap_name.as_str().to_owned(),
        ownership_token: identity.ownership_token.clone(),
        config: identity.network_config.clone(),
    })
}

fn classify_unadapted_cleanup(
    context: &RuntimeDesiredEffectContext,
    permit: &LifecycleEffectPermit<'_>,
    target: &CleanupTarget,
) -> anyhow::Result<LifecyclePhysicalAttempt> {
    let present = match target {
        CleanupTarget::Device {
            volume_id,
            ownership_token,
        } => {
            let mut exact = 0_usize;
            let mut drift = false;
            for volume in permit
                .runtime()
                .volumes
                .iter()
                .filter(|volume| &volume.volume_id == volume_id)
            {
                for device in &volume.devices {
                    let evidence = match device {
                        ObservedDevice::KernelNbd {
                            ownership_token, ..
                        }
                        | ObservedDevice::VhostUserBlk {
                            ownership_token, ..
                        } => ownership_token,
                    };
                    if valid_token(evidence) == Some(ownership_token) {
                        exact += 1;
                    } else {
                        drift = true;
                    }
                }
            }
            if drift || exact > 1 {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            exact
        }
        CleanupTarget::WarmSnapshot { snapshot_id } => match &permit.runtime().warm_snapshot {
            WarmSnapshotEvidence::Absent => 0,
            WarmSnapshotEvidence::Present {
                snapshot_id: observed,
                ..
            } if observed == snapshot_id => 1,
            WarmSnapshotEvidence::Present { .. } => return Ok(LifecyclePhysicalAttempt::Conflict),
        },
        CleanupTarget::Scope {
            scope_id,
            process_start_time_ticks,
        } => {
            let mut exact = 0_usize;
            for process in &permit.runtime().processes {
                if &process.scope_id == scope_id {
                    if &process.process_start_time_ticks != process_start_time_ticks {
                        return Ok(LifecyclePhysicalAttempt::Conflict);
                    }
                    exact += 1;
                }
            }
            if exact > 1 {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            exact
        }
        CleanupTarget::OrphanScope {
            scope_id,
            cgroup_path,
            ownership_token,
        } => {
            let mut exact = 0_usize;
            for residue in &context.accepted_full()?.observation().residue {
                if let NodeResidue::SystemdScope {
                    scope_id: observed_scope,
                    cgroup_path: observed_cgroup,
                    ownership_token: observed_token,
                } = residue
                {
                    if observed_scope == scope_id {
                        if observed_cgroup != cgroup_path
                            || valid_token(observed_token) != Some(ownership_token)
                        {
                            return Ok(LifecyclePhysicalAttempt::Conflict);
                        }
                        exact += 1;
                    }
                }
            }
            if exact > 1 {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            exact
        }
        CleanupTarget::ControlSocket {
            socket_path,
            ownership_token,
        } => {
            let mut exact = 0_usize;
            for residue in &context.accepted_full()?.observation().residue {
                if let NodeResidue::ControlSocket {
                    socket_path: observed_path,
                    ownership_token: observed_token,
                    ..
                } = residue
                {
                    if observed_path == socket_path {
                        if valid_token(observed_token) != Some(ownership_token) {
                            return Ok(LifecyclePhysicalAttempt::Conflict);
                        }
                        exact += 1;
                    }
                }
            }
            if exact > 1 {
                return Ok(LifecyclePhysicalAttempt::Conflict);
            }
            exact
        }
        CleanupTarget::CheckpointFile { .. } => {
            // A per-Cat checkpoint cannot journal deleting itself.  Only the
            // NodeCleanupCheckpoint single-slot owner may consume this arm.
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        CleanupTarget::Volume { .. } | CleanupTarget::Network { .. } => {
            return Ok(LifecyclePhysicalAttempt::Conflict)
        }
    };
    Ok(if present == 0 {
        LifecyclePhysicalAttempt::ExactPostcondition
    } else {
        // The exact target exists, but this release lacks the target-specific
        // retained handle/stop receipt needed to remove it safely.
        LifecyclePhysicalAttempt::Unavailable
    })
}

fn valid_token(
    evidence: &OwnershipTokenEvidence,
) -> Option<&cats_api::runtime_reconciliation::RandomId128> {
    match evidence {
        OwnershipTokenEvidence::Valid { ownership_token } => Some(ownership_token),
        OwnershipTokenEvidence::Missing | OwnershipTokenEvidence::Corrupt { .. } => None,
    }
}

pub(crate) struct LifecycleStepEffect {
    physical: Arc<dyn LifecyclePhysicalPort>,
    volume_transition: Arc<dyn SignedLifecycleVolumePort>,
    volume_authority: Arc<dyn VolumeDataAuthority>,
    /// Retires the object-write credential of every attachment epoch this
    /// lifecycle suffix ends. `None` composes a Node with no ObjectWrite
    /// Gateway, whose grants never carried one.
    credentials: Option<Arc<dyn ObjectWriteCredentialPort>>,
    #[cfg(feature = "proposed-node-residue-reclamation")]
    data_directory_reclaim: Option<super::DataDirectoryReclaimEffect>,
}

impl LifecycleStepEffect {
    pub(crate) fn platform(
        network_ip_binary: PathBuf,
        volume_transition: Arc<dyn SignedLifecycleVolumePort>,
        volume_authority: Arc<dyn VolumeDataAuthority>,
        serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
        vmm_process: Arc<dyn VmmProcessGlobalPort>,
        kernel_nbd_detach: Option<Arc<dyn KernelNbdDetachPort>>,
        #[cfg(feature = "proposed-node-residue-reclamation")]
        residue_authority: super::RuntimeVolumeTransitionHttpClient,
    ) -> Self {
        let physical_volume_authority = Arc::clone(&volume_authority);
        Self {
            physical: Arc::new(PlatformLifecyclePhysicalPort {
                network_ip_binary,
                serving_process,
                vmm_process,
                kernel_nbd_detach,
                blockd: PlatformPersistentBlockdControlPort,
                volume_authority: physical_volume_authority,
            }),
            volume_transition,
            volume_authority,
            credentials: None,
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim: Some(super::DataDirectoryReclaimEffect::new(residue_authority)),
        }
    }

    /// Binds the Node's object-write credential authority so an ended epoch
    /// loses its private key with the release that ended it.
    pub(crate) fn with_object_write_credentials(
        mut self,
        credentials: Arc<dyn ObjectWriteCredentialPort>,
    ) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        context.check_active()?;
        if matches!(
            desired.target,
            RuntimeTarget::Suspended | RuntimeTarget::Warm
        ) {
            return Ok(Some(stop_local()));
        }
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired)? else {
            return Ok(None);
        };
        if matches!(
            runtime.step,
            ReconcileStep::Stable {
                state: StableState::Cold
            }
        ) {
            return self
                .plan_cold_membership_rebind(context, accepted, desired, runtime)
                .map(Some);
        }
        if matches!(runtime.step, ReconcileStep::CleanupRelease { .. }) {
            if let Some(outcome) =
                self.apply_cold_membership_detach_cleanup(context, accepted, desired, runtime)?
            {
                return Ok(Some(outcome));
            }
        }
        if runtime.stable_state == Some(StableState::Suspended)
            || matches!(
                runtime.step,
                ReconcileStep::Stable {
                    state: StableState::Suspended
                }
            )
        {
            // This release has no frozen ResumeRuntime checkpoint token. Keep
            // an already-paused VMM and its possibly unique R<L journal
            // untouched instead of letting a later Running/cleanup effect
            // reinterpret Stable Suspended as a launch or teardown permit.
            return Ok(Some(stop_local()));
        }

        if !is_lifecycle_step(&runtime.step) {
            if let Some(outcome) = self.plan_first(context, desired, runtime)? {
                return Ok(Some(outcome));
            }
            return Ok(None);
        }
        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(Some(stop_local()));
        };
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .context("open lifecycle checkpoint store")?;
        if store.path() != Path::new(checkpoint_path.as_str()) {
            return Ok(Some(stop_local()));
        }
        let Some(stored) = store.load().context("load lifecycle checkpoint")? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if stored.content_digest() != content_digest
            || stored.checkpoint().step != runtime.step
            || stored.checkpoint().lifecycle_admission != LifecycleAdmission::Closed
            || runtime.lifecycle_admission != LifecycleAdmission::Closed
            || runtime.platform_guards != 0
            || runtime
                .routes
                .iter()
                .any(|route| route.active_guards != 0 || route.cancellation_pending)
        {
            return Ok(Some(stop_local()));
        }
        if !checkpoint_is_current(desired, stored.checkpoint()) {
            if let Some(successor) = superseded_drain_rebind_successor(
                desired,
                runtime,
                stored.checkpoint(),
                accepted.attestation().accepted_at_unix_ms,
            )? {
                encode_runtime_checkpoint(&successor)
                    .context("validate current lifecycle repair successor checkpoint")?;
                context.check_active()?;
                let current = store
                    .assert_current(&stored)
                    .context("retain superseded lifecycle checkpoint for current repair CAS")?;
                persist_lifecycle_successor(
                    context,
                    &store,
                    &stored,
                    &successor,
                    &current,
                    "rebind exact superseded Drain to current lifecycle intent",
                )?;
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
            }
            // A late pause/stop is containable only by a current revision's
            // explicit repair plan. Unsupported stale invocations perform no
            // I/O and retain their complete physical identity for diagnosis.
            return Ok(Some(stop_local()));
        }
        context.check_active()?;
        let current = store
            .assert_current(&stored)
            .context("retain exact lifecycle checkpoint across one physical effect")?;
        if let ReconcileStep::DeleteDisposableRoot { authorization_id } = &stored.checkpoint().step
        {
            return self
                .apply_disposable_root_delete(
                    context,
                    accepted,
                    desired,
                    runtime,
                    &store,
                    &stored,
                    &current,
                    authorization_id,
                )
                .map(Some);
        }
        if let ReconcileStep::CleanupRelease { cleanup } = &stored.checkpoint().step {
            if !cleanup_is_fresh(accepted, cleanup) {
                let permit = LifecycleEffectPermit {
                    desired,
                    runtime,
                    store: &store,
                    stored: &stored,
                };
                if !cleanup_can_rebind(context, &permit, cleanup)? {
                    return Ok(Some(stop_local()));
                }
                let Some(desired_read_position) = accepted.desired_read_position() else {
                    return Ok(Some(stop_local()));
                };
                let mut rebound = stored.checkpoint().clone();
                rebound.processes = runtime.processes.clone();
                rebound.volumes = runtime.volumes.clone();
                rebound.mounts = runtime.mounts.clone();
                rebound.networks = runtime.networks.clone();
                rebound.guest_transport = runtime.guest_transport.clone();
                rebound.warm_snapshot = runtime.warm_snapshot.clone();
                rebound.updated_at_unix_ms = accepted.attestation().accepted_at_unix_ms;
                let ReconcileStep::CleanupRelease {
                    cleanup: rebound_cleanup,
                } = &mut rebound.step
                else {
                    unreachable!("rebound lifecycle step changed kind")
                };
                rebound_cleanup.inventory_session = SessionBinding {
                    node_id: accepted.session().node_id.clone(),
                    node_boot_id: accepted.session().node_boot_id.clone(),
                    agent_instance_id: accepted.session().agent_instance_id.clone(),
                    agent_session_epoch: accepted.session().agent_session_epoch,
                };
                rebound_cleanup.inventory_epoch = accepted.attestation().inventory_epoch;
                rebound_cleanup.inventory_read_position =
                    accepted.attestation().inventory_read_position;
                rebound_cleanup.desired_read_position = desired_read_position;
                persist_lifecycle_successor(
                    context,
                    &store,
                    &stored,
                    &rebound,
                    &current,
                    "rebind exact lifecycle cleanup to fresh inventory",
                )?;
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
            }
            if matches!(cleanup.target, CleanupTarget::Volume { .. }) {
                #[cfg(feature = "proposed-node-residue-reclamation")]
                if let Some(reclaim) = &self.data_directory_reclaim {
                    if let Some(outcome) =
                        reclaim.try_apply(context, desired, &store, &stored, &current)?
                    {
                        store.revalidate_current(&stored, &current).context(
                            "revalidate lifecycle checkpoint after DataDirectory reclaim",
                        )?;
                        return Ok(Some(outcome));
                    }
                }
                return self
                    .apply_volume_release(
                        context, accepted, desired, runtime, &store, &stored, &current, cleanup,
                    )
                    .map(Some);
            }
        }
        let attempt = self.physical.apply(
            context,
            LifecycleEffectPermit {
                desired,
                runtime,
                store: &store,
                stored: &stored,
            },
        )?;
        // A successful mutation can legitimately change the physical target,
        // but never the durable token which authorized it.
        store
            .revalidate_current(&stored, &current)
            .context("revalidate lifecycle checkpoint after physical effect")?;
        if let Some(successor) = drain_attempt_successor(
            desired,
            runtime,
            stored.checkpoint(),
            &attempt,
            accepted.attestation().accepted_at_unix_ms,
        )? {
            encode_runtime_checkpoint(&successor)
                .context("validate verified drain successor checkpoint")?;
            persist_lifecycle_successor(
                context,
                &store,
                &stored,
                &successor,
                &current,
                "settle checkpoint-guarded Guest and Volume drain",
            )?;
        } else if attempt == LifecyclePhysicalAttempt::ExactPostcondition {
            let successor = match &stored.checkpoint().step {
                ReconcileStep::CleanupRelease { .. } => cleanup_postcondition_successor(
                    context,
                    accepted,
                    desired,
                    runtime,
                    stored.checkpoint(),
                )?,
                ReconcileStep::StopRuntime { .. } => stop_postcondition_successor(
                    context,
                    accepted,
                    desired,
                    runtime,
                    stored.checkpoint(),
                )?,
                _ => exact_postcondition_successor(
                    context.state_directory().path(),
                    desired,
                    runtime,
                    stored.checkpoint(),
                )?,
            };
            if let Some(successor) = successor {
                encode_runtime_checkpoint(&successor)
                    .context("validate settled lifecycle successor checkpoint")?;
                persist_lifecycle_successor(
                    context,
                    &store,
                    &stored,
                    &successor,
                    &current,
                    "settle exact lifecycle postcondition",
                )?;
            }
        }
        Ok(Some(match attempt {
            LifecyclePhysicalAttempt::SubmittedOrAmbiguous
            | LifecyclePhysicalAttempt::ExactPostcondition
            | LifecyclePhysicalAttempt::VerifiedDrain(_)
            | LifecyclePhysicalAttempt::Unavailable => {
                RuntimeDesiredEffectOutcome::refresh_inventory()
            }
            LifecyclePhysicalAttempt::Conflict => stop_local(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_volume_release(
        &self,
        context: &RuntimeDesiredEffectContext,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        desired: &DesiredRuntimeSpec,
        runtime: &ObservedRuntimeStatus,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        current: &super::checkpoint::CurrentCheckpointGuard<'_>,
        cleanup: &CleanupRelease,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let (
            CleanupTarget::Volume {
                volume_id,
                attachment_id,
                attachment_epoch,
            },
            Some(replay),
        ) = (&cleanup.target, &cleanup.volume_release)
        else {
            return Ok(stop_local());
        };
        let mut intents = desired
            .volumes
            .iter()
            .filter(|intent| &intent.volume_id == volume_id);
        let Some(intent) = intents.next() else {
            return Ok(stop_local());
        };
        if intents.next().is_some()
            || &intent.attachment_id != attachment_id
            || intent.disposition != replay.disposition
        {
            return Ok(stop_local());
        }
        let mut observed_matches = runtime
            .volumes
            .iter()
            .filter(|volume| &volume.volume_id == volume_id);
        let Some(observed) = observed_matches.next() else {
            return Ok(stop_local());
        };
        if observed_matches.next().is_some() || !observed.devices.is_empty() {
            return Ok(stop_local());
        }
        let permit = LifecycleEffectPermit {
            desired,
            runtime,
            store,
            stored,
        };
        if !volume_cleanup_observation_is_compatible(&permit, cleanup) {
            return Ok(stop_local());
        }
        let expected_head = match &observed.authority {
            VolumeAuthorityEvidence::Owned {
                attachment_id: owner,
                attachment_epoch: epoch,
                head,
            } if owner == attachment_id
                && epoch == attachment_epoch
                && head.generation == replay.generation =>
            {
                head.clone()
            }
            VolumeAuthorityEvidence::Unowned {
                attachment_epoch: epoch,
                head,
            } if attachment_epoch
                .get()
                .checked_add(1)
                .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
                == Some(*epoch)
                && head.generation == replay.generation =>
            {
                head.clone()
            }
            VolumeAuthorityEvidence::Deleting { .. }
                if matches!(
                    intent.disposition,
                    VolumeDisposition::DeleteDisposableRoot { .. }
                ) =>
            {
                return Ok(RuntimeDesiredEffectOutcome::refresh_inventory());
            }
            VolumeAuthorityEvidence::Absent
                if matches!(
                    intent.disposition,
                    VolumeDisposition::DeleteDisposableRoot { .. }
                ) =>
            {
                let successor = cleanup_postcondition_successor(
                    context,
                    accepted,
                    desired,
                    runtime,
                    stored.checkpoint(),
                )?
                .context("absent disposable Root lacks a canonical lifecycle successor")?;
                persist_lifecycle_successor(
                    context,
                    store,
                    stored,
                    &successor,
                    current,
                    "settle completed disposable Root cleanup",
                )?;
                return Ok(RuntimeDesiredEffectOutcome::refresh_inventory());
            }
            _ => return Ok(stop_local()),
        };
        let request = RuntimeVolumeTransitionRequest {
            version: ContractVersion::V1,
            session: cleanup.inventory_session.clone(),
            cat_id: desired.cat_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            transition: RuntimeVolumeTransition::Release {
                cleanup: cleanup.clone(),
            },
        };
        let accepted_context = NormalAcquireAcceptedContext {
            session: accepted.session().clone(),
            inventory_attestation: accepted.attestation().clone(),
        };
        if matches!(observed.authority, VolumeAuthorityEvidence::Unowned { .. }) {
            context.check_active()?;
            let record = match self.volume_authority.load_volume(volume_id) {
                Ok(record) => record,
                Err(error) => {
                    return Ok(RuntimeDesiredEffectOutcome::refresh_inventory_after(&error))
                }
            };
            return match recover_lifecycle_release_from_authority(
                &request,
                intent,
                &expected_head,
                &record,
                self.credentials.as_deref(),
            ) {
                Ok(NormalReleaseAuthorityRecovery::Released(_)) => {
                    if let Some(successor) = cleanup_postcondition_successor(
                        context,
                        accepted,
                        desired,
                        runtime,
                        stored.checkpoint(),
                    )? {
                        persist_lifecycle_successor(
                            context,
                            store,
                            stored,
                            &successor,
                            current,
                            "settle exact lifecycle Volume release",
                        )?;
                    }
                    Ok(RuntimeDesiredEffectOutcome::refresh_inventory())
                }
                Ok(NormalReleaseAuthorityRecovery::RetryExact) => {
                    Ok(RuntimeDesiredEffectOutcome::RetryExact)
                }
                Ok(NormalReleaseAuthorityRecovery::Blocked) | Err(_) => Ok(stop_local()),
            };
        }
        match store.load_definite_release_rejection(stored) {
            Ok(Some(_)) | Err(_) => return Ok(stop_local()),
            Ok(None) => {}
        }
        context.check_active()?;
        let attempt = match self.volume_transition.release(
            &request,
            intent,
            &expected_head,
            &accepted_context,
            context.deadline(),
        ) {
            Ok(attempt) => attempt,
            Err(_) => return Ok(stop_local()),
        };
        Ok(match attempt {
            NormalReleaseAttempt::Released(_) => RuntimeDesiredEffectOutcome::refresh_inventory(),
            NormalReleaseAttempt::RetryExact => RuntimeDesiredEffectOutcome::RetryExact,
            NormalReleaseAttempt::RefreshInventory => {
                RuntimeDesiredEffectOutcome::refresh_inventory()
            }
            NormalReleaseAttempt::ReplanDesired => RuntimeDesiredEffectOutcome::ReplanDesired,
            NormalReleaseAttempt::SessionReplacementRequired => {
                RuntimeDesiredEffectOutcome::SessionReplacementRequired
            }
            NormalReleaseAttempt::IdentityRepairRequired => {
                RuntimeDesiredEffectOutcome::IdentityRepairRequired
            }
            NormalReleaseAttempt::AuthorityRejected(reason) => RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::AuthorityRejected(reason),
            ),
            NormalReleaseAttempt::DefiniteCleanupConflict(problem) => {
                if store
                    .persist_definite_release_rejection(stored, current, &request, problem)
                    .is_err()
                {
                    return Ok(stop_local());
                }
                RuntimeDesiredEffectOutcome::refresh_inventory()
            }
            NormalReleaseAttempt::StopForLocalContract => stop_local(),
            NormalReleaseAttempt::StopForDeploymentMismatch => RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::DeploymentMismatch,
            ),
            NormalReleaseAttempt::Ambiguous => {
                context.check_active()?;
                let record = match self.volume_authority.load_volume(volume_id) {
                    Ok(record) => record,
                    Err(_) => return Ok(RuntimeDesiredEffectOutcome::RetryExact),
                };
                match recover_lifecycle_release_from_authority(
                    &request,
                    intent,
                    &expected_head,
                    &record,
                    self.credentials.as_deref(),
                ) {
                    Ok(NormalReleaseAuthorityRecovery::Released(_)) => {
                        RuntimeDesiredEffectOutcome::refresh_inventory()
                    }
                    Ok(NormalReleaseAuthorityRecovery::RetryExact) => {
                        RuntimeDesiredEffectOutcome::RetryExact
                    }
                    Ok(NormalReleaseAuthorityRecovery::Blocked) | Err(_) => stop_local(),
                }
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_disposable_root_delete(
        &self,
        context: &RuntimeDesiredEffectContext,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        desired: &DesiredRuntimeSpec,
        runtime: &ObservedRuntimeStatus,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        current: &super::checkpoint::CurrentCheckpointGuard<'_>,
        authorization_id: &Id,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        if desired.target != RuntimeTarget::Deleted {
            return Ok(stop_local());
        }
        let mut disposable = desired.volumes.iter().filter(|intent| {
            intent.disk_kind == cats_api::runtime_reconciliation::DiskKind::Root
                && matches!(
                    intent.disposition,
                    VolumeDisposition::DeleteDisposableRoot { .. }
                )
        });
        let Some(intent) = disposable.next() else {
            return Ok(stop_local());
        };
        if disposable.next().is_some() {
            return Ok(stop_local());
        }
        let mut observed = runtime
            .volumes
            .iter()
            .filter(|volume| volume.volume_id == intent.volume_id);
        let Some(volume) = observed.next() else {
            return Ok(stop_local());
        };
        if observed.next().is_some() || !volume.devices.is_empty() {
            return Ok(stop_local());
        }
        let VolumeDisposition::DeleteDisposableRoot { delete_id } = &intent.disposition else {
            unreachable!("disposable Root selection changed disposition")
        };
        match &volume.authority {
            VolumeAuthorityEvidence::Absent if volume.local_lineages.is_empty() => {
                let mut successor = stored.checkpoint().clone();
                successor.processes = runtime.processes.clone();
                successor.volumes = runtime.volumes.clone();
                successor.mounts = runtime.mounts.clone();
                successor.networks = runtime.networks.clone();
                successor.guest_transport = runtime.guest_transport.clone();
                successor.warm_snapshot = runtime.warm_snapshot.clone();
                successor.updated_at_unix_ms = accepted.attestation().accepted_at_unix_ms;
                anyhow::ensure!(
                    canonical_remaining_cleanup(
                        desired,
                        runtime,
                        stored.checkpoint(),
                        accepted.observation().residue.as_slice(),
                    )?
                    .is_empty(),
                    "disposable Root completion preceded another canonical cleanup"
                );
                settle_cleanup_target(desired, runtime, &mut successor)?;
                persist_lifecycle_successor(
                    context,
                    store,
                    stored,
                    &successor,
                    current,
                    "settle exact disposable Root absence",
                )?;
                Ok(RuntimeDesiredEffectOutcome::refresh_inventory())
            }
            VolumeAuthorityEvidence::Deleting {
                delete_id: observed_delete_id,
                attachment_epoch,
                head,
            } if observed_delete_id == delete_id => {
                let Some(expected_epoch) = attachment_epoch
                    .get()
                    .checked_sub(1)
                    .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
                else {
                    return Ok(stop_local());
                };
                self.recover_disposable_root_deleting(
                    context,
                    accepted,
                    desired,
                    intent,
                    authorization_id,
                    expected_epoch,
                    head,
                    DisposableEvidenceContext::ObservedDeleting,
                )
            }
            VolumeAuthorityEvidence::Owned {
                attachment_id,
                attachment_epoch,
                head,
            } if attachment_id == &intent.attachment_id
                && disposable_lineage_is_exact(
                    desired,
                    intent,
                    volume,
                    *attachment_epoch,
                    head,
                ) =>
            {
                let request = RuntimeVolumeTransitionRequest {
                    version: ContractVersion::V1,
                    session: SessionBinding {
                        node_id: accepted.session().node_id.clone(),
                        node_boot_id: accepted.session().node_boot_id.clone(),
                        agent_instance_id: accepted.session().agent_instance_id.clone(),
                        agent_session_epoch: accepted.session().agent_session_epoch,
                    },
                    cat_id: desired.cat_id.clone(),
                    desired_revision: desired.desired_revision,
                    spec_digest: desired.spec_digest.clone(),
                    placement: desired.placement.clone(),
                    transition: RuntimeVolumeTransition::DeleteDisposableRoot {
                        authorization_id: authorization_id.clone(),
                    },
                };
                let accepted_context = NormalAcquireAcceptedContext {
                    session: accepted.session().clone(),
                    inventory_attestation: accepted.attestation().clone(),
                };
                context.check_active()?;
                let attempt = match self.volume_transition.delete_disposable_root(
                    &request,
                    intent,
                    *attachment_epoch,
                    head,
                    &accepted_context,
                    context.deadline(),
                ) {
                    Ok(attempt) => attempt,
                    Err(_) => return Ok(stop_local()),
                };
                Ok(match attempt {
                    DisposableRootDeleteAttempt::Deleting(_) => {
                        RuntimeDesiredEffectOutcome::refresh_inventory()
                    }
                    DisposableRootDeleteAttempt::RetryExact => {
                        RuntimeDesiredEffectOutcome::RetryExact
                    }
                    DisposableRootDeleteAttempt::RefreshInventory => {
                        RuntimeDesiredEffectOutcome::refresh_inventory()
                    }
                    DisposableRootDeleteAttempt::Ambiguous => {
                        return self.recover_disposable_root_deleting(
                            context,
                            accepted,
                            desired,
                            intent,
                            authorization_id,
                            *attachment_epoch,
                            head,
                            DisposableEvidenceContext::AmbiguousOwnedAttempt,
                        );
                    }
                    DisposableRootDeleteAttempt::ReplanDesired => {
                        RuntimeDesiredEffectOutcome::ReplanDesired
                    }
                    DisposableRootDeleteAttempt::SessionReplacementRequired => {
                        RuntimeDesiredEffectOutcome::SessionReplacementRequired
                    }
                    DisposableRootDeleteAttempt::IdentityRepairRequired => {
                        RuntimeDesiredEffectOutcome::IdentityRepairRequired
                    }
                    DisposableRootDeleteAttempt::AuthorizationRejected(
                        cats_api::runtime_reconciliation::RuntimeVolumeAuthorizationRejection::InvalidLeaseDuration,
                    ) => stop_local(),
                    DisposableRootDeleteAttempt::AuthorizationRejected(_) => {
                        RuntimeDesiredEffectOutcome::ReplanDesired
                    }
                    DisposableRootDeleteAttempt::StopForLocalContract => stop_local(),
                    DisposableRootDeleteAttempt::StopForDeploymentMismatch => {
                        RuntimeDesiredEffectOutcome::Stop(
                            RuntimeDesiredEffectStopReason::DeploymentMismatch,
                        )
                    }
                })
            }
            _ => Ok(stop_local()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_disposable_root_deleting(
        &self,
        context: &RuntimeDesiredEffectContext,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        desired: &DesiredRuntimeSpec,
        intent: &cats_api::runtime_reconciliation::VolumeIntent,
        authorization_id: &Id,
        expected_epoch: cats_api::runtime_reconciliation::FenceEpoch,
        expected_head: &cats_api::runtime_reconciliation::RemoteHead,
        evidence_context: DisposableEvidenceContext,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let request = RuntimeVolumeTransitionEvidenceRequest {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: accepted.session().node_id.clone(),
                node_boot_id: accepted.session().node_boot_id.clone(),
                agent_instance_id: accepted.session().agent_instance_id.clone(),
                agent_session_epoch: accepted.session().agent_session_epoch,
            },
            authorization_id: authorization_id.clone(),
        };
        context.check_active()?;
        let recovery = self
            .volume_transition
            .recover_authorization(&request, context.deadline())
            .map_err(|error| anyhow::anyhow!("read signed disposable-Root evidence: {error}"))?;
        Ok(match recovery {
            VolumeEvidenceRecovery::Validated { evidence, decision } => {
                if exact_disposable_deleting_evidence(
                    &request,
                    desired,
                    intent,
                    authorization_id,
                    expected_epoch,
                    expected_head,
                    &evidence,
                    &decision,
                ) {
                    // The authority mutation is exact. Local lineage deletion is
                    // still unavailable and remains a zero-I/O refresh.
                    RuntimeDesiredEffectOutcome::refresh_inventory()
                } else if evidence_context == DisposableEvidenceContext::AmbiguousOwnedAttempt
                    && exact_disposable_unconsumed_evidence(
                        &request,
                        desired,
                        intent,
                        authorization_id,
                        expected_epoch,
                        expected_head,
                        &evidence,
                        &decision,
                    )
                {
                    // The ambiguous mutation did not consume its immutable
                    // authorization. Keep the checkpoint so the next bounded
                    // attempt retries that exact authorization ID.
                    RuntimeDesiredEffectOutcome::RetryExact
                } else {
                    stop_local()
                }
            }
            VolumeEvidenceRecovery::SessionReplacementRequired => {
                RuntimeDesiredEffectOutcome::SessionReplacementRequired
            }
            VolumeEvidenceRecovery::IdentityRepairRequired => {
                RuntimeDesiredEffectOutcome::IdentityRepairRequired
            }
            VolumeEvidenceRecovery::StopForDeploymentMismatch => RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::DeploymentMismatch,
            ),
            VolumeEvidenceRecovery::StopForLocalContract => stop_local(),
            VolumeEvidenceRecovery::AuthorizationEvidenceUnavailable
            | VolumeEvidenceRecovery::RetrySameRequest
            | VolumeEvidenceRecovery::Ambiguous => RuntimeDesiredEffectOutcome::RetryExact,
        })
    }

    fn plan_first(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        runtime: &ObservedRuntimeStatus,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        if desired.target == RuntimeTarget::Running
            || runtime.lifecycle_admission != LifecycleAdmission::Closed
            || runtime.platform_guards != 0
            || !matches!(
                runtime.step,
                ReconcileStep::Stable {
                    state: StableState::Running
                }
            )
        {
            return Ok(None);
        }
        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(Some(stop_local()));
        };
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .context("open lifecycle planner checkpoint")?;
        if store.path() != Path::new(checkpoint_path.as_str()) {
            return Ok(Some(stop_local()));
        }
        let Some(stored) = store.load().context("load lifecycle planner checkpoint")? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if stored.content_digest() != content_digest
            || stored.checkpoint().step != runtime.step
            || !checkpoint_is_current(desired, stored.checkpoint())
        {
            return Ok(Some(stop_local()));
        }
        let Some(step) = first_lifecycle_step(desired, runtime)? else {
            return Ok(Some(stop_local()));
        };
        let mut successor = stored.checkpoint().clone();
        successor.stable_state = None;
        successor.step = step;
        successor.lifecycle_admission = LifecycleAdmission::Closed;
        anyhow::ensure!(
            successor
                .route_gates
                .iter()
                .all(|gate| gate.gate == cats_api::runtime_reconciliation::RouteGateState::Closed),
            "lifecycle planner cannot advance while a durable route gate is active"
        );
        encode_runtime_checkpoint(&successor)
            .context("validate first lifecycle successor checkpoint")?;
        let current = store
            .assert_current(&stored)
            .context("retain first lifecycle predecessor for checkpoint CAS")?;
        persist_lifecycle_successor(
            context,
            &store,
            &stored,
            &successor,
            &current,
            "persist first lifecycle step before physical effect",
        )?;
        Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()))
    }

    fn plan_cold_membership_rebind(
        &self,
        context: &RuntimeDesiredEffectContext,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        desired: &DesiredRuntimeSpec,
        runtime: &ObservedRuntimeStatus,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            desired_revision,
            spec_digest,
            placement_epoch,
            stable_state: Some(StableState::Cold),
            step,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(stop_local());
        };
        if step.as_ref() != &runtime.step
            || desired_revision >= &desired.desired_revision
            || spec_digest == &desired.spec_digest
            || *placement_epoch != desired.placement.placement_epoch
            || !runtime_cold_physical_absence_is_exact(runtime)
        {
            return Ok(stop_local());
        }

        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .context("open Cold membership rebind checkpoint")?;
        if store.path() != Path::new(checkpoint_path.as_str()) {
            return Ok(stop_local());
        }
        let Some(stored) = store
            .load()
            .context("load Cold membership rebind checkpoint")?
        else {
            return Ok(RuntimeDesiredEffectOutcome::refresh_inventory());
        };
        if stored.content_digest() != content_digest
            || stored.checkpoint().step != runtime.step
            || !cold_membership_rebind_is_supported(desired, stored.checkpoint(), &runtime.volumes)
        {
            return Ok(stop_local());
        }

        // The accepted full scan is the physical-absence authority, but the
        // Volume rows are independently mutable. Point-read the complete
        // predecessor/successor union immediately before checkpoint CAS. A
        // stale epoch, head ABA, owner, or immutable-field drift forces a new
        // full scan and never publishes Stable Cold for the successor.
        let mut records = BTreeMap::new();
        for observed in &runtime.volumes {
            context.check_active()?;
            let record = match self.volume_authority.load_volume(&observed.volume_id) {
                Ok(record) => record,
                Err(error) => {
                    return Ok(RuntimeDesiredEffectOutcome::refresh_inventory_after(&error))
                }
            };
            if !record_matches_exact_unowned_observation(&record, observed) {
                return Ok(RuntimeDesiredEffectOutcome::refresh_inventory());
            }
            records.insert(observed.volume_id.clone(), record);
        }
        if accepted.attestation().accepted_at_unix_ms < stored.checkpoint().updated_at_unix_ms {
            return Ok(stop_local());
        }

        let successor =
            if let Some(removed) = cold_membership_removed_volume(desired, stored.checkpoint()) {
                if !removed.local_lineages.is_empty() {
                    let Some(record) = records.get(&removed.volume_id) else {
                        return Ok(RuntimeDesiredEffectOutcome::refresh_inventory());
                    };
                    if !released_cache_record_matches_checkpoint(record, removed) {
                        return Ok(stop_local());
                    }
                    cold_membership_detach_cleanup_successor(
                        accepted,
                        stored.checkpoint(),
                        removed,
                        record,
                    )?
                } else {
                    cold_membership_rebind_successor(
                        desired,
                        runtime,
                        stored.checkpoint(),
                        accepted.attestation().accepted_at_unix_ms,
                    )?
                }
            } else {
                cold_membership_rebind_successor(
                    desired,
                    runtime,
                    stored.checkpoint(),
                    accepted.attestation().accepted_at_unix_ms,
                )?
            };
        let current = store
            .assert_current(&stored)
            .context("retain exact superseded Cold checkpoint for membership CAS")?;
        persist_lifecycle_successor(
            context,
            &store,
            &stored,
            &successor,
            &current,
            "atomically rebind exact Cold volume membership",
        )?;
        Ok(RuntimeDesiredEffectOutcome::refresh_inventory())
    }

    fn apply_cold_membership_detach_cleanup(
        &self,
        context: &RuntimeDesiredEffectContext,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        desired: &DesiredRuntimeSpec,
        runtime: &ObservedRuntimeStatus,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            desired_revision,
            spec_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(None);
        };
        if desired_revision >= &desired.desired_revision || spec_digest == &desired.spec_digest {
            return Ok(None);
        }
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .context("open Cold detach cache-cleanup checkpoint")?;
        if store.path() != Path::new(checkpoint_path.as_str()) {
            return Ok(Some(stop_local()));
        }
        let Some(stored) = store
            .load()
            .context("load Cold detach cache-cleanup checkpoint")?
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if stored.content_digest() != content_digest
            || stored.checkpoint().step != runtime.step
            || !cold_membership_detach_cleanup_is_supported(
                desired,
                stored.checkpoint(),
                &runtime.volumes,
            )
        {
            return Ok(Some(stop_local()));
        }

        for observed in &runtime.volumes {
            context.check_active()?;
            let record = match self.volume_authority.load_volume(&observed.volume_id) {
                Ok(record) => record,
                Err(error) => {
                    return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory_after(
                        &error,
                    )))
                }
            };
            if !record_matches_exact_unowned_observation(&record, observed) {
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
            }
        }
        if accepted.attestation().accepted_at_unix_ms < stored.checkpoint().updated_at_unix_ms {
            return Ok(Some(stop_local()));
        }
        let current = store
            .assert_current(&stored)
            .context("retain exact Cold detach cache-cleanup checkpoint")?;

        #[cfg(feature = "proposed-node-residue-reclamation")]
        if let Some(reclaim) = &self.data_directory_reclaim {
            if let Some(outcome) = reclaim.try_apply_cold_membership_detach(
                context,
                desired,
                runtime,
                &store,
                &stored,
                &current,
                self.volume_authority.as_ref(),
            )? {
                return Ok(Some(outcome));
            }
        }

        if !accepted.observation().residue.is_empty()
            || runtime.volumes.iter().any(|volume| {
                cold_membership_cleanup_target(stored.checkpoint())
                    .is_some_and(|target| target == &volume.volume_id)
                    && !volume.local_lineages.is_empty()
            })
        {
            return Ok(Some(stop_local()));
        }
        let successor = cold_membership_detach_completion_successor(
            desired,
            runtime,
            stored.checkpoint(),
            accepted.attestation().accepted_at_unix_ms,
        )?;
        persist_lifecycle_successor(
            context,
            &store,
            &stored,
            &successor,
            &current,
            "atomically bind Cold membership after exact cache cleanup",
        )?;
        Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()))
    }
}

/// A superseded Stable Cold checkpoint can authorize only one membership
/// edit. It is never itself the stable observation for the successor.
pub(super) fn cold_membership_rebind_is_supported(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    observed_union: &[ObservedVolume],
) -> bool {
    if encode_desired_runtime_spec(desired).is_err()
        || desired.target != RuntimeTarget::Cold
        || checkpoint.version != ContractVersion::V1
        || checkpoint.cat_id != desired.cat_id
        || checkpoint.node_id != desired.placement.node_id
        || checkpoint.placement_epoch != desired.placement.placement_epoch
        || checkpoint.desired_revision >= desired.desired_revision
        || checkpoint.spec_digest == desired.spec_digest
        || !stable_cold_checkpoint_has_physical_absence(checkpoint)
    {
        return false;
    }

    let Some(checkpoint_by_id) = unique_observed_volumes(&checkpoint.volumes) else {
        return false;
    };
    let Some(union_by_id) = unique_observed_volumes(observed_union) else {
        return false;
    };
    let desired_by_id: BTreeMap<&Id, &VolumeIntent> = desired
        .volumes
        .iter()
        .map(|intent| (&intent.volume_id, intent))
        .collect();
    if desired_by_id.len() != desired.volumes.len()
        || union_by_id.len() != checkpoint_by_id.len().max(desired_by_id.len())
        || !union_by_id.keys().all(|volume_id| {
            checkpoint_by_id.contains_key(volume_id) || desired_by_id.contains_key(volume_id)
        })
    {
        return false;
    }

    for (volume_id, intent) in &desired_by_id {
        let Some(observed) = union_by_id.get(volume_id) else {
            return false;
        };
        if !cold_observed_identity_matches_intent(observed, intent)
            || !cold_observed_volume_satisfies_intent(observed, intent)
        {
            return false;
        }
    }
    for (volume_id, checkpointed) in &checkpoint_by_id {
        let Some(observed) = union_by_id.get(volume_id) else {
            return false;
        };
        if observed != checkpointed || !observed_is_exact_unowned_absence(observed) {
            return false;
        }
    }

    let added: Vec<&VolumeIntent> = desired_by_id
        .iter()
        .filter_map(|(volume_id, intent)| {
            (!checkpoint_by_id.contains_key(volume_id)).then_some(*intent)
        })
        .collect();
    let removed: Vec<&ObservedVolume> = checkpoint_by_id
        .iter()
        .filter_map(|(volume_id, observed)| {
            (!desired_by_id.contains_key(volume_id)).then_some(*observed)
        })
        .collect();
    match (added.as_slice(), removed.as_slice()) {
        ([intent], []) => {
            let Some(observed) = union_by_id.get(&intent.volume_id) else {
                return false;
            };
            intent.disk_kind == DiskKind::Persistent
                && newly_attached_volume_matches_unowned_authority(intent, observed)
        }
        ([], [observed]) => observed.disk_kind == ObservedDiskKind::Persistent,
        _ => false,
    }
}

fn cold_membership_removed_volume<'a>(
    desired: &DesiredRuntimeSpec,
    checkpoint: &'a RuntimeCheckpoint,
) -> Option<&'a ObservedVolume> {
    let desired_ids: BTreeSet<&Id> = desired
        .volumes
        .iter()
        .map(|intent| &intent.volume_id)
        .collect();
    let mut removed = checkpoint
        .volumes
        .iter()
        .filter(|volume| !desired_ids.contains(&volume.volume_id));
    let volume = removed.next()?;
    (removed.next().is_none() && volume.disk_kind == ObservedDiskKind::Persistent).then_some(volume)
}

fn cold_membership_detach_cleanup_successor(
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    checkpoint: &RuntimeCheckpoint,
    removed: &ObservedVolume,
    record: &VolumeRecord,
) -> anyhow::Result<RuntimeCheckpoint> {
    let [lineage] = removed.local_lineages.as_slice() else {
        anyhow::bail!("Cold detach cache cleanup requires one exact released lineage")
    };
    let VolumeAuthorityEvidence::Unowned {
        attachment_epoch,
        head,
    } = &removed.authority
    else {
        anyhow::bail!("Cold detach cache cleanup requires Unowned authority")
    };
    anyhow::ensure!(
        released_cache_record_matches_checkpoint(record, removed)
            && lineage.state == cats_api::runtime_reconciliation::LocalLineageState::Released
            && lineage.fenced
            && lineage.local_durable_generation == head.generation
            && lineage.remote_durable_generation == head.generation
            && lineage.pending_pack_count.get() == 0,
        "Cold detach cache cleanup lacks exact released cache authority"
    );
    let Some(desired_read_position) = accepted.desired_read_position() else {
        anyhow::bail!("Cold detach cache cleanup lacks current Desired read position")
    };
    let release_transition_id = match &record.last_transition {
        Some(LastVolumeTransition::Release { request, .. }) => request.transition_id.clone(),
        _ => anyhow::bail!("Cold detach cache cleanup lacks exact Release transition"),
    };
    let mut successor = checkpoint.clone();
    successor.stable_state = None;
    successor.step = ReconcileStep::CleanupRelease {
        cleanup: CleanupRelease {
            target: CleanupTarget::Volume {
                volume_id: removed.volume_id.clone(),
                attachment_id: lineage.attachment_id.clone(),
                attachment_epoch: lineage.attachment_epoch,
            },
            inventory_session: SessionBinding {
                node_id: accepted.session().node_id.clone(),
                node_boot_id: accepted.session().node_boot_id.clone(),
                agent_instance_id: accepted.session().agent_instance_id.clone(),
                agent_session_epoch: accepted.session().agent_session_epoch,
            },
            inventory_epoch: accepted.attestation().inventory_epoch,
            inventory_read_position: accepted.attestation().inventory_read_position,
            desired_read_position,
            volume_release: Some(VolumeReleaseReplay {
                release_transition_id,
                disposition: VolumeDisposition::DetachRetained,
                generation: head.generation,
            }),
        },
    };
    successor.updated_at_unix_ms = accepted.attestation().accepted_at_unix_ms;
    // The release-result epoch is the exact successor of the cache lineage's
    // serving epoch. Overflow and an unrelated current epoch fail closed.
    anyhow::ensure!(
        lineage
            .attachment_epoch
            .get()
            .checked_add(1)
            .and_then(FenceEpoch::new)
            == Some(*attachment_epoch),
        "Cold detach cache cleanup epoch is not the exact released successor"
    );
    encode_runtime_checkpoint(&successor)
        .context("validate typed Cold detach cache-cleanup checkpoint")?;
    Ok(successor)
}

pub(super) fn cold_membership_cleanup_target(checkpoint: &RuntimeCheckpoint) -> Option<&Id> {
    let ReconcileStep::CleanupRelease { cleanup } = &checkpoint.step else {
        return None;
    };
    let CleanupTarget::Volume { volume_id, .. } = &cleanup.target else {
        return None;
    };
    matches!(
        cleanup.volume_release,
        Some(VolumeReleaseReplay {
            disposition: VolumeDisposition::DetachRetained,
            ..
        })
    )
    .then_some(volume_id)
}

pub(super) fn cold_membership_detach_cleanup_checkpoint_is_supported(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
) -> bool {
    if encode_desired_runtime_spec(desired).is_err()
        || desired.target != RuntimeTarget::Cold
        || checkpoint.version != ContractVersion::V1
        || checkpoint.cat_id != desired.cat_id
        || checkpoint.node_id != desired.placement.node_id
        || checkpoint.placement_epoch != desired.placement.placement_epoch
        || checkpoint.desired_revision >= desired.desired_revision
        || checkpoint.spec_digest == desired.spec_digest
        || checkpoint.stable_state.is_some()
        || checkpoint.runtime_incarnation.is_some()
        || !matches!(checkpoint.runtime_launch, RuntimeLaunch::Absent)
        || !checkpoint.processes.is_empty()
        || checkpoint.volumes.is_empty()
        || !checkpoint.mounts.is_empty()
        || !checkpoint.networks.is_empty()
        || !matches!(
            checkpoint.guest_transport,
            GuestTransportEvidence::Unavailable
        )
        || !matches!(checkpoint.warm_snapshot, WarmSnapshotEvidence::Absent)
        || checkpoint.lifecycle_admission != LifecycleAdmission::Closed
        || !checkpoint.route_gates.is_empty()
        || !matches!(
            checkpoint.require_idle,
            RequireIdleCheckpoint::NotApplicable
        )
    {
        return false;
    }
    let ReconcileStep::CleanupRelease { cleanup } = &checkpoint.step else {
        return false;
    };
    let (
        CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(VolumeReleaseReplay {
            disposition: VolumeDisposition::DetachRetained,
            generation,
            ..
        }),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        return false;
    };
    if cleanup.inventory_session.node_id != desired.placement.node_id
        || cleanup.desired_read_position < cleanup.inventory_read_position
    {
        return false;
    }
    let Some(removed) = checkpoint
        .volumes
        .iter()
        .find(|volume| &volume.volume_id == volume_id)
    else {
        return false;
    };
    let [lineage] = removed.local_lineages.as_slice() else {
        return false;
    };
    let VolumeAuthorityEvidence::Unowned {
        attachment_epoch: released_epoch,
        head,
    } = &removed.authority
    else {
        return false;
    };
    if removed.disk_kind != ObservedDiskKind::Persistent
        || !removed.devices.is_empty()
        || lineage.attachment_id != *attachment_id
        || lineage.attachment_epoch != *attachment_epoch
        || lineage.local_durable_generation != *generation
        || lineage.remote_durable_generation != *generation
        || lineage.pending_pack_count.get() != 0
        || !lineage.fenced
        || lineage.state != cats_api::runtime_reconciliation::LocalLineageState::Released
        || head.generation != *generation
        || attachment_epoch
            .get()
            .checked_add(1)
            .and_then(FenceEpoch::new)
            != Some(*released_epoch)
    {
        return false;
    }
    let desired_by_id: BTreeMap<&Id, &VolumeIntent> = desired
        .volumes
        .iter()
        .map(|intent| (&intent.volume_id, intent))
        .collect();
    let Some(checkpoint_by_id) = unique_observed_volumes(&checkpoint.volumes) else {
        return false;
    };
    if desired_by_id.len() != desired.volumes.len()
        || checkpoint_by_id.len() != desired.volumes.len().saturating_add(1)
        || desired_by_id.contains_key(volume_id)
        || checkpoint_by_id.get(volume_id).copied() != Some(removed)
        || desired_by_id
            .keys()
            .any(|desired_id| !checkpoint_by_id.contains_key(desired_id))
    {
        return false;
    }
    checkpoint_by_id.iter().all(|(observed_id, observed)| {
        *observed_id == volume_id
            || desired_by_id.get(observed_id).is_some_and(|intent| {
                cold_observed_identity_matches_intent(observed, intent)
                    && cold_observed_volume_satisfies_intent(observed, intent)
            })
    })
}

pub(super) fn cold_membership_detach_cleanup_is_supported(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    observed_union: &[ObservedVolume],
) -> bool {
    if !cold_membership_detach_cleanup_checkpoint_is_supported(desired, checkpoint) {
        return false;
    }
    let Some(checkpoint_by_id) = unique_observed_volumes(&checkpoint.volumes) else {
        return false;
    };
    let Some(observed_by_id) = unique_observed_volumes(observed_union) else {
        return false;
    };
    if checkpoint_by_id.len() != observed_by_id.len()
        || checkpoint_by_id
            .keys()
            .any(|id| !observed_by_id.contains_key(id))
    {
        return false;
    }
    let Some(target) = cold_membership_cleanup_target(checkpoint) else {
        return false;
    };
    checkpoint_by_id.iter().all(|(volume_id, checkpointed)| {
        let observed = observed_by_id[volume_id];
        if *volume_id == target {
            let mut without_cache = (*checkpointed).clone();
            without_cache.local_lineages.clear();
            observed == *checkpointed || observed == &without_cache
        } else {
            observed == *checkpointed
        }
    })
}

pub(super) fn released_cache_record_matches_checkpoint(
    record: &VolumeRecord,
    observed: &ObservedVolume,
) -> bool {
    let (
        VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head,
        },
        [lineage],
        Some(LastVolumeTransition::Release { request, result }),
    ) = (
        &observed.authority,
        observed.local_lineages.as_slice(),
        &record.last_transition,
    )
    else {
        return false;
    };
    record_matches_exact_unowned_observation(record, observed)
        && request.volume_id == observed.volume_id
        && request.attachment_id == lineage.attachment_id
        && request.expected_epoch == lineage.attachment_epoch
        && result.volume_id == observed.volume_id
        && result.transition_id == request.transition_id
        && result.released_attachment_id == lineage.attachment_id
        && result.resulting_epoch == *attachment_epoch
        && result.resulting_head == *head
        && lineage.local_durable_generation == head.generation
        && lineage.remote_durable_generation == head.generation
        && lineage.pending_pack_count.get() == 0
        && lineage.fenced
        && lineage.state == cats_api::runtime_reconciliation::LocalLineageState::Released
}

pub(super) fn released_cache_record_matches_cleanup_checkpoint(
    record: &VolumeRecord,
    checkpoint: &RuntimeCheckpoint,
) -> bool {
    let ReconcileStep::CleanupRelease { cleanup } = &checkpoint.step else {
        return false;
    };
    let CleanupTarget::Volume {
        volume_id,
        attachment_id,
        attachment_epoch,
    } = &cleanup.target
    else {
        return false;
    };
    let Some(VolumeReleaseReplay {
        release_transition_id,
        disposition: VolumeDisposition::DetachRetained,
        generation,
    }) = &cleanup.volume_release
    else {
        return false;
    };
    let Some(LastVolumeTransition::Release { request, result }) = &record.last_transition else {
        return false;
    };
    let Some(checkpoint_by_id) = unique_observed_volumes(&checkpoint.volumes) else {
        return false;
    };
    let Some(observed) = checkpoint_by_id.get(volume_id).copied() else {
        return false;
    };
    let Some(target) = cold_membership_cleanup_target(checkpoint) else {
        return false;
    };
    if target != volume_id {
        return false;
    }
    released_cache_record_matches_checkpoint(record, observed)
        && request.transition_id == *release_transition_id
        && result.transition_id == *release_transition_id
        && request.attachment_id == *attachment_id
        && request.expected_epoch == *attachment_epoch
        && result.resulting_head.generation == *generation
        && *generation == record.head.generation
}

/// A current Stable Cold checkpoint is terminal only when the fresh authority
/// set is byte-exact with its rebound volume vector. Any later owner/epoch/head
/// change suppresses `stable_state` and therefore cannot settle an Operation.
pub(super) fn current_cold_checkpoint_postcondition_is_exact(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    observed: &[ObservedVolume],
) -> bool {
    if desired.target != RuntimeTarget::Cold
        || checkpoint.cat_id != desired.cat_id
        || checkpoint.node_id != desired.placement.node_id
        || checkpoint.placement_epoch != desired.placement.placement_epoch
        || checkpoint.desired_revision != desired.desired_revision
        || checkpoint.spec_digest != desired.spec_digest
        || !stable_cold_checkpoint_has_physical_absence(checkpoint)
    {
        return false;
    }
    let Some(checkpoint_by_id) = unique_observed_volumes(&checkpoint.volumes) else {
        return false;
    };
    let Some(observed_by_id) = unique_observed_volumes(observed) else {
        return false;
    };
    if checkpoint_by_id.len() != desired.volumes.len()
        || observed_by_id.len() != desired.volumes.len()
        || checkpoint_by_id != observed_by_id
    {
        return false;
    }
    desired.volumes.iter().all(|intent| {
        observed_by_id.get(&intent.volume_id).is_some_and(|volume| {
            cold_observed_identity_matches_intent(volume, intent)
                && cold_observed_volume_satisfies_intent(volume, intent)
                && (intent.disk_kind != DiskKind::Root
                    || observed_authority_head_generation(volume).is_some_and(|value| value > 0))
        })
    })
}

fn cold_membership_rebind_successor(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    observed_at: cats_api::runtime_reconciliation::UnixMillis,
) -> anyhow::Result<RuntimeCheckpoint> {
    anyhow::ensure!(
        runtime_cold_physical_absence_is_exact(runtime)
            && cold_membership_rebind_is_supported(desired, checkpoint, &runtime.volumes),
        "Cold membership successor lacks exact superseded physical absence"
    );
    let desired_ids: BTreeSet<&Id> = desired
        .volumes
        .iter()
        .map(|intent| &intent.volume_id)
        .collect();
    let mut volumes: Vec<ObservedVolume> = runtime
        .volumes
        .iter()
        .filter(|volume| desired_ids.contains(&volume.volume_id))
        .cloned()
        .collect();
    volumes.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    anyhow::ensure!(
        volumes.len() == desired.volumes.len(),
        "Cold membership successor omitted a Desired Volume"
    );

    let mut successor = checkpoint.clone();
    successor.desired_revision = desired.desired_revision;
    successor.spec_digest = desired.spec_digest.clone();
    successor.volumes = volumes;
    successor.updated_at_unix_ms = observed_at;
    encode_runtime_checkpoint(&successor)
        .context("validate exact Cold membership successor checkpoint")?;
    anyhow::ensure!(
        current_cold_checkpoint_postcondition_is_exact(desired, &successor, &successor.volumes),
        "Cold membership successor is not an exact current Stable Cold checkpoint"
    );
    Ok(successor)
}

fn cold_membership_detach_completion_successor(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    observed_at: cats_api::runtime_reconciliation::UnixMillis,
) -> anyhow::Result<RuntimeCheckpoint> {
    anyhow::ensure!(
        runtime_cold_physical_absence_is_exact(runtime)
            && cold_membership_detach_cleanup_is_supported(desired, checkpoint, &runtime.volumes,),
        "Cold detach cleanup completion lacks exact physical absence"
    );
    let target = cold_membership_cleanup_target(checkpoint)
        .context("Cold detach cleanup completion lacks its target")?;
    let target_observed = runtime
        .volumes
        .iter()
        .find(|volume| &volume.volume_id == target)
        .context("Cold detach cleanup completion lost its target authority")?;
    anyhow::ensure!(
        target_observed.local_lineages.is_empty() && target_observed.devices.is_empty(),
        "Cold detach cleanup completion still retains local cache or a device"
    );
    let desired_ids: BTreeSet<&Id> = desired
        .volumes
        .iter()
        .map(|intent| &intent.volume_id)
        .collect();
    let mut volumes: Vec<ObservedVolume> = runtime
        .volumes
        .iter()
        .filter(|volume| desired_ids.contains(&volume.volume_id))
        .cloned()
        .collect();
    volumes.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    anyhow::ensure!(
        volumes.len() == desired.volumes.len(),
        "Cold detach cleanup completion omitted a Desired Volume"
    );
    let mut successor = checkpoint.clone();
    successor.desired_revision = desired.desired_revision;
    successor.spec_digest = desired.spec_digest.clone();
    successor.volumes = volumes;
    successor.stable_state = Some(StableState::Cold);
    successor.step = ReconcileStep::Stable {
        state: StableState::Cold,
    };
    successor.updated_at_unix_ms = observed_at;
    encode_runtime_checkpoint(&successor)
        .context("validate exact post-cache Cold membership successor")?;
    anyhow::ensure!(
        current_cold_checkpoint_postcondition_is_exact(desired, &successor, &successor.volumes),
        "post-cache Cold membership successor is not terminal-exact"
    );
    Ok(successor)
}

fn stable_cold_checkpoint_has_physical_absence(checkpoint: &RuntimeCheckpoint) -> bool {
    checkpoint.runtime_incarnation.is_none()
        && matches!(checkpoint.runtime_launch, RuntimeLaunch::Absent)
        && checkpoint.stable_state == Some(StableState::Cold)
        && matches!(
            checkpoint.step,
            ReconcileStep::Stable {
                state: StableState::Cold
            }
        )
        && checkpoint.processes.is_empty()
        && !checkpoint.volumes.is_empty()
        && checkpoint.volumes.len() <= 64
        && checkpoint
            .volumes
            .iter()
            .all(observed_is_exact_unowned_absence)
        && checkpoint.mounts.is_empty()
        && checkpoint.networks.is_empty()
        && matches!(
            checkpoint.guest_transport,
            GuestTransportEvidence::Unavailable
        )
        && matches!(checkpoint.warm_snapshot, WarmSnapshotEvidence::Absent)
        && checkpoint.lifecycle_admission == LifecycleAdmission::Closed
        && checkpoint.route_gates.is_empty()
        && matches!(
            checkpoint.require_idle,
            RequireIdleCheckpoint::NotApplicable
        )
}

fn runtime_cold_physical_absence_is_exact(runtime: &ObservedRuntimeStatus) -> bool {
    runtime.runtime_incarnation.is_none()
        && runtime.processes.is_empty()
        && runtime
            .volumes
            .iter()
            .all(observed_is_exact_unowned_absence)
        && runtime.mounts.is_empty()
        && runtime.networks.is_empty()
        && matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable)
        && matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
        && runtime.lifecycle_admission == LifecycleAdmission::Closed
        && runtime.routes.is_empty()
        && runtime.platform_guards == 0
}

fn unique_observed_volumes(volumes: &[ObservedVolume]) -> Option<BTreeMap<&Id, &ObservedVolume>> {
    let mut by_id = BTreeMap::new();
    for volume in volumes {
        if by_id.insert(&volume.volume_id, volume).is_some() {
            return None;
        }
    }
    Some(by_id)
}

fn observed_is_exact_unowned_absence(volume: &ObservedVolume) -> bool {
    let VolumeAuthorityEvidence::Unowned { head, .. } = &volume.authority else {
        return false;
    };
    volume.devices.is_empty()
        && match volume.local_lineages.as_slice() {
            [] => true,
            [lineage] => {
                lineage.local_durable_generation == head.generation
                    && lineage.remote_durable_generation == head.generation
                    && lineage.pending_pack_count.get() == 0
                    && lineage.fenced
                    && lineage.state
                        == cats_api::runtime_reconciliation::LocalLineageState::Released
            }
            _ => false,
        }
}

fn cold_observed_volume_satisfies_intent(volume: &ObservedVolume, intent: &VolumeIntent) -> bool {
    if !observed_is_exact_unowned_absence(volume) {
        return false;
    }
    match volume.local_lineages.as_slice() {
        [_] => true,
        [] => {
            let (
                DiskKind::Persistent,
                VolumeAcquire::Normal {
                    expected_unowned_epoch,
                    ..
                },
                VolumeAuthorityEvidence::Unowned {
                    attachment_epoch, ..
                },
            ) = (intent.disk_kind, &intent.acquire, &volume.authority)
            else {
                return false;
            };
            expected_unowned_epoch == attachment_epoch
        }
        _ => false,
    }
}

fn cold_observed_identity_matches_intent(volume: &ObservedVolume, intent: &VolumeIntent) -> bool {
    volume.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
        && volume.disk_id.as_ref() == Some(&intent.disk_id)
        && volume.volume_id == intent.volume_id
        && volume.disk_kind
            == match intent.disk_kind {
                DiskKind::Root => ObservedDiskKind::Root,
                DiskKind::Persistent => ObservedDiskKind::Persistent,
            }
        && volume.size_bytes == Some(intent.size_bytes)
        && volume.durability == Some(intent.durability)
}

fn newly_attached_volume_matches_unowned_authority(
    intent: &VolumeIntent,
    observed: &ObservedVolume,
) -> bool {
    let (
        VolumeAcquire::Normal {
            expected_unowned_epoch,
            ..
        },
        VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head,
        },
        Some(mount),
    ) = (&intent.acquire, &observed.authority, &intent.mount)
    else {
        return false;
    };
    expected_unowned_epoch == attachment_epoch
        && match &mount.initialization {
            FilesystemInitialization::Initialize {
                expected_blank_head,
                ..
            } => head == expected_blank_head,
            FilesystemInitialization::Existing => head.generation.get() > 0,
        }
}

fn observed_authority_head_generation(volume: &ObservedVolume) -> Option<u64> {
    match &volume.authority {
        VolumeAuthorityEvidence::Unowned { head, .. } => Some(head.generation.get()),
        VolumeAuthorityEvidence::Owned { .. }
        | VolumeAuthorityEvidence::Deleting { .. }
        | VolumeAuthorityEvidence::Absent
        | VolumeAuthorityEvidence::Unavailable => None,
    }
}

fn record_matches_exact_unowned_observation(
    record: &VolumeRecord,
    observed: &ObservedVolume,
) -> bool {
    let VolumeAuthorityEvidence::Unowned {
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return false;
    };
    validate_volume_record(record).is_ok()
        && record.volume_id == observed.volume_id
        && Some(record.size_bytes) == observed.size_bytes
        && Some(record.durability) == observed.durability
        && matches!(record.admin_state, VolumeAdminState::Active)
        && record.lease_owner.is_none()
        && record.lease_epoch == *attachment_epoch
        && record.lease_expires_at.is_none()
        && record.head == *head
}

fn cleanup_can_rebind(
    context: &RuntimeDesiredEffectContext,
    permit: &LifecycleEffectPermit<'_>,
    cleanup: &CleanupRelease,
) -> anyhow::Result<bool> {
    match &cleanup.target {
        CleanupTarget::Volume { .. } => {
            Ok(volume_cleanup_observation_is_compatible(permit, cleanup))
        }
        CleanupTarget::Network {
            network_id,
            ownership_token,
        } => {
            let Some(launch) = permit.checkpoint().runtime_launch.identity() else {
                return Ok(false);
            };
            let expected = launch.network.as_ref();
            if &expected.network_config.network_id != network_id
                || &expected.ownership_token != ownership_token
            {
                return Ok(false);
            }
            let mut matches = permit.runtime().networks.iter().filter(|network| {
                &network.network_id == network_id
                    && valid_token(&network.ownership_token) == Some(ownership_token)
            });
            Ok(matches.next().is_some_and(|_| matches.next().is_none())
                || permit.runtime().networks.is_empty())
        }
        target => Ok(classify_unadapted_cleanup(context, permit, target)?
            != LifecyclePhysicalAttempt::Conflict),
    }
}

fn volume_cleanup_observation_is_compatible(
    permit: &LifecycleEffectPermit<'_>,
    cleanup: &CleanupRelease,
) -> bool {
    let (
        CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
    ) = (&cleanup.target, &cleanup.volume_release)
    else {
        return false;
    };
    let mut intents = permit
        .desired()
        .volumes
        .iter()
        .filter(|intent| &intent.volume_id == volume_id);
    let Some(intent) = intents.next() else {
        return false;
    };
    if intents.next().is_some()
        || &intent.attachment_id != attachment_id
        || intent.disposition != replay.disposition
    {
        return false;
    }
    let mut volumes = permit
        .runtime()
        .volumes
        .iter()
        .filter(|volume| &volume.volume_id == volume_id);
    let Some(volume) = volumes.next() else {
        return matches!(
            intent.disposition,
            VolumeDisposition::DeleteDisposableRoot { .. }
        );
    };
    if volumes.next().is_some() || !volume.devices.is_empty() {
        return false;
    }
    match &volume.authority {
        VolumeAuthorityEvidence::Owned {
            attachment_id: owner,
            attachment_epoch: epoch,
            head,
        } => {
            owner == attachment_id
                && epoch == attachment_epoch
                && head.generation == replay.generation
                && drained_lineage_is_exact(permit.desired(), intent, volume, *epoch, replay)
        }
        VolumeAuthorityEvidence::Unowned {
            attachment_epoch: epoch,
            head,
        } => {
            attachment_epoch
                .get()
                .checked_add(1)
                .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
                == Some(*epoch)
                && head.generation == replay.generation
        }
        VolumeAuthorityEvidence::Deleting { .. } | VolumeAuthorityEvidence::Absent => {
            matches!(
                intent.disposition,
                VolumeDisposition::DeleteDisposableRoot { .. }
            )
        }
        VolumeAuthorityEvidence::Unavailable => false,
    }
}

fn drained_lineage_is_exact(
    desired: &DesiredRuntimeSpec,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    volume: &cats_api::runtime_reconciliation::ObservedVolume,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    replay: &VolumeReleaseReplay,
) -> bool {
    let mut exact = volume.local_lineages.iter().filter(|lineage| {
        lineage.attachment_id == intent.attachment_id
            && lineage.attachment_epoch == attachment_epoch
            && lineage.node_id == desired.placement.node_id
            && lineage.placement_epoch == desired.placement.placement_epoch
            && lineage.local_durable_generation == replay.generation
            && lineage.remote_durable_generation == replay.generation
            && lineage.pending_pack_count.get() == 0
            && !lineage.fenced
            && match (&lineage.acquire_origin, &intent.acquire) {
                (
                    cats_api::runtime_reconciliation::AcquireOrigin::Normal { transition_id },
                    VolumeAcquire::Normal {
                        transition_id: intended,
                        ..
                    },
                ) => transition_id == intended,
                (
                    cats_api::runtime_reconciliation::AcquireOrigin::Takeover { authorization_id },
                    VolumeAcquire::Takeover {
                        authorization_id: intended,
                    },
                ) => authorization_id == intended,
                _ => false,
            }
    });
    exact.next().is_some() && exact.next().is_none()
}

fn disposable_lineage_is_exact(
    desired: &DesiredRuntimeSpec,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    volume: &cats_api::runtime_reconciliation::ObservedVolume,
    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    head: &cats_api::runtime_reconciliation::RemoteHead,
) -> bool {
    let mut exact = volume.local_lineages.iter().filter(|lineage| {
        lineage.attachment_id == intent.attachment_id
            && lineage.attachment_epoch == attachment_epoch
            && lineage.node_id == desired.placement.node_id
            && lineage.placement_epoch == desired.placement.placement_epoch
            && lineage.local_durable_generation >= lineage.remote_durable_generation
            && lineage.remote_durable_generation == head.generation
            && !lineage.fenced
            && match (&lineage.acquire_origin, &intent.acquire) {
                (
                    cats_api::runtime_reconciliation::AcquireOrigin::Normal { transition_id },
                    VolumeAcquire::Normal {
                        transition_id: intended,
                        ..
                    },
                ) => transition_id == intended,
                (
                    cats_api::runtime_reconciliation::AcquireOrigin::Takeover { authorization_id },
                    VolumeAcquire::Takeover {
                        authorization_id: intended,
                    },
                ) => authorization_id == intended,
                _ => false,
            }
    });
    exact.next().is_some() && exact.next().is_none()
}

fn exact_disposable_authorization_binding(
    desired: &DesiredRuntimeSpec,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    authorization_id: &Id,
    expected_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    expected_head: &cats_api::runtime_reconciliation::RemoteHead,
    authorization: &cats_api::runtime_reconciliation::DisposableRootDeleteAuthorization,
) -> bool {
    let VolumeDisposition::DeleteDisposableRoot { delete_id } = &intent.disposition else {
        return false;
    };
    desired.target == RuntimeTarget::Deleted
        && intent.disk_kind == cats_api::runtime_reconciliation::DiskKind::Root
        && authorization.authorization_id == *authorization_id
        && authorization.authorized_node_id == desired.placement.node_id
        && authorization.delete_id == *delete_id
        && authorization.disk_id == intent.disk_id
        && authorization.volume_id == intent.volume_id
        && authorization.cat_id == desired.cat_id
        && authorization.desired_revision == desired.desired_revision
        && authorization.placement_epoch == desired.placement.placement_epoch
        && authorization.expected_attachment_id == intent.attachment_id
        && authorization.expected_epoch == expected_epoch
        && authorization.expected_head == *expected_head
}

#[allow(clippy::too_many_arguments)]
fn exact_disposable_deleting_evidence(
    request: &RuntimeVolumeTransitionEvidenceRequest,
    desired: &DesiredRuntimeSpec,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    authorization_id: &Id,
    expected_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    expected_head: &cats_api::runtime_reconciliation::RemoteHead,
    evidence: &cats_api::runtime_reconciliation::RuntimeVolumeTransitionEvidenceSuccess,
    decision: &VolumeEvidenceRecoveryDecision,
) -> bool {
    let VolumeDisposition::DeleteDisposableRoot { delete_id } = &intent.disposition else {
        return false;
    };
    let (
        VolumeAuthorization::DisposableRootDelete(authorization),
        AuthorizationState::Consumed(consumed),
        VolumeEvidenceRecoveryDecision::AdoptDisposableDeleting(decision_receipt),
        Some(current),
    ) = (
        &evidence.authorization.authorization,
        &evidence.authorization.state,
        decision,
        evidence.current_volume.as_ref(),
    )
    else {
        return false;
    };
    let AuthorizationConsumedReceipt::BeginDisposableDelete(receipt) = consumed.as_ref() else {
        return false;
    };
    let Some(resulting_epoch) = expected_epoch
        .get()
        .checked_add(1)
        .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
    else {
        return false;
    };
    evidence.version == request.version
        && evidence.session == request.session
        && evidence.authorization_id == request.authorization_id
        && evidence.authorization_id == *authorization_id
        && evidence.delete_completion.is_none()
        && evidence.direct_successor_authorization.is_none()
        && exact_disposable_authorization_binding(
            desired,
            intent,
            authorization_id,
            expected_epoch,
            expected_head,
            authorization,
        )
        && decision_receipt == receipt
        && receipt.authorization_id == *authorization_id
        && receipt.volume_id == intent.volume_id
        && receipt.disk_id == intent.disk_id
        && receipt.cat_id == desired.cat_id
        && receipt.delete_id == *delete_id
        && receipt.prior_attachment_id == intent.attachment_id
        && receipt.resulting_epoch == resulting_epoch
        && receipt.resulting_head == *expected_head
        && current.volume_id == intent.volume_id
        && current.size_bytes == intent.size_bytes
        && current.durability == intent.durability
        && matches!(
            &current.admin_state,
            VolumeAdminState::Deleting { delete_id: current_delete } if current_delete == delete_id
        )
        && current.lease_owner.is_none()
        && current.lease_expires_at.is_none()
        && current.lease_epoch == resulting_epoch
        && current.head == *expected_head
        && matches!(
            &current.last_transition,
            Some(LastVolumeTransition::BeginDisposableDelete {
                authorization_id: current_authorization,
            }) if current_authorization == authorization_id
        )
}

#[allow(clippy::too_many_arguments)]
fn exact_disposable_unconsumed_evidence(
    request: &RuntimeVolumeTransitionEvidenceRequest,
    desired: &DesiredRuntimeSpec,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    authorization_id: &Id,
    expected_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    expected_head: &cats_api::runtime_reconciliation::RemoteHead,
    evidence: &cats_api::runtime_reconciliation::RuntimeVolumeTransitionEvidenceSuccess,
    decision: &VolumeEvidenceRecoveryDecision,
) -> bool {
    let (
        VolumeAuthorization::DisposableRootDelete(authorization),
        AuthorizationState::Unconsumed,
        VolumeEvidenceRecoveryDecision::RetryOriginalAuthorization {
            authorization_id: decision_authorization_id,
        },
        Some(current),
    ) = (
        &evidence.authorization.authorization,
        &evidence.authorization.state,
        decision,
        evidence.current_volume.as_ref(),
    )
    else {
        return false;
    };
    evidence.version == request.version
        && evidence.session == request.session
        && evidence.authorization_id == request.authorization_id
        && evidence.authorization_id == *authorization_id
        && decision_authorization_id == authorization_id
        && evidence.delete_completion.is_none()
        && evidence.direct_successor_authorization.is_none()
        && cats_storage::authority::validate_volume_transition_evidence_bundle(
            &evidence.authorization,
            evidence.current_volume.as_ref(),
            evidence.delete_completion.as_ref(),
            evidence.direct_successor_authorization.as_ref(),
        )
        .is_ok()
        && exact_disposable_authorization_binding(
            desired,
            intent,
            authorization_id,
            expected_epoch,
            expected_head,
            authorization,
        )
        && current.volume_id == intent.volume_id
        && current.size_bytes == intent.size_bytes
        && current.durability == intent.durability
        && matches!(current.admin_state, VolumeAdminState::Active)
        && current.lease_owner.as_ref() == Some(&intent.attachment_id)
        && current.lease_epoch == expected_epoch
        && current.lease_expires_at.is_some()
        && current.head == *expected_head
}

#[derive(Debug)]
struct PlannedCleanup {
    order: String,
    target: CleanupTarget,
    volume_release: Option<VolumeReleaseReplay>,
}

#[derive(Debug, Clone)]
struct FreshCleanupCursor {
    session: SessionBinding,
    inventory_epoch: cats_api::runtime_reconciliation::Epoch,
    inventory_read_position: cats_api::runtime_reconciliation::Sequence,
    desired_read_position: cats_api::runtime_reconciliation::Sequence,
    observed_at: cats_api::runtime_reconciliation::UnixMillis,
}

fn cleanup_postcondition_successor(
    context: &RuntimeDesiredEffectContext,
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let cursor = fresh_cleanup_cursor(accepted)?;
    let absent_serving = retained_absent_serving_devices(context, accepted, desired, checkpoint)?;
    cleanup_postcondition_successor_at_with_absent_serving(
        desired,
        runtime,
        checkpoint,
        accepted.observation().residue.as_slice(),
        &cursor,
        &absent_serving,
    )
}

fn fresh_cleanup_cursor(
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
) -> anyhow::Result<FreshCleanupCursor> {
    let Some(desired_read_position) = accepted.desired_read_position() else {
        anyhow::bail!("cleanup successor planner lacks a current Desired read position")
    };
    Ok(FreshCleanupCursor {
        session: SessionBinding {
            node_id: accepted.session().node_id.clone(),
            node_boot_id: accepted.session().node_boot_id.clone(),
            agent_instance_id: accepted.session().agent_instance_id.clone(),
            agent_session_epoch: accepted.session().agent_session_epoch,
        },
        inventory_epoch: accepted.attestation().inventory_epoch,
        inventory_read_position: accepted.attestation().inventory_read_position,
        desired_read_position,
        observed_at: accepted.attestation().accepted_at_unix_ms,
    })
}

#[cfg(test)]
fn cleanup_postcondition_successor_at(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
    cursor: &FreshCleanupCursor,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    cleanup_postcondition_successor_at_with_absent_serving(
        desired,
        runtime,
        checkpoint,
        residue,
        cursor,
        &[],
    )
}

fn cleanup_postcondition_successor_at_with_absent_serving(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
    cursor: &FreshCleanupCursor,
    absent_serving: &[cats_api::runtime_reconciliation::PreparedDeviceInput],
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let ReconcileStep::CleanupRelease { cleanup: completed } = &checkpoint.step else {
        anyhow::bail!("cleanup successor planner received another lifecycle step")
    };
    anyhow::ensure!(
        cleanup_target_is_absent(completed, runtime, residue),
        "cleanup successor planner did not receive the exact target-absent postcondition"
    );
    remaining_cleanup_successor_at_with_absent_serving(
        desired,
        runtime,
        checkpoint,
        residue,
        cursor,
        absent_serving,
    )
}

fn stop_postcondition_successor(
    context: &RuntimeDesiredEffectContext,
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let cursor = fresh_cleanup_cursor(accepted)?;
    let absent_serving = retained_absent_serving_devices(context, accepted, desired, checkpoint)?;
    stop_postcondition_successor_at_with_absent_serving(
        desired,
        runtime,
        checkpoint,
        accepted.observation().residue.as_slice(),
        &cursor,
        &absent_serving,
    )
}

#[cfg(test)]
fn stop_postcondition_successor_at(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
    cursor: &FreshCleanupCursor,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    stop_postcondition_successor_at_with_absent_serving(
        desired,
        runtime,
        checkpoint,
        residue,
        cursor,
        &[],
    )
}

fn stop_postcondition_successor_at_with_absent_serving(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
    cursor: &FreshCleanupCursor,
    absent_serving: &[cats_api::runtime_reconciliation::PreparedDeviceInput],
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let ReconcileStep::StopRuntime {
        runtime_incarnation,
        process_start_time_ticks,
        scope_id,
    } = &checkpoint.step
    else {
        anyhow::bail!("StopRuntime successor planner received another lifecycle step")
    };
    anyhow::ensure!(
        matches!(
            desired.target,
            RuntimeTarget::Warm | RuntimeTarget::Cold | RuntimeTarget::Deleted
        ),
        "StopRuntime cannot settle the current Desired target"
    );
    let launch = checkpoint
        .runtime_launch
        .identity()
        .context("StopRuntime successor lost its retained launch")?;
    anyhow::ensure!(
        checkpoint.runtime_incarnation.as_ref() == Some(runtime_incarnation)
            && runtime.runtime_incarnation.as_ref() == Some(runtime_incarnation)
            && launch.runtime_incarnation == *runtime_incarnation
            && launch.scope_id == *scope_id
            && !runtime.processes.iter().any(|process| {
                matches!(process.role, ProcessRole::Vmm { .. })
                    || (&process.scope_id == scope_id
                        && process.process_start_time_ticks == *process_start_time_ticks)
            }),
        "StopRuntime postcondition does not prove the exact VMM absent"
    );
    remaining_cleanup_successor_at_with_absent_serving(
        desired,
        runtime,
        checkpoint,
        residue,
        cursor,
        absent_serving,
    )
}

fn remaining_cleanup_successor_at_with_absent_serving(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
    cursor: &FreshCleanupCursor,
    absent_serving: &[cats_api::runtime_reconciliation::PreparedDeviceInput],
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let mut plans = canonical_remaining_cleanup_with_absent_serving(
        desired,
        runtime,
        checkpoint,
        residue,
        absent_serving,
    )?;
    // This order is the teardown dependency order, not history carried over
    // from the completed token.  Every successor is rebuilt from this one
    // accepted full inventory and the current Desired row.
    plans.sort_by(|left, right| left.order.cmp(&right.order));
    anyhow::ensure!(
        plans.windows(2).all(|pair| pair[0].order != pair[1].order),
        "cleanup successor found duplicate canonical targets"
    );

    let mut successor = checkpoint.clone();
    successor.processes = runtime.processes.clone();
    successor.volumes = runtime.volumes.clone();
    successor.mounts = runtime.mounts.clone();
    successor.networks = runtime.networks.clone();
    successor.guest_transport = runtime.guest_transport.clone();
    successor.warm_snapshot = runtime.warm_snapshot.clone();
    successor.stable_state = None;
    successor.updated_at_unix_ms = cursor.observed_at;
    if let Some(next) = plans.into_iter().next() {
        if matches!(next.target, CleanupTarget::Volume { .. }) {
            anyhow::ensure!(
                runtime.processes.is_empty()
                    && runtime
                        .volumes
                        .iter()
                        .all(|volume| volume.devices.is_empty())
                    && runtime.mounts.is_empty()
                    && runtime.networks.is_empty()
                    && matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable),
                "Volume cleanup cannot begin while runtime residue remains"
            );
        }
        successor.step = ReconcileStep::CleanupRelease {
            cleanup: CleanupRelease {
                target: next.target,
                inventory_session: cursor.session.clone(),
                inventory_epoch: cursor.inventory_epoch,
                inventory_read_position: cursor.inventory_read_position,
                desired_read_position: cursor.desired_read_position,
                volume_release: next.volume_release,
            },
        };
        return Ok(Some(successor));
    }

    if desired.target == RuntimeTarget::Deleted
        && desired.volumes.iter().any(|intent| {
            matches!(
                intent.disposition,
                VolumeDisposition::DeleteDisposableRoot { .. }
            ) && runtime
                .volumes
                .iter()
                .find(|volume| volume.volume_id == intent.volume_id)
                .is_none_or(|volume| {
                    !matches!(volume.authority, VolumeAuthorityEvidence::Absent)
                        || !volume.local_lineages.is_empty()
                })
        })
    {
        // The current contract has no local authority to turn an Owned or
        // Deleting Root into the physical delete step.  Keep the completed
        // non-Volume token as a zero-I/O fail-closed checkpoint until A2
        // supplies that exact transition/postcondition.
        return Ok(None);
    }

    settle_cleanup_target(desired, runtime, &mut successor)?;
    Ok(Some(successor))
}

fn cleanup_target_is_absent(
    completed: &CleanupRelease,
    runtime: &ObservedRuntimeStatus,
    residue: &[NodeResidue],
) -> bool {
    match &completed.target {
        CleanupTarget::Device {
            volume_id,
            ownership_token,
        } => !runtime
            .volumes
            .iter()
            .filter(|volume| &volume.volume_id == volume_id)
            .flat_map(|volume| &volume.devices)
            .any(|device| device_token(device) == Some(ownership_token)),
        CleanupTarget::Network {
            network_id,
            ownership_token,
        } => !runtime.networks.iter().any(|network| {
            &network.network_id == network_id
                && valid_token(&network.ownership_token) == Some(ownership_token)
        }),
        CleanupTarget::WarmSnapshot { snapshot_id } => !matches!(
            &runtime.warm_snapshot,
            WarmSnapshotEvidence::Present { snapshot_id: observed, .. } if observed == snapshot_id
        ),
        CleanupTarget::Scope {
            scope_id,
            process_start_time_ticks,
        } => !runtime.processes.iter().any(|process| {
            &process.scope_id == scope_id
                && &process.process_start_time_ticks == process_start_time_ticks
        }),
        CleanupTarget::OrphanScope {
            scope_id,
            cgroup_path,
            ownership_token,
        } => !residue.iter().any(|entry| {
            matches!(
                entry,
                NodeResidue::SystemdScope {
                    scope_id: observed_scope,
                    cgroup_path: observed_cgroup,
                    ownership_token: observed_token,
                } if observed_scope == scope_id
                    && observed_cgroup == cgroup_path
                    && valid_token(observed_token) == Some(ownership_token)
            )
        }),
        CleanupTarget::ControlSocket {
            socket_path,
            ownership_token,
        } => !residue.iter().any(|entry| {
            matches!(
                entry,
                NodeResidue::ControlSocket {
                    socket_path: observed_path,
                    ownership_token: observed_token,
                    ..
                } if observed_path == socket_path
                    && valid_token(observed_token) == Some(ownership_token)
            )
        }),
        CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        } => {
            let Some(replay) = &completed.volume_release else {
                return false;
            };
            let mut volumes = runtime
                .volumes
                .iter()
                .filter(|volume| &volume.volume_id == volume_id);
            let Some(volume) = volumes.next() else {
                return matches!(
                    replay.disposition,
                    VolumeDisposition::DeleteDisposableRoot { .. }
                );
            };
            if volumes.next().is_some() || !volume.devices.is_empty() {
                return false;
            }
            matches!(
                &volume.authority,
                VolumeAuthorityEvidence::Unowned {
                    attachment_epoch: observed_epoch,
                    head,
                } if attachment_epoch
                    .get()
                    .checked_add(1)
                    .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
                    == Some(*observed_epoch)
                    && head.generation == replay.generation
                    && runtime.volumes.iter().all(|candidate| {
                        &candidate.volume_id != volume_id
                            || candidate.local_lineages.iter().all(|lineage| {
                                lineage.attachment_id == *attachment_id
                                    && lineage.attachment_epoch == *attachment_epoch
                            })
                    })
            )
        }
        CleanupTarget::CheckpointFile { .. } => false,
    }
}

fn device_token(device: &ObservedDevice) -> Option<&RandomId128> {
    match device {
        ObservedDevice::KernelNbd {
            ownership_token, ..
        }
        | ObservedDevice::VhostUserBlk {
            ownership_token, ..
        } => valid_token(ownership_token),
    }
}

fn retained_absent_serving_devices(
    context: &RuntimeDesiredEffectContext,
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<Vec<cats_api::runtime_reconciliation::PreparedDeviceInput>> {
    let admission = context.node_global_process()?;
    anyhow::ensure!(
        admission.matches_observation(accepted.observation()),
        "absent serving cleanup authority belongs to another full observation"
    );
    let Some(launch) = checkpoint.runtime_launch.identity() else {
        return Ok(Vec::new());
    };
    Ok(launch
        .devices
        .iter()
        .filter(|prepared| admission.retains_absent_serving_owner(&desired.cat_id, prepared))
        .cloned()
        .collect())
}

fn canonical_remaining_cleanup(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
) -> anyhow::Result<Vec<PlannedCleanup>> {
    canonical_remaining_cleanup_with_absent_serving(desired, runtime, checkpoint, residue, &[])
}

fn canonical_remaining_cleanup_with_absent_serving(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
    absent_serving: &[cats_api::runtime_reconciliation::PreparedDeviceInput],
) -> anyhow::Result<Vec<PlannedCleanup>> {
    let launch = checkpoint.runtime_launch.identity();
    let mut plans = Vec::new();
    anyhow::ensure!(
        runtime.volumes.len() == desired.volumes.len()
            && desired.volumes.iter().all(|intent| {
                runtime
                    .volumes
                    .iter()
                    .filter(|volume| {
                        volume.volume_id == intent.volume_id
                            && volume.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
                            && volume.disk_id.as_ref() == Some(&intent.disk_id)
                    })
                    .count()
                    == 1
            }),
        "cleanup successor lacks the complete exact Desired volume set"
    );

    for intent in &desired.volumes {
        let volume = runtime
            .volumes
            .iter()
            .find(|volume| volume.volume_id == intent.volume_id)
            .context("cleanup successor lost one Desired volume")?;
        anyhow::ensure!(
            volume.devices.len() <= 1,
            "cleanup successor found duplicate devices"
        );
        if let Some(device) = volume.devices.first() {
            let token = device_token(device)
                .context("cleanup successor found a device without a valid ownership token")?;
            let prepared = launch
                .and_then(|launch| {
                    launch
                        .devices
                        .iter()
                        .find(|prepared| prepared.volume_id == intent.volume_id)
                })
                .context("cleanup successor cannot attribute a live device")?;
            anyhow::ensure!(
                token == &prepared.ownership_token,
                "cleanup successor device token changed from retained launch authority"
            );
            plans.push(PlannedCleanup {
                order: format!("0-device-{}-{}", intent.volume_id, token),
                target: CleanupTarget::Device {
                    volume_id: intent.volume_id.clone(),
                    ownership_token: token.clone(),
                },
                volume_release: None,
            });
        } else if let Some(prepared) = absent_serving
            .iter()
            .find(|prepared| prepared.volume_id == intent.volume_id)
        {
            anyhow::ensure!(
                launch.is_some_and(|launch| launch.devices.contains(prepared)),
                "absent serving cleanup target changed from retained launch authority"
            );
            plans.push(PlannedCleanup {
                order: format!("0-device-{}-{}", intent.volume_id, prepared.ownership_token),
                target: CleanupTarget::Device {
                    volume_id: intent.volume_id.clone(),
                    ownership_token: prepared.ownership_token.clone(),
                },
                volume_release: None,
            });
        }
    }

    for process in &runtime.processes {
        let token = valid_token(&process.ownership_token)
            .context("cleanup successor found a process without a valid ownership token")?;
        anyhow::ensure!(
            process_matches_launch(process, token, launch),
            "cleanup successor cannot attribute a live process"
        );
        plans.push(PlannedCleanup {
            order: format!(
                "1-scope-{}-{:020}",
                process.scope_id,
                process.process_start_time_ticks.get()
            ),
            target: CleanupTarget::Scope {
                scope_id: process.scope_id.clone(),
                process_start_time_ticks: process.process_start_time_ticks,
            },
            volume_release: None,
        });
    }

    for network in &runtime.networks {
        let token = valid_token(&network.ownership_token)
            .context("cleanup successor found a network without a valid ownership token")?;
        let expected = launch
            .map(|launch| launch.network.as_ref())
            .context("cleanup successor cannot attribute a live network")?;
        anyhow::ensure!(
            network.network_id == expected.network_config.network_id
                && network.tap_name == expected.tap_name
                && token == &expected.ownership_token,
            "cleanup successor network changed from retained launch authority"
        );
        plans.push(PlannedCleanup {
            order: format!("2-network-{}-{}", network.network_id, token),
            target: CleanupTarget::Network {
                network_id: network.network_id.clone(),
                ownership_token: token.clone(),
            },
            volume_release: None,
        });
    }

    if let WarmSnapshotEvidence::Present { snapshot_id, .. } = &runtime.warm_snapshot {
        plans.push(PlannedCleanup {
            order: format!("3-warm-snapshot-{snapshot_id}"),
            target: CleanupTarget::WarmSnapshot {
                snapshot_id: snapshot_id.clone(),
            },
            volume_release: None,
        });
    }

    for entry in residue {
        match entry {
            NodeResidue::SystemdScope {
                scope_id,
                cgroup_path,
                ownership_token,
            } => {
                if let Some(expected_token) = launch_token_for_scope(launch, scope_id) {
                    let token = valid_token(ownership_token).context(
                        "cleanup successor found an attributed orphan scope without a valid token",
                    )?;
                    anyhow::ensure!(
                        token == expected_token,
                        "cleanup successor orphan scope token changed from retained launch authority"
                    );
                    plans.push(PlannedCleanup {
                        order: format!("4-orphan-scope-{scope_id}-{token}"),
                        target: CleanupTarget::OrphanScope {
                            scope_id: scope_id.clone(),
                            cgroup_path: cgroup_path.clone(),
                            ownership_token: token.clone(),
                        },
                        volume_release: None,
                    });
                }
            }
            NodeResidue::ControlSocket {
                socket_path,
                ownership_token,
                ..
            } => {
                if absent_serving.iter().any(|prepared| {
                    &prepared.serving_process.control_socket_path == socket_path
                        || matches!(
                            &prepared.frontend,
                            cats_api::runtime_reconciliation::PrepareDeviceFrontend::KernelNbd {
                                listener_socket_path: listener,
                                ..
                            } if listener == socket_path
                        )
                        || matches!(
                            &prepared.frontend,
                            cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk {
                                socket_path: listener,
                                ..
                            } if listener == socket_path
                        )
                }) {
                    // The scanner-private owner/intent admission above, not
                    // this deliberately unowned public residue, carries the
                    // deletion authority for the complete socket directory.
                    continue;
                }
                if let Some(expected_token) = launch_token_for_socket(launch, socket_path) {
                    let token = valid_token(ownership_token).context(
                        "cleanup successor found an attributed control socket without a valid token",
                    )?;
                    anyhow::ensure!(
                        token == expected_token,
                        "cleanup successor control socket token changed from retained launch authority"
                    );
                    plans.push(PlannedCleanup {
                        order: format!("5-control-socket-{}-{token}", socket_path.as_str()),
                        target: CleanupTarget::ControlSocket {
                            socket_path: socket_path.clone(),
                            ownership_token: token.clone(),
                        },
                        volume_release: None,
                    });
                }
            }
            _ => {}
        }
    }

    if matches!(
        desired.target,
        RuntimeTarget::Warm | RuntimeTarget::Cold | RuntimeTarget::Deleted
    ) {
        for intent in &desired.volumes {
            let volume = runtime
                .volumes
                .iter()
                .find(|volume| volume.volume_id == intent.volume_id)
                .expect("complete Desired volume set checked above");
            match &volume.authority {
                VolumeAuthorityEvidence::Owned {
                    attachment_id,
                    attachment_epoch,
                    head,
                } => {
                    anyhow::ensure!(
                        attachment_id == &intent.attachment_id && volume.devices.is_empty(),
                        "cleanup successor cannot release a changed or published attachment"
                    );
                    let mut exact = volume.local_lineages.iter().filter(|lineage| {
                        lineage.attachment_id == *attachment_id
                            && lineage.attachment_epoch == *attachment_epoch
                            && lineage.node_id == desired.placement.node_id
                            && lineage.placement_epoch == desired.placement.placement_epoch
                            && lineage.local_durable_generation == head.generation
                            && lineage.remote_durable_generation == head.generation
                            && lineage.pending_pack_count.get() == 0
                            && !lineage.fenced
                            && match (&lineage.acquire_origin, &intent.acquire) {
                                (
                                    cats_api::runtime_reconciliation::AcquireOrigin::Normal {
                                        transition_id,
                                    },
                                    VolumeAcquire::Normal {
                                        transition_id: intended,
                                        ..
                                    },
                                ) => transition_id == intended,
                                (
                                    cats_api::runtime_reconciliation::AcquireOrigin::Takeover {
                                        authorization_id,
                                    },
                                    VolumeAcquire::Takeover {
                                        authorization_id: intended,
                                    },
                                ) => authorization_id == intended,
                                _ => false,
                            }
                    });
                    let fully_drained = exact.next().is_some() && exact.next().is_none();
                    if !fully_drained
                        && matches!(
                            intent.disposition,
                            VolumeDisposition::DeleteDisposableRoot { .. }
                        )
                    {
                        // R < L cannot take the normal release branch. The
                        // authorization ID is intentionally absent from
                        // Desired/checkpoint inventory, so this frozen schema
                        // cannot mint DeleteDisposableRoot here.
                        continue;
                    }
                    anyhow::ensure!(
                        fully_drained,
                        "cleanup successor cannot prove one fully drained local lineage"
                    );
                    let release_transition_id =
                        RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
                            .context("generate Volume cleanup transition identity")?;
                    plans.push(PlannedCleanup {
                        order: format!("6-volume-{}", intent.volume_intent_id),
                        target: CleanupTarget::Volume {
                            volume_id: intent.volume_id.clone(),
                            attachment_id: attachment_id.clone(),
                            attachment_epoch: *attachment_epoch,
                        },
                        volume_release: Some(VolumeReleaseReplay {
                            release_transition_id,
                            generation: head.generation,
                            disposition: intent.disposition.clone(),
                        }),
                    });
                }
                VolumeAuthorityEvidence::Unowned { .. }
                | VolumeAuthorityEvidence::Deleting { .. }
                | VolumeAuthorityEvidence::Absent => {}
                VolumeAuthorityEvidence::Unavailable => {
                    anyhow::bail!("cleanup successor lacks complete Volume authority")
                }
            }
        }
    }
    Ok(plans)
}

fn process_matches_launch(
    process: &ProcessEvidence,
    token: &RandomId128,
    launch: Option<&cats_api::runtime_reconciliation::RuntimeLaunchIdentity>,
) -> bool {
    let Some(launch) = launch else {
        return false;
    };
    match &process.role {
        ProcessRole::Vmm {
            runtime_incarnation,
        } => {
            runtime_incarnation == &launch.runtime_incarnation
                && process.scope_id == launch.scope_id
                && process.control_socket_path == launch.api_socket_path
                && token == &launch.process_identity_token
        }
        ProcessRole::Blockd {
            volume_id,
            attachment_id,
            attachment_epoch,
        } => launch.devices.iter().any(|device| {
            &device.volume_id == volume_id
                && &device.attachment_id == attachment_id
                && device.attachment_epoch == *attachment_epoch
                && device.serving_process.scope_id == process.scope_id
                && device.serving_process.control_socket_path == process.control_socket_path
                && &device.serving_process.process_identity_token == token
        }),
    }
}

fn launch_token_for_scope<'a>(
    launch: Option<&'a cats_api::runtime_reconciliation::RuntimeLaunchIdentity>,
    scope_id: &Id,
) -> Option<&'a RandomId128> {
    let launch = launch?;
    if &launch.scope_id == scope_id {
        return Some(&launch.process_identity_token);
    }
    launch
        .devices
        .iter()
        .find(|device| &device.serving_process.scope_id == scope_id)
        .map(|device| &device.serving_process.process_identity_token)
}

fn launch_token_for_socket<'a>(
    launch: Option<&'a cats_api::runtime_reconciliation::RuntimeLaunchIdentity>,
    socket_path: &HostPath,
) -> Option<&'a RandomId128> {
    let launch = launch?;
    if &launch.api_socket_path == socket_path {
        return Some(&launch.process_identity_token);
    }
    launch
        .devices
        .iter()
        .find(|device| &device.serving_process.control_socket_path == socket_path)
        .map(|device| &device.serving_process.process_identity_token)
}

fn settle_cleanup_target(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    successor: &mut RuntimeCheckpoint,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        runtime.processes.is_empty()
            && runtime
                .volumes
                .iter()
                .all(|volume| volume.devices.is_empty())
            && runtime.mounts.is_empty()
            && runtime.networks.is_empty()
            && matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable),
        "cleanup target cannot settle while runtime residue remains"
    );
    let state = match desired.target {
        RuntimeTarget::Warm => {
            anyhow::bail!("Warm is unavailable in this release")
        }
        RuntimeTarget::Cold => {
            anyhow::ensure!(
                matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
                    && runtime.volumes.iter().all(|volume| matches!(
                        volume.authority,
                        VolumeAuthorityEvidence::Unowned { .. }
                    )),
                "Cold convergence retains a Warm snapshot or owned Volume"
            );
            StableState::Cold
        }
        RuntimeTarget::Deleted => {
            anyhow::ensure!(
                matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
                    && desired.volumes.iter().all(|intent| {
                        runtime
                            .volumes
                            .iter()
                            .find(|volume| volume.volume_id == intent.volume_id)
                            .is_some_and(|volume| match intent.disposition {
                                VolumeDisposition::DetachRetained => matches!(
                                    volume.authority,
                                    VolumeAuthorityEvidence::Unowned { .. }
                                ),
                                VolumeDisposition::DeleteDisposableRoot { .. } => {
                                    matches!(volume.authority, VolumeAuthorityEvidence::Absent)
                                        && volume.local_lineages.is_empty()
                                }
                                VolumeDisposition::Retain => false,
                            })
                    }),
                "Deleted cleanup successor lacks exact detached/deleted Volume evidence"
            );
            StableState::Deleted
        }
        RuntimeTarget::Running | RuntimeTarget::Suspended => {
            anyhow::bail!("cleanup target cannot settle a Host-bound runtime")
        }
    };
    successor.runtime_incarnation = None;
    successor.runtime_launch = RuntimeLaunch::Absent;
    successor.stable_state = Some(state);
    successor.step = ReconcileStep::Stable { state };
    Ok(())
}

fn drain_attempt_successor(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    attempt: &LifecyclePhysicalAttempt,
    observed_at: cats_api::runtime_reconciliation::UnixMillis,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let LifecyclePhysicalAttempt::VerifiedDrain(receipt) = attempt else {
        return Ok(None);
    };
    let ReconcileStep::DrainPublish {
        volume_id,
        attachment_epoch,
        local_generation,
        remote_generation,
    } = &checkpoint.step
    else {
        anyhow::bail!("verified Drain receipt belongs to another lifecycle step")
    };
    let mut ordered = desired.volumes.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|intent| intent.guest_device.slot);
    anyhow::ensure!(
        desired.target != RuntimeTarget::Running
            && !ordered.is_empty()
            && ordered.len() == runtime.volumes.len()
            && ordered.len() == receipt.volumes.len()
            && ordered
                .windows(2)
                .all(|pair| pair[0].guest_device.slot != pair[1].guest_device.slot),
        "verified Drain successor lacks one canonical Desired volume set"
    );
    for (index, (intent, drained)) in ordered.iter().zip(&receipt.volumes).enumerate() {
        let ReconcileStep::DrainPublish {
            volume_id: accepted_volume_id,
            attachment_epoch: accepted_epoch,
            local_generation: accepted_local,
            remote_generation: accepted_remote,
        } = drain_step_for_intent(desired, runtime, intent)?
        else {
            unreachable!()
        };
        anyhow::ensure!(
            drained.volume_id == accepted_volume_id
                && drained.attachment_epoch == accepted_epoch
                && drained.local_generation == drained.remote_generation
                && drained.local_generation >= accepted_local
                && drained.remote_generation >= accepted_remote
                && (index != 0
                    || (accepted_volume_id == *volume_id
                        && accepted_epoch == *attachment_epoch
                        && accepted_local >= *local_generation
                        && accepted_remote >= *remote_generation)),
            "verified Drain receipt is incomplete, stale, or belongs to another checkpoint token"
        );
    }

    let mut successor = checkpoint.clone();
    successor.processes = runtime.processes.clone();
    successor.volumes = runtime.volumes.clone();
    successor.mounts = runtime.mounts.clone();
    successor.networks = runtime.networks.clone();
    successor.guest_transport = runtime.guest_transport.clone();
    successor.warm_snapshot = runtime.warm_snapshot.clone();
    successor.stable_state = None;
    successor.updated_at_unix_ms = observed_at;

    let runtime_incarnation = checkpoint
        .runtime_incarnation
        .as_ref()
        .context("verified final Drain lost its runtime incarnation")?;
    if let Ok(process) = exact_vmm_process(runtime) {
        anyhow::ensure!(
            matches!(
                process.state,
                cats_api::runtime_reconciliation::ProcessState::Running
            ),
            "verified final Drain cannot advance a non-Running live VMM"
        );
        successor.step = ReconcileStep::PauseRuntime {
            runtime_incarnation: runtime_incarnation.clone(),
            process_start_time_ticks: process.process_start_time_ticks,
        };
        return Ok(Some(successor));
    }
    anyhow::ensure!(
        matches!(
            desired.target,
            RuntimeTarget::Warm | RuntimeTarget::Cold | RuntimeTarget::Deleted
        ) && !runtime
            .processes
            .iter()
            .any(|process| matches!(process.role, ProcessRole::Vmm { .. })),
        "verified final Drain cannot settle a missing Suspended VMM"
    );
    let mut retained = checkpoint.processes.iter().filter(|process| {
        matches!(
            &process.role,
            ProcessRole::Vmm { runtime_incarnation: retained }
                if retained == runtime_incarnation
        )
    });
    let process = retained
        .next()
        .context("verified final Drain lacks its retained VMM identity")?;
    anyhow::ensure!(
        retained.next().is_none(),
        "verified final Drain retained duplicate VMM identities"
    );
    successor.step = ReconcileStep::StopRuntime {
        runtime_incarnation: runtime_incarnation.clone(),
        process_start_time_ticks: process.process_start_time_ticks,
        scope_id: process.scope_id.clone(),
    };
    Ok(Some(successor))
}

fn exact_postcondition_successor(
    _state_directory: &Path,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let ReconcileStep::PauseRuntime {
        runtime_incarnation,
        process_start_time_ticks,
    } = &checkpoint.step
    else {
        return Ok(None);
    };
    let process = exact_vmm_process(runtime)?;
    anyhow::ensure!(
        runtime.runtime_incarnation.as_ref() == Some(runtime_incarnation)
            && process.process_start_time_ticks == *process_start_time_ticks
            && process.state == cats_api::runtime_reconciliation::ProcessState::Paused,
        "PauseRuntime postcondition does not match its exact process"
    );
    let mut successor = checkpoint.clone();
    successor.processes = runtime.processes.clone();
    successor.volumes = runtime.volumes.clone();
    successor.mounts = runtime.mounts.clone();
    successor.networks = runtime.networks.clone();
    successor.guest_transport = runtime.guest_transport.clone();
    successor.warm_snapshot = runtime.warm_snapshot.clone();
    successor.stable_state = None;
    successor.step = match desired.target {
        RuntimeTarget::Suspended => {
            successor.stable_state = Some(StableState::Suspended);
            ReconcileStep::Stable {
                state: StableState::Suspended,
            }
        }
        RuntimeTarget::Warm | RuntimeTarget::Cold | RuntimeTarget::Deleted => {
            ReconcileStep::StopRuntime {
                runtime_incarnation: runtime_incarnation.clone(),
                process_start_time_ticks: *process_start_time_ticks,
                scope_id: process.scope_id.clone(),
            }
        }
        RuntimeTarget::Running => {
            anyhow::bail!("current Running Desired cannot settle PauseRuntime")
        }
    };
    Ok(Some(successor))
}

fn persist_lifecycle_successor(
    context: &RuntimeDesiredEffectContext,
    store: &FileCheckpointStore,
    predecessor: &StoredCheckpoint,
    successor: &RuntimeCheckpoint,
    current: &super::checkpoint::CurrentCheckpointGuard<'_>,
    operation: &'static str,
) -> anyhow::Result<()> {
    // The cancellation read permit and checkpoint writer/CAS guard stay live
    // together through rename+directory fsync. A cancellation which wins
    // before this point therefore observes the exact predecessor unchanged.
    let _active = context
        .linearization_permit()
        .context("linearize lifecycle checkpoint publication with cancellation")?;
    store
        .revalidate_current(predecessor, current)
        .context("revalidate lifecycle predecessor before checkpoint CAS")?;
    store
        .replace_current(predecessor, successor, current)
        .context(operation)?;
    Ok(())
}

fn is_lifecycle_step(step: &ReconcileStep) -> bool {
    matches!(
        step,
        ReconcileStep::DrainPublish { .. }
            | ReconcileStep::PauseRuntime { .. }
            | ReconcileStep::SnapshotWarmRuntime { .. }
            | ReconcileStep::StopRuntime { .. }
            | ReconcileStep::CleanupRelease { .. }
            | ReconcileStep::DeleteDisposableRoot { .. }
    )
}

fn checkpoint_is_current(desired: &DesiredRuntimeSpec, checkpoint: &RuntimeCheckpoint) -> bool {
    checkpoint.cat_id == desired.cat_id
        && checkpoint.node_id == desired.placement.node_id
        && checkpoint.placement_epoch == desired.placement.placement_epoch
        && checkpoint.desired_revision == desired.desired_revision
        && checkpoint.spec_digest == desired.spec_digest
}

fn cleanup_is_fresh(
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    cleanup: &cats_api::runtime_reconciliation::CleanupRelease,
) -> bool {
    cleanup_execution_context_is_fresh(
        accepted.session(),
        accepted.attestation(),
        accepted.desired_read_position(),
        cleanup,
    )
}

fn cleanup_execution_context_is_fresh(
    session: &cats_api::runtime_reconciliation::AgentSession,
    attestation: &cats_api::runtime_reconciliation::AdmissionInventoryAttestation,
    desired_read_position: Option<cats_api::runtime_reconciliation::Sequence>,
    cleanup: &cats_api::runtime_reconciliation::CleanupRelease,
) -> bool {
    cleanup.inventory_session.node_id == session.node_id
        && cleanup.inventory_session.node_boot_id == session.node_boot_id
        && cleanup.inventory_session.agent_instance_id == session.agent_instance_id
        && cleanup.inventory_session.agent_session_epoch == session.agent_session_epoch
        && cleanup.inventory_epoch <= attestation.inventory_epoch
        && cleanup.inventory_read_position <= attestation.inventory_read_position
        && desired_read_position.is_some_and(|position| position >= cleanup.desired_read_position)
        && match &cleanup.target {
            CleanupTarget::Volume { .. } => cleanup.volume_release.is_some(),
            _ => cleanup.volume_release.is_none(),
        }
}

fn first_lifecycle_step(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
) -> anyhow::Result<Option<ReconcileStep>> {
    anyhow::ensure!(
        desired.target != RuntimeTarget::Warm,
        "Warm is unavailable in this release"
    );
    if desired.target == RuntimeTarget::Running {
        return Ok(None);
    }
    let vmm = exact_vmm_process(runtime)?;
    if desired.target == RuntimeTarget::Suspended {
        let runtime_incarnation = runtime
            .runtime_incarnation
            .as_ref()
            .context("Suspended lifecycle planner lost its runtime incarnation")?;
        return Ok(Some(ReconcileStep::PauseRuntime {
            runtime_incarnation: runtime_incarnation.clone(),
            process_start_time_ticks: vmm.process_start_time_ticks,
        }));
    }
    if desired.target == RuntimeTarget::Deleted && has_only_explicit_disposable_root(desired) {
        let runtime_incarnation = runtime
            .runtime_incarnation
            .as_ref()
            .context("disposable Deleted lifecycle planner lost its runtime incarnation")?;
        return Ok(Some(ReconcileStep::StopRuntime {
            runtime_incarnation: runtime_incarnation.clone(),
            process_start_time_ticks: vmm.process_start_time_ticks,
            scope_id: vmm.scope_id.clone(),
        }));
    }
    // An accepted R==L observation predates this effect batch and says
    // nothing about Guest/page-cache writes after the scan.  Warm, Cold, and
    // every Deleted intent which retains a volume therefore start with a
    // fresh quiesce+remote-durability token.  The sole explicitly disposable
    // Root exception above has authority to discard its tail after stopping
    // the VMM.  Suspended performs its Guest-local quiesce in PauseRuntime and
    // retains any Relaxed R<L journal on this Host.
    anyhow::ensure!(
        !desired.volumes.is_empty() && runtime.volumes.len() == desired.volumes.len(),
        "lifecycle drain planner lacks the complete Desired volume set"
    );
    let first = desired
        .volumes
        .iter()
        .min_by_key(|volume| volume.guest_device.slot)
        .context("lifecycle drain planner lacks a canonical first volume")?;
    Ok(Some(drain_step_for_intent(desired, runtime, first)?))
}

fn has_only_explicit_disposable_root(desired: &DesiredRuntimeSpec) -> bool {
    matches!(
        desired.volumes.as_slice(),
        [intent]
            if intent.disk_kind == DiskKind::Root
                && matches!(intent.disposition, VolumeDisposition::DeleteDisposableRoot { .. })
    )
}

fn superseded_drain_rebind_successor(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    observed_at: cats_api::runtime_reconciliation::UnixMillis,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let ReconcileStep::DrainPublish {
        volume_id,
        attachment_epoch,
        local_generation,
        remote_generation,
    } = &checkpoint.step
    else {
        return Ok(None);
    };
    if checkpoint.desired_revision >= desired.desired_revision
        || checkpoint.cat_id != desired.cat_id
        || checkpoint.node_id != desired.placement.node_id
        || checkpoint.placement_epoch != desired.placement.placement_epoch
        || !matches!(desired.target, RuntimeTarget::Cold | RuntimeTarget::Deleted)
        || checkpoint.lifecycle_admission != LifecycleAdmission::Closed
        || runtime.lifecycle_admission != LifecycleAdmission::Closed
        || runtime.platform_guards != 0
        || runtime.routes.iter().any(|route| {
            route.gate != cats_api::runtime_reconciliation::RouteGateState::Closed
                || route.active_guards != 0
                || route.cancellation_pending
        })
        || checkpoint
            .route_gates
            .iter()
            .any(|route| route.gate != cats_api::runtime_reconciliation::RouteGateState::Closed)
        || runtime.runtime_incarnation != checkpoint.runtime_incarnation
        || !runtime.applied_desired.as_ref().is_some_and(|applied| {
            applied.desired_revision == desired.desired_revision
                && applied.spec_digest == desired.spec_digest
                && applied.placement == desired.placement
                && applied.target == desired.target
        })
        || !current_runtime_matches_retained_launch(desired, runtime, checkpoint)
    {
        return Ok(None);
    }

    let Some(observed) = runtime
        .volumes
        .iter()
        .find(|observed| &observed.volume_id == volume_id)
    else {
        return Ok(None);
    };
    let VolumeAuthorityEvidence::Owned {
        attachment_epoch: observed_epoch,
        ..
    } = &observed.authority
    else {
        return Ok(None);
    };
    let mut lineages = observed.local_lineages.iter().filter(|lineage| {
        lineage.attachment_epoch == *observed_epoch
            && lineage.node_id == desired.placement.node_id
            && lineage.placement_epoch == desired.placement.placement_epoch
    });
    let Some(lineage) = lineages.next() else {
        return Ok(None);
    };
    if lineages.next().is_some()
        || observed_epoch != attachment_epoch
        || lineage.local_durable_generation < *local_generation
        || lineage.remote_durable_generation < *remote_generation
    {
        return Ok(None);
    }

    let Some(step) = first_lifecycle_step(desired, runtime)? else {
        return Ok(None);
    };
    let mut successor = checkpoint.clone();
    successor.desired_revision = desired.desired_revision;
    successor.spec_digest = desired.spec_digest.clone();
    successor.processes = runtime.processes.clone();
    successor.volumes = runtime.volumes.clone();
    successor.mounts = runtime.mounts.clone();
    successor.networks = runtime.networks.clone();
    successor.guest_transport = runtime.guest_transport.clone();
    successor.warm_snapshot = runtime.warm_snapshot.clone();
    successor.stable_state = None;
    successor.step = step;
    successor.updated_at_unix_ms = observed_at;
    Ok(Some(successor))
}

fn current_runtime_matches_retained_launch(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
) -> bool {
    let Some(launch) = checkpoint.runtime_launch.identity() else {
        return false;
    };
    let Ok(process) = exact_vmm_process(runtime) else {
        return false;
    };
    let cats_api::runtime_reconciliation::OwnershipTokenEvidence::Valid { ownership_token } =
        &process.ownership_token
    else {
        return false;
    };
    let expected_shape = cats_api::runtime_reconciliation::ObservedVmShape {
        vcpus: launch.vcpus,
        memory_bytes: launch.memory_bytes,
        boot_image_digest: launch.boot_image_digest.clone(),
        guest_config_digest: launch.guest_config_digest.clone(),
    };
    if checkpoint.runtime_incarnation.as_ref() != Some(&launch.runtime_incarnation)
        || runtime.runtime_incarnation.as_ref() != Some(&launch.runtime_incarnation)
        || launch.vcpus != desired.runtime.vcpus
        || launch.memory_bytes != desired.runtime.memory_bytes
        || launch.boot_image_digest != desired.runtime.boot_image_digest
        || launch.guest_config_digest != desired.runtime.guest_config_digest
        || launch.network.network_config != desired.runtime.network_config
        || process.state != cats_api::runtime_reconciliation::ProcessState::Running
        || process.executable_path != launch.boot.vmm_executable.path
        || !matches!(
            process.control_handshake,
            cats_api::runtime_reconciliation::ControlHandshakeEvidence::Verified
        )
        || process.observed_vm_shape.as_ref() != Some(&expected_shape)
        || !process_matches_launch(process, ownership_token, Some(launch))
        || launch.devices.len() != desired.volumes.len()
        || runtime.volumes.len() != desired.volumes.len()
    {
        return false;
    }
    desired.volumes.iter().all(|intent| {
        let mut prepared_matches = launch
            .devices
            .iter()
            .filter(|prepared| prepared.volume_id == intent.volume_id);
        let Some(prepared) = prepared_matches.next() else {
            return false;
        };
        let acquire_matches = match (&prepared.acquire_origin, &intent.acquire) {
            (
                cats_api::runtime_reconciliation::AcquireOrigin::Normal { transition_id },
                VolumeAcquire::Normal {
                    transition_id: intended,
                    ..
                },
            ) => transition_id == intended,
            (
                cats_api::runtime_reconciliation::AcquireOrigin::Takeover { authorization_id },
                VolumeAcquire::Takeover {
                    authorization_id: intended,
                },
            ) => authorization_id == intended,
            _ => false,
        };
        if prepared_matches.next().is_some()
            || prepared.volume_intent_id != intent.volume_intent_id
            || prepared.disk_id != intent.disk_id
            || prepared.disk_kind != intent.disk_kind
            || prepared.attachment_id != intent.attachment_id
            || prepared.size_bytes != intent.size_bytes
            || prepared.durability != intent.durability
            || prepared.guest_device != intent.guest_device
            || !acquire_matches
        {
            return false;
        }
        let mut observed_matches = runtime
            .volumes
            .iter()
            .filter(|observed| observed.volume_id == intent.volume_id);
        let Some(observed) = observed_matches.next() else {
            return false;
        };
        let mut current_lineages = observed.local_lineages.iter().filter(|lineage| {
            lineage.attachment_id == prepared.attachment_id
                && lineage.attachment_epoch == prepared.attachment_epoch
                && lineage.acquire_origin == prepared.acquire_origin
                && lineage.node_id == desired.placement.node_id
                && lineage.placement_epoch == desired.placement.placement_epoch
        });
        let exact_current_lineage =
            current_lineages.next().is_some() && current_lineages.next().is_none();
        observed_matches.next().is_none()
            && cold_observed_identity_matches_intent(observed, intent)
            && matches!(
                &observed.authority,
                VolumeAuthorityEvidence::Owned {
                    attachment_id,
                    attachment_epoch,
                    ..
                } if attachment_id == &prepared.attachment_id
                    && attachment_epoch == &prepared.attachment_epoch
            )
            && exact_current_lineage
            && drain_step_for_intent(desired, runtime, intent).is_ok()
    })
}

fn drain_step_for_intent(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
) -> anyhow::Result<ReconcileStep> {
    let mut observed = runtime
        .volumes
        .iter()
        .filter(|observed| observed.volume_id == intent.volume_id);
    let volume = observed
        .next()
        .context("lifecycle drain planner lacks the selected Desired volume")?;
    anyhow::ensure!(
        observed.next().is_none()
            && volume.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
            && volume.disk_id.as_ref() == Some(&intent.disk_id),
        "lifecycle drain planner found an ambiguous selected Desired volume"
    );
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        ..
    } = &volume.authority
    else {
        anyhow::bail!("lifecycle drain planner found a non-Owned retained volume")
    };
    anyhow::ensure!(
        attachment_id == &intent.attachment_id,
        "lifecycle drain planner found another attachment owner"
    );
    let mut lineages = volume.local_lineages.iter().filter(|lineage| {
        lineage.attachment_id == *attachment_id
            && lineage.attachment_epoch == *attachment_epoch
            && lineage.node_id == desired.placement.node_id
            && lineage.placement_epoch == desired.placement.placement_epoch
    });
    let lineage = lineages
        .next()
        .context("lifecycle drain planner lacks the exact current local lineage")?;
    anyhow::ensure!(
        lineages.next().is_none()
            && lineage.local_durable_generation >= lineage.remote_durable_generation,
        "lifecycle drain planner found duplicate or regressed current lineage"
    );
    Ok(ReconcileStep::DrainPublish {
        volume_id: volume.volume_id.clone(),
        attachment_epoch: *attachment_epoch,
        local_generation: lineage.local_durable_generation,
        remote_generation: lineage.remote_durable_generation,
    })
}

fn exact_vmm_process(runtime: &ObservedRuntimeStatus) -> anyhow::Result<&ProcessEvidence> {
    let incarnation = runtime
        .runtime_incarnation
        .as_ref()
        .context("lifecycle predecessor lacks a runtime incarnation")?;
    let mut matches = runtime.processes.iter().filter(|process| {
        matches!(
            &process.role,
            ProcessRole::Vmm { runtime_incarnation } if runtime_incarnation == incarnation
        )
    });
    let process = matches
        .next()
        .context("lifecycle predecessor lacks the exact VMM process")?;
    anyhow::ensure!(
        matches.next().is_none(),
        "lifecycle predecessor has duplicate VMM processes"
    );
    Ok(process)
}

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, spec_digest,
        AdmissionInventoryAttestation, AgentSession, AppliedDesiredEvidence, DesiredReadSnapshot,
        NodeObservation, ProcessState, RuntimeLaunch,
    };
    use tempfile::TempDir;

    use super::super::checkpoint::WriteStage;
    use super::super::kernel_nbd::{KernelNbdDetachPort, KernelNbdDetachResult};
    use super::super::root_provision_process::{
        ManagedServingKey, NodeGlobalManagedProcessScanAdmission,
    };
    use super::super::serving_blockd_process::{
        global_sealed as serving_global_sealed, process_sealed as serving_process_sealed,
        CheckpointedServingBlockdProcess, ServingBlockdExpectation, ServingBlockdProcessPort,
        ServingBlockdProcessStart,
    };
    use super::super::vmm_process::{
        global_sealed as vmm_global_sealed, sealed as vmm_process_sealed, CheckpointedVmmProcess,
        VmmGateSuccessorProof, VmmProcessGlobalInspection, VmmProcessInspection, VmmProcessPort,
        VmmProcessStart,
    };

    fn fixtures(
        target: RuntimeTarget,
    ) -> (DesiredRuntimeSpec, RuntimeCheckpoint, ObservedRuntimeStatus) {
        let mut desired = decode_desired_runtime_spec(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-desired.json"
        )))
        .unwrap();
        desired.target = target;
        desired.desired_revision = cats_api::runtime_reconciliation::Revision::new(8).unwrap();
        let mut checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        checkpoint.desired_revision = desired.desired_revision;
        checkpoint.spec_digest = desired.spec_digest.clone();
        checkpoint.stable_state = Some(StableState::Running);
        checkpoint.step = ReconcileStep::Stable {
            state: StableState::Running,
        };
        checkpoint.lifecycle_admission = LifecycleAdmission::Closed;
        for gate in &mut checkpoint.route_gates {
            gate.gate = cats_api::runtime_reconciliation::RouteGateState::Closed;
        }
        let launch = match &checkpoint.runtime_launch {
            RuntimeLaunch::Present(launch) => launch,
            RuntimeLaunch::Absent => panic!("fixture launch absent"),
        };
        let process = ProcessEvidence {
            role: ProcessRole::Vmm {
                runtime_incarnation: launch.runtime_incarnation.clone(),
            },
            process_id: 42,
            process_start_time_ticks: cats_api::runtime_reconciliation::WireU64::new(99).unwrap(),
            executable_path: launch.boot.vmm_executable.path.clone(),
            scope_id: launch.scope_id.clone(),
            control_socket_path: launch.api_socket_path.clone(),
            state: ProcessState::Running,
            ownership_token: cats_api::runtime_reconciliation::OwnershipTokenEvidence::Valid {
                ownership_token: launch.process_identity_token.clone(),
            },
            control_handshake: cats_api::runtime_reconciliation::ControlHandshakeEvidence::Verified,
            observed_vm_shape: Some(cats_api::runtime_reconciliation::ObservedVmShape {
                vcpus: launch.vcpus,
                memory_bytes: launch.memory_bytes,
                boot_image_digest: launch.boot_image_digest.clone(),
                guest_config_digest: launch.guest_config_digest.clone(),
            }),
        };
        checkpoint.processes = vec![process];
        let runtime = ObservedRuntimeStatus {
            cat_id: checkpoint.cat_id.clone(),
            applied_desired: None,
            runtime_incarnation: checkpoint.runtime_incarnation.clone(),
            stable_state: checkpoint.stable_state,
            step: checkpoint.step.clone(),
            checkpoint: CheckpointEvidence::Missing {
                checkpoint_path: cats_api::runtime_reconciliation::HostPath::new(
                    "/placeholder".to_owned(),
                )
                .unwrap(),
            },
            processes: checkpoint.processes.clone(),
            volumes: checkpoint.volumes.clone(),
            mounts: Vec::new(),
            networks: checkpoint.networks.clone(),
            guest_transport: checkpoint.guest_transport.clone(),
            warm_snapshot: checkpoint.warm_snapshot.clone(),
            lifecycle_admission: LifecycleAdmission::Closed,
            routes: Vec::new(),
            platform_guards: 0,
            conditions: Vec::new(),
        };
        (desired, checkpoint, runtime)
    }

    fn add_second_drain_volume(
        desired: &mut DesiredRuntimeSpec,
        checkpoint: &mut RuntimeCheckpoint,
        runtime: &mut ObservedRuntimeStatus,
    ) {
        let mut intent = desired.volumes[0].clone();
        intent.volume_intent_id = Id::new("vint_z_data").unwrap();
        intent.disk_id = Id::new("disk_z_data").unwrap();
        intent.volume_id = Id::new("vol_z_data").unwrap();
        intent.attachment_id = Id::new("att_z_data").unwrap();
        intent.disk_kind = cats_api::runtime_reconciliation::DiskKind::Persistent;
        intent.guest_device.serial = Id::new("cats-data").unwrap();
        intent.guest_device.slot = 1;
        if let VolumeAcquire::Normal { transition_id, .. } = &mut intent.acquire {
            *transition_id = RandomId128::new("99999999999999999999999999999999").unwrap();
        }
        let mut volume = runtime.volumes[0].clone();
        volume.volume_intent_id = Some(intent.volume_intent_id.clone());
        volume.disk_id = Some(intent.disk_id.clone());
        volume.volume_id = intent.volume_id.clone();
        volume.disk_kind = cats_api::runtime_reconciliation::ObservedDiskKind::Persistent;
        let VolumeAuthorityEvidence::Owned { attachment_id, .. } = &mut volume.authority else {
            unreachable!()
        };
        *attachment_id = intent.attachment_id.clone();
        volume.local_lineages[0].attachment_id = intent.attachment_id.clone();
        desired.volumes.push(intent);
        runtime.volumes.push(volume);
        checkpoint.volumes = runtime.volumes.clone();
    }

    fn cold_membership_attach_fixture() -> (
        DesiredRuntimeSpec,
        RuntimeCheckpoint,
        ObservedRuntimeStatus,
        BTreeMap<Id, VolumeRecord>,
    ) {
        let (mut predecessor_desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Cold);
        predecessor_desired.spec_digest = spec_digest(&predecessor_desired).unwrap();
        checkpoint.spec_digest = predecessor_desired.spec_digest.clone();
        checkpoint.runtime_incarnation = None;
        checkpoint.runtime_launch = RuntimeLaunch::Absent;
        checkpoint.stable_state = Some(StableState::Cold);
        checkpoint.step = ReconcileStep::Stable {
            state: StableState::Cold,
        };
        checkpoint.processes.clear();
        checkpoint.mounts.clear();
        checkpoint.networks.clear();
        checkpoint.guest_transport = GuestTransportEvidence::Unavailable;
        checkpoint.warm_snapshot = WarmSnapshotEvidence::Absent;
        checkpoint.lifecycle_admission = LifecycleAdmission::Closed;
        checkpoint.route_gates.clear();
        checkpoint.require_idle = RequireIdleCheckpoint::NotApplicable;

        let root = &mut checkpoint.volumes[0];
        let (owned_epoch, root_head) = match &root.authority {
            VolumeAuthorityEvidence::Owned {
                attachment_epoch,
                head,
                ..
            } => (*attachment_epoch, head.clone()),
            other => panic!("fixture Root is not Owned: {other:?}"),
        };
        let released_epoch = FenceEpoch::new(owned_epoch.get() + 1).unwrap();
        root.authority = VolumeAuthorityEvidence::Unowned {
            attachment_epoch: released_epoch,
            head: root_head.clone(),
        };
        root.devices.clear();
        let [root_lineage] = root.local_lineages.as_mut_slice() else {
            panic!("fixture Root lacks one lineage")
        };
        root_lineage.local_durable_generation = root_head.generation;
        root_lineage.remote_durable_generation = root_head.generation;
        root_lineage.pending_pack_count =
            cats_api::runtime_reconciliation::WireU64::new(0).unwrap();
        root_lineage.fenced = true;
        root_lineage.state = cats_api::runtime_reconciliation::LocalLineageState::Released;

        let mut desired = predecessor_desired.clone();
        desired.desired_revision = cats_api::runtime_reconciliation::Revision::new(
            predecessor_desired.desired_revision.get() + 1,
        )
        .unwrap();
        let blank_head = cats_api::runtime_reconciliation::RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        let persistent = VolumeIntent {
            volume_intent_id: Id::new("vint_z_data").unwrap(),
            disk_id: Id::new("disk_z_data").unwrap(),
            volume_id: Id::new("vol_z_data").unwrap(),
            attachment_id: Id::new("att_z_data").unwrap(),
            size_bytes: 4_294_967_296,
            disk_kind: DiskKind::Persistent,
            access: cats_api::runtime_reconciliation::VolumeAccess::ReadWriteOnce,
            durability: cats_api::runtime_reconciliation::Durability::Strict,
            guest_device: cats_api::runtime_reconciliation::GuestDeviceIdentity {
                serial: Id::new("cats-data").unwrap(),
                slot: 1,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
                expected_unowned_epoch: FenceEpoch::new(1).unwrap(),
            },
            disposition: VolumeDisposition::Retain,
            mount: Some(cats_api::runtime_reconciliation::Ext4MountIntent {
                filesystem_uuid: RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
                mount_path: HostPath::new("/data".to_owned()).unwrap(),
                initialization: FilesystemInitialization::Initialize {
                    initialization_token: RandomId128::new("cccccccccccccccccccccccccccccccc")
                        .unwrap(),
                    expected_blank_head: blank_head.clone(),
                },
            }),
        };
        desired.volumes.push(persistent.clone());
        desired.spec_digest = spec_digest(&desired).unwrap();
        encode_desired_runtime_spec(&desired).unwrap();
        encode_runtime_checkpoint(&checkpoint).unwrap();

        let persistent_observed = ObservedVolume {
            volume_intent_id: Some(persistent.volume_intent_id.clone()),
            disk_id: Some(persistent.disk_id.clone()),
            volume_id: persistent.volume_id.clone(),
            disk_kind: ObservedDiskKind::Persistent,
            size_bytes: Some(persistent.size_bytes),
            durability: Some(persistent.durability),
            authority: VolumeAuthorityEvidence::Unowned {
                attachment_epoch: FenceEpoch::new(1).unwrap(),
                head: blank_head.clone(),
            },
            local_lineages: Vec::new(),
            devices: Vec::new(),
        };
        runtime.applied_desired = Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: RuntimeTarget::Cold,
        });
        runtime.runtime_incarnation = None;
        runtime.stable_state = None;
        runtime.step = checkpoint.step.clone();
        runtime.processes.clear();
        runtime.volumes = checkpoint.volumes.clone();
        runtime.volumes.push(persistent_observed.clone());
        runtime
            .volumes
            .sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
        runtime.mounts.clear();
        runtime.networks.clear();
        runtime.guest_transport = GuestTransportEvidence::Unavailable;
        runtime.warm_snapshot = WarmSnapshotEvidence::Absent;
        runtime.lifecycle_admission = LifecycleAdmission::Closed;
        runtime.routes.clear();
        runtime.platform_guards = 0;
        runtime.conditions = vec![cats_api::runtime_reconciliation::Condition::Progressing {
            reason: cats_api::runtime_reconciliation::ProgressingReason::ReconcileStep {
                step: checkpoint.step.clone(),
            },
        }];

        let mut records = BTreeMap::new();
        records.insert(
            checkpoint.volumes[0].volume_id.clone(),
            VolumeRecord {
                volume_id: checkpoint.volumes[0].volume_id.clone(),
                size_bytes: checkpoint.volumes[0].size_bytes.unwrap(),
                durability: checkpoint.volumes[0].durability.unwrap(),
                admin_state: VolumeAdminState::Active,
                head: root_head.clone(),
                lease_owner: None,
                lease_epoch: released_epoch,
                lease_expires_at: None,
                last_transition: Some(LastVolumeTransition::Release {
                    request: cats_api::runtime_reconciliation::ReleaseRequest {
                        volume_id: checkpoint.volumes[0].volume_id.clone(),
                        transition_id: RandomId128::new("dddddddddddddddddddddddddddddddd")
                            .unwrap(),
                        attachment_id: predecessor_desired.volumes[0].attachment_id.clone(),
                        expected_epoch: owned_epoch,
                    },
                    result: cats_api::runtime_reconciliation::ReleaseResult {
                        volume_id: checkpoint.volumes[0].volume_id.clone(),
                        transition_id: RandomId128::new("dddddddddddddddddddddddddddddddd")
                            .unwrap(),
                        released_attachment_id: predecessor_desired.volumes[0]
                            .attachment_id
                            .clone(),
                        resulting_epoch: released_epoch,
                        resulting_head: root_head,
                    },
                }),
            },
        );
        records.insert(
            persistent.volume_id.clone(),
            VolumeRecord {
                volume_id: persistent.volume_id,
                size_bytes: persistent.size_bytes,
                durability: persistent.durability,
                admin_state: VolumeAdminState::Active,
                head: blank_head,
                lease_owner: None,
                lease_epoch: FenceEpoch::new(1).unwrap(),
                lease_expires_at: None,
                last_transition: None,
            },
        );
        (desired, checkpoint, runtime, records)
    }

    fn detached_cache_cleanup_fixture() -> (
        DesiredRuntimeSpec,
        RuntimeCheckpoint,
        RuntimeCheckpoint,
        ObservedRuntimeStatus,
        VolumeRecord,
    ) {
        let (attached_desired, predecessor, mut runtime, mut records) =
            cold_membership_attach_fixture();
        let observed_at = cats_api::runtime_reconciliation::UnixMillis::new(
            predecessor.updated_at_unix_ms.get() + 1,
        )
        .unwrap();
        let mut stable = cold_membership_rebind_successor(
            &attached_desired,
            &runtime,
            &predecessor,
            observed_at,
        )
        .unwrap();
        let persistent_intent = attached_desired
            .volumes
            .iter()
            .find(|intent| intent.disk_kind == DiskKind::Persistent)
            .unwrap();
        let head = stable
            .volumes
            .iter()
            .find(|volume| volume.disk_kind == ObservedDiskKind::Root)
            .and_then(|volume| match &volume.authority {
                VolumeAuthorityEvidence::Unowned { head, .. } => Some(head.clone()),
                _ => None,
            })
            .unwrap();
        let attachment_epoch = FenceEpoch::new(2).unwrap();
        let released_epoch = FenceEpoch::new(3).unwrap();
        let persistent_index = stable
            .volumes
            .iter()
            .position(|volume| volume.disk_kind == ObservedDiskKind::Persistent)
            .unwrap();
        {
            let persistent = &mut stable.volumes[persistent_index];
            persistent.authority = VolumeAuthorityEvidence::Unowned {
                attachment_epoch: released_epoch,
                head: head.clone(),
            };
            persistent.local_lineages =
                vec![cats_api::runtime_reconciliation::LocalVolumeLineage {
                    attachment_id: persistent_intent.attachment_id.clone(),
                    attachment_epoch,
                    acquire_origin: cats_api::runtime_reconciliation::AcquireOrigin::Normal {
                        transition_id: match &persistent_intent.acquire {
                            VolumeAcquire::Normal { transition_id, .. } => transition_id.clone(),
                            _ => unreachable!(),
                        },
                    },
                    node_id: attached_desired.placement.node_id.clone(),
                    placement_epoch: attached_desired.placement.placement_epoch,
                    local_durable_generation: head.generation,
                    remote_durable_generation: head.generation,
                    data_directory: HostPath::new("/var/lib/cats/cache/data".to_owned()).unwrap(),
                    pending_pack_count: cats_api::runtime_reconciliation::WireU64::new(0).unwrap(),
                    fenced: true,
                    state: cats_api::runtime_reconciliation::LocalLineageState::Released,
                }];
        }
        let persistent = stable.volumes[persistent_index].clone();

        let release_transition = RandomId128::new("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        let record = VolumeRecord {
            volume_id: persistent.volume_id.clone(),
            size_bytes: persistent.size_bytes.unwrap(),
            durability: persistent.durability.unwrap(),
            admin_state: VolumeAdminState::Active,
            head: head.clone(),
            lease_owner: None,
            lease_epoch: released_epoch,
            lease_expires_at: None,
            last_transition: Some(LastVolumeTransition::Release {
                request: cats_api::runtime_reconciliation::ReleaseRequest {
                    volume_id: persistent.volume_id.clone(),
                    transition_id: release_transition.clone(),
                    attachment_id: persistent_intent.attachment_id.clone(),
                    expected_epoch: attachment_epoch,
                },
                result: cats_api::runtime_reconciliation::ReleaseResult {
                    volume_id: persistent.volume_id.clone(),
                    transition_id: release_transition.clone(),
                    released_attachment_id: persistent_intent.attachment_id.clone(),
                    resulting_epoch: released_epoch,
                    resulting_head: head.clone(),
                },
            }),
        };
        records.insert(persistent.volume_id.clone(), record.clone());

        let mut detached = attached_desired.clone();
        detached.desired_revision = cats_api::runtime_reconciliation::Revision::new(
            attached_desired.desired_revision.get() + 1,
        )
        .unwrap();
        detached
            .volumes
            .retain(|intent| intent.disk_kind == DiskKind::Root);
        detached.spec_digest = spec_digest(&detached).unwrap();
        let lineage = persistent.local_lineages[0].clone();
        let mut cleanup = stable.clone();
        cleanup.stable_state = None;
        cleanup.step = ReconcileStep::CleanupRelease {
            cleanup: CleanupRelease {
                target: CleanupTarget::Volume {
                    volume_id: persistent.volume_id.clone(),
                    attachment_id: lineage.attachment_id,
                    attachment_epoch: lineage.attachment_epoch,
                },
                inventory_session: SessionBinding {
                    node_id: detached.placement.node_id.clone(),
                    node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                        "11111111111111111111111111111111",
                    )
                    .unwrap(),
                    agent_instance_id: RandomId128::new("22222222222222222222222222222222")
                        .unwrap(),
                    agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(4).unwrap(),
                },
                inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(5).unwrap(),
                inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(6)
                    .unwrap(),
                desired_read_position: cats_api::runtime_reconciliation::Sequence::new(7).unwrap(),
                volume_release: Some(VolumeReleaseReplay {
                    release_transition_id: release_transition,
                    disposition: VolumeDisposition::DetachRetained,
                    generation: head.generation,
                }),
            },
        };
        cleanup.updated_at_unix_ms =
            cats_api::runtime_reconciliation::UnixMillis::new(stable.updated_at_unix_ms.get() + 1)
                .unwrap();
        encode_runtime_checkpoint(&cleanup).unwrap();
        runtime.applied_desired = Some(AppliedDesiredEvidence {
            desired_revision: detached.desired_revision,
            spec_digest: detached.spec_digest.clone(),
            placement: detached.placement.clone(),
            target: RuntimeTarget::Cold,
        });
        runtime.step = cleanup.step.clone();
        runtime.stable_state = None;
        runtime.volumes = cleanup.volumes.clone();
        (detached, stable, cleanup, runtime, record)
    }

    fn exact_drain_receipt(
        desired: &DesiredRuntimeSpec,
        runtime: &ObservedRuntimeStatus,
    ) -> DrainPublishReceipt {
        let mut ordered = desired.volumes.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|intent| intent.guest_device.slot);
        DrainPublishReceipt {
            volumes: ordered
                .into_iter()
                .map(|intent| {
                    let ReconcileStep::DrainPublish {
                        volume_id,
                        attachment_epoch,
                        local_generation,
                        ..
                    } = drain_step_for_intent(desired, runtime, intent).unwrap()
                    else {
                        unreachable!()
                    };
                    DrainedVolumeReceipt {
                        volume_id,
                        attachment_epoch,
                        local_generation,
                        remote_generation: local_generation,
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn cold_membership_rebind_is_exact_for_attach_then_detach() {
        let (desired, checkpoint, mut runtime, records) = cold_membership_attach_fixture();
        assert!(cold_membership_rebind_is_supported(
            &desired,
            &checkpoint,
            &runtime.volumes
        ));
        for observed in &runtime.volumes {
            assert!(record_matches_exact_unowned_observation(
                records.get(&observed.volume_id).unwrap(),
                observed
            ));
        }
        let observed_at = cats_api::runtime_reconciliation::UnixMillis::new(
            checkpoint.updated_at_unix_ms.get() + 1,
        )
        .unwrap();
        let attached =
            cold_membership_rebind_successor(&desired, &runtime, &checkpoint, observed_at).unwrap();
        assert!(current_cold_checkpoint_postcondition_is_exact(
            &desired,
            &attached,
            &attached.volumes
        ));
        let added = attached
            .volumes
            .iter()
            .find(|volume| volume.disk_kind == ObservedDiskKind::Persistent)
            .unwrap();
        assert!(added.local_lineages.is_empty());
        assert!(added.devices.is_empty());

        let mut detached_desired = desired.clone();
        detached_desired.desired_revision =
            cats_api::runtime_reconciliation::Revision::new(desired.desired_revision.get() + 1)
                .unwrap();
        detached_desired
            .volumes
            .retain(|intent| intent.disk_kind == DiskKind::Root);
        detached_desired.spec_digest = spec_digest(&detached_desired).unwrap();
        runtime.applied_desired = Some(AppliedDesiredEvidence {
            desired_revision: detached_desired.desired_revision,
            spec_digest: detached_desired.spec_digest.clone(),
            placement: detached_desired.placement.clone(),
            target: RuntimeTarget::Cold,
        });
        assert!(cold_membership_rebind_is_supported(
            &detached_desired,
            &attached,
            &runtime.volumes
        ));
        let detached = cold_membership_rebind_successor(
            &detached_desired,
            &runtime,
            &attached,
            cats_api::runtime_reconciliation::UnixMillis::new(observed_at.get() + 1).unwrap(),
        )
        .unwrap();
        assert_eq!(detached.volumes.len(), 1);
        assert_eq!(detached.volumes[0].disk_kind, ObservedDiskKind::Root);
        assert!(
            records.contains_key(&added.volume_id),
            "detach retains Volume data"
        );
    }

    #[test]
    fn cold_membership_rebind_rejects_stale_epoch_owner_aba_and_set_drift() {
        let (desired, checkpoint, runtime, mut records) = cold_membership_attach_fixture();

        let mut stale_epoch = runtime.clone();
        let added = stale_epoch
            .volumes
            .iter_mut()
            .find(|volume| volume.disk_kind == ObservedDiskKind::Persistent)
            .unwrap();
        let VolumeAuthorityEvidence::Unowned {
            attachment_epoch, ..
        } = &mut added.authority
        else {
            unreachable!()
        };
        *attachment_epoch = FenceEpoch::new(attachment_epoch.get() + 1).unwrap();
        assert!(!cold_membership_rebind_is_supported(
            &desired,
            &checkpoint,
            &stale_epoch.volumes
        ));

        let mut predecessor_aba = runtime.clone();
        let root = predecessor_aba
            .volumes
            .iter_mut()
            .find(|volume| volume.disk_kind == ObservedDiskKind::Root)
            .unwrap();
        let VolumeAuthorityEvidence::Unowned {
            attachment_epoch, ..
        } = &mut root.authority
        else {
            unreachable!()
        };
        *attachment_epoch = FenceEpoch::new(attachment_epoch.get() + 2).unwrap();
        assert!(!cold_membership_rebind_is_supported(
            &desired,
            &checkpoint,
            &predecessor_aba.volumes
        ));

        let persistent = runtime
            .volumes
            .iter()
            .find(|volume| volume.disk_kind == ObservedDiskKind::Persistent)
            .unwrap();
        let record = records.get_mut(&persistent.volume_id).unwrap();
        record.lease_owner = Some(Id::new("att_aba").unwrap());
        record.lease_epoch = FenceEpoch::new(record.lease_epoch.get() + 1).unwrap();
        record.lease_expires_at =
            Some(cats_api::runtime_reconciliation::UnixMillis::new(1_900_000_060_000).unwrap());
        assert!(!record_matches_exact_unowned_observation(
            record, persistent
        ));

        let mut two_changes = desired.clone();
        two_changes.volumes[0].volume_intent_id = Id::new("replaced_root_intent").unwrap();
        two_changes.spec_digest = spec_digest(&two_changes).unwrap();
        assert!(!cold_membership_rebind_is_supported(
            &two_changes,
            &checkpoint,
            &runtime.volumes
        ));
    }

    #[test]
    fn cold_membership_checkpoint_adopts_atomically_across_every_crash_point() {
        for stage in [
            WriteStage::Write,
            WriteStage::TempWritten,
            WriteStage::FileSynced,
            WriteStage::Renamed,
            WriteStage::DirectorySynced,
        ] {
            let (desired, predecessor, runtime, _) = cold_membership_attach_fixture();
            let successor = cold_membership_rebind_successor(
                &desired,
                &runtime,
                &predecessor,
                cats_api::runtime_reconciliation::UnixMillis::new(
                    predecessor.updated_at_unix_ms.get() + 1,
                )
                .unwrap(),
            )
            .unwrap();
            let directory = TempDir::new().unwrap();
            let store = FileCheckpointStore::open(directory.path(), &predecessor.cat_id).unwrap();
            let stored = store.create(&predecessor).unwrap();
            let context = RuntimeDesiredEffectContext::for_test(
                crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            );
            let current = store.assert_current(&stored).unwrap();
            store.inject_crash_once(stage);
            assert!(persist_lifecycle_successor(
                &context,
                &store,
                &stored,
                &successor,
                &current,
                "test Cold membership checkpoint crash",
            )
            .is_err());
            drop(current);
            drop(store);

            let reopened =
                FileCheckpointStore::open(directory.path(), &predecessor.cat_id).unwrap();
            let recovered = reopened.load().unwrap().unwrap();
            if recovered.checkpoint() == &predecessor {
                reopened.replace(&recovered, &successor).unwrap();
            } else {
                assert_eq!(recovered.checkpoint(), &successor);
            }
            let adopted = reopened.load().unwrap().unwrap();
            assert_eq!(
                adopted.checkpoint(),
                &successor,
                "restart failed at {stage:?}"
            );
            assert!(current_cold_checkpoint_postcondition_is_exact(
                &desired,
                adopted.checkpoint(),
                &successor.volumes
            ));
        }
    }

    #[test]
    fn cold_detach_cache_uses_typed_cleanup_before_membership_cas() {
        let (desired, _stable, cleanup, mut runtime, record) = detached_cache_cleanup_fixture();
        assert!(cold_membership_detach_cleanup_checkpoint_is_supported(
            &desired, &cleanup
        ));
        assert!(cold_membership_detach_cleanup_is_supported(
            &desired,
            &cleanup,
            &runtime.volumes
        ));
        let target = cold_membership_cleanup_target(&cleanup).unwrap().clone();
        let checkpointed = cleanup
            .volumes
            .iter()
            .find(|volume| volume.volume_id == target)
            .unwrap();
        assert!(released_cache_record_matches_checkpoint(
            &record,
            checkpointed
        ));
        assert!(released_cache_record_matches_cleanup_checkpoint(
            &record, &cleanup
        ));

        runtime
            .volumes
            .iter_mut()
            .find(|volume| volume.volume_id == target)
            .unwrap()
            .local_lineages
            .clear();
        assert!(cold_membership_detach_cleanup_is_supported(
            &desired,
            &cleanup,
            &runtime.volumes
        ));
        let successor = cold_membership_detach_completion_successor(
            &desired,
            &runtime,
            &cleanup,
            cats_api::runtime_reconciliation::UnixMillis::new(cleanup.updated_at_unix_ms.get() + 1)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(successor.volumes.len(), desired.volumes.len());
        assert!(successor
            .volumes
            .iter()
            .all(|volume| volume.volume_id != target));
        assert!(current_cold_checkpoint_postcondition_is_exact(
            &desired,
            &successor,
            &successor.volumes
        ));
    }

    #[test]
    fn cold_detach_cache_rejects_owner_epoch_head_aba_and_foreign_lineage() {
        let (desired, _stable, cleanup, runtime, record) = detached_cache_cleanup_fixture();
        let target = cold_membership_cleanup_target(&cleanup).unwrap();
        let checkpointed = cleanup
            .volumes
            .iter()
            .find(|volume| &volume.volume_id == target)
            .unwrap();

        let mut owner = record.clone();
        owner.lease_owner = Some(Id::new("att_foreign").unwrap());
        owner.lease_expires_at =
            Some(cats_api::runtime_reconciliation::UnixMillis::new(1_900_000_000_000).unwrap());
        assert!(!released_cache_record_matches_checkpoint(
            &owner,
            checkpointed
        ));

        let mut epoch_aba = record.clone();
        epoch_aba.lease_epoch = FenceEpoch::new(record.lease_epoch.get() + 2).unwrap();
        assert!(!released_cache_record_matches_checkpoint(
            &epoch_aba,
            checkpointed
        ));

        let mut head_aba = record.clone();
        head_aba.head.root_hash = Some(
            cats_api::runtime_reconciliation::Sha256Digest::new(format!(
                "sha256:{}",
                "f".repeat(64)
            ))
            .unwrap(),
        );
        assert!(!released_cache_record_matches_checkpoint(
            &head_aba,
            checkpointed
        ));

        let mut foreign = cleanup.clone();
        let volume = foreign
            .volumes
            .iter_mut()
            .find(|volume| &volume.volume_id == target)
            .unwrap();
        volume.local_lineages[0].attachment_id = Id::new("att_foreign").unwrap();
        assert!(!cold_membership_detach_cleanup_checkpoint_is_supported(
            &desired, &foreign
        ));

        let mut relaxed_tail = cleanup.clone();
        let volume = relaxed_tail
            .volumes
            .iter_mut()
            .find(|volume| &volume.volume_id == target)
            .unwrap();
        volume.local_lineages[0].remote_durable_generation =
            Generation::new(volume.local_lineages[0].local_durable_generation.get() - 1).unwrap();
        assert!(!cold_membership_detach_cleanup_checkpoint_is_supported(
            &desired,
            &relaxed_tail
        ));

        let mut substituted_release = cleanup.clone();
        let ReconcileStep::CleanupRelease {
            cleanup: cleanup_step,
        } = &mut substituted_release.step
        else {
            unreachable!()
        };
        cleanup_step
            .volume_release
            .as_mut()
            .unwrap()
            .release_transition_id = RandomId128::new("abababababababababababababababab").unwrap();
        assert!(!released_cache_record_matches_cleanup_checkpoint(
            &record,
            &substituted_release
        ));

        let mut duplicate_checkpoint_member = cleanup.clone();
        let duplicate_target = checkpointed.clone();
        *duplicate_checkpoint_member
            .volumes
            .iter_mut()
            .find(|volume| volume.disk_kind == ObservedDiskKind::Root)
            .unwrap() = duplicate_target;
        assert!(!cold_membership_detach_cleanup_checkpoint_is_supported(
            &desired,
            &duplicate_checkpoint_member
        ));

        let mut duplicate_residue_projection = runtime;
        duplicate_residue_projection
            .volumes
            .push(checkpointed.clone());
        assert!(!cold_membership_detach_cleanup_is_supported(
            &desired,
            &cleanup,
            &duplicate_residue_projection.volumes
        ));
    }

    #[test]
    fn cold_detach_cache_cleanup_and_final_membership_are_atomic_at_every_crash_point() {
        for stage in [
            WriteStage::Write,
            WriteStage::TempWritten,
            WriteStage::FileSynced,
            WriteStage::Renamed,
            WriteStage::DirectorySynced,
        ] {
            let (desired, stable, cleanup, mut runtime, _) = detached_cache_cleanup_fixture();
            let directory = TempDir::new().unwrap();
            let store = FileCheckpointStore::open(directory.path(), &stable.cat_id).unwrap();
            let stored = store.create(&stable).unwrap();
            let context = RuntimeDesiredEffectContext::for_test(
                crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            );
            let current = store.assert_current(&stored).unwrap();
            store.inject_crash_once(stage);
            assert!(persist_lifecycle_successor(
                &context,
                &store,
                &stored,
                &cleanup,
                &current,
                "test typed Cold detach cleanup crash",
            )
            .is_err());
            drop(current);
            drop(store);
            let reopened = FileCheckpointStore::open(directory.path(), &stable.cat_id).unwrap();
            let recovered = reopened.load().unwrap().unwrap();
            if recovered.checkpoint() == &stable {
                reopened.replace(&recovered, &cleanup).unwrap();
            } else {
                assert_eq!(recovered.checkpoint(), &cleanup);
            }

            let target = cold_membership_cleanup_target(&cleanup).unwrap();
            runtime
                .volumes
                .iter_mut()
                .find(|volume| &volume.volume_id == target)
                .unwrap()
                .local_lineages
                .clear();
            let successor = cold_membership_detach_completion_successor(
                &desired,
                &runtime,
                &cleanup,
                cats_api::runtime_reconciliation::UnixMillis::new(
                    cleanup.updated_at_unix_ms.get() + 1,
                )
                .unwrap(),
            )
            .unwrap();
            let stored_cleanup = reopened.load().unwrap().unwrap();
            reopened.inject_crash_once(stage);
            assert!(reopened.replace(&stored_cleanup, &successor).is_err());
            drop(reopened);
            let final_store = FileCheckpointStore::open(directory.path(), &stable.cat_id).unwrap();
            let recovered = final_store.load().unwrap().unwrap();
            if recovered.checkpoint() == &cleanup {
                final_store.replace(&recovered, &successor).unwrap();
            } else {
                assert_eq!(recovered.checkpoint(), &successor);
            }
            assert!(current_cold_checkpoint_postcondition_is_exact(
                &desired,
                final_store.load().unwrap().unwrap().checkpoint(),
                &successor.volumes
            ));
        }
    }

    fn disposable_evidence_fixture() -> (
        DesiredRuntimeSpec,
        cats_api::runtime_reconciliation::VolumeIntent,
        RuntimeVolumeTransitionEvidenceRequest,
        cats_api::runtime_reconciliation::FenceEpoch,
        cats_api::runtime_reconciliation::RemoteHead,
        VolumeEvidenceRecovery,
    ) {
        let (mut desired, _, runtime) = fixtures(RuntimeTarget::Deleted);
        let delete_id = Id::new("delete_root_exact").unwrap();
        desired.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
            delete_id: delete_id.clone(),
        };
        let intent = desired.volumes[0].clone();
        let authorization_id = Id::new("delete_authorization_exact").unwrap();
        let (expected_epoch, expected_head) = match &runtime.volumes[0].authority {
            VolumeAuthorityEvidence::Owned {
                attachment_epoch,
                head,
                ..
            } => (*attachment_epoch, head.clone()),
            _ => panic!("fixture Root is not Owned"),
        };
        let resulting_epoch =
            cats_api::runtime_reconciliation::FenceEpoch::new(expected_epoch.get() + 1).unwrap();
        let session = SessionBinding {
            node_id: desired.placement.node_id.clone(),
            node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                "11111111111111111111111111111111".to_owned(),
            )
            .unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(3).unwrap(),
        };
        let request = RuntimeVolumeTransitionEvidenceRequest {
            version: ContractVersion::V1,
            session: session.clone(),
            authorization_id: authorization_id.clone(),
        };
        let receipt = cats_api::runtime_reconciliation::BeginDisposableDeleteConsumedReceipt {
            authorization_id: authorization_id.clone(),
            volume_id: intent.volume_id.clone(),
            disk_id: intent.disk_id.clone(),
            cat_id: desired.cat_id.clone(),
            delete_id: delete_id.clone(),
            prior_attachment_id: intent.attachment_id.clone(),
            resulting_epoch,
            resulting_head: expected_head.clone(),
            consumed_at: cats_api::runtime_reconciliation::UnixMillis::new(1_900_000_000_100)
                .unwrap(),
        };
        let authorization = cats_api::runtime_reconciliation::DisposableRootDeleteAuthorization {
            authorization_id: authorization_id.clone(),
            authorized_node_id: desired.placement.node_id.clone(),
            delete_id: delete_id.clone(),
            disk_id: intent.disk_id.clone(),
            volume_id: intent.volume_id.clone(),
            cat_id: desired.cat_id.clone(),
            desired_revision: desired.desired_revision,
            placement_epoch: desired.placement.placement_epoch,
            expected_attachment_id: intent.attachment_id.clone(),
            expected_epoch,
            expected_head: expected_head.clone(),
            isolation_basis:
                cats_api::runtime_reconciliation::DisposableDeleteIsolationBasis::RuntimeStopped {
                    node_id: desired.placement.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    runtime_incarnation: RandomId128::new("33333333333333333333333333333333")
                        .unwrap(),
                    observation_id: RandomId128::new("44444444444444444444444444444444").unwrap(),
                },
            not_after: cats_api::runtime_reconciliation::UnixMillis::new(1_900_000_060_000)
                .unwrap(),
        };
        let current = cats_api::runtime_reconciliation::VolumeRecord {
            volume_id: intent.volume_id.clone(),
            size_bytes: intent.size_bytes,
            durability: intent.durability,
            admin_state: VolumeAdminState::Deleting {
                delete_id: delete_id.clone(),
            },
            head: expected_head.clone(),
            lease_owner: None,
            lease_epoch: resulting_epoch,
            lease_expires_at: None,
            last_transition: Some(LastVolumeTransition::BeginDisposableDelete {
                authorization_id: authorization_id.clone(),
            }),
        };
        let evidence = cats_api::runtime_reconciliation::RuntimeVolumeTransitionEvidenceSuccess {
            version: ContractVersion::V1,
            session,
            authorization_id,
            authorization: cats_api::runtime_reconciliation::AuthorizationRecord {
                authorization: VolumeAuthorization::DisposableRootDelete(authorization),
                state: AuthorizationState::Consumed(Box::new(
                    AuthorizationConsumedReceipt::BeginDisposableDelete(receipt.clone()),
                )),
            },
            current_volume: Some(current),
            delete_completion: None,
            direct_successor_authorization: None,
        };
        (
            desired,
            intent,
            request,
            expected_epoch,
            expected_head,
            VolumeEvidenceRecovery::Validated {
                evidence: Box::new(evidence),
                decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptDisposableDeleting(
                    receipt,
                )),
            },
        )
    }

    fn unconsumed_disposable_evidence_fixture() -> (
        DesiredRuntimeSpec,
        cats_api::runtime_reconciliation::VolumeIntent,
        RuntimeVolumeTransitionEvidenceRequest,
        cats_api::runtime_reconciliation::FenceEpoch,
        cats_api::runtime_reconciliation::RemoteHead,
        VolumeEvidenceRecovery,
    ) {
        let (desired, intent, request, expected_epoch, expected_head, mut recovery) =
            disposable_evidence_fixture();
        let VolumeEvidenceRecovery::Validated { evidence, decision } = &mut recovery else {
            unreachable!()
        };
        evidence.authorization.state = AuthorizationState::Unconsumed;
        **decision = VolumeEvidenceRecoveryDecision::RetryOriginalAuthorization {
            authorization_id: request.authorization_id.clone(),
        };
        let current = evidence.current_volume.as_mut().unwrap();
        current.admin_state = VolumeAdminState::Active;
        current.lease_owner = Some(intent.attachment_id.clone());
        current.lease_epoch = expected_epoch;
        let lease_expires_at =
            cats_api::runtime_reconciliation::UnixMillis::new(1_900_000_120_000).unwrap();
        current.lease_expires_at = Some(lease_expires_at);
        current.last_transition = Some(match &intent.acquire {
            VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            } => LastVolumeTransition::NormalAcquire {
                request: cats_api::runtime_reconciliation::NormalAcquireRequest {
                    volume_id: intent.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: intent.attachment_id.clone(),
                    expected_unowned_epoch: *expected_unowned_epoch,
                    desired_revision: desired.desired_revision,
                    placement_epoch: desired.placement.placement_epoch,
                    lease_duration_ms: 60_000,
                },
                result: cats_api::runtime_reconciliation::NormalAcquireResult {
                    volume_id: intent.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: intent.attachment_id.clone(),
                    resulting_epoch: expected_epoch,
                    resulting_head: expected_head.clone(),
                    lease_expires_at,
                },
            },
            VolumeAcquire::Takeover { authorization_id } => LastVolumeTransition::Takeover {
                authorization_id: authorization_id.clone(),
            },
        });
        (
            desired,
            intent,
            request,
            expected_epoch,
            expected_head,
            recovery,
        )
    }

    struct ScriptedLifecycleVolumePort {
        recovery: Mutex<Option<VolumeEvidenceRecovery>>,
        evidence_calls: AtomicUsize,
        delete_calls: AtomicUsize,
        delete_attempts: Mutex<VecDeque<DisposableRootDeleteAttempt>>,
        delete_authorization_ids: Mutex<Vec<Id>>,
    }

    impl SignedLifecycleVolumePort for ScriptedLifecycleVolumePort {
        fn release(
            &self,
            _request: &RuntimeVolumeTransitionRequest,
            _volume: &cats_api::runtime_reconciliation::VolumeIntent,
            _expected_head: &cats_api::runtime_reconciliation::RemoteHead,
            _accepted: &NormalAcquireAcceptedContext,
            _deadline: std::time::Instant,
        ) -> Result<NormalReleaseAttempt, super::super::NormalAcquireClientError> {
            panic!("Deleting evidence test must not release a Volume")
        }

        fn delete_disposable_root(
            &self,
            request: &RuntimeVolumeTransitionRequest,
            _volume: &cats_api::runtime_reconciliation::VolumeIntent,
            _expected_epoch: cats_api::runtime_reconciliation::FenceEpoch,
            _expected_head: &cats_api::runtime_reconciliation::RemoteHead,
            _accepted: &NormalAcquireAcceptedContext,
            _deadline: std::time::Instant,
        ) -> Result<DisposableRootDeleteAttempt, super::super::NormalAcquireClientError> {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            let RuntimeVolumeTransition::DeleteDisposableRoot { authorization_id } =
                &request.transition
            else {
                panic!("Deleting evidence test received a non-delete transition")
            };
            self.delete_authorization_ids
                .lock()
                .unwrap()
                .push(authorization_id.clone());
            Ok(self
                .delete_attempts
                .lock()
                .unwrap()
                .pop_front()
                .expect("Deleting evidence test exhausted its attempt script"))
        }

        fn recover_authorization(
            &self,
            _request: &RuntimeVolumeTransitionEvidenceRequest,
            _deadline: std::time::Instant,
        ) -> Result<VolumeEvidenceRecovery, super::super::VolumeEvidenceClientError> {
            self.evidence_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.recovery.lock().unwrap().take().unwrap())
        }
    }

    struct NeverLifecyclePhysical;

    impl LifecyclePhysicalPort for NeverLifecyclePhysical {
        fn apply(
            &self,
            _context: &RuntimeDesiredEffectContext,
            _permit: LifecycleEffectPermit<'_>,
        ) -> anyhow::Result<LifecyclePhysicalAttempt> {
            panic!("Deleting evidence must not reach a physical adapter")
        }
    }

    struct RecordingKernelNbdDetach {
        calls: Mutex<Vec<(Id, Id, RandomId128)>>,
    }

    impl super::super::kernel_nbd::detach_port_sealed::Sealed for RecordingKernelNbdDetach {}

    impl KernelNbdDetachPort for RecordingKernelNbdDetach {
        fn detach_checkpointed(
            &self,
            volume_id: &Id,
            ownership_token: &RandomId128,
            _store: &FileCheckpointStore,
            stored: &StoredCheckpoint,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<KernelNbdDetachResult> {
            self.calls.lock().unwrap().push((
                stored.checkpoint().cat_id.clone(),
                volume_id.clone(),
                ownership_token.clone(),
            ));
            Ok(KernelNbdDetachResult::SubmittedOrAmbiguous)
        }
    }

    struct UnavailableVolumeAuthority;

    impl VolumeDataAuthority for UnavailableVolumeAuthority {
        fn load_volume(
            &self,
            _volume_id: &Id,
        ) -> cats_storage::authority::Result<cats_storage::authority::VolumeRecord> {
            Err(cats_storage::authority::AuthorityError::BackendUnknown)
        }

        fn renew_lease(
            &self,
            _request: &cats_storage::authority::RenewLeaseRequest,
        ) -> cats_storage::authority::Result<cats_storage::authority::RenewLeaseResult> {
            Err(cats_storage::authority::AuthorityError::BackendUnknown)
        }

        fn compare_and_swap_head(
            &self,
            _request: &cats_storage::authority::VolumeHeadCasRequest,
        ) -> cats_storage::authority::Result<cats_storage::authority::VolumeHeadCasResult> {
            Err(cats_storage::authority::AuthorityError::BackendUnknown)
        }
    }

    struct VhostCleanupServingPort {
        retirements: Mutex<VecDeque<ManagedBlockdSocketOwnerRetirement>>,
    }

    impl serving_process_sealed::Sealed for VhostCleanupServingPort {}
    impl serving_global_sealed::Sealed for VhostCleanupServingPort {}

    impl ServingBlockdProcessPort for VhostCleanupServingPort {
        fn inspect(
            &self,
            _expected: &ServingBlockdExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<ServingBlockdProcessInspection> {
            Ok(ServingBlockdProcessInspection::Absent)
        }

        fn start_checkpointed(
            &self,
            _checkpointed: CheckpointedServingBlockdProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<ServingBlockdProcessStart> {
            panic!("vhost cleanup regression must not start blockd")
        }
    }

    impl ServingBlockdProcessGlobalPort for VhostCleanupServingPort {
        fn inspect_serving_exact_or_absent_after_node_global_sweep(
            &self,
            _expected: &ServingBlockdExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<ServingBlockdProcessInspection> {
            Ok(ServingBlockdProcessInspection::Absent)
        }

        fn retire_absent_socket_owner(
            &self,
            _expected: &ServingBlockdExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<ManagedBlockdSocketOwnerRetirement> {
            Ok(self
                .retirements
                .lock()
                .unwrap()
                .pop_front()
                .expect("vhost cleanup regression exhausted retirement outcomes"))
        }
    }

    struct NeverVmmProcessPort;

    impl vmm_process_sealed::Sealed for NeverVmmProcessPort {}
    impl vmm_global_sealed::Sealed for NeverVmmProcessPort {}

    impl VmmProcessPort for NeverVmmProcessPort {
        fn inspect(
            &self,
            _expected: &super::super::vmm_process::VmmProcessExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<VmmProcessInspection> {
            Ok(VmmProcessInspection::Unavailable)
        }

        fn start_checkpointed(
            &self,
            _checkpointed: CheckpointedVmmProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<VmmProcessStart> {
            panic!("vhost cleanup regression must not start a VMM")
        }
    }

    impl super::super::vmm_process::VmmProcessGlobalPort for NeverVmmProcessPort {
        fn inspect_vmm_exact_or_absent_after_node_global_sweep(
            &self,
            _expected: &super::super::vmm_process::VmmProcessExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<VmmProcessGlobalInspection> {
            Ok(VmmProcessGlobalInspection::Unavailable)
        }

        fn inspect_vmm_gate_successor_exact_after_node_global_sweep(
            &self,
            _admitted_predecessor: &super::super::vmm_process::ExactVmmProcessProof,
            _successor: &VmmGateSuccessorProof,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<VmmProcessGlobalInspection> {
            Ok(VmmProcessGlobalInspection::Unavailable)
        }
    }

    fn deleting_effect_context(
        directory: &TempDir,
        desired: &DesiredRuntimeSpec,
        runtime: ObservedRuntimeStatus,
    ) -> RuntimeDesiredEffectContext {
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: desired.placement.node_id.clone(),
            immutable_host_id: Id::new("host_exact_delete").unwrap(),
            node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                "11111111111111111111111111111111".to_owned(),
            )
            .unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(3).unwrap(),
            registration_attempt_id: RandomId128::new("55555555555555555555555555555555").unwrap(),
            guest_config_digest: desired.runtime.guest_config_digest.clone(),
            lease_deadline_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(
                1_900_000_120_000,
            )
            .unwrap(),
        };
        let read_position = cats_api::runtime_reconciliation::Sequence::new(9).unwrap();
        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("44444444444444444444444444444444").unwrap(),
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: cats_api::runtime_reconciliation::Sequence::new(8).unwrap(),
            observed_at_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(
                1_900_000_000_000,
            )
            .unwrap(),
            complete_inventory: true,
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(7).unwrap(),
            inventory_digest: Some(cats_api::runtime_reconciliation::Sha256Digest::from_bytes(
                [0; 32],
            )),
            inventory_read_position: Some(read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: vec![runtime],
            residue: Vec::new(),
        };
        observation.inventory_digest =
            Some(cats_api::runtime_reconciliation::inventory_digest(&observation).unwrap());
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest: observation.inventory_digest.clone().unwrap(),
            inventory_read_position: read_position,
            accepted_at_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(
                1_900_000_000_100,
            )
            .unwrap(),
        };
        let snapshot = DesiredReadSnapshot {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: session.node_id.clone(),
                node_boot_id: session.node_boot_id.clone(),
                agent_instance_id: session.agent_instance_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
            },
            request_sequence: read_position,
            read_position,
            issued_at_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(1_900_000_000_000)
                .unwrap(),
            expires_at_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(
                1_900_000_120_000,
            )
            .unwrap(),
            desired_specs: vec![desired.clone()],
        };
        let admission = crate::runtime_spine::RuntimeDesiredEffectAdmission::for_test(
            session,
            observation,
            attestation,
        )
        .bind_assigned_cats_for_test(&snapshot);
        RuntimeDesiredEffectContext::for_test_with_admission(
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            admission,
        )
    }

    #[test]
    fn disabled_suspended_paths_stop_before_physical_effects() {
        let (desired, _, _) = fixtures(RuntimeTarget::Suspended);
        let volume = Arc::new(ScriptedLifecycleVolumePort {
            recovery: Mutex::new(None),
            evidence_calls: AtomicUsize::new(0),
            delete_calls: AtomicUsize::new(0),
            delete_attempts: Mutex::new(VecDeque::new()),
            delete_authorization_ids: Mutex::new(Vec::new()),
        });
        let effect = LifecycleStepEffect {
            credentials: None,
            physical: Arc::new(NeverLifecyclePhysical),
            volume_transition: Arc::clone(&volume) as Arc<dyn SignedLifecycleVolumePort>,
            volume_authority: Arc::new(UnavailableVolumeAuthority),
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim: None,
        };
        let directory = TempDir::new().unwrap();
        let context = RuntimeDesiredEffectContext::for_test(
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );

        assert_eq!(
            effect.try_apply(&context, &desired).unwrap(),
            Some(stop_local())
        );
        assert_eq!(volume.evidence_calls.load(Ordering::SeqCst), 0);
        assert_eq!(volume.delete_calls.load(Ordering::SeqCst), 0);
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none());

        let (running, mut checkpoint, mut suspended) = fixtures(RuntimeTarget::Running);
        checkpoint.stable_state = Some(StableState::Suspended);
        checkpoint.step = ReconcileStep::Stable {
            state: StableState::Suspended,
        };
        checkpoint.processes[0].state = ProcessState::Paused;
        suspended.applied_desired = Some(AppliedDesiredEvidence {
            desired_revision: running.desired_revision,
            spec_digest: running.spec_digest.clone(),
            placement: running.placement.clone(),
            target: running.target,
        });
        suspended.stable_state = checkpoint.stable_state;
        suspended.step = checkpoint.step.clone();
        suspended.processes = checkpoint.processes.clone();
        suspended.checkpoint = CheckpointEvidence::Valid {
            checkpoint_path: HostPath::new("/var/lib/cats/suspended-disabled.json".to_owned())
                .unwrap(),
            content_digest: cats_api::runtime_reconciliation::Sha256Digest::from_bytes([0x51; 32]),
            version: checkpoint.version,
            cat_id: checkpoint.cat_id.clone(),
            node_id: checkpoint.node_id.clone(),
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            placement_epoch: checkpoint.placement_epoch,
            runtime_incarnation: checkpoint.runtime_incarnation.clone(),
            runtime_launch: Box::new(checkpoint.runtime_launch.clone()),
            stable_state: checkpoint.stable_state,
            step: Box::new(checkpoint.step.clone()),
            require_idle: Box::new(checkpoint.require_idle.clone()),
            updated_at_unix_ms: checkpoint.updated_at_unix_ms,
        };
        let resume_directory = TempDir::new().unwrap();
        let resume_context = deleting_effect_context(&resume_directory, &running, suspended);
        assert_eq!(
            effect.try_apply(&resume_context, &running).unwrap(),
            Some(stop_local())
        );
        assert_eq!(volume.evidence_calls.load(Ordering::SeqCst), 0);
        assert_eq!(volume.delete_calls.load(Ordering::SeqCst), 0);
        assert!(std::fs::read_dir(resume_directory.path())
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn r_equals_l_still_requires_drain_before_any_stop() {
        for target in [RuntimeTarget::Cold, RuntimeTarget::Deleted] {
            let (desired, _, runtime) = fixtures(target);
            let lineage = &runtime.volumes[0].local_lineages[0];
            assert_eq!(
                lineage.local_durable_generation, lineage.remote_durable_generation,
                "regression control must start from accepted R == L"
            );
            assert!(matches!(
                first_lifecycle_step(&desired, &runtime).unwrap(),
                Some(ReconcileStep::DrainPublish {
                    ref volume_id,
                    local_generation,
                    remote_generation,
                    ..
                }) if volume_id == &runtime.volumes[0].volume_id
                    && local_generation == lineage.local_durable_generation
                    && remote_generation == lineage.remote_durable_generation
            ));
        }
    }

    #[test]
    fn explicit_disposable_only_delete_stops_without_forging_a_guest_drain() {
        let (mut desired, _, runtime) = fixtures(RuntimeTarget::Deleted);
        desired.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
            delete_id: Id::new("delete_disposable_root").unwrap(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let process = exact_vmm_process(&runtime).unwrap();
        assert!(matches!(
            first_lifecycle_step(&desired, &runtime).unwrap(),
            Some(ReconcileStep::StopRuntime {
                ref runtime_incarnation,
                process_start_time_ticks,
                ref scope_id,
            }) if Some(runtime_incarnation) == runtime.runtime_incarnation.as_ref()
                && process_start_time_ticks == process.process_start_time_ticks
                && scope_id == &process.scope_id
        ));

        let (mut retained, mut checkpoint, mut retained_runtime) = fixtures(RuntimeTarget::Deleted);
        retained.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
            delete_id: Id::new("delete_disposable_root").unwrap(),
        };
        add_second_drain_volume(&mut retained, &mut checkpoint, &mut retained_runtime);
        retained.volumes[1].disposition = VolumeDisposition::DetachRetained;
        retained.volumes[1].mount = Some(cats_api::runtime_reconciliation::Ext4MountIntent {
            filesystem_uuid: RandomId128::new("abababababababababababababababab").unwrap(),
            mount_path: HostPath::new("/data".to_owned()).unwrap(),
            initialization: FilesystemInitialization::Existing,
        });
        retained.spec_digest = spec_digest(&retained).unwrap();
        assert!(matches!(
            first_lifecycle_step(&retained, &retained_runtime).unwrap(),
            Some(ReconcileStep::DrainPublish { .. })
        ));
    }

    #[test]
    fn cleanup_execution_accepts_later_scan_in_same_session_without_rebind_livelock() {
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: Id::new("node_cleanup_freshness").unwrap(),
            immutable_host_id: Id::new("host_cleanup_freshness").unwrap(),
            node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                "11111111111111111111111111111111",
            )
            .unwrap(),
            agent_instance_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
            agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(3).unwrap(),
            registration_attempt_id: RandomId128::new("33333333333333333333333333333333").unwrap(),
            guest_config_digest: cats_api::runtime_reconciliation::Sha256Digest::from_bytes(
                [0x44; 32],
            ),
            lease_deadline_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(
                1_900_000_120_000,
            )
            .unwrap(),
        };
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(7).unwrap(),
            inventory_digest: cats_api::runtime_reconciliation::Sha256Digest::from_bytes(
                [0x55; 32],
            ),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(9).unwrap(),
            accepted_at_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(
                1_900_000_000_100,
            )
            .unwrap(),
        };
        let desired_read_position = cats_api::runtime_reconciliation::Sequence::new(9).unwrap();
        let mut cleanup = CleanupRelease {
            target: CleanupTarget::Network {
                network_id: Id::new("net_cleanup_freshness").unwrap(),
                ownership_token: RandomId128::new("abababababababababababababababab").unwrap(),
            },
            inventory_session: SessionBinding {
                node_id: session.node_id.clone(),
                node_boot_id: session.node_boot_id.clone(),
                agent_instance_id: session.agent_instance_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
            },
            inventory_epoch: attestation.inventory_epoch,
            inventory_read_position: attestation.inventory_read_position,
            desired_read_position,
            volume_release: None,
        };
        assert!(cleanup_execution_context_is_fresh(
            &session,
            &attestation,
            Some(desired_read_position),
            &cleanup,
        ));

        cleanup.inventory_epoch =
            cats_api::runtime_reconciliation::Epoch::new(attestation.inventory_epoch.get() - 1)
                .unwrap();
        cleanup.inventory_read_position = cats_api::runtime_reconciliation::Sequence::new(
            attestation.inventory_read_position.get() - 1,
        )
        .unwrap();
        assert!(
            cleanup_execution_context_is_fresh(
                &session,
                &attestation,
                Some(desired_read_position),
                &cleanup,
            ),
            "the mandatory post-checkpoint full scan is later than the planning scan"
        );

        cleanup.inventory_epoch =
            cats_api::runtime_reconciliation::Epoch::new(attestation.inventory_epoch.get() + 1)
                .unwrap();
        assert!(!cleanup_execution_context_is_fresh(
            &session,
            &attestation,
            Some(desired_read_position),
            &cleanup,
        ));
        cleanup.inventory_epoch = attestation.inventory_epoch;
        cleanup.inventory_session.agent_instance_id =
            RandomId128::new("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap();
        assert!(!cleanup_execution_context_is_fresh(
            &session,
            &attestation,
            Some(desired_read_position),
            &cleanup,
        ));
    }

    #[test]
    fn superseded_drain_rebinds_exact_disposable_delete_before_physical_io() {
        let (old_desired, mut predecessor, mut runtime) = fixtures(RuntimeTarget::Cold);
        predecessor.stable_state = None;
        predecessor.step = first_lifecycle_step(&old_desired, &runtime)
            .unwrap()
            .expect("Cold predecessor must begin with DrainPublish");
        runtime.stable_state = None;
        runtime.step = predecessor.step.clone();
        runtime.guest_transport = GuestTransportEvidence::Unavailable;
        for volume in &mut runtime.volumes {
            volume.devices.clear();
        }

        let mut desired = old_desired.clone();
        desired.desired_revision =
            cats_api::runtime_reconciliation::Revision::new(old_desired.desired_revision.get() + 1)
                .unwrap();
        desired.target = RuntimeTarget::Deleted;
        desired.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
            delete_id: Id::new("delete_superseded_drain").unwrap(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        runtime.applied_desired = Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        });

        let observed_at = cats_api::runtime_reconciliation::UnixMillis::new(
            predecessor.updated_at_unix_ms.get() + 1,
        )
        .unwrap();
        assert!(
            superseded_drain_rebind_successor(&desired, &runtime, &predecessor, observed_at,)
                .unwrap()
                .is_some()
        );

        let mut owner_drift = runtime.clone();
        let VolumeAuthorityEvidence::Owned { attachment_id, .. } =
            &mut owner_drift.volumes[0].authority
        else {
            unreachable!()
        };
        *attachment_id = Id::new("att_foreign_owner").unwrap();
        assert!(superseded_drain_rebind_successor(
            &desired,
            &owner_drift,
            &predecessor,
            observed_at,
        )
        .unwrap()
        .is_none());

        let mut active_gate = predecessor.clone();
        let endpoint = &desired.endpoints[0];
        let launch = active_gate.runtime_launch.identity().unwrap();
        active_gate
            .route_gates
            .push(cats_api::runtime_reconciliation::CheckpointRouteGate {
                binding: cats_api::runtime_reconciliation::RouteGateBinding {
                    workspace_id: desired.workspace_id.clone(),
                    endpoint_id: endpoint.endpoint_id.clone(),
                    hostname: endpoint.hostname.clone(),
                    cat_id: desired.cat_id.clone(),
                    node_id: desired.placement.node_id.clone(),
                    runtime_incarnation: launch.runtime_incarnation.clone(),
                    route_epoch: endpoint.route_epoch,
                    protocol: endpoint.protocol,
                    target_port: endpoint.target_port,
                },
                gate: cats_api::runtime_reconciliation::RouteGateState::Active,
            });
        assert!(
            superseded_drain_rebind_successor(&desired, &runtime, &active_gate, observed_at,)
                .unwrap()
                .is_none()
        );

        let directory = TempDir::new().unwrap();
        let checkpoint_directory = directory.path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id).unwrap();
        let stored = store.create(&predecessor).unwrap();
        runtime.checkpoint = CheckpointEvidence::Valid {
            checkpoint_path: HostPath::new(store.path().to_string_lossy().into_owned()).unwrap(),
            content_digest: stored.content_digest().clone(),
            version: predecessor.version,
            cat_id: predecessor.cat_id.clone(),
            node_id: predecessor.node_id.clone(),
            desired_revision: predecessor.desired_revision,
            spec_digest: predecessor.spec_digest.clone(),
            placement_epoch: predecessor.placement_epoch,
            runtime_incarnation: predecessor.runtime_incarnation.clone(),
            runtime_launch: Box::new(predecessor.runtime_launch.clone()),
            stable_state: predecessor.stable_state,
            step: Box::new(predecessor.step.clone()),
            require_idle: Box::new(predecessor.require_idle.clone()),
            updated_at_unix_ms: predecessor.updated_at_unix_ms,
        };
        drop(store);

        let volume = Arc::new(ScriptedLifecycleVolumePort {
            recovery: Mutex::new(None),
            evidence_calls: AtomicUsize::new(0),
            delete_calls: AtomicUsize::new(0),
            delete_attempts: Mutex::new(VecDeque::new()),
            delete_authorization_ids: Mutex::new(Vec::new()),
        });
        let effect = LifecycleStepEffect {
            credentials: None,
            physical: Arc::new(NeverLifecyclePhysical),
            volume_transition: Arc::clone(&volume) as Arc<dyn SignedLifecycleVolumePort>,
            volume_authority: Arc::new(UnavailableVolumeAuthority),
            #[cfg(feature = "proposed-node-residue-reclamation")]
            data_directory_reclaim: None,
        };
        let context = deleting_effect_context(&directory, &desired, runtime);
        assert_eq!(
            effect.try_apply(&context, &desired).unwrap(),
            Some(RuntimeDesiredEffectOutcome::refresh_inventory())
        );
        assert_eq!(volume.evidence_calls.load(Ordering::SeqCst), 0);
        assert_eq!(volume.delete_calls.load(Ordering::SeqCst), 0);

        let rebound = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id)
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(
            rebound.checkpoint().desired_revision,
            desired.desired_revision
        );
        assert_eq!(rebound.checkpoint().spec_digest, desired.spec_digest);
        assert!(matches!(
            rebound.checkpoint().step,
            ReconcileStep::StopRuntime { .. }
        ));
        assert_eq!(
            rebound.checkpoint().runtime_launch,
            predecessor.runtime_launch
        );
        assert!(
            super::super::inventory::checkpoint_process_projections_match_retained_launch(
                rebound.checkpoint()
            ),
            "the rebound lifecycle journal must remain admissible to the next full scan"
        );
    }

    #[test]
    fn relaxed_suspend_pauses_locally_while_deeper_targets_drain_publish() {
        for target in [RuntimeTarget::Suspended, RuntimeTarget::Cold] {
            let (desired, _, mut runtime) = fixtures(target);
            let lineage = &mut runtime.volumes[0].local_lineages[0];
            lineage.local_durable_generation =
                cats_api::runtime_reconciliation::Generation::new(2).unwrap();
            lineage.remote_durable_generation =
                cats_api::runtime_reconciliation::Generation::new(1).unwrap();
            let process = exact_vmm_process(&runtime).unwrap();
            let planned = first_lifecycle_step(&desired, &runtime).unwrap();

            if target == RuntimeTarget::Suspended {
                assert!(matches!(
                    planned,
                    Some(ReconcileStep::PauseRuntime {
                        ref runtime_incarnation,
                        process_start_time_ticks,
                    }) if Some(runtime_incarnation) == runtime.runtime_incarnation.as_ref()
                        && process_start_time_ticks == process.process_start_time_ticks
                ));
            } else {
                assert!(matches!(
                    planned,
                    Some(ReconcileStep::DrainPublish {
                        ref volume_id,
                        local_generation,
                        remote_generation,
                        ..
                    }) if volume_id == &runtime.volumes[0].volume_id
                        && local_generation.get() == 2
                        && remote_generation.get() == 1
                ));
            }
        }
    }

    #[test]
    fn warm_target_never_enters_or_settles_the_cold_lifecycle_path() {
        let (desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Warm);
        assert!(first_lifecycle_step(&desired, &runtime).is_err());

        checkpoint.stable_state = None;
        checkpoint.step = ReconcileStep::StopRuntime {
            runtime_incarnation: checkpoint.runtime_incarnation.clone().unwrap(),
            process_start_time_ticks: runtime.processes[0].process_start_time_ticks,
            scope_id: runtime.processes[0].scope_id.clone(),
        };
        runtime.processes.clear();
        runtime.networks.clear();
        runtime.guest_transport = GuestTransportEvidence::Unavailable;
        for volume in &mut runtime.volumes {
            volume.devices.clear();
            let VolumeAuthorityEvidence::Owned {
                attachment_epoch,
                head,
                ..
            } = &volume.authority
            else {
                unreachable!()
            };
            volume.authority = VolumeAuthorityEvidence::Unowned {
                attachment_epoch: *attachment_epoch,
                head: head.clone(),
            };
        }
        assert!(settle_cleanup_target(&desired, &runtime, &mut checkpoint).is_err());
    }

    #[test]
    fn ambiguous_or_stale_drain_proof_never_advances_the_checkpoint() {
        let (mut desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Cold);
        add_second_drain_volume(&mut desired, &mut checkpoint, &mut runtime);
        checkpoint.stable_state = None;
        checkpoint.step = first_lifecycle_step(&desired, &runtime)
            .unwrap()
            .expect("Cold departure starts with one exact drain token");
        runtime.stable_state = None;
        runtime.step = checkpoint.step.clone();
        assert!(
            drain_attempt_successor(
                &desired,
                &runtime,
                &checkpoint,
                &LifecyclePhysicalAttempt::SubmittedOrAmbiguous,
                checkpoint.updated_at_unix_ms,
            )
            .unwrap()
            .is_none(),
            "response loss must retain the exact DrainPublish token"
        );

        let ReconcileStep::DrainPublish {
            remote_generation, ..
        } = &checkpoint.step
        else {
            unreachable!()
        };
        let exact = exact_drain_receipt(&desired, &runtime);
        assert_eq!(exact.volumes.len(), 2);
        let mut incomplete = exact.clone();
        incomplete.volumes.pop();
        assert!(drain_attempt_successor(
            &desired,
            &runtime,
            &checkpoint,
            &LifecyclePhysicalAttempt::VerifiedDrain(incomplete),
            checkpoint.updated_at_unix_ms,
        )
        .is_err());
        let later =
            cats_api::runtime_reconciliation::Generation::new(remote_generation.get() + 1).unwrap();
        if let ReconcileStep::DrainPublish {
            local_generation, ..
        } = &mut checkpoint.step
        {
            *local_generation = later;
        }
        runtime.step = checkpoint.step.clone();
        assert!(drain_attempt_successor(
            &desired,
            &runtime,
            &checkpoint,
            &LifecyclePhysicalAttempt::VerifiedDrain(exact),
            checkpoint.updated_at_unix_ms,
        )
        .is_err());
    }

    #[test]
    fn paused_postcondition_settles_only_the_exact_process() {
        let (desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Suspended);
        let launch = checkpoint.runtime_launch.identity().unwrap();
        checkpoint.stable_state = None;
        checkpoint.step = ReconcileStep::PauseRuntime {
            runtime_incarnation: launch.runtime_incarnation.clone(),
            process_start_time_ticks: runtime.processes[0].process_start_time_ticks,
        };
        runtime.step = checkpoint.step.clone();
        runtime.stable_state = None;
        runtime.processes[0].state = ProcessState::Paused;
        let directory = TempDir::new().unwrap();
        let successor =
            exact_postcondition_successor(directory.path(), &desired, &runtime, &checkpoint)
                .unwrap()
                .unwrap();
        assert_eq!(successor.stable_state, Some(StableState::Suspended));
        assert!(matches!(
            &successor.step,
            ReconcileStep::Stable {
                state: StableState::Suspended
            }
        ));
        encode_runtime_checkpoint(&successor).unwrap();

        runtime.processes[0].process_start_time_ticks =
            cats_api::runtime_reconciliation::WireU64::new(100).unwrap();
        assert!(
            exact_postcondition_successor(directory.path(), &desired, &runtime, &checkpoint,)
                .is_err()
        );
    }

    #[test]
    fn stopped_postcondition_advances_only_after_the_exact_vmm_is_absent() {
        let (desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Cold);
        let launch = checkpoint.runtime_launch.identity().unwrap().clone();
        let process_start_time_ticks = runtime.processes[0].process_start_time_ticks;
        checkpoint.stable_state = None;
        checkpoint.step = ReconcileStep::StopRuntime {
            runtime_incarnation: launch.runtime_incarnation.clone(),
            process_start_time_ticks,
            scope_id: launch.scope_id.clone(),
        };
        runtime.step = checkpoint.step.clone();
        runtime.stable_state = None;
        runtime.processes.clear();
        let cursor = FreshCleanupCursor {
            session: SessionBinding {
                node_id: checkpoint.node_id.clone(),
                node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                    "11111111111111111111111111111111".to_owned(),
                )
                .unwrap(),
                agent_instance_id: launch.process_identity_token.clone(),
                agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            },
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(2).unwrap(),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(2).unwrap(),
            desired_read_position: cats_api::runtime_reconciliation::Sequence::new(3).unwrap(),
            observed_at: cats_api::runtime_reconciliation::UnixMillis::new(1_800_000_000_000)
                .unwrap(),
        };

        let successor =
            stop_postcondition_successor_at(&desired, &runtime, &checkpoint, &[], &cursor)
                .unwrap()
                .expect("exact VMM absence must advance into canonical cleanup");
        assert!(matches!(
            successor.step,
            ReconcileStep::CleanupRelease { .. }
        ));
        assert!(matches!(
            successor.runtime_launch,
            RuntimeLaunch::Present(_)
        ));
        assert!(successor.processes.is_empty());
        encode_runtime_checkpoint(&successor).unwrap();

        runtime.processes = checkpoint.processes.clone();
        assert!(
            stop_postcondition_successor_at(&desired, &runtime, &checkpoint, &[], &cursor).is_err(),
            "an exact live VMM must keep StopRuntime unsettled"
        );
    }

    struct KernelNbdCleanupFixture {
        desired: DesiredRuntimeSpec,
        checkpoint: RuntimeCheckpoint,
        runtime: ObservedRuntimeStatus,
        volume_id: Id,
        ownership_token: RandomId128,
        vhost_frontend: cats_api::runtime_reconciliation::PrepareDeviceFrontend,
    }

    fn kernel_nbd_cleanup_fixture() -> KernelNbdCleanupFixture {
        let (desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Cold);
        let device_path = HostPath::new("/dev/nbd7".to_owned()).unwrap();
        let (volume_id, ownership_token, guest_device, vhost_frontend) = {
            let RuntimeLaunch::Present(launch) = &mut checkpoint.runtime_launch else {
                panic!("fixture launch absent")
            };
            let prepared = &mut launch.devices[0];
            let vhost_frontend = prepared.frontend.clone();
            let listener_socket_path = match &vhost_frontend {
                cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk {
                    socket_path,
                    ..
                } => socket_path.clone(),
                _ => panic!("fixture frontend changed"),
            };
            prepared.frontend =
                cats_api::runtime_reconciliation::PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    device_path: device_path.clone(),
                    direct: true,
                };
            (
                prepared.volume_id.clone(),
                prepared.ownership_token.clone(),
                prepared.guest_device.clone(),
                vhost_frontend,
            )
        };
        checkpoint.processes.clear();
        checkpoint.volumes[0].devices = vec![ObservedDevice::KernelNbd {
            guest_device,
            device_path,
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: ownership_token.clone(),
            },
        }];
        runtime.processes.clear();
        runtime.volumes = checkpoint.volumes.clone();
        let cleanup = CleanupRelease {
            target: CleanupTarget::Device {
                volume_id: volume_id.clone(),
                ownership_token: ownership_token.clone(),
            },
            inventory_session: SessionBinding {
                node_id: checkpoint.node_id.clone(),
                node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                    "11111111111111111111111111111111".to_owned(),
                )
                .unwrap(),
                agent_instance_id: RandomId128::new("22222222222222222222222222222222".to_owned())
                    .unwrap(),
                agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(3).unwrap(),
            },
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(7).unwrap(),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(9).unwrap(),
            desired_read_position: cats_api::runtime_reconciliation::Sequence::new(9).unwrap(),
            volume_release: None,
        };
        checkpoint.stable_state = None;
        checkpoint.step = ReconcileStep::CleanupRelease {
            cleanup: cleanup.clone(),
        };
        runtime.stable_state = None;
        runtime.step = ReconcileStep::CleanupRelease { cleanup };
        KernelNbdCleanupFixture {
            desired,
            checkpoint,
            runtime,
            volume_id,
            ownership_token,
            vhost_frontend,
        }
    }

    fn install_valid_checkpoint_evidence(
        runtime: &mut ObservedRuntimeStatus,
        checkpoint: &RuntimeCheckpoint,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
    ) {
        runtime.checkpoint = CheckpointEvidence::Valid {
            checkpoint_path: HostPath::new(store.path().to_string_lossy().into_owned()).unwrap(),
            content_digest: stored.content_digest().clone(),
            version: checkpoint.version,
            cat_id: checkpoint.cat_id.clone(),
            node_id: checkpoint.node_id.clone(),
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            placement_epoch: checkpoint.placement_epoch,
            runtime_incarnation: checkpoint.runtime_incarnation.clone(),
            runtime_launch: Box::new(checkpoint.runtime_launch.clone()),
            stable_state: checkpoint.stable_state,
            step: Box::new(checkpoint.step.clone()),
            require_idle: Box::new(checkpoint.require_idle.clone()),
            updated_at_unix_ms: checkpoint.updated_at_unix_ms,
        };
    }

    #[test]
    fn exact_kernel_nbd_device_cleanup_submits_once_through_the_checkpointed_port() {
        let KernelNbdCleanupFixture {
            desired,
            checkpoint,
            mut runtime,
            volume_id,
            ownership_token,
            ..
        } = kernel_nbd_cleanup_fixture();
        let directory = TempDir::new().unwrap();
        let store = FileCheckpointStore::open(
            &directory.path().join(CHECKPOINT_NAMESPACE),
            &checkpoint.cat_id,
        )
        .unwrap();
        let stored = store.create(&checkpoint).unwrap();
        install_valid_checkpoint_evidence(&mut runtime, &checkpoint, &store, &stored);
        let context = deleting_effect_context(&directory, &desired, runtime.clone());
        let permit = LifecycleEffectPermit {
            desired: &desired,
            runtime: &runtime,
            store: &store,
            stored: &stored,
        };
        let detach = RecordingKernelNbdDetach {
            calls: Mutex::new(Vec::new()),
        };

        assert_eq!(
            detach_exact_kernel_nbd_device(
                Some(&detach),
                &context,
                &permit,
                &volume_id,
                &ownership_token,
            )
            .unwrap(),
            LifecyclePhysicalAttempt::SubmittedOrAmbiguous
        );
        assert_eq!(
            detach.calls.lock().unwrap().as_slice(),
            &[(desired.cat_id.clone(), volume_id, ownership_token)]
        );
    }

    #[test]
    fn absent_kernel_nbd_device_retires_its_serving_socket_owner() {
        let KernelNbdCleanupFixture {
            desired,
            checkpoint,
            mut runtime,
            volume_id,
            ownership_token,
            ..
        } = kernel_nbd_cleanup_fixture();
        runtime.volumes[0].devices.clear();
        let prepared = checkpoint.runtime_launch.identity().unwrap().devices[0].clone();
        let plans = canonical_remaining_cleanup_with_absent_serving(
            &desired,
            &runtime,
            &checkpoint,
            &[],
            std::slice::from_ref(&prepared),
        )
        .unwrap();
        assert!(plans.iter().any(|plan| matches!(
            plan,
            PlannedCleanup {
                target: CleanupTarget::Device {
                    volume_id: planned_volume,
                    ownership_token: planned_token,
                },
                ..
            } if planned_volume == &volume_id && planned_token == &ownership_token
        )));
        let expectation =
            ServingBlockdExpectation::from_lifecycle_checkpoint_for_test(&checkpoint, &desired)
                .unwrap();
        let directory = TempDir::new().unwrap();
        let store = FileCheckpointStore::open(
            &directory.path().join(CHECKPOINT_NAMESPACE),
            &checkpoint.cat_id,
        )
        .unwrap();
        let stored = store.create(&checkpoint).unwrap();
        install_valid_checkpoint_evidence(&mut runtime, &checkpoint, &store, &stored);
        let key = ManagedServingKey::new(desired.cat_id.clone(), volume_id.clone());
        let scan = NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_serving_blockds(
            BTreeMap::from([(key.clone(), expectation.clone())]),
            BTreeMap::new(),
        )
        .unwrap()
        .with_absent_serving_owners(BTreeSet::from([key]))
        .unwrap();
        let context = deleting_effect_context(&directory, &desired, runtime.clone());
        let admission = scan
            .bind(context.accepted_full().unwrap().observation())
            .unwrap();
        let context = context.with_node_global_process_for_test(admission);
        let serving = Arc::new(VhostCleanupServingPort {
            retirements: Mutex::new(VecDeque::from([
                ManagedBlockdSocketOwnerRetirement::Retired,
                ManagedBlockdSocketOwnerRetirement::AlreadyAbsent,
            ])),
        });
        let detach = Arc::new(RecordingKernelNbdDetach {
            calls: Mutex::new(Vec::new()),
        });
        let physical = PlatformLifecyclePhysicalPort {
            network_ip_binary: PathBuf::new(),
            serving_process: serving.clone(),
            vmm_process: Arc::new(NeverVmmProcessPort),
            kernel_nbd_detach: Some(detach.clone()),
            blockd: PlatformPersistentBlockdControlPort,
            volume_authority: Arc::new(UnavailableVolumeAuthority),
        };
        let permit = LifecycleEffectPermit {
            desired: &desired,
            runtime: &runtime,
            store: &store,
            stored: &stored,
        };

        assert_eq!(
            physical
                .detach_exact_device(&context, &permit, &volume_id, &ownership_token)
                .unwrap(),
            LifecyclePhysicalAttempt::SubmittedOrAmbiguous
        );
        assert_eq!(
            physical
                .detach_exact_device(&context, &permit, &volume_id, &ownership_token)
                .unwrap(),
            LifecyclePhysicalAttempt::ExactPostcondition
        );
        assert!(detach.calls.lock().unwrap().is_empty());
        assert!(serving.retirements.lock().unwrap().is_empty());
        assert!(expectation.matches_device_contract(&desired.cat_id, &prepared));
    }

    #[test]
    fn checkpointed_kernel_nbd_leak_is_not_mistaken_for_an_absent_device() {
        let KernelNbdCleanupFixture {
            desired,
            checkpoint,
            mut runtime,
            volume_id,
            ownership_token,
            ..
        } = kernel_nbd_cleanup_fixture();
        let RuntimeLaunch::Present(launch) = &checkpoint.runtime_launch else {
            unreachable!()
        };
        let prepared = launch.devices[0].clone();
        let cats_api::runtime_reconciliation::PrepareDeviceFrontend::KernelNbd {
            device_path, ..
        } = &prepared.frontend
        else {
            unreachable!()
        };
        runtime.volumes[0].devices.clear();
        let directory = TempDir::new().unwrap();
        let store = FileCheckpointStore::open(
            &directory.path().join(CHECKPOINT_NAMESPACE),
            &checkpoint.cat_id,
        )
        .unwrap();
        let stored = store.create(&checkpoint).unwrap();
        install_valid_checkpoint_evidence(&mut runtime, &checkpoint, &store, &stored);
        let base = deleting_effect_context(&directory, &desired, runtime.clone());
        let mut observation = base.accepted_full().unwrap().observation().clone();
        observation.residue = vec![NodeResidue::KernelNbd {
            volume_id_hint: Some(volume_id.clone()),
            guest_device: Some(prepared.guest_device.clone()),
            device_path: device_path.clone(),
            ownership_token: OwnershipTokenEvidence::Missing,
        }];
        observation.inventory_digest =
            Some(cats_api::runtime_reconciliation::inventory_digest(&observation).unwrap());
        let admission = base
            .accepted_full()
            .unwrap()
            .clone()
            .with_observation_for_test(observation);
        let context = RuntimeDesiredEffectContext::for_test_with_admission(
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            admission,
        );
        let permit = LifecycleEffectPermit {
            desired: &desired,
            runtime: &runtime,
            store: &store,
            stored: &stored,
        };
        let detach = RecordingKernelNbdDetach {
            calls: Mutex::new(Vec::new()),
        };

        assert_eq!(
            detach_exact_kernel_nbd_device(
                Some(&detach),
                &context,
                &permit,
                &volume_id,
                &ownership_token,
            )
            .unwrap(),
            LifecyclePhysicalAttempt::SubmittedOrAmbiguous
        );
        assert_eq!(detach.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn device_cleanup_rejects_identity_drift_and_keeps_vhost_fail_closed() {
        enum Case {
            DevicePath,
            GuestIdentity,
            OwnershipToken,
            LiveVmm,
            VhostUser,
        }

        for case in [
            Case::DevicePath,
            Case::GuestIdentity,
            Case::OwnershipToken,
            Case::LiveVmm,
            Case::VhostUser,
        ] {
            let KernelNbdCleanupFixture {
                desired,
                mut checkpoint,
                mut runtime,
                volume_id,
                ownership_token,
                vhost_frontend,
            } = kernel_nbd_cleanup_fixture();
            let expected = match case {
                Case::DevicePath => {
                    let ObservedDevice::KernelNbd { device_path, .. } =
                        &mut runtime.volumes[0].devices[0]
                    else {
                        unreachable!()
                    };
                    *device_path = HostPath::new("/dev/nbd8".to_owned()).unwrap();
                    LifecyclePhysicalAttempt::Conflict
                }
                Case::GuestIdentity => {
                    let ObservedDevice::KernelNbd { guest_device, .. } =
                        &mut runtime.volumes[0].devices[0]
                    else {
                        unreachable!()
                    };
                    guest_device.serial = Id::new("cats-drifted-root").unwrap();
                    LifecyclePhysicalAttempt::Conflict
                }
                Case::OwnershipToken => {
                    let ObservedDevice::KernelNbd {
                        ownership_token, ..
                    } = &mut runtime.volumes[0].devices[0]
                    else {
                        unreachable!()
                    };
                    *ownership_token = OwnershipTokenEvidence::Valid {
                        ownership_token: RandomId128::new(
                            "99999999999999999999999999999999".to_owned(),
                        )
                        .unwrap(),
                    };
                    LifecyclePhysicalAttempt::Conflict
                }
                Case::LiveVmm => {
                    runtime.processes = fixtures(RuntimeTarget::Cold).2.processes;
                    LifecyclePhysicalAttempt::Conflict
                }
                Case::VhostUser => {
                    let (socket_path, guest_device) = {
                        let RuntimeLaunch::Present(launch) = &mut checkpoint.runtime_launch else {
                            unreachable!()
                        };
                        let prepared = &mut launch.devices[0];
                        prepared.frontend = vhost_frontend;
                        let cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk {
                            socket_path,
                            ..
                        } = &prepared.frontend
                        else {
                            unreachable!()
                        };
                        (socket_path.clone(), prepared.guest_device.clone())
                    };
                    runtime.volumes[0].devices = vec![ObservedDevice::VhostUserBlk {
                        guest_device,
                        socket_path,
                        ownership_token: OwnershipTokenEvidence::Valid {
                            ownership_token: ownership_token.clone(),
                        },
                    }];
                    LifecyclePhysicalAttempt::Unavailable
                }
            };
            let directory = TempDir::new().unwrap();
            let store = FileCheckpointStore::open(
                &directory.path().join(CHECKPOINT_NAMESPACE),
                &checkpoint.cat_id,
            )
            .unwrap();
            let stored = store.create(&checkpoint).unwrap();
            let context = RuntimeDesiredEffectContext::for_test(
                crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            );
            let permit = LifecycleEffectPermit {
                desired: &desired,
                runtime: &runtime,
                store: &store,
                stored: &stored,
            };
            let detach = RecordingKernelNbdDetach {
                calls: Mutex::new(Vec::new()),
            };

            assert_eq!(
                detach_exact_kernel_nbd_device(
                    Some(&detach),
                    &context,
                    &permit,
                    &volume_id,
                    &ownership_token,
                )
                .unwrap(),
                expected
            );
            assert!(detach.calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn admitted_serving_expectation_ignores_lease_read_skew() {
        // The admission and the effect read the continuously renewed
        // attachment lease at different instants, in either order. Any
        // equality or ordering requirement between the two reads livelocked
        // the PrepareDevice serving start; identity fields stay exact while
        // the lease expiry is excluded from admission equality.
        let (desired, checkpoint, _runtime) = fixtures(RuntimeTarget::Running);
        let admitted =
            ServingBlockdExpectation::from_lifecycle_checkpoint_for_test(&checkpoint, &desired)
                .unwrap();
        // The test constructor pins a fixed lease expiry; skew one step past it.
        let skewed_expiry =
            cats_api::runtime_reconciliation::UnixMillis::new(1_900_000_120_001).unwrap();
        let skewed = admitted.clone().with_renewed_lease_for_test(skewed_expiry);
        assert!(skewed.matches_admitted(&admitted));
        assert!(
            admitted.matches_admitted(&skewed),
            "lease read skew in either direction must not reject the admitted start"
        );

        // Calibrate the negative: an identity drift (a Desired targeting
        // Cold instead of Running inside the authorized volume) fails closed.
        let (cold_desired, cold_checkpoint, _cold_runtime) = fixtures(RuntimeTarget::Cold);
        let foreign = ServingBlockdExpectation::from_lifecycle_checkpoint_for_test(
            &cold_checkpoint,
            &cold_desired,
        )
        .unwrap();
        assert!(
            !foreign.matches_admitted(&admitted),
            "identity drift must stay rejected while lease skew is tolerated"
        );
    }

    #[test]
    fn absent_before_first_scan_vhost_owner_survives_restart_and_rejects_replacement() {
        let (desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Cold);
        let prepared = checkpoint.runtime_launch.identity().unwrap().devices[0].clone();
        let expectation =
            ServingBlockdExpectation::from_lifecycle_checkpoint_for_test(&checkpoint, &desired)
                .unwrap();
        let vmm = runtime
            .processes
            .iter()
            .find(|process| matches!(process.role, ProcessRole::Vmm { .. }))
            .unwrap()
            .clone();
        runtime.processes.clear();
        runtime.volumes[0].devices.clear();
        runtime.networks.clear();
        checkpoint.step = ReconcileStep::StopRuntime {
            runtime_incarnation: checkpoint.runtime_incarnation.clone().unwrap(),
            process_start_time_ticks: vmm.process_start_time_ticks,
            scope_id: vmm.scope_id,
        };
        let cursor = FreshCleanupCursor {
            session: SessionBinding {
                node_id: checkpoint.node_id.clone(),
                node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                    "11111111111111111111111111111111".to_owned(),
                )
                .unwrap(),
                agent_instance_id: RandomId128::new("22222222222222222222222222222222".to_owned())
                    .unwrap(),
                agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(3).unwrap(),
            },
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(7).unwrap(),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(9).unwrap(),
            desired_read_position: cats_api::runtime_reconciliation::Sequence::new(9).unwrap(),
            observed_at: cats_api::runtime_reconciliation::UnixMillis::new(1_800_000_000_000)
                .unwrap(),
        };
        let cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk {
            socket_path,
            ..
        } = &prepared.frontend
        else {
            unreachable!()
        };
        let owner_residue = [
            NodeResidue::ControlSocket {
                socket_path: prepared.serving_process.control_socket_path.clone(),
                role_hint: None,
                ownership_token: OwnershipTokenEvidence::Missing,
            },
            NodeResidue::ControlSocket {
                socket_path: socket_path.clone(),
                role_hint: None,
                ownership_token: OwnershipTokenEvidence::Missing,
            },
        ];
        checkpoint = stop_postcondition_successor_at_with_absent_serving(
            &desired,
            &runtime,
            &checkpoint,
            &owner_residue,
            &cursor,
            std::slice::from_ref(&prepared),
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            checkpoint.step,
            ReconcileStep::CleanupRelease {
                cleanup: CleanupRelease {
                    target: CleanupTarget::Device { .. },
                    ..
                }
            }
        ));
        assert!(checkpoint.runtime_launch.identity().is_some());
        runtime.stable_state = None;
        runtime.step = checkpoint.step.clone();

        let directory = TempDir::new().unwrap();
        let store = FileCheckpointStore::open(
            &directory.path().join(CHECKPOINT_NAMESPACE),
            &checkpoint.cat_id,
        )
        .unwrap();
        let stored = store.create(&checkpoint).unwrap();
        runtime.checkpoint = CheckpointEvidence::Valid {
            checkpoint_path: HostPath::new(store.path().to_string_lossy().into_owned()).unwrap(),
            content_digest: stored.content_digest().clone(),
            version: checkpoint.version,
            cat_id: checkpoint.cat_id.clone(),
            node_id: checkpoint.node_id.clone(),
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            placement_epoch: checkpoint.placement_epoch,
            runtime_incarnation: checkpoint.runtime_incarnation.clone(),
            runtime_launch: Box::new(checkpoint.runtime_launch.clone()),
            stable_state: checkpoint.stable_state,
            step: Box::new(checkpoint.step.clone()),
            require_idle: Box::new(checkpoint.require_idle.clone()),
            updated_at_unix_ms: checkpoint.updated_at_unix_ms,
        };
        let serving = Arc::new(VhostCleanupServingPort {
            retirements: Mutex::new(VecDeque::from([
                ManagedBlockdSocketOwnerRetirement::Retired,
            ])),
        });
        let physical = PlatformLifecyclePhysicalPort {
            network_ip_binary: PathBuf::new(),
            serving_process: serving.clone(),
            vmm_process: Arc::new(NeverVmmProcessPort),
            kernel_nbd_detach: None,
            blockd: PlatformPersistentBlockdControlPort,
            volume_authority: Arc::new(UnavailableVolumeAuthority),
        };

        let key = ManagedServingKey::new(desired.cat_id.clone(), prepared.volume_id.clone());
        let mut replacement_checkpoint = checkpoint.clone();
        let RuntimeLaunch::Present(replacement_launch) = &mut replacement_checkpoint.runtime_launch
        else {
            unreachable!()
        };
        replacement_launch.devices[0].ownership_token =
            RandomId128::new("99999999999999999999999999999999".to_owned()).unwrap();
        let replacement = ServingBlockdExpectation::from_lifecycle_checkpoint_for_test(
            &replacement_checkpoint,
            &desired,
        )
        .unwrap();
        let replacement_scan = NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_serving_blockds(
            BTreeMap::from([(key.clone(), replacement)]),
            BTreeMap::new(),
        )
        .unwrap()
        .with_absent_serving_owners(BTreeSet::from([key.clone()]))
        .unwrap();
        let replacement_context = deleting_effect_context(&directory, &desired, runtime.clone());
        let replacement_admission = replacement_scan
            .bind(replacement_context.accepted_full().unwrap().observation())
            .unwrap();
        let replacement_context =
            replacement_context.with_node_global_process_for_test(replacement_admission);
        let permit = LifecycleEffectPermit {
            desired: &desired,
            runtime: &runtime,
            store: &store,
            stored: &stored,
        };
        assert_eq!(
            physical
                .detach_exact_device(
                    &replacement_context,
                    &permit,
                    &prepared.volume_id,
                    &prepared.ownership_token,
                )
                .unwrap(),
            LifecyclePhysicalAttempt::Conflict
        );
        assert_eq!(serving.retirements.lock().unwrap().len(), 1);

        let absent_scan = NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_serving_blockds(
            BTreeMap::from([(key.clone(), expectation)]),
            BTreeMap::new(),
        )
        .unwrap()
        .with_absent_serving_owners(BTreeSet::from([key]))
        .unwrap();
        let context = deleting_effect_context(&directory, &desired, runtime.clone());
        let admission = absent_scan
            .bind(context.accepted_full().unwrap().observation())
            .unwrap();
        assert!(admission.retains_absent_serving_owner(&desired.cat_id, &prepared));
        let context = context.with_node_global_process_for_test(admission);
        let permit = LifecycleEffectPermit {
            desired: &desired,
            runtime: &runtime,
            store: &store,
            stored: &stored,
        };
        assert_eq!(
            physical
                .detach_exact_device(
                    &context,
                    &permit,
                    &prepared.volume_id,
                    &prepared.ownership_token,
                )
                .unwrap(),
            LifecyclePhysicalAttempt::SubmittedOrAmbiguous
        );
        assert!(serving.retirements.lock().unwrap().is_empty());
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            &checkpoint,
            "a crash after owner retirement must replay the retained Device token"
        );

        let volume_cleanup = cleanup_postcondition_successor_at_with_absent_serving(
            &desired,
            &runtime,
            &checkpoint,
            &[],
            &cursor,
            &[],
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            volume_cleanup.step,
            ReconcileStep::CleanupRelease {
                cleanup: CleanupRelease {
                    target: CleanupTarget::Volume { .. },
                    ..
                }
            }
        ));
        assert_eq!(volume_cleanup.runtime_launch, checkpoint.runtime_launch);
        assert_eq!(
            volume_cleanup.runtime_incarnation,
            checkpoint.runtime_incarnation
        );

        runtime.networks.clear();
        runtime.mounts.clear();
        runtime.guest_transport = GuestTransportEvidence::Unavailable;
        let (attachment_epoch, head) = match &runtime.volumes[0].authority {
            VolumeAuthorityEvidence::Owned {
                attachment_epoch,
                head,
                ..
            } => (*attachment_epoch, head.clone()),
            _ => panic!("vhost cleanup fixture lost its Owned authority"),
        };
        runtime.volumes[0].authority = VolumeAuthorityEvidence::Unowned {
            attachment_epoch: FenceEpoch::new(attachment_epoch.get() + 1).unwrap(),
            head,
        };
        runtime.volumes[0].local_lineages.clear();
        let successor =
            cleanup_postcondition_successor_at(&desired, &runtime, &volume_cleanup, &[], &cursor)
                .unwrap()
                .unwrap();
        assert!(matches!(
            successor.step,
            ReconcileStep::Stable {
                state: StableState::Cold
            }
        ));
        assert_eq!(successor.runtime_launch, RuntimeLaunch::Absent);
    }

    #[test]
    fn absent_network_cleanup_replans_from_fresh_inventory_without_reissuing_remove() {
        let (desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Cold);
        let launch = checkpoint.runtime_launch.identity().unwrap();
        assert!(matches!(
            plan_network_cleanup(launch.network.as_ref(), &[]),
            NetworkCleanupPlan::ExactPostcondition
        ));
        let cleanup = cats_api::runtime_reconciliation::CleanupRelease {
            target: CleanupTarget::Network {
                network_id: launch.network.network_config.network_id.clone(),
                ownership_token: launch.network.ownership_token.clone(),
            },
            inventory_session: cats_api::runtime_reconciliation::SessionBinding {
                node_id: checkpoint.node_id.clone(),
                node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                    "11111111111111111111111111111111".to_owned(),
                )
                .unwrap(),
                agent_instance_id: launch.process_identity_token.clone(),
                agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            },
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
            desired_read_position: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
            volume_release: None,
        };
        let cursor = FreshCleanupCursor {
            session: cleanup.inventory_session.clone(),
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(2).unwrap(),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(2).unwrap(),
            desired_read_position: cats_api::runtime_reconciliation::Sequence::new(3).unwrap(),
            observed_at: cats_api::runtime_reconciliation::UnixMillis::new(1_800_000_000_000)
                .unwrap(),
        };
        checkpoint.stable_state = None;
        checkpoint.step = ReconcileStep::CleanupRelease { cleanup };
        checkpoint.processes.clear();
        checkpoint.networks.clear();
        runtime.stable_state = None;
        runtime.step = checkpoint.step.clone();
        runtime.processes.clear();
        runtime.networks.clear();
        runtime.guest_transport =
            cats_api::runtime_reconciliation::GuestTransportEvidence::Unavailable;

        let successor =
            cleanup_postcondition_successor_at(&desired, &runtime, &checkpoint, &[], &cursor)
                .unwrap()
                .expect("fresh exact network absence must advance its cleanup journal");
        let ReconcileStep::CleanupRelease { cleanup } = &successor.step else {
            panic!("Owned retained volume must become the canonical next cleanup")
        };
        assert!(matches!(
            &cleanup.target,
            CleanupTarget::Volume { volume_id, .. }
                if volume_id == &runtime.volumes[0].volume_id
        ));
        assert_eq!(cleanup.inventory_epoch, cursor.inventory_epoch);
        assert_eq!(
            cleanup.inventory_read_position,
            cursor.inventory_read_position
        );
        assert_eq!(cleanup.desired_read_position, cursor.desired_read_position);
        assert_eq!(
            successor.runtime_incarnation,
            checkpoint.runtime_incarnation
        );
        assert_eq!(successor.runtime_launch, checkpoint.runtime_launch);
        encode_runtime_checkpoint(&successor).unwrap();

        let (attachment_epoch, head) = match &runtime.volumes[0].authority {
            VolumeAuthorityEvidence::Owned {
                attachment_epoch,
                head,
                ..
            } => (*attachment_epoch, head.clone()),
            _ => panic!("fixture volume is not Owned"),
        };
        runtime.volumes[0].authority = VolumeAuthorityEvidence::Unowned {
            attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(
                attachment_epoch.get() + 1,
            )
            .unwrap(),
            head,
        };
        runtime.volumes[0].local_lineages.clear();
        let stable =
            cleanup_postcondition_successor_at(&desired, &runtime, &successor, &[], &cursor)
                .unwrap()
                .expect("no remaining physical target must settle Cold");
        assert_eq!(stable.stable_state, Some(StableState::Cold));
        assert!(matches!(
            stable.step,
            ReconcileStep::Stable {
                state: StableState::Cold
            }
        ));
        encode_runtime_checkpoint(&stable).unwrap();
    }

    #[test]
    fn network_successor_does_not_forge_disposable_root_authority() {
        let (mut desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Deleted);
        desired.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
            delete_id: Id::new("delete_root_1").unwrap(),
        };
        let launch = checkpoint.runtime_launch.identity().unwrap();
        let cleanup = CleanupRelease {
            target: CleanupTarget::Network {
                network_id: launch.network.network_config.network_id.clone(),
                ownership_token: launch.network.ownership_token.clone(),
            },
            inventory_session: SessionBinding {
                node_id: checkpoint.node_id.clone(),
                node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                    "11111111111111111111111111111111".to_owned(),
                )
                .unwrap(),
                agent_instance_id: launch.process_identity_token.clone(),
                agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            },
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
            desired_read_position: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
            volume_release: None,
        };
        let cursor = FreshCleanupCursor {
            session: cleanup.inventory_session.clone(),
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(2).unwrap(),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(2).unwrap(),
            desired_read_position: cats_api::runtime_reconciliation::Sequence::new(3).unwrap(),
            observed_at: cats_api::runtime_reconciliation::UnixMillis::new(1_800_000_000_000)
                .unwrap(),
        };
        checkpoint.stable_state = None;
        checkpoint.step = ReconcileStep::CleanupRelease { cleanup };
        checkpoint.processes.clear();
        checkpoint.networks.clear();
        runtime.stable_state = None;
        runtime.step = checkpoint.step.clone();
        runtime.processes.clear();
        runtime.networks.clear();
        runtime.guest_transport = GuestTransportEvidence::Unavailable;

        let successor =
            cleanup_postcondition_successor_at(&desired, &runtime, &checkpoint, &[], &cursor)
                .unwrap()
                .expect("R == L disposable Root must take the normal release branch");
        assert!(matches!(
            &successor.step,
            ReconcileStep::CleanupRelease {
                cleanup: CleanupRelease {
                    target: CleanupTarget::Volume { .. },
                    volume_release: Some(_),
                    ..
                }
            }
        ));
        assert!(!matches!(
            successor.step,
            ReconcileStep::DeleteDisposableRoot { .. }
        ));
        assert_eq!(
            successor.runtime_incarnation,
            checkpoint.runtime_incarnation
        );
        assert_eq!(successor.runtime_launch, checkpoint.runtime_launch);
        encode_runtime_checkpoint(&successor).unwrap();
    }

    #[test]
    fn disposable_root_recovery_requires_exact_signed_evidence_and_changes_no_checkpoint() {
        let mut cases = [false, true]
            .into_iter()
            .flat_map(|deleting| {
                [
                    None,
                    Some("cat"),
                    Some("head"),
                    Some("epoch"),
                    Some("decision"),
                ]
                .into_iter()
                .map(move |fault| (deleting, false, fault))
            })
            .collect::<Vec<_>>();
        cases.extend([(false, true, None), (true, true, None)]);
        for (already_deleting, retry_unconsumed, fault) in cases {
            let (desired, intent, request, expected_epoch, expected_head, mut recovery) =
                if retry_unconsumed {
                    unconsumed_disposable_evidence_fixture()
                } else {
                    disposable_evidence_fixture()
                };
            if let Some(fault) = fault {
                let VolumeEvidenceRecovery::Validated { evidence, decision } = &mut recovery else {
                    unreachable!()
                };
                match fault {
                    "cat" => {
                        let VolumeAuthorization::DisposableRootDelete(authorization) =
                            &mut evidence.authorization.authorization
                        else {
                            unreachable!()
                        };
                        authorization.cat_id = Id::new("cat_wrong").unwrap();
                    }
                    "head" => {
                        evidence.current_volume.as_mut().unwrap().head =
                            cats_api::runtime_reconciliation::RemoteHead {
                                generation: cats_api::runtime_reconciliation::Generation::new(0)
                                    .unwrap(),
                                root_hash: None,
                                root_object_id: None,
                            }
                    }
                    "epoch" => {
                        evidence.current_volume.as_mut().unwrap().lease_epoch = expected_epoch
                    }
                    "decision" => **decision = VolumeEvidenceRecoveryDecision::Blocked,
                    _ => unreachable!(),
                }
            }
            let exact = match &recovery {
                VolumeEvidenceRecovery::Validated { evidence, decision } => {
                    if retry_unconsumed {
                        exact_disposable_unconsumed_evidence(
                            &request,
                            &desired,
                            &intent,
                            &request.authorization_id,
                            expected_epoch,
                            &expected_head,
                            evidence,
                            decision,
                        )
                    } else {
                        exact_disposable_deleting_evidence(
                            &request,
                            &desired,
                            &intent,
                            &request.authorization_id,
                            expected_epoch,
                            &expected_head,
                            evidence,
                            decision,
                        )
                    }
                }
                _ => unreachable!(),
            };
            assert_eq!(exact, fault.is_none(), "{fault:?}");

            let (_, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Deleted);
            checkpoint.desired_revision = desired.desired_revision;
            checkpoint.spec_digest = desired.spec_digest.clone();
            checkpoint.stable_state = None;
            checkpoint.step = ReconcileStep::DeleteDisposableRoot {
                authorization_id: request.authorization_id.clone(),
            };
            checkpoint.processes.clear();
            checkpoint.networks.clear();
            checkpoint.mounts.clear();
            checkpoint.guest_transport = GuestTransportEvidence::Unavailable;
            checkpoint.runtime_incarnation = None;
            checkpoint.runtime_launch = RuntimeLaunch::Absent;
            runtime.applied_desired = Some(AppliedDesiredEvidence {
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement: desired.placement.clone(),
                target: desired.target,
            });
            runtime.runtime_incarnation = None;
            runtime.stable_state = None;
            runtime.step = checkpoint.step.clone();
            runtime.processes.clear();
            runtime.networks.clear();
            runtime.mounts.clear();
            runtime.guest_transport = GuestTransportEvidence::Unavailable;
            runtime.volumes[0].authority = if already_deleting {
                VolumeAuthorityEvidence::Deleting {
                    delete_id: match &intent.disposition {
                        VolumeDisposition::DeleteDisposableRoot { delete_id } => delete_id.clone(),
                        _ => unreachable!(),
                    },
                    attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(
                        expected_epoch.get() + 1,
                    )
                    .unwrap(),
                    head: expected_head.clone(),
                }
            } else {
                VolumeAuthorityEvidence::Owned {
                    attachment_id: intent.attachment_id.clone(),
                    attachment_epoch: expected_epoch,
                    head: expected_head.clone(),
                }
            };
            let directory = TempDir::new().unwrap();
            let checkpoint_directory = directory.path().join(CHECKPOINT_NAMESPACE);
            let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id).unwrap();
            let stored = store.create(&checkpoint).unwrap();
            runtime.checkpoint = CheckpointEvidence::Valid {
                checkpoint_path: HostPath::new(store.path().to_string_lossy().into_owned())
                    .unwrap(),
                content_digest: stored.content_digest().clone(),
                version: checkpoint.version,
                cat_id: checkpoint.cat_id.clone(),
                node_id: checkpoint.node_id.clone(),
                desired_revision: checkpoint.desired_revision,
                spec_digest: checkpoint.spec_digest.clone(),
                placement_epoch: checkpoint.placement_epoch,
                runtime_incarnation: checkpoint.runtime_incarnation.clone(),
                runtime_launch: Box::new(checkpoint.runtime_launch.clone()),
                stable_state: checkpoint.stable_state,
                step: Box::new(checkpoint.step.clone()),
                require_idle: Box::new(checkpoint.require_idle.clone()),
                updated_at_unix_ms: checkpoint.updated_at_unix_ms,
            };
            drop(store);
            let port = Arc::new(ScriptedLifecycleVolumePort {
                recovery: Mutex::new(Some(recovery)),
                evidence_calls: AtomicUsize::new(0),
                delete_calls: AtomicUsize::new(0),
                delete_attempts: Mutex::new(VecDeque::from(
                    if retry_unconsumed && !already_deleting {
                        vec![
                            DisposableRootDeleteAttempt::Ambiguous,
                            DisposableRootDeleteAttempt::RetryExact,
                        ]
                    } else {
                        vec![DisposableRootDeleteAttempt::Ambiguous]
                    },
                )),
                delete_authorization_ids: Mutex::new(Vec::new()),
            });
            let effect = LifecycleStepEffect {
                credentials: None,
                physical: Arc::new(NeverLifecyclePhysical),
                volume_transition: Arc::clone(&port) as Arc<dyn SignedLifecycleVolumePort>,
                volume_authority: Arc::new(UnavailableVolumeAuthority),
                #[cfg(feature = "proposed-node-residue-reclamation")]
                data_directory_reclaim: None,
            };
            let context = deleting_effect_context(&directory, &desired, runtime);
            let outcome = effect.try_apply(&context, &desired).unwrap().unwrap();
            assert_eq!(port.evidence_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                port.delete_calls.load(Ordering::SeqCst),
                usize::from(!already_deleting),
                "{already_deleting}/{fault:?}"
            );
            assert_eq!(
                outcome,
                match (fault, retry_unconsumed, already_deleting) {
                    (Some(_), _, _) | (None, true, true) => stop_local(),
                    (None, true, false) => RuntimeDesiredEffectOutcome::RetryExact,
                    (None, false, _) => RuntimeDesiredEffectOutcome::refresh_inventory(),
                },
                "{already_deleting}/{retry_unconsumed}/{fault:?}"
            );
            if retry_unconsumed && !already_deleting {
                assert_eq!(
                    effect.try_apply(&context, &desired).unwrap(),
                    Some(RuntimeDesiredEffectOutcome::RetryExact)
                );
                assert_eq!(port.evidence_calls.load(Ordering::SeqCst), 1);
                assert_eq!(port.delete_calls.load(Ordering::SeqCst), 2);
                assert_eq!(
                    *port.delete_authorization_ids.lock().unwrap(),
                    vec![
                        request.authorization_id.clone(),
                        request.authorization_id.clone(),
                    ]
                );
            }
            let reopened =
                FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id).unwrap();
            assert_eq!(reopened.load().unwrap().unwrap().checkpoint(), &checkpoint);
        }
    }

    #[test]
    fn unconsumed_root_delete_retry_rejects_every_mismatched_authority_field() {
        for fault in [
            "authorization_id",
            "decision_id",
            "desired_revision",
            "volume_id",
            "owner",
            "epoch",
            "head",
        ] {
            let (desired, intent, request, expected_epoch, expected_head, mut recovery) =
                unconsumed_disposable_evidence_fixture();
            let VolumeEvidenceRecovery::Validated { evidence, decision } = &mut recovery else {
                unreachable!()
            };
            match fault {
                "authorization_id" => {
                    let VolumeAuthorization::DisposableRootDelete(authorization) =
                        &mut evidence.authorization.authorization
                    else {
                        unreachable!()
                    };
                    authorization.authorization_id = Id::new("wrong_authorization").unwrap();
                }
                "decision_id" => {
                    **decision = VolumeEvidenceRecoveryDecision::RetryOriginalAuthorization {
                        authorization_id: Id::new("wrong_decision_authorization").unwrap(),
                    };
                }
                "desired_revision" => {
                    let VolumeAuthorization::DisposableRootDelete(authorization) =
                        &mut evidence.authorization.authorization
                    else {
                        unreachable!()
                    };
                    authorization.desired_revision =
                        cats_api::runtime_reconciliation::Revision::new(
                            desired.desired_revision.get() + 1,
                        )
                        .unwrap();
                }
                "volume_id" => {
                    evidence.current_volume.as_mut().unwrap().volume_id =
                        Id::new("wrong_volume").unwrap();
                }
                "owner" => {
                    evidence.current_volume.as_mut().unwrap().lease_owner =
                        Some(Id::new("wrong_owner").unwrap());
                }
                "epoch" => {
                    evidence.current_volume.as_mut().unwrap().lease_epoch =
                        cats_api::runtime_reconciliation::FenceEpoch::new(expected_epoch.get() + 1)
                            .unwrap();
                }
                "head" => {
                    evidence.current_volume.as_mut().unwrap().head =
                        cats_api::runtime_reconciliation::RemoteHead {
                            generation: cats_api::runtime_reconciliation::Generation::new(0)
                                .unwrap(),
                            root_hash: None,
                            root_object_id: None,
                        };
                }
                _ => unreachable!(),
            }
            assert!(
                !exact_disposable_unconsumed_evidence(
                    &request,
                    &desired,
                    &intent,
                    &request.authorization_id,
                    expected_epoch,
                    &expected_head,
                    evidence,
                    decision,
                ),
                "mismatched {fault} must fail closed"
            );
        }
    }

    #[test]
    fn lifecycle_release_planner_covers_the_complete_multi_volume_set() {
        let (mut desired, mut checkpoint, mut runtime) = fixtures(RuntimeTarget::Cold);
        let mut persistent_intent = desired.volumes[0].clone();
        persistent_intent.volume_intent_id = Id::new("persistent-intent-02").unwrap();
        persistent_intent.disk_id = Id::new("persistent-disk-02").unwrap();
        persistent_intent.volume_id = Id::new("persistent-volume-02").unwrap();
        persistent_intent.attachment_id = Id::new("persistent-attachment-02").unwrap();
        persistent_intent.guest_device.slot = 2;
        persistent_intent.disk_kind = cats_api::runtime_reconciliation::DiskKind::Persistent;
        persistent_intent.disposition = VolumeDisposition::DetachRetained;
        persistent_intent.acquire = VolumeAcquire::Takeover {
            authorization_id: Id::new("persistent-takeover-02").unwrap(),
        };
        persistent_intent.mount = Some(cats_api::runtime_reconciliation::Ext4MountIntent {
            filesystem_uuid: RandomId128::new("88888888888888888888888888888888").unwrap(),
            mount_path: HostPath::new("/data".to_owned()).unwrap(),
            initialization: cats_api::runtime_reconciliation::FilesystemInitialization::Existing,
        });
        let mut persistent = runtime.volumes[0].clone();
        persistent.volume_intent_id = Some(persistent_intent.volume_intent_id.clone());
        persistent.disk_id = Some(persistent_intent.disk_id.clone());
        persistent.volume_id = persistent_intent.volume_id.clone();
        let VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            ..
        } = &mut persistent.authority
        else {
            panic!("fixture volume is not Owned")
        };
        *attachment_id = persistent_intent.attachment_id.clone();
        persistent.local_lineages[0].attachment_id = persistent_intent.attachment_id.clone();
        persistent.local_lineages[0].attachment_epoch = *attachment_epoch;
        persistent.local_lineages[0].acquire_origin =
            cats_api::runtime_reconciliation::AcquireOrigin::Takeover {
                authorization_id: Id::new("persistent-takeover-02").unwrap(),
            };
        persistent.devices.clear();
        desired.volumes.push(persistent_intent);
        runtime.volumes.push(persistent);
        runtime.processes.clear();
        runtime.networks.clear();
        runtime.mounts.clear();
        runtime.guest_transport = GuestTransportEvidence::Unavailable;
        checkpoint.processes.clear();
        checkpoint.networks.clear();
        checkpoint.mounts.clear();
        checkpoint.guest_transport = GuestTransportEvidence::Unavailable;

        let mut plans = canonical_remaining_cleanup(&desired, &runtime, &checkpoint, &[]).unwrap();
        plans.sort_by(|left, right| left.order.cmp(&right.order));
        assert_eq!(plans.len(), 2);
        let planned_ids = plans
            .iter()
            .map(|plan| match &plan.target {
                CleanupTarget::Volume { volume_id, .. } => volume_id.clone(),
                other => panic!("unexpected non-Volume cleanup: {other:?}"),
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            planned_ids,
            desired
                .volumes
                .iter()
                .map(|intent| intent.volume_id.clone())
                .collect()
        );
        assert!(plans.iter().all(|plan| plan.volume_release.is_some()));
    }

    #[test]
    fn superseded_checkpoint_is_not_a_current_effect_permit() {
        let (mut desired, checkpoint, _) = fixtures(RuntimeTarget::Suspended);
        desired.desired_revision = cats_api::runtime_reconciliation::Revision::new(9).unwrap();
        assert!(!checkpoint_is_current(&desired, &checkpoint));
        desired.desired_revision = checkpoint.desired_revision;
        desired.spec_digest = cats_api::runtime_reconciliation::Sha256Digest::new(format!(
            "sha256:{}",
            "f".repeat(64)
        ))
        .unwrap();
        assert!(!checkpoint_is_current(&desired, &checkpoint));
    }

    #[test]
    fn closed_dispatcher_owns_every_n1_variant() {
        let (_, checkpoint, _) = fixtures(RuntimeTarget::Cold);
        let launch = checkpoint.runtime_launch.identity().unwrap();
        let cleanup = cats_api::runtime_reconciliation::CleanupRelease {
            target: CleanupTarget::Network {
                network_id: launch.network.network_config.network_id.clone(),
                ownership_token: launch.network.ownership_token.clone(),
            },
            inventory_session: cats_api::runtime_reconciliation::SessionBinding {
                node_id: checkpoint.node_id.clone(),
                node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                    "11111111111111111111111111111111".to_owned(),
                )
                .unwrap(),
                agent_instance_id: launch.process_identity_token.clone(),
                agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            },
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
            inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
            desired_read_position: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
            volume_release: None,
        };
        let steps = [
            ReconcileStep::DrainPublish {
                volume_id: checkpoint.volumes[0].volume_id.clone(),
                attachment_epoch: match checkpoint.volumes[0].authority {
                    VolumeAuthorityEvidence::Owned {
                        attachment_epoch, ..
                    } => attachment_epoch,
                    _ => panic!("fixture volume not owned"),
                },
                local_generation: cats_api::runtime_reconciliation::Generation::new(1).unwrap(),
                remote_generation: cats_api::runtime_reconciliation::Generation::new(1).unwrap(),
            },
            ReconcileStep::PauseRuntime {
                runtime_incarnation: launch.runtime_incarnation.clone(),
                process_start_time_ticks: cats_api::runtime_reconciliation::WireU64::new(99)
                    .unwrap(),
            },
            ReconcileStep::SnapshotWarmRuntime {
                runtime_incarnation: launch.runtime_incarnation.clone(),
                snapshot_id: cats_api::runtime_reconciliation::Id::new("snapshot_1").unwrap(),
                temporary_path: cats_api::runtime_reconciliation::HostPath::new(
                    "/var/lib/cats/snapshot.tmp".to_owned(),
                )
                .unwrap(),
                source_heads: Vec::new(),
            },
            ReconcileStep::StopRuntime {
                runtime_incarnation: launch.runtime_incarnation.clone(),
                process_start_time_ticks: cats_api::runtime_reconciliation::WireU64::new(99)
                    .unwrap(),
                scope_id: launch.scope_id.clone(),
            },
            ReconcileStep::CleanupRelease { cleanup },
            ReconcileStep::DeleteDisposableRoot {
                authorization_id: cats_api::runtime_reconciliation::Id::new("auth_1").unwrap(),
            },
        ];
        assert!(steps.iter().all(is_lifecycle_step));
    }

    #[test]
    fn first_effect_token_is_never_skipped_across_checkpoint_crashes() {
        for stage in [
            WriteStage::Write,
            WriteStage::TempWritten,
            WriteStage::FileSynced,
            WriteStage::Renamed,
            WriteStage::DirectorySynced,
        ] {
            let (_, predecessor, runtime) = fixtures(RuntimeTarget::Suspended);
            let mut successor = predecessor.clone();
            successor.stable_state = None;
            successor.step = first_lifecycle_step(&fixtures(RuntimeTarget::Suspended).0, &runtime)
                .unwrap()
                .unwrap();
            encode_runtime_checkpoint(&predecessor).unwrap();
            encode_runtime_checkpoint(&successor).unwrap();

            let directory = TempDir::new().unwrap();
            let store = FileCheckpointStore::open(directory.path(), &predecessor.cat_id).unwrap();
            let stored = store.create(&predecessor).unwrap();
            let context = RuntimeDesiredEffectContext::for_test(
                crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            );
            let current = store.assert_current(&stored).unwrap();
            store.inject_crash_once(stage);
            assert!(persist_lifecycle_successor(
                &context,
                &store,
                &stored,
                &successor,
                &current,
                "test lifecycle checkpoint crash",
            )
            .is_err());
            drop(current);
            drop(store);

            let reopened =
                FileCheckpointStore::open(directory.path(), &predecessor.cat_id).unwrap();
            let recovered = reopened.load().unwrap().unwrap();
            let published = matches!(stage, WriteStage::Renamed | WriteStage::DirectorySynced);
            assert_eq!(
                recovered.checkpoint(),
                if published { &successor } else { &predecessor },
                "wrong durable token boundary after {stage:?}"
            );
        }
    }

    #[test]
    fn exact_volume_release_successor_is_atomic_across_checkpoint_crashes() {
        for stage in [
            WriteStage::Write,
            WriteStage::TempWritten,
            WriteStage::FileSynced,
            WriteStage::Renamed,
            WriteStage::DirectorySynced,
        ] {
            let (desired, mut predecessor, mut runtime) = fixtures(RuntimeTarget::Cold);
            predecessor.processes.clear();
            predecessor.networks.clear();
            predecessor.mounts.clear();
            predecessor.guest_transport = GuestTransportEvidence::Unavailable;
            runtime.processes.clear();
            runtime.networks.clear();
            runtime.mounts.clear();
            runtime.guest_transport = GuestTransportEvidence::Unavailable;
            let plans = canonical_remaining_cleanup(&desired, &runtime, &predecessor, &[]).unwrap();
            let release = plans
                .into_iter()
                .find(|plan| matches!(plan.target, CleanupTarget::Volume { .. }))
                .unwrap();
            predecessor.stable_state = None;
            predecessor.runtime_incarnation = None;
            predecessor.runtime_launch = RuntimeLaunch::Absent;
            predecessor.step = ReconcileStep::CleanupRelease {
                cleanup: CleanupRelease {
                    target: release.target,
                    inventory_session: SessionBinding {
                        node_id: predecessor.node_id.clone(),
                        node_boot_id: cats_api::runtime_reconciliation::NodeBootId::new(
                            "11111111111111111111111111111111".to_owned(),
                        )
                        .unwrap(),
                        agent_instance_id: RandomId128::new("99999999999999999999999999999999")
                            .unwrap(),
                        agent_session_epoch: cats_api::runtime_reconciliation::Epoch::new(1)
                            .unwrap(),
                    },
                    inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
                    inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(1)
                        .unwrap(),
                    desired_read_position: cats_api::runtime_reconciliation::Sequence::new(1)
                        .unwrap(),
                    volume_release: release.volume_release,
                },
            };
            let (attachment_epoch, head) = match &runtime.volumes[0].authority {
                VolumeAuthorityEvidence::Owned {
                    attachment_epoch,
                    head,
                    ..
                } => (*attachment_epoch, head.clone()),
                _ => panic!("fixture volume is not Owned"),
            };
            runtime.volumes[0].authority = VolumeAuthorityEvidence::Unowned {
                attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(
                    attachment_epoch.get() + 1,
                )
                .unwrap(),
                head,
            };
            runtime.volumes[0].local_lineages.clear();
            let cursor = FreshCleanupCursor {
                session: match &predecessor.step {
                    ReconcileStep::CleanupRelease { cleanup } => cleanup.inventory_session.clone(),
                    _ => unreachable!(),
                },
                inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(2).unwrap(),
                inventory_read_position: cats_api::runtime_reconciliation::Sequence::new(2)
                    .unwrap(),
                desired_read_position: cats_api::runtime_reconciliation::Sequence::new(2).unwrap(),
                observed_at: cats_api::runtime_reconciliation::UnixMillis::new(1_800_000_000_000)
                    .unwrap(),
            };
            let successor =
                cleanup_postcondition_successor_at(&desired, &runtime, &predecessor, &[], &cursor)
                    .unwrap()
                    .unwrap();
            assert!(matches!(
                successor.step,
                ReconcileStep::Stable {
                    state: StableState::Cold
                }
            ));

            let directory = TempDir::new().unwrap();
            let store = FileCheckpointStore::open(directory.path(), &predecessor.cat_id).unwrap();
            let stored = store.create(&predecessor).unwrap();
            let context = RuntimeDesiredEffectContext::for_test(
                crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            );
            let current = store.assert_current(&stored).unwrap();
            store.inject_crash_once(stage);
            assert!(persist_lifecycle_successor(
                &context,
                &store,
                &stored,
                &successor,
                &current,
                "test exact Volume release successor crash",
            )
            .is_err());
            drop(current);
            drop(store);

            let reopened =
                FileCheckpointStore::open(directory.path(), &predecessor.cat_id).unwrap();
            let recovered = reopened.load().unwrap().unwrap();
            let published = matches!(stage, WriteStage::Renamed | WriteStage::DirectorySynced);
            assert_eq!(
                recovered.checkpoint(),
                if published { &successor } else { &predecessor },
                "wrong Volume successor boundary after {stage:?}"
            );
        }
    }

    #[test]
    fn cancellation_before_lifecycle_checkpoint_cas_changes_nothing() {
        let (_, predecessor, runtime) = fixtures(RuntimeTarget::Suspended);
        let mut successor = predecessor.clone();
        successor.stable_state = None;
        successor.step = first_lifecycle_step(&fixtures(RuntimeTarget::Suspended).0, &runtime)
            .unwrap()
            .unwrap();
        let directory = TempDir::new().unwrap();
        let store = FileCheckpointStore::open(directory.path(), &predecessor.cat_id).unwrap();
        let stored = store.create(&predecessor).unwrap();
        let context = RuntimeDesiredEffectContext::for_test(
            crate::state_directory::StateDirectory::unanchored(directory.path().to_path_buf()),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        let current = store.assert_current(&stored).unwrap();
        context.cancel_for_test();
        assert!(persist_lifecycle_successor(
            &context,
            &store,
            &stored,
            &successor,
            &current,
            "test cancelled lifecycle checkpoint",
        )
        .is_err());
        drop(current);
        assert_eq!(store.load().unwrap().unwrap().checkpoint(), &predecessor);
    }
}
