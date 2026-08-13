//! Checkpoint-first dispatch for the closed lifecycle/cleanup suffix.
//!
//! This module deliberately owns the complete N1 step set.  A step which has
//! no installed exact physical adapter is still consumed here and returns a
//! fresh-inventory decision; it must never fall through to the Running
//! acquire planner or to a legacy teardown path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, CheckpointEvidence, CleanupTarget, DesiredRuntimeSpec, HostPath, Id,
    LifecycleAdmission, NodeResidue, ObservedDevice, ObservedRuntimeStatus, OwnershipTokenEvidence,
    ProcessEvidence, ProcessRole, ReconcileStep, RuntimeCheckpoint, RuntimeTarget, StableState,
    VolumeAuthorityEvidence, VolumeHeadEvidence, WarmSnapshotEvidence,
};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
};

use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::prepare_device_retirement::unique_runtime;
use super::{FileCheckpointStore, StoredCheckpoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// Opaque, current-checkpoint permit passed to one sealed lifecycle adapter.
/// Public observations cannot construct this value.
pub(crate) struct LifecycleEffectPermit<'a> {
    desired: &'a DesiredRuntimeSpec,
    runtime: &'a ObservedRuntimeStatus,
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

#[derive(Debug)]
struct PlatformLifecyclePhysicalPort {
    network_ip_binary: PathBuf,
}

impl LifecyclePhysicalPort for PlatformLifecyclePhysicalPort {
    fn apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        permit: LifecycleEffectPermit<'_>,
    ) -> anyhow::Result<LifecyclePhysicalAttempt> {
        let _accepted_projection = permit.runtime();
        if let ReconcileStep::CleanupRelease { cleanup } = &permit.checkpoint().step {
            if let CleanupTarget::Network {
                network_id,
                ownership_token,
            } = &cleanup.target
            {
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
                let Some(expected) = admitted.expected_networks(&permit.desired().cat_id, identity)
                else {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                };
                if permit.runtime().networks != expected {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                }
                if expected.is_empty() {
                    return Ok(LifecyclePhysicalAttempt::ExactPostcondition);
                }
                let _node_global = context.lock_node_global_effect()?;
                let admitted = context.node_global_network()?;
                if !admitted.matches_observation(accepted.observation())
                    || !admitted.has_exact_network(&permit.desired().cat_id, identity)
                {
                    return Ok(LifecyclePhysicalAttempt::Conflict);
                }
                context.check_active()?;
                let network = crate::ch::ChNetwork {
                    tap: identity.tap_name.as_str().to_owned(),
                    ownership_token: identity.ownership_token.clone(),
                    config: identity.network_config.clone(),
                };
                let _ =
                    crate::ch::remove_network_bounded(&self.network_ip_binary, &network, context);
                return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous);
            }
            return classify_unadapted_cleanup(context, &permit, &cleanup.target);
        }
        let ReconcileStep::PauseRuntime {
            runtime_incarnation,
            process_start_time_ticks,
        } = &permit.checkpoint().step
        else {
            // Drain needs a Guest quiesce+exact blockd proof, snapshot needs
            // a durable temp/rename owner, stop needs a pidfd/systemd exact
            // stop receipt, and cleanup needs target-specific retained
            // handles.  None may be approximated by a pathname operation.
            return Ok(LifecyclePhysicalAttempt::Unavailable);
        };
        let accepted = context.accepted_full()?;
        let processes = context.node_global_process()?;
        if !processes.matches_observation(accepted.observation()) {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        let Some((expected, Some(exact))) = processes.vmm(&permit.desired().cat_id) else {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        };
        if expected.checkpoint() != permit.checkpoint()
            || exact.expectation().runtime_incarnation() != runtime_incarnation
            || exact.evidence().process_start_time_ticks() != *process_start_time_ticks
        {
            return Ok(LifecyclePhysicalAttempt::Conflict);
        }
        match exact.evidence().state() {
            cats_api::runtime_reconciliation::ProcessState::Paused => {
                Ok(LifecyclePhysicalAttempt::ExactPostcondition)
            }
            cats_api::runtime_reconciliation::ProcessState::Running => {
                exact.assert_current(context)?;
                context.check_active()?;
                let Some(remaining) = context.deadline().checked_duration_since(Instant::now())
                else {
                    return Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous);
                };
                // Any return after connecting to the VMM is an ambiguous
                // external outcome.  A fresh full scan is the only oracle.
                let _ = crate::ch::pause_bounded(
                    Path::new(exact.evidence().api_socket_path().as_str()),
                    remaining,
                );
                Ok(LifecyclePhysicalAttempt::SubmittedOrAmbiguous)
            }
        }
    }
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
}

impl LifecycleStepEffect {
    pub(crate) fn platform(network_ip_binary: PathBuf) -> Self {
        Self {
            physical: Arc::new(PlatformLifecyclePhysicalPort { network_ip_binary }),
        }
    }

    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        context.check_active()?;
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired)? else {
            return Ok(None);
        };

        if !is_lifecycle_step(&runtime.step) {
            if let Some(outcome) = self.plan_first(context, desired, runtime)? {
                return Ok(Some(outcome));
            }
            return Ok(None);
        }
        if matches!(
            &runtime.step,
            ReconcileStep::CleanupRelease {
                cleanup: cats_api::runtime_reconciliation::CleanupRelease {
                    target: CleanupTarget::Volume { .. },
                    ..
                }
            }
        ) {
            // Volume cleanup remains owned by the signed A22 transition
            // planner.  N1 owns every other CleanupTarget and must not turn a
            // local physical adapter into storage authority.
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
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
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
            // A late pause/stop is containable only by the current revision's
            // explicit repair plan.  This stale invocation performs no I/O.
            return Ok(Some(stop_local()));
        }
        if let ReconcileStep::CleanupRelease { cleanup } = &runtime.step {
            if !cleanup_is_fresh(accepted, cleanup) {
                return Ok(Some(stop_local()));
            }
        }

        context.check_active()?;
        let current = store
            .assert_current(&stored)
            .context("retain exact lifecycle checkpoint across one physical effect")?;
        let attempt = self.physical.apply(
            context,
            LifecycleEffectPermit {
                desired,
                runtime,
                stored: &stored,
            },
        )?;
        // A successful mutation can legitimately change the physical target,
        // but never the durable token which authorized it.
        store
            .revalidate_current(&stored, &current)
            .context("revalidate lifecycle checkpoint after physical effect")?;
        drop(current);
        if attempt == LifecyclePhysicalAttempt::ExactPostcondition {
            if let Some(successor) = exact_postcondition_successor(
                context.state_directory().path(),
                desired,
                runtime,
                stored.checkpoint(),
            )? {
                encode_runtime_checkpoint(&successor)
                    .context("validate settled lifecycle successor checkpoint")?;
                store
                    .replace(&stored, &successor)
                    .context("settle exact lifecycle postcondition")?;
            }
        }
        Ok(Some(match attempt {
            LifecyclePhysicalAttempt::SubmittedOrAmbiguous
            | LifecyclePhysicalAttempt::ExactPostcondition
            | LifecyclePhysicalAttempt::Unavailable => {
                RuntimeDesiredEffectOutcome::RefreshInventory
            }
            LifecyclePhysicalAttempt::Conflict => stop_local(),
        }))
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
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
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
        persist_first_lifecycle_step(&store, &stored, &successor)?;
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }
}

fn exact_postcondition_successor(
    state_directory: &Path,
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
        RuntimeTarget::Warm => {
            let snapshot_id = Id::new(format!("warm-{runtime_incarnation}"))
                .context("derive Warm snapshot identity")?;
            let temporary_path = HostPath::new(
                state_directory
                    .join("warm-snapshots")
                    .join(format!(".{snapshot_id}.tmp"))
                    .to_string_lossy()
                    .into_owned(),
            )
            .context("derive Warm snapshot temporary path")?;
            ReconcileStep::SnapshotWarmRuntime {
                runtime_incarnation: runtime_incarnation.clone(),
                snapshot_id,
                temporary_path,
                source_heads: fully_drained_source_heads(desired, runtime)?,
            }
        }
        RuntimeTarget::Cold | RuntimeTarget::Deleted => ReconcileStep::StopRuntime {
            runtime_incarnation: runtime_incarnation.clone(),
            process_start_time_ticks: *process_start_time_ticks,
            scope_id: process.scope_id.clone(),
        },
        RuntimeTarget::Running => {
            anyhow::bail!("current Running Desired cannot settle PauseRuntime")
        }
    };
    Ok(Some(successor))
}

fn fully_drained_source_heads(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
) -> anyhow::Result<Vec<VolumeHeadEvidence>> {
    let mut heads = Vec::with_capacity(runtime.volumes.len());
    for volume in &runtime.volumes {
        let VolumeAuthorityEvidence::Owned {
            attachment_epoch,
            head,
            ..
        } = &volume.authority
        else {
            anyhow::bail!("Warm snapshot source is not exact Owned authority")
        };
        let exact = volume.local_lineages.iter().filter(|lineage| {
            lineage.attachment_epoch == *attachment_epoch
                && lineage.node_id == desired.placement.node_id
                && lineage.placement_epoch == desired.placement.placement_epoch
                && lineage.local_durable_generation == head.generation
                && lineage.remote_durable_generation == head.generation
        });
        anyhow::ensure!(
            exact.count() == 1,
            "Warm snapshot source is not one exact fully drained lineage"
        );
        heads.push(VolumeHeadEvidence {
            volume_id: volume.volume_id.clone(),
            attachment_epoch: *attachment_epoch,
            head: head.clone(),
        });
    }
    heads.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    Ok(heads)
}

fn persist_first_lifecycle_step(
    store: &FileCheckpointStore,
    predecessor: &StoredCheckpoint,
    successor: &RuntimeCheckpoint,
) -> anyhow::Result<()> {
    store
        .replace(predecessor, successor)
        .context("persist first lifecycle step before physical effect")?;
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
    let session = accepted.session();
    let attestation = accepted.attestation();
    cleanup.inventory_session.node_id == session.node_id
        && cleanup.inventory_session.node_boot_id == session.node_boot_id
        && cleanup.inventory_session.agent_instance_id == session.agent_instance_id
        && cleanup.inventory_session.agent_session_epoch == session.agent_session_epoch
        && cleanup.inventory_epoch == attestation.inventory_epoch
        && cleanup.inventory_read_position == attestation.inventory_read_position
        && accepted
            .desired_read_position()
            .is_some_and(|position| position >= cleanup.desired_read_position)
        && match &cleanup.target {
            CleanupTarget::Volume { .. } => cleanup.volume_release.is_some(),
            _ => cleanup.volume_release.is_none(),
        }
}

fn first_lifecycle_step(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
) -> anyhow::Result<Option<ReconcileStep>> {
    if desired.target == RuntimeTarget::Running {
        return Ok(None);
    }
    // An accepted R==L observation predates this effect batch and says
    // nothing about Guest/page-cache writes after the scan.  Every departure
    // from Running therefore starts with a fresh quiesce+durability token;
    // Pause/Stop may only be selected by a later exact Drain postcondition.
    let _vmm = exact_vmm_process(runtime)?;
    anyhow::ensure!(
        !desired.volumes.is_empty() && runtime.volumes.len() == desired.volumes.len(),
        "lifecycle drain planner lacks the complete Desired volume set"
    );
    let first = desired
        .volumes
        .iter()
        .min_by_key(|volume| volume.guest_device.slot)
        .context("lifecycle drain planner lacks a canonical first volume")?;
    let mut observed = runtime
        .volumes
        .iter()
        .filter(|observed| observed.volume_id == first.volume_id);
    let volume = observed
        .next()
        .context("lifecycle drain planner lacks the first Desired volume")?;
    anyhow::ensure!(
        observed.next().is_none()
            && volume.volume_intent_id.as_ref() == Some(&first.volume_intent_id)
            && volume.disk_id.as_ref() == Some(&first.disk_id),
        "lifecycle drain planner found an ambiguous first Desired volume"
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
        attachment_id == &first.attachment_id,
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
    Ok(Some(ReconcileStep::DrainPublish {
        volume_id: volume.volume_id.clone(),
        attachment_epoch: *attachment_epoch,
        local_generation: lineage.local_durable_generation,
        remote_generation: lineage.remote_durable_generation,
    }))
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
    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, ProcessState, RuntimeLaunch,
    };
    use tempfile::TempDir;

    use super::super::checkpoint::WriteStage;

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

    #[test]
    fn r_equals_l_still_requires_drain_before_any_pause_or_stop() {
        for target in [
            RuntimeTarget::Suspended,
            RuntimeTarget::Warm,
            RuntimeTarget::Cold,
            RuntimeTarget::Deleted,
        ] {
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
    fn planner_drains_exact_owned_lineage_before_pausing() {
        let (desired, _, mut runtime) = fixtures(RuntimeTarget::Suspended);
        let lineage = &mut runtime.volumes[0].local_lineages[0];
        lineage.local_durable_generation =
            cats_api::runtime_reconciliation::Generation::new(2).unwrap();
        lineage.remote_durable_generation =
            cats_api::runtime_reconciliation::Generation::new(1).unwrap();
        assert!(matches!(
            first_lifecycle_step(&desired, &runtime).unwrap(),
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
            successor.step,
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
            store.inject_crash_once(stage);
            assert!(persist_first_lifecycle_step(&store, &stored, &successor).is_err());
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
}
