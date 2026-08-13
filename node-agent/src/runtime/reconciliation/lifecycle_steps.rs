//! Checkpoint-first dispatch for the closed lifecycle/cleanup suffix.
//!
//! This module deliberately owns the complete N1 step set.  A step which has
//! no installed exact physical adapter is still consumed here and returns a
//! fresh-inventory decision; it must never fall through to the Running
//! acquire planner or to a legacy teardown path.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, CheckpointEvidence, CleanupRelease, CleanupTarget,
    DesiredRuntimeSpec, GuestTransportEvidence, HostPath, Id, LifecycleAdmission, NodeResidue,
    ObservedDevice, ObservedRuntimeStatus, OwnershipTokenEvidence, ProcessEvidence, ProcessRole,
    RandomId128, ReconcileStep, RuntimeCheckpoint, RuntimeLaunch, RuntimeTarget, SessionBinding,
    StableState, VolumeAuthorityEvidence, VolumeDisposition, VolumeHeadEvidence,
    VolumeReleaseReplay, WarmSnapshotEvidence,
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
                let NetworkCleanupPlan::Remove(network) = plan_network_cleanup(identity, &expected)
                else {
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
        if attempt == LifecyclePhysicalAttempt::ExactPostcondition {
            let successor = if matches!(
                stored.checkpoint().step,
                ReconcileStep::CleanupRelease { .. }
            ) {
                cleanup_postcondition_successor(accepted, desired, runtime, stored.checkpoint())?
            } else {
                exact_postcondition_successor(
                    context.state_directory().path(),
                    desired,
                    runtime,
                    stored.checkpoint(),
                )?
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
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }
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
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let Some(desired_read_position) = accepted.desired_read_position() else {
        anyhow::bail!("cleanup successor planner lacks a current Desired read position")
    };
    let cursor = FreshCleanupCursor {
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
    };
    cleanup_postcondition_successor_at(
        desired,
        runtime,
        checkpoint,
        accepted.observation().residue.as_slice(),
        &cursor,
    )
}

fn cleanup_postcondition_successor_at(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
    cursor: &FreshCleanupCursor,
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let ReconcileStep::CleanupRelease { cleanup: completed } = &checkpoint.step else {
        anyhow::bail!("cleanup successor planner received another lifecycle step")
    };
    anyhow::ensure!(
        cleanup_target_is_absent(completed, runtime, residue),
        "cleanup successor planner did not receive the exact target-absent postcondition"
    );
    let mut plans = canonical_remaining_cleanup(desired, runtime, checkpoint, residue)?;
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
                "Volume cleanup cannot retire the retained launch while runtime residue remains"
            );
            successor.runtime_incarnation = None;
            successor.runtime_launch = RuntimeLaunch::Absent;
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
        CleanupTarget::Volume { .. } | CleanupTarget::CheckpointFile { .. } => false,
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

fn canonical_remaining_cleanup(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
    checkpoint: &RuntimeCheckpoint,
    residue: &[NodeResidue],
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

    if desired.target != RuntimeTarget::Warm {
        if let WarmSnapshotEvidence::Present { snapshot_id, .. } = &runtime.warm_snapshot {
            plans.push(PlannedCleanup {
                order: format!("3-warm-snapshot-{snapshot_id}"),
                target: CleanupTarget::WarmSnapshot {
                    snapshot_id: snapshot_id.clone(),
                },
                volume_release: None,
            });
        }
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

    if matches!(desired.target, RuntimeTarget::Cold | RuntimeTarget::Deleted) {
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
                    if matches!(
                        intent.disposition,
                        VolumeDisposition::DeleteDisposableRoot { .. }
                    ) {
                        // A normal release cannot authorize discarding a Root
                        // tail.  A2 must first consume the exact V2 delete
                        // authorization and expose Deleting evidence; N1 must
                        // not synthesize that transition from Desired alone.
                        continue;
                    }
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
                    });
                    anyhow::ensure!(
                        exact.next().is_some() && exact.next().is_none(),
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
            anyhow::ensure!(
                matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Present { .. })
                    && runtime.volumes.iter().all(|volume| matches!(
                        volume.authority,
                        VolumeAuthorityEvidence::Owned { .. }
                    )),
                "Warm cleanup successor lacks its durable snapshot"
            );
            StableState::Warm
        }
        RuntimeTarget::Cold => {
            anyhow::ensure!(
                matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
                    && runtime.volumes.iter().all(|volume| matches!(
                        volume.authority,
                        VolumeAuthorityEvidence::Unowned { .. }
                    )),
                "Cold cleanup successor retains a Warm snapshot"
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
        assert!(successor.runtime_incarnation.is_none());
        assert!(matches!(successor.runtime_launch, RuntimeLaunch::Absent));
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
            cleanup_postcondition_successor_at(&desired, &runtime, &checkpoint, &[], &cursor)
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

        assert!(
            cleanup_postcondition_successor_at(&desired, &runtime, &checkpoint, &[], &cursor,)
                .unwrap()
                .is_none()
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
