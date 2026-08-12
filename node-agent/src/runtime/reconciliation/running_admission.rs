//! Sealed Ready-to-admission handoff for the Running tail.
//!
//! Public `ObservedRuntimeStatus` fields are consistency projections, never
//! authority to open a cell. One complete scanner pass may attach the opaque
//! scan admission below only after provider-private storage, frontend,
//! network, live-VMM and Guest Ready proofs agree. The production scanner is
//! the only constructor for that token; the Desired effect must still repeat
//! the complete physical proof immediately before its local gate mutation.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    CheckpointEvidence, DesiredRuntimeSpec, DiskKind, Epoch, GuestTransportEvidence, Id,
    LifecycleAdmission, NodeBootId, NodeObservation, ObservedMount, ObservedRouteGate,
    ObservedRuntimeStatus, PersistentFilesystemBinding, RandomId128, ReadyReason, ReconcileStep,
    RequireIdleCheckpoint, Revision, RouteGateState, RuntimeCheckpoint, RuntimeTarget,
    RuntimeTransition, Sequence, Sha256Digest, StableState, UnixMillis,
};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimePreScanAdmission,
    RuntimePreScanAdmissionContext,
};

use super::checkpoint::{EndpointEffectEdge, EndpointEffectEdgeStatus};
use super::gate_planner::{
    active_install_snapshot, first_endpoint_action, route_binding, validate_gate_barrier_successor,
    EndpointAction,
};
use super::inventory::DesiredCheckpointBinding;
use super::vmm_process::ExactVmmProcessProof;
use super::{
    AdmissionCell, AdmissionCellObservation, AdmissionCellRegistry, AdmissionCellSession,
    AdmissionCellSessionLookup, AdmissionGatePort, AdmissionSnapshot, ExactGuestMountedSetProof,
    FileCheckpointStore, GateSequencer, GuestReadyTransportPort, PersistTimes,
    PlatformGuestReadyTransportPort, RouteRetirementMode, RunningLaunchAuthorityRevalidator,
    StoredCheckpoint,
};

#[cfg(test)]
type AfterRegistryHook = Arc<dyn Fn(&RuntimeDesiredEffectContext) + Send + Sync>;

#[cfg(test)]
type GateBarrierHook = Arc<
    dyn Fn(&FileCheckpointStore, &StoredCheckpoint, &StoredCheckpoint) -> anyhow::Result<()>
        + Send
        + Sync,
>;

#[cfg(test)]
pub(crate) type LaunchRevalidationHook = Arc<
    dyn Fn(
            &RuntimeDesiredEffectContext,
            &DesiredRuntimeSpec,
            &FileCheckpointStore,
            &StoredCheckpoint,
            &StoredCheckpoint,
            &ExactVmmProcessProof,
        ) -> anyhow::Result<()>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunningTailReadyExpectation {
    cat_id: Id,
    desired_revision: Revision,
    spec_digest: Sha256Digest,
    placement: cats_api::runtime_reconciliation::AssignedPlacement,
    runtime_incarnation: RandomId128,
    checkpoint_content_digest: Sha256Digest,
    checkpoint: RuntimeCheckpoint,
    guest_transport: GuestTransportEvidence,
    mounts: Vec<ObservedMount>,
    // These fields come from the private AdmissionCell/Route machine scan.
    // `bind` only checks their public projection; public routes can never
    // construct this expectation.
    cell_presence: RunningTailCellPresence,
    cell: AdmissionCellObservation,
    routes: Vec<ObservedRouteGate>,
    physical: RunningTailPhysicalAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteRetirementExpectation {
    cat_id: Id,
    desired_revision: Revision,
    spec_digest: Sha256Digest,
    checkpoint_binding: DesiredCheckpointBinding,
    checkpoint_content_digest: Sha256Digest,
    checkpoint: RuntimeCheckpoint,
    gate_predecessor: Option<DesiredRuntimeSpec>,
    launch_predecessor: Option<DesiredRuntimeSpec>,
    session_generation: u64,
    cell: AdmissionCellObservation,
    routes: Vec<ObservedRouteGate>,
    mode: RouteRetirementMode,
    physical: Option<RunningTailPhysicalAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RunningTailPhysicalAuthority {
    Exact {
        physical_launch_desired: Box<DesiredRuntimeSpec>,
        vmm: Box<ExactVmmProcessProof>,
        mounted_set: Box<ExactGuestMountedSetProof>,
    },
    #[cfg(test)]
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunningTailCellPresence {
    Absent,
    Present,
}

/// Provider-private result of one complete scan, before it is bound to the
/// exact public observation. Only the production full scanner constructs an
/// exact entry, after all physical authorities agree in the same pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunningTailScanAdmission {
    ready: BTreeMap<Id, RunningTailReadyExpectation>,
    retiring: BTreeMap<Id, RouteRetirementExpectation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunningTailReadyAdmission {
    expectation: RunningTailReadyExpectation,
}

/// Accepted current-process proof retained only in the Desired effect batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunningTailAdmission {
    observation_id: RandomId128,
    node_id: Id,
    node_boot_id: NodeBootId,
    agent_instance_id: RandomId128,
    agent_session_epoch: Epoch,
    inventory_epoch: Epoch,
    inventory_digest: Sha256Digest,
    inventory_read_position: Sequence,
    ready: BTreeMap<Id, RunningTailReadyAdmission>,
    retiring: BTreeMap<Id, RouteRetirementExpectation>,
}

impl RunningTailScanAdmission {
    pub(crate) fn empty() -> Self {
        Self {
            ready: BTreeMap::new(),
            retiring: BTreeMap::new(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ready.is_empty() && self.retiring.is_empty()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the scanner seals one closed physical/checkpoint/cell authority tuple"
    )]
    pub(crate) fn insert_exact(
        &mut self,
        physical_launch_desired: DesiredRuntimeSpec,
        desired: &DesiredRuntimeSpec,
        checkpoint: &RuntimeCheckpoint,
        checkpoint_content_digest: Sha256Digest,
        vmm: ExactVmmProcessProof,
        mounted_set: ExactGuestMountedSetProof,
        observed_cell: Option<AdmissionCellObservation>,
    ) -> anyhow::Result<()> {
        let runtime_incarnation = checkpoint
            .runtime_incarnation
            .clone()
            .context("Running-tail checkpoint lacks a runtime incarnation")?;
        let launch = checkpoint
            .runtime_launch
            .identity()
            .context("Running-tail checkpoint lacks retained launch authority")?;
        super::authorized_blockd::validate_running_physical_desired_successor(
            &physical_launch_desired,
            desired,
        )?;
        anyhow::ensure!(
            desired.target == RuntimeTarget::Running
                && checkpoint.cat_id == desired.cat_id
                && checkpoint.desired_revision == desired.desired_revision
                && checkpoint.spec_digest == desired.spec_digest
                && checkpoint.node_id == desired.placement.node_id
                && checkpoint.placement_epoch == desired.placement.placement_epoch
                && launch.runtime_incarnation == runtime_incarnation
                && vmm.expectation().checkpoint() == checkpoint
                && vmm.expectation().launch_identity() == launch
                && matches!(
                    mounted_set.guest_transport(),
                    GuestTransportEvidence::VsockReady {
                        runtime_incarnation: ready_incarnation,
                        guest_cid,
                        ..
                    } if ready_incarnation == &runtime_incarnation
                        && *guest_cid == launch.guest_cid
                ),
            "Running-tail physical authority conflicts with Desired/checkpoint"
        );

        let (cell_presence, cell) = match observed_cell {
            Some(cell) => (RunningTailCellPresence::Present, cell),
            None => {
                let snapshot = AdmissionSnapshot::from_checkpoint(checkpoint)?.fail_closed();
                let cell = AdmissionCell::new(snapshot)?.observe();
                (RunningTailCellPresence::Absent, cell)
            }
        };
        anyhow::ensure!(
            cell.snapshot().applied_desired_revision() == desired.desired_revision
                && cell.snapshot().spec_digest() == &desired.spec_digest
                && cell.snapshot().placement() == &desired.placement
                && cell.snapshot().runtime_incarnation() == Some(&runtime_incarnation),
            "Running-tail AdmissionCell differs from Desired/checkpoint"
        );
        let routes = projected_routes(&cell);
        let expectation = RunningTailReadyExpectation {
            cat_id: desired.cat_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            runtime_incarnation,
            checkpoint_content_digest,
            checkpoint: checkpoint.clone(),
            guest_transport: mounted_set.guest_transport().clone(),
            mounts: mounted_set.mounts().to_vec(),
            cell_presence,
            cell,
            routes,
            physical: RunningTailPhysicalAuthority::Exact {
                physical_launch_desired: Box::new(physical_launch_desired),
                vmm: Box::new(vmm),
                mounted_set: Box::new(mounted_set),
            },
        };
        anyhow::ensure!(
            self.ready
                .insert(desired.cat_id.clone(), expectation)
                .is_none(),
            "Running-tail scan repeats one Cat"
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_route_retirement(
        &mut self,
        desired: &DesiredRuntimeSpec,
        checkpoint: &RuntimeCheckpoint,
        checkpoint_binding: DesiredCheckpointBinding,
        checkpoint_content_digest: Sha256Digest,
        gate_predecessor: Option<DesiredRuntimeSpec>,
        launch_predecessor: Option<DesiredRuntimeSpec>,
        session_generation: u64,
        cell: AdmissionCellObservation,
        mode: RouteRetirementMode,
        physical: Option<(ExactVmmProcessProof, ExactGuestMountedSetProof)>,
    ) -> anyhow::Result<()> {
        let launch = checkpoint
            .runtime_launch
            .identity()
            .context("route retirement lacks retained launch authority")?;
        anyhow::ensure!(
            checkpoint.cat_id == desired.cat_id
                && checkpoint.node_id == desired.placement.node_id
                && checkpoint.placement_epoch == desired.placement.placement_epoch
                && checkpoint.runtime_incarnation.as_ref() == Some(&launch.runtime_incarnation)
                && gate_predecessor.as_ref().is_none_or(|predecessor| {
                    predecessor.target == RuntimeTarget::Running
                        && predecessor.cat_id == checkpoint.cat_id
                })
                && launch_predecessor.as_ref().is_none_or(|predecessor| {
                    predecessor.target == RuntimeTarget::Running
                        && predecessor.cat_id == checkpoint.cat_id
                })
                && session_generation != 0
                && !self.ready.contains_key(&desired.cat_id),
            "route-retirement authority conflicts with Desired/checkpoint"
        );
        if let (Some(launch), Some(gate)) = (launch_predecessor.as_ref(), gate_predecessor.as_ref())
        {
            super::authorized_blockd::validate_running_physical_desired_successor(launch, gate)
                .context(
                    "route-retirement live-gate Desired conflicts with immutable launch provenance",
                )?;
        }
        let physical_launch_desired = launch_predecessor.clone();
        let physical = physical
            .map(|(vmm, mounted_set)| {
                let physical_launch_desired = physical_launch_desired
                    .clone()
                    .context("route install lacks immutable launch provenance")?;
                anyhow::ensure!(
                    vmm.expectation().checkpoint() == checkpoint
                        && vmm.expectation().launch_identity() == launch
                        && matches!(
                            mounted_set.guest_transport(),
                            GuestTransportEvidence::VsockReady {
                                runtime_incarnation,
                                guest_cid,
                                ..
                            } if runtime_incarnation == &launch.runtime_incarnation
                                && *guest_cid == launch.guest_cid
                        ),
                    "route-retirement physical proof conflicts with retained launch"
                );
                Ok(RunningTailPhysicalAuthority::Exact {
                    physical_launch_desired: Box::new(physical_launch_desired),
                    vmm: Box::new(vmm),
                    mounted_set: Box::new(mounted_set),
                })
            })
            .transpose()?;
        let routes = projected_routes(&cell);
        let expectation = RouteRetirementExpectation {
            cat_id: desired.cat_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            checkpoint_binding,
            checkpoint_content_digest,
            checkpoint: checkpoint.clone(),
            gate_predecessor,
            launch_predecessor,
            session_generation,
            cell,
            routes,
            mode,
            physical,
        };
        anyhow::ensure!(
            self.retiring
                .insert(desired.cat_id.clone(), expectation)
                .is_none(),
            "route-retirement scan repeats one Cat"
        );
        Ok(())
    }

    pub(crate) fn project_runtime(
        &self,
        runtime: &mut ObservedRuntimeStatus,
    ) -> anyhow::Result<()> {
        if let Some(expectation) = self.retiring.get(&runtime.cat_id) {
            runtime.lifecycle_admission = expectation.cell.snapshot().lifecycle_admission();
            runtime.platform_guards = expectation.cell.guards().platform_guards;
            runtime.routes = expectation.routes.clone();
            return Ok(());
        }
        let Some(expectation) = self.ready.get(&runtime.cat_id) else {
            return Ok(());
        };
        runtime.guest_transport = expectation.guest_transport.clone();
        runtime.mounts = expectation.mounts.clone();
        runtime.lifecycle_admission = expectation.cell.snapshot().lifecycle_admission();
        runtime.platform_guards = expectation.cell.guards().platform_guards;
        runtime.routes = expectation.routes.clone();
        let checkpoint_cell = AdmissionSnapshot::from_checkpoint(&expectation.checkpoint)?;
        if expectation.cell.snapshot() == &checkpoint_cell
            && expectation.checkpoint.stable_state == Some(StableState::Running)
            && matches!(
                expectation.checkpoint.step,
                ReconcileStep::Stable {
                    state: StableState::Running
                }
            )
        {
            runtime.conditions = vec![cats_api::runtime_reconciliation::Condition::Ready {
                reason: ReadyReason::PostconditionSatisfied {
                    target: RuntimeTarget::Running,
                },
            }];
        }
        Ok(())
    }

    pub(crate) fn bind(
        self,
        observation: &NodeObservation,
    ) -> anyhow::Result<RunningTailAdmission> {
        anyhow::ensure!(
            observation.complete_inventory,
            "Running-tail admission requires a complete observation"
        );
        let inventory_digest = observation
            .inventory_digest
            .clone()
            .context("Running-tail admission lacks inventory digest")?;
        let inventory_read_position = observation
            .inventory_read_position
            .context("Running-tail admission lacks inventory read position")?;
        let mut ready = BTreeMap::new();
        for (cat_id, expectation) in self.ready {
            let mut matches = observation
                .runtimes
                .iter()
                .filter(|runtime| runtime.cat_id == cat_id);
            let runtime = matches
                .next()
                .context("Running-tail proof names a Cat absent from inventory")?;
            anyhow::ensure!(
                matches.next().is_none(),
                "Running-tail inventory repeats one Cat"
            );
            let applied = runtime
                .applied_desired
                .as_ref()
                .context("Running-tail runtime lacks applied Desired evidence")?;
            let CheckpointEvidence::Valid {
                content_digest,
                version,
                cat_id: checkpoint_cat_id,
                node_id,
                placement_epoch,
                desired_revision,
                spec_digest,
                runtime_incarnation,
                runtime_launch,
                stable_state,
                step,
                require_idle,
                updated_at_unix_ms,
                ..
            } = &runtime.checkpoint
            else {
                anyhow::bail!("Running-tail runtime lacks an exact valid checkpoint")
            };
            let checkpoint = &expectation.checkpoint;
            anyhow::ensure!(
                expectation.cat_id == cat_id
                    && checkpoint.cat_id == cat_id
                    && checkpoint_cat_id == &cat_id
                    && checkpoint.version == *version
                    && expectation.desired_revision == *desired_revision
                    && expectation.desired_revision == applied.desired_revision
                    && checkpoint.desired_revision == *desired_revision
                    && expectation.spec_digest == *spec_digest
                    && expectation.spec_digest == applied.spec_digest
                    && checkpoint.spec_digest == *spec_digest
                    && expectation.placement == applied.placement
                    && expectation.placement.node_id == *node_id
                    && expectation.placement.placement_epoch == *placement_epoch
                    && checkpoint.node_id == *node_id
                    && checkpoint.placement_epoch == *placement_epoch
                    && applied.target == RuntimeTarget::Running
                    && runtime.runtime_incarnation.as_ref()
                        == Some(&expectation.runtime_incarnation)
                    && runtime_incarnation.as_ref() == Some(&expectation.runtime_incarnation)
                    && checkpoint.runtime_incarnation.as_ref()
                        == Some(&expectation.runtime_incarnation)
                    && runtime_launch.as_ref() == &checkpoint.runtime_launch
                    && checkpoint.runtime_launch.identity().is_some_and(|launch| {
                        launch.runtime_incarnation == expectation.runtime_incarnation
                    })
                    && checkpoint.stable_state == *stable_state
                    && &checkpoint.step == step.as_ref()
                    && &checkpoint.require_idle == require_idle.as_ref()
                    && checkpoint.updated_at_unix_ms == *updated_at_unix_ms
                    && expectation.checkpoint_content_digest == *content_digest
                    && runtime.guest_transport == expectation.guest_transport
                    && runtime.mounts == expectation.mounts
                    && matches!(
                        &runtime.guest_transport,
                        GuestTransportEvidence::VsockReady {
                            runtime_incarnation,
                            ..
                        } if runtime_incarnation == &expectation.runtime_incarnation
                    )
                    && exact_cell_projection(&expectation, runtime),
                "Running-tail private proof conflicts with its public projection"
            );
            ready.insert(cat_id, RunningTailReadyAdmission { expectation });
        }
        let mut retiring = BTreeMap::new();
        for (cat_id, expectation) in self.retiring {
            let mut matches = observation
                .runtimes
                .iter()
                .filter(|runtime| runtime.cat_id == cat_id);
            let runtime = matches
                .next()
                .context("route-retirement proof names a Cat absent from inventory")?;
            anyhow::ensure!(
                matches.next().is_none()
                    && expectation.cat_id == cat_id
                    && expectation.desired_revision
                        == runtime
                            .applied_desired
                            .as_ref()
                            .context("route-retirement runtime lacks applied Desired")?
                            .desired_revision
                    && expectation.spec_digest
                        == runtime
                            .applied_desired
                            .as_ref()
                            .context("route-retirement runtime lacks applied Desired")?
                            .spec_digest
                    && exact_checkpoint_projection(
                        &expectation.checkpoint,
                        &expectation.checkpoint_content_digest,
                        runtime,
                    )
                    && exact_cell_projection_parts(&expectation.cell, &expectation.routes, runtime,),
                "route-retirement private proof conflicts with its public projection"
            );
            retiring.insert(cat_id, expectation);
        }
        Ok(RunningTailAdmission {
            observation_id: observation.observation_id.clone(),
            node_id: observation.node_id.clone(),
            node_boot_id: observation.node_boot_id.clone(),
            agent_instance_id: observation.agent_instance_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest,
            inventory_read_position,
            ready,
            retiring,
        })
    }

    #[cfg(test)]
    fn for_test_from_authorities(
        observation: &NodeObservation,
        stored: &StoredCheckpoint,
        cell_presence: RunningTailCellPresence,
        cell: AdmissionCellObservation,
        routes: Vec<ObservedRouteGate>,
    ) -> anyhow::Result<Self> {
        let runtime = observation
            .runtimes
            .iter()
            .find(|runtime| runtime.cat_id == stored.checkpoint().cat_id)
            .context("test observation lacks the checkpoint Cat")?;
        let applied = runtime
            .applied_desired
            .as_ref()
            .context("test observation lacks applied Desired")?;
        let runtime_incarnation = stored
            .checkpoint()
            .runtime_incarnation
            .clone()
            .context("test checkpoint lacks a runtime incarnation")?;
        anyhow::ensure!(
            stored.checkpoint().runtime_launch.identity().is_some(),
            "test checkpoint lacks retained launch authority"
        );
        let ready = BTreeMap::from([(
            runtime.cat_id.clone(),
            RunningTailReadyExpectation {
                cat_id: runtime.cat_id.clone(),
                desired_revision: stored.checkpoint().desired_revision,
                spec_digest: stored.checkpoint().spec_digest.clone(),
                placement: applied.placement.clone(),
                runtime_incarnation,
                checkpoint_content_digest: stored.content_digest().clone(),
                checkpoint: stored.checkpoint().clone(),
                guest_transport: runtime.guest_transport.clone(),
                mounts: runtime.mounts.clone(),
                cell_presence,
                cell,
                routes,
                physical: RunningTailPhysicalAuthority::Test,
            },
        )]);
        Ok(Self {
            ready,
            retiring: BTreeMap::new(),
        })
    }
}

fn projected_routes(cell: &AdmissionCellObservation) -> Vec<ObservedRouteGate> {
    cell.snapshot()
        .endpoints()
        .iter()
        .map(|route| {
            let active_guards = cell
                .guards()
                .endpoint_guards
                .iter()
                .find(|count| count.endpoint_id == route.binding.endpoint_id)
                .map_or(0, |count| count.active_guards);
            ObservedRouteGate {
                binding: route.binding.clone(),
                gate: route.gate,
                active_guards,
                cancellation_pending: cell.endpoint_is_revoked(&route.binding.endpoint_id)
                    || (route.gate == RouteGateState::Closed && active_guards != 0),
                instance_count: 1,
            }
        })
        .collect()
}

fn exact_checkpoint_projection(
    checkpoint: &RuntimeCheckpoint,
    expected_digest: &Sha256Digest,
    runtime: &ObservedRuntimeStatus,
) -> bool {
    matches!(
        &runtime.checkpoint,
        CheckpointEvidence::Valid {
            content_digest,
            version,
            cat_id,
            node_id,
            placement_epoch,
            desired_revision,
            spec_digest,
            runtime_incarnation,
            runtime_launch,
            stable_state,
            step,
            require_idle,
            updated_at_unix_ms,
            ..
        } if content_digest == expected_digest
            && *version == checkpoint.version
            && cat_id == &checkpoint.cat_id
            && node_id == &checkpoint.node_id
            && *placement_epoch == checkpoint.placement_epoch
            && *desired_revision == checkpoint.desired_revision
            && spec_digest == &checkpoint.spec_digest
            && runtime_incarnation == &checkpoint.runtime_incarnation
            && runtime_launch.as_ref() == &checkpoint.runtime_launch
            && *stable_state == checkpoint.stable_state
            && step.as_ref() == &checkpoint.step
            && require_idle.as_ref() == &checkpoint.require_idle
            && *updated_at_unix_ms == checkpoint.updated_at_unix_ms
    )
}

impl RunningTailAdmission {
    pub(crate) fn matches_observation(&self, observation: &NodeObservation) -> bool {
        observation.complete_inventory
            && self.observation_id == observation.observation_id
            && self.node_id == observation.node_id
            && self.node_boot_id == observation.node_boot_id
            && self.agent_instance_id == observation.agent_instance_id
            && self.agent_session_epoch == observation.agent_session_epoch
            && self.inventory_epoch == observation.inventory_epoch
            && observation.inventory_digest.as_ref() == Some(&self.inventory_digest)
            && observation.inventory_read_position == Some(self.inventory_read_position)
    }

    fn ready(&self, cat_id: &Id) -> Option<&RunningTailReadyAdmission> {
        self.ready.get(cat_id)
    }

    fn retiring(&self, cat_id: &Id) -> Option<&RouteRetirementExpectation> {
        self.retiring.get(cat_id)
    }
}

fn exact_cell_projection(
    expectation: &RunningTailReadyExpectation,
    runtime: &ObservedRuntimeStatus,
) -> bool {
    if expectation.cell.snapshot().applied_desired_revision() != expectation.desired_revision
        || expectation.cell.snapshot().spec_digest() != &expectation.spec_digest
        || expectation.cell.snapshot().placement() != &expectation.placement
        || expectation.cell.snapshot().runtime_incarnation()
            != Some(&expectation.runtime_incarnation)
    {
        return false;
    }
    exact_cell_projection_parts(&expectation.cell, &expectation.routes, runtime)
}

fn exact_cell_projection_parts(
    cell: &AdmissionCellObservation,
    routes: &[ObservedRouteGate],
    runtime: &ObservedRuntimeStatus,
) -> bool {
    let snapshot = cell.snapshot();
    let guards = cell.guards();
    if runtime.lifecycle_admission != snapshot.lifecycle_admission()
        || runtime.platform_guards != guards.platform_guards
        || runtime.routes != routes
        || snapshot.endpoints().len() != routes.len()
    {
        return false;
    }

    let mut endpoint_guards = BTreeMap::new();
    for count in &guards.endpoint_guards {
        if count.active_guards == 0
            || endpoint_guards
                .insert(count.endpoint_id.clone(), count.active_guards)
                .is_some()
        {
            return false;
        }
    }
    if endpoint_guards.keys().any(|endpoint_id| {
        !snapshot
            .endpoints()
            .iter()
            .any(|route| &route.binding.endpoint_id == endpoint_id)
    }) {
        return false;
    }
    snapshot
        .endpoints()
        .iter()
        .zip(routes)
        .all(|(admission, observed)| {
            observed.binding == admission.binding
                && observed.gate == admission.gate
                && observed.active_guards
                    == endpoint_guards
                        .get(&admission.binding.endpoint_id)
                        .copied()
                        .unwrap_or(0)
                && observed.instance_count == 1
        })
}

impl RunningTailReadyAdmission {
    fn authorize(
        &self,
        desired: &DesiredRuntimeSpec,
        stored: &StoredCheckpoint,
    ) -> anyhow::Result<()> {
        let checkpoint = stored.checkpoint();
        anyhow::ensure!(
            desired.target == RuntimeTarget::Running
                && desired.cat_id == self.expectation.cat_id
                && desired.desired_revision == self.expectation.desired_revision
                && desired.spec_digest == self.expectation.spec_digest
                && desired.placement == self.expectation.placement
                && stored.content_digest() == &self.expectation.checkpoint_content_digest
                && checkpoint.cat_id == desired.cat_id
                && checkpoint.desired_revision == desired.desired_revision
                && checkpoint.spec_digest == desired.spec_digest
                && checkpoint.node_id == desired.placement.node_id
                && checkpoint.placement_epoch == desired.placement.placement_epoch
                && checkpoint.runtime_incarnation.as_ref()
                    == Some(&self.expectation.runtime_incarnation)
                && checkpoint == &self.expectation.checkpoint,
            "Running-tail authority does not bind the exact current Desired checkpoint"
        );
        Ok(())
    }
}

/// Checkpoint-first production effect over the process-owned registry.
pub(crate) struct RunningAdmissionEffect {
    registry: Arc<AdmissionCellRegistry>,
    guest_ready: Arc<dyn GuestReadyTransportPort>,
    launch_authority: Option<Arc<RunningLaunchAuthorityRevalidator>>,
    #[cfg(test)]
    after_registry: Option<AfterRegistryHook>,
    #[cfg(test)]
    gate_barrier: Option<GateBarrierHook>,
    #[cfg(test)]
    launch_revalidation: Option<LaunchRevalidationHook>,
}

/// Mandatory process-local close reconciler invoked by the runner before any
/// fallible physical inventory probe. It latches the complete changed/removed
/// Endpoint set for immediate process-local cancellation while leaving the
/// durable GateSequencer journal to settle one Endpoint at a time. It never
/// installs or reopens an edge.
pub(crate) struct RunningAdmissionPreScan {
    registry: Arc<AdmissionCellRegistry>,
}

impl RunningAdmissionPreScan {
    pub(crate) fn new(registry: Arc<AdmissionCellRegistry>) -> Self {
        Self { registry }
    }

    fn reconcile_session(
        &self,
        context: &RuntimePreScanAdmissionContext,
        desired: Option<&DesiredRuntimeSpec>,
        session: &Arc<AdmissionCellSession>,
    ) -> anyhow::Result<()> {
        context.check_active()?;
        let Some(desired) = desired else {
            session.cell().force_close();
            return Ok(());
        };
        let stored = match session.checkpoint_store().load() {
            Ok(Some(stored)) => stored,
            Ok(None) | Err(_) => {
                session.cell().force_close();
                return Ok(());
            }
        };
        let checkpoint = stored.checkpoint();
        let checkpoint_cell = match AdmissionSnapshot::from_checkpoint(checkpoint) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                session.cell().force_close();
                return Ok(());
            }
        };
        let Some(sealed) = session.sealed_running_desired() else {
            session.cell().force_close();
            return Ok(());
        };
        let live = session.cell().snapshot();
        let top_is_sealed = checkpoint.cat_id == sealed.cat_id
            && checkpoint.node_id == sealed.placement.node_id
            && checkpoint.placement_epoch == sealed.placement.placement_epoch
            && checkpoint.desired_revision == sealed.desired_revision
            && checkpoint.spec_digest == sealed.spec_digest;
        let top_is_current = checkpoint.cat_id == desired.cat_id
            && checkpoint.node_id == desired.placement.node_id
            && checkpoint.placement_epoch == desired.placement.placement_epoch
            && checkpoint.desired_revision == desired.desired_revision
            && checkpoint.spec_digest == desired.spec_digest;

        // A checkpoint-first ordinary global close may have durably advanced
        // to the current Desired before the cell mutation response was known.
        // Once the exact sealed source is conservatively Closed, advance only
        // that already-Closed metadata tuple so the current close journal can
        // drain and be removed. This edge can never recreate admission.
        let ordinary_close_source = top_is_current
            && !matches!(desired.transition, RuntimeTransition::RequireIdle { .. })
            && matches!(
                checkpoint.step,
                ReconcileStep::CloseAdmission {
                    require_idle_attempt_id: None
                }
            )
            && matches!(
                checkpoint.require_idle,
                RequireIdleCheckpoint::NotApplicable
            )
            && checkpoint_cell.lifecycle_admission() == LifecycleAdmission::Closed
            && checkpoint_cell
                .endpoints()
                .iter()
                .all(|route| route.gate == RouteGateState::Closed)
            && live.applied_desired_revision() == sealed.desired_revision
            && live.spec_digest() == &sealed.spec_digest
            && live.placement().node_id == sealed.placement.node_id
            && live.placement().placement_epoch == sealed.placement.placement_epoch
            && live.runtime_incarnation() == checkpoint_cell.runtime_incarnation()
            && live.guest_ipv4() == checkpoint_cell.guest_ipv4()
            && live.endpoints().len() == checkpoint_cell.endpoints().len()
            && live
                .endpoints()
                .iter()
                .zip(checkpoint_cell.endpoints())
                .all(|(source, current)| source.binding == current.binding);
        if ordinary_close_source {
            let source_closed = live.fail_closed();
            session.cell().force_close();
            let mut port = session.cell().port();
            port.advance_closed(&source_closed, &checkpoint_cell)
                .map_err(super::GateReconcileError::from)?;
            return Ok(());
        }
        // A restart-closed Endpoint successor publishes only a Closed R2
        // journal before advancing the process-local metadata tuple. If that
        // response is lost, the exact sealed R1 Closed source may finish this
        // no-admission edge; neither lifecycle nor any old route is reopened.
        let restart_endpoint_close_source = top_is_current
            && super::route_retirement::restart_closed_endpoint_successor(&sealed, desired)
            && checkpoint_cell.lifecycle_admission() == LifecycleAdmission::Closed
            && checkpoint_cell
                .endpoints()
                .iter()
                .all(|route| route.gate == RouteGateState::Closed)
            && matches!(
                checkpoint.step,
                ReconcileStep::CloseGate { .. } | ReconcileStep::OpenAdmission { .. }
            )
            && live.lifecycle_admission() == LifecycleAdmission::Closed
            && live
                .endpoints()
                .iter()
                .all(|route| route.gate == RouteGateState::Closed)
            && live.applied_desired_revision() == sealed.desired_revision
            && live.spec_digest() == &sealed.spec_digest
            && live.placement() == &sealed.placement
            && live.runtime_incarnation() == checkpoint_cell.runtime_incarnation()
            && live.guest_ipv4() == checkpoint_cell.guest_ipv4()
            && live.endpoints().len() == checkpoint_cell.endpoints().len()
            && live
                .endpoints()
                .iter()
                .zip(checkpoint_cell.endpoints())
                .all(|(source, current)| source.binding == current.binding);
        if restart_endpoint_close_source {
            let source_closed = live.fail_closed();
            session.cell().force_close();
            let mut port = session.cell().port();
            port.advance_closed(&source_closed, &checkpoint_cell)
                .map_err(super::GateReconcileError::from)?;
            return Ok(());
        }
        let require_idle_needs_settlement = !matches!(
            checkpoint.require_idle,
            RequireIdleCheckpoint::NotApplicable | RequireIdleCheckpoint::Armed { .. }
        ) && live != checkpoint_cell;
        if live.lifecycle_admission() == LifecycleAdmission::Closed
            && live
                .endpoints()
                .iter()
                .all(|route| route.gate == RouteGateState::Closed)
            && !require_idle_needs_settlement
        {
            return Ok(());
        }

        if matches!(desired.transition, RuntimeTransition::RequireIdle { .. }) {
            let result = if top_is_sealed
                && checkpoint.runtime_launch.identity().is_some()
                && checkpoint.lifecycle_admission == LifecycleAdmission::Open
                && checkpoint.stable_state == Some(StableState::Running)
                && matches!(
                    checkpoint.step,
                    ReconcileStep::Stable {
                        state: StableState::Running
                    }
                )
                && live == checkpoint_cell
            {
                let times = next_persist_times(&stored)?;
                let mut port = session.cell().port();
                GateSequencer::new(session.checkpoint_store(), &mut port)
                    .begin_require_idle(&stored, desired, times)
                    .map(|_| ())
            } else if top_is_current {
                match &checkpoint.require_idle {
                    RequireIdleCheckpoint::Armed { .. } => {
                        let times = next_persist_times(&stored)?;
                        let mut port = session.cell().port();
                        GateSequencer::new(session.checkpoint_store(), &mut port)
                            .recover_armed(&stored, desired, times)
                            .map(|_| ())
                    }
                    RequireIdleCheckpoint::Busy {
                        gate_closed: false, ..
                    } => {
                        let source_snapshot =
                            exact_require_idle_source_snapshot(&sealed, desired, checkpoint)?;
                        if live == source_snapshot {
                            Ok(())
                        } else if live == source_snapshot.fail_closed() {
                            let times = next_persist_times(&stored)?;
                            let mut port = session.cell().port();
                            GateSequencer::new(session.checkpoint_store(), &mut port)
                                .settle_open_busy_fail_closed(
                                    &stored,
                                    desired,
                                    &source_snapshot,
                                    times.after_effect,
                                )
                                .map(|_| ())
                        } else {
                            Err(super::GateReconcileError::WrongRequireIdleCheckpoint)
                        }
                    }
                    RequireIdleCheckpoint::Closed { .. }
                    | RequireIdleCheckpoint::Busy {
                        gate_closed: true, ..
                    } if live.lifecycle_admission() == LifecycleAdmission::Closed => {
                        if live == checkpoint_cell {
                            Ok(())
                        } else {
                            let source_snapshot =
                                exact_require_idle_source_snapshot(&sealed, desired, checkpoint)?;
                            let source_closed = source_snapshot.fail_closed();
                            let mut port = session.cell().port();
                            port.advance_closed(&source_closed, &checkpoint_cell)
                                .map_err(super::GateReconcileError::from)
                        }
                    }
                    _ => Err(super::GateReconcileError::WrongRequireIdleCheckpoint),
                }
            } else {
                Err(super::GateReconcileError::WrongRequireIdleSource)
            };
            if let Err(error) = result {
                session.cell().force_close();
                return Err(error.into());
            }
            return Ok(());
        }

        let eligible_running_phase = checkpoint.runtime_launch.identity().is_some()
            && matches!(
                checkpoint.step,
                ReconcileStep::OpenAdmission { .. }
                    | ReconcileStep::InstallGate { .. }
                    | ReconcileStep::CloseGate { .. }
                    | ReconcileStep::Stable {
                        state: StableState::Running
                    }
            );
        let sealed_matches_current = sealed == *desired;
        let endpoint_only = super::route_retirement::endpoint_only_successor(&sealed, desired);
        let cell_is_exact_or_closed_edge = live == checkpoint_cell
            || match &checkpoint.step {
                ReconcileStep::CloseGate { endpoint_id, .. }
                | ReconcileStep::InstallGate { endpoint_id, .. } => session
                    .checkpoint_store()
                    .endpoint_effect_edge_allows_live(endpoint_id, &live)?,
                _ => false,
            };
        let trusted = desired.target == RuntimeTarget::Running
            && eligible_running_phase
            && (sealed_matches_current || endpoint_only)
            && ((top_is_current && cell_is_exact_or_closed_edge)
                || (top_is_sealed && endpoint_only && live == checkpoint_cell));
        if !trusted {
            session.cell().force_close();
            return Ok(());
        }

        if endpoint_only {
            context.check_active()?;
            let incarnation = checkpoint
                .runtime_incarnation
                .as_ref()
                .context("Endpoint retirement lacks a runtime incarnation")?;
            let mut revoke = Vec::new();
            for route in live.endpoints() {
                let desired_binding = desired
                    .endpoints
                    .binary_search_by(|endpoint| {
                        endpoint.endpoint_id.cmp(&route.binding.endpoint_id)
                    })
                    .ok()
                    .and_then(|index| desired.endpoints.get(index))
                    .and_then(|endpoint| route_binding(desired, endpoint, Some(incarnation)));
                if desired_binding.as_ref() != Some(&route.binding) {
                    revoke.push(route.binding.endpoint_id.clone());
                }
            }
            if let Err(error) = session.cell().latch_endpoint_revocations(&live, &revoke) {
                session.cell().force_close();
                return Err(error.into());
            }
        }

        let final_checkpoint = stored.checkpoint();
        if final_checkpoint.desired_revision == desired.desired_revision
            && final_checkpoint.spec_digest == desired.spec_digest
            && session.cell().snapshot() == AdmissionSnapshot::from_checkpoint(final_checkpoint)?
            && final_checkpoint.stable_state == Some(StableState::Running)
            && matches!(
                final_checkpoint.step,
                ReconcileStep::Stable {
                    state: StableState::Running
                }
            )
        {
            session.advance_sealed_running_desired(desired.clone())?;
        }
        Ok(())
    }
}

fn exact_require_idle_source_snapshot(
    sealed: &DesiredRuntimeSpec,
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<AdmissionSnapshot> {
    super::route_retirement::validate_require_idle_checkpoint_tuple(desired, checkpoint)?;
    let RuntimeTransition::RequireIdle {
        source_revision,
        source_runtime_incarnation,
        ..
    } = &desired.transition
    else {
        anyhow::bail!("Desired is not RequireIdle")
    };
    let mut expected_successor = sealed.clone();
    expected_successor.desired_revision = desired.desired_revision;
    expected_successor.spec_digest = desired.spec_digest.clone();
    expected_successor.target = desired.target;
    expected_successor.transition = desired.transition.clone();
    anyhow::ensure!(
        expected_successor == *desired && sealed.desired_revision == *source_revision,
        "RequireIdle Desired is not the exact sealed Running successor"
    );
    let mut source_checkpoint = checkpoint.clone();
    source_checkpoint.desired_revision = sealed.desired_revision;
    source_checkpoint.spec_digest = sealed.spec_digest.clone();
    let source_snapshot = AdmissionSnapshot::from_checkpoint(&source_checkpoint)?;
    anyhow::ensure!(
        source_snapshot.runtime_incarnation() == Some(source_runtime_incarnation),
        "RequireIdle source incarnation changed"
    );
    Ok(source_snapshot)
}

impl RuntimePreScanAdmission for RunningAdmissionPreScan {
    fn reconcile(&self, context: RuntimePreScanAdmissionContext) -> anyhow::Result<()> {
        let result = (|| {
            context.check_active()?;
            let desired_specs = &context.coordinates().desired.desired_specs;
            for (cat_id, session) in self.registry.ready_sessions()? {
                let desired = desired_specs
                    .iter()
                    .find(|desired| desired.cat_id == cat_id);
                self.reconcile_session(&context, desired, &session)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.registry.fail_close_all();
        }
        result
    }

    fn fail_close_all(&self) {
        self.registry.fail_close_all();
    }
}

impl RunningAdmissionEffect {
    #[cfg(test)]
    pub(crate) fn new(registry: Arc<AdmissionCellRegistry>) -> Self {
        Self {
            registry,
            guest_ready: Arc::new(PlatformGuestReadyTransportPort),
            launch_authority: None,
            #[cfg(test)]
            after_registry: None,
            #[cfg(test)]
            gate_barrier: None,
            #[cfg(test)]
            launch_revalidation: None,
        }
    }

    pub(crate) fn with_launch_authority(
        registry: Arc<AdmissionCellRegistry>,
        launch_authority: Arc<RunningLaunchAuthorityRevalidator>,
    ) -> Self {
        Self {
            registry,
            guest_ready: Arc::new(PlatformGuestReadyTransportPort),
            launch_authority: Some(launch_authority),
            #[cfg(test)]
            after_registry: None,
            #[cfg(test)]
            gate_barrier: None,
            #[cfg(test)]
            launch_revalidation: None,
        }
    }

    #[cfg(test)]
    fn with_after_registry(mut self, hook: AfterRegistryHook) -> Self {
        self.after_registry = Some(hook);
        self
    }

    #[cfg(test)]
    fn with_gate_barrier(mut self, hook: GateBarrierHook) -> Self {
        self.gate_barrier = Some(hook);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_physical_revalidation_for_test(
        mut self,
        guest_ready: Arc<dyn GuestReadyTransportPort>,
        launch_revalidation: LaunchRevalidationHook,
    ) -> Self {
        self.guest_ready = guest_ready;
        self.launch_revalidation = Some(launch_revalidation);
        self
    }

    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        let Some(admission) = context.running_tail_admission() else {
            return Ok(None);
        };
        let Some(ready) = admission.ready(&desired.cat_id) else {
            return Ok(None);
        };
        context.check_active()?;
        let session = ready.session(&self.registry, desired)?;
        #[cfg(test)]
        if let Some(hook) = &self.after_registry {
            hook(context);
        }
        context.check_active()?;
        let live = session.cell().observe();
        anyhow::ensure!(
            live.snapshot() == ready.expectation.cell.snapshot(),
            "Running-tail sidecar is stale for the current AdmissionCell snapshot"
        );
        let stored = session
            .checkpoint_store()
            .load()
            .context("load Running-tail checkpoint")?
            .context("Running-tail authority names a missing checkpoint")?;
        ready.authorize(desired, &stored)?;
        context.check_active()?;
        let Some(action) =
            plan_running_tail_action(desired, &stored, &live, session.checkpoint_store())?
        else {
            let checkpoint = stored.checkpoint();
            let converged = session.cell().snapshot()
                == AdmissionSnapshot::from_checkpoint(checkpoint)?
                && checkpoint.stable_state == Some(StableState::Running)
                && matches!(
                    checkpoint.step,
                    ReconcileStep::Stable {
                        state: StableState::Running
                    }
                );
            // A scanner-sealed admission tail owns this dispatch. In
            // particular, a Closed endpoint with live guards must not fall
            // through into storage/network teardown while its tunnel tasks
            // are still draining. Only the exact Stable/Open replay is a
            // completed unit; every other no-action state needs fresh guard
            // evidence.
            return Ok(Some(if converged {
                RuntimeDesiredEffectOutcome::Applied
            } else {
                RuntimeDesiredEffectOutcome::RefreshInventory
            }));
        };
        context.check_active()?;
        let mut port = session.cell().port();
        let result = match action {
            RunningTailAction::OpenLifecycle => {
                let _node_global_effect = context.lock_node_global_effect()?;
                let times = next_persist_times(&stored)?;
                Some(
                    GateSequencer::new(session.checkpoint_store(), &mut port)
                        .open_admission_with_barrier(
                            &stored,
                            desired,
                            times,
                            |accepted, durable| {
                                ready.revalidate_physical(
                                    self,
                                    context,
                                    desired,
                                    session.checkpoint_store(),
                                    accepted,
                                    durable,
                                )
                            },
                        )?,
                )
            }
            RunningTailAction::CloseGate(endpoint_id) => {
                let times = next_persist_times(&stored)?;
                Some(
                    GateSequencer::new(session.checkpoint_store(), &mut port).close_gate(
                        &stored,
                        desired,
                        &endpoint_id,
                        times,
                    )?,
                )
            }
            RunningTailAction::PrepareChanged(endpoint_id) => {
                let times = next_persist_times(&stored)?;
                Some(
                    GateSequencer::new(session.checkpoint_store(), &mut port)
                        .prepare_changed_gate(&stored, desired, &endpoint_id, times.after_effect)?,
                )
            }
            RunningTailAction::RemoveGate(endpoint_id) => {
                let times = next_persist_times(&stored)?;
                Some(
                    GateSequencer::new(session.checkpoint_store(), &mut port).remove_closed_gate(
                        &stored,
                        desired,
                        &endpoint_id,
                        times.after_effect,
                    )?,
                )
            }
            RunningTailAction::InstallGate(endpoint_id) => {
                let _node_global_effect = context.lock_node_global_effect()?;
                let times = next_persist_times(&stored)?;
                Some(
                    GateSequencer::new(session.checkpoint_store(), &mut port)
                        .install_gate_with_barrier(
                            &stored,
                            desired,
                            &endpoint_id,
                            times,
                            |accepted, durable| {
                                ready.revalidate_physical(
                                    self,
                                    context,
                                    desired,
                                    session.checkpoint_store(),
                                    accepted,
                                    durable,
                                )
                            },
                        )?,
                )
            }
        };
        if let Some(result) = result {
            debug_assert_eq!(
                result.checkpoint().checkpoint().runtime_launch,
                stored.checkpoint().runtime_launch
            );
            seal_stable_running_session(&session, desired, result.checkpoint().checkpoint())?;
        }
        // Do not re-check cancellation after the local linearization point:
        // the bounded sequencer has already resolved the exact postcondition
        // and finalized its checkpoint. The runner still discards the stale
        // accepted batch and obtains a new full inventory.
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }

    /// Applies one scanner-sealed retirement edge before any component may
    /// mutate VMM, storage or network state. Every successful edge forces a
    /// fresh complete inventory; a closed gate with live guards simply waits
    /// for the cancellation-aware tunnel tasks to release them.
    pub(crate) fn try_retire(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        let Some(admission) = context.running_tail_admission() else {
            return Ok(None);
        };
        let Some(retiring) = admission.retiring(&desired.cat_id) else {
            return Ok(None);
        };
        context.check_active()?;
        anyhow::ensure!(
            retiring.desired_revision == desired.desired_revision
                && retiring.spec_digest == desired.spec_digest
                && retiring.cat_id == desired.cat_id,
            "route-retirement authority does not bind current Desired"
        );
        let session = self
            .registry
            .existing_session(&desired.cat_id)?
            .context("route-retirement authority names a missing AdmissionCell")?;
        let live = session.cell().observe();
        anyhow::ensure!(
            session.generation() == retiring.session_generation
                && live.snapshot() == retiring.cell.snapshot()
                && retiring
                    .gate_predecessor
                    .as_ref()
                    .is_none_or(|predecessor| {
                        session.sealed_running_desired().as_ref() == Some(predecessor)
                    }),
            "route-retirement shared-registry evidence changed"
        );
        let stored = session
            .checkpoint_store()
            .load()
            .context("load route-retirement checkpoint")?
            .context("route-retirement authority names a missing checkpoint")?;
        anyhow::ensure!(
            stored.content_digest() == &retiring.checkpoint_content_digest
                && stored.checkpoint() == &retiring.checkpoint,
            "route-retirement checkpoint changed after accepted inventory"
        );
        let checkpoint_cell = AdmissionSnapshot::from_checkpoint(stored.checkpoint())?;
        let current_edge_allows_live = if retiring.mode == RouteRetirementMode::EndpointOnly
            && retiring.checkpoint_binding == DesiredCheckpointBinding::Current
            && live.snapshot() != &checkpoint_cell
        {
            let endpoint_id = match &stored.checkpoint().step {
                ReconcileStep::CloseGate { endpoint_id, .. }
                | ReconcileStep::InstallGate { endpoint_id, .. } => endpoint_id,
                _ => anyhow::bail!(
                    "current Endpoint retirement cell differs outside an effect journal"
                ),
            };
            session
                .checkpoint_store()
                .endpoint_effect_edge_allows_live(endpoint_id, live.snapshot())?
        } else {
            false
        };
        let require_idle_source = if retiring.checkpoint_binding
            == DesiredCheckpointBinding::Current
            && matches!(
                retiring.mode,
                RouteRetirementMode::GlobalDesired | RouteRetirementMode::GlobalPhysicalNegative
            )
            && matches!(
                stored.checkpoint().require_idle,
                RequireIdleCheckpoint::Busy {
                    gate_closed: false,
                    ..
                }
            ) {
            let sealed = retiring
                .gate_predecessor
                .as_ref()
                .context("Busy/Open retirement lacks its sealed Running source")?;
            Some(exact_require_idle_source_snapshot(
                sealed,
                desired,
                stored.checkpoint(),
            )?)
        } else {
            None
        };
        let restart_closed_allows_live = retiring.mode == RouteRetirementMode::EndpointOnly
            && retiring.checkpoint_binding == DesiredCheckpointBinding::Superseded
            && retiring
                .gate_predecessor
                .as_ref()
                .is_some_and(|predecessor| {
                    super::route_retirement::restart_closed_endpoint_successor(predecessor, desired)
                })
            && live.snapshot() == &checkpoint_cell.fail_closed()
            && live.guards().platform_guards == 0
            && live.guards().endpoint_guards.is_empty();
        anyhow::ensure!(
            live.snapshot() == &checkpoint_cell
                || current_edge_allows_live
                || require_idle_source
                    .as_ref()
                    .is_some_and(|source| live.snapshot() == source)
                || restart_closed_allows_live,
            "route-retirement cell lost its exact checkpoint, stored effect edge, or RequireIdle source"
        );
        context.check_active()?;
        let Some(action) =
            plan_route_retirement(retiring, desired, &stored, &live, current_edge_allows_live)?
        else {
            // A Busy RequireIdle decision is already terminal and
            // intentionally preserves its exact open source. Every other
            // no-action retirement state is waiting for cancellation-aware
            // guards or fresh physical proof and must retain dispatch
            // ownership until a new complete inventory is accepted.
            let terminal_busy = matches!(
                stored.checkpoint().require_idle,
                RequireIdleCheckpoint::Busy {
                    gate_closed: false,
                    ..
                }
            );
            return Ok(Some(if terminal_busy {
                RuntimeDesiredEffectOutcome::Applied
            } else {
                RuntimeDesiredEffectOutcome::RefreshInventory
            }));
        };
        context.check_active()?;
        if matches!(action, RouteRetirementAction::RemoveSession) {
            anyhow::ensure!(
                live.guards().platform_guards == 0 && live.guards().endpoint_guards.is_empty(),
                "route-retirement cannot remove a cell with live guards"
            );
            anyhow::ensure!(
                self.registry.remove(&desired.cat_id, &session)?,
                "route-retirement shared-registry compare-remove lost ownership"
            );
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }

        let times = next_persist_times(&stored)?;
        if matches!(action, RouteRetirementAction::SettleOpenBusyFailClosed) {
            session.cell().force_close();
        }
        let mut port = session.cell().port();
        let mut sequencer = GateSequencer::new(session.checkpoint_store(), &mut port);
        let result = match action {
            RouteRetirementAction::AdoptRestartClosed(close_token) => sequencer
                .adopt_restart_closed_endpoint_successor(
                    &stored,
                    desired,
                    close_token.as_ref(),
                    times.after_effect,
                )?,
            RouteRetirementAction::CloseGate(endpoint_id) => {
                sequencer.close_gate(&stored, desired, &endpoint_id, times)?
            }
            RouteRetirementAction::PrepareChanged(endpoint_id) => sequencer.prepare_changed_gate(
                &stored,
                desired,
                &endpoint_id,
                times.after_effect,
            )?,
            RouteRetirementAction::RemoveGate(endpoint_id) => {
                sequencer.remove_closed_gate(&stored, desired, &endpoint_id, times.after_effect)?
            }
            RouteRetirementAction::InstallGate(endpoint_id) => {
                let _node_global_effect = context.lock_node_global_effect()?;
                sequencer.install_gate_with_barrier(
                    &stored,
                    desired,
                    &endpoint_id,
                    times,
                    |accepted, durable| {
                        retiring.revalidate_physical(
                            self,
                            context,
                            desired,
                            session.checkpoint_store(),
                            accepted,
                            durable,
                        )
                    },
                )?
            }
            RouteRetirementAction::CloseAll => sequencer.close_all(&stored, desired, times)?,
            RouteRetirementAction::BeginRequireIdle => {
                sequencer.begin_require_idle(&stored, desired, times)?
            }
            RouteRetirementAction::RecoverRequireIdle => {
                sequencer.recover_armed(&stored, desired, times)?
            }
            RouteRetirementAction::SettleOpenBusyFailClosed => sequencer
                .settle_open_busy_fail_closed(
                    &stored,
                    desired,
                    require_idle_source.as_ref().context(
                        "physical-negative Busy retirement lacks its exact source snapshot",
                    )?,
                    times.after_effect,
                )?,
            RouteRetirementAction::RemoveSession => unreachable!("handled before sequencer"),
        };
        debug_assert_eq!(
            result.checkpoint().checkpoint().runtime_launch,
            stored.checkpoint().runtime_launch
        );
        seal_stable_running_session(&session, desired, result.checkpoint().checkpoint())?;
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }
}

fn seal_stable_running_session(
    session: &AdmissionCellSession,
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<()> {
    if desired.target == RuntimeTarget::Running
        && checkpoint.desired_revision == desired.desired_revision
        && checkpoint.spec_digest == desired.spec_digest
        && checkpoint.stable_state == Some(StableState::Running)
        && matches!(
            checkpoint.step,
            ReconcileStep::Stable {
                state: StableState::Running
            }
        )
        && session.cell().snapshot() == AdmissionSnapshot::from_checkpoint(checkpoint)?
    {
        session.advance_sealed_running_desired(desired.clone())?;
    }
    Ok(())
}

impl RouteRetirementExpectation {
    fn revalidate_physical(
        &self,
        effect: &RunningAdmissionEffect,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        store: &FileCheckpointStore,
        accepted: &StoredCheckpoint,
        durable: &StoredCheckpoint,
    ) -> anyhow::Result<()> {
        validate_gate_barrier_successor(accepted.checkpoint(), durable.checkpoint(), desired)
            .context("validate durable route gate-only successor")?;
        #[cfg(test)]
        if let Some(barrier) = effect.gate_barrier.as_ref() {
            barrier(store, accepted, durable)?;
        }
        let Some(physical) = &self.physical else {
            anyhow::bail!("route install lacks fresh physical authority")
        };
        let (physical_launch_desired, vmm, mounted_set) = match physical {
            RunningTailPhysicalAuthority::Exact {
                physical_launch_desired,
                vmm,
                mounted_set,
            } => (
                physical_launch_desired.as_ref(),
                vmm.as_ref(),
                mounted_set.as_ref(),
            ),
            #[cfg(test)]
            RunningTailPhysicalAuthority::Test => return Ok(()),
        };
        let predecessor = self
            .gate_predecessor
            .as_ref()
            .context("route install lacks its sealed live-gate predecessor")?;
        let launch_predecessor = self
            .launch_predecessor
            .as_ref()
            .context("route install lacks immutable launch provenance")?;
        anyhow::ensure!(
            physical_launch_desired == launch_predecessor,
            "route physical proof changed its immutable launch provenance"
        );
        super::authorized_blockd::validate_running_physical_desired_successor(
            launch_predecessor,
            predecessor,
        )
        .context("live-gate predecessor conflicts with immutable launch provenance")?;
        if let Some(launch_authority) = effect.launch_authority.as_deref() {
            let successor = match self.checkpoint_binding {
                DesiredCheckpointBinding::Superseded => launch_authority
                    .revalidate_exact_retained_running_endpoint_successor(
                        context,
                        physical_launch_desired,
                        predecessor,
                        desired,
                        store,
                        accepted,
                        durable,
                        vmm,
                    )?,
                DesiredCheckpointBinding::Current => launch_authority
                    .revalidate_exact_retained_running_gate_successor(
                        context,
                        physical_launch_desired,
                        desired,
                        store,
                        accepted,
                        durable,
                        vmm,
                    )?,
            };
            mounted_set.revalidate(
                effect.guest_ready.as_ref(),
                context,
                desired,
                durable.checkpoint(),
                successor.vmm(),
            )?;
            successor.revalidate_current()
        } else {
            #[cfg(test)]
            {
                let durable_guard = store.assert_current(durable)?;
                if let Some(revalidate) = effect.launch_revalidation.as_ref() {
                    revalidate(context, desired, store, accepted, durable, vmm)?;
                } else {
                    anyhow::bail!(
                        "production route retirement lacks launch revalidation authority"
                    );
                }
                let successor_vmm = match self.checkpoint_binding {
                    DesiredCheckpointBinding::Superseded => vmm
                        .expectation()
                        .endpoint_only_gate_successor(predecessor, desired, durable.checkpoint())?
                        .prove_exact_process(vmm.evidence().clone())?,
                    DesiredCheckpointBinding::Current => vmm
                        .expectation()
                        .gate_only_successor(durable.checkpoint())?
                        .prove_exact_process(vmm.evidence().clone())?,
                };
                mounted_set.revalidate(
                    effect.guest_ready.as_ref(),
                    context,
                    desired,
                    durable.checkpoint(),
                    &successor_vmm,
                )?;
                Ok(store.revalidate_current(durable, &durable_guard)?)
            }
            #[cfg(not(test))]
            anyhow::bail!("production route retirement lacks launch revalidation authority");
        }
    }
}

impl RunningTailReadyAdmission {
    fn revalidate_physical(
        &self,
        effect: &RunningAdmissionEffect,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        store: &FileCheckpointStore,
        accepted: &StoredCheckpoint,
        durable: &StoredCheckpoint,
    ) -> anyhow::Result<()> {
        validate_gate_barrier_successor(accepted.checkpoint(), durable.checkpoint(), desired)
            .context("validate durable Running gate-only successor")?;
        #[cfg(test)]
        if let Some(barrier) = effect.gate_barrier.as_ref() {
            barrier(store, accepted, durable)?;
        }
        match &self.expectation.physical {
            RunningTailPhysicalAuthority::Exact {
                physical_launch_desired,
                vmm,
                mounted_set,
            } => {
                // First close every retained Host-side authority. The fresh
                // mounted-set challenge is deliberately last so no earlier
                // public observation, or slower Host inspection, can stand in
                // for the immediate pre-gate Guest physical barrier.
                if let Some(launch_authority) = effect.launch_authority.as_deref() {
                    let successor = launch_authority
                        .revalidate_exact_retained_running_gate_successor(
                            context,
                            physical_launch_desired,
                            desired,
                            store,
                            accepted,
                            durable,
                            vmm,
                        )?;
                    mounted_set.revalidate(
                        effect.guest_ready.as_ref(),
                        context,
                        desired,
                        durable.checkpoint(),
                        successor.vmm(),
                    )?;
                    successor.revalidate_current()
                } else {
                    #[cfg(test)]
                    {
                        let durable_guard = store.assert_current(durable)?;
                        let Some(revalidate) = effect.launch_revalidation.as_ref() else {
                            anyhow::bail!(
                            "production Running-tail effect lacks launch revalidation authority"
                        );
                        };
                        revalidate(context, desired, store, accepted, durable, vmm)?;
                        let successor_vmm = vmm
                            .expectation()
                            .gate_only_successor(durable.checkpoint())?
                            .prove_exact_process(vmm.evidence().clone())?;
                        mounted_set.revalidate(
                            effect.guest_ready.as_ref(),
                            context,
                            desired,
                            durable.checkpoint(),
                            &successor_vmm,
                        )?;
                        store.revalidate_current(durable, &durable_guard)?;
                        Ok(())
                    }
                    #[cfg(not(test))]
                    anyhow::bail!(
                        "production Running-tail effect lacks launch revalidation authority"
                    )
                }
            }
            #[cfg(test)]
            RunningTailPhysicalAuthority::Test => Ok(()),
        }
    }

    fn session(
        &self,
        registry: &AdmissionCellRegistry,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Arc<AdmissionCellSession>> {
        let cat_id = &desired.cat_id;
        match self.expectation.cell_presence {
            RunningTailCellPresence::Absent => {
                match registry.ensure_closed(
                    cat_id,
                    self.expectation.cell.snapshot().clone(),
                    Some(desired.clone()),
                )? {
                    AdmissionCellSessionLookup::CreatedClosed(session) => Ok(session),
                    AdmissionCellSessionLookup::Existing => {
                        anyhow::bail!("Running-tail sidecar expected an absent AdmissionCell")
                    }
                }
            }
            RunningTailCellPresence::Present => registry
                .existing_session(cat_id)?
                .context("Running-tail sidecar expected a present AdmissionCell"),
        }
    }
}

enum RunningTailAction {
    OpenLifecycle,
    CloseGate(Id),
    PrepareChanged(Id),
    RemoveGate(Id),
    InstallGate(Id),
}

/// Closed classification of the only checkpoint phases that may retain the
/// private all-volume Running physical proof. A correct Guest mount is never
/// allowed to manufacture route authority while Persistent initialization is
/// still in an earlier durable phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RunningTailPhase {
    Admission,
    EndpointRetirement,
    Ineligible,
}

impl RunningTailPhase {
    pub(super) fn permits_physical_proof(self) -> bool {
        self != Self::Ineligible
    }
}

pub(super) fn classify_running_tail_phase(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<RunningTailPhase> {
    if desired.target != RuntimeTarget::Running {
        return Ok(RunningTailPhase::Ineligible);
    }
    let persistent = desired
        .volumes
        .iter()
        .filter(|volume| volume.disk_kind == DiskKind::Persistent)
        .collect::<Vec<_>>();
    let admission_tail = match &checkpoint.step {
        ReconcileStep::OpenAdmission { .. }
        | ReconcileStep::InstallGate { .. }
        | ReconcileStep::Stable {
            state: StableState::Running,
        } => Some(RunningTailPhase::Admission),
        ReconcileStep::CloseGate { .. } => Some(RunningTailPhase::EndpointRetirement),
        _ => None,
    };
    if persistent.is_empty() {
        return Ok(match checkpoint.step {
            ReconcileStep::StartRuntime { .. } => RunningTailPhase::Admission,
            _ => admission_tail.unwrap_or(RunningTailPhase::Ineligible),
        });
    }
    if let Some(phase) = admission_tail {
        return Ok(phase);
    }
    let ReconcileStep::MountFilesystem { filesystem, .. } = &checkpoint.step else {
        return Ok(RunningTailPhase::Ineligible);
    };
    let final_intent = persistent
        .into_iter()
        .max_by(|left, right| {
            (left.guest_device.slot, left.guest_device.serial.as_str())
                .cmp(&(right.guest_device.slot, right.guest_device.serial.as_str()))
        })
        .expect("non-empty Persistent set");
    if final_persistent_mount_matches(checkpoint, final_intent, filesystem)? {
        Ok(RunningTailPhase::Admission)
    } else {
        Ok(RunningTailPhase::Ineligible)
    }
}

fn final_persistent_mount_matches(
    checkpoint: &RuntimeCheckpoint,
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    filesystem: &PersistentFilesystemBinding,
) -> anyhow::Result<bool> {
    let Some(mount) = intent.mount.as_ref() else {
        return Ok(false);
    };
    let Some(launch) = checkpoint.runtime_launch.identity() else {
        return Ok(false);
    };
    let mut prepared_matches = launch
        .devices
        .iter()
        .filter(|device| device.volume_intent_id == intent.volume_intent_id);
    let Some(prepared) = prepared_matches.next() else {
        return Ok(false);
    };
    anyhow::ensure!(
        prepared_matches.next().is_none(),
        "retained launch repeats the final Persistent volume intent"
    );
    Ok(filesystem.runtime_incarnation == launch.runtime_incarnation
        && filesystem.volume_intent_id == intent.volume_intent_id
        && filesystem.disk_id == intent.disk_id
        && filesystem.volume_id == intent.volume_id
        && filesystem.attachment_id == intent.attachment_id
        && filesystem.size_bytes == intent.size_bytes
        && filesystem.guest_device == intent.guest_device
        && filesystem.filesystem_uuid == mount.filesystem_uuid
        && filesystem.mount_path == mount.mount_path
        && filesystem.initialization == mount.initialization
        && prepared.disk_kind == DiskKind::Persistent
        && prepared.volume_intent_id == intent.volume_intent_id
        && prepared.disk_id == intent.disk_id
        && prepared.volume_id == intent.volume_id
        && prepared.attachment_id == intent.attachment_id
        && prepared.attachment_epoch == filesystem.attachment_epoch
        && prepared.size_bytes == intent.size_bytes
        && prepared.guest_device == intent.guest_device)
}

enum RouteRetirementAction {
    AdoptRestartClosed(Option<Id>),
    CloseGate(Id),
    PrepareChanged(Id),
    RemoveGate(Id),
    InstallGate(Id),
    CloseAll,
    BeginRequireIdle,
    RecoverRequireIdle,
    SettleOpenBusyFailClosed,
    RemoveSession,
}

fn plan_route_retirement(
    retiring: &RouteRetirementExpectation,
    desired: &DesiredRuntimeSpec,
    stored: &StoredCheckpoint,
    live: &AdmissionCellObservation,
    current_edge_allows_live: bool,
) -> anyhow::Result<Option<RouteRetirementAction>> {
    let checkpoint = stored.checkpoint();
    let cell = live.snapshot();
    let guards = live.guards();
    let cell_is_closed = cell.lifecycle_admission() == LifecycleAdmission::Closed
        && cell
            .endpoints()
            .iter()
            .all(|route| route.gate == RouteGateState::Closed);
    let all_drained = guards.platform_guards == 0 && guards.endpoint_guards.is_empty();

    if cell_is_closed
        && retiring.mode == RouteRetirementMode::EndpointOnly
        && retiring.checkpoint_binding == DesiredCheckpointBinding::Superseded
    {
        let predecessor = retiring
            .gate_predecessor
            .as_ref()
            .context("restart-closed retirement lacks its sealed Running predecessor")?;
        anyhow::ensure!(
            all_drained
                && cell == &AdmissionSnapshot::from_checkpoint(checkpoint)?.fail_closed()
                && super::route_retirement::restart_closed_endpoint_successor(predecessor, desired,),
            "restart-closed Endpoint retirement lacks its exact higher-epoch successor"
        );
        let close_token = checkpoint
            .route_gates
            .first()
            .map(|route| route.binding.endpoint_id.clone());
        return Ok(Some(RouteRetirementAction::AdoptRestartClosed(close_token)));
    }
    if cell_is_closed && retiring.mode != RouteRetirementMode::EndpointOnly {
        return Ok(all_drained.then_some(RouteRetirementAction::RemoveSession));
    }

    match retiring.mode {
        RouteRetirementMode::EndpointOnly => {
            anyhow::ensure!(
                desired.target == RuntimeTarget::Running
                    && matches!(desired.transition, RuntimeTransition::CancelAndDrain),
                "Endpoint-only route retirement lost its Running Desired"
            );
            let checkpoint_cell = AdmissionSnapshot::from_checkpoint(checkpoint)?;
            match first_endpoint_action(checkpoint, desired)? {
                Some(EndpointAction::Close { endpoint_id }) => {
                    anyhow::ensure!(
                        cell == &checkpoint_cell || current_edge_allows_live,
                        "CloseGate route retirement lost its exact predecessor cell or edge"
                    );
                    Ok(Some(RouteRetirementAction::CloseGate(endpoint_id)))
                }
                Some(EndpointAction::PrepareChanged { endpoint_id, .. }) => {
                    anyhow::ensure!(
                        cell == &checkpoint_cell,
                        "changed-gate preparation lost its exact Closed cell"
                    );
                    Ok(endpoint_is_drained(guards, &endpoint_id)
                        .then_some(RouteRetirementAction::PrepareChanged(endpoint_id)))
                }
                Some(EndpointAction::Remove { endpoint_id }) => {
                    anyhow::ensure!(
                        cell == &checkpoint_cell,
                        "closed-gate removal lost its exact Closed cell"
                    );
                    Ok(endpoint_is_drained(guards, &endpoint_id)
                        .then_some(RouteRetirementAction::RemoveGate(endpoint_id)))
                }
                Some(EndpointAction::Install { endpoint_id, .. }) => Ok(retiring
                    .physical
                    .as_ref()
                    .map(|_| RouteRetirementAction::InstallGate(endpoint_id))),
                None => anyhow::bail!(
                    "superseded Endpoint-only checkpoint has no deterministic transition"
                ),
            }
        }
        RouteRetirementMode::GlobalDesired => {
            if matches!(desired.transition, RuntimeTransition::RequireIdle { .. }) {
                return match &checkpoint.require_idle {
                    RequireIdleCheckpoint::NotApplicable => {
                        Ok(Some(RouteRetirementAction::BeginRequireIdle))
                    }
                    RequireIdleCheckpoint::Armed { .. } => {
                        Ok(Some(RouteRetirementAction::RecoverRequireIdle))
                    }
                    RequireIdleCheckpoint::Busy {
                        gate_closed: false, ..
                    } => Ok(None),
                    RequireIdleCheckpoint::Busy {
                        gate_closed: true, ..
                    }
                    | RequireIdleCheckpoint::Closed { .. } => anyhow::bail!(
                        "RequireIdle checkpoint claims Closed while its live cell remains Open"
                    ),
                };
            }
            Ok(Some(RouteRetirementAction::CloseAll))
        }
        RouteRetirementMode::GlobalPhysicalNegative
            if matches!(
                checkpoint.require_idle,
                RequireIdleCheckpoint::Busy {
                    gate_closed: false,
                    ..
                }
            ) =>
        {
            Ok(Some(RouteRetirementAction::SettleOpenBusyFailClosed))
        }
        RouteRetirementMode::GlobalPhysicalNegative => Ok(Some(RouteRetirementAction::CloseAll)),
    }
}

fn endpoint_is_drained(guards: &super::AdmissionGuardCounts, endpoint_id: &Id) -> bool {
    guards
        .endpoint_guards
        .iter()
        .all(|count| &count.endpoint_id != endpoint_id || count.active_guards == 0)
}

fn plan_running_tail_action(
    desired: &DesiredRuntimeSpec,
    stored: &StoredCheckpoint,
    live: &AdmissionCellObservation,
    store: &FileCheckpointStore,
) -> anyhow::Result<Option<RunningTailAction>> {
    let checkpoint = stored.checkpoint();
    let cell = live.snapshot();
    let guards = live.guards();
    if desired.endpoints.is_empty() {
        anyhow::ensure!(
            checkpoint.route_gates.is_empty() && cell.endpoints().is_empty(),
            "zero-Endpoint admission has an Endpoint predecessor"
        );
        return match cell.lifecycle_admission() {
            LifecycleAdmission::Closed => {
                anyhow::ensure!(
                    guards.platform_guards == 0 && guards.endpoint_guards.is_empty(),
                    "Closed zero-Endpoint admission still has active guards"
                );
                Ok(Some(RunningTailAction::OpenLifecycle))
            }
            LifecycleAdmission::Open
                if checkpoint.lifecycle_admission == LifecycleAdmission::Open
                    && checkpoint.stable_state == Some(StableState::Running)
                    && matches!(
                        checkpoint.step,
                        ReconcileStep::Stable {
                            state: StableState::Running
                        }
                    ) =>
            {
                Ok(None)
            }
            LifecycleAdmission::Open => {
                anyhow::bail!("zero-Endpoint admission is not an exact Stable Running replay")
            }
        };
    }

    let checkpoint_cell = AdmissionSnapshot::from_checkpoint(checkpoint)?;
    if cell == &checkpoint_cell {
        if let ReconcileStep::InstallGate { endpoint_id, .. } = &checkpoint.step {
            let active = checkpoint.route_gates.iter().any(|route| {
                &route.binding.endpoint_id == endpoint_id
                    && route.gate == cats_api::runtime_reconciliation::RouteGateState::Active
            });
            if active {
                // The cell effect linearized but publishing its completed
                // successor failed or lost its response. Only this exact
                // same-process snapshot may finish the burned epoch without
                // invoking the cell effect again.
                return Ok(Some(RunningTailAction::InstallGate(endpoint_id.clone())));
            }
        }
    }
    if let ReconcileStep::InstallGate { endpoint_id, .. } = &checkpoint.step {
        let active = checkpoint.route_gates.iter().any(|route| {
            &route.binding.endpoint_id == endpoint_id
                && route.gate == cats_api::runtime_reconciliation::RouteGateState::Active
        });
        if active && cell != &checkpoint_cell {
            let edge =
                EndpointEffectEdge::new(cell.clone(), checkpoint_cell.clone(), endpoint_id.clone());
            return match store.endpoint_effect_edge_status(&edge)? {
                EndpointEffectEdgeStatus::Exact => {
                    Ok(Some(RunningTailAction::InstallGate(endpoint_id.clone())))
                }
                // A reopened process deliberately has no retained edge. Send
                // the burned Active token through GateSequencer so its sealed
                // transition check returns FreshRouteEpochRequired; silently
                // treating it as converged would strand this epoch forever.
                EndpointEffectEdgeStatus::Missing => {
                    Ok(Some(RunningTailAction::InstallGate(endpoint_id.clone())))
                }
                EndpointEffectEdgeStatus::Mismatch => {
                    anyhow::bail!("Running Active InstallGate edge changed before replay")
                }
            };
        }
    }
    if cell == &checkpoint_cell.fail_closed() && cell != &checkpoint_cell {
        anyhow::ensure!(
            guards.platform_guards == 0 && guards.endpoint_guards.is_empty(),
            "restart-closed Running admission still has active guards"
        );
        // An Agent restart is a real global close. ADR-0041 forbids
        // republishing any previously Active or result-unknown Endpoint epoch,
        // even after the VMM and Guest have been freshly revalidated. Keep the
        // process-local cell closed and expose that fact in the next
        // observation; Control must issue a fresh complete Desired with higher
        // route epochs before this effect may install gates again.
        return Ok(None);
    }

    let action = match first_endpoint_action(checkpoint, desired)? {
        Some(action) => action,
        None => {
            anyhow::ensure!(
                checkpoint.stable_state == Some(StableState::Running)
                    && matches!(
                        checkpoint.step,
                        ReconcileStep::Stable {
                            state: StableState::Running
                        }
                    )
                    && cell == &checkpoint_cell,
                "Endpoint admission has no deterministic successor"
            );
            return Ok(None);
        }
    };

    match action {
        EndpointAction::Close { endpoint_id } => {
            anyhow::ensure!(
                cell == &checkpoint_cell,
                "CloseGate admission lost its exact predecessor cell"
            );
            Ok(Some(RunningTailAction::CloseGate(endpoint_id)))
        }
        EndpointAction::PrepareChanged { endpoint_id, .. } => {
            anyhow::ensure!(
                cell == &checkpoint_cell,
                "changed-gate admission lost its exact Closed cell"
            );
            Ok(endpoint_is_drained(guards, &endpoint_id)
                .then_some(RunningTailAction::PrepareChanged(endpoint_id)))
        }
        EndpointAction::Remove { endpoint_id } => {
            anyhow::ensure!(
                cell == &checkpoint_cell,
                "closed-gate admission lost its exact Closed cell"
            );
            Ok(endpoint_is_drained(guards, &endpoint_id)
                .then_some(RunningTailAction::RemoveGate(endpoint_id)))
        }
        EndpointAction::Install { endpoint_id, .. } => {
            match cell.lifecycle_admission() {
                LifecycleAdmission::Closed => {
                    let prepared_first_shape = matches!(
                        &checkpoint.step,
                        ReconcileStep::InstallGate {
                            endpoint_id: prepared_endpoint,
                            route_epoch,
                        } if prepared_endpoint == &endpoint_id
                            && *route_epoch == desired.endpoints
                                .iter()
                                .find(|endpoint| endpoint.endpoint_id == endpoint_id)
                                .context("planned Endpoint disappeared from Desired")?
                                .route_epoch
                    ) && checkpoint.route_gates.len() == 1
                        && checkpoint.route_gates[0].binding.endpoint_id == endpoint_id
                        && checkpoint.route_gates[0].gate == RouteGateState::Closed;
                    let exact_prepared_first = if prepared_first_shape {
                        let replacement = active_install_snapshot(checkpoint, &endpoint_id)?;
                        let edge =
                            EndpointEffectEdge::new(cell.clone(), replacement, endpoint_id.clone());
                        match store.endpoint_effect_edge_status(&edge)? {
                            EndpointEffectEdgeStatus::Exact | EndpointEffectEdgeStatus::Missing => {
                                true
                            }
                            EndpointEffectEdgeStatus::Mismatch => anyhow::bail!(
                                "prepared Running InstallGate edge changed before replay"
                            ),
                        }
                    } else {
                        false
                    };
                    anyhow::ensure!(
                        checkpoint.lifecycle_admission == LifecycleAdmission::Closed
                            && ((checkpoint.route_gates.is_empty()
                                && cell.endpoints().is_empty())
                                || exact_prepared_first)
                            && guards.platform_guards == 0
                            && guards.endpoint_guards.is_empty(),
                        "only the first empty or exact prepared InstallGate may open lifecycle admission"
                    );
                }
                LifecycleAdmission::Open => {
                    anyhow::ensure!(
                        !checkpoint.route_gates.is_empty()
                            && matches!(
                                &checkpoint.step,
                                ReconcileStep::InstallGate {
                                    endpoint_id: saved_endpoint,
                                    ..
                                } if saved_endpoint == &endpoint_id
                            ),
                        "subsequent InstallGate does not match the durable next step"
                    );
                }
            }
            Ok(Some(RunningTailAction::InstallGate(endpoint_id)))
        }
    }
}

fn next_persist_times(stored: &StoredCheckpoint) -> anyhow::Result<PersistTimes> {
    let wall_clock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis();
    let wall_clock_ms = u64::try_from(wall_clock_ms).context("system time exceeds wire range")?;
    let before = wall_clock_ms.max(
        stored
            .checkpoint()
            .updated_at_unix_ms
            .get()
            .checked_add(1)
            .context("Running-tail checkpoint timestamp exhausted")?,
    );
    let after = before
        .checked_add(1)
        .context("Running-tail checkpoint timestamp exhausted")?;
    Ok(PersistTimes {
        before_effect: UnixMillis::new(before)
            .context("Running-tail checkpoint timestamp is outside wire range")?,
        after_effect: UnixMillis::new(after)
            .context("Running-tail checkpoint timestamp is outside wire range")?,
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use cats_api::route_grant_v2::{
        RouteAdmissionV2Reason, RouteGrantV2Claims, RouteGrantV2TimeVerdict,
        ROUTE_GRANT_V2_AUDIENCE, ROUTE_GRANT_V2_ISSUER, ROUTE_GRANT_V2_VERSION,
    };
    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, spec_digest,
        AdmissionInventoryAttestation, AgentSession, AppliedDesiredEvidence, CheckpointEvidence,
        ContractVersion, DesiredReadSnapshot, DesiredRuntimeSpec, DiskKind, Epoch, Ext4MountIntent,
        FilesystemInitialization, GuestBootId, GuestDeviceIdentity, HostPath, Hostname, NodeBootId,
        ObservedRuntimeStatus, PersistentFilesystemBinding, ReconcileStep, RouteGateState,
        RuntimeLaunch, Sequence, SessionBinding, StableState, WarmSnapshotEvidence,
    };
    use tempfile::TempDir;

    use super::super::checkpoint::{EndpointEffectEdge, WriteStage};
    use super::super::{
        runtime_checkpoint_path, AdmissionCell, AdmissionGatePort, FileCheckpointStore,
        GateReconcileError,
    };
    use super::*;
    use crate::runtime_spine::RuntimeDesiredEffectAdmission;
    use crate::state_directory::StateDirectory;

    const DESIRED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-desired.json"
    ));
    const START_RUNTIME: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
    ));
    const CHECKPOINTS: &str = "checkpoints";

    struct Fixture {
        root: TempDir,
        desired: DesiredRuntimeSpec,
        source_digest: Sha256Digest,
    }

    impl Fixture {
        fn new(endpoint_count: usize) -> Self {
            let root = TempDir::new().expect("tempdir");
            let mut desired = decode_desired_runtime_spec(DESIRED).expect("Desired vector");
            match endpoint_count {
                0 => desired.endpoints.clear(),
                1 => {}
                2 => {
                    let mut second = desired.endpoints[0].clone();
                    second.endpoint_id = Id::new("ep_02").expect("second Endpoint ID");
                    second.hostname =
                        Hostname::new("b.example.test").expect("second Endpoint hostname");
                    second.target_port = 8081;
                    desired.endpoints.push(second);
                }
                3 => {
                    let mut second = desired.endpoints[0].clone();
                    second.endpoint_id = Id::new("ep_02").expect("second Endpoint ID");
                    second.hostname =
                        Hostname::new("b.example.test").expect("second Endpoint hostname");
                    second.target_port = 8081;
                    let mut third = desired.endpoints[0].clone();
                    third.endpoint_id = Id::new("ep_03").expect("third Endpoint ID");
                    third.hostname =
                        Hostname::new("c.example.test").expect("third Endpoint hostname");
                    third.target_port = 8082;
                    desired.endpoints.extend([second, third]);
                }
                _ => panic!("fixture supports at most three Endpoints"),
            }
            desired.spec_digest = spec_digest(&desired).expect("fixture spec digest");
            let mut checkpoint =
                decode_runtime_checkpoint(START_RUNTIME).expect("StartRuntime checkpoint");
            checkpoint.desired_revision = desired.desired_revision;
            checkpoint.spec_digest = desired.spec_digest.clone();
            checkpoint.lifecycle_admission = LifecycleAdmission::Closed;
            checkpoint.route_gates.clear();
            let store = FileCheckpointStore::open(&root.path().join(CHECKPOINTS), &desired.cat_id)
                .expect("checkpoint store");
            let stored = store.create(&checkpoint).expect("source checkpoint");
            let source_digest = stored.content_digest().clone();
            drop(store);
            Self {
                root,
                desired,
                source_digest,
            }
        }

        fn registry(&self) -> Arc<AdmissionCellRegistry> {
            AdmissionCellRegistry::new(self.root.path().join(CHECKPOINTS))
        }

        fn scan(&self, registry: &AdmissionCellRegistry) -> TestScan {
            let (stored, cell_presence, cell) = match registry
                .existing_session(&self.desired.cat_id)
                .expect("registry lookup")
            {
                Some(session) => (
                    session
                        .checkpoint_store()
                        .load()
                        .expect("load current checkpoint")
                        .expect("current checkpoint exists"),
                    RunningTailCellPresence::Present,
                    session.cell().observe(),
                ),
                None => {
                    let store = FileCheckpointStore::open(
                        &self.root.path().join(CHECKPOINTS),
                        &self.desired.cat_id,
                    )
                    .expect("scan checkpoint store");
                    let stored = store
                        .load()
                        .expect("load current checkpoint")
                        .expect("current checkpoint exists");
                    drop(store);
                    let initial = AdmissionSnapshot::from_checkpoint(stored.checkpoint())
                        .expect("checkpoint snapshot")
                        .fail_closed();
                    let cell = AdmissionCell::new(initial).expect("predicted Closed cell");
                    (stored, RunningTailCellPresence::Absent, cell.observe())
                }
            };
            let routes = projected_routes(&cell);
            let observation = observation(&self.desired, &stored, &cell, routes.clone());
            TestScan {
                stored,
                cell_presence,
                cell,
                routes,
                observation,
            }
        }

        fn context(
            &self,
            registry: &AdmissionCellRegistry,
            with_running_tail: bool,
        ) -> RuntimeDesiredEffectContext {
            context(
                self.root.path(),
                &self.desired,
                self.scan(registry),
                with_running_tail,
            )
        }
    }

    struct TestScan {
        stored: StoredCheckpoint,
        cell_presence: RunningTailCellPresence,
        cell: AdmissionCellObservation,
        routes: Vec<ObservedRouteGate>,
        observation: NodeObservation,
    }

    fn pre_scan_context(desired: DesiredRuntimeSpec) -> RuntimePreScanAdmissionContext {
        RuntimePreScanAdmissionContext::for_test(
            crate::runtime_spine::RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: desired.placement.node_id.clone(),
                    node_boot_id: NodeBootId::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
                    agent_instance_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        .unwrap(),
                    agent_session_epoch: Epoch::new(1).unwrap(),
                },
                heartbeat_sequence: Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired: DesiredReadSnapshot {
                    version: ContractVersion::V1,
                    session: SessionBinding {
                        node_id: desired.placement.node_id.clone(),
                        node_boot_id: NodeBootId::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
                        agent_instance_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                            .unwrap(),
                        agent_session_epoch: Epoch::new(1).unwrap(),
                    },
                    request_sequence: Sequence::new(1).unwrap(),
                    read_position: Sequence::new(1).unwrap(),
                    issued_at_unix_ms: UnixMillis::new(1).unwrap(),
                    expires_at_unix_ms: UnixMillis::new(2).unwrap(),
                    desired_specs: vec![desired],
                },
            },
            Instant::now() + Duration::from_secs(2),
        )
    }

    fn add_persistent_phase_volume(
        desired: &mut DesiredRuntimeSpec,
        checkpoint: &mut RuntimeCheckpoint,
        suffix: &str,
        slot: u16,
    ) -> PersistentFilesystemBinding {
        let mut intent = desired.volumes[0].clone();
        intent.volume_intent_id = Id::new(format!("vint_{suffix}")).unwrap();
        intent.disk_id = Id::new(format!("disk_{suffix}")).unwrap();
        intent.volume_id = Id::new(format!("vol_{suffix}")).unwrap();
        intent.attachment_id = Id::new(format!("att_{suffix}")).unwrap();
        intent.disk_kind = DiskKind::Persistent;
        intent.guest_device = GuestDeviceIdentity {
            serial: Id::new(format!("cats-{suffix}")).unwrap(),
            slot,
        };
        let filesystem_uuid = RandomId128::new(format!("{slot:032x}")).unwrap();
        let mount_path = HostPath::new(format!("/mnt/{suffix}")).unwrap();
        intent.mount = Some(Ext4MountIntent {
            filesystem_uuid: filesystem_uuid.clone(),
            mount_path: mount_path.clone(),
            initialization: FilesystemInitialization::Existing,
        });
        desired.volumes.push(intent.clone());

        let RuntimeLaunch::Present(launch) = &mut checkpoint.runtime_launch else {
            panic!("phase fixture retains a launch")
        };
        let mut prepared = launch.devices[0].clone();
        prepared.volume_intent_id = intent.volume_intent_id.clone();
        prepared.disk_id = intent.disk_id.clone();
        prepared.volume_id = intent.volume_id.clone();
        prepared.disk_kind = DiskKind::Persistent;
        prepared.attachment_id = intent.attachment_id.clone();
        prepared.guest_device = intent.guest_device.clone();
        launch.devices.push(prepared.clone());
        PersistentFilesystemBinding {
            runtime_incarnation: launch.runtime_incarnation.clone(),
            volume_intent_id: intent.volume_intent_id,
            disk_id: intent.disk_id,
            volume_id: intent.volume_id,
            attachment_id: intent.attachment_id,
            attachment_epoch: prepared.attachment_epoch,
            size_bytes: intent.size_bytes,
            guest_device: intent.guest_device,
            filesystem_uuid,
            mount_path,
            initialization: FilesystemInitialization::Existing,
        }
    }

    #[test]
    fn persistent_running_tail_phase_is_closed_until_the_final_sorted_mount() {
        let mut desired = decode_desired_runtime_spec(DESIRED).expect("Desired vector");
        let mut checkpoint =
            decode_runtime_checkpoint(START_RUNTIME).expect("StartRuntime checkpoint");
        assert_eq!(
            classify_running_tail_phase(&desired, &checkpoint).unwrap(),
            RunningTailPhase::Admission
        );
        let start_runtime_step = checkpoint.step.clone();
        let first = add_persistent_phase_volume(&mut desired, &mut checkpoint, "data", 1);
        let final_mount = add_persistent_phase_volume(&mut desired, &mut checkpoint, "logs", 2);

        let early = [
            start_runtime_step,
            ReconcileStep::FormatFilesystem {
                filesystem: Box::new(first.clone()),
            },
            ReconcileStep::DrainInitialization {
                filesystem: Box::new(first.clone()),
                local_generation: cats_api::runtime_reconciliation::Generation::new(1).unwrap(),
                remote_generation: cats_api::runtime_reconciliation::Generation::new(1).unwrap(),
            },
            ReconcileStep::CommitInitialized {
                filesystem: Box::new(first.clone()),
                new_remote_head: checkpoint.runtime_launch.identity().unwrap().devices[1]
                    .expected_head
                    .clone(),
            },
            ReconcileStep::MountFilesystem {
                filesystem: Box::new(first),
                expected_head: checkpoint.runtime_launch.identity().unwrap().devices[1]
                    .expected_head
                    .clone(),
            },
        ];
        for step in early {
            checkpoint.step = step;
            assert_eq!(
                classify_running_tail_phase(&desired, &checkpoint).unwrap(),
                RunningTailPhase::Ineligible
            );
        }

        checkpoint.step = ReconcileStep::MountFilesystem {
            filesystem: Box::new(final_mount),
            expected_head: checkpoint.runtime_launch.identity().unwrap().devices[2]
                .expected_head
                .clone(),
        };
        assert_eq!(
            classify_running_tail_phase(&desired, &checkpoint).unwrap(),
            RunningTailPhase::Admission
        );
        checkpoint.step = ReconcileStep::CloseAdmission {
            require_idle_attempt_id: None,
        };
        assert_eq!(
            classify_running_tail_phase(&desired, &checkpoint).unwrap(),
            RunningTailPhase::Ineligible
        );
        checkpoint.step = ReconcileStep::CloseGate {
            endpoint_id: desired.endpoints[0].endpoint_id.clone(),
            route_epoch: desired.endpoints[0].route_epoch,
        };
        assert_eq!(
            classify_running_tail_phase(&desired, &checkpoint).unwrap(),
            RunningTailPhase::EndpointRetirement
        );
    }

    #[test]
    fn production_effect_without_scanner_sealed_authority_is_inert() {
        let fixture = Fixture::new(0);
        let before = std::fs::read(runtime_checkpoint_path(
            &fixture.root.path().join(CHECKPOINTS),
            &fixture.desired.cat_id,
        ))
        .expect("source bytes");
        let registry = fixture.registry();
        let outcome = RunningAdmissionEffect::new(Arc::clone(&registry))
            .try_apply(&fixture.context(&registry, false), &fixture.desired)
            .expect("absent sealed authority is not an error");

        assert_eq!(outcome, None);
        assert!(registry.get(&fixture.desired.cat_id).is_none());
        assert_eq!(
            std::fs::read(runtime_checkpoint_path(
                &fixture.root.path().join(CHECKPOINTS),
                &fixture.desired.cat_id,
            ))
            .expect("unchanged bytes"),
            before
        );
    }

    #[tokio::test]
    async fn mandatory_pre_scan_closes_every_removed_endpoint_but_preserves_unchanged_route() {
        let fixture = Fixture::new(3);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        for _ in 0..3 {
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .unwrap()
                .expect("install each old Endpoint");
        }
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let old = session.cell().snapshot();
        assert!(old
            .endpoints()
            .iter()
            .all(|route| route.gate == RouteGateState::Active));
        let mut guards = old
            .endpoints()
            .iter()
            .map(|route| {
                session
                    .cell()
                    .acquire_verified_route(&claims(&route.binding), RouteGrantV2TimeVerdict::Valid)
                    .unwrap()
                    .0
            })
            .collect::<Vec<_>>();

        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.endpoints = vec![successor.endpoints[1].clone()];
        successor.spec_digest = spec_digest(&successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor.clone()))
            .unwrap();

        let live = session.cell().snapshot();
        assert_eq!(live.endpoints().len(), 3);
        assert!(live
            .endpoints()
            .iter()
            .all(|route| route.gate == RouteGateState::Active));
        let latched = session.cell().observe();
        assert!(latched.endpoint_is_revoked(&live.endpoints()[0].binding.endpoint_id));
        assert!(!latched.endpoint_is_revoked(&live.endpoints()[1].binding.endpoint_id));
        assert!(latched.endpoint_is_revoked(&live.endpoints()[2].binding.endpoint_id));
        let projected = projected_routes(&latched);
        assert!(projected[0].cancellation_pending);
        assert!(!projected[1].cancellation_pending);
        assert!(projected[2].cancellation_pending);
        tokio::time::timeout(Duration::from_secs(1), guards[0].cancelled())
            .await
            .expect("A cancellation");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), guards[1].cancelled())
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), guards[2].cancelled())
            .await
            .expect("C cancellation");
        assert!(matches!(
            session.cell().acquire_verified_route(
                &claims(&live.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            ),
            Err(RouteAdmissionV2Reason::GateClosed)
        ));
        let retained = session
            .cell()
            .acquire_verified_route(
                &claims(&live.endpoints()[1].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .expect("unchanged B remains admissible");
        drop(retained);
        let mut stored = session.checkpoint_store().load().unwrap().unwrap();
        assert_eq!(
            stored.checkpoint().desired_revision,
            fixture.desired.desired_revision
        );
        assert_eq!(stored.checkpoint().route_gates, live.endpoints());

        // Releasing A/C lets the canonical durable journal settle A fully
        // before touching C. B's live guard remains admitted throughout.
        let mut b_guard = guards.remove(1);
        drop(guards);
        let mut order = Vec::new();
        while let Some(action) = first_endpoint_action(stored.checkpoint(), &successor).unwrap() {
            let times = next_persist_times(&stored).unwrap();
            let mut port = session.cell().port();
            let mut sequencer = GateSequencer::new(session.checkpoint_store(), &mut port);
            let result = match action {
                EndpointAction::Close { endpoint_id } => {
                    order.push(format!("close:{}", endpoint_id.as_str()));
                    sequencer
                        .close_gate(&stored, &successor, &endpoint_id, times)
                        .unwrap()
                }
                EndpointAction::Remove { endpoint_id } => {
                    order.push(format!("remove:{}", endpoint_id.as_str()));
                    sequencer
                        .remove_closed_gate(&stored, &successor, &endpoint_id, times.after_effect)
                        .unwrap()
                }
                EndpointAction::PrepareChanged { .. } | EndpointAction::Install { .. } => {
                    panic!("removal-only successor must not prepare or install")
                }
            };
            stored = result.checkpoint().clone();
        }
        assert_eq!(
            order,
            ["close:ep_01", "remove:ep_01", "close:ep_03", "remove:ep_03"]
        );
        assert!(matches!(
            stored.checkpoint().step,
            ReconcileStep::Stable {
                state: StableState::Running
            }
        ));
        assert_eq!(
            stored.checkpoint().desired_revision,
            successor.desired_revision
        );
        let settled = session.cell().snapshot();
        assert_eq!(
            settled,
            AdmissionSnapshot::from_checkpoint(stored.checkpoint()).unwrap()
        );
        assert_eq!(settled.endpoints().len(), 1);
        assert_eq!(settled.endpoints()[0].binding.endpoint_id.as_str(), "ep_02");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), b_guard.cancelled())
                .await
                .is_err()
        );

        // The effect must seal R1 at the Stable linearization point; no
        // intervening R1 pre-scan is required before a direct R2 read.
        seal_stable_running_session(&session, &successor, stored.checkpoint()).unwrap();
        assert_eq!(session.sealed_running_desired().as_ref(), Some(&successor));
        let mut second_successor = successor.clone();
        second_successor.desired_revision =
            Revision::new(second_successor.desired_revision.get() + 1).unwrap();
        second_successor.endpoints[0].route_epoch =
            Epoch::new(second_successor.endpoints[0].route_epoch.get() + 1).unwrap();
        second_successor.endpoints[0].target_port += 10;
        second_successor.spec_digest = spec_digest(&second_successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(second_successor.clone()))
            .unwrap();
        let r2_latched = session.cell().observe();
        assert_eq!(
            r2_latched.snapshot().lifecycle_admission(),
            LifecycleAdmission::Open
        );
        assert!(r2_latched
            .endpoint_is_revoked(&r2_latched.snapshot().endpoints()[0].binding.endpoint_id));
        tokio::time::timeout(Duration::from_secs(1), b_guard.cancelled())
            .await
            .expect("direct R2 cancels its changed B stream");

        let mut leaving_running = second_successor;
        leaving_running.desired_revision =
            Revision::new(leaving_running.desired_revision.get() + 1).unwrap();
        leaving_running.target = RuntimeTarget::Cold;
        leaving_running.spec_digest = spec_digest(&leaving_running).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(leaving_running))
            .unwrap();
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
    }

    #[tokio::test]
    async fn endpoint_latch_survives_incomplete_scan_without_touching_unchanged_route() {
        let fixture = Fixture::new(2);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        for _ in 0..2 {
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .unwrap()
                .unwrap();
        }
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let before = session.checkpoint_store().load().unwrap().unwrap();
        let old = session.cell().snapshot();
        let mut a_guard = session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .unwrap()
            .0;
        let mut b_guard = session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[1].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .unwrap()
            .0;
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.endpoints[0].route_epoch =
            Epoch::new(successor.endpoints[0].route_epoch.get() + 1).unwrap();
        successor.endpoints[0].target_port += 10;
        successor.spec_digest = spec_digest(&successor).unwrap();

        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor.clone()))
            .unwrap();
        // Model a transient scanner Incomplete outcome: no retirement
        // sidecar/effect follows this successful mandatory pre-scan.
        let unchanged = session.checkpoint_store().load().unwrap().unwrap();
        assert_eq!(unchanged.content_digest(), before.content_digest());
        assert_eq!(unchanged.checkpoint(), before.checkpoint());
        tokio::time::timeout(Duration::from_secs(1), a_guard.cancelled())
            .await
            .expect("changed A guard is cancelled by the pre-scan latch");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), b_guard.cancelled())
                .await
                .is_err(),
            "unchanged B guard must survive Incomplete inventory"
        );
        assert!(session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .is_err());
        let new_a_binding = route_binding(
            &successor,
            &successor.endpoints[0],
            old.runtime_incarnation(),
        )
        .unwrap();
        assert!(session
            .cell()
            .acquire_verified_route(&claims(&new_a_binding), RouteGrantV2TimeVerdict::Valid,)
            .is_err());
        let b = session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[1].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .expect("unchanged B remains admissible after Incomplete inventory");
        drop(b);
    }

    #[tokio::test]
    async fn latched_changed_and_removed_endpoints_settle_one_at_a_time() {
        let fixture = Fixture::new(3);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        for _ in 0..3 {
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .unwrap()
                .unwrap();
        }
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let old = session.cell().snapshot();
        let mut guards = old
            .endpoints()
            .iter()
            .map(|route| {
                session
                    .cell()
                    .acquire_verified_route(&claims(&route.binding), RouteGrantV2TimeVerdict::Valid)
                    .unwrap()
                    .0
            })
            .collect::<Vec<_>>();
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.endpoints[0].route_epoch =
            Epoch::new(successor.endpoints[0].route_epoch.get() + 1).unwrap();
        successor.endpoints[0].target_port += 10;
        successor.endpoints.pop();
        successor.spec_digest = spec_digest(&successor).unwrap();

        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor.clone()))
            .unwrap();
        let latched = session.cell().observe();
        assert!(latched.endpoint_is_revoked(&old.endpoints()[0].binding.endpoint_id));
        assert!(!latched.endpoint_is_revoked(&old.endpoints()[1].binding.endpoint_id));
        assert!(latched.endpoint_is_revoked(&old.endpoints()[2].binding.endpoint_id));
        tokio::time::timeout(Duration::from_secs(1), guards[0].cancelled())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), guards[2].cancelled())
            .await
            .unwrap();
        let mut b_guard = guards.remove(1);
        drop(guards);

        let mut stored = session.checkpoint_store().load().unwrap().unwrap();
        let mut order = Vec::new();
        while let Some(action) = first_endpoint_action(stored.checkpoint(), &successor).unwrap() {
            let times = next_persist_times(&stored).unwrap();
            let mut port = session.cell().port();
            let mut sequencer = GateSequencer::new(session.checkpoint_store(), &mut port);
            let result = match action {
                EndpointAction::Close { endpoint_id } => {
                    order.push(format!("close:{}", endpoint_id.as_str()));
                    sequencer
                        .close_gate(&stored, &successor, &endpoint_id, times)
                        .unwrap()
                }
                EndpointAction::PrepareChanged { endpoint_id, .. } => {
                    order.push(format!("prepare:{}", endpoint_id.as_str()));
                    sequencer
                        .prepare_changed_gate(&stored, &successor, &endpoint_id, times.after_effect)
                        .unwrap()
                }
                EndpointAction::Install { endpoint_id, .. } => {
                    order.push(format!("install:{}", endpoint_id.as_str()));
                    sequencer
                        .install_gate_with_barrier(
                            &stored,
                            &successor,
                            &endpoint_id,
                            times,
                            |_, _| Ok(()),
                        )
                        .unwrap()
                }
                EndpointAction::Remove { endpoint_id } => {
                    order.push(format!("remove:{}", endpoint_id.as_str()));
                    sequencer
                        .remove_closed_gate(&stored, &successor, &endpoint_id, times.after_effect)
                        .unwrap()
                }
            };
            stored = result.checkpoint().clone();
        }
        assert_eq!(
            order,
            [
                "close:ep_01",
                "prepare:ep_01",
                "install:ep_01",
                "close:ep_03",
                "remove:ep_03",
            ]
        );
        assert!(matches!(
            stored.checkpoint().step,
            ReconcileStep::Stable {
                state: StableState::Running
            }
        ));
        let settled = session.cell().observe();
        assert_eq!(
            settled.snapshot(),
            &AdmissionSnapshot::from_checkpoint(stored.checkpoint()).unwrap()
        );
        assert!(!settled.endpoint_is_revoked(&old.endpoints()[0].binding.endpoint_id));
        assert!(!settled.endpoint_is_revoked(&old.endpoints()[2].binding.endpoint_id));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), b_guard.cancelled())
                .await
                .is_err()
        );
    }

    #[test]
    fn endpoint_successor_effect_seals_stable_before_an_immediate_next_revision() {
        let fixture = Fixture::new(2);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        for _ in 0..2 {
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .unwrap()
                .unwrap();
        }
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let mut first_successor = fixture.desired.clone();
        first_successor.desired_revision =
            Revision::new(first_successor.desired_revision.get() + 1).unwrap();
        first_successor.endpoints[0].route_epoch =
            Epoch::new(first_successor.endpoints[0].route_epoch.get() + 1).unwrap();
        first_successor.endpoints[0].target_port += 10;
        first_successor.spec_digest = spec_digest(&first_successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(first_successor.clone()))
            .unwrap();

        for _ in 0..8 {
            let stored = session.checkpoint_store().load().unwrap().unwrap();
            if stored.checkpoint().desired_revision == first_successor.desired_revision
                && matches!(
                    stored.checkpoint().step,
                    ReconcileStep::Stable {
                        state: StableState::Running
                    }
                )
            {
                break;
            }
            let context = if stored.checkpoint().desired_revision < first_successor.desired_revision
            {
                retirement_context(
                    fixture.root.path(),
                    &first_successor,
                    &fixture.desired,
                    &session,
                    RouteRetirementMode::EndpointOnly,
                    true,
                )
            } else {
                ready_context(fixture.root.path(), &first_successor, &session)
            };
            let outcome =
                if stored.checkpoint().desired_revision < first_successor.desired_revision {
                    effect.try_retire(&context, &first_successor)
                } else {
                    effect.try_apply(&context, &first_successor)
                }
                .unwrap();
            assert_eq!(outcome, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let stable = session.checkpoint_store().load().unwrap().unwrap();
        assert!(matches!(
            stable.checkpoint().step,
            ReconcileStep::Stable {
                state: StableState::Running
            }
        ));
        assert_eq!(
            session.sealed_running_desired().as_ref(),
            Some(&first_successor)
        );

        let mut second_successor = first_successor.clone();
        second_successor.desired_revision =
            Revision::new(second_successor.desired_revision.get() + 1).unwrap();
        second_successor.endpoints[1].route_epoch =
            Epoch::new(second_successor.endpoints[1].route_epoch.get() + 1).unwrap();
        second_successor.endpoints[1].target_port += 10;
        second_successor.spec_digest = spec_digest(&second_successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(second_successor))
            .expect("R2 directly follows the R1 effect without an R1 pre-scan");
        let live = session.cell().observe();
        assert_eq!(
            live.snapshot().lifecycle_admission(),
            LifecycleAdmission::Open
        );
        assert!(!live.endpoint_is_revoked(&live.snapshot().endpoints()[0].binding.endpoint_id));
        assert!(live.endpoint_is_revoked(&live.snapshot().endpoints()[1].binding.endpoint_id));
    }

    #[test]
    fn current_endpoint_checkpoint_replays_its_exact_sealed_predecessor_edge() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let predecessor = session.checkpoint_store().load().unwrap().unwrap();
        let source_cell = session.cell().snapshot();

        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.endpoints[0].route_epoch =
            Epoch::new(successor.endpoints[0].route_epoch.get() + 1).unwrap();
        successor.endpoints[0].target_port += 10;
        successor.spec_digest = spec_digest(&successor).unwrap();
        let endpoint_id = successor.endpoints[0].endpoint_id.clone();

        // Model a process-local response loss after the CloseGate token and
        // exact effect edge are durable, but before the AdmissionCell compare
        // close. The cell still names the sealed predecessor R1.
        let mut staged = predecessor.checkpoint().clone();
        staged.desired_revision = successor.desired_revision;
        staged.spec_digest = successor.spec_digest.clone();
        staged.stable_state = None;
        staged.require_idle = RequireIdleCheckpoint::NotApplicable;
        staged.step = ReconcileStep::CloseGate {
            endpoint_id: endpoint_id.clone(),
            route_epoch: source_cell.endpoints()[0].binding.route_epoch,
        };
        staged.updated_at_unix_ms = UnixMillis::new(staged.updated_at_unix_ms.get() + 1).unwrap();
        let mut closed = staged.clone();
        closed.route_gates[0].gate = RouteGateState::Closed;
        let edge = EndpointEffectEdge::new(
            source_cell.clone(),
            AdmissionSnapshot::from_checkpoint(&closed).unwrap(),
            endpoint_id.clone(),
        );
        assert!(session
            .checkpoint_store()
            .arm_endpoint_effect_edge(&edge)
            .unwrap());
        session
            .checkpoint_store()
            .replace(&predecessor, &staged)
            .unwrap();

        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor.clone()))
            .expect("exact current checkpoint edge remains a closed continuation");
        assert_eq!(session.cell().snapshot(), source_cell);
        assert!(session.cell().observe().endpoint_is_revoked(&endpoint_id));

        let accepted = retirement_context(
            fixture.root.path(),
            &successor,
            &fixture.desired,
            &session,
            RouteRetirementMode::EndpointOnly,
            true,
        );
        assert_eq!(
            effect.try_retire(&accepted, &successor).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let closed_cell = session.cell().snapshot();
        assert_eq!(closed_cell.lifecycle_admission(), LifecycleAdmission::Open);
        assert_eq!(closed_cell.endpoints()[0].gate, RouteGateState::Closed);
        assert_eq!(
            closed_cell.applied_desired_revision(),
            successor.desired_revision
        );
    }

    #[tokio::test]
    async fn current_global_checkpoint_settles_an_exact_sealed_fail_closed_source() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let predecessor = session.checkpoint_store().load().unwrap().unwrap();
        let source_cell = session.cell().snapshot();
        let mut guard = session
            .cell()
            .acquire_verified_route(
                &claims(&source_cell.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .unwrap()
            .0;

        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.target = RuntimeTarget::Cold;
        successor.spec_digest = spec_digest(&successor).unwrap();
        let mut staged = predecessor.checkpoint().clone();
        staged.desired_revision = successor.desired_revision;
        staged.spec_digest = successor.spec_digest.clone();
        staged.lifecycle_admission = LifecycleAdmission::Closed;
        staged
            .route_gates
            .iter_mut()
            .for_each(|route| route.gate = RouteGateState::Closed);
        staged.stable_state = None;
        staged.require_idle = RequireIdleCheckpoint::NotApplicable;
        staged.step = ReconcileStep::CloseAdmission {
            require_idle_attempt_id: None,
        };
        staged.updated_at_unix_ms = UnixMillis::new(staged.updated_at_unix_ms.get() + 1).unwrap();
        session
            .checkpoint_store()
            .replace(&predecessor, &staged)
            .unwrap();

        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor))
            .expect("checkpoint-first global close settles its exact sealed source");
        tokio::time::timeout(Duration::from_secs(1), guard.cancelled())
            .await
            .expect("global recovery cancels the old stream");
        let live = session.cell().snapshot();
        assert_eq!(live.lifecycle_admission(), LifecycleAdmission::Closed);
        assert_eq!(live, AdmissionSnapshot::from_checkpoint(&staged).unwrap());
        assert!(matches!(
            session.cell().acquire_verified_route(
                &claims(&source_cell.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            ),
            Err(RouteAdmissionV2Reason::GateClosed)
        ));
    }

    #[tokio::test]
    async fn physical_exact_require_idle_busy_preserves_open_source_and_guard() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let old = session.cell().snapshot();
        let mut guard = session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .unwrap()
            .0;
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.target = RuntimeTarget::Suspended;
        successor.transition = RuntimeTransition::RequireIdle {
            attempt_id: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
            source_revision: fixture.desired.desired_revision,
            source_runtime_incarnation: old.runtime_incarnation().cloned().unwrap(),
        };
        successor.spec_digest = spec_digest(&successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor.clone()))
            .unwrap();

        let exact = retirement_context(
            fixture.root.path(),
            &successor,
            &fixture.desired,
            &session,
            RouteRetirementMode::GlobalDesired,
            false,
        );
        assert_eq!(
            effect.try_retire(&exact, &successor).unwrap(),
            Some(RuntimeDesiredEffectOutcome::Applied)
        );
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Open
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(25), guard.cancelled())
                .await
                .is_err()
        );
        assert!(session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .is_ok());
    }

    #[tokio::test]
    async fn complete_physical_negative_overrides_require_idle_busy_and_closes_all() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let old = session.cell().snapshot();
        let mut guard = session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .unwrap()
            .0;
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.target = RuntimeTarget::Suspended;
        successor.transition = RuntimeTransition::RequireIdle {
            attempt_id: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
            source_revision: fixture.desired.desired_revision,
            source_runtime_incarnation: old.runtime_incarnation().cloned().unwrap(),
        };
        successor.spec_digest = spec_digest(&successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor.clone()))
            .unwrap();
        assert!(matches!(
            session
                .checkpoint_store()
                .load()
                .unwrap()
                .unwrap()
                .checkpoint()
                .require_idle,
            RequireIdleCheckpoint::Busy {
                gate_closed: false,
                ..
            }
        ));

        let negative = retirement_context(
            fixture.root.path(),
            &successor,
            &fixture.desired,
            &session,
            RouteRetirementMode::GlobalPhysicalNegative,
            false,
        );
        assert_eq!(
            effect.try_retire(&negative, &successor).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        tokio::time::timeout(Duration::from_secs(1), guard.cancelled())
            .await
            .expect("complete physical negative cancels Busy/Open stream");
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        assert!(session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .is_err());
    }

    #[tokio::test]
    async fn complete_physical_negative_overrides_endpoint_latch_and_closes_unchanged_route() {
        let fixture = Fixture::new(2);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        for _ in 0..2 {
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .unwrap()
                .unwrap();
        }
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let old = session.cell().snapshot();
        let mut guards = old
            .endpoints()
            .iter()
            .map(|route| {
                session
                    .cell()
                    .acquire_verified_route(&claims(&route.binding), RouteGrantV2TimeVerdict::Valid)
                    .unwrap()
                    .0
            })
            .collect::<Vec<_>>();
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.endpoints[0].route_epoch =
            Epoch::new(successor.endpoints[0].route_epoch.get() + 1).unwrap();
        successor.endpoints[0].target_port += 10;
        successor.spec_digest = spec_digest(&successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor.clone()))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), guards[0].cancelled())
            .await
            .expect("changed A is latched before the physical scan");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), guards[1].cancelled())
                .await
                .is_err()
        );

        let negative = retirement_context(
            fixture.root.path(),
            &successor,
            &fixture.desired,
            &session,
            RouteRetirementMode::GlobalPhysicalNegative,
            false,
        );
        assert_eq!(
            effect.try_retire(&negative, &successor).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        tokio::time::timeout(Duration::from_secs(1), guards[1].cancelled())
            .await
            .expect("complete physical negative cancels unchanged B too");
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
    }

    #[tokio::test]
    async fn global_close_ignores_guard_count_race_but_session_removal_waits_for_drain() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let accepted = retirement_context(
            fixture.root.path(),
            &fixture.desired,
            &fixture.desired,
            &session,
            RouteRetirementMode::GlobalDesired,
            false,
        );
        let open = session.cell().snapshot();
        let mut guard = session
            .cell()
            .acquire_verified_route(
                &claims(&open.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .unwrap()
            .0;

        assert_eq!(
            effect.try_retire(&accepted, &fixture.desired).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        tokio::time::timeout(Duration::from_secs(1), guard.cancelled())
            .await
            .expect("global close cancels the racing guard");

        let draining = retirement_context(
            fixture.root.path(),
            &fixture.desired,
            &fixture.desired,
            &session,
            RouteRetirementMode::GlobalDesired,
            false,
        );
        assert_eq!(
            effect.try_retire(&draining, &fixture.desired).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert!(registry.get(&fixture.desired.cat_id).is_some());
        drop(guard);

        let drained = retirement_context(
            fixture.root.path(),
            &fixture.desired,
            &fixture.desired,
            &session,
            RouteRetirementMode::GlobalDesired,
            false,
        );
        assert_eq!(
            effect.try_retire(&drained, &fixture.desired).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert!(registry.get(&fixture.desired.cat_id).is_none());
    }

    #[tokio::test]
    async fn mandatory_pre_scan_global_mismatch_closes_and_cancels_every_route() {
        let fixture = Fixture::new(2);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        for _ in 0..2 {
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .unwrap()
                .unwrap();
        }
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let old = session.cell().snapshot();
        let mut guards = old
            .endpoints()
            .iter()
            .map(|route| {
                session
                    .cell()
                    .acquire_verified_route(&claims(&route.binding), RouteGrantV2TimeVerdict::Valid)
                    .unwrap()
                    .0
            })
            .collect::<Vec<_>>();
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.target = RuntimeTarget::Cold;
        successor.spec_digest = spec_digest(&successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor))
            .unwrap();
        let live = session.cell().snapshot();
        assert_eq!(live.lifecycle_admission(), LifecycleAdmission::Closed);
        assert!(live
            .endpoints()
            .iter()
            .all(|route| route.gate == RouteGateState::Closed));
        for guard in &mut guards {
            tokio::time::timeout(Duration::from_secs(1), guard.cancelled())
                .await
                .expect("global cancellation");
        }
    }

    #[tokio::test]
    async fn mandatory_pre_scan_require_idle_busy_preserves_open_epoch() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let old = session.cell().snapshot();
        let mut guard = session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .unwrap()
            .0;
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.target = RuntimeTarget::Suspended;
        successor.transition = RuntimeTransition::RequireIdle {
            attempt_id: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
            source_revision: fixture.desired.desired_revision,
            source_runtime_incarnation: old.runtime_incarnation().cloned().unwrap(),
        };
        successor.spec_digest = spec_digest(&successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&registry))
            .reconcile(pre_scan_context(successor))
            .unwrap();
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Open
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(25), guard.cancelled())
                .await
                .is_err()
        );
        let stored = session.checkpoint_store().load().unwrap().unwrap();
        assert!(matches!(
            stored.checkpoint().require_idle,
            RequireIdleCheckpoint::Busy {
                gate_closed: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn mandatory_pre_scan_settles_open_busy_after_timeout_fail_close() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let old = session.cell().snapshot();
        let mut guard = session
            .cell()
            .acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .unwrap()
            .0;
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.target = RuntimeTarget::Suspended;
        successor.transition = RuntimeTransition::RequireIdle {
            attempt_id: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
            source_revision: fixture.desired.desired_revision,
            source_runtime_incarnation: old.runtime_incarnation().cloned().unwrap(),
        };
        successor.spec_digest = spec_digest(&successor).unwrap();
        let pre_scan = RunningAdmissionPreScan::new(Arc::clone(&registry));
        pre_scan
            .reconcile(pre_scan_context(successor.clone()))
            .unwrap();
        let busy = session.checkpoint_store().load().unwrap().unwrap();
        let RequireIdleCheckpoint::Busy {
            platform_guards,
            endpoint_guards,
            gate_closed: false,
            ..
        } = &busy.checkpoint().require_idle
        else {
            panic!("first RequireIdle pass must record Busy/Open")
        };
        assert_eq!(*platform_guards, 0);
        assert_eq!(endpoint_guards.len(), 1);
        let saved_guards = endpoint_guards.clone();

        // This is the runner's synchronous fallback racing after the worker
        // durably produced Busy/Open but before its response was received.
        session.cell().force_close();
        tokio::time::timeout(Duration::from_secs(1), guard.cancelled())
            .await
            .expect("timeout fallback cancels the stream");
        pre_scan
            .reconcile(pre_scan_context(successor))
            .expect("next mandatory pass settles the terminal closed result");

        let settled = session.checkpoint_store().load().unwrap().unwrap();
        assert!(matches!(
            &settled.checkpoint().require_idle,
            RequireIdleCheckpoint::Busy {
                gate_closed: true,
                platform_guards: 0,
                endpoint_guards,
                ..
            } if endpoint_guards == &saved_guards
        ));
        assert_eq!(
            session.cell().snapshot(),
            AdmissionSnapshot::from_checkpoint(settled.checkpoint()).unwrap()
        );
        assert!(matches!(
            session.cell().acquire_verified_route(
                &claims(&old.endpoints()[0].binding),
                RouteGrantV2TimeVerdict::Valid,
            ),
            Err(RouteAdmissionV2Reason::GateClosed)
        ));
    }

    #[test]
    fn mandatory_pre_scan_rejects_each_drifted_require_idle_source_coordinate() {
        for drift in ["attempt", "revision", "incarnation"] {
            let fixture = Fixture::new(1);
            let registry = fixture.registry();
            let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .unwrap()
                .unwrap();
            let session = registry
                .existing_session(&fixture.desired.cat_id)
                .unwrap()
                .unwrap();
            let old = session.cell().snapshot();
            let _guard = session
                .cell()
                .acquire_verified_route(
                    &claims(&old.endpoints()[0].binding),
                    RouteGrantV2TimeVerdict::Valid,
                )
                .unwrap()
                .0;
            let mut successor = fixture.desired.clone();
            successor.desired_revision =
                Revision::new(successor.desired_revision.get() + 1).unwrap();
            successor.target = RuntimeTarget::Suspended;
            successor.transition = RuntimeTransition::RequireIdle {
                attempt_id: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
                source_revision: fixture.desired.desired_revision,
                source_runtime_incarnation: old.runtime_incarnation().cloned().unwrap(),
            };
            successor.spec_digest = spec_digest(&successor).unwrap();
            let pre_scan = RunningAdmissionPreScan::new(Arc::clone(&registry));
            pre_scan
                .reconcile(pre_scan_context(successor.clone()))
                .unwrap();
            let busy = session.checkpoint_store().load().unwrap().unwrap();
            let mut poisoned = busy.checkpoint().clone();
            let RequireIdleCheckpoint::Busy {
                attempt_id,
                source_revision,
                source_runtime_incarnation,
                ..
            } = &mut poisoned.require_idle
            else {
                panic!("fixture did not persist Busy/Open")
            };
            match drift {
                "attempt" => {
                    *attempt_id = RandomId128::new("dddddddddddddddddddddddddddddddd").unwrap();
                }
                "revision" => {
                    *source_revision = Revision::new(source_revision.get() + 1).unwrap();
                }
                "incarnation" => {
                    *source_runtime_incarnation =
                        RandomId128::new("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
                }
                _ => unreachable!(),
            }
            poisoned.updated_at_unix_ms =
                UnixMillis::new(poisoned.updated_at_unix_ms.get() + 1).unwrap();
            session
                .checkpoint_store()
                .replace(&busy, &poisoned)
                .unwrap();

            let error = pre_scan
                .reconcile(pre_scan_context(successor))
                .expect_err("drifted RequireIdle tuple retained admission");
            assert!(format!("{error:#}").contains("different source tuples"));
            assert_eq!(
                session.cell().snapshot().lifecycle_admission(),
                LifecycleAdmission::Closed,
                "{drift} drift did not fail closed"
            );
        }
    }

    #[test]
    fn sealed_zero_endpoint_effect_reopens_only_after_a_fresh_restart_admission() {
        let fixture = Fixture::new(0);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        assert_eq!(
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("open zero-Endpoint Running tail"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let first_cell = registry
            .get(&fixture.desired.cat_id)
            .expect("registered cell");
        assert_eq!(
            first_cell.snapshot().lifecycle_admission(),
            LifecycleAdmission::Open
        );
        drop(effect);
        drop(registry);
        assert_eq!(
            first_cell.snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );

        let store = FileCheckpointStore::open(
            &fixture.root.path().join(CHECKPOINTS),
            &fixture.desired.cat_id,
        )
        .expect("successor checkpoint store");
        let stable = store
            .load()
            .expect("load stable checkpoint")
            .expect("stable checkpoint exists");
        assert_eq!(stable.checkpoint().stable_state, Some(StableState::Running));
        assert_eq!(
            stable.checkpoint().lifecycle_admission,
            LifecycleAdmission::Open
        );
        drop(store);

        let successor = fixture.registry();
        let successor_effect = RunningAdmissionEffect::new(Arc::clone(&successor));
        assert_eq!(
            successor_effect
                .try_apply(&fixture.context(&successor, true), &fixture.desired)
                .expect("reopen only from fresh accepted-full authority"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            successor
                .get(&fixture.desired.cat_id)
                .expect("successor cell")
                .snapshot()
                .lifecycle_admission(),
            LifecycleAdmission::Open
        );
    }

    #[test]
    fn sealed_endpoint_effect_installs_the_first_gate_on_the_same_registry() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        assert_eq!(
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("install first Endpoint gate"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let cell = registry
            .get(&fixture.desired.cat_id)
            .expect("registered cell");
        let snapshot = cell.snapshot();
        assert_eq!(snapshot.lifecycle_admission(), LifecycleAdmission::Open);
        assert_eq!(snapshot.endpoints().len(), 1);
        assert_eq!(snapshot.endpoints()[0].gate, RouteGateState::Active);
        assert_eq!(
            snapshot.endpoints()[0].binding.endpoint_id,
            fixture.desired.endpoints[0].endpoint_id
        );
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .expect("registry lookup")
            .expect("existing session");
        let stable = session
            .checkpoint_store()
            .load()
            .expect("load final checkpoint")
            .expect("final checkpoint exists");
        assert_eq!(stable.checkpoint().stable_state, Some(StableState::Running));
        assert_eq!(stable.checkpoint().route_gates.len(), 1);
        assert_eq!(
            stable.checkpoint().route_gates[0].gate,
            RouteGateState::Active
        );
        assert_eq!(stable.checkpoint().runtime_launch, fixture_runtime_launch());
    }

    #[test]
    fn sealed_session_advances_only_across_an_endpoint_only_successor() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        RunningAdmissionEffect::new(Arc::clone(&registry))
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let mut endpoint_successor = fixture.desired.clone();
        endpoint_successor.desired_revision =
            Revision::new(endpoint_successor.desired_revision.get() + 1).unwrap();
        endpoint_successor.endpoints[0].route_epoch =
            Epoch::new(endpoint_successor.endpoints[0].route_epoch.get() + 1).unwrap();
        endpoint_successor.spec_digest = spec_digest(&endpoint_successor).unwrap();
        session
            .advance_sealed_running_desired(endpoint_successor.clone())
            .expect("exact endpoint-only successor");
        assert_eq!(
            session.sealed_running_desired().as_ref(),
            Some(&endpoint_successor)
        );

        let mut invalid = Vec::new();
        let mut runtime = endpoint_successor.clone();
        runtime.desired_revision = Revision::new(runtime.desired_revision.get() + 1).unwrap();
        runtime.runtime.vcpus += 1;
        runtime.spec_digest = spec_digest(&runtime).unwrap();
        invalid.push(runtime);

        let mut volume = endpoint_successor.clone();
        volume.desired_revision = Revision::new(volume.desired_revision.get() + 1).unwrap();
        volume.volumes[0].size_bytes += 4096;
        volume.spec_digest = spec_digest(&volume).unwrap();
        invalid.push(volume);

        let mut placement = endpoint_successor.clone();
        placement.desired_revision = Revision::new(placement.desired_revision.get() + 1).unwrap();
        placement.placement.placement_epoch =
            Epoch::new(placement.placement.placement_epoch.get() + 1).unwrap();
        placement.spec_digest = spec_digest(&placement).unwrap();
        invalid.push(placement);

        let mut transition = endpoint_successor.clone();
        transition.desired_revision = Revision::new(transition.desired_revision.get() + 1).unwrap();
        transition.transition = RuntimeTransition::RequireIdle {
            attempt_id: RandomId128::new("dddddddddddddddddddddddddddddddd").unwrap(),
            source_revision: endpoint_successor.desired_revision,
            source_runtime_incarnation: session
                .cell()
                .snapshot()
                .runtime_incarnation()
                .cloned()
                .unwrap(),
        };
        transition.target = RuntimeTarget::Suspended;
        transition.spec_digest = spec_digest(&transition).unwrap();
        invalid.push(transition);

        let mut non_increasing = endpoint_successor.clone();
        non_increasing.endpoints[0].target_port += 1;
        non_increasing.spec_digest = spec_digest(&non_increasing).unwrap();
        invalid.push(non_increasing);

        for candidate in invalid {
            assert!(session.advance_sealed_running_desired(candidate).is_err());
            assert_eq!(
                session.sealed_running_desired().as_ref(),
                Some(&endpoint_successor)
            );
        }
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
    }

    #[test]
    fn prepared_first_install_replays_only_with_the_retained_process_edge() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let crash_registry = Arc::clone(&registry);
        let crash_cat_id = fixture.desired.cat_id.clone();
        let crashing = RunningAdmissionEffect::new(Arc::clone(&registry)).with_after_registry(
            Arc::new(move |_| {
                let session = crash_registry
                    .existing_session(&crash_cat_id)
                    .expect("registry lookup")
                    .expect("effect registered a session before planning");
                // The first publication is the Closed prepared token; fail
                // the following Active publication before the cell effect.
                session
                    .checkpoint_store()
                    .inject_crash_on_nth(WriteStage::TempWritten, 2);
            }),
        );
        let error = crashing
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .expect_err("injected Active publication crash");
        assert!(error
            .downcast_ref::<GateReconcileError>()
            .is_some_and(|error| matches!(
                error,
                GateReconcileError::Checkpoint(super::super::CheckpointStoreError::InjectedCrash)
            )));
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let prepared = session.checkpoint_store().load().unwrap().unwrap();
        assert!(matches!(
            prepared.checkpoint().step,
            ReconcileStep::InstallGate { .. }
        ));
        assert_eq!(prepared.checkpoint().route_gates.len(), 1);
        assert_eq!(
            prepared.checkpoint().route_gates[0].gate,
            RouteGateState::Closed
        );
        assert!(session.cell().snapshot().endpoints().is_empty());

        assert_eq!(
            RunningAdmissionEffect::new(Arc::clone(&registry))
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("same-process retained edge resumes the prepared token"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            session.cell().snapshot().endpoints()[0].gate,
            RouteGateState::Active
        );

        let restarted_fixture = Fixture::new(1);
        let restarted_registry = restarted_fixture.registry();
        let crash_registry = Arc::clone(&restarted_registry);
        let crash_cat_id = restarted_fixture.desired.cat_id.clone();
        let crashing = RunningAdmissionEffect::new(Arc::clone(&restarted_registry))
            .with_after_registry(Arc::new(move |_| {
                let session = crash_registry
                    .existing_session(&crash_cat_id)
                    .unwrap()
                    .unwrap();
                session
                    .checkpoint_store()
                    .inject_crash_on_nth(WriteStage::TempWritten, 2);
            }));
        crashing
            .try_apply(
                &restarted_fixture.context(&restarted_registry, true),
                &restarted_fixture.desired,
            )
            .expect_err("leave a durable prepared token");
        drop(crashing);
        drop(restarted_registry);

        let reopened = restarted_fixture.registry();
        let error = RunningAdmissionEffect::new(Arc::clone(&reopened))
            .try_apply(
                &restarted_fixture.context(&reopened, true),
                &restarted_fixture.desired,
            )
            .expect_err("a restarted process cannot replay the old route epoch");
        assert!(error
            .downcast_ref::<GateReconcileError>()
            .is_some_and(|error| matches!(
                error,
                GateReconcileError::FreshRouteEpochRequired(endpoint_id)
                    if endpoint_id == &restarted_fixture.desired.endpoints[0].endpoint_id
            )));
        let reopened_session = reopened
            .existing_session(&restarted_fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            reopened_session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        assert_eq!(
            reopened_session
                .checkpoint_store()
                .load()
                .unwrap()
                .unwrap()
                .checkpoint()
                .route_gates[0]
                .gate,
            RouteGateState::Closed
        );
    }

    #[test]
    fn active_install_barrier_failure_retries_only_with_the_retained_process_edge() {
        let fixture = Fixture::new(1);
        let registry = fixture.registry();
        let failing = RunningAdmissionEffect::new(Arc::clone(&registry)).with_gate_barrier(
            Arc::new(|store, accepted, durable| {
                assert!(matches!(
                    accepted.checkpoint().step,
                    ReconcileStep::StartRuntime { .. }
                ));
                assert!(matches!(
                    durable.checkpoint().step,
                    ReconcileStep::InstallGate { .. }
                ));
                assert_eq!(
                    durable.checkpoint().route_gates[0].gate,
                    RouteGateState::Active
                );
                let current = store.load()?.expect("durable Active checkpoint");
                assert_eq!(current.content_digest(), durable.content_digest());
                anyhow::bail!("injected final authority barrier failure")
            }),
        );
        let error = failing
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .expect_err("the barrier fails after burning the route epoch");
        assert!(error
            .downcast_ref::<GateReconcileError>()
            .is_some_and(|error| matches!(error, GateReconcileError::AdmissionBarrier(_))));
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let active = session.checkpoint_store().load().unwrap().unwrap();
        assert_eq!(
            active.checkpoint().route_gates[0].gate,
            RouteGateState::Active
        );
        assert!(session.cell().snapshot().endpoints().is_empty());

        assert_eq!(
            RunningAdmissionEffect::new(Arc::clone(&registry))
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("same-process retained edge retries the fresh barrier and cell effect"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            session.cell().snapshot().endpoints()[0].gate,
            RouteGateState::Active
        );

        let restarted_fixture = Fixture::new(1);
        let restarted_registry = restarted_fixture.registry();
        let failing = RunningAdmissionEffect::new(Arc::clone(&restarted_registry))
            .with_gate_barrier(Arc::new(|_, _, _| {
                anyhow::bail!("injected final authority barrier failure")
            }));
        failing
            .try_apply(
                &restarted_fixture.context(&restarted_registry, true),
                &restarted_fixture.desired,
            )
            .expect_err("leave Active durable and the cell at its edge predecessor");
        drop(failing);
        drop(restarted_registry);

        let reopened = restarted_fixture.registry();
        let error = RunningAdmissionEffect::new(Arc::clone(&reopened))
            .try_apply(
                &restarted_fixture.context(&reopened, true),
                &restarted_fixture.desired,
            )
            .expect_err("restart cannot replay the burned route epoch without its edge");
        assert!(error
            .downcast_ref::<GateReconcileError>()
            .is_some_and(|error| matches!(
                error,
                GateReconcileError::FreshRouteEpochRequired(endpoint_id)
                    if endpoint_id == &restarted_fixture.desired.endpoints[0].endpoint_id
            )));
        let session = reopened
            .existing_session(&restarted_fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        assert_eq!(
            session
                .checkpoint_store()
                .load()
                .unwrap()
                .unwrap()
                .checkpoint()
                .route_gates[0]
                .gate,
            RouteGateState::Active,
            "the burned Active token remains durable until Control supplies a fresh epoch"
        );
    }

    #[test]
    fn two_endpoints_install_across_fresh_acceptance_without_rewriting_the_first() {
        let fixture = Fixture::new(2);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));

        assert_eq!(
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("install first Endpoint"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let cell = registry
            .get(&fixture.desired.cat_id)
            .expect("registered cell");
        let after_first = cell.snapshot();
        assert_eq!(after_first.endpoints().len(), 1);
        assert_eq!(after_first.endpoints()[0].gate, RouteGateState::Active);
        let first_route = after_first.endpoints()[0].clone();
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .expect("registry lookup")
            .expect("existing session");
        let staged_second = session
            .checkpoint_store()
            .load()
            .expect("load staged second gate")
            .expect("staged second gate exists");
        assert_eq!(staged_second.checkpoint().route_gates.len(), 2);
        assert_eq!(staged_second.checkpoint().route_gates[0], first_route);
        assert_eq!(
            staged_second.checkpoint().route_gates[1].gate,
            RouteGateState::Closed
        );
        assert!(matches!(
            &staged_second.checkpoint().step,
            ReconcileStep::InstallGate { endpoint_id, .. }
                if endpoint_id == &fixture.desired.endpoints[1].endpoint_id
        ));
        let first_guard = cell
            .acquire_verified_route(
                &claims(&first_route.binding),
                RouteGrantV2TimeVerdict::Valid,
            )
            .expect("acquire first Endpoint guard");
        assert_eq!(
            cell.active_guards(&first_route.binding.endpoint_id),
            Some(1)
        );

        assert_eq!(
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("install second Endpoint"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let stable_cell = cell.snapshot();
        assert_eq!(stable_cell.endpoints().len(), 2);
        assert_eq!(stable_cell.endpoints()[0], first_route);
        assert_eq!(
            cell.active_guards(&first_route.binding.endpoint_id),
            Some(1)
        );
        assert!(stable_cell
            .endpoints()
            .iter()
            .all(|route| route.gate == RouteGateState::Active));
        let stable = session
            .checkpoint_store()
            .load()
            .expect("load Stable Running checkpoint")
            .expect("Stable Running checkpoint exists");
        assert_eq!(stable.checkpoint().stable_state, Some(StableState::Running));
        assert_eq!(stable.checkpoint().route_gates, stable_cell.endpoints());

        assert_eq!(
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("Stable Running replay is inert"),
            Some(RuntimeDesiredEffectOutcome::Applied)
        );
        assert_eq!(cell.snapshot(), stable_cell);
        drop(first_guard);
        assert_eq!(
            cell.active_guards(&first_route.binding.endpoint_id),
            Some(0)
        );
    }

    #[test]
    fn stable_endpoint_checkpoint_stays_closed_after_restart_until_route_epochs_advance() {
        let fixture = Fixture::new(2);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        for _ in 0..2 {
            assert_eq!(
                effect
                    .try_apply(&fixture.context(&registry, true), &fixture.desired)
                    .expect("install the next Endpoint"),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
        }
        let checkpoint_path = runtime_checkpoint_path(
            &fixture.root.path().join(CHECKPOINTS),
            &fixture.desired.cat_id,
        );
        let stable_bytes = std::fs::read(&checkpoint_path).expect("Stable checkpoint bytes");
        drop(effect);
        drop(registry);

        let successor = fixture.registry();
        let successor_effect = RunningAdmissionEffect::new(Arc::clone(&successor));
        assert_eq!(
            successor_effect
                .try_apply(&fixture.context(&successor, true), &fixture.desired)
                .expect("old Endpoint epochs remain fail-closed after restart"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let closed = successor
            .get(&fixture.desired.cat_id)
            .expect("restart-closed AdmissionCell")
            .snapshot();
        assert_eq!(closed.lifecycle_admission(), LifecycleAdmission::Closed);
        assert_eq!(closed.endpoints().len(), 2);
        assert!(closed
            .endpoints()
            .iter()
            .all(|route| route.gate == RouteGateState::Closed));
        assert_eq!(
            std::fs::read(checkpoint_path).expect("checkpoint after local restore"),
            stable_bytes,
            "fail-closing the process-local cell must not rewrite durable authority"
        );
        assert_eq!(
            successor_effect
                .try_apply(&fixture.context(&successor, true), &fixture.desired)
                .expect("old Endpoint epoch replay stays closed"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let restart_scan = fixture.scan(&successor);
        let sealed = RunningTailScanAdmission::for_test_from_authorities(
            &restart_scan.observation,
            &restart_scan.stored,
            restart_scan.cell_presence,
            restart_scan.cell,
            restart_scan.routes,
        )
        .expect("sealed restart-closed scan");
        let mut projected = restart_scan.observation.runtimes[0].clone();
        sealed
            .project_runtime(&mut projected)
            .expect("project restart-closed Running tail");
        assert_eq!(projected.lifecycle_admission, LifecycleAdmission::Closed);
        assert!(!projected.conditions.iter().any(|condition| matches!(
            condition,
            cats_api::runtime_reconciliation::Condition::Ready { .. }
        )));

        let old_bindings = closed
            .endpoints()
            .iter()
            .map(|route| route.binding.clone())
            .collect::<Vec<_>>();
        let session = successor
            .existing_session(&fixture.desired.cat_id)
            .unwrap()
            .unwrap();
        let mut fresh = fixture.desired.clone();
        fresh.desired_revision = Revision::new(fresh.desired_revision.get() + 1).unwrap();
        for endpoint in &mut fresh.endpoints {
            endpoint.route_epoch = Epoch::new(endpoint.route_epoch.get() + 1).unwrap();
        }
        let mut new_first = fresh.endpoints[0].clone();
        new_first.endpoint_id = Id::new("ep_00").unwrap();
        new_first.hostname = Hostname::new("first.example.test").unwrap();
        new_first.target_port += 100;
        fresh.endpoints.insert(0, new_first);
        fresh.spec_digest = spec_digest(&fresh).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&successor))
            .reconcile(pre_scan_context(fresh.clone()))
            .expect("strict higher-epoch successor retains only the Closed restart source");

        for _ in 0..8 {
            let stored = session.checkpoint_store().load().unwrap().unwrap();
            if stored.checkpoint().desired_revision == fresh.desired_revision
                && stored.checkpoint().stable_state == Some(StableState::Running)
            {
                break;
            }
            let context = retirement_context(
                fixture.root.path(),
                &fresh,
                &fixture.desired,
                &session,
                RouteRetirementMode::EndpointOnly,
                true,
            );
            assert_eq!(
                successor_effect.try_retire(&context, &fresh).unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
        }
        let durable = session.checkpoint_store().load().unwrap().unwrap();
        assert_eq!(
            durable.checkpoint().desired_revision,
            fresh.desired_revision
        );
        assert_eq!(
            durable.checkpoint().stable_state,
            Some(StableState::Running)
        );
        let reopened = session.cell().snapshot();
        assert_eq!(reopened.lifecycle_admission(), LifecycleAdmission::Open);
        assert!(reopened
            .endpoints()
            .iter()
            .all(|route| route.gate == RouteGateState::Active));
        for old in old_bindings {
            assert!(session
                .cell()
                .acquire_verified_route(&claims(&old), RouteGrantV2TimeVerdict::Valid)
                .is_err());
        }
        for route in reopened.endpoints() {
            assert!(session
                .cell()
                .acquire_verified_route(&claims(&route.binding), RouteGrantV2TimeVerdict::Valid,)
                .is_ok());
        }
    }

    #[test]
    fn restart_closed_zero_endpoint_source_can_install_its_first_fresh_endpoint() {
        let fixture = Fixture::new(0);
        let first_registry = fixture.registry();
        RunningAdmissionEffect::new(Arc::clone(&first_registry))
            .try_apply(&fixture.context(&first_registry, true), &fixture.desired)
            .unwrap()
            .unwrap();
        drop(first_registry);

        let restarted = fixture.registry();
        let store = FileCheckpointStore::open(
            &fixture.root.path().join(CHECKPOINTS),
            &fixture.desired.cat_id,
        )
        .unwrap();
        let source = store.load().unwrap().unwrap();
        let source_closed = AdmissionSnapshot::from_checkpoint(source.checkpoint())
            .unwrap()
            .fail_closed();
        drop(store);
        let session = match restarted
            .ensure_closed(
                &fixture.desired.cat_id,
                source_closed,
                Some(fixture.desired.clone()),
            )
            .unwrap()
        {
            AdmissionCellSessionLookup::CreatedClosed(session) => session,
            AdmissionCellSessionLookup::Existing => panic!("restart session unexpectedly existed"),
        };
        let mut successor = fixture.desired.clone();
        successor.desired_revision = Revision::new(successor.desired_revision.get() + 1).unwrap();
        successor.endpoints = decode_desired_runtime_spec(DESIRED).unwrap().endpoints;
        successor.spec_digest = spec_digest(&successor).unwrap();
        RunningAdmissionPreScan::new(Arc::clone(&restarted))
            .reconcile(pre_scan_context(successor.clone()))
            .unwrap();

        let effect = RunningAdmissionEffect::new(Arc::clone(&restarted));
        let retirement = retirement_context(
            fixture.root.path(),
            &successor,
            &fixture.desired,
            &session,
            RouteRetirementMode::EndpointOnly,
            true,
        );
        assert_eq!(
            effect.try_retire(&retirement, &successor).unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let adopted = session.checkpoint_store().load().unwrap().unwrap();
        assert_eq!(
            adopted.checkpoint().desired_revision,
            successor.desired_revision
        );
        assert!(matches!(
            adopted.checkpoint().step,
            ReconcileStep::OpenAdmission { .. }
        ));
        assert_eq!(
            session.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );

        assert_eq!(
            effect
                .try_apply(
                    &ready_context(fixture.root.path(), &successor, &session),
                    &successor,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let stable = session.checkpoint_store().load().unwrap().unwrap();
        assert_eq!(stable.checkpoint().stable_state, Some(StableState::Running));
        let live = session.cell().snapshot();
        assert_eq!(live.lifecycle_admission(), LifecycleAdmission::Open);
        assert_eq!(live.endpoints().len(), 1);
        assert_eq!(live.endpoints()[0].gate, RouteGateState::Active);
    }

    #[test]
    fn second_gate_response_loss_replay_finalizes_without_reapplying_either_gate() {
        let fixture = Fixture::new(2);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .expect("install first Endpoint")
            .expect("first Endpoint consumes the scan");
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .expect("registry lookup")
            .expect("existing session");
        let cell = Arc::clone(session.cell());
        let staged_second = session
            .checkpoint_store()
            .load()
            .expect("load staged second gate")
            .expect("staged second gate exists");
        let before_second = cell.snapshot();
        let first_route = before_second.endpoints()[0].clone();
        let second_endpoint_id = fixture.desired.endpoints[1].endpoint_id.clone();
        let mut locally_applied = staged_second.checkpoint().clone();
        locally_applied
            .route_gates
            .iter_mut()
            .find(|route| route.binding.endpoint_id == second_endpoint_id)
            .expect("staged second route")
            .gate = RouteGateState::Active;
        locally_applied.lifecycle_admission = LifecycleAdmission::Open;
        let replacement = AdmissionSnapshot::from_checkpoint(&locally_applied)
            .expect("lost-response local replacement");
        cell.port()
            .install_gate(&before_second, &replacement, &second_endpoint_id)
            .expect("model local B effect followed by response loss");
        let after_unknown = cell.snapshot();
        assert_eq!(after_unknown.endpoints().len(), 2);
        assert_eq!(after_unknown.endpoints()[0], first_route);
        assert_eq!(
            session
                .checkpoint_store()
                .load()
                .expect("load still-staged checkpoint")
                .expect("still-staged checkpoint exists")
                .checkpoint()
                .route_gates[1]
                .gate,
            RouteGateState::Closed
        );

        assert_eq!(
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("resolve B response loss from exact postcondition"),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(cell.snapshot(), after_unknown);
        let stable = session
            .checkpoint_store()
            .load()
            .expect("load final checkpoint")
            .expect("final checkpoint exists");
        assert_eq!(stable.checkpoint().stable_state, Some(StableState::Running));
        assert!(stable
            .checkpoint()
            .route_gates
            .iter()
            .all(|route| route.gate == RouteGateState::Active));
        assert_eq!(
            effect
                .try_apply(&fixture.context(&registry, true), &fixture.desired)
                .expect("final exact replay is inert"),
            Some(RuntimeDesiredEffectOutcome::Applied)
        );
        assert_eq!(cell.snapshot(), after_unknown);
    }

    #[test]
    fn stale_revision_checkpoint_or_sidecar_has_zero_gate_effect() {
        let fixture = Fixture::new(2);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .expect("install first Endpoint")
            .expect("first Endpoint consumes the scan");
        let cell = registry
            .get(&fixture.desired.cat_id)
            .expect("registered cell");
        let stale = fixture.context(&registry, true);
        let before = cell.snapshot();
        let before_bytes = checkpoint_bytes(&fixture);

        let mut next_revision = fixture.desired.clone();
        next_revision.desired_revision = Revision::new(
            fixture
                .desired
                .desired_revision
                .get()
                .checked_add(1)
                .expect("next revision"),
        )
        .expect("next revision");
        next_revision.spec_digest = spec_digest(&next_revision).expect("next spec digest");
        assert!(effect.try_apply(&stale, &next_revision).is_err());
        assert_eq!(cell.snapshot(), before);
        assert_eq!(checkpoint_bytes(&fixture), before_bytes);

        effect
            .try_apply(&fixture.context(&registry, true), &fixture.desired)
            .expect("install second Endpoint")
            .expect("second Endpoint consumes the scan");
        let stable = cell.snapshot();
        let stable_bytes = checkpoint_bytes(&fixture);
        assert!(effect.try_apply(&stale, &fixture.desired).is_err());
        assert_eq!(cell.snapshot(), stable);
        assert_eq!(checkpoint_bytes(&fixture), stable_bytes);

        let checkpoint_fixture = Fixture::new(2);
        let checkpoint_registry = checkpoint_fixture.registry();
        let checkpoint_effect = RunningAdmissionEffect::new(Arc::clone(&checkpoint_registry));
        checkpoint_effect
            .try_apply(
                &checkpoint_fixture.context(&checkpoint_registry, true),
                &checkpoint_fixture.desired,
            )
            .expect("install checkpoint-fixture first Endpoint")
            .expect("first Endpoint consumes the scan");
        let checkpoint_sidecar = checkpoint_fixture.context(&checkpoint_registry, true);
        let checkpoint_session = checkpoint_registry
            .existing_session(&checkpoint_fixture.desired.cat_id)
            .expect("registry lookup")
            .expect("existing session");
        let checkpoint_cell = checkpoint_session.cell().snapshot();
        let current = checkpoint_session
            .checkpoint_store()
            .load()
            .expect("load current checkpoint")
            .expect("current checkpoint exists");
        let mut drifted = current.checkpoint().clone();
        drifted.updated_at_unix_ms = unix_ms(
            drifted
                .updated_at_unix_ms
                .get()
                .checked_add(1)
                .expect("next checkpoint timestamp"),
        );
        checkpoint_session
            .checkpoint_store()
            .replace(&current, &drifted)
            .expect("publish a different exact checkpoint");
        let drifted_bytes = checkpoint_bytes(&checkpoint_fixture);
        assert!(checkpoint_effect
            .try_apply(&checkpoint_sidecar, &checkpoint_fixture.desired)
            .is_err());
        assert_eq!(checkpoint_session.cell().snapshot(), checkpoint_cell);
        assert_eq!(checkpoint_bytes(&checkpoint_fixture), drifted_bytes);
    }

    #[test]
    fn cancellation_after_registry_creation_leaves_cell_and_checkpoint_closed() {
        let fixture = Fixture::new(0);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry))
            .with_after_registry(Arc::new(|context| context.cancel_for_test()));
        let context = fixture.context(&registry, true);
        let error = effect
            .try_apply(&context, &fixture.desired)
            .expect_err("cancellation must stop before checkpoint publication");
        assert!(error.to_string().contains("cancelled"));
        let cell = registry
            .get(&fixture.desired.cat_id)
            .expect("closed session remains registered");
        assert_eq!(
            cell.snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        let session = registry
            .existing_session(&fixture.desired.cat_id)
            .expect("registry lookup")
            .expect("existing session");
        let stored = session
            .checkpoint_store()
            .load()
            .expect("load source checkpoint")
            .expect("source checkpoint exists");
        assert_eq!(stored.content_digest(), &fixture.source_digest);
        assert_eq!(
            stored.checkpoint().lifecycle_admission,
            LifecycleAdmission::Closed
        );
        assert!(matches!(
            stored.checkpoint().step,
            ReconcileStep::StartRuntime { .. }
        ));
    }

    #[test]
    fn sealed_scan_binding_rejects_guest_or_checkpoint_projection_changes() {
        let fixture = Fixture::new(0);
        let registry = fixture.registry();
        let authority = fixture.scan(&registry);
        let scan = RunningTailScanAdmission::for_test_from_authorities(
            &authority.observation,
            &authority.stored,
            authority.cell_presence,
            authority.cell.clone(),
            authority.routes.clone(),
        )
        .expect("test live/Ready scan proof");
        let mut changed = authority.observation.clone();
        changed.runtimes[0].guest_transport = GuestTransportEvidence::Unavailable;
        assert!(scan.clone().bind(&changed).is_err());

        let mut changed = authority.observation.clone();
        let CheckpointEvidence::Valid { content_digest, .. } = &mut changed.runtimes[0].checkpoint
        else {
            panic!("fixture checkpoint must be valid")
        };
        *content_digest = Sha256Digest::from_bytes([4; 32]);
        assert!(scan.bind(&changed).is_err());

        let routed = Fixture::new(2);
        let routed_registry = routed.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&routed_registry));
        for _ in 0..2 {
            effect
                .try_apply(&routed.context(&routed_registry, true), &routed.desired)
                .expect("install exact Endpoint")
                .expect("each Endpoint consumes one fresh scan");
        }
        let authority = routed.scan(&routed_registry);
        let scan = RunningTailScanAdmission::for_test_from_authorities(
            &authority.observation,
            &authority.stored,
            authority.cell_presence,
            authority.cell.clone(),
            authority.routes.clone(),
        )
        .expect("sealed routed scan");
        let mut projected = authority.observation.runtimes[0].clone();
        scan.clone()
            .project_runtime(&mut projected)
            .expect("project exact Stable Running tail");
        assert!(matches!(
            projected.conditions.as_slice(),
            [cats_api::runtime_reconciliation::Condition::Ready {
                reason: ReadyReason::PostconditionSatisfied {
                    target: RuntimeTarget::Running
                }
            }]
        ));
        let mut pending_routes = authority.routes.clone();
        pending_routes[0].cancellation_pending = true;
        let mut pending_observation = authority.observation.clone();
        pending_observation.runtimes[0].routes[0].cancellation_pending = true;
        assert!(RunningTailScanAdmission::for_test_from_authorities(
            &pending_observation,
            &authority.stored,
            authority.cell_presence,
            authority.cell.clone(),
            pending_routes,
        )
        .expect("sealed pending-cancellation scan")
        .bind(&pending_observation)
        .is_ok());
        let reject = |observation: NodeObservation| {
            assert!(scan.clone().bind(&observation).is_err());
        };

        let mut changed = authority.observation.clone();
        changed.runtimes[0].routes.pop();
        reject(changed);

        let mut changed = authority.observation.clone();
        let duplicate = changed.runtimes[0].routes[0].clone();
        changed.runtimes[0].routes.push(duplicate);
        reject(changed);

        let mut changed = authority.observation.clone();
        changed.runtimes[0].routes.swap(0, 1);
        reject(changed);

        let mut changed = authority.observation.clone();
        changed.runtimes[0].routes[0].binding.endpoint_id =
            Id::new("ep_wrong").expect("wrong Endpoint ID");
        reject(changed);

        let mut changed = authority.observation.clone();
        changed.runtimes[0].routes[0].gate = RouteGateState::Closed;
        reject(changed);

        let mut changed = authority.observation.clone();
        changed.runtimes[0].routes[0].active_guards = 1;
        reject(changed);

        let mut changed = authority.observation.clone();
        changed.runtimes[0].routes[0].cancellation_pending = true;
        reject(changed);

        let mut changed = authority.observation.clone();
        changed.runtimes[0].routes[0].instance_count = 2;
        reject(changed);

        let mut changed = authority.observation.clone();
        changed.runtimes[0].lifecycle_admission = LifecycleAdmission::Closed;
        reject(changed);

        let mut changed = authority.observation.clone();
        let CheckpointEvidence::Valid { step, .. } = &mut changed.runtimes[0].checkpoint else {
            panic!("fixture checkpoint must be valid")
        };
        **step = ReconcileStep::InspectInventory {
            inventory_epoch: epoch(99),
        };
        reject(changed);
    }

    fn projected_routes(cell: &AdmissionCellObservation) -> Vec<ObservedRouteGate> {
        cell.snapshot()
            .endpoints()
            .iter()
            .map(|route| {
                let active_guards = cell
                    .guards()
                    .endpoint_guards
                    .iter()
                    .find(|count| count.endpoint_id == route.binding.endpoint_id)
                    .map_or(0, |count| count.active_guards);
                ObservedRouteGate {
                    binding: route.binding.clone(),
                    gate: route.gate,
                    active_guards,
                    cancellation_pending: cell.endpoint_is_revoked(&route.binding.endpoint_id)
                        || (route.gate == RouteGateState::Closed && active_guards != 0),
                    instance_count: 1,
                }
            })
            .collect()
    }

    fn checkpoint_bytes(fixture: &Fixture) -> Vec<u8> {
        std::fs::read(runtime_checkpoint_path(
            &fixture.root.path().join(CHECKPOINTS),
            &fixture.desired.cat_id,
        ))
        .expect("checkpoint bytes")
    }

    fn observation(
        desired: &DesiredRuntimeSpec,
        stored: &StoredCheckpoint,
        cell: &AdmissionCellObservation,
        routes: Vec<ObservedRouteGate>,
    ) -> NodeObservation {
        let checkpoint = stored.checkpoint();
        let node_boot_id =
            NodeBootId::new("33333333333333333333333333333333").expect("Node boot ID");
        let agent_instance_id =
            RandomId128::new("44444444444444444444444444444444").expect("Agent instance ID");
        let inventory_digest = Sha256Digest::from_bytes([9; 32]);
        NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .expect("observation ID"),
            node_id: desired.placement.node_id.clone(),
            node_boot_id,
            agent_instance_id,
            agent_session_epoch: epoch(2),
            heartbeat_sequence: sequence(5),
            observed_at_unix_ms: unix_ms(1_900_000_000_000),
            complete_inventory: true,
            inventory_epoch: epoch(3),
            inventory_digest: Some(inventory_digest),
            inventory_read_position: Some(sequence(6)),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: vec![ObservedRuntimeStatus {
                cat_id: desired.cat_id.clone(),
                applied_desired: Some(AppliedDesiredEvidence {
                    desired_revision: desired.desired_revision,
                    spec_digest: desired.spec_digest.clone(),
                    placement: desired.placement.clone(),
                    target: desired.target,
                }),
                runtime_incarnation: checkpoint.runtime_incarnation.clone(),
                stable_state: checkpoint.stable_state,
                step: checkpoint.step.clone(),
                checkpoint: CheckpointEvidence::Valid {
                    checkpoint_path: HostPath::new(
                        runtime_checkpoint_path(&std::env::temp_dir(), &desired.cat_id)
                            .to_string_lossy()
                            .into_owned(),
                    )
                    .expect("checkpoint HostPath"),
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
                },
                processes: Vec::new(),
                volumes: Vec::new(),
                mounts: Vec::new(),
                networks: Vec::new(),
                guest_transport: GuestTransportEvidence::VsockReady {
                    runtime_incarnation: checkpoint
                        .runtime_incarnation
                        .clone()
                        .expect("runtime incarnation"),
                    guest_cid: 3,
                    guest_port: 1070,
                    guest_agent_protocol_version: ContractVersion::V1,
                    guest_boot_id: GuestBootId::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                        .expect("Guest boot ID"),
                },
                warm_snapshot: WarmSnapshotEvidence::Absent,
                lifecycle_admission: cell.snapshot().lifecycle_admission(),
                routes,
                platform_guards: cell.guards().platform_guards,
                conditions: Vec::new(),
            }],
            residue: Vec::new(),
        }
    }

    fn context(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        scan: TestScan,
        with_running_tail: bool,
    ) -> RuntimeDesiredEffectContext {
        let observation = scan.observation;
        let tail = with_running_tail.then(|| {
            RunningTailScanAdmission::for_test_from_authorities(
                &observation,
                &scan.stored,
                scan.cell_presence,
                scan.cell,
                scan.routes,
            )
            .expect("test live/Ready scan proof")
            .bind(&observation)
            .expect("bind exact full observation")
        });
        context_from_tail(root, desired, observation, tail)
    }

    fn context_from_tail(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        observation: NodeObservation,
        tail: Option<RunningTailAdmission>,
    ) -> RuntimeDesiredEffectContext {
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: observation.node_id.clone(),
            immutable_host_id: Id::new("host_a").expect("Host ID"),
            node_boot_id: observation.node_boot_id.clone(),
            agent_instance_id: observation.agent_instance_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            registration_attempt_id: RandomId128::new("cccccccccccccccccccccccccccccccc")
                .expect("registration attempt ID"),
            guest_config_digest: desired.runtime.guest_config_digest.clone(),
            lease_deadline_unix_ms: unix_ms(1_900_000_120_000),
        };
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: observation.node_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest: observation
                .inventory_digest
                .clone()
                .expect("inventory digest"),
            inventory_read_position: observation
                .inventory_read_position
                .expect("inventory read position"),
            accepted_at_unix_ms: unix_ms(1_900_000_001_000),
        };
        let mut admission =
            RuntimeDesiredEffectAdmission::for_test(session, observation, attestation);
        if let Some(tail) = tail {
            admission = admission.with_running_tail_for_test(tail);
        }
        RuntimeDesiredEffectContext::for_test_with_admission(
            StateDirectory::unanchored(root.to_path_buf()),
            Instant::now() + Duration::from_secs(30),
            admission,
        )
    }

    fn retirement_context(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        launch_predecessor: &DesiredRuntimeSpec,
        session: &Arc<AdmissionCellSession>,
        mode: RouteRetirementMode,
        physical: bool,
    ) -> RuntimeDesiredEffectContext {
        let stored = session
            .checkpoint_store()
            .load()
            .unwrap()
            .expect("retirement checkpoint");
        let cell = session.cell().observe();
        let routes = projected_routes(&cell);
        let observation = observation(desired, &stored, &cell, routes);
        let binding = if stored.checkpoint().desired_revision == desired.desired_revision
            && stored.checkpoint().spec_digest == desired.spec_digest
        {
            DesiredCheckpointBinding::Current
        } else {
            DesiredCheckpointBinding::Superseded
        };
        let gate_predecessor = session.sealed_running_desired();
        let mut scan = RunningTailScanAdmission::empty();
        scan.insert_route_retirement(
            desired,
            stored.checkpoint(),
            binding,
            stored.content_digest().clone(),
            gate_predecessor,
            Some(launch_predecessor.clone()),
            session.generation(),
            cell,
            mode,
            None,
        )
        .unwrap();
        if physical {
            scan.retiring.get_mut(&desired.cat_id).unwrap().physical =
                Some(RunningTailPhysicalAuthority::Test);
        }
        let tail = scan.bind(&observation).unwrap();
        context_from_tail(root, desired, observation, Some(tail))
    }

    fn ready_context(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        session: &Arc<AdmissionCellSession>,
    ) -> RuntimeDesiredEffectContext {
        let stored = session
            .checkpoint_store()
            .load()
            .unwrap()
            .expect("ready checkpoint");
        let cell = session.cell().observe();
        let routes = projected_routes(&cell);
        let observation = observation(desired, &stored, &cell, routes.clone());
        let tail = RunningTailScanAdmission::for_test_from_authorities(
            &observation,
            &stored,
            RunningTailCellPresence::Present,
            cell,
            routes,
        )
        .unwrap()
        .bind(&observation)
        .unwrap();
        context_from_tail(root, desired, observation, Some(tail))
    }

    fn fixture_runtime_launch() -> RuntimeLaunch {
        decode_runtime_checkpoint(START_RUNTIME)
            .expect("StartRuntime checkpoint")
            .runtime_launch
    }

    fn claims(binding: &cats_api::runtime_reconciliation::RouteGateBinding) -> RouteGrantV2Claims {
        RouteGrantV2Claims {
            version: ROUTE_GRANT_V2_VERSION,
            iss: ROUTE_GRANT_V2_ISSUER.to_owned(),
            aud: ROUTE_GRANT_V2_AUDIENCE.to_owned(),
            workspace_id: binding.workspace_id.clone(),
            endpoint_id: binding.endpoint_id.clone(),
            hostname: binding.hostname.clone(),
            cat_id: binding.cat_id.clone(),
            node_id: binding.node_id.clone(),
            runtime_incarnation: binding.runtime_incarnation.clone(),
            route_epoch: binding.route_epoch,
            protocol: binding.protocol,
            target_port: binding.target_port,
            gateway_public_key_spki_sha256:
                cats_api::runtime_reconciliation::Sha256Digest::from_bytes([0_u8; 32]),
            iat: 10,
            nbf: 10,
            exp: 20,
        }
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).expect("nonzero epoch")
    }

    fn sequence(value: u64) -> Sequence {
        Sequence::new(value).expect("nonzero sequence")
    }

    fn unix_ms(value: u64) -> UnixMillis {
        UnixMillis::new(value).expect("Unix millis")
    }
}
