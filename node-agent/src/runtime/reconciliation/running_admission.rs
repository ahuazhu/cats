//! Sealed Ready-to-admission handoff for the Running tail.
//!
//! Public `ObservedRuntimeStatus` fields are consistency projections, never
//! authority to open a cell. One complete scanner pass may attach the opaque
//! scan admission below only after provider-private live-VMM and Guest Ready
//! proofs agree. The current production scanner has no constructor for that
//! token, so this effect is composed but unreachable until that exact scanner
//! seam lands.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    CheckpointEvidence, DesiredRuntimeSpec, Epoch, GuestTransportEvidence, Id, LifecycleAdmission,
    NodeBootId, NodeObservation, ObservedRouteGate, ObservedRuntimeStatus, RandomId128,
    ReconcileStep, Revision, RuntimeCheckpoint, RuntimeTarget, Sequence, Sha256Digest, StableState,
    UnixMillis,
};

use crate::runtime_spine::{RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome};

use super::gate_planner::next_install_gate;
use super::{
    AdmissionCellObservation, AdmissionCellRegistry, AdmissionCellSession,
    AdmissionCellSessionLookup, AdmissionSnapshot, GateSequencer, PersistTimes, StoredCheckpoint,
};

#[cfg(test)]
type AfterRegistryHook = Arc<dyn Fn(&RuntimeDesiredEffectContext) + Send + Sync>;

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
    // These fields come from the private AdmissionCell/Route machine scan.
    // `bind` only checks their public projection; public routes can never
    // construct this expectation.
    cell_presence: RunningTailCellPresence,
    cell: AdmissionCellObservation,
    routes: Vec<ObservedRouteGate>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the live-VMM plus Guest Ready scanner constructs cell-presence proof in the next composition slice"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunningTailCellPresence {
    Absent,
    Present,
}

/// Provider-private result of one complete scan, before it is bound to the
/// exact public observation. There is deliberately no production constructor
/// until the live-VMM plus Guest Ready scanner owns both exact proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunningTailScanAdmission {
    ready: BTreeMap<Id, RunningTailReadyExpectation>,
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
}

impl RunningTailScanAdmission {
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
                cell_presence,
                cell,
                routes,
            },
        )]);
        Ok(Self { ready })
    }
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
}

fn exact_cell_projection(
    expectation: &RunningTailReadyExpectation,
    runtime: &ObservedRuntimeStatus,
) -> bool {
    let snapshot = expectation.cell.snapshot();
    let guards = expectation.cell.guards();
    if snapshot.applied_desired_revision() != expectation.desired_revision
        || snapshot.spec_digest() != &expectation.spec_digest
        || snapshot.placement() != &expectation.placement
        || snapshot.runtime_incarnation() != Some(&expectation.runtime_incarnation)
        || runtime.lifecycle_admission != snapshot.lifecycle_admission()
        || runtime.platform_guards != guards.platform_guards
        || runtime.routes != expectation.routes
        || snapshot.endpoints().len() != expectation.routes.len()
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
        .zip(&expectation.routes)
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
    #[cfg(test)]
    after_registry: Option<AfterRegistryHook>,
}

impl RunningAdmissionEffect {
    pub(crate) fn new(registry: Arc<AdmissionCellRegistry>) -> Self {
        Self {
            registry,
            #[cfg(test)]
            after_registry: None,
        }
    }

    #[cfg(test)]
    fn with_after_registry(mut self, hook: AfterRegistryHook) -> Self {
        self.after_registry = Some(hook);
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
        let session = ready.session(&self.registry, &desired.cat_id)?;
        #[cfg(test)]
        if let Some(hook) = &self.after_registry {
            hook(context);
        }
        context.check_active()?;
        anyhow::ensure!(
            session.cell().observe() == ready.expectation.cell,
            "Running-tail sidecar is stale for the current AdmissionCell"
        );
        let stored = session
            .checkpoint_store()
            .load()
            .context("load Running-tail checkpoint")?
            .context("Running-tail authority names a missing checkpoint")?;
        ready.authorize(desired, &stored)?;
        context.check_active()?;
        let Some(action) = plan_running_tail_action(ready, desired, &stored)? else {
            return Ok(None);
        };
        let times = next_persist_times(&stored)?;
        let mut port = session.cell().port();
        let result = match action {
            RunningTailAction::OpenLifecycle => {
                GateSequencer::new(session.checkpoint_store(), &mut port)
                    .open_admission(&stored, desired, times)?
            }
            RunningTailAction::InstallGate(endpoint_id) => GateSequencer::new(
                session.checkpoint_store(),
                &mut port,
            )
            .install_gate(&stored, desired, &endpoint_id, times)?,
        };
        debug_assert_eq!(
            result.checkpoint().checkpoint().runtime_launch,
            stored.checkpoint().runtime_launch
        );
        // Do not re-check cancellation after the local linearization point:
        // the bounded sequencer has already resolved the exact postcondition
        // and finalized its checkpoint. The runner still discards the stale
        // accepted batch and obtains a new full inventory.
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }
}

impl RunningTailReadyAdmission {
    fn session(
        &self,
        registry: &AdmissionCellRegistry,
        cat_id: &Id,
    ) -> anyhow::Result<Arc<AdmissionCellSession>> {
        match self.expectation.cell_presence {
            RunningTailCellPresence::Absent => {
                match registry.ensure_closed(cat_id, self.expectation.cell.snapshot().clone())? {
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
    InstallGate(Id),
}

fn plan_running_tail_action(
    ready: &RunningTailReadyAdmission,
    desired: &DesiredRuntimeSpec,
    stored: &StoredCheckpoint,
) -> anyhow::Result<Option<RunningTailAction>> {
    let checkpoint = stored.checkpoint();
    let cell = ready.expectation.cell.snapshot();
    let guards = ready.expectation.cell.guards();
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

    let Some(endpoint_id) = next_install_gate(checkpoint, desired)? else {
        let checkpoint_cell = AdmissionSnapshot::from_checkpoint(checkpoint)?;
        anyhow::ensure!(
            checkpoint.stable_state == Some(StableState::Running)
                && matches!(
                    checkpoint.step,
                    ReconcileStep::Stable {
                        state: StableState::Running
                    }
                )
                && cell == &checkpoint_cell,
            "Endpoint admission has no deterministic InstallGate successor"
        );
        return Ok(None);
    };

    match cell.lifecycle_admission() {
        LifecycleAdmission::Closed => {
            anyhow::ensure!(
                checkpoint.lifecycle_admission == LifecycleAdmission::Closed
                    && checkpoint.route_gates.is_empty()
                    && cell.endpoints().is_empty()
                    && guards.platform_guards == 0
                    && guards.endpoint_guards.is_empty(),
                "only the first empty-gate InstallGate may open lifecycle admission"
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
        RouteGrantV2Claims, RouteGrantV2TimeVerdict, ROUTE_GRANT_V2_AUDIENCE,
        ROUTE_GRANT_V2_ISSUER, ROUTE_GRANT_V2_VERSION,
    };
    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, spec_digest,
        AdmissionInventoryAttestation, AgentSession, AppliedDesiredEvidence, CheckpointEvidence,
        ContractVersion, DesiredRuntimeSpec, Epoch, GuestBootId, HostPath, Hostname, NodeBootId,
        ObservedRuntimeStatus, ReconcileStep, RouteGateState, RuntimeLaunch, Sequence, StableState,
        WarmSnapshotEvidence,
    };
    use tempfile::TempDir;

    use super::super::{
        runtime_checkpoint_path, AdmissionCell, AdmissionGatePort, FileCheckpointStore,
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
                _ => panic!("fixture supports at most two Endpoints"),
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
            None
        );
        assert_eq!(cell.snapshot(), stable_cell);
        drop(first_guard);
        assert_eq!(
            cell.active_guards(&first_route.binding.endpoint_id),
            Some(0)
        );
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
            None
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
            .map(|route| ObservedRouteGate {
                binding: route.binding.clone(),
                gate: route.gate,
                active_guards: cell
                    .guards()
                    .endpoint_guards
                    .iter()
                    .find(|count| count.endpoint_id == route.binding.endpoint_id)
                    .map_or(0, |count| count.active_guards),
                cancellation_pending: false,
                instance_count: 1,
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
