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
    NodeBootId, NodeObservation, RandomId128, Revision, RuntimeLaunch, RuntimeLaunchIdentity,
    RuntimeTarget, Sequence, Sha256Digest, UnixMillis,
};

use crate::runtime_spine::{RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome};

use super::{
    AdmissionCellRegistry, AdmissionCellSession, AdmissionSnapshot, GateSequencer, PersistTimes,
    StoredCheckpoint,
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
    runtime_launch: RuntimeLaunchIdentity,
    checkpoint_content_digest: Sha256Digest,
    guest_transport: GuestTransportEvidence,
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
    closed_cell_snapshot: AdmissionSnapshot,
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
                node_id,
                placement_epoch,
                desired_revision,
                spec_digest,
                runtime_incarnation,
                runtime_launch,
                ..
            } = &runtime.checkpoint
            else {
                anyhow::bail!("Running-tail runtime lacks an exact valid checkpoint")
            };
            anyhow::ensure!(
                expectation.cat_id == cat_id
                    && expectation.desired_revision == *desired_revision
                    && expectation.desired_revision == applied.desired_revision
                    && expectation.spec_digest == *spec_digest
                    && expectation.spec_digest == applied.spec_digest
                    && expectation.placement == applied.placement
                    && expectation.placement.node_id == *node_id
                    && expectation.placement.placement_epoch == *placement_epoch
                    && applied.target == RuntimeTarget::Running
                    && runtime.runtime_incarnation.as_ref()
                        == Some(&expectation.runtime_incarnation)
                    && runtime_incarnation.as_ref() == Some(&expectation.runtime_incarnation)
                    && runtime_launch.as_ref()
                        == &RuntimeLaunch::Present(Box::new(expectation.runtime_launch.clone()))
                    && expectation.runtime_launch.runtime_incarnation
                        == expectation.runtime_incarnation
                    && expectation.checkpoint_content_digest == *content_digest
                    && runtime.guest_transport == expectation.guest_transport
                    && matches!(
                        &runtime.guest_transport,
                        GuestTransportEvidence::VsockReady {
                            runtime_incarnation,
                            ..
                        } if runtime_incarnation == &expectation.runtime_incarnation
                    )
                    && runtime.lifecycle_admission == LifecycleAdmission::Closed
                    && runtime.routes.is_empty(),
                "Running-tail private proof conflicts with its public projection"
            );
            let closed_cell_snapshot = AdmissionSnapshot::new(
                applied.desired_revision,
                applied.spec_digest.clone(),
                applied.placement.clone(),
                Some(expectation.runtime_incarnation.clone()),
                LifecycleAdmission::Closed,
                Vec::new(),
            );
            ready.insert(
                cat_id,
                RunningTailReadyAdmission {
                    expectation,
                    closed_cell_snapshot,
                },
            );
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
    pub(crate) fn for_test_from_observation(observation: &NodeObservation) -> anyhow::Result<Self> {
        let mut ready = BTreeMap::new();
        for runtime in &observation.runtimes {
            let Some(applied) = &runtime.applied_desired else {
                continue;
            };
            let CheckpointEvidence::Valid {
                content_digest,
                desired_revision,
                spec_digest,
                runtime_incarnation: Some(runtime_incarnation),
                runtime_launch,
                ..
            } = &runtime.checkpoint
            else {
                continue;
            };
            let RuntimeLaunch::Present(runtime_launch) = runtime_launch.as_ref() else {
                continue;
            };
            if !matches!(
                runtime.guest_transport,
                GuestTransportEvidence::VsockReady { .. }
            ) {
                continue;
            }
            ready.insert(
                runtime.cat_id.clone(),
                RunningTailReadyExpectation {
                    cat_id: runtime.cat_id.clone(),
                    desired_revision: *desired_revision,
                    spec_digest: spec_digest.clone(),
                    placement: applied.placement.clone(),
                    runtime_incarnation: runtime_incarnation.clone(),
                    runtime_launch: (**runtime_launch).clone(),
                    checkpoint_content_digest: content_digest.clone(),
                    guest_transport: runtime.guest_transport.clone(),
                },
            );
        }
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
                && checkpoint.runtime_launch
                    == RuntimeLaunch::Present(Box::new(self.expectation.runtime_launch.clone())),
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
        let session = self
            .registry
            .ensure_closed(&desired.cat_id, ready.closed_cell_snapshot.clone())?;
        #[cfg(test)]
        if let Some(hook) = &self.after_registry {
            hook(context);
        }
        context.check_active()?;
        let session = ensure_session_identity(&self.registry, &desired.cat_id, session, ready)?;
        let stored = session
            .checkpoint_store()
            .load()
            .context("load Running-tail checkpoint")?
            .context("Running-tail authority names a missing checkpoint")?;
        ready.authorize(desired, &stored)?;
        context.check_active()?;
        let times = next_persist_times(&stored)?;
        let mut port = session.cell().port();
        let result = if desired.endpoints.is_empty() {
            GateSequencer::new(session.checkpoint_store(), &mut port)
                .open_admission(&stored, desired, times)?
        } else {
            anyhow::ensure!(
                stored.checkpoint().route_gates.is_empty()
                    && stored.checkpoint().lifecycle_admission == LifecycleAdmission::Closed,
                "the first InstallGate requires the exact Closed empty-gate predecessor"
            );
            let endpoint_id = desired
                .endpoints
                .first()
                .context("Endpoint-bearing Desired lost its first Endpoint")?
                .endpoint_id
                .clone();
            GateSequencer::new(session.checkpoint_store(), &mut port).install_gate(
                &stored,
                desired,
                &endpoint_id,
                times,
            )?
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

fn ensure_session_identity(
    registry: &AdmissionCellRegistry,
    cat_id: &Id,
    session: Arc<AdmissionCellSession>,
    ready: &RunningTailReadyAdmission,
) -> anyhow::Result<Arc<AdmissionCellSession>> {
    let snapshot = session.cell().snapshot();
    if snapshot.placement() == ready.closed_cell_snapshot.placement()
        && snapshot.runtime_incarnation() == ready.closed_cell_snapshot.runtime_incarnation()
    {
        return Ok(session);
    }
    registry
        .replace_closed(cat_id, &session, ready.closed_cell_snapshot.clone())
        .map_err(Into::into)
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

    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, spec_digest,
        AdmissionInventoryAttestation, AgentSession, AppliedDesiredEvidence, CheckpointEvidence,
        ContractVersion, DesiredRuntimeSpec, Epoch, GuestBootId, HostPath, NodeBootId,
        ObservedRuntimeStatus, ReconcileStep, RouteGateState, Sequence, StableState,
        WarmSnapshotEvidence,
    };
    use tempfile::TempDir;

    use super::super::{runtime_checkpoint_path, FileCheckpointStore};
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
        observation: NodeObservation,
        source_digest: Sha256Digest,
    }

    impl Fixture {
        fn new(with_endpoint: bool) -> Self {
            let root = TempDir::new().expect("tempdir");
            let mut desired = decode_desired_runtime_spec(DESIRED).expect("Desired vector");
            if !with_endpoint {
                desired.endpoints.clear();
                desired.spec_digest = spec_digest(&desired).expect("zero-Endpoint spec digest");
            }
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
            let observation = observation(&desired, &stored, LifecycleAdmission::Closed);
            drop(store);
            Self {
                root,
                desired,
                observation,
                source_digest,
            }
        }

        fn registry(&self) -> Arc<AdmissionCellRegistry> {
            AdmissionCellRegistry::new(self.root.path().join(CHECKPOINTS))
        }

        fn context(&self, with_running_tail: bool) -> RuntimeDesiredEffectContext {
            context(
                self.root.path(),
                &self.desired,
                self.observation.clone(),
                with_running_tail,
            )
        }
    }

    #[test]
    fn production_effect_without_scanner_sealed_authority_is_inert() {
        let fixture = Fixture::new(false);
        let before = std::fs::read(runtime_checkpoint_path(
            &fixture.root.path().join(CHECKPOINTS),
            &fixture.desired.cat_id,
        ))
        .expect("source bytes");
        let registry = fixture.registry();
        let outcome = RunningAdmissionEffect::new(Arc::clone(&registry))
            .try_apply(&fixture.context(false), &fixture.desired)
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
        let fixture = Fixture::new(false);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        assert_eq!(
            effect
                .try_apply(&fixture.context(true), &fixture.desired)
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
        let restarted_observation =
            observation(&fixture.desired, &stable, LifecycleAdmission::Closed);
        drop(store);

        let successor = fixture.registry();
        let successor_effect = RunningAdmissionEffect::new(Arc::clone(&successor));
        assert_eq!(
            successor_effect
                .try_apply(
                    &context(
                        fixture.root.path(),
                        &fixture.desired,
                        restarted_observation,
                        true,
                    ),
                    &fixture.desired,
                )
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
        let fixture = Fixture::new(true);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry));
        assert_eq!(
            effect
                .try_apply(&fixture.context(true), &fixture.desired)
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
            .ensure_closed(&fixture.desired.cat_id, snapshot)
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
    fn cancellation_after_registry_creation_leaves_cell_and_checkpoint_closed() {
        let fixture = Fixture::new(false);
        let registry = fixture.registry();
        let effect = RunningAdmissionEffect::new(Arc::clone(&registry))
            .with_after_registry(Arc::new(|context| context.cancel_for_test()));
        let context = fixture.context(true);
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
            .ensure_closed(&fixture.desired.cat_id, cell.snapshot())
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
        let fixture = Fixture::new(false);
        let scan = RunningTailScanAdmission::for_test_from_observation(&fixture.observation)
            .expect("test live/Ready scan proof");
        let mut changed = fixture.observation.clone();
        changed.runtimes[0].guest_transport = GuestTransportEvidence::Unavailable;
        assert!(scan.clone().bind(&changed).is_err());

        let mut changed = fixture.observation.clone();
        let CheckpointEvidence::Valid { content_digest, .. } = &mut changed.runtimes[0].checkpoint
        else {
            panic!("fixture checkpoint must be valid")
        };
        *content_digest = Sha256Digest::from_bytes([4; 32]);
        assert!(scan.bind(&changed).is_err());
    }

    fn observation(
        desired: &DesiredRuntimeSpec,
        stored: &StoredCheckpoint,
        live_admission: LifecycleAdmission,
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
                lifecycle_admission: live_admission,
                routes: Vec::new(),
                platform_guards: 0,
                conditions: Vec::new(),
            }],
            residue: Vec::new(),
        }
    }

    fn context(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        observation: NodeObservation,
        with_running_tail: bool,
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
        let tail = with_running_tail.then(|| {
            RunningTailScanAdmission::for_test_from_observation(&observation)
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
