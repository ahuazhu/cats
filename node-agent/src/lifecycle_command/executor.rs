//! Checkpoint-first executor for the six atomic lifecycle commands.
//!
//! The provider-facing machine is deliberately step based. `plan_initial` is
//! pure; the executor fsyncs its returned effect token before calling
//! `apply`. After an ambiguous response or Agent crash, `apply` receives the
//! same durable step and must discover its exact postcondition before it may
//! advance. A command that installs or inherits a Stop fence receives an
//! unforgeable retained journal guard for every physical effect.

use std::sync::Arc;

use anyhow::anyhow;
use cats_api::runtime_lifecycle::{LifecycleCommandEnvelope, LifecycleCommandResponse, NodeResult};
use cats_api::runtime_reconciliation::SessionBinding;

use super::journal::{
    CommandJournalState, CurrentStopFenceGuard, DurableStopFence, EmbeddedStopFence, ExactBytes,
    ExactCommandResult, ExecutionStep, FileLifecycleCommandJournal, LifecycleJournalRecord,
    LifecycleJournalStartupInventory, StartupPhysicalInventory, StoredLifecycleJournal,
};
use super::runner::{
    LifecycleCommandExecutor, LifecycleExecutionError, LifecycleExecutionFuture,
    LifecycleInventoryFuture, LifecyclePhysicalInventorySnapshot, LifecycleStartupBindingFuture,
    LifecycleTerminalAdmissionRecoveryFuture,
};

const MAX_EFFECT_TRANSITIONS_PER_CALL: usize = 1_024;

/// Complete Host inventory used by startup admission and Genesis checks.
///
/// Implementations must scan the union of the journal namespace, dedicated
/// Cat scopes, VMM/blockd/helper processes, Guest-facing frontends, sockets,
/// devices, networks, snapshots and local volume lineages. An interrupted or
/// partial scan returns `StartupPhysicalInventory::Incomplete`, never an empty
/// complete set.
pub trait LifecyclePhysicalInventoryPort: Send + Sync + 'static {
    fn scan_complete(&self) -> anyhow::Result<LifecyclePhysicalInventorySnapshot>;
}

/// Whether the next durable effect installs, preserves, or does not use the
/// command's embedded Stop fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopFenceDirective {
    None,
    Install { fence_payload: ExactBytes },
    Inherit,
}

/// One physical effect which must become durable before `apply` is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedLifecycleEffect {
    pub step: ExecutionStep,
    pub stop_fence: StopFenceDirective,
}

impl PlannedLifecycleEffect {
    pub fn unfenced(step: ExecutionStep) -> Self {
        Self {
            step,
            stop_fence: StopFenceDirective::None,
        }
    }

    pub fn install_stop_fence(step: ExecutionStep, fence_payload: ExactBytes) -> Self {
        Self {
            step,
            stop_fence: StopFenceDirective::Install { fence_payload },
        }
    }

    pub fn inherit_stop_fence(step: ExecutionStep) -> Self {
        Self {
            step,
            stop_fence: StopFenceDirective::Inherit,
        }
    }
}

/// Authority presented to one already-journaled physical effect.
pub enum LifecycleEffectAuthority<'a> {
    Unfenced,
    StopFenced(&'a CurrentStopFenceGuard<'a>),
}

impl LifecycleEffectAuthority<'_> {
    pub fn stop_fence(&self) -> Option<&CurrentStopFenceGuard<'_>> {
        match self {
            Self::Unfenced => None,
            Self::StopFenced(fence) => Some(fence),
        }
    }
}

/// Result of executing exactly the effect named by the current durable step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEffectProgress {
    Next(PlannedLifecycleEffect),
    Terminal(NodeResult),
}

/// Provider-neutral six-command physical machine.
///
/// `plan_initial` must not perform physical I/O. `apply` is synchronous and
/// bounded by deadlines frozen in the command. This lets the executor run the
/// whole call on an owned blocking worker and ensures a retained Stop-fence
/// mutex is never held across `.await`.
pub trait AtomicLifecycleEffectPort: Send + Sync + 'static {
    /// Bind provider-private evidence retained by the sole complete scan to
    /// the sole descriptor-safe journal enumeration. Implementations move a
    /// conflicting non-terminal Cat out of effect recovery while keeping
    /// healthy siblings. A conflicting already-terminal Cat stays
    /// recoverable only for exact result settlement and must be marked so the
    /// runner skips admission recovery. Returned recoverable Executing entries
    /// are replayed through `apply`, which performs exact ambiguity discovery
    /// from their already-durable step.
    fn bind_startup_inventory(
        &self,
        startup: LifecycleJournalStartupInventory,
        snapshot: &LifecyclePhysicalInventorySnapshot,
    ) -> anyhow::Result<LifecycleJournalStartupInventory>;

    /// Observation-only startup recovery for an exact durable Running
    /// terminal. Implementations must prove the response against the same
    /// complete physical snapshot before reopening local admission. This
    /// method must not execute a lifecycle effect or mutate the journal.
    fn recover_terminal_admission(
        &self,
        session: &SessionBinding,
        current: &StoredLifecycleJournal,
        startup_inventory: &StartupPhysicalInventory,
    ) -> anyhow::Result<()>;

    fn plan_initial(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor_command: Option<&LifecycleCommandEnvelope>,
        predecessor: Option<&LifecycleCommandResponse>,
        inherited_stop_fence: bool,
    ) -> anyhow::Result<PlannedLifecycleEffect>;

    fn apply(
        &self,
        command: &LifecycleCommandEnvelope,
        predecessor_command: Option<&LifecycleCommandEnvelope>,
        predecessor: Option<&LifecycleCommandResponse>,
        step: &ExecutionStep,
        authority: LifecycleEffectAuthority<'_>,
    ) -> anyhow::Result<LifecycleEffectProgress>;
}

/// Concrete executor shared by the production runner and crash tests.
pub struct AtomicLifecycleExecutor {
    inventory: Arc<dyn LifecyclePhysicalInventoryPort>,
    effects: Arc<dyn AtomicLifecycleEffectPort>,
}

impl AtomicLifecycleExecutor {
    pub fn new(
        inventory: Arc<dyn LifecyclePhysicalInventoryPort>,
        effects: Arc<dyn AtomicLifecycleEffectPort>,
    ) -> Arc<Self> {
        Arc::new(Self { inventory, effects })
    }
}

impl LifecycleCommandExecutor for AtomicLifecycleExecutor {
    fn physical_inventory(&self) -> LifecycleInventoryFuture {
        let inventory = Arc::clone(&self.inventory);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || inventory.scan_complete())
                .await
                .map_err(|error| {
                    LifecycleExecutionError::Handler(anyhow!(
                        "complete lifecycle inventory worker failed: {error}"
                    ))
                })?
                .map_err(LifecycleExecutionError::Handler)
        })
    }

    fn bind_startup_inventory(
        &self,
        startup: LifecycleJournalStartupInventory,
        snapshot: Arc<LifecyclePhysicalInventorySnapshot>,
    ) -> LifecycleStartupBindingFuture {
        let effects = Arc::clone(&self.effects);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                effects.bind_startup_inventory(startup, snapshot.as_ref())
            })
            .await
            .map_err(|error| {
                LifecycleExecutionError::Handler(anyhow!(
                    "startup lifecycle inventory binding worker failed: {error}"
                ))
            })?
            .map_err(LifecycleExecutionError::Handler)
        })
    }

    fn recover_terminal_admission(
        &self,
        session: SessionBinding,
        current: StoredLifecycleJournal,
        startup_inventory: Arc<StartupPhysicalInventory>,
    ) -> LifecycleTerminalAdmissionRecoveryFuture {
        let effects = Arc::clone(&self.effects);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                recover_terminal_admission_blocking(
                    &session,
                    &current,
                    startup_inventory.as_ref(),
                    effects.as_ref(),
                )
            })
            .await
            .map_err(|error| {
                LifecycleExecutionError::Handler(anyhow!(
                    "terminal lifecycle admission recovery worker failed: {error}"
                ))
            })?
        })
    }

    fn execute(
        &self,
        journal: Arc<FileLifecycleCommandJournal>,
        current: StoredLifecycleJournal,
    ) -> LifecycleExecutionFuture {
        let effects = Arc::clone(&self.effects);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                execute_blocking(&journal, current, effects.as_ref())
            })
            .await
            .map_err(|error| {
                LifecycleExecutionError::Handler(anyhow!(
                    "atomic lifecycle executor worker failed: {error}"
                ))
            })?
        })
    }
}

fn recover_terminal_admission_blocking(
    session: &SessionBinding,
    current: &StoredLifecycleJournal,
    startup_inventory: &StartupPhysicalInventory,
    effects: &dyn AtomicLifecycleEffectPort,
) -> Result<(), LifecycleExecutionError> {
    let response = match current.record() {
        LifecycleJournalRecord::CompletedDeleteReceipt { .. } => return Ok(()),
        LifecycleJournalRecord::Command {
            state: CommandJournalState::Terminal { result, .. },
            ..
        } => result.decode_api()?,
        LifecycleJournalRecord::Command { .. } => {
            return Err(LifecycleExecutionError::Handler(anyhow!(
                "startup admission recovery requires a durable terminal journal"
            )))
        }
    };
    if !matches!(
        response.result,
        NodeResult::RuntimeReady(_) | NodeResult::SuspendDeclined(_)
    ) {
        return Ok(());
    }
    effects
        .recover_terminal_admission(session, current, startup_inventory)
        .map_err(LifecycleExecutionError::Handler)
}

fn execute_blocking(
    journal: &FileLifecycleCommandJournal,
    mut current: StoredLifecycleJournal,
    effects: &dyn AtomicLifecycleEffectPort,
) -> Result<StoredLifecycleJournal, LifecycleExecutionError> {
    let (command, predecessor_command, predecessor) = match current.record() {
        LifecycleJournalRecord::CompletedDeleteReceipt { .. } => return Ok(current),
        LifecycleJournalRecord::Command { command, .. } => (
            command.decode_api()?,
            current.predecessor_command()?,
            current.record().decode_predecessor_response()?,
        ),
    };
    for _ in 0..MAX_EFFECT_TRANSITIONS_PER_CALL {
        let state = match current.record() {
            LifecycleJournalRecord::CompletedDeleteReceipt { .. } => return Ok(current),
            LifecycleJournalRecord::Command { state, .. } => state.clone(),
        };

        match state {
            CommandJournalState::Terminal { .. } => return Ok(current),
            CommandJournalState::Accepted { stop_fence } => {
                let plan = effects
                    .plan_initial(
                        &command,
                        predecessor_command.as_ref(),
                        predecessor.as_ref(),
                        stop_fence.is_some(),
                    )
                    .map_err(LifecycleExecutionError::Handler)?;
                current = persist_planned_effect(journal, &current, stop_fence.as_ref(), plan)?;
            }
            CommandJournalState::Executing { step, stop_fence } => {
                let token = stop_fence
                    .as_ref()
                    .map(|_| journal.recover_current_stop_fence(&current))
                    .transpose()?;
                let progress = apply_current_effect(
                    journal,
                    &current,
                    token.as_ref(),
                    effects,
                    CurrentLifecycleEffect {
                        command: &command,
                        predecessor_command: predecessor_command.as_ref(),
                        predecessor: predecessor.as_ref(),
                        step: &step,
                    },
                )?;
                current = match progress {
                    LifecycleEffectProgress::Next(plan) => persist_next_effect(
                        journal,
                        &current,
                        stop_fence.as_ref(),
                        token.as_ref(),
                        plan,
                    )?,
                    LifecycleEffectProgress::Terminal(result) => {
                        persist_terminal(journal, &current, token.as_ref(), &command, result)?
                    }
                };
            }
        }
    }

    Err(LifecycleExecutionError::Handler(anyhow!(
        "atomic lifecycle command exceeded {MAX_EFFECT_TRANSITIONS_PER_CALL} durable effect transitions"
    )))
}

struct CurrentLifecycleEffect<'a> {
    command: &'a LifecycleCommandEnvelope,
    predecessor_command: Option<&'a LifecycleCommandEnvelope>,
    predecessor: Option<&'a LifecycleCommandResponse>,
    step: &'a ExecutionStep,
}

fn apply_current_effect(
    journal: &FileLifecycleCommandJournal,
    current: &StoredLifecycleJournal,
    token: Option<&DurableStopFence>,
    effects: &dyn AtomicLifecycleEffectPort,
    input: CurrentLifecycleEffect<'_>,
) -> Result<LifecycleEffectProgress, LifecycleExecutionError> {
    let CurrentLifecycleEffect {
        command,
        predecessor_command,
        predecessor,
        step,
    } = input;
    let Some(token) = token else {
        return effects
            .apply(
                command,
                predecessor_command,
                predecessor,
                step,
                LifecycleEffectAuthority::Unfenced,
            )
            .map_err(LifecycleExecutionError::Handler);
    };
    let guard = journal.retain_current_stop_fence(current, token)?;
    let progress = effects
        .apply(
            command,
            predecessor_command,
            predecessor,
            step,
            LifecycleEffectAuthority::StopFenced(&guard),
        )
        .map_err(LifecycleExecutionError::Handler)?;
    guard.assert_current()?;
    Ok(progress)
}

fn persist_planned_effect(
    journal: &FileLifecycleCommandJournal,
    current: &StoredLifecycleJournal,
    inherited: Option<&EmbeddedStopFence>,
    plan: PlannedLifecycleEffect,
) -> Result<StoredLifecycleJournal, LifecycleExecutionError> {
    match (inherited, plan.stop_fence) {
        (Some(fence), StopFenceDirective::Inherit) => journal
            .record_execution(current, plan.step, Some(fence.clone()))
            .map_err(Into::into),
        (Some(_), StopFenceDirective::None | StopFenceDirective::Install { .. }) => {
            Err(LifecycleExecutionError::Handler(anyhow!(
                "initial effect attempted to remove or replace an inherited Stop fence"
            )))
        }
        (None, StopFenceDirective::None) => journal
            .record_execution(current, plan.step, None)
            .map_err(Into::into),
        (None, StopFenceDirective::Install { fence_payload }) => journal
            .record_stop_fence(current, plan.step, fence_payload)
            .map(|(stored, _)| stored)
            .map_err(Into::into),
        (None, StopFenceDirective::Inherit) => Err(LifecycleExecutionError::Handler(anyhow!(
            "initial effect requested a missing inherited Stop fence"
        ))),
    }
}

fn persist_next_effect(
    journal: &FileLifecycleCommandJournal,
    current: &StoredLifecycleJournal,
    current_fence: Option<&EmbeddedStopFence>,
    token: Option<&DurableStopFence>,
    plan: PlannedLifecycleEffect,
) -> Result<StoredLifecycleJournal, LifecycleExecutionError> {
    match (current_fence, token, plan.stop_fence) {
        (Some(_), Some(token), StopFenceDirective::Inherit) => journal
            .advance_stop_fenced_execution(current, token, plan.step)
            .map(|(stored, _)| stored)
            .map_err(Into::into),
        (Some(_), Some(_), StopFenceDirective::None | StopFenceDirective::Install { .. }) => {
            Err(LifecycleExecutionError::Handler(anyhow!(
                "effect attempted to remove or replace the current Stop fence"
            )))
        }
        (None, None, StopFenceDirective::None) => journal
            .record_execution(current, plan.step, None)
            .map_err(Into::into),
        (None, None, StopFenceDirective::Install { fence_payload }) => journal
            .record_stop_fence(current, plan.step, fence_payload)
            .map(|(stored, _)| stored)
            .map_err(Into::into),
        (None, None, StopFenceDirective::Inherit) => Err(LifecycleExecutionError::Handler(
            anyhow!("effect requested a missing inherited Stop fence"),
        )),
        _ => Err(LifecycleExecutionError::Handler(anyhow!(
            "journal Stop-fence projection and recovered capability disagree"
        ))),
    }
}

fn persist_terminal(
    journal: &FileLifecycleCommandJournal,
    current: &StoredLifecycleJournal,
    token: Option<&DurableStopFence>,
    command: &LifecycleCommandEnvelope,
    result: NodeResult,
) -> Result<StoredLifecycleJournal, LifecycleExecutionError> {
    let deleted = matches!(result, NodeResult::Deleted(_));
    let response = LifecycleCommandResponse::new(command, result)
        .map_err(|error| LifecycleExecutionError::Handler(anyhow!(error)))?;
    let exact = ExactCommandResult::from_api(&response)?;
    match (token, deleted) {
        (Some(token), true) => journal
            .complete_delete(current, token, exact)
            .map_err(Into::into),
        (Some(token), false) => journal
            .complete_after_stop(current, token, exact)
            .map_err(Into::into),
        (None, false) => journal.complete(current, exact).map_err(Into::into),
        (None, true) => Err(LifecycleExecutionError::Handler(anyhow!(
            "successful Delete did not retain a durable Stop fence"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use cats_api::runtime_lifecycle::{
        CommandFailedResult, CommandFailureReason, DiskRole, ExecutionAbsenceProof,
        ImmutableRuntimeConfig, LifecycleCommand, LifecyclePredecessor, PlacementIdentity,
        RetainedEvidence, RuntimeNetworkConfig, RuntimeReadyResult, RuntimeVolumeAuthorityInput,
        RuntimeVolumeConfig, RuntimeVolumeGuestBinding, StartSource, StartSpec,
        StartVolumeAuthority, VolumeTerminalReceipt,
    };
    use cats_api::runtime_reconciliation::{
        Durability, Epoch, FenceEpoch, Generation, Id, Ipv4Address, MacAddress, RandomId128,
        Sha256Digest, UnixMillis,
    };

    use super::*;
    use crate::lifecycle_command::journal::{
        AdmitCommandOutcome, GenesisLocalInventory, LifecycleJournalRecord,
    };

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn random(byte: u8) -> RandomId128 {
        RandomId128::new(format!("{byte:02x}").repeat(16)).expect("valid random ID")
    }

    fn command() -> LifecycleCommandEnvelope {
        let placement = PlacementIdentity {
            node_id: id("node_executor"),
            placement_epoch: Epoch::new(1).expect("positive placement epoch"),
        };
        let runtime_config = ImmutableRuntimeConfig::new(
            id("config_executor"),
            digest(1),
            2,
            512 * 1024 * 1024,
            digest(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_executor"),
                guest_mac: MacAddress::new("02:00:00:00:00:31").expect("valid MAC"),
                guest_ipv4: Ipv4Address::new("10.0.0.2").expect("valid guest IP"),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").expect("valid gateway IP"),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_executor_root"),
                disk_id: id("disk_executor_root"),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("executor_root_serial"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .expect("valid runtime config");
        LifecycleCommandEnvelope::new(
            id("operation_executor_start"),
            id("workspace_executor"),
            id("cat_executor"),
            placement.node_id.clone(),
            placement.clone(),
            runtime_config,
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id("creation_executor"),
                target_placement: placement,
            },
            LifecycleCommand::Start(Box::new(StartSpec {
                volume_authorities: vec![StartVolumeAuthority {
                    volume_id: id("volume_executor_root"),
                    disk_id: id("disk_executor_root"),
                    authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: FenceEpoch::new(0).expect("zero unowned epoch"),
                        transition_id: random(3),
                    },
                }],
                source: StartSource::Genesis,
                effect_deadline_unix_ms: UnixMillis::new(9_000_000).expect("positive deadline"),
            })),
        )
        .expect("valid command")
    }

    fn absence() -> ExecutionAbsenceProof {
        ExecutionAbsenceProof {
            stop_fence_receipt_digest: digest(4),
            admission_closed_receipt_digest: digest(5),
            dedicated_scope_absence_receipt_digest: digest(6),
            frontend_absence_receipt_digest: digest(7),
            restart_source_absence_receipt_digest: digest(8),
        }
    }

    fn start_failed() -> NodeResult {
        NodeResult::StartFailed(Box::new(CommandFailedResult {
            reason: CommandFailureReason::VmmFailed,
            not_running: absence(),
            retained_evidence: RetainedEvidence {
                artifact_manifest_digest: digest(9),
                adoptable_count: 0,
                gc_candidate_count: 0,
                retained_authority_or_data_count: 0,
                quarantined_count: 0,
            },
            retained_volume_receipts: Vec::new(),
        }))
    }

    fn runtime_ready(command: &LifecycleCommandEnvelope) -> NodeResult {
        NodeResult::RuntimeReady(Box::new(RuntimeReadyResult {
            runtime_incarnation: random(10),
            runtime_config_digest: command.runtime_config.config_digest.clone(),
            execution_receipt_digest: digest(11),
            guest_ready_receipt_digest: digest(12),
            volume_receipts: vec![VolumeTerminalReceipt {
                volume_id: id("volume_executor_root"),
                disk_id: id("disk_executor_root"),
                disk_role: DiskRole::Root,
                attachment_id: id("attachment_executor_root"),
                attachment_epoch: FenceEpoch::new(1).expect("positive attachment epoch"),
                local_durable_generation: Generation::new(1).expect("valid generation"),
                remote_durable_generation: Generation::new(1).expect("valid generation"),
                authority_receipt_digest: Some(digest(13)),
            }],
        }))
    }

    fn accepted(
        journal: &FileLifecycleCommandJournal,
        command: &LifecycleCommandEnvelope,
    ) -> StoredLifecycleJournal {
        match journal
            .admit_api(command, GenesisLocalInventory::ConfirmedEmpty)
            .expect("admit command")
        {
            AdmitCommandOutcome::Accepted(current) => current,
            other => panic!("unexpected admission outcome: {other:?}"),
        }
    }

    struct EmptyInventory;

    impl LifecyclePhysicalInventoryPort for EmptyInventory {
        fn scan_complete(&self) -> anyhow::Result<LifecyclePhysicalInventorySnapshot> {
            Ok(LifecyclePhysicalInventorySnapshot::physical_only(
                StartupPhysicalInventory::Complete {
                    scan_id: random(90),
                    collected_at_unix_ms: UnixMillis::new(1_000)
                        .expect("valid inventory collection time"),
                    cats: Vec::new(),
                    unattributed_artifacts: Vec::new(),
                },
            ))
        }
    }

    enum ScriptAction {
        Error,
        Next(PlannedLifecycleEffect),
        Terminal(NodeResult),
    }

    struct ScriptedEffects {
        journal: Arc<FileLifecycleCommandJournal>,
        initial: PlannedLifecycleEffect,
        actions: Mutex<VecDeque<ScriptAction>>,
        plan_calls: AtomicUsize,
        apply_calls: AtomicUsize,
        fenced_apply_calls: AtomicUsize,
    }

    impl ScriptedEffects {
        fn new(
            journal: Arc<FileLifecycleCommandJournal>,
            initial: PlannedLifecycleEffect,
            actions: Vec<ScriptAction>,
        ) -> Arc<Self> {
            Arc::new(Self {
                journal,
                initial,
                actions: Mutex::new(actions.into()),
                plan_calls: AtomicUsize::new(0),
                apply_calls: AtomicUsize::new(0),
                fenced_apply_calls: AtomicUsize::new(0),
            })
        }
    }

    impl AtomicLifecycleEffectPort for ScriptedEffects {
        fn bind_startup_inventory(
            &self,
            startup: LifecycleJournalStartupInventory,
            _snapshot: &LifecyclePhysicalInventorySnapshot,
        ) -> anyhow::Result<LifecycleJournalStartupInventory> {
            Ok(startup)
        }

        fn recover_terminal_admission(
            &self,
            _session: &SessionBinding,
            _current: &StoredLifecycleJournal,
            _startup_inventory: &StartupPhysicalInventory,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn plan_initial(
            &self,
            _command: &LifecycleCommandEnvelope,
            _predecessor_command: Option<&LifecycleCommandEnvelope>,
            _predecessor: Option<&LifecycleCommandResponse>,
            _inherited_stop_fence: bool,
        ) -> anyhow::Result<PlannedLifecycleEffect> {
            self.plan_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.initial.clone())
        }

        fn apply(
            &self,
            _command: &LifecycleCommandEnvelope,
            _predecessor_command: Option<&LifecycleCommandEnvelope>,
            _predecessor: Option<&LifecycleCommandResponse>,
            step: &ExecutionStep,
            authority: LifecycleEffectAuthority<'_>,
        ) -> anyhow::Result<LifecycleEffectProgress> {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            if authority.stop_fence().is_some() {
                self.fenced_apply_calls.fetch_add(1, Ordering::SeqCst);
            }
            let durable = self.journal.load()?.expect("durable current command");
            assert!(matches!(
                durable.record(),
                LifecycleJournalRecord::Command {
                    state: CommandJournalState::Executing {
                        step: durable_step,
                        ..
                    },
                    ..
                } if durable_step == step
            ));
            match self.actions.lock().expect("script lock").pop_front() {
                Some(ScriptAction::Error) => Err(anyhow!("ambiguous provider response")),
                Some(ScriptAction::Next(next)) => Ok(LifecycleEffectProgress::Next(next)),
                Some(ScriptAction::Terminal(result)) => {
                    Ok(LifecycleEffectProgress::Terminal(result))
                }
                None => Err(anyhow!("effect script exhausted")),
            }
        }
    }

    fn step(name: &str, payload: u8) -> ExecutionStep {
        ExecutionStep {
            name: id(name),
            recovery_payload: ExactBytes::new(vec![payload]),
        }
    }

    #[tokio::test]
    async fn fsyncs_each_effect_and_retains_stop_fence_before_terminal_failure() {
        let directory = tempfile::tempdir().expect("temporary journal directory");
        let command = command();
        let journal = Arc::new(
            FileLifecycleCommandJournal::open(directory.path(), &command.cat_id)
                .expect("open journal"),
        );
        let accepted = accepted(&journal, &command);
        let effects = ScriptedEffects::new(
            Arc::clone(&journal),
            PlannedLifecycleEffect::install_stop_fence(
                step("close_and_stop", 1),
                ExactBytes::new(b"exact-stop-fence".to_vec()),
            ),
            vec![
                ScriptAction::Next(PlannedLifecycleEffect::inherit_stop_fence(step(
                    "prove_absence",
                    2,
                ))),
                ScriptAction::Terminal(start_failed()),
            ],
        );
        let executor = AtomicLifecycleExecutor::new(Arc::new(EmptyInventory), effects.clone());

        let physical = executor
            .physical_inventory()
            .await
            .expect("complete inventory");
        assert_eq!(
            physical.physical(),
            &StartupPhysicalInventory::Complete {
                scan_id: random(90),
                collected_at_unix_ms: UnixMillis::new(1_000)
                    .expect("valid inventory collection time"),
                cats: Vec::new(),
                unattributed_artifacts: Vec::new(),
            }
        );
        let terminal = executor
            .execute(Arc::clone(&journal), accepted)
            .await
            .expect("execute command");

        assert_eq!(effects.plan_calls.load(Ordering::SeqCst), 1);
        assert_eq!(effects.apply_calls.load(Ordering::SeqCst), 2);
        assert_eq!(effects.fenced_apply_calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            terminal.record(),
            LifecycleJournalRecord::Command {
                state: CommandJournalState::Terminal {
                    stop_fence: Some(_),
                    ..
                },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn ambiguous_effect_keeps_exact_step_and_retry_does_not_replan() {
        let directory = tempfile::tempdir().expect("temporary journal directory");
        let command = command();
        let journal = Arc::new(
            FileLifecycleCommandJournal::open(directory.path(), &command.cat_id)
                .expect("open journal"),
        );
        let accepted = accepted(&journal, &command);
        let durable_step = step("launch_vmm", 3);
        let effects = ScriptedEffects::new(
            Arc::clone(&journal),
            PlannedLifecycleEffect::unfenced(durable_step.clone()),
            vec![
                ScriptAction::Error,
                ScriptAction::Terminal(runtime_ready(&command)),
            ],
        );
        let executor = AtomicLifecycleExecutor::new(Arc::new(EmptyInventory), effects.clone());

        executor
            .execute(Arc::clone(&journal), accepted)
            .await
            .expect_err("ambiguous response remains unresolved");
        let executing = journal
            .load()
            .expect("load journal")
            .expect("current command");
        assert!(matches!(
            executing.record(),
            LifecycleJournalRecord::Command {
                state: CommandJournalState::Executing { step, .. },
                ..
            } if step == &durable_step
        ));

        let terminal = executor
            .execute(Arc::clone(&journal), executing)
            .await
            .expect("retry discovers exact postcondition");
        assert_eq!(effects.plan_calls.load(Ordering::SeqCst), 1);
        assert_eq!(effects.apply_calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            terminal.record(),
            LifecycleJournalRecord::Command {
                state: CommandJournalState::Terminal {
                    stop_fence: None,
                    ..
                },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn missing_inherited_fence_is_rejected_before_physical_effect() {
        let directory = tempfile::tempdir().expect("temporary journal directory");
        let command = command();
        let journal = Arc::new(
            FileLifecycleCommandJournal::open(directory.path(), &command.cat_id)
                .expect("open journal"),
        );
        let accepted = accepted(&journal, &command);
        let effects = ScriptedEffects::new(
            Arc::clone(&journal),
            PlannedLifecycleEffect::inherit_stop_fence(step("must_be_fenced", 4)),
            Vec::new(),
        );
        let executor = AtomicLifecycleExecutor::new(Arc::new(EmptyInventory), effects.clone());

        executor
            .execute(Arc::clone(&journal), accepted)
            .await
            .expect_err("missing fence must fail closed");
        assert_eq!(effects.apply_calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            journal
                .load()
                .expect("load journal")
                .expect("current command")
                .record(),
            LifecycleJournalRecord::Command {
                state: CommandJournalState::Accepted { stop_fence: None },
                ..
            }
        ));
    }
}
