//! Host-global registry for lifecycle and Route admission cells.
//!
//! There is exactly one `Arc<LifecycleRouteAdmissionCell>` per recoverable Cat
//! in a Node process. Startup derives the set from the descriptor-safe local
//! lifecycle journal joined with one complete physical inventory. Telemetry is
//! intentionally absent: reconstruction always starts Closed, and only the
//! lifecycle executor may publish RuntimeReady after proving its exact local
//! postcondition.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use cats_api::runtime_lifecycle::{
    validate_lifecycle_command_envelope, validate_lifecycle_command_response_for_command,
    LifecycleCommand, LifecycleCommandEnvelope, LifecyclePredecessor, NodeResult,
};
use cats_api::runtime_reconciliation::{Id, SessionBinding, Sha256Digest};
use thiserror::Error;

use crate::admission::{
    AgentSessionReplacementOutcome, LifecycleRouteAdmissionCell, RouteInterlockError,
};
use crate::lifecycle_command::journal::{
    enumerate_startup_in_state_directory, LifecycleJournalError, LifecycleJournalStartupInventory,
    StartupPhysicalInventory,
};
use crate::state_directory::StateDirectory;

#[derive(Debug, Clone, PartialEq, Eq)]
enum AdmissionCellSource {
    RecoveredJournal {
        closed_anchor_operation_id: Id,
        request_fingerprint: Sha256Digest,
        recoverable_running_terminal: Option<RecoverableRunningTerminal>,
    },
    InitialTarget {
        operation_id: Id,
        request_fingerprint: cats_api::runtime_reconciliation::Sha256Digest,
        closed_anchor_operation_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoverableRunningTerminal {
    terminal_result_digest: Sha256Digest,
    source_lifecycle_operation_id: Id,
    runtime_incarnation: cats_api::runtime_reconciliation::RandomId128,
}

#[derive(Debug)]
struct AdmissionCellEntry {
    cell: Arc<LifecycleRouteAdmissionCell>,
    source: AdmissionCellSource,
}

#[derive(Debug)]
struct RegistryState {
    initialization: Option<RegistryInitialization>,
    current_session: Option<SessionBinding>,
    unattributed_artifacts_present: bool,
    cells: BTreeMap<Id, AdmissionCellEntry>,
    blocked: BTreeMap<Id, String>,
}

struct FailClosedStartupProjection {
    cells: BTreeMap<Id, AdmissionCellEntry>,
    blocked: BTreeMap<Id, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryInitialization {
    session: SessionBinding,
    state_directory: StateDirectoryAuthority,
    physical_inventory: StartupPhysicalInventory,
    startup: LifecycleJournalStartupInventory,
}

/// Exact pathname plus retained descriptor identity used for the one startup
/// enumeration. A same-string rename/recreate is not an idempotent retry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StateDirectoryAuthority {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

/// The process-wide owner of every per-Cat lifecycle/Route linearization
/// point. Lifecycle effects and the Route command runner must receive the same
/// `Arc<Self>` from composition; neither component may create a private cell.
#[derive(Debug)]
pub struct LifecycleAdmissionRegistry {
    state: Mutex<RegistryState>,
}

#[derive(Debug, Error)]
pub enum LifecycleAdmissionRegistryError {
    #[error(transparent)]
    Journal(#[from] LifecycleJournalError),
    #[error("lifecycle admission registry mutex is unavailable")]
    Unavailable,
    #[error("lifecycle admission registry has not completed startup initialization")]
    Uninitialized,
    #[error("lifecycle admission registry was already initialized from different authority")]
    InitializationConflict,
    #[error("invalid lifecycle admission startup inventory: {reason}")]
    InvalidStartupInventory { reason: String },
    #[error("Cat {cat_id} is blocked by startup recovery: {reason}")]
    CatBlocked { cat_id: Id, reason: String },
    #[error("Cat {cat_id} already has a lifecycle admission cell from another local authority")]
    CellAuthorityConflict { cat_id: Id },
    #[error("the lifecycle command cannot establish a new local admission target")]
    InvalidInitialTargetCommand,
    #[error("same-Node lifecycle successor for Cat {cat_id} has no existing admission cell")]
    MissingSameNodeAdmissionCell { cat_id: Id },
    #[error("the registry AgentSession does not match the expected session")]
    StaleAgentSession,
    #[error("the recovered journal does not contain the exact verified Running terminal")]
    RuntimeReadyRecoveryAuthorityMismatch,
    #[error("complete startup inventory contains unattributed Host artifacts")]
    UnattributedPhysicalArtifacts,
    #[error("the replacement AgentSession is not a strict successor on the same Node")]
    InvalidAgentSessionSuccessor,
    #[error("Cat {cat_id} admission interlock failed: {source}")]
    CellInterlock {
        cat_id: Id,
        #[source]
        source: RouteInterlockError,
    },
}

impl LifecycleAdmissionRegistry {
    /// Create the one Host-global handle before the inventory port, lifecycle
    /// executor and Route runner are composed. Every operation except exact
    /// one-shot initialization fails closed until initialization succeeds.
    pub fn new_uninitialized() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RegistryState {
                initialization: None,
                current_session: None,
                unattributed_artifacts_present: false,
                cells: BTreeMap::new(),
                blocked: BTreeMap::new(),
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_machine_test(session: SessionBinding) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RegistryState {
                initialization: Some(RegistryInitialization {
                    session: session.clone(),
                    state_directory: test_state_directory_authority("<machine-test-state>"),
                    physical_inventory: StartupPhysicalInventory::Complete {
                        scan_id: cats_api::runtime_reconciliation::RandomId128::new(
                            "77".repeat(16),
                        )
                        .expect("fixed test scan ID"),
                        collected_at_unix_ms: cats_api::runtime_reconciliation::UnixMillis::new(1)
                            .expect("positive test scan time"),
                        cats: Vec::new(),
                        unattributed_artifacts: Vec::new(),
                    },
                    startup: LifecycleJournalStartupInventory::default(),
                }),
                current_session: Some(session),
                unattributed_artifacts_present: false,
                cells: BTreeMap::new(),
                blocked: BTreeMap::new(),
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn insert_cell_for_machine_test(
        &self,
        cell: Arc<LifecycleRouteAdmissionCell>,
    ) -> Result<(), LifecycleAdmissionRegistryError> {
        let mut state = self.lock()?;
        require_initialized(&state)?;
        let cat_id = cell.cat_id().clone();
        if state.cells.contains_key(&cat_id) {
            return Err(LifecycleAdmissionRegistryError::CellAuthorityConflict { cat_id });
        }
        state.cells.insert(
            cat_id,
            AdmissionCellEntry {
                cell,
                source: AdmissionCellSource::InitialTarget {
                    operation_id: Id::new("machine_test_start").expect("fixed test operation ID"),
                    request_fingerprint: Sha256Digest::from_bytes([0x44; 32]),
                    closed_anchor_operation_id: Id::new("machine_test_creation")
                        .expect("fixed test creation ID"),
                },
            },
        );
        Ok(())
    }

    /// Enumerate the durable journal namespace against the runner's one
    /// complete physical scan and construct every recoverable Cat fail-closed.
    /// The same startup value is returned to worker recovery. An exact retry
    /// with the same session, path and inventory is idempotent and does not
    /// enumerate the filesystem again; every other second initialization is
    /// rejected.
    pub fn initialize_fail_closed_once(
        &self,
        session: SessionBinding,
        state_directory: &StateDirectory,
        physical_inventory: &StartupPhysicalInventory,
    ) -> Result<LifecycleJournalStartupInventory, LifecycleAdmissionRegistryError> {
        let authority = state_directory_authority(state_directory)?;
        let mut state = self.lock()?;
        if let Some(initialization) = &state.initialization {
            return if initialization.session == session
                && initialization.state_directory == authority
                && initialization.physical_inventory == *physical_inventory
            {
                Ok(initialization.startup.clone())
            } else {
                Err(LifecycleAdmissionRegistryError::InitializationConflict)
            };
        }

        // Initialization intentionally owns the registry mutex across this
        // descriptor-safe enumeration. No service or worker is allowed to use
        // the registry yet, and this guarantees one enumeration even when two
        // startup callers race.
        let startup = enumerate_startup_in_state_directory(state_directory, physical_inventory)?;
        if state_directory_authority(state_directory)? != authority {
            return Err(LifecycleAdmissionRegistryError::InitializationConflict);
        }
        let FailClosedStartupProjection { cells, blocked } =
            build_fail_closed_cells(&session, physical_inventory, &startup)?;
        state.cells = cells;
        state.blocked = blocked;
        state.unattributed_artifacts_present = physical_inventory.has_unattributed_artifacts();
        state.current_session = Some(session.clone());
        state.initialization = Some(RegistryInitialization {
            session,
            state_directory: authority,
            physical_inventory: physical_inventory.clone(),
            startup: startup.clone(),
        });
        Ok(startup)
    }

    #[cfg(test)]
    fn from_startup_inventory(
        session: SessionBinding,
        physical_inventory: &StartupPhysicalInventory,
        startup: &LifecycleJournalStartupInventory,
    ) -> Result<Self, LifecycleAdmissionRegistryError> {
        let FailClosedStartupProjection { cells, blocked } =
            build_fail_closed_cells(&session, physical_inventory, startup)?;

        Ok(Self {
            state: Mutex::new(RegistryState {
                initialization: Some(RegistryInitialization {
                    session: session.clone(),
                    state_directory: test_state_directory_authority("<test-state>"),
                    physical_inventory: physical_inventory.clone(),
                    startup: startup.clone(),
                }),
                current_session: Some(session),
                unattributed_artifacts_present: physical_inventory.has_unattributed_artifacts(),
                cells,
                blocked,
            }),
        })
    }

    /// Return the sole process-local cell for a recoverable Cat. A blocked Cat
    /// is an error, never an absent value that a caller may recreate.
    pub fn lookup(
        &self,
        cat_id: &Id,
    ) -> Result<Option<Arc<LifecycleRouteAdmissionCell>>, LifecycleAdmissionRegistryError> {
        let state = self.lock()?;
        require_initialized(&state)?;
        if let Some(reason) = state.blocked.get(cat_id) {
            return Err(LifecycleAdmissionRegistryError::CatBlocked {
                cat_id: cat_id.clone(),
                reason: reason.clone(),
            });
        }
        Ok(state.cells.get(cat_id).map(|entry| Arc::clone(&entry.cell)))
    }

    /// Ensure a fail-closed cell for a newly accepted Start whose target has no
    /// local journal predecessor: Genesis, CrossNodeColdHandoff or
    /// HostFenceRecovery. Same-node successors must already have a recovered
    /// cell and can never manufacture one from a missing journal.
    pub fn ensure_initial_target_fail_closed(
        &self,
        command: &LifecycleCommandEnvelope,
    ) -> Result<Arc<LifecycleRouteAdmissionCell>, LifecycleAdmissionRegistryError> {
        if validate_lifecycle_command_envelope(command).is_err()
            || !matches!(command.command, LifecycleCommand::Start(_))
        {
            return Err(LifecycleAdmissionRegistryError::InvalidInitialTargetCommand);
        }
        let anchor = match &command.predecessor {
            LifecyclePredecessor::Genesis {
                cat_creation_id,
                target_placement,
            } if target_placement == &command.placement_identity => cat_creation_id,
            LifecyclePredecessor::CrossNodeColdHandoff {
                cold_operation_id,
                target_placement,
                ..
            } if target_placement == &command.placement_identity => cold_operation_id,
            LifecyclePredecessor::HostFenceRecovery {
                interrupted_operation_id,
                target_placement,
                ..
            } if target_placement == &command.placement_identity => interrupted_operation_id,
            LifecyclePredecessor::SameNode { .. } => {
                let existing = self.lookup(&command.cat_id)?;
                return existing.ok_or_else(|| {
                    LifecycleAdmissionRegistryError::MissingSameNodeAdmissionCell {
                        cat_id: command.cat_id.clone(),
                    }
                });
            }
            LifecyclePredecessor::Genesis { .. }
            | LifecyclePredecessor::CrossNodeColdHandoff { .. }
            | LifecyclePredecessor::HostFenceRecovery { .. } => {
                return Err(LifecycleAdmissionRegistryError::InvalidInitialTargetCommand)
            }
        };
        self.ensure_initial_target_identity(
            command.cat_id.clone(),
            command.operation_id.clone(),
            command.request_fingerprint.clone(),
            anchor.clone(),
        )
    }

    /// Publish Running admission after startup only when the installed
    /// executor has independently rediscovered the exact physical
    /// postcondition for the journal's terminal RuntimeReady or
    /// SuspendDeclined result.
    ///
    /// The caller supplies the exact journal identity it verified alongside
    /// the rich physical Cat projection. This method re-closes that proof
    /// against the current AgentSession, the registry's closed anchor and the
    /// terminal digest before opening lifecycle admission. Endpoint lanes are
    /// not reconstructed and remain Closed until fresh per-Endpoint Enable
    /// commands for this AgentSession arrive.
    pub fn recover_verified_runtime_ready(
        &self,
        expected_session: &SessionBinding,
        cat_id: &Id,
        closed_anchor_operation_id: &Id,
        request_fingerprint: &Sha256Digest,
        terminal_result_digest: &Sha256Digest,
        ready: crate::admission::EffectiveRuntimeReady,
    ) -> Result<bool, LifecycleAdmissionRegistryError> {
        let state = self.lock()?;
        require_initialized(&state)?;
        if state.current_session.as_ref() != Some(expected_session) {
            return Err(LifecycleAdmissionRegistryError::StaleAgentSession);
        }
        if let Some(reason) = state.blocked.get(cat_id) {
            return Err(LifecycleAdmissionRegistryError::CatBlocked {
                cat_id: cat_id.clone(),
                reason: reason.clone(),
            });
        }
        let Some(entry) = state.cells.get(cat_id) else {
            return Err(LifecycleAdmissionRegistryError::RuntimeReadyRecoveryAuthorityMismatch);
        };
        let AdmissionCellSource::RecoveredJournal {
            closed_anchor_operation_id: stored_anchor,
            request_fingerprint: stored_fingerprint,
            recoverable_running_terminal: Some(terminal),
        } = &entry.source
        else {
            return Err(LifecycleAdmissionRegistryError::RuntimeReadyRecoveryAuthorityMismatch);
        };
        if stored_anchor != closed_anchor_operation_id
            || stored_fingerprint != request_fingerprint
            || &terminal.terminal_result_digest != terminal_result_digest
            || terminal.source_lifecycle_operation_id != *ready.source_lifecycle_operation_id()
            || terminal.runtime_incarnation != *ready.runtime_incarnation()
        {
            return Err(LifecycleAdmissionRegistryError::RuntimeReadyRecoveryAuthorityMismatch);
        }
        entry
            .cell
            .publish_runtime_ready(closed_anchor_operation_id, ready)
            .map_err(|source| LifecycleAdmissionRegistryError::CellInterlock {
                cat_id: cat_id.clone(),
                source,
            })
    }

    fn ensure_initial_target_identity(
        &self,
        cat_id: Id,
        operation_id: Id,
        request_fingerprint: cats_api::runtime_reconciliation::Sha256Digest,
        closed_anchor_operation_id: Id,
    ) -> Result<Arc<LifecycleRouteAdmissionCell>, LifecycleAdmissionRegistryError> {
        let mut state = self.lock()?;
        require_initialized(&state)?;
        if state.unattributed_artifacts_present {
            return Err(LifecycleAdmissionRegistryError::UnattributedPhysicalArtifacts);
        }
        if let Some(reason) = state.blocked.get(&cat_id) {
            return Err(LifecycleAdmissionRegistryError::CatBlocked {
                cat_id,
                reason: reason.clone(),
            });
        }
        if let Some(entry) = state.cells.get(&cat_id) {
            return match &entry.source {
                AdmissionCellSource::InitialTarget {
                    operation_id: current_operation_id,
                    request_fingerprint: current_fingerprint,
                    closed_anchor_operation_id: current_anchor,
                } if current_operation_id == &operation_id
                    && current_fingerprint == &request_fingerprint
                    && current_anchor == &closed_anchor_operation_id =>
                {
                    Ok(Arc::clone(&entry.cell))
                }
                AdmissionCellSource::InitialTarget { .. }
                | AdmissionCellSource::RecoveredJournal { .. } => {
                    Err(LifecycleAdmissionRegistryError::CellAuthorityConflict { cat_id })
                }
            };
        }

        let cell = LifecycleRouteAdmissionCell::new_fail_closed(
            cat_id.clone(),
            state
                .current_session
                .as_ref()
                .ok_or(LifecycleAdmissionRegistryError::Uninitialized)?
                .clone(),
            closed_anchor_operation_id.clone(),
        );
        state.cells.insert(
            cat_id,
            AdmissionCellEntry {
                cell: Arc::clone(&cell),
                source: AdmissionCellSource::InitialTarget {
                    operation_id,
                    request_fingerprint,
                    closed_anchor_operation_id,
                },
            },
        );
        Ok(cell)
    }

    /// Replace the Host-global AgentSession while the registry mutex excludes
    /// cell creation. Every current cell closes its Route lanes before the
    /// registry publishes the replacement. If a poisoned cell interrupts the
    /// pass, the old registry session remains current and an exact retry safely
    /// replays cells already closed by the first attempt.
    pub fn replace_agent_session(
        &self,
        expected: &SessionBinding,
        replacement: &SessionBinding,
    ) -> Result<BTreeMap<Id, AgentSessionReplacementOutcome>, LifecycleAdmissionRegistryError> {
        let mut state = self.lock()?;
        require_initialized(&state)?;
        let current_session = state
            .current_session
            .as_ref()
            .ok_or(LifecycleAdmissionRegistryError::Uninitialized)?;
        if current_session == replacement {
            return Ok(BTreeMap::new());
        }
        if current_session != expected {
            return Err(LifecycleAdmissionRegistryError::StaleAgentSession);
        }
        if replacement.node_id != expected.node_id
            || replacement.agent_session_epoch <= expected.agent_session_epoch
        {
            return Err(LifecycleAdmissionRegistryError::InvalidAgentSessionSuccessor);
        }

        let mut outcomes = BTreeMap::new();
        for (cat_id, entry) in &state.cells {
            let outcome = entry
                .cell
                .replace_agent_session(expected, replacement)
                .map_err(|source| LifecycleAdmissionRegistryError::CellInterlock {
                    cat_id: cat_id.clone(),
                    source,
                })?;
            outcomes.insert(cat_id.clone(), outcome);
        }
        state.current_session = Some(replacement.clone());
        Ok(outcomes)
    }

    /// Close every process-local Endpoint gate while the registry mutex
    /// excludes concurrent cell creation. Ring failure uses this fail-closed
    /// path; each cell mutex orders the close with any in-flight acquisition.
    pub fn emergency_close_all_routes(
        &self,
    ) -> Result<
        BTreeMap<Id, Vec<crate::admission::ClosedRouteEpoch>>,
        LifecycleAdmissionRegistryError,
    > {
        let state = self.lock()?;
        require_initialized(&state)?;
        let mut closed = BTreeMap::new();
        for (cat_id, entry) in &state.cells {
            let epochs = entry.cell.emergency_close_routes().map_err(|source| {
                LifecycleAdmissionRegistryError::CellInterlock {
                    cat_id: cat_id.clone(),
                    source,
                }
            })?;
            if !epochs.is_empty() {
                closed.insert(cat_id.clone(), epochs);
            }
        }
        Ok(closed)
    }

    pub fn current_agent_session(&self) -> Result<SessionBinding, LifecycleAdmissionRegistryError> {
        self.lock()?
            .current_session
            .clone()
            .ok_or(LifecycleAdmissionRegistryError::Uninitialized)
    }

    pub fn blocked_cats(&self) -> Result<BTreeMap<Id, String>, LifecycleAdmissionRegistryError> {
        let state = self.lock()?;
        require_initialized(&state)?;
        Ok(state.blocked.clone())
    }

    /// Apply only the fail-closed classifications produced by the installed
    /// provider binder after the registry's sole journal enumeration. The
    /// runner separately proves that this value is an exact partition of that
    /// enumeration; this method closes shared Route lookup for quarantined
    /// non-terminal Cats without suppressing terminal-only result settlement.
    pub(crate) fn apply_startup_binding_fail_closed(
        &self,
        startup: &LifecycleJournalStartupInventory,
    ) -> Result<(), LifecycleAdmissionRegistryError> {
        let mut state = self.lock()?;
        require_initialized(&state)?;
        let mut updates = Vec::with_capacity(startup.quarantined_commands.len());
        for quarantined in &startup.quarantined_commands {
            let entry = &quarantined.entry;
            let Some(cell) = state.cells.get(&entry.cat_id) else {
                return Err(invalid_startup(
                    "provider quarantine has no cell from the sole journal enumeration",
                ));
            };
            let AdmissionCellSource::RecoveredJournal {
                closed_anchor_operation_id,
                request_fingerprint,
                ..
            } = &cell.source
            else {
                return Err(invalid_startup(
                    "provider quarantine refers to a newly manufactured admission cell",
                ));
            };
            if closed_anchor_operation_id != entry.record.operation_id()
                || request_fingerprint != entry.record.request_fingerprint()
            {
                return Err(invalid_startup(
                    "provider quarantine changed its journal command identity",
                ));
            }
            updates.push((entry.cat_id.clone(), quarantined.reason.clone()));
        }
        for (cat_id, reason) in updates {
            state.blocked.insert(cat_id, reason);
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, RegistryState>, LifecycleAdmissionRegistryError> {
        self.state
            .lock()
            .map_err(|_| LifecycleAdmissionRegistryError::Unavailable)
    }
}

fn require_initialized(state: &RegistryState) -> Result<(), LifecycleAdmissionRegistryError> {
    state
        .initialization
        .as_ref()
        .map(|_| ())
        .ok_or(LifecycleAdmissionRegistryError::Uninitialized)
}

fn build_fail_closed_cells(
    session: &SessionBinding,
    physical_inventory: &StartupPhysicalInventory,
    startup: &LifecycleJournalStartupInventory,
) -> Result<FailClosedStartupProjection, LifecycleAdmissionRegistryError> {
    let residue_cat_ids = physical_inventory.physical_cat_ids()?;

    let mut seen = BTreeSet::new();
    let mut cells = BTreeMap::new();
    let mut blocked = BTreeMap::new();
    for entry in &startup.recoverable {
        if entry.record.cat_id() != &entry.cat_id || !seen.insert(entry.cat_id.clone()) {
            return Err(invalid_startup(
                "recoverable journal Cat identity is mismatched or duplicated",
            ));
        }
        let closed_anchor_operation_id = entry.record.operation_id().clone();
        let request_fingerprint = entry.record.request_fingerprint().clone();
        let recoverable_running_terminal = recoverable_running_terminal(&entry.record)?;
        cells.insert(
            entry.cat_id.clone(),
            AdmissionCellEntry {
                cell: LifecycleRouteAdmissionCell::new_fail_closed(
                    entry.cat_id.clone(),
                    session.clone(),
                    closed_anchor_operation_id.clone(),
                ),
                source: AdmissionCellSource::RecoveredJournal {
                    closed_anchor_operation_id,
                    request_fingerprint,
                    recoverable_running_terminal,
                },
            },
        );
    }

    for quarantined in &startup.quarantined_commands {
        let entry = &quarantined.entry;
        if entry.record.cat_id() != &entry.cat_id || !seen.insert(entry.cat_id.clone()) {
            return Err(invalid_startup(
                "quarantined journal Cat identity is mismatched or duplicated",
            ));
        }
        let closed_anchor_operation_id = entry.record.operation_id().clone();
        cells.insert(
            entry.cat_id.clone(),
            AdmissionCellEntry {
                cell: LifecycleRouteAdmissionCell::new_fail_closed(
                    entry.cat_id.clone(),
                    session.clone(),
                    closed_anchor_operation_id.clone(),
                ),
                source: AdmissionCellSource::RecoveredJournal {
                    closed_anchor_operation_id,
                    request_fingerprint: entry.record.request_fingerprint().clone(),
                    recoverable_running_terminal: None,
                },
            },
        );
        blocked.insert(entry.cat_id.clone(), quarantined.reason.clone());
    }
    for entry in &startup.blocked {
        if !seen.insert(entry.cat_id.clone()) {
            return Err(invalid_startup(
                "startup Cat appears more than once across recoverable and blocked sets",
            ));
        }
        blocked.insert(entry.cat_id.clone(), entry.reason.clone());
    }
    let mut quarantined_terminals = BTreeSet::new();
    for entry in &startup.quarantined_terminals {
        if !seen.contains(&entry.cat_id)
            || blocked.contains_key(&entry.cat_id)
            || !quarantined_terminals.insert(entry.cat_id.clone())
        {
            return Err(invalid_startup(
                "quarantined terminal Cat is not one exact recoverable journal",
            ));
        }
    }
    if !residue_cat_ids.iter().all(|cat_id| seen.contains(cat_id)) {
        return Err(invalid_startup(
            "complete physical residue contains a Cat absent from journal recovery results",
        ));
    }
    Ok(FailClosedStartupProjection { cells, blocked })
}

fn recoverable_running_terminal(
    record: &crate::lifecycle_command::journal::LifecycleJournalRecord,
) -> Result<Option<RecoverableRunningTerminal>, LifecycleAdmissionRegistryError> {
    let crate::lifecycle_command::journal::LifecycleJournalRecord::Command {
        command,
        state: crate::lifecycle_command::journal::CommandJournalState::Terminal { result, .. },
        ..
    } = record
    else {
        return Ok(None);
    };
    let command = command.decode_api()?;
    let response = result.decode_api()?;
    validate_lifecycle_command_response_for_command(&response, &command).map_err(|_| {
        invalid_startup("terminal journal response does not match its exact command")
    })?;
    let (source_lifecycle_operation_id, runtime_incarnation) = match &response.result {
        NodeResult::RuntimeReady(ready) => (
            response.operation_id.clone(),
            ready.runtime_incarnation.clone(),
        ),
        NodeResult::SuspendDeclined(declined) => (
            declined
                .effective_runtime_ready
                .source_lifecycle_operation_id
                .clone(),
            declined.effective_runtime_ready.runtime_incarnation.clone(),
        ),
        _ => return Ok(None),
    };
    Ok(Some(RecoverableRunningTerminal {
        terminal_result_digest: result.result_digest().clone(),
        source_lifecycle_operation_id,
        runtime_incarnation,
    }))
}

fn invalid_startup(reason: impl Into<String>) -> LifecycleAdmissionRegistryError {
    LifecycleAdmissionRegistryError::InvalidStartupInventory {
        reason: reason.into(),
    }
}

fn state_directory_authority(
    state_directory: &StateDirectory,
) -> Result<StateDirectoryAuthority, LifecycleAdmissionRegistryError> {
    let directory =
        state_directory
            .try_clone_directory()
            .map_err(|source| LifecycleJournalError::Io {
                operation: "retain Node state directory for lifecycle admission initialization",
                path: state_directory.path().to_path_buf(),
                source,
            })?;
    let metadata = directory
        .metadata()
        .map_err(|source| LifecycleJournalError::Io {
            operation:
                "inspect retained Node state directory for lifecycle admission initialization",
            path: state_directory.path().to_path_buf(),
            source,
        })?;
    Ok(StateDirectoryAuthority {
        canonical_path: state_directory.path().to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
    })
}

#[cfg(test)]
fn test_state_directory_authority(path: &str) -> StateDirectoryAuthority {
    StateDirectoryAuthority {
        canonical_path: PathBuf::from(path),
        device: 1,
        inode: 1,
        owner: 1,
        mode: 0o40700,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_inventory::{
        ObservedArtifactClassification, ObservedCatRuntimeTelemetry, ObservedRuntimePhysicalState,
    };
    use cats_api::runtime_lifecycle::PlacementIdentity;
    use cats_api::runtime_reconciliation::{
        Epoch, Hostname, HttpProtocol, Ipv4Address, NodeBootId, RandomId128, RouteGateBinding,
        Sha256Digest, UnixMillis,
    };
    use tempfile::TempDir;

    use crate::admission::{EffectiveRuntimeReady, EnableRoute, RouteInterlockError};
    use crate::lifecycle_command::journal::{
        BlockedStartupCat, CommandJournalState, ExactBytes, ExpectedLifecyclePredecessor,
        JournalCommandProjection, LifecycleCommandKind, LifecycleJournalRecord,
        StartupJournalEntry,
    };

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: u8) -> RandomId128 {
        RandomId128::new(format!("{value:02x}").repeat(16)).unwrap()
    }

    fn state_directory(directory: &TempDir) -> StateDirectory {
        StateDirectory::unanchored(directory.path().to_path_buf())
    }

    fn session(epoch: u64) -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: NodeBootId::new("ab".repeat(16)).unwrap(),
            agent_instance_id: random(epoch as u8),
            agent_session_epoch: Epoch::new(epoch).unwrap(),
        }
    }

    fn ready(source: &str) -> EffectiveRuntimeReady {
        EffectiveRuntimeReady::new(
            id(source),
            random(20),
            Ipv4Address::new("10.0.0.2").unwrap(),
        )
    }

    fn startup_record(cat_id: &str, operation_id: &str) -> LifecycleJournalRecord {
        LifecycleJournalRecord::Command {
            version: 1,
            command: Box::new(JournalCommandProjection {
                cat_id: id(cat_id),
                operation_id: id(operation_id),
                request_fingerprint: Sha256Digest::from_bytes([3; 32]),
                command_kind: LifecycleCommandKind::Start,
                expected_predecessor: ExpectedLifecyclePredecessor::Genesis,
                canonical_request: ExactBytes::new(b"opaque-test-command".to_vec()),
            }),
            superseded_predecessor: None,
            state: CommandJournalState::Accepted { stop_fence: None },
        }
    }

    fn physical_inventory(cat_ids: impl IntoIterator<Item = Id>) -> StartupPhysicalInventory {
        let mut cats = cat_ids
            .into_iter()
            .map(|cat_id| ObservedCatRuntimeTelemetry {
                cat_id,
                observed_placement: PlacementIdentity {
                    node_id: id("node_a"),
                    placement_epoch: Epoch::new(1).unwrap(),
                },
                observed_command_journal: None,
                observed_physical_state: ObservedRuntimePhysicalState::StoppedRetained,
                observed_runtime_incarnation: None,
                observed_artifact_manifest_digest: Sha256Digest::from_bytes([9; 32]),
                observed_artifact_classifications: Vec::new(),
                observed_volumes: Vec::new(),
                observed_conditions: Vec::new(),
            })
            .collect::<Vec<_>>();
        cats.sort_by(|left, right| left.cat_id.as_str().cmp(right.cat_id.as_str()));
        StartupPhysicalInventory::Complete {
            scan_id: random(31),
            collected_at_unix_ms: UnixMillis::new(1).unwrap(),
            cats,
            unattributed_artifacts: Vec::new(),
        }
    }

    #[test]
    fn incomplete_inventory_cannot_construct_a_registry() {
        let directory = TempDir::new().unwrap();
        let state_directory = state_directory(&directory);
        let registry = LifecycleAdmissionRegistry::new_uninitialized();
        let error = registry
            .initialize_fail_closed_once(
                session(1),
                &state_directory,
                &StartupPhysicalInventory::Incomplete {
                    reason: "process/NBD/network namespace enumeration timed out".into(),
                },
            )
            .unwrap_err();

        assert!(matches!(
            error,
            LifecycleAdmissionRegistryError::Journal(
                LifecycleJournalError::IncompletePhysicalInventory { .. }
            )
        ));
        for cat_id in [id("cat_node_global_a"), id("cat_node_global_b")] {
            assert!(matches!(
                registry.lookup(&cat_id),
                Err(LifecycleAdmissionRegistryError::Uninitialized)
            ));
        }
    }

    #[test]
    fn unattributed_artifacts_quarantine_only_new_initial_targets() {
        let cat_id = id("cat_recovered");
        let mut inventory = physical_inventory([cat_id.clone()]);
        let StartupPhysicalInventory::Complete {
            unattributed_artifacts,
            ..
        } = &mut inventory
        else {
            unreachable!("test helper always returns a complete inventory")
        };
        unattributed_artifacts.push(
            ObservedArtifactClassification::QuarantinedForeignOrAmbiguous {
                artifact_id: id("foreign_artifact"),
                evidence_digest: Sha256Digest::from_bytes([0x55; 32]),
            },
        );

        // A recoverable journal remains observable and may continue its exact
        // terminal repost even though this Host cannot accept any
        // journal-missing Genesis/cross-Node/recovery target.
        let startup = LifecycleJournalStartupInventory {
            recoverable: vec![StartupJournalEntry {
                cat_id: cat_id.clone(),
                record: startup_record("cat_recovered", "start_recovered"),
                journal_digest: Sha256Digest::from_bytes([8; 32]),
            }],
            blocked: Vec::new(),
            quarantined_commands: Vec::new(),
            quarantined_terminals: Vec::new(),
        };
        let registry =
            LifecycleAdmissionRegistry::from_startup_inventory(session(1), &inventory, &startup)
                .unwrap();
        assert!(registry.lookup(&cat_id).unwrap().is_some());
        assert!(matches!(
            registry.ensure_initial_target_identity(
                id("cat_new"),
                id("start_new"),
                Sha256Digest::from_bytes([1; 32]),
                id("creation_new")
            ),
            Err(LifecycleAdmissionRegistryError::UnattributedPhysicalArtifacts)
        ));
    }

    #[test]
    fn physical_residue_without_journal_is_blocked_not_recreated() {
        let directory = TempDir::new().unwrap();
        let state_directory = state_directory(&directory);
        let cat_id = id("cat_residue");
        let registry = LifecycleAdmissionRegistry::new_uninitialized();
        let startup = registry
            .initialize_fail_closed_once(
                session(1),
                &state_directory,
                &physical_inventory([cat_id.clone()]),
            )
            .unwrap();

        assert_eq!(startup.blocked.len(), 1);
        assert!(matches!(
            registry.lookup(&cat_id),
            Err(LifecycleAdmissionRegistryError::CatBlocked { .. })
        ));
        assert!(matches!(
            registry.ensure_initial_target_identity(
                cat_id,
                id("start"),
                Sha256Digest::from_bytes([1; 32]),
                id("creation")
            ),
            Err(LifecycleAdmissionRegistryError::CatBlocked { .. })
        ));
    }

    #[test]
    fn uninitialized_lookup_and_genesis_fail_closed() {
        let registry = LifecycleAdmissionRegistry::new_uninitialized();
        assert!(matches!(
            registry.lookup(&id("cat_a")),
            Err(LifecycleAdmissionRegistryError::Uninitialized)
        ));
        assert!(matches!(
            registry.ensure_initial_target_identity(
                id("cat_a"),
                id("start_a"),
                Sha256Digest::from_bytes([1; 32]),
                id("creation_a")
            ),
            Err(LifecycleAdmissionRegistryError::Uninitialized)
        ));
        assert!(matches!(
            registry.replace_agent_session(&session(1), &session(2)),
            Err(LifecycleAdmissionRegistryError::Uninitialized)
        ));
    }

    #[test]
    fn exact_initialization_replays_but_different_identity_is_rejected() {
        let directory = TempDir::new().unwrap();
        let state_directory = state_directory(&directory);
        let registry = LifecycleAdmissionRegistry::new_uninitialized();
        let inventory = physical_inventory([]);
        let first = registry
            .initialize_fail_closed_once(session(1), &state_directory, &inventory)
            .unwrap();
        let replay = registry
            .initialize_fail_closed_once(session(1), &state_directory, &inventory)
            .unwrap();
        assert_eq!(first, replay);
        assert!(matches!(
            registry.initialize_fail_closed_once(session(2), &state_directory, &inventory),
            Err(LifecycleAdmissionRegistryError::InitializationConflict)
        ));
    }

    #[test]
    fn same_path_state_directory_replacement_is_not_an_exact_initialization_retry() {
        let parent = TempDir::new().unwrap();
        let state_path = parent.path().join("state");
        std::fs::create_dir(&state_path).unwrap();
        let state_directory = StateDirectory::unanchored(state_path.clone());
        let registry = LifecycleAdmissionRegistry::new_uninitialized();
        let inventory = physical_inventory([]);
        registry
            .initialize_fail_closed_once(session(1), &state_directory, &inventory)
            .unwrap();

        std::fs::rename(&state_path, parent.path().join("detached-state")).unwrap();
        std::fs::create_dir(&state_path).unwrap();
        assert!(matches!(
            registry.initialize_fail_closed_once(session(1), &state_directory, &inventory),
            Err(LifecycleAdmissionRegistryError::InitializationConflict)
        ));
    }

    #[test]
    fn recovered_journal_uses_current_operation_as_closed_anchor() {
        let cat_id = id("cat_a");
        let startup = LifecycleJournalStartupInventory {
            recoverable: vec![StartupJournalEntry {
                cat_id: cat_id.clone(),
                record: startup_record("cat_a", "operation_a"),
                journal_digest: Sha256Digest::from_bytes([8; 32]),
            }],
            blocked: Vec::new(),
            quarantined_commands: Vec::new(),
            quarantined_terminals: Vec::new(),
        };
        let registry = LifecycleAdmissionRegistry::from_startup_inventory(
            session(1),
            &physical_inventory([cat_id.clone()]),
            &startup,
        )
        .unwrap();
        let cell = registry.lookup(&cat_id).unwrap().unwrap();

        assert_eq!(cell.effective_runtime_ready().unwrap(), None);
        assert_eq!(
            cell.publish_runtime_ready(&id("wrong_operation"), ready("operation_a")),
            Err(RouteInterlockError::StaleRuntimeReadySuccessor)
        );
        assert!(cell
            .publish_runtime_ready(&id("operation_a"), ready("operation_a"))
            .unwrap());
    }

    #[test]
    fn restart_runtime_ready_requires_exact_session_anchor_and_terminal_digest() {
        let cat_id = id("cat_a");
        let anchor = id("start_a");
        let fingerprint = Sha256Digest::from_bytes([3; 32]);
        let terminal_digest = Sha256Digest::from_bytes([4; 32]);
        let runtime_ready = ready("start_a");
        let physical_inventory = physical_inventory([cat_id.clone()]);
        let startup = LifecycleJournalStartupInventory::default();
        let cell = LifecycleRouteAdmissionCell::new_fail_closed(
            cat_id.clone(),
            session(1),
            anchor.clone(),
        );
        let registry = LifecycleAdmissionRegistry {
            state: Mutex::new(RegistryState {
                initialization: Some(RegistryInitialization {
                    session: session(1),
                    state_directory: test_state_directory_authority("<test-state>"),
                    physical_inventory,
                    startup,
                }),
                current_session: Some(session(1)),
                unattributed_artifacts_present: false,
                cells: BTreeMap::from([(
                    cat_id.clone(),
                    AdmissionCellEntry {
                        cell: Arc::clone(&cell),
                        source: AdmissionCellSource::RecoveredJournal {
                            closed_anchor_operation_id: anchor.clone(),
                            request_fingerprint: fingerprint.clone(),
                            recoverable_running_terminal: Some(RecoverableRunningTerminal {
                                terminal_result_digest: terminal_digest.clone(),
                                source_lifecycle_operation_id: id("start_a"),
                                runtime_incarnation: runtime_ready.runtime_incarnation().clone(),
                            }),
                        },
                    },
                )]),
                blocked: BTreeMap::new(),
            }),
        };

        assert!(matches!(
            registry.recover_verified_runtime_ready(
                &session(2),
                &cat_id,
                &anchor,
                &fingerprint,
                &terminal_digest,
                runtime_ready.clone(),
            ),
            Err(LifecycleAdmissionRegistryError::StaleAgentSession)
        ));
        assert!(matches!(
            registry.recover_verified_runtime_ready(
                &session(1),
                &cat_id,
                &anchor,
                &fingerprint,
                &Sha256Digest::from_bytes([5; 32]),
                runtime_ready.clone(),
            ),
            Err(LifecycleAdmissionRegistryError::RuntimeReadyRecoveryAuthorityMismatch)
        ));
        assert_eq!(cell.effective_runtime_ready().unwrap(), None);

        assert!(registry
            .recover_verified_runtime_ready(
                &session(1),
                &cat_id,
                &anchor,
                &fingerprint,
                &terminal_digest,
                runtime_ready.clone(),
            )
            .unwrap());
        assert_eq!(cell.effective_runtime_ready().unwrap(), Some(runtime_ready));
        assert_eq!(cell.current_serving_route(&id("endpoint_a")).unwrap(), None);
    }

    #[test]
    fn mismatched_or_duplicate_startup_authority_is_rejected() {
        let startup = LifecycleJournalStartupInventory {
            recoverable: vec![StartupJournalEntry {
                cat_id: id("cat_a"),
                record: startup_record("cat_b", "operation_a"),
                journal_digest: Sha256Digest::from_bytes([8; 32]),
            }],
            blocked: vec![BlockedStartupCat {
                cat_id: id("cat_a"),
                reason: "duplicate".into(),
            }],
            quarantined_commands: Vec::new(),
            quarantined_terminals: Vec::new(),
        };

        assert!(matches!(
            LifecycleAdmissionRegistry::from_startup_inventory(
                session(1),
                &physical_inventory([id("cat_a")]),
                &startup,
            ),
            Err(LifecycleAdmissionRegistryError::InvalidStartupInventory { .. })
        ));
    }

    #[test]
    fn exact_genesis_retry_returns_the_same_cell_arc() {
        let registry = LifecycleAdmissionRegistry::from_startup_inventory(
            session(1),
            &physical_inventory([]),
            &LifecycleJournalStartupInventory::default(),
        )
        .unwrap();
        let cat_id = id("cat_a");
        let creation_id = id("creation_a");
        let fingerprint = Sha256Digest::from_bytes([1; 32]);
        let first = registry
            .ensure_initial_target_identity(
                cat_id.clone(),
                id("start_a"),
                fingerprint.clone(),
                creation_id.clone(),
            )
            .unwrap();
        let replay = registry
            .ensure_initial_target_identity(
                cat_id.clone(),
                id("start_a"),
                fingerprint.clone(),
                creation_id,
            )
            .unwrap();
        let lookup = registry.lookup(&cat_id).unwrap().unwrap();

        assert!(Arc::ptr_eq(&first, &replay));
        assert!(Arc::ptr_eq(&first, &lookup));
        assert!(matches!(
            registry.ensure_initial_target_identity(
                cat_id,
                id("start_a"),
                fingerprint,
                id("different_creation")
            ),
            Err(LifecycleAdmissionRegistryError::CellAuthorityConflict { .. })
        ));
    }

    #[test]
    fn session_replacement_closes_every_registered_route_and_preserves_arc() {
        let registry = LifecycleAdmissionRegistry::from_startup_inventory(
            session(1),
            &physical_inventory([]),
            &LifecycleJournalStartupInventory::default(),
        )
        .unwrap();
        let cat_id = id("cat_a");
        let creation_id = id("creation_a");
        let runtime_ready = ready("start_a");
        let cell = registry
            .ensure_initial_target_identity(
                cat_id.clone(),
                id("start_a"),
                Sha256Digest::from_bytes([1; 32]),
                creation_id.clone(),
            )
            .unwrap();
        cell.publish_runtime_ready(&creation_id, runtime_ready.clone())
            .unwrap();
        let binding = RouteGateBinding {
            workspace_id: id("workspace_a"),
            endpoint_id: id("endpoint_a"),
            cat_id: cat_id.clone(),
            node_id: id("node_a"),
            runtime_incarnation: runtime_ready.runtime_incarnation().clone(),
            hostname: Hostname::new("a.example.test").unwrap(),
            route_epoch: Epoch::new(7).unwrap(),
            protocol: HttpProtocol::Http,
            target_port: 8080,
        };
        cell.enable_route(&EnableRoute::new(
            id("route_enable_a"),
            id("start_a"),
            session(1),
            binding.clone(),
        ))
        .unwrap();

        let outcomes = registry
            .replace_agent_session(&session(1), &session(2))
            .unwrap();

        assert!(matches!(
            outcomes.get(&cat_id),
            Some(AgentSessionReplacementOutcome::Replaced {
                closed_route_epochs
            }) if closed_route_epochs.len() == 1
        ));
        assert_eq!(cell.current_serving_route(&id("endpoint_a")).unwrap(), None);
        assert!(Arc::ptr_eq(
            &cell,
            &registry.lookup(&cat_id).unwrap().unwrap()
        ));
        assert_eq!(registry.current_agent_session().unwrap(), session(2));
        assert_eq!(
            cell.enable_route(&EnableRoute::new(
                id("route_enable_stale"),
                id("start_a"),
                session(1),
                binding,
            )),
            Err(RouteInterlockError::StaleAgentSession)
        );
    }
}
