//! Process-owned per-Cat admission cells.
//!
//! The registry is the production ownership boundary shared by reconciliation
//! and future Route v2 transport composition. It retains the per-Cat
//! checkpoint store with the cell so process-local Endpoint effect edges live
//! across fresh-inventory iterations. A successor process constructs a new,
//! empty registry and every cell is initialized from a fail-closed snapshot;
//! neither a stable checkpoint nor an Active route reconstructs admission.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use cats_api::runtime_reconciliation::{DesiredRuntimeSpec, Id, RuntimeTarget};
use thiserror::Error;

use crate::state_directory::StateDirectory;

use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::{
    AdmissionCell, AdmissionCellBuildError, AdmissionSnapshot, CheckpointStoreError,
    FileCheckpointStore,
};

#[derive(Debug, Error)]
pub(crate) enum AdmissionRegistryError {
    #[error("the admission registry is unavailable")]
    Unavailable,
    #[error("the admission registry is already initializing Cat {cat_id}")]
    Initializing { cat_id: Id },
    #[error("the admission registry generation counter is exhausted")]
    GenerationExhausted,
    #[error("the admission registry entry changed during replacement")]
    EntryChanged,
    #[error(transparent)]
    Checkpoint(#[from] CheckpointStoreError),
    #[error(transparent)]
    Cell(#[from] AdmissionCellBuildError),
}

pub(crate) struct AdmissionCellSession {
    generation: u64,
    cell: Arc<AdmissionCell>,
    checkpoint_store: Arc<FileCheckpointStore>,
    sealed_running_desired: Mutex<Option<DesiredRuntimeSpec>>,
}

pub(crate) enum AdmissionCellSessionLookup {
    CreatedClosed(Arc<AdmissionCellSession>),
    Existing,
}

impl AdmissionCellSession {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn cell(&self) -> &Arc<AdmissionCell> {
        &self.cell
    }

    pub(crate) fn checkpoint_store(&self) -> &FileCheckpointStore {
        self.checkpoint_store.as_ref()
    }

    pub(crate) fn sealed_running_desired(&self) -> Option<DesiredRuntimeSpec> {
        match self.sealed_running_desired.lock() {
            Ok(desired) => desired.clone(),
            Err(_) => {
                self.close();
                None
            }
        }
    }

    pub(crate) fn advance_sealed_running_desired(
        &self,
        desired: DesiredRuntimeSpec,
    ) -> Result<(), AdmissionRegistryError> {
        let mut sealed = self
            .sealed_running_desired
            .lock()
            .map_err(|_| AdmissionRegistryError::Unavailable)?;
        let Some(current) = sealed.as_ref() else {
            self.close();
            return Err(AdmissionRegistryError::EntryChanged);
        };
        if current != &desired
            && !super::route_retirement::endpoint_only_successor(current, &desired)
        {
            self.close();
            return Err(AdmissionRegistryError::EntryChanged);
        }
        *sealed = Some(desired);
        Ok(())
    }

    fn close(&self) {
        self.cell.force_close();
    }
}

enum RegistrySlot {
    Initializing { generation: u64 },
    Ready(Arc<AdmissionCellSession>),
}

struct RegistryState {
    next_generation: u64,
    entries: BTreeMap<Id, RegistrySlot>,
}

/// One Node process's complete set of live admission cells.
///
/// Registry locking never covers checkpoint I/O or an AdmissionCell
/// operation. A not-yet-published slot is unavailable to route lookup and a
/// failed initializer removes only its own generation.
pub(crate) struct AdmissionCellRegistry {
    checkpoint_directory: PathBuf,
    state: Mutex<RegistryState>,
}

impl AdmissionCellRegistry {
    pub(crate) fn for_state_directory(state_directory: &StateDirectory) -> Arc<Self> {
        Self::new(state_directory.path().join(CHECKPOINT_NAMESPACE))
    }

    pub(crate) fn new(checkpoint_directory: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            checkpoint_directory,
            state: Mutex::new(RegistryState {
                next_generation: 1,
                entries: BTreeMap::new(),
            }),
        })
    }

    pub(crate) fn get(&self, cat_id: &Id) -> Option<Arc<AdmissionCell>> {
        let state = self.lock_observing().ok()?;
        match state.entries.get(cat_id) {
            Some(RegistrySlot::Ready(session)) => Some(Arc::clone(session.cell())),
            Some(RegistrySlot::Initializing { .. }) | None => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn insert_cell_for_machine_test(
        &self,
        cat_id: Id,
        cell: Arc<AdmissionCell>,
    ) -> Result<(), AdmissionRegistryError> {
        let checkpoint_store = Arc::new(FileCheckpointStore::open(
            &self.checkpoint_directory,
            &cat_id,
        )?);
        let mut state = self.lock_mutating()?;
        if state.entries.contains_key(&cat_id) {
            return Err(AdmissionRegistryError::EntryChanged);
        }
        let generation = take_generation(&mut state)?;
        state.entries.insert(
            cat_id,
            RegistrySlot::Ready(Arc::new(AdmissionCellSession {
                generation,
                cell,
                checkpoint_store,
                sealed_running_desired: Mutex::new(None),
            })),
        );
        Ok(())
    }

    pub(crate) fn existing_session(
        &self,
        cat_id: &Id,
    ) -> Result<Option<Arc<AdmissionCellSession>>, AdmissionRegistryError> {
        let state = self.lock_observing()?;
        match state.entries.get(cat_id) {
            Some(RegistrySlot::Ready(session)) => Ok(Some(Arc::clone(session))),
            Some(RegistrySlot::Initializing { .. }) => Err(AdmissionRegistryError::Initializing {
                cat_id: cat_id.clone(),
            }),
            None => Ok(None),
        }
    }

    pub(crate) fn ensure_closed(
        &self,
        cat_id: &Id,
        checkpoint_snapshot: AdmissionSnapshot,
        sealed_running_desired: Option<DesiredRuntimeSpec>,
    ) -> Result<AdmissionCellSessionLookup, AdmissionRegistryError> {
        if sealed_running_desired.as_ref().is_some_and(|desired| {
            desired.target != RuntimeTarget::Running || &desired.cat_id != cat_id
        }) {
            return Err(AdmissionRegistryError::EntryChanged);
        }
        let generation = {
            let mut state = self.lock_mutating()?;
            match state.entries.get(cat_id) {
                Some(RegistrySlot::Ready(_)) => {
                    return Ok(AdmissionCellSessionLookup::Existing);
                }
                Some(RegistrySlot::Initializing { .. }) => {
                    return Err(AdmissionRegistryError::Initializing {
                        cat_id: cat_id.clone(),
                    })
                }
                None => {}
            }
            let generation = take_generation(&mut state)?;
            state
                .entries
                .insert(cat_id.clone(), RegistrySlot::Initializing { generation });
            generation
        };

        let initialized = self.initialize_closed(
            cat_id,
            generation,
            checkpoint_snapshot,
            sealed_running_desired,
        );
        match initialized {
            Ok(session) => {
                let session = Arc::new(session);
                let mut state = self.lock_mutating()?;
                match state.entries.get(cat_id) {
                    Some(RegistrySlot::Initializing {
                        generation: current,
                    }) if *current == generation => {
                        state
                            .entries
                            .insert(cat_id.clone(), RegistrySlot::Ready(Arc::clone(&session)));
                        Ok(AdmissionCellSessionLookup::CreatedClosed(session))
                    }
                    Some(RegistrySlot::Initializing { .. })
                    | Some(RegistrySlot::Ready(_))
                    | None => {
                        session.close();
                        Err(AdmissionRegistryError::EntryChanged)
                    }
                }
            }
            Err(error) => {
                if let Ok(mut state) = self.lock_mutating() {
                    if matches!(
                        state.entries.get(cat_id),
                        Some(RegistrySlot::Initializing {
                            generation: current,
                        }) if *current == generation
                    ) {
                        state.entries.remove(cat_id);
                    }
                }
                Err(error)
            }
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "lifecycle replacement consumes exact compare-replace in the next composition slice"
        )
    )]
    pub(crate) fn replace_closed(
        &self,
        cat_id: &Id,
        expected: &Arc<AdmissionCellSession>,
        checkpoint_snapshot: AdmissionSnapshot,
    ) -> Result<Arc<AdmissionCellSession>, AdmissionRegistryError> {
        let replacement_cell = AdmissionCell::new(checkpoint_snapshot.fail_closed())?;
        // Close first. If another registry operation wins the following CAS,
        // only this stale cell was affected and the replacement stays intact.
        expected.close();
        let mut state = self.lock_mutating()?;
        let Some(RegistrySlot::Ready(current)) = state.entries.get(cat_id) else {
            return Err(AdmissionRegistryError::EntryChanged);
        };
        if !Arc::ptr_eq(current, expected) {
            return Err(AdmissionRegistryError::EntryChanged);
        }
        let generation = take_generation(&mut state)?;
        let replacement = Arc::new(AdmissionCellSession {
            generation,
            cell: replacement_cell,
            checkpoint_store: Arc::clone(&expected.checkpoint_store),
            sealed_running_desired: Mutex::new(expected.sealed_running_desired()),
        });
        state.entries.insert(
            cat_id.clone(),
            RegistrySlot::Ready(Arc::clone(&replacement)),
        );
        Ok(replacement)
    }

    pub(crate) fn remove(
        &self,
        cat_id: &Id,
        expected: &Arc<AdmissionCellSession>,
    ) -> Result<bool, AdmissionRegistryError> {
        expected.close();
        let mut state = self.lock_mutating()?;
        let Some(RegistrySlot::Ready(current)) = state.entries.get(cat_id) else {
            return Ok(false);
        };
        if !Arc::ptr_eq(current, expected) {
            return Ok(false);
        }
        state.entries.remove(cat_id);
        Ok(true)
    }

    fn initialize_closed(
        &self,
        cat_id: &Id,
        generation: u64,
        checkpoint_snapshot: AdmissionSnapshot,
        sealed_running_desired: Option<DesiredRuntimeSpec>,
    ) -> Result<AdmissionCellSession, AdmissionRegistryError> {
        let checkpoint_store = FileCheckpointStore::open(&self.checkpoint_directory, cat_id)?;
        let cell = AdmissionCell::new(checkpoint_snapshot.fail_closed())?;
        Ok(AdmissionCellSession {
            generation,
            cell,
            checkpoint_store: Arc::new(checkpoint_store),
            sealed_running_desired: Mutex::new(sealed_running_desired),
        })
    }

    fn lock_mutating(&self) -> Result<MutexGuard<'_, RegistryState>, AdmissionRegistryError> {
        self.state
            .lock()
            .map_err(|_| AdmissionRegistryError::Unavailable)
    }

    fn lock_observing(&self) -> Result<MutexGuard<'_, RegistryState>, AdmissionRegistryError> {
        match self.state.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                close_slots(state.entries.values());
                state.entries.clear();
                Err(AdmissionRegistryError::Unavailable)
            }
        }
    }

    pub(crate) fn ready_sessions(
        &self,
    ) -> Result<Vec<(Id, Arc<AdmissionCellSession>)>, AdmissionRegistryError> {
        let state = self.lock_observing()?;
        Ok(state
            .entries
            .iter()
            .filter_map(|(cat_id, slot)| match slot {
                RegistrySlot::Ready(session) => Some((cat_id.clone(), Arc::clone(session))),
                RegistrySlot::Initializing { .. } => None,
            })
            .collect())
    }

    pub(crate) fn fail_close_all(&self) {
        if let Ok(sessions) = self.ready_sessions() {
            for (_, session) in sessions {
                session.close();
            }
        }
        // `ready_sessions` uses the observing poison path, which itself
        // closes and clears every reachable Ready slot before returning Err.
    }
}

fn take_generation(state: &mut RegistryState) -> Result<u64, AdmissionRegistryError> {
    let generation = state.next_generation;
    state.next_generation = state
        .next_generation
        .checked_add(1)
        .ok_or(AdmissionRegistryError::GenerationExhausted)?;
    Ok(generation)
}

impl Drop for AdmissionCellRegistry {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        close_slots(state.entries.values());
        state.entries.clear();
    }
}

fn close_slots<'a>(slots: impl Iterator<Item = &'a RegistrySlot>) {
    for slot in slots {
        if let RegistrySlot::Ready(session) = slot {
            session.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        decode_runtime_checkpoint, LifecycleAdmission, RouteGateState,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::runtime::reconciliation::AdmissionGatePort;

    const START_RUNTIME: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
    ));

    fn fixture() -> (TempDir, Id, AdmissionSnapshot) {
        let root = TempDir::new().expect("tempdir");
        let checkpoint = decode_runtime_checkpoint(START_RUNTIME).expect("StartRuntime checkpoint");
        let cat_id = checkpoint.cat_id.clone();
        let closed = AdmissionSnapshot::from_checkpoint(&checkpoint).expect("snapshot");
        let snapshot = AdmissionSnapshot::new(
            closed.applied_desired_revision(),
            closed.spec_digest().clone(),
            closed.placement().clone(),
            closed.runtime_incarnation().cloned(),
            LifecycleAdmission::Open,
            Vec::new(),
        );
        (root, cat_id, snapshot)
    }

    #[test]
    fn create_replace_remove_are_fail_closed_and_compare_owned() {
        let (root, cat_id, snapshot) = fixture();
        let registry = AdmissionCellRegistry::new(root.path().to_path_buf());
        let first = registry
            .ensure_closed(&cat_id, snapshot.clone(), None)
            .expect("create session");
        let AdmissionCellSessionLookup::CreatedClosed(first) = first else {
            panic!("first lookup must create the cell")
        };
        assert_eq!(
            first.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        assert!(first
            .cell()
            .snapshot()
            .endpoints()
            .iter()
            .all(|route| route.gate == RouteGateState::Closed));
        assert!(Arc::ptr_eq(
            registry.get(&cat_id).as_ref().expect("registered cell"),
            first.cell()
        ));

        let replacement = registry
            .replace_closed(&cat_id, &first, snapshot)
            .expect("replace session");
        assert!(!Arc::ptr_eq(first.cell(), replacement.cell()));
        assert_eq!(
            first.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        assert!(!registry
            .remove(&cat_id, &first)
            .expect("stale remove is harmless"));
        assert!(registry
            .remove(&cat_id, &replacement)
            .expect("remove exact replacement"));
        assert!(registry.get(&cat_id).is_none());
    }

    #[test]
    fn a_new_process_registry_never_reconstructs_open_from_disk() {
        let (root, cat_id, snapshot) = fixture();
        let first_process = AdmissionCellRegistry::new(root.path().to_path_buf());
        let first = first_process
            .ensure_closed(&cat_id, snapshot.clone(), None)
            .expect("first process session");
        let AdmissionCellSessionLookup::CreatedClosed(first) = first else {
            panic!("first process must create the cell")
        };
        let mut port = first.cell().port();
        let closed = port.snapshot();
        let open = AdmissionSnapshot::new(
            closed.applied_desired_revision(),
            closed.spec_digest().clone(),
            closed.placement().clone(),
            closed.runtime_incarnation().cloned(),
            LifecycleAdmission::Open,
            Vec::new(),
        );
        port.open_lifecycle(&closed, &open)
            .expect("open first process cell");
        drop(port);
        let retained_cell = Arc::clone(first.cell());
        drop(first);
        drop(first_process);
        assert_eq!(
            retained_cell.snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
        drop(retained_cell);

        let second_process = AdmissionCellRegistry::new(root.path().to_path_buf());
        let second = second_process
            .ensure_closed(&cat_id, snapshot, None)
            .expect("successor process session");
        let AdmissionCellSessionLookup::CreatedClosed(second) = second else {
            panic!("successor process must create its own cell")
        };
        assert_eq!(
            second.cell().snapshot().lifecycle_admission(),
            LifecycleAdmission::Closed
        );
    }
}
