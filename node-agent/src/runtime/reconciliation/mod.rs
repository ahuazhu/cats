//! Checkpoint-first admission-gate convergence for Runtime Reconciliation v1.
//!
//! This is deliberately only the local gate spine. It persists the shared
//! [`cats_api::runtime_reconciliation::RuntimeCheckpoint`] before asking the
//! in-memory admission boundary to change, and persists the resulting state
//! afterwards. Volume, VMM, device, network, mount, cleanup, inventory, and
//! production server wiring remain outside this module.

mod admission_port;
mod checkpoint;
mod gate_planner;

pub use admission_port::{
    AdmissionGatePort, AdmissionSnapshot, GatePortError, IdleCloseResult, SnapshotError,
};
pub use checkpoint::{CheckpointStoreError, FileCheckpointStore, StoredCheckpoint};
pub use gate_planner::{
    applied_desired_evidence, AppliedDesiredError, GateReconcileError, GateSequencer,
    GateTransitionResult, PersistTimes,
};

#[cfg(test)]
mod tests;
