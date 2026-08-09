//! Checkpoint-first admission-gate convergence for Runtime Reconciliation v1.
//!
//! This is deliberately only the local gate spine. It persists the shared
//! [`cats_api::runtime_reconciliation::RuntimeCheckpoint`] before asking the
//! in-memory admission boundary to change, and persists the resulting state
//! afterwards. Volume, VMM, device, network, mount, cleanup, inventory, and
//! production server wiring remain outside this module.
//!
//! In particular, this spine does not manufacture an "Endpoint-only" proof:
//! the complete reconciler must first compare the new Desired with its
//! physical/runtime/volume/network inventory. Only a revision whose non-route
//! facts are unchanged may enter `GateSequencer::close_gate`; every other
//! revision uses the global close path. The checkpoint intentionally does not
//! duplicate enough Desired fields to make that classification here.

mod admission_port;
mod checkpoint;
mod gate_planner;
mod inventory;
mod root_provision;

pub(crate) mod inventory_probe_sealed {
    pub trait Sealed {}
}

pub use admission_port::{
    AdmissionGatePort, AdmissionSnapshot, GatePortError, IdleCloseResult, SnapshotError,
};
pub use checkpoint::{
    runtime_checkpoint_path, CheckpointStoreError, FileCheckpointStore, StoredCheckpoint,
};
pub use gate_planner::{
    applied_desired_evidence, AppliedDesiredError, GateReconcileError, GateSequencer,
    GateTransitionResult, PersistTimes,
};
pub(crate) use inventory::unavailable_clean_slate_scanner;
pub use inventory::{
    CleanSlateInventoryScanner, InventoryAbsence, InventoryAbsenceProbe, InventoryProbeSetError,
};
pub use root_provision::{
    AuthorityRereadRequired, RootProvisionClientError, RootProvisionControlPort,
    RootProvisionResponseHint, RootProvisionUnknownReason, UnixRootProvisionClient,
};

#[cfg(test)]
mod tests;
