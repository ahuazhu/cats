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

mod admission_cell;
mod admission_port;
mod authorized_blockd;
mod checkpoint;
mod clean_slate_probes;
mod gate_planner;
mod inventory;
// Kernel NBD is the default ADR-0015 frontend and is a Host-global resource.
// Its reservation permit is consumed by the production PrepareDevice CAS;
// the sealed attach/listener/cleanup foundation intentionally lands before
// the follow-up inventory and dispatcher composition. Keep the exception on
// this one private provider module so that composition can remove it whole.
#[expect(
    dead_code,
    reason = "sealed kernel-NBD attach provider is staged before production composition"
)]
mod kernel_nbd;
mod normal_acquire;
mod prepare_device_retirement;
mod root_provision;
// The sealed serving-process foundation is composed with the Node-global
// managed-process admission port in the following integration slice.  Its
// fake port already exercises the complete one-effect start/adopt contract.
#[expect(
    dead_code,
    reason = "sealed serving-process foundation awaits Node-global production admission"
)]
mod serving_blockd_process;
mod serving_handoff;
mod serving_handoff_effect;
mod signed_root_provision;
mod signed_running;
// This focused foundation intentionally lands before the production systemd
// adapter and signed launch orchestrator that consume it. Keep the exception
// on this one private module; the follow-up composition removes it.
#[expect(
    dead_code,
    reason = "sealed root-provision process port is staged before production composition"
)]
mod root_provision_process;
#[expect(
    dead_code,
    reason = "systemd root-provision adapter is staged before signed launch composition"
)]
mod systemd_root_provision;
mod volume_transitions;

pub(crate) mod inventory_probe_sealed {
    pub trait Sealed {}
}

pub use admission_cell::{
    AdmissionCell, AdmissionCellBuildError, AdmissionCellPort, AdmissionGuardCounts,
    PlatformAdmissionError, PlatformAdmissionGuard, RouteAdmissionGuard,
};
pub use admission_port::{
    AdmissionGatePort, AdmissionSnapshot, GatePortError, IdleCloseResult, SnapshotError,
};
pub use authorized_blockd::{
    authorized_blockd_command, authorized_blockd_status_is_bound, AuthorizedBlockFrontend,
    AuthorizedBlockdCheckpoint, AuthorizedBlockdLaunchConfig, AuthorizedBlockdStore,
    PreparedAuthorizedBlockd,
};
pub use checkpoint::{
    runtime_checkpoint_path, CheckpointStoreError, FileCheckpointStore, StoredCheckpoint,
};
#[cfg(test)]
pub(crate) use clean_slate_probes::{
    clean_slate_scanner_for_test, clean_slate_scanner_with_volume_authority_and_blob_for_test,
    clean_slate_scanner_with_volume_authority_for_test, TestCleanSlateProbeConfig,
};
pub(crate) use clean_slate_probes::{
    installed_clean_slate_scanner, installed_root_process_effect_ports,
    InstalledCleanSlateProbeConfig,
};
pub use gate_planner::{
    applied_desired_evidence, AppliedDesiredError, GateReconcileError, GateSequencer,
    GateTransitionResult, PersistTimes,
};
pub use inventory::{
    CleanSlateInventoryScanner, InventoryAbsence, InventoryAbsenceProbe, InventoryProbeSetError,
};
pub use normal_acquire::{
    recover_normal_acquire_from_authority, recover_normal_release_from_authority,
    A19SignedVolumeTransitionTransport, ControlSignedNormalAcquireClient,
    NormalAcquireAcceptedContext, NormalAcquireAttempt, NormalAcquireAuthorityRecovery,
    NormalAcquireClientError, NormalReleaseAttempt, NormalReleaseAuthorityRecovery,
    RuntimeVolumeTransitionHttpClient, SignedVolumeTransitionResponse,
    VolumeTransitionTransportFailure,
};
pub(crate) use root_provision::PlatformRootProvisionProcessIdentityPort;
pub use root_provision::{
    AuthorityRereadRequired, RootProvisionClientError, RootProvisionControlPort,
    RootProvisionResponseHint, RootProvisionUnknownReason, UnixRootProvisionClient,
};
pub(crate) use serving_handoff_effect::ServingPrepareFrontend;
pub(crate) use signed_root_provision::{SignedRunningEffect, SignedRunningProcessPorts};
pub(crate) use signed_running::{SignedRunningAcquireEffect, SignedRunningPublicationRecovery};
// This crate-private seam is landed before the systemd composition that
// consumes it; keeping the re-export here prevents feature code from reaching
// through the module path while preserving the sealed boundary.
#[allow(unused_imports)]
pub(crate) use root_provision_process::{
    ensure_root_provision_process_after_checkpoint,
    ensure_root_provision_process_from_persisted_checkpoint, NodeGlobalManagedProcessAdmission,
    NodeGlobalManagedProcessScanAdmission, RootProvisionAuthoritySnapshot,
    RootProvisionBlockdHandshake, RootProvisionProcessConflict, RootProvisionProcessEnsureResult,
    RootProvisionProcessEvidence, RootProvisionProcessExpectation, RootProvisionProcessGlobalPort,
    RootProvisionProcessInspection, RootProvisionProcessOutcome, RootProvisionProcessPort,
    RootProvisionProcessRetirementPort, RootProvisionProcessStart, RootProvisionProcessStop,
    TargetControlProcessLaunchIdentity, TargetControlProcessPort,
};
#[allow(unused_imports)]
pub(crate) use systemd_root_provision::{
    PlatformSystemdRootProvisionProcessPort, PlatformSystemdServingBlockdProcessPort,
    RootProvisionSystemdConfig,
};
pub use volume_transitions::{
    A19SignedVolumeEvidenceTransport, ControlSignedVolumeEvidenceClient,
    SignedVolumeEvidenceResponse, VolumeEvidenceClientError, VolumeEvidenceRecovery,
    VolumeEvidenceRecoveryDecision, VolumeEvidenceTransportFailure, VolumeTransitionEvidencePort,
};

#[cfg(test)]
mod tests;
