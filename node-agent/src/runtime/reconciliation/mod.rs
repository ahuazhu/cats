//! Checkpoint-first admission-gate convergence for Runtime Reconciliation v1.
//!
//! The local gate spine persists the shared
//! [`cats_api::runtime_reconciliation::RuntimeCheckpoint`] before asking the
//! in-memory admission boundary to change, and persists the resulting state
//! afterwards. Its process-owned cells and sealed tail effect are composed in
//! the production dispatcher. Physical VMM/Guest proof and the Route v2
//! Gateway-to-Node machine transport remain separate prerequisites.
//!
//! In particular, this spine does not manufacture an "Endpoint-only" proof:
//! the complete reconciler must first compare the new Desired with its
//! physical/runtime/volume/network inventory. Only a revision whose non-route
//! facts are unchanged may enter `GateSequencer::close_gate`; every other
//! revision uses the global close path. The checkpoint intentionally does not
//! duplicate enough Desired fields to make that classification here.

mod admission_cell;
mod admission_port;
mod admission_registry;
mod authorized_blockd;
mod checkpoint;
mod clean_slate_probes;
mod gate_planner;
mod inventory;
// Kernel NBD is the default ADR-0015 frontend and is a Host-global resource.
// Keep its provider-private scan, attach and cleanup capabilities behind this
// module; production composition receives only the sealed admissions below.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "installed kernel-NBD reservation and attach compile only on Linux"
    )
)]
mod kernel_nbd;
mod network;
mod normal_acquire;
mod prepare_device_retirement;
mod root_provision;
mod running_admission;
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
// StartRuntime consumes one descriptor-retained projection of the installed
// launcher, VMM and Guest boot bytes.  The physical VMM effect lands in the
// following composition slice; keep this provider private until then.
#[expect(
    dead_code,
    reason = "fixed VMM launch artifacts are staged before StartRuntime composition"
)]
mod vmm_launch_artifacts;
// The live VMM must still own the exact checkpoint, RAM/log leaves and Unix
// socket pathnames recorded by StartRuntime. Keep the descriptor-retained
// path set private until the process inspector below composes all of it.
#[expect(
    dead_code,
    reason = "retained VMM runtime paths are staged before exact process composition"
)]
mod vmm_runtime_paths;
mod vmm_start_runtime;
mod vmm_start_runtime_effect;
// A StartRuntime attempt must own its API/vsock namespace before the fixed
// launcher or PID 1 can create anything.  This provider-private WAL and
// descriptor-rooted namespace land before the production effect consumes it.
#[expect(
    dead_code,
    reason = "managed VMM socket ownership awaits StartRuntime effect composition"
)]
mod vmm_socket_namespace;
// Cloud Hypervisor v53 exposes its live shape through a local HTTP API.  This
// provider-private adapter freezes the exact wire schema, socket ownership,
// SO_PEERCRED and deadline bounds before the process scanner composes it into
// an adoption proof.
#[expect(
    dead_code,
    reason = "bounded VMM API proof is staged before VMM process composition"
)]
mod vmm_api_inspection;
// This sealed process boundary is staged immediately before the full VMM
// inventory/adopt composition.  It already consumes the exact checkpoint and
// pinned artifact descriptors; only that follow-up may mint an accepted-full
// launch permit.
#[expect(
    dead_code,
    reason = "checkpointed VMM systemd port awaits full-inventory composition"
)]
mod vmm_process;
// Guest CID reservation is checkpoint-first and provider-private. The
// checkpoint-only StartRuntime effect consumes it; physical launch remains a
// later fresh-inventory effect.
mod vmm_cid;
mod volume_transitions;

pub(crate) mod inventory_probe_sealed {
    pub trait Sealed {}
}

pub(crate) use admission_cell::AdmissionCellObservation;
pub use admission_cell::{
    AdmissionCell, AdmissionCellBuildError, AdmissionCellPort, AdmissionGuardCounts,
    PlatformAdmissionError, PlatformAdmissionGuard, RouteAdmissionGuard,
};
pub use admission_port::{
    AdmissionGatePort, AdmissionSnapshot, GatePortError, IdleCloseResult, SnapshotError,
};
pub(crate) use admission_registry::{
    AdmissionCellRegistry, AdmissionCellSession, AdmissionCellSessionLookup,
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
pub(crate) use kernel_nbd::{
    KernelNbdClientCleanupOwner, KernelNbdInventoryConfig, KernelNbdPoolAdmission,
    KernelNbdPoolScanAdmission,
};
pub(crate) use network::{NodeGlobalNetworkAdmission, NodeGlobalNetworkScanAdmission};
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
pub(crate) use running_admission::{
    RunningAdmissionEffect, RunningTailAdmission, RunningTailScanAdmission,
};
pub(crate) use serving_handoff_effect::ServingPrepareFrontend;
pub(crate) use signed_root_provision::{
    SignedRunningEffect, SignedRunningHostConfig, SignedRunningProcessPorts,
};
pub(crate) use signed_running::{SignedRunningAcquireEffect, SignedRunningPublicationRecovery};
#[cfg(test)]
pub(crate) use vmm_cid::PlatformExactVmmCidInventoryPort;
pub(crate) use vmm_cid::{VmmCidAllocationPort, VmmCidInventoryPort};
pub(crate) use vmm_launch_artifacts::VmmLaunchArtifactPaths;
#[allow(unused_imports)]
pub(crate) use vmm_runtime_paths::ManagedVmmLaunchFilePaths;
#[cfg(target_os = "linux")]
pub(crate) use vmm_socket_namespace::ManagedVmmSocketPreparation;
#[allow(unused_imports)]
pub(crate) use vmm_socket_namespace::{
    vmm_state_directory_from_checkpoint, ManagedVmmSocketPaths, ManagedVmmSocketRoot,
    RetainedManagedVmmSocketRoot, VmmSocketReceiptStore, INSTALLED_VMM_SOCKET_ROOT,
};
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
