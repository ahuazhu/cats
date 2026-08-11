//! Exact retained launch authority shared by the Running scanner and gate tail.
//!
//! A live VMM is only one member of the Running authority tuple.  This module
//! closes the retained launch over every prepared Volume, its immutable
//! AuthorizedBlockd lineage, the exact serving process/listener and frontend,
//! the Host network, and the exact VMM.  Public inventory projections never
//! enter either proof path.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    DesiredRuntimeSpec, Id, PrepareDeviceFrontend, RequireIdleCheckpoint, RuntimeCheckpoint,
    RuntimeNetworkIdentity, RuntimeTarget, RuntimeTransition,
};
use cats_storage::authority::{VolumeDataAuthority, VolumeRecord};

use crate::runtime_spine::RuntimeDesiredEffectContext;
use crate::state_directory::StateDirectory;

use super::authorized_blockd::{
    validate_running_endpoint_only_desired_successor, validate_running_physical_desired_successor,
};
use super::checkpoint::{CurrentCheckpointGuard, FileCheckpointStore, StoredCheckpoint};
use super::inventory::AuthorityVolumeInventoryEvidence;
use super::kernel_nbd::{
    ExactKernelNbdDeviceProof, KernelNbdInventoryConfig, KernelNbdInventoryPort,
    KernelNbdPoolAdmission, KernelNbdPoolScanAdmission,
};
use super::network::{
    prepared_device_inputs, prepared_device_set_is_exact, NodeGlobalNetworkAdmission,
    NodeGlobalNetworkScanAdmission, PrepareNetworkReservationEffect,
};
use super::prepare_device_retirement::{
    prepared_device_input_is_exact, retirement_authority_lease_is_monotonic,
};
use super::retained_runtime_launch::RetainedRuntimeLaunchAuthority;
use super::root_provision_process::{
    NodeGlobalManagedProcessAdmission, NodeGlobalManagedProcessScanAdmission,
};
use super::serving_blockd_process::{
    ExactServingBlockdProcessProof, RetainedServingBlockdAuthority, ServingBlockdExpectation,
    ServingBlockdProcessGlobalPort, ServingBlockdProcessInspection,
};
use super::systemd_root_provision::RootProvisionSystemdConfig;
use super::vmm_process::{
    ExactVmmProcessProof, VmmGateSuccessorProof, VmmProcessExpectation, VmmProcessGlobalInspection,
    VmmProcessGlobalPort,
};

enum ProcessProofSet<'a> {
    Scan(&'a NodeGlobalManagedProcessScanAdmission),
    Accepted(&'a NodeGlobalManagedProcessAdmission),
}

impl<'a> ProcessProofSet<'a> {
    fn exact_process_count(&self, cat_id: &Id) -> usize {
        match self {
            Self::Scan(admission) => admission.exact_process_count(cat_id),
            Self::Accepted(admission) => admission.exact_process_count(cat_id),
        }
    }

    fn serving_blockd_count(&self, cat_id: &Id) -> usize {
        match self {
            Self::Scan(admission) => admission.serving_blockd_count(cat_id),
            Self::Accepted(admission) => admission.serving_blockd_count(cat_id),
        }
    }

    fn serving_blockd(
        &self,
        cat_id: &Id,
        volume_id: &Id,
    ) -> Option<(
        &'a ServingBlockdExpectation,
        Option<&'a ExactServingBlockdProcessProof>,
    )> {
        match self {
            Self::Scan(admission) => admission.serving_blockd(cat_id, volume_id),
            Self::Accepted(admission) => admission.serving_blockd(cat_id, volume_id),
        }
    }

    fn vmm(
        &self,
        cat_id: &Id,
    ) -> Option<(&'a VmmProcessExpectation, Option<&'a ExactVmmProcessProof>)> {
        match self {
            Self::Scan(admission) => admission.vmm(cat_id),
            Self::Accepted(admission) => admission.vmm(cat_id),
        }
    }
}

enum NetworkProofSet<'a> {
    Scan(&'a NodeGlobalNetworkScanAdmission),
    Accepted(&'a NodeGlobalNetworkAdmission),
}

impl NetworkProofSet<'_> {
    fn has_exact_network(&self, cat_id: &Id, identity: &RuntimeNetworkIdentity) -> bool {
        match self {
            Self::Scan(admission) => admission.has_exact_network(cat_id, identity),
            Self::Accepted(admission) => admission.has_exact_network(cat_id, identity),
        }
    }
}

enum KernelNbdProofSet<'a> {
    Scan(&'a KernelNbdPoolScanAdmission),
    Accepted(&'a KernelNbdPoolAdmission),
}

impl<'a> KernelNbdProofSet<'a> {
    fn device_count(&self, cat_id: &Id) -> usize {
        match self {
            Self::Scan(admission) => admission.device_count(cat_id),
            Self::Accepted(admission) => admission.device_count(cat_id),
        }
    }

    fn exact_device(&self, cat_id: &Id, volume_id: &Id) -> Option<&'a ExactKernelNbdDeviceProof> {
        match self {
            Self::Scan(admission) => admission.exact_device(cat_id, volume_id),
            Self::Accepted(admission) => admission.exact_device(cat_id, volume_id),
        }
    }
}

/// Validate the scanner-private exact Running set before minting the Running
/// tail sidecar.  `volumes` must be the complete per-Cat metadata result from
/// the same bounded scan.  AuthorizedBlockd lineage is retained inside each
/// scanner-built serving expectation; a caller cannot substitute a public
/// process or device projection here. `Ok(None)` means the closed expectation
/// set is well-formed but at least one physical component is not exact yet;
/// callers report ordinary Running progress instead of failing the full scan.
pub(crate) fn validate_retained_running_scan_exact_set<'a>(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    volumes: &[AuthorityVolumeInventoryEvidence],
    processes: &'a NodeGlobalManagedProcessScanAdmission,
    networks: &NodeGlobalNetworkScanAdmission,
    kernel_nbd: Option<&'a KernelNbdPoolScanAdmission>,
) -> Result<Option<&'a ExactVmmProcessProof>> {
    let coordinates = ValidatedRunningCheckpoint::exact(desired, checkpoint)?;
    let records = scanner_volume_records(checkpoint, volumes)?;
    let devices = prepared_device_inputs(checkpoint)?;
    anyhow::ensure!(
        records.len() == devices.len()
            && devices
                .iter()
                .all(|device| records.contains_key(&device.volume_id)),
        "Running scan VolumeRecords differ from the exact retained device set"
    );
    if !running_scan_components_are_exact(desired, checkpoint, processes, networks, kernel_nbd)? {
        return Ok(None);
    }
    validate_running_exact_set(
        coordinates,
        checkpoint,
        &records,
        ProcessProofSet::Scan(processes),
        NetworkProofSet::Scan(networks),
        kernel_nbd.map(KernelNbdProofSet::Scan),
    )
    .map(Some)
}

/// Exact physical check for a current global-close/RequireIdle checkpoint
/// whose durable top already advanced beyond the sealed Running source. The
/// checkpoint remains the exact VMM/process expectation from this scan; only
/// its top-level Desired coordinates are excluded from physical equality.
/// This proof can preserve a Busy/Open source, but can never open or install a
/// gate.
pub(crate) fn validate_retained_running_close_scan_exact_set<'a>(
    sealed_running: &DesiredRuntimeSpec,
    close_desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    volumes: &[AuthorityVolumeInventoryEvidence],
    processes: &'a NodeGlobalManagedProcessScanAdmission,
    networks: &NodeGlobalNetworkScanAdmission,
    kernel_nbd: Option<&'a KernelNbdPoolScanAdmission>,
) -> Result<Option<&'a ExactVmmProcessProof>> {
    let coordinates =
        ValidatedRunningCheckpoint::require_idle(sealed_running, close_desired, checkpoint)?;
    let records = scanner_volume_records(checkpoint, volumes)?;
    let devices = prepared_device_inputs(checkpoint)?;
    anyhow::ensure!(
        records.len() == devices.len()
            && devices
                .iter()
                .all(|device| records.contains_key(&device.volume_id)),
        "retained close scan VolumeRecords differ from the exact device set"
    );
    if !running_scan_components_are_exact(
        sealed_running,
        checkpoint,
        processes,
        networks,
        kernel_nbd,
    )? {
        return Ok(None);
    }
    validate_running_exact_set(
        coordinates,
        checkpoint,
        &records,
        ProcessProofSet::Scan(processes),
        NetworkProofSet::Scan(networks),
        kernel_nbd.map(KernelNbdProofSet::Scan),
    )
    .map(Some)
}

fn running_scan_components_are_exact(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    processes: &NodeGlobalManagedProcessScanAdmission,
    networks: &NodeGlobalNetworkScanAdmission,
    kernel_nbd: Option<&KernelNbdPoolScanAdmission>,
) -> Result<bool> {
    let launch = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?.identity();
    let devices = prepared_device_inputs(checkpoint)?;
    anyhow::ensure!(
        prepared_device_set_is_exact(desired, &devices)
            && processes.serving_blockd_count(&desired.cat_id) == devices.len(),
        "Running scan expectations do not cover the exact retained device set"
    );
    anyhow::ensure!(
        !processes.has_exact_root_control(&desired.cat_id)
            && processes.exact_process_count(&desired.cat_id) <= devices.len() + 1,
        "Running scan contains an extra exact managed process"
    );
    let mut all_exact =
        networks.exact_network_is_present(&desired.cat_id, launch.network.as_ref())?;
    let expected_kernel_nbd = devices
        .iter()
        .filter(|device| matches!(&device.frontend, PrepareDeviceFrontend::KernelNbd { .. }))
        .count();
    if expected_kernel_nbd > 0 {
        let pool = kernel_nbd.context("Running scan lacks its kernel-NBD pool proof")?;
        anyhow::ensure!(
            pool.device_count(&desired.cat_id) == expected_kernel_nbd,
            "Running scan kernel-NBD expectations differ from the retained device set"
        );
    } else if let Some(pool) = kernel_nbd {
        anyhow::ensure!(
            pool.device_count(&desired.cat_id) == 0,
            "Running scan has an extra kernel-NBD expectation"
        );
    }
    for device in &devices {
        let (expectation, exact) = processes
            .serving_blockd(&desired.cat_id, &device.volume_id)
            .context("Running scan lacks one retained serving expectation")?;
        anyhow::ensure!(
            expectation.matches_device_contract(&desired.cat_id, device),
            "Running scan serving expectation changed its retained device"
        );
        if exact.is_none() {
            all_exact = false;
        }
        if matches!(&device.frontend, PrepareDeviceFrontend::KernelNbd { .. })
            && !kernel_nbd.is_some_and(|pool| {
                pool.exact_device(&desired.cat_id, &device.volume_id)
                    .is_some()
            })
        {
            all_exact = false;
        }
    }
    let (vmm_expectation, exact_vmm) = processes
        .vmm(&desired.cat_id)
        .context("Running scan lacks its retained VMM expectation")?;
    anyhow::ensure!(
        vmm_expectation.checkpoint() == checkpoint && vmm_expectation.checkpoint_path().is_some(),
        "Running scan VMM expectation changed its current checkpoint"
    );
    all_exact &= exact_vmm.is_some();
    Ok(all_exact)
}

fn scanner_volume_records<'a>(
    checkpoint: &RuntimeCheckpoint,
    volumes: &'a [AuthorityVolumeInventoryEvidence],
) -> Result<BTreeMap<Id, &'a VolumeRecord>> {
    let mut records = BTreeMap::new();
    for volume in volumes {
        anyhow::ensure!(
            volume.observed.volume_id == volume.record.volume_id
                && checkpoint
                    .volumes
                    .iter()
                    .filter(|candidate| candidate.volume_id == volume.record.volume_id)
                    .count()
                    == 1,
            "Running scan metadata projection changed its VolumeRecord identity"
        );
        anyhow::ensure!(
            records
                .insert(volume.record.volume_id.clone(), &volume.record)
                .is_none(),
            "Running scan repeats one VolumeRecord"
        );
    }
    Ok(records)
}

/// Provider-private final read barrier for a Running gate mutation.  The
/// caller invokes this after Guest Ready is freshly challenged and immediately
/// before `GateSequencer`.  It owns no cloneable proof and returns no raw
/// descriptor, so authority cannot escape the accepted full admission.
pub(crate) struct RunningLaunchAuthorityRevalidator {
    state_directory: StateDirectory,
    systemd: RootProvisionSystemdConfig,
    network: Arc<PrepareNetworkReservationEffect>,
    authority: Arc<dyn VolumeDataAuthority>,
    serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
    vmm_process: Arc<dyn VmmProcessGlobalPort>,
    kernel_nbd: Option<KernelNbdInventoryPort>,
}

struct RetainedRunningDevice<'a> {
    expectation: &'a ServingBlockdExpectation,
    serving: &'a ExactServingBlockdProcessProof,
    kernel_nbd: Option<&'a ExactKernelNbdDeviceProof>,
    retained: RetainedServingBlockdAuthority,
    first_authority: VolumeRecord,
    first_lease_expiry: cats_api::runtime_reconciliation::UnixMillis,
}

/// Non-cloneable authority retained across the final Guest mounted-set
/// challenge. The checkpoint writer guard is acquired before the Host sweep
/// and remains held until the caller has challenged the Guest and performed
/// the final pathname revalidation immediately before the cell effect.
pub(crate) struct RetainedGateSuccessorAuthority<'store, 'checkpoint> {
    successor_vmm: ExactVmmProcessProof,
    store: &'store FileCheckpointStore,
    durable_successor: &'checkpoint StoredCheckpoint,
    checkpoint_guard: CurrentCheckpointGuard<'store>,
}

impl RetainedGateSuccessorAuthority<'_, '_> {
    pub(crate) fn vmm(&self) -> &ExactVmmProcessProof {
        &self.successor_vmm
    }

    pub(crate) fn revalidate_current(&self) -> Result<()> {
        self.store
            .revalidate_current(self.durable_successor, &self.checkpoint_guard)
            .context("revalidate durable Running gate successor after Guest challenge")
    }
}

impl RunningLaunchAuthorityRevalidator {
    pub(super) fn platform_parts(
        state_directory: StateDirectory,
        systemd: RootProvisionSystemdConfig,
        network: Arc<PrepareNetworkReservationEffect>,
        authority: Arc<dyn VolumeDataAuthority>,
        serving_process: Arc<dyn ServingBlockdProcessGlobalPort>,
        vmm_process: Arc<dyn VmmProcessGlobalPort>,
        kernel_nbd: Option<KernelNbdInventoryConfig>,
    ) -> Self {
        Self {
            state_directory,
            systemd,
            network,
            authority,
            serving_process,
            vmm_process,
            kernel_nbd: kernel_nbd.map(KernelNbdInventoryPort::new),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the method revalidates one closed cross-provider Running authority tuple"
    )]
    pub(crate) fn revalidate_exact_retained_running(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        admitted_vmm: &ExactVmmProcessProof,
    ) -> Result<()> {
        let retained = self.revalidate_exact_retained_running_gate_successor(
            context,
            desired,
            desired,
            store,
            stored,
            stored,
            admitted_vmm,
        )?;
        retained.revalidate_current()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the gate barrier closes one accepted physical predecessor and its durable successor"
    )]
    pub(crate) fn revalidate_exact_retained_running_gate_successor<'store, 'checkpoint>(
        &self,
        context: &RuntimeDesiredEffectContext,
        physical_launch_desired: &DesiredRuntimeSpec,
        gate_desired: &DesiredRuntimeSpec,
        store: &'store FileCheckpointStore,
        accepted_checkpoint: &StoredCheckpoint,
        durable_successor: &'checkpoint StoredCheckpoint,
        admitted_vmm: &ExactVmmProcessProof,
    ) -> Result<RetainedGateSuccessorAuthority<'store, 'checkpoint>> {
        self.revalidate_exact_retained_running_gate_chain(
            context,
            physical_launch_desired,
            gate_desired,
            gate_desired,
            false,
            store,
            accepted_checkpoint,
            durable_successor,
            admitted_vmm,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the Endpoint-only barrier closes immutable launch, live-gate predecessor, and durable successor separately"
    )]
    pub(crate) fn revalidate_exact_retained_running_endpoint_successor<'store, 'checkpoint>(
        &self,
        context: &RuntimeDesiredEffectContext,
        physical_launch_desired: &DesiredRuntimeSpec,
        live_gate_predecessor: &DesiredRuntimeSpec,
        gate_successor: &DesiredRuntimeSpec,
        store: &'store FileCheckpointStore,
        accepted_checkpoint: &StoredCheckpoint,
        durable_successor: &'checkpoint StoredCheckpoint,
        admitted_vmm: &ExactVmmProcessProof,
    ) -> Result<RetainedGateSuccessorAuthority<'store, 'checkpoint>> {
        self.revalidate_exact_retained_running_gate_chain(
            context,
            physical_launch_desired,
            live_gate_predecessor,
            gate_successor,
            true,
            store,
            accepted_checkpoint,
            durable_successor,
            admitted_vmm,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the closed gate chain keeps three Desired authorities and two durable checkpoints distinct"
    )]
    fn revalidate_exact_retained_running_gate_chain<'store, 'checkpoint>(
        &self,
        context: &RuntimeDesiredEffectContext,
        physical_launch_desired: &DesiredRuntimeSpec,
        live_gate_predecessor: &DesiredRuntimeSpec,
        gate_successor: &DesiredRuntimeSpec,
        endpoint_only: bool,
        store: &'store FileCheckpointStore,
        accepted_checkpoint: &StoredCheckpoint,
        durable_successor: &'checkpoint StoredCheckpoint,
        admitted_vmm: &ExactVmmProcessProof,
    ) -> Result<RetainedGateSuccessorAuthority<'store, 'checkpoint>> {
        validate_running_physical_desired_successor(
            physical_launch_desired,
            live_gate_predecessor,
        )?;
        if endpoint_only {
            validate_running_endpoint_only_desired_successor(
                live_gate_predecessor,
                gate_successor,
            )?;
        } else {
            anyhow::ensure!(
                live_gate_predecessor == gate_successor,
                "same-revision gate barrier received another Desired"
            );
        }
        anyhow::ensure!(
            accepted_checkpoint.checkpoint().cat_id == live_gate_predecessor.cat_id
                && accepted_checkpoint.checkpoint().node_id
                    == live_gate_predecessor.placement.node_id
                && accepted_checkpoint.checkpoint().placement_epoch
                    == live_gate_predecessor.placement.placement_epoch
                && accepted_checkpoint.checkpoint().desired_revision
                    == live_gate_predecessor.desired_revision
                && accepted_checkpoint.checkpoint().spec_digest
                    == live_gate_predecessor.spec_digest
                && durable_successor.checkpoint().cat_id == gate_successor.cat_id
                && durable_successor.checkpoint().node_id == gate_successor.placement.node_id
                && durable_successor.checkpoint().placement_epoch
                    == gate_successor.placement.placement_epoch
                && durable_successor.checkpoint().desired_revision
                    == gate_successor.desired_revision
                && durable_successor.checkpoint().spec_digest == gate_successor.spec_digest,
            "Running gate chain does not bind its live predecessor and durable successor"
        );
        context.check_active()?;
        anyhow::ensure!(
            context.state_directory().path() == self.state_directory.path(),
            "Running revalidator and Desired effect use different state roots"
        );
        let accepted = context.accepted_full()?;
        let process_admission = context.node_global_process()?;
        let network_admission = context.node_global_network()?;
        anyhow::ensure!(
            process_admission.matches_observation(accepted.observation())
                && network_admission.matches_observation(accepted.observation()),
            "Running revalidator sidecars are not bound to accepted full inventory"
        );
        if let Some(pool) = context.optional_kernel_nbd_pool() {
            anyhow::ensure!(
                pool.matches_observation(accepted.observation()),
                "Running kernel-NBD sidecar is not bound to accepted full inventory"
            );
        }
        let current = store
            .load()
            .context("reread Running checkpoint before authority validation")?
            .context("Running checkpoint disappeared before authority validation")?;
        anyhow::ensure!(
            current.content_digest() == durable_successor.content_digest()
                && current.checkpoint() == durable_successor.checkpoint(),
            "Running durable gate successor changed before authority validation"
        );
        let checkpoint_guard = store.assert_current(durable_successor)?;
        let devices = prepared_device_inputs(accepted_checkpoint.checkpoint())?;
        let mut first_authorities = Vec::with_capacity(devices.len());
        for device in &devices {
            let record = self
                .authority
                .load_volume(&device.volume_id)
                .with_context(|| format!("load Running Volume {}", device.volume_id.as_str()))?;
            first_authorities.push(record);
        }
        // Rebuild references after the owned vector has reached its final
        // capacity; no authority object or descriptor is cloned to satisfy
        // the borrow checker.
        let mut records = BTreeMap::new();
        for record in &first_authorities {
            anyhow::ensure!(
                records.insert(record.volume_id.clone(), record).is_none(),
                "Running Volume authority repeats one Volume"
            );
        }
        let kernel_admission = context
            .optional_kernel_nbd_pool()
            .map(KernelNbdProofSet::Accepted);
        let validated_vmm = validate_running_exact_set(
            ValidatedRunningCheckpoint::exact(
                live_gate_predecessor,
                accepted_checkpoint.checkpoint(),
            )?,
            accepted_checkpoint.checkpoint(),
            &records,
            ProcessProofSet::Accepted(process_admission),
            NetworkProofSet::Accepted(network_admission),
            kernel_admission,
        )?;
        anyhow::ensure!(
            validated_vmm == admitted_vmm,
            "Running-tail VMM proof differs from the accepted all-volume sidecar"
        );

        let mut retained_devices = Vec::with_capacity(devices.len());
        for (device, first_authority) in devices.iter().zip(first_authorities) {
            let (expectation, Some(serving)) = process_admission
                .serving_blockd(&live_gate_predecessor.cat_id, &device.volume_id)
                .context("Running retained device lacks its serving process sidecar")?
            else {
                anyhow::bail!("Running retained device lacks an exact serving process")
            };
            let retained = RetainedServingBlockdAuthority::reopen_running(
                &self.state_directory,
                accepted_checkpoint.checkpoint(),
                physical_launch_desired,
                live_gate_predecessor,
                device,
                &first_authority,
            )
            .context("reopen retained Running AuthorizedBlockd authority")?;
            anyhow::ensure!(
                retained.expectation_running(
                    &self.systemd,
                    physical_launch_desired,
                    &first_authority,
                )? == *expectation,
                "retained Running AuthorizedBlockd authority changed its process expectation"
            );
            let first_lease_expiry = first_authority
                .lease_expires_at
                .context("Running Volume authority lacks a serving lease")?;
            let kernel_nbd = context.optional_kernel_nbd_pool().and_then(|pool| {
                pool.exact_device(&live_gate_predecessor.cat_id, &device.volume_id)
            });
            retained_devices.push(RetainedRunningDevice {
                expectation,
                serving,
                kernel_nbd,
                retained,
                first_authority,
                first_lease_expiry,
            });
        }

        self.network
            .revalidate_exact_reserved(context, store, durable_successor)
            .context("revalidate retained Running network")?;
        for retained in &retained_devices {
            let current_process = match self
                .serving_process
                .inspect_serving_exact_or_absent_after_node_global_sweep(
                    retained.expectation,
                    context,
                )
                .context("fresh-scan retained Running serving process")?
            {
                ServingBlockdProcessInspection::Exact(evidence) => evidence,
                ServingBlockdProcessInspection::Absent
                | ServingBlockdProcessInspection::Conflict(_)
                | ServingBlockdProcessInspection::Unavailable => {
                    anyhow::bail!("retained Running serving process is no longer exact")
                }
            };
            anyhow::ensure!(
                current_process.as_ref() == retained.serving.evidence()
                    && current_process.exactly_matches(retained.expectation),
                "retained Running serving process changed"
            );
            retained.serving.assert_listener_current(context)?;
            let current_authority = self
                .authority
                .load_volume(retained.expectation.volume_id())
                .context("reread retained Running Volume authority")?;
            anyhow::ensure!(
                retirement_authority_lease_is_monotonic(
                    &retained.first_authority,
                    &current_authority,
                    retained.first_lease_expiry,
                ),
                "retained Running Volume authority changed"
            );
            retained.retained.assert_running_current(
                accepted_checkpoint.checkpoint(),
                physical_launch_desired,
                live_gate_predecessor,
                &current_authority,
                retained.expectation,
            )?;
            match (retained.kernel_nbd, &self.kernel_nbd) {
                (Some(admitted), Some(inventory)) => inventory.revalidate_exact_device(
                    context,
                    store,
                    durable_successor,
                    admitted,
                )?,
                (None, _) => {}
                (Some(_), None) => anyhow::bail!(
                    "retained Running kernel-NBD device lacks a production inventory port"
                ),
            }
        }
        store.revalidate_current(durable_successor, &checkpoint_guard)?;
        let successor = if endpoint_only {
            VmmGateSuccessorProof::endpoint_only(
                admitted_vmm,
                live_gate_predecessor,
                gate_successor,
                durable_successor.checkpoint(),
            )?
        } else {
            VmmGateSuccessorProof::same_revision(admitted_vmm, durable_successor.checkpoint())?
        };
        let current_vmm = match self
            .vmm_process
            .inspect_vmm_gate_successor_exact_after_node_global_sweep(
                admitted_vmm,
                &successor,
                context,
            )
            .context("fresh-scan retained Running VMM")?
        {
            VmmProcessGlobalInspection::Exact(current) => current,
            VmmProcessGlobalInspection::Absent(_)
            | VmmProcessGlobalInspection::Conflict(_)
            | VmmProcessGlobalInspection::Unavailable => {
                anyhow::bail!("retained Running VMM is no longer exact")
            }
        };
        anyhow::ensure!(
            current_vmm.expectation() == successor.successor()
                && current_vmm.evidence() == admitted_vmm.evidence(),
            "retained Running VMM changed across the gate-only successor sweep"
        );
        current_vmm.assert_current(context)?;
        store.revalidate_current(durable_successor, &checkpoint_guard)?;
        context.check_active()?;
        Ok(RetainedGateSuccessorAuthority {
            successor_vmm: *current_vmm,
            store,
            durable_successor,
            checkpoint_guard,
        })
    }
}

struct ValidatedRunningCheckpoint<'a> {
    physical_desired: &'a DesiredRuntimeSpec,
}

impl<'a> ValidatedRunningCheckpoint<'a> {
    fn exact(desired: &'a DesiredRuntimeSpec, checkpoint: &RuntimeCheckpoint) -> Result<Self> {
        anyhow::ensure!(
            desired.target == RuntimeTarget::Running
                && checkpoint.cat_id == desired.cat_id
                && checkpoint.node_id == desired.placement.node_id
                && checkpoint.placement_epoch == desired.placement.placement_epoch
                && checkpoint.desired_revision == desired.desired_revision
                && checkpoint.spec_digest == desired.spec_digest,
            "retained Running checkpoint does not bind the exact gate Desired"
        );
        Ok(Self {
            physical_desired: desired,
        })
    }

    fn require_idle(
        source: &'a DesiredRuntimeSpec,
        successor: &DesiredRuntimeSpec,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<Self> {
        let RuntimeTransition::RequireIdle {
            source_revision,
            source_runtime_incarnation,
            ..
        } = &successor.transition
        else {
            anyhow::bail!("retained close scan Desired is not RequireIdle")
        };
        super::route_retirement::validate_require_idle_checkpoint_tuple(successor, checkpoint)?;
        let mut expected = source.clone();
        expected.desired_revision = successor.desired_revision;
        expected.spec_digest = successor.spec_digest.clone();
        expected.target = successor.target;
        expected.transition = successor.transition.clone();
        anyhow::ensure!(
            source.target == RuntimeTarget::Running
                && source.desired_revision == *source_revision
                && expected == *successor
                && checkpoint.cat_id == successor.cat_id
                && checkpoint.node_id == successor.placement.node_id
                && checkpoint.placement_epoch == successor.placement.placement_epoch
                && checkpoint.desired_revision == successor.desired_revision
                && checkpoint.spec_digest == successor.spec_digest
                && checkpoint.runtime_incarnation.as_ref() == Some(source_runtime_incarnation)
                && matches!(
                    checkpoint.require_idle,
                    RequireIdleCheckpoint::Busy {
                        gate_closed: false,
                        ..
                    }
                ),
            "retained close scan is not the exact RequireIdle successor of its sealed Running source"
        );
        Ok(Self {
            physical_desired: source,
        })
    }
}

fn validate_running_exact_set<'a>(
    coordinates: ValidatedRunningCheckpoint<'_>,
    checkpoint: &RuntimeCheckpoint,
    records: &BTreeMap<Id, &VolumeRecord>,
    processes: ProcessProofSet<'a>,
    networks: NetworkProofSet<'_>,
    kernel_nbd: Option<KernelNbdProofSet<'a>>,
) -> Result<&'a ExactVmmProcessProof> {
    let desired = coordinates.physical_desired;
    let retained = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
    let launch = retained.identity();
    anyhow::ensure!(
        desired.target == RuntimeTarget::Running
            && launch.vcpus == desired.runtime.vcpus
            && launch.memory_bytes == desired.runtime.memory_bytes
            && launch.boot_image_digest == desired.runtime.boot_image_digest
            && launch.guest_config_digest == desired.runtime.guest_config_digest
            && launch.network.network_config == desired.runtime.network_config,
        "retained Running launch does not bind the exact current Desired"
    );
    let devices = prepared_device_inputs(checkpoint)?;
    anyhow::ensure!(
        !devices.is_empty()
            && prepared_device_set_is_exact(desired, &devices)
            && checkpoint.volumes.len() == devices.len()
            && records.len() == devices.len(),
        "retained Running launch does not cover the exact Volume set"
    );
    anyhow::ensure!(
        networks.has_exact_network(&desired.cat_id, launch.network.as_ref()),
        "retained Running launch lacks its exact scanner-sealed network"
    );
    anyhow::ensure!(
        processes.serving_blockd_count(&desired.cat_id) == devices.len()
            && processes.exact_process_count(&desired.cat_id) == devices.len() + 1,
        "retained Running launch has a missing or extra managed process"
    );
    let expected_kernel_nbd = devices
        .iter()
        .filter(|device| matches!(&device.frontend, PrepareDeviceFrontend::KernelNbd { .. }))
        .count();
    anyhow::ensure!(
        kernel_nbd
            .as_ref()
            .map_or(expected_kernel_nbd == 0, |pool| {
                pool.device_count(&desired.cat_id) == expected_kernel_nbd
            }),
        "retained Running launch has a missing or extra kernel-NBD device"
    );

    for device in &devices {
        let observed = checkpoint
            .volumes
            .iter()
            .find(|volume| volume.volume_id == device.volume_id)
            .context("retained Running device lacks its checkpoint Volume")?;
        let record = records
            .get(&device.volume_id)
            .context("retained Running device lacks its VolumeRecord")?;
        let (expectation, Some(serving)) = processes
            .serving_blockd(&desired.cat_id, &device.volume_id)
            .context("retained Running device lacks its serving expectation")?
        else {
            anyhow::bail!("retained Running device lacks an exact serving process")
        };
        anyhow::ensure!(
            prepared_device_input_is_exact(device, desired, observed)
                && expectation.matches_device_contract(&desired.cat_id, device)
                && expectation.matches_current_authority(record)
                && serving.expectation() == expectation,
            "retained Running device changed its Desired, Volume, or serving authority"
        );
        match &device.frontend {
            PrepareDeviceFrontend::VhostUserBlk { .. } => {
                let (volume_id, _) = serving
                    .vhost_device_projection()
                    .context("retained Running vhost device lacks an exact socket proof")?;
                anyhow::ensure!(
                    volume_id == device.volume_id,
                    "retained Running vhost proof changed its Volume"
                );
            }
            PrepareDeviceFrontend::KernelNbd { .. } => {
                let exact = kernel_nbd
                    .as_ref()
                    .and_then(|pool| pool.exact_device(&desired.cat_id, &device.volume_id))
                    .context("retained Running kernel-NBD device is not exact")?;
                anyhow::ensure!(
                    exact.listener().expectation() == expectation
                        && exact.matches_prepared_device(&desired.cat_id, device),
                    "retained Running kernel-NBD proof changed its serving or device authority"
                );
            }
        }
    }

    let (vmm_expectation, Some(vmm)) = processes
        .vmm(&desired.cat_id)
        .context("retained Running launch lacks its VMM expectation")?
    else {
        anyhow::bail!("retained Running launch lacks an exact VMM")
    };
    anyhow::ensure!(
        vmm.expectation() == vmm_expectation
            && vmm_expectation.checkpoint() == checkpoint
            && vmm_expectation.checkpoint_path().is_some(),
        "retained Running VMM does not bind the exact current checkpoint"
    );
    Ok(vmm)
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        decode_runtime_checkpoint, UnixMillis, VolumeAdminState,
    };

    use super::*;

    #[test]
    fn scanner_volume_join_accepts_pre_lineage_metadata_projection() {
        let checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        let mut observed = checkpoint.volumes[0].clone();
        assert!(!observed.local_lineages.is_empty());
        observed.local_lineages.clear();
        observed.devices.clear();
        let record = VolumeRecord {
            volume_id: observed.volume_id.clone(),
            size_bytes: observed.size_bytes.unwrap(),
            durability: observed.durability.unwrap(),
            admin_state: VolumeAdminState::Active,
            head: match &observed.authority {
                cats_api::runtime_reconciliation::VolumeAuthorityEvidence::Owned {
                    head, ..
                } => head.clone(),
                _ => panic!("StartRuntime fixture must retain owned Volume authority"),
            },
            lease_owner: Some(Id::new("att_01").unwrap()),
            lease_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(1).unwrap(),
            lease_expires_at: Some(UnixMillis::new(1_900_000_000_000).unwrap()),
            last_transition: None,
        };
        let evidence = [AuthorityVolumeInventoryEvidence { observed, record }];

        let joined = scanner_volume_records(&checkpoint, &evidence).unwrap();
        assert_eq!(joined.len(), 1);
        assert_eq!(
            joined[&Id::new("vol_root").unwrap()].volume_id.as_str(),
            "vol_root"
        );
    }
}
