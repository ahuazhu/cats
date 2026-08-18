//! One bounded `PrepareDevice.after_root_provision` physical effect.
//!
//! The atomic handoff checkpoint may still be followed by the exact old
//! target-control blockd.  This module only retires that one sealed physical
//! incarnation.  It does not start serving blockd, create a frontend/device,
//! or advance the checkpoint.  Every attempted stop therefore returns
//! `RefreshInventory`, and response loss is resolved by the next accepted
//! complete scan observing the exact process absent.  An already-absent
//! process is the completed postcondition, so the same accepted full scan may
//! fall through to the next independent `PrepareDevice` effect.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AcquireOrigin, AppliedDesiredEvidence, CheckpointEvidence,
    Condition, ContractVersion, ControlHandshakeEvidence, DesiredRuntimeSpec, DiskKind,
    GuestTransportEvidence, LifecycleAdmission, ObservedDevice, ObservedDiskKind,
    ObservedRuntimeStatus, ObservedVolume, OwnershipTokenEvidence, PrepareDeviceFrontend,
    PreparedDeviceInput, ProcessRole, ProcessState, ProgressingReason, ReconcileStep,
    RuntimeTarget, RuntimeTransition, ServingAuthorityProvenance, VolumeAcquire,
    VolumeAuthorityEvidence, WarmSnapshotEvidence,
};
use cats_storage::authority::{VolumeDataAuthority, VolumeRecord};

use crate::state_directory::StateDirectory;

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
};

use super::blockd_socket_namespace::ManagedBlockdSocketOwnerRetirement;
use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::root_provision_process::{
    RootProvisionProcessGlobalPort, RootProvisionProcessInspection, RootProvisionProcessPort,
    RootProvisionProcessStop,
};
use super::serving_handoff::ServingHandoffStore;
use super::{
    AuthorizedBlockdStore, FileCheckpointStore, PlatformSystemdRootProvisionProcessPort,
    RootProvisionProcessExpectation, RootProvisionSystemdConfig,
};

pub(crate) struct PrepareDeviceTargetRetirementEffect {
    authority: Arc<dyn VolumeDataAuthority>,
    global_process: Arc<dyn RootProvisionProcessGlobalPort>,
    process: Arc<dyn RootProvisionProcessPort>,
}

impl PrepareDeviceTargetRetirementEffect {
    pub(crate) fn platform(
        authority: Arc<dyn VolumeDataAuthority>,
        global_process: Arc<dyn RootProvisionProcessGlobalPort>,
        systemd: RootProvisionSystemdConfig,
        state_directory: StateDirectory,
    ) -> Self {
        Self {
            authority,
            global_process,
            process: Arc::new(PlatformSystemdRootProvisionProcessPort::platform(
                systemd,
                state_directory,
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        authority: Arc<dyn VolumeDataAuthority>,
        global_process: Arc<dyn RootProvisionProcessGlobalPort>,
        process: Arc<dyn RootProvisionProcessPort>,
    ) -> Self {
        Self {
            authority,
            global_process,
            process,
        }
    }

    /// Return `None` outside the one closed PrepareDevice provenance owned by
    /// this effect and once that provenance proves the old process already
    /// absent.  A stop submission, an ambiguous accepted/live race, or an
    /// unavailable read consumes the batch and requires a new accepted full
    /// inventory before later preparation.
    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        context.check_active()?;
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired)? else {
            return Ok(None);
        };
        let ReconcileStep::PrepareDevice { devices } = &runtime.step else {
            return Ok(None);
        };
        if devices
            .iter()
            .filter(|device| {
                matches!(
                    device.serving_authority.as_ref(),
                    ServingAuthorityProvenance::AfterRootProvision { .. }
                )
            })
            .count()
            != 1
        {
            return Ok(None);
        }
        if !prepare_device_base_admission_is_exact(accepted, desired, runtime) {
            return Ok(Some(stop_local()));
        }

        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(Some(stop_local()));
        };
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &checkpoint_directory,
            &desired.cat_id,
        )
        .context("open PrepareDevice target-retirement checkpoint store")?;
        anyhow::ensure!(
            Path::new(checkpoint_path.as_str()) == store.path(),
            "PrepareDevice target retirement names another checkpoint path"
        );
        let Some(stored) = store
            .load()
            .context("load PrepareDevice target-retirement checkpoint")?
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        }
        let checkpoint_guard = store
            .assert_current(&stored)
            .context("retain current PrepareDevice checkpoint through exact stop")?;

        let Some(desired_volume) = desired
            .volumes
            .iter()
            .find(|volume| volume.disk_kind == DiskKind::Root)
        else {
            return Ok(Some(stop_local()));
        };
        let authority = match self.authority.load_volume(&desired_volume.volume_id) {
            Ok(authority) => authority,
            Err(error) => {
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory_after(
                    &error,
                )))
            }
        };
        let retained = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .retain_prepare_device_handoff(stored.checkpoint(), desired)
        {
            Ok(retained) => retained,
            Err(_) => return Ok(Some(stop_local())),
        };
        let ready = match ServingHandoffStore::new(context.state_directory().clone())
            .reopen_prepare_device_handoff(stored.checkpoint(), desired, &authority, retained)
        {
            Ok(ready) => ready,
            Err(_) => return Ok(Some(stop_local())),
        };
        let Some(first_lease_expiry) = authority
            .lease_expires_at
            .filter(|current| *current >= ready.attempt().attachment.lease_expires_at)
        else {
            return Ok(Some(stop_local()));
        };
        let expectation = match RootProvisionProcessExpectation::from_retained_prepare_device(
            stored.checkpoint(),
            desired,
            ready.attempt(),
        ) {
            Ok(expectation) => expectation,
            Err(_) => return Ok(Some(stop_local())),
        };
        let _node_global_effect = context.lock_node_global_effect()?;
        let admission = match context.node_global_process() {
            Ok(admission) => admission,
            Err(_) => return Ok(Some(stop_local())),
        };
        let Some((_, admitted_serving)) = admission.serving_blockd(
            &desired.cat_id,
            &ready.attempt().attachment.identity.volume_id,
        ) else {
            return Ok(Some(stop_local()));
        };
        enum AcceptedProcess<'a> {
            None,
            Root(&'a cats_api::runtime_reconciliation::ProcessEvidence),
            Serving,
        }
        let accepted_process = match runtime.processes.as_slice() {
            [] if admitted_serving.is_none() => AcceptedProcess::None,
            [process] if public_process_matches_expectation(process, &expectation) => {
                AcceptedProcess::Root(process)
            }
            [process]
                if admitted_serving.is_some_and(|proof| proof.matches_public_process(process)) =>
            {
                AcceptedProcess::Serving
            }
            _ => return Ok(Some(stop_local())),
        };
        if !matches!(accepted_process, AcceptedProcess::Serving)
            && runtime
                .volumes
                .iter()
                .find(|volume| volume.volume_id == desired_volume.volume_id)
                .is_none_or(|volume| !volume.devices.is_empty())
        {
            return Ok(Some(stop_local()));
        }

        context.check_active()?;
        let inspection = self
            .global_process
            .inspect_exact_or_absent_after_node_global_sweep(&expectation, context)
            .context("reinspect old target-control process across Node-global sweep")?;
        let evidence = match (accepted_process, inspection) {
            (
                AcceptedProcess::None | AcceptedProcess::Serving,
                RootProvisionProcessInspection::Absent,
            ) => {
                let retirement = self
                    .global_process
                    .retire_absent_socket_owner(&expectation, context)
                    .context("retire absent PrepareDevice Root socket owner")?;
                context.check_active()?;
                let current_authority = self
                    .authority
                    .load_volume(&desired_volume.volume_id)
                    .context("reread PrepareDevice authority after socket-owner retirement")?;
                ready.assert_current(stored.checkpoint(), desired, &current_authority)?;
                store.revalidate_current(&stored, &checkpoint_guard)?;
                return Ok(match retirement {
                    ManagedBlockdSocketOwnerRetirement::Retired => {
                        Some(RuntimeDesiredEffectOutcome::refresh_inventory())
                    }
                    ManagedBlockdSocketOwnerRetirement::AlreadyAbsent => None,
                });
            }
            (AcceptedProcess::Root(_), RootProvisionProcessInspection::Absent)
            | (_, RootProvisionProcessInspection::Unavailable) => {
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()))
            }
            (AcceptedProcess::Root(accepted), RootProvisionProcessInspection::Exact(evidence))
                if accepted.process_id == evidence.process_id
                    && accepted.process_start_time_ticks == evidence.process_start_time_ticks =>
            {
                evidence
            }
            (
                AcceptedProcess::None | AcceptedProcess::Serving,
                RootProvisionProcessInspection::Exact(_),
            )
            | (AcceptedProcess::Root(_), RootProvisionProcessInspection::Exact(_))
            | (_, RootProvisionProcessInspection::Conflict(_)) => return Ok(Some(stop_local())),
        };

        // The global sweep can block long enough for local artifacts,
        // authority or cancellation to change.  Recheck all four boundaries
        // while the checkpoint guard and attachment flock remain held.
        context.check_active()?;
        let current_authority = match self.authority.load_volume(&desired_volume.volume_id) {
            Ok(authority) => authority,
            Err(error) => {
                return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory_after(
                    &error,
                )))
            }
        };
        if ready
            .assert_current(stored.checkpoint(), desired, &current_authority)
            .is_err()
            || !retirement_authority_lease_is_monotonic(
                &authority,
                &current_authority,
                first_lease_expiry,
            )
            || store
                .revalidate_current(&stored, &checkpoint_guard)
                .is_err()
        {
            return Ok(Some(stop_local()));
        }
        context.check_active()?;
        let proof = match expectation.prove_exact_process(*evidence) {
            Ok(proof) => proof,
            Err(_) => return Ok(Some(stop_local())),
        };
        Ok(Some(match self.process.stop_exact(proof, context)? {
            RootProvisionProcessStop::Submitted
            | RootProvisionProcessStop::AlreadyAbsent
            | RootProvisionProcessStop::Unavailable => {
                RuntimeDesiredEffectOutcome::refresh_inventory()
            }
            RootProvisionProcessStop::Conflict(_) => stop_local(),
        }))
    }
}

/// The process/data authority fields may not move during an exact stop.  A
/// lease renewal is the sole legal concurrent authority change and its
/// absolute expiry can only advance from the first point read.
pub(super) fn retirement_authority_lease_is_monotonic(
    before: &VolumeRecord,
    after: &VolumeRecord,
    first_lease_expiry: cats_api::runtime_reconciliation::UnixMillis,
) -> bool {
    before.volume_id == after.volume_id
        && before.size_bytes == after.size_bytes
        && before.durability == after.durability
        && before.admin_state == after.admin_state
        && before.head == after.head
        && before.lease_owner == after.lease_owner
        && before.lease_epoch == after.lease_epoch
        && before.last_transition == after.last_transition
        && before.lease_expires_at == Some(first_lease_expiry)
        && matches!(after.lease_expires_at, Some(current) if current >= first_lease_expiry)
}

pub(super) fn unique_runtime<'a>(
    runtimes: &'a [ObservedRuntimeStatus],
    desired: &DesiredRuntimeSpec,
) -> anyhow::Result<Option<&'a ObservedRuntimeStatus>> {
    let mut matches = runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let Some(runtime) = matches.next() else {
        return Ok(None);
    };
    anyhow::ensure!(
        matches.next().is_none(),
        "PrepareDevice target-retirement admission contains duplicate current Cat runtimes"
    );
    Ok(Some(runtime))
}

pub(super) fn prepared_device_inputs_from_step(
    step: &ReconcileStep,
) -> anyhow::Result<Vec<PreparedDeviceInput>> {
    if let ReconcileStep::PrepareDevice { devices }
    | ReconcileStep::PrepareNetwork { devices, .. }
    | ReconcileStep::StartRuntime { devices, .. } = step
    {
        anyhow::ensure!(
            !devices.is_empty(),
            "prepared-device phase must retain at least one device"
        );
        return Ok(devices.clone());
    }
    anyhow::bail!("prepared-device projection requires a prepared-device phase")
}

pub(super) fn prepared_device_set_is_exact(
    desired: &DesiredRuntimeSpec,
    devices: &[PreparedDeviceInput],
) -> bool {
    desired.volumes.len() == devices.len()
        && desired
            .volumes
            .iter()
            .zip(devices)
            .enumerate()
            .all(|(index, (intent, device))| {
                usize::from(intent.guest_device.slot) == index
                    && intent.volume_intent_id == device.volume_intent_id
                    && intent.disk_id == device.disk_id
                    && intent.volume_id == device.volume_id
                    && intent.disk_kind == device.disk_kind
                    && intent.attachment_id == device.attachment_id
                    && intent.size_bytes == device.size_bytes
                    && intent.durability == device.durability
                    && intent.guest_device == device.guest_device
                    && match (&intent.acquire, &device.acquire_origin) {
                        (
                            VolumeAcquire::Normal { transition_id, .. },
                            AcquireOrigin::Normal {
                                transition_id: observed,
                            },
                        ) => transition_id == observed,
                        (
                            VolumeAcquire::Takeover { authorization_id },
                            AcquireOrigin::Takeover {
                                authorization_id: observed,
                            },
                        ) => authorization_id == observed,
                        _ => false,
                    }
            })
}

/// Close the public and durable projections of one prepared device against
/// the exact Desired volume. Later launch phases copy this object verbatim, so
/// a pair of internally-consistent but foreign IDs must fail at every scanner
/// and effect admission boundary rather than becoming durable launch input.
pub(super) fn prepared_device_input_is_exact(
    device: &PreparedDeviceInput,
    desired: &DesiredRuntimeSpec,
    observed: &ObservedVolume,
) -> bool {
    let Some(intent) = desired
        .volumes
        .iter()
        .find(|intent| intent.volume_id == device.volume_id)
    else {
        return false;
    };
    let [lineage] = observed.local_lineages.as_slice() else {
        return false;
    };
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return false;
    };
    let expected_disk_kind = match intent.disk_kind {
        DiskKind::Root => ObservedDiskKind::Root,
        DiskKind::Persistent => ObservedDiskKind::Persistent,
    };
    let expected_acquire_origin = match &intent.acquire {
        VolumeAcquire::Normal { transition_id, .. } => AcquireOrigin::Normal {
            transition_id: transition_id.clone(),
        },
        VolumeAcquire::Takeover { authorization_id } => AcquireOrigin::Takeover {
            authorization_id: authorization_id.clone(),
        },
    };
    let attachment_epoch_is_desired = match &intent.acquire {
        VolumeAcquire::Normal {
            expected_unowned_epoch,
            ..
        } => {
            expected_unowned_epoch
                .get()
                .checked_add(1)
                .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
                .as_ref()
                == Some(&device.attachment_epoch)
        }
        VolumeAcquire::Takeover { .. } => true,
    };
    let expected_device = match &device.frontend {
        PrepareDeviceFrontend::KernelNbd { device_path, .. } => ObservedDevice::KernelNbd {
            guest_device: device.guest_device.clone(),
            device_path: device_path.clone(),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: device.ownership_token.clone(),
            },
        },
        PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => ObservedDevice::VhostUserBlk {
            guest_device: device.guest_device.clone(),
            socket_path: socket_path.clone(),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: device.ownership_token.clone(),
            },
        },
    };
    let device_projection_is_closed =
        observed.devices.is_empty() || observed.devices == [expected_device];

    device.volume_intent_id == intent.volume_intent_id
        && device.disk_id == intent.disk_id
        && device.volume_id == intent.volume_id
        && device.disk_kind == intent.disk_kind
        && device.attachment_id == intent.attachment_id
        && device.attachment_id == *attachment_id
        && device.attachment_epoch == *attachment_epoch
        && attachment_epoch_is_desired
        && device.acquire_origin == expected_acquire_origin
        && device.expected_head == *head
        && device.size_bytes == intent.size_bytes
        && device.durability == intent.durability
        && device.guest_device == intent.guest_device
        && observed.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
        && observed.disk_id.as_ref() == Some(&intent.disk_id)
        && observed.volume_id == intent.volume_id
        && observed.disk_kind == expected_disk_kind
        && observed.size_bytes == Some(intent.size_bytes)
        && observed.durability == Some(intent.durability)
        && device_projection_is_closed
        && lineage.attachment_id == *attachment_id
        && lineage.attachment_epoch == *attachment_epoch
        && lineage.acquire_origin == device.acquire_origin
        && lineage.node_id == desired.placement.node_id
        && lineage.placement_epoch == desired.placement.placement_epoch
        && lineage.local_durable_generation == head.generation
        && lineage.remote_durable_generation == head.generation
        && lineage.data_directory == device.serving_process.data_directory
        && lineage.pending_pack_count.get() == 0
        && !lineage.fenced
        && lineage.state == cats_api::runtime_reconciliation::LocalLineageState::Active
}

pub(super) fn prepare_device_base_admission_is_exact(
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
) -> bool {
    let observation = accepted.observation();
    let expected_applied = AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: desired.target,
    };
    let ReconcileStep::PrepareDevice { devices } = &runtime.step else {
        return false;
    };
    encode_desired_runtime_spec(desired).is_ok()
        && super::serving_handoff_effect::checkpoint_is_current_exact(desired, runtime)
        && desired.version == ContractVersion::V1
        && desired.target == RuntimeTarget::Running
        && matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        && desired.placement.node_id == accepted.session().node_id
        && prepared_device_set_is_exact(desired, devices)
        && runtime.volumes.len() == devices.len()
        && devices.iter().all(|device| {
            runtime
                .volumes
                .iter()
                .find(|observed| observed.volume_id == device.volume_id)
                .is_some_and(|observed| prepared_device_input_is_exact(device, desired, observed))
        })
        && observation.complete_inventory
        && observation.node_id == accepted.session().node_id
        && observation.node_boot_id == accepted.session().node_boot_id
        && observation.agent_instance_id == accepted.session().agent_instance_id
        && observation.agent_session_epoch == accepted.session().agent_session_epoch
        && observation.inventory_epoch == accepted.attestation().inventory_epoch
        && observation.inventory_digest.as_ref() == Some(&accepted.attestation().inventory_digest)
        && observation.inventory_read_position
            == Some(accepted.attestation().inventory_read_position)
        && accepted.attestation().node_id == accepted.session().node_id
        && accepted.attestation().agent_session_epoch == accepted.session().agent_session_epoch
        && accepted.attestation().accepted_at_unix_ms < accepted.session().lease_deadline_unix_ms
        && runtime.applied_desired.as_ref() == Some(&expected_applied)
        && runtime.runtime_incarnation.is_none()
        && runtime.stable_state.is_none()
        && runtime.processes.len() <= devices.len()
        && runtime.mounts.is_empty()
        && runtime.networks.is_empty()
        && matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable)
        && matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
        && runtime.lifecycle_admission == LifecycleAdmission::Closed
        && runtime.routes.is_empty()
        && runtime.platform_guards == 0
        && runtime.conditions
            == [Condition::Progressing {
                reason: ProgressingReason::ReconcileStep {
                    step: runtime.step.clone(),
                },
            }]
}

fn public_process_matches_expectation(
    process: &cats_api::runtime_reconciliation::ProcessEvidence,
    expected: &RootProvisionProcessExpectation,
) -> bool {
    matches!(
        &process.role,
        ProcessRole::Blockd {
            volume_id,
            attachment_id,
            attachment_epoch,
        } if volume_id == &expected.volume_id
            && attachment_id == &expected.attachment_id
            && *attachment_epoch == expected.attachment_epoch
    ) && process.process_id > 0
        && process.process_start_time_ticks.get() > 0
        && process.executable_path == expected.executable_path
        && process.scope_id == expected.scope_id
        && process.control_socket_path == expected.control_socket_path
        && process.state == ProcessState::Running
        && process.ownership_token
            == (OwnershipTokenEvidence::Valid {
                ownership_token: expected.process_identity_token.clone(),
            })
        && process.control_handshake == ControlHandshakeEvidence::Verified
        && process.observed_vm_shape.is_none()
}

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        decode_desired_runtime_spec, decode_runtime_checkpoint, Id,
    };

    use super::*;

    const DESIRED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-desired.json"
    ));
    const PREPARE_DEVICE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/runtime-reconciliation-v1-prepare-device-checkpoint.json"
    ));

    #[test]
    fn prepared_device_exactness_rejects_paired_foreign_logical_ids() {
        let desired = decode_desired_runtime_spec(DESIRED).unwrap();
        let checkpoint = decode_runtime_checkpoint(PREPARE_DEVICE).unwrap();
        let [device] = prepared_device_inputs_from_step(&checkpoint.step)
            .unwrap()
            .try_into()
            .unwrap();
        let observed = checkpoint.volumes.first().unwrap();
        assert!(prepared_device_input_is_exact(&device, &desired, observed));

        for field in ["volume_intent_id", "disk_id"] {
            let mut mutated_device = device.clone();
            let mut mutated_observed = observed.clone();
            match field {
                "volume_intent_id" => {
                    let foreign = Id::new("vint_foreign").unwrap();
                    mutated_device.volume_intent_id = foreign.clone();
                    mutated_observed.volume_intent_id = Some(foreign);
                }
                "disk_id" => {
                    let foreign = Id::new("disk_foreign").unwrap();
                    mutated_device.disk_id = foreign.clone();
                    mutated_observed.disk_id = Some(foreign);
                }
                _ => unreachable!(),
            }
            assert!(
                !prepared_device_input_is_exact(&mutated_device, &desired, &mutated_observed),
                "paired foreign {field} was accepted as Desired launch input"
            );
        }
    }
}
