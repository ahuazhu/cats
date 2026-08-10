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
    encode_desired_runtime_spec, AppliedDesiredEvidence, CheckpointEvidence, Condition,
    ContractVersion, ControlHandshakeEvidence, DesiredRuntimeSpec, DiskKind,
    GuestTransportEvidence, LifecycleAdmission, ObservedRuntimeStatus, OwnershipTokenEvidence,
    ProcessRole, ProcessState, ProgressingReason, ReconcileStep, RuntimeTarget, RuntimeTransition,
    ServingAuthorityProvenance, VolumeAccess, VolumeAcquire, VolumeAuthorityEvidence,
    VolumeDisposition, WarmSnapshotEvidence,
};
use cats_storage::authority::{VolumeDataAuthority, VolumeRecord};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
};

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
    ) -> Self {
        Self {
            authority,
            global_process,
            process: Arc::new(PlatformSystemdRootProvisionProcessPort::platform(systemd)),
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
        if !matches!(
            &runtime.step,
            ReconcileStep::PrepareDevice {
                serving_authority,
                ..
            } if matches!(
                serving_authority.as_ref(),
                ServingAuthorityProvenance::AfterRootProvision { .. }
            )
        ) {
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
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let checkpoint_guard = store
            .assert_current(&stored)
            .context("retain current PrepareDevice checkpoint through exact stop")?;

        let [desired_volume] = desired.volumes.as_slice() else {
            return Ok(Some(stop_local()));
        };
        let authority = match self.authority.load_volume(&desired_volume.volume_id) {
            Ok(authority) => authority,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
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
        let admission = context.node_global_process()?;
        let Some((_, admitted_serving)) = admission.serving_blockd(&desired.cat_id) else {
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
            && !runtime.volumes[0].devices.is_empty()
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
            ) => return Ok(None),
            (AcceptedProcess::Root(_), RootProvisionProcessInspection::Absent)
            | (_, RootProvisionProcessInspection::Unavailable) => {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
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
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
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
                RuntimeDesiredEffectOutcome::RefreshInventory
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
    let ReconcileStep::PrepareDevice {
        volume_id,
        attachment_id,
        attachment_epoch,
        acquire_origin,
        expected_head,
        size_bytes,
        durability,
        serving_authority,
        serving_process,
        ..
    } = &runtime.step
    else {
        return false;
    };
    let [desired_volume] = desired.volumes.as_slice() else {
        return false;
    };
    let [observed_volume] = runtime.volumes.as_slice() else {
        return false;
    };
    let [lineage] = observed_volume.local_lineages.as_slice() else {
        return false;
    };
    let VolumeAuthorityEvidence::Owned {
        attachment_id: observed_attachment,
        attachment_epoch: observed_epoch,
        head: observed_head,
    } = &observed_volume.authority
    else {
        return false;
    };
    encode_desired_runtime_spec(desired).is_ok()
        && desired.version == ContractVersion::V1
        && desired.target == RuntimeTarget::Running
        && matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        && desired.placement.node_id == accepted.session().node_id
        && desired_volume.disk_kind == DiskKind::Root
        && desired_volume.access == VolumeAccess::ReadWriteOnce
        && matches!(desired_volume.acquire, VolumeAcquire::Normal { .. })
        && matches!(desired_volume.disposition, VolumeDisposition::Retain)
        && desired_volume.mount.is_none()
        && matches!(
            serving_authority.as_ref(),
            ServingAuthorityProvenance::AfterRootProvision { .. }
        )
        && serving_process.data_directory == lineage.data_directory
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
        && runtime.processes.len() <= 1
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
        && observed_volume.volume_intent_id.as_ref() == Some(&desired_volume.volume_intent_id)
        && observed_volume.disk_id.as_ref() == Some(&desired_volume.disk_id)
        && observed_volume.volume_id == *volume_id
        && observed_volume.volume_id == desired_volume.volume_id
        && observed_volume.size_bytes == Some(*size_bytes)
        && observed_volume.size_bytes == Some(desired_volume.size_bytes)
        && observed_volume.durability == Some(*durability)
        && observed_volume.durability == Some(desired_volume.durability)
        && *observed_attachment == *attachment_id
        && *observed_epoch == *attachment_epoch
        && *observed_head == *expected_head
        && lineage.attachment_id == *attachment_id
        && lineage.attachment_epoch == *attachment_epoch
        && lineage.acquire_origin == *acquire_origin
        && lineage.node_id == desired.placement.node_id
        && lineage.placement_epoch == desired.placement.placement_epoch
        && lineage.local_durable_generation == expected_head.generation
        && lineage.remote_durable_generation == expected_head.generation
        && lineage.pending_pack_count.get() == 0
        && !lineage.fenced
        && lineage.state == cats_api::runtime_reconciliation::LocalLineageState::Active
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
