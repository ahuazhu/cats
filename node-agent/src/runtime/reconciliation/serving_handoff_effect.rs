//! One-effect convergence from an authoritative provision target to a sealed
//! serving handoff.
//!
//! This slice owns only the current exact `ProvisionRootImage` target phase.
//! It publishes the target-control artifact, starts/adopts a strict target
//! wrapper, or seals the handoff record—never more than one physical effect
//! from one accepted full inventory. It deliberately does not persist
//! `PrepareDevice` or create any serving/device/VMM/network state.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AppliedDesiredEvidence, CheckpointEvidence, Condition,
    ContractVersion, ControlHandshakeEvidence, DesiredRuntimeSpec, DiskKind,
    GuestTransportEvidence, HostPath, LifecycleAdmission, LocalLineageState, ObservedDiskKind,
    ObservedRuntimeStatus, OwnershipTokenEvidence, ProcessRole, ProcessState, ProgressingReason,
    RandomId128, ReconcileStep, RuntimeTarget, RuntimeTransition, UnixMillis, VolumeAccess,
    VolumeAcquire, VolumeAuthorityEvidence, VolumeDisposition, VolumeIntent, VolumeRecord,
    WarmSnapshotEvidence,
};
use cats_storage::authority::{
    validate_volume_record, AttachmentLineageIdentity, VolumeDataAuthority,
};
use cats_storage::BlobStore;

use crate::runtime_spine::RuntimeDesiredEffectContext;

use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::root_provision_process::{
    retain_target_control_process_start, RootProvisionAuthoritySnapshot,
    RootProvisionProcessConflict, RootProvisionProcessEvidence, RootProvisionProcessExpectation,
    RootProvisionProcessGlobalPort, RootProvisionProcessInspection, RootProvisionProcessStart,
    TargetControlProcessPort,
};
use super::serving_handoff::{
    ReopenedServingHandoff, ReopenedTargetControlAuthorization, ServingAuthorityTargetEvidence,
    ServingHandoffReady, ServingHandoffRetirementState, ServingHandoffStore,
    TargetControlAuthorizationReady,
};
use super::signed_running::{
    expected_provision_heads, provision_checkpoint_is_bound, ProvisionHeadRead,
};
use super::{AuthorizedBlockdStore, FileCheckpointStore};

#[derive(Debug)]
pub(crate) enum ServingHandoffEffectProgress {
    NotApplicable,
    RefreshInventory,
    Ready(Box<ServingHandoffReady>),
}

pub(crate) struct ServingHandoffEffect {
    authority: Arc<dyn VolumeDataAuthority>,
    blob: Arc<dyn BlobStore>,
    global_process: Arc<dyn RootProvisionProcessGlobalPort>,
    target_process: Arc<dyn TargetControlProcessPort>,
    executable_path: HostPath,
}

impl ServingHandoffEffect {
    pub(crate) fn new(
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        global_process: Arc<dyn RootProvisionProcessGlobalPort>,
        target_process: Arc<dyn TargetControlProcessPort>,
        executable_path: HostPath,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            Path::new(executable_path.as_str()).is_absolute(),
            "serving handoff blockd executable must be absolute"
        );
        Ok(Self {
            authority,
            blob,
            global_process,
            target_process,
            executable_path,
        })
    }

    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<ServingHandoffEffectProgress> {
        context.check_active()?;
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired)? else {
            return Ok(ServingHandoffEffectProgress::NotApplicable);
        };
        if !matches!(runtime.step, ReconcileStep::ProvisionRootImage { .. }) {
            return Ok(ServingHandoffEffectProgress::NotApplicable);
        }
        anyhow::ensure!(
            base_admission_is_exact(accepted, desired, runtime),
            "serving handoff lacks an exact current ProvisionRootImage admission"
        );
        let [volume] = desired.volumes.as_slice() else {
            unreachable!("base admission requires one Root Volume")
        };
        let (blank, target) =
            match expected_provision_heads(self.blob.as_ref(), desired, volume, context.deadline())
            {
                ProvisionHeadRead::Ready { blank, target } => (blank, target),
                ProvisionHeadRead::Retry => {
                    return Ok(ServingHandoffEffectProgress::RefreshInventory)
                }
                ProvisionHeadRead::Invalid => {
                    anyhow::bail!("serving handoff image target is invalid")
                }
            };

        let ReconcileStep::ProvisionRootImage {
            data_directory,
            provision_transition_id,
            ..
        } = &runtime.step
        else {
            unreachable!("step checked above")
        };
        let (identity, observed_head) = observed_lineage(runtime, volume, data_directory)
            .context("serving handoff lacks the exact observed Root lineage")?;
        anyhow::ensure!(
            observed_head == target,
            "serving handoff accepted authority is not the exact provision target"
        );

        // Reopen the scanner-attributed blank grant before trusting the
        // checkpoint path. Only the cloned value crosses into the handoff
        // store, which independently retains every descriptor again.
        let prepared = AuthorizedBlockdStore::new(context.state_directory().clone())
            .reopen_adopted(desired, volume, &identity)
            .context("reopen exact acquire-time Root authorization")?;
        let acquired = prepared.checkpoint().clone();
        drop(prepared);

        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            anyhow::bail!("serving handoff admission lacks a valid checkpoint")
        };
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let checkpoint_store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &checkpoint_directory,
            &desired.cat_id,
        )
        .context("open serving handoff checkpoint store without consuming pre-scan residue")?;
        anyhow::ensure!(
            Path::new(checkpoint_path.as_str()) == checkpoint_store.path(),
            "serving handoff admission names another checkpoint path"
        );
        let Some(stored) = checkpoint_store
            .load()
            .context("load serving handoff checkpoint")?
        else {
            return Ok(ServingHandoffEffectProgress::RefreshInventory);
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(ServingHandoffEffectProgress::RefreshInventory);
        }
        anyhow::ensure!(
            provision_checkpoint_is_bound(
                stored.checkpoint(),
                desired,
                volume,
                context.state_directory().path(),
                &blank,
                &target,
            ),
            "serving handoff checkpoint is not bound to the current Desired image"
        );

        context.check_active()?;
        let first_authority = match self.authority.load_volume(&volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(ServingHandoffEffectProgress::RefreshInventory),
        };
        let base_expectation = RootProvisionProcessExpectation::from_checkpoint(
            stored.checkpoint(),
            RootProvisionAuthoritySnapshot {
                attachment: acquired.attachment.clone(),
                volume: &first_authority,
            },
            self.executable_path.clone(),
        )
        .context("bind serving handoff process to target authority")?;
        anyhow::ensure!(
            first_authority.head == target
                && first_authority.head == observed_head
                && base_expectation.expected_remote_head() == &target
                && base_expectation.provision_transition_id == *provision_transition_id
                && observed_processes_are_exact(runtime, &base_expectation),
            "serving handoff admission conflicts with target authority or process identity"
        );
        let authority = ServingAuthorityTargetEvidence::new(
            provision_transition_id.clone(),
            first_authority.clone(),
        );
        let handoff = ServingHandoffStore::new(context.state_directory().clone());
        let target_ready =
            match handoff.reopen_target_control_authorization(&stored, &acquired, &authority)? {
                ReopenedTargetControlAuthorization::Absent => {
                    context.check_active()?;
                    handoff
                        .seal_target_control_authorization(&stored, &acquired, &authority)
                        .context("publish exact target-control authorization")?;
                    context.check_active()?;
                    return Ok(ServingHandoffEffectProgress::RefreshInventory);
                }
                ReopenedTargetControlAuthorization::Exact(ready) => ready,
            };
        let expectation = base_expectation
            .with_target_control_launch(target_ready.identity().process_launch_identity())?;
        let retirement =
            handoff.classify_retirement_state(&stored, &acquired, &authority, &target_ready)?;

        match (
            retirement,
            handoff.reopen_serving_handoff(&stored, *target_ready)?,
        ) {
            (
                ServingHandoffRetirementState::CurrentAttempt,
                ReopenedServingHandoff::Exact(ready),
            ) => {
                drop(ready);
                self.retire_record(
                    context,
                    &checkpoint_store,
                    &stored,
                    &acquired,
                    &first_authority,
                    &target,
                    provision_transition_id,
                    &handoff,
                )?;
                Ok(ServingHandoffEffectProgress::RefreshInventory)
            }
            (
                ServingHandoffRetirementState::CurrentAttempt,
                ReopenedServingHandoff::Absent(target_ready),
            ) => {
                drop(target_ready);
                self.rotate_process_attempt(
                    context,
                    &checkpoint_store,
                    &stored,
                    &acquired,
                    &first_authority,
                    &target,
                    provision_transition_id,
                    &handoff,
                )?;
                Ok(ServingHandoffEffectProgress::RefreshInventory)
            }
            (_, ReopenedServingHandoff::Exact(ready)) if runtime.processes.is_empty() => {
                drop(ready);
                self.retire_record(
                    context,
                    &checkpoint_store,
                    &stored,
                    &acquired,
                    &first_authority,
                    &target,
                    provision_transition_id,
                    &handoff,
                )?;
                Ok(ServingHandoffEffectProgress::RefreshInventory)
            }
            (_, ReopenedServingHandoff::Exact(ready)) => {
                self.reinspect_ready(
                    context,
                    runtime,
                    &checkpoint_store,
                    &stored,
                    &first_authority,
                    &expectation,
                    &ready,
                    &target,
                )?;
                Ok(ServingHandoffEffectProgress::Ready(ready))
            }
            (_, ReopenedServingHandoff::Absent(target_ready)) if runtime.processes.is_empty() => {
                self.start_target_process(
                    context,
                    &checkpoint_store,
                    &stored,
                    &first_authority,
                    &expectation,
                    &target_ready,
                    &target,
                )?;
                Ok(ServingHandoffEffectProgress::RefreshInventory)
            }
            (_, ReopenedServingHandoff::Absent(target_ready)) => {
                self.seal_record(
                    context,
                    runtime,
                    &checkpoint_store,
                    &stored,
                    &acquired,
                    &first_authority,
                    &expectation,
                    *target_ready,
                    &target,
                    provision_transition_id,
                    &handoff,
                )?;
                Ok(ServingHandoffEffectProgress::RefreshInventory)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn retire_record(
        &self,
        context: &RuntimeDesiredEffectContext,
        checkpoint_store: &FileCheckpointStore,
        stored: &super::StoredCheckpoint,
        acquired: &super::AuthorizedBlockdCheckpoint,
        first_authority: &VolumeRecord,
        target: &cats_api::runtime_reconciliation::RemoteHead,
        provision_transition_id: &RandomId128,
        handoff: &ServingHandoffStore,
    ) -> anyhow::Result<()> {
        let current = self.reread_same_target(context, first_authority, target)?;
        let authority =
            ServingAuthorityTargetEvidence::new(provision_transition_id.clone(), current);
        handoff.retire_record_after_exact_process_absence(
            checkpoint_store,
            stored,
            acquired,
            &authority,
            self.executable_path.clone(),
            self.global_process.as_ref(),
            context,
        )?;
        context.check_active()
    }

    #[allow(clippy::too_many_arguments)]
    fn rotate_process_attempt(
        &self,
        context: &RuntimeDesiredEffectContext,
        checkpoint_store: &FileCheckpointStore,
        stored: &super::StoredCheckpoint,
        acquired: &super::AuthorizedBlockdCheckpoint,
        first_authority: &VolumeRecord,
        target: &cats_api::runtime_reconciliation::RemoteHead,
        provision_transition_id: &RandomId128,
        handoff: &ServingHandoffStore,
    ) -> anyhow::Result<()> {
        let current = self.reread_same_target(context, first_authority, target)?;
        let authority =
            ServingAuthorityTargetEvidence::new(provision_transition_id.clone(), current);
        let (token, updated_at) = fresh_process_attempt(stored)?;
        handoff.rotate_process_token_after_retirement(
            checkpoint_store,
            stored,
            acquired,
            &authority,
            self.executable_path.clone(),
            token,
            updated_at,
            self.global_process.as_ref(),
            context,
        )?;
        context.check_active()
    }

    #[allow(clippy::too_many_arguments)]
    fn start_target_process(
        &self,
        context: &RuntimeDesiredEffectContext,
        checkpoint_store: &FileCheckpointStore,
        stored: &super::StoredCheckpoint,
        first_authority: &VolumeRecord,
        expectation: &RootProvisionProcessExpectation,
        target_ready: &TargetControlAuthorizationReady,
        target: &cats_api::runtime_reconciliation::RemoteHead,
    ) -> anyhow::Result<()> {
        let permit = retain_target_control_process_start(
            checkpoint_store,
            stored,
            expectation,
            target_ready,
        )?;
        let inspection = self
            .global_process
            .inspect_exact_or_absent_after_node_global_sweep(expectation, context)?;
        match inspection {
            // A late exact process means the accepted empty vector is stale.
            // It is never a reason to submit a second unit.
            RootProvisionProcessInspection::Exact(_) => return Ok(()),
            RootProvisionProcessInspection::Absent => {}
            RootProvisionProcessInspection::Unavailable => return Ok(()),
            RootProvisionProcessInspection::Conflict(problem) => {
                return Err(process_conflict("before target-control start", problem))
            }
        }
        self.reread_same_target(context, first_authority, target)?;
        permit.assert_current()?;
        match self
            .target_process
            .start_target_checkpointed(permit, context)?
        {
            RootProvisionProcessStart::Started(evidence)
                if evidence.exactly_matches(expectation) =>
            {
                context.check_active()?;
                Ok(())
            }
            RootProvisionProcessStart::Started(_) => Err(process_conflict(
                "after target-control start",
                RootProvisionProcessConflict::IdentityMismatch,
            )),
            RootProvisionProcessStart::Ambiguous
            | RootProvisionProcessStart::CancelledClean
            | RootProvisionProcessStart::Unavailable => {
                context.check_active()?;
                Ok(())
            }
            RootProvisionProcessStart::Conflict(problem) => {
                Err(process_conflict("during target-control start", problem))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_record(
        &self,
        context: &RuntimeDesiredEffectContext,
        runtime: &ObservedRuntimeStatus,
        checkpoint_store: &FileCheckpointStore,
        stored: &super::StoredCheckpoint,
        acquired: &super::AuthorizedBlockdCheckpoint,
        first_authority: &VolumeRecord,
        expectation: &RootProvisionProcessExpectation,
        target_ready: TargetControlAuthorizationReady,
        target: &cats_api::runtime_reconciliation::RemoteHead,
        provision_transition_id: &cats_api::runtime_reconciliation::RandomId128,
        handoff: &ServingHandoffStore,
    ) -> anyhow::Result<()> {
        target_ready.assert_current(stored)?;
        let _current = checkpoint_store.assert_current(stored)?;
        let evidence = match self
            .global_process
            .inspect_exact_or_absent_after_node_global_sweep(expectation, context)?
        {
            RootProvisionProcessInspection::Exact(evidence)
                if accepted_process_matches_reinspection(runtime, &evidence) =>
            {
                evidence
            }
            RootProvisionProcessInspection::Exact(_) => {
                anyhow::bail!("accepted Root process changed before handoff seal")
            }
            RootProvisionProcessInspection::Absent
            | RootProvisionProcessInspection::Unavailable => return Ok(()),
            RootProvisionProcessInspection::Conflict(problem) => {
                return Err(process_conflict("before handoff seal", problem))
            }
        };
        let current = self.reread_same_target(context, first_authority, target)?;
        target_ready.assert_current(stored)?;
        let proof = expectation.clone().prove_exact_process(*evidence)?;
        let authority =
            ServingAuthorityTargetEvidence::new(provision_transition_id.clone(), current);
        handoff
            .seal_serving_ready_from_target(target_ready, stored, acquired, &authority, &proof)
            .context("publish exact sealed serving handoff")?;
        context.check_active()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn reinspect_ready(
        &self,
        context: &RuntimeDesiredEffectContext,
        runtime: &ObservedRuntimeStatus,
        checkpoint_store: &FileCheckpointStore,
        stored: &super::StoredCheckpoint,
        first_authority: &VolumeRecord,
        expectation: &RootProvisionProcessExpectation,
        ready: &ServingHandoffReady,
        target: &cats_api::runtime_reconciliation::RemoteHead,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            runtime.processes.len() == 1,
            "sealed serving handoff lacks its accepted old control process"
        );
        let _current = checkpoint_store.assert_current(stored)?;
        ready.assert_current(stored)?;
        let evidence = match self
            .global_process
            .inspect_exact_or_absent_after_node_global_sweep(expectation, context)?
        {
            RootProvisionProcessInspection::Exact(evidence)
                if accepted_process_matches_reinspection(runtime, &evidence) =>
            {
                evidence
            }
            RootProvisionProcessInspection::Exact(_) => {
                anyhow::bail!("sealed handoff process changed since accepted inventory")
            }
            RootProvisionProcessInspection::Absent
            | RootProvisionProcessInspection::Unavailable => {
                anyhow::bail!("sealed handoff old control process is not currently exact")
            }
            RootProvisionProcessInspection::Conflict(problem) => {
                return Err(process_conflict("before returning handoff Ready", problem))
            }
        };
        anyhow::ensure!(
            record_process_matches(ready, &evidence),
            "sealed handoff record belongs to another physical process incarnation"
        );
        self.reread_same_target(context, first_authority, target)?;
        ready.assert_current(stored)?;
        context.check_active()
    }

    fn reread_same_target(
        &self,
        context: &RuntimeDesiredEffectContext,
        first: &VolumeRecord,
        target: &cats_api::runtime_reconciliation::RemoteHead,
    ) -> anyhow::Result<VolumeRecord> {
        context.check_active()?;
        let current = self
            .authority
            .load_volume(&first.volume_id)
            .context("reread authority immediately before serving handoff effect")?;
        validate_volume_record(&current)
            .context("serving handoff authority reread is not a closed VolumeRecord")?;
        anyhow::ensure!(
            current.head == *target && same_owner_and_marker(first, &current),
            "serving handoff authority target or owner drifted before the physical effect"
        );
        Ok(current)
    }
}

fn fresh_process_attempt(
    stored: &super::StoredCheckpoint,
) -> anyhow::Result<(RandomId128, UnixMillis)> {
    let ReconcileStep::ProvisionRootImage {
        process_identity_token: old_token,
        ..
    } = &stored.checkpoint().step
    else {
        anyhow::bail!("root-process token rotation requires provision_root_image")
    };
    let token = RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .context("generate fresh root-process attempt token")?;
    anyhow::ensure!(
        token != *old_token,
        "fresh root-process attempt token collided with its predecessor"
    );
    let wall_clock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes the Unix epoch")?
        .as_millis();
    let wall_clock_ms =
        u64::try_from(wall_clock_ms).context("system time exceeds the Runtime wire range")?;
    let minimum = stored
        .checkpoint()
        .updated_at_unix_ms
        .get()
        .checked_add(1)
        .context("root-process attempt timestamp exhausted")?;
    let updated_at = UnixMillis::new(wall_clock_ms.max(minimum))
        .context("root-process attempt timestamp is outside the Runtime wire range")?;
    Ok((token, updated_at))
}

fn unique_runtime<'a>(
    runtimes: &'a [ObservedRuntimeStatus],
    desired: &DesiredRuntimeSpec,
) -> anyhow::Result<Option<&'a ObservedRuntimeStatus>> {
    let mut matching = runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let Some(runtime) = matching.next() else {
        return Ok(None);
    };
    anyhow::ensure!(
        matching.next().is_none(),
        "serving handoff admission contains duplicate current Cat runtimes"
    );
    Ok(Some(runtime))
}

fn base_admission_is_exact(
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
    encode_desired_runtime_spec(desired).is_ok()
        && desired.version == ContractVersion::V1
        && desired.target == RuntimeTarget::Running
        && matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        && desired.volumes.len() == 1
        && desired.placement.node_id == accepted.session().node_id
        && desired.volumes.iter().all(|volume| {
            matches!(volume.acquire, VolumeAcquire::Normal { .. })
                && volume.disk_kind == DiskKind::Root
                && volume.access == VolumeAccess::ReadWriteOnce
                && volume.mount.is_none()
                && matches!(volume.disposition, VolumeDisposition::Retain)
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
        && runtime.processes.len() <= 1
        && runtime.volumes.len() == 1
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

fn observed_lineage(
    runtime: &ObservedRuntimeStatus,
    volume: &VolumeIntent,
    expected_data_directory: &HostPath,
) -> Option<(
    AttachmentLineageIdentity,
    cats_api::runtime_reconciliation::RemoteHead,
)> {
    let [observed] = runtime.volumes.as_slice() else {
        return None;
    };
    let [lineage] = observed.local_lineages.as_slice() else {
        return None;
    };
    let VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return None;
    };
    (observed.volume_intent_id.as_ref() == Some(&volume.volume_intent_id)
        && observed.disk_id.as_ref() == Some(&volume.disk_id)
        && observed.volume_id == volume.volume_id
        && observed.disk_kind == ObservedDiskKind::Root
        && observed.size_bytes == Some(volume.size_bytes)
        && observed.durability == Some(volume.durability)
        && observed.devices.is_empty()
        && lineage.attachment_id == *attachment_id
        && lineage.attachment_epoch == *attachment_epoch
        && lineage.node_id == runtime.applied_desired.as_ref()?.placement.node_id
        && lineage.placement_epoch == runtime.applied_desired.as_ref()?.placement.placement_epoch
        && lineage.local_durable_generation == head.generation
        && lineage.remote_durable_generation == head.generation
        && lineage.pending_pack_count.get() == 0
        && lineage.data_directory == *expected_data_directory
        && !lineage.fenced
        && lineage.state == LocalLineageState::Active)
        .then(|| {
            (
                AttachmentLineageIdentity {
                    volume_id: observed.volume_id.clone(),
                    attachment_id: attachment_id.clone(),
                    attachment_epoch: *attachment_epoch,
                    acquire_origin: lineage.acquire_origin.clone(),
                    node_id: lineage.node_id.clone(),
                    placement_epoch: lineage.placement_epoch,
                },
                head.clone(),
            )
        })
}

fn observed_processes_are_exact(
    runtime: &ObservedRuntimeStatus,
    expected: &RootProvisionProcessExpectation,
) -> bool {
    match runtime.processes.as_slice() {
        [] => true,
        [process] => {
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
        _ => false,
    }
}

fn accepted_process_matches_reinspection(
    runtime: &ObservedRuntimeStatus,
    current: &RootProvisionProcessEvidence,
) -> bool {
    let [accepted] = runtime.processes.as_slice() else {
        return false;
    };
    accepted.process_id == current.process_id
        && accepted.process_start_time_ticks == current.process_start_time_ticks
}

fn record_process_matches(
    ready: &ServingHandoffReady,
    current: &RootProvisionProcessEvidence,
) -> bool {
    let recorded = ready.old_control_process();
    recorded.process_id.get() == u64::from(current.process_id)
        && recorded.unit_main_process_id.get() == u64::from(current.unit_main_process_id)
        && recorded.process_start_time_ticks == current.process_start_time_ticks
        && recorded.cgroup_process_ids.as_slice()
            == [
                cats_api::runtime_reconciliation::WireU64::new(u64::from(current.process_id))
                    .expect("u32 PID fits wire"),
            ]
        && recorded.handshake.peer_process_id.get() == u64::from(current.handshake.peer_process_id)
}

fn same_owner_and_marker(before: &VolumeRecord, after: &VolumeRecord) -> bool {
    before.volume_id == after.volume_id
        && before.size_bytes == after.size_bytes
        && before.durability == after.durability
        && before.admin_state == after.admin_state
        && before.lease_owner == after.lease_owner
        && before.lease_epoch == after.lease_epoch
        && before.last_transition == after.last_transition
}

fn process_conflict(
    boundary: &'static str,
    problem: RootProvisionProcessConflict,
) -> anyhow::Error {
    anyhow::anyhow!("root-provision process conflict {boundary}: {problem:?}")
}
