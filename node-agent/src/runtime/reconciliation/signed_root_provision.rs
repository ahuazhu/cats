//! One-step execution of a current signed `ProvisionRootImage` checkpoint.
//!
//! This module is deliberately narrower than the complete root transition.
//! It can start/adopt the exact blank-head control-only process or send one
//! checkpointed provision request after a fresh full inventory proves that
//! process. Every mutation returns `RefreshInventory`; target-control reload,
//! serving handoff, and `PrepareDevice` remain separate later effects.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AppliedDesiredEvidence, CheckpointEvidence, Condition,
    ContractVersion, ControlHandshakeEvidence, DesiredRuntimeSpec, DiskKind,
    GuestTransportEvidence, HostPath, LifecycleAdmission, LocalLineageState, ObservedDiskKind,
    ObservedRuntimeStatus, OwnershipTokenEvidence, ProcessRole, ProcessState, ProgressingReason,
    ProvisionRootImageError, ReconcileStep, RuntimeTarget, RuntimeTransition, VolumeAccess,
    VolumeAcquire, VolumeAuthorityEvidence, VolumeDisposition, VolumeIntent, WarmSnapshotEvidence,
};
use cats_blockd::target_control::provision_root_image_request;
use cats_storage::authority::{AttachmentLineageIdentity, VolumeDataAuthority, VolumeRecord};
use cats_storage::BlobStore;

use crate::proc::ProcIdentity;
use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
    RuntimeDesiredEffectStopReason,
};

use super::authorized_blockd::{
    RootProvisionStopReceipt, StopReceiptPublication, StopReceiptSettlement,
};
use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::root_provision_process::{
    inspect_exact_root_provision_process, prove_exact_root_provision_process_absence,
    RootProvisionRetirementAdmission,
};
use super::signed_running::{
    expected_provision_heads, provision_checkpoint_is_bound, ProvisionHeadRead,
};
use super::SignedRunningAcquireEffect;
use super::{
    ensure_root_provision_process_from_persisted_checkpoint, AuthorizedBlockdStore,
    FileCheckpointStore, PlatformRootProvisionProcessIdentityPort,
    PlatformSystemdRootProvisionProcessPort, RootProvisionProcessConflict,
    RootProvisionProcessInspection, RootProvisionProcessOutcome, RootProvisionProcessPort,
    RootProvisionProcessRetirementPort, RootProvisionProcessStop, RootProvisionResponseHint,
    RootProvisionSystemdConfig, UnixRootProvisionClient,
};

pub(crate) mod request_sealed {
    pub(crate) trait Sealed {}
}

trait RootProvisionRequestPort: request_sealed::Sealed + Send + Sync {
    fn execute(
        &self,
        socket_path: &HostPath,
        expected_peer_process: &ProcIdentity,
        request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionResponseHint>;
}

#[derive(Debug, Clone, Copy)]
struct PlatformRootProvisionRequestPort;

impl request_sealed::Sealed for PlatformRootProvisionRequestPort {}

impl RootProvisionRequestPort for PlatformRootProvisionRequestPort {
    fn execute(
        &self,
        socket_path: &HostPath,
        expected_peer_process: &ProcIdentity,
        request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionResponseHint> {
        context.check_active()?;
        let remaining = context
            .deadline()
            .checked_duration_since(Instant::now())
            .context("root provision effect deadline expired before control request")?;
        let client =
            UnixRootProvisionClient::new(Path::new(socket_path.as_str()), remaining, remaining);
        let reread = client
            .execute_with_context_for_peer(
                request,
                expected_peer_process,
                &PlatformRootProvisionProcessIdentityPort,
                context,
            )
            .context("send exact root provision request")?;
        Ok(reread.hint().clone())
    }
}

/// Current `ProvisionRootImage` effect. It does not handle acquisition or any
/// later serving/device step; callers dispatch here only for an exact current
/// provision checkpoint from a newly accepted full inventory.
pub(crate) struct SignedRootProvisionEffect {
    authority: Arc<dyn VolumeDataAuthority>,
    blob: Arc<dyn BlobStore>,
    process: Arc<dyn RootProvisionProcessPort>,
    retirement: Arc<dyn RootProvisionProcessRetirementPort>,
    request: Arc<dyn RootProvisionRequestPort>,
    executable_path: HostPath,
}

/// Production dispatcher for the currently implemented Running prefix. A
/// current provision checkpoint is exclusively owned by `provision`; every
/// other state stays with the acquire/stale planner. The two effects are never
/// invoked for the same accepted step.
pub(crate) struct SignedRunningEffect {
    acquire: SignedRunningAcquireEffect,
    provision: SignedRootProvisionEffect,
}

impl SignedRunningEffect {
    pub(crate) fn platform(
        acquire: SignedRunningAcquireEffect,
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        systemd: RootProvisionSystemdConfig,
        retirement: Arc<dyn RootProvisionProcessRetirementPort>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            acquire,
            provision: SignedRootProvisionEffect::platform(authority, blob, systemd, retirement)?,
        })
    }
}

impl RuntimeDesiredEffect for SignedRunningEffect {
    fn apply(
        &self,
        context: RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        if let Some(outcome) = self.provision.try_apply(&context, desired)? {
            return Ok(outcome);
        }
        self.acquire.apply(context, desired)
    }
}

impl SignedRootProvisionEffect {
    pub(crate) fn platform(
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        systemd: RootProvisionSystemdConfig,
        retirement: Arc<dyn RootProvisionProcessRetirementPort>,
    ) -> anyhow::Result<Self> {
        let executable = systemd
            .blockd_binary()
            .to_str()
            .context("root provision blockd binary is not UTF-8")?;
        let executable_path = HostPath::new(executable.to_owned())
            .context("root provision blockd binary is not a canonical HostPath")?;
        let process = Arc::new(PlatformSystemdRootProvisionProcessPort::platform(systemd));
        Ok(Self {
            authority,
            blob,
            process,
            retirement,
            request: Arc::new(PlatformRootProvisionRequestPort),
            executable_path,
        })
    }

    #[cfg(test)]
    fn for_test(
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        process: Arc<dyn RootProvisionProcessPort>,
        retirement: Arc<dyn RootProvisionProcessRetirementPort>,
        request: Arc<dyn RootProvisionRequestPort>,
        executable_path: HostPath,
    ) -> Self {
        Self {
            authority,
            blob,
            process,
            retirement,
            request,
            executable_path,
        }
    }

    /// Returns `None` when the accepted current Cat is not at
    /// `ProvisionRootImage`; the acquisition/stale planner remains the sole
    /// owner of those states.
    pub(crate) fn try_apply(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        context.check_active()?;
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(accepted.observation().runtimes.as_slice(), desired)
        else {
            return Ok(None);
        };
        if !matches!(runtime.step, ReconcileStep::ProvisionRootImage { .. }) {
            return Ok(None);
        }
        if !signed_inventory_admission_is_exact(accepted, desired, runtime) {
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
        let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id)
            .context("open root provision checkpoint store")?;
        if checkpoint_path.as_str() != store.path().to_str().unwrap_or_default() {
            return Ok(Some(stop_local()));
        }
        let Some(stored) = store.load().context("load root provision checkpoint")? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        if stored.checkpoint().desired_revision != desired.desired_revision
            || stored.checkpoint().spec_digest != desired.spec_digest
            || stored.checkpoint().placement_epoch != desired.placement.placement_epoch
        {
            // The stale planner may replace this checkpoint only after the old
            // control-only process is absent in a later accepted full scan.
            // Retiring a live exact incarnation is one bounded physical
            // effect and never mutates the checkpoint or volume authority.
            return if runtime.processes.is_empty() {
                self.finish_superseded_retirement(context, runtime, &store, &stored)
            } else {
                self.retire_superseded_process(context, runtime, &stored)
                    .map(Some)
            };
        }

        if !current_provision_admission_is_exact(desired, runtime) {
            return Ok(Some(stop_local()));
        }

        let [volume] = desired.volumes.as_slice() else {
            return Ok(Some(stop_local()));
        };
        let (blank, target) =
            match expected_provision_heads(self.blob.as_ref(), desired, volume, context.deadline())
            {
                ProvisionHeadRead::Ready { blank, target } => (blank, target),
                ProvisionHeadRead::Retry => {
                    return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
                }
                ProvisionHeadRead::Invalid => return Ok(Some(stop_local())),
            };
        if !provision_checkpoint_is_bound(
            stored.checkpoint(),
            desired,
            volume,
            context.state_directory().path(),
            &blank,
            &target,
        ) {
            return Ok(Some(stop_local()));
        }

        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &stored.checkpoint().step
        else {
            return Ok(Some(stop_local()));
        };
        let Some((identity, observed_head)) = observed_lineage(runtime, volume, data_directory)
        else {
            return Ok(Some(stop_local()));
        };
        let prepared = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .reopen_adopted(desired, volume, &identity)
        {
            Ok(prepared) => prepared,
            Err(_) => return Ok(Some(stop_local())),
        };
        let attachment = prepared.checkpoint().attachment.clone();
        let record = match self.authority.load_volume(&volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
        };
        let expectation = match super::RootProvisionProcessExpectation::from_checkpoint(
            stored.checkpoint(),
            super::RootProvisionAuthoritySnapshot {
                attachment: attachment.clone(),
                volume: &record,
            },
            self.executable_path.clone(),
        ) {
            Ok(expectation) => expectation,
            Err(_) => return Ok(Some(stop_local())),
        };
        if record.head != observed_head || !observed_processes_are_exact(runtime, &expectation) {
            return Ok(Some(stop_local()));
        }

        if runtime.processes.is_empty() {
            let outcome = ensure_root_provision_process_from_persisted_checkpoint(
                &store,
                &stored,
                super::RootProvisionAuthoritySnapshot {
                    attachment,
                    volume: &record,
                },
                self.executable_path.clone(),
                self.process.as_ref(),
                context,
            )?;
            return Ok(Some(match outcome {
                RootProvisionProcessOutcome::Started(_)
                | RootProvisionProcessOutcome::Adopted(_)
                | RootProvisionProcessOutcome::RecoveredAfterAmbiguousStart(_)
                | RootProvisionProcessOutcome::AbsentAfterAmbiguousStart
                | RootProvisionProcessOutcome::CancelledClean
                | RootProvisionProcessOutcome::Unavailable => {
                    RuntimeDesiredEffectOutcome::RefreshInventory
                }
                RootProvisionProcessOutcome::Conflict(
                    RootProvisionProcessConflict::DuplicateIdentity
                    | RootProvisionProcessConflict::IdentityMismatch,
                )
                | RootProvisionProcessOutcome::TargetControlArtifactRequired => stop_local(),
            }));
        }

        // A target head means the data effect is already complete. The next
        // accepted scan is owned by the target-control/handoff slice; never
        // send the provision request again.
        if record.head == target {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        if record.head != blank {
            return Ok(Some(stop_local()));
        }

        let request = provision_root_image_request(stored.checkpoint())
            .context("project exact root provision request")?;
        context.check_active()?;
        let [_accepted_process] = runtime.processes.as_slice() else {
            return Ok(Some(stop_local()));
        };
        // Complete status/socket/systemd reinspection happens before the
        // provision connection is opened. The production control listener is
        // serial, so retaining the request stream while opening a second
        // status stream would deadlock both sides.
        let exact_process = match inspect_exact_root_provision_process(
            self.process.as_ref(),
            &expectation,
            context,
        )
        .context("reinspect exact root-provision process before request connect")?
        {
            RootProvisionProcessInspection::Exact(evidence)
                if accepted_process_matches_reinspection(runtime, &evidence) =>
            {
                evidence
            }
            RootProvisionProcessInspection::Exact(_)
            | RootProvisionProcessInspection::Conflict(_) => return Ok(Some(stop_local())),
            RootProvisionProcessInspection::Absent
            | RootProvisionProcessInspection::Unavailable => {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
        };
        let expected_peer_process = ProcIdentity {
            pid: exact_process.process_id,
            start_ticks: Some(exact_process.process_start_time_ticks.get()),
            exe: Some(Path::new(exact_process.executable_path.as_str()).to_path_buf()),
        };
        let hint = self.request.execute(
            &expectation.control_socket_path,
            &expected_peer_process,
            &request,
            context,
        )?;
        if matches!(
            hint,
            RootProvisionResponseHint::Unknown(
                super::RootProvisionUnknownReason::PeerIdentityMismatch
            )
        ) {
            return Ok(Some(stop_local()));
        }
        // Every non-peer outcome may follow a complete or partial request
        // write. Cancellation while waiting for the response is therefore not
        // authority to skip the mandatory point read: the remote data effect
        // may already have committed before cancellation was observed.
        let current = match self.authority.load_volume(&volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
        };
        if !same_owner_and_marker(&record, &current) {
            return Ok(Some(stop_local()));
        }
        if current.head == target {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        if current.head != blank {
            return Ok(Some(stop_local()));
        }
        if matches!(
            hint,
            RootProvisionResponseHint::Closed(ProvisionRootImageError::DefiniteConflict { .. })
        ) {
            return Ok(Some(stop_local()));
        }
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }

    fn retire_superseded_process(
        &self,
        context: &RuntimeDesiredEffectContext,
        runtime: &ObservedRuntimeStatus,
        stored: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &stored.checkpoint().step
        else {
            return Ok(stop_local());
        };
        let mut prepared = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .retain_exact_runtime_checkpoint(stored.checkpoint())
        {
            Ok(prepared) => prepared,
            Err(_) => return Ok(stop_local()),
        };
        let old_volume = &prepared.checkpoint().volume;
        let attachment = prepared.checkpoint().attachment.clone();
        let Some((identity, observed_head)) = observed_lineage(runtime, old_volume, data_directory)
        else {
            return Ok(stop_local());
        };
        if identity != attachment.identity {
            return Ok(stop_local());
        }
        context.check_active()?;
        let record = match self.authority.load_volume(&old_volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        let expectation = match super::RootProvisionProcessExpectation::from_checkpoint(
            stored.checkpoint(),
            super::RootProvisionAuthoritySnapshot {
                attachment,
                volume: &record,
            },
            self.executable_path.clone(),
        ) {
            Ok(expectation) => expectation,
            Err(_) => return Ok(stop_local()),
        };
        if record.head != observed_head || !observed_processes_are_exact(runtime, &expectation) {
            return Ok(stop_local());
        }
        let Some(socket) = prepared
            .retain_exact_control_socket()
            .context("retain exact root-provision socket before stop inspection")?
        else {
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        };
        context.check_active()?;
        let evidence = match self
            .retirement
            .inspect_exact_after_node_global_sweep(&expectation, context)?
        {
            RootProvisionProcessInspection::Exact(evidence)
                if accepted_process_matches_reinspection(runtime, &evidence) =>
            {
                evidence
            }
            RootProvisionProcessInspection::Exact(_)
            | RootProvisionProcessInspection::Conflict(_) => return Ok(stop_local()),
            RootProvisionProcessInspection::Absent
            | RootProvisionProcessInspection::Unavailable => {
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
        };
        let receipt = match RootProvisionStopReceipt::new(
            stored.checkpoint(),
            prepared.checkpoint(),
            record,
            evidence.as_ref().clone(),
            socket,
            root_provision_retirement_admission(context)?,
        ) {
            Ok(receipt) => receipt,
            Err(_) => return Ok(stop_local()),
        };
        let publication = match prepared.persist_or_reopen_stop_receipt(&receipt) {
            Ok(publication) => publication,
            Err(_) => return Ok(stop_local()),
        };
        match publication {
            StopReceiptPublication::Recovered(recovered) => {
                anyhow::ensure!(
                    recovered.process() == receipt.process(),
                    "recovered root-provision stop receipt changed process identity"
                );
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
            }
            StopReceiptPublication::Stable(existing)
            | StopReceiptPublication::Published(existing) => {
                anyhow::ensure!(
                    existing.process() == receipt.process(),
                    "stable root-provision stop receipt changed process identity"
                );
            }
        }
        let proof = match expectation.prove_exact_process(*evidence) {
            Ok(proof) => proof,
            Err(_) => return Ok(stop_local()),
        };
        prepared
            .assert_current()
            .context("revalidate retained old launch inputs before exact stop")?;
        context.check_active()?;
        Ok(match self.process.stop_exact(proof, context)? {
            RootProvisionProcessStop::Submitted
            | RootProvisionProcessStop::AlreadyAbsent
            | RootProvisionProcessStop::Unavailable => {
                RuntimeDesiredEffectOutcome::RefreshInventory
            }
            RootProvisionProcessStop::Conflict(_) => stop_local(),
        })
    }

    fn finish_superseded_retirement(
        &self,
        context: &RuntimeDesiredEffectContext,
        runtime: &ObservedRuntimeStatus,
        store: &FileCheckpointStore,
        stored: &super::StoredCheckpoint,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        let ReconcileStep::ProvisionRootImage { data_directory, .. } = &stored.checkpoint().step
        else {
            return Ok(Some(stop_local()));
        };
        let retained = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .retain_exact_runtime_checkpoint(stored.checkpoint())
        {
            Ok(retained) => retained,
            Err(_) => return Ok(Some(stop_local())),
        };
        let receipt = match retained
            .settle_stop_receipt()
            .context("settle superseded root-provision stop receipt")?
        {
            StopReceiptSettlement::Absent => return Ok(None),
            StopReceiptSettlement::Recovered(_) => {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
            StopReceiptSettlement::Stable(receipt) => receipt,
        };
        if receipt.checkpoint_content_digest() != stored.content_digest()
            || receipt
                .binds_retained_values(stored.checkpoint(), retained.checkpoint())
                .is_err()
        {
            return Ok(Some(stop_local()));
        }
        let old_volume = &retained.checkpoint().volume;
        let Some((identity, observed_head)) = observed_lineage(runtime, old_volume, data_directory)
        else {
            return Ok(Some(stop_local()));
        };
        if identity != retained.checkpoint().attachment.identity {
            return Ok(Some(stop_local()));
        }
        context.check_active()?;
        let current = match self.authority.load_volume(&old_volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
        };
        if current.head != observed_head
            || receipt
                .expectation_for_current_authority(
                    stored.checkpoint(),
                    retained.checkpoint(),
                    &current,
                )
                .is_err()
        {
            return Ok(Some(stop_local()));
        }
        let absence = match prove_exact_root_provision_process_absence(
            store,
            stored,
            super::RootProvisionAuthoritySnapshot {
                attachment: retained.checkpoint().attachment.clone(),
                volume: &current,
            },
            self.executable_path.clone(),
            self.retirement.as_ref(),
            context,
        ) {
            Ok(absence) => absence,
            Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
        };
        if !retirement_admission_strictly_succeeds(receipt.admission(), absence.admission()) {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        retained
            .remove_stop_receipt(&receipt)
            .context("remove exact settled root-provision stop receipt")?;
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }
}

fn root_provision_retirement_admission(
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<RootProvisionRetirementAdmission> {
    let accepted = context.accepted_full()?;
    let observation = accepted.observation();
    let attestation = accepted.attestation();
    Ok(RootProvisionRetirementAdmission {
        node_boot_id: observation.node_boot_id.clone(),
        agent_instance_id: observation.agent_instance_id.clone(),
        agent_session_epoch: observation.agent_session_epoch,
        inventory_epoch: observation.inventory_epoch,
        inventory_digest: attestation.inventory_digest.clone(),
        inventory_read_position: attestation.inventory_read_position,
    })
}

fn retirement_admission_strictly_succeeds(
    old: &RootProvisionRetirementAdmission,
    new: &RootProvisionRetirementAdmission,
) -> bool {
    let session_advances = new.agent_session_epoch > old.agent_session_epoch;
    let same_session_advances = new.agent_session_epoch == old.agent_session_epoch
        && new.node_boot_id == old.node_boot_id
        && new.agent_instance_id == old.agent_instance_id
        && new.inventory_epoch > old.inventory_epoch;
    (session_advances || same_session_advances)
        && new.inventory_read_position > old.inventory_read_position
}

fn unique_runtime<'a>(
    runtimes: &'a [ObservedRuntimeStatus],
    desired: &DesiredRuntimeSpec,
) -> Option<&'a ObservedRuntimeStatus> {
    let mut matching = runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let runtime = matching.next()?;
    matching.next().is_none().then_some(runtime)
}

fn signed_inventory_admission_is_exact(
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
        && desired.placement.node_id == accepted.session().node_id
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

fn current_provision_admission_is_exact(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
) -> bool {
    desired.target == RuntimeTarget::Running
        && matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        && desired.volumes.len() == 1
        && desired.volumes.iter().all(|volume| {
            matches!(volume.acquire, VolumeAcquire::Normal { .. })
                && volume.disk_kind == DiskKind::Root
                && volume.access == VolumeAccess::ReadWriteOnce
                && volume.mount.is_none()
                && matches!(volume.disposition, VolumeDisposition::Retain)
        })
        && runtime.processes.len() <= 1
        && runtime.volumes.len() == 1
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
    expected: &super::RootProvisionProcessExpectation,
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
    current: &super::RootProvisionProcessEvidence,
) -> bool {
    let [accepted] = runtime.processes.as_slice() else {
        return false;
    };
    accepted.process_id == current.process_id
        && accepted.process_start_time_ticks == current.process_start_time_ticks
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

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Mutex};
    use std::time::Duration;

    use cats_api::runtime_reconciliation::{
        checkpoint_content_digest, encode_provision_root_image_request,
        encode_provision_root_image_result, inventory_digest, spec_digest, AcquireOrigin,
        AdmissionInventoryAttestation, AgentSession, AssignedKind, AssignedPlacement,
        DesiredReadSnapshot, Durability, EndpointIntent, Epoch, FenceEpoch, GuestDeviceIdentity,
        Hostname, HttpProtocol, Id, Ipv4Address, IsolatedIpv4Kind, LocalVolumeLineage, MacAddress,
        NetworkConfig, NodeBootId, NodeObservation, NormalAcquireRequest, NormalAcquireResult,
        ObservedRuntimeStatus, ObservedVolume, ProcessEvidence, ProvisionRootImageResult,
        RandomId128, RemoteHead, Revision, RuntimeCheckpoint, RuntimeConfig,
        RuntimeVolumeTransitionRequest, Sequence, SessionBinding, Sha256Digest, UnixMillis,
        VolumeRecord, WireU64,
    };
    use cats_storage::authority::{
        AuthorityError, AuthorizedServingAttachment, LastVolumeTransition, RenewLeaseRequest,
        RenewLeaseResult, VolumeAdminState, VolumeHeadCasRequest, VolumeHeadCasResult,
    };
    use cats_storage::{
        encode_image_manifest, BlobError, ImageManifestChunkV1, ImageManifestV1, LowerHexSha256,
    };

    use crate::runtime_spine::{
        RuntimeDesiredEffectAdmission, RuntimeDesiredEffectContext, RuntimePreScanRecovery,
        RuntimePreScanRecoveryContext, RuntimePreScanRecoveryOutcome, RuntimeSpineFullScan,
    };
    use crate::state_directory::StateDirectory;

    use super::super::authorized_blockd::authorized_blockd_data_directory;
    use super::super::root_provision::RootProvisionProcessIdentityPort;
    use super::super::root_provision_process::{
        CheckpointedRootProvisionProcess, RootProvisionBlockdHandshake,
        RootProvisionProcessEvidence, RootProvisionProcessInspection, RootProvisionProcessStart,
    };
    use super::super::signed_running::{SignedNormalAcquirePort, SignedRunningPublicationRecovery};
    use super::super::{
        NormalAcquireAcceptedContext, NormalAcquireAttempt, NormalAcquireClientError,
        NormalReleaseAttempt,
    };
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).unwrap()
    }

    fn fence(value: u64) -> FenceEpoch {
        FenceEpoch::new(value).unwrap()
    }

    fn unix_ms(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    fn desired() -> DesiredRuntimeSpec {
        let volume = VolumeIntent {
            volume_intent_id: id("vint_root"),
            disk_id: id("disk_root"),
            volume_id: id("vol_root"),
            attachment_id: id("att_root"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-root"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: random('2'),
                expected_unowned_epoch: fence(0),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        };
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: id("ws_01"),
            cat_id: id("cat_01"),
            desired_revision: Revision::new(1).unwrap(),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: id("node_a"),
                placement_epoch: epoch(3),
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("net_01"),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: vec![volume],
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([9; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    }

    struct ExactBlob(Vec<u8>);

    impl ExactBlob {
        fn new(desired: &DesiredRuntimeSpec) -> Self {
            let manifest = ImageManifestV1 {
                version: 1,
                image_id: LowerHexSha256::from_digest(&desired.runtime.boot_image_digest),
                size_bytes: desired.volumes[0].size_bytes,
                chunks: Vec::new(),
            };
            Self(encode_image_manifest(&manifest).unwrap())
        }

        fn with_chunk(desired: &DesiredRuntimeSpec, byte: char) -> Self {
            let manifest = ImageManifestV1 {
                version: 1,
                image_id: LowerHexSha256::from_digest(&desired.runtime.boot_image_digest),
                size_bytes: desired.volumes[0].size_bytes,
                chunks: vec![ImageManifestChunkV1 {
                    chunk_idx: 0,
                    len: u32::try_from(desired.volumes[0].size_bytes).unwrap(),
                    object_id: LowerHexSha256::new(
                        std::iter::repeat_n(byte, 64).collect::<String>(),
                    )
                    .unwrap(),
                }],
            };
            Self(encode_image_manifest(&manifest).unwrap())
        }
    }

    impl BlobStore for ExactBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> Result<(), BlobError> {
            unreachable!("root provision planning never writes the image namespace")
        }

        fn get(&self, _key: &str) -> Result<Vec<u8>, BlobError> {
            Ok(self.0.clone())
        }

        fn get_bounded_until(
            &self,
            _key: &str,
            maximum: usize,
            deadline: Instant,
        ) -> Result<Vec<u8>, BlobError> {
            if Instant::now() >= deadline {
                return Err(BlobError::Backend {
                    key: "manifest".to_owned(),
                    message: "deadline".to_owned(),
                });
            }
            if self.0.len() > maximum {
                return Err(BlobError::TooLarge {
                    key: "manifest".to_owned(),
                    maximum,
                    observed_at_least: self.0.len(),
                });
            }
            Ok(self.0.clone())
        }

        fn exists(&self, _key: &str) -> Result<bool, BlobError> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> Result<(), BlobError> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> Result<Vec<String>, BlobError> {
            unreachable!()
        }
    }

    struct FakeAuthority {
        record: Mutex<VolumeRecord>,
        loads: AtomicUsize,
    }

    impl FakeAuthority {
        fn new(record: VolumeRecord) -> Self {
            Self {
                record: Mutex::new(record),
                loads: AtomicUsize::new(0),
            }
        }

        fn set_head(&self, head: cats_api::runtime_reconciliation::RemoteHead) {
            self.record.lock().unwrap().head = head;
        }

        fn set_owner(&self, owner: Id) {
            self.record.lock().unwrap().lease_owner = Some(owner);
        }

        fn set_lease_expiry(&self, expires_at: UnixMillis) {
            self.record.lock().unwrap().lease_expires_at = Some(expires_at);
        }

        fn clear_transition_marker(&self) {
            self.record.lock().unwrap().last_transition = None;
        }

        fn record(&self) -> VolumeRecord {
            self.record.lock().unwrap().clone()
        }
    }

    impl VolumeDataAuthority for FakeAuthority {
        fn load_volume(&self, volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            let record = self.record();
            (record.volume_id == *volume_id)
                .then_some(record)
                .ok_or(AuthorityError::NotFound)
        }

        fn renew_lease(
            &self,
            _request: &RenewLeaseRequest,
        ) -> Result<RenewLeaseResult, AuthorityError> {
            unreachable!()
        }

        fn compare_and_swap_head(
            &self,
            _request: &VolumeHeadCasRequest,
        ) -> Result<VolumeHeadCasResult, AuthorityError> {
            unreachable!()
        }
    }

    struct FakeProcessPort {
        inspections: AtomicUsize,
        starts: AtomicUsize,
        stops: AtomicUsize,
        inspected_identity: Option<(u32, u64)>,
        stop: RootProvisionProcessStop,
    }

    impl Default for FakeProcessPort {
        fn default() -> Self {
            Self {
                inspections: AtomicUsize::new(0),
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                inspected_identity: None,
                stop: RootProvisionProcessStop::Submitted,
            }
        }
    }

    impl FakeProcessPort {
        fn exact(process_id: u32, start_time_ticks: u64) -> Self {
            Self {
                inspections: AtomicUsize::new(0),
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                inspected_identity: Some((process_id, start_time_ticks)),
                stop: RootProvisionProcessStop::Submitted,
            }
        }
    }

    impl super::super::root_provision_process::sealed::Sealed for FakeProcessPort {}

    impl RootProvisionProcessPort for FakeProcessPort {
        fn inspect(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.inspections.fetch_add(1, Ordering::SeqCst);
            Ok(match self.inspected_identity {
                Some((process_id, start_time_ticks)) => {
                    let mut evidence = exact_process(expected);
                    evidence.process_id = process_id;
                    evidence.unit_main_process_id = process_id;
                    evidence.process_start_time_ticks = WireU64::new(start_time_ticks).unwrap();
                    evidence.cgroup_process_ids = vec![process_id];
                    evidence.handshake.peer_process_id = process_id;
                    RootProvisionProcessInspection::Exact(Box::new(evidence))
                }
                None => RootProvisionProcessInspection::Absent,
            })
        }

        fn start_checkpointed(
            &self,
            checkpointed: CheckpointedRootProvisionProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessStart> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(RootProvisionProcessStart::Started(Box::new(exact_process(
                checkpointed.expected(),
            ))))
        }

        fn stop_exact(
            &self,
            exact: super::super::root_provision_process::ExactRootProvisionProcessProof,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessStop> {
            assert_eq!(exact.evidence().process_id, 41);
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(self.stop)
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum FakeRetirementInspection {
        Exact,
        Absent,
        Duplicate,
        Drift,
        Unavailable,
    }

    struct FakeRetirementPort {
        calls: AtomicUsize,
        inspection: FakeRetirementInspection,
        after_exact_inspection: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    }

    impl FakeRetirementPort {
        fn with_inspection(inspection: FakeRetirementInspection) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                inspection,
                after_exact_inspection: Mutex::new(None),
            }
        }

        fn exact() -> Self {
            Self::with_inspection(FakeRetirementInspection::Exact)
        }

        fn absent() -> Self {
            Self::with_inspection(FakeRetirementInspection::Absent)
        }

        fn unavailable() -> Self {
            Self::with_inspection(FakeRetirementInspection::Unavailable)
        }

        fn exact_with_hook(hook: Arc<dyn Fn() + Send + Sync>) -> Self {
            let port = Self::exact();
            *port.after_exact_inspection.lock().unwrap() = Some(hook);
            port
        }

        fn inspection(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
        ) -> RootProvisionProcessInspection {
            match self.inspection {
                FakeRetirementInspection::Exact => {
                    RootProvisionProcessInspection::Exact(Box::new(exact_process(expected)))
                }
                FakeRetirementInspection::Absent => RootProvisionProcessInspection::Absent,
                FakeRetirementInspection::Duplicate => RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::DuplicateIdentity,
                ),
                FakeRetirementInspection::Drift => {
                    let mut evidence = exact_process(expected);
                    evidence.process_start_time_ticks = WireU64::new(43).unwrap();
                    RootProvisionProcessInspection::Exact(Box::new(evidence))
                }
                FakeRetirementInspection::Unavailable => {
                    RootProvisionProcessInspection::Unavailable
                }
            }
        }
    }

    impl super::super::root_provision_process::retirement_sealed::Sealed for FakeRetirementPort {}

    impl RootProvisionProcessRetirementPort for FakeRetirementPort {
        fn inspect_exact_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let inspection = self.inspection(expected);
            if let Some(hook) = self.after_exact_inspection.lock().unwrap().take() {
                hook();
            }
            Ok(inspection)
        }

        fn inspect_absent_allowing_socket_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            _allowed_socket: &HostPath,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.inspection(expected))
        }

        fn inspect_after_node_global_sweep(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.inspection(expected))
        }
    }

    struct FakeRequestPort {
        authority: Arc<FakeAuthority>,
        calls: AtomicUsize,
        conflict: bool,
        mutate_owner: bool,
        connect_failure: bool,
        identity_mismatch: bool,
    }

    #[derive(Default)]
    struct NoSignedMutationPort {
        calls: AtomicUsize,
    }

    impl SignedNormalAcquirePort for NoSignedMutationPort {
        fn acquire(
            &self,
            _request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _accepted: &NormalAcquireAcceptedContext,
            _deadline: Instant,
        ) -> Result<NormalAcquireAttempt, NormalAcquireClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(NormalAcquireAttempt::RefreshInventory)
        }

        fn release(
            &self,
            _request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _expected_head: &RemoteHead,
            _accepted: &NormalAcquireAcceptedContext,
            _deadline: Instant,
        ) -> Result<NormalReleaseAttempt, NormalAcquireClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(NormalReleaseAttempt::RefreshInventory)
        }
    }

    impl request_sealed::Sealed for FakeRequestPort {}

    impl RootProvisionRequestPort for FakeRequestPort {
        fn execute(
            &self,
            _socket_path: &HostPath,
            expected_peer_process: &ProcIdentity,
            request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionResponseHint> {
            context.check_active()?;
            assert_eq!(
                expected_peer_process,
                &ProcIdentity {
                    pid: 41,
                    start_ticks: Some(42),
                    exe: Some(Path::new("/usr/bin/cats-blockd").to_path_buf()),
                }
            );
            if self.connect_failure {
                return Ok(RootProvisionResponseHint::Unknown(
                    super::super::RootProvisionUnknownReason::Connect,
                ));
            }
            if self.identity_mismatch {
                return Ok(RootProvisionResponseHint::Unknown(
                    super::super::RootProvisionUnknownReason::PeerIdentityMismatch,
                ));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.conflict {
                return Ok(RootProvisionResponseHint::Closed(
                    ProvisionRootImageError::DefiniteConflict {
                        provision_transition_id: request.provision_transition_id.clone(),
                        volume_id: request.volume_id.clone(),
                        attachment_id: request.attachment_id.clone(),
                        attachment_epoch: request.attachment_epoch,
                        problem: cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::RequestBinding,
                    },
                ));
            }
            self.authority
                .set_head(request.expected_provisioned_head.clone());
            if self.mutate_owner {
                self.authority.set_owner(id("foreign_owner"));
            }
            Ok(RootProvisionResponseHint::Unknown(
                super::super::RootProvisionUnknownReason::Eof,
            ))
        }
    }

    struct SerialStatusProcessPort {
        inspections: AtomicUsize,
        process_id: u32,
        start_time_ticks: u64,
        socket_path: PathBuf,
    }

    impl super::super::root_provision_process::sealed::Sealed for SerialStatusProcessPort {}

    impl RootProvisionProcessPort for SerialStatusProcessPort {
        fn inspect(
            &self,
            expected: &super::super::RootProvisionProcessExpectation,
            context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            context.check_active()?;
            self.inspections.fetch_add(1, Ordering::SeqCst);
            let mut stream = UnixStream::connect(&self.socket_path)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            stream.write_all(b"status\n")?;
            let mut response = [0_u8; 10];
            stream.read_exact(&mut response)?;
            anyhow::ensure!(
                &response == b"status-ok\n",
                "serial status calibration failed"
            );

            let mut evidence = exact_process(expected);
            evidence.process_id = self.process_id;
            evidence.unit_main_process_id = self.process_id;
            evidence.process_start_time_ticks = WireU64::new(self.start_time_ticks).unwrap();
            evidence.cgroup_process_ids = vec![self.process_id];
            evidence.handshake.peer_process_id = self.process_id;
            Ok(RootProvisionProcessInspection::Exact(Box::new(evidence)))
        }

        fn start_checkpointed(
            &self,
            _checkpointed: CheckpointedRootProvisionProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessStart> {
            unreachable!("serial-listener regression starts with an accepted live process")
        }
    }

    #[derive(Clone)]
    struct FixedProcessIdentity(ProcIdentity);

    impl RootProvisionProcessIdentityPort for FixedProcessIdentity {
        fn sample(&self, process_id: u32) -> ProcIdentity {
            assert_eq!(process_id, self.0.pid);
            self.0.clone()
        }
    }

    struct SerialRequestPort {
        process_identity: FixedProcessIdentity,
        socket_path: PathBuf,
        calls: AtomicUsize,
    }

    impl request_sealed::Sealed for SerialRequestPort {}

    impl RootProvisionRequestPort for SerialRequestPort {
        fn execute(
            &self,
            _socket_path: &HostPath,
            expected_peer_process: &ProcIdentity,
            request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionResponseHint> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let remaining = context.deadline().saturating_duration_since(Instant::now());
            Ok(
                UnixRootProvisionClient::new(&self.socket_path, remaining, remaining)
                    .execute_with_context_for_peer(
                        request,
                        expected_peer_process,
                        &self.process_identity,
                        context,
                    )?
                    .hint()
                    .clone(),
            )
        }
    }

    fn accept_before(listener: &UnixListener, deadline: Instant) -> UnixStream {
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "serial listener accept timed out"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("serial listener accept failed: {error}"),
            }
        }
    }

    struct Fixture {
        _root: tempfile::TempDir,
        state: StateDirectory,
        desired: DesiredRuntimeSpec,
        checkpoint: RuntimeCheckpoint,
        attachment: AuthorizedServingAttachment,
        authority: Arc<FakeAuthority>,
        blob: Arc<ExactBlob>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::new_with_desired(desired())
        }

        fn new_with_desired(desired: DesiredRuntimeSpec) -> Self {
            let root = tempfile::Builder::new()
                .prefix("rp-")
                .tempdir_in("/tmp")
                .unwrap();
            let state = StateDirectory::unanchored(root.path().to_path_buf());
            let blob = Arc::new(ExactBlob::new(&desired));
            let ProvisionHeadRead::Ready { blank, target } = expected_provision_heads(
                blob.as_ref(),
                &desired,
                &desired.volumes[0],
                Instant::now() + Duration::from_secs(2),
            ) else {
                panic!("fixed manifest must produce exact provision heads")
            };
            let volume = &desired.volumes[0];
            let VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            } = &volume.acquire
            else {
                unreachable!()
            };
            let identity = AttachmentLineageIdentity {
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: fence(1),
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: transition_id.clone(),
                },
                node_id: desired.placement.node_id.clone(),
                placement_epoch: desired.placement.placement_epoch,
            };
            let request = NormalAcquireRequest {
                volume_id: volume.volume_id.clone(),
                transition_id: transition_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                expected_unowned_epoch: *expected_unowned_epoch,
                desired_revision: desired.desired_revision,
                placement_epoch: desired.placement.placement_epoch,
                lease_duration_ms: 60_000,
            };
            let result = NormalAcquireResult {
                volume_id: volume.volume_id.clone(),
                transition_id: transition_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                resulting_epoch: identity.attachment_epoch,
                resulting_head: blank.clone(),
                lease_expires_at: unix_ms(1_900_000_060_000),
            };
            let attachment = AuthorizedServingAttachment {
                identity: identity.clone(),
                size_bytes: volume.size_bytes,
                durability: volume.durability,
                head: blank.clone(),
                lease_expires_at: result.lease_expires_at,
                acquire_request: request.clone(),
                acquire_result: result.clone(),
            };
            drop(
                AuthorizedBlockdStore::new(state.clone())
                    .prepare(&desired, volume, &attachment)
                    .unwrap(),
            );
            let data_directory =
                authorized_blockd_data_directory(state.path(), &desired, &attachment.identity);
            let data_directory =
                HostPath::new(data_directory.to_str().unwrap().to_owned()).unwrap();
            let process_token = random('4');
            let step = ReconcileStep::ProvisionRootImage {
                provision_transition_id: random('3'),
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                scope_id: id(&format!("cats-root-{}.service", process_token.as_str())),
                control_socket_path: HostPath::new(format!(
                    "{}/root-provision.sock",
                    data_directory.as_str()
                ))
                .unwrap(),
                data_directory: data_directory.clone(),
                process_identity_token: process_token,
                size_bytes: volume.size_bytes,
                boot_image_digest: desired.runtime.boot_image_digest.clone(),
                expected_blank_head: blank.clone(),
                expected_provisioned_head: target,
            };
            let checkpoint = RuntimeCheckpoint {
                version: ContractVersion::V1,
                cat_id: desired.cat_id.clone(),
                node_id: desired.placement.node_id.clone(),
                placement_epoch: desired.placement.placement_epoch,
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                runtime_incarnation: None,
                stable_state: None,
                step,
                processes: Vec::new(),
                volumes: vec![observed_volume(
                    &desired,
                    &attachment,
                    &blank,
                    &data_directory,
                )],
                mounts: Vec::new(),
                networks: Vec::new(),
                guest_transport: GuestTransportEvidence::Unavailable,
                warm_snapshot: WarmSnapshotEvidence::Absent,
                lifecycle_admission: LifecycleAdmission::Closed,
                route_gates: Vec::new(),
                require_idle:
                    cats_api::runtime_reconciliation::RequireIdleCheckpoint::NotApplicable,
                updated_at_unix_ms: unix_ms(1_900_000_000_000),
            };
            let checkpoint_directory = state.path().join(CHECKPOINT_NAMESPACE);
            std::fs::create_dir(&checkpoint_directory).unwrap();
            let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id).unwrap();
            store.create(&checkpoint).unwrap();
            drop(store);
            let authority = Arc::new(FakeAuthority::new(VolumeRecord {
                volume_id: volume.volume_id.clone(),
                size_bytes: volume.size_bytes,
                durability: volume.durability,
                admin_state: VolumeAdminState::Active,
                head: blank,
                lease_owner: Some(volume.attachment_id.clone()),
                lease_epoch: attachment.identity.attachment_epoch,
                lease_expires_at: Some(attachment.lease_expires_at),
                last_transition: Some(LastVolumeTransition::NormalAcquire { request, result }),
            }));
            Self {
                _root: root,
                state,
                desired,
                checkpoint,
                attachment,
                authority,
                blob,
            }
        }

        fn context(&self, processes: Vec<ProcessEvidence>) -> RuntimeDesiredEffectContext {
            self.context_at(processes, 4, 12)
        }

        fn context_at(
            &self,
            processes: Vec<ProcessEvidence>,
            inventory_epoch: u64,
            inventory_read_position: u64,
        ) -> RuntimeDesiredEffectContext {
            self.context_with_lineage_path_at(
                processes,
                None,
                inventory_epoch,
                inventory_read_position,
            )
        }

        fn context_with_lineage_path(
            &self,
            processes: Vec<ProcessEvidence>,
            lineage_path: Option<HostPath>,
        ) -> RuntimeDesiredEffectContext {
            self.context_with_lineage_path_at(processes, lineage_path, 4, 12)
        }

        fn context_with_lineage_path_at(
            &self,
            processes: Vec<ProcessEvidence>,
            lineage_path: Option<HostPath>,
            inventory_epoch: u64,
            inventory_read_position: u64,
        ) -> RuntimeDesiredEffectContext {
            let mut runtime = ObservedRuntimeStatus {
                cat_id: self.desired.cat_id.clone(),
                applied_desired: Some(AppliedDesiredEvidence {
                    desired_revision: self.desired.desired_revision,
                    spec_digest: self.desired.spec_digest.clone(),
                    placement: self.desired.placement.clone(),
                    target: self.desired.target,
                }),
                runtime_incarnation: None,
                stable_state: None,
                step: self.checkpoint.step.clone(),
                checkpoint: CheckpointEvidence::Valid {
                    checkpoint_path: HostPath::new(
                        super::super::runtime_checkpoint_path(
                            &self.state.path().join(CHECKPOINT_NAMESPACE),
                            &self.desired.cat_id,
                        )
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    )
                    .unwrap(),
                    content_digest: checkpoint_content_digest(&self.checkpoint).unwrap(),
                    version: self.checkpoint.version,
                    cat_id: self.checkpoint.cat_id.clone(),
                    node_id: self.checkpoint.node_id.clone(),
                    desired_revision: self.checkpoint.desired_revision,
                    spec_digest: self.checkpoint.spec_digest.clone(),
                    placement_epoch: self.checkpoint.placement_epoch,
                    runtime_incarnation: None,
                    stable_state: None,
                    step: Box::new(self.checkpoint.step.clone()),
                    require_idle: Box::new(self.checkpoint.require_idle.clone()),
                    updated_at_unix_ms: self.checkpoint.updated_at_unix_ms,
                },
                processes,
                volumes: vec![observed_volume(
                    &self.desired,
                    &self.attachment,
                    &self.authority.record().head,
                    match &self.checkpoint.step {
                        ReconcileStep::ProvisionRootImage { data_directory, .. } => data_directory,
                        _ => unreachable!(),
                    },
                )],
                mounts: Vec::new(),
                networks: Vec::new(),
                guest_transport: GuestTransportEvidence::Unavailable,
                warm_snapshot: WarmSnapshotEvidence::Absent,
                lifecycle_admission: LifecycleAdmission::Closed,
                routes: Vec::new(),
                platform_guards: 0,
                conditions: vec![Condition::Progressing {
                    reason: ProgressingReason::ReconcileStep {
                        step: self.checkpoint.step.clone(),
                    },
                }],
            };
            if let Some(lineage_path) = lineage_path {
                runtime.volumes[0].local_lineages[0].data_directory = lineage_path;
            }
            let session = AgentSession {
                version: ContractVersion::V1,
                node_id: self.desired.placement.node_id.clone(),
                immutable_host_id: id("host_a"),
                node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
                agent_instance_id: random('5'),
                agent_session_epoch: epoch(2),
                registration_attempt_id: random('6'),
                guest_config_digest: self.desired.runtime.guest_config_digest.clone(),
                lease_deadline_unix_ms: unix_ms(1_900_000_120_000),
            };
            let digest = Sha256Digest::from_bytes([7; 32]);
            let attestation = AdmissionInventoryAttestation {
                version: ContractVersion::V1,
                node_id: session.node_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
                inventory_epoch: epoch(inventory_epoch),
                inventory_digest: digest.clone(),
                inventory_read_position: Sequence::new(inventory_read_position).unwrap(),
                accepted_at_unix_ms: unix_ms(1_900_000_000_000),
            };
            let mut observation = NodeObservation {
                version: ContractVersion::V1,
                observation_id: random('7'),
                node_id: session.node_id.clone(),
                node_boot_id: session.node_boot_id.clone(),
                agent_instance_id: session.agent_instance_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
                heartbeat_sequence: Sequence::new(9).unwrap(),
                observed_at_unix_ms: unix_ms(1_899_999_999_000),
                complete_inventory: true,
                inventory_epoch: attestation.inventory_epoch,
                inventory_digest: Some(digest),
                inventory_read_position: Some(attestation.inventory_read_position),
                key_ring_version: None,
                key_ring_digest: None,
                loaded_kids: Vec::new(),
                runtimes: vec![runtime],
                residue: Vec::new(),
            };
            // The admission constructor only requires equality with its
            // attestation, but use the real digest to keep this a valid wire
            // observation rather than a synthetic bypass.
            let digest = inventory_digest(&observation).unwrap();
            observation.inventory_digest = Some(digest.clone());
            let mut attestation = attestation;
            attestation.inventory_digest = digest;
            RuntimeDesiredEffectContext::for_test_with_admission(
                self.state.clone(),
                Instant::now() + Duration::from_secs(10),
                RuntimeDesiredEffectAdmission::for_test(session, observation, attestation),
            )
        }

        fn public_process(&self) -> ProcessEvidence {
            let ReconcileStep::ProvisionRootImage {
                volume_id,
                attachment_id,
                attachment_epoch,
                scope_id,
                control_socket_path,
                process_identity_token,
                ..
            } = &self.checkpoint.step
            else {
                unreachable!()
            };
            ProcessEvidence {
                role: ProcessRole::Blockd {
                    volume_id: volume_id.clone(),
                    attachment_id: attachment_id.clone(),
                    attachment_epoch: *attachment_epoch,
                },
                process_id: 41,
                process_start_time_ticks: WireU64::new(42).unwrap(),
                executable_path: HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
                scope_id: scope_id.clone(),
                control_socket_path: control_socket_path.clone(),
                state: ProcessState::Running,
                ownership_token: OwnershipTokenEvidence::Valid {
                    ownership_token: process_identity_token.clone(),
                },
                control_handshake: ControlHandshakeEvidence::Verified,
                observed_vm_shape: None,
            }
        }

        fn control_socket_path(&self) -> PathBuf {
            let ReconcileStep::ProvisionRootImage {
                control_socket_path,
                ..
            } = &self.checkpoint.step
            else {
                unreachable!()
            };
            PathBuf::from(control_socket_path.as_str())
        }

        fn stop_receipt_path(&self) -> PathBuf {
            self.control_socket_path()
                .parent()
                .unwrap()
                .join(super::super::authorized_blockd::ROOT_PROVISION_STOP_RECEIPT_FILE)
        }

        fn effect(
            &self,
            process: Arc<FakeProcessPort>,
            request: Arc<FakeRequestPort>,
        ) -> SignedRootProvisionEffect {
            self.effect_with_ports(
                process,
                Arc::new(FakeRetirementPort::unavailable()),
                request,
            )
        }

        fn effect_with_ports(
            &self,
            process: Arc<dyn RootProvisionProcessPort>,
            retirement: Arc<dyn RootProvisionProcessRetirementPort>,
            request: Arc<dyn RootProvisionRequestPort>,
        ) -> SignedRootProvisionEffect {
            SignedRootProvisionEffect::for_test(
                Arc::clone(&self.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&self.blob) as Arc<dyn BlobStore>,
                process,
                retirement,
                request,
                HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
            )
        }

        fn dispatcher(
            &self,
            process: Arc<FakeProcessPort>,
            request: Arc<FakeRequestPort>,
            mutations: Arc<NoSignedMutationPort>,
        ) -> SignedRunningEffect {
            self.dispatcher_with_retirement(
                process,
                Arc::new(FakeRetirementPort::unavailable()),
                request,
                mutations,
            )
        }

        fn dispatcher_with_retirement(
            &self,
            process: Arc<FakeProcessPort>,
            retirement: Arc<FakeRetirementPort>,
            request: Arc<FakeRequestPort>,
            mutations: Arc<NoSignedMutationPort>,
        ) -> SignedRunningEffect {
            let acquire = SignedRunningAcquireEffect::new(
                mutations,
                Arc::clone(&self.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&self.blob) as Arc<dyn BlobStore>,
                60_000,
            )
            .unwrap();
            SignedRunningEffect {
                acquire,
                provision: self.effect_with_ports(process, retirement, request),
            }
        }
    }

    fn recovery_context(fixture: &Fixture) -> RuntimePreScanRecoveryContext {
        let session = SessionBinding {
            node_id: fixture.desired.placement.node_id.clone(),
            node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
            agent_instance_id: random('5'),
            agent_session_epoch: epoch(2),
        };
        RuntimePreScanRecoveryContext::for_test(
            fixture.state.clone(),
            RuntimeSpineFullScan {
                session: session.clone(),
                heartbeat_sequence: Sequence::new(10).unwrap(),
                inventory_epoch: epoch(5),
                desired: DesiredReadSnapshot {
                    version: ContractVersion::V1,
                    session,
                    request_sequence: Sequence::new(20).unwrap(),
                    read_position: Sequence::new(21).unwrap(),
                    issued_at_unix_ms: unix_ms(1_900_000_005_000),
                    expires_at_unix_ms: unix_ms(1_900_000_035_000),
                    desired_specs: vec![fixture.desired.clone()],
                },
            },
            Instant::now() + Duration::from_secs(10),
        )
    }

    fn same_image_superseded_fixture() -> Fixture {
        let mut fixture = Fixture::new();
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::new(&fixture.desired));
        fixture
    }

    fn stopped_receipt_fixture() -> (
        Fixture,
        Arc<FakeProcessPort>,
        Arc<FakeRequestPort>,
        UnixListener,
    ) {
        let fixture = same_image_superseded_fixture();
        let socket_path = fixture.control_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::new(FakeRetirementPort::exact()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert!(fixture.stop_receipt_path().exists());
        (fixture, process, request, listener)
    }

    fn observed_volume(
        desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
        head: &cats_api::runtime_reconciliation::RemoteHead,
        data_directory: &HostPath,
    ) -> ObservedVolume {
        ObservedVolume {
            volume_intent_id: Some(desired.volumes[0].volume_intent_id.clone()),
            disk_id: Some(desired.volumes[0].disk_id.clone()),
            volume_id: desired.volumes[0].volume_id.clone(),
            disk_kind: ObservedDiskKind::Root,
            size_bytes: Some(desired.volumes[0].size_bytes),
            durability: Some(desired.volumes[0].durability),
            authority: VolumeAuthorityEvidence::Owned {
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                head: head.clone(),
            },
            local_lineages: vec![LocalVolumeLineage {
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                acquire_origin: attachment.identity.acquire_origin.clone(),
                node_id: attachment.identity.node_id.clone(),
                placement_epoch: attachment.identity.placement_epoch,
                local_durable_generation: head.generation,
                remote_durable_generation: head.generation,
                data_directory: data_directory.clone(),
                pending_pack_count: WireU64::new(0).unwrap(),
                fenced: false,
                state: LocalLineageState::Active,
            }],
            devices: Vec::new(),
        }
    }

    fn exact_process(
        expected: &super::super::RootProvisionProcessExpectation,
    ) -> RootProvisionProcessEvidence {
        RootProvisionProcessEvidence {
            process_id: 41,
            unit_main_process_id: 41,
            process_start_time_ticks: WireU64::new(42).unwrap(),
            executable_path: expected.executable_path.clone(),
            scope_id: expected.scope_id.clone(),
            cgroup_path: expected.cgroup_path.clone(),
            cgroup_process_ids: vec![41],
            control_socket_path: expected.control_socket_path.clone(),
            data_directory: expected.data_directory.clone(),
            ownership_token: expected.process_identity_token.clone(),
            handshake: RootProvisionBlockdHandshake {
                peer_process_id: 41,
                identity: expected.attachment.identity.clone(),
                size_bytes: expected.size_bytes,
                durability: expected.attachment.durability,
                remote_head: expected.expected_remote_head().clone(),
                process_identity_token: expected.process_identity_token.clone(),
                control_only: true,
                guest_io_enabled: false,
            },
        }
    }

    #[test]
    fn blank_full_inventory_starts_one_exact_control_process_and_rescans() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        let outcome = effect
            .try_apply(&fixture.context(Vec::new()), &fixture.desired)
            .unwrap();
        assert_eq!(outcome, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(process.starts.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exact_process_sends_once_then_authority_target_prevents_replay() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        let outcome = effect
            .try_apply(
                &fixture.context(vec![fixture.public_process()]),
                &fixture.desired,
            )
            .unwrap();
        assert_eq!(outcome, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(process.starts.load(Ordering::SeqCst), 0);

        // A new accepted full inventory observes the target head. Replaying
        // the same persisted transition performs no second control request.
        let outcome = effect
            .try_apply(
                &fixture.context(vec![fixture.public_process()]),
                &fixture.desired,
            )
            .unwrap();
        assert_eq!(outcome, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn serial_control_listener_completes_status_before_receiving_provision_request() {
        let fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head,
            ..
        } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        let socket_root = tempfile::Builder::new()
            .prefix("cats-rp-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket_path = socket_root.path().join("control.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let expected_request = provision_root_image_request(&fixture.checkpoint).unwrap();
        let mut expected_request_frame = b"provision_root_image ".to_vec();
        expected_request_frame
            .extend(encode_provision_root_image_request(&expected_request).unwrap());
        expected_request_frame.push(b'\n');
        let result = ProvisionRootImageResult {
            provision_transition_id: expected_request.provision_transition_id.clone(),
            volume_id: expected_request.volume_id.clone(),
            attachment_id: expected_request.attachment_id.clone(),
            attachment_epoch: expected_request.attachment_epoch,
            resulting_head: expected_request.expected_provisioned_head.clone(),
        };
        let mut response = b"OK ".to_vec();
        response.extend(encode_provision_root_image_result(&result).unwrap());
        response.push(b'\n');
        let authority = Arc::clone(&fixture.authority);
        let target = expected_provisioned_head.clone();
        let (events_tx, events_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut status = accept_before(&listener, deadline);
            status
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut status_line = Vec::new();
            BufReader::new(&mut status)
                .read_until(b'\n', &mut status_line)
                .unwrap();
            events_tx.send(status_line).unwrap();
            status.write_all(b"status-ok\n").unwrap();
            drop(status);

            let mut provision = accept_before(&listener, deadline);
            provision
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut provision_line = Vec::new();
            BufReader::new(&mut provision)
                .read_until(b'\n', &mut provision_line)
                .unwrap();
            events_tx.send(provision_line).unwrap();
            authority.set_head(target);
            provision.write_all(&response).unwrap();
        });

        let process_id = std::process::id();
        let start_time_ticks = 42;
        let expected_identity = ProcIdentity {
            pid: process_id,
            start_ticks: Some(start_time_ticks),
            exe: Some(Path::new("/usr/bin/cats-blockd").to_path_buf()),
        };
        let process = Arc::new(SerialStatusProcessPort {
            inspections: AtomicUsize::new(0),
            process_id,
            start_time_ticks,
            socket_path: socket_path.clone(),
        });
        let request = Arc::new(SerialRequestPort {
            process_identity: FixedProcessIdentity(expected_identity),
            socket_path,
            calls: AtomicUsize::new(0),
        });
        let effect = SignedRootProvisionEffect::for_test(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&fixture.blob) as Arc<dyn BlobStore>,
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::new(FakeRetirementPort::unavailable()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
        );
        let mut accepted_process = fixture.public_process();
        accepted_process.process_id = process_id;
        accepted_process.process_start_time_ticks = WireU64::new(start_time_ticks).unwrap();
        assert_eq!(
            effect
                .try_apply(&fixture.context(vec![accepted_process]), &fixture.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );

        assert_eq!(
            events_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            b"status\n",
            "positive calibration: the full status reinspection reached the serial listener"
        );
        assert_eq!(
            events_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            expected_request_frame,
            "the provision request must reach the same one-at-a-time listener after status closes"
        );
        server.join().unwrap();
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.authority.record().head, result.resulting_head);
    }

    #[test]
    fn real_request_with_mismatched_response_rereads_target_or_keeps_blank_unconfirmed() {
        for authority_reaches_target in [true, false] {
            let fixture = Fixture::new();
            let ReconcileStep::ProvisionRootImage {
                expected_provisioned_head,
                ..
            } = &fixture.checkpoint.step
            else {
                unreachable!()
            };
            let expected_request = provision_root_image_request(&fixture.checkpoint).unwrap();
            let mut expected_request_frame = b"provision_root_image ".to_vec();
            expected_request_frame
                .extend(encode_provision_root_image_request(&expected_request).unwrap());
            expected_request_frame.push(b'\n');

            let mut wrong_result = ProvisionRootImageResult {
                provision_transition_id: expected_request.provision_transition_id.clone(),
                volume_id: expected_request.volume_id.clone(),
                attachment_id: expected_request.attachment_id.clone(),
                attachment_epoch: expected_request.attachment_epoch,
                resulting_head: expected_request.expected_provisioned_head.clone(),
            };
            wrong_result.provision_transition_id = random('9');
            let mut wrong_response = b"OK ".to_vec();
            wrong_response.extend(encode_provision_root_image_result(&wrong_result).unwrap());
            wrong_response.push(b'\n');

            let socket_root = tempfile::Builder::new()
                .prefix("cats-rp-wrong-")
                .tempdir_in("/tmp")
                .unwrap();
            let socket_path = socket_root.path().join("control.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let authority = Arc::clone(&fixture.authority);
            let target = expected_provisioned_head.clone();
            let (request_tx, request_rx) = mpsc::channel();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request_frame = Vec::new();
                BufReader::new(&mut stream)
                    .read_until(b'\n', &mut request_frame)
                    .unwrap();
                request_tx.send(request_frame).unwrap();
                if authority_reaches_target {
                    authority.set_head(target);
                }
                stream.write_all(&wrong_response).unwrap();
            });

            let process_id = std::process::id();
            let start_time_ticks = 42;
            let process = Arc::new(FakeProcessPort::exact(process_id, start_time_ticks));
            let request = Arc::new(SerialRequestPort {
                process_identity: FixedProcessIdentity(ProcIdentity {
                    pid: process_id,
                    start_ticks: Some(start_time_ticks),
                    exe: Some(Path::new("/usr/bin/cats-blockd").to_path_buf()),
                }),
                socket_path,
                calls: AtomicUsize::new(0),
            });
            let effect = SignedRootProvisionEffect::for_test(
                Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&fixture.blob) as Arc<dyn BlobStore>,
                process,
                Arc::new(FakeRetirementPort::unavailable()),
                Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
                HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
            );
            let mut accepted_process = fixture.public_process();
            accepted_process.process_id = process_id;
            accepted_process.process_start_time_ticks = WireU64::new(start_time_ticks).unwrap();
            assert_eq!(
                effect
                    .try_apply(&fixture.context(vec![accepted_process]), &fixture.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory),
                "a post-send response mismatch remains authority-reread ambiguity"
            );
            assert_eq!(
                request_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                expected_request_frame,
                "positive calibration: the exact provision request reached the real socket"
            );
            server.join().unwrap();
            assert_eq!(request.calls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.authority.loads.load(Ordering::SeqCst), 2);
            assert_eq!(
                fixture.authority.record().head,
                if authority_reaches_target {
                    expected_request.expected_provisioned_head.clone()
                } else {
                    fixture.attachment.head.clone()
                },
                "a mismatched response cannot manufacture a target head or hide an authoritative one"
            );
        }
    }

    #[test]
    fn cancellation_after_real_request_rereads_target_before_refresh_and_never_resends() {
        let fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head,
            ..
        } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        let expected_request = provision_root_image_request(&fixture.checkpoint).unwrap();
        let mut expected_request_frame = b"provision_root_image ".to_vec();
        expected_request_frame
            .extend(encode_provision_root_image_request(&expected_request).unwrap());
        expected_request_frame.push(b'\n');

        let socket_root = tempfile::Builder::new()
            .prefix("cats-rp-cancel-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket_path = socket_root.path().join("control.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let authority = Arc::clone(&fixture.authority);
        let target = expected_provisioned_head.clone();
        let (request_tx, request_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request_frame = Vec::new();
            BufReader::new(&mut stream)
                .read_until(b'\n', &mut request_frame)
                .unwrap();
            authority.set_head(target);
            request_tx.send(request_frame).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        });

        let process_id = std::process::id();
        let start_time_ticks = 42;
        let process = Arc::new(FakeProcessPort::exact(process_id, start_time_ticks));
        let request = Arc::new(SerialRequestPort {
            process_identity: FixedProcessIdentity(ProcIdentity {
                pid: process_id,
                start_ticks: Some(start_time_ticks),
                exe: Some(Path::new("/usr/bin/cats-blockd").to_path_buf()),
            }),
            socket_path,
            calls: AtomicUsize::new(0),
        });
        let effect = Arc::new(SignedRootProvisionEffect::for_test(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&fixture.blob) as Arc<dyn BlobStore>,
            process,
            Arc::new(FakeRetirementPort::unavailable()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
        ));
        let mut accepted_process = fixture.public_process();
        accepted_process.process_id = process_id;
        accepted_process.process_start_time_ticks = WireU64::new(start_time_ticks).unwrap();
        let context = Arc::new(fixture.context(vec![accepted_process.clone()]));
        let desired = fixture.desired.clone();
        let worker_effect = Arc::clone(&effect);
        let worker_context = Arc::clone(&context);
        let worker =
            std::thread::spawn(move || worker_effect.try_apply(worker_context.as_ref(), &desired));

        assert_eq!(
            request_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            expected_request_frame,
            "positive calibration: the complete provision frame reached the real serial socket"
        );
        context.cancel_for_test();
        assert_eq!(
            worker.join().unwrap().unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory),
            "post-request cancellation must not suppress the mandatory authority reread"
        );
        assert_eq!(fixture.authority.loads.load(Ordering::SeqCst), 2);
        assert_eq!(
            fixture.authority.record().head,
            expected_provisioned_head.clone()
        );
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        server.join().unwrap();

        assert_eq!(
            effect
                .try_apply(&fixture.context(vec![accepted_process]), &fixture.desired,)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            request.calls.load(Ordering::SeqCst),
            1,
            "the authoritative target prevents a replay on the next fresh admission"
        );
    }

    #[test]
    fn exact_closed_conflict_with_blank_authority_stops_without_retry() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: true,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(process, Arc::clone(&request));
        let outcome = effect
            .try_apply(
                &fixture.context(vec![fixture.public_process()]),
                &fixture.desired,
            )
            .unwrap();
        assert_eq!(outcome, Some(stop_local()));
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.authority.loads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn foreign_lineage_path_stops_before_process_or_request_io() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        let context = fixture.context_with_lineage_path(
            Vec::new(),
            Some(HostPath::new("/var/lib/cats/foreign".to_owned()).unwrap()),
        );
        assert_eq!(
            effect.try_apply(&context, &fixture.desired).unwrap(),
            Some(stop_local())
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(process.starts.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authority_owner_drift_after_request_stops_despite_target_head() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: true,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(process, Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(request.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn process_replacement_after_accepted_scan_stops_without_request() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(43, 44));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.authority.record().head,
            fixture.attachment.head,
            "a replaced process must not receive the provision mutation"
        );
    }

    #[test]
    fn connected_process_identity_drift_stops_without_request_bytes() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: true,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authority.record().head, fixture.attachment.head);
    }

    #[test]
    fn unavailable_connection_refreshes_after_full_process_reinspection() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: true,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authority.record().head, fixture.attachment.head);
    }

    #[test]
    fn superseded_provision_falls_through_to_existing_stale_planner() {
        let mut fixture = Fixture::new();
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();

        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect(Arc::clone(&process), Arc::clone(&request));
        assert_eq!(
            effect
                .try_apply(&fixture.context(Vec::new()), &fixture.desired)
                .unwrap(),
            None,
            "the SignedRunningAcquireEffect stale planner must own this checkpoint"
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn live_superseded_process_is_receipted_stopped_cleaned_then_rebound_or_released() {
        for changed_image in [false, true] {
            let mut fixture = Fixture::new();
            if changed_image {
                let ReconcileStep::ProvisionRootImage {
                    expected_provisioned_head,
                    ..
                } = &fixture.checkpoint.step
                else {
                    unreachable!()
                };
                fixture
                    .authority
                    .set_head(expected_provisioned_head.clone());
            }
            fixture.desired.desired_revision = Revision::new(2).unwrap();
            if changed_image {
                fixture.desired.runtime.boot_image_digest = Sha256Digest::from_bytes([3; 32]);
            } else {
                fixture.desired.runtime.memory_bytes += 4096;
            }
            fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
            fixture.blob = if changed_image {
                Arc::new(ExactBlob::with_chunk(&fixture.desired, '4'))
            } else {
                Arc::new(ExactBlob::new(&fixture.desired))
            };

            let checkpoint_store = FileCheckpointStore::open(
                &fixture.state.path().join(CHECKPOINT_NAMESPACE),
                &fixture.desired.cat_id,
            )
            .unwrap();
            let checkpoint_path = checkpoint_store.path().to_path_buf();
            drop(checkpoint_store);
            let checkpoint_before = std::fs::read(&checkpoint_path).unwrap();
            let authority_before = fixture.authority.record();
            let socket_path = fixture.control_socket_path();
            let listener = UnixListener::bind(&socket_path).unwrap();
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();

            let process = Arc::new(FakeProcessPort::exact(41, 42));
            let retirement = Arc::new(FakeRetirementPort::exact());
            let request = Arc::new(FakeRequestPort {
                authority: Arc::clone(&fixture.authority),
                calls: AtomicUsize::new(0),
                conflict: false,
                mutate_owner: false,
                connect_failure: false,
                identity_mismatch: false,
            });
            let mutations = Arc::new(NoSignedMutationPort::default());
            let dispatcher = fixture.dispatcher_with_retirement(
                Arc::clone(&process),
                Arc::clone(&retirement),
                Arc::clone(&request),
                Arc::clone(&mutations),
            );
            let first = dispatcher
                .apply(
                    fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap();
            assert_eq!(
                first,
                RuntimeDesiredEffectOutcome::RefreshInventory,
                "stops={}, retirement={}, receipt={}",
                process.stops.load(Ordering::SeqCst),
                retirement.calls.load(Ordering::SeqCst),
                fixture.stop_receipt_path().exists(),
            );
            assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
            assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.authority.record(), authority_before);
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);
            assert!(fixture.stop_receipt_path().exists());

            // A real listener leaves its pathname behind when the owner exits.
            // Restart recovery must remove only that receipted refused inode.
            drop(listener);
            assert!(socket_path.exists());
            let recovery_retirement = Arc::new(FakeRetirementPort::absent());
            let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
                Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
                recovery_retirement,
            );
            assert_eq!(
                recovery.recover_one(recovery_context(&fixture)).unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: fixture.desired.cat_id.clone(),
                }
            );
            assert!(!socket_path.exists());
            assert!(fixture.stop_receipt_path().exists());
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);

            // Only a strictly newer full admission may retire the receipt.
            // That round still leaves the old Runtime checkpoint untouched.
            let absence_retirement = Arc::new(FakeRetirementPort::absent());
            let finish = fixture.dispatcher_with_retirement(
                Arc::clone(&process),
                absence_retirement,
                Arc::clone(&request),
                Arc::clone(&mutations),
            );
            assert_eq!(
                finish
                    .apply(fixture.context_at(Vec::new(), 4, 12), &fixture.desired)
                    .unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory
            );
            assert!(
                fixture.stop_receipt_path().exists(),
                "the stop-authorizing admission cannot also remove its receipt"
            );
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);
            assert_eq!(
                finish
                    .apply(fixture.context_at(Vec::new(), 5, 13), &fixture.desired)
                    .unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory
            );
            assert!(!fixture.stop_receipt_path().exists());
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);

            // A third accepted full owns the existing stale planner. Same
            // image rebinds; changed image writes CleanupRelease, and neither
            // disposition performs A22 or root-process I/O in this round.
            assert_eq!(
                finish
                    .apply(fixture.context_at(Vec::new(), 6, 14), &fixture.desired)
                    .unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory
            );
            let successor_store = FileCheckpointStore::open(
                &fixture.state.path().join(CHECKPOINT_NAMESPACE),
                &fixture.desired.cat_id,
            )
            .unwrap();
            let successor = successor_store.load().unwrap().unwrap();
            if changed_image {
                assert!(matches!(
                    successor.checkpoint().step,
                    ReconcileStep::CleanupRelease { .. }
                ));
            } else {
                assert_eq!(
                    successor.checkpoint().desired_revision,
                    fixture.desired.desired_revision
                );
                assert_eq!(
                    successor.checkpoint().spec_digest,
                    fixture.desired.spec_digest
                );
                assert!(matches!(
                    successor.checkpoint().step,
                    ReconcileStep::ProvisionRootImage { .. }
                ));
            }
            assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
            assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.authority.record(), authority_before);
        }
    }

    #[test]
    fn receipt_cleanup_allows_lease_renewal_but_preserves_on_authority_drift() {
        let (fixture, process, request, listener) = stopped_receipt_fixture();
        let socket_path = fixture.control_socket_path();
        drop(listener);
        fixture
            .authority
            .set_lease_expiry(unix_ms(1_900_000_120_000));
        let retirement = Arc::new(FakeRetirementPort::absent());
        let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
        );
        assert_eq!(
            recovery.recover_one(recovery_context(&fixture)).unwrap(),
            RuntimePreScanRecoveryOutcome::Recovered {
                cat_id: fixture.desired.cat_id.clone(),
            }
        );
        assert!(!socket_path.exists());
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);

        for drift in ["owner", "head", "marker"] {
            let (fixture, process, request, listener) = stopped_receipt_fixture();
            let socket_path = fixture.control_socket_path();
            drop(listener);
            match drift {
                "owner" => fixture.authority.set_owner(id("att_foreign")),
                "head" => {
                    let ReconcileStep::ProvisionRootImage {
                        expected_provisioned_head,
                        ..
                    } = &fixture.checkpoint.step
                    else {
                        unreachable!()
                    };
                    fixture
                        .authority
                        .set_head(expected_provisioned_head.clone());
                }
                "marker" => fixture.authority.clear_transition_marker(),
                _ => unreachable!(),
            }
            let retirement = Arc::new(FakeRetirementPort::absent());
            let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
                Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            );
            assert_eq!(
                recovery.recover_one(recovery_context(&fixture)).unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange,
                "{drift} drift must preserve the receipted socket"
            );
            assert!(socket_path.exists());
            assert!(fixture.stop_receipt_path().exists());
            assert_eq!(
                retirement.calls.load(Ordering::SeqCst),
                0,
                "authority drift must stop before physical absence inspection"
            );
            assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn maximum_endpoint_checkpoint_is_digest_bound_without_inflating_stop_receipt() {
        let mut old_desired = desired();
        old_desired.endpoints = (0..256)
            .map(|index| {
                let first_label = format!("e{index:03}{}", "a".repeat(59));
                EndpointIntent {
                    endpoint_id: id(&format!("e{index:03}{}", "x".repeat(124))),
                    hostname: Hostname::new(format!(
                        "{first_label}.{}.{}.{}",
                        "b".repeat(63),
                        "c".repeat(63),
                        "d".repeat(61)
                    ))
                    .unwrap(),
                    route_epoch: epoch(1),
                    protocol: HttpProtocol::Http,
                    target_port: 8080,
                }
            })
            .collect();
        old_desired.spec_digest = spec_digest(&old_desired).unwrap();
        let desired_bytes = encode_desired_runtime_spec(&old_desired).unwrap();
        assert_eq!(old_desired.endpoints.len(), 256);
        assert!(
            desired_bytes.len() > 100 * 1024,
            "maximum endpoint fixture did not calibrate a large valid Desired: {} bytes",
            desired_bytes.len()
        );

        let mut fixture = Fixture::new_with_desired(old_desired);
        let launch_checkpoint_path = fixture
            .control_socket_path()
            .parent()
            .unwrap()
            .join(super::super::authorized_blockd::LAUNCH_CHECKPOINT_FILE);
        let launch_checkpoint_bytes = std::fs::read(&launch_checkpoint_path).unwrap();
        assert!(launch_checkpoint_bytes.len() > desired_bytes.len());
        assert!(
            launch_checkpoint_bytes.len()
                <= super::super::authorized_blockd::MAX_LAUNCH_CHECKPOINT_BYTES
        );

        // Supersede the old checkpoint without changing its Volume lineage.
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::new(&fixture.desired));
        let socket_path = fixture.control_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::new(FakeRetirementPort::exact()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let receipt_bytes = std::fs::read(fixture.stop_receipt_path()).unwrap();
        let receipt =
            super::super::authorized_blockd::decode_root_provision_stop_receipt(&receipt_bytes)
                .unwrap();
        assert_eq!(
            receipt.authorized_checkpoint_content_digest(),
            &super::super::authorized_blockd::authorized_blockd_checkpoint_content_digest(
                &serde_json::from_slice(&launch_checkpoint_bytes).unwrap(),
            )
            .unwrap()
        );
        assert!(
            receipt_bytes.len() * 1024 <= 16 * 1024 * 1024,
            "1,024 maximum-bound checkpoints produced an excessive receipt scan budget: {} bytes each",
            receipt_bytes.len()
        );
        assert!(receipt_bytes.len() < launch_checkpoint_bytes.len() / 10);
        assert!(!receipt_bytes
            .windows(b"e000xxxxxxxxxxxxxxxx".len())
            .any(|window| window == b"e000xxxxxxxxxxxxxxxx"));
        assert!(
            super::super::authorized_blockd::decode_root_provision_stop_receipt(&vec![
                b' ';
                super::super::authorized_blockd::ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES
                    + 1
            ])
            .is_err(),
            "oversize receipt input must fail before JSON decoding"
        );
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        drop(listener);
    }

    #[test]
    fn late_live_socket_with_new_inode_is_never_removed_by_old_receipt() {
        let (fixture, process, request, listener) = stopped_receipt_fixture();
        let socket_path = fixture.control_socket_path();
        let old_inode = std::fs::symlink_metadata(&socket_path).unwrap().ino();
        drop(listener);
        let external = tempfile::Builder::new()
            .prefix("rp-old-socket-")
            .tempdir_in("/tmp")
            .unwrap();
        let retained_old_path = external.path().join("old.sock");
        std::fs::rename(&socket_path, &retained_old_path).unwrap();
        let replacement = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let new_inode = std::fs::symlink_metadata(&socket_path).unwrap().ino();
        assert_ne!(
            old_inode, new_inode,
            "positive calibration requires a new inode"
        );
        std::fs::remove_file(retained_old_path).unwrap();

        let retirement = Arc::new(FakeRetirementPort::absent());
        let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
        );
        recovery
            .recover_one(recovery_context(&fixture))
            .expect_err("a connectable replacement socket must remain a physical conflict");
        assert!(socket_path.exists());
        assert_eq!(
            std::fs::symlink_metadata(&socket_path).unwrap().ino(),
            new_inode
        );
        assert!(fixture.stop_receipt_path().exists());
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        drop(replacement);
    }

    #[test]
    fn duplicate_drift_special_bits_and_component_aba_stop_before_signal_or_receipt() {
        for inspection in [
            FakeRetirementInspection::Duplicate,
            FakeRetirementInspection::Drift,
        ] {
            let fixture = same_image_superseded_fixture();
            let checkpoint_path = fixture
                .state
                .path()
                .join(CHECKPOINT_NAMESPACE)
                .join(format!("cat-{}.checkpoint.json", fixture.desired.cat_id));
            let checkpoint_before = std::fs::read(&checkpoint_path).unwrap();
            let authority_before = fixture.authority.record();
            let socket_path = fixture.control_socket_path();
            let listener = UnixListener::bind(&socket_path).unwrap();
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let process = Arc::new(FakeProcessPort::exact(41, 42));
            let retirement = Arc::new(FakeRetirementPort::with_inspection(inspection));
            let request = Arc::new(FakeRequestPort {
                authority: Arc::clone(&fixture.authority),
                calls: AtomicUsize::new(0),
                conflict: false,
                mutate_owner: false,
                connect_failure: false,
                identity_mismatch: false,
            });
            let effect = fixture.effect_with_ports(
                Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
                Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
            );
            assert_eq!(
                effect
                    .try_apply(
                        &fixture.context(vec![fixture.public_process()]),
                        &fixture.desired,
                    )
                    .unwrap(),
                Some(stop_local())
            );
            assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
            assert_eq!(process.stops.load(Ordering::SeqCst), 0);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);
            assert!(!fixture.stop_receipt_path().exists());
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);
            assert_eq!(fixture.authority.record(), authority_before);
            drop(listener);
        }

        let fixture = same_image_superseded_fixture();
        let socket_path = fixture.control_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let data_directory = socket_path.parent().unwrap();
        std::fs::set_permissions(data_directory, std::fs::Permissions::from_mode(0o4700)).unwrap();
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let retirement = Arc::new(FakeRetirementPort::exact());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 0);
        assert_eq!(process.stops.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert!(!fixture.stop_receipt_path().exists());
        std::fs::set_permissions(data_directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(listener);

        let fixture = same_image_superseded_fixture();
        let socket_path = fixture.control_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let volume_directory = socket_path
            .ancestors()
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name == std::ffi::OsStr::new("volume-vol_root"))
            })
            .unwrap()
            .to_path_buf();
        let moved_directory = volume_directory.with_file_name("volume-moved");
        let current_directory = volume_directory.clone();
        let hook = Arc::new(move || {
            std::fs::rename(&current_directory, &moved_directory).unwrap();
            std::fs::create_dir(&current_directory).unwrap();
            std::fs::set_permissions(&current_directory, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        });
        let process = Arc::new(FakeProcessPort::exact(41, 42));
        let retirement = Arc::new(FakeRetirementPort::exact_with_hook(hook));
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(
                    &fixture.context(vec![fixture.public_process()]),
                    &fixture.desired,
                )
                .unwrap(),
            Some(stop_local())
        );
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stops.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert!(!fixture.stop_receipt_path().exists());
        drop(listener);
    }

    #[test]
    fn receipt_publication_and_socket_unlink_response_loss_recover_one_effect_per_round() {
        for target_also_exists in [false, true] {
            let (fixture, process, request, listener) = stopped_receipt_fixture();
            drop(listener);
            let target = fixture.stop_receipt_path();
            let temporary = target
                .with_file_name(super::super::authorized_blockd::ROOT_PROVISION_STOP_RECEIPT_TEMP);
            if target_also_exists {
                std::fs::copy(&target, &temporary).unwrap();
                std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            } else {
                std::fs::rename(&target, &temporary).unwrap();
            }
            let retirement = Arc::new(FakeRetirementPort::absent());
            let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
                Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
            );
            assert_eq!(
                recovery.recover_one(recovery_context(&fixture)).unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: fixture.desired.cat_id.clone(),
                }
            );
            assert!(target.exists());
            assert!(!temporary.exists());
            assert!(fixture.control_socket_path().exists());
            assert_eq!(
                retirement.calls.load(Ordering::SeqCst),
                0,
                "settling receipt publication is the only recovery effect in this round"
            );
            assert_eq!(process.stops.load(Ordering::SeqCst), 1);
            assert_eq!(request.calls.load(Ordering::SeqCst), 0);

            assert_eq!(
                recovery.recover_one(recovery_context(&fixture)).unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: fixture.desired.cat_id.clone(),
                }
            );
            assert!(!fixture.control_socket_path().exists());
            assert!(target.exists());
            assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);
        }

        let (fixture, process, request, listener) = stopped_receipt_fixture();
        let socket_path = fixture.control_socket_path();
        drop(listener);
        std::fs::remove_file(&socket_path).unwrap();
        let retirement = Arc::new(FakeRetirementPort::absent());
        let recovery = SignedRunningPublicationRecovery::with_root_process_retirement(
            Arc::clone(&fixture.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&retirement) as Arc<dyn RootProvisionProcessRetirementPort>,
        );
        assert_eq!(
            recovery.recover_one(recovery_context(&fixture)).unwrap(),
            RuntimePreScanRecoveryOutcome::Recovered {
                cat_id: fixture.desired.cat_id.clone(),
            },
            "an acknowledgement-lost unlink is parent-fsynced and forces a fresh full scan"
        );
        assert!(!socket_path.exists());
        assert!(fixture.stop_receipt_path().exists());
        assert_eq!(retirement.calls.load(Ordering::SeqCst), 1);

        let effect = fixture.effect_with_ports(
            Arc::clone(&process) as Arc<dyn RootProvisionProcessPort>,
            Arc::new(FakeRetirementPort::absent()),
            Arc::clone(&request) as Arc<dyn RootProvisionRequestPort>,
        );
        assert_eq!(
            effect
                .try_apply(&fixture.context_at(Vec::new(), 5, 13), &fixture.desired,)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert!(!fixture.stop_receipt_path().exists());
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dispatcher_rebinds_same_image_superseded_provision_without_process_or_request_io() {
        let mut fixture = Fixture::new();
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.memory_bytes += 4096;
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::new(&fixture.desired));
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let mutations = Arc::new(NoSignedMutationPort::default());
        let dispatcher = fixture.dispatcher(
            Arc::clone(&process),
            Arc::clone(&request),
            Arc::clone(&mutations),
        );
        assert_eq!(
            dispatcher
                .apply(fixture.context(Vec::new()), &fixture.desired)
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let store = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.desired.cat_id,
        )
        .unwrap();
        let rebound = store.load().unwrap().unwrap();
        assert_eq!(
            rebound.checkpoint().desired_revision,
            fixture.desired.desired_revision
        );
        assert_eq!(
            rebound.checkpoint().spec_digest,
            fixture.desired.spec_digest
        );
        assert!(matches!(
            rebound.checkpoint().step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dispatcher_checkpoints_release_for_changed_image_without_process_or_request_io() {
        let mut fixture = Fixture::new();
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head: old_target,
            ..
        } = &fixture.checkpoint.step
        else {
            unreachable!()
        };
        fixture.authority.set_head(old_target.clone());
        fixture.desired.desired_revision = Revision::new(2).unwrap();
        fixture.desired.runtime.boot_image_digest = Sha256Digest::from_bytes([3; 32]);
        fixture.desired.spec_digest = spec_digest(&fixture.desired).unwrap();
        fixture.blob = Arc::new(ExactBlob::with_chunk(&fixture.desired, '4'));
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
            connect_failure: false,
            identity_mismatch: false,
        });
        let mutations = Arc::new(NoSignedMutationPort::default());
        let dispatcher = fixture.dispatcher(
            Arc::clone(&process),
            Arc::clone(&request),
            Arc::clone(&mutations),
        );
        assert_eq!(
            dispatcher
                .apply(fixture.context(Vec::new()), &fixture.desired)
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let store = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.desired.cat_id,
        )
        .unwrap();
        let cleanup = store.load().unwrap().unwrap();
        assert!(
            matches!(
                cleanup.checkpoint().step,
                ReconcileStep::CleanupRelease { .. }
            ),
            "unexpected checkpoint: {:?}",
            cleanup.checkpoint().step
        );
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(request.calls.load(Ordering::SeqCst), 0);
        assert_eq!(mutations.calls.load(Ordering::SeqCst), 0);
    }
}
