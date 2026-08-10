//! One-step signed Running acquisition.
//!
//! This is deliberately only the `AcquireVolume` planner step. A current-
//! process accepted full inventory proves either that the fresh root is
//! physically empty or that one no-write local lineage is the exact durable
//! output of this checkpointed acquire. The exact request is fsynced before
//! A22 is called, and the grant is durably bound to the complete Desired before
//! the checkpoint advances to `ProvisionRootImage`. No process, frontend,
//! device, network or VMM port is reachable from this module.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AcquireOrigin, AgentSession, AppliedDesiredEvidence, AsciiText,
    CheckpointEvidence, CleanupRelease, CleanupTarget, Condition, ContractVersion,
    DesiredRuntimeSpec, DiskKind, FenceEpoch, Generation, GuestTransportEvidence, HostPath, Id,
    LastVolumeTransition, LifecycleAdmission, LocalLineageState, LocalVolumeLineage,
    NormalAcquireRequest, ObservedDiskKind, ObservedRuntimeStatus, ObservedVolume,
    ProgressingReason, RandomId128, ReconcileStep, RemoteHead, RequireIdleCheckpoint,
    RuntimeCheckpoint, RuntimeTarget, RuntimeTransition, RuntimeVolumeTransition,
    RuntimeVolumeTransitionRequest, SessionBinding, Sha256Digest, UnixMillis, VolumeAccess,
    VolumeAcquire, VolumeAcquireRequest, VolumeAdminState, VolumeAuthorityEvidence,
    VolumeDisposition, VolumeIntent, VolumeRecord, VolumeReleaseReplay, WarmSnapshotEvidence,
    WireU64,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, validate_authorized_serving_record,
    validate_volume_record, AttachmentLineageIdentity, AuthorityError, AuthorizedServingAttachment,
    VolumeDataAuthority,
};
use cats_storage::{read_image_manifest_until, BlobStore, ImageManifestReadError};

use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
    RuntimeDesiredEffectStopReason, RuntimePreScanRecovery, RuntimePreScanRecoveryContext,
    RuntimePreScanRecoveryOutcome,
};

use super::clean_slate_probes::{
    classify_local_publication_recovery, LocalPublicationRecoveryEvidence, CHECKPOINT_NAMESPACE,
};
use super::{
    authorized_blockd::authorized_blockd_data_directory, recover_normal_acquire_from_authority,
    recover_normal_release_from_authority, runtime_checkpoint_path, AuthorizedBlockdStore,
    ControlSignedNormalAcquireClient, FileCheckpointStore, NormalAcquireAcceptedContext,
    NormalAcquireAttempt, NormalAcquireAuthorityRecovery, NormalAcquireClientError,
    NormalReleaseAttempt, NormalReleaseAuthorityRecovery,
};

const MAX_LEASE_DURATION_MS: u64 = i64::MAX as u64;
const ROOT_PROVISION_SOCKET: &str = "root-provision.sock";

#[cfg(test)]
type AfterPrepareHook = Arc<dyn Fn(&RuntimeDesiredEffectContext) + Send + Sync>;

/// Narrow injectable boundary around the exact A19-signed A22 request.
pub(crate) trait SignedNormalAcquirePort: Send + Sync + 'static {
    fn acquire(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<NormalAcquireAttempt, NormalAcquireClientError>;

    fn release(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        expected_head: &RemoteHead,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<NormalReleaseAttempt, NormalAcquireClientError>;
}

impl<T> SignedNormalAcquirePort for ControlSignedNormalAcquireClient<T>
where
    T: super::A19SignedVolumeTransitionTransport + 'static,
{
    fn acquire(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<NormalAcquireAttempt, NormalAcquireClientError> {
        ControlSignedNormalAcquireClient::acquire(self, request, volume, accepted, deadline)
    }

    fn release(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        expected_head: &RemoteHead,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<NormalReleaseAttempt, NormalAcquireClientError> {
        ControlSignedNormalAcquireClient::release(
            self,
            request,
            volume,
            expected_head,
            accepted,
            deadline,
        )
    }
}

/// The first real signed Running effect. Its constructor rejects an invalid
/// lease budget before any accepted inventory can reach the effect lane.
pub(crate) struct SignedRunningAcquireEffect {
    volume_transition: Arc<dyn SignedNormalAcquirePort>,
    authority: Arc<dyn VolumeDataAuthority>,
    blob: Arc<dyn BlobStore>,
    lease_duration_ms: u64,
    definite_release_rejections: Mutex<BTreeSet<(Id, Id, RandomId128)>>,
    #[cfg(test)]
    after_prepare: Option<AfterPrepareHook>,
}

/// Exact restart-only recovery for the local publications surrounding A22.
/// It has no signed mutation client and cannot manufacture a new lease; the
/// current point-read authority must prove the persisted request already won.
pub(crate) struct SignedRunningPublicationRecovery {
    authority: Arc<dyn VolumeDataAuthority>,
}

impl SignedRunningPublicationRecovery {
    pub(crate) fn new(authority: Arc<dyn VolumeDataAuthority>) -> Self {
        Self { authority }
    }

    fn recover_authorized_blockd(
        &self,
        context: &RuntimePreScanRecoveryContext,
        cat_id: &Id,
    ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
        let desired = context
            .coordinates()
            .desired
            .desired_specs
            .iter()
            .find(|desired| &desired.cat_id == cat_id)
            .context("publication recovery Cat is absent from current Desired")?;
        let Some(volume) = recovery_volume(desired, &context.coordinates().session) else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&checkpoint_directory, cat_id)
            .context("open publication recovery checkpoint store")?;
        let Some(stored) = store
            .load()
            .context("load publication recovery checkpoint")?
        else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let Some(persisted) =
            persisted_acquire_request(stored.checkpoint(), desired, volume).cloned()
        else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let request = normal_acquire_request_with_binding(
            desired,
            context.coordinates().session.clone(),
            persisted,
        );
        context.check_active()?;
        let record = match self.authority.load_volume(&volume.volume_id) {
            Ok(record) => record,
            Err(AuthorityError::BackendUnknown) => {
                anyhow::bail!("volume authority unavailable during publication recovery")
            }
            Err(_) => return Ok(RuntimePreScanRecoveryOutcome::NoChange),
        };
        context.check_active()?;
        let attachment = match recover_normal_acquire_from_authority(&request, volume, &record) {
            Ok(NormalAcquireAuthorityRecovery::Granted(attachment)) => attachment,
            Ok(
                NormalAcquireAuthorityRecovery::RetryExact
                | NormalAcquireAuthorityRecovery::Blocked,
            ) => return Ok(RuntimePreScanRecoveryOutcome::NoChange),
            Err(_) => return Ok(RuntimePreScanRecoveryOutcome::NoChange),
        };
        AuthorizedBlockdStore::new(context.state_directory().clone())
            .prepare(desired, volume, &attachment)
            .context("recover exact authorized blockd publication")?;
        context.check_active()?;
        Ok(RuntimePreScanRecoveryOutcome::Recovered {
            cat_id: cat_id.clone(),
        })
    }
}

impl RuntimePreScanRecovery for SignedRunningPublicationRecovery {
    fn recover_one(
        &self,
        context: RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
        context.check_active()?;
        match classify_local_publication_recovery(&context)? {
            LocalPublicationRecoveryEvidence::None => Ok(RuntimePreScanRecoveryOutcome::NoChange),
            // Supersession is typed evidence, but it is not a publication
            // window. Rebinding requires the complete A20 physical scan; a
            // point read here cannot prove that no extra lineage or device
            // exists and therefore must not overwrite the predecessor.
            LocalPublicationRecoveryEvidence::SupersededCheckpoint { cat_id } => {
                anyhow::ensure!(
                    context
                        .coordinates()
                        .desired
                        .desired_specs
                        .iter()
                        .any(|desired| desired.cat_id == cat_id),
                    "superseded checkpoint Cat is absent from current Desired"
                );
                Ok(RuntimePreScanRecoveryOutcome::NoChange)
            }
            LocalPublicationRecoveryEvidence::CheckpointTemp { cat_id } => {
                let checkpoint_directory =
                    context.state_directory().path().join(CHECKPOINT_NAMESPACE);
                drop(
                    FileCheckpointStore::open(&checkpoint_directory, &cat_id)
                        .context("settle exact checkpoint temp publication")?,
                );
                context.check_active()?;
                Ok(RuntimePreScanRecoveryOutcome::Recovered { cat_id })
            }
            LocalPublicationRecoveryEvidence::AuthorizedBlockd { cat_id } => {
                self.recover_authorized_blockd(&context, &cat_id)
            }
        }
    }
}

impl SignedRunningAcquireEffect {
    pub(crate) fn validate_lease_duration(lease_duration_ms: u64) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=MAX_LEASE_DURATION_MS).contains(&lease_duration_ms),
            "signed normal-acquire lease duration is outside the frozen wire range"
        );
        Ok(())
    }

    pub(crate) fn new(
        acquire: Arc<dyn SignedNormalAcquirePort>,
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        lease_duration_ms: u64,
    ) -> anyhow::Result<Self> {
        Self::validate_lease_duration(lease_duration_ms)?;
        Ok(Self {
            volume_transition: acquire,
            authority,
            blob,
            lease_duration_ms,
            definite_release_rejections: Mutex::new(BTreeSet::new()),
            #[cfg(test)]
            after_prepare: None,
        })
    }

    #[cfg(test)]
    fn with_after_prepare(mut self, hook: AfterPrepareHook) -> Self {
        self.after_prepare = Some(hook);
        self
    }

    /// Handle every durable state which is not the canonical current
    /// pre-acquire path. `None` deliberately falls through to `apply_acquire`;
    /// every returned outcome either published exactly one new checkpoint or
    /// consumed one already-checkpointed A22 mutation.
    fn apply_checkpoint_replan(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        let accepted = match context.accepted_full() {
            Ok(accepted) => accepted,
            Err(_) => return Ok(Some(stop_local())),
        };
        let admission =
            match validate_prelaunch_admission(desired, accepted, context.state_directory().path())
            {
                PrelaunchAdmissionDecision::Exact(admission) => admission,
                PrelaunchAdmissionDecision::RefreshInventory => {
                    return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
                }
                PrelaunchAdmissionDecision::StopLocal => return Ok(Some(stop_local())),
            };
        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &admission.runtime.checkpoint
        else {
            return Ok(None);
        };
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id)
            .context("open signed Running checkpoint store for replan")?;
        if !path_matches(checkpoint_path, store.path()) {
            return Ok(Some(stop_local()));
        }
        let Some(stored) = store
            .load()
            .context("reread signed Running checkpoint for replan")?
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest
            || stored.checkpoint().step != admission.runtime.step
        {
            // The accepted scan no longer names the target file. Do not use
            // its physical evidence to overwrite a concurrent successor.
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let checkpoint = stored.checkpoint();
        let current_binding = checkpoint.desired_revision == desired.desired_revision
            && checkpoint.spec_digest == desired.spec_digest
            && checkpoint.placement_epoch == desired.placement.placement_epoch;
        if !current_binding {
            return self
                .plan_superseded_checkpoint(context, desired, accepted, &admission, &store, &stored)
                .map(Some);
        }

        match &checkpoint.step {
            ReconcileStep::AcquireVolume { request }
                if canonical_current_acquire_is_unowned(
                    desired,
                    admission.volume,
                    admission.runtime,
                    request,
                ) =>
            {
                Ok(None)
            }
            ReconcileStep::AcquireVolume { .. } => self
                .plan_current_owned_acquire(context, desired, accepted, &admission, &store, &stored)
                .map(Some),
            ReconcileStep::CleanupRelease { cleanup } => self
                .apply_cleanup_release(
                    context, desired, accepted, &admission, cleanup, &store, &stored,
                )
                .map(Some),
            ReconcileStep::ProvisionRootImage { .. } => {
                // Provision execution is a later composed step. Reaching a
                // current, fully typed checkpoint is successful stale-plan
                // convergence and must force a new scan, never an acquire.
                Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
            ReconcileStep::Quarantined => Ok(Some(stop_local())),
            _ => Ok(Some(stop_local())),
        }
    }

    fn plan_superseded_checkpoint(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        admission: &PrelaunchAdmission<'_>,
        store: &FileCheckpointStore,
        predecessor: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        match &predecessor.checkpoint().step {
            ReconcileStep::AcquireVolume { request } => self.plan_superseded_acquire(
                context,
                desired,
                accepted,
                admission,
                request,
                store,
                predecessor,
            ),
            ReconcileStep::ProvisionRootImage { .. } => self.plan_superseded_provision(
                context,
                desired,
                accepted,
                admission,
                store,
                predecessor,
            ),
            _ => Ok(stop_local()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_superseded_acquire(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        admission: &PrelaunchAdmission<'_>,
        old_request: &VolumeAcquireRequest,
        store: &FileCheckpointStore,
        predecessor: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let old_checkpoint = predecessor.checkpoint();
        let Some(old_observed) = checkpoint_volume_for_acquire(old_checkpoint, old_request) else {
            return Ok(stop_local());
        };
        let [current_observed] = admission.runtime.volumes.as_slice() else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        if current_observed.volume_id != admission.volume.volume_id {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        }
        let no_local_effect = admission.runtime.processes.is_empty()
            && admission
                .runtime
                .volumes
                .iter()
                .all(|volume| volume.local_lineages.is_empty() && volume.devices.is_empty());
        if no_local_effect
            && observed_is_current_unowned(current_observed, admission.volume)
            && observed_is_unowned(old_observed)
        {
            context.check_active()?;
            let current_record = match self.authority.load_volume(&admission.volume.volume_id) {
                Ok(record) => record,
                Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
            };
            if !record_is_current_unowned(&current_record, admission.volume) {
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
            }
            let old_is_still_unowned = if old_observed.volume_id != admission.volume.volume_id {
                context.check_active()?;
                let old_record = match self.authority.load_volume(&old_observed.volume_id) {
                    Ok(record) => record,
                    Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
                };
                record_matches_unowned_observation(&old_record, old_observed)
            } else {
                true
            };
            if old_is_still_unowned {
                context.check_active()?;
                let request = normal_acquire_request(
                    desired,
                    admission.volume,
                    accepted.session(),
                    self.lease_duration_ms,
                );
                let replacement = acquire_checkpoint(
                    desired,
                    admission.volume,
                    request.transition,
                    accepted.attestation().accepted_at_unix_ms,
                );
                store
                    .replace(predecessor, &replacement)
                    .context("atomically rebind superseded pre-effect acquire")?;
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
            }
        }

        context.check_active()?;
        let record = match self.authority.load_volume(&old_observed.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        let Some(attachment) =
            attachment_from_checkpoint_acquire(old_checkpoint, old_request, &record)
        else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        if attachment_is_adoptable(desired, admission.volume, old_observed, &attachment)
            && record.head == blank_head()
            && local_lineage_is_absent_or_exact(current_observed, &attachment.identity)
        {
            let request = normal_acquire_request(
                desired,
                admission.volume,
                accepted.session(),
                self.lease_duration_ms,
            );
            let mut replacement = acquire_checkpoint(
                desired,
                admission.volume,
                request.transition,
                accepted.attestation().accepted_at_unix_ms,
            );
            replacement.volumes = vec![current_observed.clone()];
            store
                .replace(predecessor, &replacement)
                .context("stage current adoption journal for superseded acquire")?;
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }
        if release_is_supported_by_current_desired(
            desired,
            admission.volume,
            current_observed,
            &attachment,
        ) {
            return self.persist_cleanup_release(
                desired,
                accepted,
                admission.runtime,
                admission.volume,
                &attachment,
                &record.head,
                store,
                predecessor,
            );
        }
        self.stop_unsupported_conflict(desired, accepted, admission.runtime, store, predecessor)
    }

    fn plan_current_owned_acquire(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        admission: &PrelaunchAdmission<'_>,
        store: &FileCheckpointStore,
        predecessor: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let Some(observed) = unique_observed_volume(admission.runtime, &admission.volume.volume_id)
        else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        let VolumeAcquire::Normal {
            expected_unowned_epoch,
            ..
        } = admission.volume.acquire
        else {
            return Ok(stop_local());
        };
        let Some(expected_identity) =
            expected_attachment_identity(desired, admission.volume, expected_unowned_epoch)
        else {
            return Ok(stop_local());
        };
        if !local_lineage_is_absent_or_exact(observed, &expected_identity) {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        }
        context.check_active()?;
        let record = match self.authority.load_volume(&admission.volume.volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        let Some(attachment) = attachment_from_current_desired(desired, admission.volume, &record)
        else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        if record.head != blank_head()
            || !observed_authority_matches_attachment(observed, &attachment)
            || !local_lineage_is_absent_or_exact(observed, &attachment.identity)
        {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        }
        let (expected_blank_head, expected_provisioned_head) =
            match self.read_image_heads(context, desired, admission.volume)? {
                ImageHeadDecision::Exact(heads) => heads,
                ImageHeadDecision::RetryExact => {
                    return Ok(RuntimeDesiredEffectOutcome::RetryExact)
                }
                ImageHeadDecision::StopLocal => return Ok(stop_local()),
            };
        self.persist_provision_step(
            context,
            desired,
            admission.volume,
            predecessor,
            attachment,
            expected_blank_head,
            expected_provisioned_head,
            store,
            accepted.attestation().accepted_at_unix_ms,
            true,
        )
    }

    fn plan_superseded_provision(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        admission: &PrelaunchAdmission<'_>,
        store: &FileCheckpointStore,
        predecessor: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let old_checkpoint = predecessor.checkpoint();
        let ReconcileStep::ProvisionRootImage {
            volume_id,
            attachment_id,
            attachment_epoch,
            expected_blank_head: old_blank,
            expected_provisioned_head: old_target,
            ..
        } = &old_checkpoint.step
        else {
            unreachable!("caller selected ProvisionRootImage")
        };
        let [old_observed] = admission.runtime.volumes.as_slice() else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        if old_observed.volume_id != *volume_id
            || old_observed.volume_id != admission.volume.volume_id
        {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        }
        let [old_lineage] = old_observed.local_lineages.as_slice() else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        let identity = AttachmentLineageIdentity {
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: *attachment_epoch,
            acquire_origin: old_lineage.acquire_origin.clone(),
            node_id: old_checkpoint.node_id.clone(),
            placement_epoch: old_checkpoint.placement_epoch,
        };
        context.check_active()?;
        let record = match self.authority.load_volume(volume_id) {
            Ok(record) => record,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        let prepared = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .reopen_adopted(desired, admission.volume, &identity)
        {
            Ok(prepared) => prepared,
            Err(_) => {
                return self.stop_unsupported_conflict(
                    desired,
                    accepted,
                    admission.runtime,
                    store,
                    predecessor,
                )
            }
        };
        let attachment = prepared.checkpoint().attachment.clone();
        if !record_matches_attachment_lineage(&record, &attachment)
            || !observed_authority_matches_attachment(old_observed, &attachment)
        {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        }
        let (current_blank, current_target) =
            match self.read_image_heads(context, desired, admission.volume)? {
                ImageHeadDecision::Exact(heads) => heads,
                ImageHeadDecision::RetryExact => {
                    return Ok(RuntimeDesiredEffectOutcome::RetryExact)
                }
                ImageHeadDecision::StopLocal => return Ok(stop_local()),
            };
        let head_is_adoptable = record.head == current_blank
            || (record.head == *old_target && *old_target == current_target);
        if attachment_is_adoptable(desired, admission.volume, old_observed, &attachment)
            && *old_blank == current_blank
            && head_is_adoptable
        {
            let replacement = rebound_provision_checkpoint(
                desired,
                admission.volume,
                admission.runtime,
                &attachment,
                prepared.data_directory(),
                current_blank,
                current_target,
                accepted.attestation().accepted_at_unix_ms,
            )?;
            context.check_active()?;
            store
                .replace(predecessor, &replacement)
                .context("rebind superseded provision checkpoint to current Desired")?;
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }
        if release_is_supported_by_current_desired(
            desired,
            admission.volume,
            old_observed,
            &attachment,
        ) {
            drop(prepared);
            return self.persist_cleanup_release(
                desired,
                accepted,
                admission.runtime,
                admission.volume,
                &attachment,
                &record.head,
                store,
                predecessor,
            );
        }
        self.stop_unsupported_conflict(desired, accepted, admission.runtime, store, predecessor)
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_cleanup_release(
        &self,
        desired: &DesiredRuntimeSpec,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        runtime: &ObservedRuntimeStatus,
        volume: &VolumeIntent,
        attachment: &AuthorizedServingAttachment,
        head: &RemoteHead,
        store: &FileCheckpointStore,
        predecessor: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let Some(desired_read_position) = accepted.desired_read_position() else {
            return Ok(stop_local());
        };
        let [observed] = runtime.volumes.as_slice() else {
            return self.stop_unsupported_conflict(desired, accepted, runtime, store, predecessor);
        };
        if observed.volume_id != volume.volume_id
            || !observed_authority_matches_attachment(observed, attachment)
            || observed.local_lineages.len() != 1
            || !local_lineage_exact(
                &observed.local_lineages[0],
                &attachment.identity,
                head.generation,
            )
        {
            return self.stop_unsupported_conflict(desired, accepted, runtime, store, predecessor);
        }
        let cleanup = CleanupRelease {
            target: CleanupTarget::Volume {
                volume_id: volume.volume_id.clone(),
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
            },
            inventory_session: session_binding(accepted.session()),
            inventory_epoch: accepted.attestation().inventory_epoch,
            inventory_read_position: accepted.attestation().inventory_read_position,
            desired_read_position,
            volume_release: Some(VolumeReleaseReplay {
                release_transition_id: random_id(),
                generation: head.generation,
                disposition: volume.disposition.clone(),
            }),
        };
        let replacement = closed_checkpoint(
            desired,
            ReconcileStep::CleanupRelease { cleanup },
            runtime.volumes.clone(),
            accepted.attestation().accepted_at_unix_ms,
        );
        store
            .replace(predecessor, &replacement)
            .context("stage exact stale-lineage release before A22")?;
        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
    }

    fn stop_unsupported_conflict(
        &self,
        _desired: &DesiredRuntimeSpec,
        _accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        _runtime: &ObservedRuntimeStatus,
        _store: &FileCheckpointStore,
        _predecessor: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        // Frozen V1 has a terminal `Condition::Quarantined { reason }`, but
        // its persisted `ReconcileStep::Quarantined` carries no reason. Do not
        // destroy the exact predecessor and later manufacture an unverifiable
        // terminal reason. Unsupported conflicts remain physically closed and
        // byte-for-byte intact for a newer contract or operator repair.
        Ok(stop_local())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_cleanup_release(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
        admission: &PrelaunchAdmission<'_>,
        cleanup: &CleanupRelease,
        store: &FileCheckpointStore,
        predecessor: &super::StoredCheckpoint,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let Some(observed) = unique_observed_volume(admission.runtime, &admission.volume.volume_id)
        else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        let (
            CleanupTarget::Volume {
                volume_id,
                attachment_id,
                attachment_epoch,
            },
            Some(replay),
        ) = (&cleanup.target, &cleanup.volume_release)
        else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        if volume_id != &admission.volume.volume_id
            || attachment_id != &admission.volume.attachment_id
            || replay.disposition != admission.volume.disposition
        {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        }
        let Some(desired_read_position) = accepted.desired_read_position() else {
            return Ok(stop_local());
        };
        if cleanup.inventory_session != session_binding(accepted.session())
            || cleanup.inventory_epoch != accepted.attestation().inventory_epoch
            || cleanup.inventory_read_position != accepted.attestation().inventory_read_position
            || cleanup.desired_read_position != desired_read_position
        {
            let mut rebound = cleanup.clone();
            rebound.inventory_session = session_binding(accepted.session());
            rebound.inventory_epoch = accepted.attestation().inventory_epoch;
            rebound.inventory_read_position = accepted.attestation().inventory_read_position;
            rebound.desired_read_position = desired_read_position;
            let replacement = closed_checkpoint(
                desired,
                ReconcileStep::CleanupRelease { cleanup: rebound },
                predecessor.checkpoint().volumes.clone(),
                accepted.attestation().accepted_at_unix_ms,
            );
            store
                .replace(predecessor, &replacement)
                .context("rebind stale cleanup to the current accepted A20 cursor")?;
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }
        let expected_head = observed_authority_head(observed).cloned();
        let Some(expected_head) = expected_head else {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        };
        if matches!(observed.authority, VolumeAuthorityEvidence::Unowned { .. }) {
            context.check_active()?;
            let record = match self.authority.load_volume(volume_id) {
                Ok(record) => record,
                Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
            };
            let request = release_transition_request(desired, cleanup.clone());
            return match recover_normal_release_from_authority(
                &request,
                admission.volume,
                &expected_head,
                &record,
            ) {
                Ok(NormalReleaseAuthorityRecovery::Released(_)) => self.stop_unsupported_conflict(
                    desired,
                    accepted,
                    admission.runtime,
                    store,
                    predecessor,
                ),
                Ok(NormalReleaseAuthorityRecovery::RetryExact) => {
                    Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
                }
                Ok(NormalReleaseAuthorityRecovery::Blocked) | Err(_) => self
                    .stop_unsupported_conflict(
                        desired,
                        accepted,
                        admission.runtime,
                        store,
                        predecessor,
                    ),
            };
        }
        if !matches!(
            observed.authority,
            VolumeAuthorityEvidence::Owned {
                ref attachment_id,
                attachment_epoch: observed_epoch,
                ..
            } if attachment_id == &admission.volume.attachment_id
                && observed_epoch == *attachment_epoch
        ) {
            return self.stop_unsupported_conflict(
                desired,
                accepted,
                admission.runtime,
                store,
                predecessor,
            );
        }
        let rejection_key = (
            desired.cat_id.clone(),
            volume_id.clone(),
            replay.release_transition_id.clone(),
        );
        if self
            .definite_release_rejections
            .lock()
            .map_err(|_| anyhow::anyhow!("definite release rejection set is poisoned"))?
            .contains(&rejection_key)
        {
            return Ok(stop_local());
        }
        let request = release_transition_request(desired, cleanup.clone());
        let accepted_context = NormalAcquireAcceptedContext {
            session: accepted.session().clone(),
            inventory_attestation: accepted.attestation().clone(),
        };
        context.check_active()?;
        let attempt = match self.volume_transition.release(
            &request,
            admission.volume,
            &expected_head,
            &accepted_context,
            context.deadline(),
        ) {
            Ok(attempt) => attempt,
            Err(_) => return Ok(stop_local()),
        };
        match attempt {
            NormalReleaseAttempt::Released(_) => Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
            NormalReleaseAttempt::RetryExact => Ok(RuntimeDesiredEffectOutcome::RetryExact),
            NormalReleaseAttempt::RefreshInventory => {
                Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            NormalReleaseAttempt::ReplanDesired => Ok(RuntimeDesiredEffectOutcome::ReplanDesired),
            NormalReleaseAttempt::SessionReplacementRequired => {
                Ok(RuntimeDesiredEffectOutcome::SessionReplacementRequired)
            }
            NormalReleaseAttempt::IdentityRepairRequired => {
                Ok(RuntimeDesiredEffectOutcome::IdentityRepairRequired)
            }
            NormalReleaseAttempt::AuthorityRejected(reason) => {
                Ok(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::AuthorityRejected(reason),
                ))
            }
            NormalReleaseAttempt::StopForLocalContract => {
                self.definite_release_rejections
                    .lock()
                    .map_err(|_| anyhow::anyhow!("definite release rejection set is poisoned"))?
                    .insert(rejection_key);
                Ok(stop_local())
            }
            NormalReleaseAttempt::StopForDeploymentMismatch => {
                Ok(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::DeploymentMismatch,
                ))
            }
            NormalReleaseAttempt::Ambiguous => {
                context.check_active()?;
                let record = match self.authority.load_volume(volume_id) {
                    Ok(record) => record,
                    Err(_) => return Ok(RuntimeDesiredEffectOutcome::RetryExact),
                };
                match recover_normal_release_from_authority(
                    &request,
                    admission.volume,
                    &expected_head,
                    &record,
                ) {
                    Ok(NormalReleaseAuthorityRecovery::Released(_)) => {
                        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
                    }
                    Ok(NormalReleaseAuthorityRecovery::RetryExact) => {
                        Ok(RuntimeDesiredEffectOutcome::RetryExact)
                    }
                    Ok(NormalReleaseAuthorityRecovery::Blocked) | Err(_) => Ok(stop_local()),
                }
            }
        }
    }

    fn read_image_heads(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
    ) -> anyhow::Result<ImageHeadDecision> {
        context.check_active()?;
        let manifest = match read_image_manifest_until(
            self.blob.as_ref(),
            &desired.runtime.boot_image_digest,
            context.deadline(),
        ) {
            Ok(manifest) => manifest,
            Err(
                ImageManifestReadError::NotFound { .. }
                | ImageManifestReadError::BackendUnavailable { .. },
            ) => return Ok(ImageHeadDecision::RetryExact),
            Err(
                ImageManifestReadError::TooLarge { .. } | ImageManifestReadError::Corrupt { .. },
            ) => return Ok(ImageHeadDecision::StopLocal),
        };
        let image_identity =
            match cats_blockd::format::image_root_identity(&manifest, volume.size_bytes) {
                Ok(identity) => identity,
                Err(_) => return Ok(ImageHeadDecision::StopLocal),
            };
        Ok(ImageHeadDecision::Exact((
            blank_head(),
            RemoteHead {
                generation: Generation::new(1).expect("one is a valid generation"),
                root_hash: Some(Sha256Digest::from_bytes(image_identity.root_hash)),
                root_object_id: Some(
                    AsciiText::new(image_identity.root_object_id)
                        .expect("a computed map object ID is printable ASCII"),
                ),
            },
        )))
    }

    fn apply_acquire(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let accepted = match context.accepted_full() {
            Ok(accepted) => accepted,
            Err(_) => return Ok(stop_local()),
        };
        let volume =
            match validate_slice_and_admission(desired, accepted, context.state_directory().path())
            {
                AdmissionDecision::Exact(volume) => volume,
                AdmissionDecision::RefreshInventory => {
                    return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
                }
                AdmissionDecision::StopLocal => return Ok(stop_local()),
            };

        // Manifest reads and target calculation are effect-free. Do them
        // before creating the first checkpoint so an unavailable image does
        // not acquire a lease that this step cannot yet journal forward.
        context.check_active()?;
        let (expected_blank_head, expected_provisioned_head) =
            match expected_provision_heads(self.blob.as_ref(), desired, volume, context.deadline())
            {
                ProvisionHeadRead::Ready { blank, target } => (blank, target),
                ProvisionHeadRead::Retry => return Ok(RuntimeDesiredEffectOutcome::RetryExact),
                ProvisionHeadRead::Invalid => return Ok(stop_local()),
            };
        context.check_active()?;

        let fresh_request =
            normal_acquire_request(desired, volume, accepted.session(), self.lease_duration_ms);
        let acquire_checkpoint = acquire_checkpoint(
            desired,
            volume,
            fresh_request.transition.clone(),
            accepted.attestation().accepted_at_unix_ms,
        );
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id)
            .context("open signed Running checkpoint store")?;
        let (predecessor, request) = match store.load().context("load signed Running checkpoint")? {
            None => (
                store
                    .create(&acquire_checkpoint)
                    .context("persist normal-acquire request before authority mutation")?,
                fresh_request,
            ),
            Some(stored) => match persisted_acquire_request(stored.checkpoint(), desired, volume) {
                Some(persisted) => {
                    let persisted = persisted.clone();
                    (
                        stored,
                        normal_acquire_request_with_payload(desired, accepted.session(), persisted),
                    )
                }
                None if provision_checkpoint_is_bound(
                    stored.checkpoint(),
                    desired,
                    volume,
                    context.state_directory().path(),
                    &expected_blank_head,
                    &expected_provisioned_head,
                ) =>
                {
                    // A previous invocation crossed the directory durability
                    // barrier and a fresh accepted scan proved the complete
                    // next-step checkpoint. This acquire unit is converged;
                    // do not perform a second mutation.
                    return Ok(RuntimeDesiredEffectOutcome::Applied);
                }
                None => return Ok(stop_local()),
            },
        };

        context.check_active()?;
        let accepted_context = NormalAcquireAcceptedContext {
            session: accepted.session().clone(),
            inventory_attestation: accepted.attestation().clone(),
        };
        let attempt = match self.volume_transition.acquire(
            &request,
            volume,
            &accepted_context,
            context.deadline(),
        ) {
            Ok(attempt) => attempt,
            Err(_) => return Ok(stop_local()),
        };
        let attachment = match attempt {
            NormalAcquireAttempt::Granted(attachment) => attachment,
            NormalAcquireAttempt::RetryExact => return Ok(RuntimeDesiredEffectOutcome::RetryExact),
            NormalAcquireAttempt::RefreshInventory => {
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            NormalAcquireAttempt::ReplanDesired => {
                return Ok(RuntimeDesiredEffectOutcome::ReplanDesired)
            }
            NormalAcquireAttempt::SessionReplacementRequired => {
                return Ok(RuntimeDesiredEffectOutcome::SessionReplacementRequired)
            }
            NormalAcquireAttempt::IdentityRepairRequired => {
                return Ok(RuntimeDesiredEffectOutcome::IdentityRepairRequired)
            }
            NormalAcquireAttempt::AuthorityRejected(reason) => {
                return Ok(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::AuthorityRejected(reason),
                ))
            }
            NormalAcquireAttempt::StopForLocalContract => return Ok(stop_local()),
            NormalAcquireAttempt::StopForDeploymentMismatch => {
                return Ok(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::DeploymentMismatch,
                ))
            }
            NormalAcquireAttempt::Ambiguous => {
                context.check_active()?;
                let record = match self.authority.load_volume(&volume.volume_id) {
                    Ok(record) => record,
                    Err(
                        AuthorityError::NotFound
                        | AuthorityError::OtherWriter
                        | AuthorityError::Fenced
                        | AuthorityError::StaleTransition
                        | AuthorityError::InvalidLeaseDuration
                        | AuthorityError::EpochExhausted
                        | AuthorityError::AdminBusy
                        | AuthorityError::HeadConflict
                        | AuthorityError::SnapshotInUse
                        | AuthorityError::InvalidAuthorization
                        | AuthorityError::BackendUnknown,
                    ) => return Ok(RuntimeDesiredEffectOutcome::RetryExact),
                };
                context.check_active()?;
                match recover_normal_acquire_from_authority(&request, volume, &record) {
                    Ok(NormalAcquireAuthorityRecovery::Granted(attachment)) => attachment,
                    Ok(NormalAcquireAuthorityRecovery::RetryExact) => {
                        return Ok(RuntimeDesiredEffectOutcome::RetryExact)
                    }
                    Ok(NormalAcquireAuthorityRecovery::Blocked) => {
                        return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
                    }
                    Err(_) => return Ok(stop_local()),
                }
            }
        };

        self.persist_provision_step(
            context,
            desired,
            volume,
            &predecessor,
            *attachment,
            expected_blank_head,
            expected_provisioned_head,
            &store,
            accepted.attestation().accepted_at_unix_ms,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_provision_step(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        predecessor: &super::StoredCheckpoint,
        attachment: AuthorizedServingAttachment,
        expected_blank_head: RemoteHead,
        expected_provisioned_head: RemoteHead,
        store: &FileCheckpointStore,
        updated_at_unix_ms: UnixMillis,
        adopted: bool,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        if attachment.head != expected_blank_head {
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }
        context.check_active()?;
        let blockd = AuthorizedBlockdStore::new(context.state_directory().clone());
        let prepared = if adopted {
            blockd.prepare_adopted(desired, volume, &attachment)
        } else {
            blockd.prepare(desired, volume, &attachment)
        }
        .context("persist exact authorized blockd grant after normal acquire or adoption")?;
        #[cfg(test)]
        if let Some(after_prepare) = &self.after_prepare {
            after_prepare(context);
        }
        context.check_active()?;

        let data_directory = host_path(
            prepared.data_directory(),
            "authorized blockd data directory",
        )?;
        let control_socket_path = host_path(
            &prepared.data_directory().join(ROOT_PROVISION_SOCKET),
            "root-provision control socket",
        )?;
        let process_identity_token = random_id();
        let scope_id = Id::new(format!(
            "cats-root-{}.service",
            process_identity_token.as_str()
        ))
        .context("root-provision process token does not form a systemd service ID")?;
        let provision = RuntimeCheckpoint {
            version: ContractVersion::V1,
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            placement_epoch: desired.placement.placement_epoch,
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            runtime_incarnation: None,
            stable_state: None,
            step: ReconcileStep::ProvisionRootImage {
                provision_transition_id: random_id(),
                volume_id: volume.volume_id.clone(),
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                scope_id,
                control_socket_path,
                data_directory: data_directory.clone(),
                process_identity_token,
                size_bytes: volume.size_bytes,
                boot_image_digest: desired.runtime.boot_image_digest.clone(),
                expected_blank_head,
                expected_provisioned_head,
            },
            processes: Vec::new(),
            volumes: vec![prepared_owned_observed_volume(
                volume,
                &attachment,
                data_directory.clone(),
            )],
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            route_gates: Vec::new(),
            require_idle: RequireIdleCheckpoint::NotApplicable,
            updated_at_unix_ms,
        };
        store
            .replace(predecessor, &provision)
            .context("advance exact acquired root to provision_root_image")?;
        // The authority mutation, grant files and next-step checkpoint are all
        // physical changes. A new accepted full scan is the only legal bridge
        // to starting the control-only process.
        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
    }
}

impl RuntimeDesiredEffect for SignedRunningAcquireEffect {
    fn apply(
        &self,
        context: RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        context.check_active()?;
        if let Some(outcome) = self.apply_checkpoint_replan(&context, desired)? {
            return Ok(outcome);
        }
        self.apply_acquire(&context, desired)
    }
}

enum ImageHeadDecision {
    Exact((RemoteHead, RemoteHead)),
    RetryExact,
    StopLocal,
}

struct PrelaunchAdmission<'a> {
    runtime: &'a ObservedRuntimeStatus,
    volume: &'a VolumeIntent,
}

enum PrelaunchAdmissionDecision<'a> {
    Exact(PrelaunchAdmission<'a>),
    RefreshInventory,
    StopLocal,
}

fn validate_prelaunch_admission<'a>(
    desired: &'a DesiredRuntimeSpec,
    accepted: &'a crate::runtime_spine::RuntimeDesiredEffectAdmission,
    _state_directory: &std::path::Path,
) -> PrelaunchAdmissionDecision<'a> {
    if encode_desired_runtime_spec(desired).is_err()
        || desired.version != ContractVersion::V1
        || desired.target != RuntimeTarget::Running
        || !matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        || desired.volumes.len() != 1
        || desired.placement.node_id != accepted.session().node_id
    {
        return PrelaunchAdmissionDecision::StopLocal;
    }
    let volume = &desired.volumes[0];
    if !matches!(volume.acquire, VolumeAcquire::Normal { .. })
        || volume.disk_kind != DiskKind::Root
        || volume.access != VolumeAccess::ReadWriteOnce
        || volume.mount.is_some()
        || !matches!(volume.disposition, VolumeDisposition::Retain)
    {
        return PrelaunchAdmissionDecision::StopLocal;
    }
    let observation = accepted.observation();
    if !observation.complete_inventory
        || observation.node_id != accepted.session().node_id
        || observation.node_boot_id != accepted.session().node_boot_id
        || observation.agent_instance_id != accepted.session().agent_instance_id
        || observation.agent_session_epoch != accepted.session().agent_session_epoch
        || observation.inventory_epoch != accepted.attestation().inventory_epoch
        || observation.inventory_digest.as_ref() != Some(&accepted.attestation().inventory_digest)
        || observation.inventory_read_position
            != Some(accepted.attestation().inventory_read_position)
        || accepted.attestation().node_id != accepted.session().node_id
        || accepted.attestation().agent_session_epoch != accepted.session().agent_session_epoch
        || accepted.attestation().accepted_at_unix_ms >= accepted.session().lease_deadline_unix_ms
    {
        return PrelaunchAdmissionDecision::StopLocal;
    }
    let mut matching = observation
        .runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let Some(runtime) = matching.next() else {
        return PrelaunchAdmissionDecision::RefreshInventory;
    };
    if matching.next().is_some() {
        return PrelaunchAdmissionDecision::StopLocal;
    }
    let expected_applied = AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: desired.target,
    };
    if runtime.applied_desired.as_ref() != Some(&expected_applied) {
        return PrelaunchAdmissionDecision::RefreshInventory;
    }
    if runtime.runtime_incarnation.is_some()
        || runtime.stable_state.is_some()
        || !runtime.processes.is_empty()
        || runtime.volumes.is_empty()
        || !runtime.mounts.is_empty()
        || !runtime.networks.is_empty()
        || !matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable)
        || !matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
        || runtime.lifecycle_admission != LifecycleAdmission::Closed
        || !runtime.routes.is_empty()
        || runtime.platform_guards != 0
        || runtime
            .volumes
            .iter()
            .any(|observed| !observed.devices.is_empty() || observed.local_lineages.len() > 1)
        || runtime.conditions
            != [Condition::Progressing {
                reason: ProgressingReason::ReconcileStep {
                    step: runtime.step.clone(),
                },
            }]
    {
        return PrelaunchAdmissionDecision::StopLocal;
    }
    PrelaunchAdmissionDecision::Exact(PrelaunchAdmission { runtime, volume })
}

fn canonical_current_acquire_is_unowned(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    runtime: &ObservedRuntimeStatus,
    request: &VolumeAcquireRequest,
) -> bool {
    let [observed] = runtime.volumes.as_slice() else {
        return false;
    };
    request_matches_volume(request, desired, volume)
        && observed_identity_matches_intent(observed, volume)
        && observed_is_current_unowned(observed, volume)
        && observed.local_lineages.is_empty()
        && observed.devices.is_empty()
}

fn unique_observed_volume<'a>(
    runtime: &'a ObservedRuntimeStatus,
    volume_id: &Id,
) -> Option<&'a ObservedVolume> {
    let mut matching = runtime
        .volumes
        .iter()
        .filter(|volume| volume.volume_id == *volume_id);
    let first = matching.next()?;
    matching.next().is_none().then_some(first)
}

fn checkpoint_volume_for_acquire<'a>(
    checkpoint: &'a RuntimeCheckpoint,
    request: &VolumeAcquireRequest,
) -> Option<&'a ObservedVolume> {
    let VolumeAcquireRequest::Normal { volume_id, .. } = request else {
        return None;
    };
    let mut matching = checkpoint
        .volumes
        .iter()
        .filter(|volume| volume.volume_id == *volume_id);
    let first = matching.next()?;
    matching.next().is_none().then_some(first)
}

fn observed_identity_matches_intent(observed: &ObservedVolume, volume: &VolumeIntent) -> bool {
    observed.volume_intent_id.as_ref() == Some(&volume.volume_intent_id)
        && observed.disk_id.as_ref() == Some(&volume.disk_id)
        && observed.volume_id == volume.volume_id
        && observed.disk_kind == ObservedDiskKind::Root
        && observed.size_bytes == Some(volume.size_bytes)
        && observed.durability == Some(volume.durability)
}

fn observed_is_current_unowned(observed: &ObservedVolume, volume: &VolumeIntent) -> bool {
    let VolumeAcquire::Normal {
        expected_unowned_epoch,
        ..
    } = volume.acquire
    else {
        return false;
    };
    matches!(
        &observed.authority,
        VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head,
        } if *attachment_epoch == expected_unowned_epoch && *head == blank_head()
    )
}

fn observed_is_unowned(observed: &ObservedVolume) -> bool {
    matches!(
        &observed.authority,
        VolumeAuthorityEvidence::Unowned { head, .. } if *head == blank_head()
    ) && observed.local_lineages.is_empty()
        && observed.devices.is_empty()
}

fn record_is_current_unowned(record: &VolumeRecord, volume: &VolumeIntent) -> bool {
    let VolumeAcquire::Normal {
        expected_unowned_epoch,
        ..
    } = volume.acquire
    else {
        return false;
    };
    validate_volume_record(record).is_ok()
        && record.volume_id == volume.volume_id
        && record.size_bytes == volume.size_bytes
        && record.durability == volume.durability
        && matches!(record.admin_state, VolumeAdminState::Active)
        && record.lease_owner.is_none()
        && record.lease_epoch == expected_unowned_epoch
        && record.lease_expires_at.is_none()
        && record.head == blank_head()
}

fn record_matches_unowned_observation(record: &VolumeRecord, observed: &ObservedVolume) -> bool {
    let VolumeAuthorityEvidence::Unowned {
        attachment_epoch,
        head,
    } = &observed.authority
    else {
        return false;
    };
    validate_volume_record(record).is_ok()
        && record.volume_id == observed.volume_id
        && Some(record.size_bytes) == observed.size_bytes
        && Some(record.durability) == observed.durability
        && matches!(record.admin_state, VolumeAdminState::Active)
        && record.lease_owner.is_none()
        && record.lease_epoch == *attachment_epoch
        && record.lease_expires_at.is_none()
        && record.head == *head
}

fn attachment_from_checkpoint_acquire(
    checkpoint: &RuntimeCheckpoint,
    request: &VolumeAcquireRequest,
    record: &VolumeRecord,
) -> Option<AuthorizedServingAttachment> {
    let VolumeAcquireRequest::Normal {
        volume_id,
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
    } = request
    else {
        return None;
    };
    if *desired_revision != checkpoint.desired_revision
        || *placement_epoch != checkpoint.placement_epoch
        || validate_volume_record(record).is_err()
        || record.volume_id != *volume_id
        || !matches!(record.admin_state, VolumeAdminState::Active)
    {
        return None;
    }
    let Some(LastVolumeTransition::NormalAcquire {
        request: stored_request,
        result,
    }) = &record.last_transition
    else {
        return None;
    };
    let expected_request = NormalAcquireRequest {
        volume_id: volume_id.clone(),
        transition_id: transition_id.clone(),
        attachment_id: attachment_id.clone(),
        expected_unowned_epoch: *expected_unowned_epoch,
        desired_revision: *desired_revision,
        placement_epoch: *placement_epoch,
        lease_duration_ms: *lease_duration_ms,
    };
    if stored_request != &expected_request
        || result.volume_id != *volume_id
        || result.transition_id != *transition_id
        || result.attachment_id != *attachment_id
        || record.lease_owner.as_ref() != Some(attachment_id)
        || record.lease_epoch != result.resulting_epoch
        || record.lease_expires_at != Some(result.lease_expires_at)
    {
        return None;
    }
    let observed = checkpoint
        .volumes
        .iter()
        .find(|observed| observed.volume_id == *volume_id)?;
    if observed.size_bytes != Some(record.size_bytes)
        || observed.durability != Some(record.durability)
    {
        return None;
    }
    let attachment = AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: result.resulting_epoch,
            acquire_origin: AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            },
            node_id: checkpoint.node_id.clone(),
            placement_epoch: checkpoint.placement_epoch,
        },
        size_bytes: record.size_bytes,
        durability: record.durability,
        head: result.resulting_head.clone(),
        lease_expires_at: result.lease_expires_at,
        acquire_request: stored_request.clone(),
        acquire_result: result.clone(),
    };
    (validate_authorized_serving_attachment(&attachment).is_ok()
        && validate_authorized_serving_record(record, &attachment, None).is_ok())
    .then_some(attachment)
}

fn attachment_from_current_desired(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    record: &VolumeRecord,
) -> Option<AuthorizedServingAttachment> {
    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &volume.acquire
    else {
        return None;
    };
    let Some(LastVolumeTransition::NormalAcquire { request, result }) = &record.last_transition
    else {
        return None;
    };
    if validate_volume_record(record).is_err()
        || record.volume_id != volume.volume_id
        || record.size_bytes != volume.size_bytes
        || record.durability != volume.durability
        || !matches!(record.admin_state, VolumeAdminState::Active)
        || request.volume_id != volume.volume_id
        || request.transition_id != *transition_id
        || request.attachment_id != volume.attachment_id
        || request.expected_unowned_epoch != *expected_unowned_epoch
        || request.desired_revision > desired.desired_revision
        || request.placement_epoch != desired.placement.placement_epoch
        || result.volume_id != volume.volume_id
        || result.transition_id != *transition_id
        || result.attachment_id != volume.attachment_id
        || record.lease_owner.as_ref() != Some(&volume.attachment_id)
        || record.lease_epoch != result.resulting_epoch
        || record.lease_expires_at != Some(result.lease_expires_at)
    {
        return None;
    }
    let attachment = AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: volume.volume_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            attachment_epoch: result.resulting_epoch,
            acquire_origin: AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            },
            node_id: desired.placement.node_id.clone(),
            placement_epoch: desired.placement.placement_epoch,
        },
        size_bytes: record.size_bytes,
        durability: record.durability,
        head: result.resulting_head.clone(),
        lease_expires_at: result.lease_expires_at,
        acquire_request: request.clone(),
        acquire_result: result.clone(),
    };
    (validate_authorized_serving_attachment(&attachment).is_ok()
        && validate_authorized_serving_record(record, &attachment, None).is_ok())
    .then_some(attachment)
}

fn attachment_is_adoptable(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    observed: &ObservedVolume,
    attachment: &AuthorizedServingAttachment,
) -> bool {
    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &volume.acquire
    else {
        return false;
    };
    observed_identity_matches_intent(observed, volume)
        && attachment.identity.volume_id == volume.volume_id
        && attachment.identity.attachment_id == volume.attachment_id
        && attachment.identity.acquire_origin
            == (AcquireOrigin::Normal {
                transition_id: transition_id.clone(),
            })
        && attachment.identity.node_id == desired.placement.node_id
        && attachment.identity.placement_epoch == desired.placement.placement_epoch
        && attachment.size_bytes == volume.size_bytes
        && attachment.durability == volume.durability
        && attachment.acquire_request.expected_unowned_epoch == *expected_unowned_epoch
        && attachment.acquire_request.desired_revision <= desired.desired_revision
}

fn observed_authority_matches_attachment(
    observed: &ObservedVolume,
    attachment: &AuthorizedServingAttachment,
) -> bool {
    matches!(
        &observed.authority,
        VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            head,
        } if attachment_id == &attachment.identity.attachment_id
            && *attachment_epoch == attachment.identity.attachment_epoch
            && head.generation >= attachment.acquire_result.resulting_head.generation
    )
}

fn record_matches_attachment_lineage(
    record: &VolumeRecord,
    attachment: &AuthorizedServingAttachment,
) -> bool {
    validate_volume_record(record).is_ok()
        && validate_authorized_serving_attachment(attachment).is_ok()
        && record.volume_id == attachment.identity.volume_id
        && record.size_bytes == attachment.size_bytes
        && record.durability == attachment.durability
        && matches!(record.admin_state, VolumeAdminState::Active)
        && record.lease_owner.as_ref() == Some(&attachment.identity.attachment_id)
        && record.lease_epoch == attachment.identity.attachment_epoch
        && record.last_transition
            == Some(LastVolumeTransition::NormalAcquire {
                request: attachment.acquire_request.clone(),
                result: attachment.acquire_result.clone(),
            })
        && record.head.generation >= attachment.acquire_result.resulting_head.generation
}

fn local_lineage_is_absent_or_exact(
    observed: &ObservedVolume,
    identity: &AttachmentLineageIdentity,
) -> bool {
    observed.local_lineages.is_empty()
        || (observed.local_lineages.len() == 1
            && observed.local_lineages.first().is_some_and(|lineage| {
                lineage.attachment_id == identity.attachment_id
                    && lineage.attachment_epoch == identity.attachment_epoch
                    && lineage.acquire_origin == identity.acquire_origin
                    && lineage.node_id == identity.node_id
                    && lineage.placement_epoch == identity.placement_epoch
                    && lineage.pending_pack_count.get() == 0
                    && !lineage.fenced
                    && lineage.state == LocalLineageState::Active
            }))
}

fn local_lineage_exact(
    lineage: &LocalVolumeLineage,
    identity: &AttachmentLineageIdentity,
    generation: Generation,
) -> bool {
    lineage.attachment_id == identity.attachment_id
        && lineage.attachment_epoch == identity.attachment_epoch
        && lineage.acquire_origin == identity.acquire_origin
        && lineage.node_id == identity.node_id
        && lineage.placement_epoch == identity.placement_epoch
        && lineage.local_durable_generation == generation
        && lineage.remote_durable_generation == generation
        && lineage.pending_pack_count.get() == 0
        && !lineage.fenced
        && lineage.state == LocalLineageState::Active
}

fn release_is_supported_by_current_desired(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    observed: &ObservedVolume,
    attachment: &AuthorizedServingAttachment,
) -> bool {
    let Some(head) = observed_authority_head(observed) else {
        return false;
    };
    observed_identity_matches_intent(observed, volume)
        && attachment_is_adoptable(desired, volume, observed, attachment)
        && observed.local_lineages.len() == 1
        && local_lineage_exact(
            &observed.local_lineages[0],
            &attachment.identity,
            head.generation,
        )
}

fn observed_authority_head(observed: &ObservedVolume) -> Option<&RemoteHead> {
    match &observed.authority {
        VolumeAuthorityEvidence::Owned { head, .. }
        | VolumeAuthorityEvidence::Unowned { head, .. } => Some(head),
        VolumeAuthorityEvidence::Absent
        | VolumeAuthorityEvidence::Deleting { .. }
        | VolumeAuthorityEvidence::Unavailable => None,
    }
}

/// Read-only discriminator used by the inventory projection to avoid
/// claiming perpetual progress for a conflict which frozen V1 cannot encode
/// with a durable quarantine reason. `true` means the accepted full planner
/// has a contract-supported rebind or exact release path; every uncertainty
/// remains an explicit, conditionless local stop.
pub(super) fn superseded_checkpoint_has_supported_replan(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    volumes: &[ObservedVolume],
) -> bool {
    let [intent] = desired.volumes.as_slice() else {
        return false;
    };
    let [current] = volumes else {
        return false;
    };
    if current.volume_id != intent.volume_id {
        return false;
    }

    match &checkpoint.step {
        ReconcileStep::AcquireVolume {
            request:
                request @ VolumeAcquireRequest::Normal {
                    transition_id,
                    attachment_id,
                    expected_unowned_epoch,
                    ..
                },
        } => {
            let Some(old) = checkpoint_volume_for_acquire(checkpoint, request) else {
                return false;
            };
            if old.volume_id != current.volume_id {
                return false;
            }
            let no_local_effect = volumes
                .iter()
                .all(|volume| volume.local_lineages.is_empty() && volume.devices.is_empty());
            if no_local_effect
                && observed_is_current_unowned(current, intent)
                && observed_is_unowned(current)
            {
                return true;
            }

            let VolumeAcquire::Normal {
                transition_id: current_transition,
                expected_unowned_epoch: current_unowned_epoch,
            } = &intent.acquire
            else {
                return false;
            };
            let Some(resulting_epoch) = expected_unowned_epoch
                .get()
                .checked_add(1)
                .and_then(FenceEpoch::new)
            else {
                return false;
            };
            let identity = AttachmentLineageIdentity {
                volume_id: intent.volume_id.clone(),
                attachment_id: attachment_id.clone(),
                attachment_epoch: resulting_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: transition_id.clone(),
                },
                node_id: checkpoint.node_id.clone(),
                placement_epoch: checkpoint.placement_epoch,
            };
            observed_identity_matches_intent(current, intent)
                && attachment_id == &intent.attachment_id
                && transition_id == current_transition
                && expected_unowned_epoch == current_unowned_epoch
                && identity.node_id == desired.placement.node_id
                && identity.placement_epoch == desired.placement.placement_epoch
                && matches!(
                    &current.authority,
                    VolumeAuthorityEvidence::Owned {
                        attachment_id: owner,
                        attachment_epoch,
                        ..
                    } if owner == attachment_id && *attachment_epoch == resulting_epoch
                )
                && local_lineage_is_absent_or_exact(current, &identity)
        }
        ReconcileStep::ProvisionRootImage {
            volume_id,
            attachment_id,
            attachment_epoch,
            ..
        } => {
            let [lineage] = current.local_lineages.as_slice() else {
                return false;
            };
            let VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            } = &intent.acquire
            else {
                return false;
            };
            expected_unowned_epoch
                .get()
                .checked_add(1)
                .and_then(FenceEpoch::new)
                .is_some_and(|expected_epoch| expected_epoch == *attachment_epoch)
                && volume_id == &intent.volume_id
                && attachment_id == &intent.attachment_id
                && observed_identity_matches_intent(current, intent)
                && lineage.attachment_id == *attachment_id
                && lineage.attachment_epoch == *attachment_epoch
                && lineage.acquire_origin
                    == (AcquireOrigin::Normal {
                        transition_id: transition_id.clone(),
                    })
                && lineage.node_id == desired.placement.node_id
                && lineage.placement_epoch == desired.placement.placement_epoch
                && lineage.pending_pack_count.get() == 0
                && !lineage.fenced
                && lineage.state == LocalLineageState::Active
                && current.devices.is_empty()
                && matches!(
                    &current.authority,
                    VolumeAuthorityEvidence::Owned {
                        attachment_id: owner,
                        attachment_epoch: owner_epoch,
                        ..
                    } if owner == attachment_id && owner_epoch == attachment_epoch
                )
        }
        _ => false,
    }
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn release_transition_request(
    desired: &DesiredRuntimeSpec,
    cleanup: CleanupRelease,
) -> RuntimeVolumeTransitionRequest {
    RuntimeVolumeTransitionRequest {
        version: ContractVersion::V1,
        session: cleanup.inventory_session.clone(),
        cat_id: desired.cat_id.clone(),
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        transition: RuntimeVolumeTransition::Release { cleanup },
    }
}

fn closed_checkpoint(
    desired: &DesiredRuntimeSpec,
    step: ReconcileStep,
    volumes: Vec<ObservedVolume>,
    updated_at_unix_ms: UnixMillis,
) -> RuntimeCheckpoint {
    RuntimeCheckpoint {
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
        volumes,
        mounts: Vec::new(),
        networks: Vec::new(),
        guest_transport: GuestTransportEvidence::Unavailable,
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission: LifecycleAdmission::Closed,
        route_gates: Vec::new(),
        require_idle: RequireIdleCheckpoint::NotApplicable,
        updated_at_unix_ms,
    }
}

#[allow(clippy::too_many_arguments)]
fn rebound_provision_checkpoint(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    runtime: &ObservedRuntimeStatus,
    attachment: &AuthorizedServingAttachment,
    data_directory: &std::path::Path,
    expected_blank_head: RemoteHead,
    expected_provisioned_head: RemoteHead,
    updated_at_unix_ms: UnixMillis,
) -> anyhow::Result<RuntimeCheckpoint> {
    let data_directory = host_path(data_directory, "adopted blockd data directory")?;
    let control_socket_path = HostPath::new(format!(
        "{}/{}",
        data_directory.as_str(),
        ROOT_PROVISION_SOCKET
    ))
    .context("adopted root-provision control socket is not canonical")?;
    let process_identity_token = random_id();
    let scope_id = Id::new(format!(
        "cats-root-{}.service",
        process_identity_token.as_str()
    ))
    .context("adopted root-provision scope ID is invalid")?;
    let Some(observed) = unique_observed_volume(runtime, &volume.volume_id) else {
        anyhow::bail!("adopted provision lacks the current root observation")
    };
    Ok(closed_checkpoint(
        desired,
        ReconcileStep::ProvisionRootImage {
            provision_transition_id: random_id(),
            volume_id: volume.volume_id.clone(),
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            scope_id,
            control_socket_path,
            data_directory,
            process_identity_token,
            size_bytes: volume.size_bytes,
            boot_image_digest: desired.runtime.boot_image_digest.clone(),
            expected_blank_head,
            expected_provisioned_head,
        },
        vec![observed.clone()],
        updated_at_unix_ms,
    ))
}

enum AdmissionDecision<'a> {
    Exact(&'a VolumeIntent),
    RefreshInventory,
    StopLocal,
}

fn validate_slice_and_admission<'a>(
    desired: &'a DesiredRuntimeSpec,
    accepted: &crate::runtime_spine::RuntimeDesiredEffectAdmission,
    state_directory: &std::path::Path,
) -> AdmissionDecision<'a> {
    if encode_desired_runtime_spec(desired).is_err()
        || desired.version != ContractVersion::V1
        || desired.target != RuntimeTarget::Running
        || !matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        || desired.volumes.len() != 1
        || desired.placement.node_id != accepted.session().node_id
    {
        return AdmissionDecision::StopLocal;
    }
    let volume = &desired.volumes[0];
    let VolumeAcquire::Normal {
        expected_unowned_epoch,
        ..
    } = &volume.acquire
    else {
        return AdmissionDecision::StopLocal;
    };
    if volume.disk_kind != DiskKind::Root
        || volume.access != VolumeAccess::ReadWriteOnce
        || volume.mount.is_some()
        || !matches!(volume.disposition, VolumeDisposition::Retain)
    {
        return AdmissionDecision::StopLocal;
    }
    let observation = accepted.observation();
    if !observation.complete_inventory
        || observation.node_id != accepted.session().node_id
        || observation.node_boot_id != accepted.session().node_boot_id
        || observation.agent_instance_id != accepted.session().agent_instance_id
        || observation.agent_session_epoch != accepted.session().agent_session_epoch
        || observation.inventory_epoch != accepted.attestation().inventory_epoch
        || observation.inventory_digest.as_ref() != Some(&accepted.attestation().inventory_digest)
        || observation.inventory_read_position
            != Some(accepted.attestation().inventory_read_position)
        || accepted.attestation().node_id != accepted.session().node_id
        || accepted.attestation().agent_session_epoch != accepted.session().agent_session_epoch
        || accepted.attestation().accepted_at_unix_ms >= accepted.session().lease_deadline_unix_ms
    {
        return AdmissionDecision::StopLocal;
    }
    let mut matching = observation
        .runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let Some(runtime) = matching.next() else {
        return AdmissionDecision::RefreshInventory;
    };
    if matching.next().is_some() {
        return AdmissionDecision::StopLocal;
    }
    let expected_applied = AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: desired.target,
    };
    if runtime.applied_desired.as_ref() != Some(&expected_applied) {
        return AdmissionDecision::RefreshInventory;
    }
    let expected_checkpoint_path =
        runtime_checkpoint_path(&state_directory.join(CHECKPOINT_NAMESPACE), &desired.cat_id);
    let Some(expected_identity) =
        expected_attachment_identity(desired, volume, *expected_unowned_epoch)
    else {
        return AdmissionDecision::StopLocal;
    };
    let expected_data_directory_path =
        authorized_blockd_data_directory(state_directory, desired, &expected_identity);
    let Ok(expected_data_directory) = host_path(
        &expected_data_directory_path,
        "authorized blockd data directory",
    ) else {
        return AdmissionDecision::StopLocal;
    };
    let expectation = AcquireAdmissionExpectation {
        unowned_epoch: *expected_unowned_epoch,
        inventory_epoch: observation.inventory_epoch,
        checkpoint_path: &expected_checkpoint_path,
        data_directory: &expected_data_directory,
        identity: &expected_identity,
    };
    if !runtime_is_acquire_only(runtime, desired, volume, &expectation) {
        return AdmissionDecision::StopLocal;
    }
    AdmissionDecision::Exact(volume)
}

struct AcquireAdmissionExpectation<'a> {
    unowned_epoch: FenceEpoch,
    inventory_epoch: cats_api::runtime_reconciliation::Epoch,
    checkpoint_path: &'a std::path::Path,
    data_directory: &'a HostPath,
    identity: &'a cats_storage::authority::AttachmentLineageIdentity,
}

fn runtime_is_acquire_only(
    runtime: &ObservedRuntimeStatus,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    expectation: &AcquireAdmissionExpectation<'_>,
) -> bool {
    if runtime.runtime_incarnation.is_some()
        || runtime.stable_state.is_some()
        || !runtime.processes.is_empty()
        || runtime.volumes.len() != 1
        || !runtime.mounts.is_empty()
        || !runtime.networks.is_empty()
        || !matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable)
        || !matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
        || runtime.lifecycle_admission != LifecycleAdmission::Closed
        || !runtime.routes.is_empty()
        || runtime.platform_guards != 0
        || runtime.conditions
            != [Condition::Progressing {
                reason: ProgressingReason::ReconcileStep {
                    step: runtime.step.clone(),
                },
            }]
    {
        return false;
    }
    let observed = &runtime.volumes[0];
    if observed.volume_intent_id.as_ref() != Some(&volume.volume_intent_id)
        || observed.disk_id.as_ref() != Some(&volume.disk_id)
        || observed.volume_id != volume.volume_id
        || observed.disk_kind != ObservedDiskKind::Root
        || observed.size_bytes != Some(volume.size_bytes)
        || observed.durability != Some(volume.durability)
        || !observed.devices.is_empty()
    {
        return false;
    }
    let authority_is_unowned = match &observed.authority {
        VolumeAuthorityEvidence::Unowned {
            attachment_epoch,
            head,
        } => *attachment_epoch == expectation.unowned_epoch && *head == blank_head(),
        _ => false,
    };
    let authority_is_owned = match &observed.authority {
        VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            head,
        } => {
            attachment_id == &expectation.identity.attachment_id
                && *attachment_epoch == expectation.identity.attachment_epoch
                && *head == blank_head()
        }
        _ => false,
    };
    match (&runtime.step, &runtime.checkpoint) {
        (
            ReconcileStep::InspectInventory {
                inventory_epoch: observed_inventory_epoch,
            },
            CheckpointEvidence::Missing { checkpoint_path },
        ) => {
            *observed_inventory_epoch == expectation.inventory_epoch
                && authority_is_unowned
                && observed.local_lineages.is_empty()
                && path_matches(checkpoint_path, expectation.checkpoint_path)
        }
        (
            ReconcileStep::AcquireVolume { request },
            CheckpointEvidence::Valid {
                cat_id,
                node_id,
                placement_epoch,
                desired_revision,
                spec_digest,
                runtime_incarnation,
                stable_state,
                step,
                require_idle,
                checkpoint_path,
                ..
            },
        ) => {
            cat_id == &desired.cat_id
                && node_id == &desired.placement.node_id
                && *placement_epoch == desired.placement.placement_epoch
                && *desired_revision == desired.desired_revision
                && spec_digest == &desired.spec_digest
                && runtime_incarnation.is_none()
                && stable_state.is_none()
                && step.as_ref() == &runtime.step
                && matches!(require_idle.as_ref(), RequireIdleCheckpoint::NotApplicable)
                && request_matches_volume(request, desired, volume)
                && path_matches(checkpoint_path, expectation.checkpoint_path)
                && ((authority_is_unowned && observed.local_lineages.is_empty())
                    || (authority_is_owned
                        // Authority may have committed before the response, or
                        // grant persistence may have committed before the
                        // checkpoint replace. Only the latter's one exact,
                        // blank, no-write lineage is adoptable after a new full
                        // inventory; every other local directory stays foreign.
                        && (observed.local_lineages.is_empty()
                            || observed.local_lineages
                                == [expected_local_lineage(
                                    expectation.identity,
                                    expectation.data_directory,
                                )])))
        }
        (
            ReconcileStep::ProvisionRootImage { .. },
            CheckpointEvidence::Valid {
                cat_id,
                node_id,
                placement_epoch,
                desired_revision,
                spec_digest,
                runtime_incarnation,
                stable_state,
                step,
                require_idle,
                checkpoint_path,
                ..
            },
        ) => {
            cat_id == &desired.cat_id
                && node_id == &desired.placement.node_id
                && *placement_epoch == desired.placement.placement_epoch
                && *desired_revision == desired.desired_revision
                && spec_digest == &desired.spec_digest
                && runtime_incarnation.is_none()
                && stable_state.is_none()
                && step.as_ref() == &runtime.step
                && matches!(require_idle.as_ref(), RequireIdleCheckpoint::NotApplicable)
                && path_matches(checkpoint_path, expectation.checkpoint_path)
                && authority_is_owned
                && observed.local_lineages
                    == [expected_local_lineage(
                        expectation.identity,
                        expectation.data_directory,
                    )]
        }
        _ => false,
    }
}

fn expected_attachment_identity(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    expected_unowned_epoch: FenceEpoch,
) -> Option<cats_storage::authority::AttachmentLineageIdentity> {
    let VolumeAcquire::Normal { transition_id, .. } = &volume.acquire else {
        unreachable!("slice validation accepted only Normal")
    };
    let attachment_epoch = expected_unowned_epoch.get().checked_add(1)?;
    Some(cats_storage::authority::AttachmentLineageIdentity {
        volume_id: volume.volume_id.clone(),
        attachment_id: volume.attachment_id.clone(),
        attachment_epoch: FenceEpoch::new(attachment_epoch)?,
        acquire_origin: AcquireOrigin::Normal {
            transition_id: transition_id.clone(),
        },
        node_id: desired.placement.node_id.clone(),
        placement_epoch: desired.placement.placement_epoch,
    })
}

fn expected_local_lineage(
    identity: &cats_storage::authority::AttachmentLineageIdentity,
    data_directory: &HostPath,
) -> LocalVolumeLineage {
    LocalVolumeLineage {
        attachment_id: identity.attachment_id.clone(),
        attachment_epoch: identity.attachment_epoch,
        acquire_origin: identity.acquire_origin.clone(),
        node_id: identity.node_id.clone(),
        placement_epoch: identity.placement_epoch,
        local_durable_generation: blank_head().generation,
        remote_durable_generation: blank_head().generation,
        data_directory: data_directory.clone(),
        pending_pack_count: WireU64::new(0).expect("zero fits WireU64"),
        fenced: false,
        state: LocalLineageState::Active,
    }
}

fn normal_acquire_request(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    session: &AgentSession,
    lease_duration_ms: u64,
) -> RuntimeVolumeTransitionRequest {
    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &volume.acquire
    else {
        unreachable!("slice validation accepted only Normal")
    };
    normal_acquire_request_with_payload(
        desired,
        session,
        VolumeAcquireRequest::Normal {
            volume_id: volume.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            expected_unowned_epoch: *expected_unowned_epoch,
            desired_revision: desired.desired_revision,
            placement_epoch: desired.placement.placement_epoch,
            lease_duration_ms,
        },
    )
}

fn normal_acquire_request_with_payload(
    desired: &DesiredRuntimeSpec,
    session: &AgentSession,
    request: VolumeAcquireRequest,
) -> RuntimeVolumeTransitionRequest {
    normal_acquire_request_with_binding(
        desired,
        SessionBinding {
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
        },
        request,
    )
}

fn normal_acquire_request_with_binding(
    desired: &DesiredRuntimeSpec,
    session: SessionBinding,
    request: VolumeAcquireRequest,
) -> RuntimeVolumeTransitionRequest {
    RuntimeVolumeTransitionRequest {
        version: ContractVersion::V1,
        session,
        cat_id: desired.cat_id.clone(),
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        transition: RuntimeVolumeTransition::Acquire { request },
    }
}

fn recovery_volume<'a>(
    desired: &'a DesiredRuntimeSpec,
    session: &SessionBinding,
) -> Option<&'a VolumeIntent> {
    if encode_desired_runtime_spec(desired).is_err()
        || desired.version != ContractVersion::V1
        || desired.target != RuntimeTarget::Running
        || !matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        || desired.placement.node_id != session.node_id
    {
        return None;
    }
    let [volume] = desired.volumes.as_slice() else {
        return None;
    };
    if !matches!(volume.acquire, VolumeAcquire::Normal { .. })
        || volume.disk_kind != DiskKind::Root
        || volume.access != VolumeAccess::ReadWriteOnce
        || volume.mount.is_some()
        || !matches!(volume.disposition, VolumeDisposition::Retain)
    {
        return None;
    }
    Some(volume)
}

pub(super) fn request_matches_volume(
    request: &VolumeAcquireRequest,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
) -> bool {
    let VolumeAcquireRequest::Normal {
        volume_id,
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
    } = request
    else {
        return false;
    };
    let VolumeAcquire::Normal {
        transition_id: intended_transition,
        expected_unowned_epoch: intended_epoch,
    } = &volume.acquire
    else {
        return false;
    };
    volume_id == &volume.volume_id
        && transition_id == intended_transition
        && attachment_id == &volume.attachment_id
        && expected_unowned_epoch == intended_epoch
        && desired_revision == &desired.desired_revision
        && placement_epoch == &desired.placement.placement_epoch
        && (1..=MAX_LEASE_DURATION_MS).contains(lease_duration_ms)
}

pub(super) fn acquire_checkpoint(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    transition: RuntimeVolumeTransition,
    updated_at_unix_ms: UnixMillis,
) -> RuntimeCheckpoint {
    let RuntimeVolumeTransition::Acquire { request } = transition else {
        unreachable!("normal request builder always returns Acquire")
    };
    RuntimeCheckpoint {
        version: ContractVersion::V1,
        cat_id: desired.cat_id.clone(),
        node_id: desired.placement.node_id.clone(),
        placement_epoch: desired.placement.placement_epoch,
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        runtime_incarnation: None,
        stable_state: None,
        step: ReconcileStep::AcquireVolume { request },
        processes: Vec::new(),
        volumes: vec![unowned_observed_volume(volume)],
        mounts: Vec::new(),
        networks: Vec::new(),
        guest_transport: GuestTransportEvidence::Unavailable,
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission: LifecycleAdmission::Closed,
        route_gates: Vec::new(),
        require_idle: RequireIdleCheckpoint::NotApplicable,
        updated_at_unix_ms,
    }
}

#[cfg(test)]
fn checkpoint_eq_except_updated_at(stored: &RuntimeCheckpoint, fresh: &RuntimeCheckpoint) -> bool {
    let mut stored = stored.clone();
    stored.updated_at_unix_ms = fresh.updated_at_unix_ms;
    stored == *fresh
}

fn persisted_acquire_request<'a>(
    checkpoint: &'a RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
) -> Option<&'a VolumeAcquireRequest> {
    let ReconcileStep::AcquireVolume { request } = &checkpoint.step else {
        return None;
    };
    if !request_matches_volume(request, desired, volume) {
        return None;
    }
    let expected = acquire_checkpoint(
        desired,
        volume,
        RuntimeVolumeTransition::Acquire {
            request: request.clone(),
        },
        checkpoint.updated_at_unix_ms,
    );
    (checkpoint == &expected).then_some(request)
}

pub(super) fn unowned_observed_volume(volume: &VolumeIntent) -> ObservedVolume {
    let VolumeAcquire::Normal {
        expected_unowned_epoch,
        ..
    } = volume.acquire
    else {
        unreachable!("slice validation accepted only Normal")
    };
    ObservedVolume {
        volume_intent_id: Some(volume.volume_intent_id.clone()),
        disk_id: Some(volume.disk_id.clone()),
        volume_id: volume.volume_id.clone(),
        disk_kind: ObservedDiskKind::Root,
        size_bytes: Some(volume.size_bytes),
        durability: Some(volume.durability),
        authority: VolumeAuthorityEvidence::Unowned {
            attachment_epoch: expected_unowned_epoch,
            head: blank_head(),
        },
        local_lineages: Vec::new(),
        devices: Vec::new(),
    }
}

fn owned_observed_volume(
    volume: &VolumeIntent,
    attachment: &AuthorizedServingAttachment,
) -> ObservedVolume {
    ObservedVolume {
        volume_intent_id: Some(volume.volume_intent_id.clone()),
        disk_id: Some(volume.disk_id.clone()),
        volume_id: volume.volume_id.clone(),
        disk_kind: ObservedDiskKind::Root,
        size_bytes: Some(volume.size_bytes),
        durability: Some(volume.durability),
        authority: VolumeAuthorityEvidence::Owned {
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            head: attachment.head.clone(),
        },
        local_lineages: Vec::new(),
        devices: Vec::new(),
    }
}

pub(super) fn prepared_owned_observed_volume(
    volume: &VolumeIntent,
    attachment: &AuthorizedServingAttachment,
    data_directory: HostPath,
) -> ObservedVolume {
    let mut observed = owned_observed_volume(volume, attachment);
    observed.local_lineages.push(expected_local_lineage(
        &attachment.identity,
        &data_directory,
    ));
    observed
}

pub(super) fn provision_checkpoint_is_bound(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    state_directory: &std::path::Path,
    expected_blank_head: &RemoteHead,
    expected_provisioned_head: &RemoteHead,
) -> bool {
    let ReconcileStep::ProvisionRootImage {
        volume_id,
        attachment_id,
        attachment_epoch,
        scope_id,
        control_socket_path,
        data_directory,
        process_identity_token,
        size_bytes,
        boot_image_digest,
        expected_blank_head: checkpoint_blank,
        expected_provisioned_head: checkpoint_target,
        ..
    } = &checkpoint.step
    else {
        return false;
    };
    let VolumeAcquire::Normal {
        expected_unowned_epoch,
        ..
    } = volume.acquire
    else {
        return false;
    };
    let Some(expected_identity) =
        expected_attachment_identity(desired, volume, expected_unowned_epoch)
    else {
        return false;
    };
    let expected_data_directory =
        authorized_blockd_data_directory(state_directory, desired, &expected_identity);
    let [observed_volume] = checkpoint.volumes.as_slice() else {
        return false;
    };
    let observed_head = match &observed_volume.authority {
        VolumeAuthorityEvidence::Owned {
            attachment_id: observed_attachment_id,
            attachment_epoch: observed_attachment_epoch,
            head,
        } if observed_attachment_id == attachment_id
            && observed_attachment_epoch == attachment_epoch
            && (head == expected_blank_head || head == expected_provisioned_head) =>
        {
            head
        }
        _ => return false,
    };
    let mut expected_lineage = expected_local_lineage(&expected_identity, data_directory);
    expected_lineage.local_durable_generation = observed_head.generation;
    expected_lineage.remote_durable_generation = observed_head.generation;
    let observed_volume_matches = observed_volume.volume_intent_id.as_ref()
        == Some(&volume.volume_intent_id)
        && observed_volume.disk_id.as_ref() == Some(&volume.disk_id)
        && observed_volume.volume_id == volume.volume_id
        && observed_volume.disk_kind == ObservedDiskKind::Root
        && observed_volume.size_bytes == Some(volume.size_bytes)
        && observed_volume.durability == Some(volume.durability)
        && observed_volume.local_lineages == [expected_lineage]
        && observed_volume.devices.is_empty();
    checkpoint.version == ContractVersion::V1
        && checkpoint.cat_id == desired.cat_id
        && checkpoint.node_id == desired.placement.node_id
        && checkpoint.placement_epoch == desired.placement.placement_epoch
        && checkpoint.desired_revision == desired.desired_revision
        && checkpoint.spec_digest == desired.spec_digest
        && checkpoint.runtime_incarnation.is_none()
        && checkpoint.stable_state.is_none()
        && checkpoint.processes.is_empty()
        && observed_volume_matches
        && checkpoint.mounts.is_empty()
        && checkpoint.networks.is_empty()
        && matches!(
            checkpoint.guest_transport,
            GuestTransportEvidence::Unavailable
        )
        && matches!(checkpoint.warm_snapshot, WarmSnapshotEvidence::Absent)
        && checkpoint.lifecycle_admission == LifecycleAdmission::Closed
        && checkpoint.route_gates.is_empty()
        && matches!(
            checkpoint.require_idle,
            RequireIdleCheckpoint::NotApplicable
        )
        && volume_id == &volume.volume_id
        && attachment_id == &expected_identity.attachment_id
        && *attachment_epoch == expected_identity.attachment_epoch
        && *size_bytes == volume.size_bytes
        && boot_image_digest == &desired.runtime.boot_image_digest
        && checkpoint_blank == expected_blank_head
        && checkpoint_target == expected_provisioned_head
        && path_matches(data_directory, &expected_data_directory)
        && scope_id.as_str() == format!("cats-root-{}.service", process_identity_token.as_str())
        && control_socket_path.as_str()
            == format!("{}/{}", data_directory.as_str(), ROOT_PROVISION_SOCKET)
}

pub(super) enum ProvisionHeadRead {
    Ready {
        blank: RemoteHead,
        target: RemoteHead,
    },
    Retry,
    Invalid,
}

pub(super) fn expected_provision_heads(
    blob: &dyn BlobStore,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    deadline: Instant,
) -> ProvisionHeadRead {
    let manifest =
        match read_image_manifest_until(blob, &desired.runtime.boot_image_digest, deadline) {
            Ok(manifest) => manifest,
            Err(
                ImageManifestReadError::NotFound { .. }
                | ImageManifestReadError::BackendUnavailable { .. },
            ) => return ProvisionHeadRead::Retry,
            Err(
                ImageManifestReadError::TooLarge { .. } | ImageManifestReadError::Corrupt { .. },
            ) => return ProvisionHeadRead::Invalid,
        };
    let Ok(image_identity) = cats_blockd::format::image_root_identity(&manifest, volume.size_bytes)
    else {
        return ProvisionHeadRead::Invalid;
    };
    ProvisionHeadRead::Ready {
        blank: blank_head(),
        target: RemoteHead {
            generation: Generation::new(1).expect("one is a valid generation"),
            root_hash: Some(Sha256Digest::from_bytes(image_identity.root_hash)),
            root_object_id: Some(
                AsciiText::new(image_identity.root_object_id)
                    .expect("a computed map object ID is printable ASCII"),
            ),
        },
    }
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: Generation::new(0).expect("zero is a valid generation"),
        root_hash: None,
        root_object_id: None,
    }
}

fn random_id() -> RandomId128 {
    RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .expect("UUID simple form is a nonzero RandomId128")
}

fn host_path(path: &std::path::Path, label: &str) -> anyhow::Result<HostPath> {
    let value = path
        .to_str()
        .with_context(|| format!("{label} is not UTF-8"))?;
    HostPath::new(value.to_owned()).with_context(|| format!("{label} is not canonical"))
}

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}

fn path_matches(path: &HostPath, expected: &std::path::Path) -> bool {
    expected
        .to_str()
        .is_some_and(|expected| path.as_str() == expected)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use cats_api::runtime_reconciliation::{
        decode_runtime_checkpoint, spec_digest, AcquireOrigin, AdmissionInventoryAttestation,
        AgentSession, AssignedKind, AssignedPlacement, DesiredReadSnapshot, Epoch,
        GuestDeviceIdentity, Ipv4Address, IsolatedIpv4Kind, LastVolumeTransition, MacAddress,
        NetworkConfig, NodeBootId, NodeObservation, NormalAcquireRequest, NormalAcquireResult,
        Revision, RuntimeConfig, RuntimeVolumeAuthorityRejection, Sequence, VolumeAdminState,
        VolumeRecord,
    };
    use cats_storage::authority::{
        AttachmentLineageIdentity, RenewLeaseRequest, RenewLeaseResult, VolumeHeadCasRequest,
        VolumeHeadCasResult,
    };
    use cats_storage::{
        encode_image_manifest, BlobError, ImageManifestChunkV1, ImageManifestV1, LowerHexSha256,
    };

    use crate::runtime_spine::{
        RuntimeDesiredEffectAdmission, RuntimeInventoryScanContext, RuntimeInventoryScanOutcome,
        RuntimePreScanRecoveryContext, RuntimeSpineFullScan,
    };
    use crate::state_directory::StateDirectory;

    use super::super::{
        clean_slate_scanner_with_volume_authority_and_blob_for_test,
        clean_slate_scanner_with_volume_authority_for_test, TestCleanSlateProbeConfig,
    };

    use super::*;

    #[derive(Default)]
    struct AcquireState {
        outcomes: VecDeque<NormalAcquireAttempt>,
        release_outcomes: VecDeque<NormalReleaseAttempt>,
        requests: Vec<RuntimeVolumeTransitionRequest>,
        release_requests: Vec<RuntimeVolumeTransitionRequest>,
        deadlines: Vec<Instant>,
        checkpoint_seen_before_call: Vec<bool>,
        checkpoint_path: Option<std::path::PathBuf>,
    }

    struct FakeAcquire {
        state: Arc<Mutex<AcquireState>>,
    }

    impl SignedNormalAcquirePort for FakeAcquire {
        fn acquire(
            &self,
            request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _accepted: &NormalAcquireAcceptedContext,
            deadline: Instant,
        ) -> Result<NormalAcquireAttempt, NormalAcquireClientError> {
            let mut state = self.state.lock().unwrap();
            let checkpoint_seen = state.checkpoint_path.as_ref().is_some_and(|path| {
                std::fs::read(path)
                    .ok()
                    .and_then(|bytes| decode_runtime_checkpoint(&bytes).ok())
                    .is_some_and(|checkpoint| {
                        matches!(checkpoint.step, ReconcileStep::AcquireVolume { .. })
                    })
            });
            state.checkpoint_seen_before_call.push(checkpoint_seen);
            state.requests.push(request.clone());
            state.deadlines.push(deadline);
            Ok(state
                .outcomes
                .pop_front()
                .unwrap_or(NormalAcquireAttempt::RetryExact))
        }

        fn release(
            &self,
            request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _expected_head: &RemoteHead,
            _accepted: &NormalAcquireAcceptedContext,
            deadline: Instant,
        ) -> Result<NormalReleaseAttempt, NormalAcquireClientError> {
            let mut state = self.state.lock().unwrap();
            state.release_requests.push(request.clone());
            state.deadlines.push(deadline);
            Ok(state
                .release_outcomes
                .pop_front()
                .unwrap_or(NormalReleaseAttempt::RetryExact))
        }
    }

    enum BlobMode {
        Present(Vec<u8>),
        Missing,
    }

    struct RecordingBlob {
        mode: BlobMode,
        reads: AtomicUsize,
        deadlines: Mutex<Vec<Instant>>,
    }

    impl RecordingBlob {
        fn present(desired: &DesiredRuntimeSpec) -> Self {
            let manifest = ImageManifestV1 {
                version: 1,
                image_id: LowerHexSha256::from_digest(&desired.runtime.boot_image_digest),
                size_bytes: desired.volumes[0].size_bytes,
                chunks: Vec::new(),
            };
            Self {
                mode: BlobMode::Present(encode_image_manifest(&manifest).unwrap()),
                reads: AtomicUsize::new(0),
                deadlines: Mutex::new(Vec::new()),
            }
        }

        fn missing() -> Self {
            Self {
                mode: BlobMode::Missing,
                reads: AtomicUsize::new(0),
                deadlines: Mutex::new(Vec::new()),
            }
        }

        fn present_with_chunk(desired: &DesiredRuntimeSpec, byte: char) -> Self {
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
            Self {
                mode: BlobMode::Present(encode_image_manifest(&manifest).unwrap()),
                reads: AtomicUsize::new(0),
                deadlines: Mutex::new(Vec::new()),
            }
        }
    }

    impl BlobStore for RecordingBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> Result<(), BlobError> {
            unreachable!("the acquire step never writes the object store")
        }

        fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
            match &self.mode {
                BlobMode::Present(bytes) => Ok(bytes.clone()),
                BlobMode::Missing => Err(BlobError::NotFound(key.to_owned())),
            }
        }

        fn get_bounded_until(
            &self,
            key: &str,
            maximum: usize,
            deadline: Instant,
        ) -> Result<Vec<u8>, BlobError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.deadlines.lock().unwrap().push(deadline);
            let bytes = self.get(key)?;
            if bytes.len() > maximum {
                return Err(BlobError::TooLarge {
                    key: key.to_owned(),
                    maximum,
                    observed_at_least: bytes.len(),
                });
            }
            Ok(bytes)
        }

        fn exists(&self, _key: &str) -> Result<bool, BlobError> {
            unreachable!("the acquire step never probes arbitrary objects")
        }

        fn delete(&self, _key: &str) -> Result<(), BlobError> {
            unreachable!("the acquire step never deletes objects")
        }

        fn list(&self, _prefix: &str) -> Result<Vec<String>, BlobError> {
            unreachable!("the acquire step never lists objects")
        }
    }

    struct FakeAuthority {
        record: Mutex<Result<VolumeRecord, AuthorityError>>,
        records: Mutex<Option<BTreeMap<Id, Result<VolumeRecord, AuthorityError>>>>,
        loads: AtomicUsize,
    }

    impl FakeAuthority {
        fn new(record: Result<VolumeRecord, AuthorityError>) -> Self {
            Self {
                record: Mutex::new(record),
                records: Mutex::new(None),
                loads: AtomicUsize::new(0),
            }
        }

        fn set(&self, record: Result<VolumeRecord, AuthorityError>) {
            *self.record.lock().unwrap() = record;
            *self.records.lock().unwrap() = None;
        }

        fn set_records(&self, records: BTreeMap<Id, Result<VolumeRecord, AuthorityError>>) {
            *self.records.lock().unwrap() = Some(records);
        }
    }

    impl VolumeDataAuthority for FakeAuthority {
        fn load_volume(&self, volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            if let Some(records) = self.records.lock().unwrap().as_ref() {
                return records
                    .get(volume_id)
                    .cloned()
                    .unwrap_or(Err(AuthorityError::NotFound));
            }
            self.record.lock().unwrap().clone()
        }

        fn renew_lease(
            &self,
            _request: &RenewLeaseRequest,
        ) -> Result<RenewLeaseResult, AuthorityError> {
            unreachable!("AcquireVolume never renews a serving process")
        }

        fn compare_and_swap_head(
            &self,
            _request: &VolumeHeadCasRequest,
        ) -> Result<VolumeHeadCasResult, AuthorityError> {
            unreachable!("AcquireVolume never publishes a volume head")
        }
    }

    fn effect(
        desired: &DesiredRuntimeSpec,
        outcomes: Vec<NormalAcquireAttempt>,
        authority: Arc<FakeAuthority>,
        blob: Arc<RecordingBlob>,
        checkpoint_path: std::path::PathBuf,
    ) -> (SignedRunningAcquireEffect, Arc<Mutex<AcquireState>>) {
        effect_with_lease(desired, outcomes, authority, blob, checkpoint_path, 60_000)
    }

    fn effect_with_lease(
        desired: &DesiredRuntimeSpec,
        outcomes: Vec<NormalAcquireAttempt>,
        authority: Arc<FakeAuthority>,
        blob: Arc<RecordingBlob>,
        checkpoint_path: std::path::PathBuf,
        lease_duration_ms: u64,
    ) -> (SignedRunningAcquireEffect, Arc<Mutex<AcquireState>>) {
        let state = Arc::new(Mutex::new(AcquireState {
            outcomes: outcomes.into(),
            checkpoint_path: Some(checkpoint_path),
            ..AcquireState::default()
        }));
        let port: Arc<dyn SignedNormalAcquirePort> = Arc::new(FakeAcquire {
            state: Arc::clone(&state),
        });
        let effect =
            SignedRunningAcquireEffect::new(port, authority, blob, lease_duration_ms).unwrap();
        // Ensure the fixture itself remains bound to the constructor budget.
        assert!(matches!(
            desired.volumes[0].acquire,
            VolumeAcquire::Normal { .. }
        ));
        (effect, state)
    }

    fn effect_with_release(
        desired: &DesiredRuntimeSpec,
        release_outcomes: Vec<NormalReleaseAttempt>,
        authority: Arc<FakeAuthority>,
        blob: Arc<RecordingBlob>,
        checkpoint_path: std::path::PathBuf,
    ) -> (SignedRunningAcquireEffect, Arc<Mutex<AcquireState>>) {
        let state = Arc::new(Mutex::new(AcquireState {
            release_outcomes: release_outcomes.into(),
            checkpoint_path: Some(checkpoint_path),
            ..AcquireState::default()
        }));
        let port: Arc<dyn SignedNormalAcquirePort> = Arc::new(FakeAcquire {
            state: Arc::clone(&state),
        });
        let effect = SignedRunningAcquireEffect::new(port, authority, blob, 60_000).unwrap();
        assert!(matches!(
            desired.volumes[0].acquire,
            VolumeAcquire::Normal { .. }
        ));
        (effect, state)
    }

    #[test]
    fn checkpoint_precedes_exact_acquire_and_only_advances_to_provision() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let (effect, calls) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            Arc::clone(&authority),
            Arc::clone(&blob),
            checkpoint_path.clone(),
        );
        let (context, deadline) = context(root.path(), &desired, None);

        let outcome = effect.apply(context, &desired).unwrap();

        assert_eq!(outcome, RuntimeDesiredEffectOutcome::RefreshInventory);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.checkpoint_seen_before_call, [true]);
        assert_eq!(calls.deadlines, [deadline]);
        assert_eq!(calls.requests.len(), 1);
        assert_exact_request(&calls.requests[0], &desired);
        assert_eq!(authority.loads.load(Ordering::SeqCst), 0);
        assert_eq!(blob.reads.load(Ordering::SeqCst), 1);
        assert_eq!(*blob.deadlines.lock().unwrap(), [deadline]);

        let checkpoint = read_checkpoint(&checkpoint_path);
        let ReconcileStep::ProvisionRootImage {
            control_socket_path,
            data_directory,
            scope_id,
            process_identity_token,
            expected_blank_head,
            expected_provisioned_head,
            ..
        } = &checkpoint.step
        else {
            panic!("expected ProvisionRootImage")
        };
        assert_eq!(expected_blank_head, &blank_head());
        assert_eq!(expected_provisioned_head.generation.get(), 1);
        assert!(expected_provisioned_head.root_hash.is_some());
        assert!(expected_provisioned_head.root_object_id.is_some());
        assert_eq!(
            scope_id.as_str(),
            format!("cats-root-{}.service", process_identity_token.as_str())
        );
        assert_eq!(
            control_socket_path.as_str(),
            format!("{}/{}", data_directory.as_str(), ROOT_PROVISION_SOCKET)
        );
        assert!(!std::path::Path::new(control_socket_path.as_str()).exists());
        assert!(checkpoint.processes.is_empty());
        assert!(checkpoint.networks.is_empty());
        assert!(checkpoint.mounts.is_empty());
        assert_eq!(checkpoint.runtime_incarnation, None);
        assert_eq!(checkpoint.stable_state, None);
        assert_eq!(checkpoint.lifecycle_admission, LifecycleAdmission::Closed);
        assert_eq!(checkpoint.volumes.len(), 1);
        assert!(matches!(
            checkpoint.volumes[0].authority,
            VolumeAuthorityEvidence::Owned { .. }
        ));
        assert_eq!(
            checkpoint.volumes[0].local_lineages,
            [expected_local_lineage(&attachment.identity, data_directory)]
        );

        let persisted: AuthorizedServingAttachment = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(data_directory.as_str()).join("authorized-serving.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(persisted, attachment);
        assert!(std::path::Path::new(data_directory.as_str())
            .join("identity.json")
            .is_file());
        assert!(std::path::Path::new(data_directory.as_str())
            .join("launch-checkpoint.json")
            .is_file());
        assert!(!root.path().join("runtime-effects").exists());
    }

    #[test]
    fn production_scanner_binds_provision_identity_and_exact_manifest_target() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let (effect, _) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            Arc::clone(&authority),
            Arc::clone(&blob),
            checkpoint_path.clone(),
        );
        let (context, _) = context(root.path(), &desired, None);
        assert_eq!(
            effect.apply(context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        authority.set(Ok(owned_record(&desired, &attachment)));
        let scanner_authority: Arc<dyn VolumeDataAuthority> = authority;
        let scanner_blob: Arc<dyn BlobStore> = blob;
        let scanner = fresh_scanner_with_blob(root.path(), scanner_authority, scanner_blob);
        assert!(matches!(
            scanner.scan_complete(scan_context(&desired)).unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));

        let store =
            FileCheckpointStore::open(&root.path().join(CHECKPOINT_NAMESPACE), &desired.cat_id)
                .unwrap();
        let current = store.load().unwrap().unwrap();
        let correct = current.checkpoint().clone();
        let mut wrong_target = current.checkpoint().clone();
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head,
            ..
        } = &mut wrong_target.step
        else {
            unreachable!("fixture reached ProvisionRootImage")
        };
        expected_provisioned_head.root_hash = Some(Sha256Digest::from_bytes([0x55; 32]));
        let wrong = store.replace(&current, &wrong_target).unwrap();
        assert!(scanner.scan_complete(scan_context(&desired)).is_err());

        let restored = store.replace(&wrong, &correct).unwrap();
        let mut wrong_token = restored.checkpoint().clone();
        let ReconcileStep::ProvisionRootImage {
            process_identity_token,
            ..
        } = &mut wrong_token.step
        else {
            unreachable!("fixture reached ProvisionRootImage")
        };
        *process_identity_token = random('9');
        store.replace(&restored, &wrong_token).unwrap();
        assert!(scanner.scan_complete(scan_context(&desired)).is_err());
    }

    #[test]
    fn cancellation_after_grant_persist_adopts_exact_lineage_after_fresh_full_restart() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let (base_effect, first_calls) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            Arc::clone(&authority),
            Arc::clone(&blob),
            checkpoint_path.clone(),
        );
        let interrupted_effect =
            base_effect.with_after_prepare(Arc::new(|context| context.cancel_for_test()));
        let (context, _) = context(root.path(), &desired, None);

        let error = interrupted_effect
            .apply(context, &desired)
            .expect_err("cancellation must stop before checkpoint replace");
        assert!(error
            .to_string()
            .contains("runtime Desired effect was cancelled"));
        assert_eq!(first_calls.lock().unwrap().requests.len(), 1);
        let acquire = read_checkpoint(&checkpoint_path);
        assert!(matches!(acquire.step, ReconcileStep::AcquireVolume { .. }));

        let data_directory =
            authorized_blockd_data_directory(root.path(), &desired, &attachment.identity);
        let before = prepared_file_snapshot(&data_directory);
        let recovered_volume = prepared_owned_observed_volume(
            &desired.volumes[0],
            &attachment,
            host(data_directory.clone()),
        );
        let fresh_runtime =
            observed_runtime(root.path(), &desired, Some((&acquire, recovered_volume)));
        authority.set(Ok(owned_record(&desired, &attachment)));
        let (restart_effect, restart_calls) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            authority,
            blob,
            checkpoint_path.clone(),
        );
        let (restart_context, _) = context_with_session(
            root.path(),
            &desired,
            Some(fresh_runtime),
            '8',
            3,
            1_900_000_010_000,
        );

        assert_eq!(
            restart_effect.apply(restart_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(restart_calls.lock().unwrap().requests.is_empty());
        assert_eq!(prepared_file_snapshot(&data_directory), before);
        assert_prepared_provision_checkpoint(
            &read_checkpoint(&checkpoint_path),
            &attachment,
            &data_directory,
        );
    }

    #[test]
    fn production_probe_fresh_scan_projects_exact_prepared_lineage_for_restart_adoption() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let (base_effect, _) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            Arc::clone(&authority),
            Arc::clone(&blob),
            checkpoint_path.clone(),
        );
        let interrupted_effect =
            base_effect.with_after_prepare(Arc::new(|context| context.cancel_for_test()));
        let (initial_context, _) = context(root.path(), &desired, None);
        interrupted_effect
            .apply(initial_context, &desired)
            .expect_err("fixture must stop after persisting the exact grant");
        let acquire = read_checkpoint(&checkpoint_path);
        assert_eq!(acquire.updated_at_unix_ms, unix_ms(1_900_000_000_000));

        authority.set(Ok(owned_record(&desired, &attachment)));
        let scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let scanner = fresh_scanner(root.path(), scanner_authority);
        let scan_session = SessionBinding {
            node_id: desired.placement.node_id.clone(),
            node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
            agent_instance_id: random('8'),
            agent_session_epoch: epoch(3),
        };
        let scan_context = RuntimeInventoryScanContext::for_test(
            RuntimeSpineFullScan {
                session: scan_session.clone(),
                heartbeat_sequence: sequence(10),
                inventory_epoch: epoch(5),
                desired: DesiredReadSnapshot {
                    version: ContractVersion::V1,
                    session: scan_session,
                    request_sequence: sequence(20),
                    read_position: sequence(21),
                    issued_at_unix_ms: unix_ms(1_900_000_005_000),
                    expires_at_unix_ms: unix_ms(1_900_000_035_000),
                    desired_specs: vec![desired.clone()],
                },
            },
            Instant::now() + Duration::from_secs(30),
        );
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(scan_context).unwrap()
        else {
            panic!("the exact checkpoint, grant files and authority must close a fresh scan")
        };
        let [scanned_runtime] = inventory.runtimes() else {
            panic!("fresh scan must project exactly one Runtime")
        };
        assert!(matches!(
            scanned_runtime.step,
            ReconcileStep::AcquireVolume { .. }
        ));
        assert_eq!(scanned_runtime.volumes.len(), 1);
        assert_eq!(scanned_runtime.volumes[0].local_lineages.len(), 1);
        assert_eq!(
            scanned_runtime.volumes[0].local_lineages[0].acquire_origin,
            attachment.identity.acquire_origin
        );

        let data_directory =
            authorized_blockd_data_directory(root.path(), &desired, &attachment.identity);
        let before = prepared_file_snapshot(&data_directory);
        let (restart_effect, restart_calls) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            Arc::clone(&authority),
            blob,
            checkpoint_path.clone(),
        );
        let (restart_context, _) = context_with_session(
            root.path(),
            &desired,
            Some(scanned_runtime.clone()),
            '8',
            3,
            1_900_000_010_000,
        );
        assert_eq!(
            restart_effect.apply(restart_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(restart_calls.lock().unwrap().requests.is_empty());
        assert_eq!(prepared_file_snapshot(&data_directory), before);
        let provision = read_checkpoint(&checkpoint_path);
        assert_eq!(provision.updated_at_unix_ms, unix_ms(1_900_000_010_000));
        assert_prepared_provision_checkpoint(&provision, &attachment, &data_directory);
    }

    #[test]
    fn acquire_checkpoint_restart_identity_ignores_only_observation_time() {
        let desired = desired();
        let attachment = attachment(&desired);
        let request = &attachment.acquire_request;
        let stored = acquire_checkpoint(
            &desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: VolumeAcquireRequest::Normal {
                    volume_id: request.volume_id.clone(),
                    transition_id: request.transition_id.clone(),
                    attachment_id: request.attachment_id.clone(),
                    expected_unowned_epoch: request.expected_unowned_epoch,
                    desired_revision: request.desired_revision,
                    placement_epoch: request.placement_epoch,
                    lease_duration_ms: request.lease_duration_ms,
                },
            },
            unix_ms(1_900_000_000_000),
        );
        let mut fresh = stored.clone();
        fresh.updated_at_unix_ms = unix_ms(1_900_000_010_000);
        assert!(checkpoint_eq_except_updated_at(&stored, &fresh));

        let mut changed = fresh.clone();
        changed.cat_id = id("cat_other");
        assert!(!checkpoint_eq_except_updated_at(&stored, &changed));
        let mut changed = fresh.clone();
        changed.desired_revision = Revision::new(2).unwrap();
        assert!(!checkpoint_eq_except_updated_at(&stored, &changed));
        let mut changed = fresh.clone();
        changed.spec_digest = Sha256Digest::from_bytes([8; 32]);
        assert!(!checkpoint_eq_except_updated_at(&stored, &changed));
        let mut changed = fresh.clone();
        changed.placement_epoch = epoch(4);
        assert!(!checkpoint_eq_except_updated_at(&stored, &changed));
        let ReconcileStep::AcquireVolume {
            request: VolumeAcquireRequest::Normal { transition_id, .. },
        } = &mut changed.step
        else {
            unreachable!("fixture checkpoint is normal acquire")
        };
        *transition_id = random('9');
        assert!(!checkpoint_eq_except_updated_at(&stored, &changed));
    }

    #[test]
    fn restart_replays_persisted_acquire_lease_when_current_config_changes() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let authority = Arc::new(FakeAuthority::new(Ok(unowned_record(&desired))));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let (first, first_calls) = effect_with_lease(
            &desired,
            vec![NormalAcquireAttempt::RetryExact],
            Arc::clone(&authority),
            Arc::clone(&blob),
            checkpoint_path.clone(),
            60_000,
        );
        let (first_context, _) = context(root.path(), &desired, None);
        assert_eq!(
            first.apply(first_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RetryExact
        );
        let acquire = read_checkpoint(&checkpoint_path);
        let acquire_runtime = observed_runtime(
            root.path(),
            &desired,
            Some((&acquire, unowned_observed_volume(&desired.volumes[0]))),
        );

        let attachment = attachment(&desired);
        let (restart, restart_calls) = effect_with_lease(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment))],
            authority,
            blob,
            checkpoint_path,
            90_000,
        );
        let (restart_context, _) = context_with_session(
            root.path(),
            &desired,
            Some(acquire_runtime),
            '8',
            3,
            1_900_000_010_000,
        );
        assert_eq!(
            restart.apply(restart_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let first = first_calls.lock().unwrap();
        let restart = restart_calls.lock().unwrap();
        let lease = |request: &RuntimeVolumeTransitionRequest| match &request.transition {
            RuntimeVolumeTransition::Acquire {
                request:
                    VolumeAcquireRequest::Normal {
                        lease_duration_ms, ..
                    },
            } => *lease_duration_ms,
            _ => unreachable!("fixture uses normal acquire"),
        };
        assert_eq!(lease(&first.requests[0]), 60_000);
        assert_eq!(lease(&restart.requests[0]), 60_000);
        assert_ne!(first.requests[0].session, restart.requests[0].session);
    }

    #[test]
    fn typed_pre_scan_supersession_never_rewrites_before_full_inventory() {
        for malformed in ["none", "extra-volume", "epoch-aba"] {
            let root = tempfile::tempdir().unwrap();
            let old = desired();
            let mut current = old.clone();
            current.desired_revision = Revision::new(2).unwrap();
            current.runtime.memory_bytes += 4096;
            current.placement.placement_epoch = epoch(4);
            current.spec_digest = spec_digest(&current).unwrap();
            let mut old_checkpoint = acquire_checkpoint_from_attachment(&old, &attachment(&old));
            match malformed {
                "none" => {}
                "extra-volume" => {
                    let mut extra = old_checkpoint.volumes[0].clone();
                    extra.volume_intent_id = Some(Id::new("other-intent").unwrap());
                    extra.disk_id = Some(Id::new("other-disk").unwrap());
                    extra.volume_id = Id::new("other-volume").unwrap();
                    old_checkpoint.volumes.push(extra);
                    old_checkpoint
                        .volumes
                        .sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
                }
                "epoch-aba" => {
                    let VolumeAuthorityEvidence::Unowned {
                        attachment_epoch, ..
                    } = &mut old_checkpoint.volumes[0].authority
                    else {
                        unreachable!("acquire fixture is Unowned")
                    };
                    *attachment_epoch = FenceEpoch::new(2).unwrap();
                }
                _ => unreachable!(),
            }
            persist_checkpoint(root.path(), &old_checkpoint);
            let path = checkpoint_path(root.path(), &current.cat_id);
            let before = std::fs::read(&path).unwrap();
            let authority = Arc::new(FakeAuthority::new(Ok(unowned_record(&current))));
            let recovery = SignedRunningPublicationRecovery::new(authority);

            assert_eq!(
                recovery
                    .recover_one(recovery_context(root.path(), &current))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange,
                "pre-scan supersession case {malformed}"
            );
            assert_eq!(std::fs::read(path).unwrap(), before);
        }
    }

    #[test]
    fn pre_scan_recovery_completes_every_authorized_blockd_publication_window() {
        for window in [
            PublicationWindow::BeforeIdentity,
            PublicationWindow::IdentityTemp,
            PublicationWindow::Identity,
            PublicationWindow::AuthorizedTemp,
            PublicationWindow::Authorized,
            PublicationWindow::LaunchTemp,
        ] {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let attachment = attachment(&desired);
            persist_acquire_checkpoint(root.path(), &desired);
            let authority = Arc::new(FakeAuthority::new(Ok(owned_record(&desired, &attachment))));
            let data_directory =
                authorized_blockd_data_directory(root.path(), &desired, &attachment.identity);
            drop(
                AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                    .prepare(&desired, &desired.volumes[0], &attachment)
                    .unwrap(),
            );
            shape_publication_window(&data_directory, window);

            let recovery = SignedRunningPublicationRecovery::new(authority);
            let outcome = recovery
                .recover_one(recovery_context(root.path(), &desired))
                .unwrap();
            assert_eq!(
                outcome,
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: desired.cat_id.clone()
                }
            );
            for name in [
                super::super::authorized_blockd::IDENTITY_FILE,
                super::super::authorized_blockd::AUTHORIZED_SERVING_FILE,
                super::super::authorized_blockd::LAUNCH_CHECKPOINT_FILE,
            ] {
                assert!(data_directory.join(name).is_file());
            }
            for name in [
                super::super::authorized_blockd::IDENTITY_TEMP,
                super::super::authorized_blockd::AUTHORIZED_SERVING_TEMP,
                super::super::authorized_blockd::LAUNCH_CHECKPOINT_TEMP,
            ] {
                assert!(!data_directory.join(name).exists());
            }

            assert_eq!(
                recovery
                    .recover_one(recovery_context(root.path(), &desired))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange
            );
        }
    }

    #[test]
    fn fork_kill_at_each_authorized_publication_barrier_recovers_exactly() {
        for point in [
            "identity.json:temp",
            "identity.json:target",
            "authorized-serving.json:temp",
            "authorized-serving.json:target",
            "launch-checkpoint.json:temp",
        ] {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let attachment = attachment(&desired);
            persist_acquire_checkpoint(root.path(), &desired);
            let marker = root.path().join("kill-ready");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("runtime::reconciliation::signed_running::tests::authorized_publication_kill_probe_child")
                .arg("--nocapture")
                .env("CATS_AUTHORIZED_BLOCKD_KILL_ROOT", root.path())
                .env("CATS_AUTHORIZED_BLOCKD_KILL_POINT", point)
                .env("CATS_AUTHORIZED_BLOCKD_KILL_MARKER", &marker)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !marker.exists() {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!("authorized publication child exited early at {point}: {status}");
                }
                assert!(
                    Instant::now() < deadline,
                    "kill probe did not reach {point}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            child.kill().unwrap();
            let status = child.wait().unwrap();
            assert!(!status.success());

            let authority = Arc::new(FakeAuthority::new(Ok(owned_record(&desired, &attachment))));
            let recovery = SignedRunningPublicationRecovery::new(authority);
            assert_eq!(
                recovery
                    .recover_one(recovery_context(root.path(), &desired))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: desired.cat_id.clone()
                },
                "failed to recover process-kill point {point}"
            );
            let data_directory =
                authorized_blockd_data_directory(root.path(), &desired, &attachment.identity);
            assert_eq!(
                prepared_file_snapshot(&data_directory).len(),
                3,
                "recovery did not complete {point}"
            );
        }
    }

    #[test]
    fn authorized_publication_kill_probe_child() {
        let Ok(root) = std::env::var("CATS_AUTHORIZED_BLOCKD_KILL_ROOT") else {
            return;
        };
        let desired = desired();
        let attachment = attachment(&desired);
        let prepared = AuthorizedBlockdStore::new(StateDirectory::unanchored(root.into()))
            .prepare(&desired, &desired.volumes[0], &attachment)
            .unwrap();
        drop(prepared);
        panic!("authorized publication kill probe passed its requested barrier");
    }

    #[test]
    fn pre_scan_recovery_settles_checkpoint_temp_but_never_hides_foreign_evidence() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        persist_acquire_checkpoint(root.path(), &desired);
        let temporary = root
            .path()
            .join(CHECKPOINT_NAMESPACE)
            .join(format!(".cat-{}.checkpoint.tmp", desired.cat_id));
        std::fs::write(&temporary, b"crashed writer bytes").unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
        let authority = Arc::new(FakeAuthority::new(Ok(unowned_record(&desired))));
        let recovery = SignedRunningPublicationRecovery::new(authority);
        assert_eq!(
            recovery
                .recover_one(recovery_context(root.path(), &desired))
                .unwrap(),
            RuntimePreScanRecoveryOutcome::Recovered {
                cat_id: desired.cat_id.clone()
            }
        );
        assert!(!temporary.exists());

        let attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Ok(owned_record(&desired, &attachment))));
        let data_directory =
            authorized_blockd_data_directory(root.path(), &desired, &attachment.identity);
        std::fs::create_dir_all(&data_directory).unwrap();
        set_directory_tree_mode(root.path(), &data_directory);
        let foreign = data_directory.join("foreign.bin");
        std::fs::write(&foreign, b"do not adopt").unwrap();
        let recovery = SignedRunningPublicationRecovery::new(authority);
        assert!(recovery
            .recover_one(recovery_context(root.path(), &desired))
            .is_err());
        assert_eq!(std::fs::read(foreign).unwrap(), b"do not adopt");
        assert!(!data_directory.join("identity.json").exists());
    }

    #[test]
    fn checkpoint_replace_conflict_after_grant_persist_restarts_without_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let (base_effect, first_calls) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            Arc::clone(&authority),
            Arc::clone(&blob),
            checkpoint_path.clone(),
        );
        let replaced_path = checkpoint_path.clone();
        let interrupted_effect = base_effect.with_after_prepare(Arc::new(move |_| {
            replace_with_exact_checkpoint_bytes(&replaced_path);
        }));
        let (context, _) = context(root.path(), &desired, None);

        let error = interrupted_effect
            .apply(context, &desired)
            .expect_err("changed checkpoint identity must reject replace");
        assert!(error
            .to_string()
            .contains("advance exact acquired root to provision_root_image"));
        assert!(format!("{error:#}").contains("checkpoint target changed after it was read"));
        assert_eq!(first_calls.lock().unwrap().requests.len(), 1);
        let acquire = read_checkpoint(&checkpoint_path);
        assert!(matches!(acquire.step, ReconcileStep::AcquireVolume { .. }));

        let data_directory =
            authorized_blockd_data_directory(root.path(), &desired, &attachment.identity);
        let before = prepared_file_snapshot(&data_directory);
        let fresh_runtime = observed_runtime(
            root.path(),
            &desired,
            Some((
                &acquire,
                prepared_owned_observed_volume(
                    &desired.volumes[0],
                    &attachment,
                    host(data_directory.clone()),
                ),
            )),
        );
        authority.set(Ok(owned_record(&desired, &attachment)));
        let (restart_effect, _) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            authority,
            blob,
            checkpoint_path.clone(),
        );
        let (restart_context, _) = context_with_session(
            root.path(),
            &desired,
            Some(fresh_runtime),
            '8',
            3,
            1_900_000_010_000,
        );

        assert_eq!(
            restart_effect.apply(restart_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert_eq!(prepared_file_snapshot(&data_directory), before);
        assert_prepared_provision_checkpoint(
            &read_checkpoint(&checkpoint_path),
            &attachment,
            &data_directory,
        );
    }

    #[test]
    fn foreign_persisted_lineage_is_preserved_and_never_replayed() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let (base_effect, _) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
            Arc::clone(&authority),
            Arc::clone(&blob),
            checkpoint_path.clone(),
        );
        let interrupted_effect =
            base_effect.with_after_prepare(Arc::new(|context| context.cancel_for_test()));
        let (context, _) = context(root.path(), &desired, None);
        interrupted_effect
            .apply(context, &desired)
            .expect_err("fixture cancellation");

        let acquire = read_checkpoint(&checkpoint_path);
        let data_directory =
            authorized_blockd_data_directory(root.path(), &desired, &attachment.identity);
        let identity_path = data_directory.join("identity.json");
        let mut foreign_identity = attachment.identity.clone();
        foreign_identity.acquire_origin = AcquireOrigin::Normal {
            transition_id: random('9'),
        };
        std::fs::write(
            &identity_path,
            serde_json::to_vec(&foreign_identity).unwrap(),
        )
        .unwrap();
        let foreign_bytes = std::fs::read(&identity_path).unwrap();

        let mut foreign_volume =
            prepared_owned_observed_volume(&desired.volumes[0], &attachment, host(data_directory));
        foreign_volume.local_lineages[0].acquire_origin = foreign_identity.acquire_origin;
        let fresh_runtime =
            observed_runtime(root.path(), &desired, Some((&acquire, foreign_volume)));
        let (restart_effect, calls) = effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment))],
            authority,
            blob,
            checkpoint_path.clone(),
        );
        let (restart_context, _) = context_with_session(
            root.path(),
            &desired,
            Some(fresh_runtime),
            '8',
            3,
            1_900_000_010_000,
        );

        let checkpoint_before = std::fs::read(&checkpoint_path).unwrap();
        assert_eq!(
            restart_effect.apply(restart_context, &desired).unwrap(),
            stop_local()
        );
        assert!(calls.lock().unwrap().requests.is_empty());
        assert_eq!(std::fs::read(identity_path).unwrap(), foreign_bytes);
        assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_before);
    }

    #[test]
    fn ambiguous_response_replays_exact_request_after_full_owned_recovery() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Ok(unowned_record(&desired))));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let (effect, calls) = effect(
            &desired,
            vec![
                NormalAcquireAttempt::Ambiguous,
                NormalAcquireAttempt::Ambiguous,
            ],
            Arc::clone(&authority),
            blob,
            checkpoint_path.clone(),
        );

        let (first_context, _) = context(root.path(), &desired, None);
        assert_eq!(
            effect.apply(first_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RetryExact
        );
        let acquire = read_checkpoint(&checkpoint_path);
        assert!(matches!(acquire.step, ReconcileStep::AcquireVolume { .. }));
        assert!(!root.path().join("data").exists());

        authority.set(Ok(owned_record(&desired, &attachment)));
        let owned_runtime = observed_runtime(
            root.path(),
            &desired,
            Some((
                &acquire,
                owned_observed_volume(&desired.volumes[0], &attachment),
            )),
        );
        let (recovered_context, _) = context(root.path(), &desired, Some(owned_runtime));
        assert_eq!(
            effect.apply(recovered_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );

        assert_eq!(authority.loads.load(Ordering::SeqCst), 2);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.requests.len(), 1);
        assert_eq!(calls.checkpoint_seen_before_call, [true]);
        assert!(matches!(
            read_checkpoint(&checkpoint_path).step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
    }

    #[test]
    fn closed_control_decisions_remain_typed_and_never_prepare_blockd() {
        let cases = [
            (
                NormalAcquireAttempt::RefreshInventory,
                RuntimeDesiredEffectOutcome::RefreshInventory,
            ),
            (
                NormalAcquireAttempt::ReplanDesired,
                RuntimeDesiredEffectOutcome::ReplanDesired,
            ),
            (
                NormalAcquireAttempt::IdentityRepairRequired,
                RuntimeDesiredEffectOutcome::IdentityRepairRequired,
            ),
            (
                NormalAcquireAttempt::SessionReplacementRequired,
                RuntimeDesiredEffectOutcome::SessionReplacementRequired,
            ),
            (
                NormalAcquireAttempt::StopForDeploymentMismatch,
                RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::DeploymentMismatch,
                ),
            ),
            (
                NormalAcquireAttempt::AuthorityRejected(
                    RuntimeVolumeAuthorityRejection::OtherWriter,
                ),
                RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::AuthorityRejected(
                        RuntimeVolumeAuthorityRejection::OtherWriter,
                    ),
                ),
            ),
        ];
        for (attempt, expected) in cases {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
            let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
            let blob = Arc::new(RecordingBlob::present(&desired));
            let (effect, _) = effect(&desired, vec![attempt], authority, blob, checkpoint_path);
            let (context, _) = context(root.path(), &desired, None);
            assert_eq!(effect.apply(context, &desired).unwrap(), expected);
            assert!(!root.path().join("data").exists());
        }
    }

    #[test]
    fn superseded_unowned_revision_spec_and_placement_stage_current_exact_acquire() {
        for change in ["revision", "spec", "placement"] {
            let root = tempfile::tempdir().unwrap();
            let old = desired();
            let mut current = old.clone();
            current.desired_revision = Revision::new(2).unwrap();
            match change {
                "revision" => {}
                "spec" => current.runtime.memory_bytes += 4096,
                "placement" => current.placement.placement_epoch = epoch(4),
                _ => unreachable!(),
            }
            current.spec_digest = spec_digest(&current).unwrap();
            let old_attachment = attachment(&old);
            let old_checkpoint = acquire_checkpoint_from_attachment(&old, &old_attachment);
            persist_checkpoint(root.path(), &old_checkpoint);
            let authority = Arc::new(FakeAuthority::new(Ok(unowned_record(&current))));
            let scanned = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
            assert_eq!(
                scanned.applied_desired.as_ref().unwrap().desired_revision,
                current.desired_revision
            );
            assert!(matches!(scanned.step, ReconcileStep::AcquireVolume { .. }));
            let blob = Arc::new(RecordingBlob::present(&current));
            let path = checkpoint_path(root.path(), &current.cat_id);
            let (effect, calls) = effect(
                &current,
                Vec::new(),
                authority,
                Arc::clone(&blob),
                path.clone(),
            );
            let (context, _) = context_with_session(
                root.path(),
                &current,
                Some(scanned),
                '8',
                3,
                1_900_000_010_000,
            );

            assert_eq!(
                effect.apply(context, &current).unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory,
                "{change}"
            );
            let rebound = read_checkpoint(&path);
            assert_eq!(rebound.desired_revision, current.desired_revision);
            assert_eq!(rebound.spec_digest, current.spec_digest);
            assert_eq!(rebound.placement_epoch, current.placement.placement_epoch);
            let ReconcileStep::AcquireVolume { request } = &rebound.step else {
                panic!("{change} did not stage current Acquire")
            };
            assert!(request_matches_volume(
                request,
                &current,
                &current.volumes[0]
            ));
            assert!(calls.lock().unwrap().requests.is_empty());
            assert_eq!(blob.reads.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn superseded_acquire_response_loss_adopts_only_after_current_journal_and_reread() {
        let root = tempfile::tempdir().unwrap();
        let old = desired();
        let mut current = old.clone();
        current.desired_revision = Revision::new(2).unwrap();
        current.runtime.memory_bytes += 4096;
        current.spec_digest = spec_digest(&current).unwrap();
        let old_attachment = attachment(&old);
        persist_checkpoint(
            root.path(),
            &acquire_checkpoint_from_attachment(&old, &old_attachment),
        );
        let authority = Arc::new(FakeAuthority::new(Ok(owned_record(&old, &old_attachment))));
        let first_scan = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let blob = Arc::new(RecordingBlob::present(&current));
        let path = checkpoint_path(root.path(), &current.cat_id);
        let (effect, calls) = effect(&current, Vec::new(), authority.clone(), blob, path.clone());
        let (first_context, _) = context_with_session(
            root.path(),
            &current,
            Some(first_scan),
            '8',
            3,
            1_900_000_010_000,
        );
        assert_eq!(
            effect.apply(first_context, &current).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let adoption = read_checkpoint(&path);
        assert_eq!(adoption.desired_revision, current.desired_revision);
        assert!(matches!(adoption.step, ReconcileStep::AcquireVolume { .. }));
        assert!(matches!(
            adoption.volumes[0].authority,
            VolumeAuthorityEvidence::Owned { .. }
        ));
        assert!(!root.path().join("data").exists());

        let second_scan = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let (second_context, _) = context_with_session(
            root.path(),
            &current,
            Some(second_scan),
            '8',
            3,
            1_900_000_020_000,
        );
        assert_eq!(
            effect.apply(second_context, &current).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let provision = read_checkpoint(&path);
        assert_eq!(provision.desired_revision, current.desired_revision);
        assert!(matches!(
            provision.step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
        assert!(calls.lock().unwrap().requests.is_empty());
        let third_scan = scan_runtime(root.path(), &current, authority, '8', 3);
        assert!(matches!(
            third_scan.step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
    }

    #[test]
    fn late_old_provision_is_rebound_only_for_the_same_image_and_placement() {
        for head_mode in ["blank", "late_target"] {
            let root = tempfile::tempdir().unwrap();
            let old = desired();
            let old_attachment = attachment(&old);
            let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
            let blob = Arc::new(RecordingBlob::present(&old));
            let path = checkpoint_path(root.path(), &old.cat_id);
            let (initial, _) = effect(
                &old,
                vec![NormalAcquireAttempt::Granted(Box::new(
                    old_attachment.clone(),
                ))],
                authority.clone(),
                blob,
                path.clone(),
            );
            let (initial_context, _) = context(root.path(), &old, None);
            assert_eq!(
                initial.apply(initial_context, &old).unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory
            );
            let old_provision = read_checkpoint(&path);
            let mut record = owned_record(&old, &old_attachment);
            if head_mode == "late_target" {
                let ReconcileStep::ProvisionRootImage {
                    expected_provisioned_head,
                    ..
                } = &old_provision.step
                else {
                    unreachable!()
                };
                record.head = expected_provisioned_head.clone();
            }
            authority.set(Ok(record));
            let mut current = old.clone();
            current.desired_revision = Revision::new(2).unwrap();
            current.runtime.memory_bytes += 4096;
            current.spec_digest = spec_digest(&current).unwrap();
            let scanned = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
            let current_blob = Arc::new(RecordingBlob::present(&current));
            let (planner, calls) = effect(
                &current,
                Vec::new(),
                authority.clone(),
                current_blob,
                path.clone(),
            );
            let (context, _) = context_with_session(
                root.path(),
                &current,
                Some(scanned),
                '8',
                3,
                1_900_000_010_000,
            );
            assert_eq!(
                planner.apply(context, &current).unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory,
                "{head_mode}"
            );
            let rebound = read_checkpoint(&path);
            assert_eq!(rebound.desired_revision, current.desired_revision);
            assert!(matches!(
                rebound.step,
                ReconcileStep::ProvisionRootImage { .. }
            ));
            assert!(calls.lock().unwrap().requests.is_empty());
            assert!(calls.lock().unwrap().release_requests.is_empty());
            let rescanned = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
            assert!(matches!(
                rescanned.step,
                ReconcileStep::ProvisionRootImage { .. }
            ));
        }
    }

    #[test]
    fn incompatible_late_image_is_released_then_stopped_without_fake_quarantine() {
        let root = tempfile::tempdir().unwrap();
        let old = desired();
        let old_attachment = attachment(&old);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let path = checkpoint_path(root.path(), &old.cat_id);
        let (initial, _) = effect(
            &old,
            vec![NormalAcquireAttempt::Granted(Box::new(
                old_attachment.clone(),
            ))],
            authority.clone(),
            Arc::new(RecordingBlob::present(&old)),
            path.clone(),
        );
        let (initial_context, _) = context(root.path(), &old, None);
        initial.apply(initial_context, &old).unwrap();
        let old_provision = read_checkpoint(&path);
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head: old_target,
            ..
        } = &old_provision.step
        else {
            unreachable!()
        };
        let mut owned = owned_record(&old, &old_attachment);
        owned.head = old_target.clone();
        authority.set(Ok(owned.clone()));

        let mut current = old.clone();
        current.desired_revision = Revision::new(2).unwrap();
        current.runtime.boot_image_digest = Sha256Digest::from_bytes([3; 32]);
        current.spec_digest = spec_digest(&current).unwrap();
        let stale = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let (planner, release_calls) = effect_with_release(
            &current,
            vec![NormalReleaseAttempt::Ambiguous],
            authority.clone(),
            Arc::new(RecordingBlob::present_with_chunk(&current, '4')),
            path.clone(),
        );
        let (stale_context, _) = context(root.path(), &current, Some(stale));
        assert_eq!(
            planner.apply(stale_context, &current).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let cleanup_checkpoint = read_checkpoint(&path);
        let ReconcileStep::CleanupRelease { cleanup } = &cleanup_checkpoint.step else {
            panic!(
                "incompatible provision must checkpoint release before A22: {:?}",
                cleanup_checkpoint.step
            )
        };
        let release_transition = cleanup
            .volume_release
            .as_ref()
            .unwrap()
            .release_transition_id
            .clone();
        assert!(release_calls.lock().unwrap().release_requests.is_empty());

        // A new Agent session cannot replay the old cleanup cursor. It first
        // republishes the same release identity under the new accepted scan.
        let restart_scan = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let (restart_context, _) = context_with_session(
            root.path(),
            &current,
            Some(restart_scan),
            '8',
            3,
            1_900_000_020_000,
        );
        assert_eq!(
            planner.apply(restart_context, &current).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let rebound_cleanup = read_checkpoint(&path);
        let ReconcileStep::CleanupRelease { cleanup } = &rebound_cleanup.step else {
            unreachable!()
        };
        assert_eq!(
            cleanup
                .volume_release
                .as_ref()
                .unwrap()
                .release_transition_id,
            release_transition
        );
        assert!(release_calls.lock().unwrap().release_requests.is_empty());

        let ready_scan = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let mut released = owned;
        let resulting_epoch = fence(old_attachment.identity.attachment_epoch.get() + 1);
        released.lease_owner = None;
        released.lease_epoch = resulting_epoch;
        released.lease_expires_at = None;
        released.last_transition = Some(LastVolumeTransition::Release {
            request: cats_api::runtime_reconciliation::ReleaseRequest {
                volume_id: current.volumes[0].volume_id.clone(),
                transition_id: release_transition.clone(),
                attachment_id: current.volumes[0].attachment_id.clone(),
                expected_epoch: old_attachment.identity.attachment_epoch,
            },
            result: cats_api::runtime_reconciliation::ReleaseResult {
                volume_id: current.volumes[0].volume_id.clone(),
                transition_id: release_transition,
                released_attachment_id: current.volumes[0].attachment_id.clone(),
                resulting_epoch,
                resulting_head: old_target.clone(),
            },
        });
        authority.set(Ok(released));
        let (ready_context, _) = context_with_session(
            root.path(),
            &current,
            Some(ready_scan),
            '8',
            3,
            1_900_000_030_000,
        );
        assert_eq!(
            planner.apply(ready_context, &current).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert_eq!(release_calls.lock().unwrap().release_requests.len(), 1);

        let released_scan = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let (released_context, _) = context_with_session(
            root.path(),
            &current,
            Some(released_scan),
            '8',
            3,
            1_900_000_040_000,
        );
        let released_checkpoint_bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            planner.apply(released_context, &current).unwrap(),
            stop_local()
        );
        assert_eq!(std::fs::read(&path).unwrap(), released_checkpoint_bytes);
        assert!(matches!(
            read_checkpoint(&path).step,
            ReconcileStep::CleanupRelease { .. }
        ));
        let closed = scan_runtime(root.path(), &current, authority, '8', 3);
        assert!(matches!(closed.step, ReconcileStep::CleanupRelease { .. }));
        assert!(closed.conditions.is_empty());
    }

    #[test]
    fn definite_cleanup_rejection_is_not_resent_after_fresh_full_scan() {
        let root = tempfile::tempdir().unwrap();
        let old = desired();
        let old_attachment = attachment(&old);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let path = checkpoint_path(root.path(), &old.cat_id);
        let (initial, _) = effect(
            &old,
            vec![NormalAcquireAttempt::Granted(Box::new(
                old_attachment.clone(),
            ))],
            authority.clone(),
            Arc::new(RecordingBlob::present(&old)),
            path.clone(),
        );
        let (initial_context, _) = context(root.path(), &old, None);
        initial.apply(initial_context, &old).unwrap();
        let provision = read_checkpoint(&path);
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head,
            ..
        } = &provision.step
        else {
            unreachable!()
        };
        let mut owned = owned_record(&old, &old_attachment);
        owned.head = expected_provisioned_head.clone();
        authority.set(Ok(owned));

        let mut current = old.clone();
        current.desired_revision = Revision::new(2).unwrap();
        current.runtime.boot_image_digest = Sha256Digest::from_bytes([3; 32]);
        current.spec_digest = spec_digest(&current).unwrap();
        let stale = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let (planner, calls) = effect_with_release(
            &current,
            vec![
                NormalReleaseAttempt::StopForLocalContract,
                NormalReleaseAttempt::Released(cats_api::runtime_reconciliation::ReleaseResult {
                    volume_id: current.volumes[0].volume_id.clone(),
                    transition_id: random('7'),
                    released_attachment_id: current.volumes[0].attachment_id.clone(),
                    resulting_epoch: fence(2),
                    resulting_head: expected_provisioned_head.clone(),
                }),
            ],
            authority.clone(),
            Arc::new(RecordingBlob::present_with_chunk(&current, '4')),
            path.clone(),
        );
        let (stage_context, _) = context_with_session(
            root.path(),
            &current,
            Some(stale),
            '8',
            3,
            1_900_000_010_000,
        );
        assert_eq!(
            planner.apply(stage_context, &current).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let cleanup_bytes = std::fs::read(&path).unwrap();

        for observed_at in [1_900_000_020_000, 1_900_000_030_000] {
            let scan = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
            let (context, _) =
                context_with_session(root.path(), &current, Some(scan), '8', 3, observed_at);
            assert_eq!(planner.apply(context, &current).unwrap(), stop_local());
            assert_eq!(std::fs::read(&path).unwrap(), cleanup_bytes);
        }
        assert_eq!(calls.lock().unwrap().release_requests.len(), 1);
    }

    #[test]
    fn placement_or_attachment_conflict_stops_without_release_or_overwrite() {
        for conflict in ["placement", "attachment"] {
            let root = tempfile::tempdir().unwrap();
            let old = desired();
            let old_attachment = attachment(&old);
            let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
            let path = checkpoint_path(root.path(), &old.cat_id);
            let (initial, _) = effect(
                &old,
                vec![NormalAcquireAttempt::Granted(Box::new(
                    old_attachment.clone(),
                ))],
                authority.clone(),
                Arc::new(RecordingBlob::present(&old)),
                path.clone(),
            );
            let (initial_context, _) = context(root.path(), &old, None);
            initial.apply(initial_context, &old).unwrap();
            let data_directory =
                authorized_blockd_data_directory(root.path(), &old, &old_attachment.identity);
            let before = prepared_file_snapshot(&data_directory);
            authority.set(Ok(owned_record(&old, &old_attachment)));
            let mut current = old.clone();
            current.desired_revision = Revision::new(2).unwrap();
            match conflict {
                "placement" => current.placement.placement_epoch = epoch(4),
                "attachment" => current.volumes[0].attachment_id = id("att_replacement"),
                _ => unreachable!(),
            }
            current.spec_digest = spec_digest(&current).unwrap();
            let scanned = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
            let (planner, calls) = effect_with_release(
                &current,
                vec![NormalReleaseAttempt::Released(
                    cats_api::runtime_reconciliation::ReleaseResult {
                        volume_id: current.volumes[0].volume_id.clone(),
                        transition_id: random('7'),
                        released_attachment_id: current.volumes[0].attachment_id.clone(),
                        resulting_epoch: fence(2),
                        resulting_head: blank_head(),
                    },
                )],
                authority.clone(),
                Arc::new(RecordingBlob::present(&current)),
                path.clone(),
            );
            let (context, _) = context_with_session(
                root.path(),
                &current,
                Some(scanned),
                '8',
                3,
                1_900_000_010_000,
            );
            let checkpoint_before = std::fs::read(&path).unwrap();
            assert_eq!(
                planner.apply(context, &current).unwrap(),
                stop_local(),
                "{conflict}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), checkpoint_before);
            assert!(calls.lock().unwrap().release_requests.is_empty());
            assert_eq!(prepared_file_snapshot(&data_directory), before);
            let closed = scan_runtime(root.path(), &current, authority, '8', 3);
            assert!(matches!(
                closed.step,
                ReconcileStep::ProvisionRootImage { .. }
            ));
            assert!(closed.conditions.is_empty());
        }
    }

    #[test]
    fn different_root_intent_stops_with_both_authority_records_preserved() {
        let root = tempfile::tempdir().unwrap();
        let old = desired();
        let old_attachment = attachment(&old);
        persist_checkpoint(
            root.path(),
            &acquire_checkpoint_from_attachment(&old, &old_attachment),
        );
        let mut current = old.clone();
        current.desired_revision = Revision::new(2).unwrap();
        current.volumes[0].volume_intent_id = id("vint_replacement");
        current.volumes[0].disk_id = id("disk_replacement");
        current.volumes[0].volume_id = id("vol_replacement");
        current.volumes[0].attachment_id = id("att_replacement");
        current.volumes[0].acquire = VolumeAcquire::Normal {
            transition_id: random('7'),
            expected_unowned_epoch: fence(0),
        };
        current.spec_digest = spec_digest(&current).unwrap();
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        authority.set_records(BTreeMap::from([
            (
                old.volumes[0].volume_id.clone(),
                Ok(owned_record(&old, &old_attachment)),
            ),
            (
                current.volumes[0].volume_id.clone(),
                Ok(unowned_record(&current)),
            ),
        ]));
        let stale = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        assert_eq!(stale.volumes.len(), 2);
        assert!(stale.conditions.is_empty());
        let path = checkpoint_path(root.path(), &current.cat_id);
        let checkpoint_before = std::fs::read(&path).unwrap();
        let (planner, calls) = effect(
            &current,
            Vec::new(),
            authority.clone(),
            Arc::new(RecordingBlob::present(&current)),
            path.clone(),
        );
        let (context, _) = context_with_session(
            root.path(),
            &current,
            Some(stale),
            '8',
            3,
            1_900_000_010_000,
        );

        assert_eq!(planner.apply(context, &current).unwrap(), stop_local());
        assert_eq!(std::fs::read(&path).unwrap(), checkpoint_before);
        assert!(calls.lock().unwrap().requests.is_empty());
        assert!(calls.lock().unwrap().release_requests.is_empty());
        let closed = scan_runtime(root.path(), &current, authority, '8', 3);
        assert!(matches!(closed.step, ReconcileStep::AcquireVolume { .. }));
        assert_eq!(closed.volumes.len(), 2);
        assert!(closed.conditions.is_empty());
    }

    #[test]
    fn extra_unowned_volume_full_scan_never_rebinds_stale_acquire() {
        let root = tempfile::tempdir().unwrap();
        let old = desired();
        persist_checkpoint(
            root.path(),
            &acquire_checkpoint_from_attachment(&old, &attachment(&old)),
        );
        let mut current = old.clone();
        current.desired_revision = Revision::new(2).unwrap();
        current.volumes[0].volume_intent_id = id("vint_replacement");
        current.volumes[0].disk_id = id("disk_replacement");
        current.volumes[0].volume_id = id("vol_replacement");
        current.volumes[0].attachment_id = id("att_replacement");
        current.volumes[0].acquire = VolumeAcquire::Normal {
            transition_id: random('7'),
            expected_unowned_epoch: fence(0),
        };
        current.spec_digest = spec_digest(&current).unwrap();
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        authority.set_records(BTreeMap::from([
            (old.volumes[0].volume_id.clone(), Ok(unowned_record(&old))),
            (
                current.volumes[0].volume_id.clone(),
                Ok(unowned_record(&current)),
            ),
        ]));
        let scanned = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        assert_eq!(scanned.volumes.len(), 2);
        assert!(scanned.conditions.is_empty());
        let path = checkpoint_path(root.path(), &current.cat_id);
        let checkpoint_before = std::fs::read(&path).unwrap();
        let (planner, calls) = effect(
            &current,
            Vec::new(),
            authority,
            Arc::new(RecordingBlob::present(&current)),
            path.clone(),
        );
        let (context, _) = context_with_session(
            root.path(),
            &current,
            Some(scanned),
            '8',
            3,
            1_900_000_010_000,
        );

        assert_eq!(planner.apply(context, &current).unwrap(), stop_local());
        assert_eq!(std::fs::read(path).unwrap(), checkpoint_before);
        assert!(calls.lock().unwrap().requests.is_empty());
        assert!(calls.lock().unwrap().release_requests.is_empty());
    }

    #[test]
    fn scan_checkpoint_digest_change_is_refresh_not_stale_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let old = desired();
        let mut current = old.clone();
        current.desired_revision = Revision::new(2).unwrap();
        current.spec_digest = spec_digest(&current).unwrap();
        let old_checkpoint = acquire_checkpoint_from_attachment(&old, &attachment(&old));
        persist_checkpoint(root.path(), &old_checkpoint);
        let authority = Arc::new(FakeAuthority::new(Ok(unowned_record(&current))));
        let scanned = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let checkpoint_store =
            FileCheckpointStore::open(&root.path().join(CHECKPOINT_NAMESPACE), &current.cat_id)
                .unwrap();
        let predecessor = checkpoint_store.load().unwrap().unwrap();
        let mut concurrent = predecessor.checkpoint().clone();
        concurrent.updated_at_unix_ms = unix_ms(1_900_000_099_000);
        checkpoint_store.replace(&predecessor, &concurrent).unwrap();
        drop(checkpoint_store);
        let path = checkpoint_path(root.path(), &current.cat_id);
        let (planner, calls) = effect(
            &current,
            Vec::new(),
            authority,
            Arc::new(RecordingBlob::present(&current)),
            path.clone(),
        );
        let (context, _) = context_with_session(
            root.path(),
            &current,
            Some(scanned),
            '8',
            3,
            1_900_000_010_000,
        );
        assert_eq!(
            planner.apply(context, &current).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert_eq!(read_checkpoint(&path), concurrent);
        assert!(calls.lock().unwrap().requests.is_empty());
    }

    #[test]
    fn superseded_desired_and_missing_image_have_zero_authority_effect() {
        let root = tempfile::tempdir().unwrap();
        let accepted_desired = desired();
        let mut superseded = accepted_desired.clone();
        superseded.desired_revision = Revision::new(2).unwrap();
        superseded.spec_digest = spec_digest(&superseded).unwrap();
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&superseded));
        let superseded_checkpoint_path = checkpoint_path(root.path(), &superseded.cat_id);
        let (superseded_effect, calls) = effect(
            &superseded,
            vec![NormalAcquireAttempt::RetryExact],
            Arc::clone(&authority),
            Arc::clone(&blob),
            superseded_checkpoint_path.clone(),
        );
        let (superseded_context, _) = context(root.path(), &accepted_desired, None);
        assert_eq!(
            superseded_effect
                .apply(superseded_context, &superseded)
                .unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(calls.lock().unwrap().requests.is_empty());
        assert_eq!(blob.reads.load(Ordering::SeqCst), 0);
        assert_eq!(authority.loads.load(Ordering::SeqCst), 0);
        assert!(!superseded_checkpoint_path.exists());

        let missing_root = tempfile::tempdir().unwrap();
        let desired = desired();
        let missing_blob = Arc::new(RecordingBlob::missing());
        let missing_checkpoint = checkpoint_path(missing_root.path(), &desired.cat_id);
        let (effect, calls) = effect(
            &desired,
            vec![NormalAcquireAttempt::RetryExact],
            Arc::clone(&authority),
            Arc::clone(&missing_blob),
            missing_checkpoint.clone(),
        );
        let (context, _) = context(missing_root.path(), &desired, None);
        assert_eq!(
            effect.apply(context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RetryExact
        );
        assert!(calls.lock().unwrap().requests.is_empty());
        assert_eq!(missing_blob.reads.load(Ordering::SeqCst), 1);
        assert_eq!(authority.loads.load(Ordering::SeqCst), 0);
        assert!(!missing_checkpoint.exists());
    }

    #[derive(Clone, Copy)]
    enum PublicationWindow {
        BeforeIdentity,
        IdentityTemp,
        Identity,
        AuthorizedTemp,
        Authorized,
        LaunchTemp,
    }

    fn persist_acquire_checkpoint(root: &std::path::Path, desired: &DesiredRuntimeSpec) {
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: desired.placement.node_id.clone(),
            immutable_host_id: id("host_a"),
            node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
            agent_instance_id: random('4'),
            agent_session_epoch: epoch(2),
            registration_attempt_id: random('5'),
            guest_config_digest: desired.runtime.guest_config_digest.clone(),
            lease_deadline_unix_ms: unix_ms(1_900_000_120_000),
        };
        let request = normal_acquire_request(desired, &desired.volumes[0], &session, 60_000);
        let checkpoint = acquire_checkpoint(
            desired,
            &desired.volumes[0],
            request.transition,
            unix_ms(1_900_000_000_000),
        );
        let store =
            FileCheckpointStore::open(&root.join(CHECKPOINT_NAMESPACE), &desired.cat_id).unwrap();
        store.create(&checkpoint).unwrap();
    }

    fn recovery_context(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
    ) -> RuntimePreScanRecoveryContext {
        let session = SessionBinding {
            node_id: desired.placement.node_id.clone(),
            node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
            agent_instance_id: random('8'),
            agent_session_epoch: epoch(3),
        };
        RuntimePreScanRecoveryContext::for_test(
            StateDirectory::unanchored(root.to_path_buf()),
            RuntimeSpineFullScan {
                session: session.clone(),
                heartbeat_sequence: sequence(10),
                inventory_epoch: epoch(5),
                desired: DesiredReadSnapshot {
                    version: ContractVersion::V1,
                    session,
                    request_sequence: sequence(20),
                    read_position: sequence(21),
                    issued_at_unix_ms: unix_ms(1_900_000_005_000),
                    expires_at_unix_ms: unix_ms(1_900_000_035_000),
                    desired_specs: vec![desired.clone()],
                },
            },
            Instant::now() + Duration::from_secs(30),
        )
    }

    fn shape_publication_window(directory: &std::path::Path, window: PublicationWindow) {
        use super::super::authorized_blockd::{
            AUTHORIZED_SERVING_FILE, AUTHORIZED_SERVING_TEMP, IDENTITY_FILE, IDENTITY_TEMP,
            LAUNCH_CHECKPOINT_FILE, LAUNCH_CHECKPOINT_TEMP,
        };
        match window {
            PublicationWindow::BeforeIdentity => {
                std::fs::remove_dir_all(directory).unwrap();
            }
            PublicationWindow::IdentityTemp => {
                std::fs::remove_file(directory.join(AUTHORIZED_SERVING_FILE)).unwrap();
                std::fs::remove_file(directory.join(LAUNCH_CHECKPOINT_FILE)).unwrap();
                std::fs::rename(directory.join(IDENTITY_FILE), directory.join(IDENTITY_TEMP))
                    .unwrap();
            }
            PublicationWindow::Identity => {
                std::fs::remove_file(directory.join(AUTHORIZED_SERVING_FILE)).unwrap();
                std::fs::remove_file(directory.join(LAUNCH_CHECKPOINT_FILE)).unwrap();
            }
            PublicationWindow::AuthorizedTemp => {
                std::fs::remove_file(directory.join(LAUNCH_CHECKPOINT_FILE)).unwrap();
                std::fs::rename(
                    directory.join(AUTHORIZED_SERVING_FILE),
                    directory.join(AUTHORIZED_SERVING_TEMP),
                )
                .unwrap();
            }
            PublicationWindow::Authorized => {
                std::fs::remove_file(directory.join(LAUNCH_CHECKPOINT_FILE)).unwrap();
            }
            PublicationWindow::LaunchTemp => {
                std::fs::rename(
                    directory.join(LAUNCH_CHECKPOINT_FILE),
                    directory.join(LAUNCH_CHECKPOINT_TEMP),
                )
                .unwrap();
            }
        }
    }

    fn set_directory_tree_mode(root: &std::path::Path, leaf: &std::path::Path) {
        let mut path = root.to_path_buf();
        for component in leaf.strip_prefix(root).unwrap().components() {
            path.push(component);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
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
            durability: cats_api::runtime_reconciliation::Durability::Strict,
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

    fn context(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        runtime: Option<ObservedRuntimeStatus>,
    ) -> (RuntimeDesiredEffectContext, Instant) {
        context_with_session(root, desired, runtime, '4', 2, 1_900_000_000_000)
    }

    fn context_with_session(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        runtime: Option<ObservedRuntimeStatus>,
        agent_instance: char,
        session_epoch: u64,
        accepted_at_unix_ms: u64,
    ) -> (RuntimeDesiredEffectContext, Instant) {
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: desired.placement.node_id.clone(),
            immutable_host_id: id("host_a"),
            node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
            agent_instance_id: random(agent_instance),
            agent_session_epoch: epoch(session_epoch),
            registration_attempt_id: random('5'),
            guest_config_digest: desired.runtime.guest_config_digest.clone(),
            lease_deadline_unix_ms: unix_ms(1_900_000_120_000),
        };
        let digest = Sha256Digest::from_bytes([7; 32]);
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            inventory_epoch: epoch(4),
            inventory_digest: digest.clone(),
            inventory_read_position: sequence(12),
            accepted_at_unix_ms: unix_ms(accepted_at_unix_ms),
        };
        let observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: random('6'),
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: sequence(9),
            observed_at_unix_ms: unix_ms(1_899_999_999_000),
            complete_inventory: true,
            inventory_epoch: attestation.inventory_epoch,
            inventory_digest: Some(digest),
            inventory_read_position: Some(attestation.inventory_read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: vec![runtime.unwrap_or_else(|| observed_runtime(root, desired, None))],
            residue: Vec::new(),
        };
        let admission = RuntimeDesiredEffectAdmission::for_test(session, observation, attestation);
        let deadline = Instant::now() + Duration::from_secs(30);
        (
            RuntimeDesiredEffectContext::for_test_with_admission(
                StateDirectory::unanchored(root.to_path_buf()),
                deadline,
                admission,
            ),
            deadline,
        )
    }

    fn fresh_scanner(
        root: &std::path::Path,
        authority: Arc<dyn VolumeDataAuthority>,
    ) -> Arc<dyn crate::runtime_spine::RuntimeInventoryScanner> {
        let proc_root = root.join("probe-proc");
        let systemd_root = root.join("probe-systemd");
        let block_root = root.join("probe-block");
        let network_root = root.join("probe-network");
        let socket_root = root.join("probe-sockets");
        for directory in [
            &proc_root,
            &systemd_root,
            &block_root,
            &network_root,
            &socket_root,
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        clean_slate_scanner_with_volume_authority_for_test(
            TestCleanSlateProbeConfig {
                state_directory: StateDirectory::unanchored(root.to_path_buf()),
                proc_root,
                systemd_cgroup_root: systemd_root,
                block_class_root: block_root,
                network_class_root: network_root,
                legacy_socket_root: socket_root,
                cloud_hypervisor_binary: root.join("bin/cloud-hypervisor"),
                blockd_binary: root.join("bin/cats-blockd"),
                guest_agent_binary: root.join("bin/cats-guest-agent"),
            },
            authority,
        )
        .unwrap()
    }

    fn fresh_scanner_with_blob(
        root: &std::path::Path,
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
    ) -> Arc<dyn crate::runtime_spine::RuntimeInventoryScanner> {
        let proc_root = root.join("probe-proc");
        let systemd_root = root.join("probe-systemd");
        let block_root = root.join("probe-block");
        let network_root = root.join("probe-network");
        let socket_root = root.join("probe-sockets");
        for directory in [
            &proc_root,
            &systemd_root,
            &block_root,
            &network_root,
            &socket_root,
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        clean_slate_scanner_with_volume_authority_and_blob_for_test(
            TestCleanSlateProbeConfig {
                state_directory: StateDirectory::unanchored(root.to_path_buf()),
                proc_root,
                systemd_cgroup_root: systemd_root,
                block_class_root: block_root,
                network_class_root: network_root,
                legacy_socket_root: socket_root,
                cloud_hypervisor_binary: root.join("bin/cloud-hypervisor"),
                blockd_binary: root.join("bin/cats-blockd"),
                guest_agent_binary: root.join("bin/cats-guest-agent"),
            },
            authority,
            blob,
        )
        .unwrap()
    }

    fn scan_context(desired: &DesiredRuntimeSpec) -> RuntimeInventoryScanContext {
        let session = SessionBinding {
            node_id: desired.placement.node_id.clone(),
            node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
            agent_instance_id: random('8'),
            agent_session_epoch: epoch(3),
        };
        RuntimeInventoryScanContext::for_test(
            RuntimeSpineFullScan {
                session: session.clone(),
                heartbeat_sequence: sequence(10),
                inventory_epoch: epoch(5),
                desired: DesiredReadSnapshot {
                    version: ContractVersion::V1,
                    session,
                    request_sequence: sequence(20),
                    read_position: sequence(21),
                    issued_at_unix_ms: unix_ms(1_900_000_005_000),
                    expires_at_unix_ms: unix_ms(1_900_000_035_000),
                    desired_specs: vec![desired.clone()],
                },
            },
            Instant::now() + Duration::from_secs(30),
        )
    }

    fn scan_runtime(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        authority: Arc<dyn VolumeDataAuthority>,
        agent_instance: char,
        session_epoch: u64,
    ) -> ObservedRuntimeStatus {
        let scanner =
            fresh_scanner_with_blob(root, authority, Arc::new(RecordingBlob::present(desired)));
        let session = SessionBinding {
            node_id: desired.placement.node_id.clone(),
            node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
            agent_instance_id: random(agent_instance),
            agent_session_epoch: epoch(session_epoch),
        };
        let scan_context = RuntimeInventoryScanContext::for_test(
            RuntimeSpineFullScan {
                session: session.clone(),
                heartbeat_sequence: sequence(10),
                inventory_epoch: epoch(5),
                desired: DesiredReadSnapshot {
                    version: ContractVersion::V1,
                    session,
                    request_sequence: sequence(20),
                    read_position: sequence(21),
                    issued_at_unix_ms: unix_ms(1_900_000_005_000),
                    expires_at_unix_ms: unix_ms(1_900_000_035_000),
                    desired_specs: vec![desired.clone()],
                },
            },
            Instant::now() + Duration::from_secs(30),
        );
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(scan_context).unwrap()
        else {
            panic!("fixture inventory did not complete")
        };
        let [runtime] = inventory.runtimes() else {
            panic!("fixture inventory did not contain exactly one Runtime")
        };
        runtime.clone()
    }

    fn observed_runtime(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        acquired: Option<(&RuntimeCheckpoint, ObservedVolume)>,
    ) -> ObservedRuntimeStatus {
        let (step, checkpoint, volume) = match acquired {
            Some((stored, volume)) => (
                stored.step.clone(),
                CheckpointEvidence::Valid {
                    checkpoint_path: host(checkpoint_path(root, &desired.cat_id)),
                    content_digest: cats_api::runtime_reconciliation::checkpoint_content_digest(
                        stored,
                    )
                    .unwrap(),
                    version: stored.version,
                    cat_id: stored.cat_id.clone(),
                    node_id: stored.node_id.clone(),
                    desired_revision: stored.desired_revision,
                    spec_digest: stored.spec_digest.clone(),
                    placement_epoch: stored.placement_epoch,
                    runtime_incarnation: stored.runtime_incarnation.clone(),
                    stable_state: stored.stable_state,
                    step: Box::new(stored.step.clone()),
                    require_idle: Box::new(stored.require_idle.clone()),
                    updated_at_unix_ms: stored.updated_at_unix_ms,
                },
                volume,
            ),
            None => {
                let step = ReconcileStep::InspectInventory {
                    inventory_epoch: epoch(4),
                };
                (
                    step,
                    CheckpointEvidence::Missing {
                        checkpoint_path: host(checkpoint_path(root, &desired.cat_id)),
                    },
                    unowned_observed_volume(&desired.volumes[0]),
                )
            }
        };
        ObservedRuntimeStatus {
            cat_id: desired.cat_id.clone(),
            applied_desired: Some(AppliedDesiredEvidence {
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement: desired.placement.clone(),
                target: desired.target,
            }),
            runtime_incarnation: None,
            stable_state: None,
            step: step.clone(),
            checkpoint,
            processes: Vec::new(),
            volumes: vec![volume],
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            routes: Vec::new(),
            platform_guards: 0,
            conditions: vec![Condition::Progressing {
                reason: ProgressingReason::ReconcileStep { step },
            }],
        }
    }

    fn attachment(desired: &DesiredRuntimeSpec) -> AuthorizedServingAttachment {
        let volume = &desired.volumes[0];
        let VolumeAcquire::Normal {
            transition_id,
            expected_unowned_epoch,
        } = &volume.acquire
        else {
            unreachable!()
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
            resulting_epoch: fence(expected_unowned_epoch.get() + 1),
            resulting_head: blank_head(),
            lease_expires_at: unix_ms(1_900_000_060_000),
        };
        AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: result.resulting_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: transition_id.clone(),
                },
                node_id: desired.placement.node_id.clone(),
                placement_epoch: desired.placement.placement_epoch,
            },
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            head: blank_head(),
            lease_expires_at: result.lease_expires_at,
            acquire_request: request,
            acquire_result: result,
        }
    }

    fn acquire_checkpoint_from_attachment(
        desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
    ) -> RuntimeCheckpoint {
        let request = &attachment.acquire_request;
        acquire_checkpoint(
            desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: VolumeAcquireRequest::Normal {
                    volume_id: request.volume_id.clone(),
                    transition_id: request.transition_id.clone(),
                    attachment_id: request.attachment_id.clone(),
                    expected_unowned_epoch: request.expected_unowned_epoch,
                    desired_revision: request.desired_revision,
                    placement_epoch: request.placement_epoch,
                    lease_duration_ms: request.lease_duration_ms,
                },
            },
            unix_ms(1_900_000_000_000),
        )
    }

    fn persist_checkpoint(root: &std::path::Path, checkpoint: &RuntimeCheckpoint) {
        let store = FileCheckpointStore::open(&root.join(CHECKPOINT_NAMESPACE), &checkpoint.cat_id)
            .unwrap();
        store.create(checkpoint).unwrap();
    }

    fn unowned_record(desired: &DesiredRuntimeSpec) -> VolumeRecord {
        let volume = &desired.volumes[0];
        let VolumeAcquire::Normal {
            expected_unowned_epoch,
            ..
        } = volume.acquire
        else {
            unreachable!()
        };
        VolumeRecord {
            volume_id: volume.volume_id.clone(),
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            admin_state: VolumeAdminState::Active,
            head: blank_head(),
            lease_owner: None,
            lease_epoch: expected_unowned_epoch,
            lease_expires_at: None,
            last_transition: None,
        }
    }

    fn owned_record(
        _desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
    ) -> VolumeRecord {
        VolumeRecord {
            volume_id: attachment.identity.volume_id.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            admin_state: VolumeAdminState::Active,
            head: attachment.head.clone(),
            lease_owner: Some(attachment.identity.attachment_id.clone()),
            lease_epoch: attachment.identity.attachment_epoch,
            lease_expires_at: Some(attachment.lease_expires_at),
            last_transition: Some(LastVolumeTransition::NormalAcquire {
                request: attachment.acquire_request.clone(),
                result: attachment.acquire_result.clone(),
            }),
        }
    }

    fn assert_exact_request(
        request: &RuntimeVolumeTransitionRequest,
        desired: &DesiredRuntimeSpec,
    ) {
        assert_eq!(request.cat_id, desired.cat_id);
        assert_eq!(request.desired_revision, desired.desired_revision);
        assert_eq!(request.spec_digest, desired.spec_digest);
        assert_eq!(request.placement, desired.placement);
        let RuntimeVolumeTransition::Acquire { request } = &request.transition else {
            panic!("expected acquire")
        };
        assert!(request_matches_volume(
            request,
            desired,
            &desired.volumes[0]
        ));
        let VolumeAcquireRequest::Normal {
            lease_duration_ms, ..
        } = request
        else {
            panic!("expected normal acquire")
        };
        assert_eq!(*lease_duration_ms, 60_000);
    }

    fn read_checkpoint(path: &std::path::Path) -> RuntimeCheckpoint {
        decode_runtime_checkpoint(&std::fs::read(path).unwrap()).unwrap()
    }

    fn prepared_file_snapshot(data_directory: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        [
            "identity.json",
            "authorized-serving.json",
            "launch-checkpoint.json",
        ]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                std::fs::read(data_directory.join(name)).unwrap(),
            )
        })
        .collect()
    }

    fn replace_with_exact_checkpoint_bytes(path: &std::path::Path) {
        let bytes = std::fs::read(path).unwrap();
        let replacement = path.with_file_name(".signed-running-concurrent-replace.tmp");
        let file = std::fs::File::create(&replacement).unwrap();
        std::fs::set_permissions(
            &replacement,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        use std::io::Write as _;
        (&file).write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        std::fs::rename(&replacement, path).unwrap();
        std::fs::File::open(path.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
    }

    fn assert_prepared_provision_checkpoint(
        checkpoint: &RuntimeCheckpoint,
        attachment: &AuthorizedServingAttachment,
        data_directory: &std::path::Path,
    ) {
        assert!(matches!(
            checkpoint.step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
        let [volume] = checkpoint.volumes.as_slice() else {
            panic!("prepared checkpoint must contain one root")
        };
        assert_eq!(
            volume.local_lineages,
            [expected_local_lineage(
                &attachment.identity,
                &host(data_directory.to_path_buf())
            )]
        );
    }

    fn checkpoint_path(root: &std::path::Path, cat_id: &Id) -> std::path::PathBuf {
        runtime_checkpoint_path(&root.join(CHECKPOINT_NAMESPACE), cat_id)
    }

    fn host(path: std::path::PathBuf) -> HostPath {
        HostPath::new(path.to_str().unwrap().to_owned()).unwrap()
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn fence(value: u64) -> FenceEpoch {
        FenceEpoch::new(value).unwrap()
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).unwrap()
    }

    fn sequence(value: u64) -> Sequence {
        Sequence::new(value).unwrap()
    }

    fn unix_ms(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }
}
