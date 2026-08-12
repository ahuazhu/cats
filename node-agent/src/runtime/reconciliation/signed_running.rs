//! One-step signed Running acquisition.
//!
//! This is deliberately only the `AcquireVolume` planner step. A current-
//! process accepted full inventory proves either that the fresh root is
//! physically empty or that one no-write local lineage is the exact durable
//! output of this checkpointed acquire. The exact request is fsynced before
//! A22 is called, and the grant is durably bound to the complete Desired before
//! the checkpoint advances to `ProvisionRootImage`. No process, frontend,
//! device, network or VMM port is reachable from this module.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, encode_runtime_checkpoint, AcquireOrigin, AgentSession,
    AppliedDesiredEvidence, AsciiText, AuthorizationConsumedReceipt, AuthorizationState,
    CheckpointEvidence, CleanupRelease, CleanupTarget, Condition, ContractVersion,
    DesiredRuntimeSpec, DiskKind, FenceEpoch, Generation, GuestTransportEvidence, HostPath, Id,
    LastVolumeTransition, LifecycleAdmission, LocalLineageState, LocalVolumeLineage,
    NormalAcquireRequest, ObservedDiskKind, ObservedRuntimeStatus, ObservedVolume,
    ProgressingReason, RandomId128, ReconcileStep, RemoteHead, RequireIdleCheckpoint,
    RuntimeCheckpoint, RuntimeLaunch, RuntimeTarget, RuntimeTransition, RuntimeVolumeTransition,
    RuntimeVolumeTransitionEvidenceRequest, RuntimeVolumeTransitionEvidenceSuccess,
    RuntimeVolumeTransitionRequest, SessionBinding, Sha256Digest, UnixMillis, VolumeAccess,
    VolumeAcquire, VolumeAcquireRequest, VolumeAdminState, VolumeAuthorityEvidence,
    VolumeAuthorization, VolumeDisposition, VolumeIntent, VolumeLeaseGrant, VolumeRecord,
    VolumeReleaseReplay, WarmSnapshotEvidence, WireU64,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, validate_authorized_serving_record,
    validate_volume_record, AttachmentLineageIdentity, AuthorityError, AuthorizedServingAcquire,
    AuthorizedServingAttachment, VolumeDataAuthority,
};
use cats_storage::{read_image_manifest_until, BlobStore, ImageManifestReadError};

use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
    RuntimeDesiredEffectStopReason, RuntimePreScanRecovery, RuntimePreScanRecoveryContext,
    RuntimePreScanRecoveryOutcome,
};

use super::authorized_blockd::StopReceiptSettlement;
use super::clean_slate_probes::{
    classify_local_publication_recovery, LocalPublicationRecoveryEvidence, CHECKPOINT_NAMESPACE,
};
#[cfg(target_os = "linux")]
use super::clean_slate_probes::{
    runtime_checkpoint_recovery_set, InstalledStaleBootVmmRecoveryPorts,
};
use super::serving_handoff::ServingHandoffStore;
#[cfg(test)]
use super::RootProvisionProcessRetirementPort;
use super::{
    authorized_blockd::authorized_blockd_data_directory, recover_normal_acquire_from_authority,
    recover_normal_release_from_authority, runtime_checkpoint_path, AuthorizedBlockdStore,
    ControlSignedNormalAcquireClient, FileCheckpointStore, NormalAcquireAcceptedContext,
    NormalAcquireAttempt, NormalAcquireAuthorityRecovery, NormalAcquireClientError,
    NormalReleaseAttempt, NormalReleaseAuthorityRecovery, SignedVolumeEvidencePort,
    StoredCheckpoint, TakeoverAcquireAttempt, VolumeEvidenceRecovery,
    VolumeEvidenceRecoveryDecision,
};

const MAX_LEASE_DURATION_MS: u64 = i64::MAX as u64;
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

    fn takeover(
        &self,
        _request: &RuntimeVolumeTransitionRequest,
        _volume: &VolumeIntent,
        _accepted: &NormalAcquireAcceptedContext,
        _deadline: Instant,
    ) -> Result<TakeoverAcquireAttempt, NormalAcquireClientError> {
        Ok(TakeoverAcquireAttempt::StopForLocalContract)
    }

    fn release(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        expected_head: &RemoteHead,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<NormalReleaseAttempt, NormalAcquireClientError>;

    fn commit_initialized(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<super::CommitInitializedAttempt, NormalAcquireClientError> {
        let _ = (request, volume, accepted, deadline);
        Err(NormalAcquireClientError::InvalidVolumeBinding)
    }
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

    fn takeover(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<TakeoverAcquireAttempt, NormalAcquireClientError> {
        ControlSignedNormalAcquireClient::takeover(self, request, volume, accepted, deadline)
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

    fn commit_initialized(
        &self,
        request: &RuntimeVolumeTransitionRequest,
        volume: &VolumeIntent,
        accepted: &NormalAcquireAcceptedContext,
        deadline: Instant,
    ) -> Result<super::CommitInitializedAttempt, NormalAcquireClientError> {
        ControlSignedNormalAcquireClient::commit_initialized(
            self, request, volume, accepted, deadline,
        )
    }
}

/// The first real signed Running effect. Its constructor rejects an invalid
/// lease budget before any accepted inventory can reach the effect lane.
pub(crate) struct SignedRunningAcquireEffect {
    volume_transition: Arc<dyn SignedNormalAcquirePort>,
    volume_evidence: Option<Arc<dyn SignedVolumeEvidencePort>>,
    authority: Arc<dyn VolumeDataAuthority>,
    blob: Arc<dyn BlobStore>,
    lease_duration_ms: u64,
    #[cfg(test)]
    after_prepare: Option<AfterPrepareHook>,
}

/// Exact restart-only recovery for the local publications surrounding A22.
/// It has no signed mutation client and cannot manufacture a new lease; the
/// current point-read authority must prove the persisted request already won.
pub(crate) struct SignedRunningPublicationRecovery {
    authority: Arc<dyn VolumeDataAuthority>,
    volume_evidence: Option<Arc<dyn SignedVolumeEvidencePort>>,
    #[cfg(target_os = "linux")]
    stale_boot_vmm: Option<InstalledStaleBootVmmRecoveryPorts>,
}

impl SignedRunningPublicationRecovery {
    #[cfg(any(test, not(target_os = "linux")))]
    pub(crate) fn new(authority: Arc<dyn VolumeDataAuthority>) -> Self {
        Self {
            authority,
            volume_evidence: None,
            #[cfg(target_os = "linux")]
            stale_boot_vmm: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_stale_boot_vmm_recovery(
        authority: Arc<dyn VolumeDataAuthority>,
        stale_boot_vmm: InstalledStaleBootVmmRecoveryPorts,
    ) -> Self {
        Self {
            authority,
            volume_evidence: None,
            stale_boot_vmm: Some(stale_boot_vmm),
        }
    }

    pub(crate) fn with_volume_evidence(
        mut self,
        evidence: Arc<dyn SignedVolumeEvidencePort>,
    ) -> Self {
        self.volume_evidence = Some(evidence);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_root_process_retirement(
        authority: Arc<dyn VolumeDataAuthority>,
        _root_process_retirement: Arc<dyn RootProvisionProcessRetirementPort>,
    ) -> Self {
        // Stable stop receipts deliberately do no pre-scan process I/O. Tests
        // retain this seam to assert the supplied port receives zero calls.
        Self {
            authority,
            volume_evidence: None,
            #[cfg(target_os = "linux")]
            stale_boot_vmm: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn recover_stale_boot_vmm(
        &self,
        context: &RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
        use super::vmm_process::{StaleBootVmmProcessGlobalInspection, VmmProcessExpectation};
        use super::vmm_socket_namespace::StaleVmmSocketReceiptScan;

        let Some(ports) = &self.stale_boot_vmm else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let Some(checkpoints) = runtime_checkpoint_recovery_set(context, &ports.socket_root)?
        else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let expected_checkpoints = checkpoints
            .iter_checkpoints()
            .filter(|checkpoint| matches!(checkpoint.runtime_launch, RuntimeLaunch::Present(_)))
            .collect::<Vec<_>>();
        let physical = context.inventory_context();
        let candidate = ports.receipts.retain_one_stale_boot_receipt(
            &ports.socket_root,
            &expected_checkpoints,
            &physical,
        )?;
        let StaleVmmSocketReceiptScan::Candidate(candidate) = candidate else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let checkpoint = checkpoints
            .checkpoint(candidate.cat_id())
            .context("stale-boot VMM receipt lacks its admitted checkpoint")?;
        let checkpoint_path = HostPath::new(
            runtime_checkpoint_path(
                &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
                &checkpoint.cat_id,
            )
            .to_string_lossy()
            .into_owned(),
        )
        .context("stale-boot recovery checkpoint path is not canonical")?;
        let expected = VmmProcessExpectation::from_checkpoint(checkpoint.clone())?
            .with_checkpoint_path(checkpoint_path)?;
        anyhow::ensure!(
            candidate.receipt().runtime_incarnation() == expected.runtime_incarnation(),
            "stale-boot VMM receipt changed incarnation after classification"
        );
        let cat_id = checkpoint.cat_id.clone();
        let recovered = ports.launch_root.recover_stale_boot_receipt(
            &ports.socket_root,
            &ports.receipts,
            checkpoint,
            *candidate,
            &physical,
            |_| match ports
                .global
                .inspect_stale_boot_absence_after_node_global_sweep(
                    &expected,
                    &checkpoints,
                    context,
                )? {
                StaleBootVmmProcessGlobalInspection::Absent(absence) => Ok(*absence),
                StaleBootVmmProcessGlobalInspection::Conflict(problem) => {
                    anyhow::bail!(
                        "stale-boot VMM recovery found conflicting global identity: {problem:?}"
                    )
                }
                StaleBootVmmProcessGlobalInspection::Unavailable => {
                    anyhow::bail!("stale-boot VMM recovery global sweep is unavailable")
                }
            },
        )?;
        context.check_active()?;
        Ok(if recovered {
            RuntimePreScanRecoveryOutcome::Recovered { cat_id }
        } else {
            RuntimePreScanRecoveryOutcome::NoChange
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn recover_stale_boot_vmm(
        &self,
        _context: &RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
        Ok(RuntimePreScanRecoveryOutcome::NoChange)
    }

    fn recover_authorized_blockd(
        &self,
        context: &RuntimePreScanRecoveryContext,
        cat_id: &Id,
        target_already_published: bool,
    ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
        let desired = context
            .coordinates()
            .desired
            .desired_specs
            .iter()
            .find(|desired| &desired.cat_id == cat_id)
            .context("publication recovery Cat is absent from current Desired")?;
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store =
            FileCheckpointStore::open_preserving_checkpoint_temp(&checkpoint_directory, cat_id)
                .context("open publication recovery checkpoint store")?;
        let Some(stored) = store
            .load()
            .context("load publication recovery checkpoint")?
        else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let Some(volume) = recovery_volume(
            desired,
            &context.coordinates().session,
            stored.checkpoint(),
            context.state_directory().path(),
        ) else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let Some(persisted) = persisted_acquire_request(
            stored.checkpoint(),
            desired,
            volume,
            context.state_directory().path(),
        )
        .cloned() else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let attachment = match &persisted {
            VolumeAcquireRequest::Normal { .. } => {
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
                match recover_normal_acquire_from_authority(&request, volume, &record) {
                    Ok(NormalAcquireAuthorityRecovery::Granted(attachment))
                        if normal_publication_closes_checkpoint_predecessor(
                            stored.checkpoint(),
                            desired,
                            volume,
                            &attachment,
                        ) =>
                    {
                        attachment
                    }
                    Ok(
                        NormalAcquireAuthorityRecovery::Granted(_)
                        | NormalAcquireAuthorityRecovery::RetryExact
                        | NormalAcquireAuthorityRecovery::Blocked,
                    )
                    | Err(_) => return Ok(RuntimePreScanRecoveryOutcome::NoChange),
                }
            }
            VolumeAcquireRequest::Takeover { authorization_id } => {
                let Some(evidence_port) = &self.volume_evidence else {
                    return Ok(RuntimePreScanRecoveryOutcome::NoChange);
                };
                let request = RuntimeVolumeTransitionEvidenceRequest {
                    version: ContractVersion::V1,
                    session: context.coordinates().session.clone(),
                    authorization_id: authorization_id.clone(),
                };
                context.check_active()?;
                let recovery = evidence_port
                    .recover_authorization(&request, context.deadline())
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "read signed takeover evidence during publication recovery: {error}"
                        )
                    })?;
                context.check_active()?;
                let (evidence, receipt) = match recovery {
                    VolumeEvidenceRecovery::Validated { evidence, decision } => match *decision {
                        VolumeEvidenceRecoveryDecision::AdoptTakeover(receipt) => {
                            (evidence, receipt)
                        }
                        _ => return Ok(RuntimePreScanRecoveryOutcome::NoChange),
                    },
                    _ => return Ok(RuntimePreScanRecoveryOutcome::NoChange),
                };
                if evidence.version != ContractVersion::V1
                    || evidence.session != request.session
                    || evidence.authorization_id != *authorization_id
                {
                    return Ok(RuntimePreScanRecoveryOutcome::NoChange);
                }
                let Some(prior) = stored
                    .checkpoint()
                    .volumes
                    .iter()
                    .find(|observed| observed.volume_id == volume.volume_id)
                else {
                    return Ok(RuntimePreScanRecoveryOutcome::NoChange);
                };
                let Some(attachment) = takeover_attachment_from_signed_evidence(
                    desired, volume, prior, &evidence, &receipt, None,
                ) else {
                    return Ok(RuntimePreScanRecoveryOutcome::NoChange);
                };
                context.check_active()?;
                let current = self.authority.load_volume(&volume.volume_id);
                context.check_active()?;
                if !signed_takeover_successor_matches_point_read(&evidence, current)? {
                    return Ok(RuntimePreScanRecoveryOutcome::NoChange);
                }
                let retained_publication = if target_already_published {
                    let retained = AuthorizedBlockdStore::new(context.state_directory().clone())
                        .reopen_adopted(desired, volume, &attachment.identity)
                        .context("reopen exact takeover publication before signed recovery")?;
                    if retained.checkpoint().desired != *desired
                        || retained.checkpoint().volume != *volume
                        || retained.checkpoint().attachment != attachment
                    {
                        return Ok(RuntimePreScanRecoveryOutcome::NoChange);
                    }
                    Some(retained)
                } else {
                    None
                };
                if takeover_successor_requires_immediate_replan(
                    &evidence,
                    authorization_id,
                    &receipt,
                ) {
                    // A later Takeover/disposable-delete needs the signed
                    // direct authorization to close it; a completed delete
                    // has no VolumeRecord at all. Neither proof can be
                    // reconstructed from the immutable primary R0 artifact
                    // on the next scan. Consume the still-fresh signed proof
                    // only to invalidate this spent Desired. Never publish or
                    // reopen a local writer for these closed successors.
                    let checkpoint_guard = store
                        .assert_current(&stored)
                        .context("retain takeover checkpoint before pre-scan replan")?;
                    store
                        .revalidate_current(&stored, &checkpoint_guard)
                        .context("revalidate takeover checkpoint before pre-scan replan")?;
                    return Ok(RuntimePreScanRecoveryOutcome::ReplanDesired {
                        cat_id: cat_id.clone(),
                    });
                }
                if retained_publication.is_some() {
                    // Exact primary R0 is already durable. Its checkpoint CAS
                    // response was the only missing publication, so leave the
                    // immutable bytes untouched and let the normal full scan
                    // plus Desired effect adopt them.
                    return Ok(RuntimePreScanRecoveryOutcome::NoChange);
                }
                Box::new(attachment)
            }
        };
        context.check_active()?;
        let current_checkpoint = store
            .assert_current(&stored)
            .context("revalidate publication recovery checkpoint before local mutation")?;
        AuthorizedBlockdStore::new(context.state_directory().clone())
            .prepare(desired, volume, &attachment)
            .context("recover exact authorized blockd publication")?;
        context.check_active()?;
        store
            .revalidate_current(&stored, &current_checkpoint)
            .context("revalidate publication recovery checkpoint after local durability")?;
        Ok(RuntimePreScanRecoveryOutcome::Recovered {
            cat_id: cat_id.clone(),
        })
    }

    fn recover_root_provision_stop_receipt(
        &self,
        context: &RuntimePreScanRecoveryContext,
        cat_id: &Id,
    ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store =
            FileCheckpointStore::open_preserving_checkpoint_temp(&checkpoint_directory, cat_id)
                .context("open root-provision stop recovery checkpoint store")?;
        let Some(stored) = store
            .load()
            .context("load root-provision stop recovery checkpoint")?
        else {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        };
        let retained = match AuthorizedBlockdStore::new(context.state_directory().clone())
            .retain_exact_runtime_checkpoint(stored.checkpoint())
        {
            Ok(retained) => retained,
            Err(_) => return Ok(RuntimePreScanRecoveryOutcome::NoChange),
        };
        let receipt = match retained
            .settle_stop_receipt()
            .context("settle root-provision stop receipt publication")?
        {
            StopReceiptSettlement::Absent => return Ok(RuntimePreScanRecoveryOutcome::NoChange),
            StopReceiptSettlement::Recovered(_) => {
                return Ok(RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: cat_id.clone(),
                })
            }
            StopReceiptSettlement::Stable(receipt) => receipt,
        };
        if receipt.checkpoint_content_digest() != stored.content_digest()
            || receipt
                .binds_retained_values(stored.checkpoint(), retained.checkpoint())
                .is_err()
        {
            return Ok(RuntimePreScanRecoveryOutcome::NoChange);
        }
        // A stable receipt is effect work, not pre-scan publication recovery.
        // The full scanner admits its typed old socket into the complete
        // RootControl + ServingBlockd set; only the later accepted-full effect
        // may prove global absence and unlink that exact retained inode.
        Ok(RuntimePreScanRecoveryOutcome::NoChange)
    }
}

impl RuntimePreScanRecovery for SignedRunningPublicationRecovery {
    fn recover_one(
        &self,
        context: RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<RuntimePreScanRecoveryOutcome> {
        context.check_active()?;
        let evidence = classify_local_publication_recovery(&context)?;
        if matches!(evidence, LocalPublicationRecoveryEvidence::None) {
            return self.recover_stale_boot_vmm(&context);
        }
        let outcome = match evidence {
            LocalPublicationRecoveryEvidence::None => unreachable!(),
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
            LocalPublicationRecoveryEvidence::DefiniteReleaseRejectionTarget { cat_id } => {
                let checkpoint_directory =
                    context.state_directory().path().join(CHECKPOINT_NAMESPACE);
                let store = FileCheckpointStore::open_preserving_checkpoint_temp(
                    &checkpoint_directory,
                    &cat_id,
                )
                .context("open definite release rejection confirmation store")?;
                let Some(stored) = store
                    .load()
                    .context("load checkpoint for definite release rejection confirmation")?
                else {
                    return self.recover_stale_boot_vmm(&context);
                };
                if !store
                    .confirm_durable_definite_release_rejection(&stored)
                    .context("confirm definite release rejection durability")?
                {
                    return self.recover_stale_boot_vmm(&context);
                }
                context.check_active()?;
                // Directory durability changed, but the visible inventory did
                // not. Continue into the full scan instead of creating an
                // endless pre-scan recovery loop for this stable marker.
                Ok(RuntimePreScanRecoveryOutcome::NoChange)
            }
            LocalPublicationRecoveryEvidence::DefiniteReleaseRejectionTemp { cat_id } => {
                let checkpoint_directory =
                    context.state_directory().path().join(CHECKPOINT_NAMESPACE);
                let store = FileCheckpointStore::open_preserving_checkpoint_temp(
                    &checkpoint_directory,
                    &cat_id,
                )
                .context("open definite release rejection recovery store")?;
                let Some(stored) = store
                    .load()
                    .context("load checkpoint for definite release rejection recovery")?
                else {
                    return self.recover_stale_boot_vmm(&context);
                };
                if !store
                    .recover_definite_release_rejection_publication(&stored)
                    .context("recover definite release rejection publication")?
                {
                    return self.recover_stale_boot_vmm(&context);
                }
                context.check_active()?;
                Ok(RuntimePreScanRecoveryOutcome::Recovered { cat_id })
            }
            LocalPublicationRecoveryEvidence::AuthorizedBlockd { cat_id } => {
                self.recover_authorized_blockd(&context, &cat_id, false)
            }
            LocalPublicationRecoveryEvidence::AuthorizedBlockdTakeoverPublication { cat_id } => {
                self.recover_authorized_blockd(&context, &cat_id, true)
            }
            LocalPublicationRecoveryEvidence::RootProvisionStopReceipt { cat_id }
            | LocalPublicationRecoveryEvidence::RootProvisionStopReceiptPublication { cat_id } => {
                self.recover_root_provision_stop_receipt(&context, &cat_id)
            }
            LocalPublicationRecoveryEvidence::ServingHandoffTemp {
                cat_id,
                kind,
                authorized,
            } => {
                let desired = context
                    .coordinates()
                    .desired
                    .desired_specs
                    .iter()
                    .find(|desired| desired.cat_id == cat_id)
                    .context("handoff temp recovery Cat is absent from current Desired")?;
                let volume = desired
                    .volumes
                    .iter()
                    .find(|volume| *volume == &authorized.volume)
                    .context("handoff temp recovery volume is absent from current Desired")?;
                let checkpoint_directory =
                    context.state_directory().path().join(CHECKPOINT_NAMESPACE);
                let store = FileCheckpointStore::open_preserving_checkpoint_temp(
                    &checkpoint_directory,
                    &cat_id,
                )
                .context("open handoff temp recovery checkpoint store")?;
                let Some(stored) = store
                    .load()
                    .context("load handoff temp recovery checkpoint")?
                else {
                    return self.recover_stale_boot_vmm(&context);
                };
                // The attachment flock is acquired before the checkpoint
                // writer guard, matching every handoff publisher's lock order.
                let prepared = AuthorizedBlockdStore::new(context.state_directory().clone())
                    .reopen_adopted(desired, volume, &authorized.attachment.identity)
                    .context("reopen scanned handoff attachment")?;
                anyhow::ensure!(
                    prepared.checkpoint() == authorized.as_ref(),
                    "handoff attachment changed after the pre-scan classification"
                );
                let _current = store
                    .assert_current(&stored)
                    .context("retain current handoff recovery checkpoint")?;
                let recovered = ServingHandoffStore::new(context.state_directory().clone())
                    .discard_recoverable_temp(&prepared, &stored, kind, &context)
                    .context("discard exact unpublished serving handoff temp")?;
                context.check_active()?;
                Ok(if recovered {
                    RuntimePreScanRecoveryOutcome::Recovered { cat_id }
                } else {
                    RuntimePreScanRecoveryOutcome::NoChange
                })
            }
        }?;
        if matches!(outcome, RuntimePreScanRecoveryOutcome::NoChange) {
            self.recover_stale_boot_vmm(&context)
        } else {
            Ok(outcome)
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
            volume_evidence: None,
            authority,
            blob,
            lease_duration_ms,
            #[cfg(test)]
            after_prepare: None,
        })
    }

    pub(crate) fn with_volume_evidence(
        mut self,
        evidence: Arc<dyn SignedVolumeEvidencePort>,
    ) -> Self {
        self.volume_evidence = Some(evidence);
        self
    }

    pub(crate) fn volume_transition_port(&self) -> Arc<dyn SignedNormalAcquirePort> {
        Arc::clone(&self.volume_transition)
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
        match store.load_definite_release_rejection(predecessor) {
            Ok(Some(_)) | Err(_) => return Ok(stop_local()),
            Ok(None) => {}
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
            NormalReleaseAttempt::DefiniteCleanupConflict(problem) => {
                if store
                    .persist_definite_release_rejection(predecessor, &request, problem)
                    .is_err()
                {
                    return Ok(stop_local());
                }
                Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            NormalReleaseAttempt::StopForLocalContract => Ok(stop_local()),
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
            Some(stored) => match persisted_acquire_request(
                stored.checkpoint(),
                desired,
                volume,
                context.state_directory().path(),
            ) {
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

        if !normal_publication_closes_checkpoint_predecessor(
            predecessor.checkpoint(),
            desired,
            volume,
            &attachment,
        ) {
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }

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

    /// Clean-slate multi-volume acquisition.  `AcquireVolume` names only the
    /// one A22 mutation currently checkpointed; `checkpoint.volumes` retains
    /// every earlier exact grant/lineage.  After the final grant, one CAS
    /// advances the unchanged complete set to Root provisioning.
    fn apply_multi_acquire(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let accepted = context.accepted_full()?;
        let runtime = match validate_multi_acquire_admission(
            desired,
            accepted,
            context.state_directory().path(),
        ) {
            MultiAcquireAdmission::Exact(runtime) => runtime,
            MultiAcquireAdmission::RefreshInventory => {
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            MultiAcquireAdmission::ReplanDesired => {
                return Ok(RuntimeDesiredEffectOutcome::ReplanDesired)
            }
            MultiAcquireAdmission::StopLocal => return Ok(stop_local()),
        };
        let volume = match &runtime.step {
            ReconcileStep::InspectInventory { .. } => &desired.volumes[0],
            ReconcileStep::AcquireVolume { request } => desired
                .volumes
                .iter()
                .find(|volume| request_matches_volume(request, desired, volume))
                .context("multi-volume acquire checkpoint names no Desired volume")?,
            ReconcileStep::ProvisionRootImage { .. } => {
                return Ok(RuntimeDesiredEffectOutcome::Applied)
            }
            _ => return Ok(stop_local()),
        };
        let root = &desired.volumes[0];

        let request =
            desired_acquire_request(desired, volume, accepted.session(), self.lease_duration_ms);
        let RuntimeVolumeTransition::Acquire {
            request: request_payload,
        } = &request.transition
        else {
            unreachable!("Desired acquire builder returns Acquire")
        };
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id)
            .context("open multi-volume acquire checkpoint store")?;
        let predecessor = match store
            .load()
            .context("load multi-volume acquire checkpoint")?
        {
            None => {
                if !matches!(runtime.checkpoint, CheckpointEvidence::Missing { .. }) {
                    return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
                }
                let checkpoint = closed_checkpoint(
                    desired,
                    ReconcileStep::AcquireVolume {
                        request: request_payload.clone(),
                    },
                    runtime.volumes.clone(),
                    accepted.attestation().accepted_at_unix_ms,
                );
                store
                    .create(&checkpoint)
                    .context("persist first multi-volume acquire request")?;
                // Checkpoint publication is this accepted-full round's sole
                // durable effect. A22 is unreachable until a new full scan
                // proves these exact bytes current.
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
            }
            Some(stored) => {
                let CheckpointEvidence::Valid {
                    checkpoint_path,
                    content_digest,
                    ..
                } = &runtime.checkpoint
                else {
                    return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
                };
                if !path_matches(checkpoint_path, store.path())
                    || stored.content_digest() != content_digest
                    || stored.checkpoint().step != runtime.step
                    || stored.checkpoint().cat_id != desired.cat_id
                    || stored.checkpoint().node_id != desired.placement.node_id
                    || stored.checkpoint().placement_epoch != desired.placement.placement_epoch
                    || stored.checkpoint().desired_revision != desired.desired_revision
                    || stored.checkpoint().spec_digest != desired.spec_digest
                    || !matches!(
                        &stored.checkpoint().step,
                        ReconcileStep::AcquireVolume { request: persisted }
                            if persisted == request_payload
                    )
                {
                    return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
                }
                stored
            }
        };

        if matches!(volume.acquire, VolumeAcquire::Normal { .. })
            && !acquire_checkpoint_predecessor_matches_accepted_or_published(
                predecessor.checkpoint(),
                runtime,
                volume,
            )
        {
            // Before either A22 variant, the fresh point-read authority and
            // durable unprepared predecessor must be byte-exact. An already
            // published R0 is the only exception: the full scanner has
            // independently value-bound that artifact and the request is an
            // idempotent replay. No malformed R0-absent predecessor may reach
            // a remote mutation.
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }

        let accepted_context = NormalAcquireAcceptedContext {
            session: accepted.session().clone(),
            inventory_attestation: accepted.attestation().clone(),
        };
        context.check_active()?;
        let attachment = match &volume.acquire {
            VolumeAcquire::Normal { .. } => {
                let attempt = self
                    .volume_transition
                    .acquire(&request, volume, &accepted_context, context.deadline())
                    .map_err(|error| {
                        anyhow::anyhow!("submit signed multi-volume acquire: {error}")
                    })?;
                match attempt {
                    NormalAcquireAttempt::Granted(attachment) => attachment,
                    NormalAcquireAttempt::RetryExact => {
                        return Ok(RuntimeDesiredEffectOutcome::RetryExact)
                    }
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
                            Err(AuthorityError::BackendUnknown) => {
                                return Ok(RuntimeDesiredEffectOutcome::RetryExact)
                            }
                            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
                        };
                        match recover_normal_acquire_from_authority(&request, volume, &record) {
                            Ok(NormalAcquireAuthorityRecovery::Granted(attachment)) => attachment,
                            Ok(NormalAcquireAuthorityRecovery::RetryExact) => {
                                return Ok(RuntimeDesiredEffectOutcome::RetryExact)
                            }
                            Ok(NormalAcquireAuthorityRecovery::Blocked) | Err(_) => {
                                return Ok(stop_local())
                            }
                        }
                    }
                }
            }
            VolumeAcquire::Takeover { authorization_id } => {
                let accepted_current = runtime
                    .volumes
                    .iter()
                    .find(|observed| observed.volume_id == volume.volume_id)
                    .context("accepted full set lacks the takeover current Volume")?;
                let prior = predecessor
                    .checkpoint()
                    .volumes
                    .iter()
                    .find(|observed| observed.volume_id == volume.volume_id)
                    .context("takeover checkpoint lacks its durable predecessor Volume")?;
                // Only the byte-exact durable predecessor may authorize a new
                // remote mutation. If A22 already won and its response/local
                // publication was lost, the fresh accepted authority differs
                // from `prior`; that branch must consume signed evidence and
                // publish R0 with zero further A22 calls.
                let may_submit_takeover =
                    accepted_current == prior && accepted_current.local_lineages.is_empty();
                let evidence_port = self
                    .volume_evidence
                    .as_ref()
                    .context("takeover acquire lacks signed evidence port")?;
                let evidence_request = RuntimeVolumeTransitionEvidenceRequest {
                    version: ContractVersion::V1,
                    session: session_binding(accepted.session()),
                    authorization_id: authorization_id.clone(),
                };
                let grant = if may_submit_takeover {
                    match self
                        .volume_transition
                        .takeover(&request, volume, &accepted_context, context.deadline())
                        .map_err(|error| {
                            anyhow::anyhow!("submit signed takeover acquire: {error}")
                        })? {
                        TakeoverAcquireAttempt::LeaseGranted(grant) => Some(grant),
                        TakeoverAcquireAttempt::RetryExact
                        | TakeoverAcquireAttempt::Ambiguous => None,
                        TakeoverAcquireAttempt::RefreshInventory => {
                            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
                        }
                        TakeoverAcquireAttempt::ReplanDesired => {
                            return Ok(RuntimeDesiredEffectOutcome::ReplanDesired)
                        }
                        TakeoverAcquireAttempt::SessionReplacementRequired => {
                            return Ok(RuntimeDesiredEffectOutcome::SessionReplacementRequired)
                        }
                        TakeoverAcquireAttempt::IdentityRepairRequired => {
                            return Ok(RuntimeDesiredEffectOutcome::IdentityRepairRequired)
                        }
                        TakeoverAcquireAttempt::AuthorizationRejected(
                            cats_api::runtime_reconciliation::RuntimeVolumeAuthorizationRejection::InvalidAuthorization,
                        ) => return Ok(RuntimeDesiredEffectOutcome::ReplanDesired),
                        TakeoverAcquireAttempt::AuthorizationRejected(
                            cats_api::runtime_reconciliation::RuntimeVolumeAuthorizationRejection::InvalidLeaseDuration,
                        )
                        | TakeoverAcquireAttempt::StopForLocalContract => {
                            return Ok(stop_local())
                        }
                        TakeoverAcquireAttempt::AuthorizationRejected(_) => {
                            return Ok(RuntimeDesiredEffectOutcome::ReplanDesired)
                        }
                        TakeoverAcquireAttempt::StopForDeploymentMismatch => {
                            return Ok(RuntimeDesiredEffectOutcome::Stop(
                                RuntimeDesiredEffectStopReason::DeploymentMismatch,
                            ))
                        }
                    }
                } else {
                    None
                };
                context.check_active()?;
                let recovery = evidence_port
                    .recover_authorization(&evidence_request, context.deadline())
                    .map_err(|error| anyhow::anyhow!("read signed takeover evidence: {error}"))?;
                let (evidence, receipt) = match recovery {
                    VolumeEvidenceRecovery::Validated { evidence, decision } => match *decision {
                        VolumeEvidenceRecoveryDecision::AdoptTakeover(receipt) => {
                            (evidence, receipt)
                        }
                        VolumeEvidenceRecoveryDecision::RetryOriginalAuthorization {
                            authorization_id: retry,
                        } if retry == *authorization_id => {
                            return Ok(if may_submit_takeover {
                                RuntimeDesiredEffectOutcome::RetryExact
                            } else {
                                RuntimeDesiredEffectOutcome::RefreshInventory
                            })
                        }
                        VolumeEvidenceRecoveryDecision::Blocked => {
                            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
                        }
                        _ => return Ok(stop_local()),
                    },
                    VolumeEvidenceRecovery::SessionReplacementRequired => {
                        return Ok(RuntimeDesiredEffectOutcome::SessionReplacementRequired)
                    }
                    VolumeEvidenceRecovery::IdentityRepairRequired => {
                        return Ok(RuntimeDesiredEffectOutcome::IdentityRepairRequired)
                    }
                    VolumeEvidenceRecovery::StopForDeploymentMismatch => {
                        return Ok(RuntimeDesiredEffectOutcome::Stop(
                            RuntimeDesiredEffectStopReason::DeploymentMismatch,
                        ))
                    }
                    VolumeEvidenceRecovery::StopForLocalContract => return Ok(stop_local()),
                    VolumeEvidenceRecovery::AuthorizationEvidenceUnavailable
                    | VolumeEvidenceRecovery::RetrySameRequest
                    | VolumeEvidenceRecovery::Ambiguous => {
                        return Ok(RuntimeDesiredEffectOutcome::RetryExact)
                    }
                };
                context.check_active()?;
                let VolumeAuthorization::Takeover(authorization) =
                    &evidence.authorization.authorization
                else {
                    return Ok(stop_local());
                };
                if !takeover_predecessor_is_exact(prior, volume, authorization, &receipt)
                    || (!may_submit_takeover
                        && !signed_takeover_current_matches_observed(&evidence, accepted_current))
                {
                    return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
                }
                context.check_active()?;
                let current = self.authority.load_volume(&volume.volume_id);
                context.check_active()?;
                match signed_takeover_successor_matches_point_read(&evidence, current) {
                    Ok(true) => {}
                    Ok(false) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
                    Err(_) => return Ok(RuntimeDesiredEffectOutcome::RetryExact),
                }
                Box::new(
                    takeover_attachment_from_signed_evidence(
                        desired,
                        volume,
                        prior,
                        &evidence,
                        &receipt,
                        grant.as_ref(),
                    )
                    .context("signed takeover evidence did not close the initial attachment")?,
                )
            }
        };
        if matches!(volume.acquire, VolumeAcquire::Normal { .. })
            && !normal_publication_closes_checkpoint_predecessor(
                predecessor.checkpoint(),
                desired,
                volume,
                &attachment,
            )
        {
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }
        let prepared = AuthorizedBlockdStore::new(context.state_directory().clone())
            .prepare(desired, volume, &attachment)
            .context("persist exact multi-volume authorized blockd grant")?;
        context.check_active()?;

        let data_directory = host_path(
            prepared.data_directory(),
            "multi-volume authorized blockd data directory",
        )?;
        let mut successor = predecessor.checkpoint().clone();
        let observed = successor
            .volumes
            .iter_mut()
            .find(|observed| observed.volume_id == volume.volume_id)
            .context("multi-volume checkpoint omitted its acquired Volume")?;
        *observed = prepared_owned_observed_volume(volume, &attachment, data_directory.clone());
        successor.updated_at_unix_ms = next_multi_checkpoint_time(&predecessor)?;

        let next = desired.volumes.iter().find(|candidate| {
            successor
                .volumes
                .iter()
                .find(|observed| observed.volume_id == candidate.volume_id)
                .is_none_or(|observed| observed.local_lineages.is_empty())
        });
        if let Some(next) = next {
            let next_request =
                desired_acquire_request(desired, next, accepted.session(), self.lease_duration_ms);
            let RuntimeVolumeTransition::Acquire {
                request: next_payload,
            } = next_request.transition
            else {
                unreachable!("Desired acquire builder returns Acquire")
            };
            successor.step = ReconcileStep::AcquireVolume {
                request: next_payload,
            };
        } else {
            let root_observed = successor
                .volumes
                .iter()
                .find(|observed| observed.volume_id == root.volume_id)
                .context("multi-volume checkpoint omitted Root")?;
            let [root_lineage] = root_observed.local_lineages.as_slice() else {
                return Ok(stop_local());
            };
            let root_identity = AttachmentLineageIdentity {
                volume_id: root.volume_id.clone(),
                attachment_id: root_lineage.attachment_id.clone(),
                attachment_epoch: root_lineage.attachment_epoch,
                acquire_origin: root_lineage.acquire_origin.clone(),
                node_id: root_lineage.node_id.clone(),
                placement_epoch: root_lineage.placement_epoch,
            };
            // The final acquired volume may itself be Root (single-volume
            // existing/takeover). Its just-published artifact already holds
            // the nonblocking attachment flock, so reopening the same
            // directory would self-deadlock/fail EWOULDBLOCK. Reuse that
            // retained descriptor; only reopen Root when another volume was
            // the final mutation.
            let reopened_root;
            let root_prepared =
                if prepared.checkpoint().attachment.identity.volume_id == root.volume_id {
                    &prepared
                } else {
                    reopened_root = AuthorizedBlockdStore::new(context.state_directory().clone())
                        .reopen_adopted(desired, root, &root_identity)
                        .context("reopen exact Root authorization after all volume acquires")?;
                    &reopened_root
                };
            let root_attachment = &root_prepared.checkpoint().attachment;
            if root_attachment.head.generation.get() > 0 {
                // Existing Root never depends on the image BlobStore and is
                // prepared by the direct full-vector effect after the next
                // accepted scan. Keep the last exact Acquire checkpoint as
                // the durable bridge; its artifact publication is already
                // this round's effect.
                encode_runtime_checkpoint(&successor)
                    .context("constructed existing-Root acquire bridge is not canonical V1")?;
                store
                    .replace(&predecessor, &successor)
                    .context("publish complete existing-Root authorization set")?;
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
            }
            let (expected_blank_head, expected_provisioned_head) = match expected_provision_heads(
                self.blob.as_ref(),
                desired,
                root,
                context.deadline(),
            ) {
                ProvisionHeadRead::Ready { blank, target } => (blank, target),
                ProvisionHeadRead::Retry => return Ok(RuntimeDesiredEffectOutcome::RetryExact),
                ProvisionHeadRead::Invalid => return Ok(stop_local()),
            };
            anyhow::ensure!(
                root_attachment.head == expected_blank_head,
                "blank Root authority disagrees with the provision predecessor"
            );
            let root_data_directory = host_path(
                root_prepared.data_directory(),
                "multi-volume Root blockd data directory",
            )?;
            let process_identity_token = random_id();
            let provision_transition_id = random_id();
            let control_socket_path =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .root_paths(&provision_transition_id)
                    .context("derive managed multi-volume Root control socket")?
                    .control_socket()
                    .clone();
            let scope_id = Id::new(format!(
                "cats-root-{}.service",
                process_identity_token.as_str()
            ))
            .context("Root provision process token does not form a service ID")?;
            successor.step = ReconcileStep::ProvisionRootImage {
                provision_transition_id,
                volume_id: root.volume_id.clone(),
                attachment_id: root_attachment.identity.attachment_id.clone(),
                attachment_epoch: root_attachment.identity.attachment_epoch,
                scope_id,
                control_socket_path,
                data_directory: root_data_directory,
                process_identity_token,
                size_bytes: root.size_bytes,
                boot_image_digest: desired.runtime.boot_image_digest.clone(),
                expected_blank_head,
                expected_provisioned_head,
            };
        }
        encode_runtime_checkpoint(&successor)
            .context("constructed multi-volume successor is not canonical V1")?;
        store
            .replace(&predecessor, &successor)
            .context("advance one checkpointed multi-volume acquire")?;
        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
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
        let provision_transition_id = random_id();
        let control_socket_path =
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                .root_paths(&provision_transition_id)
                .context("derive managed Root provision control socket")?
                .control_socket()
                .clone();
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
            runtime_launch: RuntimeLaunch::Absent,
            stable_state: None,
            step: ReconcileStep::ProvisionRootImage {
                provision_transition_id,
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
        // The production composition always injects the takeover evidence
        // port, including for a one-volume Normal Desired.  Preserve the
        // mature single-volume stale/replan state machine before dispatching
        // the clean-slate current multi-volume producer; capability presence
        // must not reinterpret an already-durable Acquire/Provision/Cleanup
        // checkpoint.
        let legacy_replan_state = desired.volumes.len() == 1
            && desired
                .volumes
                .first()
                .is_some_and(|volume| matches!(volume.acquire, VolumeAcquire::Normal { .. }))
            && context.accepted_full().ok().is_some_and(|accepted| {
                let mut runtimes = accepted
                    .observation()
                    .runtimes
                    .iter()
                    .filter(|runtime| runtime.cat_id == desired.cat_id);
                runtimes.next().is_some_and(|runtime| {
                    runtimes.next().is_none()
                        && (matches!(
                            runtime.step,
                            ReconcileStep::CleanupRelease { .. } | ReconcileStep::Quarantined
                        ) || (matches!(runtime.step, ReconcileStep::AcquireVolume { .. })
                            && runtime.volumes.iter().any(|volume| {
                                matches!(volume.authority, VolumeAuthorityEvidence::Owned { .. })
                            }))
                            || matches!(
                                &runtime.checkpoint,
                                CheckpointEvidence::Valid {
                                    placement_epoch,
                                    desired_revision,
                                    spec_digest,
                                    ..
                                } if *placement_epoch != desired.placement.placement_epoch
                                    || *desired_revision != desired.desired_revision
                                    || spec_digest != &desired.spec_digest
                            ))
                })
            });
        if legacy_replan_state {
            if let Some(outcome) = self.apply_checkpoint_replan(&context, desired)? {
                return Ok(outcome);
            }
        }
        if self.volume_evidence.is_some() || desired.volumes.len() > 1 {
            return self.apply_multi_acquire(&context, desired);
        }
        if let Some(outcome) = self.apply_checkpoint_replan(&context, desired)? {
            return Ok(outcome);
        }
        self.apply_acquire(&context, desired)
    }
}

enum MultiAcquireAdmission<'a> {
    Exact(&'a ObservedRuntimeStatus),
    RefreshInventory,
    ReplanDesired,
    StopLocal,
}

fn validate_multi_acquire_admission<'a>(
    desired: &'a DesiredRuntimeSpec,
    accepted: &'a crate::runtime_spine::RuntimeDesiredEffectAdmission,
    state_directory: &std::path::Path,
) -> MultiAcquireAdmission<'a> {
    if encode_desired_runtime_spec(desired).is_err()
        || desired.version != ContractVersion::V1
        || desired.target != RuntimeTarget::Running
        || !matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        || !(1..=64).contains(&desired.volumes.len())
        || desired.placement.node_id != accepted.session().node_id
    {
        return MultiAcquireAdmission::StopLocal;
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
        return MultiAcquireAdmission::StopLocal;
    }
    let mut matching = observation
        .runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == desired.cat_id);
    let Some(runtime) = matching.next() else {
        return MultiAcquireAdmission::RefreshInventory;
    };
    if matching.next().is_some() {
        return MultiAcquireAdmission::StopLocal;
    }
    let expected_applied = AppliedDesiredEvidence {
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        target: desired.target,
    };
    if runtime.applied_desired.as_ref() != Some(&expected_applied)
        || runtime.runtime_incarnation.is_some()
        || runtime.stable_state.is_some()
        || !runtime.processes.is_empty()
        || runtime.volumes.len() != desired.volumes.len()
        || !runtime.mounts.is_empty()
        || !runtime.networks.is_empty()
        || !matches!(runtime.guest_transport, GuestTransportEvidence::Unavailable)
        || !matches!(runtime.warm_snapshot, WarmSnapshotEvidence::Absent)
        || runtime.lifecycle_admission != LifecycleAdmission::Closed
        || !runtime.routes.is_empty()
        || runtime.platform_guards != 0
    {
        return MultiAcquireAdmission::StopLocal;
    }
    let mut closed_takeover_history = false;
    for intent in &desired.volumes {
        let Some(observed) = runtime
            .volumes
            .iter()
            .find(|observed| observed.volume_id == intent.volume_id)
        else {
            return MultiAcquireAdmission::StopLocal;
        };
        let disk_kind = match intent.disk_kind {
            DiskKind::Root => ObservedDiskKind::Root,
            DiskKind::Persistent => ObservedDiskKind::Persistent,
        };
        if observed.volume_intent_id.as_ref() != Some(&intent.volume_intent_id)
            || observed.disk_id.as_ref() != Some(&intent.disk_id)
            || observed.disk_kind != disk_kind
            || observed.size_bytes != Some(intent.size_bytes)
            || observed.durability != Some(intent.durability)
            || !observed.devices.is_empty()
            || !observed_authority_head(observed)
                .is_some_and(|head| multi_acquire_head_matches_intent(intent, head))
        {
            return MultiAcquireAdmission::StopLocal;
        }
        match &intent.acquire {
            VolumeAcquire::Normal {
                expected_unowned_epoch,
                ..
            } => {
                let Some(identity) =
                    expected_attachment_identity(desired, intent, *expected_unowned_epoch)
                else {
                    return MultiAcquireAdmission::StopLocal;
                };
                let Ok(data_directory) = host_path(
                    &authorized_blockd_data_directory(state_directory, desired, &identity),
                    "multi-volume expected blockd data directory",
                ) else {
                    return MultiAcquireAdmission::StopLocal;
                };
                match &observed.authority {
                    VolumeAuthorityEvidence::Unowned {
                        attachment_epoch, ..
                    } if attachment_epoch == expected_unowned_epoch
                        && observed.local_lineages.is_empty() => {}
                    VolumeAuthorityEvidence::Owned {
                        attachment_id,
                        attachment_epoch,
                        head,
                    } if attachment_id == &intent.attachment_id
                        && *attachment_epoch == identity.attachment_epoch
                        && (observed.local_lineages.is_empty()
                            || observed.local_lineages
                                == [expected_local_lineage_at_head(
                                    &identity,
                                    &data_directory,
                                    head,
                                )]) => {}
                    _ => return MultiAcquireAdmission::StopLocal,
                }
            }
            VolumeAcquire::Takeover { authorization_id } => {
                match observed.local_lineages.as_slice() {
                    [] => {}
                    [lineage]
                        if lineage.attachment_id == intent.attachment_id
                            && lineage.acquire_origin
                                == (AcquireOrigin::Takeover {
                                    authorization_id: authorization_id.clone(),
                                })
                            && lineage.node_id == desired.placement.node_id
                            && lineage.placement_epoch == desired.placement.placement_epoch =>
                    {
                        let identity = AttachmentLineageIdentity {
                            volume_id: intent.volume_id.clone(),
                            attachment_id: lineage.attachment_id.clone(),
                            attachment_epoch: lineage.attachment_epoch,
                            acquire_origin: lineage.acquire_origin.clone(),
                            node_id: lineage.node_id.clone(),
                            placement_epoch: lineage.placement_epoch,
                        };
                        let Ok(data_directory) = host_path(
                            &authorized_blockd_data_directory(state_directory, desired, &identity),
                            "takeover expected blockd data directory",
                        ) else {
                            return MultiAcquireAdmission::StopLocal;
                        };
                        match (&observed.authority, lineage.state) {
                            (
                                VolumeAuthorityEvidence::Owned {
                                    attachment_id,
                                    attachment_epoch,
                                    head,
                                },
                                LocalLineageState::Active,
                            ) if attachment_id == &intent.attachment_id
                                && *attachment_epoch == lineage.attachment_epoch
                                && observed.local_lineages
                                    == [expected_local_lineage_at_head(
                                        &identity,
                                        &data_directory,
                                        head,
                                    )] => {}
                            (
                                VolumeAuthorityEvidence::Owned { head, .. }
                                | VolumeAuthorityEvidence::Unowned { head, .. },
                                LocalLineageState::Released,
                            ) if lineage.fenced
                                && lineage.pending_pack_count.get() == 0
                                && lineage.local_durable_generation
                                    == lineage.remote_durable_generation
                                && lineage.local_durable_generation <= head.generation
                                && lineage.data_directory == data_directory =>
                            {
                                closed_takeover_history = true;
                            }
                            _ => return MultiAcquireAdmission::StopLocal,
                        }
                    }
                    _ => return MultiAcquireAdmission::StopLocal,
                }
            }
        }
    }
    if closed_takeover_history {
        return if runtime.conditions.is_empty() {
            MultiAcquireAdmission::ReplanDesired
        } else {
            MultiAcquireAdmission::StopLocal
        };
    }
    if runtime.conditions
        != [Condition::Progressing {
            reason: ProgressingReason::ReconcileStep {
                step: runtime.step.clone(),
            },
        }]
    {
        return MultiAcquireAdmission::StopLocal;
    }
    let checkpoint_path =
        runtime_checkpoint_path(&state_directory.join(CHECKPOINT_NAMESPACE), &desired.cat_id);
    let phase_is_exact = match (&runtime.step, &runtime.checkpoint) {
        (
            ReconcileStep::InspectInventory { inventory_epoch },
            CheckpointEvidence::Missing {
                checkpoint_path: observed,
            },
        ) => {
            *inventory_epoch == observation.inventory_epoch
                && path_matches(observed, &checkpoint_path)
                && runtime
                    .volumes
                    .iter()
                    .all(|volume| volume.local_lineages.is_empty())
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
                checkpoint_path: observed,
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
                && path_matches(observed, &checkpoint_path)
                && desired
                    .volumes
                    .iter()
                    .any(|volume| request_matches_volume(request, desired, volume))
        }
        (ReconcileStep::ProvisionRootImage { .. }, CheckpointEvidence::Valid { step, .. }) => {
            step.as_ref() == &runtime.step
        }
        _ => false,
    };
    if phase_is_exact {
        MultiAcquireAdmission::Exact(runtime)
    } else {
        MultiAcquireAdmission::StopLocal
    }
}

fn multi_acquire_head_matches_intent(intent: &VolumeIntent, head: &RemoteHead) -> bool {
    match (intent.disk_kind, intent.mount.as_ref()) {
        (DiskKind::Root, None) => true,
        (DiskKind::Persistent, Some(mount)) => match &mount.initialization {
            cats_api::runtime_reconciliation::FilesystemInitialization::Initialize {
                expected_blank_head,
                ..
            } => head == expected_blank_head,
            cats_api::runtime_reconciliation::FilesystemInitialization::Existing => {
                head.generation.get() > 0
            }
        },
        _ => false,
    }
}

pub(super) fn multi_acquire_checkpoint_is_bound(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    state_directory: &std::path::Path,
) -> bool {
    let ReconcileStep::AcquireVolume { request } = &checkpoint.step else {
        return false;
    };
    let mut targets = desired
        .volumes
        .iter()
        .filter(|intent| request_matches_volume(request, desired, intent));
    let Some(target) = targets.next() else {
        return false;
    };
    if targets.next().is_some()
        || checkpoint.version != ContractVersion::V1
        || checkpoint.cat_id != desired.cat_id
        || checkpoint.node_id != desired.placement.node_id
        || checkpoint.placement_epoch != desired.placement.placement_epoch
        || checkpoint.desired_revision != desired.desired_revision
        || checkpoint.spec_digest != desired.spec_digest
        || checkpoint.runtime_incarnation.is_some()
        || checkpoint.runtime_launch.identity().is_some()
        || checkpoint.stable_state.is_some()
        || !checkpoint.processes.is_empty()
        || checkpoint.volumes.len() != desired.volumes.len()
        || !checkpoint.mounts.is_empty()
        || !checkpoint.networks.is_empty()
        || !matches!(
            checkpoint.guest_transport,
            GuestTransportEvidence::Unavailable
        )
        || !matches!(checkpoint.warm_snapshot, WarmSnapshotEvidence::Absent)
        || checkpoint.lifecycle_admission != LifecycleAdmission::Closed
        || !checkpoint.route_gates.is_empty()
        || !matches!(
            checkpoint.require_idle,
            RequireIdleCheckpoint::NotApplicable
        )
    {
        return false;
    }
    desired.volumes.iter().all(|intent| {
        let mut observed_matches = checkpoint
            .volumes
            .iter()
            .filter(|observed| observed.volume_id == intent.volume_id);
        let Some(observed) = observed_matches.next() else {
            return false;
        };
        if observed_matches.next().is_some()
            || observed.volume_intent_id.as_ref() != Some(&intent.volume_intent_id)
            || observed.disk_id.as_ref() != Some(&intent.disk_id)
            || observed.disk_kind
                != match intent.disk_kind {
                    DiskKind::Root => ObservedDiskKind::Root,
                    DiskKind::Persistent => ObservedDiskKind::Persistent,
                }
            || observed.size_bytes != Some(intent.size_bytes)
            || observed.durability != Some(intent.durability)
            || !observed.devices.is_empty()
            || !observed_authority_head(observed)
                .is_some_and(|head| multi_acquire_head_matches_intent(intent, head))
        {
            return false;
        }
        if prepared_observed_volume_is_exact(desired, intent, observed, state_directory) {
            return true;
        }
        match (&intent.acquire, &observed.authority) {
            (
                VolumeAcquire::Normal {
                    expected_unowned_epoch,
                    ..
                },
                VolumeAuthorityEvidence::Unowned {
                    attachment_epoch, ..
                },
            ) => attachment_epoch == expected_unowned_epoch && observed.local_lineages.is_empty(),
            (
                VolumeAcquire::Normal {
                    expected_unowned_epoch,
                    ..
                },
                VolumeAuthorityEvidence::Owned {
                    attachment_id,
                    attachment_epoch,
                    ..
                },
            ) if intent.volume_id == target.volume_id => {
                observed.local_lineages.is_empty()
                    && attachment_id == &intent.attachment_id
                    && expected_unowned_epoch
                        .get()
                        .checked_add(1)
                        .is_some_and(|next| next == attachment_epoch.get())
            }
            (VolumeAcquire::Takeover { .. }, VolumeAuthorityEvidence::Owned { .. }) => {
                observed.local_lineages.is_empty()
            }
            _ => false,
        }
    })
}

fn expected_local_lineage_at_head(
    identity: &AttachmentLineageIdentity,
    data_directory: &HostPath,
    head: &RemoteHead,
) -> LocalVolumeLineage {
    let mut lineage = expected_local_lineage(identity, data_directory);
    lineage.local_durable_generation = head.generation;
    lineage.remote_durable_generation = head.generation;
    lineage
}

fn next_multi_checkpoint_time(stored: &StoredCheckpoint) -> anyhow::Result<UnixMillis> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis();
    let now = u64::try_from(now).context("system time exceeds wire range")?;
    let minimum = stored
        .checkpoint()
        .updated_at_unix_ms
        .get()
        .checked_add(1)
        .context("multi-volume checkpoint timestamp exhausted")?;
    UnixMillis::new(now.max(minimum)).context("multi-volume checkpoint timestamp is invalid")
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
        acquire: AuthorizedServingAcquire::Normal {
            request: stored_request.clone(),
            result: result.clone(),
        },
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
        acquire: AuthorizedServingAcquire::Normal {
            request: request.clone(),
            result: result.clone(),
        },
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
    let Some((request, _)) = attachment.normal_acquire() else {
        return false;
    };
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
        && request.expected_unowned_epoch == *expected_unowned_epoch
        && request.desired_revision <= desired.desired_revision
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
            && cats_storage::authority::remote_head_is_same_or_later(
                head,
                attachment.initial_head(),
            )
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
        && record.last_transition == Some(attachment.expected_last_transition())
        && cats_storage::authority::remote_head_is_same_or_later(
            &record.head,
            attachment.initial_head(),
        )
}

fn takeover_attachment_from_signed_evidence(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    prior: &ObservedVolume,
    evidence: &RuntimeVolumeTransitionEvidenceSuccess,
    decision_receipt: &cats_api::runtime_reconciliation::TakeoverConsumedReceipt,
    grant: Option<&VolumeLeaseGrant>,
) -> Option<AuthorizedServingAttachment> {
    let VolumeAcquire::Takeover { authorization_id } = &volume.acquire else {
        return None;
    };
    let VolumeAuthorization::Takeover(authorization) = &evidence.authorization.authorization else {
        return None;
    };
    let AuthorizationState::Consumed(stored_receipt) = &evidence.authorization.state else {
        return None;
    };
    let AuthorizationConsumedReceipt::Takeover(stored_receipt) = stored_receipt.as_ref() else {
        return None;
    };
    let lease_expires_at = decision_receipt
        .consumed_at
        .get()
        .checked_add(authorization.lease_duration_ms)
        .and_then(UnixMillis::new)?;
    if evidence.authorization_id != *authorization_id
        || authorization.authorization_id != *authorization_id
        || stored_receipt != decision_receipt
        || authorization.authorized_node_id != desired.placement.node_id
        || authorization.volume_id != volume.volume_id
        || authorization.new_attachment_id != volume.attachment_id
        || authorization.desired_revision != desired.desired_revision
        || authorization.new_placement_epoch != desired.placement.placement_epoch
        || !takeover_predecessor_is_exact(prior, volume, authorization, decision_receipt)
        || !multi_acquire_head_matches_intent(volume, &decision_receipt.resulting_head)
    {
        return None;
    }
    if grant.is_some_and(|grant| {
        grant.volume_id != volume.volume_id
            || grant.attachment_id != volume.attachment_id
            || grant.attachment_epoch != decision_receipt.resulting_epoch
            || grant.size_bytes != volume.size_bytes
            || grant.durability != volume.durability
            || grant.head != decision_receipt.resulting_head
            || grant.lease_expires_at != lease_expires_at
            || grant.acquire_origin
                != (AcquireOrigin::Takeover {
                    authorization_id: authorization_id.clone(),
                })
    }) {
        return None;
    }
    let attachment = AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: volume.volume_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            attachment_epoch: decision_receipt.resulting_epoch,
            acquire_origin: AcquireOrigin::Takeover {
                authorization_id: authorization_id.clone(),
            },
            node_id: desired.placement.node_id.clone(),
            placement_epoch: desired.placement.placement_epoch,
        },
        size_bytes: volume.size_bytes,
        durability: volume.durability,
        // This publication is the immutable R0 acquire artifact. A signed
        // current record may already be a renewed/head-advanced/released or
        // higher-epoch successor; it proves closure but must never rewrite the
        // primary grant that was lost before local durability.
        head: decision_receipt.resulting_head.clone(),
        lease_expires_at,
        acquire: AuthorizedServingAcquire::Takeover {
            authorization: authorization.clone(),
            receipt: stored_receipt.clone(),
        },
    };
    validate_authorized_serving_attachment(&attachment)
        .is_ok()
        .then_some(attachment)
}

fn takeover_predecessor_is_exact(
    observed: &ObservedVolume,
    volume: &VolumeIntent,
    authorization: &cats_api::runtime_reconciliation::VolumeTakeoverAuthorization,
    receipt: &cats_api::runtime_reconciliation::TakeoverConsumedReceipt,
) -> bool {
    observed.volume_intent_id.as_ref() == Some(&volume.volume_intent_id)
        && observed.disk_id.as_ref() == Some(&volume.disk_id)
        && observed.volume_id == volume.volume_id
        && observed.disk_kind
            == match volume.disk_kind {
                DiskKind::Root => ObservedDiskKind::Root,
                DiskKind::Persistent => ObservedDiskKind::Persistent,
            }
        && observed.size_bytes == Some(volume.size_bytes)
        && observed.durability == Some(volume.durability)
        && observed.local_lineages.is_empty()
        && observed.devices.is_empty()
        && matches!(
            &observed.authority,
            VolumeAuthorityEvidence::Owned {
                attachment_id,
                attachment_epoch,
                head,
            } if attachment_id == &authorization.expected_attachment_id
                && *attachment_epoch == authorization.expected_epoch
                && multi_acquire_head_matches_intent(volume, head)
                // A Takeover preserves the locked predecessor head.  The
                // authorization has no head field, so the Control-signed
                // consumed receipt is the canonical exact binding for the
                // durable checkpoint predecessor.  A merely lower/compatible
                // head could otherwise borrow an unrelated valid receipt.
                && head == &receipt.resulting_head
        )
}

fn acquire_checkpoint_predecessor_matches_accepted_or_published(
    checkpoint: &RuntimeCheckpoint,
    accepted: &ObservedRuntimeStatus,
    volume: &VolumeIntent,
) -> bool {
    let Some(durable) = checkpoint
        .volumes
        .iter()
        .find(|observed| observed.volume_id == volume.volume_id)
    else {
        return false;
    };
    let Some(current) = accepted
        .volumes
        .iter()
        .find(|observed| observed.volume_id == volume.volume_id)
    else {
        return false;
    };
    // An exact local publication can legitimately be one item ahead of the
    // checkpoint CAS. The full scanner value-binds that artifact separately.
    // Without such a lineage, the accepted point read must reproduce every
    // durable predecessor byte before A22 is reachable.
    !current.local_lineages.is_empty() || current == durable
}

fn normal_publication_closes_checkpoint_predecessor(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    attachment: &AuthorizedServingAttachment,
) -> bool {
    let Some((request, result)) = attachment.normal_acquire() else {
        return false;
    };
    let Some(prior) = checkpoint
        .volumes
        .iter()
        .find(|observed| observed.volume_id == volume.volume_id)
    else {
        return false;
    };
    prior.volume_intent_id.as_ref() == Some(&volume.volume_intent_id)
        && prior.disk_id.as_ref() == Some(&volume.disk_id)
        && prior.volume_id == volume.volume_id
        && prior.disk_kind
            == match volume.disk_kind {
                DiskKind::Root => ObservedDiskKind::Root,
                DiskKind::Persistent => ObservedDiskKind::Persistent,
            }
        && prior.size_bytes == Some(volume.size_bytes)
        && prior.durability == Some(volume.durability)
        && prior.local_lineages.is_empty()
        && prior.devices.is_empty()
        && matches!(
            &prior.authority,
            VolumeAuthorityEvidence::Unowned {
                attachment_epoch,
                head,
            } if *attachment_epoch == request.expected_unowned_epoch
                // NormalAcquire preserves the locked Unowned head. Both the
                // checkpoint predecessor and immutable local R0 therefore
                // bind the signed result exactly; monotonic compatibility is
                // insufficient for a publication-recovery boundary.
                && head == &result.resulting_head
        )
        && attachment.head == result.resulting_head
        && request_matches_volume(&attachment.checkpoint_acquire_request(), desired, volume)
        && multi_acquire_head_matches_intent(volume, &result.resulting_head)
        && validate_authorized_serving_attachment(attachment).is_ok()
}

fn signed_takeover_successor_matches_point_read(
    evidence: &RuntimeVolumeTransitionEvidenceSuccess,
    current: cats_storage::authority::Result<VolumeRecord>,
) -> anyhow::Result<bool> {
    match (evidence.current_volume.as_ref(), current) {
        (Some(signed), Ok(point)) => Ok(validate_volume_record(signed).is_ok() && point == *signed),
        (None, Err(AuthorityError::NotFound)) if evidence.delete_completion.is_some() => Ok(true),
        (_, Err(AuthorityError::BackendUnknown)) => {
            anyhow::bail!("volume authority unavailable during takeover publication recovery")
        }
        _ => Ok(false),
    }
}

fn takeover_successor_requires_immediate_replan(
    evidence: &RuntimeVolumeTransitionEvidenceSuccess,
    primary_authorization_id: &Id,
    primary_receipt: &cats_api::runtime_reconciliation::TakeoverConsumedReceipt,
) -> bool {
    if evidence.delete_completion.is_some() || evidence.current_volume.is_none() {
        return true;
    }
    match evidence
        .current_volume
        .as_ref()
        .and_then(|record| record.last_transition.as_ref())
    {
        Some(LastVolumeTransition::Takeover { authorization_id }) => {
            authorization_id != primary_authorization_id
        }
        Some(LastVolumeTransition::Release { request, .. }) => {
            request.attachment_id != primary_receipt.new_attachment_id
                || request.expected_epoch != primary_receipt.resulting_epoch
        }
        Some(LastVolumeTransition::NormalAcquire { .. }) => false,
        Some(
            LastVolumeTransition::BeginDelete { .. }
            | LastVolumeTransition::BeginDisposableDelete { .. },
        )
        | None => true,
    }
}

fn signed_takeover_current_matches_observed(
    evidence: &RuntimeVolumeTransitionEvidenceSuccess,
    observed: &ObservedVolume,
) -> bool {
    let Some(current) = evidence.current_volume.as_ref() else {
        return false;
    };
    if validate_volume_record(current).is_err()
        || current.volume_id != observed.volume_id
        || Some(current.size_bytes) != observed.size_bytes
        || Some(current.durability) != observed.durability
    {
        return false;
    }
    match (
        &current.admin_state,
        &current.lease_owner,
        &observed.authority,
    ) {
        (
            VolumeAdminState::Active,
            Some(owner),
            VolumeAuthorityEvidence::Owned {
                attachment_id,
                attachment_epoch,
                head,
            },
        ) => {
            owner == attachment_id
                && current.lease_epoch == *attachment_epoch
                && current.head == *head
        }
        (
            VolumeAdminState::Active,
            None,
            VolumeAuthorityEvidence::Unowned {
                attachment_epoch,
                head,
            },
        ) => current.lease_epoch == *attachment_epoch && current.head == *head,
        (
            VolumeAdminState::Deleting {
                delete_id: current_id,
            },
            None,
            VolumeAuthorityEvidence::Deleting {
                delete_id,
                attachment_epoch,
                head,
            },
        ) => {
            current_id == delete_id
                && current.lease_epoch == *attachment_epoch
                && current.head == *head
        }
        _ => false,
    }
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
                && observed_is_unowned(old)
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
        runtime_launch: RuntimeLaunch::Absent,
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
    let provision_transition_id = random_id();
    let control_socket_path =
        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .root_paths(&provision_transition_id)
            .context("derive managed adopted Root control socket")?
            .control_socket()
            .clone();
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
            provision_transition_id,
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

fn desired_acquire_request(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    session: &AgentSession,
    lease_duration_ms: u64,
) -> RuntimeVolumeTransitionRequest {
    match &volume.acquire {
        VolumeAcquire::Normal { .. } => {
            normal_acquire_request(desired, volume, session, lease_duration_ms)
        }
        VolumeAcquire::Takeover { authorization_id } => normal_acquire_request_with_binding(
            desired,
            session_binding(session),
            VolumeAcquireRequest::Takeover {
                authorization_id: authorization_id.clone(),
            },
        ),
    }
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
    checkpoint: &RuntimeCheckpoint,
    state_directory: &std::path::Path,
) -> Option<&'a VolumeIntent> {
    if encode_desired_runtime_spec(desired).is_err()
        || desired.version != ContractVersion::V1
        || desired.target != RuntimeTarget::Running
        || !matches!(desired.transition, RuntimeTransition::CancelAndDrain)
        || desired.placement.node_id != session.node_id
    {
        return None;
    }
    if !multi_acquire_checkpoint_is_bound(checkpoint, desired, state_directory) {
        return None;
    }
    let ReconcileStep::AcquireVolume { request } = &checkpoint.step else {
        return None;
    };
    let mut volumes = desired
        .volumes
        .iter()
        .filter(|volume| request_matches_volume(request, desired, volume));
    let volume = volumes.next()?;
    if volumes.next().is_some() {
        return None;
    }
    if volume.access != VolumeAccess::ReadWriteOnce
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
    match (request, &volume.acquire) {
        (
            VolumeAcquireRequest::Normal {
                volume_id,
                transition_id,
                attachment_id,
                expected_unowned_epoch,
                desired_revision,
                placement_epoch,
                lease_duration_ms,
            },
            VolumeAcquire::Normal {
                transition_id: intended_transition,
                expected_unowned_epoch: intended_epoch,
            },
        ) => {
            volume_id == &volume.volume_id
                && transition_id == intended_transition
                && attachment_id == &volume.attachment_id
                && expected_unowned_epoch == intended_epoch
                && desired_revision == &desired.desired_revision
                && placement_epoch == &desired.placement.placement_epoch
                && (1..=MAX_LEASE_DURATION_MS).contains(lease_duration_ms)
        }
        (
            VolumeAcquireRequest::Takeover { authorization_id },
            VolumeAcquire::Takeover {
                authorization_id: intended,
            },
        ) => authorization_id == intended,
        _ => false,
    }
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
        runtime_launch: RuntimeLaunch::Absent,
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
    state_directory: &std::path::Path,
) -> Option<&'a VolumeAcquireRequest> {
    let ReconcileStep::AcquireVolume { request } = &checkpoint.step else {
        return None;
    };
    if !request_matches_volume(request, desired, volume) {
        return None;
    }
    multi_acquire_checkpoint_is_bound(checkpoint, desired, state_directory).then_some(request)
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
        disk_kind: match volume.disk_kind {
            DiskKind::Root => ObservedDiskKind::Root,
            DiskKind::Persistent => ObservedDiskKind::Persistent,
        },
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
        disk_kind: match volume.disk_kind {
            DiskKind::Root => ObservedDiskKind::Root,
            DiskKind::Persistent => ObservedDiskKind::Persistent,
        },
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
    observed.local_lineages.push(expected_local_lineage_at_head(
        &attachment.identity,
        &data_directory,
        &attachment.head,
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
        provision_transition_id,
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
    let Some(observed_volume) = checkpoint
        .volumes
        .iter()
        .find(|observed| observed.volume_id == volume.volume_id)
    else {
        return false;
    };
    let Some((expected_identity, observed_head)) = prepared_observed_volume_identity_if_exact(
        desired,
        volume,
        observed_volume,
        state_directory,
    ) else {
        return false;
    };
    let expected_data_directory =
        authorized_blockd_data_directory(state_directory, desired, &expected_identity);
    let observed_volume_matches =
        observed_head == *expected_blank_head || observed_head == *expected_provisioned_head;
    checkpoint.version == ContractVersion::V1
        && checkpoint.cat_id == desired.cat_id
        && checkpoint.node_id == desired.placement.node_id
        && checkpoint.placement_epoch == desired.placement.placement_epoch
        && checkpoint.desired_revision == desired.desired_revision
        && checkpoint.spec_digest == desired.spec_digest
        && checkpoint.runtime_incarnation.is_none()
        && checkpoint.stable_state.is_none()
        && checkpoint.processes.is_empty()
        && checkpoint.volumes.len() == desired.volumes.len()
        && desired.volumes.iter().all(|intent| {
            checkpoint.volumes.iter().find(|observed| {
                observed.volume_id == intent.volume_id
            }).is_some_and(|observed| {
                if intent.volume_id == volume.volume_id {
                    return true;
                }
                prepared_observed_volume_is_exact(desired, intent, observed, state_directory)
            })
        })
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
        // The scope is stable for the whole provision transition, while an
        // exact dead-process retirement rotates only the attempt token.
        // Deriving the scope from the current token would make the first legal
        // retry unreadable by a fresh scanner.
        && root_provision_scope_id_is_canonical(scope_id)
        && !process_identity_token.as_str().is_empty()
        && cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .root_paths(provision_transition_id)
            .is_ok_and(|paths| control_socket_path == paths.control_socket())
}

fn prepared_observed_volume_is_exact(
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
    observed: &ObservedVolume,
    state_directory: &std::path::Path,
) -> bool {
    prepared_observed_volume_identity_if_exact(desired, intent, observed, state_directory).is_some()
}

fn prepared_observed_volume_identity_if_exact(
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
    observed: &ObservedVolume,
    state_directory: &std::path::Path,
) -> Option<(AttachmentLineageIdentity, RemoteHead)> {
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
    let acquire_is_exact = match (&intent.acquire, &lineage.acquire_origin) {
        (
            VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            },
            AcquireOrigin::Normal {
                transition_id: observed,
            },
        ) => {
            observed == transition_id
                && expected_unowned_epoch
                    .get()
                    .checked_add(1)
                    .is_some_and(|next| next == attachment_epoch.get())
        }
        (
            VolumeAcquire::Takeover { authorization_id },
            AcquireOrigin::Takeover {
                authorization_id: observed,
            },
        ) => observed == authorization_id,
        _ => false,
    };
    if !acquire_is_exact
        || observed.volume_intent_id.as_ref() != Some(&intent.volume_intent_id)
        || observed.disk_id.as_ref() != Some(&intent.disk_id)
        || observed.volume_id != intent.volume_id
        || observed.disk_kind
            != match intent.disk_kind {
                DiskKind::Root => ObservedDiskKind::Root,
                DiskKind::Persistent => ObservedDiskKind::Persistent,
            }
        || observed.size_bytes != Some(intent.size_bytes)
        || observed.durability != Some(intent.durability)
        || !observed.devices.is_empty()
        || attachment_id != &intent.attachment_id
        || *attachment_epoch != lineage.attachment_epoch
        || lineage.attachment_id != intent.attachment_id
        || lineage.node_id != desired.placement.node_id
        || lineage.placement_epoch != desired.placement.placement_epoch
        || !multi_acquire_head_matches_intent(intent, head)
    {
        return None;
    }
    let identity = AttachmentLineageIdentity {
        volume_id: intent.volume_id.clone(),
        attachment_id: lineage.attachment_id.clone(),
        attachment_epoch: lineage.attachment_epoch,
        acquire_origin: lineage.acquire_origin.clone(),
        node_id: lineage.node_id.clone(),
        placement_epoch: lineage.placement_epoch,
    };
    let expected_data_directory =
        authorized_blockd_data_directory(state_directory, desired, &identity);
    let Ok(expected_data_directory) = host_path(
        &expected_data_directory,
        "prepared observed Volume data directory",
    ) else {
        return None;
    };
    (observed.local_lineages
        == [expected_local_lineage_at_head(
            &identity,
            &expected_data_directory,
            head,
        )])
    .then(|| (identity, head.clone()))
}

fn root_provision_scope_id_is_canonical(scope_id: &Id) -> bool {
    scope_id
        .as_str()
        .strip_prefix("cats-root-")
        .and_then(|value| value.strip_suffix(".service"))
        .is_some_and(|value| RandomId128::new(value).is_some())
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
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use cats_api::runtime_reconciliation::{
        checkpoint_content_digest, decode_desired_runtime_spec, decode_runtime_checkpoint,
        spec_digest, AcquireOrigin, AdmissionInventoryAttestation, AgentSession, AssignedKind,
        AssignedPlacement, AuthorizationRecord, BeginDeleteRequest,
        BeginDisposableDeleteConsumedReceipt, DeleteCompletionReceipt, DesiredReadSnapshot,
        DisposableDeleteIsolationBasis, DisposableRootDeleteAuthorization, Epoch,
        GuestDeviceIdentity, Ipv4Address, IsolatedIpv4Kind, LastVolumeTransition, MacAddress,
        NetworkConfig, NodeBootId, NodeObservation, NormalAcquireRequest, NormalAcquireResult,
        Revision, RuntimeConfig, RuntimeVolumeAuthorityRejection,
        RuntimeVolumeTransitionPreconditionProblem, Sequence, TakeoverConsumedReceipt,
        VolumeAdminState, VolumeRecord, VolumeTakeoverAuthorization,
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

    #[cfg(target_os = "linux")]
    use super::super::clean_slate_probes::{
        InstalledStaleBootVmmRecoveryPorts, RuntimeCheckpointRecoverySet,
    };
    #[cfg(target_os = "linux")]
    use super::super::vmm_process::{
        stale_boot_recovery_global_sealed, ExactVmmProcessAbsenceProof,
        StaleBootVmmProcessGlobalInspection, StaleBootVmmProcessGlobalPort, VmmProcessExpectation,
    };
    #[cfg(target_os = "linux")]
    use super::super::vmm_runtime_paths::{
        ManagedVmmLaunchFilePaths, RetainedManagedVmmLaunchRoot, VMM_LAUNCH_FILE_NAMESPACE,
    };
    #[cfg(target_os = "linux")]
    use super::super::vmm_socket_namespace::{
        current_kernel_node_boot_id, RetainedManagedVmmSocketRoot, VmmSocketOwnershipReceiptV1,
        VmmSocketReceiptStore, VMM_SOCKET_RECEIPT_NAMESPACE,
    };

    use super::super::{
        clean_slate_scanner_with_volume_authority_and_blob_for_test,
        clean_slate_scanner_with_volume_authority_for_test, TestCleanSlateProbeConfig,
    };

    const FIXED_DESIRED_WIRE: &str =
        include_str!("../../../../testdata/runtime-reconciliation-v1-desired.json");
    const FIXED_PROVISION_ROOT_CHECKPOINT_WIRE: &str =
        include_str!("../../../../testdata/runtime-reconciliation-v1-provision-checkpoint.json");

    fn literal_file_bytes(value: &'static str) -> &'static [u8] {
        value.strip_suffix('\n').unwrap_or(value).as_bytes()
    }

    use super::*;

    #[derive(Default)]
    struct AcquireState {
        outcomes: VecDeque<NormalAcquireAttempt>,
        takeover_outcomes: VecDeque<TakeoverAcquireAttempt>,
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

    #[derive(Default)]
    struct EvidenceState {
        outcomes: VecDeque<VolumeEvidenceRecovery>,
        requests: Vec<RuntimeVolumeTransitionEvidenceRequest>,
        deadlines: Vec<Instant>,
        after_call: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    struct FakeEvidence {
        state: Arc<Mutex<EvidenceState>>,
    }

    impl SignedVolumeEvidencePort for FakeEvidence {
        fn recover_authorization(
            &self,
            request: &RuntimeVolumeTransitionEvidenceRequest,
            deadline: Instant,
        ) -> Result<VolumeEvidenceRecovery, super::super::VolumeEvidenceClientError> {
            let (outcome, after_call) = {
                let mut state = self.state.lock().unwrap();
                state.requests.push(request.clone());
                state.deadlines.push(deadline);
                (
                    state
                        .outcomes
                        .pop_front()
                        .unwrap_or(VolumeEvidenceRecovery::Ambiguous),
                    state.after_call.clone(),
                )
            };
            if let Some(after_call) = after_call {
                after_call();
            }
            Ok(outcome)
        }
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

        fn takeover(
            &self,
            request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _accepted: &NormalAcquireAcceptedContext,
            deadline: Instant,
        ) -> Result<TakeoverAcquireAttempt, NormalAcquireClientError> {
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
                .takeover_outcomes
                .pop_front()
                .unwrap_or(TakeoverAcquireAttempt::RetryExact))
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

    fn production_effect_with_release(
        desired: &DesiredRuntimeSpec,
        release_outcomes: Vec<NormalReleaseAttempt>,
        authority: Arc<FakeAuthority>,
        blob: Arc<RecordingBlob>,
        checkpoint_path: std::path::PathBuf,
    ) -> (
        SignedRunningAcquireEffect,
        Arc<Mutex<AcquireState>>,
        Arc<Mutex<EvidenceState>>,
    ) {
        let (effect, acquire) =
            effect_with_release(desired, release_outcomes, authority, blob, checkpoint_path);
        let evidence = Arc::new(Mutex::new(EvidenceState::default()));
        let port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
            state: Arc::clone(&evidence),
        });
        (effect.with_volume_evidence(port), acquire, evidence)
    }

    fn production_effect(
        _desired: &DesiredRuntimeSpec,
        normal_outcomes: Vec<NormalAcquireAttempt>,
        takeover_outcomes: Vec<TakeoverAcquireAttempt>,
        evidence_outcomes: Vec<VolumeEvidenceRecovery>,
        authority: Arc<FakeAuthority>,
        blob: Arc<RecordingBlob>,
        checkpoint_path: std::path::PathBuf,
    ) -> (
        SignedRunningAcquireEffect,
        Arc<Mutex<AcquireState>>,
        Arc<Mutex<EvidenceState>>,
    ) {
        let acquire = Arc::new(Mutex::new(AcquireState {
            outcomes: normal_outcomes.into(),
            takeover_outcomes: takeover_outcomes.into(),
            checkpoint_path: Some(checkpoint_path),
            ..AcquireState::default()
        }));
        let acquire_port: Arc<dyn SignedNormalAcquirePort> = Arc::new(FakeAcquire {
            state: Arc::clone(&acquire),
        });
        let effect =
            SignedRunningAcquireEffect::new(acquire_port, authority, blob, 60_000).unwrap();
        let evidence = Arc::new(Mutex::new(EvidenceState {
            outcomes: evidence_outcomes.into(),
            ..EvidenceState::default()
        }));
        let port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
            state: Arc::clone(&evidence),
        });
        (effect.with_volume_evidence(port), acquire, evidence)
    }

    #[test]
    fn shared_provision_predecessor_is_production_bound() {
        let desired = decode_desired_runtime_spec(literal_file_bytes(FIXED_DESIRED_WIRE)).unwrap();
        let checkpoint =
            decode_runtime_checkpoint(literal_file_bytes(FIXED_PROVISION_ROOT_CHECKPOINT_WIRE))
                .unwrap();
        assert_eq!(
            checkpoint_content_digest(&checkpoint).unwrap().as_str(),
            "sha256:ab2d78e9db6bfdebf30566f5cfba5b12e5dc0400e0607db10f29e85ada81aef0"
        );
        let (expected_blank_head, expected_provisioned_head) = match &checkpoint.step {
            ReconcileStep::ProvisionRootImage {
                expected_blank_head,
                expected_provisioned_head,
                ..
            } => (
                expected_blank_head.clone(),
                expected_provisioned_head.clone(),
            ),
            _ => panic!("fixed predecessor must remain ProvisionRootImage"),
        };
        assert!(provision_checkpoint_is_bound(
            &checkpoint,
            &desired,
            &desired.volumes[0],
            std::path::Path::new("/var/lib/cats"),
            &expected_blank_head,
            &expected_provisioned_head,
        ));

        let mut missing_owned_volume = checkpoint.clone();
        missing_owned_volume.volumes.clear();
        assert!(!provision_checkpoint_is_bound(
            &missing_owned_volume,
            &desired,
            &desired.volumes[0],
            std::path::Path::new("/var/lib/cats"),
            &expected_blank_head,
            &expected_provisioned_head,
        ));
        let mut wrong_lineage = checkpoint.clone();
        wrong_lineage.volumes[0].local_lineages[0].remote_durable_generation =
            Generation::new(1).unwrap();
        assert!(!provision_checkpoint_is_bound(
            &wrong_lineage,
            &desired,
            &desired.volumes[0],
            std::path::Path::new("/var/lib/cats"),
            &expected_blank_head,
            &expected_provisioned_head,
        ));
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
            control_socket_path,
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                .root_paths(match &checkpoint.step {
                    ReconcileStep::ProvisionRootImage {
                        provision_transition_id,
                        ..
                    } => provision_transition_id,
                    _ => unreachable!(),
                })
                .unwrap()
                .control_socket()
        );
        assert_ne!(
            std::path::Path::new(control_socket_path.as_str()).parent(),
            Some(std::path::Path::new(data_directory.as_str())),
            "durable blockd data and boot-local managed sockets must remain disjoint"
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
    fn production_first_acquire_checkpoint_is_the_rounds_only_durable_effect() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let path = checkpoint_path(root.path(), &desired.cat_id);
        let (effect, acquire, evidence) = production_effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(attachment(
                &desired,
            )))],
            Vec::new(),
            Vec::new(),
            Arc::clone(&authority),
            Arc::clone(&blob),
            path.clone(),
        );
        let (context, _) = context(root.path(), &desired, None);

        assert_eq!(
            effect.apply(context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(acquire.lock().unwrap().requests.is_empty());
        assert!(evidence.lock().unwrap().requests.is_empty());
        assert_eq!(authority.loads.load(Ordering::SeqCst), 0);
        assert_eq!(blob.reads.load(Ordering::SeqCst), 0);
        let checkpoint = read_checkpoint(&path);
        assert!(matches!(
            checkpoint.step,
            ReconcileStep::AcquireVolume { .. }
        ));
        assert!(checkpoint
            .volumes
            .iter()
            .all(|volume| volume.local_lineages.is_empty()));
    }

    #[test]
    fn production_existing_root_bypasses_the_image_store_and_keeps_the_direct_bridge() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let existing_head = RemoteHead {
            generation: Generation::new(4).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([7; 32])),
            root_object_id: Some(AsciiText::new("roots/existing-root-4").unwrap()),
        };
        let mut existing = attachment(&desired);
        existing.head = existing_head.clone();
        existing.normal_acquire_mut().unwrap().1.resulting_head = existing_head.clone();
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::missing());
        let path = checkpoint_path(root.path(), &desired.cat_id);
        let (effect, acquire, _) = production_effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(existing.clone()))],
            Vec::new(),
            Vec::new(),
            authority,
            Arc::clone(&blob),
            path.clone(),
        );
        let mut initial_volume = unowned_observed_volume(&desired.volumes[0]);
        let VolumeAuthorityEvidence::Unowned { head, .. } = &mut initial_volume.authority else {
            unreachable!()
        };
        *head = existing_head.clone();
        let initial = observed_runtime_with_volumes(
            root.path(),
            &desired,
            None,
            vec![initial_volume.clone()],
        );
        let (initial_context, _) = context(root.path(), &desired, Some(initial));
        assert_eq!(
            effect.apply(initial_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let first = read_checkpoint(&path);
        let admitted = observed_runtime_with_volumes(
            root.path(),
            &desired,
            Some(&first),
            vec![initial_volume],
        );
        let (acquire_context, _) = context(root.path(), &desired, Some(admitted));
        assert_eq!(
            effect.apply(acquire_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert_eq!(blob.reads.load(Ordering::SeqCst), 0);
        assert_eq!(acquire.lock().unwrap().requests.len(), 1);
        let bridge = read_checkpoint(&path);
        assert!(matches!(bridge.step, ReconcileStep::AcquireVolume { .. }));
        assert_eq!(bridge.volumes[0].local_lineages.len(), 1);
        assert!(matches!(
            bridge.volumes[0].authority,
            VolumeAuthorityEvidence::Owned { ref head, .. } if head == &existing_head
        ));
    }

    #[test]
    fn production_single_existing_root_takeover_persists_thick_authority_without_manifest() {
        let root = tempfile::tempdir().unwrap();
        let mut desired = desired();
        let authorization_id = id("takeover-auth-root-single");
        desired.volumes[0].acquire = VolumeAcquire::Takeover {
            authorization_id: authorization_id.clone(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let existing_head = RemoteHead {
            generation: Generation::new(5).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([8; 32])),
            root_object_id: Some(AsciiText::new("roots/takeover-root-5").unwrap()),
        };
        let volume = &desired.volumes[0];
        let authorization = VolumeTakeoverAuthorization {
            authorization_id: authorization_id.clone(),
            authorized_node_id: desired.placement.node_id.clone(),
            host_fence_event_id: id("fence-event-root-single"),
            volume_id: volume.volume_id.clone(),
            expected_attachment_id: id("att-root-old"),
            expected_epoch: fence(9),
            new_attachment_id: volume.attachment_id.clone(),
            desired_revision: desired.desired_revision,
            new_placement_epoch: desired.placement.placement_epoch,
            lease_duration_ms: 60_000,
            not_after: unix_ms(1_900_000_020_000),
        };
        let receipt = TakeoverConsumedReceipt {
            authorization_id: authorization_id.clone(),
            host_fence_event_id: authorization.host_fence_event_id.clone(),
            volume_id: volume.volume_id.clone(),
            new_attachment_id: volume.attachment_id.clone(),
            resulting_epoch: fence(10),
            resulting_head: existing_head.clone(),
            consumed_at: unix_ms(1_900_000_010_000),
        };
        let expiry = unix_ms(1_900_000_070_000);
        let record = VolumeRecord {
            volume_id: volume.volume_id.clone(),
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            admin_state: VolumeAdminState::Active,
            head: existing_head.clone(),
            lease_owner: Some(volume.attachment_id.clone()),
            lease_epoch: receipt.resulting_epoch,
            lease_expires_at: Some(expiry),
            last_transition: Some(LastVolumeTransition::Takeover {
                authorization_id: authorization_id.clone(),
            }),
        };
        let evidence = RuntimeVolumeTransitionEvidenceSuccess {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: desired.placement.node_id.clone(),
                node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
                agent_instance_id: random('4'),
                agent_session_epoch: epoch(2),
            },
            authorization_id: authorization_id.clone(),
            authorization: AuthorizationRecord {
                authorization: VolumeAuthorization::Takeover(authorization),
                state: AuthorizationState::Consumed(Box::new(
                    AuthorizationConsumedReceipt::Takeover(receipt.clone()),
                )),
            },
            current_volume: Some(record.clone()),
            delete_completion: None,
            direct_successor_authorization: None,
        };
        let grant = VolumeLeaseGrant {
            volume_id: volume.volume_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            attachment_epoch: receipt.resulting_epoch,
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            head: existing_head.clone(),
            lease_expires_at: expiry,
            acquire_origin: AcquireOrigin::Takeover {
                authorization_id: authorization_id.clone(),
            },
        };
        let blob = Arc::new(RecordingBlob::missing());
        let path = checkpoint_path(root.path(), &desired.cat_id);
        let (effect, acquire, evidence_calls) = production_effect(
            &desired,
            Vec::new(),
            vec![TakeoverAcquireAttempt::LeaseGranted(grant)],
            vec![VolumeEvidenceRecovery::Validated {
                evidence: Box::new(evidence),
                decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptTakeover(
                    receipt.clone(),
                )),
            }],
            Arc::new(FakeAuthority::new(Ok(record))),
            Arc::clone(&blob),
            path.clone(),
        );
        let initial_volume = ObservedVolume {
            volume_intent_id: Some(volume.volume_intent_id.clone()),
            disk_id: Some(volume.disk_id.clone()),
            volume_id: volume.volume_id.clone(),
            disk_kind: ObservedDiskKind::Root,
            size_bytes: Some(volume.size_bytes),
            durability: Some(volume.durability),
            authority: VolumeAuthorityEvidence::Owned {
                attachment_id: id("att-root-old"),
                attachment_epoch: fence(9),
                head: existing_head.clone(),
            },
            local_lineages: Vec::new(),
            devices: Vec::new(),
        };
        let initial = observed_runtime_with_volumes(
            root.path(),
            &desired,
            None,
            vec![initial_volume.clone()],
        );
        let (initial_context, _) = context(root.path(), &desired, Some(initial));
        assert_eq!(
            effect.apply(initial_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(acquire.lock().unwrap().requests.is_empty());
        let first = read_checkpoint(&path);
        let admitted = observed_runtime_with_volumes(
            root.path(),
            &desired,
            Some(&first),
            vec![initial_volume],
        );
        let (acquire_context, _) = context(root.path(), &desired, Some(admitted));
        assert_eq!(
            effect.apply(acquire_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let calls = acquire.lock().unwrap();
        assert_eq!(calls.requests.len(), 1);
        assert!(matches!(
            calls.requests[0].transition,
            RuntimeVolumeTransition::Acquire {
                request: VolumeAcquireRequest::Takeover { .. }
            }
        ));
        assert_eq!(evidence_calls.lock().unwrap().requests.len(), 1);
        assert_eq!(blob.reads.load(Ordering::SeqCst), 0);
        let bridge = read_checkpoint(&path);
        assert!(matches!(bridge.step, ReconcileStep::AcquireVolume { .. }));
        assert_eq!(bridge.volumes[0].local_lineages.len(), 1);
        assert!(matches!(
            bridge.volumes[0].authority,
            VolumeAuthorityEvidence::Owned { ref head, .. } if head == &existing_head
        ));
    }

    #[test]
    fn takeover_thick_evidence_requires_initial_revision_reopens_and_provisions_blank_root() {
        let root = tempfile::tempdir().unwrap();
        let mut desired = desired();
        let authorization_id = id("takeover-auth-root");
        desired.volumes[0].acquire = VolumeAcquire::Takeover {
            authorization_id: authorization_id.clone(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let volume = &desired.volumes[0];
        let head = blank_head();
        let authorization = VolumeTakeoverAuthorization {
            authorization_id: authorization_id.clone(),
            authorized_node_id: desired.placement.node_id.clone(),
            host_fence_event_id: id("fence-event-root"),
            volume_id: volume.volume_id.clone(),
            expected_attachment_id: id("old-root-attachment"),
            expected_epoch: fence(7),
            new_attachment_id: volume.attachment_id.clone(),
            desired_revision: desired.desired_revision,
            new_placement_epoch: desired.placement.placement_epoch,
            lease_duration_ms: 60_000,
            not_after: unix_ms(100_000),
        };
        let receipt = TakeoverConsumedReceipt {
            authorization_id: authorization_id.clone(),
            host_fence_event_id: authorization.host_fence_event_id.clone(),
            volume_id: volume.volume_id.clone(),
            new_attachment_id: volume.attachment_id.clone(),
            resulting_epoch: fence(8),
            resulting_head: head.clone(),
            consumed_at: unix_ms(10_000),
        };
        let record = VolumeRecord {
            volume_id: volume.volume_id.clone(),
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            admin_state: VolumeAdminState::Active,
            head: head.clone(),
            lease_owner: Some(volume.attachment_id.clone()),
            lease_epoch: receipt.resulting_epoch,
            lease_expires_at: Some(unix_ms(70_000)),
            last_transition: Some(LastVolumeTransition::Takeover {
                authorization_id: authorization_id.clone(),
            }),
        };
        let prior = ObservedVolume {
            volume_intent_id: Some(volume.volume_intent_id.clone()),
            disk_id: Some(volume.disk_id.clone()),
            volume_id: volume.volume_id.clone(),
            disk_kind: ObservedDiskKind::Root,
            size_bytes: Some(volume.size_bytes),
            durability: Some(volume.durability),
            authority: VolumeAuthorityEvidence::Owned {
                attachment_id: authorization.expected_attachment_id.clone(),
                attachment_epoch: authorization.expected_epoch,
                head: blank_head(),
            },
            local_lineages: Vec::new(),
            devices: Vec::new(),
        };
        let evidence = RuntimeVolumeTransitionEvidenceSuccess {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: desired.placement.node_id.clone(),
                node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
                agent_instance_id: random('4'),
                agent_session_epoch: epoch(2),
            },
            authorization_id: authorization_id.clone(),
            authorization: AuthorizationRecord {
                authorization: VolumeAuthorization::Takeover(authorization.clone()),
                state: AuthorizationState::Consumed(Box::new(
                    AuthorizationConsumedReceipt::Takeover(receipt.clone()),
                )),
            },
            current_volume: Some(record.clone()),
            delete_completion: None,
            direct_successor_authorization: None,
        };
        let attachment = takeover_attachment_from_signed_evidence(
            &desired, volume, &prior, &evidence, &receipt, None,
        )
        .expect("exact consumed evidence must form the thick serving authority");
        assert_eq!(attachment.lease_expires_at, unix_ms(70_000));

        let mut wrong_revision = evidence.clone();
        let VolumeAuthorization::Takeover(wrong_authorization) =
            &mut wrong_revision.authorization.authorization
        else {
            unreachable!()
        };
        wrong_authorization.desired_revision = Revision::new(2).unwrap();
        assert!(takeover_attachment_from_signed_evidence(
            &desired,
            volume,
            &prior,
            &wrong_revision,
            &receipt,
            None,
        )
        .is_none());

        let store = AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().into()));
        store.prepare(&desired, volume, &attachment).unwrap();
        let mut endpoint_only_successor = desired.clone();
        endpoint_only_successor.desired_revision = Revision::new(2).unwrap();
        endpoint_only_successor.spec_digest = spec_digest(&endpoint_only_successor).unwrap();
        store
            .reopen_adopted(
                &endpoint_only_successor,
                &endpoint_only_successor.volumes[0],
                &attachment.identity,
            )
            .expect("a higher revision may retain the immutable takeover authority");

        let producer_root = tempfile::tempdir().unwrap();
        let producer_authority = Arc::new(FakeAuthority::new(Ok(record.clone())));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let path = checkpoint_path(producer_root.path(), &desired.cat_id);
        let grant = VolumeLeaseGrant {
            volume_id: volume.volume_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            attachment_epoch: receipt.resulting_epoch,
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            head: blank_head(),
            lease_expires_at: attachment.lease_expires_at,
            acquire_origin: AcquireOrigin::Takeover {
                authorization_id: authorization_id.clone(),
            },
        };
        let recovery = VolumeEvidenceRecovery::Validated {
            evidence: Box::new(evidence.clone()),
            decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptTakeover(
                receipt.clone(),
            )),
        };
        let (effect, acquire, evidence_calls) = production_effect(
            &desired,
            Vec::new(),
            vec![TakeoverAcquireAttempt::LeaseGranted(grant)],
            vec![recovery],
            Arc::clone(&producer_authority),
            Arc::clone(&blob),
            path.clone(),
        );
        let initial = observed_runtime_with_volumes(
            producer_root.path(),
            &desired,
            None,
            vec![prior.clone()],
        );
        let (initial_context, _) = context(producer_root.path(), &desired, Some(initial));
        assert_eq!(
            effect.apply(initial_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(acquire.lock().unwrap().requests.is_empty());
        assert!(evidence_calls.lock().unwrap().requests.is_empty());

        let first = read_checkpoint(&path);
        let admitted = observed_runtime_with_volumes(
            producer_root.path(),
            &desired,
            Some(&first),
            vec![prior],
        );
        let (acquire_context, _) = context(producer_root.path(), &desired, Some(admitted));
        assert_eq!(
            effect.apply(acquire_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let provision = read_checkpoint(&path);
        assert!(matches!(
            provision.step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
        assert_eq!(acquire.lock().unwrap().requests.len(), 1);
        assert_eq!(evidence_calls.lock().unwrap().requests.len(), 1);

        producer_authority.set(Ok(record));
        let scanner_authority: Arc<dyn VolumeDataAuthority> = producer_authority;
        let scanner_blob: Arc<dyn BlobStore> = blob;
        let scanner =
            fresh_scanner_with_blob(producer_root.path(), scanner_authority, scanner_blob);
        assert!(matches!(
            scanner.scan_complete(scan_context(&desired)).unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));
    }

    #[test]
    fn restart_after_root_grant_adopts_missing_takeover_response_loss_in_a_mixed_set() {
        let root = tempfile::tempdir().unwrap();
        let mut desired = desired();
        let authorization_id = id("takeover-auth-persistent");
        let persistent = VolumeIntent {
            volume_intent_id: id("vint_z_persistent"),
            disk_id: id("disk-persistent"),
            volume_id: id("vol_z_persistent"),
            attachment_id: id("att-persistent-new"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Persistent,
            access: VolumeAccess::ReadWriteOnce,
            durability: cats_api::runtime_reconciliation::Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-persistent"),
                slot: 1,
            },
            acquire: VolumeAcquire::Takeover {
                authorization_id: authorization_id.clone(),
            },
            disposition: VolumeDisposition::Retain,
            mount: Some(cats_api::runtime_reconciliation::Ext4MountIntent {
                filesystem_uuid: random('b'),
                mount_path: HostPath::new("/srv/cats/persistent").unwrap(),
                initialization:
                    cats_api::runtime_reconciliation::FilesystemInitialization::Initialize {
                        initialization_token: random('c'),
                        expected_blank_head: blank_head(),
                    },
            }),
        };
        desired.volumes.push(persistent.clone());
        desired.spec_digest = spec_digest(&desired).unwrap();

        let takeover_observed = ObservedVolume {
            volume_intent_id: Some(persistent.volume_intent_id.clone()),
            disk_id: Some(persistent.disk_id.clone()),
            volume_id: persistent.volume_id.clone(),
            disk_kind: ObservedDiskKind::Persistent,
            size_bytes: Some(persistent.size_bytes),
            durability: Some(persistent.durability),
            authority: VolumeAuthorityEvidence::Owned {
                attachment_id: id("att-persistent-old"),
                attachment_epoch: fence(7),
                head: blank_head(),
            },
            local_lineages: Vec::new(),
            devices: Vec::new(),
        };
        let prior_takeover_record = VolumeRecord {
            volume_id: persistent.volume_id.clone(),
            size_bytes: persistent.size_bytes,
            durability: persistent.durability,
            admin_state: VolumeAdminState::Active,
            head: blank_head(),
            lease_owner: Some(id("att-persistent-old")),
            lease_epoch: fence(7),
            lease_expires_at: Some(unix_ms(1_900_000_060_000)),
            last_transition: Some(LastVolumeTransition::Takeover {
                authorization_id: id("prior-takeover-persistent"),
            }),
        };
        let root_attachment = attachment(&desired);
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let blob = Arc::new(RecordingBlob::present(&desired));
        let path = checkpoint_path(root.path(), &desired.cat_id);
        let (first_effect, first_calls, first_evidence) = production_effect(
            &desired,
            vec![NormalAcquireAttempt::Granted(Box::new(
                root_attachment.clone(),
            ))],
            Vec::new(),
            Vec::new(),
            Arc::clone(&authority),
            Arc::clone(&blob),
            path.clone(),
        );
        let initial = observed_runtime_with_volumes(
            root.path(),
            &desired,
            None,
            vec![
                unowned_observed_volume(&desired.volumes[0]),
                takeover_observed.clone(),
            ],
        );
        let (initial_context, _) = context(root.path(), &desired, Some(initial));
        assert_eq!(
            first_effect.apply(initial_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(first_calls.lock().unwrap().requests.is_empty());
        assert!(first_evidence.lock().unwrap().requests.is_empty());

        let first_checkpoint = read_checkpoint(&path);
        authority.set_records(BTreeMap::from([
            (
                desired.volumes[0].volume_id.clone(),
                Ok(unowned_record(&desired)),
            ),
            (
                persistent.volume_id.clone(),
                Ok(prior_takeover_record.clone()),
            ),
        ]));
        let first_scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let first_scanner_blob: Arc<dyn BlobStore> = blob.clone();
        let first_scanner =
            fresh_scanner_with_blob(root.path(), first_scanner_authority, first_scanner_blob);
        assert!(matches!(
            first_scanner.scan_complete(scan_context(&desired)).unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));
        let admitted = observed_runtime_with_volumes(
            root.path(),
            &desired,
            Some(&first_checkpoint),
            vec![
                unowned_observed_volume(&desired.volumes[0]),
                takeover_observed.clone(),
            ],
        );
        let (acquire_context, _) = context(root.path(), &desired, Some(admitted));
        assert_eq!(
            first_effect.apply(acquire_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let root_grant_checkpoint = read_checkpoint(&path);
        assert!(matches!(
            root_grant_checkpoint.step,
            ReconcileStep::AcquireVolume {
                request: VolumeAcquireRequest::Takeover { .. }
            }
        ));
        assert_eq!(first_calls.lock().unwrap().requests.len(), 1);
        assert_eq!(blob.reads.load(Ordering::SeqCst), 0);
        authority.set_records(BTreeMap::from([
            (
                root_attachment.identity.volume_id.clone(),
                Ok(owned_record(&desired, &root_attachment)),
            ),
            (
                persistent.volume_id.clone(),
                Ok(prior_takeover_record.clone()),
            ),
        ]));
        let root_data_directory = root_grant_checkpoint.volumes[0]
            .local_lineages
            .first()
            .map(|lineage| std::path::PathBuf::from(lineage.data_directory.as_str()))
            .unwrap();
        let held_root_data_directory = root.path().join("held-root-authorized-blockd");
        std::fs::rename(&root_data_directory, &held_root_data_directory).unwrap();
        let missing_scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let missing_scanner_blob: Arc<dyn BlobStore> = blob.clone();
        let missing_scanner =
            fresh_scanner_with_blob(root.path(), missing_scanner_authority, missing_scanner_blob);
        assert!(
            !matches!(
                missing_scanner.scan_complete(scan_context(&desired)),
                Ok(RuntimeInventoryScanOutcome::Complete(_))
            ),
            "a checkpointed prepared sibling cannot disappear from the actual blockd set"
        );
        std::fs::rename(&held_root_data_directory, &root_data_directory).unwrap();
        let partial_scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let partial_scanner_blob: Arc<dyn BlobStore> = blob.clone();
        let partial_scanner =
            fresh_scanner_with_blob(root.path(), partial_scanner_authority, partial_scanner_blob);
        assert!(matches!(
            partial_scanner
                .scan_complete(scan_context(&desired))
                .unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));
        for conflict in ["head", "origin", "epoch"] {
            let scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
            let scanner_blob: Arc<dyn BlobStore> = blob.clone();
            let root_volume_id = desired.volumes[0].volume_id.clone();
            assert_fresh_scanner_rejects_checkpoint_mutation(
                root.path(),
                &desired,
                scanner_authority,
                scanner_blob,
                move |checkpoint| {
                    let observed = checkpoint
                        .volumes
                        .iter_mut()
                        .find(|observed| observed.volume_id == root_volume_id)
                        .unwrap();
                    let [lineage] = observed.local_lineages.as_mut_slice() else {
                        panic!("Root grant must be checkpoint-prepared")
                    };
                    match conflict {
                        "head" => {
                            let conflicting = RemoteHead {
                                generation: Generation::new(2).unwrap(),
                                root_hash: Some(Sha256Digest::from_bytes([0x91; 32])),
                                root_object_id: Some(
                                    AsciiText::new("roots/checkpoint-conflict-2").unwrap(),
                                ),
                            };
                            let VolumeAuthorityEvidence::Owned { head, .. } =
                                &mut observed.authority
                            else {
                                panic!("prepared Root must be owned")
                            };
                            *head = conflicting.clone();
                            lineage.local_durable_generation = conflicting.generation;
                            lineage.remote_durable_generation = conflicting.generation;
                        }
                        "origin" => {
                            lineage.acquire_origin = AcquireOrigin::Takeover {
                                authorization_id: id("foreign_root_acquire_origin"),
                            };
                        }
                        "epoch" => {
                            let VolumeAuthorityEvidence::Owned {
                                attachment_epoch, ..
                            } = &mut observed.authority
                            else {
                                panic!("prepared Root must be owned")
                            };
                            *attachment_epoch = fence(attachment_epoch.get() + 1);
                            lineage.attachment_epoch = *attachment_epoch;
                        }
                        _ => unreachable!(),
                    }
                },
            );
        }

        let authorization = VolumeTakeoverAuthorization {
            authorization_id: authorization_id.clone(),
            authorized_node_id: desired.placement.node_id.clone(),
            host_fence_event_id: id("fence-event-persistent"),
            volume_id: persistent.volume_id.clone(),
            expected_attachment_id: id("att-persistent-old"),
            expected_epoch: fence(7),
            new_attachment_id: persistent.attachment_id.clone(),
            desired_revision: desired.desired_revision,
            new_placement_epoch: desired.placement.placement_epoch,
            lease_duration_ms: 60_000,
            not_after: unix_ms(1_900_000_020_000),
        };
        let receipt = TakeoverConsumedReceipt {
            authorization_id: authorization_id.clone(),
            host_fence_event_id: authorization.host_fence_event_id.clone(),
            volume_id: persistent.volume_id.clone(),
            new_attachment_id: persistent.attachment_id.clone(),
            resulting_epoch: fence(8),
            resulting_head: blank_head(),
            consumed_at: unix_ms(1_900_000_010_000),
        };
        let expiry = unix_ms(1_900_000_070_000);
        let takeover_record = VolumeRecord {
            volume_id: persistent.volume_id.clone(),
            size_bytes: persistent.size_bytes,
            durability: persistent.durability,
            admin_state: VolumeAdminState::Active,
            head: blank_head(),
            lease_owner: Some(persistent.attachment_id.clone()),
            lease_epoch: receipt.resulting_epoch,
            lease_expires_at: Some(expiry),
            last_transition: Some(LastVolumeTransition::Takeover {
                authorization_id: authorization_id.clone(),
            }),
        };
        let evidence = RuntimeVolumeTransitionEvidenceSuccess {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: desired.placement.node_id.clone(),
                node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
                agent_instance_id: random('8'),
                agent_session_epoch: epoch(3),
            },
            authorization_id: authorization_id.clone(),
            authorization: AuthorizationRecord {
                authorization: VolumeAuthorization::Takeover(authorization),
                state: AuthorizationState::Consumed(Box::new(
                    AuthorizationConsumedReceipt::Takeover(receipt.clone()),
                )),
            },
            current_volume: Some(takeover_record.clone()),
            delete_completion: None,
            direct_successor_authorization: None,
        };
        let recovery = VolumeEvidenceRecovery::Validated {
            evidence: Box::new(evidence.clone()),
            decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptTakeover(
                receipt.clone(),
            )),
        };
        authority.set_records(BTreeMap::from([
            (
                root_attachment.identity.volume_id.clone(),
                Ok(owned_record(&desired, &root_attachment)),
            ),
            (persistent.volume_id.clone(), Ok(takeover_record.clone())),
        ]));
        let recovery_state = Arc::new(Mutex::new(EvidenceState {
            outcomes: VecDeque::from([VolumeEvidenceRecovery::Validated {
                evidence: Box::new(evidence),
                decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptTakeover(
                    receipt.clone(),
                )),
            }]),
            ..EvidenceState::default()
        }));
        let recovery_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
            state: Arc::clone(&recovery_state),
        });
        let publication_recovery = SignedRunningPublicationRecovery::new(authority.clone())
            .with_volume_evidence(recovery_port);
        assert_eq!(
            publication_recovery
                .recover_one(recovery_context(root.path(), &desired))
                .unwrap(),
            RuntimePreScanRecoveryOutcome::Recovered {
                cat_id: desired.cat_id.clone(),
            }
        );
        assert_eq!(recovery_state.lock().unwrap().requests.len(), 1);

        let restart_scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let restart_scanner_blob: Arc<dyn BlobStore> = blob.clone();
        let restart_scanner =
            fresh_scanner_with_blob(root.path(), restart_scanner_authority, restart_scanner_blob);
        let RuntimeInventoryScanOutcome::Complete(restart_inventory) = restart_scanner
            .scan_complete(scan_context(&desired))
            .unwrap()
        else {
            panic!("mandatory recovery must close the next complete scan")
        };
        let [restarted] = restart_inventory.runtimes() else {
            panic!("restart scan must project exactly one Runtime")
        };
        let recovered_target = restarted
            .volumes
            .iter()
            .find(|volume| volume.volume_id == persistent.volume_id)
            .unwrap();
        assert!(matches!(
            recovered_target.authority,
            VolumeAuthorityEvidence::Owned {
                ref attachment_id,
                attachment_epoch,
                ..
            } if attachment_id == &persistent.attachment_id
                && attachment_epoch == receipt.resulting_epoch
        ));
        assert_eq!(recovered_target.local_lineages.len(), 1);
        let (restart_effect, restart_calls, restart_evidence) = production_effect(
            &desired,
            Vec::new(),
            vec![TakeoverAcquireAttempt::Ambiguous],
            vec![recovery],
            Arc::clone(&authority),
            blob.clone(),
            path.clone(),
        );
        let (context, _) = context_with_session(
            root.path(),
            &desired,
            Some(restarted.clone()),
            '8',
            3,
            1_900_000_010_000,
        );
        assert_eq!(
            restart_effect.apply(context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        let calls = restart_calls.lock().unwrap();
        assert!(
            calls.requests.is_empty(),
            "an exact recovered R0 must not replay the consumed takeover",
        );
        assert_eq!(restart_evidence.lock().unwrap().requests.len(), 1);
        assert_eq!(blob.reads.load(Ordering::SeqCst), 1);
        let provision = read_checkpoint(&path);
        assert!(matches!(
            provision.step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
        assert_eq!(provision.volumes.len(), 2);
        assert!(provision
            .volumes
            .iter()
            .all(|volume| volume.local_lineages.len() == 1));

        let takeover_data_directory = provision
            .volumes
            .iter()
            .find(|observed| observed.volume_id == persistent.volume_id)
            .and_then(|observed| observed.local_lineages.first())
            .map(|lineage| std::path::PathBuf::from(lineage.data_directory.as_str()))
            .unwrap();
        let takeover_attachment: AuthorizedServingAttachment = serde_json::from_slice(
            &std::fs::read(takeover_data_directory.join("authorized-serving.json")).unwrap(),
        )
        .unwrap();
        authority.set_records(BTreeMap::from([
            (
                root_attachment.identity.volume_id.clone(),
                Ok(owned_record(&desired, &root_attachment)),
            ),
            (
                takeover_attachment.identity.volume_id.clone(),
                Ok(owned_record(&desired, &takeover_attachment)),
            ),
        ]));
        let scanner_authority: Arc<dyn VolumeDataAuthority> = authority;
        let scanner_blob: Arc<dyn BlobStore> = blob.clone();
        let scanner = fresh_scanner_with_blob(
            root.path(),
            Arc::clone(&scanner_authority),
            Arc::clone(&scanner_blob),
        );
        assert!(matches!(
            scanner.scan_complete(scan_context(&desired)).unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));
        for conflict in ["head", "origin", "epoch"] {
            let persistent_volume_id = persistent.volume_id.clone();
            assert_fresh_scanner_rejects_checkpoint_mutation(
                root.path(),
                &desired,
                Arc::clone(&scanner_authority),
                Arc::clone(&scanner_blob),
                move |checkpoint| {
                    let observed = checkpoint
                        .volumes
                        .iter_mut()
                        .find(|observed| observed.volume_id == persistent_volume_id)
                        .unwrap();
                    let [lineage] = observed.local_lineages.as_mut_slice() else {
                        panic!("Persistent grant must be checkpoint-prepared")
                    };
                    match conflict {
                        "head" => {
                            let conflicting = RemoteHead {
                                generation: Generation::new(1).unwrap(),
                                root_hash: Some(Sha256Digest::from_bytes([0x92; 32])),
                                root_object_id: Some(
                                    AsciiText::new("roots/persistent-conflict-1").unwrap(),
                                ),
                            };
                            let VolumeAuthorityEvidence::Owned { head, .. } =
                                &mut observed.authority
                            else {
                                panic!("prepared Persistent must be owned")
                            };
                            *head = conflicting.clone();
                            lineage.local_durable_generation = conflicting.generation;
                            lineage.remote_durable_generation = conflicting.generation;
                        }
                        "origin" => {
                            lineage.acquire_origin = AcquireOrigin::Normal {
                                transition_id: random('f'),
                            };
                        }
                        "epoch" => {
                            let VolumeAuthorityEvidence::Owned {
                                attachment_epoch, ..
                            } = &mut observed.authority
                            else {
                                panic!("prepared Persistent must be owned")
                            };
                            *attachment_epoch = fence(attachment_epoch.get() + 1);
                            lineage.attachment_epoch = *attachment_epoch;
                        }
                        _ => unreachable!(),
                    }
                },
            );
        }
    }

    #[test]
    fn provision_scan_cross_binds_root_and_all_persistent_artifacts_by_value() {
        let root = tempfile::tempdir().unwrap();
        let mut desired = desired();
        let existing_head = RemoteHead {
            generation: Generation::new(4).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([0x31; 32])),
            root_object_id: Some(AsciiText::new("roots/persistent-existing-4").unwrap()),
        };
        let existing = VolumeIntent {
            volume_intent_id: id("vint_z_existing"),
            disk_id: id("disk_persistent_existing"),
            volume_id: id("vol_z_existing"),
            attachment_id: id("att_persistent_existing"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Persistent,
            access: VolumeAccess::ReadWriteOnce,
            durability: cats_api::runtime_reconciliation::Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-persist-exist"),
                slot: 1,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: random('5'),
                expected_unowned_epoch: fence(4),
            },
            disposition: VolumeDisposition::Retain,
            mount: Some(cats_api::runtime_reconciliation::Ext4MountIntent {
                filesystem_uuid: random('6'),
                mount_path: HostPath::new("/srv/cats/existing").unwrap(),
                initialization:
                    cats_api::runtime_reconciliation::FilesystemInitialization::Existing,
            }),
        };
        let initialize = VolumeIntent {
            volume_intent_id: id("vint_zz_initialize"),
            disk_id: id("disk_persistent_initialize"),
            volume_id: id("vol_zz_initialize"),
            attachment_id: id("att_persistent_initialize"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Persistent,
            access: VolumeAccess::ReadWriteOnce,
            durability: cats_api::runtime_reconciliation::Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-persist-init"),
                slot: 2,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: random('7'),
                expected_unowned_epoch: fence(6),
            },
            disposition: VolumeDisposition::Retain,
            mount: Some(cats_api::runtime_reconciliation::Ext4MountIntent {
                filesystem_uuid: random('8'),
                mount_path: HostPath::new("/srv/cats/initialize").unwrap(),
                initialization:
                    cats_api::runtime_reconciliation::FilesystemInitialization::Initialize {
                        initialization_token: random('9'),
                        expected_blank_head: blank_head(),
                    },
            }),
        };
        desired.volumes.extend([existing, initialize]);
        desired.spec_digest = spec_digest(&desired).unwrap();

        let root_attachment = normal_attachment(&desired, 0);
        let mut existing_attachment = normal_attachment(&desired, 1);
        existing_attachment.head = existing_head.clone();
        let AuthorizedServingAcquire::Normal { result, .. } = &mut existing_attachment.acquire
        else {
            unreachable!()
        };
        result.resulting_head = existing_head.clone();
        let initialize_attachment = normal_attachment(&desired, 2);
        let attachments = [
            root_attachment.clone(),
            existing_attachment.clone(),
            initialize_attachment.clone(),
        ];

        let mut records = desired
            .volumes
            .iter()
            .map(unowned_record_for)
            .collect::<Vec<_>>();
        records[1].head = existing_head.clone();
        let authority = Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
        let publish_records = |authority: &FakeAuthority, records: &[VolumeRecord]| {
            authority.set_records(
                records
                    .iter()
                    .map(|record| (record.volume_id.clone(), Ok(record.clone())))
                    .collect(),
            );
        };
        publish_records(&authority, &records);
        let blob = Arc::new(RecordingBlob::present(&desired));
        let path = checkpoint_path(root.path(), &desired.cat_id);
        let (effect, calls, evidence_calls) = production_effect(
            &desired,
            attachments
                .iter()
                .cloned()
                .map(|attachment| NormalAcquireAttempt::Granted(Box::new(attachment)))
                .collect(),
            Vec::new(),
            Vec::new(),
            Arc::clone(&authority),
            Arc::clone(&blob),
            path.clone(),
        );
        let mut initial_volumes = desired
            .volumes
            .iter()
            .map(unowned_observed_volume)
            .collect::<Vec<_>>();
        let VolumeAuthorityEvidence::Unowned { head, .. } = &mut initial_volumes[1].authority
        else {
            unreachable!()
        };
        *head = existing_head.clone();
        let initial = observed_runtime_with_volumes(root.path(), &desired, None, initial_volumes);
        let (initial_context, _) = context(root.path(), &desired, Some(initial));
        assert_eq!(
            effect.apply(initial_context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert!(calls.lock().unwrap().requests.is_empty());

        for (index, attachment) in attachments.iter().enumerate() {
            let scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
            let scanner_blob: Arc<dyn BlobStore> = blob.clone();
            let scanner = fresh_scanner_with_blob(root.path(), scanner_authority, scanner_blob);
            let RuntimeInventoryScanOutcome::Complete(inventory) =
                scanner.scan_complete(scan_context(&desired)).unwrap()
            else {
                panic!("partial multi-acquire scan did not complete")
            };
            let [runtime] = inventory.runtimes() else {
                panic!("partial multi-acquire scan projected the wrong Runtime set")
            };
            let (effect_context, _) = context_with_session(
                root.path(),
                &desired,
                Some(runtime.clone()),
                '8',
                3,
                1_900_000_010_000 + index as u64,
            );
            assert_eq!(
                effect.apply(effect_context, &desired).unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory
            );
            records[index] = owned_record(&desired, attachment);
            publish_records(&authority, &records);
            assert_eq!(
                read_checkpoint(&path)
                    .volumes
                    .iter()
                    .filter(|volume| !volume.local_lineages.is_empty())
                    .count(),
                index + 1,
            );
        }
        assert_eq!(calls.lock().unwrap().requests.len(), 3);
        assert!(evidence_calls.lock().unwrap().requests.is_empty());
        let provision = read_checkpoint(&path);
        let ReconcileStep::ProvisionRootImage {
            expected_provisioned_head,
            ..
        } = &provision.step
        else {
            panic!("complete volume set did not advance to Root provision")
        };
        let expected_provisioned_head = expected_provisioned_head.clone();

        let scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let scanner_blob: Arc<dyn BlobStore> = blob.clone();
        assert!(matches!(
            fresh_scanner_with_blob(root.path(), scanner_authority, scanner_blob)
                .scan_complete(scan_context(&desired))
                .unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));

        // Root may have completed its exact blank->target CAS while both
        // Persistent artifacts retain their own unrelated acquire heads.
        records[0].head = expected_provisioned_head;
        publish_records(&authority, &records);
        let scanner_authority: Arc<dyn VolumeDataAuthority> = authority.clone();
        let scanner_blob: Arc<dyn BlobStore> = blob.clone();
        assert!(matches!(
            fresh_scanner_with_blob(root.path(), scanner_authority, scanner_blob)
                .scan_complete(scan_context(&desired))
                .unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));

        // A same-generation but foreign Persistent tuple is not "later" and
        // must not be hidden by the Root provision head exception.
        records[1].head = RemoteHead {
            generation: existing_head.generation,
            root_hash: Some(Sha256Digest::from_bytes([0x32; 32])),
            root_object_id: Some(AsciiText::new("roots/persistent-conflict-4").unwrap()),
        };
        publish_records(&authority, &records);
        let scanner_authority: Arc<dyn VolumeDataAuthority> = authority;
        let scanner_blob: Arc<dyn BlobStore> = blob;
        assert!(
            !matches!(
                fresh_scanner_with_blob(root.path(), scanner_authority, scanner_blob)
                    .scan_complete(scan_context(&desired)),
                Ok(RuntimeInventoryScanOutcome::Complete(_))
            ),
            "a Persistent sibling same-generation tuple drift must fail closed"
        );
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
        let mut rotated_attempt = restored.checkpoint().clone();
        let ReconcileStep::ProvisionRootImage {
            scope_id,
            process_identity_token,
            ..
        } = &mut rotated_attempt.step
        else {
            unreachable!("fixture reached ProvisionRootImage")
        };
        let stable_scope_id = scope_id.clone();
        *process_identity_token = random('9');
        assert_ne!(
            stable_scope_id.as_str(),
            format!("cats-root-{}.service", process_identity_token.as_str())
        );
        let rotated = store.replace(&restored, &rotated_attempt).unwrap();
        assert!(matches!(
            scanner.scan_complete(scan_context(&desired)).unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));

        let mut wrong_scope = rotated.checkpoint().clone();
        let ReconcileStep::ProvisionRootImage { scope_id, .. } = &mut wrong_scope.step else {
            unreachable!("fixture reached ProvisionRootImage")
        };
        *scope_id = Id::new("foreign-root.service").unwrap();
        store.replace(&rotated, &wrong_scope).unwrap();
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
        let stored = acquire_checkpoint(
            &desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: attachment.checkpoint_acquire_request(),
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
                },
                "publication window {window:?}",
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
    fn pre_scan_recovery_completes_every_authorized_blockd_directory_prefix() {
        for acquire in [PublicationAcquire::Normal, PublicationAcquire::Takeover] {
            for prefix in [
                PublicationPrefix::Cat,
                PublicationPrefix::Volume,
                PublicationPrefix::Attachment,
                PublicationPrefix::Epoch,
            ] {
                let root = tempfile::tempdir().unwrap();
                let mut desired = desired();
                if acquire == PublicationAcquire::Takeover {
                    desired.volumes[0].acquire = VolumeAcquire::Takeover {
                        authorization_id: id("takeover_directory_prefix"),
                    };
                    desired.spec_digest = spec_digest(&desired).unwrap();
                }

                let (expected, record, evidence) = match acquire {
                    PublicationAcquire::Normal => {
                        let expected = attachment(&desired);
                        persist_acquire_checkpoint(root.path(), &desired);
                        (expected.clone(), owned_record(&desired, &expected), None)
                    }
                    PublicationAcquire::Takeover => {
                        let (expected, record, evidence, prior) =
                            takeover_recovery_fixture(&desired, 0);
                        let checkpoint = closed_checkpoint(
                            &desired,
                            ReconcileStep::AcquireVolume {
                                request: VolumeAcquireRequest::Takeover {
                                    authorization_id: id("takeover_directory_prefix"),
                                },
                            },
                            vec![prior],
                            unix_ms(1_900_000_000_000),
                        );
                        assert!(multi_acquire_checkpoint_is_bound(
                            &checkpoint,
                            &desired,
                            root.path(),
                        ));
                        persist_checkpoint(root.path(), &checkpoint);
                        (expected, record, Some(evidence))
                    }
                };
                let data_directory =
                    authorized_blockd_data_directory(root.path(), &desired, &expected.identity);
                drop(
                    AuthorizedBlockdStore::new(StateDirectory::unanchored(
                        root.path().to_path_buf(),
                    ))
                    .prepare(&desired, &desired.volumes[0], &expected)
                    .unwrap(),
                );
                shape_publication_prefix(&data_directory, prefix);

                let recovery =
                    SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(Ok(record))));
                let recovery = if let Some(evidence) = evidence {
                    recovery.with_volume_evidence(Arc::new(FakeEvidence {
                        state: Arc::new(Mutex::new(EvidenceState {
                            outcomes: VecDeque::from([evidence]),
                            ..EvidenceState::default()
                        })),
                    }))
                } else {
                    recovery
                };
                assert_eq!(
                    recovery
                        .recover_one(recovery_context(root.path(), &desired))
                        .unwrap(),
                    RuntimePreScanRecoveryOutcome::Recovered {
                        cat_id: desired.cat_id.clone(),
                    },
                    "{acquire:?} {prefix:?}",
                );
                for name in [
                    super::super::authorized_blockd::IDENTITY_FILE,
                    super::super::authorized_blockd::AUTHORIZED_SERVING_FILE,
                    super::super::authorized_blockd::LAUNCH_CHECKPOINT_FILE,
                ] {
                    assert!(
                        data_directory.join(name).is_file(),
                        "{acquire:?} {prefix:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn pre_scan_recovery_preserves_prepared_siblings_across_target_directory_prefixes() {
        for prefix in [
            PublicationPrefix::Volume,
            PublicationPrefix::Attachment,
            PublicationPrefix::Epoch,
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut desired = desired();
            desired.volumes.push(normal_persistent_volume());
            desired.spec_digest = spec_digest(&desired).unwrap();

            let prepared = normal_attachment(&desired, 0);
            let prepared_directory =
                authorized_blockd_data_directory(root.path(), &desired, &prepared.identity);
            drop(
                AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                    .prepare(&desired, &desired.volumes[0], &prepared)
                    .unwrap(),
            );
            let prepared_before = directory_file_snapshot(&prepared_directory);

            let target = normal_attachment(&desired, 1);
            let checkpoint = closed_checkpoint(
                &desired,
                ReconcileStep::AcquireVolume {
                    request: target.checkpoint_acquire_request(),
                },
                vec![
                    prepared_owned_observed_volume(
                        &desired.volumes[0],
                        &prepared,
                        host(prepared_directory.clone()),
                    ),
                    unowned_observed_volume(&desired.volumes[1]),
                ],
                unix_ms(1_900_000_000_000),
            );
            assert!(multi_acquire_checkpoint_is_bound(
                &checkpoint,
                &desired,
                root.path(),
            ));
            persist_checkpoint(root.path(), &checkpoint);

            let target_directory =
                authorized_blockd_data_directory(root.path(), &desired, &target.identity);
            drop(
                AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                    .prepare(&desired, &desired.volumes[1], &target)
                    .unwrap(),
            );
            shape_publication_prefix(&target_directory, prefix);

            let recovery = SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(Ok(
                owned_record(&desired, &target),
            ))));
            assert_eq!(
                recovery
                    .recover_one(recovery_context(root.path(), &desired))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: desired.cat_id.clone(),
                },
                "prepared sibling with target {prefix:?}",
            );
            assert_eq!(
                directory_file_snapshot(&prepared_directory),
                prepared_before,
                "prepared sibling changed while recovering target {prefix:?}",
            );
            for name in [
                super::super::authorized_blockd::IDENTITY_FILE,
                super::super::authorized_blockd::AUTHORIZED_SERVING_FILE,
                super::super::authorized_blockd::LAUNCH_CHECKPOINT_FILE,
            ] {
                assert!(target_directory.join(name).is_file(), "target {prefix:?}");
            }
        }
    }

    #[test]
    fn pre_scan_recovery_rejects_misattributed_authorized_blockd_directory_prefixes() {
        for prefix in [
            PublicationPrefix::Cat,
            PublicationPrefix::Volume,
            PublicationPrefix::Attachment,
            PublicationPrefix::Epoch,
        ] {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let expected = attachment(&desired);
            persist_acquire_checkpoint(root.path(), &desired);
            let data_directory =
                authorized_blockd_data_directory(root.path(), &desired, &expected.identity);
            drop(
                AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                    .prepare(&desired, &desired.volumes[0], &expected)
                    .unwrap(),
            );
            shape_publication_prefix(&data_directory, prefix);
            let foreign = misattribute_publication_prefix(&data_directory, prefix);

            let recovery = SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(Ok(
                owned_record(&desired, &expected),
            ))));
            assert!(
                !matches!(
                    recovery.recover_one(recovery_context(root.path(), &desired)),
                    Ok(RuntimePreScanRecoveryOutcome::Recovered { .. })
                ),
                "misattributed {prefix:?} prefix allowed publication",
            );
            assert!(
                foreign.exists(),
                "misattributed {prefix:?} residue was removed"
            );
            assert!(
                !data_directory.exists(),
                "misattributed {prefix:?} prefix was replaced by a target publication",
            );
        }
    }

    #[test]
    fn pre_scan_recovery_does_not_cross_an_unrelated_incomplete_blockd_leaf() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let expected = attachment(&desired);
        persist_acquire_checkpoint(root.path(), &desired);

        let other = second_desired();
        let other_attachment = attachment(&other);
        let other_directory =
            authorized_blockd_data_directory(root.path(), &other, &other_attachment.identity);
        drop(
            AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                .prepare(&other, &other.volumes[0], &other_attachment)
                .unwrap(),
        );
        shape_publication_window(&other_directory, PublicationWindow::IdentityTemp);
        let partial_before = directory_file_snapshot(&other_directory);

        let recovery = SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(Ok(
            owned_record(&desired, &expected),
        ))));
        assert_eq!(
            recovery
                .recover_one(recovery_context_with_desireds(
                    root.path(),
                    vec![desired.clone(), other],
                ))
                .unwrap(),
            RuntimePreScanRecoveryOutcome::NoChange,
        );
        assert!(
            !authorized_blockd_data_directory(root.path(), &desired, &expected.identity).exists(),
            "an unrelated incomplete leaf allowed target publication",
        );
        assert_eq!(directory_file_snapshot(&other_directory), partial_before);
    }

    #[test]
    fn pre_scan_takeover_recovery_requires_value_exact_prepared_siblings() {
        let root = tempfile::tempdir().unwrap();
        let mut desired = desired();
        desired.volumes.push(normal_persistent_volume());
        let authorization_id = id("takeover_sibling_value_exact");
        desired.volumes[1].acquire = VolumeAcquire::Takeover {
            authorization_id: authorization_id.clone(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let (target, record, evidence, prior) = takeover_recovery_fixture(&desired, 1);

        let checkpoint_sibling = normal_attachment(&desired, 0);
        let mut actual_sibling = checkpoint_sibling.clone();
        let wrong_head = RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([0x81; 32])),
            root_object_id: Some(AsciiText::new("roots/wrong-prepared-sibling").unwrap()),
        };
        actual_sibling.head = wrong_head.clone();
        let AuthorizedServingAcquire::Normal { result, .. } = &mut actual_sibling.acquire else {
            unreachable!("prepared sibling is Normal")
        };
        result.resulting_head = wrong_head;
        let sibling_directory =
            authorized_blockd_data_directory(root.path(), &desired, &actual_sibling.identity);
        drop(
            AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                .prepare(&desired, &desired.volumes[0], &actual_sibling)
                .unwrap(),
        );
        let checkpoint = closed_checkpoint(
            &desired,
            ReconcileStep::AcquireVolume {
                request: VolumeAcquireRequest::Takeover { authorization_id },
            },
            vec![
                prepared_owned_observed_volume(
                    &desired.volumes[0],
                    &checkpoint_sibling,
                    host(sibling_directory),
                ),
                prior,
            ],
            unix_ms(1_900_000_000_000),
        );
        assert!(multi_acquire_checkpoint_is_bound(
            &checkpoint,
            &desired,
            root.path(),
        ));
        persist_checkpoint(root.path(), &checkpoint);

        let evidence_state = Arc::new(Mutex::new(EvidenceState {
            outcomes: VecDeque::from([evidence]),
            ..EvidenceState::default()
        }));
        let recovery =
            SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(Ok(record))))
                .with_volume_evidence(Arc::new(FakeEvidence {
                    state: Arc::clone(&evidence_state),
                }));
        assert_eq!(
            recovery
                .recover_one(recovery_context(root.path(), &desired))
                .unwrap(),
            RuntimePreScanRecoveryOutcome::NoChange,
        );
        assert!(evidence_state.lock().unwrap().requests.is_empty());
        assert!(
            !authorized_blockd_data_directory(root.path(), &desired, &target.identity).exists(),
            "a checkpoint-conflicting prepared sibling allowed target publication",
        );
    }

    #[test]
    fn pre_scan_recovery_rebuilds_thick_takeover_authority_for_root_and_persistent() {
        for target_index in [0, 1] {
            let root = tempfile::tempdir().unwrap();
            let mut desired = desired();
            desired.volumes.push(normal_persistent_volume());
            let authorization_id = if target_index == 0 {
                id("takeover_recovery_root")
            } else {
                id("takeover_recovery_persistent")
            };
            desired.volumes[target_index].acquire = VolumeAcquire::Takeover {
                authorization_id: authorization_id.clone(),
            };
            desired.spec_digest = spec_digest(&desired).unwrap();

            let (expected, mut record, mut evidence, prior) =
                takeover_recovery_fixture(&desired, target_index);
            // The local R0 publication may be the only lost effect. A
            // mandatory renewal, and for Root a same-owner head CAS, may
            // already have advanced the signed current record. Recovery must
            // still materialize the immutable primary grant rather than
            // mistaking that closed successor for the first takeover result.
            record.lease_expires_at = Some(unix_ms(1_900_000_080_000));
            if target_index == 0 {
                record.head = RemoteHead {
                    generation: Generation::new(1).unwrap(),
                    root_hash: Some(Sha256Digest::from_bytes([9; 32])),
                    root_object_id: Some(AsciiText::new("roots/recovery-head-1").unwrap()),
                };
            }
            let VolumeEvidenceRecovery::Validated {
                evidence: signed, ..
            } = &mut evidence
            else {
                unreachable!("fixture returns validated takeover evidence")
            };
            signed.current_volume = Some(record.clone());
            let volumes = if target_index == 0 {
                vec![prior, unowned_observed_volume(&desired.volumes[1])]
            } else {
                let root_attachment = normal_attachment(&desired, 0);
                let data_directory = authorized_blockd_data_directory(
                    root.path(),
                    &desired,
                    &root_attachment.identity,
                );
                drop(
                    AuthorizedBlockdStore::new(StateDirectory::unanchored(
                        root.path().to_path_buf(),
                    ))
                    .prepare(&desired, &desired.volumes[0], &root_attachment)
                    .unwrap(),
                );
                vec![
                    prepared_owned_observed_volume(
                        &desired.volumes[0],
                        &root_attachment,
                        host(data_directory),
                    ),
                    prior,
                ]
            };
            let checkpoint = closed_checkpoint(
                &desired,
                ReconcileStep::AcquireVolume {
                    request: VolumeAcquireRequest::Takeover {
                        authorization_id: authorization_id.clone(),
                    },
                },
                volumes,
                unix_ms(1_900_000_000_000),
            );
            assert!(multi_acquire_checkpoint_is_bound(
                &checkpoint,
                &desired,
                root.path(),
            ));
            persist_checkpoint(root.path(), &checkpoint);

            let authority = Arc::new(FakeAuthority::new(Ok(record.clone())));
            let evidence_state = Arc::new(Mutex::new(EvidenceState {
                outcomes: VecDeque::from([evidence]),
                ..EvidenceState::default()
            }));
            let evidence_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
                state: Arc::clone(&evidence_state),
            });
            let recovery = SignedRunningPublicationRecovery::new(authority.clone())
                .with_volume_evidence(evidence_port);
            assert_eq!(
                recovery
                    .recover_one(recovery_context(root.path(), &desired))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: desired.cat_id.clone(),
                },
                "target slot {target_index}",
            );
            let data_directory =
                authorized_blockd_data_directory(root.path(), &desired, &expected.identity);
            let recovered: AuthorizedServingAttachment = serde_json::from_slice(
                &std::fs::read(data_directory.join("authorized-serving.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(recovered, expected, "target slot {target_index}");
            let state = evidence_state.lock().unwrap();
            assert_eq!(state.requests.len(), 1, "target slot {target_index}");
            assert_eq!(
                state.requests[0].authorization_id, authorization_id,
                "target slot {target_index}",
            );
            assert_eq!(state.requests[0].session.agent_instance_id, random('8'));
            drop(state);
            let other_index = usize::from(target_index == 0);
            let other_record = if target_index == 0 {
                unowned_record_for(&desired.volumes[other_index])
            } else {
                owned_record(&desired, &normal_attachment(&desired, other_index))
            };
            authority.set_records(BTreeMap::from([
                (desired.volumes[target_index].volume_id.clone(), Ok(record)),
                (
                    desired.volumes[other_index].volume_id.clone(),
                    Ok(other_record),
                ),
            ]));
            let scanner_authority: Arc<dyn VolumeDataAuthority> = authority;
            let scanner_blob: Arc<dyn BlobStore> = Arc::new(RecordingBlob::present(&desired));
            let scanner = fresh_scanner_with_blob(root.path(), scanner_authority, scanner_blob);
            let scan = scanner.scan_complete(scan_context(&desired)).unwrap();
            let RuntimeInventoryScanOutcome::Complete(inventory) = scan else {
                panic!("same-lineage renewal/head successor must remain scannable: {scan:?}")
            };
            let [runtime] = inventory.runtimes() else {
                panic!("recovered takeover scan must project exactly one Runtime")
            };
            let recovered_volume = runtime
                .volumes
                .iter()
                .find(|volume| volume.volume_id == desired.volumes[target_index].volume_id)
                .unwrap();
            assert_eq!(
                recovered_volume.local_lineages[0].state,
                LocalLineageState::Active
            );
        }
    }

    #[test]
    fn pre_scan_recovery_materializes_primary_takeover_after_closed_successors() {
        for target_index in [0, 1] {
            let mut desired = desired();
            desired.volumes.push(normal_persistent_volume());
            let authorization_id = if target_index == 0 {
                id("takeover_recovery_successor_root")
            } else {
                id("takeover_recovery_successor_persistent")
            };
            desired.volumes[target_index].acquire = VolumeAcquire::Takeover {
                authorization_id: authorization_id.clone(),
            };
            desired.spec_digest = spec_digest(&desired).unwrap();
            let (expected, primary, evidence, prior) =
                takeover_recovery_fixture(&desired, target_index);

            let (released, _) = cats_storage::authority::release(
                &primary,
                &cats_api::runtime_reconciliation::ReleaseRequest {
                    volume_id: primary.volume_id.clone(),
                    transition_id: random('e'),
                    attachment_id: desired.volumes[target_index].attachment_id.clone(),
                    expected_epoch: primary.lease_epoch,
                },
            )
            .unwrap();
            let reacquire_request = NormalAcquireRequest {
                volume_id: released.volume_id.clone(),
                transition_id: random('f'),
                attachment_id: if target_index == 0 {
                    id("att_recovery_successor_root")
                } else {
                    id("att_recovery_successor_persistent")
                },
                expected_unowned_epoch: released.lease_epoch,
                desired_revision: Revision::new(2).unwrap(),
                placement_epoch: epoch(4),
                lease_duration_ms: 60_000,
            };
            let (reacquired, _) = cats_storage::authority::normal_acquire(
                &released,
                &reacquire_request,
                unix_ms(1_900_000_090_000),
            )
            .unwrap();

            for (case, current) in [("released", released), ("higher-epoch", reacquired)] {
                let root = tempfile::tempdir().unwrap();
                let other_index = usize::from(target_index == 0);
                let (volumes, other_record) = if target_index == 0 {
                    (
                        vec![
                            prior.clone(),
                            unowned_observed_volume(&desired.volumes[other_index]),
                        ],
                        unowned_record_for(&desired.volumes[other_index]),
                    )
                } else {
                    let other_attachment = normal_attachment(&desired, other_index);
                    let other_data_directory = authorized_blockd_data_directory(
                        root.path(),
                        &desired,
                        &other_attachment.identity,
                    );
                    drop(
                        AuthorizedBlockdStore::new(StateDirectory::unanchored(
                            root.path().to_path_buf(),
                        ))
                        .prepare(&desired, &desired.volumes[other_index], &other_attachment)
                        .unwrap(),
                    );
                    (
                        vec![
                            prepared_owned_observed_volume(
                                &desired.volumes[other_index],
                                &other_attachment,
                                host(other_data_directory),
                            ),
                            prior.clone(),
                        ],
                        owned_record(&desired, &other_attachment),
                    )
                };
                let checkpoint = closed_checkpoint(
                    &desired,
                    ReconcileStep::AcquireVolume {
                        request: VolumeAcquireRequest::Takeover {
                            authorization_id: authorization_id.clone(),
                        },
                    },
                    volumes,
                    unix_ms(1_900_000_000_000),
                );
                persist_checkpoint(root.path(), &checkpoint);

                let mut successor_evidence = evidence.clone();
                let VolumeEvidenceRecovery::Validated {
                    evidence: signed, ..
                } = &mut successor_evidence
                else {
                    unreachable!("fixture returns validated takeover evidence")
                };
                signed.current_volume = Some(current.clone());
                let evidence_state = Arc::new(Mutex::new(EvidenceState {
                    outcomes: VecDeque::from([successor_evidence]),
                    ..EvidenceState::default()
                }));
                let evidence_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
                    state: Arc::clone(&evidence_state),
                });
                let authority = Arc::new(FakeAuthority::new(Ok(current.clone())));
                let recovery = SignedRunningPublicationRecovery::new(authority.clone())
                    .with_volume_evidence(evidence_port);
                assert_eq!(
                    recovery
                        .recover_one(recovery_context(root.path(), &desired))
                        .unwrap(),
                    RuntimePreScanRecoveryOutcome::Recovered {
                        cat_id: desired.cat_id.clone(),
                    },
                    "closed successor case {case}, target slot {target_index}",
                );
                let data_directory =
                    authorized_blockd_data_directory(root.path(), &desired, &expected.identity);
                let recovered: AuthorizedServingAttachment = serde_json::from_slice(
                    &std::fs::read(data_directory.join("authorized-serving.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    recovered, expected,
                    "closed successor case {case}, target slot {target_index}",
                );
                authority.set_records(BTreeMap::from([
                    (desired.volumes[target_index].volume_id.clone(), Ok(current)),
                    (
                        desired.volumes[other_index].volume_id.clone(),
                        Ok(other_record),
                    ),
                ]));
                let scanner_authority: Arc<dyn VolumeDataAuthority> = authority;
                let scanner_blob: Arc<dyn BlobStore> = Arc::new(RecordingBlob::present(&desired));
                let scanner = fresh_scanner_with_blob(root.path(), scanner_authority, scanner_blob);
                let RuntimeInventoryScanOutcome::Complete(inventory) =
                    scanner.scan_complete(scan_context(&desired)).unwrap()
                else {
                    panic!("closed successor must remain complete: {case}, slot {target_index}")
                };
                let [runtime] = inventory.runtimes() else {
                    panic!("closed successor scan must project exactly one Runtime")
                };
                assert!(runtime.conditions.is_empty());
                let recovered_volume = runtime
                    .volumes
                    .iter()
                    .find(|volume| volume.volume_id == desired.volumes[target_index].volume_id)
                    .unwrap();
                assert_eq!(
                    recovered_volume.local_lineages[0].state,
                    LocalLineageState::Released
                );
                let effect_authority =
                    Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown)));
                let effect_blob = Arc::new(RecordingBlob::present(&desired));
                let (effect, acquire_calls, evidence_calls) = production_effect(
                    &desired,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    effect_authority,
                    effect_blob,
                    checkpoint_path(root.path(), &desired.cat_id),
                );
                let (effect_context, _) = context(root.path(), &desired, Some(runtime.clone()));
                assert_eq!(
                    effect.apply(effect_context, &desired).unwrap(),
                    RuntimeDesiredEffectOutcome::ReplanDesired,
                    "closed successor case {case}, target slot {target_index}",
                );
                assert!(acquire_calls.lock().unwrap().requests.is_empty());
                assert!(evidence_calls.lock().unwrap().requests.is_empty());
            }
        }
    }

    #[test]
    fn historical_takeover_r0_rejects_checkpoint_predecessor_head_drift() {
        for target in ["root", "persistent-existing"] {
            let mut desired = desired();
            desired.volumes.push(normal_persistent_volume());
            let target_index = usize::from(target == "persistent-existing");
            let authorization_id = if target_index == 0 {
                id("takeover_historical_root")
            } else {
                id("takeover_historical_persistent")
            };
            desired.volumes[target_index].acquire = VolumeAcquire::Takeover {
                authorization_id: authorization_id.clone(),
            };
            desired.spec_digest = spec_digest(&desired).unwrap();
            let (mut attachment, mut primary, mut evidence, mut exact_prior) =
                takeover_recovery_fixture(&desired, target_index);
            if target_index == 1 {
                desired.volumes[target_index]
                    .mount
                    .as_mut()
                    .unwrap()
                    .initialization =
                    cats_api::runtime_reconciliation::FilesystemInitialization::Existing;
                desired.spec_digest = spec_digest(&desired).unwrap();
            }
            let canonical_head = RemoteHead {
                generation: Generation::new(5).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([0x55; 32])),
                root_object_id: Some(
                    AsciiText::new(format!("roots/historical-takeover-{target}-5")).unwrap(),
                ),
            };
            set_takeover_recovery_fixture_head(
                &mut attachment,
                &mut primary,
                &mut evidence,
                &mut exact_prior,
                canonical_head,
            );
            let (released, _) = cats_storage::authority::release(
                &primary,
                &cats_api::runtime_reconciliation::ReleaseRequest {
                    volume_id: primary.volume_id.clone(),
                    transition_id: random('4'),
                    attachment_id: desired.volumes[target_index].attachment_id.clone(),
                    expected_epoch: primary.lease_epoch,
                },
            )
            .unwrap();
            let reacquire_request = NormalAcquireRequest {
                volume_id: released.volume_id.clone(),
                transition_id: random('5'),
                attachment_id: if target_index == 0 {
                    id("att_historical_root_successor")
                } else {
                    id("att_historical_persistent_successor")
                },
                expected_unowned_epoch: released.lease_epoch,
                desired_revision: Revision::new(2).unwrap(),
                placement_epoch: epoch(4),
                lease_duration_ms: 60_000,
            };
            let (reacquired, _) = cats_storage::authority::normal_acquire(
                &released,
                &reacquire_request,
                unix_ms(1_900_000_090_000),
            )
            .unwrap();

            for (successor, current) in [("release", released), ("normal", reacquired)] {
                for drift in ["lower", "higher", "same-generation-foreign"] {
                    let root = tempfile::tempdir().unwrap();
                    drop(
                        AuthorizedBlockdStore::new(StateDirectory::unanchored(
                            root.path().to_path_buf(),
                        ))
                        .prepare(&desired, &desired.volumes[target_index], &attachment)
                        .unwrap(),
                    );
                    let other_index = usize::from(target_index == 0);
                    let (other_observed, other_record) = if target_index == 0 {
                        (
                            unowned_observed_volume(&desired.volumes[other_index]),
                            unowned_record_for(&desired.volumes[other_index]),
                        )
                    } else {
                        let other_attachment = normal_attachment(&desired, other_index);
                        let other_data_directory = authorized_blockd_data_directory(
                            root.path(),
                            &desired,
                            &other_attachment.identity,
                        );
                        drop(
                            AuthorizedBlockdStore::new(StateDirectory::unanchored(
                                root.path().to_path_buf(),
                            ))
                            .prepare(&desired, &desired.volumes[other_index], &other_attachment)
                            .unwrap(),
                        );
                        (
                            prepared_owned_observed_volume(
                                &desired.volumes[other_index],
                                &other_attachment,
                                host(other_data_directory),
                            ),
                            owned_record(&desired, &other_attachment),
                        )
                    };
                    let mut wrong = exact_prior.clone();
                    let VolumeAuthorityEvidence::Owned { head, .. } = &mut wrong.authority else {
                        unreachable!("historical takeover predecessor is owned")
                    };
                    let (generation, byte, suffix) = match drift {
                        "lower" => (4, 0x54, "lower"),
                        "higher" => (6, 0x56, "higher"),
                        "same-generation-foreign" => (5, 0x57, "foreign"),
                        _ => unreachable!(),
                    };
                    *head = RemoteHead {
                        generation: Generation::new(generation).unwrap(),
                        root_hash: Some(Sha256Digest::from_bytes([byte; 32])),
                        root_object_id: Some(
                            AsciiText::new(format!("roots/historical-takeover-{target}-{suffix}"))
                                .unwrap(),
                        ),
                    };
                    let volumes = if target_index == 0 {
                        vec![wrong, other_observed]
                    } else {
                        vec![other_observed, wrong]
                    };
                    let checkpoint = closed_checkpoint(
                        &desired,
                        ReconcileStep::AcquireVolume {
                            request: VolumeAcquireRequest::Takeover {
                                authorization_id: authorization_id.clone(),
                            },
                        },
                        volumes,
                        unix_ms(1_900_000_000_000),
                    );
                    assert!(multi_acquire_checkpoint_is_bound(
                        &checkpoint,
                        &desired,
                        root.path(),
                    ));
                    persist_checkpoint(root.path(), &checkpoint);
                    let authority = Arc::new(FakeAuthority::new(Ok(current.clone())));
                    authority.set_records(BTreeMap::from([
                        (
                            desired.volumes[target_index].volume_id.clone(),
                            Ok(current.clone()),
                        ),
                        (
                            desired.volumes[other_index].volume_id.clone(),
                            Ok(other_record),
                        ),
                    ]));
                    let scanner_authority: Arc<dyn VolumeDataAuthority> = authority;
                    let scanner = fresh_scanner_with_blob(
                        root.path(),
                        scanner_authority,
                        Arc::new(RecordingBlob::present(&desired)),
                    );
                    assert!(
                        !matches!(
                            scanner.scan_complete(scan_context(&desired)),
                            Ok(RuntimeInventoryScanOutcome::Complete(_))
                        ),
                        "historical R0 accepted {target}/{successor}/{drift} predecessor",
                    );
                }
            }
        }
    }

    #[test]
    fn pre_scan_delete_successors_replan_without_recovering_a_writer() {
        for case in [
            "higher-release",
            "begin-delete",
            "disposable-delete",
            "deleted",
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut desired = desired();
            let authorization_id = id("takeover_recovery_delete");
            desired.volumes[0].acquire = VolumeAcquire::Takeover {
                authorization_id: authorization_id.clone(),
            };
            desired.spec_digest = spec_digest(&desired).unwrap();
            let (expected, primary, fixture_evidence, prior) =
                takeover_recovery_fixture(&desired, 0);
            let VolumeEvidenceRecovery::Validated {
                evidence: fixture_evidence,
                ..
            } = fixture_evidence
            else {
                unreachable!("fixture returns validated takeover evidence")
            };
            let mut signed = *fixture_evidence;
            let mut point = Err(AuthorityError::NotFound);

            match case {
                "higher-release" => {
                    let (released, _) = cats_storage::authority::release(
                        &primary,
                        &cats_api::runtime_reconciliation::ReleaseRequest {
                            volume_id: primary.volume_id.clone(),
                            transition_id: random('1'),
                            attachment_id: expected.identity.attachment_id.clone(),
                            expected_epoch: expected.identity.attachment_epoch,
                        },
                    )
                    .unwrap();
                    let reacquire_request = NormalAcquireRequest {
                        volume_id: primary.volume_id.clone(),
                        transition_id: random('2'),
                        attachment_id: id("att_after_primary_takeover"),
                        expected_unowned_epoch: released.lease_epoch,
                        desired_revision: Revision::new(2).unwrap(),
                        placement_epoch: epoch(4),
                        lease_duration_ms: 60_000,
                    };
                    let (reacquired, _) = cats_storage::authority::normal_acquire(
                        &released,
                        &reacquire_request,
                        unix_ms(1_900_000_030_000),
                    )
                    .unwrap();
                    let reacquired_epoch = reacquired.lease_epoch;
                    let reacquired_owner = reacquired.lease_owner.clone().unwrap();
                    let (released_again, _) = cats_storage::authority::release(
                        &reacquired,
                        &cats_api::runtime_reconciliation::ReleaseRequest {
                            volume_id: primary.volume_id.clone(),
                            transition_id: random('3'),
                            attachment_id: reacquired_owner,
                            expected_epoch: reacquired_epoch,
                        },
                    )
                    .unwrap();
                    signed.current_volume = Some(released_again.clone());
                    point = Ok(released_again);
                }
                "begin-delete" | "deleted" => {
                    let (released, _) = cats_storage::authority::release(
                        &primary,
                        &cats_api::runtime_reconciliation::ReleaseRequest {
                            volume_id: primary.volume_id.clone(),
                            transition_id: random('d'),
                            attachment_id: expected.identity.attachment_id.clone(),
                            expected_epoch: expected.identity.attachment_epoch,
                        },
                    )
                    .unwrap();
                    let request = BeginDeleteRequest {
                        delete_id: id("delete_after_takeover"),
                        disk_id: desired.volumes[0].disk_id.clone(),
                        volume_id: primary.volume_id.clone(),
                        expected_unowned_epoch: released.lease_epoch,
                        expected_head: released.head.clone(),
                    };
                    let (deleting, _) =
                        cats_storage::authority::begin_delete(&released, &request).unwrap();
                    if case == "begin-delete" {
                        signed.current_volume = Some(deleting.clone());
                        point = Ok(deleting);
                    } else {
                        let completion = cats_storage::authority::complete_normal_delete(
                            &deleting,
                            unix_ms(1_900_000_090_000),
                        )
                        .unwrap();
                        signed.current_volume = None;
                        signed.delete_completion = Some(completion);
                    }
                }
                "disposable-delete" => {
                    let direct_id = id("disposable_after_takeover");
                    let direct_authorization = DisposableRootDeleteAuthorization {
                        authorization_id: direct_id.clone(),
                        authorized_node_id: desired.placement.node_id.clone(),
                        delete_id: id("delete_disposable_after_takeover"),
                        disk_id: desired.volumes[0].disk_id.clone(),
                        volume_id: primary.volume_id.clone(),
                        cat_id: desired.cat_id.clone(),
                        desired_revision: desired.desired_revision,
                        placement_epoch: desired.placement.placement_epoch,
                        expected_attachment_id: expected.identity.attachment_id.clone(),
                        expected_epoch: expected.identity.attachment_epoch,
                        expected_head: expected.head.clone(),
                        isolation_basis: DisposableDeleteIsolationBasis::HostFenceEvent {
                            event_id: id("fence_disposable_after_takeover"),
                        },
                        not_after: unix_ms(1_900_000_100_000),
                    };
                    let direct_receipt = BeginDisposableDeleteConsumedReceipt {
                        authorization_id: direct_id.clone(),
                        volume_id: primary.volume_id.clone(),
                        disk_id: desired.volumes[0].disk_id.clone(),
                        cat_id: desired.cat_id.clone(),
                        delete_id: direct_authorization.delete_id.clone(),
                        prior_attachment_id: expected.identity.attachment_id.clone(),
                        resulting_epoch: fence(expected.identity.attachment_epoch.get() + 1),
                        resulting_head: expected.head.clone(),
                        consumed_at: unix_ms(1_900_000_020_000),
                    };
                    let direct = AuthorizationRecord {
                        authorization: VolumeAuthorization::DisposableRootDelete(
                            direct_authorization.clone(),
                        ),
                        state: AuthorizationState::Consumed(Box::new(
                            AuthorizationConsumedReceipt::BeginDisposableDelete(
                                direct_receipt.clone(),
                            ),
                        )),
                    };
                    let mut deleting = primary.clone();
                    deleting.admin_state = VolumeAdminState::Deleting {
                        delete_id: direct_authorization.delete_id,
                    };
                    deleting.lease_owner = None;
                    deleting.lease_epoch = direct_receipt.resulting_epoch;
                    deleting.lease_expires_at = None;
                    deleting.last_transition = Some(LastVolumeTransition::BeginDisposableDelete {
                        authorization_id: direct_id,
                    });
                    signed.current_volume = Some(deleting.clone());
                    signed.direct_successor_authorization = Some(direct);
                    point = Ok(deleting);
                }
                _ => unreachable!(),
            }
            cats_storage::authority::validate_volume_transition_evidence_bundle(
                &signed.authorization,
                signed.current_volume.as_ref(),
                signed.delete_completion.as_ref(),
                signed.direct_successor_authorization.as_ref(),
            )
            .unwrap();
            let signed_for_published = signed.clone();
            let signed_for_mismatch = signed.clone();
            let point_for_published = point.clone();

            let checkpoint = closed_checkpoint(
                &desired,
                ReconcileStep::AcquireVolume {
                    request: VolumeAcquireRequest::Takeover {
                        authorization_id: authorization_id.clone(),
                    },
                },
                vec![prior],
                unix_ms(1_900_000_000_000),
            );
            persist_checkpoint(root.path(), &checkpoint);
            let evidence_state = Arc::new(Mutex::new(EvidenceState {
                outcomes: VecDeque::from([VolumeEvidenceRecovery::Validated {
                    evidence: Box::new(signed),
                    decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptTakeover(
                        match &expected.acquire {
                            AuthorizedServingAcquire::Takeover { receipt, .. } => receipt.clone(),
                            AuthorizedServingAcquire::Normal { .. } => unreachable!(),
                        },
                    )),
                }]),
                ..EvidenceState::default()
            }));
            let evidence_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
                state: Arc::clone(&evidence_state),
            });
            let authority = Arc::new(FakeAuthority::new(point));
            let recovery = SignedRunningPublicationRecovery::new(authority)
                .with_volume_evidence(evidence_port);
            assert_eq!(
                recovery
                    .recover_one(recovery_context(root.path(), &desired))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::ReplanDesired {
                    cat_id: desired.cat_id.clone(),
                },
                "closed delete case {case}",
            );
            assert!(
                !authorized_blockd_data_directory(root.path(), &desired, &expected.identity)
                    .exists(),
                "closed delete case {case} must not recover a local writer",
            );

            let published_root = tempfile::tempdir().unwrap();
            persist_checkpoint(published_root.path(), &checkpoint);
            let published = AuthorizedBlockdStore::new(StateDirectory::unanchored(
                published_root.path().to_path_buf(),
            ))
            .prepare(&desired, &desired.volumes[0], &expected)
            .unwrap();
            let authorized_path = published.data_directory().join("authorized-serving.json");
            let before = std::fs::read(&authorized_path).unwrap();
            drop(published);
            let published_evidence = Arc::new(Mutex::new(EvidenceState {
                outcomes: VecDeque::from([VolumeEvidenceRecovery::Validated {
                    evidence: Box::new(signed_for_published),
                    decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptTakeover(
                        match &expected.acquire {
                            AuthorizedServingAcquire::Takeover { receipt, .. } => receipt.clone(),
                            AuthorizedServingAcquire::Normal { .. } => unreachable!(),
                        },
                    )),
                }]),
                ..EvidenceState::default()
            }));
            let published_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
                state: published_evidence,
            });
            let published_recovery = SignedRunningPublicationRecovery::new(Arc::new(
                FakeAuthority::new(point_for_published),
            ))
            .with_volume_evidence(published_port);
            assert_eq!(
                published_recovery
                    .recover_one(recovery_context(published_root.path(), &desired))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::ReplanDesired {
                    cat_id: desired.cat_id.clone(),
                },
                "published closed delete case {case}",
            );
            assert_eq!(std::fs::read(authorized_path).unwrap(), before);

            if case == "disposable-delete" {
                let mismatch_root = tempfile::tempdir().unwrap();
                persist_checkpoint(mismatch_root.path(), &checkpoint);
                drop(
                    AuthorizedBlockdStore::new(StateDirectory::unanchored(
                        mismatch_root.path().to_path_buf(),
                    ))
                    .prepare(&desired, &desired.volumes[0], &expected)
                    .unwrap(),
                );
                let mismatch_evidence = Arc::new(Mutex::new(EvidenceState {
                    outcomes: VecDeque::from([VolumeEvidenceRecovery::Validated {
                        evidence: Box::new(signed_for_mismatch),
                        decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptTakeover(
                            match &expected.acquire {
                                AuthorizedServingAcquire::Takeover { receipt, .. } => {
                                    receipt.clone()
                                }
                                AuthorizedServingAcquire::Normal { .. } => unreachable!(),
                            },
                        )),
                    }]),
                    ..EvidenceState::default()
                }));
                let mismatch_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
                    state: mismatch_evidence,
                });
                let mismatch = SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(
                    Ok(primary.clone()),
                )))
                .with_volume_evidence(mismatch_port);
                assert_eq!(
                    mismatch
                        .recover_one(recovery_context(mismatch_root.path(), &desired))
                        .unwrap(),
                    RuntimePreScanRecoveryOutcome::NoChange,
                    "signed direct successor cannot replan against a different point read",
                );
            }
        }

        // A direct successor marker is not self-authenticating. The signed
        // bundle must retain the exact consumed direct authorization, and a
        // completion must retain its exact epoch/head tuple.
        let mut desired = desired();
        let authorization_id = id("takeover_recovery_negative");
        desired.volumes[0].acquire = VolumeAcquire::Takeover {
            authorization_id: authorization_id.clone(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let (_, primary, fixture, _) = takeover_recovery_fixture(&desired, 0);
        let VolumeEvidenceRecovery::Validated { evidence, .. } = fixture else {
            unreachable!()
        };
        let mut missing_direct = *evidence;
        missing_direct.current_volume = Some(VolumeRecord {
            last_transition: Some(LastVolumeTransition::BeginDisposableDelete {
                authorization_id: id("missing_direct_authorization"),
            }),
            admin_state: VolumeAdminState::Deleting {
                delete_id: id("missing_direct_delete"),
            },
            lease_owner: None,
            lease_epoch: fence(primary.lease_epoch.get() + 1),
            lease_expires_at: None,
            ..primary.clone()
        });
        assert!(
            cats_storage::authority::validate_volume_transition_evidence_bundle(
                &missing_direct.authorization,
                missing_direct.current_volume.as_ref(),
                None,
                None,
            )
            .is_err()
        );
        let wrong_completion = DeleteCompletionReceipt::Normal {
            request: BeginDeleteRequest {
                delete_id: id("wrong_completion_delete"),
                disk_id: desired.volumes[0].disk_id.clone(),
                volume_id: primary.volume_id.clone(),
                expected_unowned_epoch: fence(primary.lease_epoch.get() + 1),
                expected_head: primary.head.clone(),
            },
            deleting_epoch: fence(primary.lease_epoch.get() + 3),
            deleting_head: primary.head,
            completed_at: unix_ms(1_900_000_090_000),
        };
        assert!(
            cats_storage::authority::validate_volume_transition_evidence_bundle(
                &missing_direct.authorization,
                None,
                Some(&wrong_completion),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn pre_scan_normal_recovery_binds_the_exact_unowned_checkpoint_head() {
        for target in ["root", "persistent-existing"] {
            let mut desired = desired();
            let target_index = if target == "root" {
                0
            } else {
                let mut persistent = normal_persistent_volume();
                persistent.mount.as_mut().unwrap().initialization =
                    cats_api::runtime_reconciliation::FilesystemInitialization::Existing;
                desired.volumes.push(persistent);
                1
            };
            desired.spec_digest = spec_digest(&desired).unwrap();
            let canonical_head = RemoteHead {
                generation: Generation::new(5).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([0x25; 32])),
                root_object_id: Some(
                    AsciiText::new(format!("roots/{target}-normal-predecessor-5")).unwrap(),
                ),
            };
            let mut attachment = normal_attachment(&desired, target_index);
            attachment.head = canonical_head.clone();
            attachment.normal_acquire_mut().unwrap().1.resulting_head = canonical_head.clone();
            let record = owned_record(&desired, &attachment);
            let mut exact_prior = unowned_observed_volume(&desired.volumes[target_index]);
            let VolumeAuthorityEvidence::Unowned { head, .. } = &mut exact_prior.authority else {
                unreachable!("normal predecessor fixture is unowned")
            };
            *head = canonical_head.clone();

            for case in ["exact", "lower-head", "higher-head", "head-tuple"] {
                let root = tempfile::tempdir().unwrap();
                let mut prior = exact_prior.clone();
                if case != "exact" {
                    let VolumeAuthorityEvidence::Unowned { head, .. } = &mut prior.authority else {
                        unreachable!("normal predecessor fixture is unowned")
                    };
                    let (generation, byte, suffix) = match case {
                        "lower-head" => (4, 0x24, "lower"),
                        "higher-head" => (6, 0x26, "higher"),
                        "head-tuple" => (5, 0x27, "foreign-tuple"),
                        _ => unreachable!(),
                    };
                    *head = RemoteHead {
                        generation: Generation::new(generation).unwrap(),
                        root_hash: Some(Sha256Digest::from_bytes([byte; 32])),
                        root_object_id: Some(
                            AsciiText::new(format!("roots/{target}-normal-{suffix}")).unwrap(),
                        ),
                    };
                }
                let volumes = if target_index == 0 {
                    vec![prior]
                } else {
                    vec![unowned_observed_volume(&desired.volumes[0]), prior]
                };
                let checkpoint = closed_checkpoint(
                    &desired,
                    ReconcileStep::AcquireVolume {
                        request: attachment.checkpoint_acquire_request(),
                    },
                    volumes,
                    unix_ms(1_900_000_000_000),
                );
                assert!(multi_acquire_checkpoint_is_bound(
                    &checkpoint,
                    &desired,
                    root.path(),
                ));
                persist_checkpoint(root.path(), &checkpoint);
                let recovery = SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(
                    Ok(record.clone()),
                )));
                let outcome = recovery
                    .recover_one(recovery_context(root.path(), &desired))
                    .unwrap();
                let data_directory =
                    authorized_blockd_data_directory(root.path(), &desired, &attachment.identity);
                if case == "exact" {
                    assert_eq!(
                        outcome,
                        RuntimePreScanRecoveryOutcome::Recovered {
                            cat_id: desired.cat_id.clone(),
                        },
                        "{target} exact Normal predecessor",
                    );
                    assert!(data_directory.is_dir());
                } else {
                    assert_eq!(
                        outcome,
                        RuntimePreScanRecoveryOutcome::NoChange,
                        "{target} Normal predecessor drift case {case}",
                    );
                    assert!(
                        !data_directory.exists(),
                        "{target} Normal predecessor drift case {case} published R0",
                    );
                }
            }
        }
    }

    #[test]
    fn live_multi_normal_rejects_checkpoint_head_drift_before_a22() {
        for case in ["lower-head", "higher-head", "head-tuple"] {
            let root = tempfile::tempdir().unwrap();
            let mut desired = desired();
            let mut persistent = normal_persistent_volume();
            persistent.mount.as_mut().unwrap().initialization =
                cats_api::runtime_reconciliation::FilesystemInitialization::Existing;
            desired.volumes.push(persistent);
            desired.spec_digest = spec_digest(&desired).unwrap();
            let target = &desired.volumes[1];
            let canonical_head = RemoteHead {
                generation: Generation::new(5).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([0x35; 32])),
                root_object_id: Some(AsciiText::new("roots/live-normal-predecessor-5").unwrap()),
            };
            let mut attachment = normal_attachment(&desired, 1);
            attachment.head = canonical_head.clone();
            attachment.normal_acquire_mut().unwrap().1.resulting_head = canonical_head.clone();
            let mut exact_current = unowned_observed_volume(target);
            let VolumeAuthorityEvidence::Unowned { head, .. } = &mut exact_current.authority else {
                unreachable!("normal predecessor fixture is unowned")
            };
            *head = canonical_head;
            let mut wrong = exact_current.clone();
            let VolumeAuthorityEvidence::Unowned { head, .. } = &mut wrong.authority else {
                unreachable!("normal predecessor fixture is unowned")
            };
            let (generation, byte, suffix) = match case {
                "lower-head" => (4, 0x34, "lower"),
                "higher-head" => (6, 0x36, "higher"),
                "head-tuple" => (5, 0x37, "foreign-tuple"),
                _ => unreachable!(),
            };
            *head = RemoteHead {
                generation: Generation::new(generation).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([byte; 32])),
                root_object_id: Some(
                    AsciiText::new(format!("roots/live-normal-{suffix}")).unwrap(),
                ),
            };
            let checkpoint = closed_checkpoint(
                &desired,
                ReconcileStep::AcquireVolume {
                    request: attachment.checkpoint_acquire_request(),
                },
                vec![unowned_observed_volume(&desired.volumes[0]), wrong],
                unix_ms(1_900_000_000_000),
            );
            assert!(multi_acquire_checkpoint_is_bound(
                &checkpoint,
                &desired,
                root.path(),
            ));
            persist_checkpoint(root.path(), &checkpoint);
            let runtime = observed_runtime_with_volumes(
                root.path(),
                &desired,
                Some(&checkpoint),
                vec![unowned_observed_volume(&desired.volumes[0]), exact_current],
            );
            let path = checkpoint_path(root.path(), &desired.cat_id);
            let (effect, acquire, _) = production_effect(
                &desired,
                vec![NormalAcquireAttempt::Granted(Box::new(attachment.clone()))],
                Vec::new(),
                Vec::new(),
                Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown))),
                Arc::new(RecordingBlob::missing()),
                path,
            );
            let (context, _) = context(root.path(), &desired, Some(runtime));
            assert_eq!(
                effect.apply(context, &desired).unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory,
                "live multi Normal predecessor drift case {case}",
            );
            assert!(
                acquire.lock().unwrap().requests.is_empty(),
                "live multi Normal predecessor drift case {case} reached A22",
            );
            assert!(
                !authorized_blockd_data_directory(root.path(), &desired, &attachment.identity)
                    .exists(),
                "live multi Normal predecessor drift case {case} published R0",
            );
            assert_eq!(
                read_checkpoint(&checkpoint_path(root.path(), &desired.cat_id)),
                checkpoint
            );
        }
    }

    #[test]
    fn live_multi_takeover_rejects_checkpoint_predecessor_drift_before_a22() {
        for target in ["root", "persistent-existing"] {
            let mut desired = desired();
            desired.volumes.push(normal_persistent_volume());
            let target_index = usize::from(target == "persistent-existing");
            let authorization_id = if target_index == 0 {
                id("takeover_live_predecessor_root")
            } else {
                id("takeover_live_predecessor_persistent")
            };
            desired.volumes[target_index].acquire = VolumeAcquire::Takeover {
                authorization_id: authorization_id.clone(),
            };
            desired.spec_digest = spec_digest(&desired).unwrap();
            let (mut attachment, mut record, mut evidence, mut exact_current) =
                takeover_recovery_fixture(&desired, target_index);
            if target_index == 1 {
                desired.volumes[target_index]
                    .mount
                    .as_mut()
                    .unwrap()
                    .initialization =
                    cats_api::runtime_reconciliation::FilesystemInitialization::Existing;
                desired.spec_digest = spec_digest(&desired).unwrap();
            }
            let canonical_head = RemoteHead {
                generation: Generation::new(5).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([0x45; 32])),
                root_object_id: Some(
                    AsciiText::new(format!("roots/live-takeover-{target}-5")).unwrap(),
                ),
            };
            set_takeover_recovery_fixture_head(
                &mut attachment,
                &mut record,
                &mut evidence,
                &mut exact_current,
                canonical_head,
            );

            for case in ["owner", "epoch", "lower-head", "higher-head", "head-tuple"] {
                let root = tempfile::tempdir().unwrap();
                let mut wrong = exact_current.clone();
                let VolumeAuthorityEvidence::Owned {
                    attachment_id,
                    attachment_epoch,
                    head,
                } = &mut wrong.authority
                else {
                    unreachable!("takeover predecessor fixture is owned")
                };
                match case {
                    "owner" => *attachment_id = id("att_live_takeover_foreign"),
                    "epoch" => *attachment_epoch = fence(attachment_epoch.get() + 1),
                    "lower-head" | "higher-head" | "head-tuple" => {
                        let (generation, byte, suffix) = match case {
                            "lower-head" => (4, 0x44, "lower"),
                            "higher-head" => (6, 0x46, "higher"),
                            "head-tuple" => (5, 0x47, "foreign-tuple"),
                            _ => unreachable!(),
                        };
                        *head = RemoteHead {
                            generation: Generation::new(generation).unwrap(),
                            root_hash: Some(Sha256Digest::from_bytes([byte; 32])),
                            root_object_id: Some(
                                AsciiText::new(format!("roots/live-takeover-{target}-{suffix}"))
                                    .unwrap(),
                            ),
                        };
                    }
                    _ => unreachable!(),
                }
                let other_index = usize::from(target_index == 0);
                let checkpoint_volumes = if target_index == 0 {
                    vec![
                        wrong,
                        unowned_observed_volume(&desired.volumes[other_index]),
                    ]
                } else {
                    vec![
                        unowned_observed_volume(&desired.volumes[other_index]),
                        wrong,
                    ]
                };
                let checkpoint = closed_checkpoint(
                    &desired,
                    ReconcileStep::AcquireVolume {
                        request: VolumeAcquireRequest::Takeover {
                            authorization_id: authorization_id.clone(),
                        },
                    },
                    checkpoint_volumes,
                    unix_ms(1_900_000_000_000),
                );
                assert!(multi_acquire_checkpoint_is_bound(
                    &checkpoint,
                    &desired,
                    root.path(),
                ));
                persist_checkpoint(root.path(), &checkpoint);
                let current_volumes = if target_index == 0 {
                    vec![
                        exact_current.clone(),
                        unowned_observed_volume(&desired.volumes[other_index]),
                    ]
                } else {
                    vec![
                        unowned_observed_volume(&desired.volumes[other_index]),
                        exact_current.clone(),
                    ]
                };
                let runtime = observed_runtime_with_volumes(
                    root.path(),
                    &desired,
                    Some(&checkpoint),
                    current_volumes,
                );
                let grant = VolumeLeaseGrant {
                    volume_id: attachment.identity.volume_id.clone(),
                    attachment_id: attachment.identity.attachment_id.clone(),
                    attachment_epoch: attachment.identity.attachment_epoch,
                    size_bytes: attachment.size_bytes,
                    durability: attachment.durability,
                    head: attachment.head.clone(),
                    lease_expires_at: attachment.lease_expires_at,
                    acquire_origin: attachment.identity.acquire_origin.clone(),
                };
                let path = checkpoint_path(root.path(), &desired.cat_id);
                let (effect, acquire, evidence_calls) = production_effect(
                    &desired,
                    Vec::new(),
                    vec![TakeoverAcquireAttempt::LeaseGranted(grant)],
                    vec![evidence.clone()],
                    Arc::new(FakeAuthority::new(Err(AuthorityError::BackendUnknown))),
                    Arc::new(RecordingBlob::missing()),
                    path,
                );
                let (context, _) = context(root.path(), &desired, Some(runtime));
                assert_eq!(
                    effect.apply(context, &desired).unwrap(),
                    RuntimeDesiredEffectOutcome::RefreshInventory,
                    "live Takeover {target} predecessor drift case {case}",
                );
                assert!(
                    acquire.lock().unwrap().requests.is_empty(),
                    "live Takeover {target} predecessor drift case {case} reached A22",
                );
                assert_eq!(evidence_calls.lock().unwrap().requests.len(), 1);
                assert!(
                    !authorized_blockd_data_directory(root.path(), &desired, &attachment.identity,)
                        .exists(),
                    "live Takeover {target} predecessor drift case {case} published R0",
                );
                assert_eq!(
                    read_checkpoint(&checkpoint_path(root.path(), &desired.cat_id)),
                    checkpoint,
                );
            }
        }
    }

    #[test]
    fn live_multi_takeover_recovers_consumed_response_loss_without_replaying_a22() {
        let root = tempfile::tempdir().unwrap();
        let mut desired = desired();
        desired.volumes.push(normal_persistent_volume());
        let authorization_id = id("takeover_live_response_loss");
        desired.volumes[1].acquire = VolumeAcquire::Takeover {
            authorization_id: authorization_id.clone(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let (target, current, evidence, prior) = takeover_recovery_fixture(&desired, 1);

        let root_attachment = normal_attachment(&desired, 0);
        let root_directory =
            authorized_blockd_data_directory(root.path(), &desired, &root_attachment.identity);
        drop(
            AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                .prepare(&desired, &desired.volumes[0], &root_attachment)
                .unwrap(),
        );
        let root_observed = prepared_owned_observed_volume(
            &desired.volumes[0],
            &root_attachment,
            host(root_directory),
        );
        let checkpoint = closed_checkpoint(
            &desired,
            ReconcileStep::AcquireVolume {
                request: VolumeAcquireRequest::Takeover { authorization_id },
            },
            vec![root_observed.clone(), prior],
            unix_ms(1_900_000_000_000),
        );
        assert!(multi_acquire_checkpoint_is_bound(
            &checkpoint,
            &desired,
            root.path(),
        ));
        persist_checkpoint(root.path(), &checkpoint);
        let accepted_current = owned_observed_volume(&desired.volumes[1], &target);
        let runtime = observed_runtime_with_volumes(
            root.path(),
            &desired,
            Some(&checkpoint),
            vec![root_observed, accepted_current],
        );
        let path = checkpoint_path(root.path(), &desired.cat_id);
        let (effect, acquire, evidence_calls) = production_effect(
            &desired,
            Vec::new(),
            vec![TakeoverAcquireAttempt::StopForLocalContract],
            vec![evidence],
            Arc::new(FakeAuthority::new(Ok(current))),
            Arc::new(RecordingBlob::present(&desired)),
            path.clone(),
        );
        let (context, _) = context(root.path(), &desired, Some(runtime));
        assert_eq!(
            effect.apply(context, &desired).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory,
        );
        assert!(
            acquire.lock().unwrap().requests.is_empty(),
            "a consumed response-loss recovery replayed A22",
        );
        assert_eq!(evidence_calls.lock().unwrap().requests.len(), 1);
        assert!(authorized_blockd_data_directory(root.path(), &desired, &target.identity).is_dir(),);
        assert!(matches!(
            read_checkpoint(&path).step,
            ReconcileStep::ProvisionRootImage { .. }
        ));
    }

    #[test]
    fn pre_scan_takeover_recovery_binds_the_exact_checkpoint_predecessor() {
        for target in ["root", "persistent-existing"] {
            let mut desired = desired();
            let target_index = if target == "root" {
                0
            } else {
                desired.volumes.push(normal_persistent_volume());
                1
            };
            let authorization_id = if target == "root" {
                id("takeover_recovery_root_predecessor")
            } else {
                id("takeover_recovery_persistent_predecessor")
            };
            desired.volumes[target_index].acquire = VolumeAcquire::Takeover {
                authorization_id: authorization_id.clone(),
            };
            desired.spec_digest = spec_digest(&desired).unwrap();
            let (mut expected, mut record, mut evidence, mut prior) =
                takeover_recovery_fixture(&desired, target_index);
            if target == "persistent-existing" {
                desired.volumes[target_index]
                    .mount
                    .as_mut()
                    .unwrap()
                    .initialization =
                    cats_api::runtime_reconciliation::FilesystemInitialization::Existing;
                desired.spec_digest = spec_digest(&desired).unwrap();
            }
            let canonical_head = RemoteHead {
                generation: Generation::new(5).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([5; 32])),
                root_object_id: Some(
                    AsciiText::new(format!("roots/{target}-predecessor-5")).unwrap(),
                ),
            };
            set_takeover_recovery_fixture_head(
                &mut expected,
                &mut record,
                &mut evidence,
                &mut prior,
                canonical_head,
            );

            for case in ["owner", "epoch", "lower-head", "higher-head", "head-tuple"] {
                let root = tempfile::tempdir().unwrap();
                let mut wrong = prior.clone();
                let VolumeAuthorityEvidence::Owned {
                    attachment_id,
                    attachment_epoch,
                    head,
                } = &mut wrong.authority
                else {
                    unreachable!("fixture predecessor is owned")
                };
                match case {
                    "owner" => *attachment_id = id("att_foreign_predecessor"),
                    "epoch" => *attachment_epoch = fence(attachment_epoch.get() + 1),
                    "lower-head" | "higher-head" | "head-tuple" => {
                        let (generation, byte, suffix) = match case {
                            "lower-head" => (4, 4, "lower"),
                            "higher-head" => (6, 6, "higher"),
                            "head-tuple" => (5, 7, "foreign-tuple"),
                            _ => unreachable!(),
                        };
                        *head = RemoteHead {
                            generation: Generation::new(generation).unwrap(),
                            root_hash: Some(Sha256Digest::from_bytes([byte; 32])),
                            root_object_id: Some(
                                AsciiText::new(format!("roots/{target}-{suffix}")).unwrap(),
                            ),
                        };
                    }
                    _ => unreachable!(),
                }
                let volumes = if target_index == 0 {
                    vec![wrong]
                } else {
                    vec![unowned_observed_volume(&desired.volumes[0]), wrong]
                };
                let checkpoint = closed_checkpoint(
                    &desired,
                    ReconcileStep::AcquireVolume {
                        request: VolumeAcquireRequest::Takeover {
                            authorization_id: authorization_id.clone(),
                        },
                    },
                    volumes,
                    unix_ms(1_900_000_000_000),
                );
                assert!(multi_acquire_checkpoint_is_bound(
                    &checkpoint,
                    &desired,
                    root.path(),
                ));
                persist_checkpoint(root.path(), &checkpoint);
                let evidence_state = Arc::new(Mutex::new(EvidenceState {
                    outcomes: VecDeque::from([evidence.clone()]),
                    ..EvidenceState::default()
                }));
                let evidence_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
                    state: Arc::clone(&evidence_state),
                });
                let recovery = SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(
                    Ok(record.clone()),
                )))
                .with_volume_evidence(evidence_port);
                assert_eq!(
                    recovery
                        .recover_one(recovery_context(root.path(), &desired))
                        .unwrap(),
                    RuntimePreScanRecoveryOutcome::NoChange,
                    "{target} checkpoint predecessor drift case {case}",
                );
                assert_eq!(evidence_state.lock().unwrap().requests.len(), 1);
                assert!(
                    !authorized_blockd_data_directory(root.path(), &desired, &expected.identity)
                        .exists(),
                    "{target} checkpoint predecessor drift case {case} published a grant",
                );
            }
        }
    }

    #[test]
    fn pre_scan_takeover_recovery_revalidates_checkpoint_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let mut desired = desired();
        let authorization_id = id("takeover_recovery_checkpoint_drift");
        desired.volumes[0].acquire = VolumeAcquire::Takeover {
            authorization_id: authorization_id.clone(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let (expected, record, evidence, prior) = takeover_recovery_fixture(&desired, 0);
        let checkpoint = closed_checkpoint(
            &desired,
            ReconcileStep::AcquireVolume {
                request: VolumeAcquireRequest::Takeover {
                    authorization_id: authorization_id.clone(),
                },
            },
            vec![prior],
            unix_ms(1_900_000_000_000),
        );
        persist_checkpoint(root.path(), &checkpoint);

        let mut successor = checkpoint.clone();
        successor.updated_at_unix_ms = unix_ms(1_900_000_000_001);
        let successor = encode_runtime_checkpoint(&successor).unwrap();
        let checkpoint_path = checkpoint_path(root.path(), &desired.cat_id);
        let after_call: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            std::fs::write(&checkpoint_path, &successor).unwrap();
        });
        let evidence_state = Arc::new(Mutex::new(EvidenceState {
            outcomes: VecDeque::from([evidence]),
            after_call: Some(after_call),
            ..EvidenceState::default()
        }));
        let evidence_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
            state: Arc::clone(&evidence_state),
        });
        let recovery =
            SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(Ok(record))))
                .with_volume_evidence(evidence_port);
        let error = recovery
            .recover_one(recovery_context(root.path(), &desired))
            .unwrap_err();
        assert!(format!("{error:#}").contains("before local mutation"));
        assert!(
            !authorized_blockd_data_directory(root.path(), &desired, &expected.identity).exists(),
            "checkpoint drift published a local takeover grant",
        );
    }

    #[test]
    fn pre_scan_takeover_recovery_never_adopts_another_cats_signed_evidence() {
        let root = tempfile::tempdir().unwrap();
        let mut first = desired();
        let first_authorization = id("takeover_recovery_first_cat");
        first.volumes[0].acquire = VolumeAcquire::Takeover {
            authorization_id: first_authorization.clone(),
        };
        first.spec_digest = spec_digest(&first).unwrap();
        let (expected, record, _, prior) = takeover_recovery_fixture(&first, 0);
        let checkpoint = closed_checkpoint(
            &first,
            ReconcileStep::AcquireVolume {
                request: VolumeAcquireRequest::Takeover {
                    authorization_id: first_authorization.clone(),
                },
            },
            vec![prior],
            unix_ms(1_900_000_000_000),
        );
        persist_checkpoint(root.path(), &checkpoint);

        let mut second = second_desired();
        second.volumes[0].acquire = VolumeAcquire::Takeover {
            authorization_id: id("takeover_recovery_second_cat"),
        };
        second.spec_digest = spec_digest(&second).unwrap();
        let (_, _, foreign_evidence, _) = takeover_recovery_fixture(&second, 0);
        let evidence_state = Arc::new(Mutex::new(EvidenceState {
            outcomes: VecDeque::from([foreign_evidence]),
            ..EvidenceState::default()
        }));
        let evidence_port: Arc<dyn SignedVolumeEvidencePort> = Arc::new(FakeEvidence {
            state: Arc::clone(&evidence_state),
        });
        let recovery =
            SignedRunningPublicationRecovery::new(Arc::new(FakeAuthority::new(Ok(record))))
                .with_volume_evidence(evidence_port);
        assert_eq!(
            recovery
                .recover_one(recovery_context_with_desireds(
                    root.path(),
                    vec![first.clone(), second],
                ))
                .unwrap(),
            RuntimePreScanRecoveryOutcome::NoChange,
        );
        assert_eq!(evidence_state.lock().unwrap().requests.len(), 1);
        assert!(
            !authorized_blockd_data_directory(root.path(), &first, &expected.identity,).exists()
        );
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
            let (effect, calls, evidence_calls) = production_effect(
                &current,
                Vec::new(),
                Vec::new(),
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
            assert!(evidence_calls.lock().unwrap().requests.is_empty());
            assert_eq!(blob.reads.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn superseded_acquire_with_nonblank_old_unowned_head_stops_conditionless() {
        let root = tempfile::tempdir().unwrap();
        let old = desired();
        let mut old_checkpoint = acquire_checkpoint_from_attachment(&old, &attachment(&old));
        let VolumeAuthorityEvidence::Unowned { head, .. } =
            &mut old_checkpoint.volumes[0].authority
        else {
            unreachable!()
        };
        *head = RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([4; 32])),
            root_object_id: Some(AsciiText::new("maps/nonblank-old-head").unwrap()),
        };
        persist_checkpoint(root.path(), &old_checkpoint);

        let mut current = old;
        current.desired_revision = Revision::new(2).unwrap();
        current.runtime.memory_bytes += 4096;
        current.spec_digest = spec_digest(&current).unwrap();
        let authority = Arc::new(FakeAuthority::new(Ok(unowned_record(&current))));
        let scanned = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        assert!(matches!(scanned.step, ReconcileStep::AcquireVolume { .. }));
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
        let (effect, calls, evidence_calls) = production_effect(
            &current,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            authority.clone(),
            blob,
            path.clone(),
        );
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
        assert!(evidence_calls.lock().unwrap().requests.is_empty());
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
            let (planner, calls, evidence_calls) = production_effect(
                &current,
                Vec::new(),
                Vec::new(),
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
            assert!(evidence_calls.lock().unwrap().requests.is_empty());
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
        let (planner, release_calls, evidence_calls) = production_effect_with_release(
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
        assert!(evidence_calls.lock().unwrap().requests.is_empty());
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
                NormalReleaseAttempt::DefiniteCleanupConflict(
                    RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
                ),
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

        let scan = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        let (context, _) =
            context_with_session(root.path(), &current, Some(scan), '8', 3, 1_900_000_020_000);
        assert_eq!(
            planner.apply(context, &current).unwrap(),
            RuntimeDesiredEffectOutcome::RefreshInventory
        );
        assert_eq!(std::fs::read(&path).unwrap(), cleanup_bytes);
        assert_eq!(calls.lock().unwrap().release_requests.len(), 1);

        let marker = super::super::checkpoint::release_rejection_path(
            &root.path().join(CHECKPOINT_NAMESPACE),
            &current.cat_id,
        );
        assert!(marker.exists());
        let closed = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
        assert!(closed.conditions.is_empty());

        // A fresh effect instance models Agent restart: no process-memory
        // dedup state is available, but the exact durable marker still blocks
        // the checkpointed release.
        let (restart, restart_calls) = effect_with_release(
            &current,
            vec![NormalReleaseAttempt::Released(
                cats_api::runtime_reconciliation::ReleaseResult {
                    volume_id: current.volumes[0].volume_id.clone(),
                    transition_id: random('7'),
                    released_attachment_id: current.volumes[0].attachment_id.clone(),
                    resulting_epoch: fence(2),
                    resulting_head: expected_provisioned_head.clone(),
                },
            )],
            authority,
            Arc::new(RecordingBlob::present_with_chunk(&current, '4')),
            path.clone(),
        );
        let (restart_context, _) = context_with_session(
            root.path(),
            &current,
            Some(closed),
            '8',
            3,
            1_900_000_030_000,
        );
        assert_eq!(
            restart.apply(restart_context, &current).unwrap(),
            stop_local()
        );
        assert!(restart_calls.lock().unwrap().release_requests.is_empty());
        assert_eq!(std::fs::read(path).unwrap(), cleanup_bytes);
    }

    #[test]
    fn definite_cleanup_rejection_publication_windows_recover_after_restart() {
        for window in ["target", "temp", "linked"] {
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
                vec![NormalReleaseAttempt::DefiniteCleanupConflict(
                    RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict,
                )],
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
                RuntimeDesiredEffectOutcome::RefreshInventory,
                "{window}"
            );
            let ready = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
            let (ready_context, _) = context_with_session(
                root.path(),
                &current,
                Some(ready),
                '8',
                3,
                1_900_000_020_000,
            );
            assert_eq!(
                planner.apply(ready_context, &current).unwrap(),
                RuntimeDesiredEffectOutcome::RefreshInventory,
                "{window}"
            );
            assert_eq!(calls.lock().unwrap().release_requests.len(), 1, "{window}");

            let checkpoint_directory = root.path().join(CHECKPOINT_NAMESPACE);
            let marker = super::super::checkpoint::release_rejection_path(
                &checkpoint_directory,
                &current.cat_id,
            );
            let temporary = super::super::checkpoint::release_rejection_temporary_path(
                &checkpoint_directory,
                &current.cat_id,
            );
            match window {
                "target" => {}
                "temp" => std::fs::rename(&marker, &temporary).unwrap(),
                "linked" => std::fs::hard_link(&marker, &temporary).unwrap(),
                _ => unreachable!(),
            }

            let recovery = SignedRunningPublicationRecovery::new(authority.clone());
            let outcome = recovery
                .recover_one(recovery_context(root.path(), &current))
                .unwrap();
            match window {
                "target" => assert_eq!(outcome, RuntimePreScanRecoveryOutcome::NoChange),
                "temp" | "linked" => assert!(matches!(
                    outcome,
                    RuntimePreScanRecoveryOutcome::Recovered { ref cat_id }
                        if cat_id == &current.cat_id
                )),
                _ => unreachable!(),
            }
            assert!(marker.exists(), "{window}");
            assert!(!temporary.exists(), "{window}");
            let second_restart = SignedRunningPublicationRecovery::new(authority.clone());
            assert_eq!(
                second_restart
                    .recover_one(recovery_context(root.path(), &current))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange,
                "second restart did not confirm the target-only durability barrier: {window}"
            );

            let closed = scan_runtime(root.path(), &current, authority.clone(), '8', 3);
            assert!(closed.conditions.is_empty(), "{window}");
            let (restart, restart_calls) = effect_with_release(
                &current,
                vec![NormalReleaseAttempt::RetryExact],
                authority,
                Arc::new(RecordingBlob::present_with_chunk(&current, '4')),
                path,
            );
            let (restart_context, _) = context_with_session(
                root.path(),
                &current,
                Some(closed),
                '8',
                3,
                1_900_000_030_000,
            );
            assert_eq!(
                restart.apply(restart_context, &current).unwrap(),
                stop_local(),
                "{window}"
            );
            assert!(
                restart_calls.lock().unwrap().release_requests.is_empty(),
                "{window}"
            );
        }
    }

    #[test]
    fn unsynced_release_rejection_temp_is_durable_before_recovery_links_it() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let (authority, marker_path, temporary_path) = persist_release_rejection_fixture(
            root.path(),
            &desired,
            RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
        );
        let canonical = std::fs::read(&marker_path).unwrap();
        let marker =
            super::super::checkpoint::decode_definite_release_rejection(&canonical, &marker_path)
                .unwrap();
        let directory = root.path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&directory, &desired.cat_id).unwrap();
        let stored = store.load().unwrap().unwrap();
        std::fs::remove_file(&marker_path).unwrap();
        std::fs::File::open(&directory).unwrap().sync_all().unwrap();
        store.inject_release_rejection_crash_once(
            super::super::checkpoint::ReleaseRejectionWriteStage::BeforeTempFileSync,
        );
        assert!(matches!(
            store.persist_definite_release_rejection(&stored, &marker.request, marker.problem,),
            Err(super::super::CheckpointStoreError::InjectedCrash)
        ));
        drop(store);
        assert!(!marker_path.exists());
        assert_eq!(std::fs::read(&temporary_path).unwrap(), canonical);

        // A fresh recovery instance represents the process which inherited a
        // write-complete but never-fsynced temp from its predecessor.
        let recovery = SignedRunningPublicationRecovery::new(authority.clone());
        assert_eq!(
            recovery
                .recover_one(recovery_context(root.path(), &desired))
                .unwrap(),
            RuntimePreScanRecoveryOutcome::Recovered {
                cat_id: desired.cat_id.clone()
            }
        );
        assert!(!temporary_path.exists());
        assert_eq!(std::fs::read(&marker_path).unwrap(), canonical);

        // Reopen from another fresh owner after the recovered directory
        // barriers. The only visible target remains canonical and exact.
        let reopened = FileCheckpointStore::open(&directory, &desired.cat_id).unwrap();
        let reopened_checkpoint = reopened.load().unwrap().unwrap();
        assert_eq!(
            reopened
                .load_definite_release_rejection(&reopened_checkpoint)
                .unwrap(),
            Some(marker.clone())
        );
        drop(reopened);
        assert_eq!(
            SignedRunningPublicationRecovery::new(authority.clone())
                .recover_one(recovery_context(root.path(), &desired))
                .unwrap(),
            RuntimePreScanRecoveryOutcome::NoChange
        );

        let attachment = attachment(&desired);
        drop(
            AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                .prepare(&desired, &desired.volumes[0], &attachment)
                .unwrap(),
        );
        let closed = scan_runtime(root.path(), &desired, authority, '8', 3);
        assert!(closed.conditions.is_empty());
    }

    #[test]
    fn node_wide_unstable_publications_precede_stable_rejection_confirmation() {
        for unstable in ["checkpoint", "release-rejection", "authorized-blockd"] {
            let root = tempfile::tempdir().unwrap();
            let stable = desired();
            let other = second_desired();
            let stable_attachment = attachment(&stable);
            let other_attachment = attachment(&other);
            let (authority, stable_marker, _) = persist_release_rejection_fixture(
                root.path(),
                &stable,
                RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
            );
            drop(
                AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().to_path_buf()))
                    .prepare(&stable, &stable.volumes[0], &stable_attachment)
                    .unwrap(),
            );

            let checkpoint_directory = root.path().join(CHECKPOINT_NAMESPACE);
            let other_checkpoint_temp =
                checkpoint_directory.join(format!(".cat-{}.checkpoint.tmp", other.cat_id));
            let other_data =
                authorized_blockd_data_directory(root.path(), &other, &other_attachment.identity);
            let other_rejection = super::super::checkpoint::release_rejection_path(
                &checkpoint_directory,
                &other.cat_id,
            );
            let other_rejection_temp = super::super::checkpoint::release_rejection_temporary_path(
                &checkpoint_directory,
                &other.cat_id,
            );
            match unstable {
                "checkpoint" => {
                    std::fs::write(&other_checkpoint_temp, b"interrupted checkpoint").unwrap();
                    std::fs::set_permissions(
                        &other_checkpoint_temp,
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
                "release-rejection" => {
                    let _ = persist_release_rejection_fixture(
                        root.path(),
                        &other,
                        RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict,
                    );
                    drop(
                        AuthorizedBlockdStore::new(StateDirectory::unanchored(
                            root.path().to_path_buf(),
                        ))
                        .prepare(&other, &other.volumes[0], &other_attachment)
                        .unwrap(),
                    );
                    std::fs::rename(&other_rejection, &other_rejection_temp).unwrap();
                }
                "authorized-blockd" => {
                    persist_acquire_checkpoint(root.path(), &other);
                    drop(
                        AuthorizedBlockdStore::new(StateDirectory::unanchored(
                            root.path().to_path_buf(),
                        ))
                        .prepare(&other, &other.volumes[0], &other_attachment)
                        .unwrap(),
                    );
                    shape_publication_window(&other_data, PublicationWindow::IdentityTemp);
                }
                _ => unreachable!(),
            }
            authority.set_records(BTreeMap::from([
                (
                    stable.volumes[0].volume_id.clone(),
                    Ok(owned_record(&stable, &stable_attachment)),
                ),
                (
                    other.volumes[0].volume_id.clone(),
                    if unstable == "checkpoint" {
                        Ok(unowned_record(&other))
                    } else {
                        Ok(owned_record(&other, &other_attachment))
                    },
                ),
            ]));

            let stable_before = std::fs::read(&stable_marker).unwrap();
            let stable_identity_before = std::fs::metadata(&stable_marker).unwrap();
            let desireds = vec![stable.clone(), other.clone()];
            assert_eq!(
                SignedRunningPublicationRecovery::new(authority.clone())
                    .recover_one(recovery_context_with_desireds(
                        root.path(),
                        desireds.clone(),
                    ))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered {
                    cat_id: other.cat_id.clone()
                },
                "{unstable} did not run before the stable target"
            );
            assert_eq!(std::fs::read(&stable_marker).unwrap(), stable_before);
            let stable_identity_after = std::fs::metadata(&stable_marker).unwrap();
            assert_eq!(stable_identity_after.dev(), stable_identity_before.dev());
            assert_eq!(stable_identity_after.ino(), stable_identity_before.ino());
            assert_eq!(
                stable_identity_after.nlink(),
                stable_identity_before.nlink()
            );
            match unstable {
                "checkpoint" => assert!(!other_checkpoint_temp.exists()),
                "release-rejection" => {
                    assert!(other_rejection.exists());
                    assert!(!other_rejection_temp.exists());
                }
                "authorized-blockd" => {
                    assert_eq!(prepared_file_snapshot(&other_data).len(), 3)
                }
                _ => unreachable!(),
            }

            assert_eq!(
                SignedRunningPublicationRecovery::new(authority.clone())
                    .recover_one(recovery_context_with_desireds(
                        root.path(),
                        desireds.clone(),
                    ))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange,
                "{unstable} did not leave stable target confirmation for the next round"
            );
            let scanner = fresh_scanner_with_blob(
                root.path(),
                authority,
                Arc::new(RecordingBlob::present(&stable)),
            );
            let RuntimeInventoryScanOutcome::Complete(inventory) = scanner
                .scan_complete(scan_context_with_desireds(desireds))
                .unwrap()
            else {
                panic!("{unstable} did not converge to a complete full scan")
            };
            let stable_runtime = inventory
                .runtimes()
                .iter()
                .find(|runtime| runtime.cat_id == stable.cat_id)
                .unwrap();
            assert!(stable_runtime.conditions.is_empty(), "{unstable}");
        }
    }

    #[test]
    fn invalid_release_rejection_residue_is_preserved_and_never_recovered() {
        for residue in [
            "corrupt-target",
            "noncanonical-target",
            "oversized-target",
            "partial-temp",
            "foreign",
            "checkpoint-aba",
            "request-mismatch",
            "target-with-checkpoint-temp",
            "exact-temp-with-checkpoint-temp",
        ] {
            let root = tempfile::tempdir().unwrap();
            let desired = desired();
            let (authority, marker, temporary) = persist_release_rejection_fixture(
                root.path(),
                &desired,
                RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
            );
            match residue {
                "corrupt-target" => std::fs::write(&marker, b"{").unwrap(),
                "noncanonical-target" => {
                    let mut bytes = std::fs::read(&marker).unwrap();
                    bytes.push(b'\n');
                    std::fs::write(&marker, bytes).unwrap();
                }
                "oversized-target" => std::fs::write(
                    &marker,
                    vec![b'x'; super::super::checkpoint::RELEASE_REJECTION_MAX_BYTES + 1],
                )
                .unwrap(),
                "partial-temp" => {
                    std::fs::write(&temporary, b"{").unwrap();
                    std::fs::set_permissions(
                        &temporary,
                        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(
                            0o600,
                        ),
                    )
                    .unwrap();
                }
                "foreign" => {
                    let foreign = marker.with_file_name("cat-foreign.release-rejection.json");
                    std::fs::rename(&marker, foreign).unwrap();
                }
                "checkpoint-aba" => {
                    let directory = root.path().join(CHECKPOINT_NAMESPACE);
                    let store = FileCheckpointStore::open(&directory, &desired.cat_id).unwrap();
                    let stored = store.load().unwrap().unwrap();
                    let mut replacement = stored.checkpoint().clone();
                    replacement.updated_at_unix_ms = unix_ms(1_900_000_099_000);
                    store.replace(&stored, &replacement).unwrap();
                }
                "request-mismatch" => {
                    let mut rejection =
                        super::super::checkpoint::decode_definite_release_rejection(
                            &std::fs::read(&marker).unwrap(),
                            &marker,
                        )
                        .unwrap();
                    let RuntimeVolumeTransition::Release { cleanup } =
                        &mut rejection.request.transition
                    else {
                        unreachable!()
                    };
                    cleanup
                        .volume_release
                        .as_mut()
                        .unwrap()
                        .release_transition_id = random('9');
                    std::fs::write(&marker, serde_json::to_vec(&rejection).unwrap()).unwrap();
                }
                "target-with-checkpoint-temp" => {
                    let checkpoint_temp = root
                        .path()
                        .join(CHECKPOINT_NAMESPACE)
                        .join(format!(".cat-{}.checkpoint.tmp", desired.cat_id));
                    std::fs::write(&checkpoint_temp, b"partial checkpoint").unwrap();
                    std::fs::set_permissions(
                        &checkpoint_temp,
                        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(
                            0o600,
                        ),
                    )
                    .unwrap();
                }
                "exact-temp-with-checkpoint-temp" => {
                    std::fs::rename(&marker, &temporary).unwrap();
                    let checkpoint_temp = root
                        .path()
                        .join(CHECKPOINT_NAMESPACE)
                        .join(format!(".cat-{}.checkpoint.tmp", desired.cat_id));
                    std::fs::write(&checkpoint_temp, b"partial checkpoint").unwrap();
                    std::fs::set_permissions(
                        &checkpoint_temp,
                        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(
                            0o600,
                        ),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let checkpoint_directory = root.path().join(CHECKPOINT_NAMESPACE);
            let before = directory_file_snapshot(&checkpoint_directory);
            let recovery = SignedRunningPublicationRecovery::new(authority.clone());
            assert_eq!(
                recovery
                    .recover_one(recovery_context(root.path(), &desired))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange,
                "{residue}"
            );
            assert_eq!(
                directory_file_snapshot(&checkpoint_directory),
                before,
                "{residue}"
            );

            let scanner = fresh_scanner_with_blob(
                root.path(),
                authority,
                Arc::new(RecordingBlob::present(&desired)),
            );
            let scan = scanner.scan_complete(scan_context(&desired));
            assert!(
                scan.is_err() || matches!(scan, Ok(RuntimeInventoryScanOutcome::Incomplete { .. })),
                "{residue} unexpectedly admitted a complete inventory"
            );
        }
    }

    #[test]
    fn release_rejection_target_is_no_replace_with_exact_replay() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let (_authority, marker_path, _) = persist_release_rejection_fixture(
            root.path(),
            &desired,
            RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
        );
        let before = std::fs::read(&marker_path).unwrap();
        let marker =
            super::super::checkpoint::decode_definite_release_rejection(&before, &marker_path)
                .unwrap();
        let store =
            FileCheckpointStore::open(&root.path().join(CHECKPOINT_NAMESPACE), &desired.cat_id)
                .unwrap();
        let stored = store.load().unwrap().unwrap();
        assert_eq!(
            store
                .persist_definite_release_rejection(&stored, &marker.request, marker.problem,)
                .unwrap(),
            marker
        );
        assert_eq!(std::fs::read(&marker_path).unwrap(), before);
        assert!(store
            .persist_definite_release_rejection(
                &stored,
                &marker.request,
                RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict,
            )
            .is_err());
        assert_eq!(std::fs::read(marker_path).unwrap(), before);
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

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PublicationAcquire {
        Normal,
        Takeover,
    }

    #[derive(Clone, Copy, Debug)]
    enum PublicationPrefix {
        Cat,
        Volume,
        Attachment,
        Epoch,
    }

    #[derive(Clone, Copy, Debug)]
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

    #[cfg(target_os = "linux")]
    struct RecordingStaleBootGlobal {
        calls: Arc<AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl stale_boot_recovery_global_sealed::Sealed for RecordingStaleBootGlobal {}

    #[cfg(target_os = "linux")]
    impl StaleBootVmmProcessGlobalPort for RecordingStaleBootGlobal {
        fn inspect_stale_boot_absence_after_node_global_sweep(
            &self,
            selected: &VmmProcessExpectation,
            checkpoints: &RuntimeCheckpointRecoverySet,
            context: &RuntimePreScanRecoveryContext,
        ) -> anyhow::Result<StaleBootVmmProcessGlobalInspection> {
            context.check_active()?;
            anyhow::ensure!(
                checkpoints.checkpoint(selected.cat_id()) == Some(selected.checkpoint()),
                "test global port did not receive the complete selected checkpoint"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(StaleBootVmmProcessGlobalInspection::Absent(Box::new(
                ExactVmmProcessAbsenceProof::for_expectation(selected.clone()),
            )))
        }
    }

    #[cfg(target_os = "linux")]
    struct StaleBootPublicationFixture {
        _root: tempfile::TempDir,
        state: StateDirectory,
        desired: DesiredRuntimeSpec,
        checkpoint: RuntimeCheckpoint,
        socket_root: Arc<RetainedManagedVmmSocketRoot>,
        launch_root: Arc<RetainedManagedVmmLaunchRoot>,
        receipts: Arc<VmmSocketReceiptStore>,
        calls: Arc<AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl StaleBootPublicationFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let state_path = root.path().join("state");
            std::fs::create_dir(&state_path).unwrap();
            std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let launch_namespace = state_path.join(VMM_LAUNCH_FILE_NAMESPACE);
            std::fs::create_dir(&launch_namespace).unwrap();
            std::fs::set_permissions(&launch_namespace, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let state = StateDirectory::unanchored(state_path.clone());
            let socket_root = Arc::new(
                RetainedManagedVmmSocketRoot::provision_for_test(&root.path().join("sockets"))
                    .unwrap(),
            );
            let launch_root =
                Arc::new(RetainedManagedVmmLaunchRoot::open_existing(state.clone()).unwrap());
            let receipts =
                Arc::new(VmmSocketReceiptStore::provision_for_test(state.clone()).unwrap());
            let desired =
                decode_desired_runtime_spec(literal_file_bytes(FIXED_DESIRED_WIRE)).unwrap();
            let mut checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
            )))
            .unwrap();
            let incarnation = checkpoint.runtime_incarnation.as_ref().unwrap().clone();
            let sockets = socket_root.planner().paths_for(&incarnation).unwrap();
            let files = ManagedVmmLaunchFilePaths::for_incarnation(&state, &incarnation).unwrap();
            let ReconcileStep::StartRuntime {
                api_socket_path,
                vsock_socket_path,
                memory_file_path,
                serial_log_path,
                vmm_log_path,
                ..
            } = &mut checkpoint.step
            else {
                unreachable!()
            };
            *api_socket_path = sockets.api_socket_path().clone();
            *vsock_socket_path = sockets.vsock_socket_path().clone();
            *memory_file_path = files.memory_file_path().clone();
            *serial_log_path = files.serial_log_path().clone();
            *vmm_log_path = files.vmm_log_path().clone();
            checkpoint.runtime_launch = RuntimeLaunch::Present(Box::new(
                checkpoint.step.start_runtime_launch_identity().unwrap(),
            ));
            FileCheckpointStore::open(&state_path.join(CHECKPOINT_NAMESPACE), &checkpoint.cat_id)
                .unwrap()
                .create(&checkpoint)
                .unwrap();
            let mut receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
                &checkpoint,
                &state,
                &socket_root,
                current_kernel_node_boot_id().unwrap(),
                random('b'),
            )
            .unwrap();
            let current_boot = current_kernel_node_boot_id().unwrap();
            let old_boot = ["e".repeat(32), "f".repeat(32)]
                .into_iter()
                .map(|value| NodeBootId::new(value).unwrap())
                .find(|value| value != &current_boot)
                .unwrap();
            receipt.set_node_boot_id_for_test(old_boot);
            receipts.publish(&receipt).unwrap();
            Self {
                _root: root,
                state,
                desired,
                checkpoint,
                socket_root,
                launch_root,
                receipts,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn recovery(&self) -> SignedRunningPublicationRecovery {
            let authority: Arc<dyn VolumeDataAuthority> =
                Arc::new(FakeAuthority::new(Err(AuthorityError::NotFound)));
            SignedRunningPublicationRecovery::with_stale_boot_vmm_recovery(
                authority,
                InstalledStaleBootVmmRecoveryPorts {
                    global: Arc::new(RecordingStaleBootGlobal {
                        calls: Arc::clone(&self.calls),
                    }),
                    socket_root: Arc::clone(&self.socket_root),
                    launch_root: Arc::clone(&self.launch_root),
                    receipts: Arc::clone(&self.receipts),
                },
            )
        }

        fn context(&self, desired: DesiredRuntimeSpec) -> RuntimePreScanRecoveryContext {
            recovery_context(self.state.path(), &desired)
        }

        fn receipt_path(&self) -> std::path::PathBuf {
            self.state
                .path()
                .join(VMM_SOCKET_RECEIPT_NAMESPACE)
                .join(format!(
                    "vmm-{}.receipt.json",
                    self.checkpoint
                        .runtime_incarnation
                        .as_ref()
                        .expect("stale-boot fixture retains one launch")
                        .as_str()
                ))
        }

        fn install_stable_stop_receipt(
            &self,
        ) -> (DesiredRuntimeSpec, std::path::PathBuf, std::fs::Metadata) {
            let desired = second_desired();
            let attachment = attachment(&desired);
            let record = owned_record(&desired, &attachment);
            let data_directory =
                authorized_blockd_data_directory(self.state.path(), &desired, &attachment.identity);
            let data_path = HostPath::new(data_directory.to_string_lossy().into_owned()).unwrap();
            let provision_transition_id = random('c');
            let control_socket_path =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .root_paths(&provision_transition_id)
                    .unwrap()
                    .control_socket()
                    .clone();
            let expected_target = RemoteHead {
                generation: Generation::new(1).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([7; 32])),
                root_object_id: Some(AsciiText::new("roots/stable-stop-test").unwrap()),
            };
            let mut checkpoint = acquire_checkpoint_from_attachment(&desired, &attachment);
            checkpoint.step = ReconcileStep::ProvisionRootImage {
                provision_transition_id,
                volume_id: attachment.identity.volume_id.clone(),
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                scope_id: Id::new(format!("cats-root-{}.service", "d".repeat(32))).unwrap(),
                control_socket_path: control_socket_path.clone(),
                data_directory: data_path.clone(),
                process_identity_token: random('d'),
                size_bytes: attachment.size_bytes,
                boot_image_digest: desired.runtime.boot_image_digest.clone(),
                expected_blank_head: attachment.head.clone(),
                expected_provisioned_head: expected_target,
            };
            checkpoint.volumes = vec![prepared_owned_observed_volume(
                &desired.volumes[0],
                &attachment,
                data_path,
            )];
            let stored = FileCheckpointStore::open(
                &self.state.path().join(CHECKPOINT_NAMESPACE),
                &desired.cat_id,
            )
            .unwrap()
            .create(&checkpoint)
            .unwrap();
            let prepared = AuthorizedBlockdStore::new(self.state.clone())
                .prepare(&desired, &desired.volumes[0], &attachment)
                .unwrap();
            assert_eq!(prepared.data_directory(), data_directory);
            let authorized = prepared.checkpoint().clone();
            drop(prepared);
            let executable = HostPath::new(
                std::env::current_exe()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            )
            .unwrap();
            let expected =
                super::super::root_provision_process::RootProvisionProcessExpectation::from_checkpoint(
                    &checkpoint,
                    super::super::root_provision_process::RootProvisionAuthoritySnapshot {
                        attachment: attachment.clone(),
                        volume: &record,
                    },
                    executable,
                )
                .unwrap();
            let mut retained = AuthorizedBlockdStore::new(self.state.clone())
                .retain_exact_runtime_checkpoint(stored.checkpoint())
                .unwrap();
            let process = super::super::root_provision_process::RootProvisionProcessEvidence {
                process_id: 91,
                unit_main_process_id: 91,
                process_start_time_ticks: WireU64::new(123).unwrap(),
                executable_path: expected.executable_path.clone(),
                scope_id: expected.scope_id.clone(),
                cgroup_path: expected.cgroup_path.clone(),
                cgroup_process_ids: vec![91],
                control_socket_path: expected.control_socket_path.clone(),
                data_directory: expected.data_directory.clone(),
                ownership_token: expected.process_identity_token.clone(),
                handshake: super::super::root_provision_process::RootProvisionBlockdHandshake {
                    peer_process_id: 91,
                    identity: expected.attachment.identity.clone(),
                    size_bytes: expected.size_bytes,
                    durability: expected.attachment.durability,
                    remote_head: expected.expected_remote_head().clone(),
                    process_identity_token: expected.process_identity_token.clone(),
                    control_only: true,
                    guest_io_enabled: false,
                },
            };
            let socket_owner = super::super::blockd_socket_namespace::ManagedBlockdRootStopOwnerEvidence::for_test(
                &expected,
                NodeBootId::new("33333333333333333333333333333333").unwrap(),
            )
            .unwrap();
            let receipt = super::super::authorized_blockd::RootProvisionStopReceipt::new(
                stored.checkpoint(),
                &authorized,
                record,
                process,
                socket_owner,
                super::super::root_provision_process::RootProvisionRetirementAdmission {
                    node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
                    agent_instance_id: random('4'),
                    agent_session_epoch: epoch(2),
                    inventory_epoch: epoch(4),
                    inventory_digest: Sha256Digest::from_bytes([9; 32]),
                    inventory_read_position: sequence(12),
                },
            )
            .unwrap();
            assert!(matches!(
                retained.persist_or_reopen_stop_receipt(&receipt).unwrap(),
                super::super::authorized_blockd::StopReceiptPublication::Published(_)
            ));
            let receipt_path = data_directory
                .join(super::super::authorized_blockd::ROOT_PROVISION_STOP_RECEIPT_FILE);
            let identity = std::fs::metadata(&receipt_path).unwrap();
            (desired, receipt_path, identity)
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy)]
    enum UnrelatedCurrentCheckpointPhase {
        Acquire,
        Provision,
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy)]
    enum UnrelatedCurrentCheckpointDrift {
        Authorization,
        Origin,
        Attachment,
        Epoch,
        Head,
        DataDirectory,
        GuestSlot,
        ExtraObservedVolume,
        MissingObservedVolume,
    }

    #[cfg(target_os = "linux")]
    fn unrelated_current_multi_takeover_checkpoint(
        state_path: &std::path::Path,
        phase: UnrelatedCurrentCheckpointPhase,
    ) -> (DesiredRuntimeSpec, RuntimeCheckpoint) {
        let mut desired = second_desired();
        desired.volumes.push(normal_persistent_volume());
        let authorization_id = id("takeover_stale_boot_root");
        desired.volumes[0].acquire = VolumeAcquire::Takeover {
            authorization_id: authorization_id.clone(),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();

        let (root_attachment, _, _, root_predecessor) = takeover_recovery_fixture(&desired, 0);
        let checkpoint = match phase {
            UnrelatedCurrentCheckpointPhase::Acquire => closed_checkpoint(
                &desired,
                ReconcileStep::AcquireVolume {
                    request: VolumeAcquireRequest::Takeover { authorization_id },
                },
                vec![
                    root_predecessor,
                    unowned_observed_volume(&desired.volumes[1]),
                ],
                unix_ms(1_900_000_000_000),
            ),
            UnrelatedCurrentCheckpointPhase::Provision => {
                let persistent_attachment = normal_attachment(&desired, 1);
                let root_data_directory = authorized_blockd_data_directory(
                    state_path,
                    &desired,
                    &root_attachment.identity,
                );
                let persistent_data_directory = authorized_blockd_data_directory(
                    state_path,
                    &desired,
                    &persistent_attachment.identity,
                );
                let expected_provisioned_head = RemoteHead {
                    generation: Generation::new(1).unwrap(),
                    root_hash: Some(Sha256Digest::from_bytes([0x51; 32])),
                    root_object_id: Some(AsciiText::new("roots/stale-boot-multi-target").unwrap()),
                };
                let provision_transition_id = random('6');
                let control_socket_path =
                    cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                        .root_paths(&provision_transition_id)
                        .unwrap()
                        .control_socket()
                        .clone();
                closed_checkpoint(
                    &desired,
                    ReconcileStep::ProvisionRootImage {
                        provision_transition_id,
                        volume_id: desired.volumes[0].volume_id.clone(),
                        attachment_id: root_attachment.identity.attachment_id.clone(),
                        attachment_epoch: root_attachment.identity.attachment_epoch,
                        scope_id: id(&format!("cats-root-{}.service", "7".repeat(32))),
                        control_socket_path,
                        data_directory: host(root_data_directory.clone()),
                        process_identity_token: random('8'),
                        size_bytes: desired.volumes[0].size_bytes,
                        boot_image_digest: desired.runtime.boot_image_digest.clone(),
                        expected_blank_head: root_attachment.head.clone(),
                        expected_provisioned_head,
                    },
                    vec![
                        prepared_owned_observed_volume(
                            &desired.volumes[0],
                            &root_attachment,
                            host(root_data_directory),
                        ),
                        prepared_owned_observed_volume(
                            &desired.volumes[1],
                            &persistent_attachment,
                            host(persistent_data_directory),
                        ),
                    ],
                    unix_ms(1_900_000_000_000),
                )
            }
        };
        (desired, checkpoint)
    }

    #[cfg(target_os = "linux")]
    fn drifted_unrelated_current_multi_takeover_checkpoint(
        state_path: &std::path::Path,
        drift: UnrelatedCurrentCheckpointDrift,
    ) -> (DesiredRuntimeSpec, RuntimeCheckpoint) {
        let phase = if matches!(drift, UnrelatedCurrentCheckpointDrift::Authorization) {
            UnrelatedCurrentCheckpointPhase::Acquire
        } else {
            UnrelatedCurrentCheckpointPhase::Provision
        };
        let (mut desired, mut checkpoint) =
            unrelated_current_multi_takeover_checkpoint(state_path, phase);
        match drift {
            UnrelatedCurrentCheckpointDrift::Authorization => {
                let ReconcileStep::AcquireVolume {
                    request: VolumeAcquireRequest::Takeover { authorization_id },
                } = &mut checkpoint.step
                else {
                    unreachable!("authorization drift fixture must use Takeover Acquire")
                };
                *authorization_id = id("takeover_stale_boot_foreign");
            }
            UnrelatedCurrentCheckpointDrift::Origin => {
                checkpoint.volumes[0].local_lineages[0].acquire_origin = AcquireOrigin::Normal {
                    transition_id: random('9'),
                };
            }
            UnrelatedCurrentCheckpointDrift::Attachment => {
                let ReconcileStep::ProvisionRootImage { attachment_id, .. } = &mut checkpoint.step
                else {
                    unreachable!("attachment drift fixture must use Root provision")
                };
                *attachment_id = id("att_stale_boot_foreign");
            }
            UnrelatedCurrentCheckpointDrift::Epoch => {
                let ReconcileStep::ProvisionRootImage {
                    attachment_epoch, ..
                } = &mut checkpoint.step
                else {
                    unreachable!("epoch drift fixture must use Root provision")
                };
                *attachment_epoch = fence(attachment_epoch.get() + 1);
            }
            UnrelatedCurrentCheckpointDrift::Head => {
                let VolumeAuthorityEvidence::Owned { head, .. } =
                    &mut checkpoint.volumes[0].authority
                else {
                    unreachable!("head drift fixture must retain owned Root authority")
                };
                *head = RemoteHead {
                    generation: Generation::new(2).unwrap(),
                    root_hash: Some(Sha256Digest::from_bytes([0x52; 32])),
                    root_object_id: Some(AsciiText::new("roots/stale-boot-foreign-head").unwrap()),
                };
            }
            UnrelatedCurrentCheckpointDrift::DataDirectory => {
                checkpoint.volumes[0].local_lineages[0].data_directory =
                    host(state_path.join("data/stale-boot-foreign-lineage"));
            }
            UnrelatedCurrentCheckpointDrift::GuestSlot => {
                desired.volumes[1].guest_device.slot = desired.volumes[0].guest_device.slot;
            }
            UnrelatedCurrentCheckpointDrift::ExtraObservedVolume => {
                let mut extra = checkpoint.volumes[1].clone();
                extra.volume_intent_id = Some(id("vint_zz_stale_boot_extra"));
                extra.disk_id = Some(id("disk_zz_stale_boot_extra"));
                extra.volume_id = id("vol_zz_stale_boot_extra");
                checkpoint.volumes.push(extra);
            }
            UnrelatedCurrentCheckpointDrift::MissingObservedVolume => {
                checkpoint.volumes.pop();
            }
        }
        (desired, checkpoint)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_boot_recovery_runs_after_current_or_legal_superseded_classification() {
        for superseded in [false, true] {
            let fixture = StaleBootPublicationFixture::new();
            let mut desired = fixture.desired.clone();
            if superseded {
                desired.desired_revision =
                    Revision::new(desired.desired_revision.get() + 1).unwrap();
                desired.spec_digest = spec_digest(&desired).unwrap();
                assert!(matches!(
                    classify_local_publication_recovery(&fixture.context(desired.clone())).unwrap(),
                    LocalPublicationRecoveryEvidence::SupersededCheckpoint { .. }
                ));
            }
            assert!(matches!(
                fixture
                    .recovery()
                    .recover_one(fixture.context(desired))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered { cat_id }
                    if cat_id == fixture.checkpoint.cat_id
            ));
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
            assert!(fixture
                .receipts
                .load(fixture.checkpoint.runtime_incarnation.as_ref().unwrap())
                .unwrap()
                .is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stable_stop_receipt_does_not_starve_unrelated_stale_boot_vmm_recovery() {
        let fixture = StaleBootPublicationFixture::new();
        let (stable, stop_receipt, before) = fixture.install_stable_stop_receipt();
        let desireds = vec![stable.clone(), fixture.desired.clone()];
        let context = recovery_context_with_desireds(fixture.state.path(), desireds.clone());
        assert!(matches!(
            classify_local_publication_recovery(&context).unwrap(),
            LocalPublicationRecoveryEvidence::RootProvisionStopReceipt { cat_id }
                if cat_id == stable.cat_id
        ));

        assert!(matches!(
            fixture.recovery().recover_one(context).unwrap(),
            RuntimePreScanRecoveryOutcome::Recovered { cat_id }
                if cat_id == fixture.checkpoint.cat_id
        ));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert!(fixture
            .receipts
            .load(fixture.checkpoint.runtime_incarnation.as_ref().unwrap())
            .unwrap()
            .is_none());
        let after = std::fs::metadata(&stop_receipt).unwrap();
        assert_eq!(after.len(), before.len());
        assert_eq!(after.dev(), before.dev());
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.nlink(), before.nlink());

        // The stale VMM repair forces a fresh round; the unrelated stable stop
        // receipt remains full-scan effect work and is still classified.
        assert!(matches!(
            classify_local_publication_recovery(&recovery_context_with_desireds(
                fixture.state.path(),
                desireds,
            ))
            .unwrap(),
            LocalPublicationRecoveryEvidence::RootProvisionStopReceipt { cat_id }
                if cat_id == stable.cat_id
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_multi_takeover_acquire_and_provision_do_not_starve_stale_boot_recovery() {
        for phase in [
            UnrelatedCurrentCheckpointPhase::Acquire,
            UnrelatedCurrentCheckpointPhase::Provision,
        ] {
            let fixture = StaleBootPublicationFixture::new();
            let (unrelated, checkpoint) =
                unrelated_current_multi_takeover_checkpoint(fixture.state.path(), phase);
            persist_checkpoint(fixture.state.path(), &checkpoint);
            let context = recovery_context_with_desireds(
                fixture.state.path(),
                vec![fixture.desired.clone(), unrelated],
            );

            assert!(matches!(
                fixture.recovery().recover_one(context).unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered { cat_id }
                    if cat_id == fixture.checkpoint.cat_id
            ));
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
            assert!(fixture
                .receipts
                .load(fixture.checkpoint.runtime_incarnation.as_ref().unwrap())
                .unwrap()
                .is_none());
            assert_eq!(
                read_checkpoint(&checkpoint_path(fixture.state.path(), &checkpoint.cat_id,)),
                checkpoint,
                "stale-boot recovery must not mutate the unrelated checkpoint",
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drifted_current_multi_takeover_checkpoint_never_deletes_unrelated_stale_boot_receipt() {
        for drift in [
            UnrelatedCurrentCheckpointDrift::Authorization,
            UnrelatedCurrentCheckpointDrift::Origin,
            UnrelatedCurrentCheckpointDrift::Attachment,
            UnrelatedCurrentCheckpointDrift::Epoch,
            UnrelatedCurrentCheckpointDrift::Head,
            UnrelatedCurrentCheckpointDrift::DataDirectory,
            UnrelatedCurrentCheckpointDrift::GuestSlot,
            UnrelatedCurrentCheckpointDrift::ExtraObservedVolume,
            UnrelatedCurrentCheckpointDrift::MissingObservedVolume,
        ] {
            let fixture = StaleBootPublicationFixture::new();
            let receipt_path = fixture.receipt_path();
            let before_bytes = std::fs::read(&receipt_path).unwrap();
            let before = std::fs::metadata(&receipt_path).unwrap();
            let (unrelated, checkpoint) =
                drifted_unrelated_current_multi_takeover_checkpoint(fixture.state.path(), drift);
            if matches!(drift, UnrelatedCurrentCheckpointDrift::GuestSlot) {
                assert!(encode_desired_runtime_spec(&unrelated).is_err());
            } else {
                encode_desired_runtime_spec(&unrelated).unwrap();
            }
            encode_runtime_checkpoint(&checkpoint).unwrap();
            persist_checkpoint(fixture.state.path(), &checkpoint);

            assert_eq!(
                fixture
                    .recovery()
                    .recover_one(recovery_context_with_desireds(
                        fixture.state.path(),
                        vec![fixture.desired.clone(), unrelated],
                    ))
                    .unwrap(),
                RuntimePreScanRecoveryOutcome::NoChange,
                "drift case {drift:?}",
            );
            assert_eq!(
                fixture.calls.load(Ordering::SeqCst),
                0,
                "drift case {drift:?} reached the global VMM sweep",
            );
            assert!(fixture
                .receipts
                .load(fixture.checkpoint.runtime_incarnation.as_ref().unwrap())
                .unwrap()
                .is_some());
            let after = std::fs::metadata(&receipt_path).unwrap();
            assert_eq!(std::fs::read(&receipt_path).unwrap(), before_bytes);
            assert_eq!(after.len(), before.len());
            assert_eq!(after.dev(), before.dev());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.nlink(), before.nlink());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drifted_superseded_launch_never_reaches_global_or_deletes_receipt() {
        let fixture = StaleBootPublicationFixture::new();
        let store = FileCheckpointStore::open(
            &fixture.state.path().join(CHECKPOINT_NAMESPACE),
            &fixture.checkpoint.cat_id,
        )
        .unwrap();
        let stored = store.load().unwrap().unwrap();
        let mut drifted = stored.checkpoint().clone();
        let ReconcileStep::StartRuntime { vcpus, .. } = &mut drifted.step else {
            unreachable!()
        };
        *vcpus += 1;
        drifted.runtime_launch = RuntimeLaunch::Present(Box::new(
            drifted.step.start_runtime_launch_identity().unwrap(),
        ));
        store.replace(&stored, &drifted).unwrap();
        let mut desired = fixture.desired.clone();
        desired.desired_revision = Revision::new(desired.desired_revision.get() + 1).unwrap();
        desired.spec_digest = spec_digest(&desired).unwrap();
        assert!(matches!(
            fixture
                .recovery()
                .recover_one(fixture.context(desired))
                .unwrap(),
            RuntimePreScanRecoveryOutcome::NoChange
        ));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        assert!(fixture
            .receipts
            .load(fixture.checkpoint.runtime_incarnation.as_ref().unwrap())
            .unwrap()
            .is_some());
    }

    fn recovery_context(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
    ) -> RuntimePreScanRecoveryContext {
        recovery_context_with_desireds(root, vec![desired.clone()])
    }

    fn recovery_context_with_desireds(
        root: &std::path::Path,
        desired_specs: Vec<DesiredRuntimeSpec>,
    ) -> RuntimePreScanRecoveryContext {
        let node_id = desired_specs
            .first()
            .expect("recovery fixture has at least one Desired")
            .placement
            .node_id
            .clone();
        let session = SessionBinding {
            node_id,
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
                    desired_specs,
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

    fn publication_prefix_path(
        directory: &std::path::Path,
        prefix: PublicationPrefix,
    ) -> std::path::PathBuf {
        let attachment = directory.parent().expect("epoch has attachment parent");
        let volume = attachment.parent().expect("attachment has volume parent");
        let cat = volume.parent().expect("volume has Cat parent");
        match prefix {
            PublicationPrefix::Cat => cat.to_path_buf(),
            PublicationPrefix::Volume => volume.to_path_buf(),
            PublicationPrefix::Attachment => attachment.to_path_buf(),
            PublicationPrefix::Epoch => directory.to_path_buf(),
        }
    }

    fn shape_publication_prefix(directory: &std::path::Path, prefix: PublicationPrefix) {
        let prefix_path = publication_prefix_path(directory, prefix);
        match prefix {
            PublicationPrefix::Cat => {
                let volume = directory
                    .parent()
                    .and_then(std::path::Path::parent)
                    .expect("epoch has a volume ancestor");
                std::fs::remove_dir_all(volume).unwrap();
            }
            PublicationPrefix::Volume => {
                let attachment = directory.parent().expect("epoch has attachment parent");
                std::fs::remove_dir_all(attachment).unwrap();
            }
            PublicationPrefix::Attachment => {
                std::fs::remove_dir_all(directory).unwrap();
            }
            PublicationPrefix::Epoch => {
                for entry in std::fs::read_dir(&prefix_path).unwrap() {
                    let entry = entry.unwrap();
                    assert!(entry.file_type().unwrap().is_file());
                    std::fs::remove_file(entry.path()).unwrap();
                }
            }
        }
        assert!(prefix_path.is_dir());
        assert_eq!(std::fs::read_dir(prefix_path).unwrap().count(), 0);
    }

    fn misattribute_publication_prefix(
        directory: &std::path::Path,
        prefix: PublicationPrefix,
    ) -> std::path::PathBuf {
        let source = publication_prefix_path(directory, prefix);
        let foreign_name = match prefix {
            PublicationPrefix::Cat => "cat-wrong",
            PublicationPrefix::Volume => "volume-wrong",
            PublicationPrefix::Attachment => "attachment-wrong",
            PublicationPrefix::Epoch => "epoch-999",
        };
        let foreign = source.with_file_name(foreign_name);
        std::fs::rename(source, &foreign).unwrap();
        foreign
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

    fn normal_persistent_volume() -> VolumeIntent {
        VolumeIntent {
            volume_intent_id: id("vint_z_persistent"),
            disk_id: id("disk_z_persistent"),
            volume_id: id("vol_z_persistent"),
            attachment_id: id("att_z_persistent"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Persistent,
            access: VolumeAccess::ReadWriteOnce,
            durability: cats_api::runtime_reconciliation::Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-persistent"),
                slot: 1,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: random('b'),
                expected_unowned_epoch: fence(0),
            },
            disposition: VolumeDisposition::Retain,
            mount: Some(cats_api::runtime_reconciliation::Ext4MountIntent {
                filesystem_uuid: random('c'),
                mount_path: HostPath::new("/srv/cats/persistent").unwrap(),
                initialization:
                    cats_api::runtime_reconciliation::FilesystemInitialization::Initialize {
                        initialization_token: random('d'),
                        expected_blank_head: blank_head(),
                    },
            }),
        }
    }

    fn second_desired() -> DesiredRuntimeSpec {
        let mut desired = desired();
        desired.cat_id = id("cat_02");
        desired.volumes[0].volume_intent_id = id("vint_second");
        desired.volumes[0].disk_id = id("disk_second");
        desired.volumes[0].volume_id = id("vol_second");
        desired.volumes[0].attachment_id = id("att_second");
        desired.volumes[0].guest_device.serial = id("cats-second");
        desired.volumes[0].acquire = VolumeAcquire::Normal {
            transition_id: random('a'),
            expected_unowned_epoch: fence(0),
        };
        desired.runtime.network_config.network_id = id("net_02");
        desired.runtime.network_config.guest_mac = MacAddress::new("02:ca:0a:f0:00:0a").unwrap();
        desired.runtime.network_config.guest_ipv4 = Ipv4Address::new("10.240.0.10").unwrap();
        desired.runtime.network_config.gateway_ipv4 = Ipv4Address::new("10.240.0.9").unwrap();
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
        scan_context_with_desireds(vec![desired.clone()])
    }

    fn scan_context_with_desireds(
        desired_specs: Vec<DesiredRuntimeSpec>,
    ) -> RuntimeInventoryScanContext {
        let node_id = desired_specs
            .first()
            .expect("scan fixture has at least one Desired")
            .placement
            .node_id
            .clone();
        let session = SessionBinding {
            node_id,
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
                    desired_specs,
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
                    runtime_launch: Box::new(stored.runtime_launch.clone()),
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

    fn observed_runtime_with_volumes(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        checkpoint: Option<&RuntimeCheckpoint>,
        volumes: Vec<ObservedVolume>,
    ) -> ObservedRuntimeStatus {
        let (step, checkpoint) = match checkpoint {
            Some(stored) => (
                stored.step.clone(),
                CheckpointEvidence::Valid {
                    checkpoint_path: host(checkpoint_path(root, &desired.cat_id)),
                    content_digest: checkpoint_content_digest(stored).unwrap(),
                    version: stored.version,
                    cat_id: stored.cat_id.clone(),
                    node_id: stored.node_id.clone(),
                    desired_revision: stored.desired_revision,
                    spec_digest: stored.spec_digest.clone(),
                    placement_epoch: stored.placement_epoch,
                    runtime_incarnation: stored.runtime_incarnation.clone(),
                    runtime_launch: Box::new(stored.runtime_launch.clone()),
                    stable_state: stored.stable_state,
                    step: Box::new(stored.step.clone()),
                    require_idle: Box::new(stored.require_idle.clone()),
                    updated_at_unix_ms: stored.updated_at_unix_ms,
                },
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
            volumes,
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
        normal_attachment(desired, 0)
    }

    fn normal_attachment(
        desired: &DesiredRuntimeSpec,
        volume_index: usize,
    ) -> AuthorizedServingAttachment {
        let volume = &desired.volumes[volume_index];
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
            acquire: AuthorizedServingAcquire::Normal { request, result },
        }
    }

    fn takeover_recovery_fixture(
        desired: &DesiredRuntimeSpec,
        volume_index: usize,
    ) -> (
        AuthorizedServingAttachment,
        VolumeRecord,
        VolumeEvidenceRecovery,
        ObservedVolume,
    ) {
        let volume = &desired.volumes[volume_index];
        let VolumeAcquire::Takeover { authorization_id } = &volume.acquire else {
            panic!("takeover recovery fixture requires Takeover Desired")
        };
        let prior_attachment_id = if volume_index == 0 {
            id("att_root_prior")
        } else {
            id("att_persistent_prior")
        };
        let prior_epoch = fence(7 + u64::try_from(volume_index).unwrap());
        let authorization = VolumeTakeoverAuthorization {
            authorization_id: authorization_id.clone(),
            authorized_node_id: desired.placement.node_id.clone(),
            host_fence_event_id: if volume_index == 0 {
                id("fence_root_recovery")
            } else {
                id("fence_persistent_recovery")
            },
            volume_id: volume.volume_id.clone(),
            expected_attachment_id: prior_attachment_id.clone(),
            expected_epoch: prior_epoch,
            new_attachment_id: volume.attachment_id.clone(),
            desired_revision: desired.desired_revision,
            new_placement_epoch: desired.placement.placement_epoch,
            lease_duration_ms: 60_000,
            not_after: unix_ms(1_900_000_020_000),
        };
        let resulting_epoch = fence(prior_epoch.get() + 1);
        let receipt = TakeoverConsumedReceipt {
            authorization_id: authorization_id.clone(),
            host_fence_event_id: authorization.host_fence_event_id.clone(),
            volume_id: volume.volume_id.clone(),
            new_attachment_id: volume.attachment_id.clone(),
            resulting_epoch,
            resulting_head: blank_head(),
            consumed_at: unix_ms(1_900_000_010_000),
        };
        let record = VolumeRecord {
            volume_id: volume.volume_id.clone(),
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            admin_state: VolumeAdminState::Active,
            head: blank_head(),
            lease_owner: Some(volume.attachment_id.clone()),
            lease_epoch: resulting_epoch,
            lease_expires_at: Some(unix_ms(1_900_000_070_000)),
            last_transition: Some(LastVolumeTransition::Takeover {
                authorization_id: authorization_id.clone(),
            }),
        };
        let prior = ObservedVolume {
            volume_intent_id: Some(volume.volume_intent_id.clone()),
            disk_id: Some(volume.disk_id.clone()),
            volume_id: volume.volume_id.clone(),
            disk_kind: match volume.disk_kind {
                DiskKind::Root => ObservedDiskKind::Root,
                DiskKind::Persistent => ObservedDiskKind::Persistent,
            },
            size_bytes: Some(volume.size_bytes),
            durability: Some(volume.durability),
            authority: VolumeAuthorityEvidence::Owned {
                attachment_id: prior_attachment_id,
                attachment_epoch: prior_epoch,
                head: blank_head(),
            },
            local_lineages: Vec::new(),
            devices: Vec::new(),
        };
        let evidence = RuntimeVolumeTransitionEvidenceSuccess {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: desired.placement.node_id.clone(),
                node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
                agent_instance_id: random('8'),
                agent_session_epoch: epoch(3),
            },
            authorization_id: authorization_id.clone(),
            authorization: AuthorizationRecord {
                authorization: VolumeAuthorization::Takeover(authorization),
                state: AuthorizationState::Consumed(Box::new(
                    AuthorizationConsumedReceipt::Takeover(receipt.clone()),
                )),
            },
            current_volume: Some(record.clone()),
            delete_completion: None,
            direct_successor_authorization: None,
        };
        let attachment = takeover_attachment_from_signed_evidence(
            desired, volume, &prior, &evidence, &receipt, None,
        )
        .unwrap();
        (
            attachment,
            record,
            VolumeEvidenceRecovery::Validated {
                evidence: Box::new(evidence),
                decision: Box::new(VolumeEvidenceRecoveryDecision::AdoptTakeover(receipt)),
            },
            prior,
        )
    }

    fn set_takeover_recovery_fixture_head(
        attachment: &mut AuthorizedServingAttachment,
        record: &mut VolumeRecord,
        evidence: &mut VolumeEvidenceRecovery,
        prior: &mut ObservedVolume,
        head: RemoteHead,
    ) {
        attachment.head = head.clone();
        let AuthorizedServingAcquire::Takeover { receipt, .. } = &mut attachment.acquire else {
            panic!("takeover fixture must retain a takeover attachment")
        };
        receipt.resulting_head = head.clone();
        record.head = head.clone();
        let VolumeAuthorityEvidence::Owned {
            head: prior_head, ..
        } = &mut prior.authority
        else {
            panic!("takeover fixture predecessor must remain owned")
        };
        *prior_head = head.clone();
        let VolumeEvidenceRecovery::Validated { evidence, decision } = evidence else {
            panic!("takeover fixture must retain validated evidence")
        };
        let AuthorizationState::Consumed(stored) = &mut evidence.authorization.state else {
            panic!("takeover fixture authorization must remain consumed")
        };
        let AuthorizationConsumedReceipt::Takeover(stored) = stored.as_mut() else {
            panic!("takeover fixture must retain its takeover receipt")
        };
        stored.resulting_head = head.clone();
        evidence
            .current_volume
            .as_mut()
            .expect("takeover fixture has a current Volume")
            .head = head.clone();
        let VolumeEvidenceRecoveryDecision::AdoptTakeover(decision) = decision.as_mut() else {
            panic!("takeover fixture decision must remain AdoptTakeover")
        };
        decision.resulting_head = head;
    }

    fn acquire_checkpoint_from_attachment(
        desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
    ) -> RuntimeCheckpoint {
        acquire_checkpoint(
            desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: attachment.checkpoint_acquire_request(),
            },
            unix_ms(1_900_000_000_000),
        )
    }

    fn persist_checkpoint(root: &std::path::Path, checkpoint: &RuntimeCheckpoint) {
        let store = FileCheckpointStore::open(&root.join(CHECKPOINT_NAMESPACE), &checkpoint.cat_id)
            .unwrap();
        store.create(checkpoint).unwrap();
    }

    fn assert_fresh_scanner_rejects_checkpoint_mutation(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        mutate: impl FnOnce(&mut RuntimeCheckpoint),
    ) {
        let store =
            FileCheckpointStore::open(&root.join(CHECKPOINT_NAMESPACE), &desired.cat_id).unwrap();
        let current = store.load().unwrap().unwrap();
        let original = current.checkpoint().clone();
        let mut conflicting = original.clone();
        mutate(&mut conflicting);
        encode_runtime_checkpoint(&conflicting).unwrap();
        let conflicting = store.replace(&current, &conflicting).unwrap();
        let scanner = fresh_scanner_with_blob(root, authority, blob);
        assert!(
            !matches!(
                scanner.scan_complete(scan_context(desired)),
                Ok(RuntimeInventoryScanOutcome::Complete(_))
            ),
            "actual AuthorizedBlockd bytes must be value-exact with the durable checkpoint"
        );
        store.replace(&conflicting, &original).unwrap();
    }

    fn unowned_record(desired: &DesiredRuntimeSpec) -> VolumeRecord {
        unowned_record_for(&desired.volumes[0])
    }

    fn unowned_record_for(volume: &VolumeIntent) -> VolumeRecord {
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
            last_transition: Some(attachment.expected_last_transition()),
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

    fn persist_release_rejection_fixture(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        problem: RuntimeVolumeTransitionPreconditionProblem,
    ) -> (Arc<FakeAuthority>, std::path::PathBuf, std::path::PathBuf) {
        let attachment = attachment(desired);
        let cleanup = CleanupRelease {
            target: CleanupTarget::Volume {
                volume_id: attachment.identity.volume_id.clone(),
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
            },
            inventory_session: SessionBinding {
                node_id: desired.placement.node_id.clone(),
                node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
                agent_instance_id: random('8'),
                agent_session_epoch: epoch(3),
            },
            inventory_epoch: epoch(4),
            inventory_read_position: sequence(12),
            desired_read_position: sequence(21),
            volume_release: Some(VolumeReleaseReplay {
                release_transition_id: random('7'),
                generation: attachment.head.generation,
                disposition: desired.volumes[0].disposition.clone(),
            }),
        };
        let checkpoint = closed_checkpoint(
            desired,
            ReconcileStep::CleanupRelease {
                cleanup: cleanup.clone(),
            },
            vec![owned_observed_volume(&desired.volumes[0], &attachment)],
            unix_ms(1_900_000_000_000),
        );
        let directory = root.join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&directory, &desired.cat_id).unwrap();
        let stored = store.create(&checkpoint).unwrap();
        let request = release_transition_request(desired, cleanup);
        store
            .persist_definite_release_rejection(&stored, &request, problem)
            .unwrap();
        drop(store);
        (
            Arc::new(FakeAuthority::new(Ok(owned_record(desired, &attachment)))),
            super::super::checkpoint::release_rejection_path(&directory, &desired.cat_id),
            super::super::checkpoint::release_rejection_temporary_path(&directory, &desired.cat_id),
        )
    }

    fn directory_file_snapshot(directory: &std::path::Path) -> Vec<(String, Vec<u8>, u64)> {
        let mut files = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    std::fs::read(entry.path()).unwrap(),
                    metadata.nlink(),
                )
            })
            .collect::<Vec<_>>();
        files.sort_by(|left, right| left.0.cmp(&right.0));
        files
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
