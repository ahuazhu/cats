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
use std::time::Instant;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AcquireOrigin, AgentSession, AppliedDesiredEvidence, AsciiText,
    CheckpointEvidence, Condition, ContractVersion, DesiredRuntimeSpec, DiskKind, FenceEpoch,
    Generation, GuestTransportEvidence, HostPath, Id, LifecycleAdmission, LocalLineageState,
    LocalVolumeLineage, ObservedDiskKind, ObservedRuntimeStatus, ObservedVolume, ProgressingReason,
    RandomId128, ReconcileStep, RemoteHead, RequireIdleCheckpoint, RuntimeCheckpoint,
    RuntimeTarget, RuntimeTransition, RuntimeVolumeTransition, RuntimeVolumeTransitionRequest,
    SessionBinding, Sha256Digest, UnixMillis, VolumeAccess, VolumeAcquire, VolumeAcquireRequest,
    VolumeAuthorityEvidence, VolumeDisposition, VolumeIntent, WarmSnapshotEvidence, WireU64,
};
use cats_storage::authority::{AuthorityError, AuthorizedServingAttachment, VolumeDataAuthority};
use cats_storage::{read_image_manifest_until, BlobStore, ImageManifestReadError};

use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
    RuntimeDesiredEffectStopReason,
};

use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::{
    authorized_blockd::authorized_blockd_data_directory, recover_normal_acquire_from_authority,
    runtime_checkpoint_path, AuthorizedBlockdStore, ControlSignedNormalAcquireClient,
    FileCheckpointStore, NormalAcquireAcceptedContext, NormalAcquireAttempt,
    NormalAcquireAuthorityRecovery, NormalAcquireClientError,
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
}

/// The first real signed Running effect. Its constructor rejects an invalid
/// lease budget before any accepted inventory can reach the effect lane.
pub(crate) struct SignedRunningAcquireEffect {
    acquire: Arc<dyn SignedNormalAcquirePort>,
    authority: Arc<dyn VolumeDataAuthority>,
    blob: Arc<dyn BlobStore>,
    lease_duration_ms: u64,
    #[cfg(test)]
    after_prepare: Option<AfterPrepareHook>,
}

impl SignedRunningAcquireEffect {
    pub(crate) fn new(
        acquire: Arc<dyn SignedNormalAcquirePort>,
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        lease_duration_ms: u64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=MAX_LEASE_DURATION_MS).contains(&lease_duration_ms),
            "signed normal-acquire lease duration is outside the frozen wire range"
        );
        Ok(Self {
            acquire,
            authority,
            blob,
            lease_duration_ms,
            #[cfg(test)]
            after_prepare: None,
        })
    }

    #[cfg(test)]
    fn with_after_prepare(mut self, hook: AfterPrepareHook) -> Self {
        self.after_prepare = Some(hook);
        self
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
        let manifest = match read_image_manifest_until(
            self.blob.as_ref(),
            &desired.runtime.boot_image_digest,
            context.deadline(),
        ) {
            Ok(manifest) => manifest,
            Err(
                ImageManifestReadError::NotFound { .. }
                | ImageManifestReadError::BackendUnavailable { .. },
            ) => return Ok(RuntimeDesiredEffectOutcome::RetryExact),
            Err(
                ImageManifestReadError::TooLarge { .. } | ImageManifestReadError::Corrupt { .. },
            ) => return Ok(stop_local()),
        };
        let image_identity =
            match cats_blockd::format::image_root_identity(&manifest, volume.size_bytes) {
                Ok(identity) => identity,
                Err(_) => return Ok(stop_local()),
            };
        let expected_blank_head = blank_head();
        let expected_provisioned_head = RemoteHead {
            generation: Generation::new(1).expect("one is a valid generation"),
            root_hash: Some(Sha256Digest::from_bytes(image_identity.root_hash)),
            root_object_id: Some(
                AsciiText::new(image_identity.root_object_id)
                    .expect("a computed map object ID is printable ASCII"),
            ),
        };
        context.check_active()?;

        let request =
            normal_acquire_request(desired, volume, accepted.session(), self.lease_duration_ms);
        let acquire_checkpoint = acquire_checkpoint(
            desired,
            volume,
            request.transition.clone(),
            accepted.attestation().accepted_at_unix_ms,
        );
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let store = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id)
            .context("open signed Running checkpoint store")?;
        let predecessor = match store.load().context("load signed Running checkpoint")? {
            None => store
                .create(&acquire_checkpoint)
                .context("persist normal-acquire request before authority mutation")?,
            Some(stored)
                if checkpoint_eq_except_updated_at(stored.checkpoint(), &acquire_checkpoint) =>
            {
                stored
            }
            Some(stored)
                if provision_checkpoint_is_bound(
                    stored.checkpoint(),
                    desired,
                    volume,
                    context.state_directory().path(),
                    &expected_blank_head,
                    &expected_provisioned_head,
                ) =>
            {
                // A previous invocation crossed the directory durability
                // barrier and lost only its return path. Do not perform a
                // second mutation from the stale pre-acquire observation.
                return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
            }
            Some(_) => return Ok(stop_local()),
        };

        context.check_active()?;
        let accepted_context = NormalAcquireAcceptedContext {
            session: accepted.session().clone(),
            inventory_attestation: accepted.attestation().clone(),
        };
        let attempt =
            match self
                .acquire
                .acquire(&request, volume, &accepted_context, context.deadline())
            {
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
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        if attachment.head != expected_blank_head {
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        }
        context.check_active()?;
        let prepared = AuthorizedBlockdStore::new(context.state_directory().clone())
            .prepare(desired, volume, &attachment)
            .context("persist exact authorized blockd grant after normal acquire")?;
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
        self.apply_acquire(&context, desired)
    }
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
    RuntimeVolumeTransitionRequest {
        version: ContractVersion::V1,
        session: SessionBinding {
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
        },
        cat_id: desired.cat_id.clone(),
        desired_revision: desired.desired_revision,
        spec_digest: desired.spec_digest.clone(),
        placement: desired.placement.clone(),
        transition: RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Normal {
                volume_id: volume.volume_id.clone(),
                transition_id: transition_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                expected_unowned_epoch: *expected_unowned_epoch,
                desired_revision: desired.desired_revision,
                placement_epoch: desired.placement.placement_epoch,
                lease_duration_ms,
            },
        },
    }
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

fn checkpoint_eq_except_updated_at(stored: &RuntimeCheckpoint, fresh: &RuntimeCheckpoint) -> bool {
    let mut stored = stored.clone();
    stored.updated_at_unix_ms = fresh.updated_at_unix_ms;
    stored == *fresh
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

fn provision_checkpoint_is_bound(
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
    let authority_matches = matches!(
        &observed_volume.authority,
        VolumeAuthorityEvidence::Owned {
            attachment_id: observed_attachment_id,
            attachment_epoch: observed_attachment_epoch,
            head,
        } if observed_attachment_id == attachment_id
            && observed_attachment_epoch == attachment_epoch
            && head == expected_blank_head
    );
    let observed_volume_matches = observed_volume.volume_intent_id.as_ref()
        == Some(&volume.volume_intent_id)
        && observed_volume.disk_id.as_ref() == Some(&volume.disk_id)
        && observed_volume.volume_id == volume.volume_id
        && observed_volume.disk_kind == ObservedDiskKind::Root
        && observed_volume.size_bytes == Some(volume.size_bytes)
        && observed_volume.durability == Some(volume.durability)
        && authority_matches
        && observed_volume.local_lineages
            == [expected_local_lineage(&expected_identity, data_directory)]
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
    use std::collections::VecDeque;
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
    use cats_storage::{encode_image_manifest, BlobError, ImageManifestV1, LowerHexSha256};

    use crate::runtime_spine::{
        RuntimeDesiredEffectAdmission, RuntimeInventoryScanContext, RuntimeInventoryScanOutcome,
        RuntimeSpineFullScan,
    };
    use crate::state_directory::StateDirectory;

    use super::super::{
        clean_slate_scanner_with_volume_authority_for_test, TestCleanSlateProbeConfig,
    };

    use super::*;

    #[derive(Default)]
    struct AcquireState {
        outcomes: VecDeque<NormalAcquireAttempt>,
        requests: Vec<RuntimeVolumeTransitionRequest>,
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
        loads: AtomicUsize,
    }

    impl FakeAuthority {
        fn new(record: Result<VolumeRecord, AuthorityError>) -> Self {
            Self {
                record: Mutex::new(record),
                loads: AtomicUsize::new(0),
            }
        }

        fn set(&self, record: Result<VolumeRecord, AuthorityError>) {
            *self.record.lock().unwrap() = record;
        }
    }

    impl VolumeDataAuthority for FakeAuthority {
        fn load_volume(&self, _volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
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
        let state = Arc::new(Mutex::new(AcquireState {
            outcomes: outcomes.into(),
            checkpoint_path: Some(checkpoint_path),
            ..AcquireState::default()
        }));
        let port: Arc<dyn SignedNormalAcquirePort> = Arc::new(FakeAcquire {
            state: Arc::clone(&state),
        });
        let effect = SignedRunningAcquireEffect::new(port, authority, blob, 60_000).unwrap();
        // Ensure the fixture itself remains bound to the constructor budget.
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
        assert_eq!(restart_calls.lock().unwrap().requests.len(), 1);
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
        assert_eq!(restart_calls.lock().unwrap().requests.len(), 1);
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

        assert_eq!(
            restart_effect.apply(restart_context, &desired).unwrap(),
            stop_local()
        );
        assert!(calls.lock().unwrap().requests.is_empty());
        assert_eq!(std::fs::read(identity_path).unwrap(), foreign_bytes);
        assert!(matches!(
            read_checkpoint(&checkpoint_path).step,
            ReconcileStep::AcquireVolume { .. }
        ));
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
        assert_eq!(calls.requests.len(), 2);
        assert_eq!(calls.requests[0], calls.requests[1]);
        assert_eq!(calls.checkpoint_seen_before_call, [true, true]);
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
            std::fs::create_dir(directory).unwrap();
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
