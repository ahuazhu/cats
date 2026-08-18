//! One-effect convergence from an authoritative provision target to a sealed
//! serving handoff.
//!
//! This slice owns only the current exact `ProvisionRootImage` target phase.
//! It publishes the target-control artifact, starts/adopts a strict target
//! wrapper, or seals the handoff record—never more than one physical effect
//! from one accepted full inventory. The production dispatcher may consume a
//! returned `Ready` only by the CAS-only `PrepareDevice` effect below; neither
//! slice creates serving/device/VMM/network state in that round.

#[cfg(target_os = "linux")]
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, encode_runtime_checkpoint, AppliedDesiredEvidence,
    CheckpointEvidence, Condition, ContractVersion, ControlHandshakeEvidence, DesiredRuntimeSpec,
    DirectAuthorizedAttachmentPurpose, DiskKind, FilesystemInitialization, GuestTransportEvidence,
    HostPath, Id, LifecycleAdmission, LocalLineageState, ObservedDiskKind, ObservedRuntimeStatus,
    OwnershipTokenEvidence, PrepareDeviceFrontend, PreparedDeviceInput, ProcessRole, ProcessState,
    ProgressingReason, RandomId128, ReconcileStep, RuntimeCheckpoint, RuntimeTarget,
    RuntimeTransition, ServingAuthorityProvenance, ServingBlockdIdentity, UnixMillis, VolumeAccess,
    VolumeAcquire, VolumeAuthorityEvidence, VolumeDisposition, VolumeIntent, VolumeRecord,
    WarmSnapshotEvidence,
};
use cats_storage::authority::{
    validate_authorized_serving_record, validate_volume_record, AttachmentLineageIdentity,
    VolumeDataAuthority,
};
use cats_storage::BlobStore;

use crate::ch::effective_vhost_user_queues;
use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
};
#[cfg(not(target_os = "linux"))]
use crate::state_directory::StateDirectory;

use super::checkpoint::revalidate_checkpoint_namespace;
use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
#[cfg(target_os = "linux")]
use super::kernel_nbd::{KernelNbdInventoryConfig, KernelNbdInventoryPort};
use super::root_provision_process::{
    retain_target_control_process_start_with_socket_absence, RootProvisionAuthoritySnapshot,
    RootProvisionProcessConflict, RootProvisionProcessEvidence, RootProvisionProcessExpectation,
    RootProvisionProcessGlobalPort, RootProvisionProcessInspection, RootProvisionProcessStart,
    TargetControlProcessPort,
};
use super::serving_handoff::{
    target_control_process_launch_identity, ReopenedServingHandoff,
    ReopenedTargetControlAuthorization, ServingAuthorityTargetEvidence, ServingHandoffReady,
    ServingHandoffRetirementState, ServingHandoffStore, TargetControlAuthorizationReady,
};
use super::signed_running::{
    expected_provision_heads, provision_checkpoint_is_bound, ProvisionHeadRead,
};
use super::{
    AuthorizedBlockdStore, FileCheckpointStore, PreparedAuthorizedBlockd, StoredCheckpoint,
};

const SERVING_SCOPE_PREFIX: &str = "cats-serving-";
const SERVING_SCOPE_SUFFIX: &str = ".service";

/// Frontend facts which are fixed before the device ownership token is
/// allocated. The managed socket path itself is deliberately absent: both
/// control and I/O paths are derived only after the checkpoint's device token
/// exists, so a caller cannot retain the old data-directory child layout.
enum ReservedPrepareFrontends {
    #[cfg(target_os = "linux")]
    KernelNbd {
        device_paths: VecDeque<HostPath>,
        direct: bool,
    },
    VhostUserBlk {
        remaining: usize,
        queues: u16,
        queue_size: u16,
    },
}

impl ReservedPrepareFrontends {
    #[cfg(target_os = "linux")]
    fn kernel_nbd(device_paths: Vec<HostPath>, direct: bool) -> Self {
        Self::KernelNbd {
            device_paths: device_paths.into(),
            direct,
        }
    }

    fn vhost_user_blk(count: usize, queues: u16, queue_size: u16) -> Self {
        Self::VhostUserBlk {
            remaining: count,
            queues,
            queue_size,
        }
    }

    fn next(&mut self, ownership_token: &RandomId128) -> anyhow::Result<PrepareDeviceFrontend> {
        let sockets = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .serving_paths(ownership_token)
            .context("derive managed serving blockd socket paths")?;
        match self {
            #[cfg(target_os = "linux")]
            Self::KernelNbd {
                device_paths,
                direct,
            } => Ok(PrepareDeviceFrontend::KernelNbd {
                listener_socket_path: sockets.io_socket().clone(),
                device_path: device_paths
                    .pop_front()
                    .context("managed kernel-NBD plan omitted one reserved device")?,
                direct: *direct,
            }),
            Self::VhostUserBlk {
                remaining,
                queues,
                queue_size,
            } => {
                *remaining = remaining
                    .checked_sub(1)
                    .context("managed vhost-user plan omitted one frontend")?;
                Ok(PrepareDeviceFrontend::VhostUserBlk {
                    socket_path: sockets.io_socket().clone(),
                    queues: *queues,
                    queue_size: *queue_size,
                })
            }
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            Self::KernelNbd { device_paths, .. } => device_paths.is_empty(),
            Self::VhostUserBlk { remaining, .. } => *remaining == 0,
        }
    }
}

fn acquired_attachment_identity(
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
    record: &VolumeRecord,
) -> anyhow::Result<AttachmentLineageIdentity> {
    anyhow::ensure!(
        record.lease_owner.as_ref() == Some(&intent.attachment_id)
            && record.lease_expires_at.is_some(),
        "PrepareDevice authority changed owner or lost its lease"
    );
    let (attachment_epoch, acquire_origin) = match &intent.acquire {
        VolumeAcquire::Normal {
            transition_id,
            expected_unowned_epoch,
        } => {
            let attachment_epoch = expected_unowned_epoch
                .get()
                .checked_add(1)
                .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
                .context("PrepareDevice normal-acquire epoch overflowed")?;
            anyhow::ensure!(
                record.lease_epoch == attachment_epoch,
                "PrepareDevice normal-acquire epoch changed"
            );
            (
                attachment_epoch,
                cats_api::runtime_reconciliation::AcquireOrigin::Normal {
                    transition_id: transition_id.clone(),
                },
            )
        }
        VolumeAcquire::Takeover { authorization_id } => (
            record.lease_epoch,
            cats_api::runtime_reconciliation::AcquireOrigin::Takeover {
                authorization_id: authorization_id.clone(),
            },
        ),
    };
    Ok(AttachmentLineageIdentity {
        volume_id: intent.volume_id.clone(),
        attachment_id: intent.attachment_id.clone(),
        attachment_epoch,
        acquire_origin,
        node_id: desired.placement.node_id.clone(),
        placement_epoch: desired.placement.placement_epoch,
    })
}

/// Frozen Node-local frontend inputs for the one durable transition from a
/// sealed Root handoff to `PrepareDevice`. The wider Cloud Hypervisor config
/// is projected once at production composition; the effect cannot silently
/// choose a different block path later.
#[derive(Debug, Clone)]
pub(crate) enum ServingPrepareFrontend {
    #[cfg(target_os = "linux")]
    KernelNbd {
        port: KernelNbdInventoryPort,
        direct: bool,
    },
    #[cfg(not(target_os = "linux"))]
    KernelNbdUnsupported,
    VhostUserBlk {
        maximum_queues: usize,
        queue_size: u16,
    },
}

impl ServingPrepareFrontend {
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn kernel_nbd(
        state_directory: StateDirectory,
        nbd_client_binary: std::path::PathBuf,
        device_count: u32,
        direct: bool,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            nbd_client_binary.is_absolute(),
            "kernel-NBD client binary must be absolute"
        );
        anyhow::ensure!(device_count > 0, "kernel-NBD pool must not be empty");
        let _ = (state_directory, nbd_client_binary, direct);
        Ok(Self::KernelNbdUnsupported)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn kernel_nbd_from_inventory(
        config: KernelNbdInventoryConfig,
        direct: bool,
    ) -> Self {
        Self::KernelNbd {
            port: KernelNbdInventoryPort::new(config),
            direct,
        }
    }

    pub(crate) fn vhost_user_blk(maximum_queues: usize, queue_size: u16) -> anyhow::Result<Self> {
        cats_blockd::frontend_contract::validate_authorized_vhost_shape(maximum_queues, queue_size)
            .context(
                "vhost-user queue maximum or size is outside the authorized-serving contract",
            )?;
        Ok(Self::VhostUserBlk {
            maximum_queues,
            queue_size,
        })
    }
}

/// The only durable effect allowed after [`ServingHandoffEffect`] returns
/// `Ready`. It creates no process, socket or device; the new checkpoint is the
/// recovery authority for those later one-effect rounds.
pub(crate) struct ServingPrepareDeviceEffect {
    frontend: ServingPrepareFrontend,
    executable_path: HostPath,
    authority: Option<Arc<dyn VolumeDataAuthority>>,
    #[cfg(test)]
    before_replace: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    after_replace: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ServingPrepareDeviceEffect {
    pub(crate) fn new(
        frontend: ServingPrepareFrontend,
        executable_path: HostPath,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            Path::new(executable_path.as_str()).is_absolute(),
            "serving PrepareDevice blockd executable must be absolute"
        );
        Ok(Self {
            frontend,
            executable_path,
            authority: None,
            #[cfg(test)]
            before_replace: None,
            #[cfg(test)]
            after_replace: None,
        })
    }

    pub(crate) fn with_volume_authority(mut self, authority: Arc<dyn VolumeDataAuthority>) -> Self {
        self.authority = Some(authority);
        self
    }

    fn retain_persistent_authorizations(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Vec<PreparedAuthorizedBlockd>> {
        if desired.volumes.len() == 1 {
            return Ok(Vec::new());
        }
        let authority = self
            .authority
            .as_ref()
            .context("multi-volume PrepareDevice lacks production Volume authority")?;
        let blockd = AuthorizedBlockdStore::new(context.state_directory().clone());
        let mut retained = Vec::with_capacity(desired.volumes.len() - 1);
        for intent in desired.volumes.iter().skip(1) {
            context.check_active()?;
            let record = authority.load_volume(&intent.volume_id).with_context(|| {
                format!("load PrepareDevice authority for {}", intent.volume_id)
            })?;
            validate_volume_record(&record)
                .context("validate PrepareDevice Persistent authority")?;
            let identity = acquired_attachment_identity(desired, intent, &record)?;
            let prepared = blockd
                .reopen_adopted(desired, intent, &identity)
                .context("reopen exact Persistent authorized blockd artifact")?;
            validate_authorized_serving_record(&record, &prepared.checkpoint().attachment, None)
                .context("Persistent authorized artifact conflicts with current Volume")?;
            retained.push(prepared);
        }
        Ok(retained)
    }

    fn retain_direct_authorizations(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Vec<PreparedAuthorizedBlockd>> {
        let authority = self
            .authority
            .as_ref()
            .context("direct PrepareDevice lacks production Volume authority")?;
        let blockd = AuthorizedBlockdStore::new(context.state_directory().clone());
        let mut retained = Vec::with_capacity(desired.volumes.len());
        for intent in &desired.volumes {
            context.check_active()?;
            let record = authority
                .load_volume(&intent.volume_id)
                .with_context(|| format!("load direct authority for {}", intent.volume_id))?;
            validate_volume_record(&record).context("validate direct PrepareDevice authority")?;
            let identity = acquired_attachment_identity(desired, intent, &record)?;
            let prepared = blockd
                .reopen_adopted(desired, intent, &identity)
                .context("reopen exact direct authorized blockd artifact")?;
            validate_authorized_serving_record(&record, &prepared.checkpoint().attachment, None)
                .context("direct authorized artifact conflicts with current Volume")?;
            retained.push(prepared);
        }
        Ok(retained)
    }

    fn revalidate_retained_authorizations(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        first_slot: usize,
        retained: &[PreparedAuthorizedBlockd],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            desired.volumes.len().saturating_sub(first_slot) == retained.len(),
            "PrepareDevice authority revalidation set is incomplete"
        );
        if retained.is_empty() {
            return context.check_active();
        }
        let authority = self
            .authority
            .as_ref()
            .context("PrepareDevice authority revalidation is not configured")?;
        for (intent, prepared) in desired.volumes.iter().skip(first_slot).zip(retained) {
            context.check_active()?;
            // Reopen from the retained, flocked attachment directory and
            // double-sample the immutable authorization again. This proves
            // that the builder's prior identity is still the same inode and
            // bytes at the publication barrier.
            let _identity = prepared.direct_authorization_identity()?;
            let record = authority.load_volume(&intent.volume_id).with_context(|| {
                format!("reread PrepareDevice authority for {}", intent.volume_id)
            })?;
            validate_authorized_serving_record(&record, &prepared.checkpoint().attachment, None)
                .context("PrepareDevice authority drifted before checkpoint CAS")?;
        }
        context.check_active()
    }

    pub(crate) fn try_persist_direct_existing(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
    ) -> anyhow::Result<Option<RuntimeDesiredEffectOutcome>> {
        let accepted = context.accepted_full()?;
        let Some(runtime) = unique_runtime(&accepted.observation().runtimes, desired)? else {
            return Ok(None);
        };
        if !matches!(runtime.step, ReconcileStep::AcquireVolume { .. }) {
            return Ok(None);
        }
        if !checkpoint_is_current_exact(desired, runtime)
            || !base_admission_is_exact(accepted, desired, runtime)
            || !runtime.processes.is_empty()
            || runtime.volumes.len() != desired.volumes.len()
        {
            return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::LocalContract,
            )));
        }
        if runtime.volumes.iter().any(|volume| {
            volume.devices.is_empty()
                && (volume.local_lineages.is_empty()
                    || !matches!(volume.authority, VolumeAuthorityEvidence::Owned { .. }))
        }) {
            // `AcquireVolume` is also the durable bridge for the sequential
            // authorization producer. An unowned volume, or an owned volume
            // whose artifact publication was interrupted, remains the
            // acquire effect's responsibility. The direct existing-Root
            // producer becomes applicable only after the scanner projects
            // one retained lineage for every Desired volume.
            return Ok(None);
        }
        if runtime.volumes.iter().any(|volume| {
            !volume.devices.is_empty()
                || volume.local_lineages.len() != 1
                || !matches!(volume.authority, VolumeAuthorityEvidence::Owned { .. })
        }) {
            return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::LocalContract,
            )));
        }
        let Some(root) = runtime
            .volumes
            .iter()
            .find(|volume| volume.volume_id == desired.volumes[0].volume_id)
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::LocalContract,
            )));
        };
        let VolumeAuthorityEvidence::Owned { head, .. } = &root.authority else {
            unreachable!("direct admission checked owned authority")
        };
        if head.generation.get() == 0 {
            return Ok(None);
        }

        // Acquire every attachment lock in canonical slot order before the
        // checkpoint writer and optional Node-global NBD allocator.
        let prepared = self.retain_direct_authorizations(context, desired)?;
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let state_root = context.state_directory().try_clone_directory()?;
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &checkpoint_directory,
            &desired.cat_id,
        )?;
        revalidate_checkpoint_namespace(
            &state_root,
            CHECKPOINT_NAMESPACE,
            &[store.retained_directory()],
        )?;
        let Some(stored) = store.load()? else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        let CheckpointEvidence::Valid {
            checkpoint_path,
            content_digest,
            ..
        } = &runtime.checkpoint
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        };
        if Path::new(checkpoint_path.as_str()) != store.path()
            || stored.content_digest() != content_digest
            || stored.checkpoint().step != runtime.step
        {
            return Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()));
        }

        match &self.frontend {
            #[cfg(target_os = "linux")]
            ServingPrepareFrontend::KernelNbd { port, direct } => {
                port.reserve_set_and_replace(
                    context,
                    &store,
                    &stored,
                    desired.volumes.len(),
                    |device_paths| {
                        prepare_direct_device_successor(
                            desired,
                            &stored,
                            &prepared,
                            ReservedPrepareFrontends::kernel_nbd(device_paths, *direct),
                            &self.executable_path,
                        )
                    },
                    || {
                        #[cfg(test)]
                        if let Some(hook) = &self.before_replace {
                            hook();
                        }
                        self.revalidate_retained_authorizations(context, desired, 0, &prepared)
                    },
                )?;
            }
            #[cfg(not(target_os = "linux"))]
            ServingPrepareFrontend::KernelNbdUnsupported => {
                anyhow::bail!("kernel-NBD PrepareDevice composition requires Linux")
            }
            ServingPrepareFrontend::VhostUserBlk {
                maximum_queues,
                queue_size,
            } => {
                let queues = u16::try_from(effective_vhost_user_queues(
                    *maximum_queues,
                    desired.runtime.vcpus,
                ))?;
                cats_blockd::frontend_contract::validate_authorized_vhost_shape(
                    usize::from(queues),
                    *queue_size,
                )?;
                let successor = prepare_direct_device_successor(
                    desired,
                    &stored,
                    &prepared,
                    ReservedPrepareFrontends::vhost_user_blk(
                        desired.volumes.len(),
                        queues,
                        *queue_size,
                    ),
                    &self.executable_path,
                )?;
                context.check_active()?;
                #[cfg(test)]
                if let Some(hook) = &self.before_replace {
                    hook();
                }
                revalidate_checkpoint_namespace(
                    &state_root,
                    CHECKPOINT_NAMESPACE,
                    &[store.retained_directory()],
                )?;
                self.revalidate_retained_authorizations(context, desired, 0, &prepared)?;
                store.replace(&stored, &successor)?;
                revalidate_checkpoint_namespace(
                    &state_root,
                    CHECKPOINT_NAMESPACE,
                    &[store.retained_directory()],
                )?;
                context.check_active()?;
            }
        }
        Ok(Some(RuntimeDesiredEffectOutcome::refresh_inventory()))
    }

    #[cfg(test)]
    pub(crate) fn with_before_replace(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.before_replace = Some(hook);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_after_replace(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.after_replace = Some(hook);
        self
    }

    pub(crate) fn persist(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        ready: &ServingHandoffReady,
    ) -> anyhow::Result<()> {
        context.check_active()?;
        // `ready` retains Root first; retain Persistents in canonical slot
        // order before acquiring the per-Cat checkpoint writer. This is the
        // global attachment -> checkpoint -> allocator lock order.
        let persistent = self.retain_persistent_authorizations(context, desired)?;
        // `ready` already owns the attachment-directory flock. Preserve the
        // established attachment -> per-Cat checkpoint -> Node-global NBD
        // order. Every filesystem lock in that order is acquired with `NB`,
        // so a competing owner fails this admission instead of forming a
        // wait edge while the retained artifact descriptors stay live.
        let checkpoint_directory = context.state_directory().path().join(CHECKPOINT_NAMESPACE);
        let state_root = context
            .state_directory()
            .try_clone_directory()
            .context("retain Node state root for PrepareDevice publication")?;
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &checkpoint_directory,
            &desired.cat_id,
        )
        .context("open current checkpoint for sealed Root handoff consumption")?;
        revalidate_checkpoint_namespace(
            &state_root,
            CHECKPOINT_NAMESPACE,
            &[store.retained_directory()],
        )
        .context("validate PrepareDevice checkpoint namespace before admission")?;
        let stored = store
            .load()
            .context("load current checkpoint for sealed Root handoff consumption")?
            .context("sealed Root handoff lost its predecessor checkpoint")?;
        anyhow::ensure!(
            stored.content_digest() == &ready.record().checkpoint_content_digest,
            "sealed Root handoff predecessor digest is no longer current"
        );
        anyhow::ensure!(
            ready.record().expected_control_executable_path == self.executable_path
                && ready.old_control_process().executable_path == self.executable_path,
            "sealed Root handoff executable differs from current production blockd config"
        );
        validate_prepare_predecessor(desired, &stored, ready)?;
        context.check_active()?;

        ready.consume_for_prepare_device(&stored, |handoff| match &self.frontend {
            #[cfg(target_os = "linux")]
            ServingPrepareFrontend::KernelNbd { port, direct } => port
                .reserve_set_and_replace(
                    context,
                    &store,
                    &stored,
                    desired.volumes.len(),
                    |device_paths| {
                        prepare_device_successor(
                            desired,
                            &stored,
                            ready,
                            handoff,
                            &persistent,
                            ReservedPrepareFrontends::kernel_nbd(device_paths, *direct),
                        )
                    },
                    || {
                        #[cfg(test)]
                        if let Some(hook) = &self.before_replace {
                            hook();
                        }
                        self.revalidate_retained_authorizations(context, desired, 1, &persistent)
                    },
                )
                .map(|_| ()),
            #[cfg(not(target_os = "linux"))]
            ServingPrepareFrontend::KernelNbdUnsupported => {
                anyhow::bail!("kernel-NBD PrepareDevice composition requires Linux")
            }
            ServingPrepareFrontend::VhostUserBlk {
                maximum_queues,
                queue_size,
            } => {
                let queues = effective_vhost_user_queues(*maximum_queues, desired.runtime.vcpus);
                let queues = u16::try_from(queues)
                    .context("effective vhost-user queue count exceeds the wire range")?;
                cats_blockd::frontend_contract::validate_authorized_vhost_shape(
                    usize::from(queues),
                    *queue_size,
                )
                .context("effective vhost-user shape is outside the authorized-serving contract")?;
                let successor = prepare_device_successor(
                    desired,
                    &stored,
                    ready,
                    handoff,
                    &persistent,
                    ReservedPrepareFrontends::vhost_user_blk(
                        desired.volumes.len(),
                        queues,
                        *queue_size,
                    ),
                )?;
                context.check_active()?;
                #[cfg(test)]
                if let Some(hook) = &self.before_replace {
                    hook();
                }
                revalidate_checkpoint_namespace(
                    &state_root,
                    CHECKPOINT_NAMESPACE,
                    &[store.retained_directory()],
                )
                .context("validate PrepareDevice checkpoint namespace before publication")?;
                self.revalidate_retained_authorizations(context, desired, 1, &persistent)?;
                store
                    .replace(&stored, &successor)
                    .context("atomically replace Root handoff with PrepareDevice")?;
                #[cfg(test)]
                if let Some(hook) = &self.after_replace {
                    hook();
                }
                revalidate_checkpoint_namespace(
                    &state_root,
                    CHECKPOINT_NAMESPACE,
                    &[store.retained_directory()],
                )
                .context("validate PrepareDevice checkpoint namespace after publication")?;
                context.check_active()?;
                Ok(())
            }
        })
    }
}

pub(super) fn checkpoint_is_current_exact(
    desired: &DesiredRuntimeSpec,
    runtime: &ObservedRuntimeStatus,
) -> bool {
    matches!(
        &runtime.checkpoint,
        CheckpointEvidence::Valid {
            version,
            cat_id,
            node_id,
            desired_revision,
            spec_digest,
            placement_epoch,
            runtime_incarnation,
            stable_state,
            step,
            ..
        } if *version == ContractVersion::V1
            && cat_id == &desired.cat_id
            && node_id == &desired.placement.node_id
            && *placement_epoch == desired.placement.placement_epoch
            && *desired_revision == desired.desired_revision
            && spec_digest == &desired.spec_digest
            && runtime_incarnation.is_none()
            && stable_state.is_none()
            && step.as_ref() == &runtime.step
    )
}

fn validate_prepare_predecessor(
    desired: &DesiredRuntimeSpec,
    stored: &StoredCheckpoint,
    ready: &ServingHandoffReady,
) -> anyhow::Result<()> {
    let checkpoint = stored.checkpoint();
    let record = ready.record();
    let attachment = &ready.target_control_authorization().artifact.attachment;
    let Some(intent) = desired
        .volumes
        .first()
        .filter(|intent| intent.disk_kind == DiskKind::Root && intent.guest_device.slot == 0)
    else {
        anyhow::bail!("Root handoff PrepareDevice requires one Desired volume")
    };
    let ReconcileStep::ProvisionRootImage {
        provision_transition_id,
        volume_id,
        attachment_id,
        attachment_epoch,
        data_directory,
        size_bytes,
        expected_provisioned_head,
        ..
    } = &checkpoint.step
    else {
        anyhow::bail!("Root handoff predecessor is not provision_root_image")
    };
    anyhow::ensure!(
        checkpoint.cat_id == desired.cat_id
            && checkpoint.node_id == desired.placement.node_id
            && checkpoint.placement_epoch == desired.placement.placement_epoch
            && checkpoint.desired_revision == desired.desired_revision
            && checkpoint.spec_digest == desired.spec_digest
            && checkpoint.runtime_incarnation.is_none()
            && checkpoint.stable_state.is_none()
            && record.cat_id == desired.cat_id
            && record.node_id == desired.placement.node_id
            && record.placement_epoch == desired.placement.placement_epoch
            && record.desired_revision == desired.desired_revision
            && record.spec_digest == desired.spec_digest,
        "Root handoff predecessor is not the frozen current Desired"
    );
    anyhow::ensure!(
        matches!(intent.disk_kind, DiskKind::Root)
            && matches!(intent.access, VolumeAccess::ReadWriteOnce)
            && matches!(intent.disposition, VolumeDisposition::Retain)
            && *volume_id == intent.volume_id
            && *volume_id == record.volume_id
            && *volume_id == attachment.identity.volume_id
            && *attachment_id == intent.attachment_id
            && *attachment_id == record.attachment_id
            && *attachment_id == attachment.identity.attachment_id
            && *attachment_epoch == record.attachment_epoch
            && *attachment_epoch == attachment.identity.attachment_epoch
            && attachment.identity.acquire_origin == record.acquire_origin
            && *provision_transition_id == record.provision_transition_id
            && *size_bytes == intent.size_bytes
            && *size_bytes == attachment.size_bytes
            && attachment.durability == intent.durability
            && *expected_provisioned_head == record.expected_provisioned_head
            && *expected_provisioned_head == attachment.head
            && *data_directory == ready.old_control_process().data_directory,
        "Root handoff predecessor, target artifact and Desired lineage disagree"
    );
    Ok(())
}

fn prepare_device_successor(
    desired: &DesiredRuntimeSpec,
    stored: &StoredCheckpoint,
    ready: &ServingHandoffReady,
    handoff: cats_api::runtime_reconciliation::RootServingHandoff,
    persistent: &[PreparedAuthorizedBlockd],
    mut frontends: ReservedPrepareFrontends,
) -> anyhow::Result<RuntimeCheckpoint> {
    validate_prepare_predecessor(desired, stored, ready)?;
    let Some(root_intent) = desired.volumes.first() else {
        unreachable!("predecessor validation requires one Root volume")
    };
    anyhow::ensure!(
        persistent.len() + 1 == desired.volumes.len(),
        "PrepareDevice successor lacks the complete authorization set"
    );
    let root_attachment = &ready.target_control_authorization().artifact.attachment;
    let old_process = ready.old_control_process();
    let mut excluded = vec![old_process.ownership_token.clone()];
    let mut next_tokens = || -> anyhow::Result<(RandomId128, RandomId128)> {
        let references = excluded.iter().collect::<Vec<_>>();
        let process = fresh_identity_token(&references)?;
        excluded.push(process.clone());
        let references = excluded.iter().collect::<Vec<_>>();
        let device = fresh_identity_token(&references)?;
        excluded.push(device.clone());
        Ok((process, device))
    };
    let (root_process_token, root_ownership_token) = next_tokens()?;
    let root_frontend = frontends.next(&root_ownership_token)?;
    let root_sockets = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
        .serving_paths(&root_ownership_token)
        .context("derive managed Root serving socket paths")?;
    let root_scope = Id::new(format!(
        "{SERVING_SCOPE_PREFIX}{}{SERVING_SCOPE_SUFFIX}",
        root_process_token.as_str()
    ))
    .context("fresh Root serving token does not form a canonical scope")?;
    let mut devices = Vec::with_capacity(desired.volumes.len());
    devices.push(PreparedDeviceInput {
        volume_intent_id: root_intent.volume_intent_id.clone(),
        disk_id: root_intent.disk_id.clone(),
        volume_id: root_attachment.identity.volume_id.clone(),
        disk_kind: root_intent.disk_kind,
        attachment_id: root_attachment.identity.attachment_id.clone(),
        attachment_epoch: root_attachment.identity.attachment_epoch,
        acquire_origin: root_attachment.identity.acquire_origin.clone(),
        expected_head: root_attachment.head.clone(),
        size_bytes: root_attachment.size_bytes,
        durability: root_attachment.durability,
        guest_device: root_intent.guest_device.clone(),
        ownership_token: root_ownership_token,
        serving_authority: Box::new(ServingAuthorityProvenance::AfterRootProvision { handoff }),
        serving_process: ServingBlockdIdentity {
            scope_id: root_scope,
            control_socket_path: root_sockets.control_socket().clone(),
            data_directory: old_process.data_directory.clone(),
            executable_path: ready.record().expected_control_executable_path.clone(),
            process_identity_token: root_process_token,
        },
        frontend: root_frontend,
    });

    for (intent, prepared) in desired.volumes.iter().skip(1).zip(persistent) {
        let attachment = &prepared.checkpoint().attachment;
        anyhow::ensure!(
            prepared.checkpoint().volume == *intent
                && attachment.identity.volume_id == intent.volume_id
                && attachment.identity.attachment_id == intent.attachment_id
                && attachment.size_bytes == intent.size_bytes
                && attachment.durability == intent.durability,
            "Persistent retained authorization changed Desired identity"
        );
        let observed = stored
            .checkpoint()
            .volumes
            .iter()
            .find(|observed| observed.volume_id == intent.volume_id)
            .context("Root handoff predecessor omitted one Persistent Volume")?;
        let [lineage] = observed.local_lineages.as_slice() else {
            anyhow::bail!("Persistent Volume lacks one exact retained lineage")
        };
        anyhow::ensure!(
            matches!(
                &observed.authority,
                VolumeAuthorityEvidence::Owned {
                    attachment_id,
                    attachment_epoch,
                    head,
                } if attachment_id == &attachment.identity.attachment_id
                    && *attachment_epoch == attachment.identity.attachment_epoch
                    && head == &attachment.head
            ) && lineage.attachment_id == attachment.identity.attachment_id
                && lineage.attachment_epoch == attachment.identity.attachment_epoch
                && lineage.acquire_origin == attachment.identity.acquire_origin
                && lineage.local_durable_generation == attachment.head.generation
                && lineage.remote_durable_generation == attachment.head.generation
                && lineage.data_directory
                    == host_path(
                        prepared.data_directory(),
                        "Persistent retained data directory",
                    )?
                && lineage.pending_pack_count.get() == 0
                && !lineage.fenced
                && lineage.state == LocalLineageState::Active,
            "Persistent retained artifact and checkpoint lineage disagree"
        );
        let mount = intent
            .mount
            .as_ref()
            .context("Persistent PrepareDevice intent lacks its mount")?;
        let purpose = match &mount.initialization {
            FilesystemInitialization::Existing => {
                anyhow::ensure!(
                    attachment.head.generation.get() > 0,
                    "Existing Persistent authority is blank"
                );
                DirectAuthorizedAttachmentPurpose::PersistentInitialized
            }
            FilesystemInitialization::Initialize { .. }
                if attachment.head.generation.get() == 0 =>
            {
                DirectAuthorizedAttachmentPurpose::PersistentUninitialized
            }
            FilesystemInitialization::Initialize { .. } => {
                DirectAuthorizedAttachmentPurpose::PersistentInitialized
            }
        };
        let authorization = prepared.direct_authorization_identity()?;
        let data_directory = host_path(
            prepared.data_directory(),
            "Persistent serving data directory",
        )?;
        let (process_identity_token, ownership_token) = next_tokens()?;
        let frontend = frontends.next(&ownership_token)?;
        let sockets = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .serving_paths(&ownership_token)
            .context("derive managed Persistent serving socket paths")?;
        let scope_id = Id::new(format!(
            "{SERVING_SCOPE_PREFIX}{}{SERVING_SCOPE_SUFFIX}",
            process_identity_token.as_str()
        ))
        .context("fresh Persistent serving token does not form a canonical scope")?;
        devices.push(PreparedDeviceInput {
            volume_intent_id: intent.volume_intent_id.clone(),
            disk_id: intent.disk_id.clone(),
            volume_id: intent.volume_id.clone(),
            disk_kind: intent.disk_kind,
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            acquire_origin: attachment.identity.acquire_origin.clone(),
            expected_head: attachment.head.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            guest_device: intent.guest_device.clone(),
            ownership_token,
            serving_authority: Box::new(ServingAuthorityProvenance::DirectAuthorizedAttachment {
                authorization,
                purpose,
            }),
            serving_process: ServingBlockdIdentity {
                scope_id,
                control_socket_path: sockets.control_socket().clone(),
                data_directory,
                executable_path: ready.record().expected_control_executable_path.clone(),
                process_identity_token,
            },
            frontend,
        });
    }
    anyhow::ensure!(
        devices.len() == desired.volumes.len() && frontends.is_empty(),
        "PrepareDevice successor did not consume every Desired frontend"
    );
    let mut checkpoint = stored.checkpoint().clone();
    checkpoint.step = ReconcileStep::PrepareDevice { devices };
    let Some(observed) = checkpoint
        .volumes
        .iter_mut()
        .find(|observed| observed.volume_id == root_intent.volume_id)
    else {
        anyhow::bail!("Root handoff predecessor does not carry one observed volume")
    };
    anyhow::ensure!(
        observed.volume_id == root_intent.volume_id
            && observed.disk_kind == ObservedDiskKind::Root
            && observed.size_bytes == Some(root_attachment.size_bytes)
            && observed.durability == Some(root_attachment.durability)
            && !observed.local_lineages.is_empty(),
        "Root handoff predecessor observed volume is not the frozen Root lineage"
    );
    observed.authority = VolumeAuthorityEvidence::Owned {
        attachment_id: root_attachment.identity.attachment_id.clone(),
        attachment_epoch: root_attachment.identity.attachment_epoch,
        head: root_attachment.head.clone(),
    };
    for lineage in &mut observed.local_lineages {
        anyhow::ensure!(
            lineage.attachment_id == root_attachment.identity.attachment_id
                && lineage.attachment_epoch == root_attachment.identity.attachment_epoch
                && lineage.acquire_origin == root_attachment.identity.acquire_origin
                && lineage.data_directory == old_process.data_directory
                && lineage.state == LocalLineageState::Active
                && !lineage.fenced,
            "Root handoff predecessor contains another local lineage"
        );
        lineage.local_durable_generation = root_attachment.head.generation;
        lineage.remote_durable_generation = root_attachment.head.generation;
    }
    checkpoint.updated_at_unix_ms = monotonic_wall_clock(stored)?;
    encode_runtime_checkpoint(&checkpoint)
        .context("constructed Root handoff PrepareDevice checkpoint is not canonical V1")?;
    Ok(checkpoint)
}

fn prepare_direct_device_successor(
    desired: &DesiredRuntimeSpec,
    stored: &StoredCheckpoint,
    prepared: &[PreparedAuthorizedBlockd],
    mut frontends: ReservedPrepareFrontends,
    executable_path: &HostPath,
) -> anyhow::Result<RuntimeCheckpoint> {
    anyhow::ensure!(
        prepared.len() == desired.volumes.len()
            && stored.checkpoint().volumes.len() == desired.volumes.len(),
        "direct PrepareDevice successor lacks its complete canonical authorization set"
    );
    let mut excluded = Vec::<RandomId128>::new();
    let mut devices = Vec::with_capacity(desired.volumes.len());
    for ((index, intent), retained) in desired.volumes.iter().enumerate().zip(prepared) {
        let attachment = &retained.checkpoint().attachment;
        let observed = &stored.checkpoint().volumes[index];
        let [lineage] = observed.local_lineages.as_slice() else {
            anyhow::bail!("direct PrepareDevice volume lacks one exact retained lineage")
        };
        let expected_disk_kind = match intent.disk_kind {
            DiskKind::Root => ObservedDiskKind::Root,
            DiskKind::Persistent => ObservedDiskKind::Persistent,
        };
        let data_directory = host_path(retained.data_directory(), "direct serving data directory")?;
        anyhow::ensure!(
            retained.checkpoint().volume == *intent
                && attachment.identity.volume_id == intent.volume_id
                && attachment.identity.attachment_id == intent.attachment_id
                && attachment.size_bytes == intent.size_bytes
                && attachment.durability == intent.durability
                && observed.volume_intent_id.as_ref() == Some(&intent.volume_intent_id)
                && observed.disk_id.as_ref() == Some(&intent.disk_id)
                && observed.volume_id == intent.volume_id
                && observed.disk_kind == expected_disk_kind
                && observed.size_bytes == Some(attachment.size_bytes)
                && observed.durability == Some(attachment.durability)
                && observed.devices.is_empty()
                && matches!(
                    &observed.authority,
                    VolumeAuthorityEvidence::Owned {
                        attachment_id,
                        attachment_epoch,
                        head,
                    } if attachment_id == &attachment.identity.attachment_id
                        && *attachment_epoch == attachment.identity.attachment_epoch
                        && head == &attachment.head
                )
                && lineage.attachment_id == attachment.identity.attachment_id
                && lineage.attachment_epoch == attachment.identity.attachment_epoch
                && lineage.acquire_origin == attachment.identity.acquire_origin
                && lineage.node_id == attachment.identity.node_id
                && lineage.placement_epoch == attachment.identity.placement_epoch
                && lineage.local_durable_generation == attachment.head.generation
                && lineage.remote_durable_generation == attachment.head.generation
                && lineage.pending_pack_count.get() == 0
                && lineage.data_directory == data_directory
                && !lineage.fenced
                && lineage.state == LocalLineageState::Active,
            "direct retained authorization, checkpoint lineage, and Desired disagree"
        );
        let purpose = if index == 0 {
            anyhow::ensure!(
                intent.disk_kind == DiskKind::Root && attachment.head.generation.get() > 0,
                "direct Root must be an existing nonblank Root"
            );
            DirectAuthorizedAttachmentPurpose::ExistingRoot
        } else {
            let mount = intent
                .mount
                .as_ref()
                .context("direct Persistent lacks its mount intent")?;
            match &mount.initialization {
                FilesystemInitialization::Existing => {
                    anyhow::ensure!(
                        attachment.head.generation.get() > 0,
                        "Existing Persistent direct authority is blank"
                    );
                    DirectAuthorizedAttachmentPurpose::PersistentInitialized
                }
                FilesystemInitialization::Initialize { .. }
                    if attachment.head.generation.get() == 0 =>
                {
                    DirectAuthorizedAttachmentPurpose::PersistentUninitialized
                }
                FilesystemInitialization::Initialize { .. } => {
                    DirectAuthorizedAttachmentPurpose::PersistentInitialized
                }
            }
        };
        let references = excluded.iter().collect::<Vec<_>>();
        let process_identity_token = fresh_identity_token(&references)?;
        excluded.push(process_identity_token.clone());
        let references = excluded.iter().collect::<Vec<_>>();
        let ownership_token = fresh_identity_token(&references)?;
        excluded.push(ownership_token.clone());
        let frontend = frontends.next(&ownership_token)?;
        let sockets = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .serving_paths(&ownership_token)
            .context("derive managed direct serving socket paths")?;
        devices.push(PreparedDeviceInput {
            volume_intent_id: intent.volume_intent_id.clone(),
            disk_id: intent.disk_id.clone(),
            volume_id: intent.volume_id.clone(),
            disk_kind: intent.disk_kind,
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            acquire_origin: attachment.identity.acquire_origin.clone(),
            expected_head: attachment.head.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            guest_device: intent.guest_device.clone(),
            ownership_token,
            serving_authority: Box::new(ServingAuthorityProvenance::DirectAuthorizedAttachment {
                authorization: retained.direct_authorization_identity()?,
                purpose,
            }),
            serving_process: ServingBlockdIdentity {
                scope_id: Id::new(format!(
                    "{SERVING_SCOPE_PREFIX}{}{SERVING_SCOPE_SUFFIX}",
                    process_identity_token.as_str()
                ))
                .context("direct serving token does not form a canonical scope")?,
                control_socket_path: sockets.control_socket().clone(),
                data_directory,
                executable_path: executable_path.clone(),
                process_identity_token,
            },
            frontend,
        });
    }
    anyhow::ensure!(
        frontends.is_empty(),
        "direct PrepareDevice successor did not consume every managed frontend"
    );
    let mut checkpoint = stored.checkpoint().clone();
    checkpoint.step = ReconcileStep::PrepareDevice { devices };
    checkpoint.updated_at_unix_ms = monotonic_wall_clock(stored)?;
    encode_runtime_checkpoint(&checkpoint)
        .context("constructed direct PrepareDevice checkpoint is not canonical V1")?;
    Ok(checkpoint)
}

fn fresh_identity_token(excluded: &[&RandomId128]) -> anyhow::Result<RandomId128> {
    let token = RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
        .context("generate fresh Runtime physical identity token")?;
    anyhow::ensure!(
        excluded.iter().all(|candidate| **candidate != token),
        "fresh Runtime physical identity token collided with retained authority"
    );
    Ok(token)
}

fn host_path(path: &Path, label: &str) -> anyhow::Result<HostPath> {
    HostPath::new(
        path.to_str()
            .with_context(|| format!("{label} is not UTF-8"))?
            .to_owned(),
    )
    .with_context(|| format!("{label} is not a canonical absolute HostPath"))
}

fn monotonic_wall_clock(stored: &StoredCheckpoint) -> anyhow::Result<UnixMillis> {
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
        .context("PrepareDevice checkpoint timestamp exhausted")?;
    UnixMillis::new(wall_clock_ms.max(minimum))
        .context("PrepareDevice checkpoint timestamp is outside the Runtime wire range")
}

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
        if !checkpoint_is_current_exact(desired, runtime) {
            return Ok(ServingHandoffEffectProgress::NotApplicable);
        }
        anyhow::ensure!(
            base_admission_is_exact(accepted, desired, runtime),
            "serving handoff lacks an exact current ProvisionRootImage admission"
        );
        let Some(volume) = desired
            .volumes
            .first()
            .filter(|volume| volume.disk_kind == DiskKind::Root && volume.guest_device.slot == 0)
        else {
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
        if observed_head == blank {
            return Ok(ServingHandoffEffectProgress::NotApplicable);
        }
        anyhow::ensure!(
            observed_head == target,
            "serving handoff accepted authority is not the exact provision target"
        );
        let _node_global_effect = context.lock_node_global_effect()?;

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
        let expectation = base_expectation.with_target_control_launch(
            target_control_process_launch_identity(target_ready.identity()),
        )?;
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
        let Some(socket_absence) = self
            .global_process
            .retain_start_socket_absence(expectation, context)?
        else {
            return Ok(());
        };
        self.reread_same_target(context, first_authority, target)?;
        let permit = retain_target_control_process_start_with_socket_absence(
            checkpoint_store,
            stored,
            expectation,
            target_ready,
            socket_absence,
        )?;
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
        let _node_global_effect = context.lock_node_global_effect()?;
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
        let _node_global_effect = context.lock_node_global_effect()?;
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
        && (1..=64).contains(&desired.volumes.len())
        && desired.placement.node_id == accepted.session().node_id
        && desired.volumes.iter().enumerate().all(|(index, volume)| {
            volume.access == VolumeAccess::ReadWriteOnce
                && matches!(volume.disposition, VolumeDisposition::Retain)
                && usize::from(volume.guest_device.slot) == index
                && match index {
                    0 => volume.disk_kind == DiskKind::Root && volume.mount.is_none(),
                    _ => volume.disk_kind == DiskKind::Persistent && volume.mount.is_some(),
                }
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
        && runtime.volumes.len() == desired.volumes.len()
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
    let observed = runtime
        .volumes
        .iter()
        .find(|observed| observed.volume_id == volume.volume_id)?;
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        checkpoint_content_digest, spec_digest, AcquireOrigin, AdmissionInventoryAttestation,
        AgentSession, AssignedKind, AssignedPlacement, Durability, Epoch, Ext4MountIntent,
        FenceEpoch, FilesystemInitialization, Generation, GuestDeviceIdentity, Ipv4Address,
        IsolatedIpv4Kind, MacAddress, NetworkConfig, NodeBootId, NodeObservation,
        NormalAcquireRequest, NormalAcquireResult, Revision, RuntimeConfig, RuntimeLaunch,
        Sequence, Sha256Digest, TakeoverConsumedReceipt, VolumeAdminState,
        VolumeTakeoverAuthorization,
    };
    use cats_storage::authority::{
        AuthorityError, AuthorizedServingAcquire, AuthorizedServingAttachment, RenewLeaseRequest,
        RenewLeaseResult, VolumeHeadCasRequest, VolumeHeadCasResult,
    };

    use crate::runtime_spine::{RuntimeDesiredEffectAdmission, RuntimeDesiredEffectContext};
    use crate::state_directory::StateDirectory;

    use super::super::signed_running::prepared_owned_observed_volume;
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn managed_root_control_socket(provision_transition_id: &RandomId128) -> HostPath {
        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .root_paths(provision_transition_id)
            .unwrap()
            .control_socket()
            .clone()
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

    fn head(
        generation: u64,
        value: u8,
        object: &str,
    ) -> cats_api::runtime_reconciliation::RemoteHead {
        cats_api::runtime_reconciliation::RemoteHead {
            generation: Generation::new(generation).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([value; 32])),
            root_object_id: Some(cats_api::runtime_reconciliation::AsciiText::new(object).unwrap()),
        }
    }

    fn desired() -> DesiredRuntimeSpec {
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: id("ws_01"),
            cat_id: id("cat_01"),
            desired_revision: Revision::new(4).unwrap(),
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
            volumes: vec![
                VolumeIntent {
                    volume_intent_id: id("intent_0_root"),
                    disk_id: id("disk_0_root"),
                    volume_id: id("vol_0_root"),
                    attachment_id: id("att_0_root"),
                    size_bytes: 4 * 1024 * 1024,
                    disk_kind: DiskKind::Root,
                    access: VolumeAccess::ReadWriteOnce,
                    durability: Durability::Strict,
                    guest_device: GuestDeviceIdentity {
                        serial: id("cats-root"),
                        slot: 0,
                    },
                    acquire: VolumeAcquire::Normal {
                        transition_id: random('1'),
                        expected_unowned_epoch: fence(0),
                    },
                    disposition: VolumeDisposition::Retain,
                    mount: None,
                },
                VolumeIntent {
                    volume_intent_id: id("intent_1_persistent"),
                    disk_id: id("disk_1_persistent"),
                    volume_id: id("vol_1_persistent"),
                    attachment_id: id("att_1_persistent"),
                    size_bytes: 4 * 1024 * 1024,
                    disk_kind: DiskKind::Persistent,
                    access: VolumeAccess::ReadWriteOnce,
                    durability: Durability::Strict,
                    guest_device: GuestDeviceIdentity {
                        serial: id("cats-persistent"),
                        slot: 1,
                    },
                    acquire: VolumeAcquire::Normal {
                        transition_id: random('2'),
                        expected_unowned_epoch: fence(4),
                    },
                    disposition: VolumeDisposition::Retain,
                    mount: Some(Ext4MountIntent {
                        filesystem_uuid: random('3'),
                        mount_path: HostPath::new("/srv/cats/persistent").unwrap(),
                        initialization: FilesystemInitialization::Existing,
                    }),
                },
            ],
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    }

    fn takeover_desired() -> DesiredRuntimeSpec {
        let mut desired = desired();
        for (index, volume) in desired.volumes.iter_mut().enumerate() {
            volume.acquire = VolumeAcquire::Takeover {
                authorization_id: id(&format!("takeover_auth_{index}")),
            };
        }
        desired.spec_digest = spec_digest(&desired).unwrap();
        desired
    }

    fn attachment(
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        current_head: cats_api::runtime_reconciliation::RemoteHead,
    ) -> AuthorizedServingAttachment {
        let (attachment_epoch, acquire_origin, lease_expires_at, acquire) = match &volume.acquire {
            VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            } => {
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
                    resulting_head: current_head.clone(),
                    lease_expires_at: unix_ms(1_900_000_060_000),
                };
                (
                    result.resulting_epoch,
                    AcquireOrigin::Normal {
                        transition_id: transition_id.clone(),
                    },
                    result.lease_expires_at,
                    AuthorizedServingAcquire::Normal { request, result },
                )
            }
            VolumeAcquire::Takeover { authorization_id } => {
                let expected_epoch = fence(20 + u64::from(volume.guest_device.slot));
                let resulting_epoch = fence(expected_epoch.get() + 1);
                let authorization = VolumeTakeoverAuthorization {
                    authorization_id: authorization_id.clone(),
                    authorized_node_id: desired.placement.node_id.clone(),
                    host_fence_event_id: id("fence_event_takeover"),
                    volume_id: volume.volume_id.clone(),
                    expected_attachment_id: id(&format!(
                        "old_{}",
                        volume.guest_device.serial.as_str()
                    )),
                    expected_epoch,
                    expected_head: current_head.clone(),
                    new_attachment_id: volume.attachment_id.clone(),
                    desired_revision: desired.desired_revision,
                    new_placement_epoch: desired.placement.placement_epoch,
                    lease_duration_ms: 60_000,
                    not_after: unix_ms(1_900_000_030_000),
                };
                let receipt = TakeoverConsumedReceipt {
                    authorization_id: authorization_id.clone(),
                    host_fence_event_id: authorization.host_fence_event_id.clone(),
                    volume_id: volume.volume_id.clone(),
                    new_attachment_id: volume.attachment_id.clone(),
                    resulting_epoch,
                    resulting_head: current_head.clone(),
                    consumed_at: unix_ms(1_900_000_000_000),
                };
                (
                    resulting_epoch,
                    AcquireOrigin::Takeover {
                        authorization_id: authorization_id.clone(),
                    },
                    unix_ms(1_900_000_060_000),
                    AuthorizedServingAcquire::Takeover {
                        authorization,
                        receipt,
                    },
                )
            }
        };
        AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch,
                acquire_origin,
                node_id: desired.placement.node_id.clone(),
                placement_epoch: desired.placement.placement_epoch,
            },
            object_write_credential: None,
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            head: current_head,
            lease_expires_at,
            acquire,
        }
    }

    fn record(attachment: &AuthorizedServingAttachment) -> VolumeRecord {
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

    struct MapAuthority {
        records: Mutex<BTreeMap<Id, VolumeRecord>>,
        loads: AtomicUsize,
    }

    impl VolumeDataAuthority for MapAuthority {
        fn load_volume(&self, volume_id: &Id) -> Result<VolumeRecord, AuthorityError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.records
                .lock()
                .unwrap()
                .get(volume_id)
                .cloned()
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

    fn accepted_context(
        root: &std::path::Path,
        desired: &DesiredRuntimeSpec,
        stored: &StoredCheckpoint,
    ) -> RuntimeDesiredEffectContext {
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
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            inventory_epoch: epoch(4),
            inventory_digest: Sha256Digest::from_bytes([7; 32]),
            inventory_read_position: Sequence::new(12).unwrap(),
            accepted_at_unix_ms: unix_ms(1_900_000_000_000),
        };
        let checkpoint = stored.checkpoint();
        let step = checkpoint.step.clone();
        let runtime = ObservedRuntimeStatus {
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
            checkpoint: CheckpointEvidence::Valid {
                checkpoint_path: HostPath::new(
                    super::super::runtime_checkpoint_path(
                        &root.join(CHECKPOINT_NAMESPACE),
                        &desired.cat_id,
                    )
                    .to_str()
                    .unwrap()
                    .to_owned(),
                )
                .unwrap(),
                content_digest: stored.content_digest().clone(),
                version: checkpoint.version,
                cat_id: checkpoint.cat_id.clone(),
                node_id: checkpoint.node_id.clone(),
                desired_revision: checkpoint.desired_revision,
                spec_digest: checkpoint.spec_digest.clone(),
                placement_epoch: checkpoint.placement_epoch,
                runtime_incarnation: None,
                runtime_launch: Box::new(RuntimeLaunch::Absent),
                stable_state: None,
                step: Box::new(step.clone()),
                require_idle: Box::new(checkpoint.require_idle.clone()),
                updated_at_unix_ms: checkpoint.updated_at_unix_ms,
            },
            processes: Vec::new(),
            volumes: checkpoint.volumes.clone(),
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
        };
        let observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: random('6'),
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(9).unwrap(),
            observed_at_unix_ms: unix_ms(1_899_999_999_000),
            complete_inventory: true,
            inventory_epoch: attestation.inventory_epoch,
            inventory_digest: Some(attestation.inventory_digest.clone()),
            inventory_read_position: Some(attestation.inventory_read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: vec![runtime],
            residue: Vec::new(),
        };
        RuntimeDesiredEffectContext::for_test_with_admission(
            StateDirectory::unanchored(root.to_path_buf()),
            Instant::now() + Duration::from_secs(30),
            RuntimeDesiredEffectAdmission::for_test(session, observation, attestation),
        )
    }

    #[test]
    fn takeover_handoff_and_existing_root_delegate_to_exact_thick_authority() {
        let root = tempfile::tempdir().unwrap();
        let desired = takeover_desired();
        let root_attachment = attachment(&desired, &desired.volumes[0], head(2, 8, "roots/root-2"));
        let persistent_attachment = attachment(
            &desired,
            &desired.volumes[1],
            head(3, 9, "roots/persistent-3"),
        );
        let blockd = AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().into()));
        let root_prepared = blockd
            .prepare(&desired, &desired.volumes[0], &root_attachment)
            .unwrap();
        let persistent_prepared = blockd
            .prepare(&desired, &desired.volumes[1], &persistent_attachment)
            .unwrap();
        let volumes = vec![
            prepared_owned_observed_volume(
                &desired.volumes[0],
                &root_attachment,
                HostPath::new(root_prepared.data_directory().to_str().unwrap().to_owned()).unwrap(),
            ),
            prepared_owned_observed_volume(
                &desired.volumes[1],
                &persistent_attachment,
                HostPath::new(
                    persistent_prepared
                        .data_directory()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                )
                .unwrap(),
            ),
        ];
        drop((root_prepared, persistent_prepared));

        let checkpoint = RuntimeCheckpoint {
            version: ContractVersion::V1,
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            placement_epoch: desired.placement.placement_epoch,
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            runtime_incarnation: None,
            runtime_launch: RuntimeLaunch::Absent,
            stable_state: None,
            step: ReconcileStep::AcquireVolume {
                request: persistent_attachment.checkpoint_acquire_request(),
            },
            processes: Vec::new(),
            volumes,
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            route_gates: Vec::new(),
            require_idle: cats_api::runtime_reconciliation::RequireIdleCheckpoint::NotApplicable,
            updated_at_unix_ms: unix_ms(1_900_000_000_000),
        };
        encode_runtime_checkpoint(&checkpoint).unwrap();
        let store =
            FileCheckpointStore::open(&root.path().join(CHECKPOINT_NAMESPACE), &desired.cat_id)
                .unwrap();
        let stored = store.create(&checkpoint).unwrap();
        drop(store);
        let context = accepted_context(root.path(), &desired, &stored);
        let accepted = context.accepted_full().unwrap();
        let runtime = &accepted.observation().runtimes[0];

        // The generic admission is shared by the existing-Root direct bridge
        // and the post-provision handoff.  It accepts the closed acquire enum,
        // while the retained artifacts below remain the authorization proof.
        assert!(base_admission_is_exact(accepted, &desired, runtime));
        let mut post_provision_runtime = runtime.clone();
        let post_provision_data_directory = post_provision_runtime.volumes[0].local_lineages[0]
            .data_directory
            .clone();
        let provision_transition_id = random('8');
        post_provision_runtime.step = ReconcileStep::ProvisionRootImage {
            provision_transition_id: provision_transition_id.clone(),
            volume_id: desired.volumes[0].volume_id.clone(),
            attachment_id: root_attachment.identity.attachment_id.clone(),
            attachment_epoch: root_attachment.identity.attachment_epoch,
            scope_id: id("cats-root-test.service"),
            control_socket_path: managed_root_control_socket(&provision_transition_id),
            data_directory: post_provision_data_directory.clone(),
            process_identity_token: random('9'),
            size_bytes: root_attachment.size_bytes,
            boot_image_digest: desired.runtime.boot_image_digest.clone(),
            expected_blank_head: cats_api::runtime_reconciliation::RemoteHead {
                generation: Generation::new(0).unwrap(),
                root_hash: None,
                root_object_id: None,
            },
            expected_provisioned_head: root_attachment.head.clone(),
        };
        post_provision_runtime.conditions = vec![Condition::Progressing {
            reason: ProgressingReason::ReconcileStep {
                step: post_provision_runtime.step.clone(),
            },
        }];
        assert!(base_admission_is_exact(
            accepted,
            &desired,
            &post_provision_runtime
        ));
        let (post_provision_identity, post_provision_head) = observed_lineage(
            &post_provision_runtime,
            &desired.volumes[0],
            &post_provision_data_directory,
        )
        .unwrap();
        assert_eq!(post_provision_identity, root_attachment.identity);
        assert_eq!(post_provision_head, root_attachment.head);
        drop(
            blockd
                .reopen_adopted(&desired, &desired.volumes[0], &post_provision_identity)
                .unwrap(),
        );

        let records = BTreeMap::from([
            (
                root_attachment.identity.volume_id.clone(),
                record(&root_attachment),
            ),
            (
                persistent_attachment.identity.volume_id.clone(),
                record(&persistent_attachment),
            ),
        ]);
        for (volume, attachment) in desired
            .volumes
            .iter()
            .zip([&root_attachment, &persistent_attachment])
        {
            let authority = records.get(&volume.volume_id).unwrap();
            let identity = acquired_attachment_identity(&desired, volume, authority).unwrap();
            assert_eq!(identity, attachment.identity);
            drop(blockd.reopen_adopted(&desired, volume, &identity).unwrap());
        }

        let mut wrong_records = records.clone();
        let wrong_marker = cats_api::runtime_reconciliation::LastVolumeTransition::Takeover {
            authorization_id: id("wrong_takeover_authorization"),
        };
        wrong_records
            .get_mut(&persistent_attachment.identity.volume_id)
            .unwrap()
            .last_transition = Some(wrong_marker);
        let unverified = ServingPrepareDeviceEffect::new(
            ServingPrepareFrontend::vhost_user_blk(4, 256).unwrap(),
            HostPath::new("/usr/bin/cats-blockd").unwrap(),
        )
        .unwrap()
        .with_volume_authority(Arc::new(MapAuthority {
            records: Mutex::new(wrong_records),
            loads: AtomicUsize::new(0),
        }));
        let error = unverified
            .try_persist_direct_existing(&context, &desired)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("authorized artifact conflicts"),
            "{error:#}"
        );

        let authority = Arc::new(MapAuthority {
            records: Mutex::new(records),
            loads: AtomicUsize::new(0),
        });
        let effect = ServingPrepareDeviceEffect::new(
            ServingPrepareFrontend::vhost_user_blk(4, 256).unwrap(),
            HostPath::new("/usr/bin/cats-blockd").unwrap(),
        )
        .unwrap()
        .with_volume_authority(authority);
        assert_eq!(
            effect
                .try_persist_direct_existing(&context, &desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::refresh_inventory())
        );

        let prepared =
            FileCheckpointStore::open(&root.path().join(CHECKPOINT_NAMESPACE), &desired.cat_id)
                .unwrap()
                .load()
                .unwrap()
                .unwrap();
        let ReconcileStep::PrepareDevice { devices } = &prepared.checkpoint().step else {
            panic!("existing takeover Root must reach PrepareDevice")
        };
        assert_eq!(devices.len(), desired.volumes.len());
        for (device, observed) in devices.iter().zip(&prepared.checkpoint().volumes) {
            assert!(
                super::super::prepare_device_retirement::prepared_device_input_is_exact(
                    device, &desired, observed
                )
            );
            assert!(matches!(
                device.acquire_origin,
                AcquireOrigin::Takeover { .. }
            ));
        }
        assert!(matches!(
            devices[0].serving_authority.as_ref(),
            ServingAuthorityProvenance::DirectAuthorizedAttachment {
                purpose: DirectAuthorizedAttachmentPurpose::ExistingRoot,
                ..
            }
        ));

        let mut wrong_authorization = devices[0].clone();
        wrong_authorization.acquire_origin = AcquireOrigin::Takeover {
            authorization_id: id("wrong_takeover_authorization"),
        };
        assert!(
            !super::super::prepare_device_retirement::prepared_device_input_is_exact(
                &wrong_authorization,
                &desired,
                &prepared.checkpoint().volumes[0],
            )
        );
        let mut wrong_origin = devices[0].clone();
        wrong_origin.acquire_origin = AcquireOrigin::Normal {
            transition_id: random('a'),
        };
        assert!(
            !super::super::prepare_device_retirement::prepared_device_input_is_exact(
                &wrong_origin,
                &desired,
                &prepared.checkpoint().volumes[0],
            )
        );
        let mut wrong_attachment = devices[0].clone();
        wrong_attachment.attachment_id = id("wrong_attachment");
        assert!(
            !super::super::prepare_device_retirement::prepared_device_input_is_exact(
                &wrong_attachment,
                &desired,
                &prepared.checkpoint().volumes[0],
            )
        );
        let mut wrong_epoch = devices[0].clone();
        wrong_epoch.attachment_epoch = fence(wrong_epoch.attachment_epoch.get() + 1);
        assert!(
            !super::super::prepare_device_retirement::prepared_device_input_is_exact(
                &wrong_epoch,
                &desired,
                &prepared.checkpoint().volumes[0],
            )
        );
    }

    #[test]
    fn nth_retained_authority_drift_has_zero_prepare_device_cas() {
        let root = tempfile::tempdir().unwrap();
        let desired = desired();
        let root_attachment = attachment(&desired, &desired.volumes[0], head(2, 8, "roots/root-2"));
        let persistent_attachment = attachment(
            &desired,
            &desired.volumes[1],
            head(3, 9, "roots/persistent-3"),
        );
        let blockd = AuthorizedBlockdStore::new(StateDirectory::unanchored(root.path().into()));
        let root_prepared = blockd
            .prepare(&desired, &desired.volumes[0], &root_attachment)
            .unwrap();
        let persistent_prepared = blockd
            .prepare(&desired, &desired.volumes[1], &persistent_attachment)
            .unwrap();
        let volumes = vec![
            prepared_owned_observed_volume(
                &desired.volumes[0],
                &root_attachment,
                HostPath::new(root_prepared.data_directory().to_str().unwrap().to_owned()).unwrap(),
            ),
            prepared_owned_observed_volume(
                &desired.volumes[1],
                &persistent_attachment,
                HostPath::new(
                    persistent_prepared
                        .data_directory()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                )
                .unwrap(),
            ),
        ];
        drop((root_prepared, persistent_prepared));
        let checkpoint = RuntimeCheckpoint {
            version: ContractVersion::V1,
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            placement_epoch: desired.placement.placement_epoch,
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            runtime_incarnation: None,
            runtime_launch: RuntimeLaunch::Absent,
            stable_state: None,
            step: ReconcileStep::AcquireVolume {
                request: persistent_attachment.checkpoint_acquire_request(),
            },
            processes: Vec::new(),
            volumes,
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            route_gates: Vec::new(),
            require_idle: cats_api::runtime_reconciliation::RequireIdleCheckpoint::NotApplicable,
            updated_at_unix_ms: unix_ms(1_900_000_000_000),
        };
        encode_runtime_checkpoint(&checkpoint).unwrap();
        let store =
            FileCheckpointStore::open(&root.path().join(CHECKPOINT_NAMESPACE), &desired.cat_id)
                .unwrap();
        let stored = store.create(&checkpoint).unwrap();
        let before_digest = checkpoint_content_digest(stored.checkpoint()).unwrap();
        drop(store);
        let authority = Arc::new(MapAuthority {
            records: Mutex::new(BTreeMap::from([
                (
                    root_attachment.identity.volume_id.clone(),
                    record(&root_attachment),
                ),
                (
                    persistent_attachment.identity.volume_id.clone(),
                    record(&persistent_attachment),
                ),
            ])),
            loads: AtomicUsize::new(0),
        });
        let drift = Arc::clone(&authority);
        let persistent_volume_id = persistent_attachment.identity.volume_id.clone();
        let effect = ServingPrepareDeviceEffect::new(
            ServingPrepareFrontend::vhost_user_blk(4, 256).unwrap(),
            HostPath::new("/usr/bin/cats-blockd").unwrap(),
        )
        .unwrap()
        .with_volume_authority(authority.clone())
        .with_before_replace(Arc::new(move || {
            drift
                .records
                .lock()
                .unwrap()
                .get_mut(&persistent_volume_id)
                .unwrap()
                .lease_owner = Some(id("att_foreign"));
        }));
        let context = accepted_context(root.path(), &desired, &stored);

        let error = effect
            .try_persist_direct_existing(&context, &desired)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("authority drifted before checkpoint CAS"),
            "{error:#}"
        );
        assert_eq!(authority.loads.load(Ordering::SeqCst), 4);
        let current =
            FileCheckpointStore::open(&root.path().join(CHECKPOINT_NAMESPACE), &desired.cat_id)
                .unwrap()
                .load()
                .unwrap()
                .unwrap();
        assert_eq!(current.content_digest(), &before_digest);
        assert!(matches!(
            current.checkpoint().step,
            ReconcileStep::AcquireVolume { .. }
        ));
    }
}
