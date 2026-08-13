//! Strict one-effect start/adopt foundation for a PrepareDevice serving blockd.
//!
//! This module deliberately stops at the process boundary.  It neither binds
//! a kernel-NBD device nor advances a vhost/VMM checkpoint.  The sealed port
//! must obtain its answer from the same Node-global managed-process sweep as
//! full inventory; a lookup of the expected unit is not absence proof.

use std::ffi::OsString;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::blockd::DurabilityStatus;
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, ControlHandshakeEvidence, DesiredRuntimeSpec, HostPath, Id,
    ObservedDevice, ObservedRuntimeStatus, OwnershipTokenEvidence, PrepareDeviceFrontend,
    PreparedDeviceInput, ProcessEvidence, ProcessRole, ProcessState, RandomId128, ReconcileStep,
    RemoteHead, RuntimeCheckpoint, ServingAuthorityProvenance, UnixMillis, VolumeAuthorityEvidence,
    WireU64,
};
use cats_storage::authority::{
    remote_head_is_same_or_later, validate_authorized_serving_attachment, validate_volume_record,
    VolumeDataAuthority, VolumeRecord,
};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
    RuntimePhysicalReadContext,
};
use crate::state_directory::StateDirectory;

use super::authorized_blockd::{
    authorized_blockd_status_is_bound_to_head, retained_authorized_blockd_command,
    validate_running_physical_desired_successor, AuthorizedBlockFrontend, RetainedAuthorizedBlockd,
};
use super::blockd_socket_namespace::ExactManagedBlockdSocketOwnerStartAbsence;
use super::checkpoint::CurrentCheckpointGuard;
use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::inventory::AuthorizedBlockdInventoryEvidence;
use super::network::{
    prepare_device_checkpoint_view, prepared_device_input, prepared_device_inputs,
    prepared_device_set_is_exact,
};
use super::prepare_device_retirement::{
    prepare_device_base_admission_is_exact, retirement_authority_lease_is_monotonic, unique_runtime,
};
use super::serving_handoff::{PrepareDeviceHandoffReady, ServingHandoffStore};
use super::serving_handoff_effect::checkpoint_is_current_exact;
use super::signed_root_provision::signed_inventory_admission_is_exact_with_networks;
use super::systemd_root_provision::ListenerPhysicalIdentity;
use super::{
    AuthorizedBlockdCheckpoint, AuthorizedBlockdStore, FileCheckpointStore,
    RootProvisionSystemdConfig, StoredCheckpoint,
};

pub(crate) mod process_sealed {
    pub(crate) trait Sealed {}
}

pub(crate) mod global_sealed {
    pub(crate) trait Sealed {}
}

/// Exact provider-local systemd/process/status inspection.  This is not an
/// absence authority: only the Node-global port below may authorize a start.
pub(crate) trait ServingBlockdProcessPort: process_sealed::Sealed + Send + Sync {
    fn inspect(
        &self,
        expected: &ServingBlockdExpectation,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<ServingBlockdProcessInspection>;

    /// Submit at most one create-if-absent attempt.  Implementations must call
    /// `checkpointed.assert_current` immediately before their systemd submit;
    /// an ambiguous systemd response is returned, never retried here.
    fn start_checkpointed(
        &self,
        checkpointed: CheckpointedServingBlockdProcess<'_>,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<ServingBlockdProcessStart>;
}

/// The only provider boundary allowed to decide whether the serving process
/// is globally absent or exact.  Implementations must include the full
/// systemd unit/cgroup, process argv, managed socket and Unix status sweep.
pub(crate) trait ServingBlockdProcessGlobalPort:
    global_sealed::Sealed + ServingBlockdProcessPort
{
    fn retain_start_socket_absence(
        &self,
        _expected: &ServingBlockdExpectation,
        _context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<Option<ExactManagedBlockdSocketOwnerStartAbsence>> {
        anyhow::bail!("Serving start socket absence requires the production Node-global scanner")
    }

    fn inspect_serving_exact_or_absent_after_node_global_sweep(
        &self,
        expected: &ServingBlockdExpectation,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<ServingBlockdProcessInspection>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServingBlockdProcessConflict {
    IdentityMismatch,
    DuplicateIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServingBlockdProcessInspection {
    Absent,
    Exact(Box<ServingBlockdProcessEvidence>),
    Conflict(ServingBlockdProcessConflict),
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServingBlockdProcessStart {
    Submitted,
    OutcomeUnknown,
    DefinitelyNotStarted,
}

/// Complete provider-private serving-process expectation.  It is built only
/// from a descriptor-retained sealed handoff plus the credentialless systemd
/// config, never from public inventory fields or a raw command supplied by a
/// caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServingBlockdExpectation {
    volume: AuthorizedBlockdCheckpoint,
    unit_id: Id,
    cgroup_path: HostPath,
    executable_path: HostPath,
    command_line: Vec<OsString>,
    control_socket_path: HostPath,
    data_directory: HostPath,
    process_identity_token: RandomId128,
    device_ownership_token: RandomId128,
    frontend: PrepareDeviceFrontend,
    prepared_device: PreparedDeviceInput,
    expected_remote_head: RemoteHead,
    authority_lease_expires_at: UnixMillis,
}

impl ServingBlockdExpectation {
    #[allow(
        clippy::too_many_arguments,
        reason = "inventory closes one prepared device across immutable storage, Desired, authority, and installed process config"
    )]
    pub(crate) fn from_inventory(
        state_directory: &StateDirectory,
        systemd: &RootProvisionSystemdConfig,
        checkpoint: &cats_api::runtime_reconciliation::RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        prepared: &PreparedDeviceInput,
        evidence: &AuthorizedBlockdInventoryEvidence,
        authority: &VolumeRecord,
    ) -> anyhow::Result<Self> {
        Self::from_inventory_running(
            state_directory,
            systemd,
            checkpoint,
            desired,
            desired,
            prepared,
            evidence,
            authority,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Running inventory keeps immutable launch and live gate Desired authorities distinct"
    )]
    pub(crate) fn from_inventory_running(
        state_directory: &StateDirectory,
        systemd: &RootProvisionSystemdConfig,
        checkpoint: &cats_api::runtime_reconciliation::RuntimeCheckpoint,
        physical_desired: &DesiredRuntimeSpec,
        gate_desired: &DesiredRuntimeSpec,
        prepared: &PreparedDeviceInput,
        evidence: &AuthorizedBlockdInventoryEvidence,
        authority: &VolumeRecord,
    ) -> anyhow::Result<Self> {
        validate_running_physical_desired_successor(physical_desired, gate_desired)?;
        anyhow::ensure!(
            evidence.checkpoint.desired == *physical_desired
                && evidence.checkpoint.desired.cat_id == gate_desired.cat_id
                && evidence.checkpoint.attachment.identity.volume_id == prepared.volume_id
                && evidence.data_directory == prepared.serving_process.data_directory,
            "serving expectation inventory changed its Cat, Volume, or data directory"
        );
        let store = AuthorizedBlockdStore::new(state_directory.clone());
        let expectation = match prepared.serving_authority.as_ref() {
            cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision {
                ..
            } => {
                let mut prepared_checkpoint = prepare_device_checkpoint_view(checkpoint)?;
                prepared_checkpoint.desired_revision = physical_desired.desired_revision;
                prepared_checkpoint.spec_digest = physical_desired.spec_digest.clone();
                anyhow::ensure!(
                    prepared_device_input(&prepared_checkpoint)? == *prepared,
                    "Root serving expectation selected another prepared device"
                );
                let retained = store
                    .retain_prepare_device_handoff(&prepared_checkpoint, physical_desired)?;
                anyhow::ensure!(
                    retained.checkpoint() == &evidence.checkpoint,
                    "Root serving expectation reopened another authorized checkpoint"
                );
                let ready = ServingHandoffStore::new(state_directory.clone())
                    .reopen_prepare_device_handoff(
                        &prepared_checkpoint,
                        physical_desired,
                        authority,
                        retained,
                    )?;
                Self::from_handoff(
                    &ready,
                    systemd,
                    &prepared_checkpoint,
                    physical_desired,
                    authority,
                )
            }
            cats_api::runtime_reconciliation::ServingAuthorityProvenance::DirectAuthorizedAttachment {
                ..
            } => {
                let retained = store.retain_running_prepared_device(
                    checkpoint,
                    physical_desired,
                    gate_desired,
                    prepared,
                )?;
                anyhow::ensure!(
                    retained.checkpoint() == &evidence.checkpoint
                        && Path::new(evidence.data_directory.as_str())
                            == retained.data_directory(),
                    "direct serving expectation reopened another authorized checkpoint"
                );
                let frontend = match &prepared.frontend {
                    PrepareDeviceFrontend::KernelNbd {
                        listener_socket_path,
                        ..
                    } => AuthorizedBlockFrontend::NbdUnix {
                        socket: Path::new(listener_socket_path.as_str()).to_path_buf(),
                    },
                    PrepareDeviceFrontend::VhostUserBlk {
                        socket_path,
                        queues,
                        queue_size,
                    } => AuthorizedBlockFrontend::VhostUser {
                        socket: Path::new(socket_path.as_str()).to_path_buf(),
                        queues: usize::from(*queues),
                        queue_size: *queue_size,
                    },
                };
                let command = retained_authorized_blockd_command(
                    systemd.validated_blockd(),
                    &retained,
                    prepared,
                    &frontend,
                )?;
                Self::from_command(
                    retained.checkpoint().clone(),
                    command,
                    prepared.clone(),
                )
            }
        }?;
        expectation.with_current_authority(checkpoint, authority)
    }

    pub(crate) fn from_handoff(
        ready: &PrepareDeviceHandoffReady,
        systemd: &RootProvisionSystemdConfig,
        checkpoint: &cats_api::runtime_reconciliation::RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
    ) -> anyhow::Result<Self> {
        let command = ready.authorized_serving_command(
            systemd.validated_blockd(),
            checkpoint,
            desired,
            authority,
        )?;
        let prepared = prepared_device_input(checkpoint)
            .context("serving blockd expectation requires a prepared device")?;
        let mut volume = ready.authorized_checkpoint().clone();
        // The acquire-time file deliberately remains immutable at the blank
        // head.  Root provisioning advances that same attachment before the
        // handoff, so serving status and later authority revalidation must be
        // bound to the descriptor-retained target attachment instead.
        volume.attachment = ready.attempt().attachment.clone();
        Self::from_command(volume, command, prepared)
    }

    /// Build the scanner-shaped expectation used by retained-Running tests.
    /// Unlike the start-time expectation, it binds a renewed current lease.
    #[cfg(test)]
    pub(crate) fn from_running_handoff(
        ready: &PrepareDeviceHandoffReady,
        systemd: &RootProvisionSystemdConfig,
        checkpoint: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
    ) -> anyhow::Result<Self> {
        Self::from_handoff(ready, systemd, checkpoint, desired, authority)?
            .with_current_authority(checkpoint, authority)
    }

    fn from_command(
        volume: AuthorizedBlockdCheckpoint,
        command: std::process::Command,
        prepared: PreparedDeviceInput,
    ) -> anyhow::Result<Self> {
        let serving_process = &prepared.serving_process;
        let executable_path = HostPath::new(command.get_program().to_string_lossy().into_owned())
            .context("serving blockd executable is not a canonical HostPath")?;
        anyhow::ensure!(
            executable_path == serving_process.executable_path
                && serving_process.scope_id.as_str().ends_with(".service")
                && serving_process
                    .scope_id
                    .as_str()
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "serving blockd process owner is not one canonical transient service"
        );
        let cgroup_path = HostPath::new(format!(
            "/sys/fs/cgroup/system.slice/{}",
            serving_process.scope_id.as_str()
        ))
        .context("serving blockd service does not form a canonical cgroup path")?;
        let command_line = std::iter::once(command.get_program().to_owned())
            .chain(command.get_args().map(OsString::from))
            .collect::<Vec<_>>();
        anyhow::ensure!(
            command
                .get_envs()
                .any(|(name, value)| name == "CATS_CRASH_POINT" && value.is_none()),
            "serving blockd command did not clear crash injection"
        );
        let expected_remote_head = volume.attachment.head.clone();
        let authority_lease_expires_at = volume.attachment.lease_expires_at;
        Ok(Self {
            volume,
            unit_id: serving_process.scope_id.clone(),
            cgroup_path,
            executable_path,
            command_line,
            control_socket_path: serving_process.control_socket_path.clone(),
            data_directory: serving_process.data_directory.clone(),
            process_identity_token: serving_process.process_identity_token.clone(),
            device_ownership_token: prepared.ownership_token.clone(),
            frontend: prepared.frontend.clone(),
            prepared_device: prepared,
            expected_remote_head,
            authority_lease_expires_at,
        })
    }

    fn with_current_authority(
        mut self,
        checkpoint: &RuntimeCheckpoint,
        authority: &VolumeRecord,
    ) -> anyhow::Result<Self> {
        let attachment = &self.volume.attachment;
        anyhow::ensure!(
            validate_volume_record(authority).is_ok()
                && authority.volume_id == attachment.identity.volume_id
                && authority.size_bytes == attachment.size_bytes
                && authority.durability == attachment.durability
                && matches!(
                    authority.admin_state,
                    cats_api::runtime_reconciliation::VolumeAdminState::Active
                )
                && authority.lease_owner.as_ref() == Some(&attachment.identity.attachment_id)
                && authority.lease_epoch == attachment.identity.attachment_epoch
                && authority
                    .lease_expires_at
                    .is_some_and(|expiry| expiry >= attachment.lease_expires_at)
                && authority.last_transition == Some(attachment.expected_last_transition())
                && remote_head_is_same_or_later(&authority.head, &attachment.head),
            "serving process current authority changed its retained attachment"
        );
        // A generation-zero Persistent device is not allowed to acquire a
        // nonblank head before the checkpointed initialization tail begins.
        anyhow::ensure!(
            attachment.head.generation.get() > 0
                || authority.head.generation.get() == 0
                || matches!(
                    checkpoint.step,
                    ReconcileStep::FormatFilesystem { .. }
                        | ReconcileStep::DrainInitialization { .. }
                        | ReconcileStep::CommitInitialized { .. }
                        | ReconcileStep::MountFilesystem { .. }
                        | ReconcileStep::OpenAdmission { .. }
                        | ReconcileStep::InstallGate { .. }
                        | ReconcileStep::Stable {
                            state: cats_api::runtime_reconciliation::StableState::Running
                        }
                ),
            "blank Persistent authority advanced before its initialization checkpoint"
        );
        self.expected_remote_head = authority.head.clone();
        self.authority_lease_expires_at = authority
            .lease_expires_at
            .context("serving process current authority lacks a lease")?;
        Ok(self)
    }

    fn status_is_exact_at_head(&self, status: &DurabilityStatus, head: &RemoteHead) -> bool {
        let remote_generation = i64::try_from(head.generation.get()).ok().unwrap_or(-1);
        let generation_gap = status
            .local_durable_generation
            .checked_sub(status.remote_durable_generation);
        authorized_blockd_status_is_bound_to_head(
            status,
            &self.volume,
            &self.unit_id,
            &self.process_identity_token,
            &self.device_ownership_token,
            head,
        ) && status.remote_durable_generation == remote_generation
            && generation_gap.is_some_and(|gap| {
                gap >= 0
                    && usize::try_from(gap).ok() == Some(status.unpublished_generations)
                    && (gap != 0
                        || (status.unpublished_bytes == 0 && status.oldest_unpublished_age_ms == 0))
                    && (self.volume.attachment.durability
                        != cats_api::runtime_reconciliation::Durability::Strict
                        || gap == 0)
            })
    }

    fn status_is_exact(&self, status: &DurabilityStatus) -> bool {
        self.status_is_exact_at_head(status, &self.expected_remote_head)
    }

    pub(crate) fn cat_id(&self) -> &Id {
        &self.volume.desired.cat_id
    }

    pub(crate) fn volume_id(&self) -> &Id {
        &self.volume.attachment.identity.volume_id
    }

    /// Bind a provider-private device proof to the complete persisted serving
    /// attachment. The device scanner cannot reach into the authorized
    /// checkpoint or reconstruct these fields from public `ObservedDevice`.
    pub(crate) fn matches_device_contract(
        &self,
        cat_id: &Id,
        prepared: &PreparedDeviceInput,
    ) -> bool {
        self.cat_id() == cat_id && self.prepared_device == *prepared
    }

    /// Check the provider authority behind this scanner-minted expectation.
    /// Lease renewal may advance, but owner, acquire marker, head, sizing and
    /// durability must remain the exact retained serving attachment.
    pub(crate) fn matches_current_authority(&self, current: &VolumeRecord) -> bool {
        let attachment = &self.volume.attachment;
        validate_volume_record(current).is_ok()
            && validate_authorized_serving_attachment(attachment).is_ok()
            && current.volume_id == attachment.identity.volume_id
            && current.size_bytes == attachment.size_bytes
            && current.durability == attachment.durability
            && matches!(
                current.admin_state,
                cats_api::runtime_reconciliation::VolumeAdminState::Active
            )
            && current.lease_owner.as_ref() == Some(&attachment.identity.attachment_id)
            && current.lease_epoch == attachment.identity.attachment_epoch
            && current
                .lease_expires_at
                .is_some_and(|expiry| expiry >= self.authority_lease_expires_at)
            && current.head == self.expected_remote_head
            && current.last_transition == Some(attachment.expected_last_transition())
    }

    pub(super) fn unit_id(&self) -> &Id {
        &self.unit_id
    }

    pub(super) fn cgroup_path(&self) -> &HostPath {
        &self.cgroup_path
    }

    pub(super) fn executable_path(&self) -> &HostPath {
        &self.executable_path
    }

    pub(super) fn command_line(&self) -> &[OsString] {
        &self.command_line
    }

    pub(super) fn process_identity_token(&self) -> &RandomId128 {
        &self.process_identity_token
    }

    pub(super) fn control_socket_path(&self) -> &HostPath {
        &self.control_socket_path
    }

    pub(super) fn data_directory(&self) -> &HostPath {
        &self.data_directory
    }

    pub(super) fn device_ownership_token(&self) -> &RandomId128 {
        &self.device_ownership_token
    }

    pub(super) fn frontend(&self) -> &PrepareDeviceFrontend {
        &self.frontend
    }

    pub(super) fn prepared_device(&self) -> &PreparedDeviceInput {
        &self.prepared_device
    }

    /// Project only the provider-owned socket mapping into an isolated test
    /// namespace.  The input must first be an exact installed expectation;
    /// reversing the projection must reproduce every byte of the original
    /// process, attachment and device authority.
    #[cfg(test)]
    pub(crate) fn shadow_socket_root_for_test(
        &self,
        socket_root: &cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot,
    ) -> anyhow::Result<Self> {
        let installed = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .serving_paths(&self.device_ownership_token)?;
        let projected = socket_root.serving_paths(&self.device_ownership_token)?;
        anyhow::ensure!(
            &self.control_socket_path == installed.control_socket()
                && self.listener_path() == installed.io_socket()
                && &self.prepared_device.serving_process.control_socket_path
                    == installed.control_socket()
                && match &self.prepared_device.frontend {
                    PrepareDeviceFrontend::KernelNbd {
                        listener_socket_path,
                        ..
                    } => listener_socket_path == installed.io_socket(),
                    PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => {
                        socket_path == installed.io_socket()
                    }
                },
            "Serving test shadow source is outside the installed managed mapping"
        );

        fn replace_frontend_socket(
            frontend: &mut PrepareDeviceFrontend,
            expected: &HostPath,
            replacement: &HostPath,
        ) -> anyhow::Result<()> {
            let socket = match frontend {
                PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    ..
                } => listener_socket_path,
                PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => socket_path,
            };
            anyhow::ensure!(
                socket == expected,
                "Serving test shadow frontend changed before projection"
            );
            *socket = replacement.clone();
            Ok(())
        }

        fn replace_command_socket(
            command_line: &mut [OsString],
            expected: &HostPath,
            replacement: &HostPath,
        ) -> anyhow::Result<()> {
            let mut replacements = 0usize;
            for argument in command_line {
                if argument == expected.as_str() {
                    *argument = OsString::from(replacement.as_str());
                    replacements += 1;
                }
            }
            anyhow::ensure!(
                replacements == 1,
                "Serving test shadow expected one exact socket argument, found {replacements}"
            );
            Ok(())
        }

        let mut shadow = self.clone();
        replace_command_socket(
            &mut shadow.command_line,
            installed.control_socket(),
            projected.control_socket(),
        )?;
        replace_command_socket(
            &mut shadow.command_line,
            installed.io_socket(),
            projected.io_socket(),
        )?;
        shadow.control_socket_path = projected.control_socket().clone();
        shadow.prepared_device.serving_process.control_socket_path =
            projected.control_socket().clone();
        replace_frontend_socket(
            &mut shadow.frontend,
            installed.io_socket(),
            projected.io_socket(),
        )?;
        replace_frontend_socket(
            &mut shadow.prepared_device.frontend,
            installed.io_socket(),
            projected.io_socket(),
        )?;

        let mut restored = shadow.clone();
        replace_command_socket(
            &mut restored.command_line,
            projected.control_socket(),
            installed.control_socket(),
        )?;
        replace_command_socket(
            &mut restored.command_line,
            projected.io_socket(),
            installed.io_socket(),
        )?;
        restored.control_socket_path = installed.control_socket().clone();
        restored.prepared_device.serving_process.control_socket_path =
            installed.control_socket().clone();
        replace_frontend_socket(
            &mut restored.frontend,
            projected.io_socket(),
            installed.io_socket(),
        )?;
        replace_frontend_socket(
            &mut restored.prepared_device.frontend,
            projected.io_socket(),
            installed.io_socket(),
        )?;
        anyhow::ensure!(
            restored == *self,
            "Serving test shadow changed non-socket process or device authority"
        );
        Ok(shadow)
    }

    pub(super) fn listener_path(&self) -> &HostPath {
        match &self.frontend {
            PrepareDeviceFrontend::KernelNbd {
                listener_socket_path,
                ..
            } => listener_socket_path,
            PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => socket_path,
        }
    }

    pub(crate) fn prove_exact_process(
        self,
        evidence: ServingBlockdProcessEvidence,
    ) -> anyhow::Result<ExactServingBlockdProcessProof> {
        anyhow::ensure!(
            evidence.exactly_matches(&self),
            "serving blockd evidence does not exactly match its expectation"
        );
        Ok(ExactServingBlockdProcessProof {
            expectation: self,
            evidence,
        })
    }

    #[cfg(test)]
    pub(crate) fn persistent_vhost_peer_for_test(&self, unique_physical: bool) -> Self {
        let mut peer = self.clone();
        let volume_id = Id::new("vol_persistent").unwrap();
        let attachment_id = Id::new("att_persistent").unwrap();
        let volume_intent_id = Id::new("vint_persistent").unwrap();
        let disk_id = Id::new("disk_persistent").unwrap();
        let guest_serial = Id::new("cats-persistent").unwrap();
        let intent = peer
            .volume
            .desired
            .volumes
            .first_mut()
            .expect("test serving expectation has one Volume intent");
        intent.volume_intent_id = volume_intent_id.clone();
        intent.disk_id = disk_id.clone();
        intent.volume_id = volume_id.clone();
        intent.attachment_id = attachment_id.clone();
        intent.disk_kind = cats_api::runtime_reconciliation::DiskKind::Persistent;
        intent.guest_device.serial = guest_serial.clone();
        intent.guest_device.slot = 1;
        peer.volume.volume = intent.clone();
        peer.volume.attachment.identity.volume_id = volume_id.clone();
        peer.volume.attachment.identity.attachment_id = attachment_id.clone();
        let (request, result) = peer
            .volume
            .attachment
            .normal_acquire_mut()
            .expect("test fixture carries Normal authority");
        request.volume_id = volume_id.clone();
        request.attachment_id = attachment_id.clone();
        result.volume_id = volume_id.clone();
        result.attachment_id = attachment_id.clone();
        peer.prepared_device.volume_intent_id = volume_intent_id;
        peer.prepared_device.disk_id = disk_id;
        peer.prepared_device.volume_id = volume_id;
        peer.prepared_device.disk_kind = cats_api::runtime_reconciliation::DiskKind::Persistent;
        peer.prepared_device.attachment_id = attachment_id;
        peer.prepared_device.guest_device.serial = guest_serial;
        peer.prepared_device.guest_device.slot = 1;
        if unique_physical {
            peer.unit_id = Id::new("cats-blockd-persistent.service").unwrap();
            peer.cgroup_path =
                HostPath::new("/sys/fs/cgroup/system.slice/cats-blockd-persistent.service")
                    .unwrap();
            peer.data_directory = HostPath::new("/var/lib/cats/cat_01/persistent").unwrap();
            peer.process_identity_token =
                RandomId128::new("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
            peer.device_ownership_token =
                RandomId128::new("ffffffffffffffffffffffffffffffff").unwrap();
            let sockets =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .serving_paths(&peer.device_ownership_token)
                    .unwrap();
            peer.control_socket_path = sockets.control_socket().clone();
            peer.prepared_device.serving_process.scope_id = peer.unit_id.clone();
            peer.prepared_device.serving_process.control_socket_path =
                peer.control_socket_path.clone();
            peer.prepared_device.serving_process.data_directory = peer.data_directory.clone();
            peer.prepared_device.serving_process.process_identity_token =
                peer.process_identity_token.clone();
            peer.prepared_device.ownership_token = peer.device_ownership_token.clone();
            let PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } = &mut peer.frontend else {
                panic!("test serving expectation is vhost-user")
            };
            *socket_path = sockets.io_socket().clone();
            peer.prepared_device.frontend = peer.frontend.clone();
        }
        peer
    }

    #[cfg(test)]
    pub(crate) fn exact_evidence_for_test(&self, process_id: u32) -> ServingBlockdProcessEvidence {
        let head_generation = i64::try_from(self.expected_remote_head.generation.get()).unwrap();
        ServingBlockdProcessEvidence {
            process_id,
            unit_main_process_id: process_id,
            process_start_time_ticks: WireU64::new(u64::from(process_id) + 100).unwrap(),
            executable_path: self.executable_path.clone(),
            unit_id: self.unit_id.clone(),
            cgroup_path: self.cgroup_path.clone(),
            cgroup_process_ids: vec![process_id],
            command_line: self.command_line.clone(),
            control_socket_path: self.control_socket_path.clone(),
            data_directory: self.data_directory.clone(),
            process_identity_token: self.process_identity_token.clone(),
            device_ownership_token: self.device_ownership_token.clone(),
            frontend: self.frontend.clone(),
            listener_identity: ListenerPhysicalIdentity::for_test(
                process_id,
                1,
                u64::from(process_id) + 1_000,
                u64::from(process_id) + 2_000,
            ),
            handshake_peer_process_id: process_id,
            status: DurabilityStatus {
                volume_id: self.volume.attachment.identity.volume_id.to_string(),
                attachment_id: self.volume.attachment.identity.attachment_id.to_string(),
                attachment_epoch: Some(self.volume.attachment.identity.attachment_epoch),
                acquire_origin: Some(self.volume.attachment.identity.acquire_origin.clone()),
                node_id: Some(self.volume.attachment.identity.node_id.clone()),
                placement_epoch: Some(self.volume.attachment.identity.placement_epoch),
                guest_io_enabled: Some(true),
                size_bytes: Some(self.volume.attachment.size_bytes),
                scope_id: Some(self.unit_id.clone()),
                process_identity_token: Some(self.process_identity_token.clone()),
                device_ownership_token: Some(self.device_ownership_token.clone()),
                guest_device_serial: Some(self.volume.volume.guest_device.serial.clone()),
                control_only: Some(false),
                remote_head: Some(self.expected_remote_head.clone()),
                mode: match self.volume.attachment.durability {
                    cats_api::runtime_reconciliation::Durability::Strict => "strict",
                    cats_api::runtime_reconciliation::Durability::Relaxed => "relaxed",
                }
                .to_owned(),
                local_durable_generation: head_generation,
                remote_durable_generation: head_generation,
                unpublished_generations: 0,
                unpublished_bytes: 0,
                oldest_unpublished_age_ms: 0,
                max_unpublished_generations: 1,
                max_unpublished_bytes: 1,
                local_allocated_bytes: 0,
                local_accounted_bytes: 0,
                max_local_bytes: 1,
                evicted_cache_chunks: 0,
                backpressured: false,
                fenced: false,
                last_publish_error: None,
            },
        }
    }
}

/// Physical process evidence returned only by the sealed global port.  The
/// command line and frontend remain provider-private because public
/// `ProcessEvidence`/`ObservedDevice` cannot prove either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServingBlockdProcessEvidence {
    process_id: u32,
    unit_main_process_id: u32,
    process_start_time_ticks: WireU64,
    executable_path: HostPath,
    unit_id: Id,
    cgroup_path: HostPath,
    cgroup_process_ids: Vec<u32>,
    command_line: Vec<OsString>,
    control_socket_path: HostPath,
    data_directory: HostPath,
    process_identity_token: RandomId128,
    device_ownership_token: RandomId128,
    frontend: PrepareDeviceFrontend,
    listener_identity: ListenerPhysicalIdentity,
    handshake_peer_process_id: u32,
    status: DurabilityStatus,
}

impl ServingBlockdProcessEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_inspected(
        process_id: u32,
        process_start_time_ticks: WireU64,
        executable_path: HostPath,
        unit_id: Id,
        cgroup_path: HostPath,
        cgroup_process_ids: Vec<u32>,
        command_line: Vec<OsString>,
        control_socket_path: HostPath,
        data_directory: HostPath,
        process_identity_token: RandomId128,
        device_ownership_token: RandomId128,
        frontend: PrepareDeviceFrontend,
        listener_identity: ListenerPhysicalIdentity,
        handshake_peer_process_id: u32,
        status: DurabilityStatus,
    ) -> Self {
        Self {
            process_id,
            unit_main_process_id: process_id,
            process_start_time_ticks,
            executable_path,
            unit_id,
            cgroup_path,
            cgroup_process_ids,
            command_line,
            control_socket_path,
            data_directory,
            process_identity_token,
            device_ownership_token,
            frontend,
            listener_identity,
            handshake_peer_process_id,
            status,
        }
    }

    pub(super) fn exactly_matches(&self, expected: &ServingBlockdExpectation) -> bool {
        self.process_id > 0
            && self.unit_main_process_id == self.process_id
            && self.process_start_time_ticks.get() > 0
            && self.cgroup_process_ids == [self.process_id]
            && self.handshake_peer_process_id == self.process_id
            && self.executable_path == expected.executable_path
            && self.unit_id == expected.unit_id
            && self.cgroup_path == expected.cgroup_path
            && self.command_line == expected.command_line
            && self.control_socket_path == expected.control_socket_path
            && self.data_directory == expected.data_directory
            && self.process_identity_token == expected.process_identity_token
            && self.device_ownership_token == expected.device_ownership_token
            && self.frontend == expected.frontend
            && self.listener_identity.process_id == self.process_id
            && expected.status_is_exact(&self.status)
    }

    pub(crate) fn unit_id(&self) -> &Id {
        &self.unit_id
    }

    pub(crate) fn process_id(&self) -> u32 {
        self.process_id
    }

    pub(crate) fn control_socket_path(&self) -> &HostPath {
        &self.control_socket_path
    }

    pub(crate) fn durability_status(&self) -> &DurabilityStatus {
        &self.status
    }

    pub(crate) fn listener_path(&self) -> &HostPath {
        match &self.frontend {
            PrepareDeviceFrontend::KernelNbd {
                listener_socket_path,
                ..
            } => listener_socket_path,
            PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => socket_path,
        }
    }

    pub(crate) fn into_process_evidence(self) -> ProcessEvidence {
        ProcessEvidence {
            role: ProcessRole::Blockd {
                volume_id: Id::new(self.status.volume_id.clone())
                    .expect("exact serving status has a valid volume ID"),
                attachment_id: Id::new(self.status.attachment_id.clone())
                    .expect("exact serving status has a valid attachment ID"),
                attachment_epoch: self
                    .status
                    .attachment_epoch
                    .expect("exact serving status has an attachment epoch"),
            },
            process_id: self.process_id,
            process_start_time_ticks: self.process_start_time_ticks,
            executable_path: self.executable_path,
            scope_id: self.unit_id,
            control_socket_path: self.control_socket_path,
            state: ProcessState::Running,
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: self.process_identity_token,
            },
            control_handshake: ControlHandshakeEvidence::Verified,
            observed_vm_shape: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn status_mut_for_test(&mut self) -> &mut DurabilityStatus {
        &mut self.status
    }

    #[cfg(test)]
    pub(crate) fn command_line_mut_for_test(&mut self) -> &mut Vec<OsString> {
        &mut self.command_line
    }

    #[cfg(test)]
    pub(crate) fn cgroup_path_mut_for_test(&mut self) -> &mut HostPath {
        &mut self.cgroup_path
    }
}

/// Unforgeable proof that one full provider-private process observation
/// exactly matched the serving expectation derived from PrepareDevice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactServingBlockdProcessProof {
    expectation: ServingBlockdExpectation,
    evidence: ServingBlockdProcessEvidence,
}

impl ExactServingBlockdProcessProof {
    pub(crate) fn expectation(&self) -> &ServingBlockdExpectation {
        &self.expectation
    }

    pub(crate) fn evidence(&self) -> &ServingBlockdProcessEvidence {
        &self.evidence
    }

    pub(crate) fn durability_status(&self) -> &DurabilityStatus {
        self.evidence.durability_status()
    }

    /// Validate a fresh control-socket status after this exact process has
    /// advanced the same fenced attachment. The supplied head must come from
    /// an independent current Volume authority read; the status payload never
    /// self-authorizes its own remote head.
    pub(crate) fn validates_status_at_head(
        &self,
        status: &DurabilityStatus,
        head: &RemoteHead,
    ) -> bool {
        self.expectation.status_is_exact_at_head(status, head)
    }

    pub(crate) fn validates_fully_drained_status_at_head(
        &self,
        status: &DurabilityStatus,
        head: &RemoteHead,
    ) -> bool {
        self.validates_status_at_head(status, head)
            && status.local_durable_generation == status.remote_durable_generation
            && status.unpublished_generations == 0
            && status.unpublished_bytes == 0
            && status.oldest_unpublished_age_ms == 0
    }

    pub(crate) fn matches_public_process(&self, process: &ProcessEvidence) -> bool {
        public_process_matches(process, &self.expectation)
            && accepted_process_matches_evidence(process, &self.evidence)
    }

    pub(crate) fn into_process_evidence(self) -> ProcessEvidence {
        self.evidence.into_process_evidence()
    }

    pub(crate) fn vhost_device_projection(&self) -> Option<(Id, ObservedDevice)> {
        let PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } = &self.expectation.frontend
        else {
            return None;
        };
        let intent = self
            .expectation
            .volume
            .desired
            .volumes
            .iter()
            .find(|intent| {
                intent.volume_id == self.expectation.volume.attachment.identity.volume_id
            })
            .expect("exact serving expectation retained its authorized Volume intent");
        Some((
            intent.volume_id.clone(),
            ObservedDevice::VhostUserBlk {
                guest_device: intent.guest_device.clone(),
                socket_path: socket_path.clone(),
                ownership_token: OwnershipTokenEvidence::Valid {
                    ownership_token: self.expectation.device_ownership_token.clone(),
                },
            },
        ))
    }

    /// Narrow provider-private listener proof for the later frontend effect.
    /// Holding this value retains the complete exact CLI, handshake, systemd
    /// owner and both independent tokens; callers cannot manufacture it from
    /// public `ObservedDevice` projection.
    pub(crate) fn listener_proof(&self) -> ServingBlockdListenerProof {
        ServingBlockdListenerProof {
            exact: self.clone(),
        }
    }

    pub(crate) fn assert_listener_current(
        &self,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<()> {
        assert_serving_listener_current(&self.expectation, &self.evidence, context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServingBlockdListenerProof {
    exact: ExactServingBlockdProcessProof,
}

impl ServingBlockdListenerProof {
    pub(crate) fn listener_path(&self) -> &HostPath {
        match &self.exact.expectation.frontend {
            PrepareDeviceFrontend::KernelNbd {
                listener_socket_path,
                ..
            } => listener_socket_path,
            PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => socket_path,
        }
    }

    pub(crate) fn process_identity_token(&self) -> &RandomId128 {
        &self.exact.expectation.process_identity_token
    }

    pub(crate) fn device_ownership_token(&self) -> &RandomId128 {
        &self.exact.expectation.device_ownership_token
    }

    pub(crate) fn expectation(&self) -> &ServingBlockdExpectation {
        &self.exact.expectation
    }

    pub(crate) fn evidence(&self) -> &ServingBlockdProcessEvidence {
        &self.exact.evidence
    }

    pub(crate) fn matches_public_process(&self, process: &ProcessEvidence) -> bool {
        self.exact.matches_public_process(process)
    }

    /// Reopen the listener and process identity before a later frontend
    /// submission. The retained proof keeps the filesystem and kernel socket
    /// inodes private; callers receive only success or a closed error and
    /// cannot widen the listener pathname or PID admitted by the full scan.
    pub(crate) fn assert_current(
        &self,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<()> {
        assert_serving_listener_current(&self.exact.expectation, &self.exact.evidence, context)
    }
}

fn assert_serving_listener_current(
    expectation: &ServingBlockdExpectation,
    evidence: &ServingBlockdProcessEvidence,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<()> {
    #[cfg(test)]
    if evidence.listener_identity.is_test() {
        return context.check_active();
    }
    context.check_active()?;
    let before = crate::proc::ProcIdentity::sample(evidence.process_id);
    anyhow::ensure!(
        before.start_ticks == Some(evidence.process_start_time_ticks.get())
            && before.exe.as_deref() == Some(Path::new(evidence.executable_path.as_str())),
        "serving listener process identity changed after full inventory"
    );
    evidence
        .listener_identity
        .assert_current(&expectation.frontend, context)?;
    let after = crate::proc::ProcIdentity::sample(evidence.process_id);
    anyhow::ensure!(
        after == before,
        "serving listener process identity changed during current revalidation"
    );
    context.check_active()
}

/// Current checkpoint and descriptor-retained handoff held across one start
/// submission.  Its fields are private so no caller can manufacture the
/// checkpoint-current predicate from an old digest.
pub(crate) struct CheckpointedServingBlockdProcess<'a> {
    expected: &'a ServingBlockdExpectation,
    retained_authority: &'a RetainedServingBlockdAuthority,
    stored: &'a StoredCheckpoint,
    desired: &'a DesiredRuntimeSpec,
    authority: &'a VolumeRecord,
    store: &'a FileCheckpointStore,
    current_checkpoint: CurrentCheckpointGuard<'a>,
    socket_absence: Option<ExactManagedBlockdSocketOwnerStartAbsence>,
}

impl CheckpointedServingBlockdProcess<'_> {
    pub(crate) fn expected(&self) -> &ServingBlockdExpectation {
        self.expected
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        self.store
            .revalidate_current(self.stored, &self.current_checkpoint)?;
        self.retained_authority.assert_current(
            self.stored.checkpoint(),
            self.desired,
            self.authority,
            self.expected,
        )
    }
}

impl<'a> CheckpointedServingBlockdProcess<'a> {
    pub(crate) fn take_socket_absence(
        &mut self,
    ) -> Option<ExactManagedBlockdSocketOwnerStartAbsence> {
        self.socket_absence.take()
    }
}

/// Descriptor-retained immutable serving authority for one prepared Volume.
/// Root retains the post-provision handoff files; direct Persistent/Root
/// retains the original authorized attachment files.  Callers cannot choose
/// the variant independently of the checkpointed provenance.
pub(crate) enum RetainedServingBlockdAuthority {
    Root {
        prepared_checkpoint: Box<RuntimeCheckpoint>,
        prepared: PreparedDeviceInput,
        ready: Box<PrepareDeviceHandoffReady>,
    },
    Direct {
        prepared: PreparedDeviceInput,
        retained: Box<RetainedAuthorizedBlockd>,
    },
}

impl RetainedServingBlockdAuthority {
    pub(crate) fn reopen(
        state_directory: &StateDirectory,
        checkpoint: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        prepared: &PreparedDeviceInput,
        authority: &VolumeRecord,
    ) -> anyhow::Result<Self> {
        Self::reopen_running(
            state_directory,
            checkpoint,
            desired,
            desired,
            prepared,
            authority,
        )
    }

    pub(crate) fn reopen_running(
        state_directory: &StateDirectory,
        checkpoint: &RuntimeCheckpoint,
        physical_desired: &DesiredRuntimeSpec,
        gate_desired: &DesiredRuntimeSpec,
        prepared: &PreparedDeviceInput,
        authority: &VolumeRecord,
    ) -> anyhow::Result<Self> {
        validate_running_physical_desired_successor(physical_desired, gate_desired)?;
        let store = AuthorizedBlockdStore::new(state_directory.clone());
        match prepared.serving_authority.as_ref() {
            ServingAuthorityProvenance::AfterRootProvision { .. } => {
                let mut prepared_checkpoint = prepare_device_checkpoint_view(checkpoint)?;
                prepared_checkpoint.desired_revision = physical_desired.desired_revision;
                prepared_checkpoint.spec_digest = physical_desired.spec_digest.clone();
                anyhow::ensure!(
                    prepared_device_input(&prepared_checkpoint)? == *prepared,
                    "Root serving authority selected another prepared device"
                );
                let retained =
                    store.retain_prepare_device_handoff(&prepared_checkpoint, physical_desired)?;
                let ready = ServingHandoffStore::new(state_directory.clone())
                    .reopen_prepare_device_handoff(
                        &prepared_checkpoint,
                        physical_desired,
                        authority,
                        retained,
                    )?;
                Ok(Self::Root {
                    prepared_checkpoint: Box::new(prepared_checkpoint),
                    prepared: prepared.clone(),
                    ready: Box::new(ready),
                })
            }
            ServingAuthorityProvenance::DirectAuthorizedAttachment { .. } => {
                let retained = store.retain_running_prepared_device(
                    checkpoint,
                    physical_desired,
                    gate_desired,
                    prepared,
                )?;
                Ok(Self::Direct {
                    prepared: prepared.clone(),
                    retained: Box::new(retained),
                })
            }
        }
    }

    pub(crate) fn expectation(
        &self,
        systemd: &RootProvisionSystemdConfig,
        desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
    ) -> anyhow::Result<ServingBlockdExpectation> {
        let expected = self.build_expectation(systemd, desired, authority)?;
        anyhow::ensure!(
            expected.matches_current_authority(authority),
            "retained serving authority conflicts with current Volume authority"
        );
        Ok(expected)
    }

    pub(crate) fn expectation_running(
        &self,
        systemd: &RootProvisionSystemdConfig,
        checkpoint: &RuntimeCheckpoint,
        physical_desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
    ) -> anyhow::Result<ServingBlockdExpectation> {
        self.build_expectation(systemd, physical_desired, authority)?
            .with_current_authority(checkpoint, authority)
    }

    fn build_expectation(
        &self,
        systemd: &RootProvisionSystemdConfig,
        physical_desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
    ) -> anyhow::Result<ServingBlockdExpectation> {
        let expected = match self {
            Self::Root {
                prepared_checkpoint,
                ready,
                ..
            } => ServingBlockdExpectation::from_handoff(
                ready,
                systemd,
                prepared_checkpoint,
                physical_desired,
                authority,
            )?,
            Self::Direct { prepared, retained } => {
                retained.assert_prepared_authority(prepared)?;
                let frontend = match &prepared.frontend {
                    PrepareDeviceFrontend::KernelNbd {
                        listener_socket_path,
                        ..
                    } => AuthorizedBlockFrontend::NbdUnix {
                        socket: Path::new(listener_socket_path.as_str()).to_path_buf(),
                    },
                    PrepareDeviceFrontend::VhostUserBlk {
                        socket_path,
                        queues,
                        queue_size,
                    } => AuthorizedBlockFrontend::VhostUser {
                        socket: Path::new(socket_path.as_str()).to_path_buf(),
                        queues: usize::from(*queues),
                        queue_size: *queue_size,
                    },
                };
                let command = retained_authorized_blockd_command(
                    systemd.validated_blockd(),
                    retained,
                    prepared,
                    &frontend,
                )?;
                ServingBlockdExpectation::from_command(
                    retained.checkpoint().clone(),
                    command,
                    prepared.clone(),
                )?
            }
        };
        Ok(expected)
    }

    pub(crate) fn assert_current(
        &self,
        checkpoint: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
        expected: &ServingBlockdExpectation,
    ) -> anyhow::Result<()> {
        self.assert_running_current(checkpoint, desired, desired, authority, expected)
    }

    pub(crate) fn assert_running_current(
        &self,
        checkpoint: &RuntimeCheckpoint,
        physical_desired: &DesiredRuntimeSpec,
        gate_desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
        expected: &ServingBlockdExpectation,
    ) -> anyhow::Result<()> {
        validate_running_physical_desired_successor(physical_desired, gate_desired)?;
        anyhow::ensure!(
            checkpoint.cat_id == gate_desired.cat_id
                && checkpoint.node_id == gate_desired.placement.node_id
                && checkpoint.placement_epoch == gate_desired.placement.placement_epoch
                && checkpoint.desired_revision == gate_desired.desired_revision
                && checkpoint.spec_digest == gate_desired.spec_digest,
            "retained serving authority changed its current checkpoint coordinate"
        );
        let prepared = match self {
            Self::Root { prepared, .. } | Self::Direct { prepared, .. } => prepared,
        };
        anyhow::ensure!(
            prepared_device_inputs(checkpoint)?
                .iter()
                .filter(|candidate| *candidate == prepared)
                .count()
                == 1
                && expected.matches_device_contract(&checkpoint.cat_id, prepared)
                && expected.matches_current_authority(authority),
            "retained serving authority changed its prepared device or Volume authority"
        );
        match self {
            Self::Root {
                prepared_checkpoint,
                ready,
                ..
            } => ready.assert_current(prepared_checkpoint, physical_desired, authority),
            Self::Direct { prepared, retained } => {
                retained.assert_current()?;
                retained.assert_prepared_authority(prepared)
            }
        }
    }
}

pub(crate) struct ServingBlockdStartEffect {
    authority: Arc<dyn VolumeDataAuthority>,
    systemd: RootProvisionSystemdConfig,
    process: Arc<dyn ServingBlockdProcessGlobalPort>,
    submitted_admission: Mutex<Option<RandomId128>>,
    #[cfg(test)]
    after_exact_adoption: Option<ServingBlockdAdoptionObserver>,
}

#[cfg(test)]
pub(crate) type ServingBlockdAdoptionObserver =
    Arc<dyn Fn(&Id) -> anyhow::Result<()> + Send + Sync>;

struct AdmittedServingStart<'a> {
    expected: ServingBlockdExpectation,
    admitted_exact: Option<&'a ExactServingBlockdProcessProof>,
    retained: RetainedServingBlockdAuthority,
    first_authority: VolumeRecord,
    first_lease_expiry: cats_api::runtime_reconciliation::UnixMillis,
}

impl ServingBlockdStartEffect {
    pub(crate) fn new(
        authority: Arc<dyn VolumeDataAuthority>,
        systemd: RootProvisionSystemdConfig,
        process: Arc<dyn ServingBlockdProcessGlobalPort>,
    ) -> Self {
        Self {
            authority,
            systemd,
            process,
            submitted_admission: Mutex::new(None),
            #[cfg(test)]
            after_exact_adoption: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_after_exact_adoption_for_test(
        mut self,
        observer: ServingBlockdAdoptionObserver,
    ) -> Self {
        self.after_exact_adoption = Some(observer);
        self
    }

    /// Return `None` only after accepted full inventory and the sealed global
    /// port agree on the same exact serving process.  That is the sole
    /// fallthrough point for a later device effect.
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
            runtime.step,
            ReconcileStep::PrepareDevice { .. } | ReconcileStep::PrepareNetwork { .. }
        ) {
            return Ok(None);
        }
        // This accepted-full process set is Node-global. Only one Cat may
        // consume it as mutation authority; a sibling Refresh/timeout closes
        // the batch before the next waiter can submit.
        let _node_global_effect = context.lock_node_global_effect()?;
        let observed_devices = match &runtime.step {
            ReconcileStep::PrepareDevice { .. } => {
                if !prepare_device_base_admission_is_exact(accepted, desired, runtime) {
                    return Ok(Some(stop_local()));
                }
                None
            }
            ReconcileStep::PrepareNetwork { network, devices } => {
                if !prepared_device_set_is_exact(desired, devices) {
                    return Ok(Some(stop_local()));
                }
                let Some(expected_networks) = context
                    .node_global_network()?
                    .expected_networks(&desired.cat_id, network)
                else {
                    return Ok(Some(stop_local()));
                };
                if !signed_inventory_admission_is_exact_with_networks(
                    accepted,
                    desired,
                    runtime,
                    &expected_networks,
                ) || !checkpoint_is_current_exact(desired, runtime)
                {
                    return Ok(Some(stop_local()));
                }
                Some(devices.as_slice())
            }
            _ => unreachable!("phase was classified before global admission"),
        };

        let cats_api::runtime_reconciliation::CheckpointEvidence::Valid {
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
        .context("open serving PrepareDevice checkpoint store")?;
        anyhow::ensure!(
            Path::new(checkpoint_path.as_str()) == store.path(),
            "serving PrepareDevice names another checkpoint path"
        );
        let Some(stored) = store
            .load()
            .context("load serving PrepareDevice checkpoint")?
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest || stored.checkpoint().step != runtime.step {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let prepared = prepared_device_inputs(stored.checkpoint())?;
        if prepared.is_empty()
            || observed_devices.is_some_and(|observed| observed != prepared.as_slice())
        {
            return Ok(Some(stop_local()));
        }
        let admission = context.node_global_process()?;
        anyhow::ensure!(
            admission.matches_observation(accepted.observation()),
            "serving process admission is not bound to the accepted full observation"
        );
        if admission.serving_blockd_count(&desired.cat_id) != prepared.len() {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        let mut serving = Vec::with_capacity(prepared.len());
        for device in &prepared {
            let Some((admitted_expected, admitted_exact)) =
                admission.serving_blockd(&desired.cat_id, &device.volume_id)
            else {
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
            };
            if !admitted_expected.matches_device_contract(&desired.cat_id, device)
                || !accepted_devices_are_compatible(
                    context,
                    runtime,
                    admitted_expected,
                    admitted_exact,
                )?
            {
                return Ok(Some(stop_local()));
            }
            let first_authority = match self.authority.load_volume(&device.volume_id) {
                Ok(authority) => authority,
                Err(_) => return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory)),
            };
            let retained = match RetainedServingBlockdAuthority::reopen(
                context.state_directory(),
                stored.checkpoint(),
                desired,
                device,
                &first_authority,
            ) {
                Ok(retained) => retained,
                Err(_) => return Ok(Some(stop_local())),
            };
            let expected = retained.expectation(&self.systemd, desired, &first_authority)?;
            if &expected != admitted_expected {
                return Ok(Some(stop_local()));
            }
            let Some(first_lease_expiry) = first_authority.lease_expires_at else {
                return Ok(Some(stop_local()));
            };
            serving.push(AdmittedServingStart {
                expected,
                admitted_exact,
                retained,
                first_authority,
                first_lease_expiry,
            });
        }
        let admitted_exact_count = serving
            .iter()
            .filter(|entry| entry.admitted_exact.is_some())
            .count();
        if runtime.processes.len() != admitted_exact_count
            || runtime.processes.iter().any(|process| {
                serving
                    .iter()
                    .filter_map(|entry| entry.admitted_exact)
                    .filter(|proof| proof.matches_public_process(process))
                    .count()
                    != 1
            })
        {
            return Ok(Some(stop_local()));
        }

        let mut selected_absent = None;
        for (index, entry) in serving.iter().enumerate() {
            context.check_active()?;
            let inspection = self
                .process
                .inspect_serving_exact_or_absent_after_node_global_sweep(
                    &entry.expected,
                    context,
                )?;
            match (entry.admitted_exact, inspection) {
                (None, ServingBlockdProcessInspection::Absent) => {
                    selected_absent.get_or_insert(index);
                }
                (Some(admitted), ServingBlockdProcessInspection::Exact(evidence))
                    if evidence.exactly_matches(&entry.expected)
                        && evidence.as_ref() == admitted.evidence() => {}
                (_, ServingBlockdProcessInspection::Conflict(_)) => {
                    return Ok(Some(stop_local()));
                }
                (_, ServingBlockdProcessInspection::Exact(evidence))
                    if !evidence.exactly_matches(&entry.expected) =>
                {
                    return Ok(Some(stop_local()));
                }
                (_, ServingBlockdProcessInspection::Unavailable)
                | (None, ServingBlockdProcessInspection::Exact(_))
                | (Some(_), ServingBlockdProcessInspection::Absent)
                | (Some(_), ServingBlockdProcessInspection::Exact(_)) => {
                    return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
                }
            }
        }

        let guard = store.assert_current(&stored)?;
        let mut current_authorities = Vec::with_capacity(serving.len());
        for entry in &serving {
            let current = self.reread_current(
                context,
                entry.expected.volume_id(),
                &entry.first_authority,
                entry.first_lease_expiry,
            )?;
            entry.retained.assert_current(
                stored.checkpoint(),
                desired,
                &current,
                &entry.expected,
            )?;
            current_authorities.push(current);
        }
        store.revalidate_current(&stored, &guard)?;
        let Some(selected) = selected_absent else {
            if let Some(successor) = publisher_clean_checkpoint_successor(
                &stored,
                runtime,
                &serving,
                &current_authorities,
            )? {
                drop(guard);
                context.check_active()?;
                store
                    .replace(&stored, &successor)
                    .context("publish serving publisher-clean checkpoint successor")?;
                return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
            }
            #[cfg(test)]
            if let Some(observer) = &self.after_exact_adoption {
                observer(&desired.cat_id)?;
            }
            return Ok(None);
        };
        let selected_entry = &serving[selected];
        let Some(socket_absence) = self
            .process
            .retain_start_socket_absence(&selected_entry.expected, context)?
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };

        let observation_id = &accepted.observation().observation_id;
        let mut submitted = self
            .submitted_admission
            .lock()
            .map_err(|_| anyhow::anyhow!("serving process submission gate poisoned"))?;
        if submitted.as_ref() == Some(observation_id) {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }
        *submitted = Some(observation_id.clone());
        drop(submitted);
        let checkpointed = CheckpointedServingBlockdProcess {
            expected: &selected_entry.expected,
            retained_authority: &selected_entry.retained,
            stored: &stored,
            desired,
            authority: &current_authorities[selected],
            store: &store,
            current_checkpoint: guard,
            socket_absence: Some(socket_absence),
        };
        checkpointed.assert_current()?;
        let _submission = self.process.start_checkpointed(checkpointed, context)?;

        // A systemd response is never a postcondition and never permits a
        // second Volume start in this admission. Recheck every retained
        // Volume/filesystem authority, then require a newly accepted full.
        for entry in &serving {
            let after = self.reread_current(
                context,
                entry.expected.volume_id(),
                &entry.first_authority,
                entry.first_lease_expiry,
            )?;
            entry
                .retained
                .assert_current(stored.checkpoint(), desired, &after, &entry.expected)?;
        }
        Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
    }

    fn reread_current(
        &self,
        context: &RuntimeDesiredEffectContext,
        volume_id: &Id,
        first: &VolumeRecord,
        first_lease_expiry: cats_api::runtime_reconciliation::UnixMillis,
    ) -> anyhow::Result<VolumeRecord> {
        context.check_active()?;
        let current = self.authority.load_volume(volume_id)?;
        anyhow::ensure!(
            retirement_authority_lease_is_monotonic(first, &current, first_lease_expiry),
            "serving PrepareDevice authority changed across process effect"
        );
        Ok(current)
    }
}

/// A retained serving writer may advance the remote head after a Relaxed
/// publisher settles its local tail.  The immutable grant remains the origin
/// authority, while this bounded Runtime checkpoint records the newer launch
/// head.  Progress is allowed only from one exact full scan that proves every
/// serving process and lineage fully drained at the independently reread head.
fn publisher_clean_checkpoint_successor(
    stored: &StoredCheckpoint,
    runtime: &ObservedRuntimeStatus,
    serving: &[AdmittedServingStart<'_>],
    current_authorities: &[VolumeRecord],
) -> anyhow::Result<Option<RuntimeCheckpoint>> {
    let ReconcileStep::PrepareNetwork { devices, .. } = &stored.checkpoint().step else {
        return Ok(None);
    };
    if devices.len() != serving.len() || serving.len() != current_authorities.len() {
        return Ok(None);
    }

    let mut advanced = Vec::new();
    for ((device, entry), current) in devices.iter().zip(serving).zip(current_authorities) {
        let Some(exact) = entry.admitted_exact else {
            return Ok(None);
        };
        let Some(observed) = runtime
            .volumes
            .iter()
            .find(|volume| volume.volume_id == device.volume_id)
        else {
            return Ok(None);
        };
        let [lineage] = observed.local_lineages.as_slice() else {
            return Ok(None);
        };
        let VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            head,
        } = &observed.authority
        else {
            return Ok(None);
        };
        if head != &current.head
            || attachment_id != &device.attachment_id
            || *attachment_epoch != device.attachment_epoch
            || !remote_head_is_same_or_later(&current.head, &device.expected_head)
            || lineage.attachment_id != device.attachment_id
            || lineage.attachment_epoch != device.attachment_epoch
            || lineage.acquire_origin != device.acquire_origin
            || lineage.local_durable_generation != current.head.generation
            || lineage.remote_durable_generation != current.head.generation
            || lineage.pending_pack_count.get() != 0
            || lineage.fenced
            || !matches!(
                lineage.state,
                cats_api::runtime_reconciliation::LocalLineageState::Active
            )
            || !exact
                .validates_fully_drained_status_at_head(exact.durability_status(), &current.head)
        {
            return Ok(None);
        }
        if current.head != device.expected_head {
            advanced.push((device.volume_id.clone(), current.head.clone()));
        }
    }
    if advanced.is_empty() {
        return Ok(None);
    }

    let mut successor = stored.checkpoint().clone();
    let ReconcileStep::PrepareNetwork { devices, .. } = &mut successor.step else {
        unreachable!("predecessor phase was checked above")
    };
    for (volume_id, head) in &advanced {
        let Some(device) = devices
            .iter_mut()
            .find(|device| &device.volume_id == volume_id)
        else {
            return Ok(None);
        };
        device.expected_head = head.clone();

        let Some(volume) = successor
            .volumes
            .iter_mut()
            .find(|volume| &volume.volume_id == volume_id)
        else {
            return Ok(None);
        };
        let VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            head: checkpoint_head,
        } = &mut volume.authority
        else {
            return Ok(None);
        };
        let [lineage] = volume.local_lineages.as_mut_slice() else {
            return Ok(None);
        };
        if attachment_id != &device.attachment_id
            || *attachment_epoch != device.attachment_epoch
            || lineage.attachment_id != device.attachment_id
            || lineage.attachment_epoch != device.attachment_epoch
            || lineage.acquire_origin != device.acquire_origin
        {
            return Ok(None);
        }
        *checkpoint_head = head.clone();
        lineage.local_durable_generation = head.generation;
        lineage.remote_durable_generation = head.generation;
        lineage.pending_pack_count = WireU64::new(0).expect("zero fits WireU64");
    }
    let wall_clock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis();
    let wall_clock_ms = u64::try_from(wall_clock_ms).context("system time exceeds wire range")?;
    let minimum = stored
        .checkpoint()
        .updated_at_unix_ms
        .get()
        .checked_add(1)
        .context("publisher-clean checkpoint timestamp exhausted")?;
    successor.updated_at_unix_ms = UnixMillis::new(wall_clock_ms.max(minimum))
        .context("publisher-clean checkpoint timestamp exceeds the wire range")?;
    encode_runtime_checkpoint(&successor)
        .context("publisher-clean checkpoint successor is not canonical V1")?;
    Ok(Some(successor))
}

fn public_process_matches(process: &ProcessEvidence, expected: &ServingBlockdExpectation) -> bool {
    matches!(
        &process.role,
        ProcessRole::Blockd {
            volume_id,
            attachment_id,
            attachment_epoch,
        } if volume_id == &expected.volume.attachment.identity.volume_id
            && attachment_id == &expected.volume.attachment.identity.attachment_id
            && *attachment_epoch == expected.volume.attachment.identity.attachment_epoch
    ) && process.process_id > 0
        && process.process_start_time_ticks.get() > 0
        && process.executable_path == expected.executable_path
        && process.scope_id == expected.unit_id
        && process.control_socket_path == expected.control_socket_path
        && process.state == ProcessState::Running
        && process.ownership_token
            == (OwnershipTokenEvidence::Valid {
                ownership_token: expected.process_identity_token.clone(),
            })
        && process.control_handshake == ControlHandshakeEvidence::Verified
        && process.observed_vm_shape.is_none()
}

fn accepted_process_matches_evidence(
    accepted: &ProcessEvidence,
    evidence: &ServingBlockdProcessEvidence,
) -> bool {
    accepted.process_id == evidence.process_id
        && accepted.process_start_time_ticks == evidence.process_start_time_ticks
}

fn accepted_devices_are_compatible(
    context: &RuntimeDesiredEffectContext,
    runtime: &ObservedRuntimeStatus,
    expected: &ServingBlockdExpectation,
    admitted_exact: Option<&ExactServingBlockdProcessProof>,
) -> anyhow::Result<bool> {
    let Some(volume) = runtime
        .volumes
        .iter()
        .find(|volume| volume.volume_id == *expected.volume_id())
    else {
        return Ok(false);
    };
    match &expected.frontend {
        PrepareDeviceFrontend::KernelNbd { .. } => match volume.devices.as_slice() {
            [] => Ok(true),
            [observed] if admitted_exact.is_some() => {
                let Some(exact) = context
                    .kernel_nbd_pool()?
                    .exact_device(expected.cat_id(), expected.volume_id())
                else {
                    return Ok(false);
                };
                let (volume_id, projected) = exact.projection();
                Ok(exact.listener().expectation() == expected
                    && exact.matches_prepared_device(expected.cat_id(), &expected.prepared_device)
                    && volume_id == *expected.volume_id()
                    && observed == &projected)
            }
            _ => Ok(false),
        },
        PrepareDeviceFrontend::VhostUserBlk { .. } => match volume.devices.as_slice() {
            [] => Ok(admitted_exact.is_none()),
            [observed] => Ok(admitted_exact
                .and_then(ExactServingBlockdProcessProof::vhost_device_projection)
                .is_some_and(|(_, expected)| observed == &expected)),
            _ => Ok(false),
        },
    }
}

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}
