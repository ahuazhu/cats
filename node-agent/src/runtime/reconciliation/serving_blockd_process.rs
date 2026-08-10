//! Strict one-effect start/adopt foundation for a PrepareDevice serving blockd.
//!
//! This module deliberately stops at the process boundary.  It neither binds
//! a kernel-NBD device nor advances a vhost/VMM checkpoint.  The sealed port
//! must obtain its answer from the same Node-global managed-process sweep as
//! full inventory; a lookup of the expected unit is not absence proof.

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use cats_api::blockd::DurabilityStatus;
use cats_api::runtime_reconciliation::{
    ControlHandshakeEvidence, DesiredRuntimeSpec, HostPath, Id, ObservedDevice,
    ObservedRuntimeStatus, OwnershipTokenEvidence, PrepareDeviceFrontend, PreparedDeviceInput,
    ProcessEvidence, ProcessRole, ProcessState, RandomId128, ReconcileStep, WireU64,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, validate_volume_record, LastVolumeTransition,
    VolumeDataAuthority, VolumeRecord,
};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
    RuntimePhysicalReadContext,
};

use super::checkpoint::CurrentCheckpointGuard;
use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::network::{prepare_network_volume_admission_is_exact, prepared_device_input};
use super::prepare_device_retirement::{
    prepare_device_base_admission_is_exact, retirement_authority_lease_is_monotonic, unique_runtime,
};
use super::serving_handoff::{PrepareDeviceHandoffReady, ServingHandoffStore};
use super::serving_handoff_effect::checkpoint_is_current_exact;
use super::signed_root_provision::signed_inventory_admission_is_exact_with_networks;
use super::systemd_root_provision::ListenerPhysicalIdentity;
use super::{
    authorized_blockd_status_is_bound, AuthorizedBlockdCheckpoint, AuthorizedBlockdStore,
    FileCheckpointStore, RootProvisionSystemdConfig, StoredCheckpoint,
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
}

impl ServingBlockdExpectation {
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
        let mut volume = ready.authorized_checkpoint().clone();
        // The acquire-time file deliberately remains immutable at the blank
        // head.  Root provisioning advances that same attachment before the
        // handoff, so serving status and later authority revalidation must be
        // bound to the descriptor-retained target attachment instead.
        volume.attachment = ready.attempt().attachment.clone();
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
        })
    }

    fn status_is_exact(&self, status: &DurabilityStatus) -> bool {
        authorized_blockd_status_is_bound(
            status,
            &self.volume,
            &self.unit_id,
            &self.process_identity_token,
            &self.device_ownership_token,
        ) && status.local_durable_generation
            == i64::try_from(self.volume.attachment.head.generation.get())
                .ok()
                .unwrap_or(-1)
            && status.remote_durable_generation
                == i64::try_from(self.volume.attachment.head.generation.get())
                    .ok()
                    .unwrap_or(-1)
            && status.unpublished_generations == 0
            && status.unpublished_bytes == 0
            && status.oldest_unpublished_age_ms == 0
            && !status.backpressured
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
                .is_some_and(|expiry| expiry >= attachment.lease_expires_at)
            && current.head == attachment.head
            && current.last_transition
                == Some(LastVolumeTransition::NormalAcquire {
                    request: attachment.acquire_request.clone(),
                    result: attachment.acquire_result.clone(),
                })
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
    pub(crate) fn exact_evidence_for_test(&self, process_id: u32) -> ServingBlockdProcessEvidence {
        let head_generation = i64::try_from(self.volume.attachment.head.generation.get()).unwrap();
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
                control_only: Some(false),
                remote_head: Some(self.volume.attachment.head.clone()),
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

    /// Reopen the listener and process identity before a later frontend
    /// submission. The retained proof keeps the filesystem and kernel socket
    /// inodes private; callers receive only success or a closed error and
    /// cannot widen the listener pathname or PID admitted by the full scan.
    pub(crate) fn assert_current(
        &self,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<()> {
        context.check_active()?;
        let before = crate::proc::ProcIdentity::sample(self.exact.evidence.process_id);
        anyhow::ensure!(
            before.start_ticks == Some(self.exact.evidence.process_start_time_ticks.get())
                && before.exe.as_deref()
                    == Some(Path::new(self.exact.evidence.executable_path.as_str())),
            "serving listener process identity changed after full inventory"
        );
        self.exact
            .evidence
            .listener_identity
            .assert_current(&self.exact.expectation.frontend, context)?;
        let after = crate::proc::ProcIdentity::sample(self.exact.evidence.process_id);
        anyhow::ensure!(
            after == before,
            "serving listener process identity changed during current revalidation"
        );
        context.check_active()
    }
}

/// Current checkpoint and descriptor-retained handoff held across one start
/// submission.  Its fields are private so no caller can manufacture the
/// checkpoint-current predicate from an old digest.
pub(crate) struct CheckpointedServingBlockdProcess<'a> {
    expected: &'a ServingBlockdExpectation,
    handoff: &'a PrepareDeviceHandoffReady,
    stored: &'a StoredCheckpoint,
    desired: &'a DesiredRuntimeSpec,
    authority: &'a VolumeRecord,
    store: &'a FileCheckpointStore,
    current_checkpoint: CurrentCheckpointGuard<'a>,
}

impl CheckpointedServingBlockdProcess<'_> {
    pub(crate) fn expected(&self) -> &ServingBlockdExpectation {
        self.expected
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        self.store
            .revalidate_current(self.stored, &self.current_checkpoint)?;
        self.handoff
            .assert_current(self.stored.checkpoint(), self.desired, self.authority)
    }
}

pub(crate) struct ServingBlockdStartEffect {
    authority: Arc<dyn VolumeDataAuthority>,
    systemd: RootProvisionSystemdConfig,
    process: Arc<dyn ServingBlockdProcessGlobalPort>,
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
        }
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
        let prepare_network_device = match &runtime.step {
            ReconcileStep::PrepareDevice { .. } => {
                if !prepare_device_base_admission_is_exact(accepted, desired, runtime) {
                    return Ok(Some(stop_local()));
                }
                None
            }
            ReconcileStep::PrepareNetwork { network, devices } => {
                let [device] = devices.as_slice() else {
                    return Ok(Some(stop_local()));
                };
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
                Some(device)
            }
            _ => return Ok(None),
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

        let [desired_volume] = desired.volumes.as_slice() else {
            return Ok(Some(stop_local()));
        };
        let first_authority = match self.authority.load_volume(&desired_volume.volume_id) {
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
            .reopen_prepare_device_handoff(stored.checkpoint(), desired, &first_authority, retained)
        {
            Ok(ready) => ready,
            Err(_) => return Ok(Some(stop_local())),
        };
        let Some(first_lease_expiry) = first_authority
            .lease_expires_at
            .filter(|current| *current >= ready.attempt().attachment.lease_expires_at)
        else {
            return Ok(Some(stop_local()));
        };
        let expected = ServingBlockdExpectation::from_handoff(
            &ready,
            &self.systemd,
            stored.checkpoint(),
            desired,
            &first_authority,
        )?;
        let admission = context.node_global_process()?;
        let Some((admitted_expected, admitted_exact)) = admission.serving_blockd(&desired.cat_id)
        else {
            return Ok(Some(stop_local()));
        };
        let prepare_network_is_exact = prepare_network_device.is_none_or(|device| {
            expected.matches_device_contract(&desired.cat_id, device)
                && prepare_network_volume_admission_is_exact(
                    desired,
                    runtime,
                    device,
                    expected.volume_id(),
                    runtime
                        .volumes
                        .first()
                        .and_then(|volume| match volume.devices.as_slice() {
                            [observed] => Some(observed),
                            _ => None,
                        }),
                )
        });
        if admitted_expected != &expected
            || !prepare_network_is_exact
            || !accepted_devices_are_compatible(context, runtime, &expected, admitted_exact)?
        {
            return Ok(Some(stop_local()));
        }
        let accepted_process = match runtime.processes.as_slice() {
            [] if admitted_exact.is_none() => None,
            [process]
                if admitted_exact.is_some_and(|proof| proof.matches_public_process(process)) =>
            {
                Some(process)
            }
            _ => return Ok(Some(stop_local())),
        };

        context.check_active()?;
        let inspection = self
            .process
            .inspect_serving_exact_or_absent_after_node_global_sweep(&expected, context)?;
        match (accepted_process, inspection) {
            (None, ServingBlockdProcessInspection::Exact(_))
            | (Some(_), ServingBlockdProcessInspection::Absent)
            | (_, ServingBlockdProcessInspection::Unavailable) => {
                Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
            (_, ServingBlockdProcessInspection::Conflict(_)) => Ok(Some(stop_local())),
            (Some(accepted), ServingBlockdProcessInspection::Exact(evidence)) => {
                if !evidence.exactly_matches(&expected)
                    || !accepted_process_matches_evidence(accepted, &evidence)
                {
                    return Ok(Some(stop_local()));
                }
                let current = self.reread_current(
                    context,
                    &desired_volume.volume_id,
                    &first_authority,
                    first_lease_expiry,
                )?;
                ready.assert_current(stored.checkpoint(), desired, &current)?;
                let guard = store.assert_current(&stored)?;
                store.revalidate_current(&stored, &guard)?;
                Ok(None)
            }
            (None, ServingBlockdProcessInspection::Absent) => {
                let current = self.reread_current(
                    context,
                    &desired_volume.volume_id,
                    &first_authority,
                    first_lease_expiry,
                )?;
                ready.assert_current(stored.checkpoint(), desired, &current)?;
                let guard = store.assert_current(&stored)?;
                store.revalidate_current(&stored, &guard)?;
                let checkpointed = CheckpointedServingBlockdProcess {
                    expected: &expected,
                    handoff: &ready,
                    stored: &stored,
                    desired,
                    authority: &current,
                    store: &store,
                    current_checkpoint: guard,
                };
                checkpointed.assert_current()?;
                let _submission = self.process.start_checkpointed(checkpointed, context)?;

                // The response is never a postcondition.  Revalidate every
                // retained boundary after the ambiguous external call, then
                // require a newly accepted complete inventory.
                let after = self.reread_current(
                    context,
                    &desired_volume.volume_id,
                    &first_authority,
                    first_lease_expiry,
                )?;
                ready.assert_current(stored.checkpoint(), desired, &after)?;
                Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory))
            }
        }
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
    let Some(volume) = runtime.volumes.first() else {
        return Ok(false);
    };
    match &expected.frontend {
        PrepareDeviceFrontend::KernelNbd { .. } => match volume.devices.as_slice() {
            [] => Ok(true),
            [observed] if admitted_exact.is_some() => {
                let Some(exact) = context.kernel_nbd_pool()?.exact_device(expected.cat_id()) else {
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
