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
    ObservedRuntimeStatus, OwnershipTokenEvidence, PrepareDeviceFrontend, ProcessEvidence,
    ProcessRole, ProcessState, RandomId128, ReconcileStep, WireU64,
};
use cats_storage::authority::{VolumeDataAuthority, VolumeRecord};

use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
    RuntimePhysicalReadContext,
};

use super::checkpoint::CurrentCheckpointGuard;
use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::prepare_device_retirement::{
    prepare_device_admission_is_exact, retirement_authority_lease_is_monotonic, unique_runtime,
};
use super::serving_handoff::{PrepareDeviceHandoffReady, ServingHandoffStore};
use super::{
    authorized_blockd_status_is_bound, AuthorizedBlockdCheckpoint, AuthorizedBlockdStore,
    FileCheckpointStore, RootProvisionSystemdConfig, StoredCheckpoint,
};

pub(crate) mod sealed {
    pub(crate) trait Sealed {}
}

/// The only provider boundary allowed to decide whether the serving process
/// is globally absent or exact.  Implementations must include the full
/// systemd unit/cgroup, process argv, managed socket and Unix status sweep.
pub(crate) trait ServingBlockdProcessGlobalPort: sealed::Sealed + Send + Sync {
    fn inspect_exact_or_absent_after_node_global_sweep(
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
}

impl ServingBlockdExpectation {
    fn from_handoff(
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
        let ReconcileStep::PrepareDevice {
            serving_process,
            ownership_token,
            frontend,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("serving blockd expectation requires prepare_device")
        };
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
        Ok(Self {
            volume: ready.authorized_checkpoint().clone(),
            unit_id: serving_process.scope_id.clone(),
            cgroup_path,
            executable_path,
            command_line,
            control_socket_path: serving_process.control_socket_path.clone(),
            data_directory: serving_process.data_directory.clone(),
            process_identity_token: serving_process.process_identity_token.clone(),
            device_ownership_token: ownership_token.clone(),
            frontend: frontend.clone(),
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
    handshake_peer_process_id: u32,
    status: DurabilityStatus,
}

impl ServingBlockdProcessEvidence {
    fn exactly_matches(&self, expected: &ServingBlockdExpectation) -> bool {
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
            && expected.status_is_exact(&self.status)
    }

    #[cfg(test)]
    pub(crate) fn into_process_evidence(&self) -> ProcessEvidence {
        ProcessEvidence {
            role: ProcessRole::Blockd {
                volume_id: Id::new(self.status.volume_id.clone()).unwrap(),
                attachment_id: Id::new(self.status.attachment_id.clone()).unwrap(),
                attachment_epoch: self.status.attachment_epoch.unwrap(),
            },
            process_id: self.process_id,
            process_start_time_ticks: self.process_start_time_ticks,
            executable_path: self.executable_path.clone(),
            scope_id: self.unit_id.clone(),
            control_socket_path: self.control_socket_path.clone(),
            state: ProcessState::Running,
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: self.process_identity_token.clone(),
            },
            control_handshake: ControlHandshakeEvidence::Verified,
            observed_vm_shape: None,
        }
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
    _current_checkpoint: CurrentCheckpointGuard<'a>,
}

impl CheckpointedServingBlockdProcess<'_> {
    pub(crate) fn expected(&self) -> &ServingBlockdExpectation {
        self.expected
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
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
        if !matches!(runtime.step, ReconcileStep::PrepareDevice { .. }) {
            return Ok(None);
        }
        if !prepare_device_admission_is_exact(accepted, desired, runtime) {
            return Ok(Some(stop_local()));
        }

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
        if !accepted_devices_are_compatible(runtime, &expected) {
            return Ok(Some(stop_local()));
        }
        let accepted_process = match runtime.processes.as_slice() {
            [] => None,
            [process] if public_process_matches(process, &expected) => Some(process),
            _ => return Ok(Some(stop_local())),
        };

        context.check_active()?;
        let inspection = self
            .process
            .inspect_exact_or_absent_after_node_global_sweep(&expected, context)?;
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
                    _current_checkpoint: guard,
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
    runtime: &ObservedRuntimeStatus,
    expected: &ServingBlockdExpectation,
) -> bool {
    match &expected.frontend {
        PrepareDeviceFrontend::KernelNbd { .. } => runtime.volumes[0].devices.is_empty(),
        PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => {
            runtime.volumes[0].devices.is_empty()
                || matches!(
                    runtime.volumes[0].devices.as_slice(),
                    [ObservedDevice::VhostUserBlk {
                        guest_device: _,
                        socket_path: observed_socket,
                        ownership_token: OwnershipTokenEvidence::Valid { ownership_token },
                    }] if observed_socket == socket_path
                        && ownership_token == &expected.device_ownership_token
                )
        }
    }
}

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}
