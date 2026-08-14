//! Checkpoint-first PersistentDisk filesystem convergence.
//!
//! The Guest control response is physical evidence only. Every operation is
//! bracketed by the accepted exact VMM/process/device set and the current
//! storage authority; a public mount or blockd status can never select an
//! attachment, filesystem, or successor checkpoint.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::Shutdown;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse, DurabilityStatus};
use cats_api::guest::{
    FilesystemControlOperationV1, FilesystemControlOutcomeV1, FilesystemControlRequestV1,
    FilesystemControlResponseV1, FilesystemIdentityV1, FILESYSTEM_CONTROL_MAX_TIMEOUT_MS_V1,
    GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1, GUEST_HOST_CONTROL_VSOCK_PORT_V1,
};
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, CheckpointEvidence, ContractVersion, DesiredRuntimeSpec, DiskKind,
    FilesystemInitialization, Generation, Id, PersistentFilesystemBinding, PreparedDeviceInput,
    RandomId128, ReconcileStep, RemoteHead, RuntimeLaunchIdentity, RuntimeTarget,
    RuntimeVolumeTransition, RuntimeVolumeTransitionRequest, SessionBinding, UnixMillis,
    VolumeIntent,
};
use cats_storage::authority::{remote_head_is_same_or_later, validate_volume_record};
use cats_storage::authority::{VolumeDataAuthority, VolumeRecord};

use crate::guest_client::GuestClient;
use crate::runtime_spine::{
    RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome, RuntimeDesiredEffectStopReason,
    RuntimePhysicalReadContext,
};

use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::prepare_device_retirement::unique_runtime;
use super::serving_blockd_process::ExactServingBlockdProcessProof;
use super::signed_running::SignedNormalAcquirePort;
use super::vmm_process::ExactVmmProcessProof;
use super::{
    CommitInitializedAttempt, FileCheckpointStore, NormalAcquireAcceptedContext,
    RunningLaunchAuthorityRevalidator, StoredCheckpoint,
};

const BLOCKD_CONTROL_MAX_LINE_BYTES: usize = 64 * 1024;
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(super) trait PersistentFilesystemGuestPort: Send + Sync {
    fn control(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        launch: &RuntimeLaunchIdentity,
        vmm: &ExactVmmProcessProof,
        request: FilesystemControlRequestV1,
    ) -> anyhow::Result<FilesystemControlResponseV1>;
}

pub(super) trait PersistentBlockdControlPort: Send + Sync {
    fn status(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        serving: &ExactServingBlockdProcessProof,
    ) -> anyhow::Result<DurabilityStatus>;

    fn drain(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        serving: &ExactServingBlockdProcessProof,
    ) -> anyhow::Result<DurabilityStatus>;
}

#[derive(Debug, Default)]
struct PlatformPersistentFilesystemGuestPort;

impl PersistentFilesystemGuestPort for PlatformPersistentFilesystemGuestPort {
    fn control(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        launch: &RuntimeLaunchIdentity,
        vmm: &ExactVmmProcessProof,
        request: FilesystemControlRequestV1,
    ) -> anyhow::Result<FilesystemControlResponseV1> {
        context.check_active()?;
        anyhow::ensure!(
            vmm.expectation().launch_identity() == launch,
            "filesystem control VMM differs from retained launch"
        );
        vmm.assert_current(context)?;
        let remaining = remaining(context)?;
        let mut client = GuestClient::connect_hybrid_vsock_bounded(
            Path::new(launch.vsock_socket_path.as_str()),
            GUEST_HOST_CONTROL_VSOCK_PORT_V1,
            remaining,
        )?;
        let shutdown = client.try_clone_transport()?;
        let result = std::thread::scope(|scope| -> anyhow::Result<_> {
            let (sender, receiver) = mpsc::sync_channel(1);
            scope.spawn(move || {
                let result = client.filesystem_control_bounded(request, remaining);
                let _ = sender.send(result);
            });
            loop {
                match receiver.recv_timeout(CONTROL_POLL_INTERVAL) {
                    Ok(result) => return result,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        anyhow::bail!("filesystem control worker exited without a result")
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if let Err(error) = context.check_active() {
                            let _ = shutdown.shutdown(Shutdown::Both);
                            return Err(error);
                        }
                    }
                }
            }
        })?;
        context.check_active()?;
        vmm.assert_current(context)?;
        Ok(result)
    }
}

#[derive(Debug, Default)]
pub(super) struct PlatformPersistentBlockdControlPort;

impl PersistentBlockdControlPort for PlatformPersistentBlockdControlPort {
    fn status(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        serving: &ExactServingBlockdProcessProof,
    ) -> anyhow::Result<DurabilityStatus> {
        let payload = blockd_command(context, serving, BlockdControlCommand::Status)?;
        serde_json::from_str(&payload).context("decode bounded blockd status")
    }

    fn drain(
        &self,
        context: &dyn RuntimePhysicalReadContext,
        serving: &ExactServingBlockdProcessProof,
    ) -> anyhow::Result<DurabilityStatus> {
        blockd_command(context, serving, BlockdControlCommand::Drain)?;
        self.status(context, serving)
    }
}

fn blockd_command(
    context: &dyn RuntimePhysicalReadContext,
    serving: &ExactServingBlockdProcessProof,
    command: BlockdControlCommand,
) -> anyhow::Result<String> {
    context.check_active()?;
    serving.assert_listener_current(context)?;
    let evidence = serving.evidence();
    let mut stream = UnixStream::connect(Path::new(evidence.control_socket_path().as_str()))
        .context("connect exact serving blockd control socket")?;
    ensure_peer_process(&stream, evidence.process_id())?;
    let remaining = remaining(context)?;
    stream.set_write_timeout(Some(remaining.min(Duration::from_millis(500))))?;
    stream.set_read_timeout(Some(CONTROL_POLL_INTERVAL))?;
    stream.write_all(command.as_wire().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut line = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    loop {
        context.check_active()?;
        if line.len() >= BLOCKD_CONTROL_MAX_LINE_BYTES {
            anyhow::bail!("blockd control response exceeds its fixed bound")
        }
        match stream.read(&mut byte) {
            Ok(0) => anyhow::bail!("blockd control response ended before newline"),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(error) => return Err(error).context("read blockd control response"),
        }
    }
    context.check_active()?;
    let line = std::str::from_utf8(&line).context("blockd response is not UTF-8")?;
    match BlockdControlResponse::parse_wire(line) {
        Ok(BlockdControlResponse::Ok(payload)) => Ok(payload),
        Ok(BlockdControlResponse::Error(message)) => {
            anyhow::bail!("blockd {command} rejected: {message}")
        }
        Err(error) => Err(error).context("decode blockd control response"),
    }
}

#[cfg(target_os = "linux")]
fn ensure_peer_process(stream: &UnixStream, expected_process_id: u32) -> anyhow::Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` and `length` are valid writable objects of the
    // sizes passed to getsockopt, and `stream` keeps the fd live for the call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    anyhow::ensure!(
        result == 0
            && length as usize == std::mem::size_of::<libc::ucred>()
            && credentials.pid > 0
            && u32::try_from(credentials.pid).ok() == Some(expected_process_id),
        "blockd control peer is not the exact admitted process"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_peer_process(_stream: &UnixStream, _expected_process_id: u32) -> anyhow::Result<()> {
    anyhow::bail!("exact blockd peer credentials require Linux")
}

fn remaining(context: &dyn RuntimePhysicalReadContext) -> anyhow::Result<Duration> {
    context.check_active()?;
    context
        .deadline()
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("persistent filesystem effect deadline expired")
}

pub(crate) struct PersistentFilesystemEffect {
    authority: Arc<dyn VolumeDataAuthority>,
    transition: Arc<dyn SignedNormalAcquirePort>,
    guest: Arc<dyn PersistentFilesystemGuestPort>,
    blockd: Arc<dyn PersistentBlockdControlPort>,
    launch_authority: Arc<RunningLaunchAuthorityRevalidator>,
}

impl PersistentFilesystemEffect {
    pub(crate) fn platform(
        authority: Arc<dyn VolumeDataAuthority>,
        transition: Arc<dyn SignedNormalAcquirePort>,
        launch_authority: Arc<RunningLaunchAuthorityRevalidator>,
    ) -> Self {
        Self {
            authority,
            transition,
            guest: Arc::new(PlatformPersistentFilesystemGuestPort),
            blockd: Arc::new(PlatformPersistentBlockdControlPort),
            launch_authority,
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(
        authority: Arc<dyn VolumeDataAuthority>,
        transition: Arc<dyn SignedNormalAcquirePort>,
        guest: Arc<dyn PersistentFilesystemGuestPort>,
        blockd: Arc<dyn PersistentBlockdControlPort>,
        launch_authority: Arc<RunningLaunchAuthorityRevalidator>,
    ) -> Self {
        Self {
            authority,
            transition,
            guest,
            blockd,
            launch_authority,
        }
    }

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
        let filesystem_phase = matches!(
            runtime.step,
            ReconcileStep::FormatFilesystem { .. }
                | ReconcileStep::DrainInitialization { .. }
                | ReconcileStep::CommitInitialized { .. }
                | ReconcileStep::MountFilesystem { .. }
        );
        if !filesystem_phase && !matches!(runtime.step, ReconcileStep::StartRuntime { .. }) {
            return Ok(None);
        }
        if desired.target != RuntimeTarget::Running
            || !filesystem_checkpoint_is_current_exact(desired, runtime)
        {
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
        let store = FileCheckpointStore::open_preserving_checkpoint_temp(
            &context.state_directory().path().join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .context("open Persistent filesystem checkpoint")?;
        anyhow::ensure!(
            store.path() == Path::new(checkpoint_path.as_str()),
            "Persistent filesystem admission names another checkpoint"
        );
        let Some(stored) = store
            .load()
            .context("load Persistent filesystem checkpoint")?
        else {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        };
        if stored.content_digest() != content_digest
            || stored.checkpoint().step != runtime.step
            || stored.checkpoint().runtime_launch.identity().is_none()
        {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        }

        let _node_global_effect = context.lock_node_global_effect()?;
        let processes = context.node_global_process()?;
        anyhow::ensure!(
            processes.matches_observation(accepted.observation()),
            "Persistent filesystem process proof is not bound to accepted inventory"
        );
        let Some((vmm_expectation, admitted_vmm)) = processes.vmm(&desired.cat_id) else {
            return Ok(Some(stop_local()));
        };
        if vmm_expectation.checkpoint() != stored.checkpoint() {
            return Ok(Some(stop_local()));
        }
        let Some(vmm) = admitted_vmm else {
            return Ok(if filesystem_phase {
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            } else {
                None
            });
        };

        self.launch_authority
            .revalidate_exact_retained_running(context, desired, &store, &stored, vmm)?;
        match stored.checkpoint().step.clone() {
            ReconcileStep::StartRuntime { .. } => {
                self.plan_first(context, desired, processes, &store, &stored, vmm)
            }
            ReconcileStep::FormatFilesystem { filesystem } => self.apply_format(
                context,
                desired,
                processes,
                &store,
                &stored,
                vmm,
                filesystem.as_ref(),
            ),
            ReconcileStep::DrainInitialization {
                filesystem,
                local_generation,
                remote_generation,
            } => self.apply_drain(
                context,
                desired,
                processes,
                &store,
                &stored,
                vmm,
                filesystem.as_ref(),
                local_generation,
                remote_generation,
            ),
            ReconcileStep::CommitInitialized {
                filesystem,
                new_remote_head,
            } => self.apply_commit(
                context,
                desired,
                processes,
                &store,
                &stored,
                filesystem.as_ref(),
                &new_remote_head,
            ),
            ReconcileStep::MountFilesystem {
                filesystem,
                expected_head,
            } => self.apply_mount(
                context,
                desired,
                processes,
                &store,
                &stored,
                vmm,
                filesystem.as_ref(),
                &expected_head,
            ),
            _ => unreachable!("filesystem phase was selected above"),
        }
        .map(Some)
    }

    fn plan_first(
        &self,
        _context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        processes: &super::NodeGlobalManagedProcessAdmission,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        _vmm: &ExactVmmProcessProof,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let Some(prepared) = ordered_persistent_devices(stored.checkpoint())?
            .into_iter()
            .next()
        else {
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        };
        let filesystem = filesystem_binding(desired, stored.checkpoint(), prepared)?;
        let (serving, authority) =
            self.current_serving_authority(processes, desired, &filesystem.volume_id)?;
        let step = first_step(&filesystem, &authority, serving)?;
        persist_step(store, stored, step)?;
        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_format(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        processes: &super::NodeGlobalManagedProcessAdmission,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        vmm: &ExactVmmProcessProof,
        filesystem: &PersistentFilesystemBinding,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let FilesystemInitialization::Initialize {
            expected_blank_head,
            ..
        } = &filesystem.initialization
        else {
            return Ok(stop_local());
        };
        let launch = stored.checkpoint().runtime_launch.identity().unwrap();
        let probe = match self.guest.control(
            context,
            launch,
            vmm,
            filesystem_request(
                filesystem,
                expected_blank_head,
                FilesystemControlOperationV1::Probe,
            )?,
        ) {
            Ok(response) => response,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        if probe.outcome == FilesystemControlOutcomeV1::Conflict {
            return quarantine(store, stored);
        }
        match &probe.observation.filesystem {
            FilesystemIdentityV1::Blank => {
                self.launch_authority
                    .revalidate_exact_retained_running(context, desired, store, stored, vmm)?;
                let (serving, authority) =
                    self.current_serving_authority(processes, desired, &filesystem.volume_id)?;
                if authority.head != *expected_blank_head
                    || !current_attachment_matches(serving, &authority)
                {
                    return quarantine(store, stored);
                }
                let format = self.guest.control(
                    context,
                    launch,
                    vmm,
                    filesystem_request(
                        filesystem,
                        expected_blank_head,
                        FilesystemControlOperationV1::FormatExt4,
                    )?,
                );
                match format {
                    Ok(response) if response.outcome == FilesystemControlOutcomeV1::Exact => {
                        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
                    }
                    Ok(_) => quarantine(store, stored),
                    Err(_) => Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
                }
            }
            FilesystemIdentityV1::Ext4 { filesystem_uuid }
                if filesystem_uuid == &filesystem.filesystem_uuid =>
            {
                let (serving, authority) =
                    self.current_serving_authority(processes, desired, &filesystem.volume_id)?;
                let status = match self.blockd.status(context, serving) {
                    Ok(status) => status,
                    Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
                };
                if !serving.validates_status_at_head(&status, &authority.head) {
                    return quarantine(store, stored);
                }
                persist_step(
                    store,
                    stored,
                    ReconcileStep::DrainInitialization {
                        filesystem: Box::new(filesystem.clone()),
                        local_generation: status_generation(status.local_durable_generation)?,
                        remote_generation: status_generation(status.remote_durable_generation)?,
                    },
                )?;
                Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            FilesystemIdentityV1::Ext4 { .. } | FilesystemIdentityV1::Foreign => {
                quarantine(store, stored)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_drain(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        processes: &super::NodeGlobalManagedProcessAdmission,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        vmm: &ExactVmmProcessProof,
        filesystem: &PersistentFilesystemBinding,
        local_generation_lower_bound: Generation,
        remote_generation_lower_bound: Generation,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let FilesystemInitialization::Initialize {
            expected_blank_head,
            ..
        } = &filesystem.initialization
        else {
            return Ok(stop_local());
        };
        let launch = stored.checkpoint().runtime_launch.identity().unwrap();
        let probe = match self.guest.control(
            context,
            launch,
            vmm,
            filesystem_request(
                filesystem,
                expected_blank_head,
                FilesystemControlOperationV1::Probe,
            )?,
        ) {
            Ok(response) => response,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        if probe.outcome != FilesystemControlOutcomeV1::Exact
            || !matches!(
                probe.observation.filesystem,
                FilesystemIdentityV1::Ext4 { ref filesystem_uuid }
                    if filesystem_uuid == &filesystem.filesystem_uuid
            )
        {
            return quarantine(store, stored);
        }
        self.launch_authority
            .revalidate_exact_retained_running(context, desired, store, stored, vmm)?;
        match self.guest.control(
            context,
            launch,
            vmm,
            filesystem_request(
                filesystem,
                expected_blank_head,
                FilesystemControlOperationV1::FlushDevice,
            )?,
        ) {
            Ok(response) if response.outcome == FilesystemControlOutcomeV1::Exact => {}
            Ok(_) => return quarantine(store, stored),
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        }
        let (serving, accepted_authority) =
            self.current_serving_authority(processes, desired, &filesystem.volume_id)?;
        vmm.assert_current(context)?;
        serving.assert_listener_current(context)?;
        let status = match self.blockd.drain(context, serving) {
            Ok(status) => status,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        context.check_active()?;
        let authority = self
            .authority
            .load_volume(&filesystem.volume_id)
            .context("load post-drain Persistent Volume authority")?;
        if !post_drain_authority_is_same_attachment(&accepted_authority, &authority)
            || authority.head.generation.get() == 0
            || !durability_generations_preserve_lower_bounds(
                &status,
                local_generation_lower_bound,
                remote_generation_lower_bound,
            )
            || !serving.validates_fully_drained_status_at_head(&status, &authority.head)
        {
            return quarantine(store, stored);
        }
        persist_step(
            store,
            stored,
            ReconcileStep::CommitInitialized {
                filesystem: Box::new(filesystem.clone()),
                new_remote_head: authority.head,
            },
        )?;
        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_commit(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        processes: &super::NodeGlobalManagedProcessAdmission,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        filesystem: &PersistentFilesystemBinding,
        new_remote_head: &RemoteHead,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let accepted = context.accepted_full()?;
        let (serving, authority) =
            self.current_serving_authority(processes, desired, &filesystem.volume_id)?;
        let status = match self.blockd.status(context, serving) {
            Ok(status) => status,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        if &authority.head != new_remote_head
            || !serving.validates_fully_drained_status_at_head(&status, new_remote_head)
        {
            return quarantine(store, stored);
        }
        let volume = desired_volume(desired, &filesystem.volume_id)?;
        let request = RuntimeVolumeTransitionRequest {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: accepted.session().node_id.clone(),
                node_boot_id: accepted.session().node_boot_id.clone(),
                agent_instance_id: accepted.session().agent_instance_id.clone(),
                agent_session_epoch: accepted.session().agent_session_epoch,
            },
            cat_id: desired.cat_id.clone(),
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            transition: RuntimeVolumeTransition::CommitInitialized {
                filesystem: Box::new(filesystem.clone()),
                new_remote_head: new_remote_head.clone(),
            },
        };
        let accepted_context = NormalAcquireAcceptedContext {
            session: accepted.session().clone(),
            inventory_attestation: accepted.attestation().clone(),
        };
        context.check_active()?;
        let attempt = match self.transition.commit_initialized(
            &request,
            volume,
            &accepted_context,
            context.deadline(),
        ) {
            Ok(attempt) => attempt,
            Err(_) => return Ok(stop_local()),
        };
        match attempt {
            CommitInitializedAttempt::Committed(receipt)
                if receipt.initialized_head == *new_remote_head =>
            {
                persist_step(
                    store,
                    stored,
                    ReconcileStep::MountFilesystem {
                        filesystem: Box::new(filesystem.clone()),
                        expected_head: new_remote_head.clone(),
                    },
                )?;
                Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            CommitInitializedAttempt::Committed(_) => quarantine(store, stored),
            CommitInitializedAttempt::RetryExact => Ok(RuntimeDesiredEffectOutcome::RetryExact),
            CommitInitializedAttempt::RefreshInventory | CommitInitializedAttempt::Ambiguous => {
                Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
            }
            CommitInitializedAttempt::ReplanDesired => {
                Ok(RuntimeDesiredEffectOutcome::ReplanDesired)
            }
            CommitInitializedAttempt::SessionReplacementRequired => {
                Ok(RuntimeDesiredEffectOutcome::SessionReplacementRequired)
            }
            CommitInitializedAttempt::IdentityRepairRequired => {
                Ok(RuntimeDesiredEffectOutcome::IdentityRepairRequired)
            }
            CommitInitializedAttempt::AuthorityRejected(reason) => {
                Ok(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::AuthorityRejected(reason),
                ))
            }
            CommitInitializedAttempt::StopForLocalContract => Ok(stop_local()),
            CommitInitializedAttempt::StopForDeploymentMismatch => {
                Ok(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::DeploymentMismatch,
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_mount(
        &self,
        context: &RuntimeDesiredEffectContext,
        desired: &DesiredRuntimeSpec,
        processes: &super::NodeGlobalManagedProcessAdmission,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        vmm: &ExactVmmProcessProof,
        filesystem: &PersistentFilesystemBinding,
        expected_head: &RemoteHead,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let (serving, authority) =
            self.current_serving_authority(processes, desired, &filesystem.volume_id)?;
        if !mount_head_is_authorized(&authority.head, expected_head, None)
            || !current_attachment_matches(serving, &authority)
        {
            return quarantine(store, stored);
        }
        // The MountFilesystem checkpoint head is the attachment-scoped lower
        // bound established by initialization/acquire. Writes may legitimately
        // advance the same attachment before a later Persistent volume reaches
        // its mount turn, so every Guest request binds the fresh exact head.
        let current_head = authority.head.clone();
        let launch = stored.checkpoint().runtime_launch.identity().unwrap();
        let probe = match self.guest.control(
            context,
            launch,
            vmm,
            filesystem_request(
                filesystem,
                &current_head,
                FilesystemControlOperationV1::Probe,
            )?,
        ) {
            Ok(response) => response,
            Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
        };
        if probe.outcome != FilesystemControlOutcomeV1::Exact {
            return quarantine(store, stored);
        }
        if probe.observation.mounts.is_empty() {
            self.launch_authority
                .revalidate_exact_retained_running(context, desired, store, stored, vmm)?;
            let (serving, authority) =
                self.current_serving_authority(processes, desired, &filesystem.volume_id)?;
            if !mount_head_is_authorized(&authority.head, expected_head, Some(&current_head))
                || !current_attachment_matches(serving, &authority)
            {
                return quarantine(store, stored);
            }
            let mount_head = authority.head.clone();
            match self.guest.control(
                context,
                launch,
                vmm,
                filesystem_request(
                    filesystem,
                    &mount_head,
                    FilesystemControlOperationV1::MountExt4,
                )?,
            ) {
                Ok(response) if response.outcome == FilesystemControlOutcomeV1::Exact => {}
                Ok(_) => return quarantine(store, stored),
                Err(_) => return Ok(RuntimeDesiredEffectOutcome::RefreshInventory),
            }
        }
        self.advance_after_mount(desired, processes, store, stored, filesystem)
    }

    fn advance_after_mount(
        &self,
        desired: &DesiredRuntimeSpec,
        processes: &super::NodeGlobalManagedProcessAdmission,
        store: &FileCheckpointStore,
        stored: &StoredCheckpoint,
        mounted: &PersistentFilesystemBinding,
    ) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
        let ordered = ordered_persistent_devices(stored.checkpoint())?;
        let current = ordered
            .iter()
            .position(|device| device.volume_id == mounted.volume_id)
            .context("mounted Persistent device is absent from retained launch")?;
        let Some(next) = ordered.get(current + 1) else {
            return Ok(RuntimeDesiredEffectOutcome::RefreshInventory);
        };
        let filesystem = filesystem_binding(desired, stored.checkpoint(), next)?;
        let (serving, authority) =
            self.current_serving_authority(processes, desired, &filesystem.volume_id)?;
        persist_step(store, stored, first_step(&filesystem, &authority, serving)?)?;
        Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
    }

    fn current_serving_authority<'a>(
        &self,
        processes: &'a super::NodeGlobalManagedProcessAdmission,
        desired: &DesiredRuntimeSpec,
        volume_id: &Id,
    ) -> anyhow::Result<(&'a ExactServingBlockdProcessProof, VolumeRecord)> {
        let (expectation, exact) = processes
            .serving_blockd(&desired.cat_id, volume_id)
            .context("Persistent filesystem lacks one serving process expectation")?;
        let exact = exact.context("Persistent filesystem serving process is not exact")?;
        anyhow::ensure!(
            exact.expectation() == expectation,
            "Persistent filesystem serving proof changed its expectation"
        );
        let authority = self
            .authority
            .load_volume(volume_id)
            .context("load current Persistent Volume authority")?;
        anyhow::ensure!(
            current_attachment_matches(exact, &authority),
            "Persistent Volume authority differs from accepted serving process"
        );
        Ok((exact, authority))
    }
}

fn filesystem_checkpoint_is_current_exact(
    desired: &DesiredRuntimeSpec,
    runtime: &cats_api::runtime_reconciliation::ObservedRuntimeStatus,
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
            runtime_incarnation: Some(_),
            stable_state: None,
            step,
            ..
        } if *version == ContractVersion::V1
            && cat_id == &desired.cat_id
            && node_id == &desired.placement.node_id
            && *placement_epoch == desired.placement.placement_epoch
            && *desired_revision == desired.desired_revision
            && spec_digest == &desired.spec_digest
            && step.as_ref() == &runtime.step
    )
}

fn current_attachment_matches(
    serving: &ExactServingBlockdProcessProof,
    authority: &VolumeRecord,
) -> bool {
    validate_volume_record(authority).is_ok()
        && serving.expectation().matches_current_authority(authority)
}

/// A fresh Mount authority must preserve both durable bounds: the head sealed
/// in the checkpoint and, after the final launch barrier, the exact head sent
/// to the preceding Guest Probe. Checking only the older checkpoint bound
/// would let a stale authority read regress within the same attachment.
fn mount_head_is_authorized(
    current: &RemoteHead,
    checkpoint_lower_bound: &RemoteHead,
    probed_head: Option<&RemoteHead>,
) -> bool {
    remote_head_is_same_or_later(current, checkpoint_lower_bound)
        && probed_head.is_none_or(|probed| remote_head_is_same_or_later(current, probed))
}

/// The DrainInitialization checkpoint preserves acknowledged Relaxed data as
/// two independent lower bounds. A restarted or replaced blockd cannot turn a
/// lower, internally consistent `R == L` pair into initialization success.
fn durability_generations_preserve_lower_bounds(
    status: &DurabilityStatus,
    local_generation_lower_bound: Generation,
    remote_generation_lower_bound: Generation,
) -> bool {
    status_generation(status.local_durable_generation)
        .ok()
        .zip(status_generation(status.remote_durable_generation).ok())
        .is_some_and(|(local, remote)| {
            local >= local_generation_lower_bound && remote >= remote_generation_lower_bound
        })
}

/// A successful Relaxed drain may publish a new RemoteHead on the same fenced
/// attachment. The accepted process sidecar remains intentionally bound to
/// the pre-drain head, so it is only a lower bound here: the independent
/// post-drain authority read and exact blockd status must agree on the new
/// head while every non-head authority field remains closed.
pub(super) fn post_drain_authority_is_same_attachment(
    before: &VolumeRecord,
    after: &VolumeRecord,
) -> bool {
    validate_volume_record(before).is_ok()
        && validate_volume_record(after).is_ok()
        && before.volume_id == after.volume_id
        && before.size_bytes == after.size_bytes
        && before.durability == after.durability
        && before.admin_state == after.admin_state
        && before.lease_owner == after.lease_owner
        && before.lease_epoch == after.lease_epoch
        && before.last_transition == after.last_transition
        && before
            .lease_expires_at
            .zip(after.lease_expires_at)
            .is_some_and(|(accepted, current)| current >= accepted)
        && remote_head_is_same_or_later(&after.head, &before.head)
}

fn first_step(
    filesystem: &PersistentFilesystemBinding,
    authority: &VolumeRecord,
    serving: &ExactServingBlockdProcessProof,
) -> anyhow::Result<ReconcileStep> {
    anyhow::ensure!(current_attachment_matches(serving, authority));
    match &filesystem.initialization {
        FilesystemInitialization::Initialize {
            expected_blank_head,
            ..
        } => {
            anyhow::ensure!(
                authority.head == *expected_blank_head,
                "uninitialized Persistent Volume is not at its exact blank predecessor"
            );
            Ok(ReconcileStep::FormatFilesystem {
                filesystem: Box::new(filesystem.clone()),
            })
        }
        FilesystemInitialization::Existing => {
            anyhow::ensure!(
                authority.head.generation.get() > 0,
                "Existing Persistent Volume has a blank head"
            );
            Ok(ReconcileStep::MountFilesystem {
                filesystem: Box::new(filesystem.clone()),
                expected_head: authority.head.clone(),
            })
        }
    }
}

fn desired_volume<'a>(
    desired: &'a DesiredRuntimeSpec,
    volume_id: &Id,
) -> anyhow::Result<&'a VolumeIntent> {
    let mut matches = desired
        .volumes
        .iter()
        .filter(|volume| &volume.volume_id == volume_id);
    let volume = matches
        .next()
        .context("Persistent device is absent from Desired")?;
    anyhow::ensure!(matches.next().is_none(), "Desired repeats one Volume");
    Ok(volume)
}

fn ordered_persistent_devices(
    checkpoint: &cats_api::runtime_reconciliation::RuntimeCheckpoint,
) -> anyhow::Result<Vec<&PreparedDeviceInput>> {
    let launch = checkpoint
        .runtime_launch
        .identity()
        .context("Persistent filesystem checkpoint lacks retained launch")?;
    let mut devices = launch
        .devices
        .iter()
        .filter(|device| device.disk_kind == DiskKind::Persistent)
        .collect::<Vec<_>>();
    devices.sort_by(|left, right| {
        (left.guest_device.slot, left.guest_device.serial.as_str())
            .cmp(&(right.guest_device.slot, right.guest_device.serial.as_str()))
    });
    anyhow::ensure!(devices.windows(2).all(|pair| {
        pair[0].guest_device.slot < pair[1].guest_device.slot
            && pair[0].volume_id != pair[1].volume_id
    }));
    Ok(devices)
}

fn filesystem_binding(
    desired: &DesiredRuntimeSpec,
    checkpoint: &cats_api::runtime_reconciliation::RuntimeCheckpoint,
    prepared: &PreparedDeviceInput,
) -> anyhow::Result<PersistentFilesystemBinding> {
    let launch = checkpoint.runtime_launch.identity().unwrap();
    let intent = desired_volume(desired, &prepared.volume_id)?;
    let mount = intent
        .mount
        .as_ref()
        .context("Persistent Desired volume lacks ext4 mount intent")?;
    anyhow::ensure!(
        desired.target == RuntimeTarget::Running
            && prepared.disk_kind == DiskKind::Persistent
            && intent.disk_kind == DiskKind::Persistent
            && prepared.volume_intent_id == intent.volume_intent_id
            && prepared.disk_id == intent.disk_id
            && prepared.volume_id == intent.volume_id
            && prepared.attachment_id == intent.attachment_id
            && prepared.size_bytes == intent.size_bytes
            && prepared.durability == intent.durability
            && prepared.guest_device == intent.guest_device
            && match &mount.initialization {
                FilesystemInitialization::Initialize {
                    expected_blank_head,
                    ..
                } => prepared.expected_head == *expected_blank_head,
                FilesystemInitialization::Existing => {
                    prepared.expected_head.generation.get() > 0
                }
            },
        "Persistent PreparedDeviceInput differs from Desired mount authority"
    );
    Ok(PersistentFilesystemBinding {
        runtime_incarnation: launch.runtime_incarnation.clone(),
        volume_intent_id: prepared.volume_intent_id.clone(),
        disk_id: prepared.disk_id.clone(),
        volume_id: prepared.volume_id.clone(),
        attachment_id: prepared.attachment_id.clone(),
        attachment_epoch: prepared.attachment_epoch,
        size_bytes: prepared.size_bytes,
        guest_device: prepared.guest_device.clone(),
        filesystem_uuid: mount.filesystem_uuid.clone(),
        mount_path: mount.mount_path.clone(),
        initialization: mount.initialization.clone(),
    })
}

fn filesystem_request(
    filesystem: &PersistentFilesystemBinding,
    expected_head: &RemoteHead,
    operation: FilesystemControlOperationV1,
) -> anyhow::Result<FilesystemControlRequestV1> {
    let request = FilesystemControlRequestV1 {
        version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
        challenge: RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .context("generated filesystem challenge is invalid")?,
        timeout_ms: FILESYSTEM_CONTROL_MAX_TIMEOUT_MS_V1,
        operation,
        filesystem: Box::new(filesystem.clone()),
        expected_head: expected_head.clone(),
    };
    request
        .validate()
        .context("validate checkpoint-bound filesystem request")?;
    Ok(request)
}

pub(super) fn status_generation(value: i64) -> anyhow::Result<Generation> {
    let value = u64::try_from(value).context("blockd reported a negative generation")?;
    Generation::new(value).context("blockd generation exceeds the wire range")
}

fn persist_step(
    store: &FileCheckpointStore,
    current: &StoredCheckpoint,
    step: ReconcileStep,
) -> anyhow::Result<StoredCheckpoint> {
    let mut successor = current.checkpoint().clone();
    successor.stable_state = None;
    successor.step = step;
    successor.updated_at_unix_ms = monotonic_timestamp(current)?;
    encode_runtime_checkpoint(&successor).context("encode Persistent filesystem successor")?;
    store
        .replace(current, &successor)
        .context("persist Persistent filesystem successor")
}

fn quarantine(
    store: &FileCheckpointStore,
    current: &StoredCheckpoint,
) -> anyhow::Result<RuntimeDesiredEffectOutcome> {
    persist_step(store, current, ReconcileStep::Quarantined)?;
    Ok(RuntimeDesiredEffectOutcome::RefreshInventory)
}

fn monotonic_timestamp(current: &StoredCheckpoint) -> anyhow::Result<UnixMillis> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis();
    let now = u64::try_from(now).context("system time exceeds the wire range")?;
    let next = current
        .checkpoint()
        .updated_at_unix_ms
        .get()
        .checked_add(1)
        .context("Persistent filesystem checkpoint timestamp exhausted")?;
    UnixMillis::new(now.max(next)).context("Persistent filesystem timestamp is invalid")
}

fn stop_local() -> RuntimeDesiredEffectOutcome {
    RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
}

#[cfg(test)]
mod tests {
    use cats_storage::authority::{
        normal_acquire, AsciiText, Epoch, FenceEpoch, NormalAcquireRequest, Revision, Sha256Digest,
        VolumeAdminState, VolumeDurability,
    };

    use super::*;

    fn relaxed_owned_record_with_transition(transition_id: &str) -> VolumeRecord {
        let predecessor = VolumeRecord {
            volume_id: Id::new("vol_relaxed").unwrap(),
            size_bytes: 4_096,
            durability: VolumeDurability::Relaxed,
            admin_state: VolumeAdminState::Active,
            head: RemoteHead {
                generation: Generation::new(0).unwrap(),
                root_hash: None,
                root_object_id: None,
            },
            lease_owner: None,
            lease_epoch: FenceEpoch::new(0).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        };
        normal_acquire(
            &predecessor,
            &NormalAcquireRequest {
                volume_id: predecessor.volume_id.clone(),
                transition_id: RandomId128::new(transition_id).unwrap(),
                attachment_id: Id::new("att_relaxed").unwrap(),
                expected_unowned_epoch: predecessor.lease_epoch,
                desired_revision: Revision::new(1).unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
                lease_duration_ms: 60_000,
            },
            UnixMillis::new(10_000).unwrap(),
        )
        .unwrap()
        .0
    }

    fn relaxed_owned_record() -> VolumeRecord {
        relaxed_owned_record_with_transition("11111111111111111111111111111111")
    }

    fn head(generation: u64, fill: u8) -> RemoteHead {
        RemoteHead {
            generation: Generation::new(generation).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([fill; 32])),
            root_object_id: Some(AsciiText::new(format!("roots/{fill:02x}")).unwrap()),
        }
    }

    #[test]
    fn relaxed_post_drain_head_may_advance_only_on_the_exact_attachment() {
        let before = relaxed_owned_record();
        let mut after = before.clone();
        after.head = head(1, 1);
        after.lease_expires_at = Some(UnixMillis::new(70_001).unwrap());
        assert!(post_drain_authority_is_same_attachment(&before, &after));

        let mut wrong = after.clone();
        wrong.lease_owner = Some(Id::new("att_foreign").unwrap());
        assert!(!post_drain_authority_is_same_attachment(&before, &wrong));

        let mut wrong = after.clone();
        wrong.lease_epoch = FenceEpoch::new(2).unwrap();
        assert!(!post_drain_authority_is_same_attachment(&before, &wrong));

        let mut wrong = after.clone();
        wrong.lease_expires_at = before
            .lease_expires_at
            .and_then(|expiry| UnixMillis::new(expiry.get() - 1));
        assert!(!post_drain_authority_is_same_attachment(&before, &wrong));

        let mut advanced = after.clone();
        advanced.head = head(2, 2);
        assert!(post_drain_authority_is_same_attachment(&after, &advanced));
        assert!(!post_drain_authority_is_same_attachment(&advanced, &after));

        let mut conflicting = after.clone();
        conflicting.head = head(1, 9);
        assert!(!post_drain_authority_is_same_attachment(
            &after,
            &conflicting
        ));
    }

    #[test]
    fn post_drain_rejects_same_owner_epoch_aba_and_contract_drift() {
        let before = relaxed_owned_record();
        let mut after = before.clone();
        after.head = head(1, 1);
        after.lease_expires_at = Some(UnixMillis::new(70_001).unwrap());

        // An exact attachment is more than the surface owner/epoch pair. A
        // replayed acquire marker with the same owner and epoch is an ABA
        // conflict even when all other fields and the drained head agree.
        let mut replayed_acquire =
            relaxed_owned_record_with_transition("22222222222222222222222222222222");
        replayed_acquire.head = after.head.clone();
        replayed_acquire.lease_expires_at = after.lease_expires_at;
        assert!(validate_volume_record(&replayed_acquire).is_ok());
        assert!(!post_drain_authority_is_same_attachment(
            &before,
            &replayed_acquire
        ));

        let mut wrong = after.clone();
        wrong.volume_id = Id::new("vol_rebound").unwrap();
        assert!(!post_drain_authority_is_same_attachment(&before, &wrong));

        let mut wrong = after.clone();
        wrong.size_bytes += 4_096;
        assert!(!post_drain_authority_is_same_attachment(&before, &wrong));

        let mut wrong = after.clone();
        wrong.durability = VolumeDurability::Strict;
        assert!(!post_drain_authority_is_same_attachment(&before, &wrong));

        let mut wrong = after.clone();
        wrong.admin_state = VolumeAdminState::Deleting {
            delete_id: Id::new("delete_rebound").unwrap(),
        };
        assert!(!post_drain_authority_is_same_attachment(&before, &wrong));

        let mut wrong = after;
        wrong.last_transition = None;
        assert!(!post_drain_authority_is_same_attachment(&before, &wrong));
    }

    #[test]
    fn mount_final_authority_cannot_regress_after_the_guest_probe() {
        let checkpoint_lower_bound = head(1, 1);
        let probed_head = head(3, 3);

        // Looking only at the checkpoint lower bound would accept this stale
        // generation-two read after Probe already observed generation three.
        let stale_after_probe = head(2, 2);
        assert!(remote_head_is_same_or_later(
            &stale_after_probe,
            &checkpoint_lower_bound
        ));
        assert!(!mount_head_is_authorized(
            &stale_after_probe,
            &checkpoint_lower_bound,
            Some(&probed_head)
        ));

        let conflicting_same_generation = head(3, 9);
        assert!(!mount_head_is_authorized(
            &conflicting_same_generation,
            &checkpoint_lower_bound,
            Some(&probed_head)
        ));

        let advanced = head(4, 4);
        assert!(mount_head_is_authorized(
            &advanced,
            &checkpoint_lower_bound,
            Some(&probed_head)
        ));
    }

    #[test]
    fn initialization_drain_cannot_regress_checkpointed_watermarks() {
        let status = |local_durable_generation, remote_durable_generation| DurabilityStatus {
            volume_id: String::new(),
            attachment_id: String::new(),
            attachment_epoch: None,
            acquire_origin: None,
            node_id: None,
            placement_epoch: None,
            guest_io_enabled: None,
            size_bytes: None,
            scope_id: None,
            process_identity_token: None,
            device_ownership_token: None,
            guest_device_serial: None,
            control_only: None,
            remote_head: None,
            mode: "relaxed".to_owned(),
            local_durable_generation,
            remote_durable_generation,
            unpublished_generations: 0,
            unpublished_bytes: 0,
            oldest_unpublished_age_ms: 0,
            max_unpublished_generations: 4_096,
            max_unpublished_bytes: 8 << 30,
            local_allocated_bytes: 0,
            local_accounted_bytes: 0,
            max_local_bytes: 16 << 30,
            evicted_cache_chunks: 0,
            backpressured: false,
            fenced: false,
            last_publish_error: None,
        };
        let local_lower_bound = Generation::new(5).unwrap();
        let remote_lower_bound = Generation::new(3).unwrap();

        assert!(durability_generations_preserve_lower_bounds(
            &status(5, 5),
            local_lower_bound,
            remote_lower_bound
        ));
        assert!(durability_generations_preserve_lower_bounds(
            &status(7, 7),
            local_lower_bound,
            remote_lower_bound
        ));
        assert!(!durability_generations_preserve_lower_bounds(
            &status(4, 4),
            local_lower_bound,
            remote_lower_bound
        ));
        assert!(!durability_generations_preserve_lower_bounds(
            &status(6, 2),
            local_lower_bound,
            remote_lower_bound
        ));
        assert!(!durability_generations_preserve_lower_bounds(
            &status(-1, -1),
            local_lower_bound,
            remote_lower_bound
        ));
    }
}
