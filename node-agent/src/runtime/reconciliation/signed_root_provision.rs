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

use crate::runtime_spine::{
    RuntimeDesiredEffect, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
    RuntimeDesiredEffectStopReason,
};

use super::clean_slate_probes::CHECKPOINT_NAMESPACE;
use super::signed_running::{
    expected_provision_heads, provision_checkpoint_is_bound, ProvisionHeadRead,
};
use super::SignedRunningAcquireEffect;
use super::{
    ensure_root_provision_process_from_persisted_checkpoint, AuthorizedBlockdStore,
    FileCheckpointStore, PlatformSystemdRootProvisionProcessPort, RootProvisionProcessConflict,
    RootProvisionProcessOutcome, RootProvisionProcessPort, RootProvisionResponseHint,
    RootProvisionSystemdConfig, UnixRootProvisionClient,
};

pub(crate) mod request_sealed {
    pub(crate) trait Sealed {}
}

trait RootProvisionRequestPort: request_sealed::Sealed + Send + Sync {
    fn execute(
        &self,
        socket_path: &HostPath,
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
            .execute_with_context(request, context)
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
    ) -> anyhow::Result<Self> {
        Ok(Self {
            acquire,
            provision: SignedRootProvisionEffect::platform(authority, blob, systemd)?,
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
            request: Arc::new(PlatformRootProvisionRequestPort),
            executable_path,
        })
    }

    #[cfg(test)]
    fn for_test(
        authority: Arc<dyn VolumeDataAuthority>,
        blob: Arc<dyn BlobStore>,
        process: Arc<dyn RootProvisionProcessPort>,
        request: Arc<dyn RootProvisionRequestPort>,
        executable_path: HostPath,
    ) -> Self {
        Self {
            authority,
            blob,
            process,
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
        if !base_admission_is_exact(accepted, desired, runtime) {
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
        if stored.content_digest() != content_digest
            || stored.checkpoint().step != runtime.step
            || stored.checkpoint().desired_revision != desired.desired_revision
            || stored.checkpoint().spec_digest != desired.spec_digest
            || stored.checkpoint().placement_epoch != desired.placement.placement_epoch
        {
            return Ok(Some(RuntimeDesiredEffectOutcome::RefreshInventory));
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
        let hint = self
            .request
            .execute(&expectation.control_socket_path, &request, context)?;
        context.check_active()?;
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use cats_api::runtime_reconciliation::{
        checkpoint_content_digest, inventory_digest, spec_digest, AcquireOrigin,
        AdmissionInventoryAttestation, AgentSession, AssignedKind, AssignedPlacement, Durability,
        Epoch, FenceEpoch, GuestDeviceIdentity, Id, Ipv4Address, IsolatedIpv4Kind,
        LocalVolumeLineage, MacAddress, NetworkConfig, NodeBootId, NodeObservation,
        NormalAcquireRequest, NormalAcquireResult, ObservedRuntimeStatus, ObservedVolume,
        ProcessEvidence, RandomId128, Revision, RuntimeCheckpoint, RuntimeConfig, Sequence,
        Sha256Digest, UnixMillis, VolumeRecord, WireU64,
    };
    use cats_storage::authority::{
        AuthorityError, AuthorizedServingAttachment, LastVolumeTransition, RenewLeaseRequest,
        RenewLeaseResult, VolumeAdminState, VolumeHeadCasRequest, VolumeHeadCasResult,
    };
    use cats_storage::{encode_image_manifest, BlobError, ImageManifestV1, LowerHexSha256};

    use crate::runtime_spine::{RuntimeDesiredEffectAdmission, RuntimeDesiredEffectContext};
    use crate::state_directory::StateDirectory;

    use super::super::authorized_blockd::authorized_blockd_data_directory;
    use super::super::root_provision_process::{
        CheckpointedRootProvisionProcess, RootProvisionBlockdHandshake,
        RootProvisionProcessEvidence, RootProvisionProcessInspection, RootProvisionProcessStart,
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

    #[derive(Default)]
    struct FakeProcessPort {
        inspections: AtomicUsize,
        starts: AtomicUsize,
    }

    impl super::super::root_provision_process::sealed::Sealed for FakeProcessPort {}

    impl RootProvisionProcessPort for FakeProcessPort {
        fn inspect(
            &self,
            _expected: &super::super::RootProvisionProcessExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.inspections.fetch_add(1, Ordering::SeqCst);
            Ok(RootProvisionProcessInspection::Absent)
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
    }

    struct FakeRequestPort {
        authority: Arc<FakeAuthority>,
        calls: AtomicUsize,
        conflict: bool,
        mutate_owner: bool,
    }

    impl request_sealed::Sealed for FakeRequestPort {}

    impl RootProvisionRequestPort for FakeRequestPort {
        fn execute(
            &self,
            _socket_path: &HostPath,
            request: &cats_api::runtime_reconciliation::ProvisionRootImageRequest,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionResponseHint> {
            context.check_active()?;
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
            let root = tempfile::tempdir().unwrap();
            let state = StateDirectory::unanchored(root.path().to_path_buf());
            let desired = desired();
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
            self.context_with_lineage_path(processes, None)
        }

        fn context_with_lineage_path(
            &self,
            processes: Vec<ProcessEvidence>,
            lineage_path: Option<HostPath>,
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
                inventory_epoch: epoch(4),
                inventory_digest: digest.clone(),
                inventory_read_position: Sequence::new(12).unwrap(),
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

        fn effect(
            &self,
            process: Arc<FakeProcessPort>,
            request: Arc<FakeRequestPort>,
        ) -> SignedRootProvisionEffect {
            SignedRootProvisionEffect::for_test(
                Arc::clone(&self.authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&self.blob) as Arc<dyn BlobStore>,
                process,
                request,
                HostPath::new("/usr/bin/cats-blockd".to_owned()).unwrap(),
            )
        }
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
                remote_head: expected.attachment.head.clone(),
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
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: false,
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
        assert_eq!(process.inspections.load(Ordering::SeqCst), 0);
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
    fn exact_closed_conflict_with_blank_authority_stops_without_retry() {
        let fixture = Fixture::new();
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: true,
            mutate_owner: false,
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
        let process = Arc::new(FakeProcessPort::default());
        let request = Arc::new(FakeRequestPort {
            authority: Arc::clone(&fixture.authority),
            calls: AtomicUsize::new(0),
            conflict: false,
            mutate_owner: true,
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
}
