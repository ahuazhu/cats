//! Checkpoint-first process ownership for the root-provision blockd.
//!
//! This is the narrow provider-neutral boundary between Runtime
//! Reconciliation v1 and a future systemd transient-unit adapter. The adapter
//! may create or adopt a process only through the exact physical identity
//! already fsynced in `ReconcileStep::ProvisionRootImage`. An ambiguous start
//! is resolved by inspection; it is never retried in the same reconciliation
//! unit and a mismatching process is never stopped by name.

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    Durability, Epoch, FenceEpoch, HostPath, Id, RandomId128, ReconcileStep, Revision,
    RuntimeCheckpoint, Sha256Digest, WireU64,
};
use cats_storage::authority::{AttachmentLineageIdentity, AuthorizedServingAttachment};

use crate::runtime_spine::RuntimeDesiredEffectContext;

use super::{FileCheckpointStore, StoredCheckpoint};

pub(crate) mod sealed {
    pub(crate) trait Sealed {}
}

/// The exact checkpoint and grant binding a control-only blockd attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootProvisionProcessExpectation {
    pub cat_id: Id,
    pub node_id: Id,
    pub placement_epoch: Epoch,
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub provision_transition_id: RandomId128,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub scope_id: Id,
    pub control_socket_path: HostPath,
    pub data_directory: HostPath,
    pub process_identity_token: RandomId128,
    pub size_bytes: u64,
    pub boot_image_digest: Sha256Digest,
    pub attachment: AuthorizedServingAttachment,
    pub executable_path: HostPath,
}

impl RootProvisionProcessExpectation {
    pub(crate) fn from_checkpoint(
        checkpoint: &RuntimeCheckpoint,
        attachment: AuthorizedServingAttachment,
        executable_path: HostPath,
    ) -> anyhow::Result<Self> {
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
            expected_blank_head,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("checkpoint is not at provision_root_image")
        };
        let identity = &attachment.identity;
        anyhow::ensure!(
            checkpoint.node_id == identity.node_id
                && checkpoint.placement_epoch == identity.placement_epoch
                && *volume_id == identity.volume_id
                && *attachment_id == identity.attachment_id
                && *attachment_epoch == identity.attachment_epoch
                && *size_bytes == attachment.size_bytes
                && *expected_blank_head == attachment.head,
            "root-provision checkpoint and authorized grant do not form one exact lineage"
        );
        anyhow::ensure!(
            executable_path.as_str().starts_with('/'),
            "root-provision executable path must be absolute"
        );
        Ok(Self {
            cat_id: checkpoint.cat_id.clone(),
            node_id: checkpoint.node_id.clone(),
            placement_epoch: checkpoint.placement_epoch,
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            provision_transition_id: provision_transition_id.clone(),
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: *attachment_epoch,
            scope_id: scope_id.clone(),
            control_socket_path: control_socket_path.clone(),
            data_directory: data_directory.clone(),
            process_identity_token: process_identity_token.clone(),
            size_bytes: *size_bytes,
            boot_image_digest: boot_image_digest.clone(),
            attachment,
            executable_path,
        })
    }
}

/// Exact self-description required from the blockd control handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootProvisionBlockdHandshake {
    pub identity: AttachmentLineageIdentity,
    pub size_bytes: u64,
    pub durability: Durability,
    pub process_identity_token: RandomId128,
    pub control_only: bool,
    pub guest_io_enabled: bool,
}

/// One process identity proven jointly by the process owner and blockd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootProvisionProcessEvidence {
    pub process_id: u32,
    pub process_start_time_ticks: WireU64,
    pub executable_path: HostPath,
    pub scope_id: Id,
    pub cgroup_path: HostPath,
    pub control_socket_path: HostPath,
    pub data_directory: HostPath,
    pub ownership_token: RandomId128,
    pub handshake: RootProvisionBlockdHandshake,
}

impl RootProvisionProcessEvidence {
    fn exactly_matches(&self, expected: &RootProvisionProcessExpectation) -> bool {
        self.executable_path == expected.executable_path
            && self.scope_id == expected.scope_id
            && self.control_socket_path == expected.control_socket_path
            && self.data_directory == expected.data_directory
            && self.ownership_token == expected.process_identity_token
            && self.handshake.identity == expected.attachment.identity
            && self.handshake.size_bytes == expected.size_bytes
            && self.handshake.durability == expected.attachment.durability
            && self.handshake.process_identity_token == expected.process_identity_token
            && self.handshake.control_only
            && !self.handshake.guest_io_enabled
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootProvisionProcessConflict {
    DuplicateIdentity,
    IdentityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootProvisionProcessInspection {
    Absent,
    Exact(Box<RootProvisionProcessEvidence>),
    Conflict(RootProvisionProcessConflict),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootProvisionProcessStart {
    Started(Box<RootProvisionProcessEvidence>),
    /// The create request may have reached the process owner. The caller must
    /// inspect once and must not issue a second create in this unit.
    Ambiguous,
    /// No process was created, or an exactly identified created process was
    /// killed and waited for before this result was returned.
    CancelledClean,
    Unavailable,
}

/// Provider-neutral process owner. Production implementations are sealed to
/// this crate so the legacy naked-`Command` path cannot satisfy the port.
pub(crate) trait RootProvisionProcessPort: sealed::Sealed + Send + Sync {
    fn inspect(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection>;

    fn start_checkpointed(
        &self,
        checkpointed: CheckpointedRootProvisionProcess<'_>,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessStart>;
}

/// Unforgeable proof, within this module, that the complete process identity
/// crossed the checkpoint directory durability barrier.
pub(crate) struct CheckpointedRootProvisionProcess<'a> {
    expected: &'a RootProvisionProcessExpectation,
}

impl<'a> CheckpointedRootProvisionProcess<'a> {
    pub(crate) fn expected(&self) -> &'a RootProvisionProcessExpectation {
        self.expected
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootProvisionProcessOutcome {
    Started(Box<RootProvisionProcessEvidence>),
    Adopted(Box<RootProvisionProcessEvidence>),
    RecoveredAfterAmbiguousStart(Box<RootProvisionProcessEvidence>),
    AbsentAfterAmbiguousStart,
    Conflict(RootProvisionProcessConflict),
    CancelledClean,
    Unavailable,
}

#[derive(Debug)]
pub(crate) struct RootProvisionProcessEnsureResult {
    pub checkpoint: StoredCheckpoint,
    pub outcome: RootProvisionProcessOutcome,
}

/// Atomically replace the exact predecessor checkpoint, then and only then
/// inspect/create the root-provision process. A lost create response is
/// followed by exactly one inspection and never a second create.
pub(crate) fn ensure_root_provision_process_after_checkpoint<P>(
    store: &FileCheckpointStore,
    predecessor: &StoredCheckpoint,
    checkpoint: &RuntimeCheckpoint,
    attachment: AuthorizedServingAttachment,
    executable_path: HostPath,
    port: &P,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<RootProvisionProcessEnsureResult>
where
    P: RootProvisionProcessPort + ?Sized,
{
    context.check_active()?;
    let expected =
        RootProvisionProcessExpectation::from_checkpoint(checkpoint, attachment, executable_path)?;
    let persisted = store
        .replace(predecessor, checkpoint)
        .context("persist root-provision process identity before process effect")?;

    context.check_active()?;
    let inspection = port
        .inspect(&expected, context)
        .context("inspect exact root-provision process identity")?;
    let outcome = match inspection {
        RootProvisionProcessInspection::Exact(evidence) => {
            match_exact(&expected, evidence, RootProvisionProcessOutcome::Adopted)
        }
        RootProvisionProcessInspection::Conflict(problem) => {
            RootProvisionProcessOutcome::Conflict(problem)
        }
        RootProvisionProcessInspection::Unavailable => RootProvisionProcessOutcome::Unavailable,
        RootProvisionProcessInspection::Absent => {
            context.check_active()?;
            let checkpointed = CheckpointedRootProvisionProcess {
                expected: &expected,
            };
            match port
                .start_checkpointed(checkpointed, context)
                .context("start exact checkpointed root-provision process")?
            {
                RootProvisionProcessStart::Started(evidence) => {
                    match_exact(&expected, evidence, RootProvisionProcessOutcome::Started)
                }
                RootProvisionProcessStart::CancelledClean => {
                    RootProvisionProcessOutcome::CancelledClean
                }
                RootProvisionProcessStart::Unavailable => RootProvisionProcessOutcome::Unavailable,
                RootProvisionProcessStart::Ambiguous => {
                    match port
                        .inspect(&expected, context)
                        .context("recover ambiguous root-provision process start")?
                    {
                        RootProvisionProcessInspection::Exact(evidence) => match_exact(
                            &expected,
                            evidence,
                            RootProvisionProcessOutcome::RecoveredAfterAmbiguousStart,
                        ),
                        RootProvisionProcessInspection::Absent => {
                            RootProvisionProcessOutcome::AbsentAfterAmbiguousStart
                        }
                        RootProvisionProcessInspection::Conflict(problem) => {
                            RootProvisionProcessOutcome::Conflict(problem)
                        }
                        RootProvisionProcessInspection::Unavailable => {
                            RootProvisionProcessOutcome::Unavailable
                        }
                    }
                }
            }
        }
    };
    Ok(RootProvisionProcessEnsureResult {
        checkpoint: persisted,
        outcome,
    })
}

fn match_exact(
    expected: &RootProvisionProcessExpectation,
    evidence: Box<RootProvisionProcessEvidence>,
    outcome: impl FnOnce(Box<RootProvisionProcessEvidence>) -> RootProvisionProcessOutcome,
) -> RootProvisionProcessOutcome {
    if evidence.exactly_matches(expected) {
        outcome(evidence)
    } else {
        RootProvisionProcessOutcome::Conflict(RootProvisionProcessConflict::IdentityMismatch)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        ContractVersion, Generation, GuestTransportEvidence, LifecycleAdmission, RemoteHead,
        RequireIdleCheckpoint, UnixMillis, WarmSnapshotEvidence,
    };

    use super::*;
    use crate::runtime::reconciliation::checkpoint::WriteStage;
    use crate::state_directory::StateDirectory;

    #[derive(Default)]
    struct FakePortState {
        inspections: VecDeque<RootProvisionProcessInspection>,
        starts: VecDeque<RootProvisionProcessStart>,
        inspect_calls: usize,
        start_calls: usize,
    }

    #[derive(Default)]
    struct FakePort {
        state: Mutex<FakePortState>,
    }

    impl sealed::Sealed for FakePort {}

    impl RootProvisionProcessPort for FakePort {
        fn inspect(
            &self,
            _expected: &RootProvisionProcessExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            let mut state = self.state.lock().unwrap();
            state.inspect_calls += 1;
            Ok(state
                .inspections
                .pop_front()
                .unwrap_or(RootProvisionProcessInspection::Unavailable))
        }

        fn start_checkpointed(
            &self,
            checkpointed: CheckpointedRootProvisionProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<RootProvisionProcessStart> {
            assert_eq!(checkpointed.expected().scope_id, id("cats-root.scope"));
            let mut state = self.state.lock().unwrap();
            state.start_calls += 1;
            Ok(state
                .starts
                .pop_front()
                .unwrap_or(RootProvisionProcessStart::Unavailable))
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        StateDirectory,
        FileCheckpointStore,
        StoredCheckpoint,
        RuntimeCheckpoint,
        AuthorizedServingAttachment,
        RootProvisionProcessEvidence,
    ) {
        let root = tempfile::tempdir().unwrap();
        let state_directory = std::fs::File::open(root.path()).unwrap();
        let state = StateDirectory::from_test_directory(&state_directory, root.path()).unwrap();
        let checkpoint_dir = root.path().join("checkpoints");
        let store = FileCheckpointStore::open(&checkpoint_dir, &id("cat_01")).unwrap();
        let attachment = attachment();
        let mut predecessor = checkpoint(ReconcileStep::InspectInventory {
            inventory_epoch: epoch(1),
        });
        predecessor.volumes = Vec::new();
        let predecessor = store.create(&predecessor).unwrap();
        let staged = checkpoint(ReconcileStep::ProvisionRootImage {
            provision_transition_id: random('3'),
            volume_id: id("vol_root"),
            attachment_id: id("att_root"),
            attachment_epoch: fence(7),
            scope_id: id("cats-root.scope"),
            control_socket_path: host("/run/cats/cat_01/root-provision.sock"),
            data_directory: host("/var/lib/cats/cat_01/root"),
            process_identity_token: random('4'),
            size_bytes: 4_194_304,
            boot_image_digest: digest('1'),
            expected_blank_head: blank_head(),
            expected_provisioned_head: RemoteHead {
                generation: Generation::new(1).unwrap(),
                root_hash: Some(digest('2')),
                root_object_id: Some(
                    cats_api::runtime_reconciliation::AsciiText::new("roots/root-1").unwrap(),
                ),
            },
        });
        let evidence = evidence(&attachment);
        (
            root,
            state,
            store,
            predecessor,
            staged,
            attachment,
            evidence,
        )
    }

    #[test]
    fn durable_checkpoint_precedes_inspect_and_start() {
        let (_root, state, store, predecessor, staged, attachment, evidence) = fixture();
        let port = FakePort::default();
        {
            let mut fake = port.state.lock().unwrap();
            fake.inspections
                .push_back(RootProvisionProcessInspection::Absent);
            fake.starts
                .push_back(RootProvisionProcessStart::Started(Box::new(
                    evidence.clone(),
                )));
        }
        let result = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            attachment,
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .unwrap();
        assert_eq!(result.checkpoint.checkpoint(), &staged);
        assert_eq!(
            result.outcome,
            RootProvisionProcessOutcome::Started(Box::new(evidence))
        );
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (1, 1));
    }

    #[test]
    fn every_checkpoint_crash_window_has_zero_process_effect() {
        for stage in [
            WriteStage::Write,
            WriteStage::TempWritten,
            WriteStage::FileSynced,
            WriteStage::Renamed,
            WriteStage::DirectorySynced,
        ] {
            let (_root, state, store, predecessor, staged, attachment, _evidence) = fixture();
            let port = FakePort::default();
            store.inject_crash_once(stage);
            let error = ensure_root_provision_process_after_checkpoint(
                &store,
                &predecessor,
                &staged,
                attachment,
                host("/usr/bin/cats-blockd"),
                &port,
                &context(state),
            )
            .expect_err("checkpoint crash must stop before process I/O");
            assert!(format!("{error:#}").contains("checkpoint"));
            let fake = port.state.lock().unwrap();
            assert_eq!((fake.inspect_calls, fake.start_calls), (0, 0));
        }
    }

    #[test]
    fn ambiguous_start_adopts_only_one_exact_reinspection() {
        let (_root, state, store, predecessor, staged, attachment, evidence) = fixture();
        let port = FakePort::default();
        {
            let mut fake = port.state.lock().unwrap();
            fake.inspections.extend([
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Exact(Box::new(evidence.clone())),
            ]);
            fake.starts.push_back(RootProvisionProcessStart::Ambiguous);
        }
        let result = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            attachment,
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .unwrap();
        assert_eq!(
            result.outcome,
            RootProvisionProcessOutcome::RecoveredAfterAmbiguousStart(Box::new(evidence))
        );
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (2, 1));
    }

    #[test]
    fn ambiguous_absence_and_foreign_identity_never_retry_or_terminate() {
        let (_root, state, store, predecessor, staged, attachment, _evidence) = fixture();
        let port = FakePort::default();
        {
            let mut fake = port.state.lock().unwrap();
            fake.inspections.extend([
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ]);
            fake.starts.push_back(RootProvisionProcessStart::Ambiguous);
        }
        let result = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            attachment,
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .unwrap();
        assert_eq!(
            result.outcome,
            RootProvisionProcessOutcome::AbsentAfterAmbiguousStart
        );
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (2, 1));

        let (_root, state, store, predecessor, staged, attachment, _evidence) = fixture();
        let port = FakePort::default();
        port.state
            .lock()
            .unwrap()
            .inspections
            .push_back(RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity,
            ));
        let result = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            attachment,
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .unwrap();
        assert_eq!(
            result.outcome,
            RootProvisionProcessOutcome::Conflict(RootProvisionProcessConflict::DuplicateIdentity)
        );
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (1, 0));
    }

    #[test]
    fn mismatched_started_evidence_is_conflict_and_never_killed() {
        let (_root, state, store, predecessor, staged, attachment, mut evidence) = fixture();
        evidence.ownership_token = random('9');
        let port = FakePort::default();
        {
            let mut fake = port.state.lock().unwrap();
            fake.inspections
                .push_back(RootProvisionProcessInspection::Absent);
            fake.starts
                .push_back(RootProvisionProcessStart::Started(Box::new(evidence)));
        }
        let result = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            attachment,
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .unwrap();
        assert_eq!(
            result.outcome,
            RootProvisionProcessOutcome::Conflict(RootProvisionProcessConflict::IdentityMismatch)
        );
        assert_eq!(port.state.lock().unwrap().start_calls, 1);
    }

    #[test]
    fn cancelled_start_is_closed_only_after_the_port_reports_cleanup() {
        let (_root, state, store, predecessor, staged, attachment, _evidence) = fixture();
        let port = FakePort::default();
        {
            let mut fake = port.state.lock().unwrap();
            fake.inspections
                .push_back(RootProvisionProcessInspection::Absent);
            fake.starts
                .push_back(RootProvisionProcessStart::CancelledClean);
        }
        let result = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            attachment,
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .unwrap();
        assert_eq!(result.outcome, RootProvisionProcessOutcome::CancelledClean);
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (1, 1));
    }

    fn checkpoint(step: ReconcileStep) -> RuntimeCheckpoint {
        RuntimeCheckpoint {
            version: ContractVersion::V1,
            cat_id: id("cat_01"),
            node_id: id("node_a"),
            placement_epoch: epoch(3),
            desired_revision: Revision::new(5).unwrap(),
            spec_digest: digest('f'),
            runtime_incarnation: None,
            stable_state: None,
            step,
            processes: Vec::new(),
            volumes: Vec::new(),
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            route_gates: Vec::new(),
            require_idle: RequireIdleCheckpoint::NotApplicable,
            updated_at_unix_ms: UnixMillis::new(1_900_000_000_000).unwrap(),
        }
    }

    fn attachment() -> AuthorizedServingAttachment {
        use cats_api::runtime_reconciliation::{
            AcquireOrigin, NormalAcquireRequest, NormalAcquireResult,
        };
        let request = NormalAcquireRequest {
            volume_id: id("vol_root"),
            transition_id: random('6'),
            attachment_id: id("att_root"),
            expected_unowned_epoch: fence(6),
            desired_revision: Revision::new(5).unwrap(),
            placement_epoch: epoch(3),
            lease_duration_ms: 5_000,
        };
        AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: id("vol_root"),
                attachment_id: id("att_root"),
                attachment_epoch: fence(7),
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: request.transition_id.clone(),
                },
                node_id: id("node_a"),
                placement_epoch: epoch(3),
            },
            size_bytes: 4_194_304,
            durability: Durability::Strict,
            head: blank_head(),
            lease_expires_at: UnixMillis::new(1_900_000_060_000).unwrap(),
            acquire_result: NormalAcquireResult {
                volume_id: request.volume_id.clone(),
                transition_id: request.transition_id.clone(),
                attachment_id: request.attachment_id.clone(),
                resulting_epoch: fence(7),
                resulting_head: blank_head(),
                lease_expires_at: UnixMillis::new(1_900_000_060_000).unwrap(),
            },
            acquire_request: request,
        }
    }

    fn evidence(attachment: &AuthorizedServingAttachment) -> RootProvisionProcessEvidence {
        RootProvisionProcessEvidence {
            process_id: 4242,
            process_start_time_ticks: WireU64::new(700).unwrap(),
            executable_path: host("/usr/bin/cats-blockd"),
            scope_id: id("cats-root.scope"),
            cgroup_path: host("/sys/fs/cgroup/system.slice/cats-root.scope"),
            control_socket_path: host("/run/cats/cat_01/root-provision.sock"),
            data_directory: host("/var/lib/cats/cat_01/root"),
            ownership_token: random('4'),
            handshake: RootProvisionBlockdHandshake {
                identity: attachment.identity.clone(),
                size_bytes: attachment.size_bytes,
                durability: attachment.durability,
                process_identity_token: random('4'),
                control_only: true,
                guest_io_enabled: false,
            },
        }
    }

    fn context(state: StateDirectory) -> RuntimeDesiredEffectContext {
        RuntimeDesiredEffectContext::for_test(state, Instant::now() + Duration::from_secs(5))
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).unwrap()
    }

    fn fence(value: u64) -> FenceEpoch {
        FenceEpoch::new(value).unwrap()
    }

    fn host(value: &str) -> HostPath {
        HostPath::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    fn digest(value: char) -> Sha256Digest {
        Sha256Digest::new(format!(
            "sha256:{}",
            std::iter::repeat_n(value, 64).collect::<String>()
        ))
        .unwrap()
    }

    fn blank_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }
}
