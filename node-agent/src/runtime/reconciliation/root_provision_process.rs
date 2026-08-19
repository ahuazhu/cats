//! Checkpoint-first process ownership for the root-provision blockd.
//!
//! This is the narrow provider-neutral boundary between Runtime
//! Reconciliation v1 and a future systemd transient-unit adapter. The adapter
//! may create or adopt a process only through the exact physical identity
//! already fsynced in `ReconcileStep::ProvisionRootImage`. An ambiguous start
//! is resolved by inspection; it is never retried in the same reconciliation
//! unit and a mismatching process is never stopped by name.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    CheckpointEvidence, ControlHandshakeEvidence, DesiredRuntimeSpec, Durability, Epoch,
    FenceEpoch, HostPath, Id, NodeBootId, NodeObservation, ObservedDevice, OwnershipTokenEvidence,
    ProcessEvidence, ProcessRole, ProcessState, RandomId128, ReconcileStep, RemoteHead, Revision,
    RuntimeCheckpoint, Sequence, Sha256Digest, WireU64,
};
use cats_blockd::target_control::{
    provision_root_authorization_context_digest, target_control_authorization_file_name,
    ProvisionRootAuthorizationContextDigest,
};
use cats_storage::authority::{
    remote_head_is_same_or_later, validate_authorized_serving_attachment, validate_volume_record,
    AttachmentLineageIdentity, AuthorizedServingAttachment, VolumeAdminState, VolumeRecord,
};

use crate::runtime_spine::{RuntimeDesiredEffectContext, RuntimePhysicalReadContext};

use super::blockd_socket_namespace::{
    ExactManagedBlockdSocketOwnerStartAbsence, ManagedBlockdRootStopOwnerEvidence,
    ManagedBlockdSocketOwnerRetirement,
};
use super::checkpoint::CurrentCheckpointGuard;
use super::serving_handoff::{
    target_control_process_launch_identity, TargetControlAuthorizationReady,
};
use super::{FileCheckpointStore, StoredCheckpoint};

pub(crate) mod sealed {
    pub(crate) trait Sealed {}
}

/// A retirement read is stronger than an exact lookup of the expected unit.
/// Implementations must bracket the same sealed Node-global
/// systemd/process/socket sweep used by the full inventory scanner. Keeping a
/// separate sealed port prevents a caller from accidentally substituting a
/// naked `systemctl show <expected-unit>` lookup for global absence.
pub(crate) mod retirement_sealed {
    pub(crate) trait Sealed {}
}

/// Sealed read boundary for an effect-time exact-or-absent decision. Unlike a
/// lookup of the expected unit, implementations must bracket the same
/// Node-global unit/cgroup, `/proc`, and managed-socket sweep as the full
/// inventory scanner.
pub(crate) mod global_sealed {
    pub(crate) trait Sealed {}
}

pub(crate) mod target_start_sealed {
    pub(crate) trait Sealed {}
}

pub(crate) trait RootProvisionProcessGlobalPort:
    global_sealed::Sealed + RootProvisionProcessRetirementPort + Send + Sync
{
    fn inspect_exact_or_absent_after_node_global_sweep(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection>;
}

pub(crate) trait TargetControlProcessPort:
    target_start_sealed::Sealed + Send + Sync
{
    fn start_target_checkpointed(
        &self,
        checkpointed: CheckpointedTargetControlProcess<'_>,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessStart>;
}

pub(crate) trait RootProvisionProcessRetirementPort:
    retirement_sealed::Sealed + Send + Sync
{
    fn inspect_exact_stop_owner_after_node_global_sweep(
        &self,
        _expected: &RootProvisionProcessExpectation,
        _context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionManagedStopInspection> {
        Ok(RootProvisionManagedStopInspection::Unavailable)
    }

    fn retire_absent_socket_owner(
        &self,
        _expected: &RootProvisionProcessExpectation,
        _context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<ManagedBlockdSocketOwnerRetirement> {
        anyhow::bail!("Root socket-owner retirement requires the production Node-global scanner")
    }

    fn retain_start_socket_absence(
        &self,
        _expected: &RootProvisionProcessExpectation,
        _context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<Option<ExactManagedBlockdSocketOwnerStartAbsence>> {
        anyhow::bail!("Root start socket absence requires the production Node-global scanner")
    }

    /// Re-prove one exact live attempt across the same Node-global sweep used
    /// by full inventory. The default is fail-closed for test/provider ports
    /// which only implement the later absence proof.
    fn inspect_exact_after_node_global_sweep(
        &self,
        _expected: &RootProvisionProcessExpectation,
        _context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        Ok(RootProvisionProcessInspection::Unavailable)
    }

    /// Prove the exact process absent while permitting only the receipted
    /// socket basename to remain in the Node-global socket sweep. This is the
    /// restart path between an exact stop and descriptor-relative unlink of
    /// that stale inode; implementations must not treat the allowed pathname
    /// itself as process evidence.
    fn inspect_absent_with_admitted_stop_receipt(
        &self,
        _expected: &RootProvisionProcessExpectation,
        _context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        Ok(RootProvisionProcessInspection::Unavailable)
    }

    fn inspect_after_node_global_sweep(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootProvisionManagedStopInspection {
    Exact {
        process: Box<RootProvisionProcessEvidence>,
        owner: Box<ManagedBlockdRootStopOwnerEvidence>,
    },
    Absent,
    Conflict(RootProvisionProcessConflict),
    Unavailable,
}

/// The only two authority states in which the persisted root-provision
/// process may be adopted. The selected head is copied from the checkpoint,
/// never from an unbound process response or from the original acquire grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RootProvisionProcessPhase {
    AwaitingProvision {
        expected_blank_head: RemoteHead,
    },
    Provisioned {
        expected_provisioned_head: RemoteHead,
    },
}

impl RootProvisionProcessPhase {
    fn expected_remote_head(&self) -> &RemoteHead {
        match self {
            Self::AwaitingProvision {
                expected_blank_head,
            } => expected_blank_head,
            Self::Provisioned {
                expected_provisioned_head,
            } => expected_provisioned_head,
        }
    }

    fn may_start_from_blank_authorized_artifact(&self) -> bool {
        matches!(self, Self::AwaitingProvision { .. })
    }
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
    pub socket_owner_authority_digest: Sha256Digest,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub scope_id: Id,
    pub cgroup_path: HostPath,
    pub control_socket_path: HostPath,
    pub data_directory: HostPath,
    pub process_identity_token: RandomId128,
    pub size_bytes: u64,
    pub boot_image_digest: Sha256Digest,
    pub attachment: AuthorizedServingAttachment,
    pub(super) phase: RootProvisionProcessPhase,
    pub executable_path: HostPath,
    /// Provider-private launch identity decoded from the scanner-validated
    /// immutable target-control artifact. Inspection may accept the original
    /// blank-grant process or this strict replacement; creation may use only
    /// this target form.
    pub(super) target_control_launch: Option<TargetControlProcessLaunchIdentity>,
    /// A sealed handoff fixes the old control process to one physical
    /// incarnation. A live process retained across the PrepareDevice CAS may
    /// not be rebound to a later process which happens to reuse its logical
    /// unit, token and socket identity.
    pub(crate) retained_physical_identity: Option<RetainedRootProvisionPhysicalIdentity>,
}

/// Exact wrapper arguments which distinguish a target-head recovery process
/// from the original blank-head control process. The physical file identity
/// remains retained by `TargetControlAuthorizationReady`; this value alone is
/// intentionally insufficient to authorize a start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetControlProcessLaunchIdentity {
    authorization_path: HostPath,
    provision_transition_id: RandomId128,
    provision_context_digest: ProvisionRootAuthorizationContextDigest,
}

impl TargetControlProcessLaunchIdentity {
    pub(crate) fn new(
        authorization_path: HostPath,
        provision_transition_id: RandomId128,
        provision_context_digest: ProvisionRootAuthorizationContextDigest,
    ) -> Self {
        Self {
            authorization_path,
            provision_transition_id,
            provision_context_digest,
        }
    }

    pub(crate) fn authorization_path(&self) -> &HostPath {
        &self.authorization_path
    }

    pub(crate) fn provision_transition_id(&self) -> &RandomId128 {
        &self.provision_transition_id
    }

    pub(crate) fn provision_context_digest(&self) -> &Sha256Digest {
        self.provision_context_digest.as_sha256_digest()
    }
}

/// Exact OS/process identity captured in the immutable serving-handoff
/// record. PIDs are converted into the platform process-ID domain before the
/// value enters inventory, so an out-of-range wire value cannot be truncated
/// into an allowlisted process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetainedRootProvisionPhysicalIdentity {
    pub process_id: u32,
    pub unit_main_process_id: u32,
    pub process_start_time_ticks: WireU64,
    pub cgroup_process_ids: Vec<u32>,
    pub handshake_peer_process_id: u32,
}

/// Provider-private projection of the old control-only attempt retained by a
/// sealed Root handoff after the Runtime checkpoint has advanced to
/// `PrepareDevice`. Every field originates in the already validated immutable
/// handoff record/target pair; the inventory join supplies the current Desired
/// only for the boot-image binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetainedRootProvisionProcessAttempt {
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
    pub cgroup_path: HostPath,
    pub control_socket_path: HostPath,
    pub data_directory: HostPath,
    pub process_identity_token: RandomId128,
    pub expected_provisioned_head: RemoteHead,
    pub attachment: AuthorizedServingAttachment,
    pub executable_path: HostPath,
    pub target_control_launch: TargetControlProcessLaunchIdentity,
    pub physical_identity: RetainedRootProvisionPhysicalIdentity,
}

/// One strict authority reread paired with the immutable acquire-time
/// artifact. Keeping the pair in one argument prevents process creation from
/// being planned from either half in isolation.
pub(crate) struct RootProvisionAuthoritySnapshot<'a> {
    pub attachment: AuthorizedServingAttachment,
    pub volume: &'a VolumeRecord,
}

impl RootProvisionProcessExpectation {
    pub(crate) fn from_checkpoint(
        checkpoint: &RuntimeCheckpoint,
        authority: RootProvisionAuthoritySnapshot<'_>,
        executable_path: HostPath,
    ) -> anyhow::Result<Self> {
        let RootProvisionAuthoritySnapshot {
            attachment,
            volume: authority,
        } = authority;
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
            expected_provisioned_head,
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
        let phase = phase_from_exact_authority(
            &attachment,
            authority,
            expected_blank_head,
            expected_provisioned_head,
        )?;
        anyhow::ensure!(
            executable_path.as_str().starts_with('/'),
            "root-provision executable path must be absolute"
        );
        anyhow::ensure!(
            scope_id.as_str().ends_with(".service")
                && scope_id
                    .as_str()
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "root-provision process owner requires one canonical transient service unit"
        );
        let cgroup_path =
            HostPath::new(format!("/sys/fs/cgroup/system.slice/{}", scope_id.as_str()))
                .context("root-provision service does not form a canonical cgroup path")?;
        let managed_sockets =
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                .root_paths(provision_transition_id)
                .context("derive checkpointed root-provision socket namespace")?;
        anyhow::ensure!(
            control_socket_path == managed_sockets.control_socket(),
            "root-provision checkpoint carries a non-managed control socket"
        );
        let socket_owner_authority_digest = provision_root_authorization_context_digest(checkpoint)
            .context("derive Root socket owner authority")?
            .as_sha256_digest()
            .clone();
        Ok(Self {
            cat_id: checkpoint.cat_id.clone(),
            node_id: checkpoint.node_id.clone(),
            placement_epoch: checkpoint.placement_epoch,
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            provision_transition_id: provision_transition_id.clone(),
            socket_owner_authority_digest,
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: *attachment_epoch,
            scope_id: scope_id.clone(),
            cgroup_path,
            control_socket_path: control_socket_path.clone(),
            data_directory: data_directory.clone(),
            process_identity_token: process_identity_token.clone(),
            size_bytes: *size_bytes,
            boot_image_digest: boot_image_digest.clone(),
            attachment,
            phase,
            executable_path,
            target_control_launch: None,
            retained_physical_identity: None,
        })
    }

    pub(crate) fn from_retained_prepare_device(
        checkpoint: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        attempt: &RetainedRootProvisionProcessAttempt,
    ) -> anyhow::Result<Self> {
        let ReconcileStep::PrepareDevice { devices } = &checkpoint.step else {
            anyhow::bail!("retained Root handoff requires prepare_device")
        };
        let mut roots =
            devices.iter().filter(|device| {
                matches!(
            device.serving_authority.as_ref(),
            cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
        )
            });
        let device = roots
            .next()
            .context("retained Root handoff lacks its prepared device")?;
        anyhow::ensure!(
            roots.next().is_none(),
            "retained Root handoff duplicates its prepared device"
        );
        anyhow::ensure!(
            desired.cat_id == checkpoint.cat_id
                && desired.placement.node_id == checkpoint.node_id
                && desired.placement.placement_epoch == checkpoint.placement_epoch
                && desired.desired_revision == checkpoint.desired_revision
                && desired.spec_digest == checkpoint.spec_digest
                && attempt.cat_id == checkpoint.cat_id
                && attempt.node_id == checkpoint.node_id
                && attempt.placement_epoch == checkpoint.placement_epoch
                && attempt.desired_revision == checkpoint.desired_revision
                && attempt.spec_digest == checkpoint.spec_digest
                && attempt.volume_id == device.volume_id
                && attempt.attachment_id == device.attachment_id
                && attempt.attachment_epoch == device.attachment_epoch
                && attempt.attachment.identity.volume_id == device.volume_id
                && attempt.attachment.identity.attachment_id == device.attachment_id
                && attempt.attachment.identity.attachment_epoch == device.attachment_epoch
                && attempt.attachment.identity.acquire_origin == device.acquire_origin
                && attempt.expected_provisioned_head == attempt.attachment.head
                && remote_head_is_same_or_later(
                    &device.expected_head,
                    &attempt.expected_provisioned_head,
                )
                && attempt.attachment.size_bytes == device.size_bytes
                && attempt.attachment.durability == device.durability,
            "retained Root process attempt conflicts with current PrepareDevice authority"
        );
        anyhow::ensure!(
            attempt.executable_path.as_str().starts_with('/')
                && attempt.scope_id.as_str().ends_with(".service")
                && attempt
                    .scope_id
                    .as_str()
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
                && attempt.cgroup_path.as_str()
                    == format!("/sys/fs/cgroup/system.slice/{}", attempt.scope_id.as_str()),
            "retained Root process attempt has a noncanonical physical owner"
        );
        let managed_sockets =
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                .root_paths(&attempt.provision_transition_id)
                .context("derive retained root-provision socket namespace")?;
        anyhow::ensure!(
            attempt.control_socket_path == *managed_sockets.control_socket(),
            "retained Root process attempt changed its managed control socket"
        );
        let mut expectation = Self {
            cat_id: attempt.cat_id.clone(),
            node_id: attempt.node_id.clone(),
            placement_epoch: attempt.placement_epoch,
            desired_revision: attempt.desired_revision,
            spec_digest: attempt.spec_digest.clone(),
            provision_transition_id: attempt.provision_transition_id.clone(),
            socket_owner_authority_digest: attempt
                .target_control_launch
                .provision_context_digest()
                .clone(),
            volume_id: attempt.volume_id.clone(),
            attachment_id: attempt.attachment_id.clone(),
            attachment_epoch: attempt.attachment_epoch,
            scope_id: attempt.scope_id.clone(),
            cgroup_path: attempt.cgroup_path.clone(),
            control_socket_path: attempt.control_socket_path.clone(),
            data_directory: attempt.data_directory.clone(),
            process_identity_token: attempt.process_identity_token.clone(),
            size_bytes: attempt.attachment.size_bytes,
            boot_image_digest: desired.runtime.boot_image_digest.clone(),
            attachment: attempt.attachment.clone(),
            phase: RootProvisionProcessPhase::Provisioned {
                expected_provisioned_head: attempt.expected_provisioned_head.clone(),
            },
            executable_path: attempt.executable_path.clone(),
            target_control_launch: None,
            retained_physical_identity: Some(attempt.physical_identity.clone()),
        };
        expectation =
            expectation.with_target_control_launch(attempt.target_control_launch.clone())?;
        Ok(expectation)
    }

    pub(crate) fn expected_remote_head(&self) -> &RemoteHead {
        self.phase.expected_remote_head()
    }

    pub(crate) fn with_target_control_launch(
        mut self,
        launch: TargetControlProcessLaunchIdentity,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            matches!(self.phase, RootProvisionProcessPhase::Provisioned { .. })
                && launch.provision_transition_id == self.provision_transition_id
                && Path::new(launch.authorization_path.as_str()).is_absolute()
                && Path::new(launch.authorization_path.as_str()).parent()
                    == Some(Path::new(self.data_directory.as_str()))
                && Path::new(launch.authorization_path.as_str())
                    .file_name()
                    .and_then(|name| name.to_str())
                    == Some(
                        target_control_authorization_file_name(&self.provision_transition_id)
                            .as_str(),
                    ),
            "target-control process launch is not bound to the provisioned checkpoint"
        );
        self.target_control_launch = Some(launch);
        Ok(self)
    }

    pub(crate) fn target_control_launch(&self) -> Option<&TargetControlProcessLaunchIdentity> {
        self.target_control_launch.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn with_provisioned_head_for_test(
        mut self,
        expected_provisioned_head: RemoteHead,
    ) -> Self {
        self.phase = RootProvisionProcessPhase::Provisioned {
            expected_provisioned_head,
        };
        self
    }
}

fn phase_from_exact_authority(
    attachment: &AuthorizedServingAttachment,
    authority: &VolumeRecord,
    expected_blank_head: &RemoteHead,
    expected_provisioned_head: &RemoteHead,
) -> anyhow::Result<RootProvisionProcessPhase> {
    validate_authorized_serving_attachment(attachment)
        .context("root-provision authorized grant is not closed")?;
    validate_volume_record(authority).context("root-provision authority record is not closed")?;
    anyhow::ensure!(
        attachment.normal_acquire().is_some(),
        "root provisioning cannot consume a takeover attachment"
    );
    let exact_acquire_marker =
        authority.last_transition == Some(attachment.expected_last_transition());
    anyhow::ensure!(
        authority.volume_id == attachment.identity.volume_id
            && authority.size_bytes == attachment.size_bytes
            && authority.durability == attachment.durability
            && matches!(authority.admin_state, VolumeAdminState::Active)
            && authority.lease_owner.as_ref() == Some(&attachment.identity.attachment_id)
            && authority.lease_epoch == attachment.identity.attachment_epoch
            && authority.lease_expires_at.is_some()
            && exact_acquire_marker,
        "root-provision authority does not bind the checkpointed attachment"
    );
    if &authority.head == expected_blank_head {
        Ok(RootProvisionProcessPhase::AwaitingProvision {
            expected_blank_head: expected_blank_head.clone(),
        })
    } else if &authority.head == expected_provisioned_head {
        Ok(RootProvisionProcessPhase::Provisioned {
            expected_provisioned_head: expected_provisioned_head.clone(),
        })
    } else {
        anyhow::bail!("root-provision authority head is neither exact blank nor exact target")
    }
}

/// Exact self-description required from the blockd control handshake.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootProvisionBlockdHandshake {
    /// Linux `SO_PEERCRED` PID from the exact connected control socket.
    pub peer_process_id: u32,
    pub identity: AttachmentLineageIdentity,
    pub size_bytes: u64,
    pub durability: Durability,
    pub remote_head: RemoteHead,
    pub process_identity_token: RandomId128,
    pub control_only: bool,
    pub guest_io_enabled: bool,
}

/// One process identity proven jointly by the process owner and blockd.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootProvisionProcessEvidence {
    pub process_id: u32,
    pub unit_main_process_id: u32,
    pub process_start_time_ticks: WireU64,
    pub executable_path: HostPath,
    pub scope_id: Id,
    pub cgroup_path: HostPath,
    /// Exact bounded `cgroup.procs` membership for the transient service.
    pub cgroup_process_ids: Vec<u32>,
    pub control_socket_path: HostPath,
    pub data_directory: HostPath,
    pub ownership_token: RandomId128,
    pub handshake: RootProvisionBlockdHandshake,
}

impl RootProvisionProcessEvidence {
    pub(crate) fn exactly_matches(&self, expected: &RootProvisionProcessExpectation) -> bool {
        let retained_identity_matches = expected
            .retained_physical_identity
            .as_ref()
            .map(|identity| {
                self.process_id == identity.process_id
                    && self.unit_main_process_id == identity.unit_main_process_id
                    && self.process_start_time_ticks == identity.process_start_time_ticks
                    && self.cgroup_process_ids == identity.cgroup_process_ids
                    && self.handshake.peer_process_id == identity.handshake_peer_process_id
            })
            .unwrap_or(true);
        self.process_id > 0
            && self.unit_main_process_id == self.process_id
            && self.process_start_time_ticks.get() > 0
            && self.cgroup_process_ids == [self.process_id]
            && self.handshake.peer_process_id == self.process_id
            && self.executable_path == expected.executable_path
            && self.scope_id == expected.scope_id
            && self.cgroup_path == expected.cgroup_path
            && self.control_socket_path == expected.control_socket_path
            && self.data_directory == expected.data_directory
            && self.ownership_token == expected.process_identity_token
            && self.handshake.identity == expected.attachment.identity
            && self.handshake.size_bytes == expected.size_bytes
            && self.handshake.durability == expected.attachment.durability
            && &self.handshake.remote_head == expected.expected_remote_head()
            && self.handshake.process_identity_token == expected.process_identity_token
            && self.handshake.control_only
            && !self.handshake.guest_io_enabled
            && retained_identity_matches
    }
}

/// Unforgeable proof that one complete process observation exactly matched
/// the expectation derived from the authoritative provision checkpoint.
///
/// The fields stay private so downstream handoff code cannot manufacture a
/// "matched" process from a naked status response. Construction always runs
/// the same full matcher used by process adoption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactRootProvisionProcessProof {
    expectation: RootProvisionProcessExpectation,
    evidence: RootProvisionProcessEvidence,
}

/// One provider-private member of the Node-global managed-process closed set.
///
/// Variants are explicit so future serving blockd and VMM scanners can add
/// their own complete expectations without accepting an arbitrary
/// unit/PID/socket allowlist from an effect.  The first cutover stage contains
/// only the already implemented Root control process expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NodeGlobalManagedProcessExpectation {
    RootControl {
        expectation: Box<RootProvisionProcessExpectation>,
        exact: Option<Box<ExactRootProvisionProcessProof>>,
    },
    ServingBlockd {
        expectation: Box<super::serving_blockd_process::ServingBlockdExpectation>,
        exact: Option<Box<super::serving_blockd_process::ExactServingBlockdProcessProof>>,
    },
    Vmm {
        expectation: Box<super::vmm_process::VmmProcessExpectation>,
        exact: Option<Box<super::vmm_process::ExactVmmProcessProof>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ManagedServingKey {
    cat_id: Id,
    volume_id: Id,
}

impl ManagedServingKey {
    pub(crate) fn new(cat_id: Id, volume_id: Id) -> Self {
        Self { cat_id, volume_id }
    }

    pub(crate) fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub(crate) fn volume_id(&self) -> &Id {
        &self.volume_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NodeGlobalManagedProcessKey {
    RootControl(Id),
    ServingBlockd(ManagedServingKey),
    Vmm(Id),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StopReceiptSocketAdmission {
    receipt_socket: HostPath,
    socket_owner: Option<ManagedBlockdRootStopOwnerEvidence>,
    physical_paths: BTreeSet<HostPath>,
}

impl StopReceiptSocketAdmission {
    pub(crate) fn from_managed(socket_owner: ManagedBlockdRootStopOwnerEvidence) -> Self {
        Self {
            receipt_socket: socket_owner.control_socket_path().clone(),
            socket_owner: Some(socket_owner),
            physical_paths: BTreeSet::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        receipt_socket: HostPath,
        physical_paths: BTreeSet<HostPath>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            physical_paths.len() <= 1,
            "stop receipt retains more than one physical socket path"
        );
        anyhow::ensure!(
            physical_paths.iter().all(|path| path == &receipt_socket),
            "managed stop receipt physical listener changed from its public binding"
        );
        Ok(Self {
            receipt_socket,
            socket_owner: None,
            physical_paths,
        })
    }

    pub(crate) fn bind_managed_snapshot(
        &mut self,
        snapshot: &super::blockd_socket_namespace::ManagedBlockdSocketWholeRootSnapshot,
    ) -> anyhow::Result<()> {
        let owner = self
            .socket_owner
            .as_ref()
            .context("stop receipt admission lacks managed owner evidence")?;
        anyhow::ensure!(
            owner.control_socket_path() == &self.receipt_socket,
            "managed stop receipt path changed from its owner evidence"
        );
        self.physical_paths = snapshot.bind_root_stop_owner(owner)?;
        Ok(())
    }

    pub(crate) fn receipt_socket(&self) -> &HostPath {
        &self.receipt_socket
    }

    pub(crate) fn physical_paths(&self) -> &BTreeSet<HostPath> {
        &self.physical_paths
    }
}

impl NodeGlobalManagedProcessExpectation {
    fn cat_id(&self) -> &Id {
        match self {
            Self::RootControl { expectation, .. } => &expectation.cat_id,
            Self::ServingBlockd { expectation, .. } => expectation.cat_id(),
            Self::Vmm { expectation, .. } => expectation.cat_id(),
        }
    }

    fn is_exact(&self) -> bool {
        match self {
            Self::RootControl { exact, .. } => exact.is_some(),
            Self::ServingBlockd { exact, .. } => exact.is_some(),
            Self::Vmm { exact, .. } => exact.is_some(),
        }
    }

    pub(crate) fn key(&self) -> NodeGlobalManagedProcessKey {
        match self {
            Self::RootControl { expectation, .. } => {
                NodeGlobalManagedProcessKey::RootControl(expectation.cat_id.clone())
            }
            Self::ServingBlockd { expectation, .. } => {
                NodeGlobalManagedProcessKey::ServingBlockd(ManagedServingKey::new(
                    expectation.cat_id().clone(),
                    expectation.volume_id().clone(),
                ))
            }
            Self::Vmm { expectation, .. } => {
                NodeGlobalManagedProcessKey::Vmm(expectation.cat_id().clone())
            }
        }
    }
}

/// Unbound output of one complete scanner pass.  It contains the full
/// provider-private expectation even for an absent process; public inventory
/// projection alone deliberately cannot recreate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeGlobalManagedProcessScanAdmission {
    entries: Vec<NodeGlobalManagedProcessExpectation>,
    stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
    absent_serving_owners: BTreeSet<ManagedServingKey>,
    additional_managed_units: BTreeSet<Id>,
}

/// The same closed set after it is bound to the exact full observation sent
/// and accepted by Control.  This remains process-local and is never decoded
/// from an observation replay after Agent restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeGlobalManagedProcessAdmission {
    observation_id: RandomId128,
    node_id: Id,
    node_boot_id: NodeBootId,
    agent_instance_id: RandomId128,
    agent_session_epoch: Epoch,
    inventory_epoch: Epoch,
    inventory_digest: Sha256Digest,
    inventory_read_position: Sequence,
    entries: Vec<NodeGlobalManagedProcessExpectation>,
    stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
    absent_serving_owners: BTreeSet<ManagedServingKey>,
    additional_managed_units: BTreeSet<Id>,
}

impl NodeGlobalManagedProcessScanAdmission {
    /// Exact VMM facts from this shared process sweep which invalidate an old
    /// Running/Open admission even if a later independent source makes the
    /// overall inventory incomplete. `None` is exact absence because an
    /// unavailable process inspection cannot construct this admission.
    pub(crate) fn exact_running_negative_cats(&self) -> BTreeSet<Id> {
        self.entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::Vmm { expectation, exact }
                    if exact.as_ref().is_none_or(|proof| {
                        proof.evidence().state()
                            != cats_api::runtime_reconciliation::ProcessState::Running
                    }) =>
                {
                    Some(expectation.cat_id().clone())
                }
                _ => None,
            })
            .collect()
    }

    pub(crate) fn exact_process_count(&self, cat_id: &Id) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.cat_id() == cat_id && entry.is_exact())
            .count()
    }

    pub(crate) fn has_exact_root_control(&self, cat_id: &Id) -> bool {
        self.entries.iter().any(|entry| {
            matches!(
                entry,
                NodeGlobalManagedProcessExpectation::RootControl {
                    expectation,
                    exact: Some(_),
                } if &expectation.cat_id == cat_id
            )
        })
    }

    pub(crate) fn process_projections(&self) -> BTreeMap<Id, Vec<ProcessEvidence>> {
        let mut projections = BTreeMap::<Id, Vec<ProcessEvidence>>::new();
        for entry in &self.entries {
            match entry {
                NodeGlobalManagedProcessExpectation::RootControl { expectation, exact } => {
                    projections
                        .entry(expectation.cat_id.clone())
                        .or_default()
                        .extend(exact.clone().map(|proof| proof.into_process_evidence()))
                }
                NodeGlobalManagedProcessExpectation::ServingBlockd { expectation, exact } => {
                    projections
                        .entry(expectation.cat_id().clone())
                        .or_default()
                        .extend(exact.clone().map(|proof| proof.into_process_evidence()))
                }
                NodeGlobalManagedProcessExpectation::Vmm { expectation, exact } => projections
                    .entry(expectation.cat_id().clone())
                    .or_default()
                    .extend(exact.clone().map(|proof| proof.into_process_evidence())),
            }
        }
        for processes in projections.values_mut() {
            processes.sort_by(compare_process_evidence);
        }
        projections.retain(|_, processes| !processes.is_empty());
        projections
    }

    pub(crate) fn vhost_device_projections(&self) -> BTreeMap<Id, BTreeMap<Id, ObservedDevice>> {
        let mut projections = BTreeMap::<Id, BTreeMap<Id, ObservedDevice>>::new();
        for entry in &self.entries {
            let projection = match entry {
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    expectation,
                    exact: Some(proof),
                } => proof
                    .vhost_device_projection()
                    .map(|device| (expectation.cat_id().clone(), device)),
                _ => None,
            };
            if let Some((cat_id, (volume_id, device))) = projection {
                let previous = projections
                    .entry(cat_id)
                    .or_default()
                    .insert(volume_id, device);
                debug_assert!(previous.is_none(), "typed serving keys are unique");
            }
        }
        projections
    }

    /// Dynamic durability facts from the exact serving control handshake.
    /// This remains scanner-private until `inventory` joins it to the same
    /// retained Volume and process proof; public process fields cannot mint
    /// these watermarks.
    pub(crate) fn serving_status_projections(
        &self,
    ) -> BTreeMap<Id, BTreeMap<Id, cats_api::blockd::DurabilityStatus>> {
        let mut projections =
            BTreeMap::<Id, BTreeMap<Id, cats_api::blockd::DurabilityStatus>>::new();
        for entry in &self.entries {
            let NodeGlobalManagedProcessExpectation::ServingBlockd {
                expectation,
                exact: Some(proof),
            } = entry
            else {
                continue;
            };
            let previous = projections
                .entry(expectation.cat_id().clone())
                .or_default()
                .insert(
                    expectation.volume_id().clone(),
                    proof.durability_status().clone(),
                );
            debug_assert!(previous.is_none(), "typed serving keys are unique");
        }
        projections
    }

    /// Provider-private serving proof retained by the same complete scanner
    /// pass. Frontend scanners may join this proof with independent physical
    /// device evidence, but public process/device projections cannot recreate
    /// it.
    pub(crate) fn serving_blockd(
        &self,
        cat_id: &Id,
        volume_id: &Id,
    ) -> Option<(
        &super::serving_blockd_process::ServingBlockdExpectation,
        Option<&super::serving_blockd_process::ExactServingBlockdProcessProof>,
    )> {
        self.entries.iter().find_map(|entry| match entry {
            NodeGlobalManagedProcessExpectation::ServingBlockd { expectation, exact }
                if expectation.cat_id() == cat_id && expectation.volume_id() == volume_id =>
            {
                Some((expectation.as_ref(), exact.as_deref()))
            }
            _ => None,
        })
    }

    pub(crate) fn serving_blockd_count(&self, cat_id: &Id) -> usize {
        self.serving_blockds(cat_id).count()
    }

    pub(crate) fn serving_blockds<'a>(
        &'a self,
        cat_id: &'a Id,
    ) -> impl Iterator<
        Item = (
            &'a super::serving_blockd_process::ServingBlockdExpectation,
            Option<&'a super::serving_blockd_process::ExactServingBlockdProcessProof>,
        ),
    > + 'a {
        self.entries.iter().filter_map(move |entry| match entry {
            NodeGlobalManagedProcessExpectation::ServingBlockd { expectation, exact }
                if expectation.cat_id() == cat_id =>
            {
                Some((expectation.as_ref(), exact.as_deref()))
            }
            _ => None,
        })
    }

    pub(crate) fn vmm(
        &self,
        cat_id: &Id,
    ) -> Option<(
        &super::vmm_process::VmmProcessExpectation,
        Option<&super::vmm_process::ExactVmmProcessProof>,
    )> {
        self.entries.iter().find_map(|entry| match entry {
            NodeGlobalManagedProcessExpectation::Vmm { expectation, exact }
                if expectation.cat_id() == cat_id =>
            {
                Some((expectation.as_ref(), exact.as_deref()))
            }
            _ => None,
        })
    }

    pub(crate) fn from_root_controls(
        expected: BTreeMap<Id, RootProvisionProcessExpectation>,
        mut exact: BTreeMap<Id, ExactRootProvisionProcessProof>,
    ) -> anyhow::Result<Self> {
        let mut entries = Vec::with_capacity(expected.len());
        let mut units = BTreeSet::new();
        let mut pids = BTreeSet::new();
        let mut sockets = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for (cat_id, expectation) in expected {
            anyhow::ensure!(
                expectation.cat_id == cat_id,
                "Node-global Root-control expectation is indexed by another Cat"
            );
            let proof = exact.remove(&cat_id);
            if let Some(proof) = &proof {
                anyhow::ensure!(
                    proof.expectation() == &expectation,
                    "Node-global Root-control proof changed its full expectation"
                );
                let evidence = proof.evidence();
                anyhow::ensure!(
                    units.insert(evidence.scope_id.clone())
                        && pids.insert(evidence.process_id)
                        && sockets.insert(evidence.control_socket_path.clone()),
                    "Node-global Root-control proof duplicates a physical identity"
                );
            }
            let entry = NodeGlobalManagedProcessExpectation::RootControl {
                expectation: Box::new(expectation),
                exact: proof.map(Box::new),
            };
            anyhow::ensure!(
                keys.insert(entry.key()),
                "Node-global managed-process admission duplicates one typed key"
            );
            entries.push(entry);
        }
        anyhow::ensure!(
            exact.is_empty(),
            "Node-global Root-control proof lacks an authoritative expectation"
        );
        Ok(Self {
            entries,
            stop_receipt_sockets: BTreeMap::new(),
            absent_serving_owners: BTreeSet::new(),
            additional_managed_units: BTreeSet::new(),
        })
    }

    pub(crate) fn with_additional_managed_units(
        mut self,
        units: BTreeSet<Id>,
    ) -> anyhow::Result<Self> {
        let managed = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::RootControl {
                    exact: Some(proof), ..
                } => Some(proof.evidence().scope_id.clone()),
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    exact: Some(proof), ..
                } => Some(proof.evidence().unit_id().clone()),
                NodeGlobalManagedProcessExpectation::Vmm {
                    exact: Some(proof), ..
                } => Some(proof.evidence().unit_id().clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            managed.is_disjoint(&units),
            "additional managed systemd unit aliases a runtime process unit"
        );
        self.additional_managed_units = units;
        Ok(self)
    }

    /// Bind scanner-private managed owner/intent residue to an absent Serving
    /// process.  The public Device projection is necessarily empty in this
    /// state and must not be used to reconstruct this cleanup authority.
    pub(crate) fn with_absent_serving_owners(
        mut self,
        owners: BTreeSet<ManagedServingKey>,
    ) -> anyhow::Result<Self> {
        for key in &owners {
            anyhow::ensure!(
                self.entries.iter().any(|entry| matches!(
                    entry,
                    NodeGlobalManagedProcessExpectation::ServingBlockd {
                        expectation,
                        exact: None,
                    } if expectation.cat_id() == key.cat_id()
                        && expectation.volume_id() == key.volume_id()
                        && matches!(
                            expectation.frontend(),
                            cats_api::runtime_reconciliation::PrepareDeviceFrontend::VhostUserBlk { .. }
                        )
                )),
                "absent serving owner lacks its exact vhost expectation"
            );
        }
        self.absent_serving_owners = owners;
        Ok(self)
    }

    pub(crate) fn with_stop_receipt_sockets(
        mut self,
        sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
    ) -> anyhow::Result<Self> {
        let mut physical_paths = BTreeSet::new();
        for (cat_id, socket) in &sockets {
            let expected = self.entries.iter().find_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::RootControl { expectation, exact }
                    if &expectation.cat_id == cat_id =>
                {
                    Some((expectation, exact.is_some()))
                }
                _ => None,
            });
            anyhow::ensure!(
                expected.is_some_and(|(expected, _)| {
                    &expected.control_socket_path == socket.receipt_socket()
                }),
                "stop receipt socket lacks its exact RootControl expectation"
            );
            if expected.is_some_and(|(_, exact)| exact) {
                anyhow::ensure!(
                    socket.physical_paths() == &BTreeSet::from([socket.receipt_socket().clone()]),
                    "live RootControl receipt must retain its exact public socket"
                );
            }
            anyhow::ensure!(
                socket
                    .physical_paths()
                    .iter()
                    .all(|path| physical_paths.insert(path.clone())),
                "stop receipt admissions duplicate one physical socket path"
            );
            for path in socket.physical_paths() {
                for entry in &self.entries {
                    match entry {
                        NodeGlobalManagedProcessExpectation::RootControl {
                            expectation,
                            exact: Some(_),
                        } => {
                            anyhow::ensure!(
                                (&expectation.cat_id == cat_id && path == socket.receipt_socket())
                                    || path != &expectation.control_socket_path,
                                "stop receipt socket aliases another RootControl owner"
                            );
                        }
                        NodeGlobalManagedProcessExpectation::ServingBlockd {
                            expectation,
                            exact: Some(_),
                        } => {
                            anyhow::ensure!(
                                path != expectation.control_socket_path()
                                    && path != expectation.listener_path(),
                                "stop receipt socket aliases a ServingBlockd owner"
                            );
                        }
                        NodeGlobalManagedProcessExpectation::Vmm {
                            expectation,
                            exact: Some(_),
                        } => {
                            anyhow::ensure!(
                                path != expectation.api_socket_path()
                                    && path != expectation.vsock_socket_path(),
                                "stop receipt socket aliases a VMM owner"
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        self.stop_receipt_sockets = sockets;
        Ok(self)
    }

    pub(crate) fn with_serving_blockds(
        mut self,
        expected: BTreeMap<
            ManagedServingKey,
            super::serving_blockd_process::ServingBlockdExpectation,
        >,
        mut exact: BTreeMap<
            ManagedServingKey,
            super::serving_blockd_process::ExactServingBlockdProcessProof,
        >,
    ) -> anyhow::Result<Self> {
        let mut units = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::RootControl {
                    exact: Some(proof), ..
                } => Some(proof.evidence().scope_id.clone()),
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    exact: Some(proof), ..
                } => Some(proof.evidence().unit_id().clone()),
                NodeGlobalManagedProcessExpectation::Vmm {
                    exact: Some(proof), ..
                } => Some(proof.evidence().unit_id().clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let mut pids = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::RootControl {
                    exact: Some(proof), ..
                } => Some(proof.evidence().process_id),
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    exact: Some(proof), ..
                } => Some(proof.evidence().process_id()),
                NodeGlobalManagedProcessExpectation::Vmm {
                    exact: Some(proof), ..
                } => Some(proof.evidence().process_id()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let mut sockets = BTreeSet::new();
        for entry in &self.entries {
            match entry {
                NodeGlobalManagedProcessExpectation::RootControl {
                    exact: Some(proof), ..
                } => {
                    sockets.insert(proof.evidence().control_socket_path.clone());
                }
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    exact: Some(proof), ..
                } => {
                    sockets.insert(proof.evidence().control_socket_path().clone());
                    sockets.insert(proof.evidence().listener_path().clone());
                }
                NodeGlobalManagedProcessExpectation::Vmm {
                    exact: Some(proof), ..
                } => {
                    sockets.insert(proof.evidence().api_socket_path().clone());
                    sockets.insert(proof.evidence().vsock_socket_path().clone());
                }
                _ => {}
            }
        }
        let mut keys = self
            .entries
            .iter()
            .map(NodeGlobalManagedProcessExpectation::key)
            .collect::<BTreeSet<_>>();
        for (key, expectation) in expected {
            anyhow::ensure!(
                expectation.cat_id() == key.cat_id() && expectation.volume_id() == key.volume_id(),
                "Node-global serving expectation is indexed by another Cat or Volume"
            );
            let proof = exact.remove(&key);
            if let Some(proof) = &proof {
                anyhow::ensure!(
                    proof.expectation() == &expectation,
                    "Node-global serving proof changed its full expectation"
                );
                let evidence = proof.evidence();
                anyhow::ensure!(
                    units.insert(evidence.unit_id().clone())
                        && pids.insert(evidence.process_id())
                        && sockets.insert(evidence.control_socket_path().clone())
                        && sockets.insert(evidence.listener_path().clone()),
                    "Node-global serving proof duplicates a physical identity"
                );
            }
            let entry = NodeGlobalManagedProcessExpectation::ServingBlockd {
                expectation: Box::new(expectation),
                exact: proof.map(Box::new),
            };
            anyhow::ensure!(
                keys.insert(entry.key()),
                "Node-global managed-process admission duplicates one typed key"
            );
            self.entries.push(entry);
        }
        anyhow::ensure!(
            exact.is_empty(),
            "Node-global serving proof lacks an authoritative expectation"
        );
        Ok(self)
    }

    pub(crate) fn root_control_proofs(&self) -> BTreeMap<Id, ExactRootProvisionProcessProof> {
        self.entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::RootControl {
                    expectation,
                    exact: Some(proof),
                } => Some((expectation.cat_id.clone(), (**proof).clone())),
                NodeGlobalManagedProcessExpectation::RootControl { exact: None, .. } => None,
                NodeGlobalManagedProcessExpectation::ServingBlockd { .. } => None,
                NodeGlobalManagedProcessExpectation::Vmm { .. } => None,
            })
            .collect()
    }

    pub(crate) fn serving_blockd_proofs(
        &self,
    ) -> BTreeMap<ManagedServingKey, super::serving_blockd_process::ExactServingBlockdProcessProof>
    {
        self.entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    expectation,
                    exact: Some(proof),
                } => Some((
                    ManagedServingKey::new(
                        expectation.cat_id().clone(),
                        expectation.volume_id().clone(),
                    ),
                    (**proof).clone(),
                )),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn with_vmms(
        mut self,
        expected: BTreeMap<Id, super::vmm_process::VmmProcessExpectation>,
        mut exact: BTreeMap<Id, super::vmm_process::ExactVmmProcessProof>,
    ) -> anyhow::Result<Self> {
        let mut units = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::RootControl {
                    exact: Some(proof), ..
                } => Some(proof.evidence().scope_id.clone()),
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    exact: Some(proof), ..
                } => Some(proof.evidence().unit_id().clone()),
                NodeGlobalManagedProcessExpectation::Vmm {
                    exact: Some(proof), ..
                } => Some(proof.evidence().unit_id().clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let mut pids = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::RootControl {
                    exact: Some(proof), ..
                } => Some(proof.evidence().process_id),
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    exact: Some(proof), ..
                } => Some(proof.evidence().process_id()),
                NodeGlobalManagedProcessExpectation::Vmm {
                    exact: Some(proof), ..
                } => Some(proof.evidence().process_id()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let mut sockets = BTreeSet::new();
        for entry in &self.entries {
            match entry {
                NodeGlobalManagedProcessExpectation::RootControl {
                    exact: Some(proof), ..
                } => {
                    sockets.insert(proof.evidence().control_socket_path.clone());
                }
                NodeGlobalManagedProcessExpectation::ServingBlockd {
                    exact: Some(proof), ..
                } => {
                    sockets.insert(proof.evidence().control_socket_path().clone());
                    sockets.insert(proof.evidence().listener_path().clone());
                }
                NodeGlobalManagedProcessExpectation::Vmm {
                    exact: Some(proof), ..
                } => {
                    sockets.insert(proof.evidence().api_socket_path().clone());
                    sockets.insert(proof.evidence().vsock_socket_path().clone());
                }
                _ => {}
            }
        }
        let mut keys = self
            .entries
            .iter()
            .map(NodeGlobalManagedProcessExpectation::key)
            .collect::<BTreeSet<_>>();
        for (cat_id, expectation) in expected {
            anyhow::ensure!(
                expectation.cat_id() == &cat_id,
                "Node-global VMM expectation is indexed by another Cat"
            );
            let proof = exact.remove(&cat_id);
            if let Some(proof) = &proof {
                anyhow::ensure!(
                    proof.expectation() == &expectation,
                    "Node-global VMM proof changed its full expectation"
                );
                let evidence = proof.evidence();
                anyhow::ensure!(
                    units.insert(evidence.unit_id().clone())
                        && pids.insert(evidence.process_id())
                        && sockets.insert(evidence.api_socket_path().clone())
                        && sockets.insert(evidence.vsock_socket_path().clone()),
                    "Node-global VMM proof duplicates a physical identity"
                );
            }
            let entry = NodeGlobalManagedProcessExpectation::Vmm {
                expectation: Box::new(expectation),
                exact: proof.map(Box::new),
            };
            anyhow::ensure!(
                keys.insert(entry.key()),
                "Node-global managed-process admission duplicates one typed key"
            );
            self.entries.push(entry);
        }
        anyhow::ensure!(
            exact.is_empty(),
            "Node-global VMM proof lacks an authoritative expectation"
        );
        Ok(self)
    }

    pub(crate) fn vmm_proofs(&self) -> BTreeMap<Id, super::vmm_process::ExactVmmProcessProof> {
        self.entries
            .iter()
            .filter_map(|entry| match entry {
                NodeGlobalManagedProcessExpectation::Vmm {
                    expectation,
                    exact: Some(proof),
                } => Some((expectation.cat_id().clone(), (**proof).clone())),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn bind(
        self,
        observation: &NodeObservation,
    ) -> anyhow::Result<NodeGlobalManagedProcessAdmission> {
        anyhow::ensure!(
            observation.complete_inventory,
            "Node-global managed-process admission requires a complete observation"
        );
        let inventory_digest = observation
            .inventory_digest
            .clone()
            .context("Node-global managed-process admission lacks inventory digest")?;
        let inventory_read_position = observation
            .inventory_read_position
            .context("Node-global managed-process admission lacks inventory read position")?;
        let mut admitted_processes = BTreeMap::new();
        for entry in &self.entries {
            match entry {
                NodeGlobalManagedProcessExpectation::RootControl { expectation, exact } => {
                    admitted_processes
                        .entry(expectation.cat_id.clone())
                        .or_insert_with(Vec::new)
                        .extend(exact.clone().map(|proof| proof.into_process_evidence()));
                }
                NodeGlobalManagedProcessExpectation::ServingBlockd { expectation, exact } => {
                    admitted_processes
                        .entry(expectation.cat_id().clone())
                        .or_insert_with(Vec::new)
                        .extend(exact.clone().map(|proof| proof.into_process_evidence()));
                }
                NodeGlobalManagedProcessExpectation::Vmm { expectation, exact } => {
                    admitted_processes
                        .entry(expectation.cat_id().clone())
                        .or_insert_with(Vec::new)
                        .extend(exact.clone().map(|proof| proof.into_process_evidence()));
                }
            }
        }
        for processes in admitted_processes.values_mut() {
            processes.sort_by(compare_process_evidence);
        }
        let mut admitted_vhost_devices = BTreeMap::<Id, BTreeMap<Id, ObservedDevice>>::new();
        for entry in &self.entries {
            let NodeGlobalManagedProcessExpectation::ServingBlockd {
                expectation,
                exact: Some(proof),
            } = entry
            else {
                continue;
            };
            let Some((volume_id, device)) = proof.vhost_device_projection() else {
                continue;
            };
            anyhow::ensure!(
                admitted_vhost_devices
                    .entry(expectation.cat_id().clone())
                    .or_default()
                    .insert(volume_id, device)
                    .is_none(),
                "Node-global serving proofs duplicate one vhost Volume projection"
            );
        }
        for runtime in &observation.runtimes {
            let expected = admitted_processes.remove(&runtime.cat_id);
            match expected {
                Some(processes) => anyhow::ensure!(
                    runtime.processes == processes,
                    "Node-global managed-process proof conflicts with public projection"
                ),
                None => anyhow::ensure!(
                    runtime.processes.is_empty(),
                    "public process projection lacks a provider-private global expectation"
                ),
            }
            let expected_devices = admitted_vhost_devices
                .remove(&runtime.cat_id)
                .unwrap_or_default();
            let actual_devices = runtime
                .volumes
                .iter()
                .filter_map(|volume| match volume.devices.as_slice() {
                    [device @ ObservedDevice::VhostUserBlk { .. }] => {
                        Some((volume.volume_id.clone(), device.clone()))
                    }
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>();
            anyhow::ensure!(
                actual_devices == expected_devices,
                "serving vhost proofs conflict with the exact public device projection"
            );
            for volume in &runtime.volumes {
                anyhow::ensure!(
                    volume.devices.len() <= 1,
                    "public Volume projects duplicate managed frontend devices"
                );
            }
        }
        anyhow::ensure!(
            admitted_processes.is_empty(),
            "Node-global managed-process admission names a Cat absent from inventory"
        );
        anyhow::ensure!(
            admitted_vhost_devices.is_empty(),
            "Node-global serving admission names a Cat absent from inventory"
        );
        Ok(NodeGlobalManagedProcessAdmission {
            observation_id: observation.observation_id.clone(),
            node_id: observation.node_id.clone(),
            node_boot_id: observation.node_boot_id.clone(),
            agent_instance_id: observation.agent_instance_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest,
            inventory_read_position,
            entries: self.entries,
            stop_receipt_sockets: self.stop_receipt_sockets,
            absent_serving_owners: self.absent_serving_owners,
            additional_managed_units: self.additional_managed_units,
        })
    }

    #[cfg(test)]
    pub(crate) fn into_admission_for_test(self) -> NodeGlobalManagedProcessAdmission {
        NodeGlobalManagedProcessAdmission {
            observation_id: RandomId128::new("11111111111111111111111111111111").unwrap(),
            node_id: Id::new("node_test").unwrap(),
            node_boot_id: NodeBootId::new("22222222222222222222222222222222").unwrap(),
            agent_instance_id: RandomId128::new("33333333333333333333333333333333").unwrap(),
            agent_session_epoch: Epoch::new(1).unwrap(),
            inventory_epoch: Epoch::new(1).unwrap(),
            inventory_digest: Sha256Digest::from_bytes([4; 32]),
            inventory_read_position: Sequence::new(1).unwrap(),
            entries: self.entries,
            stop_receipt_sockets: self.stop_receipt_sockets,
            absent_serving_owners: self.absent_serving_owners,
            additional_managed_units: self.additional_managed_units,
        }
    }
}

fn compare_process_evidence(left: &ProcessEvidence, right: &ProcessEvidence) -> Ordering {
    match (&left.role, &right.role) {
        (
            ProcessRole::Vmm {
                runtime_incarnation: left_incarnation,
            },
            ProcessRole::Vmm {
                runtime_incarnation: right_incarnation,
            },
        ) => left_incarnation
            .as_str()
            .cmp(right_incarnation.as_str())
            .then_with(|| {
                left.process_start_time_ticks
                    .get()
                    .cmp(&right.process_start_time_ticks.get())
            })
            .then_with(|| left.process_id.cmp(&right.process_id)),
        (ProcessRole::Vmm { .. }, ProcessRole::Blockd { .. }) => Ordering::Less,
        (ProcessRole::Blockd { .. }, ProcessRole::Vmm { .. }) => Ordering::Greater,
        (
            ProcessRole::Blockd {
                volume_id: left_volume,
                attachment_id: left_attachment,
                attachment_epoch: left_epoch,
            },
            ProcessRole::Blockd {
                volume_id: right_volume,
                attachment_id: right_attachment,
                attachment_epoch: right_epoch,
            },
        ) => left_volume
            .as_str()
            .cmp(right_volume.as_str())
            .then_with(|| left_epoch.get().cmp(&right_epoch.get()))
            .then_with(|| left_attachment.as_str().cmp(right_attachment.as_str()))
            .then_with(|| {
                left.process_start_time_ticks
                    .get()
                    .cmp(&right.process_start_time_ticks.get())
            })
            .then_with(|| left.process_id.cmp(&right.process_id)),
    }
}

impl NodeGlobalManagedProcessAdmission {
    pub(crate) fn node_boot_id(&self) -> &NodeBootId {
        &self.node_boot_id
    }

    pub(crate) fn exact_process_count(&self, cat_id: &Id) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.cat_id() == cat_id && entry.is_exact())
            .count()
    }

    #[cfg(test)]
    pub(crate) fn rebind_for_test(&self, observation: &NodeObservation) -> anyhow::Result<Self> {
        NodeGlobalManagedProcessScanAdmission {
            entries: self.entries.clone(),
            stop_receipt_sockets: self.stop_receipt_sockets.clone(),
            absent_serving_owners: self.absent_serving_owners.clone(),
            additional_managed_units: self.additional_managed_units.clone(),
        }
        .bind(observation)
    }

    pub(crate) fn stop_receipt_socket(&self, cat_id: &Id) -> Option<&StopReceiptSocketAdmission> {
        self.stop_receipt_sockets.get(cat_id)
    }

    pub(crate) fn additional_managed_units(&self) -> &BTreeSet<Id> {
        &self.additional_managed_units
    }

    pub(crate) fn stop_receipt_physical_paths(&self) -> BTreeSet<HostPath> {
        self.stop_receipt_sockets
            .values()
            .flat_map(|socket| socket.physical_paths().iter().cloned())
            .collect()
    }

    pub(crate) fn matches_observation(&self, observation: &NodeObservation) -> bool {
        observation.complete_inventory
            && self.observation_id == observation.observation_id
            && self.node_id == observation.node_id
            && self.node_boot_id == observation.node_boot_id
            && self.agent_instance_id == observation.agent_instance_id
            && self.agent_session_epoch == observation.agent_session_epoch
            && self.inventory_epoch == observation.inventory_epoch
            && observation.inventory_digest.as_ref() == Some(&self.inventory_digest)
            && observation.inventory_read_position == Some(self.inventory_read_position)
    }

    pub(crate) fn root_control_state(
        &self,
    ) -> (
        BTreeMap<Id, RootProvisionProcessExpectation>,
        BTreeMap<Id, RootProvisionProcessInspection>,
    ) {
        let mut expected = BTreeMap::new();
        let mut admitted = BTreeMap::new();
        for entry in &self.entries {
            match entry {
                NodeGlobalManagedProcessExpectation::RootControl { expectation, exact } => {
                    expected.insert(expectation.cat_id.clone(), (**expectation).clone());
                    admitted.insert(
                        expectation.cat_id.clone(),
                        exact
                            .as_ref()
                            .map_or(RootProvisionProcessInspection::Absent, |proof| {
                                RootProvisionProcessInspection::Exact(Box::new(
                                    proof.evidence().clone(),
                                ))
                            }),
                    );
                }
                NodeGlobalManagedProcessExpectation::ServingBlockd { .. }
                | NodeGlobalManagedProcessExpectation::Vmm { .. } => {}
            }
        }
        (expected, admitted)
    }

    pub(crate) fn serving_blockd_state(
        &self,
    ) -> (
        BTreeMap<ManagedServingKey, super::serving_blockd_process::ServingBlockdExpectation>,
        BTreeMap<ManagedServingKey, super::serving_blockd_process::ServingBlockdProcessInspection>,
    ) {
        let mut expected = BTreeMap::new();
        let mut admitted = BTreeMap::new();
        for entry in &self.entries {
            if let NodeGlobalManagedProcessExpectation::ServingBlockd { expectation, exact } = entry
            {
                let key = ManagedServingKey::new(
                    expectation.cat_id().clone(),
                    expectation.volume_id().clone(),
                );
                expected.insert(key.clone(), (**expectation).clone());
                admitted.insert(
                    key,
                    exact.as_ref().map_or(
                        super::serving_blockd_process::ServingBlockdProcessInspection::Absent,
                        |proof| {
                            super::serving_blockd_process::ServingBlockdProcessInspection::Exact(
                                Box::new(proof.evidence().clone()),
                            )
                        },
                    ),
                );
            }
        }
        (expected, admitted)
    }

    pub(crate) fn vmm_state(
        &self,
    ) -> (
        BTreeMap<Id, super::vmm_process::VmmProcessExpectation>,
        BTreeMap<Id, super::vmm_process::VmmProcessInspection>,
    ) {
        let mut expected = BTreeMap::new();
        let mut admitted = BTreeMap::new();
        for entry in &self.entries {
            if let NodeGlobalManagedProcessExpectation::Vmm { expectation, exact } = entry {
                expected.insert(expectation.cat_id().clone(), (**expectation).clone());
                admitted.insert(
                    expectation.cat_id().clone(),
                    exact.as_ref().map_or(
                        super::vmm_process::VmmProcessInspection::Absent,
                        |proof| {
                            super::vmm_process::VmmProcessInspection::Exact(Box::new(
                                proof.evidence().clone(),
                            ))
                        },
                    ),
                );
            }
        }
        (expected, admitted)
    }

    pub(crate) fn root_control(
        &self,
        cat_id: &Id,
    ) -> Option<(
        &RootProvisionProcessExpectation,
        Option<&ExactRootProvisionProcessProof>,
    )> {
        self.entries.iter().find_map(|entry| match entry {
            NodeGlobalManagedProcessExpectation::RootControl { expectation, exact }
                if &expectation.cat_id == cat_id =>
            {
                Some((expectation.as_ref(), exact.as_deref()))
            }
            NodeGlobalManagedProcessExpectation::RootControl { .. } => None,
            NodeGlobalManagedProcessExpectation::ServingBlockd { .. }
            | NodeGlobalManagedProcessExpectation::Vmm { .. } => None,
        })
    }

    pub(crate) fn serving_blockd(
        &self,
        cat_id: &Id,
        volume_id: &Id,
    ) -> Option<(
        &super::serving_blockd_process::ServingBlockdExpectation,
        Option<&super::serving_blockd_process::ExactServingBlockdProcessProof>,
    )> {
        self.entries.iter().find_map(|entry| match entry {
            NodeGlobalManagedProcessExpectation::ServingBlockd { expectation, exact }
                if expectation.cat_id() == cat_id && expectation.volume_id() == volume_id =>
            {
                Some((expectation.as_ref(), exact.as_deref()))
            }
            _ => None,
        })
    }

    pub(crate) fn retains_absent_vhost_owner(
        &self,
        cat_id: &Id,
        prepared: &cats_api::runtime_reconciliation::PreparedDeviceInput,
    ) -> bool {
        let key = ManagedServingKey::new(cat_id.clone(), prepared.volume_id.clone());
        self.absent_serving_owners.contains(&key)
            && self
                .serving_blockd(cat_id, &prepared.volume_id)
                .is_some_and(|(expectation, exact)| {
                    exact.is_none() && expectation.matches_device_contract(cat_id, prepared)
                })
    }

    pub(crate) fn serving_blockd_count(&self, cat_id: &Id) -> usize {
        self.serving_blockds(cat_id).count()
    }

    pub(crate) fn serving_blockds<'a>(
        &'a self,
        cat_id: &'a Id,
    ) -> impl Iterator<
        Item = (
            &'a super::serving_blockd_process::ServingBlockdExpectation,
            Option<&'a super::serving_blockd_process::ExactServingBlockdProcessProof>,
        ),
    > + 'a {
        self.entries.iter().filter_map(move |entry| match entry {
            NodeGlobalManagedProcessExpectation::ServingBlockd { expectation, exact }
                if expectation.cat_id() == cat_id =>
            {
                Some((expectation.as_ref(), exact.as_deref()))
            }
            _ => None,
        })
    }

    pub(crate) fn vmm(
        &self,
        cat_id: &Id,
    ) -> Option<(
        &super::vmm_process::VmmProcessExpectation,
        Option<&super::vmm_process::ExactVmmProcessProof>,
    )> {
        self.entries.iter().find_map(|entry| match entry {
            NodeGlobalManagedProcessExpectation::Vmm { expectation, exact }
                if expectation.cat_id() == cat_id =>
            {
                Some((expectation.as_ref(), exact.as_deref()))
            }
            _ => None,
        })
    }

    /// Exact live VMM proofs retained by this accepted complete inventory.
    ///
    /// Entries whose same-pass physical inspection proved absence are
    /// deliberately omitted. Callers may consume this iterator only because
    /// the admission itself also sealed the complete Node-global absence /
    /// foreign-residue sweep; a naked empty iterator is not such a proof.
    pub(crate) fn exact_vmm_proofs(
        &self,
    ) -> impl Iterator<Item = &super::vmm_process::ExactVmmProcessProof> {
        self.entries.iter().filter_map(|entry| match entry {
            NodeGlobalManagedProcessExpectation::Vmm {
                exact: Some(proof), ..
            } => Some(proof.as_ref()),
            NodeGlobalManagedProcessExpectation::RootControl { .. }
            | NodeGlobalManagedProcessExpectation::ServingBlockd { .. }
            | NodeGlobalManagedProcessExpectation::Vmm { exact: None, .. } => None,
        })
    }
}

/// One current-process proof that the accepted complete inventory and the
/// sealed physical owner both observed no process for the exact persisted
/// attempt. Private fields prevent a naked empty vector or a naked systemd
/// lookup from authorizing retirement of a durable handoff record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactRootProvisionProcessAbsenceProof {
    checkpoint_content_digest: Sha256Digest,
    expectation: RootProvisionProcessExpectation,
    admission: RootProvisionRetirementAdmission,
    stop_receipt_socket_present: bool,
}

pub(crate) enum RootProvisionAbsencePurpose {
    Ordinary(Option<TargetControlProcessLaunchIdentity>),
    AdmittedStopReceipt(Option<TargetControlProcessLaunchIdentity>),
}

/// Durable coordinates of the accepted complete inventory that authorized
/// one retirement attempt. The next token rotation must prove a strictly
/// newer full admission; this is persisted in the retirement receipt rather
/// than remembered by the Agent process.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootProvisionRetirementAdmission {
    pub node_boot_id: NodeBootId,
    pub agent_instance_id: RandomId128,
    pub agent_session_epoch: Epoch,
    pub inventory_epoch: Epoch,
    pub inventory_digest: Sha256Digest,
    pub inventory_read_position: Sequence,
}

impl RootProvisionProcessExpectation {
    pub(crate) fn prove_exact_process(
        self,
        evidence: RootProvisionProcessEvidence,
    ) -> anyhow::Result<ExactRootProvisionProcessProof> {
        anyhow::ensure!(
            evidence.exactly_matches(&self),
            "root-provision process did not exactly match its authoritative expectation"
        );
        Ok(ExactRootProvisionProcessProof {
            expectation: self,
            evidence,
        })
    }
}

impl ExactRootProvisionProcessProof {
    pub(crate) fn expectation(&self) -> &RootProvisionProcessExpectation {
        &self.expectation
    }

    pub(crate) fn evidence(&self) -> &RootProvisionProcessEvidence {
        &self.evidence
    }

    /// Consume the exact-match proof before projecting a process as verified
    /// public inventory evidence. Raw platform observations deliberately have
    /// no such projection capability.
    pub(crate) fn into_process_evidence(self) -> ProcessEvidence {
        let evidence = self.evidence;
        ProcessEvidence {
            role: ProcessRole::Blockd {
                volume_id: evidence.handshake.identity.volume_id,
                attachment_id: evidence.handshake.identity.attachment_id,
                attachment_epoch: evidence.handshake.identity.attachment_epoch,
            },
            process_id: evidence.process_id,
            process_start_time_ticks: evidence.process_start_time_ticks,
            executable_path: evidence.executable_path,
            scope_id: evidence.scope_id,
            control_socket_path: evidence.control_socket_path,
            state: ProcessState::Running,
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: evidence.ownership_token,
            },
            control_handshake: ControlHandshakeEvidence::Verified,
            observed_vm_shape: None,
        }
    }
}

impl ExactRootProvisionProcessAbsenceProof {
    pub(crate) fn checkpoint_content_digest(&self) -> &Sha256Digest {
        &self.checkpoint_content_digest
    }

    pub(crate) fn expectation(&self) -> &RootProvisionProcessExpectation {
        &self.expectation
    }

    pub(crate) fn admission(&self) -> &RootProvisionRetirementAdmission {
        &self.admission
    }

    pub(crate) fn stop_receipt_socket_present(&self) -> bool {
        self.stop_receipt_socket_present
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
    Conflict(RootProvisionProcessConflict),
    /// The create request may have reached the process owner. The caller must
    /// inspect once and must not issue a second create in this unit.
    Ambiguous,
    /// No process was created, or an exactly identified created process was
    /// killed and waited for before this result was returned.
    CancelledClean,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootProvisionProcessStop {
    /// An exact stop was submitted. Its final result is deliberately resolved
    /// only by a new complete inventory.
    Submitted,
    AlreadyAbsent,
    Conflict(RootProvisionProcessConflict),
    Unavailable,
}

/// Provider-neutral process owner. Production implementations are sealed to
/// this crate so the legacy naked-`Command` path cannot satisfy the port.
pub(crate) trait RootProvisionProcessPort: sealed::Sealed + Send + Sync {
    fn inspect(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<RootProvisionProcessInspection>;

    fn start_checkpointed(
        &self,
        checkpointed: CheckpointedRootProvisionProcess<'_>,
        context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessStart>;

    /// Stop only the physical incarnation sealed in `exact`. Implementations
    /// must compare PID/start/unit/cgroup/socket/token again immediately before
    /// signalling and must never fall back to a unit name or PID alone.
    fn stop_exact(
        &self,
        _exact: ExactRootProvisionProcessProof,
        _context: &RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessStop> {
        Ok(RootProvisionProcessStop::Unavailable)
    }
}

/// Read and revalidate one exact process identity without creating, stopping,
/// or otherwise mutating it. Sealing the underlying port is not itself proof
/// that a returned test/platform value matches the checkpoint expectation.
pub(crate) fn inspect_exact_root_provision_process<P>(
    port: &P,
    expected: &RootProvisionProcessExpectation,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<RootProvisionProcessInspection>
where
    P: RootProvisionProcessPort + ?Sized,
{
    Ok(match port.inspect(expected, context)? {
        RootProvisionProcessInspection::Exact(evidence) if evidence.exactly_matches(expected) => {
            RootProvisionProcessInspection::Exact(evidence)
        }
        RootProvisionProcessInspection::Exact(_) => {
            RootProvisionProcessInspection::Conflict(RootProvisionProcessConflict::IdentityMismatch)
        }
        other => other,
    })
}

/// Construct exact absence only from the accepted full observation that
/// opened this effect batch and a second sealed physical inspection. The
/// caller must retain its checkpoint/artifact locks while consuming the
/// result; this value is deliberately not durable authority by itself.
pub(crate) fn prove_exact_root_provision_process_absence<P>(
    checkpoint_store: &FileCheckpointStore,
    stored_checkpoint: &StoredCheckpoint,
    authority: RootProvisionAuthoritySnapshot<'_>,
    executable_path: HostPath,
    purpose: RootProvisionAbsencePurpose,
    port: &P,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<ExactRootProvisionProcessAbsenceProof>
where
    P: RootProvisionProcessRetirementPort + ?Sized,
{
    context.check_active()?;
    let _node_global_effect = context.lock_node_global_effect()?;
    let admission =
        accepted_full_proves_exact_process_absence(context, checkpoint_store, stored_checkpoint)?;
    let mut expectation = RootProvisionProcessExpectation::from_checkpoint(
        stored_checkpoint.checkpoint(),
        authority,
        executable_path,
    )?;
    let (target_control_launch, with_stop_receipt) = match purpose {
        RootProvisionAbsencePurpose::Ordinary(launch) => (launch, false),
        RootProvisionAbsencePurpose::AdmittedStopReceipt(launch) => (launch, true),
    };
    if let Some(target_control_launch) = target_control_launch {
        expectation = expectation.with_target_control_launch(target_control_launch)?;
    }
    let stop_receipt_socket_present = if with_stop_receipt {
        let Some(receipt) = context
            .node_global_process()?
            .stop_receipt_socket(&expectation.cat_id)
        else {
            anyhow::bail!("accepted full lacks the expected stop receipt socket")
        };
        !receipt.physical_paths().is_empty()
    } else {
        false
    };
    let inspection = if with_stop_receipt {
        port.inspect_absent_with_admitted_stop_receipt(&expectation, context)
    } else {
        port.inspect_after_node_global_sweep(&expectation, context)
    };
    match inspection
        .context("reinspect sealed Node-global root-provision inventory before record retirement")?
    {
        RootProvisionProcessInspection::Absent => Ok(ExactRootProvisionProcessAbsenceProof {
            checkpoint_content_digest: stored_checkpoint.content_digest().clone(),
            expectation,
            admission,
            stop_receipt_socket_present,
        }),
        RootProvisionProcessInspection::Exact(_) => {
            anyhow::bail!("root-provision process is present; handoff record must remain sealed")
        }
        RootProvisionProcessInspection::Conflict(problem) => anyhow::bail!(
            "root-provision process identity conflicts ({problem:?}); handoff record must remain sealed"
        ),
        RootProvisionProcessInspection::Unavailable => anyhow::bail!(
            "root-provision process identity is unavailable; handoff record must remain sealed"
        ),
    }
}

fn accepted_full_proves_exact_process_absence(
    context: &RuntimeDesiredEffectContext,
    checkpoint_store: &FileCheckpointStore,
    stored_checkpoint: &StoredCheckpoint,
) -> anyhow::Result<RootProvisionRetirementAdmission> {
    let accepted = context.accepted_full()?;
    let observation = accepted.observation();
    let attestation = accepted.attestation();
    let session = accepted.session();
    let checkpoint = stored_checkpoint.checkpoint();
    anyhow::ensure!(
        observation.version == cats_api::runtime_reconciliation::ContractVersion::V1
            && session.version == cats_api::runtime_reconciliation::ContractVersion::V1
            && attestation.version == cats_api::runtime_reconciliation::ContractVersion::V1
            && observation.complete_inventory
            && observation.node_id == checkpoint.node_id
            && session.node_id == checkpoint.node_id
            && observation.node_id == session.node_id
            && observation.node_boot_id == session.node_boot_id
            && observation.agent_instance_id == session.agent_instance_id
            && observation.agent_session_epoch == session.agent_session_epoch
            && attestation.node_id == observation.node_id
            && attestation.agent_session_epoch == observation.agent_session_epoch
            && attestation.inventory_epoch == observation.inventory_epoch
            && observation.inventory_digest.as_ref() == Some(&attestation.inventory_digest)
            && observation.inventory_read_position == Some(attestation.inventory_read_position),
        "root-process absence lacks an exact accepted full-inventory admission"
    );
    let mut runtimes = observation
        .runtimes
        .iter()
        .filter(|runtime| runtime.cat_id == checkpoint.cat_id);
    let runtime = runtimes
        .next()
        .context("accepted full inventory omitted the checkpointed Cat")?;
    anyhow::ensure!(
        runtimes.next().is_none(),
        "accepted full inventory contains duplicate checkpointed Cat entries"
    );
    let CheckpointEvidence::Valid {
        checkpoint_path,
        content_digest,
        version,
        cat_id,
        node_id,
        desired_revision,
        spec_digest,
        placement_epoch,
        runtime_incarnation,
        stable_state,
        step,
        require_idle,
        updated_at_unix_ms,
        ..
    } = &runtime.checkpoint
    else {
        anyhow::bail!("accepted full inventory lacks the exact valid checkpoint evidence")
    };
    anyhow::ensure!(
        std::path::Path::new(checkpoint_path.as_str()) == checkpoint_store.path()
            && content_digest == stored_checkpoint.content_digest()
            && *version == checkpoint.version
            && cat_id == &checkpoint.cat_id
            && node_id == &checkpoint.node_id
            && *desired_revision == checkpoint.desired_revision
            && spec_digest == &checkpoint.spec_digest
            && *placement_epoch == checkpoint.placement_epoch
            && runtime_incarnation == &checkpoint.runtime_incarnation
            && stable_state == &checkpoint.stable_state
            && step.as_ref() == &checkpoint.step
            && require_idle.as_ref() == &checkpoint.require_idle
            && *updated_at_unix_ms == checkpoint.updated_at_unix_ms
            && runtime.step == checkpoint.step
            && runtime.processes.is_empty(),
        "accepted full inventory does not prove the exact checkpointed process set empty"
    );
    // `complete_inventory` makes the empty public projection meaningful for
    // this Cat. It is intentionally still insufficient by itself: the sealed
    // port inspection below owns the Node-global service/process/socket sweep
    // and rejects a late, foreign, or duplicate identity as non-absence.
    Ok(RootProvisionRetirementAdmission {
        node_boot_id: observation.node_boot_id.clone(),
        agent_instance_id: observation.agent_instance_id.clone(),
        agent_session_epoch: observation.agent_session_epoch,
        inventory_epoch: observation.inventory_epoch,
        inventory_digest: attestation.inventory_digest.clone(),
        inventory_read_position: attestation.inventory_read_position,
    })
}

/// Unforgeable proof, within this module, that the complete process identity
/// crossed the checkpoint directory durability barrier.
pub(crate) struct CheckpointedRootProvisionProcess<'a> {
    expected: &'a RootProvisionProcessExpectation,
    authority: RootCheckpointAuthority<'a>,
    socket_absence: Option<ExactManagedBlockdSocketOwnerStartAbsence>,
}

enum RootCheckpointAuthority<'a> {
    Current {
        store: &'a FileCheckpointStore,
        stored: &'a StoredCheckpoint,
        guard: CurrentCheckpointGuard<'a>,
    },
    #[cfg(test)]
    Test {
        checkpoint_content_digest: &'a Sha256Digest,
    },
}

/// Retains both the exact target artifact and current checkpoint writer guard
/// across the one strict wrapper submission/adoption attempt.
pub(crate) struct CheckpointedTargetControlProcess<'a> {
    expected: &'a RootProvisionProcessExpectation,
    authorization: &'a TargetControlAuthorizationReady,
    stored: &'a StoredCheckpoint,
    _current_checkpoint: CurrentCheckpointGuard<'a>,
    socket_absence: Option<ExactManagedBlockdSocketOwnerStartAbsence>,
}

impl<'a> CheckpointedTargetControlProcess<'a> {
    pub(crate) fn expected(&self) -> &'a RootProvisionProcessExpectation {
        self.expected
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        self.authorization.assert_current(self.stored)
    }

    pub(crate) fn checkpoint_content_digest(&self) -> &Sha256Digest {
        self.stored.content_digest()
    }

    pub(crate) fn take_socket_absence(
        &mut self,
    ) -> Option<ExactManagedBlockdSocketOwnerStartAbsence> {
        self.socket_absence.take()
    }
}

pub(crate) fn retain_target_control_process_start<'a>(
    store: &'a FileCheckpointStore,
    stored: &'a StoredCheckpoint,
    expected: &'a RootProvisionProcessExpectation,
    authorization: &'a TargetControlAuthorizationReady,
) -> anyhow::Result<CheckpointedTargetControlProcess<'a>> {
    authorization.assert_current(stored)?;
    anyhow::ensure!(
        expected.target_control_launch()
            == Some(&target_control_process_launch_identity(
                authorization.identity(),
            )),
        "target-control start authorization changed launch identity"
    );
    let current = store
        .assert_current(stored)
        .context("retain current checkpoint across target-control start")?;
    authorization.assert_current(stored)?;
    Ok(CheckpointedTargetControlProcess {
        expected,
        authorization,
        stored,
        _current_checkpoint: current,
        socket_absence: None,
    })
}

pub(crate) fn retain_target_control_process_start_with_socket_absence<'a>(
    store: &'a FileCheckpointStore,
    stored: &'a StoredCheckpoint,
    expected: &'a RootProvisionProcessExpectation,
    authorization: &'a TargetControlAuthorizationReady,
    socket_absence: ExactManagedBlockdSocketOwnerStartAbsence,
) -> anyhow::Result<CheckpointedTargetControlProcess<'a>> {
    let mut retained = retain_target_control_process_start(store, stored, expected, authorization)?;
    retained.socket_absence = Some(socket_absence);
    Ok(retained)
}

impl<'a> CheckpointedRootProvisionProcess<'a> {
    pub(crate) fn expected(&self) -> &'a RootProvisionProcessExpectation {
        self.expected
    }

    pub(crate) fn checkpoint_content_digest(&self) -> &'a Sha256Digest {
        match &self.authority {
            RootCheckpointAuthority::Current { stored, .. } => stored.content_digest(),
            #[cfg(test)]
            RootCheckpointAuthority::Test {
                checkpoint_content_digest,
            } => checkpoint_content_digest,
        }
    }

    pub(crate) fn take_socket_absence(
        &mut self,
    ) -> Option<ExactManagedBlockdSocketOwnerStartAbsence> {
        self.socket_absence.take()
    }

    /// Revalidates the same descriptor-retained checkpoint object that minted
    /// this process-start capability. Callers must bracket every namespace
    /// mutation and the final process submission with this check; a digest by
    /// itself is deliberately not current-checkpoint authority.
    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        match &self.authority {
            RootCheckpointAuthority::Current {
                store,
                stored,
                guard,
            } => Ok(store.revalidate_current(stored, guard)?),
            #[cfg(test)]
            RootCheckpointAuthority::Test { .. } => Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        expected: &'a RootProvisionProcessExpectation,
        checkpoint_content_digest: &'a Sha256Digest,
    ) -> Self {
        Self {
            expected,
            authority: RootCheckpointAuthority::Test {
                checkpoint_content_digest,
            },
            socket_absence: None,
        }
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
    /// The target head is authoritative, but the immutable authorized
    /// artifact still carries the acquire-time blank head. A replacement
    /// process cannot use that artifact and must not be submitted.
    TargetControlArtifactRequired,
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
    authority: RootProvisionAuthoritySnapshot<'_>,
    executable_path: HostPath,
    port: &P,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<RootProvisionProcessEnsureResult>
where
    P: RootProvisionProcessPort + ?Sized,
{
    context.check_active()?;
    // Validate the complete authority/checkpoint tuple before replacing the
    // predecessor. A foreign head or lineage must have zero checkpoint effect.
    let expected =
        RootProvisionProcessExpectation::from_checkpoint(checkpoint, authority, executable_path)?;
    let persisted = store
        .replace(predecessor, checkpoint)
        .context("persist root-provision process identity before process effect")?;
    let outcome = ensure_root_provision_process_from_expectation(
        expected, store, &persisted, None, port, context,
    )?;
    Ok(RootProvisionProcessEnsureResult {
        checkpoint: persisted,
        outcome,
    })
}

/// Inspect or start only the exact process identity already present in a
/// durable `ProvisionRootImage` checkpoint. This restart/full-scan entrypoint
/// cannot replace the checkpoint or mint a new process attempt token.
pub(crate) fn ensure_root_provision_process_from_persisted_checkpoint<P>(
    store: &FileCheckpointStore,
    persisted: &StoredCheckpoint,
    authority: RootProvisionAuthoritySnapshot<'_>,
    executable_path: HostPath,
    port: &P,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<RootProvisionProcessOutcome>
where
    P: RootProvisionProcessPort + ?Sized,
{
    context.check_active()?;
    let expected = RootProvisionProcessExpectation::from_checkpoint(
        persisted.checkpoint(),
        authority,
        executable_path,
    )?;
    ensure_root_provision_process_from_expectation(expected, store, persisted, None, port, context)
}

pub(crate) fn ensure_root_provision_process_from_persisted_checkpoint_with_socket_absence<P>(
    store: &FileCheckpointStore,
    persisted: &StoredCheckpoint,
    authority: RootProvisionAuthoritySnapshot<'_>,
    executable_path: HostPath,
    socket_absence: ExactManagedBlockdSocketOwnerStartAbsence,
    port: &P,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<RootProvisionProcessOutcome>
where
    P: RootProvisionProcessPort + ?Sized,
{
    context.check_active()?;
    let expected = RootProvisionProcessExpectation::from_checkpoint(
        persisted.checkpoint(),
        authority,
        executable_path,
    )?;
    ensure_root_provision_process_from_expectation(
        expected,
        store,
        persisted,
        Some(socket_absence),
        port,
        context,
    )
}

fn ensure_root_provision_process_from_expectation<'a, P>(
    expected: RootProvisionProcessExpectation,
    store: &'a FileCheckpointStore,
    persisted: &'a StoredCheckpoint,
    socket_absence: Option<ExactManagedBlockdSocketOwnerStartAbsence>,
    port: &P,
    context: &RuntimeDesiredEffectContext,
) -> anyhow::Result<RootProvisionProcessOutcome>
where
    P: RootProvisionProcessPort + ?Sized,
{
    context.check_active()?;
    let current = store
        .assert_current(persisted)
        .context("retain current checkpoint across root-provision inspection")?;
    let inspection = inspect_exact_root_provision_process(port, &expected, context)
        .context("inspect exact root-provision process identity")?;
    let outcome = match inspection {
        RootProvisionProcessInspection::Exact(evidence) => {
            match_exact(&expected, evidence, RootProvisionProcessOutcome::Adopted)
        }
        RootProvisionProcessInspection::Conflict(problem) => {
            RootProvisionProcessOutcome::Conflict(problem)
        }
        RootProvisionProcessInspection::Unavailable => RootProvisionProcessOutcome::Unavailable,
        RootProvisionProcessInspection::Absent
            if !expected.phase.may_start_from_blank_authorized_artifact() =>
        {
            RootProvisionProcessOutcome::TargetControlArtifactRequired
        }
        RootProvisionProcessInspection::Absent => {
            context.check_active()?;
            let checkpointed = CheckpointedRootProvisionProcess {
                expected: &expected,
                authority: RootCheckpointAuthority::Current {
                    store,
                    stored: persisted,
                    guard: current,
                },
                socket_absence,
            };
            checkpointed.assert_current()?;
            match port
                .start_checkpointed(checkpointed, context)
                .context("start exact checkpointed root-provision process")?
            {
                RootProvisionProcessStart::Started(evidence) => {
                    match_exact(&expected, evidence, RootProvisionProcessOutcome::Started)
                }
                RootProvisionProcessStart::Conflict(problem) => {
                    RootProvisionProcessOutcome::Conflict(problem)
                }
                RootProvisionProcessStart::CancelledClean => {
                    RootProvisionProcessOutcome::CancelledClean
                }
                RootProvisionProcessStart::Unavailable => RootProvisionProcessOutcome::Unavailable,
                RootProvisionProcessStart::Ambiguous => {
                    match inspect_exact_root_provision_process(port, &expected, context)
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
    Ok(outcome)
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
    use crate::runtime::reconciliation::checkpoint::{CheckpointStoreError, WriteStage};
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
            _context: &dyn RuntimePhysicalReadContext,
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
            assert_eq!(checkpointed.expected().scope_id, id("cats-root.service"));
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
        let provision_transition_id = random('3');
        let staged = checkpoint(ReconcileStep::ProvisionRootImage {
            provision_transition_id: provision_transition_id.clone(),
            volume_id: id("vol_root"),
            attachment_id: id("att_root"),
            attachment_epoch: fence(7),
            scope_id: id("cats-root.service"),
            control_socket_path: managed_root_control_socket(&provision_transition_id),
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
    fn stop_receipt_socket_admission_accepts_only_its_exact_public_listener() {
        let owner = random('3');
        let paths = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .root_paths(&owner)
            .unwrap();
        let public = paths.control_socket().clone();
        let quarantine = host(&format!(
            "{}/{}",
            paths.quarantine_directory(),
            cats_blockd::runtime_socket_namespace::BLOCKD_CONTROL_SOCKET_BASENAME
        ));
        for physical in [BTreeSet::new(), BTreeSet::from([public.clone()])] {
            StopReceiptSocketAdmission::new(public.clone(), physical).unwrap();
        }
        assert!(StopReceiptSocketAdmission::new(
            public.clone(),
            BTreeSet::from([quarantine.clone()]),
        )
        .is_err());
        assert!(StopReceiptSocketAdmission::new(
            public.clone(),
            BTreeSet::from([host("/run/cats/blockd-v1/arbitrary.sock")]),
        )
        .is_err());
        assert!(StopReceiptSocketAdmission::new(
            public.clone(),
            BTreeSet::from([public, quarantine.clone()]),
        )
        .is_err());
    }

    #[test]
    fn stop_receipt_admission_allows_its_live_root_but_rejects_cross_cat_alias() {
        let (_root, _state, _store, _predecessor, staged, attachment, evidence) = fixture();
        let authority = authority_record(&attachment, attachment.head.clone());
        let expectation = RootProvisionProcessExpectation::from_checkpoint(
            &staged,
            authority_snapshot(attachment, &authority),
            host("/usr/bin/cats-blockd"),
        )
        .unwrap();
        let exact = expectation
            .clone()
            .prove_exact_process(evidence.clone())
            .unwrap();
        NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::from([(expectation.cat_id.clone(), expectation.clone())]),
            BTreeMap::from([(expectation.cat_id.clone(), exact)]),
        )
        .unwrap()
        .with_stop_receipt_sockets(BTreeMap::from([(
            expectation.cat_id.clone(),
            StopReceiptSocketAdmission::new(
                expectation.control_socket_path.clone(),
                BTreeSet::from([expectation.control_socket_path.clone()]),
            )
            .unwrap(),
        )]))
        .unwrap();

        let quarantine = host(&format!(
            "{}/{}",
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                .root_paths(&random('8'))
                .unwrap()
                .quarantine_directory(),
            cats_blockd::runtime_socket_namespace::BLOCKD_CONTROL_SOCKET_BASENAME
        ));
        let mut other = expectation.clone();
        other.cat_id = id("cat_02");
        other.scope_id = id("cats-root-other.service");
        other.cgroup_path = host("/sys/fs/cgroup/system.slice/cats-root-other.service");
        other.control_socket_path = quarantine.clone();
        let mut other_evidence = evidence;
        other_evidence.scope_id = other.scope_id.clone();
        other_evidence.cgroup_path = other.cgroup_path.clone();
        other_evidence.control_socket_path = quarantine.clone();
        let other_exact = other.clone().prove_exact_process(other_evidence).unwrap();
        let admission = NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::from([
                (expectation.cat_id.clone(), expectation.clone()),
                (other.cat_id.clone(), other.clone()),
            ]),
            BTreeMap::from([(other.cat_id.clone(), other_exact)]),
        )
        .unwrap();
        assert!(admission
            .with_stop_receipt_sockets(BTreeMap::from([(
                expectation.cat_id.clone(),
                StopReceiptSocketAdmission::new(quarantine, BTreeSet::new(),).unwrap(),
            )]))
            .is_err());
    }

    #[test]
    fn durable_checkpoint_precedes_inspect_and_start() {
        let (_root, state, store, predecessor, staged, attachment, evidence) = fixture();
        let authority = authority_record(&attachment, attachment.head.clone());
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
            authority_snapshot(attachment, &authority),
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
    fn restart_uses_the_persisted_attempt_without_replacing_it() {
        let (_root, state, store, predecessor, staged, attachment, evidence) = fixture();
        let authority = authority_record(&attachment, attachment.head.clone());
        let persisted = store.replace(&predecessor, &staged).unwrap();
        let before_digest = persisted.content_digest().clone();
        let port = FakePort::default();
        port.state
            .lock()
            .unwrap()
            .inspections
            .push_back(RootProvisionProcessInspection::Exact(Box::new(
                evidence.clone(),
            )));

        let outcome = ensure_root_provision_process_from_persisted_checkpoint(
            &store,
            &persisted,
            authority_snapshot(attachment, &authority),
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .unwrap();

        assert_eq!(
            outcome,
            RootProvisionProcessOutcome::Adopted(Box::new(evidence))
        );
        let after = store.load().unwrap().unwrap();
        assert_eq!(after.checkpoint(), &staged);
        assert_eq!(after.content_digest(), &before_digest);
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (1, 0));
    }

    #[test]
    fn restart_rejects_a_replaced_checkpoint_before_any_process_io() {
        let (_root, state, store, predecessor, staged, attachment, _evidence) = fixture();
        let authority = authority_record(&attachment, attachment.head.clone());
        let persisted = store.replace(&predecessor, &staged).unwrap();
        let mut successor = staged.clone();
        successor.updated_at_unix_ms = UnixMillis::new(1_900_000_000_001).unwrap();
        store.replace(&persisted, &successor).unwrap();
        let port = FakePort::default();

        let error = ensure_root_provision_process_from_persisted_checkpoint(
            &store,
            &persisted,
            authority_snapshot(attachment, &authority),
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .expect_err("a successor checkpoint must invalidate the loaded predecessor");

        assert!(matches!(
            error.downcast_ref::<CheckpointStoreError>(),
            Some(CheckpointStoreError::ConcurrentUpdate { .. })
        ));
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (0, 0));
    }

    #[test]
    fn lost_provision_response_then_node_restart_adopts_same_process_at_exact_target() {
        let (root, state, store, predecessor, staged, attachment, blank_evidence) = fixture();
        let blank_authority = authority_record(&attachment, attachment.head.clone());
        let first_port = FakePort::default();
        {
            let mut fake = first_port.state.lock().unwrap();
            fake.inspections
                .push_back(RootProvisionProcessInspection::Absent);
            fake.starts
                .push_back(RootProvisionProcessStart::Started(Box::new(
                    blank_evidence.clone(),
                )));
        }
        let started = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            authority_snapshot(attachment.clone(), &blank_authority),
            host("/usr/bin/cats-blockd"),
            &first_port,
            &context(state.clone()),
        )
        .unwrap();
        assert!(matches!(
            started.outcome,
            RootProvisionProcessOutcome::Started(_)
        ));

        let target = match &staged.step {
            ReconcileStep::ProvisionRootImage {
                expected_provisioned_head,
                ..
            } => expected_provisioned_head.clone(),
            _ => unreachable!("fixture is a root-provision checkpoint"),
        };
        let provisioned_authority = authority_record(&attachment, target.clone());
        let mut target_evidence = blank_evidence;
        target_evidence.handshake.remote_head = target;

        drop(store);
        let restarted_store =
            FileCheckpointStore::open(&root.path().join("checkpoints"), &id("cat_01")).unwrap();
        let restarted_predecessor = restarted_store.load().unwrap().unwrap();
        let restarted_port = FakePort::default();
        restarted_port.state.lock().unwrap().inspections.push_back(
            RootProvisionProcessInspection::Exact(Box::new(target_evidence.clone())),
        );

        let adopted = ensure_root_provision_process_after_checkpoint(
            &restarted_store,
            &restarted_predecessor,
            &staged,
            authority_snapshot(attachment.clone(), &provisioned_authority),
            host("/usr/bin/cats-blockd"),
            &restarted_port,
            &context(state),
        )
        .unwrap();
        assert_eq!(
            adopted.outcome,
            RootProvisionProcessOutcome::Adopted(Box::new(target_evidence))
        );
        let fake = restarted_port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (1, 0));
        assert_eq!(attachment.head, blank_head());
        assert_eq!(attachment.initial_head(), &blank_head());
    }

    #[test]
    fn authority_head_outside_persisted_blank_or_target_stops_before_process_io() {
        let (_root, state, store, predecessor, staged, attachment, _evidence) = fixture();
        let foreign_head = RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(digest('9')),
            root_object_id: Some(
                cats_api::runtime_reconciliation::AsciiText::new("roots/foreign").unwrap(),
            ),
        };
        let authority = authority_record(&attachment, foreign_head);
        let port = FakePort::default();
        let error = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            authority_snapshot(attachment, &authority),
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .expect_err("a foreign authority head must not select a process phase");
        assert!(format!("{error:#}").contains("neither exact blank nor exact target"));
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (0, 0));
        assert_eq!(
            store.load().unwrap().unwrap().checkpoint(),
            predecessor.checkpoint()
        );
    }

    #[test]
    fn target_phase_with_absent_process_never_submits_the_blank_artifact() {
        let (_root, state, store, predecessor, staged, attachment, _evidence) = fixture();
        let target = match &staged.step {
            ReconcileStep::ProvisionRootImage {
                expected_provisioned_head,
                ..
            } => expected_provisioned_head.clone(),
            _ => unreachable!("fixture is a root-provision checkpoint"),
        };
        let provisioned_authority = authority_record(&attachment, target);
        let port = FakePort::default();
        port.state
            .lock()
            .unwrap()
            .inspections
            .push_back(RootProvisionProcessInspection::Absent);
        let result = ensure_root_provision_process_after_checkpoint(
            &store,
            &predecessor,
            &staged,
            authority_snapshot(attachment, &provisioned_authority),
            host("/usr/bin/cats-blockd"),
            &port,
            &context(state),
        )
        .unwrap();
        assert_eq!(
            result.outcome,
            RootProvisionProcessOutcome::TargetControlArtifactRequired
        );
        assert_eq!(result.checkpoint.checkpoint(), &staged);
        let fake = port.state.lock().unwrap();
        assert_eq!((fake.inspect_calls, fake.start_calls), (1, 0));
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
            let authority = authority_record(&attachment, attachment.head.clone());
            let port = FakePort::default();
            store.inject_crash_once(stage);
            let error = ensure_root_provision_process_after_checkpoint(
                &store,
                &predecessor,
                &staged,
                authority_snapshot(attachment, &authority),
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
        let authority = authority_record(&attachment, attachment.head.clone());
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
            authority_snapshot(attachment, &authority),
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
        let authority = authority_record(&attachment, attachment.head.clone());
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
            authority_snapshot(attachment, &authority),
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
        let authority = authority_record(&attachment, attachment.head.clone());
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
            authority_snapshot(attachment, &authority),
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
        let authority = authority_record(&attachment, attachment.head.clone());
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
            authority_snapshot(attachment, &authority),
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
    fn pid_start_cgroup_and_socket_peer_are_all_part_of_exact_identity() {
        let variants = [
            "zero_pid",
            "zero_start",
            "wrong_main_pid",
            "wrong_cgroup",
            "duplicate_cgroup_member",
            "foreign_socket_peer",
        ];
        for variant in variants {
            let (_root, state, store, predecessor, staged, attachment, mut evidence) = fixture();
            let authority = authority_record(&attachment, attachment.head.clone());
            match variant {
                "zero_pid" => evidence.process_id = 0,
                "zero_start" => {
                    evidence.process_start_time_ticks = WireU64::new(0).unwrap();
                }
                "wrong_main_pid" => evidence.unit_main_process_id += 1,
                "wrong_cgroup" => {
                    evidence.cgroup_path = host("/sys/fs/cgroup/system.slice/foreign.service");
                }
                "duplicate_cgroup_member" => evidence.cgroup_process_ids.push(5252),
                "foreign_socket_peer" => evidence.handshake.peer_process_id += 1,
                _ => unreachable!(),
            }
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
                authority_snapshot(attachment, &authority),
                host("/usr/bin/cats-blockd"),
                &port,
                &context(state),
            )
            .unwrap();
            assert_eq!(
                result.outcome,
                RootProvisionProcessOutcome::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch
                ),
                "{variant}"
            );
        }
    }

    #[test]
    fn exact_root_provision_identity_projects_one_verified_blockd_process() {
        let (_root, _state, _store, _predecessor, staged, attachment, evidence) = fixture();
        let expected_identity = attachment.identity.clone();
        let expected_token = random('4');
        let authority = authority_record(&attachment, attachment.head.clone());
        let expected = RootProvisionProcessExpectation::from_checkpoint(
            &staged,
            authority_snapshot(attachment, &authority),
            host("/usr/bin/cats-blockd"),
        )
        .unwrap();
        let process = expected
            .prove_exact_process(evidence)
            .unwrap()
            .into_process_evidence();

        assert_eq!(
            process.role,
            ProcessRole::Blockd {
                volume_id: expected_identity.volume_id,
                attachment_id: expected_identity.attachment_id,
                attachment_epoch: expected_identity.attachment_epoch,
            }
        );
        assert_eq!(process.process_id, 4242);
        assert_eq!(process.process_start_time_ticks, WireU64::new(700).unwrap());
        assert_eq!(process.executable_path, host("/usr/bin/cats-blockd"));
        assert_eq!(process.scope_id, id("cats-root.service"));
        assert_eq!(
            process.control_socket_path,
            managed_root_control_socket(&random('3'))
        );
        assert_eq!(process.state, ProcessState::Running);
        assert_eq!(
            process.ownership_token,
            OwnershipTokenEvidence::Valid {
                ownership_token: expected_token,
            }
        );
        assert_eq!(
            process.control_handshake,
            ControlHandshakeEvidence::Verified
        );
        assert_eq!(process.observed_vm_shape, None);
    }

    #[test]
    fn every_identity_mismatch_is_rejected_before_verified_projection() {
        let variants = [
            "zero_pid",
            "wrong_main_pid",
            "zero_start",
            "wrong_cgroup_members",
            "foreign_socket_peer",
            "wrong_executable",
            "wrong_scope",
            "wrong_cgroup_path",
            "wrong_socket",
            "wrong_data_directory",
            "wrong_owner_token",
            "wrong_attachment_identity",
            "wrong_size",
            "wrong_durability",
            "wrong_remote_head",
            "wrong_handshake_token",
            "not_control_only",
            "guest_io_enabled",
        ];
        for variant in variants {
            let (_root, _state, _store, _predecessor, staged, attachment, mut evidence) = fixture();
            let authority = authority_record(&attachment, attachment.head.clone());
            let expected = RootProvisionProcessExpectation::from_checkpoint(
                &staged,
                authority_snapshot(attachment, &authority),
                host("/usr/bin/cats-blockd"),
            )
            .unwrap();
            match variant {
                "zero_pid" => evidence.process_id = 0,
                "wrong_main_pid" => evidence.unit_main_process_id += 1,
                "zero_start" => evidence.process_start_time_ticks = WireU64::new(0).unwrap(),
                "wrong_cgroup_members" => evidence.cgroup_process_ids.push(5252),
                "foreign_socket_peer" => evidence.handshake.peer_process_id += 1,
                "wrong_executable" => evidence.executable_path = host("/usr/bin/foreign"),
                "wrong_scope" => evidence.scope_id = id("cats-foreign.service"),
                "wrong_cgroup_path" => {
                    evidence.cgroup_path = host("/sys/fs/cgroup/system.slice/cats-foreign.service");
                }
                "wrong_socket" => {
                    evidence.control_socket_path = host("/run/cats/foreign.sock");
                }
                "wrong_data_directory" => {
                    evidence.data_directory = host("/var/lib/cats/foreign");
                }
                "wrong_owner_token" => evidence.ownership_token = random('9'),
                "wrong_attachment_identity" => {
                    evidence.handshake.identity.attachment_id = id("att_foreign");
                }
                "wrong_size" => evidence.handshake.size_bytes += 1,
                "wrong_durability" => evidence.handshake.durability = Durability::Relaxed,
                "wrong_remote_head" => {
                    evidence.handshake.remote_head = RemoteHead {
                        generation: Generation::new(1).unwrap(),
                        root_hash: Some(digest('9')),
                        root_object_id: Some(
                            cats_api::runtime_reconciliation::AsciiText::new("roots/foreign")
                                .unwrap(),
                        ),
                    };
                }
                "wrong_handshake_token" => {
                    evidence.handshake.process_identity_token = random('9');
                }
                "not_control_only" => evidence.handshake.control_only = false,
                "guest_io_enabled" => evidence.handshake.guest_io_enabled = true,
                _ => unreachable!(),
            }

            assert!(
                expected.prove_exact_process(evidence).is_err(),
                "{variant} must not construct an exact proof"
            );
        }
    }

    #[test]
    fn cancelled_start_is_closed_only_after_the_port_reports_cleanup() {
        let (_root, state, store, predecessor, staged, attachment, _evidence) = fixture();
        let authority = authority_record(&attachment, attachment.head.clone());
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
            authority_snapshot(attachment, &authority),
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
            runtime_launch: cats_api::runtime_reconciliation::RuntimeLaunch::Absent,
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
            object_write_credential: None,
            size_bytes: 4_194_304,
            durability: Durability::Strict,
            head: blank_head(),
            lease_expires_at: UnixMillis::new(1_900_000_060_000).unwrap(),
            acquire: cats_storage::authority::AuthorizedServingAcquire::Normal {
                result: NormalAcquireResult {
                    volume_id: request.volume_id.clone(),
                    transition_id: request.transition_id.clone(),
                    attachment_id: request.attachment_id.clone(),
                    resulting_epoch: fence(7),
                    resulting_head: blank_head(),
                    lease_expires_at: UnixMillis::new(1_900_000_060_000).unwrap(),
                },
                request,
            },
        }
    }

    fn authority_record(
        attachment: &AuthorizedServingAttachment,
        head: RemoteHead,
    ) -> VolumeRecord {
        VolumeRecord {
            volume_id: attachment.identity.volume_id.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            admin_state: VolumeAdminState::Active,
            head,
            lease_owner: Some(attachment.identity.attachment_id.clone()),
            lease_epoch: attachment.identity.attachment_epoch,
            lease_expires_at: Some(attachment.lease_expires_at),
            last_transition: Some(attachment.expected_last_transition()),
        }
    }

    fn authority_snapshot<'a>(
        attachment: AuthorizedServingAttachment,
        volume: &'a VolumeRecord,
    ) -> RootProvisionAuthoritySnapshot<'a> {
        RootProvisionAuthoritySnapshot { attachment, volume }
    }

    fn evidence(attachment: &AuthorizedServingAttachment) -> RootProvisionProcessEvidence {
        RootProvisionProcessEvidence {
            process_id: 4242,
            unit_main_process_id: 4242,
            process_start_time_ticks: WireU64::new(700).unwrap(),
            executable_path: host("/usr/bin/cats-blockd"),
            scope_id: id("cats-root.service"),
            cgroup_path: host("/sys/fs/cgroup/system.slice/cats-root.service"),
            cgroup_process_ids: vec![4242],
            control_socket_path: managed_root_control_socket(&random('3')),
            data_directory: host("/var/lib/cats/cat_01/root"),
            ownership_token: random('4'),
            handshake: RootProvisionBlockdHandshake {
                peer_process_id: 4242,
                identity: attachment.identity.clone(),
                size_bytes: attachment.size_bytes,
                durability: attachment.durability,
                remote_head: attachment.head.clone(),
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

    fn managed_root_control_socket(provision_transition_id: &RandomId128) -> HostPath {
        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .root_paths(provision_transition_id)
            .unwrap()
            .control_socket()
            .clone()
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
