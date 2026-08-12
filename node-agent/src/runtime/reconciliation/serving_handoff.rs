//! Immutable handoff from root provisioning to a future serving blockd.
//!
//! The acquire-time `authorized-serving.json` deliberately retains its blank
//! head. Root provisioning needs that exact predecessor to recover a lost
//! response, so it must never be rewritten into a serving grant. This module
//! instead seals a sibling target-head *control* grant plus one immutable
//! handoff record. The control grant may be used only to restart/inspect a
//! control-only process after the authority CAS reached its target; its mere
//! presence is deliberately insufficient to construct serving authority.
//!
//! A [`ServingHandoffReady`] can be constructed only from both authoritative
//! postconditions required by Runtime Reconciliation v1: a raw `VolumeRecord`
//! reread at the exact target, and the exact old control-only process after it
//! has reloaded and handshaken at that same target. The returned proof does not
//! create a device or start a process. It can be consumed only while all
//! retained descriptors remain current, producing the exact closed handoff
//! provenance persisted by the expanded `PrepareDevice` step.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
#[cfg(test)]
use std::sync::Mutex;

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, encode_runtime_checkpoint, ContractVersion, DesiredRuntimeSpec,
    Epoch, HostPath, Id, NodeBootId, PrepareDeviceFrontend, RandomId128, ReconcileStep, RemoteHead,
    RootServingHandoff, RootServingHandoffRecordIdentity, RuntimeCheckpoint, Sequence,
    ServingAuthorityProvenance, Sha256Digest, VolumeRecord, WireU64,
};
#[cfg(test)]
use cats_api::runtime_reconciliation::{AcquireOrigin, Durability, FenceEpoch, Revision};
pub(crate) use cats_blockd::serving_handoff::{
    decode_serving_handoff_record, SERVING_HANDOFF_RECORD_FILE, SERVING_HANDOFF_RECORD_MAX_BYTES,
};
use cats_blockd::serving_handoff::{
    encode_serving_handoff_record, validate_serving_handoff_record, ServingControlProcessIdentity,
    ServingControlReloadHandshake, ServingHandoffCodecError, ServingHandoffRecord,
    ServingHandoffRecordIdentity, TargetControlAuthorizationIdentity,
};
#[cfg(test)]
use cats_blockd::target_control::TargetControlAuthorizationCodecError;
use cats_blockd::target_control::{
    decode_target_control_authorization, encode_target_control_authorization,
    provision_root_authorization_context_digest, provision_root_image_request,
    target_control_authorization_file_name, validate_target_control_attachment,
    StableDirectoryIdentity, StableFileIdentity, TargetControlAuthorizationArtifact,
    TargetControlLocalStateIdentity as ServingHandoffLocalStateIdentity,
    TARGET_CONTROL_AUTHORIZATION_MAX_BYTES as TARGET_AUTHORIZED_SERVING_MAX_BYTES,
};
use cats_storage::authority::{
    validate_authorized_serving_record, AttachmentLineageIdentity, AuthorizedServingAttachment,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::state_directory::StateDirectory;

use super::authorized_blockd::{
    authorized_blockd_data_directory, validate_authorized_blockd_checkpoint,
    AuthorizedBlockdCheckpoint, AuthorizedBlockdLaunchConfig, PreparedAuthorizedBlockd,
    RetainedAuthorizedBlockd, AUTHORIZED_SERVING_FILE, IDENTITY_FILE, LAUNCH_CHECKPOINT_FILE,
    MAX_AUTHORIZED_SERVING_BYTES, MAX_IDENTITY_BYTES, MAX_LAUNCH_CHECKPOINT_BYTES,
};
use super::network::{prepare_device_checkpoint_view, prepared_device_input};
use super::root_provision_process::{
    prove_exact_root_provision_process_absence, ExactRootProvisionProcessAbsenceProof,
    ExactRootProvisionProcessProof, RetainedRootProvisionPhysicalIdentity,
    RetainedRootProvisionProcessAttempt, RootProvisionAbsencePurpose,
    RootProvisionAuthoritySnapshot, RootProvisionBlockdHandshake, RootProvisionProcessEvidence,
    RootProvisionProcessExpectation, RootProvisionProcessRetirementPort,
    TargetControlProcessLaunchIdentity,
};
use super::{FileCheckpointStore, StoredCheckpoint};

const SERVING_HANDOFF_RECORD_TEMP: &str = ".serving-handoff.json.tmp";
pub(crate) const SERVING_HANDOFF_RETIREMENT_FILE: &str = "serving-handoff-retirement.json";
const SERVING_HANDOFF_RETIREMENT_TEMP: &str = ".serving-handoff-retirement.json.tmp";
pub(crate) const SERVING_HANDOFF_RETIREMENT_MAX_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServingHandoffTempKind {
    TargetAuthorization,
    Record,
    RetirementReceipt,
}

/// The exact raw-authority reread associated with the current provision step.
///
/// The transition ID is repeated intentionally: a target head left by a
/// superseded provision attempt cannot be rebound to the current checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServingAuthorityTargetEvidence {
    provision_transition_id: RandomId128,
    volume: VolumeRecord,
}

impl ServingAuthorityTargetEvidence {
    pub(crate) fn new(provision_transition_id: RandomId128, volume: VolumeRecord) -> Self {
        Self {
            provision_transition_id,
            volume,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServingHandoffRetirementAdmission {
    node_boot_id: NodeBootId,
    agent_instance_id: RandomId128,
    agent_session_epoch: Epoch,
    inventory_epoch: Epoch,
    inventory_digest: Sha256Digest,
    inventory_read_position: Sequence,
}

/// Durable, attempt-specific authority for the gap between unlinking a dead
/// handoff and rotating its checkpointed process token. It retains the full
/// record plus descriptor identity, so an absent path after restart cannot be
/// confused with a record that never existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServingHandoffRetirementReceipt {
    version: ContractVersion,
    old_checkpoint_content_digest: Sha256Digest,
    old_checkpoint: RuntimeCheckpoint,
    old_process_identity_token: RandomId128,
    record_identity: ServingHandoffRecordIdentity,
    record: ServingHandoffRecord,
    admission: ServingHandoffRetirementAdmission,
}

pub(crate) struct ScannedServingHandoffArtifact<'a> {
    pub path: HostPath,
    pub device: WireU64,
    pub inode: WireU64,
    pub length: WireU64,
    pub content_sha256: Sha256Digest,
    pub bytes: &'a [u8],
}

/// In-memory proof returned only after both immutable files and their parent
/// directory have crossed their durability barriers.
#[derive(Debug)]
pub(crate) struct ServingHandoffReady {
    retained: RetainedAttachmentContext,
    retained_target: RetainedFile,
    retained_record: RetainedFile,
    record_identity: ServingHandoffRecordIdentity,
    record: ServingHandoffRecord,
}

/// Descriptor-retained reconstruction of the old target-control process after
/// the Runtime checkpoint has atomically advanced to `PrepareDevice`.
///
/// This value is deliberately read-only.  It pins the acquire-time inputs,
/// target-head authorization, sealed handoff record and optional predecessor
/// retirement receipt under the attachment flock.  Only an exact process
/// expectation can be projected from it; it cannot start a serving process or
/// create a frontend/device.
pub(crate) struct PrepareDeviceHandoffReady {
    retained_authorized: RetainedAuthorizedBlockd,
    retained_target: RetainedFile,
    retained_record: RetainedFile,
    retained_retirement: Option<RetainedFile>,
    attempt: RetainedRootProvisionProcessAttempt,
}

impl PrepareDeviceHandoffReady {
    pub(crate) fn attempt(&self) -> &RetainedRootProvisionProcessAttempt {
        &self.attempt
    }

    pub(crate) fn authorized_checkpoint(&self) -> &AuthorizedBlockdCheckpoint {
        self.retained_authorized.checkpoint()
    }

    pub(crate) fn assert_current(
        &self,
        checkpoint: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
    ) -> Result<()> {
        self.retained_authorized.assert_current()?;
        let directory = self.retained_authorized.retained_directory();
        self.retained_target
            .assert_current(directory, &self.retained_target.identity.path)?;
        self.retained_record
            .assert_current(directory, &self.retained_record.identity.path)?;
        if let Some(retirement) = &self.retained_retirement {
            retirement.assert_current(directory, &retirement.identity.path)?;
        }
        let current = validate_retained_prepare_device_handoff(
            checkpoint,
            desired,
            authority,
            &self.retained_authorized,
            &self.retained_target,
            &self.retained_record,
            self.retained_retirement.as_ref(),
        )?;
        anyhow::ensure!(
            current == self.attempt,
            "retained PrepareDevice handoff changed its old process identity"
        );
        Ok(())
    }

    /// Build the only authorized-serving argv accepted after a sealed Root
    /// handoff. The caller must keep this proof and the per-Cat checkpoint
    /// writer guard alive through process submission, and must call
    /// [`Self::assert_current`] again at the submit boundary. Returning a
    /// [`Command`] here performs no Host effect.
    pub(crate) fn authorized_serving_command(
        &self,
        config: &AuthorizedBlockdLaunchConfig,
        checkpoint: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
    ) -> Result<Command> {
        self.assert_current(checkpoint, desired, authority)?;
        let prepared = prepared_device_input(checkpoint)
            .context("authorized Root serving command requires a prepared device")?;
        let ServingAuthorityProvenance::AfterRootProvision { handoff } =
            prepared.serving_authority.as_ref()
        else {
            anyhow::bail!("authorized Root serving command requires sealed handoff provenance")
        };
        let attachment = &self.attempt.attachment;
        anyhow::ensure!(
            config.blockd_binary.is_absolute()
                && config.blockd_binary
                    == Path::new(prepared.serving_process.executable_path.as_str()),
            "authorized Root serving executable differs from installed blockd"
        );
        anyhow::ensure!(
            config.metadata_store.name == "postgres",
            "authorized Root serving requires the frozen postgres authority adapter"
        );
        anyhow::ensure!(
            config.max_staged_bytes > 0
                && config.max_staged_packs > 0
                && config.max_local_bytes > 0,
            "authorized Root serving resource limits must be positive"
        );
        anyhow::ensure!(
            prepared.volume_id == attachment.identity.volume_id
                && prepared.attachment_id == attachment.identity.attachment_id
                && Path::new(prepared.serving_process.data_directory.as_str())
                    == self.retained_authorized.data_directory(),
            "authorized Root serving command changed its retained attachment"
        );
        anyhow::ensure!(
            prepared.serving_process.process_identity_token != prepared.ownership_token,
            "authorized Root serving process and device tokens must differ"
        );

        let mut command = Command::new(&config.blockd_binary);
        command
            .arg("--volume-id")
            .arg(prepared.volume_id.as_str())
            .arg("--data-dir")
            .arg(self.retained_authorized.data_directory())
            .arg("--attachment-id")
            .arg(prepared.attachment_id.as_str())
            .arg("--authorized-serving-handoff-record")
            .arg(handoff.record.path.as_str())
            .arg("--authorized-serving-handoff-predecessor-checkpoint-content-digest")
            .arg(handoff.predecessor_checkpoint_content_digest.as_str())
            .arg("--authorized-serving-handoff-record-device")
            .arg(handoff.record.device.get().to_string())
            .arg("--authorized-serving-handoff-record-inode")
            .arg(handoff.record.inode.get().to_string())
            .arg("--authorized-serving-handoff-record-length")
            .arg(handoff.record.length.get().to_string())
            .arg("--authorized-serving-handoff-record-content-sha256")
            .arg(handoff.record.content_sha256.as_str())
            .arg("--runtime-scope-id")
            .arg(prepared.serving_process.scope_id.as_str())
            .arg("--process-identity-token")
            .arg(prepared.serving_process.process_identity_token.as_str())
            .arg("--device-ownership-token")
            .arg(prepared.ownership_token.as_str())
            .arg("--guest-device-serial")
            .arg(prepared.guest_device.serial.as_str())
            .arg("--metadata-store-adapter")
            .arg(&config.metadata_store.name)
            .arg("--object-store-adapter")
            .arg(&config.object_store.name)
            .arg("--lease-ttl-ms")
            .arg(attachment.lease_duration_ms().to_string())
            .arg("--max-staged-bytes")
            .arg(config.max_staged_bytes.to_string())
            .arg("--max-staged-packs")
            .arg(config.max_staged_packs.to_string())
            .arg("--max-local-bytes")
            .arg(config.max_local_bytes.to_string())
            .arg("--durability")
            .arg(match attachment.durability {
                cats_api::runtime_reconciliation::Durability::Strict => "strict",
                cats_api::runtime_reconciliation::Durability::Relaxed => "relaxed",
            })
            .arg("--listen-control")
            .arg(prepared.serving_process.control_socket_path.as_str());
        match &prepared.frontend {
            PrepareDeviceFrontend::KernelNbd {
                listener_socket_path,
                ..
            } => {
                command
                    .arg("--listen-unix")
                    .arg(listener_socket_path.as_str());
            }
            PrepareDeviceFrontend::VhostUserBlk {
                socket_path,
                queues,
                queue_size,
            } => {
                cats_blockd::frontend_contract::validate_authorized_vhost_shape(
                    usize::from(*queues),
                    *queue_size,
                )
                .context("authorized Root serving vhost shape violates the frozen contract")?;
                command
                    .arg("--listen-vhost-user")
                    .arg(socket_path.as_str())
                    .arg("--vhost-user-queues")
                    .arg(queues.to_string())
                    .arg("--vhost-user-queue-size")
                    .arg(queue_size.to_string());
            }
        }
        for option in config.metadata_store.config.to_cli() {
            command.arg("--metadata-store-option").arg(option);
        }
        for option in config.object_store.config.to_cli() {
            command.arg("--object-store-option").arg(option);
        }
        command.env_remove("CATS_CRASH_POINT");
        self.assert_current(checkpoint, desired, authority)?;
        Ok(command)
    }
}

impl ServingHandoffReady {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "descriptor identity accessor is exercised by contract tests"
        )
    )]
    pub(crate) fn record_path(&self) -> &HostPath {
        self.record_identity.path()
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "descriptor identity accessor is exercised by contract tests"
        )
    )]
    pub(crate) fn record_identity(&self) -> &ServingHandoffRecordIdentity {
        &self.record_identity
    }

    pub(crate) fn target_control_authorization(&self) -> &TargetControlAuthorizationIdentity {
        &self.record.target_control_authorization
    }

    pub(crate) fn old_control_process(&self) -> &ServingControlProcessIdentity {
        &self.record.old_control_process
    }

    pub(crate) fn record(&self) -> &ServingHandoffRecord {
        &self.record
    }

    /// Revalidate every retained descriptor and every lexical mapping at the
    /// last possible point before a future persisted handoff step consumes
    /// this proof.
    pub(crate) fn assert_current(&self, stored_checkpoint: &StoredCheckpoint) -> Result<()> {
        validate_record_checkpoint_context(&self.record, stored_checkpoint)?;
        self.assert_artifacts_current()
    }

    fn assert_artifacts_current(&self) -> Result<()> {
        self.retained.assert_current()?;
        let target_identity = &self.record.target_control_authorization;
        anyhow::ensure!(
            target_identity.device() == self.retained_target.identity.device
                && target_identity.inode() == self.retained_target.identity.inode
                && target_identity.length() == self.retained_target.identity.length
                && target_identity.content_sha256()
                    == &self.retained_target.identity.content_sha256,
            "retained target-control authorization no longer matches its typed identity"
        );
        self.retained_target
            .assert_current(&self.retained.attachment_directory, target_identity.path())?;
        anyhow::ensure!(
            self.record_identity.device() == self.retained_record.identity.device
                && self.record_identity.inode() == self.retained_record.identity.inode
                && self.record_identity.length() == self.retained_record.identity.length
                && self.record_identity.content_sha256()
                    == &self.retained_record.identity.content_sha256,
            "retained handoff record no longer matches its typed identity"
        );
        self.retained_record.assert_current(
            &self.retained.attachment_directory,
            self.record_identity.path(),
        )?;
        Ok(())
    }

    /// Keep every descriptor and the attachment-directory lock retained while
    /// the caller atomically persists the next `PrepareDevice` checkpoint.
    /// Returning the typed value without executing the consumer would reopen
    /// a rename/recreate ABA window between validation and checkpoint replace.
    pub(crate) fn consume_for_prepare_device<T>(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        consume: impl FnOnce(RootServingHandoff) -> Result<T>,
    ) -> Result<T> {
        self.assert_current(stored_checkpoint)?;
        let handoff = RootServingHandoff {
            predecessor_checkpoint_content_digest: self.record.checkpoint_content_digest.clone(),
            record: RootServingHandoffRecordIdentity {
                path: self.record_identity.path.clone(),
                device: self.record_identity.device,
                inode: self.record_identity.inode,
                length: self.record_identity.length,
                content_sha256: self.record_identity.content_sha256.clone(),
            },
        };
        let result = consume(handoff)?;
        // The checkpoint replace may have crossed cancellation or a hostile
        // same-uid lexical mutation. Keep every retained descriptor and the
        // attachment flock live through one last post-publication mapping
        // check; an error leaves the durable checkpoint for the next fresh
        // inventory and never authorizes another effect from this admission.
        self.assert_artifacts_current()?;
        Ok(result)
    }
}

/// Durable target-head grant that is sufficient only to restart/inspect the
/// old role as `control_only`. It is not a serving-ready proof.
#[derive(Debug)]
pub(crate) struct TargetControlAuthorizationReady {
    identity: TargetControlAuthorizationIdentity,
    retained: RetainedAttachmentContext,
    retained_target: RetainedFile,
}

#[derive(Debug)]
pub(crate) enum ReopenedTargetControlAuthorization {
    Absent,
    Exact(Box<TargetControlAuthorizationReady>),
}

#[derive(Debug)]
pub(crate) enum ReopenedServingHandoff {
    Absent(Box<TargetControlAuthorizationReady>),
    Exact(Box<ServingHandoffReady>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServingHandoffRetirementState {
    None,
    CurrentAttempt,
    DirectPredecessor,
}

impl TargetControlAuthorizationReady {
    pub(crate) fn identity(&self) -> &TargetControlAuthorizationIdentity {
        &self.identity
    }

    pub(crate) fn assert_current(&self, stored_checkpoint: &StoredCheckpoint) -> Result<()> {
        validate_target_checkpoint_context(&self.identity.artifact, stored_checkpoint)?;
        self.retained.assert_current()?;
        anyhow::ensure!(
            self.identity.device() == self.retained_target.identity.device
                && self.identity.inode() == self.retained_target.identity.inode
                && self.identity.length() == self.retained_target.identity.length
                && self.identity.content_sha256() == &self.retained_target.identity.content_sha256,
            "retained target-control authorization no longer matches its typed identity"
        );
        self.retained_target
            .assert_current(&self.retained.attachment_directory, self.identity.path())
    }
}

pub(crate) fn target_control_process_launch_identity(
    identity: &TargetControlAuthorizationIdentity,
) -> TargetControlProcessLaunchIdentity {
    TargetControlProcessLaunchIdentity::new(
        identity.path.clone(),
        identity.artifact.provision_transition_id.clone(),
        identity.artifact.provision_context_digest.clone(),
    )
}

fn encode_serving_handoff_retirement_receipt(
    receipt: &ServingHandoffRetirementReceipt,
) -> std::result::Result<Vec<u8>, ServingHandoffCodecError> {
    validate_retirement_receipt(receipt)?;
    canonical_encode(
        receipt,
        SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
        "retirement receipt",
    )
}

pub(crate) fn decode_serving_handoff_retirement_receipt(
    bytes: &[u8],
) -> std::result::Result<ServingHandoffRetirementReceipt, ServingHandoffCodecError> {
    canonical_decode(
        bytes,
        SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
        "retirement receipt",
        validate_retirement_receipt,
    )
}

#[cfg(test)]
type TestMutation = Box<dyn FnOnce() + Send>;
#[cfg(test)]
type PendingTestMutation = Option<(PublicationStage, TestMutation)>;

pub(crate) struct ServingHandoffStore {
    state_directory: StateDirectory,
    #[cfg(test)]
    crash_once: Mutex<Option<PublicationStage>>,
    #[cfg(test)]
    mutation_once: Mutex<PendingTestMutation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServingHandoffRetirement {
    Retired,
    RecoveredAlreadyAbsent,
}

impl ServingHandoffStore {
    pub(crate) fn new(state_directory: StateDirectory) -> Self {
        Self {
            state_directory,
            #[cfg(test)]
            crash_once: Mutex::new(None),
            #[cfg(test)]
            mutation_once: Mutex::new(None),
        }
    }

    /// Reopen the deterministic target artifact through the protected state
    /// and attachment descriptors. `Exact` retains the attachment flock and
    /// every predecessor descriptor; a naked path observation is never
    /// returned to an effect caller.
    pub(crate) fn reopen_target_control_authorization(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
    ) -> Result<ReopenedTargetControlAuthorization> {
        let candidate = build_target_candidate(
            &self.state_directory,
            stored_checkpoint,
            acquired,
            authority,
        )?;
        let target_name = target_control_file_name(&candidate.provision_transition_id);
        let temporary_name = target_control_temp_name(&candidate.provision_transition_id);
        let retained = RetainedAttachmentContext::open_and_lock(
            self.state_directory.clone(),
            &candidate.data_directory,
            acquired,
            &target_name,
            &temporary_name,
        )?;
        self.finish_reopen_target(stored_checkpoint, &candidate, &target_name, retained)
    }

    /// Reopen the target artifact through an attachment descriptor whose
    /// flock is already owned by the superseded-checkpoint retirement path.
    /// This is the launch-identity bridge for target wrappers: it never drops
    /// to the blank-control argv expectation merely because the current
    /// Desired no longer names the predecessor.
    pub(crate) fn reopen_target_control_authorization_from_retained(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
        predecessor: &RetainedAuthorizedBlockd,
    ) -> Result<ReopenedTargetControlAuthorization> {
        let candidate = build_target_candidate(
            &self.state_directory,
            stored_checkpoint,
            acquired,
            authority,
        )?;
        let target_name = target_control_file_name(&candidate.provision_transition_id);
        let temporary_name = target_control_temp_name(&candidate.provision_transition_id);
        let attachment_directory = predecessor.duplicate_locked_attachment_directory()?;
        let retained = RetainedAttachmentContext::from_locked_directory(
            self.state_directory.clone(),
            &candidate.data_directory,
            acquired,
            &target_name,
            &temporary_name,
            attachment_directory,
        )?;
        predecessor.assert_current()?;
        self.finish_reopen_target(stored_checkpoint, &candidate, &target_name, retained)
    }

    fn finish_reopen_target(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        candidate: &TargetControlCandidate,
        target_name: &str,
        retained: RetainedAttachmentContext,
    ) -> Result<ReopenedTargetControlAuthorization> {
        let temporary_name = target_control_temp_name(&candidate.provision_transition_id);
        ensure_no_unpublished_handoff_temp(&retained.attachment_directory, &temporary_name)?;
        let target_name_c = c_string(target_name)?;
        if read_optional_bounded(
            &retained.attachment_directory,
            &target_name_c,
            TARGET_AUTHORIZED_SERVING_MAX_BYTES,
        )?
        .is_none()
        {
            return Ok(ReopenedTargetControlAuthorization::Absent);
        }
        let target_path = host_path(
            &candidate.data_directory.join(target_name),
            "reopened target control authorization path",
        )?;
        let retained_target = RetainedFile::open_required(
            &retained.attachment_directory,
            target_name,
            target_path,
            TARGET_AUTHORIZED_SERVING_MAX_BYTES,
        )?;
        let artifact = decode_target_control_authorization(&retained_target.bytes)?;
        let expected = target_control_artifact(stored_checkpoint, &retained, candidate)?;
        anyhow::ensure!(
            artifact == expected,
            "reopened target control authorization conflicts with current authority"
        );
        let ready = TargetControlAuthorizationReady {
            identity: target_control_identity(&retained_target, artifact),
            retained,
            retained_target,
        };
        ready.assert_current(stored_checkpoint)?;
        Ok(ReopenedTargetControlAuthorization::Exact(Box::new(ready)))
    }

    /// Reopen a sealed handoff while keeping the exact target and attachment
    /// descriptors live. `Absent` returns that retained target so the caller
    /// can perform one global process reinspection and publish without an ABA
    /// gap.
    pub(crate) fn reopen_serving_handoff(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        target_ready: TargetControlAuthorizationReady,
    ) -> Result<ReopenedServingHandoff> {
        target_ready.assert_current(stored_checkpoint)?;
        let directory = &target_ready.retained.attachment_directory;
        ensure_no_unpublished_handoff_temp(
            directory,
            &target_control_temp_name(&target_ready.identity.artifact.provision_transition_id),
        )?;
        let record_name = c_string(SERVING_HANDOFF_RECORD_FILE)?;
        if read_optional_bounded(directory, &record_name, SERVING_HANDOFF_RECORD_MAX_BYTES)?
            .is_none()
        {
            return Ok(ReopenedServingHandoff::Absent(Box::new(target_ready)));
        }
        let record_path = host_path(
            &target_ready
                .retained
                .data_directory
                .join(SERVING_HANDOFF_RECORD_FILE),
            "reopened serving handoff record path",
        )?;
        let retained_record = RetainedFile::open_required(
            directory,
            SERVING_HANDOFF_RECORD_FILE,
            record_path.clone(),
            SERVING_HANDOFF_RECORD_MAX_BYTES,
        )?;
        let record = decode_serving_handoff_record(&retained_record.bytes)?;
        anyhow::ensure!(
            record.target_control_authorization == target_ready.identity,
            "reopened handoff record changed target-control identity"
        );
        let record_identity = ServingHandoffRecordIdentity {
            path: record_path,
            device: retained_record.identity.device,
            inode: retained_record.identity.inode,
            length: retained_record.identity.length,
            content_sha256: retained_record.identity.content_sha256.clone(),
        };
        let TargetControlAuthorizationReady {
            retained,
            retained_target,
            ..
        } = target_ready;
        let ready = ServingHandoffReady {
            retained,
            retained_target,
            retained_record,
            record_identity,
            record,
        };
        ready.assert_current(stored_checkpoint)?;
        Ok(ReopenedServingHandoff::Exact(Box::new(ready)))
    }

    /// Reopen the Root handoff after its atomic `PrepareDevice` checkpoint
    /// replacement.  The current checkpoint no longer contains the old
    /// process fields, so the immutable record/target pair and acquire-time
    /// files are rejoined under retained descriptors and the attachment
    /// flock.  This is the only effect-time path that can reconstruct the old
    /// target-control process expectation.
    pub(crate) fn reopen_prepare_device_handoff(
        &self,
        checkpoint: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        authority: &VolumeRecord,
        retained_authorized: RetainedAuthorizedBlockd,
    ) -> Result<PrepareDeviceHandoffReady> {
        anyhow::ensure!(
            self.state_directory.path() == retained_authorized.state_directory_path(),
            "PrepareDevice handoff reopen uses another Node state directory"
        );
        let prepared = prepared_device_input(checkpoint)
            .context("PrepareDevice handoff reopen requires a prepared device")?;
        let ServingAuthorityProvenance::AfterRootProvision { handoff } =
            prepared.serving_authority.as_ref()
        else {
            anyhow::bail!("PrepareDevice handoff reopen requires Root serving provenance")
        };
        let data_directory = retained_authorized.data_directory();
        anyhow::ensure!(
            Path::new(prepared.serving_process.data_directory.as_str()) == data_directory
                && Path::new(handoff.record.path.as_str())
                    == data_directory.join(SERVING_HANDOFF_RECORD_FILE),
            "PrepareDevice handoff paths leave the retained attachment directory"
        );
        let directory = retained_authorized.retained_directory();
        let retained_record = RetainedFile::open_required(
            directory,
            SERVING_HANDOFF_RECORD_FILE,
            handoff.record.path.clone(),
            SERVING_HANDOFF_RECORD_MAX_BYTES,
        )?;
        let record = decode_serving_handoff_record(&retained_record.bytes)?;
        let target_name = target_control_file_name(&record.provision_transition_id);
        let target_temp = target_control_temp_name(&record.provision_transition_id);
        validate_handoff_namespace(directory, &target_name, &target_temp)?;
        let retained_target = RetainedFile::open_required(
            directory,
            &target_name,
            record.target_control_authorization.path.clone(),
            TARGET_AUTHORIZED_SERVING_MAX_BYTES,
        )?;
        let retirement_name = c_string(SERVING_HANDOFF_RETIREMENT_FILE)?;
        let retained_retirement = if read_optional_bounded(
            directory,
            &retirement_name,
            SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
        )?
        .is_some()
        {
            Some(RetainedFile::open_required(
                directory,
                SERVING_HANDOFF_RETIREMENT_FILE,
                host_path(
                    &data_directory.join(SERVING_HANDOFF_RETIREMENT_FILE),
                    "PrepareDevice handoff retirement path",
                )?,
                SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
            )?)
        } else {
            None
        };
        let attempt = validate_retained_prepare_device_handoff(
            checkpoint,
            desired,
            authority,
            &retained_authorized,
            &retained_target,
            &retained_record,
            retained_retirement.as_ref(),
        )?;
        let ready = PrepareDeviceHandoffReady {
            retained_authorized,
            retained_target,
            retained_record,
            retained_retirement,
            attempt,
        };
        ready.assert_current(checkpoint, desired, authority)?;
        Ok(ready)
    }

    /// Classify the durable retirement receipt under the same retained
    /// attachment and target descriptors used to reopen the handoff. A
    /// current-attempt receipt prevents all process starts until its record
    /// unlink is durable and a strictly successor full admission rotates the
    /// attempt token. A direct-predecessor receipt is accepted only after that
    /// exact token-only checkpoint replacement.
    pub(crate) fn classify_retirement_state(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
        target_ready: &TargetControlAuthorizationReady,
    ) -> Result<ServingHandoffRetirementState> {
        target_ready.assert_current(stored_checkpoint)?;
        anyhow::ensure!(
            self.state_directory.path() == target_ready.retained.state_directory.path(),
            "retirement receipt classification uses another Node state directory"
        );
        let candidate = build_target_candidate(
            &self.state_directory,
            stored_checkpoint,
            acquired,
            authority,
        )?;
        anyhow::ensure!(
            target_ready.identity.artifact.attachment == candidate.target_attachment,
            "retirement receipt classification changed target authority"
        );
        ensure_no_unpublished_handoff_temp(
            &target_ready.retained.attachment_directory,
            &target_control_temp_name(&candidate.provision_transition_id),
        )?;
        let receipt_name = c_string(SERVING_HANDOFF_RETIREMENT_FILE)?;
        let Some(receipt_bytes) = read_optional_bounded(
            &target_ready.retained.attachment_directory,
            &receipt_name,
            SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
        )?
        else {
            return Ok(ServingHandoffRetirementState::None);
        };
        let receipt_path = host_path(
            &candidate
                .data_directory
                .join(SERVING_HANDOFF_RETIREMENT_FILE),
            "classified serving handoff retirement receipt path",
        )?;
        let retained_receipt = RetainedFile::open_required(
            &target_ready.retained.attachment_directory,
            SERVING_HANDOFF_RETIREMENT_FILE,
            receipt_path.clone(),
            SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
        )?;
        anyhow::ensure!(
            retained_receipt.bytes == receipt_bytes,
            "serving handoff retirement receipt changed during classification"
        );
        let receipt = decode_serving_handoff_retirement_receipt(&receipt_bytes)?;
        let state = if receipt.old_checkpoint_content_digest == *stored_checkpoint.content_digest()
            && receipt.old_checkpoint == *stored_checkpoint.checkpoint()
        {
            validate_receipt_for_current_attempt(
                &receipt,
                stored_checkpoint,
                acquired,
                &candidate,
            )?;
            ServingHandoffRetirementState::CurrentAttempt
        } else {
            validate_receipt_as_direct_predecessor(
                &receipt,
                stored_checkpoint,
                acquired,
                &candidate,
            )?;
            ServingHandoffRetirementState::DirectPredecessor
        };
        validate_receipt_target_binding(
            &receipt,
            &target_ready.identity.artifact,
            &target_ready.retained_target,
        )?;
        retained_receipt
            .assert_current(&target_ready.retained.attachment_directory, &receipt_path)?;
        target_ready.assert_current(stored_checkpoint)?;
        Ok(state)
    }

    /// Serialized pre-scan recovery for one deterministic unpublished temp.
    /// The caller retains the attachment flock through `prepared` and the
    /// current checkpoint guard through this call. A temp is never promoted:
    /// it is identity-checked, descriptor-relatively unlinked, and the parent
    /// directory is fsynced before the next fresh scan.
    pub(crate) fn discard_recoverable_temp(
        &self,
        prepared: &PreparedAuthorizedBlockd,
        stored_checkpoint: &StoredCheckpoint,
        kind: ServingHandoffTempKind,
        context: &crate::runtime_spine::RuntimePreScanRecoveryContext,
    ) -> Result<bool> {
        context.check_active()?;
        anyhow::ensure!(
            prepared.state_directory_path() == self.state_directory.path(),
            "handoff temp recovery uses another Node state directory"
        );
        let checkpoint = stored_checkpoint.checkpoint();
        let ReconcileStep::ProvisionRootImage {
            provision_transition_id,
            data_directory,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("handoff temp recovery requires provision_root_image")
        };
        let acquired = prepared.checkpoint();
        validate_authorized_blockd_checkpoint(acquired)?;
        let expected_directory = authorized_blockd_data_directory(
            self.state_directory.path(),
            &acquired.desired,
            &acquired.attachment.identity,
        );
        anyhow::ensure!(
            expected_directory == Path::new(data_directory.as_str())
                && acquired.desired.cat_id == checkpoint.cat_id,
            "handoff temp recovery changed the checkpointed attachment lineage"
        );
        let target_name = target_control_file_name(provision_transition_id);
        let target_temp = target_control_temp_name(provision_transition_id);
        let directory = prepared.retained_directory();
        validate_handoff_namespace(directory, &target_name, &target_temp)?;
        let (name, maximum) = match kind {
            ServingHandoffTempKind::TargetAuthorization => {
                (target_temp.as_str(), TARGET_AUTHORIZED_SERVING_MAX_BYTES)
            }
            ServingHandoffTempKind::Record => (
                SERVING_HANDOFF_RECORD_TEMP,
                SERVING_HANDOFF_RECORD_MAX_BYTES,
            ),
            ServingHandoffTempKind::RetirementReceipt => (
                SERVING_HANDOFF_RETIREMENT_TEMP,
                SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
            ),
        };
        let name_c = c_string(name)?;
        if read_optional_bounded(directory, &name_c, maximum)?.is_none() {
            return Ok(false);
        }
        let path = host_path(
            &expected_directory.join(name),
            "recoverable serving handoff temp path",
        )?;
        let retained = RetainedFile::open_required(directory, name, path.clone(), maximum)?;
        retained.assert_current(directory, &path)?;
        context.check_active()?;
        unlink_at(directory, &name_c).context("unlink exact unpublished handoff temp")?;
        directory
            .sync_all()
            .context("sync unpublished handoff temp removal")?;
        anyhow::ensure!(
            read_optional_bounded(directory, &name_c, maximum)?.is_none(),
            "unpublished handoff temp reappeared after recovery"
        );
        Ok(true)
    }

    /// Seal the exact target-head grant needed to recover a dead control-only
    /// process after the authority CAS has already succeeded.
    ///
    /// This does not inspect a process and cannot produce
    /// [`ServingHandoffReady`]. Consumers may use the returned path only for a
    /// target-head `control_only` start/adopt attempt.
    pub(crate) fn seal_target_control_authorization(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
    ) -> Result<TargetControlAuthorizationReady> {
        let candidate = build_target_candidate(
            &self.state_directory,
            stored_checkpoint,
            acquired,
            authority,
        )?;
        let target_name = target_control_file_name(&candidate.provision_transition_id);
        let temporary_name = target_control_temp_name(&candidate.provision_transition_id);
        let retained = RetainedAttachmentContext::open_and_lock(
            self.state_directory.clone(),
            &candidate.data_directory,
            acquired,
            &target_name,
            &temporary_name,
        )?;
        let target_artifact = target_control_artifact(stored_checkpoint, &retained, &candidate)?;
        let target_bytes = encode_target_control_authorization(&target_artifact)
            .context("encode target-head control authorization")?;
        self.persist_immutable(
            &retained.attachment_directory,
            &target_name,
            &temporary_name,
            &target_bytes,
            TARGET_AUTHORIZED_SERVING_MAX_BYTES,
            PublicationArtifact::TargetAuthorization,
        )?;
        retained.assert_current()?;
        retained
            .attachment_directory
            .sync_all()
            .with_context(|| format!("sync {}", candidate.data_directory.display()))?;
        let target_path = host_path(
            &candidate.data_directory.join(&target_name),
            "target control authorization path",
        )?;
        let retained_target = RetainedFile::open_required(
            &retained.attachment_directory,
            &target_name,
            target_path,
            TARGET_AUTHORIZED_SERVING_MAX_BYTES,
        )?;
        anyhow::ensure!(
            decode_target_control_authorization(&retained_target.bytes)? == target_artifact,
            "published target control authorization changed"
        );
        let identity = target_control_identity(&retained_target, target_artifact);
        let ready = TargetControlAuthorizationReady {
            identity,
            retained,
            retained_target,
        };
        ready.assert_current(stored_checkpoint)?;
        Ok(ready)
    }

    /// Seal the immutable handoff record after the target control process has
    /// completed its exact reload handshake.
    ///
    /// Existing exact files are replayed without replacement. A conflicting
    /// target, malformed/partial temp, unsafe entry, stale transition, wrong
    /// authority tuple, or wrong process handshake fails before a Ready proof
    /// can be returned.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "direct sealed-store entry remains a focused contract-test seam"
        )
    )]
    pub(crate) fn seal_serving_ready(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
        reloaded_process: &ExactRootProvisionProcessProof,
    ) -> Result<ServingHandoffReady> {
        let target_ready =
            self.seal_target_control_authorization(stored_checkpoint, acquired, authority)?;
        self.seal_serving_ready_from_target(
            target_ready,
            stored_checkpoint,
            acquired,
            authority,
            reloaded_process,
        )
    }

    /// Publish/replay the record while consuming the exact retained target
    /// proof used for the immediately preceding global process reinspection.
    pub(crate) fn seal_serving_ready_from_target(
        &self,
        target_ready: TargetControlAuthorizationReady,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
        reloaded_process: &ExactRootProvisionProcessProof,
    ) -> Result<ServingHandoffReady> {
        target_ready.assert_current(stored_checkpoint)?;
        let checkpoint = stored_checkpoint.checkpoint();
        let candidate = build_target_candidate(
            &self.state_directory,
            stored_checkpoint,
            acquired,
            authority,
        )?;
        let ReconcileStep::ProvisionRootImage {
            scope_id,
            control_socket_path,
            data_directory,
            process_identity_token,
            ..
        } = &checkpoint.step
        else {
            unreachable!("target candidate accepted only ProvisionRootImage")
        };
        validate_exact_process_proof(
            stored_checkpoint,
            acquired,
            &candidate,
            reloaded_process.expectation(),
        )?;
        let control_process = control_process_identity(
            reloaded_process.evidence(),
            &candidate.target_attachment,
            scope_id,
            control_socket_path,
            data_directory,
            process_identity_token,
        )?;
        anyhow::ensure!(
            target_ready.identity().artifact.attachment == candidate.target_attachment,
            "target control authorization changed between authority proof and process proof"
        );
        let record = ServingHandoffRecord {
            version: ContractVersion::V1,
            checkpoint_content_digest: stored_checkpoint.content_digest().clone(),
            cat_id: checkpoint.cat_id.clone(),
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            provision_transition_id: candidate.provision_transition_id.clone(),
            volume_id: target_ready
                .identity()
                .artifact
                .attachment
                .identity
                .volume_id
                .clone(),
            attachment_id: target_ready
                .identity()
                .artifact
                .attachment
                .identity
                .attachment_id
                .clone(),
            attachment_epoch: target_ready
                .identity()
                .artifact
                .attachment
                .identity
                .attachment_epoch,
            acquire_origin: target_ready
                .identity()
                .artifact
                .attachment
                .identity
                .acquire_origin
                .clone(),
            node_id: target_ready
                .identity()
                .artifact
                .attachment
                .identity
                .node_id
                .clone(),
            placement_epoch: target_ready
                .identity()
                .artifact
                .attachment
                .identity
                .placement_epoch,
            expected_provisioned_head: target_ready.identity().artifact.attachment.head.clone(),
            expected_control_executable_path: reloaded_process
                .expectation()
                .executable_path
                .clone(),
            target_control_authorization: target_ready.identity.clone(),
            old_control_process: control_process,
        };
        let record_bytes =
            encode_serving_handoff_record(&record).context("encode serving handoff record")?;

        validate_handoff_namespace(
            &target_ready.retained.attachment_directory,
            &target_control_file_name(&candidate.provision_transition_id),
            &target_control_temp_name(&candidate.provision_transition_id),
        )?;
        target_ready.assert_current(stored_checkpoint)?;

        anyhow::ensure!(
            decode_target_control_authorization(&target_ready.retained_target.bytes)?
                == record.target_control_authorization.artifact
                && Sha256Digest::from_bytes(
                    Sha256::digest(&target_ready.retained_target.bytes).into()
                ) == record.target_control_authorization.content_sha256,
            "target control authorization is not the exact serving handoff predecessor"
        );
        self.persist_immutable(
            &target_ready.retained.attachment_directory,
            SERVING_HANDOFF_RECORD_FILE,
            SERVING_HANDOFF_RECORD_TEMP,
            &record_bytes,
            SERVING_HANDOFF_RECORD_MAX_BYTES,
            PublicationArtifact::HandoffRecord,
        )?;

        target_ready.assert_current(stored_checkpoint)?;
        target_ready
            .retained
            .attachment_directory
            .sync_all()
            .with_context(|| format!("sync {}", candidate.data_directory.display()))?;
        let record_path = host_path(
            &candidate.data_directory.join(SERVING_HANDOFF_RECORD_FILE),
            "serving handoff record path",
        )?;
        let retained_record = RetainedFile::open_required(
            &target_ready.retained.attachment_directory,
            SERVING_HANDOFF_RECORD_FILE,
            record_path.clone(),
            SERVING_HANDOFF_RECORD_MAX_BYTES,
        )?;
        anyhow::ensure!(
            decode_serving_handoff_record(&retained_record.bytes)? == record,
            "published serving handoff record changed after its durability barrier"
        );
        let record_identity = ServingHandoffRecordIdentity {
            path: record_path,
            device: retained_record.identity.device,
            inode: retained_record.identity.inode,
            length: retained_record.identity.length,
            content_sha256: retained_record.identity.content_sha256.clone(),
        };
        let TargetControlAuthorizationReady {
            retained,
            retained_target,
            ..
        } = target_ready;
        let ready = ServingHandoffReady {
            retained,
            retained_target,
            retained_record,
            record_identity,
            record,
        };
        ready.assert_current(stored_checkpoint)?;
        Ok(ready)
    }

    /// Retire only the exact sealed record for a target-control attempt whose
    /// absence was proven twice by the current accepted full scan and the
    /// sealed physical owner. This is one bounded effect: it never rotates a
    /// token, replaces a checkpoint, starts/stops a process, or removes the
    /// stable target-control authorization.
    ///
    /// A crash after unlink but before the directory fsync is recovered by
    /// re-establishing the same fsync barrier while every authority and
    /// checkpoint binding remains exact. Callers must return
    /// `RefreshInventory`; token-only checkpoint replacement belongs to the
    /// next accepted-full effect batch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retire_record_after_exact_process_absence<P>(
        &self,
        checkpoint_store: &FileCheckpointStore,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
        executable_path: HostPath,
        process_port: &P,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> Result<ServingHandoffRetirement>
    where
        P: RootProvisionProcessRetirementPort + ?Sized,
    {
        context.check_active()?;
        let candidate = build_target_candidate(
            &self.state_directory,
            stored_checkpoint,
            acquired,
            authority,
        )?;
        let target_name = target_control_file_name(&candidate.provision_transition_id);
        let target_temp_name = target_control_temp_name(&candidate.provision_transition_id);
        let retained = RetainedAttachmentContext::open_and_lock(
            self.state_directory.clone(),
            &candidate.data_directory,
            acquired,
            &target_name,
            &target_temp_name,
        )?;
        // Lock order is attachment-directory flock, then checkpoint writer
        // mutex. This matches handoff consume and AuthorizedBlockd
        // prepare->replace. Both filesystem flocks are nonblocking, and no
        // CurrentCheckpointGuard path acquires an attachment lock, so there
        // is no reverse waiting edge.
        //
        // Hold the checkpoint writer serialization and per-Cat flock across
        // the second physical inspection, unlink, and durability barrier.
        let _current_checkpoint = checkpoint_store
            .assert_current(stored_checkpoint)
            .context("retain exact checkpoint during serving handoff retirement")?;
        retained.assert_current()?;
        let target_path = host_path(
            &candidate.data_directory.join(&target_name),
            "retained retirement target-control path",
        )?;
        anyhow::ensure!(
            read_optional_bounded(
                &retained.attachment_directory,
                &c_string(&target_temp_name)?,
                TARGET_AUTHORIZED_SERVING_MAX_BYTES,
            )?
            .is_none(),
            "retirement target-control authorization retained an unpublished temp"
        );
        let retained_target = RetainedFile::open_required(
            &retained.attachment_directory,
            &target_name,
            target_path,
            TARGET_AUTHORIZED_SERVING_MAX_BYTES,
        )?;
        let target_artifact = decode_target_control_authorization(&retained_target.bytes)?;
        validate_target_checkpoint_context(&target_artifact, stored_checkpoint)?;
        anyhow::ensure!(
            target_artifact.attachment == candidate.target_attachment,
            "retirement target-control authorization is not the exact authority target"
        );
        let target_launch = TargetControlProcessLaunchIdentity::new(
            retained_target.identity.path.clone(),
            target_artifact.provision_transition_id.clone(),
            target_artifact.provision_context_digest.clone(),
        );
        let absence = prove_exact_root_provision_process_absence(
            checkpoint_store,
            stored_checkpoint,
            RootProvisionAuthoritySnapshot {
                attachment: acquired.attachment.clone(),
                volume: &authority.volume,
            },
            executable_path,
            RootProvisionAbsencePurpose::Ordinary(Some(target_launch)),
            process_port,
            context,
        )?;
        validate_absence_for_retirement(&absence, stored_checkpoint, acquired, &candidate)?;

        let record_path = host_path(
            &candidate.data_directory.join(SERVING_HANDOFF_RECORD_FILE),
            "retired serving handoff record path",
        )?;
        let record_name = c_string(SERVING_HANDOFF_RECORD_FILE)?;
        let record_temp_name = c_string(SERVING_HANDOFF_RECORD_TEMP)?;
        let retirement_name = c_string(SERVING_HANDOFF_RETIREMENT_FILE)?;
        let retirement_temp_name = c_string(SERVING_HANDOFF_RETIREMENT_TEMP)?;
        let Some(record_bytes) = read_optional_bounded(
            &retained.attachment_directory,
            &record_name,
            SERVING_HANDOFF_RECORD_MAX_BYTES,
        )?
        else {
            // Visibility may be the result of a previously completed unlink.
            // It is recoverable only from the exact durable receipt published
            // before that unlink; absence plus an in-memory proof is not
            // durable authority after an Agent crash.
            anyhow::ensure!(
                read_optional_bounded(
                    &retained.attachment_directory,
                    &record_temp_name,
                    SERVING_HANDOFF_RECORD_MAX_BYTES,
                )?
                .is_none(),
                "absent serving handoff record retained an unpublished temp"
            );
            anyhow::ensure!(
                read_optional_bounded(
                    &retained.attachment_directory,
                    &retirement_temp_name,
                    SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
                )?
                .is_none(),
                "absent serving handoff record retained an unpublished retirement receipt"
            );
            let receipt_bytes = read_optional_bounded(
                &retained.attachment_directory,
                &retirement_name,
                SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
            )?
            .context("absent serving handoff record lacks its durable retirement receipt")?;
            let receipt = decode_serving_handoff_retirement_receipt(&receipt_bytes)?;
            validate_receipt_for_current_attempt(
                &receipt,
                stored_checkpoint,
                acquired,
                &candidate,
            )?;
            validate_receipt_target_binding(&receipt, &target_artifact, &retained_target)?;
            self.maybe_crash(PublicationStage::new(
                PublicationArtifact::HandoffRetirement,
                PublicationPoint::BeforeDirectorySync,
            ))?;
            context.check_active()?;
            retained.attachment_directory.sync_all().with_context(|| {
                format!(
                    "sync retired handoff in {}",
                    candidate.data_directory.display()
                )
            })?;
            self.maybe_crash(PublicationStage::new(
                PublicationArtifact::HandoffRetirement,
                PublicationPoint::DirectorySynced,
            ))?;
            retained.assert_current()?;
            retained_target.assert_current(
                &retained.attachment_directory,
                &retained_target.identity.path,
            )?;
            return Ok(ServingHandoffRetirement::RecoveredAlreadyAbsent);
        };
        anyhow::ensure!(
            read_optional_bounded(
                &retained.attachment_directory,
                &record_temp_name,
                SERVING_HANDOFF_RECORD_MAX_BYTES,
            )?
            .is_none(),
            "sealed serving handoff record retained an unpublished temp"
        );
        let record = decode_serving_handoff_record(&record_bytes)?;
        validate_record_checkpoint_context(&record, stored_checkpoint)?;
        validate_record_absence_binding(&record, &absence)?;
        anyhow::ensure!(
            record.target_control_authorization.artifact == target_artifact
                && record.target_control_authorization.device == retained_target.identity.device
                && record.target_control_authorization.inode == retained_target.identity.inode
                && record.target_control_authorization.length == retained_target.identity.length
                && record.target_control_authorization.content_sha256
                    == retained_target.identity.content_sha256,
            "retired record is not bound to the retained target-control authorization"
        );
        let retained_record = RetainedFile::open_required(
            &retained.attachment_directory,
            SERVING_HANDOFF_RECORD_FILE,
            record_path.clone(),
            SERVING_HANDOFF_RECORD_MAX_BYTES,
        )?;
        anyhow::ensure!(
            retained_record.bytes == record_bytes,
            "serving handoff record changed between classification and retirement"
        );
        retained_record.assert_current(&retained.attachment_directory, &record_path)?;
        let record_identity = ServingHandoffRecordIdentity {
            path: record_path.clone(),
            device: retained_record.identity.device,
            inode: retained_record.identity.inode,
            length: retained_record.identity.length,
            content_sha256: retained_record.identity.content_sha256.clone(),
        };
        let receipt =
            retirement_receipt(stored_checkpoint, record.clone(), record_identity, &absence)?;
        let receipt_bytes = encode_serving_handoff_retirement_receipt(&receipt)?;
        self.persist_retirement_receipt(
            &retained.attachment_directory,
            &receipt_bytes,
            stored_checkpoint,
            acquired,
            &candidate,
        )?;
        self.maybe_crash(PublicationStage::new(
            PublicationArtifact::HandoffRetirement,
            PublicationPoint::BeforeUnlink,
        ))?;
        // The protected directory and held flock exclude legitimate writers;
        // the final retained-path check rejects rename/recreate ABA before the
        // descriptor-relative unlink.
        retained_target.assert_current(
            &retained.attachment_directory,
            &retained_target.identity.path,
        )?;
        retained_record.assert_current(&retained.attachment_directory, &record_path)?;
        context.check_active()?;
        unlink_at(&retained.attachment_directory, &record_name)
            .context("unlink exact sealed serving handoff record")?;
        self.maybe_crash(PublicationStage::new(
            PublicationArtifact::HandoffRetirement,
            PublicationPoint::Unlinked,
        ))?;
        retained.attachment_directory.sync_all().with_context(|| {
            format!(
                "sync retired handoff in {}",
                candidate.data_directory.display()
            )
        })?;
        self.maybe_crash(PublicationStage::new(
            PublicationArtifact::HandoffRetirement,
            PublicationPoint::DirectorySynced,
        ))?;
        retained.assert_current()?;
        retained_target.assert_current(
            &retained.attachment_directory,
            &retained_target.identity.path,
        )?;
        anyhow::ensure!(
            read_optional_bounded(
                &retained.attachment_directory,
                &record_name,
                SERVING_HANDOFF_RECORD_MAX_BYTES,
            )?
            .is_none(),
            "serving handoff record reappeared after retirement"
        );
        Ok(ServingHandoffRetirement::Retired)
    }

    /// In a later accepted-full batch, rotate only the process-attempt token
    /// after exact retirement is durable. Scope, sockets, data lineage,
    /// provision transition, target authorization context, and every other
    /// checkpoint field remain stable (apart from the timestamp).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rotate_process_token_after_retirement<P>(
        &self,
        checkpoint_store: &FileCheckpointStore,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
        executable_path: HostPath,
        new_process_identity_token: RandomId128,
        updated_at_unix_ms: cats_api::runtime_reconciliation::UnixMillis,
        process_port: &P,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> Result<StoredCheckpoint>
    where
        P: RootProvisionProcessRetirementPort + ?Sized,
    {
        context.check_active()?;
        let candidate = build_target_candidate(
            &self.state_directory,
            stored_checkpoint,
            acquired,
            authority,
        )?;
        let target_name = target_control_file_name(&candidate.provision_transition_id);
        let target_temp_name = target_control_temp_name(&candidate.provision_transition_id);
        let retained = RetainedAttachmentContext::open_and_lock(
            self.state_directory.clone(),
            &candidate.data_directory,
            acquired,
            &target_name,
            &target_temp_name,
        )?;
        retained.assert_current()?;
        let target_path = host_path(
            &candidate.data_directory.join(&target_name),
            "rotation target-control authorization path",
        )?;
        anyhow::ensure!(
            read_optional_bounded(
                &retained.attachment_directory,
                &c_string(&target_temp_name)?,
                TARGET_AUTHORIZED_SERVING_MAX_BYTES,
            )?
            .is_none(),
            "token rotation target-control authorization retained an unpublished temp"
        );
        let retained_target = RetainedFile::open_required(
            &retained.attachment_directory,
            &target_name,
            target_path,
            TARGET_AUTHORIZED_SERVING_MAX_BYTES,
        )?;
        let target_artifact = decode_target_control_authorization(&retained_target.bytes)?;
        validate_target_checkpoint_context(&target_artifact, stored_checkpoint)?;
        anyhow::ensure!(
            target_artifact.attachment == candidate.target_attachment,
            "token rotation target-control authorization is not the exact authority target"
        );
        let target_launch = TargetControlProcessLaunchIdentity::new(
            retained_target.identity.path.clone(),
            target_artifact.provision_transition_id.clone(),
            target_artifact.provision_context_digest.clone(),
        );
        let absence = prove_exact_root_provision_process_absence(
            checkpoint_store,
            stored_checkpoint,
            RootProvisionAuthoritySnapshot {
                attachment: acquired.attachment.clone(),
                volume: &authority.volume,
            },
            executable_path,
            RootProvisionAbsencePurpose::Ordinary(Some(target_launch)),
            process_port,
            context,
        )?;
        validate_absence_for_retirement(&absence, stored_checkpoint, acquired, &candidate)?;
        for (name, label, maximum) in [
            (
                SERVING_HANDOFF_RECORD_FILE,
                "sealed serving handoff record",
                SERVING_HANDOFF_RECORD_MAX_BYTES,
            ),
            (
                SERVING_HANDOFF_RECORD_TEMP,
                "serving handoff record temp",
                SERVING_HANDOFF_RECORD_MAX_BYTES,
            ),
        ] {
            anyhow::ensure!(
                read_optional_bounded(&retained.attachment_directory, &c_string(name)?, maximum,)?
                    .is_none(),
                "cannot rotate process token while {label} remains"
            );
        }
        anyhow::ensure!(
            read_optional_bounded(
                &retained.attachment_directory,
                &c_string(SERVING_HANDOFF_RETIREMENT_TEMP)?,
                SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
            )?
            .is_none(),
            "token rotation found an unpublished retirement receipt"
        );
        let receipt_path = host_path(
            &candidate
                .data_directory
                .join(SERVING_HANDOFF_RETIREMENT_FILE),
            "rotation retirement receipt path",
        )?;
        let retained_receipt = RetainedFile::open_required(
            &retained.attachment_directory,
            SERVING_HANDOFF_RETIREMENT_FILE,
            receipt_path,
            SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
        )?;
        let receipt = decode_serving_handoff_retirement_receipt(&retained_receipt.bytes)?;
        validate_receipt_for_current_attempt(&receipt, stored_checkpoint, acquired, &candidate)?;
        accepted_full_strictly_succeeds_retirement(&receipt, &absence)?;
        validate_receipt_target_binding(&receipt, &target_artifact, &retained_target)?;

        let mut successor = stored_checkpoint.checkpoint().clone();
        let ReconcileStep::ProvisionRootImage {
            process_identity_token,
            ..
        } = &mut successor.step
        else {
            unreachable!("target candidate accepted only provision_root_image")
        };
        anyhow::ensure!(
            *process_identity_token != new_process_identity_token,
            "root-process token rotation requires a fresh token"
        );
        anyhow::ensure!(
            updated_at_unix_ms > successor.updated_at_unix_ms,
            "root-process token rotation timestamp must advance"
        );
        *process_identity_token = new_process_identity_token;
        successor.updated_at_unix_ms = updated_at_unix_ms;
        encode_runtime_checkpoint(&successor)
            .context("validate token-only successor checkpoint")?;
        anyhow::ensure!(
            provision_root_authorization_context_digest(&successor)?
                == target_artifact.provision_context_digest
                && provision_root_image_request(&successor)? == target_artifact.request,
            "process token rotation changed the stable target-control authorization context"
        );
        // A crash after unlink but before the retirement directory fsync can
        // reopen with an absent record and the already durable receipt. The
        // strictly successor full admission above is the only authority to
        // continue; re-establish the unlink durability barrier before the
        // token-only checkpoint replacement makes a new attempt possible.
        retained
            .attachment_directory
            .sync_all()
            .context("sync retired handoff before process-token rotation")?;
        retained_target.assert_current(
            &retained.attachment_directory,
            &retained_target.identity.path,
        )?;
        retained_receipt.assert_current(
            &retained.attachment_directory,
            &retained_receipt.identity.path,
        )?;
        context.check_active()?;
        let replaced = checkpoint_store
            .replace(stored_checkpoint, &successor)
            .context("persist token-only root-process attempt rotation")?;
        retained.assert_current()?;
        retained_target.assert_current(
            &retained.attachment_directory,
            &retained_target.identity.path,
        )?;
        retained_receipt.assert_current(
            &retained.attachment_directory,
            &retained_receipt.identity.path,
        )?;
        Ok(replaced)
    }

    fn persist_retirement_receipt(
        &self,
        directory: &File,
        expected: &[u8],
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        candidate: &TargetControlCandidate,
    ) -> Result<()> {
        let target = c_string(SERVING_HANDOFF_RETIREMENT_FILE)?;
        if let Some(current) =
            read_optional_bounded(directory, &target, SERVING_HANDOFF_RETIREMENT_MAX_BYTES)?
        {
            if current == expected {
                return self.persist_immutable(
                    directory,
                    SERVING_HANDOFF_RETIREMENT_FILE,
                    SERVING_HANDOFF_RETIREMENT_TEMP,
                    expected,
                    SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
                    PublicationArtifact::HandoffRetirementReceipt,
                );
            }
            let previous = decode_serving_handoff_retirement_receipt(&current)?;
            validate_receipt_as_direct_predecessor(
                &previous,
                stored_checkpoint,
                acquired,
                candidate,
            )?;
            let path = host_path(
                &candidate
                    .data_directory
                    .join(SERVING_HANDOFF_RETIREMENT_FILE),
                "previous retirement receipt path",
            )?;
            let retained = RetainedFile::open_required(
                directory,
                SERVING_HANDOFF_RETIREMENT_FILE,
                path.clone(),
                SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
            )?;
            anyhow::ensure!(
                retained.bytes == current,
                "previous retirement receipt changed before replacement"
            );
            retained.assert_current(directory, &path)?;
            self.maybe_crash(PublicationStage::new(
                PublicationArtifact::HandoffRetirementReceipt,
                PublicationPoint::BeforeUnlink,
            ))?;
            unlink_at(directory, &target)
                .context("unlink direct-predecessor retirement receipt")?;
            directory
                .sync_all()
                .context("sync direct-predecessor retirement receipt removal")?;
        }
        self.persist_immutable(
            directory,
            SERVING_HANDOFF_RETIREMENT_FILE,
            SERVING_HANDOFF_RETIREMENT_TEMP,
            expected,
            SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
            PublicationArtifact::HandoffRetirementReceipt,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_immutable(
        &self,
        directory: &File,
        target_name: &str,
        temporary_name: &str,
        expected: &[u8],
        maximum: usize,
        artifact: PublicationArtifact,
    ) -> Result<()> {
        let target = c_string(target_name)?;
        let temporary = c_string(temporary_name)?;
        if let Some(current) = read_optional_bounded(directory, &target, maximum)? {
            anyhow::ensure!(
                current == expected,
                "serving handoff target {target_name} conflicts with the sealed value"
            );
            if read_optional_bounded(directory, &temporary, maximum)?.is_some() {
                // A safe deterministic staging file is never authoritative.
                // Once the exact no-replace target exists, discard any such
                // pre-fsync/partial residue without touching the target.
                unlink_at(directory, &temporary)
                    .with_context(|| format!("remove replay temp {temporary_name}"))?;
            }
            // Re-establish a durability barrier after a lost acknowledgement.
            directory
                .sync_all()
                .with_context(|| format!("sync exact replay {target_name}"))?;
            return Ok(());
        }

        if read_optional_bounded(directory, &temporary, maximum)?.is_some() {
            // With the target absent, exact checkpoint/authority/acquire
            // inputs and the directory flock make a safe regular single-link
            // deterministic temp an unpublished Node attempt. Never adopt its
            // unknown durability: unlink, fsync the removal, then rewrite.
            unlink_at(directory, &temporary)
                .with_context(|| format!("remove exact unpublished temp {temporary_name}"))?;
            directory
                .sync_all()
                .with_context(|| format!("sync removal of {temporary_name}"))?;
        }

        let mut file = open_at(
            directory,
            &temporary,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
        .with_context(|| format!("create serving handoff temp {temporary_name}"))?;
        verify_regular_file(&file, temporary_name, Some(0))?;
        self.maybe_crash(PublicationStage::new(artifact, PublicationPoint::Created))?;
        let split = expected.len().div_ceil(2);
        file.write_all(&expected[..split])
            .with_context(|| format!("partially write serving handoff temp {temporary_name}"))?;
        self.maybe_crash(PublicationStage::new(
            artifact,
            PublicationPoint::PartialWritten,
        ))?;
        file.write_all(&expected[split..])
            .with_context(|| format!("finish serving handoff temp {temporary_name}"))?;
        self.maybe_crash(PublicationStage::new(
            artifact,
            PublicationPoint::FullWritten,
        ))?;
        file.sync_all()
            .with_context(|| format!("sync serving handoff temp {temporary_name}"))?;
        verify_regular_file(&file, temporary_name, Some(expected.len() as u64))?;
        self.maybe_crash(PublicationStage::new(
            artifact,
            PublicationPoint::TempSynced,
        ))?;

        rename_no_replace(directory, &temporary, directory, &target)
            .with_context(|| format!("publish no-replace serving handoff {target_name}"))?;
        let published_identity = FileIdentity::from_metadata(
            &file
                .metadata()
                .with_context(|| format!("inspect published serving handoff {target_name}"))?,
        );
        self.maybe_crash(PublicationStage::new(artifact, PublicationPoint::Published))?;
        directory
            .sync_all()
            .with_context(|| format!("sync published serving handoff {target_name}"))?;
        self.maybe_crash(PublicationStage::new(
            artifact,
            PublicationPoint::DirectorySynced,
        ))?;

        verify_regular_file(&file, target_name, Some(expected.len() as u64))?;
        anyhow::ensure!(
            FileIdentity::from_metadata(
                &file
                    .metadata()
                    .with_context(|| format!("reinspect published handoff {target_name}"))?,
            ) == published_identity,
            "published serving handoff {target_name} changed through its retained descriptor"
        );
        let visible_file = open_at(
            directory,
            &target,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
        .with_context(|| format!("reopen published serving handoff {target_name}"))?;
        verify_regular_file(&visible_file, target_name, Some(expected.len() as u64))?;
        anyhow::ensure!(
            FileIdentity::from_metadata(
                &visible_file
                    .metadata()
                    .with_context(|| format!("inspect visible handoff {target_name}"))?,
            ) == published_identity,
            "published serving handoff {target_name} was replaced at its durability barrier"
        );
        let visible = read_required_bounded(directory, target_name, maximum)?;
        anyhow::ensure!(
            visible == expected,
            "published serving handoff {target_name} changed"
        );
        anyhow::ensure!(
            read_optional_bounded(directory, &temporary, maximum)?.is_none(),
            "published serving handoff {target_name} retained a temp entry"
        );
        Ok(())
    }

    #[cfg(not(test))]
    fn maybe_crash(&self, _stage: PublicationStage) -> Result<()> {
        Ok(())
    }

    #[cfg(test)]
    fn maybe_crash(&self, stage: PublicationStage) -> Result<()> {
        let mutation = {
            let mut pending = self.mutation_once.lock().expect("handoff mutation lock");
            if pending.as_ref().is_some_and(|(at, _)| *at == stage) {
                pending.take().map(|(_, mutation)| mutation)
            } else {
                None
            }
        };
        if let Some(mutation) = mutation {
            mutation();
        }
        let mut crash = self.crash_once.lock().expect("handoff fault lock");
        if crash.as_ref() == Some(&stage) {
            *crash = None;
            anyhow::bail!("injected serving handoff publication crash at {stage:?}")
        }
        Ok(())
    }

    #[cfg(test)]
    fn inject_crash_once(&self, stage: PublicationStage) {
        *self.crash_once.lock().expect("handoff fault lock") = Some(stage);
    }

    #[cfg(test)]
    fn inject_mutation_once(
        &self,
        stage: PublicationStage,
        mutation: impl FnOnce() + Send + 'static,
    ) {
        *self.mutation_once.lock().expect("handoff mutation lock") =
            Some((stage, Box::new(mutation)));
    }
}

struct TargetControlCandidate {
    data_directory: PathBuf,
    provision_transition_id: RandomId128,
    target_attachment: AuthorizedServingAttachment,
}

fn build_target_candidate(
    state_directory: &StateDirectory,
    stored_checkpoint: &StoredCheckpoint,
    acquired: &AuthorizedBlockdCheckpoint,
    authority: &ServingAuthorityTargetEvidence,
) -> Result<TargetControlCandidate> {
    let checkpoint = stored_checkpoint.checkpoint();
    encode_runtime_checkpoint(checkpoint).context("validate current Runtime checkpoint")?;
    validate_authorized_blockd_checkpoint(acquired)
        .context("validate acquire-time authorized blockd checkpoint")?;
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
        anyhow::bail!("serving handoff requires the current provision_root_image step")
    };
    let desired = &acquired.desired;
    let volume = &acquired.volume;
    let blank_attachment = &acquired.attachment;
    let identity = &blank_attachment.identity;
    let deterministic_directory =
        authorized_blockd_data_directory(state_directory.path(), desired, identity);
    let deterministic_host_path = host_path(
        &deterministic_directory,
        "deterministic authorized blockd data directory",
    )?;

    anyhow::ensure!(
        checkpoint.version == ContractVersion::V1
            && checkpoint.cat_id == desired.cat_id
            && checkpoint.node_id == desired.placement.node_id
            && checkpoint.placement_epoch == desired.placement.placement_epoch
            && checkpoint.desired_revision == desired.desired_revision
            && checkpoint.spec_digest == desired.spec_digest
            && checkpoint.runtime_incarnation.is_none()
            && checkpoint.stable_state.is_none(),
        "serving handoff checkpoint top level is not the exact acquired Desired"
    );
    anyhow::ensure!(
        volume_id == &volume.volume_id
            && attachment_id == &identity.attachment_id
            && *attachment_epoch == identity.attachment_epoch
            && *size_bytes == volume.size_bytes
            && boot_image_digest == &desired.runtime.boot_image_digest
            && data_directory == &deterministic_host_path,
        "serving handoff provision step is not the exact acquired root lineage"
    );
    let Some((_, blank_acquire_result)) = blank_attachment.normal_acquire() else {
        anyhow::bail!("root provisioning requires an exact Normal acquire predecessor")
    };
    anyhow::ensure!(
        blank_attachment.head == *expected_blank_head
            && blank_acquire_result.resulting_head == *expected_blank_head
            && exact_blank_head(expected_blank_head),
        "serving handoff acquire-time grant is not the exact blank predecessor"
    );
    anyhow::ensure!(
        expected_provisioned_head.generation.get() == 1
            && expected_provisioned_head.root_hash.is_some()
            && expected_provisioned_head.root_object_id.is_some(),
        "serving handoff target is not an exact generation-one head"
    );
    anyhow::ensure!(
        authority.provision_transition_id == *provision_transition_id,
        "serving handoff authority reread belongs to another provision transition"
    );

    let mut target_attachment = blank_attachment.clone();
    target_attachment.head = expected_provisioned_head.clone();
    validate_target_control_attachment(&target_attachment)
        .map_err(|error| anyhow::anyhow!(error))?;
    validate_authorized_serving_record(&authority.volume, &target_attachment, None)
        .map_err(|error| anyhow::anyhow!("serving authority target tuple is not exact: {error}"))?;
    let _ = (scope_id, control_socket_path, process_identity_token);
    Ok(TargetControlCandidate {
        data_directory: deterministic_directory,
        provision_transition_id: provision_transition_id.clone(),
        target_attachment,
    })
}

fn target_control_artifact(
    stored_checkpoint: &StoredCheckpoint,
    retained: &RetainedAttachmentContext,
    candidate: &TargetControlCandidate,
) -> Result<TargetControlAuthorizationArtifact> {
    let ReconcileStep::ProvisionRootImage {
        scope_id,
        control_socket_path,
        ..
    } = &stored_checkpoint.checkpoint().step
    else {
        anyhow::bail!("target-control artifact requires provision_root_image")
    };
    Ok(TargetControlAuthorizationArtifact {
        version: ContractVersion::V1,
        provision_transition_id: candidate.provision_transition_id.clone(),
        request: provision_root_image_request(stored_checkpoint.checkpoint())?,
        provision_context_digest: provision_root_authorization_context_digest(
            stored_checkpoint.checkpoint(),
        )?,
        runtime_scope_id: scope_id.clone(),
        control_socket_path: control_socket_path.clone(),
        local_state: retained.local_state.clone(),
        attachment: candidate.target_attachment.clone(),
    })
}

fn target_control_identity(
    retained: &RetainedFile,
    artifact: TargetControlAuthorizationArtifact,
) -> TargetControlAuthorizationIdentity {
    TargetControlAuthorizationIdentity {
        path: retained.identity.path.clone(),
        device: retained.identity.device,
        inode: retained.identity.inode,
        length: retained.identity.length,
        content_sha256: retained.identity.content_sha256.clone(),
        artifact,
    }
}

fn validate_exact_process_proof(
    stored_checkpoint: &StoredCheckpoint,
    acquired: &AuthorizedBlockdCheckpoint,
    candidate: &TargetControlCandidate,
    expected: &RootProvisionProcessExpectation,
) -> Result<()> {
    let checkpoint = stored_checkpoint.checkpoint();
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
        expected_provisioned_head,
        ..
    } = &checkpoint.step
    else {
        anyhow::bail!("serving process proof requires provision_root_image")
    };
    anyhow::ensure!(
        expected.cat_id == checkpoint.cat_id
            && expected.node_id == checkpoint.node_id
            && expected.placement_epoch == checkpoint.placement_epoch
            && expected.desired_revision == checkpoint.desired_revision
            && expected.spec_digest == checkpoint.spec_digest
            && expected.provision_transition_id == *provision_transition_id
            && expected.volume_id == *volume_id
            && expected.attachment_id == *attachment_id
            && expected.attachment_epoch == *attachment_epoch
            && expected.scope_id == *scope_id
            && expected.control_socket_path == *control_socket_path
            && expected.data_directory == *data_directory
            && expected.process_identity_token == *process_identity_token
            && expected.size_bytes == *size_bytes
            && expected.boot_image_digest == *boot_image_digest
            && expected.attachment == acquired.attachment
            && expected.expected_remote_head() == expected_provisioned_head
            && expected.expected_remote_head() == &candidate.target_attachment.head,
        "exact process proof is not bound to the current stored provision checkpoint"
    );
    Ok(())
}

fn validate_absence_for_retirement(
    absence: &ExactRootProvisionProcessAbsenceProof,
    stored_checkpoint: &StoredCheckpoint,
    acquired: &AuthorizedBlockdCheckpoint,
    candidate: &TargetControlCandidate,
) -> Result<()> {
    anyhow::ensure!(
        absence.checkpoint_content_digest() == stored_checkpoint.content_digest(),
        "root-process absence proof belongs to another checkpoint content"
    );
    validate_exact_process_proof(
        stored_checkpoint,
        acquired,
        candidate,
        absence.expectation(),
    )
}

fn validate_record_absence_binding(
    record: &ServingHandoffRecord,
    absence: &ExactRootProvisionProcessAbsenceProof,
) -> Result<()> {
    let expected = absence.expectation();
    let process = &record.old_control_process;
    anyhow::ensure!(
        record.checkpoint_content_digest == *absence.checkpoint_content_digest()
            && record.cat_id == expected.cat_id
            && record.node_id == expected.node_id
            && record.placement_epoch == expected.placement_epoch
            && record.desired_revision == expected.desired_revision
            && record.spec_digest == expected.spec_digest
            && record.provision_transition_id == expected.provision_transition_id
            && record.volume_id == expected.volume_id
            && record.attachment_id == expected.attachment_id
            && record.attachment_epoch == expected.attachment_epoch
            && record.expected_provisioned_head == *expected.expected_remote_head()
            && record.expected_control_executable_path == expected.executable_path
            && process.scope_id == expected.scope_id
            && process.cgroup_path == expected.cgroup_path
            && process.control_socket_path == expected.control_socket_path
            && process.data_directory == expected.data_directory
            && process.ownership_token == expected.process_identity_token
            && process.handshake.identity == expected.attachment.identity
            && process.handshake.size_bytes == expected.size_bytes
            && process.handshake.durability == expected.attachment.durability
            && process.handshake.remote_head == *expected.expected_remote_head()
            && process.handshake.process_identity_token == expected.process_identity_token
            && process.handshake.control_only
            && !process.handshake.guest_io_enabled,
        "serving handoff record does not describe the exactly absent process attempt"
    );
    Ok(())
}

fn retirement_receipt(
    stored_checkpoint: &StoredCheckpoint,
    record: ServingHandoffRecord,
    record_identity: ServingHandoffRecordIdentity,
    absence: &ExactRootProvisionProcessAbsenceProof,
) -> Result<ServingHandoffRetirementReceipt> {
    validate_record_absence_binding(&record, absence)?;
    let admission = absence.admission();
    let receipt = ServingHandoffRetirementReceipt {
        version: ContractVersion::V1,
        old_checkpoint_content_digest: stored_checkpoint.content_digest().clone(),
        old_checkpoint: stored_checkpoint.checkpoint().clone(),
        old_process_identity_token: absence.expectation().process_identity_token.clone(),
        record_identity,
        record,
        admission: ServingHandoffRetirementAdmission {
            node_boot_id: admission.node_boot_id.clone(),
            agent_instance_id: admission.agent_instance_id.clone(),
            agent_session_epoch: admission.agent_session_epoch,
            inventory_epoch: admission.inventory_epoch,
            inventory_digest: admission.inventory_digest.clone(),
            inventory_read_position: admission.inventory_read_position,
        },
    };
    validate_retirement_receipt(&receipt).map_err(anyhow::Error::from)?;
    Ok(receipt)
}

fn validate_receipt_for_current_attempt(
    receipt: &ServingHandoffRetirementReceipt,
    stored_checkpoint: &StoredCheckpoint,
    acquired: &AuthorizedBlockdCheckpoint,
    candidate: &TargetControlCandidate,
) -> Result<()> {
    validate_retirement_receipt(receipt).map_err(anyhow::Error::from)?;
    anyhow::ensure!(
        receipt.old_checkpoint_content_digest == *stored_checkpoint.content_digest(),
        "serving handoff retirement receipt belongs to another checkpoint attempt"
    );
    validate_record_checkpoint_context(&receipt.record, stored_checkpoint)?;
    anyhow::ensure!(
        receipt
            .record
            .target_control_authorization
            .artifact
            .attachment
            == candidate.target_attachment
            && receipt
                .record
                .target_control_authorization
                .artifact
                .attachment
                .identity
                == acquired.attachment.identity
            && receipt.old_process_identity_token
                == receipt.record.old_control_process.ownership_token,
        "serving handoff retirement receipt changed its authority or old process token"
    );
    Ok(())
}

fn validate_receipt_target_binding(
    receipt: &ServingHandoffRetirementReceipt,
    target_artifact: &TargetControlAuthorizationArtifact,
    retained_target: &RetainedFile,
) -> Result<()> {
    let identity = &receipt.record.target_control_authorization;
    anyhow::ensure!(
        identity.artifact == *target_artifact
            && identity.device == retained_target.identity.device
            && identity.inode == retained_target.identity.inode
            && identity.length == retained_target.identity.length
            && identity.content_sha256 == retained_target.identity.content_sha256,
        "retirement receipt is not bound to the retained target-control authorization"
    );
    Ok(())
}

fn validate_receipt_as_direct_predecessor(
    receipt: &ServingHandoffRetirementReceipt,
    stored_checkpoint: &StoredCheckpoint,
    acquired: &AuthorizedBlockdCheckpoint,
    candidate: &TargetControlCandidate,
) -> Result<()> {
    validate_retirement_receipt(receipt).map_err(anyhow::Error::from)?;
    let current = stored_checkpoint.checkpoint();
    let mut expected_successor = receipt.old_checkpoint.clone();
    let ReconcileStep::ProvisionRootImage {
        process_identity_token: old_token,
        ..
    } = &mut expected_successor.step
    else {
        anyhow::bail!("retirement receipt predecessor is not provision_root_image")
    };
    let ReconcileStep::ProvisionRootImage {
        process_identity_token: current_token,
        ..
    } = &current.step
    else {
        anyhow::bail!("retirement receipt successor is not provision_root_image")
    };
    anyhow::ensure!(
        *old_token != *current_token,
        "retirement receipt replacement requires a distinct process attempt"
    );
    *old_token = current_token.clone();
    expected_successor.updated_at_unix_ms = current.updated_at_unix_ms;
    anyhow::ensure!(
        expected_successor == *current
            && receipt.old_checkpoint_content_digest != *stored_checkpoint.content_digest()
            && receipt
                .record
                .target_control_authorization
                .artifact
                .attachment
                == candidate.target_attachment
            && receipt
                .record
                .target_control_authorization
                .artifact
                .attachment
                .identity
                == acquired.attachment.identity,
        "existing retirement receipt is not the exact token-only checkpoint predecessor"
    );
    Ok(())
}

fn accepted_full_strictly_succeeds_retirement(
    receipt: &ServingHandoffRetirementReceipt,
    absence: &ExactRootProvisionProcessAbsenceProof,
) -> Result<()> {
    let old = &receipt.admission;
    let new = absence.admission();
    let session_advances = new.agent_session_epoch > old.agent_session_epoch;
    let same_session_advances = new.agent_session_epoch == old.agent_session_epoch
        && new.node_boot_id == old.node_boot_id
        && new.agent_instance_id == old.agent_instance_id
        && new.inventory_epoch > old.inventory_epoch;
    anyhow::ensure!(
        (session_advances || same_session_advances)
            && new.inventory_read_position > old.inventory_read_position,
        "process token rotation requires a strictly successor full-inventory admission"
    );
    Ok(())
}

fn control_process_identity(
    evidence: &RootProvisionProcessEvidence,
    target: &AuthorizedServingAttachment,
    scope_id: &Id,
    control_socket_path: &HostPath,
    data_directory: &HostPath,
    process_identity_token: &RandomId128,
) -> Result<ServingControlProcessIdentity> {
    let expected_cgroup =
        HostPath::new(format!("/sys/fs/cgroup/system.slice/{}", scope_id.as_str()))
            .context("serving handoff scope does not form a canonical cgroup path")?;
    let RootProvisionBlockdHandshake {
        peer_process_id,
        identity,
        size_bytes,
        durability,
        remote_head,
        process_identity_token: handshake_token,
        control_only,
        guest_io_enabled,
    } = &evidence.handshake;
    anyhow::ensure!(
        evidence.process_id > 0
            && evidence.unit_main_process_id == evidence.process_id
            && evidence.process_start_time_ticks.get() > 0
            && evidence.cgroup_process_ids == [evidence.process_id]
            && evidence.scope_id == *scope_id
            && evidence.cgroup_path == expected_cgroup
            && evidence.control_socket_path == *control_socket_path
            && evidence.data_directory == *data_directory
            && evidence.ownership_token == *process_identity_token
            && *peer_process_id == evidence.process_id
            && identity == &target.identity
            && *size_bytes == target.size_bytes
            && *durability == target.durability
            && remote_head == &target.head
            && handshake_token == process_identity_token
            && *control_only
            && !*guest_io_enabled,
        "old control process did not reload and handshake the exact target lineage"
    );
    let process_id = wire_pid(evidence.process_id)?;
    Ok(ServingControlProcessIdentity {
        process_id,
        unit_main_process_id: wire_pid(evidence.unit_main_process_id)?,
        process_start_time_ticks: evidence.process_start_time_ticks,
        executable_path: evidence.executable_path.clone(),
        scope_id: evidence.scope_id.clone(),
        cgroup_path: evidence.cgroup_path.clone(),
        cgroup_process_ids: evidence
            .cgroup_process_ids
            .iter()
            .copied()
            .map(wire_pid)
            .collect::<Result<Vec<_>>>()?,
        control_socket_path: evidence.control_socket_path.clone(),
        data_directory: evidence.data_directory.clone(),
        ownership_token: evidence.ownership_token.clone(),
        handshake: ServingControlReloadHandshake {
            peer_process_id: wire_pid(*peer_process_id)?,
            identity: identity.clone(),
            size_bytes: *size_bytes,
            durability: *durability,
            remote_head: remote_head.clone(),
            process_identity_token: handshake_token.clone(),
            control_only: *control_only,
            guest_io_enabled: *guest_io_enabled,
        },
    })
}

fn wire_pid(process_id: u32) -> Result<WireU64> {
    anyhow::ensure!(
        process_id > 0,
        "serving handoff process ID must be positive"
    );
    WireU64::new(u64::from(process_id)).context("serving handoff process ID exceeds wire range")
}

fn validate_retirement_receipt(
    receipt: &ServingHandoffRetirementReceipt,
) -> std::result::Result<(), ServingHandoffCodecError> {
    validate_serving_handoff_record(&receipt.record)?;
    let record_bytes = encode_serving_handoff_record(&receipt.record)?;
    let record_digest = Sha256Digest::from_bytes(Sha256::digest(&record_bytes).into());
    let checkpoint_digest = checkpoint_content_digest(&receipt.old_checkpoint).map_err(|_| {
        ServingHandoffCodecError::Invalid {
            artifact: "retirement receipt",
            reason: "old checkpoint is not a valid Runtime checkpoint",
        }
    })?;
    let record_path = Path::new(receipt.record_identity.path.as_str());
    let process = &receipt.record.old_control_process;
    let old_checkpoint_token = match &receipt.old_checkpoint.step {
        ReconcileStep::ProvisionRootImage {
            process_identity_token,
            ..
        } => Some(process_identity_token),
        _ => None,
    };
    if receipt.version != ContractVersion::V1
        || receipt.old_checkpoint_content_digest != receipt.record.checkpoint_content_digest
        || receipt.old_checkpoint_content_digest != checkpoint_digest
        || receipt.old_checkpoint.version != receipt.version
        || old_checkpoint_token != Some(&receipt.old_process_identity_token)
        || receipt.old_process_identity_token != process.ownership_token
        || receipt.old_process_identity_token != process.handshake.process_identity_token
        || record_path.file_name().and_then(|name| name.to_str())
            != Some(SERVING_HANDOFF_RECORD_FILE)
        || receipt.record_identity.device.get() == 0
        || receipt.record_identity.inode.get() == 0
        || usize::try_from(receipt.record_identity.length.get()).ok() != Some(record_bytes.len())
        || receipt.record_identity.content_sha256 != record_digest
        || receipt.admission.agent_session_epoch.get() == 0
        || receipt.admission.inventory_epoch.get() == 0
        || receipt.admission.inventory_read_position.get() == 0
    {
        return Err(ServingHandoffCodecError::Invalid {
            artifact: "retirement receipt",
            reason: "receipt fields do not form one exact retired process attempt",
        });
    }
    Ok(())
}

fn validate_target_checkpoint_context(
    artifact: &TargetControlAuthorizationArtifact,
    stored_checkpoint: &StoredCheckpoint,
) -> Result<()> {
    validate_target_checkpoint_value(artifact, stored_checkpoint.checkpoint())
}

fn validate_target_checkpoint_value(
    artifact: &TargetControlAuthorizationArtifact,
    checkpoint: &RuntimeCheckpoint,
) -> Result<()> {
    let ReconcileStep::ProvisionRootImage {
        provision_transition_id,
        volume_id,
        attachment_id,
        attachment_epoch,
        scope_id,
        control_socket_path,
        data_directory,
        size_bytes,
        expected_provisioned_head,
        ..
    } = &checkpoint.step
    else {
        anyhow::bail!("target-control artifact requires current provision_root_image")
    };
    let attachment = &artifact.attachment;
    let provision_context_digest =
        provision_root_authorization_context_digest(checkpoint).map_err(anyhow::Error::from)?;
    let request = provision_root_image_request(checkpoint).map_err(anyhow::Error::from)?;
    anyhow::ensure!(
        artifact.provision_context_digest == provision_context_digest
            && artifact.request == request
            && artifact.provision_transition_id == *provision_transition_id
            && checkpoint.node_id == attachment.identity.node_id
            && checkpoint.placement_epoch == attachment.identity.placement_epoch
            && checkpoint.desired_revision == attachment.acquire_desired_revision()
            && *volume_id == attachment.identity.volume_id
            && *attachment_id == attachment.identity.attachment_id
            && *attachment_epoch == attachment.identity.attachment_epoch
            && *scope_id == artifact.runtime_scope_id
            && *control_socket_path == artifact.control_socket_path
            && *size_bytes == attachment.size_bytes
            && expected_provisioned_head == &attachment.head
            && data_directory.as_str() == artifact.local_state.attachment_directory.path.as_str(),
        "target-control artifact is stale for the current stored checkpoint"
    );
    Ok(())
}

fn validate_record_checkpoint_context(
    record: &ServingHandoffRecord,
    stored_checkpoint: &StoredCheckpoint,
) -> Result<()> {
    validate_record_checkpoint_value(
        record,
        stored_checkpoint.checkpoint(),
        stored_checkpoint.content_digest(),
    )
}

fn validate_record_checkpoint_value(
    record: &ServingHandoffRecord,
    checkpoint: &RuntimeCheckpoint,
    checkpoint_digest: &Sha256Digest,
) -> Result<()> {
    validate_target_checkpoint_value(&record.target_control_authorization.artifact, checkpoint)?;
    let ReconcileStep::ProvisionRootImage {
        provision_transition_id,
        volume_id,
        attachment_id,
        attachment_epoch,
        scope_id,
        control_socket_path,
        data_directory,
        process_identity_token,
        expected_provisioned_head,
        ..
    } = &checkpoint.step
    else {
        anyhow::bail!("serving handoff record requires current provision_root_image")
    };
    let process = &record.old_control_process;
    anyhow::ensure!(
        record.checkpoint_content_digest == *checkpoint_digest
            && record.cat_id == checkpoint.cat_id
            && record.node_id == checkpoint.node_id
            && record.placement_epoch == checkpoint.placement_epoch
            && record.desired_revision == checkpoint.desired_revision
            && record.spec_digest == checkpoint.spec_digest
            && record.provision_transition_id == *provision_transition_id
            && record.volume_id == *volume_id
            && record.attachment_id == *attachment_id
            && record.attachment_epoch == *attachment_epoch
            && record.expected_provisioned_head == *expected_provisioned_head
            && process.scope_id == *scope_id
            && process.control_socket_path == *control_socket_path
            && process.data_directory == *data_directory
            && process.ownership_token == *process_identity_token
            && process.executable_path == record.expected_control_executable_path,
        "serving handoff record is stale for the current stored checkpoint"
    );
    Ok(())
}

fn validate_retained_prepare_device_handoff(
    checkpoint: &RuntimeCheckpoint,
    desired: &DesiredRuntimeSpec,
    authority: &VolumeRecord,
    retained_authorized: &RetainedAuthorizedBlockd,
    retained_target: &RetainedFile,
    retained_record: &RetainedFile,
    retained_retirement: Option<&RetainedFile>,
) -> Result<RetainedRootProvisionProcessAttempt> {
    let prepared_checkpoint = prepare_device_checkpoint_view(checkpoint)?;
    let target = retained_scanned_artifact(retained_target);
    let record = retained_scanned_artifact(retained_record);
    let retirement = retained_retirement.map(retained_scanned_artifact);
    let attempt = validate_scanned_serving_handoff_artifacts(
        &prepared_checkpoint,
        retained_authorized.checkpoint(),
        &target,
        Some(&record),
        retirement.as_ref(),
    )?
    .context("PrepareDevice Root handoff did not retain one old process attempt")?;
    RootProvisionProcessExpectation::from_retained_prepare_device(
        &prepared_checkpoint,
        desired,
        &attempt,
    )
    .context("PrepareDevice Root handoff is not bound to current Desired")?;
    validate_authorized_serving_record(authority, &attempt.attachment, None)
        .map_err(|error| anyhow::anyhow!("PrepareDevice Root authority is not exact: {error}"))?;
    Ok(attempt)
}

fn retained_scanned_artifact(file: &RetainedFile) -> ScannedServingHandoffArtifact<'_> {
    ScannedServingHandoffArtifact {
        path: file.identity.path.clone(),
        device: file.identity.device,
        inode: file.identity.inode,
        length: file.identity.length,
        content_sha256: file.identity.content_sha256.clone(),
        bytes: &file.bytes,
    }
}

/// Provider-private classifier used by the full inventory scanner. It does
/// not project a public process proof; it only proves that every reserved
/// handoff artifact in the strict data leaf is canonical and belongs to the
/// current checkpoint/authorized attachment. This keeps the scanner from
/// turning a filename allowlist into false completeness.
pub(crate) fn validate_scanned_serving_handoff_artifacts(
    checkpoint: &RuntimeCheckpoint,
    acquired: &AuthorizedBlockdCheckpoint,
    target: &ScannedServingHandoffArtifact<'_>,
    record: Option<&ScannedServingHandoffArtifact<'_>>,
    retirement: Option<&ScannedServingHandoffArtifact<'_>>,
) -> Result<Option<RetainedRootProvisionProcessAttempt>> {
    let prepared_checkpoint;
    let checkpoint = if matches!(checkpoint.step, ReconcileStep::PrepareNetwork { .. })
        || checkpoint.runtime_launch.identity().is_some()
    {
        prepared_checkpoint = prepare_device_checkpoint_view(checkpoint)?;
        &prepared_checkpoint
    } else {
        checkpoint
    };
    let checkpoint_digest = checkpoint_content_digest(checkpoint)?;
    let target_artifact = validate_scanned_target_control(checkpoint, acquired, target)?;

    let decoded_record = record
        .map(|file| {
            validate_scanned_artifact_bytes(file, file.bytes)?;
            let decoded = decode_serving_handoff_record(file.bytes)?;
            anyhow::ensure!(
                Path::new(file.path.as_str())
                    .file_name()
                    .and_then(|name| name.to_str())
                    == Some(SERVING_HANDOFF_RECORD_FILE)
                    && record_target_matches_scan(&decoded, &target_artifact, target),
                "scanned handoff record changed physical or target identity"
            );
            Ok(decoded)
        })
        .transpose()?;

    let retained_process = match &checkpoint.step {
        ReconcileStep::ProvisionRootImage { .. } => {
            validate_target_checkpoint_value(&target_artifact, checkpoint)?;
            if let Some(decoded) = decoded_record.as_ref() {
                validate_record_checkpoint_value(decoded, checkpoint, &checkpoint_digest)?;
            }
            None
        }
        ReconcileStep::PrepareDevice { devices } => {
            let mut roots = devices.iter().filter(|device| matches!(
                device.serving_authority.as_ref(),
                ServingAuthorityProvenance::AfterRootProvision { .. }
            ));
            let device = roots.next().context(
                "PrepareDevice handoff lacks its Root prepared-device authority",
            )?;
            anyhow::ensure!(
                roots.next().is_none(),
                "PrepareDevice handoff duplicates its Root authority"
            );
            let ServingAuthorityProvenance::AfterRootProvision { handoff } =
                device.serving_authority.as_ref()
            else {
                anyhow::bail!(
                    "direct authorized attachment cannot retain root-provision handoff artifacts"
                )
            };
            let decoded = decoded_record
                .as_ref()
                .context("after-root-provision checkpoint lacks its sealed handoff record")?;
            let file = record.context("after-root-provision checkpoint lacks record identity")?;
            anyhow::ensure!(
                handoff.predecessor_checkpoint_content_digest
                    == decoded.checkpoint_content_digest
                    && file.path == handoff.record.path
                    && file.device == handoff.record.device
                    && file.inode == handoff.record.inode
                    && file.length == handoff.record.length
                    && file.content_sha256 == handoff.record.content_sha256
                    && decoded.cat_id == checkpoint.cat_id
                    && decoded.node_id == checkpoint.node_id
                    && decoded.placement_epoch == checkpoint.placement_epoch
                    && decoded.desired_revision == checkpoint.desired_revision
                    && decoded.spec_digest == checkpoint.spec_digest
                    && decoded.volume_id == device.volume_id
                    && decoded.attachment_id == device.attachment_id
                    && decoded.attachment_epoch == device.attachment_epoch
                    && decoded.acquire_origin == device.acquire_origin
                    && decoded.expected_provisioned_head == device.expected_head
                    && decoded.expected_provisioned_head == target_artifact.attachment.head
                    && target_artifact.attachment.identity == acquired.attachment.identity
                    && target_artifact.attachment.acquire == acquired.attachment.acquire
                    && target_artifact.attachment.size_bytes
                        == acquired.attachment.size_bytes
                    && target_artifact.attachment.durability
                        == acquired.attachment.durability
                    && acquired.attachment.size_bytes == device.size_bytes
                    && acquired.attachment.durability == device.durability
                    && decoded.old_control_process.data_directory
                        == device.serving_process.data_directory,
                "PrepareDevice handoff does not preserve the exact predecessor lineage"
            );
            Some(RetainedRootProvisionProcessAttempt {
                cat_id: decoded.cat_id.clone(),
                node_id: decoded.node_id.clone(),
                placement_epoch: decoded.placement_epoch,
                desired_revision: decoded.desired_revision,
                spec_digest: decoded.spec_digest.clone(),
                provision_transition_id: decoded.provision_transition_id.clone(),
                volume_id: decoded.volume_id.clone(),
                attachment_id: decoded.attachment_id.clone(),
                attachment_epoch: decoded.attachment_epoch,
                scope_id: decoded.old_control_process.scope_id.clone(),
                cgroup_path: decoded.old_control_process.cgroup_path.clone(),
                control_socket_path: decoded.old_control_process.control_socket_path.clone(),
                data_directory: decoded.old_control_process.data_directory.clone(),
                process_identity_token: decoded.old_control_process.ownership_token.clone(),
                expected_provisioned_head: decoded.expected_provisioned_head.clone(),
                attachment: target_artifact.attachment.clone(),
                executable_path: decoded.expected_control_executable_path.clone(),
                target_control_launch: TargetControlProcessLaunchIdentity::new(
                    target.path.clone(),
                    target_artifact.provision_transition_id.clone(),
                    target_artifact.provision_context_digest.clone(),
                ),
                physical_identity: RetainedRootProvisionPhysicalIdentity {
                    process_id: u32::try_from(decoded.old_control_process.process_id.get())
                        .context("sealed old control process PID exceeds the platform PID domain")?,
                    unit_main_process_id: u32::try_from(
                        decoded.old_control_process.unit_main_process_id.get(),
                    )
                    .context(
                        "sealed old control unit MainPID exceeds the platform PID domain",
                    )?,
                    process_start_time_ticks: decoded
                        .old_control_process
                        .process_start_time_ticks,
                    cgroup_process_ids: decoded
                        .old_control_process
                        .cgroup_process_ids
                        .iter()
                        .map(|process_id| {
                            u32::try_from(process_id.get()).context(
                                "sealed old control cgroup PID exceeds the platform PID domain",
                            )
                        })
                        .collect::<Result<Vec<_>>>()?,
                    handshake_peer_process_id: u32::try_from(
                        decoded.old_control_process.handshake.peer_process_id.get(),
                    )
                    .context(
                        "sealed old control handshake peer PID exceeds the platform PID domain",
                    )?,
                },
            })
        }
        _ => anyhow::bail!(
            "serving handoff artifacts require provision_root_image or after-root-provision PrepareDevice"
        ),
    };

    if let Some(file) = retirement {
        validate_scanned_artifact_bytes(file, file.bytes)?;
        let receipt = decode_serving_handoff_retirement_receipt(file.bytes)?;
        let receipt_is_current = receipt.old_checkpoint_content_digest == checkpoint_digest
            && receipt.old_checkpoint == *checkpoint;
        match &checkpoint.step {
            ReconcileStep::ProvisionRootImage { .. } => {
                if !receipt_is_current {
                    validate_receipt_checkpoint_direct_successor(
                        &receipt,
                        checkpoint,
                        &checkpoint_digest,
                    )?;
                }
            }
            ReconcileStep::PrepareDevice { .. } => {
                let decoded = decoded_record.as_ref().context(
                    "PrepareDevice retirement receipt lacks the current sealed handoff record",
                )?;
                anyhow::ensure!(
                    receipt.record != *decoded
                        && receipt.old_checkpoint_content_digest
                            != decoded.checkpoint_content_digest
                        && receipt.record.target_control_authorization
                            == decoded.target_control_authorization
                        && receipt.old_process_identity_token
                            != decoded.old_control_process.ownership_token,
                    "PrepareDevice retirement receipt is not a distinct predecessor attempt"
                );
            }
            _ => unreachable!("checkpoint step was closed above"),
        }
        anyhow::ensure!(
            record_target_matches_scan(&receipt.record, &target_artifact, target),
            "scanned retirement receipt changed target-control identity"
        );
        if let Some(decoded) = decoded_record.as_ref() {
            if receipt.record == *decoded {
                anyhow::ensure!(
                    matches!(checkpoint.step, ReconcileStep::ProvisionRootImage { .. })
                        && decoded.checkpoint_content_digest
                            == receipt.old_checkpoint_content_digest
                        && record.is_some_and(|file| {
                            scanned_identity_matches_record(file, &receipt.record_identity)
                        }),
                    "scanned record and retirement receipt disagree on checkpoint attempt"
                );
            } else {
                anyhow::ensure!(
                    !receipt_is_current,
                    "current-attempt retirement receipt conflicts with a different record"
                );
            }
        }
    }
    Ok(retained_process)
}

/// Provider-private target-wrapper identity from the same canonical bytes and
/// physical identity already accepted by the full data-directory scan. This
/// carries no serving proof and cannot authorize a start without reopening
/// the retained descriptor.
pub(crate) fn scanned_target_control_process_launch(
    checkpoint: &RuntimeCheckpoint,
    acquired: &AuthorizedBlockdCheckpoint,
    target: &ScannedServingHandoffArtifact<'_>,
) -> Result<TargetControlProcessLaunchIdentity> {
    let prepared_checkpoint;
    let checkpoint = if matches!(checkpoint.step, ReconcileStep::PrepareNetwork { .. })
        || checkpoint.runtime_launch.identity().is_some()
    {
        prepared_checkpoint = prepare_device_checkpoint_view(checkpoint)?;
        &prepared_checkpoint
    } else {
        checkpoint
    };
    let artifact = validate_scanned_target_control(checkpoint, acquired, target)?;
    Ok(TargetControlProcessLaunchIdentity::new(
        target.path.clone(),
        artifact.provision_transition_id,
        artifact.provision_context_digest,
    ))
}

fn validate_scanned_target_control(
    checkpoint: &RuntimeCheckpoint,
    acquired: &AuthorizedBlockdCheckpoint,
    target: &ScannedServingHandoffArtifact<'_>,
) -> Result<TargetControlAuthorizationArtifact> {
    let target_artifact = decode_target_control_authorization(target.bytes)?;
    validate_scanned_artifact_bytes(target, target.bytes)?;
    anyhow::ensure!(
        target_artifact.attachment.identity == acquired.attachment.identity
            && target.path.as_str()
                == format!(
                    "{}/{}",
                    target_artifact
                        .local_state
                        .attachment_directory
                        .path
                        .as_str(),
                    target_control_file_name(&target_artifact.provision_transition_id)
                ),
        "scanned target-control artifact is outside its exact authorized lineage"
    );
    match &checkpoint.step {
        ReconcileStep::ProvisionRootImage { .. } => {
            validate_target_checkpoint_value(&target_artifact, checkpoint)?;
        }
        ReconcileStep::PrepareDevice { .. } => {
            // The complete record/Prepare binding is validated by the caller;
            // the target itself still has to preserve the same attachment.
            anyhow::ensure!(
                target_artifact.attachment.identity == acquired.attachment.identity,
                "PrepareDevice target-control artifact changed attachment lineage"
            );
        }
        _ => {
            anyhow::bail!("target-control artifacts require provision_root_image or PrepareDevice")
        }
    }
    Ok(target_artifact)
}

fn validate_scanned_artifact_bytes(
    artifact: &ScannedServingHandoffArtifact<'_>,
    bytes: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        artifact.device.get() > 0
            && artifact.inode.get() > 0
            && artifact.length.get() == u64::try_from(bytes.len())?
            && artifact.content_sha256 == Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        "scanned serving handoff artifact changed physical content"
    );
    Ok(())
}

fn record_target_matches_scan(
    record: &ServingHandoffRecord,
    target_artifact: &TargetControlAuthorizationArtifact,
    target: &ScannedServingHandoffArtifact<'_>,
) -> bool {
    let identity = &record.target_control_authorization;
    identity.artifact == *target_artifact
        && identity.path == target.path
        && identity.device == target.device
        && identity.inode == target.inode
        && identity.length == target.length
        && identity.content_sha256 == target.content_sha256
}

fn scanned_identity_matches_record(
    artifact: &ScannedServingHandoffArtifact<'_>,
    identity: &ServingHandoffRecordIdentity,
) -> bool {
    artifact.path == identity.path
        && artifact.device == identity.device
        && artifact.inode == identity.inode
        && artifact.length == identity.length
        && artifact.content_sha256 == identity.content_sha256
}

fn validate_receipt_checkpoint_direct_successor(
    receipt: &ServingHandoffRetirementReceipt,
    checkpoint: &RuntimeCheckpoint,
    checkpoint_digest: &Sha256Digest,
) -> Result<()> {
    let mut expected = receipt.old_checkpoint.clone();
    let ReconcileStep::ProvisionRootImage {
        process_identity_token: old_token,
        ..
    } = &mut expected.step
    else {
        anyhow::bail!("retirement receipt old checkpoint is not provision_root_image")
    };
    let ReconcileStep::ProvisionRootImage {
        process_identity_token: current_token,
        ..
    } = &checkpoint.step
    else {
        anyhow::bail!("retirement receipt current checkpoint is not provision_root_image")
    };
    anyhow::ensure!(
        *old_token != *current_token && receipt.old_checkpoint_content_digest != *checkpoint_digest,
        "retirement receipt does not precede a distinct process attempt"
    );
    *old_token = current_token.clone();
    expected.updated_at_unix_ms = checkpoint.updated_at_unix_ms;
    anyhow::ensure!(
        expected == *checkpoint,
        "retirement receipt is not the exact token-only checkpoint predecessor"
    );
    Ok(())
}

fn canonical_encode<T: Serialize>(
    value: &T,
    maximum: usize,
    artifact: &'static str,
) -> std::result::Result<Vec<u8>, ServingHandoffCodecError> {
    let value = serde_json::to_value(value)
        .map_err(|_| ServingHandoffCodecError::Malformed { artifact })?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes)
        .map_err(|_| ServingHandoffCodecError::Malformed { artifact })?;
    if bytes.len() > maximum {
        return Err(ServingHandoffCodecError::WireBytesLimitExceeded { artifact, maximum });
    }
    Ok(bytes)
}

fn canonical_decode<T>(
    bytes: &[u8],
    maximum: usize,
    artifact: &'static str,
    validate: impl FnOnce(&T) -> std::result::Result<(), ServingHandoffCodecError>,
) -> std::result::Result<T, ServingHandoffCodecError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > maximum {
        return Err(ServingHandoffCodecError::WireBytesLimitExceeded { artifact, maximum });
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| ServingHandoffCodecError::Malformed { artifact })?;
    validate(&value)?;
    if canonical_encode(&value, maximum, artifact)? != bytes {
        return Err(ServingHandoffCodecError::NonCanonical { artifact });
    }
    Ok(value)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> serde_json::Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => serde_json::to_writer(output, string)?,
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(members) => {
            output.push(b'{');
            let mut keys = members.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical_json(&members[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[derive(Debug)]
struct RetainedAttachmentContext {
    state_directory: StateDirectory,
    root_directory: File,
    attachment_directory: File,
    data_directory: PathBuf,
    local_state: ServingHandoffLocalStateIdentity,
    acquire_inputs: RetainedAcquireInputs,
}

#[derive(Debug)]
struct RetainedAcquireInputs {
    identity: RetainedFile,
    blank_grant: RetainedFile,
    launch_checkpoint: RetainedFile,
}

#[derive(Debug)]
struct RetainedFile {
    file: File,
    identity: StableFileIdentity,
    bytes: Vec<u8>,
}

impl RetainedAttachmentContext {
    fn open_and_lock(
        state_directory: StateDirectory,
        data_directory: &Path,
        acquired: &AuthorizedBlockdCheckpoint,
        expected_target: &str,
        expected_target_temp: &str,
    ) -> Result<Self> {
        let root_directory = state_directory
            .try_clone_directory()
            .context("clone retained Node state directory")?;
        verify_retained_state_directory(&root_directory, state_directory.path())?;
        let state_identity = stable_directory_identity(&root_directory, state_directory.path())?;
        let attachment_directory = open_attachment_directory_from_root(
            &root_directory,
            state_directory.path(),
            data_directory,
        )?;
        lock_directory(&attachment_directory).with_context(|| {
            format!(
                "lock serving handoff attachment directory {}",
                data_directory.display()
            )
        })?;
        validate_handoff_namespace(&attachment_directory, expected_target, expected_target_temp)?;
        let attachment_identity = stable_directory_identity(&attachment_directory, data_directory)?;
        let identity = RetainedFile::open_required(
            &attachment_directory,
            IDENTITY_FILE,
            host_path(
                &data_directory.join(IDENTITY_FILE),
                "attachment identity path",
            )?,
            MAX_IDENTITY_BYTES,
        )?;
        let blank_grant = RetainedFile::open_required(
            &attachment_directory,
            AUTHORIZED_SERVING_FILE,
            host_path(
                &data_directory.join(AUTHORIZED_SERVING_FILE),
                "acquire authorization path",
            )?,
            MAX_AUTHORIZED_SERVING_BYTES,
        )?;
        let launch_checkpoint = RetainedFile::open_required(
            &attachment_directory,
            LAUNCH_CHECKPOINT_FILE,
            host_path(
                &data_directory.join(LAUNCH_CHECKPOINT_FILE),
                "authorized blockd launch checkpoint path",
            )?,
            MAX_LAUNCH_CHECKPOINT_BYTES,
        )?;
        validate_acquire_input_bytes(
            &identity.bytes,
            &blank_grant.bytes,
            &launch_checkpoint.bytes,
            acquired,
        )?;
        let local_state = ServingHandoffLocalStateIdentity {
            state_directory: state_identity,
            attachment_directory: attachment_identity,
            attachment_identity_file: identity.identity.clone(),
            acquire_authorization_file: blank_grant.identity.clone(),
            launch_checkpoint_file: launch_checkpoint.identity.clone(),
        };
        let retained = Self {
            state_directory,
            root_directory,
            attachment_directory,
            data_directory: data_directory.to_path_buf(),
            local_state,
            acquire_inputs: RetainedAcquireInputs {
                identity,
                blank_grant,
                launch_checkpoint,
            },
        };
        retained.assert_current()?;
        Ok(retained)
    }

    fn from_locked_directory(
        state_directory: StateDirectory,
        data_directory: &Path,
        acquired: &AuthorizedBlockdCheckpoint,
        expected_target: &str,
        expected_target_temp: &str,
        attachment_directory: File,
    ) -> Result<Self> {
        let root_directory = state_directory
            .try_clone_directory()
            .context("clone retained Node state directory")?;
        verify_retained_state_directory(&root_directory, state_directory.path())?;
        let state_identity = stable_directory_identity(&root_directory, state_directory.path())?;
        verify_private_directory(&attachment_directory, data_directory)?;
        let lexical_root = state_directory
            .try_reopen_directory()
            .context("reopen lexical Node state directory")?;
        let lexical_attachment = open_attachment_directory_from_root(
            &lexical_root,
            state_directory.path(),
            data_directory,
        )?;
        let attachment_identity = stable_directory_identity(&attachment_directory, data_directory)?;
        anyhow::ensure!(
            stable_directory_identity(&lexical_attachment, data_directory)? == attachment_identity,
            "retained authorized blockd attachment descriptor is no longer lexical"
        );
        validate_handoff_namespace(&attachment_directory, expected_target, expected_target_temp)?;
        let identity = RetainedFile::open_required(
            &attachment_directory,
            IDENTITY_FILE,
            host_path(
                &data_directory.join(IDENTITY_FILE),
                "attachment identity path",
            )?,
            MAX_IDENTITY_BYTES,
        )?;
        let blank_grant = RetainedFile::open_required(
            &attachment_directory,
            AUTHORIZED_SERVING_FILE,
            host_path(
                &data_directory.join(AUTHORIZED_SERVING_FILE),
                "acquire authorization path",
            )?,
            MAX_AUTHORIZED_SERVING_BYTES,
        )?;
        let launch_checkpoint = RetainedFile::open_required(
            &attachment_directory,
            LAUNCH_CHECKPOINT_FILE,
            host_path(
                &data_directory.join(LAUNCH_CHECKPOINT_FILE),
                "authorized blockd launch checkpoint path",
            )?,
            MAX_LAUNCH_CHECKPOINT_BYTES,
        )?;
        validate_acquire_input_bytes(
            &identity.bytes,
            &blank_grant.bytes,
            &launch_checkpoint.bytes,
            acquired,
        )?;
        let local_state = ServingHandoffLocalStateIdentity {
            state_directory: state_identity,
            attachment_directory: attachment_identity,
            attachment_identity_file: identity.identity.clone(),
            acquire_authorization_file: blank_grant.identity.clone(),
            launch_checkpoint_file: launch_checkpoint.identity.clone(),
        };
        let retained = Self {
            state_directory,
            root_directory,
            attachment_directory,
            data_directory: data_directory.to_path_buf(),
            local_state,
            acquire_inputs: RetainedAcquireInputs {
                identity,
                blank_grant,
                launch_checkpoint,
            },
        };
        retained.assert_current()?;
        Ok(retained)
    }

    fn assert_current(&self) -> Result<()> {
        verify_retained_state_directory(&self.root_directory, self.state_directory.path())?;
        assert_directory_identity(&self.root_directory, &self.local_state.state_directory)?;
        verify_private_directory(&self.attachment_directory, &self.data_directory)?;
        assert_directory_identity(
            &self.attachment_directory,
            &self.local_state.attachment_directory,
        )?;

        // Reopen the lexical root and full descendant path. A retained fd by
        // itself is insufficient after rename/recreate because its old inode
        // no longer names the path a future consumer would open.
        let current_root = self
            .state_directory
            .try_reopen_directory()
            .context("reopen current Node state directory")?;
        verify_retained_state_directory(&current_root, self.state_directory.path())?;
        assert_directory_identity(&current_root, &self.local_state.state_directory)?;
        let current_attachment = open_attachment_directory_from_root(
            &current_root,
            self.state_directory.path(),
            &self.data_directory,
        )?;
        assert_directory_identity(&current_attachment, &self.local_state.attachment_directory)?;

        self.acquire_inputs.identity.assert_current(
            &self.attachment_directory,
            &self.local_state.attachment_identity_file.path,
        )?;
        self.acquire_inputs.blank_grant.assert_current(
            &self.attachment_directory,
            &self.local_state.acquire_authorization_file.path,
        )?;
        self.acquire_inputs.launch_checkpoint.assert_current(
            &self.attachment_directory,
            &self.local_state.launch_checkpoint_file.path,
        )?;
        Ok(())
    }
}

impl RetainedFile {
    fn open_required(directory: &File, name: &str, path: HostPath, maximum: usize) -> Result<Self> {
        let name_c = c_string(name)?;
        let mut file = open_at(
            directory,
            &name_c,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
        .with_context(|| format!("open retained serving handoff file {name}"))?;
        verify_regular_file(&file, name, None)?;
        let before = FileIdentity::from_metadata(
            &file
                .metadata()
                .with_context(|| format!("inspect retained {name}"))?,
        );
        anyhow::ensure!(
            before.len <= maximum as u64,
            "retained serving handoff file {name} exceeds {maximum} bytes"
        );
        let mut bytes = Vec::with_capacity((before.len as usize).min(maximum));
        (&mut file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read retained {name}"))?;
        anyhow::ensure!(
            bytes.len() <= maximum,
            "retained serving handoff file {name} exceeds {maximum} bytes"
        );
        let after = FileIdentity::from_metadata(
            &file
                .metadata()
                .with_context(|| format!("reinspect retained {name}"))?,
        );
        anyhow::ensure!(before == after, "retained file {name} changed while read");
        let identity = stable_file_identity(&file, path, &bytes)?;
        Ok(Self {
            file,
            identity,
            bytes,
        })
    }

    fn assert_current(&self, directory: &File, expected_path: &HostPath) -> Result<()> {
        anyhow::ensure!(
            &self.identity.path == expected_path,
            "retained serving handoff path changed"
        );
        assert_file_identity(&self.file, &self.identity)?;
        let name = Path::new(expected_path.as_str())
            .file_name()
            .and_then(|name| name.to_str())
            .context("retained serving handoff path has no canonical basename")?;
        let current =
            Self::open_required(directory, name, expected_path.clone(), self.bytes.len())?;
        anyhow::ensure!(
            current.identity == self.identity && current.bytes == self.bytes,
            "serving handoff file {name} changed identity or bytes"
        );
        Ok(())
    }
}

fn validate_acquire_input_bytes(
    identity: &[u8],
    blank_grant: &[u8],
    launch: &[u8],
    acquired: &AuthorizedBlockdCheckpoint,
) -> Result<()> {
    let decoded_identity: AttachmentLineageIdentity =
        serde_json::from_slice(identity).context("decode persisted attachment identity")?;
    let decoded_blank: AuthorizedServingAttachment =
        serde_json::from_slice(blank_grant).context("decode persisted acquire-time grant")?;
    let decoded_launch: AuthorizedBlockdCheckpoint =
        serde_json::from_slice(launch).context("decode persisted authorized blockd checkpoint")?;
    anyhow::ensure!(
        decoded_identity == acquired.attachment.identity
            && decoded_blank == acquired.attachment
            && decoded_launch == *acquired
            && identity
                == serde_json::to_vec(&acquired.attachment.identity)
                    .context("re-encode persisted attachment identity")?
            && blank_grant
                == serde_json::to_vec(&acquired.attachment)
                    .context("re-encode persisted acquire-time grant")?
            && launch
                == serde_json::to_vec(acquired)
                    .context("re-encode persisted authorized blockd checkpoint")?,
        "persisted acquire-time blockd inputs changed or are noncanonical"
    );
    Ok(())
}

fn open_attachment_directory_from_root(
    root_directory: &File,
    state_directory_path: &Path,
    data_directory: &Path,
) -> Result<File> {
    let relative = data_directory
        .strip_prefix(state_directory_path)
        .context("serving handoff directory is outside the retained Node state directory")?;
    anyhow::ensure!(
        relative.components().next().is_some()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "serving handoff directory is not a strict descriptor-relative descendant"
    );
    let mut directory = root_directory
        .try_clone()
        .context("clone retained Node state directory descriptor")?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            unreachable!("relative path components were validated")
        };
        let name = CString::new(name.as_bytes()).context("serving handoff path contains NUL")?;
        directory = open_at(
            &directory,
            &name,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0,
        )
        .with_context(|| {
            format!(
                "open serving handoff directory {}",
                data_directory.display()
            )
        })?;
        verify_private_directory(&directory, data_directory)?;
    }
    Ok(directory)
}

fn verify_private_directory(directory: &File, path: &Path) -> Result<()> {
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect serving handoff directory {}", path.display()))?;
    // SAFETY: geteuid has no pointer arguments and retains no Rust memory.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o777 == 0o700,
        "serving handoff directory {} has unsafe metadata",
        path.display()
    );
    Ok(())
}

fn verify_retained_state_directory(directory: &File, path: &Path) -> Result<()> {
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect retained state directory {}", path.display()))?;
    // SAFETY: geteuid has no pointer arguments and retains no Rust memory.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o022 == 0,
        "retained state directory {} has unsafe metadata",
        path.display()
    );
    Ok(())
}

fn stable_directory_identity(file: &File, path: &Path) -> Result<StableDirectoryIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect stable directory {}", path.display()))?;
    anyhow::ensure!(metadata.ino() > 0, "stable directory has no inode");
    Ok(StableDirectoryIdentity {
        path: host_path(path, "stable serving handoff directory path")?,
        device: wire_filesystem_value(metadata.dev(), "directory device")?,
        inode: wire_filesystem_value(metadata.ino(), "directory inode")?,
    })
}

fn assert_directory_identity(file: &File, expected: &StableDirectoryIdentity) -> Result<()> {
    let path = Path::new(expected.path.as_str());
    let metadata = file
        .metadata()
        .with_context(|| format!("reinspect stable directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.dev() == expected.device.get()
            && metadata.ino() == expected.inode.get(),
        "serving handoff directory {} changed identity",
        path.display()
    );
    Ok(())
}

fn stable_file_identity(file: &File, path: HostPath, bytes: &[u8]) -> Result<StableFileIdentity> {
    verify_regular_file(file, path.as_str(), Some(bytes.len() as u64))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect stable file {}", path.as_str()))?;
    anyhow::ensure!(metadata.ino() > 0, "stable file has no inode");
    Ok(StableFileIdentity {
        path,
        device: wire_filesystem_value(metadata.dev(), "file device")?,
        inode: wire_filesystem_value(metadata.ino(), "file inode")?,
        length: wire_filesystem_value(metadata.len(), "file length")?,
        content_sha256: Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
    })
}

fn assert_file_identity(file: &File, expected: &StableFileIdentity) -> Result<()> {
    verify_regular_file(file, expected.path.as_str(), Some(expected.length.get()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reinspect stable file {}", expected.path.as_str()))?;
    anyhow::ensure!(
        metadata.dev() == expected.device.get() && metadata.ino() == expected.inode.get(),
        "serving handoff file {} changed identity",
        expected.path.as_str()
    );
    Ok(())
}

fn wire_filesystem_value(value: u64, label: &'static str) -> Result<WireU64> {
    WireU64::new(value).with_context(|| format!("serving handoff {label} exceeds wire range"))
}

fn lock_directory(directory: &File) -> io::Result<()> {
    // SAFETY: the live descriptor remains owned by the caller and flock
    // retains no Rust memory.
    let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn validate_handoff_namespace(
    directory: &File,
    expected_target: &str,
    expected_target_temp: &str,
) -> Result<()> {
    let expected = [
        expected_target.as_bytes(),
        expected_target_temp.as_bytes(),
        SERVING_HANDOFF_RECORD_FILE.as_bytes(),
        SERVING_HANDOFF_RECORD_TEMP.as_bytes(),
        SERVING_HANDOFF_RETIREMENT_FILE.as_bytes(),
        SERVING_HANDOFF_RETIREMENT_TEMP.as_bytes(),
    ];
    let mut stream = DirectoryStream::open(directory)
        .context("open descriptor-relative serving handoff directory stream")?;
    while let Some(name) = stream
        .next()
        .context("enumerate serving handoff directory")?
    {
        let reserved = name.starts_with(b"authorized-target-control-")
            || name.starts_with(b".authorized-target-control-")
            || name.starts_with(b"serving-handoff")
            || name.starts_with(b".serving-handoff");
        anyhow::ensure!(
            !reserved || expected.contains(&name.as_slice()),
            "foreign serving handoff artifact {} conflicts with the current provision transition",
            String::from_utf8_lossy(&name)
        );
    }
    Ok(())
}

fn ensure_no_unpublished_handoff_temp(directory: &File, expected_target_temp: &str) -> Result<()> {
    for (name, maximum) in [
        (expected_target_temp, TARGET_AUTHORIZED_SERVING_MAX_BYTES),
        (
            SERVING_HANDOFF_RECORD_TEMP,
            SERVING_HANDOFF_RECORD_MAX_BYTES,
        ),
        (
            SERVING_HANDOFF_RETIREMENT_TEMP,
            SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
        ),
    ] {
        anyhow::ensure!(
            read_optional_bounded(directory, &c_string(name)?, maximum)?.is_none(),
            "serving handoff effect requires pre-scan recovery of unpublished temp {name}"
        );
    }
    Ok(())
}

struct DirectoryStream(*mut libc::DIR);

impl DirectoryStream {
    fn open(directory: &File) -> io::Result<Self> {
        // SAFETY: fcntl duplicates the live descriptor and retains no Rust
        // memory. fdopendir consumes the duplicate only on success.
        let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: duplicate is a fresh owned directory descriptor.
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not consume duplicate.
            unsafe { libc::close(duplicate) };
            return Err(error);
        }
        Ok(Self(stream))
    }

    fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            set_errno(0);
            // SAFETY: this value exclusively owns the live DIR pointer.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = errno();
                return if error == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::from_raw_os_error(error))
                };
            }
            // SAFETY: readdir returned a live dirent and the bytes are copied
            // before the next call.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            return Ok(Some(name.to_vec()));
        }
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this value owns the non-null DIR pointer exactly once.
        unsafe { libc::closedir(self.0) };
    }
}

#[cfg(target_os = "linux")]
fn set_errno(value: libc::c_int) {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "linux")]
fn errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn set_errno(value: libc::c_int) {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
fn errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__error() }
}

fn read_required_bounded(directory: &File, name: &str, maximum: usize) -> Result<Vec<u8>> {
    let name_c = c_string(name)?;
    read_optional_bounded(directory, &name_c, maximum)?
        .with_context(|| format!("required serving handoff input {name} is missing"))
}

fn read_optional_bounded(directory: &File, name: &CStr, maximum: usize) -> Result<Option<Vec<u8>>> {
    let display = name.to_string_lossy();
    let mut file = match open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {display}")),
    };
    verify_regular_file(&file, &display, None)?;
    let before = FileIdentity::from_metadata(
        &file
            .metadata()
            .with_context(|| format!("inspect {display}"))?,
    );
    anyhow::ensure!(
        before.len <= maximum as u64,
        "serving handoff file {display} exceeds {maximum} bytes"
    );
    let mut bytes = Vec::with_capacity((before.len as usize).min(maximum));
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {display}"))?;
    anyhow::ensure!(
        bytes.len() <= maximum,
        "serving handoff file {display} exceeds {maximum} bytes"
    );
    let after = FileIdentity::from_metadata(
        &file
            .metadata()
            .with_context(|| format!("reinspect {display}"))?,
    );
    anyhow::ensure!(
        before == after,
        "serving handoff file {display} changed while read"
    );
    Ok(Some(bytes))
}

fn verify_regular_file(
    file: &File,
    path: impl std::fmt::Display,
    expected_len: Option<u64>,
) -> Result<()> {
    let metadata = file.metadata().with_context(|| format!("inspect {path}"))?;
    // SAFETY: geteuid has no pointer arguments and retains no Rust memory.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o777 == 0o600
            && expected_len.is_none_or(|expected| metadata.len() == expected),
        "serving handoff file {path} has unsafe metadata"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn exact_blank_head(head: &RemoteHead) -> bool {
    head.generation.get() == 0 && head.root_hash.is_none() && head.root_object_id.is_none()
}

fn target_control_file_name(provision_transition_id: &RandomId128) -> String {
    target_control_authorization_file_name(provision_transition_id)
}

fn target_control_temp_name(provision_transition_id: &RandomId128) -> String {
    format!(
        ".authorized-target-control-{}.json.tmp",
        provision_transition_id.as_str()
    )
}

fn host_path(path: &Path, label: &str) -> Result<HostPath> {
    HostPath::new(path.to_string_lossy().into_owned())
        .with_context(|| format!("{label} is not a canonical HostPath"))
}

fn c_string(value: &str) -> Result<CString> {
    CString::new(value).with_context(|| format!("serving handoff filename {value} contains NUL"))
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        // SAFETY: the directory descriptor and NUL-terminated name are live
        // for this call. openat retains neither; a successful descriptor is
        // transferred exactly once to File.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
        if descriptor >= 0 {
            // SAFETY: openat returned one fresh owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn unlink_at(directory: &File, name: &CStr) -> io::Result<()> {
    loop {
        // SAFETY: the descriptor and name remain live and unlinkat retains
        // neither.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn rename_no_replace(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both descriptors and names remain live. renameat2 retains
        // no pointers; RENAME_NOREPLACE is the required atomic publication.
        let result = unsafe {
            libc::renameat2(
                old_directory.as_raw_fd(),
                old_name.as_ptr(),
                new_directory.as_raw_fd(),
                new_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn rename_no_replace(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both descriptors and names remain live. renameatx_np
        // retains no pointers; RENAME_EXCL is the no-replace publication.
        let result = unsafe {
            libc::renameatx_np(
                old_directory.as_raw_fd(),
                old_name.as_ptr(),
                new_directory.as_raw_fd(),
                new_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationArtifact {
    TargetAuthorization,
    HandoffRecord,
    HandoffRetirementReceipt,
    HandoffRetirement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationPoint {
    Created,
    PartialWritten,
    FullWritten,
    TempSynced,
    Published,
    BeforeUnlink,
    Unlinked,
    BeforeDirectorySync,
    DirectorySynced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublicationStage {
    artifact: PublicationArtifact,
    point: PublicationPoint,
}

impl PublicationStage {
    const fn new(artifact: PublicationArtifact, point: PublicationPoint) -> Self {
        Self { artifact, point }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{BTreeMap, VecDeque};
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[cfg(not(target_os = "linux"))]
    use cats_api::runtime_reconciliation::NodeBootId;
    use cats_api::runtime_reconciliation::{
        decode_runtime_checkpoint, spec_digest, AdmissionInventoryAttestation, AgentSession,
        AppliedDesiredEvidence, AsciiText, AssignedKind, AssignedPlacement, CheckpointEvidence,
        Condition, DesiredReadSnapshot, DiskKind, Generation, GuestDeviceIdentity,
        GuestTransportEvidence, Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission, MacAddress,
        NetworkConfig, NodeObservation, NormalAcquireRequest, NormalAcquireResult, ObservedDevice,
        ObservedNetwork, ObservedRuntimeStatus, OwnershipTokenEvidence, PrepareDeviceFrontend,
        PreparedDeviceInput, ProgressingReason, RequireIdleCheckpoint, RuntimeCheckpoint,
        RuntimeConfig, RuntimeLaunchArtifact, RuntimeTarget, RuntimeTransition, Sequence,
        ServingAuthorityProvenance, ServingBlockdIdentity, SessionBinding, UnixMillis,
        VmmBootProvenance, VolumeAccess, VolumeAcquire, VolumeAdminState, VolumeAuthorityEvidence,
        VolumeDisposition, VolumeIntent, WarmSnapshotEvidence,
    };
    #[cfg(target_os = "linux")]
    use cats_api::runtime_reconciliation::{guest_config_digest, GuestRuntimeProfileReceipt};
    use cats_storage::authority::{
        AuthorityError, LastVolumeTransition, RenewLeaseRequest, RenewLeaseResult,
        VolumeDataAuthority, VolumeHeadCasRequest, VolumeHeadCasResult,
    };
    use cats_storage::{
        encode_image_manifest, AdapterConfig, AdapterSelection, BlobError, BlobStore,
        ImageManifestV1, LowerHexSha256,
    };

    use super::*;
    use crate::ch::{ChNetwork, PendingTap, TapCreatePort};
    use crate::runtime::reconciliation::blockd_socket_namespace::{
        BlockdSocketIntentStore, BlockdSocketOwnershipIntentV1, BlockdSocketPostSubmitOutcome,
        CurrentBlockdSocketBoot, ExactManagedBlockdSocketOwnerStartAbsence,
        ManagedBlockdSocketOwnerRetirement, RetainedManagedBlockdSocketRoot,
    };
    use crate::runtime::reconciliation::inventory::AuthorityVolumeInventoryEvidence;
    use crate::runtime::reconciliation::kernel_nbd::{
        attach_port_sealed as kernel_attach_sealed, KernelNbdAttachConflict, KernelNbdAttachEffect,
        KernelNbdAttachPort, KernelNbdAttachRequest, KernelNbdAttachResult,
        KernelNbdPoolScanAdmission, RetainedKernelNbdListenerGuard,
    };
    use crate::runtime::reconciliation::network::{
        NodeGlobalNetworkScanAdmission, PrepareNetworkReservationEffect,
    };
    use crate::runtime::reconciliation::prepare_device_retirement::PrepareDeviceTargetRetirementEffect;
    use crate::runtime::reconciliation::root_provision_process::{
        global_sealed as root_process_global_sealed,
        retirement_sealed as root_process_retirement_sealed, sealed as root_process_sealed,
        target_start_sealed as target_process_start_sealed, CheckpointedRootProvisionProcess,
        CheckpointedTargetControlProcess, ManagedServingKey, NodeGlobalManagedProcessScanAdmission,
        RootProvisionProcessGlobalPort, RootProvisionProcessPort,
        RootProvisionProcessRetirementPort, RootProvisionProcessStart, RootProvisionProcessStop,
        TargetControlProcessPort,
    };
    use crate::runtime::reconciliation::running_launch_authority::{
        validate_retained_running_scan_exact_set, RunningLaunchAuthorityRevalidator,
    };
    use crate::runtime::reconciliation::serving_blockd_process::{
        global_sealed as serving_global_sealed, process_sealed as serving_process_sealed,
        CheckpointedServingBlockdProcess, ServingBlockdExpectation, ServingBlockdProcessConflict,
        ServingBlockdProcessGlobalPort, ServingBlockdProcessInspection, ServingBlockdProcessPort,
        ServingBlockdProcessStart, ServingBlockdStartEffect,
    };
    use crate::runtime::reconciliation::serving_handoff_effect::{
        ServingHandoffEffect, ServingHandoffEffectProgress, ServingPrepareDeviceEffect,
        ServingPrepareFrontend,
    };
    use crate::runtime::reconciliation::signed_running::prepared_owned_observed_volume;
    #[cfg(target_os = "linux")]
    use crate::runtime::reconciliation::vmm_launch_artifacts::{
        RetainedVmmLaunchArtifacts, VmmLaunchArtifactPaths,
    };
    use crate::runtime::reconciliation::vmm_process::{
        global_sealed as vmm_global_sealed, sealed as vmm_process_sealed, CheckpointedVmmProcess,
        VmmProcessConflict, VmmProcessExpectation, VmmProcessGlobalInspection,
        VmmProcessGlobalPort, VmmProcessInspection, VmmProcessPort, VmmProcessStart,
    };
    #[cfg(target_os = "linux")]
    use crate::runtime::reconciliation::vmm_runtime_paths::{
        ManagedVmmLaunchFilePaths, RetainedManagedVmmLaunchRoot, VMM_LAUNCH_FILE_NAMESPACE,
    };
    #[cfg(target_os = "linux")]
    use crate::runtime::reconciliation::vmm_socket_namespace::{
        RetainedManagedVmmSocketRoot, VmmSocketReceiptStore,
    };
    #[cfg(target_os = "linux")]
    use crate::runtime::reconciliation::vmm_start_runtime_effect::StartRuntimePhysicalEffect;
    use crate::runtime::reconciliation::vmm_start_runtime_effect::{
        LaunchArtifactAuthorityPort, RetainedLaunchArtifactAuthority, StartRuntimeReservationEffect,
    };
    use crate::runtime::reconciliation::{
        AuthorizedBlockdStore, FileCheckpointStore, RootProvisionProcessConflict,
        RootProvisionProcessInspection, RootProvisionSystemdConfig,
    };
    use crate::runtime_spine::{
        RuntimeDesiredEffectAdmission, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
        RuntimeDesiredEffectStopReason, RuntimePhysicalReadContext,
    };

    /// One isolated, physically real analogue of the production managed Root
    /// socket namespace. Test process ports share this object so an `Absent`
    /// result, owner retirement, and a later target-control start cross the
    /// same descriptor-retained automaton as the platform bridge.
    struct IsolatedManagedRootOwner {
        _temporary: tempfile::TempDir,
        root: Arc<RetainedManagedBlockdSocketRoot>,
        intents: Arc<BlockdSocketIntentStore>,
        boot: CurrentBlockdSocketBoot,
        intent: BlockdSocketOwnershipIntentV1,
        listener: Mutex<Option<UnixListener>>,
    }

    impl IsolatedManagedRootOwner {
        fn new(checkpoint: &RuntimeCheckpoint) -> Self {
            let temporary = tempfile::Builder::new()
                .prefix("shm-")
                .tempdir_in("/private/tmp")
                .or_else(|_| tempfile::Builder::new().prefix("shm-").tempdir_in("/tmp"))
                .unwrap();
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let root = Arc::new(
                RetainedManagedBlockdSocketRoot::provision_for_test(&temporary.path().join("s"))
                    .unwrap(),
            );
            let intent_state = temporary.path().join("state");
            std::fs::create_dir(&intent_state).unwrap();
            std::fs::set_permissions(&intent_state, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let intents = Arc::new(
                BlockdSocketIntentStore::provision_for_test(StateDirectory::unanchored(
                    intent_state,
                ))
                .unwrap(),
            );
            #[cfg(target_os = "linux")]
            let node_boot_id =
                super::super::vmm_socket_namespace::current_kernel_node_boot_id().unwrap();
            #[cfg(not(target_os = "linux"))]
            let node_boot_id = NodeBootId::new("11111111111111111111111111111111").unwrap();
            let boot = CurrentBlockdSocketBoot::for_test(node_boot_id);
            let ReconcileStep::ProvisionRootImage {
                provision_transition_id,
                control_socket_path,
                ..
            } = &checkpoint.step
            else {
                unreachable!("managed Root fixture requires ProvisionRootImage")
            };
            let provision_transition_id = provision_transition_id.clone();
            let installed =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .root_paths(&provision_transition_id)
                    .unwrap()
                    .control_socket()
                    .clone();
            assert_eq!(control_socket_path, &installed);
            let owner_authority_digest = provision_root_authorization_context_digest(checkpoint)
                .unwrap()
                .as_sha256_digest()
                .clone();
            let intent = BlockdSocketOwnershipIntentV1::root(
                &root,
                &boot,
                provision_transition_id,
                owner_authority_digest,
            )
            .unwrap();
            intents.publish(&intent, &root, &boot).unwrap();
            let prepared = root
                .prepare_existing_intent(&intents, &intent, &boot)
                .unwrap();
            let listener =
                UnixListener::bind(Path::new(prepared.control_socket_path().as_str())).unwrap();
            UnixStream::connect(Path::new(prepared.control_socket_path().as_str()))
                .expect("known-positive isolated managed Root listener must accept connects");
            prepared
                .assert_post_submit_owner_current(
                    &boot,
                    BlockdSocketPostSubmitOutcome::HandshakeVerified,
                )
                .unwrap();
            drop(prepared);
            Self {
                _temporary: temporary,
                root,
                intents,
                boot,
                intent,
                listener: Mutex::new(Some(listener)),
            }
        }

        fn shadow_expectation(
            &self,
            expected: &RootProvisionProcessExpectation,
        ) -> anyhow::Result<RootProvisionProcessExpectation> {
            self.assert_same_owner(expected)?;
            let mut shadow = expected.clone();
            shadow.control_socket_path = self.intent.control_socket_path().clone();
            let mut installed = shadow.clone();
            installed.control_socket_path = expected.control_socket_path.clone();
            anyhow::ensure!(
                installed == *expected
                    && shadow.cat_id == expected.cat_id
                    && shadow.provision_transition_id == expected.provision_transition_id
                    && shadow.socket_owner_authority_digest
                        == expected.socket_owner_authority_digest,
                "isolated Root shadow changed more than its physical socket mapping"
            );
            Ok(shadow)
        }

        fn assert_same_owner(
            &self,
            expected: &RootProvisionProcessExpectation,
        ) -> anyhow::Result<()> {
            let installed =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .root_paths(&expected.provision_transition_id)?;
            let isolated = self
                .root
                .planner()
                .root_paths(&expected.provision_transition_id)?;
            anyhow::ensure!(
                self.intent.owner_authority_digest() == &expected.socket_owner_authority_digest
                    && installed.control_socket() == &expected.control_socket_path
                    && self.intent.control_socket_path() == isolated.control_socket()
                    && matches!(
                        self.intent.owner(),
                        super::super::blockd_socket_namespace::BlockdSocketOwnerV1::Root {
                            provision_transition_id,
                        } if provision_transition_id == &expected.provision_transition_id
                    ),
                "isolated managed Root fixture changed owner generation"
            );
            Ok(())
        }

        fn drop_listener_preserving_path(
            &self,
            expected: &RootProvisionProcessExpectation,
        ) -> anyhow::Result<()> {
            self.assert_same_owner(expected)?;
            if self.listener.lock().unwrap().take().is_some() {
                let socket_path = Path::new(self.intent.control_socket_path().as_str());
                anyhow::ensure!(
                    socket_path.exists(),
                    "managed Root listener pathname disappeared while its process became absent"
                );
                anyhow::ensure!(
                    UnixStream::connect(socket_path).is_err(),
                    "managed Root listener still accepted connects after its process became absent"
                );
            }
            Ok(())
        }

        fn sealed_absence(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<ExactManagedBlockdSocketOwnerStartAbsence> {
            self.assert_same_owner(expected)?;
            let accepted = context.accepted_full()?;
            anyhow::ensure!(
                accepted.observation().node_boot_id == *self.boot.node_boot_id(),
                "isolated managed Root fixture names another Node boot"
            );
            let admission = context.node_global_process()?;
            anyhow::ensure!(
                admission.matches_observation(accepted.observation()),
                "isolated managed Root fixture is not bound to the accepted full observation"
            );
            anyhow::ensure!(
                admission
                    .root_control(&expected.cat_id)
                    .is_some_and(|(admitted, exact)| admitted == expected && exact.is_none()),
                "isolated managed Root absence is not the exact accepted absent owner"
            );
            let node_global_effect = context.lock_node_global_effect()?;
            let control_socket = Path::new(self.intent.control_socket_path().as_str());
            anyhow::ensure!(
                UnixStream::connect(control_socket).is_err(),
                "isolated managed Root listener is present before the absence sweep"
            );
            let capture =
                self.root
                    .capture_start_absence(&self.intents, &self.intent, &self.boot)?;
            let (root_expectations, _) = admission.root_control_state();
            let (serving_expectations, _) = admission.serving_blockd_state();
            let mut expected_intents = root_expectations
                .values()
                .map(|root_expectation| {
                    let installed =
                        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                            .root_paths(&root_expectation.provision_transition_id)?;
                    anyhow::ensure!(
                        installed.control_socket() == &root_expectation.control_socket_path,
                        "accepted Root checkpoint socket is outside the installed managed mapping"
                    );
                    let intent = BlockdSocketOwnershipIntentV1::root(
                        &self.root,
                        &self.boot,
                        root_expectation.provision_transition_id.clone(),
                        root_expectation.socket_owner_authority_digest.clone(),
                    )?;
                    Ok(intent)
                })
                .chain(serving_expectations.values().map(|serving_expectation| {
                    let installed =
                        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                            .serving_paths(serving_expectation.device_ownership_token())?;
                    anyhow::ensure!(
                        installed.control_socket() == serving_expectation.control_socket_path()
                            && installed.io_socket() == serving_expectation.listener_path(),
                        "accepted Serving checkpoint sockets are outside the installed managed mapping"
                    );
                    let intent = BlockdSocketOwnershipIntentV1::serving(
                        &self.root,
                        &self.boot,
                        serving_expectation.device_ownership_token().clone(),
                        super::super::blockd_socket_namespace::serving_socket_owner_authority_digest(
                            serving_expectation.prepared_device(),
                        )?,
                    )?;
                    Ok(intent)
                }))
                .collect::<anyhow::Result<Vec<_>>>()?;
            if !expected_intents.iter().any(|intent| intent == &self.intent) {
                expected_intents.push(self.intent.clone());
            }
            let before = self
                .root
                .capture_closed_whole_root(&self.intents, &expected_intents)?;
            anyhow::ensure!(
                UnixStream::connect(control_socket).is_err(),
                "isolated managed Root listener appeared during the absence sweep"
            );
            let after = self
                .root
                .capture_closed_whole_root(&self.intents, &expected_intents)?;
            anyhow::ensure!(
                UnixStream::connect(control_socket).is_err(),
                "isolated managed Root listener appeared after the absence sweep"
            );
            ExactManagedBlockdSocketOwnerStartAbsence::seal_after_node_global_sweep(
                capture,
                before,
                after,
                &self.boot,
                node_global_effect,
            )
        }

        fn retire_absent_owner(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<ManagedBlockdSocketOwnerRetirement> {
            let absence = self.sealed_absence(expected, context)?;
            self.root
                .retire_absent_owner(&self.intents, &self.intent, &self.boot, absence)
        }

        fn submit_target(
            &self,
            expected: &RootProvisionProcessExpectation,
            absence: ExactManagedBlockdSocketOwnerStartAbsence,
            outcome: EffectTargetProcessOutcome,
        ) -> anyhow::Result<()> {
            let shadow = self.shadow_expectation(expected)?;
            anyhow::ensure!(
                self.intent.control_socket_path() == &shadow.control_socket_path,
                "target start did not retain its exact isolated Root shadow"
            );
            anyhow::ensure!(
                self.listener.lock().unwrap().is_none(),
                "isolated managed Root fixture still retains a live predecessor listener"
            );
            let prepared = self.root.prepare_absent_owner_for_start(
                &self.intents,
                &self.intent,
                &self.boot,
                absence,
            )?;
            match outcome {
                EffectTargetProcessOutcome::CancelledClean => {
                    prepared.assert_post_submit_owner_current(
                        &self.boot,
                        BlockdSocketPostSubmitOutcome::DefinitelyNotStarted,
                    )?;
                }
                EffectTargetProcessOutcome::ResponseLost | EffectTargetProcessOutcome::Started => {
                    let listener =
                        UnixListener::bind(Path::new(prepared.control_socket_path().as_str()))?;
                    prepared.assert_post_submit_owner_current(
                        &self.boot,
                        if matches!(outcome, EffectTargetProcessOutcome::Started) {
                            BlockdSocketPostSubmitOutcome::HandshakeVerified
                        } else {
                            BlockdSocketPostSubmitOutcome::MayHaveStarted
                        },
                    )?;
                    *self.listener.lock().unwrap() = Some(listener);
                }
            }
            Ok(())
        }
    }

    /// Per-port shadow of one production Serving owner. Both role-specific
    /// listeners are real Unix sockets, while the public expectation remains
    /// bound to the installed mapper used by production inventory.
    struct IsolatedManagedServingOwner {
        _temporary: tempfile::TempDir,
        root: Arc<RetainedManagedBlockdSocketRoot>,
        intents: Arc<BlockdSocketIntentStore>,
        boot: CurrentBlockdSocketBoot,
        intent: BlockdSocketOwnershipIntentV1,
        listeners: Option<(UnixListener, UnixListener)>,
    }

    impl IsolatedManagedServingOwner {
        fn new(
            expected: &ServingBlockdExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<Self> {
            let temporary = tempfile::Builder::new()
                .prefix("shs-")
                .tempdir_in("/private/tmp")
                .or_else(|_| tempfile::Builder::new().prefix("shs-").tempdir_in("/tmp"))?;
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
            let root = Arc::new(RetainedManagedBlockdSocketRoot::provision_for_test(
                &temporary.path().join("s"),
            )?);
            let intent_state = temporary.path().join("state");
            std::fs::create_dir(&intent_state)?;
            std::fs::set_permissions(&intent_state, std::fs::Permissions::from_mode(0o700))?;
            let intents = Arc::new(BlockdSocketIntentStore::provision_for_test(
                StateDirectory::unanchored(intent_state),
            )?);
            let boot = CurrentBlockdSocketBoot::for_test(
                context.accepted_full()?.observation().node_boot_id.clone(),
            );
            let intent = BlockdSocketOwnershipIntentV1::serving(
                &root,
                &boot,
                expected.device_ownership_token().clone(),
                super::super::blockd_socket_namespace::serving_socket_owner_authority_digest(
                    expected.prepared_device(),
                )?,
            )?;
            let owner = Self {
                _temporary: temporary,
                root,
                intents,
                boot,
                intent,
                listeners: None,
            };
            owner.assert_same_owner(expected)?;
            Ok(owner)
        }

        fn assert_same_owner(&self, expected: &ServingBlockdExpectation) -> anyhow::Result<()> {
            let installed =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                    .serving_paths(expected.device_ownership_token())?;
            let isolated = self
                .root
                .planner()
                .serving_paths(expected.device_ownership_token())?;
            anyhow::ensure!(
                installed.control_socket() == expected.control_socket_path()
                    && installed.io_socket() == expected.listener_path()
                    && self.intent.control_socket_path() == isolated.control_socket()
                    && self.intent.io_socket_path() == Some(isolated.io_socket())
                    && self.intent.owner_authority_digest()
                        == &super::super::blockd_socket_namespace::serving_socket_owner_authority_digest(
                            expected.prepared_device(),
                        )?,
                "isolated managed Serving fixture changed owner generation or socket mapping"
            );
            Ok(())
        }

        fn socket_paths(&self) -> [&Path; 2] {
            [
                Path::new(self.intent.control_socket_path().as_str()),
                Path::new(self.intent.io_socket_path().unwrap().as_str()),
            ]
        }

        fn assert_listeners_absent(&self, phase: &str) -> anyhow::Result<()> {
            for socket in self.socket_paths() {
                anyhow::ensure!(
                    UnixStream::connect(socket).is_err(),
                    "isolated managed Serving listener is present {phase}"
                );
            }
            Ok(())
        }

        fn expected_intents(
            &self,
            admission: &super::super::root_provision_process::NodeGlobalManagedProcessAdmission,
        ) -> anyhow::Result<Vec<BlockdSocketOwnershipIntentV1>> {
            let (root_expectations, _) = admission.root_control_state();
            let (serving_expectations, _) = admission.serving_blockd_state();
            let mut intents = root_expectations
                .values()
                .map(|expected| {
                    let installed =
                        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                            .root_paths(&expected.provision_transition_id)?;
                    anyhow::ensure!(
                        installed.control_socket() == &expected.control_socket_path,
                        "accepted Root socket is outside the installed managed mapping"
                    );
                    BlockdSocketOwnershipIntentV1::root(
                        &self.root,
                        &self.boot,
                        expected.provision_transition_id.clone(),
                        expected.socket_owner_authority_digest.clone(),
                    )
                })
                .chain(serving_expectations.values().map(|expected| {
                    let installed =
                        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                            .serving_paths(expected.device_ownership_token())?;
                    anyhow::ensure!(
                        installed.control_socket() == expected.control_socket_path()
                            && installed.io_socket() == expected.listener_path(),
                        "accepted Serving sockets are outside the installed managed mapping"
                    );
                    BlockdSocketOwnershipIntentV1::serving(
                        &self.root,
                        &self.boot,
                        expected.device_ownership_token().clone(),
                        super::super::blockd_socket_namespace::serving_socket_owner_authority_digest(
                            expected.prepared_device(),
                        )?,
                    )
                }))
                .collect::<anyhow::Result<Vec<_>>>()?;
            if !intents.iter().any(|intent| intent == &self.intent) {
                intents.push(self.intent.clone());
            }
            Ok(intents)
        }

        fn sealed_absence(
            &mut self,
            expected: &ServingBlockdExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<ExactManagedBlockdSocketOwnerStartAbsence> {
            self.assert_same_owner(expected)?;
            self.listeners.take();
            self.assert_listeners_absent("before the absence sweep")?;
            let accepted = context.accepted_full()?;
            let admission = context.node_global_process()?;
            anyhow::ensure!(
                admission.matches_observation(accepted.observation())
                    && accepted.observation().node_boot_id == *self.boot.node_boot_id()
                    && admission
                        .serving_blockd(expected.cat_id(), expected.volume_id())
                        .is_some_and(|(admitted, exact)| admitted == expected && exact.is_none()),
                "isolated managed Serving absence is not the exact accepted owner"
            );
            let node_global_effect = context.lock_node_global_effect()?;
            let capture =
                self.root
                    .capture_start_absence(&self.intents, &self.intent, &self.boot)?;
            let intents = self.expected_intents(admission)?;
            let before = self
                .root
                .capture_closed_whole_root(&self.intents, &intents)?;
            self.assert_listeners_absent("during the absence sweep")?;
            let after = self
                .root
                .capture_closed_whole_root(&self.intents, &intents)?;
            self.assert_listeners_absent("after the absence sweep")?;
            ExactManagedBlockdSocketOwnerStartAbsence::seal_after_node_global_sweep(
                capture,
                before,
                after,
                &self.boot,
                node_global_effect,
            )
        }

        fn submit(
            &mut self,
            absence: ExactManagedBlockdSocketOwnerStartAbsence,
            outcome: ServingBlockdProcessStart,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(
                self.listeners.is_none(),
                "isolated managed Serving fixture retains an old listener"
            );
            let prepared = self.root.prepare_absent_owner_for_start(
                &self.intents,
                &self.intent,
                &self.boot,
                absence,
            )?;
            match outcome {
                ServingBlockdProcessStart::DefinitelyNotStarted => {
                    prepared.assert_post_submit_owner_current(
                        &self.boot,
                        BlockdSocketPostSubmitOutcome::DefinitelyNotStarted,
                    )?;
                }
                ServingBlockdProcessStart::Submitted
                | ServingBlockdProcessStart::OutcomeUnknown => {
                    let ctl = UnixListener::bind(Path::new(
                        prepared.control_socket_path().as_str(),
                    ))?;
                    let io = UnixListener::bind(Path::new(
                        prepared.io_socket_path().unwrap().as_str(),
                    ))?;
                    prepared.assert_post_submit_owner_current(
                        &self.boot,
                        BlockdSocketPostSubmitOutcome::MayHaveStarted,
                    )?;
                    self.listeners = Some((ctl, io));
                }
            }
            Ok(())
        }
    }

    struct RetirementProcessPort {
        inspections: Mutex<VecDeque<RootProvisionProcessInspection>>,
        inspect_calls: Mutex<usize>,
        managed_root: Arc<IsolatedManagedRootOwner>,
    }

    impl RetirementProcessPort {
        fn with_inspections(
            fixture: &Fixture,
            inspections: impl IntoIterator<Item = RootProvisionProcessInspection>,
        ) -> Self {
            Self {
                inspections: Mutex::new(inspections.into_iter().collect()),
                inspect_calls: Mutex::new(0),
                managed_root: Arc::clone(&fixture.managed_root),
            }
        }

        fn inspect_calls(&self) -> usize {
            *self.inspect_calls.lock().unwrap()
        }
    }

    impl root_process_retirement_sealed::Sealed for RetirementProcessPort {}

    impl RootProvisionProcessRetirementPort for RetirementProcessPort {
        fn inspect_after_node_global_sweep(
            &self,
            expected: &RootProvisionProcessExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            *self.inspect_calls.lock().unwrap() += 1;
            let inspection = self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(RootProvisionProcessInspection::Unavailable);
            if matches!(inspection, RootProvisionProcessInspection::Absent) {
                self.managed_root.drop_listener_preserving_path(expected)?;
            }
            Ok(inspection)
        }
    }

    struct FixedEffectAuthority {
        record: Mutex<VolumeRecord>,
        loads: AtomicUsize,
    }

    impl FixedEffectAuthority {
        fn new(record: VolumeRecord) -> Self {
            Self {
                record: Mutex::new(record),
                loads: AtomicUsize::new(0),
            }
        }
    }

    impl VolumeDataAuthority for FixedEffectAuthority {
        fn load_volume(&self, volume_id: &Id) -> std::result::Result<VolumeRecord, AuthorityError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            let record = self.record.lock().unwrap().clone();
            (record.volume_id == *volume_id)
                .then_some(record)
                .ok_or(AuthorityError::NotFound)
        }

        fn renew_lease(
            &self,
            _request: &RenewLeaseRequest,
        ) -> std::result::Result<RenewLeaseResult, AuthorityError> {
            unreachable!("serving handoff effect is read-only authority")
        }

        fn compare_and_swap_head(
            &self,
            _request: &VolumeHeadCasRequest,
        ) -> std::result::Result<VolumeHeadCasResult, AuthorityError> {
            unreachable!("serving handoff effect never mutates authority")
        }
    }

    struct SequencedEffectAuthority {
        records: Mutex<VecDeque<VolumeRecord>>,
        loads: AtomicUsize,
    }

    impl SequencedEffectAuthority {
        fn new(records: impl IntoIterator<Item = VolumeRecord>) -> Self {
            Self {
                records: Mutex::new(records.into_iter().collect()),
                loads: AtomicUsize::new(0),
            }
        }
    }

    impl VolumeDataAuthority for SequencedEffectAuthority {
        fn load_volume(&self, volume_id: &Id) -> std::result::Result<VolumeRecord, AuthorityError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            let mut records = self.records.lock().unwrap();
            let record = match records.len() {
                0 => return Err(AuthorityError::NotFound),
                1 => records.front().unwrap().clone(),
                _ => records.pop_front().unwrap(),
            };
            (record.volume_id == *volume_id)
                .then_some(record)
                .ok_or(AuthorityError::NotFound)
        }

        fn renew_lease(
            &self,
            _request: &RenewLeaseRequest,
        ) -> std::result::Result<RenewLeaseResult, AuthorityError> {
            unreachable!("PrepareNetwork effect is read-only authority")
        }

        fn compare_and_swap_head(
            &self,
            _request: &VolumeHeadCasRequest,
        ) -> std::result::Result<VolumeHeadCasResult, AuthorityError> {
            unreachable!("PrepareNetwork effect never mutates Volume authority")
        }
    }

    struct ExactManifestBlob(Vec<u8>);

    impl BlobStore for ExactManifestBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> std::result::Result<(), BlobError> {
            unreachable!("serving handoff effect never writes image objects")
        }

        fn get(&self, _key: &str) -> std::result::Result<Vec<u8>, BlobError> {
            Ok(self.0.clone())
        }

        fn exists(&self, _key: &str) -> std::result::Result<bool, BlobError> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> std::result::Result<(), BlobError> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> std::result::Result<Vec<String>, BlobError> {
            unreachable!()
        }
    }

    struct EffectGlobalProcessPort {
        inspections: Mutex<VecDeque<RootProvisionProcessInspection>>,
        calls: AtomicUsize,
        managed_root: Arc<IsolatedManagedRootOwner>,
    }

    impl EffectGlobalProcessPort {
        fn inspect_one(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            context.check_active()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            let inspection = self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(RootProvisionProcessInspection::Unavailable);
            if matches!(inspection, RootProvisionProcessInspection::Absent) {
                self.managed_root.drop_listener_preserving_path(expected)?;
            }
            Ok(inspection)
        }
    }

    impl root_process_global_sealed::Sealed for EffectGlobalProcessPort {}
    impl root_process_retirement_sealed::Sealed for EffectGlobalProcessPort {}

    impl RootProvisionProcessRetirementPort for EffectGlobalProcessPort {
        fn inspect_after_node_global_sweep(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            self.inspect_one(expected, context)
        }

        fn retire_absent_socket_owner(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<ManagedBlockdSocketOwnerRetirement> {
            self.managed_root.retire_absent_owner(expected, context)
        }

        fn retain_start_socket_absence(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<Option<ExactManagedBlockdSocketOwnerStartAbsence>> {
            self.managed_root.drop_listener_preserving_path(expected)?;
            self.managed_root
                .sealed_absence(expected, context)
                .map(Some)
        }
    }

    impl RootProvisionProcessGlobalPort for EffectGlobalProcessPort {
        fn inspect_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            self.inspect_one(expected, context)
        }
    }

    struct RetirementEffectGlobalPort {
        inspections: Mutex<VecDeque<RootProvisionProcessInspection>>,
        calls: AtomicUsize,
        after_sweep: Mutex<Option<TestMutation>>,
        managed_root: Arc<IsolatedManagedRootOwner>,
    }

    impl RetirementEffectGlobalPort {
        fn new(
            fixture: &Fixture,
            inspections: impl IntoIterator<Item = RootProvisionProcessInspection>,
        ) -> Self {
            Self {
                inspections: Mutex::new(inspections.into_iter().collect()),
                calls: AtomicUsize::new(0),
                after_sweep: Mutex::new(None),
                managed_root: Arc::clone(&fixture.managed_root),
            }
        }

        fn with_after_sweep(
            fixture: &Fixture,
            inspection: RootProvisionProcessInspection,
            after_sweep: impl FnOnce() + Send + 'static,
        ) -> Self {
            Self {
                inspections: Mutex::new([inspection].into()),
                calls: AtomicUsize::new(0),
                after_sweep: Mutex::new(Some(Box::new(after_sweep))),
                managed_root: Arc::clone(&fixture.managed_root),
            }
        }

        fn inspect_one(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            context.check_active()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            let inspection = self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(RootProvisionProcessInspection::Unavailable);
            if let Some(after_sweep) = self.after_sweep.lock().unwrap().take() {
                after_sweep();
            }
            if matches!(inspection, RootProvisionProcessInspection::Absent) {
                self.managed_root.drop_listener_preserving_path(expected)?;
            }
            Ok(inspection)
        }
    }

    impl root_process_global_sealed::Sealed for RetirementEffectGlobalPort {}
    impl root_process_retirement_sealed::Sealed for RetirementEffectGlobalPort {}

    impl RootProvisionProcessRetirementPort for RetirementEffectGlobalPort {
        fn inspect_after_node_global_sweep(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            self.inspect_one(expected, context)
        }

        fn retire_absent_socket_owner(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<ManagedBlockdSocketOwnerRetirement> {
            self.managed_root.retire_absent_owner(expected, context)
        }
    }

    impl RootProvisionProcessGlobalPort for RetirementEffectGlobalPort {
        fn inspect_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            self.inspect_one(expected, context)
        }
    }

    struct RetirementEffectStopPort {
        outcomes: Mutex<VecDeque<RootProvisionProcessStop>>,
        stopped: Mutex<Vec<RootProvisionProcessEvidence>>,
    }

    impl RetirementEffectStopPort {
        fn new(outcomes: impl IntoIterator<Item = RootProvisionProcessStop>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into_iter().collect()),
                stopped: Mutex::new(Vec::new()),
            }
        }

        fn stopped(&self) -> Vec<RootProvisionProcessEvidence> {
            self.stopped.lock().unwrap().clone()
        }
    }

    impl root_process_sealed::Sealed for RetirementEffectStopPort {}

    impl RootProvisionProcessPort for RetirementEffectStopPort {
        fn inspect(
            &self,
            _expected: &RootProvisionProcessExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> Result<RootProvisionProcessInspection> {
            unreachable!("PrepareDevice retirement uses the Node-global sweep")
        }

        fn start_checkpointed(
            &self,
            _checkpointed: CheckpointedRootProvisionProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessStart> {
            unreachable!("PrepareDevice retirement never starts a process")
        }

        fn stop_exact(
            &self,
            exact: ExactRootProvisionProcessProof,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessStop> {
            context.check_active()?;
            self.stopped.lock().unwrap().push(exact.evidence().clone());
            Ok(self
                .outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(RootProvisionProcessStop::Unavailable))
        }
    }

    #[derive(Clone, Copy)]
    enum AuthorityDrift {
        BackToBlank,
        ForeignOwner,
    }

    struct AuthorityDriftingGlobalPort {
        authority: Arc<FixedEffectAuthority>,
        drift: AuthorityDrift,
        managed_root: Arc<IsolatedManagedRootOwner>,
    }

    impl root_process_global_sealed::Sealed for AuthorityDriftingGlobalPort {}
    impl root_process_retirement_sealed::Sealed for AuthorityDriftingGlobalPort {}

    impl RootProvisionProcessRetirementPort for AuthorityDriftingGlobalPort {
        fn inspect_after_node_global_sweep(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            context.check_active()?;
            self.managed_root.drop_listener_preserving_path(expected)?;
            Ok(RootProvisionProcessInspection::Unavailable)
        }
    }

    impl RootProvisionProcessGlobalPort for AuthorityDriftingGlobalPort {
        fn inspect_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &RootProvisionProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessInspection> {
            context.check_active()?;
            let mut record = self.authority.record.lock().unwrap();
            match self.drift {
                AuthorityDrift::BackToBlank => record.head = blank_head(),
                AuthorityDrift::ForeignOwner => {
                    record.lease_owner = Some(id("att_foreign"));
                }
            }
            self.managed_root.drop_listener_preserving_path(expected)?;
            Ok(RootProvisionProcessInspection::Absent)
        }
    }

    struct EffectTargetProcessPort {
        starts: AtomicUsize,
        evidence: RootProvisionProcessEvidence,
        outcome: EffectTargetProcessOutcome,
        managed_root: Arc<IsolatedManagedRootOwner>,
    }

    #[derive(Clone, Copy)]
    enum EffectTargetProcessOutcome {
        Started,
        ResponseLost,
        CancelledClean,
    }

    impl target_process_start_sealed::Sealed for EffectTargetProcessPort {}

    impl TargetControlProcessPort for EffectTargetProcessPort {
        fn start_target_checkpointed(
            &self,
            mut checkpointed: CheckpointedTargetControlProcess<'_>,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<RootProvisionProcessStart> {
            context.check_active()?;
            checkpointed.assert_current()?;
            let socket_absence = checkpointed
                .take_socket_absence()
                .context("fake target start lacks the real managed Root absence capability")?;
            self.starts.fetch_add(1, Ordering::SeqCst);
            anyhow::ensure!(
                self.evidence.exactly_matches(checkpointed.expected()),
                "fake target process evidence is not exact"
            );
            // The fake systemd edge returns the installed-path evidence that
            // production matches. Before doing so, consume the same real
            // managed-owner automaton in an isolated shadow namespace; Linux
            // systemd acceptance covers the installed pathname end to end.
            self.managed_root.submit_target(
                checkpointed.expected(),
                socket_absence,
                self.outcome,
            )?;
            match self.outcome {
                EffectTargetProcessOutcome::ResponseLost => {
                    return Ok(RootProvisionProcessStart::Ambiguous)
                }
                EffectTargetProcessOutcome::CancelledClean => {
                    context.cancel_for_test();
                    return Ok(RootProvisionProcessStart::CancelledClean);
                }
                EffectTargetProcessOutcome::Started => {}
            }
            checkpointed.assert_current()?;
            Ok(RootProvisionProcessStart::Started(Box::new(
                self.evidence.clone(),
            )))
        }
    }

    struct Fixture {
        _root: tempfile::TempDir,
        managed_root: Arc<IsolatedManagedRootOwner>,
        state_directory: StateDirectory,
        checkpoint_directory: PathBuf,
        data_directory: PathBuf,
        blank_authorization_path: PathBuf,
        stored_checkpoint: StoredCheckpoint,
        acquired: AuthorizedBlockdCheckpoint,
        authority: ServingAuthorityTargetEvidence,
        expected_executable_path: HostPath,
        process: RootProvisionProcessEvidence,
    }

    impl Fixture {
        fn store(&self) -> ServingHandoffStore {
            ServingHandoffStore::new(self.state_directory.clone())
        }

        fn target_path(&self) -> PathBuf {
            self.data_directory.join(target_control_file_name(
                &self.authority.provision_transition_id,
            ))
        }

        fn target_temp_path(&self) -> PathBuf {
            self.data_directory.join(target_control_temp_name(
                &self.authority.provision_transition_id,
            ))
        }

        fn record_path(&self) -> PathBuf {
            self.data_directory.join(SERVING_HANDOFF_RECORD_FILE)
        }

        fn record_temp_path(&self) -> PathBuf {
            self.data_directory.join(SERVING_HANDOFF_RECORD_TEMP)
        }

        fn retirement_path(&self) -> PathBuf {
            self.data_directory.join(SERVING_HANDOFF_RETIREMENT_FILE)
        }

        fn retirement_temp_path(&self) -> PathBuf {
            self.data_directory.join(SERVING_HANDOFF_RETIREMENT_TEMP)
        }

        fn exact_process_proof(&self) -> Result<ExactRootProvisionProcessProof> {
            self.exact_process_proof_for(self.process.clone())
        }

        fn exact_process_proof_for(
            &self,
            process: RootProvisionProcessEvidence,
        ) -> Result<ExactRootProvisionProcessProof> {
            RootProvisionProcessExpectation::from_checkpoint(
                self.stored_checkpoint.checkpoint(),
                RootProvisionAuthoritySnapshot {
                    attachment: self.acquired.attachment.clone(),
                    volume: &self.authority.volume,
                },
                self.expected_executable_path.clone(),
            )?
            .prove_exact_process(process)
        }

        fn replace_checkpoint(&mut self, checkpoint: RuntimeCheckpoint) {
            let store = FileCheckpointStore::open(
                &self.checkpoint_directory,
                &self.stored_checkpoint.checkpoint().cat_id,
            )
            .unwrap();
            let current = store.load().unwrap().unwrap();
            self.stored_checkpoint = store.replace(&current, &checkpoint).unwrap();
        }
    }

    fn scanned_file<'a>(path: &Path, bytes: &'a [u8]) -> ScannedServingHandoffArtifact<'a> {
        let metadata = std::fs::metadata(path).unwrap();
        ScannedServingHandoffArtifact {
            path: host(path.to_str().unwrap()),
            device: WireU64::new(metadata.dev()).unwrap(),
            inode: WireU64::new(metadata.ino()).unwrap(),
            length: WireU64::new(metadata.len()).unwrap(),
            content_sha256: Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
            bytes,
        }
    }

    fn effect_context_with_processes(
        fixture: &Fixture,
        processes: Vec<cats_api::runtime_reconciliation::ProcessEvidence>,
    ) -> RuntimeDesiredEffectContext {
        effect_context_with_processes_and_observation(fixture, processes, random('4'))
    }

    fn effect_context_without_node_global_process(
        fixture: &Fixture,
        processes: Vec<cats_api::runtime_reconciliation::ProcessEvidence>,
    ) -> RuntimeDesiredEffectContext {
        effect_context_with_processes_and_observation_binding(
            fixture,
            processes,
            random('4'),
            false,
        )
    }

    fn effect_context_with_processes_and_observation(
        fixture: &Fixture,
        processes: Vec<cats_api::runtime_reconciliation::ProcessEvidence>,
        observation_id: RandomId128,
    ) -> RuntimeDesiredEffectContext {
        effect_context_with_processes_and_observation_binding(
            fixture,
            processes,
            observation_id,
            true,
        )
    }

    fn effect_context_with_processes_and_observation_binding(
        fixture: &Fixture,
        processes: Vec<cats_api::runtime_reconciliation::ProcessEvidence>,
        observation_id: RandomId128,
        bind_node_global_process: bool,
    ) -> RuntimeDesiredEffectContext {
        let checkpoint = fixture.stored_checkpoint.checkpoint();
        let desired = &fixture.acquired.desired;
        #[cfg(target_os = "linux")]
        let node_boot_id =
            super::super::vmm_socket_namespace::current_kernel_node_boot_id().unwrap();
        #[cfg(not(target_os = "linux"))]
        let node_boot_id = NodeBootId::new("11111111111111111111111111111111").unwrap();
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: checkpoint.node_id.clone(),
            immutable_host_id: id("host_01"),
            node_boot_id,
            agent_instance_id: random('2'),
            agent_session_epoch: Epoch::new(2).unwrap(),
            registration_attempt_id: random('3'),
            guest_config_digest: desired.runtime.guest_config_digest.clone(),
            lease_deadline_unix_ms: UnixMillis::new(1_900_000_120_000).unwrap(),
        };
        let inventory_digest = digest('7');
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            inventory_epoch: Epoch::new(4).unwrap(),
            inventory_digest: inventory_digest.clone(),
            inventory_read_position: Sequence::new(12).unwrap(),
            accepted_at_unix_ms: UnixMillis::new(1_900_000_000_000).unwrap(),
        };
        let mut observed_volumes = checkpoint.volumes.clone();
        let [observed_volume] = observed_volumes.as_mut_slice() else {
            panic!("fixture checkpoint must carry one Root Volume")
        };
        observed_volume.authority = VolumeAuthorityEvidence::Owned {
            attachment_id: fixture.acquired.attachment.identity.attachment_id.clone(),
            attachment_epoch: fixture.acquired.attachment.identity.attachment_epoch,
            head: fixture.authority.volume.head.clone(),
        };
        for lineage in &mut observed_volume.local_lineages {
            lineage.local_durable_generation = fixture.authority.volume.head.generation;
            lineage.remote_durable_generation = fixture.authority.volume.head.generation;
        }
        let node_global_process = if bind_node_global_process
            && matches!(
                checkpoint.step,
                ReconcileStep::ProvisionRootImage { .. }
                    | ReconcileStep::PrepareDevice { .. }
                    | ReconcileStep::PrepareNetwork { .. }
                    | ReconcileStep::StartRuntime { .. }
            ) {
            let mut root_expectation =
                if matches!(checkpoint.step, ReconcileStep::ProvisionRootImage { .. }) {
                    RootProvisionProcessExpectation::from_checkpoint(
                        checkpoint,
                        RootProvisionAuthoritySnapshot {
                            attachment: fixture.acquired.attachment.clone(),
                            volume: &fixture.authority.volume,
                        },
                        fixture.expected_executable_path.clone(),
                    )
                    .unwrap()
                } else {
                    let retained = AuthorizedBlockdStore::new(fixture.state_directory.clone())
                        .retain_prepare_device_handoff(checkpoint, desired)
                        .unwrap();
                    let ready = fixture
                        .store()
                        .reopen_prepare_device_handoff(
                            checkpoint,
                            desired,
                            &fixture.authority.volume,
                            retained,
                        )
                        .unwrap();
                    let prepared_checkpoint = prepare_device_checkpoint_view(checkpoint).unwrap();
                    RootProvisionProcessExpectation::from_retained_prepare_device(
                        &prepared_checkpoint,
                        desired,
                        ready.attempt(),
                    )
                    .unwrap()
            };
            if matches!(checkpoint.step, ReconcileStep::ProvisionRootImage { .. }) {
                match fixture
                    .store()
                    .reopen_target_control_authorization(
                        &fixture.stored_checkpoint,
                        &fixture.acquired,
                        &fixture.authority,
                    )
                {
                    Ok(ReopenedTargetControlAuthorization::Absent) => {}
                    Ok(ReopenedTargetControlAuthorization::Exact(target)) => {
                        root_expectation = root_expectation
                            .with_target_control_launch(target_control_process_launch_identity(
                                target.identity(),
                            ))
                            .unwrap();
                    }
                    Err(error) => panic!(
                        "test inventory cannot bind a malformed target-control artifact: {error:#}"
                    ),
                }
            }
            let root_exact = root_expectation
                .clone()
                .prove_exact_process(fixture.process.clone())
                .ok()
                .filter(|proof| {
                    let public = proof.clone().into_process_evidence();
                    processes.iter().any(|process| process == &public)
                });

            let mut scan = NodeGlobalManagedProcessScanAdmission::from_root_controls(
                BTreeMap::from([(desired.cat_id.clone(), root_expectation)]),
                root_exact
                    .map(|proof| BTreeMap::from([(desired.cat_id.clone(), proof)]))
                    .unwrap_or_default(),
            )
            .unwrap();
            if !matches!(checkpoint.step, ReconcileStep::ProvisionRootImage { .. }) {
                let retained = AuthorizedBlockdStore::new(fixture.state_directory.clone())
                    .retain_prepare_device_handoff(checkpoint, desired)
                    .unwrap();
                let ready = fixture
                    .store()
                    .reopen_prepare_device_handoff(
                        checkpoint,
                        desired,
                        &fixture.authority.volume,
                        retained,
                    )
                    .unwrap();
                let serving_expectation =
                    if matches!(&checkpoint.step, ReconcileStep::StartRuntime { .. }) {
                        ServingBlockdExpectation::from_running_handoff(
                            &ready,
                            &serving_systemd_config(fixture),
                            checkpoint,
                            desired,
                            &fixture.authority.volume,
                        )
                        .unwrap()
                    } else {
                        ServingBlockdExpectation::from_handoff(
                            &ready,
                            &serving_systemd_config(fixture),
                            checkpoint,
                            desired,
                            &fixture.authority.volume,
                        )
                        .unwrap()
                    };
                let serving_proof = serving_expectation
                    .clone()
                    .prove_exact_process(serving_expectation.exact_evidence_for_test(51))
                    .unwrap();
                let serving_public = serving_proof.clone().into_process_evidence();
                let serving_exact = processes
                    .iter()
                    .any(|process| process == &serving_public)
                    .then_some(serving_proof);
                let serving_key = ManagedServingKey::new(
                    desired.cat_id.clone(),
                    serving_expectation.volume_id().clone(),
                );
                if let Some((_, device)) = serving_exact
                    .as_ref()
                    .and_then(|proof| proof.vhost_device_projection())
                {
                    observed_volume.devices = vec![device];
                }
                scan = scan
                    .with_serving_blockds(
                        BTreeMap::from([(serving_key.clone(), serving_expectation)]),
                        serving_exact
                            .map(|proof| BTreeMap::from([(serving_key, proof)]))
                            .unwrap_or_default(),
                    )
                    .unwrap();
            }
            let scan = if matches!(checkpoint.step, ReconcileStep::StartRuntime { .. }) {
                let checkpoint_path = host(
                    super::super::runtime_checkpoint_path(
                        &fixture.checkpoint_directory,
                        &checkpoint.cat_id,
                    )
                    .to_str()
                    .unwrap(),
                );
                let expectation =
                    super::super::vmm_process::VmmProcessExpectation::from_checkpoint(
                        checkpoint.clone(),
                    )
                    .unwrap()
                    .with_checkpoint_path(checkpoint_path)
                    .unwrap();
                let exact = expectation
                    .clone()
                    .prove_exact_process(expectation.exact_evidence_for_test(71))
                    .unwrap();
                let public = exact.clone().into_process_evidence();
                let proofs = if processes.iter().any(|process| process == &public) {
                    BTreeMap::from([(desired.cat_id.clone(), exact)])
                } else {
                    BTreeMap::new()
                };
                scan.with_vmms(
                    BTreeMap::from([(desired.cat_id.clone(), expectation)]),
                    proofs,
                )
                .unwrap()
            } else {
                scan
            };
            Some(scan.into_admission_for_test())
        } else {
            None
        };
        let runtime = ObservedRuntimeStatus {
            cat_id: checkpoint.cat_id.clone(),
            applied_desired: Some(AppliedDesiredEvidence {
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement: desired.placement.clone(),
                target: desired.target,
            }),
            runtime_incarnation: checkpoint.runtime_incarnation.clone(),
            stable_state: checkpoint.stable_state,
            step: checkpoint.step.clone(),
            checkpoint: CheckpointEvidence::Valid {
                checkpoint_path: host(
                    super::super::runtime_checkpoint_path(
                        &fixture.checkpoint_directory,
                        &checkpoint.cat_id,
                    )
                    .to_str()
                    .unwrap(),
                ),
                content_digest: fixture.stored_checkpoint.content_digest().clone(),
                version: checkpoint.version,
                cat_id: checkpoint.cat_id.clone(),
                node_id: checkpoint.node_id.clone(),
                desired_revision: checkpoint.desired_revision,
                spec_digest: checkpoint.spec_digest.clone(),
                placement_epoch: checkpoint.placement_epoch,
                runtime_incarnation: checkpoint.runtime_incarnation.clone(),
                runtime_launch: Box::new(checkpoint.runtime_launch.clone()),
                stable_state: checkpoint.stable_state,
                step: Box::new(checkpoint.step.clone()),
                require_idle: Box::new(checkpoint.require_idle.clone()),
                updated_at_unix_ms: checkpoint.updated_at_unix_ms,
            },
            processes,
            volumes: observed_volumes,
            mounts: checkpoint.mounts.clone(),
            networks: checkpoint.networks.clone(),
            guest_transport: checkpoint.guest_transport.clone(),
            warm_snapshot: checkpoint.warm_snapshot.clone(),
            lifecycle_admission: checkpoint.lifecycle_admission,
            routes: Vec::new(),
            platform_guards: 0,
            conditions: vec![Condition::Progressing {
                reason: ProgressingReason::ReconcileStep {
                    step: checkpoint.step.clone(),
                },
            }],
        };
        let observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id,
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(9).unwrap(),
            observed_at_unix_ms: UnixMillis::new(1_899_999_999_000).unwrap(),
            complete_inventory: true,
            inventory_epoch: attestation.inventory_epoch,
            inventory_digest: Some(inventory_digest),
            inventory_read_position: Some(attestation.inventory_read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: vec![runtime],
            residue: Vec::new(),
        };
        let node_global_process =
            node_global_process.map(|admission| admission.rebind_for_test(&observation).unwrap());
        let desired_snapshot = DesiredReadSnapshot {
            version: ContractVersion::V1,
            session: SessionBinding {
                node_id: session.node_id.clone(),
                node_boot_id: session.node_boot_id.clone(),
                agent_instance_id: session.agent_instance_id.clone(),
                agent_session_epoch: session.agent_session_epoch,
            },
            request_sequence: Sequence::new(13).unwrap(),
            read_position: attestation.inventory_read_position,
            issued_at_unix_ms: UnixMillis::new(1_899_999_999_500).unwrap(),
            expires_at_unix_ms: UnixMillis::new(1_900_000_119_000).unwrap(),
            desired_specs: vec![desired.clone()],
        };
        let admission = RuntimeDesiredEffectAdmission::for_test(session, observation, attestation)
            .bind_assigned_cats_for_test(&desired_snapshot);
        let context = RuntimeDesiredEffectContext::for_test_with_admission(
            fixture.state_directory.clone(),
            Instant::now() + Duration::from_secs(10),
            admission,
        );
        match node_global_process {
            Some(admission) => context.with_node_global_process_for_test(admission),
            None => context,
        }
    }

    fn absent_effect_context(fixture: &Fixture) -> RuntimeDesiredEffectContext {
        effect_context_with_processes(fixture, Vec::new())
    }

    fn successor_absent_effect_context(fixture: &Fixture) -> RuntimeDesiredEffectContext {
        mutate_absent_effect_context(fixture, |_session, observation, attestation| {
            observation.inventory_epoch = Epoch::new(5).unwrap();
            observation.inventory_read_position = Some(Sequence::new(13).unwrap());
            observation.inventory_digest = Some(digest('8'));
            attestation.inventory_epoch = observation.inventory_epoch;
            attestation.inventory_read_position = Sequence::new(13).unwrap();
            attestation.inventory_digest = digest('8');
        })
    }

    fn restarted_absent_effect_context(fixture: &Fixture) -> RuntimeDesiredEffectContext {
        mutate_absent_effect_context(fixture, |session, observation, attestation| {
            session.agent_instance_id = random('6');
            session.agent_session_epoch = Epoch::new(3).unwrap();
            observation.agent_instance_id = session.agent_instance_id.clone();
            observation.agent_session_epoch = session.agent_session_epoch;
            observation.inventory_epoch = Epoch::new(1).unwrap();
            observation.inventory_read_position = Some(Sequence::new(13).unwrap());
            observation.inventory_digest = Some(digest('8'));
            attestation.agent_session_epoch = session.agent_session_epoch;
            attestation.inventory_epoch = observation.inventory_epoch;
            attestation.inventory_read_position = Sequence::new(13).unwrap();
            attestation.inventory_digest = digest('8');
        })
    }

    fn mutate_absent_effect_context(
        fixture: &Fixture,
        mutate: impl FnOnce(&mut AgentSession, &mut NodeObservation, &mut AdmissionInventoryAttestation),
    ) -> RuntimeDesiredEffectContext {
        mutate_effect_context(fixture, absent_effect_context(fixture), mutate)
    }

    fn mutate_effect_context(
        fixture: &Fixture,
        base: RuntimeDesiredEffectContext,
        mutate: impl FnOnce(&mut AgentSession, &mut NodeObservation, &mut AdmissionInventoryAttestation),
    ) -> RuntimeDesiredEffectContext {
        let node_global_process = base.node_global_process().ok().cloned();
        let node_global_network = base.node_global_network().ok().cloned();
        let accepted = base.accepted_full().unwrap();
        let mut session = accepted.session().clone();
        let mut observation = accepted.observation().clone();
        let mut attestation = accepted.attestation().clone();
        mutate(&mut session, &mut observation, &mut attestation);
        let node_global_process = node_global_process
            .and_then(|admission| admission.rebind_for_test(&observation).ok());
        let context = RuntimeDesiredEffectContext::for_test_with_admission(
            fixture.state_directory.clone(),
            Instant::now() + Duration::from_secs(10),
            RuntimeDesiredEffectAdmission::for_test(session, observation, attestation),
        );
        let context = match node_global_process {
            Some(admission) => context.with_node_global_process_for_test(admission),
            None => context,
        };
        match node_global_network {
            Some(admission) => context.with_node_global_network_for_test(admission),
            None => context,
        }
    }

    fn prepare_device_successor(
        fixture: &Fixture,
        handoff: RootServingHandoff,
    ) -> RuntimeCheckpoint {
        let mut checkpoint = fixture.stored_checkpoint.checkpoint().clone();
        let attachment = &fixture.acquired.attachment;
        let volume = &fixture.acquired.volume;
        let process_identity_token = random('7');
        let ownership_token = random('8');
        let (serving_control_socket, serving_io_socket) = managed_serving_sockets(&ownership_token);
        let data_directory = host(fixture.data_directory.to_str().unwrap());
        checkpoint.step = ReconcileStep::PrepareDevice {
            devices: vec![PreparedDeviceInput {
                volume_intent_id: volume.volume_intent_id.clone(),
                disk_id: volume.disk_id.clone(),
                volume_id: volume.volume_id.clone(),
                disk_kind: volume.disk_kind,
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                acquire_origin: attachment.identity.acquire_origin.clone(),
                expected_head: fixture.authority.volume.head.clone(),
                size_bytes: attachment.size_bytes,
                durability: attachment.durability,
                guest_device: volume.guest_device.clone(),
                ownership_token,
                serving_authority: Box::new(ServingAuthorityProvenance::AfterRootProvision {
                    handoff,
                }),
                serving_process: ServingBlockdIdentity {
                    scope_id: id(&format!(
                        "cats-serving-{}.service",
                        process_identity_token.as_str()
                    )),
                    control_socket_path: serving_control_socket,
                    data_directory,
                    executable_path: fixture.expected_executable_path.clone(),
                    process_identity_token,
                },
                frontend: PrepareDeviceFrontend::VhostUserBlk {
                    socket_path: serving_io_socket,
                    queues: 2,
                    queue_size: 256,
                },
            }],
        };
        let observed = checkpoint
            .volumes
            .first_mut()
            .expect("production predecessor carries one Owned volume");
        observed.authority = VolumeAuthorityEvidence::Owned {
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            head: fixture.authority.volume.head.clone(),
        };
        for lineage in &mut observed.local_lineages {
            lineage.local_durable_generation = fixture.authority.volume.head.generation;
            lineage.remote_durable_generation = fixture.authority.volume.head.generation;
        }
        checkpoint.updated_at_unix_ms = UnixMillis::new(
            fixture
                .stored_checkpoint
                .checkpoint()
                .updated_at_unix_ms
                .get()
                .checked_add(1)
                .unwrap(),
        )
        .unwrap();
        encode_runtime_checkpoint(&checkpoint).expect("PrepareDevice successor is canonical V1");
        checkpoint
    }

    fn advance_fixture_to_prepare_device(
        fixture: &mut Fixture,
    ) -> cats_api::runtime_reconciliation::ProcessEvidence {
        let old_process = fixture
            .exact_process_proof()
            .unwrap()
            .into_process_evidence();
        let ready = fixture
            .store()
            .seal_serving_ready(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &fixture.exact_process_proof().unwrap(),
            )
            .unwrap();
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let replaced = ready
            .consume_for_prepare_device(&fixture.stored_checkpoint, |handoff| {
                let successor = prepare_device_successor(fixture, handoff);
                Ok(checkpoint_store.replace(&fixture.stored_checkpoint, &successor)?)
            })
            .unwrap();
        fixture.stored_checkpoint = replaced;
        old_process
    }

    fn serving_systemd_config(fixture: &Fixture) -> RootProvisionSystemdConfig {
        RootProvisionSystemdConfig::new(AuthorizedBlockdLaunchConfig {
            blockd_binary: PathBuf::from(fixture.expected_executable_path.as_str()),
            metadata_store: AdapterSelection::new(
                "postgres",
                AdapterConfig::from_pairs([("url-file", "/run/cats/postgres-url")]).unwrap(),
            ),
            object_store: AdapterSelection::new(
                "aws-s3",
                AdapterConfig::from_pairs([("bucket", "cats-runtime-test")]).unwrap(),
            ),
            max_staged_bytes: 101,
            max_staged_packs: 102,
            max_local_bytes: 103,
        })
        .unwrap()
    }

    fn complete_old_process_retirement(fixture: &mut Fixture) {
        advance_fixture_to_prepare_device(fixture);
        let global = Arc::new(RetirementEffectGlobalPort::new(
            fixture,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        ));
        let process = Arc::new(RetirementEffectStopPort::new([]));
        let effect = prepare_device_retirement_effect(fixture, global, process.clone());
        assert_eq!(
            effect
                .try_apply(&absent_effect_context(fixture), &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory),
            "the first absent round must durably retire the real managed Root owner"
        );
        assert!(!Path::new(fixture.managed_root.intent.control_socket_path().as_str()).exists());
        assert_eq!(
            effect
                .try_apply(
                    &successor_absent_effect_context(fixture),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            None,
            "a fresh accepted full may fall through only after owner retirement is already durable"
        );
        assert!(process.stopped().is_empty());
    }

    fn replace_with_kernel_nbd_prepare_device(fixture: &mut Fixture) {
        let mut checkpoint = fixture.stored_checkpoint.checkpoint().clone();
        let ReconcileStep::PrepareDevice { devices } = &mut checkpoint.step else {
            panic!("kernel-NBD test fixture is not at PrepareDevice")
        };
        devices[0].frontend = PrepareDeviceFrontend::KernelNbd {
            listener_socket_path: managed_serving_sockets(&devices[0].ownership_token).1,
            device_path: host("/dev/nbd7"),
            direct: false,
        };
        fixture.replace_checkpoint(checkpoint);
    }

    fn serving_expectation(fixture: &Fixture) -> ServingBlockdExpectation {
        let retained = AuthorizedBlockdStore::new(fixture.state_directory.clone())
            .retain_prepare_device_handoff(
                fixture.stored_checkpoint.checkpoint(),
                &fixture.acquired.desired,
            )
            .unwrap();
        let ready = fixture
            .store()
            .reopen_prepare_device_handoff(
                fixture.stored_checkpoint.checkpoint(),
                &fixture.acquired.desired,
                &fixture.authority.volume,
                retained,
            )
            .unwrap();
        ServingBlockdExpectation::from_handoff(
            &ready,
            &serving_systemd_config(fixture),
            fixture.stored_checkpoint.checkpoint(),
            &fixture.acquired.desired,
            &fixture.authority.volume,
        )
        .unwrap()
    }

    struct FakeServingBlockdPort {
        inspections: Mutex<VecDeque<ServingBlockdProcessInspectionKind>>,
        starts: AtomicUsize,
        start: ServingBlockdProcessStart,
        before_start: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
        managed_owner: Mutex<Option<IsolatedManagedServingOwner>>,
    }

    #[derive(Clone, Copy)]
    enum ServingBlockdProcessInspectionKind {
        Absent,
        Exact,
        Conflict,
        WrongStatus(&'static str),
        WrongCommand,
        WrongCgroup,
    }

    impl FakeServingBlockdPort {
        fn new(
            inspections: impl IntoIterator<Item = ServingBlockdProcessInspectionKind>,
            start: ServingBlockdProcessStart,
        ) -> Self {
            Self {
                inspections: Mutex::new(inspections.into_iter().collect()),
                starts: AtomicUsize::new(0),
                start,
                before_start: Mutex::new(None),
                managed_owner: Mutex::new(None),
            }
        }

        fn managed_owner<'a>(
            slot: &'a mut Option<IsolatedManagedServingOwner>,
            expected: &ServingBlockdExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<&'a mut IsolatedManagedServingOwner> {
            if slot.is_none() {
                *slot = Some(IsolatedManagedServingOwner::new(expected, context)?);
            }
            let owner = slot.as_mut().unwrap();
            owner.assert_same_owner(expected)?;
            Ok(owner)
        }

        fn inspection(
            &self,
            expected: &ServingBlockdExpectation,
        ) -> ServingBlockdProcessInspection {
            let kind = self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .expect("fake serving inspection exhausted");
            match kind {
                ServingBlockdProcessInspectionKind::Absent => {
                    ServingBlockdProcessInspection::Absent
                }
                ServingBlockdProcessInspectionKind::Conflict => {
                    ServingBlockdProcessInspection::Conflict(
                        ServingBlockdProcessConflict::DuplicateIdentity,
                    )
                }
                ServingBlockdProcessInspectionKind::Exact => ServingBlockdProcessInspection::Exact(
                    Box::new(expected.exact_evidence_for_test(51)),
                ),
                ServingBlockdProcessInspectionKind::WrongStatus(field) => {
                    let mut evidence = expected.exact_evidence_for_test(51);
                    let status = evidence.status_mut_for_test();
                    match field {
                        "volume" => status.volume_id = "vol_foreign".to_owned(),
                        "attachment" => status.attachment_id = "att_foreign".to_owned(),
                        "epoch" => status.attachment_epoch = Some(FenceEpoch::new(99).unwrap()),
                        "origin" => {
                            status.acquire_origin = Some(AcquireOrigin::Normal {
                                transition_id: random('9'),
                            })
                        }
                        "node" => status.node_id = Some(id("node_foreign")),
                        "placement" => status.placement_epoch = Some(Epoch::new(99).unwrap()),
                        "head" => {
                            status.remote_head.as_mut().unwrap().generation =
                                Generation::new(99).unwrap()
                        }
                        "size" => status.size_bytes = Some(status.size_bytes.unwrap() + 1),
                        "durability" => status.mode = "relaxed".to_owned(),
                        "scope" => status.scope_id = Some(id("foreign.service")),
                        "process_token" => status.process_identity_token = Some(random('9')),
                        "device_token" => status.device_ownership_token = Some(random('9')),
                        "guest_serial" => status.guest_device_serial = Some(id("cats-foreign")),
                        "missing_guest_serial" => status.guest_device_serial = None,
                        "control_only" => status.control_only = Some(true),
                        "guest_io" => status.guest_io_enabled = Some(false),
                        "local_generation" => status.local_durable_generation += 1,
                        "remote_generation" => status.remote_durable_generation += 1,
                        "unpublished_generations" => status.unpublished_generations = 1,
                        "unpublished_bytes" => status.unpublished_bytes = 1,
                        "unpublished_age" => status.oldest_unpublished_age_ms = 1,
                        "backpressured" => status.backpressured = true,
                        "fenced" => status.fenced = true,
                        _ => unreachable!(),
                    }
                    ServingBlockdProcessInspection::Exact(Box::new(evidence))
                }
                ServingBlockdProcessInspectionKind::WrongCommand => {
                    let mut evidence = expected.exact_evidence_for_test(51);
                    evidence
                        .command_line_mut_for_test()
                        .push("--foreign-argument".into());
                    ServingBlockdProcessInspection::Exact(Box::new(evidence))
                }
                ServingBlockdProcessInspectionKind::WrongCgroup => {
                    let mut evidence = expected.exact_evidence_for_test(51);
                    *evidence.cgroup_path_mut_for_test() =
                        host("/sys/fs/cgroup/system.slice/foreign.service");
                    ServingBlockdProcessInspection::Exact(Box::new(evidence))
                }
            }
        }

        fn remaining_inspections(&self) -> usize {
            self.inspections.lock().unwrap().len()
        }
    }

    impl serving_process_sealed::Sealed for FakeServingBlockdPort {}
    impl serving_global_sealed::Sealed for FakeServingBlockdPort {}

    impl ServingBlockdProcessPort for FakeServingBlockdPort {
        fn inspect(
            &self,
            expected: &ServingBlockdExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> Result<ServingBlockdProcessInspection> {
            Ok(self.inspection(expected))
        }

        fn start_checkpointed(
            &self,
            mut checkpointed: CheckpointedServingBlockdProcess<'_>,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<ServingBlockdProcessStart> {
            context.check_active()?;
            let socket_absence = checkpointed
                .take_socket_absence()
                .context("fake Serving start lacks the real managed absence capability")?;
            if let Some(hook) = self.before_start.lock().unwrap().take() {
                hook();
            }
            checkpointed.assert_current()?;
            context.check_active()?;
            self.starts.fetch_add(1, Ordering::SeqCst);
            Self::managed_owner(
                &mut self.managed_owner.lock().unwrap(),
                checkpointed.expected(),
                context,
            )?
            .submit(socket_absence, self.start)?;
            checkpointed.assert_current()?;
            Ok(self.start)
        }
    }

    impl ServingBlockdProcessGlobalPort for FakeServingBlockdPort {
        fn retain_start_socket_absence(
            &self,
            expected: &ServingBlockdExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<Option<ExactManagedBlockdSocketOwnerStartAbsence>> {
            Self::managed_owner(
                &mut self.managed_owner.lock().unwrap(),
                expected,
                context,
            )?
            .sealed_absence(expected, context)
            .map(Some)
        }

        fn inspect_serving_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &ServingBlockdExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> Result<ServingBlockdProcessInspection> {
            Ok(self.inspection(expected))
        }
    }

    #[derive(Clone, Copy)]
    enum RunningVmmInspectionKind {
        Exact,
        Conflict,
    }

    struct FakeRunningVmmPort {
        inspections: Mutex<VecDeque<RunningVmmInspectionKind>>,
    }

    impl FakeRunningVmmPort {
        fn new(inspections: impl IntoIterator<Item = RunningVmmInspectionKind>) -> Self {
            Self {
                inspections: Mutex::new(inspections.into_iter().collect()),
            }
        }

        fn inspect_one(&self, expected: &VmmProcessExpectation) -> VmmProcessInspection {
            match self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .expect("fake Running VMM inspection exhausted")
            {
                RunningVmmInspectionKind::Exact => {
                    VmmProcessInspection::Exact(Box::new(expected.exact_evidence_for_test(71)))
                }
                RunningVmmInspectionKind::Conflict => {
                    VmmProcessInspection::Conflict(VmmProcessConflict::IdentityMismatch)
                }
            }
        }
    }

    impl vmm_process_sealed::Sealed for FakeRunningVmmPort {}

    impl VmmProcessPort for FakeRunningVmmPort {
        fn inspect(
            &self,
            expected: &VmmProcessExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> Result<VmmProcessInspection> {
            Ok(self.inspect_one(expected))
        }

        fn start_checkpointed(
            &self,
            _checkpointed: CheckpointedVmmProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> Result<VmmProcessStart> {
            unreachable!("Running revalidation never starts a VMM")
        }
    }

    impl vmm_global_sealed::Sealed for FakeRunningVmmPort {}

    impl VmmProcessGlobalPort for FakeRunningVmmPort {
        fn inspect_vmm_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &VmmProcessExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> Result<VmmProcessGlobalInspection> {
            Ok(match self.inspect_one(expected) {
                VmmProcessInspection::Exact(evidence) => VmmProcessGlobalInspection::Exact(
                    Box::new(expected.clone().prove_exact_process(*evidence)?),
                ),
                VmmProcessInspection::Conflict(problem) => {
                    VmmProcessGlobalInspection::Conflict(problem)
                }
                VmmProcessInspection::Absent | VmmProcessInspection::Unavailable => {
                    unreachable!("fake Running VMM returns only exact or conflict")
                }
            })
        }

        fn inspect_vmm_gate_successor_exact_after_node_global_sweep(
            &self,
            admitted_predecessor: &super::super::vmm_process::ExactVmmProcessProof,
            successor_proof: &super::super::vmm_process::VmmGateSuccessorProof,
            _context: &RuntimeDesiredEffectContext,
        ) -> Result<VmmProcessGlobalInspection> {
            let successor = successor_proof.validate_for(admitted_predecessor)?;
            Ok(match self.inspect_one(successor) {
                VmmProcessInspection::Exact(evidence) => VmmProcessGlobalInspection::Exact(
                    Box::new(successor.clone().prove_exact_process(*evidence)?),
                ),
                VmmProcessInspection::Conflict(problem) => {
                    VmmProcessGlobalInspection::Conflict(problem)
                }
                VmmProcessInspection::Absent | VmmProcessInspection::Unavailable => {
                    unreachable!("fake Running VMM returns only exact or conflict")
                }
            })
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy)]
    enum VmmInspectionKind {
        Absent,
        Exact,
        Conflict,
        Unavailable,
    }

    #[cfg(target_os = "linux")]
    struct FakePhysicalVmmPort {
        inspections: Mutex<VecDeque<VmmInspectionKind>>,
        starts: AtomicUsize,
        start: VmmProcessStart,
        before_start: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    }

    #[cfg(target_os = "linux")]
    impl FakePhysicalVmmPort {
        fn new(
            inspections: impl IntoIterator<Item = VmmInspectionKind>,
            start: VmmProcessStart,
        ) -> Self {
            Self {
                inspections: Mutex::new(inspections.into_iter().collect()),
                starts: AtomicUsize::new(0),
                start,
                before_start: Mutex::new(None),
            }
        }

        fn with_before_start(self, before_start: impl Fn() + Send + Sync + 'static) -> Self {
            *self.before_start.lock().unwrap() = Some(Arc::new(before_start));
            self
        }

        fn next(
            &self,
            expected: &super::super::vmm_process::VmmProcessExpectation,
        ) -> VmmProcessInspection {
            match self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .expect("fake VMM inspection exhausted")
            {
                VmmInspectionKind::Absent => VmmProcessInspection::Absent,
                VmmInspectionKind::Exact => {
                    VmmProcessInspection::Exact(Box::new(expected.exact_evidence_for_test(71)))
                }
                VmmInspectionKind::Conflict => {
                    VmmProcessInspection::Conflict(VmmProcessConflict::DuplicateIdentity)
                }
                VmmInspectionKind::Unavailable => VmmProcessInspection::Unavailable,
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl vmm_process_sealed::Sealed for FakePhysicalVmmPort {}

    #[cfg(target_os = "linux")]
    impl VmmProcessPort for FakePhysicalVmmPort {
        fn inspect(
            &self,
            expected: &super::super::vmm_process::VmmProcessExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> Result<VmmProcessInspection> {
            Ok(self.next(expected))
        }

        fn start_checkpointed(
            &self,
            checkpointed: CheckpointedVmmProcess<'_>,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<VmmProcessStart> {
            context.check_active()?;
            checkpointed.assert_current()?;
            if let Some(before_start) = self.before_start.lock().unwrap().take() {
                before_start();
            }
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(self.start)
        }
    }

    #[cfg(target_os = "linux")]
    impl vmm_global_sealed::Sealed for FakePhysicalVmmPort {}

    #[cfg(target_os = "linux")]
    impl VmmProcessGlobalPort for FakePhysicalVmmPort {
        fn inspect_vmm_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &super::super::vmm_process::VmmProcessExpectation,
            _context: &RuntimeDesiredEffectContext,
        ) -> Result<VmmProcessGlobalInspection> {
            Ok(match self.next(expected) {
                VmmProcessInspection::Absent => VmmProcessGlobalInspection::Absent(Box::new(
                    super::super::vmm_process::ExactVmmProcessAbsenceProof::for_expectation(
                        expected.clone(),
                    ),
                )),
                VmmProcessInspection::Exact(evidence) => VmmProcessGlobalInspection::Exact(
                    Box::new(expected.clone().prove_exact_process(*evidence)?),
                ),
                VmmProcessInspection::Conflict(problem) => {
                    VmmProcessGlobalInspection::Conflict(problem)
                }
                VmmProcessInspection::Unavailable => VmmProcessGlobalInspection::Unavailable,
            })
        }

        fn inspect_vmm_gate_successor_exact_after_node_global_sweep(
            &self,
            admitted_predecessor: &super::super::vmm_process::ExactVmmProcessProof,
            successor_proof: &super::super::vmm_process::VmmGateSuccessorProof,
            _context: &RuntimeDesiredEffectContext,
        ) -> Result<VmmProcessGlobalInspection> {
            let successor = successor_proof.validate_for(admitted_predecessor)?;
            Ok(match self.next(successor) {
                VmmProcessInspection::Absent => VmmProcessGlobalInspection::Absent(Box::new(
                    super::super::vmm_process::ExactVmmProcessAbsenceProof::for_expectation(
                        successor.clone(),
                    ),
                )),
                VmmProcessInspection::Exact(evidence) => VmmProcessGlobalInspection::Exact(
                    Box::new(successor.clone().prove_exact_process(*evidence)?),
                ),
                VmmProcessInspection::Conflict(problem) => {
                    VmmProcessGlobalInspection::Conflict(problem)
                }
                VmmProcessInspection::Unavailable => VmmProcessGlobalInspection::Unavailable,
            })
        }
    }

    #[derive(Clone, Copy)]
    enum KernelAttachBehavior {
        OutcomeUnknown,
        Conflict,
        Cancelled,
    }

    struct FakeKernelNbdAttachPort {
        behavior: KernelAttachBehavior,
        calls: AtomicUsize,
    }

    impl kernel_attach_sealed::Sealed for FakeKernelNbdAttachPort {}

    impl KernelNbdAttachPort for FakeKernelNbdAttachPort {
        fn attach_checkpointed(
            &self,
            _request: &KernelNbdAttachRequest,
            _listener: &dyn RetainedKernelNbdListenerGuard,
            _admitted_exact_devices: &[&super::super::kernel_nbd::ExactKernelNbdDeviceProof],
            _store: &FileCheckpointStore,
            _stored: &StoredCheckpoint,
            context: &RuntimeDesiredEffectContext,
        ) -> Result<KernelNbdAttachResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(match self.behavior {
                KernelAttachBehavior::OutcomeUnknown => KernelNbdAttachResult::OutcomeUnknown,
                KernelAttachBehavior::Conflict => KernelNbdAttachResult::ConflictAfterSubmit(
                    KernelNbdAttachConflict::LiveClientIdentity,
                ),
                KernelAttachBehavior::Cancelled => {
                    context.cancel_for_test();
                    KernelNbdAttachResult::OutcomeUnknown
                }
            })
        }
    }

    #[derive(Clone, Copy)]
    enum NetworkTapBehavior {
        Publish,
        CancelAfterCreate,
        LosePublishResponse,
    }

    #[derive(Default)]
    struct NetworkTapEvents {
        creates: AtomicUsize,
        publish_attempts: AtomicUsize,
        unpublished_drops: AtomicUsize,
    }

    struct NetworkTapPort {
        behavior: NetworkTapBehavior,
        context: RuntimeDesiredEffectContext,
        events: Arc<NetworkTapEvents>,
    }

    struct NetworkPendingTap {
        lose_response: bool,
        published: bool,
        events: Arc<NetworkTapEvents>,
    }

    impl PendingTap for NetworkPendingTap {
        fn configure(
            &mut self,
            _ip_bin: &Path,
            _network: &ChNetwork,
            effect_context: &RuntimeDesiredEffectContext,
        ) -> Result<()> {
            effect_context.check_active()
        }

        fn publish(mut self: Box<Self>) -> Result<()> {
            self.events.publish_attempts.fetch_add(1, Ordering::SeqCst);
            if self.lose_response {
                anyhow::bail!("injected TAP publish response loss")
            }
            self.published = true;
            Ok(())
        }
    }

    impl Drop for NetworkPendingTap {
        fn drop(&mut self) {
            if !self.published {
                self.events.unpublished_drops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    impl TapCreatePort for NetworkTapPort {
        fn create_nonpersistent(&self, _tap_name: &str) -> Result<Box<dyn PendingTap>> {
            self.events.creates.fetch_add(1, Ordering::SeqCst);
            if matches!(self.behavior, NetworkTapBehavior::CancelAfterCreate) {
                self.context.cancel_for_test();
            }
            Ok(Box::new(NetworkPendingTap {
                lose_response: matches!(self.behavior, NetworkTapBehavior::LosePublishResponse),
                published: false,
                events: Arc::clone(&self.events),
            }))
        }
    }

    fn serving_effect(
        fixture: &Fixture,
        port: Arc<FakeServingBlockdPort>,
    ) -> ServingBlockdStartEffect {
        ServingBlockdStartEffect::new(
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            serving_systemd_config(fixture),
            port,
        )
    }

    fn accepted_serving_process(
        fixture: &Fixture,
    ) -> cats_api::runtime_reconciliation::ProcessEvidence {
        let expected = serving_expectation(fixture);
        expected
            .clone()
            .prove_exact_process(expected.exact_evidence_for_test(51))
            .unwrap()
            .into_process_evidence()
    }

    fn accepted_vmm_process(
        fixture: &Fixture,
    ) -> cats_api::runtime_reconciliation::ProcessEvidence {
        let checkpoint_path = host(
            super::super::runtime_checkpoint_path(
                &fixture.checkpoint_directory,
                &fixture.stored_checkpoint.checkpoint().cat_id,
            )
            .to_str()
            .unwrap(),
        );
        let expected = super::super::vmm_process::VmmProcessExpectation::from_checkpoint(
            fixture.stored_checkpoint.checkpoint().clone(),
        )
        .unwrap()
        .with_checkpoint_path(checkpoint_path)
        .unwrap();
        expected
            .clone()
            .prove_exact_process(expected.exact_evidence_for_test(71))
            .unwrap()
            .into_process_evidence()
    }

    fn empty_ip_binary(fixture: &Fixture) -> PathBuf {
        let path = fixture.data_directory.join("test-ip");
        std::fs::write(
            &path,
            "#!/bin/sh\nif [ \"$1\" = '-j' ]; then printf '[]'; fi\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn exact_ip_binary(fixture: &Fixture, checkpoint: &RuntimeCheckpoint) -> PathBuf {
        let network = match &checkpoint.step {
            ReconcileStep::PrepareNetwork { network, .. } => network,
            ReconcileStep::StartRuntime { network, .. } => network.as_ref(),
            _ => panic!("exact ip fixture requires PrepareNetwork or StartRuntime"),
        };
        let path = fixture.data_directory.join("test-ip-exact");
        let alias = format!(
            "cats-network:{}:{}",
            network.network_config.network_id, network.ownership_token
        );
        let links = format!(
            r#"[{{"ifindex":17,"ifname":"{}","flags":["UP"],"ifalias":"{}","linkinfo":{{"info_kind":"tun","info_data":{{"type":"tap"}}}}}}]"#,
            network.tap_name, alias
        );
        let addresses = format!(
            r#"[{{"ifindex":17,"ifname":"{}","addr_info":[{{"family":"inet","local":"{}","prefixlen":30}}]}}]"#,
            network.tap_name, network.network_config.gateway_ipv4
        );
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nif [ \"$2\" = '-d' ]; then printf '%s' '{links}'; else printf '%s' '{addresses}'; fi\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    struct FixedLaunchArtifactPort {
        launcher: RuntimeLaunchArtifact,
        boot: VmmBootProvenance,
        assertions: Arc<AtomicUsize>,
        fail_on_assertion: Option<usize>,
    }

    struct FixedRetainedLaunchArtifacts {
        launcher: RuntimeLaunchArtifact,
        boot: VmmBootProvenance,
        assertions: Arc<AtomicUsize>,
        fail_on_assertion: Option<usize>,
    }

    impl LaunchArtifactAuthorityPort for FixedLaunchArtifactPort {
        fn retain(&self) -> Result<Box<dyn RetainedLaunchArtifactAuthority>> {
            Ok(Box::new(FixedRetainedLaunchArtifacts {
                launcher: self.launcher.clone(),
                boot: self.boot.clone(),
                assertions: Arc::clone(&self.assertions),
                fail_on_assertion: self.fail_on_assertion,
            }))
        }
    }

    impl RetainedLaunchArtifactAuthority for FixedRetainedLaunchArtifacts {
        fn launcher_executable(&self) -> RuntimeLaunchArtifact {
            self.launcher.clone()
        }

        fn boot(&self) -> VmmBootProvenance {
            self.boot.clone()
        }

        fn assert_current(&self) -> Result<()> {
            let assertion = self.assertions.fetch_add(1, Ordering::SeqCst) + 1;
            anyhow::ensure!(
                self.fail_on_assertion != Some(assertion),
                "injected installed VMM artifact ABA"
            );
            Ok(())
        }
    }

    fn fixed_launch_artifacts(
        fail_on_assertion: Option<usize>,
    ) -> (Arc<FixedLaunchArtifactPort>, Arc<AtomicUsize>) {
        let template = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        let ReconcileStep::StartRuntime {
            launcher_executable,
            boot,
            ..
        } = template.step
        else {
            unreachable!()
        };
        let assertions = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(FixedLaunchArtifactPort {
                launcher: *launcher_executable,
                boot: *boot,
                assertions: Arc::clone(&assertions),
                fail_on_assertion,
            }),
            assertions,
        )
    }

    fn advance_fixture_to_start_runtime(fixture: &mut Fixture) {
        advance_fixture_to_prepare_network(fixture);
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let serving = Arc::new(FakeServingBlockdPort::new(
            std::iter::repeat_n(ServingBlockdProcessInspectionKind::Exact, 16),
            ServingBlockdProcessStart::Submitted,
        ));
        let network = Arc::new(
            PrepareNetworkReservationEffect::new(
                fixture.state_directory.clone(),
                exact_ip_binary(fixture, fixture.stored_checkpoint.checkpoint()),
                Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&serving) as Arc<dyn ServingBlockdProcessGlobalPort>,
            )
            .unwrap(),
        );
        let (artifacts, _) = fixed_launch_artifacts(None);
        let reservation = StartRuntimeReservationEffect::for_test(
            fixture.state_directory.clone(),
            network,
            Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
            serving,
            artifacts,
        );
        let context = with_exact_network_admission(
            effect_context_with_processes(fixture, vec![accepted_serving_process(fixture)]),
            fixture.stored_checkpoint.checkpoint(),
        );
        assert_eq!(
            reservation
                .try_apply(&context, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        fixture.stored_checkpoint = current_runtime_checkpoint(fixture);
        assert!(matches!(
            fixture.stored_checkpoint.checkpoint().step,
            ReconcileStep::StartRuntime { .. }
        ));
    }

    fn revalidate_retained_running_fixture(
        fixture: &Fixture,
        authority_record: VolumeRecord,
        serving_inspection: ServingBlockdProcessInspectionKind,
        vmm_inspection: RunningVmmInspectionKind,
    ) -> Result<()> {
        let context = with_exact_network_admission(
            effect_context_with_processes(
                fixture,
                vec![
                    accepted_vmm_process(fixture),
                    accepted_serving_process(fixture),
                ],
            ),
            fixture.stored_checkpoint.checkpoint(),
        );
        let authority = Arc::new(FixedEffectAuthority::new(authority_record));
        let serving = Arc::new(FakeServingBlockdPort::new(
            [serving_inspection],
            ServingBlockdProcessStart::Submitted,
        ));
        let network = Arc::new(PrepareNetworkReservationEffect::new(
            fixture.state_directory.clone(),
            exact_ip_binary(fixture, fixture.stored_checkpoint.checkpoint()),
            Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&serving) as Arc<dyn ServingBlockdProcessGlobalPort>,
        )?);
        let vmm = Arc::new(FakeRunningVmmPort::new([vmm_inspection]));
        let revalidator = RunningLaunchAuthorityRevalidator::platform_parts(
            fixture.state_directory.clone(),
            serving_systemd_config(fixture),
            network,
            authority,
            serving,
            vmm,
            None,
        );
        let store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )?;
        let admitted_vmm = context
            .node_global_process()?
            .vmm(&fixture.acquired.desired.cat_id)
            .and_then(|(_, exact)| exact)
            .context("test Running admission lacks exact VMM")?;
        revalidator.revalidate_exact_retained_running(
            &context,
            &fixture.acquired.desired,
            &store,
            &fixture.stored_checkpoint,
            admitted_vmm,
        )
    }

    #[cfg(target_os = "linux")]
    fn physical_guest_config_digest() -> Sha256Digest {
        guest_config_digest(&GuestRuntimeProfileReceipt {
            version: ContractVersion::V1,
            kernel_digest: Sha256Digest::from_bytes(Sha256::digest(b"kernel").into()),
            initramfs_digest: Some(Sha256Digest::from_bytes(
                Sha256::digest(b"initramfs").into(),
            )),
            kernel_cmdline: AsciiText::new("console=ttyS0 panic=1").unwrap(),
            guest_agent_protocol_version: ContractVersion::V1,
        })
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn physical_launch_artifacts(
        fixture: &Fixture,
    ) -> (
        PathBuf,
        VmmLaunchArtifactPaths,
        Arc<FixedLaunchArtifactPort>,
    ) {
        let root = fixture.data_directory.join("physical-artifacts");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, mode, bytes) in [
            ("launcher", 0o755, b"launcher".as_slice()),
            ("cloud-hypervisor", 0o755, b"cloud-hypervisor".as_slice()),
            ("kernel", 0o644, b"kernel".as_slice()),
            ("initramfs", 0o644, b"initramfs".as_slice()),
        ] {
            let path = root.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let paths = VmmLaunchArtifactPaths {
            launcher_executable: PathBuf::from("/launcher"),
            vmm_executable: PathBuf::from("/cloud-hypervisor"),
            kernel: PathBuf::from("/kernel"),
            initramfs: Some(PathBuf::from("/initramfs")),
            kernel_cmdline: "console=ttyS0 panic=1".to_owned(),
        };
        let retained = RetainedVmmLaunchArtifacts::open_for_test(&root, &paths).unwrap();
        let assertions = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(FixedLaunchArtifactPort {
            launcher: retained.launcher_executable().clone(),
            boot: retained.boot(),
            assertions,
            fail_on_assertion: None,
        });
        (root, paths, port)
    }

    #[cfg(target_os = "linux")]
    struct PhysicalStartFixture {
        _socket_directory: tempfile::TempDir,
        artifact_root: PathBuf,
        artifact_paths: VmmLaunchArtifactPaths,
        network: Arc<PrepareNetworkReservationEffect>,
        authority: Arc<FixedEffectAuthority>,
        serving: Arc<FakeServingBlockdPort>,
        socket_root: Arc<RetainedManagedVmmSocketRoot>,
        launch_root: Arc<RetainedManagedVmmLaunchRoot>,
        receipts: Arc<VmmSocketReceiptStore>,
    }

    #[cfg(target_os = "linux")]
    fn advance_fixture_to_physical_start(fixture: &mut Fixture) -> PhysicalStartFixture {
        advance_fixture_to_prepare_network(fixture);
        let launch_namespace = fixture
            .state_directory
            .path()
            .join(VMM_LAUNCH_FILE_NAMESPACE);
        std::fs::create_dir(&launch_namespace).unwrap();
        std::fs::set_permissions(&launch_namespace, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        // AF_UNIX paths have a small fixed bound. Keep the test-owned public
        // socket namespace directly below the platform temporary directory,
        // rather than below the deliberately verbose fixture path.
        let socket_directory = tempfile::tempdir().unwrap();
        let socket_root = Arc::new(
            RetainedManagedVmmSocketRoot::provision_for_test(&socket_directory.path().join("vmm"))
                .unwrap(),
        );
        let launch_root = Arc::new(
            RetainedManagedVmmLaunchRoot::open_existing(fixture.state_directory.clone()).unwrap(),
        );
        let receipts = Arc::new(
            VmmSocketReceiptStore::provision_for_test(fixture.state_directory.clone()).unwrap(),
        );
        let (artifact_root, artifact_paths, artifact_port) = physical_launch_artifacts(fixture);
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let serving = Arc::new(FakeServingBlockdPort::new(
            std::iter::repeat_n(ServingBlockdProcessInspectionKind::Exact, 128),
            ServingBlockdProcessStart::Submitted,
        ));
        let network = Arc::new(
            PrepareNetworkReservationEffect::new(
                fixture.state_directory.clone(),
                exact_ip_binary(fixture, fixture.stored_checkpoint.checkpoint()),
                Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&serving) as Arc<dyn ServingBlockdProcessGlobalPort>,
            )
            .unwrap(),
        );
        let reservation = StartRuntimeReservationEffect::for_test(
            fixture.state_directory.clone(),
            Arc::clone(&network),
            Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&serving) as Arc<dyn ServingBlockdProcessGlobalPort>,
            artifact_port,
        )
        .with_socket_root_for_test(socket_root.planner().clone());
        let context = with_exact_network_admission(
            effect_context_with_processes(fixture, vec![accepted_serving_process(fixture)]),
            fixture.stored_checkpoint.checkpoint(),
        );
        let reservation_outcome = reservation.try_apply(&context, &fixture.acquired.desired);
        assert!(reservation_outcome.is_ok(), "{reservation_outcome:#?}");
        assert_eq!(
            reservation_outcome.unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        fixture.stored_checkpoint = current_runtime_checkpoint(fixture);
        assert!(matches!(
            fixture.stored_checkpoint.checkpoint().step,
            ReconcileStep::StartRuntime { .. }
        ));
        PhysicalStartFixture {
            _socket_directory: socket_directory,
            artifact_root,
            artifact_paths,
            network,
            authority,
            serving,
            socket_root,
            launch_root,
            receipts,
        }
    }

    #[cfg(target_os = "linux")]
    fn physical_start_effect(
        fixture: &Fixture,
        physical: &PhysicalStartFixture,
        vmm: Arc<FakePhysicalVmmPort>,
    ) -> StartRuntimePhysicalEffect {
        StartRuntimePhysicalEffect::for_test(
            fixture.state_directory.clone(),
            physical.artifact_paths.clone(),
            physical.artifact_root.clone(),
            Arc::clone(&physical.network),
            Arc::clone(&physical.authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&physical.serving) as Arc<dyn ServingBlockdProcessGlobalPort>,
            vmm,
            Arc::clone(&physical.socket_root),
            Arc::clone(&physical.launch_root),
            Arc::clone(&physical.receipts),
        )
    }

    #[cfg(target_os = "linux")]
    fn assert_no_physical_launch_residue(fixture: &Fixture, physical: &PhysicalStartFixture) {
        let checkpoint = fixture.stored_checkpoint.checkpoint();
        let incarnation = checkpoint.runtime_incarnation.as_ref().unwrap();
        assert!(physical.receipts.load(incarnation).unwrap().is_none());
        let launch_paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(&fixture.state_directory, checkpoint)
                .unwrap();
        assert!(!Path::new(launch_paths.directory().as_str()).exists());
    }

    fn current_runtime_checkpoint(fixture: &Fixture) -> StoredCheckpoint {
        FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap()
        .load()
        .unwrap()
        .unwrap()
    }

    fn with_absent_network_admission(
        context: RuntimeDesiredEffectContext,
        checkpoint: &RuntimeCheckpoint,
    ) -> RuntimeDesiredEffectContext {
        let scan = NodeGlobalNetworkScanAdmission::absent_checkpoint_for_test(checkpoint).unwrap();
        let admission = scan
            .bind(context.accepted_full().unwrap().observation())
            .unwrap();
        context.with_node_global_network_for_test(admission)
    }

    fn with_exact_network_admission(
        context: RuntimeDesiredEffectContext,
        checkpoint: &RuntimeCheckpoint,
    ) -> RuntimeDesiredEffectContext {
        let network = match &checkpoint.step {
            ReconcileStep::PrepareNetwork { network, .. } => network,
            ReconcileStep::StartRuntime { network, .. } => network.as_ref(),
            _ => panic!("exact network test admission requires PrepareNetwork or StartRuntime"),
        };
        let node_global_process = context.node_global_process().unwrap().clone();
        let mut observation = context.accepted_full().unwrap().observation().clone();
        let [runtime] = observation.runtimes.as_mut_slice() else {
            panic!("network test admission requires one Runtime")
        };
        runtime.networks = vec![ObservedNetwork {
            kind: network.network_config.kind,
            network_id: network.network_config.network_id.clone(),
            guest_mac: network.network_config.guest_mac.clone(),
            guest_ipv4: network.network_config.guest_ipv4.clone(),
            prefix_length: network.network_config.prefix_length,
            gateway_ipv4: network.network_config.gateway_ipv4.clone(),
            tap_name: network.tap_name.clone(),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: network.ownership_token.clone(),
            },
        }];
        let node_global_process = node_global_process.rebind_for_test(&observation).unwrap();
        let admission = context
            .accepted_full()
            .unwrap()
            .clone()
            .with_observation_for_test(observation);
        let context = RuntimeDesiredEffectContext::for_test_with_admission(
            context.state_directory().clone(),
            Instant::now() + Duration::from_secs(10),
            admission,
        )
        .with_node_global_process_for_test(node_global_process);
        let scan = NodeGlobalNetworkScanAdmission::exact_checkpoint_for_test(checkpoint).unwrap();
        let admission = scan
            .bind(context.accepted_full().unwrap().observation())
            .unwrap();
        context.with_node_global_network_for_test(admission)
    }

    fn with_exact_kernel_nbd_admission(
        fixture: &Fixture,
        base: RuntimeDesiredEffectContext,
    ) -> RuntimeDesiredEffectContext {
        let node_global_process = base.node_global_process().unwrap().clone();
        let mut observation = base.accepted_full().unwrap().observation().clone();
        let prepared = prepared_device_input(fixture.stored_checkpoint.checkpoint()).unwrap();
        let PrepareDeviceFrontend::KernelNbd { device_path, .. } = &prepared.frontend else {
            panic!("kernel-NBD test admission requires a kernel-NBD checkpoint")
        };
        observation.runtimes[0].volumes[0].devices = vec![ObservedDevice::KernelNbd {
            guest_device: prepared.guest_device.clone(),
            device_path: device_path.clone(),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: prepared.ownership_token.clone(),
            },
        }];
        let node_global_process = node_global_process.rebind_for_test(&observation).unwrap();
        let admission = base
            .accepted_full()
            .unwrap()
            .clone()
            .with_observation_for_test(observation);
        let context = RuntimeDesiredEffectContext::for_test_with_admission(
            fixture.state_directory.clone(),
            Instant::now() + Duration::from_secs(10),
            admission,
        )
        .with_node_global_process_for_test(node_global_process);
        let expected = serving_expectation(fixture);
        let listener = expected
            .clone()
            .prove_exact_process(expected.exact_evidence_for_test(51))
            .unwrap()
            .listener_proof();
        let pool = KernelNbdPoolScanAdmission::exact_for_test(
            context.accepted_full().unwrap().observation(),
            fixture.stored_checkpoint.checkpoint(),
            listener,
        )
        .unwrap();
        context.with_kernel_nbd_pool_for_test(pool)
    }

    fn prepare_network_reservation_effect(
        fixture: &Fixture,
        authority: Arc<dyn VolumeDataAuthority>,
        port: Arc<FakeServingBlockdPort>,
    ) -> PrepareNetworkReservationEffect {
        PrepareNetworkReservationEffect::new(
            fixture.state_directory.clone(),
            empty_ip_binary(fixture),
            authority,
            port,
        )
        .unwrap()
    }

    fn advance_fixture_to_prepare_network(fixture: &mut Fixture) {
        complete_old_process_retirement(fixture);
        let process = Arc::new(FakeServingBlockdPort::new(
            [
                ServingBlockdProcessInspectionKind::Exact,
                ServingBlockdProcessInspectionKind::Exact,
            ],
            ServingBlockdProcessStart::Submitted,
        ));
        let effect = prepare_network_reservation_effect(
            fixture,
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            process,
        );
        assert_eq!(
            effect
                .try_apply(
                    &effect_context_with_processes(
                        fixture,
                        vec![accepted_serving_process(fixture)],
                    ),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        fixture.stored_checkpoint = current_runtime_checkpoint(fixture);
        assert!(matches!(
            fixture.stored_checkpoint.checkpoint().step,
            ReconcileStep::PrepareNetwork { .. }
        ));
    }

    fn prepare_device_retirement_effect(
        fixture: &Fixture,
        global: Arc<dyn RootProvisionProcessGlobalPort>,
        process: Arc<dyn RootProvisionProcessPort>,
    ) -> PrepareDeviceTargetRetirementEffect {
        PrepareDeviceTargetRetirementEffect::for_test(
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            global,
            process,
        )
    }

    fn fixture() -> Fixture {
        fixture_with_guest_config_digest(
            Sha256Digest::new(
                "sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2",
            )
            .unwrap(),
        )
    }

    fn fixture_with_guest_config_digest(guest_config_digest: Sha256Digest) -> Fixture {
        let root = tempfile::tempdir().expect("create serving handoff fixture");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state_directory = StateDirectory::unanchored(root.path().to_path_buf());
        let transition_id = random('1');
        let expected_unowned_epoch = FenceEpoch::new(6).unwrap();
        let attachment_epoch = FenceEpoch::new(7).unwrap();
        let desired_revision = Revision::new(11).unwrap();
        let placement_epoch = Epoch::new(3).unwrap();
        let volume = VolumeIntent {
            volume_intent_id: id("root_intent"),
            disk_id: id("root_disk"),
            volume_id: id("vol_root"),
            attachment_id: id("att_root"),
            size_bytes: cats_api::chunk::CHUNK_SIZE as u64,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats_root"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: transition_id.clone(),
                expected_unowned_epoch,
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        };
        let mut desired = cats_api::runtime_reconciliation::DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: id("ws_01"),
            cat_id: id("cat_01"),
            desired_revision,
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: id("node_a"),
                placement_epoch,
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                boot_image_digest: digest('a'),
                guest_config_digest,
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("network_a"),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: vec![volume.clone()],
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: digest('c'),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let acquire_request = NormalAcquireRequest {
            volume_id: volume.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            expected_unowned_epoch,
            desired_revision,
            placement_epoch,
            lease_duration_ms: 60_000,
        };
        let acquire_result = NormalAcquireResult {
            volume_id: volume.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            resulting_epoch: attachment_epoch,
            resulting_head: blank_head(),
            lease_expires_at: UnixMillis::new(1_720_000_060_000).unwrap(),
        };
        let blank_attachment = AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch,
                acquire_origin: AcquireOrigin::Normal { transition_id },
                node_id: desired.placement.node_id.clone(),
                placement_epoch,
            },
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            head: blank_head(),
            lease_expires_at: acquire_result.lease_expires_at,
            acquire: cats_storage::authority::AuthorizedServingAcquire::Normal {
                request: acquire_request.clone(),
                result: acquire_result.clone(),
            },
        };
        let prepared = AuthorizedBlockdStore::new(state_directory.clone())
            .prepare(&desired, &volume, &blank_attachment)
            .expect("persist acquire-time blockd inputs");
        let data_directory = prepared.data_directory().to_path_buf();
        let blank_authorization_path = prepared.authorized_serving_path().to_path_buf();
        let acquired = prepared.checkpoint().clone();
        drop(prepared);

        let process_identity_token = random('4');
        let scope_id = id(&format!(
            "cats-root-{}.service",
            process_identity_token.as_str()
        ));
        let data_directory_host = host(data_directory.to_str().unwrap());
        let provision_transition_id = random('3');
        let control_socket_path = managed_root_control_socket(&provision_transition_id);
        let target = target_head();
        let checkpoint = RuntimeCheckpoint {
            version: ContractVersion::V1,
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            placement_epoch,
            desired_revision,
            spec_digest: desired.spec_digest.clone(),
            runtime_incarnation: None,
            runtime_launch: cats_api::runtime_reconciliation::RuntimeLaunch::Absent,
            stable_state: None,
            step: ReconcileStep::ProvisionRootImage {
                provision_transition_id: provision_transition_id.clone(),
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch,
                scope_id: scope_id.clone(),
                control_socket_path: control_socket_path.clone(),
                data_directory: data_directory_host.clone(),
                process_identity_token: process_identity_token.clone(),
                size_bytes: volume.size_bytes,
                boot_image_digest: desired.runtime.boot_image_digest.clone(),
                expected_blank_head: blank_head(),
                expected_provisioned_head: target.clone(),
            },
            processes: Vec::new(),
            volumes: vec![prepared_owned_observed_volume(
                &volume,
                &blank_attachment,
                data_directory_host.clone(),
            )],
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            route_gates: Vec::new(),
            require_idle: RequireIdleCheckpoint::NotApplicable,
            updated_at_unix_ms: UnixMillis::new(1_720_000_000_000).unwrap(),
        };
        let managed_root = Arc::new(IsolatedManagedRootOwner::new(&checkpoint));
        encode_runtime_checkpoint(&checkpoint).expect("fixture checkpoint is valid");
        let checkpoint_directory = root
            .path()
            .join(super::super::clean_slate_probes::CHECKPOINT_NAMESPACE);
        let checkpoint_store =
            FileCheckpointStore::open(&checkpoint_directory, &checkpoint.cat_id).unwrap();
        let stored_checkpoint = checkpoint_store.create(&checkpoint).unwrap();
        drop(checkpoint_store);
        let authority_record = VolumeRecord {
            volume_id: volume.volume_id.clone(),
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            admin_state: VolumeAdminState::Active,
            head: target.clone(),
            lease_owner: Some(volume.attachment_id.clone()),
            lease_epoch: attachment_epoch,
            // A legal renew may have advanced this after acquire.
            lease_expires_at: Some(UnixMillis::new(1_720_000_120_000).unwrap()),
            last_transition: Some(LastVolumeTransition::NormalAcquire {
                request: acquire_request,
                result: acquire_result,
            }),
        };
        let authority =
            ServingAuthorityTargetEvidence::new(provision_transition_id, authority_record);
        let expected_executable_path = host("/opt/cats/bin/cats-blockd");
        let process = RootProvisionProcessEvidence {
            process_id: 4321,
            unit_main_process_id: 4321,
            process_start_time_ticks: WireU64::new(998_877).unwrap(),
            executable_path: expected_executable_path.clone(),
            scope_id: scope_id.clone(),
            cgroup_path: host(&format!(
                "/sys/fs/cgroup/system.slice/{}",
                scope_id.as_str()
            )),
            cgroup_process_ids: vec![4321],
            control_socket_path,
            data_directory: data_directory_host,
            ownership_token: process_identity_token.clone(),
            handshake: RootProvisionBlockdHandshake {
                peer_process_id: 4321,
                identity: blank_attachment.identity,
                size_bytes: volume.size_bytes,
                durability: volume.durability,
                remote_head: target,
                process_identity_token,
                control_only: true,
                guest_io_enabled: false,
            },
        };
        Fixture {
            _root: root,
            managed_root,
            state_directory,
            checkpoint_directory,
            data_directory,
            blank_authorization_path,
            stored_checkpoint,
            acquired,
            authority,
            expected_executable_path,
            process,
        }
    }

    fn assert_target_context_mutation_rejected(mutate: impl FnOnce(&mut RuntimeCheckpoint)) {
        let mut fixture = fixture();
        let store = fixture.store();
        let control = store
            .seal_target_control_authorization(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
            )
            .unwrap();
        let original_digest = control.identity().artifact.provision_context_digest.clone();
        let mut changed = fixture.stored_checkpoint.checkpoint().clone();
        mutate(&mut changed);
        assert_ne!(
            provision_root_authorization_context_digest(&changed).unwrap(),
            original_digest
        );
        changed.updated_at_unix_ms =
            UnixMillis::new(changed.updated_at_unix_ms.get().checked_add(1).unwrap()).unwrap();
        fixture.replace_checkpoint(changed);
        assert!(control.assert_current(&fixture.stored_checkpoint).is_err());
        drop(control);
        assert!(store
            .seal_target_control_authorization(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
            )
            .is_err());
    }

    #[test]
    fn target_with_absent_process_seals_control_recovery_then_exact_reload_seals_ready() {
        let fixture = fixture();
        let blank_before = std::fs::read(&fixture.blank_authorization_path).unwrap();
        let blank_inode = std::fs::metadata(&fixture.blank_authorization_path)
            .unwrap()
            .ino();
        let store = fixture.store();

        // Authority is already at target while the process is conceptually
        // absent. This first phase needs no process evidence and cannot create
        // a serving-ready record.
        let control = store
            .seal_target_control_authorization(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
            )
            .expect("seal target control recovery grant");
        assert_eq!(
            control.identity().artifact.attachment.head,
            fixture.authority.volume.head
        );
        assert_eq!(
            control.identity().artifact.provision_transition_id,
            fixture.authority.provision_transition_id
        );
        assert_eq!(
            control.identity().path.as_str(),
            fixture.target_path().to_str().unwrap()
        );
        assert!(fixture.target_path().exists());
        assert!(!fixture.record_path().exists());
        assert_eq!(
            decode_target_control_authorization(&std::fs::read(fixture.target_path()).unwrap())
                .unwrap(),
            control.identity().artifact
        );
        let control_identity = control.identity().clone();
        control
            .assert_current(&fixture.stored_checkpoint)
            .expect("target-control proof remains current");
        drop(control);

        let ReopenedTargetControlAuthorization::Exact(reopened) = store
            .reopen_target_control_authorization(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
            )
            .expect("reopen exact target control recovery grant")
        else {
            panic!("published target authorization must reopen exact")
        };
        let ReopenedServingHandoff::Absent(reopened) = store
            .reopen_serving_handoff(&fixture.stored_checkpoint, *reopened)
            .expect("classify absent handoff record under retained target")
        else {
            panic!("record must be absent before the seal effect")
        };
        let ready = store
            .seal_serving_ready_from_target(
                *reopened,
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &fixture.exact_process_proof().unwrap(),
            )
            .expect("seal serving ready after exact target reload");
        assert_eq!(ready.target_control_authorization(), &control_identity);
        assert_eq!(ready.old_control_process().process_id.get(), 4321);
        assert_eq!(
            ready.record_path().as_str(),
            fixture.record_path().to_str().unwrap()
        );
        assert_eq!(
            ready.record_identity().content_sha256(),
            &Sha256Digest::from_bytes(
                Sha256::digest(std::fs::read(fixture.record_path()).unwrap()).into()
            )
        );
        assert_eq!(
            decode_serving_handoff_record(&std::fs::read(fixture.record_path()).unwrap()).unwrap(),
            *ready.record()
        );
        drop(ready);

        let ReopenedTargetControlAuthorization::Exact(reopened) = store
            .reopen_target_control_authorization(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
            )
            .unwrap()
        else {
            panic!("target must remain exact")
        };
        let ReopenedServingHandoff::Exact(ready) = store
            .reopen_serving_handoff(&fixture.stored_checkpoint, *reopened)
            .expect("reopen exact sealed handoff")
        else {
            panic!("sealed handoff must reopen Ready")
        };
        ready.assert_current(&fixture.stored_checkpoint).unwrap();

        assert_eq!(
            std::fs::read(&fixture.blank_authorization_path).unwrap(),
            blank_before
        );
        assert_eq!(
            std::fs::metadata(&fixture.blank_authorization_path)
                .unwrap()
                .ino(),
            blank_inode
        );

        let target_inode = std::fs::metadata(fixture.target_path()).unwrap().ino();
        let record_inode = std::fs::metadata(fixture.record_path()).unwrap().ino();
        ready
            .assert_current(&fixture.stored_checkpoint)
            .expect("serving proof remains current before consume");
        let ready_record = ready.record().clone();
        drop(ready);
        let replay = store
            .seal_serving_ready(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &fixture.exact_process_proof().unwrap(),
            )
            .expect("exact serving handoff replay");
        assert_eq!(replay.record(), &ready_record);
        assert_eq!(
            std::fs::metadata(fixture.target_path()).unwrap().ino(),
            target_inode
        );
        assert_eq!(
            std::fs::metadata(fixture.record_path()).unwrap().ino(),
            record_inode
        );

        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let expected_record_identity = replay.record_identity().clone();
        let (replaced, successor) = replay
            .consume_for_prepare_device(&fixture.stored_checkpoint, |handoff| {
                assert_eq!(
                    &handoff.predecessor_checkpoint_content_digest,
                    fixture.stored_checkpoint.content_digest()
                );
                assert_eq!(&handoff.record.path, expected_record_identity.path());
                assert_eq!(handoff.record.device, expected_record_identity.device());
                assert_eq!(handoff.record.inode, expected_record_identity.inode());
                assert_eq!(handoff.record.length, expected_record_identity.length());
                assert_eq!(
                    &handoff.record.content_sha256,
                    expected_record_identity.content_sha256()
                );
                let successor = prepare_device_successor(&fixture, handoff);
                let replaced = checkpoint_store
                    .replace(&fixture.stored_checkpoint, &successor)
                    .context("atomically replace predecessor with PrepareDevice")?;
                assert_eq!(replaced.checkpoint(), &successor);
                assert!(fixture.record_path().exists());
                Ok((replaced, successor))
            })
            .expect("consume exact handoff with atomic PrepareDevice replace");
        let current = checkpoint_store.load().unwrap().unwrap();
        assert_eq!(current.content_digest(), replaced.content_digest());
        assert_eq!(current.checkpoint(), &successor);
        assert!(matches!(
            current.checkpoint().step,
            ReconcileStep::PrepareDevice { .. }
        ));
    }

    #[test]
    fn prepare_device_handoff_builds_only_the_strict_serving_from_handoff_command() {
        fn argument_after<'a>(arguments: &'a [String], flag: &str) -> &'a str {
            arguments
                .windows(2)
                .find_map(|pair| (pair[0] == flag).then_some(pair[1].as_str()))
                .unwrap_or_else(|| panic!("missing {flag}"))
        }

        let mut fixture = fixture();
        advance_fixture_to_prepare_device(&mut fixture);
        let retained = AuthorizedBlockdStore::new(fixture.state_directory.clone())
            .retain_prepare_device_handoff(
                fixture.stored_checkpoint.checkpoint(),
                &fixture.acquired.desired,
            )
            .expect("retain exact PrepareDevice attachment inputs");
        let ready = fixture
            .store()
            .reopen_prepare_device_handoff(
                fixture.stored_checkpoint.checkpoint(),
                &fixture.acquired.desired,
                &fixture.authority.volume,
                retained,
            )
            .expect("reopen sealed PrepareDevice handoff");
        let config = AuthorizedBlockdLaunchConfig {
            blockd_binary: PathBuf::from(fixture.expected_executable_path.as_str()),
            metadata_store: AdapterSelection::new(
                "postgres",
                AdapterConfig::from_pairs([("url-file", "/run/cats/postgres-url")]).unwrap(),
            ),
            object_store: AdapterSelection::new(
                "aws-s3",
                AdapterConfig::from_pairs([("bucket", "cats-runtime-test")]).unwrap(),
            ),
            max_staged_bytes: 101,
            max_staged_packs: 102,
            max_local_bytes: 103,
        };

        let command = ready
            .authorized_serving_command(
                &config,
                fixture.stored_checkpoint.checkpoint(),
                &fixture.acquired.desired,
                &fixture.authority.volume,
            )
            .expect("construct strict serving-from-handoff command");
        assert_eq!(command.get_program(), config.blockd_binary.as_os_str());
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let ReconcileStep::PrepareDevice { devices } = &fixture.stored_checkpoint.checkpoint().step
        else {
            panic!("fixture must have reached PrepareDevice")
        };
        let [device] = devices.as_slice() else {
            panic!("single-Root fixture must prepare one device")
        };
        let ServingAuthorityProvenance::AfterRootProvision { handoff } =
            device.serving_authority.as_ref()
        else {
            panic!("fixture must retain Root handoff provenance")
        };
        let PrepareDeviceFrontend::VhostUserBlk {
            socket_path,
            queues,
            queue_size,
        } = &device.frontend
        else {
            panic!("fixture must use vhost-user")
        };

        assert_eq!(
            argument_after(&arguments, "--authorized-serving-handoff-record"),
            handoff.record.path.as_str()
        );
        assert_eq!(
            argument_after(
                &arguments,
                "--authorized-serving-handoff-predecessor-checkpoint-content-digest"
            ),
            handoff.predecessor_checkpoint_content_digest.as_str()
        );
        assert_eq!(
            argument_after(&arguments, "--runtime-scope-id"),
            device.serving_process.scope_id.as_str()
        );
        assert_eq!(
            argument_after(&arguments, "--process-identity-token"),
            device.serving_process.process_identity_token.as_str()
        );
        assert_eq!(
            argument_after(&arguments, "--device-ownership-token"),
            device.ownership_token.as_str()
        );
        assert_eq!(
            argument_after(&arguments, "--guest-device-serial"),
            device.guest_device.serial.as_str()
        );
        assert_eq!(
            argument_after(&arguments, "--listen-control"),
            device.serving_process.control_socket_path.as_str()
        );
        assert_eq!(
            argument_after(&arguments, "--listen-vhost-user"),
            socket_path.as_str()
        );
        assert_eq!(
            argument_after(&arguments, "--vhost-user-queues"),
            queues.to_string()
        );
        assert_eq!(
            argument_after(&arguments, "--vhost-user-queue-size"),
            queue_size.to_string()
        );
        assert!(!arguments.iter().any(|argument| {
            matches!(
                argument.as_str(),
                "--authorized-serving-spec"
                    | "--authorized-control-spec"
                    | "--authorized-target-control-spec"
                    | "--control-only"
            )
        }));
        assert!(command
            .get_envs()
            .any(|(name, value)| { name == "CATS_CRASH_POINT" && value.is_none() }));

        let mut wrong_binary = config.clone();
        wrong_binary.blockd_binary = PathBuf::from("/opt/cats/bin/foreign-blockd");
        assert!(ready
            .authorized_serving_command(
                &wrong_binary,
                fixture.stored_checkpoint.checkpoint(),
                &fixture.acquired.desired,
                &fixture.authority.volume,
            )
            .is_err());
    }

    #[test]
    fn serving_blockd_response_loss_submits_once_then_requires_fresh_exact_projection() {
        let mut fixture = fixture();
        complete_old_process_retirement(&mut fixture);
        let expected = serving_expectation(&fixture);
        let accepted = expected
            .clone()
            .prove_exact_process(expected.exact_evidence_for_test(51))
            .unwrap()
            .into_process_evidence();
        let port = Arc::new(FakeServingBlockdPort::new(
            [
                ServingBlockdProcessInspectionKind::Absent,
                ServingBlockdProcessInspectionKind::Exact,
                ServingBlockdProcessInspectionKind::Exact,
            ],
            ServingBlockdProcessStart::OutcomeUnknown,
        ));
        let effect = serving_effect(&fixture, Arc::clone(&port));

        assert_eq!(
            effect
                .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(port.starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            effect
                .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(port.starts.load(Ordering::SeqCst), 1);
        let exact_context = effect_context_with_processes(&fixture, vec![accepted]);
        let retirement_global = Arc::new(RetirementEffectGlobalPort::new(
            &fixture,
            [RootProvisionProcessInspection::Absent],
        ));
        let retirement_stop = Arc::new(RetirementEffectStopPort::new([]));
        assert_eq!(
            prepare_device_retirement_effect(&fixture, retirement_global, retirement_stop.clone(),)
                .try_apply(&exact_context, &fixture.acquired.desired)
                .unwrap(),
            None,
            "exact serving projection must fall through old-Root retirement"
        );
        assert!(retirement_stop.stopped().is_empty());
        assert_eq!(
            effect
                .try_apply(&exact_context, &fixture.acquired.desired)
                .unwrap(),
            None
        );
        assert_eq!(port.starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn serving_vhost_device_projection_is_exact_and_provider_bound() {
        for field in ["guest_device", "socket", "token", "duplicate"] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let expected = serving_expectation(&fixture);
            let accepted = expected
                .clone()
                .prove_exact_process(expected.exact_evidence_for_test(51))
                .unwrap()
                .into_process_evidence();
            let base = effect_context_with_processes(&fixture, vec![accepted]);
            let context =
                mutate_effect_context(&fixture, base, |_session, observation, _attestation| {
                    let devices = &mut observation.runtimes[0].volumes[0].devices;
                    if field == "duplicate" {
                        devices.push(devices[0].clone());
                        return;
                    }
                    let [cats_api::runtime_reconciliation::ObservedDevice::VhostUserBlk {
                        guest_device,
                        socket_path,
                        ownership_token,
                    }] = devices.as_mut_slice()
                    else {
                        panic!("positive fixture must project one exact vhost device")
                    };
                    match field {
                        "guest_device" => {
                            *guest_device = cats_api::runtime_reconciliation::GuestDeviceIdentity {
                                serial: id("foreign-device"),
                                slot: 9,
                            };
                        }
                        "socket" => *socket_path = host("/run/cats/foreign-vhost.sock"),
                        "token" => {
                            *ownership_token = OwnershipTokenEvidence::Valid {
                                ownership_token: random('9'),
                            };
                        }
                        _ => unreachable!(),
                    }
                });
            let port = Arc::new(FakeServingBlockdPort::new(
                [ServingBlockdProcessInspectionKind::Exact],
                ServingBlockdProcessStart::Submitted,
            ));
            assert_eq!(
                serving_effect(&fixture, Arc::clone(&port))
                    .try_apply(&context, &fixture.acquired.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                )),
                "wrong vhost {field} escaped the bound provider proof"
            );
            assert_eq!(port.starts.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn serving_blockd_rejects_every_bound_status_or_closed_set_conflict() {
        const FIELDS: &[&str] = &[
            "volume",
            "attachment",
            "epoch",
            "origin",
            "node",
            "placement",
            "head",
            "size",
            "durability",
            "scope",
            "process_token",
            "device_token",
            "guest_serial",
            "missing_guest_serial",
            "control_only",
            "guest_io",
            "local_generation",
            "remote_generation",
            "unpublished_generations",
            "unpublished_bytes",
            "unpublished_age",
            "backpressured",
            "fenced",
        ];
        for field in FIELDS {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let expected = serving_expectation(&fixture);
            let accepted = expected
                .clone()
                .prove_exact_process(expected.exact_evidence_for_test(51))
                .unwrap()
                .into_process_evidence();
            let port = Arc::new(FakeServingBlockdPort::new(
                [ServingBlockdProcessInspectionKind::WrongStatus(field)],
                ServingBlockdProcessStart::Submitted,
            ));
            assert_eq!(
                serving_effect(&fixture, Arc::clone(&port))
                    .try_apply(
                        &effect_context_with_processes(&fixture, vec![accepted]),
                        &fixture.acquired.desired,
                    )
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                )),
                "status field {field} was not closed",
            );
            assert_eq!(port.starts.load(Ordering::SeqCst), 0);
        }

        for kind in [
            ServingBlockdProcessInspectionKind::Conflict,
            ServingBlockdProcessInspectionKind::Exact,
        ] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let port = Arc::new(FakeServingBlockdPort::new(
                [kind],
                ServingBlockdProcessStart::Submitted,
            ));
            let expected_outcome = if matches!(kind, ServingBlockdProcessInspectionKind::Exact) {
                RuntimeDesiredEffectOutcome::RefreshInventory
            } else {
                RuntimeDesiredEffectOutcome::Stop(RuntimeDesiredEffectStopReason::LocalContract)
            };
            assert_eq!(
                serving_effect(&fixture, Arc::clone(&port))
                    .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                    .unwrap(),
                Some(expected_outcome),
            );
            assert_eq!(port.starts.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn prepare_network_reservation_publishes_only_after_two_exact_authority_rounds() {
        let mut fixture = fixture();
        complete_old_process_retirement(&mut fixture);
        let predecessor_digest = fixture.stored_checkpoint.content_digest().clone();
        let accepted = accepted_serving_process(&fixture);
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let port = Arc::new(FakeServingBlockdPort::new(
            [
                ServingBlockdProcessInspectionKind::Exact,
                ServingBlockdProcessInspectionKind::Exact,
            ],
            ServingBlockdProcessStart::Submitted,
        ));
        let effect =
            prepare_network_reservation_effect(&fixture, authority.clone(), Arc::clone(&port));

        assert_eq!(
            effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        let current = current_runtime_checkpoint(&fixture);
        assert_ne!(current.content_digest(), &predecessor_digest);
        assert!(matches!(
            current.checkpoint().step,
            ReconcileStep::PrepareNetwork { .. }
        ));
        assert_eq!(authority.loads.load(Ordering::SeqCst), 3);
        assert_eq!(port.remaining_inspections(), 0);
    }

    #[test]
    fn prepare_network_reservation_rejects_incomplete_prepare_device_envelope_without_effect() {
        for field in [
            "applied_desired",
            "session",
            "guest_transport",
            "platform_guards",
            "volume_lineage",
            "paired_volume_intent_id",
            "paired_disk_id",
        ] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let predecessor_digest = fixture.stored_checkpoint.content_digest().clone();
            let accepted = accepted_serving_process(&fixture);
            let base = effect_context_with_processes(&fixture, vec![accepted]);
            let context =
                mutate_effect_context(&fixture, base, |_session, observation, _attestation| {
                    match field {
                        "applied_desired" => observation.runtimes[0].applied_desired = None,
                        "session" => {
                            observation.agent_session_epoch = Epoch::new(99).unwrap();
                        }
                        "guest_transport" => {
                            observation.runtimes[0].guest_transport =
                                GuestTransportEvidence::Malformed {
                                    raw_response_digest: digest('9'),
                                };
                        }
                        "platform_guards" => observation.runtimes[0].platform_guards = 1,
                        "volume_lineage" => {
                            observation.runtimes[0].volumes[0].local_lineages.clear();
                        }
                        "paired_volume_intent_id" => {
                            let foreign = id("foreign_intent");
                            let ReconcileStep::PrepareDevice { devices } =
                                &mut observation.runtimes[0].step
                            else {
                                panic!("fixture is not PrepareDevice")
                            };
                            devices[0].volume_intent_id = foreign.clone();
                            observation.runtimes[0].volumes[0].volume_intent_id = Some(foreign);
                        }
                        "paired_disk_id" => {
                            let foreign = id("foreign_disk");
                            let ReconcileStep::PrepareDevice { devices } =
                                &mut observation.runtimes[0].step
                            else {
                                panic!("fixture is not PrepareDevice")
                            };
                            devices[0].disk_id = foreign.clone();
                            observation.runtimes[0].volumes[0].disk_id = Some(foreign);
                        }
                        _ => unreachable!(),
                    }
                });
            let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
            let port = Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            ));
            let effect =
                prepare_network_reservation_effect(&fixture, authority.clone(), Arc::clone(&port));

            assert_eq!(
                effect
                    .try_apply(&context, &fixture.acquired.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                )),
                "incomplete {field} escaped the closed PrepareDevice envelope"
            );
            assert_eq!(
                current_runtime_checkpoint(&fixture).content_digest(),
                &predecessor_digest
            );
            assert_eq!(authority.loads.load(Ordering::SeqCst), 0);
            assert_eq!(port.remaining_inspections(), 2);
        }
    }

    #[test]
    fn prepare_network_reservation_rejects_same_listener_private_process_drift() {
        for drift in [
            ServingBlockdProcessInspectionKind::WrongStatus("head"),
            ServingBlockdProcessInspectionKind::WrongStatus("fenced"),
            ServingBlockdProcessInspectionKind::WrongCommand,
            ServingBlockdProcessInspectionKind::WrongCgroup,
        ] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let predecessor_digest = fixture.stored_checkpoint.content_digest().clone();
            let accepted = accepted_serving_process(&fixture);
            let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
            let port = Arc::new(FakeServingBlockdPort::new(
                [drift, ServingBlockdProcessInspectionKind::Exact],
                ServingBlockdProcessStart::Submitted,
            ));
            let effect =
                prepare_network_reservation_effect(&fixture, authority.clone(), Arc::clone(&port));

            assert!(effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted]),
                    &fixture.acquired.desired,
                )
                .is_err());
            assert_eq!(
                current_runtime_checkpoint(&fixture).content_digest(),
                &predecessor_digest
            );
            assert_eq!(authority.loads.load(Ordering::SeqCst), 1);
            assert_eq!(port.remaining_inspections(), 1);
        }
    }

    #[test]
    fn prepare_network_reservation_rechecks_volume_authority_at_both_cas_boundaries() {
        for exact_revalidations_before_drift in [0, 1] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let predecessor_digest = fixture.stored_checkpoint.content_digest().clone();
            let accepted = accepted_serving_process(&fixture);
            let exact = fixture.authority.volume.clone();
            let mut drifted = exact.clone();
            drifted.head.generation = Generation::new(99).unwrap();
            let mut records = vec![exact.clone()];
            records.extend(std::iter::repeat_n(exact, exact_revalidations_before_drift));
            records.push(drifted);
            let authority = Arc::new(SequencedEffectAuthority::new(records));
            let port = Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            ));
            let effect =
                prepare_network_reservation_effect(&fixture, authority.clone(), Arc::clone(&port));

            assert!(effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted]),
                    &fixture.acquired.desired,
                )
                .is_err());
            assert_eq!(
                current_runtime_checkpoint(&fixture).content_digest(),
                &predecessor_digest
            );
            assert_eq!(
                authority.loads.load(Ordering::SeqCst),
                2 + exact_revalidations_before_drift
            );
            assert_eq!(
                port.remaining_inspections(),
                1 - exact_revalidations_before_drift
            );
        }
    }

    #[test]
    fn prepare_network_physical_rejects_paired_foreign_prepared_device_ids() {
        for field in ["volume_intent_id", "disk_id"] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let reservation_port = Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            ));
            prepare_network_reservation_effect(
                &fixture,
                Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
                reservation_port,
            )
            .try_apply(
                &effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
                &fixture.acquired.desired,
            )
            .unwrap();
            fixture.stored_checkpoint = current_runtime_checkpoint(&fixture);

            let mut poisoned = fixture.stored_checkpoint.checkpoint().clone();
            let ReconcileStep::PrepareNetwork { devices, .. } = &mut poisoned.step else {
                panic!("reservation did not persist PrepareNetwork")
            };
            let [device] = devices.as_mut_slice() else {
                panic!("PrepareNetwork did not retain one device")
            };
            match field {
                "volume_intent_id" => {
                    let foreign = id("foreign_intent");
                    device.volume_intent_id = foreign.clone();
                    poisoned.volumes[0].volume_intent_id = Some(foreign);
                }
                "disk_id" => {
                    let foreign = id("foreign_disk");
                    device.disk_id = foreign.clone();
                    poisoned.volumes[0].disk_id = Some(foreign);
                }
                _ => unreachable!(),
            }
            poisoned.updated_at_unix_ms = UnixMillis::new(
                fixture
                    .stored_checkpoint
                    .checkpoint()
                    .updated_at_unix_ms
                    .get()
                    + 1,
            )
            .unwrap();
            fixture.replace_checkpoint(poisoned);
            let poisoned_digest = fixture.stored_checkpoint.content_digest().clone();

            let base =
                effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]);
            let context =
                with_absent_network_admission(base, fixture.stored_checkpoint.checkpoint());
            let events = Arc::new(NetworkTapEvents::default());
            let tap = Arc::new(NetworkTapPort {
                behavior: NetworkTapBehavior::Publish,
                context: context.clone(),
                events: Arc::clone(&events),
            });
            let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
            let process = Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            ));
            let effect = prepare_network_reservation_effect(
                &fixture,
                authority.clone(),
                Arc::clone(&process),
            )
            .with_tap_create_for_test(tap);

            assert_eq!(
                effect
                    .try_apply(&context, &fixture.acquired.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                )),
                "paired foreign {field} reached the physical TAP effect"
            );
            assert_eq!(events.creates.load(Ordering::SeqCst), 0);
            assert_eq!(authority.loads.load(Ordering::SeqCst), 0);
            assert_eq!(process.remaining_inspections(), 2);
            assert_eq!(
                current_runtime_checkpoint(&fixture).content_digest(),
                &poisoned_digest
            );
        }
    }

    #[test]
    fn prepare_network_physical_round_closes_publish_cancellation_and_response_loss() {
        for (behavior, expected_publish_attempts, expected_unpublished, expected_inspections) in [
            (NetworkTapBehavior::Publish, 1, 0, 2),
            (NetworkTapBehavior::CancelAfterCreate, 0, 1, 2),
            (NetworkTapBehavior::LosePublishResponse, 1, 1, 3),
        ] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let reservation_port = Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            ));
            let reservation = prepare_network_reservation_effect(
                &fixture,
                Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
                reservation_port,
            );
            reservation
                .try_apply(
                    &effect_context_with_processes(
                        &fixture,
                        vec![accepted_serving_process(&fixture)],
                    ),
                    &fixture.acquired.desired,
                )
                .unwrap();
            fixture.stored_checkpoint = current_runtime_checkpoint(&fixture);
            let checkpoint_digest = fixture.stored_checkpoint.content_digest().clone();
            let context = with_absent_network_admission(
                effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
                fixture.stored_checkpoint.checkpoint(),
            );
            let events = Arc::new(NetworkTapEvents::default());
            let tap = Arc::new(NetworkTapPort {
                behavior,
                context: context.clone(),
                events: Arc::clone(&events),
            });
            let process = Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            ));
            let effect = prepare_network_reservation_effect(
                &fixture,
                Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
                Arc::clone(&process),
            )
            .with_tap_create_for_test(tap);

            assert_eq!(
                effect
                    .try_apply(&context, &fixture.acquired.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
            assert_eq!(events.creates.load(Ordering::SeqCst), 1);
            assert_eq!(
                events.publish_attempts.load(Ordering::SeqCst),
                expected_publish_attempts
            );
            assert_eq!(
                events.unpublished_drops.load(Ordering::SeqCst),
                expected_unpublished
            );
            assert_eq!(process.remaining_inspections(), 3 - expected_inspections);
            assert_eq!(
                current_runtime_checkpoint(&fixture).content_digest(),
                &checkpoint_digest
            );
        }
    }

    #[test]
    fn exact_tap_falls_through_to_one_checkpoint_only_start_runtime_cas() {
        let mut fixture = fixture();
        advance_fixture_to_prepare_network(&mut fixture);
        let predecessor_digest = fixture.stored_checkpoint.content_digest().clone();
        let context = with_exact_network_admission(
            effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
            fixture.stored_checkpoint.checkpoint(),
        );
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let process = Arc::new(FakeServingBlockdPort::new(
            [
                ServingBlockdProcessInspectionKind::Exact,
                ServingBlockdProcessInspectionKind::Exact,
                ServingBlockdProcessInspectionKind::Exact,
                ServingBlockdProcessInspectionKind::Exact,
            ],
            ServingBlockdProcessStart::Submitted,
        ));
        let network = Arc::new(
            PrepareNetworkReservationEffect::new(
                fixture.state_directory.clone(),
                exact_ip_binary(&fixture, fixture.stored_checkpoint.checkpoint()),
                Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&process) as Arc<dyn ServingBlockdProcessGlobalPort>,
            )
            .unwrap(),
        );
        let (artifacts, assertions) = fixed_launch_artifacts(None);
        let artifact_port: Arc<dyn LaunchArtifactAuthorityPort> = artifacts;
        let start_runtime = StartRuntimeReservationEffect::for_test(
            fixture.state_directory.clone(),
            Arc::clone(&network),
            Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
            Arc::clone(&process) as Arc<dyn ServingBlockdProcessGlobalPort>,
            artifact_port,
        );

        assert_eq!(
            network
                .try_apply(&context, &fixture.acquired.desired)
                .unwrap(),
            None,
            "an exact TAP must be a read-only fallthrough"
        );
        assert_eq!(
            start_runtime
                .try_apply(&context, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        fixture.stored_checkpoint = current_runtime_checkpoint(&fixture);
        assert_ne!(
            fixture.stored_checkpoint.content_digest(),
            &predecessor_digest
        );
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            process_identity_token,
            network,
            devices,
            ..
        } = &fixture.stored_checkpoint.checkpoint().step
        else {
            panic!("exact TAP did not publish StartRuntime")
        };
        let [device] = devices.as_slice() else {
            panic!("StartRuntime lost its prepared device")
        };
        assert_ne!(runtime_incarnation, process_identity_token);
        assert_ne!(runtime_incarnation, &network.ownership_token);
        assert_ne!(runtime_incarnation, &device.ownership_token);
        assert_ne!(
            runtime_incarnation,
            &device.serving_process.process_identity_token
        );
        assert_eq!(assertions.load(Ordering::SeqCst), 3);
        assert_eq!(process.remaining_inspections(), 0);

        let persisted_digest = fixture.stored_checkpoint.content_digest().clone();
        let fresh = effect_context_with_processes(&fixture, Vec::new());
        assert_eq!(
            start_runtime
                .try_apply(&fresh, &fixture.acquired.desired)
                .unwrap(),
            None,
            "fresh StartRuntime was re-CASed"
        );
        assert_eq!(
            current_runtime_checkpoint(&fixture).content_digest(),
            &persisted_digest
        );
    }

    #[test]
    fn retained_running_scan_treats_only_absent_expected_members_as_not_ready() {
        let mut fixture = fixture();
        advance_fixture_to_start_runtime(&mut fixture);
        let checkpoint = fixture.stored_checkpoint.checkpoint();
        let desired = &fixture.acquired.desired;
        let serving = serving_expectation(&fixture);
        let serving_key =
            ManagedServingKey::new(serving.cat_id().clone(), serving.volume_id().clone());
        let serving_proof = serving
            .clone()
            .prove_exact_process(serving.exact_evidence_for_test(51))
            .unwrap();
        let extra = serving.persistent_vhost_peer_for_test(true);
        let extra_key = ManagedServingKey::new(extra.cat_id().clone(), extra.volume_id().clone());
        let extra_proof = extra
            .clone()
            .prove_exact_process(extra.exact_evidence_for_test(52))
            .unwrap();
        let checkpoint_path = host(
            super::super::runtime_checkpoint_path(
                &fixture.checkpoint_directory,
                &checkpoint.cat_id,
            )
            .to_str()
            .unwrap(),
        );
        let vmm = VmmProcessExpectation::from_checkpoint(checkpoint.clone())
            .unwrap()
            .with_checkpoint_path(checkpoint_path)
            .unwrap();
        let vmm_proof = vmm
            .clone()
            .prove_exact_process(vmm.exact_evidence_for_test(71))
            .unwrap();
        let build_scan = |include_serving: bool, exact_serving: bool, include_extra: bool| {
            let mut serving_expectations = BTreeMap::new();
            let mut serving_proofs = BTreeMap::new();
            if include_serving {
                serving_expectations.insert(serving_key.clone(), serving.clone());
                if exact_serving {
                    serving_proofs.insert(serving_key.clone(), serving_proof.clone());
                }
            }
            if include_extra {
                serving_expectations.insert(extra_key.clone(), extra.clone());
                serving_proofs.insert(extra_key.clone(), extra_proof.clone());
            }
            NodeGlobalManagedProcessScanAdmission::from_root_controls(
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .unwrap()
            .with_serving_blockds(serving_expectations, serving_proofs)
            .unwrap()
            .with_vmms(
                BTreeMap::from([(desired.cat_id.clone(), vmm.clone())]),
                BTreeMap::from([(desired.cat_id.clone(), vmm_proof.clone())]),
            )
            .unwrap()
        };
        let network =
            NodeGlobalNetworkScanAdmission::exact_checkpoint_for_test(checkpoint).unwrap();
        let mut metadata_observed = checkpoint.volumes[0].clone();
        assert!(!metadata_observed.local_lineages.is_empty());
        metadata_observed.local_lineages.clear();
        metadata_observed.devices.clear();
        let volumes = [AuthorityVolumeInventoryEvidence {
            observed: metadata_observed,
            record: fixture.authority.volume.clone(),
        }];

        assert!(validate_retained_running_scan_exact_set(
            desired,
            checkpoint,
            &volumes,
            &build_scan(true, true, false),
            &network,
            None,
        )
        .unwrap()
        .is_some());
        assert!(validate_retained_running_scan_exact_set(
            desired,
            checkpoint,
            &volumes,
            &build_scan(true, false, false),
            &network,
            None,
        )
        .unwrap()
        .is_none());
        assert!(validate_retained_running_scan_exact_set(
            desired,
            checkpoint,
            &volumes,
            &build_scan(false, false, false),
            &network,
            None,
        )
        .is_err());
        assert!(validate_retained_running_scan_exact_set(
            desired,
            checkpoint,
            &volumes,
            &build_scan(true, true, true),
            &network,
            None,
        )
        .is_err());
    }

    #[test]
    fn retained_running_revalidator_accepts_the_exact_physical_authority_tuple() {
        let mut fixture = fixture();
        advance_fixture_to_start_runtime(&mut fixture);

        revalidate_retained_running_fixture(
            &fixture,
            fixture.authority.volume.clone(),
            ServingBlockdProcessInspectionKind::Exact,
            RunningVmmInspectionKind::Exact,
        )
        .unwrap();
    }

    #[test]
    fn retained_running_revalidator_rejects_volume_serving_and_vmm_drift() {
        let mut volume_fixture = fixture();
        advance_fixture_to_start_runtime(&mut volume_fixture);
        let mut foreign_volume = volume_fixture.authority.volume.clone();
        foreign_volume.lease_owner = Some(id("att_foreign"));
        let volume_error = revalidate_retained_running_fixture(
            &volume_fixture,
            foreign_volume,
            ServingBlockdProcessInspectionKind::Exact,
            RunningVmmInspectionKind::Exact,
        )
        .unwrap_err();
        assert!(
            format!("{volume_error:#}").contains("Volume"),
            "{volume_error:#}"
        );

        let mut serving_fixture = fixture();
        advance_fixture_to_start_runtime(&mut serving_fixture);
        let serving_error = revalidate_retained_running_fixture(
            &serving_fixture,
            serving_fixture.authority.volume.clone(),
            ServingBlockdProcessInspectionKind::WrongStatus("volume"),
            RunningVmmInspectionKind::Exact,
        )
        .unwrap_err();
        assert!(
            format!("{serving_error:#}").contains("serving process changed"),
            "{serving_error:#}"
        );

        let mut vmm_fixture = fixture();
        advance_fixture_to_start_runtime(&mut vmm_fixture);
        let vmm_error = revalidate_retained_running_fixture(
            &vmm_fixture,
            vmm_fixture.authority.volume.clone(),
            ServingBlockdProcessInspectionKind::Exact,
            RunningVmmInspectionKind::Conflict,
        )
        .unwrap_err();
        assert!(
            format!("{vmm_error:#}").contains("VMM is no longer exact"),
            "{vmm_error:#}"
        );
    }

    #[test]
    fn start_runtime_cancellation_and_response_loss_adopt_without_recas() {
        for response_loss in [false, true] {
            let mut fixture = fixture();
            advance_fixture_to_prepare_network(&mut fixture);
            let context = with_exact_network_admission(
                effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
                fixture.stored_checkpoint.checkpoint(),
            );
            let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
            let process = Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            ));
            let network = Arc::new(
                PrepareNetworkReservationEffect::new(
                    fixture.state_directory.clone(),
                    exact_ip_binary(&fixture, fixture.stored_checkpoint.checkpoint()),
                    Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
                    Arc::clone(&process) as Arc<dyn ServingBlockdProcessGlobalPort>,
                )
                .unwrap(),
            );
            let (artifacts, _) = fixed_launch_artifacts(None);
            let artifact_port: Arc<dyn LaunchArtifactAuthorityPort> = artifacts;
            let start_runtime = StartRuntimeReservationEffect::for_test(
                fixture.state_directory.clone(),
                network,
                Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
                process,
                artifact_port,
            )
            .with_after_cid_replace(Arc::new(move |context| {
                if response_loss {
                    anyhow::bail!("injected StartRuntime publication response loss")
                }
                context.cancel_for_test();
                Ok(())
            }));

            let error = start_runtime
                .try_apply(&context, &fixture.acquired.desired)
                .expect_err("ambiguous post-publication result returned false success");
            let expected = if response_loss {
                "response loss"
            } else {
                "cancelled"
            };
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            fixture.stored_checkpoint = current_runtime_checkpoint(&fixture);
            assert!(matches!(
                fixture.stored_checkpoint.checkpoint().step,
                ReconcileStep::StartRuntime { .. }
            ));
            let persisted_digest = fixture.stored_checkpoint.content_digest().clone();
            assert_eq!(
                start_runtime
                    .try_apply(
                        &effect_context_with_processes(&fixture, Vec::new()),
                        &fixture.acquired.desired,
                    )
                    .unwrap(),
                None
            );
            assert_eq!(
                current_runtime_checkpoint(&fixture).content_digest(),
                &persisted_digest
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn physical_start_publishes_intent_and_submits_once_for_every_systemd_result() {
        for start in [
            VmmProcessStart::Submitted,
            VmmProcessStart::OutcomeUnknown,
            VmmProcessStart::DefinitelyNotStarted,
        ] {
            let mut fixture = fixture_with_guest_config_digest(physical_guest_config_digest());
            let physical = advance_fixture_to_physical_start(&mut fixture);
            let vmm = Arc::new(FakePhysicalVmmPort::new(
                std::iter::repeat_n(VmmInspectionKind::Absent, 32),
                start,
            ));
            let effect = physical_start_effect(&fixture, &physical, Arc::clone(&vmm));
            let context = with_exact_network_admission(
                effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
                fixture.stored_checkpoint.checkpoint(),
            );

            assert_eq!(
                effect
                    .try_apply(&context, &fixture.acquired.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
            assert_eq!(vmm.starts.load(Ordering::SeqCst), 1, "{start:?}");
            let incarnation = fixture
                .stored_checkpoint
                .checkpoint()
                .runtime_incarnation
                .as_ref()
                .unwrap();
            assert!(physical.receipts.load(incarnation).unwrap().is_some());
            let launch_paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
                &fixture.state_directory,
                fixture.stored_checkpoint.checkpoint(),
            )
            .unwrap();
            assert!(Path::new(launch_paths.directory().as_str()).is_dir());

            // A response loss, a successful response, and a definite local
            // failure all consume this accepted observation exactly once.
            assert_eq!(
                effect
                    .try_apply(&context, &fixture.acquired.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
            assert_eq!(vmm.starts.load(Ordering::SeqCst), 1, "{start:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn physical_start_adopts_exact_vmm_without_publishing_or_submitting() {
        let mut fixture = fixture_with_guest_config_digest(physical_guest_config_digest());
        let physical = advance_fixture_to_physical_start(&mut fixture);
        let vmm = Arc::new(FakePhysicalVmmPort::new(
            [VmmInspectionKind::Exact],
            VmmProcessStart::Submitted,
        ));
        let effect = physical_start_effect(&fixture, &physical, Arc::clone(&vmm));
        let context = with_exact_network_admission(
            effect_context_with_processes(
                &fixture,
                vec![
                    accepted_vmm_process(&fixture),
                    accepted_serving_process(&fixture),
                ],
            ),
            fixture.stored_checkpoint.checkpoint(),
        );

        assert_eq!(
            effect
                .try_apply(&context, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(vmm.starts.load(Ordering::SeqCst), 0);
        assert_no_physical_launch_residue(&fixture, &physical);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn physical_start_conflict_or_unavailable_has_zero_effect() {
        for inspection in [VmmInspectionKind::Conflict, VmmInspectionKind::Unavailable] {
            let mut fixture = fixture_with_guest_config_digest(physical_guest_config_digest());
            let physical = advance_fixture_to_physical_start(&mut fixture);
            let vmm = Arc::new(FakePhysicalVmmPort::new(
                [inspection],
                VmmProcessStart::Submitted,
            ));
            let effect = physical_start_effect(&fixture, &physical, Arc::clone(&vmm));
            let context = with_exact_network_admission(
                effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
                fixture.stored_checkpoint.checkpoint(),
            );

            let error = effect
                .try_apply(&context, &fixture.acquired.desired)
                .expect_err("ambiguous VMM inventory reached a physical effect");
            assert!(
                format!("{error:#}").contains("physical StartRuntime VMM"),
                "{error:#}"
            );
            assert_eq!(vmm.starts.load(Ordering::SeqCst), 0, "{inspection:?}");
            assert_no_physical_launch_residue(&fixture, &physical);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn physical_start_recovers_partial_launcher_residue_before_a_fresh_retry() {
        let mut fixture = fixture_with_guest_config_digest(physical_guest_config_digest());
        let physical = advance_fixture_to_physical_start(&mut fixture);
        let launch_paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            &fixture.state_directory,
            fixture.stored_checkpoint.checkpoint(),
        )
        .unwrap();
        let memory_path = PathBuf::from(launch_paths.memory_file_path().as_str());
        let vmm = Arc::new(
            FakePhysicalVmmPort::new(
                std::iter::repeat_n(VmmInspectionKind::Absent, 64),
                VmmProcessStart::DefinitelyNotStarted,
            )
            .with_before_start(move || {
                let mut memory = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&memory_path)
                    .unwrap();
                memory.write_all(b"partial-launch").unwrap();
                memory.sync_all().unwrap();
            }),
        );
        let effect = physical_start_effect(&fixture, &physical, Arc::clone(&vmm));
        let context = |observation_id| {
            with_exact_network_admission(
                effect_context_with_processes_and_observation(
                    &fixture,
                    vec![accepted_serving_process(&fixture)],
                    observation_id,
                ),
                fixture.stored_checkpoint.checkpoint(),
            )
        };

        assert_eq!(
            effect
                .try_apply(&context(random('4')), &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(vmm.starts.load(Ordering::SeqCst), 1);
        assert!(Path::new(launch_paths.memory_file_path().as_str()).exists());

        // A fresh accepted-full absence quarantines and removes the partial
        // receipt-owned attempt, but does not submit in that recovery round.
        assert_eq!(
            effect
                .try_apply(&context(random('9')), &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(vmm.starts.load(Ordering::SeqCst), 1);
        assert!(!Path::new(launch_paths.directory().as_str()).exists());

        // Only the next fresh observation may rebuild the exact attempt and
        // issue another systemd submission.
        assert_eq!(
            effect
                .try_apply(&context(random('8')), &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(vmm.starts.load(Ordering::SeqCst), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn physical_start_holds_one_exclusive_namespace_guard_through_submit() {
        let mut fixture = fixture_with_guest_config_digest(physical_guest_config_digest());
        let physical = advance_fixture_to_physical_start(&mut fixture);
        let launch_root = Arc::clone(&physical.launch_root);
        let blocked = Arc::new(AtomicUsize::new(0));
        let blocked_in_hook = Arc::clone(&blocked);
        let vmm = Arc::new(
            FakePhysicalVmmPort::new(
                std::iter::repeat_n(VmmInspectionKind::Absent, 32),
                VmmProcessStart::Submitted,
            )
            .with_before_start(move || {
                assert!(launch_root
                    .launcher_shared_lock_is_blocked_for_test()
                    .unwrap());
                blocked_in_hook.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let effect = physical_start_effect(&fixture, &physical, Arc::clone(&vmm));
        let context = with_exact_network_admission(
            effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
            fixture.stored_checkpoint.checkpoint(),
        );

        assert_eq!(
            effect
                .try_apply(&context, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(blocked.load(Ordering::SeqCst), 1);
        assert_eq!(vmm.starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn installed_artifact_aba_before_cid_publication_preserves_prepare_network() {
        let mut fixture = fixture();
        advance_fixture_to_prepare_network(&mut fixture);
        let predecessor_digest = fixture.stored_checkpoint.content_digest().clone();
        let context = with_exact_network_admission(
            effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
            fixture.stored_checkpoint.checkpoint(),
        );
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let process = Arc::new(FakeServingBlockdPort::new(
            [
                ServingBlockdProcessInspectionKind::Exact,
                ServingBlockdProcessInspectionKind::Exact,
            ],
            ServingBlockdProcessStart::Submitted,
        ));
        let network = Arc::new(
            PrepareNetworkReservationEffect::new(
                fixture.state_directory.clone(),
                exact_ip_binary(&fixture, fixture.stored_checkpoint.checkpoint()),
                Arc::clone(&authority) as Arc<dyn VolumeDataAuthority>,
                Arc::clone(&process) as Arc<dyn ServingBlockdProcessGlobalPort>,
            )
            .unwrap(),
        );
        let (artifacts, assertions) = fixed_launch_artifacts(Some(3));
        let artifact_port: Arc<dyn LaunchArtifactAuthorityPort> = artifacts;
        let start_runtime = StartRuntimeReservationEffect::for_test(
            fixture.state_directory.clone(),
            network,
            authority,
            process,
            artifact_port,
        );

        let error = start_runtime
            .try_apply(&context, &fixture.acquired.desired)
            .expect_err("installed artifact ABA reached StartRuntime publication");
        assert!(format!("{error:#}").contains("artifact ABA"), "{error:#}");
        assert_eq!(assertions.load(Ordering::SeqCst), 3);
        let current = current_runtime_checkpoint(&fixture);
        assert_eq!(current.content_digest(), &predecessor_digest);
        assert!(matches!(
            current.checkpoint().step,
            ReconcileStep::PrepareNetwork { .. }
        ));
    }

    #[test]
    fn kernel_nbd_prepare_network_recovers_serving_then_device_before_tap() {
        let mut fixture = fixture();
        complete_old_process_retirement(&mut fixture);
        replace_with_kernel_nbd_prepare_device(&mut fixture);

        let reservation_process = Arc::new(FakeServingBlockdPort::new(
            [
                ServingBlockdProcessInspectionKind::Exact,
                ServingBlockdProcessInspectionKind::Exact,
            ],
            ServingBlockdProcessStart::Submitted,
        ));
        let reservation = prepare_network_reservation_effect(
            &fixture,
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            reservation_process,
        );
        let reservation_context = with_exact_kernel_nbd_admission(
            &fixture,
            effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
        );
        assert_eq!(
            reservation
                .try_apply(&reservation_context, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        fixture.stored_checkpoint = current_runtime_checkpoint(&fixture);
        assert!(matches!(
            fixture.stored_checkpoint.checkpoint().step,
            ReconcileStep::PrepareNetwork { .. }
        ));
        let prepare_network_digest = fixture.stored_checkpoint.content_digest().clone();

        // Round one owns only the absent serving process and forces a fresh
        // full scan before the frontend effect may observe its listener.
        let restarted_serving = Arc::new(FakeServingBlockdPort::new(
            [ServingBlockdProcessInspectionKind::Absent],
            ServingBlockdProcessStart::Submitted,
        ));
        let serving_absent_context = with_absent_network_admission(
            absent_effect_context(&fixture),
            fixture.stored_checkpoint.checkpoint(),
        );
        assert_eq!(
            serving_effect(&fixture, Arc::clone(&restarted_serving))
                .try_apply(&serving_absent_context, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(restarted_serving.starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            current_runtime_checkpoint(&fixture).content_digest(),
            &prepare_network_digest
        );

        // Round two proves the restarted listener exact while the durable NBD
        // reservation remains physically absent, then submits exactly once.
        let expected = serving_expectation(&fixture);
        let exact_serving = expected
            .clone()
            .prove_exact_process(expected.exact_evidence_for_test(51))
            .unwrap();
        let attach_context = with_absent_network_admission(
            effect_context_with_processes(
                &fixture,
                vec![exact_serving.clone().into_process_evidence()],
            ),
            fixture.stored_checkpoint.checkpoint(),
        );
        let pool = KernelNbdPoolScanAdmission::absent_for_test(
            attach_context.accepted_full().unwrap().observation(),
            fixture.stored_checkpoint.checkpoint(),
            exact_serving.listener_proof(),
        )
        .unwrap();
        let attach_context = attach_context.with_kernel_nbd_pool_for_test(pool);
        let steady_serving = Arc::new(FakeServingBlockdPort::new(
            [ServingBlockdProcessInspectionKind::Exact],
            ServingBlockdProcessStart::Submitted,
        ));
        assert_eq!(
            serving_effect(&fixture, Arc::clone(&steady_serving))
                .try_apply(&attach_context, &fixture.acquired.desired)
                .unwrap(),
            None
        );
        assert_eq!(steady_serving.starts.load(Ordering::SeqCst), 0);
        let attach = Arc::new(FakeKernelNbdAttachPort {
            behavior: KernelAttachBehavior::OutcomeUnknown,
            calls: AtomicUsize::new(0),
        });
        let attach_effect = KernelNbdAttachEffect::for_test(
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            attach.clone(),
        );
        assert_eq!(
            attach_effect
                .try_apply(&attach_context, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(attach.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            current_runtime_checkpoint(&fixture).content_digest(),
            &prepare_network_digest
        );

        // Only a third accepted full with the exact NBD client can reach the
        // independent TAP effect.
        let physical_context = with_absent_network_admission(
            with_exact_kernel_nbd_admission(
                &fixture,
                effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
            ),
            fixture.stored_checkpoint.checkpoint(),
        );
        let events = Arc::new(NetworkTapEvents::default());
        let tap = Arc::new(NetworkTapPort {
            behavior: NetworkTapBehavior::Publish,
            context: physical_context.clone(),
            events: Arc::clone(&events),
        });
        let effect = prepare_network_reservation_effect(
            &fixture,
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            )),
        )
        .with_tap_create_for_test(tap);
        assert_eq!(
            effect
                .try_apply(&physical_context, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(events.creates.load(Ordering::SeqCst), 1);
        assert_eq!(events.publish_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            current_runtime_checkpoint(&fixture).content_digest(),
            &prepare_network_digest
        );
    }

    #[test]
    fn persisted_prepare_network_restarts_absent_serving_once_then_requires_fresh_full() {
        let mut fixture = fixture();
        complete_old_process_retirement(&mut fixture);
        let reservation = prepare_network_reservation_effect(
            &fixture,
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            Arc::new(FakeServingBlockdPort::new(
                [
                    ServingBlockdProcessInspectionKind::Exact,
                    ServingBlockdProcessInspectionKind::Exact,
                ],
                ServingBlockdProcessStart::Submitted,
            )),
        );
        reservation
            .try_apply(
                &effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
                &fixture.acquired.desired,
            )
            .unwrap();
        fixture.stored_checkpoint = current_runtime_checkpoint(&fixture);

        let port = Arc::new(FakeServingBlockdPort::new(
            [
                ServingBlockdProcessInspectionKind::Absent,
                ServingBlockdProcessInspectionKind::Exact,
            ],
            ServingBlockdProcessStart::Submitted,
        ));
        let absent = with_absent_network_admission(
            absent_effect_context(&fixture),
            fixture.stored_checkpoint.checkpoint(),
        );
        assert_eq!(
            serving_effect(&fixture, Arc::clone(&port))
                .try_apply(&absent, &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(port.starts.load(Ordering::SeqCst), 1);

        let fresh = with_absent_network_admission(
            effect_context_with_processes(&fixture, vec![accepted_serving_process(&fixture)]),
            fixture.stored_checkpoint.checkpoint(),
        );
        assert_eq!(
            serving_effect(&fixture, Arc::clone(&port))
                .try_apply(&fresh, &fixture.acquired.desired)
                .unwrap(),
            None
        );
        assert_eq!(port.starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn serving_blockd_start_rejects_checkpoint_aba_and_cancellation_before_submit() {
        for cancel in [false, true] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let port = Arc::new(FakeServingBlockdPort::new(
                [ServingBlockdProcessInspectionKind::Absent],
                ServingBlockdProcessStart::Submitted,
            ));
            let context = absent_effect_context(&fixture);
            if cancel {
                let canceller = context.clone();
                *port.before_start.lock().unwrap() = Some(Arc::new(move || {
                    canceller.cancel_for_test();
                }));
            } else {
                let checkpoint_path = super::super::runtime_checkpoint_path(
                    &fixture.checkpoint_directory,
                    &fixture.acquired.desired.cat_id,
                );
                let detached = fixture
                    .checkpoint_directory
                    .join("serving-aba-detached.json");
                *port.before_start.lock().unwrap() = Some(Arc::new(move || {
                    std::fs::rename(&checkpoint_path, &detached).unwrap();
                    std::fs::copy(&detached, &checkpoint_path).unwrap();
                }));
            }
            assert!(serving_effect(&fixture, Arc::clone(&port))
                .try_apply(&context, &fixture.acquired.desired)
                .is_err());
            assert_eq!(port.starts.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn serving_listener_proof_retains_exact_vhost_and_kernel_bindings() {
        for kernel in [false, true] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            if kernel {
                let mut checkpoint = fixture.stored_checkpoint.checkpoint().clone();
                let ReconcileStep::PrepareDevice { devices } = &mut checkpoint.step else {
                    unreachable!()
                };
                devices[0].frontend = PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path: managed_serving_sockets(&devices[0].ownership_token).1,
                    device_path: host("/dev/nbd7"),
                    direct: false,
                };
                fixture.stored_checkpoint = FileCheckpointStore::open(
                    &fixture.checkpoint_directory,
                    &fixture.acquired.desired.cat_id,
                )
                .unwrap()
                .replace(&fixture.stored_checkpoint, &checkpoint)
                .unwrap();
            }
            let expected = serving_expectation(&fixture);
            let exact = expected
                .clone()
                .prove_exact_process(expected.exact_evidence_for_test(51))
                .unwrap();
            let projected_device = exact.vhost_device_projection();
            let listener = exact.listener_proof();
            let context = effect_context_with_processes(
                &fixture,
                vec![exact.clone().into_process_evidence()],
            );
            let observed_devices =
                &context.accepted_full().unwrap().observation().runtimes[0].volumes[0].devices;
            assert_eq!(observed_devices.is_empty(), kernel);
            let port = Arc::new(FakeServingBlockdPort::new(
                [ServingBlockdProcessInspectionKind::Exact],
                ServingBlockdProcessStart::Submitted,
            ));
            assert_eq!(
                serving_effect(&fixture, port)
                    .try_apply(&context, &fixture.acquired.desired)
                    .unwrap(),
                None,
                "exact kernel/vhost serving proof must reach the later device suffix"
            );
            assert_eq!(listener.expectation(), &expected);
            assert_eq!(listener.evidence().process_id(), 51);
            assert_eq!(
                listener.process_identity_token(),
                expected.process_identity_token()
            );
            assert_eq!(
                listener.device_ownership_token(),
                expected.device_ownership_token()
            );
            match expected.frontend() {
                PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    ..
                } => {
                    assert_eq!(listener.listener_path(), listener_socket_path);
                    assert!(projected_device.is_none());
                    let persisted =
                        super::super::kernel_nbd::KernelNbdDeviceExpectation::from_prepare_device(
                            fixture.stored_checkpoint.checkpoint(),
                        )
                        .unwrap()
                        .unwrap();
                    persisted.assert_serving_listener(&listener).unwrap();

                    let mut wrong_direct = fixture.stored_checkpoint.checkpoint().clone();
                    let ReconcileStep::PrepareDevice { devices } = &mut wrong_direct.step else {
                        unreachable!()
                    };
                    let PrepareDeviceFrontend::KernelNbd { direct, .. } = &mut devices[0].frontend
                    else {
                        unreachable!()
                    };
                    *direct = !*direct;
                    assert!(
                        super::super::kernel_nbd::KernelNbdDeviceExpectation::from_prepare_device(
                            &wrong_direct,
                        )
                        .unwrap()
                        .unwrap()
                        .assert_serving_listener(&listener)
                        .is_err(),
                        "listener proof must not erase persisted direct mode",
                    );

                    let mut wrong_epoch = fixture.stored_checkpoint.checkpoint().clone();
                    let ReconcileStep::PrepareDevice { devices } = &mut wrong_epoch.step else {
                        unreachable!()
                    };
                    devices[0].attachment_epoch =
                        FenceEpoch::new(devices[0].attachment_epoch.get() + 1).unwrap();
                    assert!(
                        super::super::kernel_nbd::KernelNbdDeviceExpectation::from_prepare_device(
                            &wrong_epoch,
                        )
                        .unwrap()
                        .unwrap()
                        .assert_serving_listener(&listener)
                        .is_err(),
                        "listener proof must not erase the attachment epoch",
                    );
                }
                PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => {
                    assert_eq!(listener.listener_path(), socket_path);
                    let (volume_id, device) = projected_device.unwrap();
                    assert_eq!(volume_id, fixture.acquired.volume.volume_id);
                    assert!(matches!(
                        device,
                        cats_api::runtime_reconciliation::ObservedDevice::VhostUserBlk {
                            socket_path: projected_socket,
                            ownership_token: OwnershipTokenEvidence::Valid { ownership_token },
                            ..
                        } if projected_socket == *socket_path
                            && ownership_token == *expected.device_ownership_token()
                    ));
                }
            }
        }
    }

    #[test]
    fn kernel_attach_effect_submits_once_and_refreshes_every_ambiguous_outcome() {
        for behavior in [
            KernelAttachBehavior::OutcomeUnknown,
            KernelAttachBehavior::Conflict,
            KernelAttachBehavior::Cancelled,
        ] {
            let mut fixture = fixture();
            complete_old_process_retirement(&mut fixture);
            let mut checkpoint = fixture.stored_checkpoint.checkpoint().clone();
            let ReconcileStep::PrepareDevice { devices } = &mut checkpoint.step else {
                unreachable!()
            };
            devices[0].frontend = PrepareDeviceFrontend::KernelNbd {
                listener_socket_path: managed_serving_sockets(&devices[0].ownership_token).1,
                device_path: host("/dev/nbd7"),
                direct: false,
            };
            fixture.stored_checkpoint = FileCheckpointStore::open(
                &fixture.checkpoint_directory,
                &fixture.acquired.desired.cat_id,
            )
            .unwrap()
            .replace(&fixture.stored_checkpoint, &checkpoint)
            .unwrap();

            let expected = serving_expectation(&fixture);
            let exact = expected
                .clone()
                .prove_exact_process(expected.exact_evidence_for_test(51))
                .unwrap();
            let context = effect_context_with_processes(
                &fixture,
                vec![exact.clone().into_process_evidence()],
            );
            let pool = KernelNbdPoolScanAdmission::absent_for_test(
                context.accepted_full().unwrap().observation(),
                fixture.stored_checkpoint.checkpoint(),
                exact.listener_proof(),
            )
            .unwrap();
            let context = context.with_kernel_nbd_pool_for_test(pool);
            let attach = Arc::new(FakeKernelNbdAttachPort {
                behavior,
                calls: AtomicUsize::new(0),
            });
            let effect = KernelNbdAttachEffect::for_test(
                Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
                attach.clone(),
            );

            assert_eq!(
                effect
                    .try_apply(&context, &fixture.acquired.desired)
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
            assert_eq!(
                attach.calls.load(Ordering::SeqCst),
                1,
                "ambiguous attach outcome was retried in the same admission",
            );
        }
    }

    #[test]
    fn node_global_admission_keeps_same_cat_root_and_serving_as_two_closed_roles() {
        let mut fixture = fixture();
        let root = fixture.exact_process_proof().unwrap();
        let root_expectation = root.expectation().clone();
        complete_old_process_retirement(&mut fixture);
        let serving_expectation = serving_expectation(&fixture);
        let serving = serving_expectation
            .clone()
            .prove_exact_process(serving_expectation.exact_evidence_for_test(51))
            .unwrap();
        let serving_key = super::super::root_provision_process::ManagedServingKey::new(
            fixture.acquired.desired.cat_id.clone(),
            serving_expectation.volume_id().clone(),
        );
        let admission = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::from([(fixture.acquired.desired.cat_id.clone(), root_expectation)]),
            BTreeMap::from([(fixture.acquired.desired.cat_id.clone(), root)]),
        )
        .unwrap()
        .with_serving_blockds(
            BTreeMap::from([(serving_key.clone(), serving_expectation)]),
            BTreeMap::from([(serving_key, serving)]),
        )
        .unwrap();
        assert_eq!(
            admission
                .process_projections()
                .remove(&fixture.acquired.desired.cat_id)
                .unwrap()
                .len(),
            2
        );
        assert!(admission
            .vhost_device_projections()
            .contains_key(&fixture.acquired.desired.cat_id));
    }

    #[test]
    fn node_global_admission_closes_root_and_persistent_vhost_as_an_exact_set() {
        let mut fixture = fixture();
        complete_old_process_retirement(&mut fixture);
        let root = serving_expectation(&fixture);
        let persistent = root.persistent_vhost_peer_for_test(true);
        let root_key = super::super::root_provision_process::ManagedServingKey::new(
            root.cat_id().clone(),
            root.volume_id().clone(),
        );
        let persistent_key = super::super::root_provision_process::ManagedServingKey::new(
            persistent.cat_id().clone(),
            persistent.volume_id().clone(),
        );
        let root_proof = root
            .clone()
            .prove_exact_process(root.exact_evidence_for_test(51))
            .unwrap();
        let persistent_proof = persistent
            .clone()
            .prove_exact_process(persistent.exact_evidence_for_test(52))
            .unwrap();
        let admission = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_serving_blockds(
            BTreeMap::from([
                (root_key.clone(), root.clone()),
                (persistent_key.clone(), persistent.clone()),
            ]),
            BTreeMap::from([
                (root_key.clone(), root_proof.clone()),
                (persistent_key.clone(), persistent_proof.clone()),
            ]),
        )
        .unwrap();
        assert_eq!(admission.serving_blockd_count(root.cat_id()), 2);
        assert!(admission
            .serving_blockd(root.cat_id(), root.volume_id())
            .is_some_and(|(_, proof)| proof.is_some()));
        assert!(admission
            .serving_blockd(persistent.cat_id(), persistent.volume_id())
            .is_some_and(|(_, proof)| proof.is_some()));
        assert_eq!(admission.vhost_device_projections()[root.cat_id()].len(), 2);
        assert_eq!(admission.process_projections()[root.cat_id()].len(), 2);

        let missing = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_serving_blockds(
            BTreeMap::from([
                (root_key.clone(), root.clone()),
                (persistent_key.clone(), persistent.clone()),
            ]),
            BTreeMap::from([(root_key.clone(), root_proof.clone())]),
        )
        .unwrap();
        assert!(missing
            .serving_blockd(persistent.cat_id(), persistent.volume_id())
            .is_some_and(|(_, proof)| proof.is_none()));
        assert_eq!(missing.vhost_device_projections()[root.cat_id()].len(), 1);

        assert!(super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_serving_blockds(
            BTreeMap::from([(root_key.clone(), root.clone())]),
            BTreeMap::from([
                (root_key.clone(), root_proof),
                (persistent_key.clone(), persistent_proof),
            ]),
        )
        .is_err());

        let duplicate = root.persistent_vhost_peer_for_test(false);
        let duplicate_key = super::super::root_provision_process::ManagedServingKey::new(
            duplicate.cat_id().clone(),
            duplicate.volume_id().clone(),
        );
        let duplicate_proof = duplicate
            .clone()
            .prove_exact_process(duplicate.exact_evidence_for_test(52))
            .unwrap();
        assert!(super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_serving_blockds(
            BTreeMap::from([(root_key.clone(), root), (duplicate_key.clone(), duplicate)]),
            BTreeMap::from([
                (
                    root_key,
                    serving_expectation(&fixture)
                        .clone()
                        .prove_exact_process(serving_expectation(&fixture).exact_evidence_for_test(51))
                        .unwrap(),
                ),
                (duplicate_key, duplicate_proof),
            ]),
        )
        .is_err());
    }

    #[test]
    fn prepare_device_retirement_stops_only_the_current_exact_physical_incarnation() {
        let mut fixture = fixture();
        let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
        let checkpoint_digest = fixture.stored_checkpoint.content_digest().clone();
        let target_inode = std::fs::metadata(fixture.target_path()).unwrap().ino();
        let record_inode = std::fs::metadata(fixture.record_path()).unwrap().ino();
        let global = Arc::new(RetirementEffectGlobalPort::new(
            &fixture,
            [RootProvisionProcessInspection::Exact(Box::new(
                fixture.process.clone(),
            ))],
        ));
        let process = Arc::new(RetirementEffectStopPort::new([
            RootProvisionProcessStop::Submitted,
        ]));
        let effect = prepare_device_retirement_effect(&fixture, global.clone(), process.clone());

        assert_eq!(
            effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted_process]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(global.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stopped(), vec![fixture.process.clone()]);
        assert_eq!(
            FileCheckpointStore::open(
                &fixture.checkpoint_directory,
                &fixture.acquired.desired.cat_id,
            )
            .unwrap()
            .load()
            .unwrap()
            .unwrap()
            .content_digest(),
            &checkpoint_digest
        );
        assert_eq!(
            std::fs::metadata(fixture.target_path()).unwrap().ino(),
            target_inode
        );
        assert_eq!(
            std::fs::metadata(fixture.record_path()).unwrap().ino(),
            record_inode
        );
    }

    #[test]
    fn prepare_device_retirement_absent_falls_through_dispatcher_exactly_once() {
        let mut fixture = fixture();
        advance_fixture_to_prepare_device(&mut fixture);
        let global = Arc::new(RetirementEffectGlobalPort::new(
            &fixture,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        ));
        let process = Arc::new(RetirementEffectStopPort::new([]));
        let effect = prepare_device_retirement_effect(&fixture, global.clone(), process.clone());
        let mut downstream_dispatches = 0;

        assert_eq!(
            effect
            .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
            .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        match effect
            .try_apply(
                &successor_absent_effect_context(&fixture),
                &fixture.acquired.desired,
            )
            .unwrap()
        {
            None => downstream_dispatches += 1,
            Some(outcome) => panic!("completed retirement intercepted dispatcher: {outcome:?}"),
        }

        assert_eq!(downstream_dispatches, 1);
        assert_eq!(global.calls.load(Ordering::SeqCst), 2);
        assert!(process.stopped().is_empty());
    }

    #[test]
    fn prepare_device_retirement_fails_closed_for_foreign_and_duplicate_processes() {
        for inspection in [
            {
                let mut foreign = fixture().process;
                foreign.ownership_token = random('9');
                foreign.handshake.process_identity_token = random('9');
                RootProvisionProcessInspection::Exact(Box::new(foreign))
            },
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity,
            ),
        ] {
            let mut fixture = fixture();
            let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
            let global = Arc::new(RetirementEffectGlobalPort::new(&fixture, [inspection]));
            let process = Arc::new(RetirementEffectStopPort::new([]));
            let effect =
                prepare_device_retirement_effect(&fixture, global.clone(), process.clone());

            assert_eq!(
                effect
                    .try_apply(
                        &effect_context_with_processes(&fixture, vec![accepted_process]),
                        &fixture.acquired.desired,
                    )
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                ))
            );
            assert_eq!(global.calls.load(Ordering::SeqCst), 1);
            assert!(process.stopped().is_empty());
        }
    }

    #[test]
    fn prepare_device_retirement_requires_exact_accepted_physical_projection() {
        for field in ["pid", "start", "unit", "socket", "token"] {
            let mut fixture = fixture();
            let mut accepted_process = advance_fixture_to_prepare_device(&mut fixture);
            match field {
                "pid" => accepted_process.process_id += 1,
                "start" => {
                    accepted_process.process_start_time_ticks =
                        WireU64::new(accepted_process.process_start_time_ticks.get() + 1).unwrap();
                }
                "unit" => accepted_process.scope_id = id("cats-root-foreign.service"),
                "socket" => {
                    accepted_process.control_socket_path = host("/run/cats/foreign.sock");
                }
                "token" => {
                    accepted_process.ownership_token = OwnershipTokenEvidence::Valid {
                        ownership_token: random('9'),
                    };
                }
                _ => unreachable!(),
            }
            let global = Arc::new(RetirementEffectGlobalPort::new(
                &fixture,
                [RootProvisionProcessInspection::Exact(Box::new(
                    fixture.process.clone(),
                ))],
            ));
            let process = Arc::new(RetirementEffectStopPort::new([]));
            let effect =
                prepare_device_retirement_effect(&fixture, global.clone(), process.clone());

            assert_eq!(
                effect
                    .try_apply(
                        &effect_context_without_node_global_process(
                            &fixture,
                            vec![accepted_process],
                        ),
                        &fixture.acquired.desired,
                    )
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                )),
                "accepted {field} mismatch was not rejected",
            );
            assert_eq!(global.calls.load(Ordering::SeqCst), 0);
            assert!(process.stopped().is_empty());
        }
    }

    #[test]
    fn prepare_device_retirement_rechecks_fresh_authority_before_stop() {
        let mut fixture = fixture();
        let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let drifted_authority = Arc::clone(&authority);
        let global = Arc::new(RetirementEffectGlobalPort::with_after_sweep(
            &fixture,
            RootProvisionProcessInspection::Exact(Box::new(fixture.process.clone())),
            move || {
                drifted_authority.record.lock().unwrap().lease_owner = Some(id("att_foreign"));
            },
        ));
        let process = Arc::new(RetirementEffectStopPort::new([]));
        let effect =
            PrepareDeviceTargetRetirementEffect::for_test(authority, global, process.clone());

        assert_eq!(
            effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted_process]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::LocalContract,
            ))
        );
        assert!(process.stopped().is_empty());
    }

    #[test]
    fn prepare_device_retirement_rejects_initial_and_mid_sweep_lease_rollback() {
        for rollback_before_sweep in [true, false] {
            let mut fixture = fixture();
            let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
            let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
            let rollback_expiry = UnixMillis::new(
                fixture
                    .acquired
                    .attachment
                    .lease_expires_at
                    .get()
                    .checked_sub(1)
                    .unwrap(),
            )
            .unwrap();
            let global = if rollback_before_sweep {
                authority.record.lock().unwrap().lease_expires_at = Some(rollback_expiry);
                Arc::new(RetirementEffectGlobalPort::new(
                    &fixture,
                    [RootProvisionProcessInspection::Exact(Box::new(
                        fixture.process.clone(),
                    ))],
                ))
            } else {
                let rollback = Arc::clone(&authority);
                Arc::new(RetirementEffectGlobalPort::with_after_sweep(
                    &fixture,
                    RootProvisionProcessInspection::Exact(Box::new(fixture.process.clone())),
                    move || {
                        rollback.record.lock().unwrap().lease_expires_at = Some(rollback_expiry);
                    },
                ))
            };
            let process = Arc::new(RetirementEffectStopPort::new([]));
            let effect = PrepareDeviceTargetRetirementEffect::for_test(
                authority,
                global.clone(),
                process.clone(),
            );

            assert_eq!(
                effect
                    .try_apply(
                        &effect_context_with_processes(&fixture, vec![accepted_process]),
                        &fixture.acquired.desired,
                    )
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                ))
            );
            assert_eq!(
                global.calls.load(Ordering::SeqCst),
                usize::from(!rollback_before_sweep)
            );
            assert!(process.stopped().is_empty());
        }
    }

    #[test]
    fn prepare_device_retirement_allows_monotonic_lease_renewal_during_sweep() {
        let mut fixture = fixture();
        let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let renewal = Arc::clone(&authority);
        let renewed_expiry = UnixMillis::new(
            fixture
                .authority
                .volume
                .lease_expires_at
                .unwrap()
                .get()
                .checked_add(60_000)
                .unwrap(),
        )
        .unwrap();
        let global = Arc::new(RetirementEffectGlobalPort::with_after_sweep(
            &fixture,
            RootProvisionProcessInspection::Exact(Box::new(fixture.process.clone())),
            move || renewal.record.lock().unwrap().lease_expires_at = Some(renewed_expiry),
        ));
        let process = Arc::new(RetirementEffectStopPort::new([
            RootProvisionProcessStop::Submitted,
        ]));
        let effect = PrepareDeviceTargetRetirementEffect::for_test(
            authority,
            global.clone(),
            process.clone(),
        );

        assert_eq!(
            effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted_process]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(global.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stopped(), vec![fixture.process.clone()]);
    }

    #[test]
    fn prepare_device_retirement_rejects_late_process_after_accepted_absence() {
        let mut fixture = fixture();
        advance_fixture_to_prepare_device(&mut fixture);
        let global = Arc::new(RetirementEffectGlobalPort::new(
            &fixture,
            [RootProvisionProcessInspection::Exact(Box::new(
                fixture.process.clone(),
            ))],
        ));
        let process = Arc::new(RetirementEffectStopPort::new([]));
        let effect = prepare_device_retirement_effect(&fixture, global.clone(), process.clone());

        assert_eq!(
            effect
                .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::Stop(
                RuntimeDesiredEffectStopReason::LocalContract,
            ))
        );
        assert_eq!(global.calls.load(Ordering::SeqCst), 1);
        assert!(process.stopped().is_empty());
    }

    #[test]
    fn prepare_device_retirement_rejects_record_and_target_aba_before_stop() {
        for mutate_record in [true, false] {
            let mut fixture = fixture();
            let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
            let artifact_path = if mutate_record {
                fixture.record_path()
            } else {
                fixture.target_path()
            };
            let replaced_path = artifact_path.with_file_name(format!(
                "{}.aba-old",
                artifact_path.file_name().unwrap().to_str().unwrap()
            ));
            let artifact_bytes = std::fs::read(&artifact_path).unwrap();
            let global = Arc::new(RetirementEffectGlobalPort::with_after_sweep(
                &fixture,
                RootProvisionProcessInspection::Exact(Box::new(fixture.process.clone())),
                move || {
                    std::fs::rename(&artifact_path, &replaced_path).unwrap();
                    std::fs::write(&artifact_path, artifact_bytes).unwrap();
                },
            ));
            let process = Arc::new(RetirementEffectStopPort::new([]));
            let effect = prepare_device_retirement_effect(&fixture, global, process.clone());

            assert_eq!(
                effect
                    .try_apply(
                        &effect_context_with_processes(&fixture, vec![accepted_process]),
                        &fixture.acquired.desired,
                    )
                    .unwrap(),
                Some(RuntimeDesiredEffectOutcome::Stop(
                    RuntimeDesiredEffectStopReason::LocalContract,
                ))
            );
            assert!(process.stopped().is_empty());
        }
    }

    #[test]
    fn prepare_device_retirement_cancellation_before_submit_never_stops() {
        let mut fixture = fixture();
        let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
        let context = effect_context_with_processes(&fixture, vec![accepted_process]);
        let canceller = context.clone();
        let global = Arc::new(RetirementEffectGlobalPort::with_after_sweep(
            &fixture,
            RootProvisionProcessInspection::Exact(Box::new(fixture.process.clone())),
            move || canceller.cancel_for_test(),
        ));
        let process = Arc::new(RetirementEffectStopPort::new([]));
        let effect = prepare_device_retirement_effect(&fixture, global, process.clone());

        assert!(effect
            .try_apply(&context, &fixture.acquired.desired)
            .is_err());
        assert!(process.stopped().is_empty());
    }

    #[test]
    fn prepare_device_retirement_response_loss_converges_to_absent_without_second_stop() {
        let mut fixture = fixture();
        let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
        let global = Arc::new(RetirementEffectGlobalPort::new(
            &fixture,
            [
                RootProvisionProcessInspection::Exact(Box::new(fixture.process.clone())),
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        ));
        let process = Arc::new(RetirementEffectStopPort::new([
            RootProvisionProcessStop::Unavailable,
        ]));
        let effect = prepare_device_retirement_effect(&fixture, global.clone(), process.clone());

        assert_eq!(
            effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted_process]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(process.stopped().len(), 1);
        assert_eq!(
            effect
                .try_apply(
                    &successor_absent_effect_context(&fixture),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            effect
                .try_apply(
                    &restarted_absent_effect_context(&fixture),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            None
        );
        assert_eq!(process.stopped().len(), 1);
        assert_eq!(global.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn prepare_device_retirement_one_effect_refreshes_when_stop_reports_already_absent() {
        let mut fixture = fixture();
        let accepted_process = advance_fixture_to_prepare_device(&mut fixture);
        let global = Arc::new(RetirementEffectGlobalPort::new(
            &fixture,
            [RootProvisionProcessInspection::Exact(Box::new(
                fixture.process.clone(),
            ))],
        ));
        let process = Arc::new(RetirementEffectStopPort::new([
            RootProvisionProcessStop::AlreadyAbsent,
        ]));
        let effect = prepare_device_retirement_effect(&fixture, global.clone(), process.clone());

        assert_eq!(
            effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted_process]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(global.calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.stopped(), vec![fixture.process.clone()]);
    }

    #[test]
    fn serving_handoff_effect_converges_one_effect_per_fresh_full_without_repeating_start() {
        let fixture = fixture();
        let blank_bytes = std::fs::read(&fixture.blank_authorization_path).unwrap();
        let blank_inode = std::fs::metadata(&fixture.blank_authorization_path)
            .unwrap()
            .ino();
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let blob = Arc::new(exact_manifest_blob(&fixture));
        let exact = fixture.process.clone();
        let global = Arc::new(EffectGlobalProcessPort {
            inspections: Mutex::new(
                [
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Exact(Box::new(exact.clone())),
                    RootProvisionProcessInspection::Exact(Box::new(exact.clone())),
                    RootProvisionProcessInspection::Exact(Box::new(exact)),
                ]
                .into(),
            ),
            calls: AtomicUsize::new(0),
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let target_process = Arc::new(EffectTargetProcessPort {
            starts: AtomicUsize::new(0),
            evidence: fixture.process.clone(),
            outcome: EffectTargetProcessOutcome::ResponseLost,
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let effect = ServingHandoffEffect::new(
            authority.clone(),
            blob,
            global.clone(),
            target_process.clone(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();

        assert!(matches!(
            effect
                .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert!(fixture.target_path().exists());
        assert!(!fixture.record_path().exists());
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 0);
        let target_inode = std::fs::metadata(fixture.target_path()).unwrap().ino();

        assert!(matches!(
            effect
                .try_apply(
                    &successor_absent_effect_context(&fixture),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 1);
        assert!(!fixture.record_path().exists());

        // A late exact process after an ambiguous response makes the accepted
        // empty vector stale. It refreshes and never submits the unit again.
        assert!(matches!(
            effect
                .try_apply(
                    &restarted_absent_effect_context(&fixture),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 1);
        assert!(!fixture.record_path().exists());

        let accepted_process = fixture
            .exact_process_proof()
            .unwrap()
            .into_process_evidence();
        assert!(matches!(
            effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![accepted_process.clone()]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert!(fixture.record_path().exists());
        let record_inode = std::fs::metadata(fixture.record_path()).unwrap().ino();

        let ready = effect
            .try_apply(
                &effect_context_with_processes(&fixture, vec![accepted_process]),
                &fixture.acquired.desired,
            )
            .unwrap();
        let ServingHandoffEffectProgress::Ready(ready) = ready else {
            panic!("fresh exact scan must reopen the sealed handoff Ready")
        };
        ready.assert_current(&fixture.stored_checkpoint).unwrap();
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 1);
        assert_eq!(global.calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            std::fs::metadata(fixture.target_path()).unwrap().ino(),
            target_inode
        );
        assert_eq!(
            std::fs::metadata(fixture.record_path()).unwrap().ino(),
            record_inode
        );
        assert_eq!(
            std::fs::read(&fixture.blank_authorization_path).unwrap(),
            blank_bytes
        );
        assert_eq!(
            std::fs::metadata(&fixture.blank_authorization_path)
                .unwrap()
                .ino(),
            blank_inode
        );
        assert_eq!(authority.loads.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn production_prepare_cas_freezes_complete_vhost_plan_and_is_the_only_effect() {
        let fixture = fixture();
        let ready = fixture
            .store()
            .seal_serving_ready(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &fixture.exact_process_proof().unwrap(),
            )
            .unwrap();
        let context = effect_context_with_processes(
            &fixture,
            vec![fixture
                .exact_process_proof()
                .unwrap()
                .into_process_evidence()],
        );
        let effect = ServingPrepareDeviceEffect::new(
            ServingPrepareFrontend::vhost_user_blk(8, 256).unwrap(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();

        effect
            .persist(&context, &fixture.acquired.desired, &ready)
            .expect("persist complete production PrepareDevice successor");
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let current = checkpoint_store.load().unwrap().unwrap();
        let ReconcileStep::PrepareDevice { devices } = &current.checkpoint().step else {
            panic!("production Ready must advance only to PrepareDevice")
        };
        let [device] = devices.as_slice() else {
            panic!("single-Root fixture must prepare one device")
        };
        let attachment = &fixture.acquired.attachment;
        assert_eq!(
            &device.volume_intent_id,
            &fixture.acquired.volume.volume_intent_id
        );
        assert_eq!(&device.disk_id, &fixture.acquired.volume.disk_id);
        assert_eq!(&device.volume_id, &attachment.identity.volume_id);
        assert_eq!(device.disk_kind, fixture.acquired.volume.disk_kind);
        assert_eq!(&device.attachment_id, &attachment.identity.attachment_id);
        assert_eq!(
            device.attachment_epoch,
            attachment.identity.attachment_epoch
        );
        assert_eq!(&device.acquire_origin, &attachment.identity.acquire_origin);
        assert_eq!(&device.expected_head, &fixture.authority.volume.head);
        assert_eq!(device.size_bytes, attachment.size_bytes);
        assert_eq!(device.durability, attachment.durability);
        assert_eq!(&device.guest_device, &fixture.acquired.volume.guest_device);
        assert_ne!(
            &device.ownership_token,
            &device.serving_process.process_identity_token
        );
        assert_ne!(
            device.serving_process.process_identity_token,
            fixture.process.ownership_token
        );
        assert_eq!(
            device.serving_process.executable_path,
            fixture.expected_executable_path
        );
        assert_eq!(
            device.serving_process.data_directory.as_str(),
            fixture.data_directory.to_str().unwrap()
        );
        assert!(device
            .serving_process
            .scope_id
            .as_str()
            .starts_with("cats-serving-"));
        assert!(device
            .serving_process
            .scope_id
            .as_str()
            .ends_with(".service"));
        let (expected_control_socket, expected_io_socket) =
            managed_serving_sockets(&device.ownership_token);
        assert_eq!(
            device.serving_process.control_socket_path,
            expected_control_socket
        );
        let ServingAuthorityProvenance::AfterRootProvision { handoff } =
            device.serving_authority.as_ref()
        else {
            panic!("new Root must retain after-root-provision provenance")
        };
        assert_eq!(
            &handoff.predecessor_checkpoint_content_digest,
            fixture.stored_checkpoint.content_digest()
        );
        assert_eq!(
            handoff.record.path.as_str(),
            fixture.record_path().to_str().unwrap()
        );
        assert_eq!(
            &device.frontend,
            &PrepareDeviceFrontend::VhostUserBlk {
                socket_path: expected_io_socket,
                queues: fixture.acquired.desired.runtime.vcpus as u16,
                queue_size: 256,
            }
        );
        assert!(current.checkpoint().processes.is_empty());
        assert!(current.checkpoint().volumes[0].devices.is_empty());

        let durable_digest = current.content_digest().clone();
        drop(checkpoint_store);
        assert!(effect
            .persist(&context, &fixture.acquired.desired, &ready)
            .is_err());
        let replayed = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
        assert_eq!(replayed.content_digest(), &durable_digest);
    }

    #[test]
    fn cancelled_or_aba_after_prepare_cas_never_authorizes_a_second_effect() {
        let cancelled = fixture();
        let cancelled_ready = cancelled
            .store()
            .seal_serving_ready(
                &cancelled.stored_checkpoint,
                &cancelled.acquired,
                &cancelled.authority,
                &cancelled.exact_process_proof().unwrap(),
            )
            .unwrap();
        let cancelled_context = effect_context_with_processes(
            &cancelled,
            vec![cancelled
                .exact_process_proof()
                .unwrap()
                .into_process_evidence()],
        );
        let canceller = cancelled_context.clone();
        let cancelled_effect = ServingPrepareDeviceEffect::new(
            ServingPrepareFrontend::vhost_user_blk(2, 256).unwrap(),
            cancelled.expected_executable_path.clone(),
        )
        .unwrap()
        .with_after_replace(Arc::new(move || canceller.cancel_for_test()));
        let cancellation = cancelled_effect
            .persist(
                &cancelled_context,
                &cancelled.acquired.desired,
                &cancelled_ready,
            )
            .unwrap_err();
        assert!(cancellation.to_string().contains("cancelled"));
        let cancelled_current = FileCheckpointStore::open(
            &cancelled.checkpoint_directory,
            &cancelled.acquired.desired.cat_id,
        )
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
        assert!(matches!(
            cancelled_current.checkpoint().step,
            ReconcileStep::PrepareDevice { .. }
        ));

        let aba = fixture();
        let aba_ready = aba
            .store()
            .seal_serving_ready(
                &aba.stored_checkpoint,
                &aba.acquired,
                &aba.authority,
                &aba.exact_process_proof().unwrap(),
            )
            .unwrap();
        let aba_context = effect_context_with_processes(
            &aba,
            vec![aba.exact_process_proof().unwrap().into_process_evidence()],
        );
        let record_path = aba.record_path();
        let aba_effect = ServingPrepareDeviceEffect::new(
            ServingPrepareFrontend::vhost_user_blk(2, 256).unwrap(),
            aba.expected_executable_path.clone(),
        )
        .unwrap()
        .with_after_replace(Arc::new(move || swap_same_bytes(&record_path, "post-cas")));
        assert!(aba_effect
            .persist(&aba_context, &aba.acquired.desired, &aba_ready)
            .is_err());
        let aba_current =
            FileCheckpointStore::open(&aba.checkpoint_directory, &aba.acquired.desired.cat_id)
                .unwrap()
                .load()
                .unwrap()
                .unwrap();
        assert!(matches!(
            aba_current.checkpoint().step,
            ReconcileStep::PrepareDevice { .. }
        ));
    }

    #[test]
    fn sealed_handoff_process_exit_enters_durable_retirement_before_any_restart() {
        let fixture = fixture();
        drop(
            fixture
                .store()
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap(),
        );
        let global = Arc::new(EffectGlobalProcessPort {
            inspections: Mutex::new([RootProvisionProcessInspection::Absent].into()),
            calls: AtomicUsize::new(0),
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let target_process = Arc::new(EffectTargetProcessPort {
            starts: AtomicUsize::new(0),
            evidence: fixture.process.clone(),
            outcome: EffectTargetProcessOutcome::Started,
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let effect = ServingHandoffEffect::new(
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            Arc::new(exact_manifest_blob(&fixture)),
            global,
            target_process.clone(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();

        assert!(matches!(
            effect
                .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert!(!fixture.record_path().exists());
        assert!(fixture.retirement_path().exists());
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn retirement_receipt_blocks_restart_until_successor_rotation_then_reseals() {
        let mut fixture = fixture();
        drop(
            fixture
                .store()
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap(),
        );
        let old_checkpoint = fixture.stored_checkpoint.checkpoint().clone();
        let old_process = fixture
            .exact_process_proof()
            .unwrap()
            .into_process_evidence();
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let retirement_global = Arc::new(EffectGlobalProcessPort {
            inspections: Mutex::new(
                [
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                ]
                .into(),
            ),
            calls: AtomicUsize::new(0),
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let forbidden_start = Arc::new(EffectTargetProcessPort {
            starts: AtomicUsize::new(0),
            evidence: fixture.process.clone(),
            outcome: EffectTargetProcessOutcome::Started,
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let retirement_effect = ServingHandoffEffect::new(
            authority.clone(),
            Arc::new(exact_manifest_blob(&fixture)),
            retirement_global.clone(),
            forbidden_start.clone(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();

        assert!(matches!(
            retirement_effect
                .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert!(fixture.retirement_path().exists());
        assert!(!fixture.record_path().exists());

        let same_admission = retirement_effect
            .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
            .unwrap_err();
        assert!(
            same_admission.to_string().contains("strictly successor"),
            "same retirement admission was not rejected: {same_admission:#}"
        );
        assert_eq!(forbidden_start.starts.load(Ordering::SeqCst), 0);
        assert_eq!(
            FileCheckpointStore::open(
                &fixture.checkpoint_directory,
                &fixture.acquired.desired.cat_id,
            )
            .unwrap()
            .load()
            .unwrap()
            .unwrap()
            .checkpoint(),
            &old_checkpoint
        );

        // A restarted Agent with a strictly later accepted full may perform
        // only the token/timestamp replacement. The durable current-attempt
        // receipt still forbids a process start in this round.
        assert!(matches!(
            retirement_effect
                .try_apply(
                    &restarted_absent_effect_context(&fixture),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert_eq!(forbidden_start.starts.load(Ordering::SeqCst), 0);
        assert_eq!(retirement_global.calls.load(Ordering::SeqCst), 3);
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let rotated = checkpoint_store.load().unwrap().unwrap();
        let ReconcileStep::ProvisionRootImage {
            process_identity_token: new_token,
            ..
        } = &rotated.checkpoint().step
        else {
            unreachable!()
        };
        let new_token = new_token.clone();
        let mut expected_rotated = old_checkpoint.clone();
        let ReconcileStep::ProvisionRootImage {
            process_identity_token,
            ..
        } = &mut expected_rotated.step
        else {
            unreachable!()
        };
        *process_identity_token = new_token.clone();
        expected_rotated.updated_at_unix_ms = rotated.checkpoint().updated_at_unix_ms;
        assert_eq!(rotated.checkpoint(), &expected_rotated);
        fixture.stored_checkpoint = rotated;
        drop(checkpoint_store);

        // A late old process still carrying the retired token cannot be
        // rebound to the successor checkpoint or trigger a start/reseal.
        assert!(retirement_effect
            .try_apply(
                &effect_context_with_processes(&fixture, vec![old_process]),
                &fixture.acquired.desired,
            )
            .is_err());
        assert_eq!(forbidden_start.starts.load(Ordering::SeqCst), 0);
        assert!(!fixture.record_path().exists());

        fixture.process.ownership_token = new_token.clone();
        fixture.process.handshake.process_identity_token = new_token;
        let exact = fixture.process.clone();
        let converge_global = Arc::new(EffectGlobalProcessPort {
            inspections: Mutex::new(
                [
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Exact(Box::new(exact.clone())),
                    RootProvisionProcessInspection::Exact(Box::new(exact)),
                ]
                .into(),
            ),
            calls: AtomicUsize::new(0),
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let target_process = Arc::new(EffectTargetProcessPort {
            starts: AtomicUsize::new(0),
            evidence: fixture.process.clone(),
            outcome: EffectTargetProcessOutcome::ResponseLost,
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let converge_effect = ServingHandoffEffect::new(
            authority,
            Arc::new(exact_manifest_blob(&fixture)),
            converge_global.clone(),
            target_process.clone(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();

        assert!(matches!(
            converge_effect
                .try_apply(
                    &successor_absent_effect_context(&fixture),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 1);
        assert!(!fixture.record_path().exists());
        let process = fixture
            .exact_process_proof()
            .unwrap()
            .into_process_evidence();
        assert!(matches!(
            converge_effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![process.clone()]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert!(fixture.record_path().exists());
        assert!(fixture.retirement_path().exists());
        assert!(matches!(
            converge_effect
                .try_apply(
                    &effect_context_with_processes(&fixture, vec![process]),
                    &fixture.acquired.desired,
                )
                .unwrap(),
            ServingHandoffEffectProgress::Ready(_)
        ));
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 1);
        assert_eq!(converge_global.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn serving_handoff_effect_rejects_global_duplicate_before_start() {
        let fixture = fixture();
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let global = Arc::new(EffectGlobalProcessPort {
            inspections: Mutex::new(
                [RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::DuplicateIdentity,
                )]
                .into(),
            ),
            calls: AtomicUsize::new(0),
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let target_process = Arc::new(EffectTargetProcessPort {
            starts: AtomicUsize::new(0),
            evidence: fixture.process.clone(),
            outcome: EffectTargetProcessOutcome::Started,
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let effect = ServingHandoffEffect::new(
            authority,
            Arc::new(exact_manifest_blob(&fixture)),
            global,
            target_process.clone(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();
        effect
            .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
            .unwrap();
        assert!(effect
            .try_apply(
                &successor_absent_effect_context(&fixture),
                &fixture.acquired.desired,
            )
            .is_err());
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 0);
        assert!(!fixture.record_path().exists());
    }

    #[test]
    fn target_or_owner_drift_after_global_reinspection_has_zero_start_effect() {
        for drift in [AuthorityDrift::BackToBlank, AuthorityDrift::ForeignOwner] {
            let fixture = fixture();
            drop(
                fixture
                    .store()
                    .seal_target_control_authorization(
                        &fixture.stored_checkpoint,
                        &fixture.acquired,
                        &fixture.authority,
                    )
                    .unwrap(),
            );
            let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
            let global = Arc::new(AuthorityDriftingGlobalPort {
                authority: authority.clone(),
                drift,
                managed_root: Arc::clone(&fixture.managed_root),
            });
            let target_process = Arc::new(EffectTargetProcessPort {
                starts: AtomicUsize::new(0),
                evidence: fixture.process.clone(),
                outcome: EffectTargetProcessOutcome::Started,
                managed_root: Arc::clone(&fixture.managed_root),
            });
            let effect = ServingHandoffEffect::new(
                authority.clone(),
                Arc::new(exact_manifest_blob(&fixture)),
                global,
                target_process.clone(),
                fixture.expected_executable_path.clone(),
            )
            .unwrap();

            assert!(effect
                .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                .is_err());
            assert_eq!(authority.loads.load(Ordering::SeqCst), 2);
            assert_eq!(target_process.starts.load(Ordering::SeqCst), 0);
            assert!(!fixture.record_path().exists());
        }
    }

    #[test]
    fn serving_handoff_effect_leaves_unpublished_temp_for_prescan_recovery() {
        let fixture = fixture();
        std::fs::write(fixture.target_temp_path(), b"partial").unwrap();
        std::fs::set_permissions(
            fixture.target_temp_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let global = Arc::new(EffectGlobalProcessPort {
            inspections: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let target_process = Arc::new(EffectTargetProcessPort {
            starts: AtomicUsize::new(0),
            evidence: fixture.process.clone(),
            outcome: EffectTargetProcessOutcome::Started,
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let effect = ServingHandoffEffect::new(
            Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone())),
            Arc::new(exact_manifest_blob(&fixture)),
            global.clone(),
            target_process.clone(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();

        assert!(effect
            .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
            .is_err());
        assert!(fixture.target_temp_path().exists());
        assert!(!fixture.target_path().exists());
        assert_eq!(global.calls.load(Ordering::SeqCst), 0);
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn serving_handoff_effect_never_consumes_a_late_checkpoint_temp() {
        let fixture = fixture();
        let checkpoint_temp = fixture.checkpoint_directory.join(format!(
            ".cat-{}.checkpoint.tmp",
            fixture.stored_checkpoint.checkpoint().cat_id
        ));
        std::fs::write(&checkpoint_temp, b"partial").unwrap();
        std::fs::set_permissions(&checkpoint_temp, std::fs::Permissions::from_mode(0o600)).unwrap();
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let global = Arc::new(EffectGlobalProcessPort {
            inspections: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let target_process = Arc::new(EffectTargetProcessPort {
            starts: AtomicUsize::new(0),
            evidence: fixture.process.clone(),
            outcome: EffectTargetProcessOutcome::Started,
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let effect = ServingHandoffEffect::new(
            authority.clone(),
            Arc::new(exact_manifest_blob(&fixture)),
            global.clone(),
            target_process.clone(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();

        assert!(effect
            .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
            .is_err());
        assert!(checkpoint_temp.exists());
        assert!(!fixture.target_path().exists());
        assert_eq!(authority.loads.load(Ordering::SeqCst), 0);
        assert_eq!(global.calls.load(Ordering::SeqCst), 0);
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancelled_clean_target_start_keeps_only_the_replayable_artifact() {
        let fixture = fixture();
        let authority = Arc::new(FixedEffectAuthority::new(fixture.authority.volume.clone()));
        let global = Arc::new(EffectGlobalProcessPort {
            inspections: Mutex::new([RootProvisionProcessInspection::Absent].into()),
            calls: AtomicUsize::new(0),
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let target_process = Arc::new(EffectTargetProcessPort {
            starts: AtomicUsize::new(0),
            evidence: fixture.process.clone(),
            outcome: EffectTargetProcessOutcome::CancelledClean,
            managed_root: Arc::clone(&fixture.managed_root),
        });
        let effect = ServingHandoffEffect::new(
            authority.clone(),
            Arc::new(exact_manifest_blob(&fixture)),
            global,
            target_process.clone(),
            fixture.expected_executable_path.clone(),
        )
        .unwrap();

        assert!(matches!(
            effect
                .try_apply(&absent_effect_context(&fixture), &fixture.acquired.desired)
                .unwrap(),
            ServingHandoffEffectProgress::RefreshInventory
        ));
        assert!(effect
            .try_apply(
                &successor_absent_effect_context(&fixture),
                &fixture.acquired.desired,
            )
            .is_err());
        assert!(fixture.target_path().exists());
        assert!(!fixture.record_path().exists());
        assert_eq!(target_process.starts.load(Ordering::SeqCst), 1);
        assert_eq!(authority.loads.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn target_start_permit_rechecks_artifact_and_state_root_aba_at_submit_barrier() {
        {
            let fixture = fixture();
            let store = fixture.store();
            let target = store
                .seal_target_control_authorization(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                )
                .unwrap();
            let expectation = RootProvisionProcessExpectation::from_checkpoint(
                fixture.stored_checkpoint.checkpoint(),
                RootProvisionAuthoritySnapshot {
                    attachment: fixture.acquired.attachment.clone(),
                    volume: &fixture.authority.volume,
                },
                fixture.expected_executable_path.clone(),
            )
            .unwrap()
            .with_target_control_launch(target_control_process_launch_identity(target.identity()))
            .unwrap();
            let checkpoint_store = FileCheckpointStore::open(
                &fixture.checkpoint_directory,
                &fixture.stored_checkpoint.checkpoint().cat_id,
            )
            .unwrap();
            let current = checkpoint_store.load().unwrap().unwrap();
            let permit = super::super::root_provision_process::retain_target_control_process_start(
                &checkpoint_store,
                &current,
                &expectation,
                &target,
            )
            .unwrap();

            let bytes = std::fs::read(fixture.target_path()).unwrap();
            let displaced = fixture.data_directory.join("displaced-target");
            std::fs::rename(fixture.target_path(), &displaced).unwrap();
            std::fs::write(fixture.target_path(), bytes).unwrap();
            std::fs::set_permissions(
                fixture.target_path(),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();

            assert!(permit.assert_current().is_err());
            assert!(target.assert_current(&current).is_err());
        }

        let root_fixture = fixture();
        let root_store = root_fixture.store();
        let root_target = root_store
            .seal_target_control_authorization(
                &root_fixture.stored_checkpoint,
                &root_fixture.acquired,
                &root_fixture.authority,
            )
            .unwrap();
        let root_expectation = RootProvisionProcessExpectation::from_checkpoint(
            root_fixture.stored_checkpoint.checkpoint(),
            RootProvisionAuthoritySnapshot {
                attachment: root_fixture.acquired.attachment.clone(),
                volume: &root_fixture.authority.volume,
            },
            root_fixture.expected_executable_path.clone(),
        )
        .unwrap()
        .with_target_control_launch(target_control_process_launch_identity(
            root_target.identity(),
        ))
        .unwrap();
        let root_checkpoint_store = FileCheckpointStore::open(
            &root_fixture.checkpoint_directory,
            &root_fixture.stored_checkpoint.checkpoint().cat_id,
        )
        .unwrap();
        let root_current = root_checkpoint_store.load().unwrap().unwrap();
        let root_permit =
            super::super::root_provision_process::retain_target_control_process_start(
                &root_checkpoint_store,
                &root_current,
                &root_expectation,
                &root_target,
            )
            .unwrap();

        let root_path = root_fixture.state_directory.path().to_path_buf();
        let displaced_root = root_path.with_extension("submit-barrier-old");
        std::fs::rename(&root_path, &displaced_root).unwrap();
        std::fs::create_dir(&root_path).unwrap();
        std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(root_permit.assert_current().is_err());
        assert!(root_target.assert_current(&root_current).is_err());
        drop(root_permit);
        std::fs::remove_dir(&root_path).unwrap();
        std::fs::rename(displaced_root, root_path).unwrap();
    }

    #[test]
    fn sealed_record_can_retire_then_rotate_and_reseal_without_overwrite() {
        let mut fixture = fixture();
        let handoff_store = fixture.store();
        let first_ready = handoff_store
            .seal_serving_ready(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &fixture.exact_process_proof().unwrap(),
            )
            .unwrap();
        let first_record_inode = first_ready.record_identity().inode();
        let target_inode = std::fs::metadata(fixture.target_path()).unwrap().ino();
        drop(first_ready); // crash after the record durability barrier

        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let process_port = RetirementProcessPort::with_inspections(
            &fixture,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        );
        assert_eq!(
            handoff_store
                .retire_record_after_exact_process_absence(
                    &checkpoint_store,
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    fixture.expected_executable_path.clone(),
                    &process_port,
                    &absent_effect_context(&fixture),
                )
                .unwrap(),
            ServingHandoffRetirement::Retired
        );
        assert!(!fixture.record_path().exists());
        assert!(fixture.target_path().exists());
        assert_eq!(
            std::fs::metadata(fixture.target_path()).unwrap().ino(),
            target_inode
        );

        let old_checkpoint = fixture.stored_checkpoint.checkpoint().clone();
        let old_context = provision_root_authorization_context_digest(&old_checkpoint).unwrap();
        let new_token = random('5');
        fixture.stored_checkpoint = handoff_store
            .rotate_process_token_after_retirement(
                &checkpoint_store,
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                fixture.expected_executable_path.clone(),
                new_token.clone(),
                UnixMillis::new(
                    old_checkpoint
                        .updated_at_unix_ms
                        .get()
                        .checked_add(1)
                        .unwrap(),
                )
                .unwrap(),
                &process_port,
                &successor_absent_effect_context(&fixture),
            )
            .unwrap();
        let ReconcileStep::ProvisionRootImage {
            scope_id: rotated_scope,
            control_socket_path: rotated_control,
            data_directory: rotated_data,
            process_identity_token: rotated_token,
            ..
        } = &fixture.stored_checkpoint.checkpoint().step
        else {
            unreachable!()
        };
        let ReconcileStep::ProvisionRootImage {
            scope_id: old_scope,
            control_socket_path: old_control,
            data_directory: old_data,
            ..
        } = &old_checkpoint.step
        else {
            unreachable!()
        };
        assert_eq!(rotated_token, &new_token);
        assert_eq!(
            (rotated_scope, rotated_control, rotated_data),
            (old_scope, old_control, old_data)
        );
        assert_eq!(
            provision_root_authorization_context_digest(fixture.stored_checkpoint.checkpoint())
                .unwrap(),
            old_context
        );

        let replayed_target = handoff_store
            .seal_target_control_authorization(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
            )
            .unwrap();
        assert_eq!(
            std::fs::metadata(fixture.target_path()).unwrap().ino(),
            target_inode
        );
        drop(replayed_target);

        fixture.process.ownership_token = new_token.clone();
        fixture.process.handshake.process_identity_token = new_token;
        let second_ready = handoff_store
            .seal_serving_ready(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &fixture.exact_process_proof().unwrap(),
            )
            .unwrap();
        assert_ne!(second_ready.record_identity().inode(), first_record_inode);
        let target_bytes = std::fs::read(fixture.target_path()).unwrap();
        let record_bytes = std::fs::read(fixture.record_path()).unwrap();
        let retirement_bytes = std::fs::read(fixture.retirement_path()).unwrap();
        let target_scan = scanned_file(&fixture.target_path(), &target_bytes);
        let record_scan = scanned_file(&fixture.record_path(), &record_bytes);
        let retirement_scan = scanned_file(&fixture.retirement_path(), &retirement_bytes);
        validate_scanned_serving_handoff_artifacts(
            fixture.stored_checkpoint.checkpoint(),
            &fixture.acquired,
            &target_scan,
            Some(&record_scan),
            Some(&retirement_scan),
        )
        .expect("fresh classifier accepts rotated receipt plus the new exact handoff");
        let successor = second_ready
            .consume_for_prepare_device(&fixture.stored_checkpoint, |handoff| {
                let successor = prepare_device_successor(&fixture, handoff);
                checkpoint_store
                    .replace(&fixture.stored_checkpoint, &successor)
                    .context("real PrepareDevice CAS after resealed handoff")?;
                Ok(successor)
            })
            .unwrap();
        let current = checkpoint_store.load().unwrap().unwrap();
        assert_eq!(current.checkpoint(), &successor);
        assert!(matches!(
            current.checkpoint().step,
            ReconcileStep::PrepareDevice { .. }
        ));
        let retained = validate_scanned_serving_handoff_artifacts(
            current.checkpoint(),
            &fixture.acquired,
            &target_scan,
            Some(&record_scan),
            Some(&retirement_scan),
        )
        .expect("PrepareDevice fresh classifier retains the exact rotated provenance")
        .expect("PrepareDevice after-root handoff retains its old physical process");
        assert_eq!(
            retained.physical_identity,
            RetainedRootProvisionPhysicalIdentity {
                process_id: fixture.process.process_id,
                unit_main_process_id: fixture.process.unit_main_process_id,
                process_start_time_ticks: fixture.process.process_start_time_ticks,
                cgroup_process_ids: fixture.process.cgroup_process_ids.clone(),
                handshake_peer_process_id: fixture.process.handshake.peer_process_id,
            }
        );

        let mut oversized_record = decode_serving_handoff_record(&record_bytes).unwrap();
        let oversized_pid = WireU64::new(u64::from(u32::MAX) + 1).unwrap();
        oversized_record.old_control_process.process_id = oversized_pid;
        oversized_record.old_control_process.unit_main_process_id = oversized_pid;
        oversized_record.old_control_process.cgroup_process_ids = vec![oversized_pid];
        oversized_record
            .old_control_process
            .handshake
            .peer_process_id = oversized_pid;
        let oversized_record_bytes = encode_serving_handoff_record(&oversized_record).unwrap();
        let mut oversized_record_scan =
            scanned_file(&fixture.record_path(), &oversized_record_bytes);
        oversized_record_scan.length = WireU64::new(oversized_record_bytes.len() as u64).unwrap();
        let mut oversized_successor = successor.clone();
        let ReconcileStep::PrepareDevice { devices } = &mut oversized_successor.step else {
            unreachable!()
        };
        let ServingAuthorityProvenance::AfterRootProvision { handoff } =
            devices[0].serving_authority.as_mut()
        else {
            unreachable!()
        };
        handoff.record.length = oversized_record_scan.length;
        handoff.record.content_sha256 = oversized_record_scan.content_sha256.clone();
        let overflow = validate_scanned_serving_handoff_artifacts(
            &oversized_successor,
            &fixture.acquired,
            &target_scan,
            Some(&oversized_record_scan),
            None,
        )
        .unwrap_err();
        assert!(
            overflow
                .to_string()
                .contains("exceeds the platform PID domain"),
            "checked PID conversion failed for an oversized sealed record: {overflow:#}"
        );

        let mut receipt_drift = retirement_bytes.clone();
        receipt_drift.push(b' ');
        let mut retirement_drift = scanned_file(&fixture.retirement_path(), &retirement_bytes);
        retirement_drift.length = WireU64::new(receipt_drift.len() as u64).unwrap();
        retirement_drift.content_sha256 =
            Sha256Digest::from_bytes(Sha256::digest(&receipt_drift).into());
        retirement_drift.bytes = &receipt_drift;
        assert!(validate_scanned_serving_handoff_artifacts(
            current.checkpoint(),
            &fixture.acquired,
            &target_scan,
            Some(&record_scan),
            Some(&retirement_drift),
        )
        .is_err());
        assert_eq!(process_port.inspect_calls(), 2);
    }

    #[test]
    fn token_rotation_rejects_the_retirement_admission_but_accepts_a_fresh_session() {
        let mut fixture = fixture();
        let handoff_store = fixture.store();
        drop(
            handoff_store
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap(),
        );
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let port = RetirementProcessPort::with_inspections(
            &fixture,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        );
        let retirement_context = absent_effect_context(&fixture);
        handoff_store
            .retire_record_after_exact_process_absence(
                &checkpoint_store,
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                fixture.expected_executable_path.clone(),
                &port,
                &retirement_context,
            )
            .unwrap();
        let old_digest = fixture.stored_checkpoint.content_digest().clone();
        let timestamp = UnixMillis::new(
            fixture
                .stored_checkpoint
                .checkpoint()
                .updated_at_unix_ms
                .get()
                + 1,
        )
        .unwrap();
        assert!(handoff_store
            .rotate_process_token_after_retirement(
                &checkpoint_store,
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                fixture.expected_executable_path.clone(),
                random('5'),
                timestamp,
                &port,
                &retirement_context,
            )
            .unwrap_err()
            .to_string()
            .contains("strictly successor"));
        assert_eq!(
            checkpoint_store.load().unwrap().unwrap().content_digest(),
            &old_digest
        );

        fixture.stored_checkpoint = handoff_store
            .rotate_process_token_after_retirement(
                &checkpoint_store,
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                fixture.expected_executable_path.clone(),
                random('5'),
                timestamp,
                &port,
                &restarted_absent_effect_context(&fixture),
            )
            .unwrap();
        assert_ne!(fixture.stored_checkpoint.content_digest(), &old_digest);
        assert!(fixture.retirement_path().exists());
    }

    #[test]
    fn retirement_receipt_publication_recovers_every_crash_window_before_unlink() {
        for point in [
            PublicationPoint::Created,
            PublicationPoint::PartialWritten,
            PublicationPoint::FullWritten,
            PublicationPoint::TempSynced,
            PublicationPoint::Published,
            PublicationPoint::DirectorySynced,
        ] {
            let fixture = fixture();
            let handoff_store = fixture.store();
            drop(
                handoff_store
                    .seal_serving_ready(
                        &fixture.stored_checkpoint,
                        &fixture.acquired,
                        &fixture.authority,
                        &fixture.exact_process_proof().unwrap(),
                    )
                    .unwrap(),
            );
            let checkpoint_store = FileCheckpointStore::open(
                &fixture.checkpoint_directory,
                &fixture.acquired.desired.cat_id,
            )
            .unwrap();
            let port = RetirementProcessPort::with_inspections(
                &fixture,
                [
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                ],
            );
            handoff_store.inject_crash_once(PublicationStage::new(
                PublicationArtifact::HandoffRetirementReceipt,
                point,
            ));
            assert!(handoff_store
                .retire_record_after_exact_process_absence(
                    &checkpoint_store,
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    fixture.expected_executable_path.clone(),
                    &port,
                    &absent_effect_context(&fixture),
                )
                .is_err());
            assert!(fixture.record_path().exists(), "{point:?}");

            assert_eq!(
                handoff_store
                    .retire_record_after_exact_process_absence(
                        &checkpoint_store,
                        &fixture.stored_checkpoint,
                        &fixture.acquired,
                        &fixture.authority,
                        fixture.expected_executable_path.clone(),
                        &port,
                        &absent_effect_context(&fixture),
                    )
                    .unwrap(),
                ServingHandoffRetirement::Retired,
                "{point:?}"
            );
            assert!(!fixture.record_path().exists(), "{point:?}");
            assert!(fixture.retirement_path().exists(), "{point:?}");
            assert!(!fixture.retirement_temp_path().exists(), "{point:?}");
        }
    }

    #[test]
    fn handoff_retirement_recovers_every_unlink_and_fsync_crash_window() {
        for stage in [
            PublicationPoint::BeforeUnlink,
            PublicationPoint::Unlinked,
            PublicationPoint::DirectorySynced,
        ] {
            let fixture = fixture();
            let handoff_store = fixture.store();
            drop(
                handoff_store
                    .seal_serving_ready(
                        &fixture.stored_checkpoint,
                        &fixture.acquired,
                        &fixture.authority,
                        &fixture.exact_process_proof().unwrap(),
                    )
                    .unwrap(),
            );
            let checkpoint_store = FileCheckpointStore::open(
                &fixture.checkpoint_directory,
                &fixture.acquired.desired.cat_id,
            )
            .unwrap();
            let process_port = RetirementProcessPort::with_inspections(
                &fixture,
                [
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                ],
            );
            handoff_store.inject_crash_once(PublicationStage::new(
                PublicationArtifact::HandoffRetirement,
                stage,
            ));
            assert!(handoff_store
                .retire_record_after_exact_process_absence(
                    &checkpoint_store,
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    fixture.expected_executable_path.clone(),
                    &process_port,
                    &absent_effect_context(&fixture),
                )
                .is_err());
            if stage == PublicationPoint::BeforeUnlink {
                assert!(fixture.record_path().exists());
            } else {
                assert!(!fixture.record_path().exists());
            }

            if stage == PublicationPoint::Unlinked {
                handoff_store.inject_crash_once(PublicationStage::new(
                    PublicationArtifact::HandoffRetirement,
                    PublicationPoint::BeforeDirectorySync,
                ));
                assert!(handoff_store
                    .retire_record_after_exact_process_absence(
                        &checkpoint_store,
                        &fixture.stored_checkpoint,
                        &fixture.acquired,
                        &fixture.authority,
                        fixture.expected_executable_path.clone(),
                        &process_port,
                        &absent_effect_context(&fixture),
                    )
                    .is_err());
            }
            let recovered = handoff_store
                .retire_record_after_exact_process_absence(
                    &checkpoint_store,
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    fixture.expected_executable_path.clone(),
                    &process_port,
                    &absent_effect_context(&fixture),
                )
                .unwrap();
            assert!(matches!(
                recovered,
                ServingHandoffRetirement::Retired
                    | ServingHandoffRetirement::RecoveredAlreadyAbsent
            ));
            assert!(!fixture.record_path().exists());
            assert!(fixture.target_path().exists());
        }
    }

    #[test]
    fn retirement_never_deletes_on_projected_present_physical_conflict_or_path_aba() {
        let fixture = fixture();
        let handoff_store = fixture.store();
        drop(
            handoff_store
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap(),
        );
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let record_bytes = std::fs::read(fixture.record_path()).unwrap();
        let projected_process = fixture
            .exact_process_proof()
            .unwrap()
            .into_process_evidence();
        let not_inspected = RetirementProcessPort::with_inspections(
            &fixture,
            [RootProvisionProcessInspection::Absent],
        );
        assert!(handoff_store
            .retire_record_after_exact_process_absence(
                &checkpoint_store,
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                fixture.expected_executable_path.clone(),
                &not_inspected,
                &effect_context_with_processes(&fixture, vec![projected_process]),
            )
            .is_err());
        assert_eq!(not_inspected.inspect_calls(), 0);
        assert_eq!(std::fs::read(fixture.record_path()).unwrap(), record_bytes);

        for inspection in [
            RootProvisionProcessInspection::Exact(Box::new(fixture.process.clone())),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity,
            ),
            RootProvisionProcessInspection::Unavailable,
        ] {
            let port = RetirementProcessPort::with_inspections(&fixture, [inspection]);
            assert!(handoff_store
                .retire_record_after_exact_process_absence(
                    &checkpoint_store,
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    fixture.expected_executable_path.clone(),
                    &port,
                    &absent_effect_context(&fixture),
                )
                .is_err());
            assert_eq!(std::fs::read(fixture.record_path()).unwrap(), record_bytes);
        }

        let swap_path = fixture.record_path();
        handoff_store.inject_mutation_once(
            PublicationStage::new(
                PublicationArtifact::HandoffRetirement,
                PublicationPoint::BeforeUnlink,
            ),
            move || swap_same_bytes(&swap_path, "retirement-aba"),
        );
        let absent = RetirementProcessPort::with_inspections(
            &fixture,
            [RootProvisionProcessInspection::Absent],
        );
        assert!(handoff_store
            .retire_record_after_exact_process_absence(
                &checkpoint_store,
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                fixture.expected_executable_path.clone(),
                &absent,
                &absent_effect_context(&fixture),
            )
            .is_err());
        assert_eq!(std::fs::read(fixture.record_path()).unwrap(), record_bytes);
    }

    #[test]
    fn incomplete_or_nonidentical_accepted_inventory_cannot_authorize_retirement() {
        let fixture = fixture();
        let handoff_store = fixture.store();
        drop(
            handoff_store
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap(),
        );
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let record_bytes = std::fs::read(fixture.record_path()).unwrap();
        let contexts = [
            mutate_absent_effect_context(&fixture, |_session, observation, _attestation| {
                observation.complete_inventory = false;
            }),
            mutate_absent_effect_context(&fixture, |_session, observation, _attestation| {
                let runtime = observation.runtimes.first_mut().unwrap();
                let CheckpointEvidence::Valid { content_digest, .. } = &mut runtime.checkpoint
                else {
                    unreachable!()
                };
                *content_digest = digest('9');
            }),
            mutate_absent_effect_context(&fixture, |_session, observation, _attestation| {
                let runtime = observation.runtimes.first_mut().unwrap();
                let CheckpointEvidence::Valid {
                    checkpoint_path, ..
                } = &mut runtime.checkpoint
                else {
                    unreachable!()
                };
                *checkpoint_path = host("/var/lib/cats/foreign.runtime.json");
            }),
            mutate_absent_effect_context(&fixture, |_session, observation, _attestation| {
                observation.runtimes.push(observation.runtimes[0].clone());
            }),
        ];
        let port = RetirementProcessPort::with_inspections(
            &fixture,
            std::iter::repeat_n(RootProvisionProcessInspection::Absent, contexts.len()),
        );
        for context in contexts {
            assert!(handoff_store
                .retire_record_after_exact_process_absence(
                    &checkpoint_store,
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    fixture.expected_executable_path.clone(),
                    &port,
                    &context,
                )
                .is_err());
            assert_eq!(std::fs::read(fixture.record_path()).unwrap(), record_bytes);
        }
        assert_eq!(port.inspect_calls(), 0);
    }

    #[test]
    fn retirement_preserves_foreign_duplicate_and_unpublished_artifacts() {
        for residue in [
            "malformed_record",
            "duplicate_record",
            "record_temp",
            "target_temp",
        ] {
            let fixture = fixture();
            let handoff_store = fixture.store();
            drop(
                handoff_store
                    .seal_serving_ready(
                        &fixture.stored_checkpoint,
                        &fixture.acquired,
                        &fixture.authority,
                        &fixture.exact_process_proof().unwrap(),
                    )
                    .unwrap(),
            );
            let exact_record = std::fs::read(fixture.record_path()).unwrap();
            let residue_path = match residue {
                "malformed_record" => {
                    std::fs::write(fixture.record_path(), b"{}").unwrap();
                    fixture.record_path()
                }
                "duplicate_record" => {
                    let path = fixture.data_directory.join("serving-handoff-foreign.json");
                    std::fs::write(&path, b"foreign").unwrap();
                    path
                }
                "record_temp" => {
                    std::fs::write(fixture.record_temp_path(), b"partial").unwrap();
                    fixture.record_temp_path()
                }
                "target_temp" => {
                    std::fs::write(fixture.target_temp_path(), b"partial").unwrap();
                    fixture.target_temp_path()
                }
                _ => unreachable!(),
            };
            std::fs::set_permissions(&residue_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let residue_bytes = std::fs::read(&residue_path).unwrap();
            let checkpoint_store = FileCheckpointStore::open(
                &fixture.checkpoint_directory,
                &fixture.acquired.desired.cat_id,
            )
            .unwrap();
            let port = RetirementProcessPort::with_inspections(
                &fixture,
                [RootProvisionProcessInspection::Absent],
            );
            assert!(handoff_store
                .retire_record_after_exact_process_absence(
                    &checkpoint_store,
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    fixture.expected_executable_path.clone(),
                    &port,
                    &absent_effect_context(&fixture),
                )
                .is_err());
            assert_eq!(std::fs::read(&residue_path).unwrap(), residue_bytes);
            if residue != "malformed_record" {
                assert_eq!(std::fs::read(fixture.record_path()).unwrap(), exact_record);
            }
        }
    }

    #[test]
    fn retirement_holds_checkpoint_writer_barrier_through_directory_fsync() {
        let fixture = fixture();
        let handoff_store = fixture.store();
        drop(
            handoff_store
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap(),
        );
        let checkpoint_store = Arc::new(
            FileCheckpointStore::open(
                &fixture.checkpoint_directory,
                &fixture.acquired.desired.cat_id,
            )
            .unwrap(),
        );
        let mut successor = fixture.stored_checkpoint.checkpoint().clone();
        successor.updated_at_unix_ms =
            UnixMillis::new(successor.updated_at_unix_ms.get().checked_add(1).unwrap()).unwrap();
        let expected = fixture.stored_checkpoint.clone();
        let writer_store = checkpoint_store.clone();
        let (begin_tx, begin_rx) = std::sync::mpsc::channel();
        let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_completed = completed.clone();
        let writer = std::thread::spawn(move || {
            begin_rx.recv().unwrap();
            attempted_tx.send(()).unwrap();
            writer_store.replace(&expected, &successor).unwrap();
            writer_completed.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let hook_completed = completed.clone();
        handoff_store.inject_mutation_once(
            PublicationStage::new(
                PublicationArtifact::HandoffRetirement,
                PublicationPoint::BeforeUnlink,
            ),
            move || {
                begin_tx.send(()).unwrap();
                attempted_rx.recv().unwrap();
                assert!(
                    !hook_completed.load(std::sync::atomic::Ordering::SeqCst),
                    "checkpoint writer crossed the retained retirement barrier"
                );
            },
        );
        let port = RetirementProcessPort::with_inspections(
            &fixture,
            [RootProvisionProcessInspection::Absent],
        );
        assert_eq!(
            handoff_store
                .retire_record_after_exact_process_absence(
                    checkpoint_store.as_ref(),
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    fixture.expected_executable_path.clone(),
                    &port,
                    &absent_effect_context(&fixture),
                )
                .unwrap(),
            ServingHandoffRetirement::Retired
        );
        writer.join().unwrap();
        assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
        let current = checkpoint_store.load().unwrap().unwrap();
        assert_eq!(
            current.checkpoint().updated_at_unix_ms.get(),
            fixture
                .stored_checkpoint
                .checkpoint()
                .updated_at_unix_ms
                .get()
                + 1
        );
    }

    #[test]
    fn cancellation_at_the_last_pre_unlink_edge_preserves_the_record() {
        let fixture = fixture();
        let handoff_store = fixture.store();
        drop(
            handoff_store
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap(),
        );
        let record_bytes = std::fs::read(fixture.record_path()).unwrap();
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let context = absent_effect_context(&fixture);
        let cancel = context.clone();
        handoff_store.inject_mutation_once(
            PublicationStage::new(
                PublicationArtifact::HandoffRetirement,
                PublicationPoint::BeforeUnlink,
            ),
            move || cancel.cancel_for_test(),
        );
        let port = RetirementProcessPort::with_inspections(
            &fixture,
            [RootProvisionProcessInspection::Absent],
        );
        assert!(handoff_store
            .retire_record_after_exact_process_absence(
                &checkpoint_store,
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                fixture.expected_executable_path.clone(),
                &port,
                &context,
            )
            .is_err());
        assert_eq!(std::fs::read(fixture.record_path()).unwrap(), record_bytes);
    }

    #[test]
    fn failed_consume_closure_leaves_the_exact_predecessor_current() {
        let fixture = fixture();
        let ready = fixture
            .store()
            .seal_serving_ready(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &fixture.exact_process_proof().unwrap(),
            )
            .unwrap();
        let checkpoint_store = FileCheckpointStore::open(
            &fixture.checkpoint_directory,
            &fixture.acquired.desired.cat_id,
        )
        .unwrap();
        let result: anyhow::Result<()> = ready
            .consume_for_prepare_device(&fixture.stored_checkpoint, |_handoff| {
                anyhow::bail!("injected failure before checkpoint replace")
            });
        assert!(result.unwrap_err().to_string().contains("injected failure"));
        let current = checkpoint_store.load().unwrap().unwrap();
        assert_eq!(
            current.content_digest(),
            fixture.stored_checkpoint.content_digest()
        );
        assert_eq!(current.checkpoint(), fixture.stored_checkpoint.checkpoint());
    }

    #[test]
    fn wrong_transition_head_authority_tuple_or_reload_cannot_publish_ready() {
        let wrong_transition = fixture();
        let mut evidence = wrong_transition.authority.clone();
        evidence.provision_transition_id = random('9');
        assert!(wrong_transition
            .store()
            .seal_target_control_authorization(
                &wrong_transition.stored_checkpoint,
                &wrong_transition.acquired,
                &evidence,
            )
            .unwrap_err()
            .to_string()
            .contains("another provision transition"));
        assert!(!wrong_transition.target_path().exists());

        // The attachment is byte-for-byte valid for the same target, but its
        // sealed wrapper names the old provision transition. Copying those
        // bytes under the new transition's filename must not rebind them.
        let mut rebound = fixture();
        let sealed = rebound
            .store()
            .seal_target_control_authorization(
                &rebound.stored_checkpoint,
                &rebound.acquired,
                &rebound.authority,
            )
            .unwrap();
        let old_target_path = rebound.target_path();
        let copied = std::fs::read(&old_target_path).unwrap();
        drop(sealed);
        std::fs::remove_file(old_target_path).unwrap();
        let new_transition = random('9');
        let mut checkpoint = rebound.stored_checkpoint.checkpoint().clone();
        let ReconcileStep::ProvisionRootImage {
            provision_transition_id,
            ..
        } = &mut checkpoint.step
        else {
            unreachable!()
        };
        *provision_transition_id = new_transition.clone();
        rebound.replace_checkpoint(checkpoint);
        rebound.authority.provision_transition_id = new_transition;
        std::fs::write(rebound.target_path(), &copied).unwrap();
        std::fs::set_permissions(
            rebound.target_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(rebound
            .store()
            .seal_target_control_authorization(
                &rebound.stored_checkpoint,
                &rebound.acquired,
                &rebound.authority,
            )
            .unwrap_err()
            .to_string()
            .contains("conflicts"));
        assert_eq!(std::fs::read(rebound.target_path()).unwrap(), copied);

        let wrong_head = fixture();
        let mut evidence = wrong_head.authority.clone();
        evidence.volume.head = blank_head();
        assert!(wrong_head
            .store()
            .seal_target_control_authorization(
                &wrong_head.stored_checkpoint,
                &wrong_head.acquired,
                &evidence,
            )
            .is_err());
        assert!(!wrong_head.target_path().exists());

        let wrong_tuple = fixture();
        let mut evidence = wrong_tuple.authority.clone();
        evidence.volume.lease_owner = Some(id("foreign_attachment"));
        assert!(wrong_tuple
            .store()
            .seal_target_control_authorization(
                &wrong_tuple.stored_checkpoint,
                &wrong_tuple.acquired,
                &evidence,
            )
            .is_err());
        assert!(!wrong_tuple.target_path().exists());

        let wrong_reload = fixture();
        let store = wrong_reload.store();
        store
            .seal_target_control_authorization(
                &wrong_reload.stored_checkpoint,
                &wrong_reload.acquired,
                &wrong_reload.authority,
            )
            .unwrap();
        let mut process = wrong_reload.process.clone();
        process.handshake.remote_head = blank_head();
        assert!(wrong_reload
            .exact_process_proof_for(process)
            .unwrap_err()
            .to_string()
            .contains("did not exactly match"));
        assert!(wrong_reload.target_path().exists());
        assert!(!wrong_reload.record_path().exists());
    }

    #[test]
    fn every_publication_crash_window_recovers_only_by_exact_replay() {
        let stages = [
            PublicationStage::new(
                PublicationArtifact::TargetAuthorization,
                PublicationPoint::Created,
            ),
            PublicationStage::new(
                PublicationArtifact::TargetAuthorization,
                PublicationPoint::PartialWritten,
            ),
            PublicationStage::new(
                PublicationArtifact::TargetAuthorization,
                PublicationPoint::FullWritten,
            ),
            PublicationStage::new(
                PublicationArtifact::TargetAuthorization,
                PublicationPoint::TempSynced,
            ),
            PublicationStage::new(
                PublicationArtifact::TargetAuthorization,
                PublicationPoint::Published,
            ),
            PublicationStage::new(
                PublicationArtifact::TargetAuthorization,
                PublicationPoint::DirectorySynced,
            ),
            PublicationStage::new(
                PublicationArtifact::HandoffRecord,
                PublicationPoint::Created,
            ),
            PublicationStage::new(
                PublicationArtifact::HandoffRecord,
                PublicationPoint::PartialWritten,
            ),
            PublicationStage::new(
                PublicationArtifact::HandoffRecord,
                PublicationPoint::FullWritten,
            ),
            PublicationStage::new(
                PublicationArtifact::HandoffRecord,
                PublicationPoint::TempSynced,
            ),
            PublicationStage::new(
                PublicationArtifact::HandoffRecord,
                PublicationPoint::Published,
            ),
            PublicationStage::new(
                PublicationArtifact::HandoffRecord,
                PublicationPoint::DirectorySynced,
            ),
        ];
        for stage in stages {
            let fixture = fixture();
            let blank_before = std::fs::read(&fixture.blank_authorization_path).unwrap();
            let store = fixture.store();
            store.inject_crash_once(stage);
            let error = store
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap_err();
            assert!(error.to_string().contains("injected"), "{stage:?}: {error}");

            let ready = store
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .unwrap_or_else(|error| panic!("{stage:?} exact replay failed: {error:#}"));
            assert_eq!(
                ready.record().expected_provisioned_head,
                fixture.authority.volume.head
            );
            assert!(!fixture.target_temp_path().exists(), "{stage:?}");
            assert!(!fixture.record_temp_path().exists(), "{stage:?}");
            assert_eq!(
                std::fs::read(&fixture.blank_authorization_path).unwrap(),
                blank_before,
                "{stage:?}"
            );
        }
    }

    #[test]
    fn rename_recreate_and_exact_byte_aba_never_return_or_retain_ready() {
        for stage in [
            PublicationStage::new(
                PublicationArtifact::TargetAuthorization,
                PublicationPoint::DirectorySynced,
            ),
            PublicationStage::new(
                PublicationArtifact::HandoffRecord,
                PublicationPoint::DirectorySynced,
            ),
        ] {
            for name in [
                IDENTITY_FILE,
                AUTHORIZED_SERVING_FILE,
                LAUNCH_CHECKPOINT_FILE,
            ] {
                let fixture = fixture();
                let store = fixture.store();
                let path = fixture.data_directory.join(name);
                let before = std::fs::read(&path).unwrap();
                let before_inode = std::fs::metadata(&path).unwrap().ino();
                let backup = fixture.data_directory.join(format!(".aba-{name}"));
                let mutation_path = path.clone();
                let mutation_bytes = before.clone();
                store.inject_mutation_once(stage, move || {
                    std::fs::rename(&mutation_path, &backup).unwrap();
                    std::fs::write(&mutation_path, &mutation_bytes).unwrap();
                    std::fs::set_permissions(
                        &mutation_path,
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                });
                assert!(store
                    .seal_serving_ready(
                        &fixture.stored_checkpoint,
                        &fixture.acquired,
                        &fixture.authority,
                        &fixture.exact_process_proof().unwrap(),
                    )
                    .is_err());
                assert_eq!(std::fs::read(&path).unwrap(), before, "{stage:?} {name}");
                assert_ne!(
                    std::fs::metadata(&path).unwrap().ino(),
                    before_inode,
                    "{stage:?} {name}"
                );
            }
        }

        for artifact in [
            PublicationArtifact::TargetAuthorization,
            PublicationArtifact::HandoffRecord,
        ] {
            let fixture = fixture();
            let store = fixture.store();
            let swap_path = match artifact {
                PublicationArtifact::TargetAuthorization => fixture.target_path(),
                PublicationArtifact::HandoffRecord => fixture.record_path(),
                PublicationArtifact::HandoffRetirement
                | PublicationArtifact::HandoffRetirementReceipt => {
                    unreachable!("publication matrix excludes retirement")
                }
            };
            store.inject_mutation_once(
                PublicationStage::new(artifact, PublicationPoint::DirectorySynced),
                move || swap_same_bytes(&swap_path, "publish-barrier"),
            );
            assert!(store
                .seal_serving_ready(
                    &fixture.stored_checkpoint,
                    &fixture.acquired,
                    &fixture.authority,
                    &fixture.exact_process_proof().unwrap(),
                )
                .is_err());
        }

        let attachment_replaced = fixture();
        let store = attachment_replaced.store();
        let attachment_path = attachment_replaced.data_directory.clone();
        let moved_attachment = attachment_path.with_extension("retained-old");
        let replacement_path = attachment_path.clone();
        store.inject_mutation_once(
            PublicationStage::new(
                PublicationArtifact::HandoffRecord,
                PublicationPoint::DirectorySynced,
            ),
            move || {
                std::fs::rename(&replacement_path, &moved_attachment).unwrap();
                std::fs::create_dir(&replacement_path).unwrap();
                std::fs::set_permissions(&replacement_path, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            },
        );
        assert!(store
            .seal_serving_ready(
                &attachment_replaced.stored_checkpoint,
                &attachment_replaced.acquired,
                &attachment_replaced.authority,
                &attachment_replaced.exact_process_proof().unwrap(),
            )
            .is_err());

        let root_replaced = fixture();
        let store = root_replaced.store();
        let root_path = root_replaced.state_directory.path().to_path_buf();
        let moved_root = root_path.with_extension("retained-old");
        let moved_root_cleanup = moved_root.clone();
        let replacement_root = root_path.clone();
        store.inject_mutation_once(
            PublicationStage::new(
                PublicationArtifact::TargetAuthorization,
                PublicationPoint::DirectorySynced,
            ),
            move || {
                std::fs::rename(&replacement_root, &moved_root).unwrap();
                std::fs::create_dir(&replacement_root).unwrap();
                std::fs::set_permissions(&replacement_root, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            },
        );
        assert!(store
            .seal_target_control_authorization(
                &root_replaced.stored_checkpoint,
                &root_replaced.acquired,
                &root_replaced.authority,
            )
            .is_err());
        drop(store);
        std::fs::remove_dir(&root_path).unwrap();
        std::fs::rename(moved_root_cleanup, &root_path).unwrap();

        let consume_aba = fixture();
        let ready = consume_aba
            .store()
            .seal_serving_ready(
                &consume_aba.stored_checkpoint,
                &consume_aba.acquired,
                &consume_aba.authority,
                &consume_aba.exact_process_proof().unwrap(),
            )
            .unwrap();
        let checkpoint_store = FileCheckpointStore::open(
            &consume_aba.checkpoint_directory,
            &consume_aba.acquired.desired.cat_id,
        )
        .unwrap();
        swap_same_bytes(&consume_aba.record_path(), "consume");
        let invoked = Cell::new(false);
        let result = ready.consume_for_prepare_device(
            &consume_aba.stored_checkpoint,
            |handoff| -> anyhow::Result<()> {
                invoked.set(true);
                let successor = prepare_device_successor(&consume_aba, handoff);
                checkpoint_store.replace(&consume_aba.stored_checkpoint, &successor)?;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!invoked.get());
        let current = checkpoint_store.load().unwrap().unwrap();
        assert_eq!(
            current.content_digest(),
            consume_aba.stored_checkpoint.content_digest()
        );
        assert_eq!(
            current.checkpoint(),
            consume_aba.stored_checkpoint.checkpoint()
        );
    }

    #[test]
    fn process_token_rotation_replays_target_but_invalidates_concrete_handoff() {
        let mut wrong_executable = fixture();
        wrong_executable.process.executable_path = host("/opt/foreign/blockd");
        assert!(wrong_executable.exact_process_proof().is_err());
        assert!(!wrong_executable.record_path().exists());

        let mut stale = fixture();
        let ready = stale
            .store()
            .seal_serving_ready(
                &stale.stored_checkpoint,
                &stale.acquired,
                &stale.authority,
                &stale.exact_process_proof().unwrap(),
            )
            .unwrap();
        let original_digest = stale.stored_checkpoint.content_digest().clone();
        let original_target = ready.target_control_authorization().clone();
        let mut successor = stale.stored_checkpoint.checkpoint().clone();
        let ReconcileStep::ProvisionRootImage {
            process_identity_token,
            ..
        } = &mut successor.step
        else {
            unreachable!()
        };
        *process_identity_token = random('5');
        successor.updated_at_unix_ms =
            UnixMillis::new(successor.updated_at_unix_ms.get().checked_add(1).unwrap()).unwrap();
        stale.replace_checkpoint(successor);
        assert_ne!(stale.stored_checkpoint.content_digest(), &original_digest);
        assert!(ready.assert_current(&stale.stored_checkpoint).is_err());
        drop(ready);
        let replay = stale
            .store()
            .seal_target_control_authorization(
                &stale.stored_checkpoint,
                &stale.acquired,
                &stale.authority,
            )
            .expect("token-only rotation replays the stable target authorization");
        assert_eq!(replay.identity(), &original_target);
    }

    #[test]
    fn target_context_digest_rejects_every_authorization_binding_change() {
        assert_target_context_mutation_rejected(|checkpoint| {
            let ReconcileStep::ProvisionRootImage { scope_id, .. } = &mut checkpoint.step else {
                unreachable!()
            };
            *scope_id = id("cats-root-foreign.service");
        });
        assert_target_context_mutation_rejected(|checkpoint| {
            let ReconcileStep::ProvisionRootImage {
                control_socket_path,
                ..
            } = &mut checkpoint.step
            else {
                unreachable!()
            };
            *control_socket_path = host("/tmp/foreign-root-provision.sock");
        });
        assert_target_context_mutation_rejected(|checkpoint| {
            let ReconcileStep::ProvisionRootImage { data_directory, .. } = &mut checkpoint.step
            else {
                unreachable!()
            };
            *data_directory = host("/tmp/foreign-root-data");
        });
        assert_target_context_mutation_rejected(|checkpoint| {
            let ReconcileStep::ProvisionRootImage {
                boot_image_digest, ..
            } = &mut checkpoint.step
            else {
                unreachable!()
            };
            *boot_image_digest = digest('e');
        });
        assert_target_context_mutation_rejected(|checkpoint| {
            let ReconcileStep::ProvisionRootImage {
                expected_provisioned_head,
                ..
            } = &mut checkpoint.step
            else {
                unreachable!()
            };
            expected_provisioned_head.root_hash = Some(digest('e'));
        });
        assert_target_context_mutation_rejected(|checkpoint| {
            checkpoint.spec_digest = digest('e');
        });
        assert_target_context_mutation_rejected(|checkpoint| {
            checkpoint.desired_revision = Revision::new(12).unwrap();
        });
        assert_target_context_mutation_rejected(|checkpoint| {
            checkpoint.placement_epoch = Epoch::new(4).unwrap();
        });
        assert_target_context_mutation_rejected(|checkpoint| {
            checkpoint.lifecycle_admission = LifecycleAdmission::Open;
        });
    }

    #[test]
    fn unsafe_foreign_and_symlink_entries_fail_closed_without_replacement() {
        let unsafe_temp = fixture();
        std::fs::write(unsafe_temp.target_temp_path(), b"{").unwrap();
        std::fs::set_permissions(
            unsafe_temp.target_temp_path(),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let unsafe_inode = std::fs::metadata(unsafe_temp.target_temp_path())
            .unwrap()
            .ino();
        assert!(unsafe_temp
            .store()
            .seal_target_control_authorization(
                &unsafe_temp.stored_checkpoint,
                &unsafe_temp.acquired,
                &unsafe_temp.authority,
            )
            .is_err());
        assert!(!unsafe_temp.target_path().exists());
        assert_eq!(std::fs::read(unsafe_temp.target_temp_path()).unwrap(), b"{");
        assert_eq!(
            std::fs::metadata(unsafe_temp.target_temp_path())
                .unwrap()
                .ino(),
            unsafe_inode
        );

        let hardlinked_temp = fixture();
        let external_temp = hardlinked_temp
            .data_directory
            .parent()
            .unwrap()
            .join("external-temp.json");
        std::fs::write(&external_temp, b"{").unwrap();
        std::fs::set_permissions(&external_temp, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&external_temp, hardlinked_temp.target_temp_path()).unwrap();
        assert!(hardlinked_temp
            .store()
            .seal_target_control_authorization(
                &hardlinked_temp.stored_checkpoint,
                &hardlinked_temp.acquired,
                &hardlinked_temp.authority,
            )
            .is_err());
        assert_eq!(std::fs::read(&external_temp).unwrap(), b"{");
        assert!(hardlinked_temp.target_temp_path().exists());
        assert_eq!(std::fs::metadata(&external_temp).unwrap().nlink(), 2);

        let symlink_temp = fixture();
        let external_symlink_temp = symlink_temp
            .data_directory
            .parent()
            .unwrap()
            .join("external-symlink-temp.json");
        std::fs::write(&external_symlink_temp, b"external").unwrap();
        symlink(&external_symlink_temp, symlink_temp.target_temp_path()).unwrap();
        assert!(symlink_temp
            .store()
            .seal_target_control_authorization(
                &symlink_temp.stored_checkpoint,
                &symlink_temp.acquired,
                &symlink_temp.authority,
            )
            .is_err());
        assert_eq!(std::fs::read(&external_symlink_temp).unwrap(), b"external");
        assert!(std::fs::symlink_metadata(symlink_temp.target_temp_path())
            .unwrap()
            .file_type()
            .is_symlink());

        let partial_beside_target = fixture();
        let store = partial_beside_target.store();
        drop(
            store
                .seal_target_control_authorization(
                    &partial_beside_target.stored_checkpoint,
                    &partial_beside_target.acquired,
                    &partial_beside_target.authority,
                )
                .unwrap(),
        );
        let target_inode = std::fs::metadata(partial_beside_target.target_path())
            .unwrap()
            .ino();
        std::fs::write(partial_beside_target.target_temp_path(), b"{").unwrap();
        std::fs::set_permissions(
            partial_beside_target.target_temp_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let replay = store
            .seal_target_control_authorization(
                &partial_beside_target.stored_checkpoint,
                &partial_beside_target.acquired,
                &partial_beside_target.authority,
            )
            .unwrap();
        assert_eq!(
            std::fs::metadata(partial_beside_target.target_path())
                .unwrap()
                .ino(),
            target_inode
        );
        assert!(!partial_beside_target.target_temp_path().exists());
        drop(replay);

        let partial_beside_record = fixture();
        let store = partial_beside_record.store();
        drop(
            store
                .seal_serving_ready(
                    &partial_beside_record.stored_checkpoint,
                    &partial_beside_record.acquired,
                    &partial_beside_record.authority,
                    &partial_beside_record.exact_process_proof().unwrap(),
                )
                .unwrap(),
        );
        let record_inode = std::fs::metadata(partial_beside_record.record_path())
            .unwrap()
            .ino();
        std::fs::write(partial_beside_record.record_temp_path(), b"{").unwrap();
        std::fs::set_permissions(
            partial_beside_record.record_temp_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let replay = store
            .seal_serving_ready(
                &partial_beside_record.stored_checkpoint,
                &partial_beside_record.acquired,
                &partial_beside_record.authority,
                &partial_beside_record.exact_process_proof().unwrap(),
            )
            .unwrap();
        assert_eq!(
            std::fs::metadata(partial_beside_record.record_path())
                .unwrap()
                .ino(),
            record_inode
        );
        assert!(!partial_beside_record.record_temp_path().exists());
        drop(replay);

        let foreign = fixture();
        std::fs::write(foreign.target_path(), b"{}").unwrap();
        std::fs::set_permissions(
            foreign.target_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let inode = std::fs::metadata(foreign.target_path()).unwrap().ino();
        assert!(foreign
            .store()
            .seal_target_control_authorization(
                &foreign.stored_checkpoint,
                &foreign.acquired,
                &foreign.authority,
            )
            .unwrap_err()
            .to_string()
            .contains("conflicts"));
        assert_eq!(std::fs::read(foreign.target_path()).unwrap(), b"{}");
        assert_eq!(
            std::fs::metadata(foreign.target_path()).unwrap().ino(),
            inode
        );

        let stale_transition = fixture();
        let stale_path = stale_transition.data_directory.join(format!(
            "authorized-target-control-{}.json",
            random('8').as_str()
        ));
        std::fs::write(&stale_path, b"{}").unwrap();
        std::fs::set_permissions(&stale_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(stale_transition
            .store()
            .seal_target_control_authorization(
                &stale_transition.stored_checkpoint,
                &stale_transition.acquired,
                &stale_transition.authority,
            )
            .unwrap_err()
            .to_string()
            .contains("foreign serving handoff artifact"));
        assert!(!stale_transition.target_path().exists());

        let linked = fixture();
        let external = linked
            .data_directory
            .parent()
            .unwrap()
            .join("external.json");
        std::fs::write(&external, b"external").unwrap();
        symlink(&external, linked.target_path()).unwrap();
        assert!(linked
            .store()
            .seal_target_control_authorization(
                &linked.stored_checkpoint,
                &linked.acquired,
                &linked.authority,
            )
            .is_err());
        assert_eq!(std::fs::read(&external).unwrap(), b"external");
        assert!(std::fs::symlink_metadata(linked.target_path())
            .unwrap()
            .file_type()
            .is_symlink());

        let foreign_record = fixture();
        let store = foreign_record.store();
        store
            .seal_target_control_authorization(
                &foreign_record.stored_checkpoint,
                &foreign_record.acquired,
                &foreign_record.authority,
            )
            .unwrap();
        std::fs::write(foreign_record.record_path(), b"{}").unwrap();
        std::fs::set_permissions(
            foreign_record.record_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(store
            .seal_serving_ready(
                &foreign_record.stored_checkpoint,
                &foreign_record.acquired,
                &foreign_record.authority,
                &foreign_record.exact_process_proof().unwrap(),
            )
            .is_err());
        assert_eq!(std::fs::read(foreign_record.record_path()).unwrap(), b"{}");
    }

    #[test]
    fn codecs_require_bounded_canonical_closed_values() {
        let fixture = fixture();
        let store = fixture.store();
        let control = store
            .seal_target_control_authorization(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
            )
            .unwrap();
        let target = control.identity().artifact.clone();
        let target_bytes = encode_target_control_authorization(&target).unwrap();
        assert_eq!(
            decode_target_control_authorization(&target_bytes).unwrap(),
            target
        );
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(&target_bytes);
        assert!(matches!(
            decode_target_control_authorization(&noncanonical),
            Err(TargetControlAuthorizationCodecError::NonCanonical { .. })
        ));
        assert!(matches!(
            decode_target_control_authorization(&vec![
                b' ';
                TARGET_AUTHORIZED_SERVING_MAX_BYTES + 1
            ]),
            Err(TargetControlAuthorizationCodecError::WireBytesLimitExceeded { .. })
        ));
        let mut wrong_request = target.clone();
        wrong_request.request.boot_image_digest = digest('0');
        encode_target_control_authorization(&wrong_request)
            .expect("boot image is closed by the checkpoint context, not the grant alone");
        assert!(
            validate_target_checkpoint_context(&wrong_request, &fixture.stored_checkpoint).is_err()
        );
        drop(control);

        let ready = store
            .seal_serving_ready(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &fixture.exact_process_proof().unwrap(),
            )
            .unwrap();
        let record_bytes = encode_serving_handoff_record(ready.record()).unwrap();
        assert_eq!(
            decode_serving_handoff_record(&record_bytes).unwrap(),
            *ready.record()
        );
        let mut wrong_digest = ready.record().clone();
        wrong_digest.target_control_authorization.content_sha256 = digest('0');
        assert!(matches!(
            encode_serving_handoff_record(&wrong_digest),
            Err(ServingHandoffCodecError::Invalid { .. })
        ));
        let mut wrong_checkpoint_digest = ready.record().clone();
        wrong_checkpoint_digest.checkpoint_content_digest = digest('0');
        encode_serving_handoff_record(&wrong_checkpoint_digest).unwrap();
        assert!(validate_record_checkpoint_context(
            &wrong_checkpoint_digest,
            &fixture.stored_checkpoint
        )
        .is_err());
        let mut wrong_executable = ready.record().clone();
        wrong_executable.expected_control_executable_path = host("/opt/foreign/blockd");
        assert!(matches!(
            encode_serving_handoff_record(&wrong_executable),
            Err(ServingHandoffCodecError::Invalid { .. })
        ));
        let mut wrong_revision = ready.record().clone();
        wrong_revision.desired_revision = Revision::new(12).unwrap();
        assert!(matches!(
            encode_serving_handoff_record(&wrong_revision),
            Err(ServingHandoffCodecError::Invalid { .. })
        ));
        let mut wrong_placement = ready.record().clone();
        wrong_placement.placement_epoch = Epoch::new(4).unwrap();
        assert!(matches!(
            encode_serving_handoff_record(&wrong_placement),
            Err(ServingHandoffCodecError::Invalid { .. })
        ));
        let mut wrong_spec = ready.record().clone();
        wrong_spec.spec_digest = digest('0');
        assert!(
            validate_record_checkpoint_context(&wrong_spec, &fixture.stored_checkpoint).is_err()
        );
        let mut wrong_cat = ready.record().clone();
        wrong_cat.cat_id = id("cat_foreign");
        assert!(matches!(
            encode_serving_handoff_record(&wrong_cat),
            Err(ServingHandoffCodecError::Invalid { .. })
        ));
        let mut wrong_transition = ready.record().clone();
        wrong_transition
            .target_control_authorization
            .artifact
            .provision_transition_id = random('8');
        assert!(matches!(
            encode_serving_handoff_record(&wrong_transition),
            Err(ServingHandoffCodecError::Invalid { .. })
        ));
        let mut unknown = serde_json::from_slice::<Value>(&record_bytes).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("foreign".to_owned(), Value::Bool(true));
        let mut unknown_bytes = Vec::new();
        write_canonical_json(&unknown, &mut unknown_bytes).unwrap();
        assert!(matches!(
            decode_serving_handoff_record(&unknown_bytes),
            Err(ServingHandoffCodecError::Malformed { .. })
        ));
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn host(value: &str) -> HostPath {
        HostPath::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(value.to_string().repeat(32)).unwrap()
    }

    fn managed_root_control_socket(provision_transition_id: &RandomId128) -> HostPath {
        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .root_paths(provision_transition_id)
            .unwrap()
            .control_socket()
            .clone()
    }

    fn managed_serving_sockets(device_ownership_token: &RandomId128) -> (HostPath, HostPath) {
        let paths = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .serving_paths(device_ownership_token)
            .unwrap();
        (paths.control_socket().clone(), paths.io_socket().clone())
    }

    fn digest(value: char) -> Sha256Digest {
        let digit = value.to_digit(16).unwrap_or(1) as u8;
        Sha256Digest::from_bytes([digit; 32])
    }

    fn swap_same_bytes(path: &Path, label: &str) {
        let bytes = std::fs::read(path).unwrap();
        let backup = path.with_extension(format!("{label}.old"));
        std::fs::rename(path, backup).unwrap();
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn blank_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }

    fn exact_manifest_blob(fixture: &Fixture) -> ExactManifestBlob {
        let manifest = ImageManifestV1 {
            version: 1,
            image_id: LowerHexSha256::from_digest(
                &fixture.acquired.desired.runtime.boot_image_digest,
            ),
            size_bytes: fixture.acquired.volume.size_bytes,
            chunks: Vec::new(),
        };
        ExactManifestBlob(encode_image_manifest(&manifest).unwrap())
    }

    fn target_head() -> RemoteHead {
        let manifest = ImageManifestV1 {
            version: 1,
            image_id: LowerHexSha256::from_digest(&digest('a')),
            size_bytes: cats_api::chunk::CHUNK_SIZE as u64,
            chunks: Vec::new(),
        };
        let identity =
            cats_blockd::format::image_root_identity(&manifest, cats_api::chunk::CHUNK_SIZE as u64)
                .unwrap();
        RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes(identity.root_hash)),
            root_object_id: Some(AsciiText::new(identity.root_object_id).unwrap()),
        }
    }
}
