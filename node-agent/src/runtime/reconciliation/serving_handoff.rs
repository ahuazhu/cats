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
//! create a device, start a process, or advance `RuntimeCheckpoint`: the frozen
//! three-field `PrepareDevice` step cannot yet retain this proof honestly.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    encode_runtime_checkpoint, AcquireOrigin, ContractVersion, Durability, Epoch, FenceEpoch,
    HostPath, Id, RandomId128, ReconcileStep, RemoteHead, Revision, Sha256Digest, VolumeRecord,
    WireU64,
};
use cats_blockd::target_control::{
    decode_target_control_authorization, encode_target_control_authorization,
    provision_root_authorization_context_digest, target_control_authorization_file_name,
    validate_target_control_attachment, validate_target_control_authorization,
    StableDirectoryIdentity, StableFileIdentity, TargetControlAuthorizationArtifact,
    TargetControlAuthorizationCodecError,
    TargetControlLocalStateIdentity as ServingHandoffLocalStateIdentity,
    TARGET_CONTROL_AUTHORIZATION_MAX_BYTES as TARGET_AUTHORIZED_SERVING_MAX_BYTES,
};
use cats_storage::authority::{
    validate_authorized_serving_record, AttachmentLineageIdentity, AuthorizedServingAttachment,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::state_directory::StateDirectory;

use super::authorized_blockd::{
    authorized_blockd_data_directory, validate_authorized_blockd_checkpoint,
    AuthorizedBlockdCheckpoint, AUTHORIZED_SERVING_FILE, IDENTITY_FILE, LAUNCH_CHECKPOINT_FILE,
    MAX_AUTHORIZED_SERVING_BYTES, MAX_IDENTITY_BYTES, MAX_LAUNCH_CHECKPOINT_BYTES,
};
#[cfg(test)]
use super::root_provision_process::RootProvisionAuthoritySnapshot;
use super::root_provision_process::{
    ExactRootProvisionProcessProof, RootProvisionBlockdHandshake, RootProvisionProcessEvidence,
    RootProvisionProcessExpectation,
};
use super::StoredCheckpoint;

pub(crate) const SERVING_HANDOFF_RECORD_FILE: &str = "serving-handoff.json";
const SERVING_HANDOFF_RECORD_TEMP: &str = ".serving-handoff.json.tmp";
pub(crate) const SERVING_HANDOFF_RECORD_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum ServingHandoffCodecError {
    #[error("serving handoff {artifact} exceeds {maximum} bytes")]
    WireBytesLimitExceeded {
        artifact: &'static str,
        maximum: usize,
    },
    #[error("serving handoff {artifact} is malformed")]
    Malformed { artifact: &'static str },
    #[error("serving handoff {artifact} is not in canonical JSON form")]
    NonCanonical { artifact: &'static str },
    #[error("serving handoff {artifact} violates its closed contract: {reason}")]
    Invalid {
        artifact: &'static str,
        reason: &'static str,
    },
}

impl From<TargetControlAuthorizationCodecError> for ServingHandoffCodecError {
    fn from(error: TargetControlAuthorizationCodecError) -> Self {
        match error {
            TargetControlAuthorizationCodecError::WireBytesLimitExceeded { artifact, maximum } => {
                Self::WireBytesLimitExceeded { artifact, maximum }
            }
            TargetControlAuthorizationCodecError::Malformed { artifact } => {
                Self::Malformed { artifact }
            }
            TargetControlAuthorizationCodecError::NonCanonical { artifact } => {
                Self::NonCanonical { artifact }
            }
            TargetControlAuthorizationCodecError::Invalid { artifact, reason } => {
                Self::Invalid { artifact, reason }
            }
        }
    }
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

/// Durable identity of the no-replace target-head grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetControlAuthorizationIdentity {
    pub path: HostPath,
    pub device: WireU64,
    pub inode: WireU64,
    pub length: WireU64,
    pub content_sha256: Sha256Digest,
    pub artifact: TargetControlAuthorizationArtifact,
}

impl TargetControlAuthorizationIdentity {
    pub(crate) fn path(&self) -> &HostPath {
        &self.path
    }

    pub(crate) fn device(&self) -> WireU64 {
        self.device
    }

    pub(crate) fn inode(&self) -> WireU64 {
        self.inode
    }

    pub(crate) fn length(&self) -> WireU64 {
        self.length
    }

    pub(crate) fn content_sha256(&self) -> &Sha256Digest {
        &self.content_sha256
    }
}

/// The exact target reload observed on the old control-only process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServingControlReloadHandshake {
    pub peer_process_id: WireU64,
    pub identity: AttachmentLineageIdentity,
    pub size_bytes: u64,
    pub durability: Durability,
    pub remote_head: RemoteHead,
    pub process_identity_token: RandomId128,
    pub control_only: bool,
    pub guest_io_enabled: bool,
}

/// Complete physical identity of the old control process proven at handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServingControlProcessIdentity {
    pub process_id: WireU64,
    pub unit_main_process_id: WireU64,
    pub process_start_time_ticks: WireU64,
    pub executable_path: HostPath,
    pub scope_id: Id,
    pub cgroup_path: HostPath,
    pub cgroup_process_ids: Vec<WireU64>,
    pub control_socket_path: HostPath,
    pub data_directory: HostPath,
    pub ownership_token: RandomId128,
    pub handshake: ServingControlReloadHandshake,
}

/// Immutable subsidiary proof bound to one persisted `ProvisionRootImage`.
///
/// This is not a second planner journal. It can be consumed only together
/// with the matching RuntimeCheckpoint and a future handoff-aware next step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServingHandoffRecord {
    pub version: ContractVersion,
    pub checkpoint_content_digest: Sha256Digest,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub provision_transition_id: RandomId128,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub acquire_origin: AcquireOrigin,
    pub node_id: Id,
    pub placement_epoch: Epoch,
    pub expected_provisioned_head: RemoteHead,
    pub expected_control_executable_path: HostPath,
    pub target_control_authorization: TargetControlAuthorizationIdentity,
    pub old_control_process: ServingControlProcessIdentity,
}

/// Content-addressed identity of the durable handoff record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServingHandoffRecordIdentity {
    path: HostPath,
    device: WireU64,
    inode: WireU64,
    length: WireU64,
    content_sha256: Sha256Digest,
}

impl ServingHandoffRecordIdentity {
    pub(crate) fn path(&self) -> &HostPath {
        &self.path
    }

    pub(crate) fn device(&self) -> WireU64 {
        self.device
    }

    pub(crate) fn inode(&self) -> WireU64 {
        self.inode
    }

    pub(crate) fn length(&self) -> WireU64 {
        self.length
    }

    pub(crate) fn content_sha256(&self) -> &Sha256Digest {
        &self.content_sha256
    }
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

impl ServingHandoffReady {
    pub(crate) fn record_path(&self) -> &HostPath {
        self.record_identity.path()
    }

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
}

/// Durable target-head grant that is sufficient only to restart/inspect the
/// old role as `control_only`. It is not a serving-ready proof.
#[derive(Debug)]
pub(crate) struct TargetControlAuthorizationReady {
    identity: TargetControlAuthorizationIdentity,
    retained: RetainedAttachmentContext,
    retained_target: RetainedFile,
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

fn encode_serving_handoff_record(
    record: &ServingHandoffRecord,
) -> std::result::Result<Vec<u8>, ServingHandoffCodecError> {
    validate_handoff_record(record)?;
    canonical_encode(record, SERVING_HANDOFF_RECORD_MAX_BYTES, "record")
}

fn decode_serving_handoff_record(
    bytes: &[u8],
) -> std::result::Result<ServingHandoffRecord, ServingHandoffCodecError> {
    canonical_decode(
        bytes,
        SERVING_HANDOFF_RECORD_MAX_BYTES,
        "record",
        validate_handoff_record,
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
        let ReconcileStep::ProvisionRootImage {
            scope_id,
            control_socket_path,
            ..
        } = &stored_checkpoint.checkpoint().step
        else {
            unreachable!("target candidate accepted only provision_root_image")
        };
        let target_artifact = TargetControlAuthorizationArtifact {
            version: ContractVersion::V1,
            provision_transition_id: candidate.provision_transition_id.clone(),
            provision_context_digest: provision_root_authorization_context_digest(
                stored_checkpoint.checkpoint(),
            )?,
            runtime_scope_id: scope_id.clone(),
            control_socket_path: control_socket_path.clone(),
            local_state: retained.local_state.clone(),
            attachment: candidate.target_attachment,
        };
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
    pub(crate) fn seal_serving_ready(
        &self,
        stored_checkpoint: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        authority: &ServingAuthorityTargetEvidence,
        reloaded_process: &ExactRootProvisionProcessProof,
    ) -> Result<ServingHandoffReady> {
        let target_ready =
            self.seal_target_control_authorization(stored_checkpoint, acquired, authority)?;
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
    anyhow::ensure!(
        blank_attachment.head == *expected_blank_head
            && blank_attachment.acquire_result.resulting_head == *expected_blank_head
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

fn validate_handoff_record(
    record: &ServingHandoffRecord,
) -> std::result::Result<(), ServingHandoffCodecError> {
    let target_artifact = &record.target_control_authorization.artifact;
    validate_target_control_authorization(target_artifact)?;
    let attachment = &target_artifact.attachment;
    let target_bytes = encode_target_control_authorization(target_artifact)
        .map_err(ServingHandoffCodecError::from)?;
    let target_digest = Sha256Digest::from_bytes(Sha256::digest(&target_bytes).into());
    let identity = &attachment.identity;
    let acquire_request = &attachment.acquire_request;
    let process = &record.old_control_process;
    let handshake = &process.handshake;
    let expected_cgroup = format!("/sys/fs/cgroup/system.slice/{}", process.scope_id.as_str());
    let artifact_path = Path::new(record.target_control_authorization.path.as_str());
    let process_directory = Path::new(process.data_directory.as_str());
    let expected_directory_suffix = PathBuf::from("data")
        .join(format!("cat-{}", record.cat_id.as_str()))
        .join(format!("volume-{}", record.volume_id.as_str()))
        .join(format!("attachment-{}", record.attachment_id.as_str()))
        .join(format!("epoch-{}", record.attachment_epoch.get()));
    let expected_control_socket = process_directory.join("root-provision.sock");
    let expected_artifact_name = target_control_file_name(&record.provision_transition_id);
    if record.version != ContractVersion::V1
        || target_artifact.version != record.version
        || target_artifact.provision_transition_id != record.provision_transition_id
        || record.volume_id != identity.volume_id
        || record.attachment_id != identity.attachment_id
        || record.attachment_epoch != identity.attachment_epoch
        || record.acquire_origin != identity.acquire_origin
        || record.node_id != identity.node_id
        || record.placement_epoch != identity.placement_epoch
        || record.desired_revision != acquire_request.desired_revision
        || record.placement_epoch != acquire_request.placement_epoch
        || record.expected_provisioned_head != attachment.head
        || record.expected_control_executable_path != process.executable_path
        || target_artifact.runtime_scope_id != process.scope_id
        || target_artifact.control_socket_path != process.control_socket_path
        || record.target_control_authorization.device
            != target_artifact.local_state.attachment_directory.device
        || record.target_control_authorization.inode.get() == 0
        || record.target_control_authorization.length.get() != target_bytes.len() as u64
        || record.target_control_authorization.content_sha256 != target_digest
        || process.process_id.get() == 0
        || process.unit_main_process_id != process.process_id
        || process.process_start_time_ticks.get() == 0
        || process.cgroup_process_ids != [process.process_id]
        || process.cgroup_path.as_str() != expected_cgroup
        || !process_directory.ends_with(&expected_directory_suffix)
        || Path::new(process.control_socket_path.as_str()) != expected_control_socket
        || process.ownership_token != handshake.process_identity_token
        || process.process_id != handshake.peer_process_id
        || handshake.identity != *identity
        || handshake.size_bytes != attachment.size_bytes
        || handshake.durability != attachment.durability
        || handshake.remote_head != attachment.head
        || !handshake.control_only
        || handshake.guest_io_enabled
        || artifact_path.file_name().and_then(|name| name.to_str())
            != Some(expected_artifact_name.as_str())
        || artifact_path.parent() != Some(process_directory)
        || process_directory
            != Path::new(
                target_artifact
                    .local_state
                    .attachment_directory
                    .path
                    .as_str(),
            )
    {
        return Err(ServingHandoffCodecError::Invalid {
            artifact: "record",
            reason: "record fields do not form one exact serving handoff",
        });
    }
    Ok(())
}

fn validate_target_checkpoint_context(
    artifact: &TargetControlAuthorizationArtifact,
    stored_checkpoint: &StoredCheckpoint,
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
    anyhow::ensure!(
        artifact.provision_context_digest == provision_context_digest
            && artifact.provision_transition_id == *provision_transition_id
            && checkpoint.node_id == attachment.identity.node_id
            && checkpoint.placement_epoch == attachment.identity.placement_epoch
            && checkpoint.desired_revision == attachment.acquire_request.desired_revision
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
    validate_target_checkpoint_context(
        &record.target_control_authorization.artifact,
        stored_checkpoint,
    )?;
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
        expected_provisioned_head,
        ..
    } = &checkpoint.step
    else {
        anyhow::bail!("serving handoff record requires current provision_root_image")
    };
    let process = &record.old_control_process;
    anyhow::ensure!(
        record.checkpoint_content_digest == *stored_checkpoint.content_digest()
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
            .try_clone_directory()
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
fn rename_no_replace(
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
fn rename_no_replace(
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationPoint {
    Created,
    PartialWritten,
    FullWritten,
    TempSynced,
    Published,
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
    use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

    use cats_api::runtime_reconciliation::{
        spec_digest, AsciiText, AssignedKind, AssignedPlacement, DiskKind, Generation,
        GuestDeviceIdentity, GuestTransportEvidence, Ipv4Address, IsolatedIpv4Kind,
        LifecycleAdmission, MacAddress, NetworkConfig, NormalAcquireRequest, NormalAcquireResult,
        RequireIdleCheckpoint, RuntimeCheckpoint, RuntimeConfig, RuntimeTarget, RuntimeTransition,
        UnixMillis, VolumeAccess, VolumeAcquire, VolumeAdminState, VolumeDisposition, VolumeIntent,
        WarmSnapshotEvidence,
    };
    use cats_storage::authority::LastVolumeTransition;

    use super::*;
    use crate::runtime::reconciliation::{AuthorizedBlockdStore, FileCheckpointStore};

    struct Fixture {
        _root: tempfile::TempDir,
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

    fn fixture() -> Fixture {
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
                guest_config_digest: digest('b'),
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
            acquire_request: acquire_request.clone(),
            acquire_result: acquire_result.clone(),
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
        let control_socket_path =
            host(&format!("{}/root-provision.sock", data_directory.display()));
        let data_directory_host = host(data_directory.to_str().unwrap());
        let provision_transition_id = random('3');
        let target = target_head();
        let checkpoint = RuntimeCheckpoint {
            version: ContractVersion::V1,
            cat_id: desired.cat_id.clone(),
            node_id: desired.placement.node_id.clone(),
            placement_epoch,
            desired_revision,
            spec_digest: desired.spec_digest.clone(),
            runtime_incarnation: None,
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
            volumes: Vec::new(),
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            route_gates: Vec::new(),
            require_idle: RequireIdleCheckpoint::NotApplicable,
            updated_at_unix_ms: UnixMillis::new(1_720_000_000_000).unwrap(),
        };
        encode_runtime_checkpoint(&checkpoint).expect("fixture checkpoint is valid");
        let checkpoint_directory = root.path().join("runtime-checkpoints");
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

        let ready = store
            .seal_serving_ready(
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
        swap_same_bytes(&consume_aba.record_path(), "consume");
        assert!(ready
            .assert_current(&consume_aba.stored_checkpoint)
            .is_err());
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

    fn target_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(digest('d')),
            root_object_id: Some(AsciiText::new("roots/generation-1.node").unwrap()),
        }
    }
}
