//! Descriptor-relative, checkpoint-first inputs for one authorized blockd.
//!
//! This module deliberately stops before process creation. The signed Runtime
//! may persist these exact inputs only after a Normal acquire. They authorize
//! the later control-only root-provision process as well as the eventual
//! serving process, but do not prove either one exists. A later process-owner
//! port must create the systemd service and prove the blockd handshake before
//! any observation calls the lineage serving; writing these files alone is
//! not serving evidence.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result};
use cats_api::blockd::DurabilityStatus;
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, DesiredRuntimeSpec, ReconcileStep, RuntimeCheckpoint, Sha256Digest,
};
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, ContractVersion, DiskKind, Durability, Id, RandomId128,
    RuntimeTarget, VolumeAccess, VolumeAcquire, VolumeDisposition, VolumeIntent,
};
use cats_storage::authority::{
    validate_authorized_serving_attachment, validate_volume_record, AttachmentLineageIdentity,
    AuthorizedServingAttachment, VolumeRecord,
};
use cats_storage::AdapterSelection;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::state_directory::StateDirectory;

use super::network::prepared_device_input;
use super::root_provision_process::{
    RootProvisionAuthoritySnapshot, RootProvisionProcessEvidence, RootProvisionProcessExpectation,
    RootProvisionRetirementAdmission,
};
use super::serving_handoff::rename_no_replace;

const DATA_DIRECTORY: &str = "data";
pub(crate) const IDENTITY_FILE: &str = "identity.json";
pub(crate) const IDENTITY_TEMP: &str = ".identity.json.tmp";
pub(crate) const AUTHORIZED_SERVING_FILE: &str = "authorized-serving.json";
pub(crate) const AUTHORIZED_SERVING_TEMP: &str = ".authorized-serving.json.tmp";
pub(crate) const LAUNCH_CHECKPOINT_FILE: &str = "launch-checkpoint.json";
pub(crate) const LAUNCH_CHECKPOINT_TEMP: &str = ".launch-checkpoint.json.tmp";
pub(crate) const MAX_IDENTITY_BYTES: usize = 4 * 1024;
pub(crate) const MAX_AUTHORIZED_SERVING_BYTES: usize = 32 * 1024;
pub(crate) const MAX_LAUNCH_CHECKPOINT_BYTES: usize = 512 * 1024;
pub(crate) const ROOT_PROVISION_STOP_RECEIPT_FILE: &str = "root-provision-stop.json";
pub(crate) const ROOT_PROVISION_STOP_RECEIPT_TEMP: &str = ".root-provision-stop.json.tmp";
// Shorter than `root-provision.sock` so every admitted control path remains
// connect-probeable after an atomic claim on platforms with a small sun_path.
pub(crate) const ROOT_PROVISION_STOP_SOCKET_QUARANTINE: &str = ".rp-stop.sock";
const STAT_FILE_TYPE_MASK: u32 = 0o170000;
const STAT_SOCKET_FILE_TYPE: u32 = 0o140000;
// The receipt stores fixed-size digests plus the bounded physical/authority
// identity only; it deliberately does not duplicate either the (up to 4 MiB)
// Runtime checkpoint or the (up to 512 KiB) launch checkpoint. Four HostPath
// fields dominate its wire size, including JSON escaping at their 4 KiB
// contract bound. Keep a closed 64 KiB ceiling so a 1,024-Cat scan cannot be
// turned into a GiB-scale sidecar workload.
pub(crate) const ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES: usize = 64 * 1024;

/// Exact signed inputs persisted before starting an authorized blockd.
///
/// Keeping the complete Desired (rather than selected fields) gives the
/// inventory scanner a closed binding for runtime config, network config and
/// the one supported root volume. `volume` is repeated intentionally so a
/// consumer cannot silently select a different member of a future multi-disk
/// Desired; validation requires it to equal the sole member exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedBlockdCheckpoint {
    pub version: ContractVersion,
    pub desired: DesiredRuntimeSpec,
    pub volume: VolumeIntent,
    pub attachment: AuthorizedServingAttachment,
}

/// Durable provider-private journal for one exact superseded control-process
/// stop. The receipt is fsynced before the signal is submitted and survives
/// response loss or Agent restart. In particular, it fixes cleanup to the
/// socket inode owned by that accepted process incarnation; a later process
/// which reuses the basename cannot be mistaken for the old residue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootProvisionStopReceipt {
    version: ContractVersion,
    checkpoint_content_digest: Sha256Digest,
    authorized_checkpoint_content_digest: Sha256Digest,
    authority: VolumeRecord,
    process: RootProvisionProcessEvidence,
    socket: StableFsIdentity,
    admission: RootProvisionRetirementAdmission,
}

impl RootProvisionStopReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        checkpoint: &RuntimeCheckpoint,
        authorized: &AuthorizedBlockdCheckpoint,
        authority: VolumeRecord,
        process: RootProvisionProcessEvidence,
        socket: RetainedExactControlSocket,
        admission: RootProvisionRetirementAdmission,
    ) -> Result<Self> {
        let expectation = RootProvisionProcessExpectation::from_checkpoint(
            checkpoint,
            RootProvisionAuthoritySnapshot {
                attachment: authorized.attachment.clone(),
                volume: &authority,
            },
            process.executable_path.clone(),
        )?;
        anyhow::ensure!(
            process.exactly_matches(&expectation),
            "root-provision stop process is not its exact old expectation"
        );
        anyhow::ensure!(
            matches!(
                authority.lease_expires_at,
                Some(current) if current >= authorized.attachment.lease_expires_at
            ),
            "root-provision stop authority lease predates its retained launch grant"
        );
        let receipt = Self {
            version: ContractVersion::V1,
            checkpoint_content_digest: checkpoint_content_digest(checkpoint)
                .context("digest root-provision stop checkpoint")?,
            authorized_checkpoint_content_digest: authorized_blockd_checkpoint_content_digest(
                authorized,
            )?,
            authority,
            process,
            socket: socket.identity,
            admission,
        };
        validate_root_provision_stop_receipt(&receipt)?;
        Ok(receipt)
    }

    pub(crate) fn checkpoint_content_digest(&self) -> &Sha256Digest {
        &self.checkpoint_content_digest
    }

    #[cfg(test)]
    pub(crate) fn authorized_checkpoint_content_digest(&self) -> &Sha256Digest {
        &self.authorized_checkpoint_content_digest
    }

    pub(crate) fn process(&self) -> &RootProvisionProcessEvidence {
        &self.process
    }

    pub(crate) fn socket(&self) -> RetainedExactControlSocket {
        RetainedExactControlSocket {
            identity: self.socket,
        }
    }

    pub(crate) fn socket_matches_scanned_stat(&self, metadata: &libc::stat) -> bool {
        let (Some(device), Some(links), Some(length)) = (
            raw_stat_u64(metadata.st_dev),
            raw_stat_u64(metadata.st_nlink),
            raw_stat_u64(metadata.st_size),
        ) else {
            return false;
        };
        let scanned = StableFsIdentity {
            device,
            inode: metadata.st_ino,
            mode: raw_mode_to_u32(metadata.st_mode),
            links,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
            length,
            modified_seconds: metadata.st_mtime,
            modified_nanoseconds: metadata.st_mtime_nsec,
            changed_seconds: metadata.st_ctime,
            changed_nanoseconds: metadata.st_ctime_nsec,
        };
        same_socket_after_rename(&self.socket, &scanned)
    }

    pub(crate) fn admission(&self) -> &RootProvisionRetirementAdmission {
        &self.admission
    }

    /// Reconstruct the old process expectation from a fresh point read. Lease
    /// renewal may advance only `lease_expires_at`; every field which owns the
    /// process and its remote-head handshake remains exact.
    pub(crate) fn expectation_for_current_authority(
        &self,
        checkpoint: &RuntimeCheckpoint,
        authorized: &AuthorizedBlockdCheckpoint,
        current: &VolumeRecord,
    ) -> Result<RootProvisionProcessExpectation> {
        self.binds_retained_values(checkpoint, authorized)?;
        let expectation = RootProvisionProcessExpectation::from_checkpoint(
            checkpoint,
            RootProvisionAuthoritySnapshot {
                attachment: authorized.attachment.clone(),
                volume: current,
            },
            self.process.executable_path.clone(),
        )?;
        anyhow::ensure!(
            self.process.exactly_matches(&expectation)
                && same_retirement_authority(&self.authority, current),
            "current authority no longer owns the receipted root-provision process"
        );
        Ok(expectation)
    }

    pub(crate) fn binds_retained_values(
        &self,
        checkpoint: &RuntimeCheckpoint,
        authorized: &AuthorizedBlockdCheckpoint,
    ) -> Result<()> {
        anyhow::ensure!(
            checkpoint_content_digest(checkpoint)? == self.checkpoint_content_digest,
            "root-provision stop receipt belongs to another retained Runtime checkpoint"
        );
        self.binds_authorized_checkpoint(authorized)?;
        Ok(())
    }

    pub(crate) fn binds_authorized_checkpoint(
        &self,
        authorized: &AuthorizedBlockdCheckpoint,
    ) -> Result<()> {
        anyhow::ensure!(
            authorized_blockd_checkpoint_content_digest(authorized)?
                == self.authorized_checkpoint_content_digest
                && matches!(
                    self.authority.lease_expires_at,
                    Some(current) if current >= authorized.attachment.lease_expires_at
                ),
            "root-provision stop receipt belongs to another launch grant or predates it"
        );
        Ok(())
    }

    fn same_stop_attempt(&self, candidate: &Self) -> bool {
        self.version == candidate.version
            && self.checkpoint_content_digest == candidate.checkpoint_content_digest
            && self.authorized_checkpoint_content_digest
                == candidate.authorized_checkpoint_content_digest
            && same_retirement_authority(&self.authority, &candidate.authority)
            && self.process == candidate.process
            && self.socket == candidate.socket
    }
}

fn same_retirement_authority(before: &VolumeRecord, after: &VolumeRecord) -> bool {
    before.volume_id == after.volume_id
        && before.size_bytes == after.size_bytes
        && before.durability == after.durability
        && before.admin_state == after.admin_state
        && before.head == after.head
        && before.lease_owner == after.lease_owner
        && before.lease_epoch == after.lease_epoch
        && before.last_transition == after.last_transition
        && matches!(
            (before.lease_expires_at, after.lease_expires_at),
            (Some(before), Some(after)) if after >= before
        )
}

pub(crate) fn authorized_blockd_checkpoint_content_digest(
    checkpoint: &AuthorizedBlockdCheckpoint,
) -> Result<Sha256Digest> {
    validate_authorized_blockd_checkpoint(checkpoint)?;
    let bytes = bounded_json(
        checkpoint,
        MAX_LAUNCH_CHECKPOINT_BYTES,
        "authorized blockd launch checkpoint",
    )?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
}

pub(crate) fn encode_root_provision_stop_receipt(
    receipt: &RootProvisionStopReceipt,
) -> Result<Vec<u8>> {
    validate_root_provision_stop_receipt(receipt)?;
    bounded_json(
        receipt,
        ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES,
        "root-provision stop receipt",
    )
}

pub(crate) fn decode_root_provision_stop_receipt(bytes: &[u8]) -> Result<RootProvisionStopReceipt> {
    anyhow::ensure!(
        bytes.len() <= ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES,
        "root-provision stop receipt exceeds its bound"
    );
    let receipt: RootProvisionStopReceipt =
        serde_json::from_slice(bytes).context("decode root-provision stop receipt")?;
    anyhow::ensure!(
        serde_json::to_vec(&receipt).context("re-encode root-provision stop receipt")? == bytes,
        "root-provision stop receipt is not canonical"
    );
    validate_root_provision_stop_receipt(&receipt)?;
    Ok(receipt)
}

fn validate_root_provision_stop_receipt(receipt: &RootProvisionStopReceipt) -> Result<()> {
    anyhow::ensure!(
        receipt.version == ContractVersion::V1
            && Path::new(receipt.process.control_socket_path.as_str())
                == Path::new(receipt.process.data_directory.as_str()).join("root-provision.sock"),
        "root-provision stop receipt does not bind one old checkpoint attempt"
    );
    validate_volume_record(&receipt.authority)
        .context("root-provision stop receipt authority is not closed")?;
    anyhow::ensure!(
        receipt.process.process_id > 0
            && receipt.process.unit_main_process_id == receipt.process.process_id
            && receipt.process.process_start_time_ticks.get() > 0
            && receipt.process.cgroup_process_ids == [receipt.process.process_id]
            && receipt.process.handshake.peer_process_id == receipt.process.process_id
            && receipt.process.ownership_token == receipt.process.handshake.process_identity_token
            && receipt.authority.volume_id == receipt.process.handshake.identity.volume_id
            && receipt.authority.size_bytes == receipt.process.handshake.size_bytes
            && receipt.authority.durability == receipt.process.handshake.durability
            && receipt.authority.lease_owner.as_ref()
                == Some(&receipt.process.handshake.identity.attachment_id)
            && receipt.authority.lease_epoch == receipt.process.handshake.identity.attachment_epoch
            && receipt.authority.head == receipt.process.handshake.remote_head
            && receipt.process.handshake.control_only
            && !receipt.process.handshake.guest_io_enabled,
        "root-provision stop receipt process and authority are not one exact control attempt"
    );
    anyhow::ensure!(
        receipt.socket.device > 0 && receipt.socket.inode > 0,
        "root-provision stop receipt socket lacks a stable filesystem identity"
    );
    anyhow::ensure!(
        receipt.socket.mode & STAT_FILE_TYPE_MASK == STAT_SOCKET_FILE_TYPE
            && receipt.socket.links == 1
            && receipt.socket.mode & 0o7777 == 0o700,
        "root-provision stop receipt socket has an unsafe type, link count, or mode"
    );
    anyhow::ensure!(
        receipt.admission.agent_session_epoch.get() > 0
            && receipt.admission.inventory_epoch.get() > 0
            && receipt.admission.inventory_read_position.get() > 0,
        "root-provision stop receipt lacks a valid accepted-full admission"
    );
    Ok(())
}

/// Descriptor-relative store rooted in the identity-selected Node state fd.
#[derive(Clone)]
pub struct AuthorizedBlockdStore {
    state_directory: StateDirectory,
}

impl AuthorizedBlockdStore {
    pub fn new(state_directory: StateDirectory) -> Self {
        Self { state_directory }
    }

    /// Validate and durably publish the exact attachment files in their only
    /// allowed order. Exact replays recover response loss; conflicting bytes,
    /// unsafe entries and residue before the checkpoint fail closed.
    pub fn prepare(
        &self,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        attachment: &AuthorizedServingAttachment,
    ) -> Result<PreparedAuthorizedBlockd> {
        validate_checkpoint_inputs(desired, volume, attachment)?;
        self.prepare_validated(desired, volume, attachment, false)
    }

    /// Persist or reopen an attachment whose exact NormalAcquire receipt was
    /// issued to an older revision of the same-Node Desired. This never
    /// rewrites an existing launch checkpoint: a compatible old checkpoint is
    /// retained as provenance, while an absent directory receives the current
    /// Desired plus the immutable old receipt. The caller must already have a
    /// current Runtime checkpoint authorizing this adoption.
    pub(crate) fn prepare_adopted(
        &self,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        attachment: &AuthorizedServingAttachment,
    ) -> Result<PreparedAuthorizedBlockd> {
        validate_adopted_checkpoint_inputs(desired, volume, attachment)?;
        self.prepare_validated(desired, volume, attachment, true)
    }

    /// Reopen the scanner-attributed attachment and close the scan/effect ABA
    /// window by feeding the decoded candidate back through the locked,
    /// descriptor-relative exact-file verifier in `prepare_adopted`.
    pub(crate) fn reopen_adopted(
        &self,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        identity: &AttachmentLineageIdentity,
    ) -> Result<PreparedAuthorizedBlockd> {
        let directory =
            authorized_blockd_data_directory(self.state_directory.path(), desired, identity);
        let path = directory.join(AUTHORIZED_SERVING_FILE);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect adopted attachment {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= MAX_AUTHORIZED_SERVING_BYTES as u64,
            "adopted authorized-serving candidate has unsafe metadata"
        );
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read adopted attachment {}", path.display()))?;
        anyhow::ensure!(
            bytes.len() <= MAX_AUTHORIZED_SERVING_BYTES,
            "adopted authorized-serving candidate exceeds its bound"
        );
        let attachment: AuthorizedServingAttachment = serde_json::from_slice(&bytes)
            .context("decode adopted authorized-serving attachment")?;
        anyhow::ensure!(
            serde_json::to_vec(&attachment).context("re-encode adopted attachment")? == bytes
                && attachment.identity == *identity,
            "adopted authorized-serving candidate conflicts with scanned identity"
        );
        self.prepare_adopted(desired, volume, &attachment)
    }

    /// Reopen the immutable launch inputs named by an already persisted
    /// `ProvisionRootImage` checkpoint without interpreting them through the
    /// current Desired. This is the read-only retirement path for a
    /// superseded control process: every directory and file is opened beneath
    /// the retained Node-state descriptor, the leaf is locked, and missing or
    /// conflicting bytes fail closed rather than being repaired.
    pub(crate) fn retain_exact_runtime_checkpoint(
        &self,
        runtime: &RuntimeCheckpoint,
    ) -> Result<RetainedAuthorizedBlockd> {
        let ReconcileStep::ProvisionRootImage {
            volume_id,
            attachment_id,
            attachment_epoch,
            data_directory,
            size_bytes,
            boot_image_digest,
            expected_blank_head,
            ..
        } = &runtime.step
        else {
            anyhow::bail!("exact authorized blockd reopen requires provision_root_image")
        };
        let components = [
            DATA_DIRECTORY.to_owned(),
            format!("cat-{}", runtime.cat_id),
            format!("volume-{volume_id}"),
            format!("attachment-{attachment_id}"),
            format!("epoch-{}", attachment_epoch.get()),
        ];
        let expected_directory = components.iter().fold(
            self.state_directory.path().to_path_buf(),
            |path, component| path.join(component),
        );
        anyhow::ensure!(
            Path::new(data_directory.as_str()) == expected_directory,
            "provision checkpoint data directory is not its exact retained Node path"
        );

        let root_directory = self
            .state_directory
            .try_clone_directory()
            .context("clone retained Node state directory")?;
        let root_identity =
            verify_retained_state_root(&root_directory, self.state_directory.path())?;
        let mut relative = PathBuf::new();
        let mut directory = root_directory
            .try_clone()
            .context("clone retained Node state directory descriptor")?;
        let mut component_identities = Vec::with_capacity(components.len());
        for component in &components {
            relative.push(component);
            directory =
                open_existing_directory_at(&directory, component, &relative, &root_identity)?;
            component_identities.push(stable_identity(&directory, &relative)?);
        }
        lock_directory(&directory).with_context(|| {
            format!(
                "lock exact authorized blockd directory {}",
                relative.display()
            )
        })?;
        for temporary in [
            IDENTITY_TEMP,
            AUTHORIZED_SERVING_TEMP,
            LAUNCH_CHECKPOINT_TEMP,
        ] {
            let path = relative.join(temporary);
            let name = c_string(temporary, &path)?;
            anyhow::ensure!(
                read_optional_bounded(&directory, &name, &path, MAX_LAUNCH_CHECKPOINT_BYTES)?
                    .is_none(),
                "exact authorized blockd reopen found unpublished input {}",
                path.display()
            );
        }

        let (identity, identity_file): (AttachmentLineageIdentity, _) = read_required_canonical(
            &directory,
            &relative,
            IDENTITY_FILE,
            MAX_IDENTITY_BYTES,
            "attachment identity",
            &root_identity,
        )?;
        let (attachment, attachment_file): (AuthorizedServingAttachment, _) =
            read_required_canonical(
                &directory,
                &relative,
                AUTHORIZED_SERVING_FILE,
                MAX_AUTHORIZED_SERVING_BYTES,
                "authorized serving attachment",
                &root_identity,
            )?;
        let (checkpoint, checkpoint_file): (AuthorizedBlockdCheckpoint, _) =
            read_required_canonical(
                &directory,
                &relative,
                LAUNCH_CHECKPOINT_FILE,
                MAX_LAUNCH_CHECKPOINT_BYTES,
                "authorized blockd launch checkpoint",
                &root_identity,
            )?;
        validate_authorized_blockd_checkpoint(&checkpoint)?;
        anyhow::ensure!(
            identity == attachment.identity
                && attachment == checkpoint.attachment
                && runtime.cat_id == checkpoint.desired.cat_id
                && runtime.node_id == checkpoint.desired.placement.node_id
                && runtime.placement_epoch == checkpoint.desired.placement.placement_epoch
                && runtime.desired_revision == checkpoint.desired.desired_revision
                && runtime.spec_digest == checkpoint.desired.spec_digest
                && *volume_id == checkpoint.volume.volume_id
                && *attachment_id == identity.attachment_id
                && *attachment_epoch == identity.attachment_epoch
                && *size_bytes == attachment.size_bytes
                && *boot_image_digest == checkpoint.desired.runtime.boot_image_digest
                && *expected_blank_head == attachment.head,
            "Runtime checkpoint and immutable authorized blockd inputs conflict"
        );

        let retained = RetainedAuthorizedBlockd {
            state_directory: self.state_directory.clone(),
            root_directory,
            root_identity,
            components,
            component_identities,
            data_directory: expected_directory,
            checkpoint,
            directory,
            files: [identity_file, attachment_file, checkpoint_file],
        };
        retained.assert_current()?;
        Ok(retained)
    }

    /// Reopen, without repairing, the acquire-time attachment inputs retained
    /// by an `after_root_provision` `PrepareDevice` checkpoint.  The returned
    /// value holds the attachment-directory flock and every input descriptor;
    /// callers may therefore keep the original Root handoff lineage pinned
    /// through one later exact process effect.
    pub(crate) fn retain_prepare_device_handoff(
        &self,
        runtime: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
    ) -> Result<RetainedAuthorizedBlockd> {
        let prepared = prepared_device_input(runtime)
            .context("exact authorized blockd handoff reopen requires a prepared device")?;
        anyhow::ensure!(
            matches!(
                prepared.serving_authority.as_ref(),
                cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
            ),
            "exact authorized blockd handoff reopen requires Root serving provenance"
        );
        let components = [
            DATA_DIRECTORY.to_owned(),
            format!("cat-{}", runtime.cat_id),
            format!("volume-{}", prepared.volume_id),
            format!("attachment-{}", prepared.attachment_id),
            format!("epoch-{}", prepared.attachment_epoch.get()),
        ];
        let expected_directory = components.iter().fold(
            self.state_directory.path().to_path_buf(),
            |path, component| path.join(component),
        );
        anyhow::ensure!(
            Path::new(prepared.serving_process.data_directory.as_str()) == expected_directory,
            "PrepareDevice data directory is not its exact retained Node path"
        );

        let root_directory = self
            .state_directory
            .try_clone_directory()
            .context("clone retained Node state directory")?;
        let root_identity =
            verify_retained_state_root(&root_directory, self.state_directory.path())?;
        let mut relative = PathBuf::new();
        let mut directory = root_directory
            .try_clone()
            .context("clone retained Node state directory descriptor")?;
        let mut component_identities = Vec::with_capacity(components.len());
        for component in &components {
            relative.push(component);
            directory =
                open_existing_directory_at(&directory, component, &relative, &root_identity)?;
            component_identities.push(stable_identity(&directory, &relative)?);
        }
        lock_directory(&directory).with_context(|| {
            format!(
                "lock exact authorized blockd handoff directory {}",
                relative.display()
            )
        })?;
        for temporary in [
            IDENTITY_TEMP,
            AUTHORIZED_SERVING_TEMP,
            LAUNCH_CHECKPOINT_TEMP,
        ] {
            let path = relative.join(temporary);
            let name = c_string(temporary, &path)?;
            anyhow::ensure!(
                read_optional_bounded(&directory, &name, &path, MAX_LAUNCH_CHECKPOINT_BYTES)?
                    .is_none(),
                "exact authorized blockd handoff reopen found unpublished input {}",
                path.display()
            );
        }

        let (identity, identity_file): (AttachmentLineageIdentity, _) = read_required_canonical(
            &directory,
            &relative,
            IDENTITY_FILE,
            MAX_IDENTITY_BYTES,
            "attachment identity",
            &root_identity,
        )?;
        let (attachment, attachment_file): (AuthorizedServingAttachment, _) =
            read_required_canonical(
                &directory,
                &relative,
                AUTHORIZED_SERVING_FILE,
                MAX_AUTHORIZED_SERVING_BYTES,
                "authorized serving attachment",
                &root_identity,
            )?;
        let (checkpoint, checkpoint_file): (AuthorizedBlockdCheckpoint, _) =
            read_required_canonical(
                &directory,
                &relative,
                LAUNCH_CHECKPOINT_FILE,
                MAX_LAUNCH_CHECKPOINT_BYTES,
                "authorized blockd launch checkpoint",
                &root_identity,
            )?;
        validate_authorized_blockd_checkpoint(&checkpoint)?;
        let [desired_volume] = desired.volumes.as_slice() else {
            anyhow::bail!("Root PrepareDevice handoff requires one Desired volume")
        };
        anyhow::ensure!(
            identity == attachment.identity
                && attachment == checkpoint.attachment
                && checkpoint.desired == *desired
                && checkpoint.volume == *desired_volume
                && runtime.cat_id == desired.cat_id
                && runtime.node_id == desired.placement.node_id
                && runtime.placement_epoch == desired.placement.placement_epoch
                && runtime.desired_revision == desired.desired_revision
                && runtime.spec_digest == desired.spec_digest
                && prepared.volume_id == desired_volume.volume_id
                && prepared.volume_id == identity.volume_id
                && prepared.attachment_id == identity.attachment_id
                && prepared.attachment_epoch == identity.attachment_epoch
                && prepared.acquire_origin == identity.acquire_origin
                && prepared.size_bytes == attachment.size_bytes
                && prepared.durability == attachment.durability
                && prepared.expected_head.generation.get() > 0
                && prepared.expected_head.root_hash.is_some()
                && prepared.expected_head.root_object_id.is_some(),
            "PrepareDevice checkpoint and immutable authorized blockd inputs conflict"
        );

        let retained = RetainedAuthorizedBlockd {
            state_directory: self.state_directory.clone(),
            root_directory,
            root_identity,
            components,
            component_identities,
            data_directory: expected_directory,
            checkpoint,
            directory,
            files: [identity_file, attachment_file, checkpoint_file],
        };
        retained.assert_current()?;
        Ok(retained)
    }

    fn prepare_validated(
        &self,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        attachment: &AuthorizedServingAttachment,
        permit_compatible_superseded_launch: bool,
    ) -> Result<PreparedAuthorizedBlockd> {
        let checkpoint = AuthorizedBlockdCheckpoint {
            version: ContractVersion::V1,
            desired: desired.clone(),
            volume: volume.clone(),
            attachment: attachment.clone(),
        };
        let identity_bytes = bounded_json(
            &attachment.identity,
            MAX_IDENTITY_BYTES,
            "attachment identity",
        )?;
        let attachment_bytes = bounded_json(
            attachment,
            MAX_AUTHORIZED_SERVING_BYTES,
            "authorized serving spec",
        )?;
        let checkpoint_bytes = bounded_json(
            &checkpoint,
            MAX_LAUNCH_CHECKPOINT_BYTES,
            "authorized blockd launch checkpoint",
        )?;

        let root = self
            .state_directory
            .try_clone_directory()
            .context("clone retained Node state directory")?;
        let mut relative = PathBuf::new();
        let mut directory = root;
        for component in directory_components(desired, &attachment.identity) {
            relative.push(&component);
            directory = ensure_directory_at(&directory, &component, &relative)?;
        }
        lock_directory(&directory).with_context(|| {
            format!(
                "lock authorized blockd directory {}",
                self.state_directory.path().join(&relative).display()
            )
        })?;

        persist_ordered_file(
            &directory,
            &relative,
            IDENTITY_FILE,
            IDENTITY_TEMP,
            &identity_bytes,
            &[],
            MAX_IDENTITY_BYTES,
        )?;
        persist_ordered_file(
            &directory,
            &relative,
            AUTHORIZED_SERVING_FILE,
            AUTHORIZED_SERVING_TEMP,
            &attachment_bytes,
            &[IDENTITY_FILE],
            MAX_AUTHORIZED_SERVING_BYTES,
        )?;
        let checkpoint = if permit_compatible_superseded_launch {
            persist_adopted_launch_file(&directory, &relative, &checkpoint, &checkpoint_bytes)?
        } else {
            persist_ordered_file(
                &directory,
                &relative,
                LAUNCH_CHECKPOINT_FILE,
                LAUNCH_CHECKPOINT_TEMP,
                &checkpoint_bytes,
                &[IDENTITY_FILE, AUTHORIZED_SERVING_FILE],
                MAX_LAUNCH_CHECKPOINT_BYTES,
            )?;
            checkpoint
        };

        let data_directory = self.state_directory.path().join(&relative);
        Ok(PreparedAuthorizedBlockd {
            state_directory: self.state_directory.path().to_path_buf(),
            identity_path: data_directory.join(IDENTITY_FILE),
            authorized_serving_path: data_directory.join(AUTHORIZED_SERVING_FILE),
            launch_checkpoint_path: data_directory.join(LAUNCH_CHECKPOINT_FILE),
            data_directory,
            checkpoint,
            // Retain the exclusive cooperative lock through command
            // construction and process handoff.
            _directory_lock: directory,
        })
    }
}

/// Prepared exact files plus the held attachment-directory lock.
#[derive(Debug)]
pub struct PreparedAuthorizedBlockd {
    state_directory: PathBuf,
    data_directory: PathBuf,
    identity_path: PathBuf,
    authorized_serving_path: PathBuf,
    launch_checkpoint_path: PathBuf,
    checkpoint: AuthorizedBlockdCheckpoint,
    _directory_lock: File,
}

/// Read-only, descriptor-retained proof of the immutable launch inputs for a
/// superseded control process. Unlike [`PreparedAuthorizedBlockd`], this value
/// can neither create nor repair a file. `assert_current` reopens every lexical
/// component and input immediately before a destructive retirement action, so
/// a rename/recreate ABA cannot authorize that action through stale fds.
pub(crate) struct RetainedAuthorizedBlockd {
    state_directory: StateDirectory,
    root_directory: File,
    root_identity: StableFsIdentity,
    components: [String; 5],
    component_identities: Vec<StableFsIdentity>,
    data_directory: PathBuf,
    checkpoint: AuthorizedBlockdCheckpoint,
    directory: File,
    files: [RetainedExactFile; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StableFsIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct RetainedExactFile {
    name: &'static str,
    file: File,
    identity: StableFsIdentity,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactControlSocketCleanup {
    Removed,
    AlreadyAbsent,
    LiveOrChanged,
}

pub(crate) enum StopReceiptSettlement {
    Absent,
    Stable(RootProvisionStopReceipt),
    Recovered(RootProvisionStopReceipt),
}

pub(crate) enum StopReceiptPublication {
    Stable(RootProvisionStopReceipt),
    Published(RootProvisionStopReceipt),
    Recovered(RootProvisionStopReceipt),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoReplaceReceiptPublication {
    Published,
    ExactReplay,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetainedExactControlSocket {
    identity: StableFsIdentity,
}

impl RetainedAuthorizedBlockd {
    pub(crate) fn checkpoint(&self) -> &AuthorizedBlockdCheckpoint {
        &self.checkpoint
    }

    /// Duplicate the already-flocked attachment descriptor for another typed
    /// verifier. `File::try_clone` uses the same open file description, so it
    /// preserves (and does not recursively reacquire) the cooperative flock.
    /// The caller must keep this retained owner live while consuming the
    /// duplicate.
    pub(crate) fn duplicate_locked_attachment_directory(&self) -> Result<File> {
        self.assert_current()?;
        self.directory
            .try_clone()
            .context("duplicate retained authorized blockd attachment descriptor")
    }

    pub(crate) fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    pub(crate) fn retained_directory(&self) -> &File {
        &self.directory
    }

    pub(crate) fn state_directory_path(&self) -> &Path {
        self.state_directory.path()
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        anyhow::ensure!(
            verify_retained_state_root(&self.root_directory, self.state_directory.path())?
                == self.root_identity,
            "retained Node state directory changed identity"
        );
        let current_root = self
            .state_directory
            .try_reopen_directory()
            .context("reopen current Node state directory")?;
        anyhow::ensure!(
            verify_retained_state_root(&current_root, self.state_directory.path())?
                == self.root_identity,
            "lexical Node state directory changed identity"
        );
        let mut current = current_root;
        let mut relative = PathBuf::new();
        for (component, expected) in self.components.iter().zip(self.component_identities.iter()) {
            relative.push(component);
            current =
                open_existing_directory_at(&current, component, &relative, &self.root_identity)?;
            anyhow::ensure!(
                stable_identity(&current, &relative)? == *expected,
                "authorized blockd path component {} changed identity",
                relative.display()
            );
        }
        anyhow::ensure!(
            stable_identity(&self.directory, &self.data_directory)?
                == *self
                    .component_identities
                    .last()
                    .context("retained authorized blockd path is empty")?,
            "retained authorized blockd leaf changed identity"
        );
        for retained in &self.files {
            retained.assert_current(&current, &self.root_identity, &self.data_directory)?;
        }
        Ok(())
    }

    /// Recover an exact sidecar publication, if present. A valid temp could
    /// only have been written before the stop signal: publishing it is safe
    /// even when the process exited independently, and preserves the socket
    /// identity needed by the later cleanup. Conflicting/partial bytes remain
    /// fail-closed residue.
    pub(crate) fn settle_stop_receipt(&self) -> Result<StopReceiptSettlement> {
        self.assert_current()?;
        let target = self.read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_FILE)?;
        let temporary = self.read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_TEMP)?;
        match (target, temporary) {
            (None, None) => Ok(StopReceiptSettlement::Absent),
            (Some(target), None) => {
                let receipt = decode_root_provision_stop_receipt(&target)?;
                self.validate_receipt_for_retained_inputs(&receipt)?;
                Ok(StopReceiptSettlement::Stable(receipt))
            }
            (Some(target), Some(temporary)) => {
                anyhow::ensure!(
                    target == temporary,
                    "root-provision stop receipt target and temp conflict"
                );
                let receipt = decode_root_provision_stop_receipt(&target)?;
                self.validate_receipt_for_retained_inputs(&receipt)?;
                let temp = c_string(
                    ROOT_PROVISION_STOP_RECEIPT_TEMP,
                    &self.data_directory.join(ROOT_PROVISION_STOP_RECEIPT_TEMP),
                )?;
                unlink_at(&self.directory, &temp)
                    .context("remove recovered root-provision stop receipt temp")?;
                self.directory
                    .sync_all()
                    .context("sync recovered root-provision stop receipt temp removal")?;
                Ok(StopReceiptSettlement::Recovered(receipt))
            }
            (None, Some(temporary)) => {
                let receipt = decode_root_provision_stop_receipt(&temporary)?;
                self.validate_receipt_for_retained_inputs(&receipt)?;
                self.publish_stop_receipt_no_replace(&temporary)
                    .context("publish recovered root-provision stop receipt")?;
                Ok(StopReceiptSettlement::Recovered(receipt))
            }
        }
    }

    /// Durably publish or reopen the immutable journal before signalling. A
    /// replay may carry a later accepted-full admission, but every field which
    /// identifies the old checkpoint/process/socket/authority must be exact.
    pub(crate) fn persist_or_reopen_stop_receipt(
        &mut self,
        candidate: &RootProvisionStopReceipt,
    ) -> Result<StopReceiptPublication> {
        self.persist_or_reopen_stop_receipt_before_publish(candidate, || {})
    }

    #[cfg(test)]
    pub(crate) fn persist_or_reopen_stop_receipt_with_hook(
        &mut self,
        candidate: &RootProvisionStopReceipt,
        before_publish: impl FnOnce(),
    ) -> Result<StopReceiptPublication> {
        self.persist_or_reopen_stop_receipt_before_publish(candidate, before_publish)
    }

    fn persist_or_reopen_stop_receipt_before_publish(
        &mut self,
        candidate: &RootProvisionStopReceipt,
        before_publish: impl FnOnce(),
    ) -> Result<StopReceiptPublication> {
        match self.settle_stop_receipt()? {
            StopReceiptSettlement::Stable(receipt) => {
                anyhow::ensure!(
                    receipt.same_stop_attempt(candidate),
                    "existing root-provision stop receipt belongs to another attempt"
                );
                Ok(StopReceiptPublication::Stable(receipt))
            }
            StopReceiptSettlement::Recovered(receipt) => {
                anyhow::ensure!(
                    receipt.same_stop_attempt(candidate),
                    "recovered root-provision stop receipt belongs to another attempt"
                );
                Ok(StopReceiptPublication::Recovered(receipt))
            }
            StopReceiptSettlement::Absent => {
                self.validate_receipt_for_retained_inputs(candidate)?;
                let bytes = encode_root_provision_stop_receipt(candidate)?;
                let temp_path = self.data_directory.join(ROOT_PROVISION_STOP_RECEIPT_TEMP);
                let temp = c_string(ROOT_PROVISION_STOP_RECEIPT_TEMP, &temp_path)?;
                let mut file = open_at(
                    &self.directory,
                    &temp,
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
                .with_context(|| format!("create {}", temp_path.display()))?;
                verify_retained_regular_file(&file, &temp_path, &self.root_identity, Some(0))?;
                file.write_all(&bytes)
                    .context("write root-provision stop receipt temp")?;
                file.sync_all()
                    .context("sync root-provision stop receipt temp")?;
                verify_retained_regular_file(
                    &file,
                    &temp_path,
                    &self.root_identity,
                    Some(bytes.len()),
                )?;
                before_publish();
                let publication = self
                    .publish_stop_receipt_no_replace(&bytes)
                    .context("publish root-provision stop receipt")?;
                let current_leaf = stable_identity(&self.directory, &self.data_directory)?;
                *self
                    .component_identities
                    .last_mut()
                    .context("retained authorized blockd path is empty")? = current_leaf;
                Ok(match publication {
                    NoReplaceReceiptPublication::Published => {
                        StopReceiptPublication::Published(candidate.clone())
                    }
                    NoReplaceReceiptPublication::ExactReplay => {
                        StopReceiptPublication::Recovered(candidate.clone())
                    }
                })
            }
        }
    }

    /// Atomically publish the already-fsynced temp without replacing an entry
    /// which appeared after the preceding scan. EEXIST is recoverable only
    /// when both names still contain the same canonical receipt; conflicting
    /// bytes are deliberately left in place for the next full scan.
    fn publish_stop_receipt_no_replace(
        &self,
        expected: &[u8],
    ) -> Result<NoReplaceReceiptPublication> {
        let temp_path = self.data_directory.join(ROOT_PROVISION_STOP_RECEIPT_TEMP);
        let target_path = self.data_directory.join(ROOT_PROVISION_STOP_RECEIPT_FILE);
        let temp = c_string(ROOT_PROVISION_STOP_RECEIPT_TEMP, &temp_path)?;
        let target = c_string(ROOT_PROVISION_STOP_RECEIPT_FILE, &target_path)?;
        match rename_no_replace(&self.directory, &temp, &self.directory, &target) {
            Ok(()) => {
                self.directory
                    .sync_all()
                    .context("sync root-provision stop receipt publication")?;
                anyhow::ensure!(
                    self.read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_FILE)?
                        .as_deref()
                        == Some(expected)
                        && self
                            .read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_TEMP)?
                            .is_none(),
                    "published root-provision stop receipt changed or retained its temp"
                );
                Ok(NoReplaceReceiptPublication::Published)
            }
            Err(source)
                if source.kind() == io::ErrorKind::AlreadyExists
                    || source.raw_os_error() == Some(libc::EEXIST) =>
            {
                anyhow::ensure!(
                    self.read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_FILE)?
                        .as_deref()
                        == Some(expected)
                        && self
                            .read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_TEMP)?
                            .as_deref()
                            == Some(expected),
                    "root-provision stop receipt no-replace conflict"
                );
                unlink_at(&self.directory, &temp)
                    .context("remove exact replay root-provision stop receipt temp")?;
                self.directory
                    .sync_all()
                    .context("sync exact replay root-provision stop receipt temp removal")?;
                Ok(NoReplaceReceiptPublication::ExactReplay)
            }
            Err(source) => Err(source).context("atomically publish root-provision stop receipt"),
        }
    }

    pub(crate) fn remove_stop_receipt(&self, expected: &RootProvisionStopReceipt) -> Result<()> {
        self.assert_current()?;
        let bytes = encode_root_provision_stop_receipt(expected)?;
        anyhow::ensure!(
            self.read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_FILE)?
                .as_deref()
                == Some(bytes.as_slice())
                && self
                    .read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_TEMP)?
                    .is_none(),
            "root-provision stop receipt changed before cleanup"
        );
        let target = c_string(
            ROOT_PROVISION_STOP_RECEIPT_FILE,
            &self.data_directory.join(ROOT_PROVISION_STOP_RECEIPT_FILE),
        )?;
        unlink_at(&self.directory, &target).context("unlink exact root-provision stop receipt")?;
        self.directory
            .sync_all()
            .context("sync root-provision stop receipt removal")?;
        anyhow::ensure!(
            self.read_stop_receipt_bytes(ROOT_PROVISION_STOP_RECEIPT_FILE)?
                .is_none(),
            "root-provision stop receipt reappeared during cleanup"
        );
        Ok(())
    }

    fn validate_receipt_for_retained_inputs(
        &self,
        receipt: &RootProvisionStopReceipt,
    ) -> Result<()> {
        validate_root_provision_stop_receipt(receipt)?;
        anyhow::ensure!(
            Path::new(receipt.process.data_directory.as_str()) == self.data_directory,
            "root-provision stop receipt is outside the retained old inputs"
        );
        receipt.binds_authorized_checkpoint(&self.checkpoint)?;
        Ok(())
    }

    fn read_stop_receipt_bytes(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.data_directory.join(name);
        let name = c_string(name, &path)?;
        read_optional_bounded(
            &self.directory,
            &name,
            &path,
            ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES,
        )
    }

    /// Capture the exact managed socket identity before process-absence
    /// inspection. An absent pathname is synced before returning `None`, which
    /// closes a prior unlink/acknowledgement-loss window.
    pub(crate) fn retain_exact_control_socket(&self) -> Result<Option<RetainedExactControlSocket>> {
        self.assert_current()?;
        let socket = c_string("root-provision.sock", &self.data_directory)?;
        let Some(identity) = stat_at_optional(&self.directory, &socket)? else {
            self.directory
                .sync_all()
                .context("sync absent exact root-provision socket")?;
            return Ok(None);
        };
        verify_retained_socket_identity(&identity, &self.root_identity)?;
        Ok(Some(RetainedExactControlSocket { identity }))
    }

    /// Remove only the exact socket captured before the sealed absence sweep.
    /// A connectable peer, pathname replacement, unsafe metadata, or any
    /// uncertain connect result is preserved for the next full scan.
    pub(crate) fn remove_exact_stale_control_socket(
        &self,
        retained: RetainedExactControlSocket,
    ) -> Result<ExactControlSocketCleanup> {
        self.remove_exact_stale_control_socket_before_claim(retained, || {})
    }

    #[cfg(test)]
    pub(crate) fn remove_exact_stale_control_socket_with_hook(
        &self,
        retained: RetainedExactControlSocket,
        before_claim: impl FnOnce(),
    ) -> Result<ExactControlSocketCleanup> {
        self.remove_exact_stale_control_socket_before_claim(retained, before_claim)
    }

    fn remove_exact_stale_control_socket_before_claim(
        &self,
        retained: RetainedExactControlSocket,
        before_claim: impl FnOnce(),
    ) -> Result<ExactControlSocketCleanup> {
        self.assert_current()?;
        let socket_name = "root-provision.sock";
        let socket_path = self.data_directory.join(socket_name);
        let socket = c_string(socket_name, &socket_path)?;
        let quarantine_path = self
            .data_directory
            .join(ROOT_PROVISION_STOP_SOCKET_QUARANTINE);
        let quarantine = c_string(ROOT_PROVISION_STOP_SOCKET_QUARANTINE, &quarantine_path)?;

        if stat_at_optional(&self.directory, &quarantine)?.is_some() {
            return self.finish_claimed_control_socket(retained, &socket, &quarantine);
        }
        match nonblocking_unix_socket_state(&socket_path)? {
            UnixSocketState::ConnectableOrUnknown => {
                return Ok(ExactControlSocketCleanup::LiveOrChanged)
            }
            UnixSocketState::Absent => {
                self.directory
                    .sync_all()
                    .context("sync already-absent root-provision socket")?;
                return Ok(ExactControlSocketCleanup::AlreadyAbsent);
            }
            UnixSocketState::Refused => {}
        }
        let Some(current) = stat_at_optional(&self.directory, &socket)? else {
            self.directory
                .sync_all()
                .context("sync concurrently absent root-provision socket")?;
            return Ok(ExactControlSocketCleanup::AlreadyAbsent);
        };
        if current != retained.identity
            || verify_retained_socket_identity(&current, &self.root_identity).is_err()
        {
            return Ok(ExactControlSocketCleanup::LiveOrChanged);
        }
        before_claim();
        match rename_no_replace(&self.directory, &socket, &self.directory, &quarantine) {
            Ok(()) => {}
            Err(source)
                if source.kind() == io::ErrorKind::AlreadyExists
                    || source.raw_os_error() == Some(libc::EEXIST) =>
            {
                return Ok(ExactControlSocketCleanup::LiveOrChanged)
            }
            Err(source)
                if source.kind() == io::ErrorKind::NotFound
                    || source.raw_os_error() == Some(libc::ENOENT) =>
            {
                if stat_at_optional(&self.directory, &socket)?.is_some()
                    || stat_at_optional(&self.directory, &quarantine)?.is_some()
                {
                    return Ok(ExactControlSocketCleanup::LiveOrChanged);
                }
                self.directory
                    .sync_all()
                    .context("sync concurrently absent root-provision socket")?;
                return Ok(ExactControlSocketCleanup::AlreadyAbsent);
            }
            Err(source) => {
                return Err(source).context("atomically claim exact stale root-provision socket")
            }
        }
        self.directory
            .sync_all()
            .context("sync exact stale root-provision socket claim")?;
        self.finish_claimed_control_socket(retained, &socket, &quarantine)
    }

    fn finish_claimed_control_socket(
        &self,
        retained: RetainedExactControlSocket,
        socket: &CStr,
        quarantine: &CStr,
    ) -> Result<ExactControlSocketCleanup> {
        let Some(claimed) = stat_at_optional(&self.directory, quarantine)? else {
            if stat_at_optional(&self.directory, socket)?.is_none() {
                self.directory
                    .sync_all()
                    .context("sync absent claimed root-provision socket")?;
                return Ok(ExactControlSocketCleanup::AlreadyAbsent);
            }
            return Ok(ExactControlSocketCleanup::LiveOrChanged);
        };
        if verify_retained_socket_identity(&claimed, &self.root_identity).is_err()
            || !same_socket_after_rename(&retained.identity, &claimed)
        {
            self.restore_changed_socket_claim(socket, quarantine)?;
            return Ok(ExactControlSocketCleanup::LiveOrChanged);
        }
        if stat_at_optional(&self.directory, socket)?.is_some() {
            return Ok(ExactControlSocketCleanup::LiveOrChanged);
        }
        let quarantine_path = self
            .data_directory
            .join(ROOT_PROVISION_STOP_SOCKET_QUARANTINE);
        match nonblocking_unix_socket_state(&quarantine_path)? {
            UnixSocketState::ConnectableOrUnknown => {
                return Ok(ExactControlSocketCleanup::LiveOrChanged)
            }
            UnixSocketState::Absent => {
                if stat_at_optional(&self.directory, quarantine)?.is_some()
                    || stat_at_optional(&self.directory, socket)?.is_some()
                {
                    return Ok(ExactControlSocketCleanup::LiveOrChanged);
                }
                self.directory
                    .sync_all()
                    .context("sync concurrently absent claimed root-provision socket")?;
                return Ok(ExactControlSocketCleanup::AlreadyAbsent);
            }
            UnixSocketState::Refused => {}
        }
        let Some(final_claimed) = stat_at_optional(&self.directory, quarantine)? else {
            self.directory
                .sync_all()
                .context("sync concurrently absent claimed root-provision socket")?;
            return Ok(ExactControlSocketCleanup::AlreadyAbsent);
        };
        if verify_retained_socket_identity(&final_claimed, &self.root_identity).is_err()
            || !same_socket_after_rename(&retained.identity, &final_claimed)
        {
            self.restore_changed_socket_claim(socket, quarantine)?;
            return Ok(ExactControlSocketCleanup::LiveOrChanged);
        }
        unlink_at(&self.directory, quarantine)
            .context("unlink atomically claimed stale root-provision socket")?;
        self.directory
            .sync_all()
            .context("sync exact stale root-provision socket removal")?;
        anyhow::ensure!(
            stat_at_optional(&self.directory, quarantine)?.is_none(),
            "root-provision socket quarantine reappeared during exact cleanup"
        );
        Ok(ExactControlSocketCleanup::Removed)
    }

    /// A changed inode may have been atomically captured by the claim race.
    /// Never unlink it: restore it to the public basename only when that name
    /// is still empty, otherwise preserve both names as an inventory conflict.
    fn restore_changed_socket_claim(&self, socket: &CStr, quarantine: &CStr) -> Result<()> {
        match rename_no_replace(&self.directory, quarantine, &self.directory, socket) {
            Ok(()) => self
                .directory
                .sync_all()
                .context("sync restored changed root-provision socket"),
            Err(source)
                if source.kind() == io::ErrorKind::AlreadyExists
                    || source.raw_os_error() == Some(libc::EEXIST)
                    || source.kind() == io::ErrorKind::NotFound
                    || source.raw_os_error() == Some(libc::ENOENT) =>
            {
                Ok(())
            }
            Err(source) => Err(source).context("restore changed root-provision socket claim"),
        }
    }
}

fn same_socket_after_rename(before: &StableFsIdentity, after: &StableFsIdentity) -> bool {
    // rename may advance ctime, so object identity and every other socket
    // attribute remain exact while the mutable ctime fields are deliberately
    // excluded after the atomic claim.
    before.device == after.device
        && before.inode == after.inode
        && before.mode == after.mode
        && before.links == after.links
        && before.uid == after.uid
        && before.gid == after.gid
        && before.length == after.length
        && before.modified_seconds == after.modified_seconds
        && before.modified_nanoseconds == after.modified_nanoseconds
}

impl RetainedExactFile {
    fn assert_current(
        &self,
        current_directory: &File,
        root_identity: &StableFsIdentity,
        data_directory: &Path,
    ) -> Result<()> {
        let path = data_directory.join(self.name);
        verify_retained_regular_file(&self.file, &path, root_identity, Some(self.bytes.len()))?;
        anyhow::ensure!(
            stable_identity(&self.file, &path)? == self.identity,
            "retained authorized blockd input {} changed identity",
            path.display()
        );
        let name = c_string(self.name, &path)?;
        let mut current = open_at(
            current_directory,
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
        .with_context(|| format!("reopen exact authorized blockd input {}", path.display()))?;
        verify_retained_regular_file(&current, &path, root_identity, Some(self.bytes.len()))?;
        let before = stable_identity(&current, &path)?;
        let mut bytes = Vec::with_capacity(self.bytes.len());
        std::io::Read::by_ref(&mut current)
            .take(self.bytes.len() as u64 + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reread exact authorized blockd input {}", path.display()))?;
        let after = stable_identity(&current, &path)?;
        anyhow::ensure!(
            before == self.identity && after == self.identity && bytes == self.bytes,
            "authorized blockd input {} changed identity or bytes",
            path.display()
        );
        Ok(())
    }
}

impl PreparedAuthorizedBlockd {
    pub fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    pub fn identity_path(&self) -> &Path {
        &self.identity_path
    }

    pub fn authorized_serving_path(&self) -> &Path {
        &self.authorized_serving_path
    }

    pub fn launch_checkpoint_path(&self) -> &Path {
        &self.launch_checkpoint_path
    }

    pub fn checkpoint(&self) -> &AuthorizedBlockdCheckpoint {
        &self.checkpoint
    }

    pub(crate) fn retained_directory(&self) -> &File {
        &self._directory_lock
    }

    pub(crate) fn state_directory_path(&self) -> &Path {
        &self.state_directory
    }
}

/// Process composition values that are not part of Desired or Volume
/// Authority. Adapter options remain opaque and provider-neutral here.
#[derive(Debug, Clone)]
pub struct AuthorizedBlockdLaunchConfig {
    pub blockd_binary: PathBuf,
    pub metadata_store: AdapterSelection,
    pub object_store: AdapterSelection,
    pub max_staged_bytes: u64,
    pub max_staged_packs: usize,
    pub max_local_bytes: u64,
}

/// Exactly one Guest block frontend for the first Running slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedBlockFrontend {
    NbdUnix {
        socket: PathBuf,
    },
    VhostUser {
        socket: PathBuf,
        queues: usize,
        queue_size: u16,
    },
}

/// Build only the closed authorized-serving CLI. The scope, process token,
/// device token, control socket and frontend must be passed directly from one
/// fsynced `PrepareDevice` checkpoint. This does not start a child, create a
/// scope or claim that the frontend is ready.
pub fn authorized_blockd_command(
    config: &AuthorizedBlockdLaunchConfig,
    prepared: &PreparedAuthorizedBlockd,
    scope_id: &Id,
    process_identity_token: &RandomId128,
    device_ownership_token: &RandomId128,
    control_socket: &Path,
    frontend: &AuthorizedBlockFrontend,
) -> Result<Command> {
    anyhow::ensure!(
        config.blockd_binary.is_absolute(),
        "authorized blockd binary must be absolute"
    );
    anyhow::ensure!(
        config.metadata_store.name == "postgres",
        "authorized serving currently requires the frozen postgres authority adapter"
    );
    anyhow::ensure!(
        config.max_staged_bytes > 0 && config.max_staged_packs > 0 && config.max_local_bytes > 0,
        "authorized blockd resource limits must be positive"
    );
    validate_descendant(&prepared.state_directory, control_socket, "control socket")?;
    let frontend_socket = match frontend {
        AuthorizedBlockFrontend::NbdUnix { socket }
        | AuthorizedBlockFrontend::VhostUser { socket, .. } => socket,
    };
    validate_descendant(
        &prepared.state_directory,
        frontend_socket,
        "block frontend socket",
    )?;
    anyhow::ensure!(
        control_socket != frontend_socket,
        "authorized blockd control and frontend sockets must differ"
    );
    anyhow::ensure!(
        process_identity_token != device_ownership_token,
        "authorized blockd process and device ownership tokens must differ"
    );
    if let AuthorizedBlockFrontend::VhostUser {
        queues, queue_size, ..
    } = frontend
    {
        cats_blockd::frontend_contract::validate_authorized_vhost_shape(*queues, *queue_size)
            .context("authorized-serving vhost-user shape is outside the frozen contract")?;
    }

    let checkpoint = prepared.checkpoint();
    let attachment = &checkpoint.attachment;
    let mut command = Command::new(&config.blockd_binary);
    command
        .arg("--volume-id")
        .arg(attachment.identity.volume_id.as_str())
        .arg("--data-dir")
        .arg(prepared.data_directory())
        .arg("--attachment-id")
        .arg(attachment.identity.attachment_id.as_str())
        .arg("--authorized-serving-spec")
        .arg(prepared.authorized_serving_path())
        .arg("--runtime-scope-id")
        .arg(scope_id.as_str())
        .arg("--process-identity-token")
        .arg(process_identity_token.as_str())
        .arg("--device-ownership-token")
        .arg(device_ownership_token.as_str())
        .arg("--guest-device-serial")
        .arg(checkpoint.volume.guest_device.serial.as_str())
        .arg("--metadata-store-adapter")
        .arg(&config.metadata_store.name)
        .arg("--object-store-adapter")
        .arg(&config.object_store.name)
        .arg("--lease-ttl-ms")
        .arg(attachment.acquire_request.lease_duration_ms.to_string())
        .arg("--max-staged-bytes")
        .arg(config.max_staged_bytes.to_string())
        .arg("--max-staged-packs")
        .arg(config.max_staged_packs.to_string())
        .arg("--max-local-bytes")
        .arg(config.max_local_bytes.to_string())
        .arg("--durability")
        .arg(match attachment.durability {
            Durability::Strict => "strict",
            Durability::Relaxed => "relaxed",
        })
        .arg("--listen-control")
        .arg(control_socket);
    match frontend {
        AuthorizedBlockFrontend::NbdUnix { socket } => {
            command.arg("--listen-unix").arg(socket);
        }
        AuthorizedBlockFrontend::VhostUser {
            socket,
            queues,
            queue_size,
        } => {
            command
                .arg("--listen-vhost-user")
                .arg(socket)
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
    // Crash injection belongs only to explicit blockd tests. A production
    // Node never forwards an ambient value across this signed seam.
    command.env_remove("CATS_CRASH_POINT");
    Ok(command)
}

/// Accept a serving handshake only when it echoes the complete, independently
/// checkpointed process and device identities together with the exact
/// authorized attachment. The caller must additionally bind the response to
/// the inspected PID/socket/cgroup; this payload is not process authority by
/// itself.
pub fn authorized_blockd_status_is_bound(
    status: &DurabilityStatus,
    acquired: &AuthorizedBlockdCheckpoint,
    scope_id: &Id,
    process_identity_token: &RandomId128,
    device_ownership_token: &RandomId128,
) -> bool {
    let attachment = &acquired.attachment;
    process_identity_token != device_ownership_token
        && status.volume_id == attachment.identity.volume_id.as_str()
        && status.attachment_id == attachment.identity.attachment_id.as_str()
        && status.attachment_epoch == Some(attachment.identity.attachment_epoch)
        && status.acquire_origin.as_ref() == Some(&attachment.identity.acquire_origin)
        && status.node_id.as_ref() == Some(&attachment.identity.node_id)
        && status.placement_epoch == Some(attachment.identity.placement_epoch)
        && status.guest_io_enabled == Some(true)
        && status.size_bytes == Some(attachment.size_bytes)
        && status.scope_id.as_ref() == Some(scope_id)
        && status.process_identity_token.as_ref() == Some(process_identity_token)
        && status.device_ownership_token.as_ref() == Some(device_ownership_token)
        && status.guest_device_serial.as_ref() == Some(&acquired.volume.guest_device.serial)
        && status.control_only == Some(false)
        && status.remote_head.as_ref() == Some(&attachment.head)
        && status.mode
            == match attachment.durability {
                Durability::Strict => "strict",
                Durability::Relaxed => "relaxed",
            }
        && !status.fenced
}

fn validate_checkpoint_inputs(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    attachment: &AuthorizedServingAttachment,
) -> Result<()> {
    encode_desired_runtime_spec(desired).context("validate complete DesiredRuntimeSpec")?;
    validate_authorized_serving_attachment(attachment)
        .map_err(|error| anyhow::anyhow!("invalid authorized serving attachment: {error}"))?;
    anyhow::ensure!(
        desired.version == ContractVersion::V1 && desired.target == RuntimeTarget::Running,
        "authorized blockd supports only Runtime Reconciliation v1 Running"
    );
    anyhow::ensure!(
        desired.volumes.len() == 1 && desired.volumes.first() == Some(volume),
        "authorized blockd requires exactly the supplied root volume"
    );
    anyhow::ensure!(
        volume.disk_kind == DiskKind::Root
            && volume.access == VolumeAccess::ReadWriteOnce
            && volume.mount.is_none()
            && matches!(volume.disposition, VolumeDisposition::Retain),
        "authorized blockd first slice supports only an unmounted retained RWO root"
    );
    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &volume.acquire
    else {
        anyhow::bail!("authorized blockd first slice requires a Normal acquire");
    };
    let identity = &attachment.identity;
    let request = &attachment.acquire_request;
    anyhow::ensure!(
        volume.volume_id == identity.volume_id
            && volume.attachment_id == identity.attachment_id
            && volume.size_bytes == attachment.size_bytes
            && volume.durability == attachment.durability
            && desired.placement.node_id == identity.node_id
            && desired.placement.placement_epoch == identity.placement_epoch
            && request.transition_id == *transition_id
            && request.expected_unowned_epoch == *expected_unowned_epoch
            && request.desired_revision == desired.desired_revision
            && request.placement_epoch == desired.placement.placement_epoch,
        "Desired, root VolumeIntent and authorized grant do not form one exact lineage"
    );
    Ok(())
}

fn validate_adopted_checkpoint_inputs(
    desired: &DesiredRuntimeSpec,
    volume: &VolumeIntent,
    attachment: &AuthorizedServingAttachment,
) -> Result<()> {
    encode_desired_runtime_spec(desired).context("validate complete DesiredRuntimeSpec")?;
    validate_authorized_serving_attachment(attachment)
        .map_err(|error| anyhow::anyhow!("invalid authorized serving attachment: {error}"))?;
    anyhow::ensure!(
        desired.version == ContractVersion::V1
            && desired.target == RuntimeTarget::Running
            && desired.volumes.len() == 1
            && desired.volumes.first() == Some(volume)
            && volume.disk_kind == DiskKind::Root
            && volume.access == VolumeAccess::ReadWriteOnce
            && volume.mount.is_none()
            && matches!(volume.disposition, VolumeDisposition::Retain),
        "authorized blockd adoption requires one retained RWO Running root"
    );
    let VolumeAcquire::Normal {
        transition_id,
        expected_unowned_epoch,
    } = &volume.acquire
    else {
        anyhow::bail!("authorized blockd adoption requires a Normal acquire")
    };
    let identity = &attachment.identity;
    let request = &attachment.acquire_request;
    anyhow::ensure!(
        volume.volume_id == identity.volume_id
            && volume.attachment_id == identity.attachment_id
            && volume.size_bytes == attachment.size_bytes
            && volume.durability == attachment.durability
            && desired.placement.node_id == identity.node_id
            && desired.placement.placement_epoch == identity.placement_epoch
            && request.transition_id == *transition_id
            && request.expected_unowned_epoch == *expected_unowned_epoch
            && request.volume_id == volume.volume_id
            && request.attachment_id == volume.attachment_id
            && request.desired_revision <= desired.desired_revision
            && request.placement_epoch == desired.placement.placement_epoch,
        "current Desired and superseded authorized grant are not one adoptable lineage"
    );
    Ok(())
}

pub(crate) fn validate_authorized_blockd_checkpoint(
    checkpoint: &AuthorizedBlockdCheckpoint,
) -> Result<()> {
    anyhow::ensure!(
        checkpoint.version == ContractVersion::V1,
        "authorized blockd checkpoint has an unsupported version"
    );
    validate_checkpoint_inputs(
        &checkpoint.desired,
        &checkpoint.volume,
        &checkpoint.attachment,
    )
    .or_else(|_| {
        validate_adopted_checkpoint_inputs(
            &checkpoint.desired,
            &checkpoint.volume,
            &checkpoint.attachment,
        )
    })
}

fn directory_components(
    desired: &DesiredRuntimeSpec,
    identity: &AttachmentLineageIdentity,
) -> [String; 5] {
    [
        DATA_DIRECTORY.to_owned(),
        format!("cat-{}", desired.cat_id),
        format!("volume-{}", identity.volume_id),
        format!("attachment-{}", identity.attachment_id),
        format!("epoch-{}", identity.attachment_epoch.get()),
    ]
}

/// Deterministic physical path selected by the complete attachment lineage.
/// Inventory admission uses this same function when deciding whether a
/// durable directory left by an interrupted prepare is the exact effect it is
/// allowed to adopt.
pub(crate) fn authorized_blockd_data_directory(
    state_directory: &Path,
    desired: &DesiredRuntimeSpec,
    identity: &AttachmentLineageIdentity,
) -> PathBuf {
    directory_components(desired, identity)
        .into_iter()
        .fold(state_directory.to_path_buf(), |path, component| {
            path.join(component)
        })
}

fn bounded_json<T: Serialize>(value: &T, maximum: usize, label: &str) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).with_context(|| format!("encode {label}"))?;
    anyhow::ensure!(bytes.len() <= maximum, "{label} exceeds {maximum} bytes");
    Ok(bytes)
}

fn ensure_directory_at(parent: &File, name: &str, relative: &Path) -> Result<File> {
    let name_c = c_string(name, relative)?;
    // SAFETY: `parent` is a live directory descriptor and `name_c` remains
    // NUL-terminated for this call. mkdirat retains neither.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } == 0;
    if !created {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(source).with_context(|| format!("create {}", relative.display()));
        }
    } else {
        parent
            .sync_all()
            .with_context(|| format!("sync parent after creating {}", relative.display()))?;
    }
    let directory = open_at(
        parent,
        &name_c,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .with_context(|| format!("open {}", relative.display()))?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect {}", relative.display()))?;
    // SAFETY: geteuid takes no pointers and cannot fail.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o777 == 0o700,
        "authorized blockd directory {} has unsafe metadata",
        relative.display()
    );
    Ok(directory)
}

fn open_existing_directory_at(
    parent: &File,
    name: &str,
    relative: &Path,
    root_identity: &StableFsIdentity,
) -> Result<File> {
    let name = c_string(name, relative)?;
    let directory = open_at(
        parent,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .with_context(|| format!("open {}", relative.display()))?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect {}", relative.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == root_identity.uid
            && metadata.gid() == root_identity.gid
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "authorized blockd directory {} has unsafe metadata",
        relative.display()
    );
    Ok(directory)
}

fn lock_directory(directory: &File) -> io::Result<()> {
    // SAFETY: the descriptor is live and flock retains no Rust memory. The
    // lock remains held by the returned Prepared object.
    let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn persist_ordered_file(
    directory: &File,
    relative_directory: &Path,
    target_name: &str,
    temporary_name: &str,
    expected: &[u8],
    predecessors: &[&str],
    maximum: usize,
) -> Result<()> {
    let target_path = relative_directory.join(target_name);
    let temporary_path = relative_directory.join(temporary_name);
    let target_c = c_string(target_name, &target_path)?;
    let temporary_c = c_string(temporary_name, &temporary_path)?;

    if let Some(bytes) = read_optional_bounded(directory, &target_c, &target_path, maximum)? {
        anyhow::ensure!(
            bytes == expected,
            "{} conflicts with the exact authorized blockd input",
            target_path.display()
        );
        if let Some(temporary) =
            read_optional_bounded(directory, &temporary_c, &temporary_path, maximum)?
        {
            anyhow::ensure!(
                temporary == expected,
                "{} conflicts with the published authorized blockd input",
                temporary_path.display()
            );
            unlink_at(directory, &temporary_c)
                .with_context(|| format!("remove recovered {}", temporary_path.display()))?;
            directory
                .sync_all()
                .with_context(|| format!("sync {}", relative_directory.display()))?;
        }
        return Ok(());
    }

    let mut allowed = predecessors
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    allowed.push(temporary_name.to_owned());
    let entries = directory_entries(directory)
        .with_context(|| format!("enumerate {}", relative_directory.display()))?;
    let unexpected = entries
        .iter()
        .filter(|entry| !allowed.contains(entry))
        .cloned()
        .collect::<Vec<_>>();
    anyhow::ensure!(
        unexpected.is_empty(),
        "authorized blockd input {} is missing beside residue {:?}",
        target_path.display(),
        unexpected
    );
    for predecessor in predecessors {
        let predecessor_path = relative_directory.join(predecessor);
        let predecessor_c = c_string(predecessor, &predecessor_path)?;
        anyhow::ensure!(
            read_optional_bounded(
                directory,
                &predecessor_c,
                &predecessor_path,
                MAX_LAUNCH_CHECKPOINT_BYTES,
            )?
            .is_some(),
            "authorized blockd predecessor {} is missing",
            predecessor_path.display()
        );
    }

    if let Some(bytes) = read_optional_bounded(directory, &temporary_c, &temporary_path, maximum)? {
        anyhow::ensure!(
            bytes == expected,
            "{} conflicts with the exact authorized blockd input",
            temporary_path.display()
        );
    } else {
        let mut file = open_at(
            directory,
            &temporary_c,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .with_context(|| format!("create {}", temporary_path.display()))?;
        verify_regular_file(&file, &temporary_path, Some(0))?;
        file.write_all(expected)
            .with_context(|| format!("write {}", temporary_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary_path.display()))?;
        verify_regular_file(&file, &temporary_path, Some(expected.len() as u64))?;
    }
    #[cfg(test)]
    pause_authorized_publication_for_process_kill(target_name, "temp");

    anyhow::ensure!(
        read_optional_bounded(directory, &target_c, &target_path, maximum)?.is_none(),
        "authorized blockd input {} appeared before publish",
        target_path.display()
    );
    rename_at(directory, &temporary_c, directory, &target_c)
        .with_context(|| format!("publish {}", target_path.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("sync {}", relative_directory.display()))?;
    #[cfg(test)]
    pause_authorized_publication_for_process_kill(target_name, "target");
    let published = read_optional_bounded(directory, &target_c, &target_path, maximum)?
        .context("published authorized blockd input disappeared")?;
    anyhow::ensure!(
        published == expected,
        "published authorized blockd input changed"
    );
    Ok(())
}

#[cfg(test)]
fn pause_authorized_publication_for_process_kill(target_name: &str, phase: &str) {
    let Ok(requested) = std::env::var("CATS_AUTHORIZED_BLOCKD_KILL_POINT") else {
        return;
    };
    if requested != format!("{target_name}:{phase}") {
        return;
    }
    let marker = std::env::var("CATS_AUTHORIZED_BLOCKD_KILL_MARKER")
        .expect("authorized blockd kill probe marker path");
    std::fs::write(marker, requested.as_bytes()).expect("write authorized blockd kill marker");
    loop {
        std::thread::park_timeout(std::time::Duration::from_secs(60));
    }
}

fn persist_adopted_launch_file(
    directory: &File,
    relative_directory: &Path,
    current: &AuthorizedBlockdCheckpoint,
    current_bytes: &[u8],
) -> Result<AuthorizedBlockdCheckpoint> {
    let target_path = relative_directory.join(LAUNCH_CHECKPOINT_FILE);
    let temporary_path = relative_directory.join(LAUNCH_CHECKPOINT_TEMP);
    let target_c = c_string(LAUNCH_CHECKPOINT_FILE, &target_path)?;
    let temporary_c = c_string(LAUNCH_CHECKPOINT_TEMP, &temporary_path)?;
    let Some(existing_bytes) = read_optional_bounded(
        directory,
        &target_c,
        &target_path,
        MAX_LAUNCH_CHECKPOINT_BYTES,
    )?
    else {
        persist_ordered_file(
            directory,
            relative_directory,
            LAUNCH_CHECKPOINT_FILE,
            LAUNCH_CHECKPOINT_TEMP,
            current_bytes,
            &[IDENTITY_FILE, AUTHORIZED_SERVING_FILE],
            MAX_LAUNCH_CHECKPOINT_BYTES,
        )?;
        return Ok(current.clone());
    };

    let existing: AuthorizedBlockdCheckpoint = serde_json::from_slice(&existing_bytes)
        .context("decode existing authorized blockd launch checkpoint for adoption")?;
    anyhow::ensure!(
        serde_json::to_vec(&existing).context("re-encode adopted blockd checkpoint")?
            == existing_bytes,
        "existing authorized blockd launch checkpoint is not canonical"
    );
    validate_authorized_blockd_checkpoint(&existing)?;
    anyhow::ensure!(
        existing.attachment == current.attachment
            && existing.volume == current.volume
            && existing.desired.cat_id == current.desired.cat_id
            && existing.desired.placement.node_id == current.desired.placement.node_id
            && existing.desired.placement.placement_epoch
                == current.desired.placement.placement_epoch
            && existing.desired.desired_revision <= current.desired.desired_revision,
        "existing authorized blockd launch checkpoint is not compatible with adoption"
    );
    if let Some(temporary) = read_optional_bounded(
        directory,
        &temporary_c,
        &temporary_path,
        MAX_LAUNCH_CHECKPOINT_BYTES,
    )? {
        anyhow::ensure!(
            temporary == existing_bytes || temporary == current_bytes,
            "{} conflicts with adopted blockd provenance",
            temporary_path.display()
        );
        unlink_at(directory, &temporary_c)
            .with_context(|| format!("remove recovered {}", temporary_path.display()))?;
        directory
            .sync_all()
            .with_context(|| format!("sync {}", relative_directory.display()))?;
    }
    Ok(existing)
}

fn read_optional_bounded(
    directory: &File,
    name: &CStr,
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let mut file = match open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    verify_regular_file(&file, path, None)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    anyhow::ensure!(
        metadata.len() <= maximum as u64,
        "{} exceeds its bounded size",
        path.display()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= maximum,
        "{} exceeds its bounded size",
        path.display()
    );
    Ok(Some(bytes))
}

fn read_required_canonical<T>(
    directory: &File,
    relative_directory: &Path,
    file_name: &str,
    maximum: usize,
    label: &str,
    root_identity: &StableFsIdentity,
) -> Result<(T, RetainedExactFile)>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let path = relative_directory.join(file_name);
    let name = c_string(file_name, &path)?;
    let mut file = open_at(
        directory,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .with_context(|| format!("open exact {label} at {}", path.display()))?;
    verify_retained_regular_file(&file, &path, root_identity, None)?;
    let before = stable_identity(&file, &path)?;
    anyhow::ensure!(
        before.length <= maximum as u64,
        "exact {label} exceeds its bounded size"
    );
    let mut bytes = Vec::with_capacity((before.length as usize).min(maximum));
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read exact {label}"))?;
    anyhow::ensure!(bytes.len() <= maximum, "exact {label} exceeds its bound");
    let after = stable_identity(&file, &path)?;
    anyhow::ensure!(before == after, "exact {label} changed while read");
    let value = serde_json::from_slice(&bytes).with_context(|| format!("decode exact {label}"))?;
    anyhow::ensure!(
        serde_json::to_vec(&value).with_context(|| format!("re-encode exact {label}"))? == bytes,
        "exact {label} is not canonical"
    );
    let name = match file_name {
        IDENTITY_FILE => IDENTITY_FILE,
        AUTHORIZED_SERVING_FILE => AUTHORIZED_SERVING_FILE,
        LAUNCH_CHECKPOINT_FILE => LAUNCH_CHECKPOINT_FILE,
        _ => anyhow::bail!("retained exact input has an unsupported name"),
    };
    Ok((
        value,
        RetainedExactFile {
            name,
            file,
            identity: after,
            bytes,
        },
    ))
}

fn verify_retained_state_root(file: &File, path: &Path) -> Result<StableFsIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect retained Node state root {}", path.display()))?;
    // SAFETY: geteuid takes no pointers and cannot fail.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o7022 == 0,
        "retained Node state root {} has unsafe owner or mode",
        path.display()
    );
    stable_identity(file, path)
}

fn verify_retained_regular_file(
    file: &File,
    path: &Path,
    root_identity: &StableFsIdentity,
    expected_len: Option<usize>,
) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect retained input {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == root_identity.uid
            && metadata.gid() == root_identity.gid
            && metadata.permissions().mode() & 0o7777 == 0o600
            && expected_len.is_none_or(|len| metadata.len() == len as u64),
        "retained input {} has unsafe identity, owner, or mode",
        path.display()
    );
    Ok(())
}

fn stable_identity(file: &File, path: &Path) -> Result<StableFsIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect stable filesystem identity {}", path.display()))?;
    anyhow::ensure!(metadata.ino() > 0, "{} has no stable inode", path.display());
    Ok(StableFsIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn stat_at_optional(directory: &File, name: &CStr) -> Result<Option<StableFsIdentity>> {
    // SAFETY: all-zero is a valid initial stat buffer and fstatat writes it
    // only for this call. `directory` and `name` remain live throughout.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `directory`, `name`, and the writable stat buffer remain live
    // for this call; fstatat retains none of them.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &raw mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(source).context("inspect exact root-provision socket basename");
    }
    Ok(Some(StableFsIdentity {
        device: raw_stat_u64(metadata.st_dev)
            .context("root-provision socket has invalid device identity")?,
        inode: metadata.st_ino,
        mode: raw_mode_to_u32(metadata.st_mode),
        links: raw_stat_u64(metadata.st_nlink)
            .context("root-provision socket has invalid link count")?,
        uid: metadata.st_uid,
        gid: metadata.st_gid,
        length: raw_stat_u64(metadata.st_size)
            .context("root-provision socket has negative length")?,
        modified_seconds: metadata.st_mtime,
        modified_nanoseconds: metadata.st_mtime_nsec,
        changed_seconds: metadata.st_ctime,
        changed_nanoseconds: metadata.st_ctime_nsec,
    }))
}

fn verify_retained_socket_identity(
    identity: &StableFsIdentity,
    root_identity: &StableFsIdentity,
) -> Result<()> {
    anyhow::ensure!(
        identity.mode & STAT_FILE_TYPE_MASK == STAT_SOCKET_FILE_TYPE
            && identity.links == 1
            && identity.uid == root_identity.uid
            && identity.gid == root_identity.gid
            && identity.mode & 0o7777 == 0o700,
        "root-provision socket has unsafe type, identity, owner, or mode"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn raw_mode_to_u32(mode: libc::mode_t) -> u32 {
    mode
}

#[cfg(not(target_os = "linux"))]
fn raw_mode_to_u32(mode: libc::mode_t) -> u32 {
    u32::from(mode)
}

fn raw_stat_u64<T>(value: T) -> Option<u64>
where
    u64: TryFrom<T>,
{
    u64::try_from(value).ok()
}

enum UnixSocketState {
    Refused,
    Absent,
    ConnectableOrUnknown,
}

fn nonblocking_unix_socket_state(path: &Path) -> Result<UnixSocketState> {
    use std::mem::offset_of;
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    // SAFETY: zero is a valid initial sockaddr_un representation; all used
    // fields and bytes are initialized below before connect.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() < address.sun_path.len() && !bytes.contains(&0),
        "root-provision socket path is not connectable"
    );
    let address_length = offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    let socket_type = libc::SOCK_STREAM;
    #[cfg(target_os = "linux")]
    let socket_type = socket_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    // SAFETY: socket returns a fresh descriptor and retains no Rust memory.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if descriptor < 0 {
        return Ok(UnixSocketState::ConnectableOrUnknown);
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: descriptor is live; fcntl consumes and returns only integer
        // descriptor/status flags.
        let status = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        // SAFETY: descriptor is still owned and fcntl retains no Rust memory.
        let set_nonblocking =
            unsafe { libc::fcntl(descriptor, libc::F_SETFL, status | libc::O_NONBLOCK) } == 0;
        // SAFETY: descriptor is still owned and fcntl retains no Rust memory.
        let set_close_on_exec =
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } == 0;
        let nonblocking = status >= 0 && set_nonblocking && set_close_on_exec;
        if !nonblocking {
            // SAFETY: this function still owns descriptor.
            unsafe { libc::close(descriptor) };
            return Ok(UnixSocketState::ConnectableOrUnknown);
        }
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        let Ok(length) = u8::try_from(address_length) else {
            // SAFETY: this function still owns descriptor.
            unsafe { libc::close(descriptor) };
            return Ok(UnixSocketState::ConnectableOrUnknown);
        };
        address.sun_len = length;
    }
    for (target, source) in address.sun_path.iter_mut().zip(bytes.iter().copied()) {
        *target = source as libc::c_char;
    }
    // SAFETY: descriptor and address are initialized for this call and retain
    // no borrowed Rust memory.
    let connected = unsafe {
        libc::connect(
            descriptor,
            (&raw const address).cast::<libc::sockaddr>(),
            address_length as libc::socklen_t,
        )
    };
    let error = (connected != 0).then(io::Error::last_os_error);
    // SAFETY: this function owns descriptor exactly once.
    unsafe { libc::close(descriptor) };
    Ok(match error.and_then(|error| error.raw_os_error()) {
        None => UnixSocketState::ConnectableOrUnknown,
        Some(libc::ECONNREFUSED) => UnixSocketState::Refused,
        Some(libc::ENOENT) => UnixSocketState::Absent,
        Some(_) => UnixSocketState::ConnectableOrUnknown,
    })
}

fn verify_regular_file(file: &File, path: &Path, expected_len: Option<u64>) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    // SAFETY: geteuid takes no pointers and cannot fail.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == euid
            && metadata.permissions().mode() & 0o7777 == 0o600
            && expected_len.is_none_or(|len| metadata.len() == len),
        "authorized blockd file {} has unsafe metadata",
        path.display()
    );
    Ok(())
}

fn directory_entries(directory: &File) -> io::Result<Vec<String>> {
    let mut stream = DirectoryStream::open(directory)?;
    let mut entries = Vec::new();
    while let Some(bytes) = stream.next()? {
        let name = std::str::from_utf8(&bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 directory entry"))?;
        entries.push(name.to_owned());
    }
    entries.sort();
    Ok(entries)
}

struct DirectoryStream(*mut libc::DIR);

impl DirectoryStream {
    fn open(directory: &File) -> io::Result<Self> {
        // SAFETY: fcntl duplicates the live descriptor and retains no Rust
        // memory. fdopendir consumes the duplicate on success.
        let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: duplicate is a fresh owned directory descriptor.
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let source = io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not consume duplicate.
            unsafe { libc::close(duplicate) };
            return Err(source);
        }
        Ok(Self(stream))
    }

    fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            set_errno(0);
            // SAFETY: the DIR pointer is exclusively owned by this value.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = errno();
                return if error == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::from_raw_os_error(error))
                };
            }
            // SAFETY: readdir returned a live dirent and the name is copied
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

fn c_string(value: &str, path: &Path) -> Result<CString> {
    CString::new(value).with_context(|| format!("{} contains NUL", path.display()))
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        // SAFETY: directory and name remain live for this call. A successful
        // descriptor is transferred exactly once into File.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
        if descriptor >= 0 {
            // SAFETY: openat returned one new owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn rename_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both directory descriptors and names remain live for the
        // call; renameat retains none of them.
        let result = unsafe {
            libc::renameat(
                old_directory.as_raw_fd(),
                old_name.as_ptr(),
                new_directory.as_raw_fd(),
                new_name.as_ptr(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn unlink_at(directory: &File, name: &CStr) -> io::Result<()> {
    loop {
        // SAFETY: directory and name remain live; unlinkat retains neither.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn validate_descendant(root: &Path, candidate: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(candidate.is_absolute(), "{label} must be absolute");
    let relative = candidate
        .strip_prefix(root)
        .with_context(|| format!("{label} must be under the retained Node state directory"))?;
    anyhow::ensure!(
        relative.components().next().is_some()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "{label} must be a strict descriptor-derived descendant"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

    use cats_api::runtime_reconciliation::{
        spec_digest, AcquireOrigin, AsciiText, AssignedKind, AssignedPlacement, Epoch, FenceEpoch,
        Generation, GuestDeviceIdentity, HostPath, Id, Ipv4Address, IsolatedIpv4Kind,
        LastVolumeTransition, MacAddress, NetworkConfig, NodeBootId, NormalAcquireRequest,
        NormalAcquireResult, RandomId128, RemoteHead, Revision, RuntimeConfig, RuntimeTransition,
        Sequence, Sha256Digest, UnixMillis, VolumeAdminState, WireU64,
    };
    use cats_storage::authority::AttachmentLineageIdentity;
    use cats_storage::AdapterConfig;

    use super::super::root_provision_process::RootProvisionBlockdHandshake;
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).unwrap()
    }

    fn empty_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        }
    }

    fn provisioned_head() -> RemoteHead {
        RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([9; 32])),
            root_object_id: Some(AsciiText::new("roots/root-1").unwrap()),
        }
    }

    fn fixture() -> (
        DesiredRuntimeSpec,
        VolumeIntent,
        AuthorizedServingAttachment,
    ) {
        let transition_id = random(1);
        let desired_revision = Revision::new(11).unwrap();
        let placement_epoch = Epoch::new(3).unwrap();
        let expected_unowned_epoch = FenceEpoch::new(7).unwrap();
        let resulting_epoch = FenceEpoch::new(8).unwrap();
        let volume = VolumeIntent {
            volume_intent_id: id("root-intent"),
            disk_id: id("root-disk"),
            volume_id: id("volume-1"),
            attachment_id: id("attachment-1"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-root-1"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: transition_id.clone(),
                expected_unowned_epoch,
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        };
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: id("workspace-1"),
            cat_id: id("cat-1"),
            desired_revision,
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: id("node-1"),
                placement_epoch,
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("network-1"),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: vec![volume.clone()],
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        let acquire_request = NormalAcquireRequest {
            volume_id: volume.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            expected_unowned_epoch,
            desired_revision,
            placement_epoch,
            lease_duration_ms: 5_000,
        };
        let acquire_result = NormalAcquireResult {
            volume_id: volume.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            resulting_epoch,
            resulting_head: empty_head(),
            lease_expires_at: UnixMillis::new(20_000).unwrap(),
        };
        let attachment = AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: resulting_epoch,
                acquire_origin: AcquireOrigin::Normal { transition_id },
                node_id: desired.placement.node_id.clone(),
                placement_epoch,
            },
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            // Root provision may have advanced the head after acquire.
            head: provisioned_head(),
            lease_expires_at: acquire_result.lease_expires_at,
            acquire_request,
            acquire_result,
        };
        (desired, volume, attachment)
    }

    fn final_directory(root: &Path) -> PathBuf {
        root.join("data")
            .join("cat-cat-1")
            .join("volume-volume-1")
            .join("attachment-attachment-1")
            .join("epoch-8")
    }

    fn create_final_directory(root: &Path) -> PathBuf {
        let path = final_directory(root);
        std::fs::create_dir_all(&path).unwrap();
        let mut current = root.to_path_buf();
        for component in [
            "data",
            "cat-cat-1",
            "volume-volume-1",
            "attachment-attachment-1",
            "epoch-8",
        ] {
            current.push(component);
            std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn launch_config() -> AuthorizedBlockdLaunchConfig {
        AuthorizedBlockdLaunchConfig {
            blockd_binary: "/opt/cats/bin/cats-blockd".into(),
            metadata_store: AdapterSelection::new(
                "postgres",
                AdapterConfig::from_pairs([
                    ("url-env", "CATS_TEST_POSTGRES_URL"),
                    ("connect-timeout-ms", "500"),
                ])
                .unwrap(),
            ),
            object_store: AdapterSelection::new(
                "file",
                AdapterConfig::from_pairs([("root", "/srv/cats/objects")]).unwrap(),
            ),
            max_staged_bytes: 101,
            max_staged_packs: 102,
            max_local_bytes: 103,
        }
    }

    fn maximally_escaped_host_path(length: usize) -> HostPath {
        assert!(length >= 2);
        let mut path = String::from("/");
        while path.len() < length {
            path.push(if path.len() % 2 == 0 { '\\' } else { '"' });
        }
        HostPath::new(path).unwrap()
    }

    #[test]
    fn maximum_physical_identity_receipt_stays_within_the_closed_scan_budget() {
        let (_, _, attachment) = fixture();
        let authority = VolumeRecord {
            volume_id: attachment.identity.volume_id.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            admin_state: VolumeAdminState::Active,
            head: attachment.head.clone(),
            lease_owner: Some(attachment.identity.attachment_id.clone()),
            lease_epoch: attachment.identity.attachment_epoch,
            lease_expires_at: Some(attachment.lease_expires_at),
            last_transition: Some(LastVolumeTransition::NormalAcquire {
                request: attachment.acquire_request.clone(),
                result: attachment.acquire_result.clone(),
            }),
        };
        let executable_path = maximally_escaped_host_path(4096);
        let cgroup_path = maximally_escaped_host_path(4096);
        let suffix = "/root-provision.sock";
        let data_directory = maximally_escaped_host_path(4096 - suffix.len());
        let control_socket_path =
            HostPath::new(format!("{}{suffix}", data_directory.as_str())).unwrap();
        let process_id = 4242;
        let process_identity_token = random(4);
        let process = RootProvisionProcessEvidence {
            process_id,
            unit_main_process_id: process_id,
            process_start_time_ticks: WireU64::new(u64::MAX / 2).unwrap(),
            executable_path,
            scope_id: id(&"s".repeat(128)),
            cgroup_path,
            cgroup_process_ids: vec![process_id],
            control_socket_path,
            data_directory,
            ownership_token: process_identity_token.clone(),
            handshake: RootProvisionBlockdHandshake {
                peer_process_id: process_id,
                identity: attachment.identity,
                size_bytes: attachment.size_bytes,
                durability: attachment.durability,
                remote_head: attachment.head,
                process_identity_token,
                control_only: true,
                guest_io_enabled: false,
            },
        };
        // SAFETY CONTRACT TEST: these are the exact fields serialized by the
        // private constructor after it has descriptor-retained the socket.
        let receipt = RootProvisionStopReceipt {
            version: ContractVersion::V1,
            checkpoint_content_digest: Sha256Digest::from_bytes([7; 32]),
            authorized_checkpoint_content_digest: Sha256Digest::from_bytes([8; 32]),
            authority,
            process,
            socket: StableFsIdentity {
                device: u64::MAX,
                inode: u64::MAX,
                mode: STAT_SOCKET_FILE_TYPE | 0o700,
                links: 1,
                // Metadata ownership is checked against the retained state
                // root before these values are admitted to a real receipt;
                // the codec bound itself is independent of these scalars.
                uid: 0,
                gid: 0,
                length: 0,
                modified_seconds: i64::MAX,
                modified_nanoseconds: 999_999_999,
                changed_seconds: i64::MAX,
                changed_nanoseconds: 999_999_999,
            },
            admission: RootProvisionRetirementAdmission {
                node_boot_id: NodeBootId::new("11111111111111111111111111111111").unwrap(),
                agent_instance_id: random(5),
                agent_session_epoch: Epoch::new(i64::MAX as u64).unwrap(),
                inventory_epoch: Epoch::new(i64::MAX as u64).unwrap(),
                inventory_digest: Sha256Digest::from_bytes([9; 32]),
                inventory_read_position: Sequence::new(i64::MAX as u64).unwrap(),
            },
        };
        let encoded = encode_root_provision_stop_receipt(&receipt).unwrap();
        assert!(
            encoded.len() > 32 * 1024,
            "max-path probe was not calibrated: {} bytes",
            encoded.len()
        );
        assert!(encoded.len() <= ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES);
        assert!(
            encoded.len() * 1024 <= 48 * 1024 * 1024,
            "1,024 maximum-path receipts exceed the closed scan budget: {} bytes each",
            encoded.len()
        );
        assert_eq!(
            decode_root_provision_stop_receipt(&encoded).unwrap(),
            receipt
        );
    }

    fn argv(command: &Command) -> Vec<OsString> {
        command.get_args().map(ToOwned::to_owned).collect()
    }

    fn serving_status(
        acquired: &AuthorizedBlockdCheckpoint,
        scope_id: &Id,
        process_identity_token: &RandomId128,
        device_ownership_token: &RandomId128,
    ) -> DurabilityStatus {
        let attachment = &acquired.attachment;
        DurabilityStatus {
            volume_id: attachment.identity.volume_id.to_string(),
            attachment_id: attachment.identity.attachment_id.to_string(),
            attachment_epoch: Some(attachment.identity.attachment_epoch),
            acquire_origin: Some(attachment.identity.acquire_origin.clone()),
            node_id: Some(attachment.identity.node_id.clone()),
            placement_epoch: Some(attachment.identity.placement_epoch),
            guest_io_enabled: Some(true),
            size_bytes: Some(attachment.size_bytes),
            scope_id: Some(scope_id.clone()),
            process_identity_token: Some(process_identity_token.clone()),
            device_ownership_token: Some(device_ownership_token.clone()),
            guest_device_serial: Some(acquired.volume.guest_device.serial.clone()),
            control_only: Some(false),
            remote_head: Some(attachment.head.clone()),
            mode: match attachment.durability {
                Durability::Strict => "strict".into(),
                Durability::Relaxed => "relaxed".into(),
            },
            local_durable_generation: 1,
            remote_durable_generation: 1,
            unpublished_generations: 0,
            unpublished_bytes: 0,
            oldest_unpublished_age_ms: 0,
            max_unpublished_generations: 1,
            max_unpublished_bytes: 1,
            local_allocated_bytes: 0,
            local_accounted_bytes: 0,
            max_local_bytes: 4 * 1024 * 1024,
            evicted_cache_chunks: 0,
            backpressured: false,
            fenced: false,
            last_publish_error: None,
        }
    }

    #[test]
    fn complete_desired_grant_and_network_are_checkpointed_before_closed_cli_is_built() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()))
                .prepare(&desired, &volume, &attachment)
                .unwrap();

        assert_eq!(prepared.data_directory(), final_directory(temp.path()));
        assert_eq!(
            serde_json::from_slice::<AttachmentLineageIdentity>(
                &std::fs::read(prepared.identity_path()).unwrap()
            )
            .unwrap(),
            attachment.identity
        );
        assert_eq!(
            serde_json::from_slice::<AuthorizedServingAttachment>(
                &std::fs::read(prepared.authorized_serving_path()).unwrap()
            )
            .unwrap(),
            attachment
        );
        let stored: AuthorizedBlockdCheckpoint =
            serde_json::from_slice(&std::fs::read(prepared.launch_checkpoint_path()).unwrap())
                .unwrap();
        assert_eq!(
            stored.desired.runtime.network_config,
            desired.runtime.network_config
        );
        assert_eq!(stored, *prepared.checkpoint());

        let control = temp.path().join("control-sockets/cat-1-blockd.sock");
        let frontend = temp.path().join("vhost-user/cat-1-root.sock");
        let command = authorized_blockd_command(
            &launch_config(),
            &prepared,
            &id("cats-cat-1-root.scope"),
            &random(2),
            &random(3),
            &control,
            &AuthorizedBlockFrontend::VhostUser {
                socket: frontend.clone(),
                queues: 2,
                queue_size: 256,
            },
        )
        .unwrap();
        assert_eq!(command.get_program(), "/opt/cats/bin/cats-blockd");
        let arguments = argv(&command);
        for required in [
            OsString::from("--authorized-serving-spec"),
            prepared.authorized_serving_path().as_os_str().to_owned(),
            OsString::from("--listen-control"),
            control.into_os_string(),
            OsString::from("--runtime-scope-id"),
            OsString::from("cats-cat-1-root.scope"),
            OsString::from("--process-identity-token"),
            OsString::from("00000000000000000000000000000002"),
            OsString::from("--device-ownership-token"),
            OsString::from("00000000000000000000000000000003"),
            OsString::from("--guest-device-serial"),
            OsString::from("cats-root-1"),
            OsString::from("--listen-vhost-user"),
            frontend.into_os_string(),
            OsString::from("--lease-ttl-ms"),
            OsString::from("5000"),
            OsString::from("--durability"),
            OsString::from("strict"),
        ] {
            assert!(arguments.contains(&required), "missing argv {required:?}");
        }
        for forbidden in [
            "--create-volume-size",
            "--seed-image-id",
            "--collect-garbage",
            "--attachment-epoch",
            "--control-only",
            "--listen-tcp",
        ] {
            assert!(!arguments.contains(&OsString::from(forbidden)));
        }
        assert!(command
            .get_envs()
            .any(|(name, value)| name == "CATS_CRASH_POINT" && value.is_none()));
    }

    #[test]
    fn authorized_serving_command_rejects_every_frozen_vhost_bound_before_building_argv() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()))
                .prepare(&desired, &volume, &attachment)
                .unwrap();
        let control = temp.path().join("control.sock");
        let frontend = temp.path().join("vhost.sock");
        for (queues, queue_size) in [(0, 256), (65, 256), (1, 0), (1, 1), (1, 3), (1, 32_769)] {
            let result = authorized_blockd_command(
                &launch_config(),
                &prepared,
                &id("cats-cat-1-root.scope"),
                &random(2),
                &random(3),
                &control,
                &AuthorizedBlockFrontend::VhostUser {
                    socket: frontend.clone(),
                    queues,
                    queue_size,
                },
            );
            assert!(
                result.is_err(),
                "accepted out-of-contract vhost shape {queues}/{queue_size}"
            );
        }
        for (queues, queue_size) in [(1, 2), (64, 32_768)] {
            authorized_blockd_command(
                &launch_config(),
                &prepared,
                &id("cats-cat-1-root.scope"),
                &random(2),
                &random(3),
                &control,
                &AuthorizedBlockFrontend::VhostUser {
                    socket: frontend.clone(),
                    queues,
                    queue_size,
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn kernel_and_vhost_serving_commands_bind_the_same_checkpoint_serial() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()))
                .prepare(&desired, &volume, &attachment)
                .unwrap();
        let control = temp.path().join("control.sock");
        let frontends = [
            AuthorizedBlockFrontend::NbdUnix {
                socket: temp.path().join("nbd.sock"),
            },
            AuthorizedBlockFrontend::VhostUser {
                socket: temp.path().join("vhost.sock"),
                queues: 2,
                queue_size: 256,
            },
        ];
        for frontend in &frontends {
            let arguments = argv(
                &authorized_blockd_command(
                    &launch_config(),
                    &prepared,
                    &id("cats-cat-1-root.scope"),
                    &random(2),
                    &random(3),
                    &control,
                    frontend,
                )
                .unwrap(),
            );
            let serial_index = arguments
                .iter()
                .position(|argument| argument == "--guest-device-serial")
                .expect("Guest serial flag");
            assert_eq!(
                arguments.get(serial_index + 1),
                Some(&OsString::from(
                    prepared.checkpoint().volume.guest_device.serial.as_str()
                ))
            );
        }
    }

    #[test]
    fn serving_handshake_requires_both_exact_independent_tokens() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()))
                .prepare(&desired, &volume, &attachment)
                .unwrap();
        let scope_id = id("cats-cat-1-root.scope");
        let process_identity_token = random(2);
        let device_ownership_token = random(3);
        let status = serving_status(
            prepared.checkpoint(),
            &scope_id,
            &process_identity_token,
            &device_ownership_token,
        );
        assert!(authorized_blockd_status_is_bound(
            &status,
            prepared.checkpoint(),
            &scope_id,
            &process_identity_token,
            &device_ownership_token,
        ));

        let mut missing_device = status.clone();
        missing_device.device_ownership_token = None;
        assert!(!authorized_blockd_status_is_bound(
            &missing_device,
            prepared.checkpoint(),
            &scope_id,
            &process_identity_token,
            &device_ownership_token,
        ));

        let mut wrong_device = status.clone();
        wrong_device.device_ownership_token = Some(random(4));
        assert!(!authorized_blockd_status_is_bound(
            &wrong_device,
            prepared.checkpoint(),
            &scope_id,
            &process_identity_token,
            &device_ownership_token,
        ));
        let mut missing_serial = status.clone();
        missing_serial.guest_device_serial = None;
        assert!(!authorized_blockd_status_is_bound(
            &missing_serial,
            prepared.checkpoint(),
            &scope_id,
            &process_identity_token,
            &device_ownership_token,
        ));
        let mut wrong_serial = status.clone();
        wrong_serial.guest_device_serial = Some(id("cats-wrong"));
        assert!(!authorized_blockd_status_is_bound(
            &wrong_serial,
            prepared.checkpoint(),
            &scope_id,
            &process_identity_token,
            &device_ownership_token,
        ));
        assert!(!authorized_blockd_status_is_bound(
            &status,
            prepared.checkpoint(),
            &scope_id,
            &process_identity_token,
            &process_identity_token,
        ));
    }

    #[test]
    fn exact_replay_keeps_inodes_but_a_changed_grant_cannot_replace_any_file() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let store =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()));
        let prepared = store.prepare(&desired, &volume, &attachment).unwrap();
        let paths = [
            prepared.identity_path().to_path_buf(),
            prepared.authorized_serving_path().to_path_buf(),
            prepared.launch_checkpoint_path().to_path_buf(),
        ];
        let before = paths
            .iter()
            .map(|path| {
                (
                    std::fs::metadata(path).unwrap().ino(),
                    std::fs::read(path).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        drop(prepared);

        drop(store.prepare(&desired, &volume, &attachment).unwrap());
        for (path, expected) in paths.iter().zip(&before) {
            assert_eq!(std::fs::metadata(path).unwrap().ino(), expected.0);
            assert_eq!(std::fs::read(path).unwrap(), expected.1);
        }

        let mut changed_volume = volume.clone();
        changed_volume.size_bytes += 4 * 1024 * 1024;
        let mut changed_desired = desired.clone();
        changed_desired.volumes = vec![changed_volume.clone()];
        changed_desired.spec_digest = spec_digest(&changed_desired).unwrap();
        let mut changed_attachment = attachment.clone();
        changed_attachment.size_bytes = changed_volume.size_bytes;
        let error = store
            .prepare(&changed_desired, &changed_volume, &changed_attachment)
            .unwrap_err();
        assert!(error.to_string().contains("conflicts"));
        for (path, expected) in paths.iter().zip(&before) {
            assert_eq!(std::fs::metadata(path).unwrap().ino(), expected.0);
            assert_eq!(std::fs::read(path).unwrap(), expected.1);
        }
    }

    #[test]
    fn identity_temp_is_recovered_exactly_after_response_loss() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let directory = create_final_directory(temp.path());
        let temporary = directory.join(IDENTITY_TEMP);
        std::fs::write(
            &temporary,
            serde_json::to_vec(&attachment.identity).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();

        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()))
                .prepare(&desired, &volume, &attachment)
                .unwrap();
        assert!(!temporary.exists());
        assert!(prepared.identity_path().exists());
        assert!(prepared.authorized_serving_path().exists());
        assert!(prepared.launch_checkpoint_path().exists());
    }

    #[test]
    fn unknown_residue_or_symlink_before_identity_is_never_adopted() {
        let (desired, volume, attachment) = fixture();

        let residue_root = tempfile::tempdir().unwrap();
        let residue_directory = create_final_directory(residue_root.path());
        std::fs::write(residue_directory.join("cache.bin"), b"unknown").unwrap();
        let residue_store = AuthorizedBlockdStore::new(StateDirectory::unanchored(
            residue_root.path().to_path_buf(),
        ));
        let error = residue_store
            .prepare(&desired, &volume, &attachment)
            .unwrap_err();
        assert!(error.to_string().contains("residue"));
        assert!(!residue_directory.join(IDENTITY_FILE).exists());

        let symlink_root = tempfile::tempdir().unwrap();
        let symlink_directory = create_final_directory(symlink_root.path());
        let external = symlink_root.path().join("external");
        std::fs::write(&external, serde_json::to_vec(&attachment.identity).unwrap()).unwrap();
        symlink(&external, symlink_directory.join(IDENTITY_FILE)).unwrap();
        let symlink_store = AuthorizedBlockdStore::new(StateDirectory::unanchored(
            symlink_root.path().to_path_buf(),
        ));
        assert!(symlink_store
            .prepare(&desired, &volume, &attachment)
            .is_err());
        assert_eq!(
            std::fs::read(external).unwrap(),
            serde_json::to_vec(&attachment.identity).unwrap()
        );
        assert!(
            std::fs::symlink_metadata(symlink_directory.join(IDENTITY_FILE))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn unsupported_lifecycle_or_non_state_socket_fails_before_process_construction() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let mut cold = desired.clone();
        cold.target = RuntimeTarget::Cold;
        cold.spec_digest = spec_digest(&cold).unwrap();
        let store =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()));
        assert!(store.prepare(&cold, &volume, &attachment).is_err());
        assert!(!temp.path().join(DATA_DIRECTORY).exists());

        let prepared = store.prepare(&desired, &volume, &attachment).unwrap();
        let result = authorized_blockd_command(
            &launch_config(),
            &prepared,
            &id("cats-cat-1-root.scope"),
            &random(2),
            &random(3),
            Path::new("/tmp/not-state-derived-control.sock"),
            &AuthorizedBlockFrontend::NbdUnix {
                socket: temp.path().join("frontends/root.sock"),
            },
        );
        assert!(result.is_err());

        let token = random(2);
        let result = authorized_blockd_command(
            &launch_config(),
            &prepared,
            &id("cats-cat-1-root.scope"),
            &token,
            &token,
            &temp.path().join("control-sockets/cat-1-blockd.sock"),
            &AuthorizedBlockFrontend::NbdUnix {
                socket: temp.path().join("frontends/root.sock"),
            },
        );
        assert!(result.is_err());
    }
}
