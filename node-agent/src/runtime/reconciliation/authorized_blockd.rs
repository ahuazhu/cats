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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use cats_api::blockd::DurabilityStatus;
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, DesiredRuntimeSpec, DirectAuthorizedAttachmentIdentity, HostPath,
    ReconcileStep, RuntimeCheckpoint, Sha256Digest, WireU64,
};
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, ContractVersion, DiskKind, Durability, Id, RandomId128,
    RuntimeTarget, VolumeAccess, VolumeAcquire, VolumeDisposition, VolumeIntent,
};
#[cfg(test)]
use cats_blockd::target_control::provision_root_authorization_context_digest;
use cats_storage::authority::{
    validate_authorized_serving_attachment, validate_volume_record, AttachmentLineageIdentity,
    AuthorizedServingAttachment, VolumeRecord,
};
use cats_storage::AdapterSelection;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::state_directory::StateDirectory;

use super::blockd_socket_namespace::ManagedBlockdRootStopOwnerEvidence;
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
    socket_owner: ManagedBlockdRootStopOwnerEvidence,
    admission: RootProvisionRetirementAdmission,
}

impl RootProvisionStopReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        checkpoint: &RuntimeCheckpoint,
        authorized: &AuthorizedBlockdCheckpoint,
        authority: VolumeRecord,
        process: RootProvisionProcessEvidence,
        socket_owner: ManagedBlockdRootStopOwnerEvidence,
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
        Self::new_validated(
            checkpoint,
            authorized,
            authority,
            &expectation,
            process,
            socket_owner,
            admission,
        )
    }

    /// Test-only constructor for an isolated managed socket root. Production
    /// always derives its expectation from the installed mapper in `new`;
    /// namespace integration tests instead provide the already-validated
    /// expectation whose checkpoint path was derived from
    /// `RetainedManagedBlockdSocketRoot::provision_for_test`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_isolated_socket_root_test(
        checkpoint: &RuntimeCheckpoint,
        authorized: &AuthorizedBlockdCheckpoint,
        authority: VolumeRecord,
        expectation: &RootProvisionProcessExpectation,
        process: RootProvisionProcessEvidence,
        socket_owner: ManagedBlockdRootStopOwnerEvidence,
        admission: RootProvisionRetirementAdmission,
    ) -> Result<Self> {
        let mut installed_checkpoint = checkpoint.clone();
        let ReconcileStep::ProvisionRootImage {
            provision_transition_id,
            control_socket_path,
            ..
        } = &mut installed_checkpoint.step
        else {
            anyhow::bail!("isolated Root stop test requires provision_root_image")
        };
        *control_socket_path =
            cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
                .root_paths(provision_transition_id)?
                .control_socket()
                .clone();
        let mut installed_expectation = RootProvisionProcessExpectation::from_checkpoint(
            &installed_checkpoint,
            RootProvisionAuthoritySnapshot {
                attachment: authorized.attachment.clone(),
                volume: &authority,
            },
            process.executable_path.clone(),
        )?;
        installed_expectation.control_socket_path = expectation.control_socket_path.clone();
        installed_expectation.socket_owner_authority_digest =
            provision_root_authorization_context_digest(checkpoint)?
                .as_sha256_digest()
                .clone();
        anyhow::ensure!(
            installed_expectation == *expectation,
            "isolated Root stop expectation changed fields beyond its managed socket mapping"
        );
        Self::new_validated(
            checkpoint,
            authorized,
            authority,
            expectation,
            process,
            socket_owner,
            admission,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_validated(
        checkpoint: &RuntimeCheckpoint,
        authorized: &AuthorizedBlockdCheckpoint,
        authority: VolumeRecord,
        expectation: &RootProvisionProcessExpectation,
        process: RootProvisionProcessEvidence,
        socket_owner: ManagedBlockdRootStopOwnerEvidence,
        admission: RootProvisionRetirementAdmission,
    ) -> Result<Self> {
        anyhow::ensure!(
            process.exactly_matches(expectation),
            "root-provision stop process is not its exact old expectation"
        );
        anyhow::ensure!(
            socket_owner.matches_expectation(expectation),
            "root-provision stop socket owner is not its exact managed generation"
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
            socket_owner,
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

    pub(crate) fn socket_owner(&self) -> &ManagedBlockdRootStopOwnerEvidence {
        &self.socket_owner
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
            && self.socket_owner == candidate.socket_owner
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
            && receipt.socket_owner.matches_process(&receipt.process),
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
        let directory = LockedAttachmentDirectory::acquire(directory).with_context(|| {
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
        self.retain_prepared_device(runtime, desired, &prepared)
    }

    /// Reopen one exact immutable attachment selected by an explicit prepared
    /// device. This is the multi-device read-only foundation used by the full
    /// inventory scanner; it never creates or repairs a missing input.
    pub(crate) fn retain_prepared_device(
        &self,
        runtime: &RuntimeCheckpoint,
        desired: &DesiredRuntimeSpec,
        prepared: &cats_api::runtime_reconciliation::PreparedDeviceInput,
    ) -> Result<RetainedAuthorizedBlockd> {
        self.retain_running_prepared_device(runtime, desired, desired, prepared)
    }

    /// Descriptor-retained Running reopen with an immutable physical-launch
    /// Desired and a potentially later live-gate Desired kept distinct.
    pub(crate) fn retain_running_prepared_device(
        &self,
        runtime: &RuntimeCheckpoint,
        physical_desired: &DesiredRuntimeSpec,
        gate_desired: &DesiredRuntimeSpec,
        prepared: &cats_api::runtime_reconciliation::PreparedDeviceInput,
    ) -> Result<RetainedAuthorizedBlockd> {
        validate_running_physical_desired_successor(physical_desired, gate_desired)?;
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
        let directory = LockedAttachmentDirectory::acquire(directory).with_context(|| {
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
        let physical_volume = physical_desired
            .volumes
            .iter()
            .find(|volume| volume.volume_id == prepared.volume_id)
            .context("prepared device lacks its physical-launch Desired volume")?;
        let gate_volume = gate_desired
            .volumes
            .iter()
            .find(|volume| volume.volume_id == prepared.volume_id)
            .context("prepared device lacks its live-gate Desired volume")?;
        anyhow::ensure!(
            identity == attachment.identity
                && attachment == checkpoint.attachment
                && checkpoint.desired == *physical_desired
                && checkpoint.volume == *physical_volume
                && physical_volume == gate_volume
                && runtime.cat_id == gate_desired.cat_id
                && runtime.node_id == gate_desired.placement.node_id
                && runtime.placement_epoch == gate_desired.placement.placement_epoch
                && runtime.desired_revision == gate_desired.desired_revision
                && runtime.spec_digest == gate_desired.spec_digest
                && prepared.volume_id == physical_volume.volume_id
                && prepared.volume_id == identity.volume_id
                && prepared.attachment_id == identity.attachment_id
                && prepared.attachment_epoch == identity.attachment_epoch
                && prepared.acquire_origin == identity.acquire_origin
                && prepared.size_bytes == attachment.size_bytes
                && prepared.durability == attachment.durability
                && match prepared.serving_authority.as_ref() {
                    cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. } => {
                        prepared.disk_kind == DiskKind::Root
                            && prepared.expected_head.generation.get() > 0
                            && prepared.expected_head.root_hash.is_some()
                            && prepared.expected_head.root_object_id.is_some()
                    }
                    cats_api::runtime_reconciliation::ServingAuthorityProvenance::DirectAuthorizedAttachment { purpose, .. } => {
                        prepared.expected_head == attachment.head
                            && matches!(
                                (prepared.disk_kind, purpose),
                                (DiskKind::Root, cats_api::runtime_reconciliation::DirectAuthorizedAttachmentPurpose::ExistingRoot)
                                    | (DiskKind::Persistent, cats_api::runtime_reconciliation::DirectAuthorizedAttachmentPurpose::PersistentInitialized)
                                    | (DiskKind::Persistent, cats_api::runtime_reconciliation::DirectAuthorizedAttachmentPurpose::PersistentUninitialized)
                            )
                    }
                },
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
        retained.assert_prepared_authority(prepared)?;
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
        let directory = LockedAttachmentDirectory::acquire(directory).with_context(|| {
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
    _directory_lock: Arc<LockedAttachmentDirectory>,
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
    directory: Arc<LockedAttachmentDirectory>,
    files: [RetainedExactFile; 3],
}

/// One cooperatively locked attachment directory shared by typed in-process
/// proofs. The final typed owner explicitly unlocks before closing its File so
/// an unexeced fork child cannot strand the flock through an inherited OFD.
#[derive(Debug)]
pub(crate) struct LockedAttachmentDirectory {
    directory: File,
}

impl LockedAttachmentDirectory {
    pub(crate) fn acquire(directory: File) -> io::Result<Arc<Self>> {
        lock_directory(&directory)?;
        // No fallible step remains between acquiring the flock and installing
        // its last-owner Drop guard. Callers receive the Arc before performing
        // any validation which can return early.
        Ok(Arc::new(Self { directory }))
    }

    pub(crate) fn as_file(&self) -> &File {
        &self.directory
    }
}

impl std::ops::Deref for LockedAttachmentDirectory {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        self.as_file()
    }
}

impl Drop for LockedAttachmentDirectory {
    fn drop(&mut self) {
        unlock_directory(&self.directory);
    }
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

impl RetainedAuthorizedBlockd {
    pub(crate) fn checkpoint(&self) -> &AuthorizedBlockdCheckpoint {
        &self.checkpoint
    }

    /// Share the already-flocked attachment owner with another typed verifier.
    /// The final typed owner explicitly unlocks even when an unexeced fork
    /// child still retains a raw duplicate of the underlying OFD.
    pub(crate) fn duplicate_locked_attachment_directory(
        &self,
    ) -> Result<Arc<LockedAttachmentDirectory>> {
        self.assert_current()?;
        Ok(Arc::clone(&self.directory))
    }

    pub(crate) fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    pub(crate) fn retained_directory(&self) -> &File {
        self.directory.as_file()
    }

    pub(crate) fn state_directory_path(&self) -> &Path {
        self.state_directory.path()
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        anyhow::ensure!(
            mutable_directory_identity_matches(
                &verify_retained_state_root(&self.root_directory, self.state_directory.path())?,
                &self.root_identity,
            ),
            "retained Node state directory changed identity"
        );
        let current_root = self
            .state_directory
            .try_reopen_directory()
            .context("reopen current Node state directory")?;
        anyhow::ensure!(
            mutable_directory_identity_matches(
                &verify_retained_state_root(&current_root, self.state_directory.path())?,
                &self.root_identity,
            ),
            "lexical Node state directory changed identity"
        );
        let mut current = current_root;
        let mut relative = PathBuf::new();
        for (index, (component, expected)) in self
            .components
            .iter()
            .zip(self.component_identities.iter())
            .enumerate()
        {
            relative.push(component);
            current =
                open_existing_directory_at(&current, component, &relative, &self.root_identity)?;
            let current_identity = stable_identity(&current, &relative)?;
            let is_leaf = index + 1 == self.component_identities.len();
            anyhow::ensure!(
                if is_leaf {
                    current_identity == *expected
                } else {
                    mutable_directory_identity_matches(&current_identity, expected)
                },
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

    pub(crate) fn assert_prepared_authority(
        &self,
        prepared: &cats_api::runtime_reconciliation::PreparedDeviceInput,
    ) -> Result<()> {
        self.assert_current()?;
        let cats_api::runtime_reconciliation::ServingAuthorityProvenance::DirectAuthorizedAttachment {
            authorization,
            ..
        } = prepared.serving_authority.as_ref()
        else {
            return Ok(());
        };
        let retained = self
            .files
            .iter()
            .find(|file| file.name == AUTHORIZED_SERVING_FILE)
            .context("retained authorized blockd lacks its serving artifact")?;
        let expected_path = self.data_directory.join(AUTHORIZED_SERVING_FILE);
        anyhow::ensure!(
            Path::new(authorization.path.as_str()) == expected_path
                && authorization.device.get() == retained.identity.device
                && authorization.inode.get() == retained.identity.inode
                && authorization.length.get() == retained.identity.length
                && authorization.content_sha256
                    == Sha256Digest::from_bytes(Sha256::digest(&retained.bytes).into()),
            "direct serving authorization changed its descriptor-stable artifact"
        );
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
        self._directory_lock.as_file()
    }

    pub(crate) fn state_directory_path(&self) -> &Path {
        &self.state_directory
    }

    /// Seal the immutable authorized-serving file into the private
    /// PrepareDevice provenance.  The retained attachment-directory lock and
    /// descriptor-relative `O_NOFOLLOW` open keep the pathname from being
    /// swapped between validation and checkpoint publication.
    pub(crate) fn direct_authorization_identity(
        &self,
    ) -> Result<DirectAuthorizedAttachmentIdentity> {
        let path = self.data_directory.join(AUTHORIZED_SERVING_FILE);
        let name = c_string(AUTHORIZED_SERVING_FILE, &path)?;
        let mut file = open_at(
            &self._directory_lock,
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
        .with_context(|| format!("open retained direct authorization {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect retained direct authorization {}", path.display()))?;
        // SAFETY: geteuid/getegid take no pointers and cannot fail.
        let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
        anyhow::ensure!(
            metadata.file_type().is_file()
                && metadata.nlink() == 1
                && metadata.uid() == euid
                && metadata.gid() == egid
                && metadata.permissions().mode() & 0o7777 == 0o600
                && metadata.len() > 0
                && metadata.len() <= MAX_AUTHORIZED_SERVING_BYTES as u64,
            "direct authorization has unsafe type, ownership, mode, links, or size"
        );
        let before = stable_identity(&file, &path)?;
        let mut bytes = Vec::with_capacity(usize::try_from(before.length)?);
        std::io::Read::by_ref(&mut file)
            .take(MAX_AUTHORIZED_SERVING_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .context("read retained direct authorization")?;
        anyhow::ensure!(
            bytes.len() == usize::try_from(before.length)?,
            "direct authorization length changed while read"
        );
        let after = stable_identity(&file, &path)?;
        anyhow::ensure!(before == after, "direct authorization changed while read");
        let decoded: AuthorizedServingAttachment =
            serde_json::from_slice(&bytes).context("decode retained direct authorization")?;
        anyhow::ensure!(
            decoded == self.checkpoint.attachment
                && serde_json::to_vec(&decoded)
                    .context("re-encode retained direct authorization")?
                    == bytes,
            "direct authorization bytes conflict with retained launch authority"
        );
        Ok(DirectAuthorizedAttachmentIdentity {
            path: HostPath::new(
                path.to_str()
                    .context("direct authorization path is not UTF-8")?
                    .to_owned(),
            )
            .context("direct authorization path is not canonical")?,
            device: WireU64::new(before.device)
                .context("direct authorization device exceeds wire range")?,
            inode: WireU64::new(before.inode)
                .context("direct authorization inode exceeds wire range")?,
            length: WireU64::new(before.length)
                .context("direct authorization length exceeds wire range")?,
            content_sha256: Sha256Digest::from_bytes(Sha256::digest(&bytes).into()),
        })
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
    /// How a serving process reaches the ObjectWrite Gateway. `None` composes
    /// a Node with no gateway at all, whose attachments carry no object-write
    /// credential; an attachment that does carry one refuses to launch without
    /// this, because it would start a process that cannot publish.
    pub object_write_gateway: Option<ObjectWriteGatewayLaunch>,
}

/// The two launch inputs a serving process needs to publish through the
/// ObjectWrite Gateway. Neither is key material: the private half stays in the
/// credential directory, readable only by the process that owns Node state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWriteGatewayLaunch {
    /// Bare HTTPS origin of the gateway this Node registered its credentials
    /// against. It comes from Node configuration, never from a constant.
    pub gateway_url: String,
    /// Absolute credential namespace directory, not the Node state root.
    pub credential_directory: PathBuf,
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
    build_authorized_blockd_command(
        config,
        prepared.checkpoint(),
        prepared.data_directory(),
        prepared.authorized_serving_path(),
        scope_id,
        process_identity_token,
        device_ownership_token,
        control_socket,
        frontend,
    )
}

/// Build the direct-authorized serving CLI from descriptor-retained immutable
/// inputs. The retained owner must remain alive while the resulting
/// expectation is consumed; this helper performs no Host mutation.
pub(crate) fn retained_authorized_blockd_command(
    config: &AuthorizedBlockdLaunchConfig,
    retained: &RetainedAuthorizedBlockd,
    prepared: &cats_api::runtime_reconciliation::PreparedDeviceInput,
    frontend: &AuthorizedBlockFrontend,
) -> Result<Command> {
    retained.assert_prepared_authority(prepared)?;
    let checkpoint = retained.checkpoint();
    anyhow::ensure!(
        checkpoint.attachment.identity.volume_id == prepared.volume_id
            && checkpoint.attachment.identity.attachment_id == prepared.attachment_id
            && checkpoint.attachment.identity.attachment_epoch == prepared.attachment_epoch
            && checkpoint.attachment.identity.acquire_origin == prepared.acquire_origin
            && checkpoint.attachment.head == prepared.expected_head
            && checkpoint.attachment.size_bytes == prepared.size_bytes
            && checkpoint.attachment.durability == prepared.durability
            && Path::new(prepared.serving_process.data_directory.as_str())
                == retained.data_directory(),
        "retained direct serving input changed its prepared-device contract"
    );
    build_authorized_blockd_command(
        config,
        checkpoint,
        retained.data_directory(),
        &retained.data_directory().join(AUTHORIZED_SERVING_FILE),
        &prepared.serving_process.scope_id,
        &prepared.serving_process.process_identity_token,
        &prepared.ownership_token,
        Path::new(prepared.serving_process.control_socket_path.as_str()),
        frontend,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the command builder consumes one closed checkpointed serving identity"
)]
fn build_authorized_blockd_command(
    config: &AuthorizedBlockdLaunchConfig,
    checkpoint: &AuthorizedBlockdCheckpoint,
    data_directory: &Path,
    authorized_serving_path: &Path,
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
    let frontend_socket = match frontend {
        AuthorizedBlockFrontend::NbdUnix { socket }
        | AuthorizedBlockFrontend::VhostUser { socket, .. } => socket,
    };
    let managed_sockets =
        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .serving_paths(device_ownership_token)
            .context("derive authorized serving socket namespace")?;
    anyhow::ensure!(
        control_socket == Path::new(managed_sockets.control_socket().as_str())
            && frontend_socket == Path::new(managed_sockets.io_socket().as_str()),
        "authorized serving sockets are not the exact device-token managed mapping"
    );
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

    let attachment = &checkpoint.attachment;
    let mut command = Command::new(&config.blockd_binary);
    command
        .arg("--volume-id")
        .arg(attachment.identity.volume_id.as_str())
        .arg("--data-dir")
        .arg(data_directory)
        .arg("--attachment-id")
        .arg(attachment.identity.attachment_id.as_str())
        .arg("--authorized-serving-spec")
        .arg(authorized_serving_path)
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
        .arg(attachment.lease_duration_ms().to_string())
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
    // The gateway inputs travel with the credential, so a Node that never
    // minted one launches exactly the command it launched before this field
    // existed, and a credential that cannot be reached fails the launch rather
    // than starting a process that cannot publish.
    if attachment.object_write_credential.is_some() {
        let gateway = config.object_write_gateway.as_ref().context(
            "authorized attachment carries an object-write credential but this Node has no ObjectWrite Gateway launch configuration",
        )?;
        anyhow::ensure!(
            gateway.credential_directory.is_absolute(),
            "object-write credential directory must be absolute"
        );
        command
            .arg("--object-write-gateway-url")
            .arg(&gateway.gateway_url)
            .arg("--object-write-credential-directory")
            .arg(&gateway.credential_directory);
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
    authorized_blockd_status_is_bound_to_head(
        status,
        acquired,
        scope_id,
        process_identity_token,
        device_ownership_token,
        &acquired.attachment.head,
    )
}

/// The serving process retains its immutable acquire-time authorization while
/// its live engine advances the same fenced attachment.  A scanner must bind
/// the dynamic `remote_head` to the independently loaded current Volume head,
/// never to the old grant or to a public generation counter.
pub(crate) fn authorized_blockd_status_is_bound_to_head(
    status: &DurabilityStatus,
    acquired: &AuthorizedBlockdCheckpoint,
    scope_id: &Id,
    process_identity_token: &RandomId128,
    device_ownership_token: &RandomId128,
    current_head: &cats_api::runtime_reconciliation::RemoteHead,
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
        && status.remote_head.as_ref() == Some(current_head)
        && status.mode
            == match attachment.durability {
                Durability::Strict => "strict",
                Durability::Relaxed => "relaxed",
            }
        && !status.backpressured
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
        desired
            .volumes
            .iter()
            .filter(|candidate| candidate.volume_id == volume.volume_id)
            .eq([volume]),
        "authorized blockd requires exactly the supplied Desired volume"
    );
    anyhow::ensure!(
        volume.access == VolumeAccess::ReadWriteOnce
            && (volume.disk_kind == DiskKind::Persistent || volume.mount.is_none())
            && matches!(volume.disposition, VolumeDisposition::Retain),
        "authorized blockd first slice supports only an unmounted retained RWO volume"
    );
    let identity = &attachment.identity;
    let acquire_matches = match (&volume.acquire, &attachment.acquire) {
        (
            VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            },
            cats_storage::authority::AuthorizedServingAcquire::Normal { request, .. },
        ) => {
            request.transition_id == *transition_id
                && request.expected_unowned_epoch == *expected_unowned_epoch
                && request.desired_revision == desired.desired_revision
                && request.placement_epoch == desired.placement.placement_epoch
        }
        (
            VolumeAcquire::Takeover { authorization_id },
            cats_storage::authority::AuthorizedServingAcquire::Takeover { authorization, .. },
        ) => {
            authorization.authorization_id == *authorization_id
                && authorization.desired_revision == desired.desired_revision
                && authorization.new_placement_epoch == desired.placement.placement_epoch
        }
        _ => false,
    };
    anyhow::ensure!(
        volume.volume_id == identity.volume_id
            && volume.attachment_id == identity.attachment_id
            && volume.size_bytes == attachment.size_bytes
            && volume.durability == attachment.durability
            && desired.placement.node_id == identity.node_id
            && desired.placement.placement_epoch == identity.placement_epoch
            && acquire_matches,
        "Desired, VolumeIntent and authorized grant do not form one exact lineage"
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
            && desired
                .volumes
                .iter()
                .filter(|candidate| candidate.volume_id == volume.volume_id)
                .eq([volume])
            && volume.access == VolumeAccess::ReadWriteOnce
            && (volume.disk_kind == DiskKind::Persistent || volume.mount.is_none())
            && matches!(volume.disposition, VolumeDisposition::Retain),
        "authorized blockd adoption requires one retained RWO Running volume"
    );
    let identity = &attachment.identity;
    let acquire_matches = match (&volume.acquire, &attachment.acquire) {
        (
            VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            },
            cats_storage::authority::AuthorizedServingAcquire::Normal { request, .. },
        ) => {
            request.transition_id == *transition_id
                && request.expected_unowned_epoch == *expected_unowned_epoch
                && request.volume_id == volume.volume_id
                && request.attachment_id == volume.attachment_id
                && request.desired_revision <= desired.desired_revision
                && request.placement_epoch == desired.placement.placement_epoch
        }
        (
            VolumeAcquire::Takeover { authorization_id },
            cats_storage::authority::AuthorizedServingAcquire::Takeover { authorization, .. },
        ) => {
            authorization.authorization_id == *authorization_id
                && authorization.volume_id == volume.volume_id
                && authorization.new_attachment_id == volume.attachment_id
                && authorization.desired_revision <= desired.desired_revision
                && authorization.new_placement_epoch == desired.placement.placement_epoch
        }
        _ => false,
    };
    anyhow::ensure!(
        volume.volume_id == identity.volume_id
            && volume.attachment_id == identity.attachment_id
            && volume.size_bytes == attachment.size_bytes
            && volume.durability == attachment.durability
            && desired.placement.node_id == identity.node_id
            && desired.placement.placement_epoch == identity.placement_epoch
            && acquire_matches,
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

/// Proves that a later live-gate Desired reuses one immutable Running launch
/// without reinterpreting any physical/runtime/volume authority. Endpoint
/// bindings and their revision/digest may advance; every other Desired field
/// is exact. Equal revisions are accepted only as the identical full value.
pub(crate) fn validate_running_physical_desired_successor(
    physical: &DesiredRuntimeSpec,
    gate: &DesiredRuntimeSpec,
) -> Result<()> {
    encode_desired_runtime_spec(physical).context("validate physical-launch Desired")?;
    encode_desired_runtime_spec(gate).context("validate live-gate Desired")?;
    anyhow::ensure!(
        physical.target == RuntimeTarget::Running
            && gate.target == RuntimeTarget::Running
            && physical.desired_revision <= gate.desired_revision,
        "live-gate Desired is not a monotonic Running launch successor"
    );
    if physical.desired_revision == gate.desired_revision {
        anyhow::ensure!(physical == gate, "same-revision Running Desired changed");
        return Ok(());
    }
    let mut normalized = gate.clone();
    normalized.desired_revision = physical.desired_revision;
    normalized.spec_digest = physical.spec_digest.clone();
    normalized.endpoints = physical.endpoints.clone();
    anyhow::ensure!(
        normalized == *physical,
        "live-gate Desired changed non-Endpoint physical launch authority"
    );
    for current in &gate.endpoints {
        if let Some(previous) = physical
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == current.endpoint_id)
        {
            anyhow::ensure!(
                previous == current || current.route_epoch > previous.route_epoch,
                "changed retained Endpoint did not advance its route epoch"
            );
        }
    }
    Ok(())
}

/// Closed Desired transition used by the gate C barrier. It proves a strict
/// revision successor whose only semantic change is the Endpoint set; every
/// changed retained Endpoint must burn a strictly higher route epoch.
pub(crate) fn validate_running_endpoint_only_desired_successor(
    predecessor: &DesiredRuntimeSpec,
    successor: &DesiredRuntimeSpec,
) -> Result<()> {
    validate_running_physical_desired_successor(predecessor, successor)?;
    anyhow::ensure!(
        predecessor.desired_revision < successor.desired_revision
            && predecessor.spec_digest != successor.spec_digest
            && predecessor.endpoints != successor.endpoints,
        "Endpoint-only gate Desired is not a strict changed revision"
    );
    for current in &successor.endpoints {
        if let Some(previous) = predecessor
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == current.endpoint_id)
        {
            anyhow::ensure!(
                previous == current || current.route_epoch > previous.route_epoch,
                "changed Endpoint did not advance its route epoch"
            );
        }
    }
    Ok(())
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

fn unlock_directory(directory: &File) {
    loop {
        // SAFETY: the descriptor is live and flock retains no Rust memory.
        // Explicit unlock is required before close because a forked child or
        // duplicated descriptor can retain the same open file description.
        let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_UN) };
        if result == 0 {
            return;
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return;
        }
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

fn mutable_directory_identity_matches(
    current: &StableFsIdentity,
    expected: &StableFsIdentity,
) -> bool {
    current.device == expected.device
        && current.inode == expected.inode
        && current.mode == expected.mode
        && current.uid == expected.uid
        && current.gid == expected.gid
        && current.links > 0
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

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};

    use cats_api::object_write_gateway::ObjectWriteCredentialReference;
    use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

    use cats_api::runtime_reconciliation::{
        spec_digest, AcquireOrigin, AsciiText, AssignedKind, AssignedPlacement, Epoch, FenceEpoch,
        Generation, GuestDeviceIdentity, Id, Ipv4Address, IsolatedIpv4Kind, MacAddress,
        NetworkConfig, NormalAcquireRequest, NormalAcquireResult, RandomId128, RemoteHead,
        Revision, RuntimeConfig, RuntimeTransition, Sha256Digest, UnixMillis,
    };
    use cats_storage::authority::AttachmentLineageIdentity;
    use cats_storage::AdapterConfig;

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
            object_write_credential: None,
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            // Root provision may have advanced the head after acquire.
            head: provisioned_head(),
            lease_expires_at: acquire_result.lease_expires_at,
            acquire: cats_storage::authority::AuthorizedServingAcquire::Normal {
                request: acquire_request,
                result: acquire_result,
            },
        };
        (desired, volume, attachment)
    }

    #[test]
    fn running_physical_desired_successor_changes_only_endpoint_coordinates() {
        let (physical, _, _) = fixture();
        let mut gate = physical.clone();
        gate.desired_revision = Revision::new(physical.desired_revision.get() + 1).unwrap();
        gate.spec_digest = spec_digest(&gate).unwrap();
        validate_running_physical_desired_successor(&physical, &gate).unwrap();

        let mut changed_runtime = gate.clone();
        changed_runtime.runtime.memory_bytes += 4096;
        changed_runtime.spec_digest = spec_digest(&changed_runtime).unwrap();
        assert!(validate_running_physical_desired_successor(&physical, &changed_runtime).is_err());

        let mut same_revision = physical.clone();
        same_revision.runtime.memory_bytes += 4096;
        same_revision.spec_digest = spec_digest(&same_revision).unwrap();
        assert!(validate_running_physical_desired_successor(&physical, &same_revision).is_err());
    }

    #[test]
    fn running_physical_desired_successor_rejects_a_lower_retained_route_epoch() {
        let physical =
            cats_api::runtime_reconciliation::decode_desired_runtime_spec(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testdata/runtime-reconciliation-v1-desired.json"
            )))
            .unwrap();
        let mut regressed = physical.clone();
        regressed.desired_revision = Revision::new(physical.desired_revision.get() + 1).unwrap();
        regressed.endpoints[0].route_epoch =
            Epoch::new(physical.endpoints[0].route_epoch.get() - 1).unwrap();
        regressed.spec_digest = spec_digest(&regressed).unwrap();
        assert!(validate_running_physical_desired_successor(&physical, &regressed).is_err());
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

    fn retained_runtime_checkpoint(
        root: &Path,
        desired: &DesiredRuntimeSpec,
        volume: &VolumeIntent,
        attachment: &AuthorizedServingAttachment,
    ) -> RuntimeCheckpoint {
        let mut checkpoint =
            cats_api::runtime_reconciliation::decode_runtime_checkpoint(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testdata/runtime-reconciliation-v1-provision-checkpoint.json"
            )))
            .unwrap();
        checkpoint.cat_id = desired.cat_id.clone();
        checkpoint.node_id = desired.placement.node_id.clone();
        checkpoint.placement_epoch = desired.placement.placement_epoch;
        checkpoint.desired_revision = desired.desired_revision;
        checkpoint.spec_digest = desired.spec_digest.clone();
        let ReconcileStep::ProvisionRootImage {
            volume_id,
            attachment_id,
            attachment_epoch,
            data_directory,
            size_bytes,
            boot_image_digest,
            expected_blank_head,
            ..
        } = &mut checkpoint.step
        else {
            unreachable!("fixture is a provision checkpoint")
        };
        *volume_id = volume.volume_id.clone();
        *attachment_id = attachment.identity.attachment_id.clone();
        *attachment_epoch = attachment.identity.attachment_epoch;
        *data_directory =
            HostPath::new(final_directory(root).to_str().unwrap().to_owned()).unwrap();
        *size_bytes = volume.size_bytes;
        *boot_image_digest = desired.runtime.boot_image_digest.clone();
        *expected_blank_head = attachment.head.clone();
        checkpoint
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
            object_write_gateway: None,
        }
    }

    fn managed_serving_sockets(device_ownership_token: &RandomId128) -> (PathBuf, PathBuf) {
        let paths = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .serving_paths(device_ownership_token)
            .unwrap();
        (
            PathBuf::from(paths.control_socket().as_str()),
            PathBuf::from(paths.io_socket().as_str()),
        )
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

        let device_ownership_token = random(3);
        let (control, frontend) = managed_serving_sockets(&device_ownership_token);
        let command = authorized_blockd_command(
            &launch_config(),
            &prepared,
            &id("cats-cat-1-root.scope"),
            &random(2),
            &device_ownership_token,
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
        let device_ownership_token = random(3);
        let (control, frontend) = managed_serving_sockets(&device_ownership_token);
        for (queues, queue_size) in [(0, 256), (65, 256), (1, 0), (1, 1), (1, 3), (1, 32_769)] {
            let result = authorized_blockd_command(
                &launch_config(),
                &prepared,
                &id("cats-cat-1-root.scope"),
                &random(2),
                &device_ownership_token,
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
                &device_ownership_token,
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
        let device_ownership_token = random(3);
        let (control, frontend) = managed_serving_sockets(&device_ownership_token);
        let frontends = [
            AuthorizedBlockFrontend::NbdUnix {
                socket: frontend.clone(),
            },
            AuthorizedBlockFrontend::VhostUser {
                socket: frontend,
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
                    &device_ownership_token,
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
    fn prepared_drop_unlocks_before_an_inherited_descriptor_closes() {
        let temp = tempfile::tempdir().unwrap();
        let (desired, volume, attachment) = fixture();
        let store =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()));
        let prepared = store.prepare(&desired, &volume, &attachment).unwrap();
        let inherited = prepared.retained_directory().try_clone().unwrap();

        drop(prepared);
        let successor = store.prepare(&desired, &volume, &attachment).unwrap();

        drop(successor);
        drop(inherited);
    }

    #[test]
    fn retained_lock_waits_for_last_typed_owner_then_unlocks_before_inherited_close() {
        for drop_shared_first in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (desired, volume, mut attachment) = fixture();
            attachment.head = empty_head();
            let store =
                AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()));
            drop(store.prepare(&desired, &volume, &attachment).unwrap());
            let checkpoint =
                retained_runtime_checkpoint(temp.path(), &desired, &volume, &attachment);
            let mut retained = Some(store.retain_exact_runtime_checkpoint(&checkpoint).unwrap());
            let mut shared = Some(
                retained
                    .as_ref()
                    .unwrap()
                    .duplicate_locked_attachment_directory()
                    .unwrap(),
            );
            let inherited = retained
                .as_ref()
                .unwrap()
                .retained_directory()
                .try_clone()
                .unwrap();

            if drop_shared_first {
                drop(shared.take());
            } else {
                drop(retained.take());
            }
            let blocked = match store.retain_exact_runtime_checkpoint(&checkpoint) {
                Ok(_) => panic!("a live typed owner must keep the attachment flock held"),
                Err(error) => error,
            };
            assert!(blocked.chain().any(|source| {
                source
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock)
            }));
            drop(shared.take());
            drop(retained.take());
            let successor = store.retain_exact_runtime_checkpoint(&checkpoint).unwrap();

            drop(successor);
            drop(inherited);
        }
    }

    #[test]
    fn mutable_ancestor_identity_allows_siblings_but_rejects_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let ancestor = temp.path().join("ancestor");
        std::fs::create_dir(&ancestor).unwrap();
        let retained = File::open(&ancestor).unwrap();
        let expected = stable_identity(&retained, &ancestor).unwrap();

        std::fs::create_dir(ancestor.join("sibling")).unwrap();
        let changed = stable_identity(&retained, &ancestor).unwrap();
        assert!(mutable_directory_identity_matches(&changed, &expected));

        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let changed_mode = stable_identity(&retained, &ancestor).unwrap();
        assert!(!mutable_directory_identity_matches(
            &changed_mode,
            &expected
        ));
        std::fs::set_permissions(
            &ancestor,
            std::fs::Permissions::from_mode(expected.mode & 0o7777),
        )
        .unwrap();

        let leaf = ancestor.join("leaf");
        std::fs::create_dir(&leaf).unwrap();
        let leaf_file = File::open(&leaf).unwrap();
        let leaf_before = stable_identity(&leaf_file, &leaf).unwrap();
        std::fs::create_dir(leaf.join("foreign-sibling")).unwrap();
        assert_ne!(
            stable_identity(&leaf_file, &leaf).unwrap(),
            leaf_before,
            "the immutable leaf keeps strict metadata identity"
        );

        let moved = temp.path().join("ancestor-replaced");
        std::fs::rename(&ancestor, moved).unwrap();
        std::fs::create_dir(&ancestor).unwrap();
        let replacement = File::open(&ancestor).unwrap();
        let replacement_identity = stable_identity(&replacement, &ancestor).unwrap();
        assert!(!mutable_directory_identity_matches(
            &replacement_identity,
            &expected
        ));
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

    /// The gateway inputs travel with the credential: a Node that minted none
    /// launches the command it launched before this field existed, and a
    /// credentialed attachment always names the namespace blockd validates.
    #[test]
    fn object_write_gateway_flags_follow_the_attachment_credential() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(temp.path().to_path_buf()));
        let (desired, volume, attachment) = fixture();
        let credential_directory = PathBuf::from("/var/lib/cats/node/n1")
            .join(cats_api::object_write_gateway::OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME);
        let mut config = launch_config();
        config.object_write_gateway = Some(ObjectWriteGatewayLaunch {
            gateway_url: "https://gateway.invalid".to_owned(),
            credential_directory: credential_directory.clone(),
        });

        // Calibrating negative: the same configured Node, an attachment that
        // carries no credential, and the flags must not appear.
        let uncredentialed = store.prepare(&desired, &volume, &attachment).unwrap();
        let device_ownership_token = random(3);
        let (control, frontend) = managed_serving_sockets(&device_ownership_token);
        let build = |config: &AuthorizedBlockdLaunchConfig, prepared: &PreparedAuthorizedBlockd| {
            authorized_blockd_command(
                config,
                prepared,
                &id("cats-cat-1-root.scope"),
                &random(2),
                &device_ownership_token,
                &control,
                &AuthorizedBlockFrontend::VhostUser {
                    socket: frontend.clone(),
                    queues: 2,
                    queue_size: 256,
                },
            )
        };
        let arguments = argv(&build(&config, &uncredentialed).unwrap());
        for absent in [
            "--object-write-gateway-url",
            "--object-write-credential-directory",
        ] {
            assert!(
                !arguments.contains(&OsString::from(absent)),
                "an attachment with no credential must not name a gateway"
            );
        }
        drop(uncredentialed);

        let credentialed_temp = tempfile::tempdir().unwrap();
        let credentialed_store = AuthorizedBlockdStore::new(StateDirectory::unanchored(
            credentialed_temp.path().to_path_buf(),
        ));
        let mut credentialed_attachment = attachment.clone();
        credentialed_attachment.object_write_credential = Some(ObjectWriteCredentialReference {
            credential_id: id("owcred1_aaaa"),
            public_key_spki_sha256: Sha256Digest::from_bytes([9; 32]),
        });
        let credentialed = credentialed_store
            .prepare(&desired, &volume, &credentialed_attachment)
            .unwrap();
        let arguments = argv(&build(&config, &credentialed).unwrap());
        let gateway_index = arguments
            .iter()
            .position(|argument| argument == OsStr::new("--object-write-gateway-url"))
            .expect("a credentialed attachment names its gateway");
        assert_eq!(
            arguments[gateway_index + 1],
            OsString::from("https://gateway.invalid")
        );
        let directory_index = arguments
            .iter()
            .position(|argument| argument == OsStr::new("--object-write-credential-directory"))
            .expect("a credentialed attachment names its credential directory");
        let passed = PathBuf::from(&arguments[directory_index + 1]);
        assert_eq!(passed, credential_directory);
        assert!(passed.is_absolute());
        assert_eq!(
            passed.file_name().unwrap(),
            cats_api::object_write_gateway::OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME,
            "blockd refuses any path whose last component is not the namespace"
        );

        // Fail closed: a credential this Node cannot reach must not launch a
        // process that would silently be unable to publish.
        let mut ungated = launch_config();
        ungated.object_write_gateway = None;
        assert!(build(&ungated, &credentialed).is_err());
        let mut relative = launch_config();
        relative.object_write_gateway = Some(ObjectWriteGatewayLaunch {
            gateway_url: "https://gateway.invalid".to_owned(),
            credential_directory: PathBuf::from("object-write-credentials"),
        });
        assert!(build(&relative, &credentialed).is_err());
    }
}
