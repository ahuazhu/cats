//! Descriptor-retained runtime paths for one `StartRuntime` VMM.
//!
//! These files are created or consumed by the launcher, but their absolute
//! pathnames are not authority.  The full inventory retains every lexical
//! ancestor and leaf, validates the fixed process descriptors, and repeats
//! the same proof before an accepted observation can authorize another
//! effect.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;

use anyhow::{Context as _, Result};
#[cfg(target_os = "linux")]
use cats_api::runtime_reconciliation::NodeBootId;
#[cfg(target_os = "linux")]
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, decode_runtime_checkpoint, encode_runtime_checkpoint,
    RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{HostPath, RandomId128, RuntimeCheckpoint, Sha256Digest};

use crate::state_directory::StateDirectory;

use super::retained_runtime_launch::RetainedRuntimeLaunchAuthority;
use super::vmm_launch_artifacts::VmmLaunchArtifactDescriptors;
#[cfg(target_os = "linux")]
use super::vmm_socket_namespace::{
    current_kernel_node_boot_id, scan_receipt_namespace_snapshot,
    scan_stale_boot_receipt_namespace_snapshot, ReceiptNamespaceSnapshot,
    RetainedManagedVmmSocketRoot, RetainedStaleVmmSocketReceipt,
    StaleVmmReceiptRetirementAuthority, VmmSocketOwnershipReceiptV1, VmmSocketReceiptStore,
};

const CHECKPOINT_FD: i32 = 64;
const VMM_FD: i32 = 65;
const KERNEL_FD: i32 = 66;
const INITRAMFS_FD: i32 = 67;
const MEMORY_FD: i32 = 68;
const SERIAL_LOG_FD: i32 = 69;
const VMM_LOG_FD: i32 = 70;
pub(crate) const VMM_LAUNCH_FILE_NAMESPACE: &str = "vmm-launch-v1";
#[cfg(target_os = "linux")]
const VMM_LAUNCH_OWNER_BASENAME: &str = ".owner.v1.json";
#[cfg(target_os = "linux")]
const VMM_LAUNCH_QUARANTINE_PREFIX: &str = "q-";
const VMM_MEMORY_BASENAME: &str = "memory.bin";
const VMM_SERIAL_LOG_BASENAME: &str = "serial.log";
const VMM_LOG_BASENAME: &str = "vmm.log";

/// Pure, canonical mapping for the mutable files owned by one VMM attempt.
///
/// The mapping is separate from the boot-local AF_UNIX namespace.  It is
/// derived only from the identity-selected Node state path and the fresh
/// Runtime incarnation, so a StartRuntime CAS never accepts caller-chosen
/// RAM/log paths.  Creating the directory or leaves remains a later physical
/// effect guarded by the provider-private launch-resource receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedVmmLaunchFilePaths {
    directory: HostPath,
    memory_file_path: HostPath,
    serial_log_path: HostPath,
    vmm_log_path: HostPath,
}

impl ManagedVmmLaunchFilePaths {
    pub(crate) fn for_incarnation(
        state_directory: &StateDirectory,
        incarnation: &RandomId128,
    ) -> Result<Self> {
        canonical_components(state_directory.path())?;
        let directory = state_directory
            .path()
            .join(VMM_LAUNCH_FILE_NAMESPACE)
            .join(format!("p-{}", incarnation.as_str()));
        let directory = canonical_host_path(directory, "VMM launch file directory")?;
        let memory_file_path = canonical_host_path(
            Path::new(directory.as_str()).join(VMM_MEMORY_BASENAME),
            "VMM memory file path",
        )?;
        let serial_log_path = canonical_host_path(
            Path::new(directory.as_str()).join(VMM_SERIAL_LOG_BASENAME),
            "VMM serial log path",
        )?;
        let vmm_log_path = canonical_host_path(
            Path::new(directory.as_str()).join(VMM_LOG_BASENAME),
            "VMM log path",
        )?;
        Ok(Self {
            directory,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
        })
    }

    pub(crate) fn paths_from_checkpoint(
        state_directory: &StateDirectory,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<Self> {
        let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let launch = authority.identity();
        let paths = Self::for_incarnation(state_directory, &launch.runtime_incarnation)?;
        anyhow::ensure!(
            launch.memory_file_path == paths.memory_file_path
                && launch.serial_log_path == paths.serial_log_path
                && launch.vmm_log_path == paths.vmm_log_path,
            "retained VMM launch files are outside the managed namespace"
        );
        Ok(paths)
    }

    pub(crate) fn directory(&self) -> &HostPath {
        &self.directory
    }

    pub(crate) fn memory_file_path(&self) -> &HostPath {
        &self.memory_file_path
    }

    pub(crate) fn serial_log_path(&self) -> &HostPath {
        &self.serial_log_path
    }

    pub(crate) fn vmm_log_path(&self) -> &HostPath {
        &self.vmm_log_path
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedVmmLaunchRootScan {
    Accounted,
    Residue,
    Unavailable,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct RetainedManagedVmmLaunchRoot {
    state_directory: StateDirectory,
    descriptor: File,
    identity: LaunchDirectoryIdentity,
}

#[cfg(target_os = "linux")]
impl RetainedManagedVmmLaunchRoot {
    /// Opens the installation-owned mutable-file root. Individual attempts
    /// may create only an incarnation-derived child below this retained inode.
    pub(crate) fn open_existing(state_directory: StateDirectory) -> Result<Self> {
        let state = state_directory
            .try_clone_directory()
            .context("retain state directory for VMM launch files")?;
        let state_metadata = state.metadata()?;
        let descriptor = open_at(
            &state,
            OsStr::new(VMM_LAUNCH_FILE_NAMESPACE),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .context("open installed VMM launch-file namespace")?;
        let metadata = descriptor.metadata()?;
        ensure_launch_directory(&metadata, state_metadata.uid(), state_metadata.gid(), 0o700)?;
        let retained = Self {
            state_directory,
            descriptor,
            identity: LaunchDirectoryIdentity::from_metadata(&metadata),
        };
        retained.assert_current()?;
        Ok(retained)
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        let retained = self.descriptor.metadata()?;
        ensure_launch_directory(&retained, self.identity.user, self.identity.group, 0o700)?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&retained) == self.identity,
            "retained VMM launch-file namespace changed"
        );
        let state = self
            .state_directory
            .try_reopen_directory()
            .context("reopen state directory for VMM launch files")?;
        let reopened = open_at(
            &state,
            OsStr::new(VMM_LAUNCH_FILE_NAMESPACE),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&reopened.metadata()?) == self.identity,
            "VMM launch-file namespace pathname changed identity"
        );
        Ok(())
    }

    pub(crate) fn state_directory(&self) -> &StateDirectory {
        &self.state_directory
    }

    /// Acquire the short-lived Node launch-namespace exclusion used only
    /// around a fresh global-absence reinspection and one namespace mutation.
    /// Launchers take the corresponding shared lock before touching any
    /// attempt leaf, so a late launcher makes recovery refresh with zero
    /// deletion rather than racing a pathname unlink.
    pub(crate) fn try_lock_effect_namespace(
        self: &Arc<Self>,
    ) -> Result<Option<ManagedVmmLaunchNamespaceGuard>> {
        self.assert_current()?;
        let descriptor = open_at(
            &self
                .state_directory
                .try_reopen_directory()
                .context("reopen state directory for VMM launch namespace lock")?,
            OsStr::new(VMM_LAUNCH_FILE_NAMESPACE),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        if !try_flock(&descriptor, libc::LOCK_EX)? {
            return Ok(None);
        }
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&descriptor.metadata()?) == self.identity,
            "VMM launch namespace changed before effect lock"
        );
        self.assert_current()?;
        Ok(Some(ManagedVmmLaunchNamespaceGuard {
            root: Arc::clone(self),
            descriptor,
        }))
    }

    pub(crate) fn prepare_existing_receipt(
        self: &Arc<Self>,
        authority: &GuardedVmmLaunchAbsence<'_>,
        checkpoint: &RuntimeCheckpoint,
        receipt: &VmmSocketOwnershipReceiptV1,
    ) -> Result<ManagedVmmLaunchPreparation> {
        authority.assert_for(self, checkpoint)?;
        self.assert_current()?;
        let paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(&self.state_directory, checkpoint)?;
        receipt.validate_launch_paths(checkpoint, &self.state_directory, &paths)?;
        let attempt_name = launch_attempt_name(&paths)?;
        let quarantine_name = quarantine_attempt_name(&attempt_name)?;
        let existing = open_launch_attempt(self, &attempt_name)?;
        let quarantined = open_launch_attempt(self, &quarantine_name)?;
        anyhow::ensure!(
            existing.is_none() || quarantined.is_none(),
            "VMM launch attempt has both public and quarantine identities"
        );
        if let Some(directory) = quarantined {
            let residue = RetainedManagedVmmLaunchResidue::new(
                Arc::clone(self),
                attempt_name,
                quarantine_name,
                directory,
                receipt.encoded_bytes()?,
                LaunchResidueLocation::Quarantine,
            )?;
            return Ok(ManagedVmmLaunchPreparation::Residue(Box::new(residue)));
        }
        let created = existing.is_none();
        let directory = match existing {
            Some(directory) => directory,
            None => {
                mkdir_launch_attempt(&self.descriptor, &attempt_name)?;
                self.descriptor
                    .sync_all()
                    .context("fsync VMM launch-file namespace")?;
                open_launch_attempt(self, &attempt_name)?
                    .context("created VMM launch attempt disappeared")?
            }
        };
        let mut names = launch_attempt_names(&directory)?;
        let marker_bytes = receipt.encoded_bytes()?;
        if !names.contains(VMM_LAUNCH_OWNER_BASENAME) {
            anyhow::ensure!(
                names.is_empty(),
                "unmarked VMM launch attempt contains foreign entries"
            );
            create_launch_owner_marker(&directory, &marker_bytes)?;
            names.insert(VMM_LAUNCH_OWNER_BASENAME.to_owned());
            let ready = RetainedManagedVmmLaunchAttempt::new(
                Arc::clone(self),
                attempt_name,
                directory,
                marker_bytes,
            )?;
            return Ok(if created {
                ManagedVmmLaunchPreparation::Ready(Box::new(ready))
            } else {
                ManagedVmmLaunchPreparation::PublishedIntent
            });
        }
        verify_launch_owner_marker(&directory, &marker_bytes)?;
        validate_launch_attempt_entries(&directory, &names)?;
        if names.len() > 1 {
            return Ok(ManagedVmmLaunchPreparation::Residue(Box::new(
                RetainedManagedVmmLaunchResidue::new(
                    Arc::clone(self),
                    attempt_name,
                    quarantine_name,
                    directory,
                    marker_bytes,
                    LaunchResidueLocation::Public,
                )?,
            )));
        }
        Ok(ManagedVmmLaunchPreparation::Ready(Box::new(
            RetainedManagedVmmLaunchAttempt::new(
                Arc::clone(self),
                attempt_name,
                directory,
                marker_bytes,
            )?,
        )))
    }

    /// Retire one receipt-owned attempt from an earlier kernel boot. The
    /// exclusive launch-root lock is acquired before every mutable namespace
    /// is revalidated. Same-name current-boot socket replacements are never
    /// removed, and the durable receipt is removed only after any exact launch
    /// directory has been isolated and drained through its retained fd.
    pub(crate) fn recover_stale_boot_receipt(
        self: &Arc<Self>,
        socket_root: &RetainedManagedVmmSocketRoot,
        receipts: &VmmSocketReceiptStore,
        checkpoint: &RuntimeCheckpoint,
        candidate: RetainedStaleVmmSocketReceipt,
        context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        inspect_fresh_global_absence: impl FnOnce(
            &ManagedVmmLaunchNamespaceGuard,
        ) -> Result<
            super::vmm_process::ExactVmmProcessAbsenceProof,
        >,
    ) -> Result<bool> {
        context.check_active()?;
        let Some(namespace_guard) = self.try_lock_effect_namespace()? else {
            return Ok(false);
        };
        // The callback is invoked only after the same EX launch-root flock
        // held through cleanup. Production must perform the sealed global
        // unit/cgroup/process/socket/file sweep here; a point process probe is
        // not sufficient authority to retire a previous-boot receipt.
        let absence = inspect_fresh_global_absence(&namespace_guard)?;
        let authority = namespace_guard.bind_stale_boot_absence(
            absence,
            candidate.receipt(),
            checkpoint,
            context,
        )?;
        candidate.assert_current(receipts)?;
        let current_boot_id = current_kernel_node_boot_id()?;
        candidate.receipt().validate_stale_boot_against(
            checkpoint,
            receipts.state_directory(),
            socket_root,
            &current_boot_id,
        )?;
        socket_root.assert_stale_boot_attempt_absent(candidate.receipt())?;
        if let Some(residue) = self.retain_stale_boot_launch_residue(
            &authority,
            checkpoint,
            candidate.receipt(),
            &current_boot_id,
        )? {
            residue.recover_stale_boot(&authority, checkpoint)?;
        }
        context.check_active()?;
        candidate.assert_current(receipts)?;
        socket_root.assert_stale_boot_attempt_absent(candidate.receipt())?;
        candidate.retire(receipts, &authority)?;
        context.check_active()?;
        Ok(true)
    }

    fn retain_stale_boot_launch_residue(
        self: &Arc<Self>,
        authority: &GuardedStaleBootVmmLaunchAbsence<'_>,
        checkpoint: &RuntimeCheckpoint,
        receipt: &VmmSocketOwnershipReceiptV1,
        current_boot_id: &NodeBootId,
    ) -> Result<Option<Box<RetainedManagedVmmLaunchResidue>>> {
        authority.assert_for(self, checkpoint)?;
        self.assert_current()?;
        let paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(&self.state_directory, checkpoint)?;
        receipt.validate_stale_boot_launch_paths(
            checkpoint,
            &self.state_directory,
            &paths,
            current_boot_id,
        )?;
        let public_name = launch_attempt_name(&paths)?;
        let quarantine_name = quarantine_attempt_name(&public_name)?;
        let public = open_launch_attempt(self, &public_name)?;
        let quarantine = open_launch_attempt(self, &quarantine_name)?;
        anyhow::ensure!(
            public.is_none() || quarantine.is_none(),
            "stale-boot VMM launch attempt has public and quarantine aliases"
        );
        let marker_bytes = receipt.encoded_bytes()?;
        if let Some(directory) = public {
            let names = launch_attempt_names(&directory)?;
            if !names.contains(VMM_LAUNCH_OWNER_BASENAME) {
                anyhow::ensure!(
                    names.is_empty(),
                    "unmarked stale-boot VMM launch attempt contains foreign leaves"
                );
                create_launch_owner_marker(&directory, &marker_bytes)?;
                directory.sync_all()?;
                authority.assert_for(self, checkpoint)?;
            }
            return Ok(Some(Box::new(RetainedManagedVmmLaunchResidue::new(
                Arc::clone(self),
                public_name,
                quarantine_name,
                directory,
                marker_bytes,
                LaunchResidueLocation::Public,
            )?)));
        }
        if let Some(directory) = quarantine {
            return Ok(Some(Box::new(RetainedManagedVmmLaunchResidue::new(
                Arc::clone(self),
                public_name,
                quarantine_name,
                directory,
                marker_bytes,
                LaunchResidueLocation::Quarantine,
            )?)));
        }
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) enum ManagedVmmLaunchPreparation {
    Ready(Box<RetainedManagedVmmLaunchAttempt>),
    /// A crash-created empty attempt was bound to its already-durable receipt.
    /// Stop this admission and require a new accepted full scan.
    PublishedIntent,
    Residue(Box<RetainedManagedVmmLaunchResidue>),
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct ManagedVmmLaunchNamespaceGuard {
    root: Arc<RetainedManagedVmmLaunchRoot>,
    descriptor: File,
}

#[cfg(target_os = "linux")]
impl ManagedVmmLaunchNamespaceGuard {
    fn assert_for(&self, root: &Arc<RetainedManagedVmmLaunchRoot>) -> Result<()> {
        anyhow::ensure!(
            Arc::ptr_eq(&self.root, root),
            "VMM launch guard belongs to another root"
        );
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&self.descriptor.metadata()?) == root.identity,
            "locked VMM launch namespace changed identity"
        );
        root.assert_current()
    }

    pub(crate) fn bind_fresh_absence(
        &self,
        absence: super::vmm_process::ExactVmmProcessAbsenceProof,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<GuardedVmmLaunchAbsence<'_>> {
        self.assert_for(&self.root)?;
        anyhow::ensure!(
            absence.matches_checkpoint(checkpoint),
            "VMM launch guard cannot bind absence for another checkpoint"
        );
        Ok(GuardedVmmLaunchAbsence {
            guard: self,
            absence,
        })
    }

    /// A different kernel boot is a stronger absence boundary than a process
    /// point scan for the receipt's old process: Linux cannot preserve that
    /// process across the boot-ID change. The same EX namespace lock still
    /// excludes every supported current-boot launcher while old durable
    /// launch files and the receipt are quarantined.
    pub(crate) fn bind_stale_boot_absence<'a>(
        &'a self,
        absence: super::vmm_process::ExactVmmProcessAbsenceProof,
        receipt: &VmmSocketOwnershipReceiptV1,
        checkpoint: &RuntimeCheckpoint,
        context: &'a dyn crate::runtime_spine::RuntimePhysicalReadContext,
    ) -> Result<GuardedStaleBootVmmLaunchAbsence<'a>> {
        context.check_active()?;
        self.assert_for(&self.root)?;
        let current_boot_id = current_kernel_node_boot_id()?;
        anyhow::ensure!(
            receipt.node_boot_id() != &current_boot_id,
            "VMM receipt belongs to the current kernel boot"
        );
        let retained = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        anyhow::ensure!(
            absence.matches_checkpoint(checkpoint)
                && receipt.cat_id() == &checkpoint.cat_id
                && receipt.runtime_incarnation() == &retained.identity().runtime_incarnation,
            "stale-boot VMM absence or receipt names another retained launch"
        );
        Ok(GuardedStaleBootVmmLaunchAbsence {
            guard: self,
            absence,
            checkpoint: checkpoint.clone(),
            stale_boot_id: receipt.node_boot_id().clone(),
            runtime_incarnation: receipt.runtime_incarnation().clone(),
            context,
        })
    }
}

/// Non-cloneable effect-time absence authority whose lifetime cannot outlive
/// the exclusive namespace guard acquired before its fresh global sweep.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct GuardedVmmLaunchAbsence<'a> {
    guard: &'a ManagedVmmLaunchNamespaceGuard,
    absence: super::vmm_process::ExactVmmProcessAbsenceProof,
}

#[cfg(target_os = "linux")]
impl GuardedVmmLaunchAbsence<'_> {
    pub(crate) fn assert_for(
        &self,
        root: &Arc<RetainedManagedVmmLaunchRoot>,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<()> {
        self.guard.assert_for(root)?;
        anyhow::ensure!(
            self.absence.matches_checkpoint(checkpoint),
            "guarded VMM absence names another checkpoint"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct GuardedStaleBootVmmLaunchAbsence<'a> {
    guard: &'a ManagedVmmLaunchNamespaceGuard,
    absence: super::vmm_process::ExactVmmProcessAbsenceProof,
    checkpoint: RuntimeCheckpoint,
    stale_boot_id: NodeBootId,
    runtime_incarnation: RandomId128,
    context: &'a dyn crate::runtime_spine::RuntimePhysicalReadContext,
}

#[cfg(target_os = "linux")]
impl GuardedStaleBootVmmLaunchAbsence<'_> {
    fn assert_for(
        &self,
        root: &Arc<RetainedManagedVmmLaunchRoot>,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<()> {
        self.guard.assert_for(root)?;
        self.context.check_active()?;
        let retained = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        anyhow::ensure!(
            checkpoint == &self.checkpoint
                && self.absence.matches_checkpoint(checkpoint)
                && retained.identity().runtime_incarnation == self.runtime_incarnation
                && current_kernel_node_boot_id()? != self.stale_boot_id,
            "stale-boot VMM launch absence changed coordinate"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl super::vmm_socket_namespace::stale_receipt_retirement_sealed::Sealed
    for GuardedStaleBootVmmLaunchAbsence<'_>
{
}

#[cfg(target_os = "linux")]
impl StaleVmmReceiptRetirementAuthority for GuardedStaleBootVmmLaunchAbsence<'_> {
    fn assert_receipt_retirement(&self, receipt: &VmmSocketOwnershipReceiptV1) -> Result<()> {
        self.assert_for(&self.guard.root, &self.checkpoint)?;
        anyhow::ensure!(
            receipt.node_boot_id() == &self.stale_boot_id
                && receipt.runtime_incarnation() == &self.runtime_incarnation
                && receipt.cat_id() == &self.checkpoint.cat_id,
            "stale-boot VMM receipt changed recovery coordinate"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct RetainedManagedVmmLaunchAttempt {
    root: Arc<RetainedManagedVmmLaunchRoot>,
    name: CString,
    directory: File,
    directory_identity: LaunchDirectoryIdentity,
    marker_identity: LaunchLeafIdentity,
    marker_bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl RetainedManagedVmmLaunchAttempt {
    fn new(
        root: Arc<RetainedManagedVmmLaunchRoot>,
        name: CString,
        directory: File,
        marker_bytes: Vec<u8>,
    ) -> Result<Self> {
        let directory_identity = LaunchDirectoryIdentity::from_metadata(&directory.metadata()?);
        let marker = open_launch_leaf(&directory, VMM_LAUNCH_OWNER_BASENAME)?
            .context("VMM launch owner marker disappeared")?;
        let marker_identity = LaunchLeafIdentity::from_metadata(&marker.metadata()?);
        let retained = Self {
            root,
            name,
            directory,
            directory_identity,
            marker_identity,
            marker_bytes,
        };
        retained.assert_ready()?;
        Ok(retained)
    }

    /// Proves the exact marker-owned directory is still empty immediately
    /// before PID 1 is asked to start the fixed launcher.
    pub(crate) fn assert_ready(&self) -> Result<()> {
        self.root.assert_current()?;
        let metadata = self.directory.metadata()?;
        ensure_launch_directory(
            &metadata,
            self.directory_identity.user,
            self.directory_identity.group,
            0o700,
        )?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&metadata) == self.directory_identity,
            "retained VMM launch attempt changed identity"
        );
        let reopened = open_directory_at_name(&self.root.descriptor, &self.name)?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&reopened.metadata()?)
                == self.directory_identity,
            "VMM launch attempt pathname changed identity"
        );
        anyhow::ensure!(
            launch_attempt_names(&self.directory)?
                == std::collections::BTreeSet::from([VMM_LAUNCH_OWNER_BASENAME.to_owned()]),
            "VMM launch attempt is not empty before submit"
        );
        let marker = open_launch_leaf(&self.directory, VMM_LAUNCH_OWNER_BASENAME)?
            .context("VMM launch owner marker disappeared")?;
        let marker_metadata = marker.metadata()?;
        anyhow::ensure!(
            LaunchLeafIdentity::from_metadata(&marker_metadata) == self.marker_identity,
            "VMM launch owner marker changed identity"
        );
        anyhow::ensure!(
            read_exact_launch_marker(&marker)? == self.marker_bytes,
            "VMM launch owner marker changed bytes"
        );
        Ok(())
    }
}

/// A launcher-only retained guard. The shared namespace flock is acquired
/// before any socket/file mutation, waiting for the submitting effect to
/// release its exclusive side after systemd's `Type=exec` boundary. It is
/// released automatically at the successful VMM `exec` boundary because this
/// descriptor is CLOEXEC. Recovery requires the exclusive side of the same
/// lock.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct RetainedManagedVmmLauncherAttempt {
    _namespace_guard: File,
    attempt: RetainedManagedVmmLaunchAttempt,
}

#[cfg(target_os = "linux")]
impl RetainedManagedVmmLauncherAttempt {
    pub(crate) fn assert_ready(&self) -> Result<()> {
        self.attempt.assert_ready()
    }
}

#[cfg(target_os = "linux")]
impl RetainedManagedVmmLaunchRoot {
    pub(crate) fn retain_launcher_attempt(
        self: &Arc<Self>,
        checkpoint: &RuntimeCheckpoint,
        receipt: &VmmSocketOwnershipReceiptV1,
    ) -> Result<RetainedManagedVmmLauncherAttempt> {
        self.retain_launcher_attempt_inner(checkpoint, receipt, || {})
    }

    fn retain_launcher_attempt_inner(
        self: &Arc<Self>,
        checkpoint: &RuntimeCheckpoint,
        receipt: &VmmSocketOwnershipReceiptV1,
        before_lock: impl FnOnce(),
    ) -> Result<RetainedManagedVmmLauncherAttempt> {
        self.assert_current()?;
        let namespace_guard = open_at(
            &self
                .state_directory
                .try_reopen_directory()
                .context("reopen state directory for VMM launcher namespace lock")?,
            OsStr::new(VMM_LAUNCH_FILE_NAMESPACE),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        before_lock();
        lock_flock(&namespace_guard, libc::LOCK_SH)?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&namespace_guard.metadata()?) == self.identity,
            "VMM launch namespace changed before launcher lock"
        );
        let paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(&self.state_directory, checkpoint)?;
        receipt.validate_launch_paths(checkpoint, &self.state_directory, &paths)?;
        let name = launch_attempt_name(&paths)?;
        let directory = open_launch_attempt(self, &name)?
            .context("checkpointed VMM launch attempt is missing")?;
        let attempt = RetainedManagedVmmLaunchAttempt::new(
            Arc::clone(self),
            name,
            directory,
            receipt.encoded_bytes()?,
        )?;
        attempt.assert_ready()?;
        Ok(RetainedManagedVmmLauncherAttempt {
            _namespace_guard: namespace_guard,
            attempt,
        })
    }

    #[cfg(test)]
    fn retain_launcher_attempt_with_before_lock(
        self: &Arc<Self>,
        checkpoint: &RuntimeCheckpoint,
        receipt: &VmmSocketOwnershipReceiptV1,
        before_lock: impl FnOnce(),
    ) -> Result<RetainedManagedVmmLauncherAttempt> {
        self.retain_launcher_attempt_inner(checkpoint, receipt, before_lock)
    }

    #[cfg(test)]
    pub(crate) fn launcher_shared_lock_is_blocked_for_test(&self) -> Result<bool> {
        self.assert_current()?;
        let descriptor = open_at(
            &self
                .state_directory
                .try_reopen_directory()
                .context("reopen state directory for VMM launcher lock probe")?,
            OsStr::new(VMM_LAUNCH_FILE_NAMESPACE),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        Ok(!try_flock(&descriptor, libc::LOCK_SH)?)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchResidueLocation {
    Public,
    Quarantine,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchCleanupBoundary {
    BeforeQuarantine,
    AfterQuarantine,
    BeforeMemory,
    BeforeSerialLog,
    BeforeVmmLog,
    BeforeMarker,
    BeforeDirectory,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct RetainedManagedVmmLaunchResidue {
    root: Arc<RetainedManagedVmmLaunchRoot>,
    public_name: CString,
    quarantine_name: CString,
    directory: File,
    directory_identity: LaunchDirectoryIdentity,
    leaf_identities: std::collections::BTreeMap<String, LaunchLeafIdentity>,
    marker_bytes: Vec<u8>,
    location: LaunchResidueLocation,
}

#[cfg(target_os = "linux")]
trait VmmLaunchCleanupAuthority {
    fn assert_cleanup_for(
        &self,
        root: &Arc<RetainedManagedVmmLaunchRoot>,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<()>;
}

#[cfg(target_os = "linux")]
impl VmmLaunchCleanupAuthority for GuardedVmmLaunchAbsence<'_> {
    fn assert_cleanup_for(
        &self,
        root: &Arc<RetainedManagedVmmLaunchRoot>,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<()> {
        self.assert_for(root, checkpoint)
    }
}

#[cfg(target_os = "linux")]
impl VmmLaunchCleanupAuthority for GuardedStaleBootVmmLaunchAbsence<'_> {
    fn assert_cleanup_for(
        &self,
        root: &Arc<RetainedManagedVmmLaunchRoot>,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<()> {
        self.assert_for(root, checkpoint)
    }
}

#[cfg(target_os = "linux")]
impl RetainedManagedVmmLaunchResidue {
    fn new(
        root: Arc<RetainedManagedVmmLaunchRoot>,
        public_name: CString,
        quarantine_name: CString,
        directory: File,
        marker_bytes: Vec<u8>,
        location: LaunchResidueLocation,
    ) -> Result<Self> {
        let names = launch_attempt_names(&directory)?;
        validate_launch_attempt_entries(&directory, &names)?;
        match location {
            LaunchResidueLocation::Public => anyhow::ensure!(
                names.contains(VMM_LAUNCH_OWNER_BASENAME),
                "public VMM launch residue lacks its durable owner marker"
            ),
            LaunchResidueLocation::Quarantine => anyhow::ensure!(
                names.is_empty() || names.contains(VMM_LAUNCH_OWNER_BASENAME),
                "quarantined VMM launch residue lacks its owner marker"
            ),
        }
        if names.contains(VMM_LAUNCH_OWNER_BASENAME) {
            verify_launch_owner_marker(&directory, &marker_bytes)?;
        }
        let leaf_identities = launch_attempt_leaf_identities(&directory, &names)?;
        Ok(Self {
            root,
            public_name,
            quarantine_name,
            directory_identity: LaunchDirectoryIdentity::from_metadata(&directory.metadata()?),
            leaf_identities,
            directory,
            marker_bytes,
            location,
        })
    }

    /// Quarantine the exact receipt-owned directory with `RENAME_NOREPLACE`,
    /// then remove leaves only through the isolated retained directory while
    /// the launcher namespace is exclusively locked. The deployment contract
    /// makes every ancestor root-owned and non-writable (0700); the flock
    /// serializes all Cats launchers/effects. A privileged process which
    /// ignores that contract is treated as a deployment compromise, but even
    /// a public-leaf replacement before quarantine is never unlinked.
    pub(crate) fn recover(
        self,
        authority: &GuardedVmmLaunchAbsence<'_>,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<()> {
        self.recover_inner(authority, checkpoint, |_| Ok(()))
    }

    pub(crate) fn recover_stale_boot(
        self,
        authority: &GuardedStaleBootVmmLaunchAbsence<'_>,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<()> {
        self.recover_inner(authority, checkpoint, |_| Ok(()))
    }

    #[cfg(test)]
    fn recover_with_boundaries(
        self,
        authority: &GuardedVmmLaunchAbsence<'_>,
        checkpoint: &RuntimeCheckpoint,
        before_boundary: impl FnMut(LaunchCleanupBoundary) -> Result<()>,
    ) -> Result<()> {
        self.recover_inner(authority, checkpoint, before_boundary)
    }

    fn recover_inner(
        mut self,
        authority: &impl VmmLaunchCleanupAuthority,
        checkpoint: &RuntimeCheckpoint,
        mut before_boundary: impl FnMut(LaunchCleanupBoundary) -> Result<()>,
    ) -> Result<()> {
        authority.assert_cleanup_for(&self.root, checkpoint)?;
        self.assert_current()?;
        if self.location == LaunchResidueLocation::Public {
            before_boundary(LaunchCleanupBoundary::BeforeQuarantine)?;
            anyhow::ensure!(
                open_launch_attempt(&self.root, &self.quarantine_name)?.is_none(),
                "VMM launch quarantine already exists"
            );
            rename_launch_attempt_noreplace(
                &self.root.descriptor,
                &self.public_name,
                &self.quarantine_name,
            )?;
            self.root.descriptor.sync_all()?;
            let moved = open_directory_at_name(&self.root.descriptor, &self.quarantine_name)?;
            if LaunchDirectoryIdentity::from_metadata(&moved.metadata()?) != self.directory_identity
            {
                // Never clean a replacement selected by the rename race. A
                // best-effort no-replace restore preserves its public name;
                // failure leaves it isolated for a later fail-closed scan.
                let _ = rename_launch_attempt_noreplace(
                    &self.root.descriptor,
                    &self.quarantine_name,
                    &self.public_name,
                );
                let _ = self.root.descriptor.sync_all();
                anyhow::bail!("VMM launch attempt changed during quarantine")
            }
            self.directory = moved;
            self.location = LaunchResidueLocation::Quarantine;
        }
        self.assert_current()?;
        before_boundary(LaunchCleanupBoundary::AfterQuarantine)?;

        for (leaf, boundary) in [
            (VMM_MEMORY_BASENAME, LaunchCleanupBoundary::BeforeMemory),
            (
                VMM_SERIAL_LOG_BASENAME,
                LaunchCleanupBoundary::BeforeSerialLog,
            ),
            (VMM_LOG_BASENAME, LaunchCleanupBoundary::BeforeVmmLog),
        ] {
            before_boundary(boundary)?;
            self.assert_cleanup_leaf(leaf)?;
            let Some(_) = self.leaf_identities.get(leaf) else {
                continue;
            };
            unlink_isolated_launch_leaf(&self.directory, leaf)?;
            self.directory.sync_all()?;
            authority.assert_cleanup_for(&self.root, checkpoint)?;
        }
        before_boundary(LaunchCleanupBoundary::BeforeMarker)?;
        self.assert_cleanup_leaf(VMM_LAUNCH_OWNER_BASENAME)?;
        if self.leaf_identities.contains_key(VMM_LAUNCH_OWNER_BASENAME) {
            verify_launch_owner_marker(&self.directory, &self.marker_bytes)?;
            unlink_isolated_launch_leaf(&self.directory, VMM_LAUNCH_OWNER_BASENAME)?;
            self.directory.sync_all()?;
        }
        anyhow::ensure!(
            launch_attempt_names(&self.directory)?.is_empty(),
            "quarantined VMM launch attempt did not become empty"
        );
        authority.assert_cleanup_for(&self.root, checkpoint)?;
        before_boundary(LaunchCleanupBoundary::BeforeDirectory)?;
        let reopened = open_directory_at_name(&self.root.descriptor, &self.quarantine_name)?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&reopened.metadata()?)
                == self.directory_identity,
            "VMM launch quarantine changed before removal"
        );
        remove_isolated_launch_directory(&self.root.descriptor, &self.quarantine_name)?;
        self.root.descriptor.sync_all()?;
        authority.assert_cleanup_for(&self.root, checkpoint)
    }

    fn assert_cleanup_leaf(&self, name: &str) -> Result<()> {
        let current = match open_launch_leaf(&self.directory, name)? {
            Some(leaf) => Some(LaunchLeafIdentity::from_metadata(&leaf.metadata()?)),
            None => None,
        };
        anyhow::ensure!(
            current.as_ref() == self.leaf_identities.get(name),
            "quarantined VMM launch leaf {name} changed before cleanup"
        );
        Ok(())
    }

    fn assert_current(&self) -> Result<()> {
        self.root.assert_current()?;
        let metadata = self.directory.metadata()?;
        ensure_launch_directory(
            &metadata,
            self.directory_identity.user,
            self.directory_identity.group,
            0o700,
        )?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&metadata) == self.directory_identity,
            "retained VMM launch residue changed identity"
        );
        let name = match self.location {
            LaunchResidueLocation::Public => &self.public_name,
            LaunchResidueLocation::Quarantine => &self.quarantine_name,
        };
        let reopened = open_directory_at_name(&self.root.descriptor, name)?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&reopened.metadata()?)
                == self.directory_identity,
            "VMM launch residue pathname changed identity"
        );
        let names = launch_attempt_names(&self.directory)?;
        validate_launch_attempt_entries(&self.directory, &names)?;
        anyhow::ensure!(
            launch_attempt_leaf_identities(&self.directory, &names)? == self.leaf_identities,
            "retained VMM launch residue leaf identity changed"
        );
        if names.contains(VMM_LAUNCH_OWNER_BASENAME) {
            verify_launch_owner_marker(&self.directory, &self.marker_bytes)?;
        } else {
            anyhow::ensure!(
                self.location == LaunchResidueLocation::Quarantine && names.is_empty(),
                "VMM launch residue lost its owner marker before quarantine"
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LaunchDirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    user: u32,
    group: u32,
}

#[cfg(target_os = "linux")]
impl LaunchDirectoryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            user: metadata.uid(),
            group: metadata.gid(),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LaunchLeafIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    user: u32,
    group: u32,
    links: u64,
}

#[cfg(target_os = "linux")]
impl LaunchLeafIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            user: metadata.uid(),
            group: metadata.gid(),
            links: metadata.nlink(),
        }
    }
}

#[cfg(target_os = "linux")]
fn launch_attempt_name(paths: &ManagedVmmLaunchFilePaths) -> Result<CString> {
    let directory = Path::new(paths.directory().as_str());
    let name = directory
        .file_name()
        .context("VMM launch attempt has no basename")?;
    let parent = directory
        .parent()
        .context("VMM launch attempt has no namespace parent")?;
    anyhow::ensure!(
        parent.file_name() == Some(OsStr::new(VMM_LAUNCH_FILE_NAMESPACE)),
        "VMM launch attempt names another namespace"
    );
    CString::new(name.as_bytes()).context("VMM launch attempt basename contains NUL")
}

#[cfg(target_os = "linux")]
fn quarantine_attempt_name(public: &CString) -> Result<CString> {
    let public = std::str::from_utf8(public.as_bytes())
        .context("VMM launch attempt basename is not UTF-8")?;
    let incarnation = public
        .strip_prefix("p-")
        .context("VMM launch attempt lacks its public prefix")?;
    CString::new(format!("{VMM_LAUNCH_QUARANTINE_PREFIX}{incarnation}"))
        .context("VMM launch quarantine basename contains NUL")
}

#[cfg(target_os = "linux")]
fn try_flock(file: &File, kind: i32) -> Result<bool> {
    // SAFETY: flock changes only the advisory lock associated with this live
    // descriptor. LOCK_NB guarantees a late holder is a refresh signal rather
    // than an unbounded wait inside the effect deadline.
    let result = unsafe { libc::flock(file.as_raw_fd(), kind | libc::LOCK_NB) };
    if result == 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(false)
        } else {
            Err(error).context("lock VMM launch namespace")
        }
    }
}

#[cfg(target_os = "linux")]
fn lock_flock(file: &File, kind: i32) -> Result<()> {
    loop {
        // SAFETY: flock changes only the advisory lock associated with this
        // live descriptor. A launcher waits here until the effect which
        // submitted it releases its exclusive proof guard after systemd has
        // completed the Type=exec boundary.
        let result = unsafe { libc::flock(file.as_raw_fd(), kind) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error).context("lock VMM launcher namespace");
        }
    }
}

#[cfg(target_os = "linux")]
fn ensure_launch_directory(
    metadata: &std::fs::Metadata,
    user: u32,
    group: u32,
    mode: u32,
) -> Result<()> {
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == user
            && metadata.gid() == group
            && metadata.nlink() > 0
            && metadata.mode() & 0o7777 == mode,
        "VMM launch directory has unsafe type, owner, links or mode"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_launch_leaf(metadata: &std::fs::Metadata, user: u32, group: u32) -> Result<()> {
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == user
            && metadata.gid() == group
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600,
        "VMM launch leaf has unsafe type, owner, links or mode"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_directory_at_name(parent: &File, name: &CString) -> Result<File> {
    open_at(
        parent,
        OsStr::from_bytes(name.as_bytes()),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .context("open VMM launch attempt")
}

#[cfg(target_os = "linux")]
fn open_launch_attempt(
    root: &RetainedManagedVmmLaunchRoot,
    name: &CString,
) -> Result<Option<File>> {
    match open_directory_at_name(&root.descriptor, name) {
        Ok(directory) => {
            ensure_launch_directory(
                &directory.metadata()?,
                root.identity.user,
                root.identity.group,
                0o700,
            )?;
            Ok(Some(directory))
        }
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|source| source.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn mkdir_launch_attempt(parent: &File, name: &CString) -> Result<()> {
    // SAFETY: parent/name remain live and mkdirat retains neither. EEXIST is
    // intentionally a no-replace conflict rather than an adoption result.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()).context("create no-replace VMM launch attempt")
    }
}

#[cfg(target_os = "linux")]
fn launch_attempt_names(directory: &File) -> Result<std::collections::BTreeSet<String>> {
    let entries = std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .context("enumerate VMM launch attempt")?;
    let mut names = std::collections::BTreeSet::new();
    for entry in entries {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM launch entry is not UTF-8"))?;
        anyhow::ensure!(
            names.insert(name) && names.len() <= 4,
            "VMM launch attempt exceeds its closed entry set"
        );
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn open_launch_leaf(directory: &File, name: &str) -> Result<Option<File>> {
    match open_at(
        directory,
        OsStr::new(name),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    ) {
        Ok(file) => {
            ensure_launch_leaf(
                &file.metadata()?,
                directory.metadata()?.uid(),
                directory.metadata()?.gid(),
            )?;
            Ok(Some(file))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("open VMM launch leaf"),
    }
}

#[cfg(target_os = "linux")]
fn create_launch_owner_marker(directory: &File, bytes: &[u8]) -> Result<()> {
    let name = CString::new(VMM_LAUNCH_OWNER_BASENAME).expect("fixed marker basename has no NUL");
    // SAFETY: directory/name remain live. O_EXCL/O_NOFOLLOW prohibit marker
    // replacement or alias adoption.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error()).context("create VMM launch owner marker");
    }
    // SAFETY: openat returned this one newly-owned descriptor.
    let mut marker = unsafe { File::from_raw_fd(descriptor) };
    marker.write_all(bytes)?;
    marker.sync_all()?;
    directory.sync_all()?;
    verify_launch_owner_marker(directory, bytes)
}

#[cfg(target_os = "linux")]
fn read_exact_launch_marker(marker: &File) -> Result<Vec<u8>> {
    let before = marker.metadata()?;
    ensure_launch_leaf(&before, before.uid(), before.gid())?;
    anyhow::ensure!(before.len() <= 16 * 1024, "VMM launch marker is too large");
    let clone = marker.try_clone()?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    clone.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 16 * 1024, "VMM launch marker grew");
    anyhow::ensure!(
        LaunchLeafIdentity::from_metadata(&before)
            == LaunchLeafIdentity::from_metadata(&marker.metadata()?),
        "VMM launch marker changed while read"
    );
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn verify_launch_owner_marker(directory: &File, expected: &[u8]) -> Result<()> {
    let marker = open_launch_leaf(directory, VMM_LAUNCH_OWNER_BASENAME)?
        .context("VMM launch owner marker is missing")?;
    anyhow::ensure!(
        read_exact_launch_marker(&marker)? == expected,
        "VMM launch owner marker differs from durable receipt"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_launch_attempt_entries(
    directory: &File,
    names: &std::collections::BTreeSet<String>,
) -> Result<()> {
    anyhow::ensure!(
        names.iter().all(|name| matches!(
            name.as_str(),
            VMM_LAUNCH_OWNER_BASENAME
                | VMM_MEMORY_BASENAME
                | VMM_SERIAL_LOG_BASENAME
                | VMM_LOG_BASENAME
        )),
        "VMM launch attempt contains a foreign entry"
    );
    for name in names {
        anyhow::ensure!(
            open_launch_leaf(directory, name)?.is_some(),
            "VMM launch entry disappeared"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn launch_attempt_leaf_identities(
    directory: &File,
    names: &std::collections::BTreeSet<String>,
) -> Result<std::collections::BTreeMap<String, LaunchLeafIdentity>> {
    names
        .iter()
        .map(|name| {
            let leaf = open_launch_leaf(directory, name)?
                .with_context(|| format!("VMM launch leaf {name} disappeared"))?;
            Ok((
                name.clone(),
                LaunchLeafIdentity::from_metadata(&leaf.metadata()?),
            ))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn unlink_isolated_launch_leaf(directory: &File, name: &str) -> Result<()> {
    let name = CString::new(name).expect("fixed launch basename has no NUL");
    // SAFETY: recovery has already moved this exact directory to the
    // deterministic quarantine and holds the exclusive launcher namespace
    // flock. All supported writers take the shared side before touching a
    // leaf, so the retained directory is the mutation authority here.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()).context("remove quarantined VMM launch leaf")
    }
}

#[cfg(target_os = "linux")]
fn rename_launch_attempt_noreplace(parent: &File, from: &CString, to: &CString) -> Result<()> {
    // SAFETY: both names are retained, NUL-free single components below the
    // same descriptor-rooted namespace. RENAME_NOREPLACE prevents adopting or
    // overwriting a pre-existing quarantine/public path.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()).context("rename no-replace VMM launch attempt")
    }
}

#[cfg(target_os = "linux")]
fn remove_isolated_launch_directory(parent: &File, name: &CString) -> Result<()> {
    // SAFETY: the exact retained quarantine was proven empty and all supported
    // writers remain excluded by the namespace flock.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()).context("remove empty VMM launch quarantine")
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LaunchAttemptSnapshot {
    directory: LaunchDirectoryIdentity,
    names: std::collections::BTreeSet<String>,
    leaves: std::collections::BTreeMap<String, LaunchLeafIdentity>,
}

/// Bounded accounting for every mutable VMM launch attempt. A current
/// StartRuntime may own one incarnation-derived directory only when the exact
/// durable receipt selected by the first namespace snapshot also matches its
/// owner marker. Missing attempt directories and missing receipts are valid
/// before physical publication; unknown names are preserved as residue.
#[cfg(target_os = "linux")]
pub(crate) fn scan_managed_vmm_launch_root(
    root: &RetainedManagedVmmLaunchRoot,
    socket_root: &RetainedManagedVmmSocketRoot,
    receipts: &VmmSocketReceiptStore,
    expected_checkpoints: &[&RuntimeCheckpoint],
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
) -> Result<ManagedVmmLaunchRootScan> {
    scan_managed_vmm_launch_root_with_receipt_policy(
        root,
        socket_root,
        receipts,
        expected_checkpoints,
        context,
        false,
    )
}

/// Recovery-only launch-file accounting which accepts exact old-boot receipt
/// bytes (including the receipt quarantine replay name). It grants no cleanup
/// authority by itself; the selected candidate still needs the launch-root EX
/// guard and the recovery-specific Node-global absence proof.
#[cfg(target_os = "linux")]
pub(crate) fn scan_managed_vmm_launch_root_for_stale_boot_recovery(
    root: &RetainedManagedVmmLaunchRoot,
    socket_root: &RetainedManagedVmmSocketRoot,
    receipts: &VmmSocketReceiptStore,
    expected_checkpoints: &[&RuntimeCheckpoint],
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
) -> Result<ManagedVmmLaunchRootScan> {
    scan_managed_vmm_launch_root_with_receipt_policy(
        root,
        socket_root,
        receipts,
        expected_checkpoints,
        context,
        true,
    )
}

#[cfg(target_os = "linux")]
fn scan_managed_vmm_launch_root_with_receipt_policy(
    root: &RetainedManagedVmmLaunchRoot,
    socket_root: &RetainedManagedVmmSocketRoot,
    receipts: &VmmSocketReceiptStore,
    expected_checkpoints: &[&RuntimeCheckpoint],
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    allow_stale_boot: bool,
) -> Result<ManagedVmmLaunchRootScan> {
    context.check_active()?;
    if root.assert_current().is_err()
        || socket_root.assert_current().is_err()
        || receipts.assert_current().is_err()
        || expected_checkpoints.len() > 1024
    {
        return Ok(ManagedVmmLaunchRootScan::Residue);
    }
    let first_receipts = if allow_stale_boot {
        scan_stale_boot_receipt_namespace_snapshot(
            socket_root,
            receipts,
            expected_checkpoints,
            context,
        )?
    } else {
        scan_receipt_namespace_snapshot(socket_root, receipts, expected_checkpoints, context)?
    };
    match &first_receipts {
        ReceiptNamespaceSnapshot::Exact(_) => {}
        ReceiptNamespaceSnapshot::Residue => return Ok(ManagedVmmLaunchRootScan::Residue),
        ReceiptNamespaceSnapshot::Unavailable => return Ok(ManagedVmmLaunchRootScan::Unavailable),
    }
    let first = match scan_launch_root_snapshot(
        root,
        receipts,
        &first_receipts,
        expected_checkpoints,
        context,
        allow_stale_boot,
    )? {
        Some(snapshot) => snapshot,
        None => return Ok(ManagedVmmLaunchRootScan::Unavailable),
    };
    let second = match scan_launch_root_snapshot(
        root,
        receipts,
        &first_receipts,
        expected_checkpoints,
        context,
        allow_stale_boot,
    )? {
        Some(snapshot) => snapshot,
        None => return Ok(ManagedVmmLaunchRootScan::Unavailable),
    };
    if first.contains_key("<foreign>") || second.contains_key("<foreign>") || first != second {
        return Ok(ManagedVmmLaunchRootScan::Residue);
    }
    let second_receipts = if allow_stale_boot {
        scan_stale_boot_receipt_namespace_snapshot(
            socket_root,
            receipts,
            expected_checkpoints,
            context,
        )?
    } else {
        scan_receipt_namespace_snapshot(socket_root, receipts, expected_checkpoints, context)?
    };
    match &second_receipts {
        ReceiptNamespaceSnapshot::Exact(_) => {}
        ReceiptNamespaceSnapshot::Residue => return Ok(ManagedVmmLaunchRootScan::Residue),
        ReceiptNamespaceSnapshot::Unavailable => return Ok(ManagedVmmLaunchRootScan::Unavailable),
    }
    if first_receipts != second_receipts || root.assert_current().is_err() {
        return Ok(ManagedVmmLaunchRootScan::Residue);
    }
    context.check_active()?;
    Ok(ManagedVmmLaunchRootScan::Accounted)
}

#[cfg(target_os = "linux")]
fn scan_launch_root_snapshot(
    root: &RetainedManagedVmmLaunchRoot,
    receipts: &VmmSocketReceiptStore,
    receipt_snapshot: &ReceiptNamespaceSnapshot,
    expected_checkpoints: &[&RuntimeCheckpoint],
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    allow_stale_boot: bool,
) -> Result<Option<std::collections::BTreeMap<String, LaunchAttemptSnapshot>>> {
    context.check_active()?;
    let mut expected = std::collections::BTreeMap::new();
    for checkpoint in expected_checkpoints {
        let paths = match ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            root.state_directory(),
            checkpoint,
        ) {
            Ok(paths) => paths,
            Err(_) => return Ok(Some(foreign_launch_snapshot())),
        };
        let public_name = launch_attempt_name(&paths)?;
        let quarantine_name = quarantine_attempt_name(&public_name)?;
        let public_name = public_name
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM launch attempt name is not UTF-8"))?;
        let quarantine_name = quarantine_name
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM launch quarantine name is not UTF-8"))?;
        if expected
            .insert(
                public_name.clone(),
                (
                    *checkpoint,
                    LaunchResidueLocation::Public,
                    public_name.clone(),
                ),
            )
            .is_some()
            || expected
                .insert(
                    quarantine_name,
                    (*checkpoint, LaunchResidueLocation::Quarantine, public_name),
                )
                .is_some()
        {
            return Ok(Some(foreign_launch_snapshot()));
        }
    }
    let entries = match std::fs::read_dir(format!("/proc/self/fd/{}", root.descriptor.as_raw_fd()))
    {
        Ok(entries) => entries,
        Err(_) => return Ok(None),
    };
    let mut snapshot = std::collections::BTreeMap::new();
    let mut seen_attempts = std::collections::BTreeSet::new();
    for entry in entries {
        context.check_active()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return Ok(None),
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => return Ok(Some(foreign_launch_snapshot())),
        };
        if snapshot.len() >= 1024 || snapshot.contains_key(&name) {
            return Ok(Some(foreign_launch_snapshot()));
        }
        let Some((checkpoint, location, public_name)) = expected.get(&name) else {
            return Ok(Some(foreign_launch_snapshot()));
        };
        if !seen_attempts.insert(public_name.clone()) {
            return Ok(Some(foreign_launch_snapshot()));
        }
        let name_c = match CString::new(name.as_bytes()) {
            Ok(name) => name,
            Err(_) => return Ok(Some(foreign_launch_snapshot())),
        };
        let directory = match open_directory_at_name(&root.descriptor, &name_c) {
            Ok(directory) => directory,
            Err(_) => return Ok(Some(foreign_launch_snapshot())),
        };
        if ensure_launch_directory(
            &directory.metadata()?,
            root.identity.user,
            root.identity.group,
            0o700,
        )
        .is_err()
        {
            return Ok(Some(foreign_launch_snapshot()));
        }
        let names = match launch_attempt_names(&directory) {
            Ok(names) => names,
            Err(_) => return Ok(Some(foreign_launch_snapshot())),
        };
        let receipt = if allow_stale_boot {
            receipt_snapshot.stale_boot_receipt_for_checkpoint(checkpoint)?
        } else {
            receipt_snapshot.receipt_for_checkpoint(checkpoint)?
        };
        let Some(receipt) = receipt else {
            return Ok(Some(foreign_launch_snapshot()));
        };
        let paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(root.state_directory(), checkpoint)?;
        let marker_present = names.contains(VMM_LAUNCH_OWNER_BASENAME);
        let recoverable_unmarked = names.is_empty()
            && matches!(
                location,
                LaunchResidueLocation::Public | LaunchResidueLocation::Quarantine
            );
        let receipt_paths_are_exact = if allow_stale_boot {
            receipt.validate_stale_boot_launch_paths(
                checkpoint,
                receipts.state_directory(),
                &paths,
                &current_kernel_node_boot_id()?,
            )
        } else {
            receipt.validate_launch_paths(checkpoint, receipts.state_directory(), &paths)
        };
        if receipt_paths_are_exact.is_err()
            || validate_launch_attempt_entries(&directory, &names).is_err()
            || (!marker_present && !recoverable_unmarked)
            || (marker_present
                && verify_launch_owner_marker(&directory, &receipt.encoded_bytes()?).is_err())
        {
            return Ok(Some(foreign_launch_snapshot()));
        }
        let mut leaves = std::collections::BTreeMap::new();
        for leaf in &names {
            let file = match open_launch_leaf(&directory, leaf) {
                Ok(Some(file)) => file,
                Ok(None) | Err(_) => return Ok(Some(foreign_launch_snapshot())),
            };
            leaves.insert(
                leaf.clone(),
                LaunchLeafIdentity::from_metadata(&file.metadata()?),
            );
        }
        snapshot.insert(
            name,
            LaunchAttemptSnapshot {
                directory: LaunchDirectoryIdentity::from_metadata(&directory.metadata()?),
                names,
                leaves,
            },
        );
    }
    context.check_active()?;
    Ok(Some(snapshot))
}

#[cfg(target_os = "linux")]
fn foreign_launch_snapshot() -> std::collections::BTreeMap<String, LaunchAttemptSnapshot> {
    std::collections::BTreeMap::from([(
        "<foreign>".to_owned(),
        LaunchAttemptSnapshot {
            directory: LaunchDirectoryIdentity {
                device: 0,
                inode: 0,
                mode: 0,
                user: 0,
                group: 0,
            },
            names: std::collections::BTreeSet::new(),
            leaves: std::collections::BTreeMap::new(),
        },
    )])
}

fn canonical_host_path(path: PathBuf, label: &str) -> Result<HostPath> {
    canonical_components(&path).with_context(|| format!("{label} is not canonical"))?;
    let path = path
        .to_str()
        .with_context(|| format!("{label} is not UTF-8"))?;
    HostPath::new(path.to_owned()).with_context(|| format!("{label} is not a canonical HostPath"))
}

#[derive(Debug, Clone)]
pub(crate) struct VmmRuntimePathRequirements {
    pub(crate) checkpoint_path: HostPath,
    pub(crate) checkpoint: RuntimeCheckpoint,
    pub(crate) original_checkpoint_content_digest: Sha256Digest,
    pub(crate) original_desired_revision: cats_api::runtime_reconciliation::Revision,
    pub(crate) original_spec_digest: Sha256Digest,
    pub(crate) original_placement_epoch: cats_api::runtime_reconciliation::Epoch,
    pub(crate) memory_file_path: HostPath,
    pub(crate) memory_bytes: u64,
    pub(crate) serial_log_path: HostPath,
    pub(crate) vmm_log_path: HostPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VmmRuntimePathInspection {
    Exact(std::sync::Arc<RetainedVmmRuntimePaths>),
    Conflict,
    Unavailable,
}

#[derive(Debug)]
pub(crate) struct RetainedVmmRuntimePaths {
    current_checkpoint: PinnedRuntimePath,
    #[cfg(target_os = "linux")]
    launch_checkpoint: PinnedRuntimeDescriptor,
    memory: PinnedRuntimePath,
    serial_log: PinnedRuntimePath,
    vmm_log: PinnedRuntimePath,
}

impl PartialEq for RetainedVmmRuntimePaths {
    fn eq(&self, other: &Self) -> bool {
        let common = self.current_checkpoint.identity == other.current_checkpoint.identity
            && self.memory.identity == other.memory.identity
            && self.serial_log.identity == other.serial_log.identity
            && self.vmm_log.identity == other.vmm_log.identity;
        #[cfg(target_os = "linux")]
        {
            common && self.launch_checkpoint.identity == other.launch_checkpoint.identity
        }
        #[cfg(not(target_os = "linux"))]
        {
            common
        }
    }
}

impl Eq for RetainedVmmRuntimePaths {}

impl RetainedVmmRuntimePaths {
    #[cfg(target_os = "linux")]
    pub(crate) fn open(
        requirements: &VmmRuntimePathRequirements,
        process_id: u32,
    ) -> Result<VmmRuntimePathInspection> {
        let Some(current_checkpoint) = Self::open_current_checkpoint(requirements)? else {
            return Ok(VmmRuntimePathInspection::Unavailable);
        };
        let launch_checkpoint =
            match PinnedRuntimeDescriptor::open_launch_checkpoint(process_id, requirements) {
                Ok(checkpoint) => checkpoint,
                Err(_) => return Ok(VmmRuntimePathInspection::Conflict),
            };
        Self::open_with_checkpoints(requirements, current_checkpoint, launch_checkpoint)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn open_with_launch_descriptor_for_test(
        requirements: &VmmRuntimePathRequirements,
        launch_checkpoint: File,
    ) -> Result<VmmRuntimePathInspection> {
        let Some(current_checkpoint) = Self::open_current_checkpoint(requirements)? else {
            return Ok(VmmRuntimePathInspection::Unavailable);
        };
        let launch_checkpoint = match PinnedRuntimeDescriptor::from_launch_checkpoint_descriptor(
            launch_checkpoint,
            requirements,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(_) => return Ok(VmmRuntimePathInspection::Conflict),
        };
        Self::open_with_checkpoints(requirements, current_checkpoint, launch_checkpoint)
    }

    #[cfg(target_os = "linux")]
    fn open_current_checkpoint(
        requirements: &VmmRuntimePathRequirements,
    ) -> Result<Option<PinnedRuntimePath>> {
        let checkpoint_bytes = encode_runtime_checkpoint(&requirements.checkpoint)
            .context("encode exact current Runtime checkpoint")?;
        PinnedRuntimePath::open(
            &requirements.checkpoint_path,
            LeafRule::ImmutableRegular {
                mode: 0o600,
                bytes: checkpoint_bytes,
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn open_with_checkpoints(
        requirements: &VmmRuntimePathRequirements,
        current_checkpoint: PinnedRuntimePath,
        launch_checkpoint: PinnedRuntimeDescriptor,
    ) -> Result<VmmRuntimePathInspection> {
        let Some(memory) = PinnedRuntimePath::open(
            &requirements.memory_file_path,
            LeafRule::Regular {
                mode: 0o600,
                length: Some(requirements.memory_bytes),
            },
        )?
        else {
            return Ok(VmmRuntimePathInspection::Unavailable);
        };
        let Some(serial_log) = PinnedRuntimePath::open(
            &requirements.serial_log_path,
            LeafRule::Regular {
                mode: 0o600,
                length: None,
            },
        )?
        else {
            return Ok(VmmRuntimePathInspection::Unavailable);
        };
        let Some(vmm_log) = PinnedRuntimePath::open(
            &requirements.vmm_log_path,
            LeafRule::Regular {
                mode: 0o600,
                length: None,
            },
        )?
        else {
            return Ok(VmmRuntimePathInspection::Unavailable);
        };
        let retained = Self {
            current_checkpoint,
            launch_checkpoint,
            memory,
            serial_log,
            vmm_log,
        };
        if retained.assert_current().is_err() {
            return Ok(VmmRuntimePathInspection::Conflict);
        }
        Ok(VmmRuntimePathInspection::Exact(std::sync::Arc::new(
            retained,
        )))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open(
        _requirements: &VmmRuntimePathRequirements,
        _process_id: u32,
    ) -> Result<VmmRuntimePathInspection> {
        Ok(VmmRuntimePathInspection::Unavailable)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn assert_current(&self) -> Result<()> {
        self.current_checkpoint
            .assert_current()
            .context("current Runtime checkpoint path changed")?;
        self.launch_checkpoint
            .assert_current()
            .context("inherited StartRuntime checkpoint descriptor changed")?;
        self.memory
            .assert_current()
            .context("VMM memory file path changed")?;
        self.serial_log
            .assert_current()
            .context("VMM serial log path changed")?;
        self.vmm_log
            .assert_current()
            .context("VMM log path changed")?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn assert_current(&self) -> Result<()> {
        anyhow::bail!("VMM runtime path proof is unavailable on this platform")
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn assert_fixed_descriptors(
        &self,
        process_id: u32,
        launch: VmmLaunchArtifactDescriptors<'_>,
    ) -> Result<()> {
        assert_process_fd(
            process_id,
            CHECKPOINT_FD,
            &self.launch_checkpoint.identity.leaf,
        )?;
        assert_process_fd(
            process_id,
            VMM_FD,
            &LeafIdentity::from_metadata(&launch.vmm_executable().metadata()?),
        )?;
        assert_process_fd(
            process_id,
            KERNEL_FD,
            &LeafIdentity::from_metadata(&launch.kernel().metadata()?),
        )?;
        match launch.initramfs() {
            Some(initramfs) => assert_process_fd(
                process_id,
                INITRAMFS_FD,
                &LeafIdentity::from_metadata(&initramfs.metadata()?),
            )?,
            None => assert_process_fd_absent(process_id, INITRAMFS_FD)?,
        }
        assert_process_fd(process_id, MEMORY_FD, &self.memory.leaf_identity)?;
        assert_process_fd(process_id, SERIAL_LOG_FD, &self.serial_log.leaf_identity)?;
        assert_process_fd(process_id, VMM_LOG_FD, &self.vmm_log.leaf_identity)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn assert_fixed_descriptors(
        &self,
        _process_id: u32,
        _launch: VmmLaunchArtifactDescriptors<'_>,
    ) -> Result<()> {
        anyhow::bail!("VMM fixed-descriptor proof is unavailable on this platform")
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PinnedRuntimeDescriptor {
    descriptor: File,
    identity: LaunchCheckpointDescriptorIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LaunchCheckpointDescriptorIdentity {
    leaf: LeafIdentity,
    bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl PinnedRuntimeDescriptor {
    fn open_launch_checkpoint(
        process_id: u32,
        requirements: &VmmRuntimePathRequirements,
    ) -> Result<Self> {
        anyhow::ensure!(process_id > 0, "VMM process ID is zero");
        let path = PathBuf::from(format!("/proc/{process_id}/fd/{CHECKPOINT_FD}"));
        let descriptor = open_path(&path, libc::O_RDONLY | libc::O_CLOEXEC)
            .context("open inherited VMM StartRuntime checkpoint fd64")?;
        Self::from_launch_checkpoint_descriptor(descriptor, requirements)
    }

    fn from_launch_checkpoint_descriptor(
        descriptor: File,
        requirements: &VmmRuntimePathRequirements,
    ) -> Result<Self> {
        let before = descriptor.metadata()?;
        ensure_inherited_checkpoint_leaf(&before)?;
        let length = usize::try_from(before.len())
            .context("inherited StartRuntime checkpoint length exceeds usize")?;
        anyhow::ensure!(
            length <= RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
            "inherited StartRuntime checkpoint exceeds the wire bound"
        );
        let bytes = read_file_exact_length(&descriptor, length)?;
        let after = descriptor.metadata()?;
        let leaf = LeafIdentity::from_metadata(&before);
        anyhow::ensure!(
            LeafIdentity::from_metadata(&after) == leaf,
            "inherited StartRuntime checkpoint changed while read"
        );
        let checkpoint = decode_runtime_checkpoint(&bytes)
            .context("decode inherited StartRuntime checkpoint")?;
        anyhow::ensure!(
            checkpoint_content_digest(&checkpoint)?
                == requirements.original_checkpoint_content_digest,
            "inherited StartRuntime checkpoint digest differs from durable receipt"
        );
        anyhow::ensure!(
            checkpoint.desired_revision == requirements.original_desired_revision,
            "inherited StartRuntime revision differs from durable receipt"
        );
        anyhow::ensure!(
            checkpoint.spec_digest == requirements.original_spec_digest,
            "inherited StartRuntime spec digest differs from durable receipt"
        );
        anyhow::ensure!(
            checkpoint.placement_epoch == requirements.original_placement_epoch,
            "inherited StartRuntime placement differs from durable receipt"
        );
        let current = RetainedRuntimeLaunchAuthority::from_checkpoint(&requirements.checkpoint)?;
        anyhow::ensure!(
            current.matches_launch_checkpoint(&checkpoint)?,
            "inherited StartRuntime checkpoint differs from retained launch authority"
        );
        Ok(Self {
            descriptor,
            identity: LaunchCheckpointDescriptorIdentity { leaf, bytes },
        })
    }

    fn assert_current(&self) -> Result<()> {
        let before = self.descriptor.metadata()?;
        anyhow::ensure!(
            LeafIdentity::from_metadata(&before) == self.identity.leaf,
            "retained StartRuntime checkpoint descriptor identity changed"
        );
        let bytes = read_file_exact_length(&self.descriptor, self.identity.bytes.len())?;
        let after = self.descriptor.metadata()?;
        anyhow::ensure!(
            LeafIdentity::from_metadata(&after) == self.identity.leaf
                && bytes == self.identity.bytes,
            "retained StartRuntime checkpoint descriptor changed"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn ensure_inherited_checkpoint_leaf(metadata: &std::fs::Metadata) -> Result<()> {
    // A successful checkpoint CAS atomically replaces the current pathname,
    // leaving the VMM's inherited descriptor on the original, unlinked inode
    // (`st_nlink == 0`). One remaining canonical pathname is also valid before
    // the first successor CAS; multiple links would make the original launch
    // bytes mutable through an unaccounted alias.
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() <= 1
            && metadata.mode() & 0o7777 == 0o600,
        "inherited StartRuntime checkpoint type, owner, links or mode changed"
    );
    Ok(())
}

#[derive(Debug)]
struct PinnedRuntimePath {
    logical_path: PathBuf,
    directories: Vec<PinnedDirectory>,
    leaf_name: CString,
    descriptor: File,
    leaf_identity: LeafIdentity,
    rule: LeafRule,
    identity: PathIdentity,
}

impl PinnedRuntimePath {
    #[cfg(target_os = "linux")]
    fn open(path: &HostPath, rule: LeafRule) -> Result<Option<Self>> {
        let logical_path = PathBuf::from(path.as_str());
        let components = canonical_components(&logical_path)?;
        let root = open_root()?;
        let mut current = root;
        let mut directories = Vec::with_capacity(components.len());
        for component in &components[..components.len() - 1] {
            let descriptor = match open_at(
                &current,
                component,
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) if unsafe_path_error(&error) => {
                    anyhow::bail!("VMM runtime path ancestor is unsafe: {error}")
                }
                Err(error) => return Err(error).context("open VMM runtime path ancestor"),
            };
            let metadata = descriptor.metadata()?;
            ensure_safe_directory(&metadata)?;
            directories.push(PinnedDirectory {
                name: component.clone(),
                identity: DirectoryIdentity::from_metadata(&metadata),
                descriptor,
            });
            current = directories
                .last()
                .expect("just pushed one directory")
                .descriptor
                .try_clone()?;
        }
        let leaf_name = CString::new(
            components
                .last()
                .expect("canonical absolute path has one component")
                .as_bytes(),
        )?;
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let descriptor = match open_at(&current, OsStr::from_bytes(leaf_name.as_bytes()), flags) {
            Ok(descriptor) => descriptor,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if unsafe_path_error(&error) => {
                anyhow::bail!("VMM runtime path leaf is unsafe: {error}")
            }
            Err(error) => return Err(error).context("open VMM runtime path leaf"),
        };
        let metadata = descriptor.metadata()?;
        ensure_leaf(&metadata, &rule)?;
        let leaf_identity = LeafIdentity::from_metadata_for_rule(&metadata, &rule);
        assert_leaf_content(&descriptor, &leaf_identity, &rule)?;
        let identity = PathIdentity {
            logical_path: logical_path.clone(),
            directories: directories.iter().map(|item| item.identity).collect(),
            leaf: leaf_identity,
            rule: rule.clone(),
        };
        Ok(Some(Self {
            logical_path,
            directories,
            leaf_name,
            descriptor,
            leaf_identity,
            rule,
            identity,
        }))
    }

    #[cfg(target_os = "linux")]
    fn assert_current(&self) -> Result<()> {
        let retained = self.descriptor.metadata()?;
        ensure_leaf(&retained, &self.rule)?;
        anyhow::ensure!(
            LeafIdentity::from_metadata_for_rule(&retained, &self.rule) == self.leaf_identity,
            "retained VMM runtime leaf identity changed"
        );
        assert_leaf_content(&self.descriptor, &self.leaf_identity, &self.rule)?;

        let components = canonical_components(&self.logical_path)?;
        let mut current = open_root()?;
        for (component, retained) in components[..components.len() - 1]
            .iter()
            .zip(&self.directories)
        {
            anyhow::ensure!(retained.name == *component, "VMM runtime path changed");
            let retained_metadata = retained.descriptor.metadata()?;
            ensure_safe_directory(&retained_metadata)?;
            anyhow::ensure!(
                DirectoryIdentity::from_metadata(&retained_metadata) == retained.identity,
                "retained VMM runtime ancestor changed"
            );
            let reopened = open_at(
                &current,
                component,
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let reopened_metadata = reopened.metadata()?;
            ensure_safe_directory(&reopened_metadata)?;
            anyhow::ensure!(
                DirectoryIdentity::from_metadata(&reopened_metadata) == retained.identity,
                "VMM runtime ancestor pathname changed"
            );
            current = reopened;
        }
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let reopened = open_at(
            &current,
            OsStr::from_bytes(self.leaf_name.as_bytes()),
            flags,
        )?;
        let metadata = reopened.metadata()?;
        ensure_leaf(&metadata, &self.rule)?;
        anyhow::ensure!(
            LeafIdentity::from_metadata_for_rule(&metadata, &self.rule) == self.leaf_identity,
            "VMM runtime leaf pathname changed"
        );
        assert_leaf_content(&reopened, &self.leaf_identity, &self.rule)
    }
}

#[derive(Debug)]
struct PinnedDirectory {
    name: std::ffi::OsString,
    descriptor: File,
    identity: DirectoryIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LeafRule {
    ImmutableRegular { mode: u32, bytes: Vec<u8> },
    Regular { mode: u32, length: Option<u64> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathIdentity {
    logical_path: PathBuf,
    directories: Vec<DirectoryIdentity>,
    leaf: LeafIdentity,
    rule: LeafRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    // Ancestors are shared namespaces: another Cat may add or remove a
    // sibling while this proof is retained. Pin the directory object and its
    // safety attributes; `ensure_safe_directory` separately requires a live
    // link at every sample. Child-dependent link counts and timestamps are
    // deliberately not identity.
    device: u64,
    inode: u64,
    mode: u32,
    user: u32,
    group: u32,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            user: metadata.uid(),
            group: metadata.gid(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeafIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    user: u32,
    group: u32,
    links: u64,
    length: u64,
}

impl LeafIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            user: metadata.uid(),
            group: metadata.gid(),
            links: metadata.nlink(),
            length: metadata.len(),
        }
    }

    fn from_metadata_for_rule(metadata: &std::fs::Metadata, rule: &LeafRule) -> Self {
        let mut identity = Self::from_metadata(metadata);
        if matches!(rule, LeafRule::Regular { length: None, .. }) {
            identity.length = 0;
        }
        identity
    }

    fn same_object(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.mode == other.mode
            && self.user == other.user
            && self.group == other.group
            && self.links == other.links
    }
}

fn canonical_components(path: &Path) -> Result<Vec<std::ffi::OsString>> {
    anyhow::ensure!(path.is_absolute(), "VMM runtime path is not absolute");
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => components.push(component.to_owned()),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                anyhow::bail!("VMM runtime path is not canonical")
            }
        }
    }
    anyhow::ensure!(!components.is_empty(), "VMM runtime path names the root");
    Ok(components)
}

#[cfg(target_os = "linux")]
fn open_root() -> Result<File> {
    let root = open_path(
        Path::new("/"),
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    ensure_safe_directory(&root.metadata()?)?;
    Ok(root)
}

fn open_path(path: &Path, flags: libc::c_int) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `path` is NUL-terminated for this call. A successful descriptor
    // is transferred exactly once into `File`.
    let descriptor = unsafe { libc::open(path.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned this new owned descriptor above.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_at(parent: &File, component: &OsStr, flags: libc::c_int) -> io::Result<File> {
    let component = CString::new(component.as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `parent` is live and `component` is NUL-terminated. A successful
    // descriptor is transferred exactly once into `File`.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned this new owned descriptor above.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn ensure_safe_directory(metadata: &std::fs::Metadata) -> Result<()> {
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() > 0
            && metadata.mode() & 0o022 == 0,
        "VMM runtime ancestor is not a safe root-owned directory"
    );
    Ok(())
}

fn ensure_leaf(metadata: &std::fs::Metadata, rule: &LeafRule) -> Result<()> {
    let expected_mode = match rule {
        LeafRule::ImmutableRegular { mode, .. } | LeafRule::Regular { mode, .. } => *mode,
    };
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == expected_mode,
        "VMM runtime leaf type, owner, links or mode changed"
    );
    if let LeafRule::Regular {
        length: Some(length),
        ..
    } = rule
    {
        anyhow::ensure!(metadata.len() == *length, "VMM runtime file length changed");
    }
    Ok(())
}

fn assert_leaf_content(file: &File, identity: &LeafIdentity, rule: &LeafRule) -> Result<()> {
    let LeafRule::ImmutableRegular { bytes, .. } = rule else {
        return Ok(());
    };
    anyhow::ensure!(
        identity.length == bytes.len() as u64,
        "checkpoint length changed"
    );
    let mut actual = vec![0_u8; bytes.len()];
    let mut offset = 0_usize;
    while offset < actual.len() {
        let read = file.read_at(&mut actual[offset..], offset as u64)?;
        anyhow::ensure!(read > 0, "StartRuntime checkpoint ended early");
        offset += read;
    }
    anyhow::ensure!(actual == *bytes, "StartRuntime checkpoint bytes changed");
    Ok(())
}

fn read_file_exact_length(file: &File, length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0_u8; length];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let read = file.read_at(&mut bytes[offset..], offset as u64)?;
        anyhow::ensure!(read > 0, "retained file ended early");
        offset += read;
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn assert_process_fd(process_id: u32, descriptor: i32, expected: &LeafIdentity) -> Result<()> {
    let path = PathBuf::from(format!("/proc/{process_id}/fd/{descriptor}"));
    let current = open_path(&path, libc::O_PATH | libc::O_CLOEXEC)
        .with_context(|| format!("open VMM fixed fd {descriptor}"))?;
    anyhow::ensure!(
        LeafIdentity::from_metadata(&current.metadata()?).same_object(expected),
        "VMM fixed fd {descriptor} changed"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn assert_process_fd_absent(process_id: u32, descriptor: i32) -> Result<()> {
    let path = PathBuf::from(format!("/proc/{process_id}/fd/{descriptor}"));
    match open_path(&path, libc::O_PATH | libc::O_CLOEXEC) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("unexpected VMM fixed fd {descriptor}"),
        Err(error) => Err(error).with_context(|| format!("inspect VMM fixed fd {descriptor}")),
    }
}

fn unsafe_path_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EINVAL)
    )
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        decode_runtime_checkpoint, ReconcileStep, RuntimeLaunch,
    };
    #[cfg(target_os = "linux")]
    use cats_api::runtime_reconciliation::{
        encode_runtime_checkpoint, Epoch, Id, Revision, StableState,
    };
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    use super::*;

    #[cfg(target_os = "linux")]
    use super::super::vmm_process::{ExactVmmProcessAbsenceProof, VmmProcessExpectation};
    #[cfg(target_os = "linux")]
    use crate::runtime::reconciliation::{
        vmm_socket_namespace::{current_kernel_node_boot_id, StaleVmmSocketReceiptScan},
        RetainedManagedVmmSocketRoot, VmmSocketReceiptStore,
    };

    fn start_runtime_checkpoint() -> RuntimeCheckpoint {
        decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap()
    }

    fn sync_retained_launch(checkpoint: &mut RuntimeCheckpoint) {
        checkpoint.runtime_launch = RuntimeLaunch::Present(Box::new(
            checkpoint
                .step
                .start_runtime_launch_identity()
                .expect("test checkpoint remains StartRuntime"),
        ));
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy)]
    enum RunningTail {
        OpenAdmission,
        InstallGate,
        Stable,
    }

    #[cfg(target_os = "linux")]
    fn running_tail_checkpoint(
        launch_checkpoint: &RuntimeCheckpoint,
        tail: RunningTail,
    ) -> RuntimeCheckpoint {
        let mut checkpoint = launch_checkpoint.clone();
        checkpoint.desired_revision =
            Revision::new(launch_checkpoint.desired_revision.get() + 1).unwrap();
        checkpoint.spec_digest = Sha256Digest::from_bytes([0x92; 32]);
        checkpoint.step = match tail {
            RunningTail::OpenAdmission => ReconcileStep::OpenAdmission {
                runtime_incarnation: checkpoint
                    .runtime_incarnation
                    .clone()
                    .expect("Running-tail fixture has an incarnation"),
            },
            RunningTail::InstallGate => ReconcileStep::InstallGate {
                endpoint_id: Id::new("endpoint_01").unwrap(),
                route_epoch: Epoch::new(1).unwrap(),
            },
            RunningTail::Stable => {
                checkpoint.stable_state = Some(StableState::Running);
                ReconcileStep::Stable {
                    state: StableState::Running,
                }
            }
        };
        if !matches!(tail, RunningTail::Stable) {
            checkpoint.stable_state = None;
        }
        encode_runtime_checkpoint(&checkpoint).unwrap_or_else(|error| {
            panic!("running-tail checkpoint is invalid: {:?}", error.error)
        });
        checkpoint
    }

    #[cfg(target_os = "linux")]
    fn launch_checkpoint_for_paths(root: &Path) -> RuntimeCheckpoint {
        let mut checkpoint = start_runtime_checkpoint();
        let ReconcileStep::StartRuntime {
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &mut checkpoint.step
        else {
            unreachable!()
        };
        *memory_file_path =
            HostPath::new(root.join("memory.bin").to_str().unwrap().to_owned()).unwrap();
        *serial_log_path =
            HostPath::new(root.join("serial.log").to_str().unwrap().to_owned()).unwrap();
        *vmm_log_path = HostPath::new(root.join("vmm.log").to_str().unwrap().to_owned()).unwrap();
        sync_retained_launch(&mut checkpoint);
        encode_runtime_checkpoint(&checkpoint).unwrap();
        checkpoint
    }

    #[cfg(target_os = "linux")]
    fn changed_launch_identity(checkpoint: &RuntimeCheckpoint) -> RuntimeCheckpoint {
        let mut changed = checkpoint.clone();
        let ReconcileStep::StartRuntime {
            process_identity_token,
            ..
        } = &mut changed.step
        else {
            unreachable!()
        };
        *process_identity_token = RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        sync_retained_launch(&mut changed);
        encode_runtime_checkpoint(&changed).unwrap();
        changed
    }

    #[cfg(target_os = "linux")]
    fn create_mode_600(path: &Path, bytes: &[u8]) -> File {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        file
    }

    #[cfg(target_os = "linux")]
    fn inspect_after_checkpoint_cas(
        tail: RunningTail,
        inherited_identity_drift: bool,
        current_identity_drift: bool,
        receipt_digest_drift: bool,
    ) -> VmmRuntimePathInspection {
        let temporary = tempfile::Builder::new()
            .prefix("cats-fd64-")
            // `/root` is Cargo's live cache parent in the Linux gate. Its
            // metadata can legitimately change while another test builds a
            // helper, invalidating an otherwise exact retained ancestor.
            .tempdir_in("/var/lib")
            .unwrap();
        let root = temporary.path();
        let original = launch_checkpoint_for_paths(root);
        let changed = changed_launch_identity(&original);
        let inherited = if inherited_identity_drift {
            &changed
        } else {
            &original
        };
        let current_launch = if current_identity_drift {
            &changed
        } else {
            &original
        };
        let current = running_tail_checkpoint(current_launch, tail);

        let checkpoint_path = root.join("checkpoint.json");
        let original_file = create_mode_600(
            &checkpoint_path,
            &encode_runtime_checkpoint(inherited).unwrap(),
        );
        let replacement_path = root.join("checkpoint.next");
        create_mode_600(
            &replacement_path,
            &encode_runtime_checkpoint(&current).unwrap(),
        );
        std::fs::rename(&replacement_path, &checkpoint_path).unwrap();

        let launch = current.runtime_launch.identity().unwrap();
        let memory_file_path = launch.memory_file_path.clone();
        let memory_bytes = launch.memory_bytes;
        let serial_log_path = launch.serial_log_path.clone();
        let vmm_log_path = launch.vmm_log_path.clone();
        let memory = create_mode_600(Path::new(memory_file_path.as_str()), &[]);
        memory.set_len(memory_bytes).unwrap();
        memory.sync_all().unwrap();
        create_mode_600(Path::new(serial_log_path.as_str()), &[]);
        create_mode_600(Path::new(vmm_log_path.as_str()), &[]);
        let mut receipt_digest = checkpoint_content_digest(&original).unwrap();
        if receipt_digest_drift {
            receipt_digest = Sha256Digest::from_bytes([0xabu8; 32]);
        }
        let requirements = VmmRuntimePathRequirements {
            checkpoint_path: HostPath::new(checkpoint_path.to_str().unwrap().to_owned()).unwrap(),
            checkpoint: current,
            original_checkpoint_content_digest: receipt_digest,
            original_desired_revision: original.desired_revision,
            original_spec_digest: original.spec_digest.clone(),
            original_placement_epoch: original.placement_epoch,
            memory_file_path,
            memory_bytes,
            serial_log_path,
            vmm_log_path,
        };
        let inspection = RetainedVmmRuntimePaths::open_with_launch_descriptor_for_test(
            &requirements,
            original_file,
        )
        .unwrap();
        if let VmmRuntimePathInspection::Exact(retained) = &inspection {
            retained.assert_current().unwrap();
        }
        drop(temporary);
        inspection
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd64_retains_original_launch_across_admission_gate_and_stable_checkpoint_cas() {
        // The production ancestry contract requires root-owned scratch; the
        // Docker and metal root gates execute the full body.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: root-owned VMM runtime ancestry requires the root gates");
            return;
        }
        for tail in [
            RunningTail::OpenAdmission,
            RunningTail::InstallGate,
            RunningTail::Stable,
        ] {
            let inspection = inspect_after_checkpoint_cas(tail, false, false, false);
            assert!(
                matches!(&inspection, VmmRuntimePathInspection::Exact(_)),
                "{tail:?}: {inspection:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd64_rejects_receipt_old_bytes_and_current_retained_identity_drift() {
        // The production ancestry contract requires root-owned scratch; the
        // Docker and metal root gates execute the full body.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: root-owned VMM runtime ancestry requires the root gates");
            return;
        }
        assert!(matches!(
            inspect_after_checkpoint_cas(RunningTail::OpenAdmission, false, false, true),
            VmmRuntimePathInspection::Conflict
        ));
        assert!(matches!(
            inspect_after_checkpoint_cas(RunningTail::OpenAdmission, true, false, false),
            VmmRuntimePathInspection::Conflict
        ));
        assert!(matches!(
            inspect_after_checkpoint_cas(RunningTail::OpenAdmission, false, true, false),
            VmmRuntimePathInspection::Conflict
        ));
    }

    #[cfg(target_os = "linux")]
    fn pinned_runtime_path_fixture() -> (tempfile::TempDir, PathBuf, PinnedRuntimePath) {
        let temporary = tempfile::Builder::new()
            .prefix("cats-runtime-path-")
            .tempdir_in("/var/lib")
            .unwrap();
        let ancestor = temporary.path().join("runtime");
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::set_permissions(
            &ancestor,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let leaf = ancestor.join("checkpoint.json");
        create_mode_600(&leaf, b"exact-checkpoint");
        let path = HostPath::new(leaf.to_str().unwrap().to_owned()).unwrap();
        let retained = PinnedRuntimePath::open(
            &path,
            LeafRule::ImmutableRegular {
                mode: 0o600,
                bytes: b"exact-checkpoint".to_vec(),
            },
        )
        .unwrap()
        .unwrap();
        (temporary, ancestor, retained)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_runtime_path_allows_sibling_children_in_the_same_live_ancestor() {
        // The production ancestry contract requires root-owned scratch; the
        // Docker and metal root gates execute the full body.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: root-owned VMM runtime ancestry requires the root gates");
            return;
        }
        let (_temporary, ancestor, retained) = pinned_runtime_path_fixture();
        let original = ancestor.metadata().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let sibling = ancestor.join("another-cat");
        std::fs::create_dir(&sibling).unwrap();
        std::fs::set_permissions(
            &sibling,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let with_sibling = ancestor.metadata().unwrap();
        assert!(
            original.nlink() != with_sibling.nlink()
                || original.mtime() != with_sibling.mtime()
                || original.mtime_nsec() != with_sibling.mtime_nsec()
                || original.ctime() != with_sibling.ctime()
                || original.ctime_nsec() != with_sibling.ctime_nsec(),
            "fixture did not change mutable ancestor metadata"
        );
        retained.assert_current().unwrap();

        std::fs::remove_dir(&sibling).unwrap();
        retained.assert_current().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_runtime_path_rejects_an_ancestor_pathname_replacement() {
        // The production ancestry contract requires root-owned scratch; the
        // Docker and metal root gates execute the full body.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: root-owned VMM runtime ancestry requires the root gates");
            return;
        }
        let (_temporary, ancestor, retained) = pinned_runtime_path_fixture();
        let saved = ancestor.with_extension("saved");
        std::fs::rename(&ancestor, &saved).unwrap();
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::set_permissions(
            &ancestor,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        create_mode_600(&ancestor.join("checkpoint.json"), b"exact-checkpoint");

        assert!(retained.assert_current().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mutable_launch_root_remains_exact_across_owned_child_link_count_changes() {
        let temporary = tempfile::Builder::new()
            .prefix("cats-launch-root-links-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let state_path = temporary.path().join("state");
        std::fs::create_dir(&state_path).unwrap();
        std::fs::set_permissions(
            &state_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let namespace = state_path.join(VMM_LAUNCH_FILE_NAMESPACE);
        std::fs::create_dir(&namespace).unwrap();
        std::fs::set_permissions(
            &namespace,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root =
            RetainedManagedVmmLaunchRoot::open_existing(StateDirectory::unanchored(state_path))
                .unwrap();
        let original_links = root.descriptor.metadata().unwrap().nlink();
        let attempt = CString::new("inc-test").unwrap();

        mkdir_launch_attempt(&root.descriptor, &attempt).unwrap();
        let links_with_child = root.descriptor.metadata().unwrap().nlink();
        assert_eq!(
            links_with_child,
            original_links + 1,
            "tmpfs fixture did not exercise mutable directory link counts"
        );
        root.assert_current().unwrap();

        remove_isolated_launch_directory(&root.descriptor, &attempt).unwrap();
        assert_eq!(root.descriptor.metadata().unwrap().nlink(), original_links);
        root.assert_current().unwrap();
    }

    #[cfg(target_os = "linux")]
    struct LaunchFixture {
        _temporary: tempfile::TempDir,
        checkpoint: RuntimeCheckpoint,
        socket_root: RetainedManagedVmmSocketRoot,
        receipt_store: VmmSocketReceiptStore,
        receipt: VmmSocketOwnershipReceiptV1,
        launch_root: Arc<RetainedManagedVmmLaunchRoot>,
    }

    #[cfg(target_os = "linux")]
    impl LaunchFixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let state_path = temporary.path().join("state");
            std::fs::create_dir(&state_path).unwrap();
            std::fs::set_permissions(
                &state_path,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let launch_namespace = state_path.join(VMM_LAUNCH_FILE_NAMESPACE);
            std::fs::create_dir(&launch_namespace).unwrap();
            std::fs::set_permissions(
                &launch_namespace,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let state = StateDirectory::unanchored(state_path);
            let socket_root =
                RetainedManagedVmmSocketRoot::provision_for_test(&temporary.path().join("sockets"))
                    .unwrap();
            let mut checkpoint = start_runtime_checkpoint();
            let incarnation = checkpoint.runtime_incarnation.as_ref().unwrap().clone();
            let sockets = socket_root.planner().paths_for(&incarnation).unwrap();
            let files = ManagedVmmLaunchFilePaths::for_incarnation(&state, &incarnation).unwrap();
            let ReconcileStep::StartRuntime {
                api_socket_path,
                vsock_socket_path,
                memory_file_path,
                serial_log_path,
                vmm_log_path,
                ..
            } = &mut checkpoint.step
            else {
                unreachable!()
            };
            *api_socket_path = sockets.api_socket_path().clone();
            *vsock_socket_path = sockets.vsock_socket_path().clone();
            *memory_file_path = files.memory_file_path().clone();
            *serial_log_path = files.serial_log_path().clone();
            *vmm_log_path = files.vmm_log_path().clone();
            sync_retained_launch(&mut checkpoint);
            let receipt_store = VmmSocketReceiptStore::provision_for_test(state.clone()).unwrap();
            let receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
                &checkpoint,
                &state,
                &socket_root,
                current_kernel_node_boot_id().unwrap(),
                RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            )
            .unwrap();
            let launch_root = Arc::new(RetainedManagedVmmLaunchRoot::open_existing(state).unwrap());
            Self {
                _temporary: temporary,
                checkpoint,
                socket_root,
                receipt_store,
                receipt,
                launch_root,
            }
        }

        fn absence(&self) -> super::super::vmm_process::ExactVmmProcessAbsenceProof {
            let expectation = super::super::vmm_process::VmmProcessExpectation::from_checkpoint(
                self.checkpoint.clone(),
            )
            .unwrap()
            .with_checkpoint_path(
                cats_api::runtime_reconciliation::HostPath::new(
                    "/var/lib/cats/node/test/checkpoints/cat_01.json".to_owned(),
                )
                .unwrap(),
            )
            .unwrap();
            super::super::vmm_process::ExactVmmProcessAbsenceProof::for_expectation(expectation)
        }

        fn prepare(&self) -> ManagedVmmLaunchPreparation {
            let guard = self
                .launch_root
                .try_lock_effect_namespace()
                .unwrap()
                .expect("test launch namespace is unlocked");
            let authority = guard
                .bind_fresh_absence(self.absence(), &self.checkpoint)
                .unwrap();
            self.launch_root
                .prepare_existing_receipt(&authority, &self.checkpoint, &self.receipt)
                .unwrap()
        }

        fn recover(&self, residue: RetainedManagedVmmLaunchResidue) {
            let guard = self
                .launch_root
                .try_lock_effect_namespace()
                .unwrap()
                .expect("test launch namespace is unlocked");
            let authority = guard
                .bind_fresh_absence(self.absence(), &self.checkpoint)
                .unwrap();
            residue.recover(&authority, &self.checkpoint).unwrap();
        }

        fn publish_as_stale_boot(&mut self) {
            let current = current_kernel_node_boot_id().unwrap();
            let candidate = ["e".repeat(32), "f".repeat(32)]
                .into_iter()
                .map(|value| NodeBootId::new(value).unwrap())
                .find(|value| value != &current)
                .unwrap();
            self.receipt.set_node_boot_id_for_test(candidate);
            self.receipt_store.publish(&self.receipt).unwrap();
        }

        fn stale_candidate(&self) -> RetainedStaleVmmSocketReceipt {
            match self
                .receipt_store
                .retain_one_stale_boot_receipt(
                    &self.socket_root,
                    &[&self.checkpoint],
                    &scan_context(),
                )
                .unwrap()
            {
                StaleVmmSocketReceiptScan::Candidate(candidate) => *candidate,
                StaleVmmSocketReceiptScan::Settled => panic!("stale receipt was not selected"),
            }
        }

        fn recover_stale(&self) -> Result<bool> {
            self.launch_root.recover_stale_boot_receipt(
                &self.socket_root,
                &self.receipt_store,
                &self.checkpoint,
                self.stale_candidate(),
                &scan_context(),
                |guard| {
                    guard.assert_for(&self.launch_root)?;
                    anyhow::ensure!(
                        self.launch_root.try_lock_effect_namespace()?.is_none(),
                        "fresh global absence callback ran without launch-root exclusion"
                    );
                    Ok(self.absence())
                },
            )
        }
    }

    #[cfg(target_os = "linux")]
    struct TestPhysicalContext(std::time::Instant);

    #[cfg(target_os = "linux")]
    impl crate::runtime_spine::RuntimePhysicalReadContext for TestPhysicalContext {
        fn deadline(&self) -> std::time::Instant {
            self.0
        }

        fn check_active(&self) -> Result<()> {
            anyhow::ensure!(std::time::Instant::now() < self.0, "test deadline expired");
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn scan_context() -> TestPhysicalContext {
        TestPhysicalContext(std::time::Instant::now() + std::time::Duration::from_secs(5))
    }

    #[test]
    fn launch_file_mapping_is_state_selected_and_incarnation_exact() {
        let root = tempfile::tempdir().unwrap();
        let state = StateDirectory::unanchored(root.path().to_path_buf());
        let mut checkpoint = start_runtime_checkpoint();
        let incarnation = checkpoint.runtime_incarnation.as_ref().unwrap().clone();
        let paths = ManagedVmmLaunchFilePaths::for_incarnation(&state, &incarnation).unwrap();
        let expected_directory = root
            .path()
            .join("vmm-launch-v1/p-55555555555555555555555555555555");
        assert_eq!(
            paths.directory().as_str(),
            expected_directory.to_str().unwrap()
        );
        assert_eq!(
            paths.memory_file_path().as_str(),
            expected_directory.join("memory.bin").to_str().unwrap()
        );
        assert_eq!(
            paths.serial_log_path().as_str(),
            expected_directory.join("serial.log").to_str().unwrap()
        );
        assert_eq!(
            paths.vmm_log_path().as_str(),
            expected_directory.join("vmm.log").to_str().unwrap()
        );
        assert!(ManagedVmmLaunchFilePaths::paths_from_checkpoint(&state, &checkpoint).is_err());
        let ReconcileStep::StartRuntime {
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &mut checkpoint.step
        else {
            unreachable!()
        };
        *memory_file_path = paths.memory_file_path().clone();
        *serial_log_path = paths.serial_log_path().clone();
        *vmm_log_path = paths.vmm_log_path().clone();
        sync_retained_launch(&mut checkpoint);
        assert_eq!(
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(&state, &checkpoint).unwrap(),
            paths
        );
    }

    #[test]
    fn launch_file_mapping_rejects_a_noncanonical_state_root() {
        let state = StateDirectory::unanchored(PathBuf::from("relative-state"));
        let checkpoint = start_runtime_checkpoint();
        assert!(ManagedVmmLaunchFilePaths::for_incarnation(
            &state,
            checkpoint.runtime_incarnation.as_ref().unwrap()
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_attempt_prepare_is_no_replace_and_recovers_only_exact_residue() {
        let fixture = LaunchFixture::new();
        fixture.receipt_store.publish(&fixture.receipt).unwrap();
        let ready = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Ready(ready) => ready,
            ManagedVmmLaunchPreparation::PublishedIntent
            | ManagedVmmLaunchPreparation::Residue(_) => panic!("fresh attempt recovered"),
        };
        ready.assert_ready().unwrap();
        let paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            fixture.launch_root.state_directory(),
            &fixture.checkpoint,
        )
        .unwrap();
        let mut memory = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(paths.memory_file_path().as_str())
            .unwrap();
        memory.write_all(b"partial-launch").unwrap();
        memory.sync_all().unwrap();
        drop(memory);
        let residue = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Residue(residue) => *residue,
            _ => panic!("partial attempt was not retained as residue"),
        };
        assert!(Path::new(paths.memory_file_path().as_str()).exists());
        fixture.recover(residue);
        assert!(!Path::new(paths.directory().as_str()).exists());
        match fixture.prepare() {
            ManagedVmmLaunchPreparation::Ready(ready) => ready.assert_ready().unwrap(),
            ManagedVmmLaunchPreparation::PublishedIntent
            | ManagedVmmLaunchPreparation::Residue(_) => {
                panic!("settled attempt did not become ready")
            }
        }

        let foreign = Path::new(paths.directory().as_str()).join("foreign");
        std::fs::write(&foreign, b"foreign").unwrap();
        let guard = fixture
            .launch_root
            .try_lock_effect_namespace()
            .unwrap()
            .unwrap();
        let authority = guard
            .bind_fresh_absence(fixture.absence(), &fixture.checkpoint)
            .unwrap();
        assert!(fixture
            .launch_root
            .prepare_existing_receipt(&authority, &fixture.checkpoint, &fixture.receipt,)
            .is_err());
        assert_eq!(std::fs::read(foreign).unwrap(), b"foreign");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_root_scan_accounts_receipt_only_and_exact_attempt_but_rejects_foreign() {
        let fixture = LaunchFixture::new();
        fixture.receipt_store.publish(&fixture.receipt).unwrap();
        assert_eq!(
            scan_managed_vmm_launch_root(
                &fixture.launch_root,
                &fixture.socket_root,
                &fixture.receipt_store,
                &[&fixture.checkpoint],
                &scan_context(),
            )
            .unwrap(),
            ManagedVmmLaunchRootScan::Accounted
        );
        match fixture.prepare() {
            ManagedVmmLaunchPreparation::Ready(ready) => ready.assert_ready().unwrap(),
            ManagedVmmLaunchPreparation::PublishedIntent
            | ManagedVmmLaunchPreparation::Residue(_) => panic!("fresh attempt recovered"),
        }
        assert_eq!(
            scan_managed_vmm_launch_root(
                &fixture.launch_root,
                &fixture.socket_root,
                &fixture.receipt_store,
                &[&fixture.checkpoint],
                &scan_context(),
            )
            .unwrap(),
            ManagedVmmLaunchRootScan::Accounted
        );
        let foreign = fixture
            .launch_root
            .state_directory()
            .path()
            .join(VMM_LAUNCH_FILE_NAMESPACE)
            .join("p-foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::set_permissions(
            &foreign,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        assert_eq!(
            scan_managed_vmm_launch_root(
                &fixture.launch_root,
                &fixture.socket_root,
                &fixture.receipt_store,
                &[&fixture.checkpoint],
                &scan_context(),
            )
            .unwrap(),
            ManagedVmmLaunchRootScan::Residue
        );
        assert!(foreign.is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_boot_receipt_recovery_is_replayable_and_drains_exact_launch_residue() {
        for tail in [
            RunningTail::OpenAdmission,
            RunningTail::InstallGate,
            RunningTail::Stable,
        ] {
            for with_residue in [false, true] {
                let mut fixture = LaunchFixture::new();
                fixture.checkpoint = running_tail_checkpoint(&fixture.checkpoint, tail);
                fixture.publish_as_stale_boot();
                let paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
                    fixture.launch_root.state_directory(),
                    &fixture.checkpoint,
                )
                .unwrap();
                if with_residue {
                    std::fs::create_dir(paths.directory().as_str()).unwrap();
                    std::fs::set_permissions(
                        paths.directory().as_str(),
                        std::os::unix::fs::PermissionsExt::from_mode(0o700),
                    )
                    .unwrap();
                    let directory = open_launch_attempt(
                        &fixture.launch_root,
                        &launch_attempt_name(&paths).unwrap(),
                    )
                    .unwrap()
                    .unwrap();
                    create_launch_owner_marker(
                        &directory,
                        &fixture.receipt.encoded_bytes().unwrap(),
                    )
                    .unwrap();
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(paths.memory_file_path().as_str())
                        .unwrap()
                        .write_all(b"old-boot-partial-memory")
                        .unwrap();
                    directory.sync_all().unwrap();
                }

                assert!(fixture.recover_stale().unwrap());
                assert!(!Path::new(paths.directory().as_str()).exists());
                assert!(fixture
                    .receipt_store
                    .load(fixture.receipt.runtime_incarnation())
                    .unwrap()
                    .is_none());
                assert!(matches!(
                    fixture
                        .receipt_store
                        .retain_one_stale_boot_receipt(
                            &fixture.socket_root,
                            &[&fixture.checkpoint],
                            &scan_context(),
                        )
                        .unwrap(),
                    StaleVmmSocketReceiptScan::Settled
                ));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn multiple_stale_boot_cats_recover_one_per_round_without_mutating_the_other() {
        let mut fixture = LaunchFixture::new();
        fixture.publish_as_stale_boot();
        let mut second = fixture.checkpoint.clone();
        second.cat_id = Id::new("cat_02").unwrap();
        let second_incarnation = RandomId128::new("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        second.runtime_incarnation = Some(second_incarnation.clone());
        let second_sockets = fixture
            .socket_root
            .planner()
            .paths_for(&second_incarnation)
            .unwrap();
        let second_files = ManagedVmmLaunchFilePaths::for_incarnation(
            fixture.launch_root.state_directory(),
            &second_incarnation,
        )
        .unwrap();
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            scope_id,
            process_identity_token,
            api_socket_path,
            vsock_socket_path,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &mut second.step
        else {
            unreachable!()
        };
        *runtime_incarnation = second_incarnation.clone();
        *scope_id = Id::new(format!("cats-vmm-{}.service", second_incarnation.as_str())).unwrap();
        *process_identity_token = RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        *api_socket_path = second_sockets.api_socket_path().clone();
        *vsock_socket_path = second_sockets.vsock_socket_path().clone();
        *memory_file_path = second_files.memory_file_path().clone();
        *serial_log_path = second_files.serial_log_path().clone();
        *vmm_log_path = second_files.vmm_log_path().clone();
        sync_retained_launch(&mut second);
        let mut second_receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
            &second,
            fixture.receipt_store.state_directory(),
            &fixture.socket_root,
            current_kernel_node_boot_id().unwrap(),
            RandomId128::new("dddddddddddddddddddddddddddddddd").unwrap(),
        )
        .unwrap();
        second_receipt.set_node_boot_id_for_test(fixture.receipt.node_boot_id().clone());
        fixture.receipt_store.publish(&second_receipt).unwrap();

        for (checkpoint, receipt) in [
            (&fixture.checkpoint, &fixture.receipt),
            (&second, &second_receipt),
        ] {
            let paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
                fixture.launch_root.state_directory(),
                checkpoint,
            )
            .unwrap();
            std::fs::create_dir(paths.directory().as_str()).unwrap();
            std::fs::set_permissions(
                paths.directory().as_str(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let directory =
                open_launch_attempt(&fixture.launch_root, &launch_attempt_name(&paths).unwrap())
                    .unwrap()
                    .unwrap();
            create_launch_owner_marker(&directory, &receipt.encoded_bytes().unwrap()).unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(paths.memory_file_path().as_str())
                .unwrap()
                .write_all(b"old-boot-memory")
                .unwrap();
            directory.sync_all().unwrap();
        }
        let second_directory_before = std::fs::metadata(second_files.directory().as_str()).unwrap();
        let foreign = Path::new(second_files.directory().as_str()).join("foreign");
        std::fs::write(&foreign, b"foreign").unwrap();
        assert_eq!(
            scan_managed_vmm_launch_root_for_stale_boot_recovery(
                &fixture.launch_root,
                &fixture.socket_root,
                &fixture.receipt_store,
                &[&fixture.checkpoint, &second],
                &scan_context(),
            )
            .unwrap(),
            ManagedVmmLaunchRootScan::Residue
        );
        assert!(Path::new(
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(
                fixture.launch_root.state_directory(),
                &fixture.checkpoint,
            )
            .unwrap()
            .directory()
            .as_str()
        )
        .is_dir());
        assert!(fixture
            .receipt_store
            .load(fixture.receipt.runtime_incarnation())
            .unwrap()
            .is_some());
        std::fs::remove_file(&foreign).unwrap();

        let expected_checkpoints = [&fixture.checkpoint, &second];
        for expected_incarnation in [
            fixture.receipt.runtime_incarnation().clone(),
            second_receipt.runtime_incarnation().clone(),
        ] {
            let candidate = match fixture
                .receipt_store
                .retain_one_stale_boot_receipt(
                    &fixture.socket_root,
                    &expected_checkpoints,
                    &scan_context(),
                )
                .unwrap()
            {
                StaleVmmSocketReceiptScan::Candidate(candidate) => *candidate,
                StaleVmmSocketReceiptScan::Settled => panic!("stale round lacked a candidate"),
            };
            assert_eq!(
                candidate.receipt().runtime_incarnation(),
                &expected_incarnation
            );
            let checkpoint = expected_checkpoints
                .iter()
                .copied()
                .find(|checkpoint| {
                    checkpoint.runtime_incarnation.as_ref() == Some(&expected_incarnation)
                })
                .unwrap();
            let expectation = VmmProcessExpectation::from_checkpoint(checkpoint.clone())
                .unwrap()
                .with_checkpoint_path(
                    HostPath::new(format!(
                        "/var/lib/cats/checkpoints/{expected_incarnation}.json"
                    ))
                    .unwrap(),
                )
                .unwrap();
            let absence = ExactVmmProcessAbsenceProof::for_expectation(expectation);
            assert!(fixture
                .launch_root
                .recover_stale_boot_receipt(
                    &fixture.socket_root,
                    &fixture.receipt_store,
                    checkpoint,
                    candidate,
                    &scan_context(),
                    |_| {
                        anyhow::ensure!(
                            scan_managed_vmm_launch_root_for_stale_boot_recovery(
                                &fixture.launch_root,
                                &fixture.socket_root,
                                &fixture.receipt_store,
                                &expected_checkpoints,
                                &scan_context(),
                            )? == ManagedVmmLaunchRootScan::Accounted,
                            "complete stale launch set changed"
                        );
                        Ok(absence)
                    },
                )
                .unwrap());
            if expected_incarnation == *fixture.receipt.runtime_incarnation() {
                let second_directory_after =
                    std::fs::metadata(second_files.directory().as_str()).unwrap();
                assert_eq!(second_directory_before.ino(), second_directory_after.ino());
                assert_eq!(
                    fixture
                        .receipt_store
                        .load(second_receipt.runtime_incarnation())
                        .unwrap(),
                    Some(second_receipt.clone())
                );
            }
        }
        assert!(matches!(
            fixture
                .receipt_store
                .retain_one_stale_boot_receipt(
                    &fixture.socket_root,
                    &expected_checkpoints,
                    &scan_context(),
                )
                .unwrap(),
            StaleVmmSocketReceiptScan::Settled
        ));
        assert!(!Path::new(second_files.directory().as_str()).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_boot_recovery_preserves_current_socket_and_foreign_launch_replacements() {
        let mut socket_replacement = LaunchFixture::new();
        socket_replacement.publish_as_stale_boot();
        let socket_paths = socket_replacement
            .socket_root
            .planner()
            .paths_from_checkpoint(&socket_replacement.checkpoint)
            .unwrap();
        let public_socket_directory = socket_replacement.socket_root.planner().path().as_str();
        let public_socket_directory =
            Path::new(public_socket_directory).join(socket_paths.public_name());
        std::fs::create_dir(&public_socket_directory).unwrap();
        std::fs::set_permissions(
            &public_socket_directory,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        assert!(socket_replacement.recover_stale().is_err());
        assert!(public_socket_directory.is_dir());
        assert!(socket_replacement
            .receipt_store
            .load(socket_replacement.receipt.runtime_incarnation())
            .unwrap()
            .is_some());

        let mut launch_replacement = LaunchFixture::new();
        launch_replacement.publish_as_stale_boot();
        let paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            launch_replacement.launch_root.state_directory(),
            &launch_replacement.checkpoint,
        )
        .unwrap();
        std::fs::create_dir(paths.directory().as_str()).unwrap();
        std::fs::set_permissions(
            paths.directory().as_str(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let foreign = Path::new(paths.directory().as_str()).join("foreign");
        std::fs::write(&foreign, b"replacement").unwrap();
        assert!(launch_replacement.recover_stale().is_err());
        assert_eq!(std::fs::read(&foreign).unwrap(), b"replacement");
        assert!(launch_replacement
            .receipt_store
            .load(launch_replacement.receipt.runtime_incarnation())
            .unwrap()
            .is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_boot_receipt_quarantine_crash_replays_to_removal() {
        let mut fixture = LaunchFixture::new();
        fixture.publish_as_stale_boot();
        let namespace = fixture
            .receipt_store
            .state_directory()
            .path()
            .join(super::super::vmm_socket_namespace::VMM_SOCKET_RECEIPT_NAMESPACE);
        let incarnation = fixture.receipt.runtime_incarnation().as_str();
        std::fs::rename(
            namespace.join(format!("vmm-{incarnation}.receipt.json")),
            namespace.join(format!("q-vmm-{incarnation}.receipt.json")),
        )
        .unwrap();
        std::fs::File::open(&namespace).unwrap().sync_all().unwrap();

        assert!(fixture.recover_stale().unwrap());
        assert!(std::fs::read_dir(namespace).unwrap().next().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_root_accounts_and_settles_unmarked_and_quarantined_crash_windows() {
        let fixture = LaunchFixture::new();
        fixture.receipt_store.publish(&fixture.receipt).unwrap();
        let paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            fixture.launch_root.state_directory(),
            &fixture.checkpoint,
        )
        .unwrap();
        std::fs::create_dir(paths.directory().as_str()).unwrap();
        std::fs::set_permissions(
            paths.directory().as_str(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        assert_eq!(
            scan_managed_vmm_launch_root(
                &fixture.launch_root,
                &fixture.socket_root,
                &fixture.receipt_store,
                &[&fixture.checkpoint],
                &scan_context(),
            )
            .unwrap(),
            ManagedVmmLaunchRootScan::Accounted
        );
        assert!(matches!(
            fixture.prepare(),
            ManagedVmmLaunchPreparation::PublishedIntent
        ));

        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(paths.memory_file_path().as_str())
            .unwrap();
        let residue = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Residue(residue) => *residue,
            _ => panic!("launch residue was not retained"),
        };
        let public = Path::new(paths.directory().as_str());
        let quarantine = public.parent().unwrap().join(
            public
                .file_name()
                .unwrap()
                .to_string_lossy()
                .replacen("p-", "q-", 1),
        );
        std::fs::rename(public, &quarantine).unwrap();
        assert_eq!(
            scan_managed_vmm_launch_root(
                &fixture.launch_root,
                &fixture.socket_root,
                &fixture.receipt_store,
                &[&fixture.checkpoint],
                &scan_context(),
            )
            .unwrap(),
            ManagedVmmLaunchRootScan::Accounted
        );
        drop(residue);
        let quarantined = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Residue(residue) => *residue,
            _ => panic!("quarantined launch residue was not retained"),
        };
        fixture.recover(quarantined);
        assert!(!public.exists());
        assert!(!quarantine.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exclusive_recovery_guard_blocks_a_late_launcher_at_every_cleanup_boundary() {
        let fixture = LaunchFixture::new();
        fixture.receipt_store.publish(&fixture.receipt).unwrap();
        let ready = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Ready(ready) => ready,
            _ => panic!("fresh launch attempt was not ready"),
        };
        ready.assert_ready().unwrap();
        let paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            fixture.launch_root.state_directory(),
            &fixture.checkpoint,
        )
        .unwrap();
        for path in [
            paths.memory_file_path(),
            paths.serial_log_path(),
            paths.vmm_log_path(),
        ] {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.as_str())
                .unwrap();
        }
        let residue = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Residue(residue) => *residue,
            _ => panic!("launch residue was not retained"),
        };
        let guard = fixture
            .launch_root
            .try_lock_effect_namespace()
            .unwrap()
            .unwrap();
        let authority = guard
            .bind_fresh_absence(fixture.absence(), &fixture.checkpoint)
            .unwrap();
        let mut boundaries = Vec::new();
        residue
            .recover_with_boundaries(&authority, &fixture.checkpoint, |boundary| {
                boundaries.push(boundary);
                assert!(fixture
                    .launch_root
                    .launcher_shared_lock_is_blocked_for_test()?);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            boundaries,
            [
                LaunchCleanupBoundary::BeforeQuarantine,
                LaunchCleanupBoundary::AfterQuarantine,
                LaunchCleanupBoundary::BeforeMemory,
                LaunchCleanupBoundary::BeforeSerialLog,
                LaunchCleanupBoundary::BeforeVmmLog,
                LaunchCleanupBoundary::BeforeMarker,
                LaunchCleanupBoundary::BeforeDirectory,
            ]
        );
        assert!(!Path::new(paths.directory().as_str()).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quarantined_leaf_replacement_is_preserved_at_every_cleanup_boundary() {
        for boundary in [
            LaunchCleanupBoundary::AfterQuarantine,
            LaunchCleanupBoundary::BeforeMemory,
            LaunchCleanupBoundary::BeforeSerialLog,
            LaunchCleanupBoundary::BeforeVmmLog,
            LaunchCleanupBoundary::BeforeMarker,
            LaunchCleanupBoundary::BeforeDirectory,
        ] {
            let fixture = LaunchFixture::new();
            fixture.receipt_store.publish(&fixture.receipt).unwrap();
            let _ready = match fixture.prepare() {
                ManagedVmmLaunchPreparation::Ready(ready) => ready,
                _ => panic!("fresh launch attempt was not ready"),
            };
            let paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
                fixture.launch_root.state_directory(),
                &fixture.checkpoint,
            )
            .unwrap();
            for path in [
                paths.memory_file_path(),
                paths.serial_log_path(),
                paths.vmm_log_path(),
            ] {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path.as_str())
                    .unwrap();
            }
            let residue = match fixture.prepare() {
                ManagedVmmLaunchPreparation::Residue(residue) => *residue,
                _ => panic!("launch residue was not retained"),
            };
            let guard = fixture
                .launch_root
                .try_lock_effect_namespace()
                .unwrap()
                .unwrap();
            let authority = guard
                .bind_fresh_absence(fixture.absence(), &fixture.checkpoint)
                .unwrap();
            let public = PathBuf::from(paths.directory().as_str());
            let quarantine_name = quarantine_attempt_name(&launch_attempt_name(&paths).unwrap())
                .unwrap()
                .into_string()
                .unwrap();
            let quarantine = public.parent().unwrap().join(quarantine_name);
            let leaf = match boundary {
                LaunchCleanupBoundary::AfterQuarantine
                | LaunchCleanupBoundary::BeforeMemory
                | LaunchCleanupBoundary::BeforeDirectory => VMM_MEMORY_BASENAME,
                LaunchCleanupBoundary::BeforeSerialLog => VMM_SERIAL_LOG_BASENAME,
                LaunchCleanupBoundary::BeforeVmmLog => VMM_LOG_BASENAME,
                LaunchCleanupBoundary::BeforeMarker => VMM_LAUNCH_OWNER_BASENAME,
                LaunchCleanupBoundary::BeforeQuarantine => unreachable!(),
            };
            let replacement = quarantine.join(leaf);
            let saved = fixture
                ._temporary
                .path()
                .join(format!("saved-{}", leaf.replace('.', "-")));
            let replacement_bytes = if leaf == VMM_LAUNCH_OWNER_BASENAME {
                fixture.receipt.encoded_bytes().unwrap()
            } else {
                b"foreign replacement".to_vec()
            };
            let mut replaced_existing = false;
            let error = residue
                .recover_with_boundaries(&authority, &fixture.checkpoint, |current| {
                    if current == boundary {
                        if replacement.exists() {
                            std::fs::rename(&replacement, &saved)?;
                            replaced_existing = true;
                        }
                        let mut file = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&replacement)?;
                        file.write_all(&replacement_bytes)?;
                        file.sync_all()?;
                    }
                    Ok(())
                })
                .expect_err("a quarantined leaf replacement reached unlink");
            assert!(
                error.to_string().contains("changed before cleanup")
                    || error
                        .to_string()
                        .contains("remove empty VMM launch quarantine"),
                "{boundary:?}: {error:#}"
            );
            assert_eq!(std::fs::read(&replacement).unwrap(), replacement_bytes);
            if boundary != LaunchCleanupBoundary::BeforeDirectory {
                assert!(replaced_existing, "{boundary:?}");
                assert!(saved.is_file(), "{boundary:?}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_attempt_replacement_during_quarantine_is_restored_without_deletion() {
        let fixture = LaunchFixture::new();
        fixture.receipt_store.publish(&fixture.receipt).unwrap();
        let _ready = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Ready(ready) => ready,
            _ => panic!("fresh launch attempt was not ready"),
        };
        let paths = ManagedVmmLaunchFilePaths::paths_from_checkpoint(
            fixture.launch_root.state_directory(),
            &fixture.checkpoint,
        )
        .unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(paths.memory_file_path().as_str())
            .unwrap();
        let residue = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Residue(residue) => *residue,
            _ => panic!("launch residue was not retained"),
        };
        let guard = fixture
            .launch_root
            .try_lock_effect_namespace()
            .unwrap()
            .unwrap();
        let authority = guard
            .bind_fresh_absence(fixture.absence(), &fixture.checkpoint)
            .unwrap();
        let public = PathBuf::from(paths.directory().as_str());
        let original = public.with_file_name("original-receipt-owned-attempt");
        let error = residue
            .recover_with_boundaries(&authority, &fixture.checkpoint, |boundary| {
                if boundary == LaunchCleanupBoundary::BeforeQuarantine {
                    std::fs::rename(&public, &original)?;
                    std::fs::create_dir(&public)?;
                    std::fs::set_permissions(
                        &public,
                        std::os::unix::fs::PermissionsExt::from_mode(0o700),
                    )?;
                    let foreign = public.join("foreign");
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(foreign)?;
                    file.write_all(b"foreign replacement")?;
                    file.sync_all()?;
                }
                Ok(())
            })
            .unwrap_err();
        assert!(error.to_string().contains("changed during quarantine"));
        assert_eq!(
            std::fs::read(public.join("foreign")).unwrap(),
            b"foreign replacement"
        );
        assert!(original.join(VMM_MEMORY_BASENAME).is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_launcher_shared_guard_prevents_recovery_from_starting() {
        let fixture = LaunchFixture::new();
        fixture.receipt_store.publish(&fixture.receipt).unwrap();
        let _ready = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Ready(ready) => ready,
            _ => panic!("fresh launch attempt was not ready"),
        };
        let launcher = fixture
            .launch_root
            .retain_launcher_attempt(&fixture.checkpoint, &fixture.receipt)
            .unwrap();
        launcher.assert_ready().unwrap();
        assert!(fixture
            .launch_root
            .try_lock_effect_namespace()
            .unwrap()
            .is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn submitted_launcher_waits_for_effect_guard_then_acquires_shared_authority() {
        let fixture = LaunchFixture::new();
        fixture.receipt_store.publish(&fixture.receipt).unwrap();
        let _ready = match fixture.prepare() {
            ManagedVmmLaunchPreparation::Ready(ready) => ready,
            _ => panic!("fresh launch attempt was not ready"),
        };
        let effect_guard = fixture
            .launch_root
            .try_lock_effect_namespace()
            .unwrap()
            .unwrap();
        assert!(fixture
            .launch_root
            .launcher_shared_lock_is_blocked_for_test()
            .unwrap());

        let launch_root = Arc::clone(&fixture.launch_root);
        let checkpoint = fixture.checkpoint.clone();
        let receipt = fixture.receipt.clone();
        let (waiting_sender, waiting_receiver) = std::sync::mpsc::sync_channel(0);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(0);
        let launcher = std::thread::spawn(move || {
            let result = launch_root
                .retain_launcher_attempt_with_before_lock(&checkpoint, &receipt, || {
                    waiting_sender.send(()).unwrap()
                })
                .and_then(|guard| guard.assert_ready());
            result_sender.send(result)
        });
        waiting_receiver.recv().unwrap();
        assert!(matches!(
            result_receiver.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        drop(effect_guard);
        result_receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("launcher did not acquire the shared guard after submit released EX")
            .unwrap();
        launcher.join().unwrap().unwrap();
    }

    #[test]
    fn canonical_runtime_paths_reject_aliasing_components() {
        assert_eq!(
            canonical_components(Path::new("/run/cats/cat_01/vmm.sock")).unwrap(),
            ["run", "cats", "cat_01", "vmm.sock"]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        );
        for path in ["relative", "/", "/run/cats/../foreign"] {
            assert!(canonical_components(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn mutable_logs_keep_inode_identity_without_freezing_length() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vmm.log");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let rule = LeafRule::Regular {
            mode: file.metadata().unwrap().mode() & 0o7777,
            length: None,
        };
        let before = LeafIdentity::from_metadata_for_rule(&file.metadata().unwrap(), &rule);
        file.write_all(b"new VMM output").unwrap();
        let after = LeafIdentity::from_metadata_for_rule(&file.metadata().unwrap(), &rule);
        assert_eq!(before, after);

        let fixed = LeafRule::Regular {
            mode: file.metadata().unwrap().mode() & 0o7777,
            length: Some(0),
        };
        assert_ne!(
            LeafIdentity::from_metadata_for_rule(&file.metadata().unwrap(), &fixed),
            before
        );
    }
}
