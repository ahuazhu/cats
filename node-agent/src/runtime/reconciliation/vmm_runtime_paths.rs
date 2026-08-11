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
use cats_api::runtime_reconciliation::encode_runtime_checkpoint;
use cats_api::runtime_reconciliation::{HostPath, RandomId128, RuntimeCheckpoint};

use crate::state_directory::StateDirectory;

use super::vmm_launch_artifacts::VmmLaunchArtifactDescriptors;
#[cfg(target_os = "linux")]
use super::vmm_socket_namespace::{
    scan_receipt_namespace_snapshot, ReceiptNamespaceSnapshot, RetainedManagedVmmSocketRoot,
    VmmSocketOwnershipReceiptV1, VmmSocketReceiptStore,
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
        let cats_api::runtime_reconciliation::ReconcileStep::StartRuntime {
            runtime_incarnation,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("managed VMM launch file paths require StartRuntime")
        };
        anyhow::ensure!(
            checkpoint.runtime_incarnation.as_ref() == Some(runtime_incarnation),
            "StartRuntime launch file paths have a non-exact top-level incarnation"
        );
        let paths = Self::for_incarnation(state_directory, runtime_incarnation)?;
        anyhow::ensure!(
            memory_file_path == &paths.memory_file_path
                && serial_log_path == &paths.serial_log_path
                && vmm_log_path == &paths.vmm_log_path,
            "StartRuntime launch files are outside the managed VMM namespace"
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
/// before any socket/file mutation and is released automatically at the
/// successful `exec` boundary because this descriptor is CLOEXEC. Recovery
/// requires the exclusive side of the same lock.
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
    ) -> Result<Option<RetainedManagedVmmLauncherAttempt>> {
        self.assert_current()?;
        let namespace_guard = open_at(
            &self
                .state_directory
                .try_reopen_directory()
                .context("reopen state directory for VMM launcher namespace lock")?,
            OsStr::new(VMM_LAUNCH_FILE_NAMESPACE),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        if !try_flock(&namespace_guard, libc::LOCK_SH)? {
            return Ok(None);
        }
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
        Ok(Some(RetainedManagedVmmLauncherAttempt {
            _namespace_guard: namespace_guard,
            attempt,
        }))
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
    marker_bytes: Vec<u8>,
    location: LaunchResidueLocation,
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
        Ok(Self {
            root,
            public_name,
            quarantine_name,
            directory_identity: LaunchDirectoryIdentity::from_metadata(&directory.metadata()?),
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
        authority: &GuardedVmmLaunchAbsence<'_>,
        checkpoint: &RuntimeCheckpoint,
        mut before_boundary: impl FnMut(LaunchCleanupBoundary) -> Result<()>,
    ) -> Result<()> {
        authority.assert_for(&self.root, checkpoint)?;
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
            if open_launch_leaf(&self.directory, leaf)?.is_none() {
                continue;
            }
            unlink_isolated_launch_leaf(&self.directory, leaf)?;
            self.directory.sync_all()?;
            authority.assert_for(&self.root, checkpoint)?;
        }
        before_boundary(LaunchCleanupBoundary::BeforeMarker)?;
        if open_launch_leaf(&self.directory, VMM_LAUNCH_OWNER_BASENAME)?.is_some() {
            verify_launch_owner_marker(&self.directory, &self.marker_bytes)?;
            unlink_isolated_launch_leaf(&self.directory, VMM_LAUNCH_OWNER_BASENAME)?;
            self.directory.sync_all()?;
        }
        anyhow::ensure!(
            launch_attempt_names(&self.directory)?.is_empty(),
            "quarantined VMM launch attempt did not become empty"
        );
        authority.assert_for(&self.root, checkpoint)?;
        before_boundary(LaunchCleanupBoundary::BeforeDirectory)?;
        let reopened = open_directory_at_name(&self.root.descriptor, &self.quarantine_name)?;
        anyhow::ensure!(
            LaunchDirectoryIdentity::from_metadata(&reopened.metadata()?)
                == self.directory_identity,
            "VMM launch quarantine changed before removal"
        );
        remove_isolated_launch_directory(&self.root.descriptor, &self.quarantine_name)?;
        self.root.descriptor.sync_all()?;
        authority.assert_for(&self.root, checkpoint)
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
    links: u64,
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
            links: metadata.nlink(),
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
    context.check_active()?;
    if root.assert_current().is_err()
        || socket_root.assert_current().is_err()
        || receipts.assert_current().is_err()
        || expected_checkpoints.len() > 1024
    {
        return Ok(ManagedVmmLaunchRootScan::Residue);
    }
    let first_receipts =
        scan_receipt_namespace_snapshot(socket_root, receipts, expected_checkpoints, context)?;
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
    )? {
        Some(snapshot) => snapshot,
        None => return Ok(ManagedVmmLaunchRootScan::Unavailable),
    };
    if first.contains_key("<foreign>") || second.contains_key("<foreign>") || first != second {
        return Ok(ManagedVmmLaunchRootScan::Residue);
    }
    let second_receipts =
        scan_receipt_namespace_snapshot(socket_root, receipts, expected_checkpoints, context)?;
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
        let Some(receipt) = receipt_snapshot.receipt_for_checkpoint(checkpoint)? else {
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
        if receipt
            .validate_launch_paths(checkpoint, receipts.state_directory(), &paths)
            .is_err()
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
                links: 0,
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
    checkpoint: PinnedRuntimePath,
    memory: PinnedRuntimePath,
    serial_log: PinnedRuntimePath,
    vmm_log: PinnedRuntimePath,
}

impl PartialEq for RetainedVmmRuntimePaths {
    fn eq(&self, other: &Self) -> bool {
        self.identities() == other.identities()
    }
}

impl Eq for RetainedVmmRuntimePaths {}

impl RetainedVmmRuntimePaths {
    #[cfg(target_os = "linux")]
    pub(crate) fn open(
        requirements: &VmmRuntimePathRequirements,
    ) -> Result<VmmRuntimePathInspection> {
        let checkpoint_bytes = encode_runtime_checkpoint(&requirements.checkpoint)
            .context("encode exact StartRuntime checkpoint")?;
        let Some(checkpoint) = PinnedRuntimePath::open(
            &requirements.checkpoint_path,
            LeafRule::ImmutableRegular {
                mode: 0o600,
                bytes: checkpoint_bytes,
            },
        )?
        else {
            return Ok(VmmRuntimePathInspection::Unavailable);
        };
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
            checkpoint,
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
    ) -> Result<VmmRuntimePathInspection> {
        Ok(VmmRuntimePathInspection::Unavailable)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn assert_current(&self) -> Result<()> {
        self.checkpoint
            .assert_current()
            .context("StartRuntime checkpoint path changed")?;
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
        assert_process_fd(process_id, CHECKPOINT_FD, &self.checkpoint.leaf_identity)?;
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

    fn identities(&self) -> [&PathIdentity; 4] {
        [
            &self.checkpoint.identity,
            &self.memory.identity,
            &self.serial_log.identity,
            &self.vmm_log.identity,
        ]
    }
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
    device: u64,
    inode: u64,
    mode: u32,
    user: u32,
    group: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            user: metadata.uid(),
            group: metadata.gid(),
            links: metadata.nlink(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
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
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    use cats_api::runtime_reconciliation::{decode_runtime_checkpoint, ReconcileStep};

    use super::*;

    #[cfg(target_os = "linux")]
    use crate::runtime::reconciliation::{RetainedManagedVmmSocketRoot, VmmSocketReceiptStore};

    fn start_runtime_checkpoint() -> RuntimeCheckpoint {
        decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap()
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
            let receipt_store = VmmSocketReceiptStore::provision_for_test(state.clone()).unwrap();
            let receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
                &checkpoint,
                &state,
                &socket_root,
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
                    .retain_launcher_attempt(&fixture.checkpoint, &fixture.receipt)?
                    .is_none());
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
            .unwrap()
            .expect("launcher should acquire the shared guard");
        launcher.assert_ready().unwrap();
        assert!(fixture
            .launch_root
            .try_lock_effect_namespace()
            .unwrap()
            .is_none());
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
