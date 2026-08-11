//! Provider-private ownership boundary for Cloud Hypervisor Unix sockets.
//!
//! The public Runtime v1 checkpoint records the two canonical socket paths,
//! but those path strings are not filesystem ownership.  This module freezes
//! the one short, installation-owned namespace and derives all public,
//! staging and quarantine names from the already-checkpointed random runtime
//! incarnation.  Later physical effects consume these typed paths together
//! with a durable provider-private ownership receipt; no caller may choose an
//! arbitrary pathname at launch time.

use std::ffi::{CStr, CString};
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write as _;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;
#[cfg(test)]
use cats_api::runtime_reconciliation::ReconcileStep;
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, Epoch, HostPath, Id, NodeBootId, RandomId128, Revision,
    RuntimeCheckpoint, Sha256Digest,
};
use serde::{Deserialize, Serialize};

use crate::state_directory::StateDirectory;

use super::retained_runtime_launch::RetainedRuntimeLaunchAuthority;
use super::vmm_runtime_paths::ManagedVmmLaunchFilePaths;

/// Installation-owned short socket root.  It is deliberately outside the
/// durable Node state directory: AF_UNIX pathnames have a small kernel ABI
/// bound and live VMM sockets are boot-local.  The durable ownership WAL lives
/// under the identity-selected Node state directory instead.
pub(crate) const INSTALLED_VMM_SOCKET_ROOT: &str = "/run/cats/vmm-v1";

pub(crate) const VMM_API_SOCKET_BASENAME: &str = "api.sock";
pub(crate) const VMM_VSOCK_SOCKET_BASENAME: &str = "vsock.sock";
pub(crate) const VMM_SOCKET_RECEIPT_NAMESPACE: &str = "vmm-socket-receipts";
pub(crate) const VMM_SOCKET_OWNER_BASENAME: &str = ".owner.v1.json";

const VMM_SOCKET_RECEIPT_VERSION: u32 = 2;
const VMM_SOCKET_RECEIPT_MAX_BYTES: usize = 16 * 1024;
const VMM_SOCKET_LISTEN_BACKLOG: i32 = 128;
pub(crate) const MANAGED_VMM_SOCKET_ROOT_ENTRY_LIMIT: usize = 3 * 1024;

/// Read the same compact kernel boot coordinate used by Agent registration.
/// A durable receipt may authorize a boot-local `/run` inode only while this
/// value remains exact; a different value proves every process from the old
/// receipt's kernel instance is gone.
pub(crate) fn current_kernel_node_boot_id() -> anyhow::Result<NodeBootId> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read kernel Node boot ID")?;
    let compact = text.strip_suffix('\n').unwrap_or(&text).replace('-', "");
    NodeBootId::new(compact).context("kernel Node boot ID is invalid")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedVmmSocketRootScan {
    Accounted,
    Residue,
    Unavailable,
}

/// Recover the identity-selected state root only from the frozen launch-file
/// mapping already carried by StartRuntime.  The launcher has no CLI/env path
/// override and immediately revalidates all three paths through
/// `ManagedVmmLaunchFilePaths` before opening the existing receipt namespace.
pub(crate) fn vmm_state_directory_from_checkpoint(
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<StateDirectory> {
    let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
    let launch = authority.identity();
    let memory = Path::new(launch.memory_file_path.as_str());
    let attempt = memory
        .parent()
        .context("VMM memory path has no attempt directory")?;
    anyhow::ensure!(
        attempt.file_name().and_then(|name| name.to_str())
            == Some(format!("p-{}", launch.runtime_incarnation.as_str()).as_str()),
        "VMM memory path has a non-exact attempt directory"
    );
    let namespace = attempt
        .parent()
        .context("VMM memory path has no launch namespace")?;
    let state_path = namespace
        .parent()
        .context("VMM launch namespace has no state-directory parent")?;
    let state_directory = StateDirectory::unanchored(state_path.to_path_buf());
    ManagedVmmLaunchFilePaths::paths_from_checkpoint(&state_directory, checkpoint)
        .context("validate checkpointed VMM launch paths against recovered state directory")?;
    Ok(state_directory)
}

#[cfg(target_os = "linux")]
const UNIX_SOCKET_PATH_CAPACITY: usize = 108;
#[cfg(target_os = "macos")]
const UNIX_SOCKET_PATH_CAPACITY: usize = 104;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const UNIX_SOCKET_PATH_CAPACITY: usize = 104;

/// Canonical root from which every production StartRuntime socket path is
/// generated.  Construction is mutation-free; opening and retaining the
/// installed directory is a separate physical-admission operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedVmmSocketRoot {
    path: HostPath,
}

impl ManagedVmmSocketRoot {
    pub(crate) fn installed() -> Self {
        Self {
            path: HostPath::new(INSTALLED_VMM_SOCKET_ROOT)
                .expect("the fixed installed VMM socket root is canonical"),
        }
    }

    /// Test/composition constructor.  Production composition must use
    /// [`Self::installed`] so a caller cannot widen the managed namespace.
    pub(crate) fn from_canonical_path(path: HostPath) -> anyhow::Result<Self> {
        ensure_canonical_root(Path::new(path.as_str()))?;
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &HostPath {
        &self.path
    }

    pub(crate) fn paths_for(
        &self,
        incarnation: &RandomId128,
    ) -> anyhow::Result<ManagedVmmSocketPaths> {
        let public_name = format!("p-{}", incarnation.as_str());
        let staging_name = format!(".s-{}", incarnation.as_str());
        let quarantine_name = format!(".q-{}", incarnation.as_str());
        let root = Path::new(self.path.as_str());
        let public_directory = host_path(root.join(&public_name), "VMM public socket directory")?;
        let staging_directory =
            host_path(root.join(&staging_name), "VMM staging socket directory")?;
        let quarantine_directory = host_path(
            root.join(&quarantine_name),
            "VMM quarantine socket directory",
        )?;
        let api_socket_path = host_path(
            Path::new(public_directory.as_str()).join(VMM_API_SOCKET_BASENAME),
            "VMM API socket path",
        )?;
        let vsock_socket_path = host_path(
            Path::new(public_directory.as_str()).join(VMM_VSOCK_SOCKET_BASENAME),
            "VMM vsock path",
        )?;
        ensure_socket_path_fits(&api_socket_path)?;
        ensure_socket_path_fits(&vsock_socket_path)?;
        Ok(ManagedVmmSocketPaths {
            root: self.path.clone(),
            public_name,
            staging_name,
            quarantine_name,
            public_directory,
            staging_directory,
            quarantine_directory,
            api_socket_path,
            vsock_socket_path,
        })
    }

    /// Proves that a persisted StartRuntime used the only production path
    /// mapping.  This is intentionally pure and is suitable for the CAS
    /// planner before it writes the checkpoint.
    pub(crate) fn paths_from_checkpoint(
        &self,
        checkpoint: &RuntimeCheckpoint,
    ) -> anyhow::Result<ManagedVmmSocketPaths> {
        let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let launch = authority.identity();
        let paths = self.paths_for(&launch.runtime_incarnation)?;
        anyhow::ensure!(
            launch.api_socket_path == paths.api_socket_path
                && launch.vsock_socket_path == paths.vsock_socket_path,
            "retained VMM socket paths are outside the managed namespace"
        );
        Ok(paths)
    }
}

/// The complete per-incarnation physical namespace.  Public API/vsock paths
/// stay stable in the shared checkpoint; staging and quarantine names remain
/// provider-private recovery coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedVmmSocketPaths {
    root: HostPath,
    public_name: String,
    staging_name: String,
    quarantine_name: String,
    public_directory: HostPath,
    staging_directory: HostPath,
    quarantine_directory: HostPath,
    api_socket_path: HostPath,
    vsock_socket_path: HostPath,
}

impl ManagedVmmSocketPaths {
    pub(crate) fn root(&self) -> &HostPath {
        &self.root
    }

    pub(crate) fn public_name(&self) -> &str {
        &self.public_name
    }

    pub(crate) fn staging_name(&self) -> &str {
        &self.staging_name
    }

    pub(crate) fn quarantine_name(&self) -> &str {
        &self.quarantine_name
    }

    pub(crate) fn public_directory(&self) -> &HostPath {
        &self.public_directory
    }

    pub(crate) fn staging_directory(&self) -> &HostPath {
        &self.staging_directory
    }

    pub(crate) fn quarantine_directory(&self) -> &HostPath {
        &self.quarantine_directory
    }

    pub(crate) fn api_socket_path(&self) -> &HostPath {
        &self.api_socket_path
    }

    pub(crate) fn vsock_socket_path(&self) -> &HostPath {
        &self.vsock_socket_path
    }
}

/// Immutable write-ahead ownership record for one StartRuntime attempt.
///
/// This receipt is durable before the attempt creates its staging directory,
/// binds a socket, creates a transient unit, or creates a launch file.  It is
/// intentionally provider-private and does not add a ReconcileStep or another
/// control-plane authority.  The checkpoint digest keeps the complete public
/// request closed while the explicit fields make recovery diagnostics and
/// physical-path admission typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VmmSocketOwnershipReceiptV1 {
    version: u32,
    node_boot_id: NodeBootId,
    node_id: Id,
    cat_id: Id,
    desired_revision: Revision,
    spec_digest: Sha256Digest,
    placement_epoch: Epoch,
    checkpoint_content_digest: Sha256Digest,
    runtime_launch_content_digest: Sha256Digest,
    runtime_incarnation: RandomId128,
    scope_id: Id,
    process_identity_token: RandomId128,
    creation_nonce: RandomId128,
    launcher_executable_path: HostPath,
    vmm_executable_path: HostPath,
    managed_root_path: HostPath,
    managed_root_identity: DirectoryIdentity,
    public_name: String,
    staging_name: String,
    quarantine_name: String,
    api_socket_path: HostPath,
    vsock_socket_path: HostPath,
    memory_file_path: HostPath,
    serial_log_path: HostPath,
    vmm_log_path: HostPath,
}

impl VmmSocketOwnershipReceiptV1 {
    pub(crate) fn from_checkpoint(
        checkpoint: &RuntimeCheckpoint,
        state_directory: &StateDirectory,
        managed_root: &RetainedManagedVmmSocketRoot,
        node_boot_id: NodeBootId,
        creation_nonce: RandomId128,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            node_boot_id == current_kernel_node_boot_id()?,
            "VMM socket receipt publication boot differs from the running kernel"
        );
        let authority = RetainedRuntimeLaunchAuthority::from_start_runtime_checkpoint(checkpoint)?;
        let launch = authority.identity();
        let paths = managed_root
            .planner
            .paths_from_checkpoint(checkpoint)
            .context("validate managed StartRuntime socket paths")?;
        let launch_file_paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(state_directory, checkpoint)
                .context("validate managed StartRuntime launch file paths")?;
        anyhow::ensure!(
            creation_nonce != launch.runtime_incarnation
                && creation_nonce != launch.process_identity_token,
            "VMM socket creation nonce aliases another launch identity"
        );
        let receipt = Self {
            version: VMM_SOCKET_RECEIPT_VERSION,
            node_boot_id,
            node_id: checkpoint.node_id.clone(),
            cat_id: checkpoint.cat_id.clone(),
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            placement_epoch: checkpoint.placement_epoch,
            checkpoint_content_digest: checkpoint_content_digest(checkpoint)
                .context("digest StartRuntime checkpoint for socket ownership")?,
            runtime_launch_content_digest: authority.identity_content_digest()?,
            runtime_incarnation: launch.runtime_incarnation.clone(),
            scope_id: launch.scope_id.clone(),
            process_identity_token: launch.process_identity_token.clone(),
            creation_nonce,
            launcher_executable_path: launch.launcher_executable.path.clone(),
            vmm_executable_path: launch.boot.vmm_executable.path.clone(),
            managed_root_path: paths.root().clone(),
            managed_root_identity: managed_root.identity,
            public_name: paths.public_name().to_owned(),
            staging_name: paths.staging_name().to_owned(),
            quarantine_name: paths.quarantine_name().to_owned(),
            api_socket_path: paths.api_socket_path().clone(),
            vsock_socket_path: paths.vsock_socket_path().clone(),
            memory_file_path: launch_file_paths.memory_file_path().clone(),
            serial_log_path: launch_file_paths.serial_log_path().clone(),
            vmm_log_path: launch_file_paths.vmm_log_path().clone(),
        };
        receipt.validate_against(checkpoint, state_directory, managed_root)?;
        Ok(receipt)
    }

    pub(crate) fn validate_against(
        &self,
        checkpoint: &RuntimeCheckpoint,
        state_directory: &StateDirectory,
        managed_root: &RetainedManagedVmmSocketRoot,
    ) -> anyhow::Result<ManagedVmmSocketPaths> {
        anyhow::ensure!(
            self.version == VMM_SOCKET_RECEIPT_VERSION,
            "unsupported VMM socket receipt version"
        );
        anyhow::ensure!(
            self.node_boot_id == current_kernel_node_boot_id()?,
            "VMM socket ownership receipt belongs to another Node boot"
        );
        let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let launch = authority.identity();
        let paths = managed_root.planner.paths_from_checkpoint(checkpoint)?;
        let launch_file_paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(state_directory, checkpoint)?;
        anyhow::ensure!(
            self.node_id == checkpoint.node_id
                && self.cat_id == checkpoint.cat_id
                && self.placement_epoch == checkpoint.placement_epoch
                && self.runtime_launch_content_digest == authority.identity_content_digest()?
                && self.original_checkpoint_digest_matches_if_current_start(checkpoint)?
                && self.runtime_incarnation == launch.runtime_incarnation
                && self.scope_id == launch.scope_id
                && self.process_identity_token == launch.process_identity_token
                && self.creation_nonce != launch.runtime_incarnation
                && self.creation_nonce != launch.process_identity_token
                && self.launcher_executable_path == launch.launcher_executable.path
                && self.vmm_executable_path == launch.boot.vmm_executable.path
                && &self.managed_root_path == paths.root()
                && self.managed_root_identity == managed_root.identity
                && self.public_name == paths.public_name()
                && self.staging_name == paths.staging_name()
                && self.quarantine_name == paths.quarantine_name()
                && &self.api_socket_path == paths.api_socket_path()
                && &self.vsock_socket_path == paths.vsock_socket_path()
                && &self.memory_file_path == launch_file_paths.memory_file_path()
                && &self.serial_log_path == launch_file_paths.serial_log_path()
                && &self.vmm_log_path == launch_file_paths.vmm_log_path(),
            "VMM socket ownership receipt is not checkpoint-exact"
        );
        Ok(paths)
    }

    /// Validate a receipt from a previous kernel boot without granting it
    /// authority over the current boot-local socket-root inode. This is only
    /// a recovery classification: ordinary launch/adoption paths must use
    /// `validate_against`, which requires the current kernel boot and exact
    /// root identity.
    pub(crate) fn validate_stale_boot_against(
        &self,
        checkpoint: &RuntimeCheckpoint,
        state_directory: &StateDirectory,
        managed_root: &RetainedManagedVmmSocketRoot,
        current_boot_id: &NodeBootId,
    ) -> anyhow::Result<ManagedVmmSocketPaths> {
        anyhow::ensure!(
            self.version == VMM_SOCKET_RECEIPT_VERSION && &self.node_boot_id != current_boot_id,
            "VMM socket receipt is not from a distinct supported Node boot"
        );
        let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let launch = authority.identity();
        let paths = managed_root.planner.paths_from_checkpoint(checkpoint)?;
        let launch_file_paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(state_directory, checkpoint)?;
        anyhow::ensure!(
            self.node_id == checkpoint.node_id
                && self.cat_id == checkpoint.cat_id
                && self.placement_epoch == checkpoint.placement_epoch
                && self.runtime_launch_content_digest == authority.identity_content_digest()?
                && self.original_checkpoint_digest_matches_if_current_start(checkpoint)?
                && self.runtime_incarnation == launch.runtime_incarnation
                && self.scope_id == launch.scope_id
                && self.process_identity_token == launch.process_identity_token
                && self.creation_nonce != launch.runtime_incarnation
                && self.creation_nonce != launch.process_identity_token
                && self.launcher_executable_path == launch.launcher_executable.path
                && self.vmm_executable_path == launch.boot.vmm_executable.path
                && &self.managed_root_path == paths.root()
                && self.public_name == paths.public_name()
                && self.staging_name == paths.staging_name()
                && self.quarantine_name == paths.quarantine_name()
                && &self.api_socket_path == paths.api_socket_path()
                && &self.vsock_socket_path == paths.vsock_socket_path()
                && &self.memory_file_path == launch_file_paths.memory_file_path()
                && &self.serial_log_path == launch_file_paths.serial_log_path()
                && &self.vmm_log_path == launch_file_paths.vmm_log_path(),
            "stale-boot VMM socket ownership receipt is not retained-launch exact"
        );
        Ok(paths)
    }

    pub(crate) fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub(crate) fn runtime_incarnation(&self) -> &RandomId128 {
        &self.runtime_incarnation
    }

    pub(crate) fn checkpoint_content_digest(&self) -> &Sha256Digest {
        &self.checkpoint_content_digest
    }

    pub(crate) fn creation_nonce(&self) -> &RandomId128 {
        &self.creation_nonce
    }

    pub(crate) fn api_socket_path(&self) -> &HostPath {
        &self.api_socket_path
    }

    pub(crate) fn vsock_socket_path(&self) -> &HostPath {
        &self.vsock_socket_path
    }

    pub(crate) fn validate_launch_paths(
        &self,
        checkpoint: &RuntimeCheckpoint,
        state_directory: &StateDirectory,
        paths: &ManagedVmmLaunchFilePaths,
    ) -> anyhow::Result<()> {
        let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let launch = authority.identity();
        anyhow::ensure!(
            self.node_boot_id == current_kernel_node_boot_id()?,
            "VMM launch receipt belongs to another Node boot"
        );
        anyhow::ensure!(
            self.node_id == checkpoint.node_id
                && self.cat_id == checkpoint.cat_id
                && self.placement_epoch == checkpoint.placement_epoch
                && self.runtime_launch_content_digest == authority.identity_content_digest()?
                && self.original_checkpoint_digest_matches_if_current_start(checkpoint)?
                && self.runtime_incarnation == launch.runtime_incarnation
                && &self.memory_file_path == paths.memory_file_path()
                && &self.serial_log_path == paths.serial_log_path()
                && &self.vmm_log_path == paths.vmm_log_path()
                && ManagedVmmLaunchFilePaths::paths_from_checkpoint(state_directory, checkpoint)?
                    == *paths,
            "VMM launch receipt is not checkpoint-exact"
        );
        Ok(())
    }

    pub(crate) fn validate_stale_boot_launch_paths(
        &self,
        checkpoint: &RuntimeCheckpoint,
        state_directory: &StateDirectory,
        paths: &ManagedVmmLaunchFilePaths,
        current_boot_id: &NodeBootId,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == VMM_SOCKET_RECEIPT_VERSION && &self.node_boot_id != current_boot_id,
            "VMM launch receipt is not from a distinct supported Node boot"
        );
        let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let launch = authority.identity();
        anyhow::ensure!(
            self.node_id == checkpoint.node_id
                && self.cat_id == checkpoint.cat_id
                && self.placement_epoch == checkpoint.placement_epoch
                && self.runtime_launch_content_digest == authority.identity_content_digest()?
                && self.original_checkpoint_digest_matches_if_current_start(checkpoint)?
                && self.runtime_incarnation == launch.runtime_incarnation
                && &self.memory_file_path == paths.memory_file_path()
                && &self.serial_log_path == paths.serial_log_path()
                && &self.vmm_log_path == paths.vmm_log_path()
                && ManagedVmmLaunchFilePaths::paths_from_checkpoint(state_directory, checkpoint)?
                    == *paths,
            "stale-boot VMM launch receipt is not retained-launch exact"
        );
        Ok(())
    }

    fn original_checkpoint_digest_matches_if_current_start(
        &self,
        checkpoint: &RuntimeCheckpoint,
    ) -> anyhow::Result<bool> {
        if checkpoint.step.start_runtime_launch_identity().is_some() {
            Ok(self.validate_original_launch_checkpoint(checkpoint).is_ok())
        } else {
            Ok(true)
        }
    }

    /// Bind the immutable receipt fields to the exact StartRuntime bytes
    /// inherited by the VMM at fd64. Later checkpoint pathnames may advance
    /// their Desired revision while retaining the same live launch identity;
    /// those current coordinates are deliberately validated separately by
    /// `validate_against`.
    pub(crate) fn validate_original_launch_checkpoint(
        &self,
        checkpoint: &RuntimeCheckpoint,
    ) -> anyhow::Result<()> {
        let authority = RetainedRuntimeLaunchAuthority::from_start_runtime_checkpoint(checkpoint)?;
        anyhow::ensure!(
            self.node_id == checkpoint.node_id
                && self.cat_id == checkpoint.cat_id
                && self.desired_revision == checkpoint.desired_revision
                && self.spec_digest == checkpoint.spec_digest
                && self.placement_epoch == checkpoint.placement_epoch
                && self.checkpoint_content_digest == checkpoint_content_digest(checkpoint)?
                && self.runtime_launch_content_digest == authority.identity_content_digest()?,
            "VMM socket ownership receipt is not original StartRuntime-exact"
        );
        Ok(())
    }

    pub(crate) fn original_desired_revision(&self) -> Revision {
        self.desired_revision
    }

    pub(crate) fn original_spec_digest(&self) -> &Sha256Digest {
        &self.spec_digest
    }

    pub(crate) fn original_placement_epoch(&self) -> Epoch {
        self.placement_epoch
    }

    pub(crate) fn node_boot_id(&self) -> &NodeBootId {
        &self.node_boot_id
    }

    #[cfg(test)]
    pub(crate) fn set_node_boot_id_for_test(&mut self, node_boot_id: NodeBootId) {
        self.node_boot_id = node_boot_id;
    }

    pub(crate) fn encoded_bytes(&self) -> anyhow::Result<Vec<u8>> {
        encode_receipt(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
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

#[derive(Debug)]
struct RetainedPathDirectory {
    name: std::ffi::OsString,
    descriptor: File,
    identity: DirectoryIdentity,
}

/// Descriptor-retained installation-owned socket root.  Production opens an
/// already-provisioned root; an individual StartRuntime is never allowed to
/// create or replace this directory.
#[derive(Debug)]
pub(crate) struct RetainedManagedVmmSocketRoot {
    planner: ManagedVmmSocketRoot,
    directories: Vec<RetainedPathDirectory>,
    descriptor: File,
    identity: DirectoryIdentity,
}

impl RetainedManagedVmmSocketRoot {
    pub(crate) fn open_installed() -> anyhow::Result<Self> {
        Self::open(ManagedVmmSocketRoot::installed(), 0, 0)
    }

    fn open(
        planner: ManagedVmmSocketRoot,
        expected_user: u32,
        expected_group: u32,
    ) -> anyhow::Result<Self> {
        let mut directories = open_directory_chain(Path::new(planner.path().as_str()))
            .context("open installed managed VMM socket root")?;
        let descriptor = directories
            .last()
            .context("managed VMM socket root chain is empty")?
            .descriptor
            .try_clone()?;
        let metadata = descriptor.metadata()?;
        ensure_owned_directory(&metadata, expected_user, expected_group, 0o700)?;
        let retained = Self {
            planner,
            directories: std::mem::take(&mut directories),
            descriptor,
            identity: DirectoryIdentity::from_metadata(&metadata),
        };
        retained.assert_current()?;
        Ok(retained)
    }

    pub(crate) fn planner(&self) -> &ManagedVmmSocketRoot {
        &self.planner
    }

    pub(crate) fn try_clone_descriptor(&self) -> anyhow::Result<File> {
        self.assert_current()?;
        self.descriptor
            .try_clone()
            .context("clone managed VMM socket root descriptor")
    }

    pub(crate) fn owner(&self) -> (u32, u32) {
        (self.identity.user, self.identity.group)
    }

    pub(crate) fn identity_coordinate(&self) -> (u64, u64, u32, u32, u32) {
        (
            self.identity.device,
            self.identity.inode,
            self.identity.mode,
            self.identity.user,
            self.identity.group,
        )
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        let retained = self.descriptor.metadata()?;
        ensure_owned_directory(&retained, self.identity.user, self.identity.group, 0o700)?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&retained) == self.identity,
            "retained managed VMM socket root changed"
        );
        for directory in &self.directories {
            let metadata = directory.descriptor.metadata()?;
            anyhow::ensure!(
                metadata.file_type().is_dir()
                    && metadata.nlink() > 0
                    && DirectoryIdentity::from_metadata(&metadata) == directory.identity,
                "retained managed VMM socket ancestor changed"
            );
        }
        let reopened = open_directory_chain(Path::new(self.planner.path().as_str()))?;
        anyhow::ensure!(
            reopened.len() == self.directories.len()
                && reopened.iter().zip(&self.directories).all(|(left, right)| {
                    left.name == right.name && left.identity == right.identity
                }),
            "managed VMM socket root ancestor chain changed identity"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn provision_for_test(path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir(path).context("create test managed VMM socket root")?;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        let metadata = std::fs::metadata(path)?;
        let planner = ManagedVmmSocketRoot::from_canonical_path(host_path(
            path.to_path_buf(),
            "test managed VMM socket root",
        )?)?;
        Self::open(planner, metadata.uid(), metadata.gid())
    }
}

/// Bounded, descriptor-rooted accounting for the complete installed socket
/// namespace. A directory is allowed only when one current StartRuntime
/// checkpoint derives its exact name and its durable receipt/owner marker
/// close the physical contents. One crash residue name is accounted so the
/// same attempt may repair it; multiple names for one incarnation are an ABA
/// conflict and remain untouched.
pub(crate) fn scan_managed_vmm_socket_root(
    root: &RetainedManagedVmmSocketRoot,
    receipts: &VmmSocketReceiptStore,
    expected_checkpoints: &[&RuntimeCheckpoint],
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
) -> anyhow::Result<ManagedVmmSocketRootScan> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, receipts, expected_checkpoints, context);
        Ok(ManagedVmmSocketRootScan::Unavailable)
    }
    #[cfg(target_os = "linux")]
    {
        scan_managed_vmm_socket_root_linux(root, receipts, expected_checkpoints, context)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScannedAttemptKind {
    Public,
    Staging,
    Quarantine,
}

#[cfg(target_os = "linux")]
struct ExpectedManagedAttempt<'a> {
    checkpoint: &'a RuntimeCheckpoint,
    incarnation: String,
    kind: ScannedAttemptKind,
}

#[cfg(target_os = "linux")]
struct ScannedManagedAttempt {
    name: String,
    contents: std::collections::BTreeSet<String>,
    directory_identity: DirectoryIdentity,
    marker_identity: Option<StableFileIdentity>,
    api_identity: Option<StableSocketLeafIdentity>,
    vsock_identity: Option<StableSocketLeafIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScannedReceipt {
    identity: StableFileIdentity,
    bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiptNamespaceSnapshot {
    Exact(std::collections::BTreeMap<String, ScannedReceipt>),
    Residue,
    Unavailable,
}

#[cfg(target_os = "linux")]
impl ReceiptNamespaceSnapshot {
    pub(crate) fn receipt_for_checkpoint(
        &self,
        checkpoint: &RuntimeCheckpoint,
    ) -> anyhow::Result<Option<VmmSocketOwnershipReceiptV1>> {
        let Self::Exact(receipts) = self else {
            return Ok(None);
        };
        let launch = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let name = receipt_file_name(&launch.identity().runtime_incarnation)?
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM receipt filename is not UTF-8"))?;
        receipts
            .get(&name)
            .map(|receipt| decode_receipt(&receipt.bytes))
            .transpose()
    }
}

#[cfg(target_os = "linux")]
fn scan_managed_vmm_socket_root_linux(
    root: &RetainedManagedVmmSocketRoot,
    receipts: &VmmSocketReceiptStore,
    expected_checkpoints: &[&RuntimeCheckpoint],
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
) -> anyhow::Result<ManagedVmmSocketRootScan> {
    scan_managed_vmm_socket_root_linux_inner(root, receipts, expected_checkpoints, context, |_| {
        Ok(())
    })
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptScanPoint {
    FirstSnapshotCaptured,
    AttemptsScanned,
}

#[cfg(target_os = "linux")]
fn scan_managed_vmm_socket_root_linux_inner(
    root: &RetainedManagedVmmSocketRoot,
    receipts: &VmmSocketReceiptStore,
    expected_checkpoints: &[&RuntimeCheckpoint],
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    mut hook: impl FnMut(ReceiptScanPoint) -> anyhow::Result<()>,
) -> anyhow::Result<ManagedVmmSocketRootScan> {
    context.check_active()?;
    if root.assert_current().is_err()
        || receipts.assert_current().is_err()
        || expected_checkpoints.len() > 1024
    {
        return Ok(ManagedVmmSocketRootScan::Residue);
    }

    let first_receipts =
        match scan_receipt_namespace_snapshot(root, receipts, expected_checkpoints, context)? {
            ReceiptNamespaceSnapshot::Exact(snapshot) => snapshot,
            ReceiptNamespaceSnapshot::Residue => return Ok(ManagedVmmSocketRootScan::Residue),
            ReceiptNamespaceSnapshot::Unavailable => {
                return Ok(ManagedVmmSocketRootScan::Unavailable)
            }
        };
    hook(ReceiptScanPoint::FirstSnapshotCaptured)?;

    let mut expected_names = std::collections::BTreeMap::new();
    for checkpoint in expected_checkpoints {
        let paths = match root.planner.paths_from_checkpoint(checkpoint) {
            Ok(paths) => paths,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        let incarnation = match RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint) {
            Ok(authority) => authority.identity().runtime_incarnation.as_str().to_owned(),
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        for (name, kind) in [
            (paths.public_name, ScannedAttemptKind::Public),
            (paths.staging_name, ScannedAttemptKind::Staging),
            (paths.quarantine_name, ScannedAttemptKind::Quarantine),
        ] {
            if expected_names
                .insert(
                    name,
                    ExpectedManagedAttempt {
                        checkpoint,
                        incarnation: incarnation.clone(),
                        kind,
                    },
                )
                .is_some()
            {
                return Ok(ManagedVmmSocketRootScan::Residue);
            }
        }
    }

    let first_names = match managed_root_names(root, context)? {
        Some(names) => names,
        None => return Ok(ManagedVmmSocketRootScan::Unavailable),
    };
    let (expected_user, expected_group) = root.owner();
    let mut seen_incarnations = std::collections::BTreeSet::new();
    let mut scanned = Vec::with_capacity(first_names.len());
    for name in &first_names {
        context.check_active()?;
        let Some(expected) = expected_names.get(name) else {
            return Ok(ManagedVmmSocketRootScan::Residue);
        };
        if !seen_incarnations.insert(expected.incarnation.clone()) {
            return Ok(ManagedVmmSocketRootScan::Residue);
        }
        let receipt_name =
            match RetainedRuntimeLaunchAuthority::from_checkpoint(expected.checkpoint) {
                Ok(authority) => receipt_file_name(&authority.identity().runtime_incarnation)?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("VMM receipt filename is not UTF-8"))?,
                Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
            };
        let Some(scanned_receipt) = first_receipts.get(&receipt_name) else {
            return Ok(ManagedVmmSocketRootScan::Residue);
        };
        let receipt = match decode_receipt(&scanned_receipt.bytes) {
            Ok(receipt) => receipt,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        if receipt
            .validate_against(expected.checkpoint, receipts.state_directory(), root)
            .is_err()
        {
            return Ok(ManagedVmmSocketRootScan::Residue);
        }
        let directory = match open_owned_attempt_directory(
            &root.descriptor,
            name,
            expected_user,
            expected_group,
        ) {
            Ok(Some(directory)) => directory,
            Ok(None) | Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        let allow_missing_marker = expected.kind == ScannedAttemptKind::Staging;
        if verify_closed_owned_directory(&directory, &receipt, allow_missing_marker).is_err() {
            return Ok(ManagedVmmSocketRootScan::Residue);
        }
        let names = match strict_directory_names(&directory) {
            Ok(names) => names,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        if expected.kind == ScannedAttemptKind::Staging
            && (names.contains(VMM_API_SOCKET_BASENAME)
                || names.contains(VMM_VSOCK_SOCKET_BASENAME))
        {
            return Ok(ManagedVmmSocketRootScan::Residue);
        }
        let api_identity = match socket_leaf_identity(
            &directory,
            VMM_API_SOCKET_BASENAME,
            expected_user,
            expected_group,
        ) {
            Ok(identity) => identity,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        let vsock_identity = match socket_leaf_identity(
            &directory,
            VMM_VSOCK_SOCKET_BASENAME,
            expected_user,
            expected_group,
        ) {
            Ok(identity) => identity,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        let marker_identity = match owner_marker_identity(&directory) {
            Ok(identity) => identity,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        scanned.push(ScannedManagedAttempt {
            name: name.clone(),
            contents: names,
            directory_identity: DirectoryIdentity::from_metadata(&directory.metadata()?),
            marker_identity,
            api_identity,
            vsock_identity,
        });
    }

    context.check_active()?;
    let second_names = match managed_root_names(root, context)? {
        Some(names) => names,
        None => return Ok(ManagedVmmSocketRootScan::Unavailable),
    };
    if first_names != second_names || root.assert_current().is_err() {
        return Ok(ManagedVmmSocketRootScan::Residue);
    }
    for attempt in scanned {
        let directory = match open_owned_attempt_directory(
            &root.descriptor,
            &attempt.name,
            expected_user,
            expected_group,
        ) {
            Ok(Some(directory)) => directory,
            Ok(None) | Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        let current_directory = DirectoryIdentity::from_metadata(&directory.metadata()?);
        let current_contents = match strict_directory_names(&directory) {
            Ok(names) => names,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        let current_marker = match owner_marker_identity(&directory) {
            Ok(identity) => identity,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        let current_api = match socket_leaf_identity(
            &directory,
            VMM_API_SOCKET_BASENAME,
            expected_user,
            expected_group,
        ) {
            Ok(identity) => identity,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        let current_vsock = match socket_leaf_identity(
            &directory,
            VMM_VSOCK_SOCKET_BASENAME,
            expected_user,
            expected_group,
        ) {
            Ok(identity) => identity,
            Err(_) => return Ok(ManagedVmmSocketRootScan::Residue),
        };
        if current_directory != attempt.directory_identity
            || current_contents != attempt.contents
            || current_marker != attempt.marker_identity
            || current_api != attempt.api_identity
            || current_vsock != attempt.vsock_identity
        {
            return Ok(ManagedVmmSocketRootScan::Residue);
        }
    }
    hook(ReceiptScanPoint::AttemptsScanned)?;
    let second_receipts =
        match scan_receipt_namespace_snapshot(root, receipts, expected_checkpoints, context)? {
            ReceiptNamespaceSnapshot::Exact(snapshot) => snapshot,
            ReceiptNamespaceSnapshot::Residue => return Ok(ManagedVmmSocketRootScan::Residue),
            ReceiptNamespaceSnapshot::Unavailable => {
                return Ok(ManagedVmmSocketRootScan::Unavailable)
            }
        };
    if first_receipts != second_receipts {
        return Ok(ManagedVmmSocketRootScan::Residue);
    }
    context.check_active()?;
    Ok(ManagedVmmSocketRootScan::Accounted)
}

#[cfg(target_os = "linux")]
pub(crate) fn scan_receipt_namespace_snapshot(
    root: &RetainedManagedVmmSocketRoot,
    receipts: &VmmSocketReceiptStore,
    expected_checkpoints: &[&RuntimeCheckpoint],
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
) -> anyhow::Result<ReceiptNamespaceSnapshot> {
    context.check_active()?;
    if root.assert_current().is_err() || receipts.assert_current().is_err() {
        return Ok(ReceiptNamespaceSnapshot::Residue);
    }
    let mut expected = std::collections::BTreeMap::new();
    for checkpoint in expected_checkpoints {
        let launch = match RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint) {
            Ok(authority) => authority,
            Err(_) => return Ok(ReceiptNamespaceSnapshot::Residue),
        };
        let name = receipt_file_name(&launch.identity().runtime_incarnation)?
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM receipt filename is not UTF-8"))?;
        if expected.insert(name, *checkpoint).is_some() {
            return Ok(ReceiptNamespaceSnapshot::Residue);
        }
    }

    let entries =
        match std::fs::read_dir(format!("/proc/self/fd/{}", receipts.directory.as_raw_fd())) {
            Ok(entries) => entries,
            Err(_) => return Ok(ReceiptNamespaceSnapshot::Unavailable),
        };
    let mut snapshot = std::collections::BTreeMap::new();
    for entry in entries {
        context.check_active()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return Ok(ReceiptNamespaceSnapshot::Unavailable),
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => return Ok(ReceiptNamespaceSnapshot::Residue),
        };
        if snapshot.len() >= 1024 || snapshot.contains_key(&name) {
            return Ok(ReceiptNamespaceSnapshot::Residue);
        }
        let Some(checkpoint) = expected.get(&name) else {
            return Ok(ReceiptNamespaceSnapshot::Residue);
        };
        let name_c = match CString::new(name.as_bytes()) {
            Ok(name) => name,
            Err(_) => return Ok(ReceiptNamespaceSnapshot::Residue),
        };
        let scanned = match read_optional_receipt_snapshot(&receipts.directory, &name_c) {
            Ok(Some(scanned)) => scanned,
            Ok(None) => return Ok(ReceiptNamespaceSnapshot::Residue),
            Err(_) => return Ok(ReceiptNamespaceSnapshot::Residue),
        };
        let receipt = match decode_receipt(&scanned.bytes) {
            Ok(receipt) => receipt,
            Err(_) => return Ok(ReceiptNamespaceSnapshot::Residue),
        };
        if receipt
            .validate_against(checkpoint, receipts.state_directory(), root)
            .is_err()
        {
            return Ok(ReceiptNamespaceSnapshot::Residue);
        }
        snapshot.insert(name, scanned);
    }
    if receipts.assert_current().is_err() {
        return Ok(ReceiptNamespaceSnapshot::Residue);
    }
    context.check_active()?;
    Ok(ReceiptNamespaceSnapshot::Exact(snapshot))
}

#[cfg(target_os = "linux")]
fn managed_root_names(
    root: &RetainedManagedVmmSocketRoot,
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
) -> anyhow::Result<Option<std::collections::BTreeSet<String>>> {
    context.check_active()?;
    let entries = match std::fs::read_dir(format!("/proc/self/fd/{}", root.descriptor.as_raw_fd()))
    {
        Ok(entries) => entries,
        Err(_) => return Ok(None),
    };
    let mut names = std::collections::BTreeSet::new();
    for entry in entries {
        context.check_active()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return Ok(None),
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                return Ok(Some(std::collections::BTreeSet::from([
                    "<non-utf8>".to_owned()
                ])))
            }
        };
        if !names.insert(name) || names.len() > MANAGED_VMM_SOCKET_ROOT_ENTRY_LIMIT {
            return Ok(Some(std::collections::BTreeSet::from([
                "<invalid-root-enumeration>".to_owned(),
            ])));
        }
    }
    Ok(Some(names))
}

#[cfg(target_os = "linux")]
fn owner_marker_identity(directory: &File) -> anyhow::Result<Option<StableFileIdentity>> {
    let marker = match open_at(
        directory,
        &fixed_c_string(VMM_SOCKET_OWNER_BASENAME),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(marker) => marker,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).context("open VMM owner marker identity"),
    };
    let metadata = marker.metadata()?;
    ensure_owned_regular_file(
        &metadata,
        directory.metadata()?.uid(),
        directory.metadata()?.gid(),
        0o600,
    )?;
    Ok(Some(stable_file_identity(&metadata)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmmSocketReceiptPublication {
    Published,
    ExactReplay,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleReceiptLocation {
    Public,
    Quarantine,
}

/// One previous-boot receipt selected only after a bounded, stable, complete
/// receipt-namespace enumeration. The retained bytes and inode identity must
/// still be exact when the launch-root exclusion consumes this candidate.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RetainedStaleVmmSocketReceipt {
    receipt: VmmSocketOwnershipReceiptV1,
    public_name: CString,
    quarantine_name: CString,
    snapshot: ScannedReceipt,
    location: StaleReceiptLocation,
}

#[cfg(target_os = "linux")]
impl RetainedStaleVmmSocketReceipt {
    pub(crate) fn receipt(&self) -> &VmmSocketOwnershipReceiptV1 {
        &self.receipt
    }

    pub(crate) fn cat_id(&self) -> &Id {
        self.receipt.cat_id()
    }

    fn current_name(&self) -> &CStr {
        match self.location {
            StaleReceiptLocation::Public => &self.public_name,
            StaleReceiptLocation::Quarantine => &self.quarantine_name,
        }
    }

    pub(crate) fn assert_current(&self, store: &VmmSocketReceiptStore) -> anyhow::Result<()> {
        store.assert_current()?;
        let current = read_optional_receipt_snapshot(&store.directory, self.current_name())?
            .context("stale-boot VMM receipt disappeared")?;
        anyhow::ensure!(
            current == self.snapshot && decode_receipt(&current.bytes)? == self.receipt,
            "stale-boot VMM receipt changed identity or bytes"
        );
        Ok(())
    }

    pub(crate) fn retire(
        self,
        store: &VmmSocketReceiptStore,
        authority: &impl StaleVmmReceiptRetirementAuthority,
    ) -> anyhow::Result<()> {
        self.retire_inner(store, authority, |_| Ok(()))
    }

    fn retire_inner(
        mut self,
        store: &VmmSocketReceiptStore,
        authority: &impl StaleVmmReceiptRetirementAuthority,
        mut before_point: impl FnMut(StaleReceiptRetirementPoint) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        authority.assert_receipt_retirement(&self.receipt)?;
        self.assert_current(store)?;
        if self.location == StaleReceiptLocation::Public {
            before_point(StaleReceiptRetirementPoint::BeforeQuarantine)?;
            anyhow::ensure!(
                read_optional_receipt_snapshot(&store.directory, &self.quarantine_name)?.is_none(),
                "stale VMM receipt quarantine already exists"
            );
            rename_at_no_replace(
                &store.directory,
                &self.public_name,
                &store.directory,
                &self.quarantine_name,
            )
            .context("quarantine stale-boot VMM receipt")?;
            store
                .directory
                .sync_all()
                .context("fsync stale VMM receipt quarantine")?;
            let moved = read_optional_receipt_snapshot(&store.directory, &self.quarantine_name)?
                .context("quarantined stale VMM receipt disappeared")?;
            // `renameat2` updates ctime, so compare the stable object
            // coordinate and exact bytes rather than the pre-rename ctime.
            // The next retained snapshot includes the new ctime and therefore
            // still detects any subsequent A/B/A content or inode swap.
            if !moved.identity.same_file_object(self.snapshot.identity)
                || moved.bytes != self.snapshot.bytes
                || decode_receipt(&moved.bytes)? != self.receipt
            {
                // Preserve any replacement. A best-effort no-replace restore
                // can only move the exact currently selected quarantine name;
                // failure leaves all evidence isolated for the next scan.
                let _ = rename_at_no_replace(
                    &store.directory,
                    &self.quarantine_name,
                    &store.directory,
                    &self.public_name,
                );
                let _ = store.directory.sync_all();
                anyhow::bail!("stale VMM receipt changed during quarantine")
            }
            self.snapshot = moved;
            self.location = StaleReceiptLocation::Quarantine;
        }
        authority.assert_receipt_retirement(&self.receipt)?;
        self.assert_current(store)?;
        before_point(StaleReceiptRetirementPoint::AfterQuarantine)?;
        before_point(StaleReceiptRetirementPoint::BeforeRemoval)?;
        self.assert_current(store)?;
        unlink_at(&store.directory, &self.quarantine_name, 0)
            .context("remove isolated stale-boot VMM receipt")?;
        store
            .directory
            .sync_all()
            .context("fsync stale VMM receipt removal")?;
        authority.assert_receipt_retirement(&self.receipt)?;
        store.assert_current()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StaleVmmSocketReceiptScan {
    Settled,
    Candidate(Box<RetainedStaleVmmSocketReceipt>),
}

#[cfg(target_os = "linux")]
pub(crate) mod stale_receipt_retirement_sealed {
    pub(crate) trait Sealed {}
}

/// Only the launch-root module may implement this proof. Its implementation
/// owns the same exclusive namespace flock used by every supported physical
/// submit/launcher and proves that the receipt belongs to an older kernel
/// boot before any durable name is removed.
#[cfg(target_os = "linux")]
pub(crate) trait StaleVmmReceiptRetirementAuthority:
    stale_receipt_retirement_sealed::Sealed
{
    fn assert_receipt_retirement(
        &self,
        receipt: &VmmSocketOwnershipReceiptV1,
    ) -> anyhow::Result<()>;
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleReceiptRetirementPoint {
    BeforeQuarantine,
    AfterQuarantine,
    BeforeRemoval,
}

/// Durable receipt store under the identity-selected Node state directory.
/// The namespace itself is provisioned at Node installation/startup, before
/// any per-Cat attempt.  `open_existing` never creates it.
#[derive(Debug)]
pub(crate) struct VmmSocketReceiptStore {
    state_directory: StateDirectory,
    directory: File,
    identity: DirectoryIdentity,
}

impl VmmSocketReceiptStore {
    pub(crate) fn open_existing(state_directory: StateDirectory) -> anyhow::Result<Self> {
        let root = state_directory
            .try_clone_directory()
            .context("retain Node state directory for VMM socket receipts")?;
        let root_metadata = root.metadata()?;
        let name = fixed_c_string(VMM_SOCKET_RECEIPT_NAMESPACE);
        let directory = open_directory_at(&root, &name)
            .context("open provisioned VMM socket receipt namespace")?;
        let metadata = directory.metadata()?;
        ensure_owned_directory(&metadata, root_metadata.uid(), root_metadata.gid(), 0o700)?;
        let store = Self {
            state_directory,
            directory,
            identity: DirectoryIdentity::from_metadata(&metadata),
        };
        store.assert_current()?;
        Ok(store)
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        let root = self
            .state_directory
            .try_reopen_directory()
            .context("reopen Node state directory for VMM socket receipt")?;
        let current = open_directory_at(&root, &fixed_c_string(VMM_SOCKET_RECEIPT_NAMESPACE))?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&self.directory.metadata()?) == self.identity
                && DirectoryIdentity::from_metadata(&current.metadata()?) == self.identity,
            "VMM socket receipt namespace changed identity"
        );
        Ok(())
    }

    pub(crate) fn state_directory(&self) -> &StateDirectory {
        &self.state_directory
    }

    pub(crate) fn identity_coordinate(&self) -> (u64, u64, u32, u32, u32) {
        (
            self.identity.device,
            self.identity.inode,
            self.identity.mode,
            self.identity.user,
            self.identity.group,
        )
    }

    pub(crate) fn load(
        &self,
        incarnation: &RandomId128,
    ) -> anyhow::Result<Option<VmmSocketOwnershipReceiptV1>> {
        self.load_inner(incarnation, || Ok(()))
    }

    /// Select at most one previous-kernel-boot receipt after two identical,
    /// complete descriptor-relative namespace snapshots. Missing expected
    /// receipts are valid; every present public or recovery-quarantine name
    /// must map uniquely to a current retained launch checkpoint.
    #[cfg(target_os = "linux")]
    pub(crate) fn retain_one_stale_boot_receipt(
        &self,
        root: &RetainedManagedVmmSocketRoot,
        expected_checkpoints: &[&RuntimeCheckpoint],
        context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
    ) -> anyhow::Result<StaleVmmSocketReceiptScan> {
        context.check_active()?;
        self.assert_current()?;
        root.assert_current()?;
        anyhow::ensure!(
            expected_checkpoints.len() <= 1024,
            "stale-boot VMM receipt scan exceeds the checkpoint bound"
        );
        let current_boot_id = current_kernel_node_boot_id()?;
        let first = scan_boot_receipt_namespace(
            self,
            root,
            expected_checkpoints,
            &current_boot_id,
            context,
        )?;
        let second = scan_boot_receipt_namespace(
            self,
            root,
            expected_checkpoints,
            &current_boot_id,
            context,
        )?;
        anyhow::ensure!(
            first == second,
            "VMM receipt namespace changed across stale-boot classification"
        );
        self.assert_current()?;
        root.assert_current()?;
        context.check_active()?;
        Ok(first
            .stale
            .into_iter()
            .next()
            .map_or(StaleVmmSocketReceiptScan::Settled, |candidate| {
                StaleVmmSocketReceiptScan::Candidate(Box::new(candidate))
            }))
    }

    fn load_inner(
        &self,
        incarnation: &RandomId128,
        after_observation: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<Option<VmmSocketOwnershipReceiptV1>> {
        self.assert_current()?;
        let name = receipt_file_name(incarnation)?;
        let observed = read_optional_receipt(&self.directory, &name)?;
        after_observation()?;
        // The retained descriptor is only authority while the complete
        // lexical Node-state/receipt-namespace chain still selects it.  This
        // final check closes both a present-read and an absent-read rename
        // window before either observation escapes to reconciliation.
        self.assert_current()?;
        observed.map(|bytes| decode_receipt(&bytes)).transpose()
    }

    pub(crate) fn publish(
        &self,
        receipt: &VmmSocketOwnershipReceiptV1,
    ) -> anyhow::Result<VmmSocketReceiptPublication> {
        self.publish_inner(receipt, |_| Ok(()))
    }

    fn publish_inner(
        &self,
        receipt: &VmmSocketOwnershipReceiptV1,
        mut checkpoint: impl FnMut(ReceiptPublicationPoint) -> anyhow::Result<()>,
    ) -> anyhow::Result<VmmSocketReceiptPublication> {
        self.assert_current()?;
        let bytes = encode_receipt(receipt)?;
        let name = receipt_file_name(receipt.runtime_incarnation())?;
        if let Some(existing) = read_optional_receipt(&self.directory, &name)? {
            anyhow::ensure!(
                existing == bytes && decode_receipt(&existing)? == *receipt,
                "existing VMM socket receipt differs from this attempt"
            );
            self.directory
                .sync_all()
                .context("settle replayed VMM socket receipt directory")?;
            checkpoint(ReceiptPublicationPoint::DirectorySynced)?;
            // Exact replay is still a physical admission result.  Revalidate
            // the complete lexical namespace after the last injected/crash
            // boundary, just as the newly-published path does below.
            self.assert_current()?;
            return Ok(VmmSocketReceiptPublication::ExactReplay);
        }

        #[cfg(target_os = "linux")]
        {
            let mut anonymous = open_anonymous_receipt(&self.directory)?;
            checkpoint(ReceiptPublicationPoint::AnonymousCreated)?;
            anonymous
                .write_all(&bytes)
                .context("write anonymous VMM socket receipt")?;
            anonymous
                .sync_all()
                .context("fsync anonymous VMM socket receipt")?;
            checkpoint(ReceiptPublicationPoint::ContentSynced)?;
            match link_anonymous_no_replace(&anonymous, &self.directory, &name) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    let existing = read_optional_receipt(&self.directory, &name)?
                        .context("VMM socket receipt raced with an unreadable target")?;
                    anyhow::ensure!(
                        existing == bytes && decode_receipt(&existing)? == *receipt,
                        "racing VMM socket receipt differs from this attempt"
                    );
                }
                Err(source) => return Err(source).context("publish VMM socket receipt"),
            }
            checkpoint(ReceiptPublicationPoint::Published)?;
            self.directory
                .sync_all()
                .context("fsync VMM socket receipt directory")?;
            checkpoint(ReceiptPublicationPoint::DirectorySynced)?;
            let existing = read_optional_receipt(&self.directory, &name)?
                .context("published VMM socket receipt disappeared")?;
            anyhow::ensure!(
                existing == bytes && decode_receipt(&existing)? == *receipt,
                "published VMM socket receipt changed"
            );
            self.assert_current()?;
            Ok(VmmSocketReceiptPublication::Published)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (bytes, name, checkpoint);
            anyhow::bail!("durable VMM socket receipt publication requires Linux O_TMPFILE")
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn provision_for_test(state_directory: StateDirectory) -> anyhow::Result<Self> {
        let root = state_directory.try_clone_directory()?;
        let root_metadata = root.metadata()?;
        let name = fixed_c_string(VMM_SOCKET_RECEIPT_NAMESPACE);
        mkdir_at(&root, &name, 0o700)?;
        root.sync_all()?;
        let directory = open_directory_at(&root, &name)?;
        let metadata = directory.metadata()?;
        anyhow::ensure!(
            metadata.uid() == root_metadata.uid() && metadata.gid() == root_metadata.gid(),
            "test receipt namespace owner changed"
        );
        Self::open_existing(state_directory)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct BootReceiptNamespaceSnapshot {
    entries: std::collections::BTreeMap<String, ScannedReceipt>,
    stale: Vec<RetainedStaleVmmSocketReceipt>,
}

#[cfg(target_os = "linux")]
fn scan_boot_receipt_namespace(
    store: &VmmSocketReceiptStore,
    root: &RetainedManagedVmmSocketRoot,
    expected_checkpoints: &[&RuntimeCheckpoint],
    current_boot_id: &NodeBootId,
    context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
) -> anyhow::Result<BootReceiptNamespaceSnapshot> {
    context.check_active()?;
    let mut expected = std::collections::BTreeMap::new();
    for checkpoint in expected_checkpoints {
        let authority = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let public = receipt_file_name(&authority.identity().runtime_incarnation)?;
        let quarantine =
            stale_receipt_quarantine_file_name(&authority.identity().runtime_incarnation)?;
        let public = public
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM receipt filename is not UTF-8"))?;
        let quarantine = quarantine
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM receipt quarantine filename is not UTF-8"))?;
        anyhow::ensure!(
            expected
                .insert(public, (*checkpoint, StaleReceiptLocation::Public))
                .is_none()
                && expected
                    .insert(quarantine, (*checkpoint, StaleReceiptLocation::Quarantine),)
                    .is_none(),
            "VMM receipt recovery names duplicate retained identities"
        );
    }

    let entries = std::fs::read_dir(format!("/proc/self/fd/{}", store.directory.as_raw_fd()))
        .context("enumerate VMM receipt namespace for boot recovery")?;
    let mut snapshot = std::collections::BTreeMap::new();
    for entry in entries {
        context.check_active()?;
        let entry = entry.context("read VMM receipt namespace entry for boot recovery")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM receipt recovery name is not UTF-8"))?;
        anyhow::ensure!(
            snapshot.len() < 1024 && !snapshot.contains_key(&name),
            "VMM receipt recovery namespace is duplicate or over bound"
        );
        anyhow::ensure!(
            expected.contains_key(&name),
            "VMM receipt recovery found an unattributable name"
        );
        let name_c = CString::new(name.as_bytes())?;
        let scanned = read_optional_receipt_snapshot(&store.directory, &name_c)?
            .context("enumerated VMM receipt disappeared during boot recovery")?;
        snapshot.insert(name, scanned);
    }

    let mut stale = Vec::new();
    let mut seen_incarnations = std::collections::BTreeSet::new();
    for (name, scanned) in &snapshot {
        let (checkpoint, location) = expected
            .get(name)
            .expect("snapshot names were checked against expected names");
        let receipt = decode_receipt(&scanned.bytes)?;
        anyhow::ensure!(
            seen_incarnations.insert(receipt.runtime_incarnation.clone()),
            "VMM receipt recovery found public and quarantine aliases"
        );
        if receipt.node_boot_id() == current_boot_id {
            anyhow::ensure!(
                *location == StaleReceiptLocation::Public,
                "current-boot VMM receipt is stranded in recovery quarantine"
            );
            receipt.validate_against(checkpoint, store.state_directory(), root)?;
            continue;
        }
        receipt.validate_stale_boot_against(
            checkpoint,
            store.state_directory(),
            root,
            current_boot_id,
        )?;
        let public_name = receipt_file_name(receipt.runtime_incarnation())?;
        let quarantine_name = stale_receipt_quarantine_file_name(receipt.runtime_incarnation())?;
        stale.push(RetainedStaleVmmSocketReceipt {
            receipt,
            public_name,
            quarantine_name,
            snapshot: scanned.clone(),
            location: *location,
        });
    }
    store.assert_current()?;
    context.check_active()?;
    Ok(BootReceiptNamespaceSnapshot {
        entries: snapshot,
        stale,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptPublicationPoint {
    AnonymousCreated,
    ContentSynced,
    Published,
    DirectorySynced,
}

/// Result of preparing the provider-private API listener for one already
/// checkpointed StartRuntime attempt. `ExistingLive` is deliberately not an
/// adoption result: only the systemd/process/API inspector can decide whether
/// the holder is the exact VMM.  The namespace owner therefore never unlinks
/// or replaces a live endpoint while trying to start.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) enum ManagedVmmSocketPreparation<'a> {
    Prepared(Box<PreparedManagedVmmSocketAttempt<'a>>),
    ExistingLive,
}

/// Descriptor-retained API listener which may be transferred to the fixed
/// launcher.  It owns no stop authority: dropping this value only closes the
/// Agent's descriptor and intentionally leaves the exact-owned filesystem
/// entry for crash discovery.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct PreparedManagedVmmSocketAttempt<'a> {
    root: &'a RetainedManagedVmmSocketRoot,
    receipt: VmmSocketOwnershipReceiptV1,
    public_directory: File,
    public_identity: DirectoryIdentity,
    api_socket_identity: StableSocketLeafIdentity,
    api_listener: File,
    api_kernel_inode: u64,
}

#[cfg(target_os = "linux")]
impl PreparedManagedVmmSocketAttempt<'_> {
    pub(crate) fn receipt(&self) -> &VmmSocketOwnershipReceiptV1 {
        &self.receipt
    }

    pub(crate) fn api_listener(&self) -> &File {
        &self.api_listener
    }

    pub(crate) fn assert_current(&self) -> anyhow::Result<()> {
        self.root.assert_current()?;
        let metadata = self.public_directory.metadata()?;
        ensure_owned_directory(
            &metadata,
            self.public_identity.user,
            self.public_identity.group,
            0o700,
        )?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&metadata) == self.public_identity,
            "retained VMM public socket directory changed"
        );
        let public_name = CString::new(self.receipt.public_name.as_bytes())?;
        let reopened = open_directory_at(&self.root.descriptor, &public_name)
            .context("reopen VMM public socket directory")?;
        anyhow::ensure!(
            DirectoryIdentity::from_metadata(&reopened.metadata()?) == self.public_identity,
            "VMM public socket directory pathname changed identity"
        );
        verify_owner_marker(&self.public_directory, &self.receipt)?;
        let current = socket_leaf_identity(
            &self.public_directory,
            VMM_API_SOCKET_BASENAME,
            self.public_identity.user,
            self.public_identity.group,
        )?
        .context("prepared VMM API socket disappeared")?;
        anyhow::ensure!(
            current == self.api_socket_identity,
            "prepared VMM API socket pathname changed identity"
        );
        ensure_listening_unix_socket(&self.api_listener)?;
        anyhow::ensure!(
            socket_kernel_inode(&self.api_listener)? == self.api_kernel_inode,
            "prepared VMM API listener changed kernel identity"
        );
        api_listener_self_handshake(
            &self.api_listener,
            Path::new(self.receipt.api_socket_path.as_str()),
        )?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StableSocketLeafIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    user: u32,
    group: u32,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamespacePreparationPoint {
    StagingCreated,
    OwnerMarkerSynced,
    PublicPublished,
    PublicQuarantined,
    QuarantineRemoved,
    ApiBound,
    DirectorySynced,
}

#[cfg(target_os = "linux")]
impl RetainedManagedVmmSocketRoot {
    /// A previous kernel boot cannot leave a live Unix socket inode in the
    /// newly-created `/run` namespace. Never delete a same-name current-boot
    /// replacement: stale receipt retirement is allowed only while all three
    /// deterministic attempt names are absent from the current root.
    pub(crate) fn assert_stale_boot_attempt_absent(
        &self,
        receipt: &VmmSocketOwnershipReceiptV1,
    ) -> anyhow::Result<()> {
        self.assert_current()?;
        let (expected_user, expected_group) = self.owner();
        for name in [
            &receipt.public_name,
            &receipt.staging_name,
            &receipt.quarantine_name,
        ] {
            anyhow::ensure!(
                open_owned_attempt_directory(
                    &self.descriptor,
                    name,
                    expected_user,
                    expected_group,
                )?
                .is_none(),
                "current boot contains a same-name VMM socket attempt"
            );
        }
        self.assert_current()
    }

    /// Recover or prepare one exact-owned public directory and pre-bound API
    /// listener.  The durable receipt must already exist.  This method never
    /// creates the installed root or receipt namespace and never interprets a
    /// socket cleanup as proof that a VMM stopped.
    pub(crate) fn prepare_existing_receipt<'a>(
        &'a self,
        checkpoint: &RuntimeCheckpoint,
        receipts: &VmmSocketReceiptStore,
    ) -> anyhow::Result<ManagedVmmSocketPreparation<'a>> {
        self.prepare_existing_receipt_inner(checkpoint, receipts, |_| Ok(()))
    }

    fn prepare_existing_receipt_inner<'a>(
        &'a self,
        checkpoint: &RuntimeCheckpoint,
        receipts: &VmmSocketReceiptStore,
        mut checkpoint_hook: impl FnMut(NamespacePreparationPoint) -> anyhow::Result<()>,
    ) -> anyhow::Result<ManagedVmmSocketPreparation<'a>> {
        self.assert_current()?;
        receipts.assert_current()?;
        let launch = RetainedRuntimeLaunchAuthority::from_checkpoint(checkpoint)?;
        let receipt = receipts
            .load(&launch.identity().runtime_incarnation)?
            .context("VMM socket ownership receipt is not durable")?;
        let paths = receipt.validate_against(checkpoint, receipts.state_directory(), self)?;
        let (expected_user, expected_group) = self.owner();

        // A single prior crash residue is recoverable. Two names for the same
        // incarnation cannot be produced by this serialized no-replace state
        // machine; they are therefore a rename/recreate ABA and both must be
        // preserved. In particular, never settle quarantine before checking
        // whether a fresh public or staging name appeared beside it.
        let mut public = open_owned_attempt_directory(
            &self.descriptor,
            &paths.public_name,
            expected_user,
            expected_group,
        )?;
        let staging = open_owned_attempt_directory(
            &self.descriptor,
            &paths.staging_name,
            expected_user,
            expected_group,
        )?;
        let quarantine = open_owned_attempt_directory(
            &self.descriptor,
            &paths.quarantine_name,
            expected_user,
            expected_group,
        )?;
        let present_names = usize::from(public.is_some())
            + usize::from(staging.is_some())
            + usize::from(quarantine.is_some());
        anyhow::ensure!(
            present_names <= 1,
            "multiple VMM socket attempt names are a preserved ABA conflict"
        );
        if quarantine.is_some() {
            settle_quarantine(
                self,
                &receipt,
                expected_user,
                expected_group,
                &mut checkpoint_hook,
            )?;
        }
        if public.is_none() {
            let staging = match staging {
                Some(staging) => {
                    ensure_owner_marker(&staging, &receipt, true)?;
                    verify_closed_owned_directory(&staging, &receipt, true)?;
                    staging
                }
                None => {
                    let staging_name = CString::new(paths.staging_name.as_bytes())?;
                    mkdir_at(&self.descriptor, &staging_name, 0o700)
                        .context("create VMM staging socket directory")?;
                    checkpoint_hook(NamespacePreparationPoint::StagingCreated)?;
                    self.descriptor.sync_all()?;
                    let staging = open_directory_at(&self.descriptor, &staging_name)?;
                    ensure_owned_directory(
                        &staging.metadata()?,
                        expected_user,
                        expected_group,
                        0o700,
                    )?;
                    ensure_owner_marker(&staging, &receipt, false)?;
                    checkpoint_hook(NamespacePreparationPoint::OwnerMarkerSynced)?;
                    staging.sync_all()?;
                    staging
                }
            };
            publish_staging_directory(self, &paths, &staging)?;
            checkpoint_hook(NamespacePreparationPoint::PublicPublished)?;
            public = Some(open_directory_at(
                &self.descriptor,
                &CString::new(paths.public_name.as_bytes())?,
            )?);
        }

        let mut public = public.context("VMM public socket directory was not published")?;
        verify_closed_owned_directory(&public, &receipt, false)?;
        match classify_attempt_sockets(&public, &paths, expected_user, expected_group)? {
            AttemptSocketState::Empty => {}
            AttemptSocketState::Live => return Ok(ManagedVmmSocketPreparation::ExistingLive),
            AttemptSocketState::Stale => {
                quarantine_public_directory(
                    self,
                    &paths,
                    &public,
                    &receipt,
                    expected_user,
                    expected_group,
                )?;
                checkpoint_hook(NamespacePreparationPoint::PublicQuarantined)?;
                settle_quarantine(
                    self,
                    &receipt,
                    expected_user,
                    expected_group,
                    &mut checkpoint_hook,
                )?;
                let staging_name = CString::new(paths.staging_name.as_bytes())?;
                mkdir_at(&self.descriptor, &staging_name, 0o700)
                    .context("recreate VMM staging socket directory")?;
                checkpoint_hook(NamespacePreparationPoint::StagingCreated)?;
                self.descriptor.sync_all()?;
                let staging = open_directory_at(&self.descriptor, &staging_name)?;
                ensure_owned_directory(&staging.metadata()?, expected_user, expected_group, 0o700)?;
                ensure_owner_marker(&staging, &receipt, false)?;
                checkpoint_hook(NamespacePreparationPoint::OwnerMarkerSynced)?;
                staging.sync_all()?;
                publish_staging_directory(self, &paths, &staging)?;
                checkpoint_hook(NamespacePreparationPoint::PublicPublished)?;
                public = open_directory_at(
                    &self.descriptor,
                    &CString::new(paths.public_name.as_bytes())?,
                )?;
                verify_closed_owned_directory(&public, &receipt, false)?;
            }
        }

        let api_listener = bind_api_listener(&public, expected_user, expected_group)?;
        checkpoint_hook(NamespacePreparationPoint::ApiBound)?;
        public.sync_all()?;
        self.descriptor.sync_all()?;
        checkpoint_hook(NamespacePreparationPoint::DirectorySynced)?;
        let public_identity = DirectoryIdentity::from_metadata(&public.metadata()?);
        let api_socket_identity = socket_leaf_identity(
            &public,
            VMM_API_SOCKET_BASENAME,
            expected_user,
            expected_group,
        )?
        .context("bound VMM API socket is absent")?;
        let prepared = PreparedManagedVmmSocketAttempt {
            root: self,
            receipt,
            public_directory: public,
            public_identity,
            api_kernel_inode: socket_kernel_inode(&api_listener)?,
            api_socket_identity,
            api_listener,
        };
        prepared.assert_current()?;
        Ok(ManagedVmmSocketPreparation::Prepared(Box::new(prepared)))
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptSocketState {
    Empty,
    Stale,
    Live,
}

#[cfg(target_os = "linux")]
fn classify_attempt_sockets(
    directory: &File,
    paths: &ManagedVmmSocketPaths,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<AttemptSocketState> {
    let api = socket_leaf_identity(
        directory,
        VMM_API_SOCKET_BASENAME,
        expected_user,
        expected_group,
    )?;
    let vsock = socket_leaf_identity(
        directory,
        VMM_VSOCK_SOCKET_BASENAME,
        expected_user,
        expected_group,
    )?;
    if api.is_none() && vsock.is_none() {
        return Ok(AttemptSocketState::Empty);
    }
    if api.is_some() {
        match probe_api_socket(Path::new(paths.api_socket_path.as_str()))? {
            SocketLiveness::Live => return Ok(AttemptSocketState::Live),
            SocketLiveness::Stale => {}
            SocketLiveness::Unavailable => {
                anyhow::bail!("VMM API socket liveness is unavailable")
            }
        }
    }
    if vsock.is_some() {
        match named_unix_socket_liveness(paths.vsock_socket_path.as_str())? {
            SocketLiveness::Live => return Ok(AttemptSocketState::Live),
            SocketLiveness::Stale => {}
            SocketLiveness::Unavailable => {
                anyhow::bail!("VMM vsock liveness is unavailable")
            }
        }
    }
    Ok(AttemptSocketState::Stale)
}

#[cfg(target_os = "linux")]
fn open_owned_attempt_directory(
    root: &File,
    name: &str,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<Option<File>> {
    let name = CString::new(name)?;
    match open_directory_at(root, &name) {
        Ok(directory) => {
            ensure_owned_directory(&directory.metadata()?, expected_user, expected_group, 0o700)?;
            Ok(Some(directory))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(source).context("open VMM attempt socket directory"),
    }
}

#[cfg(target_os = "linux")]
fn ensure_owner_marker(
    directory: &File,
    receipt: &VmmSocketOwnershipReceiptV1,
    allow_missing_incomplete: bool,
) -> anyhow::Result<()> {
    let name = fixed_c_string(VMM_SOCKET_OWNER_BASENAME);
    if let Some(existing) = read_optional_receipt(directory, &name)? {
        anyhow::ensure!(
            existing == receipt.encoded_bytes()?,
            "VMM socket owner marker differs from its durable receipt"
        );
        return Ok(());
    }
    if allow_missing_incomplete {
        anyhow::ensure!(
            strict_directory_names(directory)?.is_empty(),
            "unmarked VMM staging directory is not empty"
        );
    }
    let bytes = receipt.encoded_bytes()?;
    let mut marker = open_at(
        directory,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .context("create VMM socket owner marker")?;
    marker.write_all(&bytes)?;
    marker.sync_all()?;
    directory.sync_all()?;
    verify_owner_marker(directory, receipt)
}

#[cfg(target_os = "linux")]
fn verify_owner_marker(
    directory: &File,
    receipt: &VmmSocketOwnershipReceiptV1,
) -> anyhow::Result<()> {
    let name = fixed_c_string(VMM_SOCKET_OWNER_BASENAME);
    let existing =
        read_optional_receipt(directory, &name)?.context("VMM socket owner marker is missing")?;
    anyhow::ensure!(
        existing == receipt.encoded_bytes()?,
        "VMM socket owner marker differs from its durable receipt"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_closed_owned_directory(
    directory: &File,
    receipt: &VmmSocketOwnershipReceiptV1,
    allow_missing_marker: bool,
) -> anyhow::Result<()> {
    let names = strict_directory_names(directory)?;
    anyhow::ensure!(
        names.iter().all(|name| {
            name == VMM_SOCKET_OWNER_BASENAME
                || name == VMM_API_SOCKET_BASENAME
                || name == VMM_VSOCK_SOCKET_BASENAME
        }),
        "VMM socket directory contains a foreign entry"
    );
    if allow_missing_marker && !names.contains(VMM_SOCKET_OWNER_BASENAME) {
        anyhow::ensure!(
            names.is_empty(),
            "unmarked VMM socket directory is not empty"
        );
    } else {
        verify_owner_marker(directory, receipt)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn strict_directory_names(directory: &File) -> anyhow::Result<std::collections::BTreeSet<String>> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let entries = std::fs::read_dir(path).context("enumerate retained VMM socket directory")?;
    let mut names = std::collections::BTreeSet::new();
    for entry in entries {
        let entry = entry.context("read retained VMM socket directory entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("VMM socket directory entry is not UTF-8"))?;
        anyhow::ensure!(
            names.insert(name),
            "VMM socket directory contains a duplicate entry"
        );
        anyhow::ensure!(
            names.len() <= 3,
            "VMM socket directory exceeds its closed entry bound"
        );
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn publish_staging_directory(
    root: &RetainedManagedVmmSocketRoot,
    paths: &ManagedVmmSocketPaths,
    staging: &File,
) -> anyhow::Result<()> {
    root.assert_current()?;
    let before = DirectoryIdentity::from_metadata(&staging.metadata()?);
    rename_at_no_replace(
        &root.descriptor,
        &CString::new(paths.staging_name.as_bytes())?,
        &root.descriptor,
        &CString::new(paths.public_name.as_bytes())?,
    )
    .context("publish VMM socket directory")?;
    root.descriptor.sync_all()?;
    let public = open_directory_at(
        &root.descriptor,
        &CString::new(paths.public_name.as_bytes())?,
    )?;
    anyhow::ensure!(
        DirectoryIdentity::from_metadata(&public.metadata()?) == before,
        "published VMM socket directory changed identity"
    );
    anyhow::ensure!(
        open_owned_attempt_directory(
            &root.descriptor,
            paths.staging_name(),
            before.user,
            before.group,
        )?
        .is_none(),
        "VMM staging directory remained after publication"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn quarantine_public_directory(
    root: &RetainedManagedVmmSocketRoot,
    paths: &ManagedVmmSocketPaths,
    public: &File,
    receipt: &VmmSocketOwnershipReceiptV1,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<()> {
    verify_closed_owned_directory(public, receipt, false)?;
    anyhow::ensure!(
        open_owned_attempt_directory(
            &root.descriptor,
            paths.quarantine_name(),
            expected_user,
            expected_group,
        )?
        .is_none(),
        "VMM quarantine directory is already occupied"
    );
    let before = DirectoryIdentity::from_metadata(&public.metadata()?);
    rename_at_no_replace(
        &root.descriptor,
        &CString::new(paths.public_name.as_bytes())?,
        &root.descriptor,
        &CString::new(paths.quarantine_name.as_bytes())?,
    )?;
    root.descriptor.sync_all()?;
    let quarantine = open_directory_at(
        &root.descriptor,
        &CString::new(paths.quarantine_name.as_bytes())?,
    )?;
    anyhow::ensure!(
        DirectoryIdentity::from_metadata(&quarantine.metadata()?) == before,
        "quarantined VMM socket directory changed identity"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn settle_quarantine(
    root: &RetainedManagedVmmSocketRoot,
    receipt: &VmmSocketOwnershipReceiptV1,
    expected_user: u32,
    expected_group: u32,
    checkpoint_hook: &mut impl FnMut(NamespacePreparationPoint) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let Some(quarantine) = open_owned_attempt_directory(
        &root.descriptor,
        &receipt.quarantine_name,
        expected_user,
        expected_group,
    )?
    else {
        return Ok(());
    };
    verify_closed_owned_directory(&quarantine, receipt, false)?;
    cleanup_exact_owned_directory(&quarantine, receipt, false, expected_user, expected_group)?;
    remove_exact_directory(
        &root.descriptor,
        &receipt.quarantine_name,
        &quarantine,
        expected_user,
        expected_group,
    )?;
    root.descriptor.sync_all()?;
    checkpoint_hook(NamespacePreparationPoint::QuarantineRemoved)
}

#[cfg(target_os = "linux")]
fn cleanup_exact_owned_directory(
    directory: &File,
    receipt: &VmmSocketOwnershipReceiptV1,
    allow_missing_marker: bool,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<()> {
    verify_closed_owned_directory(directory, receipt, allow_missing_marker)?;
    for basename in [VMM_API_SOCKET_BASENAME, VMM_VSOCK_SOCKET_BASENAME] {
        let Some(identity) =
            socket_leaf_identity(directory, basename, expected_user, expected_group)?
        else {
            continue;
        };
        let liveness = socket_leaf_liveness(directory, basename, receipt)?;
        anyhow::ensure!(
            liveness == SocketLiveness::Stale,
            "refuse to unlink a live or unclassifiable VMM socket"
        );
        unlink_socket_leaf_if_exact(directory, basename, identity)?;
        directory.sync_all()?;
    }
    let marker = fixed_c_string(VMM_SOCKET_OWNER_BASENAME);
    match unlink_at(directory, &marker, 0) {
        Ok(()) => directory.sync_all()?,
        Err(source) if source.kind() == io::ErrorKind::NotFound && allow_missing_marker => {}
        Err(source) => return Err(source).context("remove VMM socket owner marker"),
    }
    anyhow::ensure!(
        strict_directory_names(directory)?.is_empty(),
        "VMM socket directory was not emptied"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_exact_directory(
    root: &File,
    name: &str,
    directory: &File,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<()> {
    let expected = DirectoryIdentity::from_metadata(&directory.metadata()?);
    ensure_owned_directory(&directory.metadata()?, expected_user, expected_group, 0o700)?;
    let reopened = open_directory_at(root, &CString::new(name.as_bytes())?)?;
    anyhow::ensure!(
        DirectoryIdentity::from_metadata(&reopened.metadata()?) == expected,
        "VMM socket directory changed before removal"
    );
    unlink_at(root, &CString::new(name.as_bytes())?, libc::AT_REMOVEDIR)
        .context("remove exact VMM socket directory")
}

#[cfg(target_os = "linux")]
fn bind_api_listener(
    public: &File,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<File> {
    anyhow::ensure!(
        socket_leaf_identity(
            public,
            VMM_API_SOCKET_BASENAME,
            expected_user,
            expected_group,
        )?
        .is_none(),
        "VMM API socket already exists"
    );
    let bind_path = format!(
        "/proc/self/fd/{}/{}",
        public.as_raw_fd(),
        VMM_API_SOCKET_BASENAME
    );
    anyhow::ensure!(
        bind_path.len() < UNIX_SOCKET_PATH_CAPACITY,
        "descriptor-relative VMM API socket path exceeds sockaddr_un"
    );
    // SAFETY: socket returns one fresh descriptor and retains no Rust data.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error()).context("create VMM API listener");
    }
    // SAFETY: the fresh descriptor is transferred exactly once to File.
    let listener = unsafe { File::from_raw_fd(descriptor) };
    let bytes = bind_path.as_bytes();
    // SAFETY: zeroed sockaddr_un is valid initialization and all fields read
    // by bind are initialized below.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes.iter().copied()) {
        *target = source as libc::c_char;
    }
    let length = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: listener and address remain live for the call; bind retains no
    // Rust pointer.
    let result = unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error()).context("bind VMM API listener no-replace");
    }
    let basename = fixed_c_string(VMM_API_SOCKET_BASENAME);
    fchmod_at(public, &basename, 0o700)?;
    // SAFETY: listen changes only the state of this live Unix socket.
    if unsafe { libc::listen(listener.as_raw_fd(), VMM_SOCKET_LISTEN_BACKLOG) } != 0 {
        return Err(io::Error::last_os_error()).context("listen on VMM API socket");
    }
    ensure_listening_unix_socket(&listener)?;
    let identity = socket_leaf_identity(
        public,
        VMM_API_SOCKET_BASENAME,
        expected_user,
        expected_group,
    )?
    .context("VMM API bind did not create its exact leaf")?;
    let reopened = socket_leaf_identity(
        public,
        VMM_API_SOCKET_BASENAME,
        expected_user,
        expected_group,
    )?
    .context("VMM API socket disappeared after bind")?;
    anyhow::ensure!(identity == reopened, "VMM API socket changed after bind");
    Ok(listener)
}

#[cfg(target_os = "linux")]
fn ensure_listening_unix_socket(socket: &File) -> anyhow::Result<()> {
    let metadata = socket.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_socket(),
        "VMM API descriptor is not a socket"
    );
    let mut value = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: value/length are valid writable storage and the descriptor is
    // live for the complete getsockopt call.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    anyhow::ensure!(
        result == 0 && length as usize == std::mem::size_of::<i32>() && value == 1,
        "VMM API descriptor is not a listening socket"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn api_listener_self_handshake(listener: &File, path: &Path) -> anyhow::Result<()> {
    use std::os::unix::net::UnixStream;

    let client = UnixStream::connect(path).context("connect prepared VMM API listener")?;
    // SAFETY: the listener is live and nonblocking. The immediately preceding
    // connect queued one local connection; accept4 returns a fresh descriptor.
    let accepted = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        )
    };
    if accepted < 0 {
        return Err(io::Error::last_os_error()).context("accept VMM API self-handshake");
    }
    // SAFETY: accept4 returned one fresh descriptor owned by this File.
    let accepted = unsafe { File::from_raw_fd(accepted) };
    let self_pid = std::process::id();
    anyhow::ensure!(
        socket_peer_process_id(client.as_raw_fd()) == Some(self_pid)
            && socket_peer_process_id(accepted.as_raw_fd()) == Some(self_pid),
        "prepared VMM API descriptor/path peer identity differs"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn socket_peer_process_id(descriptor: i32) -> Option<u32> {
    // SAFETY: zeroed ucred is valid output storage for SO_PEERCRED.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials/length are writable and descriptor remains live.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<libc::ucred>() && credentials.pid > 0)
        .then_some(credentials.pid as u32)
}

#[cfg(target_os = "linux")]
fn socket_leaf_identity(
    directory: &File,
    basename: &str,
    expected_user: u32,
    expected_group: u32,
) -> anyhow::Result<Option<StableSocketLeafIdentity>> {
    let name = CString::new(basename)?;
    let leaf = match open_at(
        directory,
        &name,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(leaf) => leaf,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).context("open VMM socket leaf"),
    };
    let metadata = leaf.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_socket()
            && metadata.nlink() == 1
            && metadata.uid() == expected_user
            && metadata.gid() == expected_group
            && metadata.mode() & 0o7777 == 0o700,
        "VMM socket leaf has unsafe type, links, owner or mode"
    );
    Ok(Some(StableSocketLeafIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        user: metadata.uid(),
        group: metadata.gid(),
    }))
}

#[cfg(target_os = "linux")]
fn unlink_socket_leaf_if_exact(
    directory: &File,
    basename: &str,
    expected: StableSocketLeafIdentity,
) -> anyhow::Result<()> {
    let current = socket_leaf_identity(directory, basename, expected.user, expected.group)?
        .context("VMM socket leaf disappeared before exact unlink")?;
    anyhow::ensure!(current == expected, "VMM socket leaf changed before unlink");
    unlink_at(directory, &CString::new(basename)?, 0).context("unlink exact stale VMM socket")
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketLiveness {
    Live,
    Stale,
    Unavailable,
}

#[cfg(target_os = "linux")]
fn probe_api_socket(path: &Path) -> anyhow::Result<SocketLiveness> {
    use std::os::unix::net::UnixStream;

    match UnixStream::connect(path) {
        Ok(stream) => {
            drop(stream);
            Ok(SocketLiveness::Live)
        }
        Err(source) if source.raw_os_error() == Some(libc::ECONNREFUSED) => {
            Ok(SocketLiveness::Stale)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(SocketLiveness::Stale),
        Err(_) => Ok(SocketLiveness::Unavailable),
    }
}

#[cfg(target_os = "linux")]
fn named_unix_socket_liveness(path: &str) -> anyhow::Result<SocketLiveness> {
    let file = match File::open("/proc/net/unix") {
        Ok(file) => file,
        Err(_) => return Ok(SocketLiveness::Unavailable),
    };
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Ok(SocketLiveness::Unavailable);
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => return Ok(SocketLiveness::Unavailable),
    };
    Ok(
        if text
            .lines()
            .skip(1)
            .any(|line| line.split_ascii_whitespace().last() == Some(path))
        {
            SocketLiveness::Live
        } else {
            SocketLiveness::Stale
        },
    )
}

#[cfg(target_os = "linux")]
fn socket_leaf_liveness(
    directory: &File,
    basename: &str,
    receipt: &VmmSocketOwnershipReceiptV1,
) -> anyhow::Result<SocketLiveness> {
    let descriptor_relative = format!("/proc/self/fd/{}/{}", directory.as_raw_fd(), basename);
    if basename == VMM_API_SOCKET_BASENAME {
        // The API listener was bound through a descriptor-relative pathname,
        // whose numeric FD is not durable across recovery.  Connecting
        // through this retained directory proves the current socket inode is
        // still accepting; any non-refused result remains fail closed.
        return probe_api_socket(Path::new(&descriptor_relative));
    }

    // Cloud Hypervisor binds the vsock backend at the canonical public path.
    // After a crash-recovery rename, Linux retains that original name in
    // /proc/net/unix, while a future implementation could report the current
    // descriptor-relative name. Check both and never turn an unreadable table
    // into stale authority.
    for path in [receipt.vsock_socket_path.as_str(), &descriptor_relative] {
        match named_unix_socket_liveness(path)? {
            SocketLiveness::Live => return Ok(SocketLiveness::Live),
            SocketLiveness::Unavailable => return Ok(SocketLiveness::Unavailable),
            SocketLiveness::Stale => {}
        }
    }
    Ok(SocketLiveness::Stale)
}

#[cfg(target_os = "linux")]
fn socket_kernel_inode(socket: &File) -> anyhow::Result<u64> {
    let target = std::fs::read_link(format!("/proc/self/fd/{}", socket.as_raw_fd()))?;
    let bytes = target.as_os_str().as_bytes();
    let payload = bytes
        .strip_prefix(b"socket:[")
        .and_then(|bytes| bytes.strip_suffix(b"]"))
        .context("VMM API descriptor lacks a kernel socket inode")?;
    std::str::from_utf8(payload)?
        .parse::<u64>()
        .context("parse VMM API kernel socket inode")
}

#[cfg(target_os = "linux")]
fn rename_at_no_replace(
    old_parent: &File,
    old_name: &CStr,
    new_parent: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both parent descriptors and names remain live; renameat2
        // retains no Rust pointer and RENAME_NOREPLACE forbids overwrite.
        let result = unsafe {
            libc::renameat2(
                old_parent.as_raw_fd(),
                old_name.as_ptr(),
                new_parent.as_raw_fd(),
                new_name.as_ptr(),
                libc::RENAME_NOREPLACE,
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

#[cfg(target_os = "linux")]
fn unlink_at(parent: &File, name: &CStr, flags: i32) -> io::Result<()> {
    loop {
        // SAFETY: parent/name remain live and unlinkat retains neither.
        let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

#[cfg(target_os = "linux")]
fn fchmod_at(parent: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    loop {
        // SAFETY: parent/name remain live and fchmodat retains neither.
        let result = unsafe { libc::fchmodat(parent.as_raw_fd(), name.as_ptr(), mode, 0) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn encode_receipt(receipt: &VmmSocketOwnershipReceiptV1) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        receipt.version == VMM_SOCKET_RECEIPT_VERSION,
        "unsupported VMM socket receipt version"
    );
    let bytes = serde_json::to_vec(receipt).context("encode VMM socket ownership receipt")?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= VMM_SOCKET_RECEIPT_MAX_BYTES,
        "VMM socket ownership receipt exceeds its wire bound"
    );
    anyhow::ensure!(
        decode_receipt(&bytes)? == *receipt,
        "VMM socket ownership receipt is not canonically encodable"
    );
    Ok(bytes)
}

fn decode_receipt(bytes: &[u8]) -> anyhow::Result<VmmSocketOwnershipReceiptV1> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= VMM_SOCKET_RECEIPT_MAX_BYTES,
        "VMM socket ownership receipt length is outside its bound"
    );
    let receipt: VmmSocketOwnershipReceiptV1 =
        serde_json::from_slice(bytes).context("decode VMM socket ownership receipt")?;
    anyhow::ensure!(
        receipt.version == VMM_SOCKET_RECEIPT_VERSION,
        "unsupported VMM socket receipt version"
    );
    let canonical =
        serde_json::to_vec(&receipt).context("re-encode VMM socket ownership receipt")?;
    anyhow::ensure!(
        canonical == bytes,
        "VMM socket ownership receipt is not canonical"
    );
    Ok(receipt)
}

fn receipt_file_name(incarnation: &RandomId128) -> anyhow::Result<CString> {
    CString::new(format!("vmm-{}.receipt.json", incarnation.as_str()))
        .context("VMM socket receipt filename contains NUL")
}

#[cfg(target_os = "linux")]
fn stale_receipt_quarantine_file_name(incarnation: &RandomId128) -> anyhow::Result<CString> {
    CString::new(format!("q-vmm-{}.receipt.json", incarnation.as_str()))
        .context("VMM stale receipt quarantine filename contains NUL")
}

fn read_optional_receipt(directory: &File, name: &CStr) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(read_optional_receipt_snapshot(directory, name)?.map(|scanned| scanned.bytes))
}

fn read_optional_receipt_snapshot(
    directory: &File,
    name: &CStr,
) -> anyhow::Result<Option<ScannedReceipt>> {
    let mut file = match open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).context("open VMM socket ownership receipt"),
    };
    let before = file.metadata()?;
    ensure_owned_regular_file(
        &before,
        directory.metadata()?.uid(),
        directory.metadata()?.gid(),
        0o600,
    )?;
    anyhow::ensure!(
        before.len() <= VMM_SOCKET_RECEIPT_MAX_BYTES as u64,
        "VMM socket ownership receipt exceeds its wire bound"
    );
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(VMM_SOCKET_RECEIPT_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= VMM_SOCKET_RECEIPT_MAX_BYTES,
        "VMM socket ownership receipt grew beyond its wire bound"
    );
    let after = file.metadata()?;
    anyhow::ensure!(
        stable_file_identity(&before) == stable_file_identity(&after),
        "VMM socket ownership receipt changed while read"
    );
    Ok(Some(ScannedReceipt {
        identity: stable_file_identity(&after),
        bytes,
    }))
}

fn open_directory_chain(path: &Path) -> anyhow::Result<Vec<RetainedPathDirectory>> {
    ensure_canonical_root(path)?;
    let root_name = fixed_c_string("/");
    let root = loop {
        // SAFETY: the fixed root name remains live for this call. A successful
        // descriptor is transferred exactly once to `File`.
        let descriptor = unsafe {
            libc::open(
                root_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor >= 0 {
            // SAFETY: `open` returned one fresh owned descriptor.
            break unsafe { File::from_raw_fd(descriptor) };
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source).context("open filesystem root");
        }
    };
    let root_metadata = root.metadata()?;
    anyhow::ensure!(
        root_metadata.file_type().is_dir() && root_metadata.nlink() > 0,
        "filesystem root is not one live directory"
    );
    let mut directories = vec![RetainedPathDirectory {
        name: std::ffi::OsString::from("/"),
        identity: DirectoryIdentity::from_metadata(&root_metadata),
        descriptor: root,
    }];
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name_c =
            CString::new(name.as_bytes()).context("managed root component contains NUL")?;
        let descriptor = open_directory_at(
            &directories
                .last()
                .expect("filesystem root starts the directory chain")
                .descriptor,
            &name_c,
        )?;
        let metadata = descriptor.metadata()?;
        anyhow::ensure!(
            metadata.file_type().is_dir() && metadata.nlink() > 0,
            "managed VMM socket ancestor is not one live directory"
        );
        directories.push(RetainedPathDirectory {
            name: name.to_owned(),
            identity: DirectoryIdentity::from_metadata(&metadata),
            descriptor,
        });
    }
    Ok(directories)
}

fn open_directory_at(parent: &File, name: &CStr) -> io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
}

fn open_at(parent: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        // SAFETY: `parent` and `name` stay live for this call. A successful
        // descriptor is transferred exactly once to `File`.
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
        if descriptor >= 0 {
            // SAFETY: `openat` returned one fresh owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn mkdir_at(parent: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    loop {
        // SAFETY: `parent` and `name` are live and `mkdirat` retains neither.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

#[cfg(target_os = "linux")]
fn open_anonymous_receipt(directory: &File) -> io::Result<File> {
    let dot = fixed_c_string(".");
    open_at(
        directory,
        &dot,
        libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
        0o600,
    )
}

#[cfg(target_os = "linux")]
fn link_anonymous_no_replace(file: &File, directory: &File, name: &CStr) -> io::Result<()> {
    let empty = fixed_c_string("");
    loop {
        // SAFETY: both descriptors and both C strings remain live.  The
        // anonymous inode is linked exactly once and AT_EMPTY_PATH prevents
        // any pathname lookup for the source.
        let result = unsafe {
            libc::linkat(
                file.as_raw_fd(),
                empty.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::AT_EMPTY_PATH,
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

fn ensure_owned_directory(
    metadata: &std::fs::Metadata,
    expected_user: u32,
    expected_group: u32,
    expected_mode: u32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == expected_user
            && metadata.gid() == expected_group
            && metadata.nlink() > 0
            && metadata.mode() & 0o7777 == expected_mode,
        "managed VMM directory has unsafe type, owner, links or mode"
    );
    Ok(())
}

fn ensure_owned_regular_file(
    metadata: &std::fs::Metadata,
    expected_user: u32,
    expected_group: u32,
    expected_mode: u32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == expected_user
            && metadata.gid() == expected_group
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == expected_mode,
        "VMM socket receipt has unsafe type, owner, links or mode"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StableFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl StableFileIdentity {
    fn same_file_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

fn stable_file_identity(metadata: &std::fs::Metadata) -> StableFileIdentity {
    StableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn fixed_c_string(value: &str) -> CString {
    CString::new(value).expect("fixed VMM socket namespace name contains no NUL")
}

fn ensure_canonical_root(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.is_absolute(),
        "managed VMM socket root is not absolute"
    );
    let mut normal = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => normal += 1,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                anyhow::bail!("managed VMM socket root is not canonical")
            }
        }
    }
    anyhow::ensure!(normal > 0, "managed VMM socket root names filesystem root");
    anyhow::ensure!(
        !path.as_os_str().as_encoded_bytes().contains(&0),
        "managed VMM socket root contains NUL"
    );
    Ok(())
}

fn ensure_socket_path_fits(path: &HostPath) -> anyhow::Result<()> {
    let length = Path::new(path.as_str())
        .as_os_str()
        .as_encoded_bytes()
        .len();
    anyhow::ensure!(
        length < UNIX_SOCKET_PATH_CAPACITY,
        "managed VMM socket path exceeds sockaddr_un.sun_path"
    );
    Ok(())
}

fn host_path(path: PathBuf, label: &str) -> anyhow::Result<HostPath> {
    HostPath::new(path.to_string_lossy().into_owned())
        .with_context(|| format!("{label} is not a canonical HostPath"))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::io::Write as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStrExt as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::{symlink, OpenOptionsExt as _};
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{decode_runtime_checkpoint, RuntimeLaunch};
    #[cfg(target_os = "linux")]
    use cats_api::runtime_reconciliation::{encode_runtime_checkpoint, StableState};

    use super::*;

    fn checkpoint() -> RuntimeCheckpoint {
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

    fn checkpoint_for_root(
        root: &RetainedManagedVmmSocketRoot,
        state_directory: &StateDirectory,
    ) -> RuntimeCheckpoint {
        let mut checkpoint = checkpoint();
        let paths = root
            .planner()
            .paths_for(checkpoint.runtime_incarnation.as_ref().unwrap())
            .unwrap();
        let launch_file_paths = ManagedVmmLaunchFilePaths::for_incarnation(
            state_directory,
            checkpoint.runtime_incarnation.as_ref().unwrap(),
        )
        .unwrap();
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
        *api_socket_path = paths.api_socket_path().clone();
        *vsock_socket_path = paths.vsock_socket_path().clone();
        *memory_file_path = launch_file_paths.memory_file_path().clone();
        *serial_log_path = launch_file_paths.serial_log_path().clone();
        *vmm_log_path = launch_file_paths.vmm_log_path().clone();
        sync_retained_launch(&mut checkpoint);
        checkpoint
    }

    fn creation_nonce() -> RandomId128 {
        RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap()
    }

    #[cfg(target_os = "linux")]
    struct TestStaleReceiptRetirementAuthority;

    #[cfg(target_os = "linux")]
    impl stale_receipt_retirement_sealed::Sealed for TestStaleReceiptRetirementAuthority {}

    #[cfg(target_os = "linux")]
    impl StaleVmmReceiptRetirementAuthority for TestStaleReceiptRetirementAuthority {
        fn assert_receipt_retirement(
            &self,
            _receipt: &VmmSocketOwnershipReceiptV1,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn distinct_test_boot_id() -> NodeBootId {
        let current = current_kernel_node_boot_id().unwrap();
        ["e".repeat(32), "f".repeat(32)]
            .into_iter()
            .map(|value| NodeBootId::new(value).unwrap())
            .find(|value| value != &current)
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn state_path(temporary: &tempfile::TempDir) -> PathBuf {
        temporary.path().join("authority").join("state")
    }

    #[cfg(target_os = "linux")]
    fn receipt_namespace_path(temporary: &tempfile::TempDir) -> PathBuf {
        state_path(temporary).join(VMM_SOCKET_RECEIPT_NAMESPACE)
    }

    #[cfg(target_os = "linux")]
    fn write_foreign(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[cfg(target_os = "linux")]
    fn replace_receipt_contents(
        store: &VmmSocketReceiptStore,
        incarnation: &RandomId128,
        bytes: &[u8],
    ) {
        let name = receipt_file_name(incarnation).unwrap();
        let path = format!(
            "/proc/self/fd/{}/{}",
            store.directory.as_raw_fd(),
            name.to_string_lossy()
        );
        std::fs::remove_file(&path).unwrap();
        write_foreign(Path::new(&path), bytes);
        store.directory.sync_all().unwrap();
    }

    #[cfg(target_os = "linux")]
    fn replace_receipt_namespace(
        temporary: &tempfile::TempDir,
        replacement_target: Option<(&CStr, &[u8])>,
    ) -> (PathBuf, PathBuf) {
        let current = receipt_namespace_path(temporary);
        let old = current.with_file_name("vmm-socket-receipts-old");
        std::fs::rename(&current, &old).unwrap();
        std::fs::create_dir(&current).unwrap();
        std::fs::set_permissions(
            &current,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        write_foreign(&old.join("old.foreign"), b"old-foreign");
        write_foreign(&current.join("new.foreign"), b"new-foreign");
        if let Some((target, bytes)) = replacement_target {
            write_foreign(
                &current.join(std::ffi::OsStr::from_bytes(target.to_bytes())),
                bytes,
            );
        }
        (old, current)
    }

    #[cfg(target_os = "linux")]
    fn replace_state_ancestor(
        temporary: &tempfile::TempDir,
        replacement_target: (&CStr, &[u8]),
    ) -> (PathBuf, PathBuf) {
        let current = temporary.path().join("authority");
        let old = temporary.path().join("authority-old");
        std::fs::rename(&current, &old).unwrap();
        let new_namespace = current.join("state").join(VMM_SOCKET_RECEIPT_NAMESPACE);
        std::fs::create_dir_all(&new_namespace).unwrap();
        std::fs::set_permissions(
            &new_namespace,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let old_namespace = old.join("state").join(VMM_SOCKET_RECEIPT_NAMESPACE);
        write_foreign(&old_namespace.join("old.foreign"), b"old-foreign");
        write_foreign(&new_namespace.join("new.foreign"), b"new-foreign");
        write_foreign(
            &new_namespace.join(std::ffi::OsStr::from_bytes(replacement_target.0.to_bytes())),
            replacement_target.1,
        );
        (old_namespace, new_namespace)
    }

    #[cfg(target_os = "linux")]
    struct TestPhysicalContext {
        deadline: Instant,
    }

    #[cfg(target_os = "linux")]
    impl crate::runtime_spine::RuntimePhysicalReadContext for TestPhysicalContext {
        fn deadline(&self) -> Instant {
            self.deadline
        }

        fn check_active(&self) -> anyhow::Result<()> {
            anyhow::ensure!(Instant::now() < self.deadline, "test deadline expired");
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn scan_context() -> TestPhysicalContext {
        TestPhysicalContext {
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    #[test]
    fn installed_mapping_is_short_canonical_and_incarnation_exact() {
        let checkpoint = checkpoint();
        let incarnation = checkpoint.runtime_incarnation.as_ref().unwrap();
        let paths = ManagedVmmSocketRoot::installed()
            .paths_for(incarnation)
            .unwrap();
        assert_eq!(paths.root().as_str(), INSTALLED_VMM_SOCKET_ROOT);
        assert_eq!(
            paths.public_directory().as_str(),
            "/run/cats/vmm-v1/p-55555555555555555555555555555555"
        );
        assert_eq!(
            paths.api_socket_path().as_str(),
            "/run/cats/vmm-v1/p-55555555555555555555555555555555/api.sock"
        );
        assert_eq!(
            paths.vsock_socket_path().as_str(),
            "/run/cats/vmm-v1/p-55555555555555555555555555555555/vsock.sock"
        );
        assert!(paths.staging_name().starts_with(".s-"));
        assert!(paths.quarantine_name().starts_with(".q-"));
        assert!(paths.api_socket_path().as_str().len() < UNIX_SOCKET_PATH_CAPACITY);
        assert!(paths.vsock_socket_path().as_str().len() < UNIX_SOCKET_PATH_CAPACITY);
    }

    #[test]
    fn checkpoint_must_use_the_exact_managed_mapping() {
        let root = ManagedVmmSocketRoot::installed();
        let mut checkpoint = checkpoint();
        assert!(root.paths_from_checkpoint(&checkpoint).is_err());
        let paths = root
            .paths_for(checkpoint.runtime_incarnation.as_ref().unwrap())
            .unwrap();
        let ReconcileStep::StartRuntime {
            api_socket_path,
            vsock_socket_path,
            ..
        } = &mut checkpoint.step
        else {
            unreachable!()
        };
        *api_socket_path = paths.api_socket_path().clone();
        *vsock_socket_path = paths.vsock_socket_path().clone();
        sync_retained_launch(&mut checkpoint);
        assert_eq!(root.paths_from_checkpoint(&checkpoint).unwrap(), paths);
    }

    #[test]
    fn custom_root_rejects_aliases_and_sockaddr_overflow() {
        for path in ["relative", "/", "/run/cats/../vmm"] {
            if let Some(path) = HostPath::new(path) {
                assert!(ManagedVmmSocketRoot::from_canonical_path(path).is_err());
            }
        }

        let long = format!("/run/{}", "x".repeat(90));
        let root = ManagedVmmSocketRoot::from_canonical_path(HostPath::new(long).unwrap()).unwrap();
        assert!(root
            .paths_for(&RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap())
            .is_err());
    }

    #[test]
    fn production_open_boundaries_never_create_missing_roots() {
        let temporary = tempfile::tempdir().unwrap();
        let state_path = temporary.path().join("state");
        std::fs::create_dir(&state_path).unwrap();
        std::fs::set_permissions(
            &state_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let state = StateDirectory::unanchored(state_path.clone());
        assert!(VmmSocketReceiptStore::open_existing(state).is_err());
        assert!(!state_path.join(VMM_SOCKET_RECEIPT_NAMESPACE).exists());

        let missing = temporary.path().join("missing-vmm-root");
        let planner = ManagedVmmSocketRoot::from_canonical_path(
            HostPath::new(missing.to_string_lossy().into_owned()).unwrap(),
        )
        .unwrap();
        let owner = std::fs::metadata(temporary.path()).unwrap();
        assert!(RetainedManagedVmmSocketRoot::open(planner, owner.uid(), owner.gid()).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn receipt_namespace_must_be_an_existing_exact_0700_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let state_path = temporary.path().join("state");
        let receipts = state_path.join(VMM_SOCKET_RECEIPT_NAMESPACE);
        std::fs::create_dir_all(&receipts).unwrap();
        std::fs::set_permissions(
            &state_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            &receipts,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        assert!(
            VmmSocketReceiptStore::open_existing(StateDirectory::unanchored(state_path)).is_err()
        );
        assert!(receipts.is_dir());
    }

    #[cfg(target_os = "linux")]
    fn receipt_fixture() -> (
        tempfile::TempDir,
        RetainedManagedVmmSocketRoot,
        RuntimeCheckpoint,
        VmmSocketReceiptStore,
        VmmSocketOwnershipReceiptV1,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let managed_root =
            RetainedManagedVmmSocketRoot::provision_for_test(&temporary.path().join("vmm"))
                .unwrap();
        let state_path = state_path(&temporary);
        std::fs::create_dir_all(&state_path).unwrap();
        std::fs::set_permissions(
            &state_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let state_directory = StateDirectory::unanchored(state_path);
        let checkpoint = checkpoint_for_root(&managed_root, &state_directory);
        let store = VmmSocketReceiptStore::provision_for_test(state_directory).unwrap();
        let receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
            &checkpoint,
            &store.state_directory,
            &managed_root,
            current_kernel_node_boot_id().unwrap(),
            creation_nonce(),
        )
        .unwrap();
        (temporary, managed_root, checkpoint, store, receipt)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ownership_receipt_is_canonical_checkpoint_exact_and_no_replace() {
        let (_temporary, managed_root, checkpoint, store, receipt) = receipt_fixture();
        assert!(VmmSocketOwnershipReceiptV1::from_checkpoint(
            &checkpoint,
            &store.state_directory,
            &managed_root,
            distinct_test_boot_id(),
            creation_nonce(),
        )
        .is_err());
        assert_eq!(
            store.publish(&receipt).unwrap(),
            VmmSocketReceiptPublication::Published
        );
        assert_eq!(
            store.load(receipt.runtime_incarnation()).unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            store.publish(&receipt).unwrap(),
            VmmSocketReceiptPublication::ExactReplay
        );
        receipt
            .validate_against(&checkpoint, &store.state_directory, &managed_root)
            .unwrap();

        let mut changed_checkpoint = checkpoint;
        let ReconcileStep::StartRuntime { vmm_log_path, .. } = &mut changed_checkpoint.step else {
            unreachable!()
        };
        *vmm_log_path = HostPath::new("/var/log/cats/foreign.log").unwrap();
        assert!(receipt
            .validate_against(&changed_checkpoint, &store.state_directory, &managed_root,)
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_receipt_accepts_a_higher_revision_running_tail_but_not_launch_drift() {
        let (_temporary, managed_root, original, store, receipt) = receipt_fixture();
        assert_eq!(
            store.publish(&receipt).unwrap(),
            VmmSocketReceiptPublication::Published
        );

        let mut current = original.clone();
        current.desired_revision = Revision::new(original.desired_revision.get() + 1).unwrap();
        current.spec_digest = Sha256Digest::from_bytes([0x91; 32]);
        current.stable_state = Some(StableState::Running);
        current.step = ReconcileStep::Stable {
            state: StableState::Running,
        };
        encode_runtime_checkpoint(&current).unwrap();

        receipt
            .validate_original_launch_checkpoint(&original)
            .unwrap();
        receipt
            .validate_against(&current, store.state_directory(), &managed_root)
            .unwrap();
        assert_eq!(
            scan_managed_vmm_socket_root(&managed_root, &store, &[&current], &scan_context(),)
                .unwrap(),
            ManagedVmmSocketRootScan::Accounted
        );

        let RuntimeLaunch::Present(identity) = &mut current.runtime_launch else {
            unreachable!()
        };
        identity.process_identity_token =
            RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        assert!(receipt
            .validate_against(&current, store.state_directory(), &managed_root)
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn present_receipt_load_rejects_a_final_namespace_swap_without_mutation() {
        let (temporary, _managed_root, _checkpoint, store, receipt) = receipt_fixture();
        assert_eq!(
            store.publish(&receipt).unwrap(),
            VmmSocketReceiptPublication::Published
        );
        let name = receipt_file_name(receipt.runtime_incarnation()).unwrap();
        let original = std::fs::read(
            receipt_namespace_path(&temporary).join(std::ffi::OsStr::from_bytes(name.to_bytes())),
        )
        .unwrap();
        let result = store.load_inner(receipt.runtime_incarnation(), || {
            replace_receipt_namespace(&temporary, Some((&name, b"new-foreign-receipt")));
            Ok(())
        });
        assert!(result.is_err());
        let old = receipt_namespace_path(&temporary).with_file_name("vmm-socket-receipts-old");
        let new = receipt_namespace_path(&temporary);
        assert_eq!(
            std::fs::read(old.join(std::ffi::OsStr::from_bytes(name.to_bytes()))).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read(old.join("old.foreign")).unwrap(),
            b"old-foreign"
        );
        assert_eq!(
            std::fs::read(new.join("new.foreign")).unwrap(),
            b"new-foreign"
        );
        assert_eq!(
            std::fs::read(new.join(std::ffi::OsStr::from_bytes(name.to_bytes()))).unwrap(),
            b"new-foreign-receipt"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn absent_receipt_load_rejects_a_final_ancestor_swap_without_mutation() {
        let (temporary, _managed_root, _checkpoint, store, _receipt) = receipt_fixture();
        let missing = RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        let name = receipt_file_name(&missing).unwrap();
        let result = store.load_inner(&missing, || {
            replace_state_ancestor(&temporary, (&name, b"new-foreign-receipt"));
            Ok(())
        });
        assert!(result.is_err());
        let old = temporary
            .path()
            .join("authority-old")
            .join("state")
            .join(VMM_SOCKET_RECEIPT_NAMESPACE);
        let new = receipt_namespace_path(&temporary);
        assert!(!old
            .join(std::ffi::OsStr::from_bytes(name.to_bytes()))
            .exists());
        assert_eq!(
            std::fs::read(old.join("old.foreign")).unwrap(),
            b"old-foreign"
        );
        assert_eq!(
            std::fs::read(new.join("new.foreign")).unwrap(),
            b"new-foreign"
        );
        assert_eq!(
            std::fs::read(new.join(std::ffi::OsStr::from_bytes(name.to_bytes()))).unwrap(),
            b"new-foreign-receipt"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_replay_rejects_a_final_namespace_swap_without_mutation() {
        let (temporary, _managed_root, _checkpoint, store, receipt) = receipt_fixture();
        assert_eq!(
            store.publish(&receipt).unwrap(),
            VmmSocketReceiptPublication::Published
        );
        let name = receipt_file_name(receipt.runtime_incarnation()).unwrap();
        let original = std::fs::read(
            receipt_namespace_path(&temporary).join(std::ffi::OsStr::from_bytes(name.to_bytes())),
        )
        .unwrap();
        let result = store.publish_inner(&receipt, |point| {
            assert_eq!(point, ReceiptPublicationPoint::DirectorySynced);
            replace_receipt_namespace(&temporary, Some((&name, b"new-foreign-receipt")));
            Ok(())
        });
        assert!(result.is_err());
        let old = receipt_namespace_path(&temporary).with_file_name("vmm-socket-receipts-old");
        let new = receipt_namespace_path(&temporary);
        assert_eq!(
            std::fs::read(old.join(std::ffi::OsStr::from_bytes(name.to_bytes()))).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read(old.join("old.foreign")).unwrap(),
            b"old-foreign"
        );
        assert_eq!(
            std::fs::read(new.join("new.foreign")).unwrap(),
            b"new-foreign"
        );
        assert_eq!(
            std::fs::read(new.join(std::ffi::OsStr::from_bytes(name.to_bytes()))).unwrap(),
            b"new-foreign-receipt"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_receipt_publication_crash_window_replays_without_partial_name() {
        for crash in [
            ReceiptPublicationPoint::AnonymousCreated,
            ReceiptPublicationPoint::ContentSynced,
            ReceiptPublicationPoint::Published,
            ReceiptPublicationPoint::DirectorySynced,
        ] {
            let (_temporary, _managed_root, _checkpoint, store, receipt) = receipt_fixture();
            let result = store.publish_inner(&receipt, |point| {
                anyhow::ensure!(point != crash, "injected receipt publication crash");
                Ok(())
            });
            assert!(result.is_err());
            if matches!(
                crash,
                ReceiptPublicationPoint::AnonymousCreated | ReceiptPublicationPoint::ContentSynced
            ) {
                assert_eq!(store.load(receipt.runtime_incarnation()).unwrap(), None);
            }
            assert!(matches!(
                store.publish(&receipt).unwrap(),
                VmmSocketReceiptPublication::Published | VmmSocketReceiptPublication::ExactReplay
            ));
            assert_eq!(
                store.load(receipt.runtime_incarnation()).unwrap(),
                Some(receipt)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_receipt_and_symlink_are_preserved_without_overwrite_or_unlink() {
        for symlink_target in [false, true] {
            let (temporary, _managed_root, _checkpoint, store, receipt) = receipt_fixture();
            let name = format!("vmm-{}.receipt.json", receipt.runtime_incarnation());
            let path = temporary
                .path()
                .join("authority")
                .join("state")
                .join(VMM_SOCKET_RECEIPT_NAMESPACE)
                .join(name);
            if symlink_target {
                let foreign = temporary.path().join("foreign");
                std::fs::write(&foreign, b"foreign").unwrap();
                symlink(&foreign, &path).unwrap();
                assert!(store.publish(&receipt).is_err());
                assert_eq!(std::fs::read_link(&path).unwrap(), foreign);
            } else {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                file.write_all(b"foreign").unwrap();
                file.sync_all().unwrap();
                assert!(store.publish(&receipt).is_err());
                assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_receipt_retirement_preserves_replacements_at_every_cleanup_boundary() {
        for replacement_point in [
            StaleReceiptRetirementPoint::BeforeQuarantine,
            StaleReceiptRetirementPoint::AfterQuarantine,
            StaleReceiptRetirementPoint::BeforeRemoval,
        ] {
            let (temporary, root, checkpoint, store, mut receipt) = receipt_fixture();
            receipt.set_node_boot_id_for_test(distinct_test_boot_id());
            store.publish(&receipt).unwrap();
            let candidate = match store
                .retain_one_stale_boot_receipt(&root, &[&checkpoint], &scan_context())
                .unwrap()
            {
                StaleVmmSocketReceiptScan::Candidate(candidate) => *candidate,
                StaleVmmSocketReceiptScan::Settled => panic!("stale receipt was not selected"),
            };
            let incarnation = receipt.runtime_incarnation().as_str();
            let namespace = receipt_namespace_path(&temporary);
            let replacement = if replacement_point == StaleReceiptRetirementPoint::BeforeQuarantine
            {
                namespace.join(format!("vmm-{incarnation}.receipt.json"))
            } else {
                namespace.join(format!("q-vmm-{incarnation}.receipt.json"))
            };
            let retained = namespace.join(format!("retained-{incarnation}.receipt.json"));
            let mut replaced = false;
            let result =
                candidate.retire_inner(&store, &TestStaleReceiptRetirementAuthority, |point| {
                    if point == replacement_point && !replaced {
                        std::fs::rename(&replacement, &retained)?;
                        write_foreign(&replacement, b"foreign-replacement");
                        store.directory.sync_all()?;
                        replaced = true;
                    }
                    Ok(())
                });
            assert!(result.is_err());
            assert!(replaced);
            assert_eq!(std::fs::read(&replacement).unwrap(), b"foreign-replacement");
            assert_eq!(
                std::fs::read(&retained).unwrap(),
                receipt.encoded_bytes().unwrap()
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn expect_prepared(
        preparation: ManagedVmmSocketPreparation<'_>,
    ) -> PreparedManagedVmmSocketAttempt<'_> {
        match preparation {
            ManagedVmmSocketPreparation::Prepared(prepared) => *prepared,
            ManagedVmmSocketPreparation::ExistingLive => panic!("expected a fresh API listener"),
        }
    }

    #[cfg(target_os = "linux")]
    fn inject_namespace_crash(
        root: &RetainedManagedVmmSocketRoot,
        checkpoint: &RuntimeCheckpoint,
        store: &VmmSocketReceiptStore,
        target: NamespacePreparationPoint,
    ) {
        let mut reached = false;
        let result = root.prepare_existing_receipt_inner(checkpoint, store, |point| {
            if point == target {
                reached = true;
                anyhow::bail!("injected VMM socket namespace crash")
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(reached, "injected crash point was not reached");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_prepare_crash_window_replays_to_one_exact_listener() {
        for crash in [
            NamespacePreparationPoint::StagingCreated,
            NamespacePreparationPoint::OwnerMarkerSynced,
            NamespacePreparationPoint::PublicPublished,
            NamespacePreparationPoint::ApiBound,
            NamespacePreparationPoint::DirectorySynced,
        ] {
            let (_temporary, root, checkpoint, store, receipt) = receipt_fixture();
            store.publish(&receipt).unwrap();
            inject_namespace_crash(&root, &checkpoint, &store, crash);
            let prepared =
                expect_prepared(root.prepare_existing_receipt(&checkpoint, &store).unwrap());
            prepared.assert_current().unwrap();
        }

        for crash in [
            NamespacePreparationPoint::PublicQuarantined,
            NamespacePreparationPoint::QuarantineRemoved,
        ] {
            let (_temporary, root, checkpoint, store, receipt) = receipt_fixture();
            store.publish(&receipt).unwrap();
            drop(expect_prepared(
                root.prepare_existing_receipt(&checkpoint, &store).unwrap(),
            ));
            inject_namespace_crash(&root, &checkpoint, &store, crash);
            let prepared =
                expect_prepared(root.prepare_existing_receipt(&checkpoint, &store).unwrap());
            prepared.assert_current().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_api_holder_is_preserved_and_blocks_a_second_prepare() {
        let (_temporary, root, checkpoint, store, receipt) = receipt_fixture();
        store.publish(&receipt).unwrap();
        let prepared = expect_prepared(root.prepare_existing_receipt(&checkpoint, &store).unwrap());
        let before = std::fs::symlink_metadata(receipt.api_socket_path.as_str())
            .unwrap()
            .ino();

        assert!(matches!(
            root.prepare_existing_receipt(&checkpoint, &store).unwrap(),
            ManagedVmmSocketPreparation::ExistingLive
        ));
        assert_eq!(
            std::fs::symlink_metadata(receipt.api_socket_path.as_str())
                .unwrap()
                .ino(),
            before
        );
        prepared.assert_current().unwrap();

        drop(prepared);
        expect_prepared(root.prepare_existing_receipt(&checkpoint, &store).unwrap())
            .assert_current()
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_attempt_entries_and_symlinks_are_preserved() {
        for selector in 0..3 {
            let (temporary, root, checkpoint, store, receipt) = receipt_fixture();
            store.publish(&receipt).unwrap();
            let paths = root.planner().paths_from_checkpoint(&checkpoint).unwrap();
            let attempt = match selector {
                0 => paths.public_directory(),
                1 => paths.staging_directory(),
                _ => paths.quarantine_directory(),
            };
            std::fs::create_dir(attempt.as_str()).unwrap();
            std::fs::set_permissions(
                attempt.as_str(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let foreign = Path::new(attempt.as_str()).join("foreign");
            std::fs::write(&foreign, b"foreign-owned-by-someone-else").unwrap();

            assert!(root.prepare_existing_receipt(&checkpoint, &store).is_err());
            assert_eq!(
                std::fs::read(&foreign).unwrap(),
                b"foreign-owned-by-someone-else"
            );
            drop(temporary);
        }

        for selector in 0..3 {
            let (temporary, root, checkpoint, store, receipt) = receipt_fixture();
            store.publish(&receipt).unwrap();
            let paths = root.planner().paths_from_checkpoint(&checkpoint).unwrap();
            let attempt = match selector {
                0 => paths.public_directory(),
                1 => paths.staging_directory(),
                _ => paths.quarantine_directory(),
            };
            let target = temporary.path().join("foreign-directory");
            std::fs::create_dir(&target).unwrap();
            symlink(&target, attempt.as_str()).unwrap();

            assert!(root.prepare_existing_receipt(&checkpoint, &store).is_err());
            assert_eq!(std::fs::read_link(attempt.as_str()).unwrap(), target);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_prepared_attempt_rejects_public_directory_aba() {
        let (temporary, root, checkpoint, store, receipt) = receipt_fixture();
        store.publish(&receipt).unwrap();
        let prepared = expect_prepared(root.prepare_existing_receipt(&checkpoint, &store).unwrap());
        let paths = root.planner().paths_from_checkpoint(&checkpoint).unwrap();
        let displaced = temporary.path().join("vmm").join("displaced-public");
        std::fs::rename(paths.public_directory().as_str(), &displaced).unwrap();
        std::fs::create_dir(paths.public_directory().as_str()).unwrap();
        std::fs::set_permissions(
            paths.public_directory().as_str(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();

        assert!(prepared.assert_current().is_err());
        assert!(displaced.join(VMM_API_SOCKET_BASENAME).exists());
        assert!(Path::new(paths.public_directory().as_str()).is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn multiple_attempt_names_are_preserved_as_rename_recreate_aba() {
        for second_name in ["staging", "quarantine"] {
            let (_temporary, root, checkpoint, store, receipt) = receipt_fixture();
            store.publish(&receipt).unwrap();
            drop(expect_prepared(
                root.prepare_existing_receipt(&checkpoint, &store).unwrap(),
            ));
            let paths = root.planner().paths_from_checkpoint(&checkpoint).unwrap();
            let second_path = if second_name == "staging" {
                paths.staging_directory()
            } else {
                paths.quarantine_directory()
            };
            std::fs::create_dir(second_path.as_str()).unwrap();
            std::fs::set_permissions(
                second_path.as_str(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();

            assert!(root.prepare_existing_receipt(&checkpoint, &store).is_err());
            assert!(Path::new(paths.public_directory().as_str()).is_dir());
            assert!(Path::new(second_path.as_str()).is_dir());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_managed_root_scan_accounts_only_exact_receipted_attempts() {
        let (temporary, root, checkpoint, store, receipt) = receipt_fixture();
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[&checkpoint], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Accounted
        );
        store.publish(&receipt).unwrap();
        // The durable WAL may legitimately be the only published resource
        // after a crash. It must be enumerated and bound to this exact current
        // StartRuntime even while the boot-local root remains empty.
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[&checkpoint], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Accounted
        );
        drop(expect_prepared(
            root.prepare_existing_receipt(&checkpoint, &store).unwrap(),
        ));
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[&checkpoint], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Accounted
        );

        let foreign = temporary.path().join("vmm").join("foreign-entry");
        std::fs::write(&foreign, b"foreign").unwrap();
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[&checkpoint], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Residue
        );
        assert_eq!(std::fs::read(foreign).unwrap(), b"foreign");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receipt_namespace_rejects_foreign_corrupt_unassigned_and_aba_entries() {
        let (temporary, root, checkpoint, store, _receipt) = receipt_fixture();
        let namespace = receipt_namespace_path(&temporary);
        write_foreign(&namespace.join("foreign.receipt.json"), b"foreign");
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[&checkpoint], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Residue
        );
        assert_eq!(
            std::fs::read(namespace.join("foreign.receipt.json")).unwrap(),
            b"foreign"
        );

        let (temporary, root, checkpoint, store, receipt) = receipt_fixture();
        let exact_name = receipt_file_name(receipt.runtime_incarnation()).unwrap();
        let exact_path = receipt_namespace_path(&temporary)
            .join(std::ffi::OsStr::from_bytes(exact_name.to_bytes()));
        write_foreign(&exact_path, b"{\"version\":1}");
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[&checkpoint], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Residue
        );
        assert_eq!(std::fs::read(exact_path).unwrap(), b"{\"version\":1}");

        let (_temporary, root, _checkpoint, store, receipt) = receipt_fixture();
        store.publish(&receipt).unwrap();
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Residue
        );

        let (temporary, root, checkpoint, store, receipt) = receipt_fixture();
        store.publish(&receipt).unwrap();
        let name = receipt_file_name(receipt.runtime_incarnation()).unwrap();
        let original = std::fs::read(
            receipt_namespace_path(&temporary).join(std::ffi::OsStr::from_bytes(name.to_bytes())),
        )
        .unwrap();
        let (old, new) = replace_receipt_namespace(&temporary, Some((&name, &original)));
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[&checkpoint], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Residue
        );
        assert_eq!(
            std::fs::read(old.join(std::ffi::OsStr::from_bytes(name.to_bytes()))).unwrap(),
            original
        );
        assert!(new
            .join(std::ffi::OsStr::from_bytes(name.to_bytes()))
            .is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attempt_marker_uses_only_the_first_same_fd_receipt_snapshot() {
        let (_temporary, root, checkpoint, store, receipt_a) = receipt_fixture();
        let mut receipt_b = receipt_a.clone();
        receipt_b.creation_nonce = RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        receipt_b
            .validate_against(&checkpoint, store.state_directory(), &root)
            .unwrap();
        store.publish(&receipt_b).unwrap();
        drop(expect_prepared(
            root.prepare_existing_receipt(&checkpoint, &store).unwrap(),
        ));
        let bytes_a = receipt_a.encoded_bytes().unwrap();
        let bytes_b = receipt_b.encoded_bytes().unwrap();
        replace_receipt_contents(&store, receipt_a.runtime_incarnation(), &bytes_a);

        let mut restored = false;
        let result = scan_managed_vmm_socket_root_linux_inner(
            &root,
            &store,
            &[&checkpoint],
            &scan_context(),
            |point| {
                match point {
                    ReceiptScanPoint::FirstSnapshotCaptured => {
                        replace_receipt_contents(&store, receipt_a.runtime_incarnation(), &bytes_b)
                    }
                    ReceiptScanPoint::AttemptsScanned => {
                        replace_receipt_contents(&store, receipt_a.runtime_incarnation(), &bytes_a);
                        restored = true;
                    }
                }
                Ok(())
            },
        )
        .unwrap();
        if !restored {
            replace_receipt_contents(&store, receipt_a.runtime_incarnation(), &bytes_a);
        }
        assert_eq!(result, ManagedVmmSocketRootScan::Residue);
        assert_eq!(
            store.load(receipt_a.runtime_incarnation()).unwrap(),
            Some(receipt_a)
        );
        assert!(Path::new(receipt_b.api_socket_path.as_str()).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_root_scan_rejects_aba_and_entry_bound_without_cleanup() {
        let (_temporary, root, checkpoint, store, receipt) = receipt_fixture();
        store.publish(&receipt).unwrap();
        drop(expect_prepared(
            root.prepare_existing_receipt(&checkpoint, &store).unwrap(),
        ));
        let paths = root.planner().paths_from_checkpoint(&checkpoint).unwrap();
        std::fs::create_dir(paths.staging_directory().as_str()).unwrap();
        std::fs::set_permissions(
            paths.staging_directory().as_str(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[&checkpoint], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Residue
        );
        assert!(Path::new(paths.public_directory().as_str()).is_dir());
        assert!(Path::new(paths.staging_directory().as_str()).is_dir());

        let (_temporary, root, _checkpoint, store, _receipt) = receipt_fixture();
        let root_path = Path::new(root.planner().path().as_str());
        for index in 0..=MANAGED_VMM_SOCKET_ROOT_ENTRY_LIMIT {
            std::fs::write(root_path.join(format!("foreign-{index}")), b"x").unwrap();
        }
        assert_eq!(
            scan_managed_vmm_socket_root(&root, &store, &[], &scan_context()).unwrap(),
            ManagedVmmSocketRootScan::Residue
        );
        assert_eq!(std::fs::read(root_path.join("foreign-0")).unwrap(), b"x");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receipt_decoder_rejects_extra_malformed_and_noncanonical_input() {
        let (_temporary, _managed_root, _checkpoint, _store, receipt) = receipt_fixture();
        let bytes = encode_receipt(&receipt).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["extra"] = serde_json::Value::Bool(true);
        assert!(decode_receipt(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(decode_receipt(b"{}").is_err());
        let mut spaced = bytes;
        spaced.push(b'\n');
        assert!(decode_receipt(&spaced).is_err());
    }
}
