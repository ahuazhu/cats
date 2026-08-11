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
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, Epoch, HostPath, Id, RandomId128, ReconcileStep, Revision,
    RuntimeCheckpoint, Sha256Digest,
};
use serde::{Deserialize, Serialize};

use crate::state_directory::StateDirectory;

use super::vmm_runtime_paths::ManagedVmmLaunchFilePaths;

/// Installation-owned short socket root.  It is deliberately outside the
/// durable Node state directory: AF_UNIX pathnames have a small kernel ABI
/// bound and live VMM sockets are boot-local.  The durable ownership WAL lives
/// under the identity-selected Node state directory instead.
pub(crate) const INSTALLED_VMM_SOCKET_ROOT: &str = "/run/cats/vmm-v1";

pub(crate) const VMM_API_SOCKET_BASENAME: &str = "api.sock";
pub(crate) const VMM_VSOCK_SOCKET_BASENAME: &str = "vsock.sock";
pub(crate) const VMM_SOCKET_RECEIPT_NAMESPACE: &str = "vmm-socket-receipts";

const VMM_SOCKET_RECEIPT_VERSION: u32 = 1;
const VMM_SOCKET_RECEIPT_MAX_BYTES: usize = 16 * 1024;

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
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            api_socket_path,
            vsock_socket_path,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("managed VMM socket paths require StartRuntime")
        };
        anyhow::ensure!(
            checkpoint.runtime_incarnation.as_ref() == Some(runtime_incarnation),
            "StartRuntime socket paths have a non-exact top-level incarnation"
        );
        let paths = self.paths_for(runtime_incarnation)?;
        anyhow::ensure!(
            api_socket_path == &paths.api_socket_path
                && vsock_socket_path == &paths.vsock_socket_path,
            "StartRuntime socket paths are outside the managed VMM namespace"
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
    node_id: Id,
    cat_id: Id,
    desired_revision: Revision,
    spec_digest: Sha256Digest,
    placement_epoch: Epoch,
    checkpoint_content_digest: Sha256Digest,
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
        creation_nonce: RandomId128,
    ) -> anyhow::Result<Self> {
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            scope_id,
            launcher_executable,
            boot,
            process_identity_token,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("VMM socket ownership receipt requires StartRuntime")
        };
        let paths = managed_root
            .planner
            .paths_from_checkpoint(checkpoint)
            .context("validate managed StartRuntime socket paths")?;
        let launch_file_paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(state_directory, checkpoint)
                .context("validate managed StartRuntime launch file paths")?;
        anyhow::ensure!(
            &creation_nonce != runtime_incarnation && &creation_nonce != process_identity_token,
            "VMM socket creation nonce aliases another launch identity"
        );
        let receipt = Self {
            version: VMM_SOCKET_RECEIPT_VERSION,
            node_id: checkpoint.node_id.clone(),
            cat_id: checkpoint.cat_id.clone(),
            desired_revision: checkpoint.desired_revision,
            spec_digest: checkpoint.spec_digest.clone(),
            placement_epoch: checkpoint.placement_epoch,
            checkpoint_content_digest: checkpoint_content_digest(checkpoint)
                .context("digest StartRuntime checkpoint for socket ownership")?,
            runtime_incarnation: runtime_incarnation.clone(),
            scope_id: scope_id.clone(),
            process_identity_token: process_identity_token.clone(),
            creation_nonce,
            launcher_executable_path: launcher_executable.path.clone(),
            vmm_executable_path: boot.vmm_executable.path.clone(),
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
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            scope_id,
            launcher_executable,
            boot,
            process_identity_token,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("VMM socket ownership receipt requires StartRuntime")
        };
        let paths = managed_root.planner.paths_from_checkpoint(checkpoint)?;
        let launch_file_paths =
            ManagedVmmLaunchFilePaths::paths_from_checkpoint(state_directory, checkpoint)?;
        anyhow::ensure!(
            self.node_id == checkpoint.node_id
                && self.cat_id == checkpoint.cat_id
                && self.desired_revision == checkpoint.desired_revision
                && self.spec_digest == checkpoint.spec_digest
                && self.placement_epoch == checkpoint.placement_epoch
                && self.checkpoint_content_digest
                    == checkpoint_content_digest(checkpoint)
                        .context("re-digest StartRuntime checkpoint")?
                && &self.runtime_incarnation == runtime_incarnation
                && &self.scope_id == scope_id
                && &self.process_identity_token == process_identity_token
                && &self.creation_nonce != runtime_incarnation
                && &self.creation_nonce != process_identity_token
                && self.launcher_executable_path == launcher_executable.path
                && self.vmm_executable_path == boot.vmm_executable.path
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
    fn provision_for_test(path: &Path) -> anyhow::Result<Self> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmmSocketReceiptPublication {
    Published,
    ExactReplay,
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

    pub(crate) fn load(
        &self,
        incarnation: &RandomId128,
    ) -> anyhow::Result<Option<VmmSocketOwnershipReceiptV1>> {
        self.load_inner(incarnation, || Ok(()))
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
    fn provision_for_test(state_directory: StateDirectory) -> anyhow::Result<Self> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptPublicationPoint {
    AnonymousCreated,
    ContentSynced,
    Published,
    DirectorySynced,
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

fn read_optional_receipt(directory: &File, name: &CStr) -> anyhow::Result<Option<Vec<u8>>> {
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
    Ok(Some(bytes))
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

fn stable_file_identity(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
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

    use cats_api::runtime_reconciliation::decode_runtime_checkpoint;

    use super::*;

    fn checkpoint() -> RuntimeCheckpoint {
        decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap()
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
        checkpoint
    }

    fn creation_nonce() -> RandomId128 {
        RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap()
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
            creation_nonce(),
        )
        .unwrap();
        (temporary, managed_root, checkpoint, store, receipt)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ownership_receipt_is_canonical_checkpoint_exact_and_no_replace() {
        let (_temporary, managed_root, checkpoint, store, receipt) = receipt_fixture();
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
