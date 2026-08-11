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
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result};
#[cfg(target_os = "linux")]
use cats_api::runtime_reconciliation::encode_runtime_checkpoint;
use cats_api::runtime_reconciliation::{HostPath, RandomId128, RuntimeCheckpoint};

use crate::state_directory::StateDirectory;

use super::vmm_launch_artifacts::VmmLaunchArtifactDescriptors;

const CHECKPOINT_FD: i32 = 64;
const VMM_FD: i32 = 65;
const KERNEL_FD: i32 = 66;
const INITRAMFS_FD: i32 = 67;
const MEMORY_FD: i32 = 68;
const SERIAL_LOG_FD: i32 = 69;
const VMM_LOG_FD: i32 = 70;
const VMM_LAUNCH_FILE_NAMESPACE: &str = "vmm-launch-v1";
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

    fn start_runtime_checkpoint() -> RuntimeCheckpoint {
        decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap()
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
