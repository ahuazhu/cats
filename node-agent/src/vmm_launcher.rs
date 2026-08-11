//! Closed process boundary used to exec one checkpointed Cloud Hypervisor.
//!
//! The node agent never serializes a second launch request for this helper.
//! A transient service passes the already-open current Runtime checkpoint and
//! installed VMM/boot artifacts as named file descriptors.  This process
//! decodes that exact checkpoint, validates every descriptor, creates the
//! attempt-owned RAM/log files with no-replace semantics, clears its inherited
//! environment and then replaces itself with Cloud Hypervisor.

use std::ffi::OsString;
use std::path::Path;

use anyhow::Result;
use cats_api::runtime_reconciliation::{
    PrepareDeviceFrontend, ReconcileStep, RuntimeCheckpoint, RuntimeLaunchArtifact,
};

use crate::ch::{file_disk_arg_with_serial, vhost_user_disk_arg_with_serial};

pub const VMM_LAUNCHER_CONTRACT_ARGUMENT: &str = "--contract-version=1";
pub const VMM_PROCESS_TOKEN_ENVIRONMENT: &str = "CATS_VMM_PROCESS_IDENTITY_TOKEN";
pub const RUNTIME_INCARNATION_ENVIRONMENT: &str = "CATS_RUNTIME_INCARNATION";

/// Provider-private Cloud Hypervisor API listener descriptor.  It is outside
/// systemd's activation range and the frozen artifact/RAM/log descriptor set.
/// The VMM inspector treats `/proc/<MainPID>/fd/71` as part of exact process
/// identity; this number is not a Runtime wire field.
pub const VMM_API_LISTENER_FD: i32 = 71;

const MIB: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const CHECKPOINT_FD_NAME: &str = "cats-checkpoint-v1";
#[cfg(target_os = "linux")]
const VMM_FD_NAME: &str = "cats-vmm-v1";
#[cfg(target_os = "linux")]
const KERNEL_FD_NAME: &str = "cats-kernel-v1";
#[cfg(target_os = "linux")]
const INITRAMFS_FD_NAME: &str = "cats-initramfs-v1";

// These are deliberately outside systemd's activation range.  They are part
// of the provider-private V1 launch/inspection contract, not wire fields.
#[cfg(target_os = "linux")]
const CHECKPOINT_FD: i32 = 64;
#[cfg(target_os = "linux")]
const VMM_FD: i32 = 65;
const KERNEL_FD: i32 = 66;
const INITRAMFS_FD: i32 = 67;
const MEMORY_FD: i32 = 68;
const SERIAL_LOG_FD: i32 = 69;
#[cfg(target_os = "linux")]
const VMM_LOG_FD: i32 = 70;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmLauncherPlan {
    checkpoint: RuntimeCheckpoint,
    cloud_hypervisor_arguments: Vec<OsString>,
}

impl VmmLauncherPlan {
    pub fn from_checkpoint(checkpoint: RuntimeCheckpoint) -> Result<Self> {
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            boot,
            process_identity_token,
            vcpus,
            memory_bytes,
            api_socket_path: _,
            vsock_socket_path,
            guest_cid,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            network,
            devices,
            ..
        } = &checkpoint.step
        else {
            anyhow::bail!("VMM launcher checkpoint is not StartRuntime")
        };
        anyhow::ensure!(
            checkpoint.runtime_incarnation.as_ref() == Some(runtime_incarnation),
            "StartRuntime top-level incarnation is not exact"
        );
        anyhow::ensure!(
            *vcpus > 0,
            "StartRuntime VMM launch requires at least one vCPU"
        );
        anyhow::ensure!(
            *memory_bytes >= 128 * MIB && *memory_bytes % MIB == 0,
            "StartRuntime memory must be at least 128 MiB and MiB-aligned"
        );
        anyhow::ensure!(
            (3..=u32::MAX - 1).contains(guest_cid),
            "StartRuntime Guest CID is outside the allocatable range"
        );
        anyhow::ensure!(
            !vsock_socket_path.as_str().contains(','),
            "vsock socket path contains a Cloud Hypervisor separator"
        );
        let launch_file_paths = [
            Path::new(memory_file_path.as_str()),
            Path::new(serial_log_path.as_str()),
            Path::new(vmm_log_path.as_str()),
        ];
        anyhow::ensure!(
            launch_file_parents_are_equal_or_disjoint(&launch_file_paths),
            "VMM launch file parents are nested"
        );

        let mut arguments = vec![
            OsString::from("--api-socket"),
            OsString::from(format!("fd={VMM_API_LISTENER_FD}")),
            OsString::from("--kernel"),
            fixed_fd_path(KERNEL_FD),
        ];
        if boot.initramfs.is_some() {
            arguments.push(OsString::from("--initramfs"));
            arguments.push(fixed_fd_path(INITRAMFS_FD));
        }
        arguments.extend([
            OsString::from("--cmdline"),
            OsString::from(boot.kernel_cmdline.as_str()),
            OsString::from("--cpus"),
            OsString::from(format!("boot={vcpus}")),
            OsString::from("--memory"),
            OsString::from("size=0"),
            OsString::from("--memory-zone"),
            OsString::from(format!(
                "id=cat-ram,size={}M,file={},shared=on",
                memory_bytes / MIB,
                fixed_fd_path(MEMORY_FD).to_string_lossy()
            )),
            OsString::from("--vsock"),
            OsString::from(format!(
                "cid={guest_cid},socket={}",
                vsock_socket_path.as_str()
            )),
            OsString::from("--net"),
            OsString::from(format!(
                "tap={},mac={}",
                network.tap_name.as_str(),
                network.network_config.guest_mac.as_str()
            )),
        ]);
        for device in devices {
            let disk = match &device.frontend {
                PrepareDeviceFrontend::KernelNbd {
                    device_path,
                    direct,
                    ..
                } => {
                    anyhow::ensure!(
                        !device_path.as_str().contains(','),
                        "kernel-NBD device path contains a Cloud Hypervisor separator"
                    );
                    file_disk_arg_with_serial(
                        device_path.as_str(),
                        *direct,
                        device.guest_device.serial.as_str(),
                    )?
                }
                PrepareDeviceFrontend::VhostUserBlk {
                    socket_path,
                    queues,
                    queue_size,
                } => vhost_user_disk_arg_with_serial(
                    Path::new(socket_path.as_str()),
                    usize::from(*queues),
                    *queue_size,
                    device.guest_device.serial.as_str(),
                )?,
            };
            arguments.push(OsString::from("--disk"));
            arguments.push(OsString::from(disk));
        }
        arguments.extend([
            OsString::from("--serial"),
            OsString::from(format!(
                "file={}",
                fixed_fd_path(SERIAL_LOG_FD).to_string_lossy()
            )),
            OsString::from("--console"),
            OsString::from("off"),
        ]);
        anyhow::ensure!(
            !process_identity_token.as_str().is_empty(),
            "StartRuntime process token is empty"
        );
        Ok(Self {
            checkpoint,
            cloud_hypervisor_arguments: arguments,
        })
    }

    pub fn checkpoint(&self) -> &RuntimeCheckpoint {
        &self.checkpoint
    }

    pub fn cloud_hypervisor_arguments(&self) -> &[OsString] {
        &self.cloud_hypervisor_arguments
    }

    pub fn vmm_executable(&self) -> &RuntimeLaunchArtifact {
        let ReconcileStep::StartRuntime { boot, .. } = &self.checkpoint.step else {
            unreachable!("constructor accepts only StartRuntime")
        };
        &boot.vmm_executable
    }
}

fn fixed_fd_path(fd: i32) -> OsString {
    OsString::from(format!("/proc/self/fd/{fd}"))
}

fn launch_file_parents_are_equal_or_disjoint(paths: &[&Path]) -> bool {
    for (index, left) in paths.iter().enumerate() {
        let Some(left_parent) = left.parent() else {
            return false;
        };
        for right in &paths[index + 1..] {
            let Some(right_parent) = right.parent() else {
                return false;
            };
            if left_parent != right_parent
                && (left_parent.starts_with(right_parent) || right_parent.starts_with(left_parent))
            {
                return false;
            }
        }
    }
    true
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::ffi::{CStr, CString, OsString};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
    use std::os::unix::process::CommandExt as _;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;

    use anyhow::{Context as _, Result};
    use cats_api::runtime_reconciliation::{
        decode_runtime_checkpoint, ReconcileStep, RuntimeLaunchArtifact, Sha256Digest,
        RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
    };
    use sha2::{Digest as _, Sha256};

    use crate::runtime::reconciliation::{
        vmm_state_directory_from_checkpoint, ManagedVmmSocketPreparation,
        RetainedManagedVmmLaunchRoot, RetainedManagedVmmSocketRoot, VmmSocketReceiptStore,
    };

    use super::{
        fixed_fd_path, VmmLauncherPlan, CHECKPOINT_FD, CHECKPOINT_FD_NAME, INITRAMFS_FD,
        INITRAMFS_FD_NAME, KERNEL_FD, KERNEL_FD_NAME, MEMORY_FD, RUNTIME_INCARNATION_ENVIRONMENT,
        SERIAL_LOG_FD, VMM_API_LISTENER_FD, VMM_FD, VMM_FD_NAME, VMM_LOG_FD,
        VMM_PROCESS_TOKEN_ENVIRONMENT,
    };

    const HASH_BUFFER_BYTES: usize = 1024 * 1024;

    pub(super) fn run() -> Result<()> {
        let mut arguments = std::env::args_os();
        let _program = arguments.next().context("VMM launcher argv is empty")?;
        anyhow::ensure!(
            arguments.next().as_deref()
                == Some(std::ffi::OsStr::new(super::VMM_LAUNCHER_CONTRACT_ARGUMENT))
                && arguments.next().is_none(),
            "VMM launcher requires the exact V1 contract argument"
        );

        let mut open_files = SystemdOpenFiles::take_from_environment()?;
        let checkpoint_file = open_files.take(CHECKPOINT_FD_NAME)?;
        let checkpoint_bytes = read_bounded_checkpoint(&checkpoint_file)?;
        let checkpoint = decode_runtime_checkpoint(&checkpoint_bytes)
            .context("decode VMM launcher Runtime checkpoint")?;
        let plan = VmmLauncherPlan::from_checkpoint(checkpoint)?;
        let ReconcileStep::StartRuntime {
            launcher_executable,
            boot,
            runtime_incarnation,
            process_identity_token,
            memory_bytes,
            api_socket_path: _,
            vsock_socket_path,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &plan.checkpoint.step
        else {
            unreachable!("plan constructor accepts only StartRuntime")
        };

        validate_bound_environment(
            runtime_incarnation.as_str(),
            process_identity_token.as_str(),
        )?;
        validate_current_executable(launcher_executable)?;
        let vmm = open_files.take(VMM_FD_NAME)?;
        validate_artifact(&vmm, &boot.vmm_executable, 0o755)?;
        let kernel = open_files.take(KERNEL_FD_NAME)?;
        validate_artifact(&kernel, &boot.kernel, 0o644)?;
        let initramfs = match &boot.initramfs {
            Some(expected) => {
                let file = open_files.take(INITRAMFS_FD_NAME)?;
                validate_artifact(&file, expected, 0o644)?;
                Some(file)
            }
            None => None,
        };
        open_files.ensure_empty()?;

        let state_directory = vmm_state_directory_from_checkpoint(plan.checkpoint())?;
        let managed_socket_root = RetainedManagedVmmSocketRoot::open_installed()
            .context("open installed VMM socket root")?;
        let launch_root = Arc::new(
            RetainedManagedVmmLaunchRoot::open_existing(state_directory.clone())
                .context("open installed VMM launch-file namespace")?,
        );
        let socket_receipts = VmmSocketReceiptStore::open_existing(state_directory)
            .context("open installed VMM socket receipt namespace")?;
        let receipt = socket_receipts
            .load(runtime_incarnation)
            .context("load checkpointed VMM ownership receipt")?
            .context("checkpointed VMM ownership receipt is missing")?;
        // The shared namespace guard is acquired before the first socket or
        // launch-file mutation and remains live until exec. Recovery takes
        // its exclusive side, so a late launcher produces a refresh rather
        // than a leaf-replacement unlink race.
        let launch_attempt = launch_root
            .retain_launcher_attempt(plan.checkpoint(), &receipt)
            .context("retain checkpointed VMM launch attempt")?
            .context("VMM launch namespace is held by recovery")?;
        launch_attempt.assert_ready()?;
        let api_listener = match managed_socket_root
            .prepare_existing_receipt(plan.checkpoint(), &socket_receipts)
            .context("prepare checkpointed VMM socket namespace")?
        {
            ManagedVmmSocketPreparation::Prepared(prepared) => prepared,
            ManagedVmmSocketPreparation::ExistingLive => {
                anyhow::bail!("checkpointed VMM socket namespace already has a live holder")
            }
        };

        let vsock_parent = CheckedParent::open(Path::new(vsock_socket_path.as_str()))?;
        vsock_parent.ensure_absent()?;
        let [memory, serial_log, vmm_log] = OwnedLaunchFile::create_batch([
            (Path::new(memory_file_path.as_str()), *memory_bytes),
            (Path::new(serial_log_path.as_str()), 0),
            (Path::new(vmm_log_path.as_str()), 0),
        ])?;

        // Close replacement and late-socket windows after all exclusive files
        // exist but before the process boundary linearizes at exec.
        validate_current_executable(launcher_executable)?;
        validate_artifact(&vmm, &boot.vmm_executable, 0o755)?;
        validate_artifact(&kernel, &boot.kernel, 0o644)?;
        if let (Some(file), Some(expected)) = (&initramfs, &boot.initramfs) {
            validate_artifact(file, expected, 0o644)?;
        }
        api_listener.assert_current()?;
        vsock_parent.assert_current_and_absent()?;
        memory.assert_current(*memory_bytes)?;
        serial_log.assert_current(0)?;
        vmm_log.assert_current(0)?;
        launch_attempt.assert_ready()?;

        install_fixed_fd(&checkpoint_file, CHECKPOINT_FD)?;
        install_fixed_fd(&vmm, VMM_FD)?;
        install_fixed_fd(&kernel, KERNEL_FD)?;
        if let Some(initramfs) = &initramfs {
            install_fixed_fd(initramfs, INITRAMFS_FD)?;
        }
        install_fixed_fd(&memory.file, MEMORY_FD)?;
        install_fixed_fd(&serial_log.file, SERIAL_LOG_FD)?;
        install_fixed_fd(&vmm_log.file, VMM_LOG_FD)?;
        install_fixed_fd(api_listener.api_listener(), VMM_API_LISTENER_FD)?;

        let stderr_fd = duplicate_fd(VMM_LOG_FD)?;
        // SAFETY: `duplicate_fd` returned a new descriptor owned by this File.
        let stderr = unsafe { File::from_raw_fd(stderr_fd) };
        let mut command = Command::new(fixed_fd_path(VMM_FD));
        command
            .arg0(OsString::from(plan.vmm_executable().path.as_str()))
            .args(plan.cloud_hypervisor_arguments())
            .env_clear()
            .env(
                VMM_PROCESS_TOKEN_ENVIRONMENT,
                process_identity_token.as_str(),
            )
            .env(
                RUNTIME_INCARNATION_ENVIRONMENT,
                runtime_incarnation.as_str(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .current_dir("/");
        // Bracket descriptor installation and command construction with one
        // final lexical proof immediately before exec.  The fixed descriptors
        // remain the launch authority, while these checks ensure the
        // checkpointed canonical paths still name those same files.
        api_listener.assert_current()?;
        vsock_parent.assert_current_and_absent()?;
        memory.assert_current(*memory_bytes)?;
        serial_log.assert_current(0)?;
        vmm_log.assert_current(0)?;
        launch_attempt.assert_ready()?;
        let error = command.exec();
        Err(error).context("exec exact Cloud Hypervisor descriptor")
    }

    struct SystemdOpenFiles {
        files: BTreeMap<String, File>,
    }

    impl SystemdOpenFiles {
        fn take_from_environment() -> Result<Self> {
            let current_pid = std::process::id();
            let listen_pid = std::env::var("LISTEN_PID")
                .context("systemd did not pass LISTEN_PID")?
                .parse::<u32>()
                .context("LISTEN_PID is not a u32")?;
            anyhow::ensure!(listen_pid == current_pid, "LISTEN_PID is not this launcher");
            let count = std::env::var("LISTEN_FDS")
                .context("systemd did not pass LISTEN_FDS")?
                .parse::<usize>()
                .context("LISTEN_FDS is not a usize")?;
            anyhow::ensure!(
                (3..=4).contains(&count),
                "unexpected systemd open-file count"
            );
            let names = std::env::var("LISTEN_FDNAMES")
                .context("systemd did not pass LISTEN_FDNAMES")?
                .split(':')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            anyhow::ensure!(
                names.len() == count,
                "systemd open-file names do not match FDs"
            );
            let mut files = BTreeMap::new();
            for (offset, name) in names.into_iter().enumerate() {
                anyhow::ensure!(!name.is_empty(), "systemd passed an empty FD name");
                let fd = 3_i32
                    .checked_add(i32::try_from(offset).context("activation FD offset overflow")?)
                    .context("activation FD overflow")?;
                // SAFETY: systemd transfers ownership of LISTEN_FDS descriptors
                // beginning at 3 to this process exactly once.
                let file = unsafe { File::from_raw_fd(fd) };
                set_close_on_exec(&file)?;
                anyhow::ensure!(
                    files.insert(name, file).is_none(),
                    "duplicate systemd FD name"
                );
            }
            Ok(Self { files })
        }

        fn take(&mut self, name: &str) -> Result<File> {
            self.files
                .remove(name)
                .with_context(|| format!("systemd did not pass {name}"))
        }

        fn ensure_empty(&self) -> Result<()> {
            anyhow::ensure!(self.files.is_empty(), "systemd passed an unknown open file");
            Ok(())
        }
    }

    fn set_close_on_exec(file: &File) -> Result<()> {
        // SAFETY: F_GETFD only reads flags from this live owned descriptor.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error())
                .context("read systemd open-file descriptor flags");
        }
        // SAFETY: F_SETFD changes only the flags of this live owned
        // descriptor.  The fixed 64+ launch descriptors are installed later
        // without CLOEXEC; these original activation descriptors must not
        // leak through the launcher-to-VMM exec.
        let result =
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if result < 0 {
            Err(io::Error::last_os_error()).context("set CLOEXEC on systemd open-file descriptor")
        } else {
            Ok(())
        }
    }

    fn read_bounded_checkpoint(file: &File) -> Result<Vec<u8>> {
        let metadata = file.metadata().context("stat launcher checkpoint FD")?;
        ensure_regular_root_file(&metadata, 0o600)?;
        let length = usize::try_from(metadata.len()).context("checkpoint length exceeds usize")?;
        anyhow::ensure!(
            (1..=RUNTIME_CHECKPOINT_MAX_WIRE_BYTES).contains(&length),
            "launcher checkpoint length is outside the wire bound"
        );
        let mut bytes = vec![0_u8; length];
        read_exact_at(file, &mut bytes)?;
        let mut extra = [0_u8; 1];
        anyhow::ensure!(
            file.read_at(&mut extra, length as u64)
                .context("probe launcher checkpoint EOF")?
                == 0,
            "launcher checkpoint grew while it was read"
        );
        let after = file.metadata().context("re-stat launcher checkpoint FD")?;
        anyhow::ensure!(
            same_stable_file(&metadata, &after),
            "launcher checkpoint changed"
        );
        Ok(bytes)
    }

    fn validate_bound_environment(incarnation: &str, token: &str) -> Result<()> {
        anyhow::ensure!(
            std::env::var(RUNTIME_INCARNATION_ENVIRONMENT).as_deref() == Ok(incarnation),
            "launcher incarnation environment is not checkpoint-exact"
        );
        anyhow::ensure!(
            std::env::var(VMM_PROCESS_TOKEN_ENVIRONMENT).as_deref() == Ok(token),
            "launcher process-token environment is not checkpoint-exact"
        );
        for (name, _) in std::env::vars_os() {
            if let Some(name) = name.to_str() {
                anyhow::ensure!(
                    !name.starts_with("CATS_")
                        || name == RUNTIME_INCARNATION_ENVIRONMENT
                        || name == VMM_PROCESS_TOKEN_ENVIRONMENT,
                    "launcher inherited an unexpected CATS environment variable"
                );
            }
        }
        Ok(())
    }

    fn validate_current_executable(expected: &RuntimeLaunchArtifact) -> Result<()> {
        let current = std::fs::read_link("/proc/self/exe").context("read launcher executable")?;
        anyhow::ensure!(
            current == Path::new(expected.path.as_str()),
            "launcher executable pathname is not checkpoint-exact"
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")
            .context("open launcher executable")?;
        validate_artifact(&file, expected, 0o755)
    }

    fn validate_artifact(file: &File, expected: &RuntimeLaunchArtifact, mode: u32) -> Result<()> {
        let metadata = file.metadata().context("stat VMM launch artifact FD")?;
        ensure_regular_root_file(&metadata, mode)?;
        anyhow::ensure!(
            metadata.len() == expected.length.get(),
            "VMM launch artifact length changed"
        );
        let digest = hash_exact(file, metadata.len())?;
        anyhow::ensure!(
            digest == expected.content_sha256,
            "VMM launch artifact digest changed"
        );
        let after = file.metadata().context("re-stat VMM launch artifact FD")?;
        anyhow::ensure!(
            same_stable_file(&metadata, &after),
            "VMM launch artifact changed"
        );
        Ok(())
    }

    fn hash_exact(file: &File, length: u64) -> Result<Sha256Digest> {
        let mut hasher = Sha256::new();
        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
        while offset < length {
            let remaining = usize::try_from((length - offset).min(HASH_BUFFER_BYTES as u64))
                .context("artifact hash chunk exceeds usize")?;
            let read = file
                .read_at(&mut buffer[..remaining], offset)
                .context("read VMM launch artifact")?;
            anyhow::ensure!(read > 0, "VMM launch artifact ended early");
            hasher.update(&buffer[..read]);
            offset = offset
                .checked_add(read as u64)
                .context("artifact hash offset overflow")?;
        }
        let mut extra = [0_u8; 1];
        anyhow::ensure!(
            file.read_at(&mut extra, length)
                .context("probe VMM launch artifact EOF")?
                == 0,
            "VMM launch artifact grew while it was hashed"
        );
        Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
    }

    fn read_exact_at(file: &File, bytes: &mut [u8]) -> Result<()> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let read = file
                .read_at(&mut bytes[offset..], offset as u64)
                .context("read exact launcher checkpoint")?;
            anyhow::ensure!(read > 0, "launcher checkpoint ended early");
            offset = offset
                .checked_add(read)
                .context("checkpoint offset overflow")?;
        }
        Ok(())
    }

    fn ensure_regular_root_file(metadata: &std::fs::Metadata, mode: u32) -> Result<()> {
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "launch FD is not a regular file"
        );
        anyhow::ensure!(metadata.nlink() == 1, "launch FD is not single-link");
        anyhow::ensure!(
            metadata.uid() == 0 && metadata.gid() == 0,
            "launch FD is not root-owned"
        );
        anyhow::ensure!(
            metadata.mode() & 0o7777 == mode,
            "launch FD mode is not exact"
        );
        Ok(())
    }

    fn same_stable_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.len() == right.len()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.gid() == right.gid()
            && left.nlink() == right.nlink()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }

    struct CheckedParent {
        path: PathBuf,
        directories: DirectoryChain,
        basename: CString,
    }

    impl CheckedParent {
        fn open(path: &Path) -> Result<Self> {
            anyhow::ensure!(path.is_absolute(), "launch resource path is not absolute");
            let basename = path
                .file_name()
                .context("launch resource path has no basename")?;
            let basename = CString::new(basename.as_bytes())
                .context("launch resource basename contains NUL")?;
            let parent = path
                .parent()
                .context("launch resource path has no parent")?;
            let directories = open_directory_chain(parent)?;
            Ok(Self {
                path: path.to_path_buf(),
                directories,
                basename,
            })
        }

        fn descriptor(&self) -> &File {
            self.directories.leaf()
        }

        fn ensure_absent(&self) -> Result<()> {
            match stat_at(self.descriptor(), &self.basename) {
                Ok(_) => anyhow::bail!("launch resource already exists: {}", self.path.display()),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                Err(error) => Err(error).context("inspect launch resource path"),
            }
        }

        fn assert_current(&self) -> Result<Self> {
            let current = Self::open(&self.path)?;
            anyhow::ensure!(
                self.directories.retained_matches(&current.directories)?,
                "launch resource ancestor chain changed"
            );
            Ok(current)
        }

        fn freeze_after_batch(&self) -> Result<Self> {
            let current = Self::open(&self.path)?;
            anyhow::ensure!(
                self.directories
                    .retained_matches_after_batch(&current.directories)?,
                "launch resource ancestor changed while its file batch was created"
            );
            Ok(current)
        }

        fn assert_current_and_absent(&self) -> Result<()> {
            let current = self.assert_current()?;
            self.ensure_absent()?;
            current.ensure_absent()
        }
    }

    struct OwnedLaunchFile {
        parent: CheckedParent,
        file: File,
        device: u64,
        inode: u64,
    }

    impl OwnedLaunchFile {
        #[cfg(test)]
        fn create(path: &Path) -> Result<Self> {
            let [owned] = Self::create_batch([(path, 0)])?;
            Ok(owned)
        }

        fn create_batch<const N: usize>(requests: [(&Path, u64); N]) -> Result<[Self; N]> {
            Self::create_batch_inner(requests, || Ok(()))
        }

        #[cfg(test)]
        fn create_batch_with_before_freeze<const N: usize>(
            requests: [(&Path, u64); N],
            before_freeze: impl FnOnce() -> Result<()>,
        ) -> Result<[Self; N]> {
            Self::create_batch_inner(requests, before_freeze)
        }

        fn create_batch_inner<const N: usize>(
            requests: [(&Path, u64); N],
            before_freeze: impl FnOnce() -> Result<()>,
        ) -> Result<[Self; N]> {
            for (index, (path, _)) in requests.iter().enumerate() {
                anyhow::ensure!(
                    !requests[..index]
                        .iter()
                        .any(|(other_path, _)| other_path == path),
                    "VMM launch file batch contains a duplicate path"
                );
            }
            let request_paths = requests.iter().map(|(path, _)| *path).collect::<Vec<_>>();
            anyhow::ensure!(
                super::launch_file_parents_are_equal_or_disjoint(&request_paths),
                "VMM launch file parents are nested"
            );

            // Resolve every canonical parent and prove every leaf absent before
            // the first no-replace create. The batch's own sibling creates may
            // then update a shared parent, so all parent baselines are frozen
            // only after the complete known set exists.
            let mut prepared = Vec::with_capacity(N);
            for (path, expected_length) in requests {
                let parent = CheckedParent::open(path)?;
                parent.ensure_absent()?;
                prepared.push((parent, expected_length));
            }
            let mut created = Vec::with_capacity(N);
            for (parent, expected_length) in prepared {
                // SAFETY: `parent` is a retained directory descriptor and
                // `basename` is NUL-free. O_EXCL/O_NOFOLLOW prevent replacement
                // or symlink adoption at the leaf.
                let fd = unsafe {
                    libc::openat(
                        parent.descriptor().as_raw_fd(),
                        parent.basename.as_ptr(),
                        libc::O_RDWR
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )
                };
                if fd < 0 {
                    return Err(io::Error::last_os_error())
                        .context("create exclusive VMM launch file");
                }
                // SAFETY: successful openat returned one newly-owned descriptor.
                let file = unsafe { File::from_raw_fd(fd) };
                file.set_len(expected_length)
                    .context("size exclusive VMM launch file")?;
                let baseline = file.metadata().context("stat exclusive VMM launch file")?;
                ensure_owned_launch_file(&baseline, expected_length)?;
                created.push((parent, file, baseline, expected_length));
            }
            before_freeze()?;

            let mut owned = Vec::with_capacity(N);
            for (parent, file, baseline, _expected_length) in created {
                let current_parent = parent.freeze_after_batch()?;
                let retained_path = stat_at(parent.descriptor(), &parent.basename)
                    .context("reinspect newly-created VMM launch file")?;
                let current_path = stat_at(current_parent.descriptor(), &current_parent.basename)
                    .context("reopen newly-created VMM launch file")?;
                let after = file
                    .metadata()
                    .context("re-stat exclusive VMM launch file")?;
                anyhow::ensure!(
                    same_stable_file(&baseline, &after)
                        && same_stable_file(&baseline, &retained_path)
                        && same_stable_file(&baseline, &current_path),
                    "new VMM launch file pathname or contents changed"
                );
                owned.push(Self {
                    parent: current_parent,
                    file,
                    device: baseline.dev(),
                    inode: baseline.ino(),
                });
            }

            for (file, (_, expected_length)) in owned.iter().zip(requests.iter()) {
                file.assert_current(*expected_length)?;
            }
            owned
                .try_into()
                .map_err(|_| anyhow::anyhow!("VMM launch file batch length changed"))
        }

        fn assert_current(&self, expected_length: u64) -> Result<()> {
            let before = self
                .file
                .metadata()
                .context("stat retained VMM launch file")?;
            ensure_owned_launch_file(&before, expected_length)?;
            anyhow::ensure!(
                before.dev() == self.device && before.ino() == self.inode,
                "retained VMM launch file identity changed"
            );
            let retained_path = stat_at(self.parent.descriptor(), &self.parent.basename)
                .context("reinspect retained VMM launch file path")?;
            let current_parent = self.parent.assert_current()?;
            let current_path = stat_at(current_parent.descriptor(), &current_parent.basename)
                .context("reopen current VMM launch file path")?;
            let after = self
                .file
                .metadata()
                .context("re-stat retained VMM launch file")?;
            anyhow::ensure!(
                same_stable_file(&before, &after)
                    && same_stable_file(&before, &retained_path)
                    && same_stable_file(&before, &current_path),
                "VMM launch file pathname or contents changed"
            );
            Ok(())
        }
    }

    fn ensure_owned_launch_file(metadata: &std::fs::Metadata, expected_length: u64) -> Result<()> {
        ensure_regular_root_file(metadata, 0o600)?;
        anyhow::ensure!(
            metadata.len() == expected_length,
            "VMM launch file length changed"
        );
        Ok(())
    }

    // Intentionally no Drop unlink: a check-then-unlink cleanup can delete a
    // foreign pathname replacement.  Any failed or ambiguous launch leaves
    // its no-replace file for checkpoint-aware fresh-full recovery.

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct DirectoryIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    impl DirectoryIdentity {
        fn from(metadata: &std::fs::Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                links: metadata.nlink(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }

        fn same_node_and_policy(&self, other: &Self) -> bool {
            self.device == other.device
                && self.inode == other.inode
                && self.mode == other.mode
                && self.uid == other.uid
                && self.gid == other.gid
                && self.links == other.links
        }
    }

    struct RetainedDirectory {
        descriptor: File,
        identity: DirectoryIdentity,
    }

    struct DirectoryChain {
        directories: Vec<RetainedDirectory>,
    }

    impl DirectoryChain {
        fn leaf(&self) -> &File {
            &self
                .directories
                .last()
                .expect("absolute paths retain at least the root directory")
                .descriptor
        }

        fn retained_matches(&self, current: &Self) -> Result<bool> {
            if self.directories.len() != current.directories.len() {
                return Ok(false);
            }
            for (retained, reopened) in self.directories.iter().zip(&current.directories) {
                let retained_metadata = retained
                    .descriptor
                    .metadata()
                    .context("reinspect retained launch ancestor")?;
                ensure_safe_directory(&retained_metadata)?;
                if DirectoryIdentity::from(&retained_metadata) != retained.identity
                    || retained.identity != reopened.identity
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        fn retained_matches_after_batch(&self, current: &Self) -> Result<bool> {
            if self.directories.len() != current.directories.len() {
                return Ok(false);
            }
            let last = self.directories.len().saturating_sub(1);
            for (index, (retained, reopened)) in self
                .directories
                .iter()
                .zip(&current.directories)
                .enumerate()
            {
                let retained_metadata = retained
                    .descriptor
                    .metadata()
                    .context("reinspect launch ancestor after file batch")?;
                ensure_safe_directory(&retained_metadata)?;
                let retained_current = DirectoryIdentity::from(&retained_metadata);
                if index == last {
                    if !retained_current.same_node_and_policy(&retained.identity)
                        || retained_current != reopened.identity
                    {
                        return Ok(false);
                    }
                } else if retained_current != retained.identity
                    || retained.identity != reopened.identity
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }

    fn open_directory_chain(path: &Path) -> Result<DirectoryChain> {
        // SAFETY: fixed NUL-terminated path and flags; returned descriptor is
        // immediately owned by File on success.
        let root_fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(io::Error::last_os_error()).context("open launch root directory");
        }
        // SAFETY: successful open returned one owned descriptor.
        let mut current = unsafe { File::from_raw_fd(root_fd) };
        let root_metadata = current.metadata().context("stat launch root directory")?;
        ensure_safe_directory(&root_metadata)?;
        let mut directories = vec![RetainedDirectory {
            descriptor: current,
            identity: DirectoryIdentity::from(&root_metadata),
        }];
        for component in path.components() {
            match component {
                Component::RootDir => continue,
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes())
                        .context("launch directory component contains NUL")?;
                    // SAFETY: current is a retained directory, and name is a
                    // checked relative component with no NUL.
                    let fd = unsafe {
                        libc::openat(
                            directories
                                .last()
                                .expect("root is retained")
                                .descriptor
                                .as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(io::Error::last_os_error())
                            .context("open launch directory component");
                    }
                    // SAFETY: successful openat returned one owned descriptor.
                    current = unsafe { File::from_raw_fd(fd) };
                    let metadata = current
                        .metadata()
                        .context("stat launch directory component")?;
                    ensure_safe_directory(&metadata)?;
                    directories.push(RetainedDirectory {
                        descriptor: current,
                        identity: DirectoryIdentity::from(&metadata),
                    });
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    anyhow::bail!("launch resource path is not canonical")
                }
            }
        }
        Ok(DirectoryChain { directories })
    }

    fn ensure_safe_directory(metadata: &std::fs::Metadata) -> Result<()> {
        anyhow::ensure!(
            metadata.file_type().is_dir(),
            "launch ancestor is not a directory"
        );
        anyhow::ensure!(
            metadata.uid() == 0 && metadata.gid() == 0,
            "launch ancestor is not root-owned"
        );
        anyhow::ensure!(
            metadata.mode() & 0o022 == 0,
            "launch ancestor is writable by group/other"
        );
        Ok(())
    }

    fn stat_at(parent: &File, name: &CStr) -> io::Result<std::fs::Metadata> {
        let path = PathBuf::from(OsString::from_vec(name.to_bytes().to_vec()));
        // `/proc/self/fd/<n>/<name>` follows the retained parent descriptor;
        // symlink_metadata keeps the leaf no-follow for identity checks.
        std::fs::symlink_metadata(
            PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(path),
        )
    }

    fn install_fixed_fd(file: &File, target: RawFd) -> Result<()> {
        if file.as_raw_fd() != target {
            // SAFETY: both integers are descriptors; dup3 atomically replaces
            // the target and creates a non-CLOEXEC duplicate on success.
            let result = unsafe { libc::dup3(file.as_raw_fd(), target, 0) };
            if result < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("install fixed VMM descriptor {target}"));
            }
        } else {
            // SAFETY: fcntl operates only on this live descriptor.
            let flags = unsafe { libc::fcntl(target, libc::F_GETFD) };
            if flags < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("read VMM descriptor flags {target}"));
            }
            // SAFETY: F_SETFD changes only the flags of the live fixed target.
            let result = unsafe { libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
            if result < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("clear CLOEXEC on VMM descriptor {target}"));
            }
        }
        Ok(())
    }

    fn duplicate_fd(fd: RawFd) -> Result<RawFd> {
        // SAFETY: F_DUPFD_CLOEXEC duplicates one live descriptor and returns a
        // new independently-owned descriptor.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            Err(io::Error::last_os_error()).context("duplicate VMM log descriptor")
        } else {
            Ok(duplicate)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        use super::*;

        fn running_as_root() -> bool {
            // SAFETY: geteuid has no pointer arguments or side effects.
            unsafe { libc::geteuid() == 0 }
        }

        fn launch_path() -> (tempfile::TempDir, PathBuf) {
            let root = tempfile::Builder::new()
                .prefix("cats-vmm-launcher-")
                .tempdir_in("/run")
                .unwrap();
            let parent = root.path().join("cat/runtime");
            std::fs::create_dir_all(&parent).unwrap();
            (root, parent.join("launch.file"))
        }

        #[test]
        fn systemd_open_file_descriptors_are_made_close_on_exec() {
            let file = tempfile::tempfile().unwrap();
            // SAFETY: F_GETFD reads flags from the live test descriptor.
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0);
            // SAFETY: F_SETFD changes only this live test descriptor.
            let result =
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
            assert!(result >= 0);

            set_close_on_exec(&file).unwrap();

            // SAFETY: F_GETFD reads flags from the live test descriptor.
            let after = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            assert!(after & libc::FD_CLOEXEC != 0);
        }

        #[test]
        fn launch_file_rejects_leaf_replacement_and_never_unlinks_it_on_drop() {
            if !running_as_root() {
                return;
            }
            let (_root, path) = launch_path();
            let owned = OwnedLaunchFile::create(&path).unwrap();
            owned.assert_current(0).unwrap();
            let moved = path.with_extension("moved");
            std::fs::rename(&path, &moved).unwrap();
            let mut replacement = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            replacement.write_all(b"foreign").unwrap();
            replacement.sync_all().unwrap();

            assert!(owned.assert_current(0).is_err());
            drop(owned);
            assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        }

        #[test]
        fn launch_file_rejects_an_ancestor_move_away_and_back() {
            if !running_as_root() {
                return;
            }
            let (root, path) = launch_path();
            let owned = OwnedLaunchFile::create(&path).unwrap();
            owned.assert_current(0).unwrap();
            let ancestor = root.path().join("cat");
            let moved = root.path().join("moved-cat");
            std::fs::rename(&ancestor, &moved).unwrap();
            std::fs::write(moved.join("aba-marker"), b"changed").unwrap();
            std::fs::remove_file(moved.join("aba-marker")).unwrap();
            std::fs::rename(&moved, &ancestor).unwrap();

            assert!(owned.assert_current(0).is_err());
        }

        #[test]
        fn launch_file_batch_freezes_one_shared_parent_after_all_owned_creates() {
            if !running_as_root() {
                return;
            }
            let (root, path) = launch_path();
            let parent = path.parent().unwrap();
            let memory_path = parent.join("memory.bin");
            let serial_log_path = parent.join("serial.log");
            let vmm_log_path = parent.join("vmm.log");
            let [memory, serial_log, vmm_log] = OwnedLaunchFile::create_batch([
                (memory_path.as_path(), 4096),
                (serial_log_path.as_path(), 0),
                (vmm_log_path.as_path(), 0),
            ])
            .unwrap();

            memory.assert_current(4096).unwrap();
            serial_log.assert_current(0).unwrap();
            vmm_log.assert_current(0).unwrap();

            let foreign_sibling = parent.join("foreign");
            std::fs::write(&foreign_sibling, b"changed").unwrap();
            std::fs::remove_file(&foreign_sibling).unwrap();
            assert!(memory.assert_current(4096).is_err());
            assert!(serial_log.assert_current(0).is_err());
            assert!(vmm_log.assert_current(0).is_err());
            drop(root);
        }

        #[test]
        fn launch_file_batch_rejects_nested_parents_before_any_create() {
            if !running_as_root() {
                return;
            }
            let (root, path) = launch_path();
            let runtime_parent = path.parent().unwrap();
            let cat_parent = runtime_parent.parent().unwrap();
            let memory_path = cat_parent.join("memory.bin");
            let serial_log_path = runtime_parent.join("serial.log");
            let vmm_log_path = runtime_parent.join("vmm.log");

            let error = OwnedLaunchFile::create_batch([
                (memory_path.as_path(), 4096),
                (serial_log_path.as_path(), 0),
                (vmm_log_path.as_path(), 0),
            ])
            .err()
            .expect("nested launch parents must fail before create");
            assert!(error.to_string().contains("parents are nested"));
            assert!(!memory_path.exists());
            assert!(!serial_log_path.exists());
            assert!(!vmm_log_path.exists());
            drop(root);
        }

        #[test]
        fn launch_file_batch_rejects_leaf_aba_before_parent_freeze() {
            if !running_as_root() {
                return;
            }
            let (_root, path) = launch_path();
            let parent = path.parent().unwrap();
            let memory_path = parent.join("memory.bin");
            let moved_memory_path = parent.join("memory.moved");
            let serial_log_path = parent.join("serial.log");
            let vmm_log_path = parent.join("vmm.log");
            let error = OwnedLaunchFile::create_batch_with_before_freeze(
                [
                    (memory_path.as_path(), 4096),
                    (serial_log_path.as_path(), 0),
                    (vmm_log_path.as_path(), 0),
                ],
                || {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    std::fs::rename(&memory_path, &moved_memory_path)?;
                    let mut moved = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&moved_memory_path)?;
                    moved.write_all(b"foreign")?;
                    moved.sync_all()?;
                    std::fs::rename(&moved_memory_path, &memory_path)?;
                    Ok(())
                },
            )
            .err()
            .expect("leaf ABA before parent freeze must fail");

            assert!(error.to_string().contains("pathname or contents changed"));
            assert!(memory_path.exists());
            assert!(serial_log_path.exists());
            assert!(vmm_log_path.exists());
            assert!(!moved_memory_path.exists());
        }
    }
}

pub fn run() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("cats-vmm-launcher requires Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_reconciliation::decode_runtime_checkpoint;

    fn start_runtime() -> RuntimeCheckpoint {
        decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap()
    }

    #[test]
    fn exact_start_runtime_builds_the_frozen_cloud_hypervisor_argv() {
        let plan = VmmLauncherPlan::from_checkpoint(start_runtime()).unwrap();
        let arguments = plan
            .cloud_hypervisor_arguments()
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments[0..4],
            ["--api-socket", "fd=71", "--kernel", "/proc/self/fd/66"]
        );
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--initramfs", "/proc/self/fd/67"]));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--cpus", "boot=2"]));
        assert!(arguments.windows(2).any(|pair| pair
            == [
                "--memory-zone",
                "id=cat-ram,size=2048M,file=/proc/self/fd/68,shared=on"
            ]));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--vsock", "cid=3,socket=/run/cats/cat_01/vmm-vsock.sock"]));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--net", "tap=cats0001,mac=02:ca:0a:f0:00:06"]));
        assert!(arguments.windows(2).any(|pair| pair
            == [
                "--disk",
                "vhost_user=on,socket=/run/cats/cat_01/root-vhost.sock,num_queues=2,queue_size=256,serial=cats-root"
            ]));
        assert_eq!(
            &arguments[arguments.len() - 4..],
            ["--serial", "file=/proc/self/fd/69", "--console", "off"]
        );
    }

    #[test]
    fn non_start_runtime_can_never_reach_the_launcher() {
        let mut checkpoint = start_runtime();
        checkpoint.step = ReconcileStep::InspectInventory {
            inventory_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
        };
        assert!(VmmLauncherPlan::from_checkpoint(checkpoint).is_err());
    }

    #[test]
    fn kernel_nbd_arguments_preserve_direct_and_guest_slot_order() {
        let mut checkpoint = start_runtime();
        let ReconcileStep::StartRuntime { devices, .. } = &mut checkpoint.step else {
            unreachable!()
        };
        let first = devices.first_mut().unwrap();
        first.frontend = PrepareDeviceFrontend::KernelNbd {
            listener_socket_path: cats_api::runtime_reconciliation::HostPath::new(
                "/run/cats/cat_01/root-nbd.sock".to_owned(),
            )
            .unwrap(),
            device_path: cats_api::runtime_reconciliation::HostPath::new("/dev/nbd7".to_owned())
                .unwrap(),
            direct: true,
        };
        let plan = VmmLauncherPlan::from_checkpoint(checkpoint).unwrap();
        let arguments = plan
            .cloud_hypervisor_arguments()
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(arguments.windows(2).any(|pair| pair
            == [
                "--disk",
                "path=/dev/nbd7,image_type=raw,direct=on,serial=cats-root"
            ]));
    }

    #[test]
    fn vsock_paths_with_a_cloud_hypervisor_separator_are_rejected() {
        let mut checkpoint = start_runtime();
        let ReconcileStep::StartRuntime {
            vsock_socket_path, ..
        } = &mut checkpoint.step
        else {
            unreachable!()
        };
        *vsock_socket_path = cats_api::runtime_reconciliation::HostPath::new(
            "/run/cats/cat_01/vmm,vsock.sock".to_owned(),
        )
        .unwrap();

        let error = VmmLauncherPlan::from_checkpoint(checkpoint).unwrap_err();
        assert!(error
            .to_string()
            .contains("vsock socket path contains a Cloud Hypervisor separator"));
    }

    #[test]
    fn nested_launch_file_parents_are_rejected_by_the_builder() {
        let mut checkpoint = start_runtime();
        let ReconcileStep::StartRuntime {
            memory_file_path, ..
        } = &mut checkpoint.step
        else {
            unreachable!()
        };
        *memory_file_path =
            cats_api::runtime_reconciliation::HostPath::new("/var/log/cats/memory.bin".to_owned())
                .unwrap();

        let error = VmmLauncherPlan::from_checkpoint(checkpoint).unwrap_err();
        assert!(error
            .to_string()
            .contains("VMM launch file parents are nested"));
    }
}
