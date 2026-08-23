//! Dedicated PersistentDisk filesystem control.
//!
//! Unlike RuntimeReady, this path may observe a genuinely blank device. Every
//! operation retains the exact block-device file descriptor opened with
//! `O_NOFOLLOW`, brackets the effect with sysfs/fstat/mountinfo samples, and
//! refuses to unmount or replace a foreign object.

#[cfg(any(target_os = "linux", test))]
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(any(target_os = "linux", test))]
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
#[cfg(any(target_os = "linux", test))]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use cats_api::guest::{
    FilesystemControlOperationV1, FilesystemControlOutcomeV1, FilesystemControlRequestV1,
    FilesystemControlResponseV1, FilesystemIdentityV1, PersistentFilesystemMountV1,
    PersistentFilesystemObservationV1, FILESYSTEM_CONTROL_MAX_MOUNTS_V1,
    GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
};
use cats_api::runtime_reconciliation::{
    GuestDeviceIdentity, HostPath, Id, MountAccess, RandomId128,
};

const SECTOR_BYTES: u64 = 512;
const EXT4_SUPERBLOCK_OFFSET: u64 = 1_024;
const EXT4_SUPERBLOCK_BYTES: usize = 1_024;
const EXT4_MAGIC_OFFSET: usize = 56;
const EXT4_UUID_OFFSET: usize = 104;
const EXT4_UUID_BYTES: usize = 16;
const MAX_MOUNTINFO_BYTES: u64 = 256 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const BLKID_PATH: &str = "/usr/sbin/blkid";
const MKFS_EXT4_PATH: &str = "/usr/sbin/mkfs.ext4";

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceSnapshot {
    guest_device: GuestDeviceIdentity,
    name: String,
    physical_path: PathBuf,
    reported_path: HostPath,
    device_major: u32,
    device_minor: u32,
    size_bytes: u64,
}

struct RetainedDevice {
    file: File,
    path: PathBuf,
}

#[derive(Debug)]
struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Copy)]
struct EffectGuard {
    deadline: Instant,
    peer_fd: Option<std::os::fd::RawFd>,
}

pub(super) struct FilesystemController {
    sys_block_root: PathBuf,
    dev_root: PathBuf,
    reported_dev_root: PathBuf,
    mountinfo_path: PathBuf,
    blkid_path: PathBuf,
    mkfs_ext4_path: PathBuf,
}

impl FilesystemController {
    pub(super) fn system() -> Self {
        Self {
            sys_block_root: PathBuf::from("/sys/block"),
            dev_root: PathBuf::from("/dev"),
            reported_dev_root: PathBuf::from("/dev"),
            mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
            blkid_path: PathBuf::from(BLKID_PATH),
            mkfs_ext4_path: PathBuf::from(MKFS_EXT4_PATH),
        }
    }

    pub(super) fn execute(
        &self,
        request: FilesystemControlRequestV1,
        peer_fd: Option<std::os::fd::RawFd>,
    ) -> Result<FilesystemControlResponseV1> {
        request
            .validate()
            .context("validate Persistent filesystem request")?;
        let guard = EffectGuard {
            deadline: Instant::now()
                .checked_add(Duration::from_millis(u64::from(request.timeout_ms)))
                .context("filesystem request deadline overflow")?,
            peer_fd,
        };
        ensure_active(guard)?;
        let first = self.device_snapshot(&request)?;
        let retained = self.retain(&first)?;
        let initial = self.sample_stable_observation(&first, &retained, guard)?;

        let outcome = match request.operation {
            FilesystemControlOperationV1::Probe => classify_probe(&request, &initial),
            FilesystemControlOperationV1::FormatExt4 => {
                match classify_unmounted_expected_or_blank(&request, &initial) {
                    FormatAdmission::Adopt => FilesystemControlOutcomeV1::Exact,
                    FormatAdmission::Blank => {
                        if let Err(error) =
                            super::qualification_fault::record_format_invocation(&request)
                        {
                            tracing::warn!(
                                error = %format!("{error:#}"),
                                "qualification mkfs invocation marker was not recorded"
                            );
                        }
                        self.format_ext4(&retained, &request.filesystem.filesystem_uuid, guard)?;
                        ensure_active(guard)?;
                        retained
                            .file
                            .sync_all()
                            .context("sync formatted Persistent block device")?;
                        ensure_active(guard)?;
                        FilesystemControlOutcomeV1::Exact
                    }
                    FormatAdmission::Conflict => FilesystemControlOutcomeV1::Conflict,
                }
            }
            FilesystemControlOperationV1::FlushDevice => {
                if observation_is_expected_unmounted(&request, &initial) {
                    ensure_active(guard)?;
                    retained
                        .file
                        .sync_all()
                        .context("flush retained Persistent block device")?;
                    ensure_active(guard)?;
                    FilesystemControlOutcomeV1::Exact
                } else {
                    FilesystemControlOutcomeV1::Conflict
                }
            }
            FilesystemControlOperationV1::MountExt4 => {
                if observation_is_expected_mount(&request, &initial) {
                    FilesystemControlOutcomeV1::Exact
                } else if observation_is_expected_unmounted(&request, &initial) {
                    self.mount_ext4(&retained, &request, guard)?;
                    FilesystemControlOutcomeV1::Exact
                } else {
                    FilesystemControlOutcomeV1::Conflict
                }
            }
        };

        let second = self.device_snapshot(&request)?;
        anyhow::ensure!(
            first == second,
            "virtio block identity changed during effect"
        );
        retained.verify(&second)?;
        let observation = self.sample_stable_observation(&second, &retained, guard)?;
        let response = FilesystemControlResponseV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            request: Box::new(request),
            outcome,
            observation,
        };
        response
            .validate()
            .context("validate Persistent filesystem response")?;
        Ok(response)
    }

    fn device_snapshot(&self, request: &FilesystemControlRequestV1) -> Result<DeviceSnapshot> {
        let name = virtio_block_name(request.filesystem.guest_device.slot)?;
        let sysfs = self.sys_block_root.join(&name);
        let serial = Id::new(read_trimmed(&sysfs.join("serial"))?)
            .context("virtio block serial is not canonical")?;
        let sectors = parse_canonical_u64(&read_trimmed(&sysfs.join("size"))?)
            .context("virtio block sector count is not canonical")?;
        let size_bytes = sectors
            .checked_mul(SECTOR_BYTES)
            .filter(|size| *size > 0)
            .context("virtio block size is zero or overflows")?;
        let (device_major, device_minor) = parse_device_number(&read_trimmed(&sysfs.join("dev"))?)
            .context("virtio block device number is not canonical")?;
        let snapshot = DeviceSnapshot {
            guest_device: GuestDeviceIdentity {
                serial,
                slot: request.filesystem.guest_device.slot,
            },
            physical_path: self.dev_root.join(&name),
            reported_path: HostPath::new(
                self.reported_dev_root
                    .join(&name)
                    .to_string_lossy()
                    .into_owned(),
            )
            .context("reported virtio block path is not canonical")?,
            name,
            device_major,
            device_minor,
            size_bytes,
        };
        anyhow::ensure!(
            snapshot.guest_device == request.filesystem.guest_device
                && snapshot.size_bytes == request.filesystem.size_bytes,
            "virtio block slot, serial or size conflicts with the request"
        );
        Ok(snapshot)
    }

    fn retain(&self, snapshot: &DeviceSnapshot) -> Result<RetainedDevice> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&snapshot.physical_path)
            .with_context(|| {
                format!("open {} with O_NOFOLLOW", snapshot.physical_path.display())
            })?;
        let retained = RetainedDevice {
            file,
            path: snapshot.physical_path.clone(),
        };
        retained.verify(snapshot)?;
        Ok(retained)
    }

    fn sample_stable_observation(
        &self,
        snapshot: &DeviceSnapshot,
        retained: &RetainedDevice,
        guard: EffectGuard,
    ) -> Result<PersistentFilesystemObservationV1> {
        retained.verify(snapshot)?;
        ensure_active(guard)?;
        let filesystem_first = self.filesystem_identity(retained, guard)?;
        let mountinfo_first = read_bounded(&self.mountinfo_path, MAX_MOUNTINFO_BYTES)?;
        let mounts_first = mounts_from_bytes(&mountinfo_first, snapshot)?;
        let filesystem_second = self.filesystem_identity(retained, guard)?;
        let mountinfo_second = read_bounded(&self.mountinfo_path, MAX_MOUNTINFO_BYTES)?;
        anyhow::ensure!(
            filesystem_first == filesystem_second && mountinfo_first == mountinfo_second,
            "filesystem identity or mountinfo changed during sampling"
        );
        retained.verify(snapshot)?;
        Ok(PersistentFilesystemObservationV1 {
            guest_device: snapshot.guest_device.clone(),
            device_path: snapshot.reported_path.clone(),
            device_major: snapshot.device_major,
            device_minor: snapshot.device_minor,
            size_bytes: snapshot.size_bytes,
            filesystem: filesystem_first,
            mounts: mounts_first,
        })
    }

    fn filesystem_identity(
        &self,
        retained: &RetainedDevice,
        guard: EffectGuard,
    ) -> Result<FilesystemIdentityV1> {
        let superblock_uuid = read_ext4_uuid(&retained.file)?;
        let filesystem_type = run_with_retained_fd(
            &self.blkid_path,
            &["-p", "-o", "value", "-s", "TYPE"],
            retained,
            guard,
        )?;
        match filesystem_type.status.code() {
            Some(2) if trim_ascii(&filesystem_type.stdout).is_empty() => {
                Ok(if superblock_uuid.is_some() {
                    // A magic/UUID-shaped superblock which libblkid cannot
                    // validate is a partial format, never a blank device.
                    FilesystemIdentityV1::Foreign
                } else {
                    FilesystemIdentityV1::Blank
                })
            }
            Some(0) if trim_ascii(&filesystem_type.stdout) == b"ext4" => {
                let uuid = run_with_retained_fd(
                    &self.blkid_path,
                    &["-p", "-o", "value", "-s", "UUID"],
                    retained,
                    guard,
                )?;
                let Some(filesystem_uuid) = parse_blkid_uuid(&uuid)? else {
                    return Ok(FilesystemIdentityV1::Foreign);
                };
                if superblock_uuid.as_ref() == Some(&filesystem_uuid) {
                    Ok(FilesystemIdentityV1::Ext4 { filesystem_uuid })
                } else {
                    Ok(FilesystemIdentityV1::Foreign)
                }
            }
            Some(0) if !trim_ascii(&filesystem_type.stdout).is_empty() => {
                Ok(FilesystemIdentityV1::Foreign)
            }
            // libblkid reports ambivalent/mixed signatures as status 8.
            Some(8) => Ok(FilesystemIdentityV1::Foreign),
            _ => anyhow::bail!(
                "blkid probe failed: status={:?} stderr={}",
                filesystem_type.status.code(),
                String::from_utf8_lossy(&filesystem_type.stderr)
            ),
        }
    }

    fn format_ext4(
        &self,
        retained: &RetainedDevice,
        filesystem_uuid: &RandomId128,
        guard: EffectGuard,
    ) -> Result<()> {
        let dashed_uuid = dashed_uuid(filesystem_uuid);
        let output = run_with_retained_fd(
            &self.mkfs_ext4_path,
            &[
                "-q",
                "-F",
                "-U",
                &dashed_uuid,
                "-E",
                "lazy_itable_init=0,lazy_journal_init=0",
            ],
            retained,
            guard,
        )?;
        anyhow::ensure!(
            output.status.success(),
            "mkfs.ext4 failed: status={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn mount_ext4(
        &self,
        retained: &RetainedDevice,
        request: &FilesystemControlRequestV1,
        guard: EffectGuard,
    ) -> Result<()> {
        ensure_active(guard)?;
        retained.verify(&self.device_snapshot(request)?)?;
        let target_path = Path::new(request.filesystem.mount_path.as_str());
        let target = open_or_create_mount_target(target_path)?;
        let target_meta = target.metadata().context("fstat mount target")?;
        let path_meta = std::fs::symlink_metadata(target_path).context("lstat mount target")?;
        anyhow::ensure!(
            target_meta.is_dir()
                && path_meta.file_type().is_dir()
                && target_meta.dev() == path_meta.dev()
                && target_meta.ino() == path_meta.ino(),
            "mount target is a symlink, replacement or non-directory"
        );
        let source = CString::new(format!("/proc/self/fd/{}", retained.file.as_raw_fd()))?;
        let target = CString::new(format!("/proc/self/fd/{}", target.as_raw_fd()))?;
        let filesystem = CString::new("ext4")?;
        let data = CString::new("errors=remount-ro")?;
        // SAFETY: all pointers are live NUL-terminated C strings for the call,
        // both file descriptors remain open, and flags/data contain no raw
        // pointers. The retained source and target were identity-checked above.
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                libc::MS_NODEV | libc::MS_NOSUID,
                data.as_ptr().cast(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("mount exact ext4 device");
        }
        ensure_active(guard)
    }

    #[cfg(not(target_os = "linux"))]
    fn mount_ext4(
        &self,
        _retained: &RetainedDevice,
        _request: &FilesystemControlRequestV1,
        _guard: EffectGuard,
    ) -> Result<()> {
        anyhow::bail!("Persistent filesystem mount is Linux-only")
    }
}

#[cfg(target_os = "linux")]
fn open_or_create_mount_target(target_path: &Path) -> Result<File> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")
        .context("open Guest filesystem root")?;
    open_or_create_mount_target_beneath(root, target_path)
}

#[cfg(any(target_os = "linux", test))]
fn open_or_create_mount_target_beneath(mut parent: File, target_path: &Path) -> Result<File> {
    anyhow::ensure!(target_path.is_absolute(), "mount target is not absolute");
    let mut depth = 0_usize;
    for component in target_path.components() {
        let Component::Normal(name) = component else {
            anyhow::ensure!(
                component == Component::RootDir,
                "mount target is not canonical"
            );
            continue;
        };
        depth += 1;
        let name = CString::new(name.as_bytes()).context("mount target component contains NUL")?;
        let next = match open_directory_at(&parent, &name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // SAFETY: `name` is a live NUL-terminated single path
                // component and `parent` is a retained directory descriptor.
                let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
                if result != 0 {
                    let error = std::io::Error::last_os_error();
                    anyhow::ensure!(
                        error.kind() == std::io::ErrorKind::AlreadyExists,
                        "create mount target component failed: {error}"
                    );
                }
                open_directory_at(&parent, &name)
                    .context("open newly created mount target component")?
            }
            Err(error) => return Err(error).context("open mount target component"),
        };
        parent = next;
    }
    anyhow::ensure!(depth > 0, "PersistentDisk mount target cannot be /");
    Ok(parent)
}

#[cfg(any(target_os = "linux", test))]
fn open_directory_at(parent: &File, name: &CString) -> std::io::Result<File> {
    // SAFETY: `name` is a live NUL-terminated single path component and the
    // returned descriptor receives unique ownership through `File`.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `descriptor` is a fresh successful `openat` result.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

impl RetainedDevice {
    fn verify(&self, snapshot: &DeviceSnapshot) -> Result<()> {
        let metadata = self
            .file
            .metadata()
            .context("fstat retained block device")?;
        anyhow::ensure!(
            metadata.file_type().is_block_device(),
            "retained device is not a block device"
        );
        let path_metadata = std::fs::symlink_metadata(&self.path)
            .with_context(|| format!("lstat retained device path {}", self.path.display()))?;
        anyhow::ensure!(
            path_metadata.file_type().is_block_device()
                && path_metadata.dev() == metadata.dev()
                && path_metadata.ino() == metadata.ino()
                && path_metadata.rdev() == metadata.rdev(),
            "retained block device path was replaced"
        );
        #[cfg(target_os = "linux")]
        {
            let major = libc::major(metadata.rdev());
            let minor = libc::minor(metadata.rdev());
            anyhow::ensure!(
                major == snapshot.device_major && minor == snapshot.device_minor,
                "retained block device number disagrees with sysfs"
            );
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (snapshot, metadata.rdev());
            anyhow::bail!("Persistent filesystem block identity proof is Linux-only")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatAdmission {
    Adopt,
    Blank,
    Conflict,
}

fn classify_probe(
    request: &FilesystemControlRequestV1,
    observation: &PersistentFilesystemObservationV1,
) -> FilesystemControlOutcomeV1 {
    let exact = match &request.filesystem.initialization {
        cats_api::runtime_reconciliation::FilesystemInitialization::Initialize { .. } => {
            observation.mounts.is_empty()
                && (matches!(observation.filesystem, FilesystemIdentityV1::Blank)
                    || observation_has_expected_uuid(request, observation))
        }
        cats_api::runtime_reconciliation::FilesystemInitialization::Existing => {
            observation_has_expected_uuid(request, observation)
                && (observation.mounts.is_empty()
                    || observation_is_expected_mount(request, observation))
        }
    };
    if exact {
        FilesystemControlOutcomeV1::Exact
    } else {
        FilesystemControlOutcomeV1::Conflict
    }
}

fn classify_unmounted_expected_or_blank(
    request: &FilesystemControlRequestV1,
    observation: &PersistentFilesystemObservationV1,
) -> FormatAdmission {
    if observation_is_expected_unmounted(request, observation) {
        FormatAdmission::Adopt
    } else if observation.mounts.is_empty()
        && matches!(observation.filesystem, FilesystemIdentityV1::Blank)
    {
        FormatAdmission::Blank
    } else {
        FormatAdmission::Conflict
    }
}

fn observation_has_expected_uuid(
    request: &FilesystemControlRequestV1,
    observation: &PersistentFilesystemObservationV1,
) -> bool {
    matches!(
        &observation.filesystem,
        FilesystemIdentityV1::Ext4 { filesystem_uuid }
            if filesystem_uuid == &request.filesystem.filesystem_uuid
    )
}

fn observation_is_expected_unmounted(
    request: &FilesystemControlRequestV1,
    observation: &PersistentFilesystemObservationV1,
) -> bool {
    observation_has_expected_uuid(request, observation) && observation.mounts.is_empty()
}

fn observation_is_expected_mount(
    request: &FilesystemControlRequestV1,
    observation: &PersistentFilesystemObservationV1,
) -> bool {
    observation_has_expected_uuid(request, observation)
        && observation.mounts.as_slice().first().is_some_and(|mount| {
            observation.mounts.len() == 1
                && mount.mount_root.as_str() == "/"
                && mount.mount_path == request.filesystem.mount_path
                && mount.filesystem_type.as_str() == "ext4"
                && mount.access == MountAccess::ReadWrite
        })
}

fn run_with_retained_fd(
    executable: &Path,
    args: &[&str],
    retained: &RetainedDevice,
    guard: EffectGuard,
) -> Result<BoundedOutput> {
    ensure_active(guard)?;
    // SAFETY: `fcntl(F_DUPFD)` creates one new owned descriptor on success;
    // `File::from_raw_fd` takes that sole ownership exactly once below.
    let inherited_fd = unsafe { libc::fcntl(retained.file.as_raw_fd(), libc::F_DUPFD, 3) };
    if inherited_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("duplicate retained block fd");
    }
    // SAFETY: the successful F_DUPFD result is a fresh descriptor owned by
    // this File and is not wrapped anywhere else.
    let inherited = unsafe { File::from_raw_fd(inherited_fd) };
    let inherited_path = format!("/proc/self/fd/{inherited_fd}");
    let mut command = Command::new(executable);
    command
        .args(args)
        .arg(&inherited_path)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", executable.display()))?;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if ensure_active(guard).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            ensure_active(guard)?;
            anyhow::bail!("filesystem helper was cancelled");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    drop(inherited);
    anyhow::ensure!(
        output.stdout.len() <= MAX_COMMAND_OUTPUT_BYTES
            && output.stderr.len() <= MAX_COMMAND_OUTPUT_BYTES,
        "filesystem helper output exceeded its bound"
    );
    Ok(BoundedOutput {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn mounts_from_bytes(
    bytes: &[u8],
    device: &DeviceSnapshot,
) -> Result<Vec<PersistentFilesystemMountV1>> {
    let text = std::str::from_utf8(bytes).context("mountinfo is not UTF-8")?;
    let mut mounts = Vec::new();
    for line in text.lines() {
        let (left, right) = line
            .split_once(" - ")
            .context("mountinfo line lacks its field separator")?;
        anyhow::ensure!(!right.contains(" - "), "mountinfo has two field separators");
        let left: Vec<&str> = left.split_ascii_whitespace().collect();
        let right: Vec<&str> = right.split_ascii_whitespace().collect();
        anyhow::ensure!(
            left.len() >= 6 && right.len() >= 3,
            "mountinfo lacks fields"
        );
        let number = parse_device_number(left[2]).context("mountinfo device is malformed")?;
        if number != (device.device_major, device.device_minor) {
            continue;
        }
        anyhow::ensure!(
            mounts.len() < FILESYSTEM_CONTROL_MAX_MOUNTS_V1,
            "mount count exceeds filesystem control bound"
        );
        let source_path = HostPath::new(unescape_mountinfo(right[1])?)
            .context("mountinfo source path is not canonical")?;
        anyhow::ensure!(
            source_path == device.reported_path,
            "mountinfo source path disagrees with device number"
        );
        let options: Vec<&str> = left[5].split(',').collect();
        let access = match (
            options.iter().filter(|value| **value == "rw").count(),
            options.iter().filter(|value| **value == "ro").count(),
        ) {
            (1, 0) => MountAccess::ReadWrite,
            (0, 1) => MountAccess::ReadOnly,
            _ => anyhow::bail!("mountinfo access is missing or ambiguous"),
        };
        mounts.push(PersistentFilesystemMountV1 {
            device_major: number.0,
            device_minor: number.1,
            source_path,
            mount_root: HostPath::new(unescape_mountinfo(left[3])?)
                .context("mountinfo root is not canonical")?,
            mount_path: HostPath::new(unescape_mountinfo(left[4])?)
                .context("mountinfo path is not canonical")?,
            filesystem_type: Id::new(right[0].to_owned())
                .context("mountinfo filesystem type is not canonical")?,
            access,
        });
    }
    mounts.sort_by(|left, right| {
        (left.mount_path.as_str(), left.source_path.as_str())
            .cmp(&(right.mount_path.as_str(), right.source_path.as_str()))
    });
    anyhow::ensure!(
        mounts
            .windows(2)
            .all(|pair| pair[0].mount_path != pair[1].mount_path),
        "mountinfo repeats one mount path"
    );
    Ok(mounts)
}

fn read_ext4_uuid(file: &File) -> Result<Option<RandomId128>> {
    let mut superblock = [0_u8; EXT4_SUPERBLOCK_BYTES];
    file.read_exact_at(&mut superblock, EXT4_SUPERBLOCK_OFFSET)?;
    if superblock[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2] != [0x53, 0xef] {
        return Ok(None);
    }
    let uuid = hex::encode(&superblock[EXT4_UUID_OFFSET..EXT4_UUID_OFFSET + EXT4_UUID_BYTES]);
    Ok(Some(
        RandomId128::new(uuid).context("ext4 UUID is invalid")?,
    ))
}

fn parse_blkid_uuid(output: &BoundedOutput) -> Result<Option<RandomId128>> {
    if !output.status.success() {
        return Ok(None);
    }
    let value =
        std::str::from_utf8(trim_ascii(&output.stdout)).context("blkid UUID is not UTF-8")?;
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return Ok(None);
    }
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    Ok(RandomId128::new(compact))
}

fn dashed_uuid(uuid: &RandomId128) -> String {
    let value = uuid.as_str();
    format!(
        "{}-{}-{}-{}-{}",
        &value[0..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..32]
    )
}

fn virtio_block_name(slot: u16) -> Result<String> {
    let mut ordinal = usize::from(slot) + 1;
    let mut suffix = Vec::new();
    while ordinal > 0 {
        ordinal -= 1;
        suffix.push(char::from(b'a' + u8::try_from(ordinal % 26)?));
        ordinal /= 26;
    }
    suffix.reverse();
    Ok(format!("vd{}", suffix.into_iter().collect::<String>()))
}

fn read_trimmed(path: &Path) -> Result<String> {
    let value =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let trimmed = value.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(
        !trimmed.is_empty()
            && trimmed.len() <= 128
            && !trimmed.bytes().any(|byte| byte.is_ascii_whitespace()),
        "{} contains an invalid value",
        path.display()
    );
    Ok(trimmed.to_owned())
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
}

fn parse_device_number(value: &str) -> Option<(u32, u32)> {
    let (major, minor) = value.split_once(':')?;
    let major = major
        .parse::<u32>()
        .ok()
        .filter(|value| value.to_string() == major)?;
    let minor = minor
        .parse::<u32>()
        .ok()
        .filter(|value| value.to_string() == minor)?;
    Some((major, minor))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() as u64 <= maximum, "file exceeds its bound");
    Ok(bytes)
}

fn unescape_mountinfo(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let escape = bytes
            .get(index + 1..index + 4)
            .context("partial mount escape")?;
        decoded.push(match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => anyhow::bail!("noncanonical mountinfo escape"),
        });
        index += 4;
    }
    String::from_utf8(decoded).context("mountinfo path is not UTF-8")
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn ensure_active(guard: EffectGuard) -> Result<()> {
    anyhow::ensure!(
        Instant::now() < guard.deadline,
        "filesystem request deadline expired"
    );
    let Some(peer_fd) = guard.peer_fd else {
        return Ok(());
    };
    let mut byte = 0_u8;
    // SAFETY: `byte` is a live one-byte buffer, MSG_PEEK does not consume the
    // next frame, and the borrowed socket fd remains owned by the request
    // thread for the duration of this check.
    let received = unsafe {
        libc::recv(
            peer_fd,
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if received == 0 {
        anyhow::bail!("filesystem request peer cancelled the operation");
    }
    if received < 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Err(error).context("probe filesystem request peer cancellation");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        FenceEpoch, FilesystemInitialization, Generation, PersistentFilesystemBinding, RemoteHead,
    };

    use super::*;

    fn initialize_request() -> FilesystemControlRequestV1 {
        let expected_blank_head = RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        FilesystemControlRequestV1 {
            version: GUEST_HOST_CONTROL_PROTOCOL_VERSION_V1,
            challenge: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            timeout_ms: 30_000,
            operation: FilesystemControlOperationV1::FormatExt4,
            filesystem: Box::new(PersistentFilesystemBinding {
                runtime_incarnation: RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
                volume_intent_id: Id::new("intent_data").unwrap(),
                disk_id: Id::new("disk_data").unwrap(),
                volume_id: Id::new("volume_data").unwrap(),
                attachment_id: Id::new("attachment_data").unwrap(),
                attachment_epoch: FenceEpoch::new(7).unwrap(),
                size_bytes: 4_096,
                guest_device: GuestDeviceIdentity {
                    serial: Id::new("cats-data").unwrap(),
                    slot: 1,
                },
                filesystem_uuid: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
                mount_path: HostPath::new("/data").unwrap(),
                initialization: FilesystemInitialization::Initialize {
                    initialization_token: RandomId128::new("dddddddddddddddddddddddddddddddd")
                        .unwrap(),
                    expected_blank_head: expected_blank_head.clone(),
                },
            }),
            expected_head: expected_blank_head,
        }
    }

    fn observation(
        request: &FilesystemControlRequestV1,
        filesystem: FilesystemIdentityV1,
        mounts: Vec<PersistentFilesystemMountV1>,
    ) -> PersistentFilesystemObservationV1 {
        PersistentFilesystemObservationV1 {
            guest_device: request.filesystem.guest_device.clone(),
            device_path: HostPath::new("/dev/vdb").unwrap(),
            device_major: 252,
            device_minor: 16,
            size_bytes: request.filesystem.size_bytes,
            filesystem,
            mounts,
        }
    }

    fn expected_mount() -> PersistentFilesystemMountV1 {
        PersistentFilesystemMountV1 {
            device_major: 252,
            device_minor: 16,
            source_path: HostPath::new("/dev/vdb").unwrap(),
            mount_root: HostPath::new("/").unwrap(),
            mount_path: HostPath::new("/data").unwrap(),
            filesystem_type: Id::new("ext4").unwrap(),
            access: MountAccess::ReadWrite,
        }
    }

    #[test]
    fn virtio_slot_and_uuid_rendering_are_exact() {
        assert_eq!(virtio_block_name(0).unwrap(), "vda");
        assert_eq!(virtio_block_name(25).unwrap(), "vdz");
        assert_eq!(virtio_block_name(26).unwrap(), "vdaa");
        let uuid = RandomId128::new("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(dashed_uuid(&uuid), "00112233-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn mountinfo_requires_exact_source_and_reports_sorted_mounts() {
        let device = DeviceSnapshot {
            guest_device: GuestDeviceIdentity {
                serial: Id::new("cats-data").unwrap(),
                slot: 1,
            },
            name: "vdb".to_owned(),
            physical_path: PathBuf::from("/dev/vdb"),
            reported_path: HostPath::new("/dev/vdb").unwrap(),
            device_major: 252,
            device_minor: 16,
            size_bytes: 4096,
        };
        let mounts = mounts_from_bytes(
            b"31 1 252:16 / /data rw,nodev - ext4 /dev/vdb rw\n",
            &device,
        )
        .unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_path.as_str(), "/data");
        assert!(mounts_from_bytes(
            b"31 1 252:16 / /data rw,nodev - ext4 /dev/other rw\n",
            &device,
        )
        .unwrap_err()
        .to_string()
        .contains("source path"));
    }

    #[test]
    fn retained_regular_file_is_never_a_block_device() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device");
        std::fs::write(&path, [0_u8; 4096]).unwrap();
        let retained = RetainedDevice {
            file: File::open(&path).unwrap(),
            path: path.clone(),
        };
        let snapshot = DeviceSnapshot {
            guest_device: GuestDeviceIdentity {
                serial: Id::new("cats-data").unwrap(),
                slot: 1,
            },
            name: "vdb".to_owned(),
            physical_path: path,
            reported_path: HostPath::new("/dev/vdb").unwrap(),
            device_major: 7,
            device_minor: 1,
            size_bytes: 4096,
        };
        assert!(retained
            .verify(&snapshot)
            .unwrap_err()
            .to_string()
            .contains("not a block device"));
    }

    #[test]
    fn mount_target_is_created_descriptor_relative_and_replays() {
        let root = tempfile::tempdir().unwrap();
        let first = open_or_create_mount_target_beneath(
            File::open(root.path()).unwrap(),
            Path::new("/var/lib/data"),
        )
        .unwrap();
        let first_meta = first.metadata().unwrap();
        let path_meta = std::fs::symlink_metadata(root.path().join("var/lib/data")).unwrap();
        assert_eq!(
            (first_meta.dev(), first_meta.ino()),
            (path_meta.dev(), path_meta.ino())
        );

        let replay = open_or_create_mount_target_beneath(
            File::open(root.path()).unwrap(),
            Path::new("/var/lib/data"),
        )
        .unwrap();
        let replay_meta = replay.metadata().unwrap();
        assert_eq!(
            (first_meta.dev(), first_meta.ino()),
            (replay_meta.dev(), replay_meta.ino())
        );
    }

    #[test]
    fn mount_target_creation_refuses_symlink_components_and_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();

        let error = open_or_create_mount_target_beneath(
            File::open(root.path()).unwrap(),
            Path::new("/escape/data"),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("open mount target component"));
        assert!(!outside.path().join("data").exists());

        let error =
            open_or_create_mount_target_beneath(File::open(root.path()).unwrap(), Path::new("/"))
                .unwrap_err();
        assert!(error.to_string().contains("cannot be /"));
    }

    #[test]
    fn ambiguous_format_discovery_adopts_only_the_exact_unmounted_uuid() {
        let request = initialize_request();
        request.validate().unwrap();
        let expected_uuid = request.filesystem.filesystem_uuid.clone();

        assert_eq!(
            classify_unmounted_expected_or_blank(
                &request,
                &observation(&request, FilesystemIdentityV1::Blank, Vec::new())
            ),
            FormatAdmission::Blank
        );
        assert_eq!(
            classify_unmounted_expected_or_blank(
                &request,
                &observation(
                    &request,
                    FilesystemIdentityV1::Ext4 {
                        filesystem_uuid: expected_uuid.clone(),
                    },
                    Vec::new(),
                )
            ),
            FormatAdmission::Adopt,
            "a lost mkfs response must be discovered without formatting twice"
        );

        for conflicting in [
            observation(
                &request,
                FilesystemIdentityV1::Ext4 {
                    filesystem_uuid: RandomId128::new("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap(),
                },
                Vec::new(),
            ),
            observation(&request, FilesystemIdentityV1::Foreign, Vec::new()),
            observation(
                &request,
                FilesystemIdentityV1::Ext4 {
                    filesystem_uuid: expected_uuid,
                },
                vec![expected_mount()],
            ),
        ] {
            assert_eq!(
                classify_unmounted_expected_or_blank(&request, &conflicting),
                FormatAdmission::Conflict,
                "an unknown, foreign, or already-mounted disk must never be formatted"
            );
        }
    }
}
