//! Descriptor-retained authority for the files consumed by `StartRuntime`.
//!
//! A checkpoint records paths, lengths and digests, but a pathname is not a
//! launch permit.  This reader retains every traversed directory and the leaf
//! descriptor, and can prove immediately before and after a launch that the
//! canonical pathname still resolves to the same immutable bytes.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result};
use cats_api::runtime_reconciliation::{
    AsciiText, HostPath, RuntimeLaunchArtifact, Sha256Digest, VmmBootProvenance, WireU64,
};
use sha2::{Digest as _, Sha256};

const VMM_LAUNCH_ARTIFACT_MAX_BYTES: u64 = 512 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct VmmLaunchArtifactPaths {
    pub(crate) launcher_executable: PathBuf,
    pub(crate) vmm_executable: PathBuf,
    pub(crate) kernel: PathBuf,
    pub(crate) initramfs: Option<PathBuf>,
    pub(crate) kernel_cmdline: String,
}

#[derive(Debug)]
pub(crate) struct RetainedVmmLaunchArtifacts {
    launcher_executable: PinnedArtifact,
    vmm_executable: PinnedArtifact,
    kernel: PinnedArtifact,
    initramfs: Option<PinnedArtifact>,
    kernel_cmdline: AsciiText,
}

/// Borrowed, already-validated descriptors transferred into the fixed VMM
/// launcher through systemd's `OpenFile=` contract.  Fields stay private so a
/// caller cannot substitute a pathname or unrelated file after projecting the
/// checkpoint.
pub(crate) struct VmmLaunchArtifactDescriptors<'a> {
    vmm_executable: &'a File,
    kernel: &'a File,
    initramfs: Option<&'a File>,
}

impl VmmLaunchArtifactDescriptors<'_> {
    pub(crate) fn vmm_executable(&self) -> &File {
        self.vmm_executable
    }

    pub(crate) fn kernel(&self) -> &File {
        self.kernel
    }

    pub(crate) fn initramfs(&self) -> Option<&File> {
        self.initramfs
    }
}

impl RetainedVmmLaunchArtifacts {
    pub(crate) fn open(paths: &VmmLaunchArtifactPaths) -> Result<Self> {
        Self::open_from(Path::new("/"), paths, InstalledOwner::Root)
    }

    fn open_from(
        canonical_root: &Path,
        paths: &VmmLaunchArtifactPaths,
        owner: InstalledOwner,
    ) -> Result<Self> {
        let launcher_executable = PinnedArtifact::open(
            canonical_root,
            &paths.launcher_executable,
            owner,
            InstalledFileMode::Executable,
        )
        .context("open installed VMM launcher")?;
        let vmm_executable = PinnedArtifact::open(
            canonical_root,
            &paths.vmm_executable,
            owner,
            InstalledFileMode::Executable,
        )
        .context("open installed VMM executable")?;
        let kernel = PinnedArtifact::open(
            canonical_root,
            &paths.kernel,
            owner,
            InstalledFileMode::BootMember,
        )
        .context("open installed Guest kernel")?;
        let initramfs = paths
            .initramfs
            .as_ref()
            .map(|path| {
                PinnedArtifact::open(canonical_root, path, owner, InstalledFileMode::BootMember)
                    .context("open installed Guest initramfs")
            })
            .transpose()?;
        let kernel_cmdline = AsciiText::new(paths.kernel_cmdline.clone())
            .context("VMM kernel command line is not canonical printable ASCII")?;
        let retained = Self {
            launcher_executable,
            vmm_executable,
            kernel,
            initramfs,
            kernel_cmdline,
        };
        // The members are opened sequentially. Close a replacement window on
        // an earlier member before exporting one cross-file projection; the
        // caller will repeat this proof at every CAS/launch boundary.
        retained
            .assert_current()
            .context("VMM launch artifact set changed while it was opened")?;
        Ok(retained)
    }

    pub(crate) fn launcher_executable(&self) -> &RuntimeLaunchArtifact {
        &self.launcher_executable.projection
    }

    pub(crate) fn boot(&self) -> VmmBootProvenance {
        VmmBootProvenance {
            vmm_executable: self.vmm_executable.projection.clone(),
            kernel: self.kernel.projection.clone(),
            initramfs: self
                .initramfs
                .as_ref()
                .map(|artifact| artifact.projection.clone()),
            kernel_cmdline: self.kernel_cmdline.clone(),
        }
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        self.launcher_executable
            .assert_current()
            .context("installed VMM launcher changed")?;
        self.vmm_executable
            .assert_current()
            .context("installed VMM executable changed")?;
        self.kernel
            .assert_current()
            .context("installed Guest kernel changed")?;
        if let Some(initramfs) = &self.initramfs {
            initramfs
                .assert_current()
                .context("installed Guest initramfs changed")?;
        }
        Ok(())
    }

    pub(crate) fn descriptors(&self) -> VmmLaunchArtifactDescriptors<'_> {
        VmmLaunchArtifactDescriptors {
            vmm_executable: &self.vmm_executable.descriptor,
            kernel: &self.kernel.descriptor,
            initramfs: self.initramfs.as_ref().map(|artifact| &artifact.descriptor),
        }
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        canonical_root: &Path,
        paths: &VmmLaunchArtifactPaths,
    ) -> Result<Self> {
        // SAFETY: these libc accessors have no pointer arguments and only read
        // the effective credentials of the current test process.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: same invariant as `geteuid` above.
        let gid = unsafe { libc::getegid() };
        Self::open_from(canonical_root, paths, InstalledOwner::Exact { uid, gid })
    }
}

#[derive(Debug, Clone, Copy)]
enum InstalledOwner {
    Root,
    #[cfg(test)]
    Exact {
        uid: u32,
        gid: u32,
    },
}

impl InstalledOwner {
    fn accepts(self, uid: u32, gid: u32) -> bool {
        match self {
            Self::Root => uid == 0 && gid == 0,
            #[cfg(test)]
            Self::Exact {
                uid: expected_uid,
                gid: expected_gid,
            } => uid == expected_uid && gid == expected_gid,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum InstalledFileMode {
    Executable,
    BootMember,
}

impl InstalledFileMode {
    fn permission_bits(self) -> u32 {
        match self {
            Self::Executable => 0o755,
            Self::BootMember => 0o644,
        }
    }
}

#[derive(Debug)]
struct PinnedArtifact {
    canonical_root: PathBuf,
    logical_path: PathBuf,
    owner: InstalledOwner,
    mode: InstalledFileMode,
    directories: Vec<PinnedDirectory>,
    descriptor: File,
    metadata: StableMetadata,
    projection: RuntimeLaunchArtifact,
}

impl PinnedArtifact {
    fn open(
        canonical_root: &Path,
        logical_path: &Path,
        owner: InstalledOwner,
        mode: InstalledFileMode,
    ) -> Result<Self> {
        let host_path = host_path(logical_path)?;
        let (directories, descriptor) = open_artifact(canonical_root, logical_path, owner)?;
        let (metadata, content_sha256) = hash_stable_file(&descriptor, logical_path, owner, mode)?;
        let length =
            WireU64::new(metadata.length).context("VMM artifact length exceeds wire range")?;
        Ok(Self {
            canonical_root: canonical_root.to_path_buf(),
            logical_path: logical_path.to_path_buf(),
            owner,
            mode,
            directories,
            descriptor,
            metadata,
            projection: RuntimeLaunchArtifact {
                path: host_path,
                length,
                content_sha256,
            },
        })
    }

    fn assert_current(&self) -> Result<()> {
        self.assert_current_with_phase(|| {})
    }

    fn assert_current_with_phase(&self, after_fresh_hash: impl FnOnce()) -> Result<()> {
        for directory in &self.directories {
            let metadata = directory
                .descriptor
                .metadata()
                .context("reinspect retained VMM artifact ancestor")?;
            ensure_safe_directory(&metadata, self.owner)?;
            anyhow::ensure!(
                DirectoryMetadata::from(&metadata) == directory.metadata,
                "retained VMM artifact ancestor changed"
            );
        }
        let (retained_metadata, retained_digest) =
            hash_stable_file(&self.descriptor, &self.logical_path, self.owner, self.mode)?;
        anyhow::ensure!(
            retained_metadata == self.metadata && retained_digest == self.projection.content_sha256,
            "retained VMM artifact changed"
        );
        let (directories, descriptor) =
            open_artifact(&self.canonical_root, &self.logical_path, self.owner)?;
        anyhow::ensure!(
            directories == self.directories,
            "VMM artifact ancestor identity changed"
        );
        let (fresh_metadata, fresh_digest) =
            hash_stable_file(&descriptor, &self.logical_path, self.owner, self.mode)?;
        anyhow::ensure!(
            fresh_metadata == self.metadata && fresh_digest == self.projection.content_sha256,
            "VMM artifact pathname changed"
        );
        after_fresh_hash();
        let (final_directories, final_descriptor) =
            open_artifact(&self.canonical_root, &self.logical_path, self.owner)?;
        anyhow::ensure!(
            final_directories == self.directories,
            "VMM artifact ancestor changed after its fresh hash"
        );
        let final_metadata = final_descriptor
            .metadata()
            .context("reinspect VMM artifact pathname after its fresh hash")?;
        ensure_safe_file(&final_metadata, self.owner, self.mode)?;
        anyhow::ensure!(
            StableMetadata::from(&final_metadata) == self.metadata,
            "VMM artifact leaf changed after its fresh hash"
        );
        Ok(())
    }
}

#[derive(Debug)]
struct PinnedDirectory {
    name: Option<CString>,
    descriptor: File,
    metadata: DirectoryMetadata,
}

impl PartialEq for PinnedDirectory {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.metadata == other.metadata
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryMetadata {
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

impl DirectoryMetadata {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StableMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl StableMetadata {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn host_path(path: &Path) -> Result<HostPath> {
    let value = path
        .to_str()
        .context("VMM artifact path is not UTF-8")?
        .to_owned();
    HostPath::new(value).context("VMM artifact path is not canonical absolute HostPath")
}

fn path_components(path: &Path) -> Result<(Vec<CString>, CString)> {
    anyhow::ensure!(path.is_absolute(), "VMM artifact path must be absolute");
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => components.push(
                CString::new(component.as_bytes())
                    .context("VMM artifact path contains an embedded NUL")?,
            ),
            _ => anyhow::bail!("VMM artifact path is not canonical"),
        }
    }
    let basename = components
        .pop()
        .context("VMM artifact path does not name a file")?;
    Ok((components, basename))
}

fn open_artifact(
    canonical_root: &Path,
    logical_path: &Path,
    owner: InstalledOwner,
) -> Result<(Vec<PinnedDirectory>, File)> {
    let (components, basename) = path_components(logical_path)?;
    let root = open_directory_path(canonical_root)?;
    let root_metadata = root.metadata().context("inspect VMM artifact root")?;
    ensure_safe_directory(&root_metadata, owner)?;
    let mut directories = vec![PinnedDirectory {
        name: None,
        descriptor: root,
        metadata: DirectoryMetadata::from(&root_metadata),
    }];
    for component in components {
        let parent = &directories
            .last()
            .expect("the VMM artifact traversal always retains its root")
            .descriptor;
        let descriptor = open_directory_at(parent, &component)?;
        let metadata = descriptor
            .metadata()
            .context("inspect VMM artifact ancestor")?;
        ensure_safe_directory(&metadata, owner)?;
        directories.push(PinnedDirectory {
            name: Some(component),
            descriptor,
            metadata: DirectoryMetadata::from(&metadata),
        });
    }
    let descriptor = open_file_at(
        &directories
            .last()
            .expect("the VMM artifact traversal always retains its parent")
            .descriptor,
        &basename,
    )?;
    Ok((directories, descriptor))
}

fn ensure_safe_directory(metadata: &std::fs::Metadata, owner: InstalledOwner) -> Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && owner.accepts(metadata.uid(), metadata.gid())
            && metadata.mode() & 0o022 == 0,
        "VMM artifact ancestor is not an exact safe directory"
    );
    Ok(())
}

fn hash_stable_file(
    descriptor: &File,
    display: &Path,
    owner: InstalledOwner,
    mode: InstalledFileMode,
) -> Result<(StableMetadata, Sha256Digest)> {
    let before = descriptor
        .metadata()
        .with_context(|| format!("inspect VMM artifact {}", display.display()))?;
    ensure_safe_file(&before, owner, mode)?;
    anyhow::ensure!(
        before.len() > 0 && before.len() <= VMM_LAUNCH_ARTIFACT_MAX_BYTES,
        "VMM artifact length is outside the closed bound"
    );
    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    while offset < before.len() {
        let remaining = before.len() - offset;
        let requested = usize::try_from(remaining.min(HASH_BUFFER_BYTES as u64))
            .context("VMM artifact read length exceeds usize")?;
        let count = descriptor
            .read_at(&mut buffer[..requested], offset)
            .with_context(|| format!("read VMM artifact {}", display.display()))?;
        anyhow::ensure!(count > 0, "VMM artifact ended before its recorded length");
        digest.update(&buffer[..count]);
        offset = offset
            .checked_add(u64::try_from(count).context("VMM artifact read count exceeds u64")?)
            .context("VMM artifact read offset overflow")?;
    }
    let mut extra = [0_u8; 1];
    anyhow::ensure!(
        descriptor
            .read_at(&mut extra, offset)
            .with_context(|| format!("recheck VMM artifact {} length", display.display()))?
            == 0,
        "VMM artifact grew while it was read"
    );
    let after = descriptor
        .metadata()
        .with_context(|| format!("reinspect VMM artifact {}", display.display()))?;
    ensure_safe_file(&after, owner, mode)?;
    let before = StableMetadata::from(&before);
    let after = StableMetadata::from(&after);
    anyhow::ensure!(
        before == after && offset == after.length,
        "VMM artifact changed while it was read"
    );
    Ok((after, Sha256Digest::from_bytes(digest.finalize().into())))
}

fn ensure_safe_file(
    metadata: &std::fs::Metadata,
    owner: InstalledOwner,
    mode: InstalledFileMode,
) -> Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && owner.accepts(metadata.uid(), metadata.gid())
            && metadata.mode() & 0o7777 == mode.permission_bits(),
        "VMM artifact is not an exact installed file"
    );
    Ok(())
}

fn open_directory_path(path: &Path) -> Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .context("VMM artifact root contains an embedded NUL")?;
    // SAFETY: `path` is NUL-terminated and the returned descriptor is
    // immediately transferred to an owned `File`.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    anyhow::ensure!(
        descriptor >= 0,
        "open VMM artifact root: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `open` returned one new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_directory_at(parent: &File, name: &CStr) -> Result<File> {
    // SAFETY: `parent` remains open for the call, `name` is NUL-terminated,
    // and a successful descriptor is immediately transferred to `File`.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    anyhow::ensure!(
        descriptor >= 0,
        "open VMM artifact ancestor: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `openat` returned one new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_file_at(parent: &File, name: &CStr) -> Result<File> {
    // SAFETY: `parent` remains open for the call, `name` is NUL-terminated,
    // and a successful descriptor is immediately transferred to `File`.
    // O_NONBLOCK prevents a FIFO from hanging before the regular-file check.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    anyhow::ensure!(
        descriptor >= 0,
        "open VMM artifact: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `openat` returned one new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{symlink, OpenOptionsExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        root: TempDir,
        paths: VmmLaunchArtifactPaths,
    }

    impl Fixture {
        fn new(with_initramfs: bool) -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            for directory in [
                "usr",
                "usr/libexec",
                "usr/bin",
                "opt",
                "opt/cats",
                "opt/cats/guest",
            ] {
                let path = root.path().join(directory);
                fs::create_dir_all(&path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            write_file(
                root.path().join("usr/libexec/cats-vmm-launcher"),
                0o755,
                b"launcher-v1",
            );
            write_file(
                root.path().join("usr/bin/cloud-hypervisor"),
                0o755,
                b"vmm-v1",
            );
            write_file(
                root.path().join("opt/cats/guest/vmlinuz"),
                0o644,
                b"kernel-v1",
            );
            let initramfs = with_initramfs.then(|| {
                write_file(
                    root.path().join("opt/cats/guest/initramfs.img"),
                    0o644,
                    b"initramfs-v1",
                );
                PathBuf::from("/opt/cats/guest/initramfs.img")
            });
            Self {
                root,
                paths: VmmLaunchArtifactPaths {
                    launcher_executable: "/usr/libexec/cats-vmm-launcher".into(),
                    vmm_executable: "/usr/bin/cloud-hypervisor".into(),
                    kernel: "/opt/cats/guest/vmlinuz".into(),
                    initramfs,
                    kernel_cmdline: "console=ttyS0 root=/dev/vda rw".to_owned(),
                },
            }
        }

        fn physical(&self, logical: &str) -> PathBuf {
            self.root.path().join(logical.trim_start_matches('/'))
        }
    }

    fn write_file(path: PathBuf, mode: u32, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn exact_files_project_and_revalidate_from_retained_descriptors() {
        let fixture = Fixture::new(true);
        let retained =
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).unwrap();
        assert_eq!(
            retained.launcher_executable().path.as_str(),
            "/usr/libexec/cats-vmm-launcher"
        );
        assert_eq!(retained.launcher_executable().length.get(), 11);
        assert_eq!(
            retained.launcher_executable().content_sha256.as_str(),
            "sha256:81e019fd3486773c7b20aa31ec2fded1ed810f766082fdb49762ef0cb99e28a3"
        );
        let boot = retained.boot();
        assert_eq!(boot.vmm_executable.length.get(), 6);
        assert_eq!(
            boot.vmm_executable.content_sha256.as_str(),
            "sha256:82eb3564bffd38b9da51108e09f502d2e17bb13f7873b37d30ec639e73245c77"
        );
        assert_eq!(boot.kernel.length.get(), 9);
        assert_eq!(
            boot.kernel.content_sha256.as_str(),
            "sha256:e535284b6f32cd691e98d2491929fa8280e183d7540f0983feacaec8ce6da61f"
        );
        assert_eq!(boot.initramfs.as_ref().unwrap().length.get(), 12);
        assert_eq!(
            boot.initramfs.as_ref().unwrap().content_sha256.as_str(),
            "sha256:3b0971bdda0c10177ad427003b0c42ded9f761a0c2dff547cb808a40d2246507"
        );
        assert_eq!(
            boot.kernel_cmdline.as_str(),
            "console=ttyS0 root=/dev/vda rw"
        );
        retained.assert_current().unwrap();
    }

    #[test]
    fn optional_initramfs_is_an_exact_closed_choice() {
        let fixture = Fixture::new(false);
        let retained =
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).unwrap();
        assert!(retained.boot().initramfs.is_none());
        retained.assert_current().unwrap();
    }

    #[test]
    fn leaf_and_ancestor_replacements_are_rejected_after_open() {
        let fixture = Fixture::new(true);
        let retained =
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).unwrap();
        let kernel = fixture.physical("/opt/cats/guest/vmlinuz");
        let old_kernel = fixture.physical("/opt/cats/guest/vmlinuz.old");
        fs::rename(&kernel, &old_kernel).unwrap();
        write_file(kernel, 0o644, b"kernel-v1");
        assert!(retained.assert_current().is_err());

        let fixture = Fixture::new(true);
        let retained =
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).unwrap();
        let guest = fixture.physical("/opt/cats/guest");
        let old_guest = fixture.physical("/opt/cats/guest.old");
        fs::rename(&guest, &old_guest).unwrap();
        fs::create_dir(&guest).unwrap();
        fs::set_permissions(&guest, fs::Permissions::from_mode(0o755)).unwrap();
        write_file(guest.join("vmlinuz"), 0o644, b"kernel-v1");
        write_file(guest.join("initramfs.img"), 0o644, b"initramfs-v1");
        assert!(retained.assert_current().is_err());
    }

    #[test]
    fn moving_an_ancestor_away_and_back_is_still_an_aba_conflict() {
        let fixture = Fixture::new(true);
        let retained =
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).unwrap();
        let guest = fixture.physical("/opt/cats/guest");
        let moved = fixture.physical("/opt/cats/guest.moved");
        fs::rename(&guest, &moved).unwrap();
        fs::set_permissions(&moved, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&moved, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&moved, &guest).unwrap();
        assert!(retained.assert_current().is_err());
    }

    #[test]
    fn replacement_after_fresh_hash_is_rejected_by_the_final_reopen() {
        let fixture = Fixture::new(false);
        let retained =
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).unwrap();
        let kernel = fixture.physical("/opt/cats/guest/vmlinuz");
        let old_kernel = fixture.physical("/opt/cats/guest/vmlinuz.old");
        assert!(retained
            .kernel
            .assert_current_with_phase(|| {
                fs::rename(&kernel, &old_kernel).unwrap();
                write_file(kernel, 0o644, b"kernel-v1");
            })
            .is_err());
    }

    #[test]
    fn symlink_hardlink_mode_empty_and_oversize_are_rejected() {
        let fixture = Fixture::new(false);
        let kernel = fixture.physical("/opt/cats/guest/vmlinuz");
        fs::remove_file(&kernel).unwrap();
        symlink("/etc/passwd", &kernel).unwrap();
        assert!(
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).is_err()
        );

        let fixture = Fixture::new(false);
        let kernel = fixture.physical("/opt/cats/guest/vmlinuz");
        fs::hard_link(&kernel, fixture.physical("/opt/cats/guest/kernel-copy")).unwrap();
        assert!(
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).is_err()
        );

        let fixture = Fixture::new(false);
        fs::set_permissions(
            fixture.physical("/usr/bin/cloud-hypervisor"),
            fs::Permissions::from_mode(0o775),
        )
        .unwrap();
        assert!(
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).is_err()
        );

        let fixture = Fixture::new(false);
        let kernel = fixture.physical("/opt/cats/guest/vmlinuz");
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(kernel)
            .unwrap();
        assert!(
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).is_err()
        );

        let fixture = Fixture::new(false);
        OpenOptions::new()
            .write(true)
            .open(fixture.physical("/opt/cats/guest/vmlinuz"))
            .unwrap()
            .set_len(VMM_LAUNCH_ARTIFACT_MAX_BYTES + 1)
            .unwrap();
        assert!(
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).is_err()
        );
    }

    #[test]
    fn mutation_of_the_retained_inode_is_rejected() {
        let fixture = Fixture::new(false);
        let retained =
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).unwrap();
        let kernel = fixture.physical("/opt/cats/guest/vmlinuz");
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(kernel)
            .unwrap();
        file.write_all(b"kernel-v2").unwrap();
        file.sync_all().unwrap();
        assert!(retained.assert_current().is_err());
    }

    #[test]
    fn noncanonical_paths_and_cmdlines_are_rejected() {
        let mut fixture = Fixture::new(false);
        fixture.paths.kernel = "/opt/cats/guest/../guest/vmlinuz".into();
        assert!(
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).is_err()
        );

        let mut fixture = Fixture::new(false);
        fixture.paths.kernel_cmdline = "console=ttyS0\nroot=/dev/vda".to_owned();
        assert!(
            RetainedVmmLaunchArtifacts::open_for_test(fixture.root.path(), &fixture.paths).is_err()
        );
    }
}
