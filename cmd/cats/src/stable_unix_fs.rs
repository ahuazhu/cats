//! Descriptor-relative stable-path primitives shared by Unix CLI authority
//! state. Callers retain every ancestor descriptor and must revalidate the
//! complete link chain immediately before an external effect.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{bail, Context as _, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

struct DirectoryLink {
    parent: File,
    entry_name: CString,
    child_identity: FileIdentity,
}

pub(crate) struct StableDirectory {
    pub(crate) directory: File,
    links: Vec<DirectoryLink>,
    identity: FileIdentity,
}

impl StableDirectory {
    pub(crate) fn open_or_create(path: &Path) -> Result<Self> {
        anyhow::ensure!(
            path.is_absolute(),
            "Runtime Node authority state requires an absolute CATS_CONFIG_DIR"
        );
        let mut directory = open_directory_nofollow(Path::new("/"))?;
        let mut links = Vec::new();
        for component in path.components() {
            use std::path::Component;
            let component = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(component) => component,
                Component::ParentDir => {
                    bail!("Runtime Node authority state path may not contain '..'")
                }
                Component::Prefix(_) => bail!("unsupported Runtime Node authority state path"),
            };
            let name = c_os_name(component)?;
            let (next, created) = open_or_create_directory_at(&directory, &name)?;
            // Sync even when another process won the mkdir race: observing an
            // entry does not prove that process completed its parent barrier.
            // Thus every selected ancestor is durable before traversal moves
            // below it, and no request can precede an ancestor barrier.
            sync_directory(&directory, "sync selected state ancestor parent")?;
            if created {
                sync_directory(&next, "sync newly-created state ancestor")?;
            }
            links.push(DirectoryLink {
                parent: directory.try_clone()?,
                entry_name: name,
                child_identity: FileIdentity::of(&next)?,
            });
            directory = next;
        }
        validate_owned_directory(&directory, false)?;
        let identity = FileIdentity::of(&directory)?;
        Ok(Self {
            directory,
            links,
            identity,
        })
    }

    pub(crate) fn assert_current(&self) -> Result<()> {
        anyhow::ensure!(
            FileIdentity::of(&self.directory)? == self.identity,
            "Runtime Node authority state parent descriptor changed identity"
        );
        for link in &self.links {
            let linked = identity_at(&link.parent, &link.entry_name, libc::AT_SYMLINK_NOFOLLOW)?;
            anyhow::ensure!(
                linked == link.child_identity,
                "Runtime Node authority state ancestor was renamed or replaced"
            );
        }
        Ok(())
    }
}

pub(crate) fn open_or_create_directory_at(parent: &File, name: &CStr) -> Result<(File, bool)> {
    match open_file_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Ok(file) => Ok((file, false)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match mkdir_at(parent, name, 0o700) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return Ok((
                        open_file_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?,
                        false,
                    ));
                }
                Err(error) => return Err(error).context("create state directory"),
            }
            let file = open_file_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            Ok((file, true))
        }
        Err(error) => Err(error).context("open Runtime Node authority state directory"),
    }
}

pub(crate) fn sync_directory(directory: &File, context: &'static str) -> Result<()> {
    #[cfg(test)]
    if directory_sync_probe_should_fail() {
        bail!("injected directory-sync failure: {context}");
    }
    directory.sync_all().context(context)
}

#[cfg(test)]
thread_local! {
    static DIRECTORY_SYNC_PROBE: std::cell::Cell<(Option<usize>, usize)> =
        const { std::cell::Cell::new((None, 0)) };
}

#[cfg(test)]
fn directory_sync_probe_should_fail() -> bool {
    DIRECTORY_SYNC_PROBE.with(|probe| {
        let (fail_at, count) = probe.get();
        probe.set((fail_at, count + 1));
        fail_at == Some(count)
    })
}

#[cfg(test)]
pub(crate) struct DirectorySyncProbeGuard;

#[cfg(test)]
impl DirectorySyncProbeGuard {
    pub(crate) fn start(fail_at: Option<usize>) -> Self {
        DIRECTORY_SYNC_PROBE.with(|probe| probe.set((fail_at, 0)));
        Self
    }

    pub(crate) fn count(&self) -> usize {
        DIRECTORY_SYNC_PROBE.with(|probe| probe.get().1)
    }
}

#[cfg(test)]
impl Drop for DirectorySyncProbeGuard {
    fn drop(&mut self) {
        DIRECTORY_SYNC_PROBE.with(|probe| probe.set((None, 0)));
    }
}

pub(crate) fn open_directory_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .with_context(|| format!("open directory {}", path.display()))
}

pub(crate) fn validate_owned_directory(directory: &File, private: bool) -> Result<()> {
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "state entry is not a directory"
    );
    anyhow::ensure!(
        metadata.uid() == effective_uid(),
        "state directory has a different owner"
    );
    if private {
        anyhow::ensure!(
            metadata.mode() & 0o7777 == 0o700,
            "state directory must have exact mode 0700"
        );
    } else {
        anyhow::ensure!(
            metadata.mode() & 0o022 == 0,
            "state directory is writable by another user"
        );
    }
    Ok(())
}

pub(crate) fn c_os_name(value: &OsStr) -> Result<CString> {
    anyhow::ensure!(
        !value.is_empty() && !value.as_bytes().contains(&b'/'),
        "state entry is not a single path component"
    );
    CString::new(value.as_bytes()).context("state entry contains NUL")
}

pub(crate) fn open_file_at(
    directory: &File,
    name: &CStr,
    flags: i32,
    mode: libc::c_uint,
) -> io::Result<File> {
    // SAFETY: `name` is a live NUL-terminated component and the returned file
    // descriptor is uniquely transferred into `File` on success.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `descriptor` is a fresh owned descriptor from `openat`.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

pub(crate) fn mkdir_at(directory: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `name` is a live NUL-terminated component resolved against the
    // held directory descriptor.
    let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), mode) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn unlink_at(directory: &File, name: &CStr, flags: i32) -> io::Result<()> {
    // SAFETY: `name` is a live NUL-terminated component resolved against the
    // held directory descriptor; no Rust-owned memory is exposed.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn rename_noreplace_at(
    directory: &File,
    source: &CStr,
    destination: &CStr,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: both names are live NUL-terminated path components beneath
        // the retained directory descriptor. RENAME_NOREPLACE is atomic.
        let result = unsafe {
            libc::renameat2(
                directory.as_raw_fd(),
                source.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: same invariant as the Linux branch; RENAME_EXCL gives the
        // required no-replace atomic rename on Apple platforms.
        let result = unsafe {
            libc::renameatx_np(
                directory.as_raw_fd(),
                source.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (directory, source, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace rename is unsupported on this Unix platform",
        ))
    }
}

pub(crate) fn identity_at(directory: &File, name: &CStr, flags: i32) -> io::Result<FileIdentity> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: metadata points to writable storage for one `stat`, and `name`
    // is a live NUL-terminated component beneath the held directory.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            flags,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstatat` initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    let file_type = metadata.st_mode & libc::S_IFMT;
    if file_type != libc::S_IFREG && file_type != libc::S_IFDIR {
        return Err(io::Error::other(
            "state authority entry has an unsupported file type",
        ));
    }
    #[cfg(target_os = "macos")]
    let device = u64::try_from(metadata.st_dev).map_err(|_| io::Error::other("invalid device"))?;
    #[cfg(not(target_os = "macos"))]
    let device = metadata.st_dev;
    Ok(FileIdentity {
        device,
        inode: metadata.st_ino,
    })
}

pub(crate) fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no pointers and only reads the calling process's
    // effective credential; it cannot violate Rust memory invariants.
    unsafe { libc::geteuid() }
}

pub(crate) fn effective_gid() -> u32 {
    // SAFETY: `getegid` has the same no-pointer credential-read contract as
    // `geteuid` above.
    unsafe { libc::getegid() }
}
