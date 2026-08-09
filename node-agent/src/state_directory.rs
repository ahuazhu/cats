//! Process-lifetime ownership of the identity-selected Node state directory.

use std::fs::{File, OpenOptions};
use std::ops::Deref;
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use anyhow::Context as _;

/// Reserved by the production Node before any runtime worker is constructed.
/// Child processes receive this exact descriptor number without `CLOEXEC`, so
/// `/proc/self/fd/198/...` names the retained directory in the Node, blockd,
/// Guest-agent stand-in, and Cloud Hypervisor processes alike.
#[cfg(target_os = "linux")]
const PRODUCTION_STATE_DIRECTORY_FD: RawFd = 198;

/// An identity-selected state directory whose open descriptor outlives every
/// runtime path and every child process that may consume one.
#[derive(Clone)]
pub struct StateDirectory {
    path: PathBuf,
    inherited_directory: Option<Arc<File>>,
}

impl std::fmt::Debug for StateDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateDirectory")
            .field("path", &self.path)
            .field(
                "inherited_fd",
                &self
                    .inherited_directory
                    .as_ref()
                    .map(|directory| directory.as_raw_fd()),
            )
            .finish()
    }
}

impl StateDirectory {
    /// Test/development boundary for configurations that do not originate in
    /// the installed NodeIdentity flow and do not spawn production children.
    pub fn unanchored(path: PathBuf) -> Self {
        Self {
            path,
            inherited_directory: None,
        }
    }

    /// Reserves the one production descriptor and returns its stable procfs
    /// path. Failing because the descriptor is already occupied is safer than
    /// silently closing an unrelated process resource with `dup2`.
    pub(crate) fn from_installed_directory(
        directory: &File,
        _canonical_path: &Path,
    ) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let descriptor = duplicate_to_reserved_fd(directory, PRODUCTION_STATE_DIRECTORY_FD)?;
            Ok(Self {
                path: PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd())),
                inherited_directory: Some(Arc::new(descriptor)),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {
                path: _canonical_path.to_path_buf(),
                inherited_directory: Some(Arc::new(directory.try_clone()?)),
            })
        }
    }

    /// Linux regression boundary: allocate a unique inheritable descriptor so
    /// parallel tests cannot contend for the production-reserved number.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_test_directory(
        directory: &File,
        _canonical_path: &Path,
    ) -> anyhow::Result<Self> {
        let descriptor = duplicate_inheritable(directory, PRODUCTION_STATE_DIRECTORY_FD + 1)?;
        Ok(Self {
            path: PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd())),
            inherited_directory: Some(Arc::new(descriptor)),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn from_test_directory(
        directory: &File,
        canonical_path: &Path,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            path: canonical_path.to_path_buf(),
            inherited_directory: Some(Arc::new(directory.try_clone()?)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Clones the already-retained identity-selected directory. Explicit
    /// development configurations still open their path with `O_NOFOLLOW` so
    /// a sibling subsystem can use the same descriptor-relative discipline.
    pub(crate) fn try_clone_directory(&self) -> std::io::Result<File> {
        match &self.inherited_directory {
            Some(directory) => directory.try_clone(),
            None => {
                let mut options = OpenOptions::new();
                options.read(true).custom_flags(
                    libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                );
                options.open(&self.path)
            }
        }
    }

    /// Revalidates the contract immediately before runtime construction. The
    /// descriptor is deliberately not `CLOEXEC`; Rust `Command` therefore
    /// preserves the same number for all blockd, Guest, and VMM children.
    pub fn ensure_child_inheritance(&self) -> anyhow::Result<()> {
        let Some(directory) = &self.inherited_directory else {
            return Ok(());
        };
        // SAFETY: `directory` owns a live descriptor and `F_GETFD` has no
        // pointer argument or retained memory.
        let flags = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFD) };
        anyhow::ensure!(flags >= 0, "inspect inherited Node state descriptor");
        anyhow::ensure!(
            flags & libc::FD_CLOEXEC == 0,
            "Node state descriptor must remain open across child exec"
        );
        Ok(())
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn inherited_fd(&self) -> Option<RawFd> {
        self.inherited_directory
            .as_ref()
            .map(|directory| directory.as_raw_fd())
    }
}

impl Deref for StateDirectory {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

impl AsRef<Path> for StateDirectory {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl From<PathBuf> for StateDirectory {
    fn from(path: PathBuf) -> Self {
        Self::unanchored(path)
    }
}

#[cfg(target_os = "linux")]
fn duplicate_to_reserved_fd(directory: &File, reserved: RawFd) -> anyhow::Result<File> {
    // SAFETY: `F_GETFD` only examines the numeric descriptor.
    let occupied = unsafe { libc::fcntl(reserved, libc::F_GETFD) };
    if occupied >= 0 {
        anyhow::bail!("reserved Node state descriptor {reserved} is already occupied");
    }
    let error = std::io::Error::last_os_error();
    anyhow::ensure!(
        error.raw_os_error() == Some(libc::EBADF),
        "cannot inspect reserved Node state descriptor {reserved}: {error}"
    );
    // SAFETY: both descriptor numbers are valid inputs; `reserved` was just
    // proven unused, and a successful descriptor is transferred to `File`.
    let duplicated = unsafe { libc::dup3(directory.as_raw_fd(), reserved, 0) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error())
            .context("reserve inherited Node state descriptor");
    }
    // SAFETY: `dup3` returned a new descriptor owned by this call.
    Ok(unsafe { File::from_raw_fd(duplicated) })
}

#[cfg(target_os = "linux")]
fn duplicate_inheritable(directory: &File, minimum: RawFd) -> anyhow::Result<File> {
    // `F_DUPFD` intentionally clears `FD_CLOEXEC`; `F_DUPFD_CLOEXEC` would
    // break every `/proc/self/fd/<fd>` argument after child exec.
    // SAFETY: the source descriptor is live and the integer minimum is valid.
    let duplicated = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD, minimum) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error())
            .context("duplicate inherited Node state descriptor");
    }
    // SAFETY: `fcntl(F_DUPFD)` returned a new descriptor owned by this call.
    Ok(unsafe { File::from_raw_fd(duplicated) })
}
