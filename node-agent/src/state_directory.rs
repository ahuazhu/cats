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
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `directory` owns a live descriptor and `F_GETFD` has no
            // pointer argument or retained memory.
            let flags = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFD) };
            anyhow::ensure!(flags >= 0, "inspect inherited Node state descriptor");
            anyhow::ensure!(
                flags & libc::FD_CLOEXEC == 0,
                "Node state descriptor must remain open across child exec"
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = directory;
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
    // `F_DUPFD` atomically claims the lowest unused descriptor at or above the
    // requested number and deliberately clears `FD_CLOEXEC`. Accepting only
    // the exact number fails closed when another thread owns the reservation.
    // SAFETY: the source descriptor is live, and `fcntl(F_DUPFD)` neither
    // consumes it nor retains any Rust memory.
    let duplicated = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD, reserved) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error())
            .context("reserve inherited Node state descriptor");
    }
    // SAFETY: successful `fcntl(F_DUPFD)` created one new descriptor owned
    // solely by this call; wrapping it transfers that ownership to `File`.
    let duplicated = unsafe { File::from_raw_fd(duplicated) };
    if duplicated.as_raw_fd() != reserved {
        let allocated = duplicated.as_raw_fd();
        drop(duplicated);
        anyhow::bail!(
            "reserved Node state descriptor {reserved} is already occupied (lowest available descriptor was {allocated})"
        );
    }
    Ok(duplicated)
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::{Arc, Barrier, Mutex};

    use super::{duplicate_to_reserved_fd, PRODUCTION_STATE_DIRECTORY_FD};

    static RESERVED_DESCRIPTOR_TEST: Mutex<()> = Mutex::new(());

    fn same_file(left: &std::fs::File, right: &std::fs::File) -> bool {
        let left = left.metadata().expect("read left descriptor metadata");
        let right = right.metadata().expect("read right descriptor metadata");
        left.dev() == right.dev() && left.ino() == right.ino()
    }

    #[test]
    fn occupied_production_descriptor_fails_without_closing_or_replacing_sentinel() {
        let _serial = RESERVED_DESCRIPTOR_TEST
            .lock()
            .expect("serialize reserved descriptor tests");
        let temp = tempfile::tempdir().expect("create descriptor fixture");
        let sentinel_source = std::fs::File::open(temp.path()).expect("open sentinel source");
        let sentinel = duplicate_to_reserved_fd(&sentinel_source, PRODUCTION_STATE_DIRECTORY_FD)
            .expect("reserve sentinel descriptor");
        assert_eq!(sentinel.as_raw_fd(), PRODUCTION_STATE_DIRECTORY_FD);

        let candidate_path = temp.path().join("candidate");
        std::fs::create_dir(&candidate_path).expect("create candidate directory");
        let candidate = std::fs::File::open(candidate_path).expect("open candidate source");
        let error = duplicate_to_reserved_fd(&candidate, PRODUCTION_STATE_DIRECTORY_FD)
            .expect_err("occupied production descriptor must fail closed");

        assert!(error.to_string().contains("already occupied"));
        assert_eq!(sentinel.as_raw_fd(), PRODUCTION_STATE_DIRECTORY_FD);
        assert!(same_file(&sentinel, &sentinel_source));
        // SAFETY: the sentinel owns this live descriptor; `F_GETFD` only
        // inspects descriptor flags and retains no memory.
        let flags = unsafe { libc::fcntl(PRODUCTION_STATE_DIRECTORY_FD, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn concurrent_production_reservations_cannot_steal_or_replace_the_winner() {
        let _serial = RESERVED_DESCRIPTOR_TEST
            .lock()
            .expect("serialize reserved descriptor tests");
        let temp = tempfile::tempdir().expect("create descriptor fixture");
        let first_path = temp.path().join("first");
        let second_path = temp.path().join("second");
        std::fs::create_dir(&first_path).expect("create first directory");
        std::fs::create_dir(&second_path).expect("create second directory");
        let first = std::fs::File::open(first_path).expect("open first source");
        let second = std::fs::File::open(second_path).expect("open second source");
        let first_identity = first.try_clone().expect("clone first source");
        let second_identity = second.try_clone().expect("clone second source");
        let barrier = Arc::new(Barrier::new(3));

        let first_barrier = Arc::clone(&barrier);
        let first_worker = std::thread::spawn(move || {
            first_barrier.wait();
            duplicate_to_reserved_fd(&first, PRODUCTION_STATE_DIRECTORY_FD)
        });
        let second_barrier = Arc::clone(&barrier);
        let second_worker = std::thread::spawn(move || {
            second_barrier.wait();
            duplicate_to_reserved_fd(&second, PRODUCTION_STATE_DIRECTORY_FD)
        });
        barrier.wait();

        let first_result = first_worker.join().expect("first reservation panicked");
        let second_result = second_worker.join().expect("second reservation panicked");
        let (winner, winner_source, loser_error) = match (first_result, second_result) {
            (Ok(winner), Err(error)) => (winner, first_identity, error),
            (Err(error), Ok(winner)) => (winner, second_identity, error),
            (Ok(_), Ok(_)) => panic!("both concurrent reservations claimed descriptor 198"),
            (Err(first), Err(second)) => {
                panic!("both concurrent reservations failed: {first:#}; {second:#}")
            }
        };

        assert_eq!(winner.as_raw_fd(), PRODUCTION_STATE_DIRECTORY_FD);
        assert!(same_file(&winner, &winner_source));
        assert!(loser_error.to_string().contains("already occupied"));
        // The losing allocation must not overwrite or close the winner.
        assert!(same_file(&winner, &winner_source));
        // SAFETY: `winner` still owns this live descriptor; `F_GETFD` only
        // inspects descriptor flags and retains no memory.
        let flags = unsafe { libc::fcntl(PRODUCTION_STATE_DIRECTORY_FD, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, 0);
    }
}
