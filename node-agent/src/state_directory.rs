//! Process-lifetime ownership of the identity-selected Node state directory.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Deref;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use anyhow::Context as _;

/// Reserved by the production Node before any runtime worker is constructed.
/// The descriptor remains the Agent's descriptor-relative authority. Runtime
/// paths themselves use the identity-selected canonical pathname so a process
/// started by the system manager never depends on an Agent-private fd table.
#[cfg(target_os = "linux")]
const PRODUCTION_STATE_DIRECTORY_FD: RawFd = 198;

/// An identity-selected state directory retained for the Agent lifetime.
/// Manager-spawned services receive its canonical path and establish their own
/// process-local descriptor authority after reopening the same identity.
#[derive(Clone)]
pub struct StateDirectory {
    path: PathBuf,
    inherited_directory: Option<Arc<File>>,
    anchored_lexical_chain: Option<Arc<[DirectoryIdentity]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
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
            .field(
                "anchored_lexical_components",
                &self
                    .anchored_lexical_chain
                    .as_ref()
                    .map(|chain| chain.len()),
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
            anchored_lexical_chain: None,
        }
    }

    /// Retains the identity-selected directory while exposing only its
    /// canonical installed pathname to checkpoints and child argv. Failing
    /// because the reserved descriptor is already occupied is safer than
    /// silently closing an unrelated process resource with `dup2`.
    pub(crate) fn from_installed_directory(
        directory: &File,
        canonical_path: &Path,
    ) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let descriptor = duplicate_to_reserved_fd(directory, PRODUCTION_STATE_DIRECTORY_FD)?;
            let (lexical, chain) = open_lexical_directory(canonical_path)?;
            ensure_same_directory(&descriptor, &lexical)?;
            let state = Self {
                path: canonical_path.to_path_buf(),
                inherited_directory: Some(Arc::new(descriptor)),
                anchored_lexical_chain: Some(chain.into()),
            };
            Ok(state)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let retained = directory.try_clone()?;
            let (lexical, chain) = open_lexical_directory(canonical_path)?;
            ensure_same_directory(&retained, &lexical)?;
            let state = Self {
                path: canonical_path.to_path_buf(),
                inherited_directory: Some(Arc::new(retained)),
                anchored_lexical_chain: Some(chain.into()),
            };
            Ok(state)
        }
    }

    /// Linux regression boundary: allocate a unique inheritable descriptor so
    /// parallel tests cannot contend for the production-reserved number.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_test_directory(
        directory: &File,
        canonical_path: &Path,
    ) -> anyhow::Result<Self> {
        let canonical_path = std::fs::canonicalize(canonical_path)?;
        let descriptor = duplicate_inheritable(directory, PRODUCTION_STATE_DIRECTORY_FD + 1)?;
        let (lexical, chain) = open_lexical_directory(&canonical_path)?;
        ensure_same_directory(&descriptor, &lexical)?;
        let state = Self {
            path: canonical_path,
            inherited_directory: Some(Arc::new(descriptor)),
            anchored_lexical_chain: Some(chain.into()),
        };
        Ok(state)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn from_test_directory(
        directory: &File,
        canonical_path: &Path,
    ) -> anyhow::Result<Self> {
        let canonical_path = std::fs::canonicalize(canonical_path)?;
        let retained = directory.try_clone()?;
        let (lexical, chain) = open_lexical_directory(&canonical_path)?;
        ensure_same_directory(&retained, &lexical)?;
        let state = Self {
            path: canonical_path,
            inherited_directory: Some(Arc::new(retained)),
            anchored_lexical_chain: Some(chain.into()),
        };
        Ok(state)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Clones the already-retained identity-selected directory after proving
    /// that a fresh no-follow traversal of the canonical pathname still names
    /// that directory. Explicit development configurations return the freshly
    /// opened pathname descriptor.
    pub(crate) fn try_clone_directory(&self) -> std::io::Result<File> {
        match &self.inherited_directory {
            Some(directory) => {
                let retained = directory.try_clone()?;
                self.try_reopen_directory()?;
                Ok(retained)
            }
            None => open_unanchored_directory(&self.path),
        }
    }

    /// Freshly reopens the canonical pathname and, for an anchored state
    /// directory, proves it still names the retained directory. Callers keep
    /// this descriptor when they need to close a later lexical ABA window.
    pub(crate) fn try_reopen_directory(&self) -> std::io::Result<File> {
        if self.anchored_lexical_chain.is_none() {
            return open_unanchored_directory(&self.path);
        }
        let (lexical, chain) = open_lexical_directory(&self.path)?;
        if let Some(expected) = &self.anchored_lexical_chain {
            if expected.as_ref() != chain.as_slice() {
                return Err(io::Error::other(
                    "canonical Node state directory ancestor chain changed identity",
                ));
            }
        }
        if let Some(retained) = &self.inherited_directory {
            ensure_same_directory(retained, &lexical)?;
        }
        Ok(lexical)
    }

    /// Revalidates the canonical/retained identity immediately before runtime
    /// construction. The descriptor remains non-`CLOEXEC` for legacy direct
    /// children, but manager-spawned services consume only canonical paths.
    pub fn ensure_child_inheritance(&self) -> anyhow::Result<()> {
        let Some(directory) = &self.inherited_directory else {
            return Ok(());
        };
        self.try_reopen_directory().map_err(anyhow::Error::from)?;
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

fn open_unanchored_directory(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}

fn open_lexical_directory(path: &Path) -> io::Result<(File, Vec<DirectoryIdentity>)> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Node state directory path must be absolute",
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut directory = options.open(Path::new("/"))?;
    let mut chain = vec![directory_identity(&directory)?];
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Node state directory component contains NUL",
                    )
                })?;
                loop {
                    // SAFETY: `directory` owns a live directory descriptor and
                    // `name` remains NUL-terminated for this call. A successful
                    // descriptor is transferred exactly once into `File`.
                    let descriptor = unsafe {
                        libc::openat(
                            directory.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY
                                | libc::O_DIRECTORY
                                | libc::O_NOFOLLOW
                                | libc::O_CLOEXEC
                                | libc::O_NONBLOCK,
                        )
                    };
                    if descriptor >= 0 {
                        // SAFETY: `openat` returned one fresh owned descriptor.
                        directory = unsafe { File::from_raw_fd(descriptor) };
                        chain.push(directory_identity(&directory)?);
                        break;
                    }
                    let source = io::Error::last_os_error();
                    if source.kind() != io::ErrorKind::Interrupted {
                        return Err(source);
                    }
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Node state directory path is not canonical",
                ));
            }
        }
    }
    Ok((directory, chain))
}

fn directory_identity(directory: &File) -> io::Result<DirectoryIdentity> {
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir() || metadata.ino() == 0 {
        return Err(io::Error::other(
            "Node state directory component is not one stable directory",
        ));
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn ensure_same_directory(retained: &File, lexical: &File) -> io::Result<()> {
    let retained = retained.metadata()?;
    let lexical = lexical.metadata()?;
    if retained.file_type().is_dir()
        && lexical.file_type().is_dir()
        && retained.dev() == lexical.dev()
        && retained.ino() == lexical.ino()
    {
        Ok(())
    } else {
        Err(io::Error::other(
            "canonical Node state directory no longer names the retained inode",
        ))
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
    // Match the production reservation's inheritance invariant while tests
    // allocate distinct descriptor numbers and run concurrently.
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
    use std::fs::File;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::{Arc, Barrier, Mutex};

    use super::{duplicate_to_reserved_fd, StateDirectory, PRODUCTION_STATE_DIRECTORY_FD};

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

    #[test]
    fn anchored_runtime_path_is_canonical_and_rejects_an_ancestor_replacement() {
        let temp = tempfile::tempdir().expect("create anchored state fixture");
        let parent = temp.path().join("node");
        let state = parent.join("state-a");
        std::fs::create_dir_all(&state).expect("create anchored state directory");
        let source = File::open(&state).expect("open anchored state directory");
        let anchored = StateDirectory::from_test_directory(&source, &state)
            .expect("retain anchored state directory");
        let canonical = std::fs::canonicalize(&state).expect("canonicalize anchored state path");

        assert_eq!(anchored.path(), canonical);
        assert!(!anchored.path().starts_with("/proc/self/fd"));
        assert!(same_file(
            &anchored
                .try_clone_directory()
                .expect("clone retained anchored state directory"),
            &source
        ));

        let displaced = temp.path().join("node-displaced");
        std::fs::rename(&parent, &displaced).expect("displace anchored state parent");
        std::fs::create_dir(&parent).expect("create replacement state parent");
        std::fs::rename(displaced.join("state-a"), &state)
            .expect("move exact state leaf beneath replacement parent");
        let error = anchored
            .try_clone_directory()
            .expect_err("replacement ancestor must fail the lexical proof");
        assert!(error
            .to_string()
            .contains("ancestor chain changed identity"));

        std::fs::rename(&state, displaced.join("state-a"))
            .expect("return state leaf to retained parent");
        std::fs::remove_dir(&parent).expect("remove replacement parent");
        std::fs::rename(&displaced, &parent).expect("restore retained parent");
        assert!(same_file(
            &anchored
                .try_reopen_directory()
                .expect("restored lexical chain names retained state"),
            &source
        ));
    }
}
