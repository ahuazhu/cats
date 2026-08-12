//! Pure mapping for the installation-owned blockd Unix-socket namespace.
//!
//! Runtime checkpoints carry canonical socket path strings, but those strings
//! must not let callers choose arbitrary filesystem ownership. Root provision
//! sockets are owned by the stable provision transition, while serving
//! sockets are owned by the device ownership token. Staging and quarantine
//! directories are derived from the same owner so recovery can move the whole
//! socket generation without unlinking individual leaves.

use std::path::{Component, Path, PathBuf};

use cats_api::runtime_reconciliation::{HostPath, RandomId128};
use thiserror::Error;

/// Fixed production root for all blockd Unix sockets.
pub const INSTALLED_BLOCKD_SOCKET_ROOT: &str = "/run/cats/blockd-v1";

/// Durable owner marker installed inside a per-owner directory before publish.
pub const BLOCKD_SOCKET_OWNER_MARKER_BASENAME: &str = ".owner.v1.json";
/// Control-plane listener basename shared by Root and Serving owners.
pub const BLOCKD_CONTROL_SOCKET_BASENAME: &str = "ctl.sock";
/// Guest-I/O listener basename present only for Serving owners.
pub const BLOCKD_IO_SOCKET_BASENAME: &str = "io.sock";

// Linux exposes 108 sun_path bytes and Darwin exposes 104. Filesystem socket
// paths need one trailing NUL, so construction admits at most capacity - 1
// pathname bytes for the platform on which the mapping is built.
#[cfg(target_os = "linux")]
const UNIX_SOCKET_PATH_CAPACITY: usize = 108;
#[cfg(target_os = "macos")]
const UNIX_SOCKET_PATH_CAPACITY: usize = 104;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const UNIX_SOCKET_PATH_CAPACITY: usize = 104;

/// Failure to construct the closed blockd socket mapping.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeSocketNamespaceError {
    #[error("managed blockd socket root must be an absolute canonical non-root path")]
    InvalidRoot,
    #[error("derived managed blockd {path_kind} is not a canonical HostPath")]
    InvalidDerivedPath { path_kind: &'static str },
    #[error(
        "managed blockd {path_kind} uses {actual_bytes} pathname bytes; sockaddr_un.sun_path permits at most {maximum_bytes}"
    )]
    UnixSocketPathTooLong {
        path_kind: &'static str,
        actual_bytes: usize,
        maximum_bytes: usize,
    },
    #[error("{role} socket path is outside the installed public blockd namespace")]
    InvalidSocketMapping { role: &'static str },
}

/// Recovers the Root owner only from the exact installed public control path.
///
/// Custom roots and the installed staging/quarantine names are deliberately
/// not parser inputs: persisted receipts and child admission may use this as a
/// closed validation boundary without separately retaining a planner root.
pub fn root_owner_from_control_socket(
    control_socket: &HostPath,
) -> Result<RandomId128, RuntimeSocketNamespaceError> {
    let owner = parse_installed_public_owner(
        control_socket,
        "r",
        BLOCKD_CONTROL_SOCKET_BASENAME,
        "Root control",
    )?;
    let expected = ManagedBlockdSocketRoot::installed().root_paths(&owner)?;
    if expected.control_socket() != control_socket {
        return Err(RuntimeSocketNamespaceError::InvalidSocketMapping {
            role: "Root control",
        });
    }
    Ok(owner)
}

/// Recovers a Serving owner from one exact installed ctl/io socket pair.
pub fn serving_owner_from_sockets(
    control_socket: &HostPath,
    io_socket: &HostPath,
) -> Result<RandomId128, RuntimeSocketNamespaceError> {
    let control_owner = parse_installed_public_owner(
        control_socket,
        "d",
        BLOCKD_CONTROL_SOCKET_BASENAME,
        "Serving control",
    )?;
    let io_owner =
        parse_installed_public_owner(io_socket, "d", BLOCKD_IO_SOCKET_BASENAME, "Serving I/O")?;
    let expected = ManagedBlockdSocketRoot::installed().serving_paths(&control_owner)?;
    if control_owner != io_owner
        || expected.control_socket() != control_socket
        || expected.io_socket() != io_socket
    {
        return Err(RuntimeSocketNamespaceError::InvalidSocketMapping { role: "Serving" });
    }
    Ok(control_owner)
}

/// Canonical root from which every production blockd socket path is derived.
///
/// Construction is pure and does not create or open the installed directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedBlockdSocketRoot {
    path: HostPath,
}

impl ManagedBlockdSocketRoot {
    /// Returns the only socket root admitted by production composition.
    pub fn installed() -> Self {
        let path = HostPath::new(INSTALLED_BLOCKD_SOCKET_ROOT)
            .expect("the fixed installed blockd socket root is canonical");
        Self::from_canonical_path(path)
            .expect("the fixed installed blockd socket root fits sockaddr_un.sun_path")
    }

    /// Test/composition constructor for an explicitly selected canonical root.
    ///
    /// Production composition must use [`Self::installed`]. This constructor
    /// validates the longest possible derived directory/socket combination up
    /// front, so a successfully constructed root cannot later produce an
    /// unbindable owner mapping.
    #[doc(hidden)]
    pub fn from_canonical_path(path: HostPath) -> Result<Self, RuntimeSocketNamespaceError> {
        ensure_canonical_root(Path::new(path.as_str()))?;
        ensure_worst_case_socket_path_fits(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &HostPath {
        &self.path
    }

    /// Maps one stable root-provision transition to its complete namespace.
    pub fn root_paths(
        &self,
        provision_transition_id: &RandomId128,
    ) -> Result<ManagedRootSocketPaths, RuntimeSocketNamespaceError> {
        let owner = owner_directories(&self.path, "r", provision_transition_id)?;
        let owner_marker = join_host_path(
            owner.public_directory(),
            BLOCKD_SOCKET_OWNER_MARKER_BASENAME,
            "Root owner marker",
        )?;
        let control_socket = join_socket_path(
            owner.public_directory(),
            BLOCKD_CONTROL_SOCKET_BASENAME,
            "Root control socket",
        )?;
        Ok(ManagedRootSocketPaths {
            root: owner.root,
            public_directory: owner.public_directory,
            staging_directory: owner.staging_directory,
            quarantine_directory: owner.quarantine_directory,
            owner_marker,
            control_socket,
        })
    }

    /// Maps one device ownership token to its complete serving namespace.
    pub fn serving_paths(
        &self,
        device_ownership_token: &RandomId128,
    ) -> Result<ManagedServingSocketPaths, RuntimeSocketNamespaceError> {
        let owner = owner_directories(&self.path, "d", device_ownership_token)?;
        let owner_marker = join_host_path(
            owner.public_directory(),
            BLOCKD_SOCKET_OWNER_MARKER_BASENAME,
            "Serving owner marker",
        )?;
        let control_socket = join_socket_path(
            owner.public_directory(),
            BLOCKD_CONTROL_SOCKET_BASENAME,
            "Serving control socket",
        )?;
        let io_socket = join_socket_path(
            owner.public_directory(),
            BLOCKD_IO_SOCKET_BASENAME,
            "Serving I/O socket",
        )?;
        Ok(ManagedServingSocketPaths {
            root: owner.root,
            public_directory: owner.public_directory,
            staging_directory: owner.staging_directory,
            quarantine_directory: owner.quarantine_directory,
            owner_marker,
            control_socket,
            io_socket,
        })
    }
}

/// Complete per-transition namespace for a Root control-only blockd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRootSocketPaths {
    root: HostPath,
    public_directory: HostPath,
    staging_directory: HostPath,
    quarantine_directory: HostPath,
    owner_marker: HostPath,
    control_socket: HostPath,
}

impl ManagedRootSocketPaths {
    pub fn root(&self) -> &HostPath {
        &self.root
    }

    pub fn public_directory(&self) -> &HostPath {
        &self.public_directory
    }

    pub fn staging_directory(&self) -> &HostPath {
        &self.staging_directory
    }

    pub fn quarantine_directory(&self) -> &HostPath {
        &self.quarantine_directory
    }

    pub fn owner_marker(&self) -> &HostPath {
        &self.owner_marker
    }

    pub fn control_socket(&self) -> &HostPath {
        &self.control_socket
    }
}

/// Complete per-device-token namespace for a Serving blockd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedServingSocketPaths {
    root: HostPath,
    public_directory: HostPath,
    staging_directory: HostPath,
    quarantine_directory: HostPath,
    owner_marker: HostPath,
    control_socket: HostPath,
    io_socket: HostPath,
}

impl ManagedServingSocketPaths {
    pub fn root(&self) -> &HostPath {
        &self.root
    }

    pub fn public_directory(&self) -> &HostPath {
        &self.public_directory
    }

    pub fn staging_directory(&self) -> &HostPath {
        &self.staging_directory
    }

    pub fn quarantine_directory(&self) -> &HostPath {
        &self.quarantine_directory
    }

    pub fn owner_marker(&self) -> &HostPath {
        &self.owner_marker
    }

    pub fn control_socket(&self) -> &HostPath {
        &self.control_socket
    }

    pub fn io_socket(&self) -> &HostPath {
        &self.io_socket
    }
}

struct OwnerDirectories {
    root: HostPath,
    public_directory: HostPath,
    staging_directory: HostPath,
    quarantine_directory: HostPath,
}

impl OwnerDirectories {
    fn public_directory(&self) -> &HostPath {
        &self.public_directory
    }
}

fn owner_directories(
    root: &HostPath,
    role_prefix: &str,
    owner: &RandomId128,
) -> Result<OwnerDirectories, RuntimeSocketNamespaceError> {
    let public_name = format!("{role_prefix}-{}", owner.as_str());
    let staging_name = format!(".s-{role_prefix}-{}", owner.as_str());
    let quarantine_name = format!(".q-{role_prefix}-{}", owner.as_str());
    Ok(OwnerDirectories {
        root: root.clone(),
        public_directory: join_host_path(root, &public_name, "public socket directory")?,
        staging_directory: join_host_path(root, &staging_name, "staging socket directory")?,
        quarantine_directory: join_host_path(
            root,
            &quarantine_name,
            "quarantine socket directory",
        )?,
    })
}

fn parse_installed_public_owner(
    socket: &HostPath,
    role_prefix: &str,
    socket_basename: &str,
    role: &'static str,
) -> Result<RandomId128, RuntimeSocketNamespaceError> {
    let relative = Path::new(socket.as_str())
        .strip_prefix(INSTALLED_BLOCKD_SOCKET_ROOT)
        .map_err(|_| RuntimeSocketNamespaceError::InvalidSocketMapping { role })?;
    let mut components = relative.components();
    let owner_directory = match components.next() {
        Some(Component::Normal(value)) => value.to_str(),
        _ => None,
    };
    let leaf = match components.next() {
        Some(Component::Normal(value)) => value.to_str(),
        _ => None,
    };
    if components.next().is_some() || leaf != Some(socket_basename) {
        return Err(RuntimeSocketNamespaceError::InvalidSocketMapping { role });
    }
    let owner = owner_directory
        .and_then(|name| name.strip_prefix(role_prefix))
        .and_then(|suffix| suffix.strip_prefix('-'))
        .and_then(RandomId128::new)
        .ok_or(RuntimeSocketNamespaceError::InvalidSocketMapping { role })?;
    Ok(owner)
}

fn ensure_canonical_root(path: &Path) -> Result<(), RuntimeSocketNamespaceError> {
    if !path.is_absolute() {
        return Err(RuntimeSocketNamespaceError::InvalidRoot);
    }
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => normal_components += 1,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(RuntimeSocketNamespaceError::InvalidRoot);
            }
        }
    }
    if normal_components == 0 || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(RuntimeSocketNamespaceError::InvalidRoot);
    }
    Ok(())
}

fn ensure_worst_case_socket_path_fits(root: &HostPath) -> Result<(), RuntimeSocketNamespaceError> {
    let maximum_owner = RandomId128::new("ffffffffffffffffffffffffffffffff")
        .expect("the fixed maximum owner is a valid non-zero RandomId128");
    // Quarantine/staging prefixes are longer than public prefixes. Validate
    // that conservative shape even though listeners bind only after publish.
    let longest_directory = format!(".q-r-{}", maximum_owner.as_str());
    let candidate = Path::new(root.as_str())
        .join(longest_directory)
        .join(BLOCKD_CONTROL_SOCKET_BASENAME);
    ensure_socket_path_bytes(
        candidate.as_os_str().as_encoded_bytes().len(),
        "socket path",
    )
}

fn join_host_path(
    parent: &HostPath,
    leaf: &str,
    path_kind: &'static str,
) -> Result<HostPath, RuntimeSocketNamespaceError> {
    host_path(Path::new(parent.as_str()).join(leaf), path_kind)
}

fn join_socket_path(
    parent: &HostPath,
    leaf: &str,
    path_kind: &'static str,
) -> Result<HostPath, RuntimeSocketNamespaceError> {
    let path = host_path(Path::new(parent.as_str()).join(leaf), path_kind)?;
    ensure_socket_path_bytes(path.as_str().len(), path_kind)?;
    Ok(path)
}

fn host_path(
    path: PathBuf,
    path_kind: &'static str,
) -> Result<HostPath, RuntimeSocketNamespaceError> {
    HostPath::new(path.to_string_lossy().into_owned())
        .ok_or(RuntimeSocketNamespaceError::InvalidDerivedPath { path_kind })
}

fn ensure_socket_path_bytes(
    actual_bytes: usize,
    path_kind: &'static str,
) -> Result<(), RuntimeSocketNamespaceError> {
    let maximum_bytes = UNIX_SOCKET_PATH_CAPACITY - 1;
    if actual_bytes > maximum_bytes {
        return Err(RuntimeSocketNamespaceError::UnixSocketPathTooLong {
            path_kind,
            actual_bytes,
            maximum_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random(value: char) -> RandomId128 {
        RandomId128::new(std::iter::repeat_n(value, 32).collect::<String>()).unwrap()
    }

    #[test]
    fn installed_root_mapping_is_exact_and_short() {
        let root = ManagedBlockdSocketRoot::installed();
        let paths = root.root_paths(&random('3')).unwrap();
        assert_eq!(root.path().as_str(), INSTALLED_BLOCKD_SOCKET_ROOT);
        assert_eq!(paths.root(), root.path());
        assert_eq!(
            paths.public_directory().as_str(),
            "/run/cats/blockd-v1/r-33333333333333333333333333333333"
        );
        assert_eq!(
            paths.staging_directory().as_str(),
            "/run/cats/blockd-v1/.s-r-33333333333333333333333333333333"
        );
        assert_eq!(
            paths.quarantine_directory().as_str(),
            "/run/cats/blockd-v1/.q-r-33333333333333333333333333333333"
        );
        assert_eq!(
            paths.owner_marker().as_str(),
            "/run/cats/blockd-v1/r-33333333333333333333333333333333/.owner.v1.json"
        );
        assert_eq!(
            paths.control_socket().as_str(),
            "/run/cats/blockd-v1/r-33333333333333333333333333333333/ctl.sock"
        );
        assert!(paths.control_socket().as_str().len() < UNIX_SOCKET_PATH_CAPACITY);
    }

    #[test]
    fn root_owner_is_transition_stable_and_role_disjoint() {
        let root = ManagedBlockdSocketRoot::installed();
        let transition = random('4');
        let first = root.root_paths(&transition).unwrap();
        let replay = root.root_paths(&transition).unwrap();
        let changed = root.root_paths(&random('5')).unwrap();
        let serving = root.serving_paths(&transition).unwrap();
        assert_eq!(first, replay);
        assert_ne!(first.public_directory(), changed.public_directory());
        assert_ne!(first.public_directory(), serving.public_directory());
        assert_ne!(first.control_socket(), serving.control_socket());
    }

    #[test]
    fn serving_owner_rotation_changes_both_nonaliased_sockets() {
        let root = ManagedBlockdSocketRoot::installed();
        let first = root.serving_paths(&random('6')).unwrap();
        let rotated = root.serving_paths(&random('7')).unwrap();
        assert_eq!(first.root(), root.path());
        assert_eq!(
            first.public_directory().as_str(),
            "/run/cats/blockd-v1/d-66666666666666666666666666666666"
        );
        assert_eq!(
            first.staging_directory().as_str(),
            "/run/cats/blockd-v1/.s-d-66666666666666666666666666666666"
        );
        assert_eq!(
            first.quarantine_directory().as_str(),
            "/run/cats/blockd-v1/.q-d-66666666666666666666666666666666"
        );
        assert_eq!(
            first.owner_marker().as_str(),
            "/run/cats/blockd-v1/d-66666666666666666666666666666666/.owner.v1.json"
        );
        assert_eq!(
            first.control_socket().as_str(),
            "/run/cats/blockd-v1/d-66666666666666666666666666666666/ctl.sock"
        );
        assert_eq!(
            first.io_socket().as_str(),
            "/run/cats/blockd-v1/d-66666666666666666666666666666666/io.sock"
        );
        assert_ne!(first.control_socket(), first.io_socket());
        assert_ne!(first.public_directory(), rotated.public_directory());
        assert_ne!(first.control_socket(), rotated.control_socket());
        assert_ne!(first.io_socket(), rotated.io_socket());
    }

    #[test]
    fn closed_parsers_accept_only_installed_public_exact_mappings() {
        let root = ManagedBlockdSocketRoot::installed();
        let root_owner = random('9');
        let root_paths = root.root_paths(&root_owner).unwrap();
        assert_eq!(
            root_owner_from_control_socket(root_paths.control_socket()).unwrap(),
            root_owner
        );

        let serving_owner = random('a');
        let serving_paths = root.serving_paths(&serving_owner).unwrap();
        assert_eq!(
            serving_owner_from_sockets(serving_paths.control_socket(), serving_paths.io_socket(),)
                .unwrap(),
            serving_owner
        );

        let staged_root_control = join_socket_path(
            root_paths.staging_directory(),
            BLOCKD_CONTROL_SOCKET_BASENAME,
            "test Root staging socket",
        )
        .unwrap();
        let quarantined_serving_io = join_socket_path(
            serving_paths.quarantine_directory(),
            BLOCKD_IO_SOCKET_BASENAME,
            "test Serving quarantine socket",
        )
        .unwrap();
        assert!(root_owner_from_control_socket(&staged_root_control).is_err());
        assert!(serving_owner_from_sockets(
            serving_paths.control_socket(),
            &quarantined_serving_io,
        )
        .is_err());

        let other = root.serving_paths(&random('b')).unwrap();
        assert!(
            serving_owner_from_sockets(serving_paths.control_socket(), other.io_socket(),).is_err()
        );
        assert!(serving_owner_from_sockets(
            serving_paths.io_socket(),
            serving_paths.control_socket(),
        )
        .is_err());

        let custom = ManagedBlockdSocketRoot::from_canonical_path(
            HostPath::new("/run/cats/test-blockd-v1").unwrap(),
        )
        .unwrap();
        let custom_root = custom.root_paths(&random('c')).unwrap();
        let custom_serving = custom.serving_paths(&random('d')).unwrap();
        assert!(root_owner_from_control_socket(custom_root.control_socket()).is_err());
        assert!(serving_owner_from_sockets(
            custom_serving.control_socket(),
            custom_serving.io_socket(),
        )
        .is_err());
    }

    #[test]
    fn custom_root_rejects_filesystem_root_and_conservative_overflow() {
        assert!(ManagedBlockdSocketRoot::from_canonical_path(HostPath::new("/").unwrap()).is_err());

        let maximum_bytes = UNIX_SOCKET_PATH_CAPACITY - 1;
        let suffix_bytes = 1
            + ".q-r-ffffffffffffffffffffffffffffffff".len()
            + 1
            + BLOCKD_CONTROL_SOCKET_BASENAME.len();
        let fitting_root = format!("/{}", "x".repeat(maximum_bytes - suffix_bytes - 1));
        let fitting =
            ManagedBlockdSocketRoot::from_canonical_path(HostPath::new(fitting_root).unwrap())
                .unwrap();
        assert!(fitting.root_paths(&random('8')).is_ok());
        assert!(fitting.serving_paths(&random('8')).is_ok());

        let overflowing_root = format!("/{}", "x".repeat(maximum_bytes - suffix_bytes));
        assert!(ManagedBlockdSocketRoot::from_canonical_path(
            HostPath::new(overflowing_root).unwrap(),
        )
        .is_err());
    }
}
