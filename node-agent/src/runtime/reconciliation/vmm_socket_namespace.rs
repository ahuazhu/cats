//! Provider-private ownership boundary for Cloud Hypervisor Unix sockets.
//!
//! The public Runtime v1 checkpoint records the two canonical socket paths,
//! but those path strings are not filesystem ownership.  This module freezes
//! the one short, installation-owned namespace and derives all public,
//! staging and quarantine names from the already-checkpointed random runtime
//! incarnation.  Later physical effects consume these typed paths together
//! with a durable provider-private ownership receipt; no caller may choose an
//! arbitrary pathname at launch time.

use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{HostPath, RandomId128, ReconcileStep, RuntimeCheckpoint};

/// Installation-owned short socket root.  It is deliberately outside the
/// durable Node state directory: AF_UNIX pathnames have a small kernel ABI
/// bound and live VMM sockets are boot-local.  The durable ownership WAL lives
/// under the identity-selected Node state directory instead.
pub(crate) const INSTALLED_VMM_SOCKET_ROOT: &str = "/run/cats/vmm-v1";

pub(crate) const VMM_API_SOCKET_BASENAME: &str = "api.sock";
pub(crate) const VMM_VSOCK_SOCKET_BASENAME: &str = "vsock.sock";

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
    use cats_api::runtime_reconciliation::decode_runtime_checkpoint;

    use super::*;

    fn checkpoint() -> RuntimeCheckpoint {
        decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap()
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
            if let Ok(path) = HostPath::new(path) {
                assert!(ManagedVmmSocketRoot::from_canonical_path(path).is_err());
            }
        }

        let long = format!("/run/{}", "x".repeat(90));
        let root = ManagedVmmSocketRoot::from_canonical_path(HostPath::new(long).unwrap()).unwrap();
        assert!(root
            .paths_for(&RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap())
            .is_err());
    }
}
