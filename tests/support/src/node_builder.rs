//! Node-runtime fixtures without a dependency back to `cats-node-agent`.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, OnceLock};

use cats_storage::{AdapterConfig, AdapterSelection};

/// Temporary filesystem root retained for the lifetime of a test fixture.
pub struct TempDirFixture {
    directory: tempfile::TempDir,
}

impl TempDirFixture {
    pub fn new() -> Self {
        Self {
            directory: tempfile::tempdir().expect("create test fixture directory"),
        }
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    pub fn node_config(&self, node_id: impl Into<String>) -> NodeConfigBuilder {
        NodeConfigBuilder::new(self.path(), node_id)
    }
}

impl Default for TempDirFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider-neutral pieces of a node configuration.
///
/// The caller turns these pieces into its concrete `NodeConfig`; keeping that
/// final step at the call site prevents this test-only crate from depending on
/// `cats-node-agent` and creating a dev-dependency cycle.
pub struct NodeConfigParts {
    pub node_id: String,
    pub state_dir: PathBuf,
    pub blockd_bin: PathBuf,
    pub guest_agent_bin: PathBuf,
    pub metadata_store: AdapterSelection,
    pub object_store: AdapterSelection,
    pub blockd_lease_ttl_ms: i64,
}

/// Builder for the common SQLite + File + FakeVmm node-test shape.
pub struct NodeConfigBuilder {
    parts: NodeConfigParts,
}

impl NodeConfigBuilder {
    pub fn new(root: impl AsRef<Path>, node_id: impl Into<String>) -> Self {
        let root = root.as_ref();
        Self {
            parts: NodeConfigParts {
                node_id: node_id.into(),
                state_dir: root.join("node-state"),
                blockd_bin: workspace_bin("cats-blockd"),
                guest_agent_bin: workspace_bin("cats-guest-agent"),
                metadata_store: AdapterSelection {
                    name: "sqlite".into(),
                    config: AdapterConfig::from_pairs([(
                        "path",
                        root.join("meta.db").display().to_string(),
                    )])
                    .expect("SQLite adapter config"),
                },
                object_store: AdapterSelection {
                    name: "file".into(),
                    config: AdapterConfig::from_pairs([(
                        "root",
                        root.join("blob").display().to_string(),
                    )])
                    .expect("File adapter config"),
                },
                blockd_lease_ttl_ms: 1_200,
            },
        }
    }

    pub fn state_dir(&self) -> &Path {
        &self.parts.state_dir
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Self {
        self.parts.state_dir = state_dir.into();
        self
    }

    pub fn with_guest_agent_bin(mut self, guest_agent_bin: impl Into<PathBuf>) -> Self {
        self.parts.guest_agent_bin = guest_agent_bin.into();
        self
    }

    pub fn with_metadata_store(mut self, metadata_store: AdapterSelection) -> Self {
        self.parts.metadata_store = metadata_store;
        self
    }

    pub fn with_object_store(mut self, object_store: AdapterSelection) -> Self {
        self.parts.object_store = object_store;
        self
    }

    pub fn with_lease_ttl_ms(mut self, ttl_ms: i64) -> Self {
        self.parts.blockd_lease_ttl_ms = ttl_ms;
        self
    }

    pub fn into_parts(self) -> NodeConfigParts {
        self.parts
    }
}

/// Build the concrete node-agent configuration with FakeVmm and the normal
/// test defaults, while resolving node-agent types in the invoking test crate.
#[macro_export]
macro_rules! fake_node_config {
    ($builder:expr) => {
        $crate::fake_node_config!($builder, wake_budget = Default::default())
    };
    ($builder:expr, wake_budget = $wake_budget:expr) => {{
        let parts = $builder.into_parts();
        cats_node_agent::runtime::NodeConfig {
            node_id: parts.node_id,
            state_dir: parts.state_dir.into(),
            blockd_bin: parts.blockd_bin,
            guest_agent_bin: parts.guest_agent_bin,
            metadata_store: parts.metadata_store,
            object_store: parts.object_store,
            blockd_lease_ttl_ms: parts.blockd_lease_ttl_ms,
            blockd_max_staged_bytes: cats_api::blockd::DEFAULT_MAX_STAGED_BYTES,
            blockd_max_staged_packs: cats_api::blockd::DEFAULT_MAX_STAGED_PACKS,
            blockd_max_local_bytes: cats_api::blockd::DEFAULT_MAX_LOCAL_BYTES,
            metering_cgroup_root: None,
            wake_budget: $wake_budget,
            vmm: cats_node_agent::runtime::VmmMode::Fake,
        }
    }};
}

fn target_profile_dir() -> PathBuf {
    let executable = std::env::current_exe().expect("current_exe");
    let mut directory = executable
        .parent()
        .expect("test binary directory")
        .to_path_buf();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    directory
}

fn profile_args(directory: &Path) -> &'static [&'static str] {
    if directory.file_name().is_some_and(|name| name == "release") {
        &["--release"]
    } else {
        &[]
    }
}

fn package_for(binary: &str) -> &'static str {
    match binary {
        "cats-blockd" => "cats-blockd-daemon",
        "cats-guest-agent" => "cats-guest-agent",
        "cats-noded" => "cats-node-agent-daemon",
        "cats-controld" => "cats-control-plane-daemon",
        "cats-gatewayd" => "cats-network",
        "cats" => "cats-cli",
        other => panic!("unknown workspace binary {other}"),
    }
}

fn workspace_build_command(profile_directory: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO"));
    command.args(["build", "--locked"]).arg("--target-dir").arg(
        profile_directory
            .parent()
            .expect("Cargo target profile has a root"),
    );
    command
}

/// Path to a workspace binary, building it once if Cargo did not provide it.
pub fn workspace_bin(name: &str) -> PathBuf {
    static BUILD: Once = Once::new();
    let directory = target_profile_dir();
    let path = directory.join(name);
    let build = || {
        let status = workspace_build_command(&directory)
            .args(["-p", package_for(name)])
            .args(profile_args(&directory))
            .status()
            .expect("run cargo build for test binaries");
        assert!(status.success(), "building test binaries failed");
    };
    if !path.exists() {
        BUILD.call_once(build);
        if !path.exists() {
            build();
        }
    }
    assert!(
        path.exists(),
        "workspace binary {name} not found at {}",
        path.display()
    );
    path
}

/// Path to one explicit workspace example used only as an external test
/// process, building it in the active Cargo profile when necessary.
pub fn workspace_example(package: &str, name: &str) -> PathBuf {
    static BUILD_EXAMPLE: Mutex<()> = Mutex::new(());

    let directory = target_profile_dir();
    let path = directory.join("examples").join(name);
    let _build = BUILD_EXAMPLE.lock().expect("example build mutex");
    let status = workspace_build_command(&directory)
        .args(["-p", package, "--example", name])
        .args(profile_args(&directory))
        .status()
        .expect("run cargo build for test example");
    assert!(status.success(), "building test example failed");
    assert!(
        path.exists(),
        "workspace example {name} not found at {}",
        path.display()
    );
    path
}

/// Build a launcher for the explicit authorized SQLite block server used by
/// legacy `NodeRuntime` integration tests.
///
/// The production daemon has no unsigned serving mode. The wrapper keeps the
/// complete test-only grant inputs out of process-global test environment and
/// passes them only to children started through the returned fixture path.
pub fn sqlite_node_runtime_blockd_fixture(
    root: &Path,
    volume_size_bytes: u64,
    attachment_epoch: i64,
) -> PathBuf {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    static TEST_BLOCKD: OnceLock<PathBuf> = OnceLock::new();

    assert!(volume_size_bytes > 0, "test volume size must be positive");
    assert!(
        attachment_epoch > 0,
        "test attachment epoch must be positive"
    );

    let fixture_dir = root.join("sqlite-node-runtime-blockd-fixture");
    std::fs::create_dir_all(&fixture_dir).expect("create SQLite blockd fixture directory");
    let server_link = fixture_dir.join("sqlite-node-runtime-test-server");
    let server = TEST_BLOCKD
        .get_or_init(|| workspace_example("cats-blockd", "sqlite_node_runtime_test_server"));
    symlink(server, &server_link).expect("link SQLite blockd test server");

    let launcher = fixture_dir.join("cats-blockd");
    let script = format!(
        "#!/bin/sh\nset -eu\nexport CATS_TEST_BLOCKD_VOLUME_SIZE_BYTES={volume_size_bytes}\nexport CATS_TEST_BLOCKD_ATTACHMENT_EPOCH={attachment_epoch}\nexec \"${{0%/*}}/sqlite-node-runtime-test-server\" \"$@\"\n"
    );
    std::fs::write(&launcher, script).expect("write SQLite blockd test launcher");
    let mut permissions = std::fs::metadata(&launcher)
        .expect("inspect SQLite blockd test launcher")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&launcher, permissions)
        .expect("make SQLite blockd test launcher executable");
    launcher
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_workspace_build_reuses_the_active_custom_target_root() {
        let target_root = Path::new("/tmp/cats-custom-target");
        let profile_directory = target_root.join("debug");
        let command = workspace_build_command(&profile_directory);
        let arguments = command.get_args().collect::<Vec<_>>();

        assert_eq!(arguments.len(), 4);
        assert_eq!(arguments[0], "build");
        assert_eq!(arguments[1], "--locked");
        assert_eq!(arguments[2], "--target-dir");
        assert_eq!(arguments[3], target_root.as_os_str());
    }
}
