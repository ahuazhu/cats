//! Node-runtime fixtures without a dependency back to `cats-node-agent`.

use std::path::{Path, PathBuf};
use std::sync::Once;

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

/// Path to a workspace binary, building it once if Cargo did not provide it.
pub fn workspace_bin(name: &str) -> PathBuf {
    static BUILD: Once = Once::new();
    let directory = target_profile_dir();
    let path = directory.join(name);
    let build = || {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "-p", package_for(name)])
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
