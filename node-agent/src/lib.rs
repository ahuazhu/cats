//! Cats node agent: executes control-plane jobs by supervising the fake VMM
//! (guest-agent process) and one cats-blockd per attachment. See
//! `runtime.rs` for the FakeVmm / Cloud Hypervisor seam.

pub mod ch;
pub mod guest_client;
pub mod runtime;
pub mod server;

/// Test support: locate (and if needed build) workspace binaries so
/// integration/E2E tests can spawn the real `cats-blockd` and
/// `cats-guest-agent` children regardless of which package `cargo test`
/// was invoked for.
pub mod testutil {
    use std::path::PathBuf;
    use std::sync::Once;

    fn target_debug_dir() -> PathBuf {
        // .../target/debug/deps/<test-bin> -> .../target/debug
        let exe = std::env::current_exe().expect("current_exe");
        let mut dir = exe.parent().expect("deps dir").to_path_buf();
        if dir.file_name().is_some_and(|n| n == "deps") {
            dir.pop();
        }
        dir
    }

    fn package_for(bin: &str) -> &'static str {
        match bin {
            "cats-blockd" => "cats-blockd",
            "cats-guest-agent" => "cats-guest-agent",
            "cats-noded" => "cats-node-agent",
            "cats-controld" => "cats-control-plane",
            "cats-gatewayd" => "cats-network",
            "cats" => "cats-cli",
            other => panic!("unknown workspace binary {other}"),
        }
    }

    /// Path to a workspace binary, building it on first use if missing.
    pub fn workspace_bin(name: &str) -> PathBuf {
        static BUILD: Once = Once::new();
        let path = target_debug_dir().join(name);
        if !path.exists() {
            BUILD.call_once(|| {
                let status = std::process::Command::new(env!("CARGO"))
                    .args(["build", "-p", package_for(name)])
                    .status()
                    .expect("run cargo build for test binaries");
                assert!(status.success(), "building test binaries failed");
            });
            // A second missing binary after the Once fired: build directly.
            if !path.exists() {
                let status = std::process::Command::new(env!("CARGO"))
                    .args(["build", "-p", package_for(name)])
                    .status()
                    .expect("run cargo build for test binaries");
                assert!(status.success(), "building test binaries failed");
            }
        }
        assert!(
            path.exists(),
            "workspace binary {name} not found at {}",
            path.display()
        );
        path
    }
}
