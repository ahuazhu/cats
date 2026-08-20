use std::path::Path;

use anyhow::{bail, Context, Result};

pub(crate) const AGENT_DELEGATED_CGROUP_LEAF: &str = "agent";

/// Establishes the Agent's delegated metering root. The signed Runtime's own
/// inventory proof requires this root to exist: an absent root is unprovable,
/// not empty, so an Agent that never created it can never attest.
pub(crate) fn initialize_metering_cgroup_root(root: &Path) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        bail!("authoritative cgroup v2 billing is supported only on Linux");
    }
    #[cfg(target_os = "linux")]
    {
        let delegated_root = root.parent().with_context(|| {
            format!(
                "metering cgroup root {} must have a delegated parent",
                root.display()
            )
        })?;
        let delegated_processes = delegated_root.join("cgroup.procs");
        let process_id = std::process::id().to_string();
        let current_processes =
            std::fs::read_to_string(&delegated_processes).with_context(|| {
                format!(
                    "read delegated cgroup process list {}",
                    delegated_processes.display()
                )
            })?;
        anyhow::ensure!(
            current_processes.lines().any(|line| line == process_id),
            "node agent is not running in configured delegated cgroup {}",
            delegated_root.display()
        );

        let agent_leaf = delegated_root.join(AGENT_DELEGATED_CGROUP_LEAF);
        std::fs::create_dir_all(&agent_leaf)
            .with_context(|| format!("create node-agent cgroup {}", agent_leaf.display()))?;
        std::fs::write(agent_leaf.join("cgroup.procs"), &process_id)
            .with_context(|| format!("move node agent into {}", agent_leaf.display()))?;
        let remaining_processes =
            std::fs::read_to_string(&delegated_processes).with_context(|| {
                format!(
                    "re-read delegated cgroup process list {}",
                    delegated_processes.display()
                )
            })?;
        anyhow::ensure!(
            remaining_processes.lines().all(|line| line.is_empty()),
            "delegated cgroup {} contains processes other than the node agent",
            delegated_root.display()
        );

        enable_cgroup_controllers(delegated_root)?;
        std::fs::create_dir_all(root)
            .with_context(|| format!("create metering cgroup root {}", root.display()))?;
        enable_cgroup_controllers(root)?;
        Ok(())
    }
}

fn enable_cgroup_controllers(cgroup: &Path) -> Result<()> {
    let controllers_path = cgroup.join("cgroup.controllers");
    let controllers = std::fs::read_to_string(&controllers_path)
        .with_context(|| format!("read cgroup controllers {}", controllers_path.display()))?;
    let available = controllers
        .split_whitespace()
        .collect::<std::collections::HashSet<_>>();
    for required in ["cpu", "memory"] {
        anyhow::ensure!(
            available.contains(required),
            "delegated cgroup {} does not expose the {required} controller",
            cgroup.display()
        );
    }
    let subtree_control = cgroup.join("cgroup.subtree_control");
    std::fs::write(&subtree_control, "+cpu +memory").with_context(|| {
        format!(
            "enable cpu and memory controllers in {}",
            subtree_control.display()
        )
    })
}
