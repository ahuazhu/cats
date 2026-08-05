use super::*;

#[derive(Debug, Clone)]
pub(super) struct RuntimeMetering {
    pub(super) cgroup_path: PathBuf,
    pub(super) source_epoch: String,
}

impl NodeRuntime {
    /// Runtime identities for actual per-Cat host resource sampling.
    pub(crate) fn telemetry_targets(&self) -> Vec<CatTelemetryTarget> {
        let mut targets: Vec<(CatTelemetryTarget, Vec<(String, PathBuf)>)> = self
            .cats
            .lock()
            .unwrap()
            .iter()
            .map(|(cat_id, runtime)| {
                (
                    runtime.telemetry_target(cat_id),
                    runtime
                        .blockds
                        .iter()
                        .map(|(disk_id, blockd)| (disk_id.clone(), blockd.control_socket.clone()))
                        .collect(),
                )
            })
            .collect();
        let jobs: Vec<(usize, String, String, PathBuf)> = targets
            .iter()
            .enumerate()
            .flat_map(|(target_index, (target, controls))| {
                controls.iter().map(move |(disk_id, socket)| {
                    (
                        target_index,
                        target.cat_id.clone(),
                        disk_id.clone(),
                        socket.clone(),
                    )
                })
            })
            .collect();
        if !jobs.is_empty() {
            // A dead blockd has a 500 ms socket deadline. Sampling disks
            // serially would turn N dead Cats into an N*500 ms heartbeat stall,
            // so use a small bounded fan-out independent of Cat count.
            const STATUS_WORKERS: usize = 16;
            let workers = jobs.len().min(STATUS_WORKERS);
            let next = AtomicUsize::new(0);
            let sampled: Mutex<Vec<(usize, DiskDurabilityTelemetry)>> = Mutex::new(Vec::new());
            std::thread::scope(|scope| {
                for _ in 0..workers {
                    scope.spawn(|| loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some((target_index, cat_id, disk_id, socket)) = jobs.get(index) else {
                            return;
                        };
                        match BlockdProc::durability_status_at(socket, disk_id) {
                            Ok(status) => sampled.lock().unwrap().push((*target_index, status)),
                            Err(error) => tracing::warn!(
                                cat = %cat_id,
                                disk = %disk_id,
                                "read blockd durability status: {error:#}"
                            ),
                        }
                    });
                }
            });
            for (target_index, status) in sampled.into_inner().unwrap() {
                targets[target_index].0.disk_durability.push(status);
            }
            for (target, _) in &mut targets {
                target
                    .disk_durability
                    .sort_by(|left, right| left.disk_id.cmp(&right.disk_id));
            }
        }
        targets.into_iter().map(|(target, _)| target).collect()
    }

    pub(super) fn set_runtime_generation(&self, cat_id: &str, generation: i64) -> Result<()> {
        let target = {
            let cats = self.cats.lock().unwrap();
            let Some(runtime) = cats.get(cat_id) else {
                return Ok(());
            };
            if runtime.generation >= generation {
                return Ok(());
            }
            runtime.lifecycle_telemetry_target(cat_id)
        };
        self.finalize_usage(target)?;
        let mut cats = self.cats.lock().unwrap();
        let Some(runtime) = cats.get_mut(cat_id) else {
            return Ok(());
        };
        if runtime.generation >= generation {
            return Ok(());
        }
        runtime.generation = generation;
        if let Some(metering) = &mut runtime.metering {
            // A generation change is a new attribution epoch even when the
            // same cgroup counter continues monotonically. The first sample
            // in the new epoch establishes a fresh baseline.
            metering.source_epoch = uuid::Uuid::new_v4().simple().to_string();
        }
        Ok(())
    }

    pub(super) fn retire_warm_metering(&self, cat_id: &str) -> Result<()> {
        let target = {
            let cats = self.cats.lock().unwrap();
            let runtime = cats
                .get(cat_id)
                .context("warm runtime vanished before usage finalization")?;
            anyhow::ensure!(
                runtime.state == ObservedState::Warm,
                "cannot retire compute metering from {:?}",
                runtime.state
            );
            runtime.lifecycle_telemetry_target(cat_id)
        };
        let Some(expected_metering) = target.metering.clone() else {
            return Ok(());
        };

        // The Warm state already hides this epoch from heartbeat sampling.
        // Persist its final checkpoint before dropping the cgroup identity so
        // a failed lifecycle job can retry without inventing an interval.
        self.finalize_usage(target)?;

        let retired = {
            let mut cats = self.cats.lock().unwrap();
            cats.get_mut(cat_id).and_then(|runtime| {
                let still_same_epoch = runtime.state == ObservedState::Warm
                    && runtime.metering.as_ref().is_some_and(|metering| {
                        metering.source_epoch == expected_metering.source_epoch
                    });
                if still_same_epoch {
                    runtime.metering.take()
                } else {
                    None
                }
            })
        };
        Self::remove_metering_cgroup(retired.as_ref());
        Ok(())
    }

    pub(super) fn finalize_usage(&self, target: CatTelemetryTarget) -> Result<()> {
        if target.metering.is_none() {
            return Ok(());
        }
        if let Some(finalizer) = &self.usage_finalizer {
            finalizer.finalize(target)?;
        }
        Ok(())
    }

    pub(super) fn prepare_metering(&self, cat_id: &str) -> Result<Option<RuntimeMetering>> {
        let Some(root) = &self.cfg.metering_cgroup_root else {
            return Ok(None);
        };
        let source_epoch = uuid::Uuid::new_v4().simple().to_string();
        let node_dir = root.join(&self.cfg.node_id);
        std::fs::create_dir_all(&node_dir)
            .with_context(|| format!("create node metering cgroup {}", node_dir.display()))?;
        enable_cgroup_controllers(&node_dir)?;
        let cgroup_path = node_dir.join(format!("{cat_id}-{source_epoch}"));
        std::fs::create_dir_all(&cgroup_path)
            .with_context(|| format!("create metering cgroup {}", cgroup_path.display()))?;
        for required in ["cgroup.procs", "cpu.stat", "memory.current"] {
            if !cgroup_path.join(required).is_file() {
                let _ = std::fs::remove_dir(&cgroup_path);
                bail!(
                    "metering cgroup {} lacks {required}; configure a delegated cgroup v2 subtree with CPU and memory accounting",
                    cgroup_path.display()
                );
            }
        }
        Ok(Some(RuntimeMetering {
            cgroup_path,
            source_epoch,
        }))
    }

    pub(super) fn attach_to_metering(&self, runtime: &CatRuntime, process_id: u32) -> Result<()> {
        let Some(metering) = &runtime.metering else {
            return Ok(());
        };
        std::fs::write(
            metering.cgroup_path.join("cgroup.procs"),
            process_id.to_string(),
        )
        .with_context(|| {
            format!(
                "move process {process_id} into metering cgroup {}",
                metering.cgroup_path.display()
            )
        })
    }

    pub(super) fn remove_metering_cgroup(metering: Option<&RuntimeMetering>) {
        if let Some(metering) = metering {
            let _ = std::fs::remove_dir(&metering.cgroup_path);
        }
    }
}

/// Prepare the delegated cgroup v2 hierarchy before any Cat runtime starts.
///
/// A systemd service initially places its own process in the delegated unit
/// cgroup. cgroup v2 does not allow CPU or memory controllers to be enabled
/// for children while that parent contains a process, so the node agent first
/// moves itself into a sibling leaf and leaves the configured metering root
/// empty for per-Cat descendants.
pub(crate) fn initialize_metering_cgroup(cfg: &NodeConfig) -> Result<()> {
    let Some(root) = &cfg.metering_cgroup_root else {
        return Ok(());
    };
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

        let agent_leaf = delegated_root.join("agent");
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
