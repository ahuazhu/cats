use super::*;
use std::collections::HashSet;

pub(super) enum TeardownMode {
    /// Ordinary transition to Cold: every attached disk is preserved.
    Cold,
    /// Cat deletion: only the explicitly named RootDisks are disposable.
    Destroy {
        disposable_root_disk_ids: Vec<String>,
        retained_persistent_disk_ids: Vec<String>,
    },
    /// Failure cleanup after ownership has already been fenced elsewhere.
    Discard,
}

impl From<StopCatDisposition> for TeardownMode {
    fn from(disposition: StopCatDisposition) -> Self {
        match disposition {
            StopCatDisposition::Cold => Self::Cold,
            StopCatDisposition::Destroy {
                disposable_root_disk_ids,
                retained_persistent_disk_ids,
            } => Self::Destroy {
                disposable_root_disk_ids,
                retained_persistent_disk_ids,
            },
        }
    }
}

impl NodeRuntime {
    fn cat_lock(&self, cat_id: &str) -> Arc<Mutex<()>> {
        Arc::clone(
            self.cat_ops
                .lock()
                .unwrap()
                .entry(cat_id.to_string())
                .or_default(),
        )
    }

    pub fn execute(&self, job: NodeJob) -> NodeJobResult {
        if let Some(prev) = self.journal.lock().unwrap().get(&job.job_id) {
            return prev.clone();
        }
        // Every action is serialized per Cat. Stop/Cold addresses devices
        // already owned by one Cat, and its remote drains are independently
        // bounded by `stop_admission`, so unrelated Cats can stop in parallel.
        // Resume and vhost-user launches keep their existing lock exemptions;
        // other lifecycle/hot-plug paths remain conservatively node-serialized
        // until they receive their own concurrency coverage.
        // The per-Cat lock is unconditional: it is what keeps "one job per Cat at
        // a time" true, so a stop can never interleave with a start of the same
        // Cat. The node-wide lock is then layered on top only for actions that
        // touch node-global state. The order is always per-Cat then node-wide, so
        // a thread holding the node-wide lock never waits for a per-Cat lock and
        // the pair cannot deadlock.
        let needs_node_lock = match &job.action {
            NodeJobAction::ResumeCat { .. } | NodeJobAction::StopCat { .. } => false,
            NodeJobAction::StartCat { .. } | NodeJobAction::RestoreCat { .. } => {
                self.launch_allocates_node_global_state()
            }
            // Keep the existing conservative serialization for lifecycle and
            // hot-plug paths not covered by this Stop concurrency change.
            NodeJobAction::SuspendCat { .. }
            | NodeJobAction::WarmCat { .. }
            | NodeJobAction::AttachDisk { .. }
            | NodeJobAction::DetachDisk { .. }
            | NodeJobAction::SyncCat { .. }
            | NodeJobAction::CleanupCat { .. } => true,
        };
        let per_cat = self.cat_lock(job.action.cat_id());
        let _cat_guard = per_cat.lock().unwrap();
        let _stop_permit = matches!(&job.action, NodeJobAction::StopCat { .. })
            .then(|| self.stop_admission.acquire());
        let _node_guard = needs_node_lock.then(|| self.ops.lock().unwrap());
        self.execute_locked(job)
    }

    /// Whether starting a Cat competes with other Cats for node-global state.
    ///
    /// Only the kernel-NBD block path does: `nbd_attach` takes a host-wide lock
    /// and scans for a free `/dev/nbdN`. Everything else a launch allocates is
    /// derived from the Cat and disk id — the vhost-user socket path, the tap
    /// name and its /30, the per-Cat state directory and metering cgroup — so
    /// two launches cannot collide. Keeping the node-wide lock for the NBD path
    /// is what makes that path's device allocation safe.
    fn launch_allocates_node_global_state(&self) -> bool {
        matches!(
            &self.cfg.vmm,
            VmmMode::CloudHypervisor(chc) if chc.block_path == BlockPath::KernelNbd
        )
    }

    fn execute_locked(&self, job: NodeJob) -> NodeJobResult {
        // Re-check after acquiring the execution lock.
        if let Some(prev) = self.journal.lock().unwrap().get(&job.job_id) {
            return prev.clone();
        }
        let job_id = job.job_id.clone();
        let cat_id = job.action.cat_id().to_string();
        let result = match self.run_action(&job) {
            Ok(observed) => {
                let lifecycle_boundary = if observed == ObservedState::Warm {
                    self.retire_warm_metering(&cat_id)
                } else {
                    Ok(())
                };
                match lifecycle_boundary
                    .and_then(|()| self.set_runtime_generation(&cat_id, job.cat_generation))
                {
                    Ok(()) => NodeJobResult::ok(&job_id, observed),
                    Err(error) => {
                        tracing::error!(
                            job = %job_id,
                            cat = %cat_id,
                            %error,
                            "final usage checkpoint failed; lifecycle job failed closed"
                        );
                        NodeJobResult::fail(
                            &job_id,
                            self.observed_of(&cat_id),
                            format!("final usage checkpoint failed: {error:#}"),
                            true,
                        )
                    }
                }
            }
            Err(e) => {
                tracing::warn!(job = %job_id, "job failed: {e:#}");
                let observed = self.observed_of(&cat_id);
                if is_activity_changed(&e) {
                    // A rejected suspend still consumed this lifecycle job:
                    // keep the work-status watcher on the control-plane
                    // generation used for cancellation/retry.
                    if let Err(finalize_error) =
                        self.set_runtime_generation(&cat_id, job.cat_generation)
                    {
                        NodeJobResult::fail(
                            &job_id,
                            observed,
                            format!("final usage checkpoint failed: {finalize_error:#}"),
                            true,
                        )
                    } else {
                        NodeJobResult::rejected(&job_id, observed, format!("{e:#}"))
                    }
                } else {
                    NodeJobResult::fail(&job_id, observed, format!("{e:#}"), true)
                }
            }
        };
        // The final state is settled here — `run_action` returned and the
        // generation/metering step has run — so this is the one place the
        // runtime ledger is written (ADR-0028 §1). Doing it here rather than at
        // the individual `cats` mutation sites is what keeps intermediate states
        // (the Running -> Suspended -> Running bounce inside `suspend_cat`, for
        // example) out of the record. Failed jobs are recorded too: a failure
        // can still leave a mutated runtime, such as the Stopping state a failed
        // remote drain converges to.
        if self.cats.lock().unwrap().contains_key(&cat_id) {
            self.persist_cat(&cat_id);
        } else {
            // The Cat is no longer on this node: it reached Cold.
            self.forget_cat(&cat_id);
        }
        // Failures are deliberately not journaled. The journal answers
        // duplicate submissions of one logical job, but the control plane
        // retries a failed start under the same job id and expects real work;
        // replaying the first failure turned "three attempts" into one attempt
        // and two instant echoes of it.
        if result.phase != JobPhase::Failed {
            self.journal.lock().unwrap().insert(job_id, result.clone());
        }
        result
    }

    fn observed_of(&self, cat_id: &str) -> ObservedState {
        self.cats
            .lock()
            .unwrap()
            .get(cat_id)
            .map(|rt| rt.state)
            .unwrap_or(ObservedState::Cold)
    }

    // ------------------------------------------------------------------
    // Start / restore
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub(super) fn start_cat(
        &self,
        cat_id: &str,
        generation: i64,
        volumes: Vec<VolumeGrant>,
        cpus: u32,
        memory_mib: u64,
        warm_restore: bool,
    ) -> Result<ObservedState> {
        if let Some(rt) = self.cats.lock().unwrap().get(cat_id) {
            if rt.state == ObservedState::Running {
                return Ok(ObservedState::Running);
            }
        }
        if !warm_restore {
            // A Cold fallback can arrive while this Node still owns a stale
            // Suspended/Warm runtime (for example after a control-plane
            // reconnect). Tear it down before removing/recreating its runtime
            // directory; otherwise the old VMM keeps the API socket and
            // memory backing open and the new VMM cannot start.
            let existing = self.cats.lock().unwrap().remove(cat_id);
            if let Some(mut runtime) = existing {
                if matches!(
                    runtime.state,
                    ObservedState::Running | ObservedState::Suspended | ObservedState::Warm
                ) {
                    if let Err(error) =
                        self.finalize_usage(runtime.lifecycle_telemetry_target(cat_id))
                    {
                        self.cats
                            .lock()
                            .unwrap()
                            .insert(cat_id.to_string(), runtime);
                        return Err(error);
                    }
                }
                let _ = self.teardown(&mut runtime, TeardownMode::Discard);
                let _ = std::fs::remove_dir_all(&runtime.dir);
            }
        }
        if let VmmMode::CloudHypervisor(chc) = &self.cfg.vmm {
            return self.start_cat_ch(
                &chc.clone(),
                cat_id,
                generation,
                volumes,
                cpus,
                memory_mib,
                warm_restore,
            );
        }
        let dir = self.cfg.state_dir.join("cats").join(cat_id);
        if !warm_restore {
            // Cold boot: no residue may leak process identity or cache.
            let _ = std::fs::remove_dir_all(&dir);
        }
        std::fs::create_dir_all(&dir)?;

        let ctl_sock = short_socket_path(&self.cfg.state_dir, cat_id, "ctl");
        let web_sock = short_socket_path(&self.cfg.state_dir, cat_id, "web");
        let runtime_sock = short_socket_path(&self.cfg.state_dir, cat_id, "runtime");
        symlink_socket(&dir.join("ctl.sock"), &ctl_sock);
        symlink_socket(&dir.join("web.sock"), &web_sock);
        let metering = self.prepare_metering(cat_id)?;
        let mut rt = CatRuntime {
            generation,
            cpus,
            memory_mib,
            state: ObservedState::Starting,
            guest: None,
            boot_id: None,
            blockds: HashMap::new(),
            volumes: volumes.clone(),
            dir: dir.clone(),
            ctl_sock,
            web_sock,
            runtime_sock,
            activity: Arc::new(RuntimeActivity::default()),
            metering,
            ch: None,
        };
        let launch = (|| -> Result<String> {
            for grant in &volumes {
                // FakeVmm never consumes vhost-user; NBD is its only frontend.
                let proc = self.spawn_blockd(cat_id, &dir, grant, 1, None)?;
                let process_id = proc.child.id();
                rt.blockds.insert(grant.disk_id.clone(), proc);
                self.attach_to_metering(&rt, process_id)?;
            }
            self.write_disk_map(&rt)?;
            let state_file = rt.state_file();
            let guest = self.spawn_guest(&rt, warm_restore.then_some(state_file.as_path()))?;
            let process_id = guest.id();
            rt.guest = Some(ProcHandle::Owned(guest));
            self.attach_to_metering(&rt, process_id)?;
            let boot_id = self.wait_guest_ready(&rt)?;
            Ok(boot_id)
        })();

        match launch {
            Ok(boot_id) => {
                if warm_restore
                    && rt.boot_id.is_some()
                    && rt.boot_id.as_deref() != Some(boot_id.as_str())
                {
                    let _ = self.teardown(&mut rt, TeardownMode::Discard);
                    bail!("warm restore produced a different boot id");
                }
                rt.boot_id = Some(boot_id);
                rt.state = ObservedState::Running;
                self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
                Ok(ObservedState::Running)
            }
            Err(e) => {
                let _ = self.teardown(&mut rt, TeardownMode::Cold);
                Err(e)
            }
        }
    }

    /// Cloud Hypervisor start/restore: blockd -> (seed) -> block attach
    /// (kernel NBD device or vhost-user socket) -> CH direct-kernel boot (or
    /// snapshot restore) -> vsock health.
    #[allow(clippy::too_many_arguments)]
    fn start_cat_ch(
        &self,
        chc: &ChConfig,
        cat_id: &str,
        generation: i64,
        volumes: Vec<VolumeGrant>,
        cpus: u32,
        memory_mib: u64,
        warm_restore: bool,
    ) -> Result<ObservedState> {
        let restore_started = Instant::now();
        let dir = self.cfg.state_dir.join("cats").join(cat_id);
        // Warm restore reuses local state (snapshot + nbd mapping).
        let previous = if warm_restore {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("no warm state for cat on this node")?;
            anyhow::ensure!(
                rt.state == ObservedState::Warm,
                "cannot restore from {:?}",
                rt.state
            );
            rt.ch
                .as_ref()
                .map(|c| {
                    (
                        c.nbd.clone(),
                        c.snapshot_dir.clone(),
                        rt.boot_id.clone(),
                        c.network.clone(),
                    )
                })
                .context("warm state missing CH runtime")?
        } else {
            let _ = std::fs::remove_dir_all(&dir);
            (HashMap::new(), None, None, None)
        };
        let (prev_nbd, snapshot_dir, expected_boot, previous_network) = previous;
        if warm_restore {
            if let Some(previous_runtime) = self.cats.lock().unwrap().remove(cat_id) {
                Self::remove_metering_cgroup(previous_runtime.metering.as_ref());
            }
        }
        std::fs::create_dir_all(&dir)?;
        let memory_file = dir.join(ch::GUEST_MEMORY_FILE);
        if warm_restore {
            anyhow::ensure!(
                memory_file.is_file(),
                "warm state is missing Guest memory backing"
            );
        } else {
            ch::prepare_memory_backing(&memory_file, memory_mib)?;
        }

        let mut chrt = ChRuntime {
            api_sock: short_socket_path(&self.cfg.state_dir, cat_id, "chapi"),
            vsock_sock: short_socket_path(&self.cfg.state_dir, cat_id, "vsock"),
            memory_file,
            nbd: HashMap::new(),
            snapshot_dir: None,
            network: previous_network,
        };
        let metering = self.prepare_metering(cat_id)?;
        let mut rt = CatRuntime {
            generation,
            cpus,
            memory_mib,
            state: ObservedState::Starting,
            guest: None,
            boot_id: None,
            blockds: HashMap::new(),
            volumes: volumes.clone(),
            dir: dir.clone(),
            ctl_sock: short_socket_path(&self.cfg.state_dir, cat_id, "ctl"),
            web_sock: short_socket_path(&self.cfg.state_dir, cat_id, "web"),
            runtime_sock: short_socket_path(&self.cfg.state_dir, cat_id, "runtime"),
            activity: Arc::new(RuntimeActivity::default()),
            metering,
            ch: None,
        };
        // Warm may already own a tap from the preserved runtime. Publish the
        // partial CH state immediately so every failure path can tear it down.
        rt.ch = Some(chrt.clone());

        let launch = (|| -> Result<String> {
            // 1. Block backends.
            let blockd_started = Instant::now();
            // Cloud Hypervisor refuses num_queues > boot vCPUs, and the backend
            // must expose exactly the queues the VMM will configure.
            let vhost_user_queues = ch::vhost_user_queues_for(chc, cpus);
            // The root disk is provisioned from the shared golden image instead of
            // streaming a private copy of the rootfs through the block frontend
            // (ADR-0017). Publishing happens once per node, not per launch.
            let seed_image_id = match (&chc.seed_image, warm_restore) {
                (Some(image), false) => Some(self.ensure_image_published(image)?),
                _ => None,
            };
            for grant in &volumes {
                // Data disks have no image.
                let seed = seed_image_id.as_deref().filter(|_| grant.mount_path == "/");
                let proc = self.spawn_blockd(cat_id, &dir, grant, vhost_user_queues, seed)?;
                let process_id = proc.child.id();
                rt.blockds.insert(grant.disk_id.clone(), proc);
                self.attach_to_metering(&rt, process_id)?;
            }
            let blockd_us = blockd_started.elapsed().as_micros();
            // 2. Block attach (root first => /dev/vda). On a kernel-NBD restore
            //    the device indices must match the snapshot exactly; vhost-user
            //    sockets are derived from the Cat and disk id, so they are
            //    already stable across a Warm restore.
            let mut ordered: Vec<&VolumeGrant> = volumes.iter().collect();
            ordered.sort_by_key(|g| g.mount_path != "/");
            let mut disks = Vec::new();
            let block_attach_started = Instant::now();
            for grant in ordered {
                let proc = &rt.blockds[&grant.disk_id];
                match chc.block_path {
                    BlockPath::KernelNbd => {
                        let want = prev_nbd.get(&grant.disk_id).map(|s| s.as_str());
                        let dev = ch::nbd_attach(chc, &proc.socket, want)?;
                        chrt.nbd.insert(grant.disk_id.clone(), dev.clone());
                        // Record the attachment before any later fallible setup
                        // so the shared failure teardown cannot leak it.
                        rt.ch = Some(chrt.clone());
                        disks.push(ch::file_disk_arg(&dev, chc.block_direct));
                    }
                    BlockPath::VhostUser => {
                        let socket = proc
                            .vhost_user_socket
                            .as_ref()
                            .context("blockd was started without a vhost-user socket")?;
                        disks.push(ch::vhost_user_disk_arg(
                            socket,
                            vhost_user_queues,
                            chc.vhost_user_queue_size,
                        )?);
                    }
                }
            }
            let block_attach_us = block_attach_started.elapsed().as_micros();
            rt.ch = Some(chrt.clone());
            if !warm_restore {
                chrt.network = ch::prepare_network(chc, cat_id)?;
                rt.ch = Some(chrt.clone());
            }
            // 3. VMM. Store the child in `rt` immediately so a failure in
            //    readiness/health still lets `teardown` kill it (no orphan
            //    holding the api socket).
            let serial_log = dir.join("serial.log");
            let vmm_spawn_started = Instant::now();
            let vmm = ch::spawn_vmm(&ch::ChSpawn {
                cfg: chc,
                api_sock: &chrt.api_sock,
                vsock_sock: &chrt.vsock_sock,
                serial_log: &serial_log,
                cpus,
                memory_mib,
                memory_file: Some(&chrt.memory_file),
                disks: &disks,
                restore_from: snapshot_dir.as_deref(),
                network: chrt.network.as_ref(),
            })?;
            let process_id = vmm.id();
            rt.guest = Some(ProcHandle::Owned(vmm));
            self.attach_to_metering(&rt, process_id)?;
            let vmm_spawn_us = vmm_spawn_started.elapsed().as_micros();
            rt.ch = Some(chrt.clone());
            let api_ready_started = Instant::now();
            ch::wait_api_ready(&chrt.api_sock, rt.guest.as_mut().unwrap())?;
            let api_ready_us = api_ready_started.elapsed().as_micros();
            let resume_started = Instant::now();
            if warm_restore {
                ch::resume(&chrt.api_sock)?;
            }
            let resume_us = resume_started.elapsed().as_micros();
            // 4. Guest agent over vsock.
            let conn = GuestConn::Vsock(chrt.vsock_sock.clone(), GUEST_VSOCK_PORT);
            // Keep this below the control plane's 60-second node-job timeout
            // so a failed start tears down its partial VMM before the control
            // plane can retry the Cat on the same node.
            let deadline = Instant::now() + Duration::from_secs(30);
            let guest_health_started = Instant::now();
            loop {
                if let Ok(mut client) = conn.connect() {
                    if let Ok((boot_id, _)) = client.health() {
                        if warm_restore {
                            tracing::info!(
                                cat = cat_id,
                                block_path = chc.block_path.as_str(),
                                total_us = restore_started.elapsed().as_micros(),
                                blockd_us,
                                block_attach_us,
                                vmm_spawn_us,
                                api_ready_us,
                                resume_us,
                                guest_health_us = guest_health_started.elapsed().as_micros(),
                                "warm restore phase timings"
                            );
                        }
                        return Ok(boot_id);
                    }
                }
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "guest never became healthy over vsock"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        })();

        match launch {
            Ok(boot_id) => {
                if warm_restore
                    && expected_boot.is_some()
                    && expected_boot.as_deref() != Some(&boot_id)
                {
                    rt.ch = Some(chrt);
                    let _ = self.teardown(&mut rt, TeardownMode::Discard);
                    bail!("warm restore produced a different kernel boot id");
                }
                rt.boot_id = Some(boot_id);
                rt.state = ObservedState::Running;
                rt.ch = Some(chrt);
                self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
                Ok(ObservedState::Running)
            }
            Err(e) => {
                rt.ch = Some(chrt);
                let _ = self.teardown(&mut rt, TeardownMode::Discard);
                Err(e)
            }
        }
    }

    // ------------------------------------------------------------------
    // Stop / cleanup
    // ------------------------------------------------------------------

    pub(super) fn stop_cat(&self, cat_id: &str, mode: TeardownMode) -> Result<ObservedState> {
        let Some(mut rt) = self.cats.lock().unwrap().remove(cat_id) else {
            let dir = self.cfg.state_dir.join("cats").join(cat_id);
            match &mode {
                TeardownMode::Destroy {
                    disposable_root_disk_ids,
                    retained_persistent_disk_ids,
                } if dir.exists() && retained_persistent_disk_ids.is_empty() => {
                    self.remove_unsupervised_destroy_residue(&dir, disposable_root_disk_ids)?;
                }
                TeardownMode::Cold | TeardownMode::Destroy { .. } if dir.exists() => {
                    // After an agent restart the in-memory supervisor may be
                    // gone while an independently-owned disk journal remains.
                    // Only a root-only Destroy plan is sufficient authority to
                    // discard that residue.
                    bail!(
                        "cat runtime directory {} exists but is not supervised; refusing to discard possible persistent durability state",
                        dir.display()
                    );
                }
                TeardownMode::Discard => {
                    let _ = std::fs::remove_dir_all(&dir);
                }
                _ => {}
            }
            return Ok(ObservedState::Cold);
        };
        if matches!(
            rt.state,
            ObservedState::Running | ObservedState::Suspended | ObservedState::Warm
        ) {
            if let Err(error) = self.finalize_usage(rt.lifecycle_telemetry_target(cat_id)) {
                self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
                return Err(error);
            }
        }
        let prior_state = rt.state;
        if let Err(error) = self.teardown(&mut rt, mode) {
            // If the Guest is already gone, only the forced remote drain is
            // outstanding. Keep the blockd processes and local journals alive
            // under an explicit transitional state so a retry can finish it.
            if rt.guest.is_none() {
                rt.state = ObservedState::Stopping;
            } else {
                rt.state = prior_state;
            }
            self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
            return Err(error);
        }
        let _ = std::fs::remove_dir_all(&rt.dir);
        Ok(ObservedState::Cold)
    }

    /// Teardown one runtime. Cold preserves and drains every disk. Destroy may
    /// discard only the RootDisks explicitly authorized by the control plane;
    /// every remaining blockd is still a fail-closed remote-drain boundary.
    fn teardown(&self, rt: &mut CatRuntime, mode: TeardownMode) -> Result<()> {
        let persistent_to_flush = match &mode {
            TeardownMode::Destroy {
                disposable_root_disk_ids,
                retained_persistent_disk_ids,
            } => Self::validate_destroy_plan(
                rt,
                disposable_root_disk_ids,
                retained_persistent_disk_ids,
            )?,
            _ => Vec::new(),
        };
        let needs_guest_flush = matches!(mode, TeardownMode::Cold)
            || matches!(mode, TeardownMode::Destroy { .. }) && !persistent_to_flush.is_empty();
        if needs_guest_flush && rt.guest.is_some() {
            if rt.state == ObservedState::Suspended {
                // A paused guest cannot flush; wake it first.
                match &rt.ch {
                    Some(chrt) => {
                        ch::resume(&chrt.api_sock)?;
                    }
                    None => {
                        if let Some(g) = &rt.guest {
                            g.signal(libc::SIGCONT);
                        }
                    }
                }
            }
            let mut client = rt
                .conn()
                .connect()
                .context("connect guest for final sync")?;
            match &mode {
                TeardownMode::Cold => client.syncfs().context("guest final syncfs")?,
                TeardownMode::Destroy { .. } => {
                    for disk_id in &persistent_to_flush {
                        client
                            .flush_disk(disk_id)
                            .with_context(|| format!("guest final flush of {disk_id}"))?;
                    }
                }
                TeardownMode::Discard => unreachable!("discard does not flush the guest"),
            }
            if rt.ch.is_none() {
                let _ = client.shutdown();
            }
        }
        if let Some(mut vmm) = rt.guest.take() {
            match &rt.ch {
                Some(chrt) => ch::shutdown_vmm(&chrt.api_sock, &mut vmm),
                None => vmm.kill_and_reap(),
            }
        }
        if let TeardownMode::Destroy {
            disposable_root_disk_ids,
            ..
        } = &mode
        {
            self.discard_root_runtimes(rt, disposable_root_disk_ids);
        }
        if !matches!(mode, TeardownMode::Discard) {
            // syncfs pushed the guest page cache into the engines; on relaxed
            // volumes that only advances the local watermark. The VMM is gone,
            // so no late fsync can slip in behind this mandatory drain.
            let drained = rt.blockds.values().try_for_each(|proc| {
                proc.drain()
                    .with_context(|| format!("final drain of {}", proc.grant.disk_id))
            });
            if let Err(error) = drained {
                // Returning here used to skip the kernel-NBD detach below. A
                // blockd that exited on its own can never answer a drain, so
                // every attempt took this path and left its /dev/nbdN attached
                // to nothing -- the leak that deadlocked a host (issue #79).
                self.detach_exited_blockd_devices(rt);
                return Err(error);
            }
        }
        if let (Some(chrt), VmmMode::CloudHypervisor(chc)) = (&rt.ch, &self.cfg.vmm) {
            for dev in chrt.nbd.values() {
                ch::nbd_detach(chc, dev);
            }
            if let Some(network) = &chrt.network {
                ch::remove_network(chc, network);
            }
        }
        let cat_dir = rt.dir.clone();
        for (_, mut p) in rt.blockds.drain() {
            p.child.kill_and_reap();
            p.remove_socket_files(&cat_dir);
        }
        if let Some(chrt) = &mut rt.ch {
            let _ = std::fs::remove_file(&chrt.api_sock);
            let _ = std::fs::remove_file(&chrt.vsock_sock);
            chrt.nbd.clear();
            chrt.network = None;
        }
        let _ = std::fs::remove_file(rt.ctl_socket());
        let _ = std::fs::remove_file(rt.web_socket());
        let _ = std::fs::remove_file(rt.runtime_socket());
        Self::remove_metering_cgroup(rt.metering.as_ref());
        rt.state = ObservedState::Cold;
        Ok(())
    }

    /// Detach the kernel-NBD devices of blockds that have already exited.
    ///
    /// Teardown normally detaches at the end, after the drain. That is too
    /// late for a blockd that died on its own: the drain fails first, and the
    /// device stays attached to a server that no longer exists -- a pool slot
    /// no later Cat can use, on every retry, forever. Only exited
    /// blockds are reclaimed here -- a live one whose drain failed for another
    /// reason (an unreachable object store, say) is still serving its device
    /// and a retry can still publish its writes.
    fn detach_exited_blockd_devices(&self, rt: &mut CatRuntime) {
        let (Some(chrt), VmmMode::CloudHypervisor(chc)) = (&mut rt.ch, &self.cfg.vmm) else {
            return;
        };
        for (disk_id, proc) in &mut rt.blockds {
            // `exited` rather than a bare pid check: an adopted blockd whose
            // pid no longer names the recorded process counts as gone, which
            // is exactly the case whose device needs reclaiming.
            if !proc.child.exited().unwrap_or(false) {
                continue;
            }
            let Some(device) = chrt.nbd.remove(disk_id) else {
                continue;
            };
            tracing::warn!(
                disk = %disk_id,
                device = %device,
                "detaching the NBD device of a blockd that exited on its own"
            );
            ch::nbd_detach(chc, &device);
        }
    }

    fn discard_root_runtimes(&self, rt: &mut CatRuntime, root_disk_ids: &[String]) {
        if let (Some(chrt), VmmMode::CloudHypervisor(chc)) = (&mut rt.ch, &self.cfg.vmm) {
            for disk_id in root_disk_ids {
                if let Some(device) = chrt.nbd.remove(disk_id) {
                    ch::nbd_detach(chc, &device);
                }
            }
        }
        for disk_id in root_disk_ids {
            if let Some(mut proc) = rt.blockds.remove(disk_id) {
                proc.child.kill_and_reap();
                proc.remove_socket_files(&rt.dir);
            }
            let _ = std::fs::remove_dir_all(volume_data_dir(&rt.dir, disk_id));
        }
        rt.volumes
            .retain(|volume| !root_disk_ids.contains(&volume.disk_id));
    }

    fn validate_destroy_plan(
        rt: &CatRuntime,
        disposable_root_disk_ids: &[String],
        retained_persistent_disk_ids: &[String],
    ) -> Result<Vec<String>> {
        let disposable: HashSet<&str> = disposable_root_disk_ids
            .iter()
            .map(String::as_str)
            .collect();
        let retained: HashSet<&str> = retained_persistent_disk_ids
            .iter()
            .map(String::as_str)
            .collect();
        anyhow::ensure!(
            disposable.is_disjoint(&retained),
            "destroy disk plan marks one disk as both disposable and retained"
        );
        let mut persistent_to_flush = Vec::new();
        for disk_id in rt.blockds.keys() {
            match (
                disposable.contains(disk_id.as_str()),
                retained.contains(disk_id.as_str()),
            ) {
                (true, false) => {}
                (false, true) => persistent_to_flush.push(disk_id.clone()),
                (false, false) => {
                    anyhow::bail!("destroy disk plan does not classify attached disk {disk_id}")
                }
                (true, true) => unreachable!("disjoint sets checked above"),
            }
        }
        Ok(persistent_to_flush)
    }

    fn remove_unsupervised_destroy_residue(
        &self,
        dir: &Path,
        disposable_root_disk_ids: &[String],
    ) -> Result<()> {
        anyhow::ensure!(
            !disposable_root_disk_ids.is_empty(),
            "destroy supplied no disposable RootDisk"
        );
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(disk_id) = name.strip_prefix(VOLUME_DIR_PREFIX) {
                anyhow::ensure!(
                    disposable_root_disk_ids.iter().any(|root| root == disk_id),
                    "unsupervised runtime contains non-disposable disk {disk_id}"
                );
            }
        }
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod teardown_tests {
    use super::*;
    use crate::admission::WakeBudget;
    use cats_api::resources::DiskDurability;
    use cats_storage::AdapterSelection;
    use std::os::unix::fs::PermissionsExt;

    /// A blockd that exited on its own must give its kernel NBD device back,
    /// even though teardown cannot finish.
    ///
    /// The mandatory final drain runs before the detach. A dead blockd can
    /// never answer it, so teardown returned at the drain and the detach below
    /// it never ran: every retry took the same path, and the device stayed
    /// connected to a server that no longer existed until someone found it by
    /// hand (issue #79). The drain failure is still reported -- it means
    /// unpublished writes, which is not this fix's to swallow.
    #[test]
    fn a_dead_blockd_gives_its_nbd_device_back_even_when_the_drain_fails() {
        let temp = tempfile::tempdir().unwrap();
        let calls = temp.path().join("nbd-client-calls");
        let nbd_client = temp.path().join("nbd-client");
        std::fs::write(
            &nbd_client,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&nbd_client, std::fs::Permissions::from_mode(0o755)).unwrap();

        let adapter = AdapterSelection::new("unused", cats_storage::AdapterConfig::default());
        let runtime = NodeRuntime::new(NodeConfig {
            node_id: "node-a".to_string(),
            state_dir: temp.path().to_path_buf(),
            blockd_bin: PathBuf::from("unused-blockd"),
            guest_agent_bin: PathBuf::from("unused-guest-agent"),
            metadata_store: adapter.clone(),
            object_store: adapter,
            blockd_lease_ttl_ms: 1_000,
            blockd_max_staged_bytes: cats_api::blockd::DEFAULT_MAX_STAGED_BYTES,
            blockd_max_staged_packs: cats_api::blockd::DEFAULT_MAX_STAGED_PACKS,
            blockd_max_local_bytes: cats_api::blockd::DEFAULT_MAX_LOCAL_BYTES,
            metering_cgroup_root: None,
            vmm: VmmMode::CloudHypervisor(ChConfig {
                block_direct: false,
                ch_bin: PathBuf::from("unused-ch"),
                kernel: PathBuf::from("unused-kernel"),
                initramfs: None,
                cmdline: String::new(),
                seed_image: None,
                block_path: BlockPath::KernelNbd,
                vhost_user_queues: 1,
                vhost_user_queue_size: 256,
                nbd_client_bin: nbd_client,
                nbd_devices: 8,
                network_cidr: None,
                ip_bin: PathBuf::from("unused-ip"),
            }),
            wake_budget: WakeBudget::default(),
        })
        .unwrap();

        let mut dead = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        dead.wait().unwrap();
        let dir = temp.path().join("cat-a");
        std::fs::create_dir_all(&dir).unwrap();
        let mut rt = CatRuntime {
            generation: 1,
            cpus: 1,
            memory_mib: 256,
            state: ObservedState::Running,
            guest: None,
            boot_id: None,
            blockds: HashMap::from([(
                "dsk_root".to_string(),
                BlockdProc {
                    child: crate::proc::ProcHandle::Owned(dead),
                    // Same name spawn_blockd gives it, so a failure here reads
                    // the way it would in production. Nothing writes it in this
                    // test; an absent log is reported as absent.
                    log_path: dir.join("blockd-dsk_root.log"),
                    socket: dir.join("nbd.sock"),
                    vhost_user_socket: None,
                    control_socket: dir.join("ctl.sock"),
                    grant: VolumeGrant {
                        disk_id: "dsk_root".to_string(),
                        volume_id: "vol_a".to_string(),
                        attachment_id: "att_a".to_string(),
                        epoch: 1,
                        size_bytes: 1024,
                        mount_path: "/".to_string(),
                        durability: DiskDurability::Strict,
                    },
                },
            )]),
            volumes: Vec::new(),
            dir: dir.clone(),
            ctl_sock: dir.join("ctl"),
            web_sock: dir.join("web"),
            runtime_sock: dir.join("runtime"),
            activity: Arc::new(RuntimeActivity::default()),
            metering: None,
            ch: Some(ChRuntime {
                nbd: HashMap::from([("dsk_root".to_string(), "/dev/nbd7".to_string())]),
                ..ChRuntime::default()
            }),
        };

        let error = runtime
            .teardown(&mut rt, TeardownMode::Cold)
            .expect_err("a dead blockd cannot be drained");
        assert!(
            format!("{error:#}").contains("final drain of dsk_root"),
            "the drain failure must still be reported: {error:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap_or_default().trim(),
            "-d /dev/nbd7",
            "the device of a blockd that exited on its own must be detached"
        );
    }
}
