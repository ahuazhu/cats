use super::*;

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
        // Suspended resume is the one action that allocates no node-global
        // resource: it resumes a VMM that is already up (no blockd child, no
        // NBD device, no tap). It therefore runs under a per-Cat lock so that
        // several Cats wake in parallel, bounded by the wake admission budget
        // (ADR-0002 §8). The 2026-07-21 run measured ten concurrent restores
        // at 0.53 s versus 0.380 s for one, so node-wide serialization costs
        // roughly 7x on a wake storm for no correctness benefit.
        //
        // Everything else keeps the node-wide lock. In particular Warm
        // `RestoreCat` goes through `start_cat`, which allocates node-global
        // NBD devices and tap slots; making those concurrency-safe is separate
        // work. Warm is still charged its resume commitment, so the ceiling is
        // already in place for when that lands.
        // The per-Cat lock is unconditional: it is what keeps "one job per Cat at
        // a time" true, so a stop can never interleave with a start of the same
        // Cat. The node-wide lock is then layered on top only for actions that
        // touch node-global state. The order is always per-Cat then node-wide, so
        // a thread holding the node-wide lock never waits for a per-Cat lock and
        // the pair cannot deadlock.
        let needs_node_lock = match &job.action {
            NodeJobAction::ResumeCat { .. } => false,
            // A launch is independent of other Cats unless it has to pick a
            // node-global resource; see `launch_allocates_node_global_state`.
            NodeJobAction::StartCat { .. } | NodeJobAction::RestoreCat { .. } => {
                self.launch_allocates_node_global_state()
            }
            _ => true,
        };
        let per_cat = self.cat_lock(job.action.cat_id());
        let _cat_guard = per_cat.lock().unwrap();
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
                let _ = self.teardown(&mut runtime, false);
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
            rt.guest = Some(guest);
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
                    let _ = self.teardown(&mut rt, false);
                    bail!("warm restore produced a different boot id");
                }
                rt.boot_id = Some(boot_id);
                rt.state = ObservedState::Running;
                self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
                Ok(ObservedState::Running)
            }
            Err(e) => {
                let _ = self.teardown(&mut rt, true);
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
            rt.guest = Some(vmm);
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
                    let _ = self.teardown(&mut rt, false);
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
                let _ = self.teardown(&mut rt, false);
                Err(e)
            }
        }
    }

    // ------------------------------------------------------------------
    // Stop / cleanup
    // ------------------------------------------------------------------

    pub(super) fn stop_cat(&self, cat_id: &str, graceful: bool) -> Result<ObservedState> {
        let Some(mut rt) = self.cats.lock().unwrap().remove(cat_id) else {
            let dir = self.cfg.state_dir.join("cats").join(cat_id);
            if graceful && dir.exists() {
                // After an agent restart the in-memory supervisor may be gone
                // while blockd journals still exist. A graceful lifecycle
                // request must never equate "not in the map" with "safe to
                // delete"; recovery/cleanup needs an explicit path.
                bail!(
                    "cat runtime directory {} exists but is not supervised; refusing to discard possible local durability state",
                    dir.display()
                );
            }
            if !graceful {
                let _ = std::fs::remove_dir_all(&dir);
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
        if let Err(error) = self.teardown(&mut rt, graceful) {
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

    /// Teardown one runtime. A graceful transition is fail-closed: after the
    /// Guest page cache is frozen and the VMM is gone, every relaxed blockd
    /// must reach its remote durability watermark before its journal or lease
    /// may be discarded.
    fn teardown(&self, rt: &mut CatRuntime, graceful: bool) -> Result<()> {
        if graceful && rt.guest.is_some() {
            if rt.state == ObservedState::Suspended {
                // A paused guest cannot flush; wake it first.
                match &rt.ch {
                    Some(chrt) => {
                        ch::resume(&chrt.api_sock)?;
                    }
                    None => {
                        if let Some(g) = &rt.guest {
                            signal(g, libc::SIGCONT);
                        }
                    }
                }
            }
            let mut client = rt
                .conn()
                .connect()
                .context("connect guest for final sync")?;
            client.syncfs().context("guest final syncfs")?;
            if rt.ch.is_none() {
                let _ = client.shutdown();
            }
        }
        if let Some(mut vmm) = rt.guest.take() {
            match &rt.ch {
                Some(chrt) => ch::shutdown_vmm(&chrt.api_sock, &mut vmm),
                None => {
                    let _ = vmm.kill();
                    let _ = vmm.wait();
                }
            }
        }
        if graceful {
            // syncfs pushed the guest page cache into the engines; on relaxed
            // volumes that only advances the local watermark. The VMM is gone,
            // so no late fsync can slip in behind this mandatory drain.
            for proc in rt.blockds.values() {
                proc.drain()
                    .with_context(|| format!("final drain of {}", proc.grant.disk_id))?;
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
            let _ = p.child.kill();
            let _ = p.child.wait();
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
}
