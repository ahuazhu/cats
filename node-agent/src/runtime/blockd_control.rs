use super::*;
use cats_api::blockd::{BlockdControlCommand, BlockdControlResponse, DurabilityStatus};
use cats_block_client::NbdClient;

pub(super) struct BlockdProc {
    pub(super) child: ProcHandle,
    /// NBD socket: readiness probe, golden-root seeding and recovery tooling.
    /// Always present, on both block paths.
    pub(super) socket: PathBuf,
    /// vhost-user socket the VMM consumes, when the Cat runs on that path.
    pub(super) vhost_user_socket: Option<PathBuf>,
    /// Control socket for host-side commands (`drain`/`status`, ADR-0022).
    pub(super) control_socket: PathBuf,
    pub(super) grant: VolumeGrant,
}

pub(super) const BLOCKD_STATUS_TIMEOUT: Duration = Duration::from_millis(500);
// A forced drain contains real object-store and metadata-store I/O. Keep its
// deadline below the control plane's 60-second node-job timeout, but do not
// reuse the heartbeat status probe's 500 ms deadline: measured remote-drain
// tails on metal legitimately exceed that.
const BLOCKD_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCKD_CONTROL_WRITE_TIMEOUT: Duration = Duration::from_millis(500);

impl BlockdProc {
    fn command(
        control_socket: &Path,
        disk_id: &str,
        command: BlockdControlCommand,
        read_timeout: Duration,
    ) -> Result<String> {
        use std::io::{BufRead, BufReader, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(control_socket)
            .with_context(|| format!("connect blockd control for {disk_id}"))?;
        stream.set_read_timeout(Some(read_timeout))?;
        stream.set_write_timeout(Some(BLOCKD_CONTROL_WRITE_TIMEOUT))?;
        stream.write_all(command.as_wire().as_bytes())?;
        stream.write_all(b"\n")?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        match BlockdControlResponse::parse_wire(&line) {
            Ok(BlockdControlResponse::Ok(payload)) => Ok(payload),
            Ok(BlockdControlResponse::Error(_)) | Err(_) => {
                bail!("{command} of {disk_id} failed: {}", line.trim())
            }
        }
    }

    /// Publish everything the engine has staged. The forced flush points of
    /// the relaxed contract call this after the guest-side flush; on a strict
    /// volume the queue is already empty and it returns immediately.
    pub(super) fn drain(&self) -> Result<()> {
        Self::drain_at(&self.control_socket, &self.grant.disk_id)
    }

    pub(super) fn drain_at(control_socket: &Path, disk_id: &str) -> Result<()> {
        Self::command(
            control_socket,
            disk_id,
            BlockdControlCommand::Drain,
            BLOCKD_DRAIN_TIMEOUT,
        )
        .map(|_| ())
    }

    pub(super) fn durability_status_at(
        control_socket: &Path,
        disk_id: &str,
    ) -> Result<DiskDurabilityTelemetry> {
        let payload = Self::command(
            control_socket,
            disk_id,
            BlockdControlCommand::Status,
            BLOCKD_STATUS_TIMEOUT,
        )?;
        let status: DurabilityStatus =
            serde_json::from_str(&payload).context("decode blockd durability status")?;
        Ok(DiskDurabilityTelemetry {
            disk_id: disk_id.to_string(),
            mode: status.mode,
            local_durable_generation: status.local_durable_generation,
            remote_durable_generation: status.remote_durable_generation,
            unpublished_generations: status.unpublished_generations as u64,
            unpublished_bytes: status.unpublished_bytes,
            oldest_unpublished_age_ms: status.oldest_unpublished_age_ms,
            max_unpublished_generations: status.max_unpublished_generations as u64,
            max_unpublished_bytes: status.max_unpublished_bytes,
            local_allocated_bytes: status.local_allocated_bytes,
            local_accounted_bytes: status.local_accounted_bytes,
            max_local_bytes: status.max_local_bytes,
            evicted_cache_chunks: status.evicted_cache_chunks,
            backpressured: status.backpressured,
            fenced: status.fenced,
            last_publish_error: status.last_publish_error,
        })
    }

    pub(super) fn remove_socket_files(&self, cat_dir: &Path) {
        let disk_id = &self.grant.disk_id;
        for socket in [
            Some(&self.socket),
            self.vhost_user_socket.as_ref(),
            Some(&self.control_socket),
        ]
        .into_iter()
        .flatten()
        {
            let _ = std::fs::remove_file(socket);
        }
        for link in [
            cat_dir.join(format!("nbd-{disk_id}.sock")),
            cat_dir.join(format!("vhu-{disk_id}.sock")),
            cat_dir.join(format!("ctl-{disk_id}.sock")),
        ] {
            let _ = std::fs::remove_file(link);
        }
    }
}

impl NodeRuntime {
    /// Publish the golden root once and return its image id (ADR-0017).
    ///
    /// Runs `cats-blockd --publish-image`, which needs only the object store, so
    /// the node needs no object-store wiring of its own and publishing stays in
    /// the one component that already speaks every adapter. Idempotent, so a
    /// second node — or a restart — costs one manifest HEAD.
    pub(super) fn ensure_image_published(&self, image: &Path) -> Result<String> {
        let mut cached = self.seed_image_id.lock().unwrap();
        if let Some(image_id) = cached.as_ref() {
            return Ok(image_id.clone());
        }
        let started = Instant::now();
        let mut cmd = Command::new(&self.cfg.blockd_bin);
        cmd.arg("--publish-image")
            .arg(image)
            .arg("--object-store-adapter")
            .arg(&self.cfg.object_store.name);
        for option in self.cfg.object_store.config.to_cli() {
            cmd.arg("--object-store-option").arg(option);
        }
        let output = cmd.output().context("run cats-blockd --publish-image")?;
        if !output.status.success() {
            bail!(
                "publishing {} failed: {} {}",
                image.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .last()
                    .unwrap_or_default()
            );
        }
        let image_id = String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("IMAGE ").map(|id| id.trim().to_string()))
            .context("cats-blockd --publish-image printed no image id")?;
        tracing::info!(
            image = %image.display(),
            image_id = %image_id,
            publish_ms = started.elapsed().as_millis(),
            "published the golden root"
        );
        *cached = Some(image_id.clone());
        Ok(image_id)
    }

    pub(super) fn spawn_blockd(
        &self,
        cat_id: &str,
        cat_dir: &Path,
        grant: &VolumeGrant,
        vhost_user_queues: usize,
        seed_image_id: Option<&str>,
    ) -> Result<BlockdProc> {
        let socket = short_socket_path(
            &self.cfg.state_dir,
            cat_id,
            &format!("nbd-{}", grant.disk_id),
        );
        symlink_socket(
            &cat_dir.join(format!("nbd-{}.sock", grant.disk_id)),
            &socket,
        );
        // The Guest's data path. Both frontends serve one engine in one
        // process, so seeding and recovery keep using NBD while the VMM uses
        // vhost-user (spec §7.1).
        let vhost_user_socket = match &self.cfg.vmm {
            VmmMode::CloudHypervisor(chc) if chc.block_path == BlockPath::VhostUser => {
                let socket = short_socket_path(
                    &self.cfg.state_dir,
                    cat_id,
                    &format!("vhu-{}", grant.disk_id),
                );
                symlink_socket(
                    &cat_dir.join(format!("vhu-{}.sock", grant.disk_id)),
                    &socket,
                );
                Some(socket)
            }
            _ => None,
        };
        let data_dir = cat_dir.join(format!("vol-{}", grant.disk_id));
        let mut cmd = Command::new(&self.cfg.blockd_bin);
        cmd.arg("--volume-id")
            .arg(&grant.volume_id)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--attachment-id")
            .arg(&grant.attachment_id)
            .arg("--metadata-store-adapter")
            .arg(&self.cfg.metadata_store.name)
            .arg("--object-store-adapter")
            .arg(&self.cfg.object_store.name)
            .arg("--listen-unix")
            .arg(&socket)
            .arg("--create-volume-size")
            .arg(grant.size_bytes.to_string())
            .arg("--lease-ttl-ms")
            .arg(self.cfg.blockd_lease_ttl_ms.to_string())
            .arg("--max-staged-bytes")
            .arg(self.cfg.blockd_max_staged_bytes.to_string())
            .arg("--max-staged-packs")
            .arg(self.cfg.blockd_max_staged_packs.to_string())
            .arg("--max-local-bytes")
            .arg(self.cfg.blockd_max_local_bytes.to_string());
        let control_socket = short_socket_path(
            &self.cfg.state_dir,
            cat_id,
            &format!("ctl-{}", grant.disk_id),
        );
        symlink_socket(
            &cat_dir.join(format!("ctl-{}.sock", grant.disk_id)),
            &control_socket,
        );
        cmd.arg("--listen-control").arg(&control_socket);
        if grant.durability == cats_api::resources::DiskDurability::Relaxed {
            cmd.arg("--durability").arg("relaxed");
        }
        if let Some(image_id) = seed_image_id {
            // Provision from the already-published image: one manifest GET plus a
            // map write, no data bytes (ADR-0017). Safe unconditionally, because a
            // volume that already has a generation is left alone.
            cmd.arg("--seed-image-id").arg(image_id);
        }
        if let (Some(socket), VmmMode::CloudHypervisor(chc)) = (&vhost_user_socket, &self.cfg.vmm) {
            cmd.arg("--listen-vhost-user")
                .arg(socket)
                .arg("--vhost-user-queues")
                .arg(vhost_user_queues.to_string())
                .arg("--vhost-user-queue-size")
                .arg(chc.vhost_user_queue_size.to_string());
        }
        let log = std::fs::File::create(cat_dir.join(format!("blockd-{}.log", grant.disk_id)))
            .context("create blockd log")?;
        for option in self.cfg.metadata_store.config.to_cli() {
            cmd.arg("--metadata-store-option").arg(option);
        }
        for option in self.cfg.object_store.config.to_cli() {
            cmd.arg("--object-store-option").arg(option);
        }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(log)
            .env_remove("CATS_CRASH_POINT")
            .spawn()
            .context("spawn cats-blockd")?;
        let mut proc = BlockdProc {
            child: ProcHandle::Owned(child),
            socket,
            vhost_user_socket,
            control_socket,
            grant: grant.clone(),
        };
        self.wait_blockd_ready(&mut proc)
            .with_context(|| format!("blockd for {} never became ready", grant.disk_id))?;
        Ok(proc)
    }

    fn wait_blockd_ready(&self, proc: &mut BlockdProc) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(client) = NbdClient::connect_unix(&proc.socket) {
                let _ = client.disconnect();
                return Ok(());
            }
            if proc.child.exited()? {
                bail!("cats-blockd exited during startup (lease held or bad config?)");
            }
            if Instant::now() > deadline {
                bail!("timed out waiting for blockd socket");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
