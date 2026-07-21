//! Per-node runtime: executes NodeJobs by supervising one guest-agent
//! process ("the VM") and one cats-blockd process per attachment.
//!
//! VMM seam: this file implements the FakeVmm — a host process stands in
//! for Cloud Hypervisor, SIGSTOP/SIGCONT stand in for vCPU pause/resume,
//! and the guest state file stands in for the memory snapshot. Every block
//! byte still flows through the real cats-blockd engine, so storage
//! semantics (leases, FLUSH durability, cold restore) are exercised for
//! real. The Cloud Hypervisor mode (`VmmMode::CloudHypervisor`, Linux+KVM)
//! is implemented in `ch.rs`: direct-kernel boot, kernel-NBD block path,
//! vsock guest control, vm.pause/resume and vm.snapshot/--restore.
//!
//! Job idempotency: results are journaled by job_id and replayed for
//! duplicate submissions (arch doc §17.4). The journal is in-memory; a node
//! restart loses it, which is safe because every action is itself
//! idempotent at the process level.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use cats_api::nodejob::{NodeJob, NodeJobAction, NodeJobResult, VolumeGrant};
use cats_api::resources::ObservedState;
use cats_guest_agent::DiskMapEntry;

use crate::ch::{self, ChConfig, ChRuntime, GUEST_VSOCK_PORT};
use crate::guest_client::GuestClient;

/// Which VMM this node runs.
#[derive(Debug, Clone)]
pub enum VmmMode {
    /// Host-process guest (dev/tests on any OS).
    Fake,
    /// Real microVMs via Cloud Hypervisor (Linux + KVM).
    CloudHypervisor(ChConfig),
}

/// Durable object store the node hands to its blockd children.
///
/// S3 credentials are NOT part of this config: `cats-blockd` reads
/// `CATS_S3_ACCESS_KEY` / `CATS_S3_SECRET_KEY` from its environment, which
/// the node agent's own environment provides (systemd `EnvironmentFile=` in
/// the AWS deployment).
#[derive(Debug, Clone)]
pub enum BlobBackend {
    File {
        root: PathBuf,
    },
    S3 {
        endpoint: String,
        bucket: String,
        region: String,
        prefix: String,
    },
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub state_dir: PathBuf,
    pub blockd_bin: PathBuf,
    pub guest_agent_bin: PathBuf,
    pub meta_sqlite: PathBuf,
    pub blob: BlobBackend,
    pub blockd_lease_ttl_ms: i64,
    pub vmm: VmmMode,
}

struct BlockdProc {
    child: Child,
    socket: PathBuf,
    grant: VolumeGrant,
}

struct CatRuntime {
    generation: i64,
    cpus: u32,
    memory_mib: u64,
    state: ObservedState,
    guest: Option<Child>,
    boot_id: Option<String>,
    blockds: HashMap<String, BlockdProc>,
    /// Grants remembered for Warm restore.
    volumes: Vec<VolumeGrant>,
    dir: PathBuf,
    /// Short bind paths (see `short_socket_path`).
    ctl_sock: PathBuf,
    web_sock: PathBuf,
    /// Present only in Cloud Hypervisor mode.
    ch: Option<ChRuntime>,
}

/// How to reach a cat's guest agent (cloneable so locks can be dropped
/// before the potentially slow connect/health exchange).
#[derive(Debug, Clone)]
pub enum GuestConn {
    Unix(PathBuf),
    Vsock(PathBuf, u32),
}

impl GuestConn {
    pub fn connect(&self) -> Result<GuestClient> {
        match self {
            GuestConn::Unix(path) => GuestClient::connect(path),
            GuestConn::Vsock(path, port) => GuestClient::connect_hybrid_vsock(path, *port),
        }
    }
}

impl CatRuntime {
    /// Guest control connection: hybrid vsock in CH mode, unix otherwise.
    fn conn(&self) -> GuestConn {
        match &self.ch {
            Some(chrt) => GuestConn::Vsock(chrt.vsock_sock.clone(), GUEST_VSOCK_PORT),
            None => GuestConn::Unix(self.ctl_sock.clone()),
        }
    }
    fn ctl_socket(&self) -> PathBuf {
        self.ctl_sock.clone()
    }
    fn web_socket(&self) -> PathBuf {
        self.web_sock.clone()
    }
    fn disk_map_path(&self) -> PathBuf {
        self.dir.join("disk-map.json")
    }
    fn state_file(&self) -> PathBuf {
        self.dir.join("warm-state.json")
    }
}

/// AF_UNIX `sun_path` is limited to ~104 bytes on macOS (108 on Linux), and
/// tempdir + resource-id paths blow past it. All sockets are therefore bound
/// under a short base directory with hashed names; human-readable symlinks
/// are left in the cat directory (`ctl.sock`, `web.sock`) for tooling.
fn short_socket_path(state_dir: &Path, cat_id: &str, kind: &str) -> PathBuf {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let base = std::env::var_os("CATS_SOCK_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/cats-sock"));
    let _ = std::fs::create_dir_all(&base);
    let mut h = DefaultHasher::new();
    // state_dir is unique per node instance (tests use fresh tempdirs), so
    // parallel nodes/tests can never collide on a socket path.
    (state_dir, cat_id, kind).hash(&mut h);
    base.join(format!("{:016x}.sock", h.finish()))
}

fn symlink_socket(link: &Path, target: &Path) {
    let _ = std::fs::remove_file(link);
    let _ = std::os::unix::fs::symlink(target, link);
}

pub struct NodeRuntime {
    pub cfg: NodeConfig,
    /// Serializes job execution; jobs are rare and idempotent.
    ops: Mutex<()>,
    cats: Mutex<HashMap<String, CatRuntime>>,
    journal: Mutex<HashMap<String, NodeJobResult>>,
}

impl NodeRuntime {
    pub fn new(cfg: NodeConfig) -> Self {
        Self {
            cfg,
            ops: Mutex::new(()),
            cats: Mutex::new(HashMap::new()),
            journal: Mutex::new(HashMap::new()),
        }
    }

    /// Snapshot for heartbeats: (cat_id, generation, state).
    pub fn snapshot(&self) -> Vec<(String, i64, ObservedState)> {
        self.cats
            .lock()
            .unwrap()
            .iter()
            .map(|(id, rt)| (id.clone(), rt.generation, rt.state))
            .collect()
    }

    pub fn execute(&self, job: NodeJob) -> NodeJobResult {
        if let Some(prev) = self.journal.lock().unwrap().get(&job.job_id) {
            return prev.clone();
        }
        let _guard = self.ops.lock().unwrap();
        // Re-check after acquiring the execution lock.
        if let Some(prev) = self.journal.lock().unwrap().get(&job.job_id) {
            return prev.clone();
        }
        let job_id = job.job_id.clone();
        let cat_id = job.action.cat_id().to_string();
        let result = match self.run_action(&job) {
            Ok(observed) => NodeJobResult::ok(&job_id, observed),
            Err(e) => {
                tracing::warn!(job = %job_id, "job failed: {e:#}");
                let observed = self.observed_of(&cat_id);
                NodeJobResult::fail(&job_id, observed, format!("{e:#}"), true)
            }
        };
        self.journal.lock().unwrap().insert(job_id, result.clone());
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

    fn run_action(&self, job: &NodeJob) -> Result<ObservedState> {
        match &job.action {
            NodeJobAction::StartCat {
                cat_id,
                volumes,
                cpus,
                memory_mib,
                ..
            } => self.start_cat(
                cat_id,
                job.cat_generation,
                volumes.clone(),
                *cpus,
                *memory_mib,
                false,
            ),
            NodeJobAction::StopCat { cat_id } => self.stop_cat(cat_id, true),
            NodeJobAction::SuspendCat { cat_id } => self.suspend_cat(cat_id),
            NodeJobAction::ResumeCat { cat_id } => self.resume_cat(cat_id),
            NodeJobAction::WarmCat { cat_id } => self.warm_cat(cat_id),
            NodeJobAction::RestoreCat { cat_id } => self.restore_cat(cat_id, job.cat_generation),
            NodeJobAction::AttachDisk { cat_id, volume } => {
                self.attach_disk(cat_id, volume.clone())
            }
            NodeJobAction::DetachDisk { cat_id, disk_id } => self.detach_disk(cat_id, disk_id),
            NodeJobAction::CleanupCat { cat_id } => self.stop_cat(cat_id, false),
        }
    }

    // ------------------------------------------------------------------
    // Start / restore
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn start_cat(
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
        symlink_socket(&dir.join("ctl.sock"), &ctl_sock);
        symlink_socket(&dir.join("web.sock"), &web_sock);
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
            ch: None,
        };

        let launch = (|| -> Result<String> {
            for grant in &volumes {
                let proc = self.spawn_blockd(cat_id, &dir, grant)?;
                rt.blockds.insert(grant.disk_id.clone(), proc);
            }
            self.write_disk_map(&rt)?;
            let state_file = rt.state_file();
            let guest = self.spawn_guest(&rt, warm_restore.then_some(state_file.as_path()))?;
            rt.guest = Some(guest);
            let boot_id = self.wait_guest_ready(&rt)?;
            Ok(boot_id)
        })();

        match launch {
            Ok(boot_id) => {
                if warm_restore
                    && rt.boot_id.is_some()
                    && rt.boot_id.as_deref() != Some(boot_id.as_str())
                {
                    self.teardown(&mut rt, false);
                    bail!("warm restore produced a different boot id");
                }
                rt.boot_id = Some(boot_id);
                rt.state = ObservedState::Running;
                self.cats.lock().unwrap().insert(cat_id.to_string(), rt);
                Ok(ObservedState::Running)
            }
            Err(e) => {
                self.teardown(&mut rt, true);
                Err(e)
            }
        }
    }

    /// Cloud Hypervisor start/restore: blockd -> (seed) -> kernel NBD ->
    /// CH direct-kernel boot (or snapshot restore) -> vsock health.
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
                .map(|c| (c.nbd.clone(), c.snapshot_dir.clone(), rt.boot_id.clone()))
                .context("warm state missing CH runtime")?
        } else {
            let _ = std::fs::remove_dir_all(&dir);
            (HashMap::new(), None, None)
        };
        let (prev_nbd, snapshot_dir, expected_boot) = previous;
        if warm_restore {
            self.cats.lock().unwrap().remove(cat_id);
        }
        std::fs::create_dir_all(&dir)?;

        let mut chrt = ChRuntime {
            api_sock: short_socket_path(&self.cfg.state_dir, cat_id, "chapi"),
            vsock_sock: short_socket_path(&self.cfg.state_dir, cat_id, "vsock"),
            nbd: HashMap::new(),
            snapshot_dir: None,
        };
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
            ch: None,
        };

        let launch = (|| -> Result<String> {
            // 1. Block backends.
            for grant in &volumes {
                let proc = self.spawn_blockd(cat_id, &dir, grant)?;
                rt.blockds.insert(grant.disk_id.clone(), proc);
            }
            // 2. Seed a brand-new root volume with the golden image.
            if !warm_restore {
                if let Some(image) = &chc.seed_image {
                    for grant in volumes.iter().filter(|g| g.mount_path == "/") {
                        use cats_blockd::meta::MetadataStore;
                        let meta = cats_blockd::meta::SqliteMeta::open(&self.cfg.meta_sqlite)?;
                        let head = meta.load_head(&grant.volume_id)?;
                        if head.generation == 0 {
                            tracing::info!(volume = %grant.volume_id, "seeding golden root");
                            ch::seed_volume(&rt.blockds[&grant.disk_id].socket, image)?;
                        }
                    }
                }
            }
            // 3. Kernel NBD attach (root first => /dev/vda). On restore the
            //    device indices must match the snapshot exactly.
            let mut ordered: Vec<&VolumeGrant> = volumes.iter().collect();
            ordered.sort_by_key(|g| g.mount_path != "/");
            let mut disks = Vec::new();
            for grant in ordered {
                let want = prev_nbd.get(&grant.disk_id).map(|s| s.as_str());
                let dev = ch::nbd_attach(chc, &rt.blockds[&grant.disk_id].socket, want)?;
                chrt.nbd.insert(grant.disk_id.clone(), dev.clone());
                disks.push(dev);
            }
            // 4. VMM.
            let serial_log = dir.join("serial.log");
            let mut vmm = ch::spawn_vmm(&ch::ChSpawn {
                cfg: chc,
                api_sock: &chrt.api_sock,
                vsock_sock: &chrt.vsock_sock,
                serial_log: &serial_log,
                cpus,
                memory_mib,
                disks: &disks,
                restore_from: snapshot_dir.as_deref(),
            })?;
            ch::wait_api_ready(&chrt.api_sock, &mut vmm)?;
            if warm_restore {
                ch::resume(&chrt.api_sock)?;
            }
            rt.guest = Some(vmm);
            // 5. Guest agent over vsock.
            let conn = GuestConn::Vsock(chrt.vsock_sock.clone(), GUEST_VSOCK_PORT);
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Ok(mut client) = conn.connect() {
                    if let Ok((boot_id, _)) = client.health() {
                        return Ok(boot_id);
                    }
                }
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "guest never became healthy over vsock"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        })();

        match launch {
            Ok(boot_id) => {
                if warm_restore
                    && expected_boot.is_some()
                    && expected_boot.as_deref() != Some(&boot_id)
                {
                    rt.ch = Some(chrt);
                    self.teardown(&mut rt, false);
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
                self.teardown(&mut rt, false);
                Err(e)
            }
        }
    }

    fn spawn_blockd(
        &self,
        cat_id: &str,
        cat_dir: &Path,
        grant: &VolumeGrant,
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
        let data_dir = cat_dir.join(format!("vol-{}", grant.disk_id));
        let mut cmd = Command::new(&self.cfg.blockd_bin);
        cmd.arg("--volume-id")
            .arg(&grant.volume_id)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--attachment-id")
            .arg(&grant.attachment_id)
            .arg("--meta-sqlite")
            .arg(&self.cfg.meta_sqlite)
            .arg("--listen-unix")
            .arg(&socket)
            .arg("--create-volume-size")
            .arg(grant.size_bytes.to_string())
            .arg("--lease-ttl-ms")
            .arg(self.cfg.blockd_lease_ttl_ms.to_string());
        match &self.cfg.blob {
            BlobBackend::File { root } => {
                cmd.arg("--blob-file-root").arg(root);
            }
            BlobBackend::S3 {
                endpoint,
                bucket,
                region,
                prefix,
            } => {
                cmd.arg("--blob-s3-endpoint")
                    .arg(endpoint)
                    .arg("--blob-s3-bucket")
                    .arg(bucket)
                    .arg("--blob-s3-region")
                    .arg(region)
                    .arg("--blob-s3-prefix")
                    .arg(prefix);
            }
        }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("CATS_CRASH_POINT")
            .spawn()
            .context("spawn cats-blockd")?;
        let mut proc = BlockdProc {
            child,
            socket,
            grant: grant.clone(),
        };
        self.wait_blockd_ready(&mut proc)
            .with_context(|| format!("blockd for {} never became ready", grant.disk_id))?;
        Ok(proc)
    }

    fn wait_blockd_ready(&self, proc: &mut BlockdProc) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(client) = cats_blockd::nbd::NbdClient::connect_unix(&proc.socket) {
                let _ = client.disconnect();
                return Ok(());
            }
            if let Some(status) = proc.child.try_wait()? {
                bail!("cats-blockd exited during startup: {status} (lease held or bad config?)");
            }
            if Instant::now() > deadline {
                bail!("timed out waiting for blockd socket");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn write_disk_map(&self, rt: &CatRuntime) -> Result<()> {
        let map: HashMap<String, DiskMapEntry> = rt
            .blockds
            .iter()
            .map(|(disk_id, p)| {
                (
                    disk_id.clone(),
                    DiskMapEntry {
                        socket: p.socket.clone(),
                        mount_path: p.grant.mount_path.clone(),
                    },
                )
            })
            .collect();
        let tmp = rt.disk_map_path().with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&map)?)?;
        std::fs::rename(&tmp, rt.disk_map_path())?;
        Ok(())
    }

    fn spawn_guest(&self, rt: &CatRuntime, state_file: Option<&Path>) -> Result<Child> {
        let mut cmd = Command::new(&self.cfg.guest_agent_bin);
        cmd.arg("--control-socket")
            .arg(rt.ctl_socket())
            .arg("--disk-map")
            .arg(rt.disk_map_path())
            .arg("--web-socket")
            .arg(rt.web_socket())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(sf) = state_file {
            cmd.arg("--state-file").arg(sf);
        }
        cmd.spawn().context("spawn cats-guest-agent")
    }

    fn wait_guest_ready(&self, rt: &CatRuntime) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(mut client) = rt.conn().connect() {
                if let Ok((boot_id, _)) = client.health() {
                    return Ok(boot_id);
                }
            }
            if Instant::now() > deadline {
                bail!("guest agent never became healthy");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // ------------------------------------------------------------------
    // Stop / cleanup
    // ------------------------------------------------------------------

    fn stop_cat(&self, cat_id: &str, graceful: bool) -> Result<ObservedState> {
        let Some(mut rt) = self.cats.lock().unwrap().remove(cat_id) else {
            // Idempotent: also sweep any residue from a previous life.
            let dir = self.cfg.state_dir.join("cats").join(cat_id);
            let _ = std::fs::remove_dir_all(&dir);
            return Ok(ObservedState::Cold);
        };
        self.teardown(&mut rt, graceful);
        let _ = std::fs::remove_dir_all(&rt.dir);
        Ok(ObservedState::Cold)
    }

    /// Best-effort teardown: durable flush (graceful), then kill children.
    fn teardown(&self, rt: &mut CatRuntime, graceful: bool) {
        if graceful && rt.guest.is_some() {
            if rt.state == ObservedState::Suspended {
                // A paused guest cannot flush; wake it first.
                match &rt.ch {
                    Some(chrt) => {
                        let _ = ch::resume(&chrt.api_sock);
                    }
                    None => {
                        if let Some(g) = &rt.guest {
                            signal(g, libc::SIGCONT);
                        }
                    }
                }
            }
            if let Ok(mut client) = rt.conn().connect() {
                let _ = client.syncfs();
                if rt.ch.is_none() {
                    let _ = client.shutdown();
                }
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
        if let (Some(chrt), VmmMode::CloudHypervisor(chc)) = (&rt.ch, &self.cfg.vmm) {
            for dev in chrt.nbd.values() {
                ch::nbd_detach(chc, dev);
            }
        }
        for (_, mut p) in rt.blockds.drain() {
            let _ = p.child.kill();
            let _ = p.child.wait();
            let _ = std::fs::remove_file(&p.socket);
        }
        if let Some(chrt) = &mut rt.ch {
            chrt.nbd.clear();
        }
        let _ = std::fs::remove_file(rt.ctl_socket());
        let _ = std::fs::remove_file(rt.web_socket());
        rt.state = ObservedState::Cold;
    }

    // ------------------------------------------------------------------
    // Suspend / resume (pause + page-out analog)
    // ------------------------------------------------------------------

    fn suspend_cat(&self, cat_id: &str) -> Result<ObservedState> {
        let mut cats = self.cats.lock().unwrap();
        let rt = cats
            .get_mut(cat_id)
            .context("cat is not running on this node")?;
        if rt.state == ObservedState::Suspended {
            return Ok(ObservedState::Suspended);
        }
        if rt.state != ObservedState::Running {
            bail!("cannot suspend from {:?}", rt.state);
        }
        // ADR-0002 order: quiesce + durable flush BEFORE pausing.
        let mut client = rt.conn().connect()?;
        client.syncfs()?;
        match &rt.ch {
            Some(chrt) => ch::pause(&chrt.api_sock)?,
            None => {
                let guest = rt.guest.as_ref().context("guest process missing")?;
                signal(guest, libc::SIGSTOP);
            }
        }
        rt.state = ObservedState::Suspended;
        Ok(ObservedState::Suspended)
    }

    fn resume_cat(&self, cat_id: &str) -> Result<ObservedState> {
        let mut cats = self.cats.lock().unwrap();
        let rt = cats.get_mut(cat_id).context("cat is not on this node")?;
        if rt.state == ObservedState::Running {
            return Ok(ObservedState::Running);
        }
        if rt.state != ObservedState::Suspended {
            bail!("cannot resume from {:?}", rt.state);
        }
        match &rt.ch {
            Some(chrt) => ch::resume(&chrt.api_sock)?,
            None => {
                let guest = rt.guest.as_ref().context("guest process missing")?;
                signal(guest, libc::SIGCONT);
            }
        }
        let expected = rt.boot_id.clone();
        let conn = rt.conn();
        drop(cats);
        // The resumed guest must be the same one (boot_id preserved).
        let mut client = conn.connect()?;
        let (boot_id, _) = client.health()?;
        if expected.as_deref() != Some(boot_id.as_str()) {
            bail!("resume produced a different boot id");
        }
        let mut cats = self.cats.lock().unwrap();
        let rt = cats.get_mut(cat_id).context("cat vanished during resume")?;
        rt.state = ObservedState::Running;
        Ok(ObservedState::Running)
    }

    // ------------------------------------------------------------------
    // Warm (snapshot + exit) / restore
    // ------------------------------------------------------------------

    fn warm_cat(&self, cat_id: &str) -> Result<ObservedState> {
        let mut cats = self.cats.lock().unwrap();
        let rt = cats.get_mut(cat_id).context("cat is not on this node")?;
        match rt.state {
            ObservedState::Warm => return Ok(ObservedState::Warm),
            ObservedState::Suspended | ObservedState::Running => {}
            other => bail!("cannot warm from {other:?}"),
        }
        // CH mode: real memory snapshot, then everything exits (ADR-0002).
        if rt.ch.is_some() {
            let api = rt.ch.as_ref().expect("checked").api_sock.clone();
            if rt.state != ObservedState::Suspended {
                // Not paused yet: durable flush first, then pause.
                let mut client = rt.conn().connect()?;
                client.syncfs()?;
                ch::pause(&api)?;
            }
            let snap_dir = rt.dir.join("snapshot");
            let _ = std::fs::remove_dir_all(&snap_dir);
            ch::snapshot(&api, &snap_dir)?;
            if let Some(mut vmm) = rt.guest.take() {
                ch::shutdown_vmm(&api, &mut vmm);
            }
            let nbd_devices: Vec<String> = rt
                .ch
                .as_ref()
                .expect("checked")
                .nbd
                .values()
                .cloned()
                .collect();
            if let VmmMode::CloudHypervisor(chc) = &self.cfg.vmm {
                for dev in &nbd_devices {
                    ch::nbd_detach(chc, dev);
                }
            }
            for (_, mut p) in rt.blockds.drain() {
                let _ = p.child.kill();
                let _ = p.child.wait();
            }
            if let Some(chrt) = &mut rt.ch {
                chrt.snapshot_dir = Some(snap_dir);
            }
            rt.state = ObservedState::Warm;
            return Ok(ObservedState::Warm);
        }
        if let Some(g) = &rt.guest {
            signal(g, libc::SIGCONT); // wake a suspended guest to snapshot it
        }
        let mut client = rt.conn().connect()?;
        // Durable point, then persist the process identity ("snapshot"),
        // then exit the VMM and the block backends (ADR-0002 Warm).
        client.syncfs()?;
        client.save_state(&rt.state_file())?;
        let _ = client.shutdown();
        if let Some(mut g) = rt.guest.take() {
            let _ = g.kill();
            let _ = g.wait();
        }
        for (_, mut p) in rt.blockds.drain() {
            let _ = p.child.kill();
            let _ = p.child.wait();
        }
        rt.state = ObservedState::Warm;
        Ok(ObservedState::Warm)
    }

    fn restore_cat(&self, cat_id: &str, generation: i64) -> Result<ObservedState> {
        let (volumes, expected_boot_id, cpus, memory_mib) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("no warm state for cat on this node")?;
            if rt.state != ObservedState::Warm {
                bail!("cannot restore from {:?}", rt.state);
            }
            match &rt.ch {
                Some(chrt) => {
                    anyhow::ensure!(
                        chrt.snapshot_dir.as_ref().is_some_and(|d| d.exists()),
                        "warm snapshot is missing"
                    );
                }
                None => anyhow::ensure!(rt.state_file().exists(), "warm snapshot is missing"),
            }
            (
                rt.volumes.clone(),
                rt.boot_id.clone(),
                rt.cpus,
                rt.memory_mib,
            )
        };
        // CH mode keeps the runtime entry (start_cat_ch consumes it).
        if matches!(self.cfg.vmm, VmmMode::Fake) {
            self.cats.lock().unwrap().remove(cat_id);
        }
        // Re-launch on the preserved local state (cache + snapshot). The
        // fake VMM re-acquires the volume leases; the production vhost
        // implementation keeps the lease alive across Warm instead.
        let observed = self.start_cat(cat_id, generation, volumes, cpus, memory_mib, true)?;
        let now_boot = self
            .cats
            .lock()
            .unwrap()
            .get(cat_id)
            .and_then(|rt| rt.boot_id.clone());
        if expected_boot_id.is_some() && now_boot != expected_boot_id {
            let _ = self.stop_cat(cat_id, false);
            bail!("warm restore lost process identity");
        }
        Ok(observed)
    }

    // ------------------------------------------------------------------
    // Hot attach / detach
    // ------------------------------------------------------------------

    fn attach_disk(&self, cat_id: &str, grant: VolumeGrant) -> Result<ObservedState> {
        let mut cats = self.cats.lock().unwrap();
        let rt = cats
            .get_mut(cat_id)
            .context("cat is not running on this node")?;
        if rt.state != ObservedState::Running {
            bail!("hot attach requires a running cat");
        }
        if rt.ch.is_some() {
            // vm.add-disk hotplug lands with the vhost-user milestone; cold
            // cats pick bindings up at the next start.
            bail!("hot attach is not supported in Cloud Hypervisor mode yet");
        }
        if rt.blockds.contains_key(&grant.disk_id) {
            return Ok(ObservedState::Running); // idempotent
        }
        let dir = rt.dir.clone();
        let proc = self.spawn_blockd(cat_id, &dir, &grant)?;
        rt.blockds.insert(grant.disk_id.clone(), proc);
        rt.volumes.push(grant);
        self.write_disk_map(rt)?;
        Ok(ObservedState::Running)
    }

    fn detach_disk(&self, cat_id: &str, disk_id: &str) -> Result<ObservedState> {
        let mut cats = self.cats.lock().unwrap();
        let rt = cats
            .get_mut(cat_id)
            .context("cat is not running on this node")?;
        let Some(mut proc) = rt.blockds.remove(disk_id) else {
            return Ok(rt.state); // idempotent
        };
        rt.volumes.retain(|v| v.disk_id != disk_id);
        // Final durable flush through the guest before the backend exits.
        if let Ok(mut client) = rt.conn().connect() {
            let _ = client.flush_disk(disk_id);
        }
        self.write_disk_map(rt)?;
        let _ = proc.child.kill();
        let _ = proc.child.wait();
        Ok(rt.state)
    }

    // ------------------------------------------------------------------
    // Exec / proxy passthrough
    // ------------------------------------------------------------------

    pub fn exec(&self, cat_id: &str, command: Vec<String>) -> Result<(i32, String, String)> {
        let conn = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("cat is not running on this node")?;
            if rt.state != ObservedState::Running {
                bail!("cat is not running (state {:?})", rt.state);
            }
            rt.conn()
        };
        let mut client = conn.connect()?;
        client.exec(command)
    }

    /// Forward an HTTP GET to the guest web service. Returns the raw HTTP
    /// response bytes. Errors with "not active" when the cat is not running
    /// here — the gateway treats that as a stale route (409).
    pub fn proxy_get(&self, cat_id: &str, path: &str) -> Result<Vec<u8>> {
        use std::io::{Read, Write};
        let web = {
            let cats = self.cats.lock().unwrap();
            let rt = cats.get(cat_id).context("cat is not active on this node")?;
            if rt.state != ObservedState::Running {
                bail!("cat is not active on this node (state {:?})", rt.state);
            }
            rt.web_socket()
        };
        let mut stream = std::os::unix::net::UnixStream::connect(&web)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nhost: guest\r\nconnection: close\r\n\r\n"
        )?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        Ok(buf)
    }
}

fn signal(child: &Child, sig: i32) {
    unsafe {
        libc::kill(child.id() as i32, sig);
    }
}
