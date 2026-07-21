//! Per-node runtime: executes NodeJobs by supervising one guest-agent
//! process ("the VM") and one cats-blockd process per attachment.
//!
//! VMM seam: this file implements the FakeVmm — a host process stands in
//! for Cloud Hypervisor, SIGSTOP/SIGCONT stand in for vCPU pause/resume,
//! and the guest state file stands in for the memory snapshot. Every block
//! byte still flows through the real cats-blockd engine, so storage
//! semantics (leases, FLUSH durability, cold restore) are exercised for
//! real. The Cloud Hypervisor implementation replaces `spawn_guest` /
//! `pause` / `resume` / `snapshot` with ch-remote API calls on Linux and is
//! tracked as the Linux milestone (docs/README).
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

use crate::guest_client::GuestClient;

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub state_dir: PathBuf,
    pub blockd_bin: PathBuf,
    pub guest_agent_bin: PathBuf,
    pub meta_sqlite: PathBuf,
    pub blob_file_root: PathBuf,
    pub blockd_lease_ttl_ms: i64,
}

struct BlockdProc {
    child: Child,
    socket: PathBuf,
    grant: VolumeGrant,
}

struct CatRuntime {
    generation: i64,
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
}

impl CatRuntime {
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
                cat_id, volumes, ..
            } => self.start_cat(cat_id, job.cat_generation, volumes.clone(), false),
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

    fn start_cat(
        &self,
        cat_id: &str,
        generation: i64,
        volumes: Vec<VolumeGrant>,
        warm_restore: bool,
    ) -> Result<ObservedState> {
        if let Some(rt) = self.cats.lock().unwrap().get(cat_id) {
            if rt.state == ObservedState::Running {
                return Ok(ObservedState::Running);
            }
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
            state: ObservedState::Starting,
            guest: None,
            boot_id: None,
            blockds: HashMap::new(),
            volumes: volumes.clone(),
            dir: dir.clone(),
            ctl_sock,
            web_sock,
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
        let child = Command::new(&self.cfg.blockd_bin)
            .arg("--volume-id")
            .arg(&grant.volume_id)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--attachment-id")
            .arg(&grant.attachment_id)
            .arg("--meta-sqlite")
            .arg(&self.cfg.meta_sqlite)
            .arg("--blob-file-root")
            .arg(&self.cfg.blob_file_root)
            .arg("--listen-unix")
            .arg(&socket)
            .arg("--create-volume-size")
            .arg(grant.size_bytes.to_string())
            .arg("--lease-ttl-ms")
            .arg(self.cfg.blockd_lease_ttl_ms.to_string())
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
            if let Ok(mut client) = GuestClient::connect(&rt.ctl_socket()) {
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
                // A stopped process cannot flush; wake it first.
                if let Some(g) = &rt.guest {
                    signal(g, libc::SIGCONT);
                }
            }
            if let Ok(mut client) = GuestClient::connect(&rt.ctl_socket()) {
                let _ = client.syncfs();
                let _ = client.shutdown();
            }
        }
        if let Some(mut g) = rt.guest.take() {
            let _ = g.kill();
            let _ = g.wait();
        }
        for (_, mut p) in rt.blockds.drain() {
            let _ = p.child.kill();
            let _ = p.child.wait();
            let _ = std::fs::remove_file(&p.socket);
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
        let mut client = GuestClient::connect(&rt.ctl_socket())?;
        client.syncfs()?;
        let guest = rt.guest.as_ref().context("guest process missing")?;
        signal(guest, libc::SIGSTOP);
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
        let guest = rt.guest.as_ref().context("guest process missing")?;
        signal(guest, libc::SIGCONT);
        let expected = rt.boot_id.clone();
        let ctl = rt.ctl_socket();
        drop(cats);
        // The resumed process must be the same one (boot_id preserved).
        let mut client = GuestClient::connect(&ctl)?;
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
        if let Some(g) = &rt.guest {
            signal(g, libc::SIGCONT); // wake a suspended guest to snapshot it
        }
        let mut client = GuestClient::connect(&rt.ctl_socket())?;
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
        let (volumes, expected_boot_id) = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("no warm state for cat on this node")?;
            if rt.state != ObservedState::Warm {
                bail!("cannot restore from {:?}", rt.state);
            }
            if !rt.state_file().exists() {
                bail!("warm snapshot is missing");
            }
            (rt.volumes.clone(), rt.boot_id.clone())
        };
        self.cats.lock().unwrap().remove(cat_id);
        // Re-launch on the preserved local state (cache + snapshot). The
        // fake VMM re-acquires the volume leases; the production vhost
        // implementation keeps the lease alive across Warm instead.
        let observed = self.start_cat(cat_id, generation, volumes, true)?;
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
        if let Ok(mut client) = GuestClient::connect(&rt.ctl_socket()) {
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
        let ctl = {
            let cats = self.cats.lock().unwrap();
            let rt = cats
                .get(cat_id)
                .context("cat is not running on this node")?;
            if rt.state != ObservedState::Running {
                bail!("cat is not running (state {:?})", rt.state);
            }
            rt.ctl_socket()
        };
        let mut client = GuestClient::connect(&ctl)?;
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
