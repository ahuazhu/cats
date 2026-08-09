//! Ignored, Linux-only production-shaped acceptance runner.
//!
//! This deliberately bypasses the control plane and drives `NodeRuntime`
//! directly. It therefore cannot register an experimental node in the
//! production fleet or mutate the production worker service. Every Cat,
//! volume, socket, state directory, PostgreSQL row, and S3 key uses a
//! caller-supplied unique run id.
//!
//! Run through `experiments/vhost-user-soak-20260730/run-metal.sh`; the wrapper
//! provides the real KVM/Cloud Hypervisor assets and an isolated S3 prefix.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use cats_api::nodejob::{JobPhase, NodeJob, NodeJobAction, NodeJobResult, VolumeGrant};
use cats_api::resources::{DiskDurability, ObservedState};
use cats_block_client::NbdClient;
use cats_blockd::engine::{
    DurabilityStatus, DEFAULT_MAX_LOCAL_BYTES, DEFAULT_MAX_STAGED_BYTES, DEFAULT_MAX_STAGED_PACKS,
};
use cats_metadata_store_postgres::PostgresMetadataStoreFactory;
use cats_node_agent::admission::WakeBudget;
use cats_node_agent::ch::{BlockPath, ChConfig};
use cats_node_agent::runtime::{NodeConfig, NodeRuntime, VmmMode};
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_storage::{
    open_blob_store, open_metadata_store, AdapterConfig, AdapterSelection, BlobStore,
    BlobStoreFactory, MetadataStore, MetadataStoreFactory,
};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const GUEST_BENCH_PATH: &str = "/usr/local/bin/cats-fsync-bench";
const GUEST_DATA_PATH: &str = "/var/tmp/cats-fsync-data.bin";
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
// Current metal seed image: debugfs reports /bin/cat at blocks 3121..3130,
// 39,384 bytes, on a 4 KiB ext4 filesystem. Reading the same extents through
// blockd's co-served NBD frontend distinguishes engine/cache corruption from a
// vhost-user transport error. The source digest check makes an image change fail
// loudly instead of silently turning these offsets into misleading evidence.
const SEED_CAT_OFFSET: u64 = 3_121 * 4_096;
const SEED_CAT_LEN: u32 = 39_384;
const SEED_CAT_SHA256: &str = "dda0961715677dff3cd560e1933379c0eca73c0b6e19fef2737492ebc1de1700";

#[derive(Debug, Clone)]
struct SoakConfig {
    run_id: String,
    state_dir: PathBuf,
    output_dir: PathBuf,
    socket_dir: PathBuf,
    blockd_bin: PathBuf,
    guest_agent_bin: PathBuf,
    guest_bench_bin: PathBuf,
    ch_bin: PathBuf,
    kernel: PathBuf,
    initramfs: PathBuf,
    seed_image: PathBuf,
    postgres_ca: PathBuf,
    s3_bucket: String,
    s3_region: String,
    s3_prefix: String,
    disk_durability: DiskDurability,
    block_path: BlockPath,
    preflight_only: bool,
    local_samples: usize,
    remote_samples: usize,
    suspend_cycles: usize,
    warm_cycles: usize,
    cold_cycles: usize,
    concurrent_cats: usize,
}

impl SoakConfig {
    fn from_env() -> Result<Self> {
        let run_id = required_env("CATS_SOAK_RUN_ID")?;
        ensure!(
            run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "CATS_SOAK_RUN_ID contains unsafe characters"
        );
        let state_dir = required_path("CATS_SOAK_STATE_DIR")?;
        let output_dir = required_path("CATS_SOAK_OUTPUT_DIR")?;
        let socket_dir = required_path("CATS_SOAK_SOCKET_DIR")?;
        let s3_prefix =
            std::env::var("CATS_SOAK_S3_PREFIX").unwrap_or_else(|_| format!("cats-soak/{run_id}"));
        ensure!(
            s3_prefix.starts_with("cats-soak/") && s3_prefix.ends_with(&run_id),
            "S3 prefix must be a run-scoped cats-soak/<run-id> namespace"
        );
        let disk_durability = match std::env::var("CATS_SOAK_DISK_DURABILITY")
            .unwrap_or_else(|_| "relaxed".into())
            .as_str()
        {
            "strict" => DiskDurability::Strict,
            "relaxed" => DiskDurability::Relaxed,
            other => bail!("CATS_SOAK_DISK_DURABILITY must be strict|relaxed, got {other}"),
        };
        let block_path = match std::env::var("CATS_SOAK_BLOCK_PATH")
            .unwrap_or_else(|_| "vhost-user".into())
            .as_str()
        {
            "kernel-nbd" => BlockPath::KernelNbd,
            "vhost-user" => BlockPath::VhostUser,
            other => bail!("CATS_SOAK_BLOCK_PATH must be kernel-nbd|vhost-user, got {other}"),
        };
        Ok(Self {
            run_id,
            state_dir,
            output_dir,
            socket_dir,
            blockd_bin: required_path("CATS_SOAK_BLOCKD_BIN")?,
            guest_agent_bin: required_path("CATS_SOAK_GUEST_AGENT_BIN")?,
            guest_bench_bin: required_path("CATS_SOAK_GUEST_BENCH_BIN")?,
            ch_bin: required_path("CATS_SOAK_CH_BIN")?,
            kernel: required_path("CATS_SOAK_KERNEL")?,
            initramfs: required_path("CATS_SOAK_INITRAMFS")?,
            seed_image: required_path("CATS_SOAK_SEED_IMAGE")?,
            postgres_ca: required_path("CATS_SOAK_POSTGRES_CA")?,
            s3_bucket: required_env("CATS_S3_BUCKET")?,
            s3_region: required_env("CATS_AWS_REGION")?,
            s3_prefix,
            disk_durability,
            block_path,
            preflight_only: env_bool("CATS_SOAK_PREFLIGHT_ONLY", false)?,
            local_samples: env_usize("CATS_SOAK_LOCAL_SAMPLES", 1_000)?,
            remote_samples: env_usize("CATS_SOAK_REMOTE_SAMPLES", 300)?,
            suspend_cycles: env_usize("CATS_SOAK_SUSPEND_CYCLES", 50)?,
            warm_cycles: env_usize("CATS_SOAK_WARM_CYCLES", 30)?,
            cold_cycles: env_usize("CATS_SOAK_COLD_CYCLES", 10)?,
            concurrent_cats: env_usize("CATS_SOAK_CONCURRENT_CATS", 8)?,
        })
    }

    fn metadata_selection(&self) -> Result<AdapterSelection> {
        Ok(AdapterSelection::new(
            "postgres",
            AdapterConfig::from_pairs([("ca-file", self.postgres_ca.display().to_string())])?,
        ))
    }

    fn object_selection(&self) -> Result<AdapterSelection> {
        Ok(AdapterSelection::new(
            "aws-s3",
            AdapterConfig::from_pairs([
                ("bucket", self.s3_bucket.clone()),
                ("region", self.s3_region.clone()),
                ("prefix", self.s3_prefix.clone()),
            ])?,
        ))
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn required_path(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(required_env(name)?);
    ensure!(path.exists(), "{name} does not exist: {}", path.display());
    Ok(path)
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    let value = std::env::var(name)
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .with_context(|| format!("{name} must be an unsigned integer"))?
        .unwrap_or(default);
    ensure!(value > 0, "{name} must be greater than zero");
    Ok(value)
}

fn env_bool(name: &str, default: bool) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => Ok(true),
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("false") => Ok(false),
        Ok(value) => bail!("{name} must be 0|1|false|true, got {value}"),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("read {name}")),
    }
}

#[derive(Debug, Clone)]
struct GuestSample {
    sample: u64,
    write_us: u64,
    fsync_us: u64,
    total_us: u64,
    offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct Distribution {
    count: usize,
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
}

fn distribution(values: &[u64]) -> Result<Distribution> {
    ensure!(!values.is_empty(), "cannot summarize an empty sample set");
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let percentile = |numerator: usize| {
        let rank = (sorted.len() * numerator).div_ceil(100);
        sorted[rank.saturating_sub(1)]
    };
    Ok(Distribution {
        count: sorted.len(),
        p50: percentile(50),
        p95: percentile(95),
        p99: percentile(99),
        max: *sorted.last().expect("non-empty"),
    })
}

fn distribution_json(value: Distribution) -> serde_json::Value {
    serde_json::json!({
        "count": value.count,
        "p50_us": value.p50,
        "p95_us": value.p95,
        "p99_us": value.p99,
        "max_us": value.max,
    })
}

fn parse_guest_samples(stdout: &str) -> Result<Vec<GuestSample>> {
    let mut samples = Vec::new();
    for line in stdout.lines() {
        if line.starts_with("sample,") || line.trim().is_empty() {
            continue;
        }
        let fields = line.trim().split(',').collect::<Vec<_>>();
        ensure!(fields.len() == 5, "malformed guest benchmark row: {line:?}");
        let parse = |index: usize| -> Result<u64> {
            fields[index]
                .parse::<u64>()
                .with_context(|| format!("parse guest benchmark row: {line:?}"))
        };
        samples.push(GuestSample {
            sample: parse(0)?,
            write_us: parse(1)?,
            fsync_us: parse(2)?,
            total_us: parse(3)?,
            offset: parse(4)?,
        });
    }
    ensure!(!samples.is_empty(), "guest benchmark returned no samples");
    Ok(samples)
}

fn control_command(socket: &Path, command: &str) -> Result<String> {
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    stream.set_write_timeout(Some(CONTROL_TIMEOUT))?;
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\n")?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    match line.trim().strip_prefix("OK ") {
        Some(payload) => Ok(payload.to_string()),
        None => bail!("{command} failed: {}", line.trim()),
    }
}

fn durability_status(socket: &Path) -> Result<DurabilityStatus> {
    let payload = control_command(socket, "status")?;
    serde_json::from_str(&payload).context("decode durability status")
}

fn active_nbd_devices() -> Result<BTreeSet<String>> {
    let mut devices = BTreeSet::new();
    for entry in fs::read_dir("/sys/class/block").context("read /sys/class/block")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("nbd") {
            continue;
        }
        let sectors = fs::read_to_string(entry.path().join("size"))
            .unwrap_or_default()
            .trim()
            .parse::<u64>()
            .unwrap_or(0);
        if sectors > 0 {
            devices.insert(name);
        }
    }
    Ok(devices)
}

fn process_cmdlines(executable: &str, marker: &Path) -> Result<Vec<String>> {
    let marker = marker
        .to_str()
        .context("process command-line marker is not UTF-8")?;
    let mut cmdlines = Vec::new();
    for entry in fs::read_dir("/proc").context("read /proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let Ok(mut raw) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        for byte in &mut raw {
            if *byte == 0 {
                *byte = b' ';
            }
        }
        let cmdline = String::from_utf8_lossy(&raw).trim().to_string();
        if cmdline.contains(executable) && cmdline.contains(marker) {
            cmdlines.push(cmdline);
        }
    }
    Ok(cmdlines)
}

struct Soak {
    cfg: SoakConfig,
    runtime: Arc<NodeRuntime>,
    metadata: Arc<dyn MetadataStore>,
    blob: Arc<dyn BlobStore>,
    cats: Mutex<Vec<String>>,
    volumes: Mutex<Vec<String>>,
    sequence: AtomicI64,
}

impl Soak {
    fn new(cfg: SoakConfig) -> Result<Self> {
        fs::create_dir_all(&cfg.state_dir)?;
        fs::create_dir_all(&cfg.output_dir)?;
        fs::create_dir_all(&cfg.socket_dir)?;
        // `short_socket_path` reads this at use time. The runner is one test
        // process, so the process-global setting cannot collide with another
        // NodeRuntime.
        std::env::set_var("CATS_SOCK_DIR", &cfg.socket_dir);

        let metadata_selection = cfg.metadata_selection()?;
        let object_selection = cfg.object_selection()?;
        let metadata_factories: [&dyn MetadataStoreFactory; 1] = [&PostgresMetadataStoreFactory];
        let blob_factories: [&dyn BlobStoreFactory; 1] = [&AwsS3BlobStoreFactory];
        let metadata = open_metadata_store(
            &metadata_selection.name,
            &metadata_selection.config,
            &metadata_factories,
        )
        .context("open isolated PostgreSQL metadata namespace")?;
        let blob = open_blob_store(
            &object_selection.name,
            &object_selection.config,
            &blob_factories,
        )
        .context("open isolated S3 namespace")?;
        let runtime = Arc::new(NodeRuntime::new(NodeConfig {
            node_id: format!("soak-{}", cfg.run_id),
            state_dir: cfg.state_dir.clone().into(),
            blockd_bin: cfg.blockd_bin.clone(),
            guest_agent_bin: cfg.guest_agent_bin.clone(),
            metadata_store: metadata_selection,
            object_store: object_selection,
            blockd_lease_ttl_ms: 5_000,
            blockd_max_staged_bytes: DEFAULT_MAX_STAGED_BYTES,
            blockd_max_staged_packs: DEFAULT_MAX_STAGED_PACKS,
            blockd_max_local_bytes: DEFAULT_MAX_LOCAL_BYTES,
            metering_cgroup_root: None,
            wake_budget: WakeBudget {
                commitment_bytes: 32 * GIB,
                max_wakes: cfg.concurrent_cats.max(1),
                queue_timeout: Duration::from_secs(120),
            },
            vmm: VmmMode::CloudHypervisor(ChConfig {
                block_direct: false,
                ch_bin: cfg.ch_bin.clone(),
                kernel: cfg.kernel.clone(),
                initramfs: Some(cfg.initramfs.clone()),
                boot_contract: None,
                cmdline: "console=ttyS0 root=/dev/vda rw clocksource=kvm-clock".into(),
                seed_image: Some(cfg.seed_image.clone()),
                block_path: cfg.block_path,
                vhost_user_queues: 1,
                vhost_user_queue_size: 256,
                nbd_client_bin: PathBuf::from("/usr/sbin/nbd-client"),
                nbd_devices: 64,
                // No tap: storage/lifecycle control uses hybrid vsock. This
                // prevents an experiment from sharing production NAT/routing.
                ip_bin: PathBuf::from("/usr/sbin/ip"),
            }),
        })?);
        Ok(Self {
            cfg,
            runtime,
            metadata,
            blob,
            cats: Mutex::new(Vec::new()),
            volumes: Mutex::new(Vec::new()),
            sequence: AtomicI64::new(1),
        })
    }

    fn names(&self, label: &str) -> (String, VolumeGrant) {
        let compact_run = self
            .cfg
            .run_id
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .take(10)
            .collect::<String>();
        let cat_id = format!("s{compact_run}{label}");
        let disk_id = format!("d{compact_run}{label}");
        let volume_id = format!("soak_{}_{}", self.cfg.run_id, label);
        let attachment_id = format!("soak-att-{}-{label}", self.cfg.run_id);
        (
            cat_id,
            VolumeGrant {
                disk_id,
                volume_id,
                attachment_id,
                epoch: 0,
                size_bytes: 2 * GIB,
                mount_path: "/".into(),
                durability: self.cfg.disk_durability,
            },
        )
    }

    fn register(&self, cat_id: &str, volume: &VolumeGrant) {
        self.cats.lock().unwrap().push(cat_id.to_string());
        self.volumes.lock().unwrap().push(volume.volume_id.clone());
    }

    fn job(&self, action: NodeJobAction) -> NodeJob {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        let cat_id = action.cat_id().to_string();
        NodeJob {
            job_id: format!(
                "job_{}_{}_{}_{}",
                self.cfg.run_id,
                cat_id,
                sequence,
                action.kind()
            ),
            cat_generation: sequence,
            action,
        }
    }

    fn execute(&self, action: NodeJobAction, expected: ObservedState) -> Result<NodeJobResult> {
        let result = self.runtime.execute(self.job(action));
        ensure!(
            result.phase == JobPhase::Succeeded && result.observed_state == expected,
            "node job failed: {result:?}; expected {expected:?}"
        );
        Ok(result)
    }

    fn start(&self, cat_id: &str, volume: &VolumeGrant) -> Result<Duration> {
        let started = Instant::now();
        self.execute(
            NodeJobAction::StartCat {
                cat_id: cat_id.to_string(),
                image: "soak-golden-root".into(),
                cpus: 1,
                memory_mib: 512,
                volumes: vec![volume.clone()],
            },
            ObservedState::Running,
        )?;
        Ok(started.elapsed())
    }

    fn exec(&self, cat_id: &str, command: Vec<String>) -> Result<String> {
        let (code, stdout, stderr) = self.runtime.exec(cat_id, command)?;
        ensure!(
            code == 0,
            "guest command failed with {code}: stdout={stdout:?}, stderr={stderr:?}"
        );
        Ok(stdout)
    }

    fn install_guest_bench(&self, cat_id: &str) -> Result<()> {
        let bytes = fs::read(&self.cfg.guest_bench_bin).with_context(|| {
            format!(
                "read guest benchmark {}",
                self.cfg.guest_bench_bin.display()
            )
        })?;
        let (code, stdout, stderr) = self.runtime.exec_with_input(
            cat_id,
            vec![
                "sh".into(),
                "-c".into(),
                format!("umask 077; cat > {GUEST_BENCH_PATH}; chmod 0755 {GUEST_BENCH_PATH}"),
            ],
            Default::default(),
            bytes,
        )?;
        ensure!(
            code == 0,
            "install guest benchmark failed: stdout={stdout:?}, stderr={stderr:?}"
        );
        Ok(())
    }

    fn run_guest_bench(
        &self,
        cat_id: &str,
        samples: usize,
        start_index: u64,
    ) -> Result<Vec<GuestSample>> {
        let stdout = self.exec(
            cat_id,
            vec![
                GUEST_BENCH_PATH.into(),
                GUEST_DATA_PATH.into(),
                samples.to_string(),
                start_index.to_string(),
                "128".into(),
                cats_api::chunk::CHUNK_SIZE.to_string(),
                "4096".into(),
            ],
        )?;
        let parsed = parse_guest_samples(&stdout)?;
        ensure!(
            parsed.len() == samples,
            "wanted {samples} guest samples, got {}",
            parsed.len()
        );
        Ok(parsed)
    }

    fn copy_bench_blockd_log(&self, cat_id: &str, volume: &VolumeGrant) -> Result<()> {
        let source = self
            .cfg
            .state_dir
            .join("cats")
            .join(cat_id)
            .join(format!("blockd-{}.log", volume.disk_id));
        let target = self.cfg.output_dir.join("bench-blockd.log");
        fs::copy(&source, &target).with_context(|| {
            format!(
                "copy benchmark blockd log {} to {}",
                source.display(),
                target.display()
            )
        })?;
        Ok(())
    }

    fn control_socket(&self, cat_id: &str, volume: &VolumeGrant) -> PathBuf {
        self.cfg
            .state_dir
            .join("cats")
            .join(cat_id)
            .join(format!("ctl-{}.sock", volume.disk_id))
    }

    fn resolve_socket_link(socket_link: &Path, label: &str) -> Result<PathBuf> {
        let socket_target = fs::read_link(socket_link)
            .with_context(|| format!("resolve {label} socket symlink {}", socket_link.display()))?;
        if socket_target.is_absolute() {
            Ok(socket_target)
        } else {
            Ok(socket_link
                .parent()
                .with_context(|| format!("{label} socket symlink has no parent"))?
                .join(socket_target))
        }
    }

    fn seed_cat_sha_via_nbd(&self, cat_id: &str, volume: &VolumeGrant) -> Result<String> {
        let mut source = vec![0u8; SEED_CAT_LEN as usize];
        File::open(&self.cfg.seed_image)?
            .read_exact_at(&mut source, SEED_CAT_OFFSET)
            .context("read /bin/cat extents from the Host seed image")?;
        let source_sha = hex::encode(cats_blockd::format::sha256(&source));
        ensure!(
            source_sha == SEED_CAT_SHA256,
            "seed image changed: expected /bin/cat {SEED_CAT_SHA256}, got {source_sha}"
        );

        let socket_link = self
            .cfg
            .state_dir
            .join("cats")
            .join(cat_id)
            .join(format!("nbd-{}.sock", volume.disk_id));
        let socket = Self::resolve_socket_link(&socket_link, "diagnostic NBD")?;
        let mut nbd = NbdClient::connect_unix(&socket).with_context(|| {
            format!(
                "connect diagnostic NBD socket {} (from {})",
                socket.display(),
                socket_link.display()
            )
        })?;
        let bytes = nbd
            .read(SEED_CAT_OFFSET, SEED_CAT_LEN)
            .context("read /bin/cat extents through blockd NBD")?;
        Ok(hex::encode(cats_blockd::format::sha256(&bytes)))
    }

    fn status(&self, cat_id: &str, volume: &VolumeGrant) -> Result<DurabilityStatus> {
        let socket_link = self.control_socket(cat_id, volume);
        let socket = Self::resolve_socket_link(&socket_link, "blockd control")?;
        durability_status(&socket)
    }

    fn drain(&self, cat_id: &str, volume: &VolumeGrant) -> Result<Duration> {
        let started = Instant::now();
        let socket_link = self.control_socket(cat_id, volume);
        let socket = Self::resolve_socket_link(&socket_link, "blockd control")?;
        control_command(&socket, "drain")?;
        let elapsed = started.elapsed();
        let status = self.status(cat_id, volume)?;
        ensure!(
            status.local_durable_generation == status.remote_durable_generation,
            "drain returned with L={} R={}",
            status.local_durable_generation,
            status.remote_durable_generation
        );
        Ok(elapsed)
    }

    fn boot_id(&self, cat_id: &str) -> Result<String> {
        Ok(self
            .exec(
                cat_id,
                vec!["cat".into(), "/proc/sys/kernel/random/boot_id".into()],
            )?
            .trim()
            .to_string())
    }

    fn sha256(&self, cat_id: &str, path: &str) -> Result<String> {
        let output = self.exec(cat_id, vec!["sha256sum".into(), path.to_string()])?;
        output
            .split_whitespace()
            .next()
            .map(str::to_string)
            .context("sha256sum returned no digest")
    }

    fn assert_vhost_vmm_processes(&self, expected: usize) -> Result<()> {
        let cmdlines = process_cmdlines("cloud-hypervisor", &self.cfg.state_dir)?;
        ensure!(
            cmdlines.len() == expected,
            "expected {expected} run-owned Cloud Hypervisor processes, got {}: {cmdlines:?}",
            cmdlines.len()
        );
        let socket_dir = self.cfg.socket_dir.to_string_lossy();
        for cmdline in cmdlines {
            ensure!(
                cmdline.contains("vhost_user=on,socket=")
                    && cmdline.contains(socket_dir.as_ref())
                    && !cmdline.contains("/dev/nbd"),
                "run-owned VMM is not exclusively on vhost-user: {cmdline}"
            );
        }
        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        let cats = self.cats.lock().unwrap().clone();
        let mut errors = Vec::new();
        for cat_id in cats {
            let stop = self.runtime.execute(self.job(NodeJobAction::StopCat {
                cat_id: cat_id.clone(),
                disposition: cats_api::nodejob::StopCatDisposition::Cold,
            }));
            if stop.phase != JobPhase::Succeeded {
                let cleanup = self.runtime.execute(self.job(NodeJobAction::CleanupCat {
                    cat_id: cat_id.clone(),
                }));
                if cleanup.phase != JobPhase::Succeeded {
                    errors.push(format!(
                        "cleanup {cat_id}: graceful={:?}, forced={:?}",
                        stop.error, cleanup.error
                    ));
                }
            }
        }
        for volume_id in self.volumes.lock().unwrap().clone() {
            // A failed test may leave an epoch live. The exact test-scoped row
            // is revoked before deletion so a stale child cannot republish.
            let _ = self.metadata.revoke_lease(&volume_id);
            if let Err(error) = self.metadata.delete_volume(&volume_id) {
                errors.push(format!("delete metadata {volume_id}: {error}"));
            }
        }
        for prefix in ["volumes/", "images/"] {
            match self.blob.list(prefix) {
                Ok(keys) => {
                    for key in keys {
                        if let Err(error) = self.blob.delete(&key) {
                            errors.push(format!("delete object {key}: {error}"));
                        }
                    }
                }
                Err(error) => errors.push(format!("list {prefix}: {error}")),
            }
        }
        if let Err(error) = fs::remove_dir_all(&self.cfg.state_dir) {
            if error.kind() != std::io::ErrorKind::NotFound {
                errors.push(format!("remove state directory: {error}"));
            }
        }
        if let Err(error) = fs::remove_dir_all(&self.cfg.socket_dir) {
            if error.kind() != std::io::ErrorKind::NotFound {
                errors.push(format!("remove socket directory: {error}"));
            }
        }
        ensure!(errors.is_empty(), "cleanup errors: {}", errors.join("; "));
        Ok(())
    }

    fn run(&self) -> Result<()> {
        let nbd_before = active_nbd_devices()?;
        let (cat_id, root) = self.names("bench");
        self.register(&cat_id, &root);

        let create_elapsed = self.start(&cat_id, &root)?;
        let nbd_after_bench_start = active_nbd_devices()?;
        if self.cfg.block_path == BlockPath::VhostUser {
            self.assert_vhost_vmm_processes(1)?;
        }

        let queues = self
            .exec(
                &cat_id,
                vec![
                    "sh".into(),
                    "-c".into(),
                    "find /sys/block/vda/mq -mindepth 1 -maxdepth 1 -type d | wc -l".into(),
                ],
            )?
            .trim()
            .parse::<usize>()
            .context("parse Guest vda queue count")?;
        if self.cfg.block_path == BlockPath::VhostUser {
            ensure!(queues == 1, "expected one vhost-user queue, got {queues}");
        }
        let mut guest_diagnostics =
            File::create(self.cfg.output_dir.join("guest-binary-diagnostics.txt"))?;
        let cat_sha_before = self.sha256(&cat_id, "/bin/cat")?;
        writeln!(guest_diagnostics, "cat_sha_before={cat_sha_before}")?;
        let nbd_cat_sha = self.seed_cat_sha_via_nbd(&cat_id, &root)?;
        writeln!(guest_diagnostics, "seed_cat_sha={SEED_CAT_SHA256}")?;
        writeln!(guest_diagnostics, "nbd_cat_sha={nbd_cat_sha}")?;
        ensure!(
            cat_sha_before == SEED_CAT_SHA256,
            "Guest /bin/cat differs from the immutable seed before benchmark writes"
        );
        ensure!(
            nbd_cat_sha == SEED_CAT_SHA256,
            "blockd NBD comparator differs from the immutable seed before benchmark writes"
        );
        let boot_before_install = self
            .boot_id(&cat_id)
            .context("read Guest boot id before installing the benchmark")?;
        writeln!(
            guest_diagnostics,
            "boot_id_before_install={boot_before_install}"
        )?;
        if self.cfg.preflight_only {
            return Ok(());
        }

        self.install_guest_bench(&cat_id)
            .context("install Guest benchmark")?;
        let cat_sha_after = self.sha256(&cat_id, "/bin/cat")?;
        let guest_bench_sha = self.sha256(&cat_id, GUEST_BENCH_PATH)?;
        writeln!(guest_diagnostics, "cat_sha_after={cat_sha_after}")?;
        writeln!(guest_diagnostics, "guest_bench_sha={guest_bench_sha}")?;
        ensure!(
            cat_sha_before == cat_sha_after,
            "/bin/cat changed while installing the Guest benchmark"
        );
        self.exec(
            &cat_id,
            vec![
                "sh".into(),
                "-c".into(),
                "printf 'cats-vhost-soak-canary\\n' > /var/tmp/soak-canary && sync".into(),
            ],
        )?;
        self.drain(&cat_id, &root)?;
        let canary_sha = self.sha256(&cat_id, "/var/tmp/soak-canary")?;
        let initial_boot = self
            .boot_id(&cat_id)
            .context("read Guest boot id after installing the benchmark")?;
        let block_diagnostics = self.exec(
            &cat_id,
            vec![
                "sh".into(),
                "-c".into(),
                "uname -a; \
                 findmnt -no SOURCE,FSTYPE,OPTIONS /; \
                 for name in io_poll io_poll_delay nr_requests scheduler write_cache; do \
                   printf '%s=' \"$name\"; cat \"/sys/block/vda/queue/$name\" 2>/dev/null || true; \
                 done; \
                 find /sys/block/vda/mq -maxdepth 2 -type f \
                   \\( -name cpu_list -o -name nr_reserved_tags -o -name nr_tags \\) \
                   -print -exec cat {} \\; 2>/dev/null; \
                 grep -E 'virtio|vda' /proc/interrupts || true"
                    .into(),
            ],
        )?;
        fs::write(
            self.cfg.output_dir.join("guest-block-diagnostics.txt"),
            block_diagnostics,
        )?;

        // Warm the helper, ext4 allocation metadata, and engine data structures;
        // these samples are intentionally excluded from the distribution.
        self.run_guest_bench(&cat_id, 20, 0)?;
        self.drain(&cat_id, &root)?;

        // Phase A: one long Guest process issues back-to-back fsyncs while the
        // real background publisher drains S3/PostgreSQL concurrently.
        let local_done = Arc::new(AtomicBool::new(false));
        let local_done_worker = local_done.clone();
        let runtime = self.runtime.clone();
        let burst_cat = cat_id.clone();
        let local_samples = self.cfg.local_samples;
        let burst_worker = thread::spawn(move || {
            let result = runtime.exec(
                &burst_cat,
                vec![
                    GUEST_BENCH_PATH.into(),
                    GUEST_DATA_PATH.into(),
                    local_samples.to_string(),
                    "10000".into(),
                    "128".into(),
                    cats_api::chunk::CHUNK_SIZE.to_string(),
                    "4096".into(),
                ],
            );
            local_done_worker.store(true, Ordering::SeqCst);
            result
        });
        let mut backlog_file = File::create(self.cfg.output_dir.join("backlog.csv"))?;
        writeln!(
            backlog_file,
            "elapsed_ms,local_generation,remote_generation,unpublished_generations,unpublished_bytes,oldest_age_ms,backpressured,publish_error"
        )?;
        let polling_started = Instant::now();
        let mut max_unpublished_generations = 0usize;
        let mut max_unpublished_bytes = 0u64;
        let mut max_oldest_age_ms = 0u64;
        let mut saw_backpressure = false;
        let mut saw_publish_error = false;
        while !local_done.load(Ordering::SeqCst) {
            if let Ok(status) = self.status(&cat_id, &root) {
                max_unpublished_generations =
                    max_unpublished_generations.max(status.unpublished_generations);
                max_unpublished_bytes = max_unpublished_bytes.max(status.unpublished_bytes);
                max_oldest_age_ms = max_oldest_age_ms.max(status.oldest_unpublished_age_ms);
                saw_backpressure |= status.backpressured;
                saw_publish_error |= status.last_publish_error.is_some();
                writeln!(
                    backlog_file,
                    "{},{},{},{},{},{},{},{}",
                    polling_started.elapsed().as_millis(),
                    status.local_durable_generation,
                    status.remote_durable_generation,
                    status.unpublished_generations,
                    status.unpublished_bytes,
                    status.oldest_unpublished_age_ms,
                    status.backpressured,
                    status
                        .last_publish_error
                        .as_deref()
                        .unwrap_or("")
                        .replace(',', ";")
                )?;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let (burst_code, burst_stdout, burst_stderr) = burst_worker
            .join()
            .map_err(|_| anyhow::anyhow!("Guest benchmark worker panicked"))??;
        ensure!(
            burst_code == 0,
            "Guest burst failed: stdout={burst_stdout:?}, stderr={burst_stderr:?}"
        );
        let local = parse_guest_samples(&burst_stdout)?;
        ensure!(
            local.len() == self.cfg.local_samples,
            "wanted {} local samples, got {}",
            self.cfg.local_samples,
            local.len()
        );
        let burst_final_drain = self.drain(&cat_id, &root)?;
        let mut local_file = File::create(self.cfg.output_dir.join("local-flush.csv"))?;
        writeln!(local_file, "sample,write_us,fsync_us,total_us,offset")?;
        for sample in &local {
            writeln!(
                local_file,
                "{},{},{},{},{}",
                sample.sample, sample.write_us, sample.fsync_us, sample.total_us, sample.offset
            )?;
        }

        // Phase B: stage exactly one local generation, then explicitly drain it.
        // The rare sample where the 5-second timer wins the race is preserved
        // and marked; percentile summaries use samples that actually entered
        // the explicit S3/PostgreSQL drain.
        let mut remote_file = File::create(self.cfg.output_dir.join("remote-drain.csv"))?;
        writeln!(
            remote_file,
            "sample,local_fsync_us,remote_drain_us,unpublished_before,bytes_before,local_generation,remote_generation,timer_raced"
        )?;
        let mut remote_drain_us = Vec::new();
        let mut remote_local_fsync_us = Vec::new();
        let mut timer_races = 0usize;
        for sample_index in 0..self.cfg.remote_samples {
            let guest = self.run_guest_bench(
                &cat_id,
                1,
                20_000 + u64::try_from(sample_index).unwrap_or(u64::MAX),
            )?;
            let before = self.status(&cat_id, &root)?;
            let timer_raced = before.unpublished_generations == 0;
            let drain_started = Instant::now();
            self.drain(&cat_id, &root)?;
            let drain_us = u64::try_from(drain_started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let after = self.status(&cat_id, &root)?;
            if timer_raced {
                timer_races += 1;
            } else {
                remote_drain_us.push(drain_us);
            }
            remote_local_fsync_us.push(guest[0].fsync_us);
            writeln!(
                remote_file,
                "{},{},{},{},{},{},{},{}",
                sample_index,
                guest[0].fsync_us,
                drain_us,
                before.unpublished_generations,
                before.unpublished_bytes,
                after.local_durable_generation,
                after.remote_durable_generation,
                timer_raced
            )?;
        }
        ensure!(
            remote_drain_us.len() >= self.cfg.remote_samples * 9 / 10,
            "background timer raced too many explicit drains: {timer_races}/{}",
            self.cfg.remote_samples
        );
        self.copy_bench_blockd_log(&cat_id, &root)?;

        // Lifecycle soak on one long-lived volume.
        let mut lifecycle_file = File::create(self.cfg.output_dir.join("lifecycle.csv"))?;
        writeln!(
            lifecycle_file,
            "phase,cycle,duration_us,boot_id_before,boot_id_after,boot_preserved,canary_ok"
        )?;
        let mut suspend_us = Vec::new();
        let mut warm_us = Vec::new();
        let mut restore_us = Vec::new();
        let mut cold_stop_us = Vec::new();
        let mut cold_start_us = Vec::new();
        let mut expected_boot = initial_boot;
        for cycle in 0..self.cfg.suspend_cycles {
            let before = self.boot_id(&cat_id)?;
            let started = Instant::now();
            self.execute(
                NodeJobAction::SuspendCat {
                    cat_id: cat_id.clone(),
                    work_fence: None,
                },
                ObservedState::Suspended,
            )?;
            let suspend = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let started = Instant::now();
            self.execute(
                NodeJobAction::ResumeCat {
                    cat_id: cat_id.clone(),
                },
                ObservedState::Running,
            )?;
            let resume = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let after = self.boot_id(&cat_id)?;
            let canary_ok = self.sha256(&cat_id, "/var/tmp/soak-canary")? == canary_sha;
            ensure!(
                before == after && canary_ok,
                "suspend cycle {cycle} violated the boot/canary oracle"
            );
            suspend_us.push(suspend);
            writeln!(
                lifecycle_file,
                "suspend_resume,{cycle},{},{before},{after},true,{canary_ok}",
                suspend.saturating_add(resume)
            )?;
        }
        for cycle in 0..self.cfg.warm_cycles {
            self.exec(
                &cat_id,
                vec![
                    "sh".into(),
                    "-c".into(),
                    format!("printf 'warm-{cycle}\\n' > /var/tmp/warm-marker && sync"),
                ],
            )?;
            let before = self.boot_id(&cat_id)?;
            let started = Instant::now();
            self.execute(
                NodeJobAction::WarmCat {
                    cat_id: cat_id.clone(),
                },
                ObservedState::Warm,
            )?;
            let warm = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let started = Instant::now();
            self.execute(
                NodeJobAction::RestoreCat {
                    cat_id: cat_id.clone(),
                },
                ObservedState::Running,
            )?;
            let restore = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let after = self.boot_id(&cat_id)?;
            let canary_ok = self.sha256(&cat_id, "/var/tmp/soak-canary")? == canary_sha;
            ensure!(
                before == after && canary_ok,
                "warm cycle {cycle} violated the boot/canary oracle"
            );
            warm_us.push(warm);
            restore_us.push(restore);
            writeln!(
                lifecycle_file,
                "warm_restore,{cycle},{},{before},{after},true,{canary_ok}",
                warm.saturating_add(restore)
            )?;
        }
        for cycle in 0..self.cfg.cold_cycles {
            self.exec(
                &cat_id,
                vec![
                    "sh".into(),
                    "-c".into(),
                    format!("printf 'cold-{cycle}\\n' > /var/tmp/cold-marker && sync"),
                ],
            )?;
            let before = self.boot_id(&cat_id)?;
            let started = Instant::now();
            self.execute(
                NodeJobAction::StopCat {
                    cat_id: cat_id.clone(),
                    disposition: cats_api::nodejob::StopCatDisposition::Cold,
                },
                ObservedState::Cold,
            )?;
            let stop = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let start = self.start(&cat_id, &root)?;
            let start = u64::try_from(start.as_micros()).unwrap_or(u64::MAX);
            let after = self.boot_id(&cat_id)?;
            let canary_ok = self.sha256(&cat_id, "/var/tmp/soak-canary")? == canary_sha;
            ensure!(
                before != after && canary_ok,
                "cold cycle {cycle} violated the fresh-boot/canary oracle"
            );
            cold_stop_us.push(stop);
            cold_start_us.push(start);
            writeln!(
                lifecycle_file,
                "cold_restart,{cycle},{},{before},{after},false,{canary_ok}",
                stop.saturating_add(start)
            )?;
            expected_boot = after;
        }
        ensure!(
            self.boot_id(&cat_id)? == expected_boot,
            "benchmark Cat boot identity changed unexpectedly"
        );

        // Real concurrent cold starts and Warm restores. The image was already
        // published by the benchmark Cat, so this measures per-Cat work rather
        // than the one-time image upload.
        let mut concurrent = Vec::new();
        for index in 0..self.cfg.concurrent_cats {
            let (concurrent_cat, volume) = self.names(&format!("c{index}"));
            self.register(&concurrent_cat, &volume);
            concurrent.push((concurrent_cat, volume));
        }
        let launch_wall_started = Instant::now();
        let mut launch_workers = Vec::new();
        for (concurrent_cat, volume) in &concurrent {
            let runtime = self.runtime.clone();
            let job = self.job(NodeJobAction::StartCat {
                cat_id: concurrent_cat.clone(),
                image: "soak-golden-root".into(),
                cpus: 1,
                memory_mib: 512,
                volumes: vec![volume.clone()],
            });
            launch_workers.push(thread::spawn(move || {
                let started = Instant::now();
                (runtime.execute(job), started.elapsed())
            }));
        }
        let mut concurrent_launch_us = Vec::new();
        for worker in launch_workers {
            let (result, elapsed) = worker
                .join()
                .map_err(|_| anyhow::anyhow!("concurrent launch worker panicked"))?;
            ensure!(
                result.phase == JobPhase::Succeeded
                    && result.observed_state == ObservedState::Running,
                "concurrent launch failed: {result:?}"
            );
            concurrent_launch_us.push(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
        }
        let concurrent_launch_wall_us =
            u64::try_from(launch_wall_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        if self.cfg.block_path == BlockPath::VhostUser {
            self.assert_vhost_vmm_processes(1 + self.cfg.concurrent_cats)?;
        }

        let mut concurrent_boots = Vec::new();
        for (concurrent_cat, volume) in &concurrent {
            let queue_count = self
                .exec(
                    concurrent_cat,
                    vec![
                        "sh".into(),
                        "-c".into(),
                        "find /sys/block/vda/mq -mindepth 1 -maxdepth 1 -type d | wc -l".into(),
                    ],
                )?
                .trim()
                .parse::<usize>()?;
            if self.cfg.block_path == BlockPath::VhostUser {
                ensure!(queue_count == 1, "{concurrent_cat} is not on vhost-user");
            }
            self.exec(
                concurrent_cat,
                vec![
                    "sh".into(),
                    "-c".into(),
                    format!(
                        "printf '{}\\n' > /var/tmp/concurrent-canary && sync",
                        concurrent_cat
                    ),
                ],
            )?;
            self.execute(
                NodeJobAction::SyncCat {
                    cat_id: concurrent_cat.clone(),
                },
                ObservedState::Running,
            )?;
            concurrent_boots.push(self.boot_id(concurrent_cat)?);
            self.execute(
                NodeJobAction::WarmCat {
                    cat_id: concurrent_cat.clone(),
                },
                ObservedState::Warm,
            )?;
            let status_path = self.control_socket(concurrent_cat, volume);
            ensure!(
                fs::symlink_metadata(&status_path).is_err(),
                "Warm Cat retained a blockd control socket: {}",
                status_path.display()
            );
        }
        let restore_wall_started = Instant::now();
        let mut restore_workers = Vec::new();
        for (concurrent_cat, _) in &concurrent {
            let runtime = self.runtime.clone();
            let job = self.job(NodeJobAction::RestoreCat {
                cat_id: concurrent_cat.clone(),
            });
            restore_workers.push(thread::spawn(move || {
                let started = Instant::now();
                (runtime.execute(job), started.elapsed())
            }));
        }
        let mut concurrent_restore_us = Vec::new();
        for worker in restore_workers {
            let (result, elapsed) = worker
                .join()
                .map_err(|_| anyhow::anyhow!("concurrent restore worker panicked"))?;
            ensure!(
                result.phase == JobPhase::Succeeded
                    && result.observed_state == ObservedState::Running,
                "concurrent restore failed: {result:?}"
            );
            concurrent_restore_us.push(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
        }
        let concurrent_restore_wall_us =
            u64::try_from(restore_wall_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        for ((concurrent_cat, _), boot_before) in concurrent.iter().zip(&concurrent_boots) {
            ensure!(
                self.boot_id(concurrent_cat)? == *boot_before,
                "{concurrent_cat} changed boot id across concurrent Warm restore"
            );
            ensure!(
                self.exec(
                    concurrent_cat,
                    vec!["cat".into(), "/var/tmp/concurrent-canary".into()]
                )?
                .trim()
                    == concurrent_cat,
                "{concurrent_cat} lost its concurrent canary"
            );
        }

        let local_fsync = distribution(
            &local
                .iter()
                .map(|sample| sample.fsync_us)
                .collect::<Vec<_>>(),
        )?;
        let local_total = distribution(
            &local
                .iter()
                .map(|sample| sample.total_us)
                .collect::<Vec<_>>(),
        )?;
        let remote_local_fsync = distribution(&remote_local_fsync_us)?;
        let remote_drain = distribution(&remote_drain_us)?;
        let summary = serde_json::json!({
            "run_id": self.cfg.run_id,
            "environment": {
                "block_path": self.cfg.block_path.as_str(),
                "vhost_user_queues": queues,
                "state_dir": self.cfg.state_dir,
                "s3_prefix": self.cfg.s3_prefix,
                "active_nbd_before": nbd_before,
                "active_nbd_after_bench_start": nbd_after_bench_start,
                "active_nbd_after_launches": active_nbd_devices()?,
            },
            "single_create_us": u64::try_from(create_elapsed.as_micros()).unwrap_or(u64::MAX),
            "local_flush": distribution_json(local_fsync),
            "local_write_plus_flush": distribution_json(local_total),
            "remote_phase_local_flush": distribution_json(remote_local_fsync),
            "remote_drain": distribution_json(remote_drain),
            "remote_timer_races": timer_races,
            "burst_final_drain_us": u64::try_from(burst_final_drain.as_micros()).unwrap_or(u64::MAX),
            "backlog": {
                "max_unpublished_generations": max_unpublished_generations,
                "max_unpublished_bytes": max_unpublished_bytes,
                "max_oldest_age_ms": max_oldest_age_ms,
                "saw_backpressure": saw_backpressure,
                "saw_publish_error": saw_publish_error,
            },
            "lifecycle": {
                "suspend": distribution_json(distribution(&suspend_us)?),
                "warm": distribution_json(distribution(&warm_us)?),
                "restore": distribution_json(distribution(&restore_us)?),
                "cold_stop": distribution_json(distribution(&cold_stop_us)?),
                "cold_start": distribution_json(distribution(&cold_start_us)?),
                "canary_sha256": canary_sha,
            },
            "concurrency": {
                "cats": self.cfg.concurrent_cats,
                "cold_launch_wall_us": concurrent_launch_wall_us,
                "cold_launch_per_cat": distribution_json(distribution(&concurrent_launch_us)?),
                "warm_restore_wall_us": concurrent_restore_wall_us,
                "warm_restore_per_cat": distribution_json(distribution(&concurrent_restore_us)?),
            },
        });
        let summary_path = self.cfg.output_dir.join("summary.json");
        fs::write(&summary_path, serde_json::to_vec_pretty(&summary)?)?;
        println!("SOAK_SUMMARY {}", serde_json::to_string(&summary)?);
        Ok(())
    }
}

#[test]
#[ignore = "requires Linux bare metal, KVM, Cloud Hypervisor, real S3/PostgreSQL, and isolated run-scoped configuration"]
fn metal_vhost_user_soak() -> Result<()> {
    let cfg = SoakConfig::from_env()?;
    let soak = Soak::new(cfg)?;
    let run_result = soak.run();
    let cleanup_result = soak.cleanup();
    match (run_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(run_error), Ok(())) => Err(run_error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(run_error), Err(cleanup_error)) => Err(anyhow::anyhow!(
            "soak failed: {run_error:#}; cleanup also failed: {cleanup_error:#}"
        )),
    }
}
