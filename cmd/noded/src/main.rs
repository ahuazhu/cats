use std::path::PathBuf;

use anyhow::Context;
use cats_metadata_store_postgres::PostgresMetadataStoreFactory;
use cats_metadata_store_sqlite::SqliteMetadataStoreFactory;
use cats_node_agent::runtime::NodeConfig;
use cats_node_agent::server::{spawn, ServerConfig};
use cats_storage::{open_metadata_store, AdapterConfig, AdapterSelection, MetadataStoreFactory};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cats-noded", about = "Cats node agent")]
struct Args {
    #[arg(long)]
    node_id: String,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    #[arg(long, env = "CATS_NODE_ADVERTISE_URL")]
    advertise_url: Option<String>,
    #[arg(long)]
    control_plane_url: String,
    #[arg(long, env = "CATS_AUTH_TOKEN", default_value = "dev-service-token")]
    auth_token: String,
    #[arg(long, default_value = "")]
    gateway_url: String,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    blockd_bin: PathBuf,
    #[arg(long)]
    guest_agent_bin: PathBuf,
    #[arg(long)]
    metadata_store_adapter: String,
    #[arg(long = "metadata-store-option", value_name = "KEY=VALUE")]
    metadata_store_options: Vec<String>,
    #[arg(long)]
    object_store_adapter: String,
    #[arg(long = "object-store-option", value_name = "KEY=VALUE")]
    object_store_options: Vec<String>,
    /// Schedulable logical CPUs. Defaults to the detected host total.
    #[arg(long, env = "CATS_NODE_CPUS")]
    cpus: Option<u32>,
    /// Schedulable memory in MiB. Defaults to the detected host total.
    #[arg(long, env = "CATS_NODE_MEMORY_MIB")]
    memory_mib: Option<u64>,
    #[arg(long, default_value_t = 1000)]
    heartbeat_ms: u64,
    #[arg(long, default_value_t = 1500)]
    blockd_lease_ttl_ms: i64,
    /// Delegated cgroup v2 subtree for authoritative billing counters.
    #[arg(long, env = "CATS_METERING_CGROUP_ROOT")]
    metering_cgroup_root: Option<PathBuf>,

    /// Concurrent-wake commitment budget in bytes (ADR-0002 §8). Accounted in
    /// bytes because the 2026-07-21 run showed Guest memory page read-back is
    /// the limit, not the VMM. Default is the validated operating point
    /// (10 x 512 MiB), not a proven optimum: re-measure before raising it.
    #[arg(long, env = "CATS_WAKE_COMMITMENT_BUDGET_BYTES",
          default_value_t = cats_node_agent::admission::DEFAULT_WAKE_COMMITMENT_BUDGET_BYTES)]
    wake_commitment_budget_bytes: u64,
    /// Ceiling on concurrently admitted wakes, so many tiny Cats cannot
    /// bypass the byte budget. Default is the validated concurrency.
    #[arg(long, env = "CATS_MAX_CONCURRENT_WAKES",
          default_value_t = cats_node_agent::admission::DEFAULT_MAX_CONCURRENT_WAKES)]
    max_concurrent_wakes: usize,
    /// How long a wake may queue for budget before the node reports it cannot
    /// serve the wake. Above the slowest measured concurrent restore (EBS
    /// first-health P50 19.05 s) so a slow medium queues instead of falling
    /// back to Cold.
    #[arg(long, env = "CATS_WAKE_QUEUE_TIMEOUT_SECS", default_value_t = 60)]
    wake_queue_timeout_secs: u64,

    /// VMM mode: fake (host processes) or ch (Cloud Hypervisor, Linux+KVM).
    #[arg(long, default_value = "fake")]
    vmm: String,
    #[arg(long, default_value = "/usr/local/bin/cloud-hypervisor")]
    ch_bin: PathBuf,
    #[arg(long, default_value = "/opt/cats/guest/vmlinux")]
    ch_kernel: PathBuf,
    #[arg(long)]
    ch_initramfs: Option<PathBuf>,
    /// `clocksource=kvm-clock` is load-bearing, not cosmetic. On a host with an
    /// invariant TSC the guest kernel demotes kvm-clock to rating 299 and picks
    /// raw `tsc` instead (`arch/x86/kernel/kvmclock.c`), because reading `rdtsc`
    /// is cheaper. But a Warm restore re-establishes the guest clock through
    /// `KVM_SET_CLOCK`, which moves kvmclock -- a clock a `tsc` guest never
    /// reads. Its TSC is restored to the snapshot value instead, so all three
    /// guest clocks resume frozen at the moment of the snapshot and the lag
    /// accumulates across every Warm cycle
    /// (`experiments/suspend-clock-semantics-20260727`). Pinning kvm-clock puts
    /// the guest back on the clock the restore path actually adjusts.
    #[arg(
        long,
        default_value = "console=ttyS0 root=/dev/vda rw quiet clocksource=kvm-clock"
    )]
    ch_cmdline: String,
    /// Raw golden-root image written into fresh root volumes.
    #[arg(long)]
    ch_seed_image: Option<PathBuf>,
    /// Guest block data path: `kernel-nbd` (Phase A) or `vhost-user` (native
    /// virtio-blk straight into cats-blockd).
    #[arg(long, default_value = "kernel-nbd")]
    ch_block_path: String,
    /// Open the kernel-NBD device with O_DIRECT, so the host page cache stops
    /// acking Guest writes the engine has not seen yet. Off matches Cloud
    /// Hypervisor's default and is what the fleet runs today; on is what a
    /// like-for-like comparison against vhost-user requires (ADR-0015).
    #[arg(long, default_value_t = false)]
    ch_block_direct: bool,
    /// virtio-blk queues per disk on the vhost-user path.
    #[arg(long, default_value_t = 1)]
    ch_vhost_user_queues: usize,
    /// Depth of each virtio-blk queue on the vhost-user path.
    #[arg(long, default_value_t = 256)]
    ch_vhost_user_queue_size: u16,
    #[arg(long, default_value = "/usr/sbin/nbd-client")]
    ch_nbd_client: PathBuf,
    #[arg(long, default_value_t = 64)]
    ch_nbd_devices: u32,
    /// Optional private /16 split into per-Cat /30 tap networks.
    #[arg(long)]
    ch_network_cidr: Option<String>,
    #[arg(long, default_value = "/usr/sbin/ip")]
    ch_ip_bin: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let detected_cpus = std::thread::available_parallelism()
        .map(|count| u32::try_from(count.get()))
        .map_err(anyhow::Error::from)??;
    let detected_memory_mib = detect_host_memory_mib()?;
    let cpus = args.cpus.unwrap_or(detected_cpus);
    let memory_mib = args.memory_mib.unwrap_or(detected_memory_mib);
    anyhow::ensure!(cpus > 0, "--cpus must be greater than zero");
    anyhow::ensure!(memory_mib > 0, "--memory-mib must be greater than zero");
    tracing::info!(
        schedulable_cpus = cpus,
        schedulable_memory_mib = memory_mib,
        detected_cpus,
        detected_memory_mib,
        "resolved node capacity"
    );
    let metadata_store = AdapterSelection::new(
        args.metadata_store_adapter,
        AdapterConfig::from_cli(args.metadata_store_options)?,
    );
    let object_store = AdapterSelection::new(
        args.object_store_adapter,
        AdapterConfig::from_cli(args.object_store_options)?,
    );
    let metadata_factories: [&dyn MetadataStoreFactory; 2] =
        [&SqliteMetadataStoreFactory, &PostgresMetadataStoreFactory];
    let storage_meta = open_metadata_store(
        &metadata_store.name,
        &metadata_store.config,
        &metadata_factories,
    )?;
    let vmm = match args.vmm.as_str() {
        "fake" => cats_node_agent::runtime::VmmMode::Fake,
        "ch" => cats_node_agent::runtime::VmmMode::CloudHypervisor(cats_node_agent::ch::ChConfig {
            ch_bin: args.ch_bin.clone(),
            kernel: args.ch_kernel.clone(),
            initramfs: args.ch_initramfs.clone(),
            cmdline: args.ch_cmdline.clone(),
            seed_image: args.ch_seed_image.clone(),
            block_path: cats_node_agent::ch::BlockPath::parse(&args.ch_block_path)?,
            block_direct: args.ch_block_direct,
            vhost_user_queues: args.ch_vhost_user_queues,
            vhost_user_queue_size: args.ch_vhost_user_queue_size,
            nbd_client_bin: args.ch_nbd_client.clone(),
            nbd_devices: args.ch_nbd_devices,
            network_cidr: args.ch_network_cidr.clone(),
            ip_bin: args.ch_ip_bin.clone(),
        }),
        other => anyhow::bail!("unknown --vmm {other} (expected fake|ch)"),
    };
    let handle = spawn(ServerConfig {
        listen: args.listen,
        advertise_url: args.advertise_url,
        control_plane_url: args.control_plane_url,
        auth_token: args.auth_token,
        gateway_url: args.gateway_url,
        cpus,
        memory_mib,
        heartbeat_ms: args.heartbeat_ms,
        node: NodeConfig {
            node_id: args.node_id,
            state_dir: args.state_dir,
            blockd_bin: args.blockd_bin,
            guest_agent_bin: args.guest_agent_bin,
            metadata_store,
            object_store,
            blockd_lease_ttl_ms: args.blockd_lease_ttl_ms,
            metering_cgroup_root: args.metering_cgroup_root,
            wake_budget: cats_node_agent::admission::WakeBudget {
                commitment_bytes: args.wake_commitment_budget_bytes,
                max_wakes: args.max_concurrent_wakes,
                queue_timeout: std::time::Duration::from_secs(args.wake_queue_timeout_secs),
            },
            vmm,
        },
        storage_meta,
    })
    .await?;
    println!("READY {}", handle.addr);
    std::future::pending::<()>().await;
    Ok(())
}

fn detect_host_memory_mib() -> anyhow::Result<u64> {
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(memory_mib) = parse_linux_memory_mib(&contents) {
            return Ok(memory_mib);
        }
    }
    // SAFETY: sysconf reads process-wide host configuration and does not
    // dereference pointers. Negative results are checked before conversion.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    // SAFETY: same as above for the page-size selector.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    anyhow::ensure!(
        pages > 0 && page_size > 0,
        "could not detect host memory; pass --memory-mib explicitly"
    );
    u64::try_from(pages)
        .and_then(|pages| u64::try_from(page_size).map(|size| pages.saturating_mul(size)))
        .map(|bytes| bytes / 1024 / 1024)
        .context("detected host memory does not fit in u64")
}

fn parse_linux_memory_mib(contents: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "MemTotal:" {
            return None;
        }
        fields.next()?.parse::<u64>().ok().map(|kib| kib / 1024)
    })
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    fn workspace_root() -> &'static std::path::Path {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root")
    }

    #[test]
    fn parses_linux_host_memory() {
        assert_eq!(
            super::parse_linux_memory_mib("MemTotal:       197659444 kB\nMemFree: 1 kB\n"),
            Some(193_026)
        );
    }

    #[test]
    fn default_guest_cmdline_pins_kvm_clock() {
        let command = super::Args::command();
        let arg = command
            .get_arguments()
            .find(|a| a.get_id() == "ch_cmdline")
            .expect("--ch-cmdline argument");
        let default = arg
            .get_default_values()
            .first()
            .expect("--ch-cmdline has a default")
            .to_string_lossy()
            .into_owned();
        assert!(
            default.contains("clocksource=kvm-clock"),
            "a guest left on the `tsc` clocksource resumes from a Warm restore with \
             all three clocks frozen at the snapshot instant; got {default:?}"
        );
    }

    /// The units pass `--ch-cmdline` explicitly, so they override the default
    /// above rather than inheriting it. A fix applied only to the default would
    /// never reach a deployed node.
    #[test]
    fn deployment_units_pin_kvm_clock_too() {
        for unit in [
            "deploy/metal/systemd/cats-noded.service",
            "deploy/aws/metal/cats-worker.service",
        ] {
            let path = workspace_root().join(unit);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let line = text
                .lines()
                .find(|l| l.contains("--ch-cmdline"))
                .unwrap_or_else(|| panic!("{unit} no longer passes --ch-cmdline"));
            assert!(
                line.contains("clocksource=kvm-clock"),
                "{unit} overrides the guest cmdline without pinning kvm-clock: {line}"
            );
        }
    }

    #[test]
    fn guest_image_defaults_to_systemd_with_early_agent_readiness() {
        let path = workspace_root().join("deploy/metal/build-guest-image.sh");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        for required in [
            "GUEST_INIT_MODE=${GUEST_INIT_MODE:-systemd}",
            "PRIMARY_INIT=/sbin/init",
            "FALLBACK_INIT=/usr/bin/cats-init",
            "Description=Configure the Cats Guest network",
            "Before=cats-guest-agent.service network.target",
            "Requires=cats-grow-root.service cats-network.service",
            "After=cats-grow-root.service cats-network.service systemd-remount-fs.service",
            "Before=sysinit.target",
            "WantedBy=sysinit.target",
            "serial-getty@ttyS0.service",
            "systemd-networkd-wait-online.service",
        ] {
            assert!(
                text.contains(required),
                "guest image lost systemd support contract fragment {required:?}"
            );
        }
    }

    #[test]
    fn metal_acceptance_covers_systemd_service_lifecycle() {
        let path = workspace_root().join("deploy/metal/e2e.sh");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        for required in [
            "guest uses systemd as PID 1",
            "systemctl enable --now cats-e2e.service",
            "Warm preserves the service PID",
            "Warm does not restart the service",
            "Cold starts the service exactly once again",
        ] {
            assert!(
                text.contains(required),
                "metal acceptance lost systemd lifecycle oracle {required:?}"
            );
        }
    }
}
