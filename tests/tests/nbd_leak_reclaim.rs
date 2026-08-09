//! Ignored, Linux-only, root-only: kernel NBD leak and reclaim (issue #79).
//!
//! Everything here turns on the kernel nbd driver's actual behaviour, which no
//! unit test can stand in for, so it runs against real `/dev/nbdN` devices and
//! a real `cats-blockd`. It needs root, the `nbd` module loaded, `nbd-client`,
//! and a device pool the run may take over:
//!
//! ```sh
//! sudo modprobe nbd nbds_max=8
//! cargo build -p cats-blockd-daemon
//! sudo -E CATS_NBD_TEST_BLOCKD_BIN=target/debug/cats-blockd \
//!     CATS_NBD_TEST_DEVICES=8 \
//!     cargo test -p cats-e2e --test nbd_leak_reclaim -- --ignored --nocapture
//! ```
//!
//! The oracle is sysfs, read directly rather than through the code under test.
//! Measured on Linux 6.17 / nbd-client 3.26.1; raw logs in
//! `experiments/nbd-attach-mode-20260804/`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use cats_node_agent::ch::{
    leaked_nbd_device_count, nbd_attach, nbd_detach, reclaim_leaked_nbd_devices, BlockPath,
    ChConfig,
};

const VOLUME_BYTES: u64 = 1024 * 1024 * 1024;

fn env_path(name: &str) -> Result<PathBuf> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    let path = PathBuf::from(value);
    anyhow::ensure!(path.exists(), "{name} does not exist: {}", path.display());
    Ok(path)
}

fn nbd_client_bin() -> PathBuf {
    PathBuf::from(
        std::env::var("CATS_NBD_TEST_NBD_CLIENT")
            .unwrap_or_else(|_| "/usr/sbin/nbd-client".to_string()),
    )
}

fn config() -> Result<ChConfig> {
    Ok(ChConfig {
        block_direct: false,
        ch_bin: PathBuf::from("/nonexistent"),
        kernel: PathBuf::from("/nonexistent"),
        initramfs: None,
        boot_contract: None,
        cmdline: String::new(),
        seed_image: None,
        block_path: BlockPath::KernelNbd,
        vhost_user_queues: 1,
        vhost_user_queue_size: 256,
        nbd_client_bin: nbd_client_bin(),
        nbd_devices: std::env::var("CATS_NBD_TEST_DEVICES")
            .unwrap_or_else(|_| "8".to_string())
            .parse()?,
        network_cidr: None,
        ip_bin: PathBuf::from("/usr/sbin/ip"),
    })
}

/// What the kernel says, read straight from sysfs.
fn sysfs(device: &str) -> (Option<i32>, u64) {
    let n = device.trim_start_matches("/dev/nbd");
    let pid = std::fs::read_to_string(format!("/sys/block/nbd{n}/pid"))
        .ok()
        .and_then(|value| value.trim().parse().ok());
    let size = std::fs::read_to_string(format!("/sys/block/nbd{n}/size"))
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    (pid, size)
}

fn pid_is_alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).is_dir()
}

fn wait_until<F: Fn() -> bool>(what: &str, condition: F) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !condition() {
        if Instant::now() > deadline {
            bail!("timed out waiting for {what}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

struct Blockd {
    child: Child,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}

impl Blockd {
    fn spawn(binary: &Path, id: &str) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let socket = dir.path().join("nbd.sock");
        let child = Command::new(binary)
            .arg("--volume-id")
            .arg(format!("vol_{id}"))
            .arg("--attachment-id")
            .arg(format!("att_{id}"))
            .arg("--lease-ttl-ms")
            .arg("5000")
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .arg("--metadata-store-adapter")
            .arg("sqlite")
            .arg("--metadata-store-option")
            .arg(format!("path={}", dir.path().join("meta.db").display()))
            .arg("--object-store-adapter")
            .arg("file")
            .arg("--object-store-option")
            .arg(format!("root={}", dir.path().join("blob").display()))
            .arg("--listen-unix")
            .arg(&socket)
            .arg("--create-volume-size")
            .arg(VOLUME_BYTES.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn cats-blockd")?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !socket.exists() {
            if Instant::now() > deadline {
                bail!("cats-blockd never bound {}", socket.display());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_millis(500));
        Ok(Self {
            child,
            socket,
            _dir: dir,
        })
    }

    fn kill(&mut self) -> Result<()> {
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }
}

/// The whole of issue #79 against a real kernel: a blockd killed without a
/// teardown while the disk is held open leaves a device the count reports, the
/// sweep refuses to touch while it is held, and the kernel releases once the
/// holder goes -- after which the slot serves a new Cat.
#[test]
#[ignore = "requires Linux, root, the nbd kernel module and a real cats-blockd"]
fn a_blockd_killed_without_teardown_leaves_a_device_that_comes_back() -> Result<()> {
    let blockd_bin = env_path("CATS_NBD_TEST_BLOCKD_BIN")?;
    let cfg = config()?;

    let mut server = Blockd::spawn(&blockd_bin, "leak")?;
    let device = nbd_attach(&cfg, &server.socket, None)?;
    println!("attached {device}");

    let (pid, size) = sysfs(&device);
    let pid = pid.context("a healthy device must record a serving pid")?;
    assert!(
        pid_is_alive(pid),
        "the attach must leave a resident nbd-client: under nbd-client's \
         default netlink mode this pid is dead even on a healthy device, and \
         no leak detector can work"
    );
    assert!(size > 0, "a healthy device reports a size");
    assert_eq!(
        leaked_nbd_device_count(&cfg),
        0,
        "a healthy device must never be counted as leaked"
    );

    // Production shape: Cloud Hypervisor still holds the disk when blockd dies.
    let holder = std::fs::File::open(&device).context("hold the device open")?;
    server.kill()?;
    wait_until("the serving nbd-client to notice", || !pid_is_alive(pid))?;

    let (leaked_pid, leaked_size) = sysfs(&device);
    assert_eq!(
        leaked_pid,
        Some(pid),
        "the dead server's pid is still there"
    );
    assert!(leaked_size > 0, "the kernel still has the device connected");
    assert_eq!(
        leaked_nbd_device_count(&cfg),
        1,
        "this is the number that was missing on 2026-08-04"
    );

    // Held open, so the sweep must decline: sysfs cannot tell this from a
    // healthy device attached by an older agent, and disconnecting a device a
    // live process is using would take a running Guest's disk away.
    let reclaim = reclaim_leaked_nbd_devices(&cfg)?;
    assert_eq!(
        reclaim.reclaimed,
        Vec::<String>::new(),
        "nothing may be disconnected while it is held open, got {reclaim:?}"
    );
    assert!(reclaim.unreclaimed.contains(&device));
    assert!(sysfs(&device).1 > 0, "the sweep must not have touched it");

    // Once the holder is gone the resident nbd-client's teardown has already
    // cleared the socket, so the kernel releases the device on its own.
    drop(holder);
    wait_until("the kernel to release the device", || {
        sysfs(&device) == (None, 0)
    })?;
    assert_eq!(leaked_nbd_device_count(&cfg), 0);

    // The slot has to come back into service, not merely stop being dangerous.
    let mut second = Blockd::spawn(&blockd_bin, "reuse")?;
    let reused = nbd_attach(&cfg, &second.socket, Some(&device))?;
    assert_eq!(reused, device);
    let (reused_pid, reused_size) = sysfs(&device);
    assert!(reused_pid.is_some_and(pid_is_alive));
    assert!(reused_size > 0);

    nbd_detach(&cfg, &device);
    second.kill()?;
    Ok(())
}

/// A device leaked by the previous, netlink-based attach is permanent, and is
/// what the boot sweep exists to clear.
///
/// Netlink leaves no resident client, so when the server dies the kernel keeps
/// the configuration open forever -- the device stays connected even after its
/// last opener closes. This is the state 27 devices were found in; the only
/// way out is an explicit disconnect.
#[test]
#[ignore = "requires Linux, root, the nbd kernel module and a real cats-blockd"]
fn a_device_leaked_by_the_netlink_attach_is_permanent_until_the_sweep() -> Result<()> {
    let blockd_bin = env_path("CATS_NBD_TEST_BLOCKD_BIN")?;
    let cfg = config()?;
    let device = format!("/dev/nbd{}", cfg.nbd_devices - 1);

    let mut server = Blockd::spawn(&blockd_bin, "legacy")?;
    // Deliberately not through `nbd_attach`: this reproduces what the node
    // agent did before this change.
    let attached = Command::new(nbd_client_bin())
        .arg("-unix")
        .arg(&server.socket)
        .arg(&device)
        .args(["-b", "512", "-N", ""])
        .output()
        .context("legacy netlink attach")?;
    anyhow::ensure!(
        attached.status.success(),
        "legacy attach failed: {}",
        String::from_utf8_lossy(&attached.stderr)
    );
    std::thread::sleep(Duration::from_secs(1));

    let (pid, size) = sysfs(&device);
    assert!(size > 0, "attached");
    assert!(
        !pid.is_some_and(pid_is_alive),
        "netlink leaves no resident client -- this is exactly why the recorded \
         pid cannot be trusted on a device attached this way"
    );

    let holder = std::fs::File::open(&device)?;
    server.kill()?;
    std::thread::sleep(Duration::from_secs(3));
    drop(holder);
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        sysfs(&device).1 > 0,
        "a netlink-attached device stays connected after its server and its \
         last opener are both gone: nothing reclaims it"
    );
    assert_eq!(leaked_nbd_device_count(&cfg), 1);

    let reclaim = reclaim_leaked_nbd_devices(&cfg)?;
    assert!(
        reclaim.reclaimed.contains(&device),
        "the sweep is the only thing that gets this slot back, got {reclaim:?}"
    );
    assert_eq!(sysfs(&device), (None, 0));
    assert_eq!(leaked_nbd_device_count(&cfg), 0);

    let mut second = Blockd::spawn(&blockd_bin, "after-legacy")?;
    let reused = nbd_attach(&cfg, &second.socket, Some(&device))?;
    assert_eq!(reused, device);
    assert!(sysfs(&device).0.is_some_and(pid_is_alive));

    nbd_detach(&cfg, &device);
    second.kill()?;
    Ok(())
}
