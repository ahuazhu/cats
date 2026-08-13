//! Real-binary frontend, image, GC and explicit-grant composition tests.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI64, Ordering};

use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_storage::MetadataStore;

const VOL_SIZE: u64 = 4 * cats_api::chunk::CHUNK_SIZE as u64;

struct Env {
    dir: tempfile::TempDir,
    next_epoch: AtomicI64,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            dir: tempfile::tempdir().unwrap(),
            next_epoch: AtomicI64::new(1),
        };
        env.metadata()
            .create_volume("vol_frontends", VOL_SIZE)
            .unwrap();
        env
    }

    fn metadata(&self) -> SqliteMetadataStore {
        SqliteMetadataStore::open(&self.path("meta.db")).unwrap()
    }

    /// External test authority: install an exact grant before constructing the
    /// daemon command. The daemon receives that epoch and cannot acquire one.
    fn command(&self, attachment: &str) -> Command {
        let epoch = self.next_epoch.fetch_add(1, Ordering::SeqCst);
        self.metadata()
            .install_grant_for_tests("vol_frontends", attachment, epoch)
            .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_cats-blockd"));
        command
            .args([
                "--volume-id",
                "vol_frontends",
                "--attachment-id",
                attachment,
                "--attachment-epoch",
                &epoch.to_string(),
            ])
            .arg("--data-dir")
            .arg(self.path(&format!("data-{attachment}")))
            .arg("--metadata-store-adapter")
            .arg("sqlite")
            .arg("--metadata-store-option")
            .arg(format!("path={}", self.path("meta.db").display()))
            .arg("--object-store-adapter")
            .arg("file")
            .arg("--object-store-option")
            .arg(format!("root={}", self.path("blob").display()))
            .arg("--lease-ttl-ms")
            .arg("1500");
        command
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn objects(&self, prefix: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![self.path("blob").join(prefix)];
        while let Some(directory) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(directory) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    stack.push(entry.path());
                } else {
                    found.push(entry.file_name().to_string_lossy().to_string());
                }
            }
        }
        found.sort();
        found
    }
}

fn wait_ready(child: &mut Child) -> String {
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read READY line");
    assert!(
        line.starts_with("READY "),
        "unexpected first line: {line:?}"
    );
    line.trim().to_string()
}

#[test]
fn serving_without_an_authorized_grant_fails_before_adapter_open() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
        .args([
            "--volume-id",
            "vol_ungranted",
            "--attachment-id",
            "att_ungranted",
            "--metadata-store-adapter",
            "sqlite",
            "--object-store-adapter",
            "file",
        ])
        .arg("--data-dir")
        .arg(directory.path().join("data"))
        .arg("--listen-unix")
        .arg(directory.path().join("nbd.sock"))
        .output()
        .expect("run cats-blockd");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an explicit --attachment-epoch grant"),
        "unexpected rejection: {stderr}"
    );
    assert!(
        !directory.path().join("data").exists() && !directory.path().join("nbd.sock").exists(),
        "an ungranted command performed a local serving effect"
    );
}

#[test]
fn requires_at_least_one_listener() {
    let env = Env::new();
    let output = env.command("att-none").output().expect("run cats-blockd");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at least one of --listen-unix"),
        "unhelpful error: {stderr}"
    );
}

#[test]
fn rejects_two_nbd_listeners() {
    let env = Env::new();
    let output = env
        .command("att-both-nbd")
        .arg("--listen-unix")
        .arg(env.path("nbd.sock"))
        .arg("--listen-tcp")
        .arg("127.0.0.1:0")
        .output()
        .expect("run cats-blockd");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mutually exclusive"),
        "unhelpful error: {stderr}"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn vhost_user_is_rejected_off_linux() {
    let env = Env::new();
    let output = env
        .command("att-vhu-unsupported")
        .arg("--listen-vhost-user")
        .arg(env.path("vhu.sock"))
        .arg("--guest-device-serial")
        .arg("cats-root")
        .output()
        .expect("run cats-blockd");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires Linux"),
        "unhelpful error: {stderr}"
    );
}

#[test]
fn publishing_an_image_remains_a_volume_free_object_store_operation() {
    use std::io::Write as _;

    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("image.raw");
    let mut file = std::fs::File::create(&image).unwrap();
    file.write_all(b"immutable golden image").unwrap();
    file.sync_all().unwrap();
    let object_root = directory.path().join("objects");

    let publish = || {
        Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
            .arg("--publish-image")
            .arg(&image)
            .arg("--object-store-adapter")
            .arg("file")
            .arg("--object-store-option")
            .arg(format!("root={}", object_root.display()))
            .output()
            .expect("run cats-blockd --publish-image")
    };
    let first = publish();
    assert!(
        first.status.success(),
        "publish failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = publish();
    assert!(second.status.success());
    assert_eq!(
        first.stdout, second.stdout,
        "image publication is idempotent"
    );
    assert!(String::from_utf8_lossy(&first.stdout).starts_with("IMAGE "));
}

/// Golden root (ADR-0017): launching from a shared image must not upload a
/// private copy of the rootfs, and a later launch must not re-seed over data.
#[test]
fn a_root_disk_is_provisioned_from_a_shared_image_without_copying_it() {
    use cats_block_client::NbdClient;
    use std::io::Write;
    use std::process::Stdio;

    const CHUNK: usize = cats_api::chunk::CHUNK_SIZE as usize;
    let env = Env::new();
    let image = env.path("golden.raw");
    let mut body = vec![0_u8; 2 * CHUNK];
    for (index, byte) in body.iter_mut().enumerate() {
        *byte = if index < CHUNK {
            (index % 251) as u8 + 1
        } else {
            0
        };
    }
    let mut file = std::fs::File::create(&image).unwrap();
    file.write_all(&body).unwrap();
    file.sync_all().unwrap();

    let socket = env.path("seed-nbd.sock");
    let mut child = env
        .command("att-seed")
        .arg("--listen-unix")
        .arg(&socket)
        .arg("--seed-image")
        .arg(&image)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd");
    wait_ready(&mut child);
    let mut client = NbdClient::connect_unix(&socket).expect("nbd connect");
    assert_eq!(client.size(), VOL_SIZE);
    assert_eq!(client.read(0, body.len() as u32).unwrap(), body);
    assert_eq!(env.objects("images").len(), 2);
    assert!(
        env.objects("volumes/vol_frontends/data").is_empty(),
        "provisioning published private volume data"
    );
    client.disconnect().ok();
    child.kill().ok();
    child.wait().ok();

    let second_socket = env.path("seed-nbd2.sock");
    let mut second = env
        .command("att-seed-2")
        .arg("--listen-unix")
        .arg(&second_socket)
        .arg("--seed-image")
        .arg(&image)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd again");
    wait_ready(&mut second);
    let mut client = NbdClient::connect_unix(&second_socket).unwrap();
    let patch = vec![0xAB_u8; 4096];
    client.write(0, &patch).unwrap();
    client.flush().unwrap();
    client.disconnect().ok();
    second.kill().ok();
    second.wait().ok();

    let third_socket = env.path("seed-nbd3.sock");
    let mut third = env
        .command("att-seed-3")
        .arg("--listen-unix")
        .arg(&third_socket)
        .arg("--seed-image")
        .arg(&image)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd a third time");
    wait_ready(&mut third);
    let mut client = NbdClient::connect_unix(&third_socket).unwrap();
    let back = client.read(0, CHUNK as u32).unwrap();
    assert_eq!(&back[..4096], &patch);
    assert_eq!(&back[4096..], &body[4096..CHUNK]);
    client.disconnect().ok();
    third.kill().ok();
    third.wait().ok();
    assert_eq!(env.objects("images").len(), 2);
    assert_eq!(env.objects("volumes/vol_frontends/data").len(), 1);
}

/// Image publication remains volume-free; the serving step adopts an external
/// grant and provisions by immutable image id.
#[test]
fn an_image_is_published_once_and_then_referenced_by_id() {
    use cats_block_client::NbdClient;
    use std::io::Write;
    use std::process::Stdio;

    const CHUNK: usize = cats_api::chunk::CHUNK_SIZE as usize;
    let env = Env::new();
    let image = env.path("publish-once.raw");
    let body: Vec<u8> = (0..CHUNK).map(|index| (index % 251) as u8 + 3).collect();
    let mut file = std::fs::File::create(&image).unwrap();
    file.write_all(&body).unwrap();
    file.sync_all().unwrap();

    let publish = || {
        Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
            .arg("--publish-image")
            .arg(&image)
            .arg("--object-store-adapter")
            .arg("file")
            .arg("--object-store-option")
            .arg(format!("root={}", env.path("blob").display()))
            .output()
            .expect("publish image")
    };
    let first = publish();
    assert!(first.status.success());
    let image_id = String::from_utf8_lossy(&first.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("IMAGE ").map(str::to_owned))
        .expect("publish printed image id");
    assert_eq!(image_id.len(), 64);
    let second = publish();
    assert!(String::from_utf8_lossy(&second.stdout).contains(&image_id));
    assert_eq!(env.objects("images").len(), 2);

    let socket = env.path("byid-nbd.sock");
    let mut child = env
        .command("att-byid")
        .arg("--listen-unix")
        .arg(&socket)
        .arg("--seed-image-id")
        .arg(&image_id)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd");
    wait_ready(&mut child);
    let mut client = NbdClient::connect_unix(&socket).unwrap();
    assert_eq!(client.read(0, CHUNK as u32).unwrap(), body);
    assert!(env.objects("volumes/vol_frontends/data").is_empty());
    client.disconnect().ok();
    child.kill().ok();
    child.wait().ok();

    let bogus = env
        .command("att-bogus")
        .arg("--listen-unix")
        .arg(env.path("bogus.sock"))
        .arg("--seed-image-id")
        .arg("f".repeat(64))
        .output()
        .expect("run cats-blockd");
    assert!(!bogus.status.success());
    assert!(String::from_utf8_lossy(&bogus.stderr).contains("load base image"));
}

/// A GC pass adopts an exact grant, needs no listener, removes only an
/// unreachable generation, and leaves the current generation readable.
#[test]
fn collecting_garbage_needs_no_listener_and_leaves_live_objects_alone() {
    use cats_block_client::NbdClient;
    use std::process::Stdio;

    let env = Env::new();
    let socket = env.path("gc-nbd.sock");
    let mut child = env
        .command("att-gc")
        .arg("--listen-unix")
        .arg(&socket)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd");
    wait_ready(&mut child);
    let mut client = NbdClient::connect_unix(&socket).unwrap();
    const CHUNK: usize = cats_api::chunk::CHUNK_SIZE as usize;
    let first = vec![0x11_u8; CHUNK];
    let second = vec![0x22_u8; CHUNK];
    client.write(0, &first).unwrap();
    client.flush().unwrap();
    client.write(0, &second).unwrap();
    client.flush().unwrap();
    client.disconnect().ok();
    child.kill().ok();
    child.wait().ok();
    assert_eq!(env.objects("volumes/vol_frontends/data").len(), 2);

    let gc = env
        .command("att-gc-run")
        .arg("--collect-garbage")
        .output()
        .expect("run garbage collection");
    assert!(
        gc.status.success(),
        "gc failed: {}",
        String::from_utf8_lossy(&gc.stderr)
    );
    assert!(String::from_utf8_lossy(&gc.stdout).contains("data_deleted=1"));
    assert_eq!(env.objects("volumes/vol_frontends/data").len(), 1);

    let after_socket = env.path("gc-nbd2.sock");
    let mut after = env
        .command("att-gc-after")
        .arg("--listen-unix")
        .arg(&after_socket)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd after GC");
    wait_ready(&mut after);
    let mut client = NbdClient::connect_unix(&after_socket).unwrap();
    assert_eq!(client.read(0, CHUNK as u32).unwrap(), second);
    client.disconnect().ok();
    after.kill().ok();
    after.wait().ok();
}

#[cfg(target_os = "linux")]
mod vhost_user {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use cats_block_client::NbdClient;

    use super::{wait_ready, Env, VOL_SIZE};

    fn wait_exit(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "cats-blockd did not exit in time"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The compatibility data-plane path still serves NBD and vhost-user from
    /// one externally granted engine, then releases it when the VMM vanishes.
    #[test]
    fn serves_nbd_and_vhost_user_together_then_exits_with_the_vmm() {
        let env = Env::new();
        let nbd_socket = env.path("nbd.sock");
        let vhost_socket = env.path("vhu.sock");
        let mut child = env
            .command("att-dual")
            .arg("--listen-unix")
            .arg(&nbd_socket)
            .arg("--listen-vhost-user")
            .arg(&vhost_socket)
            .arg("--guest-device-serial")
            .arg("cats-root")
            .arg("--vhost-user-queues")
            .arg("2")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cats-blockd");

        let ready = wait_ready(&mut child);
        assert!(ready.contains("vhu.sock"));
        assert!(vhost_socket.exists());
        let mut client = NbdClient::connect_unix(&nbd_socket).unwrap();
        assert_eq!(client.size(), VOL_SIZE);
        let payload: Vec<u8> = (0..4096_u32).map(|value| (value % 251) as u8).collect();
        client.write(8192, &payload).unwrap();
        client.flush().unwrap();
        assert_eq!(client.read(8192, 4096).unwrap(), payload);
        client.disconnect().unwrap();

        let vmm = std::os::unix::net::UnixStream::connect(&vhost_socket).unwrap();
        drop(vmm);
        let status = wait_exit(&mut child, Duration::from_secs(15));
        assert!(status.success(), "VMM disconnect failed: {status}");

        let next_socket = env.path("nbd2.sock");
        let mut next = env
            .command("att-after")
            .arg("--listen-unix")
            .arg(&next_socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cats-blockd again");
        wait_ready(&mut next);
        let mut client = NbdClient::connect_unix(&next_socket).unwrap();
        assert_eq!(client.read(8192, 4096).unwrap(), payload);
        client.disconnect().unwrap();
        next.kill().ok();
        next.wait().ok();
    }
}
