//! Integration tests for the frontend CLI of the real `cats-blockd` binary:
//! which listeners it accepts, that one process can serve NBD and vhost-user-blk
//! over the same engine, and that a VMM disconnect releases the attachment.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const VOL_SIZE: u64 = 4 * cats_api::chunk::CHUNK_SIZE as u64;

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn command(&self, attachment: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cats-blockd"));
        cmd.args(["--volume-id", "vol_frontends", "--attachment-id", attachment])
            .arg("--data-dir")
            .arg(self.dir.path().join(format!("data-{attachment}")))
            .arg("--metadata-store-adapter")
            .arg("sqlite")
            .arg("--metadata-store-option")
            .arg(format!("path={}", self.dir.path().join("meta.db").display()))
            .arg("--object-store-adapter")
            .arg("file")
            .arg("--object-store-option")
            .arg(format!("root={}", self.dir.path().join("blob").display()))
            .arg("--create-volume-size")
            .arg(VOL_SIZE.to_string())
            .arg("--lease-ttl-ms")
            .arg("1500");
        cmd
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Objects the store holds below a prefix, so a test can assert on what a
    /// launch actually uploaded.
    fn objects(&self, prefix: &str) -> Vec<String> {
        let root = self.dir.path().join("blob").join(prefix);
        let mut found = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
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

/// Wait for the `READY <listener>` line the daemon prints once every requested
/// socket is bound.
fn wait_ready(child: &mut Child) -> String {
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read READY line");
    assert!(line.starts_with("READY "), "unexpected first line: {line:?}");
    line.trim().to_string()
}

fn wait_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "cats-blockd did not exit in time");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn requires_at_least_one_listener() {
    let env = Env::new();
    let output = env
        .command("att-none")
        .output()
        .expect("run cats-blockd");
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
        .output()
        .expect("run cats-blockd");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires Linux"),
        "unhelpful error: {stderr}"
    );
}

/// Golden root (ADR-0017): the whole point is that a launch does not upload a
/// private copy of the rootfs, so this asserts on what landed in the object store.
#[test]
fn a_root_disk_is_provisioned_from_a_shared_image_without_copying_it() {
    use cats_blockd::nbd::NbdClient;
    use std::io::Write;
    use std::process::Stdio;

    const CHUNK: usize = cats_api::chunk::CHUNK_SIZE as usize;
    let env = Env::new();
    let image = env.path("golden.raw");
    let mut body = vec![0u8; 2 * CHUNK];
    for (i, byte) in body.iter_mut().enumerate() {
        // Chunk 1 stays zero so the image is sparse; chunk 0 is distinct content.
        *byte = if i < CHUNK { (i % 251) as u8 + 1 } else { 0 };
    }
    let mut f = std::fs::File::create(&image).unwrap();
    f.write_all(&body).unwrap();
    f.sync_all().unwrap();

    let nbd = env.path("seed-nbd.sock");
    let mut child = env
        .command("att-seed")
        .arg("--listen-unix")
        .arg(&nbd)
        .arg("--seed-image")
        .arg(&image)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd");
    wait_ready(&mut child);

    let mut client = NbdClient::connect_unix(&nbd).expect("nbd connect");
    assert_eq!(client.size(), VOL_SIZE);
    let got = client
        .read(0, body.len() as u32)
        .expect("read the provisioned root");
    assert_eq!(got, body, "the Guest must see the image content");

    // The image was uploaded once, under the image namespace; the volume itself
    // published no data objects at all, only map nodes.
    let image_objects = env.objects("images");
    assert_eq!(
        image_objects.len(),
        2,
        "expected one chunk object plus the manifest, got {image_objects:?}"
    );
    assert!(
        env.objects("volumes/vol_frontends/data").is_empty(),
        "provisioning must not publish volume data objects: {:?}",
        env.objects("volumes/vol_frontends/data")
    );

    client.disconnect().ok();
    child.kill().ok();
    child.wait().ok();

    // A second launch of the same volume must not re-provision over its data.
    let mut again = env
        .command("att-seed-2")
        .arg("--listen-unix")
        .arg(env.path("seed-nbd2.sock"))
        .arg("--seed-image")
        .arg(&image)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd again");
    wait_ready(&mut again);
    let mut client = NbdClient::connect_unix(&env.path("seed-nbd2.sock")).unwrap();
    let patch = vec![0xABu8; 4096];
    client.write(0, &patch).expect("write");
    client.flush().expect("flush");
    assert_eq!(client.read(0, 4096).unwrap(), patch);
    client.disconnect().ok();
    again.kill().ok();
    again.wait().ok();

    let mut third = env
        .command("att-seed-3")
        .arg("--listen-unix")
        .arg(env.path("seed-nbd3.sock"))
        .arg("--seed-image")
        .arg(&image)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn cats-blockd a third time");
    wait_ready(&mut third);
    let mut client = NbdClient::connect_unix(&env.path("seed-nbd3.sock")).unwrap();
    let back = client.read(0, CHUNK as u32).unwrap();
    assert_eq!(&back[..4096], &patch[..], "re-seeding clobbered Guest data");
    assert_eq!(&back[4096..], &body[4096..CHUNK], "lost the shared image tail");
    client.disconnect().ok();
    third.kill().ok();
    third.wait().ok();
    // Still exactly one copy of the image, plus the one 64 KiB page the Guest wrote.
    assert_eq!(env.objects("images").len(), 2);
    assert_eq!(env.objects("volumes/vol_frontends/data").len(), 1);
}

/// The Linux-only half: vhost-user needs eventfd, memfd and SCM_RIGHTS.
#[cfg(target_os = "linux")]
mod vhost_user {
    use std::process::Stdio;
    use std::time::Duration;

    use cats_blockd::nbd::NbdClient;

    use super::{wait_exit, wait_ready, Env, VOL_SIZE};

    /// The node agent runs `cats-blockd` with both frontends: the VMM consumes
    /// vhost-user while seeding, readiness probing and recovery keep using NBD on the
    /// same engine and the same attachment lease.
    #[test]
    fn serves_nbd_and_vhost_user_together_then_exits_with_the_vmm() {
        let env = Env::new();
        let nbd_socket = env.path("nbd.sock");
        let vhost_user_socket = env.path("vhu.sock");
        let mut child = env
            .command("att-dual")
            .arg("--listen-unix")
            .arg(&nbd_socket)
            .arg("--listen-vhost-user")
            .arg(&vhost_user_socket)
            .arg("--vhost-user-queues")
            .arg("2")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cats-blockd");

        // READY is printed only after every listener is bound, so a VMM started on
        // that line cannot race the socket.
        let ready = wait_ready(&mut child);
        assert!(
            ready.contains("vhu.sock"),
            "READY should name the VMM-facing socket: {ready}"
        );
        assert!(vhost_user_socket.exists(), "vhost-user socket is missing");

        // The oracle frontend works while the VMM socket is still unconnected.
        let mut client = NbdClient::connect_unix(&nbd_socket).expect("nbd connect");
        assert_eq!(client.size(), VOL_SIZE);
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        client.write(8192, &payload).expect("nbd write");
        client.flush().expect("nbd flush");
        assert_eq!(client.read(8192, 4096).expect("nbd read"), payload);
        client.disconnect().expect("nbd disconnect");

        // A VMM connecting and then vanishing is the normal end of service: the
        // process exits so the attachment lease is released for the next host.
        let vmm = std::os::unix::net::UnixStream::connect(&vhost_user_socket)
            .expect("connect as a VMM would");
        drop(vmm);
        let status = wait_exit(&mut child, Duration::from_secs(15));
        assert!(
            status.success(),
            "a VMM disconnect must not be an error: {status}"
        );

        // The volume is attachable again right away, and the committed write is
        // still there.
        let mut next = env
            .command("att-after")
            .arg("--listen-unix")
            .arg(env.path("nbd2.sock"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cats-blockd again");
        wait_ready(&mut next);
        let mut client = NbdClient::connect_unix(&env.path("nbd2.sock")).expect("nbd connect");
        assert_eq!(client.read(8192, 4096).expect("nbd read"), payload);
        client.disconnect().expect("nbd disconnect");
        let _ = next.kill();
        let _ = next.wait();
    }
}
