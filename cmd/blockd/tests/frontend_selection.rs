//! Integration tests for the frontend CLI of the real `cats-blockd` binary:
//! which listeners it accepts, that one process can serve NBD and vhost-user-blk
//! over the same engine, and that a VMM disconnect releases the attachment.

use std::path::PathBuf;
use std::process::Command;

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

/// The Linux-only half: vhost-user needs eventfd, memfd and SCM_RIGHTS.
#[cfg(target_os = "linux")]
mod vhost_user {
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    use cats_blockd::nbd::NbdClient;

    use super::{Env, VOL_SIZE};

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
