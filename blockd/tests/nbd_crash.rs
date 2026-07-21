//! Integration tests against the real `cats-blockd` binary: NBD transport,
//! crash injection at every commit-protocol window (spec §8), fencing and
//! empty-cache cold restore.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_blockd::meta::{MetadataStore, SqliteMeta};
use cats_blockd::nbd::{NbdClient, NbdError, EPERM};

const CHUNK: u64 = cats_api::chunk::CHUNK_SIZE as u64;
const VOL_SIZE: u64 = 4 * CHUNK;

struct TestEnv {
    dir: tempfile::TempDir,
}

impl TestEnv {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn meta_path(&self) -> PathBuf {
        self.dir.path().join("meta.db")
    }
    fn blob_root(&self) -> PathBuf {
        self.dir.path().join("blob")
    }
    fn data_dir(&self, host: &str) -> PathBuf {
        self.dir.path().join(format!("data-{host}"))
    }
    fn socket(&self, host: &str) -> PathBuf {
        self.dir.path().join(format!("nbd-{host}.sock"))
    }
    fn meta(&self) -> SqliteMeta {
        SqliteMeta::open(&self.meta_path()).unwrap()
    }
}

struct Server {
    child: Child,
    socket: PathBuf,
}

impl Server {
    fn spawn(env: &TestEnv, host: &str, attachment: &str, crash_point: Option<&str>) -> Self {
        let socket = env.socket(host);
        let _ = std::fs::remove_file(&socket);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cats-blockd"));
        cmd.args([
            "--volume-id",
            "vol_it",
            "--attachment-id",
            attachment,
            "--lease-ttl-ms",
            "1500",
        ])
        .arg("--data-dir")
        .arg(env.data_dir(host))
        .arg("--meta-sqlite")
        .arg(env.meta_path())
        .arg("--blob-file-root")
        .arg(env.blob_root())
        .arg("--listen-unix")
        .arg(&socket)
        .arg("--create-volume-size")
        .arg(VOL_SIZE.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        cmd.env_remove("CATS_CRASH_POINT");
        if let Some(p) = crash_point {
            cmd.env("CATS_CRASH_POINT", p);
        }
        let child = cmd.spawn().expect("spawn cats-blockd");
        Server { child, socket }
    }

    fn connect(&mut self) -> NbdClient {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(c) = NbdClient::connect_unix(&self.socket) {
                return c;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("cats-blockd exited early: {status}");
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for cats-blockd socket");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn wait_exit(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        panic!("cats-blockd did not exit in time");
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill();
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}

fn read_all(client: &mut NbdClient) -> Vec<u8> {
    let mut out = Vec::with_capacity(VOL_SIZE as usize);
    let step = 1 << 20;
    let mut off = 0;
    while off < VOL_SIZE {
        out.extend_from_slice(&client.read(off, step as u32).unwrap());
        off += step;
    }
    out
}

#[test]
fn write_flush_read_through_binary() {
    let env = TestEnv::new();
    let mut server = Server::spawn(&env, "a", "att_a", None);
    let mut client = server.connect();
    assert_eq!(client.size(), VOL_SIZE);

    let data = pattern(300_000, 1);
    client.write(CHUNK - 1234, &data).unwrap(); // straddles a chunk boundary
    client.flush().unwrap();
    assert_eq!(client.read(CHUNK - 1234, 300_000).unwrap(), data);
    client.disconnect().unwrap();
}

/// Spec §8.1/§8.4: crash at every window; restart must recover the frozen
/// flush exactly once (generation advances to 1, data intact, pack drained).
#[test]
fn crash_matrix_every_window_recovers_exactly_once() {
    for point in ["after_pack", "after_data_upload", "before_cas", "after_cas"] {
        let env = TestEnv::new();
        let data0 = pattern(64_000, 3);
        let data1 = pattern(120_000, 7);
        {
            let mut server = Server::spawn(&env, "a", "att_a", Some(point));
            let mut client = server.connect();
            client.write(0, &data0).unwrap();
            client.write(2 * CHUNK + 999, &data1).unwrap();
            // The server aborts mid-flush: the client sees an I/O failure.
            let err = client.flush().unwrap_err();
            assert!(
                matches!(err, NbdError::Io(_)),
                "{point}: expected io error, got {err:?}"
            );
            server.wait_exit(Duration::from_secs(10));
        }
        // Same-host restart with the same attachment id (allowed lease
        // re-acquire) and no crash point: recovery must converge.
        let mut server = Server::spawn(&env, "a", "att_a", None);
        let mut client = server.connect();
        assert_eq!(
            client.read(0, 64_000).unwrap(),
            data0,
            "{point}: data0 lost"
        );
        assert_eq!(
            client.read(2 * CHUNK + 999, 120_000).unwrap(),
            data1,
            "{point}: data1 lost"
        );
        client.disconnect().unwrap();
        drop(server);

        let head = env.meta().load_head("vol_it").unwrap();
        assert_eq!(head.generation, 1, "{point}: replay must not double-commit");
        let pending = std::fs::read_dir(env.data_dir("a").join("pending"))
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(pending, 0, "{point}: pack must be drained after recovery");
    }
}

#[test]
fn fenced_writer_gets_eperm_and_new_host_takes_over() {
    let env = TestEnv::new();
    let mut server_a = Server::spawn(&env, "a", "att_a", None);
    let mut client_a = server_a.connect();
    client_a.write(0, &pattern(4096, 1)).unwrap();
    client_a.flush().unwrap();

    // Control plane fences the volume (host presumed lost).
    let meta: Arc<dyn MetadataStore> = Arc::new(env.meta());
    meta.revoke_lease("vol_it").unwrap();

    // The old writer must fail closed within a renew interval.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match client_a.write(0, b"stale") {
            Err(NbdError::Server(e)) if e == EPERM => break,
            Ok(()) | Err(_) => {
                if Instant::now() > deadline {
                    panic!("old writer was never fenced");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    assert!(matches!(client_a.flush(), Err(NbdError::Server(e)) if e == EPERM));

    // A new attachment on a fresh host continues from the committed state.
    let mut server_b = Server::spawn(&env, "b", "att_b", None);
    let mut client_b = server_b.connect();
    assert_eq!(client_b.read(0, 4096).unwrap(), pattern(4096, 1));
    client_b.write(4096, &pattern(4096, 2)).unwrap();
    client_b.flush().unwrap();
    client_b.disconnect().unwrap();

    let head = env.meta().load_head("vol_it").unwrap();
    assert_eq!(head.generation, 2);
}

#[test]
fn empty_cache_cold_restore_preserves_digest() {
    let env = TestEnv::new();
    let digest_before;
    {
        let mut server = Server::spawn(&env, "a", "att_a", None);
        let mut client = server.connect();
        client.write(0, &pattern(CHUNK as usize, 11)).unwrap();
        client.write(CHUNK * 2, &pattern(8192, 13)).unwrap();
        client.write(VOL_SIZE - 512, &pattern(512, 17)).unwrap();
        client.flush().unwrap();
        digest_before = read_all(&mut client);
        client.disconnect().unwrap();
        server.kill(); // hard kill: lease still held
    }
    // Wipe every local byte; fence the dead host; start on a "new host".
    std::fs::remove_dir_all(env.data_dir("a")).unwrap();
    env.meta().revoke_lease("vol_it").unwrap();

    let mut server = Server::spawn(&env, "b", "att_b", None);
    let mut client = server.connect();
    let digest_after = read_all(&mut client);
    assert_eq!(digest_before.len(), digest_after.len());
    assert!(
        digest_before == digest_after,
        "cold restore digest mismatch"
    );
    client.disconnect().unwrap();
}
