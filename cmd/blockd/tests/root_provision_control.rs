//! A13/A14 acceptance against the real blockd composition root.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::chunk::{CHUNKS_PER_LEAF, CHUNK_SIZE};
use cats_api::runtime_reconciliation::{
    decode_provision_root_image_result, encode_provision_root_image_request, AsciiText, FenceEpoch,
    Generation, Id, ProvisionRootImageRequest, RandomId128, RemoteHead, Sha256Digest,
    PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
};
use cats_blockd::format::{self, LeafRef};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_file::FileBlobStore;
use cats_storage::{BlobStore, MetadataStore};

const VOLUME_ID: &str = "vol_root_provision";
const ATTACHMENT_ID: &str = "att_root_provision";
const VOLUME_SIZE: u64 = 2 * CHUNK_SIZE as u64;
const TRANSITION: &str = "13579bdf2468ace013579bdf2468ace0";

struct Env {
    dir: tempfile::TempDir,
    epoch: i64,
    request: ProvisionRootImageRequest,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let meta = SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap();
        meta.create_volume(VOLUME_ID, VOLUME_SIZE).unwrap();

        let image = dir.path().join("root.img");
        let bytes: Vec<u8> = (0..CHUNK_SIZE as usize)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(9))
            .collect();
        std::fs::write(&image, bytes).unwrap();
        let manifest = cats_blockd::image::publish(blob.as_ref(), &image)
            .unwrap()
            .manifest;
        let epoch = meta
            .acquire_lease(VOLUME_ID, ATTACHMENT_ID, 60_000)
            .unwrap();
        let request = request_from_manifest(&manifest, epoch);
        Self {
            dir,
            epoch,
            request,
        }
    }

    fn meta_path(&self) -> PathBuf {
        self.dir.path().join("meta.db")
    }

    fn blob_root(&self) -> PathBuf {
        self.dir.path().join("blob")
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("control-data")
    }

    fn control_socket(&self) -> PathBuf {
        self.dir.path().join("provision.sock")
    }

    fn meta(&self) -> SqliteMetadataStore {
        SqliteMetadataStore::open(&self.meta_path()).unwrap()
    }

    fn spawn(&self, crash_point: Option<&str>) -> Server {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cats-blockd"));
        command
            .arg("--volume-id")
            .arg(VOLUME_ID)
            .arg("--attachment-id")
            .arg(ATTACHMENT_ID)
            .arg("--attachment-epoch")
            .arg(self.epoch.to_string())
            .arg("--control-only")
            .arg("--data-dir")
            .arg(self.data_dir())
            .arg("--metadata-store-adapter")
            .arg("sqlite")
            .arg("--metadata-store-option")
            .arg(format!("path={}", self.meta_path().display()))
            .arg("--object-store-adapter")
            .arg("file")
            .arg("--object-store-option")
            .arg(format!("root={}", self.blob_root().display()))
            .arg("--listen-control")
            .arg(self.control_socket())
            .arg("--lease-ttl-ms")
            .arg("60000")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("CATS_CRASH_POINT");
        if let Some(point) = crash_point {
            command.env("CATS_CRASH_POINT", point);
        }
        let child = command.spawn().unwrap();
        let mut server = Server { child };
        server.wait_ready(&self.control_socket());
        server
    }

    fn reset_stale_socket_after_verified_exit(&self) {
        if self.control_socket().exists() {
            std::fs::remove_file(self.control_socket()).unwrap();
        }
    }
}

struct Server {
    child: Child,
}

impl Server {
    fn wait_ready(&mut self, expected: &std::path::Path) {
        let stdout = self.child.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        assert_eq!(line.trim(), format!("READY {}", expected.display()));
    }

    fn wait_exit(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("control-only blockd did not exit after crash point");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn request_from_manifest(
    manifest: &format::ImageManifest,
    epoch: i64,
) -> ProvisionRootImageRequest {
    let map = manifest.base_map(VOLUME_SIZE).unwrap();
    let mut leaves = Vec::new();
    for (leaf_index, entries) in map.chunks(CHUNKS_PER_LEAF as usize).enumerate() {
        if entries.iter().all(format::ChunkRef::is_hole) {
            leaves.push(LeafRef::Empty);
        } else {
            let bytes = format::encode_leaf(leaf_index as u64 * CHUNKS_PER_LEAF as u64, entries);
            let hash = format::sha256(&bytes);
            leaves.push(LeafRef::Present {
                hash,
                object_id: format!("{}.node", lower_hex(hash)),
            });
        }
    }
    let root = format::encode_root(VOLUME_SIZE, &leaves);
    let root_hash = format::sha256(&root);
    ProvisionRootImageRequest {
        provision_transition_id: RandomId128::new(TRANSITION).unwrap(),
        volume_id: Id::new(VOLUME_ID).unwrap(),
        attachment_id: Id::new(ATTACHMENT_ID).unwrap(),
        attachment_epoch: FenceEpoch::new(epoch as u64).unwrap(),
        size_bytes: VOLUME_SIZE,
        boot_image_digest: Sha256Digest::new(format!("sha256:{}", manifest.image_id)).unwrap(),
        expected_blank_head: RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        },
        expected_provisioned_head: RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes(root_hash)),
            root_object_id: Some(AsciiText::new(format!("{}.node", lower_hex(root_hash))).unwrap()),
        },
    }
}

fn lower_hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn wire_request(request: &ProvisionRootImageRequest) -> Vec<u8> {
    let mut wire = b"provision_root_image ".to_vec();
    wire.extend(encode_provision_root_image_request(request).unwrap());
    wire.push(b'\n');
    wire
}

fn exchange(path: &std::path::Path, wire: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(wire).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn assert_ok(response: &[u8], request: &ProvisionRootImageRequest) {
    assert!(
        response.starts_with(b"OK "),
        "unexpected response: {response:?}"
    );
    assert_eq!(response.last(), Some(&b'\n'));
    let result = decode_provision_root_image_result(&response[3..response.len() - 1]).unwrap();
    assert_eq!(
        result.provision_transition_id,
        request.provision_transition_id
    );
    assert_eq!(result.volume_id, request.volume_id);
    assert_eq!(result.attachment_id, request.attachment_id);
    assert_eq!(result.attachment_epoch, request.attachment_epoch);
    assert_eq!(result.resulting_head, request.expected_provisioned_head);
}

#[test]
fn control_only_rejects_frontends_and_serves_only_the_typed_effect() {
    let env = Env::new();
    let rejected = Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
        .arg("--control-only")
        .arg("--attachment-epoch")
        .arg(env.epoch.to_string())
        .arg("--listen-control")
        .arg(env.control_socket())
        .arg("--listen-unix")
        .arg(env.dir.path().join("forbidden-nbd.sock"))
        .arg("--object-store-adapter")
        .arg("file")
        .arg("--object-store-option")
        .arg(format!("root={}", env.blob_root().display()))
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("forbids every NBD"));

    let _server = env.spawn(None);
    assert!(env.control_socket().exists());
    assert!(!env.dir.path().join("forbidden-nbd.sock").exists());
    let response = exchange(&env.control_socket(), &wire_request(&env.request));
    assert_ok(&response, &env.request);
    let head = env.meta().load_head(VOLUME_ID).unwrap();
    assert_eq!(head.generation, 1);
}

#[test]
fn first_lf_framing_enforces_prefix_crlf_and_payload_cap_before_effect() {
    let env = Env::new();
    let _server = env.spawn(None);
    let canonical = encode_provision_root_image_request(&env.request).unwrap();

    assert!(exchange(&env.control_socket(), b"wrong {}\n").is_empty());
    let mut crlf = b"provision_root_image ".to_vec();
    crlf.extend(&canonical);
    crlf.extend(b"\r\n");
    assert!(exchange(&env.control_socket(), &crlf).is_empty());
    let mut bom = b"provision_root_image \xef\xbb\xbf".to_vec();
    bom.extend(&canonical);
    bom.push(b'\n');
    assert!(exchange(&env.control_socket(), &bom).is_empty());
    let mut too_large = b"provision_root_image ".to_vec();
    too_large.extend(vec![b' '; PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES + 1]);
    too_large.push(b'\n');
    assert!(exchange(&env.control_socket(), &too_large).is_empty());
    assert_eq!(env.meta().load_head(VOLUME_ID).unwrap().generation, 0);

    let mut exact = b"provision_root_image ".to_vec();
    exact.extend(&canonical);
    exact.extend(vec![
        b' ';
        PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES
            - canonical.len()
    ]);
    exact.push(b'\n');
    let response = exchange(&env.control_socket(), &exact);
    assert_ok(&response, &env.request);
}

#[test]
fn receiver_responds_at_first_lf_without_waiting_for_half_close_or_running_tail() {
    let env = Env::new();
    let _server = env.spawn(None);
    let mut stream = UnixStream::connect(env.control_socket()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&wire_request(&env.request)).unwrap();
    // Keep the write half open: the receiver must not wait for EOF.
    let mut response = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut response)
        .unwrap();
    assert_ok(response.as_bytes(), &env.request);
    // A delayed second command on the same connection is either rejected by
    // the already-closed peer or discarded; it can never execute as command 2.
    std::thread::sleep(Duration::from_millis(20));
    let _ = stream.write_all(&wire_request(&env.request));
    assert_eq!(env.meta().load_head(VOLUME_ID).unwrap().generation, 1);
}

#[test]
fn stalled_connection_times_out_without_starving_the_next_request() {
    let env = Env::new();
    let _server = env.spawn(None);
    let mut stalled = UnixStream::connect(env.control_socket()).unwrap();
    let trickler = std::thread::spawn(move || {
        for byte in b"provision_root_image " {
            if stalled.write_all(std::slice::from_ref(byte)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    });

    let started = Instant::now();
    let response = exchange(&env.control_socket(), &wire_request(&env.request));
    assert_ok(&response, &env.request);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the serial control loop remained blocked by an idle peer"
    );
    assert_eq!(env.meta().load_head(VOLUME_ID).unwrap().generation, 1);

    // The timeout is absolute for the frame: receiving one byte every 300 ms
    // cannot reset it and become a delayed second effect source.
    trickler.join().unwrap();

    // A peer that never reads its response also cannot retain the serial
    // admission slot. The server has a write deadline in case local socket
    // backpressure prevents even this bounded response from being delivered.
    let mut nonreader = UnixStream::connect(env.control_socket()).unwrap();
    nonreader.write_all(&wire_request(&env.request)).unwrap();
    let started = Instant::now();
    let response = exchange(&env.control_socket(), &wire_request(&env.request));
    assert_ok(&response, &env.request);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the serial control loop remained blocked by a non-reading peer"
    );
}

#[test]
fn every_provision_publication_crash_window_replays_the_same_transition() {
    for point in [
        "after_provision_leaf_put",
        "after_provision_root_put",
        "after_provision_commit_put",
        "before_cas",
        "after_cas",
    ] {
        let env = Env::new();
        {
            let mut crashing = env.spawn(Some(point));
            let mut stream = UnixStream::connect(env.control_socket()).unwrap();
            stream.write_all(&wire_request(&env.request)).unwrap();
            let mut ignored = Vec::new();
            let _ = stream.read_to_end(&mut ignored);
            crashing.wait_exit();
        }
        env.reset_stale_socket_after_verified_exit();
        let _restarted = env.spawn(None);
        let response = exchange(&env.control_socket(), &wire_request(&env.request));
        assert_ok(&response, &env.request);
        let head = env.meta().load_head(VOLUME_ID).unwrap();
        assert_eq!(head.generation, 1, "{point}");
        let blob = FileBlobStore::open(env.blob_root()).unwrap();
        let commits = blob.list(&format!("volumes/{VOLUME_ID}/commits/")).unwrap();
        assert_eq!(commits.len(), 1, "{point}: replay made a second commit key");
        assert!(commits[0].ends_with(&format!("1-{TRANSITION}.json")));
    }
}
