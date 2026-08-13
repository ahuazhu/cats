//! A13/A14 acceptance against the real blockd composition root.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::blockd::{BlockdControlResponse, DurabilityStatus};
use cats_api::chunk::{CHUNKS_PER_LEAF, CHUNK_SIZE};
use cats_api::runtime_reconciliation::{
    decode_provision_root_image_result, encode_provision_root_image_request, AcquireOrigin,
    AsciiText, Epoch, FenceEpoch, Generation, Id, NormalAcquireRequest, NormalAcquireResult,
    ProvisionRootImageRequest, RandomId128, RemoteHead, Revision, Sha256Digest,
    PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
};
use cats_blockd::format::{self, LeafRef};
use cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot;
use cats_control_plane::store::Store;
use cats_metadata_store_postgres::PostgresVolumeDataAuthority;
use cats_object_store_file::FileBlobStore;
use cats_storage::authority::{
    project_volume_record, AttachmentLineageIdentity, AuthorizedServingAcquire,
    AuthorizedServingAttachment, LastVolumeTransition, UnixMillis, VolumeAdminState,
    VolumeDataAuthority, VolumeDurability, VolumeOwnerBinding, VolumeRecord,
};
use cats_storage::BlobStore;
use postgres::{Client, NoTls};

const VOLUME_ID: &str = "vol_root_provision";
const ATTACHMENT_ID: &str = "att_root_provision";
const NODE_ID: &str = "node-root-provision";
const VOLUME_SIZE: u64 = 2 * CHUNK_SIZE as u64;
const ACQUIRE_TRANSITION: &str = "2468ace013579bdf2468ace013579bdf";
const PROCESS_TOKEN: &str = "3579bdf2468ace013579bdf2468ace01";
const SCOPE_ID: &str = "cats-root-provision.scope";

struct Env {
    dir: tempfile::TempDir,
    canonical_root: PathBuf,
    owner_directory: PathBuf,
    owner_directory_identity: (u64, u64),
    postgres_url: String,
    epoch: i64,
    request: ProvisionRootImageRequest,
}

impl Env {
    fn new() -> Self {
        // macOS exposes its per-user temporary directory through `/var`,
        // which is itself a symlink to `/private/var`. Production correctly
        // rejects a Runtime data directory with any symlink ancestor, so the
        // acceptance fixture must pass the canonical spelling of the same
        // retained temporary directory.
        let canonical_temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = tempfile::tempdir_in(canonical_temp).unwrap();
        let canonical_root = dir.path().canonicalize().unwrap();
        let blob = Arc::new(FileBlobStore::open(canonical_root.join("blob")).unwrap());
        let postgres_url = cats_control_plane::testsupport::isolated_control_store_url();
        drop(Store::connect(&postgres_url, None).unwrap());
        let mut postgres = Client::connect(&postgres_url, NoTls).unwrap();
        let epoch = 7;
        insert_volume(&mut postgres, &owned_volume(epoch));
        assert_legacy_metadata_absent(&mut postgres);

        let image = canonical_root.join("root.img");
        let bytes: Vec<u8> = (0..CHUNK_SIZE as usize)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(9))
            .collect();
        std::fs::write(&image, bytes).unwrap();
        let manifest = cats_blockd::image::publish(blob.as_ref(), &image)
            .unwrap()
            .manifest;
        let transition = unique_transition(&canonical_root);
        let request = request_from_manifest(&manifest, epoch, transition);
        let socket_paths = ManagedBlockdSocketRoot::installed()
            .root_paths(&request.provision_transition_id)
            .unwrap();
        provision_installed_directory(Path::new("/run/cats"), 0o755);
        provision_installed_directory(Path::new(socket_paths.root().as_str()), 0o700);
        let owner_directory = PathBuf::from(socket_paths.public_directory().as_str());
        provision_installed_directory(&owner_directory, 0o700);
        let owner_metadata = std::fs::symlink_metadata(&owner_directory).unwrap();
        let owner_directory_identity = (owner_metadata.dev(), owner_metadata.ino());
        let attachment = authorized_attachment(epoch);
        let data_dir = canonical_root.join("control-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (path, bytes) in [
            (
                data_dir.join("identity.json"),
                serde_json::to_vec(&attachment.identity).unwrap(),
            ),
            (
                data_dir.join("authorized-control.json"),
                serde_json::to_vec(&attachment).unwrap(),
            ),
        ] {
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            dir,
            canonical_root,
            owner_directory,
            owner_directory_identity,
            postgres_url,
            epoch,
            request,
        }
    }

    fn blob_root(&self) -> PathBuf {
        self.canonical_root.join("blob")
    }

    fn data_dir(&self) -> PathBuf {
        self.canonical_root.join("control-data")
    }

    fn control_socket(&self) -> PathBuf {
        let paths = ManagedBlockdSocketRoot::installed()
            .root_paths(&self.request.provision_transition_id)
            .unwrap();
        PathBuf::from(paths.control_socket().as_str())
    }

    fn authorized_control_spec(&self) -> PathBuf {
        self.data_dir().join("authorized-control.json")
    }

    fn authority(&self) -> PostgresVolumeDataAuthority {
        PostgresVolumeDataAuthority::connect(&self.postgres_url, None).unwrap()
    }

    fn assert_legacy_metadata_absent(&self) {
        let mut postgres = Client::connect(&self.postgres_url, NoTls).unwrap();
        assert_legacy_metadata_absent(&mut postgres);
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
            .arg("--authorized-control-spec")
            .arg(self.authorized_control_spec())
            .arg("--provision-transition-id")
            .arg(self.request.provision_transition_id.as_str())
            .arg("--runtime-scope-id")
            .arg(SCOPE_ID)
            .arg("--process-identity-token")
            .arg(PROCESS_TOKEN)
            .arg("--data-dir")
            .arg(self.data_dir())
            .arg("--metadata-store-adapter")
            .arg("postgres")
            .arg("--metadata-store-option")
            .arg("url-env=CATS_BLOCKD_TARGET_TEST_POSTGRES_URL")
            .arg("--object-store-adapter")
            .arg("file")
            .arg("--object-store-option")
            .arg(format!("root={}", self.blob_root().display()))
            .arg("--listen-control")
            .arg(self.control_socket())
            .arg("--lease-ttl-ms")
            .arg("60000")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("CATS_BLOCKD_TARGET_TEST_POSTGRES_URL", &self.postgres_url)
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

impl Drop for Env {
    fn drop(&mut self) {
        let Ok(owner) = std::fs::symlink_metadata(&self.owner_directory) else {
            return;
        };
        if !owner.file_type().is_dir()
            || (owner.dev(), owner.ino()) != self.owner_directory_identity
        {
            return;
        }
        let control = self.control_socket();
        match std::fs::symlink_metadata(&control) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                let _ = std::fs::remove_file(control);
            }
            Ok(_) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return,
        }
        let _ = std::fs::remove_dir(&self.owner_directory);
    }
}

fn unique_transition(canonical_root: &Path) -> RandomId128 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let inode = std::fs::symlink_metadata(canonical_root).unwrap().ino();
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    RandomId128::new(format!(
        "{:08x}{:016x}{:08x}",
        std::process::id(),
        inode,
        u32::try_from(sequence).unwrap()
    ))
    .unwrap()
}

fn provision_installed_directory(path: &Path, mode: u32) {
    match std::fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!(
            "create installed test directory {}: {error}",
            path.display()
        ),
    }
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.file_type().is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), 0, "{} is not root-owned", path.display());
    assert_eq!(metadata.gid(), 0, "{} is not root-grouped", path.display());
    assert_eq!(
        metadata.mode() & 0o7777,
        mode,
        "{} has the wrong mode",
        path.display()
    );
}

fn owned_volume(epoch: i64) -> VolumeRecord {
    let (request, result) = acquire_receipt(epoch);
    VolumeRecord {
        volume_id: Id::new(VOLUME_ID).unwrap(),
        size_bytes: VOLUME_SIZE,
        durability: VolumeDurability::Strict,
        admin_state: VolumeAdminState::Active,
        head: RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        },
        lease_owner: Some(Id::new(ATTACHMENT_ID).unwrap()),
        lease_epoch: FenceEpoch::new(u64::try_from(epoch).unwrap()).unwrap(),
        lease_expires_at: Some(UnixMillis::new(1).unwrap()),
        last_transition: Some(LastVolumeTransition::NormalAcquire { request, result }),
    }
}

fn acquire_receipt(epoch: i64) -> (NormalAcquireRequest, NormalAcquireResult) {
    let request = NormalAcquireRequest {
        volume_id: Id::new(VOLUME_ID).unwrap(),
        transition_id: RandomId128::new(ACQUIRE_TRANSITION).unwrap(),
        attachment_id: Id::new(ATTACHMENT_ID).unwrap(),
        expected_unowned_epoch: FenceEpoch::new(u64::try_from(epoch - 1).unwrap()).unwrap(),
        desired_revision: Revision::new(5).unwrap(),
        placement_epoch: Epoch::new(3).unwrap(),
        lease_duration_ms: 60_000,
    };
    let result = NormalAcquireResult {
        volume_id: request.volume_id.clone(),
        transition_id: request.transition_id.clone(),
        attachment_id: request.attachment_id.clone(),
        resulting_epoch: FenceEpoch::new(u64::try_from(epoch).unwrap()).unwrap(),
        resulting_head: blank_head(),
        lease_expires_at: UnixMillis::new(1_900_000_060_000).unwrap(),
    };
    (request, result)
}

fn authorized_attachment(epoch: i64) -> AuthorizedServingAttachment {
    let (acquire_request, acquire_result) = acquire_receipt(epoch);
    AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: acquire_request.volume_id.clone(),
            attachment_id: acquire_request.attachment_id.clone(),
            attachment_epoch: acquire_result.resulting_epoch,
            acquire_origin: AcquireOrigin::Normal {
                transition_id: acquire_request.transition_id.clone(),
            },
            node_id: Id::new("node_a").unwrap(),
            placement_epoch: acquire_request.placement_epoch,
        },
        size_bytes: VOLUME_SIZE,
        durability: VolumeDurability::Strict,
        head: blank_head(),
        lease_expires_at: acquire_result.lease_expires_at,
        acquire: AuthorizedServingAcquire::Normal {
            request: acquire_request,
            result: acquire_result,
        },
    }
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: Generation::new(0).unwrap(),
        root_hash: None,
        root_object_id: None,
    }
}

fn insert_volume(client: &mut Client, record: &VolumeRecord) {
    let projection = project_volume_record(record).unwrap();
    let record_json = serde_json::to_string(record).unwrap();
    let size_bytes = i64::try_from(projection.size_bytes).unwrap();
    let head_generation = i64::try_from(projection.head_generation.get()).unwrap();
    let lease_epoch = i64::try_from(projection.lease_epoch.get()).unwrap();
    let lease_expires_at = projection
        .lease_expires_at
        .map(|value| i64::try_from(value.get()).unwrap());
    let transition_revision = projection
        .transition_desired_revision
        .map(|value| i64::try_from(value.get()).unwrap());
    let transition_placement = projection
        .transition_placement_epoch
        .map(|value| i64::try_from(value.get()).unwrap());
    let transition_duration = projection
        .transition_lease_duration_ms
        .map(|value| i64::try_from(value).unwrap());
    let owner_binding = VolumeOwnerBinding {
        volume_id: record.volume_id.clone(),
        owner_node_id: Id::new(NODE_ID).unwrap(),
        attachment_id: record.lease_owner.clone().unwrap(),
        attachment_epoch: record.lease_epoch,
    };
    let owner_binding_json = serde_json::to_string(&owner_binding).unwrap();
    client
        .execute(
            "INSERT INTO volume_records (
                volume_id, record, size_bytes, durability, admin_state, delete_id,
                head_generation, head_root_hash, head_root_object_id,
                lease_owner, lease_epoch, lease_expires_at,
                last_transition_kind, last_transition_id,
                transition_desired_revision, transition_placement_epoch,
                transition_lease_duration_ms, owner_binding, owner_node_id
             ) VALUES (
                $1, $2::TEXT::jsonb, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16, $17,
                $18::TEXT::jsonb, $19
             )",
            &[
                &projection.volume_id,
                &record_json,
                &size_bytes,
                &projection.durability,
                &projection.admin_state,
                &projection.delete_id,
                &head_generation,
                &projection.head_root_hash,
                &projection.head_root_object_id,
                &projection.lease_owner,
                &lease_epoch,
                &lease_expires_at,
                &projection.last_transition_kind,
                &projection.last_transition_id,
                &transition_revision,
                &transition_placement,
                &transition_duration,
                &owner_binding_json,
                &NODE_ID,
            ],
        )
        .unwrap();
}

fn assert_legacy_metadata_absent(client: &mut Client) {
    let table: Option<String> = client
        .query_one("SELECT to_regclass('cats_storage_volumes')::text", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        table, None,
        "target control-only mode must never create or probe the legacy metadata schema"
    );
}

struct Server {
    child: Child,
}

impl Server {
    fn wait_ready(&mut self, expected: &std::path::Path) {
        let stdout = self.child.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        if line.trim() != format!("READY {}", expected.display()) {
            let status = match self.child.try_wait().unwrap() {
                Some(status) => status,
                None => {
                    self.child.kill().unwrap();
                    self.child.wait().unwrap()
                }
            };
            let mut stderr = String::new();
            if let Some(mut stream) = self.child.stderr.take() {
                stream.read_to_string(&mut stderr).unwrap();
            }
            panic!(
                "control-only blockd did not publish READY: stdout={line:?}, status={status}, stderr={stderr:?}"
            );
        }
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
    provision_transition_id: RandomId128,
) -> ProvisionRootImageRequest {
    let map = format::image_base_map(manifest, VOLUME_SIZE).unwrap();
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
        provision_transition_id,
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
#[ignore = "requires the privileged installed-namespace Linux systemd gate"]
fn control_only_rejects_frontends_and_serves_only_the_typed_effect() {
    let env = Env::new();
    let rejected = Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
        .arg("--control-only")
        .arg("--attachment-epoch")
        .arg(env.epoch.to_string())
        .arg("--authorized-control-spec")
        .arg(env.authorized_control_spec())
        .arg("--provision-transition-id")
        .arg(env.request.provision_transition_id.as_str())
        .arg("--runtime-scope-id")
        .arg(SCOPE_ID)
        .arg("--process-identity-token")
        .arg(PROCESS_TOKEN)
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

    let rejected_legacy_authority = Command::new(env!("CARGO_BIN_EXE_cats-blockd"))
        .arg("--control-only")
        .arg("--attachment-epoch")
        .arg(env.epoch.to_string())
        .arg("--authorized-control-spec")
        .arg(env.authorized_control_spec())
        .arg("--provision-transition-id")
        .arg(env.request.provision_transition_id.as_str())
        .arg("--runtime-scope-id")
        .arg(SCOPE_ID)
        .arg("--process-identity-token")
        .arg(PROCESS_TOKEN)
        .arg("--listen-control")
        .arg(env.control_socket())
        .arg("--metadata-store-adapter")
        .arg("sqlite")
        .arg("--object-store-adapter")
        .arg("file")
        .output()
        .unwrap();
    assert!(!rejected_legacy_authority.status.success());
    assert!(String::from_utf8_lossy(&rejected_legacy_authority.stderr)
        .contains("requires --metadata-store-adapter postgres"));

    let _server = env.spawn(None);
    assert!(env.control_socket().exists());
    assert!(!env.dir.path().join("forbidden-nbd.sock").exists());
    let status = exchange(&env.control_socket(), b"status\n");
    let status = BlockdControlResponse::parse_wire(std::str::from_utf8(&status).unwrap()).unwrap();
    let BlockdControlResponse::Ok(status) = status else {
        panic!("control-only status returned an error")
    };
    let status: DurabilityStatus = serde_json::from_str(&status).unwrap();
    assert_eq!(status.volume_id, VOLUME_ID);
    assert_eq!(status.attachment_id, ATTACHMENT_ID);
    assert_eq!(status.attachment_epoch, Some(FenceEpoch::new(7).unwrap()));
    assert_eq!(
        status.acquire_origin,
        Some(AcquireOrigin::Normal {
            transition_id: RandomId128::new(ACQUIRE_TRANSITION).unwrap()
        })
    );
    assert_eq!(status.size_bytes, Some(VOLUME_SIZE));
    assert_eq!(status.scope_id, Some(Id::new(SCOPE_ID).unwrap()));
    assert_eq!(
        status.process_identity_token,
        Some(RandomId128::new(PROCESS_TOKEN).unwrap())
    );
    assert_eq!(status.device_ownership_token, None);
    assert_eq!(status.control_only, Some(true));
    assert_eq!(status.guest_io_enabled, Some(false));
    let response = exchange(&env.control_socket(), &wire_request(&env.request));
    assert_ok(&response, &env.request);
    let head = env
        .authority()
        .load_volume(&Id::new(VOLUME_ID).unwrap())
        .unwrap();
    assert_eq!(head.head.generation.get(), 1);
    env.assert_legacy_metadata_absent();
}

#[test]
#[ignore = "requires the privileged installed-namespace Linux systemd gate"]
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
    assert_eq!(
        env.authority()
            .load_volume(&Id::new(VOLUME_ID).unwrap())
            .unwrap()
            .head
            .generation
            .get(),
        0
    );

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
#[ignore = "requires the privileged installed-namespace Linux systemd gate"]
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
    assert_eq!(
        env.authority()
            .load_volume(&Id::new(VOLUME_ID).unwrap())
            .unwrap()
            .head
            .generation
            .get(),
        1
    );
}

#[test]
#[ignore = "requires the privileged installed-namespace Linux systemd gate"]
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
    assert_eq!(
        env.authority()
            .load_volume(&Id::new(VOLUME_ID).unwrap())
            .unwrap()
            .head
            .generation
            .get(),
        1
    );

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
#[ignore = "requires the privileged installed-namespace Linux systemd gate"]
fn every_provision_publication_crash_window_recovers_by_authority_or_exact_replay() {
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
        let after_crash = env
            .authority()
            .load_volume(&Id::new(VOLUME_ID).unwrap())
            .unwrap();
        let _restarted = if after_crash.head == env.request.expected_blank_head {
            let server = env.spawn(None);
            let response = exchange(&env.control_socket(), &wire_request(&env.request));
            assert_ok(&response, &env.request);
            Some(server)
        } else {
            // `after_cas` lost only the response. The signed Runtime closes
            // this ambiguity through the strict authority reread and does not
            // need to start another control process with a stale blank-head
            // launch grant.
            assert_eq!(after_crash.head, env.request.expected_provisioned_head);
            None
        };
        let head = env
            .authority()
            .load_volume(&Id::new(VOLUME_ID).unwrap())
            .unwrap();
        assert_eq!(head.head.generation.get(), 1, "{point}");
        env.assert_legacy_metadata_absent();
        let blob = FileBlobStore::open(env.blob_root()).unwrap();
        let commits = blob.list(&format!("volumes/{VOLUME_ID}/commits/")).unwrap();
        assert_eq!(commits.len(), 1, "{point}: replay made a second commit key");
        assert!(commits[0].ends_with(&format!(
            "1-{}.json",
            env.request.provision_transition_id.as_str()
        )));
    }
}
