//! Integration tests against the real `cats-blockd` binary: NBD transport,
//! crash injection at every commit-protocol window (spec §8), fencing and
//! empty-cache cold restore. Ownership changes are made by this harness before
//! the daemon starts; blockd only adopts the exact presented epoch.

#![cfg(target_os = "linux")]

use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use cats_api::runtime_reconciliation::{
    AcquireOrigin, Epoch, FenceEpoch, Generation, Id, NormalAcquireRequest, NormalAcquireResult,
    RandomId128, RemoteHead, Revision,
};
use cats_block_client::{NbdClient, NbdError, EPERM};
use cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot;
use cats_control_plane::store::Store;
use cats_metadata_store_postgres::PostgresVolumeDataAuthority;
use cats_storage::authority::{
    project_volume_record, AttachmentLineageIdentity, AuthorizedServingAcquire,
    AuthorizedServingAttachment, LastVolumeTransition, UnixMillis, VolumeAdminState,
    VolumeDataAuthority, VolumeDurability, VolumeOwnerBinding, VolumeRecord,
};
use postgres::{Client, NoTls};

const CHUNK: u64 = cats_api::chunk::CHUNK_SIZE as u64;
const VOL_SIZE: u64 = 4 * CHUNK;

struct TestEnv {
    _dir: tempfile::TempDir,
    canonical_root: PathBuf,
    postgres_url: String,
}

impl TestEnv {
    fn new() -> Self {
        let canonical_temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = tempfile::tempdir_in(canonical_temp).unwrap();
        let canonical_root = dir.path().canonicalize().unwrap();
        let postgres_url = cats_control_plane::testsupport::isolated_control_store_url();
        drop(Store::connect(&postgres_url, None).unwrap());
        Self {
            _dir: dir,
            canonical_root,
            postgres_url,
        }
    }

    fn blob_root(&self) -> PathBuf {
        self.canonical_root.join("blob")
    }

    fn data_dir(&self, host: &str) -> PathBuf {
        self.canonical_root.join(format!("data-{host}"))
    }

    fn authority(&self) -> PostgresVolumeDataAuthority {
        PostgresVolumeDataAuthority::connect(&self.postgres_url, None).unwrap()
    }

    /// Test-only stand-in for the external Volume Authority. The helper is
    /// deliberately outside blockd and installs the exact epoch it will pass.
    fn install_grant(&self, attachment: &str, epoch: i64) {
        let mut client = Client::connect(&self.postgres_url, NoTls).unwrap();
        let current = client
            .query_opt(
                "SELECT record::text FROM volume_records WHERE volume_id=$1",
                &[&"vol_it"],
            )
            .unwrap()
            .map(|row| {
                let record: String = row.get(0);
                serde_json::from_str::<VolumeRecord>(&record).unwrap()
            });
        let head = current.map_or_else(blank_head, |record| record.head);
        let (request, result) = acquire_receipt(attachment, epoch, head.clone());
        let record = VolumeRecord {
            volume_id: Id::new("vol_it").unwrap(),
            size_bytes: VOL_SIZE,
            durability: VolumeDurability::Strict,
            admin_state: VolumeAdminState::Active,
            head,
            lease_owner: Some(Id::new(attachment).unwrap()),
            lease_epoch: FenceEpoch::new(u64::try_from(epoch).unwrap()).unwrap(),
            lease_expires_at: Some(result.lease_expires_at),
            last_transition: Some(LastVolumeTransition::NormalAcquire { request, result }),
        };
        let mut transaction = client.transaction().unwrap();
        transaction
            .execute(
                "DELETE FROM volume_records WHERE volume_id=$1",
                &[&"vol_it"],
            )
            .unwrap();
        insert_volume(&mut transaction, &record);
        transaction.commit().unwrap();
    }

    fn authorized_attachment(&self, attachment: &str, epoch: i64) -> AuthorizedServingAttachment {
        let record = self
            .authority()
            .load_volume(&Id::new("vol_it").unwrap())
            .unwrap();
        assert_eq!(record.lease_owner.as_ref().unwrap().as_str(), attachment);
        assert_eq!(record.lease_epoch.get(), u64::try_from(epoch).unwrap());
        let LastVolumeTransition::NormalAcquire { request, result } =
            record.last_transition.clone().unwrap()
        else {
            panic!("test authority did not install a normal acquire marker");
        };
        AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: record.volume_id.clone(),
                attachment_id: Id::new(attachment).unwrap(),
                attachment_epoch: record.lease_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: request.transition_id.clone(),
                },
                node_id: Id::new("node_nbd_crash").unwrap(),
                placement_epoch: request.placement_epoch,
            },
            size_bytes: record.size_bytes,
            durability: record.durability,
            head: record.head,
            lease_expires_at: result.lease_expires_at,
            acquire: AuthorizedServingAcquire::Normal { request, result },
        }
    }
}

fn blank_head() -> RemoteHead {
    RemoteHead {
        generation: Generation::new(0).unwrap(),
        root_hash: None,
        root_object_id: None,
    }
}

fn acquire_receipt(
    attachment: &str,
    epoch: i64,
    head: RemoteHead,
) -> (NormalAcquireRequest, NormalAcquireResult) {
    let sequence = next_sequence();
    let request = NormalAcquireRequest {
        volume_id: Id::new("vol_it").unwrap(),
        transition_id: RandomId128::new(format!("{sequence:032x}")).unwrap(),
        attachment_id: Id::new(attachment).unwrap(),
        expected_unowned_epoch: FenceEpoch::new(u64::try_from(epoch - 1).unwrap()).unwrap(),
        desired_revision: Revision::new(u64::try_from(epoch).unwrap()).unwrap(),
        placement_epoch: Epoch::new(u64::try_from(epoch).unwrap()).unwrap(),
        lease_duration_ms: 1_500,
    };
    let result = NormalAcquireResult {
        volume_id: request.volume_id.clone(),
        transition_id: request.transition_id.clone(),
        attachment_id: request.attachment_id.clone(),
        resulting_epoch: FenceEpoch::new(u64::try_from(epoch).unwrap()).unwrap(),
        resulting_head: head,
        lease_expires_at: UnixMillis::new(1_900_000_001_500).unwrap(),
    };
    (request, result)
}

fn insert_volume(client: &mut impl postgres::GenericClient, record: &VolumeRecord) {
    let projection = project_volume_record(record).unwrap();
    let record_json = serde_json::to_string(record).unwrap();
    let owner_binding = VolumeOwnerBinding {
        volume_id: record.volume_id.clone(),
        owner_node_id: Id::new("node_nbd_crash").unwrap(),
        attachment_id: record.lease_owner.clone().unwrap(),
        attachment_epoch: record.lease_epoch,
    };
    let owner_binding_json = serde_json::to_string(&owner_binding).unwrap();
    let size_bytes = i64::try_from(projection.size_bytes).unwrap();
    let generation = i64::try_from(projection.head_generation.get()).unwrap();
    let epoch = i64::try_from(projection.lease_epoch.get()).unwrap();
    let expires = projection
        .lease_expires_at
        .map(|value| i64::try_from(value.get()).unwrap());
    let revision = projection
        .transition_desired_revision
        .map(|value| i64::try_from(value.get()).unwrap());
    let placement = projection
        .transition_placement_epoch
        .map(|value| i64::try_from(value.get()).unwrap());
    let duration = projection
        .transition_lease_duration_ms
        .map(|value| i64::try_from(value).unwrap());
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
                &generation,
                &projection.head_root_hash,
                &projection.head_root_object_id,
                &projection.lease_owner,
                &epoch,
                &expires,
                &projection.last_transition_kind,
                &projection.last_transition_id,
                &revision,
                &placement,
                &duration,
                &owner_binding_json,
                &"node_nbd_crash",
            ],
        )
        .unwrap();
}

fn next_sequence() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn stable_token(root: &Path, host: &str, sequence: u64) -> RandomId128 {
    let inode = std::fs::symlink_metadata(root).unwrap().ino();
    let host_bits = host
        .bytes()
        .fold(0_u64, |value, byte| value.rotate_left(5) ^ u64::from(byte));
    RandomId128::new(format!(
        "{:016x}{:016x}",
        inode ^ host_bits,
        sequence ^ u64::from(std::process::id())
    ))
    .unwrap()
}

fn provision_installed_directory(path: &Path, mode: u32) {
    match std::fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("create installed directory {}: {error}", path.display()),
    }
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.file_type().is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.mode() & 0o7777, mode);
}

struct Server {
    child: Child,
    socket: PathBuf,
}

impl Server {
    fn spawn(
        env: &TestEnv,
        host: &str,
        attachment: &str,
        epoch: i64,
        crash_point: Option<&str>,
    ) -> Self {
        let attachment_token = stable_token(&env.canonical_root, host, 0);
        let process_token = stable_token(&env.canonical_root, host, next_sequence());
        let paths = ManagedBlockdSocketRoot::installed()
            .serving_paths(&attachment_token)
            .unwrap();
        provision_installed_directory(Path::new("/run/cats"), 0o755);
        provision_installed_directory(Path::new(paths.root().as_str()), 0o700);
        let owner_directory = PathBuf::from(paths.public_directory().as_str());
        provision_installed_directory(&owner_directory, 0o700);
        let socket = PathBuf::from(paths.io_socket().as_str());
        let control_socket = PathBuf::from(paths.control_socket().as_str());
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&control_socket);
        let data_dir = env.data_dir(host);
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let attachment_artifact = env.authorized_attachment(attachment, epoch);
        let identity_path = data_dir.join("identity.json");
        let artifact_path = data_dir.join("authorized-serving.json");
        for (path, bytes) in [
            (
                &identity_path,
                serde_json::to_vec(&attachment_artifact.identity).unwrap(),
            ),
            (
                &artifact_path,
                serde_json::to_vec(&attachment_artifact).unwrap(),
            ),
        ] {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
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
        .arg(&data_dir)
        .arg("--authorized-serving-spec")
        .arg(&artifact_path)
        .arg("--runtime-scope-id")
        .arg("cats-nbd-crash.scope")
        .arg("--process-identity-token")
        .arg(process_token.as_str())
        .arg("--device-ownership-token")
        .arg(attachment_token.as_str())
        .arg("--guest-device-serial")
        .arg("cats-root")
        .arg("--metadata-store-adapter")
        .arg("postgres")
        .arg("--metadata-store-option")
        .arg("url-env=CATS_BLOCKD_TARGET_TEST_POSTGRES_URL")
        .arg("--object-store-adapter")
        .arg("file")
        .arg("--object-store-option")
        .arg(format!("root={}", env.blob_root().display()))
        .arg("--listen-unix")
        .arg(&socket)
        .arg("--listen-control")
        .arg(&control_socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("CATS_BLOCKD_TARGET_TEST_POSTGRES_URL", &env.postgres_url);
        cmd.env_remove("CATS_CRASH_POINT");
        if let Some(point) = crash_point {
            cmd.env("CATS_CRASH_POINT", point);
        }
        let child = cmd.spawn().expect("spawn cats-blockd");
        Self { child, socket }
    }

    fn connect(&mut self) -> NbdClient {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(client) = NbdClient::connect_unix(&self.socket) {
                return client;
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
    let mut offset = 0;
    while offset < VOL_SIZE {
        out.extend_from_slice(&client.read(offset, step as u32).unwrap());
        offset += step;
    }
    out
}

#[test]
fn write_flush_read_through_binary() {
    let env = TestEnv::new();
    env.install_grant("att_a", 1);
    let mut server = Server::spawn(&env, "a", "att_a", 1, None);
    let mut client = server.connect();
    assert_eq!(client.size(), VOL_SIZE);

    let data = pattern(300_000, 1);
    client.write(CHUNK - 1234, &data).unwrap();
    client.flush().unwrap();
    assert_eq!(client.read(CHUNK - 1234, 300_000).unwrap(), data);
    client.disconnect().unwrap();
}

/// Spec §8.1/§8.4: crash at every window; restart under the same external
/// grant must recover the frozen flush exactly once.
#[test]
fn crash_matrix_every_window_recovers_exactly_once() {
    for point in ["after_pack", "after_data_upload", "before_cas", "after_cas"] {
        let env = TestEnv::new();
        env.install_grant("att_a", 1);
        let data0 = pattern(64_000, 3);
        let data1 = pattern(120_000, 7);
        {
            let mut server = Server::spawn(&env, "a", "att_a", 1, Some(point));
            let mut client = server.connect();
            client.write(0, &data0).unwrap();
            client.write(2 * CHUNK + 999, &data1).unwrap();
            let err = client.flush().unwrap_err();
            assert!(
                matches!(err, NbdError::Io(_)),
                "{point}: expected io error, got {err:?}"
            );
            server.wait_exit(Duration::from_secs(10));
        }
        let mut server = Server::spawn(&env, "a", "att_a", 1, None);
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

        let head = env
            .authority()
            .load_volume(&Id::new("vol_it").unwrap())
            .unwrap()
            .head;
        assert_eq!(
            head.generation.get(),
            1,
            "{point}: replay must not double-commit"
        );
        let pending = std::fs::read_dir(env.data_dir("a").join("pending"))
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(pending, 0, "{point}: pack must be drained after recovery");
    }
}

#[test]
fn fenced_writer_gets_eperm_and_new_host_takes_over() {
    let env = TestEnv::new();
    env.install_grant("att_a", 1);
    let mut server_a = Server::spawn(&env, "a", "att_a", 1, None);
    let mut client_a = server_a.connect();
    client_a.write(0, &pattern(4096, 1)).unwrap();
    client_a.flush().unwrap();

    // External authority fences the old tuple; blockd never performs this
    // transition itself.
    env.install_grant("att_a", 2);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match client_a.write(0, b"stale") {
            Err(NbdError::Server(error)) if error == EPERM => break,
            Ok(()) | Err(_) => {
                if Instant::now() > deadline {
                    panic!("old writer was never fenced");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    assert!(matches!(client_a.flush(), Err(NbdError::Server(error)) if error == EPERM));

    env.install_grant("att_b", 3);
    let mut server_b = Server::spawn(&env, "b", "att_b", 3, None);
    let mut client_b = server_b.connect();
    assert_eq!(client_b.read(0, 4096).unwrap(), pattern(4096, 1));
    client_b.write(4096, &pattern(4096, 2)).unwrap();
    client_b.flush().unwrap();
    client_b.disconnect().unwrap();
    assert_eq!(
        env.authority()
            .load_volume(&Id::new("vol_it").unwrap())
            .unwrap()
            .head
            .generation
            .get(),
        2
    );
}

#[test]
fn empty_cache_cold_restore_preserves_digest() {
    let env = TestEnv::new();
    env.install_grant("att_a", 1);
    let digest_before;
    {
        let mut server = Server::spawn(&env, "a", "att_a", 1, None);
        let mut client = server.connect();
        client.write(0, &pattern(CHUNK as usize, 11)).unwrap();
        client.write(CHUNK * 2, &pattern(8192, 13)).unwrap();
        client.write(VOL_SIZE - 512, &pattern(512, 17)).unwrap();
        client.flush().unwrap();
        digest_before = read_all(&mut client);
        client.disconnect().unwrap();
        server.kill();
    }
    std::fs::remove_dir_all(env.data_dir("a")).unwrap();
    env.install_grant("att_b", 2);

    let mut server = Server::spawn(&env, "b", "att_b", 2, None);
    let mut client = server.connect();
    let digest_after = read_all(&mut client);
    assert_eq!(digest_before.len(), digest_after.len());
    assert_eq!(digest_before, digest_after, "cold restore digest mismatch");
    client.disconnect().unwrap();
}
