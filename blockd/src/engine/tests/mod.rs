use super::*;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_file::FileBlobStore;
use cats_storage::authority::{
    authorized_serving_attachment_from_direct_acquire, AuthorizedServingAttachment,
    DirectAcquireServingInput, LastVolumeTransition, NormalAcquireRequest, RenewLeaseResult,
    UnixMillis, VolumeAdminState, VolumeDurability, VolumeHeadCasResult, VolumeRecord,
};
use cats_test_support::blob_doubles::{
    ConcurrencyProbe, CountingBlob, SizingBlob, SlowBlob, SwitchableFailureBlob,
};
use cats_test_support::poll_bound;
use std::path::Path;
use std::sync::atomic::AtomicU64;

mod snapshot_gc;

struct Env {
    _dir: tempfile::TempDir,
    blob: Arc<dyn BlobStore>,
    meta: Arc<SqliteMetadataStore>,
    data_dir: PathBuf,
    initial_epoch: i64,
}

const VOL: &str = "vol_test";
const SIZE: u64 = 8 * CHUNK_SIZE as u64; // 32 MiB logical

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let initial_epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let data_dir = dir.path().join("data");
    Env {
        _dir: dir,
        blob,
        meta,
        data_dir,
        initial_epoch,
    }
}

fn next_test_epoch(meta: &SqliteMetadataStore) -> i64 {
    meta.load_head(VOL).unwrap().lease_epoch + 1
}

fn install_test_grant_at(path: impl AsRef<Path>, attachment_id: &str) -> i64 {
    let meta = SqliteMetadataStore::open(path.as_ref()).unwrap();
    let epoch = next_test_epoch(&meta);
    cats_test_support::install_sqlite_grant(path.as_ref(), VOL, attachment_id, epoch).unwrap();
    epoch
}

fn release_current_test_grant(meta: &dyn MetadataStore) {
    let head = meta.load_head(VOL).unwrap();
    if let Some(owner) = head.lease_owner {
        meta.release_lease(VOL, &owner, head.lease_epoch).unwrap();
    }
}

/// Keeps legacy-engine unit doubles useful while production control-only
/// composition is constrained to the target authority port. Exact PostgreSQL
/// row/transaction behavior is covered in the adapter integration tests.
struct TestVolumeDataAuthority {
    metadata: Arc<dyn MetadataStore>,
}

struct ExactServingAuthority {
    record: Mutex<VolumeRecord>,
    load_calls: AtomicU64,
    renew_calls: AtomicU64,
    fail_load_call: AtomicU64,
}

impl ExactServingAuthority {
    fn new(record: VolumeRecord) -> Self {
        Self {
            record: Mutex::new(record),
            load_calls: AtomicU64::new(0),
            renew_calls: AtomicU64::new(0),
            fail_load_call: AtomicU64::new(0),
        }
    }
}

impl VolumeDataAuthority for ExactServingAuthority {
    fn load_volume(&self, volume_id: &Id) -> cats_storage::authority::Result<VolumeRecord> {
        let call = self.load_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_load_call.load(Ordering::SeqCst) == call {
            return Err(AuthorityError::BackendUnknown);
        }
        let record = self.record.lock().unwrap();
        if record.volume_id != *volume_id {
            return Err(AuthorityError::NotFound);
        }
        Ok(record.clone())
    }

    fn renew_lease(
        &self,
        request: &RenewLeaseRequest,
    ) -> cats_storage::authority::Result<RenewLeaseResult> {
        let call = self.renew_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let now = UnixMillis::new(100_000 + call).unwrap();
        let (updated, result) =
            cats_storage::authority::renew_lease(&self.record.lock().unwrap(), request, now)?;
        *self.record.lock().unwrap() = updated;
        Ok(result)
    }

    fn compare_and_swap_head(
        &self,
        request: &VolumeHeadCasRequest,
    ) -> cats_storage::authority::Result<VolumeHeadCasResult> {
        let (updated, result) =
            cats_storage::authority::compare_and_swap_head(&self.record.lock().unwrap(), request)?;
        *self.record.lock().unwrap() = updated;
        Ok(result)
    }
}

fn target_authority(metadata: Arc<dyn MetadataStore>) -> Arc<dyn VolumeDataAuthority> {
    Arc::new(TestVolumeDataAuthority { metadata })
}

impl VolumeDataAuthority for TestVolumeDataAuthority {
    fn load_volume(&self, volume_id: &Id) -> cats_storage::authority::Result<VolumeRecord> {
        let head = self
            .metadata
            .load_head(volume_id.as_str())
            .map_err(test_authority_error)?;
        let lease_owner = head.lease_owner.map(|owner| {
            Id::new(owner).expect("legacy test attachment ids are valid target authority ids")
        });
        let lease_epoch = FenceEpoch::new(u64::try_from(head.lease_epoch).unwrap_or(0))
            .expect("zero is a valid fence epoch");
        let volume_id =
            Id::new(head.volume_id).expect("legacy test volume ids are valid target authority ids");
        let remote_head = RemoteHead {
            generation: Generation::new(u64::try_from(head.generation).unwrap_or(u64::MAX))
                .expect("legacy test generations fit the target wire range"),
            root_hash: head.root_hash.map(Sha256Digest::from_bytes),
            root_object_id: head.root_object_id.map(|object_id| {
                AsciiText::new(object_id)
                    .expect("legacy test object ids are valid target ASCII text")
            }),
        };
        let last_transition = lease_owner.as_ref().and_then(|attachment_id| {
            (lease_epoch.get() > 0).then(|| {
                let transition_id = cats_api::runtime_reconciliation::RandomId128::new(format!(
                    "{:032x}",
                    lease_epoch.get()
                ))
                .expect("positive lease epoch is a nonzero transition id");
                LastVolumeTransition::NormalAcquire {
                    request: NormalAcquireRequest {
                        volume_id: volume_id.clone(),
                        transition_id: transition_id.clone(),
                        attachment_id: attachment_id.clone(),
                        expected_unowned_epoch: FenceEpoch::new(lease_epoch.get() - 1).unwrap(),
                        placement_epoch: cats_api::runtime_reconciliation::Epoch::new(1).unwrap(),
                        lease_duration_ms: 1,
                    },
                    result: cats_api::runtime_reconciliation::NormalAcquireResult {
                        volume_id: volume_id.clone(),
                        transition_id,
                        attachment_id: attachment_id.clone(),
                        resulting_epoch: lease_epoch,
                        resulting_head: remote_head.clone(),
                        lease_expires_at: UnixMillis::new(1).unwrap(),
                    },
                }
            })
        });
        Ok(VolumeRecord {
            volume_id,
            size_bytes: head.size_bytes,
            durability: VolumeDurability::Strict,
            admin_state: VolumeAdminState::Active,
            gc_required: false,
            head: remote_head,
            lease_owner: lease_owner.clone(),
            lease_epoch,
            lease_expires_at: lease_owner
                .as_ref()
                .map(|_| UnixMillis::new(1).expect("one is a valid timestamp")),
            last_transition,
        })
    }

    fn renew_lease(
        &self,
        request: &RenewLeaseRequest,
    ) -> cats_storage::authority::Result<RenewLeaseResult> {
        self.metadata
            .renew_lease(
                request.volume_id.as_str(),
                request.attachment_id.as_str(),
                i64::try_from(request.expected_epoch.get())
                    .map_err(|_| AuthorityError::BackendUnknown)?,
                i64::try_from(request.lease_duration_ms)
                    .map_err(|_| AuthorityError::InvalidLeaseDuration)?,
            )
            .map_err(test_authority_error)?;
        Ok(RenewLeaseResult {
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            epoch: request.expected_epoch,
            lease_expires_at: UnixMillis::new(1).expect("one is a valid timestamp"),
        })
    }

    fn compare_and_swap_head(
        &self,
        request: &VolumeHeadCasRequest,
    ) -> cats_storage::authority::Result<VolumeHeadCasResult> {
        let hash = request
            .new_head
            .root_hash
            .as_ref()
            .ok_or(AuthorityError::HeadConflict)?;
        let object_id = request
            .new_head
            .root_object_id
            .as_ref()
            .ok_or(AuthorityError::HeadConflict)?;
        self.metadata
            .cas_head(
                request.volume_id.as_str(),
                i64::try_from(request.expected_head.generation.get())
                    .map_err(|_| AuthorityError::BackendUnknown)?,
                i64::try_from(request.new_head.generation.get())
                    .map_err(|_| AuthorityError::BackendUnknown)?,
                *hash.as_bytes(),
                object_id.as_str(),
                request.attachment_id.as_str(),
                i64::try_from(request.expected_epoch.get())
                    .map_err(|_| AuthorityError::BackendUnknown)?,
            )
            .map_err(test_authority_error)?;
        Ok(VolumeHeadCasResult {
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            epoch: request.expected_epoch,
            resulting_head: request.new_head.clone(),
        })
    }
}

fn test_authority_error(error: MetaError) -> AuthorityError {
    match error {
        MetaError::NotFound(_) => AuthorityError::NotFound,
        MetaError::Fenced => AuthorityError::Fenced,
        MetaError::CasConflict { .. } => AuthorityError::HeadConflict,
        MetaError::InvalidArgument(_) => AuthorityError::InvalidLeaseDuration,
        MetaError::AlreadyExists(_) | MetaError::Backend(_) => AuthorityError::BackendUnknown,
    }
}

struct ServingFixture {
    _dir: tempfile::TempDir,
    blob: Arc<FileBlobStore>,
    authority: Arc<ExactServingAuthority>,
    attachment: AuthorizedServingAttachment,
    config: EngineConfig,
    data_dir: PathBuf,
}

fn serving_fixture(durability: VolumeDurability) -> ServingFixture {
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let request = NormalAcquireRequest {
        volume_id: Id::new(VOL).unwrap(),
        transition_id: cats_api::runtime_reconciliation::RandomId128::new(
            "1234567890abcdef1234567890abcdef",
        )
        .unwrap(),
        attachment_id: Id::new("attA").unwrap(),
        expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
        placement_epoch: cats_api::runtime_reconciliation::Epoch::new(3).unwrap(),
        lease_duration_ms: 60_000,
    };
    let unowned = VolumeRecord {
        volume_id: request.volume_id.clone(),
        size_bytes: SIZE,
        durability,
        admin_state: VolumeAdminState::Active,
        gc_required: false,
        head: RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        },
        lease_owner: None,
        lease_epoch: request.expected_unowned_epoch,
        lease_expires_at: None,
        last_transition: None,
    };
    let (record, result) = cats_storage::authority::normal_acquire(
        &unowned,
        &request,
        UnixMillis::new(10_000).unwrap(),
    )
    .unwrap();
    let attachment = authorized_serving_attachment_from_direct_acquire(DirectAcquireServingInput {
        node_id: Id::new("node_a").unwrap(),
        size_bytes: record.size_bytes,
        durability: record.durability,
        request,
        result,
        current_head: record.head.clone(),
        current_lease_expires_at: record.lease_expires_at.unwrap(),
    })
    .unwrap();
    let data_dir = dir.path().join("serving-data");
    let mut config = EngineConfig::new(VOL, &data_dir, "attA");
    config.lease_ttl_ms = 60_000;
    config.durability = match durability {
        VolumeDurability::Strict => DurabilityMode::Strict,
        VolumeDurability::Relaxed => DurabilityMode::Relaxed {
            drain_interval_ms: 0,
        },
    };
    ServingFixture {
        _dir: dir,
        blob,
        authority: Arc::new(ExactServingAuthority::new(record)),
        attachment,
        config,
        data_dir,
    }
}

fn write_serving_identity(fixture: &ServingFixture) {
    fs::create_dir_all(&fixture.data_dir).unwrap();
    let file = File::create(fixture.data_dir.join("identity.json")).unwrap();
    serde_json::to_writer(&file, &fixture.attachment.identity).unwrap();
    file.sync_all().unwrap();
    File::open(&fixture.data_dir).unwrap().sync_all().unwrap();
}

fn attach(env: &Env, attachment: &str) -> Arc<ChunkEngine> {
    let epoch = install_test_grant_at(env._dir.path().join("meta.db"), attachment);
    ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, &env.data_dir, attachment),
        epoch,
        env.blob.clone(),
        env.meta.clone(),
    )
    .unwrap()
}

/// Attach on a different "host" (fresh data dir).
fn attach_at(env: &Env, attachment: &str, dir: &str) -> Arc<ChunkEngine> {
    let epoch = install_test_grant_at(env._dir.path().join("meta.db"), attachment);
    ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, env.data_dir.parent().unwrap().join(dir), attachment),
        epoch,
        env.blob.clone(),
        env.meta.clone(),
    )
    .unwrap()
}

#[test]
fn stale_caller_cannot_adopt_a_newer_epoch_for_the_same_attachment_id() {
    let env = env();
    let stale_epoch = env.initial_epoch;
    let current_epoch = install_test_grant_at(env._dir.path().join("meta.db"), "attA");
    assert!(current_epoch > stale_epoch, "positive epoch calibration");

    let result = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, &env.data_dir, "attA"),
        stale_epoch,
        env.blob.clone(),
        env.meta.clone(),
    );

    assert!(matches!(result, Err(EngineError::Meta(MetaError::Fenced))));
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn write_read_roundtrip_and_holes() {
    let env = env();
    let e = attach(&env, "attA");
    let data = pattern(10_000, 1);
    e.write(1234, &data).unwrap();
    let mut back = vec![0u8; 10_000];
    e.read(1234, &mut back).unwrap();
    assert_eq!(back, data);
    // Untouched region reads zeros.
    let mut z = vec![1u8; 4096];
    e.read(SIZE - 4096, &mut z).unwrap();
    assert!(z.iter().all(|&b| b == 0));
    // Out of bounds is rejected.
    assert!(e.read(SIZE - 1, &mut [0u8; 2]).is_err());
    assert!(e.write(SIZE, b"x").is_err());
    e.detach().unwrap();
}

/// V1 runtime adoption may only re-adopt a live `cats-blockd` if the process
/// self-reports, over the control protocol, the volume and attachment the
/// agent started it for. `status` serializes exactly this payload, so the
/// identity has to survive the wire encoding.
#[test]
fn status_reports_the_configured_volume_and_attachment() {
    let env = env();
    let e = attach(&env, "attA");
    let wire = serde_json::to_string(&e.durability_status()).unwrap();
    let status: cats_api::blockd::DurabilityStatus = serde_json::from_str(&wire).unwrap();
    assert_eq!(status.volume_id, VOL);
    assert_eq!(status.attachment_id, "attA");
    assert_eq!(status.guest_device_serial, None);
    e.detach().unwrap();

    // A later attachment of the same volume reports its own attachment id, so
    // the field tracks the configuration rather than a constant.
    let next = attach(&env, "attB");
    let status = next.durability_status();
    assert_eq!(status.volume_id, VOL);
    assert_eq!(status.attachment_id, "attB");
    next.detach().unwrap();
}

#[test]
fn authorized_serving_requires_identity_before_authority_or_local_state() {
    let fixture = serving_fixture(VolumeDurability::Strict);
    let authority: Arc<dyn VolumeDataAuthority> = fixture.authority.clone();
    let result = ChunkEngine::attach_authorized_serving(
        fixture.config.clone(),
        fixture.attachment.clone(),
        fixture.blob.clone(),
        authority,
    );
    assert!(matches!(result, Err(EngineError::Io(_))));
    assert_eq!(fixture.authority.load_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.authority.renew_calls.load(Ordering::SeqCst), 0);
    assert!(!fixture.data_dir.join(PENDING_PACK_DIR).exists());
}

#[test]
fn authorized_control_only_renews_exact_grant_and_keeps_guest_io_closed() {
    let fixture = serving_fixture(VolumeDurability::Strict);
    write_serving_identity(&fixture);
    let authority: Arc<dyn VolumeDataAuthority> = fixture.authority.clone();
    let engine = ChunkEngine::attach_authorized_control_only(
        fixture.config.clone(),
        fixture.attachment.clone(),
        fixture.blob.clone(),
        authority,
    )
    .unwrap();
    assert_eq!(fixture.authority.load_calls.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.authority.renew_calls.load(Ordering::SeqCst), 1);
    let status = engine.durability_status();
    assert_eq!(
        status.attachment_epoch,
        Some(fixture.attachment.identity.attachment_epoch)
    );
    assert_eq!(
        status.acquire_origin.as_ref(),
        Some(&fixture.attachment.identity.acquire_origin)
    );
    assert_eq!(status.guest_io_enabled, Some(false));
    assert_eq!(status.remote_head, Some(fixture.attachment.head.clone()));
    assert!(matches!(
        engine.write(0, b"must stay closed"),
        Err(EngineError::GuestIoDisabled)
    ));
}

#[test]
fn authorized_serving_renews_before_guest_io_and_writes_target_v2_lineage() {
    let fixture = serving_fixture(VolumeDurability::Relaxed);
    write_serving_identity(&fixture);
    let authority: Arc<dyn VolumeDataAuthority> = fixture.authority.clone();
    let engine = ChunkEngine::attach_authorized_serving(
        fixture.config.clone(),
        fixture.attachment.clone(),
        fixture.blob.clone(),
        authority,
    )
    .unwrap();
    assert_eq!(fixture.authority.renew_calls.load(Ordering::SeqCst), 1);

    let status = engine.durability_status();
    assert_eq!(
        status.attachment_epoch,
        Some(fixture.attachment.identity.attachment_epoch)
    );
    assert_eq!(
        status.acquire_origin.as_ref(),
        Some(&fixture.attachment.identity.acquire_origin)
    );
    assert_eq!(
        status.node_id.as_ref(),
        Some(&fixture.attachment.identity.node_id)
    );
    assert_eq!(
        status.placement_epoch,
        Some(fixture.attachment.identity.placement_epoch)
    );
    assert_eq!(status.guest_io_enabled, Some(true));

    engine.write(0, b"authorized target bytes").unwrap();
    assert_eq!(engine.flush().unwrap(), 1);
    let packs = fs::read_dir(fixture.data_dir.join(PENDING_PACK_DIR))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(packs.len(), 1);
    let bytes = fs::read(&packs[0]).unwrap();
    assert_eq!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()), 2);
    let (header, _) = format::decode_pack(&bytes).unwrap();
    assert_eq!(header.lease_epoch, None);
    assert_eq!(
        header.attachment_id.as_deref(),
        Some(fixture.attachment.identity.attachment_id.as_str())
    );
    assert_eq!(
        header.attachment_epoch,
        Some(i64::try_from(fixture.attachment.identity.attachment_epoch.get()).unwrap())
    );
    assert_eq!(
        header.acquire_origin.as_ref(),
        Some(&fixture.attachment.identity.acquire_origin)
    );

    engine.stop_authorized_serving().unwrap();
    assert_eq!(
        fixture.authority.record.lock().unwrap().head.generation,
        Generation::new(1).unwrap()
    );
    assert!(fixture
        .authority
        .record
        .lock()
        .unwrap()
        .lease_owner
        .is_some());
}

#[test]
fn authorized_serving_restarts_after_the_same_grant_advances_its_head() {
    let fixture = serving_fixture(VolumeDurability::Strict);
    write_serving_identity(&fixture);
    let first_authority: Arc<dyn VolumeDataAuthority> = fixture.authority.clone();
    let engine = ChunkEngine::attach_authorized_serving(
        fixture.config.clone(),
        fixture.attachment.clone(),
        fixture.blob.clone(),
        first_authority,
    )
    .unwrap();
    engine.write(0, b"committed before response loss").unwrap();
    assert_eq!(engine.flush().unwrap(), 1);
    engine.stop_authorized_serving().unwrap();
    drop(engine);

    assert_eq!(
        fixture.attachment.head.generation,
        Generation::new(0).unwrap()
    );
    assert_eq!(
        fixture.authority.record.lock().unwrap().head.generation,
        Generation::new(1).unwrap()
    );

    let restart_authority: Arc<dyn VolumeDataAuthority> = fixture.authority.clone();
    let restarted = ChunkEngine::attach_authorized_serving(
        fixture.config.clone(),
        fixture.attachment.clone(),
        fixture.blob.clone(),
        restart_authority,
    )
    .unwrap();
    assert_eq!(restarted.generation(), 1);
    let mut recovered = vec![0; b"committed before response loss".len()];
    restarted.read(0, &mut recovered).unwrap();
    assert_eq!(recovered, b"committed before response loss");
    restarted.stop_authorized_serving().unwrap();
}

#[test]
fn authorized_serving_retry_after_lost_startup_result_reuses_the_exact_grant() {
    let fixture = serving_fixture(VolumeDurability::Strict);
    write_serving_identity(&fixture);
    fixture.authority.fail_load_call.store(3, Ordering::SeqCst);
    let first_authority: Arc<dyn VolumeDataAuthority> = fixture.authority.clone();
    let first = ChunkEngine::attach_authorized_serving(
        fixture.config.clone(),
        fixture.attachment.clone(),
        fixture.blob.clone(),
        first_authority,
    );
    assert!(first.is_err());
    assert_eq!(fixture.authority.renew_calls.load(Ordering::SeqCst), 1);
    assert!(!fixture.data_dir.join(PENDING_PACK_DIR).exists());

    fixture.authority.fail_load_call.store(0, Ordering::SeqCst);
    let retry_authority: Arc<dyn VolumeDataAuthority> = fixture.authority.clone();
    let engine = ChunkEngine::attach_authorized_serving(
        fixture.config.clone(),
        fixture.attachment.clone(),
        fixture.blob.clone(),
        retry_authority,
    )
    .unwrap();
    assert_eq!(fixture.authority.renew_calls.load(Ordering::SeqCst), 2);
    assert_eq!(engine.epoch(), 1);
    engine.stop_authorized_serving().unwrap();
}

#[test]
fn authorized_serving_never_adopts_or_discards_legacy_and_malformed_packs() {
    let legacy = serving_fixture(VolumeDurability::Strict);
    write_serving_identity(&legacy);
    let pending = legacy.data_dir.join(PENDING_PACK_DIR);
    fs::create_dir_all(&pending).unwrap();
    let legacy_path = pending.join("00000000000000000000-legacy.pack");
    fs::write(
        &legacy_path,
        format::encode_pack(
            &PackHeader {
                txn: "legacy".into(),
                volume_id: VOL.into(),
                base_generation: 0,
                lease_epoch: Some(1),
                attachment_id: None,
                attachment_epoch: None,
                acquire_origin: None,
                entries: Vec::new(),
            },
            &[],
        ),
    )
    .unwrap();
    let authority: Arc<dyn VolumeDataAuthority> = legacy.authority.clone();
    let result = ChunkEngine::attach_authorized_serving(
        legacy.config.clone(),
        legacy.attachment.clone(),
        legacy.blob.clone(),
        authority,
    );
    assert!(matches!(result, Err(EngineError::Corrupt(_))));
    assert!(legacy_path.exists(), "legacy evidence must remain intact");
    assert_eq!(
        legacy.authority.record.lock().unwrap().head.generation,
        Generation::new(0).unwrap()
    );

    let malformed = serving_fixture(VolumeDurability::Strict);
    write_serving_identity(&malformed);
    let pending = malformed.data_dir.join(PENDING_PACK_DIR);
    fs::create_dir_all(&pending).unwrap();
    let malformed_path = pending.join("00000000000000000000-malformed.pack");
    fs::write(&malformed_path, b"not a pack").unwrap();
    let authority: Arc<dyn VolumeDataAuthority> = malformed.authority.clone();
    let result = ChunkEngine::attach_authorized_serving(
        malformed.config.clone(),
        malformed.attachment.clone(),
        malformed.blob.clone(),
        authority,
    );
    assert!(matches!(result, Err(EngineError::Corrupt(_))));
    assert!(
        malformed_path.exists(),
        "malformed target evidence must remain intact"
    );
}

#[test]
fn flush_commits_and_survives_full_cache_wipe() {
    let env = env();
    let data1 = pattern(CHUNK_SIZE as usize, 3); // full chunk 0
    let data2 = pattern(5000, 9); // straddles chunk 2/3 boundary
    {
        let e = attach(&env, "attA");
        e.write(0, &data1).unwrap();
        e.write(3 * CHUNK_SIZE as u64 - 2500, &data2).unwrap();
        let generation = e.flush().unwrap();
        assert_eq!(generation, 1);
        // Empty dirty set: flush is a no-op that keeps the generation.
        assert_eq!(e.flush().unwrap(), 1);
        e.detach().unwrap();
    }
    // Simulate a brand-new host: wipe every local byte.
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach(&env, "attB");
    assert_eq!(e.generation(), 1);
    let mut back = vec![0u8; CHUNK_SIZE as usize];
    e.read(0, &mut back).unwrap();
    assert_eq!(back, data1);
    let mut back2 = vec![0u8; 5000];
    e.read(3 * CHUNK_SIZE as u64 - 2500, &mut back2).unwrap();
    assert_eq!(back2, data2);
    // A hole chunk still reads zeros after recovery.
    let mut z = vec![1u8; 512];
    e.read(5 * CHUNK_SIZE as u64, &mut z).unwrap();
    assert!(z.iter().all(|&b| b == 0));
    e.detach().unwrap();
}

/// Interval 0 = no background committer: relaxed engines in these tests
/// drain explicitly, deterministically.
const NO_TIMER: u64 = 0;

fn attach_relaxed(env: &Env, attachment: &str) -> Arc<ChunkEngine> {
    let epoch = install_test_grant_at(env._dir.path().join("meta.db"), attachment);
    let mut cfg = EngineConfig::new(VOL, &env.data_dir, attachment);
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    ChunkEngine::attach_granted_epoch(cfg, epoch, env.blob.clone(), env.meta.clone()).unwrap()
}

#[test]
fn relaxed_flush_acks_locally_and_the_drain_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let counting = Arc::new(CountingBlob::new(Arc::new(
        FileBlobStore::open(dir.path().join("blob")).unwrap(),
    )));
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, counting.clone(), meta).unwrap();

    e.write(0, &pattern(4096, 7)).unwrap();
    let acked = e.flush().unwrap();
    assert_eq!(acked, 1, "flush reports the pack's target generation");
    assert_eq!(
        counting.data_put_count(),
        0,
        "a relaxed ack must not wait on the object store"
    );
    assert_eq!(e.generation(), 0, "nothing committed yet");
    let status = e.durability_status();
    assert_eq!(status.local_durable_generation, 1);
    assert_eq!(status.remote_durable_generation, 0);
    assert_eq!(status.unpublished_generations, 1);
    assert!(status.unpublished_bytes > 4096);
    assert!(!status.backpressured);
    assert_eq!(status.last_publish_error, None);

    // An empty flush with a staged backlog still acks the same target.
    assert_eq!(e.flush().unwrap(), 1);

    assert_eq!(e.drain_staged().unwrap(), 1);
    assert!(counting.data_put_count() > 0);
    assert_eq!(e.generation(), 1);
    e.detach().unwrap();
}

#[test]
fn one_large_barrier_is_split_into_bounded_contiguous_packs() {
    const TEST_LIMIT: usize = 18 << 20;
    const DENSE_BYTES: usize = 3 << 20;

    let _limit = PublisherWorkingSetLimitGuard::set(TEST_LIMIT);
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(CountingMeta {
        inner: Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap()),
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: None,
    });
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta.clone()).unwrap();
    let first = pattern(DENSE_BYTES, 61);
    let second = pattern(DENSE_BYTES, 62);
    e.write(0, &first).unwrap();
    e.write(CHUNK_SIZE as u64, &second).unwrap();

    assert_eq!(
        e.flush().unwrap(),
        2,
        "one logical barrier must advance once per bounded pack"
    );
    let paths: Vec<PathBuf> = e
        .staged
        .lock()
        .unwrap()
        .packs
        .iter()
        .map(|pack| pack.path.clone())
        .collect();
    assert_eq!(paths.len(), 2);
    for (index, path) in paths.iter().enumerate() {
        let encoded = fs::read(path).unwrap();
        let (header, _) = format::decode_pack(&encoded).unwrap();
        assert_eq!(header.base_generation, index as i64);
        let materialized = materialized_pack_bytes(&header).unwrap();
        assert!(
            pack_working_set_bytes(encoded.len(), materialized).unwrap() <= TEST_LIMIT,
            "pack {index} exceeded its exact publisher budget"
        );
    }

    assert_eq!(e.drain_staged().unwrap(), 2);
    assert_eq!(
        meta.cas_calls.load(Ordering::SeqCst),
        2,
        "the same budget also bounds each publisher CAS prefix"
    );
    e.detach().unwrap();

    let restored_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let restored = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
        restored_epoch,
        blob,
        meta,
    )
    .unwrap();
    let mut back = vec![0u8; DENSE_BYTES];
    restored.read(0, &mut back).unwrap();
    assert_eq!(back, first);
    restored.read(CHUNK_SIZE as u64, &mut back).unwrap();
    assert_eq!(back, second);
    restored.detach().unwrap();
}

#[test]
fn strict_flush_waits_for_every_bounded_pack_in_one_barrier() {
    const TEST_LIMIT: usize = 18 << 20;
    const DENSE_BYTES: usize = 3 << 20;

    let _limit = PublisherWorkingSetLimitGuard::set(TEST_LIMIT);
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(CountingMeta {
        inner: Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap()),
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: None,
    });
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let e = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        epoch,
        blob,
        meta.clone(),
    )
    .unwrap();
    e.write(0, &pattern(DENSE_BYTES, 63)).unwrap();
    e.write(CHUNK_SIZE as u64, &pattern(DENSE_BYTES, 64))
        .unwrap();

    assert_eq!(e.flush().unwrap(), 2);
    assert!(e.staged.lock().unwrap().packs.is_empty());
    assert_eq!(
        meta.cas_calls.load(Ordering::SeqCst),
        2,
        "Strict must publish every bounded pack before acknowledging the barrier"
    );
    e.detach().unwrap();
}

#[test]
fn failed_multi_pack_stage_queues_its_durable_prefix_and_restores_the_tail() {
    const TEST_LIMIT: usize = 18 << 20;
    const DENSE_BYTES: usize = 3 << 20;

    let _limit = PublisherWorkingSetLimitGuard::set(TEST_LIMIT);
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let data_dir = dir.path().join("data");
    let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta.clone()).unwrap();
    let first = pattern(DENSE_BYTES, 71);
    let second = pattern(DENSE_BYTES, 72);
    let third = pattern(DENSE_BYTES, 73);
    e.write(0, &first).unwrap();
    e.write(CHUNK_SIZE as u64, &second).unwrap();

    let error = {
        let _failure = StageWriteFailureGuard::set(1);
        e.flush().unwrap_err()
    };
    assert!(matches!(error, EngineError::Io(_)));
    let status = e.durability_status();
    assert_eq!(status.local_durable_generation, 1);
    assert_eq!(status.remote_durable_generation, 0);
    assert_eq!(status.unpublished_generations, 1);
    assert_eq!(e.staged.lock().unwrap().packs.len(), 1);

    // The failed barrier was not ACKed, but its durable first pack remains a
    // live prefix. The restored tail can join later writes in a new barrier
    // without a restart or a generation gap.
    e.write(2 * CHUNK_SIZE as u64, &third).unwrap();
    assert_eq!(e.flush().unwrap(), 3);
    assert_eq!(e.staged.lock().unwrap().packs.len(), 3);
    assert_eq!(e.drain_staged().unwrap(), 3);
    e.detach().unwrap();

    let restored_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let restored = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
        restored_epoch,
        blob,
        meta,
    )
    .unwrap();
    for (chunk_index, expected) in [first, second, third].iter().enumerate() {
        let mut back = vec![0u8; DENSE_BYTES];
        restored
            .read(chunk_index as u64 * CHUNK_SIZE as u64, &mut back)
            .unwrap();
        assert_eq!(&back, expected, "chunk {chunk_index} lost staged bytes");
    }
    restored.detach().unwrap();
}

#[test]
fn restart_scans_a_durable_split_prefix_without_breaking_the_watermark() {
    const TEST_LIMIT: usize = 18 << 20;
    const DENSE_BYTES: usize = 3 << 20;

    let _limit = PublisherWorkingSetLimitGuard::set(TEST_LIMIT);
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let data_dir = dir.path().join("data");
    let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let first = pattern(DENSE_BYTES, 74);
    let second = pattern(DENSE_BYTES, 75);
    {
        let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta.clone()).unwrap();
        e.write(0, &first).unwrap();
        e.write(CHUNK_SIZE as u64, &second).unwrap();
        let error = {
            let _failure = StageWriteFailureGuard::set(1);
            e.flush().unwrap_err()
        };
        assert!(matches!(error, EngineError::Io(_)));
        assert_eq!(e.staged.lock().unwrap().packs.len(), 1);
        // Drop models a crash: the in-memory queue disappears, leaving only
        // the renamed pack prefix and persistent dirty bitmap/cache.
    }
    release_current_test_grant(meta.as_ref());
    let recovered_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");

    let recovered = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, &data_dir, "attB"),
        recovered_epoch,
        blob,
        meta,
    )
    .unwrap();
    assert_eq!(
        recovered.generation(),
        1,
        "startup must replay the durable contiguous prefix"
    );
    let mut back = vec![0u8; DENSE_BYTES];
    recovered.read(0, &mut back).unwrap();
    assert_eq!(back, first);
    // The tail was never ACKed, so a crash may discard it. The recovered
    // prefix must nevertheless leave an appendable watermark.
    let replacement = pattern(4096, 76);
    recovered
        .write(2 * CHUNK_SIZE as u64, &replacement)
        .unwrap();
    assert_eq!(recovered.flush().unwrap(), 2);
    let mut replacement_back = vec![0u8; replacement.len()];
    recovered
        .read(2 * CHUNK_SIZE as u64, &mut replacement_back)
        .unwrap();
    assert_eq!(replacement_back, replacement);
    recovered.detach().unwrap();
}

#[test]
fn split_overlay_fragments_promote_to_bases_and_preserve_the_exact_bytes() {
    const RANGE_STORM_LIMIT: usize = (8 << 20) + (16 << 10);

    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let data_dir = dir.path().join("data");
    let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta.clone()).unwrap();
    let mut expected = vec![0u8; CHUNK_SIZE as usize];

    for generation in 0..3usize {
        let offset = generation * cats_api::chunk::DIRTY_PAGE_SIZE as usize;
        let bytes = pattern(4096, 81 + generation as u8);
        e.write(offset as u64, &bytes).unwrap();
        expected[offset..offset + bytes.len()].copy_from_slice(&bytes);
        e.flush().unwrap();
        e.drain_staged().unwrap();
    }
    assert_eq!(e.state.lock().unwrap().map[0].layer_count(), 3);

    let _limit = PublisherWorkingSetLimitGuard::set(RANGE_STORM_LIMIT);
    let mut range_count = 0usize;
    for page in 0..33usize {
        let page_start = page * cats_api::chunk::DIRTY_PAGE_SIZE as usize;
        for range in 0..16usize {
            let offset = page_start + range * 2;
            let byte = [(page as u8).wrapping_add(range as u8).wrapping_add(1)];
            e.write(offset as u64, &byte).unwrap();
            expected[offset] = byte[0];
            range_count += 1;
        }
    }
    let local_generation = e.flush().unwrap();
    let paths: Vec<PathBuf> = e
        .staged
        .lock()
        .unwrap()
        .packs
        .iter()
        .map(|pack| pack.path.clone())
        .collect();
    assert!(paths.len() > 1, "the range storm did not cross the budget");
    let mut persisted_ranges = 0usize;
    for path in &paths {
        let encoded = fs::read(path).unwrap();
        let (header, _) = format::decode_pack(&encoded).unwrap();
        assert_eq!(header.entries.len(), 1);
        assert_eq!(header.entries[0].page_mask, format::full_page_mask());
        persisted_ranges += header.entries[0].byte_ranges.len();
        assert!(
            pack_working_set_bytes(encoded.len(), materialized_pack_bytes(&header).unwrap())
                .unwrap()
                <= RANGE_STORM_LIMIT
        );
    }
    assert_eq!(persisted_ranges, range_count);
    assert_eq!(local_generation, 3 + paths.len() as i64);

    e.drain_staged().unwrap();
    assert_eq!(
        e.state.lock().unwrap().map[0].layer_count(),
        0,
        "budget-split overlays must end at a fresh base"
    );
    e.detach().unwrap();

    let restored_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let restored = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
        restored_epoch,
        blob,
        meta,
    )
    .unwrap();
    let mut back = vec![0u8; CHUNK_SIZE as usize];
    restored.read(0, &mut back).unwrap();
    assert_eq!(format::sha256(&back), format::sha256(&expected));
    assert_eq!(back, expected);
    restored.detach().unwrap();
}

#[test]
fn relaxed_restart_rebuilds_the_local_watermark_without_remote_writes() {
    use cats_storage::blob::FaultyBlobStore;

    let dir = tempfile::tempdir().unwrap();
    let healthy: Arc<dyn BlobStore> =
        Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let faulty = Arc::new(FaultyBlobStore::new(healthy.clone()));
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let data_dir = dir.path().join("data");

    {
        let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        let e =
            ChunkEngine::attach_granted_epoch(cfg, epoch, healthy.clone(), meta.clone()).unwrap();
        e.write(100, &pattern(4096, 1)).unwrap();
        assert_eq!(e.flush().unwrap(), 1);
        // Overwrite the same pages in a second staged pack: replay order
        // becomes observable in the final bytes.
        e.write(100, &pattern(4096, 2)).unwrap();
        e.write(CHUNK_SIZE as u64 + 7, b"second-chunk").unwrap();
        assert_eq!(e.flush().unwrap(), 2);
        assert_eq!(e.generation(), 0, "both packs staged, none committed");
        // Crash: Drop stops threads but does not drain.
    }

    faulty.fail_puts.store(10, Ordering::SeqCst);
    let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, faulty.clone(), meta).unwrap();
    assert_eq!(
        faulty.fail_puts.load(Ordering::SeqCst),
        10,
        "same-host relaxed recovery must not issue a remote PUT"
    );
    let status = e.durability_status();
    assert_eq!(status.local_durable_generation, 2);
    assert_eq!(status.remote_durable_generation, 0);
    assert_eq!(status.unpublished_generations, 2);

    // The cache plus local journal remains the running truth while the
    // remote watermark is behind.
    let mut b = vec![0u8; 4096];
    e.read(100, &mut b).unwrap();
    assert_eq!(b, pattern(4096, 2), "the later staged pack wins");
    let mut s = vec![0u8; 12];
    e.read(CHUNK_SIZE as u64 + 7, &mut s).unwrap();
    assert_eq!(&s, b"second-chunk");

    faulty.fail_puts.store(0, Ordering::SeqCst);
    assert_eq!(e.drain_staged().unwrap(), 2);
    e.detach().unwrap();
}

#[test]
fn remote_outage_is_observable_but_does_not_fail_relaxed_flush() {
    use cats_storage::blob::FaultyBlobStore;

    let dir = tempfile::tempdir().unwrap();
    let healthy: Arc<dyn BlobStore> =
        Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let faulty = Arc::new(FaultyBlobStore::new(healthy));
    faulty.fail_puts.store(u64::MAX, Ordering::SeqCst);
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: 50,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, faulty, meta).unwrap();

    e.write(0, &pattern(4096, 9)).unwrap();
    assert_eq!(
        e.flush().unwrap(),
        1,
        "remote failure must not become Guest EIO"
    );
    let deadline = std::time::Instant::now() + poll_bound();
    loop {
        let status = e.durability_status();
        if status.last_publish_error.is_some() {
            assert_eq!(status.local_durable_generation, 1);
            assert_eq!(status.remote_durable_generation, 0);
            assert_eq!(status.unpublished_generations, 1);
            assert!(status.unpublished_bytes > 0);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "background publisher failure never reached durability status"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Drop models a process failure and deliberately avoids the forced
    // remote drain performed by graceful detach.
}

#[test]
fn relaxed_cold_cache_write_and_flush_issue_no_remote_read() {
    let dir = tempfile::tempdir().unwrap();
    let healthy: Arc<dyn BlobStore> =
        Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let seed_epoch = install_test_grant_at(dir.path().join("meta.db"), "seed");
    let original = pattern(CHUNK_SIZE as usize, 71);
    {
        let e = ChunkEngine::attach_granted_epoch(
            EngineConfig::new(VOL, dir.path().join("seed"), "seed"),
            seed_epoch,
            healthy.clone(),
            meta.clone(),
        )
        .unwrap();
        e.write(0, &original).unwrap();
        e.flush().unwrap();
        e.detach().unwrap();
    }

    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let switched = Arc::new(SwitchableFailureBlob::new(healthy.clone()));
    let mut cfg = EngineConfig::new(VOL, dir.path().join("relaxed"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, switched.clone(), meta.clone()).unwrap();
    let before = switched.get_count();
    switched.set_fail_gets(true);
    let update = pattern(4096, 99);
    e.write(123, &update).unwrap();
    assert_eq!(e.flush().unwrap(), 2);
    assert_eq!(
        switched.get_count(),
        before,
        "cold-cache relaxed WRITE/FLUSH must not issue an object GET"
    );

    switched.set_fail_gets(false);
    let mut live = vec![0u8; CHUNK_SIZE as usize];
    e.read(0, &mut live).unwrap();
    let mut expected = original.clone();
    expected[123..123 + update.len()].copy_from_slice(&update);
    assert_eq!(
        live, expected,
        "a cold read merges the remote base with the local overlay"
    );
    e.drain_staged().unwrap();
    e.detach().unwrap();
    let restored_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let restored = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("restored"), "attB"),
        restored_epoch,
        healthy,
        meta,
    )
    .unwrap();
    let mut actual = vec![0u8; CHUNK_SIZE as usize];
    restored.read(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    restored.detach().unwrap();
}

#[test]
fn relaxed_read_waits_until_a_frozen_cold_overlay_is_journaled() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    let dir = tempfile::tempdir().unwrap();
    let blob: Arc<dyn BlobStore> = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let seed_epoch = install_test_grant_at(dir.path().join("meta.db"), "seed");
    let original = pattern(CHUNK_SIZE as usize, 81);
    {
        let seed = ChunkEngine::attach_granted_epoch(
            EngineConfig::new(VOL, dir.path().join("seed"), "seed"),
            seed_epoch,
            blob.clone(),
            meta.clone(),
        )
        .unwrap();
        seed.write(0, &original).unwrap();
        seed.flush().unwrap();
        seed.detach().unwrap();
    }

    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("relaxed"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    // The first tiny pack fits. The second overlay is larger than this cap,
    // so it may enter only after the first pack drains; that holds it
    // deterministically in the freeze-to-journal interval.
    cfg.max_staged_bytes = 1 << 20;
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob, meta).unwrap();
    assert!(
        !e.state.lock().unwrap().map[0].is_hole(),
        "the committed seed chunk must be present before the relaxed writes"
    );
    e.write(17, b"x").unwrap();
    e.flush().unwrap();
    assert!(e.durability_status().unpublished_bytes < 1 << 20);

    let large_offset = 1 << 20;
    let large = pattern((2 << 20) + cats_api::chunk::DIRTY_PAGE_SIZE as usize, 92);
    e.write(large_offset, &large).unwrap();
    let flushing = {
        let e = e.clone();
        thread::spawn(move || e.flush())
    };
    let deadline = Instant::now() + poll_bound();
    loop {
        if e.state.lock().unwrap().freezing.contains(&0) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second FLUSH never reached the frozen-overlay interval"
        );
        thread::sleep(Duration::from_millis(1));
    }

    let (read_tx, read_rx) = mpsc::channel();
    let reading = {
        let e = e.clone();
        thread::spawn(move || {
            let mut bytes = vec![0u8; CHUNK_SIZE as usize];
            let result = e.read(0, &mut bytes).map(|()| bytes);
            read_tx.send(result).unwrap();
        })
    };
    assert!(
        read_rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "cold read escaped while its local overlay was neither dirty nor journaled"
    );

    // Publishing the first pack makes local staging room. The second FLUSH
    // can then insert its durable pack and wake the reader.
    e.drain_staged().unwrap();
    flushing.join().unwrap().unwrap();
    let actual = read_rx
        .recv_timeout(poll_bound())
        .expect("reader did not wake after the pack became visible")
        .unwrap();
    reading.join().unwrap();

    let mut expected = original;
    expected[17] = b'x';
    expected[large_offset as usize..large_offset as usize + large.len()].copy_from_slice(&large);
    e.drain_staged().unwrap();
    if actual != expected {
        let mismatch = actual
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected)
            .unwrap();
        let st = e.state.lock().unwrap();
        panic!(
            "mismatch at byte {mismatch}: actual={} expected={}, actual_sha={} expected_sha={}, generation={}, staged={}, hydrated={}, map={:?}",
            actual[mismatch],
            expected[mismatch],
            hex::encode(format::sha256(&actual)),
            hex::encode(format::sha256(&expected)),
            st.generation,
            e.staged.lock().unwrap().packs.len(),
            st.hydrated[0],
            st.map[0],
        );
    }
    e.detach().unwrap();
}

#[test]
fn local_quota_evicts_clean_chunks_but_preserves_committed_reads() {
    let env = env();
    let mut cfg = EngineConfig::new(VOL, &env.data_dir, "attA");
    // One dense chunk plus one same-sized pending pack fits; retaining two
    // dense clean chunks while staging the second does not.
    cfg.max_local_bytes = 9 << 20;
    let e = ChunkEngine::attach_granted_epoch(
        cfg,
        env.initial_epoch,
        env.blob.clone(),
        env.meta.clone(),
    )
    .unwrap();
    let first = pattern(CHUNK_SIZE as usize, 31);
    let second = pattern(CHUNK_SIZE as usize, 47);

    e.write(0, &first).unwrap();
    e.flush().unwrap();
    e.write(CHUNK_SIZE as u64, &second).unwrap();
    e.flush().unwrap();

    let status = e.durability_status();
    assert!(
        status.evicted_cache_chunks >= 1,
        "the second dense commit should evict a clean LRU chunk"
    );
    assert!(status.local_allocated_bytes <= status.max_local_bytes);

    let mut restored = vec![0u8; CHUNK_SIZE as usize];
    e.read(0, &mut restored).unwrap();
    assert_eq!(restored, first, "an evicted clean chunk rehydrates exactly");
    e.detach().unwrap();
}

#[test]
fn relaxed_dirty_cache_reserves_pack_space_and_cannot_deadlock_the_quota() {
    let env = env();
    let mut cfg = EngineConfig::new(VOL, &env.data_dir, "attA");
    cfg.durability = DurabilityMode::Relaxed {
        // Only a pressure kick, not this timer, can publish in test time.
        drain_interval_ms: 3_600_000,
    };
    // One dense cache chunk plus its future pack fits. Two dirty cache
    // chunks do not, so the second WRITE must first stage the first one and
    // let the background publisher reclaim its reservation.
    cfg.max_local_bytes = 10 << 20;
    let e = ChunkEngine::attach_granted_epoch(
        cfg,
        env.initial_epoch,
        env.blob.clone(),
        env.meta.clone(),
    )
    .unwrap();
    let first = pattern(CHUNK_SIZE as usize, 61);
    let second = pattern(CHUNK_SIZE as usize, 73);
    e.write(0, &first).unwrap();
    let dirty = e.durability_status();
    assert_eq!(dirty.unpublished_generations, 0);
    assert!(
        dirty.local_accounted_bytes > dirty.local_allocated_bytes,
        "the future pending pack must be reserved before FLUSH"
    );

    let worker = e.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let result = worker.write(CHUNK_SIZE as u64, &second);
        let _ = tx.send(result);
    });
    rx.recv_timeout(poll_bound())
        .expect("quota pressure deadlocked before a pack could be published")
        .unwrap();
    handle.join().unwrap();

    let status = e.durability_status();
    assert!(
        status.remote_durable_generation >= 1,
        "the implicit local stage did not give the publisher work"
    );
    assert!(status.local_accounted_bytes <= status.max_local_bytes);
    e.flush().unwrap();
    e.detach().unwrap();
}

#[test]
fn relaxed_detach_publishes_staged_packs() {
    let env = env();
    let data = pattern(4096, 5);
    {
        let e = attach_relaxed(&env, "attA");
        e.write(2 * CHUNK_SIZE as u64, &data).unwrap();
        e.flush().unwrap();
        assert_eq!(e.generation(), 0);
        e.detach().unwrap();
    }
    // A different host with nothing local sees the detach-drained state.
    let e = attach_at(&env, "attB", "data-b");
    assert_eq!(e.generation(), 1);
    let mut back = vec![0u8; 4096];
    e.read(2 * CHUNK_SIZE as u64, &mut back).unwrap();
    assert_eq!(back, data);
    e.detach().unwrap();
}

#[test]
fn failed_detach_keeps_the_journal_and_lease_for_retry() {
    use cats_storage::blob::FaultyBlobStore;

    let dir = tempfile::tempdir().unwrap();
    let healthy: Arc<dyn BlobStore> =
        Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let faulty = Arc::new(FaultyBlobStore::new(healthy.clone()));
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data-a"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, faulty.clone(), meta.clone()).unwrap();
    e.write(0, &pattern(4096, 4)).unwrap();
    e.flush().unwrap();

    faulty.fail_puts.store(u64::MAX, Ordering::SeqCst);
    assert!(e.detach().is_err(), "the mandatory drain must fail closed");
    assert_eq!(e.durability_status().unpublished_generations, 1);
    let competitor = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
        epoch,
        healthy.clone(),
        meta.clone(),
    );
    assert!(matches!(
        competitor,
        Err(EngineError::Meta(MetaError::Fenced))
    ));

    faulty.fail_puts.store(0, Ordering::SeqCst);
    e.detach().unwrap();
    let next_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let next = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
        next_epoch,
        healthy,
        meta,
    )
    .unwrap();
    assert_eq!(next.generation(), 1);
    next.detach().unwrap();
}

/// Counts head swaps, so a test can prove a batch is one CAS.
struct CountingMeta {
    inner: Arc<dyn MetadataStore>,
    cas_calls: AtomicU64,
    forced_head_epoch: Option<i64>,
}

/// Commits the first CAS but drops its response, reproducing a database
/// timeout after PostgreSQL made the new root authoritative.
#[derive(Clone, Copy)]
enum CasFault {
    BackendBeforeCas,
    ResponseLost,
    ResponseLostAndFirstReconciliationFails,
    ResponseLostThenLeaseRevoked,
    ResponseLostThenGenerationAdvanced,
    ResponseLostThenSizeChanged,
    UnrelatedRootPublished,
    ExplicitFenced,
}

struct LostCasResponseMeta {
    inner: Arc<dyn MetadataStore>,
    fault: Mutex<Option<CasFault>>,
    fail_next_load: AtomicBool,
    forced_head_size: AtomicU64,
    cas_calls: AtomicU64,
}

impl MetadataStore for LostCasResponseMeta {
    fn create_volume(&self, v: &str, s: u64) -> cats_storage::metadata::Result<()> {
        self.inner.create_volume(v, s)
    }
    fn load_head(
        &self,
        v: &str,
    ) -> cats_storage::metadata::Result<cats_storage::metadata::VolumeHead> {
        if self.fail_next_load.swap(false, Ordering::SeqCst) {
            return Err(MetaError::Backend(
                "injected authoritative-head read failure".into(),
            ));
        }
        let mut head = self.inner.load_head(v)?;
        let forced_size = self.forced_head_size.load(Ordering::SeqCst);
        if forced_size != 0 {
            head.size_bytes = forced_size;
        }
        Ok(head)
    }
    fn delete_volume(&self, v: &str) -> cats_storage::metadata::Result<()> {
        self.inner.delete_volume(v)
    }
    fn renew_lease(
        &self,
        v: &str,
        a: &str,
        epoch: i64,
        ttl: i64,
    ) -> cats_storage::metadata::Result<()> {
        self.inner.renew_lease(v, a, epoch, ttl)
    }
    fn release_lease(&self, v: &str, a: &str, epoch: i64) -> cats_storage::metadata::Result<()> {
        self.inner.release_lease(v, a, epoch)
    }
    #[allow(clippy::too_many_arguments)]
    fn cas_head(
        &self,
        v: &str,
        expected: i64,
        new_generation: i64,
        hash: [u8; 32],
        object: &str,
        a: &str,
        epoch: i64,
    ) -> cats_storage::metadata::Result<i64> {
        self.cas_calls.fetch_add(1, Ordering::SeqCst);
        let fault = self.fault.lock().unwrap().take();
        match fault {
            Some(CasFault::BackendBeforeCas) => {
                return Err(MetaError::Backend(
                    "injected failure before root CAS".into(),
                ));
            }
            Some(CasFault::ExplicitFenced) => return Err(MetaError::Fenced),
            Some(CasFault::UnrelatedRootPublished) => {
                self.inner.cas_head(
                    v,
                    expected,
                    new_generation,
                    [0xa5; 32],
                    "unrelated-root.node",
                    a,
                    epoch,
                )?;
                return Err(MetaError::Backend(
                    "injected unrelated publication during ambiguous CAS".into(),
                ));
            }
            _ => {}
        }
        let generation =
            self.inner
                .cas_head(v, expected, new_generation, hash, object, a, epoch)?;
        if let Some(fault) = fault {
            match fault {
                CasFault::ResponseLost => {}
                CasFault::ResponseLostAndFirstReconciliationFails => {
                    self.fail_next_load.store(true, Ordering::SeqCst);
                }
                CasFault::ResponseLostThenLeaseRevoked => {
                    self.inner.release_lease(v, a, epoch)?;
                }
                CasFault::ResponseLostThenGenerationAdvanced => {
                    self.inner.cas_head(
                        v,
                        new_generation,
                        new_generation + 1,
                        [0xa5; 32],
                        "unrelated-root.node",
                        a,
                        epoch,
                    )?;
                }
                CasFault::ResponseLostThenSizeChanged => {
                    let changed_size = self
                        .inner
                        .load_head(v)?
                        .size_bytes
                        .checked_add(1)
                        .expect("test volume size has room to grow");
                    self.forced_head_size.store(changed_size, Ordering::SeqCst);
                }
                CasFault::BackendBeforeCas
                | CasFault::UnrelatedRootPublished
                | CasFault::ExplicitFenced => unreachable!(),
            }
            return Err(MetaError::Backend(
                "injected timeout after root CAS committed".into(),
            ));
        }
        Ok(generation)
    }
    fn create_snapshot(
        &self,
        s: &str,
        v: &str,
    ) -> cats_storage::metadata::Result<cats_storage::metadata::SnapshotRow> {
        self.inner.create_snapshot(s, v)
    }
    fn list_snapshots(
        &self,
        v: &str,
    ) -> cats_storage::metadata::Result<Vec<cats_storage::metadata::SnapshotRow>> {
        self.inner.list_snapshots(v)
    }
}

impl MetadataStore for CountingMeta {
    fn create_volume(&self, v: &str, s: u64) -> cats_storage::metadata::Result<()> {
        self.inner.create_volume(v, s)
    }
    fn load_head(
        &self,
        v: &str,
    ) -> cats_storage::metadata::Result<cats_storage::metadata::VolumeHead> {
        let mut head = self.inner.load_head(v)?;
        if let Some(epoch) = self.forced_head_epoch {
            head.lease_epoch = epoch;
        }
        Ok(head)
    }
    fn delete_volume(&self, v: &str) -> cats_storage::metadata::Result<()> {
        self.inner.delete_volume(v)
    }
    fn renew_lease(
        &self,
        v: &str,
        a: &str,
        epoch: i64,
        ttl: i64,
    ) -> cats_storage::metadata::Result<()> {
        self.inner.renew_lease(v, a, epoch, ttl)
    }
    fn release_lease(&self, v: &str, a: &str, epoch: i64) -> cats_storage::metadata::Result<()> {
        self.inner.release_lease(v, a, epoch)
    }
    #[allow(clippy::too_many_arguments)]
    fn cas_head(
        &self,
        v: &str,
        expected: i64,
        new_generation: i64,
        hash: [u8; 32],
        object: &str,
        a: &str,
        epoch: i64,
    ) -> cats_storage::metadata::Result<i64> {
        self.cas_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .cas_head(v, expected, new_generation, hash, object, a, epoch)
    }
    fn create_snapshot(
        &self,
        s: &str,
        v: &str,
    ) -> cats_storage::metadata::Result<cats_storage::metadata::SnapshotRow> {
        self.inner.create_snapshot(s, v)
    }
    fn list_snapshots(
        &self,
        v: &str,
    ) -> cats_storage::metadata::Result<Vec<cats_storage::metadata::SnapshotRow>> {
        self.inner.list_snapshots(v)
    }
}

#[test]
fn batched_drain_publishes_the_whole_queue_in_one_cas() {
    let dir = tempfile::tempdir().unwrap();
    let blob: Arc<dyn BlobStore> = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(CountingMeta {
        inner: Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap()),
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: None,
    });
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta.clone()).unwrap();

    for i in 0..5u8 {
        e.write(i as u64 * CHUNK_SIZE as u64, &pattern(4096, i + 1))
            .unwrap();
        assert_eq!(e.flush().unwrap(), i as i64 + 1);
    }
    assert_eq!(e.generation(), 0, "five packs staged, none committed");
    let before = meta.cas_calls.load(Ordering::SeqCst);

    assert_eq!(e.drain_staged().unwrap(), 5, "head jumps one step per pack");
    assert_eq!(
        meta.cas_calls.load(Ordering::SeqCst) - before,
        1,
        "the whole batch publishes under a single swap"
    );
    e.detach().unwrap();

    // A fresh host sees every pack's content: the batch really committed.
    let restored_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data-b"), "attB");
    cfg.durability = DurabilityMode::Strict;
    let e = ChunkEngine::attach_granted_epoch(cfg, restored_epoch, blob, meta).unwrap();
    assert_eq!(e.generation(), 5);
    for i in 0..5u8 {
        let mut back = vec![0u8; 4096];
        e.read(i as u64 * CHUNK_SIZE as u64, &mut back).unwrap();
        assert_eq!(back, pattern(4096, i + 1), "chunk {i}");
    }
    e.detach().unwrap();
}

#[test]
fn final_batch_record_is_byte_stable_when_recovery_uses_smaller_prefixes() {
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let (meta, epoch) = fault_meta(&dir, CasFault::BackendBeforeCas);
    let data_dir = dir.path().join("data");
    let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta.clone()).unwrap();
    e.write(0, &pattern(4096, 31)).unwrap();
    assert_eq!(e.flush().unwrap(), 1);
    e.write(CHUNK_SIZE as u64, &pattern(4096, 32)).unwrap();
    assert_eq!(e.flush().unwrap(), 2);
    let final_txn = e.staged.lock().unwrap().packs.back().unwrap().txn.clone();
    let final_record_key = chunk::keys::commit_record(VOL, 2, &final_txn);

    assert!(matches!(
        e.drain_staged(),
        Err(EngineError::Meta(MetaError::Backend(_)))
    ));
    assert_eq!(meta.load_head(VOL).unwrap().generation, 0);
    let record_before_restart = blob.get(&final_record_key).unwrap();
    assert!(
        !blob
            .exists(&chunk::keys::commit_record(
                VOL,
                1,
                &e.staged.lock().unwrap().packs.front().unwrap().txn,
            ))
            .unwrap(),
        "the failed batch writes only its final commit record"
    );

    // This is the durable state of a crash after the final record PUT and
    // before CAS. A Strict restart replays A and B separately, changing the
    // batch prefix but not the identity or bytes of B's final record.
    drop(e);
    release_current_test_grant(meta.as_ref());
    let recovered_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let recovered = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, &data_dir, "attB"),
        recovered_epoch,
        blob.clone(),
        meta.clone(),
    )
    .unwrap();
    assert_eq!(recovered.generation(), 2);
    assert_eq!(blob.get(&final_record_key).unwrap(), record_before_restart);
    assert!(fs::read_dir(data_dir.join("pending"))
        .unwrap()
        .next()
        .is_none());
    assert_eq!(
        meta.cas_calls.load(Ordering::SeqCst),
        3,
        "one failed batch CAS plus two single-pack recovery CAS operations"
    );
    recovered.detach().unwrap();
}

#[test]
fn strict_recovery_cleans_every_pack_covered_by_a_final_record_only_batch() {
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(CountingMeta {
        inner: Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap()),
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: None,
    });
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let data_dir = dir.path().join("data");
    let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta.clone()).unwrap();
    e.write(0, &pattern(4096, 41)).unwrap();
    e.flush().unwrap();
    e.write(CHUNK_SIZE as u64, &pattern(4096, 42)).unwrap();
    e.flush().unwrap();

    let paths: Vec<PathBuf> = e
        .staged
        .lock()
        .unwrap()
        .packs
        .iter()
        .map(|pack| pack.path.clone())
        .collect();
    let decoded: Vec<(PackHeader, Vec<u8>)> = paths
        .iter()
        .map(|path| format::decode_pack(&fs::read(path).unwrap()).unwrap())
        .collect();
    let packs: Vec<(&PackHeader, &[u8])> = decoded
        .iter()
        .map(|(header, payload)| (header, payload.as_slice()))
        .collect();
    let (base_map, base_leaves) = {
        let state = e.state.lock().unwrap();
        (state.map.clone(), state.leaf_refs.clone())
    };
    assert_eq!(
        e.commit_pack_batch(&packs, base_map, base_leaves).unwrap(),
        2
    );
    assert_eq!(meta.cas_calls.load(Ordering::SeqCst), 1);
    assert!(
        !blob
            .exists(&chunk::keys::commit_record(VOL, 1, &decoded[0].0.txn))
            .unwrap(),
        "a successful batch intentionally has no intermediate record"
    );

    // Simulate a crash after CAS and before local queue cleanup. Recovery must
    // use the exact authoritative generation as the oracle, not require an
    // intermediate record that the batching model never writes.
    drop(e);
    release_current_test_grant(meta.as_ref());
    let recovered_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let recovered = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, &data_dir, "attB"),
        recovered_epoch,
        blob,
        meta.clone(),
    )
    .unwrap();
    assert_eq!(recovered.generation(), 2);
    assert!(fs::read_dir(data_dir.join("pending"))
        .unwrap()
        .next()
        .is_none());
    assert_eq!(
        meta.cas_calls.load(Ordering::SeqCst),
        1,
        "cleanup of a covered prefix must not issue another CAS"
    );
    recovered.detach().unwrap();
}

#[test]
fn generation_exhaustion_rejects_a_batch_before_any_remote_write() {
    use cats_storage::blob::FaultyBlobStore;

    let dir = tempfile::tempdir().unwrap();
    let healthy: Arc<dyn BlobStore> =
        Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let blob = Arc::new(FaultyBlobStore::new(healthy));
    let meta = Arc::new(CountingMeta {
        inner: Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap()),
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: None,
    });
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let e = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        epoch,
        blob.clone(),
        meta.clone(),
    )
    .unwrap();

    let first = PackHeader {
        txn: "generation-exhaustion-a".into(),
        volume_id: VOL.into(),
        base_generation: i64::MAX - 1,
        lease_epoch: Some(e.epoch),
        attachment_id: None,
        attachment_epoch: None,
        acquire_origin: None,
        entries: Vec::new(),
    };
    let second = PackHeader {
        txn: "generation-exhaustion-b".into(),
        volume_id: VOL.into(),
        base_generation: i64::MAX,
        lease_epoch: Some(e.epoch),
        attachment_id: None,
        attachment_epoch: None,
        acquire_origin: None,
        entries: Vec::new(),
    };
    let (base_map, base_leaves) = {
        let state = e.state.lock().unwrap();
        (state.map.clone(), state.leaf_refs.clone())
    };

    // Any object-store PUT would consume this fault. The unchanged counter and
    // CAS count jointly prove the overflow is rejected before remote mutation.
    blob.fail_puts.store(1, Ordering::SeqCst);
    let cas_before = meta.cas_calls.load(Ordering::SeqCst);
    let error = e
        .commit_pack_batch(&[(&first, &[]), (&second, &[])], base_map, base_leaves)
        .unwrap_err();

    assert!(
        matches!(error, EngineError::Corrupt(ref message) if message == "commit generation overflow"),
        "unexpected generation exhaustion error: {error}"
    );
    assert_eq!(
        blob.fail_puts.load(Ordering::SeqCst),
        1,
        "generation exhaustion must precede every immutable PUT"
    );
    assert_eq!(
        meta.cas_calls.load(Ordering::SeqCst),
        cas_before,
        "generation exhaustion must precede the authority CAS"
    );

    blob.fail_puts.store(0, Ordering::SeqCst);
    e.detach().unwrap();
}

#[test]
fn malformed_batch_lineage_is_rejected_before_any_remote_write() {
    use cats_storage::blob::FaultyBlobStore;

    let dir = tempfile::tempdir().unwrap();
    let healthy: Arc<dyn BlobStore> =
        Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let blob = Arc::new(FaultyBlobStore::new(healthy));
    let meta = Arc::new(CountingMeta {
        inner: Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap()),
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: None,
    });
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let e = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        epoch,
        blob.clone(),
        meta.clone(),
    )
    .unwrap();
    let first = PackHeader {
        txn: "lineage-a".into(),
        volume_id: VOL.into(),
        base_generation: 0,
        lease_epoch: Some(e.epoch),
        attachment_id: None,
        attachment_epoch: None,
        acquire_origin: None,
        entries: Vec::new(),
    };
    let second = PackHeader {
        txn: "lineage-b".into(),
        volume_id: VOL.into(),
        base_generation: 1,
        lease_epoch: Some(e.epoch),
        attachment_id: None,
        attachment_epoch: None,
        acquire_origin: None,
        entries: Vec::new(),
    };
    let (base_map, base_leaves) = {
        let state = e.state.lock().unwrap();
        (state.map.clone(), state.leaf_refs.clone())
    };
    let malformed = [
        {
            let mut value = second.clone();
            value.base_generation = 2;
            (first.clone(), value)
        },
        (second.clone(), first.clone()),
        {
            let mut value = second.clone();
            value.volume_id = "other-volume".into();
            (first.clone(), value)
        },
        {
            let mut value = second.clone();
            value.lease_epoch = value.lease_epoch.map(|epoch| epoch + 1);
            (first.clone(), value)
        },
        {
            let mut value = second.clone();
            value.txn = first.txn.clone();
            (first.clone(), value)
        },
    ];

    for (first, second) in malformed {
        blob.fail_puts.store(1, Ordering::SeqCst);
        let cas_before = meta.cas_calls.load(Ordering::SeqCst);
        assert!(matches!(
            e.commit_pack_batch(
                &[(&first, &[]), (&second, &[])],
                base_map.clone(),
                base_leaves.clone(),
            ),
            Err(EngineError::Corrupt(_))
        ));
        assert_eq!(blob.fail_puts.load(Ordering::SeqCst), 1);
        assert_eq!(meta.cas_calls.load(Ordering::SeqCst), cas_before);
    }

    blob.fail_puts.store(0, Ordering::SeqCst);
    e.detach().unwrap();
}

#[test]
fn malformed_pack_entries_fail_before_any_remote_write_or_indexing() {
    use cats_storage::blob::FaultyBlobStore;

    let dir = tempfile::tempdir().unwrap();
    let healthy: Arc<dyn BlobStore> =
        Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let blob = Arc::new(FaultyBlobStore::new(healthy));
    let meta = Arc::new(CountingMeta {
        inner: Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap()),
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: None,
    });
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let e = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        epoch,
        blob.clone(),
        meta.clone(),
    )
    .unwrap();
    let page = vec![0x5a; cats_api::chunk::DIRTY_PAGE_SIZE as usize];
    let valid_entry = PackEntry {
        chunk_idx: 0,
        payload_offset: 0,
        len: page.len() as u32,
        sha256_hex: hex::encode(format::sha256(&page)),
        page_mask: 1,
        byte_ranges: Vec::new(),
    };

    let mut cases: Vec<(&str, PackEntry, Vec<u8>)> = vec![
        (
            "payload offset overflow",
            PackEntry {
                payload_offset: u64::MAX,
                len: 1,
                ..valid_entry.clone()
            },
            vec![0x5a],
        ),
        (
            "payload length out of bounds",
            PackEntry {
                len: valid_entry.len + 1,
                ..valid_entry.clone()
            },
            page.clone(),
        ),
        (
            "chunk out of bounds",
            PackEntry {
                chunk_idx: e.chunk_count,
                ..valid_entry.clone()
            },
            page.clone(),
        ),
        (
            "payload hash mismatch",
            PackEntry {
                sha256_hex: "00".repeat(32),
                ..valid_entry.clone()
            },
            page.clone(),
        ),
        (
            "page mask length mismatch",
            PackEntry {
                page_mask: 0b11,
                ..valid_entry
            },
            page,
        ),
    ];
    let overlay = vec![0x7b; 16];
    cases.push((
        "byte range exceeds chunk",
        PackEntry {
            chunk_idx: 0,
            payload_offset: 0,
            len: overlay.len() as u32,
            sha256_hex: hex::encode(format::sha256(&overlay)),
            page_mask: 1,
            byte_ranges: vec![PackByteRange {
                chunk_offset: CHUNK_SIZE - 8,
                payload_offset: 0,
                len: overlay.len() as u32,
            }],
        },
        overlay.clone(),
    ));
    cases.push((
        "byte range payload overflow",
        PackEntry {
            chunk_idx: 0,
            payload_offset: 0,
            len: overlay.len() as u32,
            sha256_hex: hex::encode(format::sha256(&overlay)),
            page_mask: 1,
            byte_ranges: vec![PackByteRange {
                chunk_offset: 0,
                payload_offset: u64::MAX,
                len: overlay.len() as u32,
            }],
        },
        overlay,
    ));

    let (base_map, base_leaves) = {
        let state = e.state.lock().unwrap();
        (state.map.clone(), state.leaf_refs.clone())
    };
    for (case, entry, payload) in cases {
        let header = PackHeader {
            txn: format!("malformed-{}", case.replace(' ', "-")),
            volume_id: VOL.into(),
            base_generation: 0,
            lease_epoch: Some(e.epoch),
            attachment_id: None,
            attachment_epoch: None,
            acquire_origin: None,
            entries: vec![entry],
        };
        blob.fail_puts.store(1, Ordering::SeqCst);
        let cas_before = meta.cas_calls.load(Ordering::SeqCst);
        let error = e
            .commit_pack_batch(
                &[(&header, payload.as_slice())],
                base_map.clone(),
                base_leaves.clone(),
            )
            .unwrap_err();
        assert!(
            matches!(error, EngineError::Corrupt(_)),
            "{case} returned {error}"
        );
        assert_eq!(
            blob.fail_puts.load(Ordering::SeqCst),
            1,
            "{case} reached an immutable PUT"
        );
        assert_eq!(
            meta.cas_calls.load(Ordering::SeqCst),
            cas_before,
            "{case} reached the authority CAS"
        );
    }

    blob.fail_puts.store(0, Ordering::SeqCst);
    e.detach().unwrap();
}

#[test]
fn committed_cas_with_a_lost_response_is_reconciled_without_fencing() {
    let dir = tempfile::tempdir().unwrap();
    let blob: Arc<dyn BlobStore> = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let sqlite = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    sqlite.create_volume(VOL, SIZE).unwrap();
    cats_test_support::install_sqlite_grant(&dir.path().join("meta.db"), VOL, "attA", 1).unwrap();
    let inner: Arc<dyn MetadataStore> = sqlite;
    let meta = Arc::new(LostCasResponseMeta {
        inner,
        fault: Mutex::new(Some(CasFault::ResponseLost)),
        fail_next_load: AtomicBool::new(false),
        forced_head_size: AtomicU64::new(0),
        cas_calls: AtomicU64::new(0),
    });
    let data_dir = dir.path().join("data-a");
    let e = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, &data_dir, "attA"),
        1,
        blob.clone(),
        meta.clone(),
    )
    .unwrap();
    let data = pattern(4096, 73);
    e.write(0, &data).unwrap();

    assert_eq!(
        e.flush().unwrap(),
        1,
        "a committed root must survive a lost CAS response"
    );
    assert!(!e.is_fenced(), "an ambiguous success is not a stale writer");
    assert!(fs::read_dir(data_dir.join("pending"))
        .unwrap()
        .next()
        .is_none());
    e.detach().unwrap();

    let restored_epoch = install_test_grant_at(dir.path().join("meta.db"), "attB");
    let restored = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
        restored_epoch,
        blob,
        meta,
    )
    .unwrap();
    let mut back = vec![0; data.len()];
    restored.read(0, &mut back).unwrap();
    assert_eq!(back, data);
    restored.detach().unwrap();
}

/// An engine over a `LostCasResponseMeta` primed with `fault`, with one page
/// already written so the next `flush` has something to publish. Each caller
/// passes its own `byte` so a failure names the test that wrote the data.
fn dirty_engine_with_fault(dir: &tempfile::TempDir, fault: CasFault, byte: u8) -> Arc<ChunkEngine> {
    let blob: Arc<dyn BlobStore> = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let (meta, epoch) = fault_meta(dir, fault);
    let engine = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        epoch,
        blob,
        meta,
    )
    .unwrap();
    engine.write(0, &pattern(4096, byte)).unwrap();
    engine
}

fn fault_meta(dir: &tempfile::TempDir, fault: CasFault) -> (Arc<LostCasResponseMeta>, i64) {
    let sqlite = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    sqlite.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let inner: Arc<dyn MetadataStore> = sqlite;
    let meta = Arc::new(LostCasResponseMeta {
        inner,
        fault: Mutex::new(Some(fault)),
        fail_next_load: AtomicBool::new(false),
        forced_head_size: AtomicU64::new(0),
        cas_calls: AtomicU64::new(0),
    });
    (meta, epoch)
}

#[test]
fn a_lost_cas_response_can_be_reconciled_by_the_next_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let e = dirty_engine_with_fault(&dir, CasFault::ResponseLostAndFirstReconciliationFails, 74);

    assert!(matches!(
        e.flush(),
        Err(EngineError::Meta(MetaError::Backend(_)))
    ));
    assert!(!e.is_fenced());
    assert_eq!(
        e.drain_staged().unwrap(),
        1,
        "the retry's CAS conflict must reconcile the earlier ambiguous success"
    );
    assert!(!e.is_fenced());
    e.detach().unwrap();
}

#[test]
fn a_matching_root_under_a_revoked_lease_still_fences() {
    let dir = tempfile::tempdir().unwrap();
    let e = dirty_engine_with_fault(&dir, CasFault::ResponseLostThenLeaseRevoked, 75);

    assert!(matches!(
        e.flush(),
        Err(EngineError::Meta(MetaError::Fenced))
    ));
    assert!(e.is_fenced());
}

#[test]
fn an_authoritative_generation_beyond_the_target_fences() {
    let dir = tempfile::tempdir().unwrap();
    let e = dirty_engine_with_fault(&dir, CasFault::ResponseLostThenGenerationAdvanced, 76);

    assert!(matches!(
        e.flush(),
        Err(EngineError::Meta(MetaError::CasConflict { expected: 0 }))
    ));
    assert!(e.is_fenced());
}

#[test]
fn a_target_head_with_a_different_size_cannot_reconcile_a_lost_response() {
    let dir = tempfile::tempdir().unwrap();
    let blob: Arc<dyn BlobStore> = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let (meta, epoch) = fault_meta(&dir, CasFault::ResponseLostThenSizeChanged);
    let e = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        epoch,
        blob,
        meta.clone(),
    )
    .unwrap();
    e.write(0, &pattern(4096, 77)).unwrap();

    assert!(matches!(
        e.flush(),
        Err(EngineError::Meta(MetaError::CasConflict { expected: 0 }))
    ));
    assert!(
        e.is_fenced(),
        "a changed authority binding must fail closed"
    );
    assert_eq!(e.generation(), 0, "the target head must not be adopted");
    assert_eq!(
        meta.cas_calls.load(Ordering::SeqCst),
        1,
        "ambiguous reconciliation must read, never guess with a second CAS"
    );
    let observed = meta.load_head(VOL).unwrap();
    assert_eq!(observed.generation, 1, "the injected CAS did commit");
    assert_ne!(observed.size_bytes, SIZE, "the authority size drifted");
}

#[test]
fn an_unrelated_root_at_the_target_generation_fences() {
    let dir = tempfile::tempdir().unwrap();
    let e = dirty_engine_with_fault(&dir, CasFault::UnrelatedRootPublished, 78);

    assert!(matches!(
        e.flush(),
        Err(EngineError::Meta(MetaError::CasConflict { expected: 0 }))
    ));
    assert!(e.is_fenced());
}

#[test]
fn an_explicit_fenced_error_is_never_rewritten_as_success() {
    let dir = tempfile::tempdir().unwrap();
    let e = dirty_engine_with_fault(&dir, CasFault::ExplicitFenced, 77);

    assert!(matches!(
        e.flush(),
        Err(EngineError::Meta(MetaError::Fenced))
    ));
    assert!(e.is_fenced());
}

#[test]
fn eager_committer_drains_a_burst_without_the_timer() {
    let env = env();
    let mut cfg = EngineConfig::new(VOL, &env.data_dir, "attA");
    // An hour on the timer: only the eager kick can drain in test time.
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: 3_600_000,
    };
    let e = ChunkEngine::attach_granted_epoch(
        cfg,
        env.initial_epoch,
        env.blob.clone(),
        env.meta.clone(),
    )
    .unwrap();
    for i in 0..8u8 {
        e.write(i as u64 * CHUNK_SIZE as u64, &pattern(4096, i + 1))
            .unwrap();
        e.flush().unwrap();
    }
    let deadline = std::time::Instant::now() + poll_bound();
    while e.generation() < 8 {
        assert!(
            std::time::Instant::now() < deadline,
            "the eager kick never drained the queue: generation {}",
            e.generation()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    e.detach().unwrap();
}

struct ThreadRecordingBlob {
    inner: Arc<dyn BlobStore>,
    put_calls: Mutex<Vec<(String, bool)>>,
    calls_changed: Condvar,
    put_gate: Option<Arc<PutGate>>,
}

#[derive(Default)]
struct PutGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

struct PutGateRelease {
    gate: Arc<PutGate>,
}

impl Drop for PutGateRelease {
    fn drop(&mut self) {
        self.gate.release();
    }
}

impl PutGate {
    fn block_until_released(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn wait_until_entered(&self) -> std::result::Result<(), String> {
        let deadline = std::time::Instant::now() + poll_bound();
        let mut state = self.state.lock().unwrap();
        while !state.0 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("no caller reached the blocking PUT before the deadline".into());
            }
            let (next, wait) = self.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if wait.timed_out() && !state.0 {
                return Err("no caller reached the blocking PUT before the deadline".into());
            }
        }
        Ok(())
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.1 = true;
        self.changed.notify_all();
    }

    fn was_entered(&self) -> bool {
        self.state.lock().unwrap().0
    }

    fn release_on_drop(self: &Arc<Self>) -> PutGateRelease {
        PutGateRelease {
            gate: Arc::clone(self),
        }
    }
}

impl ThreadRecordingBlob {
    /// Wait for a named committer call, rejecting a Guest-side call as soon as
    /// it is recorded. Waiting for merely "some PUT" is racy because the
    /// committer's scoped upload workers can legitimately arrive first.
    fn wait_for_named_background_put(&self) -> std::result::Result<Vec<(String, bool)>, String> {
        let deadline = std::time::Instant::now() + poll_bound();
        let mut calls = self.put_calls.lock().unwrap();
        loop {
            if calls.iter().any(|(_, publisher)| !publisher) {
                return Err(format!(
                    "remote PUT escaped the background publisher: {calls:?}"
                ));
            }
            if calls.iter().any(|(name, _)| name == "pack-committer") {
                return Ok(calls.clone());
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "the named committer produced no PUT before the deadline: {calls:?}"
                ));
            }
            let (next, wait) = self.calls_changed.wait_timeout(calls, remaining).unwrap();
            calls = next;
            if wait.timed_out() && !calls.iter().any(|(name, _)| name == "pack-committer") {
                return Err(format!(
                    "the named committer produced no PUT before the deadline: {calls:?}"
                ));
            }
        }
    }
}

fn wait_for_generation(engine: &ChunkEngine, target: i64) {
    let deadline = std::time::Instant::now() + poll_bound();
    while engine.generation() < target {
        assert!(
            std::time::Instant::now() < deadline,
            "background publisher stopped at generation {} before target {target}",
            engine.generation()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

impl BlobStore for ThreadRecordingBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        let publisher = is_background_publisher_context();
        {
            let mut calls = self.put_calls.lock().unwrap();
            calls.push((
                std::thread::current()
                    .name()
                    .unwrap_or("<unnamed>")
                    .to_string(),
                publisher,
            ));
            self.calls_changed.notify_all();
        }
        // The controlled gate is exclusively a publisher delay. If a
        // regression sends a Guest FLUSH down this remote path, return a
        // bounded diagnostic instead of blocking the controller that owns the
        // release guard.
        if !publisher {
            return Err(cats_storage::blob::BlobError::Backend {
                key: key.to_string(),
                message: "test recorder rejected a Guest-context PUT".into(),
            });
        }
        if let Some(gate) = &self.put_gate {
            gate.block_until_released();
        }
        self.inner.put_immutable(key, data)
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.inner.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.inner.list(prefix)
    }
}

/// A slow remote store must stay wholly behind the named publisher while a
/// burst stages packs under the production-default admission caps. A
/// controlled PUT holds the publisher active while another Guest FLUSH must
/// finish, proving causal independence without a wall-clock performance cap.
#[test]
fn a_slow_store_burst_publishes_only_on_the_background_committer() {
    let dir = tempfile::tempdir().unwrap();
    let put_gate = Arc::new(PutGate::default());
    let blob = Arc::new(ThreadRecordingBlob {
        inner: Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap()),
        put_calls: Mutex::new(Vec::new()),
        calls_changed: Condvar::new(),
        put_gate: Some(Arc::clone(&put_gate)),
    });
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: 3_600_000,
    };
    assert_eq!(
        cfg.max_staged_packs, DEFAULT_MAX_STAGED_PACKS,
        "the burst must exercise the production-default pack cap"
    );
    assert_eq!(
        cfg.max_staged_bytes, DEFAULT_MAX_STAGED_BYTES,
        "the burst must exercise the production-default byte cap"
    );
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta).unwrap();

    std::thread::scope(|scope| {
        // If any assertion below unwinds, release the remote call before the
        // scope joins its FLUSH worker and before ChunkEngine joins committer.
        let _release = put_gate.release_on_drop();

        // Crossing the eager watermark starts a real publish under the
        // production-default admission caps.
        for i in 0..3u32 {
            e.write(i as u64 * CHUNK_SIZE as u64, &pattern(4096, i as u8))
                .unwrap();
            assert_eq!(e.flush().unwrap(), i as i64 + 1);
        }
        put_gate.wait_until_entered().unwrap();
        let calls = blob.put_calls.lock().unwrap().clone();
        assert!(
            !calls.is_empty() && calls.iter().all(|(_, publisher)| *publisher),
            "the controlled active PUT must belong to the publisher: {calls:?}"
        );

        e.write(3 * CHUNK_SIZE as u64, &pattern(4096, 3)).unwrap();
        let flush_engine = Arc::clone(&e);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let flush_worker = scope.spawn(move || {
            let _ = result_tx.send(flush_engine.flush());
        });

        // This is a structural liveness guard, not a latency requirement: the
        // publisher remains blocked until after the result is received. A
        // FLUSH that synchronously waits for it cannot satisfy this ordering.
        let generation = result_rx
            .recv_timeout(poll_bound())
            .expect("Relaxed FLUSH waited for the active background publisher")
            .unwrap();
        assert_eq!(generation, 4);

        // Keep forming the original burst while the publisher is still held.
        // It remains far below both production-default caps.
        for i in 4..24u32 {
            e.write((i as u64 % 8) * CHUNK_SIZE as u64, &pattern(4096, i as u8))
                .unwrap();
            assert_eq!(e.flush().unwrap(), i as i64 + 1);
        }

        put_gate.release();
        flush_worker.join().unwrap();
    });

    wait_for_generation(&e, 24);
    // After releasing the upload workers, calibrate the full publish path on
    // its named committer. A publisher=false call fails immediately.
    blob.wait_for_named_background_put().unwrap();
    e.detach().unwrap();
}

/// Known-negative calibration for the causal recorder. A Guest-side remote
/// PUT must fail without entering the publisher gate; the bounded result
/// channel, release guard, and scoped join keep this diagnostic deadlock-free
/// even if the gate discrimination regresses.
#[test]
fn guest_side_put_is_detected_and_the_controlled_store_is_released() {
    let dir = tempfile::tempdir().unwrap();
    let put_gate = Arc::new(PutGate::default());
    let blob = Arc::new(ThreadRecordingBlob {
        inner: Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap()),
        put_calls: Mutex::new(Vec::new()),
        calls_changed: Condvar::new(),
        put_gate: Some(Arc::clone(&put_gate)),
    });

    std::thread::scope(|scope| {
        let _release = put_gate.release_on_drop();
        let guest_blob = Arc::clone(&blob);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let guest_put = scope.spawn(move || {
            let _ = result_tx.send(guest_blob.put_immutable("guest-put", b"data"));
        });

        let put_error = result_rx
            .recv_timeout(poll_bound())
            .expect("Guest-context PUT blocked on the publisher gate")
            .unwrap_err();
        assert!(
            put_error
                .to_string()
                .contains("test recorder rejected a Guest-context PUT"),
            "known-negative produced the wrong BlobStore error: {put_error}"
        );
        assert!(
            !put_gate.was_entered(),
            "a Guest-context PUT must never enter the publisher gate"
        );
        let recorder_error = blob.wait_for_named_background_put().unwrap_err();
        assert!(
            recorder_error.contains("escaped the background publisher"),
            "known-negative produced the wrong recorder error: {recorder_error}"
        );

        put_gate.release();
        guest_put.join().unwrap();
    });
}

/// Once local admission is full, FLUSH may park, but only the named
/// background thread may touch the remote store. This is the structural
/// isolation that keeps a transient store error out of the Guest I/O path.
#[test]
fn backpressure_waits_for_the_background_publisher() {
    let dir = tempfile::tempdir().unwrap();
    let put_gate = Arc::new(PutGate::default());
    let blob = Arc::new(ThreadRecordingBlob {
        inner: Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap()),
        put_calls: Mutex::new(Vec::new()),
        calls_changed: Condvar::new(),
        put_gate: Some(Arc::clone(&put_gate)),
    });
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: 50,
    };
    cfg.max_staged_packs = 1;
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, blob.clone(), meta).unwrap();
    // Must outlive every blocking operation but drop before the engine, so a
    // panic cannot strand the committer while ChunkEngine joins it.
    let _release = put_gate.release_on_drop();

    e.write(0, &pattern(4096, 1)).unwrap();
    let first_engine = Arc::clone(&e);
    let first_flush = std::thread::spawn(move || first_engine.flush());
    put_gate.wait_until_entered().unwrap();
    blob.wait_for_named_background_put().unwrap();
    assert_eq!(first_flush.join().unwrap().unwrap(), 1);
    e.write(CHUNK_SIZE as u64, &pattern(4096, 2)).unwrap();
    let flush_engine = Arc::clone(&e);
    let second_flush = std::thread::spawn(move || flush_engine.flush());

    // Directly observe the staging-space waiter while the sole allowed pack
    // remains pinned behind the controlled remote call. This preserves the
    // admission-pressure assertion without measuring how long it waited.
    let deadline = std::time::Instant::now() + poll_bound();
    while e.backpressure_waiters.load(Ordering::Relaxed) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the second FLUSH never entered staging backpressure"
        );
        std::thread::yield_now();
    }
    put_gate.release();
    assert_eq!(second_flush.join().unwrap().unwrap(), 2);
    wait_for_generation(&e, 2);
    let calls = blob.put_calls.lock().unwrap().clone();
    assert!(!calls.is_empty());
    assert!(
        calls.iter().all(|(_, publisher)| *publisher),
        "remote PUT escaped the background publisher: {calls:?}"
    );
    e.detach().unwrap();
}

#[test]
fn provisioning_refuses_staged_commits() {
    let env = env();
    let e = attach_relaxed(&env, "attA");
    e.write(0, &pattern(4096, 3)).unwrap();
    e.flush().unwrap();
    let manifest = format::ImageManifest {
        version: 1,
        image_id: format::LowerHexSha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        size_bytes: SIZE,
        chunks: vec![],
    };
    let err = e.provision_from_image(&manifest).unwrap_err();
    assert!(
        err.to_string().contains("staged commits"),
        "unexpected error: {err}"
    );
    e.detach().unwrap();
}

#[test]
fn multi_generation_overwrites_read_latest() {
    let env = env();
    {
        let e = attach(&env, "attA");
        e.write(100, &pattern(4096, 1)).unwrap();
        e.flush().unwrap();
        e.write(100, &pattern(4096, 2)).unwrap();
        e.write(CHUNK_SIZE as u64 + 7, b"second-chunk").unwrap();
        assert_eq!(e.flush().unwrap(), 2);
        e.detach().unwrap();
    }
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach(&env, "attB");
    let mut b = vec![0u8; 4096];
    e.read(100, &mut b).unwrap();
    assert_eq!(b, pattern(4096, 2));
    let mut s = vec![0u8; 12];
    e.read(CHUNK_SIZE as u64 + 7, &mut s).unwrap();
    assert_eq!(&s, b"second-chunk");
    e.detach().unwrap();
}

/// Object-store reads slower than the lease TTL reproduce the 2026-07-29
/// production failure: attach outlived the TTL and used to self-fence.
#[test]
fn attach_slower_than_the_lease_ttl_does_not_self_fence() {
    let env = env();
    {
        let e = attach(&env, "attA");
        e.write(0, &pattern(CHUNK_SIZE as usize, 5)).unwrap();
        e.flush().unwrap();
        e.detach().unwrap();
    }
    // Cold host: the committed map must be read back through the store.
    fs::remove_dir_all(&env.data_dir).unwrap();
    let slow: Arc<dyn BlobStore> = Arc::new(
        SlowBlob::new(env.blob.clone()).with_get_delay(std::time::Duration::from_millis(150)),
    );
    let mut cfg = EngineConfig::new(VOL, &env.data_dir, "attB");
    cfg.lease_ttl_ms = 100;
    let epoch = install_test_grant_at(env._dir.path().join("meta.db"), "attB");
    let e = ChunkEngine::attach_granted_epoch(cfg, epoch, slow, env.meta.clone()).unwrap();
    // Outlive several renewal intervals to prove the thread keeps the
    // lease alive rather than the attach merely squeaking through.
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(!e.is_fenced(), "an uncontended lapse must not fence");
    e.write(100, b"still writable").unwrap();
    e.flush().unwrap();
    e.detach().unwrap();
}

fn sizing_env() -> (Env, Arc<SizingBlob>) {
    let env = env();
    let sizing = Arc::new(SizingBlob::new(env.blob.clone()));
    (env, sizing)
}

fn attach_with(env: &Env, blob: Arc<dyn BlobStore>, attachment: &str) -> Arc<ChunkEngine> {
    let epoch = install_test_grant_at(env._dir.path().join("meta.db"), attachment);
    ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, &env.data_dir, attachment),
        epoch,
        blob,
        env.meta.clone(),
    )
    .unwrap()
}

const PAGE: u64 = cats_api::chunk::DIRTY_PAGE_SIZE as u64;

/// A golden rootfs stand-in: distinct content per chunk, one all-zero chunk,
/// and a tail shorter than a chunk — the shapes a real image has.
fn golden_image(dir: &std::path::Path, chunks: u64) -> PathBuf {
    let path = dir.join(format!("golden-{chunks}.raw"));
    let mut f = File::create(&path).unwrap();
    for chunk in 0..chunks {
        let body = if chunk == 1 {
            vec![0u8; CHUNK_SIZE as usize]
        } else {
            pattern(CHUNK_SIZE as usize, chunk as u8 + 100)
        };
        f.write_all(&body).unwrap();
    }
    f.write_all(&pattern(4096, 42)).unwrap();
    f.sync_all().unwrap();
    path
}

#[test]
fn a_volume_provisioned_from_an_image_publishes_no_data_of_its_own() {
    let (env, sizing) = sizing_env();
    let image = golden_image(env.data_dir.parent().unwrap(), 3);
    let published = crate::image::publish(sizing.as_ref(), &image).unwrap();
    // Chunk 1 was all zeros, so the image stored 2 chunks plus the padded tail.
    assert_eq!(published.manifest.chunks.len(), 3);
    let image_cost = sizing.image_bytes();
    assert_eq!(image_cost, 3 * CHUNK_SIZE as u64);
    sizing.reset();

    let e = attach_with(&env, sizing.clone(), "attA");
    let gen = e.provision_from_image(&published.manifest).unwrap();
    assert_eq!(gen, 1);

    // This is the whole point: a Cat's private cost for its root disk is zero
    // data objects, only map nodes.
    assert_eq!(sizing.data_bytes(), 0);
    assert_eq!(sizing.data_objects(), 0);
    assert_eq!(sizing.image_bytes(), 0);

    // And a fresh host still reads the image content, chunk 1 as zeros and the
    // padded tail included.
    e.detach().unwrap();
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach_with(&env, sizing.clone(), "attB");
    assert_eq!(e.generation(), 1);
    let raw = fs::read(&image).unwrap();
    let mut got = vec![0u8; raw.len()];
    e.read(0, &mut got).unwrap();
    assert_eq!(got, raw);
    let mut tail = vec![0xffu8; CHUNK_SIZE as usize - 4096];
    e.read(3 * CHUNK_SIZE as u64 + 4096, &mut tail).unwrap();
    assert!(
        tail.iter().all(|b| *b == 0),
        "padding past the image reads as zeros"
    );
}

#[test]
fn writing_onto_a_provisioned_chunk_publishes_one_page_and_keeps_sharing_the_base() {
    let (env, sizing) = sizing_env();
    let image = golden_image(env.data_dir.parent().unwrap(), 3);
    let published = crate::image::publish(sizing.as_ref(), &image).unwrap();
    let e = attach_with(&env, sizing.clone(), "attA");
    e.provision_from_image(&published.manifest).unwrap();
    sizing.reset();

    // One 4 KiB write into a shared chunk.
    let patch = pattern(4096, 7);
    e.write(0, &patch).unwrap();
    assert_eq!(e.flush().unwrap(), 2);

    // Delta packs and image sharing compose: the Cat publishes the 64 KiB page
    // it dirtied, not a 4 MiB private copy of the shared chunk.
    assert_eq!(sizing.data_bytes(), PAGE);
    assert_eq!(sizing.image_bytes(), 0);
    {
        let st = e.state.lock().unwrap();
        // The base is still the image's object — sharing did not erode.
        assert_eq!(
            st.map[0].image(),
            Some(published.manifest.image_id.as_str())
        );
        assert_eq!(st.map[0].layer_count(), 1, "one delta over the shared base");
        // An untouched chunk is still a plain reference into the image.
        assert_eq!(
            st.map[2].image(),
            Some(published.manifest.image_id.as_str())
        );
        assert_eq!(st.map[2].layer_count(), 0);
    }

    // The write wins over the image on the page it touched, and the rest of the
    // chunk still comes from the image, reassembled on a host with no cache.
    e.detach().unwrap();
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach_with(&env, sizing.clone(), "attB");
    let raw = fs::read(&image).unwrap();
    let mut got = vec![0u8; CHUNK_SIZE as usize];
    e.read(0, &mut got).unwrap();
    assert_eq!(&got[..4096], &patch[..]);
    assert_eq!(&got[4096..], &raw[4096..CHUNK_SIZE as usize]);
}

#[test]
fn provisioning_refuses_to_run_over_a_volume_that_is_not_empty() {
    let env = env();
    let image = golden_image(env.data_dir.parent().unwrap(), 2);
    let published = crate::image::publish(env.blob.as_ref(), &image).unwrap();

    // Unflushed writes: the cache would disagree with the map being published.
    let e = attach(&env, "attA");
    e.write(0, &pattern(4096, 3)).unwrap();
    assert!(e.provision_from_image(&published.manifest).is_err());

    // Committed data: provisioning replaces the whole map, so this would be a
    // silent data loss rather than an error.
    e.flush().unwrap();
    assert!(e.provision_from_image(&published.manifest).is_err());
    let mut got = vec![0u8; 4096];
    e.read(0, &mut got).unwrap();
    assert_eq!(got, pattern(4096, 3));
}

#[test]
fn an_image_larger_than_the_volume_is_refused_rather_than_truncated() {
    let env = env(); // 8 chunks
    let big = golden_image(env.data_dir.parent().unwrap(), 16);
    let published = crate::image::publish(env.blob.as_ref(), &big).unwrap();
    let e = attach(&env, "attA");
    // Silently dropping the tail would give the Guest a corrupt rootfs.
    assert!(e.provision_from_image(&published.manifest).is_err());
    assert_eq!(e.generation(), 0);
}

#[test]
fn a_commit_uploads_its_objects_concurrently() {
    // A commit's objects have distinct keys and no ordering between them, so
    // uploading them one round trip at a time is pure latency. On S3 that was
    // ~33 ms per object and most of a commit.
    let env = env();
    let probe = Arc::new(ConcurrencyProbe::new(
        env.blob.clone(),
        Duration::from_millis(20),
    ));
    let e = attach_with(&env, probe.clone(), "attA");
    let page = vec![0x33u8; PAGE as usize];
    for chunk in 0..8u64 {
        e.write(chunk * CHUNK_SIZE as u64, &page).unwrap();
    }
    assert_eq!(e.flush().unwrap(), 1);

    assert_eq!(probe.data_put_count(), 8);
    // Peak concurrency, not wall clock: the whole suite runs in parallel, so a
    // latency bound here would measure the machine's load. Serial uploads peak
    // at exactly 1, which is the regression this catches.
    assert!(
        probe.peak() >= 2,
        "uploads ran one at a time (peak in flight {})",
        probe.peak()
    );
    assert_eq!(probe.in_flight(), 0, "a worker leaked");
    e.detach().unwrap();

    // The committed data is still readable from a cold cache, which is the
    // part concurrency could plausibly have broken.
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach_with(&env, probe.clone(), "attB");
    let mut back = vec![0u8; PAGE as usize];
    for chunk in 0..8u64 {
        e.read(chunk * CHUNK_SIZE as u64, &mut back).unwrap();
        assert_eq!(back, page, "chunk {chunk} came back wrong");
    }
    e.detach().unwrap();
}

#[test]
fn a_cold_read_fetches_its_chunks_and_layers_concurrently() {
    // Reads had the same shape of problem the commit path did: one blocking
    // GET per object, none overlapping. A cold 64 MiB read off S3 ran at
    // 73 MiB/s on a 12.5 Gbps instance because of it.
    let env = env();
    let probe = Arc::new(ConcurrencyProbe::new(
        env.blob.clone(),
        Duration::from_millis(20),
    ));

    // Four chunks with a base plus two deltas each: 12 objects to fetch.
    let e = attach_with(&env, probe.clone(), "attA");
    let whole = pattern(CHUNK_SIZE as usize, 5);
    for chunk in 0..4u64 {
        e.write(chunk * CHUNK_SIZE as u64, &whole).unwrap();
    }
    e.flush().unwrap();
    // Distinct pages per round, so the chain is genuinely two deltas deep: a
    // delta that fully rewrote the previous one would replace it instead.
    for round in 0..2u64 {
        for chunk in 0..4u64 {
            e.write(
                chunk * CHUNK_SIZE as u64 + round * PAGE,
                &pattern(4096, round as u8 + 20),
            )
            .unwrap();
        }
        e.flush().unwrap();
    }
    {
        let st = e.state.lock().unwrap();
        assert_eq!(st.map[0].layer_count(), 2, "expected a base plus 2 deltas");
    }
    e.detach().unwrap();

    // A brand-new host: every one of those objects has to come back.
    fs::remove_dir_all(&env.data_dir).unwrap();
    probe.reset_peak();
    let e = attach_with(&env, probe.clone(), "attB");
    let mut back = vec![0u8; 4 * CHUNK_SIZE as usize];
    e.read(0, &mut back).unwrap();

    assert!(
        probe.peak() >= 2,
        "cold read fetched one object at a time (peak in flight {})",
        probe.peak()
    );
    assert_eq!(probe.in_flight(), 0, "a fetch leaked");
    // Concurrency must not change what comes back: each round's write wins on
    // the page it touched, the base shows through everywhere else.
    for chunk in 0..4usize {
        let at = chunk * CHUNK_SIZE as usize;
        assert_eq!(
            &back[at..at + 4096],
            &pattern(4096, 20)[..],
            "chunk {chunk}"
        );
        let second = at + PAGE as usize;
        assert_eq!(&back[second..second + 4096], &pattern(4096, 21)[..]);
        assert_eq!(&back[at + 4096..second], &whole[4096..PAGE as usize]);
    }
    e.detach().unwrap();
}

#[test]
fn gc_keeps_every_layer_of_a_live_chain_and_drops_superseded_objects() {
    let (env, sizing) = sizing_env();
    let e = attach_with(&env, sizing.clone(), "attA");

    // Chunk 0: a base, then two deltas on different pages -- all three live.
    let whole = pattern(CHUNK_SIZE as usize, 4);
    e.write(0, &whole).unwrap();
    e.flush().unwrap();
    for round in 0..2u64 {
        e.write(round * PAGE, &pattern(4096, round as u8 + 30))
            .unwrap();
        e.flush().unwrap();
    }
    // Chunk 1: written twice densely, so the first base is superseded.
    e.write(CHUNK_SIZE as u64, &pattern(CHUNK_SIZE as usize, 6))
        .unwrap();
    e.flush().unwrap();
    e.write(CHUNK_SIZE as u64, &pattern(CHUNK_SIZE as usize, 7))
        .unwrap();
    e.flush().unwrap();

    let before = env.blob.list("volumes/vol_test/data/").unwrap().len();
    let stats = e.collect_garbage().unwrap();
    let after = env.blob.list("volumes/vol_test/data/").unwrap().len();

    // Live: chunk 0's base + 2 deltas, chunk 1's second base. Dead: chunk 1's
    // first base. A GC that only kept the newest object per chunk would have
    // deleted chunk 0's base and its first delta and corrupted the volume.
    assert_eq!(stats.data_objects_live, 4);
    assert_eq!(stats.data_objects_deleted, 1);
    assert_eq!(after, before - 1);
    assert!(
        stats.map_objects_deleted > 0,
        "superseded map nodes survived"
    );

    // The volume still reads correctly from a host with nothing cached.
    e.detach().unwrap();
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach_with(&env, sizing.clone(), "attB");
    let mut back = vec![0u8; CHUNK_SIZE as usize];
    e.read(0, &mut back).unwrap();
    assert_eq!(&back[..4096], &pattern(4096, 30)[..]);
    assert_eq!(
        &back[PAGE as usize..PAGE as usize + 4096],
        &pattern(4096, 31)[..]
    );
    assert_eq!(&back[4096..PAGE as usize], &whole[4096..PAGE as usize]);
    e.read(CHUNK_SIZE as u64, &mut back).unwrap();
    assert_eq!(back, pattern(CHUNK_SIZE as usize, 7));
    e.detach().unwrap();
}

#[test]
fn gc_never_deletes_a_shared_image_even_though_the_volume_references_it() {
    let (env, sizing) = sizing_env();
    let image = golden_image(env.data_dir.parent().unwrap(), 3);
    let published = crate::image::publish(sizing.as_ref(), &image).unwrap();
    let image_keys = env
        .blob
        .list(&format!("images/{}/", published.manifest.image_id))
        .unwrap();
    assert!(!image_keys.is_empty());

    let e = attach_with(&env, sizing.clone(), "attA");
    e.provision_from_image(&published.manifest).unwrap();
    // One page written onto a shared chunk: that delta is this volume's and
    // must survive; the image base underneath it is not ours to delete.
    e.write(0, &pattern(4096, 9)).unwrap();
    e.flush().unwrap();

    let stats = e.collect_garbage().unwrap();
    assert_eq!(
        stats.data_objects_live, 1,
        "only the volume's own delta is a volume object"
    );
    assert_eq!(stats.data_objects_deleted, 0);
    assert_eq!(
        env.blob
            .list(&format!("images/{}/", published.manifest.image_id))
            .unwrap(),
        image_keys,
        "GC touched the shared image"
    );

    // And the volume still reassembles from image base + local delta.
    e.detach().unwrap();
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach_with(&env, sizing.clone(), "attB");
    let raw = fs::read(&image).unwrap();
    let mut back = vec![0u8; CHUNK_SIZE as usize];
    e.read(0, &mut back).unwrap();
    assert_eq!(&back[..4096], &pattern(4096, 9)[..]);
    assert_eq!(&back[4096..], &raw[4096..CHUNK_SIZE as usize]);
    e.detach().unwrap();
}

#[test]
fn gc_on_an_untouched_volume_deletes_nothing() {
    let env = env();
    let e = attach(&env, "attA");
    e.write(0, &pattern(4096, 1)).unwrap();
    e.flush().unwrap();
    let first = e.collect_garbage().unwrap();
    assert_eq!(first.data_objects_deleted, 0);
    // Idempotent: a second pass finds nothing new.
    let second = e.collect_garbage().unwrap();
    assert_eq!(second, first);
    e.detach().unwrap();
}

#[test]
fn discarding_whole_chunks_frees_their_objects_instead_of_publishing_zeros() {
    let (env, sizing) = sizing_env();
    let e = attach_with(&env, sizing.clone(), "attA");
    let whole = pattern(CHUNK_SIZE as usize, 8);
    for chunk in 0..3u64 {
        e.write(chunk * CHUNK_SIZE as u64, &whole).unwrap();
    }
    assert_eq!(e.flush().unwrap(), 1);
    assert_eq!(sizing.data_bytes(), 3 * CHUNK_SIZE as u64);
    sizing.reset();

    // Discard chunks 1 and 2 in full.
    e.write_zeroes(CHUNK_SIZE as u64, 2 * CHUNK_SIZE as u64)
        .unwrap();
    assert_eq!(e.flush().unwrap(), 2);

    // Nothing was published for them: writing 8 MiB of zeros would have been
    // the old behaviour, and would also have kept the old objects alive.
    assert_eq!(sizing.data_bytes(), 0);
    {
        let st = e.state.lock().unwrap();
        assert!(matches!(st.map[0], ChunkRef::Base(_)), "chunk 0 untouched");
        assert!(matches!(st.map[1], ChunkRef::Hole));
        assert!(matches!(st.map[2], ChunkRef::Hole));
    }

    // And GC can now take what they used to reference.
    let stats = e.collect_garbage().unwrap();
    assert_eq!(stats.data_objects_live, 1);
    assert_eq!(stats.data_objects_deleted, 2);

    // The Guest sees zeros, from a host with nothing cached.
    e.detach().unwrap();
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach_with(&env, sizing.clone(), "attB");
    let mut back = vec![0xffu8; CHUNK_SIZE as usize];
    e.read(CHUNK_SIZE as u64, &mut back).unwrap();
    assert!(
        back.iter().all(|b| *b == 0),
        "discarded chunk must read zero"
    );
    e.read(0, &mut back).unwrap();
    assert_eq!(
        back, whole,
        "an untouched chunk must survive a neighbour's discard"
    );
    e.detach().unwrap();
}

#[test]
fn a_partial_discard_writes_zeros_and_a_later_write_cancels_a_discard() {
    let (env, sizing) = sizing_env();
    let e = attach_with(&env, sizing.clone(), "attA");
    let whole = pattern(CHUNK_SIZE as usize, 9);
    e.write(0, &whole).unwrap();
    e.flush().unwrap();
    sizing.reset();

    // Not chunk-aligned: only the covered pages are zeroed, and the chunk
    // stays a real object because most of it still holds data.
    e.write_zeroes(PAGE, PAGE).unwrap();
    e.flush().unwrap();
    assert_eq!(sizing.data_bytes(), PAGE);
    {
        let st = e.state.lock().unwrap();
        assert!(!matches!(st.map[0], ChunkRef::Hole));
    }
    let mut back = vec![0u8; CHUNK_SIZE as usize];
    e.read(0, &mut back).unwrap();
    assert_eq!(&back[..PAGE as usize], &whole[..PAGE as usize]);
    assert!(back[PAGE as usize..2 * PAGE as usize]
        .iter()
        .all(|b| *b == 0));

    // A write after a discard, before the commit, must win: the chunk is real
    // data again, not a hole.
    e.write_zeroes(0, CHUNK_SIZE as u64).unwrap();
    let patch = pattern(4096, 3);
    e.write(0, &patch).unwrap();
    e.flush().unwrap();
    {
        let st = e.state.lock().unwrap();
        assert!(
            !matches!(st.map[0], ChunkRef::Hole),
            "a write after a discard was lost"
        );
    }
    e.detach().unwrap();
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach_with(&env, sizing.clone(), "attB");
    let mut back = vec![0xffu8; CHUNK_SIZE as usize];
    e.read(0, &mut back).unwrap();
    assert_eq!(&back[..4096], &patch[..]);
    assert!(
        back[4096..].iter().all(|b| *b == 0),
        "the discard still applied"
    );
    e.detach().unwrap();
}

#[test]
fn a_sparse_write_publishes_only_its_dirty_pages() {
    let (env, sizing) = sizing_env();
    let e = attach_with(&env, sizing.clone(), "attA");
    // One 4 KiB write in each of three chunks: three dirty 64 KiB pages, not
    // three 4 MiB chunks.
    for chunk in 0..3u64 {
        e.write(chunk * CHUNK_SIZE as u64, &pattern(4096, chunk as u8 + 1))
            .unwrap();
    }
    assert_eq!(e.flush().unwrap(), 1);

    assert_eq!(
        sizing.data_bytes(),
        3 * PAGE,
        "a commit must publish dirty pages, not whole chunks"
    );
    assert_eq!(sizing.data_objects(), 3);
    let st = e.state.lock().unwrap();
    for chunk in 0..3usize {
        match &st.map[chunk] {
            ChunkRef::Layered { base, deltas } => {
                assert!(base.is_none(), "chunk {chunk} had no committed base yet");
                assert_eq!(deltas.len(), 1);
                assert_eq!(deltas[0].page_mask, 1, "only the first page is dirty");
            }
            other => panic!("chunk {chunk} should be layered, got {other:?}"),
        }
    }
    drop(st);
    e.detach().unwrap();
}

#[test]
fn a_dense_write_publishes_a_full_base() {
    let (env, sizing) = sizing_env();
    let e = attach_with(&env, sizing.clone(), "attA");
    // More than half the chunk: a delta would save little and resetting the
    // chain is worth more than the bytes.
    e.write(0, &pattern(CHUNK_SIZE as usize / 2 + 1, 3))
        .unwrap();
    e.flush().unwrap();
    assert_eq!(
        sizing.data_bytes(),
        CHUNK_SIZE as u64,
        "a dense write should publish one full chunk"
    );
    let st = e.state.lock().unwrap();
    assert!(matches!(st.map[0], ChunkRef::Base(_)));
    drop(st);
    e.detach().unwrap();
}

#[test]
fn delta_chains_are_capped_by_a_base_rewrite() {
    let (env, sizing) = sizing_env();
    let e = attach_with(&env, sizing.clone(), "attA");
    // Each commit dirties one page of chunk 0, so each adds a layer until the
    // cap forces a fresh base.
    for round in 0..=MAX_DELTA_LAYERS {
        e.write(round as u64 * PAGE, &pattern(4096, round as u8))
            .unwrap();
        e.flush().unwrap();
        let st = e.state.lock().unwrap();
        let layers = st.map[0].layer_count();
        if round < MAX_DELTA_LAYERS {
            assert_eq!(layers, round + 1, "round {round} should add a layer");
        } else {
            assert_eq!(
                layers, 0,
                "the commit past the cap must publish a fresh base instead"
            );
            assert!(matches!(st.map[0], ChunkRef::Base(_)));
        }
    }
    // Cheap for the first four commits, one full chunk for the rewrite.
    assert_eq!(
        sizing.data_bytes(),
        MAX_DELTA_LAYERS as u64 * PAGE + CHUNK_SIZE as u64
    );
    e.detach().unwrap();
}

#[test]
fn layered_chunks_reassemble_after_the_cache_is_wiped() {
    let env = env();
    let e = attach(&env, "attA");
    // Build a chunk out of a base plus several deltas on different pages,
    // including one page written twice so a later delta has to win.
    e.write(0, &pattern(CHUNK_SIZE as usize, 9)).unwrap(); // dense -> base
    e.flush().unwrap();
    let mut expected = pattern(CHUNK_SIZE as usize, 9);
    for (round, page) in [1u64, 5, 5, 63].into_iter().enumerate() {
        let data = pattern(4096, 100 + round as u8);
        e.write(page * PAGE, &data).unwrap();
        expected[(page * PAGE) as usize..(page * PAGE) as usize + data.len()]
            .copy_from_slice(&data);
        e.flush().unwrap();
    }
    {
        let st = e.state.lock().unwrap();
        assert!(
            st.map[0].layer_count() > 1,
            "the chunk should be layered for this test to mean anything"
        );
    }
    e.detach().unwrap();

    // Fresh host, empty cache: everything has to come back from the objects.
    let restored = attach_at(&env, "attB", "data-host-b");
    let mut got = vec![0u8; CHUNK_SIZE as usize];
    restored.read(0, &mut got).unwrap();
    assert_eq!(got, expected, "layered reassembly must be byte-exact");
    restored.detach().unwrap();
}

#[test]
fn hole_reads_do_not_touch_the_blobstore() {
    let env = env();
    {
        let e = attach(&env, "attA");
        e.write(0, &pattern(4096, 5)).unwrap();
        e.flush().unwrap();
        e.detach().unwrap();
    }
    fs::remove_dir_all(&env.data_dir).unwrap();
    let counting = Arc::new(CountingBlob::new(env.blob.clone()));
    let epoch = install_test_grant_at(env._dir.path().join("meta.db"), "attB");
    let e = ChunkEngine::attach_granted_epoch(
        EngineConfig::new(VOL, &env.data_dir, "attB"),
        epoch,
        counting.clone(),
        env.meta.clone(),
    )
    .unwrap();
    let after_attach = counting.get_count(); // root + leaf loads
    let mut z = vec![1u8; 4096];
    e.read(6 * CHUNK_SIZE as u64, &mut z).unwrap();
    assert!(z.iter().all(|&b| b == 0));
    assert_eq!(counting.get_count(), after_attach, "hole read must not GET");
    // Reading committed data hydrates exactly once.
    let mut b = vec![0u8; 4096];
    e.read(0, &mut b).unwrap();
    e.read(0, &mut b).unwrap();
    assert_eq!(counting.get_count(), after_attach + 1);
    e.detach().unwrap();
}

#[test]
fn stale_writer_is_fenced_and_cannot_commit() {
    let env = env();
    let e1 = attach(&env, "attA");
    e1.write(0, &pattern(1024, 1)).unwrap();
    // Control plane fences the volume (host presumed lost).
    release_current_test_grant(env.meta.as_ref());
    let err = e1.flush().unwrap_err();
    assert!(
        matches!(err, EngineError::Meta(_)),
        "flush must fail after revoke: {err}"
    );
    assert!(e1.is_fenced());
    assert!(matches!(e1.write(0, b"x"), Err(EngineError::Fenced)));
    // The new attachment lands on a fresh host and takes over from the
    // last committed state (the fenced writer's un-acked flush is gone).
    let e2 = attach_at(&env, "attB", "data-host-b");
    assert_eq!(e2.generation(), 0);
    e2.write(0, &pattern(1024, 2)).unwrap();
    assert_eq!(e2.flush().unwrap(), 1);
    e2.detach().unwrap();
    assert!(matches!(e1.detach(), Err(EngineError::Fenced)));
}

#[test]
fn failed_upload_leaves_pack_and_recovery_replays_it() {
    use cats_storage::blob::FaultyBlobStore;
    let env = env();
    let faulty = Arc::new(FaultyBlobStore::new(env.blob.clone()));
    let data = pattern(2048, 7);
    {
        let e = ChunkEngine::attach_granted_epoch(
            EngineConfig::new(VOL, &env.data_dir, "attA"),
            env.initial_epoch,
            faulty.clone(),
            env.meta.clone(),
        )
        .unwrap();
        e.write(0, &data).unwrap();
        faulty.fail_puts.store(1, Ordering::SeqCst);
        assert!(e.flush().is_err());
        // Pack file remains for recovery.
        let pending: Vec<_> = fs::read_dir(env.data_dir.join("pending"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(pending.len(), 1);
        e.detach().unwrap();
    }
    // Reattach with a healthy store: recovery replays the pack.
    let e = attach(&env, "attB");
    assert_eq!(e.generation(), 1, "recovery must replay the pending pack");
    assert!(fs::read_dir(env.data_dir.join("pending"))
        .unwrap()
        .next()
        .is_none());
    let mut b = vec![0u8; 2048];
    e.read(0, &mut b).unwrap();
    assert_eq!(b, data);
    // And the replayed state survives a cache wipe.
    e.detach().unwrap();
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach(&env, "attC");
    let mut b = vec![0u8; 2048];
    e.read(0, &mut b).unwrap();
    assert_eq!(b, data);
    e.detach().unwrap();
}

#[test]
fn write_zeroes_marks_dirty_and_commits_zeros() {
    let env = env();
    {
        let e = attach(&env, "attA");
        e.write(0, &pattern(8192, 1)).unwrap();
        e.flush().unwrap();
        e.write_zeroes(0, 8192).unwrap();
        e.flush().unwrap();
        e.detach().unwrap();
    }
    fs::remove_dir_all(&env.data_dir).unwrap();
    let e = attach(&env, "attB");
    let mut b = vec![1u8; 8192];
    e.read(0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 0));
    e.detach().unwrap();
}

#[test]
fn detaching_does_not_wait_out_the_lease_renewal_interval() {
    // A stop, a suspend and a cold migration all detach. Joining a thread that
    // is sleeping out ttl/3 put that whole interval on the critical path of
    // every one of them, per volume.
    let env = env();
    let epoch = install_test_grant_at(env._dir.path().join("meta.db"), "attDetach");
    let e = ChunkEngine::attach_granted_epoch(
        EngineConfig {
            volume_id: VOL.into(),
            data_dir: env.data_dir.clone(),
            attachment_id: "attDetach".into(),
            lease_ttl_ms: 6_000,
            durability: DurabilityMode::Strict,
            max_staged_bytes: DEFAULT_MAX_STAGED_BYTES,
            max_staged_packs: DEFAULT_MAX_STAGED_PACKS,
            max_local_bytes: DEFAULT_MAX_LOCAL_BYTES,
        },
        epoch,
        env.blob.clone(),
        env.meta.clone(),
    )
    .unwrap();
    let started = std::time::Instant::now();
    e.detach().unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "detach waited {elapsed:?} on a 6 s lease (renewal interval is 2 s)"
    );
    // And the lease really was released: the next attachment gets it at once.
    let next = attach(&env, "attDetach2");
    assert!(next.epoch() > e.epoch());
    next.detach().unwrap();
}

#[test]
fn snapshot_captures_generation() {
    let env = env();
    let e = attach(&env, "attA");
    e.write(0, &pattern(512, 1)).unwrap();
    e.flush().unwrap();
    let snap = env.meta.create_snapshot("snap_1", VOL).unwrap();
    assert_eq!(snap.generation, 1);
    e.detach().unwrap();
}

struct RootProvisionFixture {
    engine: Arc<ChunkEngine>,
    blob: Arc<FileBlobStore>,
    meta: Arc<CountingMeta>,
    manifest: format::ImageManifest,
    request: cats_api::runtime_reconciliation::ProvisionRootImageRequest,
    data_dir: PathBuf,
    _dir: tempfile::TempDir,
}

struct ImageValidationCountingBlob {
    inner: Arc<dyn BlobStore>,
    image_data_gets: AtomicU64,
    image_data_exists: AtomicU64,
    image_data_exists_in_flight: AtomicU64,
    image_data_exists_peak: AtomicU64,
}

impl ImageValidationCountingBlob {
    fn is_image_data(key: &str) -> bool {
        key.starts_with("images/") && key.contains("/data/")
    }
}

impl BlobStore for ImageValidationCountingBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        self.inner.put_immutable(key, data)
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        if Self::is_image_data(key) {
            self.image_data_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        if Self::is_image_data(key) {
            self.image_data_exists.fetch_add(1, Ordering::SeqCst);
            let in_flight = self
                .image_data_exists_in_flight
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            self.image_data_exists_peak
                .fetch_max(in_flight, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            let result = self.inner.exists(key);
            self.image_data_exists_in_flight
                .fetch_sub(1, Ordering::SeqCst);
            return result;
        }
        self.inner.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.inner.list(prefix)
    }
}

struct LocalCacheProvisionFixture {
    _dir: tempfile::TempDir,
    source_image: PathBuf,
    cache_image: PathBuf,
    manifest: format::ImageManifest,
    engine: Arc<ChunkEngine>,
    blob: Arc<ImageValidationCountingBlob>,
    request: cats_api::runtime_reconciliation::ProvisionRootImageRequest,
}

fn local_cache_provision_fixture() -> LocalCacheProvisionFixture {
    local_cache_provision_fixture_with_source(|seed| {
        for byte in [211, 37, 89, 151] {
            seed.write_all(&pattern(CHUNK_SIZE as usize, byte)).unwrap();
        }
    })
}

fn local_cache_provision_fixture_with_source(
    write_source: impl FnOnce(&mut File),
) -> LocalCacheProvisionFixture {
    let dir = tempfile::tempdir().unwrap();
    let inner = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let source_image = dir.path().join("source-root.img");
    let mut seed = File::create(&source_image).unwrap();
    write_source(&mut seed);
    seed.sync_all().unwrap();
    let manifest = crate::image::publish(inner.as_ref(), &source_image)
        .unwrap()
        .manifest;
    let cache_directory = dir.path().join("golden-root-cache");
    fs::create_dir(&cache_directory).unwrap();
    let cache_image = cache_directory.join("rootfs.ext4");
    let blob = Arc::new(ImageValidationCountingBlob {
        inner,
        image_data_gets: AtomicU64::new(0),
        image_data_exists: AtomicU64::new(0),
        image_data_exists_in_flight: AtomicU64::new(0),
        image_data_exists_peak: AtomicU64::new(0),
    });
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let epoch = install_test_grant_at(dir.path().join("meta.db"), "attA");
    let engine = ChunkEngine::attach_control_only(
        EngineConfig::new(VOL, dir.path().join("control-data"), "attA"),
        epoch,
        blob.clone(),
        target_authority(meta),
    )
    .unwrap();
    let request = root_provision_request(
        &engine,
        &manifest,
        epoch,
        "2468ace013579bdf2468ace013579bdf",
    );
    LocalCacheProvisionFixture {
        _dir: dir,
        source_image,
        cache_image,
        manifest,
        engine,
        blob,
        request,
    }
}

#[test]
fn a_cold_local_cache_is_filled_and_the_replay_gets_no_remote_image_data() {
    let fixture = local_cache_provision_fixture();

    fixture
        .engine
        .provision_root_image_with_local_cache(&fixture.request, &fixture.cache_image)
        .unwrap();

    assert_eq!(fixture.blob.image_data_gets.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.blob.image_data_exists.load(Ordering::SeqCst), 0);
    let (cached_image_id, cached_manifest, _) = crate::image::scan(&fixture.cache_image).unwrap();
    assert_eq!(cached_image_id, fixture.manifest.image_id.as_str());
    assert_eq!(cached_manifest, fixture.manifest);

    fixture.blob.image_data_gets.store(0, Ordering::SeqCst);
    fixture.blob.image_data_exists.store(0, Ordering::SeqCst);
    fixture
        .blob
        .image_data_exists_peak
        .store(0, Ordering::SeqCst);
    fixture
        .engine
        .provision_root_image_with_local_cache(&fixture.request, &fixture.cache_image)
        .unwrap();

    assert_eq!(fixture.blob.image_data_gets.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.blob.image_data_exists.load(Ordering::SeqCst), 4);
    assert!(
        fixture.blob.image_data_exists_peak.load(Ordering::SeqCst) > 1,
        "remote object existence checks must overlap"
    );
}

#[test]
fn a_nonmatching_local_cache_is_replaced_after_remote_body_validation() {
    let fixture = local_cache_provision_fixture();
    fs::write(&fixture.cache_image, pattern(CHUNK_SIZE as usize, 99)).unwrap();

    fixture
        .engine
        .provision_root_image_with_local_cache(&fixture.request, &fixture.cache_image)
        .unwrap();

    assert_eq!(fixture.blob.image_data_gets.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.blob.image_data_exists.load(Ordering::SeqCst), 0);
    let (cached_image_id, cached_manifest, _) = crate::image::scan(&fixture.cache_image).unwrap();
    assert_eq!(cached_image_id, fixture.manifest.image_id.as_str());
    assert_eq!(cached_manifest, fixture.manifest);
}

#[test]
fn an_exact_local_cache_cannot_publish_a_map_when_a_remote_object_is_missing() {
    let fixture = local_cache_provision_fixture();
    fs::copy(&fixture.source_image, &fixture.cache_image).unwrap();
    let missing = fixture
        .blob
        .list("images/")
        .unwrap()
        .into_iter()
        .find(|key| ImageValidationCountingBlob::is_image_data(key))
        .unwrap();
    fixture.blob.delete(&missing).unwrap();

    assert_retryable_problem(
        fixture
            .engine
            .provision_root_image_with_local_cache(&fixture.request, &fixture.cache_image)
            .unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageRetryableProblem::ImageUnavailable,
    );
    assert!(volume_objects(fixture.blob.as_ref()).is_empty());
}

#[test]
fn an_unwritable_local_cache_does_not_weaken_remote_body_provision() {
    let fixture = local_cache_provision_fixture();
    let non_directory = fixture._dir.path().join("not-a-directory");
    fs::write(&non_directory, b"file").unwrap();
    let unavailable_cache = non_directory.join("rootfs.ext4");

    fixture
        .engine
        .provision_root_image_with_local_cache(&fixture.request, &unavailable_cache)
        .unwrap();

    assert_eq!(fixture.blob.image_data_gets.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.blob.image_data_exists.load(Ordering::SeqCst), 0);
}

#[test]
fn an_unaligned_image_is_validated_but_not_published_as_a_different_cache_file() {
    let fixture = local_cache_provision_fixture_with_source(|source| {
        source.write_all(&pattern(4_096, 73)).unwrap();
    });

    fixture
        .engine
        .provision_root_image_with_local_cache(&fixture.request, &fixture.cache_image)
        .unwrap();

    assert_eq!(fixture.blob.image_data_gets.load(Ordering::SeqCst), 1);
    assert!(!fixture.cache_image.exists());
    assert!(!volume_objects(fixture.blob.as_ref()).is_empty());
}

#[test]
fn cache_fill_reconstructs_duplicate_chunks_and_sparse_holes() {
    let fixture = local_cache_provision_fixture_with_source(|source| {
        let repeated = pattern(CHUNK_SIZE as usize, 41);
        source.write_all(&repeated).unwrap();
        source.write_all(&vec![0_u8; CHUNK_SIZE as usize]).unwrap();
        source.write_all(&repeated).unwrap();
    });

    fixture
        .engine
        .provision_root_image_with_local_cache(&fixture.request, &fixture.cache_image)
        .unwrap();

    assert_eq!(fixture.blob.image_data_gets.load(Ordering::SeqCst), 1);
    let (cached_image_id, cached_manifest, _) = crate::image::scan(&fixture.cache_image).unwrap();
    assert_eq!(cached_image_id, fixture.manifest.image_id.as_str());
    assert_eq!(cached_manifest, fixture.manifest);
}

fn root_provision_request(
    engine: &ChunkEngine,
    manifest: &format::ImageManifest,
    epoch: i64,
    transition: &str,
) -> cats_api::runtime_reconciliation::ProvisionRootImageRequest {
    let map = format::image_base_map(manifest, SIZE).unwrap();
    let chunks: Vec<u64> = manifest
        .chunks
        .iter()
        .map(|chunk| chunk.chunk_idx)
        .collect();
    let leaves = vec![LeafRef::Empty; chunk::leaf_count(SIZE) as usize];
    let prepared = engine.prepare_map_publication(0, &map, &leaves, &chunks);
    cats_api::runtime_reconciliation::ProvisionRootImageRequest {
        provision_transition_id: cats_api::runtime_reconciliation::RandomId128::new(transition)
            .unwrap(),
        volume_id: cats_api::runtime_reconciliation::Id::new(VOL).unwrap(),
        attachment_id: cats_api::runtime_reconciliation::Id::new("attA").unwrap(),
        attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(epoch as u64).unwrap(),
        size_bytes: SIZE,
        boot_image_digest: cats_api::runtime_reconciliation::Sha256Digest::new(format!(
            "sha256:{}",
            manifest.image_id
        ))
        .unwrap(),
        expected_blank_head: cats_api::runtime_reconciliation::RemoteHead {
            generation: cats_api::runtime_reconciliation::Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        },
        expected_provisioned_head: cats_api::runtime_reconciliation::RemoteHead {
            generation: cats_api::runtime_reconciliation::Generation::new(1).unwrap(),
            root_hash: Some(cats_api::runtime_reconciliation::Sha256Digest::from_bytes(
                prepared.root_hash,
            )),
            root_object_id: Some(
                cats_api::runtime_reconciliation::AsciiText::new(prepared.root_object_id).unwrap(),
            ),
        },
    }
}

fn root_provision_fixture() -> RootProvisionFixture {
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let inner: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    let meta = Arc::new(CountingMeta {
        inner,
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: None,
    });
    meta.create_volume(VOL, SIZE).unwrap();
    install_test_grant_at(dir.path().join("meta.db"), "attA");

    let image_path = dir.path().join("root.img");
    let mut image_file = File::create(&image_path).unwrap();
    image_file
        .write_all(&pattern(CHUNK_SIZE as usize, 211))
        .unwrap();
    image_file.sync_all().unwrap();
    let manifest = crate::image::publish(blob.as_ref(), &image_path)
        .unwrap()
        .manifest;

    let epoch = 1;
    let data_dir = dir.path().join("control-data");
    let engine = ChunkEngine::attach_control_only(
        EngineConfig::new(VOL, &data_dir, "attA"),
        epoch,
        blob.clone(),
        target_authority(meta.clone()),
    )
    .unwrap();
    let request = root_provision_request(
        &engine,
        &manifest,
        epoch,
        "13579bdf2468ace013579bdf2468ace0",
    );
    RootProvisionFixture {
        engine,
        blob,
        meta,
        manifest,
        request,
        data_dir,
        _dir: dir,
    }
}

fn assert_definite_problem(
    error: ProvisionRootImageEffectError,
    expected: cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem,
) {
    assert!(
        matches!(
            &error,
            ProvisionRootImageEffectError::Closed(
                cats_api::runtime_reconciliation::ProvisionRootImageError::DefiniteConflict {
                    problem,
                    ..
                }
            ) if *problem == expected
        ),
        "expected definite conflict {expected:?}, got {error:?}"
    );
}

fn assert_retryable_problem(
    error: ProvisionRootImageEffectError,
    expected: cats_api::runtime_reconciliation::ProvisionRootImageRetryableProblem,
) {
    assert!(
        matches!(
            &error,
            ProvisionRootImageEffectError::Closed(
                cats_api::runtime_reconciliation::ProvisionRootImageError::Retryable {
                    problem,
                    ..
                }
            ) if *problem == expected
        ),
        "expected retryable {expected:?}, got {error:?}"
    );
}

fn volume_objects(blob: &dyn BlobStore) -> Vec<String> {
    blob.list(&format!("volumes/{VOL}/")).unwrap()
}

struct LostPutResponseBlob {
    inner: Arc<dyn BlobStore>,
    fail_key: Mutex<Option<String>>,
    lost_responses: AtomicU64,
}

impl BlobStore for LostPutResponseBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> cats_storage::blob::Result<()> {
        self.inner.put_immutable(key, data)?;
        let mut fail_key = self.fail_key.lock().unwrap();
        if fail_key.as_deref() == Some(key) {
            fail_key.take();
            self.lost_responses.fetch_add(1, Ordering::SeqCst);
            return Err(BlobError::Backend {
                key: key.into(),
                message: "injected lost immutable PUT response".into(),
            });
        }
        Ok(())
    }

    fn get(&self, key: &str) -> cats_storage::blob::Result<Vec<u8>> {
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> cats_storage::blob::Result<bool> {
        self.inner.exists(key)
    }

    fn delete(&self, key: &str) -> cats_storage::blob::Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> cats_storage::blob::Result<Vec<String>> {
        self.inner.list(prefix)
    }
}

#[test]
fn typed_root_provision_is_exact_idempotent_and_never_enables_guest_io() {
    let fixture = root_provision_fixture();
    assert!(matches!(
        fixture.engine.read(0, &mut [0_u8; 1]),
        Err(EngineError::GuestIoDisabled)
    ));
    assert!(matches!(
        fixture.engine.write(0, &[1]),
        Err(EngineError::GuestIoDisabled)
    ));
    assert!(matches!(
        fixture.engine.flush(),
        Err(EngineError::GuestIoDisabled)
    ));
    assert!(matches!(
        fixture.engine.provision_from_image(&fixture.manifest),
        Err(EngineError::GuestIoDisabled)
    ));

    let result = fixture
        .engine
        .provision_root_image(&fixture.request)
        .unwrap();
    assert_eq!(
        result.resulting_head,
        fixture.request.expected_provisioned_head
    );
    assert_eq!(fixture.meta.cas_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.engine.state.lock().unwrap().remote_head.clone(),
        fixture.request.expected_provisioned_head,
        "engine state must retain the complete target rather than generation alone"
    );
    let head = fixture.meta.load_head(VOL).unwrap();
    assert_eq!(head.generation, 1);
    assert_eq!(
        head.root_hash,
        fixture
            .request
            .expected_provisioned_head
            .root_hash
            .as_ref()
            .map(|digest| *digest.as_bytes())
    );

    let record_key =
        chunk::keys::commit_record(VOL, 1, fixture.request.provision_transition_id.as_str());
    let record = fixture.blob.get(&record_key).unwrap();
    let expected_record = super::publish::encode_commit_record(
        fixture.request.provision_transition_id.as_str(),
        1,
        fixture.engine.epoch(),
        &hex::encode(head.root_hash.unwrap()),
        &[0],
    );
    assert_eq!(record, expected_record);

    let replay = fixture
        .engine
        .provision_root_image(&fixture.request)
        .unwrap();
    assert_eq!(replay, result);
    assert_eq!(
        fixture.meta.cas_calls.load(Ordering::SeqCst),
        1,
        "an exact target replay must not issue a second CAS"
    );
}

#[test]
fn request_binding_and_target_conflicts_have_zero_remote_side_effects() {
    let fixture = root_provision_fixture();
    let before_objects = volume_objects(fixture.blob.as_ref());
    let before_cas = fixture.meta.cas_calls.load(Ordering::SeqCst);

    let mut cases = Vec::new();
    let mut wrong = fixture.request.clone();
    wrong.volume_id = cats_api::runtime_reconciliation::Id::new("other-volume").unwrap();
    cases.push((
        wrong,
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::RequestBinding,
    ));
    let mut wrong = fixture.request.clone();
    wrong.attachment_id = cats_api::runtime_reconciliation::Id::new("other-owner").unwrap();
    cases.push((
        wrong,
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::RequestBinding,
    ));
    let mut wrong = fixture.request.clone();
    wrong.attachment_epoch = cats_api::runtime_reconciliation::FenceEpoch::new(
        fixture.request.attachment_epoch.get() + 1,
    )
    .unwrap();
    cases.push((
        wrong,
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::RequestBinding,
    ));
    let mut wrong = fixture.request.clone();
    wrong.size_bytes += CHUNK_SIZE as u64;
    cases.push((
        wrong,
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::RequestBinding,
    ));
    let mut wrong = fixture.request.clone();
    wrong.expected_blank_head.generation =
        cats_api::runtime_reconciliation::Generation::new(1).unwrap();
    wrong.expected_blank_head.root_hash = Some(
        cats_api::runtime_reconciliation::Sha256Digest::from_bytes([3; 32]),
    );
    wrong.expected_blank_head.root_object_id =
        Some(cats_api::runtime_reconciliation::AsciiText::new("bad.node").unwrap());
    cases.push((
        wrong,
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::TargetMismatch,
    ));
    let mut wrong = fixture.request.clone();
    wrong.expected_provisioned_head.root_hash = Some(
        cats_api::runtime_reconciliation::Sha256Digest::from_bytes([4; 32]),
    );
    cases.push((
        wrong,
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::TargetMismatch,
    ));

    for (request, expected) in cases {
        assert_definite_problem(
            fixture.engine.provision_root_image(&request).unwrap_err(),
            expected,
        );
    }
    assert_eq!(volume_objects(fixture.blob.as_ref()), before_objects);
    assert_eq!(fixture.meta.cas_calls.load(Ordering::SeqCst), before_cas);
}

#[test]
fn dirty_pending_and_staged_local_state_fail_before_remote_writes() {
    let fixture = root_provision_fixture();
    let before_objects = volume_objects(fixture.blob.as_ref());
    let before_cas = fixture.meta.cas_calls.load(Ordering::SeqCst);

    fixture.engine.state.lock().unwrap().dirty[0] = 1;
    assert_definite_problem(
        fixture
            .engine
            .provision_root_image(&fixture.request)
            .unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::LocalState,
    );
    fixture.engine.state.lock().unwrap().dirty[0] = 0;

    fs::write(
        fixture.data_dir.join(PENDING_PACK_DIR).join("residue.pack"),
        b"x",
    )
    .unwrap();
    assert_definite_problem(
        fixture
            .engine
            .provision_root_image(&fixture.request)
            .unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::LocalState,
    );
    fs::remove_file(fixture.data_dir.join(PENDING_PACK_DIR).join("residue.pack")).unwrap();

    fixture.engine.staged.lock().unwrap().bytes = 1;
    assert_definite_problem(
        fixture
            .engine
            .provision_root_image(&fixture.request)
            .unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::LocalState,
    );
    fixture.engine.staged.lock().unwrap().bytes = 0;
    fixture
        .engine
        .inflight_staging_bytes
        .store(1, Ordering::SeqCst);
    assert_definite_problem(
        fixture
            .engine
            .provision_root_image(&fixture.request)
            .unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::LocalState,
    );
    fixture
        .engine
        .inflight_staging_bytes
        .store(0, Ordering::SeqCst);

    assert_eq!(volume_objects(fixture.blob.as_ref()), before_objects);
    assert_eq!(fixture.meta.cas_calls.load(Ordering::SeqCst), before_cas);
}

#[test]
fn control_only_attach_preserves_and_refuses_legacy_pending_state() {
    let env = env();
    let image_path = env.data_dir.parent().unwrap().join("pending-root.img");
    fs::write(&image_path, pattern(CHUNK_SIZE as usize, 81)).unwrap();
    let manifest = crate::image::publish(env.blob.as_ref(), &image_path)
        .unwrap()
        .manifest;
    let epoch;
    {
        let legacy = attach_relaxed(&env, "attA");
        epoch = legacy.epoch();
        legacy.write(0, b"legacy unpublished bytes").unwrap();
        assert_eq!(legacy.flush().unwrap(), 1);
        assert_eq!(legacy.generation(), 0);
    }
    assert_eq!(
        fs::read_dir(env.data_dir.join(PENDING_PACK_DIR))
            .unwrap()
            .count(),
        1
    );

    let control = ChunkEngine::attach_control_only(
        EngineConfig::new(VOL, &env.data_dir, "attA"),
        epoch,
        env.blob.clone(),
        target_authority(env.meta.clone()),
    )
    .unwrap();
    assert!(
        control.staged.lock().unwrap().packs.is_empty(),
        "control-only attach must not recover the legacy journal into a publisher queue"
    );
    let request = root_provision_request(
        &control,
        &manifest,
        epoch,
        "fedcba9876543210fedcba9876543210",
    );
    assert_definite_problem(
        control.provision_root_image(&request).unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::LocalState,
    );
    assert_eq!(env.meta.load_head(VOL).unwrap().generation, 0);
    assert!(volume_objects(env.blob.as_ref()).is_empty());
}

#[test]
fn control_only_attach_rejects_an_owned_zero_epoch_authority_row() {
    let dir = tempfile::tempdir().unwrap();
    let blob: Arc<dyn BlobStore> = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let sqlite = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    sqlite.create_volume(VOL, SIZE).unwrap();
    cats_test_support::install_sqlite_grant(&dir.path().join("meta.db"), VOL, "attA", 1).unwrap();
    let inner: Arc<dyn MetadataStore> = sqlite;
    let granted_epoch = 1;
    assert!(granted_epoch > 0);
    let corrupt: Arc<dyn MetadataStore> = Arc::new(CountingMeta {
        inner,
        cas_calls: AtomicU64::new(0),
        forced_head_epoch: Some(0),
    });
    let data_dir = dir.path().join("control-data");

    let result = ChunkEngine::attach_control_only(
        EngineConfig::new(VOL, &data_dir, "attA"),
        granted_epoch,
        blob.clone(),
        target_authority(corrupt.clone()),
    );
    assert!(matches!(result, Err(EngineError::Corrupt(_))));
    assert!(
        !data_dir.exists(),
        "a corrupt authority row must fail before local state is created"
    );

    let result = ChunkEngine::attach_control_only(
        EngineConfig::new(VOL, &data_dir, "attA"),
        0,
        blob,
        target_authority(corrupt),
    );
    assert!(matches!(result, Err(EngineError::InvalidConfig(_))));
    assert!(!data_dir.exists());
}

#[test]
fn control_only_local_initialization_replays_every_crash_window_without_overwrite() {
    for crash_window in [
        "cache_before_sync",
        "cache_after_sync",
        "bitmap_before_sync",
        "bitmap_after_link",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let blob: Arc<dyn BlobStore> =
            Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let sqlite = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        sqlite.create_volume(VOL, SIZE).unwrap();
        cats_test_support::install_sqlite_grant(&dir.path().join("meta.db"), VOL, "attA", 1)
            .unwrap();
        let meta: Arc<dyn MetadataStore> = sqlite;
        let epoch = 1;
        let data_dir = dir.path().join("control-data");
        fs::create_dir_all(&data_dir).unwrap();

        match crash_window {
            "cache_before_sync" => {
                // Crash after creating the initialization file but before the
                // sparse cache reached its immutable volume length.
                fs::write(data_dir.join(".cache.data.init"), b"partial").unwrap();
            }
            "cache_after_sync" => {
                let cache = File::create(data_dir.join(".cache.data.init")).unwrap();
                cache.set_len(SIZE).unwrap();
                cache.sync_all().unwrap();
            }
            "bitmap_before_sync" | "bitmap_after_link" => {
                // The cache was fully installed, then bitmap initialization
                // started. Its marker proves replay never replaces a valid
                // final file while repairing the other item.
                let cache = File::create(data_dir.join("cache.data")).unwrap();
                cache.set_len(SIZE).unwrap();
                cache.write_all_at(b"keep", 0).unwrap();
                cache.sync_all().unwrap();
                let bitmap_temp = data_dir.join(".dirty.bitmap.init");
                if crash_window == "bitmap_before_sync" {
                    fs::write(bitmap_temp, b"partial").unwrap();
                } else {
                    let bitmap = File::create(&bitmap_temp).unwrap();
                    bitmap
                        .write_all_at(&format::encode_bitmap_header(chunk::chunk_count(SIZE)), 0)
                        .unwrap();
                    bitmap
                        .set_len(BITMAP_HEADER_LEN + chunk::chunk_count(SIZE) * 8)
                        .unwrap();
                    bitmap
                        .write_all_at(&0x55aa_u64.to_le_bytes(), BITMAP_HEADER_LEN)
                        .unwrap();
                    bitmap.sync_all().unwrap();
                    fs::hard_link(bitmap_temp, data_dir.join("dirty.bitmap")).unwrap();
                }
            }
            _ => unreachable!(),
        }

        let engine = ChunkEngine::attach_control_only(
            EngineConfig::new(VOL, &data_dir, "attA"),
            epoch,
            blob,
            target_authority(meta),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(data_dir.join("cache.data")).unwrap().len(),
            SIZE
        );
        assert_eq!(
            fs::metadata(data_dir.join("dirty.bitmap")).unwrap().len(),
            BITMAP_HEADER_LEN + chunk::chunk_count(SIZE) * 8
        );
        assert!(!data_dir.join(".cache.data.init").exists());
        assert!(!data_dir.join(".dirty.bitmap.init").exists());
        if crash_window.starts_with("bitmap_") {
            let cache = File::open(data_dir.join("cache.data")).unwrap();
            let mut marker = [0_u8; 4];
            cache.read_exact_at(&mut marker, 0).unwrap();
            assert_eq!(&marker, b"keep", "a valid final cache was overwritten");
        }
        if crash_window == "bitmap_after_link" {
            assert_eq!(engine.state.lock().unwrap().dirty[0], 0x55aa);
            let bitmap = File::open(data_dir.join("dirty.bitmap")).unwrap();
            let mut word = [0_u8; 8];
            bitmap.read_exact_at(&mut word, BITMAP_HEADER_LEN).unwrap();
            assert_eq!(u64::from_le_bytes(word), 0x55aa);
        }
        drop(engine);
    }
}

#[test]
fn invalid_manifest_corpus_is_rejected_before_any_volume_object_or_cas() {
    let fixture = root_provision_fixture();
    let before_objects = volume_objects(fixture.blob.as_ref());
    let before_cas = fixture.meta.cas_calls.load(Ordering::SeqCst);
    let valid_object = fixture.manifest.chunks[0].object_id.as_str();
    let invalid_manifests = vec![
        serde_json::json!({"version":2,"image_id":"","size_bytes":CHUNK_SIZE,"chunks":[]}),
        serde_json::json!({"version":1,"image_id":"","size_bytes":0,"chunks":[]}),
        serde_json::json!({"version":1,"image_id":"","size_bytes":CHUNK_SIZE,"chunks":[
            {"chunk_idx":0,"object_id":valid_object,"len":CHUNK_SIZE},
            {"chunk_idx":0,"object_id":valid_object,"len":CHUNK_SIZE}
        ]}),
        serde_json::json!({"version":1,"image_id":"","size_bytes":2*CHUNK_SIZE as u64,"chunks":[
            {"chunk_idx":1,"object_id":valid_object,"len":CHUNK_SIZE},
            {"chunk_idx":0,"object_id":valid_object,"len":CHUNK_SIZE}
        ]}),
        serde_json::json!({"version":1,"image_id":"","size_bytes":CHUNK_SIZE,"chunks":[
            {"chunk_idx":1,"object_id":valid_object,"len":CHUNK_SIZE}
        ]}),
        serde_json::json!({"version":1,"image_id":"","size_bytes":CHUNK_SIZE,"chunks":[
            {"chunk_idx":0,"object_id":valid_object,"len":1}
        ]}),
        serde_json::json!({"version":1,"image_id":"","size_bytes":CHUNK_SIZE,"chunks":[
            {"chunk_idx":0,"object_id":"ABCDEF","len":CHUNK_SIZE}
        ]}),
    ];

    for (index, mut manifest) in invalid_manifests.into_iter().enumerate() {
        let image_id = format!("{index:064x}");
        manifest["image_id"] = serde_json::Value::String(image_id.clone());
        fixture
            .blob
            .put_immutable(
                &chunk::keys::image_manifest(&image_id),
                &serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
        let mut request = fixture.request.clone();
        request.boot_image_digest =
            cats_api::runtime_reconciliation::Sha256Digest::new(format!("sha256:{image_id}"))
                .unwrap();
        let error = fixture.engine.provision_root_image(&request).unwrap_err();
        assert!(
            matches!(
                &error,
                ProvisionRootImageEffectError::Closed(
                    cats_api::runtime_reconciliation::ProvisionRootImageError::DefiniteConflict {
                        problem: cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::ImageManifest,
                        ..
                    }
                )
            ),
            "invalid manifest case {index} produced {error:?}"
        );
    }

    let mismatch_id = format!("{:064x}", 99);
    let mismatch_object = "1111111111111111111111111111111111111111111111111111111111111111";
    fixture
        .blob
        .put_immutable(
            &chunk::keys::image_data(&mismatch_id, mismatch_object),
            &vec![7; CHUNK_SIZE as usize],
        )
        .unwrap();
    let mismatch = serde_json::json!({
        "version":1,"image_id":mismatch_id,"size_bytes":CHUNK_SIZE,
        "chunks":[{"chunk_idx":0,"object_id":mismatch_object,"len":CHUNK_SIZE}]
    });
    fixture
        .blob
        .put_immutable(
            &chunk::keys::image_manifest(&mismatch_id),
            &serde_json::to_vec(&mismatch).unwrap(),
        )
        .unwrap();
    let mut request = fixture.request.clone();
    request.boot_image_digest =
        cats_api::runtime_reconciliation::Sha256Digest::new(format!("sha256:{mismatch_id}"))
            .unwrap();
    assert_definite_problem(
        fixture.engine.provision_root_image(&request).unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::ImageManifest,
    );

    assert_eq!(volume_objects(fixture.blob.as_ref()), before_objects);
    assert_eq!(fixture.meta.cas_calls.load(Ordering::SeqCst), before_cas);
}

#[test]
fn missing_image_and_changed_owner_never_publish_volume_objects() {
    let fixture = root_provision_fixture();
    let before_objects = volume_objects(fixture.blob.as_ref());
    let before_cas = fixture.meta.cas_calls.load(Ordering::SeqCst);
    let mut missing = fixture.request.clone();
    missing.boot_image_digest =
        cats_api::runtime_reconciliation::Sha256Digest::from_bytes([0xee; 32]);
    assert_retryable_problem(
        fixture.engine.provision_root_image(&missing).unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageRetryableProblem::ImageUnavailable,
    );
    assert_eq!(volume_objects(fixture.blob.as_ref()), before_objects);
    assert_eq!(fixture.meta.cas_calls.load(Ordering::SeqCst), before_cas);

    release_current_test_grant(fixture.meta.as_ref());
    assert!(matches!(
        fixture.engine.provision_root_image(&fixture.request),
        Err(ProvisionRootImageEffectError::ResultUnknown(_))
    ));
    assert_eq!(volume_objects(fixture.blob.as_ref()), before_objects);
    assert_eq!(fixture.meta.cas_calls.load(Ordering::SeqCst), before_cas);
}

#[test]
fn a_lost_generation_one_cas_response_is_adopted_from_exact_authority() {
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let sqlite = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    sqlite.create_volume(VOL, SIZE).unwrap();
    cats_test_support::install_sqlite_grant(&dir.path().join("meta.db"), VOL, "attA", 1).unwrap();
    let inner: Arc<dyn MetadataStore> = sqlite;
    let image_path = dir.path().join("root.img");
    fs::write(&image_path, pattern(CHUNK_SIZE as usize, 57)).unwrap();
    let manifest = crate::image::publish(blob.as_ref(), &image_path)
        .unwrap()
        .manifest;
    let epoch = 1;
    let meta = Arc::new(LostCasResponseMeta {
        inner,
        fault: Mutex::new(Some(CasFault::ResponseLost)),
        fail_next_load: AtomicBool::new(false),
        forced_head_size: AtomicU64::new(0),
        cas_calls: AtomicU64::new(0),
    });
    let engine = ChunkEngine::attach_control_only(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        epoch,
        blob,
        target_authority(meta.clone()),
    )
    .unwrap();
    let map = format::image_base_map(&manifest, SIZE).unwrap();
    let chunks: Vec<u64> = manifest
        .chunks
        .iter()
        .map(|chunk| chunk.chunk_idx)
        .collect();
    let prepared = engine.prepare_map_publication(
        0,
        &map,
        &vec![LeafRef::Empty; chunk::leaf_count(SIZE) as usize],
        &chunks,
    );
    let request = cats_api::runtime_reconciliation::ProvisionRootImageRequest {
        provision_transition_id: cats_api::runtime_reconciliation::RandomId128::new(
            "2468ace013579bdf2468ace013579bdf",
        )
        .unwrap(),
        volume_id: cats_api::runtime_reconciliation::Id::new(VOL).unwrap(),
        attachment_id: cats_api::runtime_reconciliation::Id::new("attA").unwrap(),
        attachment_epoch: cats_api::runtime_reconciliation::FenceEpoch::new(epoch as u64).unwrap(),
        size_bytes: SIZE,
        boot_image_digest: cats_api::runtime_reconciliation::Sha256Digest::new(format!(
            "sha256:{}",
            manifest.image_id
        ))
        .unwrap(),
        expected_blank_head: cats_api::runtime_reconciliation::RemoteHead {
            generation: cats_api::runtime_reconciliation::Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        },
        expected_provisioned_head: cats_api::runtime_reconciliation::RemoteHead {
            generation: cats_api::runtime_reconciliation::Generation::new(1).unwrap(),
            root_hash: Some(cats_api::runtime_reconciliation::Sha256Digest::from_bytes(
                prepared.root_hash,
            )),
            root_object_id: Some(
                cats_api::runtime_reconciliation::AsciiText::new(prepared.root_object_id).unwrap(),
            ),
        },
    };
    let result = engine.provision_root_image(&request).unwrap();
    assert_eq!(result.resulting_head, request.expected_provisioned_head);
    assert_eq!(meta.load_head(VOL).unwrap().generation, 1);
}

#[test]
fn lost_leaf_root_and_commit_put_responses_reconcile_by_exact_bytes() {
    for stage in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let inner_blob: Arc<dyn BlobStore> =
            Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
        let image_path = dir.path().join("root.img");
        fs::write(&image_path, pattern(CHUNK_SIZE as usize, stage + 31)).unwrap();
        let manifest = crate::image::publish(inner_blob.as_ref(), &image_path)
            .unwrap()
            .manifest;
        let blob = Arc::new(LostPutResponseBlob {
            inner: inner_blob,
            fail_key: Mutex::new(None),
            lost_responses: AtomicU64::new(0),
        });
        let sqlite = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        sqlite.create_volume(VOL, SIZE).unwrap();
        cats_test_support::install_sqlite_grant(&dir.path().join("meta.db"), VOL, "attA", 1)
            .unwrap();
        let meta: Arc<dyn MetadataStore> = sqlite;
        let epoch = 1;
        let engine = ChunkEngine::attach_control_only(
            EngineConfig::new(VOL, dir.path().join("data"), "attA"),
            epoch,
            blob.clone(),
            target_authority(meta.clone()),
        )
        .unwrap();
        let request = root_provision_request(
            &engine,
            &manifest,
            epoch,
            "abcdef0123456789abcdef0123456789",
        );
        let map = format::image_base_map(&manifest, SIZE).unwrap();
        let chunks: Vec<u64> = manifest
            .chunks
            .iter()
            .map(|chunk| chunk.chunk_idx)
            .collect();
        let prepared = engine.prepare_map_publication(
            0,
            &map,
            &vec![LeafRef::Empty; chunk::leaf_count(SIZE) as usize],
            &chunks,
        );
        let fail_key = match stage {
            0 => chunk::keys::map_node(VOL, &hex::encode(prepared.leaf_nodes[0].0)),
            1 => chunk::keys::map_node(VOL, &hex::encode(prepared.root_hash)),
            _ => chunk::keys::commit_record(VOL, 1, request.provision_transition_id.as_str()),
        };
        *blob.fail_key.lock().unwrap() = Some(fail_key);

        let result = engine.provision_root_image(&request).unwrap();
        assert_eq!(result.resulting_head, request.expected_provisioned_head);
        assert_eq!(blob.lost_responses.load(Ordering::SeqCst), 1);
        assert_eq!(meta.load_head(VOL).unwrap().generation, 1);
    }
}

#[test]
fn immutable_key_conflict_and_unrelated_head_fail_closed_without_cas() {
    let fixture = root_provision_fixture();
    let map = format::image_base_map(&fixture.manifest, SIZE).unwrap();
    let chunks: Vec<u64> = fixture
        .manifest
        .chunks
        .iter()
        .map(|chunk| chunk.chunk_idx)
        .collect();
    let prepared = fixture.engine.prepare_map_publication(
        0,
        &map,
        &vec![LeafRef::Empty; chunk::leaf_count(SIZE) as usize],
        &chunks,
    );
    let leaf_key = chunk::keys::map_node(VOL, &hex::encode(prepared.leaf_nodes[0].0));
    fixture
        .blob
        .put_immutable(&leaf_key, b"wrong bytes")
        .unwrap();
    let before_cas = fixture.meta.cas_calls.load(Ordering::SeqCst);
    assert_definite_problem(
        fixture
            .engine
            .provision_root_image(&fixture.request)
            .unwrap_err(),
        cats_api::runtime_reconciliation::ProvisionRootImageDefiniteConflictProblem::ImmutableObject,
    );
    assert_eq!(fixture.meta.cas_calls.load(Ordering::SeqCst), before_cas);

    let other = root_provision_fixture();
    other
        .meta
        .cas_head(
            VOL,
            0,
            1,
            [0xa5; 32],
            "unrelated.node",
            "attA",
            other.engine.epoch(),
        )
        .unwrap();
    let before_objects = volume_objects(other.blob.as_ref());
    let before_cas = other.meta.cas_calls.load(Ordering::SeqCst);
    assert!(matches!(
        other.engine.provision_root_image(&other.request),
        Err(ProvisionRootImageEffectError::ResultUnknown(_))
    ));
    assert_eq!(volume_objects(other.blob.as_ref()), before_objects);
    assert_eq!(other.meta.cas_calls.load(Ordering::SeqCst), before_cas);
}
