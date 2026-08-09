use super::*;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_file::FileBlobStore;
use cats_test_support::blob_doubles::{
    ConcurrencyProbe, CountingBlob, SizingBlob, SlowBlob, SwitchableFailureBlob,
};
use std::sync::atomic::AtomicU64;

struct Env {
    _dir: tempfile::TempDir,
    blob: Arc<dyn BlobStore>,
    meta: Arc<dyn MetadataStore>,
    data_dir: PathBuf,
}

const VOL: &str = "vol_test";
const SIZE: u64 = 8 * CHUNK_SIZE as u64; // 32 MiB logical

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let data_dir = dir.path().join("data");
    Env {
        _dir: dir,
        blob,
        meta,
        data_dir,
    }
}

fn attach(env: &Env, attachment: &str) -> Arc<ChunkEngine> {
    ChunkEngine::attach(
        EngineConfig::new(VOL, &env.data_dir, attachment),
        env.blob.clone(),
        env.meta.clone(),
    )
    .unwrap()
}

/// Attach on a different "host" (fresh data dir).
fn attach_at(env: &Env, attachment: &str, dir: &str) -> Arc<ChunkEngine> {
    ChunkEngine::attach(
        EngineConfig::new(VOL, env.data_dir.parent().unwrap().join(dir), attachment),
        env.blob.clone(),
        env.meta.clone(),
    )
    .unwrap()
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
    let mut cfg = EngineConfig::new(VOL, &env.data_dir, attachment);
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    ChunkEngine::attach(cfg, env.blob.clone(), env.meta.clone()).unwrap()
}

#[test]
fn relaxed_flush_acks_locally_and_the_drain_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let counting = Arc::new(CountingBlob::new(Arc::new(
        FileBlobStore::open(dir.path().join("blob")).unwrap(),
    )));
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach(cfg, counting.clone(), meta).unwrap();

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
fn relaxed_restart_rebuilds_the_local_watermark_without_remote_writes() {
    use cats_storage::blob::FaultyBlobStore;

    let dir = tempfile::tempdir().unwrap();
    let healthy: Arc<dyn BlobStore> =
        Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let faulty = Arc::new(FaultyBlobStore::new(healthy.clone()));
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    meta.create_volume(VOL, SIZE).unwrap();
    let data_dir = dir.path().join("data");

    {
        let mut cfg = EngineConfig::new(VOL, &data_dir, "attA");
        cfg.durability = DurabilityMode::Relaxed {
            drain_interval_ms: NO_TIMER,
        };
        let e = ChunkEngine::attach(cfg, healthy.clone(), meta.clone()).unwrap();
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
    let e = ChunkEngine::attach(cfg, faulty.clone(), meta).unwrap();
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
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: 50,
    };
    let e = ChunkEngine::attach(cfg, faulty, meta).unwrap();

    e.write(0, &pattern(4096, 9)).unwrap();
    assert_eq!(
        e.flush().unwrap(),
        1,
        "remote failure must not become Guest EIO"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
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
    let original = pattern(CHUNK_SIZE as usize, 71);
    {
        let e = ChunkEngine::attach(
            EngineConfig::new(VOL, dir.path().join("seed"), "seed"),
            healthy.clone(),
            meta.clone(),
        )
        .unwrap();
        e.write(0, &original).unwrap();
        e.flush().unwrap();
        e.detach().unwrap();
    }

    let switched = Arc::new(SwitchableFailureBlob::new(healthy.clone()));
    let mut cfg = EngineConfig::new(VOL, dir.path().join("relaxed"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach(cfg, switched.clone(), meta.clone()).unwrap();
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
    let restored = ChunkEngine::attach(
        EngineConfig::new(VOL, dir.path().join("restored"), "attB"),
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
    let original = pattern(CHUNK_SIZE as usize, 81);
    {
        let seed = ChunkEngine::attach(
            EngineConfig::new(VOL, dir.path().join("seed"), "seed"),
            blob.clone(),
            meta.clone(),
        )
        .unwrap();
        seed.write(0, &original).unwrap();
        seed.flush().unwrap();
        seed.detach().unwrap();
    }

    let mut cfg = EngineConfig::new(VOL, dir.path().join("relaxed"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    // The first tiny pack fits. The second overlay is larger than this cap,
    // so it may enter only after the first pack drains; that holds it
    // deterministically in the freeze-to-journal interval.
    cfg.max_staged_bytes = 1 << 20;
    let e = ChunkEngine::attach(cfg, blob, meta).unwrap();
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
    let deadline = Instant::now() + Duration::from_secs(2);
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
        .recv_timeout(Duration::from_secs(5))
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
    let e = ChunkEngine::attach(cfg, env.blob.clone(), env.meta.clone()).unwrap();
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
    let e = ChunkEngine::attach(cfg, env.blob.clone(), env.meta.clone()).unwrap();
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
    rx.recv_timeout(Duration::from_secs(5))
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
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data-a"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach(cfg, faulty.clone(), meta.clone()).unwrap();
    e.write(0, &pattern(4096, 4)).unwrap();
    e.flush().unwrap();

    faulty.fail_puts.store(u64::MAX, Ordering::SeqCst);
    assert!(e.detach().is_err(), "the mandatory drain must fail closed");
    assert_eq!(e.durability_status().unpublished_generations, 1);
    let competitor = ChunkEngine::attach(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
        healthy.clone(),
        meta.clone(),
    );
    assert!(matches!(
        competitor,
        Err(EngineError::Meta(MetaError::LeaseHeld))
    ));

    faulty.fail_puts.store(0, Ordering::SeqCst);
    e.detach().unwrap();
    let next = ChunkEngine::attach(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
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
    ResponseLost,
    ResponseLostAndFirstReconciliationFails,
    ResponseLostThenLeaseRevoked,
    ResponseLostThenGenerationAdvanced,
    UnrelatedRootPublished,
    ExplicitFenced,
}

struct LostCasResponseMeta {
    inner: Arc<dyn MetadataStore>,
    fault: Mutex<Option<CasFault>>,
    fail_next_load: AtomicBool,
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
        self.inner.load_head(v)
    }
    fn delete_volume(&self, v: &str) -> cats_storage::metadata::Result<()> {
        self.inner.delete_volume(v)
    }
    fn resize_volume(&self, v: &str, s: u64) -> cats_storage::metadata::Result<()> {
        self.inner.resize_volume(v, s)
    }
    fn acquire_lease(&self, v: &str, a: &str, ttl: i64) -> cats_storage::metadata::Result<i64> {
        self.inner.acquire_lease(v, a, ttl)
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
    fn revoke_lease(&self, v: &str) -> cats_storage::metadata::Result<()> {
        self.inner.revoke_lease(v)
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
        let fault = self.fault.lock().unwrap().take();
        match fault {
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
                CasFault::ResponseLostThenLeaseRevoked => self.inner.revoke_lease(v)?,
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
                CasFault::UnrelatedRootPublished | CasFault::ExplicitFenced => unreachable!(),
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
    fn resize_volume(&self, v: &str, s: u64) -> cats_storage::metadata::Result<()> {
        self.inner.resize_volume(v, s)
    }
    fn acquire_lease(&self, v: &str, a: &str, ttl: i64) -> cats_storage::metadata::Result<i64> {
        self.inner.acquire_lease(v, a, ttl)
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
    fn revoke_lease(&self, v: &str) -> cats_storage::metadata::Result<()> {
        self.inner.revoke_lease(v)
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
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: NO_TIMER,
    };
    let e = ChunkEngine::attach(cfg, blob.clone(), meta.clone()).unwrap();

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
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data-b"), "attB");
    cfg.durability = DurabilityMode::Strict;
    let e = ChunkEngine::attach(cfg, blob, meta).unwrap();
    assert_eq!(e.generation(), 5);
    for i in 0..5u8 {
        let mut back = vec![0u8; 4096];
        e.read(i as u64 * CHUNK_SIZE as u64, &mut back).unwrap();
        assert_eq!(back, pattern(4096, i + 1), "chunk {i}");
    }
    e.detach().unwrap();
}

#[test]
fn committed_cas_with_a_lost_response_is_reconciled_without_fencing() {
    let dir = tempfile::tempdir().unwrap();
    let blob: Arc<dyn BlobStore> = Arc::new(FileBlobStore::open(dir.path().join("blob")).unwrap());
    let inner: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    inner.create_volume(VOL, SIZE).unwrap();
    let meta = Arc::new(LostCasResponseMeta {
        inner,
        fault: Mutex::new(Some(CasFault::ResponseLost)),
        fail_next_load: AtomicBool::new(false),
    });
    let data_dir = dir.path().join("data-a");
    let e = ChunkEngine::attach(
        EngineConfig::new(VOL, &data_dir, "attA"),
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

    let restored = ChunkEngine::attach(
        EngineConfig::new(VOL, dir.path().join("data-b"), "attB"),
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
    let meta = fault_meta(dir, fault);
    let engine = ChunkEngine::attach(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        blob,
        meta,
    )
    .unwrap();
    engine.write(0, &pattern(4096, byte)).unwrap();
    engine
}

fn fault_meta(dir: &tempfile::TempDir, fault: CasFault) -> Arc<LostCasResponseMeta> {
    let inner: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    inner.create_volume(VOL, SIZE).unwrap();
    Arc::new(LostCasResponseMeta {
        inner,
        fault: Mutex::new(Some(fault)),
        fail_next_load: AtomicBool::new(false),
    })
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
    let e = ChunkEngine::attach(cfg, env.blob.clone(), env.meta.clone()).unwrap();
    for i in 0..8u8 {
        e.write(i as u64 * CHUNK_SIZE as u64, &pattern(4096, i + 1))
            .unwrap();
        e.flush().unwrap();
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
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
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
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
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
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
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
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
    let e = ChunkEngine::attach(cfg, blob.clone(), meta).unwrap();

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
            .recv_timeout(Duration::from_secs(10))
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
            .recv_timeout(Duration::from_secs(10))
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
    let mut cfg = EngineConfig::new(VOL, dir.path().join("data"), "attA");
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: 50,
    };
    cfg.max_staged_packs = 1;
    let e = ChunkEngine::attach(cfg, blob.clone(), meta).unwrap();
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
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
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
        image_id: "0123456789abcdef0123456789abcdef".into(),
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
    let e = ChunkEngine::attach(cfg, slow, env.meta.clone()).unwrap();
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
    ChunkEngine::attach(
        EngineConfig::new(VOL, &env.data_dir, attachment),
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
    assert!(stats.map_nodes_deleted > 0, "superseded map nodes survived");

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
fn the_gc_thread_sweeps_on_its_own_and_does_not_delay_detach() {
    let env = env();
    let e = attach(&env, "attA");
    // Two dense generations of one chunk: the first object becomes garbage.
    e.write(0, &pattern(CHUNK_SIZE as usize, 1)).unwrap();
    e.flush().unwrap();
    e.write(0, &pattern(CHUNK_SIZE as usize, 2)).unwrap();
    e.flush().unwrap();
    assert_eq!(env.blob.list("volumes/vol_test/data/").unwrap().len(), 2);

    e.start_gc_thread(Duration::from_millis(50));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while env.blob.list("volumes/vol_test/data/").unwrap().len() > 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "gc thread never swept"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // And it must not hold up a stop, the way lease renewal used to.
    let started = std::time::Instant::now();
    e.detach().unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "detach waited {:?} on the gc thread",
        started.elapsed()
    );
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
    let e = ChunkEngine::attach(
        EngineConfig::new(VOL, &env.data_dir, "attB"),
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
    env.meta.revoke_lease(VOL).unwrap();
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
        let e = ChunkEngine::attach(
            EngineConfig::new(VOL, &env.data_dir, "attA"),
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
    let e = ChunkEngine::attach(
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

fn root_provision_request(
    engine: &ChunkEngine,
    manifest: &format::ImageManifest,
    epoch: i64,
    transition: &str,
) -> cats_api::runtime_reconciliation::ProvisionRootImageRequest {
    let map = manifest.base_map(SIZE).unwrap();
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

    let image_path = dir.path().join("root.img");
    let mut image_file = File::create(&image_path).unwrap();
    image_file
        .write_all(&pattern(CHUNK_SIZE as usize, 211))
        .unwrap();
    image_file.sync_all().unwrap();
    let manifest = crate::image::publish(blob.as_ref(), &image_path)
        .unwrap()
        .manifest;

    let epoch = meta.acquire_lease(VOL, "attA", 60_000).unwrap();
    let data_dir = dir.path().join("control-data");
    let engine = ChunkEngine::attach_control_only(
        EngineConfig::new(VOL, &data_dir, "attA"),
        epoch,
        blob.clone(),
        meta.clone(),
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
        env.meta.clone(),
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
    let inner: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    inner.create_volume(VOL, SIZE).unwrap();
    let granted_epoch = inner.acquire_lease(VOL, "attA", 60_000).unwrap();
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
        corrupt.clone(),
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
        corrupt,
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
        let meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let epoch = meta.acquire_lease(VOL, "attA", 60_000).unwrap();
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
            meta,
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
    let valid_object = &fixture.manifest.chunks[0].object_id;
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

    fixture.meta.revoke_lease(VOL).unwrap();
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
    let inner: Arc<dyn MetadataStore> =
        Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
    inner.create_volume(VOL, SIZE).unwrap();
    let image_path = dir.path().join("root.img");
    fs::write(&image_path, pattern(CHUNK_SIZE as usize, 57)).unwrap();
    let manifest = crate::image::publish(blob.as_ref(), &image_path)
        .unwrap()
        .manifest;
    let epoch = inner.acquire_lease(VOL, "attA", 60_000).unwrap();
    let meta = Arc::new(LostCasResponseMeta {
        inner,
        fault: Mutex::new(Some(CasFault::ResponseLost)),
        fail_next_load: AtomicBool::new(false),
    });
    let engine = ChunkEngine::attach_control_only(
        EngineConfig::new(VOL, dir.path().join("data"), "attA"),
        epoch,
        blob,
        meta.clone(),
    )
    .unwrap();
    let map = manifest.base_map(SIZE).unwrap();
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
        let meta: Arc<dyn MetadataStore> =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).unwrap());
        meta.create_volume(VOL, SIZE).unwrap();
        let epoch = meta.acquire_lease(VOL, "attA", 60_000).unwrap();
        let engine = ChunkEngine::attach_control_only(
            EngineConfig::new(VOL, dir.path().join("data"), "attA"),
            epoch,
            blob.clone(),
            meta.clone(),
        )
        .unwrap();
        let request = root_provision_request(
            &engine,
            &manifest,
            epoch,
            "abcdef0123456789abcdef0123456789",
        );
        let map = manifest.base_map(SIZE).unwrap();
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
    let map = fixture.manifest.base_map(SIZE).unwrap();
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
