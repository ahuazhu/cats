//! What a FLUSH actually spends its time on.
//!
//! Guest workloads on real hardware stall for hundreds of milliseconds per FLUSH
//! (evidence: experiments/vhost-user-blk-frontend-20260726). A commit publishes
//! the dirty 64 KiB pages of each dirty chunk, so the cost scales with what the
//! Guest wrote — except when a chunk is written densely or its delta chain is
//! full, where the commit publishes a fresh 4 MiB base instead. This measures
//! both shapes.
//!
//! Ignored by default; run with
//! `cargo test --release -p cats-blockd --test commit_cost -- --ignored --nocapture`.

use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cats_blockd::engine::{ChunkEngine, DurabilityMode, EngineConfig};
use cats_blockd::format;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_object_store_file::FileBlobStore;
use cats_storage::blob::{BlobStore, Result as BlobResult};
use cats_storage::{open_blob_store, AdapterConfig, BlobStoreFactory, MetadataStore};

const CHUNK: u64 = cats_api::chunk::CHUNK_SIZE as u64;
const PAGE: u64 = cats_api::chunk::DIRTY_PAGE_SIZE as u64;
const MIB: f64 = 1024.0 * 1024.0;

/// Counts the bytes a commit actually publishes, which is the number the flush
/// cost should track.
struct SizingBlob {
    inner: Arc<dyn BlobStore>,
    data_bytes: AtomicU64,
}

impl BlobStore for SizingBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> BlobResult<()> {
        if key.contains("/data/") {
            self.data_bytes
                .fetch_add(data.len() as u64, Ordering::SeqCst);
        }
        self.inner.put_immutable(key, data)
    }
    fn get(&self, key: &str) -> BlobResult<Vec<u8>> {
        self.inner.get(key)
    }
    fn exists(&self, key: &str) -> BlobResult<bool> {
        self.inner.exists(key)
    }
    fn delete(&self, key: &str) -> BlobResult<()> {
        self.inner.delete(key)
    }
    fn list(&self, prefix: &str) -> BlobResult<Vec<String>> {
        self.inner.list(prefix)
    }
}

/// The object store a benchmark run measures against.
///
/// Defaults to a local file store so the benchmark runs anywhere. Set
/// `CATS_BENCH_S3_BUCKET` to measure against real S3 instead, which is the number
/// that matters: an object there costs a PUT round trip rather than a `create` +
/// `sync_data` + `hard_link`, and both delta packs and golden roots are about how
/// many bytes and objects reach the object store.
///
/// `prefix` keeps concurrent and repeated runs from colliding in one bucket.
fn object_store(dir: &Path, prefix: &str) -> Arc<dyn BlobStore> {
    match std::env::var("CATS_BENCH_S3_BUCKET") {
        Ok(bucket) if !bucket.is_empty() => {
            let mut pairs = vec![
                ("bucket".to_string(), bucket),
                ("prefix".to_string(), format!("bench/{prefix}")),
            ];
            if let Ok(region) = std::env::var("AWS_REGION") {
                pairs.push(("region".to_string(), region));
            }
            // S3 Express One Zone (directory buckets) needs a zonal endpoint,
            // virtual-hosted addressing, the `s3express` signing service, and
            // (typically) CreateSession auth. All optional; unset means
            // standard S3.
            for (var, option) in [
                ("CATS_BENCH_S3_ENDPOINT", "endpoint"),
                ("CATS_BENCH_S3_SIGNING_SERVICE", "signing-service"),
                ("CATS_BENCH_S3_VIRTUAL_HOST", "virtual-host"),
                ("CATS_BENCH_S3_EXPRESS_SESSION", "express-session"),
            ] {
                if let Ok(value) = std::env::var(var) {
                    if !value.is_empty() {
                        pairs.push((option.to_string(), value));
                    }
                }
            }
            let config =
                AdapterConfig::from_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.clone())))
                    .expect("s3 adapter options");
            open_blob_store(
                cats_object_store_aws_s3::ADAPTER_NAME,
                &config,
                &[&AwsS3BlobStoreFactory as &dyn BlobStoreFactory],
            )
            .expect("open s3 object store")
        }
        _ => Arc::new(FileBlobStore::open(dir.join("blob")).expect("blob")),
    }
}

/// A benchmark deliberately runs commits that take tens of seconds against a
/// remote store, which the 5 s default lease does not survive.
fn bench_lease_ttl_ms() -> i64 {
    std::env::var("CATS_BENCH_LEASE_TTL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000)
}

fn bench_samples() -> usize {
    std::env::var("CATS_BENCH_SAMPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|samples| *samples > 0)
        .unwrap_or(5)
}

/// Nearest-rank percentile over an already sorted, non-empty sample.
fn percentile(sorted: &[f64], percent: usize) -> f64 {
    let rank = (sorted.len() * percent).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

struct Env {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    blob: Arc<SizingBlob>,
    meta: Arc<SqliteMetadataStore>,
    engine: Arc<ChunkEngine>,
    published: Arc<SizingBlob>,
}

impl Env {
    fn data_dir(&self) -> std::path::PathBuf {
        self.root.join("data")
    }

    /// Attach again after the local cache has been deleted: a fresh host.
    fn reattach(&self, attachment: &str) -> Arc<ChunkEngine> {
        let mut cfg = EngineConfig::new("vol_commit", self.data_dir(), attachment);
        cfg.lease_ttl_ms = bench_lease_ttl_ms();
        ChunkEngine::attach(cfg, self.blob.clone(), self.meta.clone()).expect("reattach")
    }
}

fn env(chunks: u64, run: &str) -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let published = Arc::new(SizingBlob {
        inner: object_store(dir.path(), run),
        data_bytes: AtomicU64::new(0),
    });
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).expect("meta"));
    meta.create_volume("vol_commit", chunks * CHUNK)
        .expect("volume");
    let meta_for_reattach = meta.clone();
    let mut cfg = EngineConfig::new("vol_commit", dir.path().join("data"), "att-commit");
    cfg.lease_ttl_ms = bench_lease_ttl_ms();
    let engine = ChunkEngine::attach(cfg, published.clone(), meta).expect("attach");
    Env {
        root: dir.path().to_path_buf(),
        _dir: dir,
        blob: published.clone(),
        meta: meta_for_reattach,
        engine,
        published,
    }
}

fn relaxed_env(chunks: u64, run: &str) -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let published = Arc::new(SizingBlob {
        inner: object_store(dir.path(), run),
        data_bytes: AtomicU64::new(0),
    });
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).expect("meta"));
    meta.create_volume("vol_commit", chunks * CHUNK)
        .expect("volume");
    let meta_for_reattach = meta.clone();
    let mut cfg = EngineConfig::new("vol_commit", dir.path().join("data"), "att-commit");
    cfg.lease_ttl_ms = bench_lease_ttl_ms();
    // No timer makes the two measured boundaries explicit: Guest FLUSH can
    // only stage locally; the benchmark invokes the remote drain separately.
    cfg.durability = DurabilityMode::Relaxed {
        drain_interval_ms: 0,
    };
    let engine = ChunkEngine::attach(cfg, published.clone(), meta).expect("attach");
    Env {
        root: dir.path().to_path_buf(),
        _dir: dir,
        blob: published.clone(),
        meta: meta_for_reattach,
        engine,
        published,
    }
}

/// Measures the two Relaxed boundaries separately. The first number is what
/// ext4 waits for (local immutable pack durability); the second is background
/// S3/metadata publication. This deliberately asserts that no data object was
/// published before the local ACK instead of accidentally reporting the sum.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn relaxed_local_ack_and_remote_publish_cost_are_separate() {
    let repeats = bench_samples();
    let mut csv = std::env::var_os("CATS_BENCH_CSV").map(|path| {
        let mut output = BufWriter::new(std::fs::File::create(path).expect("create benchmark CSV"));
        writeln!(
            output,
            "dirty_chunks,sample,local_pack_bytes,local_flush_ms,remote_drain_ms,published_bytes"
        )
        .expect("write benchmark CSV header");
        output
    });
    println!(
        "\n{:>7} {:>7} {:>10}  {:>9} {:>9} {:>9} {:>9}  {:>9} {:>9} {:>9} {:>9}  {:>9}",
        "chunks",
        "samples",
        "pack KiB",
        "L p50 ms",
        "L p95 ms",
        "L p99 ms",
        "L max ms",
        "R p50 ms",
        "R p95 ms",
        "R p99 ms",
        "R max ms",
        "pub MiB"
    );
    for dirty_chunks in [1u64, 8, 32, 64] {
        let mut local_samples = Vec::new();
        let mut remote_samples = Vec::new();
        let mut staged_bytes = 0;
        let mut published_bytes = 0;
        for repeat in 0..repeats {
            let env = relaxed_env(
                dirty_chunks,
                &format!("relaxed-local-{dirty_chunks}-{repeat}"),
            );
            for chunk in 0..dirty_chunks {
                env.engine
                    .write(chunk * CHUNK + 123, &[0x7bu8; 4096])
                    .expect("partial cold-cache write");
            }

            let started = Instant::now();
            env.engine.flush().expect("local relaxed flush");
            local_samples.push(started.elapsed().as_secs_f64() * 1000.0);

            let local = env.engine.durability_status();
            assert_eq!(local.local_durable_generation, 1);
            assert_eq!(local.remote_durable_generation, 0);
            assert_eq!(local.unpublished_generations, 1);
            assert_eq!(env.published.data_bytes.load(Ordering::SeqCst), 0);
            staged_bytes = local.unpublished_bytes;

            let started = Instant::now();
            env.engine.drain_staged().expect("remote drain");
            remote_samples.push(started.elapsed().as_secs_f64() * 1000.0);
            let remote = env.engine.durability_status();
            assert_eq!(
                remote.local_durable_generation,
                remote.remote_durable_generation
            );
            published_bytes = env.published.data_bytes.load(Ordering::SeqCst);
            if let Some(output) = &mut csv {
                writeln!(
                    output,
                    "{dirty_chunks},{repeat},{staged_bytes},{},{},{published_bytes}",
                    local_samples.last().unwrap(),
                    remote_samples.last().unwrap()
                )
                .expect("write benchmark CSV sample");
            }
            env.engine.detach().unwrap();
        }
        local_samples.sort_by(f64::total_cmp);
        remote_samples.sort_by(f64::total_cmp);
        println!(
            "{:>7} {:>7} {:>10.1}  {:>9.2} {:>9.2} {:>9.2} {:>9.2}  {:>9.2} {:>9.2} {:>9.2} {:>9.2}  {:>9.2}",
            dirty_chunks,
            repeats,
            staged_bytes as f64 / 1024.0,
            percentile(&local_samples, 50),
            percentile(&local_samples, 95),
            percentile(&local_samples, 99),
            local_samples.last().unwrap(),
            percentile(&remote_samples, 50),
            percentile(&remote_samples, 95),
            percentile(&remote_samples, 99),
            remote_samples.last().unwrap(),
            published_bytes as f64 / MIB
        );
    }
    if let Some(output) = &mut csv {
        output.flush().expect("flush benchmark CSV");
    }
}

/// One 64 KiB page dirtied per chunk: the shape a 4 KiB random-write Guest
/// workload produces, where a tiny write used to dirty a whole 4 MiB chunk.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn flush_cost_scales_with_the_dirty_set() {
    let volume_chunks = 64;
    let repeats = 3;
    println!(
        "\n{:>12} {:>12} {:>14} {:>12} {:>16} {:>14}",
        "dirty chunks",
        "dirty pages",
        "published MiB",
        "flush ms",
        "ms per pub MiB",
        "sha256 MiB/s"
    );
    for dirty_chunks in [1u64, 8, 16, 32, 48] {
        let mut samples = Vec::new();
        let mut published = 0u64;
        for repeat in 0..repeats {
            let env = env(volume_chunks, &format!("sparse-{dirty_chunks}-{repeat}"));
            let page = vec![0x5au8; PAGE as usize];
            for chunk in 0..dirty_chunks {
                env.engine
                    .write(chunk * CHUNK, &page)
                    .expect("dirty one page");
            }
            let started = Instant::now();
            env.engine.flush().expect("flush");
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
            published = env.published.data_bytes.load(Ordering::SeqCst);
            env.engine.detach().unwrap();
        }
        samples.sort_by(f64::total_cmp);
        let flush_ms = samples[samples.len() / 2];
        let published_mib = published as f64 / (1024.0 * 1024.0);

        // How fast can this machine hash the published bytes? If hashing is a
        // small fraction of the flush, the copy and the writes dominate.
        let image = vec![0x5au8; published as usize];
        let started = Instant::now();
        let mut offset = 0usize;
        while offset < image.len() {
            let end = (offset + PAGE as usize).min(image.len());
            let _ = format::sha256(&image[offset..end]);
            offset = end;
        }
        let hash_mib_s = published_mib / started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);

        println!(
            "{:>12} {:>12} {:>14.2} {:>12.1} {:>16.2} {:>14.0}",
            dirty_chunks,
            dirty_chunks,
            published_mib,
            flush_ms,
            flush_ms / published_mib.max(f64::MIN_POSITIVE),
            hash_mib_s
        );
    }
}

/// Dense writes still publish full 4 MiB bases, so this is the shape delta packs
/// deliberately do not change.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn flush_cost_for_dense_writes() {
    let volume_chunks = 64;
    let repeats = 3;
    println!(
        "\n{:>12} {:>14} {:>12} {:>16}",
        "dirty chunks", "published MiB", "flush ms", "ms per pub MiB"
    );
    for dirty_chunks in [8u64, 32, 48] {
        let mut samples = Vec::new();
        let mut published = 0u64;
        for repeat in 0..repeats {
            let env = env(volume_chunks, &format!("dense-{dirty_chunks}-{repeat}"));
            let whole = vec![0xa5u8; CHUNK as usize];
            for chunk in 0..dirty_chunks {
                env.engine
                    .write(chunk * CHUNK, &whole)
                    .expect("dirty a whole chunk");
            }
            let started = Instant::now();
            env.engine.flush().expect("flush");
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
            published = env.published.data_bytes.load(Ordering::SeqCst);
            env.engine.detach().unwrap();
        }
        samples.sort_by(f64::total_cmp);
        let flush_ms = samples[samples.len() / 2];
        let published_mib = published as f64 / (1024.0 * 1024.0);
        println!(
            "{:>12} {:>14.2} {:>12.1} {:>16.2}",
            dirty_chunks,
            published_mib,
            flush_ms,
            flush_ms / published_mib
        );
    }
}

/// What a delta chain costs to read back cold — the price ADR-0016 pays for
/// publishing pages instead of chunks.
///
/// Each chunk is written once densely (a base) and then `layers` more times, each
/// touching a different page, so the chain really is that deep. Then the local
/// cache is deleted and every chunk is read back, which is what a cross-node
/// migration or a fresh host does.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn cold_read_cost_by_delta_chain_length() {
    let chunks = 16u64;
    println!(
        "\n{:>7} {:>16} {:>14} {:>12} {:>14} {:>12}",
        "layers", "objects", "chunk-at-a-time ms", "MiB/s", "one big read ms", "MiB/s"
    );
    for layers in [0u64, 1, 2, 4] {
        let env = env(chunks, &format!("chain-{layers}"));
        let whole = vec![0xc3u8; CHUNK as usize];
        for chunk in 0..chunks {
            env.engine.write(chunk * CHUNK, &whole).expect("base write");
        }
        env.engine.flush().expect("base flush");
        for layer in 0..layers {
            for chunk in 0..chunks {
                env.engine
                    .write(chunk * CHUNK + layer * PAGE, &[0x5au8; 4096])
                    .expect("delta write");
            }
            env.engine.flush().expect("delta flush");
        }
        env.engine.detach().unwrap();

        // A host with nothing cached.
        std::fs::remove_dir_all(env.data_dir()).ok();
        let engine = env.reattach("cold");
        // Chunk at a time: what a Guest doing 4 MiB reads produces. Only the
        // layers of one chunk can overlap here, which is the amplification
        // ADR-0016 is charged for.
        let mut buf = vec![0u8; CHUNK as usize];
        let started = Instant::now();
        for chunk in 0..chunks {
            engine.read(chunk * CHUNK, &mut buf).expect("cold read");
        }
        let per_chunk = started.elapsed().as_secs_f64();
        engine.detach().unwrap();

        // Whole volume in one call: what a migration or a large sequential read
        // produces, where chunks overlap too.
        std::fs::remove_dir_all(env.data_dir()).ok();
        let engine = env.reattach("cold-bulk");
        let mut whole = vec![0u8; (chunks * CHUNK) as usize];
        let started = Instant::now();
        engine.read(0, &mut whole).expect("bulk cold read");
        let bulk = started.elapsed().as_secs_f64();
        engine.detach().unwrap();

        let mib = (chunks * CHUNK) as f64 / MIB;
        println!(
            "{:>7} {:>16} {:>14.1} {:>12.0} {:>14.1} {:>12.0}",
            layers,
            chunks * (layers + 1),
            per_chunk * 1000.0,
            mib / per_chunk,
            bulk * 1000.0,
            mib / bulk
        );
    }
}
