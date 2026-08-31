//! What provisioning a Cat's root disk costs, before and after golden roots.
//!
//! Both paths are measured in the same process against the same object store, so
//! the only variable is how the volume gets its rootfs:
//!
//! * **copy** — what the node agent used to do: stream the raw image into the
//!   volume through the block layer and commit it, giving every Cat a private copy
//!   of a rootfs that is byte-identical to every other Cat's.
//! * **reference** — ADR-0017: publish the image once, then provision by writing a
//!   Map that points at its chunks.
//!
//! The 2026-07-26 metal run measured 10 concurrent creates at 128 s on S3 against
//! 24.3 s on a local object store, i.e. the rootfs upload dominates a cold create
//! and it gets worse the further away the object store is. The local numbers here
//! are therefore a *lower* bound on the win; `experiments/` carries the S3 ones.
//!
//! Ignored by default; run with
//! `cargo test --release -p cats-blockd --test golden_root_cost -- --ignored --nocapture`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_blockd::image;
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_aws_s3::AwsS3BlobStoreFactory;
use cats_object_store_file::FileBlobStore;
use cats_storage::authority::VolumeDurability;
use cats_storage::blob::{BlobStore, Result as BlobResult};
use cats_storage::{open_blob_store, AdapterConfig, BlobStoreFactory, MetadataStore, VolumeHead};
use cats_test_support::{prepare_sqlite_authorized_serving, SqliteTestVolumeGrant};

const CHUNK: u64 = cats_protocol::chunk::CHUNK_SIZE as u64;
const MIB: f64 = 1024.0 * 1024.0;

/// Splits what a volume uploaded for itself from what the shared image cost, and
/// counts objects as well as bytes: on S3 each object is a PUT round trip, which
/// is what the delta-pack measurements showed to be the residual cost.
#[derive(Default)]
struct Counters {
    volume_bytes: AtomicU64,
    volume_objects: AtomicU64,
    image_bytes: AtomicU64,
    image_objects: AtomicU64,
}

struct GoldenRootAccountingBlob {
    inner: Arc<dyn BlobStore>,
    counters: Arc<Counters>,
}

impl BlobStore for GoldenRootAccountingBlob {
    fn put_immutable(&self, key: &str, data: &[u8]) -> BlobResult<()> {
        let (bytes, objects) = if key.starts_with("images/") {
            (&self.counters.image_bytes, &self.counters.image_objects)
        } else {
            (&self.counters.volume_bytes, &self.counters.volume_objects)
        };
        bytes.fetch_add(data.len() as u64, Ordering::SeqCst);
        objects.fetch_add(1, Ordering::SeqCst);
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

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    blob: Arc<GoldenRootAccountingBlob>,
    meta: Arc<SqliteMetadataStore>,
    counters: Arc<Counters>,
}

fn env(run: &str) -> Env {
    let dir = tempfile::tempdir().expect("tempdir");
    let counters = Arc::new(Counters::default());
    let blob = Arc::new(GoldenRootAccountingBlob {
        inner: object_store(dir.path(), run),
        counters: counters.clone(),
    });
    let meta = Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).expect("meta"));
    Env {
        root: dir.path().to_path_buf(),
        _dir: dir,
        blob,
        meta,
        counters,
    }
}

/// A stand-in golden rootfs: mostly distinct content with a sparse tail, which is
/// what a real image looks like inside a volume sized for the Cat.
fn golden_image(dir: &Path, mib: u64) -> PathBuf {
    let path = dir.join(format!("golden-{mib}.raw"));
    let mut file = std::fs::File::create(&path).expect("create image");
    let mut block = vec![0u8; MIB as usize];
    for index in 0..mib {
        for (i, byte) in block.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(31).wrapping_add(index as u8 + 1);
        }
        file.write_all(&block).expect("write image");
    }
    file.sync_all().expect("sync image");
    path
}

fn bench_lease_ttl_ms() -> i64 {
    std::env::var("CATS_BENCH_LEASE_TTL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000)
}

fn attach(env: &Env, volume: &str, size: u64) -> Arc<ChunkEngine> {
    match env.meta.create_volume(volume, size) {
        Ok(()) | Err(cats_storage::MetaError::AlreadyExists(_)) => {}
        Err(error) => panic!("create volume: {error}"),
    }
    let epoch = env.meta.load_head(volume).unwrap().lease_epoch + 1;
    let data_dir = env.root.join(format!("data-{volume}"));
    let mut cfg = EngineConfig::new(volume, &data_dir, volume);
    // A benchmark deliberately runs commits that take tens of seconds against a
    // remote store; the 5 s default lease would expire under the copy path and
    // fail the CAS, which is a property of the benchmark, not of the code.
    cfg.lease_ttl_ms = bench_lease_ttl_ms();
    let (attachment, authority) = prepare_sqlite_authorized_serving(
        &env.root.join("meta.db"),
        &data_dir,
        SqliteTestVolumeGrant::new(
            volume,
            volume,
            epoch,
            u64::try_from(cfg.lease_ttl_ms).unwrap(),
            VolumeDurability::Strict,
        ),
    )
    .expect("external grant");
    ChunkEngine::attach_authorized_serving(cfg, attachment, env.blob.clone(), authority)
        .expect("attach")
}

/// The old path: write the image through the engine and commit it.
fn provision_by_copy(env: &Env, volume: &str, image: &Path, size: u64) {
    let engine = attach(env, volume, size);
    let body = std::fs::read(image).expect("read image");
    const STEP: usize = 1 << 20;
    let mut offset = 0usize;
    while offset < body.len() {
        let end = (offset + STEP).min(body.len());
        let block = &body[offset..end];
        if !block.iter().all(|b| *b == 0) {
            engine.write(offset as u64, block).expect("seed write");
        }
        offset = end;
    }
    engine.flush().expect("seed flush");
    engine.stop_authorized_serving().unwrap();
}

/// The new path: reference the already-published image.
fn provision_by_reference(
    env: &Env,
    volume: &str,
    manifest: &cats_blockd::format::ImageManifest,
    size: u64,
) {
    let engine = attach(env, volume, size);
    engine
        .provision_from_image(manifest)
        .expect("provision from image");
    engine.stop_authorized_serving().unwrap();
}

fn head(env: &Env, volume: &str) -> VolumeHead {
    env.meta.load_head(volume).expect("load head")
}

/// One create, both ways, at a few image sizes.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn provisioning_one_root_disk() {
    let repeats = 3;
    println!(
        "\n{:>10} {:>10} {:>12} {:>10} {:>12} {:>10} {:>10}",
        "image MiB", "path", "uploaded MiB", "objects", "provision ms", "speedup", "gen"
    );
    for image_mib in [64u64, 256, 512] {
        let size = cats_protocol::chunk::round_up_to_chunk(image_mib * MIB as u64) + 4 * CHUNK;
        let mut copy_samples = Vec::new();
        let mut copy_report = (0u64, 0u64, 0i64);
        for repeat in 0..repeats {
            let env = env(&format!("one-copy-{image_mib}-{repeat}"));
            let image = golden_image(&env.root, image_mib);
            let volume = format!("vol_copy_{image_mib}_{repeat}");
            let started = Instant::now();
            provision_by_copy(&env, &volume, &image, size);
            copy_samples.push(started.elapsed().as_secs_f64() * 1000.0);
            copy_report = (
                env.counters.volume_bytes.load(Ordering::SeqCst),
                env.counters.volume_objects.load(Ordering::SeqCst),
                head(&env, &volume).generation,
            );
        }
        copy_samples.sort_by(f64::total_cmp);
        let copy_ms = copy_samples[copy_samples.len() / 2];

        let mut ref_samples = Vec::new();
        let mut ref_report = (0u64, 0u64, 0i64);
        let mut publish_ms = 0.0;
        for repeat in 0..repeats {
            let env = env(&format!("one-ref-{image_mib}-{repeat}"));
            let image = golden_image(&env.root, image_mib);
            // Publishing happens once per image for the whole fleet; it is timed
            // separately rather than charged to a create.
            let started = Instant::now();
            let published = image::publish(env.blob.as_ref(), &image).expect("publish");
            publish_ms = started.elapsed().as_secs_f64() * 1000.0;
            env.counters.volume_bytes.store(0, Ordering::SeqCst);
            env.counters.volume_objects.store(0, Ordering::SeqCst);

            let volume = format!("vol_ref_{image_mib}_{repeat}");
            let started = Instant::now();
            provision_by_reference(&env, &volume, &published.manifest, size);
            ref_samples.push(started.elapsed().as_secs_f64() * 1000.0);
            ref_report = (
                env.counters.volume_bytes.load(Ordering::SeqCst),
                env.counters.volume_objects.load(Ordering::SeqCst),
                head(&env, &volume).generation,
            );
        }
        ref_samples.sort_by(f64::total_cmp);
        let ref_ms = ref_samples[ref_samples.len() / 2];

        println!(
            "{:>10} {:>10} {:>12.2} {:>10} {:>12.1} {:>10} {:>10}",
            image_mib,
            "copy",
            copy_report.0 as f64 / MIB,
            copy_report.1,
            copy_ms,
            "1.0x",
            copy_report.2
        );
        println!(
            "{:>10} {:>10} {:>12.2} {:>10} {:>12.1} {:>9.1}x {:>10}",
            image_mib,
            "reference",
            ref_report.0 as f64 / MIB,
            ref_report.1,
            ref_ms,
            copy_ms / ref_ms.max(f64::MIN_POSITIVE),
            ref_report.2
        );
        println!(
            "{:>10} {:>10} {:>12} {:>10} {:>12.1} {:>10} {:>10}",
            image_mib, "(publish)", "once", "-", publish_ms, "-", "-"
        );
    }
}

/// N Cats starting from the same image at once — the case the metal run found to
/// be the bottleneck, where every create was uploading the same rootfs.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn provisioning_many_root_disks_from_one_image() {
    let image_mib = 256u64;
    let size = cats_protocol::chunk::round_up_to_chunk(image_mib * MIB as u64) + 4 * CHUNK;
    println!(
        "\nimage {image_mib} MiB, {} logical cpus\n{:>8} {:>10} {:>12} {:>10} {:>14} {:>10}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        "cats",
        "path",
        "uploaded MiB",
        "objects",
        "wall ms",
        "speedup"
    );
    for cats in [1usize, 4, 10] {
        let mut wall = [0.0f64; 2];
        let mut uploaded = [(0u64, 0u64); 2];
        for (index, by_reference) in [false, true].into_iter().enumerate() {
            let env = env(&format!("many-{cats}-{by_reference}"));
            let image = golden_image(&env.root, image_mib);
            let manifest = by_reference.then(|| {
                image::publish(env.blob.as_ref(), &image)
                    .expect("publish")
                    .manifest
            });
            env.counters.volume_bytes.store(0, Ordering::SeqCst);
            env.counters.volume_objects.store(0, Ordering::SeqCst);

            let started = Instant::now();
            std::thread::scope(|scope| {
                for cat in 0..cats {
                    let env = &env;
                    let image = image.clone();
                    let manifest = manifest.clone();
                    let volume = format!("vol_conc_{by_reference}_{cats}_{cat}");
                    scope.spawn(move || match &manifest {
                        Some(manifest) => provision_by_reference(env, &volume, manifest, size),
                        None => provision_by_copy(env, &volume, &image, size),
                    });
                }
            });
            wall[index] = started.elapsed().as_secs_f64() * 1000.0;
            uploaded[index] = (
                env.counters.volume_bytes.load(Ordering::SeqCst),
                env.counters.volume_objects.load(Ordering::SeqCst),
            );
        }
        for (index, path) in ["copy", "reference"].into_iter().enumerate() {
            println!(
                "{:>8} {:>10} {:>12.2} {:>10} {:>14.1} {:>9.1}x",
                cats,
                path,
                uploaded[index].0 as f64 / MIB,
                uploaded[index].1,
                wall[index],
                wall[0] / wall[index].max(f64::MIN_POSITIVE)
            );
        }
    }
}

/// What the sharing costs on the read side: a provisioned chunk is not in the
/// local cache, so first touch fetches it from the image namespace.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn first_read_of_a_referenced_chunk_versus_a_private_one() {
    let image_mib = 64u64;
    let size = cats_protocol::chunk::round_up_to_chunk(image_mib * MIB as u64);
    let chunks = size / CHUNK;
    println!("\n{:>12} {:>18} {:>18}", "path", "cold read ms", "MiB/s");
    for by_reference in [false, true] {
        let env = env(&format!("read-{by_reference}"));
        let image = golden_image(&env.root, image_mib);
        let volume = format!("vol_read_{by_reference}");
        if by_reference {
            let published = image::publish(env.blob.as_ref(), &image).expect("publish");
            provision_by_reference(&env, &volume, &published.manifest, size);
        } else {
            provision_by_copy(&env, &volume, &image, size);
        }
        // A brand-new host: nothing in the local cache.
        std::fs::remove_dir_all(env.root.join(format!("data-{volume}"))).ok();
        let engine = attach(&env, &volume, size);
        let mut buf = vec![0u8; CHUNK as usize];
        let started = Instant::now();
        for chunk in 0..chunks {
            engine.read(chunk * CHUNK, &mut buf).expect("cold read");
        }
        let elapsed = started.elapsed().as_secs_f64();
        engine.stop_authorized_serving().unwrap();
        println!(
            "{:>12} {:>18.1} {:>18.0}",
            if by_reference { "reference" } else { "copy" },
            elapsed * 1000.0,
            (size as f64 / MIB) / elapsed
        );
    }
}
