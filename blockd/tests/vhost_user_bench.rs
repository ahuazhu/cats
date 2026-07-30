//! Frontend cost benchmark: NBD versus vhost-user-blk over the same engine.
//!
//! Ignored by default; it is a measurement harness, not an assertion. Run it as
//!
//! ```text
//! cargo test --release -p cats-blockd --test vhost_user_bench -- --ignored --nocapture
//! ```
//!
//! with `CATS_BENCH_CSV=<path>` to also write machine-readable rows and
//! `CATS_BENCH_REPEATS` to change the repeat count (default 3).
//!
//! # Measurement boundary (read before quoting any number)
//!
//! Both frontends are driven from userspace in this process and both call the
//! same `ChunkEngine`, so the delta is the *frontend transport* cost only:
//!
//! * vhost-user-blk: virtqueue in shared memory + eventfd kick, exactly the
//!   path a Guest driver uses.
//! * NBD: this crate's userspace `NbdClient` over a Unix socket — one
//!   `write`/`read` syscall pair per request, strictly one request in flight.
//!
//! The Phase A production path has an extra hop this harness does not model
//! (Guest virtio-blk -> Cloud Hypervisor block backend -> `/dev/nbdN` kernel
//! NBD client -> socket -> blockd). The NBD numbers here are therefore
//! *optimistic* relative to production, which makes the measured improvement a
//! lower bound on the transport win, and says nothing about Guest-visible
//! numbers. Those need a real VMM on bare metal with KVM.
#![cfg(target_os = "linux")]

mod vhu_frontend;

use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_blockd::engine::{ChunkEngine, EngineConfig};
use cats_blockd::nbd::{self, NbdClient};
use cats_blockd::vhost_user::{self, VhostUserOptions};
use cats_metadata_store_sqlite::SqliteMetadataStore;
use cats_object_store_file::FileBlobStore;
use cats_storage::MetadataStore;
use vhu_frontend::{BlkFrontend, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};

const VOLUME_ID: &str = "vol_vhu_bench";
/// 64 MiB = 16 chunks: large enough for a random workload, small enough that the
/// whole working set is cached before measuring.
const VOLUME_SIZE: u64 = 64 * 1024 * 1024;
/// Random offsets stay inside this prefix.
const RANDOM_SPAN: u64 = 32 * 1024 * 1024;
const SECTOR_SIZE: u64 = 512;
const SMALL_BLOCK: usize = 4096;
const LARGE_BLOCK: usize = 1024 * 1024;
const SMALL_OPS: usize = 20_000;
const LARGE_OPS: usize = 512;
const FLUSH_OPS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frontend {
    Nbd,
    VhostUser,
}

impl Frontend {
    fn name(self) -> &'static str {
        match self {
            Frontend::Nbd => "nbd",
            Frontend::VhostUser => "vhost-user-blk",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    RandRead,
    RandWrite,
    SeqRead,
    SeqWrite,
    Flush,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::RandRead => "randread",
            Op::RandWrite => "randwrite",
            Op::SeqRead => "seqread",
            Op::SeqWrite => "seqwrite",
            Op::Flush => "flush",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Workload {
    op: Op,
    block: usize,
    ops: usize,
    threads: usize,
    depth: usize,
}

#[derive(Debug, Clone)]
struct Sample {
    ops: usize,
    bytes: u64,
    wall: Duration,
    latencies_us: Vec<u64>,
}

impl Sample {
    fn ops_per_sec(&self) -> f64 {
        self.ops as f64 / self.wall.as_secs_f64()
    }
    fn mib_per_sec(&self) -> f64 {
        self.bytes as f64 / self.wall.as_secs_f64() / (1024.0 * 1024.0)
    }
    fn mean_us(&self) -> f64 {
        if self.latencies_us.is_empty() {
            return 0.0;
        }
        self.latencies_us.iter().sum::<u64>() as f64 / self.latencies_us.len() as f64
    }
    fn percentile_us(&self, sorted: &[u64], p: f64) -> u64 {
        if sorted.is_empty() {
            return 0;
        }
        let index = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        sorted[index]
    }
}

/// Deterministic offset stream so every frontend and repeat sees the same
/// addresses (xorshift64*, seeded per run).
struct Offsets {
    state: u64,
    span: u64,
    block: u64,
}

impl Offsets {
    fn new(seed: u64, block: usize) -> Self {
        Self {
            state: seed | 1,
            span: RANDOM_SPAN,
            block: block as u64,
        }
    }
    fn next(&mut self) -> u64 {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        let value = self.state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        // Block-aligned inside the random span.
        (value % (self.span / self.block)) * self.block
    }
}

struct Bench {
    _dir: tempfile::TempDir,
    engine: Arc<ChunkEngine>,
    vhost_user_socket: PathBuf,
    nbd_socket: PathBuf,
}

impl Bench {
    /// `serve_vhost_user` is false for NBD runs: an unused vhost-user listener
    /// would leave a thread parked in `accept()` with nothing to disconnect it.
    fn start(
        options: VhostUserOptions,
        serve_vhost_user: bool,
    ) -> (Self, Option<std::thread::JoinHandle<()>>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob = Arc::new(FileBlobStore::open(dir.path().join("blob")).expect("blob store"));
        let meta =
            Arc::new(SqliteMetadataStore::open(&dir.path().join("meta.db")).expect("meta store"));
        meta.create_volume(VOLUME_ID, VOLUME_SIZE).expect("volume");
        let engine = ChunkEngine::attach(
            EngineConfig::new(VOLUME_ID, dir.path().join("data"), "att-bench"),
            blob,
            meta,
        )
        .expect("attach engine");

        let vhost_user_socket = dir.path().join("vhu.sock");
        let server = if serve_vhost_user {
            let mut listener =
                vhost_user::bind(&vhost_user_socket, options).expect("bind vhost-user");
            let served = engine.clone();
            Some(std::thread::spawn(move || {
                let _ = vhost_user::serve_listener(&mut listener, served, options);
            }))
        } else {
            None
        };

        let nbd_socket = dir.path().join("nbd.sock");
        let nbd_listener = UnixListener::bind(&nbd_socket).expect("bind nbd");
        let nbd_engine = engine.clone();
        std::thread::spawn(move || nbd::serve_unix(nbd_listener, nbd_engine));

        (
            Self {
                _dir: dir,
                engine,
                vhost_user_socket,
                nbd_socket,
            },
            server,
        )
    }

    /// Fill the addressable working set so every measured request hits a cached
    /// chunk: the comparison is about frontend cost, not first-touch fetches.
    fn warm(&self) {
        let block = vec![0xa5u8; LARGE_BLOCK];
        let mut offset = 0;
        while offset < RANDOM_SPAN {
            self.engine.write(offset, &block).expect("warm write");
            offset += LARGE_BLOCK as u64;
        }
        self.engine.flush().expect("warm flush");
    }
}

fn run_nbd(bench: &Bench, workload: Workload, seed: u64) -> Sample {
    let started = Instant::now();
    let per_thread = workload.ops / workload.threads;
    let socket = bench.nbd_socket.clone();
    let mut handles = Vec::new();
    for thread in 0..workload.threads {
        let socket = socket.clone();
        handles.push(std::thread::spawn(move || {
            let mut client = NbdClient::connect_unix(Path::new(&socket)).expect("nbd connect");
            let mut offsets = Offsets::new(seed ^ (thread as u64 + 1) << 32, workload.block);
            let payload = vec![0x5au8; workload.block];
            let mut latencies = Vec::with_capacity(per_thread);
            let mut sequential = (thread as u64) * (RANDOM_SPAN / 8);
            for _ in 0..per_thread {
                let offset = match workload.op {
                    Op::RandRead | Op::RandWrite => offsets.next(),
                    Op::SeqRead | Op::SeqWrite => {
                        let at = sequential % RANDOM_SPAN;
                        sequential += workload.block as u64;
                        at
                    }
                    Op::Flush => 0,
                };
                let at = Instant::now();
                match workload.op {
                    Op::RandRead | Op::SeqRead => {
                        client
                            .read(offset, workload.block as u32)
                            .expect("nbd read");
                    }
                    Op::RandWrite | Op::SeqWrite => {
                        client.write(offset, &payload).expect("nbd write");
                    }
                    Op::Flush => {
                        client
                            .write(offset, &payload[..SMALL_BLOCK])
                            .expect("nbd write");
                        client.flush().expect("nbd flush");
                    }
                }
                latencies.push(at.elapsed().as_micros() as u64);
            }
            let _ = client.disconnect();
            latencies
        }));
    }
    let latencies: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().expect("nbd worker panicked"))
        .collect();
    Sample {
        ops: latencies.len(),
        bytes: latencies.len() as u64 * workload.block as u64,
        wall: started.elapsed(),
        latencies_us: latencies,
    }
}

fn run_vhost_user(bench: &Bench, workload: Workload, seed: u64) -> Sample {
    run_vhost_user_with(bench, workload, seed, 0)
}

fn run_vhost_user_with(
    bench: &Bench,
    workload: Workload,
    seed: u64,
    spin_iterations: u32,
) -> Sample {
    // One driver per thread, mirroring a multi-queue Guest.
    let mut frontend = BlkFrontend::connect(
        &bench.vhost_user_socket,
        workload.threads,
        256,
        workload.depth.max(1) as u16,
        true,
    )
    .expect("connect vhost-user frontend");

    let per_thread = workload.ops / workload.threads;
    let started = Instant::now();
    let mut handles = Vec::new();
    for thread in 0..workload.threads {
        let mut queue = frontend.take(thread);
        handles.push(std::thread::spawn(move || {
            queue.set_timeout(Duration::from_secs(60));
            queue.set_spin_iterations(spin_iterations);
            let mut offsets = Offsets::new(seed ^ (thread as u64 + 1) << 32, workload.block);
            let payload = vec![0x5au8; workload.block];
            // Payloads live in shared memory before the timed loop: a Guest
            // driver points the device at pages it already holds.
            queue.prestage_out(&payload).expect("prestage payload");
            let mut latencies = Vec::with_capacity(per_thread);
            let mut sequential = (thread as u64) * (RANDOM_SPAN / 8);
            let depth = workload.depth.max(1);
            let mut inflight: Vec<(Instant, vhu_frontend::Pending)> = Vec::with_capacity(depth);
            let mut submitted = 0usize;
            let mut completed = 0usize;
            while completed < per_thread {
                while submitted < per_thread && inflight.len() < depth {
                    let offset = match workload.op {
                        Op::RandRead | Op::RandWrite => offsets.next(),
                        Op::SeqRead | Op::SeqWrite => {
                            let at = sequential % RANDOM_SPAN;
                            sequential += workload.block as u64;
                            at
                        }
                        Op::Flush => 0,
                    };
                    let sector = offset / SECTOR_SIZE;
                    let at = Instant::now();
                    let pending = match workload.op {
                        Op::RandRead | Op::SeqRead => queue
                            .submit_staged(VIRTIO_BLK_T_IN, sector, 0, workload.block)
                            .expect("submit read"),
                        Op::RandWrite | Op::SeqWrite => queue
                            .submit_staged(VIRTIO_BLK_T_OUT, sector, workload.block, 0)
                            .expect("submit write"),
                        Op::Flush => {
                            // Same shape as the NBD flush workload: dirty a page,
                            // then commit it.
                            let write = queue
                                .write_at(sector, &payload[..SMALL_BLOCK])
                                .expect("write before flush");
                            assert_eq!(write.status, VIRTIO_BLK_S_OK);
                            queue
                                .submit_staged(vhu_frontend::VIRTIO_BLK_T_FLUSH, 0, 0, 0)
                                .expect("submit flush")
                        }
                    };
                    inflight.push((at, pending));
                    submitted += 1;
                }
                queue.kick().expect("kick");
                let (_, used_len) = queue.reap().expect("reap");
                // Requests complete in submission order in this harness (one
                // engine lock per queue), so the oldest in-flight entry matches.
                let (at, pending) = inflight.remove(0);
                let status = queue.collect_status(pending).expect("collect status");
                assert_eq!(status, VIRTIO_BLK_S_OK, "request failed");
                let _ = used_len;
                latencies.push(at.elapsed().as_micros() as u64);
                completed += 1;
            }
            latencies
        }));
    }
    let latencies: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().expect("vhost-user worker panicked"))
        .collect();
    let sample = Sample {
        ops: latencies.len(),
        bytes: latencies.len() as u64 * workload.block as u64,
        wall: started.elapsed(),
        latencies_us: latencies,
    };
    drop(frontend);
    sample
}

fn measure(bench: &Bench, frontend: Frontend, workload: Workload, seed: u64) -> Sample {
    match frontend {
        Frontend::Nbd => run_nbd(bench, workload, seed),
        Frontend::VhostUser => run_vhost_user(bench, workload, seed),
    }
}

#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn frontend_cost_nbd_versus_vhost_user() {
    let repeats: usize = std::env::var("CATS_BENCH_REPEATS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    let workloads = [
        // Core comparison: identical work, one request in flight.
        Workload {
            op: Op::RandRead,
            block: SMALL_BLOCK,
            ops: SMALL_OPS,
            threads: 1,
            depth: 1,
        },
        Workload {
            op: Op::RandWrite,
            block: SMALL_BLOCK,
            ops: SMALL_OPS,
            threads: 1,
            depth: 1,
        },
        Workload {
            op: Op::RandRead,
            block: SMALL_BLOCK,
            ops: SMALL_OPS,
            threads: 4,
            depth: 1,
        },
        Workload {
            op: Op::RandWrite,
            block: SMALL_BLOCK,
            ops: SMALL_OPS,
            threads: 4,
            depth: 1,
        },
        Workload {
            op: Op::SeqRead,
            block: LARGE_BLOCK,
            ops: LARGE_OPS,
            threads: 1,
            depth: 1,
        },
        Workload {
            op: Op::SeqWrite,
            block: LARGE_BLOCK,
            ops: LARGE_OPS,
            threads: 1,
            depth: 1,
        },
        // Control: dominated by the commit protocol, not the transport.
        Workload {
            op: Op::Flush,
            block: SMALL_BLOCK,
            ops: FLUSH_OPS,
            threads: 1,
            depth: 1,
        },
    ];

    let mut csv = String::from(
        "workload,block_bytes,threads,depth,frontend,repeat,ops,wall_us,ops_per_sec,mib_per_sec,mean_us,p50_us,p99_us\n",
    );
    println!(
        "\n{:<10} {:>7} {:>3} {:>3}  {:<15} {:>12} {:>10} {:>9} {:>9}",
        "workload", "block", "thr", "qd", "frontend", "ops/s", "MiB/s", "p50 us", "p99 us"
    );

    let mut summary: Vec<(String, f64, f64)> = Vec::new();
    for workload in workloads {
        let mut totals = [(0f64, 0f64); 2];
        for (index, frontend) in [Frontend::Nbd, Frontend::VhostUser].into_iter().enumerate() {
            for repeat in 0..repeats {
                // A fresh engine per run: no dirty state or cache carried over
                // between frontends or repeats.
                let (bench, server) = Bench::start(
                    VhostUserOptions {
                        num_queues: workload.threads,
                        queue_size: 256,
                    },
                    frontend == Frontend::VhostUser,
                );
                bench.warm();
                let seed = 0x9e37_79b9_7f4a_7c15 ^ (repeat as u64 + 1);
                let sample = measure(&bench, frontend, workload, seed);
                let mut sorted = sample.latencies_us.clone();
                sorted.sort_unstable();
                println!(
                    "{:<10} {:>7} {:>3} {:>3}  {:<15} {:>12.0} {:>10.1} {:>9} {:>9}",
                    workload.op.name(),
                    workload.block,
                    workload.threads,
                    workload.depth,
                    frontend.name(),
                    sample.ops_per_sec(),
                    sample.mib_per_sec(),
                    sample.percentile_us(&sorted, 0.50),
                    sample.percentile_us(&sorted, 0.99),
                );
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{:.1},{:.3},{:.1},{},{}\n",
                    workload.op.name(),
                    workload.block,
                    workload.threads,
                    workload.depth,
                    frontend.name(),
                    repeat,
                    sample.ops,
                    sample.wall.as_micros(),
                    sample.ops_per_sec(),
                    sample.mib_per_sec(),
                    sample.mean_us(),
                    sample.percentile_us(&sorted, 0.50),
                    sample.percentile_us(&sorted, 0.99),
                ));
                totals[index].0 += sample.ops_per_sec();
                totals[index].1 += sample.mib_per_sec();
                // The engine holds the volume lease; release it before the next
                // run attaches.
                bench.engine.detach().unwrap();
                drop(bench);
                if let Some(server) = server {
                    let _ = server.join();
                }
            }
        }
        let nbd_mean = totals[0].0 / repeats as f64;
        let vhu_mean = totals[1].0 / repeats as f64;
        summary.push((
            format!(
                "{} {}KiB t{} qd{}",
                workload.op.name(),
                workload.block / 1024,
                workload.threads,
                workload.depth
            ),
            nbd_mean,
            vhu_mean,
        ));
    }

    println!("\nmean over {repeats} repeats (ops/s):");
    println!(
        "{:<24} {:>12} {:>15} {:>9}",
        "workload", "nbd", "vhost-user-blk", "speedup"
    );
    for (name, nbd_mean, vhu_mean) in &summary {
        println!(
            "{:<24} {:>12.0} {:>15.0} {:>8.2}x",
            name,
            nbd_mean,
            vhu_mean,
            vhu_mean / nbd_mean
        );
    }

    if let Ok(path) = std::env::var("CATS_BENCH_CSV") {
        let mut file = std::fs::File::create(&path).expect("create csv");
        file.write_all(csv.as_bytes()).expect("write csv");
        println!("\nwrote {path}");
    } else {
        println!("\n{csv}");
    }
}

/// Pipelining headroom the synchronous NBD client cannot express: one queue,
/// many requests in flight. Reported separately so it is never mistaken for a
/// like-for-like comparison.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn vhost_user_queue_depth_scaling() {
    println!(
        "\n{:<10} {:>3} {:>12} {:>10}",
        "workload", "qd", "ops/s", "MiB/s"
    );
    for depth in [1usize, 4, 8, 16, 32] {
        // One backend serves one VMM connection, so each depth gets a fresh
        // engine and daemon.
        let (bench, server) = Bench::start(
            VhostUserOptions {
                num_queues: 1,
                queue_size: 256,
            },
            true,
        );
        bench.warm();
        let workload = Workload {
            op: Op::RandRead,
            block: SMALL_BLOCK,
            ops: SMALL_OPS,
            threads: 1,
            depth,
        };
        let sample = run_vhost_user(&bench, workload, 0x1234_5678_9abc_def0);
        println!(
            "{:<10} {:>3} {:>12.0} {:>10.1}",
            workload.op.name(),
            depth,
            sample.ops_per_sec(),
            sample.mib_per_sec()
        );
        bench.engine.detach().unwrap();
        drop(bench);
        if let Some(server) = server {
            let _ = server.join();
        }
    }
}

/// Is a single queue's worker thread the throughput limit?
///
/// The backend drains each virtqueue serially in that queue's worker thread, so
/// the same number of in-flight requests spread over more queues should go
/// faster if — and only if — that serialization is the bottleneck. Same total
/// depth, different queue counts.
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn vhost_user_queue_count_versus_depth() {
    println!(
        "\n{:<10} {:>7} {:>4} {:>13} {:>10}",
        "workload", "queues", "qd", "total ops/s", "MiB/s"
    );
    // 32 requests in flight, split three ways.
    for (queues, depth) in [(1usize, 32usize), (2, 16), (4, 8)] {
        let (bench, server) = Bench::start(
            VhostUserOptions {
                num_queues: queues,
                queue_size: 256,
            },
            true,
        );
        bench.warm();
        let workload = Workload {
            op: Op::RandRead,
            block: SMALL_BLOCK,
            ops: SMALL_OPS,
            threads: queues,
            depth,
        };
        let sample = run_vhost_user(&bench, workload, 0x0bad_c0de_dead_beef);
        println!(
            "{:<10} {:>7} {:>4} {:>13.0} {:>10.1}",
            workload.op.name(),
            queues,
            depth,
            sample.ops_per_sec(),
            sample.mib_per_sec()
        );
        bench.engine.detach().unwrap();
        drop(bench);
        if let Some(server) = server {
            let _ = server.join();
        }
    }
}

/// How much of the QD1 gap is the harness's own completion wait?
///
/// A Guest driver never pays for `poll(2)` plus a thread wakeup per completion:
/// the VMM injects an interrupt. Running the same workload with a short
/// used-ring spin bounds that cost, so the report can separate "backend is slow"
/// from "this harness waits expensively".
#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn vhost_user_notification_cost() {
    println!(
        "\n{:<10} {:<14} {:>12} {:>10} {:>9}",
        "workload", "driver wait", "ops/s", "MiB/s", "p50 us"
    );
    for op in [Op::RandRead, Op::RandWrite] {
        for (label, spin) in [("poll", 0u32), ("spin", 20_000u32)] {
            let (bench, server) = Bench::start(
                VhostUserOptions {
                    num_queues: 1,
                    queue_size: 256,
                },
                true,
            );
            bench.warm();
            let workload = Workload {
                op,
                block: SMALL_BLOCK,
                ops: SMALL_OPS,
                threads: 1,
                depth: 1,
            };
            let sample = run_vhost_user_with(&bench, workload, 0x5eed_1234_5678_9abc, spin);
            let mut sorted = sample.latencies_us.clone();
            sorted.sort_unstable();
            println!(
                "{:<10} {:<14} {:>12.0} {:>10.1} {:>9}",
                op.name(),
                label,
                sample.ops_per_sec(),
                sample.mib_per_sec(),
                sample.percentile_us(&sorted, 0.50)
            );
            bench.engine.detach().unwrap();
            drop(bench);
            if let Some(server) = server {
                let _ = server.join();
            }
        }
    }
}
