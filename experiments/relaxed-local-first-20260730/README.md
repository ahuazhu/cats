# Relaxed local-first FLUSH boundary benchmark — 2026-07-30

This is a development-machine mechanism check for ADR-0022, not a production
SLA and not an S3 benchmark.

## Boundary

The benchmark writes one unaligned 4 KiB range to each cold-cache chunk, then
measures two operations separately:

1. `ChunkEngine::flush()` in Relaxed mode with the timer disabled: immutable
   pack write + file fsync + rename + pending-directory fsync. It asserts that
   the remote generation and published data bytes are still zero.
2. Explicit `drain_staged()`: materialize 64 KiB pages, publish through the
   local `FileBlobStore`, write Map/commit objects and CAS SQLite.

Each row is the median of five fresh-volume runs. Temp files, FileBlobStore and
SQLite were all on the same local APFS data volume. Consequently the second
number is useful only to prove the boundaries are separated; it does not
estimate S3/PostgreSQL latency.

## Environment

- Base commit: `65cb09ea09b22b12e4808342effaf91291e1467c`
- Source state: the uncommitted ADR-0022 working tree from this change
- Host: Mac17,8, Apple M5 Pro, arm64
- OS: macOS 26.6 (25G72), APFS local journaled data volume
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Available data-volume space during run: 317 GiB

## Command

```bash
cargo test --release -p cats-blockd --test commit_cost \
  relaxed_local_ack_and_remote_publish_cost_are_separate \
  -- --ignored --nocapture
```

## Result

See [`result.csv`](result.csv). Across 1–64 cold chunks, the median local ACK
was 8.81–13.39 ms while the separately measured local-adapter remote drain was
45.05–350.03 ms. The relevant finding is isolation, not the absolute latency:
before every local ACK the test observed `R=0`, `L=1`, one pending generation
and zero published data bytes.

## Tail-latency follow-up

The original five samples cannot estimate tail latency. A follow-up run used
500 fresh volumes for each dirty-set size (2,000 samples total), nearest-rank
percentiles, and retained every observation in
[`raw-samples-500.csv`](raw-samples-500.csv). The run took 465.22 seconds:

```bash
CATS_BENCH_SAMPLES=500 \
CATS_BENCH_CSV="$PWD/experiments/relaxed-local-first-20260730/raw-samples-500.csv" \
cargo test --release -p cats-blockd --test commit_cost \
  relaxed_local_ack_and_remote_publish_cost_are_separate \
  -- --ignored --nocapture
```

| dirty chunks | local p50 | local p95 | local p99 | local max | drain p50 | drain p95 | drain p99 | drain max |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 10.33 ms | 22.08 ms | 27.21 ms | 49.25 ms | 53.47 ms | 76.44 ms | 86.43 ms | 102.36 ms |
| 8 | 9.72 ms | 18.95 ms | 26.89 ms | 144.34 ms | 81.05 ms | 119.22 ms | 135.48 ms | 2,219.35 ms |
| 32 | 11.27 ms | 21.48 ms | 27.44 ms | 50.48 ms | 219.12 ms | 278.22 ms | 310.02 ms | 1,836.62 ms |
| 64 | 11.27 ms | 17.78 ms | 21.73 ms | 24.08 ms | 373.87 ms | 499.92 ms | 535.17 ms | 2,468.06 ms |

The local path has a real broad tail: p99 is 21.73–27.44 ms against a
9.72–11.27 ms p50. It also had three rarer outliers above 30 ms in the
eight-chunk row (one at 144.34 ms) and two in the 32-chunk row. The simulated
remote path had one observation above one second at 8 chunks, one at 32, and
three at 64.

Local and drain latency were weakly correlated within a sample (Pearson
0.007–0.118 across the four rows), so the remote spikes were not generally the
same operation as the local spikes. One notable sequential effect remains:
the 2,219 ms eight-chunk drain at sample 65 was immediately followed by the
144 ms local flush at sample 66. Since FileBlobStore, SQLite, pending packs and
temporary volumes all shared one APFS filesystem, this run cannot distinguish
APFS/writeback/scheduler interference from an engine-local stall. It also
cannot predict S3/PostgreSQL tails. A production decision needs the same
distribution from real Guest ext4 through vhost-user-blk on i4i local NVMe,
with per-stage timing and a concurrent remote publisher.

The machine-readable summary is [`tail-result.csv`](tail-result.csv). SHA-256
of the raw file:
`c7bca7b3a2b5412d2f906d1a5169810199a87323baef00c51aca7b175157a434`.

## metal-1 local-NVMe follow-up

The same x86-64 release test binary was run on the purchased production node
`cats-metal-1` under its existing background workload. Despite its logical
node name, AWS reports this host as `c5d.metal`, not `i4i.metal`:

- AWS `c5d.metal`, `us-east-1a`, 96 vCPUs, Ubuntu 24.04, Linux
  `6.17.0-1019-aws`.
- `/dev/nvme3n1`, Amazon EC2 instance-store NVMe, ext4, temporarily mounted
  with `noatime` at a dedicated benchmark path.
- Five production `cats-blockd` processes remained running. Load average was
  6.74 before and 9.45 after on 96 logical CPUs.
- 500 fresh volumes per dirty-set size, 2,000 observations total,
  nearest-rank percentiles. The run took 65.30 seconds.
- FileBlobStore, SQLite, pending packs and temporary volumes were all on that
  one local NVMe device. This is still not an S3/PostgreSQL measurement and
  does not include Guest ext4 or vhost-user-blk.

| dirty chunks | local p50 | local p95 | local p99 | local max | drain p50 | drain p95 | drain p99 | drain max |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.30 ms | 0.39 ms | 0.53 ms | 0.55 ms | 2.18 ms | 2.80 ms | 3.14 ms | 4.57 ms |
| 8 | 0.49 ms | 0.65 ms | 0.96 ms | 1.39 ms | 19.19 ms | 20.97 ms | 21.79 ms | 23.17 ms |
| 32 | 1.22 ms | 1.39 ms | 1.48 ms | 1.88 ms | 35.15 ms | 35.98 ms | 36.50 ms | 58.39 ms |
| 64 | 2.15 ms | 2.31 ms | 2.37 ms | 4.09 ms | 54.81 ms | 55.96 ms | 56.52 ms | 62.98 ms |

The APFS tail was not an engine-intrinsic floor. For the comparable one-chunk
row, local p50 fell from 10.33 to 0.30 ms and p99 from 27.21 to 0.53 ms. The
NVMe run had no local observation above 0.55 ms in that row. At 64 chunks only
two observations exceeded 3 ms and one exceeded 4 ms. The local-NVMe iostat
windows reported 0.084 ms average and 0.130 ms maximum write await, 27.0%
average and 45.3% maximum device utilization. No drain exceeded 63 ms and
there was no equivalent of the APFS run's 1.8–2.5 second outliers.

This proves the engine-local stage can stay below the ~4 ms comparison point
on the purchased NVMe host. It does **not** yet prove end-to-end Guest `fsync`
does so: the next acceptance boundary must include Guest ext4, virtio,
vhost-user-blk and a concurrently running publisher.

### Deployment finding

The benchmark inspection found that the host is not currently using its local
NVMe for production Cats state. `/dev/nvme3n1` records `/var/lib/cats` as its
last mount point, but after the 2026-07-29 reboot no instance-store entry
exists in `/etc/fstab`; `/var/lib/cats` therefore resolves to the 200 GB EBS
root filesystem. During the 65-second run that root EBS device averaged 97.4%
utilization and about 21 ms write await, while the isolated local NVMe peaked
at 45.3% utilization and 0.13 ms write await. This is a production deployment
risk and can explain poor disk tails independently of ChunkStore. It must be
fixed through a controlled node drain and state migration, not by live
remounting over the active directory.

Formal evidence is under [`metal-1/`](metal-1/):

- [`tail-result.csv`](metal-1/tail-result.csv): machine-readable summary.
- [`raw-samples.csv`](metal-1/raw-samples.csv): all 2,000 observations.
- [`iostat.log`](metal-1/iostat.log): one-second device telemetry.
- [`environment-before.txt`](metal-1/environment-before.txt) and
  [`environment-after.txt`](metal-1/environment-after.txt): measurement
  environment and load boundary.
- [`SHA256SUMS`](metal-1/SHA256SUMS): downloaded-artifact verification.
- [`recovery/README.md`](metal-1/recovery/README.md): the subsequent production
  drain, fail-closed NVMe remount, six-Cat Cold recovery, and exact recovery
  timeline.

SHA-256 of the raw file:
`b5e37214bc79d5cabacedf89fd39e5f4687519b1806a78a97dd3a12b488baa23`.
