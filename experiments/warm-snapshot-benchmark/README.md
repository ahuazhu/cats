# Warm Snapshot Benchmark

This experiment suite measures Cold boot, low-RAM pause/page-out, snapshot plus
VMM exit, and a Direct-S3 block prototype on a real x86_64 KVM host. It uses
Cloud Hypervisor v53 and its in-tree vhost-user-blk backend.

The complete 2026-07-21 report, including EBS vs Local NVMe, Cold boot
diagnosis, page-out, Direct-S3, and the storage experiments, is available in
[`docs/experiments-2026-07-21-storage-lifecycle.md`](../../docs/experiments-2026-07-21-storage-lifecycle.md).

The measured transition is:

```text
Running
  -> pause
  -> snapshot VM memory/device state
  -> exit Cloud Hypervisor
  -> exit vhost-user-blk backend
  -> delete tap
  -> evict snapshot files from host page cache
  -> recreate tap and block backend
  -> start a new Cloud Hypervisor process
  -> restore memory on demand with userfaultfd
  -> resume vCPUs
  -> wait for the guest's first HTTP response
  -> fault a configurable working set back in
```

The guest service creates an in-memory UUID and touches `WORKSET_MIB` of RAM.
Every restore must return the same UUID. This proves that the result is a memory
restore, not an unnoticed cold boot.

## Requirements

- Linux x86_64
- `/dev/kvm`
- root access for tap/bridge setup
- local SSD/NVMe recommended
- Internet access during `prepare`

Docker Desktop on macOS cannot run this benchmark because its Linux VM does not
expose nested `/dev/kvm`.

## Run

```bash
sudo ./experiments/warm-snapshot-benchmark/benchmark.sh prepare

sudo MEMORY_MIB=1024 \
  WORKSET_MIB=128 \
  ITERATIONS=10 \
  ./experiments/warm-snapshot-benchmark/benchmark.sh run
```

Or prepare and run in one command:

```bash
sudo MEMORY_MIB=1024 WORKSET_MIB=128 ITERATIONS=5 \
  ./experiments/warm-snapshot-benchmark/benchmark.sh all
```

Compare a full Cold boot with pause plus file-backed Guest RAM page-out:

```bash
sudo MEMORY_MIB=1024 WORKSET_MIB=128 ITERATIONS=5 \
  ./experiments/warm-snapshot-benchmark/lifecycle_modes.sh cold

sudo MEMORY_MIB=1024 WORKSET_MIB=128 ITERATIONS=10 \
  ./experiments/warm-snapshot-benchmark/lifecycle_modes.sh pageout
```

Cold runs expose Guest boot timing in the health response and write a
`cold-profile-<iteration>.json` file containing key systemd unit timestamps and
the boot journal. `SERVICE_BOOT_MODE=early` or `earliest` is intended for boot
path experiments, not as a production systemd policy.

The minimal initramfs builder used to measure the optimized Cold lower bound is:

```bash
sudo apt-get install -y busybox-static cpio zstd
sudo ./experiments/warm-snapshot-benchmark/build_minimal_initramfs.sh \
  /path/to/ubuntu-initrd.img /path/to/cats-minimal-initrd.img
```

It is deliberately tied to this benchmark's single virtio block device, virtio
network device, static test address, and ext4 root. Production must inject
per-Cat network/storage configuration and retain the required security and
recovery features.

The default working directory is `/var/lib/cats-warm-bench`. Override it with
`WORK_DIR` if the local NVMe mount is elsewhere.

`ASSET_DIR` can point at a prepared work directory while `WORK_DIR` remains
unique per VM. This lets concurrent workers share immutable binaries, firmware,
and the pristine base image without sharing sockets, disks, snapshots, or
network devices.

Run a concurrent wake baseline after preparing the shared assets:

```bash
sudo ASSET_DIR=/var/lib/cats-warm-bench \
  BASE_WORK_DIR=/var/lib/cats-warm-concurrent \
  CAT_COUNT=10 MEMORY_MIB=512 WORKSET_MIB=64 \
  ./experiments/warm-snapshot-benchmark/concurrent.sh
```

The concurrent runner holds every worker at a barrier after its VMM and block
backend have exited. It releases all workers together, and reports the measured
spread between their absolute wake timestamps.

## Output

The CSV is written to:

```text
/var/lib/cats-warm-bench/results/warm-benchmark.csv
```

Important columns:

| Column | Meaning |
|---|---|
| `snapshot_ms` | Paused VM memory/device snapshot time |
| `shutdown_ms` | VMM, backend, and tap teardown time |
| `warm_runtime_rss_kib` | Dedicated VMM/backend RSS while Warm; expected `0` |
| `snapshot_allocated_bytes` | Physical local-disk blocks used by the snapshot |
| `network_backend_ms` | Recreate tap and start vhost-user-blk |
| `restore_to_api_ms` | New VMM start through completed on-demand restore setup |
| `resume_api_ms` | `ch-remote resume` latency |
| `wake_to_health_ms` | End-to-end wake request to first useful guest response |
| `touch_wall_ms` | Time to fault the configured working set back from NVMe |
| `full_memory_ready_ms` | Wake until v53 finishes background-prefaulting all guest RAM; another snapshot/migration is rejected before this point |
| `full_ready_rss_kib` | VMM/backend RSS after all guest RAM is resident again |
| `boot_id_preserved` | Must be `true`; proves process memory survived |

## Test matrix

Run at least these cases before making a product claim:

```bash
MEMORY_MIB=512  WORKSET_MIB=64   ITERATIONS=20 ... run
MEMORY_MIB=2048 WORKSET_MIB=256  ITERATIONS=20 ... run
MEMORY_MIB=8192 WORKSET_MIB=1024 ITERATIONS=10 ... run
```

Also repeat with 1, 10, and 100 concurrent Cats. The single-VM result validates
mechanism and latency; it does not validate fleet-level NVMe bandwidth, page
fault storms, or scheduler admission.

## Interpretation

A production candidate should initially meet:

```text
warm_runtime_rss_kib = 0 dedicated runtime RSS
boot_id_preserved    = true for every successful restore
wake_to_health_ms    P50 < 500 ms, P95 < 1000 ms
restore failure      always falls back to Cold boot
```

The in-tree vhost-user-blk process is only a protocol/reference backend. A final
decision still requires rerunning the same benchmark with `cats-blockd` and the
Direct-S3 ChunkStore data path.

## Preserved result reports

- [`c5.metal + EBS baseline`](results/c5-metal-ebs-20260721/README.md)
- [`c5.metal + EBS size/concurrency follow-up`](results/ebs-followup-20260721/README.md)
- [`i4i.metal + Local NVMe Warm`](results/i4i-local-nvme-20260721/README.md)
- [`i4i.metal Cold, page-out, and Direct-S3`](results/i4i-lifecycle-modes-20260721/README.md)
