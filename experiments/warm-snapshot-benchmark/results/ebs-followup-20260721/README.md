# EBS Warm restore follow-up — 2026-07-21

## Scope

This follow-up extends the original 1 GiB correctness run with:

- 10 sequential cycles at 512 MiB RAM and a 64 MiB application working set.
- 10 sequential cycles at 2 GiB RAM and a 256 MiB application working set.
- Barrier-synchronized wake tests with 2, 5, and 10 independent 512 MiB VMs.
- A preliminary 10-worker timeout test and a staggered 10-worker diagnostic
  run used to validate and then correct the concurrency harness.

The environment was the same existing AWS `c5.metal` host and 2 TiB EBS volume
as the original test. AWS exposes the EBS volume as an NVMe device, but it is
not local instance-store NVMe. Cloud Hypervisor was v53.0 and each VM used its
own vhost-user block backend, disk, snapshot, tap, bridge, and subnet.

## Sequential size matrix

| Guest RAM / working set | Samples | Snapshot P50 | First health P50 / max | Working-set fault P50 / max | Full RAM ready P50 / max | UUID preserved |
|---|---:|---:|---:|---:|---:|---:|
| 512 MiB / 64 MiB | 10 | 347 ms | 1.82 s / 2.78 s | 3.48 s / 7.14 s | 6.08 s / 10.90 s | 10/10 |
| 1 GiB / 128 MiB | 5 | 682 ms | 1.09 s / 1.89 s | 4.51 s / 4.53 s | 8.03 s / 8.03 s | 5/5 |
| 2 GiB / 256 MiB | 10 | 1.40 s | 1.19 s / 2.08 s | 5.72 s / 7.57 s | 16.51 s / 18.30 s | 10/10 |

Snapshot time and fully resident RSS scale roughly with configured guest RAM.
The lazy-restore setup itself stays nearly constant at about 25 ms regardless
of guest size. First-response latency is not monotonic because it is governed
by which pages are needed immediately and by EBS latency at that moment.

Every sequential cycle had zero dedicated VMM/backend RSS while Warm.

## Synchronized concurrency curve

Each worker first completed its snapshot, exited Cloud Hypervisor and its block
backend, dropped its snapshot from the host page cache with
`POSIX_FADV_DONTNEED`, and reported ready. The coordinator then released all
workers through one barrier. Absolute wake timestamps prove that the release
was synchronized.

| Simultaneous Cats | Wake spread | Restore API P50 / max | First health P50 / max | 64 MiB fault P50 / max | Full 512 MiB ready P50 / max | UUID preserved |
|---:|---:|---:|---:|---:|---:|---:|
| 1 (sequential baseline) | — | 25.31 / 25.56 ms | 1.82 / 2.78 s | 3.48 / 7.14 s | 6.08 / 10.90 s | 10/10 |
| 2 | 3.24 ms | 25.37 / 25.39 ms | 2.43 / 2.48 s | 7.82 / 8.24 s | 11.70 / 12.13 s | 2/2 |
| 5 | 7.44 ms | 25.84 / 26.17 ms | 7.20 / 7.85 s | 15.66 / 19.43 s | 24.58 / 27.59 s | 5/5 |
| 10 | 9.21 ms | 26.11 / 45.81 ms | 19.05 / 23.26 s | 50.34 / 57.46 s | 74.42 / 77.78 s | 10/10 |

The 10-worker run consumed about 5 GiB of resident memory after background
prefault completed, but still consumed zero dedicated VMM/backend RSS while all
workers were waiting at the Warm barrier.

## Diagnosis

The bottleneck is snapshot page-in bandwidth and latency, not VMM construction:

- Recreating each network and block backend stayed around 18–23 ms.
- Registering UFFD memory and reaching the Cloud Hypervisor API stayed around
  25–26 ms at P50, even with 10 workers.
- Resume calls stayed around 4 ms.
- First useful guest responses rose from 1.8 seconds to 19 seconds as
  concurrency rose from one to ten.
- Full UFFD population rose from 6.1 seconds to 74.4 seconds.
- Cloud Hypervisor logs contain successful restore/resume events and no fatal
  VMM failure. Every completed VM returned its pre-snapshot in-memory UUID.

A preliminary 10-worker run with the original 15-second health timeout ended
with 5/10 workers timing out. Raising the observation timeout showed that the
VMs were slow rather than dead: the final synchronized test completed 10/10,
with a maximum first-response latency of 23.26 seconds.

`POSIX_FADV_DONTNEED` is advisory, so these tests approximate a cold host page
cache but cannot flush every cache below the guest. That limitation would tend
to make the result look better, not explain the severe concurrency collapse.

## Product implications

1. Snapshot plus VMM exit is functionally sound and meets the low-RAM Warm
   objective. Snapshot disk capacity still scales approximately with resident
   guest RAM.
2. A host-level wake admission controller is mandatory. On this EBS setup,
   five or ten simultaneous page-in streams are not acceptable for interactive
   wake latency. Even one cold EBS restore misses a sub-second target.
3. Background prefault must not compete equally with latency-critical demand
   faults. Production should prioritize the boot/runtime/network working set,
   rate-limit background full-memory population, and cap page-in concurrency by
   measured storage bandwidth.
4. A recorded hot-page manifest or small eager hot set should be loaded before
   or immediately around vCPU resume. The rest of RAM can remain demand-paged.
5. Direct object-store restore cannot issue one S3 request per 4 KiB guest page.
   It needs larger encrypted chunks, request coalescing, a local chunk cache,
   read-ahead, and demand-fault priority.
6. The next performance test must use local instance-store NVMe. This account
   has no existing host combining local NVMe and bare-metal KVM: the existing
   `c3.4xlarge` is a Xen VM with old local SSD, while the `c5.metal` hosts have
   no instance-store disk.

## Artifacts

- Sequential 512 MiB CSV:
  `cats-warm-bench/results/warm-benchmark-512m-64m.csv`
- Sequential 2 GiB CSV:
  `cats-warm-bench/results/warm-benchmark-2048m-256m.csv`
- Strict barrier summaries:
  `cats-warm-concurrent-{2,5,10}x512-barrier-20260721/concurrent-summary.csv`
- Per-worker benchmark and Cloud Hypervisor logs are retained below each
  corresponding `cat-NN` directory.

