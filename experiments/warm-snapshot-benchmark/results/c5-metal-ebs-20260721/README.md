# c5.metal EBS benchmark — 2026-07-21

## Environment

- Existing AWS `c5.metal` host, x86_64, Linux `6.8.0-1057-aws`
- Cloud Hypervisor `v53.0`
- Cloud Hypervisor in-tree `vhost_user_block` reference backend
- Ubuntu 22.04 guest, 2 vCPUs, 1024 MiB RAM
- Guest service pre-touched a 128 MiB anonymous-memory working set
- Snapshot and guest disk were on a 2 TiB EBS volume mounted at
  `/mnt/scratch`. AWS exposes this volume as an NVMe device, but it is not
  local instance-store NVMe.
- Five sequential snapshot, VMM exit, on-demand restore, and resume cycles

Command parameters:

```text
WORK_DIR=/mnt/scratch/cats-warm-bench
MEMORY_MIB=1024
WORKSET_MIB=128
ITERATIONS=5
PREFAULT_TIMEOUT_S=300
```

## Result

All five cycles passed. Every restored guest returned the same in-memory UUID
that existed before its snapshot, proving that the guest process memory
survived VMM exit and restore. Dedicated runtime RSS while the Cat was Warm was
zero because Cloud Hypervisor and the vhost-user block backend had both exited.

With five samples, `P95` below is effectively the maximum sample and should not
be treated as a production percentile.

| Metric | P50 | P95 / max |
|---|---:|---:|
| Pause | 4.38 ms | 4.82 ms |
| Snapshot | 682.22 ms | 724.86 ms |
| VMM/backend/tap shutdown | 175.91 ms | 207.53 ms |
| Network and block-backend recreation | 16.99 ms | 38.17 ms |
| New VMM start through API ready | 25.34 ms | 25.69 ms |
| Resume API call | 3.40 ms | 4.39 ms |
| Wake request through first healthy HTTP response | 1089.99 ms | 1889.29 ms |
| Fault the 128 MiB application working set back in | 4514.61 ms | 4527.52 ms |
| Wake through all 1 GiB of guest RAM resident | 8032.56 ms | 8034.77 ms |

Additional observations:

- `boot_id_preserved`: 5/5
- Maximum Warm runtime RSS: 0 KiB
- RSS after full background prefault: about 1.01 GiB
- Snapshot apparent size: about 1.00 GiB
- Snapshot allocated size: 838 MiB on the first cycle and about 1.00 GiB on
  later cycles after all pages had become resident
- Last-cycle UFFD result: 262,144 total 4 KiB pages; 20,502 demand-faulted and
  241,642 background-prefaulted; completion took 7.988 seconds

The first healthy response and application working-set timings include genuine
page faults against a snapshot whose host page-cache residency was dropped with
`POSIX_FADV_DONTNEED`. The kernel treats that call as advice, so this is a strong
cold-cache approximation rather than proof that every lower storage cache was
empty.

## What this validates

This validates the core Warm mechanism on real KVM:

1. Pause and snapshot an unmodified Linux guest.
2. Exit the VMM and block backend, reducing dedicated Warm runtime RSS to zero.
3. Recreate networking and the vhost-user block backend.
4. Start a new VMM and register guest RAM with `userfaultfd` on-demand restore.
5. Resume the same guest process state and fetch memory pages lazily.
6. Finish prefaulting untouched RAM in the background, after which Cloud
   Hypervisor allows another snapshot or migration.

Cloud Hypervisor v53 rejects a new snapshot while background prefault is still
running. The benchmark explicitly waits for the `UFFD handler: prefault done`
event before starting the next cycle.

## What this does not validate

- Local instance-store NVMe latency; this host used EBS.
- `cats-blockd`, JuiceFS, or Direct-S3 ChunkStore behavior; the run used the
  Cloud Hypervisor reference vhost-user block backend and a local raw file.
- Concurrent wake storms or fleet-level memory/storage admission control.
- Production P50/P95/P99; five sequential samples are only a mechanism and
  baseline test.
- Snapshot compression, deduplication, encryption, upload, or cross-host
  restore.

The mechanism is viable, but the measured EBS cold path does not meet a
sub-second P95 wake target. The next meaningful run should use local
instance-store NVMe, then repeat with the production `cats-blockd` backend and
concurrent Cats.

