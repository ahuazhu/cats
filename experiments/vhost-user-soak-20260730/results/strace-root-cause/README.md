# vhost-user fsync tail strace follow-up

This follow-up ran on `metal-1` after the original 1,000-sample vhost-user
soak. It is diagnostic evidence, not an SLA and not a fair vhost-user/NBD A/B.

Boundary:

- 20 Guest samples of `pwrite(4 KiB)` followed by timed `fsync`;
- `strace -ff -yy -T` around the experiment blockd processes;
- the same local ext4/NVMe held Cats state;
- real KVM/Cloud Hypervisor, S3, and PostgreSQL remained in use.

The first 17 Guest fsync samples were 60.189–142.789 ms; the last three were
2.084–2.426 ms. In the benchmark volume, 224 immutable pack publications had
the following nearest-rank distribution:

| operation | count | P50 | P95 | P99 | Max |
|---|---:|---:|---:|---:|---:|
| pack file `fdatasync` | 224 | 21.640 ms | 31.896 ms | 57.829 ms | 110.094 ms |
| pending-directory `fsync` | 224 | 14.134 ms | 24.994 ms | 27.959 ms | 30.019 ms |
| pack `rename` | 224 | 0.036 ms | 0.086 ms | 0.103 ms | 1.878 ms |

The trace therefore places the slow time inside the two Host filesystem
durability barriers around each immutable pack. In the slow window, blockd
often handled two consecutive FLUSH generations for one Guest benchmark
iteration: a larger Guest/ext4 dirty set and the explicit 4 KiB write. Their
file and directory barriers are sufficient to compose a 70–128 ms
Guest-visible tail. The trace did not show a comparable vhost notification or
EVENT_IDX delay.

This locates the cost but does not validate the original front-end comparison.
That comparison built on the measured NVMe, always ran vhost-user first, and
ran NBD about 19 minutes later. The raw per-thread traces are retained with the
experiment audit bundle; this directory checks in the formal distributions
and the exact aggregation command without publishing Host-local paths.

Reproduce the syscall summary from an extracted trace bundle:

```bash
./experiments/vhost-user-soak-20260730/analyze-pack-strace.sh TRACE_DIRECTORY
```
