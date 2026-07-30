# metal-1 drain, NVMe remount, and Cold recovery

Date: 2026-07-30 UTC

This was an in-place production recovery exercise on logical node `metal-1`
(EC2 `c5d.metal`). The node began with `/var/lib/cats` on the root EBS volume
even though `/dev/nvme3n1` contained the intended ext4 instance-store
filesystem.

## Safety and correctness result

- Wrote and `sync`ed a unique canary inside each of the six Running Cats.
- Drained the node to `cordoned`, with zero assigned Cats and all six persisted
  as desired `running`, observed `cold`.
- Stopped `cats-worker`, verified no live VMM or blockd process, and disconnected
  one pre-existing stale `nbd0`; every NBD then reported size zero.
- Preserved the EBS-backed `/var/lib/cats` directory unchanged as rollback
  state.
- Preserved the old NVMe `node` directory as
  `node.pre-remount-20260730T081151Z`.
- Copied the stopped node state to NVMe with sparse-file preservation. Source
  and destination file-name/size manifest SHA-256:
  `3e7c9b066bf5e5579959604a7ccb7e119f841a0d177f4a0f56d3a0a1a1b171d4`.
- Labeled the ext4 filesystem `cats-data`, mounted it at `/var/lib/cats`, and
  installed the checked-in systemd mount unit and worker dependency from this
  directory.
- Restarted the worker while the node remained Cordoned, confirmed a fresh
  heartbeat with zero Cats, then uncordoned it.
- All six Cats Cold-booted with new boot IDs. Every pre-drain canary had the
  expected content and SHA-256. Each Cat then passed a fresh write, `sync`, and
  read-back check. Test files were removed afterward.

Final state:

- node: `ready`, assigned/observed Cats `6/6`
- Cats: desired/observed `running/running`, all on `metal-1`
- storage: `/dev/nvme3n1`, ext4, `rw,noatime`, 824 GiB filesystem
- processes/devices: 6 blockd, 6 Cloud Hypervisor, 6 connected NBD devices
- `cats-worker` and `var-lib-cats.mount`: active; mount unit enabled
- worker error journal since restart: no entries

The EBS state and the renamed old NVMe state were deliberately not deleted.

## Cold recovery timeline

The earlier live observation that the "first restore took about 34 seconds" used
worker start as its origin and a polling observation as its endpoint. The
per-Cat timestamps give a more accurate boundary.

The worker started at 08:13:09. The node remained unschedulable until the
uncordon at about 08:13:22. The first Cat launch directory was created at
08:13:22.448. Observed Running timestamps were:

| Cat | Launch began | Guest agent ready | Observed Running | Launch duration |
|---|---:|---:|---:|---:|
| `pr3110-s-ucca41` | 08:13:22.448 | 08:13:33.911 | 08:13:34.119 | 11.671 s |
| `pr3095-s-ucca41` | 08:13:34.117 | 08:13:39.850 | 08:13:40.058 | 5.941 s |
| `pr3095-core` | 08:13:40.057 | 08:13:46.675 | 08:13:46.877 | 6.820 s |
| `pr3113-core` | 08:13:46.876 | 08:13:56.671 | 08:13:56.864 | 9.988 s |
| `pr3085-core` | 08:13:56.863 | 08:14:02.920 | 08:14:03.119 | 6.256 s |
| `pr3110-core` | 08:14:03.118 | 08:14:09.409 | 08:14:09.607 | 6.489 s |

The six-Cat batch therefore took about 47.2 seconds from the first launch
starting to the last Cat becoming Running. The first launch also ran the
per-worker golden-root publication check, measured at 4.426 seconds.

The launch intervals do not overlap: each next Cat directory appears as the
previous Cat becomes Running. The control plane does reconcile Cats
concurrently, but production uses kernel NBD. The node agent takes its
node-wide operations lock for a kernel-NBD `StartCat` and holds it through the
whole launch, not merely while selecting `/dev/nbdN`. This serializes the batch.

## Why this is not the earlier two-second result

The earlier 1.755-second number was a five-sample P50 lower-bound experiment on
`i4i.metal`: one Cat, direct kernel boot, minimal initramfs, early networking,
and local/warm storage conditions. The product acceptance data separately
measured a single c5.metal stop/Cold-start at 1.674 seconds, and the same-host
metal E2E samples at about 0.91 seconds explicitly recorded a warm
remote/root-cache state. An empty-destination cross-node Cold migration was
4.379 seconds in one sample.

This exercise had different conditions:

1. six Cats were recovered as one node event;
2. drain had removed their per-Cat local caches, so boot reads came from the
   durable S3-backed state into an empty NVMe cache;
3. the kernel-NBD node-wide lock serialized the six launches;
4. the first launch paid a 4.426-second golden-root publication/check cost.

Consequently, 1–2 seconds remains a single-Cat optimized/hot-path measurement,
not a production node-recovery latency or SLA. The empty-cache remote-read cost
is an architectural trade-off of Direct-S3; serializing the whole kernel-NBD
launch and redoing the golden-root work are implementation constraints that can
be removed.
