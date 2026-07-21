# i4i.metal lifecycle and storage benchmark — 2026-07-21

## Conclusion

The original roughly 20–21 second Cold result was not caused by Cloud
Hypervisor, the local NVMe block backend, or the benchmark user process. The
dominant delay was the stock Ubuntu cloud-image boot transaction. In the
profiled boot, `systemd-networkd-wait-online.service` alone consumed 13.406
seconds.

After moving the readiness service off the generic Ubuntu boot critical path,
using direct kernel boot, replacing the 33 MiB generic initramfs with a 1.19 MiB
hardware-specific initramfs, and configuring the static network before
`switch_root`, a complete Cold boot reached the HTTP health endpoint in:

```text
P50       1,754.872 ms
observed  1,725.344–1,867.523 ms (5/5 successful)
```

Each optimized Cold cycle started a new guest kernel and a new Python process;
the process boot UUID changed in 5/5 runs. This was not VM memory restore.

## Test environment

- AWS `i4i.metal`, local instance-store NVMe
- Cloud Hypervisor v53, KVM, 2 guest vCPUs
- Ubuntu 22.04.5 ext4 root, Ubuntu kernel `5.15.0-185-generic`
- 1,024 MiB guest RAM and a Python service that allocates and touches 128 MiB
- Root disk exported by `vhost-user-blk`
- Health measured from host wake initiation through a successful Guest HTTP
  response
- The benchmark instance was terminated after all formal CSVs, profiles, and
  logs had been copied into this result directory

## Full lifecycle/storage results

### Cold boot from local NVMe, stock Ubuntu path

| Guest RAM / workset | Runs | Cold-to-health P50 | P95 | New process IDs |
|---|---:|---:|---:|---:|
| 512 / 64 MiB | 5 | 20,699.818 ms | 21,256.304 ms | 5/5 |
| 1,024 / 128 MiB | 5 | 21,064.079 ms | 21,196.074 ms | 5/5 |
| 2,048 / 256 MiB | 5 | 21,009.167 ms | 21,140.033 ms | 5/5 |

The nearly constant result across a 4× RAM/workset range was the first evidence
that the delay was Guest boot policy rather than application memory size.

### Pause plus file-backed RAM page-out to local NVMe

The physical suspended footprint below uses cgroup `memory.current`, not the
sum of per-process shared-mapping RSS.

| Guest RAM / workset | Runs | Wake P50 / P95 | Page-out P50 / P95 | Suspended physical P50 | Reclaimed P50 | Process preserved |
|---|---:|---:|---:|---:|---:|---:|
| 512 / 64 MiB | 10 | 231.300 / 236.427 ms | 255.328 / 359.623 ms | 6.941 MiB | 98.508% | 10/10 |
| 1,024 / 128 MiB | 10 | 212.966 / 220.153 ms | 325.293 / 577.972 ms | 11.635 MiB | 98.086% | 10/10 |
| 2,048 / 256 MiB | 10 | 212.411 / 221.484 ms | 399.638 / 1,065.636 ms | 17.336 MiB | 97.706% | 10/10 |

### Snapshot, VMM exit, and on-demand restore from local NVMe

| Guest RAM / workset | Wake P50 | Wake P95 | Full Guest RAM resident P50 |
|---|---:|---:|---:|
| 512 / 64 MiB | 379.760 ms | 385.518 ms | 1.587 s |
| 1,024 / 128 MiB | 381.745 ms | 445.509 ms | 1.802 s |
| 2,048 / 256 MiB | 398.733 ms | 452.517 ms | 3.094 s |

### Direct-S3 block prototype

The prototype path was:

```text
S3 manifest + immutable 4 MiB objects
  -> single-threaded Python/boto3 nbdkit plugin
  -> Linux NBD
  -> vhost-user-blk
  -> unmodified Guest ext4
```

Three complete Cold runs produced:

- Cold-to-health P50: 39.868 s
- Object bytes downloaded P50: 696,254,464 B (664 MiB)
- Aggregate S3 GET time P50: 18.914 s
- Durable S3 flush P50: 2.127 s
- S3 PUT bytes P50: 67,175,512 B (64.064 MiB)
- New process IDs: 3/3

This validates block semantics and durability, not production performance. The
plugin serializes NBD requests and fetches a full 4 MiB object for every miss.
The aggregate S3 GET time directly explains about half of the Cold latency.

## Where the stock Cold boot spent its time

Cloud Hypervisor made its API available in roughly 24–31 ms. A representative
profiled boot then recorded this Guest timeline:

| Guest boot time | Event | Duration or implication |
|---:|---|---|
| 0.000 s | Linux clock starts | Firmware/handoff time is outside this clock |
| 2.988 s | ext4 root mounted | Generic kernel + generic initramfs path |
| 3.672 s | cloud-init local starts | Pre-network stage |
| 4.175 s | networkd wait-online starts | Main bottleneck begins |
| 17.579 s | networkd wait-online ends | **13.406 s in this unit** |
| 17.581 s | cloud-init network starts | Not itself the 14-second wait |
| 17.962 s | cloud-init network ends | About 381 ms |
| 17.977 s | benchmark service unit starts | Only now allowed onto CPU |
| 18.210 s | Python process entry | Module loading/process startup included |
| 18.376 s | 128 MiB working set initialized | 166.751 ms |
| 18.456 s | health request observed in Guest | Service useful |
| 20.404 s host time | host sees health | Includes pre-kernel firmware/handoff |

At health time, Ubuntu still had active jobs for snapd, LXD, cloud-config, and
cloud-final. Those did not all need to complete to answer the request, but they
show why a general cloud image is the wrong readiness boundary for a microVM
product.

## Cold optimization A/B

All rows used 1,024 MiB Guest RAM and a touched 128 MiB process working set.

| Variant | Runs | Cold-to-health P50 | Observed max | Process entry in Guest P50 | What changed |
|---|---:|---:|---:|---:|---|
| Stock Ubuntu boot | 3 | 21,360.511 ms | 21,397.246 ms | 18,784.681 ms | Firmware, generic initramfs, network-online, cloud-init |
| Early service | 3 | 6,397.428 ms | 6,401.346 ms | 4,216.549 ms | Service no longer waits for cloud-init/network-online |
| Direct Ubuntu kernel | 3 | 5,326.212 ms | 5,334.610 ms | 4,291.452 ms | Bypass firmware/bootloader path |
| 1.1 MiB minimal initramfs | 5 | 3,216.171 ms | 3,262.737 ms | 1,708.392 ms | Only BusyBox + `virtio_blk` + ext4 `switch_root` |
| Minimal initramfs + early network | 5 | **1,754.872 ms** | **1,867.523 ms** | **1,185.045 ms** | Add `virtio_net`, static IP before `switch_root`, earliest service |

The final variant's 5 Cold boots were 1,725.344, 1,752.957, 1,754.872,
1,853.702, and 1,867.523 ms. Its process initialized the 128 MiB working set
in 169–275 ms.

## What this says about Sprites

Sprites' public lifecycle documentation says a warm wake preserves a suspended
VM and takes 100–500 ms, while a cold wake drops in-memory state, starts
processes fresh, and takes 1–2 seconds. Therefore their documented Cold result
should not be explained as restoring each Sprite's old process-memory snapshot.

Their published implementation details identify several relevant choices:

- Firecracker microVMs with a standard platform image instead of arbitrary OCI
  image pull/unpack on create.
- Pools of empty Sprites on workers, avoiding expensive image creation work.
- A custom, Firecracker-specific Rust init rather than stock cloud-init as the
  critical boot orchestrator.
- An outer/root runtime that owns storage, networking, logs, and the service
  manager; user code runs in an inner container and is restarted after Cold.
- A hacked JuiceFS design with rewritten SQLite metadata, Litestream
  durability, immutable object-store chunks, and a sparse NVMe dm-cache-like
  read-through cache.

The exact production Cold boot timeline, kernel configuration, prefetch policy,
and whether any clean template state is reused are not publicly specified. It
is reasonable to infer that Firecracker direct kernel boot, their custom init,
pre-positioned standard assets, immediate network/control-plane availability,
and a hot boot working set are what make the documented 1–2 second Cold wake
possible. That inference is consistent with this experiment, which reaches
1.75 seconds with Cloud Hypervisor using the same class of optimizations.

Sources:

- [Sprites lifecycle and persistence](https://docs.sprites.dev/concepts/lifecycle/)
- [The Design & Implementation of Sprites](https://fly.io/blog/design-and-implementation/)
- [Fly's public Firecracker-specific Rust init snapshot](https://github.com/superfly/init-snapshot)
- [Firecracker FAQ](https://github.com/firecracker-microvm/firecracker/blob/main/FAQ.md)
- [Cloud Hypervisor direct kernel boot](https://github.com/cloud-hypervisor/cloud-hypervisor)

## Recommended Cats production Cold path

1. Define four different readiness metrics: VMM API ready, Guest agent ready,
   `cats exec` ready, and user Service ready. Do not publish one number without
   naming the boundary.
2. Direct-boot a versioned, measured Guest kernel. Build `virtio_blk`,
   `virtio_net`, ext4, and required security features into it where practical.
3. Use a small static Rust PID 1 / Guest agent. Do not put cloud-init, snapd,
   SSH key generation, package timers, or network-online on the wake critical
   path.
4. Inject identity, network configuration, and the storage-manifest generation
   through a small config device or vsock. Make Guest-agent control available
   before general network services.
5. Keep kernel, init, standard root image, and boot-critical filesystem chunks
   pinned or prefetched on every eligible worker's NVMe.
6. Start tap/network, block backend, and VMM preparation concurrently. Add an
   admission controller so a host does not create an object-store thundering
   herd.
7. Treat the object store as truth, but keep Cold's synchronous object reads to
   the profiled boot working set. Use concurrent GETs, coalescing, smaller
   metadata/read units, and adaptive read-ahead; do not ship the serial Python
   Direct-S3 prototype.
8. Start the outer Guest agent first. Restart registered user services in the
   inner environment afterward, and report their application initialization as
   a separate latency component.
9. Keep the existing Warm options: pause + page-out for the lowest latency and
   snapshot/VMM exit when a zero-process state is operationally preferable.
10. Always fall back to a clean Cold boot if Warm restore fails or snapshot and
    host compatibility do not match.

## Limits of the 1.75-second result

- The final fast path used local NVMe. It does not prove 1.75 seconds after a
  host migration with an empty NVMe cache.
- Static IP configuration was intentionally fixed for the benchmark. A product
  needs injected per-Cat configuration and conflict-safe address management.
- It used one Cat at a time. Fleet-level concurrency and S3 GET storms remain
  to be tested.
- Serial console logging remained enabled; production can remove it after
  retaining an out-of-band failure log path.
- The generic Ubuntu kernel remained in use. A smaller measured kernel should
  reduce both boot time and attack surface further.
- A real user service may initialize faster or slower than the synthetic
  Python 128 MiB working set.

## Artifacts

- Formal result CSVs and diagnostic profiles: [`raw/`](raw/)
- Lifecycle runner: [`../../lifecycle_modes.sh`](../../lifecycle_modes.sh)
- Guest timing/profile endpoint: [`../../benchmark.sh`](../../benchmark.sh)
- Minimal initramfs builder: [`../../build_minimal_initramfs.sh`](../../build_minimal_initramfs.sh)
- Minimal init: [`../../minimal-init`](../../minimal-init)
- Direct-S3 benchmark: [`../../direct_s3_benchmark.sh`](../../direct_s3_benchmark.sh)
