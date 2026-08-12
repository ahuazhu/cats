# ADR-0015: Support vhost-user-blk as a production block frontend

- Status: Accepted
- Date: 2026-07-26

## Context

Cats exposes ordinary virtio block devices to the Guest. The original Cloud
Hypervisor path connected those devices to `cats-blockd` through the Host
kernel NBD client. That path is portable and proven, but every disk consumes a
Host-global `/dev/nbdN` and an abnormal exit can leave an attached kernel
device behind.

`cats-blockd` also implements a native vhost-user-blk frontend. It removes the
kernel NBD hop and device pool, but requires Linux, shared Guest memory, and
correct ownership of its Unix sockets.

Both frontends have passed the same real-KVM lifecycle, fencing, ext4, Warm
restore, and cross-node Cold restore checks. The choice is therefore an
operational and performance choice, not a storage-format or correctness fork.

## Decision

1. `cats-blockd` supports both NBD and vhost-user-blk frontends over the same
   `ChunkEngine`. Both translate Guest requests into the same engine calls and
   share FLUSH, fencing, dirty tracking, commit, and recovery semantics.
2. The selected frontend is a Node deployment setting:
   `--ch-block-path kernel-nbd|vhost-user`. It is not part of a Cat or disk's
   persisted identity. Moving a disk between paths requires no data migration.
3. Guest-visible geometry and request semantics are identical. The Guest sees
   512-byte sectors, ordinary virtio-blk, and unmodified ext4. FLUSH remains the
   durability boundary.
4. vhost-user queue count and depth come from the Node configuration and must
   match Cloud Hypervisor. Queue count is bounded by Guest vCPU count; one
   queue remains the default until a representative workload proves otherwise.
5. Kernel NBD remains the default deployment path. In the deployed buffered
   configuration it has a measured write-throughput advantage. vhost-user-blk
   remains fully supported and may be selected per Node.
6. Runtime ownership follows ADR-0040. Kernel NBD allocation is serialized
   under the Host resource lock. vhost-user sockets and either path's processes
   are recorded in the Cat's bounded checkpoint and reconciled with physical
   inventory after agent replacement.

## Default-flip gate

Change the default only after one reviewable experiment satisfies all of these
conditions:

- compare the deployed configurations on the same Host, Guest image, durable
  backend, and workload, using randomized or ABBA order and multiple samples;
- keep build traffic and unrelated dirty-page pressure off the measured NVMe;
- report throughput and tail latency together with sample count and raw data;
- repeat the lifecycle, crash, fencing, orphan-resource, and agent-replacement
  matrix on the candidate default;
- complete a bounded production soak with rollback to the other frontend.

No single prototype measurement is a production SLA. The retained evidence is
in [`vhost-user-blk-frontend-20260726`](../../experiments/vhost-user-blk-frontend-20260726/README.md),
[`metal-cluster-20260726`](../../experiments/metal-cluster-20260726/README.md),
[`vhost-user-soak-20260730`](../../experiments/vhost-user-soak-20260730/README.md),
and [`nbd-attach-mode-20260804`](../../experiments/nbd-attach-mode-20260804/README.md).

## Consequences

- Cats keeps one storage engine and persisted format rather than two storage
  products.
- Operators can choose the frontend per Node and can roll back without moving
  disk data.
- Kernel NBD needs bounded device allocation, leak detection, and recovery.
- vhost-user-blk needs Linux-only verification, shared-memory configuration,
  and exact socket/process ownership.
- Changes touching vhost-user-blk or Linux runtime ownership must pass
  `./scripts/quality.sh linux` in addition to the normal quality gate.
