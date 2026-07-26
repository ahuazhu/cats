## Disk types

|  | RootDisk | PersistentDisk |
|----|----|----|
| Creation | Automatic with every Cat | Explicit or via `cats create --disk` |
| Lifecycle | Deleted with the Cat | Independent until explicitly deleted |
| Guest device | System disk | Additional block device mounted at a selected path |
| Access | Owned by its Cat | RWO: one active writer in V1 |

## Create and inspect a PersistentDisk

    cats disk create project-data --size 20GiB
    cats disk ls
    cats disk get project-data

Create a Cat and an independent disk together:

    cats create dev \
      --disk project-data \
      --disk-size 20GiB \
      --mount-at /data

## Mount and unmount

    cats mount project-data --cat dev --at /data
    cats unmount project-data

A mount creates a runtime Attachment with a monotonically increasing fencing epoch. Unmount syncs and detaches before returning the disk to Available. V1 rejects a second read-write attachment even when it targets different logical blocks—the ext4 filesystem itself is single-writer.

## Grow a disk

    cats disk resize project-data --size 40GiB

V1 supports growth only. Follow the API error if the disk must be Available before resizing in the selected runtime path. Never shrink the backing volume under ext4.

## Create a snapshot

    cats disk snapshot project-data

The control plane first establishes a durable barrier, then records an immutable root and generation. The CLI creates and prints the snapshot response; convenience commands to list and restore snapshots are not exposed yet — use the HTTP API for those.

## Durability and cache semantics

The Guest sees standard virtio block devices. Normal writes may complete in managed local cache, but FLUSH/FUA success requires immutable objects to be durable and the authoritative root CAS to succeed. After that point local NVMe is only a deletable cache.

- A small dirty working set does not upload the full sparse disk.
- Empty-cache recovery lazily downloads only the logical chunks read by ext4.
- A stale attachment epoch cannot publish a new root.
- Unflushed Guest page cache or ordinary writes may be lost on permanent host failure.

## Delete safely

    cats unmount project-data
    cats disk delete project-data

**Permanent operation**

The disk must be Available. Deletion revokes access and schedules remote object cleanup; take a snapshot or export data first if retention matters.
