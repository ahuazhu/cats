## Disk types

|  | RootDisk | PersistentDisk |
|----|----|----|
| Creation | Exact Cat create | Exact PersistentDisk create |
| Ownership | Follows its Cat | Independent Workspace resource |
| Access model | One Cat | RWO: one authorized writer epoch |
| Release capacity | Immutable | Immutable |

## Create and inspect a PersistentDisk

    cats disk create project-data --size 20GiB --durability strict
    cats disk ls
    cats disk get disk_…

The create body explicitly carries `durability`, `name`, and `size_bytes`. The browser console uses the closed Strict default. Both browser and CLI persist the exact request and Idempotency-Key before transport, so an ambiguous response is recovered by exact replay rather than a second create.

Disk item lookup requires the immutable `disk_…` ID returned by create or list. Names are not accepted on item paths.

## Attach and detach while Cold

    cats disk attach disk_... --cat cat_... --mount-path /srv/data
    cats disk detach disk_... --cat cat_... --mount-path /srv/data

Both actions require the exact immutable Disk and Cat IDs, the exact Guest mount
path, an idempotency key, a terminal Cold Cat, no unresolved lifecycle command,
and an unowned PersistentDisk. They synchronously append a new immutable runtime
config and return its ID and digest. They do not hot-plug a device, create a
lifecycle Operation, or prove Guest mount readiness; the next Start freezes and
executes that config.

Snapshot, capacity change, and PersistentDisk deletion are not exposed by the
release product router or shipped CLI. Capacity is immutable. The
provider-neutral storage engine and signed Volume Authority still enforce RWO,
fencing, durable roots, and stale-writer rejection; a product client cannot use
attach or detach to self-acquire or revoke a writer epoch.

## Durability

The Guest sees a standard virtio block device. Strict durability means a successful FLUSH/FUA is remotely durable and survives permanent Host loss. Relaxed durability may acknowledge a local commit while the remote root trails; that local tail is unique data and cannot be discarded as cache.

A stale attachment epoch cannot publish a new root. Lifecycle coordination and takeover require the typed external authority path; a product client cannot self-acquire or revoke an epoch.
