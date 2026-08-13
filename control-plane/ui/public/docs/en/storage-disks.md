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

## Current lifecycle boundary

PersistentDisk attachment, snapshot, capacity change, and deletion are not exposed by the release product router or shipped CLI. Capacity is immutable. The provider-neutral storage engine and signed Volume Authority still enforce RWO, fencing, durable roots, and stale-writer rejection; those data-plane guarantees do not authorize a product mutation endpoint.

## Durability

The Guest sees a standard virtio block device. Strict durability means a successful FLUSH/FUA is remotely durable and survives permanent Host loss. Relaxed durability may acknowledge a local commit while the remote root trails; that local tail is unique data and cannot be discarded as cache.

A stale attachment epoch cannot publish a new root. Lifecycle coordination and takeover require the typed external authority path; a product client cannot self-acquire or revoke an epoch.
