# Lazy ext4 over chunk storage — minimal validation

This directory contains two validation levels for the storage shape discussed
for `cats`:

- `make demo`: the original small architectural experiment.
- `make production-demo`: a production-shaped crash-consistency test using a
  real JuiceFS mount as the durable remote store.

The cross-experiment conclusion and its relationship to the Cats VM lifecycle
are documented in the
[`2026-07-21 storage and lifecycle report`](../../docs/experiments-2026-07-21-storage-lifecycle.md).

It proves that an **unmodified ext4 filesystem** can run on a large sparse virtual
disk whose committed state lives as immutable chunks in an object directory,
while a local directory behaves like an NVMe read/write cache.

## Architecture

```text
small files
    ↓
unmodified ext4
    ↓
/dev/nbdN (real Linux block device)
    ↓
nbdkit Python backend
    ├── cache/<logical-index>.chunk       local NVMe-like cache
    ├── dirty/<logical-index>.dirty       write-back state
    ├── HEAD.json                         atomic publication point
    ├── manifests/generation-*.json       immutable block maps
    └── objects/<sha256>.chunk            immutable remote ground truth
```

The original demo uses one local state directory. The production-shaped variant
separates the local NVMe state from a real JuiceFS FUSE mount and uses immutable
generation manifests plus a checksummed, atomically replaced `HEAD.json`.

## What the demo does

1. Exposes a sparse logical disk through the Linux NBD subsystem.
2. Formats the device as ext4 and mounts it normally.
3. Creates thousands of small files.
4. Unmounts ext4 and commits only dirty chunks to the object directory.
5. Deletes the entire local cache.
6. Recreates the block device from the manifest and object chunks.
7. Mounts ext4 read-only and verifies an identical tree digest.
8. Prints cache misses and downloaded object bytes from the cold read.

No 4GiB or 100GiB disk image is ever allocated or copied as a whole.

## Run

Docker Desktop must be running. The container needs `--privileged` so it can use
the Linux NBD and ext4 kernel drivers. All generated state is held in an ephemeral
container tmpfs and disappears when the command exits.

Quick run:

```bash
make demo
```

The quick run uses a 4GiB logical disk, 1MiB chunks and 10,000 small files.

The direct 100GiB / 100,000-file variant is:

```bash
make demo-100g
```

The larger run exists to validate logical-size independence; runtime and object
bytes still depend on ext4 metadata layout and the chosen chunk size.

The production-shaped test is:

```bash
make production-demo
```

It runs this full path inside a privileged Linux container:

```text
unmodified ext4
    -> /dev/nbdN
    -> nbdkit ChunkStore
       |-> /state/nvme                    local read/write cache
       `-> /mnt/juicefs/volumes/...       immutable chunks + manifests + HEAD
             -> JuiceFS metadata (SQLite in this test)
             `-> JuiceFS file object backend (S3 substitute in this test)
```

The test deliberately does not enable JuiceFS `--writeback`: when the block
backend completes an NBD FLUSH, data must already be durable through the remote
JuiceFS mount.

It validates five properties:

1. ext4 FLUSH uploads dirty chunks, writes an immutable generation manifest,
   publishes `HEAD.json`, then clears local dirty markers.
2. After deleting both the block cache and JuiceFS client cache, an identical
   ext4 tree is reconstructed lazily from the remote store.
3. A crash after writing objects and a manifest but before HEAD leaves the old
   generation visible.
4. A crash after HEAD leaves the new generation visible; retry only clears
   dirty markers and does not create another generation.
5. Every HEAD-referenced object exists, has the expected size, and matches its
   SHA-256 name.

## Expected evidence

The report includes:

```text
virtual_size_bytes=...
virtual_chunk_count=...
mapped_chunk_count=...
object_bytes=...
cache_chunk_count=...
backend_stats={... "cache_misses": ..., "object_bytes_downloaded": ...}
```

The important relationships are:

```text
mapped_chunk_count << virtual_chunk_count
object_bytes << virtual_size_bytes
tree_digest_before == tree_digest_after
object_bytes_downloaded > 0 after cache deletion
```

The script asserts all four properties, including equality of the before/after
tree digests.

## Observed results

Verified on Docker Desktop's LinuxKit 6.12 kernel on 2026-07-17:

| Case | Logical chunks | Mapped chunks | Object data | Cold-fetched data | Result |
|---|---:|---:|---:|---:|---|
| 4GiB / 10,000 files | 4,096 | 60 | 60MiB | 49MiB | PASS |
| 100GiB / 100,000 files | 102,400 | 521 | 475MiB | 428MiB | PASS |

In the 100GiB case, 521 logical chunk positions referenced 475 physical objects
because content-addressing reused 46 identical chunks. The exact figures are not
universal: ext4 geometry, file contents and chunk size all affect them. The useful
result is that cold start and committed object bytes followed the touched working
set rather than the 100GiB logical capacity.

The production-shaped 4GiB / 10,000-file test also passed on 2026-07-20 with
JuiceFS 1.4.0. Repeated runs had the committed HEAD reference 22–23 4MiB chunks
(88–92MiB), while the cold tree walk fetched 14–15 chunks (56–60MiB). Strict
ext4 flushes published nine remote generations before cache deletion. Exact
generation and object counts depend on ext4 write timing.

## Deliberate simplifications

- Fixed-size chunks; no sub-chunk deltas or compression.
- JSON generation manifests instead of a transactional metadata service.
- The production-shaped test uses JuiceFS with local SQLite metadata and the
  `file` object backend, not Redis/TiKV plus S3/GCS.
- Explicit `chunkctl commit` instead of a background upload queue.
- Single writer, no distributed lease.
- The basic demo has local durability on NBD `FLUSH`; `production-demo` enables
  remote commit on every FLUSH.
- No object garbage collection; old content-addressed chunks are retained.
- No host power-loss test, network partition, S3 fault injection, throughput
  benchmark, multi-host fencing, encryption-key lifecycle, or long soak test.

Those constraints keep the experiment small while preserving the architectural
question being tested: ext4 can lazy-read a sparse object-backed disk through a
standard block interface without any ext4 modification.
