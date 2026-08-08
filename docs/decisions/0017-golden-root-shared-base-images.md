# ADR-0017: Provision root disks from immutable shared base images

- Status: Accepted
- Date: 2026-07-26

## Context

Every new Cat begins from a system root image. Uploading a private copy of the
same image for every RootDisk wastes launch time, object-store bandwidth, and
space. Reusing another volume's objects would also couple tenant GC and expose
cross-tenant deduplication behavior.

## Decision

1. Cats publishes operator-controlled root images in a separate immutable,
   content-addressed namespace:

   ```text
   images/<image-id>/data/<chunk-sha256>
   images/<image-id>/manifest.json
   ```

   `image-id` is the SHA-256 of the complete image. The manifest is written
   only after every referenced chunk object is durable.
2. Sharing is limited to published system images. Ordinary volume objects stay
   in their volume namespace; Cats does not provide cross-tenant deduplication.
3. `BaseRef::image` records the image origin of a chunk. The map encoding moves
   to its image-capable version only when such a reference is present.
4. `ChunkEngine::provision_from_image` publishes a map that references the
   manifest. It moves no image data and is allowed only for a generation-zero
   volume with no uncommitted dirty pages.
5. Image publication is idempotent. Concurrent publishers put the same bytes
   at the same immutable keys, and the manifest-last rule prevents consumers
   from observing a partial image.
6. Guest writes follow ADR-0016. Dirty pages become private delta layers over
   the shared image base; a chunk becomes a private full base only when the
   bounded-layer rule selects compaction.
7. Per-volume GC lists and deletes only volume-owned objects. It never deletes
   image objects. Image retirement is an explicit operator action performed
   only after MetadataStore proves that no live or retained Root references the
   image.

## Invariants

- A RootDisk created from an image has the same Guest-visible bytes as the
  published image.
- Provisioning cannot replace data in an existing volume.
- Deleting one Cat or RootDisk cannot remove an image used by another Cat.
- A referenced image object remains immutable and available for the lifetime
  of every Root that names it.
- An older binary rejects an image-capable map version rather than interpreting
  it as a private volume object.

## Evidence and consequences

Implementation and measured launch evidence are retained under
[`vhost-user-blk-frontend-20260726`](../../experiments/vhost-user-blk-frontend-20260726/README.md).
The measurements include their environment and sample boundaries and are not a
production SLA.

Provisioning becomes a small metadata publication instead of a full image
upload, and page-level deltas preserve sharing after writes. In return, image
objects have a longer lifecycle than any one volume and require an explicit,
reference-aware retirement procedure. Snapshot and retained-root reachability
must be included before any image or Root GC decision.
