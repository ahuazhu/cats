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
4. Runtime只通过当前 noded 场景语义物理 effect 和 blockd 的显式 typed control request调用
   `ChunkEngine::provision_from_image`。它发布引用manifest的Map，
   不移动image data，只允许exact owner/epoch下没有dirty/pending/staged write的generation-zero卷；
   Guest device和VMM必须等exact generation-1 target确认后才出现。
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
8. manifest、immutable volume size和既有Map编码纯确定计算generation-1 root hash/object ID。
   noded在完成effect前保留完整request和唯一transition ID；blockd以该ID固定commit object key并做
   exact blank->target head CAS。响应丢失只比较权威head，不保存第二份provision receipt。
   Cat runtime不得再用`--seed-image-id`在blockd启动时隐式provision，也不保留双路径兼容层。
9. manifest 的唯一 provider-neutral DTO、canonical artifact bytes、有界 reader、closed error与
   Control Plane只读composition由
   [Immutable Image Manifest Read v1](../specs/immutable-image-manifest-read-v1.md)冻结；blockd与Control
   不得各自保留第二套JSON parser/validator或catalog fallback。

## Invariants

- A RootDisk created from an image has the same Guest-visible bytes as the
  published image.
- Provisioning cannot replace data in an existing volume.
- Agent或blockd在任一PUT/CAS边界重启，只能用同一step确认exact target或重试exact blank；任意其他
  generation、root、owner或epoch都fail closed。
- Provision成功前没有Guest可达的block frontend或VMM，因此空白卷不能被Guest抢先写入。
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
