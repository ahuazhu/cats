# Cats agent instructions

## Repository state

This is a greenfield project. The repository currently contains architecture documents and validated experiments, not a production implementation. Do not infer that a module exists because a design document names it.

## Read before implementation

Read in this order:

1. All ADRs in [`docs/decisions/`](docs/decisions/): [`0001` greenfield baseline](docs/decisions/0001-greenfield-implementation-baseline.md), [`0002` lifecycle states](docs/decisions/0002-lifecycle-states-running-suspended-warm-cold.md), [`0003` storage backend](docs/decisions/0003-direct-s3-chunkstore-backend.md), [`0004` stack and dev environment](docs/decisions/0004-implementation-stack-and-dev-environment.md)
2. [`docs/cats-complete-product-technical-architecture.md`](docs/cats-complete-product-technical-architecture.md)
3. The task-specific design:
   - storage (selected backend, ADR-0003; Direct-OS 形态的 Direct-S3 实现): [`docs/direct-s3-chunkstore-architecture.md`](docs/direct-s3-chunkstore-architecture.md)
   - lifecycle (Running/Suspended/Warm/Cold, ADR-0002): [`docs/cats-sleep-wake-vmm-resource-reclamation.md`](docs/cats-sleep-wake-vmm-resource-reclamation.md)
   - historical JuiceFS alternative (not pursued): [`docs/cats-storage-product-blueprint.md`](docs/cats-storage-product-blueprint.md)
4. [`docs/experiments-2026-07-21-storage-lifecycle.md`](docs/experiments-2026-07-21-storage-lifecycle.md) and the linked raw CSV/log evidence.

## Source-of-truth precedence

When documents disagree, use this order:

1. Accepted ADRs for cross-component decisions.
2. Raw experiment data for measured facts.
3. Markdown architecture documents for implementation intent.
4. HTML companions for visual presentation.
5. External/Sprite reference material for background only.

Never turn a prototype measurement into a production SLA. Preserve sample count, environment, measurement boundary and correctness oracle when citing a number.

## Non-negotiable invariants

- The Guest sees standard virtio block devices and unmodified ext4; it never receives object-store or metadata-store credentials.
- Local NVMe is a deletable cache. A successful durable FLUSH must survive permanent Host loss.
- Do not upload an entire sparse virtual disk to commit a small dirty working set.
- A PersistentDisk is RWO in V1. Exactly one fencing epoch may publish writes.
- Old attachment epochs must fail closed, even if an old Host returns after a partition.
- Lifecycle states are Running / Suspended (pause + page-out) / Warm (snapshot + VMM exit) / Cold (ADR-0002). Suspended and Warm are host-bound; do not merge them into one "sleep" state.
- Suspended resume or Warm restore failure must converge to a clean Cold fallback.
- RootDisk lifecycle follows the Cat; PersistentDisk lifecycle is independent.
- Do not hard-code cloud account IDs, buckets, instance IDs, credentials or Host paths.

## Backend status

Direct-OS ChunkStore (Direct-S3 implementation: S3 immutable objects + PostgreSQL root/lease CAS) is the selected storage backend per ADR-0003. Do not implement the JuiceFS-backed sparse `disk.raw` design; `docs/cats-storage-product-blueprint.md` is historical reference only. The current Python/NBD prototype proves semantics and serves as a correctness oracle; the production target is the Rust `cats-blockd` described in the Direct-S3 document.

## Documentation maintenance

Every visual HTML design has a same-name Markdown companion for agents. When a decision or invariant changes, update both formats or make the Markdown/ADR change explicit. Mermaid diagrams in Markdown are manually maintained; rerunning `tools/html_to_agent_md.lua` leaves diagram markers that must be replaced before commit.

Keep experiment source, formal result CSVs and failed crash evidence. Generated caches such as `__pycache__` must not be committed.
