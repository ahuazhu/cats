# Cats agent instructions

## Repository state

The repository contains the full Rust workspace implementation (V1 dev shape) plus architecture documents and validated experiments. Implemented and tested: ChunkStore engine (`blockd/`, spec in `docs/specs/blockd-protocol.md`), provider-neutral storage ports and adapters, project-scoped control plane and fleet administration/monitoring, separate embedded user and administrator web consoles with optional WorkOS AuthKit sessions, node agent (FakeVmm plus a Cloud Hypervisor Phase-A path), guest agent (Unix socket plus real-Guest vsock), CLI, endpoint gateway — automated workspace tests include adapter contracts, crash injection, fencing, cross-project authorization, AuthKit PKCE/session scopes and refresh, schema migration, node drain and cross-node cold restore. The Cloud Hypervisor path has also passed the 17-check AWS bare-metal acceptance run recorded under `experiments/metal-e2e-20260721/`. NOT yet implemented: native vhost-user-blk (Phase A uses kernel NBD), tap/overlay Guest networking, PostgreSQL metadata store (SQLite dev stand-in keeps the spec's SQL shape), and privilege separation. Do not infer other modules exist because a design document names them; check the workspace.

Quality gates for any change: `cargo test --workspace` green and `cargo clippy --workspace --all-targets` warning-free.

## Read before implementation

Read in this order:

1. All ADRs in [`docs/decisions/`](docs/decisions/): [`0001` greenfield baseline](docs/decisions/0001-greenfield-implementation-baseline.md), [`0002` lifecycle states](docs/decisions/0002-lifecycle-states-running-suspended-warm-cold.md), [`0003` storage backend](docs/decisions/0003-direct-s3-chunkstore-backend.md), [`0004` stack and dev environment](docs/decisions/0004-implementation-stack-and-dev-environment.md), [`0005` provider-neutral storage ports and adapters](docs/decisions/0005-provider-neutral-storage-ports-and-adapters.md), [`0006` WorkOS AuthKit browser identity](docs/decisions/0006-workos-authkit-for-browser-identity.md)
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

Storage code follows Ports and Adapters per ADR-0005. Provider-neutral contracts live in `cats-storage`; concrete provider/product code lives in `adapters/`. AWS S3 is the first durable object-store adapter, not a dependency of core storage semantics.

## Documentation maintenance

Every visual HTML design has a same-name Markdown companion for agents. When a decision or invariant changes, update both formats or make the Markdown/ADR change explicit. Mermaid diagrams in Markdown are manually maintained; rerunning `tools/html_to_agent_md.lua` leaves diagram markers that must be replaced before commit.

Keep experiment source, formal result CSVs and failed crash evidence. Generated caches such as `__pycache__` must not be committed.
