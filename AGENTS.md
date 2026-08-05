# Cats agent instructions

## Repository state

The repository contains the full Rust workspace implementation (V1 dev shape) plus architecture documents and validated experiments. Implemented and tested: ChunkStore engine (`blockd/`, spec in `docs/specs/blockd-protocol.md`) with both frontends — NBD (portable) and native vhost-user-blk (Linux, ADR-0015) — provider-neutral storage ports and adapters, workspace-scoped control plane and fleet administration/monitoring, separate embedded user and administrator web consoles with optional WorkOS AuthKit sessions, node agent (FakeVmm plus a Cloud Hypervisor Phase-A path, `--ch-block-path kernel-nbd|vhost-user`), guest agent (Unix socket plus real-Guest vsock), systemd as the default Guest PID 1 with ordinary enabled Linux services (ADR-0023), CLI, endpoint gateway — automated workspace tests include adapter contracts, crash injection, fencing, cross-workspace authorization, AuthKit PKCE/session scopes and refresh, schema migration, node drain and cross-node cold restore, plus Linux-only vhost-user-blk acceptance tests driven by a userspace VMM stand-in (`blockd/tests/vhost_user_blk.rs`). The Cloud Hypervisor path has also passed the 17-check AWS bare-metal acceptance run recorded under `experiments/metal-e2e-20260721/`. Both block paths have now passed the same 22/23 acceptance run on AWS `i4i.metal` with real KVM and Cloud Hypervisor, including Warm `vm.snapshot`/`--restore` state alignment, and a two-node cluster over real S3 + RDS PostgreSQL did cross-node Cold migration 12/12 (`experiments/vhost-user-blk-frontend-20260726/`, `experiments/metal-cluster-20260726/`). Kernel NBD stays the default block path for a measured write-throughput trade-off, not for lack of validation; the flip criteria are in ADR-0015. Concurrent cold launches are no longer serialized node-wide (per-Cat lock always, node-wide lock only for the kernel-NBD device allocation, bounded by a separate launch ceiling) and the commit path parallelizes its copy and hashing (FLUSH 1.6x-1.8x). Delta packs (ADR-0016) and golden roots (ADR-0017) have since landed and are no longer future work: a commit publishes each dirty chunk's dirty 64 KiB pages as a delta object instead of the whole 4 MiB chunk, and the exclusive barrier copies exactly the page set the pack uploads (`copy_planned_pages`), so the "copy only dirty pages" form the earlier note ruled out is what the code now does; a chunk carries at most `MAX_DELTA_LAYERS` (4) deltas over its base, so a cold chunk read fetches at most five objects, and `plan_commit` publishes a fresh full 4 MiB base instead whenever the Guest dirtied more than half the chunk or the chain is full. Root disks are provisioned by referencing a shared, content-addressed image namespace (`images/<image-id>/`, `BaseRef::image`, `ChunkEngine::provision_from_image`) rather than every Cat uploading a byte-identical private copy. NOT yet implemented: tap/overlay Guest networking beyond per-Cat taps, and privilege separation. Do not infer other modules exist because a design document names them; check the workspace.

Quality gates for any change: `./scripts/quality.sh full` green. This checks Rust formatting and shared agent-skill contracts; rejects known security advisories, unapproved licenses and dependency sources, new transitive version splits, wildcard or inconsistent workspace dependencies, and unused direct dependencies; builds the workspace before tests; runs Clippy with warnings denied; and runs all workspace tests and rustdoc. Use `./scripts/quality.sh fast` while iterating.

The dependency gate uses pinned tool versions:

```bash
cargo install --locked cargo-deny --version 0.19.4
cargo install --locked cargo-machete --version 0.9.2
```

Shared audit, refactor, and PR-review workflows live canonically under `agent-skills/` and are linked into both `.agents/skills/` and `.claude/skills/`. Keep the audit and review workflows read-only unless the user explicitly asks for fixes.

The vhost-user-blk frontend and the node agent's Linux-only code compile out on macOS, so a change touching either must also be gated on Linux. Without a Linux box, a container is enough (no KVM needed for the protocol tests):

```bash
./scripts/quality.sh linux
```

The script keeps the target directory in a Docker volume, not in the bind-mounted repository: the shared macOS filesystem is slow and has produced spurious "can't find crate" failures mid-build. Override the defaults with `CATS_LINUX_PLATFORM`, `CATS_LINUX_TARGET_VOLUME`, or `CATS_LINUX_JOBS` when needed. The Linux gate defaults to two Cargo jobs to avoid parallel linker OOMs in constrained Docker runtimes, and child Cargo processes inherit the same limit. `cargo build` must come first because some integration tests shell out to `cargo build` for helper binaries and would otherwise deadlock on the build-directory lock.

## Working agreement

### Workspace isolation

Every independent feature or bug fix gets its own git worktree at
`.worktrees/<issue-id>`, on its own branch. Do not develop in the primary
checkout: the quality gate and the storage/lifecycle tests spawn real processes
and rewrite state directories, and the primary checkout is where the user's own
uncommitted work and untracked notes live.

```bash
git worktree add -b fix/<short-slug> .worktrees/99
```

Without an issue, name the directory after the branch slug. Never `git stash` in
the primary checkout to free it for another task — that is exactly what a second
worktree is for. Remove the worktree once its branch has merged
(`git worktree remove .worktrees/<issue-id>`).

### Verification

- Run `./scripts/quality.sh fast` while iterating and `./scripts/quality.sh full` before handoff.
- Report the exact verification commands run and their results.
- Clearly separate pre-existing failures from regressions introduced by the change.
- Run `./scripts/quality.sh linux` when a change touches code that compiles out on macOS.

### Change discipline

- Preserve observable behavior unless the task explicitly changes it.
- Before a non-trivial refactor, identify or add characterization tests.
- Keep each patch focused on one coherent purpose; do not perform unrelated cleanup.
- Do not add a production dependency without explaining why the standard library and existing dependencies are insufficient.
- Inherit shared dependency versions from `[workspace.dependencies]`; keep any policy exception in `deny.toml` version-scoped and explain why it is needed.
- Do not change public APIs, protocols, persisted formats or lifecycle semantics unless the task requires it.
- Never silence a lint globally to make CI pass. Keep any new suppression as narrow as possible and document the invariant or reason.
- Do not introduce an abstraction without a current boundary or multiple real uses.

### Rust conventions

- Fallible input, request, persistence and background-worker paths must return errors rather than panic.
- Use `unwrap` or `expect` only in tests or for a locally proven invariant that is obvious or documented.
- Do not hold a mutex or rwlock guard across `.await`, and do not put blocking work directly on an async executor.
- Prefer enums and domain-specific newtypes over new boolean-flag APIs or string protocols.
- Default visibility to private or `pub(crate)`; expose only deliberate public API.
- Avoid cloning data merely to satisfy the borrow checker; document intentionally expensive clones.
- Keep unsafe code small and isolated. Every unsafe block must explain its safety invariant.
- Do not leak framework-specific types across a domain or provider-neutral boundary without a concrete reason.

### Testing

- Test externally observable behavior rather than private implementation details.
- Bug fixes require a regression test that fails before the fix.
- Refactors must not weaken existing assertions.
- Parsers, decoders and other untrusted-input boundaries need malformed-input and boundary-value coverage.
- Concurrency changes must cover cancellation, shutdown and resource cleanup when relevant.

### Review priorities

Review in this order:

1. Correctness and data loss.
2. Memory safety and concurrency.
3. Error handling and cancellation.
4. Public API and architecture boundaries.
5. Missing tests.
6. Maintainability.

Do not report formatting issues already covered by Rustfmt or Clippy.

## Read before implementation

Read in this order:

1. All ADRs in [`docs/decisions/`](docs/decisions/): [`0001` greenfield baseline](docs/decisions/0001-greenfield-implementation-baseline.md), [`0002` lifecycle states](docs/decisions/0002-lifecycle-states-running-suspended-warm-cold.md), [`0003` storage backend](docs/decisions/0003-direct-s3-chunkstore-backend.md), [`0004` stack and dev environment](docs/decisions/0004-implementation-stack-and-dev-environment.md), [`0005` provider-neutral storage ports and adapters](docs/decisions/0005-provider-neutral-storage-ports-and-adapters.md), [`0006` WorkOS AuthKit browser identity](docs/decisions/0006-workos-authkit-for-browser-identity.md), [`0007` Guest Runtime HTTP over Unix socket](docs/decisions/0007-guest-runtime-http-over-unix-socket.md), [`0015` vhost-user-blk production block frontend](docs/decisions/0015-vhost-user-blk-production-block-frontend.md), [`0018` Workspace is the only resource owner](docs/decisions/0018-remove-the-v1-project-compatibility-layer.md), [`0023` systemd Guest PID 1](docs/decisions/0023-systemd-as-the-default-guest-init.md)
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
- Guest user programs access optional runtime capabilities through HTTP/1.1 on `/run/cats/runtime.sock`; they must not require a Cats SDK/CLI or a fixed TCP/UDP port. The VMM never accesses this Guest-local socket.
- Do not hard-code cloud account IDs, buckets, instance IDs, credentials or Host paths.

## Backend status

Direct-OS ChunkStore (Direct-S3 implementation: S3 immutable objects + PostgreSQL root/lease CAS) is the selected storage backend per ADR-0003. Do not implement the JuiceFS-backed sparse `disk.raw` design; `docs/cats-storage-product-blueprint.md` is historical reference only. The current Python/NBD prototype proves semantics and serves as a correctness oracle; the production target is the Rust `cats-blockd` described in the Direct-S3 document.

Storage code follows Ports and Adapters per ADR-0005. Provider-neutral contracts live in `cats-storage`; concrete provider/product code lives in `adapters/`. AWS S3 is the first durable object-store adapter, not a dependency of core storage semantics.

## Documentation maintenance

Every visual HTML design has a same-name Markdown companion for agents. When a decision or invariant changes, update both formats or make the Markdown/ADR change explicit. Mermaid diagrams in Markdown are manually maintained; rerunning `tools/html_to_agent_md.lua` leaves diagram markers that must be replaced before commit.

Keep experiment source, formal result CSVs and failed crash evidence. Generated caches such as `__pycache__` must not be committed.
