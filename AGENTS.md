# Cats agent instructions

## Repository reality

This repository contains a complete Rust V1 development system plus experiments and deployment
code. Implemented and tested areas include `cats-blockd`, kernel-NBD and native vhost-user-blk,
delta packs, golden roots, provider-neutral storage ports, S3/PostgreSQL adapters, a
PostgreSQL-backed Workspace control plane, user/admin consoles, optional WorkOS sessions, CLI,
FakeVmm and Cloud Hypervisor Node paths, vsock Guest Agent, systemd Guest PID 1, usage metering,
crash injection, drain and cross-node Cold restore.

Do not confuse that with completed production HA. The clean-slate runtime lifecycle authority is
the synchronous semantic model accepted by ADR-0059 and amended by ADR-0062:

```text
PostgreSQL current Cat row + current_action
  -> transaction commits before bounded Control -> noded RPC
  -> noded serializes physical effects per cat_id and returns actual state
  -> Control settles the exact current action

heartbeat / logs / metrics -> liveness and diagnostics only
current ingress target     -> withdraw before transition, publish after Ready
```

The release is one coherent clean-slate vertical cutover across schema, Control, noded effects, disk
binding, Node reset and ingress ordering, following
[`docs/operations-ha.md` §10](docs/operations-ha.md#10-首次单协议部署). It has one empty v20 target
schema and one protocol version. Desired/reconcile, NodeJob, lifecycle Operation, command
poll/result, per-Cat command journal, AgentSession and observation-settlement paths leave service
before it starts. PostgreSQL current resource rows are the sole product intent/result authority;
noded owns actual per-Cat effects and queryable runtime state. Volume owner/epoch/root CAS remains
the independent disk writer authority.

The cutover must retain characterization and regression coverage for these failure modes:

- a noded action may complete after the Control caller times out or exits; recovery must query the
  action's exact target Node before settling the current row;
- a superseded action may return after Destroy has claimed the Cat; exact action occurrence and Node
  matching must reject that late settlement;
- ambiguous attach or detach effects must be discovered rather than blindly rolled back or repeated;
- the provider-neutral normal acquire must not replace an expired owner; the current semantic
  product composes only Strict remote durability and advances an offline owner's epoch under the
  locked PostgreSQL row without claiming trusted Host fencing;
- cancellation or caller loss must not cancel a noded-owned action before its terminal physical
  result is recorded;
- an offline Node can briefly dual-run with its replacement; ingress withdraw/publish ordering and
  reset-on-return must converge it without being described as Host fencing or strict physical RWO;
- PersistentDisk attach must bind filesystem UUID/format authority and an exact Guest
  mount-readiness result;
- the control Store serializes synchronous PostgreSQL work and can block async request workers;
- product DiskSnapshot roots are not yet protected by GC and have no finished same-disk restore path;
  this is separate from the local WarmRuntimeSnapshot path.

Automatic cloud/BMC Host fencing, cross-Node Guest overlay, privilege separation and some real-metal
qualification remain separate work. Check the workspace and calibrated gates before claiming any
module, provider path or production behavior exists.

## Required reading

Read in this order before a cross-component change:

1. [`docs/architecture.md`](docs/architecture.md)
2. [`docs/README.md`](docs/README.md) for current versus target status
3. Accepted task-relevant ADRs, especially:
   - lifecycle: ADR-0002 and ADR-0059, plus the ADR-0062 Destroy preemption amendment
   - ADR-0040, ADR-0041 and ADR-0056 only when historical context or a retained lower-layer storage
     boundary is directly relevant; their lifecycle/AgentSession/Route coordination is superseded
   - storage: ADR-0003, 0005, 0015, 0016, 0017, 0021, 0022 and 0042; ADR-0025 is
     historical because current Strict direct delete has no disposable local-tail authorization
   - ownership/HA: ADR-0018, 0031, 0032, 0034 and 0038
4. Task-specific contract:
   - [`docs/control-node-semantic-protocol.md`](docs/control-node-semantic-protocol.md)
   - [`docs/runtime-lifecycle.md`](docs/runtime-lifecycle.md)
   - [`docs/storage.md`](docs/storage.md)
   - [`docs/operations-ha.md`](docs/operations-ha.md)
   - [`docs/specs/volume-authority.md`](docs/specs/volume-authority.md)
   - [`docs/specs/blockd-protocol.md`](docs/specs/blockd-protocol.md)
5. Experiment reports and raw evidence only when a measured claim matters.

Git history is the documentation archive.

## Source-of-truth precedence

When sources disagree:

1. Accepted, non-superseded ADRs decide component boundaries and failure semantics.
2. Frozen/implemented specs decide current protocols; target specs decide an explicitly scoped
   cutover that is not yet implemented.
3. Rust/SQL and calibrated tests decide what the repository does today.
4. Raw experiment data decides measured facts.
5. Architecture prose composes those facts but cannot manufacture implementation status.

Never turn a prototype or one metal run into a production SLA. Preserve sample count, environment,
measurement boundary and correctness oracle when citing a number.

## Non-negotiable invariants

- The Guest sees standard virtio block devices and unmodified ext4. It never receives object-store
  or MetadataStore credentials.
- A PersistentDisk is RWO in V1. Exactly one attachment epoch may publish writes; old epochs fail
  closed even when an old Host returns.
- Strict successful FLUSH is remotely durable and must survive permanent Host loss.
- The storage engine still defines Relaxed `R < L`, and pending packs in that window are unique data,
  not deletable cache. The ADR-0059 lifecycle may only compose a mode where successful FLUSH is
  remotely durable; it must not create new Node-local-only success states.
- Warm, Cold, Snapshot, detach and planned migration require retained volumes at `R == L`.
- Do not upload an entire sparse virtual disk to commit a small dirty set. Current commits publish
  dirty 64 KiB pages as deltas, bounded to four delta layers before a fresh base.
- Lifecycle states are Running / Suspended / Warm / Cold. Suspended retains the VMM and may page out;
  Warm retains a local snapshot and exits the VMM. Both are Host-bound and must not be merged.
- Suspended resume or Warm restore failure protects unique local data first, then converges to a
  provable Cold fallback.
- A heartbeat timeout is suspicion, not fencing. The current offline/reset protocol deliberately
  accepts a bounded dual-run window and must not claim strict physical single-instance or single-writer
  behavior during it. A trusted external Host fence remains the only proof of Host isolation.
- The provider-neutral normal acquire never steals or revokes another writer. The semantic offline
  recovery adapter may advance the locked offline owner's epoch because product FLUSH is Strict;
  Node reset or ingress withdrawal still is not proof that the old Host stopped.
- A normal acquire only accepts the exact unowned epoch; retrying the same transition returns its
  original grant. PersistentDisk capacity is immutable after create.
- Leaving Running withdraws the current ingress target before touching Guest, VMM, blockd or
  attachments. A new target is published only after noded reports the Guest and all declared mounts
  Ready.
- RootDisk follows the Cat. PersistentDisk is independent. Current product delete first stops
  blockd, releases the exact owner/epoch, and changes only an Unowned volume to Deleting. It has no
  disposable local-tail authorization; unknown or still-Owned disks fail closed.
- Missing, corrupt or ambiguously owned local state produces a typed failure, never guessed Cold and
  never blind directory deletion.
- Heartbeat, logs, metrics and partial runtime observations cannot settle a product action. Recovery
  reads the exact current action and queries its target noded runtime state.
- Guest optional runtime capabilities use HTTP/1.1 on `/run/cats/runtime.sock`; they require no Cats
  SDK/CLI or fixed TCP/UDP port. The VMM never opens this Guest-local socket.
- Do not hard-code cloud account IDs, buckets, instances, credentials or Host paths.

## Storage boundary

Direct-OS ChunkStore is the selected backend. Core contracts live in `storage/`; provider code lives
in `adapters/`. AWS S3 is an adapter, not a dependency of storage semantics. The current Rust engine
is the implementation and `docs/storage.md`/`docs/specs/blockd-protocol.md` describe it. A backend
change requires a new ADR and equivalent correctness evidence.

MetadataStore owner/epoch/root CAS is the writer authority. Its epoch prevents stale remote publish,
but does not prove an old VMM or Host stopped. Route TTL and heartbeat timeout cannot replace Host
fencing.

## Workspace isolation

Every independent feature or bug fix gets its own branch and worktree under `.worktrees/`. Never
develop in the primary checkout: tests spawn processes and rewrite state, and the primary checkout
may contain the user's work.

```bash
git worktree add -b fix/<slug> .worktrees/<slug>
```

Never stash or reset the primary checkout to make room. Remove a worktree only after its branch has
merged. Preserve unrelated dirty files in every checkout.

## Quality checks

Available repository checks:

```bash
./scripts/quality.sh fast
./scripts/quality.sh full
```

`full` checks formatting and shared skill links; dependency security, licenses, sources, version
splits and workspace inheritance; build-before-test; Clippy with warnings denied; workspace tests
and rustdoc.

The control-store tests require disposable PostgreSQL. `quality.sh` starts Docker PostgreSQL, CI has
a service container, and `CATS_TEST_POSTGRES_URL` can provide one. Tests fail rather than skip when
none exists.

Pinned dependency tools:

```bash
cargo install --locked cargo-deny --version 0.19.4
cargo install --locked cargo-machete --version 0.9.2
```

For changes touching Linux-only vhost-user-blk or Node code, the Docker compatibility check is
available when the configured native x86_64 Linux build host is unavailable:

```bash
./scripts/quality.sh linux
```

The Docker Linux gate deliberately builds first and uses a target volume with bounded Cargo jobs.
Report exact commands and results, and separate pre-existing failures from regressions.

Every `quality.sh` run prints the absolute repository root, HEAD, dirty flag and a fingerprint covering
the tracked diff plus untracked files. A result without this provenance is not evidence for a worktree.
The configured native x86_64 Linux test host can be used for Linux build/test and real integration
work. Exact clean commits can be delivered through the existing content-addressed source bundle so
the immutable build receipt is retained. Avoid rebuilding an ad-hoc test environment when that host
and the repository scripts already cover the check.

If the same environment or tool failure recurs, stop retrying the same manual steps. Fix or add the
repository script first. Promote the workflow to a shared skill only when it recurs across tasks and
requires agent judgment beyond a deterministic script.

## Change discipline

- Preserve observable behavior unless the task explicitly changes a contract.
- Before a non-trivial refactor or protocol cutover, add characterization tests for confirmed failure
  modes. A negative probe must be calibrated against a known positive.
- Keep a patch focused. Do not bundle unrelated cleanup with behavior changes.
- Do not add a production dependency without explaining why std/existing dependencies are
  insufficient. Inherit versions from `[workspace.dependencies]`.
- Do not change public APIs, Guest ABI, storage formats or lifecycle semantics implicitly.
- Never globally silence a lint. Keep any suppression narrow and document the invariant.
- Do not introduce an abstraction without a current boundary or multiple real uses.
- Ambiguous external responses require postcondition discovery; do not blindly roll back or repeat a
  destructive effect.
- Audit logging is not a recovery protocol and may not become an authority.

## Rust conventions

- Fallible input, request, persistence and worker paths return errors rather than panic.
- `unwrap`/`expect` belong in tests or obvious, documented local invariants.
- Do not hold mutex/rwlock guards across `.await`; do not run blocking work on async executors.
- Prefer enums/newtypes over boolean flags and string protocols.
- Default visibility to private or `pub(crate)`; public API is deliberate.
- Avoid clones merely to satisfy the borrow checker; document intentionally expensive clones.
- Keep unsafe code isolated and explain every safety invariant.
- Do not leak framework/provider types across domain or provider-neutral boundaries without cause.

## Testing and review

- Test observable behavior, not private implementation details.
- Bug fixes require a regression that fails before the fix.
- Refactors cannot weaken assertions.
- Untrusted parsers need malformed and boundary coverage.
- Concurrency changes cover cancellation, shutdown, restart and resource cleanup.
- Lifecycle/storage changes cover crash points, ambiguous responses, stale identity and fencing.

Review priority:

1. Correctness and data loss.
2. Memory safety and concurrency.
3. Error handling, ambiguity and cancellation.
4. Public API and authority boundaries.
5. Missing tests.
6. Maintainability.

Do not report formatting already enforced by Rustfmt/Clippy. Shared audit/refactor/review workflows
live canonically in `agent-skills/` and are symlinked into `.agents/skills/` and `.claude/skills/`.

## Documentation maintenance

- Architecture is Markdown-only. Do not recreate static HTML companions.
- Keep one canonical explanation per fact and link to it; do not copy rolling status or benchmark
  tables across README/ADRs.
- A decision changing a protocol, persisted format, failure semantic or authority gets a new ADR.
- Delete rejected/unimplemented specs; Git is the archive.
- Preserve experiment source, CSVs, environment reports, raw logs and failed crash evidence.
- Generated caches such as `__pycache__` must not be committed.
