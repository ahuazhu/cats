# Cats agent instructions

## Repository reality

This repository contains a complete Rust V1 development system plus experiments and deployment
code. Implemented and tested areas include `cats-blockd`, kernel-NBD and native vhost-user-blk,
delta packs, golden roots, provider-neutral storage ports, S3/PostgreSQL adapters, a
PostgreSQL-backed Workspace control plane, user/admin consoles, optional WorkOS sessions, CLI,
Gateway, FakeVmm and Cloud Hypervisor Node paths, vsock Guest Agent, systemd Guest PID 1, usage
metering, crash injection, fencing, authorization, drain and cross-node Cold restore.

Do not confuse that with completed production HA. The Rust control path is still V1:
`desired_state/observed_state/generation -> NodeJob`, an in-memory job journal, a full local runtime
ledger and heartbeat state overwrite. The accepted target is ADR-0040/0041/0042:

```text
PostgreSQL DesiredRuntimeSpec(revision)
  -> Node per-Cat level-triggered reconcile
  -> physical inventory + one bounded RuntimeCheckpoint
  -> observation-only status and exact Operation settlement
```

Implement this target as one coherent clean-slate vertical cutover across schema, Controller, Node
reconcile, disk binding, heartbeat, Operation settlement and Route admission, following
[`docs/operations-ha.md` §8](docs/operations-ha.md#8-首次终态部署). The exact release contains one
empty target schema and one protocol version; all old components, parser/write paths and credentials
leave service before it starts. In that release,
`DesiredRuntimeSpec` is the sole lifecycle intent, the per-Cat reconciler is the sole physical-effect
executor, `RuntimeCheckpoint` is the sole restart record and status remains observation-only. These
four facts are the complete coordination authority of that release.

Known blockers that must have characterization tests before the cutover:

- ambiguous AttachDisk completion can leave a physical mount after the control binding rolls back;
- stale generation Jobs/observations can act on or settle a newer runtime;
- current acquire has no expected-owner/takeover authority, so ordinary Start can replace an expired
  owner that still holds unique Relaxed `R < L` data;
- an Agent crash between a physical effect and ledger write can orphan a runtime or local journal;
- same-node dual Agents have no Host-global lock or PostgreSQL AgentSession fence;
- V1 Route Grants have no independent Node installed/closed admission gate;
- PersistentDisk attach has no filesystem UUID, format authority or Guest mount-readiness result;
- the control Store serializes synchronous PostgreSQL work and can block async request workers;
- product DiskSnapshot roots are not yet protected by GC and have no finished same-disk restore path;
  this is separate from the local WarmRuntimeSnapshot path.

Not implemented: Runtime Reconciliation v1, Route Grant v2, Volume Authority, automatic cloud/BMC
Host fencing, cross-Node Guest overlay and privilege separation. HTTP/WebSocket endpoint bridges
and dev E2E exist; the real Cloud Hypervisor/production WebSocket qualification is still missing.
Check the workspace before claiming any module or behavior exists.

## Required reading

Read in this order before a cross-component change:

1. [`docs/architecture.md`](docs/architecture.md)
2. [`docs/README.md`](docs/README.md) for current versus target status
3. Accepted task-relevant ADRs, especially:
   - lifecycle: ADR-0002 and ADR-0040
   - route/admission: ADR-0041
   - storage: ADR-0003, 0005, 0015, 0016, 0017, 0021, 0022, 0025 and 0042
   - ownership/HA: ADR-0018, 0031, 0032, 0034 and 0038
4. Task-specific contract:
   - [`docs/runtime-lifecycle.md`](docs/runtime-lifecycle.md)
   - [`docs/storage.md`](docs/storage.md)
   - [`docs/operations-ha.md`](docs/operations-ha.md)
   - [`docs/specs/runtime-reconciliation-v1.md`](docs/specs/runtime-reconciliation-v1.md)
   - [`docs/specs/route-grant-v2.md`](docs/specs/route-grant-v2.md)
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
- Relaxed successful FLUSH may advance local `L` while remote `R < L`. Pending packs in that window
  are unique data, not deletable cache. Local NVMe is fully disposable only when every retained
  volume has `R == L`.
- Warm, Cold, Snapshot, detach and planned migration require retained volumes at `R == L`.
- Do not upload an entire sparse virtual disk to commit a small dirty set. Current commits publish
  dirty 64 KiB pages as deltas, bounded to four delta layers before a fresh base.
- Lifecycle states are Running / Suspended / Warm / Cold. Suspended retains the VMM and may page out;
  Warm retains a local snapshot and exits the VMM. Both are Host-bound and must not be merged.
- Suspended resume or Warm restore failure protects unique local data first, then converges to a
  provable Cold fallback.
- A heartbeat timeout is suspicion, not fencing. Planned handoff requires exact release followed by
  normal acquire; unplanned cross-Node recovery requires a trusted external HostFenceEvent and an
  exact per-volume takeover authorization.
- Ordinary reconcile never steals/revokes another writer. It reports
  `Blocked(SupersededByAnotherNode)`.
- A normal acquire only accepts the exact unowned epoch; retrying the same transition returns its
  original grant. Volume capacity is immutable in the first terminal release.
- Leaving Running closes local route admission and drains active guards before touching Guest, VMM,
  blockd or attachments.
- Route Grants bind runtime incarnation and one per-Endpoint serving epoch, not the global desired
  revision. An actual gate close can reopen only after a fresh Desired raises that Endpoint epoch;
  unchanged Endpoints do not churn when another Endpoint changes.
- RootDisk follows the Cat. PersistentDisk is independent. Only explicitly disposable Root destroy
  may discard a local tail, and only after an exact authorization CAS changes the current Owned
  volume to Deleting and fences its epoch. Unknown disks and PersistentDisk discard fail closed.
- Missing/corrupt checkpoints or incomplete inventory produce Blocked/Quarantined, never guessed
  Cold and never blind directory deletion.
- A full inventory establishes a session-bound admission attestation. Partial heartbeats may update
  Cat observations but cannot replace that attestation or manufacture a complete scan.
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

## Quality gates

Use:

```bash
./scripts/quality.sh fast
./scripts/quality.sh full
```

`full` is required before handoff. It checks formatting and shared skill links; dependency security,
licenses, sources, version splits and workspace inheritance; build-before-test; Clippy with warnings
denied; workspace tests and rustdoc.

The control-store tests require disposable PostgreSQL. `quality.sh` starts Docker PostgreSQL, CI has
a service container, and `CATS_TEST_POSTGRES_URL` can provide one. Tests fail rather than skip when
none exists.

Pinned dependency tools:

```bash
cargo install --locked cargo-deny --version 0.19.4
cargo install --locked cargo-machete --version 0.9.2
```

Changes touching Linux-only vhost-user-blk or Node code also require a Linux gate. The final gate is
native `quality.sh full` on the configured x86_64 build host. When that host is unavailable during
iteration, use the Docker compatibility gate:

```bash
./scripts/quality.sh linux
```

The Docker Linux gate deliberately builds first and uses a target volume with bounded Cargo jobs.
Report exact commands and results, and separate pre-existing failures from regressions.

Every `quality.sh` run prints the absolute repository root, HEAD, dirty flag and a fingerprint covering
the tracked diff plus untracked files. A result without this provenance is not evidence for a worktree.
Use the configured native x86_64 Linux test host for final Linux build/test and real integration work;
deliver an exact clean commit through the existing content-addressed source bundle and retain its
immutable build receipt. Do not rebuild an ad-hoc test environment when that host and the repository
scripts already cover the gate.

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
