# ADR-0035: Durable LifecycleCommand authority

- Status: Accepted
- Date: 2026-08-06
- Relates to: ADR-0002 (lifecycle states), ADR-0022/0025 (durability and
  destroy), ADR-0028 (Node runtime ledger), ADR-0030 (reported runtime
  reconciliation), ADR-0032 (multi-replica control plane), ADR-0034 (bounded
  PostgreSQL connections); issue #223
- Protocol: [`Lifecycle command and NodeJob V2`](../specs/lifecycle-command-v2.md)
- Qualification: [`Lifecycle authority characterization matrix`](../lifecycle-authority-characterization-test-matrix.md)

## Context

The public Running / Suspended / Warm / Cold model is sound, but the current
control implementation spreads the authority for one transition across:

- `cats.desired_state`, `cats.observed_state`, `cats.generation` and
  `cats.node_id`;
- a current-generation Operation;
- a generation-derived NodeJob ID;
- process-local retry counters, backoff and futures;
- a Node-local runtime ledger and NodeJob result cache;
- heartbeat inventory;
- route rows; and
- storage MetadataStore owner/epoch state.

That shape cannot identify one physical action after a crash. In particular,
`Starting` can mean Start, Resume or Restore; a Job ID derived from
`cat/generation/action` can alias a later physical attempt; a transition result
currently compares only a transitional state; and an Operation can be completed
because a newer generation happens to be converged. A response lost after a
storage fencing call is also ambiguous because an unconditional replay can bump
the epoch again.

Draft implementations in #140 and `140-aba` demonstrated useful exact-CAS and
fencing tests, but also demonstrated the wrong migration shape: an opaque JSON
marker, two controller paths and a larger controller that inferred work from
state. Those branches are evidence, not a base to merge.

The architectural problem is ownership, not a missing conditional in the
controller. Lifecycle work needs one durable relational identity before any
external effect, exact dispatch/result provenance, and a reducer that is the
only component allowed to settle that identity.

## Decision

### 1. PostgreSQL owns lifecycle orchestration

The authoritative lifecycle chain is:

```text
accepted intent
  -> LifecycleCommand
  -> closed-set volume effects and grants
  -> immutable dispatch envelope
  -> durable Node acceptance/claim
  -> immutable terminal result
  -> exact reducer transaction
  -> settled runtime state + exact Operation outcome + route intent
```

PostgreSQL is the only control-plane authority for that chain. Controller
memory, a leader session, queue delivery, a heartbeat, a JSON marker and the
Node runtime ledger are not alternate authorities. They can execute, notify or
report facts; losing any of them must leave enough relational work to resume or
an explicit fail-closed record.

This decision does not create a generic workflow engine. The model is a closed
set of Cat lifecycle commands, volume effects and Node actions. The production
code is split by current boundaries: acceptance, pure planning, storage
effects/grants, dispatch, result reduction and recovery.

### 2. Authoritative relational entities

A1 (#224) implements the schema, but the following identities and constraints
are normative.

| Entity | Immutable identity | Mutable state it owns | Required constraint |
| --- | --- | --- | --- |
| Cat intent | `cat_id + intent_generation` | desired stable state | Generation is allocated only by lifecycle acceptance; desired `Deleted` is irreversible. |
| LifecycleCommand | `command_id` plus `(cat_id, intent_generation, command_seq)` | the current exact command and its phase | At most one `current` command per Cat. Kind/source/target/Operation are immutable. |
| Volume effect | `effect_id` plus command/volume/closed effect kind | planned/applied/rejected effect and MetadataStore receipt | Same effect identity cannot name another request; applied requires an exact receipt. |
| Volume grant | `grant_id` plus command/dispatch/node/volume | pending/acquired/invalidated/released grant | Attachment identity is unique to one grant; invalidation is monotonic. |
| Dispatch | `dispatch_id` plus `(command_id, dispatch_seq)` | durable payload, controller executor claim and Node acceptance | Wire bytes, digest, target Node and prerequisites are immutable; one nonterminal dispatch per command. |
| Node claim | `node_claim_id` scoped to `dispatch_id` | Node-local processing/execution/adoption identity | Created durably when the Node first accepts or rejects a recognized dispatch, before the first physical side effect, and never reused. A rejected claim authorizes no execution. |
| Result | `result_id` scoped to dispatch and Node claim | immutable accepted/progress/terminal evidence | A terminal result is immutable; duplicate ID with different bytes is corruption. |
| Settled runtime | one `cat_runtime_state` row | last reducer-authorized stable physical state and provenance | It names the exact command, dispatch, claim and terminal result that settled it. |
| Runtime observation | node/agent/heartbeat sequence/Cat | what an Agent most recently reported | Observation cannot update command, settled runtime, Operation, route, placement or storage authority. |

Opaque payloads may be retained as audit evidence, but no query needed to find,
claim, fence, dispatch or settle work may decode a JSON marker. Closed enums,
foreign keys, unique indexes, check constraints and immutable columns express
the authority model.

`cats.observed_state` becomes a compatibility/API projection during migration.
The authoritative settled physical state is `cat_runtime_state`; a transitional
label is derived from the current command kind and phase. A generic `Starting`
value never identifies a physical action.

### 3. Command identity and command chains

`intent_generation` identifies accepted desired intent. It does not identify a
physical command. One intent may require a chain of commands; for example,
Cold -> Warm is Start -> Suspend -> Warm. Each leg receives a new opaque
`command_id` and increasing `command_seq`, while retaining the same Operation
and intent generation.

The command kinds are closed:

```text
Start | Resume | Restore | Suspend | Warm | Cold | Destroy | FallbackCold
```

`FallbackCold` is explicit authority created after a failed Resume/Restore or
after another transition proves that its Host-bound source is unusable. It is
not an unrecorded `CleanupCat` side call. Destroy-related physical cleanup is
part of `Destroy`; a generic cleanup job that omits disk retention semantics is
not part of V2.

Command state fields have two explicit domains. `source_state` is
`absent | running | suspended | warm | cold`; `absent` means there is no
settled runtime, as on initial create or a proven-clean failed Start.
`target_state` is `running | suspended | warm | cold | deleted`. `deleted` is
valid only for Destroy and is a terminal **resource** state/tombstone, not a
fifth ADR-0002 runtime state. A successful Destroy leaves no settled runtime;
it does not write `deleted` into `cat_runtime_state`. All non-Destroy commands
target one of the four runtime states.

Command phases are durable and queryable:

```text
planned -> preparing -> dispatchable -> dispatched -> accepted -> settling
        \-> blocked
terminal: succeeded | failed | cancelled_before_dispatch | superseded
```

`blocked` remains current work. It is used for a missing safety proof,
indeterminate external effect, unavailable source with retained local data, or
an operator-required fence. It must appear in recovery and stuck-work queries.
It is not converted to success or a silent no-op.

`authority_revision` (or an equivalent row version) changes on every phase
transition. Every writer compares the exact revision and current-command
identity. Kind, source state, target state, intent generation, command sequence,
Operation and predecessor/successor links never change in place.

### 4. Exact lifecycle planning

A2 (#225) is a pure, exhaustive planner. Given an immutable authoritative
snapshot, it returns exactly one of: no-op, wait, reject, supersede, propose one
closed command, or invariant error. It performs no database or external I/O and
has no default arm for a reachable combination.

The stable-state paths are:

| Settled state | Desired state | Exact next command |
| --- | --- | --- |
| Cold / Creating / retry-authorized Failed | Running | Start |
| Suspended | Running | Resume |
| Warm | Running | Restore |
| Running | Suspended | Suspend |
| Warm | Suspended | Restore, then Suspend |
| Cold | Suspended | Start, then Suspend |
| Suspended | Warm | Warm |
| Running | Warm | Suspend, then Warm |
| Cold | Warm | Start, then Suspend, then Warm |
| Running / Suspended / Warm | Cold | Cold |
| Cold | Cold | no-op |
| Any non-deleted state | Deleted | Destroy |

The planner uses settled runtime provenance and the active command, never a
generic transitional label. A host-bound Resume or Restore is allowed only on
the exact Node/runtime/snapshot identity. A missing or mismatched identity
proposes `FallbackCold` once the source can be retained or fenced safely.

Desired `Deleted` and a current Destroy command are terminal authority. Start,
wake, Resume, Restore, expiry extension or policy work cannot supersede them.
Destroy may remain `blocked` until retained volumes are safe; an Operation
error does not resurrect the resource.

### 5. Supersession and cancellation

Accepting a conflicting newer intent performs one transaction:

1. lock the Cat and current command;
2. allocate the new intent generation and Operation;
3. mark the old command `superseded` and link it to the successor;
4. create the successor as the sole current authority; and
5. record whether it is blocked by an older nonterminal dispatch, grant or
   external effect.

Supersession revokes authority to settle; it does not pretend already-dispatched
physical work vanished. A successor cannot dispatch an incompatible action
until the older dispatch has a terminal result, its future volume acquisition
has been invalidated, or the old runtime/writer has been externally fenced.

A late result is always stored as immutable evidence. If its command is no
longer current it cannot settle Cat state, complete an Operation, publish a
route or grant a volume. The planner may use the proven physical outcome when
planning the successor. Example: if a superseded Suspend succeeds after a wake
request, the wake command becomes Resume rather than Start.

Cancellation before a dispatch is durable
`cancelled_before_dispatch`. After durable Node acceptance, cancellation is a
successor command plus the same retirement/fencing rules; it is never deletion
of the old row or cancellation of a controller future.

A semantic retry after a terminal Rejected/Failed result uses a new
`dispatch_id` and increasing `dispatch_seq` under the same command, after the
planner revalidates the source. A transport retry or result query reuses the
same dispatch ID and byte-identical payload. These two retry classes must not
be conflated.

### 6. Request acceptance and Operation ownership

A4 (#227) is the only entry point that accepts lifecycle intent. Its transaction
contains idempotency lookup, preconditions, Cat lock, generation allocation,
Operation creation, command creation/supersession and an after-commit wakeup.
It performs no external call.

Idempotency lookup for the exact route/action occurs before reevaluating the
original `If-Match`: if the first request committed and its HTTP response was
lost, the same key returns the original Operation even though the generation
has advanced. Reuse of a key with a different route, action or request digest
is rejected.

One Operation may cover a command chain and internal FallbackCold. It succeeds
only from the exact terminal command/result required by that Operation. It is
never completed because `(desired_state == observed_state)`, because another
Operation converged, or because `operation.resource_generation <=
cat.generation`. Superseded Operations receive an explicit superseded/cancelled
terminal outcome and successor reference.

### 7. Dispatch and NodeJob V2

A5 (#228) persists an exact NodeJob V2 envelope and commits it before network
I/O. A short controller executor claim may prevent duplicate sends, but it is
only scheduling metadata; expiry transfers execution of the same durable
dispatch, not lifecycle authority.

For a new authenticated, well-formed dispatch, the Node's first durable record
is either Accepted or terminal Rejected, both with a fresh `node_claim_id`.
That record precedes touching a volume, process, cgroup, tap or snapshot; a
Rejected claim authorizes none of those effects. Replaying the same dispatch
and exact body returns the same acceptance/progress/result. Reusing the
dispatch ID with different bytes is rejected before any side effect. Every
terminal outcome after recognizing a dispatch, including Rejected and Failed,
is durable; a semantic retry is a new dispatch.

A recognized dispatch rejected for stale command authority, runtime
precondition or grant state returns HTTP 409 with that durable terminal
Rejected envelope. The same dispatch remains queryable after Agent restart and
returns the same claim/result. Authentication, malformed envelope, wrong
target, header/body digest mismatch, or reuse of an existing dispatch ID with
different bytes fails before recognizing a new dispatch and creates no claim.
The exact HTTP/GET distinction is normative in the V2 specification.

A successful result is not merely a transient HTTP 200. It names the command,
dispatch, Node claim, intent generation, action and request digest, and carries
the postcondition evidence. For Start/Resume/Restore it is successful only
after C's Node runtime ledger durably proves adoption of the resulting runtime.

The separate V2 endpoint and fields are specified in
[`lifecycle-command-v2.md`](../specs/lifecycle-command-v2.md). V1 payloads are
never reinterpreted as V2, and a missing epoch/claim is not treated as zero or
backfilled from a path name.

### 8. Exact result reduction

A6 (#229) is the only component allowed to apply a Node result to control
authority. It first persists or matches the immutable result, then in one
transaction locks and compares the Cat, current command, dispatch,
`node_claim_id`, intent generation, authority revision and request digest.

An exact result may atomically:

- advance/terminate its command;
- update `cat_runtime_state` with complete provenance;
- propose the next command in the same intent chain;
- complete the exact Operation;
- update placement ownership when the command semantics require it; and
- persist a route publish/unpublish intent or outbox event.

Route/DNS/gateway mutation occurs after commit through the Route Controller.
It must consume the exact durable route intent and activation epoch. The
reducer never waits on route or another network service inside its transaction.

Duplicate exact results are no-ops. Mismatched results fail closed. Stale
results are retained and marked stale/superseded evidence but make none of the
authority changes above.

### 9. Failure and Cold fallback semantics

| Failed action | Required behavior |
| --- | --- |
| Start | If no runtime/grant was acquired, retain Cold and allow a new dispatch after policy. If acquisition/runtime is indeterminate, block until query or fence proves it. After the configured semantic retry budget, settle Failed for this intent. |
| Suspend | If Node proves Running was preserved, the command may retry or be superseded. If runtime integrity is lost, create FallbackCold. |
| Warm | If Suspended plus all local journals are preserved, retry without cleanup. If runtime is lost, create FallbackCold only after retained volumes are remote durable or their unique local journals remain owned. |
| Resume / Restore | Create durable FallbackCold. Do not directly mark Cold, discard a snapshot/journal or issue an untracked cleanup request. |
| Cold | A drain/network/DB failure keeps the source runtime, blockd, lease and local journal and remains blocked/retryable. A proven absent Host requires external fencing before placement transfer. |
| Destroy | Explicit disposable RootDisk tails may be discarded only under ADR-0025. Every retained PersistentDisk must drain; otherwise Destroy stays current and blocked. |

FallbackCold uses the same exact command/effect/dispatch/result chain. Relaxed
`L > R` is a safety fact: pending packs are unique authoritative data, not
cache. No fallback may revoke/release a retained volume, delete its directory
or report Cold until `R == L`, or until a separately authorized Host-loss path
records the acknowledged loss and fences the old writer. The latter is not an
ordinary transition retry.

### 10. MetadataStore effects and replay

MetadataStore is outside the control transaction even when its adapter happens
to use the same PostgreSQL instance. No database transaction or row/advisory
lock is held across a MetadataStore, Node, route or other network call.

Every mutating lifecycle storage effect is first persisted in a
command-specific relational row. The effect kind is a closed enum such as
ensure volume, conditionally invalidate/acquire/revoke/release a grant, or
delete a tombstoned volume. Each call carries an immutable `effect_id`, exact
expected predecessor state and request digest.

The MetadataStore contract used by lifecycle V2 must persist an idempotency
receipt atomically with the mutation:

```text
apply(effect_id, exact_expected_state, exact_request)
  -> same receipt on exact replay
  -> conflict on same effect_id with different request
  -> conditional rejection if predecessor state changed
```

The control-side effect phases are:

```text
planned -> applying -> applied(receipt)
                    \-> rejected(receipt)
                    \-> indeterminate
```

`applying` or a lost response is recovered by querying/replaying the same
effect ID. An epoch-changing operation that has no receipt/replay mechanism is
not V2-capable and cannot be used. In particular, blindly replaying the current
unconditional `revoke_lease(volume)` is forbidden because it can advance an
epoch twice and revoke a replacement writer.

A command becomes dispatchable only after every required pre-dispatch effect
has an exact applied receipt and every grant is still valid. Delete effects
require a persisted Destroy/tombstone decision and proof that retained volumes
crossed their durability boundary.

### 11. Transaction and lock order

All multi-row mutations use a documented transaction family. Locks are never
held across external I/O. Within a family, locks are acquired in this order:

| Transaction family | Lock order |
| --- | --- |
| Request acceptance | request-key transaction advisory lock -> Cat -> current command -> Operation/idempotency rows |
| Ordinary planner/dispatcher/reducer | Cat -> command -> dispatch -> volume effects/grants and disks sorted by `volume_id` -> Operation -> route intent |
| Placement | fleet placement transaction advisory lock -> candidate Node rows sorted by `node_id` -> Cat -> command/dispatch |
| Node fence/recovery | node-fence transaction advisory lock -> Node -> affected Cats sorted by `cat_id` -> their commands/dispatches -> grants sorted by `volume_id` -> route intents |
| Heartbeat observation | Node -> normalized observation rows only; no Cat/command/Operation/route/volume locks |

Request acceptance never also performs placement or Node fencing. A code path
that must join transaction families is split by a durable row/outbox boundary.
It must not acquire an earlier-ranked lock after a later-ranked lock. Session
advisory locks are reserved for bounded singleton leadership under ADR-0032;
there is no per-Cat session lock and no correctness dependency on an RDS Proxy
backend session remaining pinned.

PostgreSQL deadlock detection is a final guard, not the ordering mechanism.
A deadlock/serialization failure aborts the transaction and retries from a new
authoritative snapshot; it never retries only the final write.

### 12. Heartbeat is observation only

The Agent heartbeat writes a normalized, versioned observation set with
`node_id`, `agent_instance_id`, monotonic heartbeat sequence, Cat identity,
runtime generation/identity and reported state. Replacing the complete set is
atomic for that heartbeat. Staleness and missing entries remain visible.

Heartbeat may:

- drive Node liveness/conditions;
- expose inventory and orphan-runtime differences;
- wake the lifecycle/runtime-ownership reconciler; and
- provide evidence that causes the reconciler to query the durable NodeJob or
  adoption result.

Heartbeat may not directly write `cats.observed_state`, settle a command or
Operation, publish/unpublish a route, move placement, create/release a volume
grant, or turn a reported state into a synthetic NodeJob result. A missing
heartbeat is suspicion, not proof that a Host or writer stopped.

Lost Node recovery still applies ADR-0027's complete same-generation claim
rule, excluding desired Deleted claims. Under V2 the Node controller evaluates
that rule from normalized observation plus durable placement/runtime ownership
and records a separate recovery decision; the heartbeat handler itself remains
observation-only.

### 13. Authority ownership map

| Mutable fact | Sole owner and persistence boundary | Readers / non-owners |
| --- | --- | --- |
| Desired stable state and intent generation | Lifecycle request/policy acceptance transaction in `cats` | Planner and API are readers. |
| Current command, phase and supersession | Lifecycle command store through acceptance/reducer CAS | Controllers execute; memory is disposable. |
| Operation identity and terminal outcome | Operation row linked to exact intent/root command; exact reducer completes it | Newer convergence cannot complete it. |
| Dispatch bytes and controller executor claim | Lifecycle dispatch store | Queue/HTTP are delivery mechanisms. |
| Node execution claim and physical result | C Node runtime/job ledger, mirrored immutably into control PostgreSQL | Heartbeat is not a result. |
| Settled runtime state | Exact reducer transaction in `cat_runtime_state` | `cats.observed_state` is temporary projection. |
| Process/PID/snapshot/local journal existence | C Node runtime ledger with PID/runtime identity proof | It never grants storage authority. |
| Placement/reservation | Scheduler/placement transaction under the fleet lock | Lifecycle consumes the exact placement identity. |
| Volume grant and invalidation | A7/D relational grant plus MetadataStore receipt | Node may exercise only the exact valid grant. |
| Volume root/owner/epoch | MetadataStore conditional CAS and receipt | Control lifecycle cannot synthesize an epoch. |
| Route binding/activation epoch | Route Controller from durable reducer route intent | Node heartbeat cannot publish a route. |
| Latest reported inventory | Normalized heartbeat observation rows | Orphan/recovery views derive from it. |
| Backoff, semaphore, future, leader handle | No authority; process-local optimization only | Loss must not lose or change work. |

### 14. Component boundaries for A1-A9

| Slice | Boundary fixed by this ADR |
| --- | --- |
| A1 #224 | Relational entities, FKs, immutable identity, one-current-command constraint, work/recovery indexes and explicit ambiguous migration rows. |
| A2 #225 | Pure exhaustive planner over typed snapshots; no Store, HTTP, MetadataStore or process effects. |
| A3 #226 | Separate NodeJob V2 endpoint, exact wire bytes/digest, durable Node claim and all terminal results, coordinated with C. |
| A4 #227 | Sole transactional lifecycle acceptance; exactly one generation, Operation and root command before notification. |
| A5 #228 | Durable payload/effect prerequisites, bounded dispatch and level-triggered recovery; no giant reconciler. |
| A6 #229 | Exact result reducer and command-chain/fallback proposal; no external I/O in reducer. |
| A7 #230 | Conditional unique volume grants and idempotent MetadataStore receipts, coordinated with C and D. |
| A8 #231 | Expand/Shadow/Freeze/Activate/Contract rollout and deletion of every legacy/temporary path. |
| A9 #232 | Independent correctness/data-safety/concurrency/migration qualification against the separate matrix. |

The intended code shape is focused lifecycle modules (`domain`, `planner`,
`acceptance`, `effects`, `dispatcher`, `reducer`, `recovery`) and a concrete
PostgreSQL store. This does not justify a generic repository trait, generic
workflow DSL, giant controller or new abstraction without another real use.

### 15. Migration, activation and rollback

The rollout is **Expand -> Shadow -> Freeze -> Activate -> Contract**.

#### Expand

- Add the normalized schema, constraints, work indexes and version/capability
  fields without changing the current V1 writer.
- Add a separate `/v2/jobs/...` endpoint. Old Agents continue to implement the
  unchanged V1 endpoint; new Agents implement both. V1 fields are never
  reinterpreted as V2.
- Backfill only stable rows whose Cat, placement, Node inventory and volume
  topology agree. Transitional, missing or contradictory evidence becomes an
  explicit ambiguous repair row and fails closed.

#### Shadow

- Run the V2 planner and reducer as read-only comparison code. It may persist
  labelled shadow decisions for audit but has no credential/code path to
  dispatch, mutate Cat/Operation/route authority or call MetadataStore.
- V1 remains the only writer. This is not a dual-controller phase.
- Compare exact decisions against the characterization matrix and account for
  every mismatch before Freeze.

#### Freeze

- Database-enforce rejection of new V1 lifecycle mutations and disable policy
  transitions/wake sources.
- Let already accepted V1 work reach a stable state, or explicitly repair/fence
  it. Require no V1 transitional Cat, in-flight lifecycle request, unresolved
  Node job, pending grant or ambiguous volume effect.
- Snapshot the control database and record the RC commit, schema version,
  protocol versions, Node capabilities and row counts.

#### Activate

- Atomically change the database authority version to V2 and enable exactly
  one V2 acceptance/planner/dispatcher/reducer path.
- Old binaries fail closed against the authority-version gate. They cannot
  bypass Freeze or write old lifecycle columns.
- Unfreeze API/policy work only after the V2 recovery scan accounts for every
  current/nonterminal command.

Activation is a one-way authority cutover. After any V2 dispatch, "rollback"
means roll back to a V2-compatible binary that continues to honor the same
schema and protocol, or freeze and forward-fix. It does not mean re-enable the
V1 writer, which cannot represent V2 command/claim/result facts. A reverse
authority cutover is permitted only in a rehearsal before any V2 dispatch, or
after proving all Cats stable, all V2 work/effects/grants absent, and a
lossless V1 projection; the default production runbook treats that proof as
unavailable.

#### Contract

Contract is complete only when known-positive inventory proves all of the
following:

- every active Node is V2-capable and no V1 lifecycle job remains in a Node
  journal, retry queue or operational replay window;
- no deployed binary can write V1 lifecycle authority;
- every Cat has normalized command/runtime provenance or an explicit repaired
  stable state;
- no shadow mismatch or ambiguous backfill row remains;
- migration and V2-compatible binary rollback rehearsals passed against a
  production-snapshot-shaped database; and
- A9 passed the failure, data and mixed-version matrix.

Then remove, rather than disable:

- any opaque lifecycle JSON marker or JSON equality CAS;
- shadow tables/flags and Phase-A/Phase-B or V1/V2 dual controller paths;
- generation/action-derived lifecycle Job IDs and ephemeral failed-result
  handling;
- lifecycle dispatch through `/v1/jobs` and its compatibility projection;
- direct heartbeat writes to observed lifecycle state;
- convergence shortcuts (`desired == observed`, `<= generation` Operation
  completion), generic cleanup/discard fallbacks and the giant legacy
  `reconcile_cat`; and
- migration repair code and temporary feature flags.

The V1 endpoint may remain temporarily for non-lifecycle actions only if its
route cannot decode or execute a lifecycle action. Otherwise it is deleted.

### 16. Multi-AZ boundary

Multi-AZ implementation is deferred. This contract leaves the necessary
boundary: PostgreSQL is durable transactional authority, Node/MetadataStore
effects are idempotent and queryable, controllers are disposable, and no
correctness fact depends on process memory or one database session.

This ADR does not provision or qualify RDS Multi-AZ, cross-AZ Node placement,
cross-region authority, or automatic Host fencing. ADR-0032's managed failover
and ADR-0034's proxy qualification remain separate infrastructure gates. A0-A8
may be implemented and tested on a single-AZ RC environment; A9 must retain
environment/failover scope and must not turn it into an availability claim.

## Consequences

The lifecycle system gains an exact answer to "what may execute and what may
settle?" after any controller, connection or response loss. Start/Resume/
Restore remain distinct; stale results and delayed storage acquisition fail
closed; Operation completion is exact; and heartbeat cannot overwrite command
authority.

The cost is more explicit relational state and more phases. That state is the
design, not scaffolding to hide: it replaces process-local ambiguity. The
implementation must keep the modules narrow and delete the old path after
activation, so the end state has one architecture rather than a permanent
compatibility heap.

## Rejected alternatives

- **Patch the current `desired/observed` match arms.** Transitional state still
  cannot identify an exact physical action or stale result.
- **Derive Job identity from Cat/generation/action.** It aliases semantic
  retries and ABA sequences and cannot bind a Node claim or immutable payload.
- **Opaque JSON command marker.** Database constraints and recovery queries
  cannot validate its internal authority without application decoding.
- **Keep V1 and V2 writers for rollback.** Two authorities create the race this
  ADR removes. Rollback stays V2-compatible after activation.
- **Use a PostgreSQL session lock per Cat.** Session loss would become an
  authority transition and RDS Proxy pinning would scale with Cats. Durable
  rows and transaction locks are the boundary.
- **Let heartbeat settle state.** Inventory is delayed observation and lacks
  exact command/result provenance.
- **Blindly replay MetadataStore mutations.** Unconditional epoch operations
  can fence the wrong writer after a lost response; exact effect receipts are
  required.
- **Build a generic workflow engine or giant controller.** Lifecycle has a
  small closed vocabulary and existing domain boundaries; generic machinery
  would obscure rather than reduce its invariants.
