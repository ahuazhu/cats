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
| Request receipt | `request_receipt_id` plus `(workspace_id, route/action, idempotency_key)` | immutable request digest, exact replay response and optional already-satisfied completion provenance | Exact-key/exact-digest replay returns the original response. A semantic no-op binds this receipt one-to-one to a terminal Operation but allocates no intent generation or command. |
| Policy transition proposal | `policy_proposal_id` | non-authoritative auto-suspend eligibility snapshot and retirement progress | It binds the exact current intent/generation, Running runtime, route epoch and work fence. It cannot change desired authority, allocate a generation/Operation/command or cancel active work. |
| Cat intent | `cat_id + intent_generation` | desired stable state and `current/waiting/resolved/superseded` authority | At most one current accepted intent per Cat. Generation is allocated only for a real intent change; desired `Deleted` is irreversible. |
| Intent resolution | `intent_resolution_id` scoped to intent | exact source-evidence adoption, wait reason or evidence-only settlement | It names an exact settled runtime/result/fence and cannot fabricate a Node result. |
| Operation | `operation_id` | exact API-visible progress/outcome for one accepted request | Its authority root is exactly one of `intent_id` or `already_satisfied_receipt_id`. An intent-rooted Operation is valid while the intent waits with no command; an already-satisfied Operation is terminal Succeeded and references the existing Cat generation and exact settled-runtime provenance. |
| LifecycleCommand | `command_id` plus `(cat_id, intent_generation, command_seq)` | one exact executable command and its phase | At most one current executable command per Cat. Kind/source/target/Operation/source evidence are immutable and are chosen only after the evidence exists. |
| Volume effect | `effect_id` plus command/volume/closed effect kind | planned/applied/rejected effect and MetadataStore receipt | Same effect identity cannot name another request; applied requires an exact receipt. |
| Volume grant | `grant_id` plus command/dispatch/node/volume | pending/acquired/invalidated/released grant | Attachment identity is unique to one grant; invalidation is monotonic. |
| Route retirement | `retirement_id` scoped to exactly one route intent, lifecycle command or policy proposal and exact runtime/epoch | `cancel_and_drain` or `require_idle`, with planned/prepared/applying/applied/busy/blocked plus B/C proof/receipt | A command leaving Running cannot dispatch before exact epoch revocation and zero-guard/fence proof. `require_idle` never cancels a guard or changes route authority when busy. |
| Dispatch | `dispatch_id` plus `(command_id, dispatch_seq)` | durable payload, controller executor claim and Node acceptance | Wire bytes, digest, target Node and prerequisites are immutable; one nonterminal dispatch per command. |
| Node claim | `node_claim_id` scoped to `dispatch_id` | Node-local processing/execution/adoption identity | Created durably when the Node first accepts or rejects a recognized dispatch, before the first physical side effect, and never reused. A rejected claim authorizes no execution. |
| Result | `result_id` scoped to dispatch and Node claim | immutable accepted/progress/terminal evidence | A terminal result is immutable; duplicate ID with different bytes is corruption. |
| Settled runtime | one `cat_runtime_state` row | last reducer-authorized stable physical state and provenance | It stores `intent_generation` and the complete shared `SettledLifecycleLineageV1`. Evidence-only re-authorization retains the originating physical lineage byte-for-byte and records its new authorizing intent/resolution separately. |
| Route publication intent | `route_intent_id` | immutable bind/unbind handoff and B receipt/terminal stale result | The same ID and complete shared lineage continue into the materialized Route, Node ACK and local authority; A never allocates a route epoch. |
| Runtime observation | node/agent/heartbeat sequence/Cat | what an Agent most recently reported | Observation cannot update command, settled runtime, Operation, route, placement or storage authority. |

Opaque payloads may be retained as audit evidence, but no query needed to find,
claim, fence, dispatch or settle work may decode a JSON marker. Closed enums,
foreign keys, unique indexes, check constraints and immutable columns express
the authority model.

The lifecycle/route boundary shares this exact value object with B and C:

```text
SettledLifecycleLineageV1 {
  command_id + command_seq
  dispatch_id + dispatch_seq + request_body_sha256
  target_node_id
  node_claim_id
  result_id
  runtime_identity {
    runtime_id + runtime_generation
    host_boot_id? + guest_boot_id?
  }
}
```

Every member is mandatory except the two explicitly optional boot IDs. The
value is the originating physical settlement, not the latest request's
provenance. An evidence-only settlement or policy compensation MUST retain it
unchanged and record the current `intent_generation` and
`intent_resolution_id` beside it; it MUST NOT erase command, dispatch, claim or
result fields. An implementation MAY persist an audit digest in addition, but
an undefined or digest-only representation is never authority and cannot
replace field equality.

`cats.observed_state` becomes a compatibility/API projection during migration.
The authoritative settled physical state is `cat_runtime_state`; a transitional
label is derived from the current command kind and phase. A generic `Starting`
value never identifies a physical action.

### 3. Command identity and command chains

`intent_generation` identifies an accepted desired intent. It does not identify
a physical command, and an accepted intent may durably exist without an
executable command while predecessor work is unresolved. One intent may require
a chain of commands; for example, Cold -> Warm is Start -> Suspend -> Warm.
Each materialized leg receives a new opaque `command_id` and increasing
`command_seq`, while retaining the same Operation and intent generation.

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

Every command binds an immutable `source_evidence_id`. The referenced intent
resolution contains exactly one of:

```text
settled_runtime(runtime_revision, originating command/dispatch/claim/result,
                runtime_id)
predecessor_result(result_id, source_disposition, runtime_id)
fence(fence_receipt_id, proven runtime/writer disposition)
absence(absence_receipt_id)
```

The evidence must already be durable before the command is inserted. A command
kind never changes after insertion. Waiting for an old result/fence is a phase
of the accepted intent, not a placeholder Start/Resume/Restore command.

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
| Any stable state | Same desired stable state | acceptance no-op; no new intent/command |
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

1. lock the Cat, current intent and current command;
2. allocate the new intent generation and Operation;
3. make the new intent the sole current desired authority and supersede the old
   intent/command's authority to settle;
4. retain any accepted/dispatched predecessor as physical work whose exact
   outcome must still be learned or fenced; and
5. record the new intent as `waiting_predecessor` when its executable source is
   not yet proven. No successor command is inserted in that case.

Supersession revokes authority to settle; it does not pretend already-dispatched
physical work vanished. The current accepted intent is authority even while it
has no command. A successor command cannot be materialized or dispatched until
the older dispatch has a terminal result, its future volume acquisition has
been invalidated, or the old runtime/writer has been externally fenced.

A late result is always stored as immutable evidence. If its command is no
longer current it cannot settle Cat state, complete an Operation, publish a
route or grant a volume by itself. The current-intent reducer may atomically
adopt that exact result into a new `intent_resolution`, re-authorize its proven
physical state in `cat_runtime_state`, and then do exactly one of:

- materialize an immutable command bound to that resolution;
- settle the current intent/Operation as `satisfied_by_evidence` without a Node
  command; or
- remain durably waiting/blocked for a query, fence or operator decision.

For example, if a superseded Suspend succeeds after a wake request, the result
proves Suspended and the planner inserts a new immutable Resume command. If it
fails with exact `source_disposition=preserved` and proves the same Running
runtime, the wake intent is satisfied by that result. If it is indeterminate,
no action kind is guessed; the intent waits for query/fence and may later
materialize FallbackCold from exact evidence. A command never "becomes Resume".

Cancellation before a dispatch is durable
`cancelled_before_dispatch`. After durable Node acceptance, cancellation is a
new current intent plus the same predecessor retirement/fencing rules; it is
never deletion of the old row or cancellation of a controller future.

A semantic retry after a terminal Rejected/Failed result uses a new
`dispatch_id` and increasing `dispatch_seq` under the same command, after the
planner revalidates the source. A transport retry or result query reuses the
same dispatch ID and byte-identical payload. These two retry classes must not
be conflated.

### 6. Request acceptance and Operation ownership

A4 (#227) is the only entry point that accepts lifecycle intent. Its transaction
performs idempotency lookup, preconditions and the Cat lock before deciding
whether the request is a semantic no-op or a real intent change. It performs no
external call.

Idempotency lookup for the exact route/action occurs before reevaluating the
original `If-Match`: if the first request committed and its HTTP response was
lost, the same key returns the original response even when authority has since
advanced. Reuse of a key with a different route/action/request digest is
rejected. The request digest covers the canonical method/route, Workspace and
Cat, requested desired state, original precondition and exact body bytes.

Under the Cat lock, a request is `already_satisfied` only when the authoritative
settled state exactly equals the requested stable state and there is no current
intent, nonterminal/retiring command, unresolved predecessor/effect/grant,
live policy transition proposal or uncompensated route retirement that can
change that fact. This check occurs before any
intent-generation or command allocation. To preserve the existing mutation API,
the transaction atomically persists an immutable request receipt and a fresh
terminal Succeeded Operation containing:

```text
request_receipt_id
workspace_id + canonical route/action + idempotency key
request_digest
outcome = already_satisfied
cat_id
existing intent_generation
exact cat_runtime_state revision + physical provenance digest
operation_id
exact serialized response bytes + response digest
```

The Operation has typed outcome `already_satisfied`, sets
`resource_generation` to the existing Cat generation, and binds its completion
provenance to the receipt's exact settled-runtime revision and physical
provenance digest. The API still returns `202 Accepted` with the existing
`CatOperationResponse { operation, cat }` shape. It does not advance intent
generation, create an intent/command, send a wakeup, create a route intent,
allocate/revoke an epoch or otherwise touch route authority. Exact replay
returns the same receipt, Operation and byte-identical response. A fresh
idempotency key may create a new terminal already-satisfied Operation, but
still changes no lifecycle or route authority. Same key/different digest
conflicts. Deleted is handled by the resource's terminal API semantics, not by
fabricating a runtime no-op.

For a real intent change, the same transaction allocates exactly one generation
and Operation, creates the current intent, supersedes older authority, records
any predecessor wait and emits an after-commit wakeup. It may materialize the
first command only if exact source evidence already exists and no predecessor
blocks it; command creation is not a condition of intent acceptance.

A real-change Operation may cover a command chain and internal FallbackCold. It
succeeds only from the exact terminal command/result or explicit
`satisfied_by_evidence` intent resolution required by that Operation. Every
Operation has an exclusive authority-root union:

```text
intent_id XOR already_satisfied_receipt_id
```

An intent-rooted Operation exists and remains queryable even when its intent is
`waiting_predecessor` and no command has been materialized. Its terminal
completion binds the exact `intent_resolution_id` and, when applicable, the
terminal command/result/fence evidence. The receipt-rooted variant is created
terminal Succeeded during acceptance and cannot later acquire an intent or
command. An intent-rooted Operation is never completed because
`(desired_state == observed_state)`, because another Operation converged, or
because `operation.resource_generation <= cat.generation`. Superseded
Operations receive an explicit superseded/cancelled terminal outcome and
successor reference.

#### Policy auto-suspend is proposed before authority changes

The `LIFE-AUTO-001` invariant remains normative: active platform, HTTP,
WebSocket, exec or Guest work prevents auto-suspend. An automatic policy may
not accept a Suspended intent and then use route retirement to cancel the work
that should have prevented that intent.

The policy evaluator first persists a non-authoritative
`PolicyTransitionProposal`:

```text
policy_proposal_id
cat_id + target = Suspended + policy kind/version
expected Cat generation + current_intent_id?
expected desired state = Running
old_install_id + old_route_intent_id + old_route_epoch
old_settled_lineage: SettledLifecycleLineageV1
expected route authority revision
control work_version + Guest source epoch/lease sequence/freshness deadline
work provenance digest
phase = proposed | checking_idle | busy | retired | promoted
      | stale_adopted(command retirement receipt) | stale | compensated
```

Creating the proposal allocates no intent generation, Operation or command and
changes no desired, runtime or route authority. B/C then executes a
proposal-scoped `RouteRetirement(mode=require_idle)`. Under C's per-Cat
admission lock, a nonzero or unknown matching guard count returns an immutable
exact `busy` proof without revoking admission, cancelling a transport or
changing the route epoch. The proposal is retryable only through a fresh exact
eligibility/work snapshot; it never blocks a user transition as current desired
authority.

When the guard count is zero, C atomically closes admission under the same
per-Cat lock and durably returns a proposal/epoch-bound
`retirement_prepare_id`. C does not hold that lock while B conditionally
revokes the exact route epoch using that prepare identity. B/C then finalize
one queryable applied receipt with its own `retirement_token`; a failed route
CAS aborts/reconciles the prepare identity against the still-current epoch.
This is a durable prepare/CAS/finalize protocol, not an assumed cross-system
atomic transaction.
The applied receipt is still proposal-scoped. Only then may A4 run the
policy-promotion transaction. It re-locks the Cat and revalidates policy
enabled, current intent/generation,
settled Running runtime, route retirement receipt, control work version, Guest
lease sequence and zero active work. If all still match, it atomically creates
the new generation, `cat.auto_suspend` Operation, current Suspended intent,
immutable Suspend command/source evidence, and a
`PolicyRetirementPromotion` that binds the proposal receipt to that exact
intent generation and command. The command dispatch requires both the B/C
retirement receipt and this promotion record.

An applied proposal receipt without promotion is level-triggered recovery work.
After a crash, recovery either performs the same conditional promotion, finds
the exact command-scoped adoption receipt described below, or emits a
conditional fresh-epoch bind for the unchanged settled Running authority. A
work-fence, runtime, intent, policy or route mismatch makes the proposal stale.
Only a current leaving-Running command whose own receipt immutably references
this proposal receipt suppresses compensation. A generic "compatible" state,
missing route, or desired non-Running value does not. It is forbidden to leave
Running silently unpublished or to reactivate the retired epoch.

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
transaction locks and compares the Cat, current intent, command, dispatch,
`node_claim_id`, intent generation, authority revision and request digest.

An exact result may atomically:

- advance/terminate its command;
- update `cat_runtime_state` with complete physical and authorizing-intent
  provenance;
- persist an exact intent resolution and materialize the next immutable command
  in the same intent chain only when its source is proven;
- complete the exact Operation;
- update placement ownership when the command semantics require it; and
- persist an exact `RoutePublicationIntentV1`.

Route/DNS/gateway mutation occurs after commit through the Route Controller.
The reducer never waits on route or another network service inside its
transaction and never allocates a route epoch.

Duplicate exact results are no-ops. Mismatched results fail closed. Stale
results are retained and marked stale/superseded evidence but make none of the
authority changes above.

#### RouteRetirement prerequisite

Any command that can take an exact Running runtime away from Running must have
an applied `RouteRetirement` before Node dispatch. This includes Suspend, Cold
and Destroy from Running, plus FallbackCold or another recovery action that may
tear down that runtime. A retirement request binds:

```text
retirement_id
request_digest
scope = route_intent(route_intent_id)
      | lifecycle_command(cat_id + intent_generation + command_id)
      | policy_proposal(policy_proposal_id + expected Cat generation)
mode = cancel_and_drain | require_idle
old_install_id + old_route_intent_id + old_route_epoch
old_settled_lineage: SettledLifecycleLineageV1
expected predecessor = active_authority(old_install_id, old_route_epoch,
                                        old_settled_lineage)
                     | retired_by_policy(policy_proposal_id,
                                         retirement_token)
expected Endpoint/protocol/cohort
expected work fence for require_idle
phase = planned | prepared(retirement_prepare_id) | applying | applied(receipt)
      | busy(proof) | blocked
```

`retirement_prepare_id` is an internal B/C recovery identity for a local
prepare step. It is never the `retirement_token` in a receipt predecessor and
MUST NOT be accepted as one. `retirement_token` always names the random,
immutable exact receipt identity at its structural path.

B owns route authority and the epoch; C owns the local guard registry. The
`cancel_and_drain` mode is used for explicit user lifecycle actions, fleet drain,
Destroy/expiry and fencing recovery. The Route Controller conditionally revokes
admission for that exact epoch, then the Node uses its per-Cat admission lock to
prevent new guards and mark every guard for the exact
`(cat, retired route epoch, route authority revision, runtime)` cancelled. The
retirement request independently binds the accepting intent generation and
command. It closes HTTP/WebSocket/stream transports and drains outside
database/runtime locks.

`require_idle` is used only by a non-authoritative auto-suspend proposal. Under
the same per-Cat admission lock, C first compares the proposal work fence and
guard registry. If any matching guard is active, either count is unknown or the
work fence changed, B does not revoke the route and C does not cancel or drain
anything. The exact busy/stale proof binds proposal, runtime, epoch, work fence,
guard-registry revision and observed count. A zero-count exact match closes
admission and persists a `retirement_prepare_id` under the lock. B
conditionally revokes the epoch with that prepare identity, and B/C finalize
the applied receipt with its immutable `retirement_token`. Prepare recovery
queries both sides and either finishes the same revocation or reopens admission
only while the same route/runtime authority is still current.

An applied receipt has the exact shared B/C shape:

```text
RouteRetirementReceiptV1 {
  retirement_id
  mode = cancel_and_drain | require_idle
  scope = route_intent | lifecycle_command | policy_proposal
  retirement_token
  predecessor = active_authority(old_install_id, old_route_epoch,
                                 old_settled_lineage)
              | retired_by_policy(policy_proposal_id, retirement_token)
  outcome = retired | adopted_retired_predecessor
  reason_route_intent_id?
  reason_lifecycle_intent_generation?
  reason_lifecycle_command_id?
  reason_policy_proposal_id?
  old_install_id + old_route_intent_id
  old_route_epoch
  old_settled_lineage: SettledLifecycleLineageV1
  guard_registry_revision
  cancelled_guard_set_digest?
  remaining_active_guard_count = 0
  admission_state = revoked
  durable_sequence + completed_at
}
```

The scope and reason family are an immutable one-of. In a command adoption
receipt, the outer `RouteRetirementReceiptV1.retirement_token` is the new
receipt's identity, while
`RouteRetirementReceiptV1.predecessor.retirement_token` is byte-for-byte P's
existing policy-receipt token; these paths MUST NOT be conflated or reused.
The receipt names the exact retired authority and zero-active-guard proof. A
policy-scoped receipt also names its exact work fence and gains
command/generation authority only through the immutable
`PolicyRetirementPromotion`. If the Node is unreachable, only an external
isolation/fence receipt proving that runtime cannot serve may replace the Node
acknowledgement for `cancel_and_drain`; `require_idle` fails awake. TTL expiry,
heartbeat absence and Gateway cache purge are not retirement proof.

If a manual lifecycle command commits after a proposal-scoped revocation, it
changes the current intent/generation, so policy promotion fails its CAS and
cannot create an auto-suspend Operation/command. The manual command cannot
consume or rebind that proposal receipt. It persists its own
command-scoped `cancel_and_drain` request with
`expected predecessor=retired_by_policy(P, P.retirement_token)`. B serializes
on the route row and C verifies P's exact receipt token, the same
runtime/route authority and complete settled lineage, local admission still
closed, and zero guards (or performs the command-authorized cancel/drain to
zero if a local guard appeared). B/C then persist a new command-scoped receipt
with `outcome=adopted_retired_predecessor` and
`predecessor=retired_by_policy(P, P.retirement_token)`. This allocates no epoch
and never republishes the retired one. In the earlier ordering where the manual
request reaches B before the policy route CAS, it receives the ordinary
`outcome=retired` receipt and the proposal CAS becomes stale.

Node receipt creation remains serialized by C's per-Cat lock. Control-plane
receipt ingestion and compensation apply use a Cat-first transaction and lock
the same materialized Route row. Its exact policy-retirement resolution begins
as:

```text
pending_policy_retirement(P, retirement_token, old_epoch, old_install,
                          old_lineage)
```

One conditional update changes that value to exactly one of:

```text
adopted_by_command(command_id, receipt_id)
compensated_by_route(compensation_intent_id, fresh_epoch)
```

Here `P = policy_proposal_id`; `retirement_token`, `old_epoch`, `old_install`
and `old_lineage` are the exact values from P's receipt and the pending Route
row, not freshly derived aliases. `receipt_id` is the immutable
`route_retirement_receipt_id` of the winning command-scoped receipt, and
`fresh_epoch` is the greater route epoch allocated by B for the winning
compensation.

The compensation owner is the durable
`RouteRetirementCompensationIntentV1`, whose immutable
`compensation_intent_id` binds P, P's receipt, the originating
`route_intent_id`, old install/epoch/settled lineage and the expected fresh
Cat/Endpoint/Route snapshot. A token, install, epoch or lineage mismatch is a
typed stale/conflict result and performs no state change; comparison by P alone
is forbidden. The losing transaction rolls back in full, reloads the fresh Cat
and Route snapshot and replans. If compensation wins first, B allocates a fresh
epoch for Running, the immutable adoption request becomes stale, and M creates
a new immutable command-scoped retirement against that fresh epoch; it never
mutates the predecessor or treats P as its receipt. If adoption wins,
`stale_adopted` prevents compensation. Crash recovery resumes only from the
durable Route-row resolution and immutable receipt/compensation rows, never
from an in-memory winner.

Proposal recovery suppresses a compensating bind only while that exact adoption
receipt belongs to the current command/generation and the command still
requires Running to remain retired. It atomically marks the proposal
`stale_adopted`. If adoption fails, is superseded, or the current intent keeps
Running, recovery emits the fresh-epoch compensation instead. Thus neither an
unscoped translation nor a desired-state guess can strand the route.

A `cancel_and_drain` timeout, unknown guard count or mismatched epoch leaves the
retirement and lifecycle command `blocked`. The corresponding
`require_idle` outcome leaves only the non-authoritative proposal `busy` or
`stale`; route and lifecycle authority are unchanged. In either case Guest
quiesce, VMM pause/teardown, volume drain and NodeJob dispatch have not begun.
No database lock is held while checking, cancelling or draining. The NodeJob
envelope carries the exact applied receipt and any required promotion, and the
Node revalidates that the same local authority remains retired before a
physical lifecycle effect.

If the lifecycle action later fails while proving the exact Running source was
preserved, the retired epoch is never reactivated. Only an exact reducer
decision that makes Running externally admissible may emit a conditional bind
intent; B allocates a fresh epoch after comparing the retired predecessor.

#### RoutePublicationIntentV1 handoff

The immutable A-to-B handoff is:

```text
RoutePublicationIntentV1 {
  route_intent_id
  cat_id + intent_generation
  intent_resolution_id
  settled_lineage: SettledLifecycleLineageV1
  policy_proposal_id? + policy_retirement_receipt_id?
  action = bind | unbind
  endpoint_ids/protocol/cohort
  expected_route_id?
  expected_route_epoch?
  expected_route_authority_revision
  phase = planned | applying | applied(receipt) | stale | blocked
}
```

`route_intent_id` is the canonical identity; there is no second
publication-intent identity or mapping. Every bind, unbind and compensation
handoff embeds the complete originating physical lineage. Evidence-only intent
settlement and exact compensation update the separate authorizing
`intent_generation`/`intent_resolution_id` but MUST NOT null or synthesize any
lineage member. The policy proposal/receipt fields are additionally mandatory
for policy compensation; they do not replace physical lineage.

Conditional materialization and issuance require these equalities:

```text
Cat.intent_generation
  == cat_runtime_state.intent_generation
  == RoutePublicationIntentV1.intent_generation
  == materialized_route.intent_generation
  == runtime_route_authority_ack.intent_generation
  == RuntimeRouteAuthorityV1.intent_generation

cat_runtime_state.settled_lineage
  == RoutePublicationIntentV1.settled_lineage
  == materialized_route.settled_lineage
  == runtime_route_authority_ack.settled_lineage
  == RuntimeRouteAuthorityV1.settled_lineage
```

The lineage equality is structural and includes optional-field presence as
well as values. `target_node_id` in the lineage must also equal Cat assignment,
the materialized Route target and the ACK/local-authority Node. The handoff,
materialized Route and Node install ACK MUST all carry the same
`route_intent_id`. A digest may be additional audit data only; it never
authorizes a handoff or substitutes for any equality above.

B is the sole allocator of a monotonic `route_epoch`. It conditionally applies
the intent against the exact expected predecessor, installs/retires Node local
authority as required, and persists one receipt containing the allocated epoch,
materialized route revision, complete lineage and exact `route_intent_id`.
Exact replay returns the same receipt. An intent whose Cat intent, current
command, runtime, predecessor or cohort is no longer exact becomes durably
terminal `stale`; it cannot resurrect a route and is not retried as fresh work.

Route materialization uses the canonical transaction order: Cat -> current
intent -> current command (if any) -> `cat_runtime_state` -> Endpoint rows by
stable endpoint ID -> Route rows by canonical hostname ->
`RoutePublicationIntentV1`. A worker may claim scheduling ownership in a
separate short transaction, but it releases that transaction before taking
Cat; it may not hold an intent-row lock and then acquire the order backwards.
No lock is held across Node/Gateway I/O. A consumes only the immutable B receipt
when it needs route completion evidence; A never writes a route row or epoch.

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

A command becomes dispatchable only after every required pre-dispatch storage
effect and RouteRetirement has an exact applied receipt and every grant is still
valid. A proposal-scoped receipt additionally requires its exact immutable
PolicyRetirementPromotion for this command/generation. Delete effects require a
persisted Destroy/tombstone decision and proof that retained volumes crossed
their durability boundary.

### 11. Transaction and lock order

All multi-row mutations use a documented transaction family. Locks are never
held across external I/O. Within a family, locks are acquired in this order:

| Transaction family | Lock order |
| --- | --- |
| Request acceptance / policy promotion | optional request-key transaction advisory lock -> Cat -> current intent -> current command -> `cat_runtime_state` -> work rows sorted by stable ID -> PolicyTransitionProposal/retirement receipt -> Operation/request receipt |
| Ordinary planner/dispatcher/reducer | Cat -> current intent -> command -> dispatch -> volume effects/grants and disks sorted by `volume_id` -> Operation -> PolicyTransitionProposal/RouteRetirement/RoutePublicationIntentV1 |
| Route materialization / policy proposal | Cat -> current intent -> current command (if any) -> `cat_runtime_state` -> work rows sorted by stable ID -> Endpoints sorted by `endpoint_id` -> materialized Routes sorted by canonical hostname -> PolicyTransitionProposal/RoutePublicationIntentV1/RouteRetirementCompensationIntentV1 |
| Placement | fleet placement transaction advisory lock -> candidate Node rows sorted by `node_id` -> Cat -> current intent -> command/dispatch |
| Node fence/recovery | node-fence transaction advisory lock -> Node -> affected Cats sorted by `cat_id` -> their intents/commands/dispatches -> grants sorted by `volume_id` -> route retirement/publication intents |
| Heartbeat observation | Node -> normalized observation rows only; no Cat/command/Operation/route/volume locks |

Request acceptance never also performs placement or Node fencing. A code path
that must join transaction families is split by a durable row/outbox boundary.
It must not acquire an earlier-ranked lock after a later-ranked lock. Session
advisory locks are reserved for bounded singleton leadership under ADR-0032;
there is no per-Cat session lock and no correctness dependency on an RDS Proxy
backend session remaining pinned.

A Route Controller executor claim is scheduling metadata. Claiming it must not
hold a `RoutePublicationIntentV1` row lock while the materializer subsequently
acquires Cat/intent/runtime locks. Deadlock/serialization retry restarts the
whole materialization transaction from the current lifecycle and route
snapshot; it never reuses a previously validated predecessor.

A policy evaluator claim follows the same rule: it is released before Cat. No
Cat/work/route lock spans B/C idle checking or guard drain. Promotion always
reloads and revalidates the complete proposal snapshot after the external
receipt commits.

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
| Request replay / already-satisfied outcome | Immutable acceptance receipt keyed by exact idempotency identity/digest plus its one-to-one terminal Succeeded Operation | A no-op preserves the `202` Operation response but does not create intent generation, command or route work. |
| Auto-suspend eligibility before acceptance | Non-authoritative PolicyTransitionProposal plus exact work/route/runtime snapshot | Policy evaluation cannot create desired authority; a busy proof cancels no active work and changes no route epoch. |
| Desired stable state and current intent generation | Lifecycle request/policy acceptance transaction in Cat intent rows | Planner and API are readers; a waiting intent may have no command. |
| Current command, phase and supersession | Lifecycle command store through planner/reducer CAS after exact source evidence | Acceptance does not guess an action; controllers execute and memory is disposable. |
| Operation identity and terminal outcome | Operation row whose authority root is exactly one accepted intent or one already-satisfied receipt; exact reducer completes only intent-rooted work from an exact resolution and command/result/fence evidence when applicable | Acceptance completes the receipt-rooted no-op Operation from exact settled provenance; newer convergence cannot complete intent-rooted work. |
| Dispatch bytes and controller executor claim | Lifecycle dispatch store | Queue/HTTP are delivery mechanisms. |
| Node execution claim and physical result | C Node runtime/job ledger, mirrored immutably into control PostgreSQL | Heartbeat is not a result. |
| Settled runtime state | Exact reducer transaction in `cat_runtime_state` | `cats.observed_state` is temporary projection. |
| Process/PID/snapshot/local journal existence | C Node runtime ledger with PID/runtime identity proof | It never grants storage authority. |
| Placement/reservation | Scheduler/placement transaction under the fleet lock | Lifecycle consumes the exact placement identity. |
| Volume grant and invalidation | A7/D relational grant plus MetadataStore receipt | Node may exercise only the exact valid grant. |
| Volume root/owner/epoch | MetadataStore conditional CAS and receipt | Control lifecycle cannot synthesize an epoch. |
| Route guard retirement | B Route Controller plus C exact local guard receipt/fence | A requires the receipt but cannot infer zero guards from TTL/heartbeat. Auto policy uses `require_idle`; only explicit/drain/destroy/fence authority may use `cancel_and_drain`. |
| Route binding/activation epoch | B Route Controller from exact `RoutePublicationIntentV1` CAS | A emits/consumes intents/receipts but never allocates epoch; heartbeat cannot publish. |
| Latest reported inventory | Normalized heartbeat observation rows | Orphan/recovery views derive from it. |
| Backoff, semaphore, future, leader handle | No authority; process-local optimization only | Loss must not lose or change work. |

### 14. Component boundaries for A1-A9

| Slice | Boundary fixed by this ADR |
| --- | --- |
| A1 #224 | Relational request receipts, policy proposals/promotions, intents/resolutions, commands, route handoffs, FKs, one-current-intent/at-most-one-executable-command constraints, work indexes and explicit ambiguous migration rows. |
| A2 #225 | Pure exhaustive planner over typed intent/source-evidence snapshots; it materializes no command before exact evidence and performs no Store, HTTP, MetadataStore or process effects. |
| A3 #226 | Separate NodeJob V2 endpoint, exact wire bytes/digest, durable Node claim and all terminal results, coordinated with C. |
| A4 #227 | Sole transactional lifecycle acceptance/policy promotion; exact replay, a receipt plus terminal no-op Operation, or exactly one real intent/Operation, with no guessed successor command and no policy authority before idle proof. |
| A5 #228 | Durable payload/storage/route-retirement prerequisites, bounded dispatch, require-idle proposal recovery/compensation and level-triggered recovery; no giant reconciler. |
| A6 #229 | Exact result/evidence reducer, immutable command materialization and exact route-intent handoff; no external I/O or route epoch allocation. |
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
- Build a known-positive inventory of every Node that owns or reports a
  Running, Suspended or Warm runtime, a runtime ledger entry/residue, or a V1
  Node journal/retry/replay record. Each such Node must durably advertise the
  lifecycle-V2 endpoint, journal and adoption capability required by A3/C, and
  the inventory query must first detect seeded V1-only/residue controls.
- Upgrade each V1-only runtime-bearing Agent in place only when C can re-adopt
  the exact runtime under lifecycle V2. Otherwise cold-move it through the V1
  writer before cutover, or externally fence and explicitly quarantine/repair
  it. Stable Running/Suspended/Warm is not an exemption. Require zero V1
  lifecycle journal, retry-queue and operational replay residue before
  Activate.
- Snapshot the control database and record the RC commit, schema version,
  protocol versions, Node capabilities and row counts.

#### Activate

- Atomically change the database authority version to V2 and enable exactly
  one V2 acceptance/planner/dispatcher/reducer path.
- Old binaries fail closed against the authority-version gate. They cannot
  bypass Freeze or write old lifecycle columns.
- Recheck, from fresh known-positive inventory, that every runtime-bearing Node
  is lifecycle-V2 capable and no V1 replay residue appeared after the Freeze
  snapshot. A stale/missing capability report blocks activation.
- Unfreeze API/policy work only after the V2 recovery scan accounts for every
  current intent, waiting predecessor and nonterminal command.

Lifecycle-V2 capability and B's signed Route Grant cohort are orthogonal. A
Node may remain in an explicitly represented route-legacy cohort only after it
is lifecycle-V2 capable; that does not let it execute V1 lifecycle work or mint
V2 grants. Conversely, route-V2 capability never satisfies this lifecycle
activation gate.

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

- the Activate lifecycle-capability proof remains true, and no V1 lifecycle job
  exists anywhere in a Node journal, retry queue or operational replay window;
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
