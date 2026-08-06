# Lifecycle command and NodeJob V2 protocol

- Status: Architecture contract
- Version: 2
- Authority: [ADR-0035](../decisions/0035-durable-lifecycle-command-authority.md)
- Scope: control-plane lifecycle command/result identity and the internal
  control-plane -> Node Agent lifecycle job protocol

## 1. Purpose and boundaries

This specification gives every Cat lifecycle side effect a durable identity.
It defines the handoff between the relational `LifecycleCommand` authority and
the Node runtime ownership boundary. It does not define a generic workflow
protocol, storage object format, Guest runtime API, public Cats API or C's Node
runtime ledger format.

V2 is a separate protocol. A V1 `/v1/jobs` payload is never decoded as V2, an
omitted claim/epoch is never assigned a magic default, and a V1 result cannot
settle a V2 command.

Normative words `MUST`, `MUST NOT`, `SHOULD` and `MAY` are used as in RFC 2119.

## 2. Identities

| Field | Meaning | Reuse rule |
| --- | --- | --- |
| `cat_id` | Stable Cat identity | Never identifies an execution by itself. |
| `request_receipt_id` | Immutable acceptance/replay outcome | Exact request-key/digest replay keeps it; semantic no-op binds it one-to-one to a terminal Operation but creates no intent generation or command. |
| `policy_proposal_id` | Non-authoritative exact auto-suspend eligibility snapshot | Never becomes intent authority by itself; retry after busy/stale uses a fresh snapshot. |
| `policy_promotion_id` | Immutable promotion of an applied proposal retirement to one intent/command | Never reused or rebound to another proposal, generation or command. |
| `intent_generation` | Generation allocated by accepted desired intent | A command chain may share it; it never replaces `command_id`. |
| `intent_resolution_id` | Exact evidence adoption/wait/settlement under an intent | Never reused; it binds predecessor result/fence/runtime evidence before command selection. |
| `operation_id` | Exact user/policy Operation | Authority root is exactly one accepted intent or already-satisfied receipt; an intent-rooted Operation may span several commands and FallbackCold. |
| `command_id` | One immutable lifecycle command | Never reused, including the next leg of the same intent. |
| `command_seq` | Monotonic command order within an intent generation | Unique with Cat and generation. |
| `dispatch_id` | One immutable physical Node action envelope | Transport replay keeps it; a semantic retry creates a new one. |
| `dispatch_seq` | Monotonic dispatch order within a command | A new semantic attempt increments it. |
| `executor_attempt_id` | A controller process's lease to deliver/query one dispatch | May change after expiry; has no lifecycle authority. |
| `node_claim_id` | Durable Node processing identity for one recognized dispatch | Assigned once with Accepted or Rejected before physical side effects; never reused. A Rejected claim cannot execute. |
| `result_id` | Immutable terminal result identity | Exact replay returns it; different bytes under the ID are corruption. |
| `runtime_id` | Node-ledger identity of one physical Cat runtime lineage | Survives Agent restart/adoption; changes on a fresh runtime lineage. |
| `effect_id` | One conditional MetadataStore mutation | Exact replay returns the original receipt. |
| `grant_id` | One volume authority offered to one dispatch/Node/volume | Invalidated monotonically; never rebound. |
| `route_retirement_id` | One prerequisite revocation/drain for an exact Running authority | Exact replay returns the B/C receipt; it is never rebound to another epoch/runtime. |
| `route_publication_intent_id` | One immutable A-to-B bind/unbind handoff | Exact replay returns B's receipt; obsolete work terminates stale. |

All IDs are opaque, globally unique strings with their normal Cats type prefix.
No receiver parses identity or ordering from an ID. Ordering comes from the
explicit sequence/generation fields and exact foreign-key relationships.

## 3. LifecycleCommand record contract

The relational command record contains at least:

```text
LifecycleCommandV2 {
  command_id
  cat_id
  intent_generation
  command_seq
  operation_id
  kind
  source_state
  target_state
  authority_revision
  authority = current | superseded | terminal
  phase
  predecessor_command_id?
  superseded_by_command_id?
  blocked_by_dispatch_id?
  source_evidence_id
  created_at
  updated_at
}
```

`kind` is one of:

```text
start | resume | restore | suspend | warm | cold | destroy | fallback_cold
```

The two fields deliberately have different closed domains:

```text
source_state = absent | running | suspended | warm | cold
target_state = running | suspended | warm | cold | deleted
```

`absent` means no settled runtime exists, as on initial create or after a
proven-clean failed Start. `deleted` is valid only for Destroy and means the Cat
resource reached its irreversible terminal tombstone. It is not a fifth
ADR-0002 runtime state. Destroy success removes/tombstones the resource and
leaves no settled runtime row; every other command targets one of Running,
Suspended, Warm or Cold. Neither field uses `starting`, `suspending`, `warming`
or `stopping`; those are UI projections of the command phase.

The command is persisted before any volume, Node, route or Guest effect. Only
one command for a Cat can have `authority=current`. A superseded command keeps
all dispatches/results for evidence but cannot settle authority.

The command is not the accepted desired intent. PostgreSQL may contain one
current `LifecycleIntentV2` in `waiting_predecessor` with no current executable
command. A command is inserted only after an immutable source-evidence record
exists:

```text
IntentResolutionV2 {
  intent_resolution_id
  cat_id
  intent_generation
  phase = waiting_predecessor | source_proven | satisfied_by_evidence | blocked
  source_evidence_kind = settled_runtime | predecessor_result | fence | absence
  source_result_id?
  source_fence_receipt_id?
  source_runtime_id?
  source_runtime_revision?
  source_provenance_digest
}
```

For a superseded in-flight Suspend followed by a Running intent, no Resume is
created at acceptance. Suspend success proves Suspended and permits an immutable
Resume bound to that result; source-preserved failure may satisfy Running by
evidence; indeterminate outcome leaves the intent waiting for query/fence or a
later FallbackCold decision. No action field is mutated after insertion.

### 3.1 Acceptance receipt and semantic no-op

The request idempotency identity is the exact
`(workspace_id, canonical route/action, idempotency_key)`. Its digest covers the
method/route, Workspace/Cat, requested desired state, original precondition and
exact body bytes. Lookup occurs before reevaluating `If-Match`.

After taking the Cat lock but before allocating an intent generation or
command, acceptance checks whether the exact settled stable state already
equals the request and no current intent, nonterminal/retiring command,
unresolved predecessor/effect/grant, live PolicyTransitionProposal or
uncompensated RouteRetirement can change it. If so it atomically persists:

```text
LifecycleRequestReceiptV2 {
  request_receipt_id
  idempotency identity
  request_digest
  outcome = already_satisfied
  cat_id
  existing_intent_generation
  settled_runtime_revision
  settled_runtime_provenance_digest
  operation_id
  exact_response_bytes
  response_sha256
}

OperationV2 {
  operation_id
  phase = succeeded
  outcome = already_satisfied
  resource_generation = existing Cat generation
  intent_id = null
  already_satisfied_receipt_id
  completion_runtime_revision
  completion_provenance_digest
}
```

The Operation and receipt are one-to-one. The Operation authority root obeys
`intent_id XOR already_satisfied_receipt_id`; this variant has no intent or
command and cannot later acquire one. A real-change Operation instead binds its
accepted intent immediately, remains valid/queryable while that intent waits
without a command, and on terminal completion binds the exact
`intent_resolution_id` plus command/result/fence evidence when applicable. It
preserves the current public contract: `202 Accepted` with
`CatOperationResponse { operation, cat }`. It allocates no
new intent generation or command, emits no wakeup or route work, and does not
change route authority. Exact replay returns the same receipt, Operation and
byte-identical response even if later requests changed the Cat. A fresh
idempotency key may create a fresh terminal already-satisfied Operation while
leaving all lifecycle and route authority unchanged. Same identity with another
digest conflicts. Neither the receipt nor Operation is a synthetic Node result.

A real intent change allocates one generation and Operation plus a current
intent. It may create the first command in that transaction only when exact
source evidence is already present; otherwise the intent durably waits without
a placeholder command.

### 3.2 PolicyTransitionProposal and require-idle promotion

Auto-suspend MUST preserve `LIFE-AUTO-001`: active work prevents the transition
and is not cancelled to make the policy eligible. Before any generation,
Operation, intent or command exists, policy evaluation persists:

```text
PolicyTransitionProposalV2 {
  policy_proposal_id
  cat_id
  target_state = suspended
  policy_kind + policy_version
  expected_cat_generation
  expected_current_intent_id?
  expected_desired_state = running
  runtime_id + runtime_authority_revision + node_id
  expected_route_id + expected_route_epoch + expected_route_authority_revision
  control_work_version
  guest_source_epoch + guest_lease_sequence + guest_signal_freshness_deadline
  snapshot_provenance_digest
  phase = proposed | checking_idle | busy | retired | promoted
        | stale_adopted | stale | compensated
}
```

This row is scheduling/evidence only. B/C executes a proposal-scoped
RouteRetirement with `mode=require_idle`. Under C's per-Cat admission lock,
active/unknown guards or a changed work fence return an exact busy/stale proof
without route revocation, transport cancellation or any lifecycle-authority
change. At exact zero, C closes admission and durably records a
proposal-and-epoch-bound prepared token under the lock, then releases it. B
conditionally revokes the named route epoch using that token and B/C finalize a
queryable applied receipt. Recovery of a prepared token queries both sides and
either completes the same revocation or reopens admission only while the same
route/runtime authority is still current; no runtime or PostgreSQL lock spans
the call.

After the applied B/C receipt, A4 runs a fresh Cat-first transaction and
revalidates every proposal field, policy enablement, live control/Guest work
and route-retirement provenance. Only an exact match atomically creates the new
generation, `cat.auto_suspend` Operation, Suspended intent, Suspend command and:

```text
PolicyRetirementPromotionV2 {
  policy_promotion_id
  policy_proposal_id
  route_retirement_receipt_id
  cat_id
  intent_id + intent_generation
  operation_id
  command_id
  runtime_id + runtime_authority_revision
  retired_route_epoch + work_fence_digest
}
```

The Suspend dispatch carries both the proposal-scoped receipt and promotion
record, which together bind the exact command/generation. A crash after route
revocation but before promotion is recovered by conditional promotion, the
exact command-scoped predecessor-adoption protocol in section 4.4, or a
conditional fresh bind of the unchanged settled Running authority. A generic
compatible state never suppresses compensation. A stale proposal never leaves
Running silently unpublished and never reuses the retired epoch.

Proposal creation follows Cat -> current intent -> current command if any ->
exact runtime -> sorted work rows -> sorted Endpoints -> sorted Routes ->
proposal. Promotion follows Cat -> current intent -> current command if any ->
exact runtime -> sorted work rows -> proposal/retirement -> Operation. Executor
claims are released first, and no PostgreSQL lock is held while B/C checks or
drains guards.

## 4. NodeJob V2 transport

### 4.1 Endpoints

```text
PUT /v2/jobs/{dispatch_id}
GET /v2/jobs/{dispatch_id}
```

`PUT` creates or replays one immutable dispatch. `GET` queries the Node's
durable acceptance/progress/terminal record after a lost response. Both are
service-authenticated and Node-scoped.

The control plane MUST persist the exact request body bytes and their SHA-256
before `PUT`. It sends:

```text
Content-Type: application/json
X-Cats-Job-Body-SHA256: <lowercase hex SHA-256 of the exact HTTP body bytes>
```

The Node verifies the body digest before JSON decoding and stores the digest
with the dispatch record. A transport retry MUST use the persisted byte-for-byte
body. This deliberately avoids equivalence rules for differently serialized
JSON. A matching `dispatch_id` with another digest returns conflict before a
side effect.

### 4.2 Request envelope

```json
{
  "protocol_version": 2,
  "dispatch_id": "dsp_...",
  "dispatch_seq": 1,
  "command_id": "lcmd_...",
  "command_kind": "start",
  "command_seq": 1,
  "intent_generation": 42,
  "operation_id": "op_...",
  "cat_id": "cat_...",
  "target_node_id": "node_...",
  "source_evidence_id": "ires_...",
  "not_before_unix_ms": 0,
  "deadline_unix_ms": 1786000000000,
  "expected_runtime": { "mode": "absent", "fence_receipt_id": "mfx_..." },
  "route_retirement": null,
  "volume_grants": [],
  "action": { "type": "start", "spec": {} }
}
```

The URL `dispatch_id`, body `dispatch_id`, authenticated Node identity and
`target_node_id` MUST all match. The deadline bounds new work; it does not
erase an already accepted result or authorize cleanup on expiry.

### 4.3 Expected runtime precondition

Every action has an explicit runtime precondition:

```text
absent {
  fence_receipt_id?          # required when absence depends on a fence
}

exact {
  runtime_id + node_id
  runtime_generation
  node_claim_id
  host_boot_id?
  warm_snapshot_id?         # Restore only
  warm_snapshot_digest?     # Restore only
}
```

`absent` means the command is authorized to create a fresh runtime only after
the referenced fencing/absence proof is valid. It is not permission to delete
an unknown residue. `exact` prevents an old Resume/Suspend/Warm/Cold action
from operating on a replacement runtime with the same Cat ID. The source
evidence record is persisted before this envelope and its digest is included in
the exact body; the Node does not infer source state from the action name.

### 4.4 Route retirement receipt

A command that can take a Running runtime away from Running includes an exact
applied retirement. The retirement itself is scoped to one command or one
pre-authority policy proposal:

```text
route_retirement {
  route_retirement_id
  request_digest
  cat_id
  scope = command(intent_generation + command_id)
        | policy(policy_proposal_id + expected_cat_generation)
  mode = cancel_and_drain | require_idle
  runtime_id
  retired_route_epoch
  retired_authority_revision
  expected_predecessor = active_route
                       | retired_by_policy(policy_receipt_id + prepared_token_id)
  expected_work_fence?          # required for require_idle
  phase = planned | prepared | applying | applied | busy | blocked
  prepared_token_id?
  proof_or_receipt_id?
}

RouteRetirementBusyProofV1 {
  busy_proof_id
  route_retirement_id + request_digest
  policy_proposal_id
  runtime_id + node_id + route_epoch
  work_fence_digest + guard_registry_revision
  active_guard_count?           # null means unknown/fail-awake
}

RouteRetirementAppliedReceiptV1 {
  receipt_id
  route_retirement_id + request_digest
  exact scope + mode
  outcome = revoked | adopted_retired_predecessor
  runtime_id + node_id
  retired_route_epoch
  retired_authority_revision
  prepared_token_id?
  predecessor_policy_receipt_id? # required only for adopted predecessor
  zero_active_guard_proof_digest
  node_ack_or_external_fence_receipt_id
}
```

For `cancel_and_drain`, B/C issues the receipt only after exact-epoch admission
revoke, cancellation and drain of every matching HTTP/WebSocket/stream guard to
zero, or after external isolation proves an unreachable runtime cannot serve.
Explicit lifecycle, fleet drain, Destroy/expiry and fencing recovery use this
mode.

Auto-suspend uses `require_idle`. C compares the work fence and active guards
under its per-Cat admission lock before B revokes. A nonzero/unknown count or
changed fence returns an immutable busy/stale proof and MUST NOT revoke the
route, cancel a guard or change lifecycle authority. Only exact zero closes
admission and persists a prepared token under the lock. B then conditionally
revokes with that token and B/C finalizes the receipt; prepared recovery is
queryable/idempotent. An unreachable Node fails awake.

TTL/cache/heartbeat is not a receipt. Suspend, Cold/Destroy from Running and
any recovery action that may tear down Running MUST carry a command-scoped
receipt or the exact policy receipt plus PolicyRetirementPromotion. Rebinding a
receipt to another command, generation, proposal, runtime or epoch is rejected
before physical lifecycle effects.

If a manual leaving-Running command commits after a policy receipt retired the
route but before policy promotion, the changed current intent/generation makes
policy promotion stale. The manual command creates a new command-scoped
`cancel_and_drain` request whose expected predecessor is that exact policy
receipt/token. B serializes it with proposal compensation. C verifies the same
runtime/route authority and closed admission gate, then rechecks zero guards or
uses the manual command's authority to cancel/drain any local guard that
appeared. B/C returns a distinct command-scoped
`adopted_retired_predecessor` receipt referencing the policy receipt. It does
not allocate an epoch, mutate either request scope or reactivate the old epoch.

The proposal becomes `stale_adopted` and compensation is suppressed only if
that adoption receipt belongs to the exact current command/generation and the
command still requires the route retired. In an earlier ordering where the
manual route CAS wins before the policy CAS, the proposal becomes stale behind
the command's ordinary `revoked` receipt. If
the command is superseded, keeps Running, or adoption cannot be proven,
recovery conditionally publishes a fresh epoch for unchanged Running authority.

Adoption and compensation serialize on B's route row. If compensation wins,
the immutable adoption request terminates stale and the command creates a new
command-scoped retirement request against the freshly published epoch. If
adoption wins, `stale_adopted` prevents compensation. Neither branch mutates a
request predecessor or reuses an epoch.

### 4.5 Volume grant

```json
{
  "grant_id": "vgrant_...",
  "effect_receipt_id": "mfxr_...",
  "disk_id": "disk_...",
  "volume_id": "vol_...",
  "disk_kind": "root",
  "attachment_id": "att_...",
  "target_node_id": "node_...",
  "expected_predecessor": {
    "owner": null,
    "epoch": 73,
    "root_generation": 108
  },
  "granted_epoch": 74,
  "durability": "relaxed",
  "size_bytes": 107374182400,
  "mount_path": "/",
  "disposition": "retained"
}
```

A grant belongs to the exact command, dispatch, target Node and volume even
when those fields are omitted from this compact example and represented by
foreign keys in PostgreSQL. `attachment_id` includes fresh grant/dispatch
identity; it is not derived only from Cat generation.

The Node MUST validate the grant before acquisition/use. A delayed dispatch
cannot acquire after the grant has been invalidated. Same-grant acquisition is
idempotent and returns the same epoch; different predecessor state is a
conditional rejection. These MetadataStore semantics are owned by A7 and D.

### 4.6 Closed action payloads

The action `type` is bound to `command_kind`. There is no generic shell command
or Cleanup action.

#### Start

```text
start {
  image_digest
  cpus
  memory_mib
  boot_config_digest
  runtime_generation
}
```

Precondition: `expected_runtime=absent`, exact placement and valid volume
grants. Success postcondition: a new Running runtime is durably adopted in the
Node ledger, every active volume reports the exact attachment/epoch, and Guest
Agent readiness for that runtime was observed.

#### Resume

```text
resume {
  runtime_id
  suspend_fence { control_work_version, guest_lease_sequence }
}
```

Precondition: exact Suspended runtime on the same Node. Success: the same
runtime lineage is Running and durably adopted. It MUST NOT be silently
implemented as Start.

#### Restore

```text
restore {
  runtime_id
  warm_snapshot_id
  warm_snapshot_digest
  vmm_compatibility_id
}
```

Precondition: exact Warm ledger/snapshot identity on the same Node and exact
retained grants. Success: the restored lineage is Running and durably adopted.
Snapshot mismatch is a terminal Rejected/Failed result that drives
FallbackCold; it is never silently Start.

#### Suspend

```text
suspend {
  runtime_id
  work_fence { control_work_version, guest_lease_sequence }
}
```

Precondition: exact Running runtime and exact applied RouteRetirement. Success:
route guards are still zero, Guest quiesce/local durability barrier and VMM
pause completed, and the exact runtime is durably recorded as Suspended.
Work-fence change is Rejected with source preserved.

#### Warm

```text
warm {
  runtime_id
  required_remote_watermarks[]
  snapshot_id
  vmm_compatibility_id
}
```

Precondition: exact Suspended runtime. Success requires every retained volume
at `R == L`, a verified snapshot, VMM/backend exit and a durable Warm ledger
record. Drain failure preserves Suspended/local journal and is not Cold.

#### Cold

```text
cold {
  runtime_id
  retained_volume_ids[]
  required_remote_watermarks[]
  reason = user_stop | policy | drain | fallback
}
```

When the source is Running, precondition includes exact applied
RouteRetirement. Success requires new Guest/route work stopped, retained
volumes at `R == L`, VMM and backend teardown, and a durable absence/Cold
record. Failure that leaves a local-ahead journal returns source preserved or
indeterminate and MUST NOT delete it.

#### Destroy

```text
destroy {
  runtime_id?
  disposable_root_disk_ids[]
  retained_persistent_disk_ids[]
  destroy_authority_digest
}
```

The two disk lists are disjoint and cover every known runtime volume. Success
may discard local tails only for listed RootDisks. Every retained
PersistentDisk must drain and be released conditionally. Unknown volume or
residue fails closed. Control-plane MetadataStore deletion/tombstoning remains
a recorded post-Node effect under the same Destroy command. Destroy of a
Running source also requires exact applied RouteRetirement.

#### FallbackCold

```text
fallback_cold {
  failed_command_id
  failed_dispatch_id
  runtime_id?
  retained_volume_ids[]
  source_evidence_digest
}
```

It has Cold's durability postconditions and additionally binds the failure
evidence that authorized fallback. It cannot infer disposable volumes or use a
generic residue cleanup path. If the retained source can still serve Running,
it also carries exact applied RouteRetirement.

## 5. Node acceptance and execution

Before the first physical side effect, the Node performs, in order:

1. authenticate the caller and exact target Node;
2. verify body SHA-256 and protocol version;
3. look up `dispatch_id` in the durable Node job journal;
4. for a new dispatch, validate command/action/source-evidence identities,
   expected runtime, authority freshness, any required exact RouteRetirement
   and PolicyRetirementPromotion, and grant prerequisites;
5. atomically choose a fresh `node_claim_id` and persist either Accepted or a
   terminal Rejected result with the request digest and exact payload;
6. fsync/commit that record; and only for Accepted
7. execute the closed action under the per-Cat runtime lock and bounded action
   semaphore.

A Rejected claim authorizes no execution. It MUST NOT make the rejected request
replayable as a fresh attempt. Authentication failure, malformed input and a
digest conflict with an existing dispatch are protocol errors before a new
dispatch is recognized; they do not create another claim/result. If execution
fails, the Node persists Failed with exact source disposition and evidence.
The controller creates a new dispatch for any semantic retry.

Agent restart reconstructs the accepted/running job from C's durable job and
runtime ledgers. A successful Start/Resume/Restore result is written only after
the runtime ledger can be reopened and prove adoption. A successful
Cold/Destroy result is written only after the ledger proves the stated absence
and retained-volume postconditions. For a Running-source transition, the Node
revalidates under the per-Cat admission lock that the retired authority still
has zero guards before Guest/VMM/blockd effects. A mismatch is terminal
Rejected/source-preserved, not a second implicit retirement.

## 6. Response and result shape

`PUT` returns one of:

- `202 Accepted` with the durable Accepted/Running view for a new or in-flight
  exact dispatch;
- `200 OK` with the immutable terminal result for an exact replay;
- `409 Conflict` with a durable terminal Rejected envelope when a newly
  recognized dispatch has stale command, grant or runtime authority;
- `409 Conflict` without a new result for a pre-recognition conflict such as
  the same dispatch ID with a different digest, wrong target Node, URL/body
  identity mismatch or an impossible existing claim; or
- an ordinary transport/server failure, which is ambiguous and requires GET or
  exact PUT replay.

"Recognized" means authentication, target, protocol/envelope shape and request
digest checks passed and no existing dispatch record conflicts with the body.
Once recognized, authority/runtime/grant validation rejection MUST allocate one
`node_claim_id`, persist one terminal Rejected result and return that envelope
with 409. After Agent restart, `GET` for the dispatch MUST return the same claim
and result bytes. It MUST NOT degrade into an ephemeral HTTP error. Requests
that fail before recognition (including authentication, malformed input,
target/identity mismatch, digest-header mismatch or existing-ID/different-body
conflict) create no claim/result; `GET` remains 404 if no earlier exact record
exists. Authentication normally uses 401/403 and malformed input 400; the
authority distinction does not depend on the particular pre-recognition 4xx.

`GET` returns the durable record or `404` only if the Node has never durably
accepted/rejected that dispatch. It never starts work.

```json
{
  "protocol_version": 2,
  "dispatch_id": "dsp_...",
  "command_id": "lcmd_...",
  "intent_generation": 42,
  "node_claim_id": "nclaim_...",
  "request_body_sha256": "...",
  "phase": "succeeded",
  "result_id": "nres_...",
  "source_disposition": "transitioned",
  "runtime": {
    "runtime_id": "rt_...",
    "runtime_generation": 9,
    "state": "running",
    "host_boot_id": "...",
    "guest_boot_id": "..."
  },
  "volumes": [],
  "error": null,
  "accepted_at_unix_ms": 1785999999000,
  "finished_at_unix_ms": 1786000000123
}
```

`phase` is:

```text
accepted | running | succeeded | rejected | failed
```

The first two are nonterminal. The last three are terminal and immutable.
Progress fields MAY advance under a monotonic `progress_seq`; they are not
authority and cannot settle the command.

`source_disposition` is:

| Value | Meaning |
| --- | --- |
| `preserved` | Exact source runtime and all unique local data remain usable under the same ownership. |
| `transitioned` | Requested target postcondition is proven. |
| `absent` | Runtime is proven absent; volume evidence states what was retained/discarded. |
| `indeterminate` | Node cannot prove source or target; control must query, wait or fence. |

A Failed/Rejected result includes:

```text
error {
  code                  # closed, versioned error code
  message               # redacted operator text
  retry_class           # exact_replay | new_dispatch | wait | fence_required | operator_required | never
  evidence_digest
}
```

`exact_replay` is reserved for a nonterminal/ambiguous transport condition, not
for a terminal Failed result. A terminal Failed result normally requires
`new_dispatch`, wait/fence/operator action, or never.

Volume evidence contains at least the exact grant, attachment/epoch, local and
remote generations, unpublished bytes/age, fencing status, and whether the
local journal remains present. A reducer MUST NOT infer `R == L` from a generic
success message.

## 7. Control-plane result ingestion

The control plane first inserts or matches the immutable result and payload
digest. It then runs the exact ADR-0035 reducer transaction.

The result can settle only if all of these match the current authority:

```text
cat_id
current intent_generation
command_id + command_seq + authority_revision and its exact supersession status
dispatch_id + dispatch_seq + exact request digest
target_node_id
node_claim_id
action kind
source_evidence_id
expected runtime identity
required RouteRetirement identity/receipt
required PolicyRetirementPromotion for a proposal-scoped retirement
all required grant/effect identities
```

Any mismatch is stale/conflicting evidence. It remains queryable but does not
mutate settled runtime, placement, Operation, routes or grants. A duplicate
exact result is a no-op. Same identity with different content is an invariant
violation and pages an operator.

A result from a superseded command cannot directly settle current authority.
The current-intent reducer may create an immutable `IntentResolutionV2` that
adopts that exact physical evidence and then materialize a command, settle as
`satisfied_by_evidence`, or wait/fence. The resulting `cat_runtime_state` keeps
both the originating command/result provenance and the current authorizing
intent/resolution.

### 7.1 Route retirement and publication handoff

Before dispatch of any command that can leave Running, its exact
RouteRetirement must be terminal applied. A `cancel_and_drain` timeout/unknown
guard count is `blocked`; an unreachable serving runtime needs external
isolation/fence. A `require_idle` busy/unknown result changes no lifecycle or
route authority and cannot be promoted. Neither grant TTL nor route cache
expiry qualifies.

After exact reduction, A may persist one immutable handoff:

```text
RoutePublicationIntentV1 {
  route_publication_intent_id
  cat_id
  intent_generation
  intent_resolution_id
  command_id?
  dispatch_id?
  node_claim_id?
  result_id?
  policy_proposal_id?
  policy_retirement_receipt_id?
  runtime_id
  runtime_authority_revision
  node_id
  action = bind | unbind
  endpoint_ids
  protocol
  cohort
  expected_route_id?
  expected_route_epoch?
  expected_route_authority_revision
  lifecycle_provenance_digest
}
```

B alone allocates `route_epoch`. It applies under Cat -> current intent ->
current command (if any) -> exact runtime -> sorted Endpoints -> sorted Routes
-> route intent, conditionally comparing every predecessor/provenance field.
Exact replay returns the same receipt; delayed or out-of-order work becomes
terminal `stale` and cannot publish. A consumes the receipt but never writes a
route row/epoch. A controller scheduling claim must be released before the
materialization transaction and no database lock is held across Node/Gateway
I/O.

If a proposal-scoped `require_idle` revocation becomes stale before promotion,
recovery uses this same conditional handoff to bind a fresh epoch to the exact
unchanged settled Running runtime. It carries the existing authorizing intent
resolution and the stale proposal/retirement receipt. The compensation is
unnecessary only when the exact current leaving-Running command has its own
command-scoped `adopted_retired_predecessor` receipt referencing that policy
receipt. Desired state, a missing route or a proposal-scoped receipt alone is
not enough. Running is never left silently unpublished.

If a failed transition preserves Running after its epoch was retired, neither
A nor B reactivates that epoch. An exact evidence settlement may request a new
conditional bind; B compares the retired predecessor and allocates a fresh
epoch.

## 8. Lost response and recovery examples

### Applied success, response lost

```text
control persists dispatch D/body H
Node persists Accepted(D, claim C)
Node applies action and persists Succeeded(result R)
HTTP response is lost
control GETs D or re-PUTs identical body H
Node returns R
exact reducer settles command
```

No new dispatch or action is created.

### Duplicate delivery

```text
two controller executors PUT D/body H
Node's durable unique D chooses one claim C
both callers receive the same accepted/result record
```

At-most-one execution comes from the Node journal/runtime lock; correctness
does not depend on the control-plane semaphore.

### Same ID, different payload

```text
Node has D/body H1
caller sends D/body H2
Node returns 409 payload_mismatch before side effects
```

### Superseded result

```text
Suspend command S dispatches D1
new wake intent I becomes current, supersedes S and waits without a command
Node later returns Succeeded(D1, Suspended)
result is stored and adopted by exact resolution E under I
planner materializes immutable Resume W bound to E/result D1
```

If D1 instead fails with exact source-preserved Running evidence, E can settle
I as `satisfied_by_evidence` without a Node command. If D1 is indeterminate, I
remains waiting/blocked; it does not guess Start/Resume/FallbackCold.

### Stale generation after ABA

```text
gen 7 Cold dispatch D1 succeeds
gen 8 Start dispatch D2 succeeds
gen 9 Cold dispatch D3 starts
late D1 success arrives
```

Distinct command/dispatch/claim identities make D1 stale. It cannot settle D3
even though action and target state are both Cold.

### Delayed grant acquisition after fence

```text
Start dispatch D has pending grant G
successor/fence conditionally invalidates G
delayed D reaches Node and tries G
MetadataStore returns the immutable invalidation receipt/rejection
Node records Rejected before starting blockd/VMM
```

## 9. Compatibility and removal

During Expand, new Agents serve V1 and V2 on separate endpoints. V1 behavior is
unchanged; in particular, its generation/action Job ID and legacy result are
not upgraded by adding optional V2 fields. V2 dispatch is capability-gated per
Node.

During Freeze no V1 lifecycle job may remain in flight or in any Node
journal/retry/replay residue. Known-positive inventory must prove every Node
owning/reporting Running, Suspended or Warm runtime or runtime ledger residue is
lifecycle-V2 capable. A V1-only runtime is upgraded and exactly re-adopted,
cold-moved before cutover, or externally fenced/quarantined; stable state does
not exempt it. Stale/missing capability evidence blocks Activate.

Lifecycle-V2 capability is independent of the signed Route Grant cohort. A
lifecycle-V2 Node may remain explicitly route-legacy during B rollout, but a
route-V2 Node cannot remain lifecycle-V1. Activate switches the database
authority version to V2 and prevents old writers. Contract removes V1 lifecycle
decode/execute/journaling only after the ADR-0035 deletion conditions and the
characterization matrix pass.

There is no permanent translation adapter and no fallback that maps a V2
dispatch to V1 `CleanupCat`, epoch zero or a generation-derived Job ID.
