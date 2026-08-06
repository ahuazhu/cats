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
| `intent_generation` | Generation allocated by accepted desired intent | A command chain may share it; it never replaces `command_id`. |
| `operation_id` | Exact user/policy Operation | One Operation may span several commands and FallbackCold. |
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
  "not_before_unix_ms": 0,
  "deadline_unix_ms": 1786000000000,
  "expected_runtime": { "mode": "absent", "fence_receipt_id": "mfx_..." },
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
  runtime_id
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
from operating on a replacement runtime with the same Cat ID.

### 4.4 Volume grant

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

### 4.5 Closed action payloads

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

Precondition: exact Running runtime. Success: Guest quiesce/local durability
barrier and VMM pause completed, and the exact runtime is durably recorded as
Suspended. Work-fence change is Rejected with source preserved.

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

Success requires new Guest work stopped, retained volumes at `R == L`, VMM and
backend teardown, and a durable absence/Cold record. Failure that leaves a
local-ahead journal returns source preserved or indeterminate and MUST NOT
delete it.

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
a recorded post-Node effect under the same Destroy command.

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
generic residue cleanup path.

## 5. Node acceptance and execution

Before the first physical side effect, the Node performs, in order:

1. authenticate the caller and exact target Node;
2. verify body SHA-256 and protocol version;
3. look up `dispatch_id` in the durable Node job journal;
4. for a new dispatch, validate command/action identities, expected runtime,
   authority freshness and grant prerequisites;
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
and retained-volume postconditions.

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
intent_generation
command_id + command_seq + authority_revision/current status
dispatch_id + dispatch_seq + exact request digest
target_node_id
node_claim_id
action kind
expected runtime identity
all required grant/effect identities
```

Any mismatch is stale/conflicting evidence. It remains queryable but does not
mutate settled runtime, placement, Operation, routes or grants. A duplicate
exact result is a no-op. Same identity with different content is an invariant
violation and pages an operator.

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
new wake intent creates current command W and supersedes S
Node later returns Succeeded(D1, Suspended)
result is stored but cannot settle W or its Operation
planner uses the proven Suspended runtime and proposes Resume under W
```

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

During Freeze no V1 lifecycle job may remain in flight. Activate switches the
database authority version to V2 and prevents old writers. Contract removes V1
lifecycle decode/execute/journaling only after the ADR-0035 deletion conditions
and the characterization matrix pass.

There is no permanent translation adapter and no fallback that maps a V2
dispatch to V1 `CleanupCat`, epoch zero or a generation-derived Job ID.
