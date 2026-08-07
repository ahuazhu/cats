# Node runtime transaction V2

- Status: Architecture contract
- Version: 2
- Authority: [ADR-0040](../decisions/0040-terminal-durable-runtime-ownership.md)
- Scope: Node-local runtime ownership, NodeJob execution/replay, local route
  authority, admission serialization and Agent replacement

Normative words `MUST`, `MUST NOT`, `SHOULD` and `MAY` are used as in RFC 2119.
This is the only terminal contract. A V1 runtime JSON file, process-local job
journal or V1 route authority is never decoded or imported by V2.

## 1. Store and process boundary

The production path is:

```text
<state_dir>/authority/                 mode 0700, Cats service owner
  node-runtime-v2.lock                 mode 0600, exclusive process lock
  node-runtime-v2.sqlite3              mode 0600
  node-runtime-v2.sqlite3-wal          SQLite managed
  node-runtime-v2.sqlite3-shm          SQLite managed
```

The Agent MUST reject symlinks and non-regular database/lock files, verify
directory ownership/mode without following links, and hold an exclusive
nonblocking OS lock on `node-runtime-v2.lock` for its full lifetime before it
opens SQLite or touches a runtime. A second Agent performs no recovery,
NodeJob, admission or process mutation. Network filesystems are unsupported.

Every connection applies and verifies:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;       -- returned value must be "wal"
PRAGMA synchronous = FULL;       -- returned value must be 2
PRAGMA trusted_schema = OFF;
PRAGMA busy_timeout = <bounded nonzero value>;
```

Production builds MUST use SQLite defensive configuration, disable extension
loading, use bound parameters and accept only migrations compiled into the
binary. `application_id`, `user_version`, a schema content digest and the
terminal protocol version are checked before recovery. A higher, lower,
unknown or partially applied version is not auto-migrated during Agent start.

Initial creation or an offline schema upgrade MUST fsync the database and its
parent directory before the version is eligible for activation. A committed
WAL transaction under `synchronous=FULL` is authoritative even before a
checkpoint. Checkpoint failure is a health condition, not permission to delete
the WAL. Shutdown performs a bounded `wal_checkpoint(FULL)` after admission and
job execution stop; failure preserves the files and fails the shutdown gate.

All SQLite work executes on a bounded blocking authority worker, never directly
on an async executor. No authority transaction spans a systemd, `/proc`, socket,
VMM, blockd, cloud, metadata-store or network call.

## 2. Closed types and canonical bytes

Opaque IDs are nonempty canonical ASCII values bounded by the producing
protocol. Sequence and generation fields are positive signed 64-bit integers.
Digests are raw 32-byte SHA-256 values in SQLite and lowercase hexadecimal on
diagnostic surfaces. Timestamps are audit fields and never order authority.

Closed enums are represented by constrained integers, not unconstrained text:

```text
runtime_state       = running | suspended | warm | cold
runtime_phase       = preparing | current | retiring | retired | quarantined
member_role         = vmm | blockd | runtime_helper
dispatch_phase      = accepted | executing | terminal
result_phase        = succeeded | rejected | failed
step_phase          = prepared | observed | verified | compensated | quarantined
route_state         = installing | active | retiring | revoked | quarantined
gate_state          = closed | active | retiring | revoked | quarantined
retirement_mode     = cancel_and_drain | require_idle
work_phase          = prepared | draining | applied | busy | blocked | compensated
```

NodeJob V2 request and response bytes use the canonical profile frozen by
`lifecycle-command-v2.md`. The database retains the exact request body, its
SHA-256 digest, the exact terminal response body and its digest. Decoding into
rows does not replace exact bytes. Re-encoding equivalence cannot authorize a
duplicate dispatch whose original bytes differ.

## 3. Normative logical schema

Implementations MAY split indexes or audit-only columns, but MUST preserve the
following entities, relationships and constraints. Authority fields may not be
stored only inside JSON.

### 3.1 Store and Cat authority

`store_meta` is a singleton containing:

```text
schema_version, schema_digest, protocol_version,
node_id, database_id, created_host_boot_id, created_at
```

`database_id` is random and immutable. Changing `node_id`, schema digest or
protocol version in place is corruption.

`agent_session` records one fresh opaque session ID, Host boot ID and start
transaction per successful exclusive-lock acquisition. Exactly one session is
marked current. A new session is committed before listeners open; it does not
claim that a runtime was adopted.

`cat_local_authority` contains:

```text
cat_id PK, workspace_id,
authority_revision,
runtime_id?, runtime_generation?, runtime_state?, runtime_revision?,
intent_generation?,
command_id?, command_seq?, dispatch_id?, dispatch_seq?, request_body_sha256?,
target_node_id?, node_claim_id?, result_id?,
host_boot_id?, guest_boot_id?,
gate_state, current_route_install_id?,
quarantine_code?, updated_transaction_id
```

Its lineage columns are all-null only when no settled local runtime exists; for
a current runtime they are a complete `SettledLifecycleLineageV1`. Partial
lineage is forbidden. `target_node_id` MUST equal `store_meta.node_id`.
`runtime_generation` strictly increases for a Cat whenever a fresh physical
runtime lineage is created; Resume/Restore that preserve the physical lineage
retain it only when their action contract says so.

Every mutation compares `authority_revision` and increments it exactly once.
Wall clock is not an alternative CAS.

### 3.2 Runtime instances, scopes and members

`runtime_instance` contains one row per historical physical lineage:

```text
runtime_id PK, cat_id FK, runtime_generation,
created_by_dispatch_id, phase, stable_state,
host_boot_id?, guest_boot_id?,
scope_unit?, systemd_invocation_id?, cgroup_path?,
runtime_dir, snapshot_identity?, memory_backing_identity?,
created_transaction_id, retired_transaction_id?
```

`UNIQUE(cat_id, runtime_generation)` holds. At most one row per Cat has
`phase IN (preparing,current,retiring,quarantined)`. A Warm row may have null
live-scope fields; Running and Suspended production rows may not.

`runtime_member` contains:

```text
member_id PK, runtime_id FK, role, logical_key,
host_boot_id, scope_unit, systemd_invocation_id, cgroup_path,
pid, process_start_ticks, pid_namespace_inode,
executable_device, executable_inode, executable_path,
protocol_boot_id, lifecycle_phase,
started_by_step_id, exit_observation?
```

`UNIQUE(runtime_id, role, logical_key)` holds. A member becomes `verified` only
after both `/proc`/systemd identity and its role-specific protocol handshake
match. An exit observation does not authorize a signal or deletion.

`runtime_disk` contains:

```text
runtime_id FK, disk_id, volume_id, attachment_id, fencing_epoch,
durability_mode, block_path, data_dir,
local_watermark, remote_watermark,
control_socket_identity, frontend_identity,
member_id, publisher_member_id?,
PRIMARY KEY(runtime_id, disk_id)
```

`remote_watermark <= local_watermark` is checked whenever both values are
known. Unknown watermarks close teardown and writer-release gates. For
kernel-NBD, `frontend_identity` includes device major/minor, sysfs identity and
allocation generation. For vhost-user-blk it includes canonical socket inode,
negotiated device/config identity and queue count. A path alone is insufficient.

`runtime_endpoint` records exact API/vsock/network/tap/socket identities needed
to re-open and handshake the runtime. Socket inodes and peer credentials are
evidence, not authority without the matching protocol boot identity.

### 3.3 Dispatch, claim, steps and result

`node_dispatch` contains:

```text
dispatch_id PK, command_id, command_seq, dispatch_seq,
cat_id, workspace_id, intent_generation, target_node_id,
operation_id, source_evidence_id, command_kind, action_kind,
not_before_unix_ms, deadline_unix_ms,
request_body BLOB, request_body_sha256,
node_claim_id UNIQUE, phase,
accepted_transaction_id, terminal_result_id?,
UNIQUE(command_id, dispatch_seq)
```

The request identity columns and bytes are immutable. `node_claim_id` is
allocated in the first transaction for a recognized request, whether accepted
or rejected. A rejected request is inserted directly with `phase=terminal` and
one rejected result; an accepted request has `phase=accepted` before effects.

`dispatch_runtime_precondition` has exactly one row per dispatch. Its mode is
`absent` with an optional required fence receipt, or `exact` with
`runtime_id + node_id + runtime_generation + node_claim_id` and optional
Host-boot/Warm-snapshot fields as frozen by A0. `dispatch_volume_grant` stores
each exact grant/attachment/epoch/durability prerequisite in queryable columns.
`dispatch_route_retirement` stores the exact retirement request/receipt or
policy-promotion prerequisite. Closed action-specific fields use typed child
tables keyed by `dispatch_id`; no authority precondition exists only inside
the request BLOB.

`recovery_step` contains:

```text
step_id PK, dispatch_id FK, step_seq,
kind, phase, expected_authority_revision,
input_identity_digest, expected_postcondition_digest,
observed_identity_digest?, observation_bytes?,
attempt_count, last_error_class?,
UNIQUE(dispatch_id, step_seq)
```

Step kinds are action-specific closed enums. At most one nonterminal physical
step exists per dispatch. `prepared` commits before an effect; `observed` stores
the effect query; `verified` means the exact expected postcondition holds.
`compensated` requires its own receipt. `quarantined` authorizes no automatic
effect.

`node_result` contains:

```text
result_id PK, dispatch_id UNIQUE FK, node_claim_id UNIQUE,
phase, response_body BLOB, response_body_sha256,
runtime_id?, runtime_generation?, runtime_state?, runtime_revision?,
source_disposition, error_class?,
committed_transaction_id
```

A result row and every referenced byte/identity are immutable. Its runtime
identity and lineage MUST equal the `cat_local_authority` postcondition in the
same commit for `succeeded`. A failed action that proves preserved,
transitioned or absent state commits that local postcondition with its failed
result; an indeterminate failure commits quarantine with the result. Rejected
has no physical steps and commits against an unchanged authority revision.
Failed includes exact `source_disposition` and any provable runtime identity;
it is never deleted to turn transport replay into execution.

### 3.4 Route authority and admission work

`runtime_route_authority` contains:

```text
install_id PK, route_intent_id, route_epoch,
workspace_id, endpoint_id, cat_id, hostname, protocol, target_port, node_id,
intent_generation,
command_id, command_seq, dispatch_id, dispatch_seq, request_body_sha256,
target_node_id, node_claim_id, result_id,
runtime_id, runtime_generation, host_boot_id?, guest_boot_id?,
state, authority_revision,
install_request_body, install_request_sha256,
ack_body?, ack_sha256?,
installed_transaction_id, retired_transaction_id?,
UNIQUE(cat_id, route_epoch), UNIQUE(route_intent_id)
```

Every identifying field is immutable. Only state/revision and transaction
references change. `active` requires exact equality with the complete current
`cat_local_authority` lineage and Running runtime. At most one install per Cat
is `installing|active|retiring`. The exact install request and ACK are retained
for byte-identical replay; the ACK structurally echoes every identity/lineage
field, not only epoch or a digest.

`route_retirement_work` contains:

```text
retirement_work_id PK, retirement_id UNIQUE, request_digest,
scope_kind, reason_route_intent_id?,
reason_lifecycle_intent_generation?, reason_lifecycle_command_id?,
reason_policy_proposal_id?, expected_policy_cat_generation?, mode,
cat_id, install_id, old_route_intent_id, route_epoch,
old_lineage columns, expected_predecessor_kind,
predecessor_policy_proposal_id?, predecessor_retirement_token?,
expected_authority_revision, expected_work_fence?, guard_registry_revision?,
retirement_prepare_id UNIQUE,
phase, predecessor_retirement_id?, retirement_token?,
receipt_id?, receipt_body?, receipt_sha256?,
created_transaction_id, completed_transaction_id?
```

Scope and the corresponding reason family are exactly one of `route_intent`,
`lifecycle_command` or `policy_proposal`; all other reason columns are null. A
receipt cannot be rebound. `require_idle` with a nonzero or unknown exact guard
count commits `busy` without changing route authority.
`cancel_and_drain` can complete only after its selected guards are terminated
or an exact serving fence is recorded.

`authority_transaction` gives each committed local change an opaque ID and
monotonic database sequence for audit/recovery. It does not replace row-level
foreign keys or revisions.

An applied receipt is stored both as exact canonical bytes and these
structural fields:

```text
RouteRetirementReceiptV1 {
  retirement_id
  mode = cancel_and_drain | require_idle
  scope = route_intent | lifecycle_command | policy_proposal
  retirement_token
  predecessor = active_authority(old_install_id, old_route_epoch,
                                 old_settled_lineage)
              | retired_by_policy(policy_proposal_id,
                                  predecessor_retirement_token)
  outcome = retired | adopted_retired_predecessor
  reason_route_intent_id?
  reason_lifecycle_intent_generation?
  reason_lifecycle_command_id?
  reason_policy_proposal_id?
  old_install_id + old_route_intent_id + old_route_epoch
  old_settled_lineage: SettledLifecycleLineageV1
  guard_registry_revision
  cancelled_guard_set_digest?
  remaining_active_guard_count = 0
  admission_state = revoked
  durable_sequence + completed_at
}
```

Scope and reason fields are an immutable one-of. `cancelled_guard_set_digest`
is required only for `cancel_and_drain`. The receipt's `retirement_token` is a
fresh receipt identity; a `retired_by_policy` predecessor separately retains
the policy receipt token byte-for-byte. `retirement_prepare_id` never satisfies
either token. A receipt proves route admission retirement, not writer fencing
or `R == L`.

An idle busy proof structurally stores proposal/retirement/request identity,
old install/route/epoch/complete lineage, work-fence digest,
guard-registry revision, `active_guard_count > 0` or unknown, and
`authority_state=active`. It is not a retirement receipt and changes no route,
lifecycle or runtime authority.

`quarantine_condition` records entity kind/identity, stable machine code,
evidence digest, first/last transaction and explicit resolution receipt. It is
append-preserving; resolution does not erase the original evidence.

## 4. NodeJob transactions

### 4.1 Parse and recognition

Before SQLite, the Node checks transport authentication, endpoint version,
length bounds, canonical bytes, request digest, target Node, closed action and
required fields. An unparseable or unauthenticated message is not a recognized
dispatch and authorizes no row or effect.

A canonical request becomes recognized only after the pre-recognition checks
above and when its IDs are sufficient to bind a Node claim. In one immediate
transaction the Agent:

1. checks an existing `dispatch_id` byte-for-byte;
2. checks Cat, generation, command sequence and prerequisite identities;
3. allocates `node_claim_id` once;
4. inserts immutable dispatch bytes; and
5. commits either accepted authority or an exact terminal rejected result.

Only the accepted outcome authorizes recovery steps. Admission to execution is
also refused while the Cat or Node is quarantined, the local schema is not
healthy, or another dispatch owns incompatible physical work.

Wrong target Node, URL/body identity mismatch, request-header digest mismatch,
malformed input, failed transport authentication and existing-ID/different-byte
conflict are pre-recognition errors and create no claim/result. Once recognized,
stale command, runtime, retirement, promotion or volume-grant authority creates
the one durable terminal rejected claim/result.

### 4.2 Exact replay

| Existing state | Exact duplicate | Different bytes under same ID |
| --- | --- | --- |
| accepted/executing | Return same claim and current progress; do not duplicate a step | Corruption response; no mutation/effect |
| terminal succeeded | Return exact stored terminal bytes | Corruption response; no mutation/effect |
| terminal rejected | Return exact stored terminal bytes | Corruption response; no mutation/effect |
| terminal failed | Return exact stored terminal bytes | Corruption response; no mutation/effect |

Transport retry never creates a new semantic attempt. A controller that wants
another attempt creates a new `dispatch_id` under ADR-0035.

### 4.3 Physical action protocol

For each step:

1. transactionally insert `prepared` with exact input/current revision;
2. perform or query the effect outside SQLite and outside the admission mutex;
3. transactionally store the observation only if the prepared identity is
   still current;
4. independently verify the closed postcondition; and
5. mark `verified`, or persist `quarantined/blocked` evidence.

An ambiguous timeout is a possible effect. Recovery queries by exact external
identity and does not repeat a non-idempotent operation merely because step 3
is absent.

The final success transaction MUST:

- compare dispatch, claim, current authority and all verified prerequisites;
- create/update the complete runtime postcondition;
- update all exact member/resource evidence and authority revision;
- insert immutable `node_result` response bytes; and
- set `node_dispatch.phase=terminal` and result reference.

The commit is the response visibility point. There is no successful response
constructed from uncommitted memory.

## 5. Scope creation and process proof

The deterministic scope is created through systemd D-Bus with immutable Cat
metadata and the Cats runtime slice. A child used to start a runtime payload is
forked stopped or held behind a close-on-exec barrier. The Agent attaches it to
the exact scope, reads back scope `InvocationID`/`ControlGroup`, verifies the
child's `/proc/<pid>/cgroup`, persists the prepared membership evidence, and
only then releases the payload exec.

If the Agent dies before release, the blocked launcher/child MUST terminate
without executing the payload. If it dies after possible exec, startup union
reconciliation finds the scope/process even when SQLite has only a prepared
step. A payload which executed outside the intended scope is quarantined.

Adoption re-samples:

1. current Host boot ID;
2. exact systemd unit state, InvocationID and cgroup path;
3. all member PIDs in the cgroup, including unexpected members;
4. `/proc` start ticks, PID namespace, executable device/inode/path;
5. VMM/Guest/blockd role-specific handshakes; and
6. disk/frontend/socket/snapshot evidence required by the stable state.

Every expected member must match and every unexpected member must be explained
by a prepared recovery step. Otherwise the Cat is quarantined. Before sending a
signal, the Agent repeats the process tuple check or uses a pidfd opened after a
successful check. It never signals a stale recorded PID.

## 6. Admission cell protocol

### 6.1 Reconstruction

All cells begin `closed`. After union reconciliation, the Agent loads an
immutable database snapshot per Cat. It may publish `active` in memory only if:

- runtime state is Running and complete process/protocol proof is adopted;
- exactly one route install is active;
- every Workspace/Endpoint/Cat/route/Node/epoch/lineage field matches;
- no nonterminal recovery or retirement work can close admission; and
- the clock-health condition required by Route Grant V2 is true.

Database rows are never read on the request fast path. They are reflected into
the cell only by successful authority transactions plus revision checks.

### 6.2 Grant compare-and-guard

Route Grant parsing, canonical verification, signature/key/time checks and
hostname normalization occur outside the cell mutex. Then one critical section:

1. requires `gate_state=active`;
2. compares every grant claim to the cell's exact route install;
3. compares complete settled lineage and runtime identity;
4. checks the prepared token's expected authority revision has not changed;
5. increments the exact active guard generation and creates a guard; and
6. returns the immutable local proxy target bound to that guard.

No fallible I/O occurs inside the section. The guard decrement uses the same
cell and cannot underflow or apply to another guard generation.

The guard registry revision is the closed value
`{agent_session_id, sequence}`. Startup durably allocates a fresh opaque
`agent_session_id` before any listener opens; `sequence` increments in memory
on every gate transition and guard add/remove. The Agent process owns the
Node-to-Guest proxy transports, so its death closes those transports; Cat
scope processes do not proxy or retain guards. A replacement Agent starts with
zero guards under a new session ID and still processes all durable retirement
work before opening admission. Receipts retain the exact registry value; a
revision from another session is never compared as newer or older.

### 6.3 Install and reopen

An install request first closes the volatile gate under the mutex and captures
the current revision. Outside the lock a SQLite transaction structurally
validates the full A0 lineage/runtime and inserts the `installing` authority.
After any external endpoint proof, another transaction marks it active. Under
the mutex the Agent publishes the exact committed revision only if the runtime
and transition token still match. A stale install terminates stale; it never
overwrites a newer route.

Restart may reopen an active install only through §6.1. A revoke is never
reversed in place; re-publication uses a fresh route epoch and install ID.

Install CAS results are exact:

| Input | Result |
| --- | --- |
| Same `install_id` and byte-identical request | Return the stored byte-identical ACK |
| Expected predecessor differs | `stale_install`, no mutation |
| Same epoch/install ID with different bytes or lineage | `install_conflict`, quarantine/alert, no mutation |
| Runtime or full settled lineage differs | `runtime_lineage_mismatch`, no mutation |
| Fresh greater epoch, exact predecessor and runtime | Commit installing/active under the staged protocol |

### 6.4 Revoke, quiesce and retirement

The ordering is fixed:

1. outside the mutex durably recognize exact retirement work in `planned` with
   its expected authority/runtime/lineage revision; restart handles it before
   opening admission;
2. under the mutex compare that exact revision and allocate a transition token:
   - `require_idle` with nonzero/unknown guards or changed work fence leaves the
     gate/authority unchanged and captures an immutable busy observation;
   - `require_idle` at exact zero, or `cancel_and_drain`, sets the volatile gate
     to retiring and captures the guard-registry fence;
3. outside the mutex, persist a busy proof and finish without route mutation,
   or CAS `route_retirement_work(prepared)` plus the durable closing intent;
4. for `cancel_and_drain`, select/cancel exact guards outside the mutex and wait
   boundedly; a timeout remains blocked with the Running source preserved;
5. commit `revoked` authority and the exact receipt only after zero guards or a
   valid serving fence; and
6. publish the committed revoked revision under the mutex. Lifecycle physical
   quiesce may begin only after its exact command-scoped receipt is durable.

If SQLite prepare in step 3 fails, the in-memory gate can reopen only after an
outside-lock database query proves the old revision is still current and the
same transition token then wins the mutex comparison. If planned work committed
but the Agent died before step 2, restart evaluates it behind the global closed
recovery gate. If step 3 commits, restart sees prepared work and remains
closed. Stale cleanup can never reopen a newer revision.

A proposal-scoped `require_idle` receipt cannot be rebound to a lifecycle
command. Auto promotion requires that exact policy receipt plus A0's immutable
`PolicyRetirementPromotionV2`. If a manual leaving-Running command wins after
policy retirement but before promotion, it creates distinct command-scoped
`cancel_and_drain` work with
`predecessor=retired_by_policy(policy_proposal_id, policy_retirement_token)`.
Under the same Cat cell C proves the old authority is still revoked, the full
lineage/install/epoch matches, guards are zero (or are cancelled by the manual
authority), and no newer install exists; it then writes a new
`outcome=adopted_retired_predecessor` receipt without modifying or reopening
the old epoch.

Control-plane command adoption and route compensation compete through B0's one
materialized-Route CAS. If compensation installs a fresh epoch first, local
adoption of the old predecessor terminates stale; if adoption wins, the
compensation terminates stale. Node recovery returns the immutable local
receipt but never decides this global owner or changes an epoch in place.

## 7. Startup and recovery reducer

Startup does not listen on the NodeJob or proxy endpoints until the global
recovery gate is installed. It then enumerates these independently:

- all current/quarantined runtime and nonterminal work rows;
- all systemd units with the exact Cats scope metadata/prefix;
- all processes in their cgroups and every expected PID;
- all runtime directories and known socket namespaces; and
- all block frontend resources that have a recorded or discoverable Cats
  ownership tag.

Each enumerator reports success/failure and is tested against a known positive.
An unsuccessful or partial enumeration yields `unknown`, never an empty set.
The reducer operates over the union keyed by exact Cat/runtime/scope identity.

| Evidence | Outcome |
| --- | --- |
| Complete DB + exact scope/process/protocol/resource proof | Adopt current runtime and resume closed work |
| Complete Warm DB + exact snapshot/memory/disk proof and no live members | Adopt Warm local evidence |
| Prepared step + exact observed postcondition | Record observation, verify, continue transaction |
| Prepared step + proven no effect and retry-safe operation | Retry the same step identity |
| Unknown/malformed DB or failed enumeration | Cordon Node; quarantine affected/all Cats |
| Scope/process/socket/resource without complete DB binding | Quarantine; do not signal/delete/report Cold |
| DB expects member but member absent | Recover only through action-specific proof; otherwise quarantine |
| Identity or lineage mismatch | Quarantine and deny jobs/admission |

`proven_absent` requires an action-specific closed proof, not merely the lack of
one artifact. It can finish a prepared non-idempotent step but does not by
itself settle control-plane Cold.

Control-plane registration runs after local reconciliation and contains only
adopted runtime facts. Quarantine is an explicit condition. A missing or
quarantined runtime is never emitted as a Cold observation.

## 8. Normative crash outcomes

| Crash/failure boundary | Durable state | Required recovery |
| --- | --- | --- |
| Before recognized acceptance | No claim/effect authority | Safe exact redelivery |
| During acceptance commit | Commit is all-or-nothing | Query by dispatch; never infer from response loss |
| Rejected result response lost | Immutable rejected result | Return exact bytes |
| Accepted, before first step | Accepted claim | Continue or fail with exact source disposition |
| Step prepared, before effect | Prepared | Prove absence or perform same identity safely |
| Scope created, before child exec | Prepared scope/member | Remove only with exact empty-scope proof or continue |
| Child may have exec'd, before observation | Prepared + possible process | Union reconcile and handshake; never blind respawn/kill |
| VMM/blockd handshake passed, before runtime commit | Verified steps, no success | Reverify all postconditions, then atomic runtime/result commit |
| Runtime/result transaction commit, response lost | Terminal result + postcondition | Return exact bytes, no effect |
| Pause/snapshot initiated, result absent | Prepared/observed transition | Query exact VMM/snapshot and retain source or quarantine |
| VMM exits, blockd/journal remains | Recovery steps + disk watermarks | Preserve publisher/journal; finish drain or block |
| Route volatile gate closed, prepare not committed | Old durable route | Restart can revalidate/reopen old exact route |
| Retirement prepare committed, before drain | Prepared + durable closing intent | Restart closed; resume exact drain |
| Guards drained, revoke not committed | Prepared/draining | Restart closed; reverify zero/fence then commit |
| Revoke/receipt committed, response lost | Revoked + immutable receipt | Return exact receipt; never reopen epoch |
| Install committed, volatile publish absent | Active DB install, closed memory | Startup/full recheck may publish exact install |
| SQLite full/I/O/sync/corrupt/unknown schema | Authority unavailable/uncertain | Close gates, stop new work, preserve processes/data, cordon |
| Agent killed with Relaxed `R < L` | DB/process/journal may be partial | Adopt exact publisher or quarantine; never delete/release |
| Host reboot | Old live-process identity invalid | Warm disk proof may survive; all live-member states require fence/fallback |

## 9. Action postconditions

Each action implementation refines these minimums:

| Action | Success requires |
| --- | --- |
| Start | Fresh runtime generation; exact scope/members/frontends/Guest proof; all grants valid; Running row + terminal result in one commit |
| Resume | Exact Suspended source and runtime lineage; VMM running proof; route still closed until a fresh install; Running result transaction |
| Restore | Exact Warm snapshot/runtime lineage; new live-member proof as defined by A0; Running result transaction |
| Suspend | Exact command-scoped route retirement; paused VMM proof; blockd/journal ownership; Suspended result transaction |
| Warm | Exact retired route; snapshot and memory identity; VMM/blockd exit and durability disposition; Warm result transaction |
| Cold | Exact retired route; writer/grant/durability proof; no owned live members; retained/discarded local data receipt; Cold result transaction |
| Destroy | Exact route/writer/grant proof and ADR-0025 disk disposition; no runtime authority; terminal result transaction |
| FallbackCold | Exact failed Resume/Restore source disposition plus fence/durability prerequisites; Cold result transaction |

No action treats an error string, child exit or socket refusal as the complete
postcondition.

## 10. Breaking cutover and deletion inventory

V2 activation begins only from a safety manifest proving:

```text
public_v1_admission = 0
old_route_authorities = 0
old_active_sessions = 0 or externally fenced
old_node_jobs_nonterminal = 0
old_live_runtimes = 0 or externally fenced and retained
old_relaxed_journals_R_lt_L = 0 or retained behind an explicit block
```

The activation build creates an empty V2 database. It does not read
`runtime-ledger/*.json`. The following production paths are deleted in the same
terminal release:

- per-Cat JSON ledger read/write and best-effort `persist_cat/forget_cat`;
- process-local NodeJob replay authority and failed-result retry semantics;
- V1 NodeJob endpoint/decoder;
- V1/unsigned Route Grant signer, parser, verifier and admission;
- PID/path-only adoption or teardown; and
- any proxy path that reads runtime and acquires its guard separately.

Qualification inventories symbols, endpoints, systemd units, files and live
processes to prove absence. Rollback requires returning through the same
drain/fence manifest; it cannot mount a V1 reader alongside V2.

## 11. Observability without authority leakage

The Agent exports counts and stable condition codes for recovery backlog,
quarantined Cats, unexpected scopes/members, database/WAL/checkpoint health,
closed admission gates, active guards, stuck retirements and Relaxed
`R < L`. Metrics and logs contain opaque IDs/digests, not credentials, exact
grant tokens or request bodies. They can alert and diagnose; they cannot settle
a dispatch, open admission or authorize deletion.
