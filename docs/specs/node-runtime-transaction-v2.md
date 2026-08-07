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
  node-runtime-v2-meta.json            mode 0600, canonical Node/session root
  cats/                                mode 0700
    <sha256(canonical-cat-id)>.json     mode 0600, canonical Cat authority
```

The Agent MUST open the authority directory and `cats/` through verified
directory file descriptors, reject symlinks and non-regular lock/document
files, verify ownership/mode without following links, and hold an exclusive
nonblocking OS lock on `node-runtime-v2.lock` for its full lifetime before it
reads authority or touches a runtime. A second Agent performs no recovery,
NodeJob, admission or process mutation. Network filesystems are unsupported.

Every document uses the exact canonical JSON profile frozen by this protocol.
It contains schema version, schema digest and protocol version; higher, lower,
unknown, noncanonical or partially written content is not migrated during
Agent start. File names are the full lowercase SHA-256 of the canonical Cat ID,
and the decoded `cat_id` MUST hash back to the name.

Before a Cat mutation, the Agent reserves the Cat's next revision under the
admission cell and records a fresh mutation token. While that token is pending,
no second authority mutation for the Cat may start. The reservation releases
the cell mutex before encoding, filesystem work or any await. Completion
publishes the revision only when the same token still owns the reservation.

One reserved Cat mutation is one complete document replacement:

1. compare the loaded `authority_revision` and transition identity;
2. encode and re-validate the complete next document in memory;
3. create a random same-directory temporary regular file with
   `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600;
4. write all bytes, sync the file and verify its type/owner/mode through the
   held descriptor;
5. atomically rename it over the exact Cat path using directory-relative
   operations; and
6. sync the `cats/` directory before publishing the new revision or response.

A failed write, file sync, rename or directory sync publishes no success. On
restart the old or new complete document is authoritative; a stray temporary
file is never decoded as authority. Initial creation or offline schema upgrade
also syncs every created directory before activation. Cleanup is confined to
proven temporary files in the held authority directory.

A Cat document may be deleted only after an exact revision proves that it is a
settled tombstone with no current runtime, active/prepared work, unsettled
result, quarantine evidence or referenced receipt. Deletion unlinks that exact
regular file through the held `cats/` directory descriptor and syncs the
directory before reporting completion. Either the settled tombstone or absence
is safe after a crash; absence never authorizes reconstruction from residue.

`node-runtime-v2-meta.json` is replaced by the same protocol before listeners
open when a fresh Agent session is allocated. Cat mutations never require an
atomic write spanning two Cat documents or the root document. Startup rebuilds
a global immutable-ID index from all Cat documents; duplicate dispatch, claim,
result, runtime, install or retirement IDs are corruption and keep gates closed.

No authority document replacement spans a systemd, `/proc`, socket, VMM,
blockd, cloud, metadata-store or network call. Encoding and filesystem I/O run
outside async-executor and admission-mutex critical sections.

## 2. Closed types and canonical bytes

Opaque IDs are nonempty canonical ASCII values bounded by the producing
protocol. Sequence and generation fields are positive signed 64-bit integers.
Digests are exact lowercase 64-character SHA-256 hexadecimal strings in the
canonical documents and on diagnostic surfaces. Timestamps are audit fields
and never order authority.

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
`lifecycle-command-v2.md`. The Cat authority document retains the exact request
body, its SHA-256 digest, the exact terminal response body and its digest.
Decoding structural fields does not replace exact bytes. Re-encoding
equivalence cannot authorize a duplicate dispatch whose original bytes differ.

## 3. Normative logical document schema

The canonical root and Cat document schemas MUST preserve the following nested
entities, relationships and constraints. Authority fields are explicit typed
members; an opaque compatibility payload or digest is not a substitute.

### 3.1 Store and Cat authority

`store_meta` is the root document containing:

```text
schema_version, schema_digest, protocol_version,
node_id, store_id, created_host_boot_id, created_at
```

`store_id` is random and immutable. Changing `node_id`, schema digest or
protocol version in place is corruption.

`agent_session` records one fresh opaque session ID, Host boot ID and start
commit per successful exclusive-lock acquisition. Exactly one session is
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
quarantine_code?, updated_commit_id
```

Its lineage fields are all-null only when no settled local runtime exists; for
a current runtime they are a complete `SettledLifecycleLineageV1`. Partial
lineage is forbidden. `target_node_id` MUST equal `store_meta.node_id`.
`runtime_generation` strictly increases for a Cat whenever a fresh physical
runtime lineage is created; Resume/Restore that preserve the physical lineage
retain it only when their action contract says so.

Every mutation compares `authority_revision` and increments it exactly once.
Wall clock is not an alternative CAS.

### 3.2 Runtime instances, scopes and members

`runtime_instance` contains one element per retained historical physical lineage:

```text
runtime_id PK, cat_id FK, runtime_generation,
created_by_dispatch_id, phase, stable_state,
host_boot_id?, guest_boot_id?,
scope_unit?, systemd_invocation_id?, cgroup_path?,
runtime_dir, snapshot_identity?, memory_backing_identity?,
created_commit_id, retired_commit_id?
```

`UNIQUE(cat_id, runtime_generation)` holds within the canonical document. At
most one element per Cat has
`phase IN (preparing,current,retiring,quarantined)`. A Warm element may have
null live-scope fields; Running and Suspended production elements may not.

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
request_body_bytes, request_body_sha256,
node_claim_id UNIQUE, phase,
accepted_commit_id, terminal_result_id?,
UNIQUE(command_id, dispatch_seq)
```

The request identity fields and bytes are immutable. `node_claim_id` is
allocated in the first atomic document replacement for a recognized request,
whether accepted or rejected. A rejected request is inserted directly with
`phase=terminal` and one rejected result; an accepted request has
`phase=accepted` before effects.

`dispatch_runtime_precondition` has exactly one object per dispatch. Its mode is
`absent` with an optional required fence receipt, or `exact` with
`runtime_id + node_id + runtime_generation + node_claim_id` and optional
Host-boot/Warm-snapshot fields as frozen by A0. `dispatch_volume_grant` stores
each exact grant/attachment/epoch/durability prerequisite in structural fields.
`dispatch_route_retirement` stores the exact retirement request/receipt or
policy-promotion prerequisite. Closed action-specific fields use typed child
objects keyed by `dispatch_id`; no authority precondition exists only inside
the request bytes.

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
phase, response_body_bytes, response_body_sha256,
runtime_id?, runtime_generation?, runtime_state?, runtime_revision?,
source_disposition, error_class?,
committed_commit_id
```

A result entry and every referenced byte/identity are immutable. Its runtime
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
installed_commit_id, retired_commit_id?,
UNIQUE(cat_id, route_epoch), UNIQUE(route_intent_id)
```

Every identifying field is immutable. Only state/revision and commit
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
old_lineage fields, expected_predecessor_kind,
predecessor_policy_proposal_id?, predecessor_retirement_token?,
expected_authority_revision, expected_work_fence?, guard_registry_revision?,
retirement_prepare_id UNIQUE,
phase, predecessor_retirement_id?, retirement_token?,
receipt_id?, receipt_body?, receipt_sha256?,
created_commit_id, completed_commit_id?
```

Scope and the corresponding reason family are exactly one of `route_intent`,
`lifecycle_command` or `policy_proposal`; all other reason fields are null. A
receipt cannot be rebound. `require_idle` with a nonzero or unknown exact guard
count commits `busy` without changing route authority.
`cancel_and_drain` can complete only after its selected guards are terminated
or an exact serving fence is recorded.

The current `authority_commit` envelope gives each committed Cat document
revision an opaque ID, the prior and next `authority_revision`, and a document
digest for audit/recovery. The digest is computed over the canonical document
with the digest member omitted, avoiding a self-reference. The envelope does
not replace structural references or revisions.

Terminal dispatches and exact result bytes remain in the Cat document until an
exact control-plane settlement receipt proves that dispatch can never be
redelivered. History compaction is itself one ordinary authority revision; it
cannot remove the current runtime lineage, active/prepared work, an unsettled
result, quarantine evidence or any receipt referenced by current authority.

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
evidence digest, first/last commit and explicit resolution receipt. It is
append-preserving; resolution does not erase the original evidence.

## 4. NodeJob durable mutations

### 4.1 Parse and recognition

Before touching the authority store, the Node checks transport authentication,
endpoint version, length bounds, canonical bytes, request digest, target Node,
closed action and required fields. An unparseable or unauthenticated message is
not a recognized dispatch and authorizes no document mutation or effect.

A canonical request becomes recognized only after the pre-recognition checks
above and when its IDs are sufficient to bind a Node claim. In one atomic Cat
document replacement the Agent:

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

1. commit `prepared` with exact input/current revision;
2. perform or query the effect outside authority-file I/O and outside the
   admission mutex;
3. commit the observation only if the prepared identity is
   still current;
4. independently verify the closed postcondition; and
5. mark `verified`, or persist `quarantined/blocked` evidence.

An ambiguous timeout is a possible effect. Recovery queries by exact external
identity and does not repeat a non-idempotent operation merely because step 3
is absent.

The final success document replacement MUST:

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
reconciliation finds the scope/process even when the authority document has only a prepared
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
immutable authority-document snapshot per Cat. It may publish `active` in
memory only if:

- runtime state is Running and complete process/protocol proof is adopted;
- exactly one route install is active;
- every Workspace/Endpoint/Cat/route/Node/epoch/lineage field matches;
- no nonterminal recovery or retirement work can close admission; and
- the clock-health condition required by Route Grant V2 is true.

Authority documents are never read on the request fast path. They are reflected
into the cell only by successful atomic replacements plus revision checks.

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
the current revision. Outside the lock an atomic document replacement
structurally validates the full A0 lineage/runtime and inserts the `installing`
authority. After any external endpoint proof, another replacement marks it
active. Under the mutex the Agent publishes the exact committed revision only
if the runtime and transition token still match. A stale install terminates
stale; it never overwrites a newer route.

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

If the durable prepare in step 3 fails, the in-memory gate can reopen only after
an outside-lock authority-document read proves the old revision is still
current and the same transition token then wins the mutex comparison. If
planned work committed but the Agent died before step 2, restart evaluates it
behind the global closed recovery gate. If step 3 commits, restart sees
prepared work and remains closed. Stale cleanup can never reopen a newer
revision.

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

- all current/quarantined runtime and nonterminal work in Cat authority
  documents;
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
| Complete authority document + exact scope/process/protocol/resource proof | Adopt current runtime and resume closed work |
| Complete Warm document + exact snapshot/memory/disk proof and no live members | Adopt Warm local evidence |
| Prepared step + exact observed postcondition | Record observation, verify, continue the durable mutation |
| Prepared step + proven no effect and retry-safe operation | Retry the same step identity |
| Unknown/malformed authority document or failed enumeration | Cordon Node; quarantine affected/all Cats |
| Scope/process/socket/resource without complete document binding | Quarantine; do not signal/delete/report Cold |
| Authority document expects member but member absent | Recover only through action-specific proof; otherwise quarantine |
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
| Runtime/result document commit, response lost | Terminal result + postcondition | Return exact bytes, no effect |
| Pause/snapshot initiated, result absent | Prepared/observed transition | Query exact VMM/snapshot and retain source or quarantine |
| VMM exits, blockd/journal remains | Recovery steps + disk watermarks | Preserve publisher/journal; finish drain or block |
| Route volatile gate closed, prepare not committed | Old durable route | Restart can revalidate/reopen old exact route |
| Retirement prepare committed, before drain | Prepared + durable closing intent | Restart closed; resume exact drain |
| Guards drained, revoke not committed | Prepared/draining | Restart closed; reverify zero/fence then commit |
| Revoke/receipt committed, response lost | Revoked + immutable receipt | Return exact receipt; never reopen epoch |
| Install committed, volatile publish absent | Active durable install, closed memory | Startup/full recheck may publish exact install |
| File full/I/O/sync/malformed/unknown schema | Authority unavailable/uncertain | Close gates, stop new work, preserve processes/data, cordon |
| Agent killed with Relaxed `R < L` | Document/process/journal may be partial | Adopt exact publisher or quarantine; never delete/release |
| Host reboot | Old live-process identity invalid | Warm disk proof may survive; all live-member states require fence/fallback |

## 9. Action postconditions

Each action implementation refines these minimums:

| Action | Success requires |
| --- | --- |
| Start | Fresh runtime generation; exact scope/members/frontends/Guest proof; all grants valid; Running postcondition + terminal result in one commit |
| Resume | Exact Suspended source and runtime lineage; VMM running proof; route still closed until a fresh install; Running result commit |
| Restore | Exact Warm snapshot/runtime lineage; new live-member proof as defined by A0; Running result commit |
| Suspend | Exact command-scoped route retirement; paused VMM proof; blockd/journal ownership; Suspended result commit |
| Warm | Exact retired route; snapshot and memory identity; VMM/blockd exit and durability disposition; Warm result commit |
| Cold | Exact retired route; writer/grant/durability proof; no owned live members; retained/discarded local data receipt; Cold result commit |
| Destroy | Exact route/writer/grant proof and ADR-0025 disk disposition; no runtime authority; terminal result commit |
| FallbackCold | Exact failed Resume/Restore source disposition plus fence/durability prerequisites; Cold result commit |

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

The activation build creates an empty V2 authority directory. It does not read
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
quarantined Cats, unexpected scopes/members, authority-file/sync health,
closed admission gates, active guards, stuck retirements and Relaxed
`R < L`. Metrics and logs contain opaque IDs/digests, not credentials, exact
grant tokens or request bodies. They can alert and diagnose; they cannot settle
a dispatch, open admission or authorize deletion.
