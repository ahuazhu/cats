# ADR-0040: Terminal durable Node runtime ownership

- Status: Proposed
- Date: 2026-08-07
- Replaces: the removed legacy Node runtime-ledger contract (retained in Git history,
  not as a second current architecture document)
- Relates to: ADR-0002 (lifecycle), ADR-0015 (block frontends), ADR-0018
  (Workspace ownership), ADR-0021/0022 (Relaxed durability), ADR-0025
  (disposable roots), ADR-0030 (reported-runtime reconciliation), ADR-0035
  (LifecycleCommand authority), ADR-0039 (Route Grant V2); issues #207 and #273
- Protocol: [Node runtime transaction V2](../specs/node-runtime-transaction-v2.md)
- Qualification: [Runtime ownership characterization matrix](../node-runtime-ownership-characterization-test-matrix.md)
- Required contract snapshots: LifecycleCommand/NodeJob V2 at
  `bd51cc16c9238e92f10a5d99658231f2e8a99e30`; Route Grant V2 at
  `648a91a4c382b5cb8279640fa8495fa460233455`

## Context

The current Node Agent has three authority gaps which cannot be repaired
independently:

1. a per-Cat JSON ledger is written after physical runtime changes and write
   failures are logged but ignored;
2. accepted work and NodeJob results live in a process-local `HashMap`, so an
   Agent replacement can repeat an external effect or forget a terminal
   failure; and
3. route proxying reads Running/runtime identity, releases that lock, and only
   then acquires an activity guard. Lifecycle quiesce or route revocation can
   cross that interval.

The removed legacy ADR correctly required strong process identity and fail-closed adoption,
but its staged compatibility shape is no longer the product target. In
particular, "successful/rejected durable, failed retryable" conflicts with the
immutable terminal results frozen by ADR-0035, and best-effort JSON cannot be
the reciprocal local authority required by ADR-0035 and ADR-0039.

The project is still early. We therefore choose one terminal format and a
breaking activation instead of preserving the old ledger or NodeJob protocol.

## Decision

### 1. One file-backed local authority store

Each production Node has one V2 authority directory at
`<state_dir>/authority/`. A root document freezes Node identity and schema; one
canonical document per Cat contains every Cat-local authority fact. These V2
documents are the only durable Node-local authority for:

- current and historical runtime identity and local stable postcondition;
- per-Cat systemd scope and process membership proof;
- every recognized NodeJob V2 dispatch, Node claim, recovery step and exact
  terminal result bytes;
- `RuntimeRouteAuthorityV1`, install/revoke state, retirement work and exact
  receipts; and
- quarantine/cordon reasons and recovery progress.

The Agent is the only process writer. It holds one exclusive lifetime lock. A
short per-Cat mutation reservation admits at most one authority replacement at
a time without holding the admission mutex across filesystem I/O or an await.
A commit writes one complete canonical V2 document to a fresh same-directory
file opened with exclusive, no-follow semantics, syncs the file, atomically
renames it over the prior revision and syncs the parent directory. The old or
new complete document is therefore visible after a crash; a later best-effort
write is never the durability boundary. A successful lifecycle action
publishes the runtime postcondition and immutable exact result bytes in that
one replacement before the response is made visible.

No cross-Cat transaction is required: NodeJob, runtime, route and recovery
authority all name exactly one Cat, and Node-global identity changes only at
offline activation or Agent-session start before listeners open. Duplicate
global IDs across Cat documents are corruption detected while rebuilding the
startup index. A removed or Cold Cat retains a tombstone authority document
until the control plane durably acknowledges every result it can redeliver.
Only then may the Agent delete the tombstone with an exact revision check,
unlink and parent-directory sync.

The file store is local evidence, not storage or placement authority. It
cannot grant a volume lease, advance a fencing epoch, publish a Root, assign a
Cat to this Node or settle control-plane state. Those remain with their
ADR-defined authorities. Loss or corruption of the local authority store fails
closed and requires external fencing or a proven Cold reconstruction.

### 2. Closed identities, not opaque compatibility blobs

The normative schema is in the protocol. Its relationships are structural:

```text
CatLocalAuthority
  -> current RuntimeInstance
       -> RuntimeMember* -> systemd scope/process/protocol proof
  -> NodeDispatch -> NodeClaim -> RecoveryStep* -> TerminalResult
  -> RuntimeRouteAuthority -> RouteRetirementWork* -> Receipt?
  -> QuarantineCondition*
```

The shared lifecycle lineage is exactly:

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

The canonical document stores these fields structurally and compares every
field. Neither a digest-only value nor `cat_id + generation` is sufficient
authority. Opaque request/result bytes are retained in addition so an exact
replay can return the original response.

A process is identified by the closed tuple:

```text
node_id + host_boot_id + runtime_id + runtime_generation
+ scope_unit + systemd_invocation_id + cgroup_path
+ pid + process_start_ticks + pid_namespace_inode
+ executable_device + executable_inode + executable_path
+ role-specific protocol identity
```

Role-specific identity includes VMM/Guest boot identity and, for every blockd,
the exact disk, volume, attachment, fencing epoch, block path and control
protocol boot identity. A PID, executable name, socket path, Cat ID or cgroup
alone never proves ownership.

### 3. Immutable NodeJob execution

The Node validates the V2 envelope and canonical bytes before recognizing a
dispatch. For every recognized dispatch it allocates exactly one opaque
`node_claim_id` and durably commits either `accepted` or a terminal `rejected`
result before the first physical side effect. The same `dispatch_id` with the
same bytes returns the same claim/progress/result; different bytes are
corruption and authorize nothing.

All terminal phases are immutable and durable:

```text
succeeded | rejected | failed
```

A semantic retry therefore uses a fresh dispatch. It never deletes a failed
result and never reopens a terminal claim.

External effects cannot be atomically committed with a file replacement.
Before each effect, the Agent commits a closed recovery step with its expected
inputs and postcondition. After the effect it records independently verifiable
evidence. Recovery re-queries the physical subsystem using that identity; it
never assumes that a returned error means the effect did not happen.

`Start`, `Resume` and `Restore` can succeed only when the same atomic document
replacement can install a complete, reopenable runtime postcondition and exact
terminal result. Actions leaving Running can succeed only after route
retirement, runtime disposition, block frontend disposition and Relaxed
watermarks are proved. A response lost after commit is an ordinary exact
replay.

### 4. Per-Cat systemd ownership

Production runtime processes belong to a deterministic transient scope:

```text
cats-cat-<sha256(canonical cat_id)>.scope
```

under the Cats runtime slice. The full digest is used; the original Cat ID is
stored in the authority document and scope metadata rather than interpolated
into a unit name. The scope's systemd `InvocationID` and exact cgroup path are
part of runtime identity.

No VMM or blockd payload may execute before its stopped child has been attached
to the scope and membership has been verified. Subsequent signals use a fresh
`pid + start_ticks + scope + executable` comparison or a live pidfd held by the
current Agent. A mismatch is never signalled.

The Agent service keeps systemd's normal control-group containment. Surviving
Cat processes are owned by their per-Cat scopes; `KillMode=process` is not the
ownership mechanism and is not enabled to make restart tests pass.

FakeVmm and non-systemd developer platforms implement the same transaction and
identity state machines but are not production adoption evidence.

### 5. One transition-synchronized admission boundary

Every Cat has one in-memory admission cell reconstructed from durable truth:

```text
{ authority_revision, runtime_identity, settled_lineage,
  route_install, gate_state, active_guards }
```

The cell's mutex serializes:

- final Route Grant compare-and-guard;
- route-authority install, revoke and retirement transitions; and
- lifecycle quiesce or any runtime transition away from Running.

Signature parsing, authority-file replacement, fsync, systemd calls, protocol
I/O, transport cancellation and waiting happen outside the mutex. The
transition protocol is deliberately staged:

1. outside the mutex, durably recognize exact work and its expected authority
   revision; startup treats this work as a recovery prerequisite before it
   opens admission;
2. under the mutex, compare that revision and either close the volatile gate,
   or for `require_idle` return busy without changing the gate when the exact
   guard count is nonzero/unknown;
3. outside the mutex, durably CAS the prepared gate intent, then perform and
   verify external work; and
4. under the mutex, compare the same prepared identity and guard fence before
   publishing the new committed in-memory state.

If step 1 commits and the process dies, restart evaluates the work with a
closed recovery gate before serving traffic. If step 3 does not commit while
the process remains alive, the old durable authority may be reopened only
after a fresh outside-lock authority-document check and exact transition-token
compare. A stale completion may never reopen or replace a newer gate revision.

Grant admission performs all crypto and time work first, then under this one
mutex compares the grant to the complete current durable mirror and acquires
the activity guard in the same critical section. There is no read-then-acquire
gap. `unknown`, `recovering`, `retiring`, `revoked` and `quarantined` all deny a
new guard.

### 6. Startup is a union reconciliation

Before either NodeJob execution or Route Grant admission, the Agent:

1. validates authority-directory permissions, root/Cat document schemas,
   canonical encoding, revision integrity and Node identity;
2. closes every admission cell and enumerates the union of authority documents,
   Cats systemd scopes, processes in those scopes, runtime directories,
   control sockets and incomplete recovery work;
3. verifies Host boot, scope invocation, process tuples and role-specific
   protocol handshakes;
4. reduces every union member to `adopted`, `recovering`, `proven_absent` or
   `quarantined`; and
5. opens only exact Running route authorities whose complete proof and lineage
   match after all recovery work for that Cat is closed.

An empty query result is not proof of absence unless enumeration itself is
calibrated and all required namespaces were successfully inspected. Missing
heartbeat, missing PID, connection refusal, a stale socket file, a scope with
no authority document or a document with no scope is not inferred Cold.

Unknown schema, malformed documents, an unexpected scope/process, identity
mismatch or incomplete proof quarantines the Cat and cordons the Node for new
placement. The Agent does not PID-kill, delete a directory, discard a journal
or publish a Cold observation from such evidence. An operator or a
receipt-authorized recovery action must resolve it.

Warm has no live-process requirement, but its exact snapshot, memory backing,
disk journal and originating runtime lineage must be proven. Suspended requires
the paused VMM and storage members. Running requires the complete serving
runtime. In-flight actions resume only from their durable recovery steps.

### 7. Data-safety rules survive Agent replacement

The Cat authority document records the local and remote durability watermarks
for each attached disk as evidence, but it never advances them itself. `R <= L`
remains mandatory. When `R < L`, pending Relaxed packs and the
blockd/publisher able to drain them may be the only authoritative copy. C
recovery does not delete that journal, declare the disk released or kill an
unproven blockd.

Kernel NBD and vhost-user-blk have different member/resource evidence but the
same ownership state machine. Kernel NBD additionally records the exact NBD
device identity and allocation proof; vhost-user-blk records the exact socket,
queue/config identity and blockd process proof. Neither path may be adopted
from a reconstructed path name alone.

### 8. Failure outcomes are explicit

The protocol's crash table is normative. The key rule is:

- before durable acceptance: no side effect is authorized;
- after acceptance but before a verified effect: recovery resumes from the
  prepared step;
- after a possible effect but before evidence: recovery queries and proves the
  outcome, or quarantines;
- after runtime/result commit: exact replay returns the stored bytes; and
- at every route retirement point after durable prepare: restart admission
  remains closed until the same work is completed or explicitly compensated.

Authority-volume full, short write, I/O or sync failure, malformed document or
an unknown schema version is an authority failure, not a warning. The Agent
stops new jobs/admission, preserves processes and local data, exports a
condition and cordons the Node.

### 9. Breaking activation

There is no V1/V2 local-format migration, dual read, dual write, fallback
parser, mixed NodeJob endpoint or mixed Route Grant admission cohort.

Activation is a fleet safety operation:

1. stop public admission and old lifecycle dispatch;
2. durably revoke/drain each old route and prove zero active sessions, or
   externally fence its serving Node/runtime;
3. drain Relaxed journals, invalidate/release writers and move every old
   runtime to proven Cold, or externally fence and retain its residue;
4. prove no old job, route authority, scope or live runtime can act;
5. install the V2 binary and empty V2 authority directory, activate the V2
   endpoint and schema, and delete the old JSON/in-memory/PID-only paths; then
6. restore traffic only after exact A/B/C reciprocal checks pass.

Rollback uses the same full drain/fence boundary. It is not a request-level or
Node-level compatibility mode.

## Reciprocal contracts

| Upstream/downstream contract | C0 obligation |
| --- | --- |
| ADR-0035 Node acceptance | Persist one claim and accepted/rejected outcome before effects. |
| ADR-0035 terminal result | Persist succeeded/rejected/failed exact bytes immutably. |
| ADR-0035 settled lineage | Return the exact dispatch, claim, result and runtime identity committed locally. |
| ADR-0035 Start/Resume/Restore | Report success only with an adoptable runtime postcondition. |
| ADR-0035 leaving Running | Require exact route-retirement and writer/durability prerequisites before quiesce. |
| ADR-0039 local route truth | Store full `RuntimeRouteAuthorityV1` in the same Cat authority document and compare every field. |
| ADR-0039 admission | Compare durable mirror and acquire the guard atomically under one per-Cat mutex. |
| ADR-0039 revoke/idle | Persist prepared work, close restart admission, drain/check guards, then issue an exact receipt. |
| ADR-0030 heartbeat | Report only adopted facts; quarantine/absence is not Cold or authority. |

## Consequences

- Agent replacement can preserve a proven runtime without making its process
  inventory or route authority process-local.
- The design makes the existing per-Cat file boundary authoritative and adds
  explicit recovery state without introducing a second local database.
- Authority documents remain Host-bound. Losing the Host does not make them
  globally available; global fencing and Cold recovery remain necessary.
- Conservative quarantine may reduce availability, but it cannot silently
  turn uncertain local state into a second writer or serving route.
- The breaking cutover is operationally heavier once, but removes indefinite
  protocol and persistence compatibility debt.

## Alternatives considered

### Use SQLite for Node runtime ownership

Rejected. Runtime, NodeJob, route and recovery mutations are already serialized
per Cat and never require an atomic write spanning Cats. A relational store
would add schema migrations, WAL/checkpoint operation, a blocking worker and a
second production authority substrate without closing any cross-Cat invariant.
Structural validation and a startup duplicate-ID index provide the constraints
this boundary actually needs.

### Build an append-only log and snapshots in Cats

Rejected. Checksummed records, torn-tail handling, compaction, schema upgrade
and replay would be a new storage engine on the data-safety boundary. Complete
same-directory document replacement already gives the required per-Cat atomic
boundary without a log.

### Put Node runtime ownership in PostgreSQL

Rejected. PostgreSQL owns global lifecycle orchestration, but Host process,
scope and incomplete-effect evidence must be recoverable while the control
plane/network is unavailable. A remote commit also cannot prove that a local
authority-file/process mutation reached this Host. PostgreSQL consumes
immutable Node results; it does not replace local physical ownership proof.

### Use an embedded key/value store

Rejected. It adds another production storage dependency while leaving exact
one-of constraints, canonical validation and recovery indexes to application
code. The current boundary is one durable Cat transaction, not a cache lookup.

## Implementation decomposition

| Slice | Scope | Required exit gate |
| --- | --- | --- |
| C1 #279 | V2 authority documents, canonical codecs, atomic replacement, durability and corruption behavior | Filesystem/crash tests, exact schema manifest, no best-effort writes |
| C2 #186 | Per-Cat scopes, pre-exec attachment, member identity, startup union reconciliation | Real systemd Agent replacement on both block paths |
| C3 #90 | NodeJob V2 acceptance, recovery steps, immutable results and exact replay | A0 vectors plus crash injection at every effect boundary |
| C4 #276 | Route authority store, one admission cell, install/revoke/idle/drain | B0 vectors plus TOCTOU, restart and active-stream races |
| C5 #278 | Breaking activation and deletion of JSON/in-memory/V1 paths | Inventory proves no compatibility path or old live authority |
| C6 #275 | Bare-metal qualification and independent data-safety/concurrency review | Both block paths, Relaxed `R < L`, Agent/process/file fault matrix |

C1-C4 may prepare code in isolated branches, but C5 activates only the complete
A/B/C terminal boundary. C0 removes the legacy ADR and its source/test references;
the characterization matrix carries only the legacy behaviors that must remain
tested until C5 deletes their implementation. Git history retains the old
design without keeping it in the current architecture tree. The matrix must be
green before any production or qualification worker replacement.
