# Lifecycle authority characterization and qualification matrix

- Status: Normative A0 qualification plan
- Authority: [ADR-0035](decisions/0035-durable-lifecycle-command-authority.md)
- Protocol: [Lifecycle command and NodeJob V2](specs/lifecycle-command-v2.md)
- Delivery slices: A1-A9, issues #224-#232

## 1. How to use this matrix

Before replacing a V1 boundary, add a characterization test that records what
the current implementation actually does at that boundary. A characterization
test may document an unsafe V1 outcome; such a result is evidence for the
rewrite, not the V2 oracle. The corresponding V2 test must assert the
ADR-0035 invariant and must fail against an implementation that reintroduces
the V1 ambiguity.

Empty results are not proof. Every migration inventory, recovery query,
deletion check and failover probe must first demonstrate a known positive in
the same environment and through the same path. PostgreSQL concurrency tests
use real PostgreSQL and at least two independent connections/controller
instances. An in-memory Store or mock MetadataStore may cover pure logic but
does not qualify transaction, lock, receipt or crash-replay behavior.

Every result records the commit, schema and protocol versions, OS, block path,
database/object-store products, process topology, injected crash boundary,
sample count and correctness oracle. Existing experiment measurements retain
their original environment and sample count; they are not production SLAs.

Gate notation:

- **fast**: `./scripts/quality.sh fast` plus focused tests.
- **full**: `./scripts/quality.sh full` and migration/contract checks.
- **linux**: `./scripts/quality.sh linux` for Node, block frontend, process and
  systemd-sensitive paths.
- **real**: RC infrastructure with real PostgreSQL/MetadataStore adapters,
  Node Agent, Cloud Hypervisor and the selected block path.

## 2. Authority and schema

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| AUT-01 | Concurrently insert two current commands for one Cat. | The relational unique constraint commits exactly one; the loser cannot dispatch. | A1 / full |
| AUT-02 | Reuse a command, dispatch, effect, grant or result ID with different immutable fields or bytes. | Database/receiver reports a typed conflict; no row is overwritten and no effect runs. | A1, A3, A7 / full, linux |
| AUT-03 | Insert a result naming the wrong command, dispatch, Node claim or request digest. | Foreign keys/checks or reducer validation fail closed; the result cannot settle authority. | A1, A6 / full |
| AUT-04 | Put commands in every nonterminal phase, including `blocked`, then restart all controllers. | The indexed work query returns every item exactly once as claimable/reviewable work; no JSON decode is required. | A1, A5 / full |
| AUT-05 | Backfill the same stable V1 snapshot twice. | IDs/provenance are stable and the second run is a no-op. | A1, A8 / full |
| AUT-06 | Backfill transitional, missing-placement or inventory/volume-contradictory rows. | They become explicit ambiguous repair rows and never fabricated stable commands/runtimes. | A1, A8 / full, real |
| AUT-07 | Submit a heartbeat containing a complete, valid runtime inventory. | Only normalized observation rows and Node liveness change; no lifecycle-authority column is written. | A1, A6 / full |
| AUT-08 | Insert `deleted` as a source/runtime state, `absent` as a target, a non-Destroy target `deleted`, or a Destroy with another target. | Typed schema/check constraints reject every invalid domain combination; Destroy success leaves no runtime row and records the resource tombstone. | A1, A6 / full |

## 3. Pure lifecycle planner

The planner table test is generated over every desired stable state, every
settled state, every command kind/phase and the presence/absence of exact
runtime provenance. It has no wildcard success branch.

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| PLN-01 | Cold/Creating/retry-authorized Failed -> Running; Suspended -> Running; Warm -> Running. | Propose Start, Resume and Restore respectively; a projected `Starting` value is never an input discriminator. | A2 / fast |
| PLN-02 | Running -> Suspended; Suspended -> Warm; Running/Suspended/Warm -> Cold. | Propose the exact Suspend, Warm or Cold leg. | A2 / fast |
| PLN-03 | Warm -> Suspended; Cold -> Suspended; Running -> Warm; Cold -> Warm. | Produce the exact Restore/Suspend, Start/Suspend, Suspend/Warm or Start/Suspend/Warm command chain, one leg at a time. | A2 / fast |
| PLN-04 | Stable state already equals desired state with no active command. | Return no-op without completing an unrelated Operation. | A2, A6 / fast |
| PLN-05 | Any non-deleted state -> Deleted, or current Destroy plus any newer wake/start intent. | Destroy is the only proposal and cannot be superseded by non-destroy work. | A2, A4 / fast, full |
| PLN-06 | Resume/Restore source Node, runtime, claim or snapshot identity is absent/mismatched. | Wait/fail closed or propose explicit FallbackCold only after a safe retention/fence proof. | A2 / fast |
| PLN-07 | Lost/Fenced Node conditions and retained Relaxed volume with `L > R`. | Do not infer Cold/absence or release authority; produce wait/fence/operator-required decision. | A2, A7 / fast, full |
| PLN-08 | Feed every reachable typed snapshot and deliberate impossible combinations. | Every reachable combination has an explicit decision; impossible combinations return invariant error. | A2 / fast |

## 4. Acceptance, Operation and supersession

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| ACC-01 | Commit a lifecycle request, lose its HTTP response, then replay the same idempotency key with the now-stale original `If-Match`. | Return the original Operation and create no generation/command. | A4 / full |
| ACC-02 | Race identical and different idempotency keys against one Cat from two PostgreSQL sessions. | Identical requests converge to one Operation; conflicting accepted intents serialize into exact generations/supersession. | A4 / full |
| ACC-03 | Reuse an idempotency key with a different route, action or body digest. | Reject without changing Cat, command or Operation rows. | A4 / full |
| ACC-04 | Crash after each write that would allocate generation, Operation, command or wakeup. | The transaction leaves all authority facts committed together or none; wakeup is after-commit and recoverable. | A4 / full |
| ACC-05 | Supersede a command before dispatch. | Old command becomes `cancelled_before_dispatch`/superseded evidence and successor is the sole current authority. | A4 / full |
| ACC-06 | Supersede after Node acceptance, then deliver the old success late. | Success is stored but cannot settle state, Operation, route or grant; successor waits for terminal/fence/invalidation. | A4, A6 / full, linux |
| ACC-07 | Run Stop -> Start -> Stop with delayed first Stop result. | Exact command/dispatch/claim identity prevents ABA settlement. | A4, A6 / full |
| ACC-08 | Complete a newer generation while an older Operation remains active. | No `<= generation` or desired/observed convergence shortcut completes the older Operation; it gets its explicit outcome. | A4, A6 / full |
| ACC-09 | Race Destroy with Start, wake, expiry and policy transitions. | Accepted Destroy remains irreversible current authority; retained disks can keep it blocked without resurrection. | A4 / full |

## 5. Dispatch and NodeJob V2

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| DSP-01 | Kill the controller before and after payload commit, executor claim, send and response receipt. | No send precedes durable bytes; recovery reuses the same dispatch and exact body after every boundary. | A5 / full |
| DSP-02 | Let two controller replicas claim/deliver one dispatch and expire one executor claim. | Node executes at most once; the next executor transfers delivery only, not authority. | A5, A3 / full, linux |
| DSP-03 | Retry transport after persisting semantically equivalent but differently serialized JSON. | Dispatcher sends the originally persisted byte sequence and digest, never reserializes it. | A5 / full |
| DSP-04 | Send same dispatch ID/body twice and same ID/different digest once. | Exact replay returns the same claim/result; different digest is rejected before side effects. | A3 / linux |
| DSP-05 | Crash/restart Node before acceptance fsync, after fsync, during physical work and after terminal-result fsync but before response. | Work starts only after durable acceptance; restart adopts/query-resumes the same claim; terminal replay is immutable. | A3, C / linux, real |
| DSP-06 | Exercise every validation rejection and action failure, then restart the Agent. | Rejected and Failed results are durable and replayed; semantic retry uses a new dispatch. | A3 / linux |
| DSP-07 | Deliver stale expected-runtime, target-Node, command-authority or volume-grant credentials. | Reject and persist evidence before volume, process, cgroup, tap or snapshot effects. | A3, A7 / linux, real |
| DSP-08 | Start/Resume/Restore returns after process creation but before runtime-ledger adoption. | No Succeeded result exists until C's ledger durably proves the exact runtime lineage. | A3, C / linux, real |
| DSP-09 | Receive a recognized stale-authority/runtime/grant request, return 409, restart the Agent, then GET; separately send malformed and existing-ID/different-digest requests. | Recognized 409 returns and GET replays the identical durable Rejected claim/result. Pre-recognition requests create no claim/result and GET is 404 after a known-positive control proves the query path. | A3, A7 / linux, real |

## 6. MetadataStore effects and volume grants

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| VOL-01 | Apply an epoch-changing effect, lose the response, then query/replay the same effect ID. | Return the same atomic receipt and epoch; the mutation occurs once. | A7, D / full, real |
| VOL-02 | Reuse an effect ID with a different expected predecessor or request digest. | MetadataStore conflicts without mutation. | A7, D / full |
| VOL-03 | Attempt to expose current unconditional `revoke_lease(volume)` through V2 replay. | Contract/adapter tests reject the capability; no blind replay path exists. | A7, D / full |
| VOL-04 | Prepare a grant, delay dispatch, then supersede/fence and invalidate the grant before Node acquisition. | Delayed acquisition receives the immutable rejection; blockd/VMM do not start. | A7, A3 / linux, real |
| VOL-05 | Replay acquisition of the same valid grant, then try another grant against the old predecessor. | Same grant returns the same attachment/epoch; competing grant is conditionally rejected. | A7, D / full, real |
| VOL-06 | Replace a writer, then deliver a delayed conditional revoke/release for its predecessor. | Replacement writer and epoch remain valid; receipt identifies stale predecessor. | A7, D / full, real |
| VOL-07 | Pause an external MetadataStore call while another transaction needs the same Cat/volume. | PostgreSQL row/advisory locks are not held during external I/O. | A7 / full |
| VOL-08 | Leave an effect `applying` with an unreachable/non-queryable adapter outcome. | Command becomes visible `blocked`/`indeterminate`; it neither dispatches nor fabricates a receipt. | A7, A5 / full |

## 7. Reducer, fallback and durability

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| RED-01 | Apply the exact success twice. | First transaction settles all authorized facts; duplicate is a no-op. | A6 / full |
| RED-02 | Deliver wrong command/claim/digest/action/authority revision or generation N after N+1 is current. | Persist stale/conflicting evidence only; no state, Operation, placement, route or grant mutation. | A6 / full |
| RED-03 | Kill reducer after result insertion and after each transactional mutation boundary. | Recovery applies one atomic settlement; route side effects occur only from a committed exact outbox intent. | A6 / full |
| RED-04 | Fail Start before acquisition and at an indeterminate process/grant boundary. | Proven clean failure retains Cold and may use a new dispatch; ambiguity blocks until query/fence. | A6 / full, linux |
| RED-05 | Fail Suspend while source is proven Running, and with lost runtime integrity. | Preserve/retry exact Running source in the first case; create explicit FallbackCold in the second. | A6 / linux, real |
| RED-06 | Fail Warm drain/snapshot/exit with a preserved Suspended runtime and local journals. | Preserve Suspended and unique local data; do not cleanup or mark Cold. | A6 / linux, real |
| RED-07 | Fail Resume/Restore or prove their exact host-bound source unusable. | Create durable FallbackCold bound to the failed evidence; no direct state assignment or generic cleanup. | A6 / linux, real |
| RED-08 | Inject `L > R`, mismatched roots, pending-pack upload failure and successful final fsync/drain. | Never report Cold/release/delete while unique local data is ahead; success requires the recorded remote watermark/root oracle. | A6, A7 / linux, real |
| RED-09 | Fail Cold at quiesce, drain, teardown and ledger-write boundaries. | Source runtime/blockd/grant/journal remains owned or explicitly indeterminate; retry is safe. | A6 / linux, real |
| RED-10 | Destroy a Cat with disposable RootDisk tails, retained PersistentDisks and an unknown extra volume. | Only named RootDisk tails may be discarded; PersistentDisks drain/release; unknown volume blocks Destroy. | A6, A7 / linux, real |

## 8. Heartbeat and runtime ownership

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| OBS-01 | Report a state that contradicts settled runtime/current command. | Observation is stored and discrepancy exposed; heartbeat changes no authority or route. | A6, C / full |
| OBS-02 | Omit a Cat from one or many heartbeats. | Missing inventory is suspicion only; it cannot prove absence, Cold or writer release. | A6, C / full |
| OBS-03 | Register with incomplete and then complete same-generation inventory. | ADR-0027 Lost recovery occurs only from the complete valid claim through the recovery controller, never the heartbeat handler. | C, A6 / full, real |
| OBS-04 | Report an unknown or differently placed runtime. | Normalized observations expose it as orphan; no synthetic command/result is created. | C / full |
| OBS-05 | Restart Agent with accepted/running/terminal jobs and adopted runtimes. | Durable Node ledgers recover exact claims/results; control obtains them by query/reconciliation. | A3, C / linux, real |
| OBS-06 | Deliver an old heartbeat sequence or old agent instance after a new report. | It is rejected/retained as stale observation and cannot regress any projection. | A1, C / full |

## 9. PostgreSQL concurrency and lock order

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| CON-01 | Two controller processes plan, dispatch and reduce the same Cat. | Unique/CAS constraints select one transition; all losing workers reload rather than applying partial writes. | A4-A6 / full |
| CON-02 | Race request acceptance with exact result reduction. | Both follow Cat -> command order; final intent/result lineage is serializable and no Operation is miscompleted. | A4, A6 / full |
| CON-03 | Race fleet placement with Start acceptance/dispatch. | Placement-family lock order yields one exact reservation/target; lifecycle transaction never nests placement backwards. | A4, A5 / full |
| CON-04 | Race Node fencing with result reduction and volume-grant acquisition. | Node/Cat/grant facts converge under the documented family order; stale work cannot reacquire. | A6, A7 / full, real |
| CON-05 | Force a PostgreSQL deadlock or serialization abort. | Entire transaction retries from a fresh authoritative snapshot; no final-write-only retry. | A4-A7 / full |
| CON-06 | Kill leader/controller and change RDS Proxy backend sessions while work is in every phase. | Level-triggered recovery resumes from rows; no per-Cat session lock or pinned session carries correctness. | A5 / full, real |

## 10. Migration, cutover and deletion

| ID | Setup and injection | Required V2 assertion | Owner / gate |
| --- | --- | --- | --- |
| MIG-01 | Run an old binary throughout Expand while V2-capable Agents serve separate endpoints. | V1 behavior is unchanged and cannot accidentally decode V2; no authority has two writers. | A8 / full, linux |
| MIG-02 | Run Shadow against representative production-snapshot-shaped rows. | Shadow can record labelled comparisons but lacks a path/credential to write, dispatch, route or call MetadataStore. | A8 / full |
| MIG-03 | Attempt Freeze with a known-positive V1 in-flight/transitional job, then drain/repair it. | Database gate rejects new V1 lifecycle mutations; activation first fails, then succeeds only at zero verified residue. | A8 / full, real |
| MIG-04 | Start old binaries after the authority version changes to V2. | They fail closed before lifecycle writes or V1 dispatch. | A8 / full |
| MIG-05 | Kill the activating controller before/after version change and recovery scan. | Exactly one authority version is active; API/policy unfreezes only after all current work is accounted for. | A8 / full, real |
| MIG-06 | After a V2 dispatch, deploy the previous V2-compatible binary and separately attempt V1 rollback. | Compatible binary continues the same authority; V1 writer remains database-blocked. | A8 / full, real |
| MIG-07 | Seed one known-positive legacy JSON marker, V1 lifecycle journal/job, shadow row, direct heartbeat writer and legacy-controller symbol before Contract inventory. | Contract refuses deletion while each is detectable; after removal, source/schema/binary scans and operational queries prove none remain. | A8, A9 / full, linux |
| MIG-08 | Rehearse stable backfill, ambiguous repair, Freeze, Activate and V2-compatible rollback twice from the same snapshot. | Results and row counts are deterministic; no temporary dual path survives Contract. | A8, A9 / full, real |

## 11. Real-system qualification and completion

The `real` suite covers kernel NBD and vhost-user-blk on Linux with real Cloud
Hypervisor, PostgreSQL, object store and MetadataStore adapters. It exercises
Agent restart/adoption, controller loss at every durable boundary, network
response loss, fencing and Relaxed journal recovery. A PostgreSQL service
failover may be included when the RC infrastructure provides it, but its exact
topology and outage are reported; it is not evidence of an unimplemented
Multi-AZ availability guarantee.

A1-A8 are not complete merely because unit tests pass. Each child issue must
name the rows it implements, preserve the failing-before evidence where
applicable and attach exact gate output. A9 is performed by a reviewer who did
not author the implementation. The reviewer confirms:

1. every matrix row has a test/evidence link or an explicit out-of-scope
   disposition accepted in the owning issue;
2. all safety-critical rows pass with known-positive probe controls;
3. `fast`, `full`, applicable `linux`, and required `real` gates pass at the
   reviewed RC commit;
4. no correctness claim exceeds the recorded environment or sample; and
5. Contract deletion has left one lifecycle authority and one implementation
   path.

Multi-AZ provisioning, cross-AZ placement and availability qualification are
deliberately deferred. The tests retain injectable PostgreSQL/Node/adapter
boundaries so that a later Multi-AZ program can reuse the authority contract
without changing it.
