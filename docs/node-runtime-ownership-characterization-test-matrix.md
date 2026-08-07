# Node runtime ownership characterization and qualification matrix

- Status: C0 acceptance input
- Authority: [ADR-0040](decisions/0040-terminal-durable-runtime-ownership.md)
- Protocol: [Node runtime transaction V2](specs/node-runtime-transaction-v2.md)
- Issue: #273, parent #207

This matrix freezes observable safety behavior before C1-C6 replace the current
runtime supervisor. A row is not complete merely because a mock returns the
expected value: fault-boundary rows require a real process boundary and the
final qualification rows require a native Linux/systemd Host.

Every negative or empty discovery result must first be calibrated against a
known positive in the same namespace, credentials, mount namespace and unit
context. An uncalibrated empty scope/process/socket/authority query is `unknown`,
not absence.

## 1. Existing behavior to characterize before replacement

| ID | Current observable behavior | Characterization oracle | Terminal disposition |
| --- | --- | --- | --- |
| CH-01 | Per-Cat ledger uses atomic temp/fsync/rename/directory-fsync for an individual JSON file | Crash around each filesystem call; old or new complete JSON only | Reused as the V2 commit primitive; schema and fail-closed semantics break |
| CH-02 | `persist_cat`/`forget_cat` failures are logged and execution can still succeed | Inject unwritable/full ledger path and observe returned job result | Must fail closed; no success before authority/result commit |
| CH-03 | NodeJob journal is process memory | Execute terminal job, restart Agent, replay | Replaced; every terminal outcome survives |
| CH-04 | Failed jobs are intentionally replayed as execution | Fail after a physical boundary, retry same job ID | Deleted; V2 returns immutable failed result |
| CH-05 | Duplicate successful job in one process does not repeat its action | Count VMM/blockd/storage calls | Preserved with durable dispatch identity |
| CH-06 | Runtime lookup and activity-guard acquisition are separate | Race quiesce between lookup and acquire | Replaced by atomic cell compare-and-guard |
| CH-07 | Unsupervised residue causes teardown to fail closed | Remove in-memory inventory while leaving process/data | Preserved and strengthened to quarantine/cordon |
| CH-08 | Warm restore relies on local snapshot/memory/disk evidence | Restart with valid and damaged Warm artifacts | Preserved with complete transaction identity |
| CH-09 | Running/Suspended process identity checks PID/start ticks/executable and handshakes | Mutate one field at a time | Preserved and extended with scope/invocation/cgroup |
| CH-10 | Kernel-NBD and vhost-user paths expose different frontend evidence | Run the same Cat lifecycle on each path | Preserved under one ownership state machine |
| CH-11 | Relaxed pending packs survive ordinary Agent failure | Force `R < L`, terminate Agent, inspect journal/publisher | Must remain authoritative and never be cleanup residue |
| CH-12 | Control-plane disconnect does not grant local storage authority | Start/restart with control plane unavailable | Preserve local adopted runtime only; no lease resurrection |

These tests run against the pre-change RC and are retained while implementation
lands. Where the terminal behavior intentionally breaks, the test first proves
the old behavior and then changes its assertion in the deletion slice; it is
not silently removed.

## 2. Authority-file and schema gates (C1)

| ID | Scenario/fault | Required oracle |
| --- | --- | --- |
| FS-01 | First create on empty state directory | Exact owner/mode, canonical root/Cat schemas and digests; every created directory synced |
| FS-02 | Concurrent second Agent for the same authority directory | One lifetime lock wins; loser performs no job/admission/process mutation |
| FS-03 | Unknown lower/higher schema or protocol version | Global gate closed, Node cordoned, no automatic migration |
| FS-04 | Noncanonical/malformed document, duplicate global ID or partial lineage | Integrity/recovery fails closed; affected authority never loaded |
| FS-05 | Authority path symlink, wrong type/owner/mode or network filesystem | Refused through held directory descriptors before mutation |
| FS-06 | Disk full before acceptance commit | No claim/effect; retry can be recognized after repair |
| FS-07 | Disk full after accepted claim, before step prepare | Claim remains replayable; no unrecorded effect |
| FS-08 | Short write or file-sync failure during final runtime/result commit | No success response; physical state re-queried on recovery |
| FS-09 | Rename succeeds, directory sync fails | No success; restart accepts only a complete canonical old/new revision and rechecks physical state |
| FS-10 | Truncated final document or attacker-created temporary/symlink file | No best-effort decode; preserve processes/data, cordon/quarantine |
| FS-11 | Many Cat writers or slow filesystem | Per-Cat serialization and bounded backpressure; no async-executor blocking or unlocked fallback |
| FS-12 | Offline schema activation crash | Old complete or new complete authority tree only; activation manifest not advanced early |
| FS-13 | Exact lineage field null/mismatch mutation | Schema validation or startup quarantine; digest equality cannot mask it |
| FS-14 | `remote_watermark > local_watermark` or unknown at teardown | Invariant error/block; no writer release or journal deletion |
| FS-15 | Two mutations race on one Cat | One mutation token owns the next revision; no overlapping replacement or lost update |
| FS-16 | Settled tombstone deletion crashes before/after unlink or directory sync | Only the settled tombstone or absence remains; no authority is reconstructed from residue |

## 3. NodeJob and recovery gates (C3)

Run each relevant physical row with a crash immediately before the prepared
commit, after it, after the external effect, after observation, before the final
transaction, after that commit and after response write.

| ID | Scenario | Required oracle |
| --- | --- | --- |
| NJ-01 | Malformed/unauthenticated/non-V2 envelope | No recognized dispatch, claim, step or physical call |
| NJ-02 | Canonical recognized but stale runtime/command/prerequisite dispatch | One immutable rejected claim/result before effects |
| NJ-02a | Wrong-Node, URL/body mismatch or digest-header mismatch | Pre-recognition conflict; no claim/result/effect |
| NJ-03 | Exact duplicate while accepted/executing | Same claim/progress; one physical step identity |
| NJ-04 | Same dispatch ID with one request byte changed | Corruption response, no mutation/effect |
| NJ-05 | Succeeded response lost | Exact stored response returned; no effect repeats |
| NJ-06 | Rejected response lost | Exact stored response returned |
| NJ-07 | Failed response lost | Exact stored failed response returned; retry needs fresh dispatch |
| NJ-08 | Crash after acceptance, before effect | Recovery resumes the accepted step once |
| NJ-09 | External effect times out ambiguously | Query exact identity; no unconditional repeat |
| NJ-10 | Prepared process step with matching live process | Adopt/verify it; do not spawn a duplicate |
| NJ-11 | Prepared process step with mismatched live process | Quarantine; do not signal or replace by PID |
| NJ-12 | Runtime ready, before success transaction | Reverify and commit runtime/result atomically |
| NJ-13 | Success commit with one lineage field wrong | Entire replacement rejected; no partial result/runtime postcondition |
| NJ-14 | Superseded/late control-plane delivery | Store/return exact local outcome but do not infer current global authority |
| NJ-15 | Two dispatches race for incompatible Cat action | Exact revision/claim serialization; at most one effect owner |
| NJ-16 | Cancellation at each async boundary | Prepared work remains recoverable or exact failed disposition commits |

Action-specific matrix:

| ID | Boundary | Required oracle |
| --- | --- | --- |
| AC-01 | Start: after scope creation | Empty exact scope cleaned safely or same step resumed |
| AC-02 | Start: after VMM/blockd spawn | Union discovery adopts matching processes; no duplicate frontend |
| AC-03 | Start: one disk/member handshake fails | No Running result; complete source disposition and quarantine/block |
| AC-04 | Resume: VMM resumes but result absent | Re-query exact runtime; never issue a second unqualified resume |
| AC-05 | Restore: snapshot consumed/partially restored | Exact snapshot/runtime query determines resume vs quarantine |
| AC-06 | Suspend: route not durably retired | VMM pause is not started |
| AC-07 | Suspend: pause succeeds, commit fails | Admission remains closed; recover paused Running lineage to Suspended or fail exactly |
| AC-08 | Warm: snapshot durable, VMM exit pending | Resume exact teardown; retain blockd/journal until disposition proof |
| AC-09 | Cold: VMM exits with `R < L` | Publisher/journal retained and owned until remote drain/fence |
| AC-10 | Destroy: disposable Root and retained persistent disk | Exact per-disk disposition; no broad runtime-directory delete |
| AC-11 | FallbackCold after Resume/Restore failure | Requires source/fence/durability evidence; no inferred Cold |
| AC-12 | Any action final response loss | Exact terminal result only; no semantic action replay |

## 4. Scope, process and adoption gates (C2)

| ID | Scenario/fault | Required oracle |
| --- | --- | --- |
| PR-01 | Payload child before scope attachment | Payload executable has not run |
| PR-02 | Agent dies while child is held pre-exec | Child exits or is found as exact prepared work; payload did not escape |
| PR-03 | Agent dies immediately after releasing exec | Scope enumeration finds member even without an observation record |
| PR-04 | Scope unit name/metadata hash collision attempt | Full digest + stored Cat metadata reject aliasing |
| PR-05 | Same PID, different start ticks | No adoption and no signal |
| PR-06 | Same PID/start ticks, different executable inode/path | No adoption and no signal |
| PR-07 | Process moved to another cgroup/invocation | No adoption and no signal |
| PR-08 | Expected members plus one unexpected member | Quarantine complete Cat scope |
| PR-09 | Authority document without scope/process | Action-specific recovery or quarantine; not Cold |
| PR-10 | Scope/process without authority document | Quarantine/cordon; no PID kill or directory cleanup |
| PR-11 | Socket path reused by another process | Peer/protocol identity mismatch fails adoption |
| PR-12 | VMM/Guest boot ID mismatch | Quarantine; no Running/Suspended report |
| PR-13 | blockd disk/volume/attachment/epoch mismatch | Quarantine and preserve journal; no grant resurrection |
| PR-14 | Warm exact disk/snapshot evidence, no live scope | Warm adoption succeeds across Agent replacement and allowed Host reboot semantics |
| PR-15 | Warm missing/corrupt one artifact | No adoption, no inferred Cold, residue retained |
| PR-16 | Agent service restart under normal KillMode | Per-Cat scope processes survive; unrelated unit children do not escape containment |
| PR-17 | Signal after adopted member exited and PID reused | Fresh tuple/pidfd prevents signalling replacement process |
| PR-18 | Control plane offline during adoption | Exact local adoption can finish; no global placement/write authority fabricated |

Startup union calibration:

| ID | Enumerator failure | Required oracle |
| --- | --- | --- |
| UN-01 | systemd D-Bus denied/unavailable | Namespace unknown; gates closed, Node cordoned |
| UN-02 | `/proc` permission/mount-namespace mismatch | Known-positive probe fails; no absence conclusion |
| UN-03 | Runtime-directory scan permission error | Affected namespace unknown; no cleanup/admission |
| UN-04 | Socket probe returns error other than exact proven absence | Treat as possibly serving |
| UN-05 | Block frontend enumeration returns empty | Known test frontend must be found before empty is believed |
| UN-06 | All calibrated enumerators succeed and no union member exists | Local absence may be proven for the prepared step only |

## 5. Route authority and admission gates (C4)

| ID | Scenario/race | Required oracle |
| --- | --- | --- |
| RT-01 | Positive Route Grant V2 vector + exact active local authority | Guard acquired and exact proxy target returned |
| RT-02 | Mutate each claim/lineage/runtime/install field independently | Admission denied; no guard |
| RT-03 | Crypto succeeds while lifecycle closes gate before mutex | Final compare denies; no TOCTOU |
| RT-04 | Admission wins mutex immediately before retirement | Guard is counted in retirement fence and drained/busy |
| RT-05 | Retirement wins mutex immediately before admission | New guard denied |
| RT-06 | Authority-file prepare fails after volatile close | Old revision may reopen only after exact document recheck/token compare |
| RT-07 | Crash after durable retirement prepare | Restart gate closed before proxy listener serves |
| RT-08 | Crash while cancelling active stream | Restart completes exact work or remains blocked; no receipt early |
| RT-09 | Drain timeout | Running source and route-retirement work retained blocked; lifecycle not quiesced |
| RT-10 | `require_idle` sees nonzero guard | Immutable busy proof; no cancel/revoke/authority mutation |
| RT-11 | `require_idle` zero then concurrent admission | Closed mutex gate prevents new guard; exact receipt can commit |
| RT-12 | Stale completion after fresh route install | Revision/token CAS denies; old epoch never reopens |
| RT-13 | Active route authority committed, Agent crashes before memory publish | Startup complete recheck can open exact authority |
| RT-14 | Local route/runtime mismatch on restart | Quarantine/closed; Cat ID or epoch cannot repair it |
| RT-15 | Clock unhealthy | No new guards; existing stream is not silently killed |
| RT-16 | Grant expires after an active stream starts | Stream retains guard until normal close or explicit exact retirement |
| RT-17 | Policy `require_idle` receipt races manual command adoption/compensation | One exact CAS owner; no in-place epoch revival |
| RT-18 | No disk/network/fsync/await while mutex held | Instrumented lock-duration/I/O assertion remains green under faults |

## 6. Relaxed durability and block frontend gates

The same action/restart suite runs once with kernel NBD and once with
vhost-user-blk. At minimum:

| ID | Scenario | Required oracle |
| --- | --- | --- |
| ST-01 | Strict volume, successful FLUSH, permanent Agent/Host process loss | Durable Root remains readable; local ledger is not durability authority |
| ST-02 | Relaxed `R = L`, Agent replacement | Exact runtime/frontend adoption or explicit safe fallback |
| ST-03 | Relaxed `R < L`, Agent replacement, publisher alive | Publisher adopted and remote watermark progresses monotonically |
| ST-04 | Relaxed `R < L`, publisher identity unprovable | Journal preserved, writer release blocked, Node cordoned/quarantined |
| ST-05 | Kernel-NBD device number reused | Major/minor + sysfs/allocation mismatch rejects adoption |
| ST-06 | vhost-user socket path reused | Socket inode/protocol/device mismatch rejects adoption |
| ST-07 | Blockd dies while VMM survives | No successful Running adoption; exact containment/fallback proof required |
| ST-08 | VMM dies while blockd holds pending packs | Journal/publisher retained; no blind full-scope kill |
| ST-09 | Old fencing epoch process returns | Metadata CAS and local identity both fail closed |
| ST-10 | Local authority documents permanently lost | External fence + proven Cold rebuild only; no scan-to-authority reconstruction |

## 7. Breaking activation and deletion gates (C5)

| ID | Gate | Required evidence |
| --- | --- | --- |
| CU-01 | Public admission stopped | Gateway/Node request probes plus listener/config inventory |
| CU-02 | Old active sessions retired | Per-epoch zero-guard receipts or external serving fences |
| CU-03 | Old writers/runtimes safe | Volume invalidation/release, `R/L`, scope/process and fence receipts |
| CU-04 | Empty V2 authority activation | Root/schema manifest; no imported V1 document |
| CU-05 | Old ledger path deleted | Source/symbol/filesystem tests fail if the legacy `runtime-ledger` reader/writer returns |
| CU-06 | Old job journal/endpoint deleted | V1 requests rejected before recognition; source inventory zero |
| CU-07 | Old Route Grant path deleted | No signer/parser/verifier/admission fallback or mixed cohort |
| CU-08 | PID/path-only teardown deleted | Negative identity tests cannot reach a signal/delete call |
| CU-09 | Rollback rehearsal | Requires full drain/fence manifest; no per-request compatibility switch |
| CU-10 | Traffic reopen | Exact A0/B0/C0 lineage/route/runtime vectors green on installed build |

## 8. Native qualification and evidence (C6)

The merge gate is:

```text
./scripts/quality.sh fast
./scripts/quality.sh full
./scripts/quality.sh linux
```

followed by exact-head native Linux/systemd qualification on the dedicated test
Host. GitHub-hosted CI availability or account billing is not a substitute for
the native gate and is not itself a technical blocker.

Native runs must record immutable source/tree/bundle/manifest digests, Host
image and boot identity, authority schema digest, systemd version, kernel,
Cloud Hypervisor/blockd digests, block path, PostgreSQL/S3 endpoints by opaque
environment identity, command transcript and exit code. They must not retain
AWS credentials or a reusable HOME.

Required end-to-end sequences for both block paths:

1. Start -> live traffic -> Agent replacement -> exact adoption -> traffic
   continues without Guest restart.
2. Running -> Suspend -> Agent replacement at every boundary -> Resume.
3. Running -> Warm -> Agent replacement/allowed Host event -> Restore.
4. Running -> Cold with Strict and Relaxed volumes, including `R < L`.
5. Active HTTP and WebSocket -> cancel-and-drain -> lifecycle quiesce.
6. Auto-suspend `require_idle` busy/zero and manual-command race.
7. Authority-file write/sync/corruption fault while VMM/blockd remain live ->
   fail-closed quarantine, repair, exact recovery.
8. Unexpected scope/process/PID reuse -> no signal, deletion, admission or Cold
   report.
9. Response loss for each terminal result -> byte-identical replay.
10. Old endpoint/file/symbol/process inventory -> zero after terminal cutover.

Acceptance requires an independent review prioritizing correctness/data loss,
process/concurrency safety, error/cancellation behavior, A/B/C contract
closure, tests and only then maintainability. A test run is not acceptance if
the exact source digest, fault injection point or correctness oracle is absent.
