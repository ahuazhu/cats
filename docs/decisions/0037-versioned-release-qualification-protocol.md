# ADR-0037: Versioned release-qualification protocol and evidence authority

- Status: Accepted
- Date: 2026-08-06
- Relates to: ADR-0001 (greenfield baseline), ADR-0002 (lifecycle),
  ADR-0003 (Direct-S3 durability), ADR-0005 (provider-neutral boundaries),
  ADR-0012 (AWS resources and deployments), ADR-0015 (block frontend),
  ADR-0018 (Workspace ownership), ADR-0022 (dual durability watermarks),
  ADR-0023 (systemd Guest); issues #204, #210 and #234

## Context

A release gate is itself a correctness and security boundary. A scenario runner
that schedules work, injects a fault, observes the result and declares its own
success can manufacture a green verdict from its private state. An empty log or
missing metric can also be mistaken for proof of absence. Reusing evidence after
the candidate, environment, catalog or controller changes makes the verdict
describe a different execution than the artifact being released.

The reviewed qualification inventory on the historical
`feat/release-qualification` branch contains useful case identities and oracles,
but that branch also contains a large workflow controller and infrastructure
implementation. Neither its controller nor its mutable in-memory state is an
authority for Architecture V2. The inventory is migration input only, with its
exact Git object and SHA-256 retained so the selection can be reproduced.

Architecture V2 needs a focused contract before any new controller, AWS cell or
scenario implementation is built. The contract must make absence, partial
execution, actor separation, recovery ordering and coverage denominators
unambiguous.

## Decision

### Protocol files are the boundary

The normative protocol is
[`docs/specs/qualification-protocol-v1.md`](../specs/qualification-protocol-v1.md).
The machine-readable authority is split by current domain boundaries:

- `qualification/protocol/catalog/case-catalog-v1.json` freezes case identity,
  phase, environment profile, accountable oracle owner, independent oracle and
  required evidence kinds;
- a content-bound `TrialPlan` freezes the ordered set of scheduled case/trial
  identities and selected execution environments before execution;
- an Ed25519-authenticated `ActorAuthorityManifest` binds the five actor
  sessions and exact capability sets to a run without giving the Verifier a
  signing key;
- an Ed25519-authenticated append-receipt bundle binds every event digest,
  actor session, ordered ledger root and terminal checkpoint;
- the `cats-qualification-protocol` crate contains strict data types and pure
  validators for a catalog, trial record, phase coverage ledger and final
  two-phase release composition; and
- positive and negative JSON fixtures calibrate the validator against known
  results.

The crate performs no network or infrastructure mutation and owns no workflow
state. It is not a scheduler, scenario harness, durable ledger, fault injector,
observer or release controller.

Any incompatible change uses a new schema/protocol version and an ADR. Unknown
fields fail parsing so a producer cannot smuggle unverified semantics through a
V1 consumer.

### The catalog migration is reproducible, but the old branch is not authority

The source inventory is exactly:

```text
feat/release-qualification:tests/qualification/contracts/registry.json
commit: 700a0356737bee9644a120615d9481c72b407997
sha256: d8eb9218a8daf97e71e0d9efda43d7d8f1662420e826fced44d6ff7ffd610b43
contracts: 114
```

Every migrated entry was retained as a stable ID and reviewed against the
Architecture V2 baseline recorded in the new catalog. Vague source labels were
replaced with repository documents, accepted ADRs, experiment evidence or the
F epic issue. The old default owner and evidence settings were not copied:
each new entry explicitly names an architecture-domain oracle owner, its
independent oracle and its evidence kinds.

The phase sets are disjoint at the catalog level:

| Catalog phase | Cases | Release-required | Meaning |
|---|---:|---:|---|
| `functional` | 104 | yes | P0/P1 cases not assigned to AWS-P |
| `aws_performance` | 9 | yes | P0/P1 cases that require the AWS-P phase |
| `cost_observation` | 1 | no | `PERF-COST-001`, a P2 observation |

The nine AWS-P cases are `CLEAN-002`, `REPORT-PERF-001`, `PERF-ENV-001`,
`PERF-ENV-002`, `PERF-STRICT-001`, `PERF-RELAX-001`, `PERF-LIFE-001`,
`PERF-SCALE-001` and `PERF-SOAK-001`. The functional selection is therefore
104, while all release-required P0/P1 coverage is 104 + 9 = 113. P2 cost data
must never enter a release-required denominator.

### Five authenticated identities have non-overlapping authority

Every trial binds exactly one Controller, Fault Actor, Recovery Actor, Observer
and Verifier identity. Each has a distinct principal, credential fingerprint
and session. The V1 action and event sets are closed: every allowed action has
a corresponding event, and every event has exactly one authorized role.

Those identities are not fields that the trial producer may invent. The run
binds the exact bytes of an actor-authority manifest signed by a configured
Ed25519 authority key. The Verifier receives only the pinned public key. Every
event must also resolve to an append receipt in a checkpoint signed by a
separate configured ledger key. A receipt binds event sequence/ID/digest and
the exact actor identity, session and credential fingerprint from the
authenticated manifest. Five syntactically distinct strings and locally
recomputed SHA-256 values therefore cannot manufacture authority or durability.

- the Controller binds the run and schedules the trial;
- the Fault Actor starts and ends the injected fault, but cannot observe or
  seal the oracle;
- the Recovery Actor durably arms recovery before mutation and records recovery
  execution and cleanup;
- the Observer captures calibration and product observations and is the only
  producer/sealer of raw evidence; and
- the Verifier independently verifies each sealed evidence object and is the
  only issuer of a terminal record.

Possessing one role never implies another role's capability. In particular,
the component under test, controller and fault actor cannot create an
independent-oracle result.

### Mutation is downstream of durable recovery intent

All events carry immutable `run_id`, `window_id` and `trial_id` bindings and a
strictly increasing sequence allocated by an external durable append ledger.
Wall-clock timestamps are canonical UTC and monotonic but are not the
cross-actor ordering authority.

The raw append-receipt document is bound into the TrialRecord by SHA-256. Its
signed checkpoint covers every and only the ordered event receipts, the
recomputed ledger root, previous-checkpoint digest, range and event count.

For a mutating trial, the ledger order must prove:

```text
RecoveryIntentArmed < MutationStarted
MutationStarted < FaultApplicationEnded
MutationStarted < RecoveryExecutionRecorded
max(FaultApplicationEnded, RecoveryExecutionRecorded) < CleanupRecorded
CleanupRecorded < evidence seal/verify < TerminalIssued
```

`RecoveryIntentArmed` means the recovery plan and authority are durable before
the fault actor receives mutation authority. A controller crash cannot erase
the obligation. Recovery and cleanup events bind immutable result records; the
event names record execution and outcome rather than asserting success. An
unsuccessful cleanup remains visible in evidence and produces an appropriate
non-PASS terminal.

### Candidate, selected environment and protocol binding are exact

Every trial and coverage ledger binds the full lowercase candidate Git SHA,
H0 source-chain verdict digest, artifact-manifest digest, protocol version,
exact catalog file digest, exact ordered TrialPlan digest, full controller Git
SHA and exact authenticated actor-authority manifest digest.

Environment is deliberately not a run-wide field. Each PlannedTrial freezes an
`ExecutionEnvironment` (selected profile, isolated environment ID, immutable
manifest digest and `environment_is_production=false`), and its TrialRecord
must match it exactly. Functional selection is deterministic: choose `aws_f`
when the case declares it; otherwise the case must declare exactly one of
`ci`/`linux` and that profile is selected. AWS performance and cost cases select
`aws_p`. A producer cannot qualify an AWS-F/AWS-P case on a weaker profile.

The G0 cell may live in the production AWS account, but its
`cats-qualification-v2` resource lineage is an isolated qualification
environment and remains explicitly non-production. The account boundary never
changes `environment_is_production` to true. AWS-F and AWS-P may use distinct
immutable execution manifests derived from that cell handoff.

Evidence from a different binding cannot be merged. Any candidate,
source-chain verdict, artifact, selected environment manifest, catalog,
TrialPlan, authority manifest, protocol or controller change creates a new
phase run and resets authoritative coverage for that binding.

### Evidence is immutable, bounded and independently verified

Raw evidence is content-addressed by SHA-256, has a declared media type and
bounded size, binds the producing Observer identity and exact event interval,
and records a redaction-policy digest. A secret scan must pass before evidence
is eligible. Failed or absent scans, missing objects, empty objects, digest
mismatch, unlinked seals, unlinked verification, or invalid order make the
trial invalid; secrets are never qualification evidence.

The evidence lifecycle is exact:

```text
capture interval < Observer EvidenceSealed(id, digest)
                 < Verifier EvidenceVerified(id, digest)
                 < Verifier TerminalIssued(id, digest)
```

The terminal record accounts for every sealed evidence object exactly once.
The metadata validator checks identities and references; the operational
Verifier must also fetch bytes from immutable storage and recompute their
digests.

Event, observation and terminal receipt digests are not caller assertions. V1
defines compact canonical JSON preimages that exclude the digest field itself,
and the validator recomputes each SHA-256. Capture and terminal events bind the
exact recomputed observation/terminal IDs and digests.

### Absence and terminal outcomes fail closed

V1 terminal outcomes are `pass`, `fail`, `blocked`, `empty`, `incomplete`,
`unobserved`, `invalid`, `cancelled` and `timed_out`. Only `pass` contributes to
coverage.

An observed empty result is never silently promoted to PASS. It may PASS only
when the contract expects absence and the event ledger includes both a
known-positive probe and its calibration record. Each must bind a distinct,
typed EvidenceObject that is subsequently sealed by the Observer, verified by
the Verifier and included in the terminal. Opaque event subjects alone are not
calibration proof. Unexpected calibrated absence is `empty`. Missing
observation is `unobserved`; partial observation is `incomplete`. `blocked`
always contains an accountable owner and concrete exit condition.
Contradictory outcome/observation combinations are invalid.

### Coverage is a complete projection, not a success counter

A phase ledger contains exactly one entry for every catalog case in that phase,
including unattempted and failed cases. Missing, extra and duplicate IDs fail
validation. An unplanned case is explicitly `unobserved` with no invented trial
or evidence reference.

V1 permits exactly one authoritative planned trial per case. Coverage consumes
the exact TrialPlan, actor-authority manifest, raw trial records and matching
append-receipt bundles in plan order. It authenticates both authority
documents, recomputes every digest, runs the complete trial validator, and
requires exact equality of RunBinding, selected environment, case, terminal
outcome, Verifier, evidence and blocker.
A planned trial cannot be omitted; an unplanned, duplicate, extra or reordered
record is invalid. Rerun selection is deliberately absent from V1 and requires
a future signed supersession protocol rather than array order or controller
preference.

The denominators are part of the phase and final-composition types:

- `functional`: 104;
- `aws_performance`: 9;
- final release composition: 113, the exact digest-bound composition of the
  first two ledgers; and
- `cost_observation`: 1, reported separately.

A final release record contains no third copied entry array. It consumes and
fully validates raw 104-case functional/AWS-F and 9-case AWS-P phase-ledger
documents, binds their exact SHA-256 values, and requires shared candidate,
source-chain, artifact, catalog, protocol and controller identity. Phase run,
TrialPlan, authority and environment manifests may differ. Only PASS + PASS
derives final PASS. A functional `104/104` result alone cannot be interpreted
as final qualification. The
initial Architecture V2 coverage remains explicitly 0/104 functional and
0/9 AWS-P until real trials and independently verified evidence exist.

### Untrusted protocol input is bounded

The CLI checks file metadata and then performs a capped read before JSON
deserialization; it also rejects excessive or unpaired trial/receipt paths
before opening any of them. The pure validators independently cap raw authority,
plan, trial, coverage, final and receipt documents and cap model collections.
V1 allows at most 114 planned/trial documents, 256 events and 64 evidence
objects per trial, and 4096 bytes for free-form protocol text. Evidence payloads
retain their separate 1 GiB declared hard cap and are fetched by the operational
Verifier with a bounded reader. Oversize producer output becomes INVALID input,
not verifier memory exhaustion.

## Consequences

Future F-epic components can be assigned by protocol boundary without sharing
an in-memory source of truth. A controller can be replaced without changing
catalog, trial or ledger semantics, and observers/verifiers can reject malformed
producer output before it affects a verdict.

The protocol is intentionally stricter than a conventional test report. It
requires separate identities, durable ordering, complete ledgers and retained
negative outcomes, which adds operational work. That work is the cost of making
destructive qualification and release claims auditable.

This decision does not implement a controller, AWS qualification environment,
scenario adapters, durable event ledger, evidence object store, dashboard,
release verdict, deployment or Multi-AZ behavior. Those components must consume
this contract rather than expanding this crate into a workflow harness.
