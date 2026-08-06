# Cats release-qualification protocol V1

- Status: Frozen V1 (2026-08-06)
- Decision: [ADR-0037](../decisions/0037-versioned-release-qualification-protocol.md)
- Machine authority: `qualification/protocol/`

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD** and **MAY** are
normative. V1 validates qualification records; it does not execute a test or
mutate infrastructure.

## 1. Versioned documents

| Document | Schema discriminator | Purpose |
|---|---|---|
| Case catalog | `cats.qualification.catalog/v1` | Stable case, phase, oracle and evidence contract |
| Trial plan | `cats.qualification.trial-plan/v1` | Ordered authoritative trial/case schedule |
| Trial record | `cats.qualification.trial/v1` | One case attempt with identities, events, evidence and terminal |
| Coverage ledger | `cats.qualification.coverage-ledger/v1` | Complete phase projection for one exact run binding |
| Negative fixtures | `cats.qualification.negative-fixtures/v1` | JSON-pointer mutations that a V1 validator MUST reject |

All JSON objects reject unknown fields. An incompatible field, enum or semantic
change requires a new schema discriminator and ADR. Adding a case without
changing a frozen denominator requires a catalog-version change and deliberate
replacement/removal record; changing a denominator requires a new protocol
version.

`catalog_sha256` is SHA-256 over the exact catalog file bytes. Evidence digests
are SHA-256 over the exact archived object bytes. Protocol metadata uses
lowercase hexadecimal without a prefix.

## 2. IDs and exact run binding

`run_id`, `window_id`, `trial_id`, identity, event, evidence and terminal IDs
are immutable ASCII identifiers of 1–128 characters from
`[A-Za-z0-9._:-]`. Case IDs use uppercase/digit hyphen-separated components.
IDs are never recycled inside their scope.

Every `TrialRecord` and `CoverageLedger` contains the same `RunBinding` shape:

| Field | Required form | Meaning |
|---|---|---|
| `run_id` | scoped ID | Unique qualification run |
| `candidate_commit_sha` | 40 lowercase hex | Full candidate Git SHA; abbreviation forbidden |
| `source_chain_verdict_sha256` | 64 lowercase hex | Exact H0 source-chain verdict |
| `artifact_manifest_sha256` | 64 lowercase hex | Build-once candidate artifact manifest |
| `environment_id` | scoped ID | Isolated qualification environment instance |
| `environment_manifest_sha256` | 64 lowercase hex | Exact topology/configuration/inventory manifest |
| `environment_is_production` | exactly `false` | Destructive qualification MUST NOT target production |
| `protocol_version` | `1` | This protocol version |
| `catalog_sha256` | 64 lowercase hex | Exact catalog bytes used for scheduling and coverage |
| `trial_plan_sha256` | 64 lowercase hex | Exact ordered TrialPlan bytes fixed before execution |
| `controller_commit_sha` | 40 lowercase hex | Full controller implementation Git SHA |

Changing any field creates a different binding. Trials from different bindings
MUST NOT be merged, and prior PASS entries MUST NOT be carried into the new
coverage ledger.

The TrialPlan is compact JSON with schema, `run_id`, `catalog_sha256` and an
ordered `planned_trials` array. Each item has a contiguous sequence beginning at
1, unique trial ID and unique case ID. V1 permits at most one planned trial per
case. Its exact file digest is in every downstream RunBinding. The plan is
sealed before `run_bound`; scheduling a rerun requires a future signed
supersession protocol and a new binding, not insertion/reordering in V1.

## 3. Identity, action and event closure

A trial MUST bind exactly five identities. `principal`, `session_id` and
credential fingerprint MUST be distinct across roles. Credentials and tokens
MUST NOT appear in the record; only their SHA-256 fingerprint is retained.

| Role | Exact actions | Events it may emit |
|---|---|---|
| Controller | `bind_run`, `schedule_trial` | `run_bound`, `trial_scheduled` |
| Fault Actor | `apply_fault`, `end_fault` | `mutation_started`, `fault_application_ended` |
| Recovery Actor | `arm_recovery`, `execute_recovery`, `record_cleanup` | `recovery_intent_armed`, `recovery_execution_recorded`, `cleanup_recorded` |
| Observer | `capture_calibration`, `capture_observation`, `seal_evidence` | `known_positive_probe_passed`, `calibration_recorded`, `observation_captured`, `evidence_sealed` |
| Verifier | `verify_evidence`, `issue_terminal` | `evidence_verified`, `terminal_issued` |

The action list is exact: missing, duplicate or additional capabilities are
invalid. No role may emit another role's event. The Observer is the only raw
evidence producer. The Verifier MUST be independent of the Observer and is the
only role that verifies evidence or issues a terminal result.

## 4. Event ledger and recovery ordering

Each event repeats `run_id`, `window_id` and `trial_id`, names its actor identity,
and carries:

- a unique `event_id`;
- a positive, strictly increasing `ledger_sequence` allocated by a durable
  external append ledger;
- `occurred_at` in exact `YYYY-MM-DDTHH:MM:SSZ` form with a valid Gregorian
  calendar value; timestamps MUST be monotonic nondecreasing;
- a recomputed `immutable_record_sha256` for the canonical event preimage; and
- a scoped `subject_id` plus `subject_sha256` for the immutable record or object
  affected by the event.

Ledger sequence, not wall clock, is the cross-actor ordering authority. The
first event MUST be `run_bound`, bound to `run_id` and the artifact-manifest
digest. The second MUST be `trial_scheduled`, bound to `trial_id`. Exactly one
`terminal_issued` event MUST be the final event.

If `mutation_started` exists, all of these events exist exactly once and obey:

```text
recovery_intent_armed < mutation_started
mutation_started < fault_application_ended
mutation_started < recovery_execution_recorded
fault_application_ended < cleanup_recorded
recovery_execution_recorded < cleanup_recorded
```

The controller MUST wait for the durable ledger acknowledgement of
`recovery_intent_armed` before granting the Fault Actor permission to mutate.
The referenced recovery plan includes the recovery actor's authority and the
cleanup obligation. Result records say what actually happened; the event name
does not imply a successful recovery or empty cleanup inventory.

For a mutating trial, `cleanup_recorded` MUST precede every evidence seal,
verification and terminal event, regardless of the evidence event interval.
For a non-mutating trial, recovery intent, fault end, recovery execution and
cleanup events are dangling authority and are invalid.

### 4.1 Canonical receipt preimages

V1 canonical preimages use UTF-8 compact JSON produced from the ordered fields
below, with ordinary JSON string escaping, snake-case enum values, no
whitespace and no maps. The Rust hash helpers in `cats-qualification-protocol`
are the executable authority. The digest field itself is excluded.

```text
event: ledger_sequence,event_id,run_id,window_id,trial_id,kind,
       actor_identity_id,occurred_at,subject_id,subject_sha256

observation: observation_id,state,expectation,calibration_event_id,
             known_positive_event_id,captured_event_id

terminal: terminal_id,outcome,summary,verifier_identity_id,evidence_ids,
          blocker,issued_event_id
```

The validator recomputes all three SHA-256 values. These hashes protect record
content; the external append ledger receipt and sequence prove durability and
ordering. A random well-formed digest is not an acceptable receipt.

## 5. Evidence contract

Each catalog case explicitly lists `required_evidence_kinds`. A trial is invalid
if any required kind is absent. Each `EvidenceObject` contains:

| Field | Rule |
|---|---|
| identity binding | exact run/window/trial and Observer producer IDs |
| `kind`, `media_type` | non-empty and declared before execution |
| `sha256` | exact archived bytes |
| `immutable_locator` | exactly `urn:sha256:<sha256>`; storage location is resolved by the evidence archive index |
| size | positive, at most the declared bound, with V1 hard cap 1 GiB |
| redaction | immutable redaction-policy SHA-256 |
| `secret_scan` | exactly `passed`; `failed` and `not_run` are invalid |
| event interval | existing first/last ledger sequences with first ≤ last |
| seal/verify links | exact event IDs binding the same evidence ID and digest |

Evidence order MUST be:

```text
last captured event
  < observer evidence_sealed(evidence_id, sha256)
  < verifier evidence_verified(evidence_id, sha256)
  < verifier terminal_issued(terminal_id, terminal_record_sha256)
```

Every seal and verification event is linked to exactly one evidence object; no
unlinked or reused event is allowed. The terminal lists every evidence ID
exactly once. Empty files, missing scheduled evidence, digest mismatch,
redaction failure or secret-scan failure cannot become PASS.

The pure validator validates metadata links. The operational Verifier MUST
resolve every `urn:sha256` through the immutable archive index, fetch the object,
enforce the declared bound before buffering it, recompute the digest and apply
the named oracle. A locator, HTTP status or component success flag alone is not
proof.

## 6. Observations and terminal outcomes

Observation state and expectation are separate:

- state: `observed_present`, `observed_empty`, `incomplete`, `unobserved`;
- expectation: `presence`, `absence`.

An Observation also carries a stable `observation_id`, `captured_event_id` and
canonical `record_sha256`. Exactly one `observation_captured` event MUST bind
that observation ID/digest, and it MUST precede every evidence seal.

Any `observed_empty` state MUST reference exactly one
`known_positive_probe_passed` event and one `calibration_recorded` event from
the Observer. Their explicit subject IDs and digests MUST be distinct, and
ledger order is `known_positive < calibration < observation`. Other states
MUST NOT carry either the references or dangling calibration events. This is
the known-positive calibration required before believing an empty probe.

Every terminal result has a terminal ID, non-empty summary, Verifier identity,
all evidence IDs, optional blocker, issued-event ID and recomputed canonical
record digest. The issued event MUST bind that exact terminal ID/digest and
Verifier.

| Outcome | Allowed observation | Additional rule | Counts as PASS |
|---|---|---|---:|
| `pass` | present/expected presence, or calibrated empty/expected absence | evidence verified; no blocker | yes |
| `fail` | observed present | oracle or content failed; no blocker | no |
| `empty` | calibrated empty/expected presence | absence is explicit, not success | no |
| `incomplete` | incomplete | partial execution/evidence retained | no |
| `unobserved` | unobserved | no oracle reading obtained | no |
| `invalid` | any | environment/protocol/evidence invalid | no |
| `blocked` | incomplete or unobserved | non-empty owner and exit condition | no |
| `cancelled` | incomplete or unobserved | cancellation is not absence | no |
| `timed_out` | incomplete or unobserved | timeout is not absence | no |

All attempted terminal outcomes require evidence. Only `blocked` carries a
blocker. A contradictory state/outcome pair is invalid even if a producer marks
it PASS.

## 7. Catalog and phase denominators

The V1 catalog contains 114 stable IDs:

| Catalog phase | Count | Priority | Required for release |
|---|---:|---|---:|
| `functional` | 104 | P0/P1 | yes |
| `aws_performance` | 9 | P0/P1 | yes |
| `cost_observation` | 1 | P2 | no |

The 104 functional set is all source P0/P1 cases except the nine explicitly
listed AWS-P phase cases. `PERF-COST-001` is the single P2 observation. The
catalog records the exact migration source ref, source digest, selection policy
and Architecture V2 review baseline.

Case IDs are stable. A case specifies its phase, suite, environment profiles,
architecture sources, accountable oracle owner, independent oracle and explicit
evidence kinds. The global forbidden oracle is the component-under-test success
field or private in-memory state by itself.

## 8. Coverage-ledger semantics

A ledger phase is one of:

| Coverage phase | Exact `expected_total` | Catalog membership |
|---|---:|---|
| `functional` | 104 | functional cases |
| `aws_performance` | 9 | AWS performance cases |
| `release_required` | 113 | union of functional and AWS performance |
| `cost_observation` | 1 | P2 cost observation only |

The ledger MUST contain exactly one entry for every member and no other entry.
Missing, extra and duplicate case IDs are invalid. Every entry carries a
terminal outcome; failure, blockage, empty, incomplete, unobserved, invalid,
cancellation and timeout are records, not omissions.

An unplanned entry is exactly `unobserved` with null trial/digest, empty evidence
references and no Verifier. A planned entry names exactly one trial ID and one
SHA-256 over the exact raw trial-record bytes, plus evidence IDs and a Verifier
identity. `blocked` also names its owner and exit condition.

Validation requires the exact TrialPlan bytes and the raw trial documents in
filtered plan order. It recomputes each trial digest, runs the full TrialRecord
validator and requires trial/ledger RunBinding equality plus exact case,
terminal outcome, Verifier, evidence-list and blocker equality. Every
phase-relevant planned trial MUST have one record; extra, missing, duplicate or
reordered records are invalid. Thus a producer cannot omit a failed attempt,
invent trial references or relabel its terminal as PASS.

`phase_outcome` is derived:

1. any `invalid` entry → `invalid`;
2. otherwise any `fail` entry → `fail`;
3. otherwise every entry `pass` → `pass`;
4. otherwise → `incomplete`.

The operational Verifier resolves every trial-record digest, validates the
trial against the same catalog bytes, requires its `RunBinding` to equal the
ledger binding byte-for-byte, and checks that the referenced evidence objects
are the verified objects in the trial. A coverage ledger is a projection, never
an authority that can replace its trial records.

Final release logic MUST consume a passing `release_required` ledger with
113/113 PASS. A functional 104/104 ledger and AWS-P 9/9 ledger are separately
useful phase gates, but only their exact-binding 113-case union is the final
release-required coverage. `PERF-COST-001` is reported independently and MUST
NOT affect the release-required denominator.

## 9. Validator and fixtures

From the repository root:

```bash
cargo run -p cats-qualification-protocol -- \
  catalog qualification/protocol/catalog/case-catalog-v1.json

cargo run -p cats-qualification-protocol -- \
  trial qualification/protocol/catalog/case-catalog-v1.json \
  qualification/protocol/fixtures/positive/trial-v1.json

cargo run -p cats-qualification-protocol -- \
  coverage qualification/protocol/catalog/case-catalog-v1.json \
  qualification/protocol/fixtures/positive/trial-plan-empty-v1.json \
  qualification/protocol/fixtures/positive/functional-zero-of-104.coverage.json
```

`catalog-digest` prints the digest over exact catalog bytes. The positive trial
is the known-positive probe for role, mutation/recovery, evidence and terminal
linkage. The functional fixture is deliberately a valid **0/104** ledger: every
case is explicitly unobserved, so its phase result is incomplete.

`fixtures/negative/trial-validation-cases-v1.json` is executable test data. It
declares JSON-pointer set/remove mutations and the required rejection reason,
including production targeting, abbreviated candidate SHA, identity collapse,
mutation without prior recovery intent, non-monotonic and malformed time,
unauthorized evidence production, secret-scan failure, seal/terminal
substitution, contradictory outcomes and missing cleanup.

For a non-empty plan, append one `--trial <path>` per phase-relevant planned
trial in authoritative plan order. Omitting, adding or reordering these files
fails validation.

## 10. Explicit non-goals

V1 does not provide a workflow controller, infrastructure provisioning,
scenario adapters, AWS clients, mutable in-memory ledger, object archive,
dashboard, performance analyzer, release verdict or deploy trigger. A future
component may implement one of those boundaries, but MUST emit/consume these
files and MUST NOT move its private state into this protocol crate as a second
authority.
