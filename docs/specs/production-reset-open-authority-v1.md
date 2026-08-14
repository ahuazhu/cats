# Production reset and final-open authority v1

- Status: **Frozen target; implementation lands with ADR-0051**
- Scope: the first clean-slate production reset and the one final public-open transaction
- Decision: [ADR-0051](../decisions/0051-production-final-reset-and-open-authority.md)
- Reset executor: [`deploy/aws/production-clean-slate-reset.py`](../../deploy/aws/production-clean-slate-reset.py)

This contract composes terminal evidence. It does not mint Route, Usage, Volume, HostFence,
placement or release authority. A proof file is accepted only when its own closed schema and
terminal postcondition validate and all cross-bindings below match.

The Control mutation-admission authority is one independent offline Ed25519 cutover key installed
through canonical `production-cutover-operator-trust.v1.json`. WorkOS, A23 provisioner, G3 signer,
static admin and Workspace credentials are not accepted. The operator tool performs real online
STS discovery before signing and places the exact assumed-role ARN/account/partition/role inside
the command. Control verifies the offline signature, release-bound trust scope and command expiry;
it does not contact AWS or independently authenticate the signed STS claim.

## 1. Files, digests and bounds

The operator creates one actor-owned real directory with mode `0700`. Every input is a non-symlink,
single-link regular file owned by the actor, not group/world writable, stable across the bounded
read and no larger than its producer's limit (otherwise 2 MiB). No reference may contain `/`, `.`
or `..`; all referenced files are direct children of that directory.

`Sha256Digest` is `sha256:` followed by 64 lowercase hex characters. A reference is:

```text
ProofFileV1 {
  file: 1..=128 ASCII [A-Za-z0-9][A-Za-z0-9_.-]*,
  sha256: Sha256Digest,
  size_bytes: integer 1..=2097152
}
```

The consumer opens by descriptor with `O_NOFOLLOW`, verifies metadata before and after read, then
checks exact size and SHA-256. JSON decoders reject duplicate/unknown/missing fields and trailing
bytes. Producer-canonical JSON/JSONL must reproduce the exact input bytes; a consumer never
normalizes a noncanonical receipt into authority.

The fixed Control trust path is `/etc/cats/production-cutover-operator-trust.v1.json`, configured
only through `CATS_PRODUCTION_CUTOVER_OPERATOR_TRUST_FILE`. The release installs that exact
root-owned, non-group/world-writable artifact and records its SHA-256/size as a manual-release
closed-set member. There is no WorkOS, A23, G3 or static-admin fallback.

## 2. Canonical proof set

`production-cutover-proof-set.v1.json` uses Cats canonical JSON (sorted object keys, compact
separators, ASCII escapes, one terminal LF):

```text
ProductionCutoverProofSetV1 {
  kind: "cats.production-cutover-proof-set.v1",
  version: 1,
  cutover_id: Id,
  reset_id: Id,
  observed_at: RFC3339 UTC seconds,
  operator: {
    kind: "aws_sts_assumed_role" | "aws_sts_user",
    principal_arn: exact ARN,
    account_id: 12 digits
  },
  release: {
    commit: 40 lowercase hex,
    artifact_sha256: Sha256Digest,
    source_manifest_sha256: Sha256Digest,
    source_bundle_sha256: Sha256Digest,
    source_receipt: ProofFileV1,
    build_receipt: ProofFileV1,
    release_manifest: ProofFileV1
  },
  fresh: {
    deployment_id: Id,
    aws_partition: "aws" | "aws-us-gov" | "aws-cn",
    aws_region: canonical region,
    eks_cluster_name: DNS label,
    kubernetes_namespace: DNS label,
    control_schema_version: 16,
    targets: FreshTargetsV1
  },
  proofs: {
    fleet_closed: ProofFileV1,
    route_signing_command: ProofFileV1,
    route_ring_delivery: ProofFileV1,
    usage_terminal: ProofFileV1,
    old_host_inventory: ProofFileV1,
    old_host_coverage: [OldHostCoverageV1],
    qualification: {
      kernel_nbd: QualificationProofV1,
      vhost_user: QualificationProofV1
    }
  }
}
```

`FreshTargetsV1` contains exactly the fresh Control schema, Usage schema, versioned ChunkStore
bucket/exact trailing-slash prefix, Kinesis stream, DynamoDB checkpoint table and immutable Usage
archive bucket. Reset CLI inputs must match every value. Old and fresh targets must be pairwise
disjoint under the reset executor's stronger overlap rules.

The source receipt must bind `source_sha`, tree SHA, source manifest and source bundle digests. The
successful frozen build receipt must bind those four values, `exit_status=0`, `output_frozen=true`,
`job_cgroup_drained=true`, and no forwarded AWS environment or reusable home. The manual release
manifest must be v1, bind `source.commit`, and its exact file digest is the proof set's
`artifact_sha256`. Both qualification manifests must bind that same release manifest, build receipt,
source commit, schema 16 and worker bundle.

## 3. Terminal proof closed set

### 3.1 Fleet Closed and zero guards

`fleet_closed` is the canonical `FleetVerificationEvidence` emitted by the exact release's
`cats admin fleet-verify`, not a copied projection. The consumer repeats its closed validation:

- exact release commit and exact nonempty sorted Node set;
- Control Desired and current observation counts are zero;
- each Node has one current unexpired session bound to the approved Guest digest;
- session-bound complete inventory is fresh and reports assigned Desired/runtime/residue/lifecycle
  open/route active/route closed/active guard/cancellation pending/quarantine counts all zero;
- each Node loaded the exact current ring version/digest/kid set;
- the snapshot signer deployment, revision, ring version/digest and active kid are present.

The reset preflight obtains a new fleet receipt within its closed freshness window. Forward-resume
keeps the exact pre-start receipt binding but re-runs official read-only fleet discovery before every
new destructive stage. A stale receipt alone never proves the live fleet remains Closed.

### 3.2 G3 Route signing delivery

`route_signing_command` must be the committed immutable command receipt discovered by exact
`(authority_id, command_id)`. It must bind exact canonical command bytes/digest, release ID,
target deployment, expected signer predecessor and terminal `applied` outcome. The matching
`route_ring_delivery` must be the same transaction's exact adjacent signed public-ring successor:
source command/release, deployment, resulting ring version, expected predecessor, ring digest and
signed envelope bytes/digest all match. The resulting signer/ring fields must equal the
`fleet_closed` snapshot. `authority_precondition_failed`, missing delivery, a gap, replay with a
different body, or a provider/operator projection fails closed.

### 3.3 E9 final Usage terminal

`usage_terminal` must be E9's committed terminal receipt discovered by its exact reset/source/release
epoch identity. It must bind the old and fresh Usage schema/stream/table/archive targets, final event,
immutable archive object digest, projector committed watermark and terminal outcome. The final
event and watermark must prove all accepted pre-cutoff Usage events are archived and visible before
old transport retirement. A provisional marker, an empty stream/table, a local counter or a receipt
whose exact schema has not been accepted fails closed.

### 3.4 Old Host coverage and V3

`old_host_inventory` contains the sorted closed old Host/component set. `old_host_coverage` has the
same sorted Host IDs exactly once:

```text
OldHostCoverageV1 {
  host_id: Id,
  components: sorted nonempty subset of
    ["blockd","controller","gateway","node_agent","vmm"],
  terminal: {
    kind: "local_positive_stop",
    receipt: ProofFileV1
  } | {
    kind: "host_fence_event",
    event_id: Id,
    receipt: ProofFileV1
  }
}
```

Local receipts must be accepted `local_systemd` positive-stop receipts: exact machine/boot,
idle preflight, protected VMM/blockd absence, loaded unit stop and stable process-tree absence. EC2
Security Group isolation cannot appear as terminal coverage. A HostFence receipt must be a committed
V3 core event in `Active` state, pass the core validator, bind provider scope + immutable Host + Node
+ boot + session + fence attempt, and include the mandatory object-write cutoff terminal proof.
Provider-only evidence and AWS-specific fields are neither parsed nor accepted by E13.

Across coverage entries every inventory Host/component pair occurs exactly once; missing, duplicate
or extra coverage fails closed.

### 3.5 V5 qualification

Each `QualificationProofV1` contains exact `manifest.json`, `case-receipts.jsonl` and `SHA256SUMS`
references. The manifest must be terminal `passed`, `exit_code=0`, have the exact block path, schema,
release/build/installer identities and a checksum-closed output set. Required case receipts prove:
fresh cell/target identity; Persistent create→Cold attach→first-format→`R==L` Initialized→mounted
Ready→Cold drain/release→detach; Agent crash/restart adoption; stale epoch/ABA rejection; and final
Closed gates, zero guards, complete inventory with no unknown residue. Both block paths are required;
one path, skipped/deferred cases, edited JSONL or a reused run ID fails closed.

## 4. Reset plan and forward-only journal

The reset `plan` and dry-run are read-only. `apply --execute` first revalidates the proof set, exact
STS principal and live Closed fleet. It then publishes `reset-started` before the first effect.
Every reset receipt adds:

```text
operator_principal_arn
proof_set_sha256
source_manifest_sha256
source_bundle_sha256
release_manifest_sha256
fleet_closed_sha256
route_signing_command_sha256
route_ring_delivery_sha256
usage_terminal_sha256
```

The ordered chain remains `reset-started -> s3-empty -> usage-transport-empty ->
control-schema-empty -> usage-schema-empty -> reset-complete`. Each stage binds its predecessor.
After `reset-started`, only the same exact invocation may resume. A missing receipt triggers live
postcondition discovery; a completed postcondition settles the receipt without repeating the
effect. A contradictory or ahead-of-chain effect stops for investigation. `SIGINT`/`SIGTERM` before
start exits with no mutation; after start it stops only at a stage boundary and leaves the journal
resumable.

### 4.1 Bounded Qualification mode

The same schema-16 build starts `Closed`, so its own G3/V3/V5 qualification cannot depend on a
final Open receipt that does not exist yet. [ADR-0052](../decisions/0052-bounded-production-qualification-admission.md)
adds the independent sum variant below; it is not a partial `OpenBinding`:

```text
QualificationAdmissionBinding {
  qualification_id, deployment_id, release_id,
  source_commit_sha, control_schema_version: 16,
  source_manifest_sha256, source_bundle_sha256, build_receipt_sha256,
  release_manifest_sha256, worker_bundle_sha256,
  qualification_catalog_sha256, qualification_cell_manifest_sha256,
  aws_partition, aws_account_id, aws_region, cell_id, cell_namespace,
  cats_account_id, workspace_id,
  allowed_mutation_classes: [
    "cat_create", "disk_create", "disk_delete", "runtime_mutation"
  ],
  qualification_expires_at_unix_ms
}

AdmissionBinding =
  {"kind":"qualification","binding":QualificationAdmissionBinding} |
  {"kind":"open","binding":OpenBinding}
```

`qualification_expires_at_unix_ms` is later than the Begin command expiry and at most 24 hours
after command issue. PostgreSQL time is authoritative at Begin and every product transaction.
Account/Workspace must already exist and be active under the independent identity authority.

The canonical mutation tag is one of `begin_qualification`, `end_qualification`, `open`,
`emergency_close`. All use the same dedicated offline cutover signature and signed online-STS
claim. Submit and typed discovery are exact POSTs to:

```text
/v1/admin/production/mutation-admission-commands
/v1/admin/production/mutation-admission-command-discoveries
/v1/admin/production/mutation-admission-state-discoveries
```

An exact `(command_id,canonical command bytes)` replay returns the original immutable receipt;
same ID/different bytes is conflict. Begin is only `Closed -> Qualification`. End is only the
same exact `Qualification -> Closed`. EmergencyClose is exact `Qualification|Open -> Closed`.
End/close locks the singleton `FOR UPDATE`; each covered runtime product write locks it `FOR SHARE`
inside the domain-write transaction after exact API replay lookup. Thus successful End/close waits
for all admitted writers and no such writer commits afterward.

The only Qualification classes are the four ordered values above. They cover Cat create,
PersistentDisk create/delete, and the one Desired mutation root used by lifecycle, Endpoint and
attach/detach. Only the exact bound Workspace is admitted. Reads, health/reset, identity/WorkOS,
Stripe event settlement and internal observation/Operation/Usage/Volume cleanup keep their own
authority and remain available while Closed. OCI deploy/exec, snapshot/restore, legacy lifecycle,
legacy Node and wake routes are not registered by the production router.

Successful qualification publishes these non-recursive framework receipts:

```text
production-mutation-qualification-begin.receipt.json {
  kind: "cats.production-mutation-qualification-begin-receipt.v1", version: 1,
  qualification_id, binding_sha256,
  begin_command_id, begin_request_sha256, begin_command_receipt_sha256,
  resulting_revision, qualification_expires_at_unix_ms
}

production-mutation-qualification-terminal.receipt.json {
  kind: "cats.production-mutation-qualification-terminal-receipt.v1", version: 1,
  qualification_id, binding_sha256,
  begin_command_id, begin_request_sha256, begin_command_receipt_sha256,
  begin_resulting_revision,
  end_command_id, end_request_sha256, end_command_receipt_sha256,
  final_admission_state_sha256, final_closed_revision,
  fleet_closed_receipt_sha256, cleanup_inventory_receipt_sha256,
  active_guard_count: 0, product_resource_count: 0, residue_count: 0,
  completed_at_unix_ms
}
```

`final_closed_revision == begin_resulting_revision + 1`. Cleanup product mutations finish before
End. The final state/fleet/cleanup receipts are read afterward; E9 terminalization is later still.
Failure may emergency-close and destroy the isolated cell but cannot publish the successful
terminal receipt. The final qualification manifest hashes these receipts; neither receipt hashes
that manifest, avoiding a recursive digest.

## 5. Final-open transaction

Final-open has separate canonical plan/receipt kinds and a new `open_id`. The read-only plan binds
the exact `reset-complete` bytes, proof set, operator principal, mutation-open request, sorted A23
schedulable requests, reviewed Terraform plan file and final probe target. It refuses a plan whose
Terraform projection changes anything outside the closed ingress/DNS/application-open set.

Execution revalidates all terminal proof bindings and live Closed fleet before publishing
`open-started`. Its ordered receipts are:

```text
open-started
mutation-admission-open
node-<node_id>-schedulable       // sorted exact Node set
nodes-schedulable
public-ingress-open
public-probe-terminal
open-complete
```

Mutation-open and A23 effects use their canonical request IDs and exact bodies. Ambiguous HTTP or
process results retain/replay the same official pending request and discover the typed stored
outcome; never issue a new ID. Terraform applies only the exact reviewed saved plan and settles an
ambiguous response through refresh/show plus exact Kubernetes/AWS postcondition discovery. Public
Ingress is the last mutation. New product creation is forbidden until `open-complete` exists.

Cancellation before `open-started` is mutation-free. Cancellation/failure afterward invokes the
closed cleanup sequence: apply the exact reviewed ingress-close plan if ingress may be open,
re-cordon each possibly schedulable Node with new exact A23 revisions/IDs, close mutation admission,
then obtain a fresh empty-fleet/zero-guard receipt. Cleanup is idempotent and journals every
terminal result; inability to prove cleanup exits nonzero and keeps incident ownership—it never
marks the open complete or touches the old namespace.

## 6. Qualification contract

Offline fixtures must cover known-positive complete proof composition before trusting every
negative. Required negatives include missing/extra proof, duplicate JSON key, digest/size drift,
wrong release/source/reset/fresh target, provisional E9/G3/V3, provider-only fence, one V5 block
path, stale/ABA fleet session, nonzero guard/count, wrong STS principal, response loss after each
effect, crash before/after each receipt publication, exact replay, cancellation before start and
cleanup after every partial open stage. Tests assert zero external mutation before all terminal
proofs validate and zero uncordon/Ingress calls before `reset-complete` is verified.
