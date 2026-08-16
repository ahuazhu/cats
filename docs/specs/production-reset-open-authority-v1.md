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
    aws_partition: "aws" | "aws-us-gov" | "aws-cn",
    account_id: 12 digits,
    role_arn: exact IAM role ARN,
    principal_arn: exact STS assumed-role ARN
  },
  release: {
    release_id: Id,
    source_commit_sha: 40 lowercase hex,
    artifact_sha256: Sha256Digest,
    source_manifest_sha256: Sha256Digest,
    source_bundle_sha256: Sha256Digest,
    qualification_manifest_sha256: Sha256Digest,
    qualification_catalog_sha256: Sha256Digest,
    source_receipt: ProofFileV1,
    build_receipt: ProofFileV1,
    release_manifest: ProofFileV1,
    qualification_manifest: ProofFileV1,
    qualification_catalog: ProofFileV1
  },
  old: FreshTargetsV1,
  fresh: {
    deployment_id: Id,
    aws_partition: "aws" | "aws-us-gov" | "aws-cn",
    aws_account_id: 12 digits,
    aws_region: canonical region,
    cell_id: Id,
    cell_namespace: DNS label,
    control_schema_version: 16,
    targets: FreshTargetsV1
  },
  proofs: {
    fleet_closed: ProofFileV1,
    route_v2_rotation_qualification_receipt: ProofFileV1,
    route_v2_rotation_qualification_node_ack_sets: ProofFileV1,
    route_v2_rotation_qualification_transcript: ProofFileV1,
    usage_global_case_evidence: ProofFileV1,
    usage_global_finalization_manifest: ProofFileV1,
    usage_global_qualification_catalog: ProofFileV1,
    usage_global_sha256sums: ProofFileV1,
    usage_terminal_targets: ProofFileV1,
    usage_terminal_request: ProofFileV1,
    usage_terminal_receipt: ProofFileV1,
    usage_terminal_verification: ProofFileV1,
    old_host_inventory: ProofFileV1,
    old_host_coverage: ProofFileV1,
    qualification: {
      kernel_nbd: RunnerBundleProofV1,
      vhost_user: RunnerBundleProofV1
    }
  }
}

ProofFileV1 { file: direct-child name, sha256: Sha256Digest, size_bytes: u64 > 0 }

RunnerBundleProofV1 {
  manifest, case_evidence, qualification_catalog, sha256sums: ProofFileV1,
  component_journal_summary, exit_code, final_inventory,
  runtime_state, scenario_results: ProofFileV1,
  qualification_begin, qualification_terminal: ProofFileV1,
  qualification_begin_pending, qualification_begin_command_receipt: ProofFileV1,
  qualification_close_pending, qualification_close_command_receipt: ProofFileV1,
  qualification_final_state, qualification_final_fleet,
  qualification_product_inventory, qualification_cleanup_inventory: ProofFileV1
}
```

Every block-path descriptor therefore contains exactly 19 actual-file references. `SHA256SUMS`
contains exactly the other 18 logical runner filenames in C byte order, with no missing, duplicate,
foreign or self row, and every row is checked against the bytes named by its proof reference. The
flat proof directory stages each member as `<block-path>-<logical-runner-filename>`; arbitrary aliases
are rejected, while checksum rows retain the unprefixed logical filename.

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

### 3.2 G3 Route qualification and live Route state

The three `route_v2_rotation_qualification_*` files are immutable evidence from the dedicated
qualification cell. They prove disable plus full active recovery using the seven actual fresh signed
commands/Store results, both the disabled checkpoint and recovered Node ACK sets, a fresh endpoint
epoch and post-restart current-process discovery. They bind the exact runner/release/catalog and do
not claim that production is currently disabled. Independently, `fleet_closed` must prove that the
fresh production target is Closed while its expected active, nonempty ring is installed. E13 calls
the reviewed G3 typed verifier over all three exact files; it does not decode provisional templates,
AWS rollout details or a single phase receipt as terminal qualification evidence.

### 3.3 E9 final Usage terminal

Each block-path bundle first closes its unique `usage-source-terminal-receipts.json` evidence and
its own Qualification Begin→End→Closed chain. Only after both bundles are terminal does the
run-wide finalizer create `usage-global-terminal-finalization.manifest.json`,
`usage-target-terminal-request.json`, `usage-target-terminal-receipt.json` and
`usage-target-terminal-verification.receipt.json`. The global manifest binds the ordered
`kernel-nbd` and `vhost-user` manifest/case-evidence/source-set digests, the exact union of their
source epochs, the manifest-bound `usage-terminal-targets.json`, and every final target artifact.
There is no per-block target-terminal effect.

The global output is exactly seven files plus `SHA256SUMS`: `case-evidence.jsonl`, the copied
`qualification-catalog.v1.json`, the manifest, request, receipt, verification receipt and target
config. The checksum file has exactly those seven bytewise-sorted GNU rows, no self-row or extras.
The three case-evidence rows are exactly request, receipt and verification in that order and embed
the exact standalone canonical content/digest/size. The request's source list, source-set digest and
terminal epoch must independently equal the two qualified-run union; receipt↔request validation
alone cannot establish that relationship.

Python closes these outer identities but does not duplicate E9's archive/barrier oracle. It invokes
the release-bound Rust worker member exactly as follows and compares the newly produced canonical
verification receipt byte-for-byte with the referenced proof file:

```text
/opt/cats/bin/cats-usage-terminal-receipt-verifier
  --receipt-file ABS/usage-target-terminal-receipt.json
  --expected-request-file ABS/usage-target-terminal-request.json
  --expected-targets-file ABS/usage-terminal-targets.json
  --expected-targets-sha256 sha256:64lowerhex
  --release-commit 40lowerhex
  --worker-bundle-sha256 sha256:64lowerhex
  --receipt-out ABS/usage-target-terminal-verification.receipt.json
```

Only exit 0 and stdout exactly `Usage terminal receipt verified\n` pass. The tool calls the canonical
Rust target-terminal validator, requires exact request/target equality and release/worker binding,
and emits kind `cats.usage-terminal-receipt-verification.v1` with the expected-target file and
semantic target-binding digests. A pre-existing JSON projection, a Python-only field check, absent
source receipt, incomplete shard barrier or provisional marker fails closed.

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

The current local positive-stop contract remains Proposed, so its typed verifier is unavailable and
such an entry fails closed by default. EC2 Security Group isolation cannot appear as terminal
coverage. Under the accepted v1 manual-fencing decision (`CUTOVER-DECISIONS.md` D7), the reset
operator may admit `local_positive_stop` and `host_fence_event` coverage entries by supplying an
explicit, completeness-validated manual attestation (`--accept-manual-fence-evidence`, documented in
[`deploy/aws/production-clean-slate-reset.md`](../../deploy/aws/production-clean-slate-reset.md));
that input binds each staged forensic receipt by exact digest and mints no HostFenceEvent or
takeover authority. Otherwise a
HostFence receipt must be a committed
V3 core event in `Active` state, pass the core validator, bind provider scope + immutable Host + Node
+ boot + session + fence attempt, and include the mandatory object-write cutoff terminal proof.
Provider-only evidence and AWS-specific fields are neither parsed nor accepted by E13.

Across coverage entries every inventory Host/component pair occurs exactly once; missing, duplicate
or extra coverage fails closed.

### 3.5 V5 qualification

Each `RunnerBundleProofV1` contains exact `manifest.json`, `case-evidence.jsonl`,
`qualification-catalog.v1.json`, `SHA256SUMS` and its own Qualification admission support files.
The manifest's ordered `qualification_admission_required_evidence` closes the canonical Begin and
terminal framework receipts; `SHA256SUMS` also closes both pending commands, both Store receipts,
the final Closed state and the final Fleet/cleanup receipts. The catalog carries the same ordered
Begin/terminal filenames and JSON kinds as a run-wide required evidence closed set. The manifest
must be terminal `passed`, have `exit_code=0`, the exact raw block path (`kernel-nbd` or
`vhost-user`), schema,
release/build/installer/catalog identities and a checksum-closed output set. The unique embedded
`volume-init-matrix/persistent-disk-receipt.json` evidence proves:
fresh cell/target identity; Persistent create→Cold attach→first-format→`R==L` Initialized→mounted
Ready→Cold drain/release→detach; Agent crash/restart adoption; stale epoch/ABA rejection; and final
Closed gates, zero guards, complete inventory with no unknown residue. Its unique Usage source-set
evidence binds the same run/workspace/release/catalog. Both block paths are required; one path,
skipped/deferred cases, edited JSONL or a reused run ID fails closed.

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
The terminal `fresh_namespace_proof` binds both `control_schema_version: "16"` and
`usage_schema_version: "16"`; either fresh schema at another version fails before
`reset-started` and on every forward replay.
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
    "cat_create", "disk_create", "disk_delete", "object_write_ambiguity",
    "runtime_mutation"
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
/v1/admin/production/qualification-product-inventory-discoveries
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
  qualification_id, workspace_id, release_id, source_commit_sha,
  qualification_catalog_sha256,
  allowed_mutation_classes: [
    "cat_create", "disk_create", "disk_delete", "object_write_ambiguity",
    "runtime_mutation"
  ],
  binding_sha256,
  begin_command_id, begin_request_sha256, begin_command_receipt_sha256,
  resulting_revision, qualification_expires_at_unix_ms
}

production-mutation-qualification-terminal.receipt.json {
  kind: "cats.production-mutation-qualification-terminal-receipt.v1", version: 1,
  qualification_id, workspace_id, release_id, source_commit_sha,
  qualification_catalog_sha256, allowed_mutation_classes,
  qualification_expires_at_unix_ms, binding_sha256,
  begin_command_id, begin_request_sha256, begin_command_receipt_sha256,
  begin_resulting_revision,
  close_kind: "end_qualification" | "emergency_close",
  terminal_outcome: "qualified_closed" | "emergency_closed",
  close_command_id, close_request_sha256, close_command_receipt_sha256,
  final_admission_state_sha256, final_closed_revision,
  fleet_closed_receipt_sha256, product_inventory_receipt_sha256,
  cleanup_inventory_receipt_sha256,
  active_guard_count: 0, product_resource_count: 0, residue_count: 0,
  completed_at_unix_ms
}
```

`final_closed_revision == begin_resulting_revision + 1`. Cleanup product mutations finish before
End. The only valid pairs are `end_qualification -> qualified_closed` and
`emergency_close -> emergency_closed`; the latter is mandatory failure/cancellation evidence but
cannot authorize reset or Open. `qualification_id` is the exact runner run ID, not a reusable cell
label. The final state/fleet/cleanup receipts are read afterward; E9 terminalization is later still.
The final qualification manifest hashes these receipts; neither receipt hashes that manifest,
avoiding a recursive digest.

After the exact close is applied, the product-inventory discovery POST reuses the original signed
close command and dedicated cutover headers.  It accepts only `EndQualification` or a
Qualification-scoped `EmergencyClose` that is the current immutable Closed successor.  One
deadline-bound repeatable-read transaction locks the singleton `FOR SHARE`, checks the applied
command receipt, decodes the complete clean-slate product graph without pagination, and emits:

```text
production-mutation-qualification-product-inventory.receipt.json {
  kind: "cats.production-mutation-qualification-product-inventory.v1", version: 1,
  qualification_id, workspace_id, release_id, source_commit_sha,
  qualification_catalog_sha256, binding_sha256,
  close_kind, close_command_id, close_request_sha256,
  close_command_receipt_sha256, closed_revision, evaluated_at_unix_ms,
  complete: true,
  counts: {
    current_cat_count, root_disk_count, persistent_disk_count,
    disk_snapshot_count, endpoint_count, hostname_desired_lookup_count,
    pending_runtime_operation_count,
    deleted_cat_tombstone_count, terminal_runtime_operation_history_count,
    api_idempotency_receipt_count
  },
  product_resource_count
}
```

`product_resource_count` is the checked sum of the first seven counters.  A `Deleted` Desired/Cat
tombstone, terminal `runtime_operations` row, or `api_idempotency_results` row is retained history,
reported by the final three counters, and never mistaken for a live product resource.  All
`cat_records`, `endpoint_records`, `disk_records`, `disk_snapshot_records`,
`desired_runtime_specs`, `hostname_desired_lookups`, and `runtime_operations` JSON/scalar
projections are decoded and cross-checked.  A missing Cat/Desired pair, orphan RootDisk/Endpoint/
hostname/Operation, rebound Snapshot, or pending Operation not equal to current Desired is corrupt
and fails closed.  Volume/residue and physical-runtime zero remain the independent E12/fleet
oracles; clients must not infer them by counting product APIs.

### 4.2 Runner Qualification hook

Each block-path runner invocation has its own unique `run_id`, binding, 0700 operator state
directory and Begin/terminal pair. The exact source tool is
`deploy/aws/production-mutation-admission.py`. Nonsecret staged configuration labels are:

- `production-cutover-operator-trust` for the fixed
  `/etc/cats/production-cutover-operator-trust.v1.json` public trust;
- `production-mutation-qualification-binding` for the canonical run-specific
  `QualificationAdmissionBinding`;
- `production-qualification-cell-manifest` for the canonical Terraform/control identity artifact;
- the existing `qualification-catalog` and approved manual release manifest.

The offline private key is a root-only secret input to Begin/close. It is never a config label,
manifest member, digest projection or evidence copy. The cell manifest kind is
`cats.production-qualification-cell-manifest.v1` and closes exactly the run/deployment/release,
source, AWS partition/account/region, ADR-0038 cell ID/namespace, Cats account/Workspace, Control
origin/schema, release-manifest/worker/catalog digests and creation time. Its exact file digest is
the binding's `qualification_cell_manifest_sha256`.

The runner calls, with the common exact identity/file arguments shown by `--help`:

```text
production-mutation-admission.py qualification-begin COMMON-SIGNED-ARGS
... run cases and exact cleanup ...
production-mutation-admission.py qualification-close COMMON-SIGNED-ARGS \
  --close-kind end_qualification
production-mutation-admission.py qualification-product-inventory COMMON-VERIFY-ARGS \
  --close-kind end_qualification
... obtain only read-only post-close Fleet/E12 evidence and assemble cleanup ...
production-mutation-admission.py qualification-terminalize COMMON-VERIFY-ARGS \
  --close-kind end_qualification \
  --fleet-closed-receipt ABS/production-mutation-qualification-final-fleet-closed.receipt.json \
  --product-inventory-receipt ABS/production-mutation-qualification-product-inventory.receipt.json \
  --cleanup-inventory-receipt ABS/production-mutation-qualification-cleanup-inventory.receipt.json
```

Begin first signs a deterministic read-only state probe, discovers the exact current revision, then
durably creates the real pending command before submit. Close takes the conflicting Store lock and
publishes the canonical final Closed state before the runner obtains post-close evidence.
Terminalize has no private-key/AWS/OpenSSL argument and refuses to create a missing close command; it
can only exact-replay/discover the durable close and assemble evidence. The final Fleet wrapper kind
is `cats.production-mutation-qualification-final-fleet-closed.v1`; the cleanup wrapper kind is
`cats.production-mutation-qualification-cleanup-inventory.v1`. Both bind run/Workspace/source/raw
block path, are evaluated after the close commit, are complete, and carry exact zero runtime/guard/
residue projections. The cleanup wrapper additionally carries
`product_inventory_receipt_sha256` and copies the Control oracle's zero `product_resource_count`;
Fleet and cleanup evaluation times cannot predate that oracle.

The runner's failure/cancellation trap never invents cleanup. It finishes only explicitly allowed
run-bound cleanup, invokes `qualification-close --close-kind emergency_close`, then obtains the same
read-only zero proofs and terminalizes as `emergency_closed` when possible. If zero cleanup cannot be
proved, the close command receipt and final Closed state remain durable, no successful terminal
receipt is published, and the ADR-0038 cell stays isolated for Terraform destruction. An ambiguous
Begin/End/EmergencyClose is always resolved with the same pending bytes before any different command
may be prepared.

## 5. Final-open transaction

Final-open has separate canonical plan/receipt kinds and a new `open_id`. The read-only plan binds
the exact `reset-complete` bytes, proof set, operator principal, mutation-open request, sorted A23
schedulable requests, reviewed Terraform plan file and final probe target. It refuses a plan whose
Terraform projection changes anything outside the closed ingress/DNS/application-open set.
The plan records an execution deadline at least 30 seconds before the signed mutation-open command
expires. A plan at or beyond that deadline is unusable and requires a new `open_id`; it is never
silently re-signed or refreshed under the reviewed plan.

Production final-open has one installed state root,
`/var/lib/cats/production-final-open`. It and its exact two direct children, `admission-state/` and
`receipts/`, are root:root mode `0700` real directories. The production CLI runs as root and has no
state- or open-receipt-directory override; a missing path, symlink, permission/owner drift or foreign
direct child fails before an executor is constructed. Offline fixtures may inject a temporary root
only through the internal executor constructor.

Before either plan or apply reads or decides any open journal stage, it obtains a nonblocking
exclusive kernel `flock` on the one global persistent
`/var/lib/cats/production-final-open/receipts/production-final-open.transaction.lock`. The lock is a
root-owned mode `0600`, empty, regular, single-link file opened descriptor-relative with
`O_NOFOLLOW`; first creation uses no-replace `O_CREAT|O_EXCL`, never truncates, and fsyncs the file
plus the already validated mode `0700` receipts directory. There is no temporary hard-link
publication window and no payload; the fixed path defines the scope across every `open_id`. The
process retains stable directory and lock descriptors plus their dev/inode for the whole plan/apply
call, including every forward-versus-cleanup decision, adapter/effect settlement and receipt
publication. It revalidates both descriptor/path identities, metadata and empty size before each
call/publication. A concurrent owner fails before reading a stale stage prefix or invoking an
adapter. Foreign bytes/metadata, unlink, rename/recreate or same-bytes ABA fail closed. Production
never deletes or replaces the lock, including after complete/aborted; after a process crash the
kernel releases the flock and the next process opens the same persistent inode. This local
serialization is not product admission or command outcome authority.

While holding that global lock, plan and apply scan every valid `open_id` journal in the canonical
`receipts/` directory. Foreign plan and dry-run receipts may coexist. Any foreign
started/forward/cleanup chain without a terminal `open-aborted`, or any foreign `open-complete`,
blocks before adapter calls. A foreign aborted chain is ignorable only when it contains no
finalizing/Open receipt and validates the complete dynamic cleanup journal: exact cleanup context,
the Ingress-close receipt, every context-listed Node cordon in reverse order, and one uninterrupted
digest chain from `cleanup-started` through mutation admission Closed, Fleet Closed and adjacent
`open-aborted`. Every receipt must bind the foreign immutable plan and authority. Missing, extra,
reordered or rebound cleanup stages fail closed. Apply repeats this arbitration immediately before
publishing its own `open-started`. The immutable plan binds the scan as the exact sorted
`prior_terminal_aborts` list of `{open_id, open_aborted_sha256}`. Apply requires its fresh scan to be
byte-semantically equal; an added, removed or changed abort invalidates the plan before effects.
Thus after an owner crash only the same `open_id` may exact-resume an active chain. A plan that
coexisted before another ID started remains stale after that transaction aborts; only a new ID/plan
that binds the terminal abort snapshot may proceed. Wall-clock timestamps are audit evidence, not
causal authorization, so clock rollback or same-millisecond creation cannot confuse the decision.
No new ID is allowed after completed Open.

Execution revalidates all terminal proof bindings, live Closed fleet and the exact signed Open
pending request before publishing `open-started`. The effects plan has exact
`public_probe_method: "GET"`, `public_probe_path: "/healthz"` and
`public_probe_admission_mode: "closed"`; it is not a Cat, Disk, Desired or WebSocket operation. The Control health handler
reads only the process readiness latch and remains valid while the PostgreSQL singleton is Closed.
A23 Node policy and reviewed Terraform Ingress also use their independent authorities, so they are
prepared and proved before product admission changes. The production Effects adapter remains
unavailable until it can bind this exact descriptor and invocation. Its ordered receipts are:

```text
open-started
node-<node_id>-schedulable       // sorted exact Node set
nodes-schedulable
public-ingress-open
public-probe-terminal
mutation-admission-open-finalizing
mutation-admission-open
open-complete
```

A23 effects and mutation-open use their canonical request IDs and exact bodies. Ambiguous HTTP or
process results retain/replay the same official request and discover the typed stored outcome;
never issue a new ID. Terraform applies only the exact reviewed saved plan and settles an ambiguous
response through refresh/show plus exact Kubernetes/AWS postcondition discovery.

Immediately before `mutation-admission-open-finalizing`, execution repeats typed admission-state
discovery and requires the exact planned Closed bytes/revision plus at least 30 seconds of command
lifetime. Expiry, foreign state or cancellation before that marker enters cleanup. The marker binds
the exact Open command ID, request SHA-256 and expected revision and is the forward-only boundary:
after it may have linked, signal handling propagates through the nested command resolver, but signal,
response loss, process crash and receipt-publication crash all continue settling only that exact
Open. Open is the final external effect; `mutation-admission-open` and `open-complete` are published
adjacently afterward. Product creation can begin only at the authoritative Control Open commit;
`open-complete` records that terminal transaction and is not a second admission gate.

Cancellation before `open-started` is mutation-free. Cancellation/failure after `open-started` but
before the finalizing marker invokes the closed cleanup sequence: apply the exact reviewed
ingress-close plan if Ingress may be open, re-cordon each possibly schedulable Node with new exact
A23 revisions/IDs, prove admission is still the exact planned Closed state, then obtain a fresh
empty-fleet/zero-guard receipt. Cleanup cannot close or claim a foreign command merely because it
installed the same Open binding. Cleanup is idempotent and journals every terminal result; inability
to prove cleanup exits nonzero and keeps incident ownership. After the finalizing marker cleanup and
EmergencyClose are forbidden; the same plan must forward-settle Open and publish `open-complete`.

## 6. Qualification contract

Offline fixtures must cover known-positive complete proof composition before trusting every
negative. Required negatives include missing/extra proof, duplicate JSON key, digest/size drift,
wrong release/source/reset/fresh target, provisional E9/G3/V3, provider-only fence, one V5 block
path, stale/ABA fleet session, nonzero guard/count, wrong STS principal, response loss after each
effect, crash before/after each receipt publication, exact replay, cancellation before start and
cleanup after every partial open stage. A true two-process barrier must hold one owner after durable
`open-started` plus Node/Ingress receipts, prove a second process with a different `open_id` performs
no forward or cleanup effect, kill the first owner, prove the foreign ID remains blocked by the
durable active chain, and prove only the original ID exact-resumes. Completed Open blocks the foreign
ID, while separate terminal-aborted cases reject a preplanned ID and admit only a new plan that binds
the exact abort-digest snapshot under clock rollback and same-millisecond clocks. Removing a bound
abort also invalidates that new plan before effects. A SIGKILL immediately after first lock
creation must leave one replayable empty single-link inode with no temporary hard link. Foreign
bytes/symlink/hardlink/mode drift and unlink/recreate same-byte lock ABA also fail before adapter
calls. Negative fixtures remove an Ingress or Node cleanup receipt and rebind a Node link to prove
that no later `open_id` can accept an incomplete foreign abort. Tests assert zero external mutation
before all terminal proofs validate and zero
uncordon/Ingress calls before `reset-complete` is verified.
