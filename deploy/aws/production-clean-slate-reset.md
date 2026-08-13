# Production clean-slate reset executor

[`production-clean-slate-reset.py`](production-clean-slate-reset.py) is the
reviewable destructive executor for the old-namespace retirement in
[Operations and HA §8](../../docs/operations-ha.md#8-首次终态部署). It does not provision,
deploy, rotate credentials, or access a production environment by itself.
`plan` is read-only. `apply` is also read-only unless `--execute` is supplied.

This is deliberately a **post-green** executor. The terminal release must
already be running from a disjoint fresh control/usage schema, ChunkStore
boundary, Kinesis stream, checkpoint table and immutable usage archive, and
must have passed the frozen qualification gates. Until `apply --execute`
publishes `reset-started`, operators may cancel retirement and retain the old
namespace. The tool never restores, imports or mutates the fresh namespace.

The executor never discovers or broadens a target. Every account, region, EKS
cluster, Kubernetes namespace, old and fresh dedicated PostgreSQL schema,
versioned S3 bucket/object prefix, Kinesis stream, DynamoDB checkpoint table
and usage archive bucket is required on every invocation. The old configured
ChunkStore prefix `cats-old` means the exact destructive S3 boundary
`cats-old/`; it does not match `cats-old-2/` or a key named exactly `cats-old`.
The verified STS caller account and the `--aws-account-id` input must match, and
that same 12-digit account is supplied as S3 `--expected-bucket-owner` on every
bucket read, inventory, delete, multipart abort and post-delete verification.
An identically named input that resolves outside the approved account therefore
fails before an S3 response can authorize a mutation.

## Reviewed maintenance transition

Set `maintenance_mode = true` in the production-application stack and review a
saved Terraform plan before applying it. This records the old deployment stop:

- removes the Cats public Ingress, IngressClass/parameters and Route 53 aliases;
- labels the namespace ingress boundary disabled; and
- scales `cats-controld` to zero replicas, relaxes its PDB to zero, and suspends
  the credential-refresher CronJob.

The default is `false`, so adding the variable does not alter an existing
deployment. Do not substitute `kubectl delete ingress` or an unrecorded scale
operation. After the independent positive stop/fence proof, update the reviewed
production inputs to the **fresh** resource names and exact release, then set
`maintenance_mode = false` in another saved plan to start only that fresh
deployment. Keep the independent `enable_public_ingress = false`; both the
module and production stack default it to false. Starting Control replicas must
not publish ingress or manufacture route/mutation admission. Do not point new
components at the old schemas, prefixes, stream or checkpoint table.

The reset executor runs only after the fresh deployment is green. It compares
the kubeconfig context server with the named EKS cluster and requires at least
two fully available `cats-controld` replicas, exactly that many Running/Ready
Pods, the namespace label `cats.run/ingress=disabled`, and zero Cats public
Ingress or IngressClass resources. Thus neither a maintenance configuration
still at zero replicas nor a prematurely public rollout can authorize even the
read-only reset preflight. The cross-component route/mutation Closed verifier is
not defined by E2; production execute remains mechanically blocked until its
canonical proof is accepted.

## Post-green evidence

The independent maintenance actor supplies a small, non-secret JSON document
after the fresh release passes qualification. It binds the exact fresh targets,
Git commit, independent artifact digest and a placeholder old-writer declaration
to an external evidence manifest; it does not embed logs, tokens, object keys,
headers, private keys or database URLs. Until E13's canonical parser lands,
neither the declaration nor its digest authorizes production execution.

```json
{
  "kind": "cats.production-fresh-namespace-green.v1",
  "version": 1,
  "reset_id": "REPLACE_WITH_UNIQUE_RESET_ID",
  "observed_at": "2026-08-13T00:00:00Z",
  "qualified_release_commit": "REPLACE_WITH_40_LOWERCASE_HEX_GIT_COMMIT",
  "qualified_artifact_sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
  "aws_account_id": "123456789012",
  "aws_region": "us-east-1",
  "eks_cluster_name": "REPLACE_WITH_EXACT_CLUSTER",
  "kubernetes_namespace": "cats",
  "fresh_targets": {
    "control_schema": "cats_control_fresh",
    "usage_schema": "cats_usage_fresh",
    "chunkstore_bucket": "REPLACE_WITH_FRESH_VERSIONED_BUCKET",
    "chunkstore_object_prefix": "cats-fresh/",
    "usage_kinesis_stream": "REPLACE_WITH_FRESH_STREAM",
    "usage_checkpoint_table": "REPLACE_WITH_FRESH_TABLE",
    "usage_archive_bucket": "REPLACE_WITH_FRESH_OBJECT_LOCK_ARCHIVE"
  },
  "qualification": "passed",
  "qualification_manifest_sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
  "old_writers": {
    "gateway": "stopped_or_isolated",
    "controller": "stopped_or_isolated",
    "node_agent": "stopped_or_isolated",
    "vmm": "stopped_or_isolated",
    "blockd": "stopped_or_isolated"
  }
}
```

`reset_id` must equal the invocation exactly. At `plan` and the first `apply`,
`observed_at` must not be in the future and must be no more than 900 seconds
old. A plan outside that closed window requires newly observed evidence and a
new review; a different reset can never reuse the document.

No accepted canonical E13 proof format exists yet. The `old_writers` strings
and arbitrary manifest digest above are only closed declarations; this executor
does not turn them into shutdown authority. This exact binary mechanically
blocks every production `--execute` before any AWS or PostgreSQL call. A future
reviewed change may remove that block only after E13 defines a canonical,
parseable positive systemd/process-tree stop result and external isolation
receipt. A self-written document or this repository's offline fixture is not
positive shutdown evidence.

## Database and credential boundary

Supply all four old/fresh PostgreSQL URLs only through absolute single-link
`0600` files. Each URL
must enable TLS. It is translated into a transient single-purpose `0600` libpq
service file and selected by its non-secret path; the URL is never placed in
argv, stdout, stderr, an environment variable, or a receipt.

All old/fresh targets must be dedicated lowercase `cats_*` schemas, must be
pairwise distinct and must carry their canonical marker. The destructive actor
must own the two old schemas. Fresh credentials are read-only inventory
credentials and are not required to own either fresh schema:

- control: `control_schema_version`;
- usage/billing: `schema_migrations`.

There is deliberately no override for `public`, `pg_catalog`,
`information_schema`, or an arbitrary shared schema. Old schema-1 data in
`public` is **not** a deletion target. Leave it retained until a separate
reviewed exact table-level retirement proves its closed table/dependency set;
do not weaken this guard or point the tool at the entire database. This
executor drops only the two explicitly named old dedicated schemas and leaves
their RDS databases/instances intact.

## Fresh namespace and usage retirement

The executor proves old/fresh schemas, stream names, checkpoint table names and
usage archive buckets are distinct. ChunkStore prefixes must not overlap when
they share a bucket. It independently verifies both old and fresh resource
identities and inventories; the fresh control schema must be terminal schema
version 14.

Deleting the old Kinesis stream/table additionally requires a signed final
usage epoch/barrier receipt from E9. No accepted canonical format exists yet,
so this exact binary mechanically blocks production `--execute` before any
destructive stage. It does not infer a final epoch from an empty stream, table,
schema, digest or operator string. Once a later reviewed implementation accepts
that authority, the fresh stream/table remain live and both immutable
Object-Locked usage archives remain retained evidence.

## Read-only plan and dry-run

Create a private receipt directory outside the checkout. Substitute only
reviewed exact values:

```sh
python3 deploy/aws/production-clean-slate-reset.py plan \
  --reset-id REPLACE_WITH_UNIQUE_RESET_ID \
  --release-commit REPLACE_WITH_40_LOWERCASE_HEX_GIT_COMMIT \
  --artifact-sha256 REPLACE_WITH_64_LOWERCASE_HEX \
  --aws-account-id REPLACE_WITH_12_DIGITS \
  --aws-region us-east-1 \
  --eks-cluster-name REPLACE_WITH_EXACT_CLUSTER \
  --kubernetes-namespace cats \
  --kubeconfig /absolute/private/path/kubeconfig \
  --kube-context REPLACE_WITH_EXACT_CONTEXT \
  --old-control-postgres-url-file /absolute/private/path/old-control.url \
  --old-control-schema cats_control_old \
  --old-usage-postgres-url-file /absolute/private/path/old-usage.url \
  --old-usage-schema cats_usage_old \
  --old-chunkstore-bucket REPLACE_WITH_OLD_VERSIONED_BUCKET \
  --old-chunkstore-prefix cats-old \
  --old-usage-kinesis-stream REPLACE_WITH_OLD_STREAM \
  --old-usage-checkpoint-table REPLACE_WITH_OLD_TABLE \
  --old-usage-archive-bucket REPLACE_WITH_OLD_OBJECT_LOCK_ARCHIVE \
  --fresh-control-postgres-url-file /absolute/private/path/fresh-control.url \
  --fresh-control-schema cats_control_fresh \
  --fresh-usage-postgres-url-file /absolute/private/path/fresh-usage.url \
  --fresh-usage-schema cats_usage_fresh \
  --fresh-chunkstore-bucket REPLACE_WITH_FRESH_VERSIONED_BUCKET \
  --fresh-chunkstore-prefix cats-fresh \
  --fresh-usage-kinesis-stream REPLACE_WITH_FRESH_STREAM \
  --fresh-usage-checkpoint-table REPLACE_WITH_FRESH_TABLE \
  --fresh-usage-archive-bucket REPLACE_WITH_FRESH_OBJECT_LOCK_ARCHIVE \
  --post-green-evidence-file /absolute/evidence/post-green.json \
  --receipt-directory /absolute/private/path/reset-receipts
```

The command writes canonical `<reset-id>.plan.json` and its SHA-256 sidecar.
Independently review the exact targets, inventory counts/digests, schema
versions, post-green evidence digest, retained resources and destructive
actions. The plan, `reset-started`, every stage receipt and `reset-complete`
all carry the same exact reset ID, plan digest, stable-preflight digest,
40-hex Git commit, independent artifact SHA-256, targets and post-green evidence
digest.

Run `apply` with the same common arguments plus the plan path, its independently
read SHA-256 and the reset ID. Omitting `--execute` performs a second read-only
preflight and writes a `dry-run` receipt:

```sh
python3 deploy/aws/production-clean-slate-reset.py apply \
  REPEAT_EVERY_COMMON_ARGUMENT_FROM_THE_PLAN \
  --plan-receipt /absolute/private/path/reset-receipts/RESET_ID.plan.json \
  --plan-sha256 REPLACE_WITH_REVIEWED_PLAN_SHA256 \
  --confirm-reset-id REPLACE_WITH_THE_SAME_RESET_ID
```

Before `reset-started`, any change to the EKS rollout, old or fresh
schema/S3/usage inventory, or post-green evidence invalidates the plan. Generate
and review a new plan; never edit a receipt.

## Execute and receipts

Production execution is intentionally unavailable in this binary. E13 positive
stop/isolation, E9 signed final usage epoch/barrier and the cross-component
Closed route/mutation admission proof have no accepted canonical formats. Each
is a separate mechanical pre-start block, evaluated before AWS or PostgreSQL
access. `plan`, dry-run and the offline fake fixture remain available; no digest
or declaration bypasses these blocks. Removing a block belongs to the branch
that lands its accepted proof parser and calibrated negative fixtures.

Only the independent maintenance actor has the narrow delete/drop permissions.
Add `--execute` to the already reviewed `apply` invocation. Before the first
mutation the executor atomically publishes an immutable
`reset-started` receipt. From that point onward operators must assume the old
namespace retirement boundary was crossed and use fresh-release forward-fix
only, even if the process exits before a later receipt.

The executor then:

1. lists all old-prefix S3 versions and delete markers with explicit
   key/version markers;
2. deletes exact versions in batches of at most 1000;
3. lists and aborts every multipart upload with explicit pagination;
4. proves zero versions, zero delete markers, zero multipart uploads and zero
   current objects under the exact old prefix;
5. deletes the exact old Kinesis stream and DynamoDB checkpoint table and waits
   for authoritative nonexistence;
6. drops the exact old control schema, then proves it absent and publishes its
   stage receipt;
7. drops the exact old usage/billing schema, then proves it absent and publishes
   its separate stage receipt; and
8. publishes the canonical `reset-complete` receipt and SHA-256 sidecar.

Each canonical JSON file is the single immutable receipt authority. Its
`.sha256` is derived, not a second authority: if publication crashes after the
JSON no-replace link/fsync, replay verifies the exact canonical JSON bytes and
atomically creates only the missing sidecar. A sidecar without JSON, a mismatched
sidecar or different JSON bytes fails closed. Receipts contain counts, hashes
and non-secret identities, never object keys or DSNs.
Publish them through the existing append-only evidence boundary after
independent verification. The qualified fresh components remain running; only
after the final receipt is verified may a separately reviewed change retire old
credentials or other exact old resources that are outside this executor.

### Closed forward-resume

If the process exits after `reset-started`, invoke the same `apply --execute`
with the same reviewed plan, SHA, reset ID, targets, release and unchanged
post-green evidence file. Do not generate a replacement plan. Resume verifies
the canonical receipt/SHA chain and the live fresh namespace first. Evidence
freshness is rechecked against the immutable `reset-started.created_at`, where
it was already required to be at most 900 seconds old, so a long-running
forward repair does not require changing its digest.

For each missing stage the executor discovers the exact live postcondition. It
deletes only remaining old-prefix versions/uploads, treats only the service's
exact `ResourceNotFoundException` as an absent Kinesis stream/table, and checks
schema presence before an exact identity-bound drop. A successful effect whose
response or receipt was lost is therefore settled without repeating that
effect. An existing stage is re-proved live; a contradictory resource, receipt
gap, checksum drift, predecessor drift, a later physical effect ahead of the
receipt chain, changed evidence or another plan fails closed. Replaying an
exact `reset-complete` performs read-only identity and
postcondition checks and returns the original receipt without mutation.

Before `reset-started`, cancel retirement by omitting `--execute` and retaining
the entire old namespace. Any decision to abandon the fresh release must first
stop its writers and use a separately reviewed rollback; old and fresh writers
must never overlap. At or after `reset-started`, the conservative boundary is
crossed: do not restore the old deployment, import old data or recreate old
credentials; repair the same terminal release forward.
