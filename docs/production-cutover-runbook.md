# Production clean-slate cutover runbook

This is the single operator sequence for the first terminal release described by
[Operations and HA §8](operations-ha.md#8-首次终态部署). It composes existing repository
entrypoints; it does not introduce another migration, reset authority, rollback protocol or ADR.

<!-- cutover-stage: 00-current-blocker -->

## Current verdict: HOLD before destructive reset and public opening

As of this runbook's release, production `production-clean-slate-reset.py apply --execute` is
mechanically blocked before any AWS or PostgreSQL call. All three independent prerequisites remain
open:

1. E13 positive stop/isolation is still a **Proposed**, non-authoritative format;
2. E9 has no accepted signed final usage epoch/barrier receipt consumed by reset; and
3. there is no accepted canonical cross-component proof that route and mutation admission are
   Closed.

These are explicit `DEFERRED` inputs, not operator-discretion checks. A
successful E13 run, an E3 `usage-final-terminal-receipt` qualification case, an empty stream, an
operator-written digest or `enable_public_ingress=false` does not satisfy them. Do not patch,
replace or bypass the reset binary. Consequently this runbook has two explicit stages. The
currently executable closed-candidate stage is:

- prepare and qualify the exact release;
- enter maintenance and retain the old namespace;
- create a fresh Control schema and fresh ChunkStore prefix, while reusing the explicitly reviewed
  current Usage schema/stream/table/archive for this no-user candidate;
- provision cordoned Nodes, run E12 and E3, and retain all evidence;
- stop after the final gates with ingress Closed and Nodes cordoned.

The second stage begins with final Usage closure/fresh targets and reset. Destructive retirement,
mutation opening, Node uncordon, public ingress and creation of new product resources remain held.
The reset blocker is repeated at that phase so it cannot be missed when operators follow the
document sequentially. It does not prevent the closed first deployment or its internal E3 test.

## Fixed notation and safety rules

Replace every angle-bracket token with one reviewed literal before a command is copied. In
particular, `<FINAL_RELEASE_SHA>` is the final clean 40-lowercase-hex release commit, not an
intermediate integration SHA, branch or tag. The following paths are examples of the required
absolute, private locations and must be created outside the checkout:

- `/approved/cutover/<CUTOVER_ID>/` — operator inputs, saved Terraform plans and non-secret
  manifests;
- `/approved/evidence/<CUTOVER_ID>/` — mode-0700 evidence root;
- `/approved/secrets/<CUTOVER_ID>/` — mode-0700 secret root; secret files are mode 0600 and are
  never copied into evidence;
- `/approved/release/<FINAL_RELEASE_SHA>/` — exact immutable release artifacts.

Before the window, review and freeze the literal AWS account, partition, region, EKS cluster,
Kubernetes context/namespace, old/fresh Control schemas, old/fresh ChunkStore prefixes, the current
Usage schema/stream/table/archive reused only by the closed candidate, expected Node IDs and
immutable Host IDs. The later final-reset stage additionally freezes a disjoint fresh Usage target.
A destructive target must never come from a wildcard, directory scan, prefix abbreviation, default
account, current shell directory or unresolved environment value. The reset invocation repeats
every literal old and fresh target and revalidates them immediately before any effect.

This runbook deliberately contains no broad deletion command. Do not substitute a recursive
filesystem deletion, a whole bucket removal, a namespace deletion, a database/schema-wide manual
SQL retirement or a Terraform teardown for the exact reset executor. Never point reset at
`public`, a shared schema, a whole database, an unversioned bucket or an overlapping prefix.

Every step below has four fields:

- **Assert first**: a condition that must already be true;
- **Command**: an existing repository or provider entrypoint;
- **Retain**: the evidence path that becomes input to later review;
- **Cancel point**: the last safe operator action if the step does not close.

Until the immutable `reset-started` receipt exists, cancellation means leaving the old namespace
intact and keeping ingress/mutation Closed. Abandoning the fresh release additionally requires a
separately reviewed stop/rollback of its writers; there is no implicit restart of old writers in
this runbook.

## Stage A — closed candidate and internal qualification (executable)

This stage ends after phase 8. Normal product mutation remains Closed. Public ingress remains
disabled and all Nodes remain cordoned except for each explicitly approved, bounded E3
qualification window in phase 7: that window makes exactly one qualification Node schedulable and
opens ingress only long enough to exercise its run-bound Endpoint. The saved close plan and exact
A23 re-cordon apply run after either success or failure; Stage A cannot finish in the temporary
state.

## 0. Freeze and qualify the exact release before the window

**Assert first.** The release checkout is clean, `HEAD` is the reviewed final commit, and its source
bundle/build receipt will be used unchanged by Control, Gateway, Node, Guest and the metal driver.

**Command — source provenance and controller publication:**

```sh
mkdir -m 0700 /approved/evidence/<CUTOVER_ID>
./scripts/quality.sh provenance \
  > /approved/evidence/<CUTOVER_ID>/source-provenance.txt

bash deploy/aws/terraform/qualification/build-host/tools/publish-source-bundle.sh \
  <QUALIFICATION_AWS_ACCOUNT_ID> \
  /trusted/clean/cats \
  <FINAL_RELEASE_SHA> \
  <QUALIFICATION_SOURCE_BUCKET> \
  <QUALIFICATION_SOURCE_KMS_ALIAS_ARN> \
  /approved/private-work/<CUTOVER_ID> \
  /approved/evidence/<CUTOVER_ID>/source-bundle.json
```

Verify that `source.head=<FINAL_RELEASE_SHA>` and `source.dirty=false`. On the registered native
x86_64 Linux build Host, use only the three immutable identifiers emitted above:

```sh
cats-checkout-exact-sha \
  <FINAL_RELEASE_SHA> <SOURCE_MANIFEST_SHA256> <SOURCE_BUNDLE_SHA256>

cats-run-build \
  <FINAL_RELEASE_SHA> <SOURCE_MANIFEST_SHA256> <SOURCE_BUNDLE_SHA256> \
  --with-postgres -- /bin/bash -c \
  'set -o pipefail
   ./scripts/quality.sh full 2>&1 |
     tee "$CATS_BUILD_OUTPUT_DIR/quality-full.log"'

cats-publish-content-addressed evidence \
  /srv/cats-build/target/<FINAL_RELEASE_SHA>-<SOURCE_MANIFEST_SHA256>-<SOURCE_BUNDLE_SHA256>/<QUALIFICATION_JOB_ID>/output/quality-full.log
```

Take `<QUALIFICATION_JOB_ID>` from the successful Host-local immutable build receipt. Run the
publisher only after `cats-run-build` returns zero and freezes that exact root-owned job output;
never select a job by recency or publish a still-running log.

On the approved native x86_64 release builder, build the two digest-pinned images and worker
bundle from the same clean checkout:

```sh
deploy/aws/tools/build-manual-release.sh \
  --source-sha <FINAL_RELEASE_SHA> \
  --output /approved/release/<FINAL_RELEASE_SHA> \
  --image <CONTROL_ECR_REPOSITORY>:<CUTOVER_ID> \
  --gateway-image <GATEWAY_ECR_REPOSITORY>:<CUTOVER_ID> \
  --push
```

The builder's `release-manifest.v1.json` is the artifact authority. Confirm that it binds
`<FINAL_RELEASE_SHA>`, the independently observed registry digests and the worker bundle digest;
do not rebuild after credentials or fresh targets are selected.

**Retain.** `source-provenance.txt`, `source-bundle.json`, the Host-local build receipt, its
content-addressed publication receipt, `release-manifest.v1.json`, both registry digests and the
worker bundle digest under `/approved/evidence/<CUTOVER_ID>/00-release/`.

**Cancel point.** No production state has changed. Stop on a dirty source, digest mismatch, failed
native `full`, missing immutable receipt or unavailable qualified metal Host.

<!-- cutover-stage: 10-maintenance-ingress-closed -->

## 1. Enter maintenance; close ingress and stop old application writers

**Assert first.** The reviewed application tfvars set `maintenance_mode=true` and
`enable_public_ingress=false`. The saved plan must target the exact existing production backend and
must remove public ingress/DNS while scaling both Terraform-owned application Deployments to zero.
Do not replace this transition with imperative Kubernetes edits.

**Command:**

```sh
terraform -chdir=deploy/aws/terraform/stacks/production-application init \
  -backend-config=/approved/cutover/<CUTOVER_ID>/old-application.backend.hcl

terraform -chdir=deploy/aws/terraform/stacks/production-application plan \
  -input=false \
  -var-file=/approved/cutover/<CUTOVER_ID>/maintenance.tfvars \
  -out=/approved/cutover/<CUTOVER_ID>/maintenance.tfplan

terraform -chdir=deploy/aws/terraform/stacks/production-application show \
  -json /approved/cutover/<CUTOVER_ID>/maintenance.tfplan \
  > /approved/evidence/<CUTOVER_ID>/10-maintenance-plan.json

terraform -chdir=deploy/aws/terraform/stacks/production-application apply \
  -input=false /approved/cutover/<CUTOVER_ID>/maintenance.tfplan \
  > /approved/evidence/<CUTOVER_ID>/10-maintenance-apply.txt

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> get namespace cats -o json \
  > /approved/evidence/<CUTOVER_ID>/10-namespace.json

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> --namespace cats \
  get deployments -l app.kubernetes.io/part-of=cats -o json \
  > /approved/evidence/<CUTOVER_ID>/10-deployments.json

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> --namespace cats \
  get ingresses -l app.kubernetes.io/part-of=cats -o json \
  > /approved/evidence/<CUTOVER_ID>/10-ingresses.json

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> \
  get ingressclasses -l app.kubernetes.io/part-of=cats -o json \
  > /approved/evidence/<CUTOVER_ID>/10-ingressclasses.json

jq -e '.metadata.name == "cats" and .metadata.labels["cats.run/ingress"] == "disabled"' \
  /approved/evidence/<CUTOVER_ID>/10-namespace.json
jq -e 'all(.items[]; .spec.replicas == 0)' \
  /approved/evidence/<CUTOVER_ID>/10-deployments.json
jq -e '.items == []' /approved/evidence/<CUTOVER_ID>/10-ingresses.json
jq -e '.items == []' /approved/evidence/<CUTOVER_ID>/10-ingressclasses.json
```

The successful namespace and Deployment reads calibrate the Kubernetes probe before the two empty
resource assertions are trusted. This proves the Terraform ingress boundary and old Kubernetes
application stop only; it is not the missing cross-component Closed-admission receipt.

**Retain.** The reviewed saved plan, plan JSON, apply transcript and four Kubernetes projections
shown above.

**Cancel point.** Keep maintenance enabled and all ingress Closed. Do not restore an old writer or
continue to fresh startup until the old-Host step below has a receipt for every inventory Host.

## 2. Positively stop or externally isolate every old Host

**Assert first.** The exact bundle's `old-host-positive-stop.py` is staged read-only; the canonical
inventory covers the closed component set `blockd, controller, gateway, node_agent, vmm` on every
old Host. Local Hosts are already cordoned and idle. A Host with a live VMM/blockd or unique
Relaxed `R < L` data must not be stopped by this tool.

**Command — review and local positive stop (repeat with a literal Host and attempt):**

```sh
chmod 0600 /approved/evidence/<CUTOVER_ID>/20-e13/old-host-inventory.v1.json
python3 /approved/staged-worker/old-host-positive-stop.py verify --help
sha256sum /approved/evidence/<CUTOVER_ID>/20-e13/old-host-inventory.v1.json

sudo python3 /approved/staged-worker/old-host-positive-stop.py local-stop \
  --inventory /approved/evidence/<CUTOVER_ID>/20-e13/old-host-inventory.v1.json \
  --host-id <EXACT_OLD_HOST_ID> \
  --output /approved/evidence/<CUTOVER_ID>/20-e13/<EXACT_OLD_HOST_ID>.json \
  --deadline-seconds 60 \
  --stable-read-seconds 2 \
  --confirm-attempt-id <E13_ATTEMPT_ID> \
  --execute
```

For an unreachable EC2 Host, run the repository's external isolation mode from the maintenance
actor, never from that Host:

```sh
python3 /approved/staged-worker/old-host-positive-stop.py ec2-isolate \
  --inventory /approved/evidence/<CUTOVER_ID>/20-e13/old-host-inventory.v1.json \
  --host-id <EXACT_OLD_HOST_ID> \
  --output /approved/evidence/<CUTOVER_ID>/20-e13/<EXACT_OLD_HOST_ID>.json \
  --deadline-seconds 120 \
  --stable-read-seconds 2 \
  --confirm-attempt-id <E13_ATTEMPT_ID> \
  --execute
```

After every Host receipt exists, supply exactly one `--receipt` per inventory Host:

```sh
python3 /approved/staged-worker/old-host-positive-stop.py verify \
  --inventory /approved/evidence/<CUTOVER_ID>/20-e13/old-host-inventory.v1.json \
  --receipt /approved/evidence/<CUTOVER_ID>/20-e13/<OLD_HOST_1>.json \
  --receipt /approved/evidence/<CUTOVER_ID>/20-e13/<OLD_HOST_2>.json \
  --output /approved/evidence/<CUTOVER_ID>/20-e13/evidence-set.v1.json
```

Add or remove repeated receipt arguments to match the reviewed inventory exactly. Do not interpret
this Proposed evidence set as reset authority or an ADR-0040 `HostFenceEvent`.

**Retain.** Inventory, intent, every Host JSON/sidecar, aggregate evidence set/sidecar, exact tool
digest and operator-session manifest under `20-e13/`.

**Cancel point.** If any exact postcondition is unknown, preserve its intent/receipt directory and
keep all writers Closed. Do not repeat an ambiguous physical effect with a new target or stop a raw
runtime process to make the probe pass.

<!-- cutover-stage: 20-fresh-targets -->

## 3. Select the fresh Control schema and ChunkStore prefix

**Assert first.** Old writers have the retained evidence above. For the authorized closed
candidate, reuse the current Usage PostgreSQL schema, Kinesis stream, DynamoDB checkpoint table and
immutable archive unchanged because there are no users. This phase neither provisions fresh Usage
infrastructure nor turns deletable old Usage data into a final epoch/barrier. Record those four
exact current names. The Control schema and ChunkStore prefix must be fresh and disjoint from their
old counterparts.

Calibrate AWS identity and bucket versioning before trusting the empty-prefix result, then inventory
the exact prefix with the same owner binding used by the reset executor:

```sh
aws sts get-caller-identity --output json \
  > /approved/evidence/<CUTOVER_ID>/30-aws-caller.json
jq -e '.Account == "<PRODUCTION_12_DIGIT_ACCOUNT_ID>"' \
  /approved/evidence/<CUTOVER_ID>/30-aws-caller.json

aws s3api get-bucket-versioning \
  --bucket <VERSIONED_CHUNKSTORE_BUCKET> \
  --expected-bucket-owner <PRODUCTION_12_DIGIT_ACCOUNT_ID> \
  --output json \
  > /approved/evidence/<CUTOVER_ID>/30-chunkstore-versioning.json
jq -e '.Status == "Enabled"' \
  /approved/evidence/<CUTOVER_ID>/30-chunkstore-versioning.json

aws s3api list-objects-v2 \
  --bucket <VERSIONED_CHUNKSTORE_BUCKET> \
  --prefix <FRESH_EXACT_CHUNKSTORE_PREFIX>/ \
  --expected-bucket-owner <PRODUCTION_12_DIGIT_ACCOUNT_ID> \
  --output json \
  > /approved/evidence/<CUTOVER_ID>/30-fresh-prefix-current.json

aws s3api list-object-versions \
  --bucket <VERSIONED_CHUNKSTORE_BUCKET> \
  --prefix <FRESH_EXACT_CHUNKSTORE_PREFIX>/ \
  --expected-bucket-owner <PRODUCTION_12_DIGIT_ACCOUNT_ID> \
  --output json \
  > /approved/evidence/<CUTOVER_ID>/30-fresh-prefix-versions.json

aws s3api list-multipart-uploads \
  --bucket <VERSIONED_CHUNKSTORE_BUCKET> \
  --prefix <FRESH_EXACT_CHUNKSTORE_PREFIX>/ \
  --expected-bucket-owner <PRODUCTION_12_DIGIT_ACCOUNT_ID> \
  --output json \
  > /approved/evidence/<CUTOVER_ID>/30-fresh-prefix-uploads.json

jq -e '(.Contents // []) == []' \
  /approved/evidence/<CUTOVER_ID>/30-fresh-prefix-current.json
jq -e '(.Versions // []) == [] and (.DeleteMarkers // []) == []' \
  /approved/evidence/<CUTOVER_ID>/30-fresh-prefix-versions.json
jq -e '(.Uploads // []) == []' \
  /approved/evidence/<CUTOVER_ID>/30-fresh-prefix-uploads.json
```

Create only the reviewed empty Control schema. `run-postgres-probe.sh` is the existing bounded
single-query runner and uses the stopped application's `cats-runtime` database credential. The
first query is both a positive database identity control and the absence check:

```sh
deploy/aws/run-postgres-probe.sh \
  /approved/cutover/<CUTOVER_ID>/production.kubeconfig cats \
  cutover-<CUTOVER_ID>-control-before \
  "SELECT current_database() || '|' || current_user || '|' || COALESCE(to_regnamespace('<FRESH_CONTROL_SCHEMA>')::text, 'ABSENT')" \
  > /approved/evidence/<CUTOVER_ID>/30-control-schema-before.txt

deploy/aws/run-postgres-probe.sh \
  /approved/cutover/<CUTOVER_ID>/production.kubeconfig cats \
  cutover-<CUTOVER_ID>-control-create \
  "CREATE SCHEMA <FRESH_CONTROL_SCHEMA> AUTHORIZATION <FRESH_CONTROL_DATABASE_ROLE>" \
  > /approved/evidence/<CUTOVER_ID>/30-control-schema-create.txt

deploy/aws/run-postgres-probe.sh \
  /approved/cutover/<CUTOVER_ID>/production.kubeconfig cats \
  cutover-<CUTOVER_ID>-control-after \
  "SELECT n.nspname || '|' || pg_get_userbyid(n.nspowner) FROM pg_namespace n WHERE n.nspname = '<FRESH_CONTROL_SCHEMA>'" \
  > /approved/evidence/<CUTOVER_ID>/30-control-schema-after.txt
```

The operator must review the first line as
`<EXPECTED_DATABASE>|<EXPECTED_ROLE>|ABSENT`, the mutation output as `CREATE SCHEMA`, and the final
line as `<FRESH_CONTROL_SCHEMA>|<FRESH_CONTROL_DATABASE_ROLE>`. This SQL is a declared production
mutation, not a provisioner route; it creates one previously absent schema and performs no
retirement. The exact release will install the complete schema-15 catalog and stamp atomically on
its first Control connection. The application plan must preserve the current Usage target
byte-for-byte while selecting this fresh Control schema and prefix.

**Retain.** Caller/bucket identity, all bounded prefix inventories, the four literal current Usage
targets and all three PostgreSQL probe outputs under `30-fresh-targets/`.

**Cancel point.** Before `reset-started`, the fresh schema/prefix may remain unused while the old
namespace and current Usage authority are retained. Do not repoint them to old names, import old
rows/objects or manually empty a target that failed the initial absence check.

<!-- cutover-stage: 30-exact-release-credentials -->

## 4. Generate fresh credentials and bind the exact release

**Assert first.** Use the staged `cats` binary from `<FINAL_RELEASE_SHA>`. All credential output
directories are new mode-0700 directories. Kubernetes Secret names and the Secrets Manager name
are fresh, end in `-r1`, and are the exact names in the forthcoming Terraform plan. Every reviewed
Node private DNS name is listed once. Service, per-Node, database and object-store credentials that
are not generated by the commands below must arrive through the approved secret authority as
`DEFERRED(<FRESH_SERVICE_CREDENTIAL_INPUT>)`; absence of that input stops this phase and is never
replaced by an operator-chosen random string.

**Command — A23 revision-one provisioner trust:**

```sh
umask 077
/approved/staged-worker/cats --json \
  admin runtime-provisioner trust generate \
  --deployment-id <FRESH_DEPLOYMENT_ID> \
  --credential-id <FRESH_PROVISIONER_CREDENTIAL_ID> \
  --private-key-out /approved/secrets/<CUTOVER_ID>/runtime-provisioner-key.pem \
  --trust-bundle-out /approved/cutover/<CUTOVER_ID>/runtime-provisioner-trust.v1.json

/approved/staged-worker/cats --json \
  admin runtime-provisioner trust verify \
  --credential-id <FRESH_PROVISIONER_CREDENTIAL_ID> \
  --private-key /approved/secrets/<CUTOVER_ID>/runtime-provisioner-key.pem \
  --trust-bundle /approved/cutover/<CUTOVER_ID>/runtime-provisioner-trust.v1.json \
  > /approved/evidence/<CUTOVER_ID>/40-a23-trust-receipt.json
```

**Command — fresh Route v2 revision one:**

```sh
sudo /approved/staged-worker/cats --json \
  admin runtime-provisioner route-v2-r1 generate \
  --output /approved/secrets/<CUTOVER_ID>/route-v2-r1 \
  --node-server-dns <NODE_1_PRIVATE_DNS> \
  --node-server-dns <NODE_2_PRIVATE_DNS> \
  --control-secret-name <FRESH_CONTROL_ROUTE_SECRET_NAME_R1> \
  --gateway-secret-name <FRESH_GATEWAY_ROUTE_SECRET_NAME_R1> \
  --node-secret-name cats-<CURRENT_INFRASTRUCTURE_ENVIRONMENT>-route-v2-node-r1 \
  --release-commit-sha <EXACT_RELEASE_COMMIT_SHA> \
  --openssl /usr/bin/openssl

sudo /approved/staged-worker/cats --json \
  admin runtime-provisioner route-v2-r1 verify \
  --input /approved/secrets/<CUTOVER_ID>/route-v2-r1 \
  --node-server-dns <NODE_1_PRIVATE_DNS> \
  --node-server-dns <NODE_2_PRIVATE_DNS> \
  --control-secret-name <FRESH_CONTROL_ROUTE_SECRET_NAME_R1> \
  --gateway-secret-name <FRESH_GATEWAY_ROUTE_SECRET_NAME_R1> \
  --node-secret-name cats-<CURRENT_INFRASTRUCTURE_ENVIRONMENT>-route-v2-node-r1 \
  --release-commit-sha <EXACT_RELEASE_COMMIT_SHA> \
  > /approved/evidence/<CUTOVER_ID>/40-route-v2-verify.json

sudo /approved/staged-worker/cats-route-v2-node-r1-validator \
  --directory /approved/secrets/<CUTOVER_ID>/route-v2-r1/node \
  > /approved/evidence/<CUTOVER_ID>/40-route-v2-node-validate.txt

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> create \
  --filename /approved/secrets/<CUTOVER_ID>/route-v2-r1/provider/control-secret.v1.json

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> create \
  --filename /approved/secrets/<CUTOVER_ID>/route-v2-r1/provider/gateway-secret.v1.json

aws secretsmanager create-secret \
  --cli-input-json file:///approved/secrets/<CUTOVER_ID>/route-v2-r1/provider/node-secret.v1.json \
  > /approved/evidence/<CUTOVER_ID>/40-route-v2-node-secret-result.json
```

Record the returned exact Node Secret ARN and version ID without copying SecretString. Do not use
the old Secret name, version, credential ID, SPKI or private bytes.

**Retain.** Public A23 trust receipt, non-secret Route v2 verification receipts, Kubernetes Secret
metadata (never decoded data), Node Secret ARN/version and the exact release manifest under
`40-credentials/`. Keep every private key/provider JSON only under the secret root.

**Cancel point.** Fresh credentials may remain unpublished or unused. Do not replace an existing
immutable Secret, reuse an old key lineage or start any component if a required fresh credential is
still `DEFERRED`.

<!-- cutover-stage: 40-cordoned-nodes -->

## 5. Start fresh Control/Gateway Closed and provision cordoned Nodes

**Assert first.** The reviewed application tfvars select only the fresh Control schema (through the
exact storage DSN search path), fresh ChunkStore prefix, fresh Route v2 Secret names and exact image
digests while preserving the four reviewed current Usage targets unchanged. They set `maintenance_mode=false`,
`enable_public_ingress=false`, and at least two Control and Gateway replicas. The A23 trust bundle
is exact revision 1. Every initial Node policy is revision 1 and `cordoned`.

**Command — reviewed fresh application transition:**

```sh
terraform -chdir=deploy/aws/terraform/stacks/production-application plan \
  -input=false \
  -var-file=/approved/cutover/<CUTOVER_ID>/fresh-application.tfvars \
  -out=/approved/cutover/<CUTOVER_ID>/fresh-application.tfplan

terraform -chdir=deploy/aws/terraform/stacks/production-application show \
  -json /approved/cutover/<CUTOVER_ID>/fresh-application.tfplan \
  > /approved/evidence/<CUTOVER_ID>/50-fresh-application-plan.json

terraform -chdir=deploy/aws/terraform/stacks/production-application apply \
  -input=false /approved/cutover/<CUTOVER_ID>/fresh-application.tfplan \
  > /approved/evidence/<CUTOVER_ID>/50-fresh-application-apply.txt

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> --namespace cats \
  rollout status deployment/cats-controld --timeout=10m

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> --namespace cats \
  rollout status deployment/cats-gatewayd --timeout=10m

kubectl --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --context <PRODUCTION_KUBE_CONTEXT> --namespace cats \
  get deployments,pods -l app.kubernetes.io/part-of=cats -o json \
  > /approved/evidence/<CUTOVER_ID>/50-fresh-rollout.json

deploy/aws/run-postgres-probe.sh \
  /approved/cutover/<CUTOVER_ID>/production.kubeconfig cats \
  cutover-<CUTOVER_ID>-schema-version \
  "SELECT version FROM control_schema_version WHERE singleton" \
  > /approved/evidence/<CUTOVER_ID>/50-control-schema-version.txt
```

The schema query must return exactly `15`. Starting Gateway here does not open public ingress;
E12 and E3 still require every Node-local lifecycle/route gate Closed.

For each Host, prepare/export its Host-local identity while the Node service is stopped:

```sh
sudo /approved/staged-worker/cats \
  admin runtime-provisioner node-identity prepare \
  --node-id <EXACT_NODE_ID> \
  --immutable-host-id <PROVIDER_VERIFIED_IMMUTABLE_HOST_ID> \
  --state-path-id <FRESH_STATE_PATH_ID> \
  --credential-id <FRESH_NODE_CREDENTIAL_ID>

sudo /approved/staged-worker/cats \
  admin runtime-provisioner node-identity export \
  > /approved/cutover/<CUTOVER_ID>/<EXACT_NODE_ID>-node-identity.v1.json
```

From the central provisioner, apply the public identity and reviewed cordoned policy through the
only signed authority route:

```sh
/approved/staged-worker/cats \
  --api-url <FRESH_PRIVATE_CONTROL_ORIGIN> --json \
  admin runtime-node provision \
  --identity /approved/cutover/<CUTOVER_ID>/<EXACT_NODE_ID>-node-identity.v1.json \
  --policy /approved/cutover/<CUTOVER_ID>/<EXACT_NODE_ID>-cordoned-policy.v1.json \
  --deployment-id <FRESH_DEPLOYMENT_ID> \
  --provisioner-credential-id <FRESH_PROVISIONER_CREDENTIAL_ID> \
  --provisioner-private-key-file /approved/secrets/<CUTOVER_ID>/runtime-provisioner-key.pem \
  > /approved/cutover/<CUTOVER_ID>/<EXACT_NODE_ID>-authority-result.tmp

install -m 0600 \
  /approved/cutover/<CUTOVER_ID>/<EXACT_NODE_ID>-authority-result.tmp \
  /approved/evidence/<CUTOVER_ID>/50-<EXACT_NODE_ID>-authority-result.v1.json
```

Return that exact result to the same Host and activate it:

```sh
sudo install -o root -g root -m 0600 \
  /approved/evidence/<CUTOVER_ID>/50-<EXACT_NODE_ID>-authority-result.v1.json \
  /approved/host-input/node-authority-result.v1.json

sudo /approved/staged-worker/cats \
  admin runtime-provisioner node-identity activate \
  --apply-result /approved/host-input/node-authority-result.v1.json
```

Finally, update the existing production-infrastructure state with the exact worker bundle, Node
Secret ARN/version and explicit Host map. Its reviewed plan must keep the current Usage resources
unchanged, keep every Node cordoned and contain no old writer credential:

```sh
terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure init \
  -backend-config=/approved/cutover/<CUTOVER_ID>/current-infrastructure.backend.hcl

terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure output -json \
  > /approved/evidence/<CUTOVER_ID>/50-infrastructure-outputs-before.json
jq '{usage_stream_name,usage_archive_bucket_name,usage_consumer_lease_table_name}' \
  /approved/evidence/<CUTOVER_ID>/50-infrastructure-outputs-before.json \
  > /approved/evidence/<CUTOVER_ID>/50-usage-targets-before.json

terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure plan \
  -input=false \
  -var-file=/approved/cutover/<CUTOVER_ID>/closed-candidate-workers.tfvars \
  -out=/approved/cutover/<CUTOVER_ID>/closed-candidate-workers.tfplan

terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure show \
  -json /approved/cutover/<CUTOVER_ID>/closed-candidate-workers.tfplan \
  > /approved/evidence/<CUTOVER_ID>/50-closed-candidate-workers-plan.json

terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure apply \
  -input=false /approved/cutover/<CUTOVER_ID>/closed-candidate-workers.tfplan \
  > /approved/evidence/<CUTOVER_ID>/50-closed-candidate-workers-apply.txt

terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure output -json \
  > /approved/evidence/<CUTOVER_ID>/50-infrastructure-outputs-after.json
jq '{usage_stream_name,usage_archive_bucket_name,usage_consumer_lease_table_name}' \
  /approved/evidence/<CUTOVER_ID>/50-infrastructure-outputs-after.json \
  > /approved/evidence/<CUTOVER_ID>/50-usage-targets-after.json

cmp /approved/evidence/<CUTOVER_ID>/50-usage-targets-before.json \
  /approved/evidence/<CUTOVER_ID>/50-usage-targets-after.json
```

**Retain.** Application/worker plans and transcripts, rollout projection, schema stamp, every A23
identity/policy/result, worker association ID, installed release receipt, Node service state and
initial complete-inventory receipt under `50-fresh-release/`.

**Cancel point.** Any partial Node activation or worker transaction stays cordoned and is replayed
only through the same A23/worker transaction. Keep ingress Closed; do not use legacy Node admin
cordon/uncordon or direct SQL to repair authority rows.

<!-- cutover-stage: 50-e12-empty-fleet -->

## 6. E12: prove the exact empty, cordoned fleet

**Assert first.** Control reports `<FINAL_RELEASE_SHA>`; the expected Node list is complete and
contains no extra Node; each current AgentSession has a fresh complete empty inventory, all gates
Closed and an ACK of the exact installed Route v2 ring. The CLI is the same final release.

**Command** (repeat `--expected-node` for the exact closed fleet):

```sh
/approved/staged-worker/cats \
  --api-url <FRESH_PRIVATE_CONTROL_ORIGIN> --json \
  admin fleet-verify \
  --expected-node <NODE_1_ID> \
  --expected-node <NODE_2_ID> \
  --key-ring /approved/secrets/<CUTOVER_ID>/route-v2-r1/node/public-key-ring.v1.json \
  --release-commit <FINAL_RELEASE_SHA> \
  --timeout-seconds 600 \
  --poll-interval-ms 1000 \
  > /approved/evidence/<CUTOVER_ID>/60-fleet-verification.v1.json
```

The command fails on nonzero Desired/observation counts, a different provisioned Node set, session
ABA, stale/non-empty inventory, active lifecycle/route gates, guard/cancellation/residue, release
drift or key-ring mismatch. Do not replace it with separate counts or logs.

**Retain.** The canonical fleet verification evidence and exact CLI/ring digests.

**Cancel point.** Leave every Node cordoned and all ingress Closed. Fix only the exact failed
registration/inventory/release fact, then rerun E12; never fabricate an empty result by removing a
Node from `--expected-node`.

<!-- cutover-stage: 60-e3-runtime-path -->

## 7. E3: qualify create → Running → durable I/O → route → restart → usage → delete

This is an isolated qualification on already-provisioned metal; it is not a public production Cat.
The placement planner has no cordoned bypass, so each invocation temporarily makes exactly its
named qualification Node schedulable through an ordinary A23 policy revision. The public HTTP/WS
case likewise uses one operator-approved qualification-ingress window; no private Gateway bypass
or second route is introduced. The repo-owned E3
scenario driver is an input to the orchestrator and must be tracked, executable and byte-identical
to `<FINAL_RELEASE_SHA>`. If `<FINAL_RELEASE_SCENARIO_DRIVER>` is absent from the final release,
record `DEFERRED(E3_SCENARIO_DRIVER)` and stop.

**Assert first.** E12 is green; build receipt and release manifest bind the same SHA; the release
manifest digest was independently approved; and
`/opt/cats/release/worker-installation-receipt.v1.json` is the root-owned, single-link receipt from
the exact worker installation. Its worker bundle and member set must match the approved manifest.
Every binary, config, non-secret coordinate and key fingerprint below is explicit; each output
directory is absolute and does not yet exist. The control token is one root-owned mode-0600 file
passed by path, never argv content or manifest data. Before either invocation, while every Node is
still cordoned, save and review `qualification-ingress-open.tfplan`; it must change only
`enable_public_ingress=false -> true`. Also save and review the complete
`qualification-ingress-close.tfvars` with that one value fixed false and every other input
byte-identical. Install the early cleanup guard below, mark the open effect initiated, and only then
apply the open plan. Immediately plan against the now-open live state and save and review
`qualification-ingress-close.tfplan`. It must only remove or close qualification ingress. A close
plan made against the earlier Closed state is invalid.
Retain `terraform show -json` for both plans; pass those two JSON files as the required runner
configs. Run both block paths against the same release and scenario oracle.

Install the EXIT/INT/TERM guard before the ingress-open effect. Until the saved close plan is
reviewed, it uses only the pre-approved false tfvars and exact targeted resource set below, and
rejects every non-no-op managed change outside that set before apply. Approval atomically switches
the guard to the saved close plan. Then apply the reviewed full A23 policy that changes only the
exact qualification Node from `cordoned` to `schedulable`, using its exact current revision, and run
E3. Capture the runner status without exiting the operator shell. Whether the runner returns 0, 78 or any failure,
cleanup first exact-re-cordons the Node, then applies the saved ingress-close plan, then reruns the
exact E12 fleet verifier. If the schedulable apply response is ambiguous, cleanup first replays that
same durable CLI request to a terminal result before it submits the exact next-revision re-cordon.
Failure of one cleanup action must not suppress the later actions; all three must be attempted and
all three must succeed. INT/TERM received during cleanup is latched rather than starting recursive
cleanup: each effect runs at most once, remaining effects continue, and the first cleanup error wins
over the pending 130/143 status; otherwise that pending signal status is returned exactly:

```sh
set -euo pipefail
test "$(git rev-parse HEAD)" = <FINAL_RELEASE_SHA>
test "$(git hash-object deploy/metal/runtime-cutover-e3-window.sh)" = \
  "$(git rev-parse <FINAL_RELEASE_SHA>:deploy/metal/runtime-cutover-e3-window.sh)"
test "$(git hash-object deploy/metal/runtime-cutover-ingress-close-plan.sh)" = \
  "$(git rev-parse <FINAL_RELEASE_SHA>:deploy/metal/runtime-cutover-ingress-close-plan.sh)"
. deploy/metal/runtime-cutover-e3-window.sh

cats_e3_window_emergency_close() {
  terraform -chdir=deploy/aws/terraform/stacks/production-application plan \
    -input=false \
    -var-file=/approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-close.tfvars \
    -target=module.cats_kubernetes.kubernetes_namespace_v1.cats \
    -target=module.cats_kubernetes.kubernetes_manifest.ingress_class_params \
    -target=module.cats_kubernetes.kubernetes_ingress_class_v1.public \
    -target=module.cats_kubernetes.kubernetes_ingress_v1.public \
    -target=aws_route53_record.public \
    -out=/approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-emergency-close.tfplan || return
  terraform -chdir=deploy/aws/terraform/stacks/production-application show \
    -json /approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-emergency-close.tfplan \
    > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-qualification-ingress-emergency-close-plan.json || return
  deploy/metal/runtime-cutover-ingress-close-plan.sh \
    /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-qualification-ingress-emergency-close-plan.json || return
  terraform -chdir=deploy/aws/terraform/stacks/production-application apply \
    -input=false /approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-emergency-close.tfplan \
    > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-qualification-ingress-emergency-close-apply.txt
}

cats_e3_window_saved_close() {
  terraform -chdir=deploy/aws/terraform/stacks/production-application apply \
    -input=false /approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-close.tfplan \
    > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-qualification-ingress-close-apply.txt
}

cats_e3_window_run_e12() {
  /approved/staged-worker/cats \
    --api-url <FRESH_PRIVATE_CONTROL_ORIGIN> --json \
    admin fleet-verify \
    --expected-node <NODE_1_ID> \
    --expected-node <NODE_2_ID> \
    --key-ring /approved/secrets/<CUTOVER_ID>/route-v2-r1/node/public-key-ring.v1.json \
    --release-commit <FINAL_RELEASE_SHA> \
    --timeout-seconds 600 \
    --poll-interval-ms 1000 \
    > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-post-cleanup-fleet-verification.v1.json
}

<VERIFY_EXACT_FALSE_TFVARS_APPROVAL_RECEIPT>
cats_e3_window_install_guard
ingress_open_initiated=1
terraform -chdir=deploy/aws/terraform/stacks/production-application apply \
  -input=false /approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-open.tfplan \
  > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-qualification-ingress-open-apply.txt

terraform -chdir=deploy/aws/terraform/stacks/production-application plan \
  -input=false \
  -var-file=/approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-close.tfvars \
  -out=/approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-close.tfplan

terraform -chdir=deploy/aws/terraform/stacks/production-application show \
  -json /approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-qualification-ingress-close.tfplan \
  > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-qualification-ingress-close-plan.json

# Review the JSON now. It must only remove/close qualification ingress. Do not
# continue until that assertion has an operator approval receipt.
<VERIFY_EXACT_CLOSE_PLAN_APPROVAL_RECEIPT>
cats_e3_window_use_saved_close

apply_schedulable_policy() {
  /approved/staged-worker/cats \
    --api-url <FRESH_PRIVATE_CONTROL_ORIGIN> --json \
    admin runtime-node policy apply \
    --node <QUALIFICATION_NODE_ID> \
    --expected-revision <EXACT_CURRENT_CORDONED_POLICY_REVISION> \
    --file /approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-schedulable-policy.v1.json \
    --deployment-id <FRESH_DEPLOYMENT_ID> \
    --provisioner-credential-id <FRESH_PROVISIONER_CREDENTIAL_ID> \
    --provisioner-private-key-file /approved/secrets/<CUTOVER_ID>/runtime-provisioner-key.pem
}

cats_e3_window_apply_schedulable_policy() {
  apply_schedulable_policy \
    > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-schedulable-replay-result.v1.json
}

cats_e3_window_exact_re_cordon() {
  /approved/staged-worker/cats \
    --api-url <FRESH_PRIVATE_CONTROL_ORIGIN> --json \
    admin runtime-node policy apply \
    --node <QUALIFICATION_NODE_ID> \
    --expected-revision <EXACT_SCHEDULABLE_POLICY_REVISION> \
    --file /approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-re-cordoned-policy.v1.json \
    --deployment-id <FRESH_DEPLOYMENT_ID> \
    --provisioner-credential-id <FRESH_PROVISIONER_CREDENTIAL_ID> \
    --provisioner-private-key-file /approved/secrets/<CUTOVER_ID>/runtime-provisioner-key.pem \
    > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-re-cordoned-result.v1.json || return
  jq -e --arg node <QUALIFICATION_NODE_ID> --argjson revision <EXACT_RE_CORDONED_POLICY_REVISION> \
    '.version == 1 and .node_id == $node and .outcome == "policy_updated"
     and .identity_state == "provisioned" and .policy_revision == $revision' \
    /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-re-cordoned-result.v1.json || return
  jq -e --arg node <QUALIFICATION_NODE_ID> --argjson revision <EXACT_RE_CORDONED_POLICY_REVISION> \
    '.version == 1 and .node_id == $node and .policy_revision == $revision
     and .scheduling_state == "cordoned"' \
    /approved/cutover/<CUTOVER_ID>/<BLOCK_PATH>-re-cordoned-policy.v1.json
}

qualification_transition=initiated
set +e
apply_schedulable_policy \
  > /approved/evidence/<CUTOVER_ID>/70-<BLOCK_PATH>-schedulable-result.v1.json
schedulable_apply_status=$?
set -e
if [ "$schedulable_apply_status" -ne 0 ]; then
  exit "$schedulable_apply_status"
fi
qualification_transition=terminal_schedulable

set +e
deploy/metal/runtime-cutover-e2e.sh <THE_MATCHING_FULL_INVOCATION_BELOW>
e3_status=$?
cleanup_status=0
cats_e3_window_finish || cleanup_status=$?
set -e

if [ "$cleanup_status" -ne 0 ]; then
  exit "$cleanup_status"
fi

case "$e3_status" in 0|78) ;; *) exit "$e3_status" ;; esac
```

The early guard is live before `ingress_open_initiated=1`, which itself precedes the open effect, so
an ambiguous open response also takes the emergency close path. The saved-plan switch is one shell
assignment after approval; every earlier failure remains on the targeted emergency close. Clear the
guard only after exact re-cordon, ingress-close and post-cleanup E12 results all exist. E12 proves
empty/session/full-inventory/ring, while the latest A23 result and full policy independently prove
exact re-cordon.
Do not continue to the other block path if ingress-close, A23 re-cordon or E12 fails.

**Command — kernel NBD:**

```sh
deploy/metal/runtime-cutover-e2e.sh \
  --exact-commit <FINAL_RELEASE_SHA> \
  --block-path kernel-nbd \
  --run-id <CUTOVER_ID>-kernel-nbd \
  --output-dir /approved/evidence/<CUTOVER_ID>/70-metal-kernel-nbd \
  --build-receipt /approved/evidence/<CUTOVER_ID>/00-release/<BUILD_RECEIPT>.json \
  --release-manifest /approved/release/<FINAL_RELEASE_SHA>/release-manifest.v1.json \
  --release-manifest-sha256 sha256:<INDEPENDENTLY_APPROVED_RELEASE_MANIFEST_SHA256> \
  --installer-receipt /opt/cats/release/worker-installation-receipt.v1.json \
  --token-file /approved/secrets/<CUTOVER_ID>/e3-control-token \
  --control-origin <FRESH_PRIVATE_CONTROL_ORIGIN> \
  --workspace-id <QUALIFICATION_WORKSPACE_ID> \
  --expected-node <KERNEL_NBD_QUALIFICATION_NODE_ID> \
  --qualification-node <KERNEL_NBD_QUALIFICATION_NODE_ID> \
  --cat-name <KERNEL_NBD_QUALIFICATION_CAT_NAME> \
  --boot-image-digest sha256:<QUALIFIED_BOOT_IMAGE_DIGEST> \
  --endpoint-name <QUALIFICATION_ENDPOINT_NAME> \
  --endpoint-hostname <QUALIFICATION_ENDPOINT_HOSTNAME> \
  --guest-kernel <QUALIFIED_GUEST_KERNEL_RELEASE> \
  --binary <LABEL>=<ABSOLUTE_BINARY_PATH> \
  --config route-key-ring=<ABSOLUTE_ROUTE_KEY_RING_PATH> \
  --config qualification-ingress-open-plan=/approved/evidence/<CUTOVER_ID>/70-kernel-nbd-qualification-ingress-open-plan.json \
  --config qualification-ingress-close-plan=/approved/evidence/<CUTOVER_ID>/70-kernel-nbd-qualification-ingress-close-plan.json \
  --key-fingerprint <LABEL>=sha256:<PUBLIC_KEY_FINGERPRINT> \
  --scenario-driver <FINAL_RELEASE_SCENARIO_DRIVER>
```

**Command — native vhost-user-blk:**

```sh
deploy/metal/runtime-cutover-e2e.sh \
  --exact-commit <FINAL_RELEASE_SHA> \
  --block-path vhost-user \
  --run-id <CUTOVER_ID>-vhost-user \
  --output-dir /approved/evidence/<CUTOVER_ID>/70-metal-vhost-user \
  --build-receipt /approved/evidence/<CUTOVER_ID>/00-release/<BUILD_RECEIPT>.json \
  --release-manifest /approved/release/<FINAL_RELEASE_SHA>/release-manifest.v1.json \
  --release-manifest-sha256 sha256:<INDEPENDENTLY_APPROVED_RELEASE_MANIFEST_SHA256> \
  --installer-receipt /opt/cats/release/worker-installation-receipt.v1.json \
  --token-file /approved/secrets/<CUTOVER_ID>/e3-control-token \
  --control-origin <FRESH_PRIVATE_CONTROL_ORIGIN> \
  --workspace-id <QUALIFICATION_WORKSPACE_ID> \
  --expected-node <VHOST_USER_QUALIFICATION_NODE_ID> \
  --qualification-node <VHOST_USER_QUALIFICATION_NODE_ID> \
  --cat-name <VHOST_USER_QUALIFICATION_CAT_NAME> \
  --boot-image-digest sha256:<QUALIFIED_BOOT_IMAGE_DIGEST> \
  --endpoint-name <QUALIFICATION_ENDPOINT_NAME> \
  --endpoint-hostname <QUALIFICATION_ENDPOINT_HOSTNAME> \
  --guest-kernel <QUALIFIED_GUEST_KERNEL_RELEASE> \
  --binary <LABEL>=<ABSOLUTE_BINARY_PATH> \
  --config route-key-ring=<ABSOLUTE_ROUTE_KEY_RING_PATH> \
  --config qualification-ingress-open-plan=/approved/evidence/<CUTOVER_ID>/70-vhost-user-qualification-ingress-open-plan.json \
  --config qualification-ingress-close-plan=/approved/evidence/<CUTOVER_ID>/70-vhost-user-qualification-ingress-close-plan.json \
  --key-fingerprint <LABEL>=sha256:<PUBLIC_KEY_FINGERPRINT> \
  --scenario-driver <FINAL_RELEASE_SCENARIO_DRIVER>
```

Repeat `--expected-node`, `--binary`, additional `--config` and `--key-fingerprint` for the complete
reviewed fleet/input set. No `CATS_TOKEN` or `CATS_E3_*` ambient value is an input: the runner clears
them and reconstructs the scenario environment from these arguments. Binary
digests and installed paths are not caller assertions: the runner derives them from
`.artifacts.worker.members` and the installer receipt, copies every input to a private stable stage,
and re-hashes the original inputs at the end. The explicit binaries include the installed
`cats-noded`, `cats`, `cats-runtime-e3-probe`, `cats-e3-guest-workload`, and the receipt-recorded
`curl`, `systemctl`, `journalctl` and GNU `timeout`; focused test binaries are not live prerequisites.

There are exactly nine ordered cases. In the current release, seven pass and two return the typed
exit 78: V5 is `DEFERRED(V5_PERSISTENT_DISK_ATTACH_MUTATION)` and E9 lacks its accepted terminal
archive/projector receipt. Assert this honest blocked result for each output directory:

```sh
sha256sum -c /approved/evidence/<CUTOVER_ID>/70-metal-kernel-nbd/SHA256SUMS
jq -e '.state == "blocked" and .exact_commit == "<FINAL_RELEASE_SHA>" and .block_path == "kernel-nbd" and .exit_code == 78' \
  /approved/evidence/<CUTOVER_ID>/70-metal-kernel-nbd/manifest.json
jq -e -s 'map(.case_id) == ["control-startup-schema","node-registration-full-inventory","cat-create-running","durable-write-flush","route-http-ws","agent-restart-adoption","volume-init-matrix","usage-final-terminal-receipt","delete-cleanup"] and ([.[] | select(.status == "passed")] | length) == 7 and (.[] | select(.case_id == "volume-init-matrix") | .status == "blocked" and .run_exit_code == 78) and (.[] | select(.case_id == "usage-final-terminal-receipt") | .status == "blocked" and .run_exit_code == 78) and all(.[]; .cleanup_exit_code == 0 and .evidence_exit_code == 0)' \
  /approved/evidence/<CUTOVER_ID>/70-metal-kernel-nbd/scenario-results.jsonl

sha256sum -c /approved/evidence/<CUTOVER_ID>/70-metal-vhost-user/SHA256SUMS
jq -e '.state == "blocked" and .exact_commit == "<FINAL_RELEASE_SHA>" and .block_path == "vhost-user" and .exit_code == 78' \
  /approved/evidence/<CUTOVER_ID>/70-metal-vhost-user/manifest.json
jq -e -s 'map(.case_id) == ["control-startup-schema","node-registration-full-inventory","cat-create-running","durable-write-flush","route-http-ws","agent-restart-adoption","volume-init-matrix","usage-final-terminal-receipt","delete-cleanup"] and ([.[] | select(.status == "passed")] | length) == 7 and (.[] | select(.case_id == "volume-init-matrix") | .status == "blocked" and .run_exit_code == 78) and (.[] | select(.case_id == "usage-final-terminal-receipt") | .status == "blocked" and .run_exit_code == 78) and all(.[]; .cleanup_exit_code == 0 and .evidence_exit_code == 0)' \
  /approved/evidence/<CUTOVER_ID>/70-metal-vhost-user/scenario-results.jsonl
```

After V5 is implemented, the only acceptable intermediate shape is eight passed cases plus the same
typed E9 block. Neither the current seven-plus-two shape nor that future eight-plus-one shape opens
Stage B: keep the fleet cordoned until all nine pass, the manifest is `passed`, and exit code is zero.
The fixed sequence otherwise proves create and stable Running, Guest write plus successful
FLUSH/sync, public Gateway HTTP and WebSocket, an exact `cats-worker.service` restart with changed
AgentSession and fresh session-bound full inventory, post-restart Guest and route/gate evidence,
durable usage delivery, and exact delete cleanup.

**Retain.** For each block path retain the schedulable result and any exact replay result, exact
re-cordon result, any emergency close plan/JSON/apply transcript, saved ingress-close apply
transcript, post-cleanup E12 result, `manifest.json`,
`scenario-results.jsonl`, bounded journal, `final-inventory.json`, `exit-code` and `SHA256SUMS`
through the append-only evidence boundary.

**Cancel point.** A failed case still runs bounded diagnostics and cleanup, then exits nonzero.
The operator trap must restore ingress Closed, exact-re-cordon the qualification Node and rerun E12
before diagnosis. Preserve the entire output directory; do not skip a case, edit JSONL or reuse an
existing output directory.

<!-- cutover-stage: 70-final-gates -->

## 8. Recheck final full, Linux and metal gates

**Assert first.** No source or artifact changed after the receipts above. Any change creates a new
final SHA and invalidates E12/E3; it is not a same-window patch.

**Command:**

```sh
./scripts/quality.sh full \
  > /approved/evidence/<CUTOVER_ID>/80-quality-full.txt

./scripts/quality.sh linux \
  > /approved/evidence/<CUTOVER_ID>/80-quality-linux-compatibility.txt

cats-run-build \
  <FINAL_RELEASE_SHA> <SOURCE_MANIFEST_SHA256> <SOURCE_BUNDLE_SHA256> \
  --with-postgres -- /bin/bash -c \
  'set -o pipefail
   ./scripts/quality.sh full 2>&1 |
     tee "$CATS_BUILD_OUTPUT_DIR/quality-full.log"'

cats-publish-content-addressed evidence \
  /srv/cats-build/target/<FINAL_RELEASE_SHA>-<SOURCE_MANIFEST_SHA256>-<SOURCE_BUNDLE_SHA256>/<FINAL_QUALIFICATION_JOB_ID>/output/quality-full.log

sha256sum -c /approved/evidence/<CUTOVER_ID>/70-metal-kernel-nbd/SHA256SUMS
sha256sum -c /approved/evidence/<CUTOVER_ID>/70-metal-vhost-user/SHA256SUMS
```

Take `<FINAL_QUALIFICATION_JOB_ID>` only from this successful final native build receipt, then
publish its frozen log before retaining the final publication receipt. Do not reuse the phase 0
job ID or its earlier green receipt.

The Docker Linux command is an iteration/compatibility signal, not a substitute for the native
x86_64 Linux `full` receipt. The two metal manifests remain the real KVM qualification.

**Retain.** Both local provenance-bearing logs, the final native Linux build receipt/publication
receipt and revalidated metal checksum results under `80-final-gates/`.

**Cancel point.** Any gate failure returns to a new release SHA and repeats the sequence from phase
0. Keep maintenance, ingress and Nodes Closed; do not carry old green evidence across the change.

## Stage B — final Usage closure, reset and public opening (currently blocked)

Stage A may remain running as a closed candidate while this stage is blocked. It cannot serve
public users or become schedulable. Stage B requires accepted E13/reset consumption, the accepted
E9 final usage epoch/barrier, accepted cross-component Closed-admission proof and a disjoint fresh
Usage schema/stream/table/archive. The exact provisioning input for that final fresh Usage boundary
is currently `DEFERRED(FINAL_FRESH_USAGE_TARGETS)`; do not infer it from the reused candidate target
or create it with an unreviewed command.

<!-- cutover-stage: 80-reset-read-only -->

## 9. Build and review the exact reset plan; dry-run only

**Assert first.** This phase is not reachable while Stage A reuses the current Usage target. First
provide the disjoint final fresh Usage target and accepted proof inputs above. Then require E12/E3/
final gates green and make the post-green document follow the exact schema in
[`production-clean-slate-reset.md`](../deploy/aws/production-clean-slate-reset.md). It binds the same
release, artifact, reset ID, fresh targets and qualification digest and is at most 900 seconds old.
Its `old_writers` fields remain declarations until an accepted consumer says otherwise.

Run the read-only plan with every old and fresh target literal:

```sh
python3 deploy/aws/production-clean-slate-reset.py plan \
  --reset-id <RESET_ID> \
  --release-commit <FINAL_RELEASE_SHA> \
  --artifact-sha256 <RELEASE_ARTIFACT_SHA256> \
  --aws-account-id <PRODUCTION_12_DIGIT_ACCOUNT_ID> \
  --aws-region <PRODUCTION_AWS_REGION> \
  --eks-cluster-name <PRODUCTION_EKS_CLUSTER> \
  --kubernetes-namespace cats \
  --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --kube-context <PRODUCTION_KUBE_CONTEXT> \
  --old-control-postgres-url-file /approved/secrets/<CUTOVER_ID>/old-control.url \
  --old-control-schema <OLD_DEDICATED_CONTROL_SCHEMA> \
  --old-usage-postgres-url-file /approved/secrets/<CUTOVER_ID>/old-usage.url \
  --old-usage-schema <OLD_DEDICATED_USAGE_SCHEMA> \
  --old-chunkstore-bucket <OLD_VERSIONED_CHUNKSTORE_BUCKET> \
  --old-chunkstore-prefix <OLD_EXACT_CHUNKSTORE_PREFIX> \
  --old-usage-kinesis-stream <OLD_EXACT_USAGE_STREAM> \
  --old-usage-checkpoint-table <OLD_EXACT_USAGE_CHECKPOINT_TABLE> \
  --old-usage-archive-bucket <OLD_IMMUTABLE_USAGE_ARCHIVE_BUCKET> \
  --fresh-control-postgres-url-file /approved/secrets/<CUTOVER_ID>/fresh-control.url \
  --fresh-control-schema <FRESH_CONTROL_SCHEMA> \
  --fresh-usage-postgres-url-file /approved/secrets/<CUTOVER_ID>/fresh-usage.url \
  --fresh-usage-schema <FRESH_USAGE_SCHEMA> \
  --fresh-chunkstore-bucket <FRESH_VERSIONED_CHUNKSTORE_BUCKET> \
  --fresh-chunkstore-prefix <FRESH_EXACT_CHUNKSTORE_PREFIX> \
  --fresh-usage-kinesis-stream <FRESH_EXACT_USAGE_STREAM> \
  --fresh-usage-checkpoint-table <FRESH_EXACT_USAGE_CHECKPOINT_TABLE> \
  --fresh-usage-archive-bucket <FRESH_IMMUTABLE_USAGE_ARCHIVE_BUCKET> \
  --post-green-evidence-file /approved/evidence/<CUTOVER_ID>/90-post-green.json \
  --receipt-directory /approved/evidence/<CUTOVER_ID>/90-reset-receipts
```

Independently review the canonical plan and its SHA sidecar. Then run the second read-only preflight
with the same full target set:

```sh
python3 deploy/aws/production-clean-slate-reset.py apply \
  --reset-id <RESET_ID> \
  --release-commit <FINAL_RELEASE_SHA> \
  --artifact-sha256 <RELEASE_ARTIFACT_SHA256> \
  --aws-account-id <PRODUCTION_12_DIGIT_ACCOUNT_ID> \
  --aws-region <PRODUCTION_AWS_REGION> \
  --eks-cluster-name <PRODUCTION_EKS_CLUSTER> \
  --kubernetes-namespace cats \
  --kubeconfig /approved/cutover/<CUTOVER_ID>/production.kubeconfig \
  --kube-context <PRODUCTION_KUBE_CONTEXT> \
  --old-control-postgres-url-file /approved/secrets/<CUTOVER_ID>/old-control.url \
  --old-control-schema <OLD_DEDICATED_CONTROL_SCHEMA> \
  --old-usage-postgres-url-file /approved/secrets/<CUTOVER_ID>/old-usage.url \
  --old-usage-schema <OLD_DEDICATED_USAGE_SCHEMA> \
  --old-chunkstore-bucket <OLD_VERSIONED_CHUNKSTORE_BUCKET> \
  --old-chunkstore-prefix <OLD_EXACT_CHUNKSTORE_PREFIX> \
  --old-usage-kinesis-stream <OLD_EXACT_USAGE_STREAM> \
  --old-usage-checkpoint-table <OLD_EXACT_USAGE_CHECKPOINT_TABLE> \
  --old-usage-archive-bucket <OLD_IMMUTABLE_USAGE_ARCHIVE_BUCKET> \
  --fresh-control-postgres-url-file /approved/secrets/<CUTOVER_ID>/fresh-control.url \
  --fresh-control-schema <FRESH_CONTROL_SCHEMA> \
  --fresh-usage-postgres-url-file /approved/secrets/<CUTOVER_ID>/fresh-usage.url \
  --fresh-usage-schema <FRESH_USAGE_SCHEMA> \
  --fresh-chunkstore-bucket <FRESH_VERSIONED_CHUNKSTORE_BUCKET> \
  --fresh-chunkstore-prefix <FRESH_EXACT_CHUNKSTORE_PREFIX> \
  --fresh-usage-kinesis-stream <FRESH_EXACT_USAGE_STREAM> \
  --fresh-usage-checkpoint-table <FRESH_EXACT_USAGE_CHECKPOINT_TABLE> \
  --fresh-usage-archive-bucket <FRESH_IMMUTABLE_USAGE_ARCHIVE_BUCKET> \
  --post-green-evidence-file /approved/evidence/<CUTOVER_ID>/90-post-green.json \
  --receipt-directory /approved/evidence/<CUTOVER_ID>/90-reset-receipts \
  --plan-receipt /approved/evidence/<CUTOVER_ID>/90-reset-receipts/<RESET_ID>.plan.json \
  --plan-sha256 <INDEPENDENTLY_REVIEWED_PLAN_SHA256> \
  --confirm-reset-id <RESET_ID>
```

**Retain.** Post-green JSON/digest, plan JSON/digest, dry-run receipt/digest and the complete
read-only command transcript.

**Cancel point.** Phase 8 is the last currently reachable step. Once this future phase is enabled,
cancel retirement before `reset-started` by retaining all old resources and omitting the execute
flag. A change in target, inventory, rollout, evidence, reset ID, plan or digest requires a new
read-only plan and review.

<!-- cutover-stage: 90-reset-execute-forward-only -->
<!-- forward-only-boundary: immutable-reset-started -->

## 10. Destructive retirement — currently forbidden

**Assert first.** Do not enter this phase until a later exact release has accepted and implemented
all three proof authorities listed at the top, its calibrated negative fixtures pass, and the
unchanged reset invocation consumes their canonical evidence. Today this assertion is false.

The future execution is the phase-9 `apply` invocation with every argument byte-for-byte identical
and one final `--execute` argument. There is no shorter or alternate command. In the current release
it must fail before discovery or mutation and must not publish `reset-started`.

If a future accepted binary publishes the canonical immutable `reset-started` receipt, the
cancellation boundary is crossed at that publication, not at the first successful cloud response.
From then on:

- use the same plan, plan SHA, reset ID, release SHA, artifact digest, targets and evidence digest;
- invoke only the same exact `apply --execute` to discover and forward-resume missing stages;
- never restore the old deployment, import old data, recreate an old credential/name or generate a
  replacement plan;
- stop and investigate any receipt gap/drift or live postcondition contradiction.

**Retain.** In a future accepted release: immutable `reset-started`, every ordered stage receipt,
`reset-complete`, all SHA sidecars and append-only publication receipts.

**Cancel point.** Before `reset-started`, phase 9 remains cancellable. At or after `reset-started`
there is no rollback/cancel path: only forward-fix of the same terminal release is allowed.

<!-- cutover-stage: 100-uncordon-open -->

## 11. Uncordon and open — held until verified final reset

**Assert first.** An independent verifier has accepted the canonical final reset receipt and every
remaining old-retirement receipt. The accepted cross-component admission authority supplies the
exact mutation-open transition; today that input is
`DEFERRED(CROSS_COMPONENT_MUTATION_ADMISSION_OPEN)`, so none of the commands below may run.

When that prerequisite exists, ADR-0053 keeps product mutation admission at exact `Closed` while
preparing all other serving effects. Apply a reviewed monotonic A23 schedulable policy to each exact
Node (repeat per Node and use its exact current revision):

```sh
/approved/staged-worker/cats \
  --api-url <FRESH_PRIVATE_CONTROL_ORIGIN> --json \
  admin runtime-node policy apply \
  --node <EXACT_NODE_ID> \
  --expected-revision <EXACT_CURRENT_CORDONED_POLICY_REVISION> \
  --file /approved/cutover/<CUTOVER_ID>/<EXACT_NODE_ID>-schedulable-policy.v1.json \
  --deployment-id <FRESH_DEPLOYMENT_ID> \
  --provisioner-credential-id <FRESH_PROVISIONER_CREDENTIAL_ID> \
  --provisioner-private-key-file /approved/secrets/<CUTOVER_ID>/runtime-provisioner-key.pem \
  > /approved/evidence/<CUTOVER_ID>/110-<EXACT_NODE_ID>-schedulable-result.v1.json
```

With mutation admission still Closed, prepare a final application tfvars with
`maintenance_mode=false` and `enable_public_ingress=true`, then use one reviewed saved plan:

```sh
terraform -chdir=deploy/aws/terraform/stacks/production-application plan \
  -input=false \
  -var-file=/approved/cutover/<CUTOVER_ID>/public-open.tfvars \
  -out=/approved/cutover/<CUTOVER_ID>/public-open.tfplan

terraform -chdir=deploy/aws/terraform/stacks/production-application show \
  -json /approved/cutover/<CUTOVER_ID>/public-open.tfplan \
  > /approved/evidence/<CUTOVER_ID>/110-public-open-plan.json

terraform -chdir=deploy/aws/terraform/stacks/production-application apply \
  -input=false /approved/cutover/<CUTOVER_ID>/public-open.tfplan \
  > /approved/evidence/<CUTOVER_ID>/110-public-open-apply.txt
```

After rollout, rerun E12's fleet verifier with the now-schedulable policy facts and run the
repository's bounded read-only public `GET /healthz` probe while product admission is still Closed;
do not use the shell WebSocket or another product operation as this probe. Full public WebSocket
evidence remains the reset-bound G3 qualification rather than a post-reset product mutation.
Run final-open with only one operator process for the reviewed `open_id`. Both plan and apply acquire
the one persistent actor-only empty `production-final-open.transaction.lock` for the entire receipt
directory before reading any open journal and retain its stable directory/file descriptors through
every forward/cleanup decision and effect. This global scope includes different `open_id` values. A
concurrent invocation must exit before any adapter call; after a crash, a foreign ID remains blocked
by the active journal and only the original ID exact-resumes. A new ID is allowed only after terminal
Closed abort, and completed Open blocks all new IDs. Never unlink, replace or rotate the lock after
success, abort or operator crash.
Immediately re-discover the exact planned Closed revision and signed-command lifetime, publish the
forward-only `mutation-admission-open-finalizing` marker, then settle the one exact Open command as
the final external effect and publish `open-complete`. Before the marker, failure closes Ingress and
re-cordons every possibly schedulable Node; after it, cancellation or ambiguity only exact-forward
settles Open and never EmergencyClose. Do not reuse the E3 qualification Cat, any retired ID,
credential, SPKI, schema, prefix, stream or table.

**Retain.** Independent final-reset verification, mutation-open receipt, every schedulable policy
result, public-open plan/apply evidence and bounded public probes.

**Cancel point.** Before `mutation-admission-open-finalizing`, use the journaled Closed cleanup. At or
after that marker, cancellation cannot change the decision: resume the same plan and exact Open
command to `open-complete`; do not compensate with ad hoc Ingress, Node or admission commands.

## Operator sign-off checklist

- One final SHA and release manifest bind all binaries, configs, Guest payload and receipts.
- Maintenance is a reviewed Terraform transition; the only pre-reset ingress exception is each
  bounded E3 window, whose Node is exact-re-cordoned before its saved close plan is applied and E12
  is repeated.
- Stage A uses a fresh Control schema and ChunkStore prefix but the reviewed current Usage target;
  Stage B requires a disjoint final fresh Usage target.
- A23 initial policies are cordoned; E12 proves the exact empty/session/full-inventory/ring facts,
  while each latest signed A23 result plus its exact full policy proves the Node is re-cordoned.
- Both E3 block paths report all nine cases with checksum-valid seven-pass/two-typed-block evidence.
- Local/full, compatibility Linux, native x86_64 Linux and real metal evidence are retained.
- Reset planning begins only in Stage B and repeats every exact target; production execute remains
  blocked today.
- No uncordon, mutation/public opening or new product resource occurs before verified final reset.
