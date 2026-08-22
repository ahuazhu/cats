# Cats AWS Terraform

Terraform is the authoritative change path for the AWS usage infrastructure and
the Cats Kubernetes deployment described here. Running these configurations is
a production mutation: always review a saved plan in CI before apply.

No cloud resource is created merely by checking in this directory.

## Layout

| Directory | State boundary | Owns |
|---|---|---|
| `bootstrap/` | bootstrap state | Versioned, encrypted, private S3 state bucket |
| `stacks/platform/` | platform state | VPC, EKS cluster, RDS PostgreSQL, Route 53 zone, ACM certificate, ECR repository, bare-metal worker capacity and security group, GitHub Actions release role |
| `stacks/production-infrastructure/` | infrastructure state | Usage stream/archive/checkpoints, Pod Identity, alarms, worker artifacts/secrets/SSM deployment |
| `stacks/production-payments/` | payments state | Stripe prepaid-credit Product, fixed one-time Prices and signed webhook endpoint |
| `stacks/production-application/` | application state | Cats Namespace/ServiceAccount, Secret/ConfigMap, EBS PVC, Deployments, Services and public ingress |
| `modules/` | none | Reusable implementation called by stacks |

Keep the infrastructure and application states separate. The application
provider must connect to an already healthy EKS API; coupling its state to EKS
creation makes cluster recovery and provider initialization fragile.

`stacks/platform/` now owns the resources that used to be unmanaged inputs.
In a greenfield account it creates them outright, so no import is required and
a Terraform data source never stands in for ownership. In an account where they
already exist by hand, declare them from their exact live configuration and
import them before Terraform changes anything.

The platform state owns the long-lived bare-metal instances and places adjacent
workers in different private subnets. The production-infrastructure state
references those instances by stable name and ID to roll reviewed worker
bundles across the fleet.

Apply order is `bootstrap` → `platform` → `production-infrastructure` →
`production-application`. Bootstrap comes first and keeps local state because it
creates the bucket every later state stores its state in.

## State bootstrap

The bootstrap stack has no remote backend because it creates that backend.
Run it once from a locked CI workspace or an encrypted operator workspace, and
retain its small local state in an approved encrypted vault:

```sh
cd deploy/aws/terraform/bootstrap
cp bootstrap.tfvars.example bootstrap.auto.tfvars
terraform init
terraform plan -out=bootstrap.tfplan
terraform apply bootstrap.tfplan
```

The `.gitignore` excludes state, plans and `*.auto.tfvars`. Do not commit them.
The state bucket uses versioning, SSE-S3, public-access block, TLS-only access
and destroy protection. Restrict bucket access with the deployment role's IAM
policy. The production stacks use S3 native `use_lockfile`; no DynamoDB state
lock table is needed.

## Platform

Creates the network, cluster, database and public identity the later stacks
assume. Apply it directly after bootstrap:

```sh
cd deploy/aws/terraform/stacks/platform
cp backend.hcl.example backend.hcl
cp platform.tfvars.example platform.auto.tfvars
../../check-platform-tfvars.sh platform.auto.tfvars
terraform init -backend-config=backend.hcl
terraform plan -refresh-only -out=platform-refresh.tfplan
terraform show platform-refresh.tfplan
terraform plan -out=platform.tfplan
terraform show platform.tfplan
terraform apply platform.tfplan
```

Production `*.auto.tfvars` stay private and are not repository artifacts. Before
every platform plan, the preflight above requires the operator-supplied file to
preserve one NAT gateway per availability zone. Correct any older private file
that still says `one_nat_gateway_per_az = false`, then review the refresh-only
and normal saved plans and stop if either proposes any NAT gateway or
private-route change.

The following platform transitions require exact review.

**Worker identity is a stable map, not a slot.** The production state was
imported with `aws_instance.metal_worker[0]` = `metal-2` and
`aws_instance.metal_worker[1]` = `metal-1`. The checked-in `moved` blocks
preserve exactly that mapping. Before the first apply with this configuration,
replace the old private count/list inputs with the exact `metal_workers` map in
`platform.tfvars.example`, keeping `metal-2.root_volume_encrypted = false` and
`metal-1.root_volume_encrypted = true`. Save and review the ordinary plan: it
must contain neither worker replacement nor worker deletion. Apply that same
saved plan to record the stable addresses, then export the deployment input:

```sh
terraform output -json metal_worker_instance_ids
```

Copy the resulting exact two-entry map, without renaming keys, to the
production-infrastructure stack's `metal_worker_instances`. Its next saved plan
must contain one SSM association for each of `metal-2` and `metal-1`.

`metal-2` has the one known unencrypted legacy root. Terraform deliberately
does not ignore that attribute and cannot make `prevent_destroy` conditional.
Do not change it during the address migration above. In the approved
maintenance window, first stop or isolate the empty Host and arrange its fresh
A23 NodeIdentity/Route credentials, then change only
`metal-2.root_volume_encrypted` from `false` to `true` and create the explicit
saved plan:

```sh
terraform plan -out=metal-2-root-encryption.tfplan
terraform show metal-2-root-encryption.tfplan
```

Independent review must find exactly one replacement,
`aws_instance.metal_worker["metal-2"]`, and no change to
`aws_instance.metal_worker["metal-1"]`. Apply only that exact saved plan. Keep
the value `true` afterward; reverting it would request another replacement.

Four things about this stack are easy to get wrong.

**The certificate cannot validate before the registrar moves.** A Route 53
hosted zone cannot be transferred between accounts, so this stack creates a new
zone with new name servers. ACM's DNS validation only resolves once the
registrar points at them. `wait_for_certificate_validation` therefore defaults
to false: the first apply requests the certificate and writes the validation
records without blocking. Read `route53_name_servers`, change them at the
registrar, then re-apply with the flag set — or simply wait, because ACM polls
and issues on its own.

**The VPC CIDR must not overlap the guest network.** Workers NAT each Cat's tap
`/30` onto the host interface, and `CATS_GUEST_NETWORK_CIDR` is `10.240.0.0/16`
by default. The `vpc_cidr` default of `10.20.0.0/16` is clear of it; if you
change either, keep them disjoint.

**The database password is not in this state.** RDS generates and rotates it in
Secrets Manager. Read `database_master_user_secret_arn` to assemble
`storage_postgres_url` and `usage_postgres_url` for the application stack.

**The database proxy is provisioned before it is selected.** The platform
stack creates a TLS-only RDS Proxy and exports `database_proxy_endpoint`, but
the production workflow retains the direct storage URL until the optional
`RDS_PROXY_ENDPOINT` repository variable is set. Wait for the proxy target to
be `AVAILABLE` and verify its initialization timeouts before setting the
variable. Usage clients remain direct. Metal workers switch separately by
setting `CATS_POSTGRES_HOST` to that output and
`CATS_POSTGRES_SESSION_SETUP=server-verified`, but the old one-node-at-a-time
drain is not current cutover authority: use the empty, cordoned, residue-free
worker boundary below until a lifecycle migration procedure is separately
qualified. See ADR-0034 for the database cutover, rollback and metric
acceptance contract.

**Production dependencies span availability zones by default.** The RDS
instance keeps a synchronous Multi-AZ standby, and each private subnet routes
through a NAT gateway in its own zone. Disabling either setting is an explicit
cost-versus-availability decision: an AZ failure can otherwise remove the
authoritative metadata database or strand healthy workers and EKS nodes
without external egress.

The stack also creates the GitHub Actions release role. Its trust policy pins
both the audience and the subject to `github_repository` — widening the subject
to a wildcard owner would let any repository assume it. Publish
`github_release_role_arn` as the `AWS_ROLE_ARN` repository variable, alongside
`AWS_REGION` and `ECR_REPOSITORY`. GitHub may issue immutable OIDC subjects that
include numeric owner and repository IDs; keep `github_subject_repository`
aligned with the repository's `sub_claim_prefix` so the exact subject remains
trusted after a rename. Set
`github_actions_application_state_bucket_arn` to the bootstrap state bucket
ARN; the role can update only `github_actions_application_state_key`, describe
the one EKS cluster, reconcile the application DNS records and access the
cluster through an explicit EKS access entry.

## Usage infrastructure

Before the cutover window, complete the tracked SNS output/input seam, confirm
the recipient out of band, run the fail-closed live preflight and retain one
controlled delivery test as described in the
[alarm recipient runbook](../alarm-recipients-runbook.md). Terraform cannot
infer subscription confirmation from a created subscription resource. Both
production states require the same explicit AWS account, partition and region;
the AWS provider allowlist and plan-time identity reads enforce them. Platform
recipient keys are opaque stable IDs and values are sensitive. If an earlier
state used an email address as the `for_each` key, follow the runbook's reviewed
state-move/import procedure before applying; otherwise Terraform will propose a
subscription replacement.

Copy the examples outside source control, replace the bucket name, then:

```sh
cd deploy/aws/terraform/stacks/production-infrastructure
cp backend.hcl.example backend.hcl
cp production.tfvars.example production.auto.tfvars
terraform init -backend-config=backend.hcl
terraform plan -out=production.tfplan
terraform apply production.tfplan
```

Defaults are deliberately cost-conscious:

- one provisioned Kinesis shard with a 24-hour replay window;
- one dedicated S3 bucket, batched-object lifecycle to Standard-IA after
  30 days and Deep Archive after 365 days;
- one on-demand DynamoDB projector checkpoint table;
- AWS-managed Kinesis encryption and SSE-S3 for the archive;
- seven-year S3 Object Lock in GOVERNANCE mode.

Object Lock cannot be disabled after bucket creation, and retained versions
continue to cost money until their retention expires. Confirm the retention
period before the first apply. `prevent_destroy` also blocks accidental bucket
replacement. The archive must never be reused for ChunkStore blocks.

The usage module attaches the producer and consumer policies to one EKS Pod
Identity role, associated only with the `cats-controld` ServiceAccount. No
Gateway Pod Identity or shared Route table exists before the v2 route module is
composed. The replay policy remains unattached and is reserved for
controlled reconciliation jobs:

- `usage_producer_policy_arn`: Kinesis publication;
- `usage_consumer_policy_arn`: Kinesis consumption, S3 archive writes and
  DynamoDB checkpoints;
- `usage_replay_policy_arn`: read-only S3 replay evidence.

`cats-controld` freezes billing attribution before publishing each checkpoint.
The projector batches one shard for at most 50 seconds, 4 MiB or 1000 records,
writes newline-delimited JSON to S3, applies the idempotent PostgreSQL
projection and advances the DynamoDB checkpoint last. S3 Object Lock is the
long-term raw evidence; PostgreSQL remains a rebuildable query projection.
The application runs multiple API replicas, but a PostgreSQL session advisory
lock elects exactly one usage projector. The table stores checkpoints only.
Add a conditional shard-lease protocol before running multiple projector
workers concurrently.

## Stripe payments

Create the Stripe resources before enabling payment in the application. The
official provider reads `STRIPE_API_KEY`; supply it through the approved
deployment secret channel:

```sh
export STRIPE_API_KEY='sk_live_...'

cd deploy/aws/terraform/stacks/production-payments
cp backend.hcl.example backend.hcl
cp production.tfvars.example production.auto.tfvars
terraform init -backend-config=backend.hcl
terraform plan -out=production.tfplan
terraform apply production.tfplan
```

The payment state contains the sensitive webhook signing secret because Stripe
returns it only when the endpoint is created. Treat this state and its saved
plans as production credentials. Transfer `topup_price_ids` and
`webhook_secret` to the application stack through CI outputs or another
approved encrypted channel; do not paste them into a committed tfvars file.

## Kubernetes application

Generate an exact kubeconfig context for the existing EKS cluster. Put
non-secret identifiers in a private tfvars file. Inject secrets from CI, for
example:

```sh
export TF_VAR_runtime_secret_data='{"CATS_AUTH_TOKEN":"...","CATS_ADMIN_TOKEN":"..."}'
export TF_VAR_runtime_provisioner_trust_bundle_json="$(cat /approved/provisioning/runtime-provisioner-trust.v1.json)"
export TF_VAR_storage_postgres_url='postgresql://...'
export TF_VAR_usage_postgres_url='postgresql://...'
export TF_VAR_rds_ca_pem='-----BEGIN CERTIFICATE-----...'
export TF_VAR_stripe_secret_key='sk_live_...'
export TF_VAR_stripe_webhook_secret='whsec_...'
# Opaque names of pre-created immutable Secrets; their Route v2 bytes never
# become Terraform inputs or state.
export TF_VAR_route_v2_control_artifact_secret_name='cats-route-v2-control-r1'
export TF_VAR_route_v2_control_artifact_signer_revision='1'
export TF_VAR_route_v2_control_artifact_secret_sha256='sha256:REPLACE_WITH_CONTROL_SECRET_MANIFEST_64_LOWERHEX'
export TF_VAR_route_v2_gateway_artifact_secret_name='cats-route-v2-gateway-r1'

cd deploy/aws/terraform/stacks/production-application
cp backend.hcl.example backend.hcl
cp production.tfvars.example production.auto.tfvars
terraform init -backend-config=backend.hcl
terraform plan -out=production.tfplan
terraform apply production.tfplan
```

Terraform's `sensitive` flag only redacts normal CLI output. Secret values still
exist in state and in saved plans, which is why both require the same access
control as production credentials. Route v2 therefore uses only pre-created
immutable Secret names/ARNs here. The application Secret key sets and the
worker Secrets Manager JSON shape are documented in
[`../README.md`](../README.md#route-v2-artifact-delivery); never replace those
references with PEM/JSON/private-key Terraform variables.

### First clean-slate maintenance/reset

The production-application stack exposes `maintenance_mode`. A reviewed plan
with it set to `true` removes public ingress/DNS and scales `cats-controld` to
zero without creating kubectl drift. After the old writers are positively
stopped or isolated, review a second plan that points the terminal release at
disjoint fresh control/usage schemas, ChunkStore prefix or bucket, Kinesis
stream, DynamoDB checkpoint table and immutable usage archive. Set
`maintenance_mode = false` only in that reviewed fresh-target plan, while
keeping the separate `enable_public_ingress = false`. Both ingress inputs
default Closed. Starting fresh Control replicas does not itself open public or
mutation admission.

The destructive reset is a post-green retirement, not a prerequisite for
starting the fresh release. The separate fail-closed executor requires the
fresh deployment to be fully available, the exact release qualification to be
green and every old writer to remain stopped or isolated. Before
`apply --execute` publishes its immutable start receipt, retirement may be
cancelled and all old resources remain untouched. It never accepts `public` or
another shared PostgreSQL schema as a deletion target; legacy data there stays
retained for a later exact table-level retirement. The two-phase commands,
fresh-target evidence schema, exact old-resource deletion and receipt contract
are documented in
[`production-clean-slate-reset.md`](../production-clean-slate-reset.md).
Every S3 operation also binds `--expected-bucket-owner` to the same 12-digit
account proven by STS; bucket name and region alone are not destructive
authority.
The post-green document is exact-reset-bound and has a 15-minute pre-start
freshness window. Its old-writer strings only bind the separately retained,
parseable E13 positive-stop/isolation manifest; they are not proof by
themselves, and production execute remains Blocked until that manifest is
independently verified. After `reset-started`, repeat the same reviewed
`apply --execute` to forward-resume the immutable stage chain; another plan,
evidence digest or target set fails closed.
This exact reset binary still mechanically blocks production execute before any
AWS/PostgreSQL call because E13 positive-stop, E9 signed final usage
epoch/barrier and cross-component Closed-admission proof formats have not been
accepted. Terraform does not satisfy or bypass those proofs. Canonical JSON is
the immutable receipt authority; a missing derived SHA sidecar is repaired from
exact JSON without repeating an effect.
The executor never runs as part of Terraform apply or normal release CI.

### Route admission

The retained V1 Terraform inputs use one Ed25519 key pair. They describe the
pre-cutover deployment shape, not a current clean-slate ingress path. Every
control-plane replica received the same private key from application state; CI
derived the public key from that exact input and workers received only the
public half. Because the module still accepts the private PEM as a Terraform
variable, a saved plan and state containing it remain credentials even though
the current application stack does not deploy public Endpoint ingress. Keep it
out of workers, Gateway configuration, Guest images and logs. Generate it with
`openssl genpkey -algorithm ED25519` and derive the public half with
`openssl pkey -pubout` only when reproducing or retiring that historical shape.

The clean-slate route design removes the private-key Terraform variable. Terraform manages
only a secret reference, workload access policy and public verifier ring; a separate
secret channel writes key bytes. The clean-slate deployment rotates the key so every
private value retained in historical Terraform state is cryptographically obsolete. The
versioned Terraform state remains restricted infrastructure evidence; it is not imported
as product data and is not deleted by the cutover.

The old regional Route Grant cache and Gateway-only Pod Identity have been
removed. The production stack now deploys the Route v2-only `cats-gatewayd`,
publishes Endpoint wildcard DNS and routes wildcard ingress to that service.
It references the immutable revision-1 Control and Gateway artifact Secrets;
the infrastructure stack references one exact revision-1 Node artifact Secret
version. Terraform never accepts their private bytes. This is initial
distribution only: G3 still owns signer/ring rotation, overlap, reload and
acknowledged rollout.

The first qualified ADR-0040/0041 clean-slate deployment follows the single ordered runbook in
[Operations and HA §8](../../../docs/operations-ha.md#8-首次终态部署). The Terraform plan used there
must already have removed the V1 route-cache/parser inputs and private-key value, retain only the
new secret reference/public ring policy, and rotate the affected service and per-Node credentials.
Historical Terraform state remains restricted evidence and is never imported as product data.

`storage_postgres_url` and `usage_postgres_url` are independent. They may point
to the same PostgreSQL instance and database, but usage keeps its own
`cats_usage` schema and database role. Moving usage to another database changes
only the usage DSN.

Set `stripe_enabled=true` and copy the non-secret `topup_price_ids` output into
`stripe_topup_price_ids`. Cats never credits a Checkout success redirect: only
a raw-body, HMAC-verified Stripe webhook can append a top-up. The runtime secret
also pins `CATS_STRIPE_LIVEMODE`, so test events cannot settle live credit (or
vice versa).

Set the usage stream, archive bucket and checkpoint table inputs from the
infrastructure stack outputs. All container images must include an immutable
`@sha256:...` digest. Changes to
the runtime Secret or RDS CA alter Pod template checksums and therefore trigger
a zero-unavailable rolling rollout. `cats-controld` runs at least two replicas
on distinct nodes. Required hostname anti-affinity keeps the second replica
Pending until EKS Auto Mode supplies another eligible node, rather than
silently co-locating both replicas; singleton loops elect independently through
PostgreSQL.

### Manual main deployment

An operator starts `Deploy production` explicitly from a `main` commit after
the required repository and native Linux gates have passed. The workflow
builds and pushes separate control-plane and Gateway images, pins both registry
digests, creates a saved application plan, applies that exact plan and verifies
each Deployment against its own immutable image reference. A failed build,
plan, apply or rollout records a failed GitHub deployment.

That workflow updates the Terraform-managed Control and Gateway applications;
its green result is not the missing production-public-spawn PostgreSQL/Linux
runtime E2E and does not qualify a nonempty worker or the signed full
lifecycle.

Configure these non-secret repository variables:

- `AWS_REGION`, `AWS_ROLE_ARN` and `ECR_REPOSITORY`;
- `EKS_CLUSTER_NAME`;
- `TF_STATE_BUCKET` and `TF_STATE_APPLICATION_KEY`;
- `PRODUCTION_TFVARS_B64`, the Base64 encoding of the private non-secret
  application tfvars with `kubeconfig_*` and all deployment-built image inputs
  omitted;
- `ROUTE_V2_CONTROL_ARTIFACT_SECRET_NAME` and
  `ROUTE_V2_GATEWAY_ARTIFACT_SECRET_NAME`, opaque immutable revision-1 Secret
  names. Before planning, the workflow verifies their exact key sets without
  printing or persisting Secret data.

The workflow does not copy production credentials into GitHub. After assuming
the branch-pinned role, it reads the existing Terraform-managed `cats-runtime`
Secret and `cats-rds-ca` ConfigMap and supplies those values back as sensitive
Terraform inputs. This is a deployment path for an already bootstrapped
environment; the first application install still needs the explicit secret
injection described above.

Before planning, the workflow extracts both PostgreSQL control-schema bounds
from the build and queries `control_schema_version` through a one-off in-cluster
`psql` Pod. It creates the Pod without attaching, waits for a terminal phase,
then reads its logs exactly once and checks the container exit code. The guarded
HA drill uses the same runner when it maps the PostgreSQL advisory-lock owner to
a control-plane Pod. This avoids `kubectl` attach fallback replaying a fast
command's output in either safety gate. A missing version table is the reviewed
fresh-schema case; cluster, scheduling, authentication and query failures all
fail closed. `cats-controld` opens only exact clean-slate authority schema 15;
it does not migrate an earlier stamp or partial catalog in place.
The disruptive drill separately uploads fixed-rate public-probe results and
Pod/EndpointSlice transition evidence; those artifacts contain no Secret
values or response bodies and are retained for 30 days for failure correlation.

Terraform deliberately creates neither Route v2 private bytes nor a DynamoDB
Route mirror. It deploys the Gateway ServiceAccount, Deployment and Service,
while a root-only provisioning channel creates the two immutable Kubernetes
Secrets before this workflow runs.

## Metal worker deployment boundary

The infrastructure stack also owns the worker release path. CI builds one
reviewed `linux/amd64` bundle, supplies its absolute path and SHA-256, and
Terraform uploads it under a content-addressed S3 key. The EC2 role may read
only worker artifacts and the dedicated Secrets Manager runtime secret.
An SSM State Manager association can download the bundle, verify the digest,
install the host binaries/unit, atomically update the Cloud Hypervisor guest
seed with the matching Guest Agent and systemd units, validate the canonical
cgroup-v2 mount root and restart `cats-worker`. The previous guest seed stays
at `rootfs.ext4.previous` for recovery. This machinery predates the current
clean-slate exact-SHA qualification and is not authorization for a rolling
upgrade of a nonempty worker.

The retired `cats admin node drain`/uncordon sequence and its orphan Cold-stop
behavior are historical V1 paths, not a compatibility fallback. Before applying
a current bundle, use a reviewed A23 policy revision to cordon the worker and
prove both that its assigned Desired set is empty and that a complete physical
inventory has no runtime or residue. The current Running-only completion claim
does not provide an in-place lifecycle drain. If the worker is not already
empty, the association must stay blocked pending a separately qualified
migration or replacement procedure.

The association independently refuses to change installed files while any
canonical `cats-cat-<digest>.slice` remains directly under the cgroup-v2 mount
root **or** any `cats-blockd` / `cloud-hypervisor` process is alive on the
host. The process-table check exists because a blockd can survive without a
Cat slice: a clean cgroup walk alone could miss the only authoritative copy
of an unpublished Relaxed journal. This process-table check remains a
fail-closed empty-Host guard; it does not prove the signed scanner, per-Cat
adoption or A23 cordon. Do not copy production binaries, patch the seed, or
edit `worker.env` manually; update the bundle digest or secret input and apply
Terraform only after the empty-Host precondition is independently closed.

Do not stop or restart a worker that still has Cats. ADR-0040 Host lock,
per-Cat units, bounded checkpoint and union inventory have landed for the
current-Desired Running path, but no current exact SHA has passed the combined
public-spawn PostgreSQL/Linux/systemd/KVM qualification. A controlled release
therefore still requires an independently proven empty, residue-free Host.

### When the empty-Host precondition cannot be proved

An orphan or assigned runtime cannot be discarded through a Node HTTP fallback.
Signed workers receive no `CATS_AUTH_TOKEN`, production does not expose
`/v1/jobs`, and the deployment must remain fail closed with the Host untouched.
Use a separately qualified lifecycle/fenced-cleanup procedure when it exists;
do not recreate the retired shared-bearer request by hand or treat an empty
legacy row as physical absence. For transient metadata-store failures, leave
the Host cordoned and unchanged until a complete current-authority scan can
close the precondition.

## PostgreSQL split runbook

The PostgreSQL adapter creates and migrates only its configured schema. For a
future dedicated usage database:

1. provision the target database through the platform Terraform state;
2. stop the single usage writer after a final checkpoint and record the source
   watermark;
3. `pg_dump`/restore the usage schema using an encrypted operator path;
4. compare checkpoint count, interval count, max sequence per source epoch and
   the recorded watermark;
5. change only `TF_VAR_usage_postgres_url`, review and apply the application
   plan;
6. replay from the immutable S3 archive, verify no gap or duplicate charge,
   then retire the old schema through a separate reviewed change.

Never use dual writers during the cutover.

## Local checks

These checks do not contact or mutate AWS/EKS. Run them locally before handing
off a Terraform change:

```sh
terraform fmt -check -recursive deploy/aws/terraform
terraform -chdir=deploy/aws/terraform/bootstrap init -backend=false
terraform -chdir=deploy/aws/terraform/bootstrap validate
terraform -chdir=deploy/aws/terraform/stacks/platform init -backend=false
terraform -chdir=deploy/aws/terraform/stacks/platform validate
terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure init -backend=false
terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure validate
terraform -chdir=deploy/aws/terraform/stacks/production-payments init -backend=false
terraform -chdir=deploy/aws/terraform/stacks/production-payments validate
terraform -chdir=deploy/aws/terraform/stacks/production-application init -backend=false
terraform -chdir=deploy/aws/terraform/stacks/production-application validate
terraform -chdir=deploy/aws/terraform/modules/usage-infrastructure init -backend=false
terraform -chdir=deploy/aws/terraform/modules/usage-infrastructure test
terraform -chdir=deploy/aws/terraform/stacks/production-infrastructure test
python3 deploy/aws/terraform/test-alert-recipient-privacy.py
python3 deploy/aws/preflight-alarm-recipients-fixture.py
python3 deploy/aws/run-controlled-alarm-recipient-test-fixture.py
```
