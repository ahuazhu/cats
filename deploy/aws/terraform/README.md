# Cats AWS Terraform

Terraform is the authoritative change path for the AWS usage infrastructure and
the Cats Kubernetes deployment described here. Running these configurations is
a production mutation: always review a saved plan in CI before apply.

No cloud resource is created merely by checking in this directory.

## Layout

| Directory | State boundary | Owns |
|---|---|---|
| `bootstrap/` | bootstrap state | Versioned, encrypted, private S3 state bucket |
| `stacks/platform/` | platform state | VPC, EKS cluster, RDS PostgreSQL, Route 53 zone, ACM certificate, ECR repository, bare-metal worker security group, GitHub Actions release role |
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

The ChunkStore bucket and the bare-metal instances themselves remain outside
Terraform. The instances are long-lived capacity referenced by id; the platform
state owns only the security group that positions them on the network.

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
terraform init -backend-config=backend.hcl
terraform plan -out=platform.tfplan
terraform apply platform.tfplan
```

Three things about this stack are easy to get wrong.

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
Identity role, associated only with the `cats-controld` ServiceAccount. The
gateway uses the namespace default ServiceAccount and receives no usage AWS
permissions. The replay policy remains unattached and is reserved for
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
The current application is one `Recreate` replica, so the table stores
checkpoints only. Add a conditional shard-lease protocol before running more
than one projector replica.

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
export TF_VAR_storage_postgres_url='postgresql://...'
export TF_VAR_usage_postgres_url='postgresql://...'
export TF_VAR_rds_ca_pem='-----BEGIN CERTIFICATE-----...'
export TF_VAR_stripe_secret_key='sk_live_...'
export TF_VAR_stripe_webhook_secret='whsec_...'

cd deploy/aws/terraform/stacks/production-application
cp backend.hcl.example backend.hcl
cp production.tfvars.example production.auto.tfvars
terraform init -backend-config=backend.hcl
terraform plan -out=production.tfplan
terraform apply production.tfplan
```

Terraform's `sensitive` flag only redacts normal CLI output. Secret values still
exist in state and in saved plans, which is why both require the same access
control as production credentials.

`storage_postgres_url` and `usage_postgres_url` are intentionally independent.
During the early shared-RDS phase they may point to the same instance/database,
while usage uses the separate `cats_usage` schema and preferably a dedicated
database role. Moving usage later only changes the usage DSN.

Set `stripe_enabled=true` and copy the non-secret `topup_price_ids` output into
`stripe_topup_price_ids`. Cats never credits a Checkout success redirect: only
a raw-body, HMAC-verified Stripe webhook can append a top-up. The runtime secret
also pins `CATS_STRIPE_LIVEMODE`, so test events cannot settle live credit (or
vice versa).

Set the usage stream, archive bucket and checkpoint table inputs from the
infrastructure stack outputs. All container images must include an immutable
`@sha256:...` digest. Changes to
the runtime Secret or RDS CA alter Pod template checksums and therefore trigger
a rollout. `cats-controld` remains one replica with `Recreate`, because its
control-resource SQLite file is on an RWO EBS PVC.

### Automatic main deployment

`Deploy production` starts after the `CI` workflow succeeds for a `main`
commit. It builds and pushes the control-plane image, pins the registry digest,
creates a saved application plan, applies that exact plan and waits for both
Deployments to report the same immutable image reference. A failed build,
plan, apply or rollout records a failed GitHub deployment.

Configure these non-secret repository variables:

- `AWS_REGION`, `AWS_ROLE_ARN` and `ECR_REPOSITORY`;
- `EKS_CLUSTER_NAME`;
- `TF_STATE_BUCKET` and `TF_STATE_APPLICATION_KEY`;
- `PRODUCTION_TFVARS_B64`, the Base64 encoding of the private non-secret
  application tfvars with `kubeconfig_*` and both image inputs omitted.

The workflow does not copy production credentials into GitHub. After assuming
the branch-pinned role, it reads the existing Terraform-managed `cats-runtime`
Secret and `cats-rds-ca` ConfigMap and supplies those values back as sensitive
Terraform inputs. This is a deployment path for an already bootstrapped
environment; the first application install still needs the explicit secret
injection described above.

Before planning, the workflow extracts both PostgreSQL control-schema bounds
from the build and queries `control_schema_version` through a one-off in-cluster
`psql` Pod. A missing version table is the reviewed fresh-schema case; cluster,
scheduling, authentication and query failures all fail closed. `cats-controld`
only opens stamped versions inside the same range.

ADR-0031 deliberately cut over without importing the old SQLite rows. The
application state removes the control-data PVC and its temporary DLM policy;
the final manual EBS snapshot remains the archive of the pre-cutover database.
Because Terraform can schedule that orphaned PVC destroy before the in-place
Deployment update that removes its mount, the production workflow handles this
one legacy edge explicitly: after saving the complete reviewed plan, it checks
for `cats-control-data`. If the claim is still mounted only by
`cats-controld`, the workflow verifies that the saved plan restores the
PostgreSQL-era Deployment to one replica, scales the old Deployment to zero,
waits until no Pod consumes the claim, and only then applies the saved plan. It
never removes the PVC protection finalizer or force-deletes the volume. Once a
state has crossed the cutover and the PVC is absent, the step is a no-op.

## Importing the existing Kubernetes deployment

Do not run the first application apply while the YAML-created objects are
outside state. Import every live object at its module address first, including:

- Namespace `cats`;
- ServiceAccount `cats/cats-controld`, Secret `cats/cats-runtime` and ConfigMap
  `cats/cats-rds-ca`;
- both Deployments and Services;
- IngressClassParams, IngressClass and Ingress.

Before import, export the live YAML and reconcile intentional differences.
After import, require a plan with no unexpected replacement or deletion. The
legacy files under `deploy/aws/k8s/` are migration references only and must not
be applied again.

The former `cats-auto-ebs` StorageClass and `cats-control-data` PVC are not
part of the PostgreSQL-era application state and must not be imported.

Terraform will additionally create `cats-gateway-runtime`, which exposes only
`CATS_AUTH_TOKEN` to the gateway. The gateway must not receive PostgreSQL or
WorkOS credentials.

## Metal worker deployment

The infrastructure stack also owns the worker release path. CI builds one
reviewed `linux/amd64` bundle, supplies its absolute path and SHA-256, and
Terraform uploads it under a content-addressed S3 key. The EC2 role may read
only worker artifacts and the dedicated Secrets Manager runtime secret.
An SSM State Manager association downloads the bundle, verifies the digest,
installs the host binaries/unit, atomically updates the Cloud Hypervisor guest
seed with the matching Guest Agent and systemd units, creates the delegated
metering cgroup root and restarts `cats-worker`. The previous guest seed stays
at `rootfs.ext4.previous` for recovery.

A worker release is a drain boundary. Before applying a new bundle:

1. run `cats admin node drain <node-id>`;
2. wait until `cats admin node get <node-id>` reports
   `state=cordoned cats=0 orphans=0`;
3. apply the reviewed infrastructure plan and wait for the SSM association to
   succeed;
4. run `cats admin node uncordon <node-id>`.

A drain acts on both the control plane's assignments and the agent's own
reported inventory: a Cat the agent runs that the control plane never assigned
there (an *orphan runtime*, ADR-0030) gets a Cold stop by its reported
identity, and the node does not reach `cordoned` while any orphan remains. So
`state=cordoned` genuinely means the node runs nothing.

The association independently refuses to change installed files while any Cat
PID remains in the worker's metering cgroups **or** any `cats-blockd` /
`cloud-hypervisor` process is alive on the host. The process-table check
exists because a blockd is not metered: with the Guests gone the cgroup walk
reads clean, yet `systemctl stop cats-worker` (default
`KillMode=control-group`) would kill a surviving blockd together with any
unpublished journal it holds — on a relaxed volume that journal is the only
authoritative copy. This is a fail-closed guard against bypassing the drain
runbook; it does not cordon the node itself and therefore is not a substitute
for step 1. Do not copy production binaries, patch the seed, or edit
`worker.env` manually; update the bundle digest or secret input and apply
Terraform.

### When the drain cannot converge

An orphan whose Cold stop is refused by storage fencing
(`root CAS conflict: expected generation N`) can never stop cleanly: its root
was superseded elsewhere, its local journal is stale and must not be
published. The drain deliberately does not escalate — whether to discard a
journal is an operator decision, not the control plane's. After confirming
the refusal is a CAS conflict (not a transient metadata-store error) in the
controller logs, discard that Cat explicitly through the node agent's job
API, which kills its processes and deletes its runtime directory **without
publishing**:

```sh
# CATS_AUTH_TOKEN as installed in the worker's runtime secret (worker.env).
curl -sS -X POST "http://<node-agent>/v1/jobs" \
  -H "Authorization: Bearer $CATS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"job_id":"manual-cleanup-<cat-id>","cat_generation":<reported-generation>,
       "action":"cleanup_cat","cat_id":"<cat-id>"}'
```

Use this only for Cats whose stop was refused by fencing. For any other
failure (usage spool, transient storage errors) let the drain retry: those
stops publish once the dependency recovers.

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

These checks do not contact or mutate AWS/EKS, and the `terraform` job in
`.github/workflows/ci.yml` runs the same set on every pull request:

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
```
