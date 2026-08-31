# AWS deployment

Terraform under [`terraform/`](terraform/) is now the authoritative source for
new AWS usage resources and the Kubernetes production deployment. Existing
EKS, RDS, VPC, ACM, ECR, ChunkStore and bare-metal resources must be represented
from their exact live configuration and imported before Terraform changes
them. See
[`terraform/README.md`](terraform/README.md) and ADR-0012.

The platform-to-usage SNS destination, confirmed recipient preflight and
controlled delivery evidence are operated through the
[production alarm recipient runbook](alarm-recipients-runbook.md). A created
Terraform subscription alone is not paging evidence.

Production-shaped split:

- EKS Pods: active-active `cats-controld` and the supporting usage and
  credential-refresh workloads.
- EC2 bare metal: only `cats-noded`, `cats-blockd`, Cloud Hypervisor and guest
  assets. It is not an EKS node.
- RDS PostgreSQL: authoritative ChunkStore roots, leases and fencing epochs.
- S3: immutable durable ChunkStore objects.
- Usage billing: `cats-controld` publishes attributed cumulative checkpoints to
  Kinesis; its projector writes 50-second/4-MiB/1000-record NDJSON batches to a
  seven-year Object Lock S3 archive, updates the PostgreSQL `cats_usage`
  projection and advances a DynamoDB checkpoint last.
- Prepaid collection: the official Stripe Terraform provider owns one Cats
  credit Product, fixed $10/$25/$50/$100 one-time Prices, and the signed
  webhook endpoint. PostgreSQL stores append-only signup grants, top-ups and
  refund reversals; Stripe is collection infrastructure, not the balance or
  usage truth.
- One EKS Auto Mode ALB: configured control-plane hosts route to
  `cats-controld`, which exposes local `/healthz`.

The Terraform application stack creates the `cats-controld` ServiceAccount,
`cats-runtime` and `cats-rds-ca`;
secrets are injected by CI and remain protected in remote state. It also
renders the target ACM ARN and every public subnet into EKS Auto Mode ingress.
EKS Pod Identity grants the control plane only the Kinesis/S3/DynamoDB usage
permissions. Do not create or patch Terraform-owned objects manually.

The worker does not hold a copy of the database password. Set
`database_master_user_secret_arn` and the non-secret half of the DSN in
`worker_managed_environment`, and `render-postgres-url` composes
`/run/cats/postgres-url` from the RDS managed master secret before every
`cats-worker` start, with `cats-postgres-url.timer` refreshing it every fifteen
minutes in between. `cats-noded` and every `cats-blockd` it spawns read that
file at connect time, so a managed rotation reaches the fleet without a deploy
and without a restart. Leaving the ARN unset keeps the old behaviour — a static
`CATS_POSTGRES_URL` in `worker.env` — which is what a rotation silently
invalidates: established connections keep serving while every new one fails,
so the fleet looks healthy and only new Cats break.

The platform stack also creates the TLS-only, multi-AZ RDS Proxy selected by
ADR-0034. Applying that stack alone does not cut traffic over. After its target
is `AVAILABLE`, set the `RDS_PROXY_ENDPOINT` GitHub repository variable to the
`database_proxy_endpoint` output; the application workflow then changes only
the storage/control DSN and enables server-verified session defaults. The usage
DSN remains direct. For workers, set `CATS_POSTGRES_HOST` to the same endpoint
and `CATS_POSTGRES_SESSION_SETUP=server-verified` in
`worker_managed_environment`. The former V1 one-worker cordon/drain sequence is
not a clean-slate rollout authority: until the current exact release passes its
physical qualification, apply this change only to a cordoned, empty,
residue-free worker. Removing those two settings restores the direct endpoint
and `client` mode without changing credentials.

The existing worker release machinery uses the Terraform-managed artifact bucket,
Secrets Manager secret and SSM State Manager association. The bundle digest is
verified before installing `cats-noded`, `cats-blockd`, `cats-guest-agent`,
`render-postgres-url` and the worker systemd units. The same bundle carries the Guest Agent and standalone
Guest systemd units as a release-owned Guest seed payload. The association patches them
into a private copy of `rootfs.ext4`, verifies the ext4 image, preserves
`rootfs.ext4.previous`, atomically replaces the seed and immediately restarts
`cats-worker`. The updater also normalizes release-owned Guest invariants that
must be repaired in already-built seeds, including a world-readable
`/etc/resolv.conf` for APT's unprivileged resolver worker. The restart is
required, not cosmetic, because subsequent Guests must use one internally
consistent release receipt and Guest payload. This seed is not the product
Golden Root cache: Root provision uses the independent, digest-checked
`/var/lib/cats/golden-root-cache/rootfs.ext4` single slot and fills it only from
the immutable remote image namespace. Existing Cats keep their current root
until they are recreated. This installer behavior predates
the clean-slate exact-SHA qualification; the association must not be enabled as
a rolling current-runtime upgrade until the gate below is green.

The bundle carries the one CI-built, manifest-bound Guest kernel, optional
initramfs and runtime receipt; a Host-local rebuild is not release input and
does not qualify as rollback. `metal/install-worker.sh` remains a
bootstrap/development helper. Cloud Hypervisor stays under
`/opt/cats/bin` so it does not replace a host-wide binary used by another
workload. The S3 adapter uses the EC2 instance role and refreshes its temporary
credentials; no long-lived AWS key is stored in `worker.env`.

The release pipeline implements the current
[Control/Node semantic protocol](../../docs/control-node-semantic-protocol.md) and
[A23 provisioner contract](../../docs/specs/a23-production-provisioner-tooling-v1.md). One release build puts the same exact
`guest-runtime-profile.v1.json` bytes in the Control artifact and worker bundle, install them at
`/opt/cats/release/guest-runtime-profile.v1.json`, and ship the pinned Guest kernel and optional initramfs named by
that receipt. Target worker systemd `ExecStart` and Control Kubernetes container args both pass
`--guest-runtime-profile-receipt-file /opt/cats/release/guest-runtime-profile.v1.json`; missing or mismatched
receipt/boot files fail closed. Rebuilding from the Host kernel is not a fallback.

When GitHub Actions is unavailable, `tools/build-manual-release.sh` is the
repository-owned artifact builder. Run it from a clean checkout of the exact
40-hex commit on a native x86_64 Linux build Host with the Guest-image tools,
Docker Buildx and passwordless or interactive `sudo` available:

```sh
deploy/aws/tools/build-manual-release.sh \
  --source-sha "$(git rev-parse HEAD)" \
  --output /approved/private-output/cats-release \
  --image registry.example/cats/control-plane:exact-tag \
  --credential-refresher-image registry.example/cats/credential-refresher:exact-tag \
  --push
```

It exports and rechecks the exact Git tree, invokes the Guest-image generator
once, feeds that one closed payload to the Control and worker Dockerfiles,
builds the independent credential-refresher image, extracts the
receipt/manifest from the final Control image, both credential-refresher
programs from its final image and the complete Guest payload from the worker artifact, and
verifies every closed set. The
canonical `release-manifest.v1.json` binds source commit/tree/fingerprint,
build-input fingerprints, Guest release ID, Control and credential-refresher
OCI/config digests, extracted program digests and the worker tar SHA-256.
Without `--push`, both images remain only in the local Docker store and the manifest records both registry
verifications as false; that output is useful for dry-run
qualification but is not a registry deployment receipt.

To keep AWS credentials off the native build Host, replace `--push` with
`--export-images`. The output then also contains
`cats-control-plane-image.tar`, `cats-credential-refresher-image.tar` and
`SHA256SUMS`.
Those files are transport only: the unchanged manifest and its independently
recorded SHA-256 remain the authority. On an approved x86_64 operator Host with
Docker Buildx and existing ECR credentials, publish without rebuilding:

```sh
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
deploy/aws/tools/publish-manual-release.sh \
  --release /approved/private-output/cats-release \
  --manifest-sha256 sha256:REPLACE_WITH_APPROVED_MANIFEST_SHA256 \
  --output-manifest /approved/private-output/release-manifest.registry-verified.v1.json
```

The helper checks the transport sums, verifies each closed OCI archive against
the existing manifest, loads and inspects linux/amd64 identity, pushes the three
exact manifest references, verifies the registry digests and asks the existing
manual-release verifier to produce the registry-verified manifest. It neither
builds an artifact nor uploads the worker bundle. Pass the same
`cats-worker.tar.zst` and its manifest `bundle_sha256` to the existing
`production-infrastructure` Terraform inputs; that module publishes the bundle
at `worker/<sha256>/cats-worker.tar.zst` in its existing artifact bucket.
The builder never invokes Terraform, Kubernetes or a production service.

For the production AWS cell, `tools/package-production-release.py` composes
that same boundary without giving the native build Host registry credentials.
It proves the reviewed AWS account and build-Host identity, publishes the exact
source bundle, submits one SSM build, retains the content-addressed transport,
downloads it by exact S3 version and SHA-256, then publishes all three OCI
archives from the operator Host. The output is a new root containing the source
publication evidence, immutable native build result, transport, unmodified
release tree, registry-verified manifest and
`production-package-receipt.v1.json`. It stops before Terraform, Kubernetes,
Node provisioning or product mutation:

```sh
deploy/aws/tools/package-production-release.py \
  --source-repository "$(pwd -P)" \
  --source-sha "$(git rev-parse HEAD)" \
  --output /approved/private-output/production-package \
  --expected-account-id "$AWS_ACCOUNT_ID" \
  --aws-region us-east-1 \
  --build-host-instance-id "$BUILD_HOST_INSTANCE_ID" \
  --source-bucket "$SOURCE_BUCKET" \
  --source-kms-alias-arn "$SOURCE_KMS_ALIAS_ARN" \
  --artifact-bucket "$BUILD_ARTIFACT_BUCKET" \
  --control-image "$ECR_REPOSITORY:control-$CUTOVER_ID" \
  --credential-refresher-image "$ECR_REPOSITORY:refresher-$CUTOVER_ID"
```

`tools/deploy-production-release.py` consumes only that completed package. Its
canonical config names the exact AWS cell, EKS context, separate Terraform
state keys, Control schema, current qualified default Golden Root digest, both ordered tfvars lists and the complete
worker-name-to-instance map. Secret tfvars remain external root-only files;
the deployer records their config digest but never copies their bytes into a
receipt. The application tfvars must already contain the current immutable
Route/identity artifact names and all provider inputs, while infrastructure
tfvars contain the worker role, Route Node Secret ARN/version and non-secret
managed environment. Package-derived image and worker values are appended as
the final Terraform overrides and cannot be replaced by those files.

The config is canonical JSON with this exact shape (replace every example
value and use resolved absolute file paths):

```json
{"application_state_key":"cats/production/application.tfstate","application_tfvars":["/approved/root-only/application.tfvars.json","/approved/root-only/application-secrets.tfvars.json"],"aws_region":"us-east-1","control_postgres_schema":"cats_r26","default_boot_image_digest":"sha256:<CURRENT_QUALIFIED_GOLDEN_ROOT_DIGEST>","eks_cluster_name":"cats-production","expected_account_id":"123456789012","expected_aws_partition":"aws","infrastructure_state_key":"cats/production/infrastructure.tfstate","infrastructure_tfvars":["/approved/root-only/infrastructure.tfvars.json"],"kubeconfig_context":"cats-production","kubeconfig_path":"/approved/root-only/kubeconfig","namespace":"cats","schema_version":1,"terraform_state_bucket":"cats-terraform-state-123456789012-us-east-1","worker_instances":{"metal-1":"i-0123456789abcdef0","metal-2":"i-0123456789abcdef1"}}
```

The controller deliberately separates saved-plan creation from apply. Both
plan JSON files can contain sensitive Terraform values and therefore stay in
the mode-0700 plan directory:

```sh
deploy/aws/tools/deploy-production-release.py plan \
  --source-repository "$(pwd -P)" \
  --package /approved/private-output/production-package \
  --config /approved/root-only/production-deployment-config.v1.json \
  --output /approved/root-only/production-plan

deploy/aws/tools/deploy-production-release.py apply \
  --source-repository "$(pwd -P)" \
  --package /approved/private-output/production-package \
  --config /approved/root-only/production-deployment-config.v1.json \
  --plan-directory /approved/root-only/production-plan \
  --output /approved/evidence/production-apply
```

`apply` rehashes both saved plans and the exact config/package receipt, applies
the application first, proves the Control and credential-refresher image pins,
then applies the worker bundle. Terraform
waits for every explicitly named SSM association; a final read-only SSM probe
requires the installed bundle receipt and active `cats-worker.service` on each
Host. The deployer does not uncordon a Node, change mutation admission or run a
product E2E.

After the official signed `qualification-begin` flow has installed a bounded
Qualification admission for one exact Workspace, use
`tools/production-cat-lifecycle-e2e.py` to exercise only public product
actions. The driver requires that unexpired Begin framework receipt, keeps the
Workspace bearer in a caller-owned mode-0600 file and passes it to the CLI only
through `CATS_TOKEN`. It retains every canonical product response separately:

```sh
deploy/aws/tools/production-cat-lifecycle-e2e.py \
  --cats-cli /approved/bin/cats \
  --api-url https://cats.run \
  --token-file /approved/root-only/e2e-workspace-token \
  --qualification-begin-receipt /approved/evidence/qualification/production-mutation-qualification-begin.receipt.json \
  --workspace-id <EXACT_WS_ID> \
  --cat-name release-e2e-<CUTOVER_ID> \
  --disk-name release-disk-<CUTOVER_ID> \
  --disk-size 1GiB \
  --mount-path /data \
  --sleep-state suspend \
  --sleep-state warm \
  --sleep-state cold \
  --output /approved/evidence/production-cat-e2e
```

The driver uses only the clean-slate synchronous slug protocol. It creates and
retries one PersistentDisk and one mounted Cat, checks all three sleep states
and their semantic replays, exercises Cold detach/attach, returns through the
Guest mount-ready barrier, destroys both resources, and proves that each slug
can immediately name a new immutable resource identity. If any step fails, the
driver leaves the exact resources and partial evidence in place and does not
attempt an implicit destructive cleanup. Close and
terminalize Qualification through `production-mutation-admission.py` after the
E2E result is retained.

The application rollout also mounts the central provisioner's canonical public
trust bundle as the root-owned regular file
`/etc/cats/identity/runtime-provisioner-trust.v1.json` and passes exactly
`--runtime-provisioner-trust-file /etc/cats/identity/runtime-provisioner-trust.v1.json`.
The bundle checksum forces a Pod rollout; each replica pins it at startup and
persists or exact-replays its monotonic trust revision before opening the
administrator listener.

The worker artifact also contains the exact release `cats` binary. Before the
first worker association, the operator runs
[`provision-cordoned-nodes.py`](provision-cordoned-nodes.py) once. It stages the
digest-pinned CLI through SSM, performs the offline Host-local
prepare/export, applies each public identity through the official signed
`admin runtime-node provision` command, returns only the public apply result
to that Host, activates it and writes exact-replay evidence. The provisioner
private key never enters SSM, Terraform, a Node environment or an argument on
the Node. The frozen crash-safe contract is
[A23 Production Provisioner Tooling v1](../../docs/specs/a23-production-provisioner-tooling-v1.md).

The `--nodes` file is a JSON array. Every entry contains exactly `node_id`,
`instance_id`, `host_provider`, `host_partition`, `host_account_id`,
`host_region`, `immutable_host_id`, `state_path_id`, `credential_id` and the
absolute `policy_file`. Each policy must be canonical initial revision 1 and
`cordoned`. Run the offline fixture after changing the orchestration:

```sh
python3 deploy/aws/provision-cordoned-nodes-fixture.py
```

The same cutover provisioner installs the canonical root-only local identity at
`/etc/cats/identity/node-identity.v1.json`, with its matching per-Node key and credential ID. `cats-noded`
derives `node_id`, immutable Host identity and `/var/lib/cats/node/<state_path_id>` only from that artifact; the
worker name, advertise address and IMDS are not registration identity. The shared Guest payload has the exact
closed layout and manifest defined by the composition contract; Control and worker artifacts must report one
matching immutable release ID before either can be deployed.

Every Host-side worker mutation runs under the single
`/run/lock/cats/worker-deployment.lock` descriptor. The Guest activation journal remains durable across binary,
configuration, unit and seed replacement, candidate start and registration-backed readiness; only then is it
committed. A crash before commit restores the exact previous Guest set but keeps the worker stopped and the
journal retained until the complete worker transaction is replayed. Direct `systemctl start` and standalone
`update-guest-seed` cannot bypass this boundary.

The worker builds an optimized Ubuntu 24.04 Guest: direct kernel, a minimal
BusyBox initramfs used only for `switch_root`, and an Ubuntu minbase golden root
with systemd as PID 1. Root growth, deterministic tap setup and the Guest Agent
are early units ordered before `sysinit.target`; ordinary enabled user services
start normally through `multi-user.target`. The visible Guest includes
apt/curl/wget/git; cloud-init, snapd, LXD, wait-online, package timers and the
unused serial getty are not on the Cold-to-Agent readiness path. Each Cat gets
an isolated tap `/30` with outbound host NAT; host, VPC-private and cloud
metadata destinations are blocked before the general egress allow rule.
The semantic Control store exposes one current ingress target per Cat. Public
hostname, TLS and Gateway transport are outside the current deployment
contract and are not supplied by this stack.

`cats-noded` detects the host's logical CPU and memory totals when it starts;
the administrator console reports those schedulable totals plus sampled host
CPU, memory and state-filesystem disk utilization. `CATS_NODE_CPUS` and
`CATS_NODE_MEMORY_MIB` are optional lower scheduling ceilings for hosts that
reserve resources for other workloads.

The control resource database lives in managed PostgreSQL. `cats-controld`
runs at least two API replicas on distinct Kubernetes nodes with a rolling
strategy and a disruption budget. Required hostname anti-affinity makes a
second replica stay Pending until EKS Auto Mode supplies another eligible node;
the scheduler cannot silently co-locate both replicas on one node. A
terminating control-plane Pod stays alive in `preStop` for 15 seconds while
Kubernetes removes it from EndpointSlices and the EKS Auto Mode ALB drains the
target; SIGTERM then closes its admissions and HTTP server within the
30-second termination grace period. Existing API-replica and advisory-lock tests do not by themselves prove a
current public-spawn PostgreSQL-to-physical runtime takeover.

The authority database carries exact clean-slate schema version 19.
`cats-controld` does not migrate an earlier authority schema in place and fails
closed on any other stamp or catalog shape. The pre-cutover
`cats-control-data` PVC is no longer part of the runtime; its final snapshot
remains only as an archive.

The existing `verify-control-plane-ha.yml` workflow and its bounded probes,
safe-header collection, Pod-UID recheck and PDB-governed eviction are retained
as historical V1 control-plane HA evidence. Its reconciler-owner oracle targets
the retired singleton and therefore must not be run from `main` or cited as a
clean-slate runtime qualification. A replacement must use the production
public spawn, schema 19 and the synchronous semantic composition, preserve the exact
tested SHA, and pass before this boundary is promoted.

The usage ledger has the same rule for the same reason. ADR-0018 replaced the V1
`project` ownership column with `workspace_id` on usage rows and `account_id` on
funds rows and shipped no column-rename migration, so an existing `cats_usage`
schema must be recreated or `CATS_USAGE_POSTGRES_SCHEMA` pointed at a new name.
Nothing is dropped automatically: history being disposable is not a licence for
this code to destroy a credit ledger at startup, so the wipe stays an explicit
operator action.

Check the exact version before the first deploy of a build whose `SCHEMA_VERSION` moved.
Bumping that constant is what declares a control-plane schema incompatible; a
schema change that forgets to bump it lets an old database open as if it were
current.
