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

- EKS Pods: active-active `cats-controld` plus the separate active-active
  `cats-gatewayd` Route v2 public proxy. Control's machine-only mTLS listener
  is exposed through a distinct cluster-local Service on port 7443.
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
- One EKS Auto Mode ALB: exact configured control-plane hosts route to
  `cats-controld`; the one configured Endpoint wildcard routes only to
  `cats-gatewayd`. Both targets expose local `/healthz`.

The Terraform application stack creates the `cats-controld` and
`cats-gatewayd` ServiceAccounts, `cats-runtime` and `cats-rds-ca`;
secrets are injected by CI and remain protected in remote state. It also
renders the target ACM ARN and every public subnet into EKS Auto Mode ingress.
EKS Pod Identity grants the control plane only the Kinesis/S3/DynamoDB usage
permissions. Gateway has no ServiceAccount token, Pod Identity, shared Route
table or Control bearer. Do not create or patch Terraform-owned objects
manually.

### Route v2 artifact delivery

Private Route v2 bytes never enter Terraform variables, state, plans, process
arguments, environment variables or logs. Before planning, the approved
root-only credential workflow creates versioned immutable Kubernetes Secrets
in namespace `cats` and one scoped Secrets Manager secret for the workers.
Terraform receives only their opaque names/ARN. The deployment workflow checks
`.immutable == true` and exact key names without decoding or persisting data.

The Control Secret contains exactly seven keys:

- `gateway-workload-authority.v1.json`
- `gateway-client-ca-bundle.pem`
- `control-machine-server-certificate.pem`
- `control-machine-server-private-key.pem`
- `signer.v1.json`
- `public-key-ring.v1.json`
- `signer-private-key.pem`

The Gateway Secret contains exactly the frozen three keys:
`node-server-ca-bundle.pem`, `gateway-machine-client-certificate.pem` and
`gateway-machine-client-private-key.pem`. There is no fourth Gateway artifact
and no separate Control CA file: `node-server-ca-bundle.pem` must validate both
the Control server chain for
`cats-controld-route-v2.cats.svc.cluster.local` and every reviewed Node server
chain. A root init renderer copies each projected Secret into an in-memory
emptyDir so the main process sees real, single-link, root-owned files under a
root:root `0700` `/etc/cats/route-v2`; public material is `0644` and private
keys are `0600`. Main containers run as uid 0 only because the frozen reader
requires those exact owners/modes; both have a read-only root filesystem, no
privilege escalation and all Linux capabilities dropped.

The worker Secrets Manager `SecretString` is a JSON object with exactly six
non-empty base64 fields:
`public_key_ring_v1_json_b64`, `rotation_operator_trust_v1_json_b64`,
`gateway_client_ca_bundle_pem_b64`,
`node_machine_server_certificate_pem_b64` and
`node_machine_server_private_key_pem_b64`, plus the public
`node_server_ca_bundle_pem_b64`. The instance role can read only that
ARN (plus its already-scoped runtime/database secrets). Terraform also pins
the exact Secrets Manager version ID, so a later `AWSCURRENT` change cannot
alter a fresh Host's revision-1 bytes. The SSM transaction decodes, validates
and installs the six fixed Node files with the same owner,
directory and mode contract through the same Rust ring/rustls validator used
at daemon startup before starting `cats-noded`. The fixed operator trust then
authenticates adjacent public-ring delivery without giving Node a Control
credential; the production unit passes the
literal Route v2 listener `0.0.0.0:7444` and removes stale environment overrides.
A23 `node_transport_target` must therefore be the reviewed canonical
`https://<node-private-dns>:7444`, never the signed Runtime port 7301.

This wiring is initial revision 1 only. Kubernetes Secret names must end in
`-r1`, and the worker ARN must identify the exact
`cats-<environment>-route-v2-node-r1` secret in the expected partition,
account and region. A fresh Pod renders a
fresh emptyDir; a worker publishes `/etc/cats/route-v2` only when it is absent.
An existing worker directory is accepted only when the closed set, ownership,
modes, link counts and every byte are identical; any difference fails before
the deployment mutates installed binaries or units. Runtime G3 successor
delivery advances only one exact predecessor at a time through the durable
installer; full signed inventory remains the ACK authority.

The approved initial credential workflow is the offline, root-only command in
the exact release `cats` binary. Supply every reviewed private-DNS name that
will appear in an A23 `node_transport_target`; one Node certificate binds that
closed set. The default `/usr/bin/openssl` is used only here to issue X.509
certificates and is never invoked by Control, Gateway or Node at runtime.

```sh
sudo /approved/staged-worker/cats --json admin runtime-provisioner route-v2-r1 generate \
  --output /approved/credentials/route-v2-r1 \
  --node-server-dns "$metal_1_private_dns" \
  --node-server-dns "$metal_2_private_dns" \
  --control-secret-name cats-route-v2-control-r1 \
  --gateway-secret-name cats-route-v2-gateway-r1 \
  --node-secret-name cats-production-route-v2-node-r1 \
  --release-commit-sha "$source_sha" \
  --openssl /usr/bin/openssl

sudo /approved/staged-worker/cats --json admin runtime-provisioner route-v2-r1 verify \
  --input /approved/credentials/route-v2-r1 \
  --node-server-dns "$metal_1_private_dns" \
  --node-server-dns "$metal_2_private_dns" \
  --control-secret-name cats-route-v2-control-r1 \
  --gateway-secret-name cats-route-v2-gateway-r1 \
  --node-secret-name cats-production-route-v2-node-r1 \
  --release-commit-sha "$source_sha"

sudo /approved/staged-worker/cats-route-v2-node-r1-validator \
  --directory /approved/credentials/route-v2-r1/node
```

Generation creates no cloud resource. It writes five exact root-owned `0700`
directories: retained CA and offline rotation private material, Control
eight-file set, Gateway three-file set, Node six-file set, and three provider
inputs. Before returning it
reopens every file, checks the canonical signer/ring and Gateway policy, proves
the CA/key pairs, passes the Node set through the production candidate reader,
completes TLS 1.3 mutual-auth handshakes for Control and every Node DNS name,
and byte-compares the provider inputs with those validated role files. The
separate validator command above reuses the Node daemon's ring/rustls
composition before any provider input is submitted. Standard output contains
identifiers and SHA-256 receipts only.

Create the two immutable Kubernetes Secrets and the one versioned Secrets
Manager value directly from the root-only provider inputs; do not transcribe or
decode them:

```sh
kubectl create --filename /approved/credentials/route-v2-r1/provider/control-secret.v1.json
kubectl create --filename /approved/credentials/route-v2-r1/provider/gateway-secret.v1.json
aws secretsmanager create-secret \
  --cli-input-json file:///approved/credentials/route-v2-r1/provider/node-secret.v1.json
```

Record the returned worker Secret ARN and exact version ID in the infrastructure
stack inputs. The retained `authority/route-v2-ca-private-key.pem` and all three
provider JSON files contain secret material; keep the whole output directory on
the approved root-only credential channel and never add it to a release bundle,
Terraform input, shell environment or log.

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
bootstrap/development helper. It requires
`CATS_ROUTE_V2_NODE_ARTIFACT_DIR=/approved/root-only/node-route-v2` before it
changes packages, installed files or services. The source must be one real
directory containing exactly the fixed six Node artifacts documented above.
The helper stages and validates the canonical ring, CA sequence and matching
Node certificate/private key, then installs the closed set at
`/etc/cats/route-v2` before enabling `cats-worker`. Cloud Hypervisor stays under
`/opt/cats/bin` so it does not replace a host-wide binary used by another
workload. The S3 adapter uses the EC2 instance role and refreshes its temporary
credentials; no long-lived AWS key is stored in `worker.env`.

The release pipeline implements the frozen
[Agent Registration and Internal Transport v1](../../docs/specs/agent-registration-transport-v1.md) plus
[Runtime Composition Artifacts v1](../../docs/specs/runtime-composition-artifacts-v1.md).
One release build puts the same exact
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
  --gateway-image registry.example/cats/gateway:exact-tag \
  --push
```

It exports and rechecks the exact Git tree, invokes the Guest-image generator
once, feeds that one closed payload to the Control and worker Dockerfiles,
builds the independent credential-refresher target and Gateway image, extracts
the receipt/manifest from the final Control image, both credential-refresher
programs from its final image, the `cats-gatewayd` executable from the final
Gateway image and the complete Guest payload from the worker artifact, and
verifies every closed set. The
canonical `release-manifest.v1.json` binds source commit/tree/fingerprint,
build-input fingerprints, Guest release ID, Control, credential-refresher and
Gateway OCI/config digests, extracted program digests, Gateway binary digest
and the worker tar SHA-256. Without `--push`, all three images remain only in
the local Docker store and the manifest records all three registry
verifications as false; that output is useful for dry-run
qualification but is not a registry deployment receipt.

To keep AWS credentials off the native build Host, replace `--push` with
`--export-images`. The output then also contains
`cats-control-plane-image.tar`, `cats-credential-refresher-image.tar`,
`cats-gateway-image.tar` and `SHA256SUMS`.
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
  --credential-refresher-image "$ECR_REPOSITORY:refresher-$CUTOVER_ID" \
  --gateway-image "$ECR_REPOSITORY:gateway-$CUTOVER_ID"
```

`tools/deploy-production-release.py` consumes only that completed package. Its
canonical config names the exact AWS cell, EKS context, separate Terraform
state keys, Control schema, both ordered tfvars lists and the complete
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
{"application_state_key":"cats/production/application.tfstate","application_tfvars":["/approved/root-only/application.tfvars.json","/approved/root-only/application-secrets.tfvars.json"],"aws_region":"us-east-1","control_postgres_schema":"cats_r26","eks_cluster_name":"cats-production","expected_account_id":"123456789012","expected_aws_partition":"aws","infrastructure_state_key":"cats/production/infrastructure.tfstate","infrastructure_tfvars":["/approved/root-only/infrastructure.tfvars.json"],"kubeconfig_context":"cats-production","kubeconfig_path":"/approved/root-only/kubeconfig","namespace":"cats","schema_version":1,"terraform_state_bucket":"cats-terraform-state-123456789012-us-east-1","worker_instances":{"metal-1":"i-0123456789abcdef0","metal-2":"i-0123456789abcdef1"}}
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
  --boot-image-digest sha256:<GOLDEN_ROOT_DIGEST> \
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

The worker bundle also carries the exact
[`old-host-positive-stop.py`](old-host-positive-stop.py) bytes bound as a
manual-build input. That program emits the
[Proposed E13 evidence format](../../docs/specs/old-host-positive-stop-v1.md);
shipping it does not make the format accepted and does not remove the
production reset's mechanical block.

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

The same central provisioner must put the reviewed private-DNS Node listener into the A23 policy as canonical
`node_transport_target` (`https://<lowercase-dns-name>:<explicit-port>`). It is generated from fleet/IaC inventory,
not from worker registration, observation, IMDS, the listener source address, or legacy `nodes.agent_url`.
Changing it uses an A23 policy revision while the Node is cordoned and has no assigned Desired runtimes; credential
rotation preserves it, and retirement makes it unavailable to the Route Grant v2 signer.
This contract uses the exact clean-slate Control Store authority schema version 15. An existing earlier schema is
not altered in place and refuses startup; provision or recreate an empty version-15 schema before starting any new
Control replica, with no mixed-version rolling window.

Every Host-side worker mutation runs under the single
`/run/lock/cats/worker-deployment.lock` descriptor. The Guest activation journal remains durable across binary,
configuration, unit and seed replacement, candidate start and registration-backed readiness; only then is it
committed. A crash before commit restores the exact previous Guest set but keeps the worker stopped and the
journal retained until the complete worker transaction is replayed. Direct `systemctl start` and standalone
`update-guest-seed` cannot bypass this boundary.

### Runtime-cutover composition gate

The signed cutover contains the A19 registration and A20 signed Desired and
observation routes. Only an accepted new-sequence observation renews the exact
current `AgentSession`; exact replay does not. Node-loss liveness reads that
signed session/observation state, and `/v1/nodes/heartbeat` is absent from the
production route map (a service or admin bearer request receives plain 404 and
writes nothing).

This is still not a standalone deployable release: the former zero runtime effect
placeholder is gone, but the combined production-PG-to-physical and Linux/metal
qualification is still open. The production Node composes the installed
eleven-source clean-slate scanner, the signed per-Cat reconciler and one shared
route-admission registry. Local readiness stays closed with HTTP 503 until a
complete inventory has been accepted for the current AgentSession; incomplete
or conflicting evidence is never promoted to a complete observation. The
shared-bearer heartbeat and
legacy NodeJob listener are not rollout or compatibility options. Route v2
machine ingress, adjacent ring delivery and the Route command runner are
mandatory. The provisioner must install the reviewed signing ring and mTLS
artifacts through the validated revision-1 transaction; either unit fails
before lifecycle/inventory work if those artifacts, its fixed listener or the
HTTPS rotation origin is missing. The exact current evidence endpoint is recorded in
[`architecture-cross-review.md`](../../docs/architecture-cross-review.md#当前跨组件证据边界).

The worker builds an optimized Ubuntu 24.04 Guest: direct kernel, a minimal
BusyBox initramfs used only for `switch_root`, and an Ubuntu minbase golden root
with systemd as PID 1. Root growth, deterministic tap setup and the Guest Agent
are early units ordered before `sysinit.target`; ordinary enabled user services
start normally through `multi-user.target`. The visible Guest includes
apt/curl/wget/git; cloud-init, snapd, LXD, wait-online, package timers and the
unused serial getty are not on the Cold-to-Agent readiness path. Each Cat gets
an isolated tap `/30` with outbound host NAT; host, VPC-private and cloud
metadata destinations are blocked before the general egress allow rule.
Every Cat still has the stable Endpoint identity in control truth, but public
Endpoint traffic intentionally remains unavailable in this deployment until
the reviewed signing ring, Gateway/Node mTLS artifacts, listener configuration
and public proxy are installed and qualified together.

`cats-noded` detects the host's logical CPU and memory totals when it starts;
the administrator console reports those schedulable totals plus sampled host
CPU, memory and state-filesystem disk utilization. `CATS_NODE_CPUS` and
`CATS_NODE_MEMORY_MIB` are optional lower scheduling ceilings for hosts that
reserve resources for other workloads.

#### Historical V1 lifecycle evidence

The repository still contains the pre-cutover V1 lifecycle implementation and
its recorded experiments: a private file-backed memory zone, Suspended
page-out with `process_madvise(MADV_PAGEOUT)`, persisted auto-tier timers, and
the Running/Suspended/Warm/Cold test path. Those facts belong to the exact
revisions that produced the retained evidence. The production clean-slate
router does not mount the legacy NodeJob listener, and the current completion
claim is limited to the current-Desired Running path. Do not use the old
auto-tier path as evidence that the signed full lifecycle is composed.

The old controller's startup grace only delayed marking an expired-heartbeat
Node Lost; it never made timeout an isolation proof. In the signed production
composition, an absent or expired AgentSession closes admission and emits a
liveness warning without rewriting Cat placement or fencing storage. A new
writer still requires an externally established `HostFenceEvent` and the
per-volume authorization/CAS path, which remain separate qualification work.

The control resource database lives in managed PostgreSQL. `cats-controld`
runs at least two API replicas on distinct Kubernetes nodes with a rolling
strategy and a disruption budget. Required hostname anti-affinity makes a
second replica stay Pending until EKS Auto Mode supplies another eligible node;
the scheduler cannot silently co-locate both replicas on one node. A
terminating control-plane Pod stays alive in `preStop` for 15 seconds while
Kubernetes removes it from EndpointSlices and the EKS Auto Mode ALB drains the
target; SIGTERM then closes its admissions and HTTP server within the
30-second termination grace period. The production clean-slate composition
does not start the retired NodeJob reconciler or billing-enforcer singleton.
Existing API-replica and advisory-lock tests do not by themselves prove a
current public-spawn PostgreSQL-to-physical runtime takeover.

The authority database carries exact clean-slate schema version 15.
`cats-controld` does not migrate an earlier authority schema in place and fails
closed on any other stamp or catalog shape. The pre-cutover
`cats-control-data` PVC is no longer part of the runtime; its final snapshot
remains only as an archive.

The existing `verify-control-plane-ha.yml` workflow and its bounded probes,
safe-header collection, Pod-UID recheck and PDB-governed eviction are retained
as historical V1 control-plane HA evidence. Its reconciler-owner oracle targets
the retired singleton and therefore must not be run from `main` or cited as a
clean-slate runtime qualification. A replacement must use the production
public spawn, schema 15 and the signed Runtime composition, preserve the exact
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
