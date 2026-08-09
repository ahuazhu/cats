# AWS deployment

Terraform under [`terraform/`](terraform/) is now the authoritative source for
new AWS usage resources and the Kubernetes production deployment. Existing
EKS, RDS, VPC, ACM, ECR, ChunkStore and bare-metal resources must be represented
from their exact live configuration and imported before Terraform changes
them. See
[`terraform/README.md`](terraform/README.md) and ADR-0012.

Production-shaped split:

- EKS Pods: `cats-controld` (portal, user console, admin console and API) and
  `cats-gatewayd`.
- EC2 bare metal: only `cats-noded`, `cats-blockd`, Cloud Hypervisor and guest
  assets. It is not an EKS node.
- RDS PostgreSQL: authoritative ChunkStore roots, leases and fencing epochs.
- S3: immutable durable ChunkStore objects.
- Endpoint continuity: a regional DynamoDB table replicates only short-lived,
  already-signed Route Grants across `cats-gatewayd` replicas; Nodes remain the
  authorization verifier.
- Usage billing: `cats-controld` publishes attributed cumulative checkpoints to
  Kinesis; its projector writes 50-second/4-MiB/1000-record NDJSON batches to a
  seven-year Object Lock S3 archive, updates the PostgreSQL `cats_usage`
  projection and advances a DynamoDB checkpoint last.
- Prepaid collection: the official Stripe Terraform provider owns one Cats
  credit Product, fixed $10/$25/$50/$100 one-time Prices, and the signed
  webhook endpoint. PostgreSQL stores append-only signup grants, top-ups and
  refund reversals; Stripe is collection infrastructure, not the balance or
  usage truth.
- One EKS Auto Mode ALB: the user site at `cats.run`, the operator site at
  `ops.cats.run`, legacy-host redirects and the endpoint wildcard.

The Terraform application stack creates the `cats-controld` and
`cats-gatewayd` ServiceAccounts, `cats-runtime` and `cats-rds-ca`;
secrets are injected by CI and remain protected in remote state. It also
renders the target ACM ARN and every public subnet into EKS Auto Mode ingress.
EKS Pod Identity grants the control plane only the Kinesis/S3/DynamoDB usage
permissions. A separate least-privilege Gateway identity may read and write
only the signed Route Grant table. Do not create or patch these objects manually.

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
`worker_managed_environment`, then use the existing one-worker cordon/drain
release sequence. Removing those two settings restores the direct endpoint and
`client` mode without changing credentials.

Production worker releases use the Terraform-managed artifact bucket,
Secrets Manager secret and SSM State Manager association. The bundle digest is
verified before installing `cats-noded`, `cats-blockd`, `cats-guest-agent`,
`render-postgres-url` and the worker systemd units. The same bundle carries the Guest Agent and standalone
Guest systemd units as a golden-root payload. The association patches them
into a private copy of `rootfs.ext4`, verifies the ext4 image, preserves
`rootfs.ext4.previous`, atomically replaces the seed and immediately restarts
`cats-worker`. The updater also normalizes release-owned Guest invariants that
must be repaired in already-built seeds, including a world-readable
`/etc/resolv.conf` for APT's unprivileged resolver worker. The restart is
required, not cosmetic:
`ensure_image_published` caches the golden root's image id for the life of the
node process, so an updated image is otherwise ignored. Existing Cats keep
their current root until they are recreated.

The bundle does **not** carry the Host kernel, initramfs or a freshly
debootstrapped Ubuntu filesystem. Changes to those parts of
`metal/build-guest-image.sh` (including the base package set,
`cats-init` or `cats-network-setup`) still require rebuilding on the Host with
`OUT=/opt/cats/guest metal/build-guest-image.sh`, followed by a worker restart;
the Guest kernel is the Host's own, which is why the complete boot artifact is
not built in CI. `metal/install-worker.sh` remains a bootstrap/development
helper. It requires `CATS_ROUTE_GRANT_PUBLIC_KEY_FILE` to point at the reviewed
Ed25519 public key before it changes packages, installed files or services; for
example, run `sudo CATS_ROUTE_GRANT_PUBLIC_KEY_FILE=/secure/path/public.pem
deploy/aws/metal/install-worker.sh`. The helper validates and stages that key,
then installs it as root-owned mode `0644` at
`/etc/cats/route-grant-public.pem` before enabling `cats-worker`, whether or not
`worker.env` already exists. Its environment example deliberately contains
`REPLACE_WITH_UNIQUE_NODE_ID` and `PRIVATE_IPV4`; fill both before rerunning the
helper. An existing file with either placeholder is rejected before package
installation or compilation so a second host cannot claim another worker's
identity. Cloud Hypervisor stays under `/opt/cats/bin` so it does not replace a
host-wide binary used by another workload. The S3 adapter uses the EC2
instance role and refreshes its temporary credentials; no long-lived AWS key is
stored in `worker.env`.

This current Host-derived boot shape and `CATS_NODE_ID` worker environment are not eligible for the frozen target
[Agent Registration and Internal Transport v1](../../docs/specs/agent-registration-transport-v1.md) plus
[Runtime Composition Artifacts v1](../../docs/specs/runtime-composition-artifacts-v1.md).
Before the runtime-reconciliation cutover, one release build must put the same exact
`guest-runtime-profile.v1.json` bytes in the Control artifact and worker bundle, install them at
`/opt/cats/release/guest-runtime-profile.v1.json`, and ship the pinned Guest kernel and optional initramfs named by
that receipt. Target worker systemd `ExecStart` and Control Kubernetes container args both pass
`--guest-runtime-profile-receipt-file /opt/cats/release/guest-runtime-profile.v1.json`; missing or mismatched
receipt/boot files fail closed. Rebuilding from the Host kernel is not a target fallback.

The same cutover provisioner installs the canonical root-only local identity at
`/etc/cats/identity/node-identity.v1.json`, with its matching per-Node key and credential ID. Target `cats-noded`
derives `node_id`, immutable Host identity and `/var/lib/cats/node/<state_path_id>` only from that artifact; the
worker name, advertise address and IMDS are not registration identity. The shared Guest payload has the exact
closed layout and manifest defined by the composition contract; Control and worker artifacts must report one
matching immutable release ID before either can be deployed.

The worker builds an optimized Ubuntu 24.04 Guest: direct kernel, a minimal
BusyBox initramfs used only for `switch_root`, and an Ubuntu minbase golden root
with systemd as PID 1. Root growth, deterministic tap setup and the Guest Agent
are early units ordered before `sysinit.target`; ordinary enabled user services
start normally through `multi-user.target`. The visible Guest includes
apt/curl/wget/git; cloud-init, snapd, LXD, wait-online, package timers and the
unused serial getty are not on the Cold-to-Agent readiness path. Each Cat gets
an isolated tap `/30` with outbound host NAT; host, VPC-private and cloud
metadata destinations are blocked before the general egress allow rule.
Every Cat receives a stable wildcard HTTPS Endpoint for Guest port 8080; the
ALB sends wildcard hosts to `cats-gatewayd`, which resolves the owning worker
and the worker connects the service through that Cat's tap address.

`cats-noded` detects the host's logical CPU and memory totals when it starts;
the administrator console reports those schedulable totals plus sampled host
CPU, memory and state-filesystem disk utilization. `CATS_NODE_CPUS` and
`CATS_NODE_MEMORY_MIB` are optional lower scheduling ceilings for hosts that
reserve resources for other workloads.

Each Cloud Hypervisor Cat uses a private, sparse, file-backed memory zone under
its host-local runtime directory. Suspended first pauses the VM and then uses
`process_madvise(MADV_PAGEOUT)` to reclaim Guest pages into that backing file;
it does not require host swap. The worker service therefore needs
`CAP_SYS_NICE` (the default root systemd unit has it), and the state filesystem
must have enough local capacity for the active working sets. A page-out failure
is not reported as Suspended: the VM is resumed and the control plane applies
the lifecycle Cold fallback.

Automatic deeper sleep is enabled for Cats that opt into `auto_suspend`.
Running moves to Suspended when the explicit work-lease and Guest quiesce
checks pass; a stable Suspended Cat moves to Warm after 10 minutes, and a
stable Warm Cat moves to Cold after 24 hours. The latter thresholds are
persisted-state timers configured by `CATS_AUTO_WARM_AFTER_SECONDS` and
`CATS_AUTO_COLD_AFTER_SECONDS`; `0` disables the corresponding boundary. A Cat's
timer runs from the last persisted observed-state change, so a control-plane
restart does not reset it and does not demote a long-lived but recently
suspended Cat.

The elected reconciler applies automatic Node-loss fencing only after its
startup grace. The daemon handles Kubernetes `SIGTERM` explicitly, releases
its PostgreSQL leadership session, and stops singleton work before another
replica takes over.

The control resource database lives in managed PostgreSQL. `cats-controld`
runs at least two API replicas on distinct Kubernetes nodes with a rolling
strategy and a disruption budget. Required hostname anti-affinity makes a
second replica stay Pending until EKS Auto Mode supplies another eligible node;
the scheduler cannot silently co-locate both replicas on one node. Reconciler,
billing enforcer and usage projector roles elect independently through
dedicated PostgreSQL session advisory locks; losing that session cancels the
role before failover. A terminating control-plane Pod stays alive in `preStop`
for 15 seconds while Kubernetes removes it from EndpointSlices and the EKS Auto
Mode ALB drains the target; SIGTERM then stops its singleton roles and HTTP
server within the 30-second termination grace period. This ordering prevents
the edge from routing to an already-exited process during target propagation.

The database carries a schema version. `cats-controld` migrates only stamped
versions inside the build's supported range and fails closed on incompatible
versions. The pre-cutover `cats-control-data` PVC is no longer part of the
runtime; its final snapshot remains only as an archive.

Inspect the production singleton locks and control-plane network addresses from
`main` without disrupting a Pod:

```sh
gh workflow run verify-control-plane-ha.yml \
  --ref main \
  -f mode=diagnose \
  -f confirmation=READ_ONLY_CONTROL_PLANE_LEADER_DIAGNOSTIC
```

Run the reproducible production HA disruption after a multi-replica rollout:

```sh
gh workflow run verify-control-plane-ha.yml \
  --ref main \
  -f mode=disrupt \
  -f confirmation=DELETE_ONE_CATS_CONTROLD_LEADER
```

The workflow refuses a confirmation that does not match the selected mode and
checks out the dispatched `main` revision. Diagnose mode verifies two ready
Pods on different nodes, then reports the singleton locks and each Pod's Pod,
Host and node addresses without deleting anything. Disrupt mode additionally
requires an allowed PDB disruption, locates the reconciler owner through its
PostgreSQL advisory lock, and maps that database source to exactly one strictly
Ready, Running, non-terminating Pod through either its Pod IP or its EKS
node/host IP. Candidate uniqueness is checked before readiness, so a
terminating owner and a same-node replacement fail closed. Zero, duplicate, or
ambiguous owner mappings fail before disruption. The owner is resolved again
at the disruption boundary. A policy/v1 Eviction makes the Kubernetes API
atomically enforce both the PDB and selected Pod UID. All 240 public `/healthz`
probes start on a fixed 250 ms schedule with bounded concurrency, so a slow
request cannot hide the following observations. Every attempt retains its
sub-second start/end time, edge address, HTTP status, DNS/connect/TLS/TTFB/total
timings and scheduling lag. Header evidence follows an explicit safe policy:
`server` and `via` may be retained with value and size caps, while selected
edge trace headers are retained only as SHA-256 digests; all other response
headers and the transient raw curl headers are excluded. The first attempt and
its safe-header artifact must be complete and healthy before the Pod UID check
and Eviction. A signal-aware common finalizer reaps every curl child and writes
a terminal manifest for all configured attempts, distinguishing scheduled,
started, completed and missing work; interrupted or otherwise incomplete runs
exit nonzero.

The Pod and EndpointSlice collectors preserve one Kubernetes LIST-to-watch
stream each, but retain only a projected operational schema in a bounded
first-and-latest window (2,000 records and 1 MiB per stream). Original Pod logs
are converted online to timestamp, severity, diagnostic category, byte count
and SHA-256 records before the same bounded retention; application log text is
never uploaded. Every background pipeline is terminated recursively from its
recorded root PID with a fixed TERM/KILL deadline, so cancellation cannot leave
an orphaned `kubectl`, `jq` or summarizer. Snapshots and explicit Eviction,
deletion, rollout and takeover markers are uploaded for 30 days even if a later
gate fails. The workflow finally proves that two node-spread replicas and a new
reconciler owner are present. It never force-deletes or scales the Deployment.

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
