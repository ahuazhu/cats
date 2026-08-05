# AWS deployment

Terraform under [`terraform/`](terraform/) is now the authoritative source for
new AWS usage resources and the Kubernetes production deployment. The YAML
files under `k8s/` are retained only as import/migration references; do not
apply them after Terraform takeover. Existing EKS, RDS, VPC, ACM, ECR,
ChunkStore and bare-metal resources must be represented from their exact live
configuration and imported before Terraform changes them. See
[`terraform/README.md`](terraform/README.md) and ADR-0012.

Production-shaped split:

- EKS Pods: `cats-controld` (portal, user console, admin console and API) and
  `cats-gatewayd`.
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
- One EKS Auto Mode ALB: the user site at `cats.run`, the operator site at
  `ops.cats.run`, legacy-host redirects and the endpoint wildcard.

The Terraform application stack creates the `cats-controld` ServiceAccount,
`cats-runtime` and `cats-rds-ca`;
secrets are injected by CI and remain protected in remote state. It also
renders the target ACM ARN and every public subnet into EKS Auto Mode ingress.
EKS Pod Identity grants the control plane only the Kinesis/S3/DynamoDB usage
permissions; gateway Pods receive none. Do not create or patch these objects
manually.

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
helper. Cloud Hypervisor stays under `/opt/cats/bin` so it does not replace a
host-wide binary used by another workload. The S3 adapter uses the EC2
instance role and refreshes its temporary credentials; no long-lived AWS key is
stored in `worker.env`.

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

On control-plane startup, automatic Node-loss fencing waits two full Node lease
intervals for persisted workers to heartbeat. The daemon handles Kubernetes
`SIGTERM` explicitly, and the Pod termination grace is shorter than one Node
lease. Together these prevent a `Recreate` deployment gap from being mistaken
for permanent Host loss; a genuinely lost Node is fenced after the startup
grace. A Cold fallback on a still-live Node tears down any stale Suspended/Warm
runtime and removes its VMM sockets before starting a replacement.

The control resource database remains SQLite on one encrypted RWO EBS volume,
so `cats-controld` intentionally has one replica and uses `Recreate`. Shared
storage metadata is PostgreSQL and is safe across the EKS/metal boundary.

That database carries a schema version and is never migrated. `cats-controld`
refuses to start against any other version — `control-plane database ... is at
schema version N, this build requires M; recreate it` — so an incompatible
schema is a crashloop, not a degraded start. The EBS volume is designed to
survive Pod replacement, so restarting or redeploying does not clear it: delete
the `cats-control-data` PersistentVolumeClaim in the `cats` namespace and let the
`WaitForFirstConsumer` class bind a fresh one. A deployment that has never run an
earlier version needs none of this — a first install has no database to refuse.

The usage ledger has the same rule for the same reason. ADR-0018 replaced the V1
`project` ownership column with `workspace_id` on usage rows and `account_id` on
funds rows and shipped no column-rename migration, so an existing `cats_usage`
schema must be recreated or `CATS_USAGE_POSTGRES_SCHEMA` pointed at a new name.
Nothing is dropped automatically: history being disposable is not a licence for
this code to destroy a credit ledger at startup, so the wipe stays an explicit
operator action.

Check both before the first deploy of a build whose `SCHEMA_VERSION` moved.
Bumping that constant is what declares a control-plane schema incompatible; a
schema change that forgets to bump it lets an old database open as if it were
current.
