# AWS deployment

Production-shaped split:

- EKS Pods: `cats-controld` (portal, user console, admin console and API) and
  `cats-gatewayd`.
- EC2 bare metal: only `cats-noded`, `cats-blockd`, Cloud Hypervisor and guest
  assets. It is not an EKS node.
- RDS PostgreSQL: authoritative ChunkStore roots, leases and fencing epochs.
- S3: immutable durable ChunkStore objects.
- One EKS Auto Mode ALB: the user site at `cats.run`, the operator site at
  `ops.cats.run`, legacy-host redirects and the endpoint wildcard.

`k8s/base.yaml` deliberately references a pre-created `cats-runtime` Secret
and `cats-rds-ca` ConfigMap. Do not commit their values. Render
`k8s/ingress.yaml.example` with the target ACM ARN and every public subnet in
which an ingress target Pod may run; environment-specific AWS identifiers stay
outside the repository.

`metal/install-worker.sh` installs only the worker binaries and its systemd
unit. It keeps Cloud Hypervisor under `/opt/cats/bin` so it does not replace a
host-wide binary used by another workload. The S3 adapter uses the EC2
instance role and refreshes its temporary credentials; no long-lived AWS key is
stored in `worker.env`.

The worker builds an optimized Ubuntu 24.04 Guest: direct kernel, a minimal
BusyBox initramfs used only for `switch_root`, and an Ubuntu minbase golden root
with a small reaping PID 1 that starts the Guest Agent without a full systemd
transaction. The visible Guest includes apt/curl/wget/git; cloud-init, snapd,
LXD and wait-online are not on the Cold-to-Agent readiness path. Each Cat gets
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
`CATS_AUTO_COLD_AFTER_SECONDS`; `0` disables the corresponding boundary.
Existing Cats begin these deeper-tier timers when the migration is first
applied, rather than being aged from their original creation time.

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
