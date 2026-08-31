# Run Cats on Linux bare metal

This directory is the direct-host development and acceptance path for real KVM
and Cloud Hypervisor. Production AWS resources and long-lived workers are owned
through [Terraform](../aws/terraform/README.md); this runbook does not replace
their state, IAM, network, drain, or decommission procedures.

## Runtime shape

- Cloud Hypervisor boots the Cats Guest kernel and RootDisk directly.
- The Guest agent uses vsock; systemd is Guest PID 1.
- Both block paths use the same `cats-blockd` engine and persisted format:
  - `kernel-nbd` is the current default;
  - `vhost-user` is the Linux-native alternative selected with
    `--ch-block-path vhost-user`.
- Each Cat has a tap and Host SNAT for egress. The Rust development path has
  owning-Node HTTP and WebSocket ingress. Cross-Node Guest overlay and real
  production WebSocket qualification are separate gaps.

The current block-path decision and default-flip gate are in
[ADR-0015](../../docs/decisions/0015-vhost-user-blk-production-block-frontend.md).

## Host prerequisites

- x86_64 Linux with `/dev/kvm`; use a bare-metal instance for Cloud Hypervisor.
- Ubuntu 22.04 or 24.04 LTS and enough root storage for the Rust build, Guest
  image, runtime state, and evidence.
- Local NVMe for the intended cache/Relaxed path when validating that behavior.
- Least-privilege network rules and an instance role or other short-lived AWS
  identity for the selected S3/PostgreSQL adapters. Guest images never receive
  these credentials.

## Install

Use an exact reviewed repository revision:

```bash
git clone <this-repo> cats
cd cats
sudo CATS_GUEST_RUNTIME_RELEASE_DIR=/path/to/guest-runtime-release.v1 \
  deploy/metal/install.sh
sudoedit /etc/cats/cats.env
```

`install.sh` requires the provisioner-owned `/etc/cats/identity` set and
`CATS_GUEST_RUNTIME_RELEASE_DIR=.../guest-runtime-release.v1`, installs build/runtime dependencies,
builds release binaries, installs the pinned Cloud Hypervisor and the shared Guest release,
and installs the systemd units. It configures the kernel NBD pool for the
default path; vhost-user does not consume `/dev/nbdN`.

One release build carries the same exact `guest-runtime-profile.v1.json` bytes
in the Control and Node artifacts and installs them at
`/opt/cats/release/guest-runtime-profile.v1.json` with the pinned Guest kernel
and optional initramfs. Production Control and Node both pass that exact file;
there is no Host rebuild or missing-file fallback. NodeIdentity provisioning is
defined by the [A23 tooling contract](../../docs/specs/a23-production-provisioner-tooling-v1.md),
while Cat/Disk/Node registration and heartbeat use the
[current semantic protocol](../../docs/control-node-semantic-protocol.md).

The installer holds `/run/lock/cats/worker-deployment.lock` from Node stop
through installed mutations, semantic registration readiness and Guest release
commit. An interrupted transaction restores the previous Guest set, leaves the
Node stopped and retains its activation journal; rerun the complete installer
to finish or recover the transaction.

After editing `/etc/cats/cats.env`, a clean Node can start the semantic service:

```bash
sudo systemctl restart cats-noded
```

For an existing Node, use the current level-triggered planned drain before an
agent or Guest release. The drain cordons the source, moves each Cat through a
Cold-based migration and verifies the Node has no Cat or orphan residue before
the deployment transaction mutates Host state.

Cloud Hypervisor and blockd are direct children of `cats-noded` in its systemd
cgroup. `KillMode=control-group` makes a Node reset or controlled stop reap the
complete local process tree; the current protocol deliberately does not adopt
retired registration, checkpoint or command-journal authority after restart.

## Cluster configuration

Every Host needs one unique provisioner-owned Node identity/key set; hostname, IP and
environment values are not Node identity. All Hosts in one fleet point to the same control plane, PostgreSQL metadata
store, and durable object store. File and SQLite adapters are local development
adapters and cannot provide cross-Host restore.

Select vhost-user in `/etc/cats/cats.env` when required:

```text
CATS_BLOCK_PATH_ARGS=--ch-block-path vhost-user --ch-vhost-user-queues 4
```

Queue count is bounded by Guest vCPU count. Host CPU and memory are detected by
default; lower the scheduling limits with `CATS_NODE_CPUS` and
`CATS_NODE_MEMORY_MIB` to preserve Host headroom.

The default Guest is an ordinary Ubuntu root with systemd services. The golden
RootDisk expands online at first boot; provision at least 1 GiB for normal use.
`GUEST_INIT_MODE=direct` exists only for historical experiment reproduction.

## Verification boundary

`deploy/metal/e2e.sh` exercises the current synchronous Cat/Disk API: semantic
replay, PersistentDisk binding and mount readiness, Running/Suspended/Warm/Cold,
Cold-only binding changes, destroy/delete and slug reuse. Its result qualifies
only the exact repository revision, Host environment and adapters recorded by
the run; it is not an SLA or a substitute for `quality.sh full`/Linux gates.

The mount-propagation fixture is isolated acceptance work, not a production
deployment step:

```bash
sudo deploy/metal/mount-propagation-e2e.sh
```

## Operational boundaries

- Drain to an empty, residue-free Node before an agent release or Guest-image
  change.
- Rebuilding a golden image does not rebase existing RootDisks. Migrate or
  rebuild those Cats explicitly.
- Cloud Hypervisor disk changes use a stopped/Cold transition rather than
  online hot-plug.
- The Node agent currently runs with Host privileges needed by KVM, networking,
  and kernel NBD; privilege separation remains unimplemented.
- Cross-Node Guest overlay, automatic external Host fencing and privilege
  separation remain separate work. Current HTTP/WebSocket bridges do not by
  themselves prove their production Cloud Hypervisor boundary.

Decommission a Terraform-owned Host through its exact state and reviewed plan.
For a disposable manually created acceptance Host, first preserve required
evidence, verify it owns no runtime or durable-only local state, and then delete
that exact instance through the provider API.
