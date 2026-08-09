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

The runtime-reconciliation release carries the same exact
`guest-runtime-profile.v1.json` bytes in the Control and Node artifacts and install them at
`/opt/cats/release/guest-runtime-profile.v1.json` together with the pinned Guest kernel and optional initramfs.
Production Control and Node systemd `ExecStart` both pass
`--guest-runtime-profile-receipt-file /opt/cats/release/guest-runtime-profile.v1.json`; there is no Host rebuild,
missing-file or fixture fallback. The full fail-closed contract is
[Agent Registration and Internal Transport v1](../../docs/specs/agent-registration-transport-v1.md), and the
single-build payload/manifest plus root-provisioned local Node identity are frozen by
[Runtime Composition Artifacts v1](../../docs/specs/runtime-composition-artifacts-v1.md). `cats-noded` does
not derive registration identity from the development `CATS_NODE_ID`, hostname, address or Host kernel.

仅限首次安装、尚未创建任何 Cat 的空节点，配置后可以直接启动或重启服务。

```bash
sudo systemctl restart cats-noded
```

其他节点先执行：

```bash
cats admin node drain <node-id>
```

Proceed only when the admin view reports `state=cordoned cats=0 orphans=0`.
Current production units use systemd `KillMode=control-group`; stopping the
agent also stops its VMM/blockd children and can strand unpublished Relaxed
state. Agent-surviving per-Cat scopes become safe only with the complete
ADR-0040 Host-lock/checkpoint/inventory cutover.

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

## Verification

Run the real-KVM lifecycle acceptance:

```bash
sudo deploy/metal/e2e.sh
```

It checks create, Guest/systemd readiness, networking, durable writes,
Suspend/Resume, Warm snapshot/restore, Cold boot, and destroy using physical
Guest boot identities. Raw environment-specific evidence is retained under
[`metal-e2e-20260721`](../../experiments/metal-e2e-20260721/README.md),
[`vhost-user-blk-frontend-20260726`](../../experiments/vhost-user-blk-frontend-20260726/README.md),
and [`metal-cluster-20260726`](../../experiments/metal-cluster-20260726/README.md).
Those runs are correctness evidence for their exact revisions, not an SLA.

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
- Cloud Hypervisor disk changes currently take effect through a stopped/cold
  transition rather than online hot-plug.
- The Node agent currently runs with Host privileges needed by KVM, networking,
  and kernel NBD; privilege separation remains unimplemented.
- Cross-Node overlay, automatic Host fencing, and the ADR-0040/0041 coordination
  cutover remain target work. Current HTTP/WebSocket bridges do not prove their
  production Cloud Hypervisor boundary.

Decommission a Terraform-owned Host through its exact state and reviewed plan.
For a disposable manually created acceptance Host, first preserve required
evidence, verify it owns no runtime or durable-only local state, and then delete
that exact instance through the provider API.
