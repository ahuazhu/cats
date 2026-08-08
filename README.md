# Cats

Cats 是一个可休眠、可恢复、可迁移的 Linux microVM 平台。Guest 使用标准 Linux、
virtio block device 和 ext4；用户通过 CLI/API、Web Console、稳定 HTTPS Endpoint 与
Guest Runtime API使用它。S3、PostgreSQL、NVMe cache、VMM和fencing都属于平台内部。

## 仓库状态

仓库包含完整的 Rust V1 开发闭环：

- Direct-OS ChunkStore、delta packs、golden roots、Strict/Relaxed durability；
- kernel-NBD 与 native vhost-user-blk 两个前端；
- Workspace控制面、用户/管理员 Console、WorkOS sessions、CLI和Gateway；
- FakeVmm 与 Cloud Hypervisor/KVM Node路径、vsock Guest Agent、systemd Guest PID 1；
- S3/PostgreSQL provider adapters、usage/billing pipeline、Terraform/AWS部署；
- adapter contracts、crash injection、fencing、鉴权、drain、Cold restore和bare-metal实验。

这不等于已经完成生产 HA。当前 lifecycle仍是 V1
`desired/observed/generation -> NodeJob`，存在attach模糊响应、旧generation ABA、
无条件lease takeover、Agent session/adoption、PersistentDisk mount readiness和Route撤销边界等
已确认风险。接受的生产路径是
[ADR-0040](docs/decisions/0040-level-triggered-runtime-reconciliation.md) 的 level-triggered
reconciliation和 [ADR-0041](docs/decisions/0041-node-verified-route-admission.md) 的 Node本地
route gate，以及[ADR-0042](docs/decisions/0042-volume-authority-and-disk-lifecycle.md)的条件式
Volume Authority。

尚未实现/验收的主要边界：

- Runtime Reconciliation v1与Route Grant v2切换；
- Host lock、可跨 Agent存活的 per-Cat scopes和完整 restart qualification；
- conditional volume acquire/release/takeover、attachment lineage、AgentSession和ext4 mount readiness；
- 自动跨 Node恢复所需的外部 EC2/BMC Host fence；
- 真实双控制面 takeover与RDS failover组合验收；
- 产品DiskSnapshot Root的同盘restore与GC保护闭环；第一版不做clone；
- 跨Node Guest overlay和privilege separation；现有WebSocket入站dev路径仍缺真实
  Cloud Hypervisor/生产资格证据。

准确的 current/target 对照只在 [docs/README.md](docs/README.md) 维护。

## 不可破坏的边界

- Guest 永远只看到标准块设备和未修改ext4，不持有对象/元数据存储凭据。
- PersistentDisk V1为RWO；只有一个attachment epoch可以发布写入，旧epoch永久fail closed。
- Strict成功FLUSH必须在永久Host loss后恢复。
- Relaxed成功FLUSH可能只有本地 `L`；`R < L` pending data是唯一数据，不是可删除cache。
- Warm/Cold/Snapshot/detach/计划迁移前，所有保留卷必须 `R == L`。
- 生命周期只有 Running / Suspended / Warm / Cold；Suspended和Warm都Host-bound且不能合并。
- heartbeat timeout只是suspicion；计划handoff先release再normal acquire，非计划跨Node接管必须先
  取得HostFenceEvent及精确逐卷takeover authorization。
- 离开Running先关闭route admission并drain active guards，再触碰Guest/VMM/blockd。
- RootDisk跟随Cat；PersistentDisk独立。只有显式disposable Root destroy可放弃本地tail。
- Workspace是资源唯一owner；Guest runtime capability通过 `/run/cats/runtime.sock` HTTP提供。

## 开始阅读

1. [技术架构](docs/architecture.md)
2. [Runtime 生命周期](docs/runtime-lifecycle.md)
3. [存储架构](docs/storage.md)
4. [Operations and HA](docs/operations-ha.md)
5. [文档、ADR、规格与证据索引](docs/README.md)

架构文档只维护Markdown。实验数字保留在原始报告，不复制成README状态或生产SLA。

## 本地开发

需要 Rust toolchain、Docker、OpenSSL和PostgreSQL client依赖。快速启动一个控制面、一个
FakeVmm Node和Gateway：

```bash
./scripts/dev.sh up

export CATS_API_URL=http://127.0.0.1:7300
export CATS_TOKEN=dev-admin-token
target/debug/cats create dev --root-size 64MiB
target/debug/cats exec dev -- echo hello

./scripts/dev.sh status
./scripts/dev.sh down
```

`scripts/dev.sh` 使用 `/tmp/cats-dev` 保存本地状态和日志。真实Cloud Hypervisor/KVM需要
Linux bare metal，见 [deploy/metal/README.md](deploy/metal/README.md)。AWS部署见
[deploy/aws/README.md](deploy/aws/README.md)。

## 质量门

```bash
./scripts/quality.sh fast   # 迭代：format/build/clippy/主要测试
./scripts/quality.sh full   # handoff：依赖策略、workspace测试、rustdoc等完整门
./scripts/quality.sh linux  # 无native Linux host时的Docker兼容门
```

控制面测试需要一次性PostgreSQL；quality脚本默认通过Docker启动。已有外部实例时设置
`CATS_TEST_POSTGRES_URL`。Linux最终证据优先使用现有native x86_64 build host上的exact-SHA
`quality.sh full`。完整约定见 [AGENTS.md](AGENTS.md)。

## Workspace

```text
api/             跨组件资源、请求、协议类型
storage/         provider-neutral BlobStore/MetadataStore contracts
adapters/        File/S3、SQLite/PostgreSQL等具体adapter
blockd/          ChunkStore engine、NBD和vhost-user-blk frontend
control-plane/   API、PostgreSQL store、scheduler/controller、Web Console
node-agent/      Node runtime、Cloud Hypervisor、blockd/Guest supervision
guest/           vsock Guest Agent与Guest-local Runtime API
network/         Endpoint Gateway
metering/        累计usage ledger和rating
cmd/             daemon composition roots与CLI
tests/           跨组件E2E
experiments/     可复现实验、CSV、环境和原始日志
deploy/          metal/AWS/Terraform部署与qualification
docs/            architecture、ADR和wire/state specs
agent-skills/    共享audit/refactor/review workflows
```

## 实验证据

原始入口在 [experiments/README.md](experiments/README.md)。仓库已有Cloud Hypervisor/KVM、
两种块前端、双节点真实S3+RDS Cold迁移、Relaxed local-first、systemd PID 1和存储崩溃窗口
实验。每个结果只证明其记录的环境、样本和correctness oracle；不能由单机prototype或
一次metal run推导生产SLA或完整HA。

## 存储路线

生产存储采用[ADR-0003](docs/decisions/0003-direct-s3-chunkstore-backend.md)的Direct-OS
ChunkStore；provider-neutral合同与S3/PostgreSQL adapters保持分层。
