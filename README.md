# Cats

Cats 是一个可休眠、可恢复、可迁移的 Linux microVM 平台。Guest 使用标准 Linux、
virtio block device 和 ext4；用户通过 CLI/API、Web Console、稳定 HTTPS Endpoint 与
Guest Runtime API使用它。S3、PostgreSQL、NVMe cache、VMM和fencing都属于平台内部。

## 仓库状态

仓库包含完整的 Rust V1 开发闭环：

- Direct-OS ChunkStore、delta packs、golden roots、Strict/Relaxed durability；
- kernel-NBD 与 native vhost-user-blk 两个前端；
- Workspace控制面、用户/管理员 Console、WorkOS sessions和CLI；
- FakeVmm 与 Cloud Hypervisor/KVM Node路径、vsock Guest Agent、systemd Guest PID 1；
- S3/PostgreSQL provider adapters、usage/billing pipeline、Terraform/AWS部署；
- adapter contracts、crash injection、fencing、鉴权、drain、Cold restore和bare-metal实验。

这不等于已经完成生产 HA。当前 Control/Node lifecycle 按
[ADR-0059](docs/decisions/0059-semantic-control-node-synchronous-protocol.md) 直接切换为同步、
场景语义协议：Control 以 Cat 当前行和 `current_action` 串行化，transaction 外同步调用 noded；
幂等来自 Workspace、slug、完整参数和目标状态，不使用 request ID、Operation、Node poll/result、
per-Cat journal 或 AgentSession。旧 Desired/NodeJob 和 ADR-0056 atomic command 是已被取代的历史协议。
真实 Control→noded HTTP 的 Cat 全状态机和重复语义已通过；Strict PersistentDisk backend 已接入
production composition。Cloud Hypervisor 的完整实际 effects 仍在缺少精确输入时 fail closed。

尚未实现/验收的主要边界：

- 补齐真实双 Node/Cloud Hypervisor 纵向联调；
- Strict PersistentDisk backend 和精确卷/文件系统身份已接入；仍需 Guest/Cloud Hypervisor 物理
  mount readiness E2E；
- Cloud Hypervisor 的完整 semantic effects 和真实 Linux/KVM 资格；
- offline Node 允许双跑窗口、旧 Node reset 和最终单实例的两 Node 组合验收；
- 自动 EC2/BMC Host fence、长期不对称网络和真实 RDS failover仍是独立边界；
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
- heartbeat timeout只是失联判断输入，不是Host fence。当前跨Node恢复先撤旧入口、Ready后发布新入口，
  允许旧Node在心跳窗口内短暂双跑，并依靠其返回后`reset_required`最终收敛。
- MetadataStore owner/epoch和可信Host fence仍是独立的数据/物理隔离边界；Cat行、binding和入口切换
  不能冒充它们。
- 离开Running先撤掉新流量入口，再暂停或停止Guest/VMM/blockd。
- RootDisk跟随Cat；PersistentDisk独立。当前产品只允许已停止且精确 release 的 Unowned 卷进入
  Deleting，不提供放弃 `R < L` 本地tail的例外。
- Workspace是资源唯一owner；Guest runtime capability通过 `/run/cats/runtime.sock` HTTP提供。

## 开始阅读

1. [技术架构](docs/architecture.md)
2. [Runtime 生命周期](docs/runtime-lifecycle.md)
3. [存储架构](docs/storage.md)
4. [Operations and HA](docs/operations-ha.md)
5. [文档、ADR、规格与证据索引](docs/README.md)

架构文档只维护Markdown。实验数字保留在原始报告，不复制成README状态或生产SLA。

## 本地开发

需要 Rust toolchain、Docker、OpenSSL和PostgreSQL client依赖。当前同步协议通过进程内
FakeVmm、真实Control→noded HTTP和PostgreSQL测试启动隔离的开发拓扑：

```bash
cargo test -p cats-control-plane --test semantic_runtime_lifecycle
cargo test -p cats-control-plane --test semantic_noded_http_lifecycle
```

测试需要一次性PostgreSQL，仓库质量脚本会自动准备。真实Cloud Hypervisor/KVM需要Linux bare metal，
见 [deploy/metal/README.md](deploy/metal/README.md)。AWS部署见 [deploy/aws/README.md](deploy/aws/README.md)。

## 质量门

```bash
./scripts/quality.sh fast   # 迭代：format、静态契约和workspace/all-targets Clippy
./scripts/quality.sh full   # handoff：依赖策略、build、workspace测试、rustdoc等完整门
./scripts/quality.sh linux  # 无native Linux host时的Docker兼容门
```

控制面测试需要一次性PostgreSQL；quality脚本默认通过Docker启动。已有外部实例时设置
`CATS_TEST_POSTGRES_URL`。Linux最终证据优先使用现有native x86_64 build host上的exact-SHA
`quality.sh full`。完整约定见 [AGENTS.md](AGENTS.md)。

## Workspace

```text
api/             面向客户端的公共HTTP请求/响应类型
protocol/        跨组件wire合同、严格codec、签名与协议常量
artifacts/       已安装runtime制品的fail-closed读取与启动验证
storage/         provider-neutral BlobStore/MetadataStore contracts
adapters/        File/S3、SQLite/PostgreSQL等具体adapter
blockd/          ChunkStore engine、NBD和vhost-user-blk frontend
control-plane/   API、PostgreSQL store、scheduler/controller、Web Console
node-agent/      Node runtime、Cloud Hypervisor、blockd/Guest supervision
guest/           vsock Guest Agent与Guest-local Runtime API
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
