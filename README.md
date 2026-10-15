# Cats

Cats 是一个可休眠、可恢复、可通过 Cold 启动跨 Node 迁移的 Linux microVM 平台。用户通过
CLI/HTTP API 和 Web Console 管理 Cat、PersistentDisk 与 DiskSnapshot，通过 Exec/Shell 访问 Guest。
Guest 使用标准 Linux、virtio block device 和 ext4，不持有对象存储或元数据存储凭据。

## 仓库状态

仓库包含 Rust 控制面、Node/Guest runtime、块存储、部署工具与分层测试：

- Direct-OS ChunkStore、delta packs、golden roots、Strict/Relaxed durability；
- kernel-NBD 与 native vhost-user-blk 两个前端；
- Workspace 控制面、用户/管理员 Console、可选 WorkOS sessions、CLI 和 Exec/Shell；
- DiskSnapshot 创建与查询、Cold/Unowned 同盘恢复和保护当前 root 与 live Snapshot root 的 GC；
- FakeVmm 与 Cloud Hypervisor/KVM Node 路径、vsock Guest Agent、systemd Guest PID 1；
- S3/PostgreSQL provider adapters、usage/billing pipeline、Terraform/AWS 部署；
- adapter contracts、crash injection、writer epoch、鉴权、drain、Cold restore 和 bare-metal 实验。

当前 Control/Node lifecycle 按
[ADR-0059](docs/decisions/0059-semantic-control-node-synchronous-protocol.md) 及其
[Destroy 抢占修正](docs/decisions/0062-destroy-preempts-in-progress-cat-actions.md)使用同步、
场景语义协议：Control 以 Cat 当前行和 `current_action` 串行化，transaction 外同步调用 noded；
幂等来自 Workspace、slug、完整参数和目标状态，不使用 request ID、Operation、Node poll/result、
per-Cat journal 或 AgentSession。旧 Desired/NodeJob 和 ADR-0056 atomic command 是已被取代的历史协议。
Cloud Hypervisor 实际执行、Strict PersistentDisk、Guest mount readiness 和 Node offline/reset
恢复已接入当前实现；代码与测试的存在不等于每个新版本已经通过物理部署验收，也不代表完整生产 HA。

已实现能力、开放项与协议状态统一见 [docs/README.md](docs/README.md)。生产交付须按
[Operations and HA](docs/operations-ha.md#9-分层-qualification)在交付的精确版本上验证；自动
Host fencing、长期不对称网络、hot Snapshot/跨盘 clone/快照调度、跨 Node Guest overlay
和权限隔离仍是独立边界。

## 不可破坏的边界

- Guest 永远只看到标准块设备和未修改的 ext4，不持有对象/元数据存储凭据。
- PersistentDisk V1 为 RWO；只有当前 owner/attachment epoch 可以发布远端 root，旧 epoch fail closed。
- Strict 成功 FLUSH 必须在永久 Host loss 后恢复；当前产品生命周期只组合 Strict 模式。
- 底层存储引擎仍支持 Relaxed；其成功 FLUSH 可能只有本地 `L`，`R < L` pending data 是唯一数据，
  不是可删除 cache，也不能直接用于当前 offline/reset 恢复流程。
- Warm/Cold/Snapshot/detach/计划迁移前，所有保留卷必须 `R == L`。
- 四个可恢复 runtime 状态是 Running / Suspended / Warm / Cold；Suspended 保留 VMM，Warm 退出
  VMM 并保留本地快照，两者都绑定原 Host。资源行还可表示 `failure` 和终态 `destroyed`。
- heartbeat timeout 只是失联判断输入，不是 Host fence。当前跨 Node 恢复先撤旧入口、Ready 后发布新入口，
  允许旧 Node 在约定通信窗口内短暂双跑，并依靠其返回后的 `reset_required` 最终收敛。
- MetadataStore owner/epoch 和可信 Host fence 仍是独立的数据/物理隔离边界；Cat 行、binding 和入口切换
  不能冒充它们。
- 离开 Running 先撤掉新流量入口并关闭、取消和排空 Exec/Shell，再暂停或停止 Guest/VMM/blockd。
- RootDisk 跟随 Cat；PersistentDisk 独立。当前产品只允许已停止且精确 release 的 Unowned 卷进入
  Deleting，不提供放弃 `R < L` 本地 tail 的例外。
- Workspace 是资源唯一 owner。Guest-local Runtime API 合同见
  [Guest Runtime API](docs/specs/guest-runtime-api.md)。

## 开始阅读

1. [技术架构](docs/architecture.md)
2. [文档、ADR、规格与证据索引](docs/README.md)
3. [Control/Node 同步协议](docs/control-node-semantic-protocol.md)与[Runtime 生命周期](docs/runtime-lifecycle.md)
4. [存储架构](docs/storage.md)
5. [Operations and HA](docs/operations-ha.md)

架构文档只维护 Markdown。CLI 安装、登录和连接配置见 [cats-cli](cmd/cats/README.md)。

## 本地开发

使用 [rust-toolchain.toml](rust-toolchain.toml) 固定的 Rust 1.97.1（含 Rustfmt/Clippy），并准备
C/C++ 编译工具、pkg-config、OpenSSL 开发依赖、Python 3 和 Bash。Linux 原生测试还需要
e2fsprogs。先按 [AGENTS.md](AGENTS.md) 创建独立分支和 `.worktrees/` 工作区，再在其中构建：

```bash
cargo build --workspace --locked
```

可以先运行不依赖外部 PostgreSQL 的生命周期单元测试和真实 Control→noded HTTP 测试：

```bash
cargo test -p cats-control-plane --lib semantic_lifecycle::tests --locked
cargo test -p cats-node-agent --test semantic_vertical_http --locked
```

这两组测试使用内存 Store 和模拟 Node effects，覆盖动作重试、Destroy 抢占、入口顺序与
offline/reset；它们不验证 Cloud Hypervisor 或真实磁盘。

PostgreSQL 集成测试需要一次性数据库。`./scripts/quality.sh test` 和 `full` 会通过 Docker 自动
准备并清理 PostgreSQL；使用已有测试实例时设置 `CATS_TEST_POSTGRES_URL`。直接运行相关
`cargo test` 命令不会自动启动数据库，缺少该变量时测试会失败。

真实 Cloud Hypervisor/KVM 的部署与验收见 [deploy/metal/README.md](deploy/metal/README.md)，
AWS 部署见 [deploy/aws/README.md](deploy/aws/README.md)。

## 质量门

```bash
./scripts/quality.sh fast   # Rustfmt、共享技能链接、release Dockerfile 检查、Clippy
./scripts/quality.sh full   # 另含依赖策略、build、workspace 测试和 rustdoc
./scripts/quality.sh linux  # 无 native Linux host 时的 Docker 兼容门
```

`full` 需要固定版本的 cargo-deny 和 cargo-machete，安装命令见 [AGENTS.md](AGENTS.md)。
每次质量门输出工作区绝对路径、HEAD、dirty 标记和源码 fingerprint；报告须保留这些信息。
Linux 最终证据优先使用现有 native x86_64 build host 上精确提交的 `quality.sh full`。

## Workspace

```text
api/             面向客户端的公共HTTP请求/响应类型
protocol/        跨组件wire合同、严格codec、签名与协议常量
artifacts/       已安装runtime制品的fail-closed读取与启动验证
block-client/    轻量 Host NBD client，供 FakeVmm、探针和协议测试使用
storage/         provider-neutral BlobStore/MetadataStore contracts
adapters/        File/S3、SQLite/PostgreSQL等具体adapter
blockd/          ChunkStore engine、NBD和vhost-user-blk frontend
control-plane/   API、PostgreSQL store、同步生命周期、Node 恢复、Web Console
node-agent/      Node runtime、Cloud Hypervisor、blockd/Guest supervision
guest/           vsock Guest Agent与Guest-local Runtime API
metering/        累计usage ledger和rating
cmd/             daemon composition roots与CLI
tests/           跨组件契约/E2E 与共享测试支持
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
