# Cats

Cats 是一个从零实现的独立项目：为用户提供可休眠、可迁移、带持久块设备和稳定网络入口的 Linux microVM。

仓库包含**完整的 Rust workspace 实现（V1 开发形态）**与全部设计文档、实验证据：存储引擎（Direct-OS ChunkStore）、控制面、node-agent、guest-agent、CLI、Endpoint 网关，以及覆盖崩溃注入、fencing、跨节点冷恢复的 46 个自动化测试（单元 + 集成 + 端到端）。KVM/Cloud Hypervisor/vhost-user 的真实虚拟化接入是 Linux 里程碑（见下文"实现状态"）。

## Greenfield 边界

- 不复制或继续维护原 `cat.dev` (~/work/cat.dev) / `dozyfs` 的控制面、Agent、文件系统或 UI 代码。 但可以参考端到端的测试集，用于本项目的正确性验证。
- 旧项目只作为历史经验，不是新实现的依赖或兼容目标。
- 用户和公开 API 统一使用 `cats` 命名。
- Guest 看到普通 virtio block device 和 ext4；S3、NVMe Cache、Chunk/Manifest 与租约均为平台内部实现。
- 存储后端已选定为 Direct-OS ChunkStore（Direct-S3 实现，[ADR-0003](docs/decisions/0003-direct-s3-chunkstore-backend.md)）；JuiceFS 方案不再实现，仅作历史参考。
- 生命周期状态统一为 Running / Suspended / Warm / Cold（[ADR-0002](docs/decisions/0002-lifecycle-states-running-suspended-warm-cold.md)）。

具体边界记录在 [`ADR-0001: Greenfield implementation baseline`](docs/decisions/0001-greenfield-implementation-baseline.md) 及后续 ADR。

## 建议阅读顺序

1. [Cats 完整产品与技术架构](docs/cats-complete-product-technical-architecture.html)
2. [Direct-S3 ChunkStore 详细设计](docs/direct-s3-chunkstore-architecture.html) —— 已选定存储基线（ADR-0003）
3. [Cats 睡眠、唤醒与 VMM 资源回收](docs/cats-sleep-wake-vmm-resource-reclamation.html) —— 四态生命周期（ADR-0002）
4. [2026-07-21 存储与生命周期实验总报告](docs/experiments-2026-07-21-storage-lifecycle.md)
5. [Cats 存储架构设计](docs/cats-storage-product-blueprint.html) —— JuiceFS 方案，历史参考（未采用）
6. [Sprite 小文件存储路径参考](docs/sprite-storage-flow.html)

各文档的状态和关系见 [docs/README.md](docs/README.md)。

## 已有实验

| 实验 | 回答的问题 | 入口 |
|---|---|---|
| Lazy ext4 over ChunkStore | 100 GiB 虚拟盘和 10 万小文件是否需要整盘上传；删掉本地 Cache 后能否按需恢复 | [experiments/lazy-ext4-demo](experiments/lazy-ext4-demo/README.md) |
| VM lifecycle benchmark | EBS 与本地 NVMe 的 Warm restore、pause + page-out、完整 Cold、Direct-S3 的正确性与性能 | [experiments/warm-snapshot-benchmark](experiments/warm-snapshot-benchmark/README.md) |

正式数据、环境报告和原始日志索引见 [experiments/README.md](experiments/README.md)。

## 当前证据支持的基线

- 虚拟化：KVM + Cloud Hypervisor，Guest 使用未修改的 Linux/ext4。
- 块数据面：`virtio-blk -> vhost-user-blk -> cats-blockd`。
- 存储：对象存储保存 durable truth，本地 NVMe 是可删除的稀疏读写 Cache；只提交 dirty logical Chunk，不 dump 整块虚拟盘。后端为 Direct-OS ChunkStore（Direct-S3 实现，ADR-0003）。
- 磁盘：每个 Cat 有生命周期一致的 RootDisk；可选一块跨 Cat 持久化的 RWO PersistentDisk。
- Suspended（pause + page-out）：本轮唤醒约 0.21–0.23 秒，VMM 保留。
- Warm（snapshot + VMM/backend exit）：本地 NVMe 唤醒约 0.38–0.40 秒，进程状态保留且无常驻 VMM。
- Cold：直接内核、精简 initramfs、提前网络和 Agent，本轮完整新内核/新进程 P50 为 1.755 秒。
- Direct-S3：语义原型成立，当前串行 Python 实现约 39.87 秒，只用于验证和定位瓶颈。

这些数字不是生产 SLA（AWS metal 实验口径）。本仓库的自动化测试已经覆盖：跨节点空 Cache 恢复、租约 fencing/僵尸写拒绝、FLUSH 各窗口 kill -9 崩溃恢复——但均在 FakeVmm/本地 BlobStore 形态下；真实 KVM 与大规模并发见"实现状态"。

## 代码结构（Rust workspace，ADR-0004）

```text
cmd/cats/                 cats CLI（clap；等待 Operation、幂等键）
control-plane/            Resource API、Operation、Scheduler、reconcile Controller（axum + SQLite）
node-agent/               NodeJob 执行器、FakeVmm、blockd 子进程监督、心跳（cats-noded）
blockd/                   ChunkStore 引擎：Cache/Bitmap/Pack/Map、FLUSH 提交协议、
                          lease/fencing、NBD 前端、File/S3 BlobStore（cats-blockd）
guest/                    Guest Agent：控制协议、经 NBD 的块 I/O、demo web（cats-guest-agent）
network/                  Endpoint 网关：路由解析、唤醒、旧路由 fail-closed（cats-gatewayd）
api/                      共享类型：资源模型、四态、NodeJob、Guest 协议、Chunk 常量
tests/                    端到端测试（真实 CLI + 双节点 + 网关 + 真实存储子进程）
experiments/              可复现实验与原始证据
docs/                     架构、决策、协议规格和实验报告
```

## 实现状态

| 层 | 状态 | 说明 |
|---|---|---|
| 存储引擎（blockd） | ✅ 实现并测试 | 协议见 [docs/specs/blockd-protocol.md](docs/specs/blockd-protocol.md)；4 个提交窗口 kill -9 恢复、空缓存冷恢复、stale epoch 拒绝均有测试 |
| 控制面 / CLI / 网关 / node-agent / guest-agent | ✅ 实现并测试 | 单元 + 集成 + E2E 共 46 个测试 |
| S3 BlobStore | ✅ 代码 + 签名向量测试 | SigV4 通过 AWS 官方测试向量；对真实 S3/MinIO 的联测按需运行 |
| 元数据存储 | SQLite（开发） | 与规格同 SQL 形状；生产 PostgreSQL 为后续替换项 |
| 虚拟化 | FakeVmm + **Cloud Hypervisor 模式**（`--vmm ch`，Linux+KVM） | CH 直接内核启动、vsock Guest Agent、vm.pause/resume、Warm=vm.snapshot/--restore；块路径 Phase A 走内核 NBD（正确性等价，vhost-user 为性能里程碑）；部署见 `deploy/metal/` |
| Guest 网络 / tap / overlay | 未实现 | 下一里程碑；exec/健康走 vsock；Endpoint 演示仅 FakeVmm 形态 |

## 构建与测试

```bash
cargo build --workspace          # 全部组件
cargo test --workspace           # 46 个测试：单元 + 崩溃注入 + 控制面契约 + E2E
cargo clippy --workspace --all-targets   # 零警告
```

单机手动体验（四个终端或后台）：

```bash
cargo run -p cats-control-plane --bin cats-controld -- --listen 127.0.0.1:7300
cargo run -p cats-node-agent --bin cats-noded -- \
  --node-id n1 --control-plane-url http://127.0.0.1:7300 \
  --state-dir /tmp/cats-n1 --meta-sqlite cats-storage-meta.db \
  --blob-file-root /tmp/cats-blob \
  --blockd-bin target/debug/cats-blockd --guest-agent-bin target/debug/cats-guest-agent
cargo run -p cats-network --bin cats-gatewayd -- --listen 127.0.0.1:7400
cargo run -p cats-cli --bin cats -- create dev --root-size 64MiB && \
  cargo run -p cats-cli --bin cats -- exec dev -- echo hello
```

实验侧验证（原型证据，无需 Rust）：`cd experiments/lazy-ext4-demo && python3 -m unittest -v test_chunkstore.py`；完整 Lazy ext4 需要 Docker privileged/NBD；VM 生命周期实验需要 Linux x86_64、root 和 `/dev/kvm`。
