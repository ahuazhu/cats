# Cats

Cats 是一个从零实现的独立项目：为用户提供可休眠、可迁移、带持久块设备和稳定网络入口的 Linux microVM。

当前仓库处于**设计与技术验证阶段**。这里保存最近两天形成的产品架构、存储和生命周期设计、实验代码、正式结果与失败现场；尚未包含生产实现。

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

这些数字不是生产 SLA。跨 Host 空 Cache 恢复、生产 `cats-blockd`、租约 fencing、故障注入和大规模并发仍未完成。

## 计划中的代码结构

```text
cmd/cats/                 CLI
control-plane/            Resource API、Operation、Scheduler、Controller
node-agent/               Node 生命周期与本机资源管理
blockd/                   vhost-user-blk、NVMe Cache、Chunk/Manifest、FLUSH
guest/                    Kernel config、initramfs、PID 1 / Guest Agent
network/                  tap、路由、Endpoint 和策略
api/                      版本化 API schema 和生成代码
tests/                    单元、故障注入和跨组件 E2E
experiments/              可复现实验与原始证据
docs/                     架构、决策和实验报告
```

这只是目标结构；实现语言统一为 Rust 单 cargo workspace（[ADR-0004](docs/decisions/0004-implementation-stack-and-dev-environment.md)），先完成最小 `cats-blockd` 和单机生命周期闭环，再扩展控制面。

## 本地验证

无需 KVM 的 ChunkStore 单测：

```bash
cd experiments/lazy-ext4-demo
python3 -m unittest -v test_chunkstore.py
```

完整 Lazy ext4 需要 Docker privileged/NBD；VM 生命周期实验需要 Linux x86_64、root 和 `/dev/kvm`。具体命令在各实验 README 中。
