# ADR-0003：存储后端选定 Direct-OS ChunkStore（Direct-S3 实现），不实现 JuiceFS 方案

- 状态：Accepted
- 日期：2026-07-21

> 命名约定：**Direct-OS**（Direct Object Storage）指“cats-blockd 直接管理对象存储上的 Chunk/Map/Root”的后端形态；**Direct-S3** 是其第一个实现（S3 兼容对象存储 + PostgreSQL root/lease）。既有文档与文件名沿用 Direct-S3。

## 背景

ADR-0001 第 8 条曾保留 JuiceFS-backed sparse `disk.raw` 与 Direct-S3 ChunkStore 双候选。当前证据与判断：

- lazy-ext4 与 production-shaped 实验已证明“未修改 ext4 + 稀疏 ChunkStore + immutable objects + 原子 HEAD/Root”的语义与崩溃一致性（含以真实 JuiceFS mount 作为 durable store 的对照）。
- Direct-S3 原型在真实 S3 上完成冷启动、durable FLUSH 与 crash 窗口验证；39.87 s Cold 归因于串行 Python 实现，不是架构上限。
- JuiceFS raw `disk.raw` 形态（由 JuiceFS 负责 slice 映射）从未被实验覆盖，其核心风险——大 raw 文件随机写的 slice/compaction/fsync 放大——没有任何数据；生产形态还需要额外运维一套 TiKV/HA 元数据集群。
- 双轨已经开始在文档间制造语义渗透（完整架构用 Chunk/Pending Commit Pack 语义描述“V1 JuiceFS 后端”的 FLUSH），继续保留双候选会持续产生歧义。

## 决定

1. `cats-blockd` 原生实现 Direct-S3 ChunkStore 数据路径（规范见 [Direct-S3 ChunkStore 详细设计](../direct-s3-chunkstore-architecture.md)）：NVMe Cache、64 KiB Dirty Bitmap、Pending Commit Pack、V1 4 MiB Base Chunk、两级不可变 Merkle Map、S3 不可变对象、PostgreSQL root/lease CAS 与 fencing epoch。
2. 不实现任何 JuiceFS-backed 数据路径；[存储架构设计（JuiceFS raw 方案）](../cats-storage-product-blueprint.md) 降级为历史参考。不存在“JuiceFS ↔ Direct-S3 灰度切换”计划。
3. `BlobStore` / `MetadataStore` 抽象保留，用于测试替身（File backend、S3 兼容端点）与故障注入，而不是为了第二套生产后端。
4. FLUSH/FUA durability 契约以 Direct-S3 设计 §7 提交协议为准：对象先持久，Root CAS 成功后才 ACK。这也是完整架构 §10.1 的正文语义。
5. 直接面向生产实现（Rust `cats-blockd`）；Python/NBD 原型与 lazy-ext4 oracle 继续作为规格与正确性测试基线。需要数据时按需做针对性实验，不设“先完成一轮实验才能立项”的前置阶段。

## 取代关系

- 取代 ADR-0001 第 8 条（双候选保留）。
- 完整架构 §10 / §19 / §21、根 README 与 AGENTS.md 已同步修订；Direct-S3 文档状态由“候选”改为“已选定基线”。

## 风险与缓解

- **无成熟后端兜底**：FUA/FLUSH/GC/fencing/Map 的正确性全部需要自证。缓解：保留 NBD/ublk correctness oracle、fsx/fio/kill -9 崩溃注入矩阵、read-only attach 与 raw export 恢复工具；Direct-S3 设计 §16 的上线决策门不放松。
- **S3 请求成本与小写放大**：V1 Full Chunk 只用于正确性阶段；Delta Pack 与 Compaction 是 P4 必做项；基准必须记录 `guest_bytes_written`、`remote_bytes_uploaded`、S3 PUT 数与 Compaction bytes 四个量。
- **元数据可用性**：PostgreSQL 不可用时新 FLUSH 必须失败并回压/转只读（不允许绕过 CAS），纳入故障注入验收；root/lease 库需要 HA 与持续备份。
