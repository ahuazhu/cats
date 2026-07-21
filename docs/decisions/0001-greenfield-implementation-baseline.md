# ADR-0001：Greenfield implementation baseline

- 状态：Accepted（第 7 条的状态命名由 [ADR-0002](0002-lifecycle-states-running-suspended-warm-cold.md) 细化；第 8 条“保留双候选后端”由 [ADR-0003](0003-direct-s3-chunkstore-backend.md) 取代）
- 日期：2026-07-21

## 背景

Cats 将脱离旧 `cat.dev` (~/work/cat.dev) / `dozyfs` 工程，从零实现。过去两天的架构讨论和实验提供了可复用的知识与证据，但旧代码同时包含不同产品形态、命名和技术债，不适合作为新项目代码基线。

## 决定

1. 新项目只迁移设计文档、实验代码和实验结果，不迁移旧控制面、Node Agent、文件系统、UI 或部署代码。
2. 对外产品名、CLI 和 API namespace 统一为 `Cats` / `cats`。
3. Guest 存储接口固定为标准 virtio block；Guest 使用普通 ext4，不感知 JuiceFS、S3 或 Host Cache。
4. Host 块服务暂命名为 `cats-blockd`，负责 vhost-user-blk、逻辑 Chunk、Cache、dirty tracking、FLUSH durability 和 attach fencing。
5. 本地 NVMe 是可删除的 Cache，不是唯一真相源。删除一台 Host 后，已确认成功的 FLUSH 必须能从远端 durable store 恢复。
6. RootDisk 生命周期与 Cat 一致；可选 PersistentDisk 独立持久化，并且 V1 只支持单写者 RWO。
7. 生命周期实现保留三个层次：pause + page-out、snapshot + VMM exit、Cold。Warm 失败必须能回退到 Cold。
8. JuiceFS-backed 与 Direct-OS（Direct-S3 实现）-backed 都保留为候选实现。在完成相同 crash/fencing/empty-cache/performance 测试前，不在 ADR-0001 中锁定最终后端。

## 明确不继承

- 旧项目目录结构和内部包名。
- Volume 与 Cat 一一绑定等旧资源耦合。
- Guest 直接看到平台 JuiceFS/FUSE mount 的产品接口。
- 特定 AWS Account、Bucket、Region、Host 路径或测试实例标识。
- 旧项目已有测试通过就等同于新实现已验证的假设。

## 实现顺序

1. 固定协议和故障语义：block size、Chunk、Manifest、FLUSH/FUA、lease epoch。
2. 实现单机 `cats-blockd` 最小闭环，并复用 Lazy ext4 digest/crash oracle。
3. 接入 Cloud Hypervisor vhost-user-blk，完成 create/run/stop/wake/Cold。
4. 实现 NVMe Cache 和一种 durable backend，再做空 Cache 恢复。
5. 增加 RWO attach/fencing 和 Host 故障接管。
6. 最后实现多节点控制面、CLI/API、网络 Endpoint、计费和管理功能。

## 验收底线

- 不能上传整个稀疏虚拟盘来提交少量写入。
- Guest 收到成功 FLUSH 后，即使立即删除 Host，也必须能恢复该 generation。
- 旧 attachment epoch 永远不能继续写。
- 同一 RWO PersistentDisk 不能同时出现两个 writer。
- Warm restore 错误不能阻止 Cold fallback。
- 性能结论必须保留原始 CSV、样本数、测量边界和正确性判据。
