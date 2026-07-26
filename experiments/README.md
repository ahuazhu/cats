# Experiments

本目录保存 Cats 存储和 microVM 生命周期的可复现实验、原始结果与报告。

完整汇总见 [`2026-07-21 Cats 存储与生命周期实验总报告`](../docs/experiments-2026-07-21-storage-lifecycle.md)。报告统一说明了实验环境、测量边界、代码职责、正式结果、失败尝试、结论和未验证事项。

## 实验套件

| 目录 | 验证内容 | 入口 |
|---|---|---|
| [`lazy-ext4-demo/`](lazy-ext4-demo/) | 未修改 ext4 运行在稀疏 ChunkStore 上；只提交 dirty Chunk；删除本地 Cache 后懒加载；JuiceFS production-shaped crash consistency | [`README`](lazy-ext4-demo/README.md) |
| [`warm-snapshot-benchmark/`](warm-snapshot-benchmark/) | Cloud Hypervisor Cold、pause + page-out、snapshot + VMM exit、并发唤醒和 Direct-S3 | [`README`](warm-snapshot-benchmark/README.md) |
| [`metal-e2e-20260721/`](metal-e2e-20260721/) | 生产 Rust 组件在 AWS i4i.metal 上经真实 KVM、Cloud Hypervisor、vsock、ext4、内核 NBD 与真实 S3 完成四态生命周期验收 | [`README`](metal-e2e-20260721/README.md) |
| [`vhost-user-blk-frontend-20260726/`](vhost-user-blk-frontend-20260726/) | `cats-blockd` 原生 vhost-user-blk 前端:协议级验收、QEMU 真实 Guest、AWS i4i.metal 真 KVM 生命周期验收（含 Warm 状态对齐）、Guest 可见 fio 三路对照与写路径根因 | [`README`](vhost-user-blk-frontend-20260726/README.md) |
| [`metal-cluster-20260726/`](metal-cluster-20260726/) | 双节点 i4i.metal + 真实 S3 + RDS PostgreSQL：跨节点 Cold 迁移与并发拉起能力（单机 / 集群） | [`README`](metal-cluster-20260726/README.md) |

## 2026-07-21 正式结果

| 环境/范围 | 报告 |
|---|---|
| c5.metal + EBS，1 GiB Snapshot Warm 基线 | [`c5-metal-ebs-20260721`](warm-snapshot-benchmark/results/c5-metal-ebs-20260721/README.md) |
| c5.metal + EBS，尺寸矩阵和 2/5/10 并发 | [`ebs-followup-20260721`](warm-snapshot-benchmark/results/ebs-followup-20260721/README.md) |
| i4i.metal + Local NVMe，Snapshot Warm 和并发 | [`i4i-local-nvme-20260721`](warm-snapshot-benchmark/results/i4i-local-nvme-20260721/README.md) |
| i4i.metal，Cold、page-out、Cold 优化和 Direct-S3 | [`i4i-lifecycle-modes-20260721`](warm-snapshot-benchmark/results/i4i-lifecycle-modes-20260721/README.md) |
| i4i.metal，Rust Cats 全栈真实 microVM 验收 | [`metal-e2e-20260721`](metal-e2e-20260721/README.md) |

## 2026-07-26 正式结果

| 环境/范围 | 报告 |
|---|---|
| i4i.metal，vhost-user-blk 真机生命周期验收 + Guest fio + 写路径根因 | [`vhost-user-blk-frontend-20260726`](vhost-user-blk-frontend-20260726/README.md) |
| 2 × i4i.metal + S3 + RDS，跨节点 Cold 迁移与并发拉起 | [`metal-cluster-20260726`](metal-cluster-20260726/README.md) |

原始 CSV、JSON profile 和日志保存在各报告同目录的 `raw/` 或标明的结果目录中。日志用于追溯，不应把 smoke test、超时诊断或失败现场混入正式统计。
