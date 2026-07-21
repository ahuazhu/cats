# Experiments

本目录保存 Cats 存储和 microVM 生命周期的可复现实验、原始结果与报告。

完整汇总见 [`2026-07-21 Cats 存储与生命周期实验总报告`](../docs/experiments-2026-07-21-storage-lifecycle.md)。报告统一说明了实验环境、测量边界、代码职责、正式结果、失败尝试、结论和未验证事项。

## 实验套件

| 目录 | 验证内容 | 入口 |
|---|---|---|
| [`lazy-ext4-demo/`](lazy-ext4-demo/) | 未修改 ext4 运行在稀疏 ChunkStore 上；只提交 dirty Chunk；删除本地 Cache 后懒加载；JuiceFS production-shaped crash consistency | [`README`](lazy-ext4-demo/README.md) |
| [`warm-snapshot-benchmark/`](warm-snapshot-benchmark/) | Cloud Hypervisor Cold、pause + page-out、snapshot + VMM exit、并发唤醒和 Direct-S3 | [`README`](warm-snapshot-benchmark/README.md) |
| [`metal-e2e-20260721/`](metal-e2e-20260721/) | 生产 Rust 组件在 AWS i4i.metal 上经真实 KVM、Cloud Hypervisor、vsock、ext4、内核 NBD 与真实 S3 完成四态生命周期验收 | [`README`](metal-e2e-20260721/README.md) |

## 2026-07-21 正式结果

| 环境/范围 | 报告 |
|---|---|
| c5.metal + EBS，1 GiB Snapshot Warm 基线 | [`c5-metal-ebs-20260721`](warm-snapshot-benchmark/results/c5-metal-ebs-20260721/README.md) |
| c5.metal + EBS，尺寸矩阵和 2/5/10 并发 | [`ebs-followup-20260721`](warm-snapshot-benchmark/results/ebs-followup-20260721/README.md) |
| i4i.metal + Local NVMe，Snapshot Warm 和并发 | [`i4i-local-nvme-20260721`](warm-snapshot-benchmark/results/i4i-local-nvme-20260721/README.md) |
| i4i.metal，Cold、page-out、Cold 优化和 Direct-S3 | [`i4i-lifecycle-modes-20260721`](warm-snapshot-benchmark/results/i4i-lifecycle-modes-20260721/README.md) |
| i4i.metal，Rust Cats 全栈真实 microVM 验收 | [`metal-e2e-20260721`](metal-e2e-20260721/README.md) |

原始 CSV、JSON profile 和日志保存在各报告同目录的 `raw/` 或标明的结果目录中。日志用于追溯，不应把 smoke test、超时诊断或失败现场混入正式统计。
