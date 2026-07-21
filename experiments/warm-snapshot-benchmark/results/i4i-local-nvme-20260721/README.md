# i4i.metal Local NVMe Warm benchmark — 2026-07-21

## 结论

Cloud Hypervisor 的 `snapshot + VMM/backend exit + userfaultfd on-demand restore` 在 i4i.metal 本地 instance-store NVMe 上完成了 512 MiB、1 GiB、2 GiB 三个尺寸和 2/5/10 个 Cat 同时唤醒验证。

- 单 Cat 首次健康响应 P50 为 380–399 ms。
- 10 个 512 MiB Cat 同时唤醒时，首次健康响应 P50 为 530 ms、最大值为 632 ms。
- 所有正式样本均保持 snapshot 前的内存 UUID，证明是原 Guest 进程恢复，不是 Cold boot。
- Warm 等待期间 VMM 和 vhost-user block backend 已退出，专属 runtime RSS 为 0 KiB。
- 与 c5.metal EBS 相比，本地 NVMe 把 10 Cat 首次健康 P50 从 19.05 秒降到 0.53 秒；VMM restore API 在两边都约 25–26 ms，差异主要来自内存页回读数据面。

## 环境

- AWS `i4i.metal`，本地 instance-store NVMe。
- Cloud Hypervisor v53，KVM，2 Guest vCPU。
- Ubuntu 22.04 Guest，未修改的 ext4 root。
- Cloud Hypervisor in-tree `vhost_user_block` reference backend。
- Guest 服务创建内存 UUID，并触碰配置的匿名内存 working set。
- Snapshot 文件在唤醒前通过 `POSIX_FADV_DONTNEED` 尽量从 Host page cache 驱逐。

`POSIX_FADV_DONTNEED` 是 advisory 接口，因此结果是较强的冷 Host page-cache 近似，不代表所有硬件级缓存都被清空。

## 方法

每个顺序样本执行：

```text
Guest healthy + working set resident
  -> pause
  -> snapshot memory/device state to Local NVMe
  -> exit Cloud Hypervisor and vhost-user block backend
  -> remove tap
  -> drop snapshot Host page cache
  -> recreate tap and block backend
  -> start a new Cloud Hypervisor process
  -> userfaultfd on-demand restore
  -> resume
  -> wait for first healthy HTTP response
  -> fault the configured application working set
  -> wait for all Guest RAM background-prefault to finish
```

正确性要求：

- `boot_id_preserved=true`。
- Warm 期间 `warm_runtime_rss_kib=0`。
- Cloud Hypervisor v53 的 background prefault 完成后才进入下一轮 snapshot。

并发实验为每个 Cat 创建独立 VM、root disk、snapshot、tap、subnet 和 block backend。所有 worker 完成 snapshot、进程退出和 cache eviction 后停在 barrier；协调器一次释放，CSV 中的绝对 `wake_started_ns` 用来确认同时开始。

## 单 Cat 尺寸矩阵

每个规格 10 轮。P95 在 10 个样本下只是本轮观测高位值，不能当成生产 P95。

| Guest RAM / working set | Snapshot P50 | Wake-to-health P50 / P95 | Working-set fault P50 / P95 | Full RAM ready P50 / P95 | UUID 保持 |
|---|---:|---:|---:|---:|---:|
| 512 / 64 MiB | 284.182 ms | 379.760 / 385.518 ms | 978.237 / 1,151.467 ms | 1.587 / 1.817 s | 10/10 |
| 1,024 / 128 MiB | 558.027 ms | 381.745 / 445.509 ms | 1,017.997 / 1,055.838 ms | 1.802 / 1.858 s | 10/10 |
| 2,048 / 256 MiB | 1,104.815 ms | 398.733 / 452.517 ms | 1,081.851 / 1,657.248 ms | 3.094 / 3.624 s | 10/10 |

首次健康只依赖少量热页，所以配置 RAM 从 512 MiB 增至 2 GiB 时，P50 只从 380 ms 增至 399 ms。Snapshot 时间和全 RAM resident 时间随内存容量增长。

正式 CSV：

- [`512 MiB / 64 MiB`](raw/cats-warm-bench/results/warm-benchmark-512m-64m.csv)
- [`1,024 MiB / 128 MiB`](raw/cats-warm-bench/results/warm-benchmark-1024m-128m.csv)
- [`2,048 MiB / 256 MiB`](raw/cats-warm-bench/results/warm-benchmark-2048m-256m.csv)

## Barrier 同时唤醒

| 同时 Cat 数 | Wake start spread | Restore API P50 / max | Wake-to-health P50 / max | 64 MiB fault P50 / max | Full 512 MiB ready P50 / max | UUID 保持 |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 5.627 ms | 25.865 / 27.493 ms | 0.413 / 0.423 s | 1.277 / 1.286 s | 1.994 / 2.012 s | 2/2 |
| 5 | 3.695 ms | 30.683 / 32.679 ms | 0.505 / 0.555 s | 1.441 / 1.770 s | 2.256 / 2.515 s | 5/5 |
| 10 | 6.713 ms | 24.792 / 28.840 ms | 0.530 / 0.632 s | 1.869 / 2.221 s | 2.715 / 3.083 s | 10/10 |

正式并发汇总：

- [`2 Cats`](raw/cats-warm-concurrent-2x512-barrier/concurrent-summary.csv)
- [`5 Cats`](raw/cats-warm-concurrent-5x512-barrier/concurrent-summary.csv)
- [`10 Cats`](raw/cats-warm-concurrent-10x512-barrier/concurrent-summary.csv)

## 与 EBS 的同口径对比

| 512 MiB 用例 | c5.metal EBS P50 | i4i Local NVMe P50 | 改善 |
|---|---:|---:|---:|
| 单 Cat health | 1.816 s | 0.380 s | 4.8× |
| 单 Cat 64 MiB fault | 3.485 s | 0.978 s | 3.6× |
| 单 Cat 512 MiB fully resident | 6.080 s | 1.587 s | 3.8× |
| 10 Cat health | 19.052 s | 0.530 s | 35.9× |
| 10 Cat fully resident | 74.420 s | 2.715 s | 27.4× |

VMM control path 在 EBS 和 Local NVMe 上都保持约 25–26 ms。EBS 并发退化来自 snapshot page-in 带宽与延迟，而不是 VMM 创建。因此生产需要 Local NVMe Cache、wake admission、demand-fault 优先级和热页预取。

## 没有验证的内容

- Snapshot 上传对象存储和跨 Host restore。
- Host Local NVMe 完全为空时的 Warm restore。
- 50/100/1,000 Cat 同时唤醒。
- 生产 `cats-blockd`；本轮使用 Cloud Hypervisor reference backend。
- Snapshot 压缩、去重、加密、增量上传和版本兼容矩阵。
- 生产 P99；当前每个尺寸只有 10 个顺序样本，并发规格只有一个 barrier 批次。

## 代码与总报告

- Runner：[`benchmark.sh`](../../benchmark.sh)
- Barrier runner：[`concurrent.sh`](../../concurrent.sh)
- 实验套件说明：[`warm-snapshot-benchmark/README.md`](../../README.md)
- 完整跨实验报告：[`2026-07-21 Cats 存储与生命周期实验总报告`](../../../../docs/experiments-2026-07-21-storage-lifecycle.md)

本次使用的 AWS i4i.metal 实例已于 2026-07-21 终止；Local NVMe 随实例终止不可恢复，正式 CSV 和日志已经保存在本目录。
