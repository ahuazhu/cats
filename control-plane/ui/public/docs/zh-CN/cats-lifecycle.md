## Lifecycle Model

Running、Suspended、Warm 与 Cold 仍是不同 Runtime State：

| State | Process Memory | Host-bound |
|----|----|----|
| Running | Active | 否 |
| Suspended | 保留；Page 可移到 Local NVMe | 是 |
| Warm | 保留在 Local VM Snapshot；VMM 退出 | 是 |
| Cold | 丢弃；从 Durable Disk Boot | 否 |

Suspended 与 Warm 不能合并。两者都保护 Host-local State；Cold 启动新 Kernel 与 Process。离开 Running 时，系统会先关闭 Route Admission 并 Drain Guard，再执行 Guest、VMM、blockd 或 Attachment Effect。

## 当前 Release 边界

Signed Runtime Cutover 暴露 Cat Create 与 Read Projection，但不提供用户 Lifecycle Mutation。Per-Cat Reconciler 是唯一 Physical-effect Executor，`DesiredRuntimeSpec` 是唯一 Lifecycle Intent。浏览器或 CLI 不能制造 Transition、抢占 Attachment，也不能因缺少 Local Evidence 猜测 Cold。

Checkpoint/Inventory Evidence 缺失或损坏时，Reconcile 必须 Block 或 Quarantine。非计划 Cross-Node Recovery 还要求可信 Host-fence 与精确 Volume Takeover Authority。
