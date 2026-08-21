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

Signed Runtime Cutover 暴露六个精确、幂等的产品 Action：Create、Run、Suspend、Warm、
Cold 与 Destroy。PostgreSQL 对每个 Cat 最多接受一个未解决 Operation；assigned Node
上的 signed command runner 是唯一 Physical-effect Executor，并返回该命令的精确终态。
Inventory 只报告事实，不能结算 Operation。浏览器或 CLI 不能制造 Transition、抢占
Attachment，也不能因缺少 Local Evidence 猜测 Cold。

产品没有 Stop Action 或 Killed State。Node 可以在实现某个 Action 时生成私有的
execution-stopped evidence，但产品 Operation 与稳定状态都不会返回它；Cold 要求每个 retained Volume
已经远端持久化并完成 release。Command Journal 或 Inventory Evidence 缺失、损坏时，
执行必须 Block 或 Quarantine。非计划 Cross-Node Recovery 还要求可信 Host-fence 与精确
Volume Takeover Authority。
