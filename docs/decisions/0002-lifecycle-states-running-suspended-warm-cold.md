# ADR-0002：生命周期四态：Running / Suspended / Warm / Cold

- 状态：Accepted
- 日期：2026-07-21
- 协调协议：[ADR-0040](0040-level-triggered-runtime-reconciliation.md)

## 决定

Cat runtime 只有四个稳定状态：

| 状态 | 定义 | 本地与存储约束 |
|---|---|---|
| **Running** | Guest 正在执行，VMM、blockd、tap 和 attachment 存在 | Relaxed 可有 `R < L` pending data |
| **Suspended** | VMM pause，Guest RAM 可 page-out 后按需 refault | Host-bound；保留 VMM、blockd、tap、lease、journal，允许 `R < L` |
| **Warm** | Guest memory/device state 保存在本地 snapshot，VMM/backend 退出 | Host-bound；进入前所有保留卷必须 `R == L` |
| **Cold** | 不保留 Guest 内存态、VMM 或本地恢复依赖，可在任意合格 Node fresh boot | 所有保留卷必须 `R == L` |

`Deleted` 是资源终态，不是第五种 runtime 状态。进行中的步骤、失败和降级使用结构化
Condition 表达，不增加可被控制面和 Node 分别写入的过渡状态权威。

## 转换与故障合同

1. 默认自动降级为 Running → Suspended → Warm → Cold，允许策略安全跳级；所有唤醒都回到
   Running，Cold 不回填为 Warm 或 Suspended。
2. 离开 Running 前先按 [ADR-0041](0041-node-verified-route-admission.md) 关闭 route admission，
   再处理 Guest、VMM 和 volume。
3. 进入 Suspended 前完成 Guest 本地 durability barrier。Relaxed 可以保持 `R < L`，但
   Host、blockd、lease、data directory 和 pending journal 必须一起保留。
4. 进入 Warm 或 Cold，以及 Snapshot、detach 和计划迁移前，所有需要保留的卷必须
   `R == L`；drain 失败时保留源并报告 Blocked。
5. Suspended resume 或 Warm restore 失败时，先证明远端数据安全，再清理本地快路径并 Cold
   boot；不能在唯一 pending data 尚未保护时强制宣称 Cold。
6. heartbeat timeout 只表示 Host 当前不可达。可信外部isolation先建立HostFenceEvent；新完整
   Desired提高placement epoch，每个attachment epoch仍只能由精确逐卷授权CAS提高，之后才可从
   Cold恢复。永久Host loss时Strict从`R`恢复；Relaxed标记`DataLossPossible`，最后一次`L-R`
   observation不是故障瞬间的精确损失量。
7. Warm snapshot 与恢复使用兼容且固定的 VMM 版本；snapshot 必须具备加密、完整性、配额和
   安全删除。Node/VMM 升级前，无法兼容恢复的 Warm Cat 先安全转 Cold。
8. Suspended 和 Warm 都记录 resume commitment，并使用有界唤醒准入；资源记账来自物理
   observation，不从 desired 状态猜测。

跨 Host snapshot restore 和 live migration 不属于当前四态合同；V1 跨 Node 迁移使用安全
drain 后的 Cold boot。完整资源与屏障说明见 [`runtime-lifecycle.md`](../runtime-lifecycle.md)。

## 协调接口

PostgreSQL 保存带 `desired_revision` 的稳定目标；Node 每 Cat 串行检查物理事实并收敛；
observation 携带 applied revision、placement epoch、runtime incarnation、Condition 和逐卷
`R/L`。Operation 只由同 revision 的目标 postcondition 结算。通知、响应丢失和组件重启不改变
四态定义或上述屏障。

## 证据边界

2026-07-21 的单 Host 实验分别观测到：pause + page-out 唤醒 P50 0.212–0.231 s、暂停态
cgroup 物理内存 P50 6.9–17.3 MiB；snapshot + VMM exit 的本地 NVMe 唤醒 P50
0.380–0.399 s；优化 Cold P50 1.755 s。数据与环境见
[实验总报告](../experiments-2026-07-21-storage-lifecycle.md)。这些数字只证明相应样本、环境和
correctness oracle，不是当前 release 的生产 SLA。
