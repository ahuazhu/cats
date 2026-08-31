# ADR-0002：生命周期四态：Running / Suspended / Warm / Cold

- 状态：Accepted（四态分类保留；协调、路由与本地 `R < L` 组合已由 ADR-0059 取代）
- 日期：2026-07-21
- 当前协调协议：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md)；Exec/Shell access 见
  [ADR-0065](0065-exec-shell-runtime-access-lane.md)

> 本 ADR 继续决定 Running / Suspended / Warm / Cold 的产品分类。下文已按 ADR-0059 修正当前
> 协调与数据模式；旧 Operation、AgentSession、Route Grant 和 Node-local-only durability 组合见 Git
> 历史，不是当前协议。

## 决定

Cat runtime 只有四个稳定状态：

| 状态 | 定义 | 本地与存储约束 |
|---|---|---|
| **Running** | Guest 正在执行，VMM、blockd、tap 和 attachment 存在 | 当前生命周期只组合成功 FLUSH 已远端持久的模式 |
| **Suspended** | VMM pause，Guest RAM 可 page-out 后按需 refault | Host-bound；保留 VMM、blockd、tap 和 attachment，不新增只在本地成功的数据 |
| **Warm** | Guest memory/device state 保存在本地 snapshot，VMM/backend 退出 | Host-bound；进入前所有保留卷必须 `R == L` |
| **Cold** | 不保留 Guest 内存态、VMM 或本地恢复依赖，可在任意合格 Node fresh boot | 所有保留卷必须 `R == L` |

`Deleted` 是资源终态，不是第五种 runtime 状态。进行中的步骤、失败和降级使用结构化
Condition 表达，不增加可被控制面和 Node 分别写入的过渡状态权威。

## 转换与故障合同

1. 默认自动降级为 Running → Suspended → Warm → Cold，允许策略安全跳级；所有唤醒都回到
   Running，Cold 不回填为 Warm 或 Suspended。
2. 离开 Running 前先撤掉当前新流量入口，再处理 Guest、VMM 和 volume；重新 Running 只有在
   Guest 与全部声明 mount Ready 后才发布入口。
3. 进入 Suspended 前完成 Guest durability barrier。当前生命周期不接纳新的 `R < L`
   Node-local-only 成功状态；Suspended 仍因 VMM 与内存态而绑定原 Host。
4. 进入 Warm 或 Cold，以及 Snapshot、detach 和计划迁移前，所有需要保留的卷必须
   `R == L`；drain 失败时保留源并报告 Blocked。
5. Suspended resume 或 Warm restore 失败时，先证明远端数据安全，再清理本地快路径并 Cold
   boot；不能在唯一 pending data 尚未保护时强制宣称 Cold。
6. heartbeat timeout 只表示 Host 当前不可达，不是 fence。ADR-0059 的失联恢复从远端持久数据在
   其他 Node 启动并要求旧 Node 回来后 reset，明确接受窗口内双跑；它不能被描述成严格物理
   单实例或 writer takeover。需要严格 Host isolation 的底层路径仍使用独立可信 fence authority。
7. Warm snapshot 与恢复使用兼容且固定的 VMM 版本；snapshot 必须具备加密、完整性、配额和
   安全删除。Node/VMM 升级前，无法兼容恢复的 Warm Cat 先安全转 Cold。
8. Suspended 和 Warm 的唤醒使用当前 Cat 行与目标 noded 实际状态；资源记账来自实际运行时间，
   不从 heartbeat 或日志猜测动作结果。

跨 Host snapshot restore 和 live migration 不属于当前四态合同；V1 跨 Node 迁移使用安全
drain 后的 Cold boot。完整资源与屏障说明见 [`runtime-lifecycle.md`](../runtime-lifecycle.md)。

## 协调接口

PostgreSQL 每 Cat 以 `current_action/current_action_node_id` 串行动作；Control 提交 claim 后同步调用
noded，noded 按 `cat_id` 串行并返回实际结果。Control 响应丢失时查询同一目标 Node 后精确结算当前行。
heartbeat、日志和 metrics 不结算动作。完整合同见
[ADR-0059](0059-semantic-control-node-synchronous-protocol.md)。

## 证据边界

2026-07-21 的单 Host 实验分别观测到：pause + page-out 唤醒 P50 0.212–0.231 s、暂停态
cgroup 物理内存 P50 6.9–17.3 MiB；snapshot + VMM exit 的本地 NVMe 唤醒 P50
0.380–0.399 s；优化 Cold P50 1.755 s。数据与环境见
[实验总报告](../experiments-2026-07-21-storage-lifecycle.md)。这些数字只证明相应样本、环境和
correctness oracle，不是当前 release 的生产 SLA。
