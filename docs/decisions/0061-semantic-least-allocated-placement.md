# ADR-0061：场景语义生命周期使用 Least-Allocated Placement

- 状态：Accepted
- 日期：2026-08-23
- 协调协议：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md)
- 修正：[ADR-0043](0043-provisioner-owned-runtime-placement-policy.md)“不提供负载均衡策略”的结论，仅限
  ADR-0059 当前资源行生命周期的 Node 选择；不改变独立 Runtime Node authority

## 背景

ADR-0059 的当前实现从所有 `running` Node 中按内部 `node_id` 取第一个。只要最小 ID 的 Node 保持
running，连续 Cat create 就会全部落到同一台机器。Node heartbeat 虽然上报 CPU、内存和 Cat 数，但它是
可延迟、可缺失的 Node 自报诊断数据；多个 create 也可能在下一次 heartbeat 前看到同一旧值。因此它不能
单独提供并发安全的 placement reservation，也不能成为容量或可调度性 authority。

本次只需要一个简单、确定、能在多个 Control replica 下收敛的负载均衡策略。它不引入自动迁移、超配、
provider-specific machine type、动态 telemetry 调度或新的持久 scheduler 表。

## 决策

1. Control 内部建立私有 `SemanticPlacementStrategy` 边界，当前唯一生产实现为
   `LeastAllocatedPlacement`。它被 Cat create、Cold run 和失联恢复共同使用；Suspended/Warm 的同 Node
   run 和其他同 Node 动作不重新选择 placement。
2. 候选集合只包含 PostgreSQL `nodes.status='running'` 的 Node。失联恢复还排除 exact source Node。
   `draining/offline/reset_required/deleted` 一律不能接受新 placement。
3. 每个未 destroyed Cat 的有效 reservation 为
   `COALESCE(current_action_node_id, node_id)`。进行中 create、Cold run 或恢复在提交
   `current_action_node_id` 时立即计入目标 Node；否则使用稳定 `node_id`。这使下一次 placement 不必等待
   Node heartbeat。
4. 对每个候选计算 PostgreSQL 当前行中的 `(sum(cpu_count), sum(memory_bytes), count(cat_id))`，按该三元组
   升序选择，最后以 `node_id COLLATE "C"` 升序稳定打破平局。请求本身的 shape 对每个候选增加相同值，
   不改变本次排序。
5. 所有会选择新 Node 的事务先取得 schema-scoped PostgreSQL transaction advisory lock，再读取负载、锁定
   选中的 running Node row、写 Cat reservation 并提交。不同 Control replica 因而不能基于同一旧负载同时
   claim 多个 placement；rollback 自动释放锁且不留下 reservation。网络调用仍在事务提交后发生。
6. Heartbeat 的 `total_cpu/cpu_utilized/total_memory/memory_utilized` 和 Cat counts 继续只作诊断，不参与本策略。
   本次不把 Least-Allocated 表述为 capacity admission：它不证明 Node 有足够物理容量，也不拒绝超配。
7. 现有 Cat 不主动迁移。负载不均只通过后续 create、Cold run、失联恢复或显式 drain 逐步收敛。

## 后果

相同 shape 的连续 create 会在同负载 Node 间稳定分散；不同 shape 优先补到已分配 vCPU 更少的 Node，vCPU
相等时再比较内存和 Cat 数。进行中的动作已经形成 reservation，所以突发请求和多 Control replica 不需要
等待 heartbeat 才能看到前一项选择。

所有新 placement 在一个很短的 fleet-wide transaction lock 下串行。V1 每次选择聚合当前 Cat 行；若未来
规模证明该查询成为瓶颈，应在保持同一事务 authority 的前提下另行决定可校验计数投影，不能换成
replica-local cursor 或 cache。

异构 Node 的按容量比例分配、hard fit、NUMA/GPU/故障域、heartbeat soft preference 和运行中自动迁移仍未
提供。若接入 `runtime_node_placement_policies.allocatable_*` 做 normalized utilization 或 capacity rejection，
必须另行扩展合同和锁顺序，不能把 Node 自报 telemetry 当作静态 capacity。
