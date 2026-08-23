# ADR-0062：Level-Triggered Planned Node Drain

- 状态：Accepted
- 日期：2026-08-23
- 协调协议：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md)
- Placement：[ADR-0061](0061-semantic-least-allocated-placement.md)

## 背景

`nodes.status='draining'` 已经能阻止新的 Cat placement，但原有 Control 入口只改变 Node 状态，不会迁移
Node 上的 Cat。运维要维护一台仍可联系的 Node 时，需要一个可重试的一键操作，将其 Running、Suspended、
Warm Cat 安全地移到其他 Node，同时保持各 Cat 原来的产品状态。

这个操作跨 PostgreSQL、入口、源 noded 和目标 noded，可能长于一次 HTTP 请求。只把待迁移 Cat 列表放在
Control 内存中，会在请求取消、进程退出或多 Control replica 并发时丢失进度。另一方面，当前
ADR-0059 模型没有独立 Operation/job 表，本次也不恢复已被取代的 Operation 协议。

## 决策

1. Control 提供仅 fleet administrator 可调用的
   `POST /v1/admin/nodes/{node_id}/actions/drain`，请求没有 body。它先以 PostgreSQL CAS 将 exact
   `running` Node 置为 `draining`；已经 `draining` 的相同请求是幂等重试，其他状态 fail closed。
2. `draining` 提交后才发现该 Node 上仍保留 placement 的 Cat。因此新 create、Cold run、失联恢复和其他
   drain 不能再选择源 Node；空 Node 直接完成。
3. 每个 Running、Suspended 或 Warm Cat 单独迁移。Control 在同一事务中锁定 Cat、使用 ADR-0061 的
   Least-Allocated 策略选择另一个 `running` Node，并以
   `state=原状态, node_id=源, current_action='run', current_action_node_id=目标` 持久化 exact relocation
   claim。这个现有当前行组合是重启恢复事实，不新增第二套 lifecycle authority。
4. Planned drain 不抢占源 Node 上仍在执行的普通生命周期动作。遇到非本 drain 的 `current_action` 时，该
   Cat 返回 `blocked/busy`；动作结束后，level-triggered pass 再尝试。普通 lifecycle API 也不能把
   `node_id=源, current_action='run', current_action_node_id=目标` 的内部 relocation 当成用户 Run 重试。
5. exact claim 提交后，Control 按以下顺序执行：撤销旧入口；要求源 noded 将 Cat 转为 Cold；确认 retained
   volume 已远端持久且本地 writer 已关闭；在目标 noded Run；若原状态为 Suspended 或 Warm，再转换回该
   状态。只有原状态为 Running 且目标 Ready 后才发布新入口；Warm/Suspended 的瞬时 Running 不发布入口。
6. 源 Cold 成功是目标执行的前置条件。源 Cold 明确失败时，Cat 以 `failure` 留在源 Node 供清理；目标
   启动/恢复明确失败时，Cat 以 `failure` 留在目标 Node 供清理。timeout、transport failure、malformed
   response 或状态查询不完整都属于结果不明：只返回 `blocked` 并保留原 state、source placement 和 exact
   relocation claim，后续 pass 必须先发现 postcondition，不能把它们结算成 `failure`。旧 Node 不会由
   drain 接口自动关闭。
7. 成功 settlement 只接受 exact source placement、target reservation 和原 state，并将稳定 placement
   改为目标、恢复原 state、清空 action。相同 settlement 可以安全重放；不匹配的迟到结果不能覆盖新事实。
8. Control 的独立周期 recovery worker 扫描所有仍为 `draining` 且仍有 Cat placement 的 Node，并再次执行
   同一发现/claim/discovery 流程。扫描同时包含 cordon 前已经提交到 `current_action_node_id`、但尚未形成
   稳定 placement 的 reservation。因此 HTTP 取消、Control 重启、在途 create/run 和多个 replica 的重复
   执行都不会让 Node 过早报告 drained。这个 worker 与 heartbeat/liveness probe 循环分别推进；慢 noded
   lifecycle 请求不能推迟其他 Node 的失联判定，两者都响应同一进程 shutdown 并取消当前有界工作。
9. 响应为 HTTP 200 的闭集报告：顶层 `drained` 表示本次发现的 Cat 都已迁移或已变成 stale；任一 Cat
   无法迁移时为 `blocked`，并返回稳定 code/message。认证、输入、Node 状态或 Store 故障仍使用通用 HTTP
   错误。
10. drain 完成后 Node 保持 `draining`。停机、删除或重新开放 placement 是独立的显式运维步骤，不能由
    “当前没有 Cat”隐式触发。
11. 如果源 Node 在 planned drain 中变成 `offline`，planned pass 不再调用它，也不猜测 Cold。保留的
   exact relocation claim 由 ADR-0059 的 offline recovery 接管；这仍受其已接受的非 fence 双跑风险约束。
12. 如果已经预留的目标 Node 变成 `offline/reset_required/deleted` 或不再存在，源仍为 `draining` 的下一
    pass 在 Cat row lock 内用 ADR-0061 选择另一个 running Node，并在同一事务撤销可能已经发布的 exact
    旧目标入口、替换 target reservation。旧 target 的迟到 publish/settlement 因当前 target predicate 不匹配
    而零写入；普通非 relocation action 仍返回 `busy`。

## 后果

运维只需一次管理接口调用就能 cordon 并迁移一台健康 Node；即使前台请求断开，PostgreSQL 当前行和
`draining` 状态也足以让后台继续。并发调用按 Cat row lock 和 exact settlement 收敛，不需要 replica-local
队列。

迁移是逐 Cat、有界、Cold-based 的，不是 live migration。源端无法安全 Cold、没有其他 running Node、
已有动作未结束或目标恢复失败都会使结果保持 `blocked`；系统不会为了排空而丢弃数据或强制关机。
PersistentDisk/Cloud Hypervisor 的完整物理 E2E 和真实 metal qualification 仍是现有上线前置，本 ADR 不把
协议测试提升为生产硬件资格。
