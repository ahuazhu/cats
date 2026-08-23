# ADR-0059：Control Plane 与 Node 使用场景语义同步协议

- 状态：Accepted
- 日期：2026-08-22
- 详细合同：[Control Plane 与 noded 同步协议设计](../control-node-semantic-protocol.md)
- 取代：[ADR-0056](0056-atomic-per-cat-runtime-lifecycle.md) 的 lifecycle Operation、Node
  command poll/result commit、Node command journal、typed predecessor 和 HostFenceRecovery 协调模型
- 取代：[ADR-0057](0057-product-lifecycle-actions-and-internal-execution-evidence.md) 的产品
  Operation 投影；保留 `create/run/suspend/warm/cold/destroy` 六个产品动作
- 取代：[ADR-0040](0040-level-triggered-runtime-reconciliation.md) 中已被 ADR-0056 保留的
  AgentSession、完整 inventory 和 HostFence lifecycle 前置条件
- 取代：[ADR-0058](0058-route-ring-acknowledges-immutable-agent-session.md) 的 AgentSession/Route ring
  ACK 协调；新 Node 注册以 `running/offline/reset_required` 当前状态闭合
- 修正：[ADR-0041](0041-node-verified-route-admission.md) 的失联恢复边界；新协议只要求唯一当前
  入口先撤旧、后发布新目标，不以旧 Host 已被 fence 为恢复前置条件

## 背景

现有 atomic lifecycle 为任意响应丢失、进程重启、旧命令延迟到达和跨 Node 强隔离建立了独立
Operation、Node 拉取、exact result settlement、per-Cat journal、AgentSession 和 HostFenceRecovery。
这些机制的正确性边界很强，但也使一次普通的 `run` 或 `cold` 横跨多套持久 authority、后台
runner 和恢复协议。

当前产品选择一个更窄的运行假设：API 和 Control→Node 都是有界同步调用；调用方只重试同一资源、
动作和参数；磁盘只提供成功 FLUSH 已远端持久的模式；不处理长期不对称网络。这个范围内，资源当前
状态、正在执行的动作以及 Node 实际查询足以闭合常见重试和 Control 崩溃恢复，不需要再向用户或内部
协议引入独立 Operation identity。

## 决策

### 一个同步动作通道

Control Plane 在 Cat 行上通过 `current_action` 和 `current_action_node_id` 原子取得一次执行权，提交
事务后同步调用目标 noded。noded 按 `cat_id` 串行执行并在返回前完成主要物理效果。成功、明确失败或
最终超时都投影回 Cat 当前行；网络调用期间不持有数据库事务。

协议不接收 `request_id`、Idempotency-Key 或 lifecycle Operation ID。幂等只由场景语义决定：

- Cat create：`workspace_id + cat_slug + 完整创建配置`；
- Disk create：`workspace_id + disk_slug + size_bytes`；
- 状态动作：`cat_id + 目标状态`；
- attach：`cat_id + disk_id + mount_path`；
- detach/destroy：资源当前事实和目标不存在状态。

相同动作进行中时查询并等待同一动作；不同的非 destroy 动作返回 `busy`。`destroy` 是唯一例外：它在
锁住 Cat 行时替换未完成动作，并继承该动作的 `current_action_node_id`，使 noded 取消并等待同一物理
执行 lane 后清理。被替换动作的迟到结果因不再匹配当前 action/Node 而不能写回。Control 在 noded 已
完成、数据库尚未更新时退出，恢复者使用 `current_action_node_id` 调用 `GET /v1/cats/{cat_id}`，再按实际
终态完成或失败该行。若恢复时 Node 仍在执行被替换动作，Control 重发 destroy，而不是结算为 `busy`。
heartbeat、日志和 metrics 不结算动作。

### 当前资源行就是产品 authority

Cat 稳定态为 `running/suspended/warm/cold/failure/destroyed`。`failure` 只允许 `destroy`；
`destroyed` 是保留的历史行，不是可恢复 runtime 状态。PersistentDisk 为 `normal/deleted`。

Cat 和 PersistentDisk 都以 Workspace 内的用户 slug 定位当前实体。部分唯一索引只覆盖未
destroyed/deleted 的行。销毁后 slug 立即释放；再次使用相同 slug 创建新的不可变内部 ID。slug 查询
只返回当前未销毁实体，不回退到历史行。

`disk_bindings` 对 `disk_id` 建立唯一约束，保证产品数据模型中一块 PersistentDisk 同时最多绑定一个
Cat；同一个 `(cat_id, mount_path)` 也唯一。该数据库 RWO 约束不能被表述成失联双跑窗口内的物理单写
证明。

### Node 注册、心跳与 reset

Node 同时具有内部 `node_id` 和面向用户、运维展示的不可变 `node_name`。Control 使用数据库接收时间写
`node_heartbeats.last_heartbeat_at`；Node 上报时间只用于诊断。

连续心跳丢失并且主动探测失败后，Node 进入 `offline`。Control 先撤销受影响 Cat 的旧流量入口，再在
其他 Node 从远端持久数据恢复；新实例 Ready 后发布唯一当前入口。恢复不等待旧 Host fence，因此允许
旧实例短暂继续运行。旧 Node 下一次注册或心跳必须收到 `reset_required`，立即停止和清理本机全部 Cat，
完成 reset 前不得接受 placement。

在本协议明确排除长期不对称网络的假设下，双跑上限是允许的心跳窗口加停止清理时间，并最终收敛到
一个实例。唯一入口只限制新进入的流量；旧连接、后台任务、主动出站请求和旧实例写盘在该窗口内仍
可能继续。这是接受的风险，不是 Host fencing 或严格物理 RWO。

### 空数据单协议切换

该切换不提供新老 schema、wire、route 或状态的双写、双读、转换器和兼容窗口。目标 release 使用一个
新的空数据库 schema；部署时停止旧服务并删除旧产品数据，再只启动新 Control 和 noded。服务启动必须
拒绝旧 schema version；Node 必须拒绝旧 lifecycle command poll/result commit、Operation 和
AgentSession wire。

生产 composition 只挂载新同步 REST/internal routes。旧 lifecycle Operation 表、command poll/result
route、journal runner、observation settlement、旧 DTO/parser 和只验证这些退役路径的测试直接删除，
不迁移、不修复，也不保留 retired production harness。Git history 是旧实现的档案。

底层 virtio/ext4、ChunkStore 对象格式和 Workspace 授权不是这次协议兼容层；它们可以作为新实现继续
使用，但不得重新引入旧 lifecycle authority。

## 验收与测试切换

最终 composition 至少证明：

1. Cat 和 Disk 销毁后可以复用 slug，新查询只解析新内部 ID；
2. 多 Control replica 只能为同一 Cat 取得一个 `current_action`；noded 同一 Cat 的物理动作也串行；
3. `UNIQUE(disk_id)` 拒绝同一 PersistentDisk 同时绑定两个 Cat；
4. noded 成功后 Control 退出，恢复者能查询 Node 并清除原 `current_action`；
5. offline 旧 Node 的下一次心跳返回 `reset_required`，reset 完成前不接收 placement；
6. 跨 Node 恢复先撤旧入口，新实例 Ready 后才发布新入口，旧 Node reset 后收敛到单实例；
7. production route map 和进程 composition 不再包含 lifecycle Operation GET、command poll/result
   commit、observation settlement或旧 AgentSession runner。

测试清理遵循同一边界：旧协议专属测试直接删除，包括只验证旧 Operation ID、poll/result replay、
journal crash matrix、typed predecessor、HostFenceRecovery、AgentSession inventory attestation 和
observation settlement 的测试；slug/RWO、同 Cat 串行、Control crash-query、offline-reset 和入口切流等
仍适用场景改写成新协议测试，不以跳过旧测试代替新行为覆盖。

## 后果

Control lifecycle 路径收敛为“检查当前事实 → claim `current_action` → 同步调用 noded → 写终态”，
Node 只维护按 Cat 串行的实际状态。API 重试不需要调用方保存随机 key，资源 slug 的当前含义也直接可见。

代价是该协议只在约定的同步、有界重试和网络假设内工作。它不保证任意延迟旧请求的 exactly-once，
不保留 Node-local-only durability，不承诺失联恢复期间物理单实例或物理单写者，也不据此声明完整生产
HA。未来若需要这些保证，必须提交新的 ADR 扩展协议，而不能让 heartbeat、failure、日志或可变 binding
暗中承担 authority。
