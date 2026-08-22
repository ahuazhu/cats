# Runtime 生命周期

- 状态：ADR-0059 当前产品合同；实现和物理资格边界见
  [Architecture §3](architecture.md#3-当前实现边界)
- 决策：[ADR-0002](decisions/0002-lifecycle-states-running-suspended-warm-cold.md)、
  [ADR-0022](decisions/0022-relaxed-local-first-dual-watermark.md)、
  [ADR-0059](decisions/0059-semantic-control-node-synchronous-protocol.md)
- 精确协议：[Control Plane 与 noded 同步协议设计](control-node-semantic-protocol.md)

本文组合产品状态、同步动作、入口屏障和数据屏障。用户面只有
`create/run/suspend/warm/cold/destroy` 六个动作。旧 `Start/Stop/Delete/Killed`、lifecycle
Operation、command poll/result、Node command journal、typed predecessor、AgentSession 和
HostFenceRecovery 不属于当前协议。

## 1. 产品状态

| 状态 | Guest/VMM | 本地依赖 | placement | 含义 |
|---|---|---|---|---|
| `running` | Guest 与 VMM 运行 | 当前 Node 运行资源 | 当前 Node | 可以发布新流量入口 |
| `suspended` | Guest pause，VMM 保留 | 原 Node 内存/设备状态 | 原 Node | 不接收新流量 |
| `warm` | VMM 退出，本地快照保留 | 原 Node snapshot | 原 Node | 不接收新流量 |
| `cold` | 无 VMM/内存态 | 不依赖原 Node | 无固定 Node | 可以在其他 Node 从远端数据启动 |
| `failure` | 残留物理状态可能未知 | 可能仍需原 Node 清理 | 可保留 Node | 只允许 destroy |
| `destroyed` | 产品资源终止 | 无可恢复 runtime | 无 | 历史行，slug 已释放 |

首次 create 进行中时 `state` 可以为空；它不是稳定产品状态。Suspended 与 Warm 不合并：前者保留
VMM，后者退出 VMM，恢复成本和 Host 依赖不同。

`destroyed` 是产品资源终点，不是第五个 runtime 状态。destroy 后同一 slug 可以创建新的
`cat_id`，旧 Node 内部动作必须始终使用不可变 `cat_id`。

## 2. 合法动作

| 当前状态 | 动作 | 成功后 |
|---|---|---|
| 不存在 | `create` | `running` |
| `running` | `suspend` | `suspended` |
| `running` | `warm` | `warm` |
| `running` | `cold` | `cold` |
| `suspended` | `run` | `running` |
| `suspended` | `warm` | `warm` |
| `suspended` | `cold` | `cold` |
| `warm` | `run` | `running` |
| `warm` | `cold` | `cold` |
| `cold` | `run` | `running` |
| 任意未销毁状态 | `destroy` | `destroyed` |
| `failure` | `destroy` | `destroyed` |

其他组合返回 `invalid_state`，不调用 noded。已经达到目标时返回 `already_*`，不执行第二次物理动作。

create/run/suspend/warm/cold 的明确失败把 Cat 写为 `failure`。destroy 失败保持 `failure` 并允许再次
destroy；失败不会自动删除 PersistentDisk。

## 3. 同步协调规则

### 3.1 Control

Control 对每个动作执行同一顺序：

1. 认证 Workspace，并通过当前 slug 或不可变 ID 找到资源。
2. 检查目标是否已经满足；满足就直接返回。
3. 比较完整参数；同一语义资源但参数不同返回 `conflict`。
4. 使用 Cat 行条件更新取得 `current_action` 和 `current_action_node_id`。
5. 提交 PostgreSQL transaction。
6. 在 transaction 外同步调用目标 noded。
7. 写稳定结果、placement 和错误，并清除动作字段。

相同动作正在进行时，重复调用查询目标 noded并等待同一结果；不同动作返回 `busy`。多 Control
replica 依靠数据库条件更新串行化，而不是依靠进程内锁。

Control 在 noded 已完成、数据库尚未更新时退出，恢复者读取 `current_action_node_id`，调用
`GET /v1/cats/{cat_id}`，再按实际结果更新当前行。heartbeat、日志和 metrics 都不能完成动作。

### 3.2 noded

noded 对每个 `cat_id` 建立一个互斥执行单元：

- 不同 Cat 可以并行；
- 同一 Cat 的非 destroy 动作不能并行；
- 相同目标已经完成时返回 `already_done`；
- 相同 create 但配置不同返回 conflict；
- destroy 可以通知当前动作退出，但返回前必须等待退出并完成清理；
- destroy 后，本注册周期内的同一 `cat_id` 不能被旧 create/run 重新启动。

noded 返回成功前必须完成该动作要求的主要物理效果。它不先返回成功再在后台完成 VMM、数据屏障或
Guest mount。

## 4. 动作合同

### 4.1 create / run -> Running

create 由 Control 分配 `cat_id`、解析完整 PersistentDisk mounts、选择 running Node并同步 PUT 到 noded。
run 从 Suspended、Warm 或 Cold 进入 Running；Cold run 可以重新选择 Node。

成功 Running 至少证明：

- 配置对应的 VMM/Guest 已经运行；
- Root device 和所有声明的 PersistentDisk 已接入；
- 每块 PersistentDisk 以预期稳定身份出现，文件系统验证通过且 Guest 目标路径已经 mount；
- Guest readiness 已完成；
- 当前 Node 仍允许 placement；
- 新流量入口只在上述条件完成后发布。

真实 Control→noded HTTP 的 Cat 全状态机和重复语义已经通过。Strict PersistentDisk provision/delete
backend 也已完成并正在合入 production composition；Cloud Hypervisor 的完整实际 effects、精确 Guest
卷/文件系统身份和物理挂载 E2E 尚未闭合。这些仍是上线前置，不能把 HTTP/FakeVmm 或 backend 单层通过
写成完整物理路径完成。

create 最终失败或超时时，Control 可以对同一 `cat_id` 调用一次 noded DELETE 清理尝试残留；产品 Cat
仍写为 `failure`，不会自动变成 destroyed。用户随后显式 destroy。

### 4.2 suspend -> Suspended

成功前必须：

1. 撤掉新的外部流量入口；
2. 停止接受新工作并处理当前连接的有界 drain；
3. pause Guest；
4. 验证 VMM 仍存在且 Guest 不再执行新的块请求。

Suspended 仍依赖原 Node。当前同步协议不要求保留一套独立的 command journal；Node 重置时也不承诺保留
本地 Suspended 状态。

### 4.3 warm -> Warm

成功前必须撤流、停止 Guest，确保所有需要保留的数据已经远端持久，生成并验证 Host-local 快速恢复
状态，然后退出 VMM。Warm 仍依赖原 Node；跨 Node 恢复不会搬运这份内存/设备快照。

任何数据无法证明已远端持久时，动作失败并保留数据，不得猜成 Cold 或删除源数据。

### 4.4 cold -> Cold

成功 Cold 至少证明：

```text
停止新流量
-> 停止 Guest/VMM 和 Guest-facing frontend
-> 所有 retained volume 已远端持久
-> 关闭本机 attachment/writer
-> 清除 Host-local runtime 依赖
-> Control 清空 node_id
```

Cold 可以在其他 Node 从远端数据启动。任一 Root/PersistentDisk 无法证明远端持久或无法关闭 writer 时，
不能返回 Cold。

### 4.5 destroy -> Destroyed

destroy 先撤流并停止同一 Cat 的当前动作和本地运行资源。PersistentDisk 只解除 binding，不随 Cat 删除；
RootDisk 按产品删除规则处理。成功后 Control 删除 bindings、写 `destroyed`、清空 placement 和动作字段。

PersistentDisk 有未远端持久数据、未知写入权限或无法安全 detach 时，destroy 必须失败并保留数据。
Root 与 PersistentDisk 的具体 owner/epoch、remote root 和删除屏障由
[Volume Authority](specs/volume-authority.md)负责；其中依赖旧 lifecycle Operation/AgentSession 的组合部分
已被 ADR-0059 supersede，不能作为当前 Control/Node wire。

## 5. 配置、磁盘与 placement

Cat 只有在 Cold 时才能 attach/detach PersistentDisk；create 可以原子建立初始 bindings。V1 不支持
热挂、热卸、resize 或 hotplug。

attach 的场景语义为 `(cat_id, disk_id, mount_path)`：

- 同 Cat、同路径已经绑定：`already_attached`；
- 同 Cat、不同路径：`mount_path_conflict`；
- 绑定到其他 Cat：`disk_already_attached`；
- 同一 Cat 的目标路径被另一 Disk 占用：`mount_path_conflict`。

`UNIQUE(disk_id)` 是产品 placement 约束；真正的远端 writer 仍由 MetadataStore owner/epoch 控制。
普通 lifecycle 不得绕过该边界抢占 writer。

计划维护先将 Cat 变为 Cold，再在目标 Node run，最后按原目标恢复为 Running/Suspended/Warm。
Suspended/Warm 的本地状态不跨 Node 搬运。

## 6. 入口屏障

当前 Control/Node 合同只管理每个 Cat 的唯一当前新流量目标：

```text
create/run -> Guest 与 mounts Ready -> publish(cat_id, node_id)
离开 Running -> withdraw(cat_id, old_node_id) -> 再改变 Guest/VMM
跨 Node 恢复 -> withdraw old -> recover -> Ready -> publish new
```

同一目标重复 publish 成功；未先 withdraw 时不能直接换 Node；旧 Node 的迟到 withdraw 不能删除新目标。

该入口只限制新进入的流量。已有连接、后台任务和主动出站请求不因此停止。公网 Gateway、TLS 和
Endpoint 协议不在 ADR-0059 范围；旧 Route Operation/AgentSession lane 不是当前 lifecycle 的依赖。

## 7. Node 失联

连续 heartbeat 丢失后，Control 再主动探测 `control_endpoint`；仍失败才把 Node 标记 offline。
heartbeat 使用 Control 的数据库接收时间，Node 自报时间只用于诊断。

offline 后，Control 反复扫描当前 Cat：先撤旧入口，再从远端持久数据在其他 running Node恢复；Running
Ready 后发布新入口，原目标为 Suspended/Warm 时先 Cold boot 再转换回目标状态。旧 Node 下次 heartbeat
或注册得到 `reset_required`，必须立即停止并清理全部 Cat，reset 完成前不能接受 placement。

该流程不等待 Host fence，因此允许短暂双跑。协议假设旧 Node 会在允许的心跳窗口内恢复通信；双跑
通常上限是该窗口加停止清理时间。它不处理旧 Node 长期不能联系 Control 却持续运行的不对称网络。

可信 Host fence 和 `runtime_node_authority` 是独立安全/运维边界，不是 lifecycle 前置步骤，也不能由
heartbeat timeout、入口撤销或 reset 要求替代。

## 8. 存储数据屏障

底层存储仍定义 Strict 与 Relaxed：`R` 是远端 root，`L` 是本地已确认进度，Relaxed 的 `R < L` 表示
原 Node 上存在唯一数据。该数据不是 cache，不能删除或从其他 Node完整恢复。

ADR-0059 只允许成功 FLUSH 已远端持久的模式，因此当前同步 lifecycle、offline 恢复和 reset 不得创建或
依赖 `R < L` 的成功状态。Warm、Cold、detach、计划迁移和 PersistentDisk 保留都必须先证明远端可恢复。

若未来重新开放 Relaxed local-first 产品语义，必须新增 ADR 重新设计 Node 失联、writer takeover、reset
和数据丢失呈现；不能只修改 heartbeat 或 binding。

## 9. 观察与计量

heartbeat 和资源使用率用于：

- Node 可达性和 placement capacity；
- running/suspended/warm 数量；
- CPU/内存监控；
- 漂移、异常和计量诊断。

它们不能把动作写成成功/失败、不能把 Cat 猜成 Cold、不能授权磁盘 writer，也不能证明 Host 已隔离。
Control 崩溃恢复动作只查询保存的目标 Node 和 Cat 实际状态。

## 10. 验收重点

- 同一 Workspace 并发 create 同一 slug 只产生一个当前 Cat；destroy 后同 slug 新建得到新 `cat_id`。
- 相同配置 create、相同目标动作和相同 attach 不产生第二次效果；参数不同返回 conflict。
- 多 Control replica 只能取得一个 `current_action`；noded 同一 Cat 动作串行，不同 Cat 可以并行。
- destroy 能终止进行中的 create，并阻止同一旧 `cat_id` 再启动。
- noded 成功、Control 写回前退出，恢复后查询 Node完成当前行。
- Running 发布入口前 Guest 和 mounts Ready；离开 Running 先撤入口。
- offline 恢复先撤旧入口，新 Node Ready 后发布；旧 Node 返回时 reset 并最终收敛到单实例。
- `disk_bindings` 的 RWO、MetadataStore writer epoch 和 Host fence 三个边界不互相冒充。
- 已通过的真实 Control→noded HTTP Cat 状态机、PersistentDisk backend、PostgreSQL composition 和 Cloud
  Hypervisor 必须分层验证；文档不得把前两层通过写成真实物理路径完成。
