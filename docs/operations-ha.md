# Operations and HA

- 状态：ADR-0059 运维合同；同步 Control/Node 生产 composition 已组成，完整纵向和物理资格仍开放
- 决策：[ADR-0031](decisions/0031-control-store-on-postgresql.md)、
  [ADR-0032](decisions/0032-control-plane-multi-replica-and-postgresql-leadership.md)、
  [ADR-0038](decisions/0038-production-account-qualification-cell-boundary.md)、
  [ADR-0059](decisions/0059-semantic-control-node-synchronous-protocol.md)
- 协议：[Control Plane 与 noded 同步协议设计](control-node-semantic-protocol.md)
- 数据：[storage.md](storage.md)、[Volume Authority](specs/volume-authority.md)

本文定义运行拓扑、PostgreSQL/Control 边界、Node heartbeat/reset、失联恢复、独立 Host fence 和
qualification。旧 lifecycle Operation、Node command poll/result、per-Cat command journal、AgentSession、
inventory settlement 和 HostFenceRecovery 不是当前运维路径。

## 1. 运行拓扑

- **Control Plane API**：可以运行多个 stateless replica，共享 PostgreSQL。每个请求先在数据库取得
  `current_action`，transaction 提交后同步调用目标 noded。
- **Node liveness monitor**：与 Control co-deploy；用数据库 heartbeat 接收时间、连续丢失窗口和一次主动
  health probe 判定 offline。耗时的 offline recovery/planned drain 由独立周期 worker 反复发现，不能阻塞
  heartbeat probe cadence；两个循环共享有界 shutdown/cancellation。
- **Gateway/入口层**：每个 Cat 只消费一个当前 `cat_id -> node_id` 目标；本次协议不定义公网 TLS、hostname
  或缓存细节。
- **noded**：每台机器一个有效进程；注册 `node_id/node_name/control_endpoint`，按 `cat_id` 串行动作，
  reset 时停止并清理本机全部 Cat。
- **PostgreSQL**：Cat/Disk/Node 当前资源、`current_action`、bindings、heartbeat 和当前入口目标的事务域；
  也是底层 storage MetadataStore 的部署载体，但两类 authority 不混用。
- **Object Store**：保存 immutable Chunk/Map/Delta/Base/Snapshot objects，不决定当前 Cat、placement 或 writer。
- **独立 fleet authority**：`runtime_node_authority` 继续管理 provisioner-owned Node policy/credential，不进入
  Cat 生命周期、heartbeat 或 offline 恢复判断。

Guest 不持有 S3、MetadataStore、Control 或 WorkOS 凭据。已经 Running 的计算不依赖 Control heartbeat
继续执行；Control 全断会停止新动作和新入口更新，但不会主动终止已运行 VMM。

## 2. 故障合同

| 故障 | 继续 | 停止或降级 |
|---|---|---|
| 单个 Control replica 退出 | 其他 replica 从 PostgreSQL 当前行继续，并查询动作目标 Node | 该进程尚未返回的 HTTP response 可能丢失 |
| Control 全断 | 已 Running compute 和已有连接继续 | 新 mutation、状态转换、placement 和入口切换 |
| PostgreSQL 暂不可用 | 已 Running compute；底层缓存读按存储合同继续 | 新动作 claim、状态写回、入口更新、需要 metadata CAS 的 FLUSH |
| Object Store 暂不可用 | cache-hit read | 远端持久 FLUSH、Warm/Cold、迁移和 offline 恢复完成 |
| Control→noded response 丢失 | 重试相同动作或查询相同 `cat_id` | 任意延迟旧请求的 exactly-once |
| noded 进程重启 | 重新注册/reset 后从 Control 当前事实恢复服务 | 保留本地 Suspended/Warm 的进程级无损续跑 |
| Node 失联 | 先撤入口，在其他 Node 从远端恢复，旧 Node 回来 reset | 恢复窗口内严格物理单实例、旧连接立即停止 |
| Host 永久丢失 | 只恢复已经远端持久的数据 | 用 heartbeat timeout 证明 Host 已停止 |
| Gateway 退出 | 其他 Gateway 在 Control 健康时读取当前目标 | Control 全断时冷缓存 replica 的新流量 |

所有 connect/request/retry、heartbeat、health probe、drain 和 reset 都必须有界。超时产生明确
`timeout/node_unavailable/failure`，不能自动变成动作成功、Cold、writer release 或 Host fence。

## 3. PostgreSQL 与同步动作

同步 PostgreSQL driver 只在有界 blocking executor/connection pool 中运行，不能占住 async worker。
每类请求有独立 queue/running/deadline 指标和容量预算。

每个 Cat 当前行保存：

```text
state
current_action
current_action_started_at
current_action_node_id
node_id
last_error
```

Control 通过条件更新取得空闲 `current_action`；多 replica 同时竞争时只有一个成功。网络调用发生在
transaction 之外：

```text
检查当前资源和参数
-> claim current_action + target node
-> commit
-> sync call noded
-> compare/update stable result
-> clear current_action
```

相同动作的重复请求查询/等待同一目标；不同动作返回 `busy`。如果 noded 已完成而 Control 在写回前
退出，新 replica 读取 `current_action_node_id` 并查询 `GET /v1/cats/{cat_id}`。heartbeat、日志和 runtime
inventory 不能结算动作。`controld` 的 120 秒前台 deadline 覆盖 claim 后的 ingress 等待；相同 action 重试刷新数据库活动时钟但不改变 occurrence 身份。至少 135 秒没有前台活动、越过 deadline 和最长 10 秒 Create 清理窗口后的动作扫描、单例选举和精确终态 CAS 见
[Control–Node 语义协议 §10](control-node-semantic-protocol.md#10-control-plane-异常后的恢复)。

Create Cat 和 Create Disk 依靠当前 slug 的部分唯一索引串行化。destroy/delete 后历史行退出索引，slug
可立即创建新的内部 ID。Disk attach/detach/destroy 在同一 transaction 锁定目标 Disk 和 Cat；
`UNIQUE(disk_id)` 保证产品 binding RWO。

## 4. Node 注册、heartbeat 与 reset

noded 首次注册必须显式提供：

```text
node_id
node_name
control_endpoint
vendor / region / zone / instance_id / machine_type / version
```

Control 不根据请求来源地址猜 `control_endpoint`。`node_name` 和云实例身份创建后不能由 heartbeat
隐式修改；地址只允许在显式注册或 reset 完成后的重新注册更新。

每台 Node 在 `node_heartbeats` 只有一行最新值。Control 使用 PostgreSQL 接收时间写
`last_heartbeat_at` 并据此判断失联；`node_reported_at` 只用于诊断。

默认建议每 10 秒 heartbeat，连续 3 次未收到后进入 suspected 判断，再由 Control 调用一次
`GET /v1/health`。探测成功则保持 running，失败才标记 offline。

offline/reset_required Node 不能接受 placement。旧 Node 下一次 heartbeat 或 register收到
`reset_required` 后必须立即：

1. 停止接受新的 Cat 动作；
2. 停止本机所有 Cat 进程和设备；
3. 删除本地 Running/Suspended/Warm 状态；
4. 不删除 PersistentDisk 产品行、远端对象或 Control binding；
5. reset 完成后重新注册，得到 running 后才恢复 placement。

`deleted` Node 不得复活；同一机器重新提供服务时使用新的 `node_id`。

## 5. Node 失联恢复

恢复顺序固定为：

```text
heartbeat window exceeded
-> active health probe fails
-> mark node offline
-> withdraw each affected Cat's old ingress target
-> claim recovery target on another running Node
-> sync create/run from remote durable state
-> if original target was Suspended/Warm, convert back after Cold boot
-> publish only a Ready Running target
-> old Node later receives reset_required and cleans residues
```

恢复是 level-triggered，不依赖一次性内存事件。独立 recovery 周期重新查询 offline Node 上仍有稳定
placement 或未结束动作的 Cat；Control 重启、目标 Node 临时不可达或一次恢复失败后，后续周期继续从数据库
当前事实尝试。这个耗时 worker 不参与 heartbeat probe 的串行路径。

恢复前 withdraw，Ready 后 publish。旧 Node 的迟到 withdraw 不能删除新目标。Suspended/Warm 目标在新 Node
最终不发布入口；Running 只有 Guest 和全部 mounts Ready 后才发布。

这个流程有意不等待旧 Host fence。入口切换只约束新流量，旧连接、后台任务、出站请求和旧实例写盘
仍可能继续。ADR-0059 假设旧 Node 会在允许的 heartbeat 窗口内重新联系 Control，因此双跑通常不超过
heartbeat 窗口加停止清理时间。长期不对称网络不在当前保证范围。

## 6. Host fence 与数据 authority 的独立边界

heartbeat timeout、Node offline、入口撤销、reset 要求、lease expiry 和日志都不是 Host fence。可信的云/BMC
隔离证据仍是“旧 Host 已经停止”的独立 authority，`runtime_node_authority` 仍是受信 Node
provisioning/credential 的独立管理边界。

ADR-0059 只是不再把 HostFenceRecovery、AgentSession 或 fence predecessor 作为 Cat lifecycle 协调协议；
它没有把 Host fence 的含义转移给 heartbeat，也没有把 volume writer 权限转移给 Cat row。

底层存储仍要求：

- MetadataStore owner/attachment epoch 决定谁能发布远端 root；
- `disk_bindings` 只保证 Control 产品模型的 RWO，不能证明旧物理 writer 已停止；
- 成功 FLUSH 必须远端持久，当前简化恢复不能接纳 `R < L` 的 Node-local-only 成功数据；
- 未知磁盘、未知 writer、无法验证的 mount 或未持久数据 fail closed，不因 reset 被删除。

Automatic cloud/BMC fencing、真实 provider 资格和长期不对称分区处理仍是后续独立工作。不能把当前允许
的双跑窗口描述为已经获得严格 fencing 或完整生产 HA。

## 7. 正常维护与 drain

fleet administrator 通过以下无 body 管理接口启动正常 Node 退出：

```text
POST /v1/admin/nodes/{node_id}/actions/drain
```

Control 执行：

1. 将 Node 置为 `draining`，停止新 placement；
2. 为每个 Running/Suspended/Warm Cat 记录原状态，并用 Least-Allocated 策略预留另一个 running Node；
3. 将每个 Cat 转成 Cold，确认数据已经远端持久并关闭本地 writer；
4. 在其他 running Node run；
5. 原状态为 Suspended/Warm 时，在目标 Node 再转换到对应状态；
6. 返回逐 Cat 的 `migrated/stale/blocked` 结果。

`draining` 和 per-Cat relocation claim 都在 PostgreSQL 中持久化。周期任务反复发现仍有 Cat 的 draining
Node，所以请求取消或 Control 重启不会取消排空。普通生命周期动作不会被 drain 抢占；`busy`、没有目标
Node、源 Cold 失败或目标恢复失败都会返回顶层 `blocked`。任一 Cat 无法 Cold 时保留在源 Node，不强制
关机。入口依然遵守先撤旧、Ready 后发新；Suspended/Warm 的目标端瞬时 Running 不发布入口。

源 Cold 只要未确认成功（包括明确 failure/conflict）就不结算 `failure`，而是保留原 state 和 source
placement；因为 target effect 尚未开始，同一 settlement 释放未使用的 target reservation，后续 pass 重新
claim。目标端只有明确失败才结算到目标 `failure`，结果不明仍保留 exact claim。预留目标不再可用时，
后续 pass 在 Cat row lock 内原子改投另一个 running Node，旧目标的迟到 settlement 不能覆盖新
reservation。planned drain/recovery worker 与 heartbeat/liveness probe 分离，慢迁移不能推迟其他 Node 的
失联判定。

接口不会自动关机、delete 或 uncordon。只有收到 `drained` 并完成必要的失败清理/检查后，运维才执行独立
的 Node 停机步骤；Node 保持 `draining`，防止停机前重新接收 placement。

## 8. 运行监控

至少监控：

- Control：PG pool/queue/running/deadline、动作 CAS 冲突、`current_action` age、noded 调用耗时/重试/
  timeout、Node 查询恢复结果；
- Node：register/heartbeat 结果、reset_required、reset duration、per-Cat action age、busy/already/failure、
  本地清理失败；
- Fleet：last heartbeat DB age、连续丢失、active probe、running/draining/offline/reset_required 数量、
  recovery retry 和 Cat backlog；
- Ingress：withdraw/publish/resolve、旧 Node 迟到 withdraw、Ready 前 publish 拒绝；
- Storage：owner/epoch、远端 FLUSH latency/error、未远端持久数据、PersistentDisk provision/delete、
  UUID/mount readiness 和 delete blocker；
- Runtime：FakeVmm/Cloud Hypervisor effects、Guest readiness、mount readiness、Cold/restore/cleanup failure；
- Usage：counter gap/reset、projection/rating lag。

heartbeat、日志和监控事件都不是产品状态或磁盘 writer authority。

## 9. 分层 qualification

每一层使用 exact clean commit 和可重复 oracle：

1. **Pure/domain**：slug、配置比较、状态转换、错误闭集、Disk binding、Node registration/heartbeat 和
   入口目标规则。
2. **PostgreSQL integration**：并发 create、slug 复用、动作 CAS、Disk RWO、数据库时间 heartbeat、
   Control 写回前 crash-query、level-triggered offline recovery。
3. **HTTP/FakeVmm vertical**：真实 Control→noded HTTP Cat 全状态机和重复语义已通过；仍需补齐
   PersistentDisk→Cat→入口→offline/reset→destroy→slug 复用的完整链。
4. **Node local Linux**：真实 process/device cleanup、reset gate、Guest mount-ready、kernel-NBD 与
   vhost-user-blk。
5. **Cloud Hypervisor/Guest**：真实启动、pause、Warm/Cold、PersistentDisk provision/delete、文件系统身份、
   mount 和失败清理。
6. **Two-Node/failure**：heartbeat/probe、旧入口撤销、新实例 Ready、允许双跑窗口、旧 Node reset 和最终
   单实例；单列 Host fence provider 证据，不把它写进同步 lifecycle。
7. **Production cell**：真实 RDS/Object Store/secret/internal network、监控、rollback 和 exact immutable
   build receipt。

最终 handoff 运行 `./scripts/quality.sh full`。Node/Linux-only 变更还需要适用的 Linux/Cloud Hypervisor
门禁；若环境不可用，必须记录 exact commit 和阻塞，不能把 FakeVmm 结果冒充物理资格。

## 10. 首次单协议部署

本次只允许一次空数据 v19 cutover：

1. 离线构建相同版本的 Control、noded 和 CLI，验证 schema/wire 版本及旧入口 absence。
2. 进入维护窗口，关闭公网 ingress 和 mutation。
3. 停止旧 Control、Node、Gateway 和其他 write path，确认不会再写旧 schema。
4. 轮换或撤销旧 service/Node credential。
5. 删除旧产品/runtime 数据，创建唯一空 v19 schema；不迁移 Desired、Operation、journal、AgentSession、
   inventory settlement 或 Route lane。
6. 启动 Control；Node 清空本地 Cat 状态后，以 `node_id/node_name/control_endpoint` 注册。
7. 先验证 register/heartbeat/reset、资源 API 和 FakeVmm/PostgreSQL smoke，再执行适用的真实磁盘和
   Cloud Hypervisor qualification。
8. 只有 exact commit 的最终门禁和 operator review通过后才开放 mutation 和入口。

旧 schema、wire、parser、runner 和测试不提供双读、双写、转换器或 mixed-version fallback。历史实现由
Git 保留。

## 11. 明确不宣称

- 同步 semantic production composition和真实 Control→noded HTTP Cat 状态机已组成；Strict PersistentDisk
  backend 已接入 production composition。这不表示完整 PersistentDisk/Cloud Hypervisor 物理链或 production
  qualification 已通过。
- heartbeat/reset 的最终收敛不表示恢复窗口内严格物理单实例、严格物理单写或旧连接立即停止。
- heartbeat timeout、入口撤销、数据库 binding 和 audit log 都不是可信 Host fence。
- 当前协议不支持 Node-local-only 的成功持久数据；底层 Relaxed 能力不能直接用于此恢复流程。
- Warm/Suspended 不是跨 Host HA 副本。
- prototype 或单台测试机结果不自动成为 production SLA；报告必须保留 environment、sample count、
  boundary 和 oracle。
- privilege separation、cross-Node Guest overlay、automatic cloud/BMC fencing 和长期不对称网络处理仍是
  独立后续边界。
