# Runtime Reconciliation v1

- 状态：Target contract；尚未实现
- Authority：[ADR-0040](../decisions/0040-level-triggered-runtime-reconciliation.md)
- 生命周期：[runtime-lifecycle.md](../runtime-lifecycle.md)

本文定义 Control Plane 与 Node Agent 之间最小、可测试的收敛合同。传输可以是
heartbeat、long-poll 或普通 GET；正确性不得依赖通知必达、连接不断或消息只到达一次。

文中的 MUST/MUST NOT 是上线条件。

## 1. 身份与顺序

- `desired_revision`：每 Cat 单调递增、永不复用的 64-bit 正整数。
- `placement_epoch`：每次 placement owner 变化时单调递增。
- `runtime_incarnation`：每次创建 VMM 前生成并落盘的 128-bit 随机值。
- `agent_instance_id`：每次 Agent 进程启动生成的 128-bit 随机值。
- `agent_session_epoch`：每 Node 单调递增的服务端 session epoch。
- `heartbeat_sequence`：一个 Agent instance 内从 1 严格递增。
- `attachment_epoch`：MetadataStore 用于 RWO writer fencing 的单调 epoch。
- `route_epoch`：每个 Endpoint 的单调 serving epoch。binding变化时递增；任何实际关闭的gate若要
  重开，也必须先由新的完整Desired递增。只检查到Busy且从未close时不递增。

这些值分别阻止不同的 ABA，不得互相替代。新 revision 不证明旧 Host 已停止；Agent
restart 不改变 placement；Route TTL 不改变 attachment epoch。

## 2. 可信 Node 与 AgentSession

Node 不能用注册请求中的 `node_id` 自证身份。Node 上线前，IaC 或管理员必须先在 Control
Store 建立：

```text
NodeIdentity {
  node_id,
  immutable_host_id,
  credential_id,
  credential_public_key_hash | provider_principal,
  state_path_id,
  state: Provisioned | Retired
}
```

每个 Node 使用独立 credential。注册端同时验证 credential、`node_id` 和
`immutable_host_id` 的预置绑定；共享 fleet token、调用方任意指定 `node_id`、仅凭
hostname/IP 注册都不允许。credential 轮换是对同一 `NodeIdentity` 的显式管理操作。

Agent 在读取任何 runtime state 前，必须在由 `state_path_id` 决定的固定、受保护路径取得
Host 级 kernel 排他锁，并核对本地 root-owned identity。命令行更换 state directory 不能绕过
排他锁。同一 Host 的第二个 Agent 必须启动失败。

控制面每个 Node 只保存一个当前 session：

```text
AgentSession {
  node_id, immutable_host_id, node_boot_id,
  agent_instance_id, agent_session_epoch,
  registration_attempt_id, lease_deadline
}
```

一次成功的全量inventory还为当前session建立独立的签发证明：

```text
AdmissionInventoryAttestation {
  node_id, agent_session_epoch, inventory_epoch,
  inventory_digest, inventory_read_position, accepted_at
}
```

`inventory_epoch`在同一session内单调递增，`accepted_at`由PostgreSQL写入。后续partial heartbeat只
引用该epoch并upsert具体Cat，不能覆盖这条attestation。Route signer同时检查fresh attestation与
fresh per-Cat observation；不要求每次heartbeat重新做全量scan。

注册步骤如下：

1. Agent 先在 Host lock 下 fsync
   `AgentRegistrationAttempt {attempt_id, agent_instance_id, node_boot_id,
   expected_agent_session_epoch?}`，再发 RPC。
2. `(node_id, attempt_id)` 唯一；同一 attempt 的重复请求返回同一个 session，不重复提高
   epoch。
3. 同一 Host 上的新进程先重试本地遗留 attempt，解析上次模糊结果；随后可用精确
   `expected_agent_session_epoch` 和新 attempt 做 CAS replacement。Host lock 证明旧本地进程已退出。
4. 不同 Host 不能 replacement 同一 `node_id`。它必须先经过显式 retire/fence 和 reprovision，
   取得新的 NodeIdentity/credential。
5. heartbeat、desired 读取和 observation 都绑定当前 session。新 session 成功后，旧 session
   的所有请求永久拒绝。

## 3. DesiredRuntimeSpec

```text
DesiredRuntimeSpec {
  version: 1,
  workspace_id,
  cat_id,
  desired_revision,
  target: Running | Suspended | Warm | Cold | Deleted,
  placement: Assigned {node_id, placement_epoch},
  runtime: {
    vcpus, memory_bytes, boot_image_digest,
    guest_config_digest, network_config
  },
  volumes: [VolumeIntent],
  endpoints: [EndpointIntent],
  transition: CancelAndDrain | RequireIdle {
    attempt_id, source_revision, source_runtime_incarnation
  },
  spec_digest
}
```

一个 revision 是完整快照，不读取旧 revision 也能解释。数组按稳定 identity 排序且不能重复；
`spec_digest` 覆盖除自身外的全部规范化字段。同 revision 不同 digest 是
`Quarantined(SpecDigestConflict)`。

`placement` 始终存在，并标识负责本 revision 收敛的 Node。Cold 仍保留逻辑 owner，但 Cold
postcondition 不得依赖该 Host 的运行资源。Deleted 保留最后负责清理的 placement，直到 tombstone
满足第 13 节的回收条件。

### 3.1 VolumeIntent

`VolumeIntent` 至少包含稳定intent id、`attachment_id`、volume id、不可变`size_bytes`、
Root/Persistent disposition、RWO access、Strict/Relaxed durability、Guest device identity、
device slot和：

```text
acquire: Normal {transition_id, expected_unowned_epoch}
       | Takeover {authorization_id}
```

`Normal` 不能 revoke 其他 owner；同一 transition 的重试返回同一 LeaseGrant。`Takeover` 只
引用第 9 节的逐卷授权。授权行、MetadataStore CAS 与卷状态机由
[Volume Authority](volume-authority.md) 定义；它是 Runtime acquire/takeover 的硬依赖，Host
事件本身不授予卷写权限。HostFenceEvent来源的首次消费必须在同一PostgreSQL事务锁event、
authorization和VolumeRecord，完成卷CAS并写不可变`AuthorizationConsumedReceipt`。

Deleted Desired还为每卷显式声明`DetachRetained`或`DeleteDisposableRoot {delete_id}`。后一种只允许
Control Store权威分类的RootDisk；Node停止runtime/blockd并报告精确observation后，Control Plane才
建立同revision的`DisposableRootDeleteAuthorization`供reconciler查询和消费。PersistentDisk、未知
分类或stale revision一律不能使用。

需要 Guest mount 的 PersistentDisk 还包含：

```text
Ext4MountIntent {
  filesystem_uuid,
  mount_path,
  initialization: Existing | Initialize {
    initialization_token,
    expected_blank_root,
    expected_blank_generation
  }
}
```

`filesystem_uuid` 在 Disk 创建时预定。`Initialize` 只能来自 Control Store 中持久的
`Uninitialized(token, blank_root, generation)`，不得现场猜测空盘。Guest Agent 只有在 Node
取得精确 attachment、当前 Root/generation 与 blank predecessor 一致时才可格式化。已是预期
UUID 表示幂等完成；其他 UUID、predecessor 已变化或部分格式化痕迹都必须 quarantine。
format/probe 成功后先做 device flush，并要求 blockd 把初始化写 drain 到 `R == L`；Control Store
再以 token、blank predecessor、UUID 和新 remote head 做 CAS，转为 Initialized 并消费 token。
之后 Guest 才 mount；device/UUID/path/read-write 全部匹配后才能 Mounted/Ready。响应丢失时按
同一 token、UUID 和 remote head 幂等确认。

V1 不做热插拔、热拔盘或运行中改变 VM shape。当前状态不是精确 Cold 时，修改 CPU、内存、
boot image 或磁盘集合的请求以 `PreconditionFailed(MustBeCold)` 返回，不创建 Desired/Operation。
调用方需要变更时使用两个普通 mutation：

1. revision A 保留原 placement、shape 和磁盘集合，目标为 Cold；
2. A 的 Operation 成功后，revision B 写入新 shape/完整磁盘集合和请求的目标状态。

Control Plane 不为这两个请求保存额外 workflow；每个 Operation 都只绑定自己的 revision。
volume容量创建后不可变；Control Plane、MetadataStore、blockd与Guest合同都不提供resize API。

### 3.2 Endpoint 与 transition

`EndpointIntent` 至少包含endpoint id、hostname、route epoch、protocol和target port。route epoch
由Control Store在完整Desired事务中分配；目标非Running时它表达需要关闭的gate。

`RequireIdle` 只用于自动 Running -> Suspended。它就是一个已提交的普通 Desired revision：

1. Control Plane 以当前 Running revision/incarnation 为 compare condition，提交带唯一
   `attempt_id` 的完整 Suspended revision。
2. Node 先把 attempt 以 `Armed` fsync 到 checkpoint，再只执行一次
   `AdmissionCell.try_close_all_if_idle`。guard 非零时 cell/runtime 完全不变；Node 持久化并报告
   terminal `PreconditionFailed(Busy)`。
3. guards 为零时同时关闭全部 work admission，持久化 `Succeeded/Closed`，然后在 cell 外检查
   Guest watcher fresh+idle 并执行 quiesce fence。检查失败时同样terminal Busy，gate保持Closed；
   不能恢复旧serving epoch。
4. restart 看到 `Succeeded/Closed` 时继续转换；看到没有 terminal outcome 的 `Armed` 时保守
   结算 Busy。同一 attempt 永不因后来变 idle 而重试。
5. Control Plane接受Busy observation后，在一个compare transaction中把该Suspended Operation
   置为Failed，并创建复制原完整spec的新Running revision/Operation。若gate从未close，保留原
   route epochs；只要gate曾close或结果不明，新revision就提高全部可能关闭的Endpoint epochs。
   Node重新验证runtime、volume和route identity后只安装新epoch。

用户 stop、Node drain、destroy 使用 `CancelAndDrain`：关闭 gate、取消并有界等待 guards；
超时保留源并报告 Blocked。

### 3.3 提交、placement 与 Operation

所有API mutation共用PostgreSQL：

```text
ApiIdempotencyResult {
  authenticated_workspace_id, canonical_route, idempotency_key,
  request_fingerprint,
  outcome: Succeeded {http_status, response} | Failed {http_status, typed_error},
  created_at
}
```

主键是`(authenticated_workspace_id, canonical_route, idempotency_key)`。事务必须先取得该key的
transaction-scoped reservation并读取result，再取得任何domain资源锁；此前只验证调用者身份、当前
Workspace membership和route permission，不查询目标资源是否仍存在。同fingerprint重放只返回不可变
outcome，同key异fingerprint返回`IdempotencyConflict`。只有result miss才检查resource ownership和
tuple；跨Workspace miss回滚reservation且零持久副作用。首次执行的业务变化和最终result同一commit，
不保留持久Pending；无法提交事务时二者都不存在。V1已提交result不因resource或Operation删除而GC。

1. API 在创建 revision 前完成合法性、Cold-only 和 placement/capacity 检查。无法选择 Node
   时不创建 Desired 或 Operation；选中的 placement 与完整 spec/Operation 在同一事务提交。
2. 完整 spec、精确绑定它的 Operation与API result在同一 PostgreSQL 事务写入。同key重放返回
   同一不可变HTTP response；异步response包含原`operation_id`，但不复制Operation的可变phase或status。
   已经完全满足相同 spec 时不创建空 revision。
3. 新 revision 提交时，旧的 Pending Operation 原子变为 Superseded。
4. 每次 placement 变化都是一个新的完整 revision、提高后的 `placement_epoch` 和新
   Operation；不存在只改调度表、不改 Desired 的旁路。
5. Host loss 时，当前 Pending Operation 先以 `HostLost` Failed；取得第 9 节证据后，再创建
   指向新 placement 的系统 revision 和 Operation。已终结的历史 Operation 不改写。
6. placement 提交后若 Node 明确拒绝不可满足的容量/能力，当前 Operation Failed；Controller
   重新选择 Node 时必须创建新的系统 revision，不能原地替换 placement。

## 4. Desired delivery 与 AdmissionCell

Control Plane 必须支持 Node 周期性拉取其全部 assigned specs。push/notify 只能提前触发拉取。
列表带服务端读取位置和“完整集合”标志；一次缺项不能触发 orphan 删除。

Node 处理规则：

- 小于本地 applied revision：拒绝并报告 stale desired；
- revision 相等且 digest 相同：幂等 reconcile；
- revision 相等且 digest 不同：关闭 admission 并 quarantine；
- revision 更大：先持久化 checkpoint，再按 transition 更新 AdmissionCell，之后才做 cell 外
  副作用；
- placement 不匹配：关闭 admission，停止新增副作用并报告 residue。抢写只能消费逐卷 takeover
  authorization并完成epoch CAS；删除`R < L`只能消费精确disposable-root delete authorization。

每 Cat 只有一个 reconciler worker 修改 checkpoint 和物理资源。Running 热路径使用短临界区：

```text
AdmissionCell {
  applied_desired_revision, spec_digest, placement_epoch, runtime_incarnation?,
  lifecycle_admission: Open | Closed,
  endpoints: Map<endpoint_id, InstalledGate>,
  guards: Map<guard_id, Endpoint(endpoint_id) | Platform>
}
```

HTTP/WebSocket和exec/deploy/control都在同一个cell内检查admission并原子取得guard。收到更新的
非条件desired后，reconciler在cell内推进`applied_desired_revision`。Endpoint-only revision只
替换变化Endpoint的serving gate；未变Endpoint的route epoch/gate/guards保持不动。离开Running时
同时关闭全部gate。`RequireIdle`遇Busy时cell完全不变；一旦close，旧epoch永不重开。网络、
数据库、VMM、枚举和fsync都在cell外。

Agent 启动时 cell 默认 Closed。只有完成 session 注册、完整 inventory，并确认 desired、
placement、runtime incarnation、volumes和routes一致后，才可为Running打开。因为Agent进程重启使
内存gate实际关闭，Control Plane必须先为新AgentSession提交一个提高所有原Active Endpoint
route epochs的系统Desired revision；checkpoint中的旧epoch只能用于识别stale token，不能复活。

## 5. RuntimeCheckpoint

每 Cat 恰有一份当前 checkpoint：

```text
RuntimeCheckpoint {
  format_version,
  cat_id, node_id, placement_epoch,
  desired_revision, spec_digest,
  runtime_incarnation?, stable_state?, step,
  processes_and_scopes,
  volumes_and_local_paths,
  snapshot_identity?, route_gates,
  require_idle_attempt?,
  current_effect_token?, updated_at
}
```

要求：

1. 第一个物理副作用前写 revision、digest、placement 和窄 effect token。
2. 使用临时文件写入、file fsync、atomic rename、parent directory fsync。
3. 每个可见副作用后替换同一记录；稳定状态也保留 adoption/cleanup 所需身份。
4. checkpoint 大小只随当前 Cat 资源数增长；历史审计独立轮转，不能成为恢复前提。

checkpoint 是证据之一，不是排他的事实来源。

## 6. Inventory 与可用性

完整 inventory 合并：checkpoint、systemd scopes/cgroups、进程 start time、control socket
handshake、NBD/vhost-user/tap、data directories、pending packs、snapshot、MetadataStore
owner/epoch/root 和 blockd 的 attachment/`L/R`/fenced 状态。自描述进程必须握手；非自描述
资源必须有 ownership token。

以下场景必须先完成一次有边界的全量扫描，期间所有 AdmissionCell 保持 Closed：

- Agent 启动或 Host rejoin；
- adoption、orphan 判断和任何破坏性 cleanup；
- checkpoint 损坏或上一步结果不确定。

稳定Running期间还以独立、低频且有硬deadline的后台full scan刷新admission attestation；它不在
每次heartbeat执行，也不持有AdmissionCell。当前attestation尚fresh时，单次刷新失败按Degraded
处理并保持既有gate；超过签发freshness窗口后Control Plane停止签发新Grant，但不伪造冲突或
立即拆除VMM。

`complete_inventory=true`只表示该Node的全部约定来源在同一bounded scan中完成，并附带新
`inventory_epoch`、读取位置/digest；Control Plane接受后写入session级
AdmissionInventoryAttestation。普通heartbeat可只报告变化或单个Cat，必须标为false并引用最近
accepted inventory epoch；缺项不代表资源不存在，也不能覆盖attestation。

完整扫描失败但没有发现冲突时报告 `Blocked(IncompleteInventory)`，不执行 cleanup。已经验证
并稳定 Running 的 Cat，后续短暂无法读取 PostgreSQL、MetadataStore 或某个 inventory source
时报告 `Degraded`，冻结新的破坏性/生命周期副作用，但保持已验证的 VMM 和现有 admission。
一旦发现两个 VMM/writer、identity/epoch 冲突、无法归属的 `R < L` 或未知 PersistentDisk，
立即关闭相关 gates 并进入 Quarantined；这不是 Degraded。

完整 inventory 发现本地 Cat 不在 assigned desired 集合时只报告 Orphan。必须再用强身份、卷
与 Desired tombstone 证据决定 cleanup，不能因控制面缺行盲删。

## 7. Reconcile 与物理 effect

每个 worker 循环：

1. 读取最新完整 spec、checkpoint 和所需 inventory。
2. 分类为 Converged、NeedsStep、Blocked 或 Quarantined。
3. 再读当前 revision/placement，生成一个有界 next step。
4. 在副作用前持久化窄 token 和物理身份。
5. 执行一次副作用并查询物理 postcondition；超时不等于失败或成功。
6. 更新 checkpoint、发布 observation，再读取最新 desired。

“副作用前重读”不能消除网络调用期间的新 revision。正确合同是：旧结果不能结算或报告新
revision、不能取得新 placement/route/writer authority；已经在本地线性化的 VMM/systemd
动作可能在 supersede 后完成，但必须绑定精确 incarnation，保留 durable data，并由下一轮
reconcile adopt 或修复。

planner 只发出下表中的有界物理步骤；每个步骤实例只处理一个 volume、resource 或 systemd
unit。Inspect、Verify 和 Quarantine 本身不产生外部 effect。

| planner step | 副作用前必须持久化 | 可执行条件与晚到结果 |
|---|---|---|
| CloseAdmission | desired/cell revision、原gate集合、RequireIdle attempt state | cell内compare-and-close；Armed模糊结果按Busy且Closed结算，fresh Running只以更高route epochs重开 |
| AcquireVolume | volume、attachment、transition id + expected unowned epoch，或 authorization id | MetadataStore 精确 CAS；authorization首次消费还要求Active event并原子写`AuthorizationConsumedReceipt`；只有同 transition/authorization 可 adopt，或在 `R == L` 后精确 release |
| PrepareDevices | NBD/tap/socket slot、ownership token | 完整 inventory 后 create-if-absent；晚到资源只按 token adopt 或删除 |
| FormatFilesystem | attachment、device、filesystem UUID、initialization token、blank predecessor | Guest Agent 只按精确 predecessor 格式化；晚到结果按 UUID probe/adopt，冲突立即 quarantine |
| DrainInitialization | attachment epoch、local/remote root generation | device flush 后只向精确 owner/epoch publish，直到 `R == L` |
| CommitInitialized | token、blank predecessor、UUID、新 remote head | Control Store 精确 CAS；相同结果幂等，冲突 quarantine |
| MountFilesystem | attachment、device、UUID、mount path | 只 mount 精确 device/UUID；晚到 mount 不产生 route authority，stale 时按精确 identity unmount |
| StartRuntime | runtime incarnation、scope/socket 名、process identity token | create-if-absent 后握手；晚到进程不开放 route，当前 spec 不再需要时按精确身份停止 |
| DrainPublish | attachment epoch、local/remote root generation | 只向精确 owner/epoch CAS publish；晚到成功可安全 adopt，旧 epoch 不能写新 root |
| PauseRuntime | runtime incarnation、process start time | 只 pause 该 incarnation；晚到 pause 可发生，当前 revision 负责 resume 或重建 |
| SnapshotWarmRuntime | runtime incarnation、snapshot temp id、source root/epoch | 验证VMM postcondition与durable rename；晚到文件不覆盖其他WarmRuntimeSnapshot |
| StopRuntime | runtime incarnation、process start time、scope id | 只 stop 该 incarnation；晚到 stop 可发生，当前 revision 负责重建 |
| CleanupRelease | 全部物理 identity、`R == L`/disposition、当前 desired 读取位置 | 只删匹配资源、只 release 精确 owner/epoch；stale cleanup 不得按可重算名称删除新资源 |
| DeleteDisposableRoot | delete authorization、精确lineage、owner/epoch/head | 无live DiskSnapshotRecord且Guest/VMM/blockd已停后，按event/auth/volume/control锁序原子写Consumed receipt及两边Deleting；成功后才删该`R < L`lineage |
| InstallGate | desired checkpoint、spec digest、placement、runtime incarnation、endpoint/route epoch | cell只接受一个serving epoch；任何已close gate必须由更大epoch重开 |

每步都可被 kill。重启后只能确认 postcondition、重试同一 token、继续或 quarantine，不能先
teardown 再重做。不建立通用 effect workflow。

## 8. 外部边界

- Volume normal acquire：只允许精确 `expected_unowned_epoch` 的 Unowned -> this attachment；只有
  重放同一 `transition_id` 才返回原 LeaseGrant。
- Volume publish/release：携带 expected owner/epoch/root；PersistentDisk release 前 `R == L`。
- VMM/blockd/systemd：名称含 Cat/incarnation，使用 process start time 和 socket handshake。
- NBD slot、tap 等共享资源：完整 inventory 后分配，checkpoint 先写 ownership token。
- WarmRuntimeSnapshot：先写temp identity；成功要求VMM postcondition、文件metadata和durable
  rename。产品DiskSnapshot不走Runtime planner，只能按Volume Authority在stable Cold/unowned时
  使用通用API key reservation，再锁VolumeRecord、重验认证Workspace拥有Disk及精确tuple，并在一个
  PostgreSQL事务写业务变化与result。create插入的单一`DiskSnapshotRecord`同时是产品资源和GC
  live-root；delete删该row，restore前进Volume head。重放只读result。只支持同盘restore，不支持clone
  或Golden Image GC。
- Route：遵守 [Route Grant v2](route-grant-v2.md) 的本地 gate/guard 合同。

任何cleanup只作用于精确物理identity。普通volume delete必须证明无Desired intent、无有效
attachment、无inventory residue，并且不存在live `DiskSnapshotRecord`；任一仍存在即返回
`SnapshotInUse`且不改变Disk/Volume。Snapshot必须按Volume Authority通过通用API result幂等删除该row，
Disk delete不隐式cascade。normal `begin_delete`锁VolumeRecord并在同一PostgreSQL事务把Control Disk
与VolumeRecord从Active改为相同Deleting；normal acquire与它只能一方提交。当前Deleted Desired中的
disposable Root可使用
[Volume Authority §11](volume-authority.md#11-delete)的精确Owned->Deleting授权；CAS成功前不能清
tail。HostFenceEvent来源按`event -> authorization -> VolumeRecord -> Control rows`锁序，在同一事务
写Consumed receipt和两边Deleting；成功后只清授权lineage。RPC超时不回滚Desired。

## 9. HostFenceEvent 与逐卷 takeover

heartbeat timeout 只产生 `NodeSuspected`，不能提高 placement 或 attachment epoch。Host loss
必须由 provider/BMC adapter 的权威结果建立一个 durable event：

```text
HostFenceEvent {
  event_id, provider, immutable_host_id, node_id, expected_node_boot_id,
  expected_agent_session_epoch, fence_attempt_id,
  isolation_state, observed_at,
  state: Active | Rejoined
}
```

同一 fence attempt 只保留一个 event。Active event 是 Host 级隔离事实，不是卷权限。Control
Plane 对旧 placement 中每个需要恢复的卷分别创建：

```text
VolumeTakeoverAuthorization {
  authorization_id, host_fence_event_id,
  volume_id, expected_owner, expected_epoch,
  new_attachment_id, desired_revision, new_placement_epoch,
  not_after, issuer_proof
}
```

首次消费按固定锁序`HostFenceEvent -> authorization -> VolumeRecord`，要求event仍为Active和数据库
时间未超过`not_after`，在同一PostgreSQL事务完成精确逐卷CAS并写不可变
`AuthorizationConsumedReceipt`。相同authorization只读取receipt并返回同一LeaseGrant，不再次改变
volume；换卷、换旧owner、换attachment、换placement、过期或Rejoined后的首次消费都失败。运行时
Desired的`attachment_id`、revision、placement必须与authorization一致，对应`VolumeIntent.acquire`
必须引用该authorization。精确schema/CAS以[Volume Authority](volume-authority.md)为准。

provider receipt只建立Active HostFenceEvent，不直接授予placement或writer。Control Plane先把旧
Pending Operation置为`Failed(HostLost)`，再在一个事务中创建新完整Desired/Operation、placement、
全部新attachments和每卷VolumeTakeoverAuthorization；新Desired逐卷引用授权。目标Node消费所有
MetadataStore CAS后才能Ready，不存在另一种writer-proof fallback。

session失效或提高attachment epoch不是解除旧Host隔离的条件。旧Host重用前必须在隔离网络内以
新boot/session完成完整inventory，保持gates Closed，停止旧runtime/transport/socket/tap/guards，
并把旧epoch的`R < L` lineage移入quarantine而非删除。授权派生、首次消费和
`Active -> Rejoined`都先锁同一event行；rejoin再按稳定顺序锁定该event的全部授权，所以不会漏掉
in-flight首次消费。Control Plane核对每个Unconsumed授权都已过`not_after`，每个Consumed授权都有
匹配payload的不可变receipt；当前VolumeRecord必须是receipt直接结果或更大epoch的合法状态机后继，
receipt含Disk postcondition时Control Disk也必须匹配同一Deleting；两边记录已删除时必须有精确
`DeleteCompletionReceipt`。缺失、倒退或冲突保持Blocked。接受
`HostRejoinProof`并在同一事务把event持久转为Rejoined后provider才恢复workload网络；此后未消费
授权不能首次生效，已消费授权只幂等读取receipt。相关authorization和`DeleteCompletionReceipt`保留到Rejoined。

## 10. Observation 与 Conditions

```text
NodeObservation {
  node_id, node_boot_id, agent_instance_id, agent_session_epoch,
  heartbeat_sequence, observed_at,
  complete_inventory, inventory_epoch, inventory_digest?, inventory_read_position?,
  key_ring_version, key_ring_digest, loaded_kids,
  runtimes: [ObservedRuntimeStatus]
}
```

runtime status至少包含desired revision/digest、placement epoch、runtime incarnation、稳定状态/
step、Conditions、进程证据、逐卷owner/epoch/`R/L`、mount与routes/guards。Control Plane只接受
当前session/instance的递增sequence；Node的`observed_at`不用于排序或freshness。
`complete_inventory=false`时只upsert报告中列出的Cat，不能按缺项删除，并且不得覆盖当前
AdmissionInventoryAttestation；true时才可按读取位置和inventory digest对完整集合做residue
对账并建立新attestation。所有freshness使用PostgreSQL `accepted_at`。

Condition type 是闭集：`Ready`、`Progressing`、`Blocked`、`PreconditionFailed`、`Degraded`、
`Quarantined`、`DataLossPossible`。Conditions是可并存的集合；reason和evidence使用有类型字段，
不能按message文本分支。

- Blocked 是可重试前置条件，Operation 保持 Pending。
- PreconditionFailed 是该 revision 的终态；例如 RequireIdle Busy 使 Operation Failed。
- Degraded 表示已验证的稳定服务继续运行，但暂时不能安全做新副作用。attestation和per-Cat
  facts仍fresh时可报告`Ready + Degraded`，保持既有admission并允许signer继续验证Ready；任一
  freshness过期或安全postcondition不再可证时必须移除Ready并停止新Grant签发。
- Quarantined 表示确定的身份/ownership 冲突；立即关闭 gates，并使当前 Pending Operation
  Failed。修复或删除必须提交新 revision。若该 revision 的 Operation 早已 Succeeded，不回写
  历史结果；控制面创建新的系统修复 revision 来承载失败与处置。

## 11. 稳定 postcondition

- **Running**：VMM/Guest Ready；精确 VM shape、磁盘/epoch/mount 集合；无未知 residue；当前
  Endpoint gates Active；observation 与 revision/incarnation 匹配。
- **Suspended**：gates Closed 且 guards=0；VMM paused；本地 durability barrier 完成；所有
  `R < L` journal/lease/blockd 保留。
- **Warm**：gates Closed；VMM 不存在；snapshot 已验证；所有保留卷 `R == L`。
- **Cold**：gates Closed；VMM/blockd 不存在；保留卷 `R == L` 且 attachment 已释放；本地只剩
  可删除 cache/诊断证据。
- **Deleted**：无可服务 route/runtime；Root 按 disposition 处理；PersistentDisk 只 detach，
  不删除；待删除Disk没有live `DiskSnapshotRecord`；普通卷已release，disposable Root已消费精确delete
  authorization；开始删除时Control Disk与VolumeRecord已原子进入同一Deleting，完成后有精确
  DeleteCompletionReceipt；没有未知卷或未跟踪的attachment residue。

未满足完整条件只能 Progressing、Blocked、Degraded 或 Quarantined，不能发布目标稳定态。

## 12. Operation 与 placement 闭环

Operation phase：Pending、Succeeded、Failed、Superseded。

- 只有 `operation.desired_revision == observation.desired_revision == current desired`，并同时
  匹配 placement 与完整 postcondition，才能 Succeeded。
- 新 revision 在同一事务把旧 Pending Operation 变为 Superseded。
- PreconditionFailed、永久请求错误、HostLost 或 Quarantined 使当前 Pending Operation Failed。
- Progressing、Blocked、Degraded 和暂时离线保持 Pending。

N+2 达到同名状态不能结算 N。observation 不写 Desired；所有用户和系统 placement 变更都走
资源 API/Controller 的完整 revision 事务。

计划跨 Node 迁移只用两个普通 revision：

1. revision A 在源 placement 目标 Cold；成功条件包括 `R == L`、runtime 停止和 attachments
   release。
2. A 成功后，revision B 提高 placement epoch、指向目标 Node，并恢复迁移前目标（通常
   Running）。目标使用新的 attachment identity 做普通 acquire。

源未达到精确 Cold 不创建 B。整个过程始终只有当前 Desired revision 是 authority。

## 13. Deleted 与保留

Deleted Desired 是 tombstone，不能在提交后立即删行。其 Operation 只有在第 11 节 Deleted
postcondition满足时成功。若负责 Node 永久丢失，需要 provider 的 Host 已销毁证据，或该 Host
rejoin 后的空 inventory，才能证明物理 runtime 已不存在；仅网络隔离足以阻止服务，不足以
声称 residue 已清空。

Operation 结算、volume disposition 完成且不存在 fence/rejoin 待办后，才可 GC 当前 Desired、
observation 和 checkpoint 索引。审计按独立产品策略保留。Node 删除 checkpoint 前还必须证明
无runtime、无未跟踪volume residue和无route gate。授权丢弃的Root lineage必须已删除；Active
HostFenceEvent上的隔离lineage由event/rejoin记录继续跟踪，关联的authorization与
`DeleteCompletionReceipt`必须保留到Rejoined，不能因VolumeRecord或本地目录缺席猜测消失。

## 14. 最小验收矩阵

| 场景 | Oracle |
|---|---|
| N/N+1/N+2 ABA | 旧结果不能结算/授权 N+2；已线性化的本地 effect 可被下一轮安全修复 |
| 双 Agent / register 响应丢失 | Host lock 排他；同 attempt 返回同 session；旧 session 永久拒绝 |
| 各 planner step kill | restart 后确认、重试、继续或 quarantine；无重复 writer/误删 |
| normal acquire 遇到旧 owner | Blocked，不 revoke；只有精确逐卷 takeover authorization 可 CAS |
| Running 改盘/shape | 请求先 PreconditionFailed(MustBeCold)；Cold 成功后的新请求才改完整 spec |
| `R < L` + remote down | Suspend 可完成；Warm/Cold/detach/migrate 阻塞且唯一数据保留 |
| startup/inventory source down | gates 保持 Closed，Blocked；稳定 Running 的短暂故障为 Degraded |
| RequireIdle Busy/crash | attempt 只评估一次，Suspended Operation Failed，系统创建新 Running revision |
| identity conflict | gates Closed，Quarantined，当前 Pending Operation Failed |
| Host fence 与多个卷 | 一个 HostFenceEvent 派生多个独立逐卷授权；错 tuple 全部拒绝 |
| authorization consume 与Rejoined并发 | 两者锁同一event；只能consume先提交并留下receipt，或Rejoined先提交且epoch不变 |
| consumed授权后继 | takeover→release与delete→sweep后均可凭单调状态/精确DeleteCompletionReceipt完成rejoin；错receipt保持Blocked |
| normal acquire与begin-delete并发 | 同一VolumeRecord串行且只能一方提交；Control Disk与Volume不会出现单边Deleting |
| disposable Root `R < L` | event/auth/volume/control同事务写receipt和两边Deleting后才删lineage；PersistentDisk拒绝 |
| Snapshot create crash/响应丢失 | exact record与成功result同时提交或都不存在；重放只读result，不从record缺席推断可重建 |
| create→delete→旧create重放 | 返回原成功result和原snapshot ID，不重新插row；snapshot ID永不复用 |
| Snapshot跨Workspace访问/重放 | NotFound/Forbidden；不写Operation/result，不改变Volume、Disk或Snapshot |
| Snapshot API同key异payload | 在资源锁前返回IdempotencyConflict，保留原result且不改变资源 |
| Snapshot与Disk delete并发 | create/begin-delete锁同一VolumeRecord；live record返回SnapshotInUse且两边状态不变 |
| Deleted | tombstone 保留到物理/卷/route postcondition 和 Operation 闭环 |

## 15. Clean-slate 切换

首次部署按 [Operations and HA §8](../operations-ha.md#8-首次终态部署)执行。本规格的切换前置是：
目标 schema 只包含本合同的 NodeIdentity、AgentSession、Desired、Operation、observation 与
attestation；exact release 不含 NodeJob、heartbeat overwrite 或旧 ledger 恢复入口；空 fleet 的
Node 必须先完成 session 注册和 complete empty inventory，才允许任何 Running Desired。
