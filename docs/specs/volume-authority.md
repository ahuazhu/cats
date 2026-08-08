# Volume Authority 与磁盘生命周期

- 状态：目标合同；尚未实现
- 决策：[ADR-0042](../decisions/0042-volume-authority-and-disk-lifecycle.md)
- 协调协议：[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
- 数据协议：[cats-blockd 协议](blockd-protocol.md)

本文定义卷从创建、附着、格式化、快照、迁移到删除的完整合同。目标是让每个危险动作都由
一个窄的条件状态转换保护，而不是依靠 TTL、控制面缓存或“调用看起来成功”。

本规格只声明存储前置条件：删除现有 Cat、Disk、Snapshot、volume metadata、对象和 Node 本地
目录后启用本合同；实现不读取旧 pending pack，不转换旧 attachment，也不长期保留两套接口。
完整、有序的操作以[Operations and HA §8](../operations-ha.md#8-首次终态部署)为唯一runbook。

## 1. 权威和不变量

每类事实只有一个权威：

| 事实 | 权威 |
|---|---|
| Disk 是否存在、属于哪个 Workspace、是否可加入 Cat | Control Store |
| 当前 DesiredRuntimeSpec 中的完整磁盘集合 | Control Store |
| 当前 volume owner、fencing epoch、remote Root | MetadataStore |
| DiskSnapshot产品资源与GC live-root | DiskSnapshotRecord |
| API mutation的请求身份与不可变返回结果 | PostgreSQL `ApiIdempotencyResult` |
| 本地 pending pack、cache、blockd 进程是否存在 | Node 物理 inventory |
| ext4 UUID 和当前 mount 是否真实存在 | Guest Agent probe |
| Host 是否已被外部隔离、逐卷授权是否已消费 | PostgreSQL HostFenceEvent/Authorization rows |

Control Store 与 MetadataStore 是逻辑边界，不是两套提交authority。生产终态把`HostFenceEvent`、
由它派生的authorization、不可变消费回执和`VolumeRecord`放在同一PostgreSQL事务域；SQLite contract
adapter提供相同原子语义。首次消费授权与`Active -> Rejoined`都通过该事务域的固定锁序完成。

全局锁DAG是`ApiIdempotencyResult key reservation -> HostFenceEvent -> AuthorizationRecord ->
VolumeRecord -> Control Disk/Cat/Desired rows -> DiskSnapshotRecord`；事务跳过自己不涉及的节点，同类
多行按稳定ID排序。API mutation先取得由认证Workspace、canonical route和`Idempotency-Key`导出的
PostgreSQL transaction-scoped reservation，再读结果；它不能先锁资源，也不落持久Pending。这样同一
key即使携带不同资源也不会分别先锁不同Volume。normal acquire只锁`VolumeRecord`，因此它与snapshot
mutation或begin-delete仍只能有一方先提交。HostFenceEvent来源的内部恢复没有API前缀，从event开始。

必须始终满足：

1. 一个 RWO volume 同时最多一个 owner/epoch 可以发布 Root。
2. 所有 ownership 变化都增加 epoch；旧 epoch 永久失败。
3. lease TTL 只表示 owner 多久没有续约，不授予其他 attachment 抢占权。
4. `R <= L`。Strict FLUSH 在 `R` 前进后 ACK，Relaxed FLUSH 在 `L` 前进后 ACK。
5. `R < L` 的 pack 绑定一个精确 attachment lineage，不能被新 attachment 采用。
6. Cold、磁盘集合变更、DiskSnapshot、detach、计划迁移和删除保留盘前必须 `R == L`；唯一例外是
   当前 Deleted Desired 明确放弃的 disposable Root，并且必须先消费 §11 的精确删除授权。
7. Volume admin 操作和普通 attach 不能并发越过彼此。
8. 每条`DiskSnapshotRecord`命名的Root必须进入GC live set；不存在第二份物化记录。
9. Snapshot API先验证调用者身份、当前Workspace membership和route permission，再reserve/read该
   Workspace的幂等key；精确命中直接返回result。只有miss才在事务内重验Workspace拥有Disk及精确
   disk/volume/snapshot tuple；跨Workspace miss返回不泄露存在性的`NotFound`/`Forbidden`并回滚
   reservation，不写Operation、result或资源行。

## 2. 核心身份

- `attachment_id`：一次逻辑 attachment 的全局唯一 ID；创建后永不复用。
- `attachment_epoch`：MetadataStore 中每卷单调递增的 fencing 数字。
- `transition_id`：一次 lease/admin 状态转换的全局唯一 ID；重试必须复用，其他操作不得复用。
- `desired_revision`、`placement_epoch`：来自 Runtime Reconciliation 合同。
- `HostFenceEventId`：一次 Host 外部隔离事件的稳定 ID。

`transition_id` 解决响应丢失，epoch 解决 ABA。两者不能互相代替。

## 3. PostgreSQL authority 模型

逻辑Control Store/MetadataStore记录如下；具体 SQL 可以拆表，但标明原子的条件必须在一个数据库
事务中完成：

```text
VolumeRecord {
  volume_id,
  size_bytes,
  durability: Strict | Relaxed,
  admin_state: Active | Deleting { delete_id },
  generation,
  root_hash?,
  root_object_id?,

  lease_owner?,
  lease_epoch,
  lease_expires_at?,
  last_transition: {
    transition_id,
    kind: Acquire | Release | Takeover | BeginDelete | BeginDisposableDelete,
    request_fingerprint,
    attachment_id?,
    resulting_epoch
  }?,
}

DiskRecord {
  disk_id,
  workspace_id,
  volume_id,
  state: Active | Deleting { delete_id }
}

DiskSnapshotRecord {
  snapshot_id,
  disk_id,
  volume_id,
  size_bytes,
  generation,
  root_hash?,
  root_object_id?,
  created_at
}

ApiIdempotencyResult {
  authenticated_workspace_id,
  canonical_route,
  idempotency_key,
  request_fingerprint,
  outcome: Succeeded { http_status, response }
         | Failed { http_status, typed_error },
  created_at
}

AuthorizationRecord {
  authorization_id,
  host_fence_event_id?,
  kind: Takeover | DisposableRootDelete,
  payload,
  request_fingerprint,
  not_after,
  state: Unconsumed | Consumed { receipt: AuthorizationConsumedReceipt }
}

AuthorizationConsumedReceipt {
  authorization_id,
  request_fingerprint,
  volume_id,
  transition_kind: Takeover | BeginDisposableDelete,
  resulting_epoch,
  resulting_admin_state,
  resulting_disk_state?,
  resulting_owner?,
  resulting_attachment_id?,
  consumed_at
}

DeleteCompletionReceipt {
  disk_id,
  volume_id,
  delete_id,
  deleting_epoch,
  begin_transition_id,
  begin_request_fingerprint,
  completed_at
}
```

`ApiIdempotencyResult`的主键是`(authenticated_workspace_id, canonical_route, idempotency_key)`。
`request_fingerprint`覆盖规范化route参数和请求body；同key同fingerprint只返回不可变`outcome`，同key
不同fingerprint在读取任何资源锁前返回`IdempotencyConflict`。首次请求在reservation下执行一次资源
事务，并在同一commit写最终result；业务成功或确定性业务失败可以结算，serialization、连接中断或
无法提交事务不写result。V1的已提交result不因对应resource或Operation删除而GC，也不通过resource是否
仍存在决定是否重放；它是API重试权威，不是Snapshot产品查询或GC authority。异步接口把
`operation_id`放在不可变HTTP response中，但不复制Operation的phase或status；Snapshot create、delete
和restore是同步事务，不创建Operation。

`AuthorizationConsumedReceipt`一经写入不可修改，只记录授权首次消费的直接Volume/Disk结果，并保留到相关
HostFenceEvent转为Rejoined。`DeleteCompletionReceipt`只在`VolumeRecord`被删除后证明同一卷、delete
和epoch已经沿状态机完成；它保留到删除Operation结算，且只要仍有引用该卷的Active HostFenceEvent
就必须继续保留。

`request_fingerprint`是规范化完整请求的hash。同一ID但payload不同返回`StaleTransition`。只保留
最近一次转换结果；Control Plane在一个转换结果被确认前不得启动下一转换。已经被后续转换取代的
旧重试返回`StaleTransition`且不产生副作用，绝不重新执行。

`lease_epoch` 在 acquire、release、takeover 以及会改变 attach 前提的 restore/delete
边界单调增加。这样，晚到的旧 acquire 即使看到 volume 再次 Unowned，也不能用旧
`expected_epoch` 复活。

MetadataStore 错误是闭集：`NotFound`、`OtherWriter`、`Fenced`、`StaleTransition`、
`AdminBusy`、`HeadConflict`、`SnapshotInUse`、`InvalidAuthorization`、`BackendUnknown`。调用方不得
按文本分支。

### 3.1 Volume核心状态机

| 当前状态 | 唯一允许的转换 | 结果 |
|---|---|---|
| Active + Unowned | normal acquire | Active + Owned(new attachment, epoch + 1) |
| Active + Owned | renew | owner/epoch不变，只延长health TTL |
| Active + Owned | exact release | Active + Unowned(epoch + 1) |
| Active + Owned | authorized takeover | Active + Owned(new attachment, epoch + 1) |
| Active + Unowned | same-disk restore | Active + Unowned(new head/generation, epoch + 1) |
| Active + Unowned | begin delete | Deleting(delete_id, epoch + 1) |
| Active + Owned | authorized disposable Root delete | Deleting(delete_id, owner cleared, epoch + 1) |
| Deleting | idempotent sweep完成 | Removed |

表外转换全部拒绝。`transition_id`只让表内同一次转换可重试，不允许跳过前置状态。

## 4. Lease 接口和状态机

### 4.1 Normal acquire

```text
acquire_normal {
  volume_id,
  transition_id,
  attachment_id,
  expected_unowned_epoch,
  desired_revision,
  placement_epoch,
  ttl
} -> LeaseGrant {attachment_id, epoch, transition_id}
```

原子规则：

1. `admin_state` 必须是 Active。
2. `lease_owner` 必须为空，且当前 epoch 等于 `expected_unowned_epoch`。
3. 成功时设置 owner，epoch 增加 1，并保存 transition/result。
4. 同一 `transition_id` 的重试返回原 `LeaseGrant`，不再增加 epoch。
5. 任何其他 owner，即使 TTL 已过，也返回 `OtherWriter`。
6. 同一 attachment 但不同 transition 也不隐式采用；reconciler 必须使用原 transition 或明确
   quarantine。

Node 在调用前把 request 写入 RuntimeCheckpoint。响应不明确时读取 VolumeRecord：只有
`last_transition.transition_id`、owner 和结果 epoch 全部匹配才算成功。

### 4.2 Renew

```text
renew {volume_id, attachment_id, epoch, ttl}
```

只有 owner/epoch 精确匹配时更新时间。单纯 TTL lapse 可以继续 renew；owner/epoch 改变后返回
`Fenced`。renew 不改变 epoch，也不能把其他 owner 改成自己。

### 4.3 Release

```text
release {
  volume_id,
  transition_id,
  attachment_id,
  expected_epoch
} -> UnownedGrant {epoch, transition_id}
```

release 的前置条件是 blockd 已停止接受 I/O，所有保留数据 `R == L`，且 owner/epoch 精确匹配。
成功时清空 owner、增加 epoch并保存 transition。相同 transition 重试返回相同结果；其他不匹配
返回 `Fenced`，不能静默成功。

### 4.4 Protected takeover

普通 reconcile 不存在 revoke。takeover 只接受逐卷授权：

```text
VolumeTakeoverAuthorization {
  authorization_id,
  host_fence_event_id,
  volume_id,
  expected_owner,
  expected_epoch,
  new_attachment_id,
  desired_revision,
  new_placement_epoch,
  not_after,
  issuer_proof
}
```

首次消费使用固定锁序`HostFenceEvent -> AuthorizationRecord -> VolumeRecord`，在一个PostgreSQL
事务中同时验证event仍为Active、authorization仍为Unconsumed、数据库当前时间未超过`not_after`、
旧owner/epoch和目标identity精确匹配；随后设置新owner、增加epoch，并原子把authorization改为
`Consumed(AuthorizationConsumedReceipt)`。`authorization_id`同时是transition ID。

相同授权重试只读取不可变receipt并返回原grant，即使event已经Rejoined也不再次修改VolumeRecord。
换卷、换placement、换attachment、payload不同、过期或event不再Active的首次消费全部返回
`InvalidAuthorization`。

### 4.5 Host fence 与逐卷授权

`HostFenceEvent` 是 Host 级事实：

```text
HostFenceEvent {
  event_id,
  provider,
  immutable_host_id,
  node_id,
  expected_node_boot_id,
  expected_agent_session_epoch,
  fence_attempt_id,
  isolation_state: HostIsolationState,
  observed_at,
  state: Active | Rejoined
}

HostIsolationState =
  { kind: "isolated" }
| { kind: "host_destroyed", receipt: HostDestroyedReceipt }

HostDestroyedReceipt {
  provider: Id,
  immutable_host_id: Id,
  node_id: Id,
  expected_node_boot_id: NodeBootId,
  expected_agent_session_epoch: Epoch,
  state_path_id: Id,
  state_storage_disposition: "permanently_destroyed",
  destroyed_at_unix_ms: UnixMillis
}
```

Control Plane 只在 provider/BMC 证明旧 Host 已隔离且隔离仍被维持时建立 Active event。它为该
Host 上每个需要恢复的 volume 派生独立 `VolumeTakeoverAuthorization`。一个 Host event 可以派生
多份授权；每份授权只能消费一次。heartbeat timeout、route TTL、AgentSession 失效都不能建立
event。

`host_destroyed`复用同一event行，只能来自provider adapter验证过的HostDestroyed receipt。receipt必须
把provider、immutable Host、node及expected boot/session逐字段绑定event，并把immutable Host、node和
state path绑定该event创建时锁定的`NodeIdentity` immutable lineage（该row此后可以retired）；provider
adapter还必须证明承载该state path的storage永久销毁。network isolation、power state或普通`isolated`
不能升级推断出这个事实。
Active event可以直接以`host_destroyed`建立，或从`isolated`单调更新；receipt一经提交不可变，相同
receipt重放只读原结果，任一字段不同都拒绝。`host_destroyed`不会转为Rejoined；替换Host必须使用新的
provisioned identity。
该receipt只可作为Runtime tombstone GC的Host缺席证据，不授予placement/writer，也不跳过本规格的逐卷
authorization、receipt或disposition闭环。

旧 Host 恢复时先进入隔离rejoin流程：提高AgentSession epoch，枚举并停止全部旧VMM/blockd，按
`VolumeLocalIdentity`把所有失效epoch目录移入quarantine，并证明旧route、socket和进程均不可用。

从`isolated`升级时先锁同一event行，并用`state=Active`、`isolation_state={kind:"isolated"}`及未改变的
完整event tuple（`event_id`、provider、immutable host、node、expected boot/session、fence attempt和
`observed_at`）做exact CAS。`isolated -> host_destroyed`、授权派生、授权首次消费、
`Active -> Rejoined`和使用HostDestroyed proof的Runtime tombstone GC都持有该行锁到事务提交并重验各自
要求的state、isolation variant和event tuple；竞争事务只能按锁取得顺序提交，后一方不得沿用旧读取。
rejoin事务取得该锁后，按
`authorization_id`稳定顺序锁定该event的全部授权，因此不存在已经开始但尚未被它观察的首次消费。
它逐项验证：

1. Unconsumed授权必须按PostgreSQL当前时间超过`not_after`；否则保持Active/Blocked。
2. Consumed授权的不可变receipt必须与authorization payload精确匹配。若`VolumeRecord`仍存在，
   相同epoch必须精确等于receipt的直接postcondition；更大epoch必须是§3.1状态机产生的合法单调
   后继；receipt包含Disk postcondition时，Control Disk也必须仍为同一`Deleting(delete_id)`。所有
   后续转换都锁同一VolumeRecord且epoch只增不减，因此当前状态足以证明后继。若Volume/Disk记录已
   删除，必须存在同disk、同卷、同delete且`deleting_epoch >= resulting_epoch`的
   `DeleteCompletionReceipt`。缺失、epoch倒退或identity冲突全部保持Blocked。

同一事务接受`HostRejoinProof`并把event持久改为Rejoined后，provider才可恢复workload网络。
Rejoined event不能再派生授权；Unconsumed授权因首次消费必须检查Active event而永久不能生效；
Consumed授权仍可幂等读取receipt。相关authorization与`DeleteCompletionReceipt`至少保留到event
Rejoined，之后才可按审计策略GC。旧epoch的`R < L`目录保留作人工恢复证据，永不参与新Root。

`host_destroyed`不等待永远不会发生的Rejoined。没有Runtime tombstone、其他HostFenceEvent或live
recovery引用相关逐卷记录，所有Unconsumed authorization都已过`not_after`、所有Consumed authorization
的receipt及最终volume disposition都已验证后，相关逐卷authorization/receipt/
`DeleteCompletionReceipt`可在一个事务中按审计策略GC；任一引用、仍可首次消费的authorization或未闭合
disposition都拒绝且零副作用。compact
HostFenceEvent/HostDestroyed receipt继续按现有Operation/审计引用保留，只有全部引用消失后才可GC。

## 5. blockd 采用 grant，不改变 ownership

Node 是 lease transition 的执行者。顺序固定：

1. 在 checkpoint 写 acquire/takeover request。
2. 调用 MetadataStore，并对模糊结果读取精确 transition postcondition。
3. 把 `LeaseGrant` 原子写回 checkpoint。
4. 创建 attachment 专属 data-dir identity。
5. 启动 blockd，传入 volume、attachment、epoch 和 transition ID。
6. blockd 从 MetadataStore 验证精确 owner/epoch后开始 renew和服务。

blockd 启动不得调用 acquire、takeover或增加 epoch。它只可以 renew、以精确 owner/epoch发布 Root，
以及报告 status。Cold detach 时 Node 先 drain、停止 blockd，再执行 release。

## 6. 本地 attachment lineage

每个 data directory 属于一次 attachment，而不是只按 Disk ID 复用：

```text
VolumeLocalIdentity {
  volume_id,
  attachment_id,
  attachment_epoch,
  acquire_transition_id,
  node_id,
  placement_epoch
}
```

identity 在创建任何 cache/pack 前完成 file fsync、rename 和 parent directory fsync。每个 pending
pack 重复记录 `volume_id + attachment_id + attachment_epoch + acquire_transition_id`。

恢复规则：

- 完全相同 lineage：按 generation 顺序 replay；
- MetadataStore 仍是相同 owner/epoch：可以继续 publish；
- epoch 已失效或 identity 不匹配：整个目录 quarantine，不读取其中数据构造新 Root；
- pack 缺口、损坏或 identity 缺失：quarantine；
- `R == L` 且 release 已完成的旧目录可按精确 ownership token删除。
- disposable Root 的唯一例外：§11 的 Owned -> Deleting CAS 已成功后，才能删除授权中精确
  attachment lineage 的 `R < L` tail；该例外不能用于其他目录或其他卷。

clean-slate cutover 不解析缺少这些字段的旧 pack。

## 7. Cold-only 磁盘成员关系

第一版终态不支持 hot attach、hot detach、resize 或 Running DiskSnapshot。volume 容量在创建时确定，
之后不可变；Control Plane、MetadataStore 和 blockd 都不提供 resize API。

- PersistentDisk 加入或离开 Cat 的磁盘集合，只能在 Cat 已稳定 Cold 时提交。
- Cold -> Running 使用完整、排序且无重复的 VolumeIntent 集合一次启动。
- Running 中请求改变磁盘集合返回前置条件错误；调用方先将 Cat 变为 Cold。
- RootDisk 始终随 Cat；PersistentDisk 可在不同 Cat 的 Cold 状态之间移动。

这条限制消除了 Guest 重新 mount、打开文件句柄、VMM hotplug 和 blockd drain 之间的竞态。未来若
确有产品需要，hotplug 必须单独设计并验证，不能放宽本合同的 Cold 前置条件。

## 8. ext4 初始化与 mount readiness

PersistentDisk 创建时，Control Store 一次写入：

```text
Uninitialized {
  initialization_token,
  filesystem_uuid,
  expected_blank_generation,
  expected_blank_root
}
```

首次 Cold -> Running 在 route admission 打开前执行：

1. 取得精确 LeaseGrant，确认 MetadataStore head仍等于 blank predecessor。
2. checkpoint 写 `FormatStarted(token, attachment, epoch, blank_head)` 并 fsync。
3. Guest Agent按稳定virtio device identity probe。看到期望UUID就采用；确认全盘blank且没有部分
   格式痕迹时，按同一token执行`mkfs.ext4 -U <filesystem_uuid>`；其他UUID或部分格式直接
   quarantine。
4. RPC模糊或Agent crash后重新probe。期望UUID继续采用；仍严格blank可用同一token重试；任何
   其他结果quarantine。`Initialized`之后永不进入mkfs路径。
5. 磁盘尚未 mount，没有业务写入。Guest Agent执行设备 flush，Node要求 blockd drain到
   `R == L`，并记录新的 remote generation/Root。
6. Control Store 以 token、blank predecessor、期望 UUID和新 remote head做 CAS，转为
   `Initialized`。相同 token/UUID 重试幂等。
7. Guest Agent mount并回报 device identity、UUID、mount path、read/write状态。只有全部匹配后
   Running 才 Ready并打开 route admission。

初始化阶段即使是 Relaxed volume也必须先达到 `R == L`。否则 Host 丢失后 Control Store 会记得
UUID，而远端盘仍是空白。

## 9. 容量不可变

`size_bytes` 是创建卷时写入的不可变属性，并包含在每个 Root 和`DiskSnapshotRecord`中。所有读取都必须
校验三者一致；不一致时 fail closed。

第一版删除现有 resize API，不实现 offline/online resize、maintenance attachment、Map 扩边或
Guest 文件系统扩容。需要其他容量时创建新 Disk 并由 Guest 在两个稳定挂载之间复制数据。这是
明确的产品边界，不是暂时保留一条无条件 metadata update 路径。

## 10. DiskSnapshot、GC 与同盘恢复

这里的DiskSnapshot不是WarmRuntimeSnapshot。唯一的`DiskSnapshotRecord`既是产品资源，也是远端
Root的GC live-root；`ApiIdempotencyResult`只保存API返回结果，不参与产品查询、restore或GC。

Workspace ownership仍由`DiskRecord`权威持有；产品查询以record的`disk_id`连接Disk并按Workspace
过滤，GC按`volume_id`读取同一row。Disk存在live record时不能删除，因此不需要在第二张表复制归属。

create、delete和restore都要求非空`Idempotency-Key`。API先验证调用者身份、当前Workspace membership
和route permission，但不以目标Disk或Snapshot是否仍存在决定重放；随后取得§3的key reservation。
已有相同fingerprint的result时只返回其不可变outcome，绝不再读或修改Snapshot/Volume；不同
fingerprint立即冲突。只有尚无result的首次请求才继续按`VolumeRecord -> DiskRecord(owner Workspace)/
Cat/Desired -> DiskSnapshotRecord`锁序重验认证Workspace拥有Disk、Disk/volume绑定及各操作前置，并在
同一commit写业务变化与最终result。跨Workspace miss回滚reservation且不写Operation、result或资源。

### 10.1 创建

仅在产品Disk row为Active、Disk Cold且 volume unowned时允许：

```text
create_snapshot {
  disk_id,
  expected_unowned_epoch,
  expected_size,
  expected_generation,
  expected_root
}
```

首次事务重验产品Disk仍为Active、属于认证Workspace、所属Cat处于精确stable Cold，且
`DiskRecord.volume_id`与Active + Unowned的`VolumeRecord`一致；epoch、size、generation和Root必须与
请求完全相同。服务端随后分配一个全局唯一且永不复用的`snapshot_id`，插入包含精确disk/volume、
size、generation、Root和`created_at`的`DiskSnapshotRecord`，并原子写入包含
完整Snapshot返回值的成功result。客户端不能提供或复用`snapshot_id`。

normal acquire与Disk begin-delete也先锁同一`VolumeRecord`，因此它们与create只能按提交顺序发生，
响应丢失后只可能同时存在result与exact record，或二者都不存在。只有取得一个尚无result的key
reservation的首次事务可以把record不存在解释为尚未创建；任意重放不得从record缺席推断可以重建。

没有 writer，因此record命名的Root与新publish之间不存在空窗。

### 10.2 GC

卷GC的live roots是current Root与该volume的全部`DiskSnapshotRecord`。对每个root遍历Root、Leaf、
Base和全部Delta；任一snapshot record命名的Root无法读取或校验时，本轮GC失败且不删除对象。

Golden Image 继续是不可变、不可自动删除的系统工件。第一版不实现 image GC。

### 10.3 Restore

第一版只支持恢复到原 Disk：

1. Disk 必须属于认证Workspace并且Cold、unowned、Active。
2. 在通用key reservation后按统一锁序验证`DiskSnapshotRecord`；record的disk/volume必须精确指向
   当前Disk，且record、VolumeRecord和Root中的`size_bytes`必须完全相同。
3. 首次`restore_same_disk(snapshot_id, expected head, expected unowned epoch)`把当前head指向snapshot
   Root、generation和epoch各增加1，并在同一事务写含新head/generation/epoch的成功result。
4. 相同key重放只读result，因此至多前进一次；晚到acquire因expected epoch失效而失败。

restore 不倒退 generation；它发布一个引用旧不可变数据的新 generation。第一版不支持 clone，
不建立跨 volume COW引用。

### 10.4 删除 Snapshot

Snapshot删除是独立操作，不由Disk删除隐式级联：

```text
delete_snapshot {
  snapshot_id,
  disk_id,
  expected_generation,
  expected_root
}
```

首次事务按统一锁序重验认证Workspace拥有Disk，并验证Disk、Volume与`DiskSnapshotRecord`的
disk/volume/generation/Root tuple完全一致。成功时删除这一行，并原子写包含`snapshot_id`和删除结果的
通用成功result；相同key重放只读result。record缺失且没有既有result是新的`NotFound`结果，不能猜测
某次旧删除或创建是否成功。

`create_snapshot`、`delete_snapshot`和Disk `begin_delete`都锁同一`VolumeRecord`，因此创建record、
删除record与关闭volume authority只能按一个确定顺序发生。删除record后，若该Root仍是current Root，它仍由
current Root进入GC live set。

## 11. Delete

删除使用一条当前状态和两种窄入口；每个入口都用一次PostgreSQL事务同时关闭Control Disk与
Volume authority。

两种入口都必须在锁定`VolumeRecord`后检查不存在该Disk的live `DiskSnapshotRecord`。任一存在即
返回`SnapshotInUse`，不改变Disk或Volume状态，也不删除对象。调用方必须先按§10.4显式删除Snapshot；
Disk删除不做隐式cascade。

### 11.1 已安全释放的卷

PersistentDisk、需要保留数据的 RootDisk，以及已经正常 drain 的卷必须先满足：没有新的 Desired
引用、没有live `DiskSnapshotRecord`、Cat稳定 Cold、`R == L`、blockd停止、精确 release完成且 owner为空。

`begin_delete(delete_id, disk_id, volume_id, expected_generation, expected_head,
expected_unowned_epoch)`按`VolumeRecord -> Control Disk/Cat/Desired rows -> DiskSnapshotRecord rows`锁序，
在同一事务重验全部前置、Control Disk仍为Active、VolumeRecord精确为Active + Unowned，然后原子执行：

- `Control Disk Active -> Deleting(delete_id)`；
- `VolumeRecord Active + Unowned -> Deleting(delete_id, epoch + 1)`并记录同一delete transition。

相同delete ID的模糊响应只有在两边都处于精确postcondition，或两边均已删除且存在匹配
`DeleteCompletionReceipt`时才返回原结果；单边状态或字段不一致返回`BackendUnknown`。normal acquire
也先锁VolumeRecord：acquire先提交则begin-delete的Unowned检查失败；begin-delete先提交则acquire的
Active检查失败，不存在重新取得owner的中间窗口。

### 11.2 放弃本地 tail 的 disposable Root

这是 `R == L` 与 normal release 规则的唯一例外：

```text
DisposableRootDeleteAuthorization {
  authorization_id,          // 同时作为 transition_id
  delete_id,
  volume_id, cat_id,
  desired_revision, placement_epoch,
  expected_attachment_id, expected_epoch,
  expected_generation, expected_root,
  isolation_basis:
      RuntimeStopped {node_id, agent_session_epoch, runtime_incarnation, observation_id}
    | HostFenceEvent {event_id},
  not_after,
  issuer_proof
}
```

Control Plane 只为当前 `Deleted` Desired 中明确标为 disposable 的 RootDisk建立授权。可达 Host 必须
先关闭admission、停止Guest/VMM和blockd，并提交精确stop observation；失联Host必须已有Active
HostFenceEvent。授权绑定当前revision/placement、delete ID、remote head和最后owner/epoch，不能
跨Cat、卷、attachment或重试身份复用。

HostFenceEvent来源的首次消费使用固定锁序
`HostFenceEvent -> AuthorizationRecord -> VolumeRecord -> Control Disk/Desired/DiskSnapshotRecord rows`；
RuntimeStopped来源使用相同后缀而没有event行。一个PostgreSQL事务重验event或stop observation、
authorization完整tuple、Control Disk仍为Active、当前Deleted Desired仍把该Root标为disposable，
并确认没有live `DiskSnapshotRecord`，然后原子执行：

- `VolumeRecord Active + Owned(expected owner/epoch) -> Deleting(delete_id, owner cleared, epoch + 1)`；
- `Control Disk Active -> Deleting(delete_id)`；
- authorization `Unconsumed -> Consumed(AuthorizationConsumedReceipt)`，receipt记录两边postcondition。

相同授权重试只读取receipt；snapshot record仍存活时返回`SnapshotInUse`且三边都不改变，其他字段变化、
过期或非Root/disposable请求返回`InvalidAuthorization`。事务成功前不得删除pending data；成功后旧
epoch永久不能publish，Node才可删除授权所指lineage的`R < L` tail。这里不经过会产生可抢占窗口的
`Active + Unowned`，也不能扩展到PersistentDisk。

HostFenceEvent路径上的本地lineage在旧Host rejoin时进入quarantine；删除授权记录至少保留到该
event转为Rejoined，使rejoin仍能核对所有派生结果。

### 11.3 共同清理

1. 只有§11.1或§11.2事务已经证明Control Disk与VolumeRecord都为同一`Deleting(delete_id)`后才进入
   sweep；此后不能进入新DesiredRuntimeSpec或normal acquire。
2. Node完整inventory证明所有可达本地资源已按授权处理；失联Host residue由Active event跟踪。
3. sweeper断言`DiskSnapshotRecord`仍为空，再幂等删除`volumes/<volume-id>/`下的data/maps/commits；
   它不负责删除Snapshot。
4. 对象前缀确认为空后，一个PostgreSQL事务再次比较两边delete ID，写入精确
   `DeleteCompletionReceipt`并同时删除VolumeRecord与Control Disk row。

不存在根据控制面一列状态、lease TTL或目录缺失直接删除volume的路径。删除完成后无需保留兼容
tombstone；但只要某个Active HostFenceEvent的Consumed authorization引用该卷，精确
`DeleteCompletionReceipt`、event和authorization都必须保留到Rejoined，供合法后继校验。

## 12. 两 revision Cold 迁移

计划迁移不使用 takeover：

1. revision N+1仍由源 Node负责，目标为 Cold。源关闭 admission、drain guards和Guest，所有
   保留卷到 `R == L`，停止 blockd并逐卷 release，最后发布精确 Cold observation。
2. 只有 N+1 Operation成功后，Control Plane选择目标 Node，在事务中写 revision N+2、提高
   placement epoch，目标为 Running并携带完整磁盘集合。
3. 目标对每卷执行 normal acquire；因为源已 release，volume必须是 Unowned。
4. 旧 revision、placement、attachment和route grant全部失败。

源未证明 Cold/release时不创建 N+2。开发期不提供一个跨两 revision的 Node workflow；API可以
显式返回两个精确 Operation，fleet drain也按相同当前状态规则推进。

非计划 Host loss不走这条路径，只能走 HostFenceEvent + per-volume takeover。

## 13. 模块依赖和实施顺序

1. 先建立旧实现必失败的 characterization tests：普通抢占、重复 acquire、silent release、旧 pack
   新 epoch replay、expired-owner delete、snapshot create/delete/GC和初始化 crash点。
2. 一次替换 MetadataStore schema、trait和 PostgreSQL/SQLite adapter contract；HostFenceEvent、
   `AuthorizationConsumedReceipt`、VolumeRecord与Rejoined使用同一事务域和固定锁序。
3. 一次替换 pack header、data-dir identity、blockd启动参数和status；删除旧 pack parser。
4. 接入 RuntimeCheckpoint、VolumeIntent/Observation和Node lease executor。
5. 接入 Guest Agent probe/format/mount和Cold-only API前置条件。
6. 实现通用`ApiIdempotencyResult`与单一`DiskSnapshotRecord`的原子create/delete、snapshot-aware GC、
   same-disk restore、Control/Volume原子begin-delete和后置fail-closed sweeper。
7. 接入 HostFenceEvent/takeover与两 revision Cold migration。
8. 同一发布删除旧 acquire/revoke、hot disk mutation、resize API和无条件 delete路径。

## 14. 最小验收矩阵

| 场景 | Oracle |
|---|---|
| normal acquire响应丢失 | 相同transition返回同epoch，不产生第二次fence |
| expired other owner | normal acquire始终OtherWriter；owner可继续renew |
| release响应丢失 | 相同transition幂等；旧epoch永久不能publish |
| stale acquire晚到release之后 | expected epoch不匹配，不能重新占有volume |
| Host takeover | 只有精确逐卷授权成功；跨volume/placement/replay失败 |
| 首次consume与Host rejoin并发 | 两者锁同一event；consume先提交则rejoin观察receipt，Rejoined先提交则consume失败且epoch不变 |
| Host rejoin遇到未消费授权 | 未过`not_after`时保持Active/Blocked；过期后才可Rejoined，且不能首次消费 |
| consumed授权的后继 | takeover→release→rejoin成功；delete→sweep以DeleteCompletionReceipt→rejoin成功；缺失/错receipt保持Blocked |
| 旧pending目录遇到新attachment | quarantine，remote Root不改变 |
| 相同lineage blockd crash | 从pack恢复L并按序publish |
| resize请求 | API不存在；`size_bytes` 在Volume/Root/Snapshot中始终一致 |
| normal acquire与begin-delete并发 | 两者锁同一VolumeRecord且只能一方提交；不存在Control Deleting但Volume仍可acquire的窗口 |
| delete各步骤crash | begin-delete两边原子进入Deleting；sweep后置幂等；重试同delete ID并最终同时移除两边metadata |
| disposable Root `R < L` | 固定event/auth/volume/control锁序；receipt与两边Deleting原子提交后才删lineage；PersistentDisk拒绝 |
| mkfs各步骤crash | 只adopt期望UUID或quarantine；Initialized前R==L |
| Running磁盘变更 | API拒绝，先Cold；不存在hotplug竞态 |
| Snapshot与GC并发 | record命名的对象始终存活；坏record使GC fail closed |
| Snapshot create crash/响应丢失 | 同一commit同时产生exact record和不可变result，或二者都不存在；重放只读result |
| create→delete→旧create重放 | create成功result跨Snapshot删除保留；返回原snapshot ID且不重新插row，该ID永不复用 |
| Snapshot delete crash/响应丢失 | 同一commit同时删除record并写result，或二者都不发生；相同key只读原删除结果 |
| Snapshot API同key异payload | key reservation先串行；返回`IdempotencyConflict`，不取得资源锁、不改变任何资源 |
| Snapshot跨Workspace访问/重放 | 返回不泄露存在性的NotFound/Forbidden；不写Operation/result，不改变Volume、Disk或Snapshot |
| Snapshot与Disk delete并发 | create与begin-delete锁同一VolumeRecord；live record返回SnapshotInUse；显式snapshot delete删除一行 |
| same-disk restore/重放 | 首次事务原子写新head与result；generation/epoch只前进一次，容量不变，字节等于snapshot |
| 两revision迁移 | 源Cold/release前目标无writer；目标只normal acquire |
| Host loss `R < L` | 从R恢复并报告DataLossPossible；backlog只是最后样本 |

以上矩阵必须同时覆盖 PostgreSQL 和 SQLite contract；数据路径矩阵同时覆盖 kernel-NBD 与
vhost-user-blk。模糊结果测试必须先证明故障实际注入，不能用空日志作为通过证据。
