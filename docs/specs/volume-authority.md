# Volume Authority 与磁盘生命周期

- 状态：Implemented/Frozen internal Volume authority；command-scoped run-grant/Cold/destroy data semantics、
  receipt ledger、Cold-only attach/detach与Persistent initialization vertical已实现；current release gate见
  [Atomic Runtime Lifecycle v1 §11](atomic-runtime-lifecycle-v1.md#11-acceptance-matrix)，production
  DiskSnapshot/GC与external Host-fence资格验证仍显式开放
- 决策：[ADR-0042](../decisions/0042-volume-authority-and-disk-lifecycle.md)
- Product action/projection：
  [ADR-0057](../decisions/0057-product-lifecycle-actions-and-internal-execution-evidence.md)
- 协调协议：[Atomic Runtime Lifecycle v1](atomic-runtime-lifecycle-v1.md)
- 保留的共享identity/inventory：[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
- 数据协议：[cats-blockd 协议](blockd-protocol.md)

本文定义卷从创建、附着、格式化、快照、迁移到删除的完整合同。目标是让每个危险动作都由
一个窄的条件状态转换保护，而不是依靠 TTL、控制面缓存或“调用看起来成功”。

本规格只声明存储前置条件：删除现有 Cat、Disk、Snapshot、volume metadata、对象和 Node 本地
目录后启用本合同；实现不读取旧 pending pack，不转换旧 attachment，也不长期保留两套接口。
完整、有序的操作以[Operations and HA §8](../operations-ha.md#8-首次终态部署)为唯一runbook。

## 0. Atomic lifecycle composition

[ADR-0056](../decisions/0056-atomic-per-cat-runtime-lifecycle.md)只替换谁发起/闭合runtime storage
transitions，不替换本规格的MetadataStore state machine、owner/epoch CAS、RWO、L/R、authorization
或receipt；ADR-0057只替换产品动作与投影。下表的`Start*`/`Delete*`若作为Rust type出现，指current
Node-Control internal codec，不是product action；其内部命名仍受Atomic Runtime Lifecycle §11.0门约束。
atomic release的直接组合只有下列authority：

| 事实 | 唯一input/receipt |
|---|---|
| disk/placement intent | exact lifecycle Operation中的immutable `RuntimeVolumeConfig`、`StartVolumeAuthority`与placement |
| Cold volume terminal | `ColdResult.volume_dispositions` 的`NormallyReleased | AlreadyUnowned` closed union |
| normal cross-Node run | source `ColdResult` + 逐卷同variant的disposition receipt digest |
| destroy disposition | internal teardown spec、same action `ExecutionStopped` evidence与closed Root/Persistent receipts |
| product attach/detach | exact terminal Cold head与append-only immutable runtime config mutation；不创建lifecycle Operation |

所有acquire/renew/release/takeover/delete mutation必须绑定current unresolved lifecycle Operation、canonical
request/fingerprint、typed predecessor与Node current authenticated session；terminal storage receipts进入exact
NodeResult。inventory/telemetry不结算Operation，也不重建`R == L`、release、stop或delete完成。

Persistent initialization仍由create/run的内部EnsureRunning执行完成，但signed mutation绑定exact
execution Operation/request、Guest UUID/device-flush evidence与current Volume/Disk/config；它不等待或消费
Observation。cold/destroy/Snapshot等产品
transaction消费PostgreSQL已存的exact terminal lifecycle result与Volume receipts，而不是Node物理事实的Control
重演。

`RuntimeVolumeConfig`只保存immutable product配置；acquire/adopt/takeover输入只来自同一StartSpec中与config
volume有序1:1的`StartVolumeAuthority`，并被request fingerprint绑定。Genesis/Cold使用normal-unowned，
Suspended/Warm same-Node使用same-node-owned；run failure后的exact retry按原run result中嵌入的retained
receipt逐卷使用same-node-owned，没有retained receipt的卷必须使用normal-unowned；HostFenceRecovery使用takeover；不能从
config或current Volume状态猜测variant。Root config只允许`root_boot`且不携带filesystem UUID/mount path；Persistent只允许
`persistent_ext4 {filesystem_uuid,mount_path}`，role不匹配fail closed。

### 0.1 Atomic command receipt digests

Atomic lifecycle Volume transport只引用经下列closed shape验证并存入immutable ledger的
command-scoped receipt/digest。Owned slot使用attachment-bearing target；已Unowned slot只使用
identity，不伪造attachment：

```text
LifecycleVolumeCommandScope {
  operation_id: Id,
  request_fingerprint: Sha256Digest,
  cat_id: Id,
  node_id: Id,
  placement_identity: { node_id: Id, placement_epoch: Epoch }
}

LifecycleVolumeTarget {
  disk_id: Id,
  disk_role: "root" | "persistent",
  volume_id: Id,
  attachment_id: Id,
  attachment_epoch: FenceEpoch
}

LifecycleVolumeIdentity {
  disk_id: Id,
  disk_role: "root" | "persistent",
  volume_id: Id
}

CommandVolumeDurabilityProof {
  scope: LifecycleVolumeCommandScope,
  volume: LifecycleVolumeTarget,
  remote_head: RemoteHead,
  local_durable_generation: Generation,
  remote_durable_generation: Generation,
  pending_pack_count: 0
}

CommandNormalReleaseReceipt {
  durability: CommandVolumeDurabilityProof,
  request: ReleaseRequest,
  result: ReleaseResult
}

AlreadyUnownedProvenance =
  { kind: "pristine" }
| { kind: "normal_release",
    receipt: CommandNormalReleaseReceipt,
    receipt_digest: Sha256Digest }

CommandAlreadyUnownedReceipt {
  scope: LifecycleVolumeCommandScope,
  volume: LifecycleVolumeIdentity,
  expected_epoch: FenceEpoch,
  expected_head: RemoteHead,
  provenance: AlreadyUnownedProvenance
}

ColdCommandVolumeSet {
  scope: LifecycleVolumeCommandScope,
  volumes: [LifecycleVolumeIdentity]
}

DefaultRootDiscardDisposition {
  root: LifecycleVolumeIdentity,
  delete_id: Id
}

DeleteCommandVolumeSet {
  scope: LifecycleVolumeCommandScope,
  root_disposition: DefaultRootDiscardDisposition,
  persistent_volumes: [LifecycleVolumeIdentity]
}

CommandDisposableAuthorizationConsumedReceipt {
  command: DeleteCommandVolumeSet,
  authorization_id: Id,
  persistent_dispositions_digest: Sha256Digest,
  receipt: BeginDisposableDeleteConsumedReceipt
}

CommandRootDeleteAuthorityReceipt =
  { kind: "normal_release", receipt: CommandNormalReleaseReceipt }
| { kind: "already_unowned", receipt: CommandAlreadyUnownedReceipt }
| { kind: "disposable_authorization_consumed",
    receipt: CommandDisposableAuthorizationConsumedReceipt }

CommandDeleteCompletionReceipt {
  command: DeleteCommandVolumeSet,
  root_authority: CommandRootDeleteAuthorityReceipt,
  completion: DeleteCompletionReceipt
}
```

共同算法是`SHA-256(ASCII(domain) || 0x00 || CJ(input))`并编码为
`sha256:<64 lowercase hex>`。下列input都是验证后的完整typed value，不删字段，也不对
调用方传来的opaque JSON直接hash：

| lifecycle引用 | domain separator | canonical input与hash前验证 |
|---|---|---|
| Start grant | `cats.volume-authority.command-start-volume-grant-receipt.v1` | 完整`LifecycleCommandStartVolumeGrantReceipt`；绑定Operation、grant sequence、runtime volume config、acquire/renew request/result与current owner lineage |
| `command_normal_release_receipt_digest` | `cats.volume-authority.command-normal-release-receipt.v1` | 完整`CommandNormalReleaseReceipt`（含durability proof）；先与current released Volume及`last_transition.release`逐字段闭合 |
| Cold already-Unowned | `cats.volume-authority.command-cold-already-unowned-receipt.v1` | 完整`CommandAlreadyUnownedReceipt`；绑定current Unowned epoch/head和`pristine | prior normal-release`来源 |
| Delete already-Unowned | `cats.volume-authority.command-delete-already-unowned-receipt.v1` | 同一closed receipt shape，但使用与Cold分离的domain，不得跨命令重放 |
| Persistent disposition set | `cats.volume-authority.persistent-delete-dispositions.v1` | 完整排序Persistent set中`normally_released | already_unowned`的role/disposition/digest投影 |
| `command_disposable_authorization_consumed_receipt_digest` | `cats.volume-authority.command-disposable-authorization-consumed-receipt.v1` | 完整`CommandDisposableAuthorizationConsumedReceipt`；先闭合exact Delete command、Consumed parent `AuthorizationRecord`和current Deleting Volume |
| `command_delete_completion_receipt_digest` | `cats.volume-authority.command-delete-completion-receipt.v1` | 完整`CommandDeleteCompletionReceipt`；要求current Volume absent并验证normal-release/already-Unowned/disposable prior Root authority的exact chain |

当前storage integration fixed vectors（每个值只属于其对应typed fixture）为：

| fixture | digest |
|---|---|
| Start initial grant | `sha256:8d13843f444482836c0c4c2e4f6bffb3b18b563384df14172ce753ff5e1d3114` |
| normal release | `sha256:71681866927a00a0737b504e1ca4a03d1d8f366d6ccd5c0904da42fc79529d30` |
| Cold already-Unowned | `sha256:a8c0ba6d0fc4740451eba234798e8966f62e3ea1c370ae37791a74ef43c4a734` |
| Delete already-Unowned | `sha256:967b922e19b27ebf611a3bdb7c40df0e569fc8afda453a8e7499ce88bd077a3e` |
| one-owned-Persistent disposition set | `sha256:4d9a7c1251a9dda993b9a8351d47e2e91bd87b46e5c5d48383acc2f02534daff` |
| mixed pristine/owned Persistent disposition set | `sha256:daab4746a11e6b878354c179f6d181c888ee41c9b6fdfbf92c92ce9a10ed29ac` |
| disposable authorization consumed | `sha256:7623e53b48a61f0751cdd9d5ad302646862f516ee4cb4a6e86f6975d2e7b9229` |
| normal-Root delete completion | `sha256:32c759b4e3d3900061fad4d3dc1007c20c8d3adfaa912b29d1922223ed60b3e1` |
| disposable-Root delete completion | `sha256:64f0b1aafd4b445d1879edc05e6de4a9f57b422f27e875f4177a8bf3cf8fb118` |

实现测试必须从完整typed fixture重新CJ/hash，不得只比较硬编码digest。

normal Root completion必须持久保存完整prior normal-release request/result；旧`DeleteCompletionReceipt.normal`
没有这些字段，Volume row删除后不能据它重算authority receipt digest。digest helper只能在上述current-state/
parent-chain验证成功后hash，不能对调用者提供的任意JSON签名。array沿用本规格的role与stable-ID顺序；scope中
`node_id == placement_identity.node_id`，并与exact lifecycle Operation/request逐字段相同。

normal release receipt中的durability proof是在Guest-facing I/O关闭后采样的exact final blockd事实；
receipt不重复scope/volume，它们只由proof携带并与request/result逐字段闭合。`pending_pack_count == 0`、
`local_durable_generation == remote_durable_generation == remote_head.generation`，`remote_head`逐字段等于
`ReleaseResult.resulting_head`及current released Volume head。`ReleaseRequest/ReleaseResult`本身不含L/R，
因此proof必须随receipt持久化并进入digest；Control从该同一proof投影Node result的L/R，禁止把一个合法
authority digest与调用方另报的任意generation拼接。

所有command-scoped receipt必须进入同一PostgreSQL authority域的immutable
`lifecycle_volume_receipts` ledger。物理唯一键是
`(operation_id, volume_id, receipt_kind, receipt_sequence)`，并以FK绑定exact Operation/fingerprint/config/
placement；normal release在Owned→Unowned与
`last_transition.release`同一事务写完整receipt/digest，disposable receipt在authorization consume与
Owned→Deleting同一事务写，delete completion在prefix-empty验证、completion写入及Volume/Disk row删除的同一
事务写。相同key只能逐byte重放原canonical receipt/digest；不同payload是stored corruption，不能覆盖或追加
“更完整”版本。

Control lifecycle settlement只从该ledger strict decode完整receipt，重验command scope、parent chain/current
authority postcondition并重算domain digest，再与NodeResult引用比较。NodeResult不能携带一份替代ledger payload，
Control也绝不从Node报告的L/R、legacy`last_transition`或`DeleteCompletionReceipt`补造command receipt。后两者
仍是Volume state transition marker，但单独不足以承载final`R == L`proof；被terminal result/predecessor/
authorization引用的ledger row不得提前GC。

atomic lifecycle command涉及现有Cat时固定锁序为`current credential lineage/NodeIdentity -> AgentSession ->
CatRecord -> exact current LifecycleOperation -> sorted VolumeRecord -> sorted DiskRecord -> immutable
lifecycle-volume receipt ledger`；非signed内部事务跳过认证前缀。事务可以先无锁读取Operation scope来定位Cat，
但该读取不授予任何权限；锁Cat后必须重新锁定并逐字段验证exact current unresolved Operation。settlement、
Route和command-scoped Volume transition都不得先锁Operation或Volume再反向取得Cat，也不得持Cat锁反向认证session。

## 1. 权威和不变量

每类事实只有一个权威：

| 事实 | 权威 |
|---|---|
| Disk 是否存在、属于哪个 Workspace、是否可加入 Cat | Control Store |
| Cat的完整磁盘集合与immutable runtime配置 | Control Store `CatRuntimeConfig` |
| Endpoint产品identity、所属Cat与管理名 | `EndpointRecord` |
| Endpoint当前hostname/protocol/port/route epoch binding | current `EndpointBinding` |
| hostname到current Endpoint的定位 | `HostnameEndpointLookup`投影；不是binding authority |
| 当前 volume owner、fencing epoch、remote Root | MetadataStore |
| DiskSnapshot产品资源与GC live-root | DiskSnapshotRecord |
| 本规格覆盖的Workspace product mutation请求身份与不可变返回结果 | PostgreSQL `ApiIdempotencyResult` |
| 本地 pending pack、cache、blockd 进程是否存在 | Node 物理 inventory |
| ext4 UUID 和当前 mount 是否真实存在 | Guest Agent probe |
| Host 是否已被外部隔离、逐卷授权是否已消费 | PostgreSQL HostFenceEvent/Authorization rows |

Control Store 与 MetadataStore 是逻辑边界，不是两套提交authority。生产终态把`HostFenceEvent`、
由它派生的authorization、不可变消费回执和`VolumeRecord`放在同一PostgreSQL事务域；SQLite只作
pure-domain/data-row fixture，不提供Control cross-row authority。首次消费授权
通过唯一PG事务域的固定锁序完成。

全局锁DAG是`ApiIdempotencyResult key reservation -> CatNameLock -> DiskNameLock -> NodeIdentity（写old/new assigned
placement/config或消费current Node command时）-> current credential lineage（signed Node command适用时）
-> AgentSession -> lifecycle Operation/current Cat chain head（适用时）
-> HostFenceEvent -> AuthorizationRecord -> VolumeRecord -> Control Cat/Disk/config/Endpoint rows ->
DiskSnapshotRecord`；事务跳过自己不涉及的节点，同类
多行按稳定ID排序。§3.3覆盖的Workspace product mutation先取得由认证Workspace、canonical route和`Idempotency-Key`导出的
PostgreSQL transaction-scoped reservation，再读结果；它不能先锁资源，也不落持久Pending。这样同一
key即使携带不同资源也不会分别先锁不同Volume。normal acquire只锁`VolumeRecord`，因此它与snapshot
mutation或begin-delete仍只能有一方先提交。production Runtime HTTP owner不能直接暴露该primitive；它必须先按
[Atomic Runtime Lifecycle v1](atomic-runtime-lifecycle-v1.md)取得NodeIdentity、exact active credential lineage、
current AgentSession和exact lifecycle command锁前缀，然后才进入本文的event/authorization/Volume后缀。HostFenceEvent来源的内部恢复没有API前缀；
改变event eligibility或创建placement时从NodeIdentity开始，只消费已有authorization且不再读Node时从event开始。
`CatNameLock`和`DiskNameLock`都不是row或authority。只有会插入新Cat identity的create事务使用前者；
Root Disk与PersistentDisk共享同一Workspace内的产品名称空间，因此两种create都在API key之后、任何Node/
Volume/candidate identity锁之前取得后者。Cat create固定在API key之后
取得它并先闭合名称分支：合法existing Cat按既有Volume→Cat→Disk→config→Endpoint/lookup→Operation锁序
闭合existing graph后只写exact 409 result，不读取或锁定candidate plan/NodeIdentity；name free且将插入新Cat/config时，
才在任何candidate Volume/Cat/Disk row或candidate-ID lock之前锁定并重验candidate `NodeIdentity`。删除已有Cat由
被锁定的existing Cat row与唯一索引
线性化，不取得name lock，因此§1的Cat Destroy锁序没有反向边。

Persistent initialization CAS没有API/event前缀，固定锁序是`current NodeIdentity -> current AgentSession row ->
current unresolved Start Operation/Cat chain head -> VolumeRecord -> DiskRecord -> current CatRuntimeConfig ->
immutable signed Guest/device-flush evidence`。session replacement和command settlement也必须先锁同一NodeIdentity，
再锁AgentSession/Operation，任何事务都不得先锁它们或Volume后反向取NodeIdentity；因此旧session检查与Initialized commit之间没有
ABA窗口。

covered Cat Destroy的Cold fast path使用`ApiIdempotencyResult key -> current NodeIdentity -> current AgentSession ->
exact terminal Cold Operation/result + immutable release receipts -> VolumeRecord -> Disk/Cat/current config ->
DiskSnapshotRecord`。它不保留前一command/evidence的新历史authority；所有判断与下述Root
normal begin都在持锁的current rows上完成。

必须始终满足：

1. 一个 RWO volume 同时最多一个 owner/epoch 可以发布 Root。
2. 所有 ownership 变化都增加 epoch；旧 epoch 永久失败。
3. lease TTL 只表示 owner 多久没有续约，不授予其他 attachment 抢占权。
4. `R <= L`。Strict FLUSH 在 `R` 前进后 ACK，Relaxed FLUSH 在 `L` 前进后 ACK。
5. `R < L` 的 pack 绑定一个精确 attachment lineage，不能被新 attachment 采用。
6. Warm、Cold、磁盘集合变更、DiskSnapshot、detach、计划迁移和Delete中的每个PersistentDisk必须
   `R == L`；唯一例外是current DeleteSpec明确放弃的default disposable Root，并且必须先消费 §11 的
   exact authorization。Cold对Root也无例外。
7. Volume admin 操作和普通 attach 不能并发越过彼此。
8. 每条`DiskSnapshotRecord`命名的Root必须进入GC live set；不存在第二份物化记录。
9. Snapshot API先验证调用者身份、当前Workspace membership和route permission，再reserve/read该
   Workspace的幂等key；精确命中直接返回result。只有miss才在事务内重验Workspace拥有Disk及精确
   disk/volume/snapshot tuple；跨Workspace miss返回不泄露存在性的`NotFound`/`Forbidden`并回滚
   reservation，不写Operation、result或资源行。

## 2. 核心身份

- `attachment_id`：一次逻辑 attachment 的全局唯一 ID；创建后永不复用。
- `attachment_epoch`：MetadataStore 中每卷单调递增的 fencing 数字。
- `transition_id: RandomId128`：只用于normal acquire和release；同一次重试必须复用，其他操作不得复用。
- `authorization_id: Id`：takeover或disposable delete授权row的稳定主键。
- `delete_id: Id`：一次Disk/Volume删除的稳定身份。
- `lifecycle_operation_id`、`placement_epoch`：来自 Atomic Runtime Lifecycle合同；authorization/request
  必须绑定exact command identity/fingerprint。
- `HostFenceEventId`：一次 Host 外部隔离事件的稳定 ID。

本文复用[Runtime Reconciliation §1.1](runtime-reconciliation-v1.md#11-v1-wire-基础类型)的`Id`、
`AsciiText`、`RandomId128`、`Revision`、`Epoch`、`FenceEpoch`、`Generation`、`UnixMillis`和
`Sha256Digest`、`Hostname`定义。normal transition、authorization和delete保留各自类型，不引入可混用的统一ID。
操作ID解决响应丢失，epoch解决ABA；两者不能互相代替。

## 3. PostgreSQL authority 模型

逻辑Control Store/MetadataStore记录如下；具体 SQL 可以拆表，但标明原子的条件必须在一个数据库
事务中完成：

```text
RemoteHead {
  generation: Generation,
  root_hash: Sha256Digest | null,
  root_object_id: AsciiText | null
}

VolumeRecord {
  volume_id: Id,
  size_bytes: integer 1..=9223372036854775807,
  durability: "strict" | "relaxed",
  admin_state: VolumeAdminState,
  head: RemoteHead,
  lease_owner: Id | null,
  lease_epoch: FenceEpoch,
  lease_expires_at: UnixMillis | null,
  last_transition: LastVolumeTransition | null
}

VolumeOwnerBinding {
  volume_id: Id,
  owner_node_id: Id,
  attachment_id: Id,
  attachment_epoch: FenceEpoch
}

VolumeAdminState =
  { kind: "active" }
| { kind: "deleting", delete_id: Id }

LastVolumeTransition =
  { kind: "normal_acquire", request: NormalAcquireRequest, result: NormalAcquireResult }
| { kind: "release", request: ReleaseRequest, result: ReleaseResult }
| { kind: "takeover", authorization_id: Id }
| { kind: "begin_delete", request: BeginDeleteRequest, result: BeginDeleteResult }
| { kind: "begin_disposable_delete", authorization_id: Id }

CatRecord {
  cat_id: Id,
  workspace_id: Id,
  name: Id,
  cat_creation_id: Id,
  lifecycle_head_operation_id: Id | null,
  stable_state: "running" | "suspended" | "warm" | "cold" | null,
  effective_runtime_ready_operation_id: Id | null,
  runtime_incarnation: RandomId128 | null,
  created_at: UnixMillis
}

CatRuntimeConfig {
  cat_id: Id,
  config: AtomicLifecycle.ImmutableRuntimeConfig
}

EndpointRecord {
  endpoint_id: Id,
  workspace_id: Id,
  cat_id: Id,
  name: Id,
  created_at: UnixMillis
}

EndpointBinding {
  endpoint_id: Id,
  hostname: Hostname,
  protocol: "http",
  target_port: integer 1..=65535,
  route_epoch: Epoch
}

HostnameEndpointLookup {
  hostname: Hostname,
  workspace_id: Id,
  cat_id: Id,
  endpoint_id: Id
}

CatCreateRequest {
  name: Id,
  boot_image_digest: Sha256Digest,
  vcpus: integer 1..=4294967295,
  memory_bytes: integer 1..=9223372036854775807,
  root_size_bytes: integer 1..=1099511627776,
  durability: "strict" | "relaxed"
}

CatCreateAcceptedResponse {
  cat_id: Id,
  operation_id: Id
}

CatNameAlreadyExistsResponse = ErrorBody {
  code: "already_exists",
  message: "cat name already exists",
  request_id: omitted
}

DiskRecord {
  disk_id: Id,
  workspace_id: Id,
  name: Id,
  volume_id: Id,
  size_bytes: integer 1..=9223372036854775807,
  durability: "strict" | "relaxed",
  created_at: UnixMillis,
  admin_state: DiskAdminState,
  role: DiskRole
}

DiskAdminState =
  { kind: "active" }
| { kind: "deleting", delete_id: Id }

DiskRole =
  { kind: "root", cat_id: Id }
| { kind: "persistent", initialization: PersistentDiskInitialization }

PersistentDiskInitialization =
  {
    kind: "uninitialized",
    initialization_token: RandomId128,
    filesystem_uuid: RandomId128,
    expected_blank_head: RemoteHead
  }
| {
    kind: "initialized",
    initialization_token: RandomId128,
    filesystem_uuid: RandomId128,
    expected_blank_head: RemoteHead,
    initialized_head: RemoteHead,
    initialized_at: UnixMillis
  }

DiskSnapshotRecord {
  snapshot_id: Id,
  disk_id: Id,
  volume_id: Id,
  size_bytes: integer 1..=9223372036854775807,
  head: RemoteHead,
  created_at: UnixMillis
}

ApiIdempotencyResult {
  authenticated_workspace_id: Id,
  canonical_route: AsciiText,
  idempotency_key: AsciiText,
  request_fingerprint: Sha256Digest,
  http_status: integer 200..=599,
  content_type: "application/json" | null,
  response_body: bytes 0..=1048576,
  created_at: UnixMillis
}

AuthorizationRecord {
  authorization: VolumeAuthorization,
  state: { kind: "unconsumed" }
       | { kind: "consumed", receipt: AuthorizationConsumedReceipt }
}

VolumeAuthorization = VolumeTakeoverAuthorization | DisposableRootDeleteAuthorization

AuthorizationConsumedReceipt = TakeoverConsumedReceipt | BeginDisposableDeleteConsumedReceipt

TakeoverConsumedReceipt {
  kind: "takeover",
  authorization_id: Id,
  host_fence_event_id: Id,
  volume_id: Id,
  new_attachment_id: Id,
  resulting_epoch: FenceEpoch,
  resulting_head: RemoteHead,
  consumed_at: UnixMillis
}

BeginDisposableDeleteConsumedReceipt {
  kind: "begin_disposable_delete",
  authorization_id: Id,
  volume_id: Id,
  disk_id: Id,
  cat_id: Id,
  delete_id: Id,
  prior_attachment_id: Id,
  resulting_epoch: FenceEpoch,
  resulting_head: RemoteHead,
  consumed_at: UnixMillis
}

DeleteCompletionReceipt =
  {
    kind: "normal",
    request: BeginDeleteRequest,
    deleting_epoch: FenceEpoch,
    deleting_head: RemoteHead,
    completed_at: UnixMillis
  }
| {
    kind: "disposable_root",
    disk_id: Id,
    volume_id: Id,
    delete_id: Id,
    authorization_id: Id,
    prior_attachment_id: Id,
    deleting_epoch: FenceEpoch,
    deleting_head: RemoteHead,
    completed_at: UnixMillis
  }
```

`VolumeOwnerBinding`是与`VolumeRecord`同表、同事务提交的Runtime inventory内部authority，不扩展
blockd可见的`VolumeRecord` wire。Active + Owned时它必须且只能存在，并逐字段等于
`VolumeRecord(volume_id, lease_owner, lease_epoch)`；Unowned或Deleting时必须为null。normal acquire和
takeover在owner/epoch线性化点同时写入当前Node；release和两种begin-delete同时清除。takeover首次消费还要求
旧binding的Node等于已锁HostFenceEvent的Node，host-fence disposable consume同理；runtime-stopped release/
delete要求当前authenticated Node。binding/projection/Volume任一漂移都按stored corruption fail closed。

clean-slate schema 18提供两个partial ordered B-tree：projection arm
`(owner_node_id, volume_id COLLATE "C") WHERE owner_node_id IS NOT NULL`与canonical arm
`((owner_binding->>'owner_node_id'), volume_id COLLATE "C") WHERE owner_binding IS NOT NULL`。Runtime
inventory在一个read-only Repeatable Read事务中以两臂各自bounded查询并严格解码，最多返回`65536`
条；第`65537`条、双向漂移、重复或backend不确定都拒绝，不能截断成complete。这个provider-neutral
enumeration port还接收current `CatRuntimeConfig`集合固定的完整volume candidate ID集合，并在同一事务中通过
`volume_records`主键把candidate行并入Node-owned两臂的去重结果；candidate缺失或总union越界由Node
scanner拒绝，不能另开point-read事务拼出complete。该port只供signed Runtime scanner；blockd的
`VolumeDataAuthority`仍只能读取自己的exact grant，
不得枚举Node或fleet ownership。

`RemoteHead`只有两种合法形态：`generation == 0`当且仅当`root_hash`和`root_object_id`都为`null`；
`generation > 0`当且仅当两者都非`null`。Root hash、object ID和generation始终作为一个不可拆分tuple
比较、保存和复制；任何result或receipt写“exact head”都复用这三个字段，不能只比较其中一部分。
本文的“head generation非倒退”固定表示：更小generation拒绝；相同generation时hash和object ID也必须
逐字段相同；只有更大generation才进入对应的数据面CAS或closed successor验证。

`CatRecord`保存immutable product identity与Atomic Lifecycle定义的current chain/product projection；它不复制
`root_disk_id`、volume generation、physical process或observation facts。Root关系只由
`DiskRecord.role.root {cat_id}`回答；runtime shape/volume set只由`CatRuntimeConfig`回答；command/result只由
exact lifecycle Operation回答。`stable_state/effective_runtime_ready/runtime_incarnation`是同一terminal
settlement transaction写入的current投影，不是第二个command authority。每个Cat恰好一个Root的交叉约束按
Disk/config锁定验证。

`EndpointRecord`的五个字段创建后都不可修改，`endpoint_id`全局唯一、`(cat_id, name)`唯一；workspace/cat
必须逐字段指向同一合法Cat。它只保存产品identity和管理名，不复制hostname、protocol、port、route epoch、
placement或wake状态。`HostnameEndpointLookup.hostname`全局唯一，并且只定位
`workspace_id/cat_id/endpoint_id`；signer必须在同一snapshot重读current `EndpointBinding`、Serving receipt与
effective RuntimeReady，不能单独把lookup当作签发authority。创建或改变Endpoint的事务必须原子写完整binding
与对应lookup；移除Endpoint则在同一事务删除旧lookup。任一不等是store invariant failure并
fail closed。

`DiskRecord`的disk/workspace/name/volume identity、size、durability和created_at创建后不可修改，且
size/durability必须与同一`VolumeRecord`逐字段相同。`DiskRecord.volume_id`全局唯一：产品Disk与Volume
严格一对一，任意两个Disk row不得引用同一Volume。`(workspace_id, name)`唯一。`DiskRole.kind`和
Root的`cat_id`不可修改；Persistent role唯一允许的变化是保留同一token/UUID/blank head，从
Uninitialized一次性变为Initialized。Root只保存`root {cat_id}`，没有假的NotApplicable initialization字段；
Persistent只保存上述两态initialization。Available/Bound不是
Disk row状态：Root的Cat必须与Disk属于同一Workspace，每个Cat恰好一个Root，且该Root只能出现在该Cat的
current `CatRuntimeConfig`；Persistent绑定只从全部current config的RuntimeVolumeConfig集合推导，任一
PersistentDisk同时最多被一个current config引用。attach、detach、move和delete mutation都按全局锁序锁定
同一Disk/Volume及涉及的current config rows；并发绑定只能一方提交，不能靠先读后写绕过RWO唯一性。
任一交叉约束破坏都是Control Store invariant failure并fail closed。产品删除完成后不保留
`Deleted` Disk row；可观察的产品状态只有Active、Deleting和row不存在。

产品mutation path中的`{disk}`只解析不可变`disk_id`。`name`只用于展示和显式name lookup入口；同一path
不得实现“先按ID、找不到再按name”或其他name-or-ID猜测。

`lease_owner == null`当且仅当`lease_expires_at == null`；owner非null时Volume必须为Active，owner即
当前`attachment_id`。Deleting Volume必须owner/expiry都为null。`last_transition`是closed enum：每个
没有独立row的normal acquire/release/begin delete保存完整typed request和首次direct result；takeover和
begin-disposable-delete只保存`authorization_id` foreign-key marker，payload/receipt唯一从锁定的
`AuthorizationRecord`读取，不能在Volume row复制第二份。same-disk restore由`ApiIdempotencyResult`幂等化，提交
新head/epoch时把`last_transition`清为null，使任何更早domain transition重放都成为`StaleTransition`。

`ApiIdempotencyResult`只用于§3.3覆盖的Workspace product mutation；主键是
`(authenticated_workspace_id, canonical_route, idempotency_key)`，唯一fingerprint算法见§3.3。同key同
fingerprint逐字节重放`http_status + content_type + response_body`；同key
不同fingerprint在读取任何资源锁前返回`IdempotencyConflict`。首次请求在reservation下执行一次资源事务，
并在同一commit写最终result；业务成功或确定性业务失败可以结算。serialization/连接错误或已知未提交
事务不写result；commit acknowledgement或HTTP response transport不明不得另写一个失败result，最终PG
状态只能是“业务变化+result同时存在”或“两者都不存在”，重试按key读取判定。V1已提交result不因对应
resource或Operation删除而GC，也不通过
resource是否仍存在决定是否重放；它是API重试权威，不是Snapshot产品查询或GC authority。row不另存
`operation_id`、Operation phase/status或结构化业务response；异步接口的operation ID若存在，只是当时
`response_body`中的bytes。需要精确重放的全部语义只能由status、content type和body承载；covered route不得
依赖row未保存的`ETag`、`Location`或其他语义response header。动态request ID等非语义header可在每次重放时
不同，不属于result，也不增加generic header map。
`created_at`取首次写result事务的PostgreSQL DB now且之后不可修改，重放不刷新。超过1MiB的response不能提交
业务变化或result。Snapshot create/delete/restore以及PersistentDisk
create/delete都不创建自己的Operation。

`AuthorizationRecord`由同一PostgreSQL trust/transaction域内的唯一Control Store writer创建；Node只提交
`authorization_id`。consumer按ID锁row并读取服务器端不可变`authorization`，不存在客户端可替换的payload，
也不使用第二套签名或canonical request hash。同一authorization ID逐字段相同只读取原row/result；同ID
不同typed payload是store invariant violation并拒绝。首次消费把state和对应closed receipt原子写入；receipt
variant必须匹配authorization variant，且所有共有字段逐字段相同。AuthorizationRecord是authorization
payload和receipt的唯一持久权威；VolumeRecord只能保存authorization ID marker。

normal acquire/release/delete只对当前`last_transition`或保留的completion receipt做ID比较：ID相同且完整
typed request逐字段相同时返回原result，ID相同但payload不同返回`StaleTransition`。VolumeRecord只保留最近
一次`last_transition`；它被合法后续转换取代后不保留第二份ledger，旧request按当前state/expected epoch
安全拒绝且零副作用，绝不重新执行或猜回旧result。
`AuthorizationConsumedReceipt`一经写入不可修改，并保留到相关HostFenceEvent完成后继验证。
`DeleteCompletionReceipt`只在对象sweep完成且Control Disk/Volume rows同事务删除时写入，供row删除后的
精确重放；保留规则见§11.3。

`lease_epoch` 在 acquire、release、takeover 以及会改变 attach 前提的 restore/delete
边界单调增加。这样，晚到的旧 acquire 即使看到 volume 再次 Unowned，也不能用旧
`expected_epoch` 复活。

MetadataStore 错误是闭集：`NotFound`、`OtherWriter`、`Fenced`、`StaleTransition`、`InvalidLeaseDuration`、
`EpochExhausted`、
`AdminBusy`、`HeadConflict`、`SnapshotInUse`、`InvalidAuthorization`、`BackendUnknown`。调用方不得
按文本分支。

所有`lease_epoch + 1`使用checked-add；当前epoch已为`9223372036854775807`时返回`EpochExhausted`且
row/result/receipt全部不变，不能wrap、饱和或改用另一种操作继续。

### 3.1 Volume核心状态机

| 当前状态 | 唯一允许的转换 | 结果 |
|---|---|---|
| Active + Unowned | normal acquire | Active + Owned(new attachment, epoch + 1) |
| Active + Owned | renew | owner/epoch不变，以本次DB-now + duration重设absolute health expiry |
| Active + Owned | exact release | Active + Unowned(epoch + 1) |
| Active + Owned | authorized takeover | Active + Owned(new attachment, epoch + 1) |
| Active + Unowned | same-disk restore | Active + Unowned(new head/generation, epoch + 1) |
| Active + Unowned | begin delete | Deleting(delete_id, epoch + 1) |
| Active + Owned | authorized disposable Root delete | Deleting(delete_id, owner cleared, epoch + 1) |
| Deleting | idempotent sweep完成 | Removed |

表外转换全部拒绝。各variant自己的transition/authorization/delete ID只让表内同一次转换可重试，不允许
跳过前置状态或在variant之间复用。

### 3.2 Pure domain 与事务编排边界

pure domain函数只接受当前`VolumeRecord`，takeover/disposable路径再接受同一事务已锁定的
`HostFenceEvent`（仅适用时）和`AuthorizationRecord`；它只判断这些row自身的精确字段、closed state转换、
epoch checked-add、DB时间和typed replay，输出新的VolumeRecord/direct result或上面的closed error。它不读取
CatRuntimeConfig、lifecycle Operation、Disk、Snapshot、Node inventory或物理进程，也不接受`verified=true`、proof boolean、opaque
`VerifiedContext`之类可绕过检查的参数。

唯一的PostgreSQL事务owner按§1固定锁序逐字段验证所有跨row前置，再调用pure domain函数并在同一commit写入
它的结果及相关Control rows。terminal atomic lifecycle result、`R == L`、blockd stopped、当前
CatRuntimeConfig/revision/placement、Disk kind/ownership/state、`DiskSnapshotRecord`为空、exact
strong-stop receipt或HostFenceEvent事实都属于这一层；
每项必须从本事务锁定的权威row读取，不能先算成bool或由调用者声称。SQLite只可复用pure domain函数作为
窄数据面/单row fixture；它不实现或模拟Control cross-row事务，也不形成第二个authority。

测试责任也分两层：pure domain table tests穷举每个Volume/Event/Authorization当前状态、exact replay、
同ID异payload、epoch与RemoteHead边界；唯一PostgreSQL Control adapter的integration tests逐项改变跨row字段并
覆盖固定锁序、并发提交与每个crash点。SQLite可复用前一层，但domain fixture中的伪上下文不能替代PG验收。

### 3.3 Workspace product API idempotency

本节只覆盖同时满足两项的HTTP mutation：资源归属一个已认证Workspace；业务rows和最终result能在唯一
Control PostgreSQL事务中原子commit。当前闭集是Cat/runtime config/lifecycle Operation、
Endpoint、Disk和DiskSnapshot等
Workspace-scoped product mutations。Account/WorkOS、Billing/Stripe、fleet/admin、Node/internal、webhook，
以及先在外部系统产生副作用的route不使用本row；它们只复用各自已经存在的external ID、event ID、
revision/attempt/authorization或provider idempotency协议，禁止伪造“system workspace”或再写一份
`ApiIdempotencyResult`。

router中的每条mutation必须在构建/启动验收时恰好归入“本节PG result”或一个既有domain协议。未分类或
双重归属的route fail gate且不可注册；测试枚举全部mutation routes。这个分类不是新table、ledger或运行时
workflow，也不能为排除项发明第二个幂等协议。

本节覆盖的route共用一个byte-level算法，不再各写canonical JSON或参数归一化。定义
`frame(b) = u64-BE(len(b)) || b`，其中length是后续payload的octet数；`if_match` payload在header缺席时
固定为单byte `0x00`，存在时固定为`0x01 || u64-BE(parsed_generation)`。最终：

```text
request_fingerprint = SHA-256(
  ASCII("cats.api-idempotency.v1") || 0x00 ||
  frame(UTF8(authenticated_workspace_id)) ||
  frame(ASCII(canonical_route)) ||
  frame(raw_path_and_query_bytes) ||
  frame(if_match_payload) ||
  frame(raw_body_bytes)
)
```

`canonical_route`固定为大写HTTP method、一个ASCII space和router匹配到的route template，例如
`POST /v1/workspaces/{workspace}/disks`；不是raw path。`raw_path_and_query_bytes`是server收到的原始path及存在时的`?query`，
保留percent encoding、query顺序和重复参数。`raw_body_bytes`是移除HTTP transfer framing后、JSON解析前的
完整body。每个covered route在注册时固定唯一request media envelope：无body route只接受空body且没有
Content-Type field；有body route只接受恰好一个、逐byte等于该route注册常量的Content-Type field-value，
不接受别名或额外parameter。Content-Encoding只允许没有该field或恰好一个逐byte为`identity`的field。
envelope错误、
超出route固定body byte cap、重复/非法`If-Match`或无法解析为`Generation`都在hash/reservation前拒绝。
`If-Match`合法文本的不同写法只要解析为同一Generation就使用相同9-byte payload。

请求必须携带恰好一个`Idempotency-Key` field occurrence；在HTTP field-line解析并移除包围field-value的
OWS后，其exact value必须为1..=512 bytes且每个byte都在`0x20..=0x7e`。实现必须在任何comma folding前
拒绝重复field，缺失、重复、空值、非printable或超长都在reservation前拒绝。该exact value只在row主键中，
不进入hash；Authorization、Cookie、request ID、User-Agent和其他不影响
mutation语义的header也不进入hash。除`If-Match`外，将来任何会改变mutation的header必须先发布新的
fingerprint domain/version并整体切换，不能在单个route偷偷追加frame。JSON whitespace/key order不同，或
path/query percent spelling、顺序不同，即使业务解析后等价，也会得到不同fingerprint并安全返回
`IdempotencyConflict`；server不做语义归一化。

以下fixed vectors中字符串均为所示ASCII/UTF-8 bytes，`if_match_payload`以hex表示：

| vector | workspace | canonical route | raw path-and-query | if_match payload | raw body bytes | expected fingerprint |
|---|---|---|---|---|---|---|
| absent If-Match | `ws_01` | `POST /v1/workspaces/{workspace}/disks` | `/v1/workspaces/ws_01/disks` | `00` | `{"durability":"strict","name":"data","size_bytes":1073741824}` | `sha256:5069be7db8918e6a363d4d842224d9437a9eba202965ccc372838579b3b4ecbe` |
| generation 7 | `ws_01` | `POST /v1/workspaces/{workspace}/disks/{disk}/actions/{verb}` | `/v1/workspaces/ws_01/disks/disk_01/actions/mount?note=a%2Fb` | `010000000000000007` | hex `7b0a2020226361745f6964223a20226361745f3031222c0a2020226d6f756e745f6174223a20222f64617461220a7d` | `sha256:d07a08a0b37fbf5b6ee2022a6561f9441a186d516fd4316c5cce9068401bd6b7` |
| Cat create | `ws_01` | `POST /v1/workspaces/{workspace}/cats` | `/v1/workspaces/ws_01/cats` | `00` | `{"boot_image_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","durability":"strict","memory_bytes":2147483648,"name":"app","root_size_bytes":4294967296,"vcpus":2}` | `sha256:8745422e60778a889e8a85f9a45a7cadbbd57d71ba412417bf02daaedcb0f76c` |

## 4. Lease 接口和状态机

### 4.1 Normal acquire

```text
NormalAcquireRequest {
  volume_id: Id,
  transition_id: RandomId128,
  attachment_id: Id,
  expected_unowned_epoch: FenceEpoch,
  lifecycle_operation_id: Id,
  lifecycle_request_fingerprint: Sha256Digest,
  placement_epoch: Epoch,
  lease_duration_ms: integer 1..=9223372036854775807
}

NormalAcquireResult {
  volume_id: Id,
  transition_id: RandomId128,
  attachment_id: Id,
  resulting_epoch: FenceEpoch,
  resulting_head: RemoteHead,
  lease_expires_at: UnixMillis
}
```

原子规则：

1. `admin_state` 必须是 Active。
2. `lease_owner` 必须为空，且当前 epoch 等于 `expected_unowned_epoch`。
3. 事务只读取一次PostgreSQL `db_now: UnixMillis`，对`db_now + lease_duration_ms`做checked-add；输入为0、
   非canonical正整数或加法溢出返回`InvalidLeaseDuration`且零副作用。
4. 成功时设置owner、把epoch增加1、保存未改变的exact head与absolute `lease_expires_at`，并把完整
   request/result写为`last_transition.normal_acquire`。
5. 当前`last_transition.normal_acquire`的`transition_id`相同时，request逐字段相同的重试返回原
   `NormalAcquireResult`，不重读时钟或增加epoch；同ID异payload返回`StaleTransition`。若已被后续转换
   取代则按当前state/expected epoch拒绝，不恢复旧result。
6. 任何其他 owner，即使expiry已过，也返回 `OtherWriter`。
7. 同一 attachment 但不同 transition 也不隐式采用；atomic command必须使用原 transition 或明确
   quarantine。

Node在调用前把request写入当前Node-private command journal/installed physical manifest。响应
不明确时读取VolumeRecord：只有
`last_transition.kind="normal_acquire"`且其中完整request/result、当前owner和结果epoch逐字段匹配才算成功。

### 4.2 Renew

```text
RenewLeaseRequest {
  volume_id: Id,
  attachment_id: Id,
  expected_epoch: FenceEpoch,
  lease_duration_ms: integer 1..=9223372036854775807
}

RenewLeaseResult {
  volume_id: Id,
  attachment_id: Id,
  epoch: FenceEpoch,
  lease_expires_at: UnixMillis
}
```

只有Active且owner/epoch精确匹配时才用本事务一次读取的PostgreSQL `db_now`做同样checked-add并写
`lease_expires_at = checked_add(db_now, lease_duration_ms)`；非法duration或溢出返回
`InvalidLeaseDuration`。单纯expiry lapse可以继续renew；
owner/epoch改变后返回`Fenced`。renew不改变epoch、head或`last_transition`，也不能把其他owner改成自己。

### 4.3 Release

```text
ReleaseRequest {
  volume_id: Id,
  transition_id: RandomId128,
  attachment_id: Id,
  expected_epoch: FenceEpoch,
  lifecycle_operation_id: Id,
  lifecycle_request_fingerprint: Sha256Digest
}

ReleaseResult {
  volume_id: Id,
  transition_id: RandomId128,
  released_attachment_id: Id,
  resulting_epoch: FenceEpoch,
  resulting_head: RemoteHead
}
```

pure domain转换只判断VolumeRecord为Active且owner/epoch逐字段等于request；成功时清空owner和expiry、
增加epoch、保留exact head，并把完整request/result写为`last_transition.release`。blockd已停止、保留数据
`R == L`及其他跨row事实由§3.2事务owner先验证。当前`last_transition.release`的ID相同且request相同返回
原result；同ID异payload返回`StaleTransition`。已被后续转换取代或其他owner/epoch不匹配返回`Fenced`，
不能恢复旧result或静默成功。

### 4.4 Protected takeover

普通atomic command不存在revoke。takeover只接受HostFenceRecovery的逐卷授权：

```text
VolumeTakeoverAuthorization {
  kind: "takeover",
  authorization_id: Id,
  authorized_node_id: Id,
  host_fence_event_id: Id,
  volume_id: Id,
  disk_id: Id,
  cat_id: Id,
  expected_attachment_id: Id,
  expected_epoch: FenceEpoch,
  new_attachment_id: Id,
  interrupted_operation_id: Id,
  host_lost_result_digest: Sha256Digest,
  recovery_operation_id: Id,
  recovery_request_fingerprint: Sha256Digest,
  new_placement_epoch: Epoch,
  lease_duration_ms: integer 1..=9223372036854775807,
  not_after: UnixMillis
}
```

`authorized_node_id`在授权派生事务中逐字段复制目标new placement Node，随payload一次写定且
不因lifecycle head、placement或AgentSession后续变化而改写。Node只提交`authorization_id`，不提交
或签名上述payload。首次消费使用固定锁序
`HostFenceEvent -> AuthorizationRecord -> VolumeRecord`，在一个PostgreSQL事务中读服务器端immutable
authorization，同时验证event仍为Active、authorization仍为Unconsumed、本事务`db_now <= not_after`、
调用Node精确等于`authorized_node_id`、旧attachment/epoch和目标identity精确匹配，并对
`db_now + lease_duration_ms`checked-add。随后设置新owner、
增加epoch、保持exact head，写absolute expiry和`last_transition.takeover {authorization_id}` marker，并原子把authorization改为
`Consumed(TakeoverConsumedReceipt)`；receipt的`consumed_at`就是该次`db_now`，所以original expiry唯一等于
`checked_add(consumed_at, authorization.lease_duration_ms)`。
receipt不重复`authorized_node_id`；它仍嵌在同一个不可变`AuthorizationRecord`，validator必须把receipt
逐字段绑定父authorization，不能把receipt拆成第二份授权或ledger。

相同授权重试只读取不可变receipt并返回原grant，不再次修改VolumeRecord。
换卷、换placement、换attachment、payload不同、过期、duration非法/溢出或event不再Active的首次消费
全部拒绝且零副作用；duration错误返回`InvalidLeaseDuration`，其他授权错误返回`InvalidAuthorization`。

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
  state: Active
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
receipt重放只读原结果，任一字段不同都拒绝。替换Host必须使用新的
provisioned identity。
该receipt只可作为Runtime tombstone GC的Host缺席证据，不授予placement/writer，也不跳过本规格的逐卷
authorization、receipt或disposition闭环。

从`isolated`升级时先锁该event绑定的NodeIdentity并重验immutable lineage，再锁同一event行，
并用`state=Active`、`isolation_state={kind:"isolated"}`及未改变的
完整event tuple（`event_id`、provider、immutable host、node、expected boot/session、fence attempt和
`observed_at`）做exact CAS。event创建、`isolated -> host_destroyed`、
使用HostDestroyed proof的Runtime tombstone GC以及会创建CatRuntimeConfig placement的授权派生都先按
node ID锁全部NodeIdentity，再锁event；只有不改event eligibility state、不再读NodeIdentity的授权
首次消费保持`HostFenceEvent -> Authorization -> Volume`顺序。这些事务都持有event行锁到commit并重验
各自要求的state、isolation variant和event tuple；竞争事务只能按锁取得顺序提交，后一方不得
沿用旧读取。旧epoch的`R < L`目录保留作人工恢复证据，永不参与新Root。

没有Runtime tombstone、其他HostFenceEvent或live
recovery引用相关逐卷记录，所有Unconsumed authorization都已过`not_after`、所有Consumed authorization
的receipt及最终volume disposition都已验证后，相关逐卷authorization/receipt/
`DeleteCompletionReceipt`可在一个事务中按审计策略GC；任一引用、仍可首次消费的authorization或未闭合
disposition都拒绝且零副作用。compact
HostFenceEvent/HostDestroyed receipt继续按现有Operation/审计引用保留，只有全部引用消失后才可GC。

## 5. blockd 采用 grant，不改变 ownership

Node 是 lease transition 的执行者。顺序固定：

1. 在当前Node-private lifecycle journal/installed physical manifest写acquire/takeover request。
2. 调用atomic lifecycle的signed
   `POST /v1/internal/runtime/lifecycle-volume-transitions`；所有模糊结果都按§5.1重放同一exact
   command-scoped request，由immutable receipt ledger/current marker返回原receipt。
3. 把command-scoped EnsureRunning grant receipt原子写回该private recovery record。
4. 创建 attachment 专属 data-dir identity。
5. 启动 blockd，传入 volume、attachment、epoch 和既有的closed acquire origin。
6. blockd 从 MetadataStore 验证精确 owner/epoch后开始 renew和服务。

第3步的durable serving artifact不是薄grant的复制。它是closed
`Normal {request,result} | Takeover {authorization,receipt}`：Takeover必须来自§5.1同一command-scoped
transition response中的完整consumed authorization record，且首次expiry精确等于
`checked_add(receipt.consumed_at, authorization.lease_duration_ms)`。artifact与current Volume按
origin/owner/epoch/marker/exact head闭合后才可创建data-dir或启动blockd。

blockd 启动不得调用 acquire、takeover或增加 epoch。它只可以 renew、以精确 owner/epoch发布 Root，
以及报告 status。会产生Cold terminal result的atomic command先drain、停止blockd，再执行release。

### 5.1 Signed command-scoped replay

atomic release不提供按任意`authorization_id`读取authorization历史的Node接口，也不返回
`direct_successor_authorization`。pre-cutover Runtime Volume Transitions的A19 evidence-read spec、DTO、codec、
constant与route parser已经物理删除；旧Desired/revision scope与任意ID read严格拒绝，历史只在Git中保留。

Node唯一可调用的transition边界是current AgentSession签名的
`POST /v1/internal/runtime/lifecycle-volume-transitions`。每次request精确绑定Operation、request
fingerprint、Cat、Node、placement、command kind与排序volume targets；Node在发出请求前把同一scope和
transition identity写入private journal。response丢失时只重放完全相同的request，不通过另一条read API
查询或拼接结果。

Control在同一transition事务中锁current session、unresolved Operation/Cat head和exact Volume domain rows。
immutable receipt ledger与Volume current marker使同一transition重放返回原receipt bytes；identity或scope任一
不同时fail closed。调用方不能提交结果bool、猜测successor、枚举authorization历史或取得Control SQL
credential。takeover与disposable Root authorization同样只能在exact command scope中消费并返回closed
receipt；模糊结果通过重放原command transition闭合。

Node把返回的command-scoped receipt持久化到同一private recovery record后才可继续physical effect。缺少
receipt、ledger/current marker不一致、session/Operation已变化或stored projection损坏都保持
Blocked/Quarantined；audit log、inventory、目录存在性和旧A19 evidence route都不能替代。

## 6. 本地 attachment lineage

每个 data directory 属于一次 attachment，而不是只按 Disk ID 复用：

```text
AcquireOrigin =
  { kind: "normal", transition_id: RandomId128 }
| { kind: "takeover", authorization_id: Id }

VolumeLocalIdentity {
  volume_id: Id,
  attachment_id: Id,
  attachment_epoch: FenceEpoch,
  acquire_origin: AcquireOrigin,
  node_id: Id,
  placement_epoch: Epoch
}
```

identity 在创建任何 cache/pack 前完成 file fsync、rename 和 parent directory fsync。每个 pending
pack 重复记录 `volume_id + attachment_id + attachment_epoch + acquire_origin`。normal acquire从锁定的
`last_transition.normal_acquire`复制`normal {transition_id}`，takeover从锁定的`AuthorizationRecord`复制
`takeover {authorization_id}`；不能从ID文本猜测namespace。

active lineage的`identity.json`、每个pending pack、Runtime checkpoint/inventory与生成当前精确grant的
服务器端acquire marker必须逐字段绑定同一个完整`AcquireOrigin` variant，之后才可adopt或publish。精确
release覆盖`last_transition`后，cleanup改为逐字段匹配release前已持久化的checkpoint、当前full inventory、
identity和全部pack，不重建已被覆盖的acquire marker。即使`transition_id`与`authorization_id`文本相同，
`normal`和`takeover`也不是同一identity；variant缺失、unknown `kind`、旧裸`acquire_transition_id`或任一
字段冲突都不得adopt、publish或cleanup该目录，只能保留完整证据并quarantine。

恢复规则：

- 完全相同 lineage：按 generation 顺序 replay；
- MetadataStore 仍是相同 owner/epoch：可以继续 publish；
- epoch 已失效或 identity 不匹配：整个目录 quarantine，不读取其中数据构造新 Root；
- pack 缺口、损坏或 identity 缺失：quarantine；
- `R == L` 且 release 已完成的旧目录可按精确 ownership token删除。
- disposable Root 的唯一例外：§11 的 Owned -> Deleting CAS 已成功后，才能删除授权中精确
  attachment lineage 的 `R < L` tail；该例外不能用于其他目录或其他卷。

clean-slate cutover 不解析缺少这些字段的旧 pack，也不接受旧裸`acquire_transition_id`的identity或pack。

## 7. Cold-only 磁盘成员关系

第一版终态不支持 hot attach、hot detach、resize 或 Running DiskSnapshot。volume 容量在创建时确定，
之后不可变；Control Plane、MetadataStore 和 blockd 都不提供 resize API。

- PersistentDisk加入或离开Cat的磁盘集合，只能在Cat current head是exact terminal Cold、
  没有unresolved Operation时提交。Cold head始终闭合自己冻结的历史config/result；同一
  Cold window可append多个新config，current pointer只由每次mutation的source->target CAS推进，
  不改写历史Cold Operation。
- attach/detach是同步product mutation：它在同一事务重验Disk/Volume为Active + Unowned、
  current membership全局唯一，插入append-only新`ImmutableRuntimeConfig`并CAS Cat pointer；
  不创建lifecycle Operation、不调用Node、不读取inventory推断完成。
- attach从Disk的一次性filesystem UUID与request mount path生成`persistent_ext4`，分配未占用
  Guest slot/serial；detach必须逐字段命中同Cat/config/UUID/mount的exact binding。
- Cold -> Running的run冻结已锁定的latest current config，不要求它等于历史Cold
  command config。Control对旧Cold slots重验exact `NormallyReleased | AlreadyUnowned` receipts；
  已detach的旧slot只留在source receipt set而不进入target authority，Cold后新attach的
  Persistent slot必须是fresh locked `Active + Unowned`，以current exact epoch构造
  `NormalUnowned`。Root不能用这个规则换或新增。
- internal EnsureRunning spec最终使用latest config的完整、排序且无重复`RuntimeVolumeConfig`集合一次运行；
  predecessor中的Cold disposition digests仍字节级绑定历史Cold result的完整slot set。
- Running 中请求改变磁盘集合返回前置条件错误；调用方先将 Cat 变为 Cold。
- RootDisk始终随Cat；PersistentDisk要移到另一Cat，必须先在原Cat的Cold window完成
  detach，再在目标Cat的Cold window完成attach；并发只有一方能commit。

这条限制消除了 Guest 重新 mount、打开文件句柄、VMM hotplug 和 blockd drain 之间的竞态。未来若
确有产品需要，hotplug 必须单独设计并验证，不能放宽本合同的 Cold 前置条件。

## 8. ext4 初始化与 mount readiness

### 8.1 Disk create

mutation path中的Disk引用遵守§3的immutable `disk_id`规则；create response可以展示name，但后续资源path
不以name代替ID。

#### Atomic Cat create

production Cat create只构造atomic lifecycle graph。HTTP idempotency、immutable image读取与placement
planner分别沿用[§3.3](#33-workspace-product-api-idempotency)、
[Immutable Image Manifest Read v1](immutable-image-manifest-read-v1.md)和
[Runtime Placement Policy v1](runtime-placement-policy-v1.md)的唯一合同；这里不复制它们的rolling
字段表。

一个成功的PostgreSQL commit全有或全无地写入：

- `CatRecord/cat_creation_id`与append-only `ImmutableRuntimeConfig`；
- generation-zero、Unowned、blank-head的唯一Root `DiskRecord/VolumeRecord`；
- default bound Endpoint、hostname lookup、route epoch 1，且所有Node gate仍Closed；
- `LifecyclePredecessor::Genesis`、`StartSource::Genesis`、Root `normal_unowned(epoch=0)` authority的
  unresolved Start Operation；
- exact `ApiIdempotencyResult`，其202 response绑定同一Cat/Operation identity。

canonical request、runtime config digest、placement、Root volume identity与normal-acquire transition在同一
candidate中冻结；Endpoint不进入runtime config。candidate identity碰撞、placement/session/full-inventory
重验失败或事务明确回滚均不留下业务row/result；commit response不明只查询/重放同一
idempotency result，不重抽单个identity或创建replacement Operation。Node随后仅通过
[Atomic Runtime Lifecycle v1 §4](atomic-runtime-lifecycle-v1.md#4-command-envelopepredecessor-与-admission)
取得该Start并返回`RuntimeReady | StartFailed`；inventory不结算create。

#### Retained PersistentDisk create

**PersistentDisk独立create。** 它是同步资源事务，不走Runtime Operation。认证、当前membership/route permission和§3.3
key reservation通过后，result miss的唯一PostgreSQL事务由server分配永不复用的`disk_id`、`volume_id`、
`initialization_token`和`filesystem_uuid`，并使用同一次DB now原子写：

- Active + Unowned `VolumeRecord`：请求的immutable size/durability、`lease_epoch=0`、owner/expiry和
  `last_transition`为null，exact blank `RemoteHead = {generation:0, root_hash:null, root_object_id:null}`；
- Active `DiskRecord`：相同size/durability/volume、请求name、created_at和
  `persistent {initialization: uninitialized {token, uuid, expected_blank_head}}`，其中blank head逐字段等于
  新Volume head；
- `201 application/json`的exact resource response bytes及同一created_at写入`ApiIdempotencyResult`。

三者全部commit或全部不存在；连接/commit结果不明不能留下无result的单边Disk/Volume。同key重放只返回
原201 bytes，不读resource；同key异fingerprint冲突。该路径不创建Operation、initialization job或transition
ledger。result miss先取得`DiskNameLock(workspace_id, name)`并重验名称；命中合法existing Disk只写exact 409
result，名称free才按Volume、Disk、initialization token、filesystem UUID的稳定candidate锁序插入。它不得先锁
Volume或Disk再反向取得名称锁；与Cat Root create并发时，持同一名称锁的一方提交后，另一方只能得到typed 409
或typed whole-bundle candidate collision，数据库unique constraint只作不可达invariant backstop。

### 8.2 Initialization CAS

首次Start一个尚未初始化的PersistentDisk时，Node必须在route admission仍Closed且业务mount尚未发生的
边界内完成inspect -> format -> durable commit -> mount。Control不从inventory或“看见了ext4”推断
Initialized。

signed `InspectPersistentInitialization`的binding闭合：

- lifecycle Operation/request fingerprint、Cat/Node/placement；
- runtime config ID/digest与exact Persistent `RuntimeVolumeConfig`；
- current Start grant receipt、attachment/epoch与Volume head。

AgentSession只认证outer request，刻意不进入initialization identity；Agent replacement恢复同一Start时不能
因此得到第二个format authority。inspect只返回closed
`Uninitialized {token, filesystem_uuid, expected_blank_head}`或
`Initialized {same tuple, initialized_head, initialized_at}`。

若为Uninitialized，Node在private execution journal中先持久化exact format plan；fresh验证Volume仍是同一
Active+Owned attachment/epoch、同一blank predecessor后，Guest按稳定virtio identity检查设备。只有全盘严格
blank才可用同一token执行`mkfs.ext4 -U <filesystem_uuid>`；期望UUID可adopt，其他UUID、部分格式痕迹、
head/epoch/attachment变化或模糊证据均零mkfs并quarantine。format与commit是Node-private相邻恢复步骤，
不是public lifecycle状态。

commit前磁盘仍unmounted。Guest返回
`LifecyclePersistentInitializationGuestProbe {exact_ext4_unmounted, runtime_incarnation,
device serial/slot/major/minor/size, filesystem_uuid, challenge/response digest}`；随后device FLUSH和blockd
drain必须产生同attachment的非blank `initialized_head`、`L == R == head.generation`和pending=0。
signed `CommitPersistentInitialization`精确携带binding、`format_plan_digest`、token/UUID、blank/new head、
Guest probe和完整flush/drain receipt。

Control在一个PostgreSQL transaction重验current session、unresolved Start、config、Start grant、
Volume/Disk与上述每个字段，只允许同一Uninitialized tuple单向写为Initialized，并保存
`LifecyclePersistentInitializationCommitReceipt`及
`cats.atomic-lifecycle.persistent-initialization-commit-receipt.v1` digest。相同exact commit返回原
`initialized_at`/receipt；错session只拒绝transport，错command/config/grant/attachment/head/UUID、
`R != L`、单边状态或不同payload都fail closed，不存在第二条initialization job/ledger。

commit确认后Guest才mount exact UUID/path并返回read/write与完整mounted-set readiness；每轮mount probe使用
fresh current head且不得回退或same-generation换root。只有全部Persistent slot匹配，Start才可返回
RuntimeReady；所有Endpoint gate仍Closed，后续Route Enable才可Serving。
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

create、delete和restore都要求满足§3.3的唯一合法`Idempotency-Key`和request envelope。API先验证调用者身份、当前Workspace membership
和route permission，但不以目标Disk或Snapshot是否仍存在决定重放；随后取得§3的key reservation。
已有相同fingerprint的result时只返回其不可变status/content-type/body，绝不再读或修改Snapshot/Volume；不同
fingerprint立即冲突。只有尚无result的首次请求才继续按`VolumeRecord -> DiskRecord(owner Workspace)/
Cat/config/current lifecycle head -> DiskSnapshotRecord`锁序重验认证Workspace拥有Disk、Disk/volume绑定及各操作前置，并在
同一commit写业务变化与最终result。跨Workspace miss回滚reservation且不写Operation、result或资源。

### 10.1 创建

仅在产品Disk row为Active、Disk Cold且 volume unowned时允许：

```text
create_snapshot {
  disk_id: Id,
  expected_unowned_epoch: FenceEpoch,
  expected_size: integer 1..=9223372036854775807,
  expected_head: RemoteHead
}
```

首次事务重验产品Disk仍为Active、属于认证Workspace、所属Cat current head是exact terminal Cold result且
其normal release receipt覆盖该Disk/volume，且
`DiskRecord.volume_id`与Active + Unowned的`VolumeRecord`一致；epoch、size和exact RemoteHead必须与
请求完全相同。服务端随后分配一个全局唯一且永不复用的`snapshot_id`，插入包含精确disk/volume、
size、head和`created_at`的`DiskSnapshotRecord`，并原子写入包含
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
2. 在§3.3 covered key reservation后按统一锁序验证`DiskSnapshotRecord`；record的disk/volume必须精确指向
   当前Disk，且record、VolumeRecord和Root中的`size_bytes`必须完全相同。
3. 首次`restore_same_disk(snapshot_id: Id, expected_head: RemoteHead,
   expected_unowned_epoch: FenceEpoch)`把当前head指向snapshot
   Root、generation和epoch各增加1，并在同一事务写含新head/generation/epoch的成功result。
4. 相同key重放只读result，因此至多前进一次；晚到acquire因expected epoch失效而失败。

restore 不倒退 generation；它发布一个引用旧不可变数据的新 generation。第一版不支持 clone，
不建立跨 volume COW引用。

### 10.4 删除 Snapshot

Snapshot删除是独立操作，不由Disk删除隐式级联：

```text
delete_snapshot {
  snapshot_id: Id,
  disk_id: Id,
  expected_head: RemoteHead
}
```

首次事务按统一锁序重验认证Workspace拥有Disk，并验证Disk、Volume与`DiskSnapshotRecord`的
disk/volume/RemoteHead tuple完全一致。成功时删除这一行，并原子写包含`snapshot_id`和删除结果的
covered成功result；相同key重放只读result。record缺失且没有既有result是新的`NotFound`结果，不能猜测
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

普通入口共同要求没有live `DiskSnapshotRecord`、`R == L`、blockd及其upload workers已停止、精确release
完成且Volume为Unowned。role-specific前置严格分开：

- Root不接受直接Root Disk DELETE API，只能由current DeleteCat Operation驱动；同一个server分配的
  `delete_id`必须同时进入exact `DeleteSpec` Root `discard_with_cat` disposition和
  `BeginDeleteRequest`。Node在同一DeleteCat内部先完成strong Stop与全部Persistent disposition，再按current
  Root `VolumeRecord`选择唯一入口：
  - Root已由本Operation exact release且`R == L`时，用normal BeginDelete；事务锁current
    NodeIdentity/AgentSession、unresolved Delete Operation/Cat chain、Volume、Disk/config与snapshots，逐字段
    闭合Operation ID/fingerprint/placement、Root identity/size/durability、release receipt、Active + Unowned与
    no live snapshot；不读取Observation。
  - Root仍Owned且`R < L`时只能走§11.2 exact disposable authorization。Active HostFenceEvent恢复路径下任何
    仍Owned Root同样只走authorization，即使最后已知`R == L`或L未知；它不伪造Node release。
  - wrong Operation/fingerprint/delete ID、Persistent尚未全部完成、foreign lineage或仅凭Disk未绑定都拒绝。

Root cleanup/release与authorization derive以现有`VolumeRecord`作为分支gate，不增加row。derive事务创建
authorization后必须取得Volume锁并fresh重验current Delete Operation exact lineage及Active + Owned才能commit；
release取得Volume锁后必须fresh读取同一delete ID/Operation的authorization，任一已commit就拒绝，并重验
current command。release先commit时derive随后看到Unowned并整笔回滚；derive先commit时release看到auth并
零副作用拒绝。这个fresh probe必须以projection current scope **或** canonical authorization中的同一
volume/delete/Operation/placement scope选出至多两个候选，再完整closed decode并交叉验证projection；任一方向
drift都属于corruption，而旧lineage不进入候选。clean-slate schema 18必须在启动时精确校验
两个独立index：canonical
arm由`GIN ((record->'authorization') jsonb_path_ops)`承载，projection arm由partial ordered B-tree
`(volume_id, lifecycle_operation_id, placement_epoch, authorization_id COLLATE "C") WHERE kind='disposable_root_delete'`
承载。两臂各自至多取两个ID、`UNION`去重后才读取完整row；同一健康row命中两臂不能误报重复，外层
`LIMIT 2`本身不能作为任一臂全历史扫描的bound。
不能在锁前缓存“无authorization”后越过这个重验。
- Persistent不读取或保存“历史上属于哪个Cat”。显式Disk delete要求全部current `CatRuntimeConfig`都不引用该Disk，且current
  accepted complete inventory按
  [Runtime Inventory and Telemetry v1 §9](runtime-inventory-observation-v1.md#9-store-transaction与schema)在同一
  snapshot重验live session、60秒freshness、内部binding和current assigned-set snapshot，随后对相关物理
  identity证明不存在该volume的blockd、active lineage、device、mount或其他residue；任一缺失/旧inventory、
  session/assigned set变化或partial-only事实都拒绝。

attach/detach/move与begin-delete均锁同一VolumeRecord、DiskRecord和涉及的current config rows；attach先提交
则delete看到绑定而拒绝，delete先提交则attach看到Deleting而拒绝，不存在已删除Disk被并发重新绑定的窗口。

```text
BeginDeleteRequest {
  delete_id: Id,
  disk_id: Id,
  volume_id: Id,
  expected_unowned_epoch: FenceEpoch,
  expected_head: RemoteHead,
  origin: BeginDeleteOrigin
}

BeginDeleteOrigin =
  { kind: "lifecycle_delete", lifecycle_operation_id: Id,
    lifecycle_request_fingerprint: Sha256Digest }
| { kind: "disk_api", api_request_fingerprint: Sha256Digest }

BeginDeleteResult {
  delete_id: Id,
  disk_id: Id,
  volume_id: Id,
  resulting_epoch: FenceEpoch,
  resulting_head: RemoteHead
}
```

`BeginDeleteRequest`按`VolumeRecord -> Control Disk/Cat/config/Operation rows -> DiskSnapshotRecord rows`锁序，
在同一事务按role重验上述全部前置、Control Disk仍为Active、VolumeRecord精确为Active + Unowned，然后原子执行：

- `Control Disk Active -> Deleting(delete_id)`；
- `VolumeRecord Active + Unowned -> Deleting(delete_id, epoch + 1)`，owner/expiry保持null、head不变；
- 把完整request/direct result写为`last_transition.begin_delete`；
- 对显式Disk delete API，把`202 application/json`的exact `BeginDeleteResult` response bytes写入同一
  `ApiIdempotencyResult`。

`BeginDeleteResult`固定表示Control Disk和Volume都已进入同一`Deleting(request.delete_id)`且Volume
owner/expiry为null，不重复镜像两个state对象。

显式Disk delete在§3.3 key reservation miss后由server只分配一次`delete_id`并执行上述事务；commit后同步
返回202，不创建Operation。此后GET Disk在row存在时返回Deleting，completion删除row后返回404；无论对象
sweep是否已完成、产品GET是否已404，同key同fingerprint都永久重放首次202 bytes，绝不把重试变成404或
创建第二个Operation。RootDisk删除由其现有Cat lifecycle Operation驱动同一Deleting state，不创建Disk
Operation。

pure domain要求request的volume/epoch/head与row逐字段相同；它不复制更早release链。当前Active+Unowned
只能由本规格closed state machine产生，后继验证使用epoch单调、RemoteHead generation非倒退和当前
`last_transition.begin_delete`的exact request/result，而不是保存第二份中间历史。

相同delete ID且完整request相同的模糊响应，只有在两边都处于`BeginDeleteResult`精确postcondition，或两边
均已删除且存在逐字段匹配的`DeleteCompletionReceipt.normal`时才返回原result；同ID异payload返回
`StaleTransition`，单边状态或其他字段不一致返回`BackendUnknown`。normal acquire
也先锁VolumeRecord：acquire先提交则begin-delete的Unowned检查失败；begin-delete先提交则acquire的
Active检查失败，不存在重新取得owner的中间窗口。

### 11.2 放弃本地 tail 的 disposable Root

这是 `R == L` 与 normal release 规则的唯一例外：

```text
DisposableRootDeleteAuthorization {
  kind: "disposable_root_delete",
  authorization_id: Id,
  authorized_node_id: Id,
  delete_id: Id,
  disk_id: Id,
  volume_id: Id,
  cat_id: Id,
  lifecycle_operation_id: Id,
  lifecycle_request_fingerprint: Sha256Digest,
  placement_epoch: Epoch,
  expected_attachment_id: Id,
  expected_epoch: FenceEpoch,
  expected_head: RemoteHead,
  disposition: "discard_with_cat",
  persistent_dispositions_digest: Sha256Digest,
  isolation_basis: DisposableDeleteIsolationBasis,
  not_after: UnixMillis
}

DisposableDeleteIsolationBasis =
  {
    kind: "strong_stop",
    node_id: Id,
    agent_session_epoch: Epoch,
    lifecycle_operation_id: Id,
    strong_stop_receipt_digest: Sha256Digest,
    execution_absence_proof_digest: Sha256Digest,
    inventory_attestation_digest: Sha256Digest
  }
| {
    kind: "host_fence_event",
    event_id: Id,
    interrupted_operation_id: Id,
    host_lost_result_digest: Sha256Digest
  }
```

Control Plane只为current Delete Operation的canonical request中明确`discard_with_cat`的RootDisk建立授权，且
exact Persistent set必须已经全部`R == L`、normal released、retained detached。
`authorized_node_id`在同一派生事务中复制该Delete placement Node：`strong_stop`是可达执行Node，
`host_fence_event`内部worker路径仍保留被隔离的原placement Node，但该worker不使用Node HTTP或
evidence route。它随payload不可变，不会因后续chain/session变化改绑新Node。可达 Host 必须
先关闭admission、停止Guest/VMM和Guest-facing block frontend，并提交exact strong-Stop/inventory proof，且只有`R < L`才走授权；`R == L`
必须先走上述normal release。失联Host必须已有Active HostFenceEvent；此时任何仍Owned的exact Root都可授权，
不要求或伪造`R < L`，包括last known为`R == L`或L未知。授权绑定current
Operation/fingerprint/placement、delete ID、disposition、Persistent completion、remote head和最后owner/epoch；
strong_stop arm另外绑定strong Stop result/proof，HostFence arm只绑定event/interrupted Operation/HostLost digest且
绝不伪造strong Stop，不能
跨Disk、Cat、卷、attachment或重试身份复用。唯一Control Store writer在锁定这些权威row的同一
PostgreSQL事务中写完整immutable authorization；不增加第二套签名，Node消费时只提交`authorization_id`。

HostFenceEvent来源的首次消费使用固定锁序
`HostFenceEvent -> AuthorizationRecord -> VolumeRecord -> Control Disk/config/Operation/DiskSnapshotRecord rows`；
StrongStop来源使用相同后缀而没有event行。一个PostgreSQL事务读取服务器端authorization row，重验
event或authenticated strong-Stop proof、authorization完整tuple、Control Disk仍为Active、current Delete
Operation/request仍把该Root标为`discard_with_cat`、全部Persistent dispositions仍闭合，并确认没有live
`DiskSnapshotRecord`。StrongStop basis还要求current AgentSession、session-bound complete inventory attestation、
exact execution absence、Guest/VMM/frontend/mount stopped以及唯一Active、unfenced、`R < L` Root lineage；
HostFenceEvent basis要求exact Active event/HostLost result与metadata owner/epoch/head。Observation、heartbeat timeout
或目录缺失都不能替代这些proof。全部通过后才原子执行：

- `VolumeRecord Active + Owned(expected owner/epoch) -> Deleting(delete_id, owner cleared, epoch + 1)`；
- `Control Disk Active -> Deleting(delete_id)`；
- authorization `Unconsumed -> Consumed(BeginDisposableDeleteConsumedReceipt)`；
- Volume只写`last_transition.begin_disposable_delete {authorization_id}` marker，不复制authorization或receipt。

receipt逐字段绑定authorization、prior attachment、未改变的exact head和
`resulting_epoch = expected_epoch + 1`。该variant固定表示Volume owner/expiry已清空、Volume和Control Disk
都已进入同一`Deleting(authorization.delete_id)` direct state；不在receipt镜像state对象或另存bool proof。
receipt也不重复`authorized_node_id`；它只能连同同一不可变AuthorizationRecord的父payload一起验证。

相同授权重试只读取receipt；snapshot record仍存活时返回`SnapshotInUse`且三边都不改变，其他字段变化、
过期或非Root/disposable请求返回`InvalidAuthorization`。事务成功前不得删除pending data；成功后旧
epoch永久不能publish，Node才可删除授权所指lineage的`R < L` tail。这里不经过会产生可抢占窗口的
`Active + Unowned`，也不能扩展到PersistentDisk。被授权lineage可能有`R < L`tail，也可能因Host在
`R == L`后、release前失联而没有未发布tail；两者使用同一exact owner/epoch/head安全边界。

### 11.3 共同清理

1. sweeper只按稳定ID分页扫描Control Disk/Volume双方同一`Deleting(delete_id)`的level-triggered状态；
   不创建job、claim、lease或第二个Operation。§11.1 begin已证明blockd stopped、精确release和`R == L`；
   §11.2 begin已消费strong-stop/HostFence授权并fence旧epoch。Deleting禁止进入新runtime command或normal acquire，
   因而begin后不存在可合法创建新Root的writer。正常stop必须join全部blockd upload worker并确认没有
   in-flight PUT；HostFence路径只能使用Runtime规格中已完成object-write cutoff/barrier语义的同一Active
   HostFenceEvent：旧Host不能再发起PUT，barrier前已经被BlobStore接受的PUT必须已成功且对后续LIST可见，
   或已永久失败。不能完成该barrier时保持Deleting；若仍可能有旧PUT在后续empty LIST之后成功，不得
   sweep completion。
2. Node完整inventory证明所有可达本地资源已按授权处理；失联Host residue由Active event跟踪。sweeper重验
   `DiskSnapshotRecord`仍为空，再以object adapter的有界分页/list/delete幂等删除
   `volumes/<volume-id>/`下的data/maps/commits；它不负责删除Snapshot。
3. 用于completion的provider-neutral `BlobStore`必须满足
   [ADR-0005](../decisions/0005-provider-neutral-storage-ports-and-adapters.md)的destructive LIST合同：对已经
   成功完成的PUT/DELETE线性可见。删除请求全部返回后必须重新从prefix起点列举并确认empty；stale-empty或
   eventual-consistent LIST adapter不合格。仅“本轮delete成功”、缓存计数、目录缺席或
   调用方传入的`sweep_complete=true`都不是完成证据。由于writer已在begin事务中关闭且Deleting没有写后继，
   这个权威prefix-empty reread就是对象面的完成边界。
4. prefix确认empty后，一个PostgreSQL completion事务按固定锁序重新锁定并逐字段比较两边delete ID、
   Disk role/admin state/volume binding、zero snapshots、Volume
   `last_transition`、deleting epoch和exact head。normal begin把
   `last_transition.begin_delete.request`复制进`DeleteCompletionReceipt.normal`；disposable begin按Volume中的
   authorization ID marker锁定唯一AuthorizationRecord，并从其
   `BeginDisposableDeleteConsumedReceipt`复制authorization ID/prior attachment进
   `DeleteCompletionReceipt.disposable_root`。事务以PostgreSQL `db_now`写`completed_at`，写入精确
   `DeleteCompletionReceipt`并同时删除VolumeRecord与Control Disk row。

`DeleteCompletionReceipt`的closed variant保存一次且仅一次的disk/volume/delete identity、deleting epoch/head，
并与首次begin direct result逐字段相同：normal identity只来自完整`BeginDeleteRequest`，disposable identity
来自variant自身及锁定的唯一authorization receipt。该receipt固定且只表示：owner/expiry已在begin时清空、对象sweep
已经完整结束、Control Disk和Volume rows已在写receipt的同一commit删除；不增加`owner_cleared`、
`sweep_complete`或`rows_deleted` bool。相同delete ID只有完整begin request逐字段一致才可在row删除后返回
原result，同ID异payload返回`StaleTransition`。

任一步失败都保留Deleting供下一轮重试。多个sweeper可以安全地重复同一object delete和empty reread；
completion只允许一个exact compare/CAS事务提交，后到者看到rows已删除及同一receipt就停止。这里没有
跨PostgreSQL/object store的两阶段事务：PG Deleting始终是唯一待清理authority，对象操作可重放，最终receipt
只在empty reread之后的单个PG commit产生；receipt提交后再次LIST同prefix仍必须为empty。

不存在根据控制面一列状态、lease TTL或目录缺失直接删除volume的路径。删除完成后无需保留兼容
tombstone；但只要某个Active HostFenceEvent的Consumed authorization引用该卷，精确
`DeleteCompletionReceipt`、event和authorization都必须保留，供合法后继校验。

## 12. Atomic Cold handoff 迁移

计划迁移不使用 takeover：

1. source `ColdCat` command关闭admission、strong Stop并使全部Root/Persistent `R == L`。当卷
   仍Owned时做exact normal release；命令开始时已Unowned时使用closed
   `AlreadyUnowned` provenance，不伪造attachment/release。只有exact authenticated `ColdResult`
   terminal settlement可完成source Operation。
2. Control验证`ColdResult.volume_dispositions`完整覆盖source Cold Operation冻结的
   immutable config，并且每个digest与variant匹配后选择target Node、提高placement epoch并创建
   target `StartCat`。若Cold window内已attach/detach，target Start冻结latest current config；typed predecessor仍必须是
   `CrossNodeColdHandoff {cold_operation_id,cold_result_digest,source_node_id,source_placement,
   volume_disposition_receipts,target_placement}`，其中每卷receipt是
   `NormallyReleased {volume_id,normal_release_receipt_digest}`或
   `AlreadyUnowned {volume_id,already_unowned_receipt_digest}`的closed union。
3. target对每卷执行绑定Start Operation/fingerprint的normal acquire；两种source disposition都
   必须在Volume Authority中闭合为current exact Unowned epoch/head，target不能把
   `AlreadyUnowned`改写为虚构release。
4. old operation/placement/attachment/route Grant全部fail closed；target不读取或解释source checkpoint。

source未返回exact Cold/mixed disposition set时不创建target Start。两条Operation是causal
chain，不存在跨Node workflow、desired-state revision或Observation推断。

非计划 Host loss不走这条路径，只能走 HostFenceEvent + per-volume takeover。

## 13. 实现边界

clean-slate schema 18已组成唯一PostgreSQL Volume authority adapter、signed lifecycle-volume
transition route、command-scoped receipt ledger、Start grant/renewal、Cold mixed disposition、Delete begin/
completion、Cold-window config succession、Persistent inspect/commit initialization与snapshot-aware delete sweeper。Node私有journal/
physical manifest负责effect crash recovery，不是Control protocol或另一storage authority。

发布可达性与失败后继的唯一canonical gate是
[Atomic Runtime Lifecycle v1 §11](atomic-runtime-lifecycle-v1.md#11-acceptance-matrix)。本规格不另行复制
rolling implementation checklist；特别是Cold-only attach/detach必须在产品级验收中证明新
runtime-config head须按§7的历史Cold receipts + current pristine slots规则进入下一Start，并在
新Persistent首次使用时继续进入§8.2的signed initialization；不得用内部seeded
fixture取代这条product oracle。

## 14. 最小验收矩阵

| 场景 | Oracle |
|---|---|
| RemoteHead边界 | 只接受`0/null/null`或`>0/non-null/non-null`；hash、object ID、generation任一改变都会使exact compare失败；result/receipt逐字段复制tuple |
| mutation分类gate | 枚举全部HTTP mutation；Workspace product route恰好使用本节PG result，Account/WorkOS、Billing/Stripe、fleet/admin、Node/internal、webhook及external-first route只使用既有domain协议；未分类或双归属均fail gate且不伪造system workspace |
| API fingerprint fixed vectors | 独立实现按五个u64-BE frame重算§3.3三个hash；body key order/whitespace、raw percent spelling/query order或If-Match Generation任一改变都会冲突，Idempotency-Key/auth/cookie/request ID/User-Agent变化不改hash |
| API envelope/result exact replay | Idempotency-Key缺失、重复、空、非printable或超过512 bytes，以及wrong media type/non-identity encoding均在reservation前拒绝；hit不读resource并逐字节重放status/content-type/body，且route不依赖未保存的ETag/Location；response body超过1MiB则业务/result都不能commit；transport/commit unknown本身不结算失败row，最终只可能业务+result全有或全无 |
| Cat create closed request | 4095/4096/4097-byte边界、非canonical/percent-encoded path、`?x=1`/结尾裸`?`、wrong/duplicate media与encoding、任一If-Match、unknown/duplicate/missing/null字段、非canonical integer、name首尾/大小写/长度、旧image alias/disk/auto-suspend/expiry都在fast lookup前按合同拒绝；合法raw bytes匹配§3.3 Cat vector |
| DiskRecord identity/closed role | `volume_id`全局一对一；Root与Cat同Workspace且每Cat恰好一个，Persistent同时最多一个current CatRuntimeConfig；Root只含不可变cat ID，Persistent只含两态initialization且仅允许同lineage的一次Uninitialized→Initialized；`{disk}`只解析disk_id，name只能显式lookup；完成删除后row缺席 |
| Root create crash/重放 | Cat/cat_creation_id + CatRuntimeConfig + default Endpoint/binding/hostname lookup + Genesis Start Operation + generation-zero/unowned Root Disk/Volume + API result同一PG commit或全无；相同key只返回原operation ID且不生成第二identity；Root无Persistent initialization或第二Disk Operation |
| Root create fast lookup/竞态 | exact fast hit不执行placement/capacity；异fingerprint在resource前冲突；fast miss后另一session以同key先commit时，业务事务reservation+reread命中、丢弃整组candidate且零candidate row |
| Root create manifest/release/planner来源 | boot digest只读同digest immutable manifest，size按4MiB向上取整且覆盖manifest/不超1TiB；guest digest只来自验证过的release receipt；planner只选匹配digest的current session/fresh full inventory、无Active HostFenceEvent、post-assigned count最多1024的Node并返回exact network，任何缺失都不以fixture/default补齐 |
| Root create name并发 | 两个不同key同Workspace/name经CatNameLock只能一方提交202全套rows，另一方零业务row并提交fixed 409；原Cat后来删除后，409 key仍逐byte重放；unique violation不能充当409路径 |
| Root create candidate/corruption | 每类candidate ID/Endpoint/hostname/name碰撞、existing Cat cross-row corruption、serialization/connection failure均不写409/result或半rows；collision只用全新未使用bundle和重新编码的202重试 |
| Root create exact初态/时间 | config固定一个Root、default web HTTP:8080 route epoch1、placement epoch1、Genesis Start request；Volume仅接受Active+Unowned、epoch0、blank head、null owner/expiry/transition，Root normal acquire expected epoch0；Cat/Endpoint/Disk/Operation/result使用同一DB-now，Operation为unresolved；所有gate Closed，202/409 fixed vector由独立encoder逐byte重算 |
| Endpoint单一authority | EndpointRecord只保留immutable product identity/name；hostname lookup只定位current EndpointBinding；三者同txn且signer必须重读完整binding+Serving/effective RuntimeReady。改record/lookup/binding任一identity/epoch或制造hostname并发碰撞都fail closed，不采用旧binding |
| Persistent create crash/重放 | Disk + empty exact Volume + 201 result同一PG commit或全无；相同key只返回原201且无Operation，异fingerprint不读resource |
| initialization CAS/重放 | 锁current NodeIdentity、AgentSession与unresolved Start Operation/head后才锁Volume/Disk/config；signed request绑定Operation/fingerprint/placement、valid command checkpoint `commit_initialized`、Guest probe/flush、Owned attachment/epoch/head和active lineage，new head非空且generation>0、R==L；session replacement或command settlement先提交则旧evidence零副作用；exact tuple保留首次time且无第二ledger，Observation不参与 |
| normal acquire响应丢失/异payload | 相同RandomId128且完整request相同返回原result/absolute expiry；同ID异任一字段Stale，不使用domain request hash、不产生第二次fence |
| lease duration/DB time | 0、非canonical number、DB-now checked-add溢出均零副作用；acquire、renew与takeover都把该次唯一DB-now加duration所得值写为absolute expiry；expiry lapse仍不授予takeover/revoke |
| expired other owner | normal acquire始终OtherWriter；精确owner/epoch可继续renew |
| release响应丢失/异payload | 相同RandomId128且完整request相同返回原result；同ID异payload Stale，旧epoch永久不能publish |
| stale acquire晚到release之后 | expected epoch不匹配，不能重新占有volume |
| authorization单一authority | Node只传authorization ID；两类payload都含派生时immutable `authorized_node_id`且consume caller必须匹配；锁定row中的payload/receipt是唯一权威，receipt不重复Node ID，Volume last_transition仅ID marker；不存在客户端payload、第二签名或重复receipt副本 |
| signed command-scoped replay | current AgentSession、unresolved Operation/request fingerprint、Cat/Node/placement、command kind、transition identity与sorted targets逐字段相同才返回immutable ledger中的原receipt bytes；任一identity/payload不同fail closed，不接受任意authorization/volume/delete/successor查询key |
| authorization response-loss/current successor | takeover/disposable consume丢response只重放原command transition；后续合法renew/head-CAS/release/第二authorization不能改变已存receipt bytes。ledger、current marker、epoch/head或closed receipt任一不一致保持Blocked/Quarantined，不读取或枚举authorization history |
| authorization response-loss/delete completion | disposable consume或delete completion丢response后重放原command transition，exact ledger返回同一consumed/completion receipt；Volume/Disk已合法删除时仍不得从row absence猜成功，receipt缺失/错variant/错volume/delete/prior attachment/epoch/head均Blocked |
| retired transport absence/isolation | pre-cutover Runtime Volume Transitions DTO/codec/constants/spec与mutation/evidence parser均不存在；旧ContractName严格拒绝。先用current lifecycle-volume transition正例校准探针，再证明旧path/payload、wrong/retired Node、wrong Operation/session/fingerprint与额外query key均零domain write；Node无authorization/completion raw SQL credential |
| Host takeover | 只有精确逐卷授权成功；跨volume/placement/replay失败；receipt精确记录event/volume/new attachment/resulting epoch/head |
| consumed授权的后继 | direct takeover/disposable state缺失或写错对应authorization marker必须Blocked；更大epoch的takeover→release/restore/delete按closed状态机、epoch单调和head generation非倒退验证；delete→sweep以精确DeleteCompletionReceipt重连；缺失/错receipt保持Blocked，不复制中间链 |
| pure D / cross-row split | pure-domain table只输入Volume/Event/Authorization rows且可复用于SQLite fixture；唯一PG integration逐项改变Cold result、R==L、blockd stop、Operation/config、Disk、Snapshot、strong-Stop proof并断言同事务拒绝；不存在bool/VerifiedContext旁路 |
| acquire origin namespace | normal/takeover即使携带相同文本ID也不是同一lineage并进入quarantine；缺失/unknown variant和旧裸字段严格拒绝，不能猜namespace |
| 旧pending目录遇到新attachment | quarantine，remote Root不改变 |
| 相同lineage blockd crash | identity、全部pending pack、runtime evidence与当前grant的服务器端acquire marker逐字段绑定同一完整`AcquireOrigin`后，才从pack恢复L并按序publish；任一冲突quarantine |
| resize请求 | API不存在；`size_bytes` 在Volume/Root/Snapshot中始终一致 |
| normal acquire与begin-delete并发 | 两者锁同一VolumeRecord且只能一方提交；不存在Control Deleting但Volume仍可acquire的窗口 |
| Persistent绑定与delete并发 | attach/detach/delete锁同一Disk/Volume/current config；attach先提交则delete因current引用拒绝，delete先提交则attach因Deleting拒绝；delete不读取历史Cat，缺current complete inventory或任一residue时保持Active |
| Root normal begin authority | direct Root Disk DELETE拒绝；current Delete Operation在strong Stop与全部Persistent disposition完成后，Root R=L先exact release再normal BeginDelete，R<L只exact disposable authorization；Active HostFence下任何仍Owned状态只authorization；全部绑定Operation/fingerprint/placement/delete ID，Observation零authority |
| Root normal begin crash | Delete在release前/response unknown/Unowned begin/result publication各点crash都以原Operation/fingerprint/release/delete ID重放，不需要历史Desired/Observation/Cold payload |
| Root release/auth derive竞态 | 两个PG session都以VolumeRecord为branch gate并在锁后重验；release先提交使derive因Unowned全回滚，derive先提交使release看到同delete lineage auth而零副作用拒绝，不出现auth+Unowned |
| Root在release前失联 | last known即使`R == L`，Active HostFenceEvent+HostLost下仍Owned Root也可用exact Operation/owner/epoch/head authorization进入Deleting；不要求伪造`R < L`或等待不可达Node release |
| Disk delete 202/GET/replay | 首次begin事务原子写双方Deleting及exact 202 result且不建Operation；GET先见Deleting、completion后404，同key始终重放原202 |
| delete LIST/late PUT/crash | adapter contract suite用已成功PUT正样本判定stale-empty fake/adapter不合格；暂停一个已接受PUT时HostFence barrier不得返回且不能commit receipt，PUT成功可见或永久失败后才delete/re-list empty；多sweeper只有一个exact completion CAS，receipt后再次LIST仍empty；任一失败保留Deleting且不存job/claim/opaque bool |
| disposable Root `R < L` | common authorization逐字段绑定Delete Operation/fingerprint、Node/Cat/placement、Root attachment/epoch/head、discard disposition与Persistent completion；reachable arm另绑strong-Stop result/proof/session/inventory，HostFence arm只绑event/interrupted op/HostLost digest；固定event/auth/volume/control锁序，closed receipt与两边Deleting原子提交后才删lineage；PersistentDisk拒绝 |
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

pure domain矩阵可以同时跑PostgreSQL row adapter和SQLite fixture；Control cross-row、锁序、并发与crash矩阵
只由唯一PostgreSQL authority adapter覆盖。数据路径矩阵同时覆盖kernel-NBD与vhost-user-blk。模糊结果
测试必须先证明故障实际注入，不能用空日志作为通过证据。
