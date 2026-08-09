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
| Endpoint产品identity、所属Cat与管理名 | `EndpointRecord` |
| Endpoint当前hostname/protocol/port/route epoch binding | current完整`DesiredRuntimeSpec` |
| hostname到current Desired的定位 | `HostnameDesiredLookup`投影；不是binding authority |
| 当前 volume owner、fencing epoch、remote Root | MetadataStore |
| DiskSnapshot产品资源与GC live-root | DiskSnapshotRecord |
| 本规格覆盖的Workspace product mutation请求身份与不可变返回结果 | PostgreSQL `ApiIdempotencyResult` |
| 本地 pending pack、cache、blockd 进程是否存在 | Node 物理 inventory |
| ext4 UUID 和当前 mount 是否真实存在 | Guest Agent probe |
| Host 是否已被外部隔离、逐卷授权是否已消费 | PostgreSQL HostFenceEvent/Authorization rows |

Control Store 与 MetadataStore 是逻辑边界，不是两套提交authority。生产终态把`HostFenceEvent`、
由它派生的authorization、不可变消费回执和`VolumeRecord`放在同一PostgreSQL事务域；SQLite只作
pure-domain/data-row fixture，不提供Control cross-row authority。首次消费授权与`Active -> Rejoined`
都通过唯一PG事务域的固定锁序完成。

全局锁DAG是`ApiIdempotencyResult key reservation -> CatNameLock -> HostFenceEvent -> AuthorizationRecord ->
VolumeRecord -> Control Cat/Disk/Desired/Endpoint rows -> DiskSnapshotRecord`；事务跳过自己不涉及的节点，同类
多行按稳定ID排序。§3.3覆盖的Workspace product mutation先取得由认证Workspace、canonical route和`Idempotency-Key`导出的
PostgreSQL transaction-scoped reservation，再读结果；它不能先锁资源，也不落持久Pending。这样同一
key即使携带不同资源也不会分别先锁不同Volume。normal acquire只锁`VolumeRecord`，因此它与snapshot
mutation或begin-delete仍只能有一方先提交。HostFenceEvent来源的内部恢复没有API前缀，从event开始。
`CatNameLock`不是row或authority；只有会插入新Cat identity的create事务使用它，并固定在API key之后、
任何Volume/Cat/Disk row或candidate-ID lock之前取得。删除已有Cat由被锁定的existing Cat row与唯一索引
线性化，不取得name lock，因此§1的Cat Destroy锁序没有反向边。

Persistent initialization CAS没有API/event前缀，固定锁序是`current AgentSession row -> 该session的
highest accepted-observation receive-state -> VolumeRecord -> DiskRecord -> current Desired -> immutable
accepted observation payload`。session replacement和observation acceptance也必须先锁同一AgentSession/
receive-state，任何事务都不得先锁Volume再反向取得它们；因此旧session检查与Initialized commit之间没有
ABA窗口。

covered Cat Destroy的Cold fast path使用`ApiIdempotencyResult key -> current AgentSession/highest
accepted receive-state + immutable Cold observation -> VolumeRecord -> Disk/Cat/current Cold Desired及其
Operation -> DiskSnapshotRecord`。它不保留前一revision/evidence的新历史authority；所有判断与下述Root
normal begin都在持锁的current rows上完成。

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
- `transition_id: RandomId128`：只用于normal acquire和release；同一次重试必须复用，其他操作不得复用。
- `authorization_id: Id`：takeover或disposable delete授权row的稳定主键。
- `delete_id: Id`：一次Disk/Volume删除的稳定身份。
- `desired_revision`、`placement_epoch`：来自 Runtime Reconciliation 合同。
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
  created_at: UnixMillis
}

EndpointRecord {
  endpoint_id: Id,
  workspace_id: Id,
  cat_id: Id,
  name: Id,
  created_at: UnixMillis
}

HostnameDesiredLookup {
  hostname: Hostname,
  workspace_id: Id,
  cat_id: Id,
  endpoint_id: Id,
  desired_revision: Revision
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

`RemoteHead`只有两种合法形态：`generation == 0`当且仅当`root_hash`和`root_object_id`都为`null`；
`generation > 0`当且仅当两者都非`null`。Root hash、object ID和generation始终作为一个不可拆分tuple
比较、保存和复制；任何result或receipt写“exact head”都复用这三个字段，不能只比较其中一部分。
本文的“head generation非倒退”固定表示：更小generation拒绝；相同generation时hash和object ID也必须
逐字段相同；只有更大generation才进入对应的数据面CAS或closed successor验证。

`CatRecord`只保存产品identity：四个字段创建后都不可修改，`(workspace_id, name)`唯一。它不复制
`root_disk_id`、Desired/Observed state、generation、Node/placement、runtime shape或transition；这些事实分别
只由`DiskRecord.role.root {cat_id}`、current完整`DesiredRuntimeSpec`、accepted observation和`Operation`
回答。每个Cat恰好一个Root的交叉约束仍按下段锁定Disk/current Desired验证，不能向Cat row增加缓存字段作为
第二个关系权威。Cat create的初始target也只由同事务的Desired/Operation携带，`CatRecord`不另存或选择target。

`EndpointRecord`的五个字段创建后都不可修改，`endpoint_id`全局唯一、`(cat_id, name)`唯一；workspace/cat
必须逐字段指向同一合法Cat。它只保存产品identity和管理名，不复制hostname、protocol、port、route epoch、
placement或wake状态。`HostnameDesiredLookup.hostname`全局唯一，并且只定位
`workspace_id/cat_id/endpoint_id/desired_revision`；signer必须在同一snapshot重读该revision的current完整
Desired并逐字段闭合Endpoint binding，不能单独把lookup当作签发authority。创建或改变Endpoint的事务必须
原子写完整Desired与对应lookup；任何提交仍包含该Endpoint的新current完整Desired revision的事务也必须把
lookup推进到同一revision，移除Endpoint则在同一事务删除旧lookup。任一不等是store invariant failure并
fail closed。

`DiskRecord`的disk/workspace/name/volume identity、size、durability和created_at创建后不可修改，且
size/durability必须与同一`VolumeRecord`逐字段相同。`DiskRecord.volume_id`全局唯一：产品Disk与Volume
严格一对一，任意两个Disk row不得引用同一Volume。`(workspace_id, name)`唯一。`DiskRole.kind`和
Root的`cat_id`不可修改；Persistent role唯一允许的变化是保留同一token/UUID/blank head，从
Uninitialized一次性变为Initialized。Root只保存`root {cat_id}`，没有假的NotApplicable initialization字段；
Persistent只保存上述两态initialization。Available/Bound不是
Disk row状态：Root的Cat必须与Disk属于同一Workspace，每个Cat恰好一个Root，且该Root只能出现在该Cat的
current完整`DesiredRuntimeSpec`；Persistent绑定只从全部current完整Desired的VolumeIntent集合推导，任一
PersistentDisk同时最多被一个current Desired引用。attach、detach、move和delete mutation都按全局锁序锁定
同一Disk/Volume及涉及的current Desired rows；并发绑定只能一方提交，不能靠先读后写绕过RWO唯一性。
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
精确重放和Host rejoin验证；保留规则见§4.5与§11.3。

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
Desired、Disk、Snapshot、Node observation或物理进程，也不接受`verified=true`、proof boolean、opaque
`VerifiedContext`之类可绕过检查的参数。

唯一的PostgreSQL事务owner按§1固定锁序逐字段验证所有跨row前置，再调用pure domain函数并在同一commit写入
它的结果及相关Control rows。Cold、`R == L`、blockd stopped、当前Desired/revision/placement、Disk kind/
ownership/state、`DiskSnapshotRecord`为空、RuntimeStopped observation和provider fence事实都属于这一层；
每项必须从本事务锁定的权威row读取，不能先算成bool或由调用者声称。SQLite只可复用pure domain函数作为
窄数据面/单row fixture；它不实现或模拟Control cross-row事务，也不形成第二个authority。

测试责任也分两层：pure domain table tests穷举每个Volume/Event/Authorization当前状态、exact replay、
同ID异payload、epoch与RemoteHead边界；唯一PostgreSQL Control adapter的integration tests逐项改变跨row字段并
覆盖固定锁序、并发提交与每个crash点。SQLite可复用前一层，但domain fixture中的伪上下文不能替代PG验收。

### 3.3 Workspace product API idempotency

本节只覆盖同时满足两项的HTTP mutation：资源归属一个已认证Workspace；业务rows和最终result能在唯一
Control PostgreSQL事务中原子commit。当前闭集是Cat/Desired、Endpoint、Disk和DiskSnapshot等
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
  desired_revision: Revision,
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
7. 同一 attachment 但不同 transition 也不隐式采用；reconciler 必须使用原 transition 或明确
   quarantine。

Node 在调用前把 request 写入 RuntimeCheckpoint。响应不明确时读取 VolumeRecord：只有
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
  expected_epoch: FenceEpoch
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

普通 reconcile 不存在 revoke。takeover 只接受逐卷授权：

```text
VolumeTakeoverAuthorization {
  kind: "takeover",
  authorization_id: Id,
  host_fence_event_id: Id,
  volume_id: Id,
  expected_attachment_id: Id,
  expected_epoch: FenceEpoch,
  new_attachment_id: Id,
  desired_revision: Revision,
  new_placement_epoch: Epoch,
  lease_duration_ms: integer 1..=9223372036854775807,
  not_after: UnixMillis
}
```

Node只提交`authorization_id`，不提交或签名上述payload。首次消费使用固定锁序
`HostFenceEvent -> AuthorizationRecord -> VolumeRecord`，在一个PostgreSQL事务中读服务器端immutable
authorization，同时验证event仍为Active、authorization仍为Unconsumed、本事务`db_now <= not_after`、
旧attachment/epoch和目标identity精确匹配，并对`db_now + lease_duration_ms`checked-add。随后设置新owner、
增加epoch、保持exact head，写absolute expiry和`last_transition.takeover {authorization_id}` marker，并原子把authorization改为
`Consumed(TakeoverConsumedReceipt)`；receipt的`consumed_at`就是该次`db_now`，所以original expiry唯一等于
`checked_add(consumed_at, authorization.lease_duration_ms)`。

相同授权重试只读取不可变receipt并返回原grant，即使event已经Rejoined也不再次修改VolumeRecord。
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
2. Consumed授权的closed receipt variant和全部字段必须与服务器端authorization逐字段匹配。
   `TakeoverConsumedReceipt`的direct state是Active、owner为`new_attachment_id`、epoch为
   `resulting_epoch`，且`last_transition`必须精确为`takeover {authorization_id}`；同epoch下只允许该owner
   按数据面CAS发布出的generation非倒退head或renew expiry。更大epoch的当前状态或completion必须位于
   §3.1、§8和§11的closed successor closure，精确绑定同一volume，epoch单调且head generation不倒退；
   当前`last_transition`非null时必须逐字段匹配其request/result或authorization marker，null只可由§10.3
   same-disk restore的immutable API result及当前exact postcondition证明。这里不复制中间链，只凭数字更大
   不能通过。
3. `BeginDisposableDeleteConsumedReceipt`的direct state要求Volume owner/expiry为null、Volume和Control
   Disk都精确为receipt中的同一Deleting(delete ID)、epoch/head相同，且Volume `last_transition`精确为
   `begin_disposable_delete {authorization_id}`。Deleting没有另一个可写后继。
4. 若Volume/Disk rows已删除，必须存在§11.3的精确`DeleteCompletionReceipt`。对disposable consume，
   `kind="disposable_root"`的authorization/prior attachment必须匹配同一receipt；对takeover后继，completion的normal
   exact `BeginDeleteRequest`或另一个已验证的disposable authorization必须构成closed state machine后继。receipt缺失、
   head/generation/epoch倒退、只比较delete ID或任何identity冲突都保持Blocked。

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
5. 启动 blockd，传入 volume、attachment、epoch 和既有的closed acquire origin。
6. blockd 从 MetadataStore 验证精确 owner/epoch后开始 renew和服务。

blockd 启动不得调用 acquire、takeover或增加 epoch。它只可以 renew、以精确 owner/epoch发布 Root，
以及报告 status。Cold detach 时 Node 先 drain、停止 blockd，再执行 release。

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

- PersistentDisk 加入或离开 Cat 的磁盘集合，只能在 Cat 已稳定 Cold 时提交。
- Cold -> Running 使用完整、排序且无重复的 VolumeIntent 集合一次启动。
- Running 中请求改变磁盘集合返回前置条件错误；调用方先将 Cat 变为 Cold。
- RootDisk 始终随 Cat；PersistentDisk 可在不同 Cat 的 Cold 状态之间移动。

这条限制消除了 Guest 重新 mount、打开文件句柄、VMM hotplug 和 blockd drain 之间的竞态。未来若
确有产品需要，hotplug 必须单独设计并验证，不能放宽本合同的 Cold 前置条件。

## 8. ext4 初始化与 mount readiness

### 8.1 Disk create

mutation path中的Disk引用遵守§3的immutable `disk_id`规则；create response可以展示name，但后续资源path
不以name代替ID。

**Public Cat create request到完整candidate。** 唯一route是
`POST /v1/workspaces/{workspace}/cats`，canonical route template逐byte同该string。它的HTTP envelope固定为：

- transfer framing移除后的完整raw body最多4096 bytes；恰好4096合法，读到第4097 byte即可停止并拒绝，
  不得先分配或解析无界body；
- 恰好一个`Content-Type` field，field-value逐byte等于`application/json`；`Content-Encoding`只能缺席或
  恰好一个逐byte等于`identity`的field；
- `If-Match`必须完全缺席，任一occurrence都在fingerprint/fast lookup前拒绝；因此§3.3 fingerprint的
  `if_match_payload`恒为单byte `0x00`；
- raw path bytes必须精确等于`/v1/workspaces/<path中canonical workspace_id>/cats`，不接受percent-encoded
  等价写法；query component必须缺席，`?x=1`和结尾裸`?`都在fingerprint/fast lookup前拒绝；
- 必须携带§3.3的exact `Idempotency-Key`。fingerprint保留server收到的raw path/query和raw body bytes，
  不把JSON重编码后再hash。

body必须是无BOM的UTF-8 JSON object，并按上面的`CatCreateRequest`闭合：六个字段全部必填，unknown字段、
duplicate key、null、错误JSON kind和尾随非空白bytes都拒绝；integer沿用Runtime §1.1的canonical raw number
token和范围。`name`进一步收窄为1..=30 ASCII bytes，只允许`[a-z0-9-]`且首尾必须是`[a-z0-9]`；不trim、
不lowercase、不做Unicode或DNS归一化。六个字段都没有隐式default。旧create-time `image` alias、额外`disk`、
`auto_suspend`、`expires_at`及其optional/null形态都不是本route字段；磁盘成员、自动休眠和过期策略是后续
独立mutation/policy，不能偷偷进入首个Desired。

envelope/DTO、身份、当前Workspace membership和route permission通过后，按§3.3计算fingerprint并执行不查
resource的fast lookup。exact hit逐byte重放且不得读取image、release receipt、placement或capacity；conflict
也在这些读取前返回。只有fast miss才按以下唯一来源构造candidate：

1. `boot_image_digest`直接寻址ADR-0017的
   `images/<boot_image_digest去掉sha256:后的64位hex>/manifest.json`。service按
   [blockd §6.3.1](blockd-protocol.md#631-root-provision-control-effect)完整验证immutable manifest；不解析image
   alias/tag，也不查询catalog。Root实际`size_bytes = ceil(root_size_bytes / CHUNK_SIZE) * CHUNK_SIZE`，其中
   `CHUNK_SIZE=4194304`；结果必须不小于manifest `size_bytes`且不大于`MAX_VOLUME_BYTES=1099511627776`。
   manifest缺失/暂不可读、非法或size不满足时不生成可提交candidate，不以fixture manifest继续。
2. `guest_config_digest`只取Control Plane启动时已验证的唯一
   [GuestRuntimeProfileReceipt](runtime-reconciliation-v1.md#2-可信-node-与-agentsession) digest；请求、image
   manifest和builder都不能提供或重算另一个值。生产service构造器要求显式release receipt，不能使用测试
   fixture digest、编译期示例常量或空值fallback。
3. placement planner只从当前provisioned/schedulable Node的current未失效`AgentSession`、fresh full
   `AdmissionInventoryAttestation`及现有Node/placement事实中选择；session的`guest_config_digest`必须等于
   上一步active release digest。调用时service把本批candidate `network_id`交给planner；planner为本次
   candidate返回一个`node_id`和完整合法`NetworkConfig`；service
   用该node构造`AssignedPlacement {kind:"assigned", node_id:planner node_id, placement_epoch:1}`，
   NetworkConfig的`network_id`逐字段
   等于本批candidate network ID，地址/MAC满足Runtime §3。
   具体Node排序、capacity估算和地址选择算法不属于共享合同；planner结果只是可失效的pre-transaction plan，
   不创建capacity reservation、network lease、scheduler row或第二authority。无可选Node/config时不创建
   Desired/Operation。commit后Node/capacity/address事实变化由既有
   `PlacementRejected(insufficient_vcpus|insufficient_memory|unsupported_block_path|unsupported_network|
   unsupported_guest_capability)`
   终结revision 1；任何重新选择都创建placement epoch更大的新系统revision，不能原地改candidate。

public API/service在调用Store前一次生成整批独立、非全零`RandomId128`，并固定编码为
`cat_<random>`、`disk_<random>`、`vol_<random>`、`att_<random>`、`vint_<random>`、`op_<random>`、
`ep_<random>`和`net_<random>`；normal acquire的`transition_id`使用另一裸`RandomId128`。这些分别是
Cat、Root Disk、Volume、attachment、volume intent、Operation、default Endpoint和network identity。
同一candidate或任何重试不得重抽其中单个ID；任一identity/hostname碰撞或candidate事务回滚都丢弃整批，
下一次只使用全新整批。planner一旦返回NetworkConfig，该network ID/MAC/IPv4/prefix/gateway也作为一个
不可拆分binding固定；要改变任一字段就丢弃整批并以新network ID重plan，不能在同ID下换地址。
Endpoint opaque suffix精确取`endpoint_id`去掉`ep_`后的32位lowercase hex，default
hostname固定为`<request.name>-<suffix>.cats.run`；name上限保证该DNS label最长恰好63 bytes。

fast miss后的唯一构造顺序固定为：先完成上面的immutable manifest与active release receipt验证；再一次生成
上述整批ID；随后以请求shape和本批`network_id`调用planner；只在exact NetworkConfig返回后构造并验证完整
Desired、计算`spec_digest`及全部cross-row binding；然后用同批`cat_id/operation_id`编码exact 202并准备固定
409 envelope；最后才调用Store。planner拒绝、candidate/encoder验证失败或已知事务回滚都丢弃整批，不能保留
某个ID、NetworkConfig或已编码202供下一批复用；commit/result不明只按§3.3重放权威查询，不能盲目重建。

由上述事实构造的唯一初始`DesiredRuntimeSpec`是：

- `version=1`、请求path中的`workspace_id`、candidate `cat_id`、`desired_revision=1`、`target="running"`、
  planner node上的`placement_epoch=1`、`transition={kind:"cancel_and_drain"}`；
- runtime的`vcpus/memory_bytes/boot_image_digest`逐字段来自request，`guest_config_digest`来自active release
  receipt，`network_config`逐字段来自planner；
- `volumes`恰好一个Root intent：使用candidate intent/disk/volume/attachment ID和上面的rounded size，
  `disk_kind="root"`、`access="read_write_once"`、request durability、
  `guest_device={serial:"cats-root",slot:0}`、
  `acquire={kind:"normal",transition_id:candidate transition_id,expected_unowned_epoch:0}`、
  `disposition={kind:"retain"}`、`mount=null`；
- `endpoints`恰好一个default binding：candidate `endpoint_id`、上述hostname、`route_epoch=1`、
  `protocol="http"`、`target_port=8080`；产品管理名`web`不复制进Runtime `EndpointIntent`，
  `wake_on_request`是ADR-0010固定行为而不是第二份可变binding；
- 最后按Runtime §16对除`spec_digest`外的完整字段计算唯一`spec_digest`。builder不能从测试Desired、Store
  default或旧Cat row复制任何缺失字段。

同一candidate还包含`CatRecord`、Root `DiskRecord/VolumeRecord`、
`EndpointRecord {endpoint_id, workspace_id, cat_id, name:"web", created_at:待注入}`、与上述hostname/Desired
revision逐字段相同的`HostnameDesiredLookup`、绑定该Desired的Pending Operation及exact 202 envelope。
Store接收的是这份完整candidate；它只验证closed schema、全部交叉绑定和digest，不接受public request、image
alias、planner callback或任意default参数来补全它。

**RootDisk随Cat create。** auth/membership/route permission通过后，API先做一次不查resource的只读result
fast lookup；hit直接重放，miss只是一条可失效的优化提示，不创建reservation或Pending。只有fast miss才完成
placement/capacity等当前状态准备，并由public API/service边界在进入Store前一次性生成全部candidate identity、形成包含
完整Desired及所有非时间业务字段的已验证bundle，并用同一批candidate通过canonical response encoder编码成功response；candidate尚未提交时不对外
可见且永不复用。result miss后的唯一PG事务首次持久化这些identity，并原子写入Cat、current完整
Desired、default `EndpointRecord`及hostname lookup、绑定该revision的runtime Operation、
`root {cat_id}` Disk、generation-zero且Unowned的Root Volume，以及包含原operation ID的exact
`ApiIdempotencyResult`。Cat、Endpoint、Disk和Desired的Workspace/Cat identity逐字段相同，
Desired恰好引用这一个Root Disk/Volume。全部rows/result同一commit或全部不存在；commit/response不明后
同key只重放原status/body/operation ID，不生成第二个Cat、Endpoint、network、Disk、Volume、Desired或Operation。
初始Volume精确为`admin_state=Active`、`lease_epoch=0`、owner/expiry/last_transition均为null、head精确为
`{generation:0, root_hash:null, root_object_id:null}`。Desired中唯一Root intent使用normal acquire且
`expected_unowned_epoch=0`；任何非零epoch、非blank head、已有owner/transition或takeover acquire都拒绝整个bundle。
candidate集合一次性包含`cat_id`、Root `disk_id/volume_id`、`attachment_id`、`volume_intent_id`、normal-acquire
`transition_id`、`operation_id`、`endpoint_id`、`network_id`以及完整Desired中出现的全部`Id/RandomId128`；
Cat/Endpoint/Root/Volume全部非时间字段也在同一bundle内。Store逐字段验证Workspace、Root role、
size/durability、Endpoint/hostname lookup、Desired volume/operation binding与spec digest，不接收
`placement_ok`、`capacity_ok`或其他验证bool。placement/capacity结果允许在commit后变旧，
按Runtime §3.3既有`PlacementRejected -> new revision`闭环处理，不新增capacity reservation authority。
Root不携带Persistent initialization状态，也不创建第二个Disk Operation。事务只读取一次PostgreSQL DB now，
并把同一毫秒值写入`CatRecord.created_at`、`EndpointRecord.created_at`、`DiskRecord.created_at`、
Operation的created/updated time和
`ApiIdempotencyResult.created_at`；重放不刷新任何时间。

Cat create调用边界同时携带两个非持久、由public API层预先编码的exact HTTP envelope：成功response和
`(workspace_id, name)`已存在时的`409 application/json` name-conflict response。Control Store只验证status、
content type和body cap并在锁定事实后选择其一，不拼装、解析或重新序列化HTTP body。result miss下名称可用时，
上述业务rows与成功result同一commit；名称已被另一个合法Cat占用时，零业务row变化并只把调用方提供的409
response与同一次DB now原子写入`ApiIdempotencyResult`。因此该key以后始终重放原409，即使原Cat随后删除。
成功response只使用同一bundle中的candidate identity和请求内已有字段，不包含`created_at`或其他必须等事务
DB now/数据库生成值才能编码的字段；其operation ID必须逐字段等于待持久化Operation。result hit发生在任何
candidate资源锁前，Store直接丢弃本次bundle/envelope并逐字节返回旧result。
该事务必须重新取得key reservation并重新读取result；fast lookup与业务事务之间若另一请求先提交，仍以事务
内hit为准。fast lookup不是第二authority，也不能让调用方跳过事务内重检。
事务内result miss后立即取得`CatNameLock(workspace_id, name)`；V1 PostgreSQL实现固定执行
`pg_advisory_xact_lock(hashtextextended(current_schema() || ':cat-name:' || $1 || ':' || $2,
0::BIGINT))`，其中`$1=workspace_id`、`$2=name`。
`Id`中的冒号或64-bit hash碰撞最多让不同名称额外串行，不会让相同tuple得到不同lock。持锁后读取并验证
`CatRecord`：合法existing row选择409；absent才继续
Volume→Cat→Disk→Desired→EndpointRecord/hostname lookup→Operation锁/插入；corrupt row
返回BackendUnknown。唯一约束只作invariant backstop，意外constraint error整体回滚，不能事后翻译成409。
首次持久化的Operation固定为`phase=Pending, terminal=null`，其workspace/cat/revision/spec digest/placement/
target从同一完整Desired和candidate operation ID构造；`created_at_unix_ms=updated_at_unix_ms`都由上述单次
DB now注入。调用边界不携带一个带伪时间的“完整Operation row”，Store也不选择placement或重算spec。
Root `DiskRecord.name`固定逐字节等于candidate `disk_id`，不从用户Cat name派生，也不增加第二种用户可观察
name-conflict。若该server-generated disk ID/name意外碰撞既有Disk，则与其他candidate identity碰撞相同，
整体回滚并用从未使用的新candidate bundle重试。
`EndpointRecord.endpoint_id`、`(cat_id,"web")`和lookup hostname使用数据库unique约束作并发/invariant
backstop；候选endpoint/hostname与不属于同一candidate的现有row碰撞时整体回滚并换全新bundle，不能改suffix、
采用existing Endpoint或写Cat name 409。
server生成的cat/endpoint/network/disk/volume/operation ID/name碰撞、stored row损坏和数据库/serialization失败不是name conflict，
不得写409 result；事务回滚后按其既有infrastructure/invariant规则处理。

两个route response使用UTF-8、无BOM/空白/newline且按下列字段序编码；这是public API encoder fixed vector，
不属于Runtime §16的wire或digest：

| outcome | status/content-type | exact body bytes | bytes | SHA-256 |
|---|---|---|---:|---|
| accepted | `202 application/json` | `{"cat_id":"cat_01","operation_id":"op_01"}` | 42 | `9ff23d30170e1a81a16e5cdc847c79af292a48b2da3ce2764749320b8826bfda` |
| name exists | `409 application/json` | `{"code":"already_exists","message":"cat name already exists"}` | 61 | `38f397c0f602012a22d578aec019b53c40b42e5e01611e1264be45fac3eb421e` |

实际accepted body逐字节替换示例中的两个`Id`；name-conflict body恒定，不带动态name、request ID或时间。

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
ledger。

### 8.2 Initialization CAS

首次 Cold -> Running 在 route admission 打开前执行：

1. 取得精确 LeaseGrant，确认 MetadataStore head仍等于 blank predecessor。
2. checkpoint 写 `FormatStarted(token, attachment, epoch, blank_head)` 并 fsync。
3. Guest Agent按稳定virtio device identity probe。看到期望UUID就采用；确认全盘blank且没有部分
   格式痕迹时，按同一token执行`mkfs.ext4 -U <filesystem_uuid>`；其他UUID或部分格式直接
   quarantine。
4. RPC模糊或Agent crash后重新probe。期望UUID继续采用；仍严格blank可用同一token重试；任何
   其他结果quarantine。`Initialized`之后永不进入mkfs路径。
5. 磁盘尚未 mount，没有业务写入。Guest Agent执行设备 flush，Node要求 blockd drain到
   `R == L`，并记录新的exact RemoteHead。
6. `commit_initialized` step只能在Guest probe再次读到Desired的exact UUID、device flush完成且Node已观察
   `R == L`后写入valid checkpoint；错UUID或模糊probe不能进入该step。step中的`new_remote_head`必须是
   generation严格大于blank generation 0的合法非空`RemoteHead`。
7. Control Store不接受调用方bool或新proof DTO，只复用已经由current AgentSession接受并完整保存的
   `NodeObservation` row。它按§1的
   `current AgentSession -> highest accepted-observation receive-state -> VolumeRecord -> DiskRecord ->
   current Desired -> immutable accepted observation payload`顺序在一个PG事务锁定并逐字段重验：
   receive-state仍精确指向该session binding、heartbeat sequence和observation ID，且immutable payload就是
   被引用row；该Cat的applied revision/
   placement匹配Desired；`ObservedRuntimeStatus.step`与valid checkpoint的step相同且精确为
   `commit_initialized {volume_id, initialization_token, expected_blank_head, new_remote_head}`；同一`ObservedVolume`绑定该Disk/
   Volume，authority为当前attachment/epoch拥有的exact new head，并有同attachment/epoch/placement的
   active、非fenced lineage满足
   `local_durable_generation == remote_durable_generation == head.generation`。事务中的
   Volume还必须为Active+Owned的同一attachment/epoch/head，Persistent role仍是同一Uninitialized
   token/UUID/blank head，Disk/Volume/Desired的size/durability及Desired initialize tuple全部一致。
   通过后以本事务DB now原子改为
   `Initialized {same token, uuid, blank head, initialized_head, initialized_at}`。
8. Guest Agent mount并回报 device identity、UUID、mount path、read/write状态。只有全部匹配后
   Running 才 Ready并打开 route admission。

初始化阶段即使是 Relaxed volume也必须先达到 `R == L`。否则 Host 丢失后 Control Store 会记得
UUID，而远端盘仍是空白。第6步响应不明时，已是Initialized且token、UUID、blank head和initialized head
全部相同就返回原`initialized_at`且不改row；旧session/attachment/epoch、错UUID/head、`R != L`、任一字段
不同、单边状态或不匹配evidence都fail closed并保留现状。没有另一条initialization transition记录。

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
Cat/Desired -> DiskSnapshotRecord`锁序重验认证Workspace拥有Disk、Disk/volume绑定及各操作前置，并在
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

首次事务重验产品Disk仍为Active、属于认证Workspace、所属Cat处于精确stable Cold，且
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

- Root不接受直接Root Disk DELETE API，只能由已有Cat lifecycle Operation驱动；同一个server分配的
  `delete_id`必须同时进入Deleted Desired的exact Root
  `delete_disposable_root` disposition和`BeginDeleteRequest`。只有两条current-only normal路径：
  - **Cold fast path**：covered Cat Destroy事务按§1锁定current session/receive-state、immutable complete
    stable-Cold observation、Root Volume、Disk/Cat、current Cold Desired/settled Operation和snapshots，逐字段
    证明同placement、同Root disk/volume/attachment/size/durability、无runtime/blockd、`R == L`且Active +
    Unowned。随后同一commit写新current Deleted Desired、绑定它的Pending Cat Operation、双方
    `Deleting(delete_id)`/normal BeginDelete direct result及API result；全有或全无。
  - **Deleted converge path**：若Cat Destroy已只提交current Deleted Desired/Operation，normal begin事务先锁
    current AgentSession/highest receive-state及其immutable current-revision observation，再锁Volume/Disk/Cat/
    Desired/Operation/snapshots。observation必须应用该exact Deleted revision/placement并证明Root已经
    `R == L`、Active + Unowned且没有runtime/blockd/residue；Operation与Root intent/disposition/delete ID仍
    逐字段相同。它不读取前一Desired或旧Cold observation。
  仍Owned时不能normal begin：`R == L`由Node用同一Deleted disposition/delete ID做
  [Runtime §7](runtime-reconciliation-v1.md#7-reconcile-与物理-effect) exact cleanup/release，
  接受新的current observation后再走第二条；可达Host的`R < L`只走§11.2 authorization，Active
  HostFenceEvent下任何仍Owned状态也只走authorization，即使最后已知`R == L`或L未知。live Cold direct
  delete、旧revision/observation、错delete ID、别的Cat或仅凭Disk未绑定都必须拒绝。

Root cleanup/release与authorization derive以现有`VolumeRecord`作为分支gate，不增加row。derive事务创建
authorization后必须取得Volume锁并fresh重验current Deleted exact lineage及Active + Owned才能commit；
release取得Volume锁后必须fresh读取同一delete ID/revision的authorization，任一已commit就拒绝，并重验
current Deleted。release先commit时derive随后看到Unowned并整笔回滚；derive先commit时release看到auth并
零副作用拒绝。不能在锁前缓存“无authorization”后越过这个重验。
- Persistent不读取或保存“历史上属于哪个Cat”。它要求全部current完整Desired都不引用该Disk，且current
  accepted complete inventory对相关物理identity证明不存在该volume的blockd、active lineage、device、mount
  或其他residue；任一缺失/旧inventory都拒绝。

attach/detach/move与begin-delete均锁同一VolumeRecord、DiskRecord和涉及的current Desired rows；attach先提交
则delete看到绑定而拒绝，delete先提交则attach看到Deleting而拒绝，不存在已删除Disk被并发重新绑定的窗口。

```text
BeginDeleteRequest {
  delete_id: Id,
  disk_id: Id,
  volume_id: Id,
  expected_unowned_epoch: FenceEpoch,
  expected_head: RemoteHead
}

BeginDeleteResult {
  delete_id: Id,
  disk_id: Id,
  volume_id: Id,
  resulting_epoch: FenceEpoch,
  resulting_head: RemoteHead
}
```

`BeginDeleteRequest`按`VolumeRecord -> Control Disk/Cat/Desired rows -> DiskSnapshotRecord rows`锁序，
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
  delete_id: Id,
  disk_id: Id,
  volume_id: Id,
  cat_id: Id,
  desired_revision: Revision,
  placement_epoch: Epoch,
  expected_attachment_id: Id,
  expected_epoch: FenceEpoch,
  expected_head: RemoteHead,
  isolation_basis: DisposableDeleteIsolationBasis,
  not_after: UnixMillis
}

DisposableDeleteIsolationBasis =
  {
    kind: "runtime_stopped",
    node_id: Id,
    agent_session_epoch: Epoch,
    runtime_incarnation: RandomId128,
    observation_id: RandomId128
  }
| { kind: "host_fence_event", event_id: Id }
```

Control Plane 只为当前 `Deleted` Desired 中明确标为 disposable 的 RootDisk建立授权。可达 Host 必须
先关闭admission、停止Guest/VMM和blockd，并提交精确stop observation，且只有`R < L`才走授权；`R == L`
必须先走上述normal release。失联Host必须已有Active HostFenceEvent；此时任何仍Owned的exact Root都可授权，
不要求或伪造`R < L`，包括最后observation为`R == L`、L未知或没有最后observation。授权绑定current
revision/placement、delete ID、remote head和最后owner/epoch，不能
跨Disk、Cat、卷、attachment或重试身份复用。唯一Control Store writer在锁定这些权威row的同一
PostgreSQL事务中写完整immutable authorization；不增加第二套签名，Node消费时只提交`authorization_id`。

HostFenceEvent来源的首次消费使用固定锁序
`HostFenceEvent -> AuthorizationRecord -> VolumeRecord -> Control Disk/Desired/DiskSnapshotRecord rows`；
RuntimeStopped来源使用相同后缀而没有event行。一个PostgreSQL事务读取服务器端authorization row，重验
event或stop observation、authorization完整tuple、Control Disk仍为Active、当前Deleted Desired仍把该Root标为disposable，
并确认没有live `DiskSnapshotRecord`，然后原子执行：

- `VolumeRecord Active + Owned(expected owner/epoch) -> Deleting(delete_id, owner cleared, epoch + 1)`；
- `Control Disk Active -> Deleting(delete_id)`；
- authorization `Unconsumed -> Consumed(BeginDisposableDeleteConsumedReceipt)`；
- Volume只写`last_transition.begin_disposable_delete {authorization_id}` marker，不复制authorization或receipt。

receipt逐字段绑定authorization、prior attachment、未改变的exact head和
`resulting_epoch = expected_epoch + 1`。该variant固定表示Volume owner/expiry已清空、Volume和Control Disk
都已进入同一`Deleting(authorization.delete_id)` direct state；不在receipt镜像state对象或另存bool proof。

相同授权重试只读取receipt；snapshot record仍存活时返回`SnapshotInUse`且三边都不改变，其他字段变化、
过期或非Root/disposable请求返回`InvalidAuthorization`。事务成功前不得删除pending data；成功后旧
epoch永久不能publish，Node才可删除授权所指lineage的`R < L` tail。这里不经过会产生可抢占窗口的
`Active + Unowned`，也不能扩展到PersistentDisk。被授权lineage可能有`R < L`tail，也可能因Host在
`R == L`后、release前失联而没有未发布tail；两者使用同一exact owner/epoch/head安全边界。

HostFenceEvent路径上的本地lineage在旧Host rejoin时进入quarantine；删除授权记录至少保留到该
event转为Rejoined，使rejoin仍能核对所有派生结果。

### 11.3 共同清理

1. sweeper只按稳定ID分页扫描Control Disk/Volume双方同一`Deleting(delete_id)`的level-triggered状态；
   不创建job、claim、lease或第二个Operation。§11.1 begin已证明blockd stopped、精确release和`R == L`；
   §11.2 begin已消费stop/HostFence授权并fence旧epoch。Deleting禁止进入新Desired或normal acquire，
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

Host rejoin在rows已删除时，必须把Consumed authorization逐字段匹配receipt：disposable路径要求
`DeleteCompletionReceipt.disposable_root`的authorization ID和prior attachment等于同一
`BeginDisposableDeleteConsumedReceipt`。对更早的takeover receipt，completion必须是同volume、
deleting epoch严格更大、head generation非倒退，并且closed begin variant本身可由normal exact request或
另一个已验证的disposable authorization唯一解释；不复制中间Release链。仅有更大的数字、相同delete ID或
目录缺席都不够。

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
2. 一次替换pure domain/MetadataStore schema、trait和唯一PostgreSQL authority adapter；SQLite只复用窄
   data-domain fixture。HostFenceEvent、`AuthorizationConsumedReceipt`、VolumeRecord与Rejoined使用同一
   PG事务域和固定锁序。
3. 一次替换 pack header、data-dir identity、blockd启动参数和status；删除旧 pack parser。
4. 接入 RuntimeCheckpoint、VolumeIntent/Observation和Node lease executor。
5. 接入 Guest Agent probe/format/mount和Cold-only API前置条件。
6. 实现唯一byte-level fingerprint与§3.3 scoped `ApiIdempotencyResult`、exact `DiskRecord`、单一
   `DiskSnapshotRecord`、Persistent create/initialization CAS、snapshot-aware GC、same-disk restore、
   Control/Volume原子begin-delete和level-triggered fail-closed sweeper。
7. 接入 HostFenceEvent/takeover与两 revision Cold migration。
8. 同一发布删除旧 acquire/revoke、hot disk mutation、resize API和无条件 delete路径。

## 14. 最小验收矩阵

| 场景 | Oracle |
|---|---|
| RemoteHead边界 | 只接受`0/null/null`或`>0/non-null/non-null`；hash、object ID、generation任一改变都会使exact compare失败；result/receipt逐字段复制tuple |
| mutation分类gate | 枚举全部HTTP mutation；Workspace product route恰好使用本节PG result，Account/WorkOS、Billing/Stripe、fleet/admin、Node/internal、webhook及external-first route只使用既有domain协议；未分类或双归属均fail gate且不伪造system workspace |
| API fingerprint fixed vectors | 独立实现按五个u64-BE frame重算§3.3三个hash；body key order/whitespace、raw percent spelling/query order或If-Match Generation任一改变都会冲突，Idempotency-Key/auth/cookie/request ID/User-Agent变化不改hash |
| API envelope/result exact replay | Idempotency-Key缺失、重复、空、非printable或超过512 bytes，以及wrong media type/non-identity encoding均在reservation前拒绝；hit不读resource并逐字节重放status/content-type/body，且route不依赖未保存的ETag/Location；response body超过1MiB则业务/result都不能commit；transport/commit unknown本身不结算失败row，最终只可能业务+result全有或全无 |
| Cat create closed request | 4095/4096/4097-byte边界、非canonical/percent-encoded path、`?x=1`/结尾裸`?`、wrong/duplicate media与encoding、任一If-Match、unknown/duplicate/missing/null字段、非canonical integer、name首尾/大小写/长度、旧image alias/disk/auto-suspend/expiry都在fast lookup前按合同拒绝；合法raw bytes匹配§3.3 Cat vector |
| DiskRecord identity/closed role | `volume_id`全局一对一；Root与Cat同Workspace且每Cat恰好一个，Persistent同时最多一个current Desired；Root只含不可变cat ID，Persistent只含两态initialization且仅允许同lineage的一次Uninitialized→Initialized；`{disk}`只解析disk_id，name只能显式lookup；完成删除后row缺席 |
| Root create crash/重放 | Cat + default Endpoint/hostname lookup + current完整Desired + runtime Operation + generation-zero/unowned Root Disk/Volume + API result同一PG commit或全无；相同key只返回原operation ID且不生成第二identity；Root无Persistent initialization或第二Disk Operation |
| Root create fast lookup/竞态 | exact fast hit不执行placement/capacity；异fingerprint在resource前冲突；fast miss后另一session以同key先commit时，业务事务reservation+reread命中、丢弃整组candidate且零candidate row |
| Root create manifest/release/planner来源 | boot digest只读同digest immutable manifest，size按4MiB向上取整且覆盖manifest/不超1TiB；guest digest只来自验证过的release receipt；planner只选匹配digest的current session/fresh full inventory并返回exact network，任何缺失都不以fixture/default补齐 |
| Root create name并发 | 两个不同key同Workspace/name经CatNameLock只能一方提交202全套rows，另一方零业务row并提交fixed 409；原Cat后来删除后，409 key仍逐byte重放；unique violation不能充当409路径 |
| Root create candidate/corruption | 每类candidate ID/Endpoint/hostname/name碰撞、existing Cat cross-row corruption、serialization/connection failure均不写409/result或半rows；collision只用全新未使用bundle和重新编码的202重试 |
| Root create exact初态/时间 | Desired固定revision1/Running/placement epoch1/cancel-and-drain、一个Root、一个web HTTP:8080 route epoch1；Volume仅接受Active+Unowned、epoch0、blank head、null owner/expiry/transition，Root normal acquire expected epoch0；Cat/Endpoint/Disk/Operation/result五处使用同一DB-now，Operation为Pending/null；202/409 fixed vector由独立encoder逐byte重算 |
| Endpoint单一authority | EndpointRecord只保留immutable product identity/name；hostname lookup只定位current Desired；三者同txn且signer必须重读完整binding。改record/lookup/Desired任一identity/revision或制造hostname并发碰撞都fail closed，不采用旧binding |
| Persistent create crash/重放 | Disk + empty exact Volume + 201 result同一PG commit或全无；相同key只返回原201且无Operation，异fingerprint不读resource |
| initialization CAS/重放 | 锁current AgentSession与highest accepted head后才锁Volume/Disk/Desired/observation；observation ID、revision/placement、valid checkpoint `commit_initialized`、Owned attachment/epoch/head和active lineage逐字段匹配，new head非空且generation>0、R==L；session replacement或新observation先提交则旧evidence零副作用，initialize先提交则replacement随后正常前进；exact tuple保留首次time且无ledger |
| normal acquire响应丢失/异payload | 相同RandomId128且完整request相同返回原result/absolute expiry；同ID异任一字段Stale，不使用domain request hash、不产生第二次fence |
| lease duration/DB time | 0、非canonical number、DB-now checked-add溢出均零副作用；acquire、renew与takeover都把该次唯一DB-now加duration所得值写为absolute expiry；expiry lapse仍不授予takeover/revoke |
| expired other owner | normal acquire始终OtherWriter；精确owner/epoch可继续renew |
| release响应丢失/异payload | 相同RandomId128且完整request相同返回原result；同ID异payload Stale，旧epoch永久不能publish |
| stale acquire晚到release之后 | expected epoch不匹配，不能重新占有volume |
| authorization单一authority | Node只传authorization ID；锁定row中的immutable payload/receipt是唯一权威，Volume last_transition仅ID marker；不存在客户端payload、第二签名或重复receipt副本 |
| Host takeover | 只有精确逐卷授权成功；跨volume/placement/replay失败；receipt精确记录event/volume/new attachment/resulting epoch/head |
| 首次consume与Host rejoin并发 | 两者锁同一event；consume先提交则rejoin观察receipt，Rejoined先提交则consume失败且epoch不变 |
| Host rejoin遇到未消费授权 | 未过`not_after`时保持Active/Blocked；过期后才可Rejoined，且不能首次消费 |
| consumed授权的后继 | direct takeover/disposable state缺失或写错对应authorization marker必须Blocked；更大epoch的takeover→release/restore/delete按closed状态机、epoch单调和head generation非倒退验证；delete→sweep以精确DeleteCompletionReceipt重连；缺失/错receipt保持Blocked，不复制中间链 |
| pure D / cross-row split | pure-domain table只输入Volume/Event/Authorization rows且可复用于SQLite fixture；唯一PG integration逐项改变Cold、R==L、blockd stop、Desired、Disk、Snapshot、stop observation并断言同事务拒绝；不存在bool/VerifiedContext旁路 |
| acquire origin namespace | normal/takeover即使携带相同文本ID也不是同一lineage并进入quarantine；缺失/unknown variant和旧裸字段严格拒绝，不能猜namespace |
| 旧pending目录遇到新attachment | quarantine，remote Root不改变 |
| 相同lineage blockd crash | identity、全部pending pack、runtime evidence与当前grant的服务器端acquire marker逐字段绑定同一完整`AcquireOrigin`后，才从pack恢复L并按序publish；任一冲突quarantine |
| resize请求 | API不存在；`size_bytes` 在Volume/Root/Snapshot中始终一致 |
| normal acquire与begin-delete并发 | 两者锁同一VolumeRecord且只能一方提交；不存在Control Deleting但Volume仍可acquire的窗口 |
| Persistent绑定与delete并发 | attach/detach/delete锁同一Disk/Volume/current Desired；attach先提交则delete因current引用拒绝，delete先提交则attach因Deleting拒绝；delete不读取历史Cat，缺current complete inventory或任一residue时保持Active |
| Root normal begin authority | direct Root Disk DELETE拒绝；Cold fast path把current Cold evidence验证、Deleted Desired/Pending Operation、normal BeginDelete和API result置于同一commit；其他可达路径只用current Deleted observation的R==L+Unowned证据，仍Owned的R==L先exact release、R<L只authorization；Active HostFence下任何仍Owned状态只authorization；全部绑定同一revision/delete ID，旧observation/ID零副作用 |
| Root normal begin crash | fast path在任一点crash后上述rows/result全有或全无；Deleted converge在release前/响应不明/接受current Unowned observation后crash都以原release/delete ID重放，不需要历史Desired或Cold payload |
| Root release/auth derive竞态 | 两个PG session都以VolumeRecord为branch gate并在锁后重验；release先提交使derive因Unowned全回滚，derive先提交使release看到同delete lineage auth而零副作用拒绝，不出现auth+Unowned |
| Root在release前失联 | 最后observation即使`R == L`，Active HostFenceEvent下仍Owned Root也可用exact owner/epoch/head authorization进入Deleting；不要求伪造`R < L`或等待不可达Node release |
| Disk delete 202/GET/replay | 首次begin事务原子写双方Deleting及exact 202 result且不建Operation；GET先见Deleting、completion后404，同key始终重放原202 |
| delete LIST/late PUT/crash | adapter contract suite用已成功PUT正样本判定stale-empty fake/adapter不合格；暂停一个已接受PUT时HostFence barrier不得返回且不能commit receipt，PUT成功可见或永久失败后才delete/re-list empty；多sweeper只有一个exact completion CAS，receipt后再次LIST仍empty；任一失败保留Deleting且不存job/claim/opaque bool |
| disposable Root `R < L` | 固定event/auth/volume/control锁序；closed receipt与两边Deleting原子提交后才删lineage；Volume只存authorization ID marker，PersistentDisk拒绝 |
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
