# Cats 技术架构

- 状态：目标架构；ADR-0040/0041/0042 已接受，Rust 实现尚未完成切换
- 更新：2026-08-08
- 适用范围：产品资源、控制面、Node、网络入口、microVM 与块存储

## 1. 大目标

Cats 提供可休眠、可恢复、可迁移的 Linux microVM。用户看到普通 Linux、
virtio block device、ext4、稳定 HTTPS Endpoint 和标准 CLI/API；对象存储、
本地 NVMe、VMM、fencing 与路由权限都留在平台内部。

架构首先保证三件事：

1. **正确**：不丢不该丢的数据，不出现双写者，不让旧任务或旧路由复活。
2. **稳定**：组件重启、重复请求、响应丢失和部分失败都能从当前事实收敛。
3. **高可用**：单个控制面进程或 Node Agent 退出不应停止已经 Running 的工作负载；
   Node 永久丢失后，在可信外部隔离完成时从远端 durable state 恢复。

## 2. 结论

不推翻已验证的技术底座：

- KVM + Cloud Hypervisor、标准 virtio-blk/ext4；
- Direct-OS ChunkStore、S3 immutable objects、PostgreSQL root/lease CAS；
- Strict/Relaxed durability、RWO attachment 与 fencing epoch；
- Running / Suspended / Warm / Cold 四态；
- PostgreSQL 控制面、多 API 副本与有界 singleton leadership；
- 短期 Ed25519 Route Grant 和 Node 作为最终 admission verifier；
- systemd Guest PID 1、Guest Runtime HTTP/Unix socket、Workspace ownership。

控制面到 Node 的协调模型整体切到以下闭环。每个边界只保留一份当前 authority，Node 的
恢复状态与当前 Cat 数量成正比：

```text
PostgreSQL DesiredRuntimeSpec(revision)
                 |
                 | level-triggered delivery / pull
                 v
       Node per-Cat reconciler -------- MetadataStore owner/epoch CAS
                 |
                 | inspect + converge
                 v
 physical runtime + one bounded RuntimeCheckpoint
                 |
                 | complete ObservedRuntimeStatus
                 v
        PostgreSQL read model / exact Operation settlement
```

通知、队列和缓存只能加速这个循环；丢失它们不能改变正确性。

## 3. 结构性问题

现有故障不是一串互不相关的 bug，而是六个系统边界没有闭合：

| 结构性问题 | 当前表现 | 终态规则 |
|---|---|---|
| 生命周期权威分裂 | Cat 行、Controller transitional state、NodeJob、heartbeat 和内存结果都能影响状态 | PostgreSQL只写完整desired；Node只执行并报告observation |
| 物理所有权不可恢复 | Agent重启会杀子进程，副作用后才写ledger，资源按hash猜名字 | Host lock、per-Cat scope、effect前checkpoint和完整物理inventory |
| 卷接管与Guest可用混在一起 | 过期lease可被普通Start抢占，block attach被当成mount Ready | normal acquire与proof-bound takeover分离；ext4 UUID/mount是Ready条件 |
| 路由能力与runtime事实脱节 | token有效期、共享mirror和Node generation共同充当route状态 | Grant只传递能力；Node本地gate/guard是最终admission authority |
| 怀疑被当成隔离证明 | heartbeat超时可能推动跨Node恢复 | timeout只产生suspicion；HostFenceEvent后仍需新Desired和逐卷授权CAS |
| 运行面缺少有界故障合同 | 同步PG阻塞async worker，故障域、告警和真实资格测试分散 | 有界DB执行、明确故障域、同一套可重复的Linux/metal故障矩阵 |

这些问题只能通过一次协调面重建共同解决。单独修NodeJob、延长TTL、增加重试或再建一份
状态表都会保留原来的多权威结构。

### 3.1 当前实现事实

仓库当前是完整的 V1 开发实现，不是上述目标协议：

| 范围 | 当前事实 | 目标差距 |
|---|---|---|
| ChunkStore | Rust engine、delta pack、golden root、NBD/vhost-user-blk、fencing 与 crash tests 已存在 | 保持格式和语义；补齐组合故障验收 |
| 控制面 | PostgreSQL 同时保存 desired、observed、generation；Controller 派生 `NodeJob` | 切到完整 DesiredSpec 和纯 observation read model |
| Node | 动作结果只在内存 journal；动作结束后才写完整 JSON ledger | 副作用前写一个有界 checkpoint，并以物理枚举重建 |
| heartbeat | 只有 Node/Cat generation/state，会直接覆盖 Cat observed | 加 agent instance、sequence、完整 inventory；只写 observation |
| route | 已签名并在 Node 验证，Gateway另有DynamoDB mirror，但没有独立的本地 installed/retired gate | 精确绑定incarnation/per-Endpoint route epoch并原子guard；删除shared mirror |
| Node restart | 测试能重新打开部分子进程，但生产 unit 仍会随 Agent cgroup 杀进程，且无 Host 排他锁 | per-Cat scope、union enumeration、Host lock 后才宣称可接管 |
| HA | 多副本/RDS/RDS Proxy结构已存在；双节点Cold迁移有真机证据；当前Store会同步串行慢DB调用 | 异步有界DB执行；真实control-plane takeover、RDS failover和自动Host fence验收 |
| PersistentDisk | 当前只把raw virtio设备和`mount_path`送到Node，没有filesystem identity或Guest mount结果 | ext4 UUID、一次性format authority和mounted observation |
| Placement/Guest network | legacy `nodes` capacity与Node本地CIDR/FNV仍存在；per-Cat tap和dev E2E已存在 | A23 policy/planner/exact Desired network尚未实现；真实CH资格证据与跨Node overlay仍缺失 |

### 3.2 组件职责

| 组件 | 只负责 | 不负责 |
|---|---|---|
| Control Plane | WorkOS/Workspace授权、资源API、DesiredSpec、Operation、placement、Grant签发、fleet策略 | Running块I/O、逐请求Guest代理、物理状态猜测 |
| Gateway | hostname解析、用户入口、wake触发、缓存并转发不透明Grant | route authority、token重签、生命周期副作用 |
| Node Agent | Host资源、per-Cat reconcile、物理inventory、VMM/blockd/route gate | 用户资源authority、跨Host自行抢占 |
| Cloud Hypervisor/Guest Agent | microVM执行、pause/snapshot/restore、vsock控制、Guest-local Runtime API | S3/PostgreSQL凭据和平台调度 |
| cats-blockd | 标准块协议、cache/pending、commit、lease/fencing | Cat placement和用户身份 |
| PostgreSQL | 控制资源事务、Operation、usage projection、volume root/lease CAS | VMM是否实际存在 |
| Object Store | immutable data/map/commit/archive objects | 当前writer和current root选择 |
| Metering | Node累计计数器、durable delivery、可重建projection/rating | 用desired allocation猜实际消耗 |

具体云产品只出现在 composition root和`adapters/`；domain/storage contracts不依赖AWS类型。

### 3.3 关键数据路径

- **Create/Wake/Stop**：API事务写新 DesiredSpec/Operation，Node拉取并收敛，observation精确
  结算Operation。Controller重启只重扫当前desired，不重放历史命令。
- **Running HTTP/WebSocket**：Gateway取得短Grant后直达owning Node；Node本地gate验证并
  guard，Control Plane不在每请求热路径。
- **Guest block I/O**：Guest -> virtio -> NBD/vhost-user -> blockd；FLUSH的唯一持久性
  边界是本地`L`和远端`R`，与lifecycle消息无关。
- **Usage**：Node从Cat专属cgroup读取单调累计量，经durable spool/delivery进入projection；
  支付提供商和展示缓存都不是ledger authority。
- **Admin/fleet**：provisioner用[ADR-0043](decisions/0043-provisioner-owned-runtime-placement-policy.md)
  的signed/revisioned policy声明capacity/capability/CIDR；cordon/drain只产生受版本保护的变化；跨Node恢复仍受route drain、
  `R == L`、lease release或HostFenceEvent约束。

## 4. 简单的权威边界

不存在一份包办所有事实的“全局真相”。每类事实只有一个写入权威：

| 事实 | 唯一权威 | 其他副本的地位 |
|---|---|---|
| 用户意图、完整 runtime spec、目标状态、placement | PostgreSQL `DesiredRuntimeSpec` | Node 只缓存当前 revision |
| Node schedulable、allocatable capacity、production capability、Guest IPv4 pool | PostgreSQL `NodePlacementPolicy`，只由provisioner/admin CAS | heartbeat、legacy node row和Node自报数字无权修改 |
| covered Workspace product API请求重放与不可变结果、Operation 与审计 | PostgreSQL `ApiIdempotencyResult` / Control rows | 日志不是恢复依据；其他domain沿用自己的identity |
| VMM/blockd/Guest/snapshot 是否真实存在 | Node 新鲜物理枚举和协议握手 | PostgreSQL 只保存 observation |
| 当前恢复步骤 | 每 Cat 一个原子替换的 `RuntimeCheckpoint` | 只是一条有界恢复线索，不覆盖物理事实 |
| volume writer、attachment epoch、remote root | MetadataStore CAS | desired attachment 是请求，不是写权限 |
| Relaxed 尚未远端发布的数据 | 原 Node 的 pending pack/journal，直到 `R == L` | 这部分不是可删除 cache |
| Endpoint 配置和 route epoch | PostgreSQL | Gateway 只缓存 |
| 当前 Node admission | Node 本地 route gate + active guards | 签名 Grant 是 capability，不是物理状态 |
| Node 存活/库存 | 带 instance/sequence 的 observation | timeout 只是 suspicion，不是 Host fence |

本地 checkpoint 缺失、损坏或与物理事实冲突时，Node 必须报告
`Blocked`/`Quarantined`；“没在文件里看到”不能推断 Cat 已 Cold。

只有能与业务rows在唯一Control PG事务原子提交的Workspace product mutation使用
`ApiIdempotencyResult`，以`(authenticated workspace, canonical route, Idempotency-Key)`唯一标识，并使用
[Volume Authority §3.3](specs/volume-authority.md#33-workspace-product-api-idempotency)冻结的统一byte-level
fingerprint：domain separator后依次length-frame workspace、matched method/route template、raw path-query、
If-Match presence/Generation和raw body，不做JSON/path/query语义归一化。调用者身份、当前Workspace
membership和route permission先通过；事务随后取得
该key reservation并优先读取result，再沿
`NodeIdentity -> current credential lineage（A19 auth适用时）-> AgentSession -> observation receive/cursor -> HostFenceEvent -> authorization ->
VolumeRecord -> Disk/Desired -> DiskSnapshotRecord`的全局DAG锁定
自己涉及的行；首次业务变化与保存status/content-type/exact response bytes的result同一commit，不落持久
Pending。同key重放只读
result，即使目标资源已删除也不先查资源；同key异payload在资源锁前失败。只有result miss才检查资源
ownership并取得domain locks；跨Workspace miss回滚reservation且零持久副作用。V1已提交result不随
resource或Operation删除而GC。Account/WorkOS、Billing/Stripe、fleet/admin、Node/internal、webhook和
external-first route只用既有domain identity；router gate要求每条mutation恰好分类一次，不伪造system
workspace或双重幂等。covered route要求单一1..=512 printable-ASCII key、固定media type和identity/no
Content-Encoding；精确重放语义只能放在持久化的status/content-type/body，不能依赖未保存的ETag/Location。

Volume domain不复用HTTP request fingerprint：normal acquire/release分别用`RandomId128` transition，
takeover/disposable delete只提交唯一Control Store writer已持久化的authorization ID，delete使用自己的ID；
row内closed `last_transition`只为没有独立row的normal variants保存完整typed request/direct result；
authorization variants只存ID marker并从唯一AuthorizationRecord逐字段replay。lease request携positive
duration，由同一PG事务用DB time checked-add为absolute expiry；expiry只影响liveness。Remote head及安全
receipt始终保存generation、root hash和root object ID的exact tuple，不拆字段验证，也不增加第二套签名。

## 5. 产品资源

- **Workspace** 是唯一资源 owner；Account/Organization 只参与身份、成员关系和计费。
- **Cat** 持有 runtime spec、RootDisk、稳定 Endpoint 和四态目标。
- **RootDisk** 跟随 Cat 生命周期；只有显式 disposable-root Destroy 可以放弃未远端
  发布的 tail。
- **PersistentDisk** 独立存在且为 RWO；任何未知分类或残留 attachment 都要 fail closed。
- **DiskRecord** 只保存immutable product identity/size/durability、Active/Deleting和closed
  `Root {cat_id} | Persistent {Uninitialized|Initialized}`；Available/Bound来自current complete Desired，
  完成删除后row缺席。Disk与Volume全局一对一；Root与同Workspace Cat一对一，Persistent同时最多属于
  一个current Desired。product path中的`{disk}`只解析immutable disk ID，name不参与猜测。
- **Snapshot** 是远端 durable root 的不可变引用，不能引用仅存在本地的 `R < L`。
- **Operation** 精确绑定一个 `desired_revision`，是runtime mutation的结果，不是 Node 工作流；
  PersistentDisk create/delete和Snapshot mutation同步使用API result，不创建自己的Operation。

## 6. 生命周期协调

### 6.1 DesiredRuntimeSpec

每次有效 mutation 在一个 PostgreSQL 事务内写完整 spec，并递增单调
`desired_revision`。它至少包含：Cat/Workspace、稳定目标态、placement node 和 epoch、
CPU/内存/boot image、完整磁盘 attachment 集、网络/Endpoint epoch，以及离开 Running 时
使用 `require_idle` 还是 `cancel_and_drain`。需要Guest挂载的PersistentDisk还声明稳定
device identity、ext4 UUID、mount path和仅对空白新盘有效的一次性format authority。首版只在
Cold修改VM shape和磁盘集合，并且只在Cold创建DiskSnapshot；卷容量创建后不可变，Running
attach/detach不引入hotplug状态机。

Endpoint mutation与新的完整desired revision、`route_epoch`和hostname lookup index在同一
PostgreSQL事务提交。`route_epoch`是per-Endpoint serving lineage：binding变化递增；任何gate实际
close后重开也必须由fresh Desired递增。未变Endpoint不因其他Endpoint mutation重绑或中断。
lookup只定位current revision，不成为另一份Endpoint authority。Running请求
只有按[Runtime Placement Policy v1](specs/runtime-placement-policy-v1.md)在同一snapshot选定placement、capacity
和exact NetworkConfig才能提交；无可选Node时API返回`placement_unavailable`，不留下半个desired。

相同workspace/route/key和request fingerprint返回原不可变HTTP response；异步response只引用原
`operation_id`，Operation的当前phase/status仍只由Operation row权威持有。异payload fail closed。
已经处于同一目标且 spec 未变时不制造新 revision。
一个 revision 是完整期望，不依赖读取旧命令才能解释。

### 6.2 Node reconcile

每个Node进程先取得Host级排他锁，每个Cat由一个常驻reconciler worker串行修改checkpoint
和物理资源。每Cat另有一个短`AdmissionCell`，其中保存per-Endpoint gates、全局lifecycle
admission以及Endpoint/Platform guards；reconcile的枚举、数据库、VMM和fsync不持有该cell。
一次reconcile：

1. 读取最新 spec，拒绝旧 revision、错误 node 或 placement epoch。
2. 合并 checkpoint、systemd scopes、进程 start time、控制 socket、blockd status、
   data directory、snapshot 和 MetadataStore owner/epoch，形成完整现况。
3. 身份不足或冲突时 quarantine；绝不猜测、抢租约或删除未知目录。
4. 在第一个副作用前原子写当前 checkpoint；外部副作用使用当前 revision、incarnation或
   transition identity的最窄条件合同。
5. 只执行下一个安全、幂等步骤；安装或关闭route时只在内存线性化点短暂进入AdmissionCell；
   每步后更新同一checkpoint。
6. 达到稳定目标后发布完整 observation；checkpoint 收敛为稳定快照，而非追加历史。

新Root的唯一数据初始化步骤是`acquire_volume -> provision_root_image -> prepare_device`：checkpoint绑定
Desired image、immutable size、attachment/epoch、blank和由manifest/Map编码纯确定计算的generation-1 head。
blockd只可先开放Host control socket；exact target确认前没有Guest device或VMM。RPC不明时只读Volume head，
exact target成功、exact blank重试同transition，其他head/owner/epoch fail closed；没有第二个receipt。

tap name/ownership token、kernel-NBD slot和vhost-user socket按Host inventory在Host resource lock下分配，
Guest subnet/MAC/gateway只消费Desired exact NetworkConfig。exact identity先写checkpoint。容量耗尽是明确placement failure；cleanup只删除ownership token与
物理identity同时匹配的资源，不按Cat hash重算名字后先删。

新 VMM 进程创建前生成 `runtime_incarnation`。Warm restore 创建新 VMM，因此也产生新
incarnation；Suspended 的原进程 resume 可以保持 incarnation。已经在线性化的旧pause/stop
可能完成，但只能作用于它记录的incarnation，不能取得新存储authority、打开新route、发布
新observation或结算新Operation；最新revision随后按物理postcondition继续修复。

### 6.3 Observation 与 Operation

provisioner先把`node_id`、provider验证的不可变Host identity和每Node credential绑定在
PostgreSQL；注册不接受Agent自报identity或fleet共享credential。Agent在请求前持久化
registration attempt，同一attempt重试返回同一session epoch；同Host新session使旧session永久
失效。不同Host不得接管同一`node_id`；旧identity先显式fence/retire，随后以新的NodeIdentity和
新`node_id` provision。直接提交的`NodeObservation`包含
session epoch、agent instance、该instance内单调sequence和本次inventory是否完整。full scan在
current session下建立独立`AdmissionInventoryAttestation`；partial observation引用其epoch而不覆盖。

Node只从root/provisioner安装的canonical local `NodeIdentity` artifact取得Node/Host/state-path lineage，
并逐byte绑定per-Node key；CLI、hostname/IP和IMDS不补身份。Control与Node只消费同一次release build冻结的
closed Guest payload/manifest，见
[Runtime Composition Artifacts v1](specs/runtime-composition-artifacts-v1.md)。
每个Cat status包含
applied revision/spec digest、placement epoch、runtime incarnation、物理状态、结构化
Condition、逐卷 owner/epoch 与 `R/L`、route gate 和 active guard 数。

控制面只接受当前注册Agent的递增sequence。observation可以更新read model，但不得改desired。
Operation只有在同revision、同placement、满足目标postcondition时成功；新的用户intent使旧
Operation `Superseded`，placement丢失则当前Operation明确`Failed`，系统恢复使用新的system
revision。Quarantined同样使当前Operation失败，人工处理通过新revision表达。Deleted desired
保留到精确complete inventory证明checkpoint absent，或provider HostDestroyed receipt证明旧Host state
storage永久销毁且该Cat保留的placement与immutable Host/state-path lineage匹配event，并且逐卷处置全部
闭合后再GC；该检查不要求index最新boot/session等于event的fence session，普通隔离fence不够。N+2的同名
状态不能完成N。

共享domain合同见 [Runtime Reconciliation v1](specs/runtime-reconciliation-v1.md)，决策见
[ADR-0040](decisions/0040-level-triggered-runtime-reconciliation.md)。注册的唯一终态入口是
`POST /v1/internal/runtime/agent-sessions`；它和全部internal runtime请求共用的per-Node签名adapter、
registration public error、session lease与release receipt路径由
[Agent Registration and Internal Transport v1](specs/agent-registration-transport-v1.md)冻结。Desired delivery只使用
`POST /v1/internal/runtime/desired-reads`，inventory/observation接受只使用
`POST /v1/internal/runtime/observations`；它们的事务、endpoint-local error和planner/signer freshness由
[Runtime Inventory and Observation Spine v1](specs/runtime-inventory-observation-v1.md)冻结。两条session-bound mutation
在`READ COMMITTED`下统一从`NodeIdentity FOR UPDATE -> exact active credential lineage FOR SHARE ->
current AgentSession -> receive/cursor state`
开始，planner/signer仍是单一`REPEATABLE READ READ ONLY` snapshot。observation的唯一session续期点
还使用每replica独占的有界Store worker/queue/PostgreSQL connection，不与volume/product/controller
work共享。legacy
`/v1/nodes/register`、heartbeat/inventory route和shared service/admin bearer不属于目标架构。
Node把checkpoint中的normal/takeover acquire、exact release和disposable Root authorization consume提交给
Control的唯一窄mutation route `POST /v1/internal/runtime/volume-transitions`；wire、同一current
session/inventory/Desired校验、锁序与模糊响应恢复由
[Runtime Volume Transitions v1](specs/runtime-volume-transitions-v1.md)冻结。authorization类结果不明只经
A19-signed Control `POST /v1/internal/runtime/volume-transition-evidence`按authorization ID读取一份一致exact
snapshot；immutable
`authorized_node_id`把读取者绑定原执行Node，即使session/revision已变化也不回看stale Desired。Node没有
Control authorization/completion表的SQL credential；evidence不枚举授权历史或返回success bool，并与blockd
的`VolumeDataAuthority`分离。blockd继续只读/renew/head-CAS，不得取得ownership transition或
authorization/completion read能力。

## 7. 四态和数据屏障

四态定义与资源账本见 [runtime-lifecycle.md](runtime-lifecycle.md)。核心边界不变：

`WarmRuntimeSnapshot`指Host本地的VMM memory/device快照；`DiskSnapshot`指MetadataStore中
远端durable Root的产品资源。两者生命周期、GC和上线门独立。

- Suspended = VMM pause + page-out，Host-bound；允许 Relaxed `R < L`，但必须完成 Guest
  本地 durability barrier，并保留 Host、blockd、lease 和 journal。
- Warm = memory/device snapshot + VMM exit，Host-bound；进入前所有保留卷必须 `R == L`。
- Cold = 无 VMM/Guest 内存状态；所有保留卷必须 `R == L`。
- Warm restore 或 Suspended resume 失败，先保护本地唯一数据，再收敛到可证明的 Cold。

普通Start遇到另一个writer时，即使其lease TTL已过，也必须返回
`Blocked(SupersededByAnotherNode)`。normal acquire只允许精确的unowned epoch；只有重放同一个
transition才返回原grant。计划handoff先由源release，再由目标normal acquire；非计划Host loss
才使用精确绑定旧owner/epoch、新attachment/placement与`HostFenceEvent`的逐卷takeover
authorization。一个Host fence可以派生多个逐卷授权，但每份授权只能CAS一个卷。
heartbeat timeout、Route Grant TTL和“Node看起来不健康”都不是fence。

## 8. 存储

Guest 只看到标准块设备。`cats-blockd` 把稀疏本地 cache、64 KiB dirty page、delta/base
objects、Merkle Map 和 PostgreSQL root/lease CAS 组合成一个卷。详细当前合同见
[storage.md](storage.md) 与 [blockd protocol](specs/blockd-protocol.md)。

Strict 的成功 FLUSH 保证远端 root 已 CAS；Relaxed 的成功 FLUSH 只保证 `L`，可能仍有
`R < L` 的唯一数据。因此本地 NVMe 只有在 `R == L` 时才完全是可删除 cache。Warm、Cold、
snapshot、detach、计划迁移和 PersistentDisk destroy 前必须 drain 到 `R == L`。

磁盘集合在Cold desired中修改。RPC响应丢失时不回滚binding；控制面等待Node observation
收敛。Persistent volume删除先阻止新attachment，再证明没有desired、lease、pending和inventory residue；
Root的`R == L` normal begin只允许同一delete ID的两条current-only路径：stable Cold Destroy在一个PG
commit原子写Deleted/Operation/begin/API result，或Node在current Deleted revision完成exact release后由新的
current Unowned observation触发begin。直接Root Disk DELETE和live Cold direct delete均拒绝。进入Deleting状态后幂等清对象，不能只相信
控制面的一列状态。唯一disposable Root `R < L`例外必须先消费
绑定Deleted revision、delete ID、attachment、owner/epoch/head与stop/fence证据的精确授权，把
Owned卷直接CAS到Deleting并提高epoch，随后才删除该`R < L`lineage；PersistentDisk不能使用。
Active HostFenceEvent下最后`R == L`或L未知但仍Owned的Root也走同一exact authorization，因为Node已无法
release；可达R==L仍先release。release/derive以VolumeRecord锁后重验，不能留下auth+Unowned。
Disk delete遇到live `DiskSnapshotRecord`时返回`SnapshotInUse`且不改变状态；Snapshot由独立幂等
API操作与covered `ApiIdempotencyResult`同事务删除该row，Disk delete不隐式cascade。

显式Disk delete的begin事务同时写Disk/Volume Deleting和exact 202 result，不创建Operation；GET随后见
Deleting，completion后404，同key仍重放原202。sweeper只扫描这个level state，不持久job/claim：writer已在
begin时关闭后，幂等删除并重新列举object prefix到empty。completion所用BlobStore LIST必须对已完成
PUT/DELETE线性可见；normal stop必须join upload workers，HostFenceEvent只有在provider cutoff阻止新PUT且
所有已接受PUT已成功可见或永久失败后才满足barrier。不能证明时保持Deleting；随后才以一个exact PG
compare/CAS写completion receipt
并删除两row。失败保留Deleting，多实例可竞争重试；PG与object store之间没有第二份事务authority。

block attach只证明virtio设备存在。声明了ext4 mount的PersistentDisk只有在Guest按稳定device
identity找到设备、验证期望UUID并报告目标path已mount后才算Ready。新盘创建时在Control Store
以一个PG事务原子写empty Volume、closed Uninitialized Disk和201 result，不建Operation；同时预定UUID和
一次性initialization token。匹配UUID可幂等adopt，其他UUID或部分格式化痕迹进入quarantine，不再格式化。
初始化必须在exact UUID probe、device flush并把卷推进到`R == L`后，只复用current AgentSession已接受的
完整observation row；事务先锁current NodeIdentity、AgentSession/highest accepted head，再按Volume→Disk→current
Desired→immutable observation锁序逐字段匹配observation ID、revision/
placement、valid checkpoint `commit_initialized`、Owned attachment/epoch/non-empty head与`R == L`
lineage，再CAS成Initialized；session replacement/observation advance竞争同一前缀。随后mount和Mounted
observation是独立的Ready条件。

Cat create同一PG commit写Cat、current完整Desired、runtime Operation、唯一Root Disk、generation-zero/
Unowned Volume和exact result；Root没有Persistent初始化状态或第二个Disk Operation，响应不明的同key
重放不能产生第二组identity。Node随后以RuntimeCheckpoint中的显式typed provision step引用operator已发布
的immutable golden manifest；`--seed-image-id`启动时隐式provision不属于终态合同，也没有兼容路径。

DiskSnapshot首版只允许Cold且unowned的卷。create/delete/restore先验证当前Workspace membership和
route permission，再读取covered result；精确命中直接返回。只有miss才验证认证Workspace拥有Disk及精确
disk/volume/snapshot tuple，并在同一事务写资源变化与result。create由服务端分配永不复用的snapshot
ID并插入一条精确`DiskSnapshotRecord`，该row同时是产品资源与GC live-root；只支持恢复到同一Disk。
这三个Snapshot mutation同步完成，不创建Operation；产品row只表示资源现在是否存在，covered result只保存
旧HTTP请求当时返回什么。clone与Golden Image自动GC不在本轮范围。
详细状态机见[Volume Authority and Disk Lifecycle](specs/volume-authority.md)。

## 9. 路由

Endpoint 的 Running 数据路径不逐请求访问控制面：

1. 公网请求只按canonical hostname查Endpoint；Workspace身份用于管理API，不强加给用户应用。
2. 控制面只为 `Ready/Running` 的精确observation签发短期Route Grant；Ready证明Guest网络、
   runtime和磁盘mount，不要求应用端口已监听。
3. Gateway把Grant连同Control Plane验证过的Node transport target放入有界per-replica cache；
   Grant保持不透明，Gateway到Control Plane和Node使用认证且加密的机器连接。
4. Node验证签名、时间、Workspace/Endpoint/Cat/Node、runtime incarnation、per-Endpoint route
   epoch、hostname、协议和端口。desired revision留在signer current-state snapshot，不进入Grant。
5. Node在短`AdmissionCell`内比较当前installed gate并取得active guard；比较与guard取得
   不可分割，且该cell不执行任何外部I/O。

离开 Running 时，Node 先关闭 gate，拒绝新 admission，再按策略确认 idle 或取消/排空
现有 HTTP/WebSocket guards，最后才 pause、snapshot、detach 或 teardown。TTL 限制新
admission，不能撤销已存在的流，也不能替代本地 gate。

Endpoint A变化只提高A的route epoch；未变B的gate与既有Grant不受影响。任何gate一旦实际close
或结果不明，重开前都必须由fresh Desired提高该Endpoint epoch；Agent重启也遵守这条规则，不能
从checkpoint复活旧token。Node任意时刻只接受一个epoch。

只有Node在取得guard、连接Guest和发送任何upstream byte之前返回的typed stale rejection，
Gateway才compare-and-delete精确cache并singleflight刷新。当前HTTP/WebSocket请求不自动重放；
刷新只服务后续请求。Guest连接失败、部分响应或transport歧义不清route，也不触发业务重放。

每个Gateway cache有固定容量、resolve并发上限、per-host singleflight和短negative backoff。
控制面全断时只有已经预热该entry的replica能在token expiry前接新连接；不宣称fleet-wide冷cache HA。

Route正确性只依赖签名Grant、当前Node gate和原子guard。详见
[Route Grant v2](specs/route-grant-v2.md) 和
[ADR-0041](decisions/0041-node-verified-route-admission.md)。

## 10. 高可用故障合同

| 故障 | 保证 | 明确不保证 |
|---|---|---|
| 单个 API/Controller 退出 | 其他副本继续；新 leader 从 PG desired 扫描 | 内存队列不恢复，也不需要恢复 |
| 控制面全断 | 已Running的VMM/blockd和现有流继续；预热该entry的Gateway replica可在Grant过期前接新流 | 新mutation、唤醒、Grant续期和冷Gateway cache |
| PostgreSQL/MetadataStore 暂时不可用 | Running 计算继续；Relaxed 可在本地配额内推进 `L` | Strict FLUSH、远端 publish 和 lifecycle drain 必须成功 |
| Object Store 暂时不可用 | cache hit 读和 Relaxed 本地提交可有界继续 | cache miss、Strict commit、Warm/Cold 转换 |
| Node Agent 退出 | 目标形态下VMM/blockd scopes继续；systemd重启Agent，取Host lock后重建 | 代理中的连接可中断、新admission短暂不可用；当前V1尚未满足 |
| Node 网络分区 | 保留源，不在另一 Node 自动启动 writer | heartbeat timeout 不等于失效转移 |
| Host 永久丢失 | HostFenceEvent、新Desired和逐卷CAS后从remote `R` Cold恢复；旧epoch永久失败 | Relaxed `R < L` 的tail可能丢失，报告`DataLossPossible` |
| Warm/Suspended 局部损坏 | 保留卷安全后 Cold fallback | Host-bound 快路径本身不是 HA 副本 |
| Gateway 退出 | 其他 Gateway 可从控制面取新 route | 无共享镜像时，冷 Gateway 不在 CP 全断期间接新流量 |

AWS自动Node failover使用一个窄、可审计的EC2/BMC Host-fence adapter。provider receipt只建立
绑定不可变Host/boot、旧session和fence attempt的Active HostFenceEvent，不直接创建placement或
writer。Control Plane以一个事务失败旧Operation并创建新完整Desired/Operation/placement及全部
逐卷授权；每卷CAS后才恢复。旧Host网络持续隔离，rejoin把旧`R < L`lineage quarantine并核对全部
派生授权/current owner。授权派生、首次consume和`Active -> Rejoined`都锁同一event行；首次consume
只从服务器端immutable authorization row读取payload，在同一PostgreSQL事务完成Volume CAS并写closed、
不可变receipt。rejoin验证receipt以及当前卷是其直接结果或合法单调后继；VolumeRecord已删除时，精确
`DeleteCompletionReceipt`还必须证明normal exact `BeginDeleteRequest`或同一disposable authorization的begin identity、
deleting epoch/head、object sweep和两边row原子删除。未消费授权必须已过期。
HostRejoinProof把event持久转为Rejoined后才恢复网络，此后未消费授权不能首次生效。

数据库调用在有界blocking executor/连接池中执行，不能让同步driver占住Tokio worker。
拓扑、故障检测、告警和测试机资格合同见[Operations and HA](operations-ha.md)。

## 11. 安全和运维边界

- Guest 不持有 S3、MetadataStore、WorkOS 或 Node 管理凭据。
- 用户身份、机器身份和 fleet break-glass 身份分离；所有资源按 Workspace 授权。
- Route Grant 私钥只在控制面 signer；Node 持有 key ring，Gateway 不解读或重签。
- blockd/VMM/Guest 最终应运行在 per-Cat systemd scope；Node Agent 本身另有 Host lock。
- privilege separation 与跨 Node overlay 尚未实现，继续保持为后续工作。
- 审计事件可以追加、轮转和外送，但删除审计历史不影响恢复。

## 12. 模块和实施依赖

只拆五个有真实边界的模块；每个副作用使用所属边界的窄条件合同：

| 模块 | 负责 | 核心模型或算法 | 依赖 |
|---|---|---|---|
| A. Control truth | DesiredSpec、ApiIdempotencyResult、Operation、Endpoint revision、NodeIdentity、NodePlacementPolicy、AgentSession、observation | PostgreSQL事务、revision CAS、keyset placement、周期扫描 | 共享身份/错误闭集 |
| B. Node convergence | Host lock、per-Cat reconciler、checkpoint、scope、inventory、Host资源分配 | inspect -> plan one step -> persist -> act -> verify | A的revision/session |
| C. Volume and disk | RWO lease、逐卷takeover、pack lineage、ext4、snapshot、delete | transition-id CAS、`R/L`屏障、Cold-only磁盘变化 | A的disk intent、B的checkpoint |
| D. Route and work admission | Endpoint lookup、Grant、Gateway cache、Node gate/guard、RequireIdle | signer一致快照、pre-admission verify、AdmissionCell线性化 | A、B，且C mount Ready |
| E. Operations and HA | 有界DB执行、控制面/Gateway副本、Host fence/rejoin、告警、资格测试 | suspicion -> proof -> recovery，固定故障oracle | A-D全部稳定 |

依赖顺序是 `A -> B -> C -> D -> E`，但A的schema、B的Host基础和C的MetadataStore合同可在
接口冻结后并行实现。D只能在revision、incarnation和mount readiness已经可用后接入；E中的
Host恢复必须同时调用AgentSession、逐卷takeover和route close，不能先上线半条链。

严重程度也只有三层：

1. **阻止数据损坏或双写**：revision/session、normal acquire/takeover、pack lineage、checkpoint、
   `R/L`屏障、ext4初始化和route close。
2. **阻止单点故障进入用户面**：有界DB、Agent restart、控制面/Gateway副本、Host fence/rejoin。
3. **不阻塞本轮的能力**：跨Host Warm/live migration、hotplug、Disk clone、Golden Image自动GC、
   overlay、privilege separation和新billing形态。

### 12.1 开发与验证顺序

1. 先把每个已知失败写成外部行为oracle：ABA、响应丢失、逐步kill、双Agent、过期owner、
   `R < L`、错误UUID、旧Grant、active WebSocket和慢数据库。
2. 在同一开发分支实现A-C并删除旧NodeJob、lease接管和本地ledger路径；测试与部署artifact只
   包含终态接口。
3. 接入D并删除DynamoDB route mirror、旧claims/parser、旧IAM和Terraform输入。
4. 接入E，完成两种block path、真实Cloud Hypervisor、控制面/RDS/Gateway/Agent/Host故障矩阵。
5. 独立native x86_64 Linux测试机运行exact clean commit的`quality.sh full`并保存不可变receipt；
   满足隔离、空闲和exact-artifact前置的metal Host再运行同一`runtime-cutover-e2e.sh` oracle的
   kernel-NBD和vhost-user两次结果。没有合格Host时真实KVM上线门保持Blocked。

### 12.2 Clean-slate 部署

现阶段产品数据可删除，因此首次部署不迁移旧 runtime/data，也不做在线 authority 切换。完整、
有序的 reset、credential rotation、NodeIdentity bootstrap、qualification 与最后回滚点只由
[Operations and HA §8](operations-ha.md#8-首次终态部署)定义。继续使用 Chunk/Map/Delta 格式、
virtio/ext4 和四态，是因为它们是已验证且合适的终态设计，不是兼容要求。

## 13. 上线门

目标只能在以下 oracle 全部通过后称为“正确、稳定、高可用”：

- 旧revision/observation不能结算新revision；晚到物理effect只作用于原incarnation，不能取得
  新authority或打开新route，最新planner能按postcondition修复；
- 同一Host只有一个持锁Agent；per-Node credential和已登记Host identity阻止另一Host自报node_id，
  幂等registration attempt解决响应丢失；
- 普通Start在过期的其他owner上仍Blocked，只有精确handoff/fence takeover可提高epoch；
- pending pack与attachment lineage绑定；新attachment不能发布旧epoch本地写；
- crash后只能adopt、继续或quarantine，无孤儿删除、重复writer和lease抢占；
- covered Workspace product API fingerprint fixed vectors跨实现一致；每条mutation恰好分类到PG result或
  既有domain协议；same key只重放exact status/content-type/body，非法key/envelope在reservation前拒绝；
- PersistentDisk create只产生同事务Disk/Volume/201 result，不建Operation；Disk role/init closed且成员关系只
  来自current complete Desired；Disk/Volume一对一、Root/Cat一对一且path只用disk ID；
- Cat create连同Root/Volume/Desired/Operation/result全有或全无；PersistentDisk格式化后必须锁current
  session/accepted head并绑定exact UUID/checkpoint/owner/head和`R == L`再标记Initialized；
- Root provision target由manifest+size+Map编码独立重算；step fsync、各PUT、CAS、响应丢失和Agent restart
  只能得到exact generation-1 target或保留exact blank重试，同transition不换object identity，任何其他
  generation绝不覆盖且device/VMM不提前出现；
- `DiskSnapshotRecord`直接进入GC mark set，Deleting状态阻止新attach并完成对象清理；
- snapshot业务变化与covered API result原子提交；create→delete后的旧create重放不复活row，跨Workspace
  mutation不写Operation/result或资源；
- disposable Root `R < L`只有精确Owned->Deleting授权CAS后可删，且不能扩展到PersistentDisk；
- Root direct/live-Cold delete拒绝；Cold fast path全有或全无，deferred normal begin只读current Deleted
  observation且不保留历史evidence；release/auth derive两种提交顺序只有一方成功，HostFence在R==L后、
  release前丢失也能授权；Disk delete begin
  原子写双方Deleting和202 result；多sweeper只能在provider cutoff/late PUT barrier和LIST强一致后以
  prefix-empty和exact completion CAS删除row；stale-empty adapter fail gate，且不创建job/第二Operation；
- `R < L` 时 Warm/Cold/detach/migrate 被阻止，远端恢复后能 drain；
- Host 未 fence 时不跨 Node 启动；takeover后旧epoch永久fail closed，旧Host通过rejoin清场
  前不恢复workload网络；
- route先在AdmissionCell停止admission并drain guards，再触碰runtime；慢reconcile I/O不阻塞
  已Active gate；
- 未变Endpoint不因其他Endpoint mutation失效；任何实际close后的gate只以更高route epoch重开；
- stale route只更新cache供后续请求，任何可能已到Guest的请求都不自动重放；
- 双控制面与真实 RDS failover 不重复副作用；
- kernel-NBD 与 vhost-user-blk 运行相同安全矩阵。

实验数字只按原始环境、样本和 correctness oracle 引用，不转换成生产 SLA。

## 14. 文档边界

- 本文：组件、权威和故障边界。
- [runtime-lifecycle.md](runtime-lifecycle.md)：四态、资源屏障和降级。
- [storage.md](storage.md)：当前 ChunkStore 数据正确性。
- [Volume Authority and Disk Lifecycle](specs/volume-authority.md)：卷所有权、磁盘状态机和GC。
- [Runtime Volume Transitions v1](specs/runtime-volume-transitions-v1.md)：Node到Control的卷状态转换与签名evidence transport、事务边界。
- [Operations and HA](operations-ha.md)：运行拓扑、故障恢复和分层验证。
- `docs/specs/`：可实现、可测试的 wire/state 合同。
- `docs/decisions/`：为什么选择这些边界。
- `experiments/` 与实验报告：证据，不是规范。
