# Cats 技术架构

- 状态：目标架构 + 当前实现边界；ADR-0056 atomic lifecycle内部软件组成与
  [ADR-0057](decisions/0057-product-lifecycle-actions-and-internal-execution-evidence.md)六动作
  product adapter已落地并隐藏private`Start/Stop/Delete/Killed`；Route resolve使用`run_required`并严格拒绝
  旧`wake_required`。clean-slate release gate与production qualification仍未宣称完成
- 更新：2026-08-21
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

控制面到Node的协调模型整体切到每Cat一条atomic command lane。Node的恢复状态与active Cat数量成正比：

```text
PostgreSQL LifecycleOperation (one unresolved per Cat)
                 |
                 | exact command + typed predecessor
                 v
       Node durable command journal ---- MetadataStore owner/epoch CAS
                 |
                 | effects / recovery / strong stop
                 v
          exact terminal NodeResult
                 |
                 v
        PostgreSQL exact Operation settlement

Observation -> monitoring / diagnostics / capacity / drift only
```

通知、队列和缓存只能加速这个循环；丢失它们不能改变正确性。

## 3. 结构性问题

触发clean-slate切换的V1故障不是一串互不相关的 bug，而是六个系统边界没有闭合：

| 结构性问题 | 被替换的V1表现 | 终态规则 |
|---|---|---|
| 生命周期权威分裂 | Cat 行、Controller transitional state、NodeJob、heartbeat 和内存结果都能影响状态 | PostgreSQL只admit exact Operation；Node执行并返回exact result，Observation不结算 |
| 物理所有权不可恢复 | Agent重启会杀子进程，副作用后才写ledger，资源按hash猜名字 | Host lock、per-Cat scope、effect前checkpoint和完整物理inventory |
| 卷接管与Guest可用混在一起 | 过期lease可被普通Start抢占，block attach被当成mount Ready | normal acquire与proof-bound takeover分离；ext4 UUID/mount是Ready条件 |
| 路由能力与runtime事实脱节 | token有效期、共享mirror和Node generation共同充当route状态 | Grant只传递能力；Node本地gate/guard是最终admission authority |
| 怀疑被当成隔离证明 | heartbeat超时可能推动跨Node恢复 | timeout只产生suspicion；HostFenceEvent终结为HostLost后仍需typed recovery与逐卷授权CAS |
| 运行面缺少有界故障合同 | 同步PG阻塞async worker，故障域、告警和真实资格测试分散 | 有界DB执行、明确故障域、同一套可重复的Linux/metal故障矩阵 |

这些问题只能通过一次协调面重建共同解决。单独修NodeJob、延长TTL、增加重试或再建一份
状态表都会保留原来的多权威结构。

### 3.1 当前实现事实

仓库当前已组成clean-slate schema 17的signed atomic Runtime production spine；这不等于
release qualification已通过。下表把已实现边界与仍开放的边界分开：

| 范围 | 当前事实 | 目标差距 |
|---|---|---|
| ChunkStore | Rust engine、delta pack、golden root、NBD/vhost-user-blk、fencing 与 crash tests 已存在 | 保持格式和语义；补齐组合故障验收 |
| 控制面 | PostgreSQL schema 17、one-unresolved lifecycle/Route lanes、exact result settlement、volume receipt ledger、A23 policy/planner、atomic Cat-create、六动作product adapter与run_required fixed vector已组成 | 禁止终态/schema枚举、legacy parser absence、final digest vectors与真实RDS/HostFence仍是release gate |
| Node | production `noded`组成signed lifecycle/volume/Route clients、installed executor、Node-private journal/StopFence、full inventory与admission registry | 全部合法failure successor与retained cleanup链须通过crash matrix；exact release须过Linux/metal门 |
| inventory/session | Full/Partial `RuntimeInventoryReport`只作telemetry/attestation，accepted report可单调续期current AgentSession；legacy work routes不在production route map | timeout只产生suspicion，不得替代HostFenceEvent |
| route | v2 Grant、signed per-Endpoint poll/result lane、Node AdmissionCell/guard、mandatory installed listener/delivery、mTLS tunnel与gatewayd proxy已组成 | 真实production mTLS/rotation qualification与跨Node overlay仍分别开放 |
| Node restart | Host lock、per-Cat scopes、Node-private journal/physical manifest、installed full scanner、StopFence与response-loss replay已组成 | systemd 255 + KVM/Cloud Hypervisor exact-SHA证据与每个physical effect crash point仍是release gate |
| HA | bounded PostgreSQL执行、多副本lock DAG、exact Operation result commit、HostLost wire、takeover primitives与Control invalidation已实现 | current Control仍拒绝HostFenceRecovery admission；真实RDS failover、external/automatic Host fence与two-Node故障证据仍开放 |
| PersistentDisk | Cold-only append-only attach/detach、latest-config run继承、signed inspect/commit initialization、ext4 UUID、format/flush/drain与Cold/destroy mixed disposition已实现 | 完整product E2E、Snapshot/GC与crash矩阵仍须验收 |
| Placement/Guest network | A23 provisioner policy、同snapshot planner、immutable runtime config内的exact `/30`和per-Cat tap已实现 | 跨Node Guest overlay仍deferred |

除本节明确标成“当前事实”的内容外，后文描述的是accepted终态合同及其上线门，不能从规范中的
四态流程或验收oracle反推当前release已经完成对应实现或物理qualification。

### 3.2 组件职责

| 组件 | 只负责 | 不负责 |
|---|---|---|
| Control Plane | WorkOS/Workspace授权、资源API、runtime config、Operation admission/result、placement、Grant签发、fleet策略 | Running块I/O、逐请求Guest代理、Node-local postcondition重建 |
| Gateway | hostname解析、用户入口、缓存并转发不透明Grant | route authority、token重签、run或其他生命周期副作用 |
| Node Agent | Host资源、per-Cat atomic command/journal、物理inventory、VMM/blockd/route gate | 用户资源authority、跨Host自行抢占 |
| Cloud Hypervisor/Guest Agent | microVM执行、pause/snapshot/restore、vsock控制、Guest-local Runtime API | S3/PostgreSQL凭据和平台调度 |
| cats-blockd | 标准块协议、cache/pending、commit、lease/fencing | Cat placement和用户身份 |
| PostgreSQL | 控制资源事务、Operation、usage projection、volume root/lease CAS | VMM是否实际存在 |
| Object Store | immutable data/map/commit/archive objects | 当前writer和current root选择 |
| Metering | Node累计计数器、durable delivery、可重建projection/rating | 用desired allocation猜实际消耗 |

具体云产品只出现在 composition root和`adapters/`；domain/storage contracts不依赖AWS类型。

### 3.3 关键数据路径

- **create/run/suspend/warm/cold/destroy**：API事务admit exact product Operation；Node以current AgentSession签名poll已commit的目标Node
  unresolved command，持久接受后执行/恢复，再签名commit exact terminal NodeResult；Control只用该result
  结算。poll不创建/claim intent；transport unknown只repoll/repost同Operation。
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
| immutable runtime config、lifecycle command/causal head、placement与terminal result | PostgreSQL `CatRuntimeConfig` / `LifecycleOperation` | Node只持有exact command journal/high-watermark |
| Node schedulable、allocatable capacity、production capability、Guest IPv4 pool | PostgreSQL `NodePlacementPolicy`，只由provisioner/admin CAS | heartbeat、legacy node row和Node自报数字无权修改 |
| covered Workspace product API请求重放与不可变结果、Operation chain/result | PostgreSQL `ApiIdempotencyResult` / Control rows | 日志与Observation不是恢复/settlement依据 |
| VMM/blockd/Guest/snapshot 是否真实存在 | Node command执行、新鲜物理枚举和协议握手 | PostgreSQL observation只作telemetry |
| 当前恢复步骤 | 每 Cat 一个有界、原子替换的Node-private `LifecycleJournalRecord`及physical manifest | Control只见accepted/terminal boundary，不解释内部step |
| volume writer、attachment epoch、remote root | MetadataStore CAS | command config 是请求，不是写权限 |
| Relaxed 尚未远端发布的数据 | 原 Node 的 pending pack/journal，直到 `R == L` | 这部分不是可删除 cache |
| Endpoint 配置和 route epoch | PostgreSQL | Gateway 只缓存 |
| 当前 Node admission | Node 本地 route gate + active guards | 签名 Grant 是 capability，不是物理状态 |
| Node 存活/库存 | session-bound complete inventory/observation | timeout只是suspicion，不是Host fence或Operation result |

本地 checkpoint 缺失、损坏或与物理事实冲突时，Node 必须报告
`Blocked`/`Quarantined`；“没在文件里看到”不能推断 Cat 已 Cold。

只有能与业务rows在唯一Control PG事务原子提交的Workspace product mutation使用
`ApiIdempotencyResult`，以`(authenticated workspace, canonical route, Idempotency-Key)`唯一标识，并使用
[Volume Authority §3.3](specs/volume-authority.md#33-workspace-product-api-idempotency)冻结的统一byte-level
fingerprint：domain separator后依次length-frame workspace、matched method/route template、raw path-query、
If-Match presence/Generation和raw body，不做JSON/path/query语义归一化。调用者身份、当前Workspace
membership和route permission先通过；事务随后取得
该key reservation并优先读取result，再沿
`NodeIdentity -> current credential lineage（signed Node command适用时）-> AgentSession -> lifecycle Operation/Cat head -> HostFenceEvent -> authorization ->
VolumeRecord -> Disk/config -> DiskSnapshotRecord`的全局DAG锁定
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
- **Cat** 持有immutable runtime config、RootDisk、稳定Endpoint和current lifecycle chain投影。
- **RootDisk** 跟随 Cat 生命周期；只有显式 disposable-root Destroy 可以放弃未远端
  发布的 tail。
- **PersistentDisk** 独立存在且为 RWO；任何未知分类或残留 attachment 都要 fail closed。
- **DiskRecord** 只保存immutable product identity/size/durability、Active/Deleting和closed
  `Root {cat_id} | Persistent {Uninitialized|Initialized}`；Available/Bound来自current complete config，
  完成删除后row缺席。Disk与Volume全局一对一；Root与同Workspace Cat一对一，Persistent同时最多属于
  一个current config。product path中的`{disk}`只解析immutable disk ID，name不参与猜测。
- **Snapshot** 是远端 durable root 的不可变引用，不能引用仅存在本地的 `R < L`。
- **Operation** 精确绑定canonical command/fingerprint与typed predecessor，是唯一Control command/result row；
  PersistentDisk create/delete和Snapshot mutation同步使用API result，不创建自己的Operation。

## 6. 生命周期协调

### 6.1 Operation admission与causal chain

PostgreSQL在Cat-row transaction中保证每Cat最多一条unresolved
create/run/suspend/warm/cold/destroy Operation。存在unresolved时所有新external lifecycle request在创建row、使命令可被poll前返回
`LifecycleOperationInProgress`，不queue、supersede、preempt或cancel。只有exact authenticated Node result
提交PG才释放lane；Active trusted HostFenceEvent是唯一可把unreachable command终结为HostLost的外部例外。

每条command绑定canonical request/fingerprint、placement与closed typed predecessor：Genesis、SameNode、
CrossNodeColdHandoff或HostFenceRecovery。Control验证current chain head/legal successor，Node再以bounded local
result/checkpoint high-watermark或exact Cold/fence/volume receipts独立验证。same Operation ID异payload/target/
predecessor fail closed；normal cross-Node run只消费exact Cold handoff。

CatRuntimeConfig 是 append-only version history；Cat row 只以 exact config ID+digest 指向 current
version，每条 Operation 同样冻结该 exact version，不能覆盖旧 config 后改变已提交 command 的含义。
每个内部execution envelope都内嵌该完整versioned config；product adapter只暴露ADR-0057六动作。config包含shape、boot、完整volume/device/mount输入，并内嵌closed
`RuntimeNetworkConfig {isolated_ipv4, network_id, guest_mac, guest_ipv4, /30, gateway_ipv4}`；不保留独立
`network_config_digest`。Endpoint metadata/route epoch独立，
改变Endpoint不重跑run。shape/volume set仍只在exact Cold时修改，volume容量不可变。
volume config不嵌入owner/epoch；内部EnsureRunning request另以同序1:1 volume-authority vector冻结normal-unowned、
same-node-owned或HostFence takeover输入，并由command fingerprint整体绑定。
Guest binding按role闭合：Root只有RootBoot且无UUID/mount path，Persistent只有带exact UUID/mount path的
PersistentExt4。

### 6.2 Node command journal与strong stop

每个Node进程先取得Host-global lock；每Cat只有一个command worker与一个bounded
Node-private lifecycle journal。持久对象是最多6 MiB的
`LifecycleJournalDocument {checkpoint: LifecycleJournalRecord,checkpoint_content_digest}`；command record保存
canonical projection、一个superseded predecessor、`Accepted | Executing | Terminal`与可选embedded
StopFence，destroy的内部teardown清除executable command后改为`CompletedCommandReceipt`。内部effect step和physical
manifest都是Node-private implementation，不是public wire。Node在first physical effect前fsync
accepted command/effect identity，在return前fsync terminal result；Agent replacement在current
AgentSession与complete inventory下resume同一command。exact
重复poll/result repost返回original result；successor accepted后poll中晚到old command返回
SupersededOperation且零effect。production没有Control→Node lifecycle client；PG仍是intent authority。

Node独占command内部acquire/provision/device/network/VMM/pause/snapshot/drain/release/delete步骤、ambiguous
response postcondition discovery、rollback/strong stop与artifact classification。Control不解释这些steps。
missing/corrupt checkpoint、incomplete inventory或foreign evidence只Blocked/Quarantine，不能猜Cold或执行已停止，也不能
generic delete。

run/suspend/warm/cold/destroy需要证明旧执行停止时，在原动作内部安装durable StopFence、
join/neutralize stale workers、关闭AdmissionCell全部gate并做bounded graceful drain；deadline后强停
dedicated Cat scope并防止resurrection。`ExecutionStopped` proof不要求R=L/release/GC，只能嵌入原动作
result，不是product state/head/successor。private Stop/Killed wire可继续承载maintenance与causal evidence；
Control product adapter隐藏它，Operation GET对private maintenance Stop返回404。

destroy移除executable checkpoint后留下最小non-executable CompletedCommandReceipt供response-loss replay；exact
result-stored ack后才GC。任何command non-success前将artifact分类为adoptable、exact Cat-owned GC candidate、
retained authority/data或quarantine；generic GC不能删除Volume/pending pack/R<L/Persistent/foreign evidence。

### 6.3 Result settlement、identity与telemetry

provisioner先把`node_id`、provider验证的不可变Host identity和每Node credential绑定在
PostgreSQL；注册不接受Agent自报identity或fleet共享credential。Agent在请求前持久化
registration attempt，同一attempt重试返回同一session epoch；同Host新session使旧session永久
失效。不同Host不得接管同一`node_id`；旧identity先显式fence/retire，随后以新的NodeIdentity和
新`node_id` provision。atomic release直接提交clean-slate `RuntimeInventoryReport`，不保留
`NodeObservation` wire。Full/Partial都绑定current SessionBinding、report ID、session-local sequence与time；
Full另带session-local epoch、scan ID、canonical digest、完整sorted Cat facts及unattributed artifact
classifications并建立`RuntimeInventoryAttestation`，Partial只引用exact epoch/更新明确subset且不能覆盖或刷新Full。

Node只从root/provisioner安装的canonical local `NodeIdentity` artifact取得Node/Host/state-path lineage，
并逐byte绑定per-Node key；CLI、hostname/IP和IMDS不补身份。Control与Node只消费同一次release build冻结的
closed Guest payload/manifest，见
[Runtime Composition Artifacts v1](specs/runtime-composition-artifacts-v1.md)。
每个Cat telemetry只含placement、closed atomic command-journal phase/identity/digests、runtime incarnation与物理
state、artifact manifest/classifications、逐卷`R/L`摘要和typed conditions；不含Desired/revision/spec、legacy
reconcile/checkpoint、route gate/guard、Operation settlement或inventory read cursor。

控制面只接受current AgentSession的递增telemetry sequence；runtime inventory更新read model但不能admit、settle、
fail或supersede Operation。Operation只以绑定same identity/fingerprint的authenticated NodeResult结算；新的
external intent在unresolved lane期间直接拒绝。NeedsIntervention terminal释放lane但限制typed successor；
Killed与HostLost都是condition，不是stable state。

共享atomic合同见 [Atomic Runtime Lifecycle v1](specs/atomic-runtime-lifecycle-v1.md)，决策见
[ADR-0056](decisions/0056-atomic-per-cat-runtime-lifecycle.md)。注册的唯一终态入口仍是
`POST /v1/internal/runtime/agent-sessions`；它和全部internal runtime请求共用的per-Node签名adapter、
registration public error、session lease与release receipt路径由
[Agent Registration and Internal Transport v1](specs/agent-registration-transport-v1.md)冻结。complete
inventory/attestation与telemetry接受继续由
[Runtime Inventory and Telemetry v1](specs/runtime-inventory-observation-v1.md)提供shared foundation，
但其atomic wire是RuntimeInventoryReport；Signer与lifecycle settlement不消费physical telemetry来制造
Ready/Serving/result。

Node command内的normal/takeover acquire、exact release与disposable Root authorization consume仍走唯一窄
Volume transition boundary并绑定Operation/fingerprint/current session。authorization response-loss只按exact ID
读取immutable evidence；Node没有Control authorization/completion raw SQL credential。blockd继续只读/renew/
head-CAS，不得取得ownership transition或authorization read能力。

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

磁盘集合只在exact Cold result之后修改CatRuntimeConfig。poll/commit响应丢失时Node discover/retry同command/transition，
Control不靠Observation收敛。destroy在同一产品动作内部strong stop，再使每个Persistent `R == L`、normal release并retained
detached；任一Persistent失败都阻止Root discard。Root `R == L`走normal release/delete；default Root
`R < L`可消费exact disposable authorization后从Owned直接CAS到Deleting并提高epoch，再删authorized lineage。
authorization绑定destroy Operation/fingerprint、Node/Cat/placement、Root attachment/epoch/head、disposition与
Persistent completion；可达Node arm另绑定strong-stop proof，HostFence arm只绑定event/interrupted
Operation/HostLost digest，不伪造execution-stop proof。PersistentDisk不能使用。
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
初始化必须在exact UUID probe、device flush并把卷推进到`R == L`后，以current AgentSession签名的exact
EnsureRunning execution Operation/fingerprint、Guest/flush evidence、attachment/epoch/head提交CAS；事务锁
NodeIdentity/session/Operation/Cat head/Volume/Disk/config，Observation不参与。随后mount是run/create
RuntimeReady条件，route仍Closed。

Cat create同一PG commit写Cat/config、Genesis EnsureRunning execution Operation、唯一Root Disk、generation-zero/
Unowned Volume和exact result；Root没有Persistent初始化状态或第二个Disk Operation，响应不明的同key
重放不能产生第二组identity。Node随后以private journal/EnsureRunning physical manifest中的显式typed
provision step引用operator已发布
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
2. 控制面只为current lifecycle head投影的exact effective RuntimeReady与per-Endpoint terminal Serving
   receipt签发短期Route Grant；不要求应用端口已监听，Observation不授权。
3. Gateway把Grant连同Control Plane在同一snapshot从fleet/admin-owned A23 policy验证过的strict HTTPS
   Node transport target放入有界per-replica cache；registration/observation与legacy `nodes.agent_url`不能覆盖；
   Grant保持不透明，Gateway到Control Plane和Node使用认证且加密的机器连接。
4. Node验证签名、时间、Workspace/Endpoint/Cat/Node、runtime incarnation、per-Endpoint route
   epoch、hostname、协议和端口。lifecycle Operation/AgentSession不进入Grant，但Serving binding必须绑定
   exact admission session epoch。
5. Node在短`AdmissionCell`内比较当前installed gate并取得active guard；比较与guard取得
   不可分割，且该cell不执行任何外部I/O。

每Cat lifecycle lane与每Endpoint route lane只在shared AdmissionCell线性化。离开Running action的first
local effect关闭全部gate，再cancel/有界drain；internal strong stop到grace deadline可强停Guest/VMM并断开流。
RequireIdle Busy只有cell从未close时非破坏性，并由new head保留original effective RuntimeReady投影。

Endpoint A变化只提高A的route epoch；未变B的gate与既有Grant不受影响。任何gate一旦实际close
或结果不明，重开前都必须提高该Endpoint epoch；Agent replacement使AdmissionCell默认Closed、old Serving
因session epoch失效，必须burn epoch再Enable，不能从checkpoint复活。Node任意时刻只接受一个epoch。

只有Node在取得guard、连接Guest和发送任何upstream byte之前返回的typed stale rejection，
Gateway才compare-and-delete精确cache并singleflight刷新。当前HTTP/WebSocket请求不自动重放；
刷新只服务后续请求。Guest连接失败、部分响应或transport歧义不清route，也不触发业务重放。

每个Gateway cache有固定容量、resolve并发上限、per-host singleflight和短negative backoff。
控制面全断时只有已经预热该entry的replica能在token expiry前接新连接；不宣称fleet-wide冷cache HA。

Route正确性只依赖签名Grant、当前Node gate和原子guard。详见
[Route Grant v2](specs/route-grant-v2.md) 和
[ADR-0041](decisions/0041-node-verified-route-admission.md)、
[ADR-0056](decisions/0056-atomic-per-cat-runtime-lifecycle.md)。

## 10. 高可用故障合同

下表是accepted终态故障合同，不是当前release完成清单；已实现与仍开放的边界只以§3.1和
[当前跨组件证据边界](architecture-cross-review.md#当前跨组件证据边界)为准。

| 故障 | 保证 | 明确不保证 |
|---|---|---|
| 单个 API/Controller 退出 | 其他副本继续；从PG unresolved Operation查询/重试exact command | 内存队列不恢复，也不需要恢复 |
| 控制面全断 | 已Running的VMM/blockd和现有流继续；预热该entry的Gateway replica可在Grant过期前接新流 | 新mutation、显式run、Grant续期和冷Gateway cache |
| PostgreSQL/MetadataStore 暂时不可用 | Running 计算继续；Relaxed 可在本地配额内推进 `L` | Strict FLUSH、远端 publish 和 lifecycle drain 必须成功 |
| Object Store 暂时不可用 | cache hit 读和 Relaxed 本地提交可有界继续 | cache miss、Strict commit、Warm/Cold 转换 |
| Node Agent 退出 | 独立per-Cat units、Host lock、Node-private journal/physical manifest与完整inventory重建同exact command；新session的AdmissionCell默认Closed | 代理中的连接可中断、新admission短暂不可用；真实systemd/KVM/Cloud Hypervisor exact release仍须物理qualification |
| Node 网络分区 | 保留源，不在另一 Node 自动启动 writer | heartbeat timeout 不等于失效转移 |
| Host 永久丢失 | HostFenceEvent把exact unresolved op终结HostLost；HostFenceRecovery +逐卷CAS后从remote `R`恢复，旧epoch永久失败 | Relaxed `R < L` 的tail可能丢失，报告`DataLossPossible` |
| Warm/Suspended 局部损坏 | 保留卷安全后 Cold fallback | Host-bound 快路径本身不是 HA 副本 |
| Gateway 退出 | 其他 Gateway 可从控制面取新 route | 无共享镜像时，冷 Gateway 不在 CP 全断期间接新流量 |

目标AWS自动Node failover使用一个窄、可审计的EC2/BMC Host-fence adapter；该adapter及其物理故障矩阵
尚未进入当前完成声明。provider receipt只建立
绑定不可变Host/boot、旧session和fence attempt的Active HostFenceEvent，不直接创建placement或
writer。Control Plane以一个事务把exact unresolved Operation终结HostLost，再以typed HostFenceRecovery创建
新Operation/placement并绑定全部逐卷授权；每卷CAS后才恢复。旧Host网络持续隔离。首次consume
只从服务器端immutable authorization row读取payload，在同一PostgreSQL事务完成Volume CAS并写closed、
不可变receipt。

数据库调用在有界blocking executor/连接池中执行，不能让同步driver占住Tokio worker。
拓扑、故障检测、告警和测试机资格合同见[Operations and HA](operations-ha.md)。

## 11. 安全和运维边界

- Guest 不持有 S3、MetadataStore、WorkOS 或 Node 管理凭据。
- 用户身份、机器身份和 fleet break-glass 身份分离；所有资源按 Workspace 授权。
- Route Grant 私钥只在控制面 signer；Node 持有 key ring，Gateway 不解读或重签。
- production Running路径在独立per-Cat systemd units/scopes运行blockd/VMM，Node Agent另持Host lock；
  当前clean SHA仍需systemd 255 + KVM/Cloud Hypervisor资格证据。
- privilege separation 与跨 Node overlay 尚未实现，继续保持为后续工作。
- 审计事件可以追加、轮转和外送，但删除审计历史不影响恢复。

## 12. 模块和实施依赖

只拆五个有真实边界的模块；每个副作用使用所属边界的窄条件合同：

| 模块 | 负责 | 核心模型或算法 | 依赖 |
|---|---|---|---|
| A. Control truth | CatRuntimeConfig、ApiIdempotencyResult、LifecycleOperation chain/result、Endpoint/Serving、NodeIdentity/Policy/Session | PostgreSQL事务、one-unresolved constraint、typed predecessor、keyset placement | 共享身份/错误闭集 |
| B. Node command | Host lock、per-Cat command/journal/StopFence、scope、inventory、Host资源分配 | accept/fsync -> effect/discover -> strong stop/result/fsync -> replay/ack | A的Operation/session |
| C. Volume and disk | RWO lease、逐卷takeover、pack lineage、ext4、snapshot、delete | transition-id CAS、`R/L`屏障、Cold-only磁盘变化 | A的disk intent、B的checkpoint |
| D. Route and work admission | Endpoint lookup、Serving receipt、Grant、Gateway cache、Node gate/guard、RequireIdle | effective RuntimeReady + AgentSession、pre-admission verify、AdmissionCell线性化 | A、B，且C mount Ready |
| E. Operations and HA | 有界DB执行、控制面/Gateway副本、Host fence、告警、资格测试 | suspicion -> proof -> recovery，固定故障oracle | A-D全部稳定 |

依赖顺序是 `A -> B -> C -> D -> E`，但A的schema、B的Host基础和C的MetadataStore合同可在
接口冻结后并行实现。D只能在lifecycle source、session、incarnation和mount readiness已经可用后接入；E中的
Host恢复必须同时调用AgentSession、逐卷takeover和route close，不能先上线半条链。

严重程度也只有三层：

1. **阻止数据损坏或双写**：Operation predecessor/session、normal acquire/takeover、pack lineage、journal、
   `R/L`屏障、ext4初始化和route close。
2. **阻止单点故障进入用户面**：有界DB、Agent restart、控制面/Gateway副本、Host fence。
3. **不阻塞本轮的能力**：跨Host Warm/live migration、hotplug、Disk clone、Golden Image自动GC、
   overlay、privilege separation和新billing形态。

### 12.1 已完成边界与剩余验证顺序

1. schema 17、atomic lifecycle/Volume/Route signed lanes、installed Node executor/journal/inventory/
   AdmissionCell、Control exact settlement与六动作product adapter已组成；private Start/Stop/Delete/Killed
   不进入product projection；Route resolve只接受run_required；旧Desired/NodeJob/Observation settlement不在
   production composition。仅供显式回归的retired codec/harness也必须与production parser/export边界隔离。
2. 软件组成不覆盖current release的forbidden-enum/parser-absence、全部failure successor、
   final digest vectors、Snapshot/GC、外部Host fence或RDS failover门。
3. 先从production public spawn与真实PostgreSQL开始，穿过installed scanner、signed command
   runner与真实physical effect执行组合E2E；recording seam不能替代该门。
4. 独立native x86_64 Linux测试机对同一exact clean commit运行`quality.sh full`并保存不可变receipt。
5. 满足隔离、空闲、systemd 255和exact-artifact前置的metal Host再对两种适用block path运行新的
   clean-slate KVM oracle并保留同一SHA证据。没有合格Host或新oracle尚未绿色时，真实物理上线门保持Blocked；
   历史`deploy/metal/e2e.sh`四态结果不能替代它。

### 12.2 Clean-slate 部署

现阶段产品数据可删除，因此首次部署不迁移旧 runtime/data，也不做在线 authority 切换。完整、
有序的 reset、credential rotation、NodeIdentity bootstrap、qualification 与最后回滚点只由
[Operations and HA §8](operations-ha.md#8-首次终态部署)定义。继续使用 Chunk/Map/Delta 格式、
virtio/ext4 和四态，是因为它们是已验证且合适的终态设计，不是兼容要求。

## 13. 上线门

目标只能在以下 oracle 全部通过后称为“正确、稳定、高可用”：

- 多Control replica对same Cat只能admit一条unresolved command；competing request零row且不能进入poll；result已收到但
  PG result未commit仍不释放lane；
- 产品action只序列化create/run/suspend/warm/cold/destroy；internal `ExecutionStopped`不成为Operation/head/
  successor，`Start/Stop/Delete/Killed`不出现在product route或read projection，Route resolve不返回wake_required；
- typed predecessor/current head/result digest错一项都zero-effect；normal cross-Node run只接受exact Cold
  handoff；HostLost只来自Active trusted HostFenceEvent；
- signed poll只能返回本Node已admit unresolved exact command，signed result commit/ACK exact replay；command/effect/
  result各fsync边界crash后只resume exact Operation；successor accepted后late old command不作用新runtime；
  Observation不能settle；
- 同一Host只有一个持锁Agent；per-Node credential和已登记Host identity阻止另一Host自报node_id，
  幂等registration attempt解决响应丢失；
- 普通run在过期的其他owner上仍Blocked，只有精确handoff/fence takeover可提高epoch；
- pending pack与attachment lineage绑定；新attachment不能发布旧epoch本地写；
- crash后只能adopt、继续或quarantine，无孤儿删除、重复writer和lease抢占；
- covered Workspace product API fingerprint fixed vectors跨实现一致；每条mutation恰好分类到PG result或
  既有domain协议；same key只重放exact status/content-type/body，非法key/envelope在reservation前拒绝；
- PersistentDisk create只产生同事务Disk/Volume/201 result；membership来自current config；Disk/Volume一对一、
  Root/Cat一对一；initialization绑定current EnsureRunning execution/fingerprint/session、exact UUID/flush/owner/head与R=L，
  Observation不参与；
- Cat create连同Cat/config/Genesis EnsureRunning execution/Root/Volume/default Endpoint/result全有或全无；所有gate Closed；
- Root provision target由manifest+size+Map编码独立重算；step fsync、各PUT、CAS、响应丢失和Agent restart
  只能得到exact generation-1 target或保留exact blank重试，同transition不换object identity，任何其他
  generation绝不覆盖且device/VMM不提前出现；
- `DiskSnapshotRecord`直接进入GC mark set，Deleting状态阻止新attach并完成对象清理；
- snapshot业务变化与covered API result原子提交；create→delete后的旧create重放不复活row，跨Workspace
  mutation不写Operation/result或资源；
- destroy先在同一动作内strong stop且全部Persistent R=L/released/detached；default Root R<L只有exact
  Operation/fingerprint/Node/Cat/placement/attachment/epoch/head/disposition authorization CAS后可删；strong-stop与
  HostFence sum arms不混用proof，Persistent不能使用；
- Root direct delete拒绝；release/auth derive两种提交顺序只有一方成功；Disk delete begin
  原子写双方Deleting和202 result；多sweeper只能在provider cutoff/late PUT barrier和LIST强一致后以
  prefix-empty和exact completion CAS删除row；stale-empty adapter fail gate，且不创建job/第二Operation；
- `R < L` 时 Warm/Cold/detach/migrate 被阻止，远端恢复后能 drain；
- Host 未 fence 时不跨 Node 启动；takeover后旧epoch永久fail closed，旧Host不恢复workload网络；
- route/lifecycle race在AdmissionCell线性化；internal strong-stop grace timeout可force stop；RequireIdle Busy仅cell never closed时
  继承effective RuntimeReady；
- Serving绑定AgentSession；replacement默认Closed并burn epoch；未变Endpoint不因sibling mutation失效；
- stale route只更新cache供后续请求，任何可能已到Guest的请求都不自动重放；
- 双控制面与真实 RDS failover 不重复副作用；
- kernel-NBD 与 vhost-user-blk 运行相同安全矩阵。

实验数字只按原始环境、样本和 correctness oracle 引用，不转换成生产 SLA。

## 14. 文档边界

- 本文：组件、权威和故障边界。
- [runtime-lifecycle.md](runtime-lifecycle.md)：四态、资源屏障和降级。
- [Atomic Runtime Lifecycle v1](specs/atomic-runtime-lifecycle-v1.md)：command wire、causal chain、journal/result与验收。
- [storage.md](storage.md)：当前 ChunkStore 数据正确性。
- [Volume Authority and Disk Lifecycle](specs/volume-authority.md)：卷所有权、磁盘状态机和GC。
- [Atomic Runtime Lifecycle v1](specs/atomic-runtime-lifecycle-v1.md)与
  [Volume Authority](specs/volume-authority.md)：current Node到Control的command-scoped卷状态转换、receipt与事务边界；
  pre-cutover Runtime Volume Transitions spec已删除且旧wire严格拒绝。
- [Operations and HA](operations-ha.md)：运行拓扑、故障恢复和分层验证。
- `docs/specs/`：可实现、可测试的 wire/state 合同。
- `docs/decisions/`：为什么选择这些边界。
- `experiments/` 与实验报告：证据，不是规范。
