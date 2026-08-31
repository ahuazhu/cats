# ADR-0042：用一个条件状态机管理 Volume Authority 与磁盘生命周期

- 状态：Accepted（storage CAS/receipt state machine保留；全部 lifecycle composition 已由
  [ADR-0059](0059-semantic-control-node-synchronous-protocol.md)取代）
- 日期：2026-08-08
- 规格：[Volume Authority 与磁盘生命周期](../specs/volume-authority.md)
- 当前产品组合：[Runtime 生命周期](../runtime-lifecycle.md)与同步 noded 协议；旧 command-scoped
  lifecycle transport 仅为历史实现

> 本 ADR 继续决定 owner/epoch/root CAS、RWO、L/R、条件transition和危险删除的存储边界。正文中
> RuntimeCheckpoint、Desired、Operation、AgentSession、signed transition与HostFenceRecovery接线均是
> 历史composition，不得接回当前ADR-0059生命周期。

## 背景

ChunkStore 的数据格式、Root CAS、delta pack和双持久化水位已经验证，但 volume外围的控制合同
仍不是一个完整系统：

- 普通 acquire可以在其他 owner的TTL过期后直接提高epoch；
- 同一 attachment重试 acquire也会再次提高epoch；
- blockd启动时自行取得lease，Node无法给它一个已经验证的精确grant；
- pending pack没有attachment identity，新epoch可能采用旧lineage的本地数据；
- resize可绕过writer authority，delete把TTL或控制面binding当成writer已停止的证据；
- ext4初始化、DiskSnapshot、GC、restore和对象删除没有端到端原子边界；
- Host级fence proof与逐卷takeover授权没有分层。

这些不是独立小缺陷。它们共同说明：系统缺少一份从Control Store意图到MetadataStore writer
authority、Node本地数据和Guest filesystem的磁盘状态机。

## 决定

### 1. 保留已经验证的数据面

继续使用 Direct-OS ChunkStore、immutable objects、Root CAS、4 MiB Chunk、64 KiB page Delta、
最多四层Delta、Golden Root、Strict/Relaxed、kernel-NBD和vhost-user-blk。它们是终态正确性，
不是历史兼容层。

### 2. 所有 ownership 变化使用条件 transition

normal acquire和release各携带`RandomId128 transition_id`，takeover只携服务器端authorization row的
`Id authorization_id`，delete保留`Id delete_id`；不造可混用的统一ID。VolumeRecord `last_transition`
的normal acquire/release/begin-delete variants保存完整typed request/direct result；takeover/disposable variants
只保存authorization ID marker，payload/receipt唯一保存在AuthorizationRecord，不保存Volume-domain request hash。
当前last-transition的同ID逐字段exact replay返回原结果，同ID异payload为Stale；被后续转换取代的旧重试
按当前state/expected epoch拒绝且无副作用，不增加第二份历史ledger。
所有ownership变化增加epoch。

TTL只用于健康判断。普通acquire永远不能因为另一个owner过期而抢占。takeover必须消费从可信
HostFenceEvent派生的逐卷授权；计划handoff使用release后normal acquire。删除无条件
`revoke_lease`。

lease请求只接受positive `lease_duration_ms`。唯一PostgreSQL事务owner用本事务DB time做checked-add并
在row中保存absolute expiry；过期只影响liveness/renew scheduling，不授予takeover或revoke。Remote head
始终是`generation + nullable root hash + nullable root object ID`的exact tuple：generation为0时后两者都
null，非0时后两者都non-null。

HostFenceEvent的授权派生与首次消费都先锁同一个PostgreSQL event行。authorization由唯一
Control Store writer在同一PG trust/transaction域写完整immutable payload；takeover与disposable payload都把
派生时的takeover目标new placement Node或disposable Deleted placement Node写为`authorized_node_id`，不因
后续session/revision改变。Node只携ID，不再增加第二套
签名。receipt留在同一AuthorizationRecord且不重复该字段。首次消费还锁authorization和VolumeRecord，
在同一事务完成卷CAS并写closed、不可变
`AuthorizationConsumedReceipt`；卷已删除后由精确`DeleteCompletionReceipt`证明合法后继。这些安全回执
按审计策略保留和GC。

### 3. Node取得grant，blockd只采用grant

Node在RuntimeCheckpoint记录normal acquire/release的typed request、takeover或disposable authorization ID，
本文原先只经Runtime Volume Transitions signed mutation/evidence read提交与解析；该pre-cutover spec、DTO、
codec和route parser已删除。current atomic release只经command-scoped signed mutation提交，模糊结果只重放
同一exact transition并读取immutable receipt；Node没有authorization/completion表SQL权限。
然后Node把精确attachment/epoch交给blockd。release checkpoint还绑定完整物理
target、full-inventory/Desired读取位置、唯一transition ID、generation和disposition；响应丢失
只能重放同一request或采用精确的last-transition postcondition，不得从“当前是Unowned”
猜测成功。blockd验证、renew和publish，但不自行acquire、takeover或增加epoch。

data-dir和pending pack绑定volume、attachment、epoch和closed
`AcquireOrigin = normal {transition_id} | takeover {authorization_id}`。即使ID文本相同，variant不同也不是
同一lineage；只有identity/pack/runtime evidence逐字段相同才可恢复，其他情况只能quarantine。
attachment专属`authorized-serving`文件使用closed tagged grant：normal保存完整request/result；takeover
保存Control-signed evidence返回的完整immutable `VolumeTakeoverAuthorization + TakeoverConsumedReceipt`，
绝不把A22的薄LeaseGrant或Node自构字段当成授权。takeover首次absolute expiry只能由
`checked_add(receipt.consumed_at, authorization.lease_duration_ms)`得到；current Volume必须保留exact
takeover marker、owner/epoch并与artifact head精确相等，artifact head只允许相对receipt head合法单调推进。

### 4. 磁盘管理先保持Cold-only

第一版磁盘集合变更和DiskSnapshot只在Cat稳定Cold且volume unowned时进行。不实现hot attach、
hot detach或Running Snapshot。volume 容量创建后不可变，删除现有 resize API；需要其他容量时
创建新 Disk 并由 Guest 复制。这避免为低频操作引入 maintenance writer、Map 扩边、Guest 文件
系统扩容和额外 crash recovery 状态。

### 5. 文件系统初始化必须先远端持久

`DiskRecord`固定保存immutable disk/workspace/name/volume/size/durability/created-at、Active/Deleting与closed
role：Root只含cat ID，Persistent只含`Uninitialized`或`Initialized`的token/UUID/blank-head lineage。
Available/Bound只从current complete Desired推导，Deleted由row缺席表示，不再复制产品状态。
`volume_id`在Disk rows中全局一对一；Root与Cat同Workspace且每Cat恰好一个；Persistent RWO同时最多出现在
一个current完整Desired。绑定与删除事务锁同一Disk/Volume/Desired rows，避免并发attach绕过约束。
product path中的`{disk}`只接受不可变disk ID；name只用于展示或显式lookup。

Persistent create在一个PG事务原子写empty exact Volume、Uninitialized Disk和201
`ApiIdempotencyResult`，同步完成且不创建Operation。Guest Agent执行唯一一次mkfs并probe结果；Node在
发出mkfs前还必须在最终retained-launch barrier后fresh确认同attachment/epoch的MetadataStore head仍逐字段
等于blank predecessor；Relaxed drain允许head前进，但post-drain fresh authority必须逐字段等于blockd的
fully-drained `R == L` status。Control Store写Initialized前必须再次probe exact UUID并使blockd达到`R == L`。
Mount每轮使用fresh current head，实际mount前在最终barrier后再读一次并拒绝lineage回退或同generation不同
root；只有完整Persistent mounted-set闭合才可打开admission。初始化事务不接收bool/
proof；它先锁current NodeIdentity，再锁AgentSession及highest accepted-observation receive-state，再按Volume→Disk→current
Desired→immutable observation锁序复用已接受的完整`NodeObservation` row，逐字段绑定observation ID、revision/placement、valid checkpoint的
`commit_initialized`、ObservedVolume owner/epoch/non-empty head与`R == L`lineage，再只更新Disk的closed
initialization variant；session replacement/observation advance竞争同一前缀，完整tuple重试幂等，冲突
fail closed，不增加transition ledger。

Root随Cat create在同一PG commit写Cat、current完整Desired、runtime Operation、Root Disk、generation-zero/
Unowned Volume和exact result。Root没有Persistent initialization状态或第二个Disk Operation；同key响应
不明只重放原operation ID。

### 6. Snapshot产品row就是GC live-root

DiskSnapshot只在Cold/unowned时创建。只有能把业务rows和result在唯一Control PostgreSQL事务原子提交的
Workspace product mutation使用`ApiIdempotencyResult`；完整scope、envelope与分类gate见
[Volume Authority §3.3](../specs/volume-authority.md#33-workspace-product-api-idempotency)。其主键是认证Workspace、canonical route和`Idempotency-Key`；fingerprint固定为
`SHA-256("cats.api-idempotency.v1" || 0x00 || u64-BE length-framed workspace/route/raw path-query/
If-Match marker+Generation/raw body)`，不做JSON、path或query语义归一化。row只保存status、可选
`application/json`、不超过1MiB的exact response bytes和created-at，不另存Operation状态。同key异payload
fail closed。调用者身份、当前Workspace membership
和route permission通过后，API先取得该key的transaction-scoped reservation；精确result命中直接返回，
不依赖目标资源仍存在。只有miss才按`VolumeRecord -> Disk(owner Workspace)/Desired ->
DiskSnapshotRecord`锁序重验精确disk/volume/snapshot tuple，并在同一事务写业务变化和result。
跨Workspace miss回滚reservation，没有资源、Operation或result副作用。

create的`snapshot_id`由服务端首次事务分配且永不复用；事务同时插入唯一`DiskSnapshotRecord`与成功
result。该row同时是产品资源和GC live-root；delete原子删除该row并写covered result；restore原子前进
head/generation/epoch并写covered result。重放只读result，不能因record缺失重新
执行；已提交result不随Snapshot删除而GC。GC标记current Root和全部snapshot records。
Snapshot mutation同步完成，不创建Operation；产品row只表示当前资源，covered result只保存旧HTTP回答。
第一版只支持原Disk restore；不支持clone或跨volume COW。Disk删除遇到任一live record返回
`SnapshotInUse`且不隐式cascade；Golden Image第一版不回收。

### 7. 删除先关闭authority，再删除对象

普通删除只接受已经`R == L`并精确release且没有live `DiskSnapshotRecord`的Unowned卷。`begin_delete`
锁VolumeRecord后在同一PostgreSQL事务重验全部前置，并同时把Control Disk和VolumeRecord从Active
改为同一`Deleting(delete_id)`。显式Disk delete API还把exact 202 JSON `BeginDeleteResult`写入covered result
并同步返回；它不创建Disk Operation。GET在row存在时观察Deleting，完成后404，但key重放始终返回原202。
直接Root Disk DELETE始终拒绝。Root的`R == L` normal begin只由现有current Cat lifecycle Operation驱动，
Cold fast path在同一covered PG事务验证current stable-Cold evidence并原子写Deleted Desired/Operation、
normal BeginDelete和API result；否则Node在current Deleted revision下以同一delete ID完成`R == L` release，
Control Plane只凭current Unowned observation normal begin。live Cold direct delete、旧revision或错delete ID
都拒绝；可达Host仍Owned且`R < L`只走既有disposable authorization，Active HostFenceEvent下任何仍Owned
Root（最后`R == L`或L未知也包括）同样走authorization。release与derive以VolumeRecord为branch gate并在
锁后重验，不能同时提交。
normal acquire与begin只能一方提交。

Deleting rows本身就是level-triggered work。sweeper不建job/claim/opaque proof，只分页扫描Deleting，
重验snapshot为空，幂等删除volume objects并从prefix起点重新列举到empty。用于完成判定的BlobStore LIST
必须对已完成PUT/DELETE线性可见；stale-empty adapter不合格。normal stop必须join upload workers；HostFence
路径只能使用已经完成provider object-write cutoff/barrier语义的HostFenceEvent：旧Host不能发新PUT，隔离前
已被接受的PUT已成功并对后继LIST可见或永久失败，因而empty之后不存在late PUT。不支持者保持Deleting。
最后一个PG事务才重新锁定并比较exact Disk/Volume/delete/head/epoch/last-transition，
写`DeleteCompletionReceipt`并同时删除两边metadata。失败保留Deleting，多sweeper只允许一个exact CAS
提交；这不是跨PG/object的两阶段事务或第二authority。
completion receipt保存disk/volume/delete、normal exact `BeginDeleteRequest`或disposable authorization/prior
attachment的closed begin variant、deleting epoch和exact head。owner已清、object sweep完成及两边row已删除
是该receipt的固定语义，不存bool；因此row删除后仍能验证同authorization的合法后继。

ADR-0025的disposable Root例外使用唯一的第二个入口：Control Plane根据当前Deleted Desired与
精确stop observation或Active HostFenceEvent签发
`DisposableRootDeleteAuthorization`，绑定delete ID、revision/placement、volume、attachment、
owner/epoch、remote head和派生时的immutable `authorized_node_id`。runtime-stopped路径是执行Node；
HostFence内部worker保留隔离placement Node但不借用Node HTTP。receipt仍嵌在同一AuthorizationRecord且不
重复该字段。HostFenceEvent来源按
`event -> authorization -> VolumeRecord -> Control rows`固定锁序，在一个事务写Consumed receipt、
把精确Owned卷CAS到Deleting、清owner并提高epoch，同时把Control Disk改为相同Deleting；CAS成功后
才允许删除该lineage的`R < L`tail。它不经过Active+Unowned窗口，不能用于PersistentDisk。
Deleting保留到对象sweep完成，随后由精确completion receipt证明结果。

### 8. 迁移只做两revision Cold迁移

源revision先收敛Cold、`R == L`并release；之后才创建目标Node上的Running revision和新placement
epoch。目标使用normal acquire，不使用takeover。Host丢失另走HostFenceEvent和逐卷授权。

## Clean-slate 切换

本 ADR 只声明存储前置条件：切换前删除当前开发数据、Cat、Disk、Snapshot、volume objects和
Node本地状态，目标release只读取本ADR定义的attachment identity和pack格式。完整、有序的操作
以[Operations and HA §10](../operations-ha.md#10-首次单协议部署)为当前runbook。

持久格式仍保留显式version、hash校验和未知版本fail closed。这些机制防止损坏或错误解释当前
数据，并不要求兼容切换前数据。

## 后果

优点：

- normal retry、planned handoff和Host takeover成为三个清楚、可测的合同；
- 旧writer、晚到请求和旧pending pack不能跨epoch复活；
- snapshot和delete不再绕过writer authority，resize入口被删除；
- snapshot必须显式删除，Disk delete不会静默删除live record保护的数据；
- disposable Root放弃tail只有一条精确、幂等且先fence writer的删除转换；
- filesystem readiness有可恢复的远端durability边界；
- 第一版不承担hotplug、clone和image GC的额外状态空间。

代价：

- 用户改变磁盘集合或snapshot前需要先把Cat变为Cold；容量变化需要新建Disk并复制数据；
- MetadataStore schema、ports、blockd pack/start协议、Node checkpoint和Guest Agent必须一次垂直
  切换；
- Host-loss takeover仍依赖真实provider/BMC隔离，不能由TTL自动完成。

这是一个完整cutover。只修改文档、只替换lease API或只增加checkpoint都不能建立本ADR的保证。
