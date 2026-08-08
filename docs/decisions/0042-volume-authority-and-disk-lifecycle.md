# ADR-0042：用一个条件状态机管理 Volume Authority 与磁盘生命周期

- 状态：Accepted
- 日期：2026-08-08
- 规格：[Volume Authority 与磁盘生命周期](../specs/volume-authority.md)

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

HostFenceEvent的授权派生、首次消费与Rejoined转换都先锁同一个PostgreSQL event行。authorization由唯一
Control Store writer在同一PG trust/transaction域写完整immutable payload；Node只携ID，不再增加第二套
签名。首次消费还锁authorization和VolumeRecord，在同一事务完成卷CAS并写closed、不可变
`AuthorizationConsumedReceipt`；
Rejoined先提交后，未消费授权不能首次生效。rejoin校验receipt以及当前卷是其直接结果或合法的
单调后继；卷已删除时改验精确`DeleteCompletionReceipt`。这些安全回执保留到相关event Rejoined，
随后按审计策略GC。

### 3. Node取得grant，blockd只采用grant

Node在RuntimeCheckpoint记录normal acquire/release的typed request或takeover authorization ID，调用MetadataStore并解析
模糊结果，然后把精确attachment/epoch交给blockd。release checkpoint还绑定完整物理
target、full-inventory/Desired读取位置、唯一transition ID、generation和disposition；响应丢失
只能重放同一request或采用精确的last-transition postcondition，不得从“当前是Unowned”
猜测成功。blockd验证、renew和publish，但不自行acquire、takeover或增加epoch。

data-dir和pending pack绑定volume、attachment、epoch和acquire transition。相同lineage可以恢复；
失效或不同lineage只能quarantine。

### 4. 磁盘管理先保持Cold-only

第一版磁盘集合变更和DiskSnapshot只在Cat稳定Cold且volume unowned时进行。不实现hot attach、
hot detach或Running Snapshot。volume 容量创建后不可变，删除现有 resize API；需要其他容量时
创建新 Disk 并由 Guest 复制。这避免为低频操作引入 maintenance writer、Map 扩边、Guest 文件
系统扩容和额外 crash recovery 状态。

### 5. 文件系统初始化必须先远端持久

PersistentDisk UUID在Control Store预定。Guest Agent执行唯一一次mkfs并probe结果；Node在
Control Store写Initialized前必须使blockd达到`R == L`。正确UUID可以幂等adopt；其他UUID、部分
格式或模糊且无法证明未执行的状态进入quarantine。

### 6. Snapshot产品row就是GC live-root

DiskSnapshot只在Cold/unowned时创建。create、delete和same-disk restore统一使用PostgreSQL
`ApiIdempotencyResult`：主键是认证Workspace、canonical route和`Idempotency-Key`，绑定canonical请求
fingerprint与不可变成功/失败结果；同key异payload fail closed。调用者身份、当前Workspace membership
和route permission通过后，API先取得该key的transaction-scoped reservation；精确result命中直接返回，
不依赖目标资源仍存在。只有miss才按`VolumeRecord -> Disk(owner Workspace)/Desired ->
DiskSnapshotRecord`锁序重验精确disk/volume/snapshot tuple，并在同一事务写业务变化和result。
跨Workspace miss回滚reservation，没有资源、Operation或result副作用。

create的`snapshot_id`由服务端首次事务分配且永不复用；事务同时插入唯一`DiskSnapshotRecord`与成功
result。该row同时是产品资源和GC live-root；delete原子删除该row并写通用result；restore原子前进
head/generation/epoch并写通用result。重放只读result，不能因record缺失重新
执行；已提交result不随Snapshot删除而GC。GC标记current Root和全部snapshot records。
Snapshot mutation同步完成，不创建Operation；产品row只表示当前资源，通用result只保存旧HTTP回答。
第一版只支持原Disk restore；不支持clone或跨volume COW。Disk删除遇到任一live record返回
`SnapshotInUse`且不隐式cascade；Golden Image第一版不回收。

### 7. 删除先关闭authority，再删除对象

普通删除只接受已经`R == L`并精确release且没有live `DiskSnapshotRecord`的Unowned卷。`begin_delete`
锁VolumeRecord后在同一PostgreSQL事务重验全部前置，并同时把Control Disk和VolumeRecord从Active
改为同一`Deleting(delete_id)`；normal acquire与它只能一方提交。sweeper在该提交之后断言没有live
`DiskSnapshotRecord`，
幂等删除volume对象，最后写`DeleteCompletionReceipt`并同时删除两边metadata。
completion receipt保存disk/volume/delete、normal exact `BeginDeleteRequest`或disposable authorization/prior
attachment的closed begin variant、deleting epoch和exact head。owner已清、object sweep完成及两边row已删除
是该receipt的固定语义，不存bool；因此Host rejoin在row删除后仍能验证同authorization的合法后继。

ADR-0025的disposable Root例外使用唯一的第二个入口：Control Plane根据当前Deleted Desired与
精确stop observation或Active HostFenceEvent签发
`DisposableRootDeleteAuthorization`，绑定delete ID、revision/placement、volume、attachment、
owner/epoch和remote head。HostFenceEvent来源按
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
以[Operations and HA §8](../operations-ha.md#8-首次终态部署)为唯一runbook。

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
