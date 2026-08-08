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

normal acquire、release和takeover都携带全局唯一`transition_id`与expected epoch。当前相同
transition重试返回原结果；被后续转换取代的旧重试返回Stale且无副作用。不同或晚到的transition
不能越过已经前进的epoch。所有ownership变化增加epoch。

TTL只用于健康判断。普通acquire永远不能因为另一个owner过期而抢占。takeover必须消费从可信
HostFenceEvent派生的逐卷授权；计划handoff使用release后normal acquire。删除无条件
`revoke_lease`。

HostFenceEvent的授权派生与Rejoined转换串行。Rejoined前，已消费授权必须匹配精确postcondition，
所有未消费takeover/delete授权必须已过`not_after`；转换后它们不能首次生效。

### 3. Node取得grant，blockd只采用grant

Node在RuntimeCheckpoint记录transition，调用MetadataStore并解析模糊结果，然后把精确
attachment/epoch交给blockd。blockd验证、renew和publish，但不自行acquire、takeover或增加epoch。

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

### 6. Snapshot是受GC保护的Root pin

DiskSnapshot只在Cold/unowned时以精确head创建。GC同时标记current Root和全部Snapshot Roots。
第一版只支持原Disk restore；不支持clone，不建立跨volume COW。Golden Image第一版不回收。

### 7. 删除先关闭authority，再删除对象

普通删除只接受已经`R == L`并精确release的Unowned卷。Volume进入`Deleting(delete_id)`后永久
拒绝新attach，sweeper再幂等删除volume对象和snapshot pins，最后删除metadata与Control Store row。

ADR-0025的disposable Root例外使用唯一的第二个入口：Control Plane根据当前Deleted Desired与
精确stop observation或Active HostFenceEvent签发
`DisposableRootDeleteAuthorization`，绑定delete ID、revision/placement、volume、attachment、
owner/epoch和remote head。MetadataStore消费它时直接把精确Owned卷CAS到Deleting、清owner并提高
epoch；CAS成功后才允许删除该lineage的`R < L`tail。它不经过Active+Unowned窗口，不能用于
PersistentDisk。Deleting是当前动作状态，不是长期历史ledger。

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
- disposable Root放弃tail只有一条精确、幂等且先fence writer的删除转换；
- filesystem readiness有可恢复的远端durability边界；
- 第一版不承担hotplug、clone和image GC的额外状态空间。

代价：

- 用户改变磁盘集合或snapshot前需要先把Cat变为Cold；容量变化需要新建Disk并复制数据；
- MetadataStore schema、ports、blockd pack/start协议、Node checkpoint和Guest Agent必须一次垂直
  切换；
- Host-loss takeover仍依赖真实provider/BMC隔离，不能由TTL自动完成。

这是一个完整cutover。只修改文档、只替换lease API或只增加checkpoint都不能建立本ADR的保证。
