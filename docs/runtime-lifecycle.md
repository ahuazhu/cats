# Runtime 生命周期

- 状态：目标合同；四态已实现，协调协议待 ADR-0040/0041 切换
- 决策依据：[ADR-0002](decisions/0002-lifecycle-states-running-suspended-warm-cold.md)、
  [ADR-0022](decisions/0022-relaxed-local-first-dual-watermark.md)、
  [ADR-0040](decisions/0040-level-triggered-runtime-reconciliation.md)
- 精确协调合同：[Runtime Reconciliation v1](specs/runtime-reconciliation-v1.md)

本文只定义稳定状态、转换顺序和资源屏障。Starting、Suspending、Warming、Stopping 是 Node
checkpoint/observation 中的 step，不是控制面的权威生命周期状态。

## 1. 四个稳定状态

| 状态 | Guest CPU/内存 | VMM | 本地状态 | 远端状态 | 绑定 |
|---|---|---|---|---|---|
| Running | 运行 | 存在 | cache；Relaxed 可有唯一 pending data | 最近 remote root `R` | 当前 Node |
| Suspended | pause，内存可 page-out | 存在 | VMM、blockd、lease、journal 全保留 | 可为 `R < L` | Host-bound |
| Warm | memory/device snapshot | 退出 | snapshot、cache、恢复身份 | 所有保留卷 `R == L` | Host-bound |
| Cold | 不保留内存态 | 不存在 | cache 可删；无 pending data | 所有保留卷 `R == L` | 无 Host 快路径依赖 |

Suspended 与 Warm 不能合并：前者保留 VMM，后者退出 VMM，唤醒路径和资源成本不同。

Warm 的 snapshot 是 Host 本地 `WarmRuntimeSnapshot`。产品 `DiskSnapshot` 是远端 durable Root
引用，合同独立。`Deleted` 是资源终态，不是第五种 runtime 状态。

## 2. 不变量

1. 每个 Cat 同时只有一个 Desired placement epoch；每个 Node 上只有一个 per-Cat reconciler。
2. 每个 RWO volume 同时只有一个有效 attachment owner/epoch。
3. 所有离开 Running 的路径先关闭 work/route admission，再处理 Guest、VMM 和 volume。
4. `R <= L`。Relaxed volume 的 `R < L` pending data 是唯一数据，不是 cache。
5. Warm、Cold、detach和计划迁移前，所有保留卷必须`R == L`；DiskSnapshot还要求Cat稳定Cold且
   volume unowned，并在一个PostgreSQL事务创建一条exact `DiskSnapshotRecord`；该row就是GC live-root。
6. Suspended/Warm 的 Host 快路径失败时，只有证明 durable data 安全后才能 Cold fallback。
7. RootDisk 跟随 Cat；PersistentDisk 生命周期独立，Destroy 默认只 detach。
8. Runtime shape 与磁盘集合只在精确 Cold 改变；V1 不做 hot attach/detach。
9. volume容量创建后不可变；不提供resize。DiskSnapshot record命名远端Root，只支持同盘restore。
10. Disk删除不隐式删除Snapshot；live `DiskSnapshotRecord`使`begin_delete`返回`SnapshotInUse`，
    Snapshot create/delete/restore与通用PostgreSQL `ApiIdempotencyResult`同事务结算，重放只读result。

## 3. 转换合同

### 3.1 Cold -> Running

Node 必须先验证当前 AgentSession、placement 和完整 inventory。普通启动遇到其他 writer 时
报告 `Blocked(OtherWriter)`，不得 revoke 或提高 epoch。

安全顺序：

1. 持久化当前 revision、placement 和新的 runtime incarnation。
2. 为完整磁盘集合做 normal acquire；若 Desired 带逐卷 takeover authorization，则按该精确
   tuple CAS。
3. 新Root仍是exact blank时，先fsync `provision_root_image` step，以control-only且Guest I/O关闭的
   blockd把Desired image纯确定CAS到exact generation-1 head；响应不明只接受exact target或重试exact
   blank，任何其他head/owner/epoch都fail closed。
4. provision确认后才准备virtio block frontend、per-Cat systemd scope、tap/vsock 和 VMM。
5. Guest Ready 后按稳定 device identity 验证所有磁盘。只有持久 initialization token、blank
   Root 和 generation 都匹配时，Guest Agent 才可格式化；异 UUID 或部分格式痕迹 quarantine。
   初始化写先 device flush 并 drain 到 `R == L`，Control Store CAS Initialized/消费 token 后才
   mount。
6. 验证VM shape、boot identity、volume size/epochs、UUID/mount集合和Endpoint target。
7. 在AdmissionCell内安装精确incarnation/route-epoch gates，发布Ready observation。

RPC 响应丢失时用 checkpoint、握手和物理 postcondition确认或重试同一 token，不能先 teardown。
新Cat若直接以Cold为目标，也必须先acquire并完成相同Root provision，再release；它不创建device/VMM，
generation-zero blank Root不能结算stable Cold。PersistentDisk initialization不使用这个step。

### 3.2 Running -> Suspended

先按第 4 节关闭 admission。Guest quiesce fence 再确认没有新工作。每个卷执行本地 durability
barrier，使已向 Guest 确认的数据至少到 `L`；Relaxed 此时不要求 `R == L`。最后 pause VMM
并 page-out。

只要 `R < L`，Host、blockd、journal、data directory 和 writer attachment 都必须保留。对象
存储故障不会强迫 Cat 进入更深状态。

### 3.3 Suspended -> Running

只在原 VMM/Host 上 resume。重新验证 session、process/incarnation、volume owner/epoch、Guest
Ready 和当前 Desired，最后才开 gate。失败时先尝试把 `R` 推进到 `L`；只有 durable data 已
安全且坏的本地快路径可替代，才删除快路径并 Cold boot，否则保持 Blocked。

### 3.4 Suspended -> Warm

保持 gates Closed，把所有保留卷 drain 到 `R == L`，再生成 memory/device snapshot，验证文件
identity 与 VMM postcondition，最后退出 VMM。模糊结果靠 inventory 判定，不能因超时删除源。

### 3.5 Warm -> Running

Warm restore 只在拥有完整 snapshot、volume roots 和恢复身份的原 Host 尝试。新 VMM 使用新的
runtime incarnation，因此旧 route gate 不可复用。设备状态、Guest identity、volume epoch 或
snapshot 不匹配时，只能删除已证明可替代的快路径，再从 remote Root 做 Cold boot。

### 3.6 Warm -> Cold

Warm 已保证 `R == L`。Node 删除已验证可替代的本地 snapshot/cache，释放所有 attachments，
并用 inventory 复核无 VMM/blockd/pending data 后报告 Cold。

### 3.7 Running/Suspended/Warm -> Cold

Running 先关闭 admission、quiesce Guest 并 drain。Suspended 若有 `R < L`，先恢复 publish worker
或保持源。所有保留卷达到 `R == L` 后，停止 VMM/blockd、释放精确 attachments，最后用完整
磁盘集合和 inventory 证明 Cold。

### 3.8 Deleted

Destroy先关闭admission并停止Guest/VMM。PersistentDisk必须完整drain/release，不能随Cat删除；
只有当前Deleted Desired明确disposable的RootDisk可以按ADR-0025放弃local tail。它必须先消费
绑定delete ID、revision/placement、immutable `authorized_node_id`、attachment、owner/epoch、head和
stop/fence证据的精确授权，
HostFenceEvent来源按`event -> authorization -> VolumeRecord -> Control rows`锁序，在同一事务写
Consumed receipt、把Volume从Owned转为Deleting并提高epoch、把Control Disk转为相同Deleting；提交后
才删除该lineage。未知卷、冲突identity或未完成fence/rejoin都阻止Deleted Operation成功。

待删除Disk必须没有live `DiskSnapshotRecord`，否则保持原状态并返回`SnapshotInUse`。Snapshot创建
先取得认证Workspace/route/key reservation，再锁VolumeRecord并重验Disk owner、Active/Cold/unowned，
与通用result同事务插入一条exact record；Snapshot删除同样原子删除该row并写result，Disk delete
不负责cascade。普通begin-delete同样锁VolumeRecord，并在
一个PostgreSQL事务原子把Control Disk与VolumeRecord从Active改为同一Deleting；normal acquire与它
只能一方提交。Volume对象清空后写`DeleteCompletionReceipt`并同时删除两边row；若相关
HostFenceEvent仍Active，该receipt保留到Rejoined。

Deleted Desired 作为 tombstone 保留，直到无可服务runtime/route、卷 disposition完成，且GC absence
proof严格二选一：负责Node当前session接受的complete inventory精确证明
checkpoint absent，或现有`HostFenceEvent`中的provider HostDestroyed receipt绑定旧Host/state path并
证明其storage永久销毁，同时由该Cat保留的tombstone/placement及immutable Host/state-path lineage匹配
event；index最新boot/session不必等于event的fence session。后者不伪造
AgentSession/inventory；一个Host event可验证多个Cat，network/power isolation不够，且两条路径都不能
跳过逐卷authorization、receipt和disposition闭环。

## 4. Work、route 与 RequireIdle

工作信号只来自显式 guard 和有 freshness 的 Guest observation，不用 CPU/load/静默猜空闲。

- HTTP/WebSocket 使用 per-Endpoint guard；exec/deploy/control 使用 Platform guard。它们都在
  同一个 per-Cat AdmissionCell 内原子检查 lifecycle admission 并取得 guard。
- Guest-local Runtime API 的 activity 由 Guest watcher 报告；信号缺失、过期或 watcher 不新鲜
  时 fail awake。
- `RequireIdle {attempt_id, source_revision, source_runtime_incarnation}` 是一个普通的 Suspended
  Desired revision。Node 先持久化 Armed，再只检查一次 guards。任一 guard 存在时 cell/runtime
  完全不变，持久化 terminal `PreconditionFailed(Busy)`；同一 attempt 后来变 idle 也不重试。
- guards为零时Node原子关闭全部admission、持久化Succeeded/Closed，再在cell外验证watcher
  fresh+idle和Guest quiesce。后续检查失败也结算Busy并保持Closed，不恢复旧serving epoch。
  restart发现结果不明的Armed时保守结算Busy且gate Closed。
- Control Plane 接受 Busy 后把该 Suspended Operation 置为 Failed，并创建新的完整 Running
  revision；若gate从未close则保留epoch，否则提高所有可能关闭的Endpoint route epochs。Node
  重新验证runtime/volume/route后只安装新epoch。
- 用户 stop、Node drain、destroy 使用 `CancelAndDrain`：先关 gate，再取消并有界等待 guards；
  超时保留源，不 teardown。

进入稳定 Suspended/Warm 后，控制面可根据 `stable_since` 提交下一个普通 Desired revision；
策略计时不绕过本地最终 fence。

## 5. Shape、磁盘与 placement

### 5.1 Shape 或磁盘集合变更

当前不是精确 Cold 时，变更请求返回 `PreconditionFailed(MustBeCold)`，不创建 revision。调用方
需要变更时使用两个普通 mutation：

1. revision A 保留原 shape、完整磁盘集合和 placement，目标 Cold；
2. A 的 Operation Succeeded 后，revision B 写入新 shape/磁盘集合和请求的目标状态。

每个 Operation 只绑定自己的 revision；Control Plane 不为两次请求保存额外 workflow。
volume size创建后不可变；需要其他容量时创建新Disk，并在两个稳定挂载之间由Guest复制数据。

### 5.2 计划跨 Node 迁移

V1 只有 Cold migration，同样使用两个普通 revision：

1. revision A 指向源 placement、目标 Cold。源关闭 admission，完成 `R == L`、停止 runtime、
   release attachments；A 的 Operation 由精确 Cold observation 结算。
2. A 成功后，revision B 提高 placement epoch、指向目标 Node，并恢复迁移前目标（通常
   Running）。目标使用新 attachment identity 做 normal acquire，从 remote roots 启动。

源未证明 Cold 时不创建 B；整个过程始终只有当前 Desired revision 是 authority。

### 5.3 Node 网络分区

heartbeat timeout 只产生 `NodeSuspected`。源可能仍运行且持有 Relaxed 唯一数据；控制面不得
据此提高 placement/attachment epoch。恢复连接后按 AgentSession、instance sequence、placement
和完整 inventory 对账。

### 5.4 Host 永久丢失

只有云API、BMC或等价系统的receipt建立可信、持久的Active `HostFenceEvent`后，控制面才能在
一个事务中把旧Pending Operation置为HostLost、创建新完整Desired/Operation/placement与全部逐卷
授权。Host event只是Host级隔离事实；每个volume还必须取得独立
`VolumeTakeoverAuthorization`，精确绑定旧 owner/epoch、新 attachment、Desired revision 和
目标 placement，并把目标`authorized_node_id`不可变写入payload。首次消费先锁同一PostgreSQL event行，
再锁authorization与VolumeRecord，在一个
事务中提高epoch并写不可变`AuthorizationConsumedReceipt`。对应 schema/CAS 由
[Volume Authority](specs/volume-authority.md) 定义。

Strict 从 remote `R` 恢复。Relaxed 也只能从 `R` 恢复并标记
`DataLossPossible(last_remote, last_observed_local)`；最后 observation 的 `L-R` 不是故障瞬间的
精确损失。

失联Host返回后，旧epoch永久不能publish，旧`R < L` lineage移入quarantine而不删除。它必须在
workload网络仍隔离时，以新boot/session完成完整inventory和清场；Control Plane还要核对该event
派生的全部takeover/delete authorizations。授权派生、首次消费和`Active -> Rejoined`共用event行
串行点：未消费授权必须已过`not_after`；已消费授权必须有匹配payload的不可变receipt，当前卷必须
是直接结果或更大epoch的合法后继；receipt包含Disk postcondition时Control Disk也必须匹配，两边row
已删除时必须有精确`DeleteCompletionReceipt`。
接受HostRejoinProof并把event持久转为Rejoined后，未消费授权不能首次生效，provider才恢复网络。

## 6. Inventory、故障与 Operation

Agent 启动/rejoin、adoption、orphan 判断、破坏性 cleanup 和不确定恢复都要求完整 union
inventory，期间 gates Closed。扫描不完整时报告 `Blocked(IncompleteInventory)`，不能推断 Cold
或先删再建。

已验证并稳定 Running 后，PostgreSQL、MetadataStore 或某项 inventory 短暂不可用时报告
Degraded，保持现有 VMM 和 admission，冻结新生命周期/破坏性副作用。发现确定的重复
VMM/writer、identity/epoch 冲突、未知 PersistentDisk 或无法归属的 `R < L` 时立即关 gates，
进入 Quarantined。

Condition 语义：

- `Progressing(step)`：正在收敛当前 revision；
- `Blocked(reason)`：前置条件暂未满足，Operation 保持 Pending；
- `PreconditionFailed(reason)`：本 revision 的条件转换终止，Operation Failed；
- `Degraded(reason)`：稳定服务继续，但不能安全推进新副作用；
- `Quarantined(reason)`：确定冲突，当前 Pending Operation Failed；修复/删除用新 revision；
- `DataLossPossible(...)`：Relaxed Host loss；
- `Ready`：当前 observation 满足完整目标 postcondition。

若 Operation 已经 Succeeded，后续健康变化不改写历史；Control Plane 创建新的系统修复 revision
来承载处置。N+2 达到同名状态不能完成 N。

## 7. 资源与计量

| 资源 | Running | Suspended | Warm | Cold |
|---|---:|---:|---:|---:|
| vCPU 调度 | 是 | 否 | 否 | 否 |
| VMM 进程 | 是 | 是 | 否 | 否 |
| Guest RAM resident | 是 | 低/可回收 | 否 | 否 |
| 本地 snapshot | 否 | 否 | 是 | 否 |
| blockd/attachment | blockd + ownership | blockd + ownership | blockd 退出；Host-bound ownership 可保留 | 已安全释放 |
| 本地唯一 pending data | Relaxed 可有 | Relaxed 可有 | 不允许 | 不允许 |
| remote root | 是 | 是 | 是 | 是 |

计量读取新鲜物理 observation，不读取 Desired 或 step 猜资源已释放。样本不新鲜时标记缺口，
累计计数器使用单调 checkpoint。

## 8. 验收重点

- 在 acquire、start、pause、drain、snapshot、stop、release、gate install 每个边界 kill Agent；
  重启后只能确认、重试、继续或 quarantine。
- Root provision在step fsync、manifest/Map PUT、commit PUT、CAS及CAS响应丢失各边界kill；restart只能以
  同一transition确认exact generation-1 target或在exact blank上重试，任意其他head不得覆盖，device/VMM
  不得提前出现。
- 活跃 HTTP/WebSocket 下 RequireIdle 必须 terminal Busy 且 cell 不变；同 attempt 不得重试。
- `R < L` 且 remote 故障时，Suspend 可完成，Warm/Cold/detach/migrate 必须阻塞且唯一数据保留。
- 非 Cold shape/disk 变更先失败，Cold 成功后的新请求才改 spec；计划迁移严格使用两个普通
  revision。
- volume size不可变；DiskSnapshot只在stable Cold/unowned时创建一条exact `DiskSnapshotRecord`，
  该row进入GC live set，只同盘restore。
- Snapshot create/delete/restore的业务变化与通用API result同一commit；重放只读result，restore的
  generation/epoch只前进一次。
- create→delete后旧create key重放返回原snapshot ID但不复活record；跨Workspace请求零副作用。
- live record使Disk delete返回SnapshotInUse；显式snapshot delete原子删除该row并写通用result。
- Host 未 fence 时不迁移；fence 后逐卷 takeover 错 tuple 全部失败，旧 writer/route/session 永久
  失效。
- authorization首次consume与Rejoined并发时只有一方先提交；takeover后release、delete后sweep都可
  用`AuthorizationConsumedReceipt`/`DeleteCompletionReceipt`证明合法后继，错或缺失receipt保持Blocked。
- normal acquire与begin-delete只能一方提交；HostFence disposable Root只有event/auth/volume/control
  同事务写receipt和两边Deleting后可删`R < L`，PersistentDisk同请求必须拒绝。
- kernel-NBD 与 vhost-user-blk 运行同一生命周期和数据屏障矩阵。

实验数据用于选择默认值和容量预算，不替代这些安全合同。
