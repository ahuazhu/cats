# ADR-0040：电平触发的 Runtime Reconciliation

- 状态：Accepted
- 日期：2026-08-08
- 取代：ADR-0027、ADR-0028、ADR-0030、ADR-0035，以及 ADR-0002 中的旧协调合同
- 规格：[Runtime Reconciliation v1](../specs/runtime-reconciliation-v1.md)
- Internal delivery/acceptance：[Runtime Inventory and Observation Spine v1](../specs/runtime-inventory-observation-v1.md)
- Volume transition transport：[Runtime Volume Transitions v1](../specs/runtime-volume-transitions-v1.md)
- composition：[Runtime Composition Artifacts v1](../specs/runtime-composition-artifacts-v1.md)

## 背景

当前实现把 `desired_state`、`observed_state` 和 `generation` 放在同一 Cat 行。Controller 先写
Starting/Suspending 等中间状态，再下发一次性 NodeJob；Node 的持久 ledger 又晚于物理动作。
heartbeat 最后把 Node 报告覆盖回 Cat 行。

因此意图、执行过程和物理事实没有清楚边界：旧动作可能作用于新 runtime，旧 observation
可能结算新 Operation；attach 响应丢失会形成控制面与物理挂载分叉；普通 Start 可能 revoke
其他 writer；Agent crash 后也缺少足以安全 adopt 的强身份。

这些不是在 NodeJob 上增加重试或状态字段能解决的问题。需要一次替换整条协调链路。

## 决策

Runtime 改为电平触发闭环：PostgreSQL 保存完整且单调版本的期望，Node 反复枚举物理状态并
收敛，每 Cat 只保留一份当前 checkpoint，Control Plane 用精确 observation 结算精确 revision
的 Operation。

```text
DesiredRuntimeSpec(revision, placement)
             |
             v
      per-Cat reconciler ----> physical runtime
             |                         |
             +-> RuntimeCheckpoint <---+
             +-> ObservedRuntimeStatus
```

审计不参与恢复，可以独立轮转。

## 权威边界

1. PostgreSQL 是 DesiredRuntimeSpec、placement、Operation 和`ApiIdempotencyResult`的权威。
2. MetadataStore 的 owner/epoch/root CAS 是 RWO writer 与 remote durability 的权威。
3. 带强身份的物理枚举和协议握手决定进程、socket、snapshot、journal 是否存在。
4. 强归属Cat/tombstone的cleanup只由该Cat的RuntimeCheckpoint保存crash recovery所需的
   当前步骤和身份；无法唯一归属的residue只Quarantine。checkpoint文件自删使用规格中
   唯一、单槽的NodeCleanupCheckpoint；两种checkpoint都不能推翻物理事实或自行授权cleanup。
5. Route admission 使用 [ADR-0041](0041-node-verified-route-admission.md) 的本地 gate/guard。

Volume 的精确状态机由 [Volume Authority](../specs/volume-authority.md) 定义；Runtime 只编排
它的窄acquire/publish/release/takeover/delete接口。Node到Control的acquire/release/disposable consume
只使用[Runtime Volume Transitions v1](../specs/runtime-volume-transitions-v1.md)冻结的签名mutation边界和
单一PostgreSQL transaction；authorization response-loss只使用同一规格的Control-signed exact evidence
read。Node没有Control表的raw SQL权限，blockd不获得ownership mutation或authorization read能力。

只有能把业务rows与结果在唯一Control PostgreSQL事务中原子提交的Workspace product mutation使用
`ApiIdempotencyResult`；精确scope、request envelope、fingerprint和重放合同以
[Volume Authority §3.3](../specs/volume-authority.md#33-workspace-product-api-idempotency)为权威。
Account/WorkOS、Billing/Stripe、fleet/admin、Node/internal、webhook和external-first route只使用已有
domain identity，不伪造system workspace或双重幂等。router gate要求每条mutation恰好归入其中一类。

heartbeat 只追加 observation，不写 Desired。Starting、Suspending、Warming、Stopping 是
observation/checkpoint 的 step，不是控制面的稳定状态或新 authority。

## NodeIdentity 与 AgentSession

Node 必须先由 IaC/管理员 provision。Control Store 保存 `node_id`、不可变 Host identity 和
per-node credential/public-key 或 provider principal 的绑定。注册服务验证该绑定，不接受
调用方自报身份，也不使用共享 fleet credential。Node、immutable Host和state path的provisioning
lineage一次写定且跨retire不可复用；换Host、换state path或重新provision必须使用新Node identity。

Agent 必须先取得固定 Host state path 的 kernel 排他锁。它在注册 RPC 前持久化随机
`agent_instance_id` 和 `registration_attempt_id`。同一 attempt 的重试返回同一 session；新进程
先解析遗留 attempt，再用精确 expected session epoch 做 CAS replacement。新 session 建立后，
旧 session 的 heartbeat、desired read 和 observation 永久拒绝。不同 Host 不得接管同一`node_id`；
旧identity先显式fence/retire，替换Host随后用新的`NodeIdentity`和新`node_id` provision。

这两个边界分工明确：Host lock 排除同机双进程，AgentSession 排除延迟包和跨 boot/session
复用，provisioned credential 排除另一台机器自称同一 Node。

Node本地identity artifact、identity-selected固定state path与Host lock，以及Control/Node共同消费的单一
Guest release payload属于composition，不增加数据库authority；exact path、provision/rotation和部署规则由
Runtime Composition Artifacts v1冻结。

## Desired、placement 与 Operation

每个 Desired revision 是可独立解释的完整快照，包含目标四态或 Deleted、Assigned placement、
完整 VM shape、磁盘、Endpoint 和 transition policy。revision、placement epoch、runtime
incarnation、attachment epoch 和 route epoch 各自防止对应 ABA。

一次covered product mutation在同一 PostgreSQL 事务写完整 spec、精确绑定它的 Operation和幂等result。提交前必须完成
合法性、Cold-only 与 placement/capacity 检查；没有 placement 时不创建 revision。每次 placement
改变也是一个新 revision 和 Operation，没有旁路调度权威。新 revision 原子 Supersede 旧的
Pending Operation。已选 Node 若明确拒绝不可满足的容量/能力，当前 Operation Failed；重新调度
只能创建提高 placement epoch 的新系统 revision。

Cat create把Cat、current完整Desired、runtime Operation、generation-zero且Unowned的唯一Root
Disk/Volume和exact API result放在同一PG commit；不留下半套identity。Root没有Persistent
initialization状态或第二个Disk Operation。generation-zero只表示Control identity已原子创建，不是可启动
postcondition；Node acquire后必须以RuntimeCheckpoint中的单一`provision_root_image` step把Desired指定的
immutable image确定性CAS为generation 1，确认前不暴露device或启动VMM。

其中Cat row只保存不可变`cat_id/workspace_id/name/created_at`，不复制Root、Desired、observation、placement或
Operation事实；Root关系只由`DiskRecord.role.root {cat_id}`和current完整Desired回答。Cat/Disk/Operation/API
result的创建时间取同一次PostgreSQL DB now，Cat的初始target只存在于Desired/Operation。

Operation 只有在 current desired、observation revision、placement 和完整 postcondition 全部
匹配时才成功；顶层observation Node、Operation placement、applied desired placement和current
desired placement必须绑定同一Node，applied/Operation/current desired与实际结算target也必须
相同。错Node返回`wrong_placement`，既不接受observation也不结算Operation。Blocked/Degraded保持
Pending；PreconditionFailed、Quarantined 和 HostLost 使当前 Pending Operation Failed，处置使用
新 revision。已经完成的历史 Operation 不因后续健康变化重写。

Deleted 是保留到物理 runtime、route 和 volume disposition 全部完成的 tombstone，不是立即
删行。Operation闭环后仍保留tombstone和关联observation index；只有Control Plane接受来自负责
Node当前session的complete inventory、精确确认该tombstone绑定的RuntimeCheckpoint不存在，或验证
现有HostFenceEvent中逐字段绑定旧Host且证明Host state storage永久销毁的provider HostDestroyed
receipt，并在GC事务用该Cat保留的tombstone/placement与immutable Host/state-path lineage精确匹配event，
才能GC。event的expected boot/session继续绑定fence/rejoin序列，但不要求等于该Cat index最近接受的
session。一个
Host级event可分别验证多个Cat，不复制Cat列表。两条absence路径严格二选一；HostDestroyed路径不伪造
AgentSession/inventory，普通network/power isolation不够。两条路径都不授予placement/writer，全部
volume authorization、receipt和disposition仍须逐卷闭合。

## 生命周期与变更

产品稳定态仍只有 Running、Suspended、Warm、Cold；Deleted 是资源终态。完整屏障见
[Runtime 生命周期](../runtime-lifecycle.md)。

- `RequireIdle {attempt_id, source_revision, source_runtime_incarnation}` 是一个普通的 Running ->
  Suspended Desired revision。Node 在 checkpoint fsync Armed 后只评估一次：guards 为零时原子
  关闭AdmissionCell并继续；一旦close就不恢复旧serving epoch。Busy时cell/runtime不变、该Operation以
  `PreconditionFailed(Busy)` Failed。Control Plane 随后创建新的完整 Running revision。同一
  attempt不因后来空闲而重试；restart遇到结果不明的Armed也保守结算Busy并保持Closed。fresh
  Running revision只在gate确实从未close时复用route epoch，否则提高所有可能关闭的Endpoint epochs。
- 用户 stop/drain/destroy 使用 `CancelAndDrain`，先关 admission，再取消并等待 guards。
- V1 的 VM shape 和磁盘集合只在 Cold 改变。非 Cold 变更请求直接返回
  `PreconditionFailed(MustBeCold)`；调用方先提交普通 Cold revision，成功后再以新请求提交完整
  配置。volume容量创建后不可变，不提供resize；DiskSnapshot只在stable Cold/unowned时创建，
  单一`DiskSnapshotRecord`同时是产品资源和GC live-root，只支持同盘restore。Disk delete遇到live
  record时返回`SnapshotInUse`。Snapshot create/delete/restore使用covered `ApiIdempotencyResult`与
  Volume Authority变化同事务结算；重放只读result，Disk delete不隐式cascade。
- 计划跨 Node 迁移同样只有两个普通 revision：源 placement 收敛到 Cold；成功后新 revision
  提高 placement epoch 并在目标 Node 恢复；整个过程始终只有当前 Desired 是 authority。

## Node 收敛

每个 Cat 只有一个 reconciler worker。每轮读取最新完整 Desired、当前 checkpoint 与所需物理
inventory，只执行一个有界、带 postcondition 的步骤。副作用前先持久化 revision、placement、
精确物理 identity 和窄 effect token；模糊响应后查询 postcondition，而不是回滚 Desired。

旧 effect 已经在 VMM/systemd 等本地边界线性化时，可能在新 revision 提交后才完成。合同不
假装消除这个竞态，而是保证：旧结果不能结算或授权新 revision，不能取得新的 writer/route/
placement authority；晚到的本地结果绑定精确 incarnation，由下一轮 adopt、停止或重建。

实现不增加通用 effect workflow。各边界只使用自己的最窄条件：

- volume acquire/publish/release 使用 owner/epoch/root CAS；release在RuntimeCheckpoint先持久
  唯一transition ID、generation、disposition与full-inventory/Desired读取绑定，响应丢失只重放
  同request或核对精确transition postcondition；
- 新Root image provision同样只用现有checkpoint和head CAS：`acquire_volume -> provision_root_image ->
  prepare_device`，step绑定image、size、attachment、blank和纯确定target；模糊结果只认exact target或exact
  blank，不把任意非零generation当成功，也不增加receipt；
- process/scope/socket 使用 runtime incarnation、start time 和 handshake；
- NBD/tap 使用完整 inventory 与 checkpoint ownership token；
- WarmRuntimeSnapshot使用temp identity、文件metadata和VMM postcondition；DiskSnapshot走Volume
  Authority的单一`DiskSnapshotRecord`；
- route使用AdmissionCell中的runtime incarnation/per-Endpoint route epoch compare-and-guard；全局
  desired revision仍用于reconcile和signer snapshot，不进入Grant serving binding。

planner 的逐步 token、条件和晚到结果处理以 Runtime Reconciliation spec 的表格为准。

standalone scope/socket只在token/path唯一匹配某个Cat checkpoint且当前Desired/tombstone
仍证实该归属时，才进入该Cat的cleanup step。删除checkpoint文件自身不能由该文件
充当journal；只能在Deleted tombstone仍保留且其他Deleted物理postcondition已满足后使用Node
单槽。单槽只是crash journal，不是新authority、queue或per-dispatch本地数据库。target仍存在时
必须重验tombstone；若当前session的新full scan已证明精确target不存在，则只清除已完成的Node
单槽不再需要tombstone。checkpoint path是inventory evidence而非checkpoint content；同path重建的
different-valid、corrupt或other-Cat文件必须保留，并拒绝旧cleanup/GC。

## Inventory 与稳定服务

Agent 启动、Host rejoin、adoption、orphan 判断、破坏性 cleanup 和不确定恢复必须先完成全量
union inventory，期间gate保持Closed。full scan在当前AgentSession下建立单调inventory epoch、
digest、read position与PostgreSQL `accepted_at_unix_ms`组成的`AdmissionInventoryAttestation`。普通增量
heartbeat引用该epoch，只upsert具体Cat，缺项不代表不存在，也不能覆盖attestation。Route signer
同时检查fresh attestation和fresh per-Cat observation，不要求每次heartbeat全量扫描。稳定Running
用独立、低频、有硬deadline的periodic full scan刷新attestation；失败先Degraded，过期后停止新
Grant签发而不猜测Quarantine。

Control Plane对当前AgentSession按heartbeat sequence接受observation：大于已接受最高值的新payload
在一个事务中原子应用；等于且完整payload相同是零新副作用的exact replay；等于但
payload不同是typed conflict；更小是stale。conflict/stale都不更新observation、freshness、
attestation或Operation。

全量扫描不完整时 Blocked，不做 cleanup。已经验证并稳定 Running 后，PostgreSQL、
MetadataStore 或某个 inventory source 的短暂故障是 Degraded：保留当前 VMM 和已验证 admission，
冻结新生命周期/破坏性动作。发现确定的重复 VMM/writer 或 identity/epoch 冲突则立即关 gate
并 Quarantine。

## Host fencing 与 Volume takeover

heartbeat timeout只产生怀疑，不能触发跨Node writer。provider/BMC receipt只可建立持久
`HostFenceEvent`，绑定不可变Host identity、Node、expected node boot、旧session epoch、fence
attempt和隔离状态。若同一event携带HostDestroyed receipt，还必须绑定provisioned state path，并由
provider adapter证明其storage永久销毁；这里绑定的是event创建时锁定且此后可retired、不可复用的
NodeIdentity lineage，不要求GC时仍为provisioned。不得从断电或网络隔离推断。每个Cat的旧placement只由现有
tombstone/placement及接受observation时从锁定NodeIdentity复制的immutable Host/state-path lineage在GC
事务匹配该Host event，不复制到event，也不依赖index最近的boot/session。
它是 Host 级事实，不是 volume 写权限。

`isolated`和`host_destroyed`还共享同一个provider fence success语义：旧Host principal不能再发起新的
BlobStore PUT，且cutoff前已被接受的PUT已经成功并对后继强一致LIST可见，或已永久失败。adapter返回前
必须跨过这个可验证barrier；单独power/network隔离、异步IAM revoke或进程消失不够。不支持者保持Blocked，
Deleting中的对象清理也不得写completion receipt；这不增加event字段或第二个proof authority。

HostDestroyed永不Rejoined。没有tombstone/recovery引用且全部authorization已terminal、逐卷disposition
闭合后，可按审计策略回收逐卷恢复记录；compact event/receipt仍按现有Operation/审计引用保留。

Control Plane先把旧Pending Operation置为HostLost，再在一个事务中创建新完整Desired/Operation、
placement、全部新attachments，并从该event和旧attachment facts为每个卷创建独立
`VolumeTakeoverAuthorization`，精确绑定 volume、旧 owner/epoch、新 attachment、Desired
revision、新 placement及目标`authorized_node_id`。该Node ID随authorization payload不可变，不随之后的
session/revision改变；receipt仍嵌在同一AuthorizationRecord且不重复它。MetadataStore 按 tuple CAS、提高
epoch；同一 authorization 幂等，
任何绑定变化都需新授权。DesiredRuntimeSpec 只引用授权 id。

逐卷授权的 schema、CAS 和状态机由 [Volume Authority](../specs/volume-authority.md) 定义。它与
本 ADR 是 Runtime Host-loss 路径的硬依赖；Node reconciler 不另设 lease revoke 路径。

旧Host仍保持workload网络隔离。新boot/session下完成全量inventory，把旧epoch的`R < L` lineage
移入quarantine，并核对该event派生的全部takeover/delete authorization与每卷current owner/epoch。
`isolated -> host_destroyed`用`state=Active + isolation_state=isolated + 完整event tuple`做exact CAS。
该更新、授权派生、首次consume、`Active -> Rejoined`和HostDestroyed tombstone GC都锁同一event行到
事务提交并在取得锁后重验；竞争只有一个顺序能提交。首次consume在同一PostgreSQL事务
完成Volume CAS并写不可变receipt。rejoin验证receipt以及当前卷是其直接结果或合法单调后继；
VolumeRecord已删除时验证精确`DeleteCompletionReceipt`。未消费授权必须已过`not_after`；Control
Plane接受HostRejoinProof并把event持久转为Rejoined后才恢复网络，此后未消费授权不能首次生效，
已消费授权仍可幂等读取原receipt。

Root direct Disk DELETE始终拒绝。对current stable Cold且Root已`R == L`、Unowned的Cat，covered Destroy
事务可原子验证current session/observation并写Deleted Desired/Pending Operation、normal BeginDelete与API
result；否则Node在current Deleted revision下以同一delete ID完成exact `R == L` cleanup/release，Control
Plane只凭新的current Unowned observation normal begin。两条normal路径都不保留历史Cold evidence。

disposable Root放弃`R < L`tail也不绕过volume authority。Control Plane只为当前Deleted Desired
和精确stop observation或Active HostFenceEvent建立`DisposableRootDeleteAuthorization`；
MetadataStore把精确Owned卷直接CAS到Deleting、清owner并提高epoch。成功后才可删除授权lineage，
PersistentDisk不能使用。可达Host的`R == L`先release，`R < L`才授权；Active HostFenceEvent下任何仍Owned
Root都可授权，包括最后`R == L`或L未知，不能等待已不可达Node release。release与derive以VolumeRecord
串行并在锁后重验，先release则derive回滚，先derive则release拒绝。

## 控制面运行方式

多个无状态 API/Controller 副本共享 PostgreSQL。周期扫描提供 correctness；LISTEN/NOTIFY 或
内存队列只降低延迟。数据库事务和 advisory lock 不跨外部 I/O。

已验证 Running 的数据面不依赖 Controller 心跳继续运行。控制面失联时不接受新 mutation，也
不启动新生命周期转换；Node 依据最后接受的 Desired 保持稳定服务或在已开始的安全步骤上
停住。

## 实施依赖与切换

模块依赖如下，开发可以并行，生产启用必须是一次完整 vertical cutover：

1. Control schema：NodeIdentity/AgentSession、完整 Desired/placement、Operation、observation。
2. Node 基础：Host lock、强进程身份、per-Cat checkpoint、checkpoint自删的唯一Node单槽、
   完整 inventory。
3. Volume Authority：normal acquire 与 HostFenceEvent 派生的逐卷 takeover CAS。
4. Runtime planner：有界 steps、四态 postconditions、AdmissionCell；Root provision同时从隐式
   `--seed-image-id`切换为显式typed blockd control request，Route 实现同时按 ADR-0041 切换。
5. crash/ABA/double-Agent/Host-loss/Deleted 验收矩阵全部通过后，才允许部署。

当前开发数据可删除，因此不做 V1 row 或 runtime 迁移。首次部署按
[Operations and HA §8](../operations-ha.md#8-首次终态部署)执行一次 clean-slate vertical cutover；
切换后只有空的新 schema 和一套协议版本，组件版本不匹配直接启动失败。ChunkStore 格式与 Guest
ABI 可以继续使用，但切换不依赖任何旧数据。
所有Runtime V1顶层合同都使用同名必填`version: 1`字段和同一严格decoder规则，不保留
`format_version`或为error/checkpoint定制的版本入口。

## 后果

收益是 authority 少而明确，恢复状态只随当前资源增长，重复 delivery 天然安全，故障测试能
直接验证物理 postcondition。代价是 Node identity、完整 inventory、强资源身份和逐卷 fencing
必须在启用前真正实现；只替换 Controller 或 Node 的一半不成立。
