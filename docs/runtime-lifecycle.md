# Runtime 生命周期

- 状态：Frozen product contract；产品动作只有`create/run/suspend/warm/cold/destroy`。
  current product route、CLI与Operation read已经使用这六个名称并隐藏Node-Control private
  `Start/Stop/Delete/Killed`；Route resolve使用`run_required`并严格拒绝旧`wake_required`。product
  vocabulary已闭合；其他release gate与production qualification见
  [Atomic Runtime Lifecycle v1 §11](specs/atomic-runtime-lifecycle-v1.md#11-acceptance-matrix)
- 决策依据：[ADR-0002](decisions/0002-lifecycle-states-running-suspended-warm-cold.md)、
  [ADR-0022](decisions/0022-relaxed-local-first-dual-watermark.md)、
  [ADR-0056](decisions/0056-atomic-per-cat-runtime-lifecycle.md)、
  [ADR-0057](decisions/0057-product-lifecycle-actions-and-internal-execution-evidence.md)
- 精确协调合同：[Atomic Runtime Lifecycle v1](specs/atomic-runtime-lifecycle-v1.md)

本文只组合产品稳定状态、产品动作与route/data屏障。用户面只有：

| 产品动作 | 含义 |
|---|---|
| `create` | 创建Cat与其初始运行所需资源；内部可启动首次run执行 |
| `run` | 从Cold、Warm或Suspended进入Running |
| `suspend` | Running -> Suspended |
| `warm` | Running/Suspended -> Warm |
| `cold` | Running/Suspended/Warm -> Cold |
| `destroy` | 删除Cat产品资源，不是第五个runtime state |

current product adapter已把Genesis private `Start`投影为create、其他private `Start`投影为run、private
`Delete`投影为destroy，并隐藏private `Stop/Killed`；这些旧名可以留在Node-Control执行协议，但不得出现在
product route、Operation或用户文档。`ExecutionStopped`是strong-stop/absence的内部证据，不是产品动作、
稳定状态、Operation terminal head或合法产品后继。private wire中的`Killed`只承载这类causal evidence，
不是同义产品概念。

exact internal wire、result fields、typed predecessor、Node journal/replay和验收vector由Atomic Runtime
Lifecycle v1管理；这些private类型不增加产品动作或状态。旧
[Runtime Reconciliation v1](specs/runtime-reconciliation-v1.md) 的Desired/reconcile/Observation settlement已被
取代；NodeIdentity、AgentSession、Host lock和complete inventory foundation继续保留。

## 1. 四个稳定状态

| 状态 | Guest CPU/内存 | VMM | 本地状态 | 远端状态 | 绑定 |
|---|---|---|---|---|---|
| Running | 运行 | 存在 | cache；Relaxed可有unique pending data | 最近remote root `R` | current Node |
| Suspended | pause，内存可page-out | 存在 | VMM、blockd、owner、journal保留 | 可为`R < L` | Host-bound |
| Warm | memory/device snapshot | 退出 | verified snapshot、cache、restore identity | 所有retained volume `R == L` | Host-bound |
| Cold | 不保留内存态 | 不存在 | cache可删；无pending data/attachment | 所有volume `R == L`且released | location-independent |

Suspended与Warm不能合并：前者保留VMM，后者退出VMM，恢复路径和资源成本不同。
`WarmRuntimeSnapshot`是Host-local VMM snapshot；产品`DiskSnapshot`是remote durable Root引用。

destroy完成是资源终点，不是第五个runtime state。`NeedsIntervention`是内部需人工介入的
terminal result/condition，也不是第五态。`ExecutionStopped`只能嵌入需要证明“已不再
执行”的命令结果，不单独投影产品condition或head。

## 2. Coordination与共同不变量

每个Cat在所有Control replica间最多一条unresolved lifecycle Operation。run/suspend/warm/cold/
destroy任一尚未把exact Node result提交PostgreSQL时，新的external lifecycle request返回
`LifecycleOperationInProgress`：不创建Operation、不让命令进入poll batch、不queue/supersede/preempt/cancel。

每条内部command绑定current causal head的typed predecessor。Genesis只用于create产生的首次
run；same-Node successor绑定exact local result digest；normal cross-Node run只消费成功Cold与全卷
disposition receipts；Host loss recovery绑定
HostLost、Active HostFenceEvent与逐卷takeover authorization。Node在first effect前fsync command，return前fsync
terminal result。production由Node以current AgentSession签名poll已commit unresolved command并签名commit result；
poll不创建/claim intent，transport unknown只repoll/repost同Operation，不存在Control→Node lifecycle client。

始终满足：

1. 每个RWO volume同时最多一个有效owner/attachment epoch；ordinary command不抢占其他writer。
2. `R <= L`；Relaxed `R < L` pack是unique data，不是cache。
3. 所有离开Running的动作，Node accepted后的first local effect是在shared AdmissionCell关闭lifecycle
   admission和全部Endpoint gate。
4. Warm、Cold、DiskSnapshot、detach、计划迁移与destroy中的每个PersistentDisk必须`R == L`；Cold的Root也
   必须`R == L`。
5. default Root仅在destroy的exact `discard_with_cat` disposition中可放弃local tail；PersistentDisk永不允许。
6. shape与volume set只在exact Cold result后改变；volume capacity immutable，不提供resize/hotplug。
7. missing/corrupt checkpoint或incomplete/ambiguous inventory只Blocked/Quarantine，不猜Cold或执行已停止，
   不blind delete。
8. heartbeat timeout只表示suspicion；不终结Operation、不fence Host、不授权writer/takeover。

## 3. Atomic command contracts

### 3.1 run -> Running | failure

create内含的Genesis boot使用同一private `EnsureRunning` executor，但不属于product run。run只覆盖
已有Cat的Cold boot、Suspended resume、Warm restore与合法same-Node retry。Node内部可以执行
normal/takeover acquire、Root provision、device/network准备、VMM launch/restore/resume与Guest readiness；
Control不协调这些steps。

run在产品上public只是一个动作，不是一组新的lifecycle state。执行较长时，
Node会在同一内部Run Operation内对已取得的Volume grant做exact monotonic renewal，并用私有
journal/physical manifest记住crash前做到哪一步。这些是lease安全和恢复机制，不增加
`Starting`、`Renewing`或`Resuming`等产品态，Control仍只看到accepted与一个closed
terminal result。current Rust内部仍使用`Start*`符号；它们已由Run product adapter隔离，不能
直接序列化给用户。exact private边界只在
[Atomic Runtime Lifecycle v1 §5](specs/atomic-runtime-lifecycle-v1.md#5-node-acceptancejournal-与-replay)定义。

immutable RuntimeVolumeConfig不携带lease authority；内部Run request另带与完整volume config有序1:1、由request
fingerprint绑定的volume authority vector。Genesis/Cold使用NormalUnowned，Suspended/Warm same-Node使用
SameNodeOwned；run failure后的exact same-Node retry逐卷消费该run result内嵌的retained receipt，保留卷使用
SameNodeOwned，其余卷使用NormalUnowned；HostFenceRecovery使用Takeover，不能从current row猜测或默认。
Root volume的Guest binding只能是RootBoot且不带filesystem UUID/mount path；Persistent只能是带exact
filesystem UUID/mount path的PersistentExt4。

`RuntimeReady`只证明local compute ready：exact VMM executing、shape/boot/device/network正确、Guest/root/
declared mounts与Guest transport ready、volume owner/epoch正确。它不证明Gateway、Route Grant、Endpoint gate或
application port；run success后全部route gate仍Closed。

任何terminal internal failure先执行strong stop，并在run failure中嵌入
`ExecutionStopped + retained_evidence`。返回前每个
created/adopted artifact都必须durably分类为exact adoptable state、Cat-owned GC candidate、retained authority/
data或foreign/ambiguous quarantine。失败不能留下normally Running runtime；generic GC不能删除volume、pending
pack、`R < L` tail、Persistent state、unknown path或restart safety source。

若该失败来自exact Warm restore，Node可在`retained_evidence.artifact_manifest_digest`指向的
私有terminal-retained manifest中保留原Warm cleanup authority。只有紧接着的
same-Node run retry且Node/placement/config/volume authority与全部digest完全匹配时才可
继续；缺失、篡改、已Transfer/Remove或非直接predecessor都fail closed，不回退到fresh run。
这仍是同一run合同的合法retry source，不是新的第五态。
若直接后继是合法cold/destroy，Node以同一exact carrier纯重绑为`Remove`，先持久化
cleanup authority，再按descriptor删除prepared payload/RAM；不根据路径猜测，不让generic
GC代替。普通、无retained carrier的run failure仍走原cold/destroy内部路径。

### 3.2 suspend -> Suspended | action-specific failure

成功Suspended前：route/work Closed且guards drained；exact VMM verified paused；Guest不能执行或提交新block
request；pause barrier前accepted writes已到local `L`；owner/epoch/blockd/journal/local lineage保留。Relaxed
允许`R < L`。

`RequireIdle`只有AdmissionCell原子检查发现active guard且证明cell从未close时，才返回
`SuspendDeclined(Busy, effective_runtime_ready)`。Declined成为new lifecycle head，但保留original RuntimeReady
source与route epoch；same Operation以后变idle也不重试。

一旦cell实际close或结果模糊，就不能Decline。无法证明完整Suspended的命令先strong Stop，再返回
`SuspendFailed(not_running)`；old route epochs被burn。

### 3.3 warm -> Warm | action-specific failure

成功Warm前：route/work Closed；每个retained volume exact `R == L`；WarmRuntimeSnapshot与exact runtime/
volume lineage durable且verified；VMM与Guest-facing frontend停止；checkpoint保留Host-bound restore identity。
Warm不因VMM退出而自动release volume ownership。

任何volume无法达到`R == L`时，Node strong Stop、保留owner/packs/journal/checkpoint/snapshot evidence并返回
NeedsIntervention。其他terminal failure同样先strong Stop并完整分类residue。不能因timeout删源或猜Cold。

### 3.4 cold -> Cold | action-specific failure

cold在同一内部command内完成strong stop与数据屏障：

```text
ExecutionStopped evidence -> every Root/Persistent R == L
                          -> Owned: exact normal release
                          -> already Unowned: closed provenance
                          -> Cold
```

成功Cold证明无VMM/Guest-facing frontend/active blockd/attachment、全部volume均以
`NormallyReleased | AlreadyUnowned`的exact disposition闭合且无Host-local recovery dependency。
Cold receipt与同variant的全卷disposition receipts是location-independent handoff；已Unowned的卷不伪造
attachment或release receipt。

任一Root或Persistent `R < L`都返回NeedsIntervention并保留unique data/authority；不release、discard、takeover
或generic GC。Control不能把heartbeat/inventory observation与“看起来没有进程”拼成Cold。

### 3.5 内部 strong stop 与 `ExecutionStopped` evidence

strong stop不是产品动作，也不创建独立product Operation。private maintenance Stop可承载同一proof但不进入
产品Operation namespace；run/suspend/warm/cold/destroy在需要证明旧执行已停止时，
由可达且仍拥有authoritative execution boundary的Node在该产品动作内部完成：

1. 安装durable StopFence，join current worker或neutralize stale worker；
2. 关闭AdmissionCell全部gate，cancel并做bounded graceful drain；
3. grace deadline后强停dedicated Cat的完整Guest/VMM scope，即使active HTTP/WebSocket会断开；
4. 关闭Guest-facing frontend，阻止systemd/old checkpoint/stale effect复活；
5. 把`ExecutionStopped` proof嵌入发起动作的result，并保留StopFence，直到same-Node run atomic replace、
   destroy remove或cold转source tombstone。

`ExecutionStopped` proof本身不等待route RPC、GC、normal release或`R == L`。StopFence下允许non-serving
publisher把已有`L`推进到`R`，但不能打开frontend/VMM/gate。unreachable/lost Host不能伪造此proof；只能由
trusted HostFenceEvent按相应产品动作的HostLost路径终结unresolved Operation。该proof不是product
chain head、condition或后继；private executor可以把它作为causal evidence读取，产品面只看到原动作outcome。

### 3.6 destroy -> resource absent | action-specific failure

destroy总是在内部先strong stop；所有non-success都嵌入`ExecutionStopped` proof。canonical disposition为：

```text
RootDisk       -> discard_with_cat
PersistentDisk -> retain_detached
```

Node在任何Root destructive action前发现完整Persistent set。每个Persistent必须停止写入、settle到final `L`、
达到`R == L`并保留为detached product Disk；Owned slot做normal release，已Unowned slot使用closed
provenance。任一失败返回NeedsIntervention，保留owner/data，
且Root尚未discard。

default Root不要求`R == L`：已`R == L`走normal release/delete；`R < L`只在Volume Authority消费exact
`DisposableRootDeleteAuthorization`后，Owned -> Deleting并提高epoch，再删除authorized lineage。authorization
绑定destroy Operation/request fingerprint、Node/Cat/placement、Root attachment/epoch/head、disposition与
Persistent completion；可达Node arm另绑定strong-Stop result/proof，HostFence arm只绑定Active event、
interrupted Operation与HostLost digest，不伪造strong Stop。

destroy成功前不得留下execution/frontend/open gate/restart source/storage lineage或deferred destructive GC。
Node写non-executable CompletedCommandReceipt供response-loss replay；Control settlement把Cat投影为资源不存在，
不新增Deleted runtime state。

## 4. Route/work两lane interlock

Route Controller从Endpoint metadata自动派生per-Endpoint EnableRoute/DisableRoute；用户不把Endpoint变化当
lifecycle command。每Cat lifecycle lane、每Endpoint route lane在一个per-Cat AdmissionCell中线性化：

```text
create/first run or run -> RuntimeReady -> EnableRoute(endpoint) -> Serving
leaving-Running action -> Closed -> internal ExecutionStopped evidence when required
```

Control只从current lifecycle head投影的effective RuntimeReady生成Enable/signing；接受任一leaving-Running
Operation的同一Cat-row transaction停止fresh generation。Enable先线性化可暂时install，lifecycle close随后关闭；
close先线性化使late Enable stale/zero-effect。late Route result不能恢复current Serving。

Serving binding/receipt绑定完整effective RuntimeReady、placement、runtime incarnation、route epoch与exact
`SessionBinding`。Agent replacement后AdmissionCell默认Closed，old Serving因session mismatch失效；Route
Controller burn epoch并fresh Enable。Grant无需session claim，fresh epoch+incarnation已拒绝old token。

SuspendDeclined成为new head时，Signer比较该head投影的`effective_runtime_ready`与Serving source，而不是要求
Serving source等于head Operation。只有cell-never-closed proof允许继承；actual/ambiguous close、Agent replacement
或incarnation改变都失效并burn epoch。

## 5. Config、磁盘与placement

current Cat不是exact Cold时，shape/volume membership mutation返回MustBeCold且不改config。调用方先提交
`cold`；exact Cold settlement后再单独修改immutable config并`run`。Persistent attach/detach/move锁同一
Disk/Volume/config rows；并发只能一方commit。

同一Cold window可append多个config，但不改写历史Cold Operation。下一次run冻结latest
current config：保留的旧slot继承Cold result的exact `NormallyReleased | AlreadyUnowned`
receipt，已detach slot只留在source evidence而不进入target，新attach Persistent slot必须从
fresh locked `Active + Unowned` authority构造`NormalUnowned`。新Persistent若仍Uninitialized，该次
run在route Closed时完成exact inspect、Guest ext4-unmounted probe、format、flush/drain到`R == L`、
signed commit和mount readiness；初始化不是另一Operation或产品state。

计划迁移只有typed handoff：source `cold`返回exact Cold + release receipts；Control提高target placement
epoch并创建`run`，其内部predecessor为CrossNodeColdHandoff。target normal acquire，不读取source checkpoint。

Node network partition保留source，不自动启动另一writer。Host永久丢失只有Active trusted HostFenceEvent可把exact
unresolved Operation terminalize为HostLost；recovery successor使用HostFenceRecovery并逐卷takeover。Strict从
remote `R`恢复；Relaxed也只能从`R`恢复并单独报告DataLossPossible。旧Host返回后旧epoch永久失败。
当前Control仍显式返回`HostFenceRecoveryUnavailable`；上述合同只有在external fence
producer、exact admission composition与two-Node qualification同时闭合后才开放。

## 6. Runtime inventory、status与计量

Atomic release的`RuntimeInventoryReport`只用于Node health/capacity、physical status、unexpected
death/resurrection、drift/degradation、manual intervention与metering，不保留旧`NodeObservation` wire。Full
建立session-bound complete attestation；Partial只更新exact epoch的明确Cat subset，不能刷新或制造Full。
report不admit、settle、fail、rollback、supersede或reopen lifecycle/route Operation，也不携带Desired/reconcile/
route/settlement authority字段。

用户product state只投影Running/Suspended/Warm/Cold或资源不存在；action-specific failure、
NeedsIntervention/HostLost可作为condition，`ExecutionStopped`不能。health/drift来自runtime inventory telemetry。
一次successful run后的later crash不改写历史run result；lane空闲后policy可请求新产品Operation。

计量继续读取fresh physical inventory与单调cgroup counter，不从command intent猜资源；样本不fresh时记gap。

## 7. 资源账本

| 资源 | Running | Suspended | Warm | Cold |
|---|---:|---:|---:|---:|
| vCPU调度 | 是 | 否 | 否 | 否 |
| VMM进程 | 是 | 是 | 否 | 否 |
| Guest RAM resident | 是 | 低/可回收 | 否 | 否 |
| local snapshot | 否 | 否 | 是 | 否 |
| blockd/attachment | blockd + ownership | blockd + ownership | frontend退出；Host-bound ownership可保留 | exact released |
| local unique pending data | Relaxed可有 | Relaxed可有 | 不允许 | 不允许 |
| remote root | 是 | 是 | 是 | 是 |

## 8. 验收重点

- command admission在多Control replica下严格one-unresolved；competing request零Operation且不进入poll。
- acquire/provision/device/network/VMM/pause/snapshot/drain/release/delete每个effect前后kill Agent，restart只resume
  same command；deadline/EOF/result或ACK loss只exact repoll/repost。
- run/suspend/warm/cold failure需要停止旧执行时均在原动作内strong stop并分类residue；poll中晚到old command
  不作用successor runtime，`ExecutionStopped`不成为独立head。
- active HTTP/WebSocket下RequireIdle Busy保持cell/source/epoch；close race和Agent replacement后old Serving失效。
- internal strong-stop grace timeout后真实强停完整scope，stale worker/systemd/checkpoint不能resurrect；
  外部不能创建Stop Operation。
- `R < L`时suspend可完成；warm/cold/migration/Persistent destroy全部fail closed并保留unique data。
- destroy所有Persistent先R=L/release/detach；default Root tail只在exact authorization+epoch fence后删除。
- Host未fence不迁移；HostLost/HostFenceRecovery/逐卷takeover exact tuple错一项均零effect。
- Runtime inventory rejection/sibling Cat错误不能结算或阻塞本Cat command。
- kernel-NBD与vhost-user-blk运行同一command/route/data屏障矩阵；exact commit通过full与native Linux gate。
- 产品route、request、Operation、terminal projection与successor只接受
  `create/run/suspend/warm/cold/destroy`，拒绝并且不序列化private `start/stop/delete/Killed`；Route
  resolve使用`run_required`，不再公开`wake_required`。
