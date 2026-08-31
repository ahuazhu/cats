# ADR-0056：每 Cat 原子 Runtime 生命周期命令

- 状态：Superseded by [ADR-0059](0059-semantic-control-node-synchronous-protocol.md)
- 日期：2026-08-20
- 历史范围：本文的 Operation、poll/result、journal、typed predecessor、AgentSession 与 Route lane
  只记录已退役设计；不得作为当前实现合同
- schema组成修正：[ADR-0058](0058-route-ring-acknowledges-immutable-agent-session.md) 将终态推进到
  schema 18，并让Route ring ACK绑定immutable AgentSession history
- 部分取代：[ADR-0057](0057-product-lifecycle-actions-and-internal-execution-evidence.md)取代本文的
  公开`Start/Suspend/Warm/Cold/Stop/Delete`动作命名、独立`Stop -> Killed`产品head与直接product
  Operation投影；本文的atomic execution/authority边界继续有效
- 取代：[ADR-0040](0040-level-triggered-runtime-reconciliation.md) 的 lifecycle coordination、
  Desired-driven reconcile 与 observation-based Operation settlement
- 取代：[ADR-0041](0041-node-verified-route-admission.md) 中 drain timeout 必须保留 runtime/writer 的
  语义及其与 lifecycle revision 的绑定
- 取代：[ADR-0025](0025-destroy-disposable-root-without-remote-drain.md) 与
  [ADR-0042](0042-volume-authority-and-disk-lifecycle.md) 中 Deleted Desired/RuntimeStopped Observation作为
  disposable Root authorization input；保留Root discard产品语义与Volume Authority CAS/receipt
- 保留：ADR-0040 的 NodeIdentity、AgentSession、Host 全局锁、完整 inventory/attestation 与
  HostFence 边界；ADR-0041 的短期 Grant、per-Endpoint epoch、Node 本地 admission/guard 与 key
  rotation 边界
- Volume authority：[ADR-0042](0042-volume-authority-and-disk-lifecycle.md) 与
  [Volume Authority](../specs/volume-authority.md)
- 历史规格：已随 ADR-0059 切换从当前文档集删除；Git history 保留原文
- 实现边界：schema 18 atomic lifecycle/Volume/Route内部软件组成与ADR-0057六动作product adapter已落地；
  private Start/Stop/Delete/Killed execution wire/head不进入product projection；Route resolve只接受
  `run_required`并拒绝旧`wake_required`。其他current release gate
  与production qualification曾由已删除的历史规格维护；当前边界见
  [Architecture §3.1](../architecture.md#31-当前实现事实)

## 背景

ADR-0040 把生命周期建模为 PostgreSQL `DesiredRuntimeSpec(revision)` 驱动、Node per-Cat
level-triggered reconcile、observation 回传并结算 Operation。这个模型把用户命令、Node 内部恢复和
Control 对结果的判断分散在多个 authority 中：新的 revision 可以 supersede 仍有物理 effect 的旧
revision，observation 需要反推某次命令是否完成，Control 也必须理解 attach、VMM、route、snapshot、
local tail 和 release 的中间步骤。

这些问题不能靠更多 observation 字段消除。一次 Suspend、Warm、Cold、Stop 或 Delete 的正确结果取决于
多个本地 effect 的顺序、模糊响应后的 postcondition discovery、crash 后重放以及失败后的强 Stop；拥有
物理资源和本地恢复证据的 Node 才能闭合这个结果。

同时，ADR-0041 把有界 drain 超时解释为必须保留 runtime/writer。该规则适合非破坏性的
`RequireIdle`，却会让显式 Stop/Delete 永远无法给出终态。服务连接不能成为强制停止计算资源的无限
lease。

## 决策

每个 Cat 使用一个串行、原子、同步的 lifecycle command lane：

```text
Control PostgreSQL Operation
        ^
        | Node signed poll：只拉取已admit unresolved exact command
        |
Node durable command journal -> physical effects/recovery/rollback/local classification
        |
        | Node signed result commit：exact terminal NodeResult
        v
Control settles that exact Operation

Observation -> monitoring / diagnostics / capacity / drift only
```

这里“原子”不是一次 syscall 或数据库事务，而是调用方只看到一个冻结的终态结果与其已证明的
postcondition；命令内部可以有多个 crash-replayable effect。这里“同步”不是无限等待：Node 返回的响应
必须是终态，deadline、EOF、连接丢失或 malformed response 都是结果未知，Control 只能查询或以完全相同的
Operation 重试，不能据此创建替代命令。production传输固定为Node使用current AgentSession签名POST拉取已在
PostgreSQL commit的目标Node unresolved command，再签名POST exact terminal result；仓库没有、也不新增
Control→Node lifecycle client。poll只是delivery，不能创建/claim命令，PostgreSQL仍是intent authority；重复
poll join/resume同一journal command，result或ACK丢失则repost同一result，从而实现exact query/retry。

精确 wire、结果闭集、predecessor、journal、state transition、route interlock 与验收 oracle 曾由其
配套规格冻结；该规格已由 ADR-0059 取代并由 Git history 保存。

## Authority 与单 lane

PostgreSQL `Operation` 是 Control 唯一的生命周期命令与结果记录。每 Cat 在所有 Control replica 之间
最多有一个 `Unresolved` lifecycle Operation。只要该 Operation 尚未把 exact terminal result 提交到
PostgreSQL，所有新的外部 Start/Suspend/Warm/Cold/Stop/Delete 都返回
`LifecycleOperationInProgress`：不创建 Operation、不让命令进入poll batch、不排队、不 supersede、不 preempt，也
没有旁路 cancel。

Control 在一个事务中锁住 Cat 的 chain head，验证合法 successor，写入 canonical request、request
fingerprint、target placement 和 typed predecessor。Node 在第一个物理 effect 前持久化接受的命令；在
返回前持久化 terminal result。Control 只以该 authenticated result 结算同一 Operation。heartbeat、完整
或 partial observation、Control 对物理状态的推断都不能结算 Operation。

一条 terminal result 提交 PostgreSQL 后才释放外部 lane。`NeedsIntervention` 是 terminal result，因而
会释放 lane，但不是第五个生命周期状态；它的 typed result 限制后继命令。`Killed` 同样是 Stop 的
terminal safety condition/receipt，不是第五个稳定状态。

## Typed predecessor 与交接

每个命令必须携带以下四类 predecessor 之一：

- `Genesis`：只允许空链且完整本地 inventory 无冲突的第一次 Start；
- `SameNode`：绑定前一条 terminal result 的 Operation ID、kind、digest、Node 与 placement；
- `CrossNodeColdHandoff`：绑定成功 Cold、源 Node/placement 和每卷 normal release receipt；
- `HostFenceRecovery`：绑定 exact `HostLost` result、Active HostFenceEvent、旧 Node identity、目标
  placement 与逐卷 takeover authorization。

Control 验证 current chain head 和 successor legality；Node 再以本地 bounded result/checkpoint
high-watermark 或相应 storage/fence receipts 独立验证。相同 Operation ID 携带不同 payload、target、
predecessor 或 fingerprint 必须 fail closed。pre-acceptance mismatch 是零副作用
`StaleOperation`。正常跨 Node Start 只接受 Cold handoff，不把 Warm、Killed、failure 或
NeedsIntervention 当作可迁移 Cold。

每一类 lifecycle command envelope 都携带同一 exact、versioned `ImmutableRuntimeConfig`，使 Node 与
Control restart 后不必补读可变 product state。该 config 必须内嵌独立 clean-slate `RuntimeNetworkConfig`：
`isolated_ipv4` kind、network ID、Guest MAC/IPv4、`/30` prefix与gateway IPv4。它不保存或追随
`network_config_digest`；整个 immutable config 已由domain-separated canonical digest绑定，Node按这些
网络字段逐项准备和验证。

同一immutable product config不携带volume owner/epoch authority。每个StartSpec另带与config volume按位置
严格1:1的`StartVolumeAuthority`，并由整个request fingerprint绑定：Genesis/Cold只用exact
`NormalUnowned`，Suspended/Warm的same-Node Start只用`SameNodeOwned`；Killed后的same-Node Start逐卷绑定
exact predecessor receipt，仍被保留的卷用`SameNodeOwned`，未被保留的卷用`NormalUnowned`；
HostFenceRecovery只用逐卷`Takeover`。这样重用同一产品config不会暗中重用上次attachment或authorization。
volume的Guest binding也是closed role union：Root只用`RootBoot`且没有filesystem UUID/mount path；
Persistent只用`PersistentExt4 {filesystem_uuid, mount_path}`，禁止为Root伪造UUID或`/`。

Active 且可信的 HostFenceEvent 是唯一可以在没有 Node result 时从外部终结 lane 的例外：Control 把该
unresolved Operation 精确终结为 `HostLost {event_id, interrupted_operation_id}`。heartbeat timeout、
session replacement、用户 cancel 和新的 placement 都不能这样做；HostLost 不伪造 Cold 或 Killed。
恢复命令必须使用 `HostFenceRecovery` 并携带逐卷 takeover authorization。

## Node journal 与重放

Node 对每 Cat 只保存一个有界、可 fsync 的 command checkpoint，以及 bounded terminal
high-watermark。Agent crash/replacement 后先在 Host 全局锁、current AgentSession 和完整 inventory 下恢复
同一命令；不能把未知物理状态猜成 Cold 或重新执行一个新命令。

完全相同的 Operation 重poll/result repost返回原 terminal result，直到 Control 确认它已提交 PostgreSQL。一个
successor 在 Node 持久接受后，poll中晚到的旧命令返回 `SupersededOperation` 且零副作用。Delete 删除完整
checkpoint 后只留下有界、不可执行的 `CompletedCommandReceipt`；它保存exact command identity、Deleted
terminal response及其digests，只用于result repost/ACK recovery，不授予runtime、route、volume或cleanup
authority，并在收到exact result-stored acknowledgement后才可GC。

Node 自己拥有命令内部 effect、模糊响应发现、恢复、失败 rollback/strong Stop 与本地 artifact
classification。Control 不编排这些步骤，也不从 observation 重建结果。

## 生命周期结果与数据屏障

产品稳定态仍只有 Running、Suspended、Warm、Cold；Deleted 是资源终态。命令合同为：

- `StartCat`：成功返回本地 compute-ready 的 `RuntimeReady`；失败必须返回已 strong Stop 的
  `StartFailed(not_running, retained_evidence)`。RuntimeReady 只证明 VMM、设备、Guest/root 与 Guest-local
  network ready，不打开 Gateway、route 或 admission gate。
- `SuspendCat`：成功返回 `Suspended`；`RequireIdle` 在 AdmissionCell 从未关闭时可返回
  `SuspendDeclined(Busy, runtime_ready)`；其他失败先 strong Stop，再返回 not-running
  `SuspendFailed`。Suspended 保留 VMM/authority，已接受 block writes 到本地 `L`，允许 `R < L`。
- `WarmCat`：成功前关闭 route/work、使全部 retained volume `R == L`、验证 host-bound Warm snapshot 并
  停止 VMM/frontends。无法证明数据屏障时 strong Stop、保留 authority/evidence，返回
  `NeedsIntervention` 或冻结的失败结果。
- `ColdCat`：先 strong Stop；只有全部 Root 和 Persistent volume 都 `R == L`、normal release 完成且无
  Host-local recovery dependency 时才返回 `Cold`。任一 `R < L` 都不能 release、discard 或 takeover，
  必须保留 unique data/authority 并返回 `NeedsIntervention`。Cold 内部完成
  `Killed -> R == L -> release -> Cold`，Control 不拆分协调。
  normal-release receipt的canonical digest必须包含绑定同一command/volume的final durability proof
  （exact remote head、L=R、pending=0），不能把release authority与另报L/R拼接。
- `StopCat`：可达的 authoritative Node 必须安装 StopFence、join/neutralize command worker、关闭全部
  gate、做有界 graceful drain，并在 deadline 后强制停止该 Cat 的完整 dedicated scope，然后关闭
  frontends并阻止复活。成功返回 `Killed`；它不等待 route drain、GC、normal release 或 `R == L`，允许
  非 serving publisher 在 StopFence 下继续使 `L` 收敛到 `R`。丢失的 Host 不能声称 Killed。
- `DeleteCat`：总是先 strong Stop。所有 PersistentDisk 必须先停止写入、完成 `R == L`、normal release
  并成为 retained detached；其中任一失败都阻止 Root discard。默认 disposable Root 在
  `R < L` 时可由绑定本 Operation/Node/Cat/volume/attachment/epoch/head/disposition 的 exact authorization
  CAS 进入 `Deleting` 并 fence epoch；可达Node arm还绑定strong-stop result/proof，HostFence arm只绑定
  Active event/interrupted Operation/HostLost digest且不伪造strong Stop。随后删除authorized lineage；它不要求上传可丢弃 tail。
  只有 Root Delete 可走此路径。成功 `Deleted` 前不得留下 deferred destructive cleanup。

命令失败后的共同 strong Stop、每个 result 的精确字段与 successor table 只在规格中展开。

## Route 的双 lane 与共享 AdmissionCell

生命周期和 Route 是两个独立的串行 lane：每 Cat 一个 lifecycle Operation lane，每 Endpoint 一个 route
Operation lane；它们只在每 Cat 的一个 Node `AdmissionCell` 中线性化。Start 只到
`RuntimeReady`，随后自动 Route Controller 才能为当前 Endpoint 提交 `EnableRoute` 并进入
`Serving`。用户不直接用 Endpoint lifecycle 命令。离开 Running 的 lifecycle 命令持久接受后的第一个
Node-local effect，是关闭 lifecycle admission 和全部 Endpoint gate。

`EnableRoute`/Serving receipt 必须绑定 exact `SessionBinding`、source
lifecycle Operation、runtime incarnation 与 route epoch。Agent replacement 后内存 AdmissionCell 默认
Closed，旧 Serving 自动失效；Route Controller 必须 burn epoch 后重新 Enable。Grant 不增加 session
claim；新的 route epoch 与 runtime incarnation 足以使旧 Grant 失效。

如果 Enable 先在 AdmissionCell 线性化，随后 lifecycle close 会关闭并 drain；如果 close 先线性化，
晚到 Enable 以 stale/Closed 零副作用失败。Stop 的有界 drain 超时后可强停 VMM/Guest，晚到的 route
结果只是历史结果，不能恢复 Serving。该规则取代 ADR-0041 的“drain timeout 保留 runtime/writer”；
`RequireIdle` Busy 仍是非破坏性例外。

`SuspendDeclined(Busy)` 会成为新的 lifecycle chain head，但若 AdmissionCell 可证明从未关闭，其 result
保留原 `effective_runtime_ready`。Signer 比较 current head 投影出的
`effective_runtime_ready` 与 Serving receipt 的 source，而不是简单要求 Serving source 等于 head
Operation。任何实际或模糊 close 都使旧 Serving 失效并 burn route epoch。

历史 Route v2 wire、epoch 和 signer 快照由 Git history 保存；本 ADR 与该 Route composition 均已由
ADR-0059 取代。

## 保留的边界

本决策不削弱下列既有 authority：

- Host-global executor/lock、provisioned NodeIdentity、PostgreSQL AgentSession fence；
- session-bound complete physical inventory/AdmissionInventoryAttestation；partial heartbeat 不能制造
  complete scan；
- MetadataStore owner/epoch/root CAS、RWO、Strict/Relaxed、Volume Authority receipt 与逐卷
  HostFence takeover；
- trusted external HostFenceEvent，heartbeat timeout 仍只表示 suspicion；
- Route Grant 签名、machine-authenticated hop、key/ring rotation 和 per-Endpoint route epoch。

Observation 保留为 monitoring、diagnostics、capacity 和 drift 输入，但不再是 lifecycle、route 或
volume authority。

## Clean-slate cutover

这是一次全链路替换，不提供 Desired/reconcile 与 atomic-command 的双写、双读、translator、迁移或
兼容窗口。首次部署只有一个空目标 schema 与一套协议版本；旧 Controller、Node parser/write path、
credential 和仍能结算 observation 的组件必须在新服务启动前离场。旧 checkpoint 或未知 wire 必须
fail closed，不能导入成 atomic command journal。

Runtime Reconciliation v1 中仍被组合使用的 Host/Agent/full-inventory 基础合同可继续存在，但其
Desired lifecycle planner、revision supersede 和 observation settlement 不再是目标 authority。

## 后果

收益是用户命令、Node effect 与 Operation result 有一条可审计的精确链；Control 不再重演物理状态机，
旧命令不能通过 observation 或新 revision 作用于新的 runtime，Stop/Delete 也有真正有界的终态。

代价是 Node 必须拥有可靠的 fsync journal、exact replay、strong Stop 与结果保留，Control 必须把
per-Cat unresolved uniqueness、typed predecessor、result settlement 和 HostLost exception 做成数据库
不变量；Route Controller 还必须处理 AgentSession 失效、effective RuntimeReady 投影与 epoch burn。

生产接受前必须通过 Atomic Runtime Lifecycle v1 的 crash/ambiguity/stale identity/double-Agent、四态、
route race、Relaxed tail、Delete disposition、HostLost 与 clean-slate 验收矩阵。ADR的
Accepted只表示决策生效；软件组成与production qualification必须分别以上述current
实现边界与exact build/test receipt证明。
