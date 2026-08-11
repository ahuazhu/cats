# ADR-0041：短期签名 Route Grant + Node 本地 admission gate

- 状态：Accepted
- 日期：2026-08-08
- 取代：ADR-0033、ADR-0039
- 依赖：[ADR-0040](0040-level-triggered-runtime-reconciliation.md)
- 规格：[Route Grant v2](../specs/route-grant-v2.md)

## 背景

Running HTTP/WebSocket 不应逐请求访问 Control Plane，否则数据库或控制面抖动会进入用户数据面。
短期签名 token 可以证明 Control Plane 曾授权一个 route，却不能证明目标 runtime、revision、
Endpoint binding 或 Node 本地 serving state 现在仍有效。只靠 TTL 会让旧但未过期的 token 在
unbind、replacement 或 teardown 后继续被重放。

当前 V1 已有 Ed25519 token、Gateway forwarding 和 Node verification，但没有以下终态合同。它不
构成本 ADR 的兼容基线；实现通过一次 clean-slate vertical cutover替换它。

## 决策

保留短期签名 capability，但最终 admission authority 是 Node 本地 gate。一次请求只有在以下条件
同时成立时才能连接 Guest：

1. Grant 的签名、`kid`、issuer、audience、wire version、字段和时间窗口有效；
2. 全部 claims 精确匹配 Node 当前 installed Endpoint gate；
3. Endpoint 与全局 lifecycle gate 都允许 admission；
4. Node 在该 Cat 的短 `AdmissionCell` 临界区内原子取得 active guard。

Grant至少绑定Workspace、Endpoint/hostname、Cat、Node、runtime incarnation、per-Endpoint route
epoch、protocol、target port和时间窗口。`runtime_incarnation`关闭VMM replacement ABA；
`route_epoch`关闭Endpoint serving lineage ABA。全局`desired_revision`仍用于reconcile、Operation、
checkpoint、observation和signer一致snapshot，但不进入Grant或Node serving compare。

## Authority 与签发

Endpoint mutation、递增的 route epoch、包含全部 Endpoint 的新完整 DesiredRuntimeSpec、hostname
lookup index 和 Operation 在一个 PostgreSQL transaction 内提交。lookup index只定位 current
revision，不是第二份 route authority。

Signer在一个PostgreSQL transaction snapshot中重新闭合Endpoint binding、Running desired、
placement、current provisioned NodeIdentity、A23 policy中的strict HTTPS Node transport target和current AgentSession。
target只由fleet/admin apply写入，registration/observation与legacy `nodes.agent_url`不能覆盖或fallback。
该session必须有fresh `AdmissionInventoryAttestation`；最新
per-Cat accepted observation引用同一inventory epoch，并报告applied revision、runtime incarnation、
platform Ready、installed Endpoint gate，且active signer `kid`属于`loaded_kids`。两类freshness都使用
PostgreSQL `accepted_at_unix_ms`。partial heartbeat不能覆盖full attestation。任一事实不成立就不签发；
Node自报时间、旧observation、未来revision和lookup index单独读取都不能授权。

Endpoint A的mutation创建新desired revision时，只提高A的route epoch，并先用checkpoint中的durable
`CloseGate {endpoint_id, old route_epoch}`精确关闭/fsync old binding，再drain A；changed A才持久化new
binding Closed并InstallGate；removed A在checkpoint仍保留old Closed binding时先从cell compare-remove，
确认absent后才删除checkpoint entry/推进step且不install。changed entry/InstallGate和removed deletion/next
step各自使用一次checkpoint replace。step不复制full binding，expected tuple来自
checkpoint top-level revision/spec/placement/incarnation与同一old entry。任一revision/binding不匹配都
零副作用，不能关闭后来revision的gate。binding和route epoch完全未变的Endpoint B不修改checkpoint
entry、serving gate、guards或cancellation，已有stream和旧Grant继续有效。同Cat的removed/changed/new
Endpoint delta按endpoint ID稳定，每个完整序列一次一个，不建立batch token。

每次full inventory前，runner在与checkpoint effect lane串行的mandatory pre-scan中检查process-local
AdmissionCell session。session只封闭保存由accepted Ready effect或complete scan确认的最后一个exact Running
gate Desired；它可在StartRuntime/final Mount建立，不要求checkpoint已经Stable。strict
Endpoint-only successor在一个cell临界区内立即latch并取消全部changed/removed Endpoint tunnel，未变
Endpoint保持原gate、guards和stream；durable CloseGate/drain/remove仍按Endpoint ID逐个完成。pre-scan只在
exact current Stable/cell、previous exact Stable + strict Endpoint successor的完整latch、exact RequireIdle
Busy/Open source，或current checkpoint与retained effect edge结算之一成立时，才允许Open gate继续存活；
前两类是概念上的exact-retained/endpoint-latched状态，不新增wire。已经Closed/untrusted的session可先
fail-close后正常返回。通过上述保留条件后scanner Incomplete/deadline按Degraded保留已证明gate；
pre-scan本身非完成或scanner显式corrupt/conflict/foreign必须全局fail-close并取消tunnel。

若revision同时改变runtime/placement/lifecycle/volume/mount/network/platform，则使用全局`CloseAdmission`关闭
全部Endpoint；Endpoint-only不得使用它。任何实际或不明close后的reopen都先通过新完整Desired提高相应
Endpoint route epochs。Agent restart/global close仍提高全部原Active Endpoint epochs，不能靠CloseGate
恢复旧epoch。Node任意时刻只接受一个epoch。

platform Ready 指 VMM、network、完整 disks/mounts 和 Guest transport Ready，不要求用户应用已经
监听 target port。应用 health是独立产品策略。

## Node gate 与 lifecycle

每个 Active Endpoint gate 保存完整 Grant binding和`Active|Closed`状态。每 Cat 一个
`AdmissionCell` 保存 per-Endpoint gates、全局 lifecycle admission、Endpoint/Platform guards 和
cancellation handles。token验证后的binding compare、gate check和guard increment在其中线性化；
它不执行网络、数据库、VMM、文件或fsync I/O，也不持锁跨`.await`。

Endpoint install先fsync Closed prepared token及同进程effect edge，再fsync Active token；最后一次fsync后，
以immutable launch Desired、live gate predecessor和current Endpoint successor三层authority重新闭合Host与
Guest物理事实，随后才compare-and-publish到内存，最后持久化completed postcondition。observation只能随后
报告Active。prepared只可在exact edge仍保留的同进程内重放；Active可由该edge继续，或在cell已等于exact
postcondition时只完成结算。重启默认Closed并烧掉Active/结果不明epoch。zero-Endpoint OpenAdmission同样先持久Stable/Open successor，最后barrier后才打开cell，cell后没有
尚待CAS的状态。Endpoint-only
close先fsync只含Endpoint/old epoch的CloseGate token，在cell内compare-and-close同entry完整old binding，
再fsync该entry Closed；相同binding已Closed是幂等postcondition，结果不明必须以同binding重试，或在
restart默认Closed后确认，确认前不能只写Closed。旧epoch永不重开，new binding必须使用更大epoch。Agent启动/
重启先结合current desired、checkpoint和complete physical inventory重建，证明闭合前全部Closed。

离开Running、runtime replacement、Node drain或placement change先关闭全部admission，再在cell外
取消并有界drain已有guards；未归零就保留runtime/writer并报告Blocked。active WebSocket的TTL到期
不撤销stream，只有显式cancel-and-drain、连接终止或进程故障结束它。

auto Suspend使用单revision条件转换：Control Plane以当前Running revision为compare condition，
提交一个携带`RequireIdle {attempt_id, source_revision, source_runtime_incarnation}`的完整Suspended
revision。Node只评估一次。guards非零时不改变cell/runtime，持久化terminal Busy，Controller随后
创建新的Running revision；guards为零时原子close，再在cell外验证watcher/quiesce。一旦close，
后续Busy或结果不明都保持Closed，不恢复旧epoch；fresh Running revision必须提高所有可能关闭的
Endpoint epochs。不得增加proposal、closure proof、proof consumption或第二次authority commit。
手动stop、drain、migration和destroy使用`CancelAndDrain`。

attempt在评估前以`Armed` fsync进checkpoint；restart只继续durable Closed后的后置检查，未结算的
Armed保守变成Busy并保持Closed，等待带更高epoch的fresh Running revision，绝不因后来变idle而
复用同一attempt。

## Gateway 与请求语义

默认 Endpoint 是公网应用入口。Gateway只按canonical SNI/Host路由，不要求WorkOS session，也不
替应用做用户鉴权；management API身份边界保持独立。Gateway -> Control Plane和Gateway -> Node
必须使用加密的machine-authenticated hop。Grant不暴露给client或Guest。

Gateway为每个replica维护有界LRU：positive/negative/in-flight总容量、单key waiter、resolve并发、
response size和deadline均有硬上限；per-host singleflight和短negative/backoff吸收miss风暴。
cache是可丢的availability optimization，不是authority，也不通过DynamoDB或另一份数据库共享。

只有Node在guard取得、Guest connect和任何upstream byte之前返回的authenticated typed rejection，
才能compare-and-delete精确token digest并singleflight resolve。这个resolve只更新后续请求；触发它
的当前HTTP请求或WebSocket upgrade绝不自动重放。guard取得后的Guest/app/stream失败统一是
`UpstreamUnavailable`，不刷新route。transport歧义也不重放，即使HTTP方法看起来幂等。

Node必须先验签，再比较request/local binding和gate；只有binding及Active gate都有效时才暴露
`Expired/NotYetValid`。这样`Expired`不会掩盖stale binding。详细错误闭集和refresh矩阵由规格冻结。

## Key 与故障边界

Signer只使用一个active Ed25519 private key；Node原子加载有界、版本化public-key ring。rotation
顺序是public key verifier-first、全部schedulable Node ACK、signer switch、等待
`last_old_issue_at + max TTL + clock skew`、删除旧public/private key。IaC只保存secret reference和
policy；private bytes不进入Terraform plan/state/artifact，也不进入Gateway、Node或Guest。

Control Plane全断时，已有stream继续，且只有已经预热对应entry的Gateway replica能在token expiry
前接新admission。冷/重启Gateway没有共享cache，不能在Control Plane全断时接新流量。Node/Host
partition不触发自动改投；恢复需要Active HostFenceEvent、新完整Desired以及逐卷authorization CAS。

## Clean-slate cutover

首次部署遵循 [Operations and HA §8](../operations-ha.md#8-首次终态部署)。Route 模块的硬前置是：
exact release 已删除旧 parser 和 DynamoDB mirror，旧 route credential 已轮换；Node 以全 gate
Closed 加载并 ACK 新 public ring 后，Gateway 才能启动。目标 release 只接受本 ADR 的 wire 和
authority 合同。

## 后果与验收

Running热路径不依赖Control Plane，撤销不必等待TTL；代价是Node必须持久化gate、重建inventory、
管理guards和key ring，Gateway必须接受per-replica warm-cache的明确可用性边界。

上线前至少证明：signer拒绝stale desired/observation revision，Node拒绝错误runtime incarnation/
route epoch；close竞态后无新guard；changed/removed A在close、fsync、replace/delete各边界的in-process
失败/重试只操作A，stale CloseGate不关闭new binding，A变更不修改或取消B；若Agent进程crash则全部
内存gate实际Closed并提高所有原Active Endpoint epochs，不能声称只恢复A；
RequireIdle guard Busy且cell从未close时不关闭route；任何实际或不明close后旧epoch不得重开，且
attempt始终不复用；active HTTP/WS正确drain；app port failure不刷新；当前request不重放；cache/DB
慢路径有硬界；rotation全过程fail closed；Control Plane outage的warm/cold Gateway边界与Host
fence oracle均成立。
