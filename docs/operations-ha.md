# Operations and HA

- 状态：运维合同；atomic lifecycle内部软件组成与六动作product adapter已落地，private
  `Start/Stop/Delete/Killed`不进入product projection；Route resolve使用`run_required`并拒绝旧
  `wake_required`；clean-slate release gate、
  外部HostFence与真实production qualification均未宣称完成
- 决策：[ADR-0031](decisions/0031-control-store-on-postgresql.md)、
  [ADR-0032](decisions/0032-control-plane-multi-replica-and-postgresql-leadership.md)、
  [ADR-0038](decisions/0038-production-account-qualification-cell-boundary.md)、
  [ADR-0056](decisions/0056-atomic-per-cat-runtime-lifecycle.md)、
  [ADR-0057](decisions/0057-product-lifecycle-actions-and-internal-execution-evidence.md)
- Runtime：[Atomic Runtime Lifecycle v1](specs/atomic-runtime-lifecycle-v1.md)
- Host/Agent/inventory foundation：[Runtime Reconciliation v1](specs/runtime-reconciliation-v1.md)、
  [Runtime Inventory and Telemetry v1](specs/runtime-inventory-observation-v1.md)
- Route：[Route Grant v2](specs/route-grant-v2.md)
- Volume：[Volume Authority](specs/volume-authority.md)

本文定义运行拓扑、故障域、PostgreSQL/Controller边界、Host fence、监控、qualification与首次clean-slate
部署。旧Desired/reconcile/Observation-settled Operation不是目标运维路径；Observation只做telemetry。

## 1. 终态拓扑

- **Control Plane API**：至少两个stateless replica，共享PostgreSQL；不持有correctness-critical内存queue。
- **Controller/Route Controller**：可与API co-deploy；lifecycle intent只写PG。Node签名poll本Node已admit的
  unresolved exact command并签名commit result；Route按Endpoint独立派生Enable/Disable。LISTEN/NOTIFY只降latency。
- **Gateway**：至少两个replica；无共享route mirror，只有bounded per-replica Grant cache。
- **Node Agent**：每Host一个executor，固定state path kernel lock + provisioned NodeIdentity + current
  AgentSession；每Cat一个command journal/worker与shared AdmissionCell。
- **PostgreSQL**：Cat/runtime config/Operation/result、Endpoint/Serving、Node/session/fence、Volume Authority、
  product/API idempotency与usage projection的唯一事务域。
- **Object Store**：immutable Chunk/Map/Delta/Base/Snapshot objects；不决定current root/writer。

Route private key只在independent signer/secret boundary；Node只持versioned public ring，Gateway只搬运opaque
Grant。Guest没有S3、MetadataStore、Control或WorkOS credential。

已经Running的数据面不依赖Controller heartbeat继续执行。Node/Host loss恢复是external fence后从remote `R`
启动的新runtime，不是live failover；Suspended/Warm是Host-bound optimization，不是HA replica。

## 2. 故障合同

| 故障 | 继续 | 停止/降级 |
|---|---|---|
| 单个API/Controller退出 | 其他replica从PG Operation继续；exact retry安全 | 该进程内未提交response丢失 |
| Control Plane全断 | 已Running compute与existing stream；warm Gateway cache在Grant expiry前可新admit | 新mutation、command settlement、Grant续签、cold Gateway cache |
| PostgreSQL暂不可用 | Running compute；Relaxed可在local quota内推进L | command admission/result commit、Strict metadata CAS、route resolve |
| Object Store暂不可用 | cache-hit read、允许的Relaxed local commit | cache miss、Strict commit、warm/cold/Persistent destroy convergence |
| Node Agent crash/replacement | Host lock/session/inventory下resume exact command；systemd scope维持或StopFence保护 | proxy stream可能断；AdmissionCell默认Closed，old Serving失效 |
| Node network partition | source保持；不自动启动另一writer | heartbeat timeout只suspicion，unresolved lane保持 |
| Host永久丢失 | trusted HostFenceEvent终结exact op为HostLost，逐卷takeover后从R恢复 | Relaxed local tail可能丢失；报告DataLossPossible |
| Gateway退出 | 其他Gateway在Control健康时resolve | CP全断时cold replica不能接新流 |

所有timeout、queue、retry、grace drain与data convergence都有硬界。超界结果是typed backpressure、
Unavailable、unknown或NeedsIntervention；绝不自动变成fence、Cold、execution-stopped proof、release、discard或成功。

## 3. PostgreSQL、Controller与command lane

同步PostgreSQL driver只在bounded blocking executor/connection pool运行；不得占用async worker。每类request有
独立queue/running/deadline指标和容量预算。runtime command、volume transition、product mutation与telemetry
不能共享一个可被长query饥饿的single mutex/worker。

每Cat最多一个unresolved lifecycle Operation由Cat row lock + database constraint共同保证。accept transaction
验证current terminal chain head、typed predecessor、canonical request/fingerprint与legal successor；存在unresolved
时在Operation insert、使命令可被poll前拒绝。external network I/O不在DB transaction内。

Node response只有在authenticated identity、Operation/fingerprint/placement与terminal result digest完全匹配时，
才和Cat product projection同一commit settlement。一个Controller收到response但commit失败，lane仍unresolved；
Node可向任何replica重poll/repost same Operation。Observation/capacity/read model不参与settlement。

production runtime transport只允许Node→Control两条current-AgentSession signed POST：command poll只返回已在
PG commit、仍unresolved且目标为该Node的canonical command；result commit把exact response/digest与product
projection同事务保存并返回exact ACK。poll不admit/claim/renew Operation，Node不能创造intent；重复poll
join/resume本地journal，result或ACK丢失只repost同一result。没有Control→Node lifecycle client或legacy
`agent_url`旁路。

全局锁DAG的共同前缀是：

```text
ApiIdempotencyResult key / product name lock (where applicable)
  -> NodeIdentity
  -> current credential lineage
  -> AgentSession
  -> lifecycle Operation + Cat chain head
  -> HostFenceEvent
  -> per-volume AuthorizationRecord
  -> VolumeRecord
  -> Disk / CatRuntimeConfig / Endpoint
  -> DiskSnapshotRecord
```

事务跳过不相关节点，同类多row按stable ID排序；不得先锁Volume/Operation后反向取NodeIdentity/session。
ordinary normal acquire只锁其exact Volume domain row，但signed runtime transport在进入domain前必须闭合current
Node/session/Operation。API idempotency result与covered product mutation同commit；hit只replay saved status/
content-type/body，不从resource当前存在性重建结果。

Node command内部effect journal不是第二Control workflow。first effect前fsync accepted/effect token，return前fsync
terminal result；response unknown只repoll/repost exact identity。successor accepted后poll中晚到old command返回
SupersededOperation，历史API replay仍从PG返回original terminal result。

## 4. Host fence与HostLost

heartbeat timeout、lease expiry、route TTL、AgentSession replacement和Controller cancel都不是fence。Host recovery
顺序固定：

1. provider/BMC adapter对immutable Host/boot/session/fence-attempt执行外部隔离；
2. 保存并验证trusted `HostFenceEvent {state: Active}`；network suspicion或power API request本身不够；
3. 在一个PG transaction锁exact Cat unresolved Operation与event，把它terminalize为
   `HostLost {host_fence_event_id, interrupted_operation_id}`；不制造Cold或execution-stopped proof；
4. 为target placement创建HostFenceRecovery EnsureRunning execution，typed predecessor绑定HostLost digest、old Node identity、
   event与完整per-volume takeover authorization IDs；
5. 每卷在event -> authorization -> VolumeRecord锁序下CAS owner/epoch并写immutable consumed receipt；
6. target只从remote `R`启动，old epoch/route/session永久fail closed。

HostLost是normal command result rule的唯一external exception。HostLost wire与per-volume takeover
primitives已组成，但current Control仍明确拒绝`HostFenceRecovery` admission。production
HostFence producer、exact successor composition与physical qualification是同一独立上线门；
在它们完成前unreachable unresolved lane宁可保持blocked，也不能用timeout解锁。

Root destroy的HostFence authorization arm只绑定event、interrupted Operation与HostLost digest，不伪造
strong-stop/absence。可达Node disposable Root arm才绑定current AgentSession、strong-stop result/proof与complete
inventory。两者都还须绑定destroy Operation/fingerprint、Node/Cat/placement、Root attachment/epoch/head、
`discard_with_cat`和Persistent completion；Persistent任何`R < L`都使destroy NeedsIntervention。

## 5. Route与Agent replacement

每Cat lifecycle lane与每Endpoint Route lane只在shared AdmissionCell线性化。接受leaving-Running Operation的
Cat-row transaction同时停止new signing/Enable generation；Node accepted后的first local effect关闭lifecycle与
全部Endpoint gate。

Serving receipt/installed binding绑定effective RuntimeReady source、runtime incarnation、route epoch与exact
`admission_session_epoch`。Agent replacement后memory cell默认Closed，old Serving自动失效；Route Controller
burn epoch后fresh Enable。Grant不增加session claim。

SuspendDeclined(Busy)成为new lifecycle head，但只有cell-never-closed proof可保留original
effective_runtime_ready；Signer比较head projection而非`Serving.source == head op`。actual/ambiguous close、Agent
replacement或incarnation change都burn epoch。

需要停止旧执行的产品动作在bounded guard drain后可internal strong stop Guest/VMM并drop connection；active
stream不是无限execution lease。该proof嵌入原动作result，不创建产品Stop/Killed head；RequireIdle Busy仍是
non-destructive例外。

## 6. 运行监控

至少监控：

- Control：PG pool/queue/running/deadline、transaction retry/serialization、per-Cat unresolved age、signed poll
  空/重复/拒绝、result repost/ACK unknown、commit conflict、LifecycleOperationInProgress、HostLost transition；
- Node：Host lock/session conflict、command phase/age/replay、StopFence、complete inventory/attestation freshness、
  missing/corrupt journal、artifact classification/GC、scope resurrection、effect ambiguity；
- Route：effective RuntimeReady/Serving mismatch、admission session mismatch、route epoch burn、Active/Closed gates、
  guards/drain/force stop、Grant cache/resolve/ring ACK；
- Storage：owner/epoch、R/L gap、Strict FLUSH latency/error、pending pack quota、normal release、takeover/disposable
  authorization、Persistent destroy blockers、Snapshot live roots与sweeper progress；
- Fleet：heartbeat suspicion、provider fence attempt/event、old Host return、capacity/cordon、RDS/Object Store health；
- Usage：spool backlog、counter gap/reset、projection/rating lag。

RuntimeInventoryReport staleness/rejection是telemetry incident，不得改变command terminal result。Full
inventory attestation与Partial subset分别监控；Partial不能刷新complete scan freshness。

## 7. 分层qualification

每一层使用exact clean commit与可重复oracle：

1. **Pure/domain**：ADR-0057六动作product projection与旧名absence、action-specific ExecutionStopped evidence、
   command successor table、fingerprint/digest vectors、one-unresolved DB constraint、Volume owner/epoch state
   machine、authorization sum type、Route binding compare。
2. **PostgreSQL integration**：多replica admission race、response-received/result-commit crash、HostLost transaction、
   lock DAG、API replay、Cat create全有或全无、Persistent initialization signed command CAS、Snapshot/delete。
3. **Node local Linux**：real systemd scopes/cgroups、Host lock/double Agent、journal fsync crash points、StopFence/
   force stop/resurrection、complete inventory、per-Cat GC、kernel-NBD与vhost-user-blk。
4. **Runtime integration**：Cloud Hypervisor/Guest readiness、四态、Warm snapshot、R/L convergence、exact release、
   destroy Persistent-first/Root discard、Route race/active HTTP/WebSocket。
5. **Two-Node/failure**：normal Cold handoff、Agent/Control/PG response loss、network partition、external HostFence/
   per-volume takeover、old Host return。
6. **Production cell**：real RDS/Object Store/KMS/secret/mTLS/Gateway/provisioner artifacts、monitoring/rollback/open
   evidence，exact immutable build receipt。

`./scripts/quality.sh full`是handoff门；Node/Linux-only change还要configured native x86_64 build host的full gate。
本机迭代可用`./scripts/quality.sh linux`，但不能替代final native receipt。已知与改动无关的门禁flakiness需记录
provenance并隔离，不在同一失败上无限重试。

## 8. 首次终态部署

atomic lifecycle只允许一次one-version clean-slate vertical cutover：

1. 离线构建exact Controller/Node/Gateway/Volume/provisioner bundle；验证schema/wire/version、migration absence、
   credential inventory与全部qualification receipts。
2. 进入维护窗口，关闭公网ingress与mutation；可达runtime用atomic target之外的现有安全runbook drain，
   不可达Host必须完成external fence或明确阻断cutover，不能由timeout猜隔离。
3. 停止所有旧Controller/Node/Gateway/signer/write path，确认不会再写旧schema、route mirror或volume authority。
4. rotate/revoke旧service/Node/route credentials；删除旧Desired read、reconcile、Observation settlement、NodeJob、
   heartbeat overwrite、legacy Route parser/mirror和兼容IAM input。
5. 删除开发product/runtime state，创建唯一empty atomic schema 18。没有Desired/Operation/checkpoint/runtime/
   route migration、translator、dual write/read、fallback或mixed-version window。
6. provision immutable NodeIdentity/state-path/credential与cordoned NodePlacementPolicy；Node先取得Host lock、fresh
   AgentSession、complete inventory，所有AdmissionCell/gate Closed。
7. 启动PostgreSQL/control authority，再启动Node/Route signer ring；全部compatible version、inventory attestation、
   public key ring与machine mTLS ACK后才启动Gateway/API mutation。
8. 在exact deployed SHA上执行smoke + Linux/runtime/route/storage crash oracle；保存immutable build/deploy/test
   receipt。任何old parser/credential、schema drift、unknown checkpoint或qualification failure保持Closed。
9. 只有all-green receipt与operator review后才打开mutation和public ingress。

production reset/open的更细artifact流程继续由
[production clean-slate reset](../deploy/aws/production-clean-slate-reset.md)及accepted production qualification
ADRs维护；它们不得重新引入legacy lifecycle authority。

## 9. 明确不宣称

- atomic lifecycle内部软件组成与current product adapter不表示clean-slate release gate、
  automatic HostFence、real RDS failover或production Route qualification已通过。
- heartbeat timeout、last Observation、audit record和“目录不存在”都不是fence/result/delete authority。
- Warm/Suspended不是跨Host HA副本；Relaxed Host loss可能丢失`R-L` local tail。
- test machine/prototype样本不自动成为production SLA；报告必须保留environment、sample count、boundary与oracle。
- privilege separation、cross-Node Guest overlay与automatic cloud/BMC Host fencing仍是独立后续边界。
