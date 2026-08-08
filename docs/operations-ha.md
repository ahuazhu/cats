# Operations and HA

- 状态：Target operations contract；终态模块尚未全部实现
- 架构：[Architecture](architecture.md)
- Runtime：[Runtime Reconciliation v1](specs/runtime-reconciliation-v1.md)
- Route：[Route Grant v2](specs/route-grant-v2.md)

本文只定义终态运行边界和验收入口。它不引入新的 authority、工作流、共享 route cache或
qualification 基础设施。

## 1. 终态拓扑

- 两个以上 Gateway replica 分布在独立 failure domain，经公网负载均衡接收应用流量。每个 replica
  只有有界本地 Route Grant cache。
- 两个以上 stateless Control Plane/API/Controller replica 分布在独立 failure domain。所有可恢复
  工作来自 PostgreSQL current desired/Operation/AgentSession/observation；内存队列和 leader身份都
  不是authority。重复controller靠相同transaction/CAS合同收敛。
- Multi-AZ PostgreSQL保存Control/Metadata authority；对象存储保存immutable durable data；两者都
  不在Running HTTP热路径。同步数据库client只运行在有界blocking executor。
- 每台Host只有一个持锁Node Agent。每个Cat的VMM、blockd和Guest运行在独立systemd scope；Agent
  restart先以admission Closed重建current desired、checkpoint和complete inventory。
- Route private key来自专用secret channel；Node只持versioned public ring，Gateway只搬运Grant。
- 终态route状态只有PostgreSQL binding、per-replica cache和Node gate；旧mirror及其他协调authority
  在首次启动前退出。

这套拓扑提供control-plane和Gateway副本冗余，但不把单个Running Cat复制到多Host。Host丢失后的
恢复是经过fence、以远端durable root `R`进行的Cold recovery，不是live failover；Suspended/Warm
仍是Host-bound优化。

## 2. 故障合同

| 故障 | 保证 | 明确不保证 |
|---|---|---|
| 单个Control Plane replica退出 | 其他副本继续API/resolve；level-triggered controller从PG重扫 | 恢复该进程内存queue |
| Control Plane全断 | Running VMM/blockd及已有stream继续；预热该hostname的Gateway replica可在Grant expiry前接新流 | mutation、wake、续签或cold Gateway admission |
| PostgreSQL暂时不可用 | Running compute和已有stream继续；有本地额度时Relaxed可推进local `L` | Strict FLUSH、authority transfer、lifecycle成功或新route签发 |
| Object Store暂时不可用 | 已缓存读和允许的Relaxed local commit有界继续 | cache miss、Strict durability、Warm/Cold转换 |
| 单个Gateway退出 | 其他replica在Control Plane健康时自行resolve | 复制丢失replica的local cache；CP全断时cold-cache HA |
| Node Agent退出 | systemd重启Agent；目标形态下VMM/blockd scopes继续；重建完成前gate Closed | 代理中的stream不断线或重建期新admission |
| Node网络分区 | 保留源placement和writer，不在别处猜测启动 | heartbeat timeout自动takeover |
| Host永久丢失 | provider隔离Host，再逐卷CAS writer epoch后从remote `R` Cold恢复 | Relaxed `R < L` 的local tail；必须报告`DataLossPossible` |
| Gateway -> Guest应用失败 | 释放guard并返回UpstreamUnavailable | route refresh或当前request replay |
| Signer/key异常 | 停止签发；缺active key的Node Closed/cordoned | unsigned、旧wire或single-key fallback |

所有timeout、队列、retry和drain都有硬界。超界的正常结果是backpressure、Unavailable或Blocked，
不是继续堆积、猜测成功或绕过authority。

## 3. PostgreSQL 与controller边界

每个进程必须显式配置并在启动时校验：connection pool上限、blocking worker数、排队上限、pool
acquire deadline、connect/query/lock/transaction timeout、单批rows/bytes和controller scan page。
同步driver不得占用Tokio worker；blocking queue满时立即backpressure。

事务规则只有三条：

1. mutation、Endpoint revision、signer snapshot、AgentSession和result settlement各使用文档规定的
   固定lock order和一个bounded transaction；不在transaction内做网络、VMM、object-store或fsync。
2. 只对serialization/deadlock/明确transient连接错误做有限次数、带jitter的retry；每次从fresh
   snapshot重放整个transaction，不能只重放最后一条write。外部副作用只能通过idempotency key、
   revision/incarnation/epoch的窄CAS重试。
3. controller只分页扫描current state，按稳定key排序，每轮有work/time budget；notify只负责提前
   唤醒。没有无界in-memory backlog，也不靠历史command重建意图。

API mutation先完成调用者认证、当前Workspace membership和route permission检查，再取得
`(authenticated workspace, canonical route, Idempotency-Key)`的transaction-scoped reservation。
全局锁DAG是`API key -> HostFenceEvent -> authorization -> VolumeRecord -> Disk/Desired ->
DiskSnapshotRecord`，不涉及的节点直接跳过，同类多行按稳定ID排序。fingerprint唯一使用
[Volume Authority §3.3](specs/volume-authority.md#33-唯一-api-idempotency-fingerprint)的domain-separated、
u64-BE length-framed workspace/route/raw path-query/If-Match/raw body bytes；不允许route-local JSON或参数
归一化。相同fingerprint只读status/content-type/exact response bytes，即使目标资源后来已删除也不先查询它；
不同fingerprint在资源锁前
失败。只有result miss才检查当前资源ownership并取得domain locks；跨Workspace miss回滚reservation，
零持久副作用。首次业务变化与成功/确定性失败result同一commit且不落持久Pending。V1已提交result
不随resource或Operation删除而GC。request超过route body cap、非identity Content-Encoding和非法
If-Match在reservation前拒绝；transport/commit结果不明本身不写失败result，最终事务只允许业务+result
全有或全无，重试按key判定。

数据库慢或pool饱和时，readiness、队列拒绝和延迟指标必须先于全局超时告警；Running数据面不因
controller retry而停止。

## 4. Host fence 与rejoin

heartbeat缺失、AgentSession过期、EC2状态查询或Gateway不可达都只是suspicion。它们不能单独授权
新placement、writer epoch或route publication。

自动恢复使用一个窄provider/BMC fence adapter：

1. Control Plane把source placement标记Blocked，停止新Grant，并创建绑定
   `provider + immutable_host_id + node_id + expected_node_boot_id + expected_agent_session_epoch +
   fence_attempt_id`的attempt。
2. adapter执行并重新读取权威power/network isolation结果，产生不可变receipt。PostgreSQL只在
   identities仍精确匹配且receipt证明旧Host不能serving或访问writer authority时，CAS建立Active
   `HostFenceEvent`。receipt本身不创建placement，也不是逐卷writer permission。
3. Control Plane先把当前Pending Operation置为`Failed(HostLost)`，再在一个事务中创建新完整
   Desired/Operation、placement、全部新attachments与每卷`VolumeTakeoverAuthorization`；Desired
   逐卷引用授权。任何一项无法建立就保持Blocked，不留下旁路placement。
4. replacement只从remote durable`R` Cold启动。每卷首次消费必须按
   `HostFenceEvent -> authorization -> VolumeRecord`锁序，在同一PostgreSQL事务确认event仍Active、
   完成epoch CAS并写不可变`AuthorizationConsumedReceipt`；不存在另一种writer-proof fallback。
   全部volume、runtime和新route epochs Ready后才serving。旧Grant/gate/writer全部fail closed。

HostFenceEvent来源的disposable Root删除在上述锁序后继续锁Control rows；同一事务写Consumed receipt，
把VolumeRecord和Control Disk改为同一Deleting。对象sweep只能在该提交后执行。普通begin-delete也在
一个PostgreSQL事务同时改变两边；显式Disk delete API在该事务持久化exact 202 result且不创建Operation，
Root继续由现有Cat Operation驱动。begin与normal acquire锁同一VolumeRecord，只能一方提交。
Deleting rows就是level-triggered工作：sweeper只分页扫描
current rows，不持久job/claim；它幂等delete并从prefix起点re-list到empty，再以一个事务重验exact
Disk/Volume/delete/head/epoch/last-transition和zero snapshots，写completion receipt并删除两row。失败保持
Deleting，多实例只有一个compare/CAS可提交；object store与PG之间没有两阶段事务或第二authority。

旧Host即使恢复供电也持续隔离。它只能以新boot/session进入cordoned rejoin：完成union inventory，
停止旧VMM/blockd/tap/socket/gate/guard，把旧epoch的`R < L`lineage移入quarantine；随后核对该event
派生的全部takeover/delete authorizations。授权派生、首次消费与`Active -> Rejoined`都先锁同一
event行；rejoin取得该锁后再按稳定顺序锁全部授权，所以不会漏掉in-flight首次消费。Unconsumed授权
必须已过`not_after`；Consumed授权必须有匹配payload的不可变receipt，当前VolumeRecord必须是直接
结果或更大epoch的合法后继；receipt含Disk postcondition时Control Disk也必须匹配，两边记录已删除
时必须有精确`DeleteCompletionReceipt`。任何缺失、倒退或
冲突保持Blocked。Control Plane在同一事务接受`HostRejoinProof`并持久改为Rejoined后，provider才
恢复workload网络。此后未消费授权不能首次生效，已消费授权只读取原receipt；相关authorization和
`DeleteCompletionReceipt`至少保留到Rejoined。没有可验证external fence的平台保持Blocked等待人工处置。

## 5. 运行监控

指标使用有界label；resource identity进入structured log/evidence，不进入高基数metric label。禁止
采集Grant、signature、private key、Cookie、Authorization或响应body。

必须覆盖：

- Control Plane：PG pool/queue saturation、acquire/query/lock timeout、transaction retry、scan lag、
  desired-to-observation lag、stale observation拒签、AgentSession conflict、API fingerprint conflict/result replay、
  signer active kid；
- Gateway：每replica LRU size/bytes/eviction、hit/miss/expiry、negative/backoff、in-flight keys、
  singleflight waiters/reject、resolve latency/error、typed pre-admission reason、UpstreamUnavailable；
- Node：Host lock/session、inventory attestation epoch/freshness、checkpoint rebuild、gate Active/Closed、active guards、
  close/drain time、Blocked reason、runtime incarnation、ring version/digest/loaded kids；
- Storage/lifecycle：逐卷owner/epoch、`R/L` gap、Strict FLUSH、object-store error、Cold fallback、
  `DataLossPossible`、orphan/quarantine、Deleting row age、sweeper scan/delete/re-list-empty failure和completion
  CAS contention；
- HA：replica/failure-domain count、public probe、fence attempt age/result、replacement/rejoin phase。

告警阈值必须来自部署容量和经验证基线，不能把单次实验数字写成SLA。每个page指向一个按
`observe -> stop unsafe progress -> collect bounded evidence -> recover -> verify postcondition`编排的
runbook；禁止以“重启看看”跳过fence或durability proof。

## 6. 分层qualification

不再创建测试环境。终态复用三个已有入口，并按从便宜到昂贵的顺序运行：

1. **Workspace/model**：在开发worktree运行`./scripts/quality.sh fast`；覆盖JWT fixed vectors、
   AdmissionCell/close race、RequireIdle one-shot、Gateway LRU/singleflight/backoff和PostgreSQL双session
   transaction tests。FakeVmm integration注入慢DB、响应丢失、restart/cancel和HTTP/WS transport歧义。
   [Volume Authority §14](specs/volume-authority.md#14-最小验收矩阵)是同一上线门，必须覆盖acquire/
   release模糊响应、旧lineage、API fingerprint fixed vectors与raw-byte差异、PersistentDisk
   create/201原子提交、exact Disk role/init、mkfs/Initialized CAS crash、snapshot create/result原子提交及lost response、
   create→delete→旧create replay不复活、跨Workspace零副作用、`DiskSnapshotRecord`/GC、显式snapshot
   delete与`SnapshotInUse`、同盘restore只前进一次、Disk delete 202/Deleting/404/replay、普通begin-delete
   与acquire竞争、双sweeper/prefix-empty/completion CAS，以及disposable Root两边Deleting的每个crash点；
   还要用PostgreSQL双session覆盖authorization
   首次consume与Rejoined竞争以及合法后继receipt校验。
2. **独立native x86_64 Linux build host**：使用现有
   [qualification build host](../deploy/aws/terraform/qualification/build-host/README.md)；controller发布
   exact 40-hex commit后，在Host运行：

   ```sh
   cats-checkout-exact-sha "$EXACT_40_HEX_COMMIT" "$MANIFEST_SHA256" "$BUNDLE_SHA256"
   cats-run-build "$EXACT_40_HEX_COMMIT" "$MANIFEST_SHA256" "$BUNDLE_SHA256" \
     --with-postgres -- ./scripts/quality.sh full
   ```

   该入口原生覆盖Linux-only build/tests和PostgreSQL。`cats-run-build`只冻结Host本地output并写
   immutable receipt；需要append-only evidence时，另以
   `cats-publish-content-addressed evidence <file>`发布指定日志。不要在这里运行Docker版
   `quality.sh linux`，也不要另建build host。
3. **批准的隔离metal/KVM Host**：Host必须先证明安装exact artifact、cordoned、`cats=0/orphans=0`
   且使用隔离qualification Workspace；没有合格Host时本层明确Blocked，不能把生产worker或历史
   evidence当作当前gate。满足前置后按[metal runbook](../deploy/metal/README.md)运行真实Cloud
   Hypervisor基线，再用下节同一个oracle分别设置`kernel-nbd`和`vhost-user`，覆盖真实HTTP/WS、
   Agent restart、gate rebuild、Endpoint rebind、RequireIdle active-stream race、key overlap、Control
   Plane/Gateway interruption和cleanup。provider adapter还必须跑两卷HostFenceEvent→逐卷CAS→旧
   writer拒绝→quarantine→Rejoined矩阵，包含错tuple、consume/Rejoined边界竞争、未消费授权阻止
   rejoin、takeover后release、HostFence disposable event/auth/volume/control原子提交和delete完成
   receipt两种合法后继。
4. **生产拓扑smoke**：前三层全绿后，才运行已有
   [control-plane HA workflow](../.github/workflows/verify-control-plane-ha.yml)的diagnose/disrupt模式，
   保存public probe和Pod/EndpointSlice evidence。该workflow目前只证明Control Plane副本切换；它不
   替代Route、Node、storage或Host-fence oracle。

## 7. 缺少的evidence脚本

现有机器入口足够；缺的是仓库内确定性执行器。实现阶段新增一个
`deploy/metal/runtime-cutover-e2e.sh`，但不让它provision、apply Terraform或创建长期service。脚本
合同必须包括：

- 必填exact commit、block path、run id和绝对output directory；启动时记录Host/Guest kernel、
  binary/config SHA-256、schema version和**非secret**key fingerprints；不接受branch/tag或dirty binary；
- 用同一scenario和oracle运行两种block path；每个case有稳定id、deadline、预期postcondition和
  cleanup，失败后继续收集有界diagnostic但最终非零退出；
- 覆盖§6列出的route/lifecycle/restart/outage矩阵，并校验过程中没有request replay、guard leak、
  dual writer、gate resurrection或secret泄漏；
- 输出`manifest.json`、`scenario-results.jsonl`、有界component journal摘要、最终inventory、退出码和
  `SHA256SUMS`。每个artifact写临时文件后原子rename；超限时保留first/latest及truncation marker，
  不能静默截断；
- 不采集token/private key/用户header/raw response body。构建receipt、scenario manifest和exact
  commit互相引用，随后进入现有append-only evidence发布边界。

确定性逻辑、故障注入、oracle和artifact生成必须是可审查的repo script；skill若存在，只说明何时
调用脚本和如何review evidence，不能复制脚本逻辑或代替执行证据。

## 8. 首次终态部署

本节是 clean-slate cutover 顺序的唯一权威；各模块规格只声明自己的前置条件。

1. 先在代码、schema和IaC中删除旧入口，形成只含终态合同的exact clean commit；由独立native
   Linux build host验证完整workspace并保存build receipt。真实KVM场景还必须在满足第6节前置的
   隔离metal Host验证同一artifact；没有合格Host时该上线门保持Blocked。
2. 进入维护窗口，关闭公网 ingress 和 mutation。drain 可达 runtime；对不可达 Host 执行外部
   fence，并正向证明旧 Gateway、Controller、Node Agent、VMM 和 blockd 已停止或被隔离。
3. 按批准的 destructive runbook 删除 Cat、Disk、Snapshot、Operation、旧API幂等状态、route/cache、Node runtime
   state、产品 object prefixes 以及 Metadata/Control/Usage/Billing 数据。Terraform state、实验和
   审计 evidence 继续受限保留，但不导入新系统。
4. 在任何终态组件启动前，核对待部署artifact与步骤1的receipt完全一致，并证明其schema/IaC不含
   NodeJob、heartbeat overwrite、旧Route parser/mirror、旧IAM/Terraform inputs或transitional
   writes；随后轮换service、per-Node、database、object-store与route-signing credentials。此步不
   重建或修改artifact。
5. 创建空目标 schema，启动同一个 exact release 的 Control Plane，并 provision
   `NodeIdentity`/per-Node credential binding。
6. Node 以所有 gate Closed 注册新 `AgentSession`，提交 complete empty inventory attestation 和
   key-ring ACK；随后启动 Gateway。
7. 在 cordoned 状态运行第 6 节全部 qualification 和故障 oracle。全绿后才开放 ingress、
   uncordon 并创建全新产品资源。

步骤3前可以取消并恢复旧部署；步骤3后只允许forward-fix终态版本。目标schema/protocol version
是启动前置事实，运行期只有这一套authority。

后续同一终态协议内的普通 release 可以逐副本/逐空 Node 部署，但必须保持 schema 兼容范围、
key overlap、Node drain 和不可变 artifact digest；该路径不能用于首次 cutover。
