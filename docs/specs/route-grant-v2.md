# Route Grant v2

- 状态：Target contract；shared codec、Control独立Gateway machine resolve transport、Node
  verification/admission core与Gateway到Node machine tunnel已实现；public proxy仍保持关闭
- Authority：[ADR-0041](../decisions/0041-node-verified-route-admission.md)
- Runtime identity：[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
- Runtime accepted facts：[Runtime Inventory and Observation Spine v1](runtime-inventory-observation-v1.md)
- Operations：[Operations and HA](../operations-ha.md)

Route Grant 是 Control Plane 为一个当前 Running runtime 签发的短期 capability。Gateway
只缓存并搬运 token；Node 同时验证签名和本地 gate，并原子取得 active guard。token、Gateway
cache、hostname lookup index 和 observation 都不是独立 authority。

## 1. Wire contract

- Compact JWS/JWT，UTF-8 JSON；协议版本只接受 `2`。
- protected header 精确包含 `alg=EdDSA`、`typ=cats-route-grant+jwt` 和 `kid`。
- `kid = hex(SHA-256(SubjectPublicKeyInfo DER))`；只允许 Ed25519，不协商算法。
- compact token、decoded header 和 decoded payload 的协议硬上限分别是 4096、512 和 2048
  bytes；在分配或 JSON decode 前检查。
- payload 拒绝未知字段、重复 JSON key、错误类型、空 identity、非规范 hostname 和超范围整数。
- JSON member 顺序不属于语义；signer/verifier 必须共享由同一 schema 生成的 fixed vectors。

claims 的逻辑形态：

```json
{
  "version": 2,
  "iss": "cats-control-plane",
  "aud": "cats-node-agent",
  "workspace_id": "ws_...",
  "endpoint_id": "ep_...",
  "hostname": "app.cats.run",
  "cat_id": "cat_...",
  "node_id": "node-a",
  "runtime_incarnation": "0198...",
  "route_epoch": 7,
  "protocol": "http",
  "target_port": 8080,
  "gateway_public_key_spki_sha256": "sha256:...",
  "iat": 1786156800,
  "nbf": 1786156800,
  "exp": 1786156920
}
```

| 字段 | 约束 |
|---|---|
| `version` | 必须为 `2` |
| `iss` | 精确为 `cats-control-plane` |
| `aud` | 精确为 `cats-node-agent`，不接受额外 audience |
| `workspace_id` / `endpoint_id` / `cat_id` / `node_id` | 分别使用Runtime Reconciliation v1 `Id`的精确wire与验证；必须与本地期望逐字节相等 |
| `hostname` | Runtime Reconciliation v1 `Hostname`；小写ASCII DNS名，无端口、路径或尾点 |
| `runtime_incarnation` | Runtime Reconciliation v1 `RandomId128`（32个小写十六进制字符），精确匹配当前 VMM |
| `route_epoch` | Runtime Reconciliation v1 `Epoch`（`1..=9223372036854775807`），精确匹配Endpoint serving gate；close后重开必须更大 |
| `protocol` | v2 只允许 `http`；WebSocket 是该 HTTP route 的 upgrade |
| `target_port` | `1..=65535`，精确匹配 gate；请求不能覆盖 |
| `gateway_public_key_spki_sha256` | Control machine listener实际认证并授权的Gateway leaf canonical Ed25519 SPKI SHA-256；精确匹配Node tunnel同一TLS connection的leaf |
| `iat`/`nbf`/`exp` | JSON integer `0..=9223372036854775807` Unix seconds；`iat <= nbf < exp` |

默认 TTL 为 120 秒，最大 TTL 为 300 秒，最大时钟偏差为 5 秒；必须满足
`0 < exp - iat <= 300`。部署可以缩短 TTL，不能提高 wire 上限。TTL 只限制新的 admission，
不会终止已经持有 guard 的 HTTP/WebSocket stream。

Node 以可信 wall clock `now` 计算 time verdict：`now + 5 < nbf` 是 `NotYetValid`，
`now - 5 >= exp` 是 `Expired`，其余在时间窗口内。时钟不可信的 Node 保持 admission Closed。
`now`必须先转换并验证为同样的`0..=9223372036854775807` Unix seconds范围。本规格的所有integer/time
加减，包括`route_epoch + 1`、生成`nbf`/`exp`、`exp - iat`、`now + 5`、`now - 5`以及key retention
deadline，都必须使用checked arithmetic；任何overflow/underflow都fail closed（mutation/signer不提交或
不签发，verifier返回`InvalidClaims`），禁止wrapping或saturating替代。signer/verifier不得为上述
identity或时间字段另定义更宽范围。

## 2. Endpoint authority 与 revision

Endpoint 是完整 `DesiredRuntimeSpec` 的一部分。一次 Endpoint create、unbind、hostname/port/
protocol change 或 rebind 必须在一个 PostgreSQL transaction 内：

1. 锁定并校验 Cat 当前 desired revision；
2. 为变化的 Endpoint 增加 `route_epoch`；
3. 写入包含全部 Endpoint 的新完整 desired revision；
4. 更新 canonical hostname lookup index；
5. 创建或复用精确绑定该 revision 的 Operation。

transaction任一部分失败就全部回滚。hostname index只把lookup定位到当前
`workspace_id/cat_id/endpoint_id/desired_revision`；它不保存第二份可签发binding，也不能被
signer单独读取。`desired_revision`仍是协调与签发snapshot条件，但不进入Grant或serving gate。

`route_epoch`是per-Endpoint serving lineage：binding变化必须递增；任何gate一旦真正Closed或结果
不明，重开前也必须通过新的完整Desired递增。Node任意时刻只安装一个epoch，不保留双epoch窗口。
只检查到RequireIdle Busy且cell从未close时可以保留原epoch。

Node应用仅含Endpoint变化的revision时使用[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
定义的durable `CloseGate`，不得调用全局`CloseAdmission`。每次gate变化都在`AdmissionCell`内线性化：

- changed/removed Endpoint先持久化只含endpoint ID/old route epoch的`CloseGate`，以checkpoint中同一
  old entry的完整binding compare-and-close，立即fsync Closed，再只取消并drain它自己的guards；若以后
  重开必须使用更大route epoch；
- binding、route epoch、runtime incarnation和platform target都未变化的其他Endpoint不修改
  serving gate，不关闭、不重绑，也不取消已有guards；
- new/changed Endpoint 在其 platform target Ready 且 checkpoint 已持久化后才发布 Active。

因此Endpoint A的变化不会中断Endpoint B的active stream或新请求，B的既有Grant继续有效。若
revision还改变placement、runtime identity、volume、mount、network、platform或lifecycle target，它不是Endpoint-only
revision，必须走全局close-and-drain；之后重开全部受影响Endpoint时提高各自route epoch。

## 3. Signer snapshot

一次 resolve 必须在同一个 PostgreSQL transaction snapshot 中读取并闭合：

1. canonical hostname index 与当前 Endpoint binding 指向同一 current desired revision；
2. desired target 为 Running，placement node/epoch 是当前值；
3. current NodeIdentity是provisioned，且A23 current `NodePlacementPolicy.node_id`与identity、desired placement
   逐字段相同；同一policy给出strict canonical `node_transport_target`。缺policy或JSON/projection不一致是stored
   corruption；registration/observation与legacy `nodes.agent_url`不能提供fallback；
4. 当前`AgentSession`精确属于该node、Host/boot/agent instance；
5. 该session有fresh `AdmissionInventoryAttestation {inventory_epoch, inventory_digest,
   inventory_read_position,
   accepted_at_unix_ms}`；它来自accepted full scan，完整schema与digest算法以
   [Runtime Reconciliation v1](runtime-reconciliation-v1.md) §2/§16为准，
   后续partial observation不能覆盖；fresh精确使用
   [Inventory Spine §7.2](runtime-inventory-observation-v1.md#72-route-signer-freshness)的同一DB-now与
   `accepted_at <= db_now < accepted_at + 60000ms`，右边界相等已过期；
6. 最新per-Cat accepted observation属于该session、引用同一inventory epoch，且其PostgreSQL
   `accepted_at_unix_ms`满足同一DB-now的
   `accepted_at <= db_now < accepted_at + 30000ms`，右边界相等已过期；freshness只使用数据库时间，
   不信Node上报时钟；
7. observation 的 applied revision、placement、runtime incarnation、Running/Ready condition 与
   desired 完全一致；
8. observation 报告同Endpoint gate Active、同route epoch/protocol/port；
9. observation的ring version/digest均非null、按精确`loaded_kids`重算匹配，且当前signer `kid`出现
   在该Node原子加载并ACK的`loaded_kids`中；Runtime合同的unavailable或empty-but-valid ring都不签发。

Signer 以同一 snapshot 的数据库时间生成 `iat/nbf/exp`。任何条件不成立都返回
Wake/Pending/Unavailable，不签发未来 revision，不从旧 token 复制 authority，也不建立 durable
route workflow。签发后若 token 已到期就丢弃。

Conditions可以同时包含`Ready + Degraded`。只要attestation和per-Cat事实仍fresh且上述Ready
postcondition继续成立，Degraded本身不阻止签发；freshness或安全事实失效时observation必须移除
Ready，signer也停止签发。

`Ready` 在这里表示平台拥有正确的 VMM、网络、完整磁盘集合、声明的 Guest mounts 和可用的
Guest transport。它不表示用户应用已经监听 `target_port`。应用 health/readiness 若产品需要，
必须作为独立策略实现，不能改变 route authority 的含义。

## 4. Public ingress 与内部身份

默认 Endpoint 是公网应用入口。Gateway 规范化 TLS SNI/HTTP Host 后查 route；它不要求
WorkOS session，也不替用户应用做 Workspace 成员鉴权。用户的 Authorization、Cookie 和应用
headers 作为应用数据转发给 Guest。Cats management API 继续使用自己的用户/Workspace 鉴权。

Gateway -> Control Plane resolve 和 Gateway -> Node hop 必须使用独立的 workload machine identity
并全程加密；Node 同时要求可信 Gateway identity 和有效 Grant。Grant 放在保留的内部字段，进入
Guest 前删除，不能发送给浏览器。日志、trace、错误页和 qualification evidence 都不能包含 token、
signature、private key、Cookie 或用户 Authorization。

### 4.1 Control resolve HTTP frame

machine transport 完成身份认证后，只能把不可由HTTP字段构造的typed Gateway principal注入handler；
handler在读取body、取得admission permit或访问PostgreSQL前要求该principal。resolve frame冻结为：

- method/path精确为`POST /v1/internal/routes/resolve`，不得带query；它与legacy
  `/v1/routes/resolve`完全不同，也不接受legacy wake、Node URL或shared bearer；
- request/response media type精确为`application/json`，不接受content encoding、media parameter、
  `Authorization`、`Cookie`、条件或method-override headers；request body最多512 bytes，完整deadline
  从headers到最终response为2000ms；
- request是canonical JSON `{"version":2,"hostname":"app.cats.run"}`。decoder拒绝非canonical
  member order/whitespace、重复或未知字段；
- success最多8192 bytes，canonical JSON字段依次是`version`、`cat_id`、`endpoint_id`、
  `node_transport_target`、`expires_at_unix_seconds`、`opaque_grant`、`grant_sha256`。Gateway只校验
  strict A23 target、expiry range、opaque grant ASCII/4096-byte bound和`SHA-256(opaque_grant)`；不解析
  protected header、claims或签名；
- authenticated authority outcome精确映射为`200` success，`404 not_found`、`410 gone`、
  `409 wake_required|pending`、`503 unavailable`。认证失败为`401 authentication_failed`；frame错误为
  `400/405/406/413/415 invalid_request`；stored/internal错误为`500 internal`。所有response带
  `Cache-Control: no-store`；`405`带`Allow: POST`，`503`带`Retry-After: 1`；不redirect；
- per-replica resolve semaphore与body/deadline是资源界，不是authority。handler与其已经启动的Store
  closure共同持有同一个active owner；timeout或client取消只能释放handler owner，不能提前释放Store owner。
  graceful shutdown先关闭新admission，再等待所有active owner归零。client取消不会产生durable route
  workflow；签名response丢失后普通重试重新闭合当前snapshot，不复用丢失token。

Gateway到Control的独立identity由[ADR-0045](../decisions/0045-independent-gateway-workload-identity.md)
与[Gateway Workload Identity Authority v1](gateway-workload-identity-v1.md)冻结：固定CA先验证TLS chain，
verified leaf canonical SPKI再映射PG current credential；每个keepalive request都重验，Workspace scope只使用
hostname在同一authority snapshot解出的current Workspace。PG exact revision/current pointer是唯一运行时
authority，filesystem JSON只做install candidate。它不借legacy或HTTP header principal。

[ADR-0044](../decisions/0044-independent-route-v2-signing-authority.md)与
[Route v2 Signing Authority v1](route-signing-authority-v1.md)另行冻结独立Route v2 signer。production success
只有在machine listener的Gateway credential和进程内fixed signer分别等于同一PG snapshot的current binding时
开放；无machine配置仍pre-body/pre-PG `401`，principal已认证但signer未组成则pre-body/pre-PG `503`，不存在
legacy V1 signer/key fallback。签发时还把该request实际授权的Gateway leaf SPKI digest写入Grant；
Gateway到Node必须以同一leaf证明持有credential。

A19只授权Node到Control，A23只授权deployment provisioner写placement policy；两者都不能授权Gateway。
legacy shared bearer、`nodes.agent_url`、HTTP header自报principal、推测的SPIFFE/SAN或云IAM映射都不是
fallback。test principal仍只用于显式test router，不能进入production machine listener。

### 4.2 Node machine tunnel frame

[ADR-0046](../decisions/0046-gateway-node-route-v2-machine-tunnel.md)冻结完整hop：Gateway以固定client
certificate对A23 strict HTTPS target建立TLS 1.3，Node用固定Gateway client CA验证chain并从leaf提取
canonical Ed25519 SPKI digest。method/path精确为`POST /v1/internal/routes/tunnel`，无query，只接受
HTTP/1.1、exact `application/json`、`Connection: upgrade`与
`Upgrade: cats-route-v2-tunnel`；不接受Authorization、Cookie、content/transfer encoding、条件、
method override或未知header。TLS/header/body/Guest connect各有独立deadline，connections与tunnels有硬上限。

request body最多5120 bytes，是canonical JSON：

```json
{"version":2,"cat_id":"cat_01","endpoint_id":"ep_01","hostname":"app.cats.run","opaque_grant":"...","grant_sha256":"sha256:..."}
```

Node先验证Grant signature/claims并把frame的`cat_id/endpoint_id/hostname`与local Node/protocol完整request
binding逐字段闭合，产生不可由wire构造的claims/time proof；只有随后才允许用该proof中已验证的`cat_id`在
本进程唯一registry定位cell。未验证frame的`cat_id`不得触发registry lookup。Node再比较Grant中的Gateway leaf
digest与同一cell binding，在cell内原子取得guard和checkpointed Guest IPv4，再在锁外连接Grant target port。
成功返回`101`，同一exchange随后成为public HTTP/WebSocket raw byte tunnel；Grant和内部frame不进入Guest。
这是实际proxy request，不是裸Grant preflight。tampered signature和unknown `kid`不得因Cat present/absent改变
typed error或触达guard/Guest；只有完整已验证请求对应的Cat absent才返回`RuntimeNotReady`。

full inventory中的ring version/digest/`loaded_kids`必须从这个listener实际使用的同一进程
`Arc<RouteGrantV2Verifier>`读取；磁盘ring只是在下次受控启动时可加载的candidate，不能冒充已加载事实。
listener未组成时inventory必须报告ring unavailable，使§3 signer闭合失败。

pre-admission failure为canonical JSON
`{"version":2,"guard_acquired":false,"reason":"expired"}`及§8闭集；只有已取得guard后的Guest
connect失败为`502`和`UpstreamUnavailable, guard_acquired=true`。普通stream failure关闭tunnel。Gateway不
redirect、不fallback、不自动重试当前request。Node shutdown先关闭new admission，再cancel/join全部tunnel，
guard覆盖从admission到EOF/error/cancel/shutdown的完整lifetime。

## 5. Gateway cache

每个 Gateway replica 只有一个进程内 cache；不使用 DynamoDB mirror、共享 route authority 或
跨 replica 一致性协议。positive entry 精确保存：

```text
canonical hostname -> {
  cat_id, endpoint_id, node_transport_target, opaque_grant,
  grant_digest, expires_at
}
```

Control Plane 的 authenticated resolve response 显式返回 expiry；Gateway 不解析或改写 claims。
`node_transport_target`逐byte使用A23的canonical HTTPS authority string。它只是hint，最终authority仍是Node gate。

cache 必须是有界状态机：

- positive、negative 和 in-flight key 共享启动时校验过的 `max_entries/max_bytes` 上限，并按 LRU
  eviction；单个 entry 和单个 hostname waiter 数也有硬上限；
- 所有 resolve 共用固定并发 semaphore、连接/请求 deadline 和 bounded response body；
- 同 hostname 同时只有一个 resolve，等待者数量有界；容量耗尽时 backpressure，不创建无界 task；
- authoritative NotFound/Gone 使用短 negative TTL；Control Plane unavailable/timeout 只在没有有效
  positive entry 时记录带 jitter 的有界指数 backoff，不覆盖仍有效的 Grant；
- expiry、miss 和正常 negative-cache 到期可以发起 ordinary resolve；cache hit 始终仍经 Node 验证。

只有 authenticated Node 在**尚未取得 guard、尚未连接 Guest、尚未发送 upstream byte**时返回的
refreshable typed rejection，才能 compare-and-delete 精确 `grant_digest` 并启动一次 bounded
singleflight resolve。延迟旧拒绝不能删除新 entry。

触发拒绝的当前 HTTP 请求或 WebSocket upgrade **绝不自动重放**；resolve 只为后续请求更新 cache。
Node transport failure、Guest connect failure、部分响应、timeout、取消和任何 guard-acquired 结果都不
清 cache、不触发 authority refresh，也不重放。这个规则同样适用于看似幂等的请求，避免 transport
歧义导致应用操作执行两次。

## 6. Node verification 与 guard

Node 对每个内部请求按以下顺序执行：

1. 认证并加密 Gateway machine hop；比较Grant绑定的Gateway leaf SPKI digest；限制request/token/segment大小。
2. 严格解析 protected header，按 `kid` 选择本地 ring key并验证 Ed25519 signature。
3. 严格 decode claims，验证 version/issuer/audience/字段结构；计算 time verdict，但先不返回
   `Expired/NotYetValid`。
4. 比较请求到达的 Node、frame Cat、canonical hostname、Endpoint 和 protocol；只有全部相等才产生不可由wire
   构造的verified claims/time proof，并按proof的claims Cat查询registry。有效签名对应的cell absent返回
   `RuntimeNotReady`；在此之前不得观察registry。
5. 进入已验证Cat的短临界区`AdmissionCell`，加载对应Endpoint entry；精确比较workspace、Cat、Node、
   runtime incarnation、route epoch、hostname、protocol、port和platform target。
6. 若 binding 不同返回 `BindingMismatch`；若 gate/target 已关闭返回 `GateClosed` 或
   `RuntimeNotReady`。只有 binding 和 Active gate 都有效时才返回步骤 3 的时间错误。
7. 时间有效时，在仍持有 cell 的情况下 increment active guard；释放 cell 后才连接 Guest target。
8. request/connection 在成功、错误、取消、panic 和 timeout 的所有路径释放 guard。

步骤 5–7 必须线性化。每 Cat 只有一个 `AdmissionCell`，保存 per-Endpoint gate map、全局 lifecycle
admission、Endpoint/Platform guards 和 cancellation handles。HTTP/WebSocket、exec/deploy/control
都必须在该 cell 内原子检查 open 并取 guard。cell 内不执行网络、数据库、文件、VMM 或 fsync I/O，
也不持锁跨 `.await`。

当前Node core实现以同一个mutex同时承载complete `AdmissionSnapshot` compare-and-apply和已验签Grant的
binding compare/guard increment；snapshot精确包含desired revision、spec digest、placement、runtime
incarnation、checkpointed Guest IPv4、lifecycle与全部Endpoint bindings。replacement在取得mutex前完整验证；
同一cell/incarnation的open、install/close/remove、global close/try-close与RequireIdle open-Busy source都要求
Guest IPv4完全相等，target变化只能进入new incarnation/new cell。Endpoint-scoped stale
revision/spec/placement/target compare零副作用，全局compare歧义则fail closed。Endpoint close和新guard不能跨
两个锁竞态。guard是不可clone的RAII值，
普通返回、错误、panic和async task取消都经`Drop`归还。machine transport只从CA-verified TLS leaf构造
不可由wire生成的typed Gateway principal，并用同一registry执行该core；它不从header构造principal。

一旦 guard increment 成功，Node 后续只能返回 `UpstreamUnavailable` 或普通 upstream response，
不能再伪装成 pre-admission rejection。一次 Grant 只授权指定 target 上的一次 admission，不授权
lifecycle、volume、其他 Endpoint 或 Node 管理操作。

## 7. Gate 安装、close 与 RequireIdle

Node 只在当前 revision 的 VMM/Guest、完整磁盘集合、声明 mounts、network 和 Guest transport
达到 platform Ready 后，把 checkpoint 中的 Endpoint gate 持久化为：

```text
Active {
  workspace_id, endpoint_id, hostname, cat_id, node_id,
  runtime_incarnation, route_epoch,
  protocol, target_port
}
```

reconciler先fsync包含current desired依据的Closed prepared checkpoint和同进程effect edge，再fsync
Active checkpoint。最后一次fsync后，以immutable launch Desired、live gate predecessor Desired和current
Endpoint successor Desired三层封闭authority重跑Host全局扫描与Guest mounted-set challenge；只有该barrier
仍绑定durable Active successor时，才短暂进入`AdmissionCell`compare-and-publish Active，随后持久化completed
postcondition并由observation报告route Active。prepared只可在保留exact effect edge的同进程内重放；Active
可由该edge继续，或在cell已逐字段等于exact postcondition时只完成持久结算。重启默认Closed，任何已Active或
结果不明的epoch均烧掉并要求更高epoch。重复安装完全相同值幂等；同route epoch不同binding是
`SpecDigestConflict`。Agent启动或重启时，先从checkpoint、当前desired和完整物理inventory重建；
证明闭合前全局lifecycle admission和全部Endpoint entries都保持Closed。进程重启使内存gate实际
关闭，因此新AgentSession建立后，Control Plane必须提交提高所有原Active Endpoint route epochs的
系统Desired revision；Node不能直接把checkpoint中的旧epoch重新发布Active。

Endpoint-only changed/removed A的durable close顺序固定为：

1. checkpoint top-level先绑定new current Desired的revision/spec/placement/incarnation；
   `route_gates[A]`仍保存当前实际安装的old完整binding/Active，step写
   `close_gate {endpoint_id:A, route_epoch:old_epoch}`并fsync。step不复制binding。
2. effect前重读checkpoint和current Desired，逐字段重验top-level tuple，并由step唯一选择A的old entry；
   在cell内只允许相同完整binding的`Active -> Closed`，相同binding已Closed是唯一幂等postcondition。
   任一revision或binding不匹配都零副作用，交给current revision重plan；identity冲突Quarantine。
3. close成功后立即把A entry fsync为Closed，再只cancel/drain A。响应/进程结果不明时必须以同binding
   重新compare，或依赖restart默认Closed确认postcondition后持久化；绝不能在Active仍可能服务时只写Closed。
   一旦实际或不明close，old epoch永久不得重开。
4. changed A在drain后以一次checkpoint replace把entry替换为new完整binding/Closed并把step改为
   `InstallGate(A,new_epoch)`，只安装更大epoch；removed A在checkpoint仍保留old Closed binding时，先在
   cell内compare exact old binding/Closed并删除entry，确认absent后才以一次replace删除checkpoint entry、
   推进next step且不install。in-process retry可接受该exact absence，但仍重做A的drain；其他missing或
   binding mismatch不能adopt。new Endpoint没有old entry，直接从new binding/Closed进入InstallGate。

完整binding不变的B，其checkpoint entry、cell gate、guards和cancellation handles都不得修改；已有stream和
缓存Grant继续。一个Cat的removed/changed/new Endpoint delta按endpoint ID稳定升序，每个Endpoint完整序列
完成后才处理下一个，不引入batch close token。
stale CloseGate遇到new revision或new binding只能零副作用，不能按endpoint ID误关新gate。

每次full inventory之前，runner还必须执行mandatory serialized pre-scan。process-local session封闭保存由
accepted Ready effect或complete scan确认的最后一个exact Running gate Desired；它可在StartRuntime/final
Mount建立，不要求checkpoint已经Stable。strict Endpoint-only successor会在一个cell临界区内立即latch并取消全部
changed/removed Endpoint tunnel，未变Endpoint保持原gate、guard和stream。该process-local latch可一次覆盖
多个changed Endpoint，但durable CloseGate/drain/remove仍严格按Endpoint ID逐个完成。pre-scan只在exact
current Stable/cell、previous exact Stable + strict Endpoint successor的完整latch、exact RequireIdle Busy/Open
source，或current checkpoint与retained effect edge结算之一成立时，才允许Open gate继续存活；前两类只是
概念上的exact-retained/endpoint-latched状态。已经Closed/untrusted的session可先fail-close后正常返回。通过
上述保留条件后scanner Incomplete/deadline按Degraded保留已证明gate；pre-scan
本身非完成或scanner显式corrupt/conflict/foreign必须全局fail-close并取消tunnel。

`CloseAdmission`只用于离开Running、runtime replacement、Node drain、placement、volume、mount、network、
platform变化以及下面的RequireIdle；它在cell内同时关闭全局lifecycle admission和全部Endpoint gates，
Endpoint-only revision不得使用。`CancelAndDrain`在cell外持久化close、取消对应
transport 并有界等待 guards 归零；超时就保持 runtime 和 writer，报告 Blocked，不能继续 pause、
snapshot、detach 或 teardown。active WebSocket 不因 token TTL 中断，只由显式 cancellation/drain、
连接端点或 Agent 进程故障结束。

`RequireIdle` 只用于一次自动 Running -> Suspended 条件转换，不使用 proposal、idle-closure proof
或二次 Control Plane commit：

1. Control Plane 以当前 Running revision 为 compare condition，提交一个完整 Suspended desired
   revision；其中 `RequireIdle {attempt_id, source_revision, source_runtime_incarnation}` 只引用这一次
   revision transition。
2. Node先把该attempt写为checkpoint中的`Armed`并fsync，再只执行一次
   `try_close_all_if_idle`。任一 Endpoint/Platform guard 非零时，
   cell 和 runtime 完全不变，持久化该 revision 的 terminal `PreconditionFailed(Busy)`。
3. guard Busy后Controller创建新的完整Running revision，保留原route epochs；不能在guards后来
   归零时复用失败的Suspended revision。cell从未close，因此旧gate可以继续服务已缓存Grant，
   但signer在desired恢复Running前停止新签发。
4. guards为零时，Node在一个cell线性化点关闭全部work admission，持久化`Succeeded/Closed`后在
   cell外验证watcher fresh+idle并quiesce。任一步失败都terminal Busy且保持Closed，不恢复旧gate。
   restart看到`Succeeded/Closed`继续后置检查；看到结果不明的`Armed`保守Busy且保持Closed。
5. 只要gate曾close或结果不明，Controller创建fresh Running revision时提高全部可能关闭的Endpoint
   route epochs；Node重新验证后只安装新epoch。同一attempt不再次评估，也没有第二个authority
   handshake或旧epoch恢复路径。

手动 stop、drain、migration 和 destroy 一律使用 `CancelAndDrain`，不能用 `RequireIdle` 等待用户流。

## 8. Typed results 与 refresh

Node-to-Gateway 内部结果是闭集；公开响应不得泄漏 identity：

| reason | 产生条件 | cache 行为 |
|---|---|---|
| `Expired` | signature、binding 和 Active gate 都有效，只有自然过期 | 精确删除并为后续请求 resolve |
| `NotYetValid` | signature、binding 和 Active gate 都有效，Node 时钟早于窗口 | 不刷新；告警时钟/配置 |
| `BindingMismatch` | 已验签 claims 与 request 或 installed binding 不同 | 精确删除并为后续请求 resolve |
| `GateClosed` | exact binding 的 Endpoint/lifecycle gate 已关闭 | 精确删除并为后续请求 resolve |
| `RuntimeNotReady` | exact binding 的 platform runtime/transport 尚未 Ready | 精确删除并为后续请求 resolve |
| `UnknownKey` / `InvalidSignature` / `InvalidClaims` | key、签名或结构不可信 | 不刷新；安全遥测 |
| `UpstreamUnavailable` | guard 已取得后 Guest connect/stream/应用端口失败 | 不刷新、不重放 |

前五类都只能在 `guard_acquired=false` 时产生，其中只有表中明确写“resolve”的三类加
`Expired` 可刷新。没有 authenticated typed response 的 transport error 不是 refresh signal。

## 9. Key ring 与 rotation

Signer 每一时刻只使用一个 active private key；Node 使用最多8把key的有界、版本化 public-key ring。fixed
artifact、secret reference、持久lineage与精确ACK合同由
[Route v2 Signing Authority v1](route-signing-authority-v1.md)唯一冻结。ring 更新
必须完整验证后原子 swap；加载失败的 Node 不 Ready并保持 admission Closed。heartbeat/
observation 报告AgentSession、ring version、按
[Runtime Reconciliation v1 §16](runtime-reconciliation-v1.md)计算的`key_ring_digest`和已排序
`loaded_kids`。Runtime合同的null/null/empty表示尚无有效ring；non-null/non-null/empty表示已经加载的
合法空ring。两者都保持admission Closed，只有non-null version/digest、重算匹配且包含active `kid`才
满足Route签发条件。

普通 rotation 顺序固定：

1. 在专用 secret service/HSM 边界生成或导入新 private key；IaC 只管理 secret reference 和读取
   policy，private bytes 不进入 Terraform variable、plan、state、artifact、日志或 Gateway/Node。
2. 把新 public key 作为 staged ring version 发布；所有可调度 Node 原子加载并 ACK。
3. Signer transaction 切换 active `kid`，并持久化旧 key 的 `last_old_issue_at`；此后只用新 key。
4. 保留旧 public key到 `last_old_issue_at + max_token_ttl + max_clock_skew` 之后，再发布删除旧 key
   的 ring version并等待 Node ACK；最后删除旧 private secret。

只有旧 private key和两个 public keys仍部署时才能回切。不得启用 unsigned、旧 wire、单 key cohort
或 verifier fallback。key 泄漏时先停止签发并关闭所有可达 Node admission；不可达 Host 必须外部
隔离。部署全新 ring并取得 ACK 后才能重开。终止已有 streams 仍需 cancel-and-drain 或 Host/network
fence，删除 public key本身只阻止新的 admission。

## 10. Route availability boundary

| 故障 | 行为 |
|---|---|
| 单个 Control Plane replica 失败 | Gateway resolve 由其他健康副本处理 |
| Control Plane 全断 | 已有 stream 继续；仅已预热该 hostname 的 Gateway replica 可在 Grant expiry 前接新 admission |
| 冷/重启 Gateway | local cache 为空；Control Plane 不可达时不接新 admission，不宣称 fleet-wide cache HA |
| 单个 Gateway 失败 | 其他 Gateway 在 Control Plane 健康时自行 resolve；不复制故障 replica cache |
| Node Agent 重启 | proxy stream可中断；新session+inventory attestation后先提交更高route epochs，旧token不复活 |
| VMM replacement | 新 runtime incarnation；旧 token立即 mismatch |
| Endpoint rebind | changed Endpoint使用新route epoch且旧token立即mismatch；未变Endpoint保持原serving lineage |
| Node/Host partition | 不自动改投；恢复需Active HostFenceEvent、新完整Desired及逐卷authorization CAS |

更完整的数据库、Host fence、监控和 qualification 合同见
[Operations and HA](../operations-ha.md)。

## 11. Verification

同一 schema 生成并由 signer/verifier 跨 crate 共享：固定测试 key、positive compact token、完整
expected claims，以及identity/incarnation/route-epoch/port/time、wrong alg、unknown kid、重复/未知
字段、oversize、tampered signature和rotation overlap的negative vectors。signer另测stale desired/
observation revision，不能把desired revision塞回Grant vector。

还必须证明：

- 四个`Id` claims使用Runtime边界；time claims在0与`i64::MAX`边界解析一致，所有TTL/skew/retention
  checked arithmetic的overflow/underflow都fail closed；
- admission 与 close 并发时，close 线性化点后没有新 guard；panic/cancel/timeout 不泄漏 guard；
- changed A先以durable CloseGate关闭/fsync old binding，再以更大epoch安装new binding；remove A关闭/drain
  后先从cell compare-remove exact old Closed entry，确认absent才删checkpoint entry/advance且不install；
  unbind A只取消A，B的checkpoint entry、gate、guards、active WebSocket与新
  admission不中断，serving epoch不变；
- CloseGate在cell close前、close后fsync前、Closed后替换/删除前分别注入不终止Agent的effect/fsync
  失败；重试只操作A并确认同binding Closed，old epoch不重开；stale token遇new revision/binding零副作用
  且不能关闭new gate；
- 同Cat removed/changed/new delta按endpoint ID稳定逐个执行；不生成batch close；无进程重启的失败/重试
  当前A不修改B；
- `RequireIdle` guard Busy不改变cell/epoch；任何实际或不明close后旧epoch不能重开；
- 在上述每个边界另行kill Agent；restart使全部内存gate实际Closed，必须提高全部原Active Endpoint epochs，
  不能声称只恢复A，也不把CloseGate当作旧epoch恢复依据；
- app port未监听产生 `UpstreamUnavailable`，不把 platform gate误报为未Ready，不刷新 route；
- Node machine TLS矩阵覆盖有效Gateway leaf、无client certificate、未知CA、错误EKU、非Ed25519 leaf和
  错误ALPN；有效chain但Grant绑定另一Gateway SPKI时必须在Guest connect前返回`BindingMismatch`；
- tunnel frame覆盖noncanonical/duplicate/unknown/oversize header与body、错误digest、错误Node、过期Grant、
  frame Cat与claims Cat不等、缺registry cell、缺Guest target和Closed gate；tampered signature/unknown `kid`在
  registry present/absent时同错且零guard/Guest I/O，只有valid signed absent Cat返回`RuntimeNotReady`；只有完整
  认证/验签/request binding/gate通过才允许触达Guest socket；
- same-incarnation AdmissionSnapshot的open、install、close、remove、global close、try-close与RequireIdle Busy
  source逐项拒绝Guest IPv4-only drift；两个Active Endpoint下close A不能改变B取得的target；
- Gateway到Node每个current request最多一次TCP/TLS/HTTP attempt；TLS/HTTP/Guest失败和typed rejection均不
  自动重放。`101`后的双向EOF/cancel以及Node shutdown都必须有界结束并把guard/permit归零；
- pre-admission stale rejection与新resolve竞争时，旧 digest不能删除新entry；当前POST和WebSocket
  upgrade都不重放；
- per-replica LRU、negative backoff、singleflight、waiter和resolve semaphore在高基数hostname与慢
  Control Plane下保持硬上限；
- key staged/switch/overlap/retire、atomic reload、unknown kid和紧急close全部 fail closed；
- Control Plane全断明确区分existing stream、warm replica cached Grant、expired Grant和cold replica。

## 12. Clean-slate cutover

首次部署的唯一有序 runbook 是
[Operations and HA §8](../operations-ha.md#8-首次终态部署)。本规格只增加 Route 验收条件：exact
release 只解析 v2；旧 mirror/parser 和 credential 已退出；Node 在全 gate Closed 时提交 current
AgentSession、empty inventory attestation 与新 ring ACK；Gateway 启动后仍必须通过第 11 节 oracle
才可开放 ingress。
