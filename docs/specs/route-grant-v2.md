# Route Grant v2

- 状态：Target contract；shared codec、Control resolve handler 与 Node verification/admission core
  分阶段实现，production machine transports 与 public proxy 仍保持关闭
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
- success最多8192 bytes，canonical JSON字段依次是`version`、`endpoint_id`、
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

当前repository尚无能满足本节的Gateway workload credential authority。[ADR-0044](../decisions/0044-independent-route-v2-signing-authority.md)
与[Route v2 Signing Authority v1](route-signing-authority-v1.md)已经冻结独立Route v2 signer secret
reference/public-ring artifact与rotation边界；Node production full inventory已只读投影fixed installed ring，
Control signer snapshot也会消费其exact ACK，但installer、持久rotation writer和production composition尚未完成；
v2绝不借legacy V1 signer/key作为fallback。因此production listener不会
构造typed principal，普通Control组合固定在pre-body/pre-PG `401`；即使未来误注入principal但尚无独立
v2 signer，也在body/admission/PG前返回`503`。后续Accepted authority必须至少冻结：

1. 独立Gateway workload ID、不可复用credential ID、credential lineage与current/revoked状态；
2. Control与Node各自的current allow policy，以及TLS peer proof到该精确credential的绑定；
3. verifier-first rotation overlap、撤销、重启加载失败和credential丢失的fail-closed行为；
4. Control与Node encrypted listener的trust root、部署artifact固定路径/权限以及rotation ACK证据。

A19只授权Node到Control，A23只授权deployment provisioner写placement policy；两者都不能授权Gateway。
legacy shared bearer、`nodes.agent_url`、HTTP header自报principal、推测的SPIFFE/SAN或云IAM映射都不是
fallback。在该新authority Accepted并组成listener前，test principal只能用于显式test router。

### 4.2 Node admission frame的冻结边界

Node typed failure envelope已经冻结为canonical JSON
`{"version":2,"guard_acquired":false,"reason":"expired"}`及§8闭集；只有
`UpstreamUnavailable`允许`guard_acquired=true`。但完整Gateway->Node HTTPS request frame尚不能从现有
authority推导：Gateway credential/trust、内部grant保留字段、public request header/body streaming、
upgrade、deadline、取消以及guard与proxy lifetime的组合仍未冻结。实现不得增加裸Grant preflight，
也不得借legacy Node HTTP/shared bearer旁路；Node verification/admission core保持可组合但production
HTTPS route/listener关闭，直到同一Accepted合同闭合这些边界。

## 5. Gateway cache

每个 Gateway replica 只有一个进程内 cache；不使用 DynamoDB mirror、共享 route authority 或
跨 replica 一致性协议。positive entry 精确保存：

```text
canonical hostname -> {
  endpoint_id, node_transport_target, opaque_grant,
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

1. 认证并加密 Gateway machine hop；限制 request/token/segment 大小。
2. 严格解析 protected header，按 `kid` 选择本地 ring key并验证 Ed25519 signature。
3. 严格 decode claims，验证 version/issuer/audience/字段结构；计算 time verdict，但先不返回
   `Expired/NotYetValid`。
4. 比较请求到达的 Node、canonical hostname、Endpoint 和 protocol。
5. 进入该Cat的短临界区`AdmissionCell`，加载对应Endpoint entry；精确比较workspace、Cat、Node、
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
incarnation、lifecycle与全部Endpoint bindings。replacement在取得mutex前完整验证；Endpoint-scoped
stale revision/spec/placement compare零副作用，全局compare歧义则fail closed。Endpoint close和新guard
不能跨两个锁竞态。guard是不可clone的RAII值，
普通返回、错误、panic和async task取消都经`Drop`归还。该core要求不可由wire构造的authenticated
Gateway principal，但不会自行构造principal或执行proxy I/O；HTTPS transport仍受§4.2阻塞。

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

reconciler先fsync包含current desired依据的checkpoint，再短暂进入`AdmissionCell`发布Active，
随后observation才能报告route Active。重复安装完全相同值幂等；同route epoch不同binding是
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
