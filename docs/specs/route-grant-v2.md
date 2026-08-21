# Route Grant v2

- 状态：Implemented/Frozen v2 authority；shared codec、Control signer/independent Gateway machine resolve、
  Node verification/admission、signed per-Endpoint command poll/result lane、Gateway到Node tunnel、
  `cats-gatewayd` public proxy以及atomic lifecycle AdmissionCell interlock已组成；真实production
  mTLS E2E与rotation qualification仍开放。ADR-0057 product vocabulary已闭合：resolve rejection使用
  `run_required`且fixed vector严格拒绝旧`wake_required`，Gateway不得触发隐式lifecycle action
- Route Authority：[ADR-0041](../decisions/0041-node-verified-route-admission.md)
- Lifecycle interlock：[ADR-0056](../decisions/0056-atomic-per-cat-runtime-lifecycle.md)
- Product actions：[ADR-0057](../decisions/0057-product-lifecycle-actions-and-internal-execution-evidence.md)
- Runtime identity/result：[Atomic Runtime Lifecycle v1](atomic-runtime-lifecycle-v1.md)
- Full inventory foundation：[Runtime Inventory and Telemetry v1](runtime-inventory-observation-v1.md)
- Operations：[Operations and HA](../operations-ha.md)

Route Grant 是 Control Plane 为一个当前 Running runtime 签发的短期 capability。Gateway
只缓存并搬运 token；Node 同时验证签名和本地 gate，并原子取得 active guard。token、Gateway
cache、hostname lookup index 和 observation 都不是独立 authority。

ADR-0056 已取代本规格旧版对完整 Desired revision、Running/route Observation 与 lifecycle reconciler 的
依赖。atomic release 的 signer只消费 exact RuntimeReady/Serving receipts、current lifecycle head、current
AgentSession和fresh full-inventory attestation；Observation只用于监控/drift，绝不授权签发或结算Route。

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

## 2. Endpoint authority 与 Route Operation

Endpoint不是runtime lifecycle command的一部分。`EndpointRecord`/current Endpoint binding 是产品
authority；`HostnameEndpointLookup`只定位current binding，不是第二份可签发authority。一次 Endpoint
create、unbind、hostname/port/protocol change 或 rebind 必须在一个 PostgreSQL transaction 内：

1. 锁current Cat与Endpoint identity；
2. 对changed/new binding分配严格增加的per-Endpoint `route_epoch`；removed binding同样永久burn旧epoch；
3. 写完整current Endpoint binding；
4. 更新canonical hostname lookup；
5. 标记该Endpoint不可继续从旧Serving receipt签发。

transaction任一部分失败就全部回滚。Route Controller随后从current Endpoint metadata与current lifecycle
head自动派生per-Endpoint `EnableRoute`/`DisableRoute` Operation；用户不创建Route lifecycle intent。每
Endpoint最多一个unresolved Route Operation，不同Endpoint可独立推进；它不加入per-Cat lifecycle lane。

`route_epoch`是per-Endpoint serving lineage：binding变化、gate实际Closed、close结果不明或Agent replacement
后重开都必须严格增加。Node任意时刻只安装一个epoch，不保留双epoch窗口。唯一保留epoch的路径是
`SuspendDeclined(Busy)` 的exact proof证明AdmissionCell从未close。

Endpoint A的Disable/Enable只compare-and-close/install A，不能修改B的gate、guards、cancellation或active
stream。生命周期离开Running则由shared AdmissionCell一次关闭全部Endpoint；later Start只到RuntimeReady，
Route Controller再为intended Endpoint分别生成fresh Enable。

## 3. Signer snapshot

一次 resolve 必须在同一个 PostgreSQL transaction snapshot 中读取并闭合：

1. canonical hostname index 与current Endpoint binding逐字段相同；
2. Cat current lifecycle head投影出exact `effective_runtime_ready`，没有任何leaving-Running unresolved
   lifecycle Operation，placement node/epoch为current值；
3. current terminal per-Endpoint Route Operation是`Serving`，其receipt逐字段绑定current Endpoint、route
   epoch、effective RuntimeReady source、runtime incarnation与current AgentSession的
   `admission_session_epoch`；
4. current NodeIdentity是provisioned，且A23 current `NodePlacementPolicy.node_id`与identity、placement
   逐字段相同；同一policy给出strict canonical `node_transport_target`。缺policy或JSON/projection不一致是stored
   corruption；registration/observation与legacy `nodes.agent_url`不能提供fallback；
5. 当前`AgentSession`精确属于该node、Host/boot/agent instance，且epoch等于Serving receipt；
6. 该session有fresh `RuntimeInventoryAttestation {session, inventory_epoch, scan_id,
   inventory_digest, source_report_id, source_sequence, accepted_at_unix_ms}`；它来自accepted full scan，
   完整schema与digest算法以
   [Runtime Inventory Observation v1](runtime-inventory-observation-v1.md) 为准，
   后续partial observation不能覆盖；fresh精确使用
   [Runtime Inventory and Telemetry v1 §9](runtime-inventory-observation-v1.md#9-store-transaction与schema)的同一DB-now与
   `accepted_at <= db_now < accepted_at + 60000ms`，右边界相等已过期；
7. current AgentSession的durable key-ring ACK中，ring version/digest非null、按exact `loaded_kids`重算
   匹配，且current signer `kid`出现于Node原子加载的`loaded_kids`；unavailable或empty-but-valid ring都不签发。

Signer 以同一 snapshot 的数据库时间生成 `iat/nbf/exp`。任何条件不成立都返回
RunRequired/Pending/Unavailable，不从旧 token、lookup或Observation复制authority。`run_required`只提示调用方
显式发起product run，不让Gateway创建Operation。签发后若token已到期就丢弃。旧
`WakeRequired/wake_required`严格decode失败，不是兼容alias。

Observation的Degraded/Ready字段只是telemetry：它不能建立或延长Serving。RuntimeReady证明平台拥有正确
VMM、network、完整device/mount与Guest transport；Serving证明exact Endpoint gate已安装。两者都不表示用户
应用已监听`target_port`；应用health若产品需要必须作为独立策略，不能改变route authority。

## 4. Public ingress 与内部身份

默认 Endpoint 是公网应用入口。Gateway 规范化 TLS SNI/HTTP Host 后查 route；它不要求
WorkOS session，也不替用户应用做 Workspace 成员鉴权。用户的 Authorization、Cookie 和应用
headers 作为应用数据转发给 Guest。Cats management API 继续使用自己的用户/Workspace 鉴权。

唯一local operational exception是同一listener在完成有界request-head解析后处理exact
`GET /healthz`：请求必须有一个合法Host、没有body/transfer encoding或WebSocket upgrade，响应固定为
`200`并`Connection: close`。它只证明Gateway fixed artifacts、TLS clients、cache与listener已完成启动组合，
不得访问cache、Control、Node或其他外部I/O。其他method、相近path和query仍是普通应用route；带body或
transfer encoding的`GET /healthz`返回`400`并关闭连接，已缓冲的pipeline bytes不得成为下一请求。

Gateway的public HTTP/1.1 proxy按一个request/一个Node tunnel严格证明response boundary。response head与
chunk/trailer metadata沿用public head byte cap，拒绝重复或冲突的`Content-Length`/`Transfer-Encoding`；
HEAD、204/205、304、fixed Content-Length与single canonical chunked分别按其精确边界转发。无长度response只
能以tunnel EOF定界，完成后必须关闭public connection；`Connection: close`、畸形、截断或response边界后的
额外tunnel bytes同样关闭且额外bytes不转发。只有self-delimited response后同一单请求tunnel立即证明EOF且
无extra bytes，才可把public keepalive用于下一次独立resolve/admission。普通HTTP的interim 1xx在v1中fail
closed；request `Expect`也被拒绝，因此不会破坏普通non-interim路径。WebSocket只先转发upgrade head；只有
Guest返回exact HTTP/1.1 101、`Connection: Upgrade`与`Upgrade: websocket`后，才转发已缓冲及后续raw bytes。
非101或畸形upgrade response关闭双方连接并丢弃client pipeline。
从cache lookup、Node connector/open、request head/body tunnel write、tunnel request half-close，到等待Guest
response、转发response body与WebSocket raw stream，全阶段都在同一connection task内持续观察public peer
EOF/error与有界pipeline overflow；命中即取消当前阶段future、drop当前tunnel并释放Node guard与Gateway
connection permit，且不得继续发送Guest mutation bytes。为下一request预读的public bytes只进入同一有硬上限
的pipeline buffer，不由detached watcher消费；超限fail closed。

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
  `409 run_required|pending`、`503 unavailable`。认证失败为`401 authentication_failed`；frame错误为
  `400/405/406/413/415 invalid_request`；stored/internal错误为`500 internal`。所有response带
  `Cache-Control: no-store`；`405`带`Allow: POST`，`503`带`Retry-After: 1`；不redirect；
- per-replica resolve semaphore与body/deadline是资源界，不是authority。handler与其已经启动的Store
  closure共同持有同一个active owner；timeout或client取消只能释放handler owner，不能提前释放Store owner。
  graceful shutdown先关闭新admission，再等待所有active owner归零。client取消不会产生durable route
  workflow；签名response丢失后普通重试重新闭合当前snapshot，不复用丢失token。

Gateway到Control的独立identity由[ADR-0045](../decisions/0045-independent-gateway-workload-identity.md)
与[Gateway Workload Identity Authority v1](gateway-workload-identity-v1.md)冻结：固定CA先验证TLS chain，
verified leaf canonical SPKI再映射PG current credential；每个keepalive request都重验，Workspace scope只使用
hostname在同一authority snapshot解出的current Workspace。PG exact Endpoint/lifecycle/Serving current pointers是唯一运行时
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

Gateway公网listener对每个已经缓冲的client egress write使用一个不可续期的absolute backpressure
deadline：默认`5000 ms`，部署只可配置`1..=60000 ms`；zero、超上限或当前monotonic clock不能表示的值都在
listener bind前拒绝。partial write进展不能重置deadline，public reader EOF/error/overflow与该write竞速并立即
取消同task的tunnel/guard/permit；没有待写bytes的空闲WebSocket不启动这个deadline。

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

production `cats-noded`把fixed signer artifacts、durable rotation origin、installed verifier/listener与
signed Route command runner视为一个必选composition。listener与mandatory live delivery未完成
就不启动lifecycle/inventory task；不存在“Route delivery可选、其余runtime继续”的
production branch。

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

atomic release以同一个mutex同时承载exact `AdmissionSnapshot` compare-and-apply和已验签Grant的
binding compare/guard increment；snapshot精确包含current lifecycle head/effective RuntimeReady、placement、
runtime incarnation、checkpointed Guest IPv4、AgentSession epoch、lifecycle与全部Endpoint bindings。replacement在取得mutex前完整验证；
同一cell/incarnation的open、install/close/remove、global close/try-close与RequireIdle open-Busy source都要求
Guest IPv4完全相等，target变化只能进入new incarnation/new cell。Endpoint-scoped stale
lifecycle source/session/placement/target compare零副作用，全局compare歧义则fail closed。Endpoint close和新guard不能跨
两个锁竞态。guard是不可clone的RAII值，
普通返回、错误、panic和async task取消都经`Drop`归还。machine transport只从CA-verified TLS leaf构造
不可由wire生成的typed Gateway principal，并用同一registry执行该core；它不从header构造principal。

一旦 guard increment 成功，Node 后续只能返回 `UpstreamUnavailable` 或普通 upstream response，
不能再伪装成 pre-admission rejection。一次 Grant 只授权指定 target 上的一次 admission，不授权
lifecycle、volume、其他 Endpoint 或 Node 管理操作。

## 7. Route command、gate close 与 lifecycle interlock

Node 只接受绑定 exact terminal `RuntimeReady`/effective RuntimeReady 的 `EnableRoute`。production
transport与lifecycle command lane平行，但不共享per-Cat lane：Node使用current `AgentSession`签名
`POST /v1/internal/runtime/route-command-polls`并把exact response签名提交到
`POST /v1/internal/runtime/route-result-commits`。poll可携带durable `RouteNodeRingAck`；ACK只证明
该session已原子加载一个public ring，不证明RuntimeReady或Serving。

public command contract是：

```text
RouteServingBinding {
  workspace_id, endpoint_id, hostname, cat_id,
  placement_identity,
  effective_runtime_ready,
  route_epoch,
  admission_session,
  protocol, target_port
}

RouteCommandEnvelope {
  version, operation_id, binding,
  predecessor: Genesis | Exact {operation_id, terminal_result_kind, terminal_result_digest},
  command: Enable | Disable,
  request_fingerprint
}

RouteNodeResult =
  Serving {binding, admission_cell_receipt_digest}
| Closed {binding, admission_cell_receipt_digest}
| Rejected {binding, reason, no_effect_receipt_digest}
```

`effective_runtime_ready`是完整
`EffectiveRuntimeReady {source_lifecycle_operation_id,runtime_incarnation,runtime_config_digest,
runtime_ready_receipt_digest}`，不得只传operation ID或incarnation。`admission_session`是完整
`SessionBinding`，不得把单一epoch当成session identity。Control只以terminal
`Serving | Closed | Rejected`结算Node response；Endpoint binding、lifecycle close/ambiguous close或
AgentSession replacement可用exact `ControlInvalidation`终结已不可执行的unresolved Route
Operation，但它不伪造Node gate receipt。

EnableRoute在first gate effect前fsyncper-Endpoint route command与Closed prepared binding；重新闭合current
AgentSession、effective RuntimeReady、Endpoint metadata、runtime/Guest target与fresh full inventory
attestation后，才在AdmissionCell compare-and-publish Active，并在return前fsync exact Serving result。exact
retry返回原result；same route Operation ID不同binding/fingerprint fail closed。Observation只能随后报告Active，
不能结算Route Operation。

Agent启动/replacement后内存AdmissionCell默认Closed，不能从checkpoint直接重开。Serving receipt绑定old
`admission_session_epoch`因current session mismatch立即无效；Route Controller必须burn route epoch并提交fresh
Enable。Grant不增加session claim，fresh epoch+runtime incarnation已使old Grant无法匹配。

Endpoint-only changed/removed A的Disable顺序固定为：

1. fsync exact per-Endpoint command，绑定old完整ServingBinding与route Operation identity；
2. 在AdmissionCell只compare-and-close A的exact binding；same binding已Closed是幂等postcondition，stale
   binding/epoch零副作用，不能按endpoint ID关闭new binding；
3. fsyncClosed result，再只cancel/drain A；changed A以后只以更大epoch Enable，removed A保持absent；
4. binding不变的B，其gate、guard、cancellation、stream和epoch都不改变。

close结果模糊视为可能已Closed，old epoch永久burn。不同Endpoint各走独立lane；不建立batch command或以A的
失败阻塞B。

每次full inventory前，Node执行serialized admission pre-scan。current AgentSession与exact in-memory
AdmissionCell仍可信时，complete scan可验证现有binding；partial/incomplete scan不能制造Active或新
attestation。Agent replacement、foreign/conflicting route evidence或无法闭合session时全局fail-close并取消
tunnel。

接受任何离开Running的atomic lifecycle command后，Node的first local effect是在同一AdmissionCell关闭全局
lifecycle admission与全部Endpoint gates，再在cell外cancel/drain：

```text
EnableRoute linearizes first -> install可完成 -> lifecycle close随后关闭
lifecycle close linearizes first -> late Enable sees stale/Closed -> zero effects
```

Control在接受suspend/warm/cold/destroy的同一Cat-row transaction中停止fresh signing/Enable generation。
需要停止旧执行的产品动作不等待所有per-Endpoint RPC；late Serving result只是历史evidence，不能重开
current runtime。

`RequireIdle`只用于atomic Suspend的`admission_policy=require_idle`。Node durably接受Suspend后在cell内只检查
一次：任一Endpoint/Platform guard非零时cell/runtime完全不变，返回
`SuspendDeclined {reason: Busy, effective_runtime_ready, cell_never_closed_receipt}`。Declined成为新lifecycle
head，但Signer使用该head投影的original effective RuntimeReady，因此old Serving/epoch可继续。guards后来归零
不重试同Operation。

guards为零时Node原子close；之后任何失败、crash或模糊结果都保持Closed并burn全部可能关闭的Endpoint
epochs，不能返回Declined或恢复old epoch。`close_and_drain`永不返回Busy：grace deadline前正常drain，
需要strong stop的action到期后可以force-stop Guest/VMM并断开stream。该规则取代旧“drain timeout必须保留
runtime/writer”；active WebSocket仍不因Grant TTL单独中断。

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
observation可以报告ring telemetry，但signer只消费current AgentSession的durable ring ACK：ring version、按
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
| Node/Host partition | 不自动改投；恢复需Active HostFenceEvent、HostLost predecessor、新placement及逐卷authorization CAS |

更完整的数据库、Host fence、监控和 qualification 合同见
[Operations and HA](../operations-ha.md)。

## 11. Verification

同一 schema 生成并由 signer/verifier 跨 crate 共享：固定测试 key、positive compact token、完整
expected claims，以及identity/incarnation/route-epoch/port/time、wrong alg、unknown kid、重复/未知
字段、oversize、tampered signature和rotation overlap的negative vectors。signer另测stale lifecycle head、
effective RuntimeReady、Serving receipt、AgentSession与attestation；Observation不能授权，lifecycle Operation ID/
session epoch也不能塞进Grant vector。

还必须证明：

- 四个`Id` claims使用Runtime边界；time claims在0与`i64::MAX`边界解析一致，所有TTL/skew/retention
  checked arithmetic的overflow/underflow都fail closed；
- admission 与 close 并发时，close 线性化点后没有新 guard；panic/cancel/timeout 不泄漏 guard；
- changed A先以durable DisableRoute关闭/fsync old binding，再以更大epoch Enable；remove A关闭/drain
  后从cell compare-remove exact old Closed entry且不install；unbind A只取消A，B的route state、gate、guards、active WebSocket与新
  admission不中断，serving epoch不变；
- DisableRoute在cell close前、close后fsync前、Closed result前分别注入不终止Agent的effect/fsync
  失败；重试只操作A并确认同binding Closed，old epoch不重开；stale token遇new lifecycle source/binding零副作用
  且不能关闭new gate；
- 同Cat removed/changed/new delta按endpoint ID稳定逐个执行；不生成batch close；无进程重启的失败/重试
  当前A不修改B；
- `RequireIdle` guard Busy不改变cell/epoch；任何实际或不明close后旧epoch不能重开；
- `SuspendDeclined(Busy)`成为new lifecycle head时，Signer从head投影original effective RuntimeReady并继续匹配
  old Serving source；若cell-never-closed proof错/缺则不签发；
- 在上述每个边界另行kill Agent；restart使全部内存gate实际Closed，必须提高全部原Active Endpoint epochs，
  old Serving因exact admission session epoch失效，不能声称只恢复A，也不把route checkpoint当作旧epoch恢复依据；
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
  自动重放。阻塞cache waiter、connector、request head/body write或request half-close时public disconnect必须
  立即drop同栈future且不再产生Guest bytes；`101`后的双向EOF/cancel以及Node shutdown都必须有界结束并把
  guard/permit归零；
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
