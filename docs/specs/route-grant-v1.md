# Route Grant V1 wire protocol（冻结）

- 状态：Frozen v1（2026-08-06）；B0 只冻结契约，生产实现由 B1–B5 完成
- 决策依据：[ADR-0033](../decisions/0033-short-lived-signed-route-grants.md)
- 共同测试输入：[固定向量](route-grant-v1-vectors/README.md)

改变 compact bytes、字段、验签/时间语义、Node admission、cache 状态或 key 轮换顺序，必须先
更新 ADR 并升 wire version。不得为了兼容旧 unsigned route 在 v1 parser 中增加可选分支。

## 1. 常量

| 名称 | 值 | 说明 |
|---|---:|---|
| `WIRE_VERSION` | `1` | protected header 的整数 `v` |
| `ALGORITHM` | `EdDSA` | 仅 Ed25519；不做算法协商 |
| `TYPE` | `cats-route-grant+jwt` | 防止与其他 JWS/JWT 混用 |
| `ISSUER` | `cats-control-plane` | claims 的 `iss` |
| `AUDIENCE` | `cats-node-agent` | claims 的 `aud` |
| `DEFAULT_LIFETIME_SECONDS` | `60` | issuer 默认值 |
| `MAX_LIFETIME_SECONDS` | `120` | `exp - iat` 的硬上限 |
| `MAX_CLOCK_SKEW_SECONDS` | `5` | 只用于 not-before 下界与真实新-admission replay 上界 |
| `MAX_COMPACT_BYTES` | `4096` | ASCII compact token 总长度 |
| `MAX_HEADER_BYTES` | `512` | protected header 解码后上限 |
| `MAX_CLAIMS_BYTES` | `2048` | claims 解码后上限 |
| `SIGNATURE_BYTES` | `64` | Ed25519 signature 长度 |
| `NEGATIVE_CACHE_SECONDS` | `5` | Gateway 仅对权威 404/410 缓存 |

以真实时间计，一张最大寿命 grant 在最坏 Node 时钟负偏差下可准入最多 125 秒。这只界定新的
admission/replay；已建立的 stream 可以继续持有 guard，因此 125 秒等待本身不构成旧 Node
authority transfer proof。

## 2. Compact envelope 与 canonical encoding

wire 是 ASCII：

```text
BASE64URL(PROTECTED_HEADER) "." BASE64URL(CLAIMS) "." BASE64URL(SIGNATURE)
```

签名输入是前两个已编码 segment 及中间的一个 ASCII `.`，不含末尾 `.` 或换行。

### 2.1 base64url

- RFC 4648 URL-safe alphabet `A-Z a-z 0-9 - _`，禁止 `=` padding、空白和换行；
- decoder 必须拒绝不可能的长度、non-zero unused tail bits 和任何解码后再编码不逐字节相同的
  segment；
- compact 必须恰有三个非空 segment，signature 解码后必须恰为 64 bytes；
- 在 JSON parsing 或 key lookup 前执行总长度与 segment 解码上限检查。

### 2.2 JSON profile

Header 与 claims 都是 UTF-8 JSON object，但 v1 只允许下表列出的 member：

- member 必须按本文表格给出的顺序出现；无 member 前后空白、冒号/逗号旁无空白；
- 禁止重复、未知、缺失 member；禁止 BOM、浮点数、负数、指数、`null`、array、嵌套 object；
- integer 使用最短十进制表示；所有 v1 string 限制为 ASCII，禁止 JSON escape；
- parser 必须在反序列化为 map/struct 前侦测 duplicate member，并将原始 bytes 与按本 profile
  重编码的 bytes 做 constant-content equality；不接受“语义等价”JSON。

该窄 profile 刻意不宣称支持任意 RFC 7515/7519 token，也不要求引入通用 JWT 框架。

## 3. Protected header

exact member order 和约束如下：

| 顺序 | member | JSON 类型 | exact constraint |
|---:|---|---|---|
| 1 | `alg` | string | `EdDSA` |
| 2 | `kid` | string | 64 lowercase hex；SHA-256(raw 32-byte Ed25519 public key) |
| 3 | `typ` | string | `cats-route-grant+jwt` |
| 4 | `v` | integer | `1` |

canonical 示例：

```json
{"alg":"EdDSA","kid":"21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9","typ":"cats-route-grant+jwt","v":1}
```

`alg=none`、其他 EdDSA curve、embedded JWK、`crit`、`b64=false` 和未知 `kid` 均 fail closed。

## 4. Claims

exact member order 和 owner 如下。资源 id 必须是 1–128 bytes ASCII，匹配
`[A-Za-z0-9][A-Za-z0-9_-]{0,127}`；这包含当前 opaque id 形态，但不把 display name 放入授权。

| 顺序 | member | 类型 | owner / constraint |
|---:|---|---|---|
| 1 | `aud` | string | exact `cats-node-agent` |
| 2 | `cat_generation` | integer | A；`1..=2^63-1` |
| 3 | `cat_id` | string | A/C；opaque resource id |
| 4 | `endpoint_id` | string | B；opaque resource id |
| 5 | `exp` | integer | Unix seconds；`iat < exp <= iat + 120` |
| 6 | `grant_id` | string | B issuer；每次签发新的 opaque id |
| 7 | `hostname` | string | B；§5 canonical hostname |
| 8 | `iat` | integer | PostgreSQL snapshot 的 Unix seconds |
| 9 | `iss` | string | exact `cats-control-plane` |
| 10 | `nbf` | integer | 必须等于 `iat` |
| 11 | `node_id` | string | C/G；目标 Node identity |
| 12 | `protocol` | string | v1 exact `http`；WebSocket 是 HTTP Upgrade |
| 13 | `route_epoch` | integer | B；`1..=2^63-1`，每次 authority 变化严格递增 |
| 14 | `target_port` | integer | B/C；`1..=65535` |
| 15 | `workspace_id` | string | ADR-0018 resource owner；opaque resource id |

canonical claims 示例和完整 token 见 `positive.json`。v1 不包含 Guest IP、Node URL、用户 headers、
Cookie、wake policy 或任意通配 scope。Node URL 是 Gateway 的传输 hint，不是授权 claim；Guest
IP/socket 从 Node local runtime truth 派生。

## 5. Hostname normalization

所有创建、数据库唯一键、resolve、cache key、claim 与 Node local truth 共用一个函数，顺序固定：

1. 输入是 HTTP authority 的原始 bytes，1–253 bytes；拒绝非 ASCII、NUL/control、空白、`/`、
   `\\`、`@`、`%`、`#`、`?`、IPv4/IPv6 literal 和 bracket authority；
2. 允许非 bracket DNS authority 携带一个 `:<decimal-port>` transport suffix；port 必须
   `1..=65535`，只剥离该 suffix，不把它签入 hostname；多个冒号拒绝；
3. ASCII `A-Z` 转小写；不做 Unicode normalization、IDNA 转换或 DNS lookup；上游若支持国际
   域名，必须在创建 Route 前先产生并存储唯一 ASCII A-label；
4. 拒绝 leading/trailing dot、空 label、label 长度大于 63；每个 label 只允许
   `[a-z0-9]` 或内部 `-`，不得以 `-` 开头/结尾；总 canonical hostname 不超过 253 bytes；
5. TLS 场景中，canonical SNI 与 canonical HTTP authority 必须相等；不等即在 resolve 前拒绝。

不接受 trailing-dot alias，避免 cache/证书/Route 表对同一名字产生两个 authority。固定语料见
`hostname.json`，所有组件必须得到相同结果。

## 6. Issuer：一个原子 snapshot

唯一发行 API 从同一个 PostgreSQL transaction 取得不可变
`RouteAuthorizationSnapshotV1`。issuer 和所有 route mutation 的 row-lock 顺序为：

```text
Cat row
  -> current LifecycleCommand (if present) + exact cat_runtime_state
    -> Endpoint rows by stable endpoint_id
      -> Route rows by canonical hostname
```

snapshot 必须同时证明 active Route、Workspace/Cat/Endpoint 外键闭合、assignment 与 route
target Node 相同，以及 claim 的 hostname/protocol/port/generation/epoch 全部相同。Running
authority 只来自 A0 exact reducer 已结算的 `cat_runtime_state`：它必须是 `running`，携带与当前
intent generation 相同的 command/dispatch/Node claim/terminal result/runtime identity provenance，
没有能 invalidate 它的 current nonterminal command，并且 route publication intent/materialized
Route 引用同一 settled provenance。

V2 issuer 禁止读取 `cats.observed_state` 或 heartbeat observation 作为授权；前者只是迁移期 API
projection，后者只是 observation。pre-activation V1 只能留在 legacy cohort，不能 mint v1
grant。`iat` 取 transaction 的整秒数据库时间；编码/签名不得再次读取或补写某个 claim。签名
结束时若 `now >= exp`，丢弃结果。

Control Plane 给 Gateway 的 V2 接口冻结为：

```http
GET /v2/internal/route-grants/resolve?hostname=<percent-encoded-canonical-hostname>
Authorization: Bearer <gateway-service-credential>

200 OK
Content-Type: application/json
Cache-Control: no-store

{"node_proxy_url":"https://node.internal.example","route_grant":"<compact>"}
```

JSON response 只允许这两个 member。`node_proxy_url` 是不可信 transport hint：Gateway 可以用它
选择 hop，Node 必须用自身 identity 与 grant/local truth 裁决。Gateway 必须确认 token 中的
canonical hostname 等于 lookup key，响应才可进入 cache。

| HTTP status | machine class | Gateway 行为 |
|---:|---|---|
| 200 | `ok` | strict parse；成功才原子替换 cache entry |
| 404 | `route_not_found` | 5 秒 negative cache；删除同 key 旧 grant |
| 410 | `route_gone` | 5 秒 negative cache；删除同 key 旧 grant |
| 401/403 | `gateway_auth_failed` | 全局身份失败；停止 resolve，报警，不做 per-key 重试 |
| 409 | `route_not_running` | 不缓存；若产品入口允许则走显式 wake，不降级 unsigned |
| 429 | `issuer_overloaded` | 使用 `Retry-After`，进入共享 outage backoff |
| 5xx/transport | `issuer_unavailable` | 保留仍有效旧 grant，进入共享 outage backoff |

任何 error body 仅是诊断，不参与状态机。cache miss/expired 时这些失败对外是有界 503。

## 7. Gateway cache/outage 状态机

Gateway 可以 strict parse header/claims 来建立 cache key 和时间边界，但不因此成为最终 verifier。
状态只由 canonical hostname、signed `iat/exp`、当前时间和权威结果决定：

```text
             now reaches midpoint                    now >= exp
  Fresh ------------------------------> StaleValid ----------------> Expired
    ^                                      |   |                         |
    | 200 strict-valid atomic replace      |   +-- serve + one refresh  +-- never serve
    +--------------------------------------+       per host

  404/410 -> Negative(5s)      transport/429/5xx -> shared Backoff
  401/403 -> GlobalAuthFailed  Node rejection    -> evict exact grant
```

- refresh midpoint = `iat + floor((exp - iat) / 2)`；Fresh 可直接服务；
- StaleValid 可继续服务，并且同 hostname 最多一个 refresh in flight；等待者不阻塞在 refresh；
- Expired 永不服务，即使控制面/数据库离线；
- 200 中 malformed、hostname mismatch 或生命周期超过上限的新 token 不替换旧 entry；该响应按
  `malformed_issuer_response` 报警，旧 entry 只可服务到自己的 expiry；
- 404/410 是 authority supersession，必须删旧 entry；negative cache 到期后才允许新 probe；
- transport/429/5xx backoff 在单个 Gateway replica 内跨所有 hostname 共享：非零初始 delay、
  bounded exponential backoff、full jitter、half-open 只允许一个 probe；具体容量参数属于 B3，
  但 backoff 上限不得延长任何 grant；
- cache 必须是有界内存 LRU；具体容量属于 B3/部署配置。逐出只降低可用性，不改变授权；不得
  把 compact token 持久化到磁盘；
- Node 对 exact token 返回 `route_grant_rejected` 或 `route_authority_mismatch` 时立即逐出，最多
  resolve 一张新 token 重试一次；绝不重放同一 token。

Running HTTP 不再逐请求 acquire/release 控制面 work lease；WebSocket 不续控制面 lease。
WebSocket 在 Upgrade 时用同一 grant 准入，随后只依赖 Node activity guard。普通 token expiry
不切断已有 guard；显式 route revoke、quiesce 或 transfer 必须按 §10 取消并 drain。

## 8. Gateway → Node internal wire

HTTP 与 WebSocket 使用独立的 V2 internal endpoint，但携带同一种 token：

```http
POST /v2/internal/endpoint-proxy/http
Cats-Route-Grant: <compact>
Authorization: Bearer <gateway-service-credential>
Content-Type: application/json

<ProxyHttpRequestV2 without cat_id, target_port or route_epoch>
```

```http
GET /v2/internal/endpoint-proxy/websocket?path=<percent-encoded-origin-form>
Connection: Upgrade
Upgrade: websocket
Cats-Route-Grant: <compact>
Authorization: Bearer <gateway-service-credential>
```

外部用户提供的 `Cats-Route-Grant` 与 hop-level service `Authorization` 必须在 Gateway 边界
删除，再由 Gateway 写入；原始用户 Authorization 若允许转发，只能位于有界 HTTP envelope 或
WebSocket forwarded-header encoding 中。internal credentials 与 grant 不得转发给 Guest。
WebSocket token 禁止放 query string；query 只携带原始 origin-form `path`，不得包含
`cat_id`、`target_port` 或 `route_epoch`。HTTP envelope 只承载 method、path/query、允许的用户
headers 和 body；Node 的 Guest target 只能来自已证明相等的 local authority。

Node 对签名/claim/local-truth 拒绝统一返回：

```http
401 Unauthorized
Cats-Route-Result: route_grant_rejected
Cache-Control: no-store
```

Node 不在 response 暴露 `unknown_key`、signature、expiry 或哪个 claim mismatch。若 token 已通过
密码学验证但 durable authority 已前进，允许同一对外响应下使用内部
`route_authority_mismatch` metric，Gateway 仍按 exact-token eviction 处理。runtime 正在 quiesce
或非 Running 返回 409 `runtime_not_admitting`；Node service/transport failure 返回 503。

## 9. Node verification 与原子 admission

固定执行顺序如下；任何一步失败都不能建立 Guest connection：

1. 校验 internal Gateway identity；从专用 header 读取 token，并执行 compact/size/base64 checks；
2. duplicate-aware parse header，校验 canonical bytes、`typ/v/alg/kid`，从 active verifier ring
   查 exact `kid`；
3. 对原始 signing input 做 strict Ed25519 verify；拒绝非 canonical scalar `S`；
4. duplicate-aware parse claims，校验 canonical bytes、固定值、类型、范围、hostname；
5. 校验 `nbf == iat`、`0 < exp - iat <= 120`、`now + 5 >= nbf`、`now < exp`；Node 无法
   证明时钟健康/偏差不超过 5 秒时，不执行新 admission；
6. 在无 runtime lock 状态完成以上工作后，获取 per-Cat admission lock；
7. 锁内逐字段比对 Node identity 和 durable `RuntimeRouteAuthorityV1`，证明 runtime Running；
8. 同一临界区获取 `RuntimeActivityGuard`；若 quiesce 已开始则失败；释放 lock；
9. 仅从 local authority 派生 Guest address/port，建立连接。guard 登记 exact
   `(cat_id, generation, route_epoch, runtime_identity)` 和 cancellation handle，持有到 HTTP
   response 完成、WebSocket/transport 关闭，或显式 revoke 取消它。

per-Cat admission lock 与 lifecycle quiesce、route authority install/revoke 共用。锁内不得网络
I/O、磁盘 I/O 或 `.await`。验证在锁外、最终 compare-and-guard 在锁内，既限制恶意 token 的
锁占用，又消除 Running-check 与 quiesce 的 TOCTOU。

内部稳定失败分类是：

| 分类 | 触发阶段 |
|---|---|
| `malformed_envelope` | size、segment 数、base64url、signature length |
| `unsupported_version` | `typ`/`v` 不支持 |
| `unsupported_algorithm` | `alg` 不是 exact EdDSA/Ed25519 |
| `unknown_key` | active verifier ring 无 `kid` |
| `noncanonical_encoding` | JSON member/order/escape/duplicate 或 Ed25519 S 不 canonical |
| `invalid_signature` | strict Ed25519 verify 失败 |
| `invalid_claims` | 固定值、类型、id/hostname/range 不合法 |
| `not_yet_valid` | `now + 5 < nbf` |
| `expired` | `now >= exp` |
| `lifetime_exceeded` | `exp - iat` 不在 `1..=120` |
| `authority_mismatch` | 任一 signed claim 与 local truth/Node identity 不同 |
| `runtime_unavailable` | 非 Running、quiescing、guard 获取失败 |
| `clock_unhealthy` | 时钟健康门禁失败 |

这些分类只进 bounded metric 和结构化内部日志；对 Gateway 合并为 §8 的少数结果，避免形成
远程 verifier oracle。

## 10. Durable authority、publication 与 revoke

`RuntimeRouteAuthorityV1` 至少持久化：Workspace/Endpoint/Cat、generation、hostname、Node、
epoch、protocol、port，以及 C 定义的 runtime identity。activate 顺序不可交换：

```text
allocate greater route epoch
  -> Node atomic write + file fsync + rename + directory fsync
  -> Node ACK exact identity and authority digest
  -> Control Plane commits active publication
  -> issuer may mint
```

generic ledger 的 best-effort persistence 不能作为 ACK 成功门。reachable revoke/rebind 的顺序
不可交换：

1. per-Cat admission lock 内 durable revoke/advance old local authority，阻止旧 epoch 新 guard，
   并标记其 active guards cancelled；
2. 锁外关闭 Node↔Guest HTTP/WebSocket/streaming transport 并有界 drain；不持锁等待 I/O；
3. 再次证明旧 authority active guard count 为零并持久 ACK；
4. Control Plane 才可发布 route 变化或把 authority 交给新 runtime。

drain timeout 保持 transfer blocked，除非强制停止/隔离旧 runtime 并取得外部 fence proof。旧 Node
不可达时必须先用云 API、BMC、电源或网络隔离证明它不能继续服务；唯一例外是等待至少 125 秒
后，另有独立可信的 zero-active-session 且 runtime-non-serving proof。TTL wait、heartbeat 缺报、
Gateway cache purge 都不能单独满足 transfer gate。

## 11. Verification key ring

Node ring 是版本化、持久化的 `{kid -> raw Ed25519 public key, state}` 集合，state 只允许
`staged | active | retiring`。三个 state 都是 verification-eligible：`staged` 表示 signer 尚未
切换，`active` 是当前 signer，`retiring` 表示只为旧 grant overlap 保留；只有从 ring durable
删除后才不可验证。ring update 必须签名认证、单调 version、atomic durable，ACK 带 version、
sorted-key digest 与每个 fingerprint。Gateway 没有 key ring，Control Plane private key 不离开
signer/KMS 边界。

轮换必须 verifier-first：staged verifier 覆盖全部目标 V2 Node并有证据 → signer switch → 双 key
overlap 至少从最后一次旧 key 签发后 125 秒 → retire。rollback 只能切到仍部署的 key；ring
removal 只停止新 admission。incident 若要终止已有会话还必须 epoch-aware cancel-and-drain；
无法收到 compromise revoke 的 Node 必须隔离。

## 12. V2 cohort 与旧路径删除

| 旧路径 | V2 replacement | 删除门禁 |
|---|---|---|
| unsigned `RouteBinding` authority | compact signed grant + Node local truth | B1–B3 contract tests green |
| Gateway `target_port`/`route_epoch` 字段 | signed claims；Node local-derived target | V2 Node/Gateway qualification |
| WebSocket route query fields | `Cats-Route-Grant` header | Upgrade/expiry/active-revoke evidence |
| HTTP per-request work acquire/release | epoch-aware Node activity guard | lifecycle/revoke/drain race tests |
| WebSocket control-plane renewal | connection-lifetime Node guard | long WS outage test |
| Node `cat_id + Running` admission | strict verifier + atomic compare-and-guard | negative vectors + race tests |
| single verifier/unsigned fallback | durable versioned key ring | rotation/rollback evidence |

迁移期间 legacy 与 V2 由显式 Node capability 和独立 Gateway cohort 隔离。Cat 只以 Cold move、new
generation/new epoch 进入 V2；V2 失败绝不 request-level downgrade。全部目标完成 qualification 后
删除 migration adapter，不保留永久兼容层。Multi-AZ 继续是 #179 的 deferred scope，本协议不把
短期离线窗口宣称为 Multi-AZ HA。

## 13. Observability 与敏感信息

禁止记录 compact token、signature、private key、用户 Authorization/Cookie 或完整 request body。
允许记录 grant id、resource ids、`kid` 前 12 hex、稳定失败分类、cache state、expiry bucket、ring
version/digest。panic、HTTP debug、trace propagation 和 qualification artifact 同样适用该限制。
