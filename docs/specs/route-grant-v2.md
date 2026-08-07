# Route Grant V2 wire protocol（冻结）

- 状态：Frozen v2（2026-08-07）；B0 只冻结契约，生产实现由 B1–B5 完成
- 决策依据：[ADR-0039](../decisions/0039-architecture-v2-route-grant-contract.md)
- 共同测试输入：[固定向量](route-grant-v2-vectors/README.md)

改变 compact bytes、字段、验签/时间语义、Node admission、cache 状态或 key 轮换顺序，必须先
更新 ADR 并升 wire version。v2 是终态唯一协议；不得为了兼容 ADR-0033 或旧 unsigned route，
增加第二套 parser、issuer、Node admission、cohort 或请求级 fallback。

## 1. 常量

| 名称 | 值 | 说明 |
|---|---:|---|
| `WIRE_VERSION` | `2` | protected header 的整数 `v`；任何其他版本必须拒绝 |
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

Header 与 claims 都是 UTF-8 JSON object，但 v2 只允许下表列出的 member：

- member 必须按本文表格给出的顺序出现；无 member 前后空白、冒号/逗号旁无空白；
- 禁止重复、未知、缺失 member；禁止 BOM、浮点数、负数、指数、`null`、array、嵌套 object；
- integer 使用最短十进制表示；所有 v2 string 限制为 ASCII，禁止 JSON escape；
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
| 4 | `v` | integer | `2` |

canonical 示例：

```json
{"alg":"EdDSA","kid":"21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9","typ":"cats-route-grant+jwt","v":2}
```

`alg=none`、其他 EdDSA curve、embedded JWK、`crit`、`b64=false` 和未知 `kid` 均 fail closed。

## 4. Claims

exact member order 和 owner 如下。资源 id 必须是 1–128 bytes ASCII，匹配
`[A-Za-z0-9][A-Za-z0-9_-]{0,127}`；这包含当前 opaque id 形态，但不把 display name 放入授权。

| 顺序 | member | 类型 | owner / constraint |
|---:|---|---|---|
| 1 | `aud` | string | exact `cats-node-agent` |
| 2 | `cat_generation` | integer | wire 名称；exact A0 `intent_generation`；`1..=2^63-1` |
| 3 | `cat_id` | string | A/C；opaque resource id |
| 4 | `endpoint_id` | string | B；opaque resource id |
| 5 | `exp` | integer | Unix seconds；`iat < exp <= iat + 120` |
| 6 | `grant_id` | string | B issuer；每次签发新的 opaque id |
| 7 | `hostname` | string | B；§5 canonical hostname |
| 8 | `iat` | integer | PostgreSQL snapshot 的 Unix seconds |
| 9 | `iss` | string | exact `cats-control-plane` |
| 10 | `nbf` | integer | 必须等于 `iat` |
| 11 | `node_id` | string | C/G；目标 Node identity |
| 12 | `protocol` | string | v2 exact `http`；WebSocket 是 HTTP Upgrade |
| 13 | `route_epoch` | integer | B；`1..=2^63-1`，每次 authority 变化严格递增 |
| 14 | `target_port` | integer | B/C；`1..=65535` |
| 15 | `workspace_id` | string | ADR-0018 resource owner；opaque resource id |

canonical claims 示例和完整 token 见 `positive.json`。v2 不包含 Guest IP、Node URL、用户 headers、
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
`RouteAuthorizationSnapshotV1`。`cat_generation` 只是 A0 `intent_generation` 的 wire 名称；禁止
把 C 的 `runtime_generation`、旧 `cats.generation` projection 或 B 自己的 counter 放入该 claim。
issuer 和所有 route mutation 的 row-lock 顺序为：

```text
Cat row
  -> current LifecycleCommand (if present) + exact cat_runtime_state
    -> Endpoint rows by stable endpoint_id
      -> Route rows by canonical hostname
```

snapshot 必须同时证明 active Route、Workspace/Cat/Endpoint 外键闭合、assignment 与 route
target Node 相同，以及 claim 的 hostname/protocol/port/generation/epoch 全部相同。其最小权威
shape 是：

```text
SettledLifecycleLineageV1 {
  command_id + command_seq
  dispatch_id + dispatch_seq + request_body_sha256
  target_node_id
  node_claim_id
  result_id
  runtime_identity {
    runtime_id + runtime_generation
    host_boot_id? + guest_boot_id?
  }
}

RouteAuthorizationSnapshotV1 {
  Cat { intent_generation, assignment_node_id }
  current_lifecycle_command = null
  policy_transition_proposal?             # nonauthority; does not alter snapshot before receipt
  cat_runtime_state {
    state = running, intent_generation, settled_lineage: SettledLifecycleLineageV1
  }
  reducer_route_intent {
    route_intent_id, action = publish, intent_generation,
    settled_lineage: SettledLifecycleLineageV1
  }
  materialized_route {
    route_intent_id, route_epoch,
    workspace_id, endpoint_id, cat_id, hostname, protocol, target_port, target_node_id,
    admission_state = active, retirement_receipt_id = null,
    intent_generation, settled_lineage: SettledLifecycleLineageV1
  }
  runtime_route_authority_ack {
    install_id, route_intent_id, route_epoch,
    workspace_id, endpoint_id, cat_id, hostname, protocol, target_port, node_id,
    admission_state = active, intent_generation,
    settled_lineage: SettledLifecycleLineageV1
  }
}
```

Running authority 只来自 A0 exact reducer 已结算的 `cat_runtime_state`。下列等式必须全部成立：

```text
Cat.intent_generation
  == cat_runtime_state.intent_generation
  == reducer_route_intent.intent_generation
  == materialized_route.intent_generation
  == runtime_route_authority_ack.intent_generation
  == RuntimeRouteAuthorityV1.intent_generation
  == grant.cat_generation
```

`command_id + command_seq`、`dispatch_id + dispatch_seq + request_body_sha256`、`target_node_id`、
`node_claim_id`、`result_id` 和完整 runtime identity 也必须在四个 snapshot lineage 层及 durable local authority
逐字段相同；route intent、materialized Route 与 ACK 必须引用同一个 `route_intent_id`。存在任何
`authority=current` 的 nonterminal
LifecycleCommand 就拒签，不区分 action 是否“看起来”会改变 Running：全部
`start|resume|restore|suspend|warm|cold|destroy|fallback_cold` 和全部
`planned|preparing|dispatchable|dispatched|accepted|settling|blocked` 都在拒签矩阵内。terminal 或
superseded command 只能作为 lineage 历史存在，不能成为 `current`。

ACK 的 Workspace/Endpoint/Cat/hostname/protocol/port/Node/epoch 必须分别等于 materialized Route、
Cat assignment 与待签 claims；`install_id` 必须是该 exact route epoch 唯一成功 install。任一资源
binding、intent、epoch 或 lineage 只在一层不同，都拒签，不能以“ACK 较新”或 `<= generation`
接受。

`PolicyTransitionProposal` 是 auto policy 在 promotion 前的非权威候选：它不改变 Cat
`intent_generation`，不是 current LifecycleCommand，也不使一个仍 active 的 Route snapshot 拒签。
一旦 Node 的 successful `require_idle` receipt 被控制面 ingestion，receipt、Route admission
关闭与 A0 promotion 必须在同一个 Cat-first transaction 可见；之后 issuer 必须因 route 非 active、
generation/lineage 不闭合或 current command 至少一项而拒签。Node local revoke 到 receipt ingestion
之间即使 issuer 尚不可见，Node 也已经 fail closed 拒绝旧 token；recovery 必须收敛该短暂可用性缺口。

V2 issuer 禁止读取 `cats.observed_state` 或 heartbeat observation 作为授权；前者只是 API
projection，后者只是 observation。ADR-0033 的 signer/admission 路径必须在启用 V2 前删除，不能
与 V2 共存。`iat` 取 transaction 的整秒数据库时间；编码/签名不得再次读取或补写某个 claim。签名
结束时若 `now >= exp`，丢弃结果。

Route Controller discovery 不得用持锁的 route-intent claim 跨进 apply transaction。apply 必须从
fresh snapshot 按 Cat → current intent/command + runtime → Endpoint(sorted) → Route(sorted) →
route intent 的顺序获取锁；任何 serialization/deadlock/CAS failure 都回滚并从 fresh snapshot 重试
整个事务，绝不只重试最后一次 route write。

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
7. 锁内逐字段比对 Node identity 和 durable `RuntimeRouteAuthorityV1`，并证明其完整 settled
   lineage 与 C runtime ledger 当前 lineage 逐字段相同、runtime Running；
8. 同一临界区获取 `RuntimeActivityGuard`；若 quiesce 已开始则失败；释放 lock；
9. 仅从 local authority 派生 Guest address/port，建立连接。guard 登记 exact
   `(cat_id, intent_generation, route_epoch, runtime_identity)` 和 cancellation handle，持有到 HTTP
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
| `runtime_unavailable` | 非 Running、local authority `retiring|revoked`、quiescing、guard 获取失败 |
| `clock_unhealthy` | 时钟健康门禁失败 |

这些分类只进 bounded metric 和结构化内部日志；对 Gateway 合并为 §8 的少数结果，避免形成
远程 verifier oracle。

## 10. Durable authority、publication 与 revoke

`RuntimeRouteAuthorityV1` 至少持久化：Workspace/Endpoint/Cat、`intent_generation`、hostname、
Node、epoch、protocol、port、`route_intent_id`、`install_id`、完整
`SettledLifecycleLineageV1` 与 C 定义的 runtime identity。相应 ACK 必须逐字段回显全部
identity/lineage，不能只回显 epoch 或一个没有冻结 canonical bytes 的 digest。activate 顺序不可交换：

```text
consume exact A0 reducer publish intent
  -> prove old grant/writer retirement and required durability receipts
  -> allocate greater route epoch and exact expected predecessor
  -> Node lineage/install CAS + file fsync + rename + directory fsync
  -> Node ACK exact identity and lineage
  -> Control Plane conditional commit of active publication
  -> issuer may mint
```

install request 必须包含新 authority exact fields 和 expected predecessor
`absent | {route_epoch, install_id, route_intent_id, SettledLifecycleLineageV1}`。Node 的 CAS 结果冻结为：

- 相同 `install_id` + 相同 bytes：idempotent replay，同一 ACK；
- old epoch、expected predecessor mismatch：`stale_install`，不写入；
- 同 epoch 或同 `install_id` 但 lineage 不同：`install_conflict`，不写入并报警；
- lineage 与 C runtime ledger 不同：`runtime_lineage_mismatch`，不写入；
- restart 后 durable authority/ledger mismatch：停止 admission 并上报 condition，不从 Cat id、
  generation 或 epoch 猜测恢复。

generic ledger 的 best-effort persistence 不能作为 ACK 成功门。reachable revoke/rebind 使用同一个
per-Cat admission serialization protocol，顺序不可交换：

```text
RetirementModeV1 = cancel_and_drain | require_idle
```

mode 映射是规范的一部分：manual Stop/Suspend、Node drain、Destroy、operator fence 和 route
unbind/rebind 使用 `cancel_and_drain`；auto-suspend policy 只能使用 `require_idle`。不得把 auto
policy 当成 generic revoke 来取消用户 work，也不得让人工/Drain/Destroy 误用 `require_idle` 后
无限等待用户连接。

1. Node 先 durable 接受 exact retirement work（route retirement job、A0 NodeJob 或 auto-policy
   idle-probe job）；该 work 使 crash recovery 在任何 admission 之前恢复 retirement；
2. per-Cat lock 内读取 exact authority/guard-registry revision：
   - `require_idle` 且 active guard count 非零：不改变 authority/registry，释放 lock 后持久化 exact
     busy proof 并结束本次 proposal；
   - `require_idle` 且 count 为零，或 `cancel_and_drain`：以 exact authority revision 从
     `active -> retiring`，阻止旧 epoch 新 guard 并记录 retirement id/revision；释放 lock；
3. 锁外通过 dedicated blocking/durable worker 以该 revision CAS 持久 authority revoke；不得持有
   mutex guard 跨 `.await`，也不得在 async executor 上直接 fsync；
4. 再次获取同一 per-Cat lock，证明 retirement id/revision 未变，转为 `revoked` 并标记该 exact
   lineage 的全部 active guards cancelled（仅 `cancel_and_drain`）；`require_idle` 必须再次证明
   count 仍为零且没有 cancellation；释放 lock；
5. `cancel_and_drain` 在锁外关闭 Node↔Guest HTTP/WebSocket/streaming transport 并有界 drain；
   `require_idle` 没有需要关闭的 transport；
6. 再次证明旧 authority active guard count 为零并持久 ACK；
7. Control Plane 才可发布 route 变化或把 authority 交给新 runtime。

`retiring|revoked` 都拒绝新 guard。若进程在步骤 1–6 任一点崩溃，restart admission gate 必须先
读取 durable retirement work、authority 和 NodeJob ledger，恢复/完成同一 CAS 与 drain；在三者
闭合前不能把 authority 当 `active`。这实现“同一 per-Cat 序列化边界的 durable revoke”，但不靠
持锁磁盘 I/O。

该 ACK 的最小形态冻结为：

```text
RouteRetirementReceiptV1 {
  retirement_id
  mode = cancel_and_drain | require_idle
  scope = route_intent | lifecycle_command | policy_proposal
  retirement_token                         # random, immutable, exact receipt identity
  predecessor = active_authority(old_install_id, old_route_epoch, old_settled_lineage)
              | retired_by_policy(policy_proposal_id, retirement_token)
  outcome = retired | adopted_retired_predecessor
  reason_route_intent_id?                 # route mutation 发起时
  reason_lifecycle_intent_generation?     # lifecycle 发起时
  reason_lifecycle_command_id?
  reason_policy_proposal_id?              # require_idle promotion 前
  old_install_id + old_route_intent_id
  old_route_epoch
  old_settled_lineage: SettledLifecycleLineageV1
  guard_registry_revision
  cancelled_guard_set_digest?             # cancel_and_drain required; require_idle absent
  remaining_active_guard_count = 0
  admission_state = revoked
  durable_sequence + completed_at
}
```

scope/reason family 必须一一对应且只能有一个完整存在：`cancel_and_drain` lifecycle retirement 带新的
intent/command，route-only mutation 带 exact route intent，promotion 前的 `require_idle` 带 exact
policy proposal id。receipt 只证明该 route lineage 已停止 admission/active guards；它不证明 volume
writer 已 fence，也不证明 `R == L`。receipt scope/owner immutable，不能把 policy/route receipt 的
reason id 改成 command id 后重放。普通 retirement 的 predecessor 是 `active_authority(...)` 且
outcome=`retired`；从 policy retirement 接管的 command receipt 必须且只能是
`predecessor=retired_by_policy(P, retirement_token)`、
`outcome=adopted_retired_predecessor`，其中 token 必须逐字节等于 P 的 immutable proposal receipt。

`require_idle` 的 busy result 最少包含 proposal id、old install/route-intent/epoch、old settled lineage、
guard registry revision、`active_guard_count > 0` 和 `authority_state=active`。它证明“本次未晋升”，
不是 idle receipt；不得触发 Cat generation、Operation、LifecycleCommand、route epoch 或 local
authority 变化。policy 只能 backoff 后从 fresh snapshot 重新 proposal。

所有 source=`running` 且 target!=`running` 的 lifecycle action 都必须复用相应 mode。manual/drain/
destroy 的 A0 current intent/command 先令 issuer 拒签，再执行 `cancel_and_drain`；auto policy 在
promotion 前以非权威 proposal 执行 `require_idle`。Node 必须在 Guest quiesce、VMM pause/exit、
blockd teardown 和写入 success result 之前完成 durable receipt；`cancel_and_drain` 才允许 cancel
exact lineage 的 HTTP/WebSocket/streaming guards。drain timeout 返回 source-preserved evidence，保留 Running runtime、
blockd 和 writer，A0 command 保持 `blocked`；不得把 timeout 当 success，也不得在持锁时等待 I/O。
若 lifecycle 后续失败但 exact result 证明 Running 被保留，恢复服务必须使用新的 reducer route
intent、route epoch 和 lineage install CAS。

successful `require_idle` receipt 的 ingestion/promotion 必须在一个 Cat-first PostgreSQL transaction
内比较 proposal id、expected Cat intent generation、`current_lifecycle_command=null`、settled
lineage、Endpoint、Route epoch/install id/admission state，然后原子持久 receipt、把旧 route admission
标为 revoked/unpublished，并调用 A0 acceptance 创建新 intent/Operation/current command。任一 CAS
失败则 proposal/receipt terminal stale，绝不能 supersede 已前进 authority；恢复旧 Running 服务也
必须用 fresh reducer route intent、更大 epoch 和 install CAS，不能把旧 local record 改回 active。

proposal-scoped receipt 本身只授权该 proposal 的 promotion，不直接授权任何 lifecycle command。
A0 在同一个 Cat-first transaction 创建的 exact `PolicyRetirementPromotionV2` 将该 receipt 绑定到
auto-generated Suspend command；receipt + promotion 合在一起是该 auto command 的 dispatch
prerequisite，不需要也不得伪造第二张 command-scoped receipt。它们不授权并发 manual command。

若 Node 已有 proposal-scoped revoked authority，A0 manual command/NodeJob 必须先创建
distinct command-scoped `cancel_and_drain` route-retirement work，固定
`predecessor=retired_by_policy(P, retirement_token)`；不得把 proposal work 改 owner 或只换 reason id。
该 command retirement work 再执行 exact adoption CAS：

1. 验证 A0 V2 current command/dispatch/Node claim freshness 和 command 所需 mode；
2. 同 per-Cat lock 比较 existing revoked record、proposal receipt、old install/route epoch/完整
   settled lineage 与 `active_guard_count=0`，并证明没有更大 epoch/install；
3. 不 re-activate、不递增或复用旧 epoch，不修改原 receipt；持久化新的 command-scoped
   `RouteRetirementReceiptV1`，固定
   `predecessor=retired_by_policy(P, retirement_token)`、
   `outcome=adopted_retired_predecessor`；
4. exact replay 返回同一 adoption receipt；wrong command/lineage/epoch/scope 返回
   `retirement_adoption_mismatch` 并保持 command blocked。

只有在 receipt/promotion race 中先提交的 manual command 走该 adoption 协议。auto promotion 产生的
command 携带 exact policy receipt + `PolicyRetirementPromotionV2`；proposal receipt 如果因 manual
command 而 terminal stale，仍可作为“old physical route 已 revoke”的 immutable evidence，但不能完成
manual Operation/result。

Node 上的 receipt creation 由 per-Cat lock 串行；控制面 receipt ingestion 与 compensation apply 则在
Cat-first transaction 中锁定同一 materialized Route row，并以
`pending_policy_retirement(P, retirement_token, old_epoch, old_install, old_lineage)` 为 exact predecessor
做唯一 CAS。command adoption 将其改成 `adopted_by_command(command_id, receipt_id)`；compensation 将其
改成 `compensated_by_route(compensation_intent_id, fresh_epoch)`。loser 必须回滚整个 transaction，从
fresh Cat/Route snapshot 重试，不得只重放旧 receipt。

无 command 时的补偿 owner 冻结为：proposal 仍 eligible 则 policy controller 重试 promotion；
proposal terminal/abandoned、Cat 仍为同一个 Running settled lineage 且无 current command 时，B
Route Controller 才可创建 `RouteRetirementCompensationIntentV1`，绑定 proposal/receipt、原 A0
reducer route intent、old install/epoch 和 expected Cat/Endpoint/Route snapshot，以更大 epoch 对
同一 Running lineage 重新 install/publish。intent discovery/creation 与 apply 是 durable boundary；
因此已合法创建的 compensation intent 可能在随后 manual command acceptance 后才进入 Route-row
apply，并与 command adoption 串行。若 command adoption 先提交，compensation CAS terminal
stale；若 compensation 先提交，旧 retired predecessor 上的 adoption terminal stale，manual command
必须从新 epoch/authority 重规划并重试。较新 Cat/Route 先提交时 owner 转为 current authority。禁止
原地把旧 local authority/epoch 改回 active；crash recovery 必须从 durable
proposal/receipt/command/compensation rows 与 Route-row resolution 按此优先级选择唯一 owner。

旧 Node 不可达时有两个独立门：

1. route-admission retirement 需要外部 serving fence；或者等待至少 125 秒并另有独立可信的
   zero-active-session + runtime-non-serving proof。TTL wait、heartbeat 缺报、Gateway cache purge
   都不能单独满足；
2. new-route/writer transfer 还必须有 exact A0 reducer route intent、旧 A7 grant 的 conditional
   invalidation/release receipt 或 writer/Host fence receipt，以及 lifecycle 要求的 durability
   receipt。zero-session/non-serving proof 绝不替代 writer fence；writer unknown、旧 grant 仍
   acquired 或 retained volume `L > R` 时禁止新 publication。

一个外部 fence 只有在其 exact receipt 同时证明 runtime 不可服务和旧 writer 不可写时，才可同时
满足两个门。

Route Controller conditional apply 的 proof set 至少包含：A0 immutable `route_intent_id` 与完整
settled lineage、每个被替换 runtime 的 `RouteRetirementReceiptV1` 或 serving-fence receipt、按
`volume_id` 排序的旧 grant conditional invalidation/release receipt 或 writer-fence receipt、按
`volume_id` 排序且满足 action 要求的 durability receipt，以及新 Node exact install ACK。任一
receipt 必须引用预期 predecessor、command/dispatch/runtime/volume identity；不允许用 boolean
`fenced=true`、heartbeat absence、最新状态查询或无 identity 的“success”代替。无旧 route/writer 的
首次 publication 必须用显式 `absent` predecessor 表示，不能省略后由实现猜测。

## 11. PostgreSQL 两 session 并发门禁

以下不是 in-memory Store 测试。B1/B2 必须在真实 PostgreSQL 上用两个独立 connection/session、
显式 barrier 和已知正例行执行。每个 loser 都回滚并从 fresh authoritative snapshot 重试整个
transaction；deadlock detector 只是最后保护，不是 lock-order 设计。

| ID | Session A | Session B | 必须证明 |
|---|---|---|---|
| `PG-ISSUER-INTENT` | 按 Cat-first 锁读取可签发 snapshot | 接受新 intent/创建任意 current nonterminal command | 只存在两个串行结果：旧 grant 在 intent commit 前签出，或 issuer 看见 current command 后拒签；绝不签出“新 Cat generation + 旧 settled lineage” |
| `PG-ISSUER-REDUCER` | issuer 读取旧 settled lineage/Route | reducer 写 exact `cat_runtime_state` 与 reducer route intent | issuer 得到完整旧 snapshot 或在 route materialization 完成后得到完整新 snapshot；中间 lineage/intent/Route 混合态拒签 |
| `PG-ISSUER-REBIND` | issuer 锁 Cat → command/runtime → Endpoint → Route | Endpoint rebind/target Node/port/hostname 变化，使用相同顺序 | grant 只能精确绑定 rebind 前或后的一套值；route epoch 严格前进，不能拼接两代字段 |
| `PG-ROUTE-APPLY` | Route Controller 从无锁/已提交 work discovery 进入 fresh Cat-first apply | reducer/issuer 同时处理同一 Cat | Route Controller 从不持 route-intent row lock 反向拿 Cat；旧 intent CAS 为 terminal stale，serialization/deadlock 重试整事务且不会 route resurrection |
| `PG-POLICY-PROMOTE` | ingestion exact `require_idle` receipt 并按 Cat-first promotion | issuer 或 manual lifecycle acceptance 并发 | issuer 只见 receipt 前完整 active snapshot 或 promotion 后拒签；manual intent 若先提交则 proposal/receipt stale，policy 绝不 supersede 它 |
| `PG-POLICY-MANUAL` | manual intent/current command 在 proposal local revoke 后提交并 ingestion command adoption | policy receipt promotion 或 Route compensation 锁同一 Route row | proposal receipt 不完成 manual command；adoption 赢时写 exact `retired_by_policy(P, token)` / `adopted_retired_predecessor` 且 compensation CAS 失败；compensation 赢时 manual 从 fresh epoch/authority 重规划 |

## 12. Verification key ring

Node ring 是版本化、持久化的 `{kid -> raw Ed25519 public key, state}` 集合，state 只允许
`staged | active | retiring`。三个 state 都是 verification-eligible：`staged` 表示 signer 尚未
切换，`active` 是当前 signer，`retiring` 表示只为旧 grant overlap 保留；只有从 ring durable
删除后才不可验证。ring update 必须签名认证、单调 version、atomic durable，ACK 带 version、
sorted-key digest 与每个 fingerprint。Gateway 没有 key ring，Control Plane private key 不离开
signer/KMS 边界。

终态 `kid` 只对 raw 32-byte key 求 digest。早期实现的 SPKI fingerprint 不能充当 verifier-ring
coverage evidence；breaking cutover 必须建立新的 ring version/digest 与逐 Node ACK。

轮换必须 verifier-first：staged verifier 覆盖全部目标 V2 Node并有证据 → signer switch → 双 key
overlap 至少从最后一次旧 key 签发后 125 秒 → retire。rollback 只能切到仍部署的 key；ring
removal 只停止新 admission。incident 若要终止已有会话还必须 epoch-aware cancel-and-drain；
无法收到 compromise revoke 的 Node 必须隔离。

## 13. 破坏式终态切换与旧路径删除

| 旧路径 | V2 replacement | 删除门禁 |
|---|---|---|
| ADR-0033 Route Grant / unsigned `RouteBinding` authority | V2 compact grant + Node local truth | 恢复流量前删除；B1–B3 contract tests green |
| Gateway `target_port`/`route_epoch` 字段 | signed claims；Node local-derived target | V2 Node/Gateway qualification |
| WebSocket route query fields | `Cats-Route-Grant` header | Upgrade/expiry/active-revoke evidence |
| HTTP per-request work acquire/release | epoch-aware Node activity guard | lifecycle/revoke/drain race tests |
| WebSocket control-plane renewal | connection-lifetime Node guard | long WS outage test |
| Node `cat_id + Running` admission | strict verifier + atomic compare-and-guard | negative vectors + race tests |
| single verifier/unsigned fallback | durable versioned key ring | rotation/rollback evidence |

不实现 legacy/V2 cohort、migration adapter、双 parser/verifier、请求级 downgrade 或回滚兼容。
切换必须先停止旧 issuer 与公网 admission，对旧 runtime 完成 cancel-and-drain 或外部 fence，并
独立完成 writer/durability gate；随后轮换 trust root，丢弃旧 route-authority/cache/local-ledger
状态，整体部署终态组件并 qualification。部分更新的 fleet 保持 unready/cordoned。只有证明旧
runtime 不再服务、旧 writer 不再写入且 V1 admission 路径已删除后，才恢复流量。Multi-AZ 继续是
#179 的 deferred scope，本协议不把短期离线窗口宣称为 Multi-AZ HA。

## 14. Observability 与敏感信息

禁止记录 compact token、signature、private key、用户 Authorization/Cookie 或完整 request body。
允许记录 grant id、resource ids、`kid` 前 12 hex、稳定失败分类、cache state、expiry bucket、ring
version/digest。panic、HTTP debug、trace propagation 和 qualification artifact 同样适用该限制。
