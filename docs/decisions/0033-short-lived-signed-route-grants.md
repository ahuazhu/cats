# ADR-0033：短期签名 Route Grant 与控制面离线数据面授权

- 状态：Accepted
- 日期：2026-08-06
- 关联：ADR-0002（生命周期四态）、ADR-0010（默认 HTTP Endpoint）、
  ADR-0018（Workspace 是唯一资源所有者）、ADR-0028（Node runtime ledger）、
  ADR-0031/0032（PostgreSQL 控制权威与多副本）、ADR-0035（A0 LifecycleCommand V2）；
  Architecture V2 #204、Epic B #206、B0 #216

## 背景

当前 Endpoint 热路径把 unsigned `RouteBinding` 缓存在 Gateway，再为每个 HTTP 请求获取、
释放控制面 work lease；WebSocket 还要周期续租。Gateway 把 `target_port` 与 `route_epoch`
作为普通请求字段传给 Node。Node 最终只证明 Cat id 在本进程内存在且为 `Running`，没有把
Workspace、Cat generation、Endpoint、hostname、target Node、route epoch 和 port 绑定为
一个不可伪造的授权决定。

这带来两个结构性问题：

1. 控制面或 PostgreSQL 短暂不可用，会直接扩大为已经 Running 的 Endpoint 中断；每个请求
   的 acquire/release 还会把一次公共故障放大成控制面请求风暴。
2. Gateway 一旦被攻陷，或缓存里存在来自迁移前的旧 binding，它可以自由改写端口/epoch，
   而 Node 没有足够的本地权威证明来拒绝跨 Workspace、旧 generation 或旧 Guest 的请求。

仅给现有 JSON 加一个签名不能解决第二个问题。签名输入如果来自互不相关的多次数据库读取，
会认证一个从未原子成立过的状态；Node 如果只验签、不与持久本地 runtime truth 比较，迁移、
重启和 route epoch 变化后仍会接受过期授权。

## 决定

### 1. Route Grant 是窄化的 capability，不是通用 JWT

控制面为一个已发布且 Running 的 Endpoint 签发短期 `Route Grant v1`。它精确绑定：

- normalized hostname、Workspace、Endpoint、Cat；
- Cat generation、target Node、route epoch；
- HTTP protocol 与 target port；
- issuer、audience、grant id、issued-at/not-before/expiry；
- wire version、Ed25519 algorithm 和 verification-key `kid`。

wire 采用一个严格、确定性的 compact JWS profile；完整字节规范、字段限制、错误码和固定
向量见 [`docs/specs/route-grant-v1.md`](../specs/route-grant-v1.md)。这不是引入泛用 JWT/JWS
框架：v1 只接受一组固定 header/claim、一个算法和一套 canonical JSON 表示。未知字段、重复
字段、未知版本/算法/key、非 canonical base64url/JSON 一律 fail closed。

### 2. 信任边界固定为 Control Plane 签发、Gateway 搬运、Node 最终裁决

| 主体 | 可以做 | 绝不能做 |
|---|---|---|
| Control Plane | 从 PostgreSQL 原子 route snapshot 签发；管理 signer | 从多次松散读取拼 claims；把 private key 下发 |
| Gateway | 按 canonical hostname 缓存、搬运完整 grant；选择网络 hop | mint、延长、重签、改写或解释出新的授权；指定 Guest IP/port |
| Node | 通过 verifier key ring 验签、比对本地 truth、原子获取 activity guard | 只凭签名放行；从 Gateway 参数覆盖 grant；离线复活 runtime authority |
| Guest | 接收已经准入的 HTTP/WebSocket 字节 | 看到 grant、signing key、Node/控制面凭据 |

Gateway 被视为可能失陷的 courier。持有一个未过期 grant 的 Gateway 能在该 grant 的精确边界
内发请求，这是 capability 的固有限制；它不能扩大到另一个 Workspace/Cat/Node/epoch/port，
也不能延长 expiry。Node 身份与内部传输认证仍独立存在，Route Grant 不替代 mTLS/service
identity。

### 3. 所有 claims 必须来自一个 PostgreSQL 原子快照

B1 的唯一发行入口读取一个 `RouteAuthorizationSnapshot`。V2 issuer 只消费 A0 reducer 已结算
的 relational runtime authority。所有会改变 route/generation 的事务与 issuer 使用同一锁族
顺序：

1. Cat row；
2. current LifecycleCommand（若有）和 exact `cat_runtime_state`；
3. Endpoint row（稳定 endpoint id 顺序）；
4. Route row（canonical hostname 顺序）。

同一事务必须证明：

- Endpoint、Route 和 Cat 的 Workspace/Cat 外键闭合；
- `cat_runtime_state` 是 exact reducer 已结算的 `running`，并携带与当前 Cat intent generation
  一致的 command/dispatch/Node claim/terminal result/runtime identity provenance；
- 没有能 invalidate 该 Running authority 的 current nonterminal LifecycleCommand，route
  publication intent 与 materialized active Route 均引用上述 exact settled provenance；
- Cat assignment、Route target Node 和要签发的 `node_id` 完全一致；
- Route `state = active`，endpoint id/hostname/protocol/port 与 route 一致；
- Cat generation 与 route epoch 均为正数。

`cats.observed_state` 在 V2 中只是迁移期 API compatibility projection，heartbeat 只写 normalized
observation；二者都不得参与 V2 issuer 判断。pre-activation V1 若仍按 `observed_state` 工作，也
只能留在隔离的 legacy cohort，不能 mint Route Grant v1 或发布 V2 Route。

`iat` 取该事务的整秒时间，`exp` 由它计算；事务结果复制为不可变 snapshot 后才允许编码和
签名。签名完成时若 snapshot 已到期则丢弃，不得延长。签名期间 route 可能继续前进，这只会
产生一张被 Node 新本地 epoch 拒绝的旧 grant，不能扩大权限。

所有 route mutation 也必须走 Cat-first 锁，不允许保留绕过该边界的直接 `UPDATE routes`。
A #205 拥有 Cat generation 的递增语义；B 不自行递增或推断 generation。B 拥有 endpoint
route epoch，任何 bind、unbind、target port、target Node、generation 或 runtime publication
变化都必须产生更大的 epoch。

### 4. Node 的持久本地 truth 是签名之外的第二道门

控制面只有在目标 Node 已 durable 安装相同的 `RuntimeRouteAuthority v1` 并返回带完整 identity
的 ACK 后，才能把 route 发布为 `active` 并签发 grant。该本地记录至少包含 grant 中所有
资源绑定字段以及本地 runtime identity。写入必须经过 C #207 的 atomic write + fsync +
rename + directory fsync 成功门禁；当前 generic runtime ledger 的 best-effort “记日志后继续”
语义不能用于 route authority。

每次 Node admission 固定为：

1. 在持有任何 runtime lock 前完成有界 envelope/JSON/签名/时间解析；
2. 获取与 lifecycle、route-authority update 共用的 per-Cat admission lock；
3. 在锁内证明本 Node id、Workspace、Endpoint、hostname、Cat、generation、route epoch、
   protocol、port 与 durable local truth 逐字节一致，并证明 runtime 仍为 `Running`；
4. 在同一临界区获取 `RuntimeActivityGuard`；quiesce 已开始则拒绝；
5. 释放锁，目标 Guest IP/socket/port 只从已证明的本地 runtime authority 派生，再建立连接。

这消除“检查 Running 后、获取 guard 前开始 Suspend”的 TOCTOU。锁内不做网络或异步 I/O，
不得持有 mutex guard 跨 `.await`。HTTP request 和 WebSocket 都只在建立时准入；expiry 是新
admission 的硬边界。普通时间流逝不会强制中断已经持有 guard 的请求/连接，但显式 epoch
revoke、lifecycle quiesce 或 authority transfer 必须按下一节取消并 drain 它们。

### 5. Route publication、revoke 和迁移有明确顺序

正常 activate 顺序是：创建更大 route epoch → Node durable install/ACK → 控制面发布 active
route → issuer 可见。每个 activity guard 必须登记 exact
`(cat_id, generation, route_epoch, runtime_identity)` 和 cancellation handle。

reachable unbind/rebind/revoke 的顺序是：在 per-Cat admission lock 内 durable advance/revoke
旧 local authority 并阻止旧 epoch 新 guard → 标记该 authority 的 active guards cancelled →
锁外关闭 Node↔Guest HTTP/WebSocket/streaming transport 并有界 drain → 重新证明旧 authority
active guard count 为零 → 持久 ACK → 控制面才可发布变化或把 authority 交给新 runtime。
drain 超时不是成功；必须保持 transfer blocked，或强制停止/隔离旧 runtime 后取得 fence proof。

若旧 Node 不可达，控制面不能假装已立即撤销离线 capability。必须选择其一：

- 通过云 API、BMC、电源或网络隔离等外部 fence proof，证明旧 Node/runtime 不可能继续服务；或
- 在等待最后 grant 的 `MAX_LIFETIME + MAX_CLOCK_SKEW` 之外，再取得独立可信的“旧 authority
  active session 为零且 runtime 已不可服务”证明。

单纯等待 125 秒只耗尽**新 admission**，不能结束一条已经建立、可能恶意或卡死且仍持有 guard
的 WebSocket/streaming HTTP；它绝不是 authority transfer proof。heartbeat 缺报、Gateway cache
purge 或控制面计时器也都不能证明旧数据面静默。需要 revoke/transfer 时必须完成 reachable
cancel-and-drain 或外部 fence；否则保持 blocked。

### 6. 时间窗口有界，时钟不健康时停止新准入

v1 默认签发 60 秒，最大寿命 120 秒；`nbf == iat`。允许 Node 相对 issuer 最多 5 秒的
not-before 偏差，但 expiry 没有额外宽限：`now >= exp` 的新 admission 必须失败。

部署必须持续校准 Node 时钟。Node 无法证明 wall clock 可用或偏差不超过 5 秒时，停止新的
Route Grant admission 并暴露 condition；已有连接不因时钟异常自动切断。以真实时间计，旧
grant 的最坏**新准入/replay**窗口不超过 125 秒。active-session revoke latency 由 §5 的
cancel-and-drain/fence 决定，不由 TTL 保证。更长 TTL 会改善长控制面故障的 cache hit，却同比
扩大新准入 replay 和 key compromise 窗口；v1 选择短窗口并把长故障后的新连接明确降级为 503。

### 7. Gateway 使用一个有界 cache/outage 状态机

cache key 只能是严格规范化 hostname。未到 refresh boundary 的 entry 为 Fresh；进入后但
尚未 expiry 为 StaleValid，可以继续服务并触发每 host singleflight refresh；Expired 永不
服务。权威 404/410 建立短 negative cache；401/403 使 Gateway 的控制面身份进入失败状态。

transport timeout/refused 与 5xx 进入共享 outage backoff，不能由每个 hostname/request 各自
重试。失败或 malformed 的新响应绝不覆盖一张仍可验证、未过期的现有 grant，但也绝不被当成
授权；旧 grant 到期后 fail closed。Node 对某 grant 返回 invalid/authority mismatch 后，
Gateway 必须逐出该 grant，不得用同一 token 重试。

控制面离线只保证已经 Running 且 Gateway 持有未过期 grant 的新 HTTP/WebSocket admission。
cache miss、expired grant、Cold/Suspended/Warm wake、route rebind 和新 Endpoint 仍需要控制面，
失败返回有界 503。已建立 WebSocket 持有 Node guard，不依赖控制面 lease renewal。

### 8. Ed25519 key ring 使用 verifier-first 轮换

v1 只允许 Ed25519。`kid` 是 32-byte raw Ed25519 public key 的 SHA-256 lowercase hex。
Control Plane 只持 signer reference/private material；Gateway 不持任何 signing material；
Node 只持有版本化 verifier key ring。

轮换顺序不可交换：

1. 生成新 signer，先把新 public verifier 作为 staged key 发布到所有目标 V2 Node；
2. G/H 通过 Node capability、key-ring version/digest 与 fingerprint evidence 证明覆盖；
3. Control Plane 切 signer，旧、新 public key 同时可验证；
4. 从最后一次旧 key 签发起等待至少 125 秒，并证明没有旧 grant admission；
5. 再 retire/remove 旧 verifier。

rollback 只能切回仍在所有目标 Node ring 中的 signer。key compromise 时停止签发并分发 revoke
ring；ring removal 只阻止新 admission，不会终止 active guard。incident 若要求撤销已有会话，
还必须执行 epoch-aware cancel-and-drain；无法收到新 ring/revoke 的 Node 必须隔离，不能声明
已立即撤销。

### 9. mixed-version 只存在于隔离的 V2 cohort migration boundary

V2 Node 从首次 admission 起只接受 Route Grant v1，不支持 unsigned fallback。Legacy Node
继续由隔离的 legacy Gateway/cohort 服务；路由选择通过显式 Node capability 完成，而不是在
领域代码里散落 `v1/v2` 分支。Cat 以 Cold activation 和新 generation/route epoch 迁入 V2。

任何进入 V2 cohort 的 Endpoint 不得因签名、key、控制面故障静默 downgrade。回滚需要显式
drain/Cold move 回 legacy cohort。完成条件是全部 Cat/Endpoint 离开 legacy cohort、完整
qualification 通过，随后删除 migration adapter 与所有旧路径。

必须删除的旧路径包括：

- unsigned RouteBinding 作为 Node authority；
- Gateway 可传的 `target_port`/`route_epoch` proxy 字段或 WebSocket query；
- Running HTTP 每请求控制面 work acquire/release；
- WebSocket 控制面 lease renewal；
- Node 仅按 `cat_id + Running` 放行；
- 单 verification key 与签名失败后的 unsigned fallback。

## 威胁模型与处置

| 威胁 | v1 防线 | 剩余边界 |
|---|---|---|
| Gateway 被攻陷 | 不能签发/改写；Node 校验全部 claims 与 local truth | 所持 grant 可在最多 125 秒内发起新 admission；已建连接需显式 revoke/drain |
| token replay | short TTL；Node generation/epoch/runtime match | 同一有效 grant 内不做 per-request nonce DB；这是刻意的离线权衡 |
| stale route / Node migration | route epoch、node id、generation；旧 Node cancel-and-drain 或外部 fence | TTL wait 单独不能证明 active stream 静默；客户端在旧连接被关闭后重连 |
| 跨 Workspace/Cat/port | signed Workspace/Endpoint/Cat/port；Node exact match | 无通配 grant |
| hostname ambiguity | 唯一 canonical ASCII hostname；严格 authority parser | V1 不接受 Unicode/IP/trailing-dot 等别名 |
| algorithm confusion | exact `alg=EdDSA`、`typ`、version、kid；unknown header fails | 不支持算法协商 |
| malformed/duplicate claims | size/depth/type/duplicate/unknown/canonical checks先于使用 | parser 错误对 Gateway 统一，不暴露 verifier oracle |
| signature malleability | 64-byte Ed25519 strict verify，拒绝 non-canonical S | 依赖 B0 向量校准所选 crypto backend |
| clock skew/rollback | 5 秒上限、hard expiry、clock-unhealthy condition | 时钟健康证据属于 G/B4 qualification |
| signing-key compromise | key ring revoke、Node local truth、短 TTL、active-guard revoke、隔离失联 Node | 攻击者仍可在本地 truth 范围内 mint，需 incident rotation/fencing |
| 控制面/DB outage | 未过期 cache 可继续；shared backoff | cache miss/expiry/wake 明确不可用；不承诺无限离线 |

grant、完整 compact token、signature、private key、用户 header 和 Cookie 不进入日志、metrics、
trace 或 qualification artifact。允许记录 `grant_id`、`kid` 前 12 hex、资源 ids、结果分类与
expiry bucket，但不得记录可重放 token。

## 所有权和依赖边界

| 边界 | Owner | B 的依赖/承诺 |
|---|---|---|
| Cat generation 与 lifecycle supersession | A #205 | 只读取并精确绑定，不自行递增 |
| Atomic route snapshot、epoch、issuer | B1 #217 | 实现本文 Cat-first 事务与 signer |
| Durable Node runtime/route truth、admission lock | C #207 + B2 #218 | C 提供 durability/identity container；B 拥有 route 字段和比对语义 |
| Gateway cache/outage/HTTP/WS | B3 #219 | 一个状态机，不叠加零散 fallback |
| Key delivery、Node capability/admission | G #211 + B4 #220 | verifier-first、digest/fingerprint evidence |
| Cohort migration、legacy deletion、release | H #212 + B5 #221 | 不保留永久双路径 |
| Fault actor 与 authoritative evidence | F #210 + B6 #222 | 真停控制面/DB、rotation/skew/tamper qualification |

Multi-AZ 不由本 ADR 实现。RDS Multi-AZ、per-AZ NAT 与跨 AZ 数据面仍是 #179 的 accepted/
deferred risk；本协议保留多副本/多 Node 能力，但不得把短期离线 grant 宣称为 Multi-AZ HA。

## 后果

Running Endpoint 的新请求在未过期授权窗口内不再逐请求依赖控制面或数据库，Gateway 故障
重试被限制在 per-host singleflight 与 fleet-shared backoff。Node 获得一个可审计、可独立
验证、与 runtime truth 闭合的最终准入边界。

代价是新 admission 的离线 availability 与 replay window 由同一个 TTL 决定，而已建立 stream
有独立的撤销协议。Node 必须有可信时钟、durable route authority、epoch-aware active-guard
registry 与版本化 key ring；部署和 cancel/drain/fence 顺序都成为安全协议的一部分。

## 被拒绝的替代方案

- **继续逐请求 work lease：**保留控制面热路径和故障放大，不解决 Gateway 可改字段。
- **签名现有 RouteBinding：**缺少 atomic snapshot、Endpoint/generation/local truth 与明确
  parser/time/key contract。
- **Gateway 验签后 Node 信任 Gateway：**Gateway 正是被约束的主体，不能成为最终 authority。
- **长寿命或可续期离线 token：**扩大 replay/revoke/key compromise 窗口，并把 Gateway 变成
  隐式授权服务器。
- **Node 离线向控制面回查：**重新引入要消除的故障依赖。
- **永久 legacy fallback：**签名失败时会降级为旧不安全路径，违反 Architecture V2 删除条件。

## 验收

- B0 固定向量必须被 issuer、Gateway parser 和 Node verifier 的实现共同消费，且由独立实现
  验证签名和 canonical bytes。
- wrong host/Workspace/Endpoint/Cat/generation/Node/epoch/protocol/port、expiry/skew、unknown
  version/alg/kid/claim、duplicate claim、malformed base64/JSON、tamper 与 non-canonical Ed25519
  signature 全部 deterministic fail closed。
- 真正停止 control plane 与数据库时，缓存窗口内 Running HTTP 和新 WebSocket 可建立；到期
  后新 admission 失败，已有 WebSocket 保持。
- reachable route revoke 必须取消旧 epoch active WebSocket/streaming HTTP、drain guard 至零后
  才允许新 authority；drain 超时保持 blocked。
- unreachable Node 即使经过 125 秒，只要没有外部 fence 或独立的 zero-session + non-serving
  proof，authority transfer 仍必须失败；取得 fence proof 后才能继续。
- migration、key rotation、clock skew、Agent replacement、Suspend race 和 route rebind 必须
  在 V2 cohort 两条 block path 上留下 authoritative evidence。
