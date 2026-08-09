# Runtime Inventory and Observation Spine v1

- 状态：Frozen target contract；尚未实现
- 上位决策：[ADR-0040](../decisions/0040-level-triggered-runtime-reconciliation.md)
- 共享类型与状态机：[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
- Node 请求认证：[Agent Registration Transport v1 §4](agent-registration-transport-v1.md#4-per-node-request-proof-adapter)
- 卷事实：[Volume Authority](volume-authority.md)
- Route 消费方：[Route Grant v2](route-grant-v2.md)

本文冻结 Control Plane 与当前 Node Agent 之间最小的 Desired delivery、完整 inventory 接受、
observation 接收、服务端 attestation 和 planner 读取合同。
[Agent Registration Transport](agent-registration-transport-v1.md)已冻结共用internal前缀、唯一
per-Node proof adapter、registration endpoint和60秒session lease policy；本文不重新定义它们，
只冻结该adapter之后两条session-bound endpoint、read-position、接受事务和freshness。
Runtime Reconciliation v1 仍是共享domain类型、digest、postcondition和Operation语义权威；本文
只对这条internal service spine给出更窄、与A19一致的实现约束。

本文不引入 heartbeat/inventory 第二套 authority。旧 `/api/v1/nodes/*/heartbeat`、legacy `nodes`
表中的 capacity/state/heartbeat overwrite、共享 fleet token 和任意 `capacity_ok`/`proof_ok` boolean
都不得被适配或双写到本合同。Desired 仍只有 current `DesiredRuntimeSpec`，物理事实仍只有当前
session 下接受的 `NodeObservation`，attestation 只是服务端对一次 accepted full inventory 的有界
receipt。

## 1. 常量与共享 wire

本合同固定使用以下常量。in-flight cap是每个Control Plane replica的进程内non-blocking
HTTP admission；renewal-critical worker/queue/connection是另一层不可借用的Store保留容量。两者都只
保护本replica资源，non-durable、non-authoritative且不进入schema。部署可以用更小的
per-replica global cap 或更短的 HTTP deadline，但不能
改变 wire/body 上限、lease、read-position 或 freshness 的语义值：

| 名称 | v1 值 |
|---|---:|
| `AGENT_SESSION_LEASE_MS` | `60000`，精确复用A19 §7常量 |
| `DESIRED_READ_TTL_MS` | `30000` |
| `PLACEMENT_INVENTORY_MAX_AGE_MS` | `60000` |
| `ROUTE_CAT_OBSERVATION_MAX_AGE_MS` | `30000` |
| 每 replica 两个 A20 route 合计 global in-flight cap | `64` |
| 每 replica、每个 authenticated Node 合计 in-flight cap | `1` |
| handler deadline | `10000` ms |
| observation renewal-critical Store worker | 每 replica `1`，不与其他Store work共享 |
| observation renewal-critical Store queue | 每 replica `1`（不含正在执行的一项） |
| observation renewal-critical PostgreSQL connection | 每 replica `1`，不得借给其他lane |
| Desired read request wire cap | `16384` bytes |
| Desired read response wire cap | `16777216` bytes |
| Observation request wire cap | `8388608` bytes |
| Observation success wire cap | `16384` bytes |
| A20 error wire cap | `20480` bytes |

所有新 DTO 使用 [Runtime §1.1](runtime-reconciliation-v1.md#11-v1-wire-基础类型)和
[§16.1](runtime-reconciliation-v1.md#161-cats-canonical-json-v1)的 exact 类型、strict decoder、
canonical encoder 与 error selection。`SessionBinding`沿用 Runtime §16.4；它不含 credential，
也不能代替 A19 authentication context。

```text
DesiredReadRequest {
  version: 1,
  session: SessionBinding,
  request_sequence: Sequence
}

DesiredReadSnapshot {
  version: 1,
  session: SessionBinding,
  request_sequence: Sequence,
  read_position: Sequence,
  issued_at_unix_ms: UnixMillis,
  expires_at_unix_ms: UnixMillis,
  desired_specs: [DesiredRuntimeSpec]
}

ObservationAcceptance {
  version: 1,
  session: SessionBinding,
  observation_id: RandomId128,
  heartbeat_sequence: Sequence,
  accepted_at_unix_ms: UnixMillis,
  lease_deadline_unix_ms: UnixMillis,
  inventory: ObservationInventoryAcceptance
}

ObservationInventoryAcceptance =
  {
    kind: "full",
    attestation: AdmissionInventoryAttestation
  }
| {
    kind: "partial",
    inventory_epoch: Epoch
  }
```

`desired_specs`按 `cat_id`严格升序且无重复，最多 1024 项；每项必须是 current full
`DesiredRuntimeSpec`，不能返回 projection。`DesiredReadSnapshot`这个封闭类型本身就表示完整集合，
因此没有 `complete`、`complete_proof` 或 `capacity_ok` boolean。`ObservationAcceptance.inventory`
使用 closed union，而不是 nullable attestation 或另一个 proof flag。

这三个新 DTO 不建立新 digest domain。Desired snapshot 保存并重放 exact typed response；full
observation 继续只使用 Runtime §16.2 的 `inventory_digest`，attestation 逐字段复制该 digest。
实现不得增加 `desired_snapshot_digest`、把 ordinary SHA-256 checksum 当 authority，或用 snapshot hash
代替完整 assigned-set 比较。

## 2. HTTP 与 authentication envelope

本规格唯一的两条session-bound route是：

```text
POST /v1/internal/runtime/desired-reads
POST /v1/internal/runtime/observations
```

path 必须逐 byte 等于上述 ASCII；query、trailing slash、percent-encoded alias 和 method override
全部拒绝。两个 endpoint 都复用
[A19 `AuthenticatedNodeCredential` adapter](agent-registration-transport-v1.md#4-per-node-request-proof-adapter)：

- `Cats-Node-Credential-Id`、`Cats-Node-Public-Key-Spki`、`Cats-Node-Signature`各恰好一个值；
- signature domain、uppercase method、exact path、`application/json`、credential ID、exact Ed25519
  SPKI DER、body length 和 exact raw body SHA-256 全部按 A19 frame 验证；
- 验证结果只能是
  `AuthenticatedNodeCredential {credential_id, CredentialBinding::PublicKey
  {public_key_spki_sha256}}`；
- `Authorization`、Cookie、shared bearer/fleet secret、mTLS subject 猜 `node_id`或 body 自报 credential
  都不接受。

A20 不重复解析 public key 或签名。adapter 成功后，service 以 `credential_id`查唯一 provisioned
`NodeIdentity`，要求 stored `credential_binding`与 authenticated binding 逐字段相同，再把 body 的完整
`SessionBinding`绑定到该 Node 当前 `AgentSession`。credential 不存在、retired、binding 不等或 body
`node_id`不等都在读取 Desired/observation receive-state 前 fail closed；前三类统一为
`identity_not_eligible`，body Node不等在authenticated Node的current session stage返回`wrong_session`，且
绝不按body Node查询。调用方不能通过 body 选择另一Node。

公共 HTTP 约束：

- `Content-Type`必须各恰好一个值且 field-value 在去掉 HTTP field-line OWS 后按ASCII大小写不敏感
  等于`application/json`；参数和逗号折叠拒绝，A19签名frame仍固定使用小写literal；
- `Content-Encoding`和`Authorization`必须不存在；不自动decompress、不把proof转换为Bearer；
- `Accept`必须不存在，或恰好一个无parameter、按ASCII大小写不敏感等于`application/json`的值；
- `Idempotency-Key`、`If-Match`、`If-None-Match`和 `X-HTTP-Method-Override`必须不存在；domain sequence
  是唯一 replay identity；
- raw body 在 JSON decode 前执行本 route byte cap；读取 `maximum + 1` 即停止并返回 Runtime
  `limit_exceeded`；不解压、不trim、不改写 body；
- 成功固定为 `200 application/json`，设置`Cache-Control: no-store`且无`Content-Encoding`；body 是对应
  DTO 的 Cats Canonical JSON bytes，无 BOM、前后whitespace 或结尾 newline。

A20 endpoint的所有非404错误共用closed envelope；它复用A19的proof verdict，但不是registration-local
`AgentRegistrationError`：

```text
RuntimeSpineError {
  version: 1,
  error: RuntimeSpineErrorDetail,
  message: string 0..=1024 UTF-8 bytes
}

RuntimeSpineErrorDetail =
  { code:"authentication_failed" }
| { code:"identity_not_eligible" }
| {
    code:"http_request_rejected",
    problem:"method_not_allowed" | "query_not_allowed"
          | "content_type_not_allowed" | "content_encoding_not_allowed"
          | "authorization_not_allowed" | "accept_not_allowed"
          | "semantic_header_not_allowed"
  }
| { code:"contract_error", contract_error: ContractError }
| { code:"node_request_in_flight" }
| { code:"temporarily_unavailable" }
| { code:"internal" }
```

error body使用Cats Canonical JSON，最大20480 bytes，固定设置`Content-Type: application/json`、
`Cache-Control: no-store`且无`Content-Encoding`。`message`只供人读；client只能按typed detail分支。
mapping固定为：

| condition | HTTP / detail |
|---|---|
| proof header/signature/SPKI任一失败 | `401 authentication_failed`，并设置 `WWW-Authenticate: CatsNodeSignature realm="runtime-internal"` |
| proof成功但credential无唯一provisioned exact-binding NodeIdentity，含retired/unsupported provider | `403 identity_not_eligible` |
| exact path但method不是POST | `405 http_request_rejected(method_not_allowed)`并设置`Allow: POST` |
| query存在（含空`?`） | `400 http_request_rejected(query_not_allowed)` |
| Content-Type / Content-Encoding / Authorization / Accept / 其他禁止的semantic header不符合上文 | 分别为`415 / 415 / 400 / 406 / 400`及同名`http_request_rejected`problem |
| F0 wire `limit_exceeded` | `413 contract_error`嵌入原error |
| F0 malformed/unsupported | `400 contract_error`嵌入原error |
| 本规格context-bound closed error | `409 contract_error`嵌入原error |
| per-Node cap满 | `429 node_request_in_flight`，设置`Retry-After: 1` |
| global cap、DB/deadline/serialization retry exhausted | `503 temporarily_unavailable`，设置`Retry-After: 1` |
| Control Store invariant failure或未分类server bug | `500 internal` |

不匹配path返回普通404且没有A20 envelope。HTTP server仍可加入正确的`Content-Length`/`Date`等framing
header。任何error都不得持久化成observation/Condition或domain success/error receipt。

固定处理顺序是：path dispatch -> method -> query -> Content-Type -> Content-Encoding -> Authorization ->
Accept -> forbidden semantic headers -> non-blocking global admission -> bounded body -> A19 proof -> F0 decoder ->
credential的唯一provisioned NodeIdentity + exact active credential lineage -> non-blocking per-Node admission ->
session/domain transaction（NodeIdentity锁后再次join并持有lineage share lock到commit）。前一
stage失败不得读取或暴露后一stage事实；特别是proof失败不解析JSON、不查credential，F0失败不查
NodeIdentity，identity失败不查session。A19 authentication 得到eligible Node后才按`node_id`取得per-Node
admission。没有 handler admission等待队列；跨replica并发不靠内存cap证明唯一性，仍由§3/§6相同的
PostgreSQL current-row lock和exact replay状态机串行化。handler deadline 从收到完整 headers 开始；在事务 commit 前到期必须
回滚，commit 结果不明则关闭 response，Agent 只能按相同 domain sequence exact replay。实现可在 deadline
内对 serialization/deadlock做最多 3 次完整事务重试；每次必须从 authentication 后的 immutable decoded
request 重新读取全部 Control Store facts，不能复用前一次 snapshot。

HTTP global/per-Node permit本身不能保护唯一session续期点：它们之后仍可能共享同一个
blocking worker、queue或PostgreSQL connection。因此`POST .../observations`的全部Store调用（包括先判定
sequence的exact replay）必须进入本规格表中的renewal-critical lane：它有独立的一个blocking
worker、最多一个waiter的FIFO queue和一个独立Control Store PostgreSQL connection。这是使用同一DSN、
schema和transaction函数的第二个有界Store执行实例，不是新authority或新数据库。Desired read、
registration、planner/signer、product/controller mutation和
[Runtime Volume Transitions](runtime-volume-transitions-v1.md)均不得提交、借用或在空闲时抢占该worker、queue或
connection。这一个保留connection必须计入replica/RDS Proxy的硬上限。
部署在计算ordinary pool上限前先从该replica和database/proxy的connection budget中扣除这一席；
replica启动/readiness必须打开该connection，断线重连仍消耗同一保留席。ordinary Store不得
因保留connection尚未发送SQL就把该席计入自己的可用上限。

renewal-critical Store调用携带从HTTP headers到达时刻派生的同一absolute deadline，排队时间、
connection acquire、全部transaction retry和commit都消耗这一额度。queue满立即503；在queue中
取消必须删除closure。已开始的调用必须使用不超过剩余额度的connection/statement/lock timeout，
取消或shutdown时必须cancel query、rollback或关闭连接并join worker；不得在handler返回后让detached
closure稍后提交续期或observation。commit outcome已不明时只关闭response并由exact replay解析，
不得用503猜测事务未发生。

## 3. Desired read-position

### 3.1 scope、顺序与签发

Control Store为每个 Node 保存一个 bounded logical `DesiredReadState`：

```text
DesiredReadState {
  node_id,
  read_position_high_water,
  current_session: SessionBinding,
  last_request_sequence,
  last_response: DesiredReadSnapshot,
  consumed_by: {observation_id, heartbeat_sequence} | null
}
```

这是逻辑合同，不规定 Rust struct 或 SQL column 布局。每个 Node 最多一份 current response；
`read_position_high_water`跨 session 保留并且永不回退、重置或复用。第一次成功签发为 1，之后每次新
snapshot 都以 checked add 得到 `high_water + 1`；耗尽是 store invariant/unready，不wrap、不归零。

`request_sequence`只在一个 exact `SessionBinding`内有序。这是会覆盖bounded read state的
`READ COMMITTED` mutation transaction；它先按authenticated identity取得并重验
`NodeIdentity FOR UPDATE`，再锁current `AgentSession -> DesiredReadState`，取一次PostgreSQL
`db_now`，并严格按“Node identity → current session binding
→ `db_now < lease_deadline_unix_ms` → server-time causality → request sequence”判定。只要state仍保留任一
session最后一份response，就必须先满足`db_now >= last_response.issued_at_unix_ms`；倒退是fatal/
unready且零写入，不得返回exact replay或签发新snapshot。然后才按下列顺序处理：

1. 新 session 的第一份 request 必须为 1。
2. 只有current session仍满足`db_now < lease_deadline`后，等于该 session 当前
   `last_request_sequence` 的完整 decoded request才是exact replay，逐 byte 返回原 `last_response`，包括原
   issued/expiry 和原 specs；不读取 current Desired，不延长 session/read TTL。expired session连Desired
   exact replay也返回`session_expired`；deadline后唯一可返回success的例外只有§4 highest exact
   observation，用来解析不可逆accept commit。
3. 小于 last 返回 `stale_desired_read_sequence`；大于 `last + 1`返回
   `wrong_desired_read_sequence`。与 heartbeat sequence 不同，Desired request 不允许 gap。
4. 恰好 `last + 1`时，仅当上一 cursor 已被 full observation 消费、`db_now >= expires_at_unix_ms`，或
   当前 assigned set 已不再逐字段等于上一 snapshot，才可签发下一位置。三者都不是时返回
   `desired_read_in_progress`，其中error的`request_sequence`逐字段复制本次
   `DesiredReadRequest.request_sequence`（也就是presented `last + 1`），而不是retained response的
   `request_sequence`（也就是state的`last_request_sequence`）；不覆盖可重放 response。

新 snapshot 在上述同一 PostgreSQL transaction snapshot 中完成：读取所有
`placement.kind="assigned" && placement.node_id=authenticated node` 的 current full Desired，按
`cat_id`排序、strict decode、重算 `spec_digest`并核对全部 projection；分配新 read position，令
`issued_at_unix_ms=db_now`、`expires_at_unix_ms=checked_add(db_now,30000)`，最后原子保存完整 response。
任何 invalid row、overflow、超过 1024 specs 或 canonical response 大于 16777216 bytes 都整笔回滚；
前三者是 store invariant/unready。route可在进入unready前对超限count编码
`assigned_set_limit_exceeded {limit:"desired_specs"}`，但不签发/持久snapshot；A23 planner loader必须
将同一事实视为fatal，不是ordinary candidate rejection。response byte cap仍返回该error的
`limit:"wire_bytes"` variant。

snapshot 是 signed request 对应的 immutable read receipt，不是 Desired authority。签发后 current Desired
可继续变化；因此 full observation 接受时必须按 §5 重读并比较 current set，不能只相信 cursor 尚未过期。

### 3.2 session replacement、replay 与 GC

注册 replacement 一旦提交，旧 session 的 Desired request 永久先返回 `stale_session`/`wrong_session`；
即使旧 response 仍在 row 中也不能重放。新 session 第一次 request 用 sequence 1覆盖旧 response，但
`read_position_high_water`继续增加。无需注册事务跨模块删除 A20 rows：每次 A20 读取都必须先绑定 current
session，旧绑定本身即不可消费。

current response只有在上述第4条允许时覆盖。覆盖后更老 request sequence只返回 stale，不维护历史
response ledger。已消费 cursor仍作为最新 request 的 exact replay response保留，直到新 snapshot 覆盖；
expiry不删除 replay 结果。GC因此只是每 Node 一行 bounded overwrite，不允许 per-poll row、随机
request-ID ledger、按 Desired revision累积快照或定时全表历史清理。

## 4. Observation session/sequence gate

`POST .../observations`的 request body 直接是 Runtime §10 `NodeObservation`，不套 heartbeat envelope。
adapter/F0通过后，context-bound固定顺序为：

1. credential -> provisioned `NodeIdentity FOR UPDATE` -> body `SessionBinding` -> current
   `AgentSession FOR UPDATE`；
2. current session 的 observation receive-state/highest accepted heartbeat sequence；
3. 对新 sequence 才检查 session deadline；
4. full/partial inventory cursor、epoch与assigned set；
5. Runtime §16.4.3 revision、stored digest、placement；
6. Runtime §12 Operation settlement/postcondition；
7. 一个事务提交全部接受结果。

heartbeat sequence严格沿用 Runtime §10：首次可为任一有效 `Sequence`，更大值可有 gap；等于 highest 且
完整 decoded `NodeObservation`逐字段相同是 exact replay；等于但任一字段不同是
`observation_sequence_conflict`；更小是 `stale_observation_sequence`。只保存 current session highest
payload和首次 `ObservationAcceptance`，不保存历史sequence ledger。

exact replay 在 deadline/cursor/epoch/current Desired 检查之前返回原 canonical success。只要 body 仍绑定
同一个 current session，即使现在 `db_now >= lease_deadline`、read position 已过期/消费或 Desired 已变化，
也必须解析首次 commit 的模糊结果；它不写任何 row、不刷新时间、不再次结算 Operation。session 已被
replacement时仍先拒绝，旧 session success不能跨 session重放。

只有此前未接受的更大 sequence要求单次事务 `db_now < current lease_deadline_unix_ms`；相等即
`session_expired`。若Node receive-state已有任一session的首次接受结果，还要求
`db_now >= last_accepted_at_unix_ms`；倒退是fatal/unready且零写入。任一新 observation 完整接受时，精确实现
[A19 §7](agent-registration-transport-v1.md#7-agentsession-lease-policy)的唯一续期点：用同一次 `db_now`令
`accepted_at_unix_ms=db_now`，先checked计算`candidate=checked_add(db_now,60000)`，再把current session
deadline单调写为`max(old_deadline,candidate)`，并在response返回相同updated值。Desired read、exact replay、任何拒绝、HTTP
成功以外的请求或客户端自报 deadline都不能续期。

registration attempt保存的首次 `AgentSession` result仍immutable且保留初始deadline；current session row
只允许相同 identity/session字段和不小于既有值的deadline。实现重验attempt/current时必须比较除deadline外全部字段
逐字段相同，并要求 `current.deadline >= immutable_attempt_result.deadline`；不能继续要求两个完整
`AgentSession`逐字段相等，也不能回写attempt result。

## 5. Full 与 partial inventory 接受

### 5.1 inventory epoch

`inventory_epoch`只在 exact session 内有效：

- 该 session 第一次 accepted full inventory必须为 1；
- 后续 accepted full必须精确为 current attestation epoch的 checked `+1`；小于等于 current 返回
  `stale_inventory_epoch`，大于 expected返回 `wrong_inventory_epoch`；epoch耗尽时 fail closed/unready；
- partial必须已有 current session attestation，并且 epoch逐字段等于它；更小返回
  `stale_inventory_epoch`，更大返回 `wrong_inventory_epoch`；
- session replacement后旧 attestation即使尚未物理覆盖也不属于新 session；新 session从 full epoch 1
  重新开始。read position与它不同，跨 session永不复用。

Runtime §10的 intrinsic规则保持不变：full必须
`complete_inventory=true`、digest/read-position非null并可重算、可携带 bounded Node residue；partial必须
`complete_inventory=false`、digest/read-position均null、`residue=[]`。

### 5.2 full cursor 与 complete assigned set

对新 full observation，事务在 sequence/deadline通过后要求：

1. 当前 Node 有同 session 的 `DesiredReadState`；presented read position等于 current response位置。
   更小返回 `stale_inventory_read_position`，更大返回 `wrong_inventory_read_position`；无 current cursor
   返回 `missing_inventory_read_position`。
2. cursor未被其他 accepted full observation消费，且同一次
   `issued_at_unix_ms <= db_now && db_now < expires_at_unix_ms`；相等expiry即过期。已消费返回
   `inventory_read_position_consumed`，过期返回 `inventory_read_position_expired`；`db_now`早于cursor
   issuance或stored `issued_at >= expires_at`是server-time/stored-state invariant failure，fatal/unready且零写入，
   不得构造accepted time早于read-position issuance的receipt。
3. 在同一 PostgreSQL transaction snapshot重新读取该Node全部 current assigned full Desired，并逐字段
   等于 cursor snapshot，包括集合成员、每项完整 schema、revision、digest、placement和全部 intent。
   任一增删改返回 `assigned_set_changed`；不得接受部分交集或用 digest aggregate代替。
4. inventory epoch符合 §5.1。
5. `NodeObservation.runtimes`对 snapshot中每个 `cat_id`恰有一份完整 `ObservedRuntimeStatus`。缺失返回
   `incomplete_assigned_inventory`并稳定选择最小 missing `cat_id`。full scan可以另含本地 orphan Cat；
   它仍按 Runtime schema/排序验证，缺少可关联的有效 checkpoint/Desired时才允许
   `applied_desired=null`。extra不把 cursor snapshot变成 assigned Desired。
6. 对 snapshot中每个assigned Cat，不论其Operation是Pending、Succeeded、Failed、Superseded还是不存在，
   对应runtime的`applied_desired`都必须非null，并逐字段等于由该Cat cursor/current
   `DesiredRuntimeSpec`投影的
   `AppliedDesiredEvidence {desired_revision,spec_digest,placement,target}`。任一null或字段不等返回
   `assigned_runtime_binding_mismatch`，按最小`cat_id`选择，error的`expected`复制server snapshot投影，
   `presented`复制request值（允许null）。该检查在Operation settlement之前执行；不能因Operation已经terminal、
   没有Pending row，或runtime带Ready/Condition就跳过。只有不在snapshot assigned set中的extra orphan才允许
   `applied_desired=null`。

以上全部通过后才进入现有 revision/digest/placement和Operation stage。

`complete_inventory=true`只证明 Runtime §6列出的全部约定物理来源已在 Node 的 bounded scan完成；Control
Plane不能从“有每个 assigned Cat”推导缺失的物理source已扫描。Agent若有任一source unavailable，必须按
Runtime规则发送 partial/Blocked evidence或不提交 full，不能用空数组伪造完整。

### 5.3 partial

新 partial observation要求 current session已有 accepted full attestation，且 epoch精确相同。它只替换
`runtimes`列出的 per-Cat current observation；没有列出的 Cat保持原 row，缺项从不表示 absent。partial
不能覆盖 full observation、assigned snapshot、Node residue或 attestation，也不能把一次 per-Cat更新变成
新的 complete inventory。列出的每个 runtime仍完整替换该Cat状态，不做字段patch。

每个partial `runtime.cat_id`还必须已经存在于current `AdmissionInventoryState.full_observation.runtimes`；
否则按cat ID选择最小项返回`partial_cat_not_in_full_inventory`，整份observation零写入。新assigned Cat或新
orphan只能由下一次full inventory加入current physical集合；partial不能不断轮换新cat ID扩张数据库。
因此一个Node的current per-Cat row数始终不超过最近full inventory的1024项，full replacement是唯一增删
membership的入口。

### 5.4 服务端 attestation 与 current read model

full成功时，Control Plane从已验证的 request和同一 `db_now`唯一构造：

```text
AdmissionInventoryAttestation {
  version: 1,
  node_id: observation.node_id,
  agent_session_epoch: observation.agent_session_epoch,
  inventory_epoch: observation.inventory_epoch,
  inventory_digest: observation.inventory_digest,
  inventory_read_position: observation.inventory_read_position,
  accepted_at_unix_ms: db_now
}
```

Node request不能提交 attestation、`accepted_at`或 freshness。full acceptance还原子保存一个 bounded current
`AdmissionInventoryState`，包含完整 attestation、产生它的完整 accepted full `NodeObservation`和 cursor
中的完整 assigned `DesiredReadSnapshot`；这些是同一 receipt 的可重验组成，不是三个可独立更新的
authority。partial永不修改该state。

current per-Cat read model至少保存完整 `ObservedRuntimeStatus`、完整 `SessionBinding`、inventory epoch、
source observation ID/heartbeat sequence、服务端 accepted time和来源 `full|partial`。full把该Node全部
per-Cat rows原子替换成 request `runtimes`的精确集合；因此已不在 physical full inventory中的旧 orphan
row被删除。partial只upsert列出的rows。所有JSON row都必须 strict decode/re-encode并与 scalar projection
逐字段核对；不合法stored row是 invariant failure，不降级成Node error。

cursor在full成功事务中标记为由该 observation ID/sequence消费。`ObservationAcceptance.inventory.full`
返回上述 exact attestation；partial response返回引用的 epoch。两种 response都和 highest accepted payload
一起保存供 exact replay。

full acceptance只是在该commit建立current receipt，不承诺它在后来Desired/session变化后仍可消费。任何
planner、signer、adoption、cleanup、Persistent delete或“物理不存在”判定都必须在自己的单一PostgreSQL
snapshot重验：current live session、state外层session、`accepted_at <= db_now < accepted_at+60000`、state
内部完整binding、`cursor.issued_at <= accepted_at < cursor.expires_at`以及current assigned set与stored
snapshot逐字段相同。普通partial不能延长full receipt
freshness。任一消费者只读attestation digest/epoch、忽略assigned snapshot，或在多个transaction拆读都不
构成complete inventory proof。

## 6. 单一原子事务与 Operation settlement

每个首次接受的新 observation只有一个 PostgreSQL `READ COMMITTED` mutation
transaction，禁止在 commit 前后分拆 attestation、read model、session lease或Operation。
跨副本的 logical lock/read顺序固定为：

```text
authenticated current NodeIdentity FOR UPDATE
-> exact active credential lineage FOR SHARE（A19 auth适用时）
-> current AgentSession
-> Node observation receive-state
-> DesiredReadState / AdmissionInventoryState（适用时）
-> VolumeRecord，按 volume_id
-> DiskRecord，按 disk_id
-> current Desired，按 cat_id
-> current Pending Operation，按 cat_id
-> DiskSnapshotRecord / delete completion receipt，按 disk_id/receipt identity
-> per-Cat observation rows，按 cat_id
-> attestation/cursor/receive-state/current session deadline writes
```

`NodeIdentity`是assigned-set的coordination row，不是只在HTTP proof后做一次不加锁的
eligibility lookup。所有会为current Node插入、supersede、移动或删除current Desired的mutation
transaction都必须先锁同一`NodeIdentity FOR UPDATE`，再按本规格/全局DAG取得后续row。
这使full assigned-set重读与新Desired INSERT没有phantom窗口，也与
[Runtime Volume Transitions §4.1](runtime-volume-transitions-v1.md#41-共同前缀与锁序)使用同一可证锁前缀。

实现可在锁前bounded发现request涉及的Cat/volume/disk identity，但不能据此判定或写入；取得上述authority锁后
必须重新读取current rows并从头验证。这个顺序保持Volume Authority的
`Volume -> Control Disk/Desired/Operation -> DiskSnapshotRecord`全局锁序；不适用的row跳过，不能为了省锁
改成`Desired -> Volume`或`Snapshot -> Desired`。这是coordination lock顺序，不改变§4/Runtime §16.4.3的
error stage：为遵守DAG可先仅按主键取得Volume/Disk锁，但在revision/digest/placement全部通过前不得decode、
比较、按row存在性分支或渲染任何volume/postcondition error；完整authority facts只在最后postcondition
stage读取使用。

`NodeIdentity` lock是A23后每Node current assigned full Desired的唯一serialization前缀，不是新的
observation authority。Desired read、full/partial observation、AgentSession registration/replacement、policy apply和
任何会写old/new assigned current Desired任一字段的commit都必须先锁定并重验authenticated/affected Node的
current `NodeIdentity`，再按上述顺序
取exact active credential lineage（仅A19-auth path；其他路径跳过）、AgentSession/receive/cursor rows；任何事务都不得先锁credential lineage、
AgentSession、receive-state、cursor或Desired后
反向取NodeIdentity。identity在auth与transaction之间retire/rotate时，锁后重验拒绝旧事实，
不得用auth时的cached row。

因此observation与Cat-create/policy apply的两个并发方向只能由先取得NodeIdentity的一方前进：
observation先提交时create/apply在锁后看到new receive/admission facts；create/apply先提交时
observation在锁后看到new assigned set/policy并按同一个current contract重新判定。后一方可返回
stale/changed并fresh retry，但不存在`AgentSession -> NodeIdentity`与`NodeIdentity -> AgentSession`
或`credential lineage -> NodeIdentity`与正序同时等待的环。

这里的“任一字段”包括placement/shape以外的target、route、volume intent、disk/disposition、require-idle和
任何仍使`DesiredReadSnapshot` canonical bytes/spec digest变化的字段。writer从无锁snapshot得到old/new
assigned node并按node ID锁全后，必须重读current Desired；affected set变化就rollback/fresh retry。
因此non-shape revision与Cat-create也覆盖两种barrier顺序：revision先提交时create只能读取new full spec；
create先提交时revision在同一NodeIdentity后看到new assigned set，二者都不得死锁或让observation接受混合集合。

事务只做同一Control PostgreSQL中的Control Store/Volume Authority I/O，不访问filesystem、Node、object
store、provider或Gateway。
消费本attestation的A22 volume transition不得只查看expected Cat的runtime：它必须从保留的完整
`NodeObservation`按volume ID索引全部runtime中的ObservedVolume、blockd process和mount，并同时检查顶层
Node residue。expected runtime中的metadata authority映射不等于本地物理writer；duplicate/foreign volume、
blockd、mount或可能命名该volume的residue都必须显式进入调用方的closed判定。
Runtime §16.4.3 的完整 error selection必须在任何 write前完成。full/partial validation、per-Cat
replace/upsert、full complete replacement、server attestation、cursor consume、Operation settlement、highest
sequence、exact success response、accepted time和lease renewal全有或全无。

Operation必须在这个事务内按 Runtime §12精确结算，不能先接受 observation再由异步worker补结算：

- 只考虑 request `runtimes`中 `applied_desired != null`且该Cat有 current Pending Operation的项；
- current Desired、Operation和applied evidence的revision/digest/placement逐stage验证；任何一项失败拒绝整份
  NodeObservation，不接受其他Cat；
- §11 stable postcondition必须同时重验同snapshot锁定后的current Volume/Disk/Snapshot/delete receipt事实；
  observed `VolumeAuthorityEvidence`不能替代`VolumeRecord`。Running/Suspended/Warm/Cold/Deleted各自仍使用
  Runtime §11和Volume Authority的唯一闭合分支；Deleted完成允许其合同要求的Volume/Disk row absent并以
  exact `DeleteCompletionReceipt`闭合，其他target缺row或owner/epoch/head、`R/L`、snapshot/receipt任一不等
  只保持Pending或按既有closed Condition结算，不能仅凭Node自报stable state成功；
- 在全部context validation通过后，对每个runtime精确复用Runtime §12的唯一selector：
  从已按§10.4 canonical order排序的`conditions`中取第一个`precondition_failed|quarantined`，
  将其`kind`/`reason`逐字段映射为`OperationFailure`；多个terminal Condition不另建severity、
  不聚合也不以SQL/扫描顺序选择。存在候选时必须`Pending -> Failed`，并且先于
  Ready/§11 success判定；没有候选时才由精确stable target postcondition决定
  `Pending -> Succeeded`，否则保持Pending。HostLost只由Runtime §9的trusted controller/fence事务写入，
  不从Node Condition推导；
- 新 Desired supersede并发仍由 Desired mutation transaction负责；observation事务只结算它锁后重验仍为
  current且绑定同revision的Pending Operation；
- exact replay只读首次 response，不再次执行 terminal transition、写updated time或产生审计副作用。

所有本次terminal Operation的`terminal.completed_at_unix_ms`和`updated_at_unix_ms`都精确等于本次同一
`db_now`，并在写前要求它不小于各Operation既有`created_at/updated_at`；任一倒退整份observation
fatal abort。多Cat settlement不能各取一次时间。

任一 terminal postcondition需要 transaction外物理读取，说明该证据没有完整进入
`NodeObservation`合同，V1必须保持 Pending/拒绝，不能在本事务内做外部I/O或事后补一个 bool proof。

上述`READ COMMITTED`只适用于session-bound Desired/observation mutation。本规格§7的planner与
signer仍必须使用各自单一`REPEATABLE READ READ ONLY` snapshot；它们不取代这个
NodeIdentity coordination lock，也不得将多个普通read拼成伪snapshot。

## 7. Planner / signer 的同 snapshot读取

### 7.1 Store 返回的完整 admission facts

A20 Store只提供完整facts loader，不提供 `eligible`、`fresh`、`capacity_ok`或 `network_ok` boolean：

```text
PlacementAdmissionSnapshot {
  evaluated_at_unix_ms: UnixMillis,
  node_identity: NodeIdentity,
  agent_session: AgentSession,
  inventory_attestation: AdmissionInventoryAttestation,
  full_inventory_observation: NodeObservation,
  assigned_desired_specs: [DesiredRuntimeSpec]
}
```

这是 Control service内部typed contract，不是 HTTP wire、持久 authority或Runtime F0顶层合同。
`assigned_desired_specs`是 planner transaction snapshot中的完整 current set，而不是从 attested response
反序列化后直接返回；loader必须同时比较它与 `AdmissionInventoryState`保存的 cursor snapshot逐字段相同。

一次standalone候选读取使用一个 PostgreSQL `REPEATABLE READ READ ONLY` transaction snapshot和一次数据库
`db_now`；A23 whole-fleet planner则把所有keyset page/candidate放在同一个这样的outer transaction。A20 loader
必须接受调用方transaction与该次`db_now`，不能为每个Node自行begin/commit。在同一snapshot完成：

1. `NodeIdentity.state=provisioned`，identity/credential projection完整自洽；
2. `AgentSession`是该Node current row，identity/Host绑定自洽，且
   `db_now < lease_deadline_unix_ms`；deadline相等已过期；
3. session `guest_config_digest`逐字段等于调用方传入的 active release digest；
4. current `AdmissionInventoryState`外层session等于current session；若仍是合法旧session残留，返回普通
   `inventory_session_replaced`。外层session已相同后，attestation/full observation/cursor snapshot必须
   逐字段闭合，full flag/digest/read position/epoch全部相同，并满足
   `cursor.issued_at_unix_ms <= attestation.accepted_at_unix_ms < cursor.expires_at_unix_ms`；任一不等或
   时间因果不成立都是stored corruption；
5. `accepted_at_unix_ms <= db_now`且以checked arithmetic满足
   `db_now < accepted_at_unix_ms + 60000`；等于加和即 stale，未来accepted time或加法overflow是stored
   corruption，不是fresh；
6. current assigned full Desired集合逐字段等于 attested cursor snapshot，全部strict decode、digest/
   projection自洽，并按cat ID完整返回；
7. stored full inventory `runtimes`覆盖其stored assigned snapshot中的每个Cat；这是§5 acceptance后不可
   破坏的内部invariant，缺项是fatal corruption。额外orphan证据也必须完整返回在
   `full_inventory_observation`中，不能由loader过滤。

缺少state、state属于已replacement旧session、freshness过期或current assigned set已变只是该Node本次不可选，
loader返回 closed `PlacementAdmissionRejection` reason；同session state内部任一binding不等、full缺失其
accepted assigned Cat、stored JSON/projection/digest不自洽、server time倒退或overflow是fatal Store error并
使本replica unready。两者都不返回半份snapshot，也不能把stored corruption降级成“换个Node”。
本loader读到的current `assigned_desired_specs`若超过1024项同样是fatal/unready；只有未超限、
逐字段完整的集合才能返回给planner。

```text
PlacementAdmissionRejection =
  "identity_not_provisioned"
| "session_missing"
| "session_expired"
| "guest_config_mismatch"
| "inventory_missing"
| "inventory_stale"
| "inventory_session_replaced"
| "assigned_set_changed"
```

具体Node排序、静态schedulable/capability来源、capacity估算和NetworkConfig地址选择由
[Runtime Placement Policy v1](runtime-placement-policy-v1.md)唯一冻结，不由A20建立scheduler row或
reservation。A23在同一个`REPEATABLE READ READ ONLY`transaction和同一个DB now中，以keyset page 64把
current policy与上面的完整snapshot组合；不能先读policy、随后为A20另开snapshot。planner必须用完整assigned
specs/full observation计算占用和network residue，不能回退legacy Node heartbeat或把Node自报数字变成
第二authority。A20 snapshot只是可失效的pre-transaction plan；Cat create commit后事实变化按Runtime既有
`PlacementRejected -> new revision`闭合。

当前`PostMutationPlacementPlan`（Cat create是其closed subtype）必须携带A23的完整
`PlacementPolicySnapshot`（其中包含上述`PlacementAdmissionSnapshot`）、source/current CAS、
server-derived exclusion、HostFence facts和exact `NetworkConfig`，而不是只摘出
NodeIdentity/AgentSession/attestation三项让service误以为已检查freshness。service仍逐字段验证完整binding；
它不接受planner自报boolean或source exclusion。
Cat create事务在name free且将写新Desired的分支，必须先以candidate NodeIdentity作为每Node assigned-set唯一
coordination row取得`FOR UPDATE`，再按§6的NodeIdentity-first顺序重载并逐字段比较完整
policy/admission/HostFence snapshot、重算post-mutation count/capacity与network probe，随后才可锁
Volume/Disk/Desired/Operation；合法same-name 409分支不改变Desired，只保存exact result，因此不读取或
锁定这份可失效plan。
该409分支仍按Volume Authority既有顺序锁定并验证existing Cat graph；“不消费plan”不允许把existing graph
降成unlocked snapshot，也不允许在并发Destroy赢得Volume锁后缓存一个假的name conflict。

### 7.2 Route signer freshness

Route signer每次resolve同样使用一个 PostgreSQL `REPEATABLE READ READ ONLY` transaction snapshot和一次
`db_now`：

- session deadline与attestation检查完全复用 §7.1；attestation max age固定60000 ms；
- current per-Cat accepted row必须绑定相同session与attestation inventory epoch，并满足
  `accepted_at_unix_ms <= db_now && db_now < checked_add(accepted_at_unix_ms,30000)`；等于expiry即 stale；
- per-Cat row可以来自full或后续partial，但其完整runtime evidence仍必须满足 Route Grant v2 §3的
  revision/placement/incarnation/Ready/gate/ring条件；
- future server timestamp、overflow或row/projection不自洽是fatal/unready，不签发；普通stale返回
  RuntimeNotReady/Unavailable，不签发但不改Desired/observation。

signer不能分别在多个transaction读取session、attestation、Desired和per-Cat row，也不能用Node的
`observed_at_unix_ms`、legacy heartbeat time或进程wall clock判 freshness。

## 8. Closed context errors 与固定选择

本规格给 Runtime §16.4 `ContractErrorDetail`增加以下 closed variants；字段都是经过F0验证的共享类型：

```text
{ code:"missing_agent_session", node_id }
{ code:"session_expired", node_id, agent_session_epoch,
  lease_deadline_unix_ms, server_time_unix_ms }

{ code:"stale_desired_read_sequence", node_id, agent_session_epoch,
  presented_request_sequence, last_request_sequence }
{ code:"wrong_desired_read_sequence", node_id, agent_session_epoch,
  expected_request_sequence, presented_request_sequence }
{ code:"desired_read_in_progress", node_id, agent_session_epoch,
  request_sequence, read_position, expires_at_unix_ms }
{ code:"assigned_set_limit_exceeded", node_id,
  limit:"desired_specs" | "wire_bytes", maximum, observed_at_least }

{ code:"missing_inventory_read_position", node_id, agent_session_epoch }
{ code:"stale_inventory_read_position", node_id, agent_session_epoch,
  presented_read_position, current_read_position }
{ code:"wrong_inventory_read_position", node_id, agent_session_epoch,
  current_read_position, presented_read_position }
{ code:"inventory_read_position_expired", node_id, agent_session_epoch,
  read_position, expires_at_unix_ms, server_time_unix_ms }
{ code:"inventory_read_position_consumed", node_id, agent_session_epoch,
  read_position, accepted_observation_id, accepted_heartbeat_sequence }
{ code:"assigned_set_changed", node_id, agent_session_epoch, read_position }
{ code:"incomplete_assigned_inventory", node_id, agent_session_epoch,
  read_position, missing_cat_id }
{ code:"assigned_runtime_binding_mismatch", node_id, agent_session_epoch,
  read_position, cat_id, expected:AppliedDesiredEvidence,
  presented:AppliedDesiredEvidence | null }

{ code:"missing_inventory_attestation", node_id, agent_session_epoch }
{ code:"stale_inventory_epoch", node_id, agent_session_epoch,
  presented_inventory_epoch, current_inventory_epoch }
{ code:"wrong_inventory_epoch", node_id, agent_session_epoch,
  expected_inventory_epoch, presented_inventory_epoch }
{ code:"partial_cat_not_in_full_inventory", node_id, agent_session_epoch,
  inventory_epoch, cat_id }
```

`assigned_set_limit_exceeded`在 item超限时固定为
`{limit:"desired_specs",maximum:1024,observed_at_least:1025}`，在 response encoder越过byte cap时固定为
`{limit:"wire_bytes",maximum:16777216,observed_at_least:16777217}`；若两者同时发生，item limit优先。
`wrong_desired_read_sequence`只用于 first不是1或
presented大于checked `last+1`；`stale_desired_read_sequence`严格小于last。`stale_inventory_epoch`
严格满足presented小于等于current；`wrong_inventory_epoch`严格大于expected，或first full不等于1。
`desired_read_in_progress.request_sequence`固定来自本次presented request，不是retained
`DesiredReadSnapshot.request_sequence`；其`read_position/expires_at_unix_ms`固定来自retained response。
`assigned_runtime_binding_mismatch.expected`固定从已经重验与current相同的cursor spec投影，`presented`固定
从同Cat request runtime复制；不按第一个不同field缩窄payload或改用Operation binding。

在 Runtime §16.4.3 的 session与observation sequence之后、revision之前，固定选择顺序是：

1. 对新 request检查 `session_expired`；exact observation replay已在此前返回，不进入本stage。
2. full按 missing/read-position stale/wrong/consumed/expired、assigned-set-changed、inventory epoch、最小
   missing assigned Cat、最小assigned runtime binding mismatch顺序；同一类只有一个 current
   cursor/epoch，因此无store-order tie-break。binding检查覆盖每个assigned Cat且不以Pending Operation为
   前提。
3. partial按 missing attestation、inventory epoch、最小
   `partial_cat_not_in_full_inventory.cat_id`顺序。
4. 所有这些通过后才进入现有revision -> digest -> placement -> settlement。

Desired read endpoint在session binding后独立执行 session expiry -> retained-response server-time causality
-> request sequence -> in-progress/set limit；causality failure是fatal Store invariant/unready，不是
`ContractError`。因此expired request不读取或返回stored Desired snapshot，也不泄露last request sequence。
任一错误零持久副作用；错误response不保存、不续lease、不改变cursor/highest sequence/attestation/
per-Cat row/Operation。多个可能的revision/digest/placement错误继续使用 Runtime §16.4.3按最小cat和stage
选择，本文不建立第二套排序。

## 9. Fixed vectors

以下 code block 内容是 exact Cats Canonical JSON bytes：单行UTF-8、无前后whitespace和结尾newline。
它们只校准 DTO/field order；列出的普通SHA-256是文档完整性checksum，不进入签名以外的新authority。
A19 request signature仍对调用时 exact raw body独立计算SHA-256。

**DesiredReadRequest：**

```json
{"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}
```

`SHA-256(exact bytes) = 4e231231b83a31f2731a0a95724d883020084d0239f58ba1e615083072f36245`

使用A19 §4.4相同的RFC 8032 test seed/SPKI和`credential_id=credential_a`，该body在
`POST /v1/internal/runtime/desired-reads`下的proof vector是：

```text
body_octet_length = 194
signed_request_length = 223
signed_request_sha256 = e9ff2d78db69f299fc7853fbc7a5f75aba37fdd29bdddf54ac2306472f396fcc
Cats-Node-Signature = 4veg_1IoMfKpXj149Ky48wGnXYS1xGiamgVwibgHbU3ktHmaYCPWC2Lt6rdv22nRJFSp_c8JzM1yfeAyXVARCw
```

**Partial NodeObservation request/proof：**

```json
{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"complete_inventory":false,"heartbeat_sequence":9,"inventory_digest":null,"inventory_epoch":4,"inventory_read_position":null,"key_ring_digest":null,"key_ring_version":null,"loaded_kids":[],"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","observation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at_unix_ms":1720000004000,"residue":[],"runtimes":[],"version":1}
```

```text
body_octet_length = 465
body_sha256 = f8cc412d7820597b09c7ee5d9b8b2ad75dfaef9596bea557e0064ee5fdfae7a7
signed_request_length = 222
signed_request_sha256 = 4bed38ed887508ac9a6beb1b41915b28869ec7f2e793d3d7f6901df1ab805288
Cats-Node-Signature = 4iiUxzN7kwuyg5z0xwb20qpLxwIUTO09N1JS-GGA1iGlVJseDYNVFfvXZEULquVW8cLcvGj69dWGNSzzF3pfDA
```

这条partial body通过F0；是否接受仍取决于current session已有epoch 4 attestation。把proof移到另一个A20
path、改变method/content-type/body任一byte都必须验签失败。

**空 assigned-set DesiredReadSnapshot：**

```json
{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}
```

`SHA-256(exact bytes) = 5e71eabff38019ccb7ff142593f07261de677547da3b2882163886578c21c00d`

**对应 Runtime §16.3 empty full inventory 的一次接受**（前置current attestation epoch为3；这不是该session
第一次full）：

```json
{"accepted_at_unix_ms":1720000005000,"heartbeat_sequence":9,"inventory":{"attestation":{"accepted_at_unix_ms":1720000005000,"agent_session_epoch":2,"inventory_digest":"sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05","inventory_epoch":4,"inventory_read_position":12,"node_id":"node_a","version":1},"kind":"full"},"lease_deadline_unix_ms":1720000065000,"observation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}
```

`SHA-256(exact bytes) = a67ae8fbd6adf6f1ba57d6c5027c75b7d412dd5d04ad27756aa6522e27eba086`

下列是一个exact Cats Canonical JSON `ObservedRuntimeStatus.conditions`片段，不是新顶层wire。它同时
携带Ready、两个PreconditionFailed和一个Quarantined，用于校准Runtime §12的唯一
terminal selector：

```json
[{"kind":"ready","reason":{"kind":"postcondition_satisfied","target":"running"}},{"kind":"precondition_failed","reason":{"kind":"must_be_cold","observed_state":"running"}},{"kind":"precondition_failed","reason":{"kind":"placement_rejected","node_id":"node_a","placement_epoch":3,"reason":"insufficient_memory"}},{"kind":"quarantined","reason":{"kind":"checkpoint_corrupt","raw_content_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]
```

`byte_length = 469`；`SHA-256(exact bytes) =
5c3ee698b8e2c2f113edac24c1213b765eec474f740ad233fd9f81f77851c7dd`。在其他binding/context全部合法时，
唯一选中的exact `OperationFailure`是：

```json
{"kind":"precondition_failed","reason":{"kind":"must_be_cold","observed_state":"running"}}
```

`byte_length = 90`；`SHA-256(exact bytes) =
02f0c1a22771e9f653526233f827a978f55f258a8bf7528101b9d03c96fd595d`。Ready不能越过terminal failure，
后面的PlacementRejected/Quarantined也不能覆盖第一个canonical terminal。

实现验收必须由独立encoder逐byte重建上述向量，并覆盖：wrong method/path/body导致A19 signature拒绝；
live Desired request exact replay、expired Desired replay拒绝；read cursor expiry equality；session expiry equality与
expired highest exact observation唯一成功例外；first/subsequent inventory epoch边界；
assigned set任一增删改；full缺最小Cat；full replacement/partial upsert；commit响应丢失exact replay不续lease；
以及多Cat Operation任一失败使整份observation零副作用。DB clock回拨到retained Desired
`issued_at`之前时，Desired exact replay与first full均fatal/零写入；任一人为破坏的
`AdmissionInventoryState`中`cursor.issued_at <= accepted_at < cursor.expires_at`不成立时，planner必须
fatal/unready而不是candidate rejection。multi-terminal selector还必须覆盖：反向Store/SQL
枚举不改变选择；交换conditions顺序先被F0以`non_canonical_order`拒绝；删除首个
terminal才选中下一个；后续PlacementRejected binding错误仍在selector前使整份observation
零副作用，不能因它未被选中就隐藏invalid evidence。

error mapping验收必须让retained Desired request sequence为1、presented next为2且cursor尚in-progress时，
`desired_read_in_progress.request_sequence=2`，同时`read_position/expires_at`来自retained snapshot。full
inventory还必须覆盖没有Pending Operation（包括已有Succeeded/Failed Operation）的assigned Cat：null
`applied_desired`以及revision/digest/placement/target各自不等都返回最小Cat的
`assigned_runtime_binding_mismatch`并整份零写入；反向Store枚举不能改变error，完全匹配才允许建立attestation。

## 10. 最小 schema/cardinality 与验收

实现可以合并JSON与projection列，但必须表达以下bounded cardinality和唯一性：

| logical state | 唯一性 / 保留 |
|---|---|
| Desired read state | 每 Node 1；跨session high-water + 当前session最后response |
| Observation receive-state | 每 Node 1；当前session highest payload + exact success |
| Admission inventory state | 每 Node 1；当前attestation + full observation + assigned snapshot |
| Current per-Cat observation | 每 `(node_id, cat_id)` 1且每Node最多1024；full replace membership，partial只更新既有full member |

不得创建 per-heartbeat、per-read、per-attestation历史authority。若产品需要审计，只能把已commit outcome异步
输出到独立bounded audit sink；audit失败不回滚或补写domain state，也不能用于exact replay。

实现最小验收还包括：

- schema clean-create、projection corruption、server clock overflow、sequence/epoch/read-position耗尽都fail
  closed；
- 两个Control Plane副本各自都已取得本地cap并并发同一Node request，最多一个首次commit，另一方只能exact
  replay或closed conflict；不得增加fleet-wide semaphore/lease row；
- Node当前assigned set为1024时仍可签发/接受完整snapshot，A23同Node新增第1025项必须
  在plan与commit两层零Desired/Operation/API-result拒绝；任何故障注入已存在1025项时loader
  fatal/unready而不裁剪或返回ordinary candidate miss；
- observation与Cat-create、observation与policy apply各以两种先取得NodeIdentity的顺序做并发barrier
  test；后一方只能在锁后看到前一方新facts并commit或closed retry，不允许
  AgentSession/receive-state -> NodeIdentity逆序、deadlock或用锁前cache判定；
- 对shape/placement不变但target、route、volume intent、disk/disposition或require-idle变化的revision，分别与
  Cat-create及full observation做两个先提交方向；读取方只能看到完整old或new full Desired，writer发现
  pre-read affected node变化只能整笔fresh retry，不能先锁Desired再反取NodeIdentity；
- full接受事务的每一个write point做crash injection，恢复后只能看到全旧或全新；
- 一个合法credential用连续partial轮换新cat ID全部按最小ID closed error拒绝，row数始终不超过最近full
  的runtime集合；下一次full才可改变membership；
- Desired在scan期间变化时旧cursor full拒绝，next request sequence可签发新position；
- 使用真实PostgreSQL双connection保留Desired INSERT/full observation的双向竞态oracle：Desired
  mutation先取得`NodeIdentity FOR UPDATE`并提交时，携旧cursor的full随后返回
  `assigned_set_changed`且零写；full先取得该锁时，它在锁内对一个完整assigned set提交，
  INSERT只能在其后提交，之后任何planner/transition消费都以`assigned_set_changed`使旧
  attestation失效；两个方向都必须证明暂停点已命中，不得用未执行的race当通过；
- session replacement不重置read high-water，新session full epoch从1开始，旧session所有endpoint永久拒绝；
- planner和signer在同snapshot证明全部返回facts；attestation恰好60秒、per-Cat恰好30秒、session恰好deadline
  均视为过期；
- DB clock早于last Desired issued time时连Desired exact replay也必须fatal；新observation的DB clock早于
  last accepted time，或Operation settlement时早于Operation created/updated time，都必须整笔fatal零写入，
  不能写倒退server timestamp；
- legacy heartbeat/inventory row存在或更新时，A20结果完全不变；生产代码不得import legacy Node
  heartbeat/capacity DTO或查询其动态列。
- renewal-critical lane的正例先证明新sequence observation能更新deadline；随后饱和
  Runtime Volume Transition/ordinary Store worker与queue，新observation仍只使用保留worker/queue/
  connection并在10000 ms absolute deadline内提交或明确503。分别在保留queue等待、SQL已开始和
  commit边界取消/关机，必须证明后两者已rollback/connection-close并join，或commit不明后只由
  exact replay返回首次结果；handler结束后不得观察到detached续期/observation写入。
