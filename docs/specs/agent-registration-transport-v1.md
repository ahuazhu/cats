# Agent Registration and Internal Transport v1

- 状态：Frozen target contract；尚未实现
- Authority：[ADR-0040](../decisions/0040-level-triggered-runtime-reconciliation.md)
- 共享runtime类型：[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
- Session-bound delivery/acceptance：[Runtime Inventory and Observation Spine v1](runtime-inventory-observation-v1.md)

本文冻结Node Agent注册的唯一HTTP接口、所有runtime internal请求共用的per-Node machine
authentication adapter、注册错误映射、session lease policy，以及
`GuestRuntimeProfileReceipt`的唯一build/deployment/config路径。它不增加identity或session
authority：adapter只把请求证明转换成`AuthenticatedNodeCredential`，NodeIdentity和当前
AgentSession仍只由Control Store裁决。

Node本地`NodeIdentity` artifact、identity-selected state path，以及Control/Node共同消费的一次构建
Guest release payload由
[Runtime Composition Artifacts v1](runtime-composition-artifacts-v1.md)冻结；本文件的固定credential/
receipt paths和该composition合同必须同时满足。

本文中的MUST/MUST NOT是F3b及后续internal transport实现的上线条件。V1没有legacy
`/v1/nodes/register`兼容路由、shared service/admin bearer fallback、双写、协商、动态receipt catalog或
provider-principal fallback。

A19 wire和`AgentSession`有意不携带Node transport target。Gateway可达地址只来自A23
`NodePlacementPolicy.node_transport_target`的fleet/admin apply；Node registration、observation、来源IP、hostname
或legacy `nodes.agent_url`都不能自报、覆盖或补出该authority。

## 1. Authority boundary 与固定常量

| 项目 | V1唯一值 |
|---|---|
| internal path prefix | `/v1/internal/runtime` |
| registration route | `POST /v1/internal/runtime/agent-sessions` |
| request/response media type | `application/json`，无parameter |
| registration request cap | 16384 octets |
| registration success cap | 16384 octets |
| registration error cap | 20480 octets |
| session lease duration | 60000 ms |
| receipt release member | `guest-runtime-profile.v1.json` |
| receipt installed path | `/opt/cats/release/guest-runtime-profile.v1.json` |
| receipt config key | CLI `--guest-runtime-profile-receipt-file` / env `CATS_GUEST_RUNTIME_PROFILE_RECEIPT_FILE` |
| Node Guest kernel | `/opt/cats/guest/vmlinuz` |
| Node Guest initramfs | `/opt/cats/guest/initramfs.img` when receipt digest is nonnull; no VMM argument when null |
| Node private key | `/etc/cats/identity/node-registration-key.pem` |
| Node credential ID | `/etc/cats/identity/node-registration-credential-id` |

internal runtime handler、Store和Node不得读取`CATS_AUTH_TOKEN`、browser session、admin session、workspace
token或另一个service bearer。生产请求使用server-authenticated HTTPS和§4的per-Node签名；HTTP只允许显式
test adapter绑定loopback listener，不能由production配置降级。
注册之外，Desired/observation两条session-bound delivery route只由
[Runtime Inventory and Observation Spine §2](runtime-inventory-observation-v1.md#2-http-与-authentication-envelope)冻结；
卷状态转换的一条session-bound mutation route和一条authorization evidence read route只由
[Runtime Volume Transitions v1](runtime-volume-transitions-v1.md)冻结。本文的共用prefix/proof adapter不会自动
创建GET、long-poll、legacy heartbeat或任何未被这两个下位合同逐条冻结的可路由入口。

Node的`--control-plane-url`必须是`https://<authority>` origin：除根`/`外没有path，不含userinfo、query或
fragment；client在它后拼接本规格的exact path。TLS使用部署Host的reviewed WebPKI trust roots并验证URL DNS
hostname和certificate chain；不得接受invalid certificate、关闭hostname验证或跟随跨authority redirect。TLS
trust不证明Node identity，也不进入`AuthenticatedNodeCredential`。反向代理若终止TLS，proxy到handler的链路和
部署边界必须受同等保护，且不得生成、替换或删除§4 proof headers。

## 2. Registration HTTP wire

### 2.1 Request target 与headers

请求必须满足全部条件：

- method是`POST`；request-target path octets精确为
  `/v1/internal/runtime/agent-sessions`。尾随`/`、percent-encoded alias和其他path不匹配route。
- query必须不存在；空query marker `?`也拒绝。fragment不属于HTTP request-target且客户端不得发送。
- `Content-Type`必须恰有一个field value；去除可选HTTP OWS后按ASCII大小写不敏感比较必须等于
  `application/json`，不得带`charset`或其他parameter。签名输入始终使用小写literal
  `application/json`。
- `Content-Encoding`和`Authorization`必须不存在。不得自动decompress，也不得把proof转换成Bearer。
- §4的三个proof header都恰好出现一次。HTTP header name按协议大小写不敏感；重复line、comma-joined
  多值或代理合并后的多值都拒绝。
- body是exact `AgentRegistrationAttempt` UTF-8 JSON octets，最大16384 octets。chunked或已知
  `Content-Length`都可以，但handler必须只读取到16385 octets；宣称或实际超过上限都停止读取并返回
  §5的typed 413。`Content-Length`不可信，不能代替实际计数。

route dispatch的固定结果：exact path上的非`POST`方法返回405和`Allow: POST`；不匹配的path返回普通404，
不得被registration handler解释；exact path带任何query返回400。handler不存在redirect、trailing-slash
normalization或method override。

### 2.2 Success

新注册和exact attempt replay都返回：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Content-Encoding: <absent>

<canonical AgentSession JSON>
```

body是[Runtime Reconciliation v1 §2](runtime-reconciliation-v1.md#2-可信-node-与-agentsession)的完整
`AgentSession`，使用其§16.1 canonical encoder，总长不得超过16384 octets。新提交必须先在同一数据库事务
durable写入attempt result和current session，再发送body。exact replay逐byte重新编码首次提交的immutable
attempt result；不得返回后来续期的current deadline。

Node在发请求前必须按§6落盘exact attempt bytes和proof所需identity。收到200后先用F0 decoder验证
`AgentSession`，再验证除server分配epoch/deadline外全部field逐字段等于pending attempt，随后atomic persist并
fsync session。完成前不得发送session-bound请求、启动VMM或打开任何gate。EOF、timeout、连接重置、超限、
非JSON或无法验证的200都视为ambiguous result，只能重发同一pending attempt，不能猜测新epoch。client禁止
自动follow任何redirect。

## 3. Server processing order

同一请求只允许以下顺序；更早失败时不得执行后续阶段：

1. exact route/method/query与HTTP header admission；
2. bounded读取body。超过16384 octets产生固定F0 `limit_exceeded`，不进入proof或JSON解析；
3. §4 proof格式、Ed25519验证和`AuthenticatedNodeCredential`构造；
4. 对body运行F0 `AgentRegistrationAttempt` context-free decoder；
5. 把credential和typed attempt一起交给唯一Control Store registration transaction；
6. 把Store outcome按§5映射为唯一HTTP response。

proof未通过时不得解析body内容、查询NodeIdentity或暴露credential是否存在。通过proof不代表identity
eligible。Store只用credential ID定位candidate node ID，随后固定顺序是：(a) 先锁该`node_identities`
current row，再锁并join A23 `runtime_node_credential_lineage` exact ID/node/SPKI digest row；provisioned identity
要求它是唯一active row，retired identity只接受current binding对应的exact retired row，任一不等为identity
not eligible；(b) 查`(node_id, registration_attempt_id)`，exact attempt返回
immutable result，binding不同返回registration attempt conflict；(c) 对未命中attempt检查provisioned state与
`immutable_host_id`；(d) 检查approved guest config digest；(e) 锁current session并检查expected epoch，最后才
分配epoch/deadline和写入。adapter不得使用body中的`node_id`、`immutable_host_id`、hostname、IP或TLS client
address构造认证身份。retired identity只允许步骤(b)解析此前ambiguous exact attempt，不允许新attempt。

## 4. Per-Node request proof adapter

本节是全部`/v1/internal/runtime/*` endpoint共用的唯一V1 machine authentication adapter。registration、
Desired read和observation不得各自实现签名方言。

### 4.1 Header wire

| Header | exact value |
|---|---|
| `Cats-Node-Credential-Id` | 一个`Id`，1..=128 ASCII octets |
| `Cats-Node-Public-Key-Spki` | RFC 4648 base64url、无padding、无空白；decode后恰好44 octets |
| `Cats-Node-Signature` | RFC 4648 base64url、无padding、无空白；decode后恰好64 octets |

SPKI DER必须是唯一canonical Ed25519 SubjectPublicKeyInfo：hex prefix
`302a300506032b6570032100`后接32-byte public key。algorithm OID是1.3.101.112，parameters必须absent；不能接受
带NULL parameter、PEM文本、裸key、自定义DER等价编码或其他算法。所有base64url decoder必须拒绝`=`、标准
base64的`+`/`/`、非canonical尾部bits和任意额外byte。

### 4.2 Canonical signed request

定义：

```text
frame(x) = u64-big-endian(byte_length(x)) || x
body_digest = SHA-256(exact HTTP body octets)

signed_request =
  ASCII("cats.internal-runtime.request.v1") || 0x00
  || frame(uppercase_method_ascii)
  || frame(exact_path_octets)
  || frame(ASCII("application/json"))
  || frame(credential_id_ascii)
  || frame(exact_spki_der)
  || u64-big-endian(body_octet_length)
  || body_digest
```

`uppercase_method_ascii`是endpoint规定的uppercase literal（本endpoint为`POST`），不是调用方任意
normalization。`exact_path_octets`不含scheme、authority或query；所有V1 endpoint已禁止query。body length和
digest从bounded读取的raw octets计算，不能parse/re-encode JSON后再签。Ed25519按RFC 8032 pure mode对完整
`signed_request`签名；不得使用Ed25519ph、ECDSA、RSA、HMAC或二次hash整个`signed_request`。

签名不含timestamp或one-time nonce是有意的：网络结果不明时，客户端必须能重发exact durable attempt。
method/path/content-type/credential/key/body length/body digest阻止把proof移到其他operation、path、credential或
payload；TLS阻止跨连接窃取。服务器重放安全由各endpoint的domain idempotency键完成，proof本身不创建第二个
replay database。日志不得记录signature、private key或完整registration body。

### 4.3 Verification 与adapter output

验证器必须：

1. 在各endpoint body cap内计算exact body length/digest；
2. 严格decode三个headers和canonical SPKI；
3. 构造§4.2 bytes并用SPKI内Ed25519 key验证signature；
4. 计算普通`SHA-256(exact_spki_der)`并按`Sha256Digest`编码；
5. 只输出：

```text
AuthenticatedNodeCredential {
  credential_id: Cats-Node-Credential-Id,
  binding: {
    kind: "public_key",
    public_key_spki_sha256: SHA-256(exact_spki_der)
  }
}
```

`AuthenticatedNodeCredential`是进程内adapter value，不是新wire类型、session或bearer。Store把它与预置
`NodeIdentity.credential_id`和完整`credential_binding`exact比较；比较使用constant-time digest comparison。
同一合法proof因identity不存在、retired、Host/Node binding不等而失败时统一成为`identity_not_eligible`。

`CredentialBinding::ProviderPrincipal`不受这个V1 adapter支持。带该binding的identity调用本HTTP transport固定
`identity_not_eligible`；不得降级为header principal、cloud metadata声明或shared credential。将来增加provider
adapter必须先冻结新的独立proof和映射合同。

任何proof header missing/duplicate/格式错误、SPKI非canonical、signature invalid都返回相同
`authentication_failed`，不得指出具体阶段或credential是否存在。

### 4.4 Fixed proof vector

本向量使用RFC 8032 test key seed
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`；seed只用于测试，绝不能部署。

```text
credential_id = credential_a
public_key = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
spki_der = 302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
Cats-Node-Public-Key-Spki = MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo
public_key_spki_sha256 = sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9
```

exact 359-octet body是Runtime Reconciliation v1 §16.3的attempt vector：

```json
{"agent_instance_id":"44444444444444444444444444444444","expected_agent_session_epoch":null,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","immutable_host_id":"host_a","node_boot_id":"33333333333333333333333333333333","node_id":"node_a","registration_attempt_id":"55555555555555555555555555555555","version":1}
```

```text
body_sha256 = 28ddcfcd78cb15238b011f68e35ef844a3195584b592741729fe8a5e27ce38a5
signed_request_length = 224
signed_request_sha256 = b1a4024e454c47966e45707d64fd3f1dd6712dec69b1d2e20b7bfeb4bb4f5e38
Cats-Node-Signature = X0xnGNt7Yux9_i9-T4LaBjP-E0KXsjGmOuGtJ2-ATmYLivVTILs2kD4_mWScT1YNyS1GGjw9_b_rJxmPoziuBg
```

验收必须独立重建bytes、验证positive vector，并至少证明method、path、content-type、credential ID、SPKI、body
length和body任一byte变化都使原signature失败。

## 5. Registration error wire 与status mapping

### 5.1 Envelope

registration handler的非2xx body使用endpoint-local类型，不扩充F0共享`ContractErrorDetail`：

```text
AgentRegistrationError {
  version: 1,
  error: AgentRegistrationErrorDetail,
  message: string 0..=1024 UTF-8 bytes
}

AgentRegistrationErrorDetail =
  { code: "authentication_failed" }
| { code: "identity_not_eligible" }
| {
    code: "session_epoch_mismatch",
    current_agent_session_epoch: Epoch | null,
    presented_expected_agent_session_epoch: Epoch | null
  }
| {
    code: "http_request_rejected",
    problem: "method_not_allowed" | "query_not_allowed"
           | "content_type_not_allowed" | "content_encoding_not_allowed"
           | "authorization_not_allowed"
  }
| { code: "contract_error", contract_error: ContractError }
| { code: "temporarily_unavailable" }
| { code: "internal" }
```

所有字段必填、拒绝unknown/duplicate，union使用`code`，integer/string规则继承Runtime Reconciliation v1
§1/§16.4。body用§16.1 canonical JSON，总长最多20480 octets。每个error response都设置
`Content-Type: application/json`、`Cache-Control: no-store`且无`Content-Encoding`。`message`只供人读，client
只能按typed `error`分支；server必须在cap内使用不含credential存在性、key、signature、SQL或内部路径的消息。

`authentication_failed`额外设置：

```http
WWW-Authenticate: CatsNodeSignature realm="runtime-registration"
```

### 5.2 Exact mapping

| condition / Store outcome | HTTP | detail |
|---|---:|---|
| proof missing、duplicate、malformed或invalid | 401 | `authentication_failed` |
| credential identity不存在，或credential binding/`attempt.node_id`不等（含provider-binding identity）；未命中attempt时identity retired或`immutable_host_id`不等 | 403 | `identity_not_eligible` |
| `expected_agent_session_epoch`不等当前（含一边null） | 409 | `session_epoch_mismatch`，两个nullable epoch逐字段来自Store outcome与attempt |
| exact path但method不是POST | 405 | `http_request_rejected {problem:"method_not_allowed"}`并设置`Allow: POST` |
| query存在 | 400 | `http_request_rejected {problem:"query_not_allowed"}` |
| Content-Type absent、duplicate、有parameter或不是JSON | 415 | `http_request_rejected {problem:"content_type_not_allowed"}` |
| Content-Encoding存在 | 415 | `http_request_rejected {problem:"content_encoding_not_allowed"}` |
| Authorization存在 | 400 | `http_request_rejected {problem:"authorization_not_allowed"}` |
| F0 `limit_exceeded {limit:"wire_bytes"}` | 413 | `contract_error`嵌入原`ContractError` |
| F0 `malformed_payload`或`unsupported_version` | 400 | `contract_error`嵌入原`ContractError` |
| Store `registration_attempt_conflict` | 409 | `contract_error`嵌入原`ContractError` |
| Store `guest_config_mismatch` | 412 | `contract_error`嵌入原`ContractError` |
| bounded DB pool/transaction临时不可用 | 503 | `temporarily_unavailable`，可带`Retry-After` |
| 未分类server invariant failure | 500 | `internal` |

同stage多个HTTP header错误按表格从method、query、Content-Type、Content-Encoding、Authorization的顺序选择；
body cap优先于proof，proof优先于F0 decode。registration Store在该边界可返回的`ContractError` closed set只有
`registration_attempt_conflict`和`guest_config_mismatch`；出现其他detail表示server wiring/invariant bug，
必须fail closed为500 `internal`，不得随意选一个4xx。

Store错误优先级严格使用§3的(a)到(e)，而不是本表行顺序：基础credential/Node binding先于attempt lookup；
lookup命中后exact replay或attempt conflict先于retired/Host/release/epoch；未命中后identity eligibility先于
guest config，guest config先于session epoch。这样同一输入不能因adapter或SQL查询顺序不同返回两种public error。

`identity_not_eligible`和`session_epoch_mismatch`是明确closed错误：两者都不创建attempt/session、不分配epoch、
不续期、不改变current row，也不得触发Node runtime动作。client收到403必须停止注册并等待重新provision；收到
409只能先durable记录returned current epoch，再以新的`registration_attempt_id`和exact expected epoch发起
replacement。409 body不是session，不能直接授权任何请求。

valid 500、503 typed response和ambiguous transport failure只允许重试同一durable attempt；客户端使用bounded
exponential backoff和jitter。任何valid closed 4xx typed response都按上文语义fail closed，不自动无限重试。
普通404没有registration error envelope且是确定的route/deployment配置错误，client保留pending并停止自动重试。

除valid 200、status与detail匹配的valid closed typed error、以及上述plain 404之外，所有response都是ambiguous：
包括HTML/plain 502/504、unexpected 2xx/3xx/4xx/5xx、redirect、错误status上的typed detail、missing/错误/重复
Content-Type、任何Content-Encoding、超20480-octet error body、超16384-octet success body、malformed/unknown
error和无法验证的session。client必须保留exact pending bytes/ID、保持所有runtime gate Closed、告警并只以原
attempt重试；不得因代理替换了Control commit后的response而删除pending或创建新attempt。

## 6. Node credential 与registration durability

provisioner为每个Node生成独立Ed25519 key。private key以PKCS#8 PEM安装到
`/etc/cats/identity/node-registration-key.pem`，owner `root:root`、mode `0600`；不得出现在release bundle、
Terraform state/output、environment、argv或日志。credential ID文件owner `root:root`、mode `0600`，内容是一个
合法`Id` ASCII后恰好一个LF；parser只移除这一个LF，拒绝其他前后空白、多行或额外bytes。provisioner把
credential ID和canonical SPKI DER digest预先写入唯一NodeIdentity。
初始provision和rotation只允许`CredentialBinding::PublicKey`；credential ID和SPKI digest的Control
Store all-history唯一、active/retired lineage DDL与不可reverse-CAS规则由
[Runtime Placement Policy §3.4](runtime-placement-policy-v1.md#34-apply-replay事务与取消)冻结。A19
proof adapter不会为`ProviderPrincipal`或已rotation移出current NodeIdentity的历史key建立fallback。
最终retire仍保留exact current binding时，只保留本规格已冻结的retired identity exact-attempt replay；
这不是new attempt、eligibility、rotation回滚或credential重用。

所有A19-authenticated internal route把proof得到的exact credential ID/SPKI digest传入业务transaction；该
transaction在`NodeIdentity` lock后必须按上述join重验current active lineage并持有lineage share lock到commit。
只有retired identity的步骤(b) exact immutable registration-attempt replay使用exact retired lineage；其他
retired/history row一律不能认证。`node_identities` current credential与lineage的deferred composite FK、
all-history唯一和rotation/retire原子边界由A23 §3.4冻结。

Node不得从`--node-id`、hostname/IP或provider metadata补出该NodeIdentity。production local artifact、
filesystem校验、initial no-replace provision、credential rotation和retire/Host replacement规则以
[Composition §2](runtime-composition-artifacts-v1.md#2-local-nodeidentity-artifact)为唯一权威。

key轮换前必须证明没有pending attempt并保持Node cordoned；随后先staged安装新private key，再以显式管理事务
替换同一NodeIdentity的credential ID/binding，最后atomic激活对应key。切换窗口不会同时接受两把key；失败必须
保持Node cordoned，不能用fleet credential解锁或丢弃pending attempt。

取得[Runtime Reconciliation v1 §2](runtime-reconciliation-v1.md#2-可信-node-与-agentsession)规定的Host
lock后，Node在其受保护state path使用固定相对路径：

```text
agent-registration/pending-attempt.json
agent-registration/session.json
```

pending文件保存要发送的exact canonical attempt bytes；每次创建先写同目录temporary file、fsync file、rename、
fsync parent。进程启动若存在pending，必须先用相同credential/key和§4算法重新签名并重试它；signature本身不需
落盘。200 session以相同步骤持久化后才能删除pending，并再次fsync parent。crash发生在任意rename/fsync/response
窗口都收敛到重试同一attempt或使用已验证session，不能生成第二attempt来猜测结果。session只保存server结果，
不是Bearer；每个后续internal request仍必须带新的body-bound §4 signature并由Store检查current session fields。

## 7. AgentSession lease policy

V1 lease duration是server constant 60000 ms；没有request field、environment override、Node override或按release
协商。Control Plane只使用PostgreSQL transaction time，不使用Node时间或应用进程wall clock。

- 首次或replacement注册提交时，immutable attempt result的
  `lease_deadline_unix_ms = db_now_unix_ms + 60000`，溢出fail closed。
- live判断唯一为`db_now_unix_ms < current_session.lease_deadline_unix_ms`；相等已经expired。
- exact registration attempt replay返回首次提交的immutable `AgentSession` exact bytes，包括initial deadline；即使
  identity后来retired、current deadline已续期或已过期，也只解析该attempt的模糊结果，不恢复eligibility或续期。
- 新attempt只有在exact `expected_agent_session_epoch` CAS成功时分配下一epoch和新的initial deadline。
- 唯一续期点是同一current session的**新**`heartbeat_sequence` observation在一个Control Store transaction
  完整验证并接受时：用同一`db_now`令current deadline单调更新为
  `max(old_deadline, db_now + 60000)`，并在该accept response返回current `SessionBinding`与更新后的
  `lease_deadline_unix_ms`；不返回或改写immutable registration result。
- exact observation replay、stale/conflict/invalid observation、Desired read、registration replay、失败请求和仅有
  网络连接都不得续期。

immutable attempt result与current session除`lease_deadline_unix_ms`外的全部`AgentSession`字段（包括
`version`和`registration_attempt_id`）必须逐字段相等；current deadline可以且只能因上一条规则大于等于initial
deadline。任一非deadline字段不等或current deadline小于initial是fatal Store corruption，当前session
unready且事务零写入。实现不得要求两个deadline永远相等。

expired session不能签发或exact replay `DesiredReadSnapshot`、首次接受新observation/attestation、参与
placement/admission或打开route gate；这些边界必须用同一PG-now重验current exact session和deadline。唯一例外
是current session对highest
accepted `heartbeat_sequence`及其exact observation的重放：deadline后仍返回首次success，零写入且不续期，只用于
解析此前commit的response loss。expiry是Control liveness gate，不替代HostFence、attachment epoch或route
epoch，不能仅凭expiry宣称旧Host/volume writer已经被fence。

上述续期点、expired Desired拒绝和deadline后highest exact observation例外的唯一结果映射、
事务顺序及response wire见
[Runtime Inventory and Observation Spine §3–§6](runtime-inventory-observation-v1.md#3-desired-read-position)；
本节不定义第二个observation接受或lease-renewal路径。

## 8. GuestRuntimeProfileReceipt release path

### 8.1 One build output, exact bytes

release build从最终要部署的pinned Guest kernel完整bytes、可选initramfs完整bytes、唯一exact VMM kernel cmdline和
compiled Guest Agent protocol literal生成一次
`guest-runtime-profile.v1.json`。生成器必须使用Runtime Reconciliation v1 §16.1 canonical encoder，无BOM、前后
空白或结尾LF，最大4096 octets；随后用该规格§2的domain计算`guest_config_digest`。

“生成一次”的process composition、closed manifest/layout、immutable release identity、Control/worker
artifact exact-copy qualification和Node crash-safe install/rollback由
[Composition §3](runtime-composition-artifacts-v1.md#3-one-shared-guest-runtime-release-payload)冻结。

同一个exact receipt member必须逐byte进入Control release artifact、Node/worker release bundle和release
manifest。manifest记录receipt本身的普通SHA-256和guest kernel/initramfs artifact digest；构建资格检查要extract
两边member并证明bytes和manifest digest一致。Control或Node独立重建“等价JSON”不合格。

Runtime Reconciliation v1 §16.3 fixed receipt的普通artifact hash必须为
`sha256:dae6f9b08706e17d03cbeece8141fef960185fe0758f80f999f9f2218d43e10a`，domain-separated
`guest_config_digest`必须为该节冻结的
`sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2`；两者不能互换。

生产Control与Node按唯一三态解析receipt config：(1) CLI
`--guest-runtime-profile-receipt-file`存在时只选择并校验CLI，env不参与；(2) 否则选择env
`CATS_GUEST_RUNTIME_PROFILE_RECEIPT_FILE`；(3) 两者都缺失时startup fail closed。selected value必须逐byte等于
`/opt/cats/release/guest-runtime-profile.v1.json`，否则startup fail closed。因此CLI exact加env alternate接受CLI，
CLI alternate加env exact仍拒绝。production Node systemd和Metal Control systemd固定传exact `ExecStart`
argument，AWS Control Kubernetes container固定传相同argument：
`--guest-runtime-profile-receipt-file /opt/cats/release/guest-runtime-profile.v1.json`，不得依赖程序default或
EnvironmentFile。测试temp receipt只能通过production CLI/env不可达的显式test-only reader/constructor注入；
production binary不能接受任意temp path。没有inline JSON、fixture fallback、catalog lookup、DB row或hot reload。

### 8.2 Install/startup fail closed

部署器把receipt与它声明的pinned kernel/initramfs作为同一staged release验证，安装receipt为
`root:root 0644`到exact path，使用same-filesystem atomic rename并fsync file和parent后才切换服务。Node release
把kernel安装到`/opt/cats/guest/vmlinuz`；nonnull initramfs安装到`/opt/cats/guest/initramfs.img`，null时VMM
launch完全不传`--ch-initramfs`。不得在Host上从当前内核临时重建Guest kernel/initramfs，也不得把image alias
当作digest。升级非空Node必须先
cordon/drain；receipt、Guest boot files、Node binary未一起就绪时不得restart或注册。

Control startup必须在打开internal listener前：bounded读取exact path，运行F0
`GuestRuntimeProfileReceipt` decoder（其中包括canonical exact-byte检查），重算domain digest并固定为该进程唯一
approved digest。missing、symlink/非regular file、owner/mode不符、超限、decode失败或receipt read在启动期间
发生变化都拒绝启动。release qualification另外逐byte检查Control/Node artifact双方member
与manifest记录相等。

Node startup必须在注册前执行相同receipt检查，并额外：

- 重算实际配置给VMM的kernel完整文件bytes SHA-256并逐字段相等；
- `initramfs_digest:null`时证明launch完全不配置initramfs；非null时重算实际文件并相等；
- launch使用的cmdline exact printable ASCII bytes逐byte等于receipt，不trim、分词或追加；
- binary内Guest Agent protocol literal逐字段等于receipt；
- 本地重算的`guest_config_digest`是每个attempt携带的唯一值。

任一missing/mismatch都使Node保持cordoned、所有route/volume/runtime gate Closed，拒绝注册和创建VMM。Control
Store仍逐attempt检查其digest等于本进程approved digest；Node本地成功不能越过server检查。

当前AWS worker bundle若不携带Host kernel/initramfs并在Host用当前kernel派生Guest boot artifact，不能满足本
合同。F3b可部署release必须先让同一release pipeline分发pinned Guest kernel、可选initramfs与exact receipt；
禁止以Host rebuild、缺失receipt、旧`--ch-kernel`默认或fixture digest作为兼容路径。

## 9. Minimal acceptance matrix

| boundary | required oracle |
|---|---|
| route | exact POST成功；wrong method 405；query 400；trailing slash/encoded alias 404；无redirect |
| media/body | absent/parameterized/duplicate Content-Type为415；Content-Encoding为415；16384进入F0，16385为typed 413；chunked实际计数 |
| proof | fixed vector成功；三个header各自missing/duplicate/malformed及signature mutation都同一401；body未认证时不decode/查Store |
| credential mapping | SPKI digest映射exact；不存在/credential/Node mismatch与provider binding都403；未命中committed attempt的retired identity或new attempt Host mismatch为403且零写入 |
| replay | response-loss后同pending attempt返回同epoch和initial deadline；retire后exact committed attempt仍200 original而new attempt为403；binding任一字段变化为typed 409 conflict；不同path/body不可复用signature |
| epoch | null首次、exact replacement和null/non-null mismatch；`session_epoch_mismatch` 409不分配epoch/row |
| lease | PG-now +60000；deadline等于now已过期；只有新sequence accepted observation续期；replay/read/error均不续期；current deadline可大于attempt initial；registration_attempt_id/任一非deadline字段不等或deadline回退为fatal unready/零写入 |
| receipt | Control/Node/bundle extract exact bytes相等；fixed digest；kernel/initramfs/nullability/cmdline/protocol任一变化fail closed；missing/noncanonical/fixture fallback拒绝启动 |
| crash | pending/session每个write/rename/fsync/response window注入crash，恢复只重试same attempt；成功前无session-bound副作用 |
| response substitution | Control commit后把response替换为HTML 502/504、unexpected status、redirect、malformed或oversize body；pending exact bytes/ID不变，只重试same attempt且无runtime副作用 |
| production receipt config | CLI/env都缺失失败；CLI exact+env alternate取CLI成功；CLI alternate+env exact失败；只env exact成功；任意selected alternate path失败；只有test-only constructor可注入temp receipt |
| legacy negative | production route table无`/v1/nodes/register`；internal handler不读取shared service/admin bearer |
