# Runtime Volume Transitions v1

- 状态：Frozen target contract；尚未实现
- 上位决策：[ADR-0040](../decisions/0040-level-triggered-runtime-reconciliation.md)、[ADR-0042](../decisions/0042-volume-authority-and-disk-lifecycle.md)
- 共享runtime类型：[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
- session/authentication：[Agent Registration and Internal Transport v1](agent-registration-transport-v1.md)
- inventory/accepted facts：[Runtime Inventory and Observation Spine v1](runtime-inventory-observation-v1.md)
- 卷状态机：[Volume Authority](volume-authority.md)

本文冻结当前Node把已经fsync到`RuntimeCheckpoint`的三类卷状态转换交给唯一Control PostgreSQL事务的
最小internal HTTP边界：normal/takeover acquire、exact release、以及消费已经由Control建立的
disposable Root delete authorization。它不建立通用effect workflow、command queue、transport receipt、
第二份grant ledger或新的volume state。

blockd继续只通过`VolumeDataAuthority`读取`VolumeRecord`、renew exact owner/epoch和CAS exact head；它不能
acquire、release、takeover或delete。Control内部的authorization derive、normal begin-delete、sweeper、
same-disk restore、snapshot与HostFence/Rejoin也不暴露在本文route。Node不能直接调用Control Store的pure
single-row acquire/release helper，因为那会跳过current AgentSession、fresh complete inventory、current
Desired、Disk和delete分支的同事务校验。

本文中的MUST/MUST NOT是production per-Cat reconciler启用卷effect前的上线条件。V1没有legacy
MetadataStore acquire/revoke RPC、shared bearer fallback、query参数、batch、多卷transaction、异步job或
兼容route。

## 1. 唯一route、caps与共享HTTP admission

唯一route是：

```text
POST /v1/internal/runtime/volume-transitions
```

V1常量：

| 项目 | exact value |
|---|---:|
| request wire cap | 16384 octets |
| success wire cap | 16384 octets |
| error wire cap | 20480 octets |
| 每replica独立global in-flight cap | 64 |
| 每replica、每个authenticated Node独立in-flight cap | 1 |
| handler absolute deadline | 10000 ms |

这条mutation lane与A20 Desired/observation lane分别计数，不能占用或等待A20的per-Node permit；但
独立HTTP semaphore仍不足以保护唯一session续期点。A22的handler、Store closure、blocking worker、
queue和PostgreSQL connection都不得进入、借用或占用
[A20的renewal-critical Store lane](runtime-inventory-observation-v1.md#2-http-与-authentication-envelope)。A22只使用
ordinary bounded Store execution capacity；其饱和必须返回503，不得等待保留lane或把volume工作
伪装成observation。这些lane都不是authority，不进入schema，也不能代替PostgreSQL锁。
部署可把A22 global cap调小或deadline调短，但不能扩大cap、增加等待队列或改变wire/domain replay语义。

route逐byte遵守A19/A20 internal HTTP合同：

- exact path、uppercase `POST`，没有query（包括空`?`）、trailing slash、percent alias、redirect或method
  override；
- `Content-Type`恰一个、去HTTP OWS后ASCII case-insensitive等于`application/json`且无parameter；签名frame
  仍使用lowercase literal；
- `Content-Encoding`和`Authorization`不存在；`Accept`不存在或恰一个无parameter的
  `application/json`；`Idempotency-Key`、`If-Match`、`If-None-Match`、Cookie和
  `X-HTTP-Method-Override`必须不存在，任一出现都是`semantic_header_not_allowed`；domain
  transition ID是唯一replay identity；
- bounded reader最多读取16385 octets，cap在proof和JSON前执行；不解压、不trim、不先信
  `Content-Length`；
- exact path上的wrong method为405并带`Allow: POST`，query为400，未匹配path为普通404且没有本文error
  envelope；
- 成功固定`200 application/json`，全部success/error设置`Cache-Control: no-store`，没有
  `Content-Encoding`；除合法framing header外没有会改变语义但未进入body的response header。

每个请求复用A19 §4三个proof header和唯一Ed25519算法。签名的method/path/content-type/credential/SPKI/raw
body length与digest全部按A19 frame；proof只能产出`AuthenticatedNodeCredential`，不能按body Node、TLS
address、hostname、IMDS或shared token构造身份。

固定处理顺序是：path -> method -> query -> media/semantic headers -> 独立global admission -> bounded body
-> A19 proof -> F0 decoder -> 唯一provisioned exact-binding NodeIdentity -> 独立per-Node admission ->
§4唯一transaction。更早失败不得读取后续事实。handler deadline从完整headers到达开始；commit前到期必须
rollback，commit结果不明就关闭response。deadline内最多3次完整serialization/deadlock retry，每次从
immutable decoded request重新读取全部PG事实。

## 2. Closed request与success wire

所有类型使用Runtime §1.1/§16.1的基础类型、strict decoder、canonical encoder和error selection。
三个顶层decoder在Runtime `ContractName` closed set中的exact名字分别是
`runtime_volume_transition_request`、`runtime_volume_transition_success`和
`runtime_volume_transition_error`；它们不复用或伪装成Desired/observation合同。

```text
RuntimeVolumeTransitionRequest {
  version: 1,
  session: SessionBinding,
  cat_id: Id,
  desired_revision: Revision,
  spec_digest: Sha256Digest,
  placement: AssignedPlacement,
  transition: RuntimeVolumeTransition
}

RuntimeVolumeTransition =
  { kind: "acquire", request: VolumeAcquireRequest }
| { kind: "release", cleanup: CleanupRelease }
| { kind: "delete_disposable_root", authorization_id: Id }
```

`VolumeAcquireRequest`、`CleanupRelease`和所有嵌套类型逐字段复用Runtime §10.1，不定义transport副本。
Intrinsic规则固定为：

1. `session.node_id == placement.node_id`；
2. `transition.kind="acquire"`且request为normal时，request的`desired_revision`和`placement_epoch`分别等于
   顶层revision和placement epoch；takeover只携authorization ID；
3. release只接受`cleanup.target.kind="volume"`且`cleanup.volume_release != null`，并要求
   `cleanup.inventory_session == session`；其他Cleanup target绝不能借本route产生Control mutation；
4. delete只携authorization ID，不允许客户端展开、覆盖或签名服务器端authorization payload；
5. 顶层Cat/revision/digest/placement是这次current-context compare，不是transition receipt。session
   replacement或fresh replan后必须先按Runtime规则重写并fsync完整checkpoint；只有release允许保留同一
   `release_transition_id`并重绑新的inventory/tombstone evidence，normal acquire与两类authorization不得把
   原ID移植到不匹配的新revision/placement。

成功body：

```text
RuntimeVolumeTransitionSuccess {
  version: 1,
  session: SessionBinding,
  cat_id: Id,
  desired_revision: Revision,
  spec_digest: Sha256Digest,
  placement: AssignedPlacement,
  outcome: RuntimeVolumeTransitionOutcome
}

RuntimeVolumeTransitionOutcome =
  { kind: "lease_granted", grant: VolumeLeaseGrant }
| { kind: "released", release: ReleaseResult }
| {
    kind: "disposable_root_deleting",
    receipt: BeginDisposableDeleteConsumedReceipt
  }

VolumeLeaseGrant {
  volume_id: Id,
  attachment_id: Id,
  attachment_epoch: FenceEpoch,
  size_bytes: integer 1..=9223372036854775807,
  durability: "strict" | "relaxed",
  head: RemoteHead,
  lease_expires_at: UnixMillis,
  acquire_origin: AcquireOrigin
}
```

normal result的`acquire_origin={kind:"normal",transition_id}`；takeover为
`{kind:"takeover",authorization_id}`。首次grant的size/durability/head/owner epoch/absolute expiry全部从同一事务
锁定并更新后的`VolumeRecord`逐字段构造，不能从Desired复制后不比较。exact replay则从
`last_transition.normal_acquire` request/result或immutable authorization receipt重建首次grant；它不用后续
renew/head-CAS已变化的current expiry/head改写旧结果。`ReleaseResult`和
`BeginDisposableDeleteConsumedReceipt`逐字段复用Volume Authority的closed类型；它们不是新row。

success顶层context逐字段回显transaction已经验证的request context。Node必须先用F0 decoder验证body，再
比较session/Cat/revision/digest/placement与当前attempt，并且把outcome逐字段绑回已fsync的step：

- acquire只接受`lease_granted`；grant volume/attachment等于request，size/durability等于current intent，
  normal origin/transition ID精确且`attachment_epoch = checked_add(expected_unowned_epoch,1)`，takeover
  origin/authorization ID精确；
- release只接受`released`；result volume/transition/released attachment等于从cleanup导出的request，
  `resulting_epoch = checked_add(target.attachment_epoch,1)`，resulting head逐字段等于锁定的current Volume和
  accepted full authority head，其generation等于cleanup generation；
- delete只接受`disposable_root_deleting`；receipt authorization/Cat/Disk/volume/delete/prior attachment、
  resulting epoch/head必须与current authorization、Desired和accepted full physical evidence精确匹配。

旧response晚到新session/revision/step，上述任一字段不等，或checked-add无合法后继时，整个success都是
ambiguous/mismatched；Node保留step并按§3读权威行，不能启动blockd、删lineage或推进新checkpoint。
服务器不保存整个HTTP success；domain的`last_transition`或immutable authorization receipt已经是唯一
replay authority，HTTP只从它和当前context确定性重编码。

## 3. Replay与ambiguous result

Node在发送前必须已经按Runtime checkpoint合同fsync完整`VolumeAcquireRequest`、`CleanupRelease`或
authorization ID。proof signature可以每次重新计算，但body在同一context retry时逐byte相同。

- normal acquire/release用各自`transition_id`和完整request做domain replay；同ID异payload固定
  `stale_transition`，不得生成新ID掩盖冲突；
- takeover/disposable delete只用服务器端immutable authorization ID/payload/receipt。相同ID首次消费只发生
  一次；重试只读receipt，客户端永远不提交payload；
- HTTP EOF、timeout、reset、invalid/oversize/mismatched success、普通proxy 502/504和deadline-after-commit
  都是ambiguous。Node保留同一step；同context重发exact request。context变化不能做通用“只换wrapper”：
  normal acquire的nested revision/placement和takeover/disposable authorization都绑定原current Desired，失配即
  stale/replan，不能把旧effect移植给新revision；release则按Runtime §10允许在新session/full scan后重新持久化
  完整`CleanupRelease`，只替换inventory session/epoch/read positions与tombstone read position，必须保留
  target、`release_transition_id`、generation和disposition，因此导出的`ReleaseRequest`逐字段不变；
- normal acquire/release的模糊结果可使用已部署的
  `VolumeDataAuthority.load_volume(volume_id)`解析：normal acquire只接受完整matching
  `last_transition.normal_acquire`和current owner/epoch，release只接受完整matching
  `last_transition.release`、Unowned、exact head/epoch。这不为blockd增加方法；
- takeover/disposable的模糊结果只使用
  [Volume Authority §5.1](volume-authority.md#51-node-only-transition-recovery-read-port)的provider-neutral、
  Node-reconciler-only `RuntimeTransitionRecoveryReader`。它外部只接受authorization ID，并在
  一个consistent read-only snapshot返回原exact AuthorizationRecord、由其volume派生的current
  Volume/null、DeleteCompletionReceipt/null，以及只由current marker或disposable completion直接引用的
  最多一个associated AuthorizationRecord。Node只按原authorization receipt和current direct marker，或现在
  epoch/head单调且closed marker/receipt完整的合法后继确认首次commit；不枚举授权历史、
  不复制transition chain或接受opaque success bool。暂时读不到或原authorization缺失时Blocked；
  exact Unconsumed + matching predecessor只允许重放厚authorization，Consumed却无法闭合则Blocked/
  Quarantined，两者都不猜成功；
- 本文不增加HTTP read route。`RuntimeTransitionRecoveryReader`与blockd的
  `VolumeDataAuthority`是两个独立port/object graph，只有前者可见authorization/completion、且两者都没有
  ownership transition。PostgreSQL adapter当前使用的精确Node只读权限和未来签名read替换规则
  以Volume Authority §5.1为唯一权威；
- current Desired已supersede/GC时，transition HTTP可以拒绝旧context，即使domain conversion已经commit。
  Node仍按上面的authoritative row/receipt和Runtime stale cleanup规则adopt；HTTP response不是唯一恢复证据。

expired session没有domain replay例外：它既不能首次执行也不能经本route重放已提交transition。A19允许的
deadline后highest exact observation replay不扩展到本文。replacement session必须先完成A20 full inventory和
current Desired read，才可以在current context下解析相同domain transition。

client只把status/detail相互匹配的closed typed error当作确定response。valid 401/403使Node保留
checkpoint并cordon等待credential/identity修复；valid 400/405/406/413/415是本地wire或部署合同错误，
停止该step自动重试并告警；valid 409重读Desired/full inventory/Volume并按typed detail重规划；valid
429/500/503只以同一durable request做有界backoff retry。plain 404是确定的route/deployment mismatch，保留
checkpoint并停止自动重试。带Node/Cat/volume/authorization/session/revision字段的error detail还必须与
本次request和当前checkpoint精确相等；不同identity的语法合法error不得驱动本step。除valid 200、
上述valid closed error和plain 404外，任何response都是
ambiguous：包括redirect、unexpected status、HTML/plain proxy body、status/detail不匹配、missing/错误/重复
Content-Type、任何Content-Encoding、超cap、malformed/unknown body或无法验证的success。它们都不得
清checkpoint、换domain ID或推进后续物理步骤。

## 4. 唯一PostgreSQL transaction owner

### 4.1 共同前缀与锁序

每个request使用一个Control PostgreSQL `READ COMMITTED` mutation transaction。固定锁DAG是：

```text
authenticated NodeIdentity
-> current AgentSession
-> observation receive-state / AdmissionInventoryState
-> HostFenceEvent（authorization需要时）
-> AuthorizationRecord（authorization需要时）
-> VolumeRecord
-> DiskRecord / Cat / current Desired / current Operation
-> DiskSnapshotRecord / immutable accepted observation
```

同类多row按稳定ID排序。取得NodeIdentity协调锁后，transaction可以无行锁读取它保护的current
Desired以及authorization/cleanup routing hint，先证明request携带的Cat、volume、authorization和当前intent
属于同一context；任何authenticated Node都不能用不受信的ID让Control取得另一Cat/volume/event/
authorization的锁。这个routing read不是authority result，不用于提交；取得上述固定顺序的row锁后
必须从closed row重新decode和逐字段验证。在session/revision/digest/placement通过前不得decode、比较
Volume行、按其存在性分支或渲染后stage error。

NodeIdentity行同时是A20 assigned-set mutation coordination lock。所有会插入、supersede、移动或删除该Node
current Desired的transaction，都必须先取得同一NodeIdentity锁并在锁内重验candidate/current session；因此
full attestation和新的Desired INSERT不存在phantom窗口。Desired mutation先提交时，携旧cursor的
full/transition必须观察新assigned set并拒绝；full先提交时，INSERT只能随后提交，此后该
attestation立即因assigned-set changed不可消费。本文transaction取得它后，current assigned
完整Desired集合必须仍逐字段等于fresh AdmissionInventoryState cursor snapshot。

共同context validation按Runtime §16.4.3执行：authenticated identity -> current exact session ->
current session的`guest_config_digest`逐字段等于Control启动时从A19 exact receipt批准的active release digest ->
`db_now < lease_deadline` -> current session的complete admission attestation存在，并满足
`accepted_at <= db_now < checked_add(accepted_at,60000)`（等于上界即stale）-> assigned
set仍相同 -> revision -> stored/context digest -> placement。wrapper的Cat必须恰有一份current完整Desired，
placement Node必须等于authenticated Node。任何stored JSON/projection/receipt自相矛盾、future time、checked
time overflow或current Desired引用缺失/错Workspace Disk/Volume都是fatal `internal`，不是可重试的普通
precondition。

一个transaction只读一次PG `db_now`。它不访问filesystem、Node、Guest、provider、object store或blockd，
也不接受`inventory_ok`、`stopped`、`r_equals_l`、`authorized`等boolean。所有跨row事实来自锁定的current
Control rows和A20 accepted observation。无论首次成功、exact domain replay还是任何失败，本route都不更新
AgentSession deadline或observation sequence；A19冻结的唯一续期点仍是A20首次接受的new-sequence observation。

### 4.2 Acquire

normal acquire要求：

1. current Desired target不是Deleted，并且恰有一个VolumeIntent的volume/attachment/acquire
   transition/expected epoch、size/durability与request、Disk和Volume逐字段相同；
2. current fresh complete inventory覆盖该Cat，applied Desired exact，且不存在会使同attachment出现两个
   active lineage/writer的conflicting physical evidence；missing/unknown/corrupt lineage不能降级为empty；
3. `VolumeRecord`仍为Active + Unowned且epoch等于request，随后调用Volume Authority pure
   `normal_acquire`并在同一commit写回；
4. exact replay仍先通过本节current session/admission/Desired checks，随后从same transition marker返回原
   absolute expiry，不重读时钟或增加epoch。

takeover要求current Desired同样不是Deleted，唯一intent的acquire exact引用authorization，且服务器端
authorization的new attachment/revision/placement/volume与current intent/context逐字段相同。首次消费继续遵守
`HostFenceEvent -> Authorization -> Volume`，event Active、not-after、旧owner/epoch和duration都在同一
transaction验证并写receipt。已消费exact replay不要求event仍Active，但仍要求本文current Node/session/
admission/Desired context；它只读immutable receipt并重建grant。

acquire success后只取得lease grant；Node仍须把grant fsync进checkpoint，随后以同一只读authority
确认current Volume的immutable size/durability、owner/epoch/head及acquire marker与grant逐字段相同。若current head/
expiry已因同attachment的合法blockd改变，该acquire step不得再启一个实例，只能经full inventory和
现有blockd handshake走adoption。对尚未启动的exact grant，blockd必须以exact owner/epoch完成本次renew/
authority check，才以exact volume/attachment/epoch/size/durability/head/acquire_origin启动并开放Guest I/O。
响应本身不开放Guest I/O或route。

### 4.3 Release

server只从`cleanup.target`和`cleanup.volume_release`构造唯一`ReleaseRequest`：

```text
volume_id = target.volume_id
transition_id = volume_release.release_transition_id
attachment_id = target.attachment_id
expected_epoch = target.attachment_epoch
```

不得接受客户端另传一份ReleaseRequest。事务逐字段执行Runtime CleanupRelease合同：current session、引用的
accepted full inventory/session/epoch/read position、current Desired/tombstone read position、target physical
identity、完整acquire origin、attachment/epoch、disposition和generation都匹配；blockd/VMM/Guest writer已停，
保留数据路径精确`R == L == volume_release.generation`。对Root disposable `R == L` normal分支，current
Desired必须是同delete ID的Deleted revision；取得Volume锁后fresh检查该delete lineage不存在任何已经派生的
disposable authorization。对Persistent detach/retain按Volume Authority current-only规则验证不再有冲突
binding/residue。

任一授权已先commit则release零副作用返回`authorization_branch_conflict`；release先commit时后续derive因
Unowned整笔回滚。全部通过后调用pure `release`并同commit写Unowned结果。release响应确认后Node才能删除不再
需要的local lineage；响应不明先按§3解析，不能因expiry或“现在看起来Unowned”猜是自己的release。

### 4.4 Disposable Root authorization consume

request只有authorization ID。事务从服务器端row取得kind/event/volume/disk/Cat/delete/revision/placement/
old attachment/epoch/head/isolation/not-after，要求全部与request current context、current Deleted Root
disposition和Control Disk逐字段相同，并证明没有live DiskSnapshotRecord。

`runtime_stopped` basis还必须引用current session下已经接受的exact stop observation：same Cat/revision/
placement/runtime incarnation，Guest/VMM/blockd stopped，授权首次建立时的`R < L`事实仍与exact lineage一致。
`host_fence_event` basis按event cutoff/barrier和Volume Authority规则验证；调用者仍必须是current Desired
placement的current Node，授权ID本身不允许任意authenticated Node消费。Host完全失联且没有replacement Node
时，Control内部worker可以调用同一transaction函数但不经过HTTP；它必须携带服务器内部typed context并执行
相同Desired/Disk/event checks，不能伪装Node proof或建立第二条conversion。

首次消费在一个commit写Volume与Disk同一Deleting(delete ID)、清owner并提高epoch、写authorization receipt；
成功后Node才可删receipt命名的旧lineage/tail。exact consumed replay仍要求current context，并逐字段验证两边
direct state或Volume Authority允许的closed successor；缺row/错receipt/单边Deleting是fatal internal，不能
返回假成功。

## 5. Closed HTTP error与固定映射

本文使用endpoint-local envelope，不扩A20 `RuntimeSpineError`，也不把Volume domain错误伪装成F0
`ContractErrorDetail`：

```text
RuntimeVolumeTransitionError {
  version: 1,
  error: RuntimeVolumeTransitionErrorDetail,
  message: string 0..=1024 UTF-8 bytes
}

RuntimeVolumeTransitionErrorDetail =
  { code: "authentication_failed" }
| { code: "identity_not_eligible" }
| {
    code: "http_request_rejected",
    problem: "method_not_allowed" | "query_not_allowed"
           | "content_type_not_allowed" | "content_encoding_not_allowed"
           | "authorization_not_allowed" | "accept_not_allowed"
           | "semantic_header_not_allowed"
  }
| { code: "contract_error", contract_error: ContractError }
| {
    code: "transition_precondition_failed",
    cat_id: Id,
    problem: "inventory_session_replaced" | "inventory_stale"
           | "volume_intent_mismatch" | "cleanup_evidence_mismatch"
           | "authorization_branch_conflict"
  }
| {
    code: "volume_authority_rejected",
    volume_id: Id,
    reason: "other_writer" | "fenced" | "stale_transition"
          | "invalid_lease_duration" | "epoch_exhausted" | "admin_busy"
  }
| {
    code: "volume_authorization_rejected",
    authorization_id: Id,
    reason: "invalid_authorization" | "invalid_lease_duration"
          | "snapshot_in_use" | "epoch_exhausted"
  }
| { code: "node_request_in_flight" }
| { code: "temporarily_unavailable" }
| { code: "internal" }
```

body为canonical JSON且最多20480 octets；message不得含credential存在性、signature、SQL、Host path、volume
row或authorization payload。固定mapping：

| condition | HTTP / detail |
|---|---|
| proof/SPKI/header任一失败 | 401 `authentication_failed`，`WWW-Authenticate: CatsNodeSignature realm="runtime-internal"` |
| credential没有唯一provisioned exact-binding NodeIdentity | 403 `identity_not_eligible` |
| method/query/media/semantic header | 与A20相同的405/400/415/406/400 `http_request_rejected` |
| wire cap | 413 `contract_error(limit_exceeded)` |
| F0 malformed/unsupported | 400 `contract_error` |
| current AgentSession的guest digest不等于Control active exact receipt | 409 `contract_error(guest_config_mismatch)`；expected为active digest，presented为session digest |
| session/revision/spec digest/placement、missing attestation、assigned-set changed | 409，嵌入Runtime现有exact `ContractError` |
| attestation绑定旧session或超过60秒 | 409 `transition_precondition_failed`对应problem |
| current Desired/action/intent不匹配 | 409 `volume_intent_mismatch` |
| release的full physical/R/L/cleanup binding不匹配 | 409 `cleanup_evidence_mismatch` |
| release与disposable authorization竞态 | 409 `authorization_branch_conflict` |
| normal acquire/release pure domain的列举错误 | 409 `volume_authority_rejected` |
| 已通过stored-row closed validation的takeover authorization在`db_now + duration`时溢出 | 409 `volume_authorization_rejected(invalid_lease_duration)` |
| authorization consume的其他列举错误/live snapshot | 409 `volume_authorization_rejected` |
| 独立per-Node cap | 429 `node_request_in_flight`，`Retry-After: 1` |
| global cap、deadline、DB pool、serialization retry exhausted | 503 `temporarily_unavailable`，`Retry-After: 1` |
| Authority `NotFound`/`BackendUnknown`/未列举HeadConflict、stored corruption或server bug | 500 `internal` |

`missing_agent_session`、`stale_session`、`wrong_session`、active-release `guest_config_mismatch`、`session_expired`
及revision/spec digest/placement按§4.1与Runtime §16.4.3的原顺序选择；missing attestation与assigned set changed
随后按A20精确typed error。它们都先于
precondition/domain错误。相同stage多个action-specific候选固定按：inventory session -> inventory freshness
-> volume intent -> cleanup evidence -> authorization branch -> pure domain。前一个失败零写且不得读取/渲染
后一个事实。

`NotFound`不能从一个已经通过current Desired/Disk cross-row验证的合法request产生；出现即stored corruption。
`BackendUnknown`永不暴露为4xx。客户端只能按typed detail行动；valid 429/503或ambiguous response重试同一
request，valid 409先重读Desired/full inventory/Volume并按Runtime选择Blocked/Quarantined/replan，绝不能自动
更换transition或authorization ID。

## 6. Fixed vectors

以下向量只校准wire，不建立新authority。它使用Runtime §16.3的session、placement和spec digest，以及A19
§4.4的RFC 8032 test key；所有object key均按Cats Canonical JSON UTF-8 byte顺序排列。

**Normal acquire request**（exact 624 octets）：

```json
{"cat_id":"cat_01","desired_revision":7,"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","transition":{"kind":"acquire","request":{"attachment_id":"att_01","desired_revision":7,"expected_unowned_epoch":0,"kind":"normal","lease_duration_ms":60000,"placement_epoch":3,"transition_id":"22222222222222222222222222222222","volume_id":"vol_root"}},"version":1}
```

```text
SHA-256(exact request bytes) = f8b0e2c8fbb23f456aadf2cae9e2ae7422ee8d35938edcc96ab83a97cce5f473
signed_request_length = 228
SHA-256(signed_request) = 15269284739a36f17639042b66c00be04f13d99d4d03d788052ab0cbdfed206a
Cats-Node-Signature = 8N562xDOzm7X1Vd-nZFaGT82qOm3Zoauot5l-j7iwOLO2eRs2-HA_S7j1AWKWZOo-VZl8mMb2ATyO5M8HdrjCQ
```

**Lease-granted success**（exact 713 octets）：

```json
{"cat_id":"cat_01","desired_revision":7,"outcome":{"grant":{"acquire_origin":{"kind":"normal","transition_id":"22222222222222222222222222222222"},"attachment_epoch":1,"attachment_id":"att_01","durability":"strict","head":{"generation":0,"root_hash":null,"root_object_id":null},"lease_expires_at":1720000060000,"size_bytes":4294967296,"volume_id":"vol_root"},"kind":"lease_granted"},"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","version":1}
```

```text
SHA-256(exact success bytes) = a823cbaa5fa2819e9a560753ce0428312bc59faeb219fb258aad1aba4ca10ef4
```

**Inventory-stale error**（exact 149 octets）：

```json
{"error":{"cat_id":"cat_01","code":"transition_precondition_failed","problem":"inventory_stale"},"message":"complete inventory is stale","version":1}
```

```text
SHA-256(exact error bytes) = 1e80edaf0a2fbcad3b50843f620f9bc26286d17d4a569c256e3fb6bd086bdd9c
```

独立实现必须重建三个JSON及其长度/checksum，重建A19 frame并验证positive signature；method、path、
content-type、credential ID、SPKI、body length或body任一byte变化都必须使该signature失败。

## 7. 最小验收矩阵

| boundary | required oracle |
|---|---|
| route/admission | exact POST；wrong method/query/path/media/semantic headers；16384/16385；proof失败不decode/查DB；独立global/per-Node caps且不占A20 observation permit；饱和A22 ordinary Store worker/queue/connection时A20保留renewal-critical lane仍可提交新sequence续期；absolute deadline/cancel/late commit |
| codecs | request三variant及acquire两variant、success三variant、error全部closed；missing/unknown/duplicate/noncanonical integer、wrong union field和16KiB边界；fixed vectors及proof mutation |
| auth/session | body Node不能选credential；retired/wrong binding拒绝；missing/stale/wrong/expired session；replacement必须先fresh full；expired没有transition replay例外 |
| routing isolation | 合法Node在body中填另一Cat/volume/authorization ID只得到current-intent mismatch，不锁、不读取后者的authority payload也不泄露其是否存在；NodeIdentity锁后的routing hint与后row-lock reread不一致必须零写入 |
| release binding | current session guest digest必须等于Control active exact receipt；旧release session即使其他字段匹配也零卷副作用 |
| assigned-set lock | 真实PG双connection双向pause：Desired INSERT先锁/提交则旧cursor full/transition拒绝且零写；full先锁/提交则INSERT只能在后，旧attestation随即以assigned-set changed不可消费；所有Desired mutation、A20 mutation和transition先锁同一NodeIdentity；两Control replicas双session覆盖 |
| normal acquire | current Desired/intent/Disk/Volume逐字段；fresh complete inventory；same transition exact replay不刷新expiry；异payload、other writer、epoch mismatch、Deleting和epoch max零副作用 |
| takeover | caller只传ID；event/auth/volume固定锁序；current intent/new attachment/revision/placement绑定；首次consume、Rejoined并发、not-after过期、`db_now + duration`溢出的exact typed错误、exact receipt replay |
| grant | size/durability/head/owner/epoch/expiry/origin来自同一updated VolumeRecord；Node落checkpoint后才spawn/adopt；success字段替换或late old-session response不能开Guest I/O |
| release | CleanupRelease唯一导出ReleaseRequest；current full evidence、origin、stop、R==L==generation、Desired/tombstone和disposition；same ID replay、异payload、response loss、epoch max |
| release/auth race | 两session按Volume锁后fresh重验；release先则derive全rollback，derive先则release exact 409零写；无auth+Unowned |
| disposable | runtime-stopped与host-fence两basis；current Deleted Root/delete ID、Disk、snapshot、stop/event、old owner/epoch/head全绑定；receipt/Volume/Disk同commit；成功前不删tail |
| corruption | 每张JSONB/projection、receipt/direct state、missing referenced row和future time逐项破坏均500/零写；recovery snapshot还覆盖错primary ID/variant/volume、current Volume与completion并存、同volume重复completion、marker引用缺失或associated row错volume/variant；绝不降级4xx或接受半postcondition |
| authorization recovery read | 唯一input是authorization ID；在同snapshot返回exact primary、derived Volume/null、derived completion/null和只被current marker/completion直接引用的最多一个associated authorization；无volume/delete/successor key输入、无全volume授权枚举/分页、无bool或chain ledger；使用无关ID的正例校准后，证明它不读/返回其他volume/receipt/authorization；PostgreSQL role只读三表，三表write与第四张Control表read均拒绝；blockd composition不能取得该port |
| ambiguity | commit前/后断连接；同domain ID重放；current context变化后fresh rebind；normal用direct `load_volume`，authorization用recovery snapshot；takeover commit丢response后允许current Volume已经合法renew/head-CAS/release/更大epoch后继，仍必须由原authorization receipt + current marker/最多一associated authorization + epoch/head单调闭合；Unconsumed + null marker + exact predecessor只重放原ID，Consumed + null marker缺same-disk restore API result时必须Blocked；disposable commit丢response后sweeper已删Volume/Disk row时只凭exact completion receipt闭合，缺receipt保持Blocked；plain 404停止自动重试；redirect、HTML、status/detail/header不匹配、超cap和malformed success/error全部保留checkpoint且只重试原request；不建HTTP result row或second grant ledger |
| legacy negative | production route表没有legacy acquire/revoke；blockd port没有ownership mutation；Node不直接调用pure Control single-row method；internal handler不读shared bearer |

这些测试使用真实PostgreSQL双session与两个Control Plane实例。failure probe必须先证明注入命中；空日志或未执行
late worker不能当通过。接线完成前production per-Cat worker不得启用`AcquireVolume`、volume
`CleanupRelease`或`DeleteDisposableRoot`effect。
