# Runtime Inventory and Telemetry v1

- 状态：Implemented/Frozen v1；ADR-0056 clean-slate inventory/telemetry合同
- 上位决策：[ADR-0056](../decisions/0056-atomic-per-cat-runtime-lifecycle.md)
- 产品动作边界：[ADR-0057](../decisions/0057-product-lifecycle-actions-and-internal-execution-evidence.md)
- Lifecycle：[Atomic Runtime Lifecycle v1](atomic-runtime-lifecycle-v1.md)
- Node注册与签名：[Agent Registration and Internal Transport v1](agent-registration-transport-v1.md)
- Route：[Route Grant v2](route-grant-v2.md)
- Volume：[Volume Authority](volume-authority.md)

本文冻结Node到Control的session-bound完整physical inventory和增量telemetry协议。它只回答“Node当前看见
什么”，不回答“用户要求什么”或“某条命令是否完成”。Lifecycle intent和terminal result只由
`LifecycleOperation`、Node command journal和exact signed result commit闭合。

Atomic release不发送旧`DesiredReadRequest`、`DesiredReadSnapshot`或`NodeObservation`，也没有Desired
read-position、assigned snapshot、reconcile step、legacy `RuntimeCheckpoint`、route gate、Operation
settlement字段或兼容parser。旧`POST /v1/internal/runtime/desired-reads`不在production route map；原
`POST /v1/internal/runtime/observations`路径只安装本文的新decoder。

## 1. Authority boundary

`RuntimeInventoryReport`是telemetry。即使报告由current AgentSession签名、通过canonical digest并被
PostgreSQL接受，下列事实仍保持唯一authority：

| 事实 | Authority | inventory地位 |
|---|---|---|
| lifecycle intent、causal head、terminal result | PostgreSQL `LifecycleOperation` + exact NodeResult | 不admit、不settle、不fail、不supersede、不reopen |
| VMM、scope、frontend、snapshot、local journal是否存在 | Node physical inventory | 当前报告是有时效的read model |
| volume owner/epoch/head、release/delete receipt | MetadataStore/Volume Authority CAS | `ObservedVolumeWatermarkSummary`只诊断，不授权release/takeover/discard |
| route Serving、Endpoint epoch、public-ring ACK | Route Operation/Serving receipt/独立ring ACK | inventory不携带route gate、Grant或ring ACK |
| product stable state | exact terminal lifecycle head | `ObservedRuntimePhysicalState`不能改写product state |
| artifact删除权限 | command-bound classification + exact domain postcondition | observed classification本身不授权GC |

Full report可建立一个current-session、freshness-bounded的完整inventory attestation。它只能作为另一事务的
窄admission输入；消费方仍须在同一事务锁住并重验current AgentSession、attestation freshness和自己的
domain facts。Partial不能建立、刷新或替换Full attestation。

## 2. 固定常量与HTTP

| 名称 | v1值 |
|---|---:|
| method | `POST` |
| path | `/v1/internal/runtime/observations` |
| report wire cap | `8388608` bytes |
| acceptance wire cap | `16384` bytes |
| error wire cap | `16384` bytes |
| handler deadline | `10000` ms |
| AgentSession renewal | `60000` ms，使用PostgreSQL time |
| placement inventory maximum age | `60000` ms |
| Cats per report | `1024` |
| volumes per Cat | `64` |
| artifact classifications per Cat | `1024` |
| unattributed artifacts per Full | `4096` |
| conditions per Cat | `64` |

HTTP只接受一个`Content-Type: application/json`；`Accept`若出现也只能为`application/json`。禁止query、
`Content-Encoding`、`Authorization`、`Idempotency-Key`、conditional headers和method override。body在decode
前按Content-Length和stream limit双重有界。

请求复用Agent Registration §4唯一per-Node Ed25519 proof adapter。签名覆盖exact method、path和raw body；
credential proof失败在读取Node/session/report state前返回401。HTTP adapter先做只读credential到Node
解析以取得per-Node non-blocking permit，随后Store transaction重新锁定并验证NodeIdentity、credential
lineage和current AgentSession。只读预解析从不替代事务内鉴权。

inventory ingress使用独立bounded Store worker/queue/connection和自己的global/per-Node in-flight admission。
Lifecycle poll/result commit使用另一条独立lane。malformed、stale或被拒的inventory不能占用、续租、释放或
阻断lifecycle command lane。

## 3. 共享scalar与canonical JSON

以下scalar沿用同release中冻结的strict类型：

- `ContractVersion`：本文只接受`1`；
- `Id`：1..=128 ASCII alphanumeric或`._:-`；
- `RandomId128`：32位lowercase hex；
- `Epoch`、`Sequence`：positive integer；
- `Generation`：non-negative integer；
- `FenceEpoch`：Volume Authority定义的epoch；
- `UnixMillis`：non-negative integer；
- `Sha256Digest`：`sha256:`加64位lowercase hex；
- `SessionBinding {node_id,node_boot_id,agent_instance_id,agent_session_epoch}`。

所有struct使用`deny_unknown_fields`，所有union是closed tagged enum；无alias、default、nullable boolean
discriminator或自由字符串condition。encoder使用Cats canonical JSON；decoder拒绝unknown/trailing value、
invalid scalar、越界collection、重复identity、非canonical vector order和cross-field contradiction。

## 4. Report wire

```text
RuntimeInventoryReport {
  version: 1,
  session: SessionBinding,
  report_id: RandomId128,
  sequence: Sequence,
  collected_at_unix_ms: UnixMillis,
  inventory: RuntimeInventoryBody
}

RuntimeInventoryBody =
  { kind: "full",
    inventory_epoch: Epoch,
    scan_id: RandomId128,
    inventory_digest: Sha256Digest,
    cats: [ObservedCatRuntimeTelemetry],
    unattributed_artifacts: [ObservedArtifactClassification] }
| { kind: "partial",
    inventory_epoch: Epoch,
    cats: [ObservedCatRuntimeTelemetry] }
```

`session`必须逐字段等于current AgentSession。`report_id`标识一次exact payload；`sequence`在同一session内
严格递增，但允许跳号。相同sequence的exact同payload是replay并返回原acceptance；同sequence异payload是
`ReportSequenceConflict`；更小sequence是`StaleReportSequence`。replacement session拥有自己的sequence
空间，旧session永久拒绝。

`collected_at_unix_ms`是Node诊断时间，不是lease、freshness、fence或ordering authority。Control接受时间和
lease deadline只用同一transaction的PostgreSQL time。

### 4.1 Full

`inventory_epoch`在每个AgentSession内从1开始且每次Full精确加1；不能重复、倒退或跳号。`scan_id`标识
Node一次完整physical scan。`cats`是该scan发现的完整、按`cat_id`严格升序且无重复集合；Full成功后原子
替换该Node current per-Cat telemetry，所以不再出现的旧Cat row被删除。Full可以为空。

`unattributed_artifacts`包含不能安全归到某Cat的Host-local evidence，按`artifact_id`严格升序且无重复。
它使“完整scan”不必把unknown residue猜成Cat、Cold或可删除对象。

### 4.2 Partial

Partial必须引用current session最近一次Full的exact `inventory_epoch`。它的`cats`仍按ID排序，但每个Cat必须
已经属于该Full的完整集合；否则整份report以最小非法Cat返回`PartialCatNotInFullInventory`且零写入。

成功Partial只upsert明确列出的per-Cat telemetry。它不删除未列出的Cat、不扩张Full membership，也绝不更新
`runtime_full_inventory_attestations`的JSON、epoch、digest、scan ID、source report/sequence或accepted time。
Partial引用epoch只用于session association和诊断，不是complete-scan proof。

## 5. Full inventory digest

Full digest domain固定为：

```text
cats.runtime-inventory.full.v1
```

输入是完整`RuntimeInventoryReport`的canonical JSON，唯一移除字段为
`inventory.inventory_digest`；因此digest绑定version、SessionBinding、report ID、sequence、Node collected
time、inventory epoch、scan ID、完整sorted Cat facts和全部unattributed artifacts。计算为：

```text
SHA256(domain || 0x00 || canonical_json(full_report_without_digest_field))
```

接收方必须重算并逐byte比较。Partial没有inventory digest，也不能调用Full digest helper。digest只证明
payload self-consistency；它不把Node claim变成lifecycle、volume、route或GC authority。

空Full的冻结canonical vector（整行无结尾LF）是：

```json
{"collected_at_unix_ms":6,"inventory":{"cats":[],"inventory_digest":"sha256:04a80ea20c2306d1a7fd8c2b7d9fa718886fef8a99edcfa2a646492a01c9cae4","inventory_epoch":1,"kind":"full","scan_id":"00000000000000000000000000000007","unattributed_artifacts":[]},"report_id":"00000000000000000000000000000004","sequence":5,"session":{"agent_instance_id":"00000000000000000000000000000002","agent_session_epoch":3,"node_boot_id":"11111111111111111111111111111111","node_id":"node_a"},"version":1}
```

移除`inventory_digest` member后按上述domain计算，期望digest就是该vector内的
`sha256:04a80ea20c2306d1a7fd8c2b7d9fa718886fef8a99edcfa2a646492a01c9cae4`。

## 6. Per-Cat observed facts

```text
ObservedCatRuntimeTelemetry {
  cat_id: Id,
  observed_placement: PlacementIdentity,
  observed_command_journal: ObservedCommandJournal | null,
  observed_physical_state: ObservedRuntimePhysicalState,
  observed_runtime_incarnation: RandomId128 | null,
  observed_artifact_manifest_digest: Sha256Digest,
  observed_artifact_classifications: [ObservedArtifactClassification],
  observed_volumes: [ObservedVolumeWatermarkSummary],
  observed_conditions: [ObservedRuntimeCondition]
}
```

所有字段显式使用`Observed`命名，避免调用方把read model当product或command authority。
`observed_placement.node_id`必须等于report session Node。Cat、artifact和volume vectors分别按`cat_id`、
`artifact_id`和`volume_id`严格升序；一个Cat内`disk_id`也唯一。

### 6.1 Physical state与journal

```text
ObservedRuntimePhysicalState =
  "absent" | "executing" | "paused" | "warm_snapshot_retained"
| "stopped_retained" | "ambiguous"
```

`executing`/`paused`必须有runtime incarnation；`absent`必须没有。`warm_snapshot_retained`、
`stopped_retained`和`ambiguous`保留其实际可知的incarnation，不推断stable Warm/Cold或
`ExecutionStopped` proof；后者只能来自发起动作的exact Node result。

`ObservedCommandJournal`是closed phase union：

- `accepted`、`executing`：Operation ID、command kind、request fingerprint、journal digest；
- `terminal`、`awaiting_result_stored_ack`：以上字段加terminal result digest；
- `completed_delete_receipt`：current internal codec tag，记录destroy teardown execution的
  Operation/fingerprint、journal/result/completed receipt digests；它不是product Delete action。

这些字段帮助发现stuck/replay/drift；Control不得从phase或digest重建NodeResult。只有signed lifecycle result
commit可结算Operation。

### 6.2 Artifact classification

`ObservedArtifactClassification`是closed union，不同variant的evidence shape也是wire的一部分：

- `adoptable_cat_state {artifact_id,ownership_digest}`；
- `cat_owned_gc_candidate {artifact_id,ownership_digest,postcondition_digest}`；
- `retained_authority_or_data {artifact_id,evidence_digest}`；
- `quarantined_foreign_or_ambiguous {artifact_id,evidence_digest}`。

GC candidate的ownership与已验证postcondition必须是两个独立digest；旧单一
`evidence_digest`形状拒绝decode。这仍只是Node当前分类的telemetry，不是删除授权。
真正adopt/GC必须在effect前重新验exact command identity、ownership和postcondition；Volume、
pending pack、`R < L`、Persistent或unknown evidence不能因本字段被删除。

当前release的installed Full/Partial/startup scanner不产生可执行的
`cat_owned_gc_candidate`；未终结Start中看到的candidate也降级为
`retained_authority_or_data`。production没有generic destructive artifact-GC worker；首个真实
producer与worker必须一起通过
[Atomic Runtime Lifecycle v1 §11.4](atomic-runtime-lifecycle-v1.md#114-destroystoragegc)后才可开放。

### 6.3 Volume watermarks

```text
ObservedVolumeWatermarkSummary {
  volume_id, disk_id, disk_role,
  observed_attachment: ObservedVolumeAttachment,
  observed_watermark: ObservedVolumeWatermark
}

ObservedVolumeAttachment =
  {kind:"unowned", attachment_epoch}
| {kind:"owned", owner_node_id, attachment_id, attachment_epoch}
| {kind:"deleting", previous_owner_node_id, fenced_attachment_epoch}
| {kind:"unknown", evidence_digest}

ObservedVolumeWatermark =
  {kind:"known", local_durable_generation:L,
                 remote_durable_generation:R}
| {kind:"unknown", evidence_digest}
```

Known必须满足`R <= L`。该检查只拒绝内部矛盾；Control仍以MetadataStore/Volume Authority row和exact receipt
决定owner、release、takeover、delete与durability。Unknown不被猜成`R == L`。

### 6.4 Conditions

`ObservedRuntimeConditionKind`固定为`healthy/progressing/blocked/degraded/drift/quarantined/
data_loss_possible`。每个condition带typed kind和evidence digest，无自由字符串。conditions按kind严格升序，
所以同kind最多一个；它们只影响health/status/alerting，不改写stable state或Operation。

## 7. Acceptance wire

```text
RuntimeInventoryAcceptance {
  version: 1,
  session: SessionBinding,
  report_id: RandomId128,
  sequence: Sequence,
  accepted_at_unix_ms: UnixMillis,
  lease_deadline_unix_ms: UnixMillis,
  inventory: RuntimeInventoryAcceptanceKind
}

RuntimeInventoryAcceptanceKind =
  {kind:"full", attestation: RuntimeInventoryAttestation}
| {kind:"partial", inventory_epoch: Epoch}

RuntimeInventoryAttestation {
  version: 1,
  session: SessionBinding,
  inventory_epoch: Epoch,
  scan_id: RandomId128,
  inventory_digest: Sha256Digest,
  source_report_id: RandomId128,
  source_sequence: Sequence,
  accepted_at_unix_ms: UnixMillis
}
```

Full attestation逐字段复制accepted Full身份和digest。Partial acceptance只回显关联epoch，不返回或制造
attestation。`accepted_at`和lease deadline来自同一DB timestamp；deadline不得早于accepted time。

current session下最高sequence exact replay即使deadline后来到期仍返回原acceptance，因为它不产生新写入；
任何新payload在`db_now >= lease_deadline`时返回`SessionExpired`。replacement session后旧report不能exact
replay成功。

成功Full或Partial可单调延长AgentSession deadline到`max(current_deadline, db_now + 60000)`。Lifecycle command
poll独立完成相同续期，所以inventory decode/reject、full-scan故障或telemetry Store饱和不会阻断已admit command。

## 8. Node startup、journal与sender

Lifecycle与telemetry共享caller-owned `StartupInventoryCache`，但不共享执行lane。startup固定顺序为：

```text
Lifecycle sole complete physical scan
-> cache Empty -> Physical（每个Cat的observed_command_journal必须为null）
-> admission registry sole descriptor-safe lifecycle-journal enumeration
-> overlay exact journal digest/phase，形成sorted physical+journal union
-> cache Physical -> Joined
-> RuntimeInventoryRunner first Full consumes exact Joined seed once
```

initialize和join的exact replay幂等，异evidence冲突fail closed；Joined seed只能消费一次。首个Full禁止第二次
startup scan，也禁止在cache未Joined、source不可用或scan incomplete时制造empty Full。journal-only但可验证的Cat
以实际command placement和`absent` physical state进入union；corrupt journal若没有可归属physical placement则不能猜成
Cat或成功attest。无法归属的physical artifact只能进入Full的`quarantined_foreign_or_ambiguous` unattributed集合。

Node sender在独立task运行。`open`只恢复并fsync session-bound exact-report journal，同时返回cloneable
`AwaitingFull | Attested` watch；它不等待scan或网络。`run`先发送上述startup Full，之后Full refresh才调用同一个
installed complete-union collector重扫，Partial只对accepted Full member采样。collector是required dependency，没有
no-op/empty production fallback。

每份report在网络I/O前以canonical exact bytes原子replace、file fsync和directory fsync落盘。ambiguous transport、
invalid response、429/503或5xx只重试同一pending bytes；只有逐字段匹配report的canonical acceptance才能推进sequence、
Full epoch或清除pending。新AgentSession原子清空旧sender state，并从sequence/Full epoch 1重新开始；旧session不能
重新打开较新的journal。

本地readiness只在Full ACK后变为Attested，并在无法刷新时早于Control 60秒DB freshness窗口保守关闭。readiness不是
Route、lifecycle或volume authority。collection/transport失败保持AwaitingFull并独立重试；它不能阻塞lifecycle poll、
result commit、per-Cat worker或其Store lane。shutdown可终止sender而不修改任何lifecycle journal。

## 9. Store transaction与schema

一次new report acceptance在单个PostgreSQL transaction内按以下顺序：

```text
NodeIdentity FOR UPDATE
-> exact credential lineage FOR SHARE
-> current AgentSession FOR UPDATE
-> runtime_inventory_receive_states FOR UPDATE
-> runtime_full_inventory_attestations FOR UPDATE
-> validate sequence/session/epoch/full membership
-> full attestation + per-Cat replacement，或partial per-Cat upsert
-> receive state
-> monotonic session renewal
-> commit
```

事务不读取、锁定或写入`runtime_operations`、Cat lifecycle head、route Operation、Volume Authority或Desired
表。任何rejection通过transaction reject/rollback返回，零telemetry/attestation/session/Operation写入。一个
sibling Cat malformed使整份report拒绝，但不影响独立lifecycle lane。

最小schema/cardinality：

| table | cardinality与字段 |
|---|---|
| `runtime_inventory_receive_states` | 每Node 1；exact report/acceptance、session projection、report sequence/ID、accepted time |
| `runtime_full_inventory_attestations` | 每Node 1；attestation/full report、session、epoch、scan ID、digest、source report/sequence、accepted time |
| `runtime_current_cat_telemetry` | 最近Full最多1024项；Full完整替换，Partial只upsert成员；source kind为full/partial |

表和字段不保留`observation`、`heartbeat_sequence`、`full_observation`、`runtime_record`、Desired cursor或
assigned snapshot alias。PostgreSQL JSON与scalar projection必须逐字段一致；corrupt projection是fatal
backend-unknown，不降级为empty inventory。

Freshness由消费方在一个DB snapshot同时验证attestation SessionBinding等于locked current AgentSession及
`accepted_at_unix_ms <= database_now < accepted_at_unix_ms + 60000`；加法溢出或DB clock倒退fail closed。
Partial accepted time不能刷新Full freshness。

## 10. Closed errors

wire error envelope为`RuntimeInventoryError {version,error,message}`；message是bounded printable ASCII，error为
closed union：

- decode/limit：`MalformedPayload`、`UnsupportedVersion`、`LimitExceeded`；
- HTTP/auth：`AuthenticationFailed`、`IdentityNotEligible`、`HttpRequestRejected`；
- session：`MissingAgentSession`、`StaleSession`、`WrongSession`、`SessionExpired`；
- stream：`StaleReportSequence`、`ReportSequenceConflict`；
- inventory：`MissingFullInventory`、`StaleInventoryEpoch`、`WrongInventoryEpoch`、
  `PartialCatNotInFullInventory`；
- local admission/failure：`NodeRequestInFlight`、`TemporarilyUnavailable`、`Internal`。

body/collection超界返回413；malformed/digest mismatch返回400；unsupported version和session/sequence/epoch
conflict返回409；invalid proof返回401；ineligible identity返回403；bounded resource或ambiguous commit返回503。
当HTTP owner已发送COMMIT但response unknown时只返回503并要求exact report retry，不能假定接受或重发不同
sequence。

## 11. Clean-slate与验收矩阵

首次部署不迁移旧Desired cursor、NodeObservation、observation acceptance、assigned snapshot、per-Cat
observation row或credential。旧Controller/Node parser/write path先退出并rotate credential，随后创建唯一空
schema和本文一个protocol version。unknown旧payload严格malformed；旧Desired route为404。

最低验收oracle：

- [ ] canonical Full fixed vector与digest跨实现一致；改变session/report/sequence/time/epoch/scan/Cat/artifact任一
  字段改变digest；Partial不能计算Full digest；
- [ ] vectors unsorted、重复、越界，`R > L`，physical state/incarnation矛盾、unknown/trailing字段均在DB前拒绝；
- [ ] current session第一份Full只接受epoch 1；后续只接受`current+1`；replacement session重新从1开始；
- [ ] exact report replay返回原acceptance；stale/conflicting sequence零写入；old session永久拒绝；
- [ ] Partial在无Full、错误epoch或新增Cat时整份拒绝；成功Partial只更新明确subset，Full attestation bytes和
  freshness完全不变；
- [ ] Full原子替换完整per-Cat集合并保留unattributed artifacts；空Full删除旧Cat telemetry；
- [ ] accepted、malformed、stale、wrong-session、Full和Partial report前后，任意existing lifecycle Operation
  bytes完全不变；reject后lifecycle poll可立即取得自己的DB lane/locks；
- [ ] telemetry lane饱和或PostgreSQL错误不阻断独立lifecycle poll/result lane；poll可独立续租session；
- [ ] DB clock回拨、JSON/scalar projection corruption和session replacement竞态fail closed；
- [ ] production route map没有Desired read或旧NodeObservation decoder，Route ring ACK走独立Route contract。
- [ ] lifecycle startup只做一次complete physical scan和一次journal enumeration；首个Full逐字段复用Joined seed，
  cache exact replay幂等/conflict fail，后续refresh才调用installed collector；无empty fallback；
- [ ] pending report在进程重启后逐byte恢复；ambiguous/invalid ACK不推进sequence；Partial ACK不替换retained Full；
  telemetry collection/transport故障保持unattested且不阻断lifecycle lane或shutdown。
