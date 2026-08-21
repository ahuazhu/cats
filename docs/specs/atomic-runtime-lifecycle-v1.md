# Atomic Runtime Lifecycle v1

- 状态：Implemented/Frozen internal v1 + product action projection；release gates open。clean-slate schema 17、
  Control command/volume/Route lanes、Node installed lifecycle executor/journal/inventory/Route composition已组成，
  product route、CLI与Operation read已投影`create/run/suspend/warm/cold/destroy`并隐藏private
  `Start/Stop/Delete/Killed`。Node-Control private wire可保留这些执行名称；Route resolve已使用
  `run_required` fixed vector并严格拒绝旧`wake_required`。release还须通过§11的forbidden legacy surface、合法
  successor、product E2E与fixed-vector门，真实production
  mTLS、systemd/KVM/Cloud Hypervisor、RDS failover与external HostFence另行qualification
- Internal atomic authority：[ADR-0056](../decisions/0056-atomic-per-cat-runtime-lifecycle.md)
- Product action/projection authority：
  [ADR-0057](../decisions/0057-product-lifecycle-actions-and-internal-execution-evidence.md)
- 产品状态：[Runtime 生命周期](../runtime-lifecycle.md)
- Route：[Route Grant v2](route-grant-v2.md)
- Storage：[Volume Authority](volume-authority.md)
- Host/Agent/inventory foundation：[Runtime Reconciliation v1](runtime-reconciliation-v1.md) 中明确保留的
  NodeIdentity、AgentSession、Host lock、complete inventory/attestation 合同

本文记录current clean-slate atomic lifecycle内部wire、命令lane、causal chain、Node journal、terminal
result、四态postcondition、Route interlock、HostLost例外和验收oracle。内部数据安全、replay与authority的
MUST/MUST NOT仍是上线条件；本文中把`Start/Stop/Delete/Killed`直接作为产品command/head/successor的部分已被
ADR-0057取代，不是冻结的产品合同。

本规格不规定 SQL 表名、Rust 私有字段或 Node 内部 effect 数量。实现可以把一个命令分成多个有界步骤，
但 Control 只能看到内部accepted/terminal boundary，不能解释中间步骤或 observation 来结算命令；product
adapter只投影[Runtime 生命周期](../runtime-lifecycle.md)定义的六个动作。

## 0. 产品动作边界与current implementation状态

产品语义只在[Runtime 生命周期](../runtime-lifecycle.md)和ADR-0057解释一次：create包含Genesis
`EnsureRunning`，run让已有Cat从Cold/Warm/Suspended回到Running；没有产品Stop，执行停止只作为发起动作的
嵌入证据。本文其余章节保留current内部类型名，便于逐项审计现有Rust/SQL，不得据此制造第二套产品词汇。

截至2026-08-21的current tree已经完成product adapter边界：

- `control-plane/src/api/mod.rs`只注册`actions/run|suspend|warm|cold|destroy`；Cat create使用独立create route；
- `api/src/runtime_product_reads.rs`的`CatOperationAction`闭集是
  `Create|Run|Suspend|Warm|Cold|Destroy`，Operation read只返回in-progress/succeeded/failed；
- `control-plane/src/api/runtime_operations.rs`把Genesis内部执行投影为create、其他恢复执行投影为run、
  teardown投影为destroy，并隐藏internal stop。
- `cmd/cats`只暴露run/suspend/warm/cold/destroy Cat mutation，明确拒绝旧
  start/stop/delete/resume命令，并用同一product Operation read轮询结果。

`api/src/runtime_lifecycle.rs`的`LifecycleCommandKind`/`LifecycleCommand`继续使用private
`Start|Stop|Delete`，`TerminalResultKind`/`NodeResult`继续使用private `Killed`承载causal/
`ExecutionStopped` evidence；这不是product vocabulary gap。§4.4是internal causal table，§6.6是private
execution proof。product Operation不序列化这些名称，Route resolve只编码`run_required`并拒绝旧
`wake_required`；§11保留这些positive absence回归门。本文不据内部enum名称宣称release-complete。

## 1. Authority、原子性与同步性

每个普通生命周期转换只有以下 authority：

1. PostgreSQL `LifecycleOperation`：Control 命令 intent、per-Cat unresolved exclusion、canonical
   request、causal predecessor 与 exact terminal result；
2. Node-private `LifecycleJournalRecord`/embedded `StopFence`：当前命令 crash recovery 与本地
   execution barrier；它们不是Control wire或第五个product state；
3. `CompletedCommandReceipt`：destroy的内部teardown已移除executable checkpoint后的response-loss replay；
4. Volume Authority receipt：normal acquire/release、takeover 与 disposable-Root delete 的唯一 storage
   authority。

NodeObservation、heartbeat、audit log、GC manifest、route cache 和 API queue 都不是 lifecycle completion
authority。

“原子”指一次接口只有一个 closed terminal result，且该 result 的 postcondition 在本规格中冻结；不表示
物理工作是一个 syscall 或事务。“同步”指 Node 对一个已持久接受的 command 最终只产生一个 terminal
response，不表示 Control 主动直连 Node。production transport 固定为 Node 使用 current AgentSession
签名拉取已由 PostgreSQL admit 的 unresolved command，再签名提交 exact result。deadline、EOF、连接丢失、
malformed response 和无法认证的 response 都使结果保持 unknown；Node 只能重新 poll 或 repost 完全相同的
result，Control 不能推断失败、提交替代 Operation 或从 observation 结算。

## 2. 共享 wire 规则与 digest

### 2.1 基础类型

本规格复用 [Runtime Reconciliation v1 §1.1](runtime-reconciliation-v1.md#11-v1-wire-基础类型) 的
`ContractVersion`、`Id`、`AsciiText`、`RandomId128`、`Revision`、`Epoch`、`FenceEpoch`、
`Generation`、`Sequence`、`UnixMillis`、`Sha256Digest`、`Hostname`、`Ipv4Address`、`MacAddress` 与 strict JSON decoder 规则。
这些共享 scalar/Node identity 规则不属于被 ADR-0056 取代的 Desired lifecycle coordination。

所有 object 字段必填；`T | null` 也必须显式出现。object 拒绝 unknown field 和 duplicate key；one-of
使用内部 `kind` tag；simple enum 使用本文列出的 snake_case string。integer 只接受规范 raw JSON integer
token。array 不得截断；本文规定顺序的 array 必须严格升序且无重复 key。

顶层 wire byte cap：

| 顶层对象 | 最大 UTF-8 JSON octets |
|---|---:|
| `LifecycleCommandEnvelope` | 1,048,576 |
| `LifecycleCommandResponse` | 1,048,576 |
| `LifecycleCommandPollRequest` | 16,384 |
| `LifecycleCommandBatch` | 16,777,216 |
| `LifecycleResultCommitRequest` | 1,048,576 |
| `LifecycleResultStoredAck` | 16,384 |
| `CompletedCommandReceipt` | 1,048,576 |
| `AtomicLifecycleError` | 16,384 |

所有请求/结果对象的 nested array 上限为：volume 64、takeover authorization 64、release/disposition
receipt 64、artifact classification 1,024、Endpoint close evidence 256。volume/Endpoint/artifact array
分别按 `volume_id`、`endpoint_id`、`artifact_id` 的 bytewise ASCII 升序编码。
一个 `LifecycleCommandBatch` 最多 64 条 command，按 `cat_id` bytewise ASCII 严格升序，且
`operation_id` 不重复。

### 2.2 Canonical JSON 与 digest

`CJ(x)` 使用 [Cats Canonical JSON v1](runtime-reconciliation-v1.md#161-cats-canonical-json-v1)：UTF-8、
object key 按 UTF-8 bytes 排序、无非必要 whitespace、无 BOM 和结尾 newline。digest 固定为：

```text
SHA-256(ASCII(domain_separator) || 0x00 || CJ(input))
```

并按 `sha256:<64 lowercase hex>` 编码：

| 字段 | domain separator | 输入 |
|---|---|---|
| `request_fingerprint` | `cats.atomic-lifecycle.request.v1` | 完整 `LifecycleCommandEnvelope` 删除且仅删除 `request_fingerprint` |
| `terminal_result_digest` | `cats.atomic-lifecycle.result.v1` | 完整 `LifecycleTerminalResult` |
| `checkpoint_content_digest` | `cats.atomic-lifecycle.checkpoint.v1` | Node-private `LifecycleJournalRecord`的完整canonical JSON；outer document digest字段不在input中 |
| `completed_receipt_digest` | `cats.atomic-lifecycle.completed-receipt.v1` | 完整 receipt 删除且仅删除 `completed_receipt_digest` |

接收方必须重算并逐 byte 比较。相同 Operation ID 的 fingerprint 不同是 identity conflict，不是新的重试。

## 3. Control Operation 与单 unresolved lane

逻辑 PostgreSQL 记录为：

```text
LifecycleOperation {
  version: 1,
  operation_id: Id,
  workspace_id: Id,
  cat_id: Id,
  node_id: Id,
  placement_identity: PlacementIdentity,
  runtime_config_id: Id,
  runtime_config_digest: Sha256Digest,
  command_kind: LifecycleCommandKind,
  canonical_request: LifecycleCommandEnvelope,
  request_fingerprint: Sha256Digest,
  expected_predecessor_operation_id: Id | null,
  predecessor: LifecyclePredecessor,
  state: LifecycleOperationState,
  created_at_unix_ms: UnixMillis,
  terminal_at_unix_ms: UnixMillis | null
}

PlacementIdentity {
  node_id: Id,
  placement_epoch: Epoch
}

LifecycleCommandKind =
  "start" | "suspend" | "warm" | "cold" | "stop" | "delete"

LifecycleOperationState =
  { kind: "unresolved" }
| { kind: "terminal", terminal: LifecycleTerminalResult,
    terminal_result_digest: Sha256Digest }

LifecycleTerminalResult =
  { kind: "node_result", response: LifecycleCommandResponse }
| { kind: "host_lost", host_fence_event_id: Id,
    interrupted_operation_id: Id }
```

`LifecycleOperation` 中重复保存的字段只是 `canonical_request` 的数据库索引投影，不是第二份可独立
变化的值。decode、insert、poll 和 settlement 都必须逐字段验证：Operation 的 `operation_id`、
`workspace_id`、`cat_id`、`node_id`、`placement_identity`、`runtime_config_id`、
`runtime_config_digest`、`request_fingerprint`、
`expected_predecessor_operation_id` 与 `predecessor` 分别等于 canonical request 的同名字段，
其中 config 投影分别等于 `canonical_request.runtime_config.config_id/config_digest`，
`command_kind == canonical_request.command.kind`，且两处 `node_id` 都等于
`placement_identity.node_id`。任一不等是 corrupt/`OperationIdentityConflict`，不得投递或结算。

Cat runtime config 使用 append-only history。`cat_runtime_configs` 的一行以 exact config ID、canonical
bytes 与 digest 标识；update/delete 均被数据库拒绝。Cat row 保存 current config ID+digest 的 exact
pointer，每个 Operation 再复制该 pointer 并以 FK/transaction invariant 绑定历史行。只有已终结 Cold 后
的显式 config mutation 可以插入新版本并 CAS Cat pointer；旧 Operation 永远继续读取它冻结的历史 config。

## 4. Command envelope、predecessor 与 admission

### 4.0 Production signed pull/result-commit transport

production 不部署 Control 到 Node 的 lifecycle client，也不信任 legacy `agent_url`。唯一传输是复用
[Agent Registration and Internal Transport v1](agent-registration-transport-v1.md) proof 的 Node→Control
signed POST；签名覆盖 method、exact path、body digest、credential lineage、session 与 sequence：

```text
POST /v1/internal/runtime/lifecycle-command-polls

LifecycleCommandPollRequest {
  version: 1,
  session: SessionBinding,
  request_sequence: Sequence
}

LifecycleCommandBatch {
  version: 1,
  session: SessionBinding,
  request_sequence: Sequence,
  commands: [LifecycleCommandEnvelope]
}

POST /v1/internal/runtime/lifecycle-result-commits

LifecycleResultCommitRequest {
  version: 1,
  session: SessionBinding,
  response: LifecycleCommandResponse,
  terminal_result_digest: Sha256Digest
}

response: LifecycleResultStoredAck
```

Control 对 poll 先验证 current provisioned NodeIdentity、active credential lineage 与 AgentSession；batch 必须
逐字段 echo request 的 `session`/`request_sequence`，且只含已经在 PostgreSQL commit、仍 unresolved、
`node_id == session.node_id` 的 exact canonical commands。poll 不创建、claim、admit、renew 或改变 Operation；
Node 不能提交自造 command。空 batch 是正常结果，LISTEN/NOTIFY 只能提示立即再 poll，不能搬运 authority。

Node 对 batch 中每条命令调用同一个 durable journal admission/replay path。若命令已 accepted/executing，重复
poll 只 join/resume；若已有 terminal response，则不重复 effect，而是 repost 同一 result commit。Control 在
result transaction 中重验 current session 只作为 transport authentication，并将 exact response、digest 与
product projection 同一 commit；完全相同的 repost 返回同一 `LifecycleResultStoredAck`。ACK 丢失时 Node
继续 repost，不等待 Control 主动 query。由此，“query/retry exact Operation”在 production 的具体实现就是
重 poll unresolved command与重 post terminal result；没有另一个 Control→Node query/RPC authority。

AgentSession replacement 只改变下一次 poll/commit 的 `SessionBinding`；command/result identity 中没有
session epoch。replacement Agent 在 Host lock、complete inventory 与 journal 下恢复同一 command后，可用新
current session repost原 result。旧 session 的 poll/commit一律拒绝且不能改变 Operation。

### 4.1 Command envelope

```text
LifecycleCommandEnvelope {
  version: 1,
  operation_id: Id,
  workspace_id: Id,
  cat_id: Id,
  node_id: Id,
  placement_identity: PlacementIdentity,
  runtime_config: ImmutableRuntimeConfig,
  expected_predecessor_operation_id: Id | null,
  predecessor: LifecyclePredecessor,
  command: LifecycleCommand,
  request_fingerprint: Sha256Digest
}
```

transport 使用 current AgentSession 的 signed internal-request proof，但 `agent_session_epoch` 不进入
command identity：Agent replacement 必须恢复已接受命令。transport 仍须验证 envelope `node_id` 与
provisioned NodeIdentity/current session 一致，不能把命令投递给另一 Node。

```text
LifecycleCommand =
  { kind: "start", spec: StartSpec }
| { kind: "suspend", spec: SuspendSpec }
| { kind: "warm", spec: WarmSpec }
| { kind: "cold", spec: ColdSpec }
| { kind: "stop", spec: StopSpec }
| { kind: "delete", spec: DeleteSpec }

StartSpec {
  volume_authorities: [StartVolumeAuthority],
  source: StartSource,
  effect_deadline_unix_ms: UnixMillis
}

StartVolumeAuthority {
  volume_id: Id,
  disk_id: Id,
  authority: RuntimeVolumeAuthorityInput
}

StartSource =
  { kind: "genesis" }
| { kind: "same_node_suspended" }
| { kind: "same_node_warm" }
| { kind: "same_node_cold" }
| { kind: "same_node_stopped" }
| { kind: "same_node_retry" }
| { kind: "cold_handoff" }
| { kind: "host_fence_recovery" }

SuspendSpec {
  admission_policy: "require_idle" | "close_and_drain",
  grace_deadline_unix_ms: UnixMillis
}

WarmSpec {
  grace_deadline_unix_ms: UnixMillis,
  convergence_deadline_unix_ms: UnixMillis
}

ColdSpec {
  grace_deadline_unix_ms: UnixMillis,
  convergence_deadline_unix_ms: UnixMillis
}

StopSpec {
  grace_deadline_unix_ms: UnixMillis
}

DeleteSpec {
  delete_id: Id,
  grace_deadline_unix_ms: UnixMillis,
  convergence_deadline_unix_ms: UnixMillis,
  volume_dispositions: [RequestedVolumeDisposition]
}

RequestedVolumeDisposition =
  { kind: "discard_with_cat", volume_id: Id, disk_id: Id,
    disk_role: "root" }
| { kind: "retain_detached", volume_id: Id, disk_id: Id,
    disk_role: "persistent" }
```

`convergence_deadline_unix_ms >= grace_deadline_unix_ms`。deadline 使用 checked arithmetic；到期只选择
本命令冻结的终态，不授予 storage discard/release/takeover。Stop 的 grace 到期进入强制 execution stop；
Cold/Delete 的 convergence 到期返回保留证据的 terminal non-success。

`ImmutableRuntimeConfig` 是从 product Cat config 读取的 closed immutable command input，最多 1 MiB。
它位于 envelope 顶层，因此 Start/Suspend/Warm/Cold/Stop/Delete 都能在 Control 或 Agent restart 后仅凭
同一 canonical command 恢复执行；command-specific spec 不得再从 current product row、旧 Desired 或
Observation 补读执行配置：

```text
ImmutableRuntimeConfig {
  version: 1,
  config_id: Id,
  config_digest: Sha256Digest,
  boot_image_digest: Sha256Digest,
  vcpus: integer 1..=4294967295,
  memory_bytes: integer 1..=9223372036854775807,
  guest_runtime_profile_digest: Sha256Digest,
  network_config: RuntimeNetworkConfig,
  volumes: [RuntimeVolumeConfig]
}

RuntimeNetworkConfig {
  kind: "isolated_ipv4",
  network_id: Id,
  guest_mac: MacAddress,
  guest_ipv4: Ipv4Address,
  prefix_length: 30,
  gateway_ipv4: Ipv4Address
}

RuntimeVolumeConfig {
  volume_id: Id,
  disk_id: Id,
  disk_role: "root" | "persistent",
  size_bytes: integer 1..=9223372036854775807,
  durability: "strict" | "relaxed",
  guest_device_serial: Id,
  guest_device_slot: integer 0..=65535,
  guest_binding: RuntimeVolumeGuestBinding
}

RuntimeVolumeGuestBinding =
  { kind: "root_boot" }
| { kind: "persistent_ext4",
    filesystem_uuid: RandomId128,
    mount_path: AsciiText }

RuntimeVolumeAuthorityInput =
  { kind: "normal_unowned", expected_unowned_epoch: FenceEpoch,
    transition_id: RandomId128 }
| { kind: "same_node_owned", attachment_id: Id,
    attachment_epoch: FenceEpoch }
| { kind: "takeover", authorization_id: Id }
```

`config_digest` 使用 `cats.atomic-lifecycle.runtime-config.v1` 对完整 config 删除该字段后的 CJ 计算。
Endpoint/hostname/route epoch 不在 runtime config 中；改变一个 Endpoint 不得改变 config 或触发 Start。
provider-specific process path、socket、tap、CID 与 effect token 由 Node 从 provisioned composition 与本地
journal产生，不进入 Control lifecycle result state machine。

`RuntimeNetworkConfig` 是 clean-slate command 内嵌的完整、不可变网络输入，不是对旧 Desired、placement
policy或Node observation的digest引用。V1只接受`isolated_ipv4`与`prefix_length=30`；guest/gateway必须在同一
`/30`、互不相同且都不是network/broadcast address，MAC必须是locally-administered unicast。Node必须对
network identity逐字段准备、枚举与验证；仅比较一个opaque digest不合格。

`RuntimeVolumeConfig` 只保存immutable product/device/Guest binding，不保存owner/epoch/transition/
authorization。`disk_role=root`必须且只能使用`root_boot`；`disk_role=persistent`必须且只能使用
`persistent_ext4`。Root没有filesystem UUID/mount path，也不得伪造UUID或`/`占位；Persistent必须携带其
exact预定ext4 UUID与规范mount path。每个StartSpec的`volume_authorities`必须与
`runtime_config.volumes`长度相同、顺序相同，且
每个位置的`volume_id`/`disk_id`逐字段相等；因此request fingerprint绑定完整有序1:1 authority input，不能
按ID fallback、缺省或复用上次Start。closed映射为：Genesis及successful Cold后的same/cross-Node Start全部
使用`normal_unowned`；Suspended或Warm后的same-Node Start全部使用`same_node_owned`；Killed后的
same-Node Start逐卷匹配exact predecessor：`retained_volume_receipts`中的卷使用`same_node_owned`，没有
retained receipt的卷使用`normal_unowned`；HostFenceRecovery全部使用`takeover`。typed failure的
`same_node_retry`必须逐卷匹配该failure保留的exact
authority/result receipt，只能落入上述可证明variant；模糊/缺失证据不能Start。

### 4.2 Typed predecessor

```text
LifecyclePredecessor =
  { kind: "genesis",
    cat_creation_id: Id,
    target_placement: PlacementIdentity }
| { kind: "same_node",
    operation_id: Id,
    terminal_result_kind: TerminalResultKind,
    terminal_result_digest: Sha256Digest,
    node_id: Id,
    placement_identity: PlacementIdentity }
| { kind: "cross_node_cold_handoff",
    cold_operation_id: Id,
    cold_result_digest: Sha256Digest,
    source_node_id: Id,
    source_placement: PlacementIdentity,
    volume_disposition_receipts: [ColdVolumeDispositionDigest],
    target_placement: PlacementIdentity }
| { kind: "host_fence_recovery",
    interrupted_operation_id: Id,
    host_lost_result_digest: Sha256Digest,
    host_fence_event_id: Id,
    old_node_identity: OldNodeIdentity,
    takeover_authorization_ids: [VolumeAuthorizationId],
    target_placement: PlacementIdentity }

ColdVolumeDispositionDigest =
  { kind: "normally_released", volume_id: Id,
    normal_release_receipt_digest: Sha256Digest }
| { kind: "already_unowned", volume_id: Id,
    already_unowned_receipt_digest: Sha256Digest }

VolumeAuthorizationId { volume_id: Id, authorization_id: Id }
OldNodeIdentity { node_id: Id, immutable_host_id: Id, state_path_id: Id }
```

`expected_predecessor_operation_id` 对 Genesis 必须为 null；其他 variant 必须等于其中的 predecessor
Operation ID。target placement 必须等于 envelope placement。Control 在 Cat-row transaction 验证 chain
head、stored terminal variant/digest、source/target config、Cold-window membership lineage与 legal successor。Node 在写 accepted checkpoint 前
独立验证：

- Genesis：Control chain 为空，target 正确，session-bound complete local inventory 无该 Cat 的 conflict/
  residue；
- SameNode：Node ID/placement 与本机相同，exact result kind/digest 等于 current terminal checkpoint；接受
  successor 时再把它原子投影为本 checkpoint 的 bounded `superseded_predecessor`；
- CrossNodeColdHandoff：只能是 successful Cold；`volume_disposition_receipts`完整且
  byte-for-byte匹配**source Cold Operation冻结config/result**的同variant digest，不是简单与
  successor Start config对齐。同一Cold window内的exact append-only attach/detach可使target config
  不同：已detach旧slot的receipt仍保留在predecessor set，新attach Persistent slot只能
  从current exact `Active + Unowned` authority构造`normal_unowned`；Root不可换入。Control闭合
  该历史，target Node只验证canonical predecessor/current target authority且不读取source
  journal；source/target placement必须不同；
- HostFenceRecovery：exact HostLost、Active event、old Host identity、target 与每卷未消费/可消费 takeover
  authorization 完全闭合。

相同 Operation ID 携带不同 target、predecessor、command 或 fingerprint 返回
`OperationIdentityConflict`；predecessor/high-watermark mismatch 返回 `StaleOperation`。两者都在 accepted
checkpoint 前发生且物理 effect 为零。normal cross-Node Start 只接受 CrossNodeColdHandoff；Killed、Warm、
failure 或 NeedsIntervention 不能伪装成 Cold。

### 4.3 PostgreSQL 锁序

所有已存在 Cat 的 lifecycle、Route 与 command-scoped Volume 事务使用同一个前缀。signed Node 请求先按
`current credential lineage/NodeIdentity -> AgentSession`认证；随后用无锁读取仅定位`workspace_id/cat_id`，
再按 `CatRecord -> current LifecycleOperation -> sorted VolumeRecord -> sorted DiskRecord -> immutable
receipt/Endpoint/Route rows` 取得锁。无锁结果没有授权含义；取得 Cat 和 Operation
锁后必须逐字段重验 current chain head、unresolved state、request fingerprint、placement 与 runtime config。
admission 同样先锁 Cat，再验证或插入唯一 unresolved Operation。任何 settlement、Route 或 Volume 路径都不得
先锁 Operation/Volume 后反向取得 Cat 锁，也不得持有Cat/Operation锁后反向认证Node session。

### 4.4 Private internal legal successor

> **不是product state/action表：** 下表冻结Node-Control private causal chain。product adapter把create/run/
> suspend/warm/cold/destroy映射到相应internal command；private Stop/Killed可用于maintenance与exact causal
> evidence，但不得出现在产品route、Operation read或用户文档。

Control 与 Node 必须使用同一 closed table：

| current private terminal result | legal next internal command |
|---|---|
| none | Start with Genesis only |
| RuntimeReady | Suspend, Warm, Cold, Stop, Delete |
| SuspendDeclined(Busy) with retained effective RuntimeReady | Suspend, Warm, Cold, Stop, Delete |
| Suspended | Start same Node, Warm, Cold, Stop, Delete |
| Warm | Start same Node, Cold, Stop, Delete |
| Cold | Start same Node with `SameNode` + `same_node_cold`，或不同 Node with exact Cold handoff；Delete |
| Killed | Start same Node, Cold same Node, Delete same Node |
| StartFailed/SuspendFailed/WarmFailed | Start with `same_node_retry`；Cold；Stop；Delete |
| NeedsIntervention | 同exact target的Warm/Cold/Delete convergence retry；Stop；只有closed reason允许时另可Delete |
| HostLost | Start on target only with HostFenceRecovery |
| Deleted | none |

`NeedsIntervention`中retained `R < L`/authority禁止ordinary automatic Start、placement change、normal
release、takeover、discard和generic GC。`foreign_or_ambiguous_residue`只允许Stop；其他reason
只允许上表的exact convergence路径，且Delete仍受role-specific disposition限制。PersistentDisk
Delete failure继续阻止Root discard。未来repair command不在v1；不能用Start隐式获得repair
authority。

### 4.5 Start Volume grant与renewal

Start对Volume Authority使用独立的signed
`POST /v1/internal/runtime/lifecycle-volume-transitions`，但仍只属于同一条Start
Operation。`LifecycleStartVolumeBatch` exact绑定Operation/fingerprint/Cat/Node/placement，并以
durable、严格单调的`grant_sequence`区分round：

- sequence 0对每卷执行`NormalAcquire | RenewSameNode | Takeover`的初次闭合；
- 后续sequence只对同一exact attachment执行`RenewSameNode`，且每次必须是checked
  successor；
- 每个round的immutable grant receipt保留原acquire/takeover lineage，重放只返回该round
  的原receipt set，不改写authority来源。

`renewal_lease_duration_ms`只是Start执行期内防止已取得writer authority意外过期的
storage lease参数，不是lifecycle command renewal，不创建Operation、product state或public
Start子状态。Node-private journal保存当前round/effect recovery identity；Control lifecycle
lane仍只见一次accepted与一个terminal result。完整receipt与Persistent initialization形状由
[Volume Authority §0.1](volume-authority.md#01-atomic-command-receipt-digests)唯一定义。

## 5. Node acceptance、journal 与 replay

### 5.1 Durable state machine

实现对每Cat只保存一个原子替换、最大6 MiB的Node-private journal document；它不是public
API或Control可解释的lifecycle state machine：

```text
LifecycleJournalDocument {
  checkpoint: LifecycleJournalRecord,
  checkpoint_content_digest: Sha256Digest
}

LifecycleJournalRecord =
  { record_kind: "command", version: 1,
    command: JournalCommandProjection,
    superseded_predecessor: SupersededPredecessor | null,
    state: CommandJournalState }
| { record_kind: "completed_delete_receipt", version: 1,
    receipt: CompletedCommandReceipt }

CommandJournalState =
  { phase: "accepted", stop_fence: EmbeddedStopFence | null }
| { phase: "executing", step: NodePrivateExecutionStep,
    stop_fence: EmbeddedStopFence | null }
| { phase: "terminal", result: ExactCommandResult,
    stop_fence: EmbeddedStopFence | null }

EmbeddedStopFence.state = "installed" | "converted_to_cold_tombstone"
```

`JournalCommandProjection`保留exact canonical command bytes，其Cat/Operation/fingerprint/kind投影每次
decode都要重验；`NodePrivateExecutionStep`只保存有界step name与recovery bytes。危险effect的
typed plan/receipt可存在各installed provider的物理manifest，但都只是Node-private recovery evidence，不得
暴露为Start子状态或Control authority。same-Node Start在原子接受exact successor时清除旧
StopFence；journal不伪造一个已替换的persisted fence state。successful Cold可将其转成
non-executable tombstone。

Node在first physical effect前fsync `accepted`，每个危险effect前先fsync对应recovery identity，
模糊响应后discover exact postcondition，不能盲目rollback/repeat destructive action。terminal exact
response bytes与digest在return前fsync。artifact classification来自transactional physical manifest与complete
inventory，不在journal中再造第二份权威列表。

Agent restart/replacement 在取得固定Host state path的kernel lock、current AgentSession与complete union
inventory后恢复exact journal/physical manifest。partial telemetry、缺/坏journal或incomplete inventory不得猜成
Cold/Killed；foreign/ambiguous evidence quarantine。same-Host dual Agent 必须由 Host lock 与 AgentSession
共同排除。

### 5.2 Query、retry、supersede 与 acknowledgement

```text
LifecycleResultStoredAck {
  version: 1,
  node_id: Id,
  cat_id: Id,
  operation_id: Id,
  request_fingerprint: Sha256Digest,
  terminal_result_digest: Sha256Digest
}
```

- production exact retry/query 由重复 poll 与 result repost实现：terminal result 尚未由 Control ack 时返回/
  提交 original response，不重复 effects；
- same Operation ID/fingerprint 的 active command 只 join/resume single worker；
- successor durably accepted 后，poll中晚到的older command或Node-local exact query返回
  `SupersededOperation {current_operation_id}` 且零 effects；Control 的历史 API replay 从 PostgreSQL row
  返回原结果；
- ack 必须在 exact terminal result 与 product projection 同一 PostgreSQL commit 后发送；错 identity/digest
  ack 零副作用；
- current terminal response保留在checkpoint，直到successor被durably accepted；该原子替换只在bounded
  `SupersededPredecessor`中保留上一个terminal的exact canonical response与digest，不形成无界历史。Node
  effect从这里取得same-Node predecessor的incarnation、retained volume与absence evidence；它足以验证direct
  predecessor并让晚到旧命令返回`SupersededOperation`。CrossNode/HostFence initial target没有本地
  predecessor response；StopFence 的删除/替换仍只由successor规则授权。

Delete 在移除 VMM/frontend/restart source/storage lineage 和 executable checkpoint 前写：

```text
CompletedCommandReceipt {
  version: 1,
  node_id: Id,
  cat_id: Id,
  placement_identity: PlacementIdentity,
  operation_id: Id,
  request_fingerprint: Sha256Digest,
  terminal_response: LifecycleCommandResponse,
  terminal_result_digest: Sha256Digest,
  completed_receipt_digest: Sha256Digest
}
```

receipt 只支持 exact result repost/ACK recovery。上层identity字段必须逐字段等于`terminal_response`，
`terminal_result_digest`必须重算匹配，且response只能是Deleted；它不授权execution、restart、volume
mutation、route、GC或deletion。Node收到exact ack后才删除它。成功Delete不留下executable checkpoint或
deferred destructive GC。

### 5.3 Artifact classification 与 GC

Start/Suspend/Warm/Cold/Delete 的 terminal non-success 返回前，每个 command-created/adopted artifact 必须
durably归入：

```text
ArtifactClassification =
  { kind: "adoptable_cat_state", artifact_id: Id,
    ownership_digest: Sha256Digest }
| { kind: "cat_owned_gc_candidate", artifact_id: Id,
    ownership_digest: Sha256Digest, postcondition_digest: Sha256Digest }
| { kind: "retained_authority_or_data", artifact_id: Id,
    evidence_digest: Sha256Digest }
| { kind: "quarantined_foreign_or_ambiguous", artifact_id: Id,
    evidence_digest: Sha256Digest }
```

per-Cat GC 只消费 exact `cat_owned_gc_candidate`，restart 后幂等继续，并在删除前重验 ownership/postcondition。
Volume、pending pack、`R < L` tail、PersistentDisk state、unknown path、foreign process、authority record、
StopFence 和 restart source 不能是 generic GC candidate。cleanup failure 是 telemetry/typed Cat status，不重开
已 terminal Operation，也不能阻塞 sibling Cat。

本首次 clean release 冻结上述 wire shape，但 installed provider **刻意不生产** `cat_owned_gc_candidate`：当前
Start terminal-retained manifest、Warm terminal/prepared/intent bundle、Volume lineage、quarantine 与 Delete receipt
分别仍是 retry/restart/唯一数据/foreign evidence 或 exact result replay 载体，没有一个满足可独立删除的 typed
ownership + postcondition 合同。所有 production scanner 必须校准为零 candidate；Executing/incomplete artifact
只能降级为 Retained/Quarantine。成功 Delete 继续同步证明零残留且不得 enqueue。因而本 release 不编译空转的
destructive GC worker；首个真实 candidate producer、closed target descriptor、restart-idempotent executor 与 crash
matrix 作为同一后续 vertical 一起进入，不能先落 generic path consumer。

## 6. Terminal response 与状态 postcondition

### 6.1 Response wire

```text
LifecycleCommandResponse {
  version: 1,
  operation_id: Id,
  workspace_id: Id,
  cat_id: Id,
  node_id: Id,
  placement_identity: PlacementIdentity,
  request_fingerprint: Sha256Digest,
  result: NodeResult
}

NodeResult =
  { kind: "runtime_ready", value: RuntimeReadyResult }
| { kind: "start_failed", value: CommandFailedResult }
| { kind: "suspended", value: SuspendedResult }
| { kind: "suspend_declined", value: SuspendDeclinedResult }
| { kind: "suspend_failed", value: CommandFailedResult }
| { kind: "warm", value: WarmResult }
| { kind: "warm_failed", value: CommandFailedResult }
| { kind: "cold", value: ColdResult }
| { kind: "killed", value: KilledResult }
| { kind: "deleted", value: DeletedResult }
| { kind: "needs_intervention", value: NeedsInterventionResult }
```

result variant 必须匹配 command：Start 只返回 runtime_ready/start_failed；Suspend 只返回
suspended/suspend_declined/suspend_failed；Warm 只返回 warm/warm_failed/needs_intervention；Cold 只返回
cold/needs_intervention；Stop只返回killed；Delete只返回deleted/needs_intervention。Cold/Delete的
不可安全收敛结局必须使用带exact retained evidence的`needs_intervention`，不存在generic
`cold_failed`/`delete_failed` public variant。wrong variant是malformed response，Operation保持unresolved。

共享 result evidence：

```text
ExecutionAbsenceProof {
  stop_fence_receipt_digest: Sha256Digest,
  admission_closed_receipt_digest: Sha256Digest,
  dedicated_scope_absence_receipt_digest: Sha256Digest,
  frontend_absence_receipt_digest: Sha256Digest,
  restart_source_absence_receipt_digest: Sha256Digest
}

RetainedEvidence {
  artifact_manifest_digest: Sha256Digest,
  adoptable_count: integer 0..=1024,
  gc_candidate_count: integer 0..=1024,
  retained_authority_or_data_count: integer 0..=1024,
  quarantined_count: integer 0..=1024
}

EffectiveRuntimeReady {
  source_lifecycle_operation_id: Id,
  runtime_incarnation: RandomId128,
  runtime_config_digest: Sha256Digest,
  runtime_ready_receipt_digest: Sha256Digest
}

VolumeTerminalReceipt {
  volume_id: Id,
  disk_id: Id,
  disk_role: "root" | "persistent",
  attachment_id: Id,
  attachment_epoch: FenceEpoch,
  local_durable_generation: Generation,
  remote_durable_generation: Generation,
  authority_receipt_digest: Sha256Digest | null
}
```

每个 `VolumeTerminalReceipt` 必须满足 `remote_durable_generation <= local_durable_generation`。
`RuntimeReady`/`Suspended`/`Warm`的receipt array、`ColdResult.volume_dispositions`与
`DeletedResult.volume_dispositions`分别完整覆盖该command的canonical runtime config/delete
disposition set；`Killed.retained_volume_receipts`与
`NeedsIntervention.retained_volume_receipts`则是按`volume_id`排序、无重复的exact子集，
并且允许为空，不得由缺席推断Unowned或deletable。receipt digest只引用其来源 authority 的
exact immutable receipt，不能由 Node 自行制造。normal release时它精确使用
[Volume Authority §0.1](volume-authority.md#01-atomic-command-receipt-digests) 的
`command_normal_release_receipt_digest`；其他阶段没有closed authority receipt时必须为null。
normal-release `VolumeTerminalReceipt`的volume/disk/role/attachment/epoch及L/R必须逐字段投影自同一个
`CommandNormalReleaseReceipt`及其digested durability proof；尤其L=R=proof remote head generation且pending=0，
不能把合法authority digest与另报的generation拼接。
settlement从Volume Authority的PG immutable command-receipt ledger读取/验证/重算digest；NodeResult只引用
digest与closed projection，不能提供receipt authority或让Control从legacy transition marker补造。

### 6.2 StartCat：RuntimeReady 或 not-running failure

```text
RuntimeReadyResult {
  runtime_incarnation: RandomId128,
  runtime_config_digest: Sha256Digest,
  execution_receipt_digest: Sha256Digest,
  guest_ready_receipt_digest: Sha256Digest,
  volume_receipts: [VolumeTerminalReceipt]
}

CommandFailedResult {
  reason: CommandFailureReason,
  not_running: ExecutionAbsenceProof,
  retained_evidence: RetainedEvidence
}

CommandFailureReason =
  "invalid_local_precondition" | "capacity_unavailable" |
  "volume_authority_rejected" | "image_unavailable" |
  "device_prepare_failed" | "network_prepare_failed" |
  "vmm_failed" | "guest_not_ready" | "snapshot_invalid" |
  "durability_convergence_timeout" | "normal_release_failed" |
  "local_cleanup_failed" | "stored_evidence_conflict"
```

`RuntimeReady` 精确证明：

- expected VMM incarnation 在 dedicated Cat scope 内 executing；
- immutable shape/boot/device/network config 与 config digest 相符；
- 全部 virtio block device、Guest/root、filesystem UUID/mount 与 Guest runtime transport ready；
- 每个 volume 的 owner/attachment epoch 与 Node-local frontend 相符；
- Guest-local network ready；
- lifecycle AdmissionCell 已设置为 RuntimeReady，但所有 Endpoint gates 仍 Closed。

RuntimeReady 不证明 Gateway、Route Controller、Grant、application port 或 Serving。Start 包含 Cold boot、
Suspended resume 与 Warm restore；source/predecessor 决定路径，Control 不编排 intermediate effect。

任何 accepted Start terminal failure 前都必须 strong Stop，并返回 `not_running` 与完整
`retained_evidence`。failure 可以保留已分类、以后 exact same-Node Start 可 adopt 的 inert artifact；不能留下
normally Running runtime 或 unclassified residue。

当Warm restore已转移source准备权威后Start失败，Node不得删除或降级该source：它将exact Warm
intent/prepared/content descriptors、payload/RAM identity、volume receipts、failed Start Operation/fingerprint与
terminal manifest digest封入Node-private retained carrier，并以`StartFailed.retained_evidence`commit。只有
立即后继、same Node/placement/config、以该StartFailed为direct predecessor的
`Start(source=same_node_retry)`可重绑并fresh re-inspect它；缺失、篡改或已被transfer/remove均
fail closed，不允许退化为fresh boot。这些都是一个Start命令的private recovery evidence，不新增
product稳定状态或public中间状态。

同一direct StartFailed的合法Cold/Stop/Delete后继必须先把carrier纯重绑为`Remove`；
Remove authority持久化后才能按exact descriptor删除prepared payload/RAM和retained installed
source。它不能由路径猜测或generic GC代替，也不能先删TerminalRetained manifest丢失
cleanup authority。普通无carrier的StartFailed继续使用各后继原有路径。

### 6.3 SuspendCat：Suspended、Busy 或 not-running failure

```text
SuspendedResult {
  runtime_incarnation: RandomId128,
  runtime_config_digest: Sha256Digest,
  pause_receipt_digest: Sha256Digest,
  local_durability_receipts: [VolumeTerminalReceipt]
}

SuspendDeclinedResult {
  reason: "busy",
  admission_cell_never_closed_receipt_digest: Sha256Digest,
  effective_runtime_ready: EffectiveRuntimeReady
}
```

成功 Suspended 证明：全部 route/work admission Closed、active guards 已 drain；exact VMM verified paused；
Guest 不能执行或提交新 block request；pause barrier 前接受的 block request 已到 local `L`；attachment owner、
epoch、blockd journal 与 local lineage 保留。Relaxed volume 允许 `R < L`。

只有 `admission_policy=require_idle` 且 AdmissionCell 原子检查证明从未 close，才可返回
`SuspendDeclined(Busy)`。此时 compute 仍满足 original RuntimeReady，result 必须保留其
`effective_runtime_ready`；该 Declined Operation 成为 causal head，但不改变 effective Running source 或
route epoch。

一旦 cell 实际 close 或 close 结果模糊，就不得返回 Declined。无法证明完整 Suspended 的命令必须 strong
Stop 并返回 `suspend_failed(not_running)`；旧 route epoch 永不重开。

### 6.4 WarmCat：Host-bound Warm

```text
WarmResult {
  runtime_config_digest: Sha256Digest,
  source_runtime_incarnation: RandomId128,
  warm_snapshot_receipt_digest: Sha256Digest,
  warm_snapshot_manifest_digest: Sha256Digest,
  volume_receipts: [VolumeTerminalReceipt]
}
```

Warm 证明 route/work Closed、所有 retained volume exact `R == L`、WarmRuntimeSnapshot 与 exact
runtime/volume lineage durable且验证成功、VMM 与 Guest-facing frontend 已停止、Guest 不可能执行或写入，并
保留 exact Host-bound restore identity。`warm_snapshot_receipt_digest`绑定command completion；
`warm_snapshot_manifest_digest`另外绑定两阶段terminal manifest中的pre-stop snapshot content、最终
absence proof、volume receipts与exact command identity，二者不得互换。Warm不因VMM exit
自动释放volume ownership。

任一 retained volume 无法达到 `R == L` 时，Node strong Stop、保留 owner/packs/journal/checkpoint/
snapshot evidence，返回 `NeedsIntervention`。非 data-safety 的 terminal failure 可返回
`warm_failed(not_running)`；两者都不能猜 Cold 或删除源。

### 6.5 ColdCat：location-independent Cold

```text
ColdResult {
  runtime_config_digest: Sha256Digest,
  execution_absence: ExecutionAbsenceProof,
  volume_dispositions: [ColdVolumeDisposition],
  local_recovery_dependency_absent_digest: Sha256Digest
}

ColdVolumeDisposition =
  { kind: "normally_released",
    volume: VolumeTerminalReceipt,
    normal_release_receipt_digest: Sha256Digest }
| { kind: "already_unowned",
    volume_id: Id, disk_id: Id, disk_role: "root" | "persistent",
    unowned_epoch: FenceEpoch, remote_head: RemoteHead,
    already_unowned_receipt_digest: Sha256Digest }
```

Cold先完成strong Stop。成功证明每个RootDisk/PersistentDisk都`R == L`，且本命令已完成
exact normal release或闭合了一个已Unowned slot，
VMM、Guest-facing frontend、active blockd/attachment与Host-local recovery dependency均不存在。当本命令
从Owned释放时使用`normally_released`，其`volume.authority_receipt_digest`与外层
`normal_release_receipt_digest`必须是同一exact receipt，且`L == R`。命令开始时已为
Unowned的slot使用identity-only `already_unowned`：不伪造attachment、L或本命令执行的release，
而是绑定current epoch/head及`pristine | prior normal-release`的closed provenance。两种variant
共同组成与immutable config完整1:1、按volume ID排序的集合。

任何卷 `R < L` 都返回 `NeedsIntervention`：保留 unique local data、ownership、pending packs、journal 与
data directory，不 normal release、不 discard、不 takeover。Cold 内部拥有
`Killed -> R == L -> release -> Cold`，Control 不能把它拆成多条 Operation 或 observation settlement。

Cold receipt 是唯一 normal cross-Node Start handoff。它不依赖源 Host 的 snapshot/checkpoint/cache，因而
location-independent。

### 6.6 Private internal StopCat/Killed evidence

本节记录current executor的private strong-stop安全机制。Node-Control可以用独立Stop command与Killed
terminal承载causal/`ExecutionStopped` evidence；ADR-0057只禁止把它们投影成产品action、state、condition或
可见Operation head。run/suspend/warm/cold/destroy需要停止旧执行时，同样在原动作内部安装StopFence并嵌入
相应absence proof。product API不能创建Stop Operation，product Operation GET对private maintenance Stop返回404。

```text
KilledResult {
  stopped_runtime_incarnation: RandomId128 | null,
  execution_absence: ExecutionAbsenceProof,
  stop_fence_receipt_digest: Sha256Digest,
  retained_volume_receipts: [VolumeTerminalReceipt],
  retained_evidence: RetainedEvidence
}
```

可达且仍拥有 authoritative Node execution boundary 的 Node 对 accepted Stop 没有 Cat-local business failure
variant。它必须：

1. 在 first destructive effect 前安装 durable StopFence；
2. join current command worker，或以 fence neutralize stale worker/effect；
3. 在 AdmissionCell 关闭 lifecycle admission 与全部 Endpoint gate；
4. cancel 并在 `grace_deadline` 前等待 guards/Guest graceful shutdown；
5. 到期后强制停止 dedicated Cat 的完整 VMM/Guest execution scope，即使这会断开 HTTP/WebSocket；
6. 关闭 Guest-facing block frontend，阻止 systemd/old checkpoint/stale worker 重启或复活；
7. 返回 Killed，并保留 fence，直到 same-node Start atomic replace、Delete remove 或 Cold 转为 source
   tombstone。

Stop 不等待 inert artifact GC、normal release、`R == L` 或 publisher drain。StopFence 下允许 non-serving
publisher 把已存在的 `L` 推进到 `R`，但不能重开 frontend/VMM/gate。丢失 Host 或丢失 Host-global execution
boundary 时 Node 不能返回 Killed；结果保持 unknown，只有 §8 HostLost 可在外部终结。

current `Killed` wire是private execution-safety receipt/causal evidence。它不是product condition、stable
state、可见head或product successor，不能直接序列化给用户；其内部名称本身不是发布阻断项。

`retained_evidence`始终必填；即使一个volume都未保留，successor也不得从缺少manifest推断
“没有本地artifact”。`retained_volume_receipts`是按`volume_id`排序、无重复且属于exact
runtime config的子集，并允许为空；它只
列出Stop完成后此Node仍持有authority/local evidence的卷。Stop可能发生在Start尚未acquire任何卷、仅acquire
部分卷或部分卷已经normal release之后，因而不能伪造完整volume set。后续same-Node Start按该子集逐卷选择
`same_node_owned`，其余卷必须提供`normal_unowned`；Control仍以current Volume Authority逐卷复核。

### 6.7 DeleteCat：Deleted resource terminal

```text
DeletedResult {
  execution_absence: ExecutionAbsenceProof,
  volume_dispositions: [CompletedVolumeDisposition],
  destructive_cleanup_absent_digest: Sha256Digest
}

CompletedVolumeDisposition =
  { kind: "persistent_retained_detached",
    volume: VolumeTerminalReceipt,
    normal_release_receipt_digest: Sha256Digest }
| { kind: "persistent_already_detached",
    volume_id: Id, disk_id: Id,
    already_unowned_receipt_digest: Sha256Digest }
| { kind: "root_normally_deleted",
    volume: VolumeTerminalReceipt,
    delete_completion_receipt_digest: Sha256Digest }
| { kind: "root_already_unowned_deleted",
    volume_id: Id, disk_id: Id,
    already_unowned_receipt_digest: Sha256Digest,
    delete_completion_receipt_digest: Sha256Digest }
| { kind: "root_disposable_tail_deleted",
    volume_id: Id,
    disk_id: Id,
    previous_attachment_id: Id,
    previous_attachment_epoch: FenceEpoch,
    disposable_authorization_id: Id,
    authorization_consumed_receipt_digest: Sha256Digest,
    delete_completion_receipt_digest: Sha256Digest,
    local_lineage_absence_digest: Sha256Digest }
```

三个字段分别严格使用Volume Authority §0.1的domain：`normal_release_receipt_digest`是
`command_normal_release_receipt_digest`，`delete_completion_receipt_digest`是
`command_delete_completion_receipt_digest`，`already_unowned_receipt_digest`使用Cold/Delete各自独立的
already-Unowned domain，`authorization_consumed_receipt_digest`是
`command_disposable_authorization_consumed_receipt_digest`。不能对旧receipt、projection或调用方JSON直接hash。

Delete 总是先 strong Stop；所有 non-success 都必须有 `not_running`。请求必须列出完整 volume set，Root
恰好一条 `discard_with_cat`，每个 Persistent 恰好一条 `retain_detached`。Node 在消费任何 Root destructive
authority 前发现并闭合完整 Persistent set。

每个 PersistentDisk必须停止写入、settle accepted writes到final `L`、达到`R == L`；Owned
slot做normal release并返回`persistent_retained_detached`，命令开始时已Unowned的slot使用
`persistent_already_detached`的closed provenance，不伪造attachment/release。任何PersistentDisk失败或
`R < L`都返回NeedsIntervention，保留其
owner/packs/journal/data，并且 Root 尚未 discard。

默认 Root 不要求 `R == L`：

- 若Owned且`R == L`，可走ordinary exact release/delete；若已Unowned，可在closed
  already-Unowned provenance下begin/delete并返回两个digest；
- 若 `R < L`，必须先取得 `DisposableRootDeleteAuthorization`，它 exact 绑定本 Delete Operation、Node、
  Cat、placement、request fingerprint、Root volume/attachment/owner epoch/head、`discard_with_cat`与已完成的
  Persistent disposition set。可达Node arm另绑定completed strong Stop result/proof；HostFence arm只绑定Active
  event、interrupted Operation与HostLost digest，不伪造strong Stop。exact closed schema见
  [Volume Authority §11.2](volume-authority.md#112-放弃本地-tail-的-disposable-root)。Volume Authority
  原子 consume 后把 exact Owned lineage 转为 Deleting并提高/fence epoch、持久 receipt；只有 commit 后 Node
  才删除该 local lineage，且必须在 Deleted 前完成。

该例外只用于本 Delete 的 default Root。PersistentDisk、Cold、migration、unknown/conflicting lineage 与有
live DiskSnapshot root 的 volume 都 fail closed。Deleted 证明无 Cat execution/frontend/open gate/restart
source；Persistent 全部 R=L/released/detached；Root 完成 normal 或 exact authorized disposition；无 deferred
destructive cleanup。Node 不删除 Control product row；Control settlement transaction完成产品 terminal
projection。Node 写 §5.2 non-executable CompletedCommandReceipt 后才能移除 executable checkpoint。

### 6.8 NeedsIntervention

```text
NeedsInterventionResult {
  attempted_target: "warm" | "cold" | "delete",
  reason: InterventionReason,
  not_running: ExecutionAbsenceProof,
  retained_evidence: RetainedEvidence,
  retained_volume_receipts: [VolumeTerminalReceipt]
}

InterventionReason =
  "retained_local_tail" | "persistent_disk_not_remote_durable" |
  "authority_ambiguous" | "foreign_or_ambiguous_residue" |
  "warm_snapshot_ambiguous" | "normal_release_ambiguous" |
  "destructive_authorization_rejected" | "local_lineage_absence_unproven"
```

NeedsIntervention 是 terminal 并释放 external lane，但不是 stable state。Control 必须从 exact reason、role 与
receipt 投影 §4.4 successor restrictions；不得把它归一化为 Cold/Killed/Deleted 或 generic failure。
`retained_volume_receipts`同样是exact runtime config的排序子集且可为空；未列出的卷不能据此推断Owned、
Unowned、released或deletable，后继仍必须从Volume Authority取得exact typed input。

## 7. Route 两条 lane 与 shared AdmissionCell

### 7.1 独立 lane

Route Controller 从 Endpoint metadata 自动派生 per-Endpoint `EnableRoute`/`DisableRoute`；用户不为
Endpoint 发 lifecycle command。系统同时只有：

- 每 Cat 一条 lifecycle lane；
- 每 Endpoint 一条 route Operation lane；
- 每 Cat 一个 Node-local `AdmissionCell`，供 lifecycle close、route install 与 guard acquire 线性化。

```text
LifecycleAdmission =
  { kind: "closed", closing_operation_id: Id }
| { kind: "runtime_ready",
    source_lifecycle_operation_id: Id,
    runtime_incarnation: RandomId128 }
```

`ServingBinding` 的 exact wire 只由 [Route Grant v2 §7](route-grant-v2.md#7-route-commandgate-close-与-lifecycle-interlock)
定义；AdmissionCell compare 使用整个 binding，不能另建缺少 Workspace/Cat/Node identity 的 lifecycle
projection。

AdmissionCell critical section 不做 network/database/VMM/filesystem/fsync I/O，也不持锁跨 await。Grant
verification后的 binding compare、gate check 和 guard increment 在同一 cell 中原子完成。

### 7.2 Lifecycle/Route race

Control 只从 current chain head 的 `effective_runtime_ready` 且无 leaving-Running unresolved Operation 时生成
EnableRoute/签名。接受 Suspend/Warm/Cold/Stop/Delete 的同一 Cat-row transaction必须创建 lifecycle
Operation并停止新的 signing/Enable generation。

每个 leaving-Running command 在 Node accepted checkpoint 后的 first local effect 是在 AdmissionCell 关闭
lifecycle admission与全部 Endpoint gate，再在 cell 外 cancel/drain。竞态结果固定为：

```text
EnableRoute first -> 可安装 -> lifecycle close 随后关闭并 drain
lifecycle close first -> late Enable sees Closed/stale source -> zero effects
```

Stop 不等所有 route RPC；late route result 只能存为 historical route result，不能恢复 current Serving。
strong Stop 的 grace deadline 后可 force-stop Guest/VMM，即使 guard 未归零。`RequireIdle` Busy 是唯一
non-destructive exception。

Start success 后全部 gates Closed。任何实际或模糊 closed Endpoint 必须 burn route epoch 后 fresh Enable；
同一 runtime incarnation 也不能复用 old epoch。

### 7.3 AgentSession 与 effective RuntimeReady

Serving receipt/installed binding 必须绑定 current AgentSession 的 exact `admission_session_epoch`。Agent
replacement 后 process-memory AdmissionCell 默认 Closed，旧 Serving 因 session epoch 不匹配自动失效；Route
Controller burn route epoch 并提交 fresh Enable。Route Grant v2 不新增 session claim；fresh route epoch +
runtime incarnation 已使旧 Grant 无法匹配新 gate。

正常 RuntimeReady 的 effective projection 是本 Operation：

```text
effective_runtime_ready = {
  source_lifecycle_operation_id: RuntimeReady.operation_id,
  runtime_incarnation,
  runtime_config_digest,
  runtime_ready_receipt_digest
}
```

`SuspendDeclined(Busy)` 会成为新的 causal head，但仅当 cell-never-closed proof有效时继承 result 中的 original
effective RuntimeReady。Signer 比较 current head 投影的 `effective_runtime_ready` 与 ServingBinding source，
而不是简单要求 `Serving.source_lifecycle_operation_id == current_head.operation_id`。任何实际/模糊 close、
Agent replacement 或 runtime incarnation改变都清空该投影/使 Serving失效并 burn epoch。

Signer/resolve 消费 exact current Serving receipt、current lifecycle head projection、current AgentSession 与
fresh full inventory attestation；不消费 Running/route observation。Grant claims、Gateway cache、key rotation、
machine tunnel 与 per-request guard 的 exact wire 继续由 Route Grant v2 冻结。

## 8. HostLost 外部例外

normal lane 只由 authenticated NodeResult terminalize。唯一外部例外是 trusted Active
`HostFenceEvent`。Control transaction 必须锁 exact unresolved Operation、Cat chain head、NodeIdentity、event
与 volume authorizations，并写：

```text
LifecycleTerminalResult = {
  kind: "host_lost",
  host_fence_event_id: Id,
  interrupted_operation_id: Id
}
```

其 digest 仍按 §2.2。event 必须证明 exact immutable Host 已隔离；heartbeat timeout、suspicion、AgentSession
replacement、Controller cancellation、新的product mutation（包括destroy）或新 placement 都不能终结 lane。HostLost 不制造 Cold、
Killed、release receipt 或 runtime absence proof。

唯一普通 recovery successor 是 Start + `HostFenceRecovery`，target 新 placement，并逐卷消费 exact takeover
authorization。Strict 从 remote R恢复；Relaxed 只能从 remote R恢复并报告独立 data-loss risk telemetry。旧 Host
返回后旧 epoch 永久无法 publish/serve。HostLost terminal/wire与per-volume takeover primitives已
组成，但current Control admission显式返回`HostFenceRecoveryUnavailable`；该successor现在
不可用。trusted external HostFenceEvent producer、exact admission composition与真实云/BMC
qualification必须作为同一独立release gate闭合，不得由timeout补齐。

## 9. Runtime inventory、status 与计量

Atomic release使用clean-slate `RuntimeInventoryReport`，不发送superseded `NodeObservation`。Full/Partial都绑定
current `SessionBinding`、report ID、session-local monotonic sequence与reported time。Full另带session-local
inventory epoch、scan ID、canonical inventory digest、按Cat ID排序的完整Cat facts与按artifact ID排序的
unattributed artifact classifications；Partial只能引用exact current full epoch并更新明确列出的Cat subset，不能
覆盖、刷新或制造complete scan/attestation。

每个Cat fact只报告current placement、closed atomic command-journal phase/identity/digests、physical
state/runtime incarnation、artifact manifest/classifications、逐卷L/R摘要与typed conditions。wire不含Desired/
revision/spec、reconcile step、legacy RuntimeCheckpoint、route gate/guard、Operation settlement字段或inventory
read cursor。Route Serving由独立Route receipt，lifecycle result只由command result authority回答。

Full inventory仍建立session-bound admission attestation。report rejection、staleness、sibling Cat corruption或
Partial失败不能完成、失败、rollback、supersede或reopen lifecycle/route Operation。Control不从physical/journal/
volume telemetry重建NodeResult。terminal Start后的later runtime failure是新的telemetry/policy input，不改写
历史Start；lane空闲后才可请求新Operation。

用户状态投影来自terminal lifecycle head与最新telemetry的组合：stable product state来自exact result；
action-specific failure、NeedsIntervention/HostLost可成为condition，`ExecutionStopped`不能；
health/degraded/drift来自runtime inventory。计量可继续读可信
physical/cgroup事实，但不能因此创造lifecycle authority。

## 10. Clean-slate cutover

本 release 只有一个空 target schema 与一套 atomic wire：

1. offline 构建并验证 exact Controller/Node/Route/Volume bundle；
2. 停止所有旧写入者与数据面组件；
3. 删除旧 Desired/reconcile/observation-settlement schema、parser、write path 与 credential；
4. 清空开发 product/runtime state，创建 empty atomic schema 17；
5. 所有 Node 以 Host lock + fresh AgentSession + complete inventory、AdmissionCell Closed 启动；
6. Node/Route/Volume compatible version全部 ACK 后才启动 API/Gateway。

不做旧 Desired row、Operation、checkpoint、route gate、runtime 或 credential migration；不提供 dual write/read、
translator、fallback、feature flag 或 mixed-version window。unknown/old checkpoint fail closed，不能导入为 command
journal。ChunkStore object format与Guest ABI若未改变可继续使用，但 cutover 不依赖旧 product data。

Runtime Reconciliation v1 只保留 NodeIdentity、AgentSession、Host lock、complete inventory/attestation 等明确
共享 foundation；其 Desired lifecycle planner、revision supersede、RuntimeCheckpoint step wire、Observation
settlement 与 Operation state不是本 release authority。

## 11. Acceptance matrix

### 11.0 Product vocabulary（blocking）

- [ ] 产品mutation route、request/response、Operation GET、CLI与用户文档的action闭集只有
  `create/run/suspend/warm/cold/destroy`；private `start/stop/delete/Killed`均有positive absence test，Route
  resolve只返回`run_required`而不返回`wake_required`。
- [ ] create在同一产品Operation中包含Genesis `EnsureRunning`；run只处理已有Cat从
  Cold/Warm/Suspended回Running，且两者都不制造Starting/Resuming等产品state。
- [ ] internal strong stop evidence不会成为product action、state、condition或visible Operation head；private
  maintenance Stop/Killed若保留，其Operation GET为404，其他产品动作只投影原action-specific outcome。
- [ ] product adapter与Node-Control wire有明确边界；内部source、journal、volume authority、StopFence和
  artifact evidence均不能被product Operation直接序列化。

### 11.1 Command protocol与causal chain

- [ ] 多 Control replica并发只产生一条 unresolved lifecycle Operation；loser 在命令可进入任何poll batch前
  返回`LifecycleOperationInProgress`。
- [ ] 任一product mutation unresolved期间，其他mutation不排队、不preempt、不cancel、不进入poll；result已
  收到但PG未commit仍不放行successor。
- [ ] Genesis遇任一 local Cat conflict/residue零effect拒绝；SameNode exact high-watermark mismatch零effect拒绝。
- [ ] Operation ID复用但payload/target/predecessor/fingerprint不同，返回identity conflict且零effect。
- [ ] API decoder、Rust `NodeResult`、Control projection与SQL closed enums只接受§6.1列出的
  terminal set；`cold_failed`/`delete_failed`及任何legacy variant在schema/startup门即被拒绝。
- [ ] §4.4 private causal matrix在Control与Node完全一致；product builder只映射ADR-0057六动作，不提供
  product Stop/Killed。run failure或private Killed的empty/partial retained set与internal successor按exact
  predecessor + current Volume Authority逐卷构造，不整组复制旧authority。
- [ ] normal cross-Node run只接受exact Cold + 与每卷同variant的
  `normally_released | already_unowned` disposition digests；Warm/failure/NeedsIntervention不能替代。
- [ ] Node在first effect前fsync accepted，return前fsync terminal；每个effect边界kill/restart只resume同命令。
- [ ] wrong/stale session的poll/commit零write；batch精确echo session/sequence，仅返回本Node已commit的
  unresolved command，按Cat排序且不重复；Node不能通过poll自造或claim Operation。
- [ ] deadline/EOF/malformed/result或ACK loss保持unknown；exact repoll/repost返回original result且不重复effect。
- [ ] successor accepted后poll中晚到old command返回SupersededOperation且不作用于新runtime；Control历史replay仍读PG。
- [ ] observation rejection或sibling Cat错误不影响该命令settlement。
- [ ] destroy的内部teardown移除checkpoint后由CompletedCommandReceipt replay；只有exact result-stored ack可GC该receipt，ack不清
  StopFence且不授权cleanup。
- [ ] lifecycle command fingerprint、每terminal result digest与CompletedCommandReceipt digest都有独立
  fixed vectors，不只有roundtrip/self-hash test。

### 11.2 Run/Route/Suspend

- [ ] Cold boot、Suspended resume、Warm restore使用同一internal `EnsureRunning`接口和exact typed source；
  ambiguous physical success被discover/adopt或strong stop，不重复创建。
- [ ] run success证明local RuntimeReady但不依赖Gateway/route/app port；所有Endpoint gate保持Closed。
- [ ] acquire/provision/device/network/VMM/Guest每个失败点只在strong stop + residue全分类后返回run failure。
- [ ] Warm-origin run在source transfer后失败保留exact non-executable carrier；只有immediate
  same-node retry + direct run-failure predecessor可重绑，tamper/missing/replay零restore且不回退fresh boot。
- [ ] Warm-origin run failure的product后继cold/destroy（以及private maintenance Stop）在各自terminal前以同一exact
  retained carrier执行descriptor-safe Remove；不留prepared payload/RAM，也不先删manifest丢失
  cleanup authority。
- [ ] EnsureRunning Volume grant sequence 0只做initial acquire/adopt/takeover；后续严格单调round只做
  exact renewal并重放原receipt，不生成额外Operation或lifecycle state。
- [ ] Route Controller从Endpoint metadata自动派生操作；单Endpoint变化不rerun并且不churn sibling Endpoint。
- [ ] lifecycle Operation acceptance与停止fresh signing/Enable generation同PG transaction。
- [ ] Enable-first随后被close；close-first使late Enable zero-effect；late route result不恢复Serving。
- [ ] Serving绑定exact AgentSession/admission session epoch；Agent replacement默认全Closed、old Serving失效、burn
  epoch后fresh Enable；Grant无需session claim。
- [ ] Suspend RequireIdle Busy只在cell从未close时返回，并保留original effective RuntimeReady/source与route
  epochs；Signer按head projection比较。
- [ ] 任一actual/ambiguous close或Agent replacement使old effective Serving失效并提高epoch。
- [ ] Suspend success证明VMM paused、Guest不能写、accepted writes到L；Relaxed R<L允许。其他failure先strong
  Stop并not-running。

### 11.3 Warm/Cold/internal strong stop

- [ ] Warm要求每个retained volume R=L、exact verified snapshot、VMM/frontend absent；Warm仍Host-bound且不隐式
  release ownership。
- [ ] Cold要求Root+全部Persistent R=L，每卷结果为exact normal release或closed already-Unowned，且无
  Host-local recovery dependency；任一R<L返回
  NeedsIntervention且unique data/authority完整保留。
- [ ] Cold可在任意eligible Node以remote durable state + source Cold mixed disposition receipts +
  Cold-window current `Active + Unowned` slots运行；Control不由absence observation拼Cold。
- [ ] 需要strong stop的产品动作在graceful path和grace timeout force path均嵌入exact
  `ExecutionStopped` evidence；force path可断active HTTP/WS，但不存在product Stop/Killed Operation。
- [ ] StopFence neutralize stale worker/systemd/checkpoint resurrection；non-serving publisher可L->R但不能打开
  frontend/VMM/gate。
- [ ] ExecutionStopped proof不等R=L/release/GC；grace deadline与data convergence deadline互不制造对方结果。
- [ ] Node/Host execution boundary lost时不返回false absence proof；只有Active trusted HostFenceEvent可terminalize HostLost。

### 11.4 Destroy/storage/GC

- [ ] destroy在任何destructive disposition前strong stop并发现complete Persistent set。
- [ ] 每个Persistent必须R=L；Owned slot normal release，已Unowned slot使用closed provenance，两者均
  retained detached；任一Persistent失败时Root仍未discard。
- [ ] destroy的Root normal-release、already-Unowned与disposable-tail三条路径均保留exact prior authority
  并产生独立delete-completion digest；不得从目录缺席推断completion。
- [ ] default Root R<L不要求upload；仅exact disposable authorization consume + epoch fence后可删local lineage。
- [ ] Persistent、Cold、migration、unknown/conflicting disk、live snapshot root不能使用Root discard authority。
- [ ] crash matrix覆盖Persistent drain/release、Root authorization consume、local lineage delete、Deleted result、PG
  settlement、CompletedReceipt ack；每点均不重复危险effect或丢失unique Persistent data。
- [ ] Deleted无execution/frontend/gate/restart source/storage lineage/deferred destructive GC；Control可在exact
  result settlement中退休active membership/capacity projection。
- [ ] 本 release 的installed Full/Partial/startup scanner校准为零Cat-owned candidate；Executing/incomplete只降级为
  Retained/Quarantine，成功Delete同步零残留且不enqueue。
- [ ] 首个真实generic GC vertical同时提供exact Cat-owned producer、closed descriptor target、restart ownership/
  postcondition重验与crash matrix；不得删除Volume/pending pack/R<L tail/Persistent/foreign evidence/StopFence/
  successor resource，也不得阻塞sibling Cat。（本 release deferred。）

### 11.5 Host/clean release/gates

- [ ] Host lock与AgentSession排除same-Host dual Agent；complete inventory校准missing/corrupt/ambiguous evidence且
  partial heartbeat不能制造attestation。
- [ ] timeout/suspicion/cancel不能terminalize lane或授权takeover；Active HostFenceEvent + per-volume auth才可
  HostLost recovery。
- [ ] old Desired/reconcile/observation-settlement、`cat_generation` Route-v1 claims、legacy
  Node cleanup/checkpoint与desired-revision Volume-transition parser/export/write path从exact release删除；
  mixed version启动失败，无migration/dual authority。
- [ ] `./scripts/quality.sh full`通过；Node/block/frontend变更的exact clean commit通过native x86_64 Linux gate，
  覆盖systemd scope、Cloud Hypervisor、两种block frontend、四态、route race、Agent restart与response loss。

## 12. Closed public error set

pre-acceptance/API errors不结算 Operation：

```text
AtomicLifecycleError =
  { code: "malformed_payload", json_pointer: AsciiText, message: AsciiText }
| { code: "unsupported_version", supported_version: 1 }
| { code: "limit_exceeded", limit: AsciiText, maximum: integer }
| { code: "authentication_failed" }
| { code: "wrong_node", expected_node_id: Id }
| { code: "lifecycle_operation_in_progress",
    operation_id: Id, command_kind: LifecycleCommandKind }
| { code: "operation_identity_conflict", operation_id: Id }
| { code: "stale_operation", current_operation_id: Id | null }
| { code: "illegal_successor", predecessor_kind: TerminalResultKind,
    command_kind: LifecycleCommandKind }
| { code: "superseded_operation", current_operation_id: Id }
| { code: "conflicting_terminal_result", operation_id: Id }
```

`TerminalResultKind` 是 §6 `NodeResult.kind` 加 `host_lost` 的 closed string set。Node only errors 必须在
accepted checkpoint前返回；accepted 后业务结局只能是 §6 terminal NodeResult或结果unknown。error message不得
包含credential、Host path、token、raw journal、volume tail或其他secret。
