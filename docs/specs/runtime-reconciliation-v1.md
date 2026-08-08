# Runtime Reconciliation v1

- 状态：Target contract；尚未实现
- Authority：[ADR-0040](../decisions/0040-level-triggered-runtime-reconciliation.md)
- 生命周期：[runtime-lifecycle.md](../runtime-lifecycle.md)

本文定义 Control Plane 与 Node Agent 之间最小、可测试的收敛合同。传输可以是
heartbeat、long-poll 或普通 GET；正确性不得依赖通知必达、连接不断或消息只到达一次。

文中的 MUST/MUST NOT 是上线条件。

本文中的schema冻结逻辑domain/wire事实、验证和digest；它不规定SQL表/索引、repository分层、Rust私有
字段布局或日志格式。V1没有兼容tag、feature flag、任意extension map或未来variant占位。

本规格的共享合同集合是§2的身份/session/attestation、§3的Desired及全部嵌套类型、§5/§10的
checkpoint/observation/condition物理证据、§12的Operation以及§16的digest/error类型。§3.3的
`ApiIdempotencyResult`和§9的HostFence/authorization只说明跨authority事务关系；它们分别由public API
和[Volume Authority](volume-authority.md)冻结，不属于本共享合同集合。

## 1. 身份与顺序

- `desired_revision`：每 Cat 单调递增、永不复用的 64-bit 正整数。
- `placement_epoch`：每次 placement owner 变化时单调递增。
- `runtime_incarnation`：每次创建 VMM 前生成并落盘的 128-bit 随机值。
- `agent_instance_id`：每次 Agent 进程启动生成的 128-bit 随机值。
- `agent_session_epoch`：每 Node 单调递增的服务端 session epoch。
- `heartbeat_sequence`：一个 Agent instance 内从 1 严格递增。
- `attachment_epoch`：MetadataStore 用于 RWO writer fencing 的单调 epoch。
- `route_epoch`：每个 Endpoint 的单调 serving epoch。binding变化时递增；任何实际关闭的gate若要
  重开，也必须先由新的完整Desired递增。只检查到Busy且从未close时不递增。

这些值分别阻止不同的 ABA，不得互相替代。新 revision 不证明旧 Host 已停止；Agent
restart 不改变 placement；Route TTL 不改变 attachment epoch。

### 1.1 V1 wire 基础类型

本规格中的共享对象都使用 UTF-8 JSON。下表和后文 schema 是 V1 的完整逻辑 wire 合同；数据库可以
拆表，Rust 可以使用 newtype，但不能改变 wire 值：

| 逻辑类型 | JSON wire 与验证 |
|---|---|
| `ContractVersion` | JSON integer；本规格只接受 `1` |
| `Id` | JSON string；1..=128 个 ASCII bytes，只允许 `[A-Za-z0-9._:-]`，区分大小写，不做 Unicode 归一化 |
| `AsciiText` | JSON string；1..=512 个 printable ASCII bytes（`0x20..=0x7e`） |
| `JsonPointer` | 0..=512 个 printable ASCII bytes；必须是空string（根）或合法RFC 6901 pointer |
| `RandomId128` | 32 个小写十六进制字符，表示非全零16 bytes；不带连字符或`0x` |
| `NodeBootId` | 把 Host boot UUID 解析为 16 bytes 后按 `RandomId128` 编码 |
| `Revision` / `Epoch` / `Sequence` | JSON integer `1..=18446744073709551615`；禁止 `0`、负数、浮点数和 JSON string |
| `U64` | JSON integer `0..=18446744073709551615` |
| `Generation` | `U64`；只用于volume/local/remote generation |
| `FenceEpoch` | `U64`；只用于可能从0开始的MetadataStore attachment/lease epoch |
| `UnixMillis` | JSON integer `0..=9223372036854775807`，从 Unix epoch 起的毫秒；Control Plane freshness 只使用 PostgreSQL 写入的值 |
| `Sha256Digest` | JSON string `sha256:` 加 64 个小写十六进制字符 |
| `KeyId` | 64 个小写十六进制字符；等于Ed25519 SubjectPublicKeyInfo DER的SHA-256，不带`sha256:`前缀，以保持Route Grant v2 `kid` wire |
| `HostPath` | 1..=4096 bytes 的绝对 UTF-8 路径；禁止C0/DEL、`.`/`..` path component和尾随`/`（根目录`/`除外） |
| `Hostname` | 1..=253 bytes的小写ASCII DNS名；每个label 1..=63且只含`[a-z0-9-]`、首尾为`[a-z0-9]`；禁止端口、路径和尾点 |
| `Ipv4Address` | 无前导零的 canonical dotted-decimal IPv4，例如 `10.240.0.6` |
| `MacAddress` | 六组小写十六进制 octet，例如 `02:ca:0a:f0:00:06` |

所有 object 字段都必填；后文写为 `T | null` 的字段也必须出现，并显式编码为 JSON `null`。所有 object
拒绝未知字段和重复 key。结构化 one-of 使用内部 tag `"kind"`；唯一例外是§16.4
`ContractErrorDetail`，其`"code"`同时是稳定错误码和union tag。简单无 payload 枚举使用下文列出的
snake_case JSON string。数组保留 wire 顺序，并按各 schema 指定的稳定 key 严格升序；重复 key、漏排或
逆序都是`malformed_payload`，接收方不能替调用方重排后接受。字符串不得包含控制字符；除`HostPath`
和人读`message`允许非ASCII外，共享合同字符串都必须是ASCII。

## 2. 可信 Node 与 AgentSession

Node 不能用注册请求中的 `node_id` 自证身份。Node 上线前，IaC 或管理员必须先在 Control
Store 建立：

```text
NodeIdentity {
  version: 1,
  node_id: Id,
  immutable_host_id: Id,
  credential_id: Id,
  credential_binding: CredentialBinding,
  state_path_id: Id,
  state: "provisioned" | "retired"
}

CredentialBinding =
  { kind: "public_key", public_key_spki_sha256: Sha256Digest }
| { kind: "provider_principal", provider: Id, principal: AsciiText }
```

`credential_binding`是严格one-of；两个variant的字段不能同时出现。`public_key_spki_sha256`覆盖
SubjectPublicKeyInfo DER，而不是PEM文本。`provider`是adapter的稳定名字，`principal`是该provider
已经认证的不可变principal ID。`state_path_id`只是provisioner绑定的逻辑ID，不暴露或允许注册请求
覆盖Host路径。

每个 Node 使用独立 credential。注册端同时验证 credential、`node_id` 和
`immutable_host_id` 的预置绑定；共享 fleet token、调用方任意指定 `node_id`、仅凭
hostname/IP 注册都不允许。credential 轮换是对同一 `NodeIdentity` 的显式管理操作。

Agent 在读取任何 runtime state 前，必须在由 `state_path_id` 决定的固定、受保护路径取得
Host 级 kernel 排他锁，并核对本地 root-owned identity。命令行更换 state directory 不能绕过
排他锁。同一 Host 的第二个 Agent 必须启动失败。

控制面每个 Node 只保存一个当前 session：

```text
AgentRegistrationAttempt {
  version: 1,
  node_id: Id,
  immutable_host_id: Id,
  node_boot_id: NodeBootId,
  agent_instance_id: RandomId128,
  registration_attempt_id: RandomId128,
  expected_agent_session_epoch: Epoch | null
}

AgentSession {
  version: 1,
  node_id: Id,
  immutable_host_id: Id,
  node_boot_id: NodeBootId,
  agent_instance_id: RandomId128,
  agent_session_epoch: Epoch,
  registration_attempt_id: RandomId128,
  lease_deadline_unix_ms: UnixMillis
}
```

首次注册的`expected_agent_session_epoch`必须为`null`；replacement必须是当前精确epoch。同一
`(node_id, registration_attempt_id)`只能对应一个完整`AgentSession`，payload任一其他字段不同都返回
`wrong_session`，不能把它当作新attempt。`agent_session_epoch`和`lease_deadline_unix_ms`由Control
Plane按PostgreSQL时间分配；Agent请求不能提供或延长deadline。

一次成功的全量inventory还为当前session建立独立的签发证明：

```text
AdmissionInventoryAttestation {
  version: 1,
  node_id: Id,
  agent_session_epoch: Epoch,
  inventory_epoch: Epoch,
  inventory_digest: Sha256Digest,
  inventory_read_position: Sequence,
  accepted_at_unix_ms: UnixMillis
}
```

`inventory_epoch`在同一session内从1单调递增。`inventory_read_position`是该bounded scan开始时
Control Plane完整assigned-spec读取返回的不可复用服务端位置；full scan必须再读同一位置仍覆盖完整
集合后才能提交，不能用Node本地时间或目录游标代替。`accepted_at_unix_ms`由PostgreSQL写入。后续
partial heartbeat只引用该epoch并upsert具体Cat，不能覆盖这条attestation。Route signer同时检查fresh
attestation与fresh per-Cat observation；不要求每次heartbeat重新做全量scan。

注册步骤如下：

1. Agent 先在 Host lock 下 fsync上述完整`AgentRegistrationAttempt`，再发 RPC。
2. `(node_id, registration_attempt_id)` 唯一；同一 attempt 的重复请求返回同一个 session，不重复提高
   epoch。
3. 同一 Host 上的新进程先重试本地遗留 attempt，解析上次模糊结果；随后可用精确
   `expected_agent_session_epoch` 和新 attempt 做 CAS replacement。Host lock 证明旧本地进程已退出。
4. 不同 Host 不能 replacement 同一 `node_id`。它必须先经过显式 retire/fence 和 reprovision，
   取得新的 NodeIdentity/credential。
5. heartbeat、desired 读取和 observation 都绑定当前 session。新 session 成功后，旧 session
   的所有请求永久拒绝。

## 3. DesiredRuntimeSpec

```text
DesiredRuntimeSpec {
  version: 1,
  workspace_id: Id,
  cat_id: Id,
  desired_revision: Revision,
  target: "running" | "suspended" | "warm" | "cold" | "deleted",
  placement: AssignedPlacement,
  runtime: RuntimeConfig,
  volumes: [VolumeIntent],
  endpoints: [EndpointIntent],
  transition: RuntimeTransition,
  spec_digest: Sha256Digest
}

AssignedPlacement {
  kind: "assigned",
  node_id: Id,
  placement_epoch: Epoch
}

RuntimeConfig {
  vcpus: integer 1..=4294967295,
  memory_bytes: integer 1..=18446744073709551615,
  boot_image_digest: Sha256Digest,
  guest_config_digest: Sha256Digest,
  network_config: NetworkConfig
}

NetworkConfig {
  kind: "isolated_ipv4",
  network_id: Id,
  guest_mac: MacAddress,
  guest_ipv4: Ipv4Address,
  prefix_length: 30,
  gateway_ipv4: Ipv4Address
}

RuntimeTransition =
  { kind: "cancel_and_drain" }
| {
    kind: "require_idle",
    attempt_id: RandomId128,
    source_revision: Revision,
    source_runtime_incarnation: RandomId128
  }
```

V1每Cat使用一个`/30`，`guest_ipv4`与`gateway_ipv4`必须属于同一子网、互不相同且都不是network或
broadcast address。`guest_mac`必须是locally administered unicast MAC。Host tap名字和ownership token
是物理inventory事实，不进入Desired；它们由Node分配并通过§10.2 observation闭合。`network_id`是
该Guest-facing配置的稳定identity，创建后不复用；地址/MAC变化必须使用新`network_id`和新revision。

一个 revision 是完整快照，不读取旧 revision 也能解释。数组按稳定 identity 排序且不能重复；
`volumes`按`volume_intent_id`、`endpoints`按`endpoint_id`严格升序。`spec_digest`覆盖除自身外的
全部规范化字段，精确算法见§16。同 revision 不同 digest 是
`Quarantined(SpecDigestConflict)`。

`placement` 始终存在，并标识负责本 revision 收敛的 Node。Cold 仍保留逻辑 owner，但 Cold
postcondition 不得依赖该 Host 的运行资源。Deleted 保留最后负责清理的 placement，直到 tombstone
满足第 13 节的回收条件。

### 3.1 VolumeIntent

```text
VolumeIntent {
  volume_intent_id: Id,
  disk_id: Id,
  volume_id: Id,
  attachment_id: Id,
  size_bytes: integer 1..=18446744073709551615,
  disk_kind: "root" | "persistent",
  access: "read_write_once",
  durability: "strict" | "relaxed",
  guest_device: GuestDeviceIdentity,
  acquire: VolumeAcquire,
  disposition: VolumeDisposition,
  mount: Ext4MountIntent | null
}

GuestDeviceIdentity {
  serial: Id,
  slot: integer 0..=65535
}

VolumeAcquire =
  {
    kind: "normal",
    transition_id: RandomId128,
    expected_unowned_epoch: FenceEpoch
  }
| { kind: "takeover", authorization_id: Id }

VolumeDisposition =
  { kind: "retain" }
| { kind: "detach_retained" }
| { kind: "delete_disposable_root", delete_id: Id }

Ext4MountIntent {
  filesystem_uuid: RandomId128,
  mount_path: HostPath,
  initialization: FilesystemInitialization
}

FilesystemInitialization =
  { kind: "existing" }
| {
    kind: "initialize",
    initialization_token: RandomId128,
    expected_blank_root: Sha256Digest | null,
    expected_blank_generation: Generation
  }
```

`Normal` 不能 revoke 其他 owner；同一 transition 的重试返回同一 LeaseGrant。`Takeover` 只
引用第 9 节的逐卷授权。授权行、MetadataStore CAS 与卷状态机由
[Volume Authority](volume-authority.md) 定义；它是 Runtime acquire/takeover 的硬依赖，Host
事件本身不授予卷写权限。HostFenceEvent来源的首次消费必须在同一PostgreSQL事务锁event、
authorization和VolumeRecord，完成卷CAS并写不可变`AuthorizationConsumedReceipt`。

`target != "deleted"`时所有volume的disposition必须是`retain`。Deleted Desired为每卷显式声明
`detach_retained`或`delete_disposable_root`。后一种只允许
Control Store权威分类的RootDisk；Node停止runtime/blockd并报告精确observation后，Control Plane才
建立同revision的`DisposableRootDeleteAuthorization`供reconciler查询和消费。PersistentDisk、未知
分类或stale revision一律不能使用。

RootDisk的`mount`必须为`null`；PersistentDisk的`mount`必须是`Ext4MountIntent`。同一spec内
`disk_id`、`volume_id`、`attachment_id`、Guest `serial`和`slot`也分别唯一。`filesystem_uuid`在wire
上使用无连字符的canonical 128-bit文本；`mount_path`不能是`/`。`volume_intent_id`标识该Cat磁盘集合中
一次逻辑成员关系，创建后不复用；detach后再次加入必须使用新intent和新attachment ID。

`filesystem_uuid` 在 Disk 创建时预定。`Initialize` 只能来自 Control Store 中持久的
`Uninitialized(token, blank_root, generation)`，不得现场猜测空盘。Guest Agent 只有在 Node
取得精确 attachment、当前 Root/generation 与 blank predecessor 一致时才可格式化。已是预期
UUID 表示幂等完成；其他 UUID、predecessor 已变化或部分格式化痕迹都必须 quarantine。
format/probe 成功后先做 device flush，并要求 blockd 把初始化写 drain 到 `R == L`；Control Store
再以 token、blank predecessor、UUID 和新 remote head 做 CAS，转为 Initialized 并消费 token。
之后 Guest 才 mount；device/UUID/path/read-write 全部匹配后才能 Mounted/Ready。响应丢失时按
同一 token、UUID 和 remote head 幂等确认。

V1 不做热插拔、热拔盘或运行中改变 VM shape。当前状态不是精确 Cold 时，修改 CPU、内存、
boot image 或磁盘集合的请求以 `PreconditionFailed(MustBeCold)` 返回，不创建 Desired/Operation。
调用方需要变更时使用两个普通 mutation：

1. revision A 保留原 placement、shape 和磁盘集合，目标为 Cold；
2. A 的 Operation 成功后，revision B 写入新 shape/完整磁盘集合和请求的目标状态。

Control Plane 不为这两个请求保存额外 workflow；每个 Operation 都只绑定自己的 revision。
volume容量创建后不可变；Control Plane、MetadataStore、blockd与Guest合同都不提供resize API。

### 3.2 Endpoint 与 transition

```text
EndpointIntent {
  endpoint_id: Id,
  hostname: Hostname,
  route_epoch: Epoch,
  protocol: "http",
  target_port: integer 1..=65535
}
```

同一spec内`endpoint_id`和`hostname`分别唯一。route epoch
由Control Store在完整Desired事务中分配；目标非Running时它表达需要关闭的gate。

`RequireIdle` 只用于自动 Running -> Suspended。它就是一个已提交的普通 Desired revision：

1. Control Plane 以当前 Running revision/incarnation 为 compare condition，提交带唯一
   `attempt_id` 的完整 Suspended revision。
2. Node 先把 attempt 以 `Armed` fsync 到 checkpoint，再只执行一次
   `AdmissionCell.try_close_all_if_idle`。guard 非零时 cell/runtime 完全不变；Node 持久化并报告
   terminal `PreconditionFailed(Busy)`。
3. guards 为零时同时关闭全部 work admission，持久化 `Succeeded/Closed`，然后在 cell 外检查
   Guest watcher fresh+idle 并执行 quiesce fence。检查失败时同样terminal Busy，gate保持Closed；
   不能恢复旧serving epoch。
4. restart 看到 `Succeeded/Closed` 时继续转换；看到没有 terminal outcome 的 `Armed` 时保守
   结算 Busy。同一 attempt 永不因后来变 idle 而重试。
5. Control Plane接受Busy observation后，在一个compare transaction中把该Suspended Operation
   置为Failed，并创建复制原完整spec的新Running revision/Operation。若gate从未close，保留原
   route epochs；只要gate曾close或结果不明，新revision就提高全部可能关闭的Endpoint epochs。
   Node重新验证runtime、volume和route identity后只安装新epoch。

用户 stop、Node drain、destroy 使用 `CancelAndDrain`：关闭 gate、取消并有界等待 guards；
超时保留源并报告 Blocked。

`require_idle`只允许`target="suspended"`，且`source_revision < desired_revision`；Control Plane提交时还
必须compare source revision对应Running和同一`source_runtime_incarnation`。其他transition以及手动
Suspended都使用`cancel_and_drain`。不接受缺省transition、boolean `require_idle`或额外policy字段。

### 3.3 提交、placement 与 Operation

所有API mutation共用PostgreSQL：

```text
ApiIdempotencyResult {
  authenticated_workspace_id, canonical_route, idempotency_key,
  request_fingerprint,
  outcome: Succeeded {http_status, response} | Failed {http_status, typed_error},
  created_at
}
```

`ApiIdempotencyResult`是Control Store逻辑原子性合同，不是Control Plane -> Node共享wire，也不属于本
规格的Rust F0 codegen集合；其中HTTP response的精确public API schema由对应route定义。本节只冻结其
replay key、fingerprint、不可变outcome和事务边界，§16.4冻结双方共用的`idempotency_conflict`错误。

主键是`(authenticated_workspace_id, canonical_route, idempotency_key)`。事务必须先取得该key的
transaction-scoped reservation并读取result，再取得任何domain资源锁；此前只验证调用者身份、当前
Workspace membership和route permission，不查询目标资源是否仍存在。同fingerprint重放只返回不可变
outcome，同key异fingerprint返回`IdempotencyConflict`。只有result miss才检查resource ownership和
tuple；跨Workspace miss回滚reservation且零持久副作用。首次执行的业务变化和最终result同一commit，
不保留持久Pending；无法提交事务时二者都不存在。V1已提交result不因resource或Operation删除而GC。

1. API 在创建 revision 前完成合法性、Cold-only 和 placement/capacity 检查。无法选择 Node
   时不创建 Desired 或 Operation；选中的 placement 与完整 spec/Operation 在同一事务提交。
2. 完整 spec、精确绑定它的 Operation与API result在同一 PostgreSQL 事务写入。同key重放返回
   同一不可变HTTP response；异步response包含原`operation_id`，但不复制Operation的可变phase或status。
   已经完全满足相同 spec 时不创建空 revision。
3. 新 revision 提交时，旧的 Pending Operation 原子变为 Superseded。
4. 每次 placement 变化都是一个新的完整 revision、提高后的 `placement_epoch` 和新
   Operation；不存在只改调度表、不改 Desired 的旁路。
5. Host loss 时，当前 Pending Operation 先以 `HostLost` Failed；取得第 9 节证据后，再创建
   指向新 placement 的系统 revision 和 Operation。已终结的历史 Operation 不改写。
6. placement 提交后若 Node 明确拒绝不可满足的容量/能力，当前 Operation Failed；Controller
   重新选择 Node 时必须创建新的系统 revision，不能原地替换 placement。

## 4. Desired delivery 与 AdmissionCell

Control Plane 必须支持 Node 周期性拉取其全部 assigned specs。push/notify 只能提前触发拉取。
列表带服务端读取位置和“完整集合”标志；一次缺项不能触发 orphan 删除。

Node 处理规则：

- 小于本地 applied revision：拒绝并报告 stale desired；
- revision 相等且 digest 相同：幂等 reconcile；
- revision 相等且 digest 不同：关闭 admission 并 quarantine；
- revision 更大：先持久化 checkpoint，再按 transition 更新 AdmissionCell，之后才做 cell 外
  副作用；
- placement 不匹配：关闭 admission，停止新增副作用并报告 residue。抢写只能消费逐卷 takeover
  authorization并完成epoch CAS；删除`R < L`只能消费精确disposable-root delete authorization。

每 Cat 只有一个 reconciler worker 修改 checkpoint 和物理资源。Running 热路径使用短临界区：

```text
AdmissionCell {
  applied_desired_revision: Revision,
  spec_digest: Sha256Digest,
  placement_epoch: Epoch,
  runtime_incarnation: RandomId128 | null,
  lifecycle_admission: Open | Closed,
  endpoints: Map<endpoint_id, InstalledGate>,
  guards: Map<guard_id, Endpoint(endpoint_id) | Platform>
}
```

这段只定义线性化点必须持有的逻辑事实，不是wire、持久格式或Rust私有容器布局；`InstalledGate`的共享
binding精确等于§10.2的`RouteGateBinding`。

HTTP/WebSocket和exec/deploy/control都在同一个cell内检查admission并原子取得guard。收到更新的
非条件desired后，reconciler在cell内推进`applied_desired_revision`。Endpoint-only revision只
替换变化Endpoint的serving gate；未变Endpoint的route epoch/gate/guards保持不动。离开Running时
同时关闭全部gate。`RequireIdle`遇Busy时cell完全不变；一旦close，旧epoch永不重开。网络、
数据库、VMM、枚举和fsync都在cell外。

Agent 启动时 cell 默认 Closed。只有完成 session 注册、完整 inventory，并确认 desired、
placement、runtime incarnation、volumes和routes一致后，才可为Running打开。因为Agent进程重启使
内存gate实际关闭，Control Plane必须先为新AgentSession提交一个提高所有原Active Endpoint
route epochs的系统Desired revision；checkpoint中的旧epoch只能用于识别stale token，不能复活。

## 5. RuntimeCheckpoint

每 Cat 恰有一份当前 checkpoint：

```text
RuntimeCheckpoint {
  format_version: 1,
  cat_id: Id,
  node_id: Id,
  placement_epoch: Epoch,
  desired_revision: Revision,
  spec_digest: Sha256Digest,
  runtime_incarnation: RandomId128 | null,
  stable_state: "running" | "suspended" | "warm" | "cold" | "deleted" | null,
  step: ReconcileStep,
  processes: [ProcessEvidence],
  volumes: [ObservedVolume],
  mounts: [ObservedMount],
  network: ObservedNetwork,
  warm_snapshot: WarmSnapshotEvidence,
  lifecycle_admission: "open" | "closed",
  route_gates: [CheckpointRouteGate],
  require_idle: RequireIdleCheckpoint,
  updated_at_unix_ms: UnixMillis
}

CheckpointRouteGate {
  endpoint_id: Id,
  binding: RouteGateBinding,
  gate: "active" | "closed"
}

RequireIdleCheckpoint =
  { kind: "not_applicable" }
| {
    kind: "armed",
    attempt_id: RandomId128,
    source_revision: Revision,
    source_runtime_incarnation: RandomId128
  }
| {
    kind: "busy",
    attempt_id: RandomId128,
    source_revision: Revision,
    source_runtime_incarnation: RandomId128,
    gate_closed: boolean,
    platform_guards: integer 0..=4294967295,
    endpoint_guards: [EndpointGuardCount]
  }
| {
    kind: "closed",
    attempt_id: RandomId128,
    source_revision: Revision,
    source_runtime_incarnation: RandomId128
  }
```

数组使用§10的相同排序/唯一性规则；`route_gates`按`endpoint_id`排序。`step`本身携带当前窄effect
token，不存在另一个任意payload的`current_effect_token`。非`require_idle`Desired必须使用
`not_applicable`；同一attempt只能从`armed`一次性进入`busy`或`closed`，不得回退或复用。
直接观察到guard Busy写`busy {gate_closed:false}`；close后的watcher/quiesce失败和restart遇到结果不明
的`armed`都写`busy {gate_closed:true}`并保持Closed。只有`gate_closed:false`的Busy允许fresh Running
保留原route epochs。

要求：

1. 第一个物理副作用前写 revision、digest、placement 和窄 effect token。
2. 使用临时文件写入、file fsync、atomic rename、parent directory fsync。
3. 每个可见副作用后替换同一记录；稳定状态也保留 adoption/cleanup 所需身份。
4. checkpoint 大小只随当前 Cat 资源数增长；历史审计独立轮转，不能成为恢复前提。

checkpoint 是证据之一，不是排他的事实来源。

## 6. Inventory 与可用性

完整 inventory 合并：checkpoint、systemd scopes/cgroups、进程 start time、control socket
handshake、NBD/vhost-user/tap、data directories、pending packs、snapshot、MetadataStore
owner/epoch/root 和 blockd 的 attachment/`L/R`/fenced 状态。自描述进程必须握手；非自描述
资源必须有 ownership token。

以下场景必须先完成一次有边界的全量扫描，期间所有 AdmissionCell 保持 Closed：

- Agent 启动或 Host rejoin；
- adoption、orphan 判断和任何破坏性 cleanup；
- checkpoint 损坏或上一步结果不确定。

稳定Running期间还以独立、低频且有硬deadline的后台full scan刷新admission attestation；它不在
每次heartbeat执行，也不持有AdmissionCell。当前attestation尚fresh时，单次刷新失败按Degraded
处理并保持既有gate；超过签发freshness窗口后Control Plane停止签发新Grant，但不伪造冲突或
立即拆除VMM。

`complete_inventory=true`只表示该Node的全部约定来源在同一bounded scan中完成，并附带新
`inventory_epoch`、读取位置/digest；Control Plane接受后写入session级
AdmissionInventoryAttestation。普通heartbeat可只报告变化或单个Cat，必须标为false并引用最近
accepted inventory epoch；缺项不代表资源不存在，也不能覆盖attestation。

完整扫描失败但没有发现冲突时报告 `Blocked(IncompleteInventory)`，不执行 cleanup。已经验证
并稳定 Running 的 Cat，后续短暂无法读取 PostgreSQL、MetadataStore 或某个 inventory source
时报告 `Degraded`，冻结新的破坏性/生命周期副作用，但保持已验证的 VMM 和现有 admission。
一旦发现两个 VMM/writer、identity/epoch 冲突、无法归属的 `R < L` 或未知 PersistentDisk，
立即关闭相关 gates 并进入 Quarantined；这不是 Degraded。

完整 inventory 发现本地 Cat 不在 assigned desired 集合时只报告 Orphan。必须再用强身份、卷
与 Desired tombstone 证据决定 cleanup，不能因控制面缺行盲删。

## 7. Reconcile 与物理 effect

每个 worker 循环：

1. 读取最新完整 spec、checkpoint 和所需 inventory。
2. 分类为 Converged、NeedsStep、Blocked 或 Quarantined。
3. 再读当前 revision/placement，生成一个有界 next step。
4. 在副作用前持久化窄 token 和物理身份。
5. 执行一次副作用并查询物理 postcondition；超时不等于失败或成功。
6. 更新 checkpoint、发布 observation，再读取最新 desired。

“副作用前重读”不能消除网络调用期间的新 revision。正确合同是：旧结果不能结算或报告新
revision、不能取得新 placement/route/writer authority；已经在本地线性化的 VMM/systemd
动作可能在 supersede 后完成，但必须绑定精确 incarnation，保留 durable data，并由下一轮
reconcile adopt 或修复。

planner 只发出下表中的有界物理步骤；每个步骤实例只处理一个 volume、resource 或 systemd
unit。Inspect、Verify 和 Quarantine 本身不产生外部 effect。

| planner step | 副作用前必须持久化 | 可执行条件与晚到结果 |
|---|---|---|
| CloseAdmission | desired/cell revision、原gate集合、RequireIdle attempt state | cell内compare-and-close；Armed模糊结果按Busy且Closed结算，fresh Running只以更高route epochs重开 |
| AcquireVolume | volume、attachment、transition id + expected unowned epoch，或 authorization id | MetadataStore 精确 CAS；authorization首次消费还要求Active event并原子写`AuthorizationConsumedReceipt`；只有同 transition/authorization 可 adopt，或在 `R == L` 后精确 release |
| PrepareDevices | NBD/tap/socket slot、ownership token | 完整 inventory 后 create-if-absent；晚到资源只按 token adopt 或删除 |
| FormatFilesystem | attachment、device、filesystem UUID、initialization token、blank predecessor | Guest Agent 只按精确 predecessor 格式化；晚到结果按 UUID probe/adopt，冲突立即 quarantine |
| DrainInitialization | attachment epoch、local/remote root generation | device flush 后只向精确 owner/epoch publish，直到 `R == L` |
| CommitInitialized | token、blank predecessor、UUID、新 remote head | Control Store 精确 CAS；相同结果幂等，冲突 quarantine |
| MountFilesystem | attachment、device、UUID、mount path | 只 mount 精确 device/UUID；晚到 mount 不产生 route authority，stale 时按精确 identity unmount |
| StartRuntime | runtime incarnation、scope/socket 名、process identity token | create-if-absent 后握手；晚到进程不开放 route，当前 spec 不再需要时按精确身份停止 |
| DrainPublish | attachment epoch、local/remote root generation | 只向精确 owner/epoch CAS publish；晚到成功可安全 adopt，旧 epoch 不能写新 root |
| PauseRuntime | runtime incarnation、process start time | 只 pause 该 incarnation；晚到 pause 可发生，当前 revision 负责 resume 或重建 |
| SnapshotWarmRuntime | runtime incarnation、snapshot temp id、source root/epoch | 验证VMM postcondition与durable rename；晚到文件不覆盖其他WarmRuntimeSnapshot |
| StopRuntime | runtime incarnation、process start time、scope id | 只 stop 该 incarnation；晚到 stop 可发生，当前 revision 负责重建 |
| CleanupRelease | 全部物理 identity、`R == L`/disposition、当前 desired 读取位置 | 只删匹配资源、只 release 精确 owner/epoch；stale cleanup 不得按可重算名称删除新资源 |
| DeleteDisposableRoot | delete authorization、精确lineage、owner/epoch/head | 无live DiskSnapshotRecord且Guest/VMM/blockd已停后，按event/auth/volume/control锁序原子写Consumed receipt及两边Deleting；成功后才删该`R < L`lineage |
| InstallGate | desired checkpoint、spec digest、placement、runtime incarnation、endpoint/route epoch | cell只接受一个serving epoch；任何已close gate必须由更大epoch重开 |

每步都可被 kill。重启后只能确认 postcondition、重试同一 token、继续或 quarantine，不能先
teardown 再重做。不建立通用 effect workflow。

## 8. 外部边界

- Volume normal acquire：只允许精确 `expected_unowned_epoch` 的 Unowned -> this attachment；只有
  重放同一 `transition_id` 才返回原 LeaseGrant。
- Volume publish/release：携带 expected owner/epoch/root；PersistentDisk release 前 `R == L`。
- VMM/blockd/systemd：名称含 Cat/incarnation，使用 process start time 和 socket handshake。
- NBD slot、tap 等共享资源：完整 inventory 后分配，checkpoint 先写 ownership token。
- WarmRuntimeSnapshot：先写temp identity；成功要求VMM postcondition、文件metadata和durable
  rename。产品DiskSnapshot不走Runtime planner，只能按Volume Authority在stable Cold/unowned时
  使用通用API key reservation，再锁VolumeRecord、重验认证Workspace拥有Disk及精确tuple，并在一个
  PostgreSQL事务写业务变化与result。create插入的单一`DiskSnapshotRecord`同时是产品资源和GC
  live-root；delete删该row，restore前进Volume head。重放只读result。只支持同盘restore，不支持clone
  或Golden Image GC。
- Route：遵守 [Route Grant v2](route-grant-v2.md) 的本地 gate/guard 合同。

任何cleanup只作用于精确物理identity。普通volume delete必须证明无Desired intent、无有效
attachment、无inventory residue，并且不存在live `DiskSnapshotRecord`；任一仍存在即返回
`SnapshotInUse`且不改变Disk/Volume。Snapshot必须按Volume Authority通过通用API result幂等删除该row，
Disk delete不隐式cascade。normal `begin_delete`锁VolumeRecord并在同一PostgreSQL事务把Control Disk
与VolumeRecord从Active改为相同Deleting；normal acquire与它只能一方提交。当前Deleted Desired中的
disposable Root可使用
[Volume Authority §11](volume-authority.md#11-delete)的精确Owned->Deleting授权；CAS成功前不能清
tail。HostFenceEvent来源按`event -> authorization -> VolumeRecord -> Control rows`锁序，在同一事务
写Consumed receipt和两边Deleting；成功后只清授权lineage。RPC超时不回滚Desired。

## 9. HostFenceEvent 与逐卷 takeover

heartbeat timeout 只产生 `NodeSuspected`，不能提高 placement 或 attachment epoch。Host loss
必须由 provider/BMC adapter 的权威结果建立一个 durable event：

```text
HostFenceEvent {
  event_id, provider, immutable_host_id, node_id, expected_node_boot_id,
  expected_agent_session_epoch, fence_attempt_id,
  isolation_state, observed_at,
  state: Active | Rejoined
}
```

同一 fence attempt 只保留一个 event。Active event 是 Host 级隔离事实，不是卷权限。Control
Plane 对旧 placement 中每个需要恢复的卷分别创建：

```text
VolumeTakeoverAuthorization {
  authorization_id, host_fence_event_id,
  volume_id, expected_owner, expected_epoch,
  new_attachment_id, desired_revision, new_placement_epoch,
  not_after, issuer_proof
}
```

首次消费按固定锁序`HostFenceEvent -> authorization -> VolumeRecord`，要求event仍为Active和数据库
时间未超过`not_after`，在同一PostgreSQL事务完成精确逐卷CAS并写不可变
`AuthorizationConsumedReceipt`。相同authorization只读取receipt并返回同一LeaseGrant，不再次改变
volume；换卷、换旧owner、换attachment、换placement、过期或Rejoined后的首次消费都失败。运行时
Desired的`attachment_id`、revision、placement必须与authorization一致，对应`VolumeIntent.acquire`
必须引用该authorization。精确schema/CAS以[Volume Authority](volume-authority.md)为准。

provider receipt只建立Active HostFenceEvent，不直接授予placement或writer。Control Plane先把旧
Pending Operation置为`Failed(HostLost)`，再在一个事务中创建新完整Desired/Operation、placement、
全部新attachments和每卷VolumeTakeoverAuthorization；新Desired逐卷引用授权。目标Node消费所有
MetadataStore CAS后才能Ready，不存在另一种writer-proof fallback。

session失效或提高attachment epoch不是解除旧Host隔离的条件。旧Host重用前必须在隔离网络内以
新boot/session完成完整inventory，保持gates Closed，停止旧runtime/transport/socket/tap/guards，
并把旧epoch的`R < L` lineage移入quarantine而非删除。授权派生、首次消费和
`Active -> Rejoined`都先锁同一event行；rejoin再按稳定顺序锁定该event的全部授权，所以不会漏掉
in-flight首次消费。Control Plane核对每个Unconsumed授权都已过`not_after`，每个Consumed授权都有
匹配payload的不可变receipt；当前VolumeRecord必须是receipt直接结果或更大epoch的合法状态机后继，
receipt含Disk postcondition时Control Disk也必须匹配同一Deleting；两边记录已删除时必须有精确
`DeleteCompletionReceipt`。缺失、倒退或冲突保持Blocked。接受
`HostRejoinProof`并在同一事务把event持久转为Rejoined后provider才恢复workload网络；此后未消费
授权不能首次生效，已消费授权只幂等读取receipt。相关authorization和`DeleteCompletionReceipt`保留到Rejoined。

## 10. Observation 与 Conditions

```text
NodeObservation {
  version: 1,
  observation_id: RandomId128,
  node_id: Id,
  node_boot_id: NodeBootId,
  agent_instance_id: RandomId128,
  agent_session_epoch: Epoch,
  heartbeat_sequence: Sequence,
  observed_at_unix_ms: UnixMillis,
  complete_inventory: boolean,
  inventory_epoch: Epoch,
  inventory_digest: Sha256Digest | null,
  inventory_read_position: Sequence | null,
  key_ring_version: Epoch,
  key_ring_digest: Sha256Digest,
  loaded_kids: [KeyId],
  runtimes: [ObservedRuntimeStatus]
}

ObservedRuntimeStatus {
  cat_id: Id,
  applied_desired: AppliedDesiredEvidence | null,
  runtime_incarnation: RandomId128 | null,
  stable_state: "running" | "suspended" | "warm" | "cold" | "deleted" | null,
  step: ReconcileStep,
  checkpoint: CheckpointEvidence,
  processes: [ProcessEvidence],
  volumes: [ObservedVolume],
  mounts: [ObservedMount],
  network: ObservedNetwork,
  warm_snapshot: WarmSnapshotEvidence,
  lifecycle_admission: "open" | "closed",
  routes: [ObservedRouteGate],
  platform_guards: integer 0..=4294967295,
  conditions: [Condition]
}

AppliedDesiredEvidence {
  desired_revision: Revision,
  spec_digest: Sha256Digest,
  placement: AssignedPlacement,
  target: "running" | "suspended" | "warm" | "cold" | "deleted"
}
```

`applied_desired=null`只允许full inventory发现了无法关联到有效checkpoint/Desired的orphan；它不能
携带`Ready`，也不能结算Operation。Running/Suspended必须有`runtime_incarnation`；Warm/Cold/Deleted
必须为`null`。只有§11完整postcondition成立时`stable_state`才非null。

Control Plane只接受当前session/instance的递增sequence；Node的`observed_at_unix_ms`不用于排序或
freshness。`loaded_kids`按`KeyId`升序且无重复，`runtimes`按`cat_id`升序且无重复。
`complete_inventory=false`时只upsert报告中列出的Cat，不能按缺项删除，并且不得覆盖当前
AdmissionInventoryAttestation；此时`inventory_digest`和`inventory_read_position`必须都是`null`，
`inventory_epoch`引用当前已接受attestation。`complete_inventory=true`时两者必须非null，且digest必须
按§16重算成功，才能按读取位置对完整集合做residue对账并建立新attestation。所有freshness使用
PostgreSQL `accepted_at_unix_ms`。partial只表示Node级Cat集合不完整；数组中每个
`ObservedRuntimeStatus`仍是该Cat的完整替换快照，不存在field-level patch语义。

### 10.1 checkpoint 与 step

```text
CheckpointEvidence =
  { kind: "missing" }
| { kind: "corrupt", content_digest: Sha256Digest }
| {
    kind: "valid",
    format_version: ContractVersion,
    cat_id: Id,
    node_id: Id,
    desired_revision: Revision,
    spec_digest: Sha256Digest,
    placement_epoch: Epoch,
    runtime_incarnation: RandomId128 | null,
    stable_state: "running" | "suspended" | "warm" | "cold" | "deleted" | null,
    step: ReconcileStep,
    require_idle: RequireIdleCheckpoint,
    updated_at_unix_ms: UnixMillis
  }

ReconcileStep =
  { kind: "inspect_inventory", inventory_epoch: Epoch }
| { kind: "stable", state: "running" | "suspended" | "warm" | "cold" | "deleted" }
| { kind: "close_admission", require_idle_attempt_id: RandomId128 | null }
| { kind: "acquire_volume", volume_id: Id, attachment_id: Id, acquire: VolumeAcquire }
| {
    kind: "prepare_device",
    volume_id: Id,
    guest_device: GuestDeviceIdentity,
    ownership_token: RandomId128
  }
| {
    kind: "format_filesystem",
    volume_id: Id,
    attachment_id: Id,
    filesystem_uuid: RandomId128,
    initialization_token: RandomId128,
    expected_blank_root: Sha256Digest | null,
    expected_blank_generation: Generation
  }
| {
    kind: "drain_initialization",
    volume_id: Id,
    attachment_epoch: FenceEpoch,
    local_generation: Generation,
    remote_generation: Generation
  }
| {
    kind: "commit_initialized",
    volume_id: Id,
    initialization_token: RandomId128,
    expected_blank_root: Sha256Digest | null,
    expected_blank_generation: Generation,
    new_remote_root: Sha256Digest,
    new_remote_generation: Generation
  }
| {
    kind: "mount_filesystem",
    volume_id: Id,
    guest_device: GuestDeviceIdentity,
    filesystem_uuid: RandomId128,
    mount_path: HostPath
  }
| {
    kind: "start_runtime",
    runtime_incarnation: RandomId128,
    scope_id: Id,
    process_identity_token: RandomId128
  }
| {
    kind: "drain_publish",
    volume_id: Id,
    attachment_epoch: FenceEpoch,
    local_generation: Generation,
    remote_generation: Generation
  }
| { kind: "pause_runtime", runtime_incarnation: RandomId128, process_start_time_ticks: U64 }
| {
    kind: "snapshot_warm_runtime",
    runtime_incarnation: RandomId128,
    snapshot_id: Id,
    temporary_path: HostPath,
    source_heads: [VolumeHeadEvidence]
  }
| {
    kind: "stop_runtime",
    runtime_incarnation: RandomId128,
    process_start_time_ticks: U64,
    scope_id: Id
  }
| { kind: "cleanup_release", target: CleanupTarget }
| {
    kind: "delete_disposable_root",
    authorization_id: Id,
    delete_id: Id,
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    expected_generation: Generation,
    expected_root: Sha256Digest | null
  }
| { kind: "install_gate", endpoint_id: Id, route_epoch: Epoch }
| { kind: "quarantined" }

CleanupTarget =
  { kind: "volume", volume_id: Id, attachment_id: Id, attachment_epoch: FenceEpoch }
| { kind: "device", volume_id: Id, ownership_token: RandomId128 }
| { kind: "network", network_id: Id, ownership_token: RandomId128 }
| { kind: "warm_snapshot", snapshot_id: Id }
| { kind: "scope", scope_id: Id, process_start_time_ticks: U64 }

VolumeHeadEvidence {
  volume_id: Id,
  attachment_epoch: FenceEpoch,
  generation: Generation,
  root: Sha256Digest | null
}
```

`source_heads`按`volume_id`升序且无重复。`ObservedRuntimeStatus.step`与valid checkpoint中的`step`必须
逐字段相同；missing/corrupt checkpoint只能处于`inspect_inventory`或`quarantined`。这里的step闭集
就是§7 planner当前允许的窄effect，不是可扩展workflow或通用command envelope。

### 10.2 物理证据

```text
ProcessEvidence {
  role: ProcessRole,
  process_id: integer 1..=4294967295,
  process_start_time_ticks: U64,
  executable_path: HostPath,
  scope_id: Id,
  control_socket_path: HostPath,
  state: "running" | "paused"
}

ProcessRole =
  { kind: "vmm", runtime_incarnation: RandomId128 }
| {
    kind: "blockd",
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch
  }

ObservedVolume {
  volume_intent_id: Id | null,
  disk_id: Id | null,
  volume_id: Id,
  disk_kind: "root" | "persistent" | "unknown",
  authority: VolumeAuthorityEvidence,
  local_lineages: [LocalVolumeLineage],
  device: ObservedDevice
}

VolumeAuthorityEvidence =
  { kind: "unavailable" }
| { kind: "absent" }
| {
    kind: "unowned",
    attachment_epoch: FenceEpoch,
    generation: Generation,
    remote_root: Sha256Digest | null
  }
| {
    kind: "owned",
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    generation: Generation,
    remote_root: Sha256Digest | null
  }
| {
    kind: "deleting",
    delete_id: Id,
    attachment_epoch: FenceEpoch,
    generation: Generation,
    remote_root: Sha256Digest | null
  }

LocalVolumeLineage {
  attachment_id: Id,
  attachment_epoch: FenceEpoch,
  acquire_transition_id: Id,
  node_id: Id,
  placement_epoch: Epoch,
  local_durable_generation: Generation,
  remote_durable_generation: Generation,
  data_directory: HostPath,
  pending_pack_count: U64,
  fenced: boolean,
  state: "active" | "released" | "quarantined"
}

ObservedDevice =
  { kind: "absent" }
| {
    kind: "kernel_nbd",
    guest_device: GuestDeviceIdentity,
    device_path: HostPath,
    ownership_token: RandomId128
  }
| {
    kind: "vhost_user_blk",
    guest_device: GuestDeviceIdentity,
    socket_path: HostPath,
    ownership_token: RandomId128
  }

ObservedMount {
  volume_id: Id,
  guest_device: GuestDeviceIdentity,
  filesystem_uuid: RandomId128,
  mount_path: HostPath,
  access: "read_write" | "read_only"
}

ObservedNetwork =
  { kind: "absent" }
| {
    kind: "isolated_ipv4",
    network_id: Id,
    guest_mac: MacAddress,
    guest_ipv4: Ipv4Address,
    prefix_length: 30,
    gateway_ipv4: Ipv4Address,
    tap_name: Id,
    ownership_token: RandomId128
  }

WarmSnapshotEvidence =
  { kind: "absent" }
| {
    kind: "present",
    snapshot_id: Id,
    runtime_incarnation: RandomId128,
    path: HostPath,
    file_size_bytes: U64,
    file_digest: Sha256Digest,
    source_heads: [VolumeHeadEvidence],
    durable_rename_complete: boolean
  }

ObservedRouteGate {
  endpoint_id: Id,
  binding: RouteGateBinding,
  gate: "active" | "closed",
  active_guards: integer 0..=4294967295,
  cancellation_pending: boolean
}

RouteGateBinding {
  workspace_id: Id,
  endpoint_id: Id,
  hostname: Hostname,
  cat_id: Id,
  node_id: Id,
  runtime_incarnation: RandomId128,
  route_epoch: Epoch,
  protocol: "http",
  target_port: integer 1..=65535
}
```

`processes`按`(role.kind, role中的稳定ID, process_id)`、`volumes`按`volume_id`、每卷
`local_lineages`按`(attachment_epoch, attachment_id)`、`mounts`按`(volume_id, mount_path)`、`routes`
按`endpoint_id`严格升序且各自无重复。`local_durable_generation >= remote_durable_generation`。
`disk_kind="unknown"`时`volume_intent_id`和`disk_id`都必须为`null`，否则两者都必须非null。process
只有在scope、start time和control-socket handshake都已验证并与`role`精确一致时才能进入数组；仅看到
PID或文件名不构成`ProcessEvidence`。

### 10.3 Condition 闭集

```text
Condition =
  { kind: "ready", reason: ReadyReason }
| { kind: "progressing", reason: ProgressingReason }
| { kind: "blocked", reason: BlockedReason }
| { kind: "precondition_failed", reason: PreconditionFailureReason }
| { kind: "degraded", reason: DegradedReason }
| { kind: "quarantined", reason: QuarantineReason }
| { kind: "data_loss_possible", reason: DataLossReason }

ReadyReason =
  {
    kind: "postcondition_satisfied",
    target: "running" | "suspended" | "warm" | "cold" | "deleted"
  }

ProgressingReason = { kind: "reconcile_step", step: ReconcileStep }

InventorySource = "checkpoint" | "systemd" | "process" | "control_socket"
                | "block_frontend" | "network" | "data_directory"
                | "pending_pack" | "warm_snapshot" | "metadata_store" | "guest_mount"

BlockedReason =
  { kind: "incomplete_inventory", unavailable_sources: [InventorySource] }
| {
    kind: "superseded_by_another_node",
    volume_id: Id,
    owner_node_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch
  }
| {
    kind: "active_guards",
    platform_guards: integer 0..=4294967295,
    endpoint_guards: [EndpointGuardCount]
  }
| { kind: "volume_authority_unavailable", volume_ids: [Id] }
| {
    kind: "remote_durability_lag",
    volume_id: Id,
    attachment_epoch: FenceEpoch,
    local_generation: Generation,
    remote_generation: Generation
  }
| { kind: "authorization_unavailable", volume_id: Id, authorization_id: Id }
| { kind: "host_rejoin_pending", host_fence_event_id: Id }
| { kind: "control_plane_unavailable", last_desired_revision: Revision | null }
| {
    kind: "key_ring_unavailable",
    expected_version: Epoch,
    expected_digest: Sha256Digest,
    loaded_version: Epoch | null,
    loaded_digest: Sha256Digest | null
  }

EndpointGuardCount { endpoint_id: Id, active_guards: integer 1..=4294967295 }

PreconditionFailureReason =
  {
    kind: "busy",
    attempt_id: RandomId128,
    gate_closed: boolean,
    platform_guards: integer 0..=4294967295,
    endpoint_guards: [EndpointGuardCount]
  }
| {
    kind: "must_be_cold",
    observed_state: "running" | "suspended" | "warm" | "cold" | "deleted" | null
  }
| {
    kind: "placement_rejected",
    node_id: Id,
    placement_epoch: Epoch,
    reason: "insufficient_vcpus" | "insufficient_memory" | "unsupported_block_path"
          | "unsupported_network" | "unsupported_guest_capability"
  }

DegradedSource = "control_store" | "metadata_store" | "checkpoint" | "systemd"
               | "process" | "control_socket" | "block_frontend" | "network"
               | "data_directory" | "pending_pack" | "warm_snapshot" | "guest_mount"

DegradedReason =
  {
    kind: "source_unavailable",
    sources: [DegradedSource],
    since_unix_ms: UnixMillis
  }
| {
    kind: "attestation_refresh_failed",
    inventory_epoch: Epoch,
    since_unix_ms: UnixMillis
  }

QuarantineReason =
  {
    kind: "spec_digest_conflict",
    desired_revision: Revision,
    expected_digest: Sha256Digest,
    observed_digest: Sha256Digest
  }
| { kind: "checkpoint_corrupt", content_digest: Sha256Digest }
| {
    kind: "runtime_identity_conflict",
    expected_incarnation: RandomId128,
    observed_incarnations: [RandomId128]
  }
| { kind: "duplicate_runtime", observed_incarnations: [RandomId128] }
| {
    kind: "process_identity_conflict",
    role: ProcessRole,
    process_ids: [integer 1..=4294967295]
  }
| {
    kind: "volume_identity_conflict",
    volume_id: Id,
    expected_attachment_id: Id,
    expected_attachment_epoch: FenceEpoch,
    observed_attachment_id: Id,
    observed_attachment_epoch: FenceEpoch
  }
| {
    kind: "local_lineage_conflict",
    volume_id: Id,
    data_directory: HostPath,
    expected_attachment_id: Id,
    observed_attachment_id: Id | null
  }
| {
    kind: "local_lineage_corrupt",
    volume_id: Id,
    data_directory: HostPath,
    problem: "identity_missing" | "pending_pack_gap" | "pending_pack_corrupt"
  }
| {
    kind: "duplicate_writer",
    volume_id: Id,
    observed_attachments: [AttachmentIdentity]
  }
| {
    kind: "filesystem_identity_conflict",
    volume_id: Id,
    expected_filesystem_uuid: RandomId128,
    observed_filesystem_uuid: RandomId128 | null
  }
| { kind: "unknown_persistent_disk", volume_id: Id, data_directory: HostPath | null }
| {
    kind: "warm_snapshot_conflict",
    snapshot_id: Id,
    expected_digest: Sha256Digest,
    observed_digest: Sha256Digest | null
  }
| {
    kind: "route_gate_conflict",
    endpoint_id: Id,
    expected_binding: RouteGateBinding,
    observed_binding: RouteGateBinding
  }

AttachmentIdentity {
  attachment_id: Id,
  attachment_epoch: FenceEpoch
}

DataLossReason =
  {
    kind: "remote_tail_unavailable",
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    local_generation: Generation,
    remote_generation: Generation,
    host_fence_event_id: Id
  }
```

`InventorySource`、source列表、ID列表、guard列表、incarnation列表和PID列表都按wire值升序且无重复；
`observed_attachments`按`(attachment_epoch, attachment_id)`升序，长度必须`>= 2`且identity互不相同。
`unavailable_sources`、`sources`、`volume_ids`、`duplicate_runtime.observed_incarnations`和
`process_identity_conflict.process_ids`都非空，后两者至少两个元素。所有
`remote_durability_lag`/`remote_tail_unavailable`必须满足`local_generation > remote_generation`；
`active_guards`必须至少有一个非零platform或Endpoint guard。
Conditions可并存，但`kind="ready"`每个runtime至多一个，其他Condition按
`(kind, reason.kind, canonical evidence bytes)`升序且不允许逐字节重复。V1不得增加string-only reason、
任意JSON evidence或按message文本分支；新物理故障语义需要先修改本闭集。

- Blocked 是可重试前置条件，Operation 保持 Pending。
- PreconditionFailed 是该 revision 的终态；例如 RequireIdle Busy 使 Operation Failed。
- Degraded 表示已验证的稳定服务继续运行，但暂时不能安全做新副作用。attestation和per-Cat
  facts仍fresh时可报告`Ready + Degraded`，保持既有admission并允许signer继续验证Ready；任一
  freshness过期或安全postcondition不再可证时必须移除Ready并停止新Grant签发。
- Quarantined 表示确定的身份/ownership 冲突；立即关闭 gates，并使当前 Pending Operation
  Failed。修复或删除必须提交新 revision。若该 revision 的 Operation 早已 Succeeded，不回写
  历史结果；控制面创建新的系统修复 revision 来承载失败与处置。

## 11. 稳定 postcondition

- **Running**：VMM/Guest Ready；精确 VM shape、磁盘/epoch/mount 集合；无未知 residue；当前
  Endpoint gates Active；observation 与 revision/incarnation 匹配。
- **Suspended**：gates Closed 且 guards=0；VMM paused；本地 durability barrier 完成；所有
  `R < L` journal/lease/blockd 保留。
- **Warm**：gates Closed；VMM 不存在；snapshot 已验证；所有保留卷 `R == L`。
- **Cold**：gates Closed；VMM/blockd 不存在；保留卷 `R == L` 且 attachment 已释放；本地只剩
  可删除 cache/诊断证据。
- **Deleted**：无可服务 route/runtime；Root 按 disposition 处理；PersistentDisk 只 detach，
  不删除；待删除Disk没有live `DiskSnapshotRecord`；普通卷已release，disposable Root已消费精确delete
  authorization；开始删除时Control Disk与VolumeRecord已原子进入同一Deleting，完成后有精确
  DeleteCompletionReceipt；没有未知卷或未跟踪的attachment residue。

未满足完整条件只能 Progressing、Blocked、Degraded 或 Quarantined，不能发布目标稳定态。

## 12. Operation 与 placement 闭环

Operation是用户可见的revision结算记录，不是Node step journal。V1完整逻辑schema是：

```text
Operation {
  version: 1,
  operation_id: Id,
  workspace_id: Id,
  cat_id: Id,
  desired_revision: Revision,
  desired_spec_digest: Sha256Digest,
  placement: AssignedPlacement,
  target: "running" | "suspended" | "warm" | "cold" | "deleted",
  phase: "pending" | "succeeded" | "failed" | "superseded",
  terminal: OperationTerminal | null,
  created_at_unix_ms: UnixMillis,
  updated_at_unix_ms: UnixMillis
}

OperationTerminal =
  {
    kind: "succeeded",
    result: OperationSuccess,
    completed_at_unix_ms: UnixMillis
  }
| {
    kind: "failed",
    error: OperationFailure,
    completed_at_unix_ms: UnixMillis
  }
| {
    kind: "superseded",
    superseded_by_revision: Revision,
    superseded_by_operation_id: Id,
    completed_at_unix_ms: UnixMillis
  }

OperationSuccess {
  observation_id: RandomId128,
  node_id: Id,
  agent_session_epoch: Epoch,
  heartbeat_sequence: Sequence,
  observed_target: "running" | "suspended" | "warm" | "cold" | "deleted",
  runtime_incarnation: RandomId128 | null
}

OperationFailure =
  { kind: "precondition_failed", reason: PreconditionFailureReason }
| {
    kind: "host_lost",
    node_id: Id,
    agent_session_epoch: Epoch,
    host_fence_event_id: Id
  }
| { kind: "quarantined", reason: QuarantineReason }
| { kind: "contract_error", error: ContractErrorDetail }
```

`phase="pending"`时`terminal`必须为`null`；其他phase必须携带同名`kind`的terminal。Succeeded的
`observed_target`必须等于Operation `target`；Running/Suspended result的`runtime_incarnation`必须非null，
Warm/Cold/Deleted必须为null。Superseded的revision必须更大，且不能引用自身Operation。时间只能单调
前进：`updated_at_unix_ms >= created_at_unix_ms`，terminal completion等于`updated_at_unix_ms`。
`contract_error`只允许当前已提交Desired自身的`unsupported_version`或`malformed_payload`；stale/wrong
session、revision、digest或placement只拒绝那次输入，绝不能终结当前Operation。

- 只有 `operation.desired_revision == observation.desired_revision == current desired`，并同时
  匹配`desired_spec_digest`、完整`AssignedPlacement`与postcondition，才能 Succeeded；result保存实际
  结算的observation/session/sequence，不复制可变observation内容。
- 新 revision 在同一事务把旧 Pending Operation 变为 Superseded。
- PreconditionFailed、永久请求错误、HostLost 或 Quarantined 使当前 Pending Operation Failed。
- Progressing、Blocked、Degraded 和暂时离线保持 Pending。

N+2 达到同名状态不能结算 N。observation 不写 Desired；所有用户和系统 placement 变更都走
资源 API/Controller 的完整 revision 事务。

计划跨 Node 迁移只用两个普通 revision：

1. revision A 在源 placement 目标 Cold；成功条件包括 `R == L`、runtime 停止和 attachments
   release。
2. A 成功后，revision B 提高 placement epoch、指向目标 Node，并恢复迁移前目标（通常
   Running）。目标使用新的 attachment identity 做普通 acquire。

源未达到精确 Cold 不创建 B。整个过程始终只有当前 Desired revision 是 authority。

## 13. Deleted 与保留

Deleted Desired 是 tombstone，不能在提交后立即删行。其 Operation 只有在第 11 节 Deleted
postcondition满足时成功。若负责 Node 永久丢失，需要 provider 的 Host 已销毁证据，或该 Host
rejoin 后的空 inventory，才能证明物理 runtime 已不存在；仅网络隔离足以阻止服务，不足以
声称 residue 已清空。

Operation 结算、volume disposition 完成且不存在 fence/rejoin 待办后，才可 GC 当前 Desired、
observation 和 checkpoint 索引。审计按独立产品策略保留。Node 删除 checkpoint 前还必须证明
无runtime、无未跟踪volume residue和无route gate。授权丢弃的Root lineage必须已删除；Active
HostFenceEvent上的隔离lineage由event/rejoin记录继续跟踪，关联的authorization与
`DeleteCompletionReceipt`必须保留到Rejoined，不能因VolumeRecord或本地目录缺席猜测消失。

## 14. 最小验收矩阵

| 场景 | Oracle |
|---|---|
| N/N+1/N+2 ABA | 旧结果不能结算/授权 N+2；已线性化的本地 effect 可被下一轮安全修复 |
| 双 Agent / register 响应丢失 | Host lock 排他；同 attempt 返回同 session；旧 session 永久拒绝 |
| 各 planner step kill | restart 后确认、重试、继续或 quarantine；无重复 writer/误删 |
| normal acquire 遇到旧 owner | Blocked，不 revoke；只有精确逐卷 takeover authorization 可 CAS |
| Running 改盘/shape | 请求先 PreconditionFailed(MustBeCold)；Cold 成功后的新请求才改完整 spec |
| `R < L` + remote down | Suspend 可完成；Warm/Cold/detach/migrate 阻塞且唯一数据保留 |
| startup/inventory source down | gates 保持 Closed，Blocked；稳定 Running 的短暂故障为 Degraded |
| RequireIdle Busy/crash | attempt 只评估一次，Suspended Operation Failed，系统创建新 Running revision |
| identity conflict | gates Closed，Quarantined，当前 Pending Operation Failed |
| Host fence 与多个卷 | 一个 HostFenceEvent 派生多个独立逐卷授权；错 tuple 全部拒绝 |
| authorization consume 与Rejoined并发 | 两者锁同一event；只能consume先提交并留下receipt，或Rejoined先提交且epoch不变 |
| consumed授权后继 | takeover→release与delete→sweep后均可凭单调状态/精确DeleteCompletionReceipt完成rejoin；错receipt保持Blocked |
| normal acquire与begin-delete并发 | 同一VolumeRecord串行且只能一方提交；Control Disk与Volume不会出现单边Deleting |
| disposable Root `R < L` | event/auth/volume/control同事务写receipt和两边Deleting后才删lineage；PersistentDisk拒绝 |
| Snapshot create crash/响应丢失 | exact record与成功result同时提交或都不存在；重放只读result，不从record缺席推断可重建 |
| create→delete→旧create重放 | 返回原成功result和原snapshot ID，不重新插row；snapshot ID永不复用 |
| Snapshot跨Workspace访问/重放 | NotFound/Forbidden；不写Operation/result，不改变Volume、Disk或Snapshot |
| Snapshot API同key异payload | 在资源锁前返回IdempotencyConflict，保留原result且不改变资源 |
| Snapshot与Disk delete并发 | create/begin-delete锁同一VolumeRecord；live record返回SnapshotInUse且两边状态不变 |
| Deleted | tombstone 保留到物理/卷/route postcondition 和 Operation 闭环 |

## 15. Clean-slate 切换

首次部署按 [Operations and HA §8](../operations-ha.md#8-首次终态部署)执行。本规格的切换前置是：
目标 schema 只包含本合同的 NodeIdentity、AgentSession、Desired、Operation、observation 与
attestation；exact release 不含 NodeJob、heartbeat overwrite 或旧 ledger 恢复入口；空 fleet 的
Node 必须先完成 session 注册和 complete empty inventory，才允许任何 Running Desired。

## 16. Canonical encoding、digest 与跨组件错误

### 16.1 Cats Canonical JSON v1

三个V1 digest都使用同一确定性编码，不依赖Rust struct声明顺序或`serde_json::Map`实现：

1. 先按本规格完成全部类型、范围、one-of、排序和唯一性验证；无效对象没有digest。
2. object key按其UTF-8 bytes无符号字典序升序；array保持schema要求的已验证顺序。
3. 不输出空白。输出固定token `null`、`true`、`false`；integer用最短十进制文本，零只编码为`0`，
   禁止`-0`、指数、浮点和前导零。
4. string以`"`包围；`"`和`\`分别编码为`\"`和`\\`，U+0008/U+000C/U+000A/U+000D/U+0009分别
   使用`\b`/`\f`/`\n`/`\r`/`\t`，其他U+0000..U+001F使用小写`\u00xx`；其余Unicode scalar直接
   输出UTF-8，不转义`/`，不做Unicode归一化。
5. digest bytes是`ASCII(domain_separator) || 0x00 || UTF8(canonical_json)`；算法固定SHA-256。
   wire使用`Sha256Digest`格式。比较digest使用解码后的32 bytes常量时间比较。

任何实现即使使用普通serde类型，也必须显式执行以上canonical writer；不能把默认JSON object顺序、
pretty JSON或数据库JSONB导出直接拿来hash。

### 16.2 三个 digest 输入

| digest | domain separator | canonical JSON输入 |
|---|---|---|
| `spec_digest` | `cats.runtime.desired-spec.v1` | 完整`DesiredRuntimeSpec`删除且仅删除顶层`spec_digest`字段；`version`保留 |
| `inventory_digest` | `cats.runtime.inventory.v1` | 下述`InventoryDigestInput` |
| `key_ring_digest` | `cats.runtime.key-ring.v1` | 下述`KeyRingDigestInput` |

```text
InventoryDigestInput {
  version: 1,
  node_id: Id,
  node_boot_id: NodeBootId,
  agent_instance_id: RandomId128,
  agent_session_epoch: Epoch,
  inventory_epoch: Epoch,
  inventory_read_position: Sequence,
  runtimes: [InventoryRuntimeEvidence]
}

InventoryRuntimeEvidence {
  cat_id: Id,
  applied_desired: AppliedDesiredEvidence | null,
  runtime_incarnation: RandomId128 | null,
  stable_state: "running" | "suspended" | "warm" | "cold" | "deleted" | null,
  step: ReconcileStep,
  checkpoint: CheckpointEvidence,
  processes: [ProcessEvidence],
  volumes: [ObservedVolume],
  mounts: [ObservedMount],
  network: ObservedNetwork,
  warm_snapshot: WarmSnapshotEvidence,
  lifecycle_admission: "open" | "closed",
  routes: [ObservedRouteGate],
  platform_guards: integer 0..=4294967295
}

KeyRingDigestInput {
  version: 1,
  key_ring_version: Epoch,
  loaded_kids: [KeyId]
}
```

`InventoryRuntimeEvidence`是`ObservedRuntimeStatus`删除且仅删除`conditions`后的逐字段投影；排序规则
不变。`NodeObservation`的observation ID、heartbeat sequence、Node时间、`complete_inventory`、key ring
字段不进入inventory digest。`KeyRingDigestInput.loaded_kids`与observation中的数组逐字节相同。这样
诊断Condition或heartbeat重发不会伪造新的物理inventory，而session、epoch、read position或任一物理
事实变化都会改变digest。

### 16.3 fixed vectors

以下code block内每个canonical JSON都是一行ASCII bytes，末尾没有newline。

**Desired spec vector**的hash输入domain为`cats.runtime.desired-spec.v1`：

```json
{"cat_id":"cat_01","desired_revision":7,"endpoints":[{"endpoint_id":"ep_01","hostname":"app.example.test","protocol":"http","route_epoch":9,"target_port":8080}],"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"runtime":{"boot_image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","guest_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","memory_bytes":2147483648,"network_config":{"gateway_ipv4":"10.240.0.5","guest_ipv4":"10.240.0.6","guest_mac":"02:ca:0a:f0:00:06","kind":"isolated_ipv4","network_id":"net_01","prefix_length":30},"vcpus":2},"target":"cold","transition":{"kind":"cancel_and_drain"},"version":1,"volumes":[{"access":"read_write_once","acquire":{"expected_unowned_epoch":0,"kind":"normal","transition_id":"22222222222222222222222222222222"},"attachment_id":"att_01","disk_id":"disk_root","disk_kind":"root","disposition":{"kind":"retain"},"durability":"strict","guest_device":{"serial":"cats-root","slot":0},"mount":null,"size_bytes":4294967296,"volume_id":"vol_root","volume_intent_id":"vint_root"}],"workspace_id":"ws_01"}
```

```text
spec_digest = sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409
```

**Empty full inventory vector**的hash输入domain为`cats.runtime.inventory.v1`：

```json
{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"inventory_epoch":4,"inventory_read_position":12,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","runtimes":[],"version":1}
```

```text
inventory_digest = sha256:81105374fe1984eb2eb5180c9cc58e9367f6d537098f77f51d66ee56192a0b7e
```

**Two-key ring vector**的hash输入domain为`cats.runtime.key-ring.v1`：

```json
{"key_ring_version":5,"loaded_kids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"version":1}
```

```text
key_ring_digest = sha256:7881e60fd2e5dfa2fda716f560d6f124a7defd6c06b9d23c1038c42471cc8000
```

实现测试必须逐字节断言canonical JSON和digest，另测object输入key顺序变化不改变结果、数组逆序/重复
被拒绝、`spec_digest`自身变化不进入其输入，以及任一被覆盖字段变化都会改变digest。

### 16.4 跨组件 typed errors

所有runtime contract边界使用同一错误对象：

```text
ContractError {
  error: ContractErrorDetail,
  message: string 0..=1024 UTF-8 bytes
}

SessionBinding {
  node_id: Id,
  node_boot_id: NodeBootId,
  agent_instance_id: RandomId128,
  agent_session_epoch: Epoch
}

ContractErrorDetail =
  {
    code: "stale_session",
    node_id: Id,
    presented_agent_session_epoch: Epoch,
    current_agent_session_epoch: Epoch
  }
| {
    code: "wrong_session",
    expected: SessionBinding,
    presented: SessionBinding
  }
| {
    code: "stale_revision",
    cat_id: Id,
    presented_revision: Revision,
    current_revision: Revision
  }
| {
    code: "wrong_revision",
    cat_id: Id,
    expected_revision: Revision,
    presented_revision: Revision
  }
| {
    code: "revision_digest_conflict",
    cat_id: Id,
    desired_revision: Revision,
    expected_digest: Sha256Digest,
    presented_digest: Sha256Digest
  }
| {
    code: "wrong_placement",
    cat_id: Id,
    desired_revision: Revision,
    expected: AssignedPlacement,
    presented: AssignedPlacement
  }
| {
    code: "unsupported_version",
    contract: ContractName,
    supported_version: 1,
    presented_version: integer 0..=18446744073709551615
  }
| {
    code: "malformed_payload",
    contract: ContractName,
    json_pointer: JsonPointer,
    problem: "missing_field" | "unknown_field" | "duplicate_field" | "invalid_type"
           | "invalid_value" | "duplicate_identity" | "non_canonical_order"
  }
| {
    code: "idempotency_conflict",
    authenticated_workspace_id: Id,
    canonical_route: AsciiText,
    idempotency_key: AsciiText,
    expected_request_fingerprint: Sha256Digest,
    presented_request_fingerprint: Sha256Digest
  }

ContractName = "node_identity" | "agent_registration_attempt" | "agent_session"
             | "admission_inventory_attestation" | "desired_runtime_spec"
             | "node_observation" | "operation"
```

`message`只供人读，接收方只能按`error.code`及typed payload分支。`json_pointer`使用RFC 6901文本，根
对象是空string。解析/验证优先级固定为：JSON语法/重复key/大小上限 -> object字段与primitive类型 ->
`version` -> 字段值和数组排序/唯一性 -> session -> revision -> digest -> placement。presented session
epoch小于current返回`stale_session`；epoch相同但boot/instance不匹配，或presented epoch更大，返回
`wrong_session`。Desired delivery中revision小于current返回`stale_revision`；精确结算要求不相等时
返回`wrong_revision`；revision相同而digest不同返回`revision_digest_conflict`。node ID或placement
epoch任一不匹配都返回`wrong_placement`。这些错误都不得推进checkpoint、结算Operation或产生物理
副作用。
