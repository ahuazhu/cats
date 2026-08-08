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

- `desired_revision`：每 Cat 单调递增、永不复用的 PostgreSQL BIGINT 正整数。
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
| `ContractVersion` | JSON integer `0..=9223372036854775807`；本规格支持值只为`1` |
| `Id` | JSON string；1..=128 个 ASCII bytes，只允许 `[A-Za-z0-9._:-]`，区分大小写，不做 Unicode 归一化 |
| `AsciiText` | JSON string；1..=512 个 printable ASCII bytes（`0x20..=0x7e`） |
| `JsonPointer` | 0..=512 个 printable ASCII bytes；必须是空string（根）或合法RFC 6901 pointer |
| `RandomId128` | 32 个小写十六进制字符，表示非全零16 bytes；不带连字符或`0x` |
| `NodeBootId` / `GuestBootId` | 把对应kernel boot UUID解析为16 bytes后按`RandomId128`编码 |
| `Revision` / `Epoch` / `Sequence` | JSON integer `1..=9223372036854775807`；禁止 `0`、负数、浮点数和 JSON string |
| `U64` | JSON integer `0..=9223372036854775807`；名称表示非负逻辑计数，不表示wire可接受完整Rust `u64`范围 |
| `Generation` | `U64`；只用于volume/local/remote generation |
| `FenceEpoch` | `U64`；只用于可能从0开始的MetadataStore attachment/lease epoch |
| `UnixMillis` | JSON integer `0..=9223372036854775807`，从 Unix epoch 起的毫秒；Control Plane freshness 只使用 PostgreSQL 写入的值 |
| `Sha256Digest` | JSON string `sha256:` 加 64 个小写十六进制字符 |
| `KeyId` | 64 个小写十六进制字符；等于Ed25519 SubjectPublicKeyInfo DER的SHA-256，不带`sha256:`前缀，以保持Route Grant v2 `kid` wire |
| `HostPath` | 1..=4096 bytes 的绝对 UTF-8 路径；禁止C0/DEL、空path component（即重复`/`）、`.`/`..` component和尾随`/`（根目录`/`除外） |
| `Hostname` | 1..=253 bytes的小写ASCII DNS名；每个label 1..=63且只含`[a-z0-9-]`、首尾为`[a-z0-9]`；禁止端口、路径和尾点 |
| `Ipv4Address` | 无前导零的 canonical dotted-decimal IPv4，例如 `10.240.0.6` |
| `MacAddress` | 六组小写十六进制 octet，例如 `02:ca:0a:f0:00:06` |

所有 object 字段都必填；后文写为 `T | null` 的字段也必须出现，并显式编码为 JSON `null`。所有 object
拒绝未知字段和重复 key。结构化 one-of 使用内部 tag `"kind"`；唯一例外是§16.4
`ContractErrorDetail`，其`"code"`同时是稳定错误码和union tag。简单无 payload 枚举使用下文列出的
snake_case JSON string。数组保留 wire 顺序，并按各 schema 指定的稳定 key 严格升序；重复 key、漏排或
逆序都是`malformed_payload`，接收方不能替调用方重排后接受。字符串不得包含控制字符；除`HostPath`
和人读`message`允许非ASCII外，共享合同字符串都必须是ASCII。

`HostPath`的实现算法固定为：`"/"`单独合法；其他值首byte必须是`/`且末byte不能是`/`，对移除首个
`/`后的bytes按`/`分割，每个component必须非空且不等于`.`或`..`。校验只按UTF-8 bytes执行，不查询
filesystem、不解析symlink，也不做Unicode或平台路径归一化。

### 1.2 V1 wire 与集合硬上限

接收方必须在分配或解析完整JSON前执行顶层wire byte上限。byte数是收到的完整UTF-8 JSON octet数，
不含HTTP framing；恰好等于上限合法。超过上限返回§16.4 `limit_exceeded {limit:"wire_bytes"}`。

| 顶层合同 | 最大wire bytes |
|---|---:|
| `NodeIdentity` | 16384 |
| `AgentRegistrationAttempt` | 16384 |
| `AgentSession` | 16384 |
| `AdmissionInventoryAttestation` | 16384 |
| `DesiredRuntimeSpec` | 1048576 |
| `RuntimeCheckpoint` | 4194304 |
| `NodeObservation` | 8388608 |
| `Operation` | 65536 |
| `ContractError` | 16384 |

所有array的item上限和total order在§10.4集中冻结；digest input继承其来源对象的相同上限。接收方不得
截断、分页解释一个顶层合同或静默丢弃超限item；array超限返回
`limit_exceeded {limit:"array_items"}`，且`json_pointer`指向该array。

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
`(node_id, registration_attempt_id)`只能对应一个完整`AgentSession`。相同完整
`AgentRegistrationAttempt`重放返回原session；`immutable_host_id`、`node_boot_id`、
`agent_instance_id`或`expected_agent_session_epoch`任一不同都返回§16.4
`registration_attempt_conflict`，不能把它当作新attempt，也不能复用`wrong_session`。
`agent_session_epoch`和`lease_deadline_unix_ms`由Control
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
  memory_bytes: integer 1..=9223372036854775807,
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
  size_bytes: integer 1..=9223372036854775807,
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
  networks: [ObservedNetwork],
  guest_transport: GuestTransportEvidence,
  warm_snapshot: WarmSnapshotEvidence,
  lifecycle_admission: "open" | "closed",
  route_gates: [CheckpointRouteGate],
  require_idle: RequireIdleCheckpoint,
  updated_at_unix_ms: UnixMillis
}

CheckpointRouteGate {
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

数组使用§10的相同排序/唯一性规则；`route_gates`按`binding.endpoint_id`排序。`step`本身携带当前窄effect
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
| CleanupRelease | 完整`CleanupTarget`、full-scan inventory epoch、`R == L`/disposition、当前 desired 读取位置 | 只删匹配资源、只 release 精确 owner/epoch；`orphan_scope`重读token/cgroup并证明无live PID/process，`control_socket`重读token并证明无live owner，`checkpoint_file`重读并重算digest/完整identity且由当前Desired/tombstone证明不再需要；重建或身份变化后的stale cleanup必须拒绝 |
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
  key_ring_version: Epoch | null,
  key_ring_digest: Sha256Digest | null,
  loaded_kids: [KeyId],
  runtimes: [ObservedRuntimeStatus],
  residue: [NodeResidue]
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
  networks: [ObservedNetwork],
  guest_transport: GuestTransportEvidence,
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
`key_ring_version`与`key_ring_digest`必须同时为null或同时非null：null/null要求`loaded_kids=[]`并表示
当前session尚无有效ring；非null时即使kids为空也表示已原子加载一个有效ring，且digest必须按§16.2
以该version和精确kids重算匹配。禁止null/non-null混合或null/null携带kids。Route signer只接受两个字段
都非null、digest匹配且active `kid`存在于`loaded_kids`的形态；unavailable和合法空ring都不能签发。
`complete_inventory=false`时只upsert报告中列出的Cat，不能按缺项删除，并且不得覆盖当前
AdmissionInventoryAttestation；此时`inventory_digest`和`inventory_read_position`必须都是`null`，
`inventory_epoch`引用当前已接受attestation，且Node级`residue`必须为空。`complete_inventory=true`
时两者必须非null，`residue`是该scan发现的完整Node级集合，且digest必须
按§16重算成功，才能按读取位置对完整集合做residue对账并建立新attestation。所有freshness使用
PostgreSQL `accepted_at_unix_ms`。partial只表示Node级Cat集合不完整；数组中每个
`ObservedRuntimeStatus`仍是该Cat的完整替换快照，不存在field-level patch语义。

### 10.1 checkpoint 与 step

```text
CheckpointEvidence =
  { kind: "missing" }
| { kind: "corrupt", raw_content_digest: Sha256Digest }
| {
    kind: "valid",
    content_digest: Sha256Digest,
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
| {
    kind: "orphan_scope",
    scope_id: Id,
    cgroup_path: HostPath,
    ownership_token: RandomId128
  }
| {
    kind: "control_socket",
    socket_path: HostPath,
    ownership_token: RandomId128
  }
| {
    kind: "checkpoint_file",
    checkpoint_path: HostPath,
    content_digest: Sha256Digest,
    cat_id: Id,
    node_id: Id,
    placement_epoch: Epoch,
    desired_revision: Revision
  }

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

`scope`是仍有精确process identity的进程绑定cleanup；已无进程的scope只能从
`NodeResidue.systemd_scope`产生`orphan_scope`。只有`ownership_token.kind="valid"`的
`systemd_scope`或`control_socket` residue才能分别产生对应target，并逐字段复制
scope/cgroup/path/token；missing/corrupt token不得产生target。执行`orphan_scope`前必须
重读token并确认逐字节相同、cgroup仍是同一个，且没有live PID或matching
`ProcessEvidence`；执行`control_socket`前必须重读相同token，且没有live process
拥有该socket。

`checkpoint_file`只能从`ResidueCheckpointFileEvidence.valid`产生，且target必须逐字段
复制path/content digest/Cat/Node/placement/revision。删除前必须重读文件，按§16.2
重算并核对content digest及完整identity，还必须由Control Plane当前Desired或
tombstone证明该checkpoint已不需要。`ResidueCheckpointFileEvidence.corrupt`不得产生
target，只能Quarantine/人工处理。scan后任一资源被重建，token、cgroup或
digest/identity发生变化时，旧cleanup必须拒绝，不得按可重算名称或path删除。

`CheckpointEvidence.valid.content_digest`必须等于§16.2对完整`RuntimeCheckpoint`（包括process、volume、
device、mount、network、Guest transport、snapshot、route gate和RequireIdle事实）计算的digest；valid
projection中的其余字段必须与该checkpoint逐字段相同。`corrupt.raw_content_digest`只是损坏文件原始bytes
的普通SHA-256（不加domain separator），用于关联诊断，不能伪装成valid checkpoint content digest。

### 10.2 物理证据

```text
ProcessEvidence {
  role: ProcessRole,
  process_id: integer 1..=4294967295,
  process_start_time_ticks: U64,
  executable_path: HostPath,
  scope_id: Id,
  control_socket_path: HostPath,
  state: "running" | "paused",
  ownership_token: OwnershipTokenEvidence,
  control_handshake: ControlHandshakeEvidence,
  observed_vm_shape: ObservedVmShape | null
}

ProcessRole =
  { kind: "vmm", runtime_incarnation: RandomId128 }
| {
    kind: "blockd",
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch
  }

ObservedVmShape {
  vcpus: integer 1..=4294967295,
  memory_bytes: integer 1..=9223372036854775807,
  boot_image_digest: Sha256Digest,
  guest_config_digest: Sha256Digest
}

ControlHandshakeEvidence =
  { kind: "unavailable" }
| { kind: "malformed", raw_response_digest: Sha256Digest }
| { kind: "verified" }

GuestTransportEvidence =
  { kind: "unavailable" }
| { kind: "malformed", raw_response_digest: Sha256Digest }
| {
    kind: "vsock_ready",
    runtime_incarnation: RandomId128,
    guest_cid: integer 3..=4294967295,
    guest_port: integer 1..=65535,
    guest_agent_protocol_version: 1,
    guest_boot_id: GuestBootId
  }

OwnershipTokenEvidence =
  { kind: "missing" }
| { kind: "corrupt", raw_content_digest: Sha256Digest }
| { kind: "valid", ownership_token: RandomId128 }

ObservedVolume {
  volume_intent_id: Id | null,
  disk_id: Id | null,
  volume_id: Id,
  disk_kind: "root" | "persistent" | "unknown",
  size_bytes: integer 1..=9223372036854775807 | null,
  durability: "strict" | "relaxed" | null,
  authority: VolumeAuthorityEvidence,
  local_lineages: [LocalVolumeLineage],
  devices: [ObservedDevice]
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
  {
    kind: "kernel_nbd",
    guest_device: GuestDeviceIdentity,
    device_path: HostPath,
    ownership_token: OwnershipTokenEvidence
  }
| {
    kind: "vhost_user_blk",
    guest_device: GuestDeviceIdentity,
    socket_path: HostPath,
    ownership_token: OwnershipTokenEvidence
  }

ObservedMount {
  volume_id: Id,
  guest_device: GuestDeviceIdentity,
  filesystem_uuid: RandomId128,
  mount_path: HostPath,
  access: "read_write" | "read_only",
  instance_count: integer 1..=9223372036854775807
}

ObservedNetwork {
  kind: "isolated_ipv4",
  network_id: Id,
  guest_mac: MacAddress,
  guest_ipv4: Ipv4Address,
  prefix_length: 30,
  gateway_ipv4: Ipv4Address,
  tap_name: Id,
  ownership_token: OwnershipTokenEvidence
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
  binding: RouteGateBinding,
  gate: "active" | "closed",
  active_guards: integer 0..=4294967295,
  cancellation_pending: boolean,
  instance_count: integer 1..=9223372036854775807
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

RouteBindingEvidence =
  { kind: "missing" }
| { kind: "corrupt", raw_content_digest: Sha256Digest }
| { kind: "valid", binding: RouteGateBinding }

NodeResidue =
  {
    kind: "process",
    process_id: integer 1..=4294967295,
    process_start_time_ticks: U64,
    executable_path: HostPath,
    scope_id: Id | null,
    control_socket_path: HostPath | null,
    role_hint: ProcessRole | null,
    ownership_token: OwnershipTokenEvidence,
    control_handshake: ControlHandshakeEvidence
  }
| {
    kind: "systemd_scope",
    scope_id: Id,
    cgroup_path: HostPath,
    ownership_token: OwnershipTokenEvidence
  }
| {
    kind: "control_socket",
    socket_path: HostPath,
    role_hint: ProcessRole | null,
    ownership_token: OwnershipTokenEvidence
  }
| {
    kind: "checkpoint_file",
    checkpoint_path: HostPath,
    evidence: ResidueCheckpointFileEvidence
  }
| {
    kind: "kernel_nbd",
    volume_id_hint: Id | null,
    guest_device: GuestDeviceIdentity | null,
    device_path: HostPath,
    ownership_token: OwnershipTokenEvidence
  }
| {
    kind: "vhost_user_blk",
    volume_id_hint: Id | null,
    guest_device: GuestDeviceIdentity | null,
    socket_path: HostPath,
    ownership_token: OwnershipTokenEvidence
  }
| {
    kind: "network_tap",
    network_id_hint: Id | null,
    tap_name: Id,
    ownership_token: OwnershipTokenEvidence
  }
| {
    kind: "data_directory",
    volume_id_hint: Id | null,
    data_directory: HostPath,
    ownership_token: OwnershipTokenEvidence,
    lineage: ResidueLineageEvidence
  }
| {
    kind: "mount",
    volume_id_hint: Id | null,
    source_path: HostPath,
    mount_path: HostPath,
    instance_count: integer 1..=9223372036854775807
  }
| {
    kind: "warm_snapshot",
    snapshot_id_hint: Id | null,
    path: HostPath,
    file_size_bytes: U64,
    file_digest: Sha256Digest | null
  }
| {
    kind: "route_gate",
    binding: RouteBindingEvidence,
    gate: "active" | "closed",
    active_guards: integer 0..=4294967295,
    cancellation_pending: boolean,
    instance_count: integer 1..=9223372036854775807
  }

ResidueLineageEvidence =
  { kind: "unreadable" }
| {
    kind: "readable",
    attachment_id_hint: Id | null,
    attachment_epoch_hint: FenceEpoch | null,
    local_durable_generation: Generation,
    remote_durable_generation: Generation,
    pending_pack_count: U64,
    fenced: boolean
  }

ResidueCheckpointFileEvidence =
  { kind: "corrupt", raw_content_digest: Sha256Digest }
| {
    kind: "valid",
    content_digest: Sha256Digest,
    format_version: ContractVersion,
    cat_id: Id,
    node_id: Id,
    placement_epoch: Epoch,
    desired_revision: Revision,
    spec_digest: Sha256Digest,
    runtime_incarnation: RandomId128 | null
  }
```

`local_durable_generation >= remote_durable_generation`。`disk_kind="unknown"`时
`volume_intent_id`和`disk_id`都必须为`null`；其他kind时两者都必须非null。`size_bytes`和`durability`
是从blockd/attachment物理配置取得的observed值，不得从Desired复制来冒充证据；无法读取时为`null`，
任何稳定态要求的卷都必须非null且等于Desired。

同一`ProcessRole`可以出现多个不同process identity；同一`volume_id`可以出现多个device；同一
`network_id`可以出现多个tap；同一`endpoint_id`可以出现多个route record。完全相同的route binding/
gate/guard事实合并为一项并用`instance_count`保留multiplicity，不能去重成1。空`devices`或`networks`
分别表示没有发现frontend或tap，不再使用会压扁冲突的单值`absent`variant。

`ProcessEvidence.role`是scope/checkpoint/token给出的归属主张，不代表已经验证；只有
`control_handshake="verified"`才证明control socket自报身份匹配。VMM的
`observed_vm_shape`当且仅当control handshake verified时非null；blockd永远为null。Running稳定态还
要求`guest_transport="vsock_ready"`绑定同一runtime incarnation，且Guest boot ID/protocol握手成功。
本节所有`raw_content_digest`/`raw_response_digest`都是字段所指原始bytes的普通SHA-256，不加domain
separator；它们只关联不可解析证据，不能当作成功handshake或ownership。

full scan发现的每个约定资源必须恰好进入某个`ObservedRuntimeStatus`，或在不能可靠归属Cat/Volume时
进入顶层`NodeObservation.residue`。`*_hint`和`role_hint`只记录不可信线索，不能据此cleanup。
没有live matching process的systemd scope/cgroup与control socket分别进入`systemd_scope`和
`control_socket`；仍存在但不能关联assigned Cat的checkpoint进入`checkpoint_file`。scope/socket只有
ownership token为valid且与持久化cleanup identity精确匹配时才可清理。valid checkpoint evidence的
content digest按§16.2绑定完整文件，所列字段必须与文件逐字段相同；corrupt evidence只保留path和raw
digest并禁止自动清理。不能因为进程已死就按可重算scope/socket/checkpoint名字删除。
`systemd_scope`要求bounded scan确认该cgroup没有live PID且没有匹配`ProcessEvidence`；`control_socket`
要求没有任何live `(process_start_time_ticks, process_id)`拥有该socket。否则必须同时报告对应process
事实，不能伪装成可直接清理的standalone residue。
非自描述资源的token文件缺席/损坏分别编码`missing`/`corrupt`；`corrupt.raw_content_digest`是原始文件
bytes的普通SHA-256。不得因token无效而省略资源。readable residue lineage也必须满足
`local_durable_generation >= remote_durable_generation`；attachment ID/epoch hints必须同时为null或
同时非null，且只作为线索。完全相同的Node residue mount按
`(volume_id_hint, source_path, mount_path)`合并并累计`instance_count`。partial observation不携带Node级residue；full
inventory digest覆盖全部runtime evidence和完整residue集合。

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
| { kind: "checkpoint_corrupt", raw_content_digest: Sha256Digest }
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
| { kind: "duplicate_device", volume_id: Id, observed_device_count: U64 }
| {
    kind: "duplicate_mount",
    volume_id: Id,
    mount_path: HostPath,
    observed_instance_count: U64
  }
| { kind: "duplicate_network", network_id: Id, observed_tap_count: U64 }
| { kind: "duplicate_route", endpoint_id: Id, observed_instance_count: U64 }
| {
    kind: "invalid_ownership_token",
    resource: OwnershipTokenResource,
    evidence: OwnershipTokenEvidence
  }
| { kind: "unattributed_node_residue", residue: NodeResidue }
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

OwnershipTokenResource =
  { kind: "process", process_id: integer 1..=4294967295, process_start_time_ticks: U64 }
| { kind: "kernel_nbd", device_path: HostPath }
| { kind: "vhost_user_blk", socket_path: HostPath }
| { kind: "network_tap", tap_name: Id }
| { kind: "data_directory", data_directory: HostPath }

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

所有Condition内array按§10.4的rank/tuple升序且无重复；`observed_attachments`长度必须`>= 2`且identity
互不相同。
`unavailable_sources`、`sources`和`volume_ids`都非空。`runtime_identity_conflict.observed_incarnations`
非空且至少一项不同于`expected_incarnation`；`duplicate_runtime.observed_incarnations`和
`process_identity_conflict.process_ids`都要求`length >= 2`且各值不同。所有
`remote_durability_lag`/`remote_tail_unavailable`必须满足`local_generation > remote_generation`；
`active_guards`必须至少有一个非零platform或Endpoint guard。
`duplicate_device.observed_device_count`、`duplicate_mount.observed_instance_count`、
`duplicate_network.observed_tap_count`和
`duplicate_route.observed_instance_count`都必须至少为2。device count精确等于该`ObservedVolume.devices`
长度；mount count精确等于同一`(volume_id, mount_path)`各item的`instance_count`之和；tap count精确等于
同一`network_id`的`ObservedNetwork` item数；route count精确等于所有
`binding.endpoint_id == reason.endpoint_id`的`ObservedRouteGate.instance_count`之和。所有和必须可表示为`U64`。
`invalid_ownership_token.evidence`只允许`missing`或
`corrupt`，不能携带`valid`。
Conditions可并存，但`kind="ready"`每个runtime至多一个，其他Condition按
§10.4的rank/bytes tuple升序且不允许逐字节重复。V1不得增加string-only reason、
任意JSON evidence或按message文本分支；新物理故障语义需要先修改本闭集。

- Blocked 是可重试前置条件，Operation 保持 Pending。
- PreconditionFailed 是该 revision 的终态；例如 RequireIdle Busy 使 Operation Failed。
- Degraded 表示已验证的稳定服务继续运行，但暂时不能安全做新副作用。attestation和per-Cat
  facts仍fresh时可报告`Ready + Degraded`，保持既有admission并允许signer继续验证Ready；任一
  freshness过期或安全postcondition不再可证时必须移除Ready并停止新Grant签发。
- Quarantined 表示确定的身份/ownership 冲突；立即关闭 gates，并使当前 Pending Operation
  Failed。修复或删除必须提交新 revision。若该 revision 的 Operation 早已 Succeeded，不回写
  历史结果；控制面创建新的系统修复 revision 来承载失败与处置。

### 10.4 Array 上限与 canonical total order

下表覆盖本规格出现的全部array。比较integer使用数值顺序，string/`Id`/path/digest使用wire UTF-8 bytes
的无符号字典序，boolean使用`false < true`，`null`小于任何非null值；enum/union的rank是其schema中从
上到下的variant顺序。`CJ(x)`是§16.1的canonical JSON bytes。表中tuple从左到右比较，最后的
`CJ(item)`使tuple覆盖item所有字段并形成完整total order；array必须严格升序，逐字段完全相同的item
不能重复。需要保留完全相同物理实例multiplicity的observed/residue mount和route使用
`instance_count`，不能复制相同item。

| Array（相同嵌套类型的checkpoint/digest投影继承同一规则） | 最大items | total-order tuple；额外唯一性 |
|---|---:|---|
| `DesiredRuntimeSpec.volumes` | 64 | `(volume_intent_id)`；§3.1列出的各identity分别唯一 |
| `DesiredRuntimeSpec.endpoints` | 256 | `(endpoint_id)`；`endpoint_id`和`hostname`分别唯一 |
| `processes` | 128 | `(role.kind rank, role stable identity, process_start_time_ticks, process_id, CJ(item))`；`role stable identity`对VMM是`runtime_incarnation`，对blockd是`(volume_id, attachment_epoch, attachment_id)`；`(process_start_time_ticks, process_id)`唯一 |
| `volumes` | 64 | `(volume_id)`；`volume_id`唯一 |
| `ObservedVolume.local_lineages` | 8 | `(attachment_epoch, attachment_id, data_directory, CJ(item))`；`data_directory`唯一 |
| `ObservedVolume.devices` | 16 | `(kind rank, physical_path, guest_device.serial, guest_device.slot, CJ(item))`；kernel NBD的`physical_path=device_path`，vhost-user的`physical_path=socket_path`，physical path唯一 |
| `mounts` | 64 | `(volume_id, mount_path, guest_device.serial, guest_device.slot, access rank, CJ(item))`；完全相同的stacked mount合并并累计`instance_count` |
| `networks` | 16 | `(network_id, tap_name, guest_mac, guest_ipv4, gateway_ipv4, CJ(item))`；`tap_name`唯一 |
| `RequireIdleCheckpoint.endpoint_guards`、`BlockedReason.active_guards.endpoint_guards`、`PreconditionFailureReason.busy.endpoint_guards` | 256 | `(endpoint_id)`；`endpoint_id`唯一 |
| `ReconcileStep.snapshot_warm_runtime.source_heads`、`WarmSnapshotEvidence.present.source_heads` | 64 | `(volume_id)`；`volume_id`唯一 |
| `RuntimeCheckpoint.route_gates` | 256 | `(binding.endpoint_id)`；`binding.endpoint_id`唯一 |
| `ObservedRuntimeStatus.routes` | 512 | `(binding.endpoint_id, binding.route_epoch, binding.workspace_id, binding.cat_id, binding.node_id, binding.runtime_incarnation, gate rank, CJ(item))`；允许同Endpoint不同binding，完全相同实例累计`instance_count` |
| `ObservedRuntimeStatus.conditions` | 64 | `(Condition.kind rank, reason.kind rank, CJ(item))` |
| `NodeObservation.loaded_kids` / `KeyRingDigestInput.loaded_kids` | 64 | `(KeyId)`；`KeyId`唯一 |
| `NodeObservation.runtimes` / `InventoryDigestInput.runtimes` | 1024 | `(cat_id)`；`cat_id`唯一 |
| `NodeObservation.residue` / `InventoryDigestInput.residue` | 4096 | `(NodeResidue.kind rank, residue primary identity, CJ(item))`；全部variant合计，primary identity见下文 |
| `IncompleteInventory.unavailable_sources` | 11 | `(InventorySource rank)`；非空且variant唯一 |
| `DegradedReason.source_unavailable.sources` | 12 | `(DegradedSource rank)`；非空且variant唯一 |
| `BlockedReason.volume_authority_unavailable.volume_ids` | 64 | `(Id)`；非空且ID唯一 |
| `QuarantineReason.runtime_identity_conflict.observed_incarnations` | 128 | `(RandomId128)`；非空、identity唯一，且至少一项不等于同reason的`expected_incarnation` |
| `QuarantineReason.duplicate_runtime.observed_incarnations` | 128 | `(RandomId128)`；至少2项且identity唯一 |
| `QuarantineReason.process_identity_conflict.process_ids` | 128 | `(integer)`；至少2项且PID唯一 |
| `QuarantineReason.duplicate_writer.observed_attachments` | 64 | `(attachment_epoch, attachment_id)`；至少2项且identity唯一 |

`NodeResidue`的primary identity按variant分别是：process的
`(process_start_time_ticks, process_id, executable_path)`、systemd scope的`(scope_id, cgroup_path)`、
control socket的`socket_path`、checkpoint file的`checkpoint_path`、kernel NBD的`device_path`、vhost-user的
`socket_path`、network tap的`tap_name`、data directory的`data_directory`、mount的
`(mount_path, source_path)`、warm snapshot的`path`、route gate的`CJ(binding)`。同一物理path/PID/tap
以及同一scope/control socket/checkpoint file不得在runtime evidence与`residue`重复出现。任何array超过
表中上限都使整个顶层合同失败，不能把
`complete_inventory`降为false后截断发送。

## 11. 稳定 postcondition

- **Running**：恰好一个匹配incarnation的VMM process，control handshake verified且state为Running；
  `observed_vm_shape`逐字段匹配vCPU、memory、boot image和guest config；`guest_transport`为绑定同一
  incarnation的`vsock_ready`。每个Desired volume的size/durability、authority owner/epoch、唯一frontend
  device、Guest serial/slot及要求的UUID/read-write mount逐字段匹配，且无额外volume/device/mount。
  恰好一个匹配Desired network的tap；每个Endpoint恰好一个`instance_count=1`的Active route，binding
  全匹配且无额外route；ownership token全部valid、Node级`residue`为空；observation与
  revision/placement/incarnation匹配。
- **Suspended**：gates Closed 且 guards=0；VMM paused；本地 durability barrier 完成；所有
  `R < L` journal/lease/blockd 保留；VM shape、volume size/durability和ownership证据仍与Desired匹配。
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
| 进程崩溃，scope/socket/checkpoint仍存在 | full inventory报告三类standalone residue；valid evidence产生精确CleanupRelease，cleanup后的full rescan报告residue为空，Running可重新满足Ready |
| scan与cleanup之间资源被重建 | token、digest、cgroup或process identity任一不匹配时旧cleanup拒绝，新资源保留 |
| standalone scope/socket token missing或corrupt | 不生成CleanupTarget，不删除，进入Quarantined/人工处理 |
| standalone checkpoint corrupt | 不生成`checkpoint_file` target，不自动删除，进入Quarantined/人工处理 |
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

本节四个V1 deterministic digest都使用同一确定性编码，不依赖Rust struct声明顺序或
`serde_json::Map`实现：

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

### 16.2 Digest 输入

| digest | domain separator | canonical JSON输入 |
|---|---|---|
| `spec_digest` | `cats.runtime.desired-spec.v1` | 完整`DesiredRuntimeSpec`删除且仅删除顶层`spec_digest`字段；`version`保留 |
| `CheckpointEvidence.valid.content_digest` | `cats.runtime.checkpoint-content.v1` | 完整`RuntimeCheckpoint`，不删除任何字段 |
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
  runtimes: [InventoryRuntimeEvidence],
  residue: [NodeResidue]
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
  networks: [ObservedNetwork],
  guest_transport: GuestTransportEvidence,
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

checkpoint content digest的输入先按`RuntimeCheckpoint`的全部验证和§10.4上限/排序验证，再直接
canonical encode；它不hash文件外层长度、filesystem metadata或raw JSON空白。这样valid evidence中的
一个digest绑定checkpoint里没有逐字段复制出来的全部物理事实。

`InventoryRuntimeEvidence`是`ObservedRuntimeStatus`删除且仅删除`conditions`后的逐字段投影；排序规则
不变。`NodeObservation`的observation ID、heartbeat sequence、Node时间、`complete_inventory`、key ring
字段不进入inventory digest；顶层`residue`逐字段进入。`KeyRingDigestInput.loaded_kids`与observation中的数组逐字节相同。这样
诊断Condition或heartbeat重发不会伪造新的物理inventory，而session、epoch、read position或任一物理
事实变化都会改变digest。

`KeyRingDigestInput`只在NodeObservation的ring version/digest都非null时存在；null/null/empty的
unavailable形态没有key-ring digest input。non-null/non-null/empty是合法空ring，必须对
`{version:1,key_ring_version,loaded_kids:[]}`正常canonical encode并验证digest，不能与unavailable合并。

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
{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"inventory_epoch":4,"inventory_read_position":12,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","residue":[],"runtimes":[],"version":1}
```

```text
inventory_digest = sha256:12c19ac927b853c8f66f6dac52d448d6f2e797925527a0c606c7692b6f714e05
```

**Checkpoint content vector**的hash输入domain为`cats.runtime.checkpoint-content.v1`：

```json
{"cat_id":"cat_01","desired_revision":7,"format_version":1,"guest_transport":{"kind":"unavailable"},"lifecycle_admission":"closed","mounts":[],"networks":[],"node_id":"node_a","placement_epoch":3,"processes":[],"require_idle":{"kind":"not_applicable"},"route_gates":[],"runtime_incarnation":null,"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"updated_at_unix_ms":1720000000000,"volumes":[],"warm_snapshot":{"kind":"absent"}}
```

```text
checkpoint_content_digest = sha256:2c934710769641606abfeababb6dd599670852e38f0c774b6733e33d42b9bed5
```

**Non-empty full inventory vector**使用同一个inventory domain。它刻意包含两个frontend、两个tap、
route multiplicity、VMM shape/Guest Ready、volume size/durability、missing/corrupt token及Node residue，
包括dead-process遗留的scope/cgroup、control socket、corrupt checkpoint，并在无法归属的data directory
中保留`R < L` lineage，所以不是Ready postcondition：

```json
{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"inventory_epoch":4,"inventory_read_position":12,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","residue":[{"cgroup_path":"/sys/fs/cgroup/system.slice/cats-orphan.scope","kind":"systemd_scope","ownership_token":{"kind":"valid","ownership_token":"dddddddddddddddddddddddddddddddd"},"scope_id":"cats-orphan.scope"},{"kind":"control_socket","ownership_token":{"kind":"missing"},"role_hint":null,"socket_path":"/run/cats/orphan/control.sock"},{"checkpoint_path":"/var/lib/cats/checkpoints/orphan.json","evidence":{"kind":"corrupt","raw_content_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"kind":"checkpoint_file"},{"data_directory":"/var/lib/cats/orphan-vol","kind":"data_directory","lineage":{"attachment_epoch_hint":4,"attachment_id_hint":"att_orphan","fenced":false,"kind":"readable","local_durable_generation":6,"pending_pack_count":2,"remote_durable_generation":5},"ownership_token":{"kind":"corrupt","raw_content_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"volume_id_hint":null}],"runtimes":[{"applied_desired":{"desired_revision":7,"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","target":"running"},"cat_id":"cat_01","checkpoint":{"cat_id":"cat_01","content_digest":"sha256:2c934710769641606abfeababb6dd599670852e38f0c774b6733e33d42b9bed5","desired_revision":7,"format_version":1,"kind":"valid","node_id":"node_a","placement_epoch":3,"require_idle":{"kind":"not_applicable"},"runtime_incarnation":null,"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"updated_at_unix_ms":1720000000000},"guest_transport":{"guest_agent_protocol_version":1,"guest_boot_id":"cccccccccccccccccccccccccccccccc","guest_cid":3,"guest_port":5000,"kind":"vsock_ready","runtime_incarnation":"55555555555555555555555555555555"},"lifecycle_admission":"closed","mounts":[{"access":"read_write","filesystem_uuid":"99999999999999999999999999999999","guest_device":{"serial":"cats-root","slot":0},"instance_count":1,"mount_path":"/","volume_id":"vol_root"}],"networks":[{"gateway_ipv4":"10.240.0.5","guest_ipv4":"10.240.0.6","guest_mac":"02:ca:0a:f0:00:06","kind":"isolated_ipv4","network_id":"net_01","ownership_token":{"kind":"valid","ownership_token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"prefix_length":30,"tap_name":"tap0"},{"gateway_ipv4":"10.240.0.5","guest_ipv4":"10.240.0.6","guest_mac":"02:ca:0a:f0:00:06","kind":"isolated_ipv4","network_id":"net_01","ownership_token":{"kind":"corrupt","raw_content_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"prefix_length":30,"tap_name":"tap1"}],"platform_guards":0,"processes":[{"control_handshake":{"kind":"verified"},"control_socket_path":"/run/cats/cat_01/vmm.sock","executable_path":"/usr/bin/cloud-hypervisor","observed_vm_shape":{"boot_image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","guest_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","memory_bytes":2147483648,"vcpus":2},"ownership_token":{"kind":"valid","ownership_token":"66666666666666666666666666666666"},"process_id":1001,"process_start_time_ticks":9001,"role":{"kind":"vmm","runtime_incarnation":"55555555555555555555555555555555"},"scope_id":"cats-cat_01","state":"running"},{"control_handshake":{"kind":"verified"},"control_socket_path":"/run/cats/cat_01/blockd-root.sock","executable_path":"/usr/bin/cats-blockd","observed_vm_shape":null,"ownership_token":{"kind":"valid","ownership_token":"77777777777777777777777777777777"},"process_id":1002,"process_start_time_ticks":9002,"role":{"attachment_epoch":8,"attachment_id":"att_01","kind":"blockd","volume_id":"vol_root"},"scope_id":"cats-cat_01","state":"running"}],"routes":[{"active_guards":0,"binding":{"cat_id":"cat_01","endpoint_id":"ep_01","hostname":"app.example.test","node_id":"node_a","protocol":"http","route_epoch":9,"runtime_incarnation":"55555555555555555555555555555555","target_port":8080,"workspace_id":"ws_01"},"cancellation_pending":false,"gate":"closed","instance_count":2},{"active_guards":0,"binding":{"cat_id":"cat_01","endpoint_id":"ep_01","hostname":"app.example.test","node_id":"node_a","protocol":"http","route_epoch":10,"runtime_incarnation":"55555555555555555555555555555555","target_port":8080,"workspace_id":"ws_01"},"cancellation_pending":false,"gate":"closed","instance_count":1}],"runtime_incarnation":"55555555555555555555555555555555","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"volumes":[{"authority":{"attachment_epoch":8,"attachment_id":"att_01","generation":4,"kind":"owned","remote_root":"sha256:2222222222222222222222222222222222222222222222222222222222222222"},"devices":[{"device_path":"/dev/nbd0","guest_device":{"serial":"cats-root","slot":0},"kind":"kernel_nbd","ownership_token":{"kind":"valid","ownership_token":"88888888888888888888888888888888"}},{"guest_device":{"serial":"cats-root","slot":0},"kind":"vhost_user_blk","ownership_token":{"kind":"missing"},"socket_path":"/run/cats/cat_01/root.sock"}],"disk_id":"disk_root","disk_kind":"root","durability":"strict","local_lineages":[{"acquire_transition_id":"tx_01","attachment_epoch":8,"attachment_id":"att_01","data_directory":"/var/lib/cats/vol_root","fenced":false,"local_durable_generation":5,"node_id":"node_a","pending_pack_count":1,"placement_epoch":3,"remote_durable_generation":4,"state":"active"}],"size_bytes":4294967296,"volume_id":"vol_root","volume_intent_id":"vint_root"}],"warm_snapshot":{"kind":"absent"}}],"version":1}
```

```text
inventory_digest = sha256:e0124bbd80a4ebf490a7e2b8d5db3c351df0937a1a0bb09cdb108d1f463c2792
```

**Valid empty key ring vector**的hash输入domain为`cats.runtime.key-ring.v1`：

```json
{"key_ring_version":1,"loaded_kids":[],"version":1}
```

```text
key_ring_digest = sha256:966a44bd1b4337c7e7dae913607740e7c7359bab2b7d4127419d63f3f9903cbb
```

**Two-key ring vector**的hash输入domain为`cats.runtime.key-ring.v1`：

```json
{"key_ring_version":5,"loaded_kids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"version":1}
```

```text
key_ring_digest = sha256:7881e60fd2e5dfa2fda716f560d6f124a7defd6c06b9d23c1038c42471cc8000
```

实现测试必须逐字节断言全部canonical JSON和digest，另测object输入key顺序变化不改变结果、数组
逆序/重复/超限被拒绝、`spec_digest`自身变化不进入其输入，以及checkpoint物理字段、inventory residue/
multiplicity或任一其他被覆盖字段变化都会改变对应digest。NodeObservation serde/validation另测
null/null/empty unavailable、non-null/non-null/empty valid ring及所有禁止的混合组合；unavailable没有
key-ring digest，valid empty ring必须匹配上面的fixed vector。negative tests还必须覆盖route gate外层
`endpoint_id`作为unknown field被拒绝、`runtime_identity_conflict`单个different identity合法、只有
expected identity非法、`duplicate_runtime`少于两个different identity非法，以及invalid UTF-8、invalid
JSON、duplicate field、invalid type/value按§16.4优先级返回且前两者pointer为空。

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

RegistrationAttemptBinding {
  immutable_host_id: Id,
  node_boot_id: NodeBootId,
  agent_instance_id: RandomId128,
  expected_agent_session_epoch: Epoch | null
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
    code: "registration_attempt_conflict",
    node_id: Id,
    registration_attempt_id: RandomId128,
    expected: RegistrationAttemptBinding,
    presented: RegistrationAttemptBinding
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
    presented_version: integer 0..=9223372036854775807
  }
| {
    code: "malformed_payload",
    contract: ContractName,
    json_pointer: JsonPointer,
    problem: "invalid_utf8" | "invalid_json" | "missing_field" | "unknown_field"
           | "duplicate_field" | "invalid_type"
           | "invalid_value" | "duplicate_identity" | "non_canonical_order"
  }
| {
    code: "limit_exceeded",
    contract: ContractName,
    json_pointer: JsonPointer,
    limit: "wire_bytes" | "array_items",
    maximum: U64,
    observed_at_least: U64
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
             | "runtime_checkpoint" | "node_observation" | "operation" | "contract_error"
```

`message`只供人读，接收方只能按`error.code`及typed payload分支。`json_pointer`使用RFC 6901文本，根
对象是空string。`limit_exceeded.observed_at_least`必须大于`maximum`；decoder在读到
`maximum + 1`个byte/item时即可停止并报告该值，不需要继续接收攻击者控制的剩余payload。解析/验证
优先级固定为：顶层wire byte上限 -> UTF-8 decode -> JSON grammar -> duplicate object key -> object字段与
primitive类型 -> `version` -> array item上限 -> 字段值和数组排序/唯一性 -> session -> revision ->
digest -> placement。UTF-8 decode失败返回`invalid_utf8`，UTF-8合法但JSON grammar不完整/非法返回
`invalid_json`；二者的`json_pointer`固定为空string。只有完整JSON grammar成功后才检测
`duplicate_field`，其pointer指向重复member；`invalid_type`/`invalid_value`再晚于object字段检查。
presented session
epoch小于current返回`stale_session`；epoch相同但boot/instance不匹配，或presented epoch更大，返回
`wrong_session`。Desired delivery中revision小于current返回`stale_revision`；精确结算要求不相等时
返回`wrong_revision`；revision相同而digest不同返回`revision_digest_conflict`。node ID或placement
epoch任一不匹配都返回`wrong_placement`。这些错误都不得推进checkpoint、结算Operation或产生物理
副作用。

`version`不是JSON integer或超出`0..=9223372036854775807`时返回
`malformed_payload {json_pointer:"/version", problem:"invalid_type"|"invalid_value"}`；范围内但不等于1
才返回`unsupported_version`。因此unsupported error自身始终能无损进入PostgreSQL BIGINT。

registration replay在当前session检查前先按`(node_id, registration_attempt_id)`查找已提交attempt；命中
且binding不同返回`registration_attempt_conflict`。`expected`是首次提交的四字段binding，`presented`
是本次请求，不包含服务端分配的session epoch/deadline，也不构造两个虚假的`SessionBinding`。
