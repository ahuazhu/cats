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
runtime/Node cleanup checkpoint、observation/condition物理证据、§12的Operation以及§16的
digest/error类型。§3.3的
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

所有上述逻辑integer及schema内直接写出的非负integer范围都只接受raw JSON number token
`0|[1-9][0-9]*`，再检查各自逻辑域；decoder必须保留或等价检查原始number lexeme，不能让JSON库先把
`1.0`、`1e0`或`-0`归一化为integer。完整错误分类和stage见§16.4。

所有 object 字段都必填；后文写为 `T | null` 的字段也必须出现，并显式编码为 JSON `null`。所有 object
拒绝未知字段和重复 key。结构化 one-of 使用内部 tag `"kind"`；唯一例外是§16.4
`ContractErrorDetail`，其`"code"`同时是稳定错误码和union tag。简单无 payload 枚举使用下文列出的
snake_case JSON string。数组保留 wire 顺序，并按各 schema 指定的稳定 key 严格升序；重复 key、漏排或
逆序都是`malformed_payload`，接收方不能替调用方重排后接受。字符串不得包含控制字符；除`HostPath`
和人读`message`允许非ASCII外，共享合同字符串都必须是ASCII。

`HostPath`的实现算法固定为：`"/"`单独合法；其他值首byte必须是`/`且末byte不能是`/`，对移除首个
`/`后的bytes按`/`分割，每个component必须非空且不等于`.`或`..`。校验只按UTF-8 bytes执行，不查询
filesystem、不解析symlink，也不做Unicode或平台路径归一化。

§1.2列出的每个顶层合同都必须有名为`version`、wire类型为`ContractVersion`的必填字段，
V1的值只能是`1`；顶层不存在`format_version`或按合同名变化的version字段。
`CheckpointEvidence.valid`和`ResidueCheckpointFileEvidence.valid`中的`version`是对
`RuntimeCheckpoint.version`的逐字段投影，不是另一个版本空间。§16.4的同一decoder优先级和
`unsupported_version`规则适用于全部顶层合同，包括`RuntimeCheckpoint`和`ContractError`；
为拒绝非V1输入而返回的`ContractError`自身仍必须编码`version: 1`。

### 1.2 V1 wire 与集合硬上限

接收方必须在分配或解析完整JSON前执行顶层wire byte上限。byte数是收到的完整UTF-8 JSON octet数，
不含HTTP framing；恰好等于上限合法。超过上限返回§16.4 `limit_exceeded {limit:"wire_bytes"}`。
该错误的`json_pointer`固定为根空string，`observed_at_least`固定为`maximum + 1`。

| 顶层合同 | 最大wire bytes |
|---|---:|
| `NodeIdentity` | 16384 |
| `AgentRegistrationAttempt` | 16384 |
| `AgentSession` | 16384 |
| `AdmissionInventoryAttestation` | 16384 |
| `DesiredRuntimeSpec` | 1048576 |
| `RuntimeCheckpoint` | 4194304 |
| `NodeCleanupCheckpoint` | 65536 |
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
覆盖Host路径。`(node_id, immutable_host_id, state_path_id)`在provision时一次写定，此后不可修改或
复用；其中Host/state-path pair也不能重新绑定到另一NodeIdentity。retire只改变`state`并保留这组lineage。
替换Host、替换state path或重新provision都必须取得新的`node_id`和未使用过的Host/state-path lineage，
不能复活retired identity或把旧`node_id`绑定到另一组Host/state path。

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
    expected_blank_head: RemoteHead
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
  version: 1,
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

standalone residue的普通cleanup仍由强归属的Cat reconciler拥有，并把完整
`CleanupRelease`写入该Cat的`RuntimeCheckpoint`。唯一不能这样持久化的effect是删除
该`RuntimeCheckpoint`文件自身；checkpoint文件不得充当删除自身的journal。V1只为这个
最后一步定义一个Node级单槽：

```text
NodeCleanupCheckpoint {
  version: 1,
  node_id: Id,
  cleanup: CleanupRelease
}
```

`NodeCleanupCheckpoint.cleanup.target.kind`必须是`checkpoint_file`，`volume_release`必须为
`null`，`target.node_id`、`cleanup.inventory_session.node_id`和顶层`node_id`必须逐字段相同。
空槽由该文件不存在表示；不允许`null`、array、queue或历史记录。槽只能在当前
Deleted tombstone仍保留、§11的Deleted物理postcondition已满足、full inventory中的
`ObservedRuntimeStatus.checkpoint=CheckpointEvidence.valid`与该tombstone强匹配，且除该文件外已无该Cat
物理residue时写入。它使用与
`RuntimeCheckpoint`相同的temp write/file fsync/atomic rename/parent directory fsync，但物理位置
必须在per-Cat checkpoint文件之外的受保护Node state path。

该槽只是crash journal，不授予cleanup authority。target仍存在时，执行删除前必须按
`CleanupRelease`重做full scan、session、Deleted tombstone与content digest复核；无tombstone、
任一绑定变化或读取不完整都必须拒绝，不删target也不清槽。

唯一例外是已经满足删除postcondition：当前session的新full scan直接证明
`target.checkpoint_path`上没有filesystem entry，且全部checkpoint inventory中也没有该精确
target时，Node可原子清槽，即使Control Plane已经GC Desired/tombstone。这条规则只能
清除已完成的Node journal，不得在path仍存在时被用作无tombstone删除权。删除target后
crash而槽尚未清除就走此路径。同path若重建为different-valid、corrupt或other-Cat文件，target
并未满足“没有filesystem entry”，Node必须保留新文件、拒绝旧cleanup且不得清槽。槽已占用时不得被
不同target覆盖；必须先完成/清槽，冲突则Quarantine。
不建立per-dispatch数据库、通用workflow或第二cleanup authority。

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
| AcquireVolume | normal时完整`VolumeAcquireRequest`（含positive lease duration），takeover时只有authorization id | MetadataStore 精确 CAS；authorization首次消费还要求Active event并原子写`AuthorizationConsumedReceipt`；只有完整typed request或同authorization可adopt，或在 `R == L` 后精确release |
| PrepareDevices | NBD/tap/socket slot、ownership token | 完整 inventory 后 create-if-absent；晚到资源只按 token adopt 或删除 |
| FormatFilesystem | attachment、device、filesystem UUID、initialization token、blank predecessor | Guest Agent 只按精确 predecessor 格式化；晚到结果按 UUID probe/adopt，冲突立即 quarantine |
| DrainInitialization | attachment epoch、local/remote root generation | device flush 后只向精确 owner/epoch publish，直到 `R == L` |
| CommitInitialized | token、blank predecessor exact RemoteHead、UUID、新exact RemoteHead | Control Store 精确 CAS；相同结果幂等，冲突 quarantine |
| MountFilesystem | attachment、device、UUID、mount path | 只 mount 精确 device/UUID；晚到 mount 不产生 route authority，stale 时按精确 identity unmount |
| StartRuntime | runtime incarnation、scope/socket 名、process identity token | create-if-absent 后握手；晚到进程不开放 route，当前 spec 不再需要时按精确身份停止 |
| DrainPublish | attachment epoch、local/remote root generation | 只向精确 owner/epoch CAS publish；晚到成功可安全 adopt，旧 epoch 不能写新 root |
| PauseRuntime | runtime incarnation、process start time | 只 pause 该 incarnation；晚到 pause 可发生，当前 revision 负责 resume 或重建 |
| SnapshotWarmRuntime | runtime incarnation、snapshot temp id、source root/epoch | 验证VMM postcondition与durable rename；晚到文件不覆盖其他WarmRuntimeSnapshot |
| StopRuntime | runtime incarnation、process start time、scope id | 只 stop 该 incarnation；晚到 stop 可发生，当前 revision 负责重建 |
| CleanupRelease | 完整`CleanupRelease`：物理target、inventory session/epoch/read position、Desired/tombstone read position，volume还有release transition/generation/disposition | 只删匹配资源、只 release 精确 owner/epoch；`orphan_scope`重读token/cgroup并证明无live PID/process，`control_socket`重读token并证明无live owner，`checkpoint_file`只由Node单槽重读并重算digest/完整identity且由当前Deleted tombstone证明不再需要；重建或身份变化后的stale cleanup必须拒绝 |
| DeleteDisposableRoot | authorization ID；payload与direct result只读服务器端AuthorizationRecord | 无live DiskSnapshotRecord且Guest/VMM/blockd已停后，按event/auth/volume/control锁序原子写Consumed receipt及两边Deleting；Node从closed receipt取得精确lineage，成功后才删该`R < L`lineage |
| InstallGate | desired checkpoint、spec digest、placement、runtime incarnation、endpoint/route epoch | cell只接受一个serving epoch；任何已close gate必须由更大epoch重开 |

每步都可被 kill。重启后只能确认 postcondition、重试同一 token、继续或 quarantine，不能先
teardown 再重做。不建立通用 effect workflow。

新建任一携scope/socket/device/tap等ownership token的物理实例前，必须先生成新的
`RandomId128`并写入该Cat checkpoint；已用于另一物理实例或已完成cleanup的token
永不复用。create-if-absent响应丢失时可以用已持久的同token确认/重试同一次create；
只有确认旧attempt没有留下任何实例后，新attempt才生成新token。预期名称/path处已有
missing/corrupt/不同token的实例是identity conflict，必须Quarantine，不得覆写token、
adopt或按名删除。

volume `CleanupRelease`必须先持久化，再以`target.volume_id`、`target.attachment_id`、
`target.attachment_epoch`和`volume_release.release_transition_id`构造Volume Authority的exact
release request；`generation`和`disposition`是Runtime的决策/前置绑定，不增加第二个
MetadataStore authority。若release已提交但响应丢失，重启只能：

1. 逐字段重放同一request/同一`release_transition_id`，并接受原`UnownedGrant`；或
2. 读取VolumeRecord，仅当`last_transition.kind="release"`中的完整typed request/result逐字段匹配、
   owner/expiry已为空、resulting epoch精确等于`target.attachment_epoch + 1`、resulting exact
   `RemoteHead`等于当前head且其generation等于cleanup绑定值时adopt成功。

上述加一必须使用checked arithmetic；epoch已为`i64::MAX`时不存在可执行release。
其他owner、epoch、transition payload或generation一律不得当作成功；身份冲突进入
Quarantine，暂时无法读取则Blocked。Control Plane在该release结果确认前不得为该volume
启动后续ownership transition；因此不允许用“当前又是Unowned”推断某个旧release成功。

## 8. 外部边界

- Volume normal acquire：只允许精确 `expected_unowned_epoch` 的 Unowned -> this attachment；只有
  重放同一 `transition_id` 才返回原 LeaseGrant。
- Volume publish/release：publish携带expected owner/epoch/exact RemoteHead；release携带已持久的唯一
  `release_transition_id`和expected owner/epoch，并按§7解析重放；PersistentDisk release前`R == L`。
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
  isolation_state: HostIsolationState, observed_at,
  state: Active | Rejoined
}

HostIsolationState =
  { kind: "isolated" }
| { kind: "host_destroyed", receipt: HostDestroyedReceipt }

HostDestroyedReceipt {
  provider: Id,
  immutable_host_id: Id,
  node_id: Id,
  expected_node_boot_id: NodeBootId,
  expected_agent_session_epoch: Epoch,
  state_path_id: Id,
  state_storage_disposition: "permanently_destroyed",
  destroyed_at_unix_ms: UnixMillis
}
```

同一 fence attempt 只保留一个 event。Active event 是 Host 级隔离事实，不是卷权限。Control
Plane 对旧 placement 中每个需要恢复的卷分别创建：

```text
VolumeTakeoverAuthorization {
  authorization_id, host_fence_event_id,
  volume_id, expected_attachment_id, expected_epoch,
  new_attachment_id, desired_revision, new_placement_epoch,
  lease_duration_ms, not_after
}
```

该row由唯一Control Store writer在同一PostgreSQL trust/transaction域写入；Node只携
`authorization_id`，不提交payload或第二套签名。首次消费按固定锁序
`HostFenceEvent -> authorization -> VolumeRecord`，要求event仍为Active和数据库
时间未超过`not_after`，在同一PostgreSQL事务完成精确逐卷CAS并写不可变
`AuthorizationConsumedReceipt`。相同authorization只读取receipt并返回同一LeaseGrant，不再次改变
volume；换卷、换旧owner、换attachment、换placement、过期或Rejoined后的首次消费都失败。运行时
Desired的`attachment_id`、revision、placement必须与authorization一致，对应`VolumeIntent.acquire`
必须引用该authorization。精确schema/CAS以[Volume Authority](volume-authority.md)为准。

普通provider isolation receipt只建立`isolated`的Active HostFenceEvent。`host_destroyed`只能来自
provider adapter验证过的HostDestroyed receipt；receipt的provider、immutable Host、node及expected
boot/session必须逐字段等于event，receipt的immutable Host、node和state path还必须等于该event创建时
锁定的`NodeIdentity` immutable lineage（该row此后可以retired）。adapter必须证明承载该state path的
provider storage已
永久销毁，不能仅把实例状态、网络隔离或断电翻译为该variant。Active event可以直接以
`host_destroyed`建立，或把`isolated`单调更新为`host_destroyed`。后一种更新先锁该
`HostFenceEvent`行，并用`state=Active`、`isolation_state={kind:"isolated"}`及未改变的完整event tuple
（`event_id`、provider、immutable host、node、expected boot/session、fence attempt和`observed_at`）做
exact CAS；receipt一经提交不可变，相同receipt重放只读原结果，任何字段不同的重放都拒绝。
`host_destroyed`不会转为Rejoined；替换Host必须使用新的provisioned identity。两种receipt都不直接授予
placement或writer。Control Plane先把旧
Pending Operation置为`Failed(HostLost)`，再在一个事务中创建新完整Desired/Operation、placement、
全部新attachments和每卷VolumeTakeoverAuthorization；新Desired逐卷引用授权。目标Node消费所有
MetadataStore CAS后才能Ready，不存在另一种writer-proof fallback。

session失效或提高attachment epoch不是解除旧Host隔离的条件。旧Host重用前必须在隔离网络内以
新boot/session完成完整inventory，保持gates Closed，停止旧runtime/transport/socket/tap/guards，
并把旧epoch的`R < L` lineage移入quarantine而非删除。`isolated -> host_destroyed`、授权派生、首次消费、
`Active -> Rejoined`和使用HostDestroyed proof的tombstone GC都先锁同一event行并持有到事务提交，再重验
各自要求的state、isolation variant和完整event tuple；竞争事务只能按锁取得顺序提交，后一方必须基于
前一方已提交的状态重新判定，不能用旧读取继续。rejoin再按稳定顺序锁定该event的全部授权，所以不会漏掉
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

Control Plane先按§16.4确认当前完整session/instance，再对该session的
`heartbeat_sequence`执行唯一接收状态机。“相同payload”指两个已通过严格decoder的
`NodeObservation`逐字段相同；JSON object member的输入顺序和无意义空白不参与比较，
但`observation_id`和所有嵌套证据都参与：

1. 无已接受值，或presented sequence大于最高已接受值：完成全部validation后，在一个
   PostgreSQL事务中原子记录新的最高sequence/完整payload，并执行该observation的Cat
   replacement、attestation刷新与Operation结算；任一验证或commit失败时全部不发生。sequence
   可跨过从未被Control Plane接受的值，不要求恰好`last + 1`。
2. presented sequence等于最高已接受值且payload相同：exact replay，返回首次接受的
   同一成功结果，不重复upsert、刷新`accepted_at_unix_ms`/freshness、重建attestation
   或再次结算Operation。
3. presented sequence等于最高已接受值但payload任一字段不同：返回
   `observation_sequence_conflict`，零副作用。即使两者`observation_id`恰好相同，其他字段
   不同仍是conflict。
4. presented sequence小于最高已接受值：返回`stale_observation_sequence`，零副作用；
   不再为该旧sequence查找或重放历史成功结果。

Node的`observed_at_unix_ms`不用于sequence比较或freshness。`loaded_kids`按`KeyId`升序且无重复，
`runtimes`按`cat_id`升序且无重复。
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
  { kind: "missing", checkpoint_path: HostPath }
| {
    kind: "corrupt",
    checkpoint_path: HostPath,
    raw_content_digest: Sha256Digest
  }
| {
    kind: "valid",
    checkpoint_path: HostPath,
    content_digest: Sha256Digest,
    version: ContractVersion,
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
| { kind: "acquire_volume", request: VolumeAcquireRequest }
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
    expected_blank_head: RemoteHead
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
    expected_blank_head: RemoteHead,
    new_remote_head: RemoteHead
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
| { kind: "cleanup_release", cleanup: CleanupRelease }
| { kind: "delete_disposable_root", authorization_id: Id }
| { kind: "install_gate", endpoint_id: Id, route_epoch: Epoch }
| { kind: "quarantined" }

VolumeAcquireRequest =
  {
    kind: "normal",
    volume_id: Id,
    transition_id: RandomId128,
    attachment_id: Id,
    expected_unowned_epoch: FenceEpoch,
    desired_revision: Revision,
    placement_epoch: Epoch,
    lease_duration_ms: integer 1..=9223372036854775807
  }
| { kind: "takeover", authorization_id: Id }

CleanupRelease {
  target: CleanupTarget,
  inventory_session: SessionBinding,
  inventory_epoch: Epoch,
  inventory_read_position: Sequence,
  desired_read_position: Sequence,
  volume_release: VolumeReleaseReplay | null
}

VolumeReleaseReplay {
  release_transition_id: RandomId128,
  generation: Generation,
  disposition: VolumeDisposition
}

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
  head: RemoteHead
}

RemoteHead {
  generation: Generation,
  root_hash: Sha256Digest | null,
  root_object_id: AsciiText | null
}
```

`source_heads`按`volume_id`升序且无重复。`ObservedRuntimeStatus.step`与valid checkpoint中的`step`必须
逐字段相同；missing/corrupt checkpoint只能处于`inspect_inventory`或`quarantined`。这里的step闭集
就是§7 planner当前允许的窄effect，不是可扩展workflow或通用command envelope。

“完整物理`CleanupTarget`”指直接持久上述variant的全部字段，不得换成repository row ID、
可重算名称或任意payload。执行前，该target必须在新full inventory中匹配恰好一个物理实例；
零个按已完成的精确postcondition处理，多个或任一identity不同都Quarantine。带
`ownership_token`的target还要求full inventory中该token只出现一次且evidence为valid；
missing/corrupt或同token出现在多个实例上都不得自动cleanup。

`CleanupRelease`持久化的`inventory_session`/epoch/read position必须逐字段等于用于
规划该step的已接受`AdmissionInventoryAttestation`及其当前`SessionBinding`；
`desired_read_position >= inventory_read_position`，且必须是规划时最后一次完整Desired/
tombstone读取的服务端位置。执行前必须确认当前session仍相同，并以不早于
`desired_read_position`的新读取重验同一Desired/tombstone证明；旧session、旧inventory或已变化的
Desired只能拒绝/重新规划，不能执行原target。
新AgentSession从checkpoint恢复未决cleanup时，必须先接受新full inventory并重读当前
Desired/tombstone，然后才能fsync替换`inventory_session`、`inventory_epoch`、
`inventory_read_position`和`desired_read_position`。这个rebind必须保留逐字段相同的
`target`与`volume_release`（包括原`release_transition_id`）；若新scan不再证实同一
物理identity/前置，则不得rebind或生成新transition来猜测旧effect。target已精确不存在，
或volume已满足§7的原transition postcondition时，按已完成处理；其他冲突Quarantine。
上述rebind只适用于仍有物理effect需要执行的cleanup。`NodeCleanupCheckpoint`的target若由
§5要求的当前session新full scan证明已精确不存在，Node直接原子清槽，不需要已GC的
Desired/tombstone，也不需要把已完成effect rebind到新session；target仍存在时不得使用这条例外。

`target.kind="volume"`当且仅当`volume_release`非`null`。其`disposition`只能是
`retain`或`detach_retained`；`delete_disposable_root`只走独立的`delete_disposable_root` step。
`generation`必须同时等于full inventory中该attachment的authority generation、
`local_durable_generation`和`remote_durable_generation`，从而明确证明`R == L`。其他target的
`volume_release`必须为`null`。同一`release_transition_id`只能绑定一个完整
`(target, generation, disposition)`；任一字段冲突都进入Quarantine，不得以新payload重放该ID。

standalone residue和最后一个attributed checkpoint的cleanup owner只有下表三种结果：

| full-scan归属结果 | 唯一持久owner | 允许的结果 |
|---|---|---|
| standalone scope/socket的token/path/identity只匹配一个Cat checkpoint，且当前Desired或保留tombstone逐字段证实该Cat/placement/revision | 该Cat的`RuntimeCheckpoint` | 持久一个`cleanup_release`；不得并行交给Node槽 |
| attributed `CheckpointEvidence.valid`逐字段匹配该Cat的Deleted tombstone，且已允许最后删除checkpoint文件自身 | 唯一`NodeCleanupCheckpoint`槽 | 只能持久`checkpoint_file`、删除后清槽 |
| 无匹配、多个匹配、归属字段冲突、unexpected/unassigned checkpoint或evidence missing/corrupt | 无cleanup owner | 保留物理证据并Quarantine，关闭gates且等待人工处理 |

“只匹配一个Cat checkpoint”对`systemd_scope`要求valid token和`scope_id`同时等于该
checkpoint保留的process/scope identity；对`control_socket`要求valid token和`socket_path`
同时等于该checkpoint保留的process/socket identity。只有完成这个强归属后，才能分别
生成`orphan_scope`或`control_socket` target，并逐字段复制scope/cgroup/path/token。
`scope`仍是有精确process identity的进程绑定cleanup；已无进程的scope只使用
`orphan_scope`。执行前必须重读token并确认逐字节相同、cgroup仍是同一个，且没有
live PID或matching `ProcessEvidence`；执行`control_socket`前还必须确认没有live process
拥有该socket。

正常归属assigned Cat的checkpoint文件必须进入该Cat的`CheckpointEvidence`；只有unexpected或
不能关联assigned Cat的checkpoint才进入`NodeResidue.checkpoint_file`。`checkpoint_file` target只能从
当前Deleted Cat的`CheckpointEvidence.valid`产生，且target必须逐字段复制
checkpoint path/content digest/Cat/Node/placement/revision。任何`RuntimeCheckpoint.step`都不得持有
`checkpoint_file` target；它只能在§5的`NodeCleanupCheckpoint`中持久，因此既不会自删
journal，也不会让一个Cat的checkpoint删除另一个Cat的checkpoint。删除前必须重读
文件，按§16.2重算并核对content digest及完整identity，还必须由Control Plane
当前Deleted tombstone证明该checkpoint已不需要。`CheckpointEvidence.missing`/`corrupt`和任何
`NodeResidue.checkpoint_file`都不得产生target。scan后任一资源被重建，token、cgroup或
checkpoint path/digest/identity发生变化时，旧cleanup必须拒绝并Quarantine，不得按可重算名称或
path删除；尤其旧文件删除后同path出现different-valid、corrupt或other-Cat文件时必须保留新文件，
不得把它解释为旧target已不存在。

`CheckpointEvidence.valid.content_digest`必须等于§16.2对完整`RuntimeCheckpoint`（包括process、volume、
device、mount、network、Guest transport、snapshot、route gate和RequireIdle事实）计算的digest；valid
projection中除`checkpoint_path`外的其余字段必须与该checkpoint逐字段相同。三个variant的
`checkpoint_path`都是full scan读取的inventory-layer物理证据，进入`NodeObservation`及
`inventory_digest`，不属于`RuntimeCheckpoint`内容，也不进入其content digest。
`corrupt.raw_content_digest`只是损坏文件原始bytes的普通SHA-256（不加domain separator），用于关联诊断，
不能伪装成valid checkpoint content digest。

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
    head: RemoteHead
  }
| {
    kind: "owned",
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    head: RemoteHead
  }
| {
    kind: "deleting",
    delete_id: Id,
    attachment_epoch: FenceEpoch,
    head: RemoteHead
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
  source_path: HostPath,
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
    version: ContractVersion,
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

`RemoteHead`与[Volume Authority](volume-authority.md)是同一tuple：generation为0当且仅当hash/object ID
都为null，generation大于0当且仅当两者都非null；比较时三个字段不可拆分。

同一`ProcessRole`可以出现多个不同process identity；同一`volume_id`可以出现多个device；同一
`network_id`可以出现多个tap；同一`endpoint_id`可以出现多个route record。完全相同的route binding/
gate/guard事实合并为一项并用`instance_count`保留multiplicity，不能去重成1。空`devices`或`networks`
分别表示没有发现frontend或tap，不再使用会压扁冲突的单值`absent`variant。

`ObservedMount.source_path`是本次full或partial scan从实际mountinfo（或等价OS mount table）直接读取的
物理source。它不得从Desired、`guest_device`或`ObservedVolume.devices`候选推导；无法读取或解析source时，
不得伪造`ObservedMount`事实。

`ProcessEvidence.role`是scope/checkpoint/token给出的归属主张，不代表已经验证；只有
`control_handshake="verified"`才证明control socket自报身份匹配。VMM的
`observed_vm_shape`当且仅当control handshake verified时非null；blockd永远为null。Running稳定态还
要求`guest_transport="vsock_ready"`绑定同一runtime incarnation，且Guest boot ID/protocol握手成功。
本节所有`raw_content_digest`/`raw_response_digest`都是字段所指原始bytes的普通SHA-256，不加domain
separator；它们只关联不可解析证据，不能当作成功handshake或ownership。

full scan发现的每个约定资源必须恰好进入某个`ObservedRuntimeStatus`，或在不能可靠归属Cat/Volume时
进入顶层`NodeObservation.residue`。`*_hint`和`role_hint`只记录不可信线索，不能据此cleanup。
没有live matching process的systemd scope/cgroup与control socket分别进入`systemd_scope`和
`control_socket`；assigned Cat预期path缺席、损坏或存在valid checkpoint分别进入该Cat的
`CheckpointEvidence.missing`/`corrupt`/`valid`，unexpected或不能关联assigned Cat的checkpoint才进入
`NodeResidue.checkpoint_file`。scope/socket只有
ownership token为valid且与持久化cleanup identity精确匹配时才可清理。valid checkpoint evidence的
content digest按§16.2绑定完整文件，所列字段必须与文件逐字段相同；corrupt evidence只保留path和raw
digest并禁止自动清理。不能因为进程已死就按可重算scope/socket/checkpoint名字删除。
`systemd_scope`要求bounded scan确认该cgroup没有live PID且没有匹配`ProcessEvidence`；`control_socket`
要求没有任何live `(process_start_time_ticks, process_id)`拥有该socket。否则必须同时报告对应process
事实，不能伪装成可直接清理的standalone residue。
非自描述资源的token文件缺席/损坏分别编码`missing`/`corrupt`；`corrupt.raw_content_digest`是原始文件
bytes的普通SHA-256。不得因token无效而省略资源。readable residue lineage也必须满足
`local_durable_generation >= remote_durable_generation`；attachment ID/epoch hints必须同时为null或
同时非null，且只作为线索。同一`(mount_path, source_path)`下完全相同的Node residue mount事实合并并累计
`instance_count`；该physical identity相同而其他字段不同时是identity collision，不能靠不同hint拆成两项。
partial observation不携带Node级residue；full inventory digest覆盖全部runtime evidence和完整residue集合。

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
| `mounts` | 64 | `(volume_id, mount_path, source_path, guest_device.serial, guest_device.slot, access rank, CJ(item))`；physical identity为`(mount_path, source_path)`；完全相同的mount事实合并并累计`instance_count` |
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
以及同一scope/control socket/checkpoint file不得在runtime evidence与`residue`重复出现。
`ObservedMount`和`NodeResidue.mount`的跨runtime/residue physical collision identity也统一为
`(mount_path, source_path)`；完整inventory中同一pair出现于两处必须返回`duplicate_identity`。同一
`mount_path`下不同`source_path`的stacked mounts是不同且合法的wire事实，不能合并；只有pair及其余字段
在同一evidence array内逐字段完全相同时才合并为一项并累计`instance_count`。
`CheckpointEvidence.checkpoint_path`与`NodeResidue.checkpoint_file.checkpoint_path`在完整inventory中
全局唯一；同一path出现两次是`duplicate_identity`，不能靠Cat归属或variant不同绕过。任何array超过
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
```

`phase="pending"`时`terminal`必须为`null`；其他phase必须携带同名`kind`的terminal。Succeeded的
`observed_target`必须等于Operation `target`；Running/Suspended result的`runtime_incarnation`必须非null，
Warm/Cold/Deleted必须为null。Superseded的revision必须更大，且不能引用自身Operation。时间只能单调
前进：`updated_at_unix_ms >= created_at_unix_ms`，terminal completion等于`updated_at_unix_ms`。
standalone `Operation` decode/validation还必须逐字段要求
`terminal.succeeded.result.node_id == Operation.placement.node_id`，以及
`terminal.failed.error.host_lost.node_id == Operation.placement.node_id`。若failed precondition reason是
`placement_rejected`，还必须要求其`node_id`和`placement_epoch`分别等于
`Operation.placement.node_id/placement_epoch`。不等分别返回指向`/terminal/result/node_id`、
`/terminal/error/node_id`、`/terminal/error/reason/node_id`或
`/terminal/error/reason/placement_epoch`的
`malformed_payload {problem:"invalid_value"}`，不能等到observation settlement才发现。
`contract_error`不是`OperationFailure` variant。完整Desired在与Operation同事务提交前已经通过同一
§16.4.1 decoder；Node或任意row不能用自报ContractError把Operation变为Failed。standalone Operation若携带
该旧tag且其他字段都属于当前union-wide字段集合，按Schema substage 2返回指向
`/terminal/error/kind`的`invalid_value`；若还携带已删除variant的`error`等字段，则Schema substage 1更早
返回指向该字段的`unknown_field`。这里没有specific override，也不得把已删除字段加入union-wide集合做兼容。
顶层`ContractError`合同继续用于边界请求拒绝，不是Operation terminal。stale/wrong session、
stale/conflicting observation sequence、revision、stored digest或placement也只拒绝那次输入，绝不能终结
当前Operation。

- 结算时必须先从`NodeObservation.runtimes`选出唯一
  `runtime.cat_id == Operation.cat_id`的`ObservedRuntimeStatus`，且`runtime.applied_desired`非`null`。
  只有Operation、`runtime.applied_desired`和`current_desired`三者的`desired_revision`相等，
  三者的`spec_digest`相等（Operation字段名为`desired_spec_digest`），以及
  `Operation.placement == runtime.applied_desired.placement == current_desired.placement`逐字段
  同时成立，并且顶层`NodeObservation.node_id`、`Operation.placement.node_id`、
  `runtime.applied_desired.placement.node_id`和`current_desired.placement.node_id`四者相等，
  以及`runtime.applied_desired.target`、`Operation.target`、`current_desired.target`、
  `runtime.stable_state`和待写入的`OperationSuccess.observed_target`五者相等时，才进入§11
  完整postcondition判定并可能Succeeded。任一Node或target绑定不等都不得Succeeded。
  `observation.desired_revision`不是合法字段路径，实现不得从顶层猜测或复制它。
  `OperationSuccess.observation_id/node_id/agent_session_epoch/heartbeat_sequence`必须分别等于
  顶层`NodeObservation`的同名字段，`observed_target`等于`runtime.stable_state`，
  `runtime_incarnation`等于`runtime.runtime_incarnation`。result只保存这些实际结算的不可变
  引用，不复制可变observation内容。
- 上述四处Node不全等时，整个NodeObservation按§16.4的固定优先级返回`wrong_placement`。
  该拒绝不得推进最高heartbeat sequence、写observation/attestation/freshness或结算任何Operation。
- observation通过§16.4既有session/sequence/revision/digest/placement检查、开始用
  `precondition_failed` Condition结算当前Operation时，任何
  `reason.kind="placement_rejected"`都必须先逐字段匹配该Operation的完整placement。Node或epoch不等时返回
  `malformed_payload {problem:"invalid_value"}`，pointer分别固定为
  `/runtimes/{runtime_index}/conditions/{condition_index}/reason/node_id`或
  `/runtimes/{runtime_index}/conditions/{condition_index}/reason/placement_epoch`；index是输入canonical array
  中的十进制数值位置。多个condition候选按§16.4逻辑path选择；同一reason两字段都不等时选择`node_id`。
  该拒绝作用于整份observation且零副作用，不能写入一个与Operation placement不一致的terminal reason。
- 新 revision 在同一事务把旧 Pending Operation 变为 Superseded。
- PreconditionFailed、HostLost 或 Quarantined 使当前 Pending Operation Failed。
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
postcondition满足时成功。仅网络隔离、断电、heartbeat timeout或普通Active HostFenceEvent足以阻止
服务但不能证明Host state path已经消失，不能据此声称residue已清空。

Deleted Operation成功后仍必须保留当前Desired/tombstone和关联observation index，不得把
Operation Succeeded、NodeCleanupCheckpoint已写槽或某次partial observation的缺项当作checkpoint
已不存在。Control Plane只允许以下严格二选一的GC absence proof；一次GC attempt选择其中一个分支，
不得混合字段或从一个分支伪造另一个分支：

这里的关联observation index不是新wire合同或authority，而是Control Plane对已接受
`NodeObservation`保留的最小投影：`cat_id`、完整`AssignedPlacement`、`node_boot_id`、
`agent_session_epoch`、`immutable_host_id`、`state_path_id`、最后一次full evidence的`checkpoint_path`，
以及若曾接受valid checkpoint时的逻辑identity和`content_digest`。接受observation并写入或替换该index的
同一事务必须锁定当时仍为provisioned的`NodeIdentity`，从中复制不可变的
`immutable_host_id/state_path_id`；其余字段直接来自同一个已接受的顶层observation/runtime evidence。
这两个服务端字段不进入`NodeObservation` wire或inventory digest。同一index已有不同Host/state-path
lineage时拒绝该observation，不能覆盖。retire后只要仍有index、tombstone或HostFenceEvent引用，就保留
同一NodeIdentity row供验证；GC前index不能被partial observation覆盖或丢弃。

1. **Node inventory**：原placement Node仍存在或已重连。当前AgentSession的
   `complete_inventory=true` observation已接受且digest验证成功；其
   `inventory_read_position`对应的完整assigned-spec读取仍包含该Deleted tombstone，Control Plane在
   接受inventory时重读同一tombstone。由保留tombstone和observation index绑定的
   `checkpoint_path`必须有精确absence：该Cat的`CheckpointEvidence`必须是同一path的`missing`，且该path
   没有`NodeResidue.checkpoint_file`。若index保留了旧valid checkpoint，还必须证明其逻辑identity
   `(cat_id, node_id, placement_epoch, desired_revision, spec_digest)`及物理identity
   `(checkpoint_path, content_digest)`没有出现在全部checkpoint inventory。同path的different-valid、
   corrupt或other-Cat文件是冲突，不是absence，必须保留文件并拒绝GC。
2. **HostDestroyed**：负责旧placement的Host无法再提供inventory。Control Plane锁定现有
   `HostFenceEvent`，验证其中§9 `HostDestroyedReceipt`的provider、immutable host、node、expected boot、
   expected session epoch逐字段等于event；event/receipt的`node_id`和`immutable_host_id`、以及receipt的
   `state_path_id`还必须逐字段等于该event创建时锁定、现为provisioned或retired的同一NodeIdentity
   immutable lineage。GC事务还必须重读该Cat现有Deleted tombstone和保留index：tombstone完整
   `AssignedPlacement`必须等于index中该Cat的旧placement，二者的`node_id`等于event，index的
   `immutable_host_id`等于event、receipt及该NodeIdentity，`state_path_id`等于receipt及该NodeIdentity。
   index中最近接受的boot/session可以晚于event的expected boot/session，不能参与此GC匹配；event的expected tuple仍只绑定
   原fence/rejoin序列，不能被新session改写。
   receipt的`state_storage_disposition="permanently_destroyed"`必须已由provider adapter证明承载Host state
   path的storage永久销毁。一个Host级event可用同一Host tuple分别验证多个Cat，各Cat仍只使用自己的
   tombstone/index绑定，不在event中复制Cat列表或placement。此分支不要求、也不得伪造AgentSession、
   heartbeat或inventory；普通network isolation、power state或未带该receipt的HostFenceEvent不能使用。

两个分支都不授予新placement或writer，也不替代volume authority。该Cat全部volume的authorization、
不可变receipt和Deleted disposition仍须按§9/§11逐卷闭合；任何所需授权未消费、未失效，receipt缺失/
冲突或volume disposition未完成都拒绝GC。只有验证所选absence proof和这些逐卷条件后，Control Plane
才可GC当前Desired/tombstone和关联observation index。proof校验与GC在同一Control Plane事务中完成；
不得先用新observation覆盖/删除保留index，再把身份已丢失后的“缺项”解释为精确absence。审计按独立
产品策略保留。Node分支验证不完整、wrong/stale session、wrong Node、仍看到任意冲突checkpoint或尚未
接受complete inventory，以及HostDestroyed分支receipt任一绑定错误，都必须拒绝且零持久副作用。
Control Plane已GC后，本地NodeCleanupCheckpoint可按§5的“target已精确不存在”规则在无
tombstone时清槽。Node删除checkpoint前还必须证明无runtime、无未跟踪volume residue和
无route gate。授权丢弃的Root lineage必须已删除；Active
HostFenceEvent上的隔离lineage由event/rejoin记录继续跟踪，关联的authorization与
`DeleteCompletionReceipt`不能因VolumeRecord或本地目录缺席猜测消失。普通`isolated` event至少保留到
Rejoined；`host_destroyed`永不Rejoined，因此在没有tombstone、其他HostFenceEvent或live recovery引用、
全部authorization已Consumed并验证receipt或已过`not_after`且不能首次消费、且逐卷disposition闭合后，
相关逐卷恢复记录可按审计策略GC，不等待Rejoined。compact HostFenceEvent/HostDestroyed receipt仍按
现有Operation及审计引用保留；只有所有引用都不存在时才可GC。

## 14. 最小验收矩阵

| 场景 | Oracle |
|---|---|
| N/N+1/N+2 ABA | 旧结果不能结算/授权 N+2；已线性化的本地 effect 可被下一轮安全修复 |
| 双 Agent / register 响应丢失 | Host lock 排他；同 attempt 返回同 session；旧 session 永久拒绝 |
| 各 planner step kill | restart 后确认、重试、继续或 quarantine；无重复 writer/误删 |
| 进程崩溃，scope/socket/checkpoint仍存在 | full inventory报告scope/socket standalone residue及attributed checkpoint evidence；scope/socket强归属后产生Cat CleanupRelease，Deleted checkpoint只从`CheckpointEvidence.valid`产生Node单槽target；rescan后才可Ready/GC |
| standalone residue归属冲突 | 只有scope/socket唯一Cat/tombstone强匹配才写该Cat RuntimeCheckpoint；unexpected/unassigned checkpoint及无/多匹配都保留证据并Quarantine，不自动删除 |
| NodeCleanup写槽前crash | target未删除且没有持久Node槽；保留tombstone，restart以新full scan重新规划，不从未落盘的cleanup猜测成功 |
| NodeCleanup写槽后、删除前crash | 单槽和tombstone均保留；restart只在当前session full scan、完整绑定和content digest复核通过后删除精确target |
| checkpoint删除后、清槽前crash | 新full scan证明path没有filesystem entry后原子清槽；即使tombstone随后已GC也无需rebind；同path重建为different-valid/corrupt/other-Cat时保留新文件并拒绝旧cleanup/GC |
| Control Plane提前GC | Operation成功、槽已写入、partial或未接受的full inventory都不足；Node分支必须有精确missing evidence，HostDestroyed分支必须有完整绑定和永久storage销毁receipt，否则GC拒绝且零持久副作用 |
| HostDestroyed receipt/GC crash | proof验证与tombstone/index GC同事务，要么全部保留要么全部删除；不创建伪AgentSession/inventory，event和逐卷receipt按各自保留规则继续存在 |
| HostDestroyed但volume未闭合 | receipt不授予writer/disposition；任一逐卷authorization仍可首次消费、receipt冲突或Deleted disposition未完成时GC拒绝 |
| scan与cleanup之间资源被重建 | token、digest、cgroup或process identity任一不匹配时旧cleanup拒绝，新资源保留 |
| standalone scope/socket token missing或corrupt | 不生成CleanupTarget，不删除，进入Quarantined/人工处理 |
| standalone checkpoint corrupt | 不生成`checkpoint_file` target，不自动删除，进入Quarantined/人工处理 |
| RemoteHead/nullability | authority/checkpoint中的head只接受`0/null/null`或`>0/non-null/non-null`；generation/hash/object ID任一错配都拒绝，fixed inventory覆盖non-null tuple |
| normal acquire 遇到旧 owner | Blocked，不 revoke；positive lease duration和DB absolute expiry不授予抢占，只有服务器端精确逐卷 takeover authorization 可 CAS |
| volume release提交后响应丢失 | 同一`release_transition_id`及完整typed request重放返回原UnownedGrant，或精确`last_transition.release` request/result postcondition被adopt；epoch只增加1 |
| release N / reacquire N+1 / 旧release N重放 | attachment/expected epoch/transition不匹配，旧N不能释放N+1 writer，不能以当前Unowned猜测成功 |
| 新物理实例遇到旧token | 每个新create attempt使用新token；名称/path已有不同token时Quarantine，不覆写/adopt/删除 |
| Running 改盘/shape | 请求先 PreconditionFailed(MustBeCold)；Cold 成功后的新请求才改完整 spec |
| `R < L` + remote down | Suspend 可完成；Warm/Cold/detach/migrate 阻塞且唯一数据保留 |
| startup/inventory source down | gates 保持 Closed，Blocked；稳定 Running 的短暂故障为 Degraded |
| RequireIdle Busy/crash | attempt 只评估一次，Suspended Operation Failed，系统创建新 Running revision |
| Observation接受响应丢失 | 相同session/sequence/完整payload重放返回原成功，不刷新freshness或重复结算Operation |
| Observation same-sequence ABA | 同sequence改`observation_id`或任一嵌套字段返回`observation_sequence_conflict`且零副作用；更小sequence返回stale |
| Node A observation结算Node B Operation | 顶层Node、Operation/applied/current placement Node不全等时返回`wrong_placement`；不接受observation、不推进sequence/freshness且不结算任何Operation |
| identity conflict | gates Closed，Quarantined，当前 Pending Operation Failed |
| Host fence 与多个卷 | 一个 HostFenceEvent 派生多个独立逐卷授权；错 tuple 全部拒绝 |
| authorization consume 与Rejoined并发 | Node只传ID且AuthorizationRecord为payload/receipt唯一权威；两者锁同一event，只能consume先提交并留下closed receipt，或Rejoined先提交且epoch不变 |
| consumed授权后继 | Volume只存authorization ID marker；takeover→release与delete→sweep按closed状态/epoch/head及精确DeleteCompletionReceipt完成rejoin，不复制中间链；错receipt保持Blocked |
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
目标 schema 只包含本合同的 NodeIdentity、AgentSession、Desired、Operation、observation、
attestation、per-Cat RuntimeCheckpoint与唯一NodeCleanupCheckpoint槽；exact release不含NodeJob、
heartbeat overwrite、per-dispatch数据库或旧ledger恢复入口；空fleet的
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
canonical writer不能替decoder“修正”非canonical number；任何`1.0`、`1e0`、`-0`或负数必须先按§16.4
拒绝，不能归一化后参与digest。

### 16.2 Digest 输入

| digest | domain separator | canonical JSON输入 |
|---|---|---|
| `spec_digest` | `cats.runtime.desired-spec.v1` | 完整`DesiredRuntimeSpec`删除且仅删除顶层`spec_digest`字段；`version`保留 |
| `CheckpointEvidence.valid.content_digest` | `cats.runtime.checkpoint-content.v1` | 完整`RuntimeCheckpoint`，不删除任何字段 |
| `inventory_digest` | `cats.runtime.inventory.v1` | 下述`InventoryDigestInput` |
| `key_ring_digest` | `cats.runtime.key-ring.v1` | 下述`KeyRingDigestInput` |

这四种digest中，同一顶层payload同时携带完整projection和claim的self-digest只有第1/3/4行，即
`DesiredRuntimeSpec.spec_digest`、complete `NodeObservation.inventory_digest`和non-null
`NodeObservation.key_ring_digest`；它们在context-free decoder内重算。`RuntimeCheckpoint`本身只产生
checkpoint content digest而不携带claim；`CheckpointEvidence.valid.content_digest`、
`AdmissionInventoryAttestation.inventory_digest`、`RuntimeCheckpoint.spec_digest`、
`AppliedDesiredEvidence.spec_digest`和`Operation.desired_spec_digest`都缺少同payload完整projection，必须在
§16.4.3与文件或stored context验证。

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
{"cat_id":"cat_01","desired_revision":7,"guest_transport":{"kind":"unavailable"},"lifecycle_admission":"closed","mounts":[],"networks":[],"node_id":"node_a","placement_epoch":3,"processes":[],"require_idle":{"kind":"not_applicable"},"route_gates":[],"runtime_incarnation":null,"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"updated_at_unix_ms":1720000000000,"version":1,"volumes":[],"warm_snapshot":{"kind":"absent"}}
```

```text
checkpoint_content_digest = sha256:602bd0f3a0f1a29f269fa2946fa1a52ea154ba1623b5ca2de18e657cad3753fb
```

**Non-empty full inventory vector**使用同一个inventory domain。它刻意包含两个frontend、两个tap、
route multiplicity、VMM shape/Guest Ready、volume size/durability、missing/corrupt token及Node residue，
包括dead-process遗留的scope/cgroup、control socket、corrupt checkpoint，并在无法归属的data directory
中保留`R < L` lineage，所以不是Ready postcondition：

```json
{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"inventory_epoch":4,"inventory_read_position":12,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","residue":[{"cgroup_path":"/sys/fs/cgroup/system.slice/cats-orphan.scope","kind":"systemd_scope","ownership_token":{"kind":"valid","ownership_token":"dddddddddddddddddddddddddddddddd"},"scope_id":"cats-orphan.scope"},{"kind":"control_socket","ownership_token":{"kind":"missing"},"role_hint":null,"socket_path":"/run/cats/orphan/control.sock"},{"checkpoint_path":"/var/lib/cats/checkpoints/orphan.json","evidence":{"kind":"corrupt","raw_content_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"kind":"checkpoint_file"},{"data_directory":"/var/lib/cats/orphan-vol","kind":"data_directory","lineage":{"attachment_epoch_hint":4,"attachment_id_hint":"att_orphan","fenced":false,"kind":"readable","local_durable_generation":6,"pending_pack_count":2,"remote_durable_generation":5},"ownership_token":{"kind":"corrupt","raw_content_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"volume_id_hint":null}],"runtimes":[{"applied_desired":{"desired_revision":7,"placement":{"kind":"assigned","node_id":"node_a","placement_epoch":3},"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","target":"running"},"cat_id":"cat_01","checkpoint":{"cat_id":"cat_01","checkpoint_path":"/var/lib/cats/checkpoints/cat_01.json","content_digest":"sha256:602bd0f3a0f1a29f269fa2946fa1a52ea154ba1623b5ca2de18e657cad3753fb","desired_revision":7,"kind":"valid","node_id":"node_a","placement_epoch":3,"require_idle":{"kind":"not_applicable"},"runtime_incarnation":null,"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"updated_at_unix_ms":1720000000000,"version":1},"guest_transport":{"guest_agent_protocol_version":1,"guest_boot_id":"cccccccccccccccccccccccccccccccc","guest_cid":3,"guest_port":5000,"kind":"vsock_ready","runtime_incarnation":"55555555555555555555555555555555"},"lifecycle_admission":"closed","mounts":[{"access":"read_write","filesystem_uuid":"99999999999999999999999999999999","guest_device":{"serial":"cats-root","slot":0},"instance_count":1,"mount_path":"/","source_path":"/dev/nbd0","volume_id":"vol_root"}],"networks":[{"gateway_ipv4":"10.240.0.5","guest_ipv4":"10.240.0.6","guest_mac":"02:ca:0a:f0:00:06","kind":"isolated_ipv4","network_id":"net_01","ownership_token":{"kind":"valid","ownership_token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"prefix_length":30,"tap_name":"tap0"},{"gateway_ipv4":"10.240.0.5","guest_ipv4":"10.240.0.6","guest_mac":"02:ca:0a:f0:00:06","kind":"isolated_ipv4","network_id":"net_01","ownership_token":{"kind":"corrupt","raw_content_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"prefix_length":30,"tap_name":"tap1"}],"platform_guards":0,"processes":[{"control_handshake":{"kind":"verified"},"control_socket_path":"/run/cats/cat_01/vmm.sock","executable_path":"/usr/bin/cloud-hypervisor","observed_vm_shape":{"boot_image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","guest_config_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","memory_bytes":2147483648,"vcpus":2},"ownership_token":{"kind":"valid","ownership_token":"66666666666666666666666666666666"},"process_id":1001,"process_start_time_ticks":9001,"role":{"kind":"vmm","runtime_incarnation":"55555555555555555555555555555555"},"scope_id":"cats-cat_01","state":"running"},{"control_handshake":{"kind":"verified"},"control_socket_path":"/run/cats/cat_01/blockd-root.sock","executable_path":"/usr/bin/cats-blockd","observed_vm_shape":null,"ownership_token":{"kind":"valid","ownership_token":"77777777777777777777777777777777"},"process_id":1002,"process_start_time_ticks":9002,"role":{"attachment_epoch":8,"attachment_id":"att_01","kind":"blockd","volume_id":"vol_root"},"scope_id":"cats-cat_01","state":"running"}],"routes":[{"active_guards":0,"binding":{"cat_id":"cat_01","endpoint_id":"ep_01","hostname":"app.example.test","node_id":"node_a","protocol":"http","route_epoch":9,"runtime_incarnation":"55555555555555555555555555555555","target_port":8080,"workspace_id":"ws_01"},"cancellation_pending":false,"gate":"closed","instance_count":2},{"active_guards":0,"binding":{"cat_id":"cat_01","endpoint_id":"ep_01","hostname":"app.example.test","node_id":"node_a","protocol":"http","route_epoch":10,"runtime_incarnation":"55555555555555555555555555555555","target_port":8080,"workspace_id":"ws_01"},"cancellation_pending":false,"gate":"closed","instance_count":1}],"runtime_incarnation":"55555555555555555555555555555555","stable_state":null,"step":{"inventory_epoch":4,"kind":"inspect_inventory"},"volumes":[{"authority":{"attachment_epoch":8,"attachment_id":"att_01","head":{"generation":4,"root_hash":"sha256:2222222222222222222222222222222222222222222222222222222222222222","root_object_id":"volumes/vol_root/roots/4"},"kind":"owned"},"devices":[{"device_path":"/dev/nbd0","guest_device":{"serial":"cats-root","slot":0},"kind":"kernel_nbd","ownership_token":{"kind":"valid","ownership_token":"88888888888888888888888888888888"}},{"guest_device":{"serial":"cats-root","slot":0},"kind":"vhost_user_blk","ownership_token":{"kind":"missing"},"socket_path":"/run/cats/cat_01/root.sock"}],"disk_id":"disk_root","disk_kind":"root","durability":"strict","local_lineages":[{"acquire_transition_id":"tx_01","attachment_epoch":8,"attachment_id":"att_01","data_directory":"/var/lib/cats/vol_root","fenced":false,"local_durable_generation":5,"node_id":"node_a","pending_pack_count":1,"placement_epoch":3,"remote_durable_generation":4,"state":"active"}],"size_bytes":4294967296,"volume_id":"vol_root","volume_intent_id":"vint_root"}],"warm_snapshot":{"kind":"absent"}}],"version":1}
```

```text
inventory_digest = sha256:acfa3a47d5a3a8cec76e7ca78b080df9f296ef04fb4f1f11770c6a2df6f2b284
```

**Valid unexpected standalone socket/checkpoint inventory vector**使用inventory domain。它与上面的
checkpoint vector交叉绑定，证明valid ownership token和unexpected valid checkpoint residue的wire；
因为checkpoint未归属`ObservedRuntimeStatus`，它只能Quarantine，不能产生checkpoint cleanup target：

```json
{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"inventory_epoch":5,"inventory_read_position":13,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","residue":[{"kind":"control_socket","ownership_token":{"kind":"valid","ownership_token":"abababababababababababababababab"},"role_hint":null,"socket_path":"/run/cats/orphan/valid.sock"},{"checkpoint_path":"/var/lib/cats/checkpoints/cat_01.json","evidence":{"cat_id":"cat_01","content_digest":"sha256:602bd0f3a0f1a29f269fa2946fa1a52ea154ba1623b5ca2de18e657cad3753fb","desired_revision":7,"kind":"valid","node_id":"node_a","placement_epoch":3,"runtime_incarnation":null,"spec_digest":"sha256:529c32e8600910283f99bf949af5c31fdadcf3757463eb6c4811c61673ed9409","version":1},"kind":"checkpoint_file"}],"runtimes":[],"version":1}
```

```text
inventory_digest = sha256:cfa4e65423289e7f61f400f00f1c9a11d1fb27c20d76a2c5653da1b125055f8f
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

以下三个是严格serde/canonical wire fixed vectors，不增加新的digest domain。

**Volume CleanupRelease wire vector**：

```json
{"desired_read_position":15,"inventory_epoch":5,"inventory_read_position":13,"inventory_session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"target":{"attachment_epoch":8,"attachment_id":"att_01","kind":"volume","volume_id":"vol_root"},"volume_release":{"disposition":{"kind":"detach_retained"},"generation":5,"release_transition_id":"acacacacacacacacacacacacacacacac"}}
```

**NodeCleanupCheckpoint wire vector**（target path/digest/identity与Non-empty full inventory的attributed
valid checkpoint交叉校验；这里只固定wire，不表示该Running observation已满足Deleted cleanup授权）：

```json
{"cleanup":{"desired_read_position":15,"inventory_epoch":4,"inventory_read_position":12,"inventory_session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"target":{"cat_id":"cat_01","checkpoint_path":"/var/lib/cats/checkpoints/cat_01.json","content_digest":"sha256:602bd0f3a0f1a29f269fa2946fa1a52ea154ba1623b5ca2de18e657cad3753fb","desired_revision":7,"kind":"checkpoint_file","node_id":"node_a","placement_epoch":3},"volume_release":null},"node_id":"node_a","version":1}
```

**Observation sequence conflict ContractError wire vector**：

```json
{"error":{"accepted_observation_id":"10101010101010101010101010101010","agent_session_epoch":2,"code":"observation_sequence_conflict","heartbeat_sequence":19,"node_id":"node_a","presented_observation_id":"20202020202020202020202020202020"},"message":"same sequence carried a different observation","version":1}
```

实现测试必须逐字节断言全部canonical JSON、七个digest结果和三个non-digest wire vectors，另测object
输入key顺序变化不改变digest、数组逆序/重复/超限被拒绝、`spec_digest`自身变化不进入其输入，以及checkpoint
物理字段、inventory residue/multiplicity或任一其他被覆盖字段变化都会改变对应digest。全部§1.2顶层合同
必须共用version tests：missing/错误类型/越界、范围内非1，以及`format_version` unknown field；
`ContractError`自身也必须携带`version:1`。

NodeObservation serde/validation另测null/null/empty unavailable、non-null/non-null/empty valid ring及所有禁止
的混合组合；unavailable没有key-ring digest，valid empty ring必须匹配上面的fixed vector。接收状态机必须测：
首次commit后响应丢失的exact replay不重复副作用且不刷新freshness；同sequence改observation ID、保持ID但改
嵌套字段都返回`observation_sequence_conflict`；更小sequence返回`stale_observation_sequence`；三者均遵守
session-first优先级和§10零副作用。

Mount inventory tests必须覆盖同一`guest_device`同时存在多个frontend时，`source_path`严格采用mountinfo实际值
且不随device候选顺序改变；source无法读取时不得猜测或发送该mount事实。runtime mount与
`NodeResidue.mount`出现相同`(mount_path, source_path)`必须返回`duplicate_identity`；不同pair（包括同一
`mount_path`下不同source的stacked mounts）是合法wire事实，完全相同的事实只能合并并累计`instance_count`。

Cleanup tests必须逐字段覆盖volume target与`volume_release`同为有值、非volume target与null的双向约束，
`desired_read_position >= inventory_read_position`，release generation的`R == L`绑定，以及epoch加一溢出拒绝。
release commit后响应丢失/Agent crash必须用同一transition得到原UnownedGrant或精确adopt postcondition；
新session rebind只替换session/read positions并保留target/原transition；同transition异payload、
release N后reacquire N+1再重放N，以及scan后token/digest变化都必须拒绝且不误删。
standalone socket只能在唯一Cat checkpoint强匹配后写该Cat的cleanup step；valid checkpoint自删除必须使用
单槽NodeCleanupCheckpoint且只从attributed Deleted `CheckpointEvidence.valid`构造；三个CheckpointEvidence
variant的path都必须进入inventory digest但不改变RuntimeCheckpoint content digest，unexpected/unassigned
checkpoint即使valid也只进NodeResidue且不产生cleanup。分别测试写槽前crash、写槽后删除前crash、删除后
清槽前crash，以及Control Plane在接受精确absence proof前GC被拒绝。还必须测试tombstone已GC但target
确实absent时清槽、tombstone已GC但target仍存在时拒绝删除，以及旧文件删除后同path重建为
different-valid、corrupt、other-Cat三种情况都保留新文件并拒绝旧cleanup/GC。被删checkpoint试图记录自身
cleanup、无法归属及missing/corrupt evidence都不得产生cleanup。

GC tests必须分别覆盖Node inventory和HostDestroyed两个分支：Node分支要求当前session、complete inventory、
tombstone读取位置和精确path missing；HostDestroyed分支逐字段改变provider、immutable host、node、boot、
session epoch、state path、storage disposition，以及该Cat retained index中的placement epoch、immutable
host或state path，都必须拒绝，network isolation/断电也必须拒绝，且不得创建AgentSession/inventory
占位。必须接受`S0 isolated -> S1 cordoned complete inventory -> 同一Active event HostDestroyed -> GC`，
此时index可以保存S1 boot/session而event继续保存S0 expected tuple；也必须接受S1首次complete inventory前
即HostDestroyed，此时index仍保留S0 boot/session。同一Host两个Cat即使index分别来自S0/S1且placement epoch不同，也必须能各自匹配
同一HostDestroyed event。以相同`node_id`换immutable Host或state path的reprovision/ABA必须拒绝。两个分支都要在
每个volume authorization/receipt/disposition未闭合时拒绝；在proof校验或GC事务任一点crash后，tombstone
与index必须全有或全无。HostDestroyed逐卷恢复记录的GC还必须测试最后一个tombstone/recovery引用消失前
拒绝、全部authorization terminal且disposition闭合后允许、事务crash全有或全无；compact event若仍被
Operation引用则保留。

HostFenceEvent concurrency tests必须覆盖`isolated -> host_destroyed`与authorization派生/首次消费、
`Active -> Rejoined`及HostDestroyed tombstone GC并发：所有事务都先取得同一event行锁再重验。upgrade与
rejoin只能由先提交者决定终态，后一方的exact CAS必须拒绝；GC先取得锁时因尚无HostDestroyed proof拒绝，
upgrade先提交时GC只能看到完整不可变receipt；derive/consume与upgrade可以依锁序先后完成，但不能基于旧
`isolated`读取越过已提交状态。每个锁取得顺序和事务crash点都不得出现半个receipt、漏authorization或
proof与tombstone/index非原子。

Operation settlement negative tests必须分别改变顶层`NodeObservation.node_id`、Operation/applied/current
三处placement Node和applied/Operation/current/stable/result五处target中的每一处。Node A observation不得
结算Node B Operation；每个Node不匹配都按§16.4固定优先级返回`wrong_placement`，且不接受observation、
不推进最高sequence或freshness、不写terminal result。其他placement或target不等也不得结算Operation。
另以standalone Operation decoder分别改变Succeeded result、Failed HostLost error的`node_id`，以及Failed
PreconditionFailed PlacementRejected reason的`node_id`、`placement_epoch`和两者，必须在持久化前按上述
精确pointer拒绝；两者同时错误时固定选择`node_id`。observation settlement也要分别覆盖条件中Node、epoch
和两者不匹配，pointer指向该condition的精确reason字段且整份observation零副作用；匹配placement的正例
必须接受。stale session与placement_rejected mismatch并存时必须先返回session error，且不读取或结算
Operation。

Context-bound conflict selector tests必须覆盖：两个Cat同时revision或digest冲突时，即使Store反向返回rows，
也固定选择较小`cat_id`；同一Cat的Operation和applied revision同时冲突、digest同时冲突时都固定选择
Operation source，并用mock断言不读取/比较后一source。presented revision小于current返回stale、大于current
返回wrong；revision与digest、digest与placement同时冲突时分别只报告更早stage。交换任意JSON member顺序不
改变typed payload；placement仍按Operation、applied、顶层Node的既有顺序，并在首错后停止后续Cat/Store读取。

`contract_error`移除测试必须把只有当前union-wide字段的旧OperationFailure tag送入standalone decoder，断言
`malformed_payload {problem:"invalid_value", json_pointer:"/terminal/error/kind"}`；另把已删除variant的
`error`字段与旧tag同时送入，断言按Schema substage 1先返回
`malformed_payload {problem:"unknown_field", json_pointer:"/terminal/error/error"}`。不得为这两例添加specific
override或把`error`加入union-wide字段集合做兼容。在NodeObservation Condition伪造同名tag也必须按closed
union拒绝且整份observation零副作用。重建的current完整Desired正常通过
F0时Operation保持Pending，不能采用Node自报error；完整row缺失、无法canonical encode或重放失败时必须断言
当前事务abort、Operation row原状态不变、observation未接受/未结算，Control Plane进入内部fatal/unready且停止
签发新的Desired/placement/Grant；不得生成quarantined/blocked Condition、Operation terminal或Node自报error。
顶层`ContractError`的既有serde/version/error vectors继续通过。

decoder/validator contract tests必须直接覆盖§16.4的统一pipeline：

- Transport：invalid UTF-8和invalid JSON都返回根pointer；超限array在第`maximum + 1`项之后仍放置非法
  JSON、duplicate key、unknown/missing field、invalid type和unknown discriminator，验证所有更早stage先于
  `array_items`且decoder不保留无界items。同一payload放多个duplicate key并交换member顺序，必须固定选择
  logical path最小的`duplicate_field`。
- Union schema：在schema-reachable nested union放unknown tag，并分别在payload其他位置放duplicate key、
  non-union missing和union-field-set外unknown key，依次验证duplicate/schema错误先于tag；unknown tag与同一
  union的variant-specific missing/type并存时固定返回tag `invalid_value`且不猜variant；valid outer variant的
  missing与其可达nested unknown tag并存时也由更早tag substage获胜。交换所有object member顺序不改变
  code/problem/pointer。
- Scalar：每类unsigned integer至少测试非number、`1.0`、`1e0`、`-0`、负数、逻辑域边界及十进制overflow；
  前者为`invalid_type`，其余无效number为精确field `invalid_value`。另保留route gate外层`endpoint_id`
  unknown；`runtime_identity_conflict`单个different identity合法、只有expected identity非法，
  `duplicate_runtime`少于两个different identity非法；并覆盖Id/HostPath/closed literal边界。超限array尾部若
  只有`1.0`或非法Id这类Intrinsic错误，必须先返回更早的`array_items`；尾部unknown discriminator则因Schema
  更早而返回tag `invalid_value`。
- Array/identity：同一array duplicate与逆序分别返回指向array的`duplicate_identity`和
  `non_canonical_order`；跨array/variant collision指向参与字段的最小共同object。两个item在index 2和10同时
  失败时按数值选择2。
- Pointer确定性：同一stage放多个missing/unknown/type/value候选并交换member顺序；unknown key包含`~`和
  `/`，验证`~0`/`~1`；escape后恰好512 bytes保留精确pointer，超过512固定根空string。多个长pointer先按
  未转义logical path选择，禁止先fallback或截断。
- Digest/context：修改`DesiredRuntimeSpec.spec_digest`、complete inventory digest和有效key-ring digest的
  claim必须由context-free decoder返回指向claim的`malformed_payload invalid_value`；重新生成自洽claim后，
  再令同revision的stored digest不同，context-bound validator才返回`revision_digest_conflict`。standalone
  decode必须用mock证明不读取Store/filesystem/provider；intrinsically valid但与accepted inventory/Desired、
  attestation、checkpoint file或current Operation不匹配的对象先通过decoder，再由对应context stage拒绝。

### 16.4 跨组件 typed errors

所有runtime contract边界使用同一错误对象：

```text
ContractError {
  version: 1,
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
    code: "stale_observation_sequence",
    node_id: Id,
    agent_session_epoch: Epoch,
    presented_heartbeat_sequence: Sequence,
    last_accepted_heartbeat_sequence: Sequence
  }
| {
    code: "observation_sequence_conflict",
    node_id: Id,
    agent_session_epoch: Epoch,
    heartbeat_sequence: Sequence,
    accepted_observation_id: RandomId128,
    presented_observation_id: RandomId128
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
             | "runtime_checkpoint" | "node_cleanup_checkpoint" | "node_observation"
             | "operation" | "contract_error"
```

`message`只供人读，接收方只能按`error.code`及typed payload分支。所有顶层合同共用下面唯一的
validation pipeline；实现不得为某个合同类型另排优先级或在serde首次报错处提前返回。

#### 16.4.1 Context-free decoder（F0）

F0只实现不读取Control Store、filesystem、provider或其他合同对象的context-free decoder。每个stage都要
先扫描完整bounded payload、收集该stage的全部候选并按§16.4.2选出唯一错误；只有当前stage没有候选才进入
下一stage。固定顺序如下：

1. **Transport**
   - 顶层wire byte cap最先执行；读到`maximum + 1` byte即可停止，返回
     `limit_exceeded {json_pointer:"", limit:"wire_bytes", maximum, observed_at_least:maximum + 1}`。
   - 未超byte cap时必须消费全部payload，依次完成UTF-8、完整JSON grammar和全payload duplicate-key
     prepass，包括unknown-field subtree中的object。UTF-8/grammar各取最早input byte错误并返回根pointer；
     只有完整grammar成功后才收集所有`duplicate_field`候选，pointer指向重复member。不能让尾部错误被
     前面的schema或array错误遮蔽。
2. **Schema**。该stage再分为三个全payload substage，顺序不可交换：
   1. 对non-union object检查全部required/unknown field和primitive JSON kind；对discriminated union
      object只检查discriminator（通常`kind`，`ContractErrorDetail`为`code`）required/type，并检查每个key
      是否属于所有variant字段名的并集。此时不得要求某一variant的其他字段，也不得检查其类型。
   2. 对全部string-typed discriminator检查closed literal；未知tag返回指向tag field的
      `malformed_payload {problem:"invalid_value"}`。
   3. 只对已选定的variant检查该variant的required/unknown field和primitive JSON kind；属于另一variant的
      field在这里是`unknown_field`。unknown tag不选择或猜测variant，因此同一union里的variant-specific
      missing/type错误不产生候选。

   “全payload union”只包括从顶层schema可达的union occurrence。valid discriminator可以用于发现其selected
   variant中的嵌套schema；即使外层还有variant-specific missing/unknown候选，也必须继续收集嵌套union更早
   substage的候选。outer discriminator无效时不得臆测其variant-specific subtree中的nested union schema。
   实现必须在报告任何后一个substage前完成所有可达对象的前一个substage；object member输入顺序或递归遍历
   顺序不能改变结果。这里的primitive kind只区分object/array/string/number/boolean/null；number的
   canonical integer lexeme和范围在Intrinsic stage检查。
3. **Version 与 array item limit**
   - Schema通过后先验证顶层`/version`。number token不满足canonical unsigned integer或超出
     `0..=9223372036854775807`返回`invalid_value`；有效范围内但不等于1才返回
     `unsupported_version`。`unsupported_version`只由正在decode的顶层`version`产生；嵌套projection的
     `version`在Intrinsic stage按closed scalar literal验证，不创建第二个version空间。
   - Version通过后检查§10.4全部array item上限。多个超限array按§16.4.2选取，pointer固定指向array；
     `observed_at_least`固定为`maximum + 1`。实现可在该项后停止保存domain item或精确计数，但Transport和
     Schema仍必须先扫描全部payload；不得因array超限跳过尾部grammar、duplicate、required、unknown、type
     或discriminator错误，也不得为超限array分配无界内存。
4. **Intrinsic**。只验证payload自身足以证明的事实，并按以下substage顺序执行：
   1. 所有scalar value：每个unsigned numeric字段只接受JSON number token
      `0|[1-9][0-9]*`，再按其`ContractVersion`/`Revision`/`Epoch`/`Sequence`/`U64`等逻辑域检查范围。
      非number已在Schema返回`invalid_type`；`-0`、负数、fraction、exponent和超出逻辑域或
      `9223372036854775807`的值均为`invalid_value`。实现必须按十进制token判定overflow，不能先溢出机器
      integer。随后验证Id、HostPath、其他string格式及所有非discriminator closed scalar literal。
   2. 所有array的strict order和identity约束。
   3. 只引用同一payload字段的wire cross-field invariant。
   4. payload同时携带完整digest projection与claimed digest时，按§16.1/§16.2重算并比较。V1具体是
      `DesiredRuntimeSpec.spec_digest`、complete `NodeObservation.inventory_digest`及non-null
      `NodeObservation.key_ring_digest`；不完整projection不能冒充self-digest input。重算不等返回
      `malformed_payload {problem:"invalid_value"}`并精确指向claimed digest字段。

standalone `Operation`的phase/terminal规则及§12明确列出的result、HostLost和PlacementRejected placement
binding都属于Intrinsic wire cross-field；§12的精确field pointer是§16.4.2通则的specific override，必须
保留。context-free decoder通过只表示该单一payload自洽，不表示其session、revision、digest、placement、
cleanup target或物理事实已经获得外部授权。

#### 16.4.2 唯一 error 定位与 tie-break

`json_pointer`使用RFC 6901文本，根对象是空string。每个stage/substage先按未转义的逻辑JSON path选择错误：共同
prefix相同时短path先于child；object key按decoded UTF-8 bytes无符号字典序；array index按数值排序，所以
2先于10。同一逻辑path再按problem rank
`missing_field < unknown_field < duplicate_field < invalid_type < invalid_value < duplicate_identity < non_canonical_order`
选择。不同stage永远按§16.4.1的stage顺序，不能由输入member顺序、hash-map顺序或发现顺序改变。

通用定位规则覆盖全部schema，不再逐字段枚举：

- missing/unknown/type错误指向精确field或array item；缺失field也使用本应出现的完整逻辑path。
- 单一numeric range、Id、HostPath、string格式或非discriminator closed literal失败返回`invalid_value`并指向
  精确field/item；数字的`1.0`、`1e0`、`-0`、负数和overflow都遵守此规则。JSON grammar本身禁止的前导零
  仍在Transport返回根`invalid_json`。
- 同一array内identity重复返回`duplicate_identity`、pointer为该array；非duplicate但不严格递增返回
  `non_canonical_order`、pointer也为该array。
- 跨array或variant的identity collision返回`duplicate_identity`，pointer为包含全部参与字段的最小共同
  object。未被更具体规则覆盖的multi-field intrinsic invariant返回`invalid_value`，pointer同样是全部参与
  字段的最小共同object。§12等已明确更具体field pointer的规则优先于这个fallback。
- self-digest mismatch固定指向同payload中的claimed digest字段；它不使用
  `revision_digest_conflict`。

选出候选后才渲染pointer：object segment把`~`编码为`~0`、`/`编码为`~1`，array segment使用十进制index，
再以`/`连接。若完整RFC 6901 pointer不是§1.1合法`JsonPointer`，特别是转义后超过512 UTF-8 bytes，则固定
回退根空string；禁止截断、返回ancestor、按escaped pointer排序或先fallback再tie-break。

#### 16.4.3 Context-bound validator（Store / Node）

context-free decoder通过后，需要外部状态的边界才进入context-bound validator；这不属于F0 decoder。
适用的stage按下列固定顺序执行，不适用的stage直接跳过。前一stage失败时不得读取、执行或产生后一stage的
任何副作用：

1. **session**：presented epoch小于current返回`stale_session`；epoch相同但boot/instance不匹配，或
   presented epoch更大，返回`wrong_session`。
2. **observation sequence**：session通过后才执行§10唯一接收状态机。小于最高值返回
   `stale_observation_sequence`；等于但decoded payload不同返回`observation_sequence_conflict`；exact replay
   只读首次成功结果。
3. **revision**：此时才读取current Desired/Operation的revision字段，按边界语义返回`stale_revision`或
   `wrong_revision`，不能用后来revision结算旧Operation。
4. **stored/context digest**：revision通过后才读取对应stored digest并比较。只有同Cat、同revision的
   current Desired/Operation spec digest不等才返回`revision_digest_conflict`；该code绝不表示§16.4.1
   self-digest重算失败，也不用于file content、inventory attestation或其他context digest。其他context
   digest mismatch按其既有domain语义拒绝，不构造虚假的revision字段。
5. **placement**：digest通过后才读取对应stored/current Operation的placement字段；node ID或placement
   epoch不匹配返回`wrong_placement`。
6. **Operation settlement / postcondition / external facts**：最后才结算Operation、验证目标完整postcondition
   或读取/执行Node物理事实。stale session等前层错误不得读取Operation、filesystem或provider事实。

外部checkpoint文件的content digest，Cleanup与accepted inventory/Desired的绑定，
`AdmissionInventoryAttestation`与已接受inventory的绑定，Operation与current Desired的绑定，以及runtime、
volume、route、provider等事实都不属于单对象decoder。Admission attestation与accepted inventory的digest
在第4 stage验证；Operation/current Desired的revision、digest和placement绑定分别在第3/4/5 stage验证；
external file、Cleanup binding、terminal settlement和物理postcondition只在第6 stage执行。任何非stored
revision/spec的digest mismatch都不能伪造`revision_digest_conflict`payload。
特别地，`CheckpointEvidence.valid`只携带checkpoint projection，不携带完整`RuntimeCheckpoint`，所以其
`content_digest`只能由Node读取完整文件后验证，不是self-digest规则。

Control Store中的完整Desired在与Operation同一事务提交前已经通过§16.4.1。若后来无法从该current完整row
重建等价canonical wire，或重建后不再通过同一decoder，这是Control Store invariant failure：当前事务整体
abort，既有Operation row保持进入事务时的原状态（通常为Pending），该observation不接受也不结算；Control
Plane进入内部fatal/unready并停止签发新的Desired、placement和Grant，直到operator恢复可信数据库状态。这不是
`Condition.kind=quarantined`或`Condition.kind=blocked`，因此不触发Operation terminal，也不能落盘Node自报的
`contract_error`。不得新增raw Desired ledger、error receipt或旁路证明。

非Observation边界的`wrong_placement.expected/presented`就是该边界实际比较的两份完整
`AssignedPlacement`，不能为填充错误payload构造虚假placement。

NodeObservation settlement的revision、stored spec digest和placement三个stage共用同一外层选择：只遍历
`runtime.applied_desired != null`且该Cat有current Pending Operation的runtime；每个stage都独立从
`runtimes.cat_id`最小项开始扫描，整个revision stage无冲突后才能重新从最小Cat进入digest，整个digest
stage无冲突后才能进入placement。没有current Pending Operation的Cat不参与settlement选择；对于settlement
index标记为有Pending Operation的Cat，对应current Desired或Operation row缺失是Control Store invariant
破坏，必须fail closed且不伪造下列typed error。每个runtime内先比较current Desired与Operation binding，再比较
current Desired与`runtime.applied_desired`；一旦选中候选，不得读取、比较或报告同runtime的后一来源、后续
Cat或后续stage。

- **revision**：`expected_revision = current Desired.desired_revision`。先取
  `Operation.desired_revision`，不等即为`presented_revision`；只有相等时才读取并比较
  `runtime.applied_desired.desired_revision`。首个candidate小于expected返回`stale_revision`，大于expected
  返回`wrong_revision`；error的`cat_id`和current/expected revision均来自该Cat current Desired。
- **stored spec digest**：只有全部revision binding通过后才执行。
  `expected_digest = current Desired.spec_digest`；先比较`Operation.desired_spec_digest`，相等后才比较
  `runtime.applied_desired.spec_digest`。首个不等返回
  `revision_digest_conflict {cat_id, desired_revision:current Desired.desired_revision, expected_digest,
  presented_digest:selected source}`。
- **placement**：只有全部digest binding通过后才执行，`expected = current Desired.placement`。依次选择
  `Operation.placement`、`runtime.applied_desired.placement`，最后比较顶层`NodeObservation.node_id`；前两者
  使用完整不等placement，顶层Node不等时构造
  `{kind:"assigned", node_id:NodeObservation.node_id, placement_epoch:expected.placement_epoch}`作为
  `presented`。首个不等返回该Cat/current revision的`wrong_placement`。

Store查询返回顺序和JSON object member输入顺序都不参与选择。任一上述错误都拒绝整个NodeObservation，
不得推进checkpoint、接受observation/attestation、更新freshness、结算任何Operation或产生物理副作用。
placement通过后才执行§12的PlacementRejected settlement binding；其specific pointer保持不变。stale
session与该reason mismatch并存时先返回session error且不读取Operation。

`AgentRegistrationAttempt`没有可先验证的current session，因此保留§2的端点specific replay顺序：先按
`(node_id, registration_attempt_id)`查找已提交attempt；命中且binding不同返回
`registration_attempt_conflict`。`expected`是首次提交的四字段binding，`presented`是本次请求，不包含
服务端分配的session epoch/deadline，也不构造两个虚假的`SessionBinding`。这不是F0 decoder规则，也不改变
其他session-bound边界的stage顺序。通用API idempotency仍按§4在domain mutation前处理，不属于单对象decoder。

`stale_observation_sequence`必须满足`presented_heartbeat_sequence <
last_accepted_heartbeat_sequence`。`observation_sequence_conflict.heartbeat_sequence`必须等于已接受和
本次payload共用的sequence；`accepted_observation_id`来自首次已提交payload，
`presented_observation_id`来自本次payload，两者允许相同，因为conflict也可能发生在其他字段。
两类错误都不得写observation/最高sequence、更新attestation/freshness、结算Operation或产生任何其他
Control Plane/Node物理副作用。
