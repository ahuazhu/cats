# Runtime Placement Policy v1

- 状态：Frozen target contract；尚未实现
- Authority：[ADR-0043](../decisions/0043-provisioner-owned-runtime-placement-policy.md)
- Runtime authority：[ADR-0040](../decisions/0040-level-triggered-runtime-reconciliation.md)
- Admission facts：[Runtime Inventory and Observation Spine v1](runtime-inventory-observation-v1.md)
- Cat-create atomicity：[Volume Authority §8.1](volume-authority.md#81-disk-create)
- Local composition：[Runtime Composition Artifacts v1](runtime-composition-artifacts-v1.md)

本文冻结 production Cat-create 缺失的最后一段静态 placement authority：谁能声明一个
`NodeIdentity`可调度、可分配多少 vCPU/内存、安装了哪一组 production runtime capability，以及
Guest private IPv4 从哪里分配。它同时冻结多副本 Control 的确定性 planner、地址碰撞处理和
Cat-create commit 重验。

本合同不建立 scheduler reservation、capacity lease、fleet total row、heartbeat capacity 或第二份
network authority。legacy `nodes` row、Node heartbeat、自报 CPU/内存、环境变量、fixture boolean 和
Node 本地 CIDR 推导都不是输入。V1 只有本文件的 `NodePlacementPolicy`、A20 的完整 admission facts、
current assigned `DesiredRuntimeSpec` 与 Desired 中的 exact `NetworkConfig`。

## 1. 固定常量与类型

除本节显式收窄外，`Id`、`RandomId128`、`Epoch`、`Sha256Digest`、`Ipv4Address`、
`MacAddress`、closed object、integer token及 Cats Canonical JSON 使用
[Runtime Reconciliation §1/§16](runtime-reconciliation-v1.md#1-范围与标量)。所有加法、乘法、epoch
递增、地址转换和计数都使用 checked arithmetic；overflow 是 stored invariant failure，不 wrap、截断或
把该 Node 当作普通不可选。

| 项目 | V1 唯一值 |
|---|---|
| node page size | `64` |
| planner transaction | PostgreSQL `REPEATABLE READ READ ONLY`，一次 DB now |
| planner/commit Store deadline | `10000 ms` |
| policy route | `POST /v1/admin/runtime/node-authority-applies` |
| route request cap | `65536` octets |
| route success cap | `16384` octets |
| route error cap | `20480` octets |
| provisioner trust bundle cap | `16384` octets |
| provisioner trust path | `/etc/cats/identity/runtime-provisioner-trust.v1.json` |
| provisioner trust config | `--runtime-provisioner-trust-file`，value必须是上述exact path |
| policy IPv4 pool | aligned RFC 1918 `/16` |
| `/30` slots in a `/16` | `16384` |
| reserved slot | `0` |
| allocatable slots | `1..=16383` |
| placement-unavailable retry hint | `Retry-After: 1` |

`NodePlacementPolicy`是 provider-neutral Control Store record：

```text
NodePlacementPolicy {
  version: 1,
  node_id: Id,
  policy_revision: Epoch,
  scheduling_state: "cordoned" | "schedulable",
  allocatable_vcpus: integer 1..=4294967295,
  allocatable_memory_bytes: integer 1..=9223372036854775807,
  capabilities: RuntimePlacementCapabilities,
  guest_ipv4_pool: GuestIpv4Pool
}

RuntimePlacementCapabilities {
  vmm: "cloud_hypervisor",
  block_frontend: "kernel_nbd" | "vhost_user_blk",
  guest_network: "isolated_ipv4",
  guest_transport: "vsock",
  guest_agent_protocol_version: 1,
  guest_config_digest: Sha256Digest
}

GuestIpv4Pool {
  kind: "private_ipv4_16",
  network_address: Ipv4Address,
  prefix_length: 16
}
```

`network_address`必须是 prefix `/16` 的 network address，低 16 bit 全零，并且整个 `/16`完全位于
`10.0.0.0/8`、`172.16.0.0/12`或`192.168.0.0/16`之一。broadcast、link-local、CGNAT、documentation、
multicast、loopback和public范围都拒绝。这里的地址域是每个 Node 的 Host-local isolated L2 realm；
不同 Node 可以使用相同 `/16`，因此本合同没有由 RFC 1918 空间反推的 fleet total cap。V1 不声称它是跨
Node overlay；若以后把多个 Node 放进同一 L2/overlay，必须先增加显式network-domain authority，不能把
本合同的Host-local地址当成fleet-global地址。

`allocatable_*`是 provisioner 在扣除 Host/Control/Node reserve 后批准给 Cats 的静态上限，不是物理
CPU/RAM探测结果。`capabilities`证明该 Node 的 production deployment exact composition；FakeVmm、dev
network、未验证的Guest artifact和隐式默认 block path 都不能编码成合法 policy。`guest_config_digest`
必须来自 A19/A19a 的同一 release receipt，不是能力字符串或 catalog key。

## 2. Authority、revision 与合法变更

Control Store对每个 `NodeIdentity.node_id`恰好保存一条 current policy。它以`node_id`作主键和
NodeIdentity外键；identity不是`provisioned`或policy不是`schedulable`都普通fail closed。由于initial
provision原子写两者，provisioned identity缺policy是stored corruption并使replica unready，不能静默跳过。
NodeIdentity的immutable Host/state-path lineage继续以ADR-0040/A19a为权威，policy不能改写它。
持久logical row就是§1完整`NodePlacementPolicy`，没有另一个mutable capacity/schedulable projection；物理列若
为查询复制revision/state，Store每次读取必须与closed policy逐字段相等，任何差异使replica unready。

policy只有本文件§3的node-authority apply transaction能创建或更新。Node的A19 credential、AgentSession、
Desired/observation handler、heartbeat、legacy admin/service token、部署环境变量和测试fixture都没有写权限。
Node可以报告实际能力不足并让当前 Operation 进入既有 `PlacementRejected`，但报告不能提高capacity、改变
pool或把自己从`cordoned`变成`schedulable`。

revision规则如下：

1. `provision`在同一transaction原子创建`NodeIdentity(state="provisioned")`和
   `NodePlacementPolicy(policy_revision=1,scheduling_state="cordoned")`；二者全有或全无。不存在先写
   identity、随后用direct SQL补policy的窗口。
2. `update_policy`必须提供exact current `expected_policy_revision=N`和完整new policy；new
   `policy_revision`必须是checked `N+1`。耗尽拒绝，不归零。
3. `schedulable -> cordoned`可以在仍有assigned Desired时提交；它只停止新placement，不迁移、不停止现有
   Cat。drain仍通过ADR-0040完整Desired revision完成。
4. `allocatable_*`、`capabilities`或`guest_ipv4_pool`任一变化，只允许current和new policy均为
   `cordoned`，并且锁后current assigned Desired集合为空。`cordoned -> schedulable`只允许这些静态字段与
   current policy逐字段相同；它仍要求后续planner独立通过fresh A20 admission。
5. 相同Node换`guest_ipv4_pool`必须先cordon并drain到assigned set为空。以后任何指向该policy revision的
   placement都生成fresh `network_id`和完整fresh `NetworkConfig`；旧network ID即使碰巧得到相同地址也不
   复用。跨Node placement同样总是fresh network identity/config和更高Desired/placement revision。
6. credential rotation不改变policy或policy revision，但必须与policy update/Create通过同一
   NodeIdentity coordination row串行；retire永久保留最后policy、所有apply result与审计principal。

`update_policy`除revision外还必须至少改变一个字段；semantic no-op拒绝为
`authority_precondition_failed`，不能只制造revision抖动。

policy row不是availability声明。`schedulable`只说明provisioner允许考虑该Node；A20 current session、fresh
full inventory、release digest、assigned set与residue检查仍需全部通过。

## 3. Provisioner apply

### 3.1 单一 mutation route

所有初始provision、policy CAS、A19a credential rotation和retire走一个closed route：

```text
RuntimeNodeAuthorityApply {
  version: 1,
  apply_id: RandomId128,
  node_id: Id,
  mutation: RuntimeNodeAuthorityMutation
}

RuntimeNodeAuthorityMutation =
  {
    kind: "provision",
    node_identity: NodeIdentity,
    placement_policy: NodePlacementPolicy
  }
| {
    kind: "update_policy",
    expected_policy_revision: Epoch,
    placement_policy: NodePlacementPolicy
  }
| {
    kind: "rotate_credential",
    expected_credential_id: Id,
    expected_credential_binding: CredentialBinding,
    new_credential_id: Id,
    new_credential_binding: CredentialBinding
  }
| {
    kind: "retire",
    expected_policy_revision: Epoch,
    expected_credential_id: Id,
    expected_credential_binding: CredentialBinding
  }

RuntimeNodeAuthorityApplyResult {
  version: 1,
  apply_id: RandomId128,
  node_id: Id,
  outcome: "provisioned" | "policy_updated" | "credential_rotated" | "retired",
  identity_state: "provisioned" | "retired",
  policy_revision: Epoch
}

RuntimeNodeAuthorityStoredOutcome =
  { kind: "applied", response: RuntimeNodeAuthorityApplyResult }
| { kind: "authority_precondition_failed" }
```

所有重复出现的`node_id`必须逐字段相同。`provision`只接受A19a canonical `NodeIdentity`，其state必须是
`provisioned`；policy必须revision 1且cordoned。identity或policy已存在时只有§3.4 exact apply replay可
成功，不能adopt等价row。`rotate_credential`按A19a exact old ID+binding CAS；new ID/binding必须不同且合法，
policy必须cordoned、assigned set为空、current AgentSession不存在或以本次同一DB now判断已过期。它不建立
第二把同时有效的Node key。`retire`要求exact credential、exact policy revision、policy cordoned、assigned
set为空和session absent/expired，再把identity置为retired；retired identity不能update/rotate/unretire。

route envelope固定为：exact path、method `POST`、query完全缺席（含裸`?`）、恰好一个无parameter
`Content-Type: application/json`、`Content-Encoding`缺席、body为无BOM的UTF-8 closed JSON且最大65536
octets。handler从收到完整headers起总deadline为10000 ms，最多对serialization/deadlock做3次完整transaction
重试；每次从已认证、immutable decoded request重读全部Store facts。

官方CLI只提供以下薄封装，并把exact request在调用前durable保存以便response-loss replay：

```text
cats admin runtime-node provision --identity <artifact> --policy <policy>
cats admin runtime-node policy apply --node <id> --expected-revision <n> --file <policy>
cats admin runtime-node credential rotate --request <file>
cats admin runtime-node retire --request <file>
```

CLI调用上述HTTP route，不打开数据库连接、不执行SQL；A19a §2.3/§2.4的crash recovery source继续保存
old/new Node private halves和identity descriptors，central IaC/provisioning state则必须在发送前durable保存exact
`apply_id`与canonical request。A19a closed Host recovery directory不增加policy/request/provisioner-key文件；
ambiguous recovery组合这两份既有durable source，只重放same request。Node/Guest上不安装CLI的provisioner
private key。

### 3.2 两种且仅两种 authenticated principal

成功的adapter只向Store输出：

```text
FleetPolicyPrincipal =
  {
    kind: "deployment_provisioner",
    deployment_id: Id,
    credential_id: Id,
    public_key_spki_sha256: Sha256Digest
  }
| {
    kind: "workos_fleet_administrator",
    subject: Id,
    organization_id: Id
  }
```

两种adapter互斥；请求同时携带两种凭据时返回401，不选择更强或更先出现的一种。

**Deployment provisioner。** Control production release必须通过§1 exact CLI参数读取exact trust path；无env
alternate、inline key、fixture fallback或hot reload。文件是root:root 0644、single-link、non-symlink regular
file，使用Runtime canonical JSON，closed schema如下：

```text
RuntimeProvisionerTrustBundle {
  version: 1,
  deployment_id: Id,
  credentials: [RuntimeProvisionerCredential]
}

RuntimeProvisionerCredential {
  credential_id: Id,
  public_key_spki: Base64UrlNoPad
}
```

`credentials`长度1..=4，按`credential_id`严格升序且无重复；SPKI必须是A19 §4.1同一个canonical Ed25519
44-octet DER，credential ID与SPKI都不能重复。Control bounded读取、strict decode并在打开admin listener前
固定整个bundle；flag缺失、value不是exact path、文件metadata/bytes不合法或读取中变化都使production Control
startup fail closed。private half只在central IaC/provisioning environment，绝不进入Control config、Node、Guest、
日志或request body。

同一Control schema/cell的`deployment_id`不可变。跨release，已有credential ID只能保留exact SPKI；new key使用
fresh ID，已移除ID不得重新引入或绑定另一SPKI。release qualification必须把candidate bundle与上一accepted
bundle逐字段比较并保存receipt；这不是Node heartbeat或数据库policy写入口。

machine request必须恰有一个`Cats-Provisioner-Credential-Id`和一个
`Cats-Provisioner-Signature` header；不得有`Authorization`、Cookie或A19的三个
`Cats-Node-*` headers。credential ID选择bundle中的exact SPKI；signature是RFC 4648 base64url无padding的
64-octet Ed25519 signature，签名输入为：

```text
frame(x) = u64-big-endian(byte_length(x)) || x
body_digest = SHA-256(exact_body_octets)

signed_request =
  ASCII("cats.runtime-node-authority.request.v1") || 0x00
  || frame(ASCII("POST"))
  || frame(ASCII("/v1/admin/runtime/node-authority-applies"))
  || frame(ASCII("application/json"))
  || frame(ASCII(trust_bundle.deployment_id))
  || frame(ASCII(Cats-Provisioner-Credential-Id))
  || u64-big-endian(body_octet_length)
  || body_digest
```

没有timestamp是有意的：TLS防窃取，method/path/deployment/key/body binding防搬用，Store的`apply_id`提供exact
replay/conflict。proof格式/签名失败统一401，不查询NodeIdentity或apply row。trust key rotation使用overlap：先
部署含old+new且提高release identity的bundle，切换IaC signer并用new key完成或重放同一apply，最后部署移除old
的bundle。apply identity不包含credential ID，所以合法new key可重放old key response-loss；审计仍保留首次
principal。

**Human fleet administrator。** 只接受ADR-0006 sealed admin Cookie，或通过WorkOS签名/issuer/audience/expiry
验证的短期access JWT；其`organization_id`必须等于部署配置的管理员Organization，且token/session的
`permissions`集合必须包含exact `cats:fleet:admin`。不得用role slug、display name、普通Organization
membership或workspace permission推断。WorkOS未配置/不可用时该adapter fail closed，deployment provisioner
仍独立工作。static `admin_token`、service bearer、Workspace automation token、普通user/admin混用Cookie和
A19 Node proof一律拒绝。两种成功principal拥有同一mutation语义，差异只进入immutable audit actor。

### 3.3 处理顺序与HTTP mapping

唯一处理顺序是：route/method/query -> media/forbidden-auth-header分类 -> bounded body -> 选择并验证一个auth
adapter -> closed decoder -> Store apply。machine proof通过前不parse JSON或查Store；WorkOS principal通过前
也不查Node/apply事实。

| outcome | HTTP |
|---|---|
| success或stored-success exact replay | `200 application/json`，canonical `RuntimeNodeAuthorityApplyResult` |
| wrong method on exact path | `405`，`Allow: POST` |
| exact path带query或裸`?` | `400 invalid_request_target` |
| wrong/trailing-slash/percent-encoded path | ordinary `404` |
| missing/duplicate/parameterized Content-Type或任意Content-Encoding | `415 unsupported_media_type` |
| body实际或声明超过65536 octets | `413 request_too_large` |
| malformed JSON、duplicate/unknown/missing field或typed constraint | `400 invalid_request` |
| missing、mixed或invalid credential | `401 authentication_failed` |
| valid WorkOS identity但org/permission不足 | `403 permission_denied` |
| same apply ID不同request | `409 apply_id_conflict` |
| expected revision/credential不等或mutation precondition不满足 | `409 authority_precondition_failed` |
| deadline、DB unavailable、serialization retries exhausted | `503 temporarily_unavailable`，`Retry-After: 1` |
| stored projection/canonical row损坏 | replica unready；public `503 temporarily_unavailable` |

所有response带`Cache-Control: no-store`，不压缩。typed error body不含current capacity、credential binding、
pool、other node ID或stored request。

`authority_precondition_failed` body固定为
`{"code":"authority_precondition_failed","message":"runtime node authority precondition failed"}`；该确定性
409按§3.4持久并exact replay。authentication/envelope error、`apply_id_conflict`、infrastructure failure和stored
corruption不创建新apply record。

### 3.4 Apply replay、事务与取消

Control Store保存下列immutable logical row；实现可用typed columns而不是JSON，但读回必须重建完全相同的closed
value，projection不等是stored corruption：

```text
RuntimeNodeAuthorityApplyRecord {
  apply_id: RandomId128,
  request: RuntimeNodeAuthorityApply,
  request_sha256: Sha256Digest,
  principal: FleetPolicyPrincipal,
  outcome: RuntimeNodeAuthorityStoredOutcome,
  committed_at_unix_ms: UnixMillis
}
```

主键是global `apply_id`；`request_sha256`是Runtime canonical request bytes的普通SHA-256，但exact replay仍比较
完整typed request，不能只信digest。row不更新、不因retire或trust-key rotation删除。
它是fleet/admin domain identity，不是ADR-0040的Workspace `ApiIdempotencyResult`，不伪造system workspace。

每次请求在一个PG transaction中先对`apply_id`取得transaction reservation并读取record：exact typed request
命中立即返回原stored 200或409，即使Node已retire或policy后来提高revision；同ID不同request立即409，二者都不读current
Node/policy。miss才按`node_id`锁NodeIdentity coordination row（initial absent使用node-scoped advisory lock），
再按mutation读取exact最小facts：provision只读identity/policy absence；policy update读current policy和按cat ID
排序的current assigned Desired；rotation/retire另读current AgentSession deadline。cordon不因session/
observation缺失而被阻断。precondition通过时把domain mutation、applied record、audit principal/response同一
commit；确定性precondition失败则零domain mutation并提交rejected record。两种都使用同一次DB now，均可在
response loss后exact replay。没有半个identity/policy或无record mutation。

apply transaction固定`READ COMMITTED`。result miss后取得/重取NodeIdentity coordination，随后只取一次
PostgreSQL `db_now`供session expiry、record time和domain time使用；assigned-set mutation已按§6先锁同一
NodeIdentity，所以锁后facts不会被另一个合法Control replica越过。serialization/deadlock retry必须重新begin、
重新锁并重取DB now，不能复用旧snapshot。

apply reservation固定为
`pg_advisory_xact_lock(hashtextextended(current_schema() || ':runtime-node-authority-apply:' || $1, 0::BIGINT))`，
其中`$1`是32 lowercase hex `apply_id`；随后读取record。primary key只作invariant backstop，不能在unique
violation abort后补写result。

initial absent lock固定为
`pg_advisory_xact_lock(hashtextextended(current_schema() || ':runtime-node-authority:' || $1, 0::BIGINT))`，
其中`$1=node_id`。Id内冒号或64-bit hash collision最多让不同Node额外串行，不会让相同Node绕过lock；row存在后
所有mutation只按NodeIdentity `FOR UPDATE`继续，且Cat-create从不需要这把initial-only advisory lock。

client在发送前取消不产生request；server在domain transaction commit前观察到deadline/cancel必须rollback且零
record/domain写；commit一旦可能已发送给PostgreSQL，server不得用连接drop猜rollback，后台完成commit/rollback
判定。response丢失、client取消或Control replica crash后，调用方只重发same exact body/apply ID；不得生成新
identity/key/policy revision。exact replay先做current auth，所以已移除的old provisioner key不能继续调用，
但任一current合法principal可解析原结果。

## 4. Multi-replica placement planner

### 4.1 完整same-snapshot facts

planner输入是已经完成Cat-create idempotency fast miss、image manifest验证和active release receipt验证后的
request shape、整批candidate `network_id`与active `guest_config_digest`。它不接收`capacity_ok`、
`schedulable` boolean或调用方Node hint。

```text
PlacementPolicySnapshot {
  evaluated_at_unix_ms: UnixMillis,
  node_placement_policy: NodePlacementPolicy,
  admission: PlacementAdmissionSnapshot
}

CatCreatePlacementPlan {
  version: 1,
  request_vcpus: integer 1..=4294967295,
  request_memory_bytes: integer 1..=9223372036854775807,
  network_id: Id,
  snapshot: PlacementPolicySnapshot,
  network_config: NetworkConfig
}
```

`snapshot.admission.node_identity.node_id`、policy node、selected placement node和NetworkConfig必须逐字段绑定；
plan的request shape/network ID必须逐字段等于同批candidate Desired，Store不能用plan字段覆盖或default Desired。
这是service/Store内部typed plan，不是persisted scheduler authority或HTTP wire。

一次planner call只开一个`REPEATABLE READ READ ONLY` transaction，并只取一次PostgreSQL `db_now`；A20
`evaluated_at_unix_ms`和本snapshot time都是它。NodeIdentity用exact keyset page：

```sql
WHERE state = 'provisioned'
  AND node_id COLLATE "C" > :last_node_id COLLATE "C"
ORDER BY node_id COLLATE "C" ASC
LIMIT 64
```

第一页没有cursor；下一页使用上一页最后一个`node_id`，禁止OFFSET。每页在同一transaction/snapshot批量加载
64个identity各自的current policy与A20 §7.1完整facts；不能为每页/每Node另开snapshot或取新clock。实现每次只
保留当前page和当前候选，内存O(64)，一直翻页到EOF；没有1024/4096等fleet cap，也不把“页数过多”当capacity
不足。10000 ms deadline到期是infrastructure unavailable，不是no capacity。

这里及assigned Desired的`cat_id`排序都是canonical ASCII octet order，PostgreSQL实现固定`COLLATE "C"`，
不继承数据库locale。严格按`node_id`升序first-fit：对一个Node完成§4.2全部检查和§5 allocation后即选择它，不比较utilization ratio、
空闲百分比、随机权重或另一套tie breaker。普通不可选继续下一个Node；检查到stored corruption立即fatal，
不能跳到后续Node掩盖坏authority。选择完成后不decode更大node ID只是first-fit语义，不表示它们健康。

### 4.2 Eligibility 与exact capacity

每个Node依次检查：

1. identity/projection自洽且provisioned；current policy必须存在且closed/canonical/self-consistent；缺失或
   非法是fatal，合法`cordoned`才是ordinary rejection；
2. policy capability由§1 closed decoder证明是production值；policy、current AgentSession和Control active release三处
   `guest_config_digest`相等；
3. A20 §7.1同一个session、fresh full attestation、full observation和current assigned snapshot全部通过；
4. full observation中的每个`ObservedNetwork`都逐字段对应current assigned Desired的exact
   `NetworkConfig`；任何`NodeResidue.network_tap`、unassigned/changed/duplicate network是普通
   `network_cleanup_pending`，必须等Node完成cleanup并提交new full inventory；
5. capacity与§5 network slot均可分配。

capacity只由snapshot内**所有**current assigned Desired的`runtime.vcpus`和`memory_bytes`求和；Running、
Suspended、Warm、Cold、Deleted全部按完整shape计费，不能因观测到sleep/stop、Host物理free或Operation terminal
而折扣。两个和分别用checked `u128`累加；再checked加本次request。结果小于等于policy allocatable才fit；
equality成功，超过1即拒绝。字段为零、decode/projection不自洽、duplicate current Cat、累加overflow都是fatal
Store corruption，不是ordinary capacity failure。

closed ordinary rejection是：

```text
PlacementCandidateRejection =
  "policy_cordoned"
| "policy_guest_config_mismatch"
| PlacementAdmissionRejection
| "network_cleanup_pending"
| "insufficient_vcpus"
| "insufficient_memory"
| "network_exhausted"
```

若EOF仍无candidate，planner保留最小`node_id`的首个rejection用于bounded internal metric；fleet为空用
`no_provisioned_nodes`。public response永远不暴露该原因或Node identity，见§7。

Runtime既有`unsupported_block_path|unsupported_network|unsupported_guest_capability`继续是Node在commit后
发现实际deployment不再满足policy/Desired时的closed `PlacementRejected`，不是允许policy保存未知enum或
planner把malformed policy降级为ordinary rejection的理由。

## 5. Isolated IPv4 `/30` allocation

### 5.1 Candidate start slot

slot 0（pool的首个`/30`）永久留给provisioner/Host network infrastructure，不进入Desired。其余16383个slot
使用candidate whole-batch `network_id`计算start：

```text
frame(x) = u64-big-endian(byte_length(x)) || x

H = SHA-256(
  ASCII("cats.runtime.isolated-ipv4-slot.v1") || 0x00
  || frame(ASCII(node_id))
  || frame(four network-order octets of guest_ipv4_pool.network_address)
  || frame(ASCII(network_id))
)

seed = u64-big-endian(H[0..8])
start_slot = 1 + (seed mod 16383)
```

候选从`k=0..=16382`做确定性linear probe：

```text
slot = 1 + ((start_slot - 1 + k) mod 16383)
```

运算在checked `u32/u64`中完成。不能用language hash、FNV、random retry、SQL row order或Node-local cat ID
derivation改变顺序。

### 5.2 唯一collision unit与config

occupied set只来自同一A20/planner snapshot的全部current assigned Desired NetworkConfig。每项必须先反向验证：

- `kind="isolated_ipv4"`、prefix 30、network ID合法且assigned set内唯一；
- guest/gateway同属policy `/16`与同一非零slot；gateway=`subnet_base+1`、guest=`subnet_base+2`；
- `guest_mac = 02:ca:<guest IPv4的四个network-order octet>`；
- subnet base/broadcast分别是`pool_base + slot*4`与`base+3`，全部checked且不越过pool。

反向验证失败、两个current Desired占同一slot、同network ID多config或MAC/address不等都是stored corruption。
唯一collision unit是selected `/30` slot；MAC和addresses由slot单射得到，不另做一个可能碰撞的hash/lease表。
candidate `network_id`若命中Volume Authority §8.1的既有identity collision，整批candidate rollback/discard并以
全新整批重试；linear probe只解决slot占用，绝不能给相同network identity换slot来“修复”identity collision。

选择首个free slot后构造：

```text
subnet_base = pool_base + checked(slot * 4)
gateway_ipv4 = subnet_base + 1
guest_ipv4 = subnet_base + 2
broadcast = subnet_base + 3
prefix_length = 30
guest_mac = 02:ca:<guest_ipv4 octet 0>:<1>:<2>:<3>
network_id = exact candidate network_id
```

`02`确保locally administered unicast；同一Node/pool中guest IPv4唯一，所以MAC唯一。不同Node是§1独立L2
realm，不声称MAC fleet-global。probe检查完16383个slot仍无free即ordinary `network_exhausted`；不扩大CIDR、
不使用slot0、不复用其他Node地址，也不写reservation。

### 5.3 删除、迁移与安全复用

一个slot只有在旧NetworkConfig已离开current assigned Desired集合，且其后当前session接受的new complete full
inventory同时证明：没有任何runtime仍报告该unassigned config/network ID，且没有任何
`NodeResidue.network_tap`，才可进入下一次planner的free set。partial observation、heartbeat timeout、Cold状态、
旧tap“可能退出”或Control本地时间都不能释放slot。

若placement改变，即使target Node policy使用同一CIDR/slot/addresses，也必须生成fresh whole-batch
`network_id`、完整fresh Desired revision和更高placement epoch。若新policy CIDR不同更不能原地改旧config。
旧Node先按旧Desired清理并用full inventory闭合；新Node只消费新Desired。这样network identity不会ABA，slot
复用只依赖current Desired + fresh physical absence，而不是永久lease表。

## 6. Cat-create commit与所有Desired mutation

Volume Authority §8.1既有顺序保持：HTTP/idempotency exact hit或conflict最先，且hit不得读取image、release、
policy、admission或capacity；miss才验证image/release、生成一整批candidate、调用本planner并构造完整Desired。

name仍free并准备写revision 1时，事务顺序固定为：

```text
ApiIdempotency key reservation/result reread
-> CatNameLock
-> NodeIdentity FOR UPDATE
-> current NodePlacementPolicy + A20 admission/assigned facts
-> VolumeRecord
-> Cat/Disk/Desired/Endpoint/Operation
```

在NodeIdentity锁内，Store用一次transaction DB now重载policy、identity、session、freshness、full inventory和
current assigned Desired；要求plan中所有非时间facts仍逐字段相同、policy revision仍相同，并以current time
重新证明lease/freshness。随后从current assigned set重算§4 capacity和§5对same candidate network ID的完整probe；
selected slot/config必须仍逐字段等于plan。任一ordinary变化返回`placement_plan_stale`，零business row、零API
result；stored corruption使replica unready。只有全部通过才按ADR-0032/0042继续在Volume之后写完整candidate。
commit不重扫更小Node：first-fit只定义plan snapshot的确定结果，更小Node后来变得eligible不影响selected Node的
safety，也不允许为“更优”placement中止一个仍完全有效的plan。

合法same-name 409分支不改变Desired，按Volume Authority现有graph锁序持久exact 409 result，并且不读取或
消费已失效placement plan。事务内idempotency hit也直接丢弃candidate。

policy apply、observation assigned-set acceptance和每个会增加/删除/换Node的Desired mutation都以
NodeIdentity作为唯一per-Node serialization row。涉及多个Node时先按`node_id`严格升序锁全部NodeIdentity，
重验每个Node的policy/A20/assigned facts，再进入Volume；不能`Desired -> NodeIdentity`逆序。迁移/Host takeover
向target增加assignment时使用本planner和fresh NetworkConfig；从source移除assignment也在同一事务锁source。
没有scheduler reservation table、capacity counter、network lease、advisory boolean或fleet total cap。

若commit前request取消/timeout，事务rollback且不写result。PostgreSQL commit可能已发送后，Control使用现有
non-cancellable cleanup确认结果；client只以同Cat-create idempotency key replay。exact result hit先于后来
cordon、capacity或image错误，response loss绝不生成第二批network identity。

## 7. Node消费边界、错误与rollout

Node必须逐字段消费`DesiredRuntimeSpec.runtime.network_config`的`network_id`、guest MAC、guest IPv4、prefix和
gateway；只把tap name与ownership token作为Host物理inventory，在Host resource lock/checkpoint下分配。它不从
cat ID/network ID/hash/本地CIDR重算Guest-facing配置。实际deployment block frontend必须等于policy批准值；
不能满足exact Desired时只报告ADR-0040 closed `PlacementRejected`，不能替换地址或路径继续启动。

tap effect的唯一logical input是完整Desired `NetworkConfig`加Node freshly generated ownership token；Host allocator
在resource lock下选择未占用tap name，checkpoint先持久化`(network_id,tap_name,ownership_token,exact config)`再
create。`ObservedNetwork`逐字段回报同一tuple。tap name/token不进入hash、slot occupancy或Guest config，也不能
让Node改写MAC/address；晚到tap只按exact token adopt/cleanup。

旧`node-agent` FNV-1a/cat-ID `/30`推导和`--ch-network-cidr`配置是上线阻断项：实现A23时先让Node exact
Desired驱动Cloud Hypervisor/tap，再删除flag、environment/config plumbing、parser、derivation和相关fixture。
Control planner/policy schema、Node consumer与clean-slate schema必须同一release切换；任一旧Node仍可能本地推导
网络时，所有A23 policy保持cordoned，不允许mixed authority rollout。

Cat-create placement错误的public mapping固定为：

| internal outcome | HTTP/public body |
|---|---|
| EOF无candidate，含capacity、cordon、admission、cleanup或network exhaustion | `503 application/json` + `Retry-After: 1`，`placement_unavailable` |
| commit policy/admission/capacity/slot变化，`placement_plan_stale` | 同一个`placement_unavailable` response |
| planner/commit deadline、DB unavailable、serialization exhausted | `503 temporarily_unavailable` + `Retry-After: 1` |
| stored policy/assigned config/projection corruption | replica unready；public `503 temporarily_unavailable` |

`placement_unavailable` exact body是无空白/newline的UTF-8：

```json
{"code":"placement_unavailable","message":"no runtime node can currently accept this cat"}
```

不返回per-Node rejection、capacity数字、CIDR或fleet size。image/manifest、request validation、idempotency conflict
和name conflict继续使用Volume Authority/A21既有mapping；A23不覆盖它们。Node在commit后才发现能力不足时，
仍按Runtime现有`PlacementRejected -> new system revision`，不是把已提交202重写成同步错误。
上述placement/infrastructure 503都不写`ApiIdempotencyResult`；同key以后先fast miss并可在facts恢复后用全新
whole-batch candidate重试。只有既有name 409和成功202按Volume Authority保存exact result。

## 8. Fixed vectors

以下code block均是exact canonical bytes、无结尾LF。实现测试必须独立重建，不得只比较文档里的hash。

**Policy：**

```json
{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","policy_revision":1,"scheduling_state":"cordoned","version":1}
```

```text
policy_octets = 497
policy_sha256 = sha256:e6f9c7b26334e4728119a96a40579f8f6ba3862c557160eb078cbc97428ab620
```

**Provisioner trust bundle：**

```json
{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],"deployment_id":"deployment_a","version":1}
```

```text
trust_bundle_octets = 174
trust_bundle_sha256 = sha256:e348b9d89a43efd190cfc8443abdd2dcb4e14bf21537f5bfef0ec82a1d70a144
```

**Update-policy apply/result：**

```json
{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mutation":{"expected_policy_revision":1,"kind":"update_policy","placement_policy":{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","policy_revision":2,"scheduling_state":"schedulable","version":1}},"node_id":"node_a","version":1}
```

```text
apply_octets = 663
apply_sha256 = sha256:1934e94054f59ea3f20de3232a9783448943e76c664f94977d93c490459fa702
signed_request_octets = 204
signed_request_sha256 = sha256:3441dcc9b166491330f9b2579919c04779c2842180929cbc3cbef5db23bd05f0
Cats-Provisioner-Signature = ZqMEaH3fIxcNWG5CExvV4nHOSk7OEQORKctt-z9R_naZm2s0OM64IGOAHr_5hhNdl2SZ1CeUBCKNX1t-O-wyAg
```

signature使用A19 §4.4同一个RFC 8032 test seed；只用于测试，绝不能部署。

```json
{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity_state":"provisioned","node_id":"node_a","outcome":"policy_updated","policy_revision":2,"version":1}
```

```text
result_octets = 156
result_sha256 = sha256:94ff5e6829405355d85dfff7c1a7f1e7f02cf420c64cab408c68366438e16468
authority_precondition_error_octets = 95
authority_precondition_error_sha256 = sha256:0c7d1b09d9bb4e70e65e1b105833a49d00caa7062ac4a9bedb7a0be289c35a83
```

**Network allocation：** exact input uses policy pool `10.240.0.0`, node `node_a` and
`network_id=net_77777777777777777777777777777777`.

```text
slot_hash = sha256:c7f62ab3afab39e75814e7a306e9fe3f279e4306a07e801f3814cc38876f3d97
seed = 14408751009053227495
start_slot = 8738
selected_slot_when_occupied_set_empty = 8738
subnet = 10.240.136.136/30
gateway_ipv4 = 10.240.136.137
guest_ipv4 = 10.240.136.138
guest_mac = 02:ca:0a:f0:88:8a
```

**Public placement error：**

```text
body_octets = 90
body_sha256 = sha256:a4636d17031808e21932b2f54dc3b0d104243a1e9e56e33962f678cd4d810839
```

## 9. Minimal acceptance matrix

| boundary | required oracle |
|---|---|
| authority/auth | provisioner signature fixed vector；wrong deployment/key/path/body拒绝；WorkOS只按admin org + exact permission；role slug、static admin/service bearer、workspace token和A19 Node proof均拒绝 |
| route/trust bounds | query、encoded/trailing path、wrong method/media mapping；chunked/Content-Length实际65536进decoder、65537为413；success/error cap；trust bundle 16384边界、metadata/path/read-change fail startup |
| apply replay | response loss exact replay原200或persisted precondition 409；same apply ID异payload 409；new trust key可重放old-key apply；revision/credential CAS conflict零domain写入且保存rejected outcome |
| A19a lifecycle | atomic identity+cordoned policy；cordoned/drained/expired-session rotation；retire保留policy/apply；retired永不unretire；crash windows只重放same request/private half |
| policy mutation | cordon与create两种lock先后各自线性；有assigned set时不能改capacity/capability/CIDR；uncordon不能夹带静态变化 |
| pages/replicas | 0、1、64、65和超过1024 Node；keyset无漏重；一个snapshot/DB now；两个Control replica稳定选同一最小eligible node；无fleet cap |
| capacity | lifecycle各态都计完整shape；equality fit、超1拒绝；vCPU/memory分别边界；checked sum/add overflow fatal；不读heartbeat/legacy node capacity |
| simultaneous create | 同Node剩余恰好一份capacity时只有一个commit；不同idempotency key不超卖；同key只一组identity/result；无reservation row |
| network hash/probe | fixed vector；slot0永不用；首slot collision、连续collision、16383->1 wrap；full 16383 exhaustion；duplicate/malformed assigned config fatal |
| reuse/migration | Desired移除但旧full inventory/tap residue仍拒绝；new full absence后可复用；跨Node或CIDR变化fresh network ID/config/revision；MAC只由selected slot导出 |
| stale plan | plan后cordon、policy revision、session replacement、freshness、assigned set、capacity或slot任一变化都零business/result并503；unchanged plan commit |
| order/cancel | idempotency hit在image/policy前；name 409不消费plan；commit前cancel零写；commit/response不明只同key replay |
| Node rollout | exact Desired network进入tap/CH；任一字段不等拒绝；删除FNV/cat-ID derivation、`--ch-network-cidr`和fallback；mixed release保持cordoned |
| calibrated negative | 对legacy `nodes` capacity、heartbeat CPU/RAM、env/fixture schedulable、FNV和`ch-network-cidr`的negative grep先以当前legacy positive校准，再在A23 production path证明零read |
