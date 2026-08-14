# Runtime Placement Policy v1

- 状态：Implemented frozen v1；clean-slate rollout only
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
[Runtime Reconciliation §1.1](runtime-reconciliation-v1.md#11-v1-wire-基础类型)和
[§16.1](runtime-reconciliation-v1.md#161-cats-canonical-json-v1)。所有加法、乘法、epoch
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
| 每 replica admin apply global in-flight cap | `32` |
| 每 replica、每 authenticated principal in-flight cap | `4` |
| shutdown commit-resolution join deadline | `30000 ms` |
| provisioner trust bundle cap | `16384` octets |
| provisioner trust path | `/etc/cats/identity/runtime-provisioner-trust.v1.json` |
| provisioner trust config | `--runtime-provisioner-trust-file`，value必须是上述exact path |
| policy IPv4 pool | aligned RFC 1918 `/16` |
| `/30` slots in a `/16` | `16384` |
| reserved slot | `0` |
| allocatable slots | `1..=16383` |
| placement-unavailable retry hint | `Retry-After: 1` |

两个in-flight cap是每个Control replica进程内的non-blocking admission，不是持久队列、
leader或分布式配额。所有时间上限都从收到完整headers起算并包含认证与Store时间。

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
  guest_ipv4_pool: GuestIpv4Pool,
  node_transport_target: NodeTransportTarget
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

NodeTransportTarget = canonical string "https://<hostname>:<port>"
```

`NodeTransportTarget`是1..=512 ASCII octets的strict HTTPS authority。`hostname`逐byte满足Runtime
`Hostname`（lowercase ASCII DNS，且不能是canonical或decimal/octal/hex缩写IPv4 number）；`port`必须显式存在、为
`1..=65535`的canonical十进制且无前导零。userinfo、path（包括`/`）、query、fragment、尾斜杠、默认端口
省略、IP literal、uppercase scheme/host和任何URL normalization一律拒绝。它只给Gateway定位加密、
machine-authenticated Node hop；Node本地gate仍是Route authority，TLS/workload identity不编码进这个hint。

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
required transport-target JSON/projection与exact catalog CHECK继续属于clean-slate authority schema 15；
任何早期版本不做in-place ALTER，startup必须拒绝并要求operator创建空的version-14 schema。

policy只有本文件§3的node-authority apply transaction能创建或更新。Node的A19 credential、AgentSession、
Desired/observation handler、heartbeat、legacy admin/service token、部署环境变量和测试fixture都没有写权限。
特别地，A19 registration/observation不携带或覆盖`node_transport_target`；legacy `nodes.agent_url`不是fallback。
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
4. `allocatable_*`、`capabilities`、`guest_ipv4_pool`或`node_transport_target`任一变化，只允许current和new policy均为
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
    expected_policy_revision: Epoch,
    expected_credential_id: Id,
    expected_credential_binding: PublicKeyCredentialBinding,
    new_credential_id: Id,
    new_credential_binding: PublicKeyCredentialBinding
  }
| {
    kind: "retire",
    expected_policy_revision: Epoch,
    expected_credential_id: Id,
    expected_credential_binding: PublicKeyCredentialBinding
  }

PublicKeyCredentialBinding = {
  kind: "public_key",
  public_key_spki_sha256: Sha256Digest
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
`provisioned`，且`credential_binding`必须是上述exact `PublicKeyCredentialBinding`；V1对
`CredentialBinding::ProviderPrincipal`和其他variant固定返回并持久
`authority_precondition_failed`，不建立provider-principal lineage。policy必须revision 1且cordoned。
identity或policy已存在时只有§3.4 exact apply replay可成功，不能adopt等价row。
`rotate_credential`按exact policy revision与old ID+public-key binding CAS；new ID/binding必须不同且是
从未出现过的fresh value，policy必须cordoned、assigned set为空、current AgentSession不存在或
以本次同一DB now判断已过期。它不建立第二把同时有效的Node key。`retire`要求
exact public-key credential、exact policy revision、policy cordoned、assigned set为空和session
absent/expired，再把identity置为retired；retired identity不能update/rotate/unretire。

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

每个上述命令只选择一种认证来源。deployment provisioner同时提供
`--deployment-id <id> --provisioner-credential-id <id>
--provisioner-private-key-file <path>`；key file必须是current user拥有、single-link、无symlink、exact
`0600`的strict PKCS#8 PEM，只有路径进入argv，private-key octets不进入argv、log、pending或resolution
receipt。每次重试都从该file读取current signer，因此同一pending可在trust rotation后由new current key重签。
human先用`cats admin login`取得独立的admin-Organization WorkOS session（也可显式提供一个短期WorkOS
access JWT），再运行上述命令；这个login/session不读取Cats Account/Workspace login，`--workspace`与
`CATS_WORKSPACE`在`admin login/logout`和`admin runtime-node`均固定拒绝。

独立admin session的credential-store account、跨进程排他锁和Control network authority都以同一个
canonical HTTPS origin为scope：由唯一URL parser序列化origin，host case与IDNA归一化、默认`:443`省略，且
拒绝userinfo、非`/` path、query和fragment。锁必须位于OS user-global、`CATS_CONFIG_DIR`之外的稳定
namespace；文件型实现以canonical credential account的domain-separated SHA-256命名，不能把URL字节直接
拼进path。Unix使用不受`HOME`/`XDG_DATA_HOME`影响的固定root-owned sticky临时目录，并在其下使用按effective
UID隔离、owner匹配且exact `0700`的私有目录；进程环境不能为同一OS user/keyring account选择第二个锁namespace。
旧版raw URL account只可在canonical lock内迁移：canonical缺失时先逐byte写入并确认，再删除raw；
两者已存在且bytes不同必须fail closed；写入后任一crash都可由下次调用按相同规则继续，不能双消费refresh
token。

Unix实现从稳定ancestor/root descriptor以`openat(O_NOFOLLOW)`打开single-link lock，取得`flock`后重验完整
ancestor/root/lock dev+ino与owner/mode/link合同，并在持锁阶段的每次credential read/write/delete及
Control/WorkOS network effect紧邻的前后再次重验；任何rename/recreate或unlink/recreate都在下一个effect前
fail closed。login取得全新、尚未持久化session的public/device-flow network不消费shared refresh token，完成
后才进入上述locked replacement。该descriptor identity合同不声称消除同UID actor在最终pre-effect check后
纳秒级重命名的竞态。login最终替换、refresh和logout都先取得该锁再重读当前credential，且持锁完成
rotating refresh token的替换或删除；因此指向同一origin、使用不同`CATS_CONFIG_DIR`的两个CLI进程也不能
同时消费同一个refresh token，后取得锁者必须看到已轮换的token；不同non-default port origin则保持隔离。
session-derived human Runtime Node请求从上述重读/refresh一直持有同一canonical锁，紧邻最终Control network
effect前后都重验（包括network error）；显式`--token`不消费shared rotating credential，因此不取得该锁。

平台若尚未实现本节要求的crash-safe pending/receipt backend，普通CLI、admin login/logout与help仍必须可编译
运行；`admin runtime-node`则在读取request/key、创建本地authority state或发送network request之前返回明确的
platform-unavailable错误。不得为了跨平台编译退化为普通path I/O或非durable apply。

CLI调用上述HTTP route，不打开数据库连接、不执行SQL；A19a §2.3/§2.4的crash recovery source继续保存
old/new Node private halves和identity descriptors，central IaC/provisioning state则必须在发送前durable保存exact
`apply_id`与canonical request。A19a closed Host recovery directory不增加policy/request/provisioner-key文件；
ambiguous recovery组合这两份既有durable source，只重放same request。Node/Guest上不安装CLI的provisioner
private key。

#### 官方 CLI 的 closed response state machine

CLI在首次发送前，必须持有一把该pending item的exclusive local lock，用temporary file + file
fsync + atomic no-replace rename + parent-directory fsync保存下列不可变事实：exact HTTPS origin（含
authority/port）、`POST`、exact request target、`application/json`、exact canonical body octets、
`apply_id`和body SHA-256。pending item不保存private key。重试可以用任一当前合法的provisioner
credential重签，但不得改origin、path、body、apply ID或mutation，也不得创建第二个pending item。

HTTP client关闭redirect following和automatic decompression；任何301/302/303/307/308都不跟随。只有下列
两个terminal response可以结算pending item：

1. exact origin返回`200`，恰好一个无parameter `Content-Type: application/json`，无
   `Content-Encoding`，body不超过16384 octets，并且是canonical closed
   `RuntimeNodeAuthorityApplyResult`。`apply_id`/`node_id`必须等于pending request；`provision`必须
   `provisioned/provisioned/revision=1`，`update_policy`必须
   `policy_updated/provisioned/revision=placement_policy.policy_revision`，`rotate_credential`必须
   `credential_rotated/provisioned/revision=expected_policy_revision`，`retire`必须
   `retired/retired/revision=expected_policy_revision`。
2. exact origin返回§3.3持久的`409 authority_precondition_failed`，并且status、media/
   encoding headers、exact 95-octet body和20480-octet cap全部匹配；response还必须恰好含一个
   `Cats-Node-Authority-Apply-Id` header，其值逐octet等于pending `apply_id`。

结算时CLI先用同样的temp/fsync/rename/parent-fsync流程写入绑定`apply_id`、request digest和
exact terminal response的不可变resolution receipt，然后才durably删除pending item并fsync parent。
EOF、reset、timeout、TLS错误、redirect、任意`1xx/3xx/5xx`、`401/403/429/503`、
`409 apply_id_conflict`、其他status、超限/压缩/非canonical body或字段不绑定的`200`都保留exact
pending item，且之后只能重发该item。`apply_id_conflict`还必须停止automatic retry并警报人工
调查，但不得把未结算item标成失败或换ID。CLI crash在任意窗口恢复时，resolution receipt优先于
pending deletion判定已结算；只有pending则继续same-request replay。

### 3.2 两种且仅两种 authenticated principal

成功的adapter只向Store输出：

```text
FleetPolicyPrincipal =
  {
    kind: "deployment_provisioner",
    deployment_id: Id,
    credential_id: Id,
    public_key_spki: Base64UrlNoPad,
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
  trust_revision: Epoch,
  expected_previous: null | {
    trust_revision: Epoch,
    active_set_sha256: Sha256Digest
  },
  credentials: [RuntimeProvisionerCredential]
}

RuntimeProvisionerCredential {
  credential_id: Id,
  public_key_spki: Base64UrlNoPad
}

RuntimeProvisionerActiveSet {
  version: 1,
  deployment_id: Id,
  credentials: [RuntimeProvisionerCredential]
}
```

`credentials`长度1..=4，按`credential_id`严格升序且无重复；SPKI必须是A19 §4.1同一个canonical Ed25519
44-octet DER，credential ID与SPKI都不能重复。Control bounded读取、strict decode并在打开admin listener前
固定整个bundle；flag缺失、value不是exact path、文件metadata/bytes不合法或读取中变化都使production Control
startup fail closed。private half只在central IaC/provisioning environment，绝不进入Control config、Node、Guest、
日志或request body。

`active_set_sha256 = SHA-256(CatsCanonicalJson(RuntimeProvisionerActiveSet))`，projection只删除
`trust_revision/expected_previous`，不能重排或过滤credentials。revision 1必须
`expected_previous=null`；revision大于1必须有non-null previous，其`trust_revision`恰好是
checked `bundle.trust_revision - 1`。这两个revision字段都使用`Epoch`，不得wrap或跳号。

同一Control schema/cell的`deployment_id`不可变。不能只把candidate bundle与“上一个release”比较；
每次production startup必须在打开admin listener前把完整bundle下述持久all-history lineage
进行CAS。一个schema只允许一个deployment identity，credential ID、exact SPKI和SPKI digest各自在该
schema全历史唯一；它们在移除、retire、多个release和多次rotation后也永不可重用。

最小PostgreSQL DDL固定为（`Id`、digest和time的closed decoder/check仍必须在Store边界执行）：

```sql
CREATE TABLE runtime_provisioner_deployment_identity (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  deployment_id TEXT NOT NULL UNIQUE,
  current_trust_revision BIGINT NOT NULL CHECK (current_trust_revision > 0),
  current_active_set_sha256 TEXT NOT NULL
    CHECK (current_active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0)
);

CREATE TABLE runtime_provisioner_trust_revisions (
  deployment_id TEXT NOT NULL REFERENCES runtime_provisioner_deployment_identity(deployment_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  trust_revision BIGINT NOT NULL CHECK (trust_revision > 0),
  active_set_sha256 TEXT NOT NULL
    CHECK (active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  expected_previous_trust_revision BIGINT NULL
    CHECK (expected_previous_trust_revision > 0),
  expected_previous_active_set_sha256 TEXT NULL
    CHECK (expected_previous_active_set_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  committed_at_unix_ms BIGINT NOT NULL CHECK (committed_at_unix_ms >= 0),
  PRIMARY KEY (deployment_id, trust_revision),
  UNIQUE (deployment_id, trust_revision, active_set_sha256),
  CHECK (
    (trust_revision = 1 AND expected_previous_trust_revision IS NULL
      AND expected_previous_active_set_sha256 IS NULL) OR
    (trust_revision > 1
      AND expected_previous_trust_revision = trust_revision - 1
      AND expected_previous_active_set_sha256 IS NOT NULL)
  )
);

ALTER TABLE runtime_provisioner_deployment_identity
  ADD CONSTRAINT runtime_provisioner_current_trust_revision
  FOREIGN KEY (deployment_id, current_trust_revision, current_active_set_sha256)
  REFERENCES runtime_provisioner_trust_revisions(
    deployment_id, trust_revision, active_set_sha256)
  ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE runtime_provisioner_credential_lineage (
  credential_id TEXT PRIMARY KEY,
  deployment_id TEXT NOT NULL REFERENCES runtime_provisioner_deployment_identity(deployment_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  public_key_spki TEXT NOT NULL UNIQUE,
  public_key_spki_sha256 TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
  first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0),
  retired_at_unix_ms BIGINT NULL CHECK (
    retired_at_unix_ms IS NULL OR retired_at_unix_ms >= first_committed_at_unix_ms),
  CHECK ((state = 'active' AND retired_at_unix_ms IS NULL) OR
         (state = 'retired' AND retired_at_unix_ms IS NOT NULL))
);
```

startup CAS使用一个transaction和一次DB now，先取得
`pg_advisory_xact_lock(hashtextextended(current_schema() || ':runtime-provisioner-trust', 0::BIGINT))`，
再读取/锁singleton row `FOR UPDATE`，最后按credential ID锁
全部current/candidate lineage。实现从canonical SPKI DER独立重算digest，并从全部`state=active` row按
credential ID重建current active-set canonical bytes；row里的current digest、revision receipt和重建值
任一不等都是stored corruption并fail startup。closed outcome只有：

- empty schema只接受revision 1 + null previous；同一commit插入deployment row、revision receipt和全部
  active lineage；
- candidate revision等于current revision时，只允许bundle expected-previous、active-set digest和每个
  ID/exact SPKI/digest逐字段等于该revision receipt/current active set的exact replay，零row mutation；
- candidate revision恰好是checked current+1时，`expected_previous`必须逐字段等于current
  revision+active-set digest，且candidate active set必须与current不同。已见ID只能匹配原exact
  SPKI/digest；已见SPKI或digest只能匹配原ID；retired值不能重新出现。transaction插入fresh key、把
  candidate缺席的current active row单调转retired、插入immutable revision receipt，最后以exact
  old revision+digest CAS推进singleton current pointer；
- older revision、gap、same revision不同set、previous mismatch或并发输掉CAS都fail startup且零mutation。

因此一个replica仅因自己的bundle缺少另一把active key，不能把它全局retire；只有central IaC发布的next
revision和exact previous-set CAS能改变active set。revision receipt、retired row、ID或SPKI永不删除/
重激活；除lineage `active -> retired`与retired time、singleton exact forward CAS外，字段不可更改。
这不是Node heartbeat或policy写入口。

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
replay/conflict。proof格式/签名失败统一401，不查询NodeIdentity或apply row。签名通过后，
每次request（包括exact apply replay）还必须先读取§3.2持久trust lineage，要求该
`deployment_id`、credential ID、exact SPKI和SPKI digest逐字段等于current `active` row，并把这四项放进
typed `FleetPolicyPrincipal`交给Store。数据库不可用返回503；
retired/mismatch返回401，不得因为本地旧bundle还有key而接受。

trust key rotation使用显式revision：先让每个replica部署含old+new的next-revision bundle；第一台以
expected previous-set CAS加入new，其他replica只能exact replay该revision，
再切换IaC signer并用new key完成或重放同一apply，确认没有old-key pending后才部署移除old
的下一revision bundle；首个新replica CAS后old才持久retire，仍在运行的旧replica也因per-request lineage检查立即
拒绝old。retired tombstone跨后续release永不重用。apply identity不包含credential ID，所以合法
new key可重放old key response-loss；审计仍保留首次principal。

**Human fleet administrator。** 只接受ADR-0006 sealed admin Cookie，或通过WorkOS签名/issuer/audience/expiry
验证的短期access JWT，二者只产生candidate subject，不是当前authorization的持久证明。
每个request（包括exact apply replay）都必须在Store apply前通过WorkOS authoritative User
Management API在线重读该subject对部署配置admin Organization的current membership，要求
membership当前active、`organization_id`逐字段等于配置值，并检查该current membership解析出的
`permissions`集合含exact `cats:fleet:admin`。不得用role slug、display name、普通Organization
membership、workspace permission或sealed session/JWT里的stale permission推断。

Cookie与JWT是两个互斥envelope：Cookie形态必须恰好一个Cats admin-session Cookie、无
`Authorization`、无provisioner/Node headers且不得混入user-session Cookie；JWT形态必须恰好
一个`Authorization: Bearer <token>`、无任何Cookie、无provisioner/Node headers。重复、其他auth
scheme或三种形态任意混合统一401，不选择“更强”的一个。无效/过期session/token返回401；
online lookup证明非active、错org或缺exact permission返回403；WorkOS/JWKS/membership API未配置、
outage、timeout或rate limit统一503 + `Retry-After: 1`，且不调用Store、不创建apply row。
deployment provisioner在WorkOS outage下仍独立工作。static `admin_token`、service bearer、
Workspace automation token和A19 Node proof一律拒绝。两种成功principal拥有同一mutation语义，
差异只进入immutable audit actor。

### 3.3 处理顺序与HTTP mapping

唯一处理顺序是：route/method/query -> media/forbidden-auth-header分类 -> non-blocking global
in-flight admission -> bounded body -> 选择并完整验证一个auth adapter（含machine persisted
trust active check或WorkOS online membership/permission check）-> non-blocking authenticated-principal
admission -> closed decoder -> Store apply。machine proof通过前不parse JSON或查Node/apply；WorkOS
principal通过前也不查Node/apply事实。两个admission都只尝试一次、不排队不等待；
machine principal key是`(deployment_id, credential_id)`，WorkOS principal key是
`(subject, organization_id)`。

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
| 本replica global in-flight cap已满 | `503 temporarily_unavailable`，`Retry-After: 1` |
| 该authenticated principal in-flight cap已满 | `429 principal_request_in_flight`，`Retry-After: 1` |
| WorkOS/JWKS/current membership lookup不可用 | `503 temporarily_unavailable`，`Retry-After: 1` |
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
`principal_request_in_flight`的exact body是
`{"code":"principal_request_in_flight","message":"runtime node authority request already in flight for this principal"}`。
本route的global cap、WorkOS/DB outage、deadline和retry exhaustion全部使用exact
`{"code":"temporarily_unavailable","message":"runtime node authority is temporarily unavailable"}`；不得把上游
WorkOS/SQL错误body透传给client。

只有Store已经同一commit持久化的`authority_precondition_failed`首次响应或exact replay才返回
恰好一个`Cats-Node-Authority-Apply-Id: <apply_id>` response header；value必须是请求中的32 lowercase
hex ID。其他4xx/5xx、`apply_id_conflict`和未进Store的失败不得返回该header。header缺失、重复或值不等时，
官方CLI不能把普通409猜成已持久结果。

global permit从admission成功持有到response完整编码交给transport，或commit已可能发送后
把解析工作交给预留的commit-resolution lane；principal permit从认证后admission持有到同一
边界。permit不得在发送PG commit后因handler cancel提前释放，也不得让cleanup job重新取一个
permit而死锁。cap满、WorkOS不可用和未进Store的任何认证错误都零apply/domain/audit写入。

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

Node credential不只保存在current `NodeIdentity`中。下列all-history lineage是clean-slate schema的
必需表；现有`node_identities`是实现`NodeIdentity`的主表，不得另造同义表或用无外键日志代替：

```sql
CREATE TABLE runtime_node_credential_lineage (
  credential_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES node_identities(node_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  public_key_spki_sha256 TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
  first_committed_at_unix_ms BIGINT NOT NULL CHECK (first_committed_at_unix_ms >= 0),
  retired_at_unix_ms BIGINT NULL CHECK (
    retired_at_unix_ms IS NULL OR retired_at_unix_ms >= first_committed_at_unix_ms),
  CHECK ((state = 'active' AND retired_at_unix_ms IS NULL) OR
         (state = 'retired' AND retired_at_unix_ms IS NOT NULL)),
  UNIQUE (node_id, credential_id),
  UNIQUE (node_id, credential_id, public_key_spki_sha256, state)
);

CREATE UNIQUE INDEX runtime_node_one_active_credential
  ON runtime_node_credential_lineage(node_id) WHERE state = 'active';

ALTER TABLE node_identities
  ADD COLUMN credential_lineage_state TEXT NULL,
  ADD CONSTRAINT node_identity_credential_lineage_state_matches_identity CHECK (
    (credential_kind = 'public_key' AND credential_lineage_state IS NOT NULL AND
      ((state = 'provisioned' AND credential_lineage_state = 'active') OR
       (state = 'retired' AND credential_lineage_state = 'retired'))) OR
    (credential_kind = 'provider_principal' AND credential_lineage_state IS NULL)
  );

ALTER TABLE node_identities
  ADD CONSTRAINT node_identity_current_public_key_lineage
  FOREIGN KEY (
    node_id, credential_id, credential_public_key_spki_sha256, credential_lineage_state)
  REFERENCES runtime_node_credential_lineage(
    node_id, credential_id, public_key_spki_sha256, state)
  ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;
```

`credential_id`和`public_key_spki_sha256`各自在整个Control schema的全历史中唯一，不仅在
一个Node或active set中唯一。只有`active -> retired`和首次retired timestamp可变；ID、Node、SPKI、
first time都immutable，row永不删除/重激活，NodeIdentity也因外键不能在lineage仍存在时GC。
两个deferred FK使同一transaction可以创建/轮换/retire两侧，但commit时每个PublicKey
`node_identities` current credential必须逐字段指向exact lineage：provisioned只能指向唯一active row，
retired只能指向其exact retired row；partial update、错Node/digest/state或active row不等于current binding
都由constraint abort，不能靠应用层best effort检查。composite FK的`NO ACTION`是有意的：rotation事务内
old lineage state和current binding可先后更新，到deferred commit一起检查；不能改成会在中间态立即拒绝的
`RESTRICT`。
`provision`在identity/policy同一commit插入active row；rotation在同一commit把exact old row转为
retired、插入fresh active row并替换NodeIdentity current binding；retire在同一commit把exact active
row转retired并retire identity。任何历史ID或SPKI命中，即使来自另一Node或已retire row，也是
持久`authority_precondition_failed`；V1不存在可重用的provider principal投影。

主键是global `apply_id`；`request_sha256`是Runtime canonical request bytes的普通SHA-256，但exact replay仍比较
完整typed request，不能只信digest。row不更新、不因retire或trust-key rotation删除。
它是fleet/admin domain identity，不是ADR-0040的Workspace `ApiIdempotencyResult`，不伪造system workspace。

每次请求在一个PG transaction中先对`apply_id`取得transaction reservation。若typed principal是
deployment provisioner，事务随后按固定顺序锁
`runtime_provisioner_deployment_identity FOR SHARE -> exact runtime_provisioner_credential_lineage FOR SHARE`，
从principal的canonical SPKI独立重算digest，并重验deployment、credential ID、exact SPKI、digest和
`state=active`全部逐字段相同；这两把row lock持有到apply/domain/result commit。锁后不等属于
`401 authentication_failed`并整笔rollback，零apply/domain/audit row，不能持久为authority precondition。
WorkOS principal不走trust rows。

完成上述current-auth revalidation后才读取apply record：exact typed request命中立即返回原stored 200或409，
即使Node已retire或policy后来提高revision；同ID不同request立即409，二者都不读current Node/policy。
miss且mutation带new credential时，先对new credential ID和SPKI digest取得下述全局
lineage locks；随后才按`node_id`锁NodeIdentity coordination row（initial absent使用node-scoped advisory lock），
再按mutation读取exact最小facts：provision只读identity/policy absence；policy update读current policy和按cat ID
排序的current assigned Desired；rotation/retire在§6统一顺序下另读current AgentSession deadline。cordon不因session/
observation缺失而被阻断。precondition通过时把domain mutation、applied record、audit principal/response同一
commit；确定性precondition失败则零domain mutation并提交rejected record。两种都使用同一次DB now，均可在
response loss后exact replay。没有半个identity/policy或无record mutation。

apply transaction固定`READ COMMITTED`。result miss后取得/重取NodeIdentity coordination，随后只取一次
PostgreSQL `db_now`供session expiry、record time和domain time使用；assigned-set mutation已按§6先锁同一
NodeIdentity，所以锁后facts不会被另一个合法Control replica越过。serialization/deadlock retry必须重新begin、
重新锁并重取DB now，不能复用旧snapshot。

apply reservation固定为
`pg_advisory_xact_lock(hashtextextended(current_schema() || ':runtime-node-authority-apply:' || $1, 0::BIGINT))`，
其中`$1`是32 lowercase hex `apply_id`；随后先完成上述current-auth transaction revalidation，再读取record。
primary key只作invariant backstop，不能在unique
violation abort后补写result。

trust revision CAS从不取得apply-ID lock；initial/rotation都先取上述schema-scoped trust advisory lock，再锁
deployment singleton `FOR UPDATE`（存在时）和credential rows。
因此与machine apply没有lock cycle。apply先取得singleton/credential share lock时，retirement必须等其
domain+result commit后才能前进；retirement先提交时，即使adapter早先已验证signature，apply事务锁后也只能
看到retired并401 rollback。不得在Store transaction外缓存`active=true`越过这个barrier。

new-credential lineage locks固定对`("credential_id", new_credential_id)`和
`("public_key_spki_sha256", new_spki_digest)`按整个tuple的ASCII octet order排序后逐个执行：

```text
pg_advisory_xact_lock(hashtextextended(
  current_schema() || ':runtime-node-credential-lineage:' || kind || ':' || value,
  0::BIGINT))
```

取得后查询ID和SPKI两个历史索引；任一row存在即走持久409。hash collision只使无关
credential额外串行，不破坏安全。DDL unique constraints只是invariant backstop，不允许依赖transaction-aborting
unique violation后猜测返回，所有provision/rotation writer都必须使用这个顺序。

initial absent lock固定为
`pg_advisory_xact_lock(hashtextextended(current_schema() || ':runtime-node-authority:' || $1, 0::BIGINT))`，
其中`$1=node_id`。Id内冒号或64-bit hash collision最多让不同Node额外串行，不会让相同Node绕过lock；row存在后
所有mutation只按NodeIdentity `FOR UPDATE`继续，且Cat-create从不需要这把initial-only advisory lock。

client在发送前取消不产生request；server在domain transaction commit前观察到deadline/cancel必须rollback且零
record/domain写；commit一旦可能已发送给PostgreSQL，server不得用连接drop猜rollback，后台完成commit/rollback
判定。response丢失、client取消或Control replica crash后，调用方只重发same exact body/apply ID；不得生成新
identity/key/policy revision。exact replay先做current auth，所以已移除的old provisioner key不能继续调用，
但任一current合法principal可解析原结果。

shutdown先关闭listener并拒绝新admission，再取消所有确定未进入commit-send边界的job；
每个已可能发送commit的job都必须留在reserved resolution lane并join到确认commit/rollback、写完
stored response且释放in-flight permits。进程的固定join deadline是30000 ms，production supervisor的
termination grace必须不小于该值；deadline到仍有未解析job时必须以非零shutdown failure退出，
不能报告clean shutdown、detach task或猜测结果。客户端pending item仍用same apply ID闭合response-loss。

## 4. Multi-replica placement planner

### 4.1 完整same-snapshot facts

Cat-create的planner输入是已经完成idempotency fast miss、image manifest验证和active release receipt
验证后的request shape、整批candidate `network_id`与active `guest_config_digest`。其他会改变placement/
shape的Desired mutation使用同一planner和下列post-mutation model。它不接收`capacity_ok`、
`schedulable` boolean、调用方Node hint、调用方自报source exclusion或Host-fenced boolean。
这个planner不取代Runtime/Volume的Cold-only、RWO fence、idle/transition或authorization前置；service必须
先通过它们才可规划shape/move，commit仍在同一事务按各authority重验。

```text
PlacementPolicySnapshot {
  evaluated_at_unix_ms: UnixMillis,
  node_placement_policy: NodePlacementPolicy,
  admission: PlacementAdmissionSnapshot,
  active_host_fence_event: HostFenceEvent | null
}

PlacementCurrentCas {
  cat_id: Id,
  desired_revision: Revision,
  spec_digest: Sha256Digest,
  placement: AssignedPlacement,
  vcpus: integer 1..=4294967295,
  memory_bytes: integer 1..=9223372036854775807,
  network_config: NetworkConfig
}

PlacementMutation =
  {
    kind: "cat_create",
    cat_id: Id,
    target_desired_revision: 1,
    target_placement_epoch: 1,
    target_vcpus: integer 1..=4294967295,
    target_memory_bytes: integer 1..=9223372036854775807,
    candidate_network_id: Id
  }
| {
    kind: "same_node_reconfigure",
    current: PlacementCurrentCas,
    target_desired_revision: Revision,
    target_placement_epoch: Epoch,
    target_vcpus: integer 1..=4294967295,
    target_memory_bytes: integer 1..=9223372036854775807
  }
| {
    kind: "move",
    reason: "planned_migration" | "host_takeover" | "placement_retry",
    current: PlacementCurrentCas,
    target_desired_revision: Revision,
    target_placement_epoch: Epoch,
    target_vcpus: integer 1..=4294967295,
    target_memory_bytes: integer 1..=9223372036854775807,
    candidate_network_id: Id,
    required_source_host_fence_event_id: Id | null
  }

SourceAssignmentSnapshot {
  node_identity: NodeIdentity,
  assigned_desired_specs: [DesiredRuntimeSpec],
  active_host_fence_event: HostFenceEvent | null
}

PostMutationPlacementPlan {
  version: 1,
  mutation: PlacementMutation,
  server_derived_excluded_source_node_ids: [Id],
  target_snapshot: PlacementPolicySnapshot,
  source_snapshot: SourceAssignmentSnapshot | null,
  network_config: NetworkConfig
}

CatCreatePlacementPlan = PostMutationPlacementPlan where mutation.kind = "cat_create"
```

`target_snapshot.admission.node_identity.node_id`、policy node、selected placement node和NetworkConfig必须
逐字段绑定；plan的target revision/placement epoch/shape/network ID必须逐字段等于同批candidate Desired，Store不能
用plan字段覆盖或default Desired。`PlacementCurrentCas`是从current full Desired服务端投影的
exact CAS；它不是调用方提供的old shape。这是service/Store内部typed plan，不是persisted
scheduler authority或HTTP wire。

`server_derived_excluded_source_node_ids`由Store在同一planner snapshot从current Desired/placement和trusted
HostFenceEvent派生，按`node_id` ASCII octet order严格升序且无重复：Cat create和
same-node reconfigure必须为空；任何`move`必须恰好包含`current.placement.node_id`。
public/service request没有这个字段，不得删除source、添加任意Node或把同Node move伪装成
same-node reconfigure。`planned_migration|placement_retry`必须
`required_source_host_fence_event_id=null`；`host_takeover`必须绑定trusted controller已为current source
建立的exact Active event ID。反向组合或event与current placement/immutable Host/session lineage不等是
stored/service invariant failure，不允许用null/fallback降级。

target candidate domain同样是closed的：Cat create扫描全部NodeIdentity；same-node reconfigure只读取并
评估`current.placement.node_id`这一Node，target必须与它相等，不参与fleet first-fit；move才扫描全部
NodeIdentity并跳过exact source。create/move在各自domain内都使用§4.2的`node_id` first-fit，调用方不能
通过candidate list或hint收窄/重排。

Cat create的`source_snapshot=null`；same-node reconfigure的source就是exact target snapshot，也编码null；
`move`必须携带source的full `SourceAssignmentSnapshot`。该snapshot与全fleet target pages使用同一
`REPEATABLE READ` transaction和DB now；source assigned set最多1024项且逐字段closed decode。

一次planner call只开一个`REPEATABLE READ READ ONLY` transaction，并只取一次PostgreSQL `db_now`；A20
`evaluated_at_unix_ms`和本snapshot time都是它。NodeIdentity用exact keyset page：

```sql
WHERE state = 'provisioned'
  AND node_id COLLATE "C" > :last_node_id COLLATE "C"
ORDER BY node_id COLLATE "C" ASC
LIMIT 64
```

第一页没有cursor；下一页使用上一页最后一个`node_id`，禁止OFFSET。每页在同一transaction/snapshot批量加载
64个identity各自的current policy、A20 §7.1完整facts和该Node的current Active
`HostFenceEvent`（无则null）；不能为每页/每Node另开snapshot或取新clock。一个NodeIdentity
同时最多一个Active event；Runtime rejoin/Host replacement状态机保证这个约束，Store读到多个是
fatal corruption而不是选最小ID。实现每次只
保留当前page和当前候选，内存O(64)，一直翻页到EOF；没有1024/4096等fleet cap，也不把“页数过多”当capacity
不足。10000 ms deadline到期是infrastructure unavailable，不是no capacity。

这里及assigned Desired的`cat_id`排序都是canonical ASCII octet order，PostgreSQL实现固定`COLLATE "C"`，
不继承数据库locale。严格按`node_id`升序first-fit：对一个Node完成§4.2全部检查和§5 allocation后即选择它，不比较utilization ratio、
空闲百分比、随机权重或另一套tie breaker。普通不可选继续下一个Node；检查到stored corruption立即fatal，
不能跳到后续Node掩盖坏authority。选择完成后不decode更大node ID只是first-fit语义，不表示它们健康。

### 4.2 Eligibility 与exact capacity

每个Node依次检查：

1. `node_id`不在server-derived source exclusion中；命中是ordinary `source_node_excluded`，不得用它的
   剩余capacity原地“调度”一次move；
2. identity/projection自洽且provisioned；current policy必须存在且closed/canonical/self-consistent；缺失或
   非法是fatal，合法`cordoned`才是ordinary rejection；
3. 同snapshot查到任何current `HostFenceEvent.state=Active`都是ordinary
   `active_host_fence_event`，该Node不能成为new placement target；任何event/projection无法closed decode是
   fatal，不得把它当作“没有Active event”；
4. policy capability由§1 closed decoder证明是production值；policy、current AgentSession和Control active release三处
   `guest_config_digest`相等；
5. A20 §7.1同一个session、fresh full attestation、full observation和current assigned snapshot全部通过；
6. full observation中的每个`ObservedNetwork`都逐字段对应current assigned Desired的exact
   `NetworkConfig`；任何`NodeResidue.network_tap`、unassigned/changed/duplicate network是普通
   `network_cleanup_pending`，必须等Node完成cleanup并提交new full inventory；
7. §4.3 post-mutation assigned set/capacity与§5 network slot均可分配。

任何current assigned set已超过1024项都fatal stored corruption并使replica unready，不能裁剪、分页或将
第1025项当作ordinary capacity miss。合法current set的具体post-mutation计算见§4.3；结果集合
必须在任何业务/result写入前证明每个受影响Node都`assigned_count <= 1024`。

closed ordinary rejection是：

```text
PlacementCandidateRejection =
  "source_node_excluded"
| "active_host_fence_event"
| "policy_cordoned"
| "policy_guest_config_mismatch"
| PlacementAdmissionRejection
| "network_cleanup_pending"
| "assigned_set_limit"
| "insufficient_vcpus"
| "insufficient_memory"
| "network_exhausted"
```

若EOF仍无candidate，planner保留最小`node_id`的首个rejection用于bounded internal metric；fleet为空用
`no_provisioned_nodes`。public response永远不暴露该原因或Node identity，见§7。

Runtime既有`unsupported_block_path|unsupported_network|unsupported_guest_capability`继续是Node在commit后
发现实际deployment不再满足policy/Desired时的closed `PlacementRejected`，不是允许policy保存未知enum或
planner把malformed policy降级为ordinary rejection的理由。

### 4.3 通用 post-mutation assigned set 与 capacity

对每个受影响Node，Store先把current assigned full Desired strict decode为以`cat_id`为key的map
`C(node)`。所有lifecycle state（Running/Suspended/Warm/Cold/Deleted）都以完整
`runtime.vcpus/memory_bytes`计费，不因observation sleep/stop、Host physical free或Operation terminal折扣。
字段为0、duplicate Cat、decode/projection不自洽或`|C(node)| > 1024`都fatal/unready。

post-mutation map只有下列closed构造：

- `cat_create`：target `C' = C + (new cat, target shape, fresh network)`；current map已有该cat是
  stale/service invariant failure；target revision和placement epoch必须都精确为1。
- `same_node_reconfigure`：`current.placement.node_id` 必须等于target Node，current map必须
  包含与`PlacementCurrentCas`的revision/digest/placement/old shape/network逐字段相同的唯一Cat；
  `C'`只用new Desired的target shape替换该项，并保留exact old `NetworkConfig`。这不分配
  new network ID/slot，不允许借shape change改Guest network或placement epoch；target revision必须是
  checked `current.desired_revision + 1`，target placement epoch必须等于current值。
- `move`：source map必须含exact `PlacementCurrentCas`，source
  `C' = C - current cat`；target map必须不含该cat，target
  `C' = C + (same cat, target shape, fresh network)`。target必须与source不同，使用fresh whole-batch
  network ID/config；target revision必须是checked `current.desired_revision + 1`，target placement epoch必须是
  checked `current.placement.placement_epoch + 1`。CIDR或选中slot恰好相同也不例外。

纯assignment removal（例如已闭合tombstone的最终清理）不跑fleet target planner，但仍必须在锁定
source NodeIdentity后用同一exact-CAS规则构造`C' = C - current cat`。除上述四种外，
不得直接更改placement/shape或按SQL delta更改capacity counter。

每个`C'`的count用checked integer重算并必须`<= 1024`。因此target 1023 -> 1024可以
继续；1024 -> 1025固定ordinary `assigned_set_limit`，planner不返回plan，commit重验时则
零Desired/Volume/Operation/API result写入。same-node replace的count不变，move对source减1、target加1；
不得先写后由A20 encoder拒绝超限集合。

vCPU和memory分别用checked `u128`。先对`C(node)`每项求`total`，再按mutation求target
post-total：create/move target是`checked_add(total, new)`；same-node reconfigure精确是
`checked_add(checked_sub(total, exact_old), new)`。不能只加shape delta，不能对shrink做wrap，
也不能从调用方old shape做subtract。target两个post-total均小于等于current policy
allocatable才fit；equality成功，超过1即分别拒绝`insufficient_vcpus|insufficient_memory`。
source removal也做checked subtract以证明map自洽，但不要求source schedulable/fresh，也不会因减少
使用量而被source capacity阻断。任何sum/add/sub/count overflow都fatal，不是ordinary capacity miss。

same-node reconfigure与target新assignment要求target通过§4.2全部eligibility，含schedulable、fresh A20和
无Active HostFenceEvent。`planned_migration|placement_retry`的source snapshot必须无Active event；
`host_takeover`必须由`required_source_host_fence_event_id`命中一个仍Active、完整lineage相等的event。
二者的target都要求无任何Active event。event在plan后变化使plan stale，不得自动在
migration/takeover/retry reason间转换。

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
-> 全部受影响NodeIdentity FOR UPDATE，按node_id
-> current NodePlacementPolicy，按node_id
-> current AgentSession，按node_id（target admission适用时）
-> Node observation receive-state / DesiredReadState / AdmissionInventoryState，按node_id（适用时）
-> HostFenceEvent，按event_id（存在性/状态重验适用时）
-> VolumeRecord
-> Cat/Disk/Desired/Endpoint/Operation
```

多Node mutation必须先按`node_id` ASCII顺序取得**全部**NodeIdentity lock，才能取任何
policy/session/receive/event lock；不得按“source全部rows -> target全部rows”交错。在这些锁内，
Store用一次transaction DB now重载target policy、A20 session/freshness/full inventory、所有受影响
current assigned Desired、server-derived exclusion和HostFenceEvent facts。assigned Desired在Volume前只做受
NodeIdentity serialization保护的读取/比较，不提前取`Desired FOR UPDATE`；写锁仍在Volume之后。

事务要求plan的全部非时间facts、policy revision、`PlacementCurrentCas`、source snapshot和exclusion
仍逐字段相同，并以current DB time重新证明target lease/freshness。它按§4.3从current maps重建post-
mutation maps/count/capacity，对create/move按§5用same candidate network ID重做完整probe，对same-node
reconfigure则要求exact old NetworkConfig不变。target必须仍无Active HostFenceEvent；
non-takeover source必须仍无Active event，host takeover必须锁定并重验exact required event仍Active且
lineage匹配。selected slot/config必须仍逐字段等于plan。

任一ordinary变化返回`placement_plan_stale`，零Desired/Volume/Operation/business row、零API/
mutation result；stored corruption使replica unready。特别地，plan后target从1023变成1024使本次
post-count=1025时，必须在Volume前拒绝且零result写入。只有全部通过才按ADR-0032/0042继续
在Volume之后锁定current Desired/Operation、再以exact current revision/digest/placement CAS写新完整
Desired。两个replica同时same-node resize、move或create时，只有先取得NodeIdentity且CAS仍成立的
一方可提交；后一方必须fresh replan，不能应用old-shape delta。
commit不重扫更小Node：first-fit只定义plan snapshot的确定结果，更小Node后来变得eligible不影响selected Node的
safety，也不允许为“更优”placement中止一个仍完全有效的plan。

合法same-name 409分支不改变Desired，按Volume Authority现有graph锁序持久exact 409 result，并且不读取或
消费已失效placement plan。事务内idempotency hit也直接丢弃candidate。

policy apply、Agent registration/session replacement、Desired read cursor、observation acceptance和
**任何写current full Desired任一字段**的mutation，只要old或new placement是assigned，都以
NodeIdentity作为唯一per-Node serialization row，并共用
`NodeIdentity -> current credential lineage（A19-auth path）-> AgentSession -> observation receive/cursor ->
HostFenceEvent -> Volume`前缀；不涉及的row跳过。不能
`credential-lineage|AgentSession|receive-state|Desired|HostFenceEvent -> NodeIdentity`逆序。一个HostFenceEvent的新建、
`Active -> Rejoined`或任何会改变placement eligibility的state/lineage mutation也必须先锁该
NodeIdentity，再锁event；这使target NodeIdentity锁下的“无Active event”重验不会被并发插入或
rejoin越过。只消费已有event且不改event eligibility state的Volume authorization继续可按
`HostFenceEvent -> Authorization -> Volume`走，因为它不会再反向取NodeIdentity。

Desired writer的affected set是old assigned node与new assigned node的并集：insert只取new，remove只取old，
same-node lifecycle/route/volume-intent/disk/disposition/require-idle/target或其他non-shape revision也必须取该
same Node，move取source+target并按node ID排序。writer可以在无锁snapshot定位candidate set，但必须在取得
全部NodeIdentity后重读current full Desired；若old placement或应锁集合不同，整笔rollback并从fresh
snapshot重试，不能先锁Desired再补NodeIdentity。只有old/new都unassigned且不消费Node evidence的mutation可
跳过该前缀。non-shape mutation不需要伪造placement plan，但仍以exact current full Desired CAS写完整new
revision；这样A20 full snapshot、policy/create capacity read与每个字段变化都在线性化点两侧看到全旧或全新。

迁移/Host takeover/placement retry向target增加assignment时使用本planner和fresh NetworkConfig；
从source移除assignment在同一事务锁source并完成exact old Desired CAS。
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
| EOF无candidate，含source exclusion、Active fence、assigned-set cap、capacity、cordon、admission、cleanup或network exhaustion | `503 application/json` + `Retry-After: 1`，`placement_unavailable` |
| commit current CAS、policy/admission/event/post-set/capacity/slot变化，`placement_plan_stale` | 同一个`placement_unavailable` response |
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
对不直接绑定public HTTP的migration/takeover/placement-retry worker，相同ordinary no-candidate/stale不写
新Desired/Operation terminal/result，保留触发intent并从fresh snapshot重规划；它不能把内部reason持久为
scheduler lease或更改已结算HTTP response。若以后绑定新public mutation route，该route必须显式冻结自己的
idempotency envelope；不得默认复用Cat-create key。

## 8. Fixed vectors

以下code block均是exact canonical bytes、无结尾LF。实现测试必须独立重建，不得只比较文档里的hash。

**Policy：**

```json
{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","node_transport_target":"https://node-a.internal:7301","policy_revision":1,"scheduling_state":"cordoned","version":1}
```

```text
policy_octets = 552
policy_sha256 = sha256:fdfcf8bb96ab5ba124aeeaff498eb4bbd88eeda2e0afd2cf0ab188778e67464e
```

**Provisioner active set 与revisioned trust bundle：**

```json
{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],"deployment_id":"deployment_a","version":1}
```

```text
active_set_octets = 174
active_set_sha256 = sha256:e348b9d89a43efd190cfc8443abdd2dcb4e14bf21537f5bfef0ec82a1d70a144
```

```json
{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],"deployment_id":"deployment_a","expected_previous":null,"trust_revision":1,"version":1}
```

```text
initial_trust_bundle_octets = 218
initial_trust_bundle_sha256 = sha256:f054993251d9e78ea0cc9169ec5156e36465b874257f946d970a624d0b92b49a
```

revision-2 overlap的active set canonical bytes为：

```json
{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},{"credential_id":"provisioner_b","public_key_spki":"MCowBQYDK2VwAyEAPUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw"}],"deployment_id":"deployment_a","version":1}
```

```text
overlap_active_set_octets = 288
overlap_active_set_sha256 = sha256:707f709222d120452e07a4e999ea540ad214d43fc0243b30a9c65043ec6c96fd
```

```json
{"credentials":[{"credential_id":"provisioner_a","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},{"credential_id":"provisioner_b","public_key_spki":"MCowBQYDK2VwAyEAPUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw"}],"deployment_id":"deployment_a","expected_previous":{"active_set_sha256":"sha256:e348b9d89a43efd190cfc8443abdd2dcb4e14bf21537f5bfef0ec82a1d70a144","trust_revision":1},"trust_revision":2,"version":1}
```

```text
overlap_trust_bundle_octets = 442
overlap_trust_bundle_sha256 = sha256:931a8758e7b0c82208bb23b8a831b4e97532747b7e7c3df61e26f973ca6eeca0
```

Store transaction收到并持久审计的deployment-provisioner principal为：

```json
{"credential_id":"provisioner_a","deployment_id":"deployment_a","kind":"deployment_provisioner","public_key_spki":"MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","public_key_spki_sha256":"sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"}
```

```text
provisioner_principal_octets = 275
provisioner_principal_sha256 = sha256:407a741259f6155606c029218830fce0319cd6884ec8500490ccda36f555490d
```

**Update-policy apply/result：**

```json
{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mutation":{"expected_policy_revision":1,"kind":"update_policy","placement_policy":{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","node_transport_target":"https://node-a.internal:7301","policy_revision":2,"scheduling_state":"schedulable","version":1}},"node_id":"node_a","version":1}
```

```text
apply_octets = 718
apply_sha256 = sha256:b03395b52d23522f5c549493b82c5d00f1b4ee102dbbe27770c475509cf36d21
signed_request_octets = 259
signed_request_sha256 = sha256:4c67c5a92e987723f0e64e1468ca77a7ddcac6ea4f06d12c85444e9050fb939e
Cats-Provisioner-Signature = 2e7RW-nONH8NAPi7tPQeVdiOCRG0fUKI9OMO6MxjwvmPLPdefC2DWPwvDC-lE6BQ2XzFdZEoKcgb4LCo_MBXAA
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

**Rotate-credential apply/result：**

```json
{"apply_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mutation":{"expected_credential_binding":{"kind":"public_key","public_key_spki_sha256":"sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"},"expected_credential_id":"credential_a","expected_policy_revision":2,"kind":"rotate_credential","new_credential_binding":{"kind":"public_key","public_key_spki_sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"new_credential_id":"credential_b"},"node_id":"node_a","version":1}
```

```text
rotate_apply_octets = 519
rotate_apply_sha256 = sha256:d3cfcb8571a784a0dbca3bf8d8925a2559d2797cf5213080433baafba6642e7f
```

```json
{"apply_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","identity_state":"provisioned","node_id":"node_a","outcome":"credential_rotated","policy_revision":2,"version":1}
```

**Admin admission errors：**

```json
{"code":"principal_request_in_flight","message":"runtime node authority request already in flight for this principal"}
```

```json
{"code":"temporarily_unavailable","message":"runtime node authority is temporarily unavailable"}
```

```text
rotate_result_octets = 160
rotate_result_sha256 = sha256:aad4b26cb05aa5e180af128f60c312dfbb511395447762a3640d3ef8ddccd657
principal_request_in_flight_error_octets = 118
principal_request_in_flight_error_sha256 = sha256:eac5b2096359dfe57f9fe0a5ada932225eea73d6b6bf73e45c5a8211b8a1576a
temporarily_unavailable_error_octets = 96
temporarily_unavailable_error_sha256 = sha256:97cb00c37ff5a12fb38e8142d3497f6b3707f0cea88bbae1b2ccfaa322fd8b25
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
| machine authority | provisioner signature fixed vector；wrong deployment/key/path/body拒绝；typed principal携带deployment/ID/exact SPKI/digest；Store apply锁住并重验exact active lineage到domain/result commit；apply-first后retire、retire-first后401零写两个barrier顺序；local bundle key已retire时每个replica立即拒绝；DB outage下503且不读apply；static admin/service bearer、workspace token和A19 Node proof均拒绝 |
| WorkOS authority | Cookie/JWT/provisioner三形态互斥，duplicate/mixed统一401；每次apply/replay都online验current active admin-org membership + exact `cats:fleet:admin`；role slug、token/session stale permission不算；current deny为403，JWKS/WorkOS/API outage/timeout/rate-limit为503且零Store写 |
| route/trust bounds | query、encoded/trailing path、wrong method/media mapping；chunked/Content-Length实际65536进decoder、65537为413；success/error cap叉rotate/admin-error fixed vectors；trust bundle 16384边界、metadata/path/read-change fail startup；active-set/initial/overlap/principal fixed vectors；persisted deployment current-pointer/revision-receipt/lineage DDL check/unique/FK/projection corruption fail closed |
| trust revision/history | revision1 null-previous；old -> overlap old+new -> new-only使用连续revision/exact previous-set CAS；两个replica同revision exact replay零写；same revision不同set、old-only stale restart、gap、wrong previous和两个不同next-set竞态输家均fail startup且不能retire current key；已移除ID、已retire SPKI、same ID/different SPKI、different ID/same SPKI和deployment改名均fail；tombstone/revision receipt不GC/不重激活 |
| apply replay | response loss exact replay原200或persisted precondition 409；same apply ID异payload 409；new trust key可重放old-key apply；revision/credential CAS conflict零domain写入且保存rejected outcome |
| official CLI | machine fixed-vector headers且key octets不落argv/log/state、same pending可换current key重签；human admin-only与同时拥有ordinary Workspace两种identity都只取独立admin-org session，runtime/admin login拒绝Workspace selector；等价`https://CONTROL.example`/`https://control.example:443/`、不同`CATS_CONFIG_DIR`的两个真实进程共用canonical account/lock并只refresh一次，后者重读rotated token，不同port origin隔离；legacy raw account逐byte迁移可重入且conflict fail closed；root rename/recreate和lock unlink/recreate的两进程barrier均使旧holder在credential/network前失败；pending在首send前逐级ancestor/record fsync；canonical bound 200和带exact单一apply-ID header的persisted precondition 409才先durably写resolution/index再清pending；A→B→A、不同exact apply ID、不同normalized origin和root/ancestor ABA均零错误重发；409 header缺失/重复/错值、EOF/reset/timeout/redirect/401/403/429/5xx/apply conflict/超限或mismatched 200都保留same body/apply ID；apply conflict报警不换ID；crash每个fsync窗口都不重新结算；未实现durable backend的平台仍编译普通/admin CLI并在任何Runtime Node I/O前fail closed |
| admission/shutdown | global 32、每principal 4恰好边界；无等待，global满503/per-principal满429且Retry-After 1、零apply；cancel在commit-send前回滚，之后permit留到resolution；shutdown拒绝新请求、join可能commit的job，30000 ms未解析只能非零退出 |
| Node credential lineage | exact现有`node_identities`表名；deferred circular/composite FK令current public-key ID/digest/state只指向同Node exact active/retired lineage；A19锁后join且只给retired exact-attempt replay例外；provision/rotation只接受PublicKey，ProviderPrincipal持久409；same/different Node历史ID/SPKI重用均持久409；partial/错state constraint注入整笔abort且不伪造result |
| A19a lifecycle | atomic identity+cordoned policy；cordoned/drained/expired-session rotation；pre-commit可保留old，commit后只能forward-complete new；old永久retired无reverse CAS；new half丢失只能retire/new lineage；crash windows只重放same apply/private half |
| policy mutation | cordon与create两种lock先后各自线性；有assigned set时不能改capacity/capability/CIDR；uncordon不能夹带静态变化 |
| lock DAG | registration/Desired read/observation/policy/create都是NodeIdentity -> credential lineage -> AgentSession -> receive/cursor（不涉及lineage的路径跳过）；observation与create、observation与policy各跑两种先提交顺序；placement/shape不变的target/route/volume-intent/disk/disposition/require-idle revision与create也跑双向barrier，只能看到完整old/new或fresh retry；无Desired -> NodeIdentity反序/deadlock，连续serialization retry都从fresh DB now开始 |
| pages/replicas | 0、1、64、65和超过1024 Node；keyset无漏重；一个snapshot/DB now；两个Control replica稳定选同一最小eligible node；无fleet cap |
| capacity/count | lifecycle各态都计完整shape；equality fit、超1拒绝；vCPU/memory分别边界；checked sum/add/sub/count overflow fatal；count 1023->1024成功、1024->1025在plan和commit均零business/result；stored 1025使replica unready；不读heartbeat/legacy node capacity |
| post-mutation plan | same-node resize只评估current node、精确`total-old+new`且保留network；planned migration/takeover/retry从source删、target加并fresh network/revision/epoch；current revision/digest/placement/old shape/network任一变化就stale；两replica resize/move只一个CAS胜出；纯remove也锁source NodeIdentity |
| source/fence | exclusion只由server从current source派生且source不能当move target；任何Active event target都拒绝；plan后event create/rejoin在NodeIdentity锁下重验；non-takeover要求source无Active，takeover要求exact Active event/lineage；错/null event零Desired/result |
| simultaneous create | 同Node剩余恰好一份capacity或一个assigned-set slot时只有一个commit；不同idempotency key不超卖；同key只一组identity/result；无reservation row |
| network hash/probe | fixed vector；slot0永不用；首slot collision、连续collision、16383->1 wrap；full 16383 exhaustion；duplicate/malformed assigned config fatal |
| reuse/migration | Desired移除但旧full inventory/tap residue仍拒绝；new full absence后可复用；跨Node或CIDR变化fresh network ID/config/revision；MAC只由selected slot导出 |
| stale plan | plan后cordon、policy revision、session replacement、freshness、assigned set/count、current CAS、event、capacity或slot任一变化都零business/result并503；unchanged plan commit |
| order/cancel | idempotency hit在image/policy前；name 409不消费plan；commit前cancel零写；commit/response不明只同key replay |
| Node rollout | exact Desired network进入tap/CH；任一字段不等拒绝；删除FNV/cat-ID derivation、`--ch-network-cidr`和fallback；mixed release保持cordoned |
| calibrated negative | 对legacy `nodes` capacity、heartbeat CPU/RAM、env/fixture schedulable、FNV和`ch-network-cidr`的negative grep先以当前legacy positive校准，再在A23 production path证明零read |
