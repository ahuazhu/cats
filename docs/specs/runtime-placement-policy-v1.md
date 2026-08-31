# Runtime Node Authority and Placement Policy v1

- 状态：当前已实现的独立 Node identity/policy authority
- 决策：[ADR-0043](../decisions/0043-provisioner-owned-runtime-placement-policy.md)、
  [ADR-0061](../decisions/0061-semantic-least-allocated-placement.md)
- 运维工具：[A23 Production Provisioner Tooling v1](a23-production-provisioner-tooling-v1.md)
- 当前生命周期：[ADR-0059](../decisions/0059-semantic-control-node-synchronous-protocol.md)

本文只定义仍由 `runtime_node_authority` 实现的 Node identity、静态 policy、provisioner trust 和
apply/replay 边界。ADR-0059 的 Cat 生命周期不读取本合同来选择 Node；当前 Cat create、Cold run、失联恢复按
ADR-0061 从 `nodes.status='running'` 和 Cat 当前资源行计算 least-allocated placement。这里的
`schedulable`、`allocatable_*` 和 capability 不是当前 scheduler 的 capacity admission，也不能替代 Node
注册、heartbeat 或实际效果检查。

旧 Desired、AgentSession、完整 inventory、Route、ObjectWrite writer authority、HostFence provider queue、
per-Cat placement plan 和 `/30` 分配不属于当前合同。Git history 保留那些已取代的设计。

## 1. Closed wire

所有对象使用 Cats canonical JSON，拒绝 duplicate/unknown field、非 canonical integer/string、错误版本和超限
body。核心记录为：

```text
NodeIdentity {
  version: 1,
  node_id: Id,
  provider_scope: { provider, partition, account_id, region },
  immutable_host_id: Id,
  credential_id: Id,
  credential_binding: { kind: "public_key", public_key_spki_sha256 },
  state_path_id: Id,
  state: "provisioned" | "retired"
}

NodePlacementPolicy {
  version: 1,
  node_id: Id,
  policy_revision: Epoch,
  scheduling_state: "cordoned" | "schedulable",
  allocatable_vcpus: 1..=4294967295,
  allocatable_memory_bytes: 1..=9223372036854775807,
  capabilities: {
    vmm: "cloud_hypervisor",
    block_frontend: "kernel_nbd" | "vhost_user_blk",
    guest_network: "isolated_ipv4",
    guest_transport: "vsock",
    guest_agent_protocol_version: 1,
    guest_config_digest: Sha256Digest
  },
  guest_ipv4_pool: {
    kind: "private_ipv4_16",
    network_address: Ipv4Address,
    prefix_length: 16
  }
}
```

IPv4 pool 必须是对齐的 RFC 1918 `/16`。它是保留的 Host-local 静态配置，不表示已经实现跨 Node overlay 或
当前 semantic scheduler 的地址分配。

API 类型仍能解码通用 `CredentialBinding::ProviderPrincipal`，但本 authority 的 provision/rotation 只接受
canonical Ed25519 public-key binding；provider principal 会得到持久的 precondition failure。

## 2. 唯一 apply route

所有变更走：

```text
POST /v1/admin/runtime/node-authority-applies
Content-Type: application/json

RuntimeNodeAuthorityApply {
  version: 1,
  apply_id: RandomId128,
  node_id: Id,
  mutation:
    { kind: "provision", node_identity, placement_policy }
  | { kind: "update_policy", expected_policy_revision, placement_policy }
  | { kind: "rotate_credential", expected_policy_revision,
      expected_credential_id, expected_credential_binding,
      new_credential_id, new_credential_binding }
  | { kind: "retire", expected_policy_revision,
      expected_credential_id, expected_credential_binding }
}

RuntimeNodeAuthorityApplyResult {
  version: 1,
  apply_id: RandomId128,
  node_id: Id,
  outcome: "provisioned" | "policy_updated" | "credential_rotated" | "retired",
  identity_state: "provisioned" | "retired",
  policy_revision: Epoch
}
```

request 上限 65536 octets，success 上限 16384 octets，error 上限 20480 octets。query、redirect、错误 method、
错误或带参数的 content type、压缩 body、混合认证 envelope 全部拒绝。

## 3. Mutation invariants

### 3.1 Provision

`provision` 在同一事务创建一条 `NodeIdentity` 和一条 revision-1、`cordoned` policy。所有重复的
`node_id` 必须相等；同一 provider scope + immutable Host 只能有一个 provisioned identity，同一
`immutable_host_id + state_path_id` 不能被另一 identity 复用。credential ID 和 SPKI digest 在历史 lineage
中都不能复用。initial identity 必须使用 public-key binding，`state_path_id` 不能是 `.` 或 `..`。

### 3.2 Policy update

`expected_policy_revision` 必须等于 current，new revision 必须为 checked `current + 1`，且至少一个字段变化。
只改变 `cordoned/schedulable` 可以直接 CAS。若 vCPU、memory、capability 或 IPv4 pool 任一静态字段变化，old
和 new policy 都必须为 `cordoned`，并且该 Node 不能仍有非 destroyed、非稳定 Cold 的 Cat 或进行中的 Cat
动作。policy 是独立运维 authority；当前 ADR-0061 scheduler 尚不消费这些静态容量字段。

### 3.3 Credential rotation and retirement

rotation/retire 要求 exact policy revision、exact current credential ID/binding、policy `cordoned`，并满足与
静态 policy 变化相同的 runtime quiescence。rotation 的 new credential ID 和 SPKI digest 必须历史未见；旧
lineage 单向变为 retired，不能重新激活。retire 将 identity 单向变为 `retired`，不删除最后 policy 或历史
apply result。

任何合法解码但不满足上述 authority 条件的请求都持久化
`authority_precondition_failed`，而不是部分写入或猜测 adoption。

## 4. Authentication, trust and replay

machine caller 使用 startup 固定的 `RuntimeProvisionerTrustBundle`：revision 1 要求
`expected_previous=null`；后续 revision 必须是 exact current+1，并绑定前一 active-set digest。credential
ID、canonical Ed25519 SPKI 和其 digest 都有全历史 lineage；被移除的 credential 永不复用。

请求恰好携带 `Cats-Provisioner-Credential-Id` 和 `Cats-Provisioner-Signature`。Ed25519 frame 绑定固定
domain、method、path、`application/json`、deployment ID、credential ID、exact body length 和 body SHA-256。
Store 在提交 apply 的同一事务再次验证该 machine principal 仍是 current active lineage。独立 WorkOS fleet
administrator 是另一种互斥 principal；普通 service/admin bearer、Workspace token 和 Node proof 不是 machine
provisioner authentication。

`apply_id` 是持久 exact replay key：

- 相同 ID + 相同 canonical request 返回原 stored success 或 precondition failure；
- 相同 ID + 不同 request 返回 `apply_id_conflict`，不换 ID、不写 domain row；
- response loss 只能重放同一 body/apply ID；
- success 的 `apply_id`、`node_id`、outcome、identity state 和 policy revision 必须与 mutation 精确绑定。

官方 CLI 的 durable pending/resolution、key filesystem transaction 和首次 activation 细节见 A23；CLI 不直连
PostgreSQL，也不提供 ObjectWrite/Route/HostFence authority 子命令。

## 5. Persistence and verification

v19 空库只保留：

- `node_identities` 与 `runtime_node_credential_lineage`；
- `runtime_node_placement_policies`；
- `runtime_node_authority_apply_records`；
- `runtime_provisioner_deployment_identity`、trust revision 与 credential lineage。

canonical record 与查询 projection 必须逐字段一致；缺行、partial projection、非法 enum/digest/revision 或历史
lineage 冲突是 stored corruption，Control fail closed。固定 canonical JSON、signature、trust rotation、apply
replay、HTTP envelope 和 PostgreSQL CAS 的可执行 oracle 分别位于 API fixed-vector tests、
`runtime_node_authority_http` 与 Store tests；规格不复制滚动 hash 表。
