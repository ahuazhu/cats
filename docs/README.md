# Cats 文档索引

这里是工程文档的唯一入口。架构和协议只维护 Markdown；公开产品文档由
`control-plane/ui/` 单独维护。

## 先读什么

1. [技术架构](architecture.md)：组件、当前 authority、实现边界和数据安全边界。
2. [Control Plane 与 noded 同步协议设计](control-node-semantic-protocol.md)：当前 Cat/Disk/Node
   数据模型、同步 wire、场景语义幂等和失联 reset。
3. [Runtime 生命周期](runtime-lifecycle.md)：Running/Suspended/Warm/Cold、failure/destroy 和入口/数据屏障。
4. [存储架构](storage.md)：ChunkStore、Strict/Relaxed、owner/epoch、fencing 和恢复边界。
5. [Operations and HA](operations-ha.md)：运行拓扑、heartbeat/offline/reset、分层 qualification 和空数据部署。
6. 与任务相关且未被 supersede 的 ADR/spec；引用数字时再读
   [实验总报告](experiments-2026-07-21-storage-lifecycle.md)及其原始证据。

## 当前实现与目标

当前 Control/Node 生命周期唯一协议由
[ADR-0059](decisions/0059-semantic-control-node-synchronous-protocol.md)决定：Control 用资源当前行和
`current_action` 串行动作，transaction 外同步调用 noded；幂等来自 Workspace、slug、完整参数和目标
状态，不使用 request ID、Operation、Node poll/result 或 per-Cat journal。

当前分支已经组成：

- v19 Cat/Disk/Node 当前资源 schema、可复用 slug、Disk binding RWO、数据库时间 heartbeat 和当前入口目标；
- 同步 Cat/Disk API、CLI、Control lifecycle 和 noded HTTP client/server；
- noded 按 Cat 串行、destroy 清理、Node registration/heartbeat/reset/drain；
- offline Node 的 level-triggered Cat 恢复，以及 `withdraw old -> Ready -> publish new`；
- `controld` 对普通 `current_action` 的单例超时恢复扫描，按 noded 实际状态收敛而不使用 heartbeat 结算；
- 真实 Control→noded HTTP 的 Cat 全状态机和重复调用语义；
- 已接入 production composition 的 Strict PersistentDisk provision/delete backend，包括 volume/disk authority 和 BlobStore delete postcondition；
- production Control 只挂载 semantic resource/Node 主监听，旧 lifecycle Operation、AgentSession、
  observation settlement 和 Route Operation 不再进入生产 composition；
- 独立 `runtime_node_authority` 管理入口继续组成，但不承担 Cat lifecycle authority。

仍开放：

- 旧 Route v2 部署合同随新入口传输实现一起清理；
- PersistentDisk/Cloud Hypervisor 的 Guest 物理挂载链 E2E；
- Cloud Hypervisor 的完整 `SemanticCatEffects`；当前 bridge 缺少输入时在物理副作用前失败；
- 两 Node 双跑窗口/reset 收敛、Linux/Cloud Hypervisor 和最终全仓门禁。

详细滚动进度只维护在
[场景语义 Control/Node 协议实施计划](semantic-control-node-implementation-plan.md)，不要从本文推断
某项正在开发的物理路径已经完成。

## Active architecture

| 文档 | 状态 | 用途 |
|---|---|---|
| [architecture.md](architecture.md) | Target + current boundary | 系统总图、当前 authority、实现差距和上线门 |
| [Control/Node semantic protocol](control-node-semantic-protocol.md) | Accepted target, implementation in progress | 当前同步 wire、状态机、场景语义、Node reset |
| [runtime-lifecycle.md](runtime-lifecycle.md) | Current product contract | 四态、failure/destroy、动作和入口/数据屏障 |
| [storage.md](storage.md) | Implemented core + explicit gaps | ChunkStore 格式、FLUSH、R/L、owner/epoch、GC |
| [operations-ha.md](operations-ha.md) | Current operations contract | heartbeat/offline/reset、故障域、qualification、clean-slate deploy |
| [architecture-cross-review.md](architecture-cross-review.md) | Historical cross-review | ADR-0056 时期的证据复核；协议结论已被 ADR-0059 supersede |
| [实验总报告](experiments-2026-07-21-storage-lifecycle.md) | Evidence | 记录环境、样本、结果和失败尝试 |

## Protocol/spec status

| 规格 | 状态 | 当前用途 |
|---|---|---|
| [Control/Node semantic protocol](control-node-semantic-protocol.md) | Current accepted target | Cat/Disk/Node 同步协议和验收 |
| [blockd protocol](specs/blockd-protocol.md) | Implemented data plane | Chunk/Map/FLUSH；生命周期只使用远端持久模式 |
| [Guest Runtime API](specs/guest-runtime-api.md) | Frozen v1 | Guest-local `/run/cats/runtime.sock` 能力 |
| [Interactive Shell](specs/interactive-shell-protocol.md) | Implemented v1 | WorkOS 鉴权 WebSocket PTY |
| [Volume Authority](specs/volume-authority.md) | Storage authority retained; lifecycle composition sections superseded | owner/epoch/remote root 和数据安全；旧 Operation/AgentSession 接线不再是当前 wire |
| [Atomic Runtime Lifecycle v1](specs/atomic-runtime-lifecycle-v1.md) | Superseded by ADR-0059 | 历史 Operation/poll/journal 协议资料，不是当前目标 |
| [Runtime Reconciliation v1](specs/runtime-reconciliation-v1.md) | Superseded by ADR-0059 for lifecycle | 历史 Desired/AgentSession/inventory 协议；不进入当前 lifecycle |
| [Agent Registration and Internal Transport v1](specs/agent-registration-transport-v1.md) | Superseded for current Node registration | 历史 signed session/lease wire；当前使用 semantic register/heartbeat/reset |
| [Runtime Inventory and Telemetry v1](specs/runtime-inventory-observation-v1.md) | Superseded by ADR-0059 for Node lifecycle | 历史 session-bound inventory；当前 heartbeat/Node 查询不使用其 settlement |
| [Route Grant v2](specs/route-grant-v2.md) | Superseded for current Control/Node lifecycle composition | 历史 Route Operation/AgentSession lane；当前只要求唯一入口目标 |
| [Route v2 Signing Authority v1](specs/route-signing-authority-v1.md) | Historical, not in current semantic composition | 旧 signing/ring/ACK 路径 |
| [Runtime Placement Policy v1](specs/runtime-placement-policy-v1.md) | Fleet policy foundation retained | 独立 provisioner-owned capacity/policy；不充当 Cat action authority |
| [A23 Provisioner Tooling v1](specs/a23-production-provisioner-tooling-v1.md) | Operations foundation retained | 独立 `runtime_node_authority` 配置入口 |
| [Runtime Composition Artifacts v1](specs/runtime-composition-artifacts-v1.md) | Historical implementation reference | Node/Guest artifact 背景；不定义当前同步 lifecycle |
| [Immutable Image Manifest Read v1](specs/immutable-image-manifest-read-v1.md) | Storage/boot reference retained | 不表示当前 CH semantic effects 已接入 |
| [Old Host Positive Stop Evidence v1](specs/old-host-positive-stop-v1.md) | Historical proposed evidence | 不是 heartbeat/reset 或 Host fence authority |

旧 spec 保留用于说明历史实现和仍适用的底层安全事实。凡涉及 lifecycle Operation、poll/result、journal、
AgentSession 或 HostFenceRecovery 协调的段落，都由 ADR-0059 supersede；不得作为当前目标合同引用。

## Active decisions

### 当前协调决策

- [0059 Control/Node 场景语义同步协议](decisions/0059-semantic-control-node-synchronous-protocol.md)
- [0061 场景语义 Least-Allocated Placement](decisions/0061-semantic-least-allocated-placement.md)
- [0002 四态生命周期](decisions/0002-lifecycle-states-running-suspended-warm-cold.md)
- [0031 PostgreSQL control store](decisions/0031-control-store-on-postgresql.md)
- [0032 Control Plane 多副本](decisions/0032-control-plane-multi-replica-and-postgresql-leadership.md)
- [0038 Production cell qualification](decisions/0038-production-account-qualification-cell-boundary.md)

### 被 ADR-0059 取代的协调决策

- [0040 Level-triggered runtime reconciliation](decisions/0040-level-triggered-runtime-reconciliation.md)：
  lifecycle Desired/AgentSession/inventory 前置已取代；通用 Host/运维背景仅作历史参考。
- [0041 Node-verified route admission](decisions/0041-node-verified-route-admission.md)：
  当前只保留 ADR-0059 的唯一入口先撤后发边界。
- [0056 Atomic per-Cat runtime lifecycle](decisions/0056-atomic-per-cat-runtime-lifecycle.md)：
  Operation/poll/result/journal/typed predecessor/HostFenceRecovery 已取代。
- [0057 Product lifecycle actions](decisions/0057-product-lifecycle-actions-and-internal-execution-evidence.md)：
  六动作名称保留，Operation 投影已取代。
- [0058 Route ring ACK / AgentSession](decisions/0058-route-ring-acknowledges-immutable-agent-session.md)：
  AgentSession/Route ACK 协调已取代。

### 存储、身份和产品边界

- [0003 Direct-OS ChunkStore](decisions/0003-direct-s3-chunkstore-backend.md)
- [0005 Storage Ports and Adapters](decisions/0005-provider-neutral-storage-ports-and-adapters.md)
- [0015 vhost-user-blk](decisions/0015-vhost-user-blk-production-block-frontend.md)
- [0016 delta packs](decisions/0016-delta-pack-page-granular-commits.md)
- [0017 golden roots](decisions/0017-golden-root-shared-base-images.md)
- [0021 Relaxed durability](decisions/0021-relaxed-durability-tier.md)
- [0022 dual watermark](decisions/0022-relaxed-local-first-dual-watermark.md)
- [0025 disposable Root destroy](decisions/0025-destroy-disposable-root-without-remote-drain.md)
- [0042 Volume Authority 与磁盘生命周期](decisions/0042-volume-authority-and-disk-lifecycle.md)
- [0018 Workspace 唯一 owner](decisions/0018-remove-the-v1-project-compatibility-layer.md)
- [0006 WorkOS AuthKit](decisions/0006-workos-authkit-for-browser-identity.md)
- [0007 Guest Runtime HTTP/Unix socket](decisions/0007-guest-runtime-http-over-unix-socket.md)
- [0008 CLI Device Login](decisions/0008-workos-device-login-and-cli-workspaces.md)
- [0010 默认 HTTP Endpoint](decisions/0010-default-http-endpoint-per-cat.md)

### 其他保留决策索引

- [0004 Rust 技术栈](decisions/0004-implementation-stack-and-dev-environment.md)
- [0009 Interactive Shell](decisions/0009-interactive-shell-over-authenticated-websocket.md)
- [0011 累计 usage ledger](decisions/0011-cumulative-usage-metering-and-billing-ledger.md)
- [0012 Terraform AWS](decisions/0012-terraform-managed-aws-resources-and-deployments.md)
- [0013 Prepaid credit/Stripe](decisions/0013-prepaid-credit-ledger-and-stripe-checkout.md)
- [0014 Account/Workspace/Billing](decisions/0014-account-workspace-identity-billing-and-switching.md)
- [0019 Cat absolute expiry](decisions/0019-absolute-cat-expiry.md)
- [0023 systemd Guest PID 1](decisions/0023-systemd-as-the-default-guest-init.md)
- [0024 digest-pinned OCI bundle](decisions/0024-digest-pinned-oci-bundle-deploy.md)
- [0026 OCI deploy outlives request](decisions/0026-oci-deploy-outlives-its-request.md)
- [0029 Database password authority](decisions/0029-one-authority-for-the-database-password.md)
- [0034 RDS Proxy](decisions/0034-bound-postgresql-connections-with-rds-proxy.md)
- [0060 完整生产发布清单绑定独立 credential refresher](decisions/0060-complete-production-release-binds-credential-refresher.md)
- [0043 Provisioner-owned runtime placement policy](decisions/0043-provisioner-owned-runtime-placement-policy.md)
- [0044 独立 Route v2 signing authority](decisions/0044-independent-route-v2-signing-authority.md)（历史 Route 组成）
- [0045 独立 Gateway workload identity authority](decisions/0045-independent-gateway-workload-identity.md)（历史 Route 组成）
- [0046 Gateway 到 Node Route v2 machine tunnel](decisions/0046-gateway-node-route-v2-machine-tunnel.md)（历史 Route 组成）

## Evidence

实验源码、正式 CSV、环境报告、原始日志和失败 crash evidence 保留在 `experiments/`，入口见
[`experiments/README.md`](../experiments/README.md)。历史证据包括 Cloud Hypervisor/KVM 生命周期、
kernel-NBD/vhost-user-blk、真实 S3/RDS Cold migration、delta/golden root、Relaxed、fencing 和 crash
injection。

这些证据只证明各自记录的样本和 oracle，不自动证明 ADR-0059 的完整纵向组合、自动 Host fencing、
完整 PersistentDisk/Cloud Hypervisor 物理链、RDS failover 或生产 SLA。

## Source of truth

冲突时按以下顺序：

1. Accepted 且未被 supersede 的 ADR；
2. 当前协议/spec；尚未实现部分以明确标为 target 的合同为目标；
3. Rust/SQL 和可重复测试决定仓库现在做什么；
4. 原始实验数据决定测量事实；
5. 架构和专题文档组合这些边界，不能制造实现状态。

## 维护规则

- 一个事实只在一个 authority 文档展开；其他位置使用链接。
- 修改公开 API、persisted format、Guest ABI、故障语义或 component authority 必须新增 ADR。
- 旧目标 spec 若仍保留，必须在索引中明确标为 superseded，不能继续作为当前合同引用。
- 未实现且被否决的 spec 可以删除，Git 是 archive。
- 架构只维护 Markdown，不生成静态 HTML companion。
- 实验源码、CSV、环境报告、原始日志和失败 evidence 不因协议变化而删除。
