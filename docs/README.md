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

当前 Control/Node 生命周期协议由
[ADR-0059](decisions/0059-semantic-control-node-synchronous-protocol.md)及其
[ADR-0062 Destroy 修正](decisions/0062-destroy-preempts-in-progress-cat-actions.md)决定：Control 用资源当前行和
`current_action` 串行动作，transaction 外同步调用 noded；幂等来自 Workspace、slug、完整参数和目标
状态，不使用 request ID、Operation、Node poll/result 或 per-Cat journal。

当前实现包括：

- v19 Cat/Disk/Node 当前资源 schema、可复用 slug、Disk binding RWO、数据库时间 heartbeat 和当前入口目标；
- 同步 Cat/Disk API、CLI、Control lifecycle 和 noded HTTP client/server；
- 独立 Exec/Shell access lane：Workspace 鉴权后按需 run，再由 noded 绑定当前 Running 实例；
  离开 Running 或 reset 前关闭、取消并有界排空会话，不以 access response 结算生命周期；
- noded 按 Cat 串行、destroy 清理、Node registration/heartbeat/reset；Control 的管理接口先 cordon Node，
  再以可重试的 Cold-based drain 迁移其 Running/Suspended/Warm Cat；
- offline Node 的 level-triggered Cat 恢复，以及 `withdraw old -> Ready -> publish new`；
- `controld` 对普通 `current_action` 的单例超时恢复扫描，按 noded 实际状态收敛而不使用 heartbeat 结算；
- 真实 Control→noded HTTP 的 Cat 全状态机、重复调用、Destroy 抢占和双 Node offline/reset 测试；
  该测试使用内存 Store 与模拟 effects，入口见
  [`semantic_vertical_http.rs`](../node-agent/tests/semantic_vertical_http.rs)；
- 已接入 production composition 的 Strict PersistentDisk provision/delete backend，包括 volume/disk authority 和 BlobStore delete postcondition；
- Cloud Hypervisor 实际执行、RootDisk/PersistentDisk attach、精确文件系统身份、Guest mount-ready、
  Suspend/Warm/Cold/Destroy 和 Node reset，实现在
  [`semantic_installed.rs`](../node-agent/src/semantic_installed.rs)；物理验收入口见
  [metal runbook](../deploy/metal/README.md#verification-boundary)；
- production Control 只挂载 semantic resource/Node 主监听，旧 lifecycle Operation、AgentSession、
  observation settlement 和 Route Operation 不再进入生产 composition；
- 独立 `runtime_node_authority` 管理入口继续组成，但不承担 Cat lifecycle authority。

当前产品生命周期只使用 Strict；底层引擎保留 Relaxed `R < L` 能力，不代表产品支持仅本地持久的
成功 FLUSH。数据合同见 [storage.md](storage.md)。

仍开放或不属于当前产品保证的边界：

- product DiskSnapshot 的同盘 restore 与 GC root 保护闭环；这与 Host-local WarmRuntimeSnapshot 不同；
- 自动 cloud/BMC Host fencing、长期不对称网络、真实 RDS failover 资格、跨 Node Guest overlay 与权限隔离；
- 公网 Gateway/稳定 HTTPS Endpoint 不在当前 semantic production composition 中；当前入口目标表
  只提供 `withdraw -> Ready -> publish` 的协调边界，不能据此声称公网服务已接通；
- Guest-local HTTP/lease 原语仍存在，但当前 lifecycle 不承诺自动休眠或 lease keep-awake 的完整组合。

每个后续交付须在自身精确提交上重跑 full、Linux 和适用的 production qualification，不能复用旧发布
候选的通过结果。分层门禁见 [Operations and HA §9](operations-ha.md#9-分层-qualification)。

各模块的当前实现边界由代码、校准测试和对应的现行合同共同决定；Git history 保存切换实施记录。

## Active architecture

| 文档 | 状态 | 用途 |
|---|---|---|
| [architecture.md](architecture.md) | Target + current boundary | 系统总图、当前 authority、实现差距和上线门 |
| [Control/Node semantic protocol](control-node-semantic-protocol.md) | Current implemented protocol | 当前同步 wire、状态机、场景语义、Node reset |
| [runtime-lifecycle.md](runtime-lifecycle.md) | Current product contract | 四态、failure/destroy、动作和入口/数据屏障 |
| [storage.md](storage.md) | Implemented core + explicit gaps | ChunkStore 格式、FLUSH、R/L、owner/epoch、GC |
| [operations-ha.md](operations-ha.md) | Current operations contract | heartbeat/offline/reset、故障域、qualification、clean-slate deploy |
| [实验总报告](experiments-2026-07-21-storage-lifecycle.md) | Evidence | 记录环境、样本、结果和失败尝试 |

## Protocol/spec status

| 规格 | 状态 | 当前用途 |
|---|---|---|
| [Control/Node semantic protocol](control-node-semantic-protocol.md) | Current implemented protocol | Cat/Disk/Node 同步协议和验收 |
| [blockd protocol](specs/blockd-protocol.md) | Implemented data plane | Chunk/Map/FLUSH；生命周期只使用远端持久模式 |
| [Guest Runtime API](specs/guest-runtime-api.md) | Frozen v1 primitives | Guest-local `/run/cats/runtime.sock` HTTP/lease 原语；自动休眠组合见上面的开放边界 |
| [Exec/Shell](specs/interactive-shell-protocol.md) | Semantic composition implemented | Bearer 鉴权、按需 run、Node access gate；有界 Exec 与 WebSocket PTY，物理资格另验 |
| [Volume Authority](specs/volume-authority.md) | Current v19 storage contract | direct acquire/renew/release/delete、owner/epoch、remote root 和 blockd serving admission |
| [Runtime Placement Policy v1](specs/runtime-placement-policy-v1.md) | Fleet policy foundation retained | 独立 provisioner-owned capacity/policy；不充当 Cat action authority |
| [A23 Provisioner Tooling v1](specs/a23-production-provisioner-tooling-v1.md) | Operations foundation retained | 独立 `runtime_node_authority` 配置入口 |
| [Immutable Image Manifest Read v1](specs/immutable-image-manifest-read-v1.md) | Storage/boot contract | immutable image manifest 读取；默认 Boot Image 的部署绑定见 ADR-0063 |

已取代的协议规格由 Git history 保存；当前文档不得把 lifecycle Operation、poll/result、journal、AgentSession、
Route v2 或 HostFenceRecovery 协调作为目标合同引用。

## Active decisions

### 当前协调决策

- [0059 Control/Node 场景语义同步协议](decisions/0059-semantic-control-node-synchronous-protocol.md)
- [0065 Exec/Shell Runtime Access Lane](decisions/0065-exec-shell-runtime-access-lane.md)
- [0064 Cat 动作时钟与运行时钟](decisions/0064-cat-run-and-action-clocks.md)
- [0063 Control-owned 默认 Boot Image](decisions/0063-control-owned-default-boot-image.md)
- [0062 Destroy 抢占进行中的 Cat 动作](decisions/0062-destroy-preempts-in-progress-cat-actions.md)
- [0061 场景语义 Least-Allocated Placement](decisions/0061-semantic-least-allocated-placement.md)
- [0062 Level-Triggered Planned Node Drain](decisions/0062-level-triggered-planned-node-drain.md)
- [0063 语义协议下的 Cat 用量计量](decisions/0063-semantic-node-usage-metering.md)
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
- [0025 disposable Root destroy](decisions/0025-destroy-disposable-root-without-remote-drain.md)：
  local-tail discard authorization 已由 ADR-0059 的 Strict direct delete 取代。

### 存储、身份和产品边界

- [0003 Direct-OS ChunkStore](decisions/0003-direct-s3-chunkstore-backend.md)
- [0005 Storage Ports and Adapters](decisions/0005-provider-neutral-storage-ports-and-adapters.md)
- [0015 vhost-user-blk](decisions/0015-vhost-user-blk-production-block-frontend.md)
- [0016 delta packs](decisions/0016-delta-pack-page-granular-commits.md)
- [0017 golden roots](decisions/0017-golden-root-shared-base-images.md)
- [0021 Relaxed durability](decisions/0021-relaxed-durability-tier.md)
- [0022 dual watermark](decisions/0022-relaxed-local-first-dual-watermark.md)
- [0042 Volume Authority 与磁盘生命周期](decisions/0042-volume-authority-and-disk-lifecycle.md)
- [0018 Workspace 唯一 owner](decisions/0018-remove-the-v1-project-compatibility-layer.md)
- [0006 WorkOS AuthKit](decisions/0006-workos-authkit-for-browser-identity.md)
- [0007 Guest Runtime HTTP/Unix socket](decisions/0007-guest-runtime-http-over-unix-socket.md)
- [0008 CLI Device Login](decisions/0008-workos-device-login-and-cli-workspaces.md)
- [0010 默认 HTTP Endpoint](decisions/0010-default-http-endpoint-per-cat.md)

### 其他保留决策索引

- [0066 API、协议与安装制品 crate 边界](decisions/0066-api-protocol-artifact-crate-boundaries.md)
- [0004 Rust 技术栈](decisions/0004-implementation-stack-and-dev-environment.md)
- [0009 Interactive Shell](decisions/0009-interactive-shell-over-authenticated-websocket.md)（由 ADR-0065
  接入当前 semantic Control/Node）
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
- [0061 Node 本地 Golden Root 加速空 RootDisk provision](decisions/0061-node-local-golden-root-provision-validation.md)
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

同步协议切换后的历史验收另见
[Git 中归档的完成记录](https://github.com/ahuazhu/cats/blob/c8cf9d6bcf4ed73264a58d3d962c7f2cd4faeb23/docs/semantic-control-node-implementation-plan.md)：
`5cc9723e` 对应的 kernel-NBD/Cloud Hypervisor/Guest 环境记录了 PersistentDisk mount-ready、Cold
重挂和双 Node 恢复/reset；候选 `7d03e879` 记录了本机与 production x86_64 native full 通过及
immutable receipt。这些历史结果不替代当前提交的资格门，也不外推到 vhost-user 或生产 HA。

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
