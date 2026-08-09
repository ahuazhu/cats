# Cats 文档索引

这里是工程文档的唯一入口。架构和协议只维护 Markdown；不再维护一套容易漂移的静态
HTML companion。公开产品文档仍由 `control-plane/ui/` 独立维护双语 HTML/Markdown。

## 先读什么

1. [技术架构](architecture.md)：大目标、组件、唯一权威、故障边界和实施路线。
2. [Runtime 生命周期](runtime-lifecycle.md)：Running/Suspended/Warm/Cold、route/data屏障。
3. [存储架构](storage.md)：当前 Rust ChunkStore、Strict/Relaxed、fencing和恢复边界。
4. 与任务相关的 accepted ADR 和 `docs/specs/` 合同。
5. 需要引用数字时再读[实验总报告](experiments-2026-07-21-storage-lifecycle.md)及其原始证据。

Agent注册的HTTP/proof/lease见
[Agent Registration and Internal Transport v1](specs/agent-registration-transport-v1.md)；Node本地identity
artifact与单一Guest release payload见
[Runtime Composition Artifacts v1](specs/runtime-composition-artifacts-v1.md)。

## 当前实现与目标

决策状态和实现状态是两回事。2026-08-08 的准确边界：

| 范围 | 当前 Rust/部署 | 已接受目标 |
|---|---|---|
| 存储 | ChunkStore、delta pack、golden root、NBD/vhost-user、S3/PostgreSQL adapters 已实现并测试 | ADR-0042条件lease、attachment lineage、Cold-only磁盘生命周期、Snapshot/GC |
| 生命周期协调 | V1 `desired/observed/generation -> NodeJob`，heartbeat直接回写状态 | ADR-0040完整 DesiredSpec +有界checkpoint + observation-only |
| Route | v1 Ed25519 Grant和DynamoDB mirror已实现，Node没有独立 installed/retired gate | ADR-0041 v2 incarnation/per-Endpoint serving epoch + AdmissionCell；删除shared mirror |
| Agent restart | full JSON ledger/adoption局部存在；无 Host lock，生产 unit仍可能连带终止 runtime | per-Cat scopes、union inventory、crash-safe checkpoint后才具备接管 |
| 控制面 HA | PostgreSQL、多副本、RDS Proxy/leadership已实现；当前Store同步串行慢DB调用 | AgentSession、异步有界DB执行、真实Pod takeover、RDS failover和Host fence |
| PersistentDisk | raw virtio attach和`mount_path`存在，没有fs UUID/format/mounted result | ext4-only mount readiness闭环 |
| 网络 | per-Cat tap与owning-node HTTP/WebSocket dev路径 | 跨Node overlay和真实CH/生产WebSocket资格证据 |
| privilege | 进程权限仍较集中 | privilege separation尚未实现 |

协调面按 [Operations and HA §8](operations-ha.md#8-首次终态部署)一次 clean-slate 切换：离线验证
exact release，维护窗口内退出旧组件并清空产品状态，轮换 credentials，再启动唯一的空目标 schema
和协议。当前代码仍是 V1。

当前协调面的上线阻断风险已写入ADR-0040和目标规格：attach模糊响应、revision ABA、
conditional lease takeover、AgentSession、checkpoint crash窗口、ext4 mount readiness和
AdmissionCell。它们由同一个vertical cutover合同和故障矩阵收敛。

## Active architecture

| 文档 | 状态 | 用途 |
|---|---|---|
| [architecture.md](architecture.md) | Target + current boundary | 系统总图、authority matrix、HA合同和路线 |
| [runtime-lifecycle.md](runtime-lifecycle.md) | Product contract | 四态、work/admission、数据屏障、Host loss |
| [storage.md](storage.md) | Implemented core + explicit gaps | ChunkStore格式、FLUSH、L/R、lease/fencing、GC |
| [operations-ha.md](operations-ha.md) | Target operations contract | failure domain、有界DB、Host fence/rejoin、分层qualification |
| [architecture-cross-review.md](architecture-cross-review.md) | Frozen review evidence | 三边界交叉复核、阻断项关闭与接口oracle |
| [实验总报告](experiments-2026-07-21-storage-lifecycle.md) | Evidence | 2026-07-21方法、样本、结果和失败尝试 |

## Active specs

| 规格 | 状态 | 实现 |
|---|---|---|
| [blockd protocol](specs/blockd-protocol.md) | Implemented data plane + target Volume Authority | Chunk/Map/FLUSH已实现；pack v2/grant adoption未实现 |
| [Guest Runtime API](specs/guest-runtime-api.md) | Frozen v1 | `/run/cats/runtime.sock`、work lease |
| [Interactive Shell](specs/interactive-shell-protocol.md) | Implemented v1 | WorkOS鉴权 WebSocket PTY |
| [Runtime Reconciliation v1](specs/runtime-reconciliation-v1.md) | Target，未实现 | ADR-0040切换合同 |
| [Agent Registration and Internal Transport v1](specs/agent-registration-transport-v1.md) | Frozen target，未实现 | per-Node签名、注册wire、lease与Guest receipt部署路径 |
| [Runtime Inventory and Observation Spine v1](specs/runtime-inventory-observation-v1.md) | Frozen target，未实现 | Desired read-position、inventory/observation接受与freshness |
| [Runtime Composition Artifacts v1](specs/runtime-composition-artifacts-v1.md) | Frozen target，未实现 | local NodeIdentity artifact与单一Guest release payload |
| [Route Grant v2](specs/route-grant-v2.md) | Target，未实现 | ADR-0041切换合同；固定向量待实现时重建 |
| [Volume Authority](specs/volume-authority.md) | Target，未实现 | ADR-0042卷、attachment、ext4、snapshot和delete合同 |

协议状态必须明确写 `Implemented/Frozen` 或 `Target, not implemented`。不存在“文档写了就算
代码存在”。

## Active decisions

### 基础与资源边界

- [0001 Greenfield baseline](decisions/0001-greenfield-implementation-baseline.md)
- [0002 四态生命周期](decisions/0002-lifecycle-states-running-suspended-warm-cold.md)
- [0003 Direct-OS ChunkStore](decisions/0003-direct-s3-chunkstore-backend.md)
- [0004 Rust 技术栈](decisions/0004-implementation-stack-and-dev-environment.md)
- [0005 Storage Ports and Adapters](decisions/0005-provider-neutral-storage-ports-and-adapters.md)
- [0018 Workspace 唯一 owner](decisions/0018-remove-the-v1-project-compatibility-layer.md)

### 身份、入口和产品 API

- [0006 WorkOS AuthKit](decisions/0006-workos-authkit-for-browser-identity.md)
- [0007 Guest Runtime HTTP/Unix socket](decisions/0007-guest-runtime-http-over-unix-socket.md)
- [0008 CLI Device Login](decisions/0008-workos-device-login-and-cli-workspaces.md)
- [0009 Interactive Shell](decisions/0009-interactive-shell-over-authenticated-websocket.md)
- [0010 默认 HTTP Endpoint](decisions/0010-default-http-endpoint-per-cat.md)
- [0014 Account/Workspace/Billing](decisions/0014-account-workspace-identity-billing-and-switching.md)
- [0019 Cat absolute expiry](decisions/0019-absolute-cat-expiry.md)
- [0023 systemd Guest PID 1](decisions/0023-systemd-as-the-default-guest-init.md)
- [0024 digest-pinned OCI bundle](decisions/0024-digest-pinned-oci-bundle-deploy.md)
- [0026 OCI deploy outlives request](decisions/0026-oci-deploy-outlives-its-request.md)

### 存储、数据与计费

- [0011 累计 usage ledger](decisions/0011-cumulative-usage-metering-and-billing-ledger.md)
- [0012 Terraform AWS](decisions/0012-terraform-managed-aws-resources-and-deployments.md)
- [0013 prepaid credit/Stripe](decisions/0013-prepaid-credit-ledger-and-stripe-checkout.md)
- [0015 vhost-user-blk](decisions/0015-vhost-user-blk-production-block-frontend.md)
- [0016 delta packs](decisions/0016-delta-pack-page-granular-commits.md)
- [0017 golden roots](decisions/0017-golden-root-shared-base-images.md)
- [0021 Relaxed durability](decisions/0021-relaxed-durability-tier.md)
- [0022 dual watermark](decisions/0022-relaxed-local-first-dual-watermark.md)
- [0042 Volume Authority与磁盘生命周期](decisions/0042-volume-authority-and-disk-lifecycle.md)
- [0025 disposable Root destroy](decisions/0025-destroy-disposable-root-without-remote-drain.md)
- [0029 database password authority](decisions/0029-one-authority-for-the-database-password.md)
- [0034 RDS Proxy](decisions/0034-bound-postgresql-connections-with-rds-proxy.md)

### 协调与高可用

- [0031 PostgreSQL control store](decisions/0031-control-store-on-postgresql.md)
- [0032 control-plane multi-replica](decisions/0032-control-plane-multi-replica-and-postgresql-leadership.md)
- [0038 production cell qualification](decisions/0038-production-account-qualification-cell-boundary.md)
- [0040 level-triggered runtime reconciliation](decisions/0040-level-triggered-runtime-reconciliation.md)
- [0041 Node-verified route admission](decisions/0041-node-verified-route-admission.md)

### Deferred

- [0020 S3 Express One Zone hot commits](decisions/0020-s3-express-one-zone-hot-commits.md)：
  不属于当前实现路线；需要新的成本/可用性证据才重新评估。

## Evidence

实验源码、正式 CSV、环境报告、原始日志和失败 crash evidence保留在 `experiments/`，入口见
[`experiments/README.md`](../experiments/README.md)。主要已知证据包括：

- Cloud Hypervisor + KVM bare-metal生命周期验收；
- kernel-NBD/vhost-user-blk同场对照；
- 双节点真实 S3 + RDS 的 Cold migration；
- delta/golden root、Relaxed local-first、fencing和crash injection。

这些证据证明各自记录的样本和 oracle，不自动证明控制面 HA、真实 RDS failover、自动
Host fencing、Snapshot/GC安全或生产 SLA。引用数字时必须保留环境、样本量、测量边界和
correctness oracle。

## Source of truth

冲突时按以下顺序：

1. Accepted且未被 supersede的 ADR；
2. Frozen/implemented spec；对尚未实现的切换则以 target spec为目标合同；
3. 当前 Rust/SQL和可重复测试决定“现在实际做什么”；
4. 原始实验数据决定测量事实；
5. `architecture.md`/专题文档用于组合上述边界。

文档不能覆盖代码事实，也不能把 prototype结果写成生产承诺。

## 维护规则

- 一个事实只在一个 authority文档展开；其他位置用链接，不复制滚动状态和 benchmark表。
- 改公开 API、persisted format、Guest ABI、故障语义或组件 authority必须新增 ADR。
- Superseded ADR留短 tombstone；未实现且被否决的 spec直接删除，Git就是 archive。
- architecture Markdown不再生成/手工维护 static HTML。
- 实验源码、CSV、环境报告、原始日志和失败 evidence不得因结论变化而删除。
- 任何实现变更仍执行 `./scripts/quality.sh fast`，handoff前执行 `./scripts/quality.sh full`；
  Linux-only block/Node代码以现有native x86_64 build host的exact-SHA `full`为最终门，本机无该
  Host时用`./scripts/quality.sh linux`做Docker兼容检查。
