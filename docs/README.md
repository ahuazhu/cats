# Cats 文档索引

HTML 面向人类阅读和视觉演示；同名 Markdown 面向 Agent/实现者，包含可检索正文、Mermaid 图、明确状态和本地证据链接。实验总报告原生为 Markdown。

## 规格（实现的直接依据）

| 文档 | 状态 | 对应实现 |
|---|---|---|
| [blockd 协议规格](specs/blockd-protocol.md) | Frozen v1 | `blockd/`（常量出处 `api/src/chunk.rs`）；改动需新增 ADR |
| [Guest Runtime API v1](specs/guest-runtime-api.md) | Frozen v1 | `guest/` 的 `/run/cats/runtime.sock` HTTP 工作租约；依据 ADR-0007 |
| [Interactive Shell Protocol v1](specs/interactive-shell-protocol.md) | Implemented v1 | `cats shell` 的 WorkOS 鉴权 WebSocket、Node/Guest PTY 流；依据 ADR-0009 |

实现状态一览见根 [README](../README.md#实现状态)。真实 microVM（Cloud Hypervisor + KVM）已实现为 node-agent 的 `--vmm ch` 模式（`node-agent/src/ch.rs`），块路径 Phase A 经内核 NBD 复用已验前端，裸金属部署与验收见 [deploy/metal/](../deploy/metal/README.md)。共享 PostgreSQL root/lease 元数据 adapter 已实现；仍属后续里程碑：原生 vhost-user-blk（性能）、tap/overlay Guest 网络、控制面资源库 PostgreSQL/outbox 化、特权拆分。

Rust 工程质量现状、已修问题和后续优先项见 [Rust 工程实践审查](rust-engineering-review.md)。

## 公开用户文档

控制面会把无需登录的产品用户文档发布到 `/docs/`（英语）和 `/zh-CN/docs/`（简体中文）。
可索引 HTML 片段位于 `control-plane/ui/public/docs/<locale>/*.html`；每个页面都有同名
Markdown companion，便于 Agent 检索并满足 HTML/Markdown 同步维护约定。入口分别为：

- [English usage docs](../control-plane/ui/public/docs/en/index.md)
- [简体中文使用文档](../control-plane/ui/public/docs/zh-CN/index.md)

这些页面描述当前 Rust workspace 已实现的用户能力，并明确标注 native vhost-user-blk、
tap/overlay、Suspended page-out、控制面资源库 PostgreSQL 化与权限拆分等尚未完成项。跨组件事实仍以 ADR、
原始实验数据和本文档索引中的架构 Markdown 为更高优先级来源。

Fleet 管理员指南不属于官网用户文档。其双语源文件位于
`control-plane/ui/ops/docs/<locale>/index.{html,md}`，生产环境由 `ops.cats.run/docs/`
与 `ops.cats.run/zh-CN/docs/` 提供，并通过 `noindex` 与官网 sitemap 隔离。

如果同一设计的两种格式暂时不同，以 ADR 和实验数据为最高依据，随后以 Markdown 的实现约束为准，并尽快同步 HTML。

## 当前基线

| 文档 | 人类版 | Agent 版 | 状态 | 用途 |
|---|---|---|---|---|
| 完整产品与技术架构 | [HTML](cats-complete-product-technical-architecture.html) | [Markdown](cats-complete-product-technical-architecture.md) | 产品/系统基线 | 资源模型、CLI/API、控制面、Node、VM、网络、存储、安全、可靠性和交付阶段 |
| Direct-S3 ChunkStore（Direct-OS 实现）详细设计 | [HTML](direct-s3-chunkstore-architecture.html) | [Markdown](direct-s3-chunkstore-architecture.md) | 已选定存储基线（ADR-0003） | cats-blockd 的对象块存储：Chunk/Map、Pending Commit、FLUSH、lease/fencing、Snapshot、GC 与恢复 |
| 睡眠、唤醒与资源回收 | [HTML](cats-sleep-wake-vmm-resource-reclamation.html) | [Markdown](cats-sleep-wake-vmm-resource-reclamation.md) | 生命周期基线（ADR-0002 四态） | Running、Suspended（pause/page-out）、Warm（snapshot/VMM exit）、Cold 的资源与失败处理 |
| 工作驱动快速休眠 | — | [Markdown](cats-auto-tier-product-and-implementation-design.md) | V1 dev shape（ADR-0007 Guest ABI） | 显式工作租约、立即 Suspend、Guest Runtime HTTP、竞态栅栏与 fail-awake |
| 实验总报告 | — | [Markdown](experiments-2026-07-21-storage-lifecycle.md) | 实验证据 | 方法、代码、正式数字、失败尝试、结论和未验证事项 |

## 历史方案与外部参考

| 文档 | 人类版 | Agent 版 | 状态 | 用途 |
|---|---|---|---|---|
| 存储架构设计（JuiceFS raw 方案） | [HTML](cats-storage-product-blueprint.html) | [Markdown](cats-storage-product-blueprint.md) | 历史参考，未采用（ADR-0003） | RootDisk/PersistentDisk 产品语义的最初出处；JuiceFS-backed disk.raw 备选设计 |
| Sprite 小文件存储路径 | [HTML](sprite-storage-flow.html) | [Markdown](sprite-storage-flow.md) | 历史/竞品参考 | 解释小文件、ext4 逻辑块、Chunk 和对象存储之间的关系 |

`Sprite` 文档用于理解和比较，不代表 Cats 必须复刻其未公开实现。Direct-S3（Direct-OS 实现）已按 ADR-0003 选定为存储基线；当前 Python 原型只证明语义，不能代表生产性能。JuiceFS 蓝图不再实现，其中与后端无关的产品语义已并入完整架构文档。

## Architecture Decision Records

- [ADR-0001：Greenfield implementation baseline](decisions/0001-greenfield-implementation-baseline.md)
- [ADR-0002：生命周期四态 Running / Suspended / Warm / Cold](decisions/0002-lifecycle-states-running-suspended-warm-cold.md)
- [ADR-0003：存储后端选定 Direct-OS ChunkStore（Direct-S3 实现）](decisions/0003-direct-s3-chunkstore-backend.md)
- [ADR-0004：实现技术栈（全 Rust）与开发测试环境](decisions/0004-implementation-stack-and-dev-environment.md)
- [ADR-0005：云无关存储边界采用 Ports and Adapters](decisions/0005-provider-neutral-storage-ports-and-adapters.md)
- [ADR-0006：浏览器身份使用 WorkOS AuthKit](decisions/0006-workos-authkit-for-browser-identity.md)
- [ADR-0007：Guest Runtime API 使用 Unix Socket 上的 HTTP](decisions/0007-guest-runtime-http-over-unix-socket.md)
- [ADR-0008：CLI 使用 WorkOS Device Login 与多 Workspace 会话](decisions/0008-workos-device-login-and-cli-workspaces.md)
- [ADR-0009：交互式 Shell 使用受鉴权的 WebSocket PTY 流](decisions/0009-interactive-shell-over-authenticated-websocket.md)

后续发生会改变数据格式、公开 API、故障语义或组件边界的决定时，应新增 ADR，而不是直接覆盖实验结论。
