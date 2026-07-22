# ADR-0005：云无关存储边界采用 Ports and Adapters

- 状态：Accepted
- 日期：2026-07-21

## 背景

V1 已经定义 `BlobStore` 与 `MetadataStore` trait，但契约、File/SQLite 开发实现和
AWS S3 实现都位于 `cats-blockd` crate；控制面为了使用元数据契约反向依赖
`cats-blockd`，node-agent 与各进程 CLI 也直接暴露 S3/SQLite 参数。这使核心组件
知道具体云产品，违背 Cats 不绑定云厂商与云产品的目标。

“plugin”容易暗示运行时发现、动态链接 ABI 或第三方扩展 SDK；V1 并不需要这些
机制，因此不用它描述实现边界。

## 决定

1. 使用 **Ports and Adapters（端口与适配器）** 作为统一术语：
   - `cats-storage` 定义 provider-neutral ports（契约）：`BlobStore`、
     `MetadataStore`、错误语义、adapter factory 和选择配置。
   - `adapters/` 下的独立 crate 实现这些 ports；crate 名可包含厂商或产品名，但
     provider-specific SDK、协议、凭据和配置不得进入 `cats-storage` 或核心业务
     crate。
2. V1 静态链接已知 adapter，由每个进程的 composition root 通过通用
   `adapter name + key=value options` 选择；不建立动态库 ABI、运行时下载或代码
   注入机制。
3. 首批 adapter 为：
   - `object-store-file`：开发、测试与故障注入，不提供 Host-loss durability；
   - `metadata-store-sqlite`：单机开发替身，保持生产 CAS/lease 的 SQL 形状；
   - `object-store-aws-s3`：第一版 durable object-store adapter。
4. 核心依赖方向固定为 `control/data plane -> cats-storage ports`。daemon composition
   root 独立位于 `cmd/blockd`、`cmd/controld`、`cmd/noded`；只有这些 crate 和
   adapter crate 可以依赖具体实现。node-agent 只透传 opaque selection，
   `cats-blockd` 引擎只接收 trait object。
5. adapter options 只传非秘密配置。凭据通过 adapter 原生的 workload identity、
   环境或 secret handle 注入，不进入 NodeJob、Guest、日志或通用命令行选项。
6. 所有 adapter 必须满足同一语义契约，尤其是 immutable put、幂等 delete、
   durable FLUSH、generation/owner/epoch/expiry 原子 CAS 和 stale epoch fail-closed。
   换 adapter 不得改变 Guest 的 virtio block/ext4 接口、磁盘格式或生命周期语义。

## 与既有决定的关系

- ADR-0003 仍决定唯一数据路径为 Direct-OS ChunkStore，不恢复 JuiceFS sparse
  `disk.raw` 方案。
- 本 ADR 修正 ADR-0003 第 3 条中“抽象只用于测试替身”的范围：ports 是长期架构
  边界，AWS S3 是第一个生产 adapter；未来是否增加其他生产 adapter 另按需求
  决定，但不允许为具体云产品污染核心契约。
- PostgreSQL metadata adapter 已按同一 port 实现，并作为 Linux/AWS 多节点
  root/lease 权威元数据实现；SQLite 只用于本地开发。

## 影响

- 新增 provider 时，只需新增 adapter crate、契约测试和 composition-root 注册；
  不修改 `ChunkEngine`、控制器、NodeJob 或 Guest 协议。
- 通用 CLI 参数不再出现 bucket、region、endpoint、SQLite path 等产品字段；这些
  字段仅作为选中 adapter 的 opaque options。
- 静态注册意味着新增 adapter 需要重新构建二进制。这是 V1 有意选择的更小攻击
  面；若以后确需第三方运行时扩展，再单独设计版本化 ABI 和信任模型。
