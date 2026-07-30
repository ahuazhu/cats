# Cats 结构化重构计划

- 状态：Draft
- 日期：2026-07-30
- 分支：`codex/structural-refactor`
- 基线：`d0c09d25d7ec8a2dca6804efec6a137803515e1c`
- 性质：行为保持型重构；除非阶段明确声明，不改变产品、协议、持久化或故障语义

## 1. 目标

本轮重构解决当前实现中最影响可读性、依赖方向和演进安全性的结构问题：

1. 把 `blockd/src/engine.rs`、`control-plane/src/store.rs`、
   `control-plane/src/api.rs`、`control-plane/src/auth.rs` 和
   `node-agent/src/runtime.rs` 从单体模块拆成可独立审查的职责模块。
2. 让 Guest、Node 和 blockd 之间只通过共享协议类型或轻量客户端依赖，不让客户端
   依赖服务端实现 crate。
3. 把计量领域与 SQLite usage adapter 分离，使 `cats-metering` 恢复为
   provider-neutral core。
4. 用同一套契约测试验证 File/S3、SQLite/PostgreSQL adapter，减少实现语义漂移。
5. 为后续控制面 PostgreSQL 化和 `ChunkEngine` 内部组件化建立稳定边界，但不在首轮
   重构中同时改变数据库、锁粒度或提交协议。

## 2. 当前基线

| 文件 | 行数 | 当前混合职责 |
|---|---:|---|
| `blockd/src/engine.rs` | 5,030 | I/O、cache、quota、stage、publish、hydrate、GC、lease、后台线程、测试替身 |
| `control-plane/src/store.rs` | 4,092 | Account、Workspace、Cat、work、Disk、Node、Operation、Endpoint、schema |
| `control-plane/src/api.rs` | 3,389 | 84 条路由；用户、内部、管理、计费、usage、route、shell |
| `node-agent/src/runtime.rs` | 2,715 | 进程监管、生命周期、blockd 控制、计量、shell、HTTP proxy |
| `control-plane/src/auth.rs` | 2,017 | WorkOS client、JWT、AuthKit flow、session、workspace switching、provisioning |
| `metering/src/lib.rs` | 2,038 | 领域类型、ports、计价、累计量、SQLite adapter、schema |

当前 Cargo 图没有循环依赖，但存在以下不理想的正常依赖：

```text
cats-guest-agent -> cats-blockd
cats-node-agent  -> cats-guest-agent
cats-node-agent  -> cats-blockd
cats-metering    -> rusqlite
```

## 3. 不可改变的不变量

所有阶段必须保留下列行为；任何需要改变它们的工作必须退出本计划并单独立 ADR：

- Guest 只看到标准 virtio block 和未修改的 ext4，不接收对象存储或元数据凭据。
- PersistentDisk 保持 RWO；旧 attachment epoch 永远 fail closed。
- Strict FLUSH 只有在远端对象持久且 Root CAS 成功后才能 ACK。
- Relaxed 始终满足 `remote_durable_generation <= local_durable_generation`；Guest
  FLUSH 只走本地 durability path，强制 drain 失败不得清理唯一的本地副本。
- Pending pack、对象上传、Map/commit record、Root CAS 和本地清理的顺序不变。
- Running / Suspended / Warm / Cold 四态不合并；Suspended/Warm 失败收敛到 Cold。
- Kernel NBD 和 vhost-user-blk 继续复用同一个 `ChunkEngine` 和提交协议。
- Storage provider-specific SDK、凭据和配置不进入 `cats-storage` 或业务核心 crate。
- Workspace 仍是唯一资源所有者，Account 仍是唯一计费所有者。
- 对外 HTTP、WebSocket、Guest runtime、NodeJob、blockd 和磁盘格式保持字节兼容。

## 4. 实施原则

1. **先护栏，后移动。** 先补可复用 contract tests 和测试 builder，再拆模块。
2. **一次只改变一个维度。** 文件移动、依赖图调整、数据库后端和锁模型不得混在同一
   PR。
3. **保留 façade。** 第一轮继续由 `ChunkEngine`、`NodeRuntime`、`Store` 和现有
   router 函数提供同一公开入口。
4. **保留事务聚合。** 不按数据库表机械创建 repository；创建 Cat 等跨资源事务必须
   保持原子。
5. **不以行数作为唯一目标。** 拆分以职责、依赖和不变量为准；避免产生只转发一行调用
   的碎片模块。
6. **每个 PR 可独立回滚。** 首轮不得包含 schema migration 或数据重写。

## 5. 阶段 0：建立重构护栏

> 实施状态：已完成（2026-07-30）。SQLite/File 契约进入默认 workspace test；
> PostgreSQL/S3 契约分别由 `CATS_POSTGRES_URL` 和
> `CATS_AWS_S3_TEST_ENDPOINT` 显式启用。

### 5.1 创建共享测试支持 crate

新增仅供 `dev-dependencies` 使用的 `cats-test-support`，建议路径：

```text
tests/support/
  Cargo.toml
  src/
    lib.rs
    storage_contract.rs
    blob_doubles.rs
    node_builder.rs
```

职责：

- `metadata_store_contract`：接受 store factory，运行同一组 volume、resize、
  acquire/renew/revoke、expiry takeover、stale epoch、generation CAS、snapshot 用例。
- `blob_store_contract`：运行 immutable put、同 key 同 bytes 幂等、同 key 不同 bytes
  冲突、get/list/delete、非法 key 用例。
- 集中 `SlowBlob`、`CountingBlob`、`SizingBlob`、`ConcurrencyProbe` 和可切换故障
  wrapper。
- 提供 `NodeConfigBuilder`、FakeVmm 默认 adapter 和临时目录 fixture。

PostgreSQL 和真实 S3 contract 可以通过显式环境变量启用；SQLite/File contract 必须
进入默认 workspace test。

### 5.2 验收条件

- SQLite 和 PostgreSQL metadata adapter 引用同一组语义用例。
- File 和 S3-compatible blob adapter 引用同一组核心语义用例。
- `blockd/src/engine.rs` 不再重复定义通用 BlobStore wrapper。
- 测试支持 crate 不进入任何生产依赖。

## 6. 阶段 1：机械模块拆分

此阶段不改变函数签名、SQL、锁、线程、超时和错误映射。

### 6.1 Control Plane API

目标结构：

```text
control-plane/src/api/
  mod.rs                 # AppState、Failure、router 组装、共享鉴权 helper
  accounts.rs
  cats.rs
  disks.rs
  endpoints.rs
  nodes.rs
  operations.rs
  billing.rs
  usage.rs
  routes.rs
  sessions.rs            # exec / shell proxy
```

要求：

- `router()` 继续是唯一公开组装入口。
- 路径、method、handler、认证规则和响应类型逐条保持不变。
- 为路由表增加快照式测试，至少断言 path + method 集合不漂移。

### 6.2 Control Plane Store

目标结构：

```text
control-plane/src/store/
  mod.rs                 # Store、连接/事务 helper、公共记录类型
  schema.rs
  accounts.rs
  cats.rs
  work.rs
  disks.rs
  nodes.rs
  operations.rs
  endpoints.rs
  rows.rs                # row_to_* 和 enum/string 映射
  tests/
```

要求：

- 继续由一个 `Store` façade 拥有当前 SQLite connection。
- `create_cat` 等跨领域事务保留在一个明确的 aggregate 模块中，不拆成多次提交。
- schema version、migration 范围和 SQL 文本不变。

### 6.3 Auth

目标结构：

```text
control-plane/src/auth/
  mod.rs
  workos_client.rs
  token.rs
  web_flow.rs
  session.rs
  provisioning.rs
  cookie.rs
```

WorkOS API 调用、JWT 验证、sealed cookie、Personal Account provision 和 HTTP handler
分离，但 `WorkOsConfig` 与现有 handler 入口保持兼容。

### 6.4 Node Runtime

目标结构：

```text
node-agent/src/runtime/
  mod.rs                 # NodeRuntime façade、共享 runtime state
  supervisor.rs
  lifecycle.rs
  blockd_control.rs
  metering.rs
  proxy.rs
  fake.rs
  tests/
```

要求：

- `execute`、per-Cat lock、node-global allocation lock 和 admission 行为不变。
- start/suspend/warm/restore/cold 的动作顺序不变。
- blockd drain timeout 与 status timeout 继续分开。

### 6.5 Block Engine

先移动测试，再抽取纯逻辑：

```text
blockd/src/engine/
  mod.rs                 # ChunkEngine façade、锁与共享状态
  status.rs
  quota.rs
  pack.rs
  plan.rs
  hydrate.rs
  publish.rs
  recovery.rs
  gc.rs
  lease.rs
  tests/
```

限制：

- `ChunkEngine` 仍拥有现有锁和后台线程。
- 不改变 coarse-lock 基线，不引入新的异步 runtime。
- `stage_pack`、`drain_one_batch`、CAS、recover 和 detach 的调用顺序不变。
- 先迁移 `ChunkPlan`、`CopyRun`、pack 编解码等纯逻辑，再移动持锁方法。

### 6.6 阶段验收

- 公开 Rust API 和所有 wire/schema 格式不变。
- 每个拆分提交只包含移动、visibility 收窄/放宽和必要 import 调整。
- 不允许在“顺手重命名”中改变错误文案、日志字段或 CLI 参数。

## 7. 阶段 2：修复协议和客户端依赖方向

### 7.1 Guest 协议

移动到 `cats-api::guest` 或其子模块：

- `DiskMapEntry` / `DiskMap`
- length-prefixed JSON framing helper
- Guest client/server 共用的边界常量

目标：

```text
cats-node-agent -> cats-api
cats-guest-agent -> cats-api
```

Node 不再为了 framing 或 DiskMap 类型依赖 `cats-guest-agent`。

### 7.2 blockd 控制协议

新增 `cats-api::blockd`：

- `DurabilityStatus`
- control socket command/response DTO
- 可观测字段的稳定 serde contract

配置默认值可以保留在 blockd config 模块；如果 Node 也需要默认值，则放入一个不依赖
engine 实现的共享 config 类型，而不是从 `engine` 模块导入。

### 7.3 NBD 客户端

把只用于 FakeVmm、readiness、oracle 和恢复工具的 `NbdClient` 移入轻量
`cats-block-client` crate。NBD server 仍属于 `cats-blockd`。

目标依赖：

```text
cats-guest-agent -> cats-api + cats-block-client
cats-node-agent  -> cats-api + cats-block-client
cats-blockd      -> cats-api + cats-storage
```

`cats-guest-agent` 不再链接 blockd engine、storage ports 或 Linux vhost-user 依赖。

### 7.4 阶段验收

- `cargo metadata` 中不存在：
  - `cats-guest-agent -> cats-blockd`
  - `cats-node-agent -> cats-guest-agent`
  - `cats-node-agent -> cats-blockd`，除非仍有一个经审查无法迁出的实现级需求
- Guest/Node/blockd 协议序列化 golden tests 逐字节不变。
- FakeVmm、真实 Guest、NBD 和 vhost-user 测试仍通过。

## 8. 阶段 3：Metering Ports and Adapters 对齐

目标结构：

```text
metering/src/
  lib.rs
  error.rs
  model.rs
  ports.rs
  validation.rs
  rating.rs
  accumulator.rs

adapters/usage-store-sqlite/
  Cargo.toml
  src/
    lib.rs
    schema.rs
    usage.rs
    credit.rs
    migration.rs
```

迁移内容：

- `SqliteUsageStore`
- rusqlite error conversion
- SQLite schema 与 migration
- SQLite row conversion和数据库专属测试

保留在 `cats-metering`：

- `UsageStore` / `CreditStore`
- checkpoint 和 attribution 验证
- exact integer rating
- interval projection 的 provider-neutral 算法
- `RuntimeMeterAccumulator`

验收条件：

- `cats-metering` 的正常依赖中不存在 `rusqlite`。
- SQLite/PostgreSQL 同时运行共享 Usage/Credit contract。
- 乱序 checkpoint、重复事件、冻结 attribution、u128 数值、Stripe payment/refund
  幂等结果与重构前一致。

## 9. 阶段 4：控制面持久化边界

此阶段收益高但风险也高，只有阶段 0–3 全部完成后才能进入。

### 9.1 先冻结事务清单

列出必须原子的领域事务：

- Cat + RootDisk + 可选 PersistentDisk + default Endpoint + Operation
- desired state generation + Operation + idempotency
- placement reservation + Node capacity
- RWO bind/unbind
- signup provisioning state + billing binding

### 9.2 引入领域级 store port

避免“一张表一个 repository”。按命令/查询聚合定义边界，例如：

```text
AccountStore
CatStore
DiskStore
FleetStore
RouteStore
OperationStore
```

跨聚合事务由更高层的 `ControlStoreTransaction` 或明确的原子命令保持，不允许 handler
串联多个独立提交模拟事务。

### 9.3 隔离阻塞数据库 I/O

短期可以仿照 usage PostgreSQL adapter 使用固定 worker pool，让 SQLite 不阻塞 Tokio
executor；长期 PostgreSQL 方案需单独决定 driver、migration 和 HA 边界。

以下内容不与接口抽取放在同一 PR：

- SQLite → PostgreSQL 数据迁移
- schema redesign
- Outbox/event bus
- 控制面多副本

## 10. 阶段 5：ChunkEngine 内部组件化

只有共享 storage contract、crash injection 和 Linux protocol tests 稳定后进入。

候选内部组件：

- `LocalJournal`：pending pack fsync、rename、directory fsync、recovery inventory
- `CacheManager`：allocated/accounted bytes、pin、clean eviction
- `CommitPlanner`：dirty ranges → delta/base 计划
- `Publisher`：batch upload、Map 构造、commit record、Root CAS
- `Hydrator`：cold read、layer fetch、checksum、miss coalescing
- `LeaseMaintainer`：renew、fence、detach coordination

第一轮组件化仍由 `ChunkEngine` 统一编排。改变锁粒度、上传并发、线程模型或 cache
eviction 算法必须单独提交，并附：

- crash point matrix
- strict/relaxed 双水位恢复证明
- stale epoch 测试
- Linux NBD/vhost-user 协议测试
- 性能 A/B；结果只描述测量环境，不转化为生产 SLA

## 11. 推荐提交 / PR 顺序

1. `test: add reusable storage contracts and fixtures`
2. `refactor: split control-plane API by bounded context`
3. `refactor: split control-plane store without changing SQLite semantics`
4. `refactor: split WorkOS auth responsibilities`
5. `refactor: split node runtime supervision and lifecycle modules`
6. `refactor: move block engine tests and pure planning helpers`
7. `refactor: extract guest and blockd protocol seams`
8. `refactor: move SQLite usage store into an adapter crate`
9. `design: freeze control-plane transaction ports`
10. `refactor: isolate blocking control-plane persistence`
11. `refactor: componentize ChunkEngine behind the existing façade`

每个序号可以拆成多个小 PR；不得为了保持序号而扩大单个 review 单元。

## 12. 每阶段质量门

macOS / 当前开发机：

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

任何触及 blockd、NBD/vhost-user、node-agent Linux 路径或协议边界的阶段还必须运行：

```bash
docker run --rm --platform linux/arm64 -v "$PWD":/work -w /work \
  -v cats-cargo-registry:/usr/local/cargo/registry \
  -v cats-target-linux:/target rust:1.97-bookworm \
  sh -c 'rustup component add clippy &&
         cargo build --workspace --target-dir /target &&
         cargo clippy --workspace --all-targets --target-dir /target &&
         cargo test --workspace --target-dir /target'
```

附加检查：

- `cargo metadata` 的内部依赖边符合该阶段目标。
- `git diff --check` 通过。
- schema version、API 路由、CLI help 和 serde golden snapshot 无意外变化。
- WorkOS、service token、Stripe、对象存储和 metadata 凭据未进入日志或新 DTO。

## 13. 完成标准

本计划完成时应满足：

- 大型文件按职责拆分，核心 façade 和领域事务仍清晰可追踪。
- Guest 和 Node 不依赖 Guest/blockd 服务端实现来获得协议类型。
- `cats-metering` 不依赖 SQLite；所有 usage store 都位于 adapters。
- File/S3、SQLite/PostgreSQL 的同类端口由同一套 contract tests 验证。
- 控制面阻塞持久化具有明确隔离边界，后端迁移不要求重写 HTTP handler。
- `ChunkEngine` 内部职责可以独立测试，但 durability、fencing 和生命周期语义未改变。
- Workspace tests 与 clippy 全绿，Linux-only 路径在 Linux 门禁中全绿。

## 14. 暂不纳入

- 修改 Strict/Relaxed 产品契约。
- 翻转默认 block path。
- 合并 Suspended 与 Warm。
- 新增跨 Host replicated write log。
- 实现 tap/overlay 网络或 privilege separation。
- 借重构改变价格、计费 meter、WorkOS 授权模型或 Workspace 所有权。
- 仅为了减少重复 SQL 而构造跨 SQLite/PostgreSQL 的通用 SQL DSL；共享的是契约和领域
  验证，不是数据库方言。
