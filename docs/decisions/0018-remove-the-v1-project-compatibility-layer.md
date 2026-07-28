# ADR-0018：移除 V1 Project 兼容层，Workspace 是唯一资源归属

- 状态：Accepted
- 日期：2026-07-28
- 取代：
  - ADR-0014「slug、URL 与兼容路径」中保留 `/v1/projects/{project}`、资源表 `project`
    列和每个 Workspace 一个 `legacy_project` 路由键的决定；
  - ADR-0008 中「底层 `/v1/projects/{project}` 保持不变」的决定。

## 背景

ADR-0014 已经把 V1 的 Project 拆成 Account（租户与计费所有者）和 Workspace（资源隔离
边界），并留了一层兼容：每个 Workspace 带一个全局唯一的不可变 `legacy_project`，
`cats`/`disks`/`operations` 同时存 `workspace_id` 和 `project`，资源 API 仍走
`/v1/projects/{project}`。当时的计划是「新 API 大版本再移除 Project 命名」。

这层兼容自己就是一组不变量：六个 SQLite 触发器强制 `workspace_id` 与 `project` 一致、
`legacy_billing_bindings` 把历史 ledger 聚合进 Account 余额、`workspaces.legacy_project`
需要一个和 slug 分开的全局唯一命名空间。也就是说每个资源有两个所有权字段、每个 Account
有多个 billing ledger、每个 Workspace 有两个名字。没有外部客户依赖 V1 路径，Cats 也还没
有需要保留的生产历史数据，因此继续养这层兼容的成本全部是内部复杂度，换不到任何兼容收益。

## 决策

1. `Workspace` 是唯一的资源隔离边界与归属键。`cats`、`disks`、`operations` 只有
   `workspace_id`，唯一名字约束是 `(workspace_id, name)`。`project` 列、
   `workspaces.legacy_project` 列和 `legacy_billing_bindings` 表全部删除。
2. 资源 API 路由改为 `/v1/workspaces/{workspace_id}/…`，`{workspace_id}` 是不可变
   Workspace ID。路由键不接受可改的 slug，因此「改名不影响归属」不再需要额外不变量来
   保证——slug 根本不出现在资源路由里。人类可读的 `account/workspace` locator 只存在于
   CLI、Web URL 和 `/v1/me` 响应里，由客户端解析成 ID。
3. 一个 Account 恰好一个 Billing Account，Workspace 永不是计费所有者。余额与用量按
   Account 的 canonical ledger 读取，不再聚合历史 ledger。注册赠金的受益人仍然只是用户
   Personal Account（ADR-0014），Organization Account 的 `signup_credit_nanos` 是 0。
4. 用量归属字段是 `workspace_id`（哪个 Workspace 产生的用量），资金侧字段是
   `account_id`（哪个 Account 拥有这笔钱）。V1 用一个 `project_id` 兼任两者，拆开后
   `billing_accounts` 和 `checkout_intents` 用 `account_id`，`usage_checkpoints` 和
   `usage_intervals` 用 `workspace_id`。
5. 静态部署映射从「Project → WorkOS Organization」改为「Account slug → WorkOS
   Organization」：`--workos-account-organization ACCOUNT=ORG_ID` /
   `CATS_WORKOS_ACCOUNT_ORGANIZATIONS`。启动时幂等 provision 这些 Account 及其
   `default` Workspace；Personal Account 仍然走 AuthKit onboarding。
6. 机器凭据（service/admin token）没有 WorkOS 身份可以枚举自己的 Workspace，因此新增
   `GET /v1/admin/workspaces`（admin 鉴权）作为目录，用于把 `account/workspace` locator
   解析成不可变 ID。它不是用户 API，不出现在公开文档里。

## 迁移：没有迁移

历史数据不迁移，也不为迁移留脚手架。`project` 列记录的归属指向已经不存在的
Account/Workspace 合成结果，无法可靠重建。因此这次同时删掉了兼容层和"检测兼容层"的代码：

- 控制面 SQLite 用 `PRAGMA user_version` 单一版本闸门。`Store::open` 只做两件事：
  版本不匹配就以 `FailedPrecondition` 拒绝并要求重建，匹配就建表。原来的
  `ensure_column` 迁移梯（`telemetry_json`、`auto_suspend`、`work_version`、
  `observed_state_since_ms`）、`.cats.local` → 公网 hostname 改写和默认 Endpoint 补齐
  （`backfill_public_endpoints`）全部删除：它们服务的每一个数据库形态都在版本闸门之外，
  留着就是一份没人跑、却仍然要被读懂和维护的考古层。发布流水线在替换 live Pod 前也校验
  这个版本，且从不自动删除 PVC——重建数据库始终是运维的显式动作。
- 用量 PostgreSQL schema 不加 `project_id` 改名迁移。一个只为消灭旧名字而永久保留旧名字
  的 DDL，本身就是要清理的东西。既有 usage schema 需要重建，或用 `--usage-schema`
  指向新名字。这条路不写自动 `DROP`：即使历史数据可弃，启动时静默摧毁资金账本不是
  这套代码该有的行为。

代价明确：任何早于本次变更的控制面数据库都必须重建，没有升级路径。这是被显式接受的，
不是遗漏。

### 一次被撤回的 V0 → V1 例外

这条决定曾被短暂推翻。生产 EKS 当时确实在运行未打版本戳的 V0 Project-shaped SQLite，
「没有状态需要存活」的前提失效，于是仓库加入了一条 V0 → V1 迁移和相应的
`MIN_SUPPORTED_SCHEMA_VERSION` 支持区间。

那条迁移写出来时，它唯一的对象已经不存在了：生产 PVC 与其 EBS 卷在迁移合并前几分钟被显式
销毁，控制面以一个全新 V1 数据库重新上线。此后世界上不存在任何 V0 控制面数据库，也无法
再产生一个——当前 build 只会写入版本 1。那条迁移的 312 行连同它的测试因此永远走不到，
正是本 ADR 要删除的那类考古层，于是被撤回。

记录在此，是为了让下一个考虑重新加它的人先回答同一个问题：**此刻真的存在一个需要被迁移的
数据库吗？** 如果存在，扩大支持区间必须同时提交完整迁移链、生产副本演练和版本边界更新；
如果不存在，那条迁移从写下的第一行起就没有对象。

## 不变量与验收

- 资源只能通过不可变 `workspace_id` 定位与授权；触发器仍然禁止资源在 Workspace 之间移动。
- 同一个名字在两个 Workspace 里互不冲突，在同一个 Workspace 内仍然唯一。
- 改 Workspace slug 或 display name 不影响资源、用量、余额或任何 URL 的解析结果。
- 一个 Account 内的所有 Workspace 读到同一个余额；跨 Account 的余额互相隔离。
- 重复执行 Account provision 不会产生第二个 default Workspace。
- 支持范围内的控制面数据库无损迁移；范围外的版本拒绝启动并给出版本信息；本 build
  自己写出的数据库可以反复打开。
- 代码库中不存在 Project 概念的任何实现载体。仅存三类同形字符串：ADR 本身、
  usage projector 的"投影"词义（`project_shard` 等），以及公开文档的 retired-contract
  断言列表（`/v1/projects/`、`CATS_PROJECT`）——那是防止文档回退的围栏，不是残留。

## 后果

优点：

- 每个资源一个所有权字段、每个 Account 一个 ledger、每个 Workspace 一个名字；
- 六个 workspace/project 一致性触发器缩减为三个 ownership-immutability 触发器；
- 「按不可变 ID 授权」从一条需要人工遵守的规则变成路由形状本身；
- `Store::open` 从一条读不动的迁移梯变成"版本对不上就拒绝"。

代价：

- 破坏性 API 变更：`/v1/projects/{project}` 直接消失，没有兼容期；
- 任何早于本次变更的控制面数据库必须重建，历史资源与账本不保留；
- 既有 usage PostgreSQL schema 必须重建或换名，没有列改名迁移；
- 机器凭据的工作流多一步 locator → ID 解析（`GET /v1/admin/workspaces`）；
- 下一次不兼容 schema 变更必须记得 bump `SCHEMA_VERSION`，否则旧库会被当成同版本打开。
