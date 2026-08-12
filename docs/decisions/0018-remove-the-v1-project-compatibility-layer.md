# ADR-0018：Workspace 是唯一资源归属键

- 状态：Accepted
- 日期：2026-07-28
- 取代：ADR-0008 与 ADR-0014 中保留双资源归属字段和可变资源路由键的决定

## 背景

ADR-0014 已将租户与计费所有权归于 Account，将资源隔离归于 Workspace。持久化模型和
API 也应直接表达这两个边界：一个资源只能有一个归属键，余额只能有一个资金所有者，
可修改的名称不能参与授权。

## 决定

### 唯一归属与路由

1. `Workspace` 是 Cat、Disk、Operation、Endpoint 等资源唯一的隔离边界与归属键。
   资源表只保存 `workspace_id`，名字唯一性约束是 `(workspace_id, name)`；归属字段不可
   原地修改。
2. 资源 API 使用 `/v1/workspaces/{workspace_id}/...`，其中 `workspace_id` 是不可变 ID。
   Account/Workspace slug 只用于 CLI locator 和 Web 导航，客户端先解析为 ID，服务端不按
   slug 授权。
3. 机器凭据没有 WorkOS 身份来枚举 Workspace。Administrator 可通过
   `GET /v1/admin/workspaces` 把人类可读 locator 解析为 Workspace ID；资源请求仍使用 ID。

### 计费归属

1. 一个 Account 恰有一个 Billing Account，Workspace 不是计费所有者。余额、充值、退款
   和 checkout intent 都按 Account 的 canonical ledger 处理。
2. 用量记录同时携带 `workspace_id` 和 Billing Account ID：前者说明资源来源，后者说明
   费用归属。资金记录使用 `account_id`，不会从可修改名称反推所有者。
3. 静态部署映射使用 Account slug 到 WorkOS Organization：
   `--workos-account-organization ACCOUNT=ORG_ID` /
   `CATS_WORKOS_ACCOUNT_ORGANIZATIONS`。启动时幂等 provision Account 及其 default
   Workspace；Personal Account 由 AuthKit onboarding provision。

### 精确 Schema 与重建

1. 每个持久化存储的 canonical schema 由版本戳和当前 DDL 精确定义。进程只打开空 schema
   或当前 build 明确声明支持的版本；不通过探测列、猜测旧字段含义或重建映射来推导资源
   归属。
2. 支持范围外的 schema 以 `FailedPrecondition` 拒绝启动，并报告实际版本与当前要求。
   运维显式选择重建数据库或使用新的 schema；应用启动过程不得自动删除数据库、schema、
   PVC 或账本。
3. 控制存储的版本范围和 DDL 串行化由 ADR-0031 定义。任何需要保留生产状态的 schema
   变化都必须先定义受支持的迁移范围并通过副本演练；不在范围内的数据形态不进入正常
   运行路径。

## 不变量与验收

- 资源只能通过不可变 `workspace_id` 定位与授权；存储约束禁止资源跨 Workspace 改归属。
- 同名资源可存在于不同 Workspace，同一 Workspace 内仍保持唯一。
- 修改 Account/Workspace slug 或 display name 不影响资源、用量、余额或授权。
- 一个 Account 内所有 Workspace 读取同一个余额，不同 Account 的余额互相隔离。
- 重复执行 Account provision 不会产生第二个 default Workspace 或 Billing Account。
- 空 schema 可初始化；当前支持版本可重复打开；不支持的版本拒绝启动且不会被自动破坏。
- API、资源表和授权路径只有一个 Workspace 归属字段，不存在第二套可写资源身份。

## 后果

资源所有权、计费所有权和用户可读名称各自只有一个职责。API 路由天然携带不可变的授权
标识，数据库无需维护两套归属一致性。代价是机器凭据在使用可读 locator 时需要先解析
Workspace ID，不兼容 schema 需要明确的运维重建或单独批准的迁移。
