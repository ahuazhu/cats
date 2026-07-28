# ADR-0014：Account、Workspace、成员关系、赠金与会话切换

- 状态：Accepted
- 日期：2026-07-25
- 取代：
  - ADR-0006 中“无 Organization 的用户映射到 `personal-<user_id>` Project”的决定；
  - ADR-0008 中“一个 WorkOS Organization 一一映射一个 Workspace”的决定；
  - ADR-0013 中“每个 Billing Account 首次建立即获得注册赠金”的决定。

> 「slug、URL 与兼容路径」最后一条（保留 `/v1/projects/{project}`、资源表 `project` 列和
> 每个 Workspace 一个 `legacy_project` 路由键）与「迁移顺序」中的 Project 合成步骤已由
> ADR-0018 取代：Workspace 是唯一归属键，资源路由是 `/v1/workspaces/{workspace_id}`，
> 历史 Project 数据不迁移。本 ADR 的领域模型、成员关系、赠金和会话切换决定继续有效。

## 背景

Cats V1 把 Project 同时当作资源隔离边界、WorkOS Organization 映射和 Billing
Account。这个一一模型足以验证跨 Project 授权与账本，却不能安全支持以下产品行为：

- 一个用户同时拥有个人空间并加入多个组织；
- 一个组织拥有多个 Workspace，且在 Workspace 之间共享成员和账单；
- CLI 和 Web 登录一次后切换 Account/Workspace；
- Workspace 改名但资源归属、链接和历史 usage/credit 不漂移；
- 注册赠金只发一次，不能通过反复创建 Workspace 或 Organization 放大。

WorkOS 的 session access token 带一个 `org_id`。同一个 Organization 内切换
Workspace 不需要刷新 WorkOS token；跨 Organization 必须用旋转 refresh token
请求新的 Organization scope。WorkOS 在 refresh 请求省略 `organization_id` 时会保留
最近使用的 Organization，因此“无 Organization session 表示 Personal”不是可靠的
双向切换模型。

## 决策

### 领域模型

Cats 采用下面的资源所有权层级：

```text
WorkOS User
    │ AccountMembership
    ▼
Account (Personal | Organization) ─── BillingAccount
    │
    ├── Workspace (default)
    └── Workspace (...)
            │
            └── Cat / Disk / Operation / Endpoint
```

1. `Account` 是租户和计费所有者，使用不可变 `account_id`。Account 有可修改的
   display name、V1 不开放修改且全局唯一的 slug、类型 `personal|organization`、唯一
   WorkOS Organization ID 和一个不可变 Billing Account ID。
2. `Workspace` 是 Account 内的资源隔离边界，使用不可变 `workspace_id`。slug 在
   Account 内唯一；display name 和 slug 可改。每个 Account 恰有一个 default
   Workspace，删除 default 前必须先选择另一个 default。
3. 用户通过 Account membership 获得 Account；V1 中 active Account member 默认可见
   该 Account 的全部 Workspace。表结构保留 Workspace 级 grant，后续私有 Workspace
   不需要重做资源所有权。
4. WorkOS 是用户认证、Organization membership、Account role 和 permission 的
   权威源；Cats 保存用于资源连接、审计和故障恢复的本地 shadow。授权请求必须重新
   解析不可变 `account_id` / `workspace_id` 并确认 active membership，不能只信任
   URL slug、客户端缓存、email 或 display name。
5. Personal 与 Organization Account 在 Cats UI 中保持不同产品语义，但两者都映射到
   一个 WorkOS Organization。Personal Organization 使用稳定 external ID
   `cats-personal:<workos_user_id>` 幂等创建，只有该用户是 owner；Personal Account
   不开放邀请。

### slug、URL 与兼容路径

- 新 Account 的 slug 根据个人 handle 或组织名称生成；冲突时追加短随机后缀。新
  Account 的初始 Workspace slug 固定为 `default`，展示名为 `Default`。Workspace
  slug 和两者的展示名可以修改；Account slug 在 V1 保持稳定，身份与资源外键不变。
- 用户可复制的 Web URL 为
  `/user/{account_slug}/{workspace_slug}/...`。`/user/` 根据上次选择或 default
  Workspace 重定向。浏览器本地状态只是导航偏好，不是授权依据。
- CLI 接受无歧义 locator：当前 Account 内可写 `workspace`，跨 Account 写
  `account/workspace`。API 返回 `account_id`、`account_slug`、`workspace_id` 和
  workspace slug，客户端不再把裸 workspace slug 当作全局主键。
- V1 的 `/v1/projects/{project}` 和资源表 `project` 列在兼容期保留。每个 Workspace
  有不可变且全局唯一的 `legacy_project` 路由键；旧资源不改 project 值。slug 改名
  不改 `legacy_project`，旧 CLI/API 路径仍可解析到同一 Workspace。新 API 大版本再
  移除 Project 命名。

### 注册与 10 美元赠金

1. 新 WorkOS 用户首次完成 Cats 登录时，Cats 幂等 provision：
   Personal WorkOS Organization、owner membership、Personal Account、default
   Workspace、Personal Billing Account 和一次 `$10` signup grant。
2. WorkOS、本地 metadata 和 credit ledger 之间没有分布式事务。Cats 使用以
   WorkOS user ID 为键的持久化 provisioning 状态机和稳定 external/idempotency
   key；只有所有步骤成功后 Account 才进入 `active` 并对用户可见。失败返回可重试
   错误，重试继续未完成步骤，不重复建 Account 或发赠金。这是对用户可见的原子性，
   不声称跨服务 ACID。
3. 赠金 eligibility 唯一键是
   `(workos_user_id, campaign = 'signup-2026-10usd')`，beneficiary 固定为该用户的
   Personal Billing Account。创建额外 Workspace、Organization Account、被邀请加入
   Organization 或退出重进都不会再次发放。
4. 赠金不能转移到 Organization，也不能在 Workspace 间“搬动”。Personal Account
   内各 Workspace 共享 Personal Billing Account；Organization 的 Workspace 共享
   该 Organization 自己的 Billing Account。
5. 现有 `billing_account/project/<project>`、usage checkpoint、usage interval 和
   credit ledger entry 都是历史事实。迁移为旧 Project 合成 Account/Workspace 和
   billing binding，但不改任何历史 billing account ID、金额或 usage row。迁移后
   的新 usage 和充值只写 Account 的 canonical Billing Account；余额与查询通过
   binding 聚合 canonical ledger 和历史 ledger，不继续把 Workspace 当计费所有者。

### Organization 创建、邀请与成员生命周期

- 只有具备 `cats:members:manage` permission 的 Organization Account 成员可以邀请、
  重发或撤销邀请以及停用成员；服务端校验 permission，不依赖可改的 role slug。
- 邀请使用 WorkOS invitation，绑定一个明确 Organization、规范化 email 和初始
  role。接受邀请由 WorkOS 创建/激活 Organization membership；Cats 不自建密码、
  magic link 或平行的身份成员表。创建邀请要求 `Idempotency-Key` 并原样传给
  WorkOS；相同键的网络重试返回同一个 invitation。
- 邀请、membership 更新和删除以 WorkOS object ID 幂等写入本地 shadow。V1 在登录、
  列举 Account、资源授权和敏感成员操作时直接向 WorkOS 读取并校验 active
  membership，因此撤权 fail closed；本地 shadow 不是授权真相源。后续若增加异步
  WorkOS Events 消费，只能选择一个消费流并持久化 event ID，不同时接 webhook，
  避免双重投递。
- Workspace 级 grant 只收窄 Account membership，不能扩大它；Account membership
  失效时所有 Workspace grant 立即无效。

### CLI 会话

- `cats login` 只登录一次并缓存 Account/Workspace 清单。秘密仍只进操作系统凭据
  存储。
- `cats workspace use <locator>` 修改持久默认选择；`--workspace <locator>` 和
  `CATS_WORKSPACE` 只覆盖当前命令，绝不修改默认选择。
- 同一 Account 内切 Workspace 只更改本地 workspace ID/路由键，不 refresh WorkOS。
  跨 Account 使用当前旋转 refresh token 请求目标 WorkOS Organization，验证返回的
  `sub` 与 `organization_id` 后原子替换 access/refresh token。
- CLI 对同一 credential key 的读取、refresh、写回持有跨进程排他锁。拿锁后必须
  重新读取最新 refresh token；这样两个并发 CLI 进程不会同时消费同一个旋转 token。
  refresh 或校验失败时不改变默认选择，也不覆盖旧 credential。

### Web 会话

- sealed、HttpOnly cookie 同时保存当前 WorkOS Organization scope、Account ID、
  Workspace ID 和旋转 refresh token。服务端忽略客户端提交的 Account ID 并从
  Organization scope 与 membership 重新解析。
- 同一 Account 切 Workspace 时，服务端校验 workspace ownership 和 membership 后
  只轮换 sealed cookie 中的 workspace context。跨 Account 时用 cookie 中的 refresh
  token 切换 WorkOS Organization，验证返回身份后把新 token 与新 context 一次写入
  `Set-Cookie`。
- Account/Workspace 列表和切换均由服务端 API 提供。前端 selector 和可复制 URL
  共用该 API；不得只改 JavaScript 的 `state.project`。
- 多标签页可能持有旧的旋转 refresh token。跨 Account 切换通过服务端按 session ID
  串行化；失败的旧标签页重新读取当前 session，而不是清空有效登录。

### 迁移顺序

1. 建立 Account、Workspace、membership shadow、Workspace grant、billing binding、
   signup eligibility、`accounts.status` provisioning 状态和 WorkOS event receipt
   表及约束。
2. 对现有资源表中每个 distinct Project、静态
   `CATS_WORKOS_PROJECT_ORGANIZATIONS` 映射和历史 billing account 合成兼容
   Account/Workspace。迁移可重复执行，旧资源主键和 `project` 值保持不变。
3. 在兼容读路径能解析新旧标识后，写路径开始保存不可变 Workspace ID；Project API
   继续接受 `legacy_project`。
4. 最后启用 Personal onboarding、Organization 创建/邀请、CLI/Web switcher。回滚
   应用版本不删除新表，也不回写历史账本。

## 不变量与验收

- 相同 slug 在不同 Account 可以存在；任何请求最终都按不可变 ID 授权。
- 未映射 Organization、inactive membership、Account/Workspace 不匹配和旧 token
  全部 fail closed。
- 并发首次登录最多产生一个 Personal Account、一个 default Workspace 和一笔赠金。
- 同 Account 切换不调用 WorkOS refresh；跨 Account 恰好提交一次成功的 token
  轮换，失败不污染选择。
- 改 slug 后资源、usage、余额和旧 Project 兼容路径仍指向原 Workspace。
- 邀请重放、event 重放和 provision 重试不重复成员、Workspace 或赠金。

## 后果

优点：

- 身份、租户、资源隔离和计费边界不再由一个可修改的 Project 字符串兼任；
- Personal 和 Organization 的切换共享同一条可靠的 WorkOS Organization 机制；
- 注册赠金有明确 beneficiary 和全局一次性约束；
- CLI、Web 与 API 使用同一授权模型，同时保留现有资源与财务历史。

代价：

- 每个个人用户也会占用一个 WorkOS Organization；
- onboarding 是需要监控和重试的跨系统状态机；
- 兼容期同时存在 Account/Workspace ID、用户 slug 与 legacy Project 路由键；
- WorkOS membership/event 暂不可用时，成员管理和需要重新确认成员关系的操作会
  fail closed。
