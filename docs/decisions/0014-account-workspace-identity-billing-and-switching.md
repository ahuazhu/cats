# ADR-0014：Account、Workspace、成员关系、赠金与会话切换

- 状态：Accepted
- 日期：2026-07-25
- 取代：ADR-0006、ADR-0008 和 ADR-0013 中与 Personal Account、Organization 映射及
  注册赠金归属冲突的决定
- 细化：Workspace 唯一资源归属与 API 路由由 ADR-0018 定义

## 背景

一个用户可以同时拥有个人空间并加入多个组织；一个组织也可以拥有多个隔离的
Workspace。身份 scope、资源隔离和计费所有权因此不能由同一个可修改名称表达。Cats
需要用不可变 ID 连接 WorkOS 身份、资源和账本，同时让 CLI 与 Web 在一次登录后切换
Account/Workspace。

## 决定

### 领域模型

```text
WorkOS User
    │ active membership
    ▼
Account (Personal | Organization) ─── BillingAccount
    │
    ├── Workspace (default)
    └── Workspace (...)
            │
            └── Cat / Disk / Operation / Endpoint
```

1. `Account` 是租户和计费所有者，使用不可变 `account_id`。它有 display name、全局唯一
   slug、`personal|organization` 类型、唯一 WorkOS Organization ID 和唯一且不可变的
   Billing Account ID。
2. `Workspace` 是 Account 内的资源隔离边界，使用不可变 `workspace_id`。slug 在
   Account 内唯一；display name 和 slug 可修改。每个 Account 恰有一个 default
   Workspace。
3. V1 中 active Account member 可见该 Account 的全部 Workspace。WorkOS 是用户身份、
   Organization membership、role 和 permission 的权威源；Cats 的本地 shadow 只服务于
   资源连接、审计和恢复，不单独授予访问权。
4. Personal 与 Organization Account 都映射到一个 WorkOS Organization。Personal
   Organization 使用稳定 external ID `cats-personal:<workos_user_id>` 幂等创建，只有该
   用户是 owner，且不开放邀请。

### 标识、URL 与授权

- Account slug 根据个人 handle 或组织名称生成；冲突时追加短随机后缀。初始 Workspace
  slug 为 `default`，展示名为 `Default`。
- 用户 Web URL 使用 `/user/{account_slug}/{workspace_slug}/...`；`/user/` 根据会话选择
  或 default Workspace 重定向。slug 和浏览器本地状态都只是导航信息。
- CLI 在当前 Account 内可使用无歧义 Workspace slug，跨 Account 使用
  `account/workspace`，也可以直接使用 Workspace ID。
- 资源 API 使用 `/v1/workspaces/{workspace_id}/...`。服务端按不可变 `account_id`、
  `workspace_id`、Account 状态和 active membership 授权，不信任 URL slug、客户端缓存、
  email 或 display name。

### 注册与计费

1. 新 WorkOS 用户首次完成 Cats 登录时，Cats 幂等 provision Personal Organization、
   owner membership、Personal Account、default Workspace、Billing Account 和一次
   `$10` signup grant。
2. WorkOS、本地控制状态和 credit ledger 之间没有分布式事务。Provisioning 使用
   WorkOS user ID、稳定 external ID 和 idempotency key 继续未完成步骤；所有步骤完成后
   Account 才进入 `active` 并对用户可见。
3. 赠金 eligibility 唯一键是
   `(workos_user_id, campaign = 'signup-2026-10usd')`，受益人固定为该用户的 Personal
   Billing Account。创建 Workspace、创建或加入 Organization、退出后重进都不会再次
   发放；赠金不能转移到 Organization。
4. 一个 Account 恰有一个 Billing Account，Account 内所有 Workspace 共享余额。
   `workspace_id` 记录用量来源，`account_id` 与 Billing Account ID 记录资金所有权；
   Workspace 不是计费所有者。

### Organization 成员

- 只有具有 `cats:members:manage` permission 的 Organization Account 成员可以邀请、
  重发或撤销邀请以及修改成员；服务端校验 permission，不依赖可修改的 role slug。
- 邀请由 WorkOS 管理，绑定明确 Organization、规范化 email 和初始 role；请求携带
  `Idempotency-Key`，相同键的网络重试返回同一个 invitation。
- Cats 按 WorkOS object ID 幂等更新本地 invitation/membership shadow。在登录、Account
  枚举、资源授权和敏感成员操作时重新确认 active membership；WorkOS 不可用时 fail
  closed。

### CLI 与 Web 会话

- CLI 的 token 只进入操作系统凭据存储；Account/Workspace 清单和当前选择是可刷新缓存。
  同 Account 切换只更新本地 Workspace；跨 Account 在跨进程锁内轮换 refresh token，
  验证 `sub` 与目标 Organization 后再原子保存。
- Web 使用 sealed、HttpOnly session cookie 和独立的 Account/Workspace context。服务端
  忽略客户端声称的 Account ID，并从 WorkOS Organization scope、active membership 与
  Workspace ownership 重新解析。
- 同 Account 的 Web 切换只轮换 context；跨 Account 切换从该 session 的最新 refresh
  head 请求目标 Organization scope，再一次写入新 session 与 context。多标签页的并发
  refresh 按 WorkOS session ID 串行化。

## 不变量与验收

- 相同 Workspace slug 可存在于不同 Account；资源定位与授权最终只使用不可变 ID。
- Account/Workspace 不匹配、inactive membership、错误 Organization scope 均 fail closed。
- 并发首次登录最多产生一个 Personal Account、一个 default Workspace 和一笔 signup
  grant；失败重试不会产生重复账本条目。
- 一个 Account 内所有 Workspace 读取同一余额，不同 Account 的余额互相隔离。
- 修改 slug 或 display name 不影响资源归属、用量或余额。
- 有效 access token 下，同 Account 切换不发起 scope refresh；跨 Account 切换失败不污染
  有效会话或默认选择。
- invitation 重试和 membership shadow 重放不会产生重复成员。

## 后果

Account 统一承载租户、成员和计费关系，Workspace 只承载资源隔离。Personal 与
Organization 使用同一套 WorkOS Organization scope 和切换协议；代价是 Personal
onboarding 需要一个可观测、可重试的跨系统 provisioning 流程，WorkOS 不可用时相关授权
操作会 fail closed。
