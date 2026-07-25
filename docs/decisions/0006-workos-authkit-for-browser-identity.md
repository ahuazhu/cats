# ADR-0006：浏览器身份使用 WorkOS AuthKit

- 状态：Accepted
- 日期：2026-07-22

> CLI project token 部分已由 ADR-0008 取代；本 ADR 的浏览器 session、组织映射和
> user/admin 隔离决定继续有效。无 Organization 的 Personal Project 及
> Organization/Workspace 一一映射已由 ADR-0014 取代。

## 背景

V1 开发控制面最初只接受静态 Bearer Token。它适合 node-agent、gateway、CLI 和
自动化测试，但不适合作为生产 Web 登录：浏览器需要用户身份、组织成员关系、短期
会话、登出、MFA/SSO 扩展点，以及 user/admin 两个站点之间明确的权限边界。

完整产品架构已经要求 Edge/API Gateway 校验 OIDC/session/API token 并生成 tenant
context。本 ADR 确定当前 Rust 控制面中浏览器身份的具体实现，同时保留已有机器和
CLI 调用契约。

## 决定

1. 嵌入式 user/admin Web 站点使用 **WorkOS AuthKit Hosted UI** 登录。授权码流程
   必须使用 PKCE 和随机 `state`；回调在服务端交换 code，WorkOS API Key 不进入
   浏览器。
2. WorkOS Organization 与 Cats Project 通过显式配置一一映射。用户 session 的
   `org_id` 只允许访问对应 project；未映射 organization fail closed。没有
   Organization membership 的 AuthKit 用户只在 user 站获得由 WorkOS `user_id`
   确定的独立个人 Project（`personal-<user_id>`），不得回落到共享 Project。该例外
   不适用于 admin 站。
3. Fleet 管理员使用独立 admin session cookie，并且必须同时满足：
   - session 属于配置的管理员 Organization；
   - session permissions 包含 `cats:fleet:admin`（名称可配置）。
   普通 organization member 或只拥有 user cookie 的请求不得访问 admin API。
4. user/admin 使用不同的 AES-GCM sealed、`HttpOnly`、`SameSite=Lax` Cookie。生产
   HTTPS 下 Cookie 必须带 `Secure`。短期 access token 过期后，控制面使用 sealed
   refresh token 向 WorkOS 换取并轮换 session；认证响应不得缓存。
5. 内部服务继续使用独立 Bearer Token：service token 只用于 node-agent、gateway 与
   控制器，admin token 用于 fleet 自动化。普通用户 CLI 鉴权已由 ADR-0008 改为
   WorkOS Device Login，不再使用 project token。WorkOS session 不得获得 service
   权限，Guest 不接收任何上述凭据。
6. user/admin Web 站点只使用 WorkOS 登录，不提供静态 Token 表单或开发回退。
   WorkOS 未配置时浏览器站点 fail closed。Bearer API 本身仍保留给 CLI 和内部服务。
7. 使用 WorkOS 官方 Rust SDK 提供的 AuthKit、PKCE 与 sealed-session helper，不自行
   实现密码学协议。由此 workspace 最低 Rust 版本从 1.85 提升到 1.88。
8. 公共 user 入口不预先枚举 Project。若 WorkOS Hosted UI 因现有登录上下文返回一个
   未映射 Organization，但该用户的 active membership 与部署映射的交集恰好只有一个
   Workspace，控制面使用 WorkOS refresh-token organization switching 将该 session
   切换到唯一候选后再授权。候选为零个或多个时 fail closed；无 Organization session
   的个人 Project 行为不变。该规则避免同时拥有平台管理员 Organization 和一个用户
   Workspace 的账号被管理员登录上下文挡在 user 站之外。

## 安全边界

- `WORKOS_API_KEY`、Cookie password、refresh/access token 不写数据库日志、不返回
  `/auth/config`、不进入前端 JavaScript 或 Guest。
- 登录 flow cookie 最长 10 分钟；回调必须同时匹配 sealed flow、site、state 和
  return path。组织 session 必须匹配请求的 organization；仅 user 站允许无组织
  session 进入其确定性的个人 Project。自动 organization switching 前必须从 WorkOS
  重新读取 active memberships；切换后的 user ID、organization ID 和显式 Project
  映射必须全部匹配，否则拒绝登录。
- user/admin session 相互独立；admin session 可以管理所有 Cats projects，但不能
  调用 service-only node/gateway API。
- Project 名称不通过公开认证配置接口枚举。公共用户入口先完成 WorkOS 认证，再从
  已验证的 Organization membership 或 WorkOS user ID 确定工作区；受控邀请链接仍可
  显式指定团队或个人 Project，并在回调时重新校验身份匹配。

## 影响

- WorkOS 不可用时，未过期且已 sealed 的浏览器 access token 仍可完成本地校验；新
  登录和到期 refresh 会失败。CLI 的详细失败语义见 ADR-0008；service 路径不依赖
  WorkOS。
- 每个生产环境需要配置 WorkOS redirect URI、团队 Project/Organization 映射、
  管理员 Organization 和权限；无组织用户的个人 Project 无需预配置。生产 Web
  必须使用 HTTPS。
- AuthKit 基础登录与企业 SSO/Directory Sync 的商业计费独立，启用企业连接前需要
  将连接成本计入产品套餐。
