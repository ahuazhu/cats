# ADR-0006：浏览器身份使用 WorkOS AuthKit

- 状态：Accepted
- 日期：2026-07-22

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
   `org_id` 只允许访问对应 project；未映射 organization fail closed。
3. Fleet 管理员使用独立 admin session cookie，并且必须同时满足：
   - session 属于配置的管理员 Organization；
   - session permissions 包含 `cats:fleet:admin`（名称可配置）。
   普通 organization member 或只拥有 user cookie 的请求不得访问 admin API。
4. user/admin 使用不同的 AES-GCM sealed、`HttpOnly`、`SameSite=Lax` Cookie。生产
   HTTPS 下 Cookie 必须带 `Secure`。短期 access token 过期后，控制面使用 sealed
   refresh token 向 WorkOS 换取并轮换 session；认证响应不得缓存。
5. `cats` CLI 和内部服务继续使用 Bearer Token：
   - project token 用于 CLI/自动化；
   - admin token 用于 fleet CLI；
   - service token 只用于 node-agent、gateway 与控制器。
   WorkOS session 不得获得 service 权限，Guest 不接收任何上述凭据。
6. WorkOS 配置是可选的。未配置时保留本地 token 登录；配置后 Web 默认隐藏 token
   表单，只有显式启用开发回退时才显示。Bearer API 本身仍保留给 CLI。
7. 使用 WorkOS 官方 Rust SDK 提供的 AuthKit、PKCE 与 sealed-session helper，不自行
   实现密码学协议。由此 workspace 最低 Rust 版本从 1.85 提升到 1.88。

## 安全边界

- `WORKOS_API_KEY`、Cookie password、refresh/access token 不写数据库日志、不返回
  `/auth/config`、不进入前端 JavaScript 或 Guest。
- 登录 flow cookie 最长 10 分钟；回调必须同时匹配 sealed flow、site、state、
  organization 和 return path。
- user/admin session 相互独立；admin session 可以管理所有 Cats projects，但不能
  调用 service-only node/gateway API。
- Project 名称不通过公开认证配置接口枚举；用户从受控入口或邀请链接获得项目名。

## 影响

- WorkOS 不可用时，未过期且已 sealed 的 access token 仍可完成本地校验；新登录和
  到期 refresh 会失败。CLI/service 路径不依赖 WorkOS。
- 每个生产环境需要配置 WorkOS redirect URI、Project/Organization 映射、管理员
  Organization 和权限；生产 Web 必须使用 HTTPS。
- AuthKit 基础登录与企业 SSO/Directory Sync 的商业计费独立，启用企业连接前需要
  将连接成本计入产品套餐。
