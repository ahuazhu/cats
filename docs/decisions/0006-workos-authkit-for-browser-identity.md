# ADR-0006：浏览器身份使用 WorkOS AuthKit

- 状态：Accepted
- 日期：2026-07-22
- 相关：[ADR-0014](0014-account-workspace-identity-billing-and-switching.md)、
  [ADR-0018](0018-remove-the-v1-project-compatibility-layer.md)

## 背景

浏览器入口需要用户身份、Organization membership、短期会话、登出、MFA/SSO 扩展点，
并且必须把用户站、管理员站和机器身份隔离。Cats 的资源归属是 Account/Workspace；WorkOS
负责用户认证和 Organization membership，Cats 负责把已验证身份映射为不可变的
`account_id` / `workspace_id` 并执行资源授权。

## 决策

1. 嵌入式 user/admin Web 站点使用 **WorkOS AuthKit Hosted UI**。授权码流程使用 PKCE 和
   随机 `state`；回调由服务端通过官方 SDK 交换 code，WorkOS API key 不进入浏览器。
2. WorkOS Organization scope 解析为一个 Cats Account。Account 内的 Workspace 选择必须
   再校验 Workspace ownership 与 active membership；slug、email、显示名和浏览器本地状态
   都不是授权主键。
3. Personal 与 Organization Account 都遵循 ADR-0014 的领域模型。Personal Account 只允许
   owner，Organization Account 的可见性和权限来自 active WorkOS membership。部署预置的
   Organization 使用显式 Account slug 到 WorkOS Organization ID 的映射；未映射身份
   fail closed。
4. user/admin 使用不同的 AES-GCM sealed、`HttpOnly`、`SameSite=Lax` Cookie。生产 HTTPS
   Cookie 带 `Secure`。Cookie 保存当前 Organization scope、Account、Workspace 和旋转
   refresh token；服务端忽略客户端提交的 Account identity，并从 session 与 membership
   重新解析。
5. 同一 Account 内切换 Workspace 只更新经过校验的 Workspace context。跨 Account 切换通过
   旋转 refresh token 请求目标 Organization scope，验证返回的 user/organization identity
   后原子替换 session。并发 refresh 按 session 串行，失败不覆盖仍有效的 session。
6. Fleet 管理员使用独立 admin session，并且必须同时属于配置的管理员 Organization、持有
   `cats:fleet:admin` permission。普通 user session 或普通 Organization member 不能访问
   admin API。
7. node-agent、Gateway、Controller 和 fleet 自动化使用独立机器凭据。WorkOS session 不获得
   service 权限，Guest 不接收 WorkOS、Cookie、service 或 admin 凭据。
8. WorkOS 未配置时浏览器入口 fail closed，不提供静态 token 登录表单。未过期且已 sealed 的
   session 可以继续本地验证；新登录、membership refresh 和 token refresh 需要 WorkOS。

## 安全与验收

- `WORKOS_API_KEY`、Cookie password、access/refresh token 不进入前端 JavaScript、公开配置、
  数据库日志、错误响应或 Guest。
- 登录 flow cookie 有界过期；回调必须匹配 site、sealed flow、`state` 和允许的 return path，
  code/state 重放必须失败。
- 每次资源请求最终按不可变 `account_id` / `workspace_id` 和 active membership 授权；跨
  Workspace、跨 Account、inactive membership 和 scope 不匹配全部 fail closed。
- user/admin Cookie、权限和路由彼此隔离；admin session 不能调用 service-only Node/Gateway
  API。
- refresh token 轮换、跨 Account 切换、多标签页并发及 WorkOS 暂时不可用均有回归测试，失败
  不清空或降权绕过一个仍有效的 session。

## 后果

浏览器身份由 WorkOS 承担，资源授权仍由 Cats 的 Account/Workspace 模型承担。新登录和会话
续期依赖 WorkOS；已经 Running 的数据面和机器服务路径不依赖浏览器身份服务。
