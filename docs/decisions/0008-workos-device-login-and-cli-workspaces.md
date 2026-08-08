# ADR-0008：CLI 使用 WorkOS Device Login 与 Workspace 会话

- 状态：Accepted
- 日期：2026-07-22
- 取代：ADR-0006 中 CLI 使用静态用户凭据的决定
- 细化：Account、Workspace 与会话切换由 ADR-0014 定义；资源归属与路由由
  ADR-0018 定义

## 背景

CLI 需要代表真实用户访问其有权使用的 Workspace，并在一次登录后安全切换当前
Workspace。登录身份、WorkOS Organization scope 和本地 Workspace 选择是三个相关但
不同的状态；客户端显示的名称和缓存都不能成为授权依据。

## 决定

### 登录与凭据

1. `cats login` 使用 WorkOS AuthKit Device Authorization Grant。CLI 从控制面的
   `/auth/config` 读取公开 `client_id` 和 WorkOS API base URL，显示验证 URL 与
   `user_code`，并轮询授权结果。`device_code` 不进入输出、日志或错误信息，
   `WORKOS_API_KEY` 不进入 CLI。
2. Access token 和轮换 refresh token 只保存在操作系统凭据存储。权限为 `0600` 的普通
   配置文件只保存 API URL、用户展示信息、可用 Workspace 和当前选择。
3. 控制面把 CLI access token 当作 WorkOS 签发的短期 JWT。它按 `kid` 获取并缓存 JWKS，
   只接受 RS256，并验证签名、`exp`、精确 `iss`、`sub`、`sid` 和 `client_id`。不得使用
   未验签 payload 建立身份或 Workspace 上下文；`WORKOS_ISSUER` 必须匹配当前
   Application access token 的 issuer。

### Workspace 选择

1. 用户可见的 Account 和 Workspace 来自已验证的 WorkOS 身份、active Organization
   membership 与本地不可变 Account/Workspace 记录。未知 Organization、inactive
   membership 或标识不一致都 fail closed。
2. `cats workspace use <locator>` 保存默认选择；`--workspace <locator>` 与
   `CATS_WORKSPACE` 只覆盖当前命令。locator 可以是无歧义的 Workspace slug、
   `account/workspace` 或不可变 Workspace ID，资源请求最终只使用 Workspace ID。
3. 同一 Account 内切换 Workspace 不改变 WorkOS Organization scope，只更新本地选择；
   access token 的正常到期刷新独立进行。跨 Account 切换使用当前轮换 refresh token 请求
   目标 Organization scope，并验证返回的用户 ID 和 `organization_id` 后原子替换凭据与
   选择。
4. CLI 对同一凭据使用跨进程排他锁；拿锁后重新读取最新 refresh token，防止并发进程
   重复消费轮换凭据。刷新或校验失败时不修改当前选择，也不覆盖有效凭据。
5. CLI 提供 `cats whoami`、`cats workspace list`、`cats workspace use` 和
   `cats logout`。登出尝试撤销远端会话，并始终删除本地凭据；远端暂时不可用不能阻止
   本地登出。

### 机器身份

WorkOS Device Login 是普通用户入口。Workspace machine token、组件 service token 和
administrator token 使用各自的有限权限，不冒充用户会话；这些凭据都不会进入 Guest。

### macOS 凭据存储

macOS CLI 通过路径固定的 `/usr/bin/security` 访问 Keychain，避免频繁变化的本地构建
被识别成不同访问方。读取与删除使用独立参数；写入使用 `security -i`，只从 stdin 传入
带编码前缀的 Base64 凭据。token 不进入进程参数、日志或错误信息，调用最长等待 60 秒。
Windows 与 Linux 分别使用 Credential Manager 与 Secret Service。

## 失败与安全语义

- email 和 display name 只用于展示；稳定用户主键是 WorkOS `sub`。
- Workspace 枚举、切换与资源授权都重新验证不可变 ID 和 active membership。
- WorkOS membership 或 JWKS 暂时不可用时返回 `503`；未知、过期、签名错误或属于其他
  Application 的 JWT 返回 `401`；有效身份访问无权 Workspace 返回 `403`。
- 本地 Workspace 缓存只改善导航体验，不能扩大服务端授权。

## 验收

- CLI 登录过程中不接触 WorkOS API key，不泄露 `device_code`，普通配置文件不含 token。
- 伪造、过期、错误 issuer、错误 client 或非 RS256 JWT 均不能建立会话。
- 有效 access token 下，同 Account 切换不发起 scope refresh；跨 Account 切换只提交一次
  成功的 token 轮换。
- 两个并发 CLI 进程不会同时消费同一个 refresh token。
- 登出在远端撤销失败时仍清除本地凭据。
