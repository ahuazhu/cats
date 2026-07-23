# ADR-0008：CLI 使用 WorkOS Device Login 与多 Workspace 会话

- 状态：Accepted
- 日期：2026-07-22
- 取代：ADR-0006 第 5 条中的 CLI project token 决定；其浏览器与机器身份决定继续有效

## 背景

早期 `cats` CLI 默认使用静态 `dev-token`，控制面通过
`CATS_PROJECT_TOKENS=PROJECT=TOKEN` 把一个 token 固定到一个 Project。这种方式无法
标识真实用户、无法继承 WorkOS 的停用/MFA/组织成员关系，也让一个用户切换多个
workspace 时必须人工分发多份长期 secret。

Sprites CLI 的交互把“登录身份”和“当前组织选择”分开：用户登录一次，保存一个默认
组织，也可以对单条命令覆盖。本 ADR 采用这一用户模型，但沿用 Cats 已有的
Project 资源命名空间。

## 决定

1. `cats login` 使用 WorkOS AuthKit Device Authorization Grant。CLI 从控制面的
   `/auth/config` 读取公开 `client_id` 和 WorkOS API base URL，向用户显示验证 URL 与
   `user_code`，轮询时绝不显示或记录 `device_code`。`WORKOS_API_KEY` 不进入 CLI。
2. CLI access/refresh token 只保存在操作系统凭据存储（macOS Keychain、Windows
   Credential Manager、Linux Secret Service）。普通配置文件只保存 API URL、用户
   展示信息、可用 workspace 和当前选择，不保存任何 token。
3. 控制面把 CLI access token 当作 WorkOS 签发的短期 JWT：按 `kid` 获取并缓存 JWKS，
   只接受 RS256，验证签名、`exp`、`iss`、`sub` 和 `client_id`。不得用未验签 payload
   生成 tenant context。`WORKOS_ISSUER` 必须显式配置为当前 WorkOS Application
   access token 中的精确 `iss` claim（当前格式为
   `https://api.workos.com/user_management/<default-client-id>`），不得使用 AuthKit
   登录页面域名、关闭 issuer 校验，或只校验裸 WorkOS API base URL。
4. 用户可用 workspace 来自其 **active WorkOS Organization membership** 与
   `CATS_WORKOS_PROJECT_ORGANIZATIONS` 显式映射的交集。未映射 Organization fail
   closed，不向 CLI 暴露。无 Organization session 仍只能访问由 WorkOS `user_id`
   决定的 `personal-<user_id>` workspace。
5. `cats workspace use <slug>` 保存默认 workspace，并用 refresh token 向 WorkOS
   换取目标 `organization_id` 范围的新 access token。每个资源请求的 URL Project
   必须与已验证 JWT 的 `org_id` 映射一致；仅仅修改本地 workspace 字符串不能越权。
   `--workspace <slug>` / `CATS_WORKSPACE` 只覆盖当前命令，不修改默认选择。
6. 提供 `cats whoami`、`cats workspace list` 和 `cats logout`。登出先尝试撤销 WorkOS
   session，然后无条件删除本地凭据；远端暂时不可用不能阻止本地登出。
7. 删除 `CATS_PROJECT_TOKENS`、`--project-token` 及服务端静态用户 token 校验路径。
   当前实现从未建立 project token 数据表，因此不需要数据迁移或保留兼容列。
8. `CATS_AUTH_TOKEN` 继续只用于 node-agent/gateway/controller；
   `CATS_ADMIN_TOKEN` 暂时保留为 fleet 自动化的 break-glass 机器凭据。两者都不是普通
   用户登录方式，Guest 永远不会收到这些凭据。

### macOS 凭据存储实现

macOS 上的 CLI 通过 Apple 自带且路径固定的 `/usr/bin/security` 访问 Keychain，而不由
每次本地构建产生的新 `cats` 二进制直接调用 Security.framework。这与
[GitHub CLI 使用的 macOS keyring 实现](https://github.com/zalando/go-keyring/blob/v0.2.8/keyring_darwin.go)
一致，可避免 ad-hoc 签名或二进制哈希变化让 Keychain 把每次构建识别成新的访问方。
读取和删除使用独立参数；写入使用 `security -i`，只通过 stdin 传递 Base64 编码后的
凭据，token 不得进入进程参数、日志或错误信息。调用最长等待 60 秒。

旧版 `cats` 写入的同 service/account 原始 JSON 可继续读取；后续登录或 token 刷新会
原位改写为带编码前缀的 Base64 表示。Windows 与 Linux 继续分别使用系统 Credential
Manager 与 Secret Service。正式 macOS 发行包仍应使用稳定 Developer ID 签名并完成
notarization；本实现同时改善频繁变化的本地开发二进制体验。

## 安全与失败语义

- email 只用于展示；稳定用户主键是 WorkOS `sub`（user ID）。
- access token 过期前 CLI 使用旋转 refresh token 换新；refresh 后返回的
  `organization_id` 必须与所选 workspace 完全一致，否则切换失败且不更新本地选择。
- WorkOS membership/JWKS 暂时不可用时，workspace 枚举或首次 key fetch 返回 `503`；
  未知、过期、签名错误或其他 Application 的 JWT 返回 `401`；有效身份访问其他
  workspace 返回 `403`。
- 本地 JSON 配置使用 `0600` 创建，但其内容仍按公开元数据对待；秘密只进入系统
  credential store。

## 影响

- 本地开发若不配置 WorkOS，普通用户 CLI fail closed；组件/E2E 测试可显式使用
  admin machine credential 驱动资源路径，用户授权契约由 WorkOS JWT 集成测试覆盖。
- 一个用户加入或退出 Organization 后，下一次 `cats workspace list` 反映最新成员关系；
  已撤销成员的旧短期 token 最迟在 session/token 到期时失效，服务端仍按 token
  `org_id` 和显式映射限制资源范围。
- 当前 workspace 的产品名与 CLI 统一为 Workspace；底层 `/v1/projects/{project}`
  路径和资源表 `project` 列保持兼容，后续 API 大版本再决定是否改名。
