## 公开站点与控制台

产品站与文档无需登录即可访问。用户控制台 [`/user/`](/user/) 和管理员控制台 `/admin/` 可以在无凭据时加载，以便发起登录；但有效会话建立前不能读取资源数据。控制台与认证路由会向搜索引擎声明禁止索引。

## WorkOS 浏览器登录

1.  选择**使用 WorkOS 登录**。
2.  服务端发起带 PKCE 与短期 sealed state cookie 的 Authorization Code Flow。
3.  回调后，服务端仅在加密 HttpOnly session cookie 中保存 access/refresh 信息。
4.  页面调用与 CLI 相同的 Workspace 级资源 API；JavaScript 中没有 Service Credential。

WorkOS 未配置时，浏览器站点会 fail closed 并显示面向管理员的说明，不会退回 Token 输入表单。

## CLI Device Login

`cats login` 启动 WorkOS Device Authorization，显示验证 URL/Code，并在可能时打开浏览器。Access Token 与轮换 Refresh Token 只保存在操作系统凭据存储；权限为 `0600` 的 CLI 配置文件只包含 API URL、公开用户/Workspace 数据与当前选择。使用 `cats whoami`、`cats workspace list`、`cats workspace use SLUG` 与 `cats logout` 管理会话。

## Workspace

WorkOS Organization 必须显式映射到一个 Cats Workspace。未映射 Organization 不能被枚举或访问。没有 Organization Membership 的用户会基于已验证 WorkOS User ID 获得确定性的个人 Workspace。

**用户名称与 API 兼容性**

CLI 与控制台把该边界称为 *Workspace*。V1 HTTP API 路径和资源库列仍保留兼容名称 `project`；修改 URL 字符串不能改变已验证身份建立的 Workspace。

登录与选择相互独立。`cats workspace use acme-dev` 保存默认值并获取 Organization 范围的 Access Token；`--workspace acme-prod` 仅覆盖一条命令，不改变默认选择。

## 用户控制台

控制台提供：

- 当前工作区的 Cats、休眠状态、磁盘与活跃 Operation 概览。
- Cat 的创建、启动、Suspend、Warm、Stop、Exec、Expose 与 Destroy。
- 磁盘的创建、Snapshot、Mount、Unmount、Resize 与 Delete。
- 结构化状态/错误展示与自动 Session Refresh。

## 语言切换

用户与管理员控制台均支持英语和简体中文。默认读取 `navigator.languages`/`navigator.language`。手动选择会保存在当前站点的本地存储，并更新静态文案、动态状态/操作、表单标签、错误、日期、数字格式、文档标题与 `html lang`。

语言偏好只影响显示，不会改变 Session、Workspace 映射、权限、资源值或 API 行为。

## 管理员隔离

管理员站点使用独立 Cookie，并且必须同时满足已配置的管理员 Organization 与 Fleet Permission（通常为 `cats:fleet:admin`）。普通 Organization Member 或用户控制台 Cookie 不能调用 Fleet API。

## 退出与 Session 失败

浏览器退出会请求 WorkOS 撤销远端 Session 并清理本地 Cookie。Session 过期后，控制台会尝试服务端 Refresh；Refresh 失败或无权限时返回登录页。`cats logout` 会尝试远端撤销，即使网络不可用也会删除本地 Keychain 凭据。认证响应使用 `no-store`。
