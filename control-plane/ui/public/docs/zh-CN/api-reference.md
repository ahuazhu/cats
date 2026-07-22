## 约定

外部 API 使用 HTTP + JSON。用户资源通过兼容路径 `/v1/projects/{project}/…` 确定作用域，其中 Project 值是面向用户的 Workspace Slug。已验证 WorkOS 身份只能访问当前选择的 Workspace；修改 URL 不能改变授权上下文。

    Authorization: Bearer <short-lived-workos-access-token>
    Accept: application/json
    Content-Type: application/json
    Idempotency-Key: <unique-request-id>   # 变更请求
    If-Match: "<generation>"                # 带并发保护的状态变更

`cats login` 通过 WorkOS Device Authorization 获取并刷新用户 Token，不会把它写入普通配置文件。其他用户客户端必须采用批准的 WorkOS Flow 与相同的已验证 JWT 契约；服务端不接受静态 Project Token。浏览器控制台使用 HttpOnly WorkOS Session，不会向 JavaScript 暴露 Bearer Token。Service 与 Administrator 机器身份拥有独立权限。

## 身份与 Workspace

    GET  /auth/config       # 公开 WorkOS Client/Base URL 配置
    GET  /v1/me             # 用户资料与可用 Workspace
    GET  /v1/workspaces     # 刷新可用 Workspace 列表
    POST /v1/auth/logout    # 撤销 CLI WorkOS Session

Workspace 枚举返回拥有显式部署映射的 Active WorkOS Organization Membership；无 Organization 用户还会获得隔离的个人 Workspace。授权资源路径前，服务端会验证用户 Access Token 的签名、Issuer、Client ID、过期时间、Subject 与 Organization Scope。

## Cats

    POST   /v1/projects/{project}/cats
    GET    /v1/projects/{project}/cats
    GET    /v1/projects/{project}/cats/{cat}
    DELETE /v1/projects/{project}/cats/{cat}
    POST   /v1/projects/{project}/cats/{cat}/actions/{verb}
    POST   /v1/projects/{project}/cats/{cat}/exec
    GET    /v1/projects/{project}/cats/{cat}/work
    GET    /v1/projects/{project}/cats/{cat}/auto-suspend
    PUT    /v1/projects/{project}/cats/{cat}/auto-suspend

Lifecycle Verb 包括 `start`、`stop`、`suspend`、`resume` 与 `warm`。Create 省略 `auto_suspend` 时默认为 `true`。Cat 的 Create/Lifecycle/Delete 返回异步 Operation；请求超时后应查询 Operation，而不是用新意图重复变更。

    POST /v1/projects/acme-dev/cats
    Idempotency-Key: request-7f12

    {
      "name": "dev",
      "image": "ubuntu-24.04",
      "cpus": 2,
      "memory_mib": 2048,
      "root_size_bytes": 8589934592
    }

## 磁盘与快照

    POST   /v1/projects/{project}/disks
    GET    /v1/projects/{project}/disks
    GET    /v1/projects/{project}/disks/{disk}
    DELETE /v1/projects/{project}/disks/{disk}
    POST   /v1/projects/{project}/disks/{disk}/actions/{verb}
    POST   /v1/projects/{project}/disks/{disk}/snapshots
    GET    /v1/projects/{project}/disks/{disk}/snapshots

Disk Action Verb 为 `mount`、`unmount` 与 `resize`。Mount Body 指定 Cat 与 Guest 路径。服务会强制执行 RWO，并拒绝过期或冲突的 Attachment 状态。

## Endpoint

    POST /v1/projects/{project}/cats/{cat}/endpoints
    GET  /v1/projects/{project}/cats/{cat}/endpoints

    {
      "name": "web",
      "target_port": 3000,
      "protocol": "http",
      "wake_policy": "wake_on_request"
    }

## Operation

    GET /v1/projects/{project}/operations
    GET /v1/operations/{operation}

Operation 包含 Workspace Owner（存储字段仍为 Project）、类型、目标 Resource ID/Generation、阶段、时间戳与可选结构化错误。即使单个 Operation URL 没有 Project 分段，访问仍按 Workspace 限制。

## 错误

    {
      "code": "failed_precondition",
      "message": "disk must be available before deletion"
    }

客户端应基于稳定 Code 分支，并把 Message 用作上下文。重要 Code 包括 `invalid_argument`、`unauthenticated`、`permission_denied`、`not_found`、`already_exists`、`failed_precondition`、`conflict`、`stale_epoch`、`deadline_exceeded`、`unavailable` 与 `internal`。

**版本权威**

本页描述当前 V1 Rust Router。发布自动生成客户端前，应从相同 Request/Resource 类型生成并评审 OpenAPI；不要从架构示例猜测未记录字段。
