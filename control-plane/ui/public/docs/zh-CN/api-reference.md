## 约定

外部 API 使用 HTTP + JSON。用户资源通过不可变 Workspace ID 确定作用域（`/v1/workspaces/{workspace_id}/…`），可改的 slug 不会出现在资源路由里。已验证 WorkOS 身份只能访问 active Account membership 所拥有的 Workspace；修改 URL 不能凭空产生 membership。

    Authorization: Bearer <short-lived-workos-access-token>
    Accept: application/json
    Content-Type: application/json
    Idempotency-Key: <unique-request-id>   # 变更请求
    If-Match: "<generation>"                # 带并发保护的状态变更

`cats login` 通过 WorkOS Device Authorization 获取并刷新用户 Token，不会把它写入普通配置文件。其他用户客户端必须采用批准的 WorkOS Flow 与相同的已验证 JWT 契约；服务端不接受静态用户 Token。浏览器控制台使用 HttpOnly WorkOS Session，不会向 JavaScript 暴露 Bearer Token。Workspace Manager 可以为 CI 签发可撤销的 `cats_wst_…` 机器凭据；它只授权签发它的不可变 Workspace，且不能继续签发 Token。Service 与 Administrator 机器身份拥有独立权限。

## 身份与 Workspace

    GET  /auth/config       # 公开 WorkOS Client/Base URL 配置
    GET  /v1/me             # 用户资料与可用 Workspace
    GET  /v1/workspaces     # 刷新可用 Workspace 列表
    POST /v1/accounts/{account}/workspaces
    PATCH /v1/workspaces/{workspace}
    GET|POST /v1/workspaces/{workspace}/tokens
    DELETE /v1/workspaces/{workspace}/tokens/{token}
    GET|POST /v1/accounts/{account}/invitations
    POST /v1/accounts/{account}/invitations/{invitation}/actions/revoke
    GET /v1/accounts/{account}/members
    PATCH|DELETE /v1/accounts/{account}/members/{membership}
    POST /v1/auth/logout    # 撤销 CLI WorkOS Session

Workspace 枚举根据 Active WorkOS Organization Membership 返回 Personal/Organization Account。创建或修改 Workspace 需要 Account 管理权限；修改 slug 不会改变不可变 ID，因此所有资源路由继续解析到同一个 Workspace。邀请与成员变更要求 `cats:members:manage`、拒绝 Personal Account，并通过 WorkOS 执行。创建邀请还要求 `Idempotency-Key`，Cats 将其透传给 WorkOS，使网络重试返回同一个 invitation。授权前会校验 Access Token 签名、Issuer、Client ID、过期时间、Subject、Organization Scope、active membership、Account ID 与 Workspace 归属。

创建 Token 返回 `{ "access_token": {…元数据…}, "token": "cats_wst_…" }`；明文 `token` 只返回一次，Cats 只保存其 SHA-256 Digest。List 永远不包含 Secret；撤销会从下一次请求开始生效。

## Cats

    POST   /v1/workspaces/{workspace_id}/cats
    GET    /v1/workspaces/{workspace_id}/cats
    GET    /v1/workspaces/{workspace_id}/cats/{cat}
    DELETE /v1/workspaces/{workspace_id}/cats/{cat}
    POST   /v1/workspaces/{workspace_id}/cats/{cat}/actions/{verb}
    POST   /v1/workspaces/{workspace_id}/cats/{cat}/exec
    GET    /v1/workspaces/{workspace_id}/cats/{cat}/work
    GET    /v1/workspaces/{workspace_id}/cats/{cat}/auto-suspend
    PUT    /v1/workspaces/{workspace_id}/cats/{cat}/auto-suspend

Lifecycle Verb 包括 `start`、`stop`、`suspend`、`resume` 与 `warm`。Create 省略 `auto_suspend` 时默认为 `true`。Cat 的 Create/Lifecycle/Delete 返回异步 Operation；请求超时后应查询 Operation，而不是用新意图重复变更。

Cat、Disk 和 Operation 响应都包含不可变 `workspace_id`，它是唯一的资源归属键。

`exec` 接受 `command`、可选 `timeout_ms`、可选字符串 Map `env` 与可选字节数组 `stdin`。`env` 只传给子进程，不写入 Cats Registry。响应包含 `exit_code`、`stdout` 与 `stderr`。

    POST /v1/workspaces/ws_01J8QK.../cats
    Idempotency-Key: request-7f12

    {
      "name": "dev",
      "image": "ubuntu-24.04",
      "cpus": 2,
      "memory_mib": 2048,
      "root_size_bytes": 8589934592
    }

## 磁盘与快照

    POST   /v1/workspaces/{workspace_id}/disks
    GET    /v1/workspaces/{workspace_id}/disks
    GET    /v1/workspaces/{workspace_id}/disks/{disk}
    DELETE /v1/workspaces/{workspace_id}/disks/{disk}
    POST   /v1/workspaces/{workspace_id}/disks/{disk}/actions/{verb}
    POST   /v1/workspaces/{workspace_id}/disks/{disk}/snapshots
    GET    /v1/workspaces/{workspace_id}/disks/{disk}/snapshots

Disk Action Verb 为 `mount`、`unmount` 与 `resize`。Mount Body 指定 Cat 与 Guest 路径。服务会强制执行 RWO，并拒绝过期或冲突的 Attachment 状态。

## Endpoint

    POST /v1/workspaces/{workspace_id}/cats/{cat}/endpoints
    GET  /v1/workspaces/{workspace_id}/cats/{cat}/endpoints

    {
      "name": "web",
      "target_port": 3000,
      "protocol": "http",
      "wake_policy": "wake_on_request"
    }

## 用量与账单

    GET /v1/workspaces/{workspace_id}/billing/usage
        ?from_ms=<包含的-unix-毫秒>
        &to_ms=<不包含的-unix-毫秒>
        [&cat=<活跃-cat-名称> | &cat_id=<不可变-cat-id>]
        [&bucket_ms=<毫秒>]
        [&detail=true]

开放账期的响应是 `provisional` 预估，包含范围总额、按 Meter 汇总、按 Cat 汇总、不可变 Rate Card ID 与当前最新可见 Interval End。Cat 删除后仍可通过 `cat_id` 查询。`bucket_ms` 返回服务端时间桶，用于曲线和有界时段详单；不得小于 60 秒，且最多产生 512 个时间桶。`detail=true` 返回原始 Ledger Interval，应只用于受控对账查询，避免浏览器直接查询很长范围。

当前 Rate Card 的 CPU 单价为 `$0.07 / CPU-hour`，内存为 `$0.045 / GiB-hour`。十进制 Quantity 与纳美元金额使用 JSON String，防止客户端丢失整数精度。范围总额在聚合后只计价一次；时间桶金额只用于展示预估，不是最终账单。

    GET  /v1/workspaces/{workspace_id}/billing/balance
    POST /v1/workspaces/{workspace_id}/billing/checkout
    Idempotency-Key: <唯一键>
    {"amount_cents": 1000}

新用户只在自己的 Personal Billing Account 获得一次性、不续期的 `$10` 注册赠金；Organization Account、额外 Workspace 和邀请不会产生赠金。余额响应使用 append-only 赠金与充值总额减去全部准实时暂估用量。Checkout 只接受官网公布的固定充值档位，并返回 Stripe 托管支付地址。仅从 Checkout 返回不会入账；Cats 只在收到签名正确且状态为 paid 的 Stripe Webhook 后增加余额。

可用额度耗尽时，付费计算 Admission 返回 HTTP `402` 和 `payment_required` Code；停止、休眠和删除资源仍然可用。

## Operation

    GET /v1/workspaces/{workspace_id}/operations
    GET /v1/operations/{operation}

Operation 包含不可变 `workspace_id` Owner、类型、目标 Resource ID/Generation、阶段、时间戳与可选结构化错误。即使单个 Operation URL 没有 Workspace 分段，访问仍按 Workspace 限制。

## 错误

    {
      "code": "failed_precondition",
      "message": "disk must be available before deletion"
    }

客户端应基于稳定 Code 分支，并把 Message 用作上下文。重要 Code 包括 `invalid_argument`、`unauthenticated`、`permission_denied`、`not_found`、`already_exists`、`failed_precondition`、`payment_required`、`conflict`、`stale_epoch`、`deadline_exceeded`、`unavailable` 与 `internal`。

**版本权威**

本页描述当前 V1 Rust Router。发布自动生成客户端前，应从相同 Request/Resource 类型生成并评审 OpenAPI；不要从架构示例猜测未记录字段。
