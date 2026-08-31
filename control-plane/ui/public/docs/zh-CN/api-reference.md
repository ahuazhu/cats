## 约定

外部 API 使用 HTTP JSON。产品资源由 `/v1/workspaces/{workspace_id}/…` 中不可变的 Workspace ID 隔离；可变 slug 不是资源键。浏览器请求使用 HttpOnly WorkOS Session，CLI 与自动化请求使用对应的 WorkOS 或 Workspace Credential。

两个 Create Collection 都要求精确的 `Content-Type: application/json`、且仅出现一次的可打印 `Idempotency-Key`、无 Query 的 canonical Workspace Path，以及下方 closed request body。Lifecycle Action 则要求空 Body 且不能发送 `Content-Type`。响应不明确时只能重放完全相同的 Path、Body 与 Key。

## 当前 Cat Surface

    POST /v1/workspaces/{workspace_id}/cats
    GET  /v1/workspaces/{workspace_id}/cats
    GET  /v1/workspaces/{workspace_id}/cats/{cat_id}
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/run
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/suspend
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/warm
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/cold
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/destroy

    {
      "name": "dev",
      "vcpus": 2,
      "memory_bytes": 2147483648,
      "root_size_bytes": 1073741824,
      "durability": "strict"
    }

Control 会自动为新 Cat 绑定部署当前已资格化的 Boot Image。Request 不接受镜像覆盖，已有 Cat 始终保留创建时的精确 Digest。

Create 精确返回 `202 application/json` 和 `{"cat_id":"…","operation_id":"…"}`。Collection Read 只接受有界 `limit` 与 opaque `cursor`；Item Read 和 Lifecycle Action 只接受不可变 `cat_…` ID。

每个 Lifecycle Action 都要求且只要求一个 `Idempotency-Key`、空 Body，并且不能发送 `Content-Type`；成功时精确返回 `202 application/json` 和 `{"operation_id":"op_…"}`。不明确响应保持 Pending，必须逐字节重放；已退役的 `start`、`stop`、`delete` 与 `resume` Route 不是兼容别名。Exec、Deployment、Endpoint、Expiry 与 Work Policy Mutation 仍不属于本 release router。

## 当前 PersistentDisk Surface

    POST /v1/workspaces/{workspace_id}/disks
    GET  /v1/workspaces/{workspace_id}/disks
    GET  /v1/workspaces/{workspace_id}/disks/{disk_id}
    POST /v1/workspaces/{workspace_id}/disks/{disk_id}/actions/attach
    POST /v1/workspaces/{workspace_id}/disks/{disk_id}/actions/detach

    {
      "durability": "strict",
      "name": "project-data",
      "size_bytes": 21474836480
    }

Create 以精确的 `201 application/json` 返回已创建 Disk Projection。这个 release 中容量和 Durability 不可变；Item Read 要求不可变 `disk_…` ID。Attach/Detach 是只用于终态 Cold Cat 的同步、幂等产品事务，两者都使用 closed body `{"cat_id":"cat_…","mount_path":"/absolute/guest/path"}`。容量变更 Mutation 不可用。

## DiskSnapshot Surface

    POST /v1/workspaces/{workspace_id}/snapshots
    GET  /v1/workspaces/{workspace_id}/snapshots
    GET  /v1/workspaces/{workspace_id}/snapshots/{snapshot_slug}
    POST /v1/workspaces/{workspace_id}/snapshots/{snapshot_slug}/actions/restore
    POST /v1/workspaces/{workspace_id}/snapshots/{snapshot_slug}/actions/destroy

Create 使用 closed body `{"snapshot_slug":"before-upgrade","disk_slug":"project-data"}`。Restore 使用 closed body `{"expected_generation":42}`；它是目标磁盘的最新 Generation，不是 Snapshot 捕获时的 Generation。Restore 成功会把捕获的 Root 发布为 Generation 43，并返回 `disk_head_generation: 43`。Destroy 使用空 Body。这些同步 Route 不接收 Idempotency-Key，也不创建 Operation。

Snapshot Projection 暴露不可变 Snapshot/Disk ID、当前 Slug、容量、状态、捕获 Generation 与创建/删除时间，绝不暴露内部 Root Hash 或 Object Key。第一版只支持恢复到原盘；Clone、Hot Snapshot 与跨 Workspace Copy 都不是可用 Route。

## Operation

    GET /v1/workspaces/{workspace_id}/operations/{operation_id}

Cat Create 和每个 Lifecycle Action 都返回 Operation ID。只提供精确 Operation Lookup；产品投影只包含 `create`、`run`、`suspend`、`warm`、`cold`、`destroy`，以及 `in_progress`、`succeeded`、`failed`，不会返回 Node 执行命令或证据。鉴权先于查找，其他 Workspace 的 opaque ID 与不存在的 ID 表现相同。没有 Operation Collection，也没有全局 Operation URL。

## Error

Error 使用稳定 JSON `code` 与便于阅读的 `message`。客户端应按 code 分支。Route 不存在不代表可以退回 Legacy Body 或 Mutation Path。

**版本权威**

本页描述 release 产品 Router。Account、Session、Billing 与内部 Signed Authority Route 是独立 Surface，不会重新打开 Cat/Disk Lifecycle Mutation。
