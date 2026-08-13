## 约定

外部 API 使用 HTTP JSON。产品资源由 `/v1/workspaces/{workspace_id}/…` 中不可变的 Workspace ID 隔离；可变 slug 不是资源键。浏览器请求使用 HttpOnly WorkOS Session，CLI 与自动化请求使用对应的 WorkOS 或 Workspace Credential。

两个 Create Collection 都要求精确的 `Content-Type: application/json`、且仅出现一次的可打印 `Idempotency-Key`、无 Query 的 canonical Workspace Path，以及下方 closed request body。响应不明确时只能重放完全相同的 Path、Body 与 Key。

## 当前 Cat Surface

    POST /v1/workspaces/{workspace_id}/cats
    GET  /v1/workspaces/{workspace_id}/cats
    GET  /v1/workspaces/{workspace_id}/cats/{cat_id}

    {
      "name": "dev",
      "boot_image_digest": "sha256:<64-lowercase-hex>",
      "vcpus": 2,
      "memory_bytes": 2147483648,
      "root_size_bytes": 1073741824,
      "durability": "strict"
    }

Create 精确返回 `202 application/json` 和 `{"cat_id":"…","operation_id":"…"}`。Collection Read 只接受有界 `limit` 与 opaque `cursor`；Item Read 只接受不可变 `cat_…` ID。

Signed Runtime Cutover 期间，Lifecycle、Exec、Deployment、Endpoint、Expiry、Work Policy 与 Delete Route 不属于 release router。客户端必须在本地失败，不能探测这些路径。

## 当前 PersistentDisk Surface

    POST /v1/workspaces/{workspace_id}/disks
    GET  /v1/workspaces/{workspace_id}/disks
    GET  /v1/workspaces/{workspace_id}/disks/{disk_id}

    {
      "durability": "strict",
      "name": "project-data",
      "size_bytes": 21474836480
    }

Create 以精确的 `201 application/json` 返回已创建 Disk Projection。这个 release 中容量和 Durability 不可变；Item Read 要求不可变 `disk_…` ID。Attachment、Snapshot、容量变更与 Delete Mutation 均不可用。

## Operation

    GET /v1/workspaces/{workspace_id}/operations/{operation_id}

只提供精确 Operation Lookup。鉴权先于查找，其他 Workspace 的 opaque ID 与不存在的 ID 表现相同。没有 Operation Collection，也没有全局 Operation URL。

## Error

Error 使用稳定 JSON `code` 与便于阅读的 `message`。客户端应按 code 分支。Route 不存在不代表可以退回 Legacy Body 或 Mutation Path。

**版本权威**

本页描述 release 产品 Router。Account、Session、Billing 与内部 Signed Authority Route 是独立 Surface，不会重新打开 Cat/Disk Lifecycle Mutation。
