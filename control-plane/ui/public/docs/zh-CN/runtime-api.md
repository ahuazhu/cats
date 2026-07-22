## 用途与发现

Cat 内的应用通过工作租约表达“此任务活跃期间保持 Cat Running”。API 使用 Guest 本地 Unix socket 上的 HTTP/1.1 + JSON：

    /run/cats/runtime.sock

    curl --unix-socket /run/cats/runtime.sock \
      http://cats-runtime/v1/work-leases

没有默认 TCP/UDP Listener，不要求 Cats SDK，协议中也没有控制面或对象存储凭据。任何支持 Unix socket 的 HTTP 客户端都能调用。

## 创建工作租约

    curl --unix-socket /run/cats/runtime.sock \
      -H 'Content-Type: application/json' \
      -d '{"label":"release-build","ttl_ms":300000}' \
      http://cats-runtime/v1/work-leases

成功返回 `201 Created`、生成的不透明 Lease ID 和剩余 TTL。默认 TTL 为 5 分钟，最大 1 小时，每个 Guest 最多有 64 个活跃租约。

## 续租与释放

    curl --unix-socket /run/cats/runtime.sock \
      -X PUT -H 'Content-Type: application/json' \
      -d '{"ttl_ms":300000}' \
      http://cats-runtime/v1/work-leases/LEASE_ID

    curl --unix-socket /run/cats/runtime.sock \
      -X DELETE \
      http://cats-runtime/v1/work-leases/LEASE_ID

建议在 TTL 约三分之一处续租。DELETE 幂等，即使租约已经过期也返回 `204`。成功、失败与取消路径都应释放；TTL 是进程崩溃时的恢复边界。

## 查看状态

    curl --unix-socket /run/cats/runtime.sock \
      http://cats-runtime/v1/work-leases

响应包括 `source_epoch`、单调递增的 `lease_sequence`、`quiescing` 与当前租约。ID 与 sequence 是不透明协调值，不是用户身份或持久游标。

## 稳定错误

| HTTP | Code | 处理方式 |
|----|----|----|
| 400 | `invalid_request` / `invalid_json` | 修正字段、TTL 或 JSON。 |
| 404 | `lease_not_found` | 工作仍活跃时创建新租约。 |
| 409 | `activity_changed` | Suspend quiesce 与新工作竞态；确认 Cat 继续 Running 后重试。 |
| 429 | `too_many_leases` | 释放或合并调用方。 |

## 重要语义

- 租约会阻止工作驱动 Suspend，但不证明某个 Linux 进程仍存在。
- 该 socket 无法唤醒已经休眠的 Cat，因为此时 Guest 代码不能运行。
- 如果 socket 存在但 acquire/renew 失败，则 keep-awake 保证没有建立。
- 在普通本机环境中，应用可以检测 socket 不存在，并按自身策略继续。

**不要在 Cats 内静默忽略失败**

如果任务正确性依赖保持 Running，请暴露 acquire/renew 失败，并明确决定是否停止任务。
