# Cats Guest Runtime API v1

- 状态：Frozen v1（V1 dev shape 已实现）
- 决策依据：[ADR-0007](../decisions/0007-guest-runtime-http-over-unix-socket.md)
- 实现：`protocol/src/guest.rs`、`guest/src/lib.rs`

## 1. 传输与发现

Guest Agent 在下面的 Unix Domain Socket 上提供 HTTP/1.1：

```text
/run/cats/runtime.sock
```

没有默认 TCP/UDP listener。URL 中的 authority 只是 HTTP `Host` 占位，不参与连接：

```bash
curl --unix-socket /run/cats/runtime.sock http://cats-runtime/v1/work-leases
```

V1 每个连接处理一个请求并返回 `Connection: close`。请求 body 使用 `Content-Length`；
不接受 `Transfer-Encoding`。Header 最大 16 KiB，body 最大 64 KiB，单次读写超时 5 秒。
响应带 `Cache-Control: no-store`。

socket 父目录由 Guest 系统管理，普通用户不能替换；socket mode 为 `0666`。任意 Guest
用户可以声明本 Cat 的工作，但不能由此获得 Host、控制面或其他 Cat 的权限。

## 2. 数据类型

### WorkLease

```json
{
  "id": "work_0123456789ab",
  "label": "release-build",
  "remaining_ttl_ms": 299997
}
```

- `id` 是 Guest Agent 生成的不透明标识；客户端不得解析。
- `label` 是最多 64 bytes 的非空 UTF-8 字符串，只用于解释/观测。
- `remaining_ttl_ms` 来自 Guest Agent 单调时钟，是读取时的近似剩余值。

### WorkStatus

```json
{
  "source_epoch": "0123456789abcdef...",
  "lease_sequence": 7,
  "quiescing": false,
  "leases": []
}
```

`source_epoch` 每次 Guest Agent 启动变化；`lease_sequence` 在 acquire、renew、有效
release、TTL 清理，以及 quiesce 窗口中被拒绝的新工作到达时单调增加。它们用于
Guest/Node suspend fence，不是用户身份或持久游标。

## 3. 接口

### 3.1 创建租约

```http
POST /v1/work-leases HTTP/1.1
Content-Type: application/json
Content-Length: ...

{"label":"release-build","ttl_ms":300000}
```

- `ttl_ms` 可省略，默认 300,000 ms（5 分钟）。
- 单次最大 3,600,000 ms（1 小时）；每个 Guest 最多 64 个 live lease。
- 成功：`201 Created`，body 为 `WorkLease`，`Location` 指向新资源。
- Guest 正在 quiesce：`409 activity_changed`；调用方应等待 Cat 保持 Running 后重试。

### 3.2 续租

```http
PUT /v1/work-leases/{lease_id} HTTP/1.1
Content-Type: application/json
Content-Length: ...

{"ttl_ms":300000}
```

- TTL 从本次成功处理时重新开始，不是给原 expiry 累加。
- 成功：`200 OK`，body 为更新后的 `WorkLease`。
- 租约不存在或已过期：`404 lease_not_found`；调用方若仍在工作，应重新 `POST`。
- quiesce 竞态：`409 activity_changed`。

### 3.3 释放租约

```http
DELETE /v1/work-leases/{lease_id} HTTP/1.1
```

成功返回 `204 No Content`。DELETE 幂等：租约已经释放、过期或因 Guest Agent 重启而
消失时也返回 204。最后一个租约释放会推动 sequence，Node 长轮询可立即看到空集合。

### 3.4 查看状态

```http
GET /v1/work-leases HTTP/1.1
```

成功返回 `200 OK` 和 `WorkStatus`。GET 会先清除过期租约，因此可能推进 sequence。

## 4. 错误格式

除 204 外，错误为：

```json
{
  "error": {
    "code": "invalid_request",
    "message": "work TTL must be positive"
  }
}
```

稳定业务错误包括：

| HTTP | code | 含义 |
|---:|---|---|
| 400 | `invalid_request` / `invalid_json` | 字段、TTL 或 JSON 无效 |
| 404 | `not_found` / `lease_not_found` | 路径或续租目标不存在 |
| 405 | `method_not_allowed` | 路径上的 method 不支持 |
| 409 | `activity_changed` | Suspend quiesce 与新工作发生竞态 |
| 413 | `body_too_large` | body 超过 64 KiB |
| 429 | `too_many_leases` | 已达到 64 个 live lease |
| 431 | `headers_too_large` | header 超过 16 KiB |

HTTP 解析类错误 code 也会保持结构化，但客户端不应依赖其完整枚举。

## 5. 运行时语义

租约表达“调用方要求 Cat 暂时保持 Running”，不证明某个 Linux 进程存在，也不替代
应用自己的作业状态。CPU、load、网络静默、监听端口和 `/proc` 扫描不会自动生成租约。

应用应在工作开始前创建租约，在 `ttl/3` 左右续租，并在成功、失败和取消路径释放。
TTL 是进程崩溃/丢 release 的恢复边界，不应把超长 TTL 当永久 pin。

Guest Agent 将租约摘要经 AF_VSOCK 控制协议交给 Node Agent；Node 再上报控制面。
VMM 不访问 Unix socket。Cat Suspended/Warm 后 Guest 不能执行，因此这个 API 不能唤醒
Cat；Gateway、shell/exec 或显式 start 必须先在 Guest 外部触发 wake。

## 6. 普通本机开发

同一份应用在 Cats 外运行时可以检查 socket：

```bash
if [ -S /run/cats/runtime.sock ]; then
  # acquire / renew / release
fi
```

不存在时跳过租约不会阻止应用本身启动。在启用了 Cats auto-suspend 的 Guest 内，
acquire/renew 失败意味着“保持 Running”的保证没有建立；应用应记录或按自身正确性要求
失败，不能由通用包装层静默伪装成成功。
