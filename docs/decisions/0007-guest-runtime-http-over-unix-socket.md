# ADR-0007：Guest Runtime API 使用 Unix Socket 上的 HTTP

- 状态：Accepted
- 日期：2026-07-22

## 背景

工作驱动的快速休眠需要 Guest 内用户程序显式创建、续租和释放工作租约。第一版实现
在 `/run/cats/work.sock` 上使用 Cats 私有的长度前缀 JSON 帧，并提供
`cats-guest-work` CLI。这个形态会让用户误以为应用必须链接 Cats SDK 或依赖一个
预装 CLI；如果改用固定 TCP 端口，又会引入端口登记、Guest 内监听冲突和不必要的
网络暴露。

Cats 对用户应当是运行时沙箱。应用可以选择使用运行时能力，但不应为此依赖 Cats
特有的客户端实现。

## 决定

1. Guest 内的稳定运行时入口为 `/run/cats/runtime.sock`。Guest Agent 在该 Unix
   socket 上提供 HTTP/1.1 + JSON，不默认监听任何 TCP 或 UDP 端口。
2. V1 工作租约 API 为：
   - `POST /v1/work-leases`：创建；请求 `{"label":"build","ttl_ms":300000}`；
   - `PUT /v1/work-leases/{lease_id}`：续租；请求 `{"ttl_ms":300000}`；
   - `DELETE /v1/work-leases/{lease_id}`：释放；
   - `GET /v1/work-leases`：列出 Guest 当前租约和序列状态。
3. 协议不要求 Cats SDK 或 CLI。任何能通过 Unix socket 发送 HTTP 的通用客户端都
   可以调用；`cats-guest-work` 只保留为可选便利工具，并且自身也只能调用上述公开
   HTTP 接口，不能拥有额外能力。
4. 该 socket 只在 Guest 文件系统命名空间内存在。真实 VMM、Cloud Hypervisor 和
   Host Node Agent 都不打开它：Guest Agent 在内存中维护租约，再通过既有 AF_VSOCK
   控制协议向 Node Agent 提供 `WorkStatus`、`PrepareSuspend` 和 `AbortSuspend`。
   Node/控制面维护分布式工作计数并驱动 VMM pause/resume。
5. Unix socket 是阻止休眠的 Guest→平台信号，不是唤醒入口。Cat 已 Suspended/Warm
   时 Guest 代码不能运行；Endpoint Gateway、shell/exec 或显式 start 必须先从 Guest
   外部触发唤醒。
6. socket 文件由 Guest Agent 创建，父目录不可由普通 Guest 用户替换，V1 socket
   mode 为 `0666`，允许 Cat 内任意用户声明工作。调用不携带 Cat id、控制面 token、
   对象存储凭据或 metadata 凭据。所有 Guest 用户属于同一 Cat 信任/计费边界；若
   未来提供 Guest 内多用户互不信任模型，再按 peer credentials 增加授权策略。
7. HTTP 请求有明确的 header/body 大小和读取超时；响应使用结构化 JSON error、
   `Cache-Control: no-store` 和连接关闭。租约 TTL、数量上限、单调时钟、quiesce
   sequence fence 与 fail-awake 语义不因传输改变。完整 wire contract 见
   [`Guest Runtime API v1`](../specs/guest-runtime-api.md)。

## 本地开发语义

应用可以先检查 `/run/cats/runtime.sock` 是否存在：在普通本机环境不存在时跳过
租约，使同一份业务代码可以运行；在启用了 Cats auto-suspend 的 Cat 内，创建或续租
失败意味着应用无法保证 Cat 保持 Running，不应被 SDK 或 CLI 静默吞掉。是否把这种
失败作为业务错误，由应用决定。

Unix socket HTTP 仍要求客户端支持 Unix transport；这不是 Cats SDK 依赖。Shell 可
使用 `curl --unix-socket`，其他语言可使用其通用 HTTP 客户端的 Unix-socket transport
或直接写标准 HTTP/1.1 字节。若某语言只能使用 TCP，未来可以增加显式配置的 loopback
兼容监听，但它不是 Guest ABI，也不分配固定默认端口。

## 影响

- Cats 不再占用或约定 2287 等 Guest TCP 端口。
- 稳定发现约定从“固定端口/私有帧”变为“固定 Unix socket 路径/标准 HTTP”。
- Guest Agent 是 HTTP 终点和 vsock 摘要源；VMM 仍只执行生命周期动作，不理解 HTTP
  或工作租约。
- 传输改变不影响 ADR-0002 的四态定义、durable FLUSH 门禁、Warm/Cold fallback 或
  PersistentDisk fencing。
