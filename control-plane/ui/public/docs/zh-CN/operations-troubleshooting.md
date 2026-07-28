## 理解 Operation

Create、Lifecycle 与 Delete 请求是异步的。控制面记录包含 ID、类型、目标资源、阶段、时间戳和可选结构化错误的 Operation。

    cats operation ls
    cats operation get OPERATION_ID
    cats operation wait OPERATION_ID

阶段从 pending/running 进入 succeeded 或 failed。网络超时不代表原变更失败——重试前先查询已经接受的 Operation。

## 常见错误类型

| Code | 含义 | 第一步处理 |
|----|----|----|
| `unauthenticated` | 身份缺失或过期 | 重新执行 `cats login`，或刷新浏览器 Session。 |
| `permission_denied` | 身份有效，但 Workspace 错误 | 执行 `cats whoami`，检查已保存/临时覆盖的 Workspace。 |
| `not_found` | 作用域内没有该资源 | 在同一 Workspace 执行对应 List 命令。 |
| `already_exists` | 名称冲突 | 选择新名称或检查现有资源。 |
| `failed_precondition` | 当前生命周期或 Attachment 状态阻止操作 | 查看 Cat/Disk 状态并完成前置转换。 |
| `conflict` | 并发 Generation 或 RWO 冲突 | 刷新状态；不要强行创建第二写者。 |
| `stale_epoch` | 旧磁盘或 Route Owner 尝试工作 | 视为已 fenced；从当前 Assignment 重建。 |
| `unavailable` | 临时依赖故障 | 有界退避重试并查看 Operation。 |

## Cat 无法 Ready

1.  执行 `cats get NAME --json`，记录 desired/observed state 与 Node。
2.  查看最近 Operation 及最终错误。
3.  管理员检查 Node Heartbeat、blockd/Guest readiness、Console Output 与 Attachment Epoch。
4.  如果 Suspended/Warm 恢复失败，确认 Controller 已收敛到 Cold fallback，而不是停在中间态。

## 磁盘无法 Mount、Resize 或 Delete

执行 `cats disk get NAME`。PersistentDisk 只能有一个活跃读写 Attachment。移动或删除前先安全 Unmount，并遵守当前运行路径的 Resize 前置条件。绝不能绕过 Fencing 冲突。

## 自动休眠未触发

    cats sleep status dev

检查活跃平台/Guest Lease、Guest 信号新鲜度和打印的原因。过期信号会有意 fail awake。确认长期运行应用会释放工作租约，且没有 Shell、Exec、Deploy 或 Gateway Activation Lease。

## 控制面无法访问

已经 Running 的 Cat 可能继续运行，因为 API 进程不在 Guest I/O 热路径。新的生命周期变更与 durable Root 发布可能延迟或 fail closed。权威 Metadata CAS 不可用时，不能宣称 FLUSH 成功。

## 有用的故障证据

升级处理时请保留 Request ID、Operation ID、Account/Workspace Slug、Cat/Disk 名称、Node ID、Generation、Attachment/Route Epoch、时间戳、CLI 版本与结构化错误。移除 Token、Cookie、Secret、Guest 磁盘内容与终端明文。
