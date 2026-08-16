## 理解 Operation

Cat Create 是异步的。控制面返回 canonical Operation 的 ID；该记录绑定 Cat、Desired Revision/Spec、Placement、Target、阶段、时间戳，以及可选的终态结果或错误。

    cats operation get OPERATION_ID
    cats operation wait OPERATION_ID

Operation 从 `pending` 进入且只进入 `succeeded`、`failed` 或 `superseded` 之一。请使用接受该变更的同一 Workspace；其他 Workspace 与不存在的 ID 会有意返回相同结果。Operation List 当前不可用。网络超时不代表原变更失败——以相同持久 Create 意图重放并取回已接受的 ID，再精确查询该 Operation。

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

## Cat 在 Create 后无法 Ready

1.  执行 `cats get CAT_ID --json`，记录 desired/observed state 与 Node。
2.  按已接受的 ID 查看 Operation 及其终态结果或错误。
3.  管理员检查 Node Heartbeat、blockd/Guest readiness、Console Output 与 Attachment Epoch。
4.  如果 Suspended/Warm 恢复失败，确认 Controller 已收敛到 Cold fallback，而不是停在中间态。

## Disk Mutation 不可用

执行 `cats disk get DISK_ID` 查看当前 Projection。Attachment、Snapshot、容量变更与删除不属于 release product surface。不要探测 Legacy Route，也不要绕过 Authority/Fencing Conflict。

## Lifecycle 命令不可用

Signed Runtime Cutover 期间有意不提供 Lifecycle 与 Guest-command Client。请保留已接受的 Create Operation ID 与当前 Cat Projection；不要替换为旧命令或旧 Route。

## 控制面无法访问

已经 Running 的 Cat 可能继续运行，因为 API 进程不在 Guest I/O 热路径。新的生命周期变更与 durable Root 发布可能延迟或 fail closed。权威 Metadata CAS 不可用时，不能宣称 FLUSH 成功。

## 有用的故障证据

升级处理时请保留 Request ID、Operation ID、Account/Workspace Slug、Cat/Disk 名称、Node ID、Generation、Attachment/Route Epoch、时间戳、CLI 版本与结构化错误。移除 Token、Cookie、Secret、Guest 磁盘内容与终端明文。
