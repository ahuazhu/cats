# ADR-0065：Exec/Shell 使用独立的 Runtime Access Lane

- 状态：Accepted
- 日期：2026-08-31
- 扩展：[ADR-0009](0009-interactive-shell-over-authenticated-websocket.md) 的 Shell
  admission、生命周期互锁和失败语义
- 组合：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md) 的场景语义 Control/Node
  协议；不增加 Cat lifecycle action
- 精确合同：[Exec 与 Interactive Shell Protocol v1](../specs/interactive-shell-protocol.md)

## 背景

Guest Agent 的 argv Exec、PTY Shell frame 和 Node `GuestClient` transport 仍是可复用的底层能力，
但 ADR-0059 clean-slate 切换删除了旧 Control/Node session composition 和 CLI 命令。直接恢复旧 handler
会重新依赖已经退役的 Work lease、Desired reconcile 或旧 runtime admission；把 Exec/Shell 加进
`current_action` 又会把一个活跃会话误建模成产品状态转换。

Exec 和 Shell 还具有生命周期动作没有的失败形态：Exec 可能已经产生副作用但响应丢失；Shell 是
不定长双向流；两者都必须与同一个 Node 上的精确 Running runtime 绑定，并在 runtime 离开 Running
前停止。恢复它们会改变公开 API、失败语义和 Node authority，因此用本 ADR 冻结新边界。

## 决定

### 独立的 live access lane

Exec 和 Shell 是一条独立的、非持久化的 runtime access lane：

- 它们不是 `create/run/suspend/warm/cold/destroy` 之一，不写 `CatAction`、`current_action` 或稳定 state；
- PostgreSQL Cat 当前行继续决定 Workspace identity、当前 placement 和正常 wake；
- noded 的 per-Cat access gate 是当前物理 runtime 的唯一 session admission authority；
- session guard 只证明本 Node 上该精确 runtime incarnation 在 guard 生命周期内仍获准接受 access，
  不成为 lifecycle、placement、volume writer、Host fence 或 HA authority；
- access session 不持有 PostgreSQL transaction，也不生成可恢复 Operation 或持久任务结果。

同一 Cat 可以有多个受配置上限约束的 access session。每个 session 都在 Node 注册、进入有界队列并
取得 guard 后才连接 Guest；资源耗尽应在产生 Guest 副作用前拒绝，不能用无界 task、channel 或输出
缓冲吸收压力。

### 公开认证、wake 与内部身份

公开请求先完成调用方身份和目标 Workspace/Cat 授权。认证或授权失败时，Control 不调用 `run`、不连接
noded，也不产生 Guest 副作用。用户 token 不转发给 Node；Control→noded 使用现有内部 machine
credential。

V1 public Exec/Shell endpoint 只接受显式 `Authorization: Bearer`，不接受 Web session Cookie fallback。
任何携带 `Origin` header 的请求都在 auth/wake 前拒绝；这组 endpoint 不提供 browser WebSocket/Fetch
入口，避免同站或跨站页面借用户 Cookie 建立 PTY。若未来需要 browser client，必须另行设计精确 Origin、
CSRF/session grant 和 token 暴露边界，不能放宽本规则。

Cat 不是 Running 时，Control 只通过 ADR-0059 的正常 `run` 动作唤醒，不创建 session 专用状态转换。
`run` 返回后 Control 重新读取当前 Cat、`current_action` 和 placement，再向该当前 Node 使用 immutable
`cat_id` 发起 access。并发 suspend/warm/cold/destroy 或 placement 改变不会由 access 请求撤销；noded
gate 关闭时请求以无副作用错误失败。

### Node exact-incarnation admission

noded 为每个物理 Cat runtime 维护一个本地 access gate。gate 默认 Closed，只能在 create/run 已完成
VMM、设备、Guest 和 mounts Ready，并安装新的 `runtime_incarnation` 后 Open。一次 admission 必须在
同一个线性化点验证：

1. immutable `cat_id` 属于本 Node 当前管理的 runtime；
2. 物理状态为 Running；
3. Node placement/reset gate 仍允许服务；
4. access gate 为 Open，且绑定的 incarnation 与当前 `ManagedCat` 完全相同。

取得的 guard 绑定这个 exact incarnation。Guest connect、Shell `shell_ready` 或 Exec dispatch 前后若
incarnation 改变，必须在用户命令或 PTY 可用前 fail closed。旧 guard、迟到 connect 和旧 runtime 的
response 不能在新 incarnation 上继续。

### 与生命周期的互锁

同一 Node 上，任何离开 Running 的 suspend、warm、cold、destroy，以及 Node reset，都必须把关闭
access gate 作为触碰 Guest、VMM、block frontend 或 attachment 之前的本地效果：

1. 原子 Close，拒绝新的 Exec/Shell admission；
2. 向全部 active session 发送取消；
3. 在配置的短 deadline 内 drain 并 join session worker；
4. 确认没有旧-incarnation access worker 后，才继续生命周期物理效果。

取消必须向 Guest 传播：Shell 关闭 PTY；Exec 终止其 Unix process group 并 reap。一个 access worker
不能因 Control 客户端消失就丢掉 guard 后在 Guest 内无主运行。若非破坏性动作不能在 deadline 内证明
access 已停止，它必须 fail closed，不能虚报 Suspended/Warm/Cold；destroy/reset 可以按各自合同强制停止
完整 runtime，但仍不得让旧 gate 或 worker 在之后重新开放。只有后续成功 create/run 安装的新 exact
incarnation 才能重新 Open。

### Exec 是有界、不可透明重放的调用

Exec 接受 argv、环境增量、可选 stdin 和 wall timeout；它不经过 shell 解析。命令、环境、stdin、
timeout、stdout/stderr 和 response 都有固定上限。wall timeout、Node↔Guest internal transport loss、
生命周期 gate 关闭或输出超限都会终止完整 Unix process group 并 reap，不能只杀直接 child 而留下后代。

普通 public Exec HTTP client disconnect 不是可靠的 cancellation signal：Hyper 可能继续运行已经进入的
handler。Control→noded reqwest/TCP 断开同样不能取消已经进入 noded handler 的命令。Node worker 仍必须
持有 access guard，并只允许继续到 effective wall timeout、Node lifecycle close、Node↔Guest transport
loss 或正常 terminal result；不能脱离 guard 变成无界后台任务。调用方没有收到完整 response 时结果
未知，不得自动重试。

Control shutdown 取消并回收本地 inflight request future、关闭 internal TCP，但不声称取消 Node/Guest
Exec。V1 不增加 request ID、cancel RPC 或持久 cancel authority；Node 继续以上述本地边界有界收敛。

一次 Node dispatch 之后的 timeout、EOF、代理退出或 malformed response 对外使用现有
`SemanticErrorCode::NodeUnavailable`；对 Exec 而言它表示结果可能未知，不表示零副作用。Control 和 CLI
不自动重发，ADR-0059 的“查询目标 state 后重试同一动作”只适用生命周期动作，不能套用到 Exec。调用方
显式再次执行是一个新的、可能重复副作用的命令。V1 不保存 Exec request ID、输出或 terminal result，
也不提供 detach/result lookup。

access lane 不增加第二套 error enum：非法或超限输入使用 `InvalidRequest`；gate closing、生命周期冲突
或 quota 用 `Busy`；wake 后仍非 Running 用 `InvalidState`；明确 wall deadline 用 `Timeout`；只有 dispatch
前的平台内部不变量失败用 `InternalError`。Guest 不可达/EOF、Control→noded transport loss，以及
malformed/incomplete noded success 都使用 `NodeUnavailable`。其中只有 Guest side effect 前的
`InvalidRequest`、`InvalidState` 或 `Busy` 可以被调用方按新请求处理；Exec 的 `NodeUnavailable` 一律
不得透明重试。

### Shell 是绑定连接的 PTY

Shell 使用认证 WebSocket 承载 PTY byte stream、resize 和 exact exit。它不创建 SSH user/key/port，
不支持 detach/reconnect；客户端、Control、Node 或 Guest 任一 hop 断开都取消 session 并关闭 PTY。
Control shutdown 必须主动关闭 public 和 noded WebSocket 并有界回收 session，不能无限等待 stream 或
让它越过 Control process 生命周期。
只有收到 exact `exit` frame，CLI 才能报告远端 exit code；在此之前的 close/EOF 是失败。用户若需要让
进程跨客户端断线继续，应在 Guest 内显式使用 `tmux`/`screen` 等工具，这不把平台 Shell session
变成可恢复资源。

### ADR-0059 的网络与 HA 边界保持不变

access lane 不修复 ADR-0059 接受的 offline 双跑窗口。旧 Node 在不对称网络中仍可能暂时运行旧 runtime
和已有 session；撤销公开入口或把 Cat placement 切到新 Node 不是 Host fence。旧 Node 再次与 Control
通信并收到 `reset_required` 时，才在本地关闭 gate、取消 session 并清理 runtime。

因此本 ADR 只保证可达 Node 内 exact-incarnation admission 与 lifecycle interlock，不承诺任意网络分区下
旧 Shell 立即断开、全局物理单实例或完整生产 HA。需要消除该窗口时必须另行增加可信 Host fencing 和
跨 Node session authority，不能把 access guard、WebSocket heartbeat 或日志冒充隔离证据。

## 安全与观测

- Workspace auth 在 wake 前完成；public endpoint 只接受无 `Origin` 的 explicit Bearer，不接受 Web
  Cookie；内部 hop 只接受 machine credential。WorkOS、Control、存储和 metadata credential 不进入 Guest。
- Cat 仍是一个 Guest 信任边界。默认 Shell/Exec 使用 Guest Agent 配置的系统身份；本文不增加 Guest
  内多用户隔离。
- 普通日志不记录 argv 中的敏感值、env、stdin、stdout/stderr 或终端内容；只记录 Cat/Node/session
  identity、时间、字节计数、exit/error category 和取消原因。
- WebSocket frame、channel、session 数和 Exec 输出都必须有界；backpressure 贯穿 CLI、Control、Node
  和 Guest，不能通过丢弃有序 PTY bytes 假装成功。

## 后果

恢复 Exec/Shell 不需要恢复旧 reconcile、Work lease、Operation 或 AgentSession。代价是 Node 增加一套
只负责 live access 的 per-Cat gate/session registry，所有离开 Running 和 reset 路径都必须覆盖其
close/cancel/drain；Exec 还必须提供真实 timeout、输出边界、disconnect cancellation 和 process-group
cleanup；其中 disconnect cancellation 只指 Node↔Guest transport loss。public Exec disconnect、
Control→noded loss 和 Control shutdown 遵守上面的“Node 持 guard 有界继续”语义。

本 ADR 的 Accepted 只表示合同生效。公开 route、Control proxy、Node gate、CLI、Guest cancellation 和
Cloud Hypervisor 纵向行为必须由当前代码与 exact test receipt 分层证明，不能从保留的 Guest DTO/PTY
原语或历史 Git 实现推断已经上线。
