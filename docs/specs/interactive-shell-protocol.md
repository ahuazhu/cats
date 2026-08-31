# Cats Exec 与 Interactive Shell Protocol v1

- 状态：Accepted target；semantic Control/Node 实现进行中，尚未形成 production qualification
- 决策依据：[ADR-0009](../decisions/0009-interactive-shell-over-authenticated-websocket.md)、
  [ADR-0065](../decisions/0065-exec-shell-runtime-access-lane.md)
- 当前共享 DTO/限制：[`api/src/sessions.rs`](../../api/src/sessions.rs)
- 已保留 Guest wire/PTY 原语：[`api/src/guest.rs`](../../api/src/guest.rs)、
  [`guest/src/exec.rs`](../../guest/src/exec.rs)、[`guest/src/lib.rs`](../../guest/src/lib.rs)、
  [`node-agent/src/guest_client.rs`](../../node-agent/src/guest_client.rs)
- semantic composition 目标位置：[`control-plane/src/api/sessions.rs`](../../control-plane/src/api/sessions.rs)、
  [`control-plane/src/semantic_session.rs`](../../control-plane/src/semantic_session.rs)、
  [`node-agent/src/semantic_lifecycle.rs`](../../node-agent/src/semantic_lifecycle.rs)、
  [`cmd/cats/src/lib.rs`](../../cmd/cats/src/lib.rs)、[`cmd/cats/src/shell.rs`](../../cmd/cats/src/shell.rs)

本规格冻结公开 Exec/Shell wire、Node access gate 和生命周期互锁。以上路径用于定位当前代码，不能把
DTO、Guest 单元测试或历史实现的存在解释成公开 route、真实 Cloud Hypervisor 或 production 行为已经
通过；实现状态以当前代码和 exact test receipt 为准。

## 1. 协调模型

Exec/Shell 是独立的 live runtime access lane，不是 Cat lifecycle action：

```text
public auth
-> optional normal `run`
-> re-read current Cat + placement
-> Control machine-authenticated hop
-> noded exact-Running-incarnation access gate
-> Guest Exec or PTY
```

它们不写 `current_action`、不生成 Operation、没有持久 session/result row，也不参与 lifecycle 场景语义
重试。Control 不在 stream 或 Node 网络调用期间持有 PostgreSQL transaction。

## 2. 公开接口

### 2.1 Exec

```http
POST /v1/workspaces/{workspace_id}/cats/{cat_slug}/exec HTTP/1.1
Authorization: Bearer <WorkOS access token or workspace machine token>
Content-Type: application/json

{
  "command": ["/usr/bin/env", "true"],
  "timeout_ms": 120000,
  "env": {"NAME": "value"},
  "stdin": []
}
```

`command` 是 argv，Cats 不做 shell 拼接或解释。`env` 只向 child 增加/覆盖环境；`stdin` 是 JSON byte
array。省略 `timeout_ms` 使用 120,000 ms。成功响应：

```json
{
  "exit_code": 0,
  "stdout": "",
  "stderr": ""
}
```

远端非零 `exit_code` 仍是一个已完整取得的 Exec response。CLI 对合法远端 `1..=255` 使用 exact process
exit code；远端负数、超过 255、transport/protocol failure 或其他异常统一 exit 1。命令不存在返回
127；被信号终止且平台没有可移植 signal-to-exit-code 映射时 Guest 返回 -1，因此 CLI 归一为 1。
stdout/stderr 按 Guest ABI 转成 UTF-8 string；V1 不提供 byte-preserving Exec 输出，二进制交互应使用
Shell/PTY 或应用协议。

### 2.2 Interactive Shell

```http
GET /v1/workspaces/{workspace_id}/cats/{cat_slug}/shell?rows=24&cols=80 HTTP/1.1
Authorization: Bearer <WorkOS access token or workspace machine token>
Connection: Upgrade
Upgrade: websocket
```

`rows` 和 `cols` 可省略，默认 `24x80`，有效范围均为 `1..=1000`。Control 在 public upgrade 前完成
Workspace auth、必要 wake、重新解析 placement，并在当前 noded 建立 Guest PTY；任何一步失败都返回普通
HTTP semantic error，不返回 `101`。

认证必须先于读取 Cat 详情以外的副作用：无权限调用不能唤醒 Cat、连接 Node 或启动 Guest process。
public Exec/Shell 只接受显式 `Authorization: Bearer`，不读取 Web session Cookie。任何携带 `Origin`
header 的请求都在 wake 前拒绝；V1 不允许 browser Fetch/WebSocket 使用这些 endpoint。用户 Bearer token
不转发给 Node。

## 3. Wake 与竞态

Control 按以下顺序准备 session：

1. 认证调用方并验证 `workspace_id`；
2. 把 `cat_slug` 解析为该 Workspace 当前未 destroyed 的 immutable `cat_id`；
3. Cat 非 Running 时调用 ADR-0059 的正常 `run`；
4. `run` 返回后重新读取 Cat state、`current_action`、`node_id`、Node status 和 `control_endpoint`；
5. 只有 stable Running、没有 lifecycle action、当前 Node 为 running 时才发起内部 access；
6. noded 再以本地 access gate 做最终 exact-incarnation admission。

Control 的预检查不是 Node authority。若 concurrent suspend/warm/cold/destroy/reset 已关闭 gate，access
失败且不撤销该动作；Control 不通过重发 session 请求“赢回”Running。Exec 一旦已经尝试 Node dispatch，
更不能因 `Busy`、timeout、EOF 或 malformed response 自动重发。

## 4. Exec 边界与取消

### 4.1 请求和输出上限

| 项目 | V1 上限 |
|---|---:|
| wall timeout | 默认 120,000 ms；最大 3,600,000 ms；必须大于 0 |
| argv 数量 | 256 |
| 单个 argv | 16 KiB |
| argv 总量 | 64 KiB |
| env 数量 | 256 |
| env key | 256 bytes；非空且不能含 `=`/NUL |
| env value | 16 KiB；不能含 NUL |
| env key/value 总量 | 64 KiB |
| stdin | 1 MiB |
| stdout + stderr | 合计 1 MiB |
| encoded Exec JSON request | 5 MiB |
| encoded Exec JSON response | 7 MiB |

所有入口都调用同一共享 validator，public/internal body reader 还分别执行上述 encoded JSON 上限。
较大的 encoded request 上限用于 `Vec<u8>` JSON number array 和 worst-case escaping，不放宽 1 MiB raw
stdin；response 上限同理不放宽 1 MiB UTF-8 stdout/stderr 合计。超限在 Guest side effect 前返回
`InvalidRequest`；不能只在 CLI 限制而让直接 REST/内部请求绕过。

Guest 为每个 Exec 创建独立 Unix process group。以下任一事件必须终止整个 group 并 reap：

- wall timeout；
- Node↔Guest internal transport disconnect 或请求取消；
- Node access gate close；
- stdout/stderr 合计超过 1 MiB；
- Guest/Node shutdown。

stdout 和 stderr 必须并行 drain；向 stdin 写入不能阻止读取输出。超时和输出超限是明确失败，不返回
截断后伪装成功的 `ExecResponse`。

普通 public HTTP client disconnect 不保证 Hyper 取消已经进入的 handler，因而不是“立即 kill”的合同。
Control→noded reqwest/TCP 断开也不保证 Axum 取消已经进入的 noded handler。命令可以继续，但 Node worker
必须一直持有 exact access guard，并在 effective wall timeout、Node lifecycle close、Node↔Guest
transport loss 或正常 terminal result 之一发生时有界结束。public caller/Control 未取得完整 response 时
结果未知，不能自动重试；V1 不把这个继续执行的请求变成 detached/persisted task。

Control shutdown 必须取消并回收本地 inflight request future、关闭 internal TCP；这只完成 Control 本地
drain，不是 Guest Exec cancellation proof。V1 没有 request ID、cancel endpoint 或持久 cancel authority，
Node/Guest 可以按上一段继续执行。

### 4.2 模糊结果

Control→noded Exec 只 dispatch 一次。尝试 dispatch 后如果没有取得完整、合法 response，公开 semantic
错误使用现有 `NodeUnavailable`；对 Exec 而言它表示结果可能未知，不表示零副作用。Control、CLI 和 HTTP
client 都不自动重试，也不把 Cat state 查询当作 Exec result discovery。

V1 不保存 Exec ID/result，调用方无法稍后查询。用户显式再次运行相同 argv 是一个新命令，必须自行承担
重复副作用。这个规则与 ADR-0059 lifecycle 同动作重试不同。

### 4.3 现有 semantic error 映射

本协议不增加第二套跨组件 error enum：

| `SemanticErrorCode` | Access 含义 |
|---|---|
| `InvalidRequest` | argv/env/stdin/timeout/terminal dimensions/frame 不合法或超限 |
| `Busy` | gate 正在关闭、并发生命周期动作或 session quota 已满；没有 Guest 副作用时可返回 |
| `InvalidState` | wake 后 Cat 仍不是 stable Running |
| `NodeUnavailable` | Guest 不可达/EOF、Control→noded transport loss、malformed/incomplete noded success，或 Exec dispatch 后其他结果不明；它不证明 Node/Guest 已取消，Exec 一律不得自动重试 |
| `Timeout` | Guest 已终止并 reap 超时 Exec，或 session deadline 明确到期 |
| `InternalError` | dispatch 前的平台内部不变量失败；不能用于已 dispatch 的 malformed/incomplete success，也不能伪造 command exit |

`CatNotFound`、`Unauthorized` 和 lifecycle wake 自身的 error 沿用 ADR-0059。Shell 在 public `101` 之前使用
同一 semantic error body；升级后的失败使用 Shell `error` frame 或 abnormal WebSocket close。

## 5. WebSocket frame

### 5.1 Client → Server

- Binary：原样写入 PTY stdin。
- Text resize：`{"type":"resize","rows":40,"cols":120}`。
- Text close：`{"type":"close"}`。
- Ping/Pong：标准 WebSocket 保活帧。

### 5.2 Server → Client

- Binary：PTY stdout/stderr 合并后的原始 byte。
- Text exit：`{"type":"exit","exit_code":0}`，是正常终止的最后一个业务 frame。
- Text error：`{"type":"error","message":"..."}`，CLI 按失败结束。
- Ping/Pong：标准 WebSocket 保活帧。

公开和内部 WebSocket message/frame 最大 64 KiB。未知 JSON、方向错误的控制 frame、非法 terminal
dimensions 或超限 message 都会取消 session。客户端未收到 exact `exit` 就断线时必须报告失败，不能
推断 exit 0。

每一 hop 使用容量固定的 channel 并传播 backpressure；不能无界缓存，也不能静默丢 PTY bytes。当前
Guest control protocol 仍有自己的 16 MiB frame 上限，但它不放宽 public/internal 64 KiB 上限。

## 6. Node ↔ Guest frame

Node 与 Guest 在现有控制 Unix socket/vsock 上先发送 request/response handshake。

Exec：

```json
{"id":1,"op":"exec","command":["true"],"timeout_ms":120000}
{"id":1,"result":"exec","exit_code":0,"stdout":"","stderr":""}
```

Shell：

```json
{"id":1,"op":"shell","rows":24,"cols":80}
{"id":1,"result":"shell_ready"}
```

Shell 随后在同一连接切换为 `GuestShellFrame` 的 4-byte big-endian length-prefixed JSON stream：

```json
{"type":"input","data":[108,115,10]}
{"type":"resize","rows":40,"cols":120}
{"type":"output","data":[36,32]}
{"type":"exit","exit_code":0}
{"type":"close"}
```

Host 连接 Guest 时使用 access guard 捕获的 exact `vsock_socket + guest_port + vmm_pid`。connect/handshake
不得改用稍后重新查询的 socket 或 PID，否则旧 session 可能跨到另一个 incarnation。

## 7. Node RuntimeAccessGate

每个 Cat 有一个 `RuntimeAccessGate`，每 Node 有全局 session quota：

- 每 Cat 最多 8 个 active/正在 admission 的 Exec + Shell；
- 每 Node 最多 256 个；
- 超限在 Guest connect/exec/PTY side effect 前以 `Busy` 拒绝。

gate Open target 是 `{cat_id, runtime_incarnation, vsock_socket, guest_port, exact_vmm_pid}`。admission 在
semantic Cat lane state lock 下同时检查 placement/reset gate Open、record state Running、没有 active
lifecycle/destroy pending，并取得 exact target 的 guard。Guest connect 前后仍须验证 guard 未取消。

create/run 只有在 Guest 和 mounts Ready 后才能从 installed `ManagedCat` 采样 exact target 并 Open。
suspend/warm/cold/destroy 在物理 effect 前执行：

```text
Close -> reject new admission -> cancel all sessions -> drain/join <= 10 s
      -> lifecycle physical effect
```

Node reset 对全部 Cat 先执行同样的 close/cancel/drain，deadline 也是 10 秒；超时后 reset 继续关闭 VMM
作为 backstop。普通 suspend/warm/cold 若无法证明旧 access process/worker 已停止，不能虚报目标 state。
离开 Running 失败后的 postcondition discovery 也只能在旧 session 已安全 drain 时保留旧 exact gate
target；Control 已结算为 `failure` 时仍拒绝新的 acquisition。

session worker 从 admission 到 Guest process/PTY 终止一直持有 guard。Node↔Guest internal disconnect 和
gate cancel 会触发取消，而不是先释放 guard 留下 Guest 内后台 command。public Exec HTTP disconnect、
Control→noded loss 和 Control shutdown 遵守 §4.1 的窄语义，不保证传播到已经进入的 noded worker。
只有新的 successful create/run 安装新 incarnation 后才能重新 Open；旧 guard/worker 永远不能打开 gate。

## 8. Shell lifecycle 与 CLI

完整 Shell 顺序：

1. Control 完成 auth、normal wake 和 placement re-read；
2. noded 为 exact Running incarnation 取得 guard；
3. Guest 建立 login PTY 并返回 `shell_ready`；
4. public upgrade 完成，开始传输 frame；
5. shell exit 时 Guest 尽力排空已读取的 PTY 输出，再发送 exact exit；
6. client close/disconnect 或 lifecycle cancel 关闭 PTY，join worker 并释放 guard；
7. Control shutdown 主动关闭 public 和 noded WebSocket，在有界等待内回收 proxy/session，再完成退出。

V1 不支持 detach/reconnect。`tmux`/`screen` 可以让 Guest 内进程继续，但断线的 Cats WebSocket/PTY
session 本身仍被关闭。

CLI grammar：

```text
cats exec CAT [--timeout SECONDS] [--env-file PATH] [--stdin-file PATH] -- ARGV...
cats shell CAT
```

Exec 把 stdout/stderr 分别写到本地 stdout/stderr；不经 shell 解释 argv，HTTP/模糊错误不重试。Shell
在本地 TTY 使用 RAII raw mode、每 250 ms 检查 resize、每 20 秒 ping，并在所有退出路径恢复 terminal。
非 TTY stdin 仍传 binary bytes；EOF 向远端 PTY 发送 EOF 后等待 exact exit，不能把本地 EOF 当成功。
Exec 和 Shell 收到合法远端 exit `1..=255` 时，CLI process 使用 exact code；远端 exit 不在 `0..=255`、
WebSocket 在 exact Exit 前断开，以及其他 transport/protocol failure 都归一为 1。

## 9. 安全、日志和 HA 边界

- public auth 先于 wake，只接受无 `Origin` 的 explicit Bearer，不接受 Web session Cookie；internal
  noded route 只接受 service Bearer。
- WorkOS、service、storage 和 metadata credential 不进入 Guest；env/stdin 也不写普通日志。
- 普通日志只记录 session identity、Cat/Node、incarnation 的非敏感标识、时长、bytes、exit/error category
  和取消原因；不记录终端内容、stdout/stderr 或用户 secret。
- Shell/Exec 使用 Guest Agent 配置的系统 identity。Cat 是一个 Guest trust boundary；V1 不增加 Guest
  内多用户隔离。

本 access gate 只协调可达 Node 内的 runtime。ADR-0059 offline 双跑窗口内，旧 Node 和已有 session 可能
继续，直到旧 Node 重新联系 Control、收到 `reset_required` 并本地 close/cancel/drain。入口撤销、WebSocket
ping 和 access guard 都不是 Host fence；本规格不承诺网络分区下旧 Shell 立即停止、物理单实例或完整
production HA。

## 10. 验收矩阵

- 未认证、无 Workspace 权限和 Cat not found 都在 wake/Node/Guest side effect 前失败。
- Cookie-only、Cookie + hostile/same-site `Origin`、以及 Bearer + 任意 `Origin` 都在 wake 前失败；只有
  无 `Origin` 的 valid Bearer 可以进入 session preparation。
- Suspended/Warm/Cold 只通过正常 `run` 唤醒；wake 后 placement 改变会重新解析 current Node。
- Exec/Shell 不出现在 `CatAction/current_action`，也不改变稳定 Cat state。
- gate 只在 exact Running incarnation Open；旧 socket/PID、late admission 和 reset gate 都 fail closed。
- suspend/warm/cold/destroy/reset 先 close/cancel/drain；并发 admission 只能在线性化顺序的一侧成功。
- quota、argv/env/stdin/output/timeout/terminal dimensions 和 WebSocket message 的每个边界都有正反测试。
- Exec timeout、output overflow、Node↔Guest transport loss 和 lifecycle cancel 都 kill/reap 完整 Unix
  process group；public HTTP disconnect、Control→noded loss 和 Control shutdown 按 §4.1 让 Node 保持
  guard 并最终有界结束，不产生脱离 guard 的 orphan child。
- Exec dispatch 后的 response loss 不产生第二次命令；客户端得到 `NodeUnavailable`，不伪造 exit 0。
- Shell disconnect 关闭 PTY；没有 detach/reconnect；只有 exact exit frame 可成为 CLI remote exit code。
- CLI 对合法远端 exit `1..=255` 精确透传，其他远端/transport/protocol 异常归一为 1。
- bounded channel 在慢 client/Guest 下传播 backpressure；cancel/shutdown 能 join 所有 bridge task；
  Control shutdown 会关闭并回收 public/noded WebSocket session。
- 活跃 Exec 下 Control shutdown 会回收本地 future 并关闭 internal TCP，但测试不得把它当 Node/Guest
  cancel proof；Node session 继续持 guard，并在 effective wall timeout/Node 本地 cancel/terminal 内收敛。
- Fake Guest 覆盖 wire/concurrency，真实 Linux/Cloud Hypervisor 覆盖 PTY、process group、vsock exact peer
  和 lifecycle 纵向竞态；前者不能替代后者的 production qualification。
