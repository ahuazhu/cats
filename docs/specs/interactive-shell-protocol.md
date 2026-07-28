# Cats Interactive Shell Protocol v1

- 状态：Implemented v1
- 决策依据：[ADR-0009](../decisions/0009-interactive-shell-over-authenticated-websocket.md)
- 实现：`cmd/cats/src/shell.rs`、`control-plane/src/api.rs`、
  `node-agent/src/server.rs`、`guest/src/lib.rs`

## 1. 公开连接

```http
GET /v1/workspaces/{workspace_id}/cats/{cat}/shell?rows=24&cols=80 HTTP/1.1
Authorization: Bearer <WorkOS access token>
Connection: Upgrade
Upgrade: websocket
```

`rows` 和 `cols` 可省略，默认 `24x80`，有效范围均为 `1..=1000`。控制面先完成
Workspace 授权、获取 work lease、必要时唤醒 Cat，并连接正确 Node；任何步骤失败都在
upgrade 前返回普通 API 错误。成功后返回 `101 Switching Protocols`。

管理员机器 token 只用于自动化测试或 break-glass 路径；普通用户 CLI 使用
`cats login` 保存的 WorkOS session。

## 2. WebSocket frame

### Client → Server

- Binary：原样写入 PTY stdin。
- Text resize：`{"type":"resize","rows":40,"cols":120}`。
- Text close：`{"type":"close"}`。
- Ping/Pong：标准 WebSocket 保活帧。

### Server → Client

- Binary：PTY stdout/stderr 合并后的原始字节。
- Text exit：`{"type":"exit","exit_code":0}`，是正常终止的最后一个业务帧。
- Text error：`{"type":"error","message":"..."}`，CLI 必须按失败结束。
- Ping/Pong：标准 WebSocket 保活帧。

未知 JSON、方向错误的控制帧、非法尺寸或超过 64 KiB 的 WebSocket message 会关闭会话。
客户端未收到 `exit` 就断线时，必须报告失败，不能推断 exit 0。

## 3. Node ↔ Guest frame

Node 与 Guest 在现有控制 Unix socket/vsock 上先发送普通 request/response handshake：

```json
{"id":1,"body":{"type":"shell","rows":24,"cols":80}}
{"id":1,"body":{"type":"shell_ready"}}
```

随后同一连接切换为 `GuestShellFrame` 的 4-byte big-endian length-prefixed JSON stream：

```json
{"type":"input","data":[108,115,10]}
{"type":"resize","rows":40,"cols":120}
{"type":"output","data":[36,32]}
{"type":"exit","exit_code":0}
{"type":"close"}
```

每个 frame 继续受 Guest 控制协议现有的 16 MiB 上限保护。Node 两个方向各使用容量 32
的有界 channel；Guest 的输入与输出事件队列容量同样为 32。

## 4. 生命周期

1. 控制面授权后获取 `WorkKind::Exec` lease。
2. Cold/Warm/Suspended Cat 通过既有 reconcile 路径回到 Running。
3. Node 获取 runtime activity guard，Guest 建立 PTY 并返回 `shell_ready`。
4. upgrade 完成，双方开始传输终端 frame；控制面每 30 秒续期 120 秒 work lease。
5. shell exit 时 Guest 先尽力排空 PTY 输出，再发送 exit status。
6. 客户端断线、代理断线或 close 会终止 Guest shell；所有 guard/lease 释放，控制面重新
   计算 auto-suspend。

V1 不支持 detach/reconnect。需要在客户端断线后继续的工作应由用户在 Cat 内使用
`tmux`/`screen`，或使用非交互任务机制和 Guest Runtime work lease。

## 5. CLI 终端行为

TTY 场景下 CLI 在连接成功后进入 raw mode，并在所有退出路径恢复原终端；`Ctrl-C`、
`Ctrl-D` 等字节由远端 shell 解释。CLI 每 250 ms 检查窗口尺寸变化，每 20 秒发送 ping。
stdin/stdout 不是 TTY 时不启用 raw mode，因此下面的非交互验收同样受支持：

```bash
printf "printf 'ready\\n'; exit\\n" | cats shell dev
```
