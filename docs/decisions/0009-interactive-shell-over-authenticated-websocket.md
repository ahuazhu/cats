# ADR-0009：交互式 Shell 使用受鉴权的 WebSocket PTY 流

- 状态：Accepted
- 日期：2026-07-22

## 背景

产品架构要求 `cats shell dev` 像本地终端一样进入 Cat，并在 Cat 休眠时先唤醒。
现有 `cats exec` 是一次性 JSON 请求，只能返回完整 stdout/stderr，不能表达 PTY、窗口
尺寸变化、实时输入输出或终端退出状态。直接在 Guest 中运行 sshd 又会引入端口、用户、
host key、authorized_keys 和另一套身份生命周期；这些都与 Cats 已有的 WorkOS 身份和
Workspace 授权重复。

长期架构可以把会话流量迁到独立 Session Gateway，但 V1 已有的控制面是唯一公开 HTTPS
入口。为了先固定用户契约和 Guest 协议，V1 由控制面承担受限的会话代理角色。

## 决定

1. CLI 提供 `cats shell <cat>`。它使用当前 `cats login` 的短期 WorkOS access token 和
   当前 Workspace，不建立 SSH 账号、SSH key 或 TCP 22 listener。
2. 公开入口是
   `GET /v1/workspaces/{workspace_id}/cats/{cat}/shell?rows={rows}&cols={cols}` 的 WebSocket
   upgrade。控制面必须在唤醒 Cat 和连接 Node 之前完成与普通资源 API 相同的 Workspace
   授权；内部 Control Plane → Node WebSocket 使用独立 service bearer token。
3. Cat 非 Running 时，控制面先获取 work lease 并触发既有 singleflight wake。会话存活
   期间持续持有并续期 work lease，防止自动 Suspend；结束后释放，再重新计算
   auto-suspend。
4. Node Agent 在接受 upgrade 之前确认 Cat 仍为 Running、获取 runtime activity guard，
   然后通过既有 Unix/vsock Guest 控制通道打开 PTY。Suspend quiesce 竞态返回 409，
   控制面最多重试一次。
5. Guest Agent 使用平台 PTY 启动 `/bin/sh -l`，设置 `TERM=xterm-256color`，并把它绑定
   到 Cat 的信任边界。V1 不提供 detach/reconnect；客户端断开会关闭 PTY 并终止 shell。
6. WebSocket binary frame 是不解释的终端字节。JSON text frame 只承载 resize、close、
   exit status 和结构化错误；ping/pong 用于保活。Guest 内部使用同语义的有界
   length-prefixed JSON frame。完整格式见
   [Interactive Shell Protocol v1](../specs/interactive-shell-protocol.md)。
7. rows/cols 必须在 1..=1000；每一跳使用有界 channel，不允许慢客户端造成无界输出
   缓冲。终端明文不写资源数据库或应用日志。

## 安全与失败语义

- 公共 upgrade 前先校验 WorkOS JWT 的签名、issuer、client、expiry、subject 和
  Organization/个人 Workspace 映射；仅改变 URL 中的 workspace/cat 不能越权。
- WorkOS、service token、对象存储和 metadata 凭据不进入 Guest。Guest 只接收 PTY
  字节和尺寸控制帧。
- 任一代理跳断开都会向下游关闭会话；CLI 必须收到显式 exit frame 才把远端退出码当作
  正常结束。异常关闭按失败返回，不能伪装为 exit 0。
- 当前默认 shell 以 Guest Agent 的系统身份运行。V1 把整个 Cat 视为一个用户信任
  边界；未来若提供 Cat 内多用户隔离，必须新增身份映射和 privilege-drop 设计。

## 影响

- V1 的控制面同时转发 PTY 字节，与完整架构中独立 Session Gateway 的目标拓扑不同；
  这是明确的实现阶段选择。以后拆出 Session Gateway 时应保持公开 WebSocket frame 和
  CLI 行为兼容，并把 Node service 鉴权替换为短期单用途 session credential。
- `cats exec` 继续使用非 PTY argv API，适合脚本和结构化 stdout/stderr；`cats shell`
  用于交互终端，二者不互相模拟。
- 会话审计事件、detach/reconnect、文件复制和 IDE tunnel 不在本 ADR 的已实现范围内。
