# ADR-0058：Route ring ACK 绑定不可变 AgentSession 历史

- 状态：Accepted
- 日期：2026-08-21
- 修正：[ADR-0056](0056-atomic-per-cat-runtime-lifecycle.md) 的 schema 17 组成；新终态为
  clean-slate schema 18
- 相关规格：[Agent Registration and Internal Transport v1](../specs/agent-registration-transport-v1.md)、
  [Route v2 Signing Authority v1](../specs/route-signing-authority-v1.md)

## 背景

每个 Node 的 `current_agent_sessions` 只有一行。正常 Agent replacement 会把这一行从旧
SessionBinding 更新成新 SessionBinding。schema 17 却让 `route_node_ring_acks` 的 exact-session
外键指向这行可变 current pointer；只要 Node 已经提交过 ring ACK，旧 ACK 就会阻止 current row
更新。Control 因此无法签发下一张 AgentSession，Node 又必须先取得新 AgentSession 才能提交新 ACK，
形成无法自行恢复的循环依赖。

旧 ACK 不是当前会话授权。它只是某个已签发会话曾安装某版 public ring 的持久历史事实；Route signer
是否可签发仍必须在同一数据库快照中把 ACK、current AgentSession、fresh Full inventory、Serving
receipt 和 current ring 逐项精确比较。

## 决策

schema 18 将 `route_node_ring_acks_exact_session_fkey` 改为引用不可变的
`agent_registration_attempts(node_id,node_boot_id,agent_instance_id,agent_session_epoch)`，并为该 exact
tuple 建立唯一约束。

- Agent replacement 可以先创建下一 epoch 并原子替换 `current_agent_sessions`；
- 旧 ring ACK 保留且仍能证明它引用的历史 AgentSession 确实签发过，但因为不等于 current session，
  不能参与 Route 签发、uncordon 或 Serving；
- replacement 后 Node 从 Closed 开始，提交 current session 的 fresh Full inventory 和新 ring ACK；
- `route_node_ring_acks` 仍保持每 Node 一行、epoch/sequence forward-only，不能删除或倒退；
- immutable registration attempt 不能更新或删除，因此历史 ACK 的关系完整性不会因 current pointer
  前进而丢失。

schema 17 与 18 不共用一个版本号，也不提供双写、兼容 reader 或在线修补。首次 schema 18 部署使用现有
clean-slate reset，并由 cordoned Node provisioning 工具重新建立 NodeIdentity；测试数据不迁移。

## 后果

Node 每次进程重启可以按 exact expected epoch 正常取得下一张 AgentSession。旧 ACK 会自然变成 stale，
而不是阻塞注册；只有新会话完成 inventory 与 ring ACK 后才重新具备 admission 条件。

代价是 schema 18 需要一次 clean-slate 发布与 NodeIdentity 重新 provision。该步骤属于发布自动化，不允许
再以手工 SQL、临时公网入口或删除 ACK 绕过。
