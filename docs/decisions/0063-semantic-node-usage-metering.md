# ADR-0063：语义协议下的 Cat 用量计量与可信归属

- 状态：Accepted
- 日期：2026-08-24
- 计量与计价：[ADR-0011](0011-cumulative-usage-metering-and-billing-ledger.md)
- 协调协议：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md)
- 计费账本：[ADR-0013](0013-prepaid-credit-ledger-and-stripe-checkout.md)、
  [ADR-0014](0014-account-workspace-identity-billing-and-switching.md)

## 背景

ADR-0011 的账本、计价、归属冻结、Kinesis 投递与 PostgreSQL 投影都仍在服务，读侧
`GET /v1/workspaces/{workspace}/billing/{balance,usage}` 也仍然正确。但原有生产者是为
ADR-0040 的签名 Runtime spine 写的：Node 侧 usage spool 与签名投递、Control 侧
`/v1/internal/usage/checkpoints` 的 Ed25519 request proof 与 AgentSession fence。原子生命周期
切换一次性下线了这一整条链路，ADR-0059 的语义协议没有重建它。

结果不是报错，而是静默：账本一直是空的，每个计费读取都返回一个格式正确的 0。生产从
2026-08-10 起再没有一条 usage 记录进入流，同时仍有 Cat 在运行并计费为零。

语义协议也不再具有原生产者依赖的权威：没有 per-Node Ed25519 凭据、没有 AgentSession epoch、
没有 Desired revision。照搬旧生产者需要重新引入这些签名域，而下层
`(source_id, source_epoch, metric, sequence)` 的确定性 `event_id` 与累计计数器语义已经独立提供
了防重放与防重复计费。

## 决策

1. **Node 侧生产者回到语义协议内。** noded 在 systemd 委派的 cgroup v2 子树下为每个 Cat runtime
   建立一个 cgroup，把该 Cat 的 Guest VMM 记入其中，按 1 秒采样 `cpu.stat usage_usec` 与
   `memory.current`，按 10 秒发布累计检查点。ADR-0011 的 meter 定义、单位、
   `RuntimeMeterAccumulator` 积分与 Rate Card 不变。
2. **source epoch 就是 runtime incarnation。** 一个 Cat runtime 的 cgroup 在其整个受管生命期内保留，
   跨 Suspend、Warm 与 Warm restore 都是同一 epoch，因此 CPU 计数器保持单调；Cold 或 Destroy 释放
   cgroup 并发布该 epoch 的 final 检查点，之后的 run 是一个带自己 baseline 的新 epoch。
3. **投递复用既有 Node 通道的权威。** `POST /v1/internal/usage/checkpoints` 与 register/heartbeat
   一样以共享 noded service token 认证，不再有 per-request Ed25519 proof、AgentSession fence 或
   Desired revision 校验。理由是这些校验在语义协议下没有可校验的权威可绑定，而账本的幂等性来自
   确定性 `event_id` 与累计量本身。
4. **归属仍然只由 Control 冻结，并绑定 placement。** 生产者只报告 Cat、meter 与累计量。Control 用
   exact `cats` 行解析 Workspace 与 Billing Account，并在该 source epoch 的首个检查点上冻结；同一
   epoch 的后续检查点重用冻结结果，因此已销毁或已改属的 Cat 的尾部仍记在原所有者名下，Node 永远不能
   改变金额的归属。
   开启一个新 epoch 还必须证明报告方确实在跑这个 Cat：service token 是 Node fleet 级共享的，所以
   「认证为某个 Node」不能证明可以给哪些 Cat 记账。Control 因此要求 `cats.node_id` 或
   `cats.current_action_node_id` 之一等于报告 Node —— 前者是已落定的 placement，后者覆盖首个检查点
   早于 create 动作结束、以及 planned drain 期间源已落定而目标持有动作这两种真实情况。两者都不匹配的
   检查点被点名拒绝；这不会伤害 epoch，因为下一条累计样本会重新解析归属。
5. **计量是观测，不是权威。** 任何 cgroup 建立、采样或投递失败只记录并跳过，绝不影响 Cat 的启动、
   停止或任何物理效果。未投递的检查点在 Node 内存中有界排队；队列溢出丢弃最旧的一条，
   因为累计计数器让后一条携带同样的总量，只可能少计、不可能重复计费。
6. **无法归属的检查点被点名，而不是重试。** 找不到计费所有者的检查点在响应中作为 `rejected` 返回，
   使有序批次里它后面的检查点仍能结算，生产者也不再重发它。

## 后果

- 计量精度不变：仍然是实际消耗的 cgroup 计数器，而不是 desired allocation 或瞬时 telemetry。
- 计量的传输权威被削弱为 Node fleet 级共享 token。持有该 token 的一方只能为 Control 认定在它所声称的
  Node 上的 Cat 开启用量 epoch；它不能选择付款方，不能改写已冻结的归属，也不能重复计费同一
  `event_id`。
- **残余暴露（明确不在本 ADR 关闭）**：ADR-0059 全程用一个 fleet 共享 token，Node 身份写在 body 里
  ——`register` 和 `heartbeat` 就是这样认身份的。因此 `node_id` 是被声称的，不是被证明的：持有 token 的
  一方可以声称自己是另一台 Node，从而给那台 Node 上的 Cat 记账。比较 body 里的两个字段不能制造出身份，
  所以本 ADR 不假装 `node_id == session.node_id` 是认证；它只是报文自洽检查。
  真正收窄它需要在整个语义面（register/heartbeat 一起）引入 per-Node 身份，那是协议变更和独立工作。
  在那之前，边界由 placement 和「金额只由 Control 决定」这两件事界定，并由
  `a_claimed_node_identity_is_bounded_by_placement_not_proven` 钉住现状：per-Node 身份一旦落地，
  这个测试的第一条断言就会开始失败，提示回来更新本节。
- Suspended 与 Warm 期间 CPU 计数器自然停止增长，内存按该 cgroup 实际保留的字节继续积分。两个状态都是
  Host-bound 且真的占着本机内存，因此这不是多计，而是与 ADR-0002 的状态语义一致。
- Node 进程崩溃会丢失尚未投递的尾部（秒级到分钟级），并使下一个 epoch 从新 baseline 开始。这是
  ADR-0011 允许的 coverage 缺口方向：少计，不是多计。恢复持久 spool 是独立工作。
- 运行 `cats-noded` 的每个 systemd unit 必须声明 `Delegate=cpu memory`；缺少委派的 Host 正常服务但
  不产生用量，并在启动时记录 error。
