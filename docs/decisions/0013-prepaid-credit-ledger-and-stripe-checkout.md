# ADR-0013：预付费资金账本与 Stripe Checkout

- 状态：Accepted
- 日期：2026-07-25
- 相关：[ADR-0011](0011-cumulative-usage-metering-and-billing-ledger.md)、
  [ADR-0014](0014-account-workspace-identity-billing-and-switching.md)、
  [ADR-0018](0018-remove-the-v1-project-compatibility-layer.md)、
  [ADR-0040](0040-level-triggered-runtime-reconciliation.md)

## 背景

Cats 使用预付费余额控制付费工作。赠金、充值、退款和 usage 扣减必须在并发、Webhook
重放、乱序及伪造支付跳转下保持可审计。Stripe 负责收款和退款通知；Cats 的不可变资金
账本才是余额权威。

## Account 与注册赠金

- 每个 Account 恰好拥有一个不可变 `billing_account_id`；该 Account 的全部 Workspace
  共享这一本资金账。Workspace 产生用量，但不是计费所有者。
- 注册赠金资格唯一键是 `(workos_user_id, campaign)`，受益人固定为该用户的 Personal
  Account Billing Account。首个 campaign 为一次性 `$10`；创建 Workspace、加入或创建
  Organization Account、退出后重进都不产生第二笔赠金。
- Organization Account 不领取 Personal signup credit。
- 金额统一使用带符号 USD nanodollar 整数，API 使用十进制 String；任何余额、账本和
  Rate Card 路径禁止浮点数。

## 资金账本与余额

- `credit_ledger_entries` 是不可变资金事实；赠金和充值为正数，退款/reversal 为负数。数据库
  拒绝 UPDATE/DELETE。
- 每笔业务事件使用稳定 external/idempotency key；相同 key 不同 payload 是冲突，重放不
  产生第二笔资金分录。
- 当前可用额度为：

  `SUM(credit ledger) - all-time provisional rated usage`

- 余额是 admission projection，不是已关闭发票。Invoice close 和迟到 adjustment 遵循
  ADR-0011，不能改写已关闭分录。

## Stripe 边界

1. Checkout 只能使用 Terraform 管理的固定 Price ID 与允许的 `$10/$25/$50/$100` 档位；
   浏览器不能指定任意 Price 或入账金额。
2. Cats 在调用 Stripe 前持久化 Checkout intent。intent 与 Stripe metadata 都绑定内部
   intent ID、`account_id`、`billing_account_id`、金额和币种；Workspace 不进入资金归属。
3. Stripe POST 使用稳定 Idempotency-Key。Checkout success redirect 只用于展示，绝不入账。
4. Webhook 必须对原始 body 验证 `Stripe-Signature`、timestamp tolerance 和 deployment
   livemode。只有 paid 的 `checkout.session.completed` 或
   `checkout.session.async_payment_succeeded` 可以入账。
5. Stripe Event ID、Checkout Session ID、PaymentIntent ID 与内部 intent 必须相互匹配；
   event receipt 和 credit entry 在同一数据库事务内提交。
6. `refund.created` / `refund.updated` 只有在状态为 `succeeded` 时产生负数 reversal。退款先于
   原 paid Checkout 到达时返回可重试错误，不凭未知事件创建资金。
7. Stripe customer identity 绑定 Account Billing Account；Stripe metadata、跳转参数或
   Webhook payload 不能改变 Cats 内部归属。

## 余额门禁

- Account 可用额度 `<= 0` 时，其 Workspace 中的 Create、Start/Resume、Exec/Shell 和
  Endpoint wake 返回 `payment_required`。
- Stop、Suspend、Warm、Delete、数据 drain 和账单查询始终允许，避免欠费阻止资源释放或
  数据保护。
- credit enforcer 只提交受版本保护的 lifecycle desired change，并使用 ADR-0040 的正常
  reconciliation 收敛；它不直接操作 Node runtime。
- 采样、delivery 和 projection 有延迟，因此预付费控制允许有界超额，不宣称零延迟 hard cap。

## 基础设施与秘密

- 官方 Stripe Terraform Provider 管理 Product、Price 和 Webhook Endpoint；支付资源使用
  独立 Terraform state。
- Stripe secret key、Webhook secret 和 Price ID map 通过受控 secret channel 进入仅控制面
  可读的运行时 Secret，不进入浏览器、Guest、日志或 Terraform 普通输出。
- 资金账与 usage projection 使用 PostgreSQL 中逻辑隔离的表；Stripe 不是数据库备份或恢复源。

## 验收

- 并发 Personal onboarding 对同一 `(workos_user_id, campaign)` 最多产生一笔赠金；
  Organization onboarding 不产生赠金。
- Checkout 创建/重试、Webhook 重放与乱序不会重复入账；相同 identity 不同金额或 Account
  必须失败。
- success redirect、错误签名、错误 livemode、过期 timestamp、未知 intent 和归属不匹配均
  不能改变余额。
- paid、async paid、refund 和 reversal 在进程或数据库事务边界崩溃后可幂等恢复。
- Account 的所有 Workspace 共享同一余额，不同 Account 互相隔离；producer 不能通过
  Workspace 或 Stripe metadata 选择另一个 Billing Account。
- 正式收费开关只在 usage shadow reconciliation、Stripe test/live 对账、退款/乱序故障测试
  和财务验收完成后开启。

## 后果

Account 是资金责任边界，Personal signup eligibility 是赠金边界，Stripe 只负责外部支付事件。
这让充值、退款和 usage 扣减可以独立重放和审计，也把支付可用性与 Running 数据面解耦。
