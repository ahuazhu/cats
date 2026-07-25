# ADR-0013：预付费资金账本与 Stripe Checkout

- 状态：Accepted
- 日期：2026-07-25

> “每个 Billing Account 首次建立时赠送 10 美元”已由 ADR-0014 的 Personal signup
> eligibility 规则取代；不可变资金账本、Stripe 和余额控制决定继续有效。

## 背景

ADR-0011 已选定累计 usage ledger、精确整数 Rate Card 与准实时账单分析，并明确支付
提供商不是 usage 真相源。产品现在采用预付费模式：每个新账户赠送 10 美元，用完后
通过 Stripe 充值，CPU 为 `$0.07 / CPU-hour`，内存为
`$0.045 / GiB-hour`。

注册赠金、充值、退款与 usage 扣减必须在并发、Webhook 重放、乱序和支付跳转伪造下
保持可审计。仅依赖 Stripe Checkout 成功返回页会允许伪造入账，也无法回答某一时刻
账户为什么有当前余额。

## 决策

### 账户与赠金

- 当前一个 Project 对应一个显式
  `billing_account/project/<project>`。未来 Organization 到多个 Project 的映射通过
  新表演进，不改写历史资金或 usage。
- 每个 Billing Account 首次建立时生成一次 `$10`、不续期的 promotional credit。
  同一 Organization 邀请多个用户不会重复领取个人赠金。
- 金额统一使用带符号 USD nanodollar 整数。API 使用十进制 String，禁止浮点金额。

### 双账本与余额

- `usage_checkpoints` 是不可变用量事实；`usage_intervals` 是可重建投影。
- `credit_ledger_entries` 是不可变资金事实。赠金和充值是正数，退款是负数；数据库
  Trigger 拒绝 UPDATE/DELETE。
- 当前可用额度为：

  `SUM(credit ledger) - all-time provisional rated usage`

- 余额是准实时 admission projection，不是已关闭发票。正式 invoice close、迟到
  adjustment 和税务凭证仍需独立实现。

### Stripe 边界

- Stripe Checkout 使用服务端创建的固定 Price ID，只开放 Terraform 管理的
  `$10/$25/$50/$100` 档位。浏览器不能提交任意 Price ID 或任意入账金额。
- Cats 在调用 Stripe 前持久化 Checkout intent，并把内部 intent、Billing Account
  和 Project 写入 Stripe metadata。Stripe POST 使用稳定 Idempotency-Key。
- Checkout success redirect 绝不入账。只有对原始 Body 验证
  `Stripe-Signature`、五分钟 timestamp tolerance 和 deployment livemode 后，
  `payment_status=paid` 的 `checkout.session.completed` 或
  `checkout.session.async_payment_succeeded` 才能入账。
- Stripe Event ID、Checkout Session ID、PaymentIntent ID 和内部 intent 必须匹配；
  Event receipt 与 credit entry 在同一数据库事务内提交。
- `refund.created` / `refund.updated` 只有在状态为 `succeeded` 时生成负数 reversal。
  Webhook 乱序到达且找不到原 paid Checkout 时返回非 2xx，让 Stripe 重试。
- Stripe 是收款和退款通知基础设施，不是 Cats 余额或资源授权真相源。

### 余额不足

- 可用额度 `<= 0` 时，创建 Cat、Start/Resume、Exec/Shell 与 Endpoint wake 返回
  HTTP `402` / `payment_required`。
- Stop、Suspend、Warm、Delete 和账单查询不被阻止，避免欠费用户无法释放资源或
  取回账单证据。
- Web Console 收到 `402` 后按最小充值档位发起服务端 Checkout 并跳转 Stripe；
  Billing 页面也提供全部固定档位。
- 启用生产收费开关后，周期性 credit enforcer 每 10 秒检查活跃 Project；可用额度
  `<= 0` 时把仍要求 Running 的 Cat 收敛到 Cold。由于采样、Kinesis projector 与
  final checkpoint 都有延迟，它是有界超额的预付费控制，不宣称为零延迟 hard cap。

### 基础设施

- 官方 `stripe/stripe` Terraform Provider 管理 Product、Price 和 Webhook Endpoint，
  独立 `production-payments` state 保存敏感 webhook secret。
- Application state 通过受控 secret channel 接收 Stripe secret key、Webhook secret
  与 Price ID map，并写入仅 `cats-controld` 可见的 Kubernetes Secret。
- 本功能不购买新的数据库或对象存储。早期阶段与 usage projection 共用 PostgreSQL
  实例和 `cats_usage` schema 中的逻辑隔离表；未来按 ADR-0011 的一致性 runbook 拆库。

## 后果

优点：

- 赠金、充值、退款与 usage 都有不可变证据，Webhook 重放不会重复加钱；
- Stripe Hosted Checkout 降低支付页面与卡数据处理范围；
- 固定 Price 和 Terraform 状态使生产配置可审查、可复现。

代价：

- 准实时余额受 usage checkpoint/projector 延迟影响；
- Stripe 密钥和 Terraform payment state 都属于生产凭据；
- 上线严格预付费控制前还要完成 Running workload 收敛、Webhook 乱序/退款/故障
  重放、Stripe test/live shadow reconciliation 和财务验收。
