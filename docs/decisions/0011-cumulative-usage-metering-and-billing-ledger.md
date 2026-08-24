# ADR-0011：累计计数器计量、可重放 Usage Ledger 与整数计价

- 状态：Accepted
- 日期：2026-07-24
- 相关：[ADR-0014](0014-account-workspace-identity-billing-and-switching.md)、
  [ADR-0018](0018-remove-the-v1-project-compatibility-layer.md)、
  [ADR-0040](0040-level-triggered-runtime-reconciliation.md)
- 当前生产者与投递权威：[ADR-0063](0063-semantic-node-usage-metering.md)

## 背景

账单必须在心跳丢失、Node 重启、重复或乱序投递、runtime 替换和全量重放后仍得到同一结果。
调度器的 desired allocation 和瞬时 telemetry gauge 都不能证明用户实际消耗，因此计量以
Node 读取的单调累计计数器为原始事实。

首个公开 Rate Card 为 CPU `$0.07 / CPU-hour`、内存 `$0.045 / GiB-hour`。开放账期展示
provisional 费用；正式财务分录必须来自可重放的 usage 与带版本的 Rate Card。

## Meter 与原始来源

| Meter | Canonical quantity | 权威来源 |
|---|---|---|
| `cats.compute.cpu.v1` | microsecond | 每 Cat runtime cgroup v2 `cpu.stat usage_usec` |
| `cats.compute.memory.v1` | byte-millisecond | Node 周期采样 `memory.current` 后在本地积分 |
| `cats.storage.hot.v1` | byte-millisecond | NVMe manager 的客户可归属 live bytes 积分 |
| `cats.storage.cold.v1` | byte-millisecond | ChunkStore 可达对象的客户可归属 bytes 积分 |
| `cats.network.egress.v1` | byte | 最外层客户公网 egress 计数器 |

Meter 名称、quantity 和分母一经写入不可改变。内存使用 `1 GiB = 2^30 bytes`；变更单位或价格
必须发布新的 Rate Card。存储和 egress 只有在独立 Rate Card 明确费率、归属和免费额度后
才产生金额。

## 累计检查点

Node 以 1 秒为目标采样 CPU/内存，以 10 秒为目标发布累计检查点。每个检查点至少包含：

```text
event_id
source_id, source_epoch, sequence
observed_at_unix_ms
cat_id, desired_revision, runtime_incarnation
metric, cumulative_quantity
```

- `(source_id, source_epoch, metric)` 内时间、sequence 和 quantity 单调；runtime 或计数器重建
  时创建新 source epoch，并绑定 ADR-0040 的 `desired_revision` 与 `runtime_incarnation`。
- `event_id` 由 source、epoch、metric 和 sequence 确定性派生；相同 ID 不同 payload 是冲突。
- 第一条检查点只建立 baseline。后续检查点之差形成 usage interval；中间检查点丢失由下一条
  累计值补齐，重复投递不重复计费。
- `cumulative_quantity` 在内存使用 `u128`，wire 使用 canonical decimal string，PostgreSQL
  使用 `NUMERIC(39,0)`。
- 缺少 baseline、runtime identity 不匹配、counter continuity 无法证明或 epoch 缺少最终
  检查点的区间不猜测、不补齐、不收费，并产生 coverage 告警。

Node 在本地积分 memory byte-milliseconds。控制面不能用稀疏 heartbeat 的瞬时 memory gauge
代替积分，也不能从 desired state 推导实际费用。

## 可信归属

数据面 producer 只报告 Cat、runtime identity、meter 和累计量，不选择租户、Billing Account
或价格。控制面验明 Node identity、当前 accepted revision/incarnation 与资源关系后，为原始
检查点冻结：

```text
account_id
billing_account_id
workspace_id
resource_type, resource_id
attributed_cat_id
```

`workspace_id` 表示用量由哪个资源隔离域产生，`account_id` 表示由哪个 Account 承担费用；
每个 Account 的 `billing_account_id` 是其不可变财务账本键。Workspace 不是计费所有者。
PersistentDisk 独立计量到 Disk resource；`attributed_cat_id` 只记录当时关联，不能把同一批
bytes 同时记到 Cat 和 Disk。

## Ledger 与计价

处理链固定为：

```text
authoritative counters
  -> immutable raw checkpoints
  -> replayable usage intervals / aggregates
  -> versioned Rate Card rating
  -> append-only financial ledger
  -> invoice / payment collection
```

- 原始检查点不可变；聚合、interval 和 provisional balance 是可重建投影。
- Rate Card 有不可变 ID、生效区间、canonical denominator 和币种。
- quantity 使用无符号整数，USD 使用有符号 nanodollar；任何金额路径禁止浮点数。
- 在账单查询范围内按 meter 聚合后只舍入一次。
- Invoice 保存 Rate Card version 与 usage watermark。close 后到达的 usage 通过下一周期
  adjustment 追加，不改写已关闭财务分录。
- Stripe 等支付提供商负责收款，不是 usage、余额或资源授权的权威。

首个 compute Rate Card 精确表达为：

```text
CPU:    70,000,000 nanodollars / 3,600,000,000 microseconds
Memory: 45,000,000 nanodollars /
        (1,073,741,824 bytes * 3,600,000 milliseconds)
```

## 查询与交付

同一份 interval ledger 支持按 `account_id`、`workspace_id`、不可变 `cat_id`、resource 和
meter 查询任意 `[from,to)` 范围。开放账期响应标记 `provisional` 并携带 freshness/coverage；
stream lag、Node 分区和 backfill 必须暴露滞后。

Node 先写本地 durable outbox，再以 at-least-once 方式交付。生产原始事件进入 durable stream
和独立的不可变 S3 usage archive；PostgreSQL 保存可重建投影、Rate Card、invoice watermark
和 append-only financial ledger。投影 checkpoint 只有在 archive 与数据库提交完成后推进。
组件重启从 durable checkpoint 重放，不能从内存进度猜测完成。

## 生命周期边界

- Compute billing epoch 在 Guest Ready 且 work/admission gate 开启后开始。
- 离开 Running 前先关闭新工作 gate，采集并持久交付最终累计检查点，再结束 source epoch。
- Suspended 中仍可归属到 Cat runtime cgroup 的 CPU/RAM 按实际消耗计量；共享平台进程不进入
  Cat cgroup。
- 启动失败、restore 失败或 quiesce 后的清理时间不自动收费；身份或 coverage 证据不足时
  fail closed。

## 验收

- 重复、乱序、缺失中间检查点和全量 archive replay 得到相同 interval 与金额。
- runtime replacement 后旧 revision/incarnation 的检查点不能进入新 epoch，也不能改变其
  Operation 或归属。
- 伪造 `account_id`、`workspace_id`、`billing_account_id`、价格或 resource attribution 的
  producer payload 被拒绝。
- Node/stream/projector/PostgreSQL 在每个持久边界崩溃后不丢量、不重复计费；无法证明的区间
  显示 coverage gap。
- u128/NUMERIC 边界、Rate Card 生效边界、任意查询区间和一次舍入规则有确定性测试。
- 正式收费只在持续 shadow billing、archive 全量 replay reconciliation、invoice close、迟到
  adjustment 和财务对账全部通过后开启。

## 后果

计量正确性来自单调累计量、不可变原始事件和可重放投影，不依赖通知必达或某个进程的内存。
代价是必须持久保存 source identity、coverage 和最终检查点，并把正式收费置于独立财务验收门后。
