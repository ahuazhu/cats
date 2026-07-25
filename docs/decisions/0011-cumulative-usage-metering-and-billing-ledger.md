# ADR-0011：累计计数器计量、可重放 Usage Ledger 与整数计价

- 状态：Accepted
- 日期：2026-07-24

## 背景

Cats 已决定采用 Sprites 类似的实际用量模型，首个公开 Rate Card 为：

- CPU：`$0.07 / CPU-hour`
- 内存：`$0.045 / GiB-hour`

用户还必须能够查询一个 Billing Account（当前 V1 的 Workspace/Project）任意时间范围的
账单、一个 Cat 任意时间范围的详单，以及按计费项聚合的账单，并在正常情况下看到
10～60 秒内更新的预估费用。

旧架构文档 §16 按 allocation/lifecycle 事件推导 vCPU 和 RAM，用心跳中的瞬时浮点
gauge 表示资源用量。这无法在心跳丢失、Node 重启、重复投递、进程切换或账单重放时
给出可证明的结果，也会把调度器的逻辑容量承诺误当成用户实际消耗。

## 决定

### 1. Meter 定义与原始来源

V1 meter 名称和 canonical quantity 一经写入不可改变：

| Meter | Canonical quantity | 权威来源 |
|---|---|---|
| `cats.compute.cpu.v1` | microsecond | 每 Cat runtime cgroup v2 `cpu.stat usage_usec` |
| `cats.compute.memory.v1` | byte-millisecond | Node 每秒采样 `memory.current` 后在本地积分 |
| `cats.storage.hot.v1` | byte-millisecond | NVMe manager 的客户可归属 live bytes 积分 |
| `cats.storage.cold.v1` | byte-millisecond | ChunkStore 可达对象的客户归属 bytes 积分 |
| `cats.network.egress.v1` | byte | 最外层客户公网 egress 数据面计数器 |

首个 Rate Card 只给 compute meter 定价。存储和 egress 可以先进入 ledger，但在独立
Rate Card 明确费率、归属和免费额度以前不得产生金额。

内存分母明确采用 `1 GiB = 2^30 bytes`；如果产品文案写 GB，它仍指这个 Rate Card
固定的二进制分母。改变为十进制 GB 必须发布新 Rate Card，不能改写历史账单。

当前 `NodeTelemetry.cpu_usage_cores`、`memory_rss_bytes` 和
`host_disk_used_bytes` 只用于监控，不能进入财务账单。Suspended/Warm 的
`resume_commit_bytes` 是调度容量承诺，也不是实际内存计量。

### 2. 采样与累计检查点

Node 在本地以 1 秒为目标采样 CPU/内存，按 10 秒为目标发布累计检查点；生命周期
关闭门禁、runtime epoch 结束和正常 Node shutdown 前必须再发布最终检查点。检查点
包含：

```text
event_id
source_id, source_epoch, sequence
observed_at_unix_ms
cat_id, cat_generation
metric, cumulative_quantity
```

- `source_epoch` 在 cgroup/计数器可能归零、runtime 重建、Cat generation 或账单归属
  改变时必须改变。
- `(source_id, source_epoch, metric)` 内时间、sequence 和 quantity 单调。
- `event_id` 由 source、epoch、metric、sequence 确定性派生；相同 ID 不同 payload
  是冲突，不是更新。
- 第一条检查点只建立 baseline，不产生用量。后续检查点的差值形成 usage interval。
- 丢失中间检查点不会丢量；下一条累计值补齐整个缺口。重复投递不重复计费。
- `cumulative_quantity` 在内存中使用 `u128`，wire 使用 canonical decimal string，
  PostgreSQL 使用 `NUMERIC(39,0)`。不能用 `u64/BIGINT` 保存 byte-milliseconds：
  1 GiB 常驻约 198 天就会超过 `u64`，更大内存会更快溢出。
- 缺少 baseline、无法验证 counter continuity 或 epoch 结束时没有最终检查点的区间
  不猜测、不补齐、不收费，并产生 freshness/coverage 告警。

Node 先在本地积分 memory byte-milliseconds，再发送累计值。控制面不能只用两次
10 秒心跳的 memory gauge 代替 1 秒积分；否则短时峰值和丢包都会改变账单。

### 3. 可信归属

数据面 producer 不选择 `billing_account_id` 或价格。控制面接收检查点时验证 Node
身份、Cat ownership 和 generation，再冻结：

```text
billing_account_id
project_id
resource_type, resource_id
attributed_cat_id
```

Billing Account 是独立、不可变的财务主键；WorkOS Organization ID 是可变的身份映射，
不是 usage 主键。当前仓库没有独立 Project/Organization 表，开发实现暂时使用显式的
`billing_account/project/<project>` 映射。引入一 org 多 project 或个人账户时增加映射
表，不改写历史 usage。

PersistentDisk 独立计量到 Disk resource；`attributed_cat_id` 只表示当时的操作关联，
不能同时把同一批 bytes 记到 Cat 和 Disk 两次。RootDisk 可归属所属 Cat。

### 4. Ledger、聚合、计价和财务账分层

处理链固定为：

```text
authoritative counters
  -> immutable raw checkpoints
  -> replayable usage intervals / minute buckets
  -> versioned Rate Card rating
  -> append-only financial ledger
  -> invoice / payment collection
```

- 原始检查点不可变；乱序到达时可以重建相邻 interval。
- 聚合表是可重建投影，不是原始真相。
- Rate Card 有不可变 ID、生效区间、canonical denominator 和币种。
- quantity 使用无符号整数；USD 使用有符号纳美元。禁止浮点金额。
- 先在账单查询范围内按 meter 聚合，再只舍入一次。不能每秒或每分钟分别舍入后求和。
- Invoice 保存 rate-card 版本和 usage watermark。Invoice close 之后到达的迟到数据通过
  下一周期 adjustment 追加，不修改已出具财务分录。
- Stripe 等支付提供商只负责订阅和收款，不是 usage、余额或资源授权的真相源。

首个 compute Rate Card 的精确表达为：

```text
CPU:
  70,000,000 nanodollars / 3,600,000,000 microseconds

Memory:
  45,000,000 nanodollars /
  (1,073,741,824 bytes * 3,600,000 milliseconds)
```

### 5. 查询与准实时语义

同一份 interval ledger 必须支持：

1. `billing_account_id + [from,to)`：账户账单；
2. `attributed_cat_id + [from,to)`：单 Cat 详单；API 同时接受活跃 Cat name 和不可变
   `cat_id`，删除后的历史详单必须用 `cat_id` 查询；
3. `metric + [from,to)`：按计费项聚合；
4. project/resource 等内部对账维度。

开放账期的 API 返回 `provisional`。正常路径目标为采样 1 秒、检查点 10 秒、查询投影
10～60 秒内可见。生产 archive writer 最长缓存 50 秒，给检查点发布周期预留 10 秒。
响应中的 latest interval end 只表示当前已处理到的最新数据，不是
finalization watermark。发生 Node 分区、stream lag 或 backfill 时必须显示滞后；不能用
控制面 desired state 伪造“看起来更新”的费用。

任意时间范围与 interval 边界不对齐时，查询按 interval 内均匀分布对边界部分做比例
分摊。该部分是展示估算；最终账单应使用完整结算 bucket 和 invoice watermark。

### 6. 存储和交付形态

本地开发使用同一个 SQLite 文件中的独立 `usage_checkpoints` 和 `usage_intervals` 表，
验证事件、去重、重放、查询和整数计价契约；这不是生产吞吐承诺。

生产形态为：

- 托管 durable stream（AWS 首版可用 Kinesis）承接 at-least-once 检查点；
- 独立 S3 usage archive bucket 保存原始事件和 replay/backfill 证据；不得复用
  ChunkStore 用户块数据 bucket；
- PostgreSQL 独立 usage/billing schema 或 logical database 保存查询投影、Rate Card、
  invoice watermark 和 append-only financial ledger；
- V1 不要求购买 ClickHouse。只有 PostgreSQL 聚合延迟或保留成本经测量超过门槛后再引入。

当前 AWS 生产形态已经由 Terraform 创建 Kinesis、独立 S3 archive 和 DynamoDB
projector checkpoint table，并把 EKS Pod Identity 最小权限授予 control plane 的
专用 ServiceAccount。Node 不需要新的 block volume；本地 spool 使用现有受配额管理的
NVMe，只用于断网缓冲，Kinesis 与 S3 才是 Host 之外的持久证据。

## 计费生命周期边界

- Compute billing session 在 Guest Ready 且工作 admission gate 打开后开始。
- 进入 Suspend/Warm/Cold 时，先关闭新工作 gate，采集最终累计检查点，再结束 epoch。
- Suspended 的 cgroup 若仍有少量 runtime CPU/内存，仍按“实际消耗”进入 compute
  meter。共享 Node Agent、控制面和非 Cat 专属后台任务不得放入该 cgroup；VMM/device
  backend 无法与 Guest 物理内存完全拆分的专属开销属于该 Cat 的实际 runtime footprint。
- `auto_suspend=false` 或 Pin 只是让 session 持续存在，仍按实际 CPU 和实际内存积分，
  不按配置 allocation 补量。
- 平台启动失败、restore 失败或 quiesce 后的清理时间不自动收费；缺少可信 gate/epoch
  证据时 fail closed。

## 与既有文档的关系

本 ADR 在计费模型上取代
[`cats-complete-product-technical-architecture.md` §16](../cats-complete-product-technical-architecture.md)
中的 allocation/lifecycle 推导费率和旧 `UsageRecord` 草案。该文档中的不可变 usage
ledger、支付提供商不是真相源、欠费保留策略等原则继续有效。

它不改变 ADR-0002 的 Running/Suspended/Warm/Cold 语义，不把实际账单数字用于调度；
也不改变 ADR-0003/0005 的 ChunkStore durable truth 与 provider-neutral storage ports。

## 当前实现状态

本次实现新增：

- `cats-api::metering` 的稳定 meter/checkpoint/report wire types；
- `cats-metering::UsageStore` 端口，以及 SQLite 开发 adapter 的确定性 ID、
  重复/乱序/重放处理、任意区间查询、org/project、Cat、metric 聚合和精确 compute
  rating；控制面不再依赖具体 SQLite 类型；
- PostgreSQL production usage adapter：独立 schema、显式 migration version、
  固定连接 worker pool、同 source epoch 的事务级 advisory lock、数据库级 insert-only
  raw checkpoint trigger、`NUMERIC(39,0)` 累计量、可变/可重建 interval projection，
  以及可选 live contract test；
- service-only checkpoint ingestion 与 project-scoped provisional usage API；
- Node delegated cgroup v2 采样：默认 1 秒采样、10 秒累计检查点；未配置权威 cgroup
  时不会从 `/proc` telemetry 生成账单；
- Node 本地 SQLite usage spool：WAL、`synchronous=FULL`、不可变 outbox、启动重放和
  at-least-once delivery；lifecycle 关闭 runtime 前同步采集 final checkpoint，并在
  Kinesis 接受该 checkpoint 后才报告操作成功；
- AWS durable delivery adapter：控制面先冻结可信归属，再向 Kinesis `PutRecord`；
  projector 按 shard 最多缓存 50 秒、4 MiB 或 1000 条，把 exact attributed envelope
  写成 NDJSON S3 Object Lock archive，然后幂等投影 PostgreSQL，最后推进 DynamoDB
  checkpoint。重启会从未推进的 checkpoint 重放；
- Terraform 管理 Kinesis、七年 GOVERNANCE S3 archive、DynamoDB checkpoint、
  CloudWatch 告警、EKS Pod Identity、Kubernetes ServiceAccount 与应用发布；
- AWS bare-metal 生产形态已验证 1 秒 cgroup 采样、持久 outbox、删除后的 final
  checkpoint、Kinesis/S3/PostgreSQL/DynamoDB 全链路，以及 provisional API 的
  account/Cat/meter 聚合。

尚未实现、不能由本 ADR 推断为已有：

- storage/egress Rate Card；
- invoice close 与迟到 adjustment；Stripe 预付费 collection 已由 ADR-0013
  实现，但仍需完成 shadow reconciliation 和财务上线验收；
- projector 多副本 shard lease。当前 `cats-controld` 是 `Recreate` 的单副本，
  DynamoDB 只保存每个 shard 的 durable checkpoint；扩成多副本前必须增加条件租约，
  不能让多个 projector 无协调地消费同一 shard。

当前只提供 `provisional` 账单分析，正式扣费保持关闭。开启生产收费前仍必须完成
stream/Node 故障注入、S3 全量 replay reconciliation、连续 shadow billing、invoice
close/迟到 adjustment 和财务对账验收。
