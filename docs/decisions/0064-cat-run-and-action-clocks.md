# ADR-0064：Cat 的动作时钟与运行时钟是两个独立的产品读字段

- 状态：Accepted
- 日期：2026-08-24
- 修正：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md) 的 Cat 产品投影字段集
- 保留：[ADR-0062](0062-destroy-preempts-in-progress-cat-actions.md) 与重试轮转把
  `current_action_started_at` 作为 settlement identity 的语义

## 背景

`cats` row 上原本只有一个对外可见的时间轴 `updated_at`。它承担了两件互相冲突的事：

1. 动作落定后，它是进入该产品状态的时刻；
2. 动作进行中，它是**活动时钟**——`refresh_current_action_activity` 和两条重试轮转
   (`rotate_stale_semantic_cat_action` 及其 destroy 变体) 会在同一个 action occurrence 继续时推进它，
   并刻意不动 `current_action_started_at`，因为后者是精确结算身份。

产品读只有 `updated_at` 时，任何"这个动作跑了多久"的展示都只能读活动时钟。这在最需要它的时候给出
反向答案：一个被重试卡了几分钟的动作，会显示成刚刚被重置的几秒。

同时，"这只 Cat 最后一次真的在运行是什么时候"在库里根本无法回答。`updated_at` 是最后一次任意变更，
running → suspended → warm → cold 走完之后它已经被后续转换覆盖；v19 schema 没有生命周期事件日志
(`runtime_operations` 属于 `FORBIDDEN_LEGACY_CONTROL_TABLES`)。唯一的近似是从计费区间反推
`usage_intervals`，而那既不准也不便宜：`storage_cold_byte_millis` 在 cold 态仍在累积，所以必须限定
`metric='cpu_usec'`；suspended 期间 cgroup 仍在、checkpoint 继续写出 quantity=0 的区间，所以还要
`AND quantity > 0`；精度只到 checkpoint 周期，且受计费保留期与查询窗口限制。

## 决策

1. `CatView` 增加两个观测字段，均为 `Option`：`current_action_started_at_unix_ms` 与
   `last_running_at_unix_ms`。两者都是**观测**，不是权威：它们不参与任何 CAS、不进入 Node 命令、
   不构成结算条件。
2. `current_action_started_at_unix_ms` 直接投影已存在的 `cats.current_action_started_at`，
   存在性与 `current_action` 完全同步（镜像 `cats_current_action_shape_check`）。它是"这个动作跑了
   多久"的唯一正确来源。`updated_at` 保留其现有含义，读者需要知道动作进行中它是活动时钟。
3. 新增 `cats.last_running_at BIGINT`，定义为**最近一次该 Cat 被记录为 settled Running 的时刻**，
   从未运行过为 `NULL`。维护规则：每一个 settle 写入，只要结果状态**或**前一个状态是 `running`，
   就把它设为该语句的 DB 时钟；其他转换不动它。`SET` 表达式里裸列引用读的是 update 前的行，所以
   一条 CASE 就能同时覆盖进入和离开 Running 两侧，无需额外往返。
4. `CHECK (state IS DISTINCT FROM 'running' OR last_running_at IS NOT NULL)`。一只已落定为 running
   的 Cat 按定义被记录过运行，为空说明漏了写入点——让它在写入时失败，而不是静默投影出一个
   "从未运行过"的 running Cat。`CatView::validate` 镜像同一条规则。
5. 列变更沿用本仓库既有立场，不引入增量迁移：`AUTHORITY_SCHEMA_PROBES` 里的 `cats` 探针加上新列，
   于是形状过期的库在**启动时**大声失败并要求重建，而不是在用户下一次动作时才在 SQL 层报错。
   `SCHEMA_VERSION` 不变，与 2026-08-23 加入 `current_action_recovery_started_at` 的做法一致：
   同一次 clean-slate 重建覆盖两列。
6. `CatView` 保留 `deny_unknown_fields`。`cats-cli` 既不发布到 crates.io 也没有安装脚本，只随
   release 分发，不存在需要兼容的旧客户端群；为一个不存在的兼容面放弃闭合形状不划算，而闭合形状
   在 request DTO 上是有价值的（ADR-0063 正是靠它拒绝 `boot_image` 覆盖）。

## 后果

`cats show` 现在能分别回答三个问题：落定态停了多久（`updated_at`）、进行中的动作跑了多久
（`current_action_started_at`，并在活动时钟已走过起点时补一句 last activity）、以及非 running 的 Cat
最后一次真的在运行是何时（`last_running_at`）。三者不再互相假冒。

产品延迟目标（创建 ≤2s、睡/醒 ≈500ms）第一次有了库内的可观测面：动作时钟给出每次转换的真实耗时，
不依赖轮询抓帧。这不替代按 Operation 的历史记录——单行只保留最新一次，没有历史。

`last_running_at` 只在 settle 写入，成本 O(1)，不需要心跳或后台推进。它明确**不是** SLA 或计费口径：
计费仍只认 `usage_intervals`。

部署这次变更需要一次控制面数据库重建。这不是本 ADR 新增的负担——main 自 2026-08-23 起就已经因
`current_action_recovery_started_at` 处于同一状态；两列在同一次重建里一起生效。
