# 让真实应用能睡：Cat 与应用的责任划分

> 状态：设计提案，未实现。2026-07-27。
>
> 人类版：[`cats-sleepable-workload-design.html`](cats-sleepable-workload-design.html)（自包含单文件，可直接在浏览器打开）。
>
> 服从 ADR-0002（Running / Suspended / Warm / Cold）与 ADR-0007（Guest Runtime API）。
> 实测依据见 [`experiments/suspend-clock-semantics-20260727`](../experiments/suspend-clock-semantics-20260727/README.md)
> 与 [`experiments/dozing-memory-reclaim-20260727`](../experiments/dozing-memory-reclaim-20260727/README.md)。

## 1. 要解决的问题

Cat 睡觉是为了省钱。但一个真实的应用被放进"会自己睡觉"的机器里，会以很多种方式坏掉，
而且大部分坏法都不是"定时任务不跑了"这么直白。

把一个真实的 agent 类负载迁进 microVM 沙箱之后，实际遇到的问题是这些：

| 症状 | 表现 |
|---|---|
| 定时任务静默停止 | 进程内的 `@Scheduled` / `setInterval` / `time.Ticker` 到点不触发 |
| 定时任务醒来暴走 | 一次唤醒补跑几十次，重复写库、重复调外部 API |
| 应用永远睡不着 | 应用自己的健康检查或后台 tick 被算成"有工作"，账单按全价走 |
| 应用被冻在一次 IO 中间 | 后台任务写文件写到一半机器睡了，醒来是半截数据 |
| 看门狗杀健康的进程 | 睡醒后心跳当然是旧的，看门狗以为进程卡死了，把它重启 |
| 凭据在睡眠期间过期 | 醒来第一个请求就 401 |
| 挂载和连接池失效 | 对端早已超时释放，应用以为自己还持有 |
| 慢启动被冻在半路 | 冷启动要几分钟，期间平台看不到任何"工作"，中途睡下并卡死 |
| 日志管道断裂 | 应用输出用的管道跨睡眠断开，之后写日志报错 |
| Cold 之后进程不再存在 | 没有任何东西负责把用户的常驻进程重新拉起来 |
| Warm 之后墙钟静默错误 | 时钟被冻在快照那一刻，且每次 Warm 循环累加；日志时间戳、TLS 有效期、JWT `exp` 全部受影响 |

十一条里只有前两条是"定时任务"问题。所以本设计不是一个定时任务功能，而是**一套让应用能在
会睡觉的机器里正确运行的责任划分**。

## 2. 原则

> **平台只报事实，应用做判断。**

平台知道两件应用不可能知道的事：

- 现在几点（即使应用刚被创造出来）
- 应用刚睡了多久、错过了哪些时刻

应用知道一件平台不可能知道的事：

- **打断这段工作，有没有人要善后**

第 1 节里的坑，全部来自有人越过了这条线。平台去猜应用忙不忙——猜宽了永远不睡，猜紧了冻在
半路。应用假设自己一直醒着——醒来发现凭据过期、看门狗要杀自己、挂载失效。

方案就是把这条线画清楚，然后给两侧各一套最小的词汇。

## 3. 方案

五层，各自解决第 1 节里的一组症状。层与层之间有依赖，见第 6 节的顺序。

### 3.1 Service 定义：Cold 之后由谁启动进程

**解决**：Cold 之后进程不再存在。

Cat 降到 Cold 之后，Guest 里的进程随虚拟机一起消失。`cats exec` 起的东西断连即死；
`setsid`、`nohup`、`tmux -d` 都活不过平台侧的清理。因此需要一个由平台记住、每次开机执行的
命令定义：

```
cats service set order-sync --cmd '/usr/bin/java -jar /app/order-sync.jar'
cats service ls
cats service rm order-sync
```

Guest Agent 在每次开机（Cold 冷启动、Warm restore 之后进程不存在的情况）启动它，
崩溃后重启它。

**刻意不做**：依赖顺序、就绪探针、重启退避策略、多副本。这些属于应用编排，不属于沙箱。
一个 Cat 一到几条 Service 定义就够，复杂编排请在应用内部完成。

**为什么必须在平台侧**：只有平台知道"进程消失了"这件事发生过。Guest 里没有任何东西在那一刻
是活着的。

### 3.2 两种"我在忙"

**解决**：应用永远睡不着；应用被冻在一次 IO 中间。

现有的工作租约是一个平铺的并集——任何未过期的租约都压住休眠。这让每一个后台周期任务
都面临两难：

- 老实申报 → 每分钟的清理任务每分钟重新压住休眠 → **这个 Cat 永远不会自动睡**
- 不申报 → 它随时可能被冻在写文件的中间 → **半截数据**

两条路都是坑。原因是"我在忙"这一个词被用来表达两种不同的意思。拆开：

| 模式 | 语义 | 典型用途 |
|---|---|---|
| **`pin`** | 我能把 Cat 唤醒，并且按住它不许睡 | 用户在等的响应；必须投递的消息；正在处理的请求 |
| **`drain`** | **我不唤醒 Cat。但如果它此刻正醒着，让我跑完再睡。** | 清理临时文件、驱逐空闲缓存、上报指标 |

`drain` 必须带一个预算上限（默认 60 秒）。超过预算后，**工作继续跑，但失去冻结保护**——
这是刻意的降级而不是错误，否则一个卡死的后台 tick 能把 Cat 永久钉在 Running。

落地形态：`WorkKind`（gateway / exec / guest / schedule / pin / control）保持不变，它表达
**工作来源**；新增一个正交字段表达**保活语义**：

```rust
pub enum WorkMode { Pin, Drain }

pub struct WorkLease {
    pub kind: WorkKind,
    pub mode: WorkMode,              // 新增
    pub drain_budget_ms: Option<u32>,// 仅 Drain 有意义
    // ...现有字段不变
}
```

判定规则相应修改：`pin` 租约的并集为空即可尝试休眠；`drain` 租约不参与"是否可以睡"的判定，
只推迟已判定的休眠动作，且推迟不超过预算。

**给用户的判断规则只有一句话**：

> 打断它，有没有人要善后？有 → `pin`。没有 → `drain`。

应用侧长这样：

```java
try (var w = Cats.pin("sync-orders")) {        // 客户看得见的工作
    syncOrders();
}

try (var w = Cats.drain("clean-temp", ofSeconds(30))) {  // 家务
    cleanTempFiles();
}
```

**为什么必须在平台侧**：这是每个可休眠应用都会遇到的同一个两难，做错就是那两个经典失败。
让每个客户自己发明一遍是浪费，而且他们只会在踩过坑之后才发明。

### 3.3 睡了多久：平台唯一能替应用做的事

**解决**：看门狗杀健康进程；凭据过期；挂载和连接池失效；日志管道断裂。

应用醒来时唯一缺的信息是"我刚才不在了多久"。给它这个数，上面四条它自己就能处理；不给，
每个应用都要自己发明一套"我是被冻住了还是我卡死了"的启发式判断。

三个档位，按改动量递增，任选：

**零改动**——`/etc/cats/on-resume.d/` 目录，Guest Agent 在 resume 后按序执行其中的脚本。

**一行改动**——长轮询 Guest Runtime API：

```
GET /v1/resume-events          （长轮询，走 /run/cats/runtime.sock）
→ { "slept_ms": 7200000, "from_state": "warm", "resumed_at_unix_ms": 1785146271000 }
```

**契约文字**——写进文档并在 `cats create` 输出里提示：

> resume 之后，缓存的 token、连接池、DNS 结果、以及任何由本地时钟推导出的 deadline，
> 一律视为可疑。

`slept_ms` 比"我醒了"这个信号有用得多，因为它一个数就分出了三种处置：

- 睡了 3 秒 → 什么都不用做
- 睡了 2 小时 → token 肯定过期，重新获取；连接池全部作废
- 睡了 2 小时 → 心跳当然是旧的，**看门狗不要杀应用**

**为什么必须在平台侧**：Guest 在睡眠期间没有任何东西在运行，它不可能自己测出这段空白。

### 3.4 时刻表：只叫醒，加一份"错过清单"

**解决**：定时任务静默停止；定时任务醒来暴走；慢启动被冻在半路。

#### 平台承诺什么

一句话：**"你会在这些时刻是运行着的。"**

不携带信息，不调用应用的任何入口。唤醒时平台持有一个**短的交接租约**——只够应用建立
自己的 `pin`。交接完成后保活权威转移给应用。这个交接租约同时解决"慢启动被冻在半路"：
它覆盖的是唤醒到应用接过接力棒之间的空白，而不是任务时长。

**为什么不做"平台调用你的任务"**：那需要平台维护任务名字空间、完成检测、超时、重试，
一步步长成一个作业调度系统。而且它做不到——一次生成式的 agent turn 不可能用一个 HTTP
请求的时长来建模，请求早晚会被某一层超时砍断，连带砍掉保活。

#### 关键约束：能否"自己察觉"是分状态的

这一点由实测决定，直接影响本层的必要性：

| 从哪个状态醒来 | guest 的三个时钟 | 应用能否自己发现错过了 deadline |
|---|---|---|
| **Suspended**（同 host pause） | **照走**，误差 0.07% | **能**，恢复后约 2 毫秒内察觉 |
| **Warm**（snapshot + VMM 退出 + restore 进新进程） | **全部冻结**——静置 120 秒，三个时钟一秒都没走 | **不能**，它认为一秒都没过去 |
| **Cold** | 全新进程，单调钟从零开始 | **不能**，没有任何记忆 |

而自动分层是 **Suspended 稳定 10 分钟即降 Warm**——所以**任何周期超过约 10 分钟的定时任务，
醒来时都在 Warm 或 Cold**，恰好是应用无法自我察觉的两档。

**结论：错过清单不是便利功能，而是承重结构。** 只有周期短于 10 分钟的任务能靠自己察觉；
其余全部依赖平台把信息送达。同理，`wake_lead_ms` 只对 Suspended 唤醒有意义——Warm 下
guest 根本不会察觉，提前多久都一样。

#### Warm 还要额外补一次校时

Warm 之后 guest 的墙钟落后真实时间（实测：静置 120 秒 → 落后 120.9 秒），而且**逐次累加**。
NTP 救不了：即使 guest 里跑 chrony 把 `CLOCK_REALTIME` 步进回来，`CLOCK_MONOTONIC` 也不会
被修正，而后者才是所有运行时定时器 deadline 用的时钟。

所以 Warm restore 之后平台必须做一件事：**把时钟推进到当前墙钟**。CH 源码里有一个
`ClockRestoreMode::SnapshotRestore`（注释就是"advance to current wall time"），但实测
没有生效——是没被 `vm.restore` 路径触发、需要额外标志、还是 CH 缺陷，尚未查清。
这决定了工作量是"触发已有机制"还是"自己补一次 `KVM_SET_CLOCK`"。

#### 时刻表从哪里来

| 来源 | 用户改动 | 说明 |
|---|---|---|
| `crontab` / `cron.d` / systemd timer | **无** | Guest Agent 只读地解析磁盘上的文件。注意默认 Cats 镜像里 systemd 不是 PID 1、也没装 cron，所以这条路只对自己装了 cron 的用户有效 |
| 应用上报 | 一个依赖或几行代码 | 框架适配器枚举已声明的定时任务后上报；见 3.5 |
| 显式声明 | 一条命令 | `cats schedule create worker --cron "*/10 * * * *"` |

#### 应用问"我错过了什么"

这是这一层的关键。应用在启动或 resume 之后问一句：

```
GET /v1/schedules/missed
→ [ { "name": "sync-orders",
      "scheduled_at_unix_ms": 1785146271000,
      "missed_count": 143,
      "reason": "cold" } ]

POST /v1/schedules/missed/ack   { "name": "sync-orders" }
```

平台只报事实：**这些时刻我叫醒过（或本该叫醒），你还没确认。** 应用自己决定怎么办，
因为**只有应用知道错过一次要不要紧**——这和 3.2 的 `pin`/`drain` 是同一个判断。

这个设计有两个直接好处：

1. **平台侧不需要"错过补偿策略"配置项。** 平台不做这个决定，所以没有
   skip / 补一次 / 全补 这类需要用户理解的旋钮。
2. **它给了应用处理补跑暴发的机会。** Java 的 `fixedRate` 在唤醒瞬间会把错过的每一轮
   都补跑一遍（实测：暂停 240 秒、周期 20 秒 → 12 次执行挤在 10.6 毫秒内；`fixedDelay`
   和 `cron` 不会）。平台管不了 JVM 内部的补跑，但应用看到"错过 143 次"之后可以选择
   只跑一次。

#### 时区与夏令时

一旦平台拥有 cron 表达式，它就拥有了夏令时正确性。每条时刻表存自己的时区；
`0 2 * * *` 在春季跳钟那天该跑零次、一次还是两次，必须写进文档，不能依赖 cron 库的默认行为。

#### 数据

```sql
CREATE TABLE cat_schedules (
    id                TEXT PRIMARY KEY,
    cat_id            TEXT NOT NULL,
    source            TEXT NOT NULL,   -- crontab | systemd | app_reported | explicit
    name              TEXT NOT NULL,   -- 同一个 Cat 内唯一，用于错过清单的确认
    cron              TEXT NOT NULL,
    timezone          TEXT NOT NULL,
    wake_lead_ms      INTEGER NOT NULL,-- 提前量：单调 deadline 的调度器可为 0
    enabled           INTEGER NOT NULL,
    next_fire_at_ms   INTEGER NOT NULL,
    last_fire_at_ms   INTEGER,
    last_ack_at_ms    INTEGER          -- 应用确认到哪里了
);
```

没有队列表、没有执行历史表、没有重试状态机。唤醒尝试记录复用现有的 operations 表。

`wake_lead_ms` 的存在是因为不同调度器察觉的速度不同：基于单调 deadline 的调度器
（JVM、Go、Node、Python）在 resume 后约 2 毫秒内就被唤醒（实测），提前量可以是 0；
而传统 cron 每分钟轮询一次，最坏要等 60 秒，所以应该提前十几秒叫醒，让它的下一次轮询
正好落在目标时刻。

### 3.5 框架适配器：把不可约的判断变成可见的清单

**解决**：降低 3.2 那个分类判断的成本——但不消除它。

各生态的调度框架都存着一张已声明任务的登记表，可以枚举；而且大多提供了正式的中间件或
监听器机制，可以在任务执行前后插入代码：

| 生态 | 枚举时刻表 | 执行前后插一脚 |
|---|---|---|
| Java / Spring | `ScheduledTaskHolder` | 自定义 `TaskScheduler` 或 `SchedulingConfigurer` |
| Python / APScheduler | `get_jobs()` | `add_listener`（`JOB_SUBMITTED` / `JOB_EXECUTED`） |
| Python / Celery beat | `beat_schedule` | `task_prerun` / `task_postrun` 信号 |
| Go / robfig/cron | `Entries()` | `cron.WithChain(JobWrapper)` |
| Node / NestJS | `SchedulerRegistry` | 拦截器 |
| .NET / Quartz | 调度器的 job 列表 | `IJobListener` |

所以一个适配器能自动做到：上报时刻表、为每个任务套上保活模式、在启动或 resume 后查询
错过清单。

**它不能自动做到的是分类。** `@Scheduled(每10分钟)` 说明了**什么时候**，没有说明
**打断了要不要紧**。而默认值只能是 `drain`——否则每分钟的任务每分钟重新压住休眠，
Cat 永远不睡——可 `drain` 恰好对最重要的那类工作是错的。

因此适配器的正确行为是：**默认 `drain`，并在启动时把完整清单打印出来**：

```
[cats] 已上报 12 个定时任务，默认按"可打断"处理：
  syncOrders        每 10 分钟   ← 打断有后果的话请标注 @CatsPin
  refreshToken      每 50 分钟   ← 打断有后果的话请标注 @CatsPin
  cleanTempFiles    每  1 分钟
  ...
  查询与标注：https://docs.cats.dev/sleepable#classify
```

把不可约的工作量变成一张开发第一天就看得见的清单，而不是三个月后的一次事故。

**覆盖边界**：以上都要求应用使用了调度库。**手写的循环**
（`for { <-ticker.C; work() }`、`while True: sleep(600)`、`setInterval(fn, 600000)`）
既没有登记表可枚举，也没有函数边界可包——这类工作只能由应用自己调用租约 API。
这与语言无关：Java 里手写 `while(true){ Thread.sleep(600000); work(); }` 同样无解。

## 4. 完整例子

一个 Spring Boot 订单同步服务：

- `@Scheduled(fixedRate = 10 分钟)` `syncOrders()`——拉订单写库，客户看得见
- `@Scheduled(fixedRate = 1 分钟)` `cleanTempFiles()`——清理临时目录
- 一个对外的 HTTP API
- 一个每小时过期的第三方 token

### 用户需要做的全部事情

```xml
<dependency><artifactId>cats-spring-boot-starter</artifactId></dependency>
```

```java
@CatsPin                                  // ← 唯一需要人来判断的一行
@Scheduled(fixedRate = 600_000)
public void syncOrders() { ... }

@Scheduled(fixedRate = 60_000)            // 不标注 = 家务 = drain
public void cleanTempFiles() { ... }
```

```
cats service set order-sync --cmd 'java -jar /app/order-sync.jar'
```

注解不动、方法体不动、cron 周期仍然只有源码里那一份。

### 运行时

| 时刻 | 发生的事 | 依赖哪一层 |
|---|---|---|
| 10:00:02 | 请求处理完，`pin` 释放；每分钟的家务任务是 `drain`，不阻止休眠 → **Cat 睡** | 3.2 |
| 10:10:00 | 平台按时刻表唤醒，持有交接租约 | 3.4 |
| 10:10:00 | Guest 时钟跨暂停照走，JVM 的 deadline 早已到期 → `syncOrders` **自己触发** | 实测 |
| 10:10:00 | starter 看到 `@CatsPin`，取一个 `pin` → 交接完成，平台松手 | 3.2 / 3.4 |
| 10:10:02 | 任务结束，`pin` 释放 → **Cat 立刻回去睡**。账单：每 10 分钟约 2 秒 | 3.2 |
| 10:31 | Suspended 稳定 10 分钟 → 自动降 **Warm** | ADR-0002 |
| 次日 10:31 | Warm 满 24 小时 → 降 **Cold**，进程消失 | ADR-0002 |
| 次日 11:00 | 时刻表到点 → 平台唤醒 → **Service 定义把进程拉起来** | **3.1** |
| 次日 11:00 | 应用收到 `slept_ms = 86400000` → 判定 token 早已过期，重新获取 | **3.3** |
| 次日 11:00 | 查询错过清单 → 平台答"错过 143 次" → 应用决定**只补跑一次** | **3.4** |

最后三行是这个方案的价值所在。缺 3.1，进程根本不会启动；缺 3.3，它会拿着过期 token 去
调 API；缺 3.4，它要么什么都不知道，要么被 JVM 补跑 143 次。

## 5. 明确不做的

这条边界会被持续推——一旦有了时刻表，用户马上会要重试、执行历史、失败告警、
"立刻运行一次"、暂停恢复、补跑历史区间。建议一次钉死：

- **不做作业队列**——没有 fan-out、worker 池、优先级。一条时刻表对应一次唤醒。
- **不做重试退避策略引擎**——唤醒尝试记在 operations 表里，重试语义交给幂等契约。
- **不做执行历史与产物存储**——应用自己的日志里有。
- **不做依赖编排**——没有 DAG，没有上下游。
- **不承诺 exactly-once**——契约必须写明"你的任务需要幂等"。
- **不做进程管理器**——只有"这条命令应该在跑"，没有依赖顺序和就绪探针。

能保持这么小的唯一原因：**任务的实际执行完全留在应用里。**

## 6. 落地顺序

| 顺序 | 内容 | 为什么在这个位置 |
|---|---|---|
| 0 | **Service 定义**（3.1） | 不补这个，Cold 之后一切归零，后面几层都是空中楼阁 |
| 1 | **`pin` / `drain`**（3.2） | 修一个今天就存在的缺陷；不关心的用户完全无感（默认 `pin`，行为不变） |
| 2 | **resume 事实 + `slept_ms`**（3.3） | 极便宜，解锁应用侧一大片自救能力 |
| 3 | **时刻表 + 错过清单**（3.4） | 依赖第 0 层，且依赖下面那项测量 |
| 4 | **框架适配器 + 启动清单**（3.5） | 按生态逐个铺；建议顺序 Python → Java → Go → Node |

### 时钟语义已测完，结论已并入 3.4

Suspended / Warm / Cold 三档的时钟行为均已实测，见
[`experiments/suspend-clock-semantics-20260727`](../experiments/suspend-clock-semantics-20260727/README.md)。
两条对设计有决定性影响的结论已写入 3.4：错过清单是承重结构；Warm restore 之后必须补校时。

**剩下一个待查项**（不阻塞第 0–2 层，阻塞第 3 层的实现细节）：CH 的
`ClockRestoreMode::SnapshotRestore` 为什么没有推进时钟。查清它决定 Warm 校时是"触发 CH
已有机制"还是"Cats 自己补一次"。

## 7. 责任划分总表

| 事项 | 归谁 | 理由 |
|---|---|---|
| Cold 之后启动进程 | 平台 | 只有平台知道"进程消失过" |
| 两种保活语义 + 预算 | 平台 | 每个应用都会遇到同一个两难，做错就是那两个经典失败 |
| 唤醒到应用接手之间的交接 | 平台 | 那段时间应用还没准备好为自己说话 |
| 时刻表与到点唤醒 | 平台 | 应用睡着时不可能给自己定闹钟 |
| 睡了多久、错过了什么 | 平台 | Guest 在空白期没有任何东西在运行 |
| Warm restore 之后把时钟推进到当前墙钟 | 平台 | 实测 Warm 会冻住全部三个时钟且漂移累加；guest 侧无法自救（NTP 不修正单调钟） |
| 时区与夏令时正确性 | 平台 | 拥有 cron 表达式就拥有这个责任 |
| **把每段工作分类为 pin / drain** | **应用，不可约** | 这是关于业务语义的判断，平台无从得知 |
| 错过之后要不要补、补几次 | 应用 | 同上 |
| 任务幂等 | 应用 | 平台不承诺 exactly-once |
| resume 后重建凭据、连接、挂载 | 应用 | 平台只能提供 `slept_ms` 这个输入 |
| 跨 Cold 存活的业务状态 | 应用 | 属业务域；平台不做作业队列 |

这个方案不消除工作量，它把工作量放到唯一有能力承担它的一侧。应用仍然要逐处判断
"打断这段工作要不要紧"——这是不可约的。平台要做的是给出对的词汇、给出只有它知道的事实、
兜住应用不可能兜住的场景。
