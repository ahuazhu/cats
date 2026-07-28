# Cat 睡一觉之后，它的时钟到底走没走

状态：完成（2026-07-27，AWS c5.metal）。机制验证，不是生产 SLA。

## 1. 为什么要测这个

设计「闹钟」（控制面持有时刻表、到点唤醒 Cat）时有两种可能的架构：

- **只叫醒**：Cats 只承诺「你会在这些时刻是运行着的」，不携带任何信息。
  guest 醒来后自己发现「10:10 已经过了」并执行任务。
- **按名触发**：Cats 醒来后还要主动调用用户的任务入口，并且必须关掉框架内部的调度器
  以免双跑。

选哪个，完全取决于一个事实：**Cat 被暂停期间，guest 的时钟走不走。**

- 如果走 → guest 醒来发现 deadline 早过了，自己就会执行 → **「只叫醒」成立**。
- 如果不走 → Cats 白叫一次、guest 什么都不做、Cat 又睡回去 → 只叫醒对进程内定时器无效。

这个事实决定的不是某个默认参数，而是整个架构选型。

## 2. 结论

**Suspended 和 Warm 的行为完全相反，这是本轮最重要的发现。**

| | Suspended（同 host pause） | Warm（snapshot + VMM 退出 + restore 进新进程） |
|---|---|---|
| guest `CLOCK_REALTIME` | **照走** | **冻结** |
| guest `CLOCK_MONOTONIC` | **照走** | **冻结** |
| guest `CLOCK_BOOTTIME` | **照走** | **冻结** |
| 应用能否自己发现错过了 deadline | **能**（恢复后约 2 ms 内察觉） | **不能**（它认为一秒都没过去） |
| 「只叫醒」架构 | **成立** | **不成立** |

Suspended 侧还测出一个必须处理的副作用：**Java `fixedRate` 会在唤醒瞬间补跑一串**——
240 秒的暂停配 20 秒周期，12 次执行挤在 **10.6 毫秒**里。

Warm 侧则相反——它一次都不补，因为它不知道该补。代价是**墙钟落后于真实时间，且每次 Warm
循环累加**：120 秒静置之后 guest 认为的时间比宿主机慢 120.9 秒。

## 3. 环境与方法

| 项 | 值 |
|---|---|
| 机器 | AWS c5.metal，us-east-1d，96 核 / 188 GiB（复用已有的 `cats-bench-20260727f` 机器） |
| 内核 | 6.17.0-1019-aws（host 与 guest 同一个，Cats 镜像复用 host 内核） |
| VMM | Cloud Hypervisor v53.0 |
| Guest | Cats 自己的镜像（`/opt/cats/guest` 的 vmlinuz + initramfs + rootfs.ext4），512 MiB / 2 vCPU |
| 探针 | guest 内 python3（镜像自带），输出走串口，宿主机读串口日志 |

Warm 那一轮（§6.5）在另一台同规格 c5.metal 上跑，同一个探针，两处不同：guest RAM 用**匿名内存**
（让快照自包含——file-backed zone 在 snapshot 时会被刻意跳过），静置时长扫 120 / 60 秒两档。

**为什么直接驱动 CH 而不是走 `cats suspend`**：Cats 的 Suspended 是「CH pause +
`MADV_PAGEOUT`」，page-out 只搬内存不动时钟；而 `node-agent` 里**没有任何时钟处理代码**
（`grep -riE "set_clock|KVM_SET_CLOCK|ClockRestoreMode|tsc" node-agent/src/` 无命中，
它的 resume 就是一句 `PUT /api/v1/vm.resume`）。所以直接调 CH 的 API 在时钟语义上等价，
而且不会打扰这台机器上正在跑的 `cats-noded` 部署。

探针一次开机同时回答三个问题：

- **CLK** 每 250 ms 采一次 `CLOCK_REALTIME` / `CLOCK_MONOTONIC` / `CLOCK_BOOTTIME`。
  跨过暂停那一对样本的差值就是答案。
- **DEADL** 一个线程停在落在暂停窗口**内部**的 deadline 上，看它在恢复后多久才触发——
  这是 `wake_lead_ms` 的输入。
- **RATE** 一个用 `next = base + k × period` 规则的循环，也就是 Java
  `ScheduledThreadPoolExecutor` 对 fixedRate 用的同一条规则，让补跑爆发能被实测而不是靠推断。

暂停时长扫了 90 / 30 / 240 秒三档，每档前后各留 25–60 秒稳定期。

## 4. 结果一：三个时钟都照走

| host 侧暂停时长 | guest CLOCK_REALTIME 增量 | guest CLOCK_MONOTONIC 增量 | guest CLOCK_BOOTTIME 增量 |
|---|---|---|---|
| 90 s | 90.063 s | **90.063 s** | 90.063 s |
| 30 s | 30.034 s | **30.034 s** | 30.034 s |
| 240 s | 240.030 s | **240.030 s** | 240.030 s |

三个时钟完全同步前进，增量等于宿主机侧的暂停时长（90 秒暂停误差 63 ms，0.07%）。
guest 墙钟与 host 墙钟之间有一个 **−0.19 秒的固定偏移**（三次分别是 −0.186 / −0.187 / −0.190），
是 kvmclock 的初始化偏移，**不随暂停累积漂移**。

这与 CH v53 源码里的声明一致（`hypervisor/src/lib.rs`）：

```rust
pub enum ClockRestoreMode {
    /// Same-host pause -> resume; the clock kept running, nothing to advance.
    SameHostResume,
    /// Restored from a snapshot or migrated in; advance to current wall time.
    SnapshotRestore,
}
```

**「单调钟停走导致定时任务永久漂移」这个担心在 Suspended 上不成立**：单调钟要冻结，必须有人
主动去冻结它，而 guest 内核在暂停期间没有运行、没机会做任何记账，CH 的同 host resume 路径也
不去调 TSC offset。**但同一个担心在 `Warm` 上完全成立，见 §6.5**——那条路径会把三个时钟一起
冻住，而且漂移逐次累加。

## 5. 结果二：恢复后的「察觉延迟」约等于零

停在暂停窗口内部那个 deadline（目标 mono=50.72）在 mono=120.888 触发，
而恢复后第一个采样点在 mono=120.886——**parked 的线程在 guest 恢复后 ~2 毫秒内就醒了。**

所以对**基于单调 deadline 的调度器**（JVM、Go、Node、Python），`wake_lead_ms` 可以是 0：
guest 一恢复就立刻察觉。

（不要把 −0.19 秒的 guest/host 墙钟偏移误读成延迟，它三次都一样，是固定偏移。）

## 6. 结果三：fixedRate 会补跑一串，而且量很大

周期 20 秒：

| 暂停时长 | 恢复瞬间连续触发次数 | 挤在多长时间内 |
|---|---|---|
| 30 s | 2 | 1.1 ms |
| 90 s | 4 | 3.7 ms |
| 240 s | **12** | **10.6 ms** |

次数正好等于 `暂停时长 ÷ 周期`。JDK 源码解释得很直接
（`ScheduledThreadPoolExecutor.ScheduledFutureTask.setNextRunTime`）：

```java
private void setNextRunTime() {
    long p = period;
    if (p > 0) time += p;              // fixedRate：基于原定时刻累加
    else       time = triggerTime(-p);  // fixedDelay：now + delay
}
```

`time += p` 意味着下一次的目标时刻仍在过去，于是立刻再跑一次，直到追平。

**一个重要的不对称：**

- `@Scheduled(fixedRate = ...)` → **会爆发**。睡 2 小时、周期 10 分钟 → 醒来连跑 12 次。
- `@Scheduled(fixedDelay = ...)` → **不会**，因为它是 `now + delay`。
- `@Scheduled(cron = ...)` → Spring 的 `CronTrigger` 从上次完成时间重算，**至多迟跑一次**。
  （本轮未实测，属源码推断。）

## 6.5 结果四：Warm 把所有时钟一起冻住

第二轮（2026-07-27，另一台 c5.metal）测的是完整的 Warm 循环：
启动 → pause → snapshot → **VMM 进程退出** → 静置 → restore 进**全新的 VMM 进程**。
Guest RAM 用匿名内存，让快照自包含（file-backed zone 在快照时会被刻意跳过）。

| host 侧 pause→restore | guest REALTIME 增量 | guest MONOTONIC 增量 | guest BOOTTIME 增量 | restore 后 guest 墙钟落后宿主机 |
|---|---|---|---|---|
| 121.32 s | **+1.064 s** | **+1.064 s** | **+1.064 s** | **−120.9 s** |
| 61.30 s | **+1.072 s** | **+1.072 s** | **+1.072 s** | **−60.9 s** |

那 1.06–1.07 秒是 pause 到 snapshot 之间的间隔（脚本里 pause 后 sleep 1 秒再 snapshot）。
**也就是说静置那 120 秒 / 60 秒，guest 的三个时钟一秒都没走。**

旁证一致：

- **restore 之后 `fixedRate` 循环一次补跑都没有**（5 次触发全部 `ontime`，0 次 `BURST`）——
  因为 guest 认为没有时间流逝，没什么可补。对照 Suspended 的 240 秒暂停产生 12 次补跑。
- 停在 45 秒 deadline 上的线程在 **guest 时间**里只迟了 0.0002 秒——它按自己的时钟准点触发，
  而那已经是真实时间的 121 秒之后。
- 后半段日志里**没有 `probe_start`**，说明是同一个进程延续下来的——进程状态跨快照完整保留，
  Warm 该有的语义是对的，坏的只是时钟。
- restore 延迟（`vm.restore` 调用到返回）两次都是 **0.413 秒**；512 MiB guest 的快照 513 MiB。

### 与 Cloud Hypervisor 源码声明的差异

CH v53 的 `hypervisor/src/lib.rs` 对这条路径的声明是：

```rust
/// Restored from a snapshot or migrated in; advance to current wall time.
SnapshotRestore,
```

**实测没有发生这个推进。** guest restore 之后仍然认为时间停在快照那一刻。
可能的原因（本轮未区分）：该模式没有被这条 `vm.restore` 路径触发；或者调整只作用于某个
不向 guest 时钟传播的位置；或者需要额外的配置/标志。**这是一个待查项**，因为如果 CH 本来
就该做这件事，那 Cats 可能只是没触发到它。

### 为什么这一条比 Suspended 那一条重要

自动分层是 **Suspended 稳定 10 分钟即降 Warm**。所以**任何周期超过约 10 分钟的定时任务，
醒来时都在 Warm**——恰好是应用无法自己察觉的那一档。

而且时钟落后是**累加**的：每次 Warm 循环都往上叠。一个反复小睡上百次的 Cat，
它的 guest 墙钟会比真实时间慢几个小时。这会连带影响日志时间戳、TLS 证书有效期校验、
JWT `exp` 校验、任何带时间戳的签名请求——**这是一类超出本文档最初症状清单的新问题：
Warm 之后 guest 的墙钟是静默错误的。**

注意 NTP 救不了这件事：即使 guest 里跑 chrony 把 `CLOCK_REALTIME` 步进回来，
`CLOCK_MONOTONIC` 也不会被修正，而后者才是所有运行时定时器 deadline 用的时钟。

## 7. 结果五：Cold 之后 guest 什么都不记得

全新开机的 guest：单调钟从 5.75 重新开始，`RATE` 的第一次触发落在它自己的 mono=25.75，
即"自己启动后 20 秒"，**完全不知道上一个化身错过了什么**。deadline 也只迟了 0.2 毫秒（正常）。

同时确认：**全新 guest 的墙钟是正确的**（从 host 经 kvmclock 取得，与 host_before_boot
相差约等于开机耗时）。所以墙钟驱动的调度器（cron 带补跑、systemd `Persistent=true`）
理论上能靠磁盘状态补跑，而基于单调 deadline 的调度器一定丢。

## 8. 顺带发现：默认 Cats 镜像里没有可导入的声明式时刻表

这一条会直接改掉「导入 crontab / systemd timer」那条路的可行性判断：

- **systemd 装了但不是 PID 1**（`cats-init` 才是，它最后 exec 到 `cats-guest-agent`）。
  所以 **guest 里的 systemd timer 根本不会触发**。
- **`rootfs.manifest` 里没有 cron**。

也就是说默认镜像里**没有任何在跑的声明式调度器**，「读 crontab 提升成控制面 schedule」
这条路要么先往镜像里加 cron，要么只对自己装了 cron 的用户有效。

## 9. 对「闹钟」设计的影响

| 原先的设计假设 | 实测之后 |
|---|---|
| 单调钟可能停走，所以只叫醒可能无效 | **分状态：Suspended 三个时钟都照走，只叫醒成立；Warm 三个时钟全冻住，只叫醒不成立。** |
| 需要 `wake_lead_ms` 提前唤醒 | Suspended 下**不需要**（察觉延迟 ~2 ms）。**Warm 下这个参数没有意义**——guest 根本不会察觉，提前多久都一样。 |
| 「错过清单」是个便利功能 | **变成承重结构**。Warm 是周期 >10 分钟任务的主场，而那一档 guest 无法自我发现，信息只能由平台送达。 |
| 导入 crontab 时必须 mask 掉 guest 内定时器以免双跑 | **在「只叫醒」架构下整条警告作废**——只有一个触发源。而且默认镜像里也没有 cron/systemd timer 可 mask。 |
| `on_overrun`（重叠策略）由平台定义 | 不需要。平台不触发，重叠语义由 guest 自己的调度器决定。 |
| `on_missed`（错过补偿）由平台定义 | 仍然需要，但含义变了：**平台不用补触发，要防的是 guest 自己补跑太多**。 |

**新增的头号风险是 fixedRate 爆发。** 它不是平台能替用户消掉的——补跑发生在 JVM 内部。
可做的三件事：

1. **文档明确写死**：`fixedRate` 在 Cat 睡醒后会补跑「睡眠时长 ÷ 周期」次；
   要避免就用 `fixedDelay` 或 `cron`。这是一行文档换掉一类事故。
2. **`cats sleep status` 之类的解释性输出里给出警告**：这个 Cat 上一次睡了 2 小时，
   如果你有 `fixedRate` 任务，醒来会补跑约 12 次。
3. **控制面侧限幅**：睡眠超过阈值时不要一次性唤醒到 Running 就撒手，
   而是记录一条 operation 说明「本次唤醒可能触发 guest 侧补跑」，让事故可解释。

## 10. 未验证 / 偏差

- **Warm 已测（§6.5），但只到 120 秒静置。** 跨小时的 Warm 静置、以及"累加漂移"在几十次
  循环后的实际幅度都没测。按机制推断是线性累加，但没有数据。
- **CH 的 `SnapshotRestore` 为什么没有推进时钟，没有查清。** 可能是没被这条 `vm.restore`
  路径触发、可能需要额外标志、也可能是 CH 的缺陷。这决定 Cats 是"自己补一次校时"还是
  "只要触发到 CH 已有的机制"，工作量差别很大。
- **Warm 循环用的是匿名 guest RAM**（为了让快照自包含）。生产的 Suspended 路径用
  file-backed memory zone，两者在 snapshot 时的行为不同（file-backed zone 会被跳过），
  所以生产形态下的 Warm 需要再验一次。
- `@Scheduled(cron=...)` 不爆发是读 Spring 源码推断的，没实测。
- 探针是 python，不是真的 JVM。补跑规则与 JDK 源码逐行一致，但没有跑真实的 Spring。
- 块后端用了 `--disk path=`，不是生产的 vhost-user-blk。时钟与块后端无关，
  但 resume 的**延迟**数字会受影响，所以本文不引用 resume 延迟。
- 暂停时长只到 240 秒。跨小时的暂停（自动降到 Warm 之后）没测。
- 单机 n=1，每档一次，无重复测量。

## 11. 复现

```bash
sudo ./run-clock.sh    # Suspended：派生探针 rootfs、扫 90/30/240 秒三档暂停
sudo ./run-warm.sh     # Warm：pause → snapshot → VMM 退出 → 静置 → restore 进新进程
```

需要 `/opt/cats/guest/` 下有 Cats guest 镜像产物，以及 `/usr/local/bin/cloud-hypervisor`。
脚本只读 `/opt/cats/guest`，不碰任何 Cats 服务。

原始数据分两处。Suspended 与 Cold 在 [`results/`](results/)：

- `serial-sweep.log`——暂停扫描的完整串口输出（821 个时钟采样点 + RATE/DEADLINE 事件）
- `serial-cold.log`——冷启动那一档
- `host-events.csv`——宿主机侧记录的每次 pause/resume 时刻，用来核对 guest 的说法

Warm 在 [`results-warm/`](results-warm/)：

- `serial-warm-<dwell>-before.log.frozen`——快照之前的完整串口输出
- `serial-warm-<dwell>-after.log`——restore 之后的输出（restore 会截断重写原文件，
  所以前后两半天然分离，`.frozen` 是快照前那一份的副本）
- `host-events.csv`——宿主机侧的 pause / snapshot / vmm_exited / restore / resumed 时刻

已知脚本缺陷：`run-clock.sh` 的 `teardown()` 里 `wait` 一个被 `kill -9` 的进程返回 137，
在 `set -e` 下会让脚本提前退出，所以 Suspended 那轮的 `phase_cold_boot` 是单独补跑的。
