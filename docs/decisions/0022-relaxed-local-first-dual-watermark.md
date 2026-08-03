# ADR-0022：Relaxed local-first 双持久化水位与强制 drain

- 状态：Accepted
- 日期：2026-07-30
- 修订：取代 ADR-0021 中“5 秒固定丢失窗口”“pack 满后前台/超时内联
  publish”“detach 失败仍释放 lease”以及 Snapshot 不强制同步的部分；
  strict 契约与按盘选择不变。
- 后续修订：ADR-0024 仅允许 Cat Destroy 丢弃随后会 tombstone 的 RootDisk；
  PersistentDisk 与其他生命周期边界仍必须强制 drain。

## 背景

`pr3094-core` 在运行中随后无法写文件，CI 原地恢复明确得到
`Read-only file system`；同时 Tunnel 健康、Platform API 返回 200，而
Web/Cats origin 返回 502。这个组合说明控制面和网络入口仍活着，故障域在
Cat 所在 Host/卷：文件系统可能被 fencing，或者承载运行时的根文件系统因
底层 I/O 错误/容量耗尽被内核 remount 为只读。这不是 Paperboy 构建失败。

旧 Relaxed 实现虽然先 fsync 本地 pack，但有三个结构性耦合：

1. 队列到固定 pack 数或等待 10 秒后，Guest FLUSH 会自己进入 S3 PUT +
   PostgreSQL CAS；远端故障因此重新进入 ext4 的 I/O 返回路径。
2. “后台每 5 秒”被描述成“最多丢 5 秒”，但远端故障期间真实 RPO 是最老
   未发布 generation 的年龄，可能远大于定时器。
3. Stop/Warm/Detach 的 drain 错误被吞掉，甚至释放 lease、删除本地目录；
   一个瞬时远端故障可以把已经本地 ACK 的数据变成永久丢失。

这些不是某个 timeout 数值没调好的细节，而是 durability point、故障域和
生命周期所有权放错位置的结构性风险。Relaxed 可以接受 Host 丢失时的非零
RPO，但不能把 S3/DB 的瞬时故障直接翻译成运行中 ext4 的 EIO，也不能在未
确认远端水位时销毁唯一的本地副本。

## 决定

### 1. 两个明确水位

每个 blockd 同时维护：

- `L = local_durable_generation`：Guest 已收到成功 FLUSH/FUA，且相应
  immutable pending pack 已 fsync + rename + directory fsync 到本地 NVMe。
- `R = remote_durable_generation`：数据/Map/commit record 已写入对象存储，
  PostgreSQL head CAS 已成功。

必须始终满足 `R <= L`。Strict 的 ACK 条件仍是 `R == L`；Relaxed 的 ACK
条件是 `L` 前进。Host 永久丢失时可恢复到 `R`，所以 Relaxed 的真实风险
不是“配置的 5 秒”，而是当时 `L-R` 的 generation 数、字节数和最老年龄。

### 2. Guest WRITE/FLUSH 只走本地路径

Relaxed 对冷缓存块的局部 WRITE 不再为了补齐旧 64 KiB page 而同步 GET S3。
blockd 在 cache 中写入新字节，并在 FLUSH 时把精确 byte ranges 固定进本地
pack。后台 publisher 才读取远端 base、合成完整 dirty pages、上传 immutable
objects 并做 generation CAS。读取冷且未完整缓存的数据仍可能需要对象存储；
本 ADR 不把 Direct-S3 伪装成一块完全离线可读的本地盘。

Guest 线程不得调用 S3 PUT/GET 或 PostgreSQL generation CAS。唯一例外是本地
容量已经用尽后的**背压等待**：请求可以等待后台 publisher 回收空间，但远端
错误本身不能作为该 FLUSH 的 EIO 返回。真正的本地 fsync/ENOSPC、校验损坏或
确定 fencing 仍必须 fail closed。

### 3. 有界后台 publisher

- 后台线程按 generation 顺序消费本地 packs；可把连续 packs 合并成一次并发
  object wave + 一次 CAS，单批内存上限仍为 256 MiB。
- `drain_interval_ms` 是空闲尾部的发布目标，不是 RPO 保证；队列超过 eager
  watermark 时立即唤醒。
- S3/DB 失败记录 `last_publish_error`，pack 保留并在后续 tick 重试。
  PostgreSQL work queue 有界，调用有 deadline，断开的连接在下一任务前重连。
- CAS conflict 或 owner/epoch 不匹配是终态 fencing；普通网络/数据库错误不是。

### 4. 配额、pin 与背压

默认每卷：

- 未发布 pack：8 GiB 或 4096 generations，任一先到；
- `cache.data` 已分配块 + pending packs：16 GiB。

达到物理水位时先按 LRU hole-punch 已远端提交的 clean chunks。dirty chunks、
unpublished packs 涉及的 chunks 和当前 I/O 范围都被 pin，绝不能用 eviction
伪造空间。只剩 pin 数据时，新的本地 durability barrier 停在 condvar 上，并
唤醒后台 publisher；publisher 前进后再继续。单个超大 barrier 可以超过 staged
软水位一次，但仍受物理本地水位约束。

admission 同时记账实际 allocated bytes 和把当前 dirty set 固定成 pack 所需的
reserved/accounted bytes。否则普通 WRITE 可以先吃满 cache，下一次 FLUSH
没有空间生成 publisher 输入，形成永久闭环。接近水位时允许在 Guest WRITE
线程做一次**仅本地**的隐式 stage 并唤醒 publisher；它仍不得执行 S3/DB。

这是每卷硬隔离，防止一个 Cat 无界吃满运行时文件系统；节点还必须用容量规划
给所有卷、Warm snapshot、日志和系统保留空间。跨进程的节点总配额/预留不是
本 ADR 已实现的能力，不能把每卷上限相加后当成 Host 安全证明。

### 5. lease 与 fencing

lease 到期时间只决定竞争者何时可以 acquire。只要数据库行仍是同一
`owner + epoch`，原 holder 可以 renew，也可以在 generation CAS 中继续发布；
单纯本地调度或 DB 抖动导致的 expiry lapse 不能把健康 Cat 自我 fencing。

竞争 acquire 或显式 revoke 必须原子增加 epoch。旧 epoch 的 renew/CAS 随后
失败并永久进入 fenced；即使旧 Host 从网络分区恢复，也不能发布。

### 6. 恢复和生命周期

- Relaxed 同 Host blockd 重启先从本地 pack 重建 `L`，不在 attach 恢复阶段
  做远端写；后台 publisher 随后推进 `R`。
- `drain` 成功的定义是所有卷 `R == L`。`status` 控制命令返回两个水位、
  unpublished generations/bytes/oldest age、配额、eviction、backpressure、
  fencing 和最后发布错误。
- Stop/Cold、Warm、hot detach、Snapshot、`cats sync`、计划内 Node drain/
  冷迁移都必须先停止晚到的 Guest 写，再强制 drain。失败时保留 blockd、
  local journal 和 lease，控制器重试；不得标记 Cold、解绑/删除盘或清理源。
- **Cat Destroy 的 RootDisk 例外**：RootDisk 与 Cat 同生命周期且本次操作会删除
  它的 metadata/对象，因此 Guest/VMM 停止后可以不发布其本地 tail，直接丢弃该
  RootDisk 的 blockd、journal 与 cache。这个例外不能扩展到普通 Stop/Cold，也不能
  扩展到 PersistentDisk；同一次 Destroy 中需要返回 Available 的 PersistentDisk 仍
  必须完成 final drain，任一失败就保留其 blockd/journal/lease 并重试。Node job 必须
  携带控制面按 `DiskKind` 生成的显式 disposable/retained 清单，未知或冲突分类 fail
  closed，不能由 mount path 猜测。
- Snapshot 在 Running 时先 guest syncfs + drain；Suspended 已在 pause 前
  syncfs，只需 drain frozen engines。Warm/Cold 已跨过强制 drain 边界。
- 非计划 Host 丢失无法 drain，按 Relaxed 的实时 `L-R` 暴露 RPO，控制面提高
  epoch 后从 `R` 冷恢复。这是产品选择，不是“自动恢复零丢失”。

## 可观测性

控制 socket 的 `status` 进入 Node heartbeat，并导出至少：

- `cats_disk_local_durable_generation`
- `cats_disk_remote_durable_generation`
- `cats_disk_unpublished_generations`
- `cats_disk_unpublished_bytes`
- `cats_disk_oldest_unpublished_age_ms`
- `cats_disk_local_allocated_bytes` / `cats_disk_local_accounted_bytes` /
  `cats_disk_max_local_bytes`
- `cats_disk_evicted_cache_chunks`
- `cats_disk_backpressured`
- `cats_disk_fenced`
- `cats_disk_publish_error`

告警应基于实际 age/bytes、水位是否持续不收敛和 Host free space；不得再以
“后台定时器是 5 秒”推断 RPO。

## 验证

自动化必须覆盖：

1. S3 PUT 持续失败时 Relaxed FLUSH 仍本地成功，错误只出现在 status；
2. 冷缓存非空 remote base 上的局部 WRITE/FLUSH 不发 object GET，恢复后字节
   合并正确；
3. blockd 崩溃后不做远端写即可重建本地水位，恢复发布保持 generation 顺序；
4. 配额只淘汰 clean chunks，pin 数据不丢，背压期间远端调用只来自 publisher；
5. drain 失败时普通 Stop/Warm/Snapshot/Detach/Node drain 不销毁源；Destroy 只允许
   销毁显式列出的 RootDisk，PersistentDisk 源必须保留，远端恢复后同一 job 可重试
   并从新 Host 校验 digest；
6. expiry lapse 不自我 fence，而 revoke/竞争 acquire 后旧 epoch 必须失败。

测试数字只说明相应测试环境和边界，不是生产 SLA。生产 rollout 还必须观察
真实 workload 的 local FLUSH P50/P99、publisher throughput、queue age、Host
容量和冷读 GET 放大。

本地机制基准与环境边界记录在
[`experiments/relaxed-local-first-20260730/`](../../experiments/relaxed-local-first-20260730/)。

## 后果

- Relaxed 的可用性显著提高：S3/DB 短故障与 Guest ext4 解耦，fsync 延迟由
  本地 pack 大小和 NVMe 决定。
- 风险变得显式而不是消失：未发布数据仍只有一个 Host 副本，Host 永久丢失
  会丢 `L-R`；冷读仍依赖对象存储。
- 本地 NVMe 不再对所有状态都是“可删除 cache”。`R < L` 时 pending packs
  是唯一权威副本，生命周期和运维必须把它当数据而不是缓存。
- Strict 仍是默认和 RPO 0 的唯一单 Host 方案；需要本地级 fsync 且承受 Host
  丢失的工作负载，必须增加跨 Host replicated log，不能靠调小 drain interval
  冒充。
