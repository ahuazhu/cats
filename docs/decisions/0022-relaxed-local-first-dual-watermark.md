# ADR-0022：Relaxed local-first 双持久化水位与强制 drain

- 状态：Accepted
- 日期：2026-07-30
- 细化：[ADR-0021](0021-relaxed-durability-tier.md)
- RootDisk Destroy例外：[ADR-0025](0025-destroy-disposable-root-without-remote-drain.md)
- Volume Authority：[ADR-0042](0042-volume-authority-and-disk-lifecycle.md)

## 背景

Relaxed把Guest durability point放在本地NVMe，同时异步推进远端durability。正确性需要
明确区分两个水位：定时器不能代表RPO，远端故障不能直接变成运行中ext4的EIO，生命周期
也不能在远端水位落后时销毁唯一的本地副本。

## 决定

### 1. 两个明确水位

每个 blockd 同时维护：

- `L = local_durable_generation`：最高一个连续durable generation。`generation <= R`的内容已远端
  durable；每个`R < generation <= L`都必须有完成file fsync、rename和directory fsync的
  immutable pending pack。这个定义与Guest是否已经收到ACK无关。
- `R = remote_durable_generation`：数据/Map/commit record 已写入对象存储，
  PostgreSQL head CAS 已成功。

必须始终满足 `R <= L`。Strict 的 ACK 条件是目标barrier已推进`R`；Relaxed 的 ACK
条件是目标barrier已推进`L`。发布后先推进`R`再删除相应pack，`L`保持不变。Host永久丢失时只能恢复
到远端`R`。Node在线时以`L-R`的generation
数、字节数和最老年龄暴露实时风险；Host丢失后最后一次observation只是最近样本，不是
故障瞬间精确损失量。

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

lease到期时间只用于健康判断，不授予竞争者acquire权限。只要数据库行仍是同一
`owner + epoch`，原holder可以renew，也可以在generation CAS中继续发布；单纯本地调度或DB
抖动导致的expiry lapse不能把健康Cat自我fencing。

normal acquire只允许带`transition_id + attachment_id + expected_unowned_epoch`的精确
`Unowned -> Owned`转换；相同transition重试返回原grant。release也必须幂等且精确匹配
owner/epoch。其他owner即使过期也返回`OtherWriter`。非计划接管必须使用从Active
`HostFenceEvent`派生的逐卷授权并原子提高epoch；旧epoch的renew/CAS随后永久失败。

Node取得精确LeaseGrant后启动blockd；blockd只采用、renew和使用该grant，不自行acquire或换epoch。
data-dir与pending pack必须绑定volume、attachment、epoch和acquire transition，新attachment不得
采用旧lineage的`R < L`数据。完整接口见[Volume Authority规格](../specs/volume-authority.md)。

### 6. 恢复和生命周期

- Relaxed 同 Host blockd 重启先从本地 pack 重建 `L`，不在 attach 恢复阶段
  做远端写；后台 publisher 随后推进 `R`。
- `drain` 成功的定义是所有卷 `R == L`。`status` 控制命令返回两个水位、
  unpublished generations/bytes/oldest age、配额、eviction、backpressure、
  fencing 和最后发布错误。
- Stop/Cold、Warm、`cats sync`和计划内 Node drain/冷迁移都必须先停止晚到的 Guest 写，再强制
  drain。失败时保留 blockd、
  local journal 和 lease，控制器重试；不得标记 Cold、解绑/删除盘或清理源。
- **Cat Destroy 的 RootDisk 例外**：RootDisk 与 Cat 同生命周期且本次操作会删除
  它的 metadata/对象，因此 Guest/VMM 停止后可以不发布其本地 tail，直接丢弃该
  RootDisk 的journal与cache；但必须先消费ADR-0042定义的精确disposable-root删除授权，
  把当前Owned卷原子置为Deleting并提高epoch。这个例外不能扩展到普通Stop/Cold，也不能
  扩展到 PersistentDisk；同一次 Destroy 中需要返回 Available 的 PersistentDisk 仍
  必须完成 final drain，任一失败就保留其 blockd/journal/lease 并重试。删除授权CAS成功前不得
  清本地tail；成功后旧epoch永久不能publish。生命周期期望必须在每个`VolumeIntent`上携带
  `DeleteDisposableRoot {delete_id}`或`DetachRetained`；未知或冲突分类fail closed，不能由mount
  path猜测。
- 第一版不支持hot attach、hot detach、resize或Running DiskSnapshot。磁盘成员关系与
  DiskSnapshot只在Cat稳定Cold且volume unowned时改变；volume容量创建后不可变。这里的
  DiskSnapshot是远端Root pin，不是WarmRuntimeSnapshot。
- 非计划 Host 丢失无法 drain；从最后远端`R`冷恢复并报告`DataLossPossible`，附带最后
  observation的backlog作为诊断。外部隔离先建立HostFenceEvent，随后只有精确逐卷授权CAS才能
  提高attachment epoch。这是产品选择，不是“自动恢复零丢失”。

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

告警基于实际age/bytes、水位是否持续不收敛和Host free space。

## 验证

自动化必须覆盖：

1. S3 PUT 持续失败时 Relaxed FLUSH 仍本地成功，错误只出现在 status；
2. 冷缓存非空 remote base 上的局部 WRITE/FLUSH 不发 object GET，恢复后字节
   合并正确；
3. blockd 崩溃后不做远端写即可重建本地水位，恢复发布保持 generation 顺序；
4. 配额只淘汰 clean chunks，pin 数据不丢，背压期间远端调用只来自 publisher；
5. drain 失败时普通 Stop/Cold、Warm/Node drain 不销毁源；Destroy 只允许
   销毁显式列出的 RootDisk，PersistentDisk 源必须保留，远端恢复后同一 job 可重试
   并从新 Host 校验 digest；
6. expiry lapse不自我fence，normal acquire不能抢占owner；逐卷授权takeover后旧epoch必须失败；
7. 重复acquire/release transition返回同一结果，新attachment不能重放旧lineage pack；
8. Running磁盘变更、resize与DiskSnapshot请求被拒绝，Cold Snapshot Root进入GC live set。

测试数字只说明相应测试环境和边界，不是生产 SLA。生产 rollout 还必须观察
真实 workload 的 local FLUSH P50/P99、publisher throughput、queue age、Host
容量和冷读 GET 放大。

本地机制基准与环境边界记录在
[`experiments/relaxed-local-first-20260730/`](../../experiments/relaxed-local-first-20260730/)。

## 后果

- Relaxed 的可用性显著提高：S3/DB 短故障与 Guest ext4 解耦，fsync 延迟由
  本地 pack 大小和 NVMe 决定。
- 风险变得显式而不是消失：未发布数据仍只有一个 Host 副本，Host 永久丢失只能恢复到`R`；
  故障前最后一次观测的`L-R`只是风险样本，不是故障瞬间精确损失量；冷读仍依赖对象存储。
- 本地 NVMe 不再对所有状态都是“可删除 cache”。`R < L` 时 pending packs
  是唯一权威副本，生命周期和运维必须把它当数据而不是缓存。
- Strict仍是默认的单Host RPO 0档位。本地级fsync同时要求Host-loss RPO 0时，需要独立
  ADR定义跨Host replicated log。
