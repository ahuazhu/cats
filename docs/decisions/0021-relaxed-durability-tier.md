# ADR-0021：按盘可选的 relaxed 持久性档位

- 状态：Accepted
- 日期：2026-07-29

## 背景

严格 FLUSH 把对象存储往返放在每个 fsync 的关键路径上（Standard ~109 ms，
Express One Zone ~67 ms，ADR-0020）。大量 cat 负载（CI、构建缓存、agent
沙箱）本质可重建，愿意用一个有界的丢失窗口换本地级 fsync。市场先例是
Fly Sprites——实测其 fsync ~4 ms、本地 ack + 异步上传、崩溃丢弃已 ack
数据（2026-07-29 sysrq panic 实验），但**没有文档披露窗口**；Modal 则把
同一形态做成显式 `commit()` API。我们选择：可以宽松，但必须显式、可选、
写明窗口。

## 决定

持久性是**盘的属性**，默认 strict，创建时选定后不可变（改变它会改变
guest 已收到的 ack 的含义）：

- `cats create --durability strict|relaxed`（作用于本命令创建的根盘与
  `--disk`）；`cats disk create --durability ...`；`disks` 表新列
  （schema v3，走 ADR-0019 的 user_version 梯子原地迁移，旧盘一律
  strict）；经 `VolumeGrant.durability` 到 blockd argv。
- **引擎实现（stage/publish 拆分）**：`flush()` 拆为 stage（冻结屏障 +
  本地 pack fsync）与 publish（对象上传 + 元数据 CAS）。strict 的 ack
  在 publish 后（行为不变）；relaxed 的 ack 在 stage 后（~1 ms），后台
  committer 每 `drain_interval_ms`（默认 5 s）按序 publish。staged 队列
  超过 `MAX_STAGED_PACKS`(16) 时 FLUSH 退化为内联 drain——对象存储故障
  表现为延迟，不表现为无界丢失窗口。
- **pack 链**：staged pack 以 `next_base` 单调计数器链式分配
  base_generation，文件名以其为前缀使字典序 = 世代序；崩溃后
  `recover_pending_packs` 按序重放整条链。同机重启（blockd 崩溃、进程
  被杀）**零丢失**——ack 的最低背书是本地 pack 落盘。
- **锁纪律**：publish 走独立的 `publish_lock`，让 relaxed 的 stage/ack
  不被慢 publish 阻塞；GC 与 provision 同时持有 `flush_lock` +
  `publish_lock`（否则 GC 会把「已上传、未 CAS」的对象扫成垃圾）。

## 契约（用户可见文案）

relaxed 盘上：fsync 在本地提交后返回；数据在 ≤5 秒内到达对象存储；
**宿主机非计划死亡时，最近 ≤5 秒的写入（含已 fsync 的）可能丢失**。
以下点位强制全量 publish，完成前不返回：

- 生命周期：stop/teardown（VMM 退出后 drain，杜绝末尾窗口）、warm
  （pause 之后）、hot detach。suspend 不显式 drain：VMM 驻留同机，
  后台 committer 在一个周期内自然清空。
- `cats sync <name>`：随时买一个 strict 时刻（guest syncfs → 每个
  blockd 经控制 socket `drain`）。脚本在对外承诺之前调它。
- fencing 时已 staged 未 publish 的 pack 随 lease 作废——这在 relaxed
  契约允许的窗口内；strict 盘不受影响（无 staged 队列）。

## 后果

- blockd 新增 `--durability`、`--drain-interval-ms`、`--listen-control`
  （行协议：`drain` → `OK <generation>`）；node-agent 在四个强制点调用。
- relaxed 合批天然降低 S3 PUT 次数与请求费。
- 已知缺口：`create_snapshot` 不强制 sync，快照捕获的是最近提交的
  generation（strict 下同样存在，relaxed 下窗口更宽）——后续应在快照
  路径前置一次 sync。
- 跨多个 staged pack 反复写同一 chunk 时，delta 链可能暂超
  `MAX_DELTA_LAYERS`（plan 以已提交 map 为准），上限受队列长度约束，
  只影响冷读 GET 数，不影响正确性。

## 修订（2026-07-29，同日）：合批 publish 与停车式背压

首日生产暴露了 v1 泄压设计的车队病理：持续 fsync 负载下队列贴着
16-pack 上限运行，每个撞限的 FLUSH 排队等 `publish_lock` 并亲自串行
publish 整个积压——fsync 地板升到一整轮 publish（实测 min 672ms、
p90 4.6s），relaxed 反而比旁边的 strict 卷更慢。修订如下：

- **合批 publish**：一次 drain 把整个队列作为一批——所有 pack 的对象
  合成一个并发上传波、按链序套用 map、单次 CAS 让 head 一次跳 N 代
  （`MetadataStore::cas_head` 增加显式 `new_generation`，比较仍在
  expected 上，fencing 语义不变）。批内存驻留以 256 MiB 为界分段。
- **commit record 按批留档**：只写批尾一条（中间 record 不能预写——
  CAS 前崩溃的逐 pack 重放会以真实 root 重写同名 key，撞
  `put_immutable` 的不可变检查）。审计轨迹的 generation 序列因此有
  空洞。
- **恢复路径不变**：CAS 前崩溃逐 pack 重放如旧；CAS 后残留 pack 落入
  既有 superseded 清理（内容已在已提交 map 中）。
- **eager committer**：队列超过 2 个即被踢醒并持续 drain；
  `drain_interval_ms` 降级为空闲兜底（0 = 不起后台线程，测试确定性
  模式）。
- **停车式背压**：撞限的 FLUSH 在 condvar 上等 committer 每批 pop 的
  唤醒（约一轮 publish 的停顿），不再亲自 drain；10 秒无空位退回内联
  drain，对象存储瘫痪不得无限扣押 guest FLUSH。committer 批间释放
  `publish_lock`。上限 16 → 64（合批后单轮 drain 成本与 pack 数无关）。

复验：100ms/PUT 的存储上 80 连发 fsync，单次最大 88ms（修订前同形态
负载为 0.7–4.6s）。
