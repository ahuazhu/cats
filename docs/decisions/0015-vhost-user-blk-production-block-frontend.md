# ADR-0015：vhost-user-blk 作为生产 Guest 块前端，内核 NBD 保留为可选路径

- 状态：Accepted
- 日期：2026-07-26

## 背景

ADR-0001 第 3 条把「接入 Cloud Hypervisor vhost-user-blk」列为 V1 里程碑，但 Phase A
先用内核 NBD 打通正确性：`Guest virtio-blk → CH 内置 block backend → /dev/nbdN
（内核 NBD client）→ cats-blockd NBD 前端 → ChunkEngine`。该路径已通过 2026-07-21 的
17 项 AWS 裸金属验收（[`metal-e2e-20260721`](../../experiments/metal-e2e-20260721/README.md)），
证明提交协议、fencing 与四态生命周期正确，但它有三个结构性代价：

1. 每个 Guest 请求都要穿过 Host 内核 NBD client 和一个 Unix socket，payload 必须
   跨 socket 复制；请求间没有多队列并行。
2. 每块盘占用一个全局 `/dev/nbdN`，需要 `modprobe nbd nbds_max=…`、一把宿主级
   分配锁，以及 Warm restore 时把设备号还原成快照里的同一个索引。
3. `nbd-client` 是额外的运行时依赖，且 attach/detach 只能以 root 操作宿主块层。

## 决定

1. `cats-blockd` 原生实现 vhost-user-blk 前端（规范见
   [blockd 协议 §7.1](../specs/blockd-protocol.md)），基于 rust-vmm
   `vhost-user-backend` / `virtio-queue` / `vm-memory`（ADR-0004 已指定该生态）。
   仅 Linux 编译，NBD 前端保持跨平台。
2. **前端只做协议适配**：virtio-blk 的 IN/OUT/FLUSH/DISCARD/WRITE_ZEROES/GET_ID
   全部翻译成与 NBD 前端完全相同的 `ChunkEngine` 调用。提交协议（§6）、dirty
   tracking、lease/fencing 与崩溃恢复不因前端而改变，因此两条路径共用同一套正确性
   测试，NBD 继续作为 oracle。
3. 一个 `cats-blockd` 进程可以同时监听两个 socket：vhost-user 给 VMM，NBD 给
   readiness 探测、golden root seeding 与恢复工具。二者服务同一个 engine 实例，
   同一个 attachment lease。
4. Node Agent 用 `--ch-block-path {kernel-nbd|vhost-user}` 选择路径，默认仍是
   `kernel-nbd`。切换是每个 Node 的部署选项，不是 Cat 的属性，也不需要数据迁移：
   卷格式、Map、对象布局完全一致，同一个卷可以在两条路径之间来回启动。
5. Guest 可见几何保持不变：`blk_size` 报 512（与 Phase A 的 `nbd-client -b 512`
   一致），`writeback=1`（持久点仍然只在 FLUSH），`write_zeroes_may_unmap=0`
   （V1 写真零，不产生 Hole，符合 §7 的 TRIM 语义）。已 seed 的 golden root 镜像
   在两条路径上按字节等价。
6. 队列数与队列深度由 Node 配置（`--ch-vhost-user-queues`、
   `--ch-vhost-user-queue-size`），后端每个队列一个 worker 线程，数量按每个 Cat 的 vCPU 数
   夹住（Cloud Hypervisor 拒绝 `num_queues > vCPU`）。FLUSH 仍是整卷屏障，与队列数无关。
   **队列多不等于更快**：同样 32 个在飞请求，1 队列 667k ops/s 对 4 队列 211k——单队列深排队
   的批处理效果强于跨队列并行，所以默认保持 1 个队列。

## 现状:已验证到什么程度

- **协议级**(本机,无需 KVM):vhost-user 协商、config space、六类请求、多描述符 payload、
  多队列并行、EVENT_IDX 开关、越界与未知请求按请求失败、fenced attachment 对 Guest fail closed,
  以及与 NBD oracle 的逐字节一致。10/10。
- **真实 Guest**(QEMU/TCG,无需 KVM):真实 Linux 6.1 内核 `virtio_blk` + 真实 ext4,
  mkfs/写/sync/umount/e2fsck 全过;删除本地缓存目录后重新 attach 仍 fsck clean、摘要一致。
- **真机**(AWS `i4i.metal`,真 KVM + Cloud Hypervisor v53):`deploy/metal/e2e.sh` 在两条路径上
  同为 **22 passed / 1 failed**(唯一失败与块路径无关),**包含 Warm `vm.snapshot` / `--restore`
  后 boot_id 保持与文件存活**——ADR-0002 要求的重验项已完成。Warm restore 总耗时 51.9 ms vs
  92.5–98.7 ms(块挂载 40 ms → 5 µs)。
- **集群形态**:两节点 + 真实 S3 + RDS PostgreSQL 下跨节点 Cold 迁移 12/12 通过(4.4 s)。
- 证据:[`vhost-user-blk-frontend-20260726`](../../experiments/vhost-user-blk-frontend-20260726/README.md)、
  [`metal-cluster-20260726`](../../experiments/metal-cluster-20260726/README.md)。

## 为什么默认值仍是 `kernel-nbd`

不是因为没验过,而是一个**按当前部署形态**的写吞吐权衡:

- 节点代理今天让 Cloud Hypervisor **带缓冲**打开 `/dev/nbdN`(`direct=off` 是 CH 默认),宿主
  page cache 会在引擎看到之前就 ack Guest 的写。按这个形态对比,kernel-nbd 在写与顺序读上更快
  (Guest fio 4 KiB 随机写 QD32:213–223k vs 23–33k IOPS)。
- 把这层缓冲关掉(`direct=on`)做同层次对照,**vhost-user 在 6 项负载里的 5 项快 1.7×–5.7×**,
  随机读 p50 从 32 µs 降到 9–10 µs。
- 两条路径在这个负载上**都是 flush-bound**:V1 提交整个 4 MiB chunk,4 KiB 随机写的写放大约
  100×,一次提交要写下约 200 MiB。差别只在提交协议前面垫了多少易失缓冲。

**翻转默认值的判据**:(a) delta pack(Direct-S3 设计 P4:只提交脏的 64 KiB 页)落地并把提交
成本降下来,或 (b) 明确接受"用写吞吐换随机读延迟与 Warm 速度"这个权衡并有对应负载证据;
外加 (c) 一轮多样本 soak。在此之前 vhost-user 是显式选项。

**2026-07-27 全量复测(第二次,环境已对齐):只剩判据 (c) 没做。**
给 kernel-nbd 补上 `--ch-block-direct` 之后,公平对照终于可做,结果是**单向的**
([原始数据](../../experiments/vhost-user-blk-frontend-20260726/raw/metal-fio-matrix.log)):

| 负载(i4i,本地 NVMe,median of 2 轮) | kernel-nbd `direct=on` | vhost-user | |
|---|---|---|---|
| 4 KiB 随机读 QD1 | 23 479 | **61 994** | 2.6× |
| 4 KiB 随机写 QD1 | 7 106 | **15 106** | 2.1× |
| 4 KiB 随机读 QD32 | 121 510 | **216 066** | 1.8× |
| 4 KiB 随机写 QD32 | 20 277 | **40 650** | 2.0× |
| 1 MiB 顺序读 | 1 172 MiB/s | **3 606** | 3.1× |
| 1 MiB 顺序写 | 554 MiB/s | **1 998** | 3.6× |

**六项全胜。**并发上差距更大:10 个并发创建 16 692 → **3874 ms(4.3×)**、10 个并发唤醒
1129 → **371 ms(3.0×)**,而单个 Cat 的创建/唤醒/挂起两条路用户感觉不出差别
([`raw/c5-lifecycle-summary.log`](../../experiments/vhost-user-blk-frontend-20260726/raw/c5-lifecycle-summary.log))。
并发那部分的原因很具体:节点代理为每个 kernel-nbd 启动都要拿一把**全机器共享的 `/dev/nbdN`
分配锁**,vhost-user 从不需要。

还有一条不是性能的理由:**cats-blockd 死掉而 `/dev/nbdN` 还连着时,任何碰这个设备的进程进入
不可中断睡眠**——节点代理扛过 SIGKILL、继续占着端口、systemd 无法重启,只能手工 `nbd-client -d`。
vhost-user 没有内核设备可以变成孤儿。

所以判据 (b)「明确接受权衡」**已经不适用了:没有权衡需要接受**。**唯一剩下的是 (c) 一轮多样本
soak** —— 现有数据是 fio 2 轮中位数、生命周期 3 次中位数、并发单样本,不够 SLA 级别。在那之前
默认值保持 `kernel-nbd`。

**上一次(同日早些时候)那轮复测作废**,留作记录:那轮把 ChunkStore 的本地 cache 落在了 EBS
而不是实例 NVMe,对象存储也换成了 S3,所以绝对值既不能引用也不能和 2026-07-26 的表比
([原始数据](../../experiments/vhost-user-blk-frontend-20260726/raw/metal-blockpath-fio-rerun.log)
顶部有警告)。它当时得出的「卡点是节点代理没有 `direct=on` 选项」这个判断是对的,该选项随后
就加上了(`--ch-block-direct`),上面那组数字就是用它测的。

## 后续优化的验证结果(2026-07-26)

- **做了**:提交路径的拷贝与哈希并行化 → FLUSH 快 **1.6×–1.8×**(32–192 MiB 的提交);
  节点内并发拉起从"基本串行"(并发度 1.1)到 **4.0×–5.3×**,并发有独立上限。两者对两条
  前端都有效。
- **验证为负收益**:每队列请求并行。同样 32 个在飞请求,1 队列 667k ops/s 对 4 队列 211k。
- **验证为当前设计下不可行**:golden root 复用(对象 key 按卷命名空间,GC 会误删跨卷引用),
  需要先决定内容寻址或显式 clone 血缘。
- **仍是根治项**:delta pack(只提交脏的 64 KiB 页)。注意"只拷脏页但仍上传整 chunk"的中间
  形态**不成立**——屏障必须拷贝它将要上传的内容,否则重建时会读到屏障之后的新写。

数据见 [`vhost-user-blk-frontend-20260726`](../../experiments/vhost-user-blk-frontend-20260726/README.md)
的"四个优化点的验证结果"。

## 风险与缓解

- **Warm restore 状态对齐**：CH 快照恢复要重新连接 vhost-user socket。Node 侧 socket
  路径由 (state_dir, cat_id, disk_id) 决定，restore 前先起 blockd，路径与快照一致。
  真机验收前不得把 vhost-user 设为默认。
- **队列参数不一致**：VMM 与后端的 `num_queues`/`queue_size` 必须相同，否则表现为
  Guest 设备不完成请求。两侧参数来自同一份 Node 配置，且写在 `--disk` 参数里。
- **共享内存要求**：vhost-user 需要 Guest RAM 是 `MAP_SHARED`。CH 模式已经为
  `MADV_PAGEOUT`（ADR-0002 Suspended）使用命名共享 memory zone，无新增要求。
- **恶意/异常 Guest**：单请求 payload 上限与 NBD 前端一致（32 MiB）；畸形描述符链
  只失败该请求并记日志，不影响队列继续服务。
