# vhost-user-blk 前端验收与前端成本测量（2026-07-26）

本目录保存 `cats-blockd` 原生 vhost-user-blk 前端（[ADR-0015](../../docs/decisions/0015-vhost-user-blk-production-block-frontend.md)、
[blockd 协议 §7.1](../../docs/specs/blockd-protocol.md)）的**协议级验收**证据，以及三条块传输路径的
**前端成本**测量。

## 结论摘要

1. 协议级验收 **10/10 通过**，外加 1 项针对真实 `cats-blockd` 二进制的双前端集成测试通过。
   正确性判据是「Guest 路径与 oracle 路径看到同一批字节」：每个写入都用 NBD 前端从同一个
   engine 读回比对（规范 §7 指定 NBD 为 oracle）。
2. 相对**真实 Phase A 宿主链路**（fio + O_DIRECT + `/dev/nbd0`）：1 MiB 顺序读
   **2.4–3.8×**、顺序写 **2.8–3.4×**、4 KiB 随机 QD1 **1.7–1.8×**（驱动阻塞等待）
   或 **4.6–5.0×**（驱动自旋等待）、单队列 QD32 4 KiB 随机读 **1.4–1.6×**。
3. 相对**进程内 NBD 客户端**（刻意乐观的对照，不含内核 NBD 跳）：1 MiB 顺序
   **1.7–2.5×**、4 路并发 4 KiB **1.07–1.29×**、单路 QD1 4 KiB **0.80–0.95×**（无提升）。
4. 单路 QD1 没有提升的原因不在后端：把 harness 驱动侧的 `poll(2)`+线程唤醒换成短自旋后，
   同一后端同一负载做到 95–100k ops/s（对进程内 NBD 为 2.2–2.3×），p50 从 25 µs 降到 8–9 µs。
   真实 Guest 的完成通知由 VMM 注入中断，不付 harness 这笔开销。
5. 单队列排队深度 1→32：34–35k → 222–239k ops/s（约 930 MiB/s）。同步 NBD 客户端无法表达
   这种并行度。
6. FLUSH 提交路径两条前端落在同一区间（控制项，0.87–0.98×），证明前端只做协议适配、
   没有改动提交协议。
7. 所有数字都跑了**两轮独立测量**（间隔约 15 分钟，同一台机器）。内核 NBD 侧非常稳定
   （±1–7%），vhost-user 侧的大块读波动明显（5.5 vs 8.8 GiB/s），所以本报告一律给区间，
   不给单点。这也是虚拟化开发环境不能替代裸金属验收的直接证据。
8. **真实 Guest 已验**（QEMU/TCG，不需要 KVM）：真实 Linux 6.1 内核的 `virtio_blk` 驱动
   加真实 ext4 跑在后端上，mkfs / 写 / sync / umount / e2fsck 全过；删掉本地缓存目录后重新
   attach 同一个卷，仍然 fsck clean 且四个 sha256 摘要一致。QEMU 同时充当一个与本仓库无关的
   frontend 实现。
9. **仍未做**：真实 Cloud Hypervisor + KVM 下的 Guest 启动、Guest 内 fio 负载与 Warm
   snapshot/restore 状态对齐。开发机没有 `/dev/kvm`，这一步必须在裸金属上按
   [`metal-e2e-20260721`](../metal-e2e-20260721/README.md) 的形式补做。因此
   `--ch-block-path` 默认仍是 `kernel-nbd`。

## 环境与测量边界

- 宿主：Apple Silicon macOS 开发机；测量在 Docker Desktop 的 Linux VM 内进行
  （`Linux 6.12.76-linuxkit aarch64`，容器可见 18 CPU / 7.7 GiB，**无 `/dev/kvm`**）。
- rustc 1.97.1，release profile（`--release`）测性能，debug profile（断言开启）跑验收。
- 存储后端：`FileBlobStore` + `SqliteMetadataStore`，数据目录在容器文件系统（overlayfs）。
  **不是** S3/PostgreSQL，也不是本地 NVMe；因此绝对值只能用于同机同负载的前端对比。
- 每个性能点 5 次重复，每次都新建 engine 并把可寻址范围（32 MiB）预热成已缓存 chunk，
  避免测到首次取块。整套测量做了两轮（run 1 / run 2），原始文件里带 `-run1` 后缀的是第一轮。
  表内给出均值、中位数与极值范围。
- 证据溯源：`raw/environment.txt` 记录的 `git_commit` 是**测量当时**的提交
  （run 2 = `854902e`，run 1 = 分支基点 `96994a1` 的工作树）。该分支随后 rebase 到并发唤醒准入
  （PR #4）之上，提交 id 因此变化；但本测量只跑 `cats-blockd`，而 `blockd/`、`storage/`、
  `adapters/` 三者在 rebase 前后逐字节相同，变化都在 node-agent/控制面侧，不参与测量。
  run 1 与 run 2 之间的代码差异也只在数据路径之外（CLI 校验顺序、一处 per-connection 日志
  替代原子写、队列深度上界文案）。
- 这是**虚拟化宿主内的容器测量**，不是生产 SLA，也不是 Guest 可见性能。

### 三条被测路径

| 路径 | 链路 | 说明 |
|---|---|---|
| `nbd`（进程内） | 本仓库 `NbdClient` → unix socket → NBD 前端 → ChunkEngine | 每请求一次 `write`/`read` 系统调用对，严格单请求在飞。**乐观基线**：不含内核 NBD 跳。 |
| `vhost-user-blk` | 测试用 VMM 侧驱动 → 共享内存 virtqueue + eventfd → vhost-user 前端 → ChunkEngine | 与真实 Guest 驱动同一条队列路径，但通知由 `poll(2)` 完成（真实 Guest 是注入中断）。 |
| `kernel-nbd`（真实 Phase A 宿主链路） | `fio`（O_DIRECT）→ 宿主内核块层 → `/dev/nbd0` → 内核 NBD client → unix socket → NBD 前端 → ChunkEngine | `--ch-block-path kernel-nbd` 实际使用的链路，缺 Guest 内核与 VMM 自身块后端。需要 privileged 容器。 |

因此对「传输层收益」有一个上下界：进程内 NBD 对照给**下界**（低估 NBD 成本），
真实内核 NBD 链路对照给**上界**（只有 NBD 侧含内核块层）。真实 Guest 的数字落在两者之间，
只有真机验收能定死。

## 实现范围

- `blockd/src/vhost_user.rs`：vhost-user-blk 后端（listen 侧）。协议特性 `MQ`/`CONFIG`；
  virtio 特性 `VERSION_1`/`INDIRECT_DESC`/`EVENT_IDX`/`SEG_MAX`/`BLK_SIZE`/`FLUSH`/`DISCARD`/
  `WRITE_ZEROES`（多队列时加 `MQ`）；请求类型 `IN`/`OUT`/`FLUSH`/`DISCARD`/`WRITE_ZEROES`/`GET_ID`；
  每队列一个 worker 线程。仅 Linux 编译。
- `cmd/blockd`：`--listen-vhost-user`、`--vhost-user-queues`、`--vhost-user-queue-size`；
  可与 `--listen-unix` 同时使用（VMM 走 vhost-user，seeding/readiness/恢复走 NBD，同一 engine
  同一 lease）。
- `node-agent`：`--ch-block-path kernel-nbd|vhost-user`（默认 `kernel-nbd`）、
  `--ch-vhost-user-queues`、`--ch-vhost-user-queue-size`；vhost-user 模式下不再分配
  `/dev/nbdN`，`--disk` 变成 `vhost_user=on,socket=…,num_queues=…,queue_size=…`。
- 测试 harness `blockd/tests/vhu_frontend/`：**独立实现的 VMM/驱动侧**（memfd 当 Guest RAM、
  `SET_MEM_TABLE` 交出内存、手写 split virtqueue、kick/call eventfd）。故意不复用
  `vhost-user-backend` 生态的辅助代码，否则等于用被测实现验证自己。

## 协议级验收

`blockd/tests/vhost_user_blk.rs`，原始输出见 [`raw/acceptance-tests.log`](raw/acceptance-tests.log)。

| 测试 | 断言 |
|---|---|
| `config_space_reports_the_engine_geometry` | capacity=卷字节/512、`blk_size`=512（与 Phase A `nbd-client -b 512` 一致）、`seg_max`=queue_size−2、`writeback`=1、`num_queues`、DISCARD 上限非零、`write_zeroes_may_unmap`=0；截短的 GET_CONFIG 也要能回答 |
| `write_read_flush_matches_the_nbd_oracle` | 写入经 Guest 路径读回一致，且经 NBD oracle 读回一致；空洞读零；FLUSH 推进恰好一个 generation；空 FLUSH 成功且不推进；oracle 侧写入对 Guest 路径可见（同一 engine） |
| `payload_split_across_descriptors_is_reassembled` | 12 KiB 负载拆成 3 个描述符后仍按连续 payload 处理 |
| `discard_and_write_zeroes_zero_the_range` | DISCARD 与 WRITE_ZEROES（含 UNMAP 提示）都写真零；多段请求成功；未定义 flag 返回 `UNSUPP` |
| `get_id_reports_the_volume_id` | `GET_ID` 返回 volume id |
| `out_of_range_and_unknown_requests_fail_the_request_only` | 越界读写返回 `IOERR`、未知请求类型返回 `UNSUPP`，且队列继续正常服务 |
| `fenced_attachment_fails_closed_for_the_guest` | 控制面吊销 lease 后，FLUSH 与后续写都返回 `IOERR`（fail closed，不 ACK 永远无法提交的数据） |
| `multi_queue_requests_run_in_parallel` | 4 队列 4 线程各写各自 1 MiB 区间并回读，全部经 oracle 复核，不串数据 |
| `works_without_event_idx` | 驱动拒绝 `EVENT_IDX` 时走后端的普通通知路径 |
| `pipelined_requests_complete_out_of_order_safely` | 单队列 8 个请求同时在飞，批量完成后逐个复核 |
| `frontend_selection::vhost_user::serves_nbd_and_vhost_user_together_then_exits_with_the_vmm`（`cmd/blockd`） | 真实二进制同时绑定两个 socket；`READY` 在全部 socket 就绪后才打印；NBD 侧可读写；VMM 断开后进程正常退出并释放 lease，下一次 attach 立刻成功且已提交数据仍在 |

`cargo test -p cats-blockd` 全量（两条前端共用的 engine/格式/崩溃测试）见
[`raw/blockd-crate-tests.log`](raw/blockd-crate-tests.log)。

## 真实 Guest 验收（QEMU/TCG，无需 KVM）

协议级 harness 是本仓库自己写的驱动端，Cloud Hypervisor 又需要 KVM。QEMU 用 TCG（纯软件
模拟）可以在没有 KVM 的机器上充当 vhost-user frontend，于是能补上 harness 补不了的两件事：
**一个与本仓库无关的 frontend 实现**，以及**真实 Linux `virtio_blk` 驱动 + 真实 ext4**。

脚本 [`qemu-guest-smoke.sh`](qemu-guest-smoke.sh)；串行日志
[`raw/qemu-guest-boot1.log`](raw/qemu-guest-boot1.log)、
[`raw/qemu-guest-boot2.log`](raw/qemu-guest-boot2.log)；后端日志
[`raw/qemu-blockd.log`](raw/qemu-blockd.log)。

场景：256 MiB 卷、2 队列。boot 1 先在文件系统区域之外做裸扇区读写回环，然后 `mkfs.ext4`
（前 200 MiB）、mount、写三个确定内容的文件、`sync`、`umount`（ext4 journal 在这里发 FLUSH）、
`e2fsck -fn`。随后主机**杀掉后端并删除本地缓存目录**，用新的 data-dir 重新 attach 同一个卷
（规范 §8 判据 2 的空缓存懒读）。boot 2 再 `e2fsck`、mount、重算全部摘要。

| 断言 | 结果 |
|---|---|
| Guest 看到的容量 | 268435456（= 卷字节数，来自 config space） |
| 逻辑块大小 | 512（与 Phase A `nbd-client -b 512` 一致） |
| Guest 硬件队列数 | 2（`/sys/block/vda/mq/`，多队列协商生效） |
| 写缓存语义 | `write back`（持久点在 FLUSH） |
| 裸扇区读写回环 | ok |
| boot 1 `e2fsck -fn` | clean |
| boot 2（空缓存 attach 之后）`e2fsck -fn` | clean |
| boot 2 `dumpe2fs` 文件系统状态 | clean |
| small / large / nested 文件摘要跨空缓存 attach | 三个 sha256 全部一致 |
| 裸扇区区域摘要跨空缓存 attach | 一致 |

内核自己打印的设备行是 `virtio_blk virtio1: 2/0/0 default/read/poll queues` 与
`[vda] 524288 512-byte logical blocks (268 MB/256 MiB)`。第二次 attach 时本地缓存为空，
114 个已提交对象留在对象存储里，数据是从那里懒读回来的。

**这一轮不覆盖**：Cloud Hypervisor 自身，以及 Warm（`vm.snapshot` / `--restore`）的设备
状态对齐。

## 性能测量

### 进程内前端对比（每点 5 次重复，两轮测量）

原始数据 [`raw/frontend-cost.csv`](raw/frontend-cost.csv)（run 2，对应提交 `854902e`）与
[`raw/frontend-cost-run1.csv`](raw/frontend-cost-run1.csv)（run 1）；控制台输出同名 `.log`。
下表 `ops/s` 为 5 次重复的均值，两轮各列一行。

| 负载 | 线程/队列 | 轮次 | nbd ops/s | vhost-user ops/s | 倍数 | nbd p50/p99 µs | vhu p50/p99 µs |
|---|---|---|---|---|---|---|---|
| 4 KiB 随机读 | 1 | run 1 | 43 426 | 37 064 | 0.85× | 20 / 95 | 24 / 85 |
| 4 KiB 随机读 | 1 | run 2 | 42 921 | 34 416 | 0.80× | 20 / 94 | 25 / 85 |
| 4 KiB 随机写 | 1 | run 1 | 36 462 | 33 384 | 0.92× | 20 / 132 | 25 / 112 |
| 4 KiB 随机写 | 1 | run 2 | 36 571 | 34 852 | 0.95× | 20 / 121 | 24 / 112 |
| 4 KiB 随机读 | 4 | run 1 | 71 390 | 81 022 | **1.13×** | 49 / 178 | 43 / 128 |
| 4 KiB 随机读 | 4 | run 2 | 71 050 | 76 323 | **1.07×** | 47 / 178 | 44 / 135 |
| 4 KiB 随机写 | 4 | run 1 | 55 513 | 70 624 | **1.27×** | 52 / 335 | 42 / 312 |
| 4 KiB 随机写 | 4 | run 2 | 53 887 | 69 650 | **1.29×** | 55 / 345 | 42 / 302 |
| 1 MiB 顺序读 | 1 | run 1 | 3 585（3.6 GiB/s） | 8 815（8.8 GiB/s） | **2.46×** | 244 / 509 | 101 / 210 |
| 1 MiB 顺序读 | 1 | run 2 | 3 234（3.2 GiB/s） | 5 479（5.5 GiB/s） | **1.69×** | 276 / 510 | 174 / 270 |
| 1 MiB 顺序写 | 1 | run 1 | 4 086（4.1 GiB/s） | 8 329（8.3 GiB/s） | **2.04×** | 220 / 481 | 100 / 284 |
| 1 MiB 顺序写 | 1 | run 2 | 3 501（3.5 GiB/s） | 6 910（6.9 GiB/s） | **1.97×** | 261 / 497 | 120 / 294 |
| 4 KiB 写 + FLUSH（控制项） | 1 | run 1 | 48 | 42 | 0.87× | 20 688 / 24 194 | 25 216 / 31 080 |
| 4 KiB 写 + FLUSH（控制项） | 1 | run 2 | 49 | 49 | 0.98× | 20 115 / 24 937 | 20 218 / 23 416 |

极值范围（run 2）：4 KiB 随机读 t1 nbd 41.8–44.0k / vhu 33.8–35.1k；1 MiB 顺序读
nbd 2.55–3.87k / vhu 5.07–5.89k；FLUSH nbd 48–52 / vhu 48–50。FLUSH 每次提交
约 20–25 ms，由提交协议与 overlayfs 的 `fdatasync` 主导，两轮里前端选择都不可见。

1 MiB 顺序读在两轮之间从 8.8 GiB/s 掉到 5.5 GiB/s（NBD 侧同向从 3.6 掉到 3.2 GiB/s），
而下一节的内核 NBD 链路两轮几乎一致。可以确定的是大块 I/O 有明显提升，具体倍数
（1.7–2.5×）受这台虚拟化宿主的内存/页缓存状态影响，不适合当成单一结论值。

### QD1 4 KiB 为什么没有提升

驱动侧每完成一个请求要 `poll(2)` 一次并被唤醒一次；NBD 客户端只需一次阻塞 `read`。
把 harness 的等待方式换成短自旋（[`raw/notification-cost.log`](raw/notification-cost.log)、
[`raw/notification-cost-run1.log`](raw/notification-cost-run1.log)）：

| 负载 | 驱动等待 | run 1 ops/s | run 2 ops/s | p50 µs |
|---|---|---|---|---|
| 4 KiB 随机读 | poll | 35 222 | 33 995 | 25 |
| 4 KiB 随机读 | spin | **99 947** | **95 354** | **9** |
| 4 KiB 随机写 | poll | 31 878 | 31 880 | 25 |
| 4 KiB 随机写 | spin | **75 983** | **80 231** | **8** |

即后端在 QD1 下能做到 95–100k ops/s（对进程内 NBD 的 ~43k 为 2.2–2.3×），差距来自 harness
的通知方式。真实 Guest 的完成通知由 VMM 注入中断，不经过 `poll(2)`+用户态线程唤醒。
本报告因此把 QD1 的 0.80–0.95× 记为 **harness 伪影**而不是后端退化——但也不把 spin 数字
当作可交付的 Guest 性能。

### 单队列排队深度（vhost-user，4 KiB 随机读）

[`raw/queue-depth.log`](raw/queue-depth.log)、[`raw/queue-depth-run1.log`](raw/queue-depth-run1.log)：

| QD | 1 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|
| run 1 ops/s | 34 268 | 88 864 | 127 466 | 184 694 | 222 461 |
| run 2 ops/s | 35 224 | 85 664 | 133 212 | 178 329 | 238 597 |
| run 2 MiB/s | 138 | 335 | 520 | 697 | 932 |

同步 NBD 客户端无法表达这一维度（每次只能有一个请求在飞），所以这里没有对照列；
真实内核 NBD client 会做流水线，其 QD32 数字见下一节。

### 真实 Phase A 宿主链路（fio + O_DIRECT + `/dev/nbd0`）

原始数据 [`raw/kernel-nbd-fio.csv`](raw/kernel-nbd-fio.csv)（run 2）与
[`raw/kernel-nbd-fio-run1.csv`](raw/kernel-nbd-fio-run1.csv)（run 1），每点 10 s（2 s ramp），
fio JSON 保存在 `raw/fio-*.json`。这是 `--ch-block-path kernel-nbd` 在宿主侧的真实链路。

| 负载 | QD | run 1 IOPS / 吞吐 | run 2 IOPS / 吞吐 | run 2 p50 / p99 µs |
|---|---|---|---|---|
| 4 KiB 随机读 | 1 | 20 191 | 20 167（78.8 MiB/s） | 38 / 129 |
| 4 KiB 随机写 | 1 | 20 531 | 20 733（81.0 MiB/s） | 36 / 126 |
| 4 KiB 随机读 | 32 | 154 998 | 153 259（599 MiB/s） | 198 / 449 |
| 4 KiB 随机写 | 32 | 181 498 | 181 425（709 MiB/s） | 161 / 379 |
| 1 MiB 顺序读 | 1 | 2 297 MiB/s | 2 293 MiB/s | 403 / 676 |
| 1 MiB 顺序写 | 1 | 2 651 MiB/s | 2 475 MiB/s | 183 / 330 |

两点结论：

1. **内核 NBD 跳本身很贵。** 同一个 engine、同一个 NBD 前端，进程内客户端 QD1 4 KiB 随机读
   ~43k ops/s，经 `/dev/nbd0` 只有 ~20.2k——即上一节那个「乐观基线」把 NBD 的成本低估了
   约 2.1×。1 MiB 顺序读同理：3.2–3.6 GiB/s → 2.3 GiB/s。
2. **对真实 Phase A 链路，vhost-user 的提升区间**（两轮的最小/最大值）：

   | 负载 | kernel-nbd（真实链路） | vhost-user（poll 等待） | vhost-user（spin 等待） |
   |---|---|---|---|
   | 4 KiB 随机读 QD1 | 20.2k | 34.4–37.1k（**1.7–1.8×**） | 95.4–99.9k（**4.7–5.0×**） |
   | 4 KiB 随机写 QD1 | 20.5–20.7k | 33.4–34.9k（**1.6–1.7×**） | 76.0–80.2k（**3.7–3.9×**） |
   | 4 KiB 随机读 QD32（单队列） | 153–155k | 222–239k（**1.4–1.6×**） | — |
   | 1 MiB 顺序读 QD1 | 2.29–2.30 GiB/s | 5.5–8.8 GiB/s（**2.4–3.8×**） | — |
   | 1 MiB 顺序写 QD1 | 2.48–2.65 GiB/s | 6.9–8.3 GiB/s（**2.8–3.4×**） | — |

**这张表不是 Guest 可见性能。** fio 侧含宿主内核块层，vhost-user 侧两端都没有内核块层
（真实 Guest 自己有一层）；两边的通知机制也都不是 VMM 注入中断。可以确定的是：被去掉的
那一跳（内核 NBD client + 每请求 socket 往返 + payload 复制）在同一台机器上值
1.4×–5×，且大块 I/O 与高队列深度的收益最确定。真实数字要靠裸金属验收。

## 未验证事项（必须在裸金属上补做）

1. 真实 Cloud Hypervisor（KVM）用 `--disk vhost_user=on,...` 启动 Guest，跑通四态生命周期，
   与 2026-07-21 的 17 项验收等价。
2. Warm（`vm.snapshot` / `--restore`）在 vhost-user 设备上的状态对齐（ADR-0002 已列为必须重验项）：
   restore 前先起 blockd，socket 路径由 (state_dir, cat_id, disk_id) 决定，理论上稳定，但需要实测。
3. Guest 内 ext4 + fio 的可见性能，以及多队列在真实 vCPU 数下的收益曲线。
4. `nbd` 内核模块与 `nbd-client` 依赖去除后的部署路径（`install.sh` 仍按 kernel-nbd 配置）。

## 复现

```bash
# 协议级验收 + 进程内前端成本（不需要 KVM / root；macOS 上自动进容器）
experiments/vhost-user-blk-frontend-20260726/run.sh

# 真实 Guest：QEMU/TCG 当 frontend，真实内核驱动 + 真实 ext4（不需要 KVM）
experiments/vhost-user-blk-frontend-20260726/qemu-guest-smoke.sh

# 真实内核 NBD 链路对照（需要 nbd 模块、nbd-client、fio 与 privileged 容器）
experiments/vhost-user-blk-frontend-20260726/kernel-nbd-baseline.sh
```

环境摘要写入 [`raw/environment.txt`](raw/environment.txt)。
