# vhost-user-blk 前端验收与前端成本测量（2026-07-26）

本目录保存 `cats-blockd` 原生 vhost-user-blk 前端（[ADR-0015](../../docs/decisions/0015-vhost-user-blk-production-block-frontend.md)、
[blockd 协议 §7.1](../../docs/specs/blockd-protocol.md)）的**协议级验收**证据，以及三条块传输路径的
**前端成本**测量。

## 结论摘要

真机(AWS `i4i.metal`,真 KVM + Cloud Hypervisor v53)与本机容器两处证据,真机结论优先。

1. **正确性:与内核 NBD 路径完全等价。** 同一套 `deploy/metal/e2e.sh` 在两条路径上都是
   **22 passed / 1 failed**,唯一失败是 golden rootfs 里没有 `git` 的陈旧断言,与块路径无关。
   通过项包含四态生命周期、**Warm(`vm.snapshot` / `--restore`)后 boot_id 保持且文件存活**
   ——正是 ADR-0002 要求用带 dirty/lease 状态的 blockd 重验的那一项。
2. **Warm restore 快 1.8×**:总耗时 51.9 ms vs 92.5–98.7 ms,原因很具体——块挂载步骤从
   ~40 ms(`nbd-client` 挂 `/dev/nbdN`,还要抢宿主全局分配锁)降到 **5 µs**(只是拼一个 socket 路径)。
3. **Guest 可见吞吐:公平对照下 6 项里 5 项快 1.7×–5.7×。** 关键前提是把宿主 page cache
   从对照里去掉(见第 4 条):

   | Guest fio(4 vCPU,ext4 root,O_DIRECT) | kernel-nbd `direct=on` | vhost-user | 倍数 |
   |---|---|---|---|
   | 4 KiB 随机读 QD1 | 26 952 IOPS | 68 485–74 006 | **2.5–2.7×** |
   | 4 KiB 随机读 QD32 | 129 301 | 260 741–270 724 | **2.0–2.1×** |
   | 4 KiB 随机写 QD32 | 5 841 | 23 379–33 000 | **4.0–5.7×** |
   | 1 MiB 顺序读 | 1 056 MiB/s | 3 575–3 642 | **3.4×** |
   | 1 MiB 顺序写 | 723 MiB/s | 1 242–1 702 | **1.7–2.4×** |
   | 4 KiB 随机写 QD1 | 11 928 | 6 080–8 197 | **0.5–0.7×**(唯一劣势) |

4. **不要拿今天的默认配置直接比。** 生产用的 kernel-nbd 路径里,Cloud Hypervisor 是
   **带缓冲**打开 `/dev/nbdN` 的(`direct=off` 是 CH 默认),宿主 page cache 会先把 Guest 的写
   吃掉再 ack,引擎当时还没看到这些写。所以按当前部署形态对比,NBD 在写和顺序读上更快
   (4 KiB 随机写 QD32 213–223k vs 23–33k)。这不是传输层的差距,而是多了一层易失缓冲——
   把它关掉,同一条 NBD 路径就比 vhost-user 慢。详见 [根因](#写路径根因flush-bound不是前端)。
5. **协议级验收 10/10**,外加真实二进制的双前端集成测试;QEMU/TCG 下真实 Linux 6.1 内核的
   `virtio_blk` + 真实 ext4 也全通过,含删掉本地缓存后重新 attach 仍 fsck clean、四个 sha256 一致。
6. **默认值仍是 `kernel-nbd`。** 理由不再是"没验过",而是第 4 条那个按当前部署形态的写吞吐
   权衡:在 delta pack(Direct-S3 设计 P4)落地把提交成本降下来之前,不建议把带缓冲的
   NBD 路径换成 vhost-user 作为默认。翻转默认值的判据写在 [ADR-0015](../../docs/decisions/0015-vhost-user-blk-production-block-frontend.md)。

## 环境与测量边界

### 真机(结论依据)

- AWS `i4i.metal`,`us-east-1`,Ubuntu 24.04 x86_64,Linux `6.17.0-1019-aws`,`/dev/kvm` 可用,
  128 vCPU / 1 007 GiB RAM;Cloud Hypervisor `v53.0`;rustc 1.97.1。
- ChunkStore 本地 cache 放在**本地 NVMe 实例存储**(`/dev/nvme0n1` 挂到 `/var/lib/cats`),
  与 2026-07-21 的 i4i 基线同形态;object store 为 file adapter(同一块 NVMe),
  storage-meta 为 SQLite。跨节点那部分另用 RDS PostgreSQL + 真实 S3(见
  [`metal-cluster-20260726`](../metal-cluster-20260726/README.md))。
- 每个 Guest 都是 4 vCPU / 2 GiB / 6 GiB root 的真 microVM,fio 在 Guest 内对 ext4 root 上的
  文件跑 `--direct=1`,单 job,每点 10 s(2 s ramp)。fio 两轮(`-r2` 后缀)。
- 环境摘要 [`raw/metal-environment.txt`](raw/metal-environment.txt);实例、RDS、S3 桶、
  IAM 角色、key pair 与安全组在跑完后全部销毁。

### 本机容器(前端传输成本,次要证据)

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

**这一轮不覆盖** Cloud Hypervisor 自身与 Warm 状态对齐——那两项由下面的真机验收覆盖。
保留这一轮的价值在于:它不需要 KVM,任何开发机都能跑,而且 frontend 是 QEMU 而不是本仓库
自己写的驱动。

## 真机验收(AWS i4i.metal,真 KVM + Cloud Hypervisor)

### 生命周期验收:两条路径同分

`deploy/metal/e2e.sh` 的 23 项断言,同一台机器、同一个 Guest 镜像,只改
`CATS_BLOCK_PATH_ARGS`。原始日志 [`raw/metal-e2e-kernel-nbd.log`](raw/metal-e2e-kernel-nbd.log)、
[`raw/metal-e2e-vhost-user.log`](raw/metal-e2e-vhost-user.log)。

| 路径 | 结果 | 唯一失败项 |
|---|---|---|
| kernel-nbd(默认) | **22 passed / 1 failed** | `guest includes apt, curl and git`(golden rootfs 不再装 git,与块路径无关) |
| vhost-user | **22 passed / 1 failed** | 同上 |

vhost-user 那轮里通过的关键项:`create` 收敛 running 并给出真 kernel boot id;
Guest 内 `virtio_blk virtio0: 2/0/0 default/read/poll queues`、
`[vda] 2097152 512-byte logical blocks`;suspend/resume 保持 boot_id;
**warm(snapshot + VMM 退出)/ restore 保持 boot_id 且 `/data.txt` 存活**;
stop/start 换新 boot_id 且已 flush 数据完好;destroy 后无残留 VMM。
运行期间 `ls /sys/block/nbd*/pid | wc -l` 为 **0**——一个内核 NBD 设备都没用到。

`--ch-vhost-user-queues 4` 配合 4 vCPU 的 Cat,Guest 侧 `/sys/block/vda/mq/` 是 4 个队列;
1 vCPU 的 Cat 自动夹到 1 个队列(见下)。

### 真机暴露的一个 bug(已修)

第一次在 e2e 里跑 vhost-user 全挂:`cloud-hypervisor exited during startup: exit status: 1`,
VMM 日志是 `ParsingConfig(Validation(TooManyQueues(2, 1)))` —— **Cloud Hypervisor 校验
`num_queues ≤ boot vCPUs`**。原实现把队列数当成节点级静态配置,于是"配 2 队列的节点永远
起不了 1 vCPU 的 Cat"。修法是按每个 Cat 的 vCPU 数夹住,并保证 VMM 与后端拿到同一个值
(`ch::vhost_user_queues_for`,含单元测试)。这类问题协议级 harness 永远发现不了。

### Warm restore:块挂载从 40 ms 变 5 µs

节点代理自己打的阶段计时([`raw/metal-warm-restore-timings.log`](raw/metal-warm-restore-timings.log)):

| block_path | total | blockd 启动 | **块挂载** | VMM spawn | API ready | resume | guest health |
|---|---|---|---|---|---|---|---|
| kernel-nbd | 92.5 ms | 10.8 ms | **39.5 ms** | 0.2 ms | 25.6 ms | 1.4 ms | 15.0 ms |
| kernel-nbd | 98.7 ms | 11.1 ms | **42.2 ms** | 0.5 ms | 27.7 ms | 1.3 ms | 15.9 ms |
| vhost-user | **51.9 ms** | 10.9 ms | **0.005 ms** | 0.5 ms | 24.0 ms | 1.2 ms | 15.2 ms |

`nbd-client` 挂载 `/dev/nbdN` 要走宿主全局分配锁 + 内核块层建设备,占了 Warm restore 的
四成;vhost-user 这一步只是把 socket 路径写进 `--disk` 参数。这是本次最干净的一个收益。

### Guest 可见 fio:三种配置

原始 CSV:[`raw/metal-guest-fio-kernel-nbd.csv`](raw/metal-guest-fio-kernel-nbd.csv)、
[`-r2`](raw/metal-guest-fio-kernel-nbd-r2.csv)、
[`raw/metal-guest-fio-kernel-nbd-direct.csv`](raw/metal-guest-fio-kernel-nbd-direct.csv)、
[`raw/metal-guest-fio-vhost-user.csv`](raw/metal-guest-fio-vhost-user.csv)、
[`-r2`](raw/metal-guest-fio-vhost-user-r2.csv)。脚本
[`metal-guest-fio.sh`](metal-guest-fio.sh)。

| 负载 | kernel-nbd 缓冲(今天的默认) | kernel-nbd `direct=on` | vhost-user |
|---|---|---|---|
| 4 KiB 随机读 QD1 | 49 368 / 54 148 | 26 952 | **74 006 / 68 485** |
| 4 KiB 随机写 QD1 | **11 517 / 21 446** | 11 928 | 8 197 / 6 080 |
| 4 KiB 随机读 QD32 | 309 107 / 326 805 | 129 301 | 260 741 / 270 724 |
| 4 KiB 随机写 QD32 | **212 992 / 222 676** | 5 841 | 23 379 / 33 000 |
| 1 MiB 顺序读 | 5 280 / 4 010 MiB/s | 1 056 | 3 575 / 3 642 |
| 1 MiB 顺序写 | 1 776 / 1 734 MiB/s | 723 | 1 242 / 1 702 |
| p50 延迟(4 KiB 随机读 QD1) | 14 µs | 32 µs | **9–10 µs** |

`direct=on` 那一列是把 CH 打开 `/dev/nbdN` 的宿主 page cache 关掉后的同一条路径;它与
vhost-user 才是同一层次的对照。注意 Guest 硬件队列数:kernel-nbd 只有 1 个(CH 内置块后端
默认单队列),vhost-user 是 4 个。

### 写路径根因:flush-bound,不是前端

完整数据 [`raw/metal-flush-root-cause.txt`](raw/metal-flush-root-cause.txt)。方法是**把 Guest 写
速率对齐**(`--rate_iops=800`,20 s),这样两条路径唯一的差别只能是前端;Guest 侧计数来自
`/sys/block/vda/stat`,提交大小来自引擎新加的 `commit barrier frozen` 日志。

| | kernel-nbd 缓冲 | kernel-nbd `direct=on` | vhost-user |
|---|---|---|---|
| Guest 写次数 | 13 775 | 14 846 | 14 852 |
| Guest flush 次数 | 65 | 9 | 28 |
| **每次 flush 停顿** | 324 ms | **772 ms** | 638 ms |
| 引擎每次提交的 dirty chunk | 23.6 | **53.7** | 47.4 |
| 每次提交 pack | 94.4 MiB | 214.8 MiB | 195.6 MiB |

1. 这个负载**在任何路径上都是 flush-bound**:20 秒窗口几乎全部花在 FLUSH 停顿里。V1 提交
   整个 4 MiB chunk,所以一次 4 KiB 随机写就脏掉 4 MiB,一次提交要拷贝、哈希并写下约 200 MiB。
   实测进对象存储的写放大约 **100×**。
2. kernel-nbd 之所以"看起来快",只是因为 CH **带缓冲**打开 `/dev/nbdN`(`direct=off` 是 CH
   默认,也是节点代理今天用的形态):宿主 page cache 先吸收并合并 Guest 的写,于是提交更频繁
   但每次更便宜。关掉它(`direct=on`)后,同一条路径变成 **772 ms/flush、53.7 chunk/commit**,
   比 vhost-user 更差。
3. **所以 vhost-user 前端不是写回归的原因**,差别只在提交协议前面垫了多少易失缓冲。
4. 本次能做的修复:把 sha256 从**独占提交屏障**里移出去(屏障只保留点时刻镜像必需的拷贝),
   并把每 chunk 一次 4 MiB 分配换成整包一次分配。实测约 **5%**(638 → 627 ms/flush,
   3.37 → 3.21 ms/已提交 MiB)。剩下的都是整 chunk 拷贝 + pack 落盘 + 对象写入,只有
   **delta pack**(Direct-S3 设计 P4:只提交脏的 64 KiB 页而不是整 4 MiB chunk)能真正拿掉,
   那需要独立的 ADR 与崩溃矩阵工作,不在本次范围。

## 前端传输成本(本机容器,次要证据)

以下是在没有 KVM 的开发机上做的前端层面对照,结论以上面的真机数据为准。保留它是因为它
把传输成本单独隔离了出来,而真机数据里传输成本被提交协议掩盖。


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

## 四个优化点的验证结果(2026-07-26 追加)

把"未验证清单"里点名的优化项逐个量了一遍。两个做了并有实测收益,一个**验证为负收益不做**,
一个**验证为在当前设计下不可行**。原始输出见
[`raw/commit-cost.log`](raw/commit-cost.log)、[`raw/queue-count-versus-depth.log`](raw/queue-count-versus-depth.log)、
[`raw/concurrent-launch.log`](raw/concurrent-launch.log)。

### 1. 提交路径的拷贝与哈希并行化 —— 做了,FLUSH 快 1.6×–1.8×

先量成本结构(`blockd/tests/commit_cost.rs`,median of 3):**FLUSH 耗时与 pack 字节数严格线性**,
而 **sha256 单线程只有 546 MiB/s(≈1.83 ms/MiB),占整个提交的约 47%**。拷贝和哈希都是按 chunk
独立的,于是把屏障内的拷贝和屏障外的哈希都摊到最多 8 个线程:

| dirty chunks | pack | 串行 FLUSH | 并行 FLUSH | 倍数 |
|---|---|---|---|---|
| 8 | 32 MiB | 131.8 ms | **80.3 ms** | 1.64× |
| 16 | 64 MiB | 266.7 ms | **156.4 ms** | 1.71× |
| 32 | 128 MiB | 491.7 ms | **269.1 ms** | 1.83× |
| 48 | 192 MiB | 749.5 ms | **411.3 ms** | 1.82× |

单 chunk 的小提交走内联路径不开线程。崩溃注入矩阵(每个提交窗口)全过。这一项对**两条前端
都有效**,因为它在共享引擎里。

### 2. 节点内并发拉起 —— 做了,8 个并发从"基本串行"到 4.0–5.3×

`NodeRuntime::execute` 原来除 `ResumeCat` 外一律拿节点级 `ops: Mutex<()>`。实测(FakeVmm,
`node-agent/tests/concurrent_start.rs`):单个拉起 74 ms,8 个并发 **539 ms**,而完全串行是
592 ms —— 也就是**并发度约 1.1**。

改动:每-Cat 锁改为**无条件**持有(这同时修掉 `ResumeCat` 与 `StopCat` 之间原本可交错的隐患),
节点级锁只在真正分配节点全局资源时叠加——只有内核 NBD 路径需要(`nbd_attach` 要抢宿主锁扫
`/dev/nbdN`);vhost-user 的 socket 路径、tap 名与 /30、状态目录、metering cgroup 全部由
cat/disk id 决定,天然不冲突。并发上限用一个**独立**的 launch 门限,不复用唤醒预算的字节口径
(唤醒预算按 resume commitment 计,预算小于单个 Cat 时拒绝唤醒是对的;冷启动没有快照要读回,
不能因为同样的理由被拒)。

结果:8 个并发 **539 ms → 114–137 ms(4.0×–5.3×)**,六个并发在上限为 2 时全部排队成功、不失败。

### 3. 每队列请求并行 —— 验证为负收益,不做

同样 32 个在飞请求:**1 队列 667k ops/s、2 队列各 16 深 243k、4 队列各 8 深 211k**。单队列深排队
反而快 2.7–3.2×(一次 kick 排干整批、只发一次通知),拆队列要付每队列 kick/唤醒与跨线程争用。
真机上那个"一个 vring worker 90.9% CPU、另三个空闲"是写路径卡在提交协议,不是调度缺陷。

### 4. golden root 复用 —— 做了,创建不再上传根盘(见下一节)

当时记为「需要先做决定」:对象 key 按卷做命名空间,GC 按「没有 Root 引用」删除,所以新卷的 Map
无法引用另一个卷的 chunk。那个决定现在做了([ADR-0017](../../docs/decisions/0017-golden-root-shared-base-images.md)):
镜像放进**系统所有的 `images/` 命名空间**,而不是把用户数据对象改成全局内容寻址——后者会让
「另一个租户是否已存有这段内容」通过 PUT 是否命中变得可观测,并且把 GC 变成全局引用计数。

### 关于"中间形态 delta pack"的自我修正,以及对这个自我修正的更正

我先前提过一个"只拷脏页、不改 Map 和读路径"的中间形态,并判断它不成立——**那个判断的理由对,
结论的范围错了**。理由:屏障必须拷贝它将要上传的内容,所以不能"只拷脏页、却上传整块"。但由此
推不出"发布必须是整块":一次提交**没有携带**的页自上次提交以来未被修改,其内容已经作为不可变
对象存在于对象存储里,所以直接**只发布脏页**是安全的。必须成立的约束是「屏障拷贝的就是本次要
发布的」。ADR-0016 就是按这个约束做的,见下一节。

## Delta Pack 与 Golden Root 的实测结果(2026-07-26 追加)

上一节列的四项之外,写放大与创建成本这两个真机测量指出的根因也做了,并且**互相正交、互相放大**:
delta pack 降低**写**的发布量,golden root 降低**创建**的发布量。

### Delta Pack:一次提交只发布脏的 64 KiB 页([ADR-0016](../../docs/decisions/0016-delta-pack-page-granular-commits.md))

原始数据 [`raw/commit-cost-delta-pack.log`](raw/commit-cost-delta-pack.log)。release,aarch64 Linux
容器,median of 3,单独串行跑。48 个 dirty chunk、每 chunk 一个脏页(即 4 KiB 随机写的形态):

| | 整块发布(旧行为) | Delta Pack |
|---|---|---|
| 发布字节 | 192 MiB | **3 MiB(64× 少)** |
| FLUSH 延迟 | 412 ms(同一轮内的密集写对照) | **109 ms(3.8×)** |
| 对比 delta pack 之前记录的串行基线 749.5 ms | | **6.9×** |
| 8 个 dirty chunk | 83 ms | **30.5 ms** |
| 32 个 dirty chunk | 301 ms | **85.9 ms** |

密集写(整块脏)**故意不变**:192 MiB / 412 ms。延迟没有跟着字节数降 64×,是因为成本结构翻转
了——36 ms/发布 MiB vs 密集写的 2.15,残余是**每对象固定开销**(约 2.3 ms/对象:file store 里
一次 create + `sync_data` + hard_link,S3 上一次 PUT 往返)。下一个杠杆是**减少每次提交的对象数**,
不是继续减字节。

代价:满链 chunk 的冷读要取 5 个对象而不是 1 个,`MAX_DELTA_LAYERS = 4` 就是为此选的。

### Golden Root:创建卷改为引用共享镜像([ADR-0017](../../docs/decisions/0017-golden-root-shared-base-images.md))

原始数据 [`raw/golden-root-cost.log`](raw/golden-root-cost.log)(与 delta pack 同一平台:
release,aarch64 Linux 容器,median of 3;macOS 作为第二平台见
[`raw/golden-root-cost-macos.log`](raw/golden-root-cost-macos.log))。同一进程、同一对象存储,
唯一变量是卷如何获得 rootfs;`copy` 是**引擎层**的复制,比旧的「经 NBD socket 流式写入」更快,
所以下面的倍数是保守的。

| 单个 create | 上传字节 | 对象数 | provision 延迟 | |
|---|---|---|---|---|
| 512 MiB 镜像,复制 | 512.01 MiB | 131 | 1239.8 ms | 1.0× |
| 512 MiB 镜像,引用 | **0.02 MiB** | **3** | **7.0 ms** | **178×** |
| 256 MiB 镜像,引用 | 0.01 MiB | 3 | 7.5 ms | 108× |
| 64 MiB 镜像,引用 | 0.00 MiB | 3 | 6.5 ms | 29× |

provision 延迟与镜像大小**无关**(恒定约 7 ms):它只写 map node 与 commit record,那
0.01–0.02 MiB 就是这些 map node。

| 10 个 Cat 同时创建(256 MiB 镜像) | 上传字节 | 对象数 | 墙钟 | |
|---|---|---|---|---|
| 复制 | 2560 MiB | 670 | 5725 ms | 1.0× |
| 引用 | **0.11 MiB** | **30** | **56 ms** | **102×** |

冷读代价:空 cache 逐 chunk 读完 64 MiB,复制 446 MiB/s vs 引用 452 MiB/s——**在噪声内**
(引用侧还略快一点)。被引用的 chunk 就是一个对象,和私有 chunk 完全一样,共享在读路径上不要钱。

代价:第一次发布落在第一个用到该镜像的 launch 上(512 MiB 约 2.7 s,之后每次都是 `exists`
命中);以及 GC 必须把镜像对象视为镜像所有而不是卷所有(ADR-0017 第 8 条)。

### 组合效果

一个刚创建的 Cat 写一页,总共向对象存储写 **64 KiB**。旧行为是 512 MiB(创建)+ 4 MiB(那次写)。

### 顺带查出的两个缺陷(都已修,都有回归测试)

1. **`ChunkEngine::detach` 要等掉三分之一个租约 TTL。** golden root 的 benchmark 一开始每行都有
   一个 1674 ms 的地板,查出来是 detach 去 join 一个正在 `sleep(lease_ttl_ms / 3)` 的续期线程——
   也就是**每次 stop、suspend、冷迁移,按卷计,都白等 1.67 s**(默认 TTL)。续期改为等 condvar。
2. **8 个进程同时打开同一个新建 sqlite 元数据库,有 2 个失败**(`database is locked`):
   `PRAGMA journal_mode=WAL` 的切换不受 `busy_timeout` 保护。之前一直被"总有人先打开过"掩盖着,
   删掉节点代理里那个不再需要的元数据 handle 之后就露出来了。改为重试并把"已经是 WAL"视为成功。

## 真机复测:AWS i4i.metal + 真 KVM + 真实 S3(2026-07-27)

原始数据:[`raw/metal-golden-root-s3.log`](raw/metal-golden-root-s3.log)、
[`raw/metal-concurrent-create-ab.log`](raw/metal-concurrent-create-ab.log)、
[`raw/metal-e2e-golden-root.log`](raw/metal-e2e-golden-root.log)。

### Delta Pack 在真实 S3 上:收益比本地**小**,不是更大

原始数据 [`raw/metal-delta-pack-s3.log`](raw/metal-delta-pack-s3.log)(c6a.8xlarge,
us-east-1;这是纯 blockd benchmark,不需要 KVM,所以用便宜机型跑,同机带本地对象存储对照)。

同一轮内 dense(整块发布)→ sparse(delta pack)的 FLUSH 延迟:

| dirty chunks | 真实 S3 | 同机本地文件存储 |
|---|---|---|
| 8 | 858.9 → 374.0 ms = **2.3×** | 166.4 → 43.8 ms = 3.8× |
| 32 | 3031.5 → 1149.4 ms = **2.6×** | 1974.0 → 140.2 ms = 14.1× |
| 48 | 4913.5 → 1669.3 ms = **2.9×** | 2974.7 → 312.6 ms = 9.5× |

**这纠正了这一轮之前写下的一个猜测**(「两项改动在 S3 上应该只会更好」)。delta pack 把发布
字节降 64×,但**每次提交的对象数不变**——每个 dirty chunk 仍然一个对象——而 S3 上一个对象就是
一次 PUT 往返,于是 delta pack 没有触及的那部分固定成本占比大得多。sparse 那几行直接把它显示
出来:48 chunk 时 **556 ms/发布 MiB**,而 dense 是 25.6 ms/发布 MiB;也就是说,sparse 提交付的
是往返,不是字节。

Golden root 没有这个性质(它把对象整个去掉了,所以 S3 上 162× 反而比本地 102× 更大);
delta pack 有,而这正是 ADR-0016 已经点名的下一步最有力的论据:**把多个 chunk 的 delta 打包成
一个对象**,让提交的对象数跟着字节数一起降。

发布字节降 64× 是算术,在哪都成立;能换回多少 flush 时间取决于后端。

### Golden Root 在真实 S3 上的存储成本

每个对象都是一次真实 PUT 往返,而不是本地的 create + `sync_data` + hard_link:

| | 复制 | 引用 |
|---|---|---|
| 单个 create,512 MiB 镜像 | 15472.6 ms / 512 MiB | **89.7 ms / 0.02 MiB(172×)** |
| 10 个并发 | 27230 ms / 2560 MiB | **167.4 ms / 0.11 MiB(162×)** |

引用侧对镜像大小和并发数都**不敏感**(90–210 ms)。S3 上的倍数比本地更大,因为复制侧每 4 MiB
对象要付一次 PUT 往返。

### 端到端:同一台机器、同一个 S3、同一个 VMM,10 个并发冷创建

唯一的变量是二进制:`复制` 是本分支的父提交(有 delta pack、无 golden root)。

| | 墙钟 | 失败的操作 |
|---|---|---|
| 复制 rootfs(父提交) | 121.4 s | **4** |
| 引用共享镜像(本分支) | **61.6 s** | **0** |

复制那一行复现了 2026-07-26 记录的 128 s(不同机器、不同日期),两个数字互相印证。复制路径
**10 个里失败了 4 个**:每个 Cat 各传 512 MiB、传十遍,会把 launch 顶过它自己的超时——真机日志里
看到的就是提交 286 MiB 的过程中租约续不上(`lease renewal failed; fencing writes`)。

单个 create:节点上第一个 Cat 6.9 s(顺带发布镜像),第二个 **4.5 s**,Guest 从引用的 chunk
正常起来(`/dev/vda 2.0G 279M used`、`/usr/bin` 411 个可执行文件、真实 ext4)。

**剩下的 61.6 s 不是存储**:十个 create 的存储部分合计 167 ms。墙钟是一条约 6 s/个的斜坡
(min 8.2 s、p50 28 s、max 61.6 s),看起来是完全串行的;换成 kernel-nbd 路径是 60.4 s,几乎一样,
所以也不是块路径(`launch_allocates_node_global_state` 只在 kernel-nbd 下加节点全局锁)。
**golden root 拿掉了并发创建的存储成本,剩下的是节点代理之上的某个队列**,那是下一个要量的东西。

### 验收未回退

`deploy/metal/e2e.sh` 走 vhost-user + 真实 S3:**22 passed / 1 failed**,唯一失败仍是 PR #8 就
记录过的陈旧断言(golden rootfs 里没有 `git`),与块路径和本次改动无关。

桶里最后的样子:`images/` 74 个对象 / 306 MB —— 512 MiB rootfs 去掉全零 chunk 后的**唯一一份**,
被这一轮创建的 43 个卷共同引用。

### 真机顺带查出的一个设计错误(已修)

第一版接线让 `cats-blockd --seed-image` 在 **attach 之后**发布镜像,也就是握着卷租约做一次 8 秒的
512 MiB 上传。节点代理配的租约 TTL 是 1.5 s,于是租约丢了、launch 失败:

```
INFO  attached volume=vol_f11ad38fc6d3 epoch=1 generation=0
ERROR lease renewal failed; fencing writes: lease epoch is stale or expired
Error: seed volume from image /opt/cats/guest/rootfs.ext4
       provision from base image: attachment is fenced; refusing writes
```

发布根本不需要租约(它只写 `images/` 命名空间,不属于任何卷),所以现在发布在 attach 之前;
更进一步,发布是**全队列一次性**的工作,不该落在某次 launch 上,于是拆成
`cats-blockd --publish-image`(发布并打印 image id)与 `--seed-image-id`(按 id provision,
成本是一次 manifest GET 加一次 map 写),节点代理每个节点发布一次。

## 仍未验证 / 后续项

1. **减少每次提交的对象数**:delta pack 之后 FLUSH 的残余是每对象约 2.3 ms 的固定开销,
   把多个 chunk 的 delta 打进一个对象是下一个杠杆。
2. **delta 链的冷读放大**:满链 chunk 冷读取 5 个对象,链长分布与跨节点冷迁移的实际影响
   还没在真机上单独量过。
3. **镜像预发布**:第一个用到某镜像的 launch 现在要付一次发布代价(512 MiB 约 3 s);在镜像
   部署时预发布可以去掉这一次。
4. **GC**:仍未实现。delta pack 要求把 base 与全部 delta 都视为存活,golden root 要求把镜像
   对象视为镜像所有,两者都必须在实现 GC 时落到代码里。
5. **多队列在真实 vCPU 数下的收益曲线**:本次只验了 1 和 4 两个点,而且已知队列多不等于更快。
6. **长时间 soak 与多 Cat 同机压力**:本次每个场景都是单样本,不构成 SLA。
7. **`nbd` 内核模块依赖的移除**:`install.sh` 仍无条件 `modprobe nbd`,以便随时切回默认路径。
8. **把多次 chunk 的 delta 合并成一个对象**:真实 S3 上 delta pack 只有 2.3–2.9×(本地
   3.8–14×),差别全在「对象数没降」上,见上面那一节。这是目前证据最强的下一个杠杆。
9. **并发拉起的天花板应该由实测饱和点决定**,而不是沿用 wake 的那个常量。

## 复现

真机部分:在 `i4i.metal` 上 `sudo deploy/metal/install.sh`,把 `/etc/cats/cats.env` 的
`CATS_BLOCK_PATH_ARGS` 在空(kernel-nbd)与 `--ch-block-path vhost-user --ch-vhost-user-queues 4`
之间切换,每次 `systemctl restart cats-noded` 后跑 `deploy/metal/e2e.sh` 与
`experiments/vhost-user-blk-frontend-20260726/metal-guest-fio.sh <label>`。

本机部分:

```bash
# 协议级验收 + 进程内前端成本（不需要 KVM / root；macOS 上自动进容器）
experiments/vhost-user-blk-frontend-20260726/run.sh

# 真实 Guest：QEMU/TCG 当 frontend，真实内核驱动 + 真实 ext4（不需要 KVM）
experiments/vhost-user-blk-frontend-20260726/qemu-guest-smoke.sh

# 真实内核 NBD 链路对照（需要 nbd 模块、nbd-client、fio 与 privileged 容器）
experiments/vhost-user-blk-frontend-20260726/kernel-nbd-baseline.sh
```

环境摘要写入 [`raw/environment.txt`](raw/environment.txt)。
