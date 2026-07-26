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

## 仍未验证 / 后续项

真机验收已覆盖四态生命周期与 Warm 状态对齐,剩下的是:

1. **写吞吐的真正修复**:delta pack(只提交脏的 64 KiB 页而不是整 4 MiB chunk,Direct-S3
   设计 P4)。这是"按当前部署形态 NBD 写更快"的唯一根治办法,需要独立 ADR + 崩溃矩阵。
2. **每队列请求并行**:后端目前每个 virtqueue 由单个 worker 线程串行处理。实测单 job Guest
   负载下一个 vring worker 90.9% CPU 打满、另外三个空闲
   ([`raw/metal-backend-cpu-during-qd32-write.txt`](raw/metal-backend-cpu-during-qd32-write.txt))。
   在当前 flush-bound 的负载里它不是瓶颈,但读多的负载会碰到。
3. **多队列在真实 vCPU 数下的收益曲线**:本次只验了 1 和 4 两个点。
4. **长时间 soak 与多 Cat 同机压力**:本次每个场景都是单样本,不构成 SLA。
5. **`nbd` 内核模块依赖的移除**:`install.sh` 仍无条件 `modprobe nbd`,以便随时切回默认路径。

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
