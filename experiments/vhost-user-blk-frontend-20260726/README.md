# vhost-user-blk 前端验收与前端成本测量（2026-07-26）

本目录保存 `cats-blockd` 原生 vhost-user-blk 前端（[ADR-0015](../../docs/decisions/0015-vhost-user-blk-production-block-frontend.md)、
[blockd 协议 §7.1](../../docs/specs/blockd-protocol.md)）的**协议级验收**证据，以及三条块传输路径的
**前端成本**测量。

## 结论摘要

1. 协议级验收 **10/10 通过**，外加 1 项针对真实 `cats-blockd` 二进制的双前端集成测试通过。
   正确性判据是「Guest 路径与 oracle 路径看到同一批字节」：每个写入都用 NBD 前端从同一个
   engine 读回比对（规范 §7 指定 NBD 为 oracle）。
2. 1 MiB 顺序 I/O 吞吐提升最大：读 **2.3–2.5×**、写 **2.0×**，p50 延迟从 ~244/220 µs 降到
   ~101/100 µs。payload 不再穿过 socket 是主要原因。
3. 4 路并发 4 KiB 随机 I/O：读 **1.13×**、写 **1.24–1.27×**，p99 同时下降。
4. 单路 QD1 4 KiB：本 harness 下**没有提升**（0.80–0.92×）。原因不在后端：把驱动侧的
   `poll(2)`+线程唤醒换成短自旋后，同一后端同一负载变成 **2.3×**（读 99.9k vs NBD 43.4k ops/s）、
   **2.1×**（写），p50 从 25 µs 降到 8–9 µs。真实 Guest 由 VMM 注入中断完成通知，不付 harness 这笔开销。
5. 单队列排队深度 1→32：34.3k → 222.5k ops/s（869 MiB/s）。同步 NBD 客户端无法表达这种并行度。
6. FLUSH 提交路径两条前端落在同一区间（控制项），证明前端只做协议适配、没有改动提交协议。
7. **未做**：真实 Cloud Hypervisor + KVM 下的 Guest 启动、ext4/fio 负载与 Warm
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
  避免测到首次取块。表内给出均值、中位数与极值范围。
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

## 性能测量

### 进程内前端对比（5 次重复，均值）

原始数据 [`raw/frontend-cost.csv`](raw/frontend-cost.csv)，控制台输出 [`raw/frontend-cost.log`](raw/frontend-cost.log)。

| 负载 | 线程/队列 | nbd ops/s | vhost-user ops/s | 倍数 | nbd p50/p99 µs | vhu p50/p99 µs |
|---|---|---|---|---|---|---|
| 4 KiB 随机读 | 1 | 43 426 | 37 064 | 0.85× | 20 / 95 | 24 / 85 |
| 4 KiB 随机写 | 1 | 36 462 | 33 384 | 0.92× | 20 / 132 | 25 / 112 |
| 4 KiB 随机读 | 4 | 71 390 | 81 022 | **1.13×** | 49 / 178 | 43 / 128 |
| 4 KiB 随机写 | 4 | 55 513 | 70 624 | **1.27×** | 52 / 335 | 42 / 312 |
| 1 MiB 顺序读 | 1 | 3 585（3.6 GiB/s） | 8 815（8.8 GiB/s） | **2.46×** | 244 / 509 | 101 / 210 |
| 1 MiB 顺序写 | 1 | 4 086（4.1 GiB/s） | 8 329（8.3 GiB/s） | **2.04×** | 220 / 481 | 100 / 284 |
| 4 KiB 写 + FLUSH（控制项） | 1 | 48 | 42 | 0.87× | 20 688 / 24 194 | 25 216 / 31 080 |

中位数口径：0.80× / 0.87× / 1.14× / 1.24× / 2.29× / 1.98× / 0.83×。极值范围：

- 4 KiB 随机读 t1：nbd 41.3–45.5k，vhu 31.8–48.6k（vhu 方差明显更大，见下）
- 1 MiB 顺序读：nbd 3.1–3.8k，vhu 8.3–9.4k（区间不重叠）
- FLUSH：nbd 47–49，vhu 38–48（区间重叠；每次提交 ~20–25 ms，由提交协议和 overlayfs
  的 fdatasync 主导，前端选择在其中不可见）

### QD1 4 KiB 为什么没有提升

驱动侧每完成一个请求要 `poll(2)` 一次并被唤醒一次；NBD 客户端只需一次阻塞 `read`。
把 harness 的等待方式换成短自旋（`raw/notification-cost.log`）：

| 负载 | 驱动等待 | ops/s | p50 µs |
|---|---|---|---|
| 4 KiB 随机读 | poll | 35 222 | 25 |
| 4 KiB 随机读 | spin | **99 947** | **9** |
| 4 KiB 随机写 | poll | 31 878 | 25 |
| 4 KiB 随机写 | spin | **75 983** | **8** |

即后端在 QD1 下能做到 ~100k ops/s（对 NBD 的 43.4k 为 2.3×），差距完全来自 harness 的
通知方式。真实 Guest 的完成通知由 VMM 注入中断，不经过 `poll(2)`+用户态线程唤醒。
这也是为什么本报告把 QD1 的 0.85× 记为**harness 伪影**而不是后端退化——但也不把
spin 数字当作可交付的 Guest 性能。

### 单队列排队深度（vhost-user，4 KiB 随机读）

[`raw/queue-depth.log`](raw/queue-depth.log)：

| QD | 1 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|
| ops/s | 34 268 | 88 864 | 127 466 | 184 694 | 222 461 |
| MiB/s | 134 | 347 | 498 | 722 | 869 |

同步 NBD 客户端无法表达这一维度（每次只能有一个请求在飞），所以这里没有对照列；
真实内核 NBD client 会做流水线，其 QD32 数字见下一节。

### 真实 Phase A 宿主链路（fio + O_DIRECT + `/dev/nbd0`）

原始数据 [`raw/kernel-nbd-fio.csv`](raw/kernel-nbd-fio.csv)，每点 10 s（2 s ramp），fio JSON 保存在
`raw/fio-*.json`。这是 `--ch-block-path kernel-nbd` 在宿主侧的真实链路。

| 负载 | QD | IOPS / 吞吐 | p50 µs | p99 µs |
|---|---|---|---|---|
| 4 KiB 随机读 | 1 | 20 191（78.9 MiB/s） | 39 | 126 |
| 4 KiB 随机写 | 1 | 20 531（80.2 MiB/s） | 37 | 127 |
| 4 KiB 随机读 | 32 | 154 998（605 MiB/s） | 196 | 416 |
| 4 KiB 随机写 | 32 | 181 498（709 MiB/s） | 161 | 383 |
| 1 MiB 顺序读 | 1 | 2 297（2.3 GiB/s） | 403 | 668 |
| 1 MiB 顺序写 | 1 | 2 651（2.7 GiB/s） | 179 | 285 |

两点结论：

1. **内核 NBD 跳本身很贵。** 同一个 engine、同一个 NBD 前端，进程内客户端 QD1 4 KiB 随机读
   43.4k ops/s，经 `/dev/nbd0` 只有 20.2k——即上一节那个「乐观基线」把 NBD 的成本低估了
   约 2.1×。1 MiB 顺序读同理：3.6 GiB/s → 2.3 GiB/s。
2. **对真实 Phase A 链路，vhost-user 的提升区间**（vhost-user 数字取自上两节）：

   | 负载 | kernel-nbd（真实链路） | vhost-user（poll 等待） | vhost-user（spin 等待） |
   |---|---|---|---|
   | 4 KiB 随机读 QD1 | 20 191 | 37 064（1.8×） | 99 947（5.0×） |
   | 4 KiB 随机写 QD1 | 20 531 | 33 384（1.6×） | 75 983（3.7×） |
   | 4 KiB 随机读 QD32（单队列） | 154 998 | 222 461（1.4×） | — |
   | 1 MiB 顺序读 QD1 | 2.3 GiB/s | 8.8 GiB/s（3.8×） | — |
   | 1 MiB 顺序写 QD1 | 2.7 GiB/s | 8.3 GiB/s（3.1×） | — |

**这张表不是 Guest 可见性能。** fio 侧含宿主内核块层，vhost-user 侧两端都没有内核块层
（真实 Guest 自己有一层）；两边的通知机制也都不是 VMM 注入中断。可以确定的是：被去掉的
那一跳（内核 NBD client + 每请求 socket 往返 + payload 复制）在同一台机器上值
1.4×–5×，且大块 I/O 收益最确定。真实数字要靠裸金属验收。

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

# 真实内核 NBD 链路对照（需要 nbd 模块、nbd-client、fio 与 privileged 容器）
experiments/vhost-user-blk-frontend-20260726/kernel-nbd-baseline.sh
```

环境摘要写入 [`raw/environment.txt`](raw/environment.txt)。
