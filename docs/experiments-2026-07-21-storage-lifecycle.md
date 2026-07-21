# 2026-07-21 Cats 存储与生命周期实验总报告

本文汇总本轮关于 Cats 系统盘、对象存储、Lazy Load、Warm/Cold 唤醒和资源回收的实验方法、代码、原始结果与结论。

报告中的 AWS 性能数据均在 2026-07-21 采集。Lazy ext4 的正式基线还引用了 2026-07-17 和 2026-07-20 已保存的验证结果，并补充了本轮重新运行的 4 GiB / 10,000 文件结果。所有性能数字都从仓库内 CSV 重新计算；样本数较小时，表中的 P95 实际等于观测最大值，不能当成生产 P95。

## 1. 最终结论

这轮实验回答了六个核心问题。

1. **100 GiB 虚拟盘不需要整体上传。** ext4 可以保持完全不修改。块后端只上传发生过有效写入的逻辑 Chunk。100 GiB / 100,000 小文件实验最终只映射 521 个 1 MiB 逻辑 Chunk，内容寻址后只存了 475 MiB 对象数据。
2. **本地 NVMe 可以作为对象存储真相源前面的稀疏读写缓存。** 删除整个本地缓存后，NBD 后端能按 ext4 读请求从远端 Chunk 懒加载，文件树摘要保持一致。
3. **Warm 有两种可用机制。** `pause + page-out` 唤醒约 0.21–0.23 秒，暂停态物理内存约 6.9–17.3 MiB，但 VMM 仍存在；`snapshot + VMM exit` 在本地 NVMe 上唤醒约 0.38–0.40 秒，暂停态 VMM/后端进程和专属 RSS 均为 0。
4. **远端存储介质决定并发 Warm 的上限。** 10 个 512 MiB Cat 同时从 EBS 恢复时，首次健康响应 P50 为 19.05 秒；从 i4i 本地 NVMe 恢复时为 0.53 秒。两者的 VMM restore API 都约 25–26 ms，因此主要瓶颈是内存页回读，不是 Cloud Hypervisor。
5. **原始 20–21 秒 Cold 主要慢在 Ubuntu 启动策略。** `systemd-networkd-wait-online` 单项占 13.406 秒。通过直接内核启动、精简 initramfs、提前配置网络和提前启动 Agent，完整新内核、新进程的 Cold-to-health P50 降到 1.755 秒。
6. **Direct-S3 原型证明了语义，但性能不能直接用于生产。** 当前单线程 Python/boto3 后端 Cold P50 为 39.87 秒，其中累计 S3 GET 时间约 18.91 秒。生产版必须实现并行请求、合并读取、预取、热 Chunk 固定、可靠提交和本地缓存。

因此，当前推荐的产品组合是：

```text
Running
  ├── 短时间休眠：pause + page-out
  │     优点：最快唤醒；约 6.9–17.3 MiB/Cat 暂停态物理内存
  │
  ├── 更深 Warm：snapshot + VMM/backend exit
  │     优点：无常驻 VMM；进程状态保留；本地 NVMe 唤醒约 0.4 秒
  │
  └── Cold：新内核 + 新 Agent/用户进程
        优点：不依赖内存快照兼容性；目标约 1–2 秒

系统盘/持久盘
  Guest ext4 -> virtio-blk -> vhost-user-blk -> cats-blockd
      -> 本地 NVMe 稀疏 Cache
      -> Manifest + immutable chunks -> S3/JuiceFS durable store
```

## 2. 实验范围与术语

本报告严格区分下面几条路径：

| 名称 | Guest 内核/进程是否延续 | VMM 是否退出 | 暂停态数据位置 | 本轮测量边界 |
|---|---|---|---|---|
| Pause + page-out | 延续 | 否 | Guest RAM backing file 在本地 NVMe，物理页被回收 | 发起 resume 到健康 HTTP |
| Snapshot Warm | 延续 | 是 | VM 状态和 RAM snapshot 在 EBS 或本地 NVMe | 重建网络/后端/VMM、restore、resume 到健康 HTTP |
| Cold | 不延续 | 每次新建 | root disk；不使用旧内存状态 | Host 发起启动到新 Guest 进程健康 HTTP |
| Direct-S3 Cold | 不延续 | 每次新建 | S3 Manifest + immutable Chunk，本地缓存初始为空 | Host 发起启动到健康 HTTP，并单测持久化 FLUSH |
| Lazy ext4 | 文件系统状态延续 | 不涉及 VM | 对象 Chunk 是提交真相，本地 Cache 可全部删除 | ext4 文件树写入、提交、删缓存、重挂载、摘要校验 |

正确性判据也不同：

- Warm/page-out 要求 `boot_id_preserved=true`，证明原来的内存中 UUID 和进程状态仍在。
- Cold/Direct-S3 要求 `boot_id_changed=true`，证明不是误把内存恢复当成 Cold。
- Lazy ext4 要求删除缓存前后的文件树 digest 完全相同，并且冷读产生远端对象下载。

## 3. 实验环境

| 环境 | 存储 | 用途 | 重要限制 |
|---|---|---|---|
| macOS Docker Desktop / LinuxKit | Container tmpfs + 本地 JuiceFS 测试挂载 | Lazy ext4、Crash consistency、10 万小文件 | 不能暴露嵌套 `/dev/kvm`，所以不测 microVM 唤醒 |
| AWS `c5.metal` | 2 TiB EBS，Linux 中显示为 NVMe 设备 | Snapshot Warm 基线、EBS 尺寸矩阵和并发唤醒 | 不是本地 instance-store NVMe |
| AWS `i4i.metal` | 本地 instance-store NVMe | Snapshot Warm、并发、page-out、Cold、Direct-S3 | 单 Host；尚未测空缓存跨 Host 迁移 |

共同的 VM 配置：

- Cloud Hypervisor v53，KVM，2 个 Guest vCPU。
- Ubuntu 22.04.5 ext4 root；Cold 实验使用 Ubuntu `5.15.0-185-generic` 内核。
- root disk 由 Cloud Hypervisor 自带的 `vhost_user_block` 参考后端导出。
- Guest 测试服务生成一个内存 UUID，并实际触碰指定大小的匿名内存 working set。
- Host 通过 Guest HTTP 健康接口读取 UUID 和启动阶段时间戳。

为了尽量形成冷读，Snapshot 测试对内存快照执行 `POSIX_FADV_DONTNEED`，Cold 测试对 root/seed 文件做同类处理。这是 Linux 的 advisory 接口，能形成较强的冷 Host page-cache 近似，但不能证明下层设备的所有缓存都为空。

## 4. 代码和职责

### 4.1 稀疏 ext4 / ChunkStore

| 文件 | 作用 |
|---|---|
| [`lazy-ext4-demo/demo.sh`](../experiments/lazy-ext4-demo/demo.sh) | 创建稀疏虚拟盘、NBD、ext4、小文件，提交后删 Cache，再次挂载并校验 |
| [`lazy-ext4-demo/production_demo.sh`](../experiments/lazy-ext4-demo/production_demo.sh) | 使用真实 JuiceFS mount，验证 FLUSH、HEAD 原子发布和两个 Crash 窗口 |
| [`lazy-ext4-demo/chunkstore.py`](../experiments/lazy-ext4-demo/chunkstore.py) | 本地 Cache、dirty 状态、immutable object、Manifest 和 HEAD 的核心状态机 |
| [`lazy-ext4-demo/lazy_chunk_plugin.py`](../experiments/lazy-ext4-demo/lazy_chunk_plugin.py) | 把 ChunkStore 暴露成 nbdkit Python block backend |
| [`lazy-ext4-demo/chunkctl.py`](../experiments/lazy-ext4-demo/chunkctl.py) | 初始化、提交、清缓存、查看状态和一致性检查 |
| [`lazy-ext4-demo/test_chunkstore.py`](../experiments/lazy-ext4-demo/test_chunkstore.py) | ChunkStore 单元测试 |

### 4.2 VM 生命周期和 Direct-S3

| 文件 | 作用 |
|---|---|
| [`benchmark.sh`](../experiments/warm-snapshot-benchmark/benchmark.sh) | 准备 Cloud Hypervisor/Guest；运行 snapshot、VMM exit、on-demand restore 基准；采集 Guest 时间线 |
| [`concurrent.sh`](../experiments/warm-snapshot-benchmark/concurrent.sh) | 为每个 Cat 创建独立资源，通过严格 barrier 同时释放唤醒请求 |
| [`lifecycle_modes.sh`](../experiments/warm-snapshot-benchmark/lifecycle_modes.sh) | 运行完整 Cold 和 pause + file-backed RAM page-out 两种模式 |
| [`process_madvise_file.py`](../experiments/warm-snapshot-benchmark/process_madvise_file.py) | 用 `process_madvise(MADV_PAGEOUT/POPULATE_READ)` 回收或预取 VMM 的 file-backed Guest RAM |
| [`runtime_exec.py`](../experiments/warm-snapshot-benchmark/runtime_exec.py) | 在分配 Guest RAM 前把 VMM/后端加入 cgroup，使用 `memory.current` 测物理占用 |
| [`build_minimal_initramfs.sh`](../experiments/warm-snapshot-benchmark/build_minimal_initramfs.sh) | 从 Ubuntu initrd 构建仅含 BusyBox、ext4、virtio block/net 的实验 initramfs |
| [`minimal-init`](../experiments/warm-snapshot-benchmark/minimal-init) | 挂载 root、配置固定实验网络并 `switch_root` 的最小 init |
| [`direct_s3_benchmark.sh`](../experiments/warm-snapshot-benchmark/direct_s3_benchmark.sh) | 发布稀疏 root 到 S3，清空 Cache，运行 Direct-S3 Cold 和 durable FLUSH 测试 |
| [`s3_chunk_plugin.py`](../experiments/warm-snapshot-benchmark/s3_chunk_plugin.py) | 单线程 nbdkit Direct-S3 后端；实现读、写、dirty Cache、Manifest commit 和统计 |
| [`s3_chunkctl.py`](../experiments/warm-snapshot-benchmark/s3_chunkctl.py) | 初始化 S3 Manifest/Chunk，管理本地 Direct-S3 状态 |

## 5. 实验一：10 万小文件是否会上传整块盘

### 5.1 验证架构

```text
10 万个普通文件
      │ POSIX read/write
      ▼
未修改的 ext4
      │ 4 KiB block I/O
      ▼
/dev/nbdN
      │ READ / WRITE / FLUSH
      ▼
nbdkit ChunkStore
      ├── cache/<logical-index>.chunk        本地 NVMe Cache
      ├── dirty/<logical-index>.dirty        脏 Chunk 标记
      ├── objects/<sha256>.chunk             不可变内容对象
      ├── manifests/generation-N.json        逻辑 Chunk -> object 的映射
      └── HEAD.json                          当前已提交 generation
```

ChunkStore 管理的是**虚拟块地址空间**，不是 ext4 文件。ext4 的 inode、目录项、journal 和文件内容最终都只是某些逻辑块范围内的数据。一个 Chunk 只要没有被写过，就不出现在 Manifest 中，读取时直接返回全零；因此物理盘上所谓“洞很多”不会导致扫描或上传全部 100 GiB。

### 5.2 方法

1. 创建 4 GiB 或 100 GiB 的稀疏逻辑块设备。
2. 通过 NBD 把它暴露成真实 Linux block device。
3. 直接在设备上 `mkfs.ext4` 并正常挂载，不修改 ext4。
4. 创建 10,000 或 100,000 个小文件。
5. unmount/FLUSH，将 dirty Chunk 内容寻址后写入对象目录，生成新 Manifest 和 HEAD。
6. 删除全部本地 Cache。
7. 仅凭 Manifest 和对象重新启动 NBD，read-only 挂载 ext4。
8. 重新遍历文件树，比较 digest，并统计冷读下载的对象字节。

本轮 4 MiB Chunk 的直接复现命令：

```bash
docker run --rm --privileged \
  --tmpfs /state:exec,size=4g \
  -e VIRTUAL_SIZE_GB=4 \
  -e CHUNK_SIZE_MB=4 \
  -e FILE_COUNT=10000 \
  catdev/lazy-ext4-demo:local
```

### 5.3 结果

| 用例 | 虚拟容量/逻辑 Chunk | 映射逻辑 Chunk | 远端对象数据 | 删除 Cache 后实际下载 | 结果 |
|---|---:|---:|---:|---:|---|
| 4 GiB / 10,000 文件，1 MiB Chunk | 4,096 | 60 | 60 MiB | 49 MiB | PASS |
| 100 GiB / 100,000 文件，1 MiB Chunk | 102,400 | 521 | 475 MiB | 428 MiB | PASS |
| 本轮 4 GiB / 10,000 文件，4 MiB Chunk | 1,024 | 23 | 96,468,992 B | 62,914,560 B | PASS |

100 GiB 用例中，521 个逻辑位置只对应 475 个物理对象，因为 46 个完全相同的 Chunk 被 SHA-256 内容寻址复用。

本轮 4 MiB 用例的关键原始统计：

```text
mapped_chunk_count=23/1024
object_bytes=96468992/4294967296
cache_misses=15
object_bytes_downloaded=62914560
tree_digest_before == tree_digest_after
```

### 5.4 Production-shaped JuiceFS 验证

`production_demo.sh` 进一步把 durable directory 放到了真实 JuiceFS 1.4.0 mount 上：

```text
ext4 -> NBD -> ChunkStore
              ├── /state/nvme              本地 Cache/dirty
              └── /mnt/juicefs/volumes/... Manifest/HEAD/objects
                    ├── SQLite metadata     仅本实验
                    └── file object backend S3 的本地替代
```

4 GiB / 10,000 文件多次运行结果：

- HEAD 最终引用 22–23 个 4 MiB Chunk，即 88–92 MiB。
- 删除 block Cache 和 JuiceFS client Cache 后，文件树冷遍历只下载 14–15 个 Chunk，即 56–60 MiB。
- strict ext4 FLUSH 在删 Cache 前发布了 9 个远端 generation。
- Crash before HEAD：新 objects/Manifest 已存在，但旧 generation 仍可见。
- Crash after HEAD：新 generation 可见；重试只清 dirty marker，不重复创建 generation。
- 每个 HEAD 引用对象都存在、长度正确、SHA-256 与对象名一致。

### 5.5 能得出的结论

- 小文件在 Guest 中是否分散，不决定上传整个虚拟盘；决定上传量的是它们最终触碰了多少**逻辑 Chunk**。
- 这个映射不是“把 NVMe 的物理块一一映射到 JuiceFS Chunk”，而是把 Guest 看到的逻辑块地址范围映射成后端 Chunk。
- ext4 不需要支持 JuiceFS lazy load。ext4 只看到正常块设备，Lazy Load 在 NBD/vhost-user block backend 中完成。
- 这组实验验证了架构语义，没有验证多写者 lease/fencing、S3 故障、吞吐、GC、加密或生产元数据服务。

详细基线和限制见 [`lazy-ext4-demo/README.md`](../experiments/lazy-ext4-demo/README.md)。

## 6. 实验二：EBS 上的 Snapshot + VMM exit

### 6.1 方法

每轮执行：

```text
Guest healthy + touched working set
  -> pause vCPU
  -> snapshot VM memory/device state
  -> Cloud Hypervisor exit
  -> vhost-user block backend exit
  -> 删除 tap
  -> POSIX_FADV_DONTNEED(snapshot)
  -> 重建 tap 和 block backend
  -> 启动新 Cloud Hypervisor
  -> userfaultfd on-demand restore
  -> resume
  -> 第一个健康 HTTP
  -> 触碰应用 working set
  -> 等待所有 Guest RAM background-prefault 完成
```

同一个内存 UUID 必须在每轮 restore 后保持不变。Cloud Hypervisor v53 在 background prefault 结束前会拒绝再次 snapshot，所以 runner 明确等待 `UFFD handler: prefault done`。

### 6.2 c5.metal / 1 GiB 基线

配置为 1,024 MiB Guest RAM、128 MiB working set、5 轮。

| 指标 | P50 | P95/最大值 |
|---|---:|---:|
| Pause | 4.383 ms | 4.816 ms |
| Snapshot | 682.215 ms | 724.862 ms |
| VMM/backend/tap shutdown | 175.907 ms | 207.528 ms |
| 重建 network/backend | 16.986 ms | 38.173 ms |
| VMM start 到 restore API ready | 25.342 ms | 25.686 ms |
| Resume API | 3.398 ms | 4.386 ms |
| Wake 到健康 HTTP | 1,089.992 ms | 1,889.294 ms |
| 128 MiB working set 回读 | 4,514.614 ms | 4,527.516 ms |
| 1 GiB RAM 全部 resident | 8,032.562 ms | 8,034.769 ms |

正确性：UUID 保持 5/5。Warm 期间 Cloud Hypervisor 和 block backend 都已退出，专属 runtime RSS 为 0 KiB。snapshot 的 apparent size 约 1 GiB，首次 allocated 约 838 MiB，后续在全部页面 resident 后接近 1 GiB。

### 6.3 EBS 尺寸矩阵

| RAM / working set | 样本 | Snapshot P50 | 健康 P50 / 最大值 | working set P50 / 最大值 | 全 RAM P50 / 最大值 | UUID 保持 |
|---|---:|---:|---:|---:|---:|---:|
| 512 / 64 MiB | 10 | 347 ms | 1.82 / 2.78 s | 3.48 / 7.14 s | 6.08 / 10.90 s | 10/10 |
| 1,024 / 128 MiB | 5 | 682 ms | 1.09 / 1.89 s | 4.51 / 4.53 s | 8.03 / 8.03 s | 5/5 |
| 2,048 / 256 MiB | 10 | 1.40 s | 1.19 / 2.08 s | 5.72 / 7.57 s | 16.51 / 18.30 s | 10/10 |

Snapshot 时间和全 RAM resident 时间大体随 Guest RAM 增长；VMM restore control path 保持约 25 ms。

### 6.4 EBS 同时唤醒

每个 worker 有独立 VM、tap、block backend、root disk 和 snapshot。所有 worker 先完成 snapshot/exit 和 cache eviction，再在同一个 barrier 上等待，最后在 3–9 ms 内同时开始唤醒。

| 同时 Cat 数 | 起始时间散布 | Restore API P50/最大 | 健康 P50/最大 | 64 MiB 回读 P50/最大 | 512 MiB 全 resident P50/最大 | UUID 保持 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | — | 25.31/25.56 ms | 1.82/2.78 s | 3.48/7.14 s | 6.08/10.90 s | 10/10 |
| 2 | 3.24 ms | 25.37/25.39 ms | 2.43/2.48 s | 7.82/8.24 s | 11.70/12.13 s | 2/2 |
| 5 | 7.44 ms | 25.84/26.17 ms | 7.20/7.85 s | 15.66/19.43 s | 24.58/27.59 s | 5/5 |
| 10 | 9.21 ms | 26.11/45.81 ms | 19.05/23.26 s | 50.34/57.46 s | 74.42/77.78 s | 10/10 |

早期的 10-worker runner 使用 15 秒健康超时，只完成 5/10。把超时提高后，严格 barrier 测试完成 10/10，证明其余 VM 是慢，不是 restore 失败。

### 6.5 结论

- Snapshot + VMM exit 的正确性成立，并能把 Warm 期间 VMM/后端进程占用降为零。
- 并发变大时 VMM API 仍约 25 ms，而健康和全 RAM 回读急剧变慢，瓶颈是 EBS page-in 数据面。
- 生产必须有 wake admission controller；demand fault 要优先于 background prefault；需要记录或学习 boot/runtime 热页集合。

原始资料：

- [`c5.metal 基线报告`](../experiments/warm-snapshot-benchmark/results/c5-metal-ebs-20260721/README.md)
- [`EBS 尺寸与并发报告`](../experiments/warm-snapshot-benchmark/results/ebs-followup-20260721/README.md)

## 7. 实验三：i4i.metal 本地 NVMe Snapshot Warm

### 7.1 单 Cat 尺寸矩阵

每个规格 10 轮，实验流程和正确性判据与 EBS 完全相同。

| RAM / working set | Snapshot P50 | 健康 P50 / P95 | working set P50 / P95 | 全 RAM resident P50 / P95 | UUID 保持 |
|---|---:|---:|---:|---:|---:|
| 512 / 64 MiB | 284.182 ms | 379.760 / 385.518 ms | 978.237 / 1,151.467 ms | 1.587 / 1.817 s | 10/10 |
| 1,024 / 128 MiB | 558.027 ms | 381.745 / 445.509 ms | 1,017.997 / 1,055.838 ms | 1.802 / 1.858 s | 10/10 |
| 2,048 / 256 MiB | 1,104.815 ms | 398.733 / 452.517 ms | 1,081.851 / 1,657.248 ms | 3.094 / 3.624 s | 10/10 |

首次健康响应只需要少量热页，因此 512 MiB 到 2 GiB 的 P50 仅从 380 ms 增至 399 ms；全内存 resident 时间则随内存大小增长。

### 7.2 本地 NVMe 同时唤醒

| 同时 Cat 数 | 起始时间散布 | Restore API P50/最大 | 健康 P50/最大 | 64 MiB 回读 P50/最大 | 512 MiB 全 resident P50/最大 | UUID 保持 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | — | 约 24–32 ms | 0.380/0.386 s | 0.978/1.151 s | 1.587/1.817 s | 10/10 |
| 2 | 5.63 ms | 25.87/27.49 ms | 0.413/0.423 s | 1.277/1.286 s | 1.994/2.012 s | 2/2 |
| 5 | 3.70 ms | 30.68/32.68 ms | 0.505/0.555 s | 1.441/1.770 s | 2.256/2.515 s | 5/5 |
| 10 | 6.71 ms | 24.79/28.84 ms | 0.530/0.632 s | 1.869/2.221 s | 2.715/3.083 s | 10/10 |

### 7.3 EBS 与本地 NVMe 的直接对比

| 512 MiB 用例 | EBS P50 | Local NVMe P50 | 改善 |
|---|---:|---:|---:|
| 单 Cat 健康 | 1.816 s | 0.380 s | 4.8× |
| 单 Cat 64 MiB 回读 | 3.485 s | 0.978 s | 3.6× |
| 单 Cat 512 MiB 全 resident | 6.080 s | 1.587 s | 3.8× |
| 10 Cat 健康 | 19.052 s | 0.530 s | 35.9× |
| 10 Cat 全 resident | 74.420 s | 2.715 s | 27.4× |

这证明本地 NVMe 对低延迟 Warm 不是普通优化，而是关键数据面。对象存储/EBS 仍可作 durable truth，但不能让大量 Guest 直接、无限并发地从远端逐页恢复。

原始 CSV 位于 [`i4i-local-nvme-20260721/raw/`](../experiments/warm-snapshot-benchmark/results/i4i-local-nvme-20260721/raw/)。

## 8. 实验四：Pause + file-backed RAM page-out

### 8.1 方法

1. Cloud Hypervisor 使用本地 NVMe 上的 file-backed Guest RAM。
2. Guest working set 初始化完毕后 pause vCPU。
3. 通过 `process_madvise(MADV_PAGEOUT)` 回收 VMM 映射对应的物理页。
4. 以 cgroup `memory.current` 测暂停态真实物理内存，而不是把多个进程的 shared mapping RSS 相加。
5. resume 后等待原进程的健康 HTTP 和 working-set touch。
6. UUID 必须保持不变。

### 8.2 结果

| RAM / working set | 轮数 | Wake P50 / P95 | Page-out P50 / P95 | 暂停态物理内存 P50 | 回收比例 P50 | UUID 保持 |
|---|---:|---:|---:|---:|---:|---:|
| 512 / 64 MiB | 10 | 231.300 / 236.427 ms | 255.328 / 359.623 ms | 6.941 MiB | 98.508% | 10/10 |
| 1,024 / 128 MiB | 10 | 212.966 / 220.153 ms | 325.293 / 577.972 ms | 11.635 MiB | 98.086% | 10/10 |
| 2,048 / 256 MiB | 10 | 212.411 / 221.484 ms | 399.638 / 1,065.636 ms | 17.336 MiB | 97.706% | 10/10 |

补充 working-set touch P50 分别为 90.645 ms、214.137 ms 和 354.469 ms。

### 8.3 结论

- pause 立即停止 vCPU 调度，因此 Guest CPU 已回收。
- page-out 后绝大多数 Guest RAM 物理页已回收，但 VMM、backend、页表、socket、控制结构和少量热页仍存在，所以不是 0 MiB。
- 这种模式比 VMM exit 快约 150–180 ms，适合作为最浅层 Warm。
- 它不能直接跨 Host；Host 维护、迁移和版本不兼容时仍需要 snapshot 或 Cold fallback。

## 9. 实验五：完整 Cold 为什么是 20 秒

### 9.1 Stock Ubuntu 结果

每一轮都关闭旧 VMM/后端，丢弃 root/seed Host page cache，启动新内核和新 Python 服务。进程 UUID 每轮必须变化。

| RAM / working set | 轮数 | Cold-to-health P50 | P95/最大 | 新 UUID |
|---|---:|---:|---:|---:|
| 512 / 64 MiB | 5 | 20,699.818 ms | 21,256.304 ms | 5/5 |
| 1,024 / 128 MiB | 5 | 21,064.079 ms | 21,196.074 ms | 5/5 |
| 2,048 / 256 MiB | 5 | 21,009.167 ms | 21,140.033 ms | 5/5 |

RAM/working set 增加 4 倍，但 Cold 基本不变，说明应用内存不是主要瓶颈。

### 9.2 代表性 Guest 时间线

| Guest boot 时间 | 事件 | 解释 |
|---:|---|---|
| 2.988 s | ext4 root mounted | generic kernel + generic initramfs |
| 3.672 s | cloud-init local starts | 网络前阶段 |
| 4.175 s | networkd wait-online starts | 主瓶颈开始 |
| 17.579 s | networkd wait-online ends | 单项耗时 13.406 s |
| 17.581–17.962 s | cloud-init network | 约 381 ms，不是 14 秒主因 |
| 17.977 s | 测试 service unit starts | 之前一直未进入应用路径 |
| 18.210 s | Python process entry | 新用户进程开始 |
| 18.376 s | 128 MiB working set ready | 初始化耗时 166.751 ms |
| 18.456 s | Guest 收到 health | Guest 已可用 |
| 20.404 s Host time | Host 收到 health | 含 Guest 时钟前的 handoff |

在 health 时，snapd、LXD、cloud-config、cloud-final 仍在运行。这些工作不需要阻塞 Agent 可用，却存在于通用 cloud image 的启动事务里。

## 10. 实验六：Cold 优化 A/B

所有变体都是 1,024 MiB RAM / 128 MiB working set，且每轮启动新内核和新进程。

| 变体 | 轮数 | Cold P50 | 最大值 | Guest 进程入口 P50 | 改动 |
|---|---:|---:|---:|---:|---|
| Stock Ubuntu profile | 3 | 21,360.511 ms | 21,397.246 ms | 18,784.681 ms | firmware、generic initramfs、cloud-init、network-online |
| Early service | 3 | 6,397.428 ms | 6,401.346 ms | 4,216.549 ms | Agent 不再等待 cloud-init/network-online |
| Direct Ubuntu kernel | 3 | 5,326.212 ms | 5,334.610 ms | 4,291.452 ms | 绕开 firmware/bootloader 路径 |
| 1.19 MiB minimal initramfs | 5 | 3,216.171 ms | 3,262.737 ms | 1,708.392 ms | 仅 BusyBox、virtio-blk、ext4、switch_root |
| Minimal init + early network | 5 | **1,754.872 ms** | **1,867.523 ms** | **1,185.045 ms** | initramfs 内加载 virtio-net、固定 IP，最早启动 Agent |

最终 5 次 Cold 为：

```text
1.725 s, 1.753 s, 1.755 s, 1.854 s, 1.868 s
```

相对同规格 stock P50，时间从 21.064 秒降至 1.755 秒，缩短约 91.7%，快约 12 倍。

### 10.1 这一轮舍弃了什么

从**唤醒关键路径**中移除了：

- 通用 firmware/bootloader 链路。
- 33 MiB 通用 initramfs 中与此固定硬件模型无关的模块和探测。
- `systemd-networkd-wait-online`。
- cloud-init、snapd、LXD、SSH key generation、package timer 等非 Agent-ready 必需任务。
- “整个 Ubuntu boot transaction 完成才算可用”的错误 readiness 定义。

没有舍弃的能力：

- 新 Linux 内核启动。
- 未修改的 Ubuntu ext4 root。
- systemd 在 `switch_root` 后继续正常启动。
- virtio block 和 virtio network。
- Python Agent 进程和真实 128 MiB 内存初始化。

因此这不是 BusyBox-only 的假操作系统，也不是内存 snapshot restore。它可以继续运行正常 Agent 服务。但当前脚本硬编码了 root 设备和静态 IP，只能视为启动路径原型；生产需要 Rust PID 1/Guest Agent、配置注入、失败恢复、安全模块、度量启动和兼容性管理。

## 11. 实验七：Direct-S3 ChunkStore

### 11.1 架构

```text
S3 HEAD/Manifest + immutable 4 MiB objects
                    │ boto3 GET/PUT
                    ▼
          nbdkit Python plugin
           ├── clean cache Chunk
           └── dirty Chunk + commit
                    │ NBD
                    ▼
              /dev/nbd2
                    │
                    ▼
             vhost-user-blk
                    │ virtio-blk
                    ▼
          未修改的 Guest ext4
```

发布阶段把 4 GiB raw root 中非零/有效映射的部分转成对象：

- 450 个 4 MiB 对象。
- 1,887,436,800 B，约 1.758 GiB。
- 不上传整个 4 GiB。
- 本次发布约 10.55 秒。

正式运行每轮清空本地 Chunk Cache，从 S3 冷启动 Guest；Guest 产生写入后执行 durable barrier 并校验 dirty 数清零、远端 generation 前进。

### 11.2 结果

| 指标 | P50 | 最大值 |
|---|---:|---:|
| Cold-to-health | 39.868 s | 40.959 s |
| 下载对象数据 | 696,254,464 B（664 MiB） | 704,643,072 B（672 MiB） |
| 累计 S3 GET 时间 | 18.914 s | 19.635 s |
| Guest sync | 703.964 ms | 1,350.808 ms |
| Durable S3 flush | 2,126.812 ms | 2,318.606 ms |
| S3 PUT 数据 | 67,175,512 B（64.064 MiB） | 75,564,339 B（72.064 MiB） |
| 本次 commit dirty Chunk | 19 | 21 |

新进程 UUID：3/3。最终 dirty Chunk：0。

### 11.3 发现并修复的持久化问题

第一次 smoke test 使用 `blockdev --flushbufs`，观察到 Guest 看似 sync 完成，但 NBD 后端没有收到足以提交 dirty Chunk 的 FLUSH。保留的失败现场仍有 dirty 文件。

修正后的 durable barrier 是对 block device 本身执行 `fsync(/dev/nbd2)`。修正后每轮都观察到：

```text
dirty chunks > 0
  -> fsync(/dev/nbd2)
  -> PUT immutable objects
  -> publish new manifest/HEAD
  -> dirty chunks = 0
```

这个问题说明生产协议不能把“Guest 发过 sync”直接等价为“对象存储 HEAD 已提交”。`cats-blockd` 需要清晰定义 Guest FLUSH、Host cache、remote commit 和确认返回之间的 durability contract。

### 11.4 结论

- Direct-S3 可把普通 ext4 建立在 Manifest + immutable objects 上，读写和远端提交语义成立。
- 当前性能差是实现形态造成的：所有 NBD 请求被单线程串行化，每次 miss 下载完整 4 MiB，缺少并行 GET、request coalescing、read-ahead 和 hot-set。
- 39.87 秒不能作为架构的最终性能，也不能当作生产版本结果；它是一个正确性/瓶颈定位原型。

详细结果见 [`i4i lifecycle 报告`](../experiments/warm-snapshot-benchmark/results/i4i-lifecycle-modes-20260721/README.md)。

## 12. 跨实验总表

下面选择 1 GiB/128 MiB 或最接近的代表配置。不同模式保存的状态不同，数字不能只按快慢排序。

| 模式 | 数据介质 | 状态语义 | 首次健康 P50 | 休眠物理资源 | 跨 Host 潜力 |
|---|---|---|---:|---|---|
| Pause + page-out | i4i Local NVMe | 原进程继续 | 0.213 s | VMM 保留；约 11.635 MiB cgroup memory | 低，需额外迁移机制 |
| Snapshot + VMM exit | i4i Local NVMe | 原进程继续 | 0.382 s | VMM/backend 退出；snapshot 占本地盘 | 中，需搬运/远端化 snapshot |
| Snapshot + VMM exit | EBS | 原进程继续 | 1.090 s | VMM/backend 退出；snapshot 在 EBS | 较高，但并发页回读慢 |
| 优化 Cold | i4i Local NVMe | 新内核、新进程 | 1.755 s | 无 VM RAM/VMM | 高，前提是 root 热 Chunk 可快速获得 |
| Stock Cold | i4i Local NVMe | 新内核、新进程 | 21.064 s | 无 VM RAM/VMM | 高，但启动策略不可接受 |
| Direct-S3 原型 Cold | S3，无初始 Cache | 新内核、新进程 | 39.868 s | 无本地 durable 依赖 | 高；当前实现仅验证语义 |

## 13. 对 Cats 完整架构的建议

### 13.1 存储层

实现一个通用的 `cats-blockd`，对上提供 vhost-user-blk，对下提供：

```text
                 logical block requests
Guest ext4 -> virtio-blk -> cats-blockd
                              ├── NVMe clean cache
                              ├── NVMe dirty/WAL or equivalent durable journal
                              ├── chunk map + immutable generation manifest
                              ├── uploader / downloader / prefetcher
                              └── S3/JuiceFS durable object store
```

关键要求：

- Guest 只看到普通 block device，JuiceFS/S3 对用户完全不可见。
- 以逻辑 Chunk 追踪 dirty，不扫描/上传整块虚拟盘。
- immutable object + 原子 Manifest/HEAD publication。
- 明确 FLUSH/FUA 的 durable acknowledgement 边界。
- 单写者 RWO lease、fencing token 和故障接管；外挂持久盘同一时间只挂一个 Cat。
- 并行、合并和取消读取；优先 demand read，限速 background prefetch。
- 本地 Cache 可全部删除，空 Host 能仅凭远端 metadata/object 恢复。
- 热目录、boot Chunk、Agent binary 和必要 ext4 metadata 可形成预取 Manifest。

JuiceFS 仍可作为已有的对象/元数据能力底座；Direct-S3 则能减少一层文件系统抽象。最终选择不能只看这轮原型速度，要比较 crash consistency、metadata/lease、运维复杂度、S3 请求放大和二次开发成本。

### 13.2 生命周期层

建议三层状态机：

```text
ACTIVE
  │ idle 短
  ▼
WARM_PAGEOUT        VMM 存在，内存页大部分回收，~0.2 s wake
  │ idle 更久/Host 压力
  ▼
WARM_SNAPSHOT       VMM 退出，进程状态在 snapshot，~0.4 s local-NVMe wake
  │ snapshot 不兼容/迁移/更久 idle
  ▼
COLD                新内核、新 Agent/用户进程，目标 1–2 s
```

并且分别发布四个 readiness：

1. VMM API ready。
2. Guest Agent ready。
3. `cats exec` ready。
4. 用户 Service ready。

任何 Warm restore 失败都必须回退到 Cold，而不是让 Cat 卡在不可恢复状态。

### 13.3 唤醒调度

- 每 Host 根据 NVMe/S3 实测带宽限制同时 page-in 的 Cat 数。
- demand fault 高优先级；full-RAM background prefault 低优先级。
- 先加载 Guest Agent、网络栈、页表和应用热页，再 resume vCPU。
- 对象存储 Cold 使用并发 GET、合并相邻读、适应性 read-ahead 和 Host 共享 Cache。
- 记录 wake 的分阶段时间，不能只上报一个总时延。

## 14. 本轮没有验证的事项

以下内容仍不能基于本轮实验作生产承诺：

- 在另一台空 NVMe Host 上从对象存储恢复优化 Cold 的 1–2 秒结果。
- VM memory snapshot 上传对象存储、跨 Host 兼容和增量快照。
- 100/1,000 个 Cat 的 page-out、snapshot 和 Cold wake storm。
- `cats-blockd` 生产 Rust 实现及 io_uring/multi-queue 性能。
- S3 网络抖动、限流、超时、部分 PUT、HEAD 冲突、Host power loss 的故障注入。
- RWO lease/fencing、多 Host attach/detach、强制接管和 split-brain 防护。
- Chunk GC、引用计数、加密、密钥轮换、租户隔离和审计。
- 长时间随机读写、ext4 journal 压力、TRIM/discard、在线扩容和 fsck。
- 真实 Agent/代码仓库 workload 的 P50/P95/P99；当前服务是 Python + 固定内存 working set。

## 15. 下一轮建议

按优先级建议：

1. 用 Rust 实现最小 `cats-blockd`，保留同一套 NBD/vhost-user correctness oracle，增加并行 GET、singleflight、range/read-ahead 和可配置 Chunk size。
2. 在第二台 i4i.metal 或清空当前 NVMe 的隔离目录中测试“远端只有 S3，Host Cache 为空”的优化 Cold，分离 Agent-ready 与用户 Service-ready。
3. 对 10/50/100 个 Cat 测 page-out、Snapshot Warm 和 optimized Cold，同步记录 NVMe queue、CPU、major fault、S3 请求与流量。
4. 实现 hot-Chunk Manifest：先预取 kernel/init/root metadata/Agent，验证是否能把远端 Cold 控制在 2 秒附近。
5. 为 FLUSH/commit 做 kill -9、断网、失败 PUT、HEAD 并发更新和重启恢复测试。
6. 加入单写者 lease/fencing，完成可选持久盘的 attach/detach/reattach E2E。
7. 换成实际 Agent workload：git clone、10 万小文件、grep/build、服务端口恢复和持久写入。

## 16. 复现实验

### 16.1 Lazy ext4

```bash
cd experiments/lazy-ext4-demo
make test
make demo
make demo-100g
make production-demo
```

需要 Docker `--privileged`，因为容器要使用 Linux NBD 和 ext4 kernel driver。

### 16.2 Snapshot Warm

```bash
sudo ./experiments/warm-snapshot-benchmark/benchmark.sh prepare

sudo WORK_DIR=/mnt/local/cats-warm-bench \
  MEMORY_MIB=1024 WORKSET_MIB=128 ITERATIONS=10 \
  ./experiments/warm-snapshot-benchmark/benchmark.sh run
```

### 16.3 同时唤醒

```bash
sudo ASSET_DIR=/mnt/local/cats-warm-bench \
  BASE_WORK_DIR=/mnt/local/cats-warm-concurrent \
  CAT_COUNT=10 MEMORY_MIB=512 WORKSET_MIB=64 \
  ./experiments/warm-snapshot-benchmark/concurrent.sh
```

### 16.4 Cold 和 page-out

```bash
sudo WORK_DIR=/mnt/local/cats-cold \
  MEMORY_MIB=1024 WORKSET_MIB=128 ITERATIONS=5 \
  ./experiments/warm-snapshot-benchmark/lifecycle_modes.sh cold

sudo WORK_DIR=/mnt/local/cats-pageout \
  MEMORY_MIB=1024 WORKSET_MIB=128 ITERATIONS=10 \
  ./experiments/warm-snapshot-benchmark/lifecycle_modes.sh pageout
```

### 16.5 Minimal initramfs

```bash
sudo apt-get install -y busybox-static cpio zstd
sudo ./experiments/warm-snapshot-benchmark/build_minimal_initramfs.sh \
  /path/to/ubuntu-initrd.img \
  /path/to/cats-minimal-initrd.img
```

### 16.6 Direct-S3

```bash
sudo WORK_DIR=/mnt/local/cats-direct-s3 \
  S3_BUCKET=<test-bucket> S3_PREFIX=<isolated-prefix> \
  ./experiments/warm-snapshot-benchmark/direct_s3_benchmark.sh prepare-remote

sudo WORK_DIR=/mnt/local/cats-direct-s3 \
  S3_BUCKET=<test-bucket> S3_PREFIX=<isolated-prefix> \
  MEMORY_MIB=512 WORKSET_MIB=64 ITERATIONS=3 \
  ./experiments/warm-snapshot-benchmark/direct_s3_benchmark.sh run
```

这些 VM 实验必须在 Linux x86_64、root、`/dev/kvm` 可用的 Host 上运行；macOS Docker Desktop 不能替代 KVM 真机。

## 17. 原始结果索引

- Lazy ext4 方法、历史观测和限制：[`experiments/lazy-ext4-demo/README.md`](../experiments/lazy-ext4-demo/README.md)
- c5.metal EBS 正式基线：[`results/c5-metal-ebs-20260721/`](../experiments/warm-snapshot-benchmark/results/c5-metal-ebs-20260721/)
- EBS 尺寸/并发跟进：[`results/ebs-followup-20260721/`](../experiments/warm-snapshot-benchmark/results/ebs-followup-20260721/)
- i4i Local NVMe Warm 报告：[`results/i4i-local-nvme-20260721/README.md`](../experiments/warm-snapshot-benchmark/results/i4i-local-nvme-20260721/README.md)
- i4i Local NVMe Warm 原始 CSV/log：[`results/i4i-local-nvme-20260721/raw/`](../experiments/warm-snapshot-benchmark/results/i4i-local-nvme-20260721/raw/)
- i4i Cold/page-out/Direct-S3 报告：[`results/i4i-lifecycle-modes-20260721/README.md`](../experiments/warm-snapshot-benchmark/results/i4i-lifecycle-modes-20260721/README.md)
- i4i Cold/page-out/Direct-S3 原始 CSV/profile/log：[`results/i4i-lifecycle-modes-20260721/raw/`](../experiments/warm-snapshot-benchmark/results/i4i-lifecycle-modes-20260721/raw/)

AWS `i4i.metal` 测试实例 `i-06e2118acba45b9fe` 已于 2026-07-21 执行强制终止并确认进入 `terminated`。Local NVMe 随实例终止不可恢复；正式 CSV、JSON profile 和日志已经回收到本仓库。报告中不记录 Console 密码、SSO token、Access Key 或其他登录凭据。
