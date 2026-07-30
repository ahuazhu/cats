# Relaxed vhost-user 多样本 soak 与 kernel-NBD A/B（2026-07-30）

## 结论

**本轮不翻转 production `metal-1`，继续使用 kernel-NBD；但不能把下面的
P99 差异归因给 vhost-user。**

vhost-user 的正确性、真实 KVM 生命周期和并发能力已经通过。最初记录的
Guest-visible local fsync 数字是：

| block path | 样本 | P50 | P95 | P99 | Max | `> 4 ms` |
|---|---:|---:|---:|---:|---:|---:|
| vhost-user | 1,000 | 1.111 ms | 1.616 ms | **70.137 ms** | **128.403 ms** | 13 |
| kernel-NBD (`direct=off`) | 1,000 | 1.219 ms | 1.391 ms | **2.112 ms** | **3.063 ms** | 0 |

这组 A/B 后来被判定为**有混杂，不能用于前端归因**。runner 把约 14 GiB 的
Cargo target、源码和工具链写在与 Cats state 相同的 ext4/NVMe 上；vhost-user
总是在这些构建和多次失败尝试之后先跑，kernel-NBD 则约 19 分钟后才跑。
当时内核仍报告约 4.7 GiB Dirty，顺序也没有 ABBA 或随机化。因此“其余条件相同、
只改变块前端”不成立，70.137 ms 对 2.112 ms 不能作为 production 翻转判据。

默认值保持不变，是因为 ADR-0015 原有的公平吞吐权衡和多样本翻转门仍未被一轮
有效的 end-to-end ABBA 关闭，不是因为已经证明 vhost-user 有 70 ms P99。

## 环境和测量边界

- Host：AWS `c5d.metal`（`metal-1`），96 vCPU；本轮不是 `i4i.metal`。
- Cats state：`/dev/nvme3n1` 上的 ext4，`rw,noatime`。
- durable backend：真实 S3 + RDS PostgreSQL。
- VMM：真实 KVM + Cloud Hypervisor；Guest 是未修改 ext4。
- 节点同时承载 6 个 production Cats；隔离实验使用独立 state/socket、S3 prefix
  和 PostgreSQL volume rows，没有注册到 production fleet。
- production Cats 全程保持 kernel-NBD，未 drain、未重启、未翻转。

表中的时间不是生产 SLA：

- **Local FLUSH / local fsync**：Guest 进程 `pwrite(4 KiB)` 后调用 `fsync`，计时只取
  `fsync`；Relaxed 成功边界是本地 pack 已 fsync，水位 `L` 前进。
- **Remote drain**：先产生一个 local generation，再通过 blockd control socket
  强制 publish，直到 `R == L`；包含 S3 object PUT 和 PostgreSQL CAS。
- **Published**：remote generation 已前进，Host 永久丢失后仍能从对象存储和 metadata
  恢复；不是“后台线程已经开始上传”。

## vhost-user 长 run

原始证据在
[`results/full-phases-before-socket-cleanup/`](results/full-phases-before-socket-cleanup/)。
该 run 完成全部性能和单 Cat 生命周期样本，在第一个并发 Cat 进入 Warm 后因检查到
陈旧 blockd control socket 而失败；这个资源清理缺口随后修复，并由聚焦 run 完成剩余路径。

### Local fsync 与 remote drain

| 边界 | 样本 | P50 | P95 | P99 | Max |
|---|---:|---:|---:|---:|---:|
| Guest local fsync | 1,000 | 1.111 ms | 1.616 ms | 70.137 ms | 128.403 ms |
| Guest write + fsync | 1,000 | 1.116 ms | 1.656 ms | 70.161 ms | 128.424 ms |
| Remote drain | 300 | 284.044 ms | 418.145 ms | 542.706 ms | 727.768 ms |

前两行保留为该次 vhost-user run 的观测值；它们不是 production SLA，也不能与后跑的
kernel-NBD 行组成因果 A/B。

Remote drain 没有 timer race；300 次中 4 次超过 500 ms。这直接解释了为什么
node-agent 原来把 `status` 与 `drain` 共用 500 ms socket deadline 会让 Warm
偶发返回 `EAGAIN`。修复后 `status` 仍为 500 ms，forced drain 单独为 30 s，
低于 control plane 的 60 s node-job timeout。

burst 期间最大 backlog 为 1,986 generations / 20,549,995 bytes，最老 1,199 ms；
没有 backpressure，也没有 publish error。这个数字只描述该 workload。

### 生命周期

CSV 的 duration 是相应成对操作的总耗时。

| 操作 | 样本 | P50 | P95 | P99 / Max | 正确性 oracle |
|---|---:|---:|---:|---:|---|
| Suspend + Resume | 50 | 3.534 s | 4.356 s | 4.963 s | boot ID 保持、canary 保持 |
| Warm + Restore | 30 | 0.844 s | 1.032 s | 1.416 s | boot ID 保持、canary 保持 |
| Cold stop + fresh start | 10 | 10.519 s | 11.422 s | 11.422 s | boot ID 改变、canary 保持 |

本轮 steady Cold 是约 10–11 s，不支持“当前最少 34 s”的说法。34 s 是另一轮不同
边界/状态的观测，不能当作这个实现的固有下限。

## vhost-user 聚焦完成 run

原始证据在
[`results/focused-completion/`](results/focused-completion/)，正式结果见
[`summary.json`](results/focused-completion/summary.json)。配置为 20 local、
10 drain、2 Suspend、2 Warm、2 Cold 和 8 个并发 Cats；exit status 0。

- 8-Cat cold launch：wall 10.469 s；per-Cat P50 9.783 s，Max 10.468 s。
- 8-Cat Warm concurrent restore：wall 430 ms；per-Cat P50 359 ms，Max 430 ms。
- 当前 run 的所有 Cloud Hypervisor 命令行都必须包含 run-scoped
  `vhost_user=on,socket=...`，并且不得包含 `/dev/nbd`。
- active NBD 在 before / single launch / 8-Cat launch 三个观测点都只是 production
  的 `nbd0..4`。
- 每个并发 Cat 进入 Warm 后，短 NBD/vhost/control socket 和可读 symlink 均已删除；
  随后的并发 restore 保持 boot ID 与 canary。

## kernel-NBD 对照

原始证据在 [`results/kernel-nbd-ab/`](results/kernel-nbd-ab/)，正式结果见
[`summary.json`](results/kernel-nbd-ab/summary.json)。配置为 1,000 local、
20 drain、各 1 次生命周期和 1 个并发 Cat；exit status 0。

该对照的 local fsync 1,000/1,000 都小于 4 ms，但它发生在 vhost-user run 约
19 分钟之后。两次 run 之间的构建写入、Dirty/writeback、试验顺序和设备状态没有
被控制，因此它只能证明“这一次 kernel-NBD run 很平”，不能回答“切换前端会让
用户 fsync 怎样”。

## P99/Max root-cause 复查

后续在同一节点做了 20 个 Guest fsync 的 `strace -ff -yy -T` 聚焦 run。它确认：

- 慢时间实际消耗在 Host ext4 对 pending pack 的持久化，不在
  vhost-user queue notification、EVENT_IDX 或 S3/PostgreSQL；
- 每个 pack 的顺序是 `fdatasync(.tmp-pack) → rename → fsync(pending dir)`；
- benchmark Cat 的 224 个 pack barrier 中，file `fdatasync` 的
  P50/P95/P99/Max 为 21.640/31.896/57.829/110.094 ms，目录 `fsync` 为
  14.134/24.994/27.959/30.019 ms，rename P99 只有 0.103 ms；
- 慢窗口中一次 Guest fsync 常对应连续两个 engine FLUSH generation：一个包含
  Guest/ext4 的其他脏数据，另一个包含 4 KiB benchmark 写。两套 file+directory
  barrier 足以组成 70–128 ms 的 Guest-visible 尾部。

这解释了“时间花在哪里”，但不证明“为什么只有先跑的 vhost-user run 遇到这个
设备状态”。真正的系统性风险是多 Cat、构建产物、pending journal 与其他 Host
写入共享一个 ext4/NVMe，当前没有 per-Cat I/O 隔离；file-per-generation 的两次
持久性 barrier 则是可优化的实现细节。

本 PR 的 runner 已把 source/Cargo target/toolchain 移到另一文件系统，强制
build 与 Cats state 的 mount source 不同，并在 benchmark 前 `sync` + settle，
记录 Dirty/Writeback。最终翻转仍需要独立执行器按 ABBA 或随机顺序交替前端、固定
缓存冷热状态、监控设备队列/利用率，并把 target 放在被测 NVMe 之外。

## 本轮发现并修复的问题

1. **Relaxed 冷块局部写的 cache completeness 错误**：publisher 在私有内存中合并
   remote base 与 overlay 后，曾错误地把稀疏 cache 标为 fully hydrated；另有
   freeze 到 journal 之间的读竞争窗口。修复为显式 `freezing` gate 和
   `cache_present`，并增加确定性回归测试。这个是实现状态机错误，不是
   Direct-S3/local-first 边界本身错误，但影响字节正确性，必须按 P0 对待。
2. **forced drain 误用 500 ms status deadline**：真实 P99 已超过 500 ms，Warm
   因此被误判失败。拆分为 500 ms status 与 30 s drain，并用 750 ms 延迟响应测试锁住。
3. **Warm 遗留 blockd sockets**：blockd 已退出但短 socket 与 symlink 未统一清理。
   teardown、CH Warm 和 FakeVmm Warm 现在走同一个 socket 清理逻辑。
4. **测试夹具的全局归属错误**：长 Unix symlink 超过 `SUN_LEN`，以及比较整台 Host
   的 NBD 集合会被其他隔离实验误伤。夹具现在解析短 socket target，并按本 run 的
   Cloud Hypervisor 命令行验证实际块路径。

结构性风险仍是 ADR-0022 已明确接受的部分：`R < L` 时唯一权威副本只在一个 Host，
Host 永久丢失会丢失实时 backlog。异步化隔离了普通 S3/DB 抖动与 Guest fsync，
但没有把单 Host local journal 变成多副本日志。

## 质量门和证据完整性

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- metal runner 先执行所有 `cats-blockd relaxed` 测试和 node-agent Relaxed lifecycle
  测试，再进入真实 Guest。
- 三个结果目录的 `SHA256SUMS` 均已在下载后通过 `sha256sum -c`。

最终源码归档 SHA-256：
`ad986c38459037e37697810537f2ca841c7dfacdb07ba08223189d047a73f889`。
