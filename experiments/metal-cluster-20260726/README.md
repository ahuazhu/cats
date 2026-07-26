# 双节点裸金属:跨节点 Cold 迁移与并发拉起能力(2026-07-26)

本目录保存两台 AWS `i4i.metal` 组成的双节点集群上的两项验证:**跨节点 Cold 迁移**,以及
**并发拉起能力**(单机与集群)。块路径用的是新的 vhost-user-blk 前端
([ADR-0015](../../docs/decisions/0015-vhost-user-blk-production-block-frontend.md)),所以这里
同时也是它在共享 S3 + PostgreSQL 形态下的证据。

## 结论摘要

1. **跨节点 Cold 迁移 12/12 通过,4.4 秒**。Cat 在 metal-1 上写入并 flush,stop 成 Cold,
   cordon metal-1 后 start,调度器落到 metal-2,**目标节点本地缓存为空**,数据全部经
   Direct-S3 懒读回来,boot_id 换新,已提交数据逐字节完好。
2. **并发 Warm restore 是可用的:单机 10 个并发 2.1 秒完成**(p50 1.07 s,全部成功)。这是
   ADR-0002 §8 的准入门在真机上第一次被压。
3. **并发 cold create 是当前的瓶颈:单机 10 个并发 p50 63.5 秒**,且有 1 个超过 CLI 的
   120 秒等待。根因不是节点级串行,而是**每个 Cat 都要把 512 MiB golden root 播种后上传
   S3**:同一负载把 object store 换成本地 file adapter 后 p50 降到 12.2 秒、收敛 24.3 秒、
   零失败(**5.3×**)。
4. **加第二个节点没有让 cold create 变快**(10 个 create 拆到两台:收敛 140 s vs 单机 128 s)。
   这一条**不足以下结论**——上一批 20 个 Cat 的销毁可能与它重叠。要判定集群是否线性扩容,
   需要一轮干净的重跑。
5. 这些都是**单样本**,不是 SLA。绝对值只在同机同配置下可比。

## 环境

- 2 × AWS `i4i.metal`(`us-east-1`,Ubuntu 24.04,Linux `6.17.0-1019-aws`,128 vCPU /
  1 007 GiB RAM,`/dev/kvm`),Cloud Hypervisor `v53.0`。
- 每台把一块**本地 NVMe 实例存储**挂在 `/var/lib/cats` 作为 ChunkStore cache。
- **共享层**(跨节点迁移的前提):真实 S3 桶作 durable object store(经 EC2 instance profile
  取凭证,节点上没有长期密钥),**RDS PostgreSQL 18.3**(`db.m5.large`,`sslmode=require` +
  RDS CA)作 storage-meta 的 root/lease CAS。SQLite 与 file adapter 是每台主机私有的,
  **根本无法迁移**,所以集群形态必须换掉它们。
- 控制面与网关只在 metal-1 上;两台各跑一个节点代理(`metal-1` / `metal-2`)。
- 块路径:`--ch-block-path vhost-user --ch-vhost-user-queues 4`。
- 跑完后实例、RDS、S3 桶、IAM 角色、key pair 与安全组全部销毁。

为了让这套形态能配出来,本次顺带修了部署侧三个现存缺口:systemd unit 把 `--node-id` 和监听
地址写死(README 说支持多节点但配不出来)、`e2e.sh` 没带 CLI 需要的 bearer token、
`install.sh` 缺 `libssl-dev`。

## 1. 跨节点 Cold 迁移

脚本 [`cold-migration.sh`](cold-migration.sh),日志 [`raw/cold-migration.log`](raw/cold-migration.log)。

流程:cordon metal-2 → 在 metal-1 上 create → 写 `/migrated.txt` 并 `sync` → uncordon →
`stop`(Cold)→ **cordon metal-1** → `start` → 断言落到 metal-2 → 校验数据与 boot_id →
在新节点上再写一次并 flush。

12 项断言全部通过,其中关键的四项:

| 断言 | 结果 |
|---|---|
| 迁移到目标节点 | `node=metal-2` |
| Cold 迁移是全新启动 | boot_id 与源节点不同 |
| 已提交数据跨节点存活 | `/migrated.txt` 内容一致 |
| 目标节点可继续写并 flush | 追加内容可读回 |

**耗时 4 379 ms**(单样本),这是"目标节点本地缓存为空、全部走 S3 懒读 + PostgreSQL root CAS"
的冷启动代价。

## 2. 并发拉起能力

脚本 [`concurrent-start.sh`](concurrent-start.sh)。三个阶段:并发 cold create → 全部 warm
(snapshot + VMM 退出)→ 并发 warm restore。每个阶段都等舰队真正收敛到目标状态才算结束
(CLI 的单操作等待会在饱和时先超时,拿它当阶段结束会得到无意义的数字)。

日志:[`raw/concurrent-single-10.log`](raw/concurrent-single-10.log)、
[`raw/concurrent-cluster-20.log`](raw/concurrent-cluster-20.log)、
[`raw/concurrent-scaling.log`](raw/concurrent-scaling.log)。

### 单机 10 个(S3 durable 层)

| 阶段 | 完成 | min | p50 | p95 | max | 失败 | 批次墙钟 |
|---|---|---|---|---|---|---|---|
| cold create | 10 | 12.7 s | 63.1 s | 120.0 s | 120.0 s | 1 | 120.1 s |
| warm | 10 | 16.4 s | 16.7 s | 17.1 s | 17.1 s | 0 | 17.1 s |
| **warm restore** | 10 | **0.31 s** | **1.07 s** | **2.12 s** | **2.12 s** | **0** | **2.1 s** |

并发 warm restore 表现良好——这正是 ADR-0002 §8 准入门放开并发的那条路径
(`NodeRuntime::execute` 里只有 `ResumeCat` 走每-Cat 锁)。

### cold create 的瓶颈:S3 播种

同样 10 个并发 create,只换 object store:

| object store | p50 | 收敛 | 失败 |
|---|---|---|---|
| 真实 S3 | 63.5 s | 128 s | 1 |
| 本地 file adapter(同一块 NVMe) | **12.2 s** | **24.3 s** | **0** |

file adapter 下收敛 24.3 s ≈ 10 × 单个 create 2.4 s,与"节点级 `ops: Mutex<()>` 严格串行"
的预期吻合,没有额外争用。换成 S3 后多出的 5.3× 来自每个 Cat 播种 512 MiB golden root 再
FLUSH 上传(10 个 ≈ 5 GB)。

### 集群 20 个(饱和)

20 个并发 create 时,11 个超过 CLI 的 120 秒等待、20 个 warm 全部超时、7 个 restore 超时,
但**最终 20/20 都在 running**——是吞吐天花板,不是数据问题。这一轮的 warm/restore 数字被
上一阶段的积压污染,不能引用;它的价值只是说明"CLI 的单操作等待不是舰队收敛的证据"。

## 证据完整性说明

`raw/` 下的日志是运行时控制台输出的**转录**,不是机器上的原始文件:两台实例上的
`~/cold-migration.log` / `~/concurrent-*.log` 在销毁实例前没有拉下来,这是本次操作上的一个
失误。数字与判定逐条来自当时的输出,但如果要更强的可追溯性,应按"复现"一节重跑一遍并把
文件收回本目录。上一节的 vhost-user 实验目录里的真机文件(`metal-e2e-*.log`、
`metal-guest-fio-*.csv`、`metal-warm-restore-timings.log` 等)是从机器上 rsync 回来的原件。

## 待做

1. **重跑集群扩容对比**(等前一批完全清理干净后再开始),判定加节点能否线性提升 cold create。
2. **cold create 并发化**:`start_cat` 现在分配节点全局的 NBD 设备与 tap slot,所以走节点级锁。
   vhost-user 路径已经不需要 NBD 设备(socket 路径由 cat/disk id 决定),这条限制少了一半。
3. **播种路径优化**:golden root 目前每个 Cat 都完整上传一遍;共享基础镜像的 chunk 复用能直接
   拿掉这 5.3×。
4. 多样本 + 更大规模(50/100 并发),以及 RDS 独立于节点后的元数据层压力。

## 复现

```bash
# 每台机器:sudo deploy/metal/install.sh,然后按上面"环境"配 /etc/cats/cats.env
# (CATS_NODE_ID / CATS_NODE_LISTEN / CATS_CONTROL_PLANE_URL / postgres + s3 adapters)
experiments/metal-cluster-20260726/cold-migration.sh metal-1 metal-2
CATS_PHASES=create,warm,restore experiments/metal-cluster-20260726/concurrent-start.sh single-10 10
```
