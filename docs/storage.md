# Cats 存储架构

- 状态：当前存储合同；ChunkStore、Strict 产品路径、Volume Authority、Cold DiskSnapshot、同盘 restore
  与完整 root GC 保护已实现；生命周期只组合成功 FLUSH 已远端持久的模式，外部 Host-fence 资格仍开放
- 精确协议：[cats-blockd 协议规格](specs/blockd-protocol.md)、
  [Volume Authority 与磁盘生命周期](specs/volume-authority.md)
- 关键决定：[ADR-0003](decisions/0003-direct-s3-chunkstore-backend.md)、
  [ADR-0005](decisions/0005-provider-neutral-storage-ports-and-adapters.md)、
  [ADR-0016](decisions/0016-delta-pack-page-granular-commits.md)、
  [ADR-0017](decisions/0017-golden-root-shared-base-images.md)、
  [ADR-0022](decisions/0022-relaxed-local-first-dual-watermark.md)、
  [ADR-0042](decisions/0042-volume-authority-and-disk-lifecycle.md)、
  [ADR-0066](decisions/0066-product-disk-snapshot-gc-and-same-disk-restore.md)

本文解释终态存储边界，并明确当前实现差距。常量、二进制编码、对象键和提交顺序以协议
规格为准；实验数字只属于其记录的环境，不是 SLA。

## 一句话架构

Guest 看到普通 virtio block device，并在其上运行未修改的 ext4。`cats-blockd` 把稀疏块设备映射为不可变对象和两级 Merkle Map；对象存储保存数据，PostgreSQL 以单行 Root CAS 保存每卷的权威版本并提供单写者 fencing。本地 NVMe 平时是缓存，但在 Relaxed 模式 `R < L` 时还保存尚未发布的唯一数据。

## 边界与组件

```text
Guest ext4
    │ standard virtio-blk READ / WRITE / FLUSH
    ▼
kernel-NBD 或 vhost-user-blk frontend
    │ 同一个 ChunkEngine、同一个 attachment lease
    ▼
cats-blockd
    ├── Host NVMe: cache + pending packs
    ├── BlobStore: immutable data / map / commit objects
    └── MetadataStore: volume head + writer lease
```

- Guest 不知道 Chunk、对象存储或 PostgreSQL，也不持有这些系统的凭证。
- NBD 与 vhost-user-blk 只改变 Host 到 VMM 的传输，不改变 FLUSH、格式或 fencing 语义。
- `cats-storage` 定义 provider-neutral 的 `BlobStore` 和 `MetadataStore` 契约。AWS S3 与 PostgreSQL 是集群形态；file 与 SQLite 适配器用于开发、测试和单机实验，不能组成跨节点持久层。
- `BlobStore` destructive LIST必须对已完成PUT/DELETE线性可见。volume delete只有在阻止新writer、等待
  所有in-flight PUT完成或永久失败，并从prefix起点完整LIST到empty后才能提交completion；stale-empty
  adapter不合格。精确定义与adapter contract tests见[ADR-0005](decisions/0005-provider-neutral-storage-ports-and-adapters.md)。
- 系统不是 Guest 可见的分布式文件系统，也不会为一次小写上传整块虚拟盘。

## 数据模型

### Chunk、Page 与对象

- 卷按 4 MiB Chunk 寻址；每个 Chunk 含 64 个 64 KiB dirty page。Guest 仍以 512 B 逻辑扇区访问。
- 一个 Chunk 在已提交 Map 中是 `Hole`、完整 `Base`，或 `Base/Hole + Delta` 链。
- Delta 对象只包含本次屏障中变脏的 64 KiB pages，按页序拼接，并以 `page_mask` 标识。未携带的 pages 沿用旧的不可变层。
- Delta 链最多 4 层。本次脏页超过半块，或旧链已满时，publisher 写新的 4 MiB Base 并清空链。因此一个冷 Chunk 最多读取一个 Base 和四个 Delta；正确性和读放大有界性不依赖后台 compactor。
- 读取对象时同时校验引用中的长度和 SHA-256；Hole 恒读为零。

### 两级 Merkle Map 与权威 Root

每个 Leaf 描述 256 个 Chunk，即 1 GiB 逻辑空间。Leaf 和 Root 都使用确定性编码，以完整编码的 SHA-256 命名；未修改的 Leaf 被新 Root 复用。

对象写入顺序是：

1. 写数据对象；
2. 写受影响的 Leaf 和新 Root；
3. 写不可变 commit record；
4. PostgreSQL 以 `expected generation + attachment owner + lease epoch` 原子 CAS 新 Root。

前 3 步产生的对象都不是卷的当前版本。只有第 4 步成功后，新 Root 才成为权威状态。`generation` 单调前进，重试使用相同的事务身份和不可变对象；CAS 结果不明确时，必须用精确的 generation、Root、owner 和 epoch 重新读取并判定，不能凭“对象存在”猜成功。

## FLUSH 与双持久化水位

每卷维护两个水位，始终满足 `R <= L`：

- `L`（local durable generation）：最高连续durable generation。`generation <= R`已远端持久；每个
  `R < generation <= L`都有完成文件fsync、rename和目录fsync的immutable pending pack。Guest
  是否已收到ACK不参与水位定义。
- `R`（remote durable generation）：相应数据、Map 和 commit 对象已经持久，且权威 Root CAS 已成功。

一次 FLUSH 先冻结 dirty set；屏障之后的新写进入下一集合，不污染已冻结内容。FUA 使用同一持久化边界。空 dirty set 的 FLUSH 成功但不推进 generation。

### Strict

Strict 只有在 publisher 推进 `R` 后才向 Guest ACK，因此 ACK 的 FLUSH 可在永久丢失当前 Host 后从对象存储与 MetadataStore 恢复。对象存储或 PostgreSQL 不可用时，不能绕过 Root CAS 提前 ACK。Strict 是默认档位。

### Relaxed

Relaxed 在 `L` 前进后向 Guest ACK，后台 publisher 再推进 `R`。Guest 的 WRITE/FLUSH 路径不执行 S3 GET/PUT 或 PostgreSQL CAS；冷缓存局部写以精确 byte ranges 进入本地 pack，由 publisher 合成完整 pages。远端短暂故障保留 pack 并暴露状态；本地容量耗尽时通过有界配额、clean-cache eviction 和背压限流。

`R < L` 时，pending packs 是这些已 ACK 字节的唯一权威副本，**不是 cache**：

- 不能删除、重建或把它当作可牺牲的临时目录；
- 同 Host 的 blockd 重启应先从 pack 恢复 `L`，无需在 attach 阶段执行远端写；
- Host 永久丢失只能恢复到 `R`；最后一次Node observation中的`L-R`、bytes和oldest age
  只是故障前最近样本，不能证明故障瞬间的精确风险窗口；
- 调小后台定时器不能把这种单 Host 数据变成高可用数据。

任何会释放或重建 Host 存储所有权的正常边界——Cold、Warm、DiskSnapshot、计划迁移、Node
drain 和 `cats sync`——都必须先停止晚到的 Guest 写并 drain 到 `R == L`。底层引擎仍保留 Relaxed
能力，但 ADR-0059 当前产品生命周期不接纳 `R < L` 的成功状态，Suspended 也不能用它制造新的
Node-local-only 成功数据。第一版磁盘成员关系和DiskSnapshot mutation只在Cat稳定 Cold且Volume
Unowned时改变，不实现hot attach/hot detach/hot Snapshot。volume容量创建后不可变，不提供 resize API。

## RWO 与 fencing

PersistentDisk 是 RWO。所有 ownership 变化使用带 `transition_id` 和 expected epoch 的条件状态
转换，并原子增加 epoch：

- normal acquire只允许精确`Unowned -> this attachment`；相同transition重试返回原grant；
- release只释放精确owner/epoch，相同transition幂等，其他不匹配显式失败；
- 其他owner即使TTL已过也保持`OtherWriter`；TTL只表达健康，不授予抢占权；
- renew和Root CAS都携带精确owner/epoch，旧epoch永久fail closed。

当前 noded/Strict backend 在启动 blockd 前取得并验证精确 attachment authority；blockd只采用、renew
和使用该grant，不自行acquire或增加epoch。下层data-dir和每个pending pack仍绑定volume、attachment、
epoch和acquire transition；新attachment不能发布旧lineage的`R < L`数据。

Metadata fencing只阻止旧写者发布Root，不能证明旧VMM已停止。跨Node恢复仍必须先完成真实Host
隔离，才能宣称严格物理单实例；heartbeat timeout、入口撤销和lease
TTL都不能代替。ADR-0059 的 offline/reset 流程选择了较弱合同：从远端持久数据恢复并接受旧 Node
reset 前的双跑窗口。完整下层接口与算法见 [Volume Authority](specs/volume-authority.md)。

## RootDisk、PersistentDisk 与 Golden Root

- RootDisk与Cat同生命周期；PersistentDisk独立存在。PersistentDisk创建时固定ext4 UUID和精确
  volume identity，产品数据库以`UNIQUE(disk_id)`保证一块盘最多有一个当前binding。Guest Agent格式化、
  probe exact UUID并确认目标mount；noded只有在blockd达到所需远端持久屏障且Guest mount-ready后才返回
  Running。heartbeat或日志不参与结算。
- Cat create在当前 Cat 行上claim `current_action=create`，保存完整创建配置和初始bindings，提交后同步
  调用目标noded。Control响应丢失时查询该Node的实际`cat_id`状态，不创建Genesis Operation或第二套
  lifecycle identity。
- PersistentDisk只能在Cat稳定Cold时加入或移出完整磁盘集合。DiskSnapshot create/destroy/restore也以
  Cold/unowned为前置；同盘restore把captured root发布为新的generation并推进epoch。volume容量创建后
  不可变；需要其他容量时新建Disk并在Guest内复制数据。
- Warm、Cold和迁移对两类保留盘执行final drain；当前协议没有独立 Stop/Killed 产品动作。
- Destroy先由noded停止同一Cat的物理资源，再删除随Cat存在的Root；PersistentDisk只解除binding，不随
  Cat删除。当前产品先精确release，再只允许`Unowned -> Deleting`；没有discard本地tail的授权路径。
  未知、遗漏、仍Owned或冲突分类一律fail closed。
- durability是每盘创建时确定的属性，不能在已有ACK语义上原地切换。

Golden Root 位于独立的 `images/<image-id>/` 命名空间。镜像 ID 来自完整镜像内容，非零 Chunk
按内容寻址，manifest 最后写入。空卷 provision 时只发布引用这些 Base 的 Map，不为每个 Cat
复制相同 rootfs。安装模式 Node 可按
[ADR-0061](decisions/0061-node-local-golden-root-provision-validation.md) 使用独立的 Node 共享单槽 cache：
精确命中时重建同一 manifest并并发确认远端对象存在，从而避免每个新 Cat 重新 GET 完整 Golden Root body；
miss 时以同一批远端已验证 bytes 原子填充 cache。本地文件不进入 Map、不直接服务 Guest，任一不匹配回退
远端 body 校验。之后的小写继续形成卷私有 Delta，只有达到 Base
重写条件时才私有化整块。
第一版 Golden Image 不删除，不引入尚无可靠 oracle 的 image GC。

## 恢复与 GC

### 恢复

- Fresh Host 从 MetadataStore 的当前 Root 开始，校验并懒加载 Map 和数据对象；停止新 I/O、完成最后屏障且 `R == L` 后，本地目录可全部删除并从远端重建。
- 同Host重启先验证data-dir identity，再按generation扫描pending packs。只有相同attachment、epoch
  和acquire transition且MetadataStore仍认可该grant时才重放。
- pack出现缺口、格式损坏、identity缺失或attachment已被fence时，整个目录quarantine；不能跳过
  generation、把旧pack交给新attachment或静默回退。
- Fresh attachment使用自己的data-dir。旧目录只有在`R == L`且release完成后才是可删除cache；
  当前产品没有`R < L`删除例外。

### GC

blockd sweep 只把当前进程内存 Map 可达的 Root/Leaf、Base 和 Delta 标成存活，并与本进程
stage/publish 互斥。它是下层 current-root 工具，不是产品 GC；本地锁无法排斥另一个 Host 或 attachment，
因此 production composition 仍不启用它。

产品 GC 由 Control 在 Volume `Strict + Unowned + GarbageCollecting` maintenance 下独占执行。它从一个
PostgreSQL claim 冻结 current Root 与全部 live DiskSnapshot Root，先完整验证所有可达对象，再通过
带 exclusive cursor 的有界 LIST 只回收同卷 `data/` 和 `maps/` orphan。任何 live graph 或 LIST 异常都在
第一次 DELETE 前 fail closed；完成时重新比较 exact gc_id、head 与 roots digest。完整边界见
[Volume Authority §10](specs/volume-authority.md#10-disksnapshotgc-与同盘恢复)和
[blockd protocol §9](specs/blockd-protocol.md#9-gc对象回收)。

Volume删除先进入`Deleting(delete_id)`并提高epoch，再清对象。所有产品卷要求Cold、`R == L`且owner
为空；Root由当前语义 Cat Destroy 的已停止物理结果驱动，PersistentDisk由独立Disk destroy驱动。若下层
仍存在旧disposable Root状态，schema v20 startup直接拒绝而不是迁移。全部Persistent必须先
R=L/release/detach。lease TTL、控制面缺行或
本地目录缺失都不是删除证明。

normal begin前必须停止blockd、join upload workers并精确release。删除器幂等delete后用符合ADR-0005
强一致合同的完整prefix LIST确认empty，再在同一锁定产品/volume scope移除row；weak/stale LIST或late PUT
都会保持Deleting。这不是object store与PG的两阶段事务，也不需要旧job/claim/proof row。

卷GC和volume删除永不进入`images/`。Golden Image第一版不自动或人工回收。

## 已验证边界

- 当前`cats-blockd`自动化测试覆盖Base/Delta合并与链上限、pending重放、提交崩溃点、
  CAS歧义、RWO fencing、Relaxed本地恢复与背压、Golden Root、TRIM和当前Root的GC存活集合。
- NBD 与 vhost-user-blk 调用同一 engine；Linux 协议测试覆盖真实 virtqueue 请求、错误隔离、多队列和 stale attachment fail-closed。
- 仓库保留了真实 KVM + Cloud Hypervisor + ext4、真实 S3、以及双节点 S3 + PostgreSQL Cold 恢复的限定环境证据：
  [首轮裸金属闭环](../experiments/metal-e2e-20260721/README.md)、
  [两种块前端与存储机制](../experiments/vhost-user-blk-frontend-20260726/README.md)、
  [双节点 Cold 迁移](../experiments/metal-cluster-20260726/README.md)、
  [Relaxed 本地提交边界](../experiments/relaxed-local-first-20260730/README.md)。

这些结果证明相应 revision、环境、样本和 correctness oracle；它们不自动证明当前提交的生产可用性、规模上限或尾延迟。

## 尚未验证或尚未实现

- 没有面向当前 release 的长期、多故障组合和大规模生产资格测试，也没有可引用的可用性或性能 SLA。
- S3/RDS 的 Multi-AZ failover、备份恢复、区域灾难恢复和 CAS 超时风暴仍需在目标部署形态验证。
- Relaxed 的未发布数据没有跨 Host 副本；如产品要求 Host 丢失下 `RPO=0`，需要另一种明确的持久性方案，不能重新解释现有模式。
- attachment lineage绑定、Cold-only磁盘API和ext4初始化已有组成；snapshot-aware GC、same-disk restore
  和delete sweeper仍未实现。
- clone、hot disk mutation与Golden Image GC明确不在第一版目标内。
- 本地容量限制是每卷机制，不是跨所有 blockd、Warm snapshot、日志和系统预留的 Node 总容量证明。

上线判断应围绕这些缺口补齐证据，不再引入第二套存储后端或一套泛化工作流来绕开现有正确性边界。
