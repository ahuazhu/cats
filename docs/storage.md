# Cats 存储架构

- 状态：目标架构；ChunkStore 数据面已实现，Volume Authority 切换尚未实现
- 精确协议：[cats-blockd 协议规格](specs/blockd-protocol.md)、
  [Volume Authority 与磁盘生命周期](specs/volume-authority.md)
- 关键决定：[ADR-0003](decisions/0003-direct-s3-chunkstore-backend.md)、
  [ADR-0005](decisions/0005-provider-neutral-storage-ports-and-adapters.md)、
  [ADR-0016](decisions/0016-delta-pack-page-granular-commits.md)、
  [ADR-0017](decisions/0017-golden-root-shared-base-images.md)、
  [ADR-0022](decisions/0022-relaxed-local-first-dual-watermark.md)、
  [ADR-0042](decisions/0042-volume-authority-and-disk-lifecycle.md)

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
    └── MetadataStore: volume head + writer lease + snapshots
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
drain 和 `cats sync`——都必须先停止晚到的 Guest 写并 drain 到 `R == L`。Suspended 仍绑定
原 Host，可以保留本地 pending，但不得删除它。第一版磁盘成员关系和DiskSnapshot只在Cat稳定
Cold时改变，不实现hot attach/hot detach或Running Snapshot。volume容量创建后不可变，不提供
resize API。

## RWO 与 fencing

PersistentDisk 是 RWO。所有 ownership 变化使用带 `transition_id` 和 expected epoch 的条件状态
转换，并原子增加 epoch：

- normal acquire只允许精确`Unowned -> this attachment`；相同transition重试返回原grant；
- release只释放精确owner/epoch，相同transition幂等，其他不匹配显式失败；
- 其他owner即使TTL已过也保持`OtherWriter`；TTL只表达健康，不授予抢占权；
- takeover只消费从Active `HostFenceEvent`派生的逐卷授权；计划handoff先release再normal acquire；
- renew和Root CAS都携带精确owner/epoch，旧epoch永久fail closed。

Node在atomic command内执行lease transition并把精确grant写入RuntimeCommandCheckpoint，再启动blockd。blockd只采用、renew和使用
该grant，不自行acquire、takeover或增加epoch。本地data-dir和每个pending pack都绑定volume、
attachment、epoch和acquire transition；新attachment不能发布旧lineage的`R < L`数据。

Metadata fencing只阻止旧写者发布Root，不能证明旧VMM已停止。跨Node恢复仍必须先完成真实Host
隔离；heartbeat timeout、Route TTL和lease TTL都不能代替。完整接口与算法见
[Volume Authority](specs/volume-authority.md)。

## RootDisk、PersistentDisk 与 Golden Root

- RootDisk与Cat同生命周期；PersistentDisk独立存在。PersistentDisk创建时预定ext4 UUID和一次性
  initialization token。Disk与Volume全局一对一，Root与同Workspace Cat一对一，PersistentDisk同时
  最多被一个current CatRuntimeConfig引用；product path只用immutable disk ID。Guest Agent格式化后必须再次
  probe exact UUID并让blockd达到`R == L`；Control Store锁current NodeIdentity/AgentSession/Start Operation/
  Cat head/Volume/Disk/config，再逐字段匹配signed Guest/flush evidence、checkpoint、owner/epoch/head后写
  Initialized，Observation不参与。正确UUID和mount path是RuntimeReady条件，route仍需separate Enable。
- Cat create在一个PG commit写Cat/config、Genesis Start Operation、唯一Root Disk、generation-zero/
  Unowned Volume和exact API result。Root没有Persistent initialization状态或第二个Disk Operation。
- PersistentDisk只能在Cat稳定Cold时加入或移出完整磁盘集合。DiskSnapshot和restore也只在
  Cold/unowned时执行。volume容量创建后不可变；需要其他容量时新建Disk并在Guest内复制数据。
- Warm、Cold和迁移对两类保留盘执行final drain；Stop只保证Killed，不要求R=L/release。
- Destroy唯一例外：Guest/VMM停止后，控制面明确列出的disposable RootDisk可以丢弃未发布tail；
  但必须先消费绑定Delete Operation/fingerprint、Node/Cat/placement、delete ID、attachment、owner/epoch/head、
  disposition与Persistent completion的exact authorization；可达Node与HostFence使用closed不同proof arm。
  Volume原子置为Deleting并提高epoch后才删除lineage。PersistentDisk仍必须
  `R == L`。未知、遗漏或冲突分类一律fail closed。
- durability是每盘创建时确定的属性，不能在已有ACK语义上原地切换。

Golden Root 位于独立的 `images/<image-id>/` 命名空间。镜像 ID 来自完整镜像内容，非零 Chunk
按内容寻址，manifest 最后写入。空卷 provision 时只发布引用这些 Base 的 Map，不为每个 Cat
复制相同 rootfs。安装模式 Node 可按
[ADR-0061](decisions/0061-node-local-golden-root-provision-validation.md) 用 exact local seed 重建同一
manifest，并发确认远端对象存在，从而避免每个新 Cat 重新 GET 完整 Golden Root body；本地文件不进入
Map、不直接服务 Guest，任一不匹配回退远端 body 校验。之后的小写继续形成卷私有 Delta，只有达到 Base
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
  唯一例外是disposable Root的授权Owned->Deleting CAS成功后删除该精确lineage。

### GC

每卷GC在持有writer lease且与stage/publish互斥时运行。live roots是当前Root与该卷全部
`DiskSnapshotRecord`；每个root的Root/Leaf、Base和所有Delta都必须标记。任一record命名的Root无法
读取或校验时，本轮fail closed，不删除对象。commit records按保留策略处理。

DiskSnapshot只在Cold/unowned时创建一条精确包含disk/volume/size/generation/Root的
`DiskSnapshotRecord`；该row同时是产品资源和GC live-root。第一版只支持恢复到原Disk：restore发布
一个新的、单调递增generation；不支持clone或跨volume COW。

Volume删除先进入`Deleting(delete_id)`并提高epoch，再清对象。普通卷要求Cold、`R == L`且owner
为空；Root只由current DeleteCat驱动：R=L时exact release后normal begin，default Root R<L时消费绑定
Operation/fingerprint/Node/Cat/placement/attachment/epoch/head/disposition的exact authorization后从Owned直接进入
Deleting。可达Node arm另绑定strong-Stop proof；HostFence arm只绑定event/interrupted Operation/HostLost digest，
不伪造Stop。全部Persistent必须先R=L/release/detach。release与derive用VolumeRecord锁后重验保证只有一条分支提交。lease TTL、控制面缺行或
本地目录缺失都不是删除证明。

normal begin前必须停止blockd并join upload workers；HostFenceEvent必须由provider cutoff阻止旧Host发起新
PUT，并等待已接受PUT成功可见或永久失败。sweeper幂等delete后用符合ADR-0005强一致合同的完整prefix LIST确认
empty，再执行exact PG completion CAS；weak/stale LIST或暂停的late PUT都会保持Deleting。receipt提交后
再次LIST仍须empty。这不是object store与PG的两阶段事务，也不需要job/claim/proof row。

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
- attachment lineage绑定、Cold-only磁盘API、ext4初始化、snapshot-aware GC、same-disk restore和
  delete sweeper未实现。
- clone、hot disk mutation与Golden Image GC明确不在第一版目标内。
- 本地容量限制是每卷机制，不是跨所有 blockd、Warm snapshot、日志和系统预留的 Node 总容量证明。

上线判断应围绕这些缺口补齐证据，不再引入第二套存储后端或一套泛化工作流来绕开现有正确性边界。
