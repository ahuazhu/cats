# cats-blockd 目标协议

- 状态：目标合同；Chunk/Map/FLUSH 数据面已实现，Volume Authority 切换尚未实现
- 依据：[ADR-0003](../decisions/0003-direct-s3-chunkstore-backend.md)、
  [ADR-0042](../decisions/0042-volume-authority-and-disk-lifecycle.md)、
  [Cats 存储架构](../storage.md)、[Volume Authority](volume-authority.md)

本次开发期切换会删除旧 volume 和本地状态，不读取旧 pending pack，也不提供双协议。切换完成后，
改变常量、编码、提交顺序或 fencing 规则必须新增 ADR；届时再按实际持久数据决定迁移或版本策略。

## 1. 常量

| 名称 | 值 | 说明 |
|---|---|---|
| `LOGICAL_BLOCK_SIZE` | 512 B | 前端向 Guest 暴露的逻辑扇区 |
| `CHUNK_SIZE` | 4 MiB | Map寻址与完整Base的单位；稀疏提交使用64 KiB page Delta |
| `DIRTY_PAGE_SIZE` | 64 KiB | Dirty bitmap 粒度；每 chunk 64 页 = 一个 u64 位图字 |
| `CHUNKS_PER_LEAF` | 256 | 每个 Map Leaf 覆盖 1 GiB 逻辑空间 |
| `MAX_VOLUME_BYTES` | 1 TiB | 两级 Map 的 V1 上限 |
| 卷大小 | 必须为 CHUNK_SIZE 的整数倍 | 控制面在创建卷前向上取整 |

## 2. 远端对象布局（BlobStore 键空间）

```text
volumes/<volume-id>/data/<object-id>            # 不可变数据对象（整块 base 或一组脏页，见 §6.2）
volumes/<volume-id>/maps/<hex-sha256>.node      # 不可变 Map Leaf/Root 节点
volumes/<volume-id>/commits/<gen>-<txn>.json    # 不可变提交记录（审计/恢复辅助）

images/<image-id>/data/<chunk-sha256>           # 共享基础镜像的 chunk（系统所有，见 §6.3）
images/<image-id>/manifest.json                 # 镜像清单；最后写入
```

- `object-id` = `<txn>-c<chunk_idx>`；同一 txn 内对同一 chunk 幂等重传时键不变，重复 PUT 内容必须字节一致。
- 数据对象内容 = chunk 的原始字节（V1 不压缩不加密；加密引入时以对象头版本区分，另立 ADR）。
- 所有对象只写一次；GC 之外禁止 DELETE/覆写。

## 3. Map 节点编码（确定性二进制）

所有多字节整数为小端。节点哈希 = SHA-256(完整编码字节)；节点对象键 = `maps/<hex(hash)>.node`。

### 3.1 Leaf

```text
[magic "CATSLEAF"] [version u16 = 1]
[first_chunk u64] [entry_count u32]
entry_count × ChunkRef
```

`ChunkRef`：

```text
[tag u8]            # 0 = Hole；1 = Base；2 = Layered（版本 ≥ 2，见 §6.2）
tag==1 时:
  [object_id_len u16] [object_id bytes]
  [data_len u32]     # chunk 有效字节数（恒为 CHUNK_SIZE，卷尾不足时为余量）
  [sha256 32B]       # 明文校验和；READ miss 下载后必须验证
  版本 ≥ 3 追加:
  [image_id_len u16] [image_id bytes]   # 空串 = 本卷自己的对象；非空 = images/<image-id>/
```

版本按「用到才升」：leaf 只在实际包含 `Layered` 时写版本 2、只在实际包含镜像 base 时写版本 3，
所以没用到这些特性的卷 map node 逐字节不变（对象 id 也不变）。解码同时接受 1、2、3。

### 3.2 Root

```text
[magic "CATSROOT"] [version u16 = 1]
[volume_size u64] [leaf_count u32]
leaf_count × LeafRef
```

`LeafRef`：

```text
[tag u8]            # 0 = EmptyLeaf（整段为洞）；1 = Present
tag==1 时: [leaf_hash 32B] [object_id_len u16] [object_id bytes]
```

未修改的 Leaf 在新 Root 中原样引用（不重传）。读取任何 Map 对象后必须先验哈希再使用。

## 4. 权威元数据（MetadataStore）

权威`VolumeRecord`、closed transition与receipt schema唯一见
[Volume Authority §3](volume-authority.md#3-postgresql-authority-模型)。Control Store是唯一PostgreSQL DDL和
cross-row事务owner；本协议不复制第二份Volume SQL schema。SQLite只可作为blockd数据面projection/CAS及
pure-domain fixture，不实现Control事务或形成第二个authority。

blockd adapter只读取当前`volume_id`、不可变`size_bytes`、`admin_state`、exact `RemoteHead`、
`lease_owner`、`lease_epoch`和absolute `lease_expires_at` projection，以精确owner/epoch renew，并执行下面的
head CAS。它不建权威表，不执行acquire、release、takeover、revoke、resize、delete或snapshot mutation。

`RemoteHead`的generation/hash/object ID nullability和exact compare沿用Volume Authority；generation只通过
下述数据面CAS或该规格允许的Control transition前进。Root CAS（blockd提交唯一入口）必须在一条原子语句
内完成：

```sql
UPDATE volumes
   SET root_hash = :new_root, root_object_id = :new_obj, generation = generation + 1
 WHERE volume_id = :vol
   AND admin_state = 'Active'
   AND size_bytes = :expected_size
   AND generation = :expected_generation
   AND lease_owner = :attachment_id
   AND lease_epoch = :epoch;
-- 受影响行数必须恰好为 1，否则本次远端发布失败
```

`size_bytes`创建后不可变；blockd还必须验证新Root编码的`volume_size`与grant对应的VolumeRecord
一致。协议不提供resize入口。

### 4.1 Lease / Fencing

- Node先按Volume Authority取得精确grant，再把volume、attachment、epoch及既有acquire transition identity
  交给blockd；blockd只adopt该grant，不能创建或改变ownership。
- `renew_lease`必须携带当前owner/epoch和positive duration；唯一PG authority按本事务DB-now checked-add写
  absolute expiry。owner/epoch不匹配即失败，blockd进入 **fenced**：拒绝新WRITE/FLUSH（返回错误），
  在飞提交一律作废。
- 旧 epoch 的任何 Root CAS 必然 0 行受影响 —— 这是双写防护的最后一道闸，与租约到期判断相互独立。
- expiry只用于健康判断，不打开竞争acquire。短暂renewal lapse不得自我fence；只有精确release或
  授权takeover原子增加epoch后，旧Writer的renew/CAS才fail closed。
- 完整ownership/admin状态机、typed replay和错误闭集唯一见
  [Volume Authority](volume-authority.md#4-lease-接口和状态机)。blockd绝不自行增加epoch。

## 5. 本地状态（Cache + Relaxed 权威暂存）

```text
<data-dir>/identity.json               # attachment lineage；创建其他文件前原子持久化
<data-dir>/cache.data                  # 单个稀疏 cache 文件，offset = 逻辑偏移
<data-dir>/dirty.bitmap                # 持久 dirty 位图（见 §5.1）
<data-dir>/pending/<txn>.pack          # 冻结的 Pending Commit Pack
```

`identity.json`包含`volume_id + attachment_id + attachment_epoch + acquire_transition_id + node_id +
placement_epoch`。data-dir属于这一次attachment，不能仅按volume id被下一个attachment复用。

- **Strict 写路径**：WRITE → 若目标 chunk 已有已提交 Base 且 cache 未水化，先整
  chunk 水化；写 cache；记录 dirty page/range。
- **Relaxed 写路径**：冷缓存局部 WRITE 不先 GET 旧 chunk。只写新 bytes，并记录
  精确 dirty byte ranges；FLUSH 把 ranges 与 payload 固定进本地 pack，后台
  publisher 才读取 remote base 并合成可发布 page/base。
- **读路径**：cache 命中直接返回；miss 按当前 Map 解析 → Hole 返回零 → Base 下载并验 sha256 后水化 cache。同一 chunk 的并发 miss 必须合并为一次下载（singleflight）。
- `R == L` 时删除整个 `<data-dir>` 后可凭远端状态重建；Relaxed 的 `R < L`
  时 pending pack 是唯一权威副本，绝不能删除。

### 5.1 dirty.bitmap

```text
[magic "CATSDRTY"] [version u16 = 1] [chunk_count u64]
chunk_count × u64（小端；bit i = 页 i dirty）
```

### 5.2 Pending Commit Pack（目标格式：内嵌冻结数据）

FLUSH 冻结时把每个 dirty chunk 本次要发布的内容拷入 pack——默认是它的脏 64 KiB 页，整块重写时是完整 chunk（§6.2）。屏障后的新写继续进 cache，不影响已冻结输入：

```text
[magic "CATSPACK"] [version u16 = 2]
[header_len u32] [header JSON]
[payload bytes…]
```

header JSON：

```json
{
  "txn": "<txn-id>",
  "volume_id": "…",
  "attachment_id": "…",
  "attachment_epoch": E,
  "acquire_transition_id": "…",
  "base_generation": N,
  "entries": [
    {
      "chunk_idx": i,
      "payload_offset": o,
      "len": l,
      "sha256_hex": "…",
      "page_mask": m,
      "byte_ranges": [{"chunk_offset": b, "payload_offset": p, "len": n}]
    }
  ]
}
```

写入顺序：写临时文件 → fdatasync → rename 为 `<txn>.pack` → fdatasync 目录。
以上lineage字段、`page_mask`和`byte_ranges`都必须存在并通过校验。目标实现只接受version 2；旧
pack不转换、不回放，clean-slate切换前直接删除。

## 6. FLUSH 提交协议（双持久化水位）

每卷维护 `L = local_durable_generation` 和
`R = remote_durable_generation`，始终 `R <= L`。顺序固定，不可交换
（架构边界见 [Cats 存储架构](../storage.md#flush-与双持久化水位)，完整决定见
[ADR-0022](../decisions/0022-relaxed-local-first-dual-watermark.md)）：

`L`是最高连续durable generation：`generation <= R`已远端持久，每个`R < generation <= L`都
必须存在完整、已同步的pending pack；它不表示Guest已经收到ACK。

1. 捕获屏障：冻结当前 dirty set（清 volatile 位图对应位，新写进入下一集合）。
2. 生成并落盘 Pending Pack（§5.2）；完成 fsync/rename/directory fsync 后 `L`
   前进。Relaxed 此时向 Guest ACK；Strict 继续等待。
3. 后台 publisher 按 generation 读取 pack。验证pack与启动时采用的精确LeaseGrant、data-dir
   identity完全相同；再按`byte_ranges`读取远端 base
   并按序叠加，构造完整 page/base；PUT `data/<txn>-c<idx>`（幂等，重试同键）。
4. 构造新 Leaf/Root，PUT `maps/…`；PUT `commits/<gen+1>-<txn>.json`。
5. Root CAS（§4）。恰好 1 行 → `R` 前进；Strict 此时向 Guest ACK。
6. 清持久 bitmap 中该集合的位；删除 pack。

dirty set 为空时 FLUSH 直接成功（generation 不变）。

Relaxed 的 Guest WRITE/FLUSH 线程不得调用 S3 PUT/GET 或 PostgreSQL CAS。S3/DB
普通错误由 publisher 记录并重试，不直接作为 Guest EIO；CAS owner/epoch
冲突、校验损坏、本地 fsync/ENOSPC 则仍 fail closed。到 staged/physical quota
时先 LRU hole-punch clean committed cache；dirty/staged/I/O chunks 被 pin。
只剩 pin 数据时前台在 condvar 背压，等待 publisher 回收空间。
admission 必须把“当前 dirty set 的未来 pack”作为 accounted reservation；
接近水位可隐式执行一次仅本地 stage 并 kick publisher，防止 cache 吃满后再也
没有空间生成 pack。

### 6.1 崩溃恢复规则

启动时扫描 `pending/*.pack`，先重建 `L` 和本地有序队列，不在 Relaxed attach
恢复阶段执行远端写；后台 publisher 随后对每个 pack：

- 先验证pack、data-dir identity和当前LeaseGrant的volume、attachment、epoch、acquire transition
  完全相同，且MetadataStore仍认可该owner/epoch。缺失、损坏、已fence或不匹配时整个目录
  quarantine；不能删除pack，也不能交给新attachment发布。
- 再读MetadataStore当前generation：
  - `generation > base_generation` 且 `commits/<base+1>-<txn>` 存在 → **CAS 已发生**：只清位图/删 pack，不得重复提交；
  - 否则 → 从 pack 幂等重放步骤 3–6（对象 PUT 键不变）。
- 每卷publisher在同一grant内严格按generation串行，前一pack结果未判定前不能提交后一pack；因此
  在grant仍精确有效时，上述generation前进只能包含队首txn。该不变量必须由并发测试覆盖。
- CAS 前崩溃产生的无 Root 引用对象成为 Orphan，由 GC 按 grace period 清理；恢复流程不负责删除。

### 6.2 发布粒度：Delta Pack（[ADR-0016](../decisions/0016-delta-pack-page-granular-commits.md)）

一次提交对每个 dirty chunk 只发布**该 chunk 的脏 64 KiB 页**，按页序拼接成一个对象。
未携带的页自上次提交以来未被修改，其内容已作为不可变对象存在，因此省略它们不影响点时刻
一致性——屏障必须拷贝的是**本次要发布的内容**，而不是必须是整块。

- `PackEntry` 的 `page_mask` 说明携带哪些页；`page_mask == u64::MAX`（且 `len == CHUNK_SIZE`）
  表示整块 base。该字段是必填项；缺失即拒绝整个pack。
- Map 的 `ChunkRef` 增加 `Layered { base: Option<BaseRef>, deltas: [DeltaRef] }`；`base` 为
  `None` 表示底座是空洞。后写的 delta 在重叠页上覆盖先写的。
- 对象键：base 为 `data/<txn>-c<idx>`，delta 为 `data/<txn>-c<idx>-d`。一次提交对一个 chunk
  最多产生一个对象。
- **自压缩**：满足任一条件时本次提交对该 chunk 发布新的整块 base 并清空链——链长达到
  `MAX_DELTA_LAYERS`（当前 4），或本次脏页超过半块（> 32 页）。因此冷读放大有硬上限
  （≤ 5 个对象/chunk），正确性不依赖后台 Compactor。
- 读路径在 hydration 处解析层：base（或全零）+ 按序应用 delta，一次性整块写入本地 cache；
  每个对象按其引用中的 `len` 与 `sha256` 校验。
- **GC 必须把 base 与全部 delta 都视为存活**（存活判据仍是"被当前 Root 引用"）。
- Leaf 编码只在实际包含 `Layered` 时写版本 2，未产生 delta 的卷 map node 逐字节不变。

### 6.3 共享基础镜像：Golden Root（[ADR-0017](../decisions/0017-golden-root-shared-base-images.md)）

镜像是系统所有的一等不可变工件，放在 `images/` 命名空间下（**不在任何 `volumes/` 前缀里**），
新卷通过**引用**它的 chunk 来完成 provision，不移动任何数据字节。

- `<image-id>` = 镜像文件的 sha256；chunk 对象按内容寻址（`data/<chunk-sha256>`），因此镜像内
  重复的 chunk 只存一份，全零 chunk 根本不存。卷尾不足一块的部分补零成整块。
- **发布幂等**：任何节点对同一镜像算出同一个 id，重复发布是把相同字节写到相同 key（§2 的
  `put_immutable` 契约里这是 no-op），多节点并发发布安全。
- **manifest 最后写**：读到 manifest 即意味着它引用的每个对象都已持久。半途中断只留下无引用
  的对象，不会留下「可引用但不完整」的镜像。
- **provision** 从 manifest 构造 Map（每个非空洞 chunk 一条 `Base`，`image_id` 指向该镜像），
  然后走与任何一次提交完全相同的 §6 步骤 3–5（leaf → root → commit record → Root CAS）。
  只允许在 `generation == 0` 且无未提交脏页的卷上执行。
- **写入不整块私有化**：Guest 写一页就发布一页 delta（§6.2），镜像对象继续做 base。只有写满
  半块或链达到 `MAX_DELTA_LAYERS` 才改写成私有整块 base。
- **GC**：镜像对象属于镜像而不属于卷，存活判据**不是**「某个卷的 Root 引用它」。第一版既不
  自动删除，也不提供人工删除入口；Golden Image GC不在本协议范围内。

## 7. NBD 前端（开发/测试/恢复通道）

- 协议：NBD newstyle fixed（`NBD_OPT_GO`），仅导出单卷；支持 `READ / WRITE / FLUSH / TRIM / WRITE_ZEROES / DISC`。
- 传输：unix socket（默认）或 TCP。
- 语义映射：WRITE→§5 写路径；FLUSH→§6；TRIM/WRITE_ZEROES→见 §7.2；`FUA` 位按 FLUSH 处理。
- NBD 永久保留用于恢复工具、golden root seeding、readiness 探测与 oracle 测试；生产 Guest 路径见 §7.1。

## 7.1 vhost-user-blk 前端（生产 Guest 路径，Linux）

选定为生产前端（[ADR-0015](../decisions/0015-vhost-user-blk-production-block-frontend.md)）。
后端 listen、VMM connect；一个进程可同时提供 §7 的 NBD socket 与本节的 vhost-user
socket，两者服务同一个 engine 与同一个 attachment lease。

- 传输：unix socket + `VHOST_USER_SET_MEM_TABLE` 共享 Guest 内存 + 每队列 kick/call eventfd。
- 协议特性：`MQ`、`CONFIG`。virtio 特性：`VERSION_1`、`INDIRECT_DESC`、`EVENT_IDX`、
  `SEG_MAX`、`BLK_SIZE`、`FLUSH`、`DISCARD`、`WRITE_ZEROES`，`num_queues > 1` 时加 `MQ`。
- Config space：`capacity` = 卷字节数 / 512；`blk_size` = 512（与 §7 路径 Guest 可见
  几何一致）；`size_max` = 32 MiB；`seg_max` = queue_size − 2；`writeback` = 1；
  `write_zeroes_may_unmap` = 1(整块覆盖的 chunk 确实会被解除映射,见 §7.2,而 Hole 读出来就是零)。
- 请求映射（与 §7 完全同构，调用同一批 engine 入口）：

  | virtio-blk 请求 | 语义 |
  |---|---|
  | `IN` | §5 读路径，`sector * 512` 偏移，长度为可写描述符总长减状态字节 |
  | `OUT` | §5 写路径 |
  | `FLUSH` | §6 提交协议；dirty set 为空则直接成功 |
  | `DISCARD` / `WRITE_ZEROES` | 见 §7.2；每段 16 字节 `{sector, num_sectors, flags}` |
  | `GET_ID` | 返回 volume id（截断到 20 字节） |

- 状态码：成功 `OK`；未知请求类型与未定义 flag `UNSUPP`；越界、fenced attachment
  与其它 engine 错误 `IOERR`。**fenced 必须 fail closed**：旧 epoch 的写和 FLUSH 都返回
  `IOERR`，不允许 ACK 永远无法提交的数据。
- 每个队列一个 worker 线程；队列数不改变提交协议，FLUSH 始终是整卷屏障。
- 畸形描述符链（缺状态字节、header 被截断）只失败该请求并记日志，队列继续服务。

### 7.2 TRIM / WRITE_ZEROES:整块丢弃变成 Hole

被**完整覆盖**的 chunk 走「丢弃」而不是写零:提交对它不发布任何对象,Map 项改成 `Hole`。
它引用过的对象因此不再可达,GC 就能收走(§9),而且这个 chunk 之后的冷读一个对象都不用取。
写零的老做法正好相反——每个 chunk 发布 4 MiB 的零,还让旧对象继续活着。

- **没被整块覆盖的部分仍然写字面零**,因为半块的 chunk 里还有数据。
- 本地 cache 仍然被清零:它比这次丢弃活得久,读者直接命中它。
- **丢弃不进 dirty bitmap**,所以提交前崩溃会丢掉这次丢弃(旧内容回来)——TRIM 是建议性的,
  这可以接受;重新 attach 时 cache 会按 Map 重新 hydrate,不会不一致。
- **提交前又写了这个 chunk**:丢弃不能简单取消。丢弃已经把该 chunk 在 cache 里清零了,如果只
  发布新写的那几页,那些零就永远到不了对象存储,被丢弃的数据会在下次冷读时复活。所以此时
  **整块转为 dirty**,把 cache 里的真相(零 + 新写)整块发布。
- pending pack 用 `page_mask == 0` 表示丢弃(delta 至少携带一页,所以不会混淆),恢复重放得到
  同样的结果。

## 8. 正确性判据（测试必须覆盖）

1. Strict：任意时刻 kill -9/删除 Host 后，已 ACK FLUSH 从远端可恢复；
   Relaxed：同 Host blockd 重启从 pack 恢复全部 ACK 数据，Host 永久丢失只承诺
   `R`；`L-R`、bytes和oldest age只能报告最后一次Node observation，不得声称是故障瞬间的
   精确损失量。
2. 仅在 `R == L` 且release完成后删除普通本地状态，空缓存懒读全卷digest与删除前一致。唯一例外
   是disposable Root：精确Owned->Deleting删除授权CAS已成功、旧epoch已fence后，才删除该
   attachment lineage的`R < L`tail。
3. normal acquire不能越过任何owner；逐卷授权takeover增加epoch后，旧blockd无法完成任何Root
   CAS或继续ACK写；单纯expiry lapse不自我fence。
4. 同一 txn 重放不产生第二个 generation。
5. Hole 读取恒为零且不产生远端 GET。
6. Relaxed 冷 cache 局部 WRITE/FLUSH 不产生远端 GET；publisher 合并后 fresh-host
   byte digest 一致。
7. Stop/Cold、Warm、`cats sync`和计划迁移必须drain到`R == L`；失败保留pending、lease与源
   runtime，重试成功前不得越过生命周期边界。磁盘成员关系与DiskSnapshot只允许Cold/unowned；
   volume容量创建后不可变。

### 8.1 控制命令与可观测性

- `status` 返回 durability mode、local/remote generation、unpublished
  generations/bytes/oldest age、max staged/local bytes、allocated/accounted
  bytes、eviction、backpressure、fenced、last publish error以及精确attachment lineage。
- `drain`只在`R == L`后成功；它不释放lease。Node停止blockd后调用MetadataStore的幂等release。
  任一步失败必须可重试，不能清理journal。
- blockd不执行volume delete。disposable Root必须先停止blockd，再由Node消费
  [Volume Authority §11](volume-authority.md#11-delete)的精确删除授权；只有MetadataStore已返回
  Deleting/新epoch，Node才可删除授权中的本地lineage。
- 上述 quota 当前是每卷隔离；不是跨 blockd 进程的 Host 总容量证明。

## 9. GC（对象回收）

存活判据是**从卷当前 Root和全部DiskSnapshotRecord Root可达**:root节点、它命名的leaf节点,以及每个
`ChunkRef`命名的每个对象——delta pack之后这意味着**base加上它的全部delta**,而不是"每个
chunk最新的那个对象"。删掉一个chunk的base只留最新delta,会直接损坏该chunk。任一record命名的Root无法
读取或校验时，本轮GC fail closed，不删除任何对象。

- **绝不碰 `images/`。**镜像对象属于镜像、被所有从它 provision 的卷共享,删一个卷不能删掉全队列
  的 rootfs(§6.3)。GC只列举和删除本卷前缀下的对象;`ChunkRef`里带image origin的base根本
  不算本卷的对象。第一版不提供Golden Image删除或GC。
- **必须持有卷租约运行**,这样没有别的写者会在发布 Root 尚未命名的对象。本写者自己的 pending
  pack 无所谓:恢复会从 pack 文件重放并重新上传被删掉的对象。
- **commit record 不删**:它是审计线索、体积极小,清理它属于保留策略而不是垃圾回收。
- 完全被后来的 delta 覆盖的旧 delta**根本不会进入 Map**:`with_delta` 在追加时就把
  `page_mask` 被新 delta 完全覆盖的旧 delta 丢掉了(它在 hydration 里会被逐字节覆盖,留着只是
  让链更长、冷读更贵、GC 还得当它活着)。

入口有两个:

- `cats-blockd --collect-garbage`:附着、扫一遍、退出,不需要监听套接字。
- 服务期间**按 `--gc-interval-ms` 定时自动跑**(默认 600000,设 0 关闭)。默认开着,因为没有它
  被取代的对象会伴随卷的整个生命周期堆积,而**只有持有租约的这个进程有资格扫**。扫描失败只是
  记一条 warn,下一轮重试,不会挡住 Guest。
