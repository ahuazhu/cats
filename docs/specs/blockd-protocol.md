# cats-blockd 协议规格（P0 冻结）

- 状态：Frozen v1（2026-07-21）；对应实现 `blockd/`，常量的唯一代码出处是 `api/src/chunk.rs`
- 依据：[ADR-0003](../decisions/0003-direct-s3-chunkstore-backend.md)、[Direct-S3 ChunkStore 详细设计](../direct-s3-chunkstore-architecture.md)

改变本文任何一项（常量、编码、提交顺序、fencing 规则）都必须新增 ADR，并提供迁移或版本协商方案。

## 1. 常量

| 名称 | 值 | 说明 |
|---|---|---|
| `LOGICAL_BLOCK_SIZE` | 512 B | 前端向 Guest 暴露的逻辑扇区 |
| `CHUNK_SIZE` | 4 MiB | 远端对象与 Map 的单位（V1 full-chunk 提交） |
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

每卷一行（SQLite 开发实现 / PostgreSQL 生产实现，同一 SQL 形状）：

```text
volumes(volume_id PK, size_bytes, generation, root_hash, root_object_id,
        lease_owner, lease_epoch, lease_expires_at_unix_ms)
snapshots(snapshot_id PK, volume_id, generation, root_hash, root_object_id, created_at)
```

- `generation` 单调递增；`generation=0` 表示空卷（全洞，无 Root 对象）。
- Root CAS（提交唯一入口）必须在一条原子语句内完成：

```sql
UPDATE volumes
   SET root_hash = :new_root, root_object_id = :new_obj, generation = generation + 1
 WHERE volume_id = :vol
   AND generation = :expected_generation
   AND lease_owner = :attachment_id
   AND lease_epoch = :epoch
   AND lease_expires_at > now
-- 受影响行数必须恰好为 1，否则本次 FLUSH 失败且不得 ACK
```

### 4.1 Lease / Fencing

- `acquire_lease(volume, attachment, ttl)`：仅当无有效租约（过期或空）时成功；成功即 `lease_epoch += 1` 并返回新 epoch。
- `renew_lease` 必须携带当前 epoch；不匹配即失败，blockd 进入 **fenced**：拒绝新 WRITE/FLUSH（返回错误），在飞提交一律作废。
- 旧 epoch 的任何 Root CAS 必然 0 行受影响 —— 这是双写防护的最后一道闸，与租约到期判断相互独立。

## 5. 本地状态（可全部删除的 Cache + 提交暂存）

```text
<data-dir>/cache.data                  # 单个稀疏 cache 文件，offset = 逻辑偏移
<data-dir>/dirty.bitmap                # 持久 dirty 位图（见 §5.1）
<data-dir>/pending/<txn>.pack          # 冻结的 Pending Commit Pack
```

- **写路径**：WRITE → 若目标 chunk 已有已提交 Base 且 cache 未水化，先整 chunk 水化（读远端→cache）；写 cache；置位 dirty 页；对 bitmap 文件 fdatasync 后 ACK（普通写=易失缓存语义，bitmap 持久化保证的是重启后不"漏提交"，不是数据持久）。
- **读路径**：cache 命中直接返回；miss 按当前 Map 解析 → Hole 返回零 → Base 下载并验 sha256 后水化 cache。同一 chunk 的并发 miss 必须合并为一次下载（singleflight）。
- 删除整个 `<data-dir>` 后，凭 MetadataStore 的 Root + 远端对象必须能完整重建（空缓存冷恢复）。

### 5.1 dirty.bitmap

```text
[magic "CATSDRTY"] [version u16 = 1] [chunk_count u64]
chunk_count × u64（小端；bit i = 页 i dirty）
```

### 5.2 Pending Commit Pack（V1：内嵌冻结数据）

FLUSH 冻结时把每个 dirty chunk 本次要发布的内容拷入 pack——默认是它的脏 64 KiB 页，整块重写时是完整 chunk（§6.2）。屏障后的新写继续进 cache，不影响已冻结输入：

```text
[magic "CATSPACK"] [version u16 = 1]
[header_len u32] [header JSON]
[payload bytes…]
```

header JSON：

```json
{
  "txn": "<txn-id>",
  "volume_id": "…",
  "base_generation": N,
  "lease_epoch": E,
  "entries": [
    {"chunk_idx": i, "payload_offset": o, "len": l, "sha256_hex": "…"}
  ]
}
```

写入顺序：写临时文件 → fdatasync → rename 为 `<txn>.pack` → fdatasync 目录。

## 6. FLUSH 提交协议（持久性边界）

顺序固定，不可交换（Direct-S3 设计 §7）：

1. 捕获屏障：冻结当前 dirty set（清 volatile 位图对应位，新写进入下一集合）。
2. 生成并落盘 Pending Pack（§5.2）。
3. 对每个 entry：PUT `data/<txn>-c<idx>`（幂等，重试同键）。
4. 构造新 Leaf/Root，PUT `maps/…`；PUT `commits/<gen+1>-<txn>.json`。
5. Root CAS（§4）。恰好 1 行 → 持久点达成。
6. 清持久 bitmap 中该集合的位；删除 pack。
7. 向 Guest 返回 FLUSH 成功。

dirty set 为空时 FLUSH 直接成功（generation 不变）。

### 6.1 崩溃恢复规则

启动时扫描 `pending/*.pack`，对每个 pack：

- 读 MetadataStore 当前 generation：
  - `generation > base_generation` 且 `commits/<base+1>-<txn>` 存在 → **CAS 已发生**：只清位图/删 pack，不得重复提交；
  - 否则 → 从 pack 幂等重放步骤 3–6（对象 PUT 键不变）。
- 重放前必须验证租约 epoch 仍属于本 attachment；已被 fence 则丢弃 pack 并保持只读。
- CAS 前崩溃产生的无 Root 引用对象成为 Orphan，由 GC 按 grace period 清理；恢复流程不负责删除。

### 6.2 发布粒度：Delta Pack（[ADR-0016](../decisions/0016-delta-pack-page-granular-commits.md)）

一次提交对每个 dirty chunk 只发布**该 chunk 的脏 64 KiB 页**，按页序拼接成一个对象。
未携带的页自上次提交以来未被修改，其内容已作为不可变对象存在，因此省略它们不影响点时刻
一致性——屏障必须拷贝的是**本次要发布的内容**，而不是必须是整块。

- `PackEntry` 的 `page_mask` 说明携带哪些页；`page_mask == u64::MAX`（且 `len == CHUNK_SIZE`）
  表示整块 base。该字段有 serde 默认值，旧版本写下的 pending pack 仍按整块重放。
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
- **GC**：镜像对象属于镜像而不属于卷，存活判据**不是**「某个卷的 Root 引用它」。V1 规则是镜像
  对象不自动回收，由运营方在确认没有卷引用该 image-id 后显式删除。

## 7. NBD 前端（开发/测试/恢复通道）

- 协议：NBD newstyle fixed（`NBD_OPT_GO`），仅导出单卷；支持 `READ / WRITE / FLUSH / TRIM / WRITE_ZEROES / DISC`。
- 传输：unix socket（默认）或 TCP。
- 语义映射：WRITE→§5 写路径；FLUSH→§6；TRIM/WRITE_ZEROES→写零（V1 不改 Map 为 Hole，Compaction 阶段优化）；`FUA` 位按 FLUSH 处理。
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
  `write_zeroes_may_unmap` = 0。
- 请求映射（与 §7 完全同构，调用同一批 engine 入口）：

  | virtio-blk 请求 | 语义 |
  |---|---|
  | `IN` | §5 读路径，`sector * 512` 偏移，长度为可写描述符总长减状态字节 |
  | `OUT` | §5 写路径 |
  | `FLUSH` | §6 提交协议；dirty set 为空则直接成功 |
  | `DISCARD` / `WRITE_ZEROES` | 写零（V1 不改 Map 为 Hole）；每段 16 字节 `{sector, num_sectors, flags}` |
  | `GET_ID` | 返回 volume id（截断到 20 字节） |

- 状态码：成功 `OK`；未知请求类型与未定义 flag `UNSUPP`；越界、fenced attachment
  与其它 engine 错误 `IOERR`。**fenced 必须 fail closed**：旧 epoch 的写和 FLUSH 都返回
  `IOERR`，不允许 ACK 永远无法提交的数据。
- 每个队列一个 worker 线程；队列数不改变提交协议，FLUSH 始终是整卷屏障。
- 畸形描述符链（缺状态字节、header 被截断）只失败该请求并记日志，队列继续服务。

## 8. 正确性判据（测试必须覆盖）

1. 任意时刻 kill -9 blockd，重启恢复后：已 ACK 的 FLUSH 数据可读且 digest 一致；未 ACK 的 FLUSH 要么完整可见要么完全不可见（generation 原子推进）。
2. 删除全部本地状态后空缓存懒读，全卷 digest 与删除前一致，且只下载被读到的对象。
3. 旧 epoch 的 blockd 无法完成任何 Root CAS，也无法在续租失败后继续 ACK 写。
4. 同一 txn 重放不产生第二个 generation。
5. Hole 读取恒为零且不产生远端 GET。

## 9. GC（对象回收）

存活判据是**从卷当前 Root 可达**:root 节点、它命名的 leaf 节点,以及每个 `ChunkRef` 命名的每个
对象——delta pack 之后这意味着 **base 加上它的全部 delta**,而不是"每个 chunk 最新的那个对象"。
删掉一个 chunk 的 base 只留最新 delta,会直接损坏该 chunk。

- **绝不碰 `images/`。**镜像对象属于镜像、被所有从它 provision 的卷共享,删一个卷不能删掉全队列
  的 rootfs(§6.3)。GC 只列举和删除本卷前缀下的对象;`ChunkRef` 里带 image origin 的 base 根本
  不算本卷的对象。这也意味着**镜像的回收是另一件事**:V1 不自动回收,由运营方在确认无卷引用
  该 image-id 后显式删除。
- **必须持有卷租约运行**,这样没有别的写者会在发布 Root 尚未命名的对象。本写者自己的 pending
  pack 无所谓:恢复会从 pack 文件重放并重新上传被删掉的对象。
- **commit record 不删**:它是审计线索、体积极小,清理它属于保留策略而不是垃圾回收。
- 完全被后来的 delta 覆盖的旧 delta**根本不会进入 Map**:`with_delta` 在追加时就把
  `page_mask` 被新 delta 完全覆盖的旧 delta 丢掉了(它在 hydration 里会被逐字节覆盖,留着只是
  让链更长、冷读更贵、GC 还得当它活着)。

入口:`cats-blockd --collect-garbage`(不需要监听套接字,扫完即退出)。
