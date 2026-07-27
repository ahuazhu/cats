# ADR-0016：提交按 64 KiB 页粒度发布(Delta Pack),不再整块发布 4 MiB Chunk

- 状态：Accepted
- 日期：2026-07-26

## 背景

V1 的提交协议把每个 dirty chunk 按**整块 4 MiB** 发布([blockd 协议 §6](../specs/blockd-protocol.md))。
ADR-0003 的风险节把这件事标成过渡态:「V1 Full Chunk 只用于正确性阶段;Delta Pack 与
Compaction 是 P4 必做项」,[Direct-S3 架构](../direct-s3-chunkstore-architecture.md)也已经写明
远端数据对象形态是「4 MiB Base Chunk;后续增加 64 KiB 粒度的 Delta Record」。

2026-07-26 的真机测量把代价量化了([实验报告](../../experiments/vhost-user-blk-frontend-20260726/README.md)):

- Guest 4 KiB 随机写会脏掉整个 4 MiB chunk,一次提交要拷贝、哈希并写下约 **200 MiB**;
  进对象存储的**写放大约 100×**。
- 两条块前端(内核 NBD 与 vhost-user)在这种负载下**都是 flush-bound**:20 秒窗口几乎全部
  花在 FLUSH 停顿里,每次 flush 停顿 324–772 ms。
- 引擎其实**已经**按 64 KiB 页记 dirty 位(`DIRTY_PAGE_SIZE`、`PAGES_PER_CHUNK = 64`),
  只是 `flush()` 只用它判断「这个 chunk 脏不脏」,随后把页级精度丢掉。

## 关键洞察

只发布脏页**不会**破坏点时刻一致性:一次提交没有携带的那些页,自上次提交以来未被修改,
因此它们的内容**已经作为不可变对象存在于对象存储里**。所以

```
chunk 当前内容 = base 对象 + 历史 delta + 本次提交的脏页
```

三部分都不受屏障之后的新写影响。这也纠正了本仓库先前的一个判断("屏障必须拷贝它将要上传的
整块内容"):必须成立的约束是**屏障拷贝的就是本次要发布的**,而不是"发布必须是整块"。

## 决定

1. 一次提交对每个 dirty chunk 发布**一个对象**,内容是该 chunk 的脏 64 KiB 页按页序拼接。
   `PackEntry` 增加 `page_mask` 字段说明携带了哪些页;`page_mask == u64::MAX` 表示整块 base。
2. Map 的 `ChunkRef` 增加 `Layered { base: Option<BaseRef>, deltas: Vec<DeltaRef> }`。
   `base` 为 `None` 表示底座是空洞(全零)。后写的 delta 在重叠页上覆盖先写的。
3. **何时改回整块**:出现下列任一情况,本次提交对该 chunk 发布一个新的整块 base 并清空链:
   - 该 chunk 的 delta 链长度已达 `MAX_DELTA_LAYERS`(当前 **4**);
   - 本次脏页数超过半块(> 32 页)——再用 delta 省不了多少,而重置链更值。

   这让系统**自压缩**:不需要后台 Compactor 来保证正确性或有界性,冷读放大有硬上限
   (≤ 5 个对象/chunk)。后台 Compactor 仍然是可选优化,可以把这个上限放宽。
4. **屏障内只拷脏页**,相邻脏页合并成连续 pread;拷贝与哈希继续并行(见 PR #8)。
5. **格式兼容**:leaf 编码只在实际包含 `Layered` 时才写版本 2,所以从未产生过 delta 的卷
   map node 逐字节不变(对象 id 也不变);解码同时接受版本 1 和 2。`PackEntry.page_mask`
   有 serde 默认值,**旧版本写下的 pending pack 仍可被重放**为整块提交。
6. **读路径**在 hydration 处解析层:base(或全零)+ 按序应用 delta,一次性整块写入本地
   cache,所以 cache 文件里不可能残留上一代的字节。每个对象都按其引用里的 len 与 sha256 校验。

## 实测结果

`blockd/tests/commit_cost.rs`(release,aarch64 Linux 容器,median of 3)。48 个 dirty chunk、
每 chunk 一个脏页,即 4 KiB 随机写的形态:

| | 整块发布(旧行为) | Delta Pack |
|---|---|---|
| 发布字节 | 192 MiB | **3 MiB(64× 少)** |
| FLUSH 延迟 | 412 ms | **109 ms(3.8×)** |
| 8 个 dirty chunk | 83 ms | **30.5 ms** |
| 32 个 dirty chunk | 301 ms | **85.9 ms** |

密集写(整块脏)一列**故意不变**:192 MiB / 412 ms,与设计一致。

延迟没有跟着字节数降 64×,是因为成本结构翻转了——残余是**每对象固定开销**(48 个对象各要
一次 create + `sync_data` + hard_link;在 S3 上是 48 次 PUT 往返),约 2.3 ms/对象。下一个杠杆
因此是**减少每次提交的对象数**(把多个 chunk 的 delta 打包成一个对象),而不是继续减字节。

2026-07-27 在真实 S3 上复测证实了这一点,而且方向和当初的猜测相反
([原始数据](../../experiments/vhost-user-blk-frontend-20260726/raw/metal-delta-pack-s3.log)):

| dirty chunks | 真实 S3(dense → sparse) | 同机本地文件存储 |
|---|---|---|
| 8 | 858.9 → 374.0 ms = **2.3×** | 166.4 → 43.8 ms = 3.8× |
| 32 | 3031.5 → 1149.4 ms = **2.6×** | 1974.0 → 140.2 ms = 14.1× |
| 48 | 4913.5 → 1669.3 ms = **2.9×** | 2974.7 → 312.6 ms = 9.5× |

**S3 上的收益比本地小**:字节降 64×,但对象数一个没少,而 S3 上一个对象就是一次 PUT 往返。
sparse 行的 556 ms/发布 MiB 对 dense 的 25.6 ms/发布 MiB,说明 sparse 提交付的是往返而不是字节。
发布字节降 64× 是算术,在哪都成立;能换回多少 flush 时间取决于后端。

## 代价与风险

- **冷读放大**:一个满链 chunk 的冷读要取 5 个对象而不是 1 个。这是本决定最主要的代价,
  `MAX_DELTA_LAYERS = 4` 就是为此选的(而不是 8 或更多)。跨节点冷迁移与空缓存恢复会更慢,
  幅度取决于链长分布;真机上尚未单独测量这一项。
- **GC(尚未实现)必须把 base 与全部 delta 都视为存活**:存活判据仍然是"被当前 Root 引用",
  只是一个 chunk 现在可能引用多个对象。实现 GC 时必须遍历 `ChunkRef::object_ids()`。
- **对象数量增加**:同样的写入量会产生更多、更小的对象。S3 的 PUT 次数按 ADR-0003 的要求
  仍然要记入基准四元组(`guest_bytes_written`、`remote_bytes_uploaded`、PUT 数、Compaction bytes)。
- **前向兼容**:写过 delta 的卷,其 map node 是版本 2,旧版二进制读到会明确报错(不会静默误读)。

## 取代关系

- 取代 [blockd 协议 §6](../specs/blockd-protocol.md) 中"提交整个 chunk"的部分,该节已相应修订并
  新增 §6.2。
- 落实 ADR-0003 风险节列为 P4 的 Delta Pack 项的第一步;Compaction 仍未实现(靠上面第 3 条的
  自压缩替代其正确性职责)。
