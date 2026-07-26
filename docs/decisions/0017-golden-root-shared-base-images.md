# ADR-0017：Golden Root——共享基础镜像,创建卷改为引用而非复制

- 状态：Accepted
- 日期：2026-07-26

## 背景

每个 Cat 的根盘都从同一个 golden rootfs 起步,而在此之前每个 Cat 也都**各自上传了一份**:
`create` 把镜像通过块前端流式写入卷,弄脏每一个 chunk,提交几百 MiB **与上一个 Cat 逐字节相同**
的数据。

2026-07-26 真机测量([实验报告](../../experiments/vhost-user-blk-frontend-20260726/README.md))
把这件事标成了冷创建的主要成本:

- 10 个并发 create 在真实 S3 上要 **128 s**,在本地对象存储上 **24.3 s**——差别就是这 512 MiB
  根盘的上传;对象存储越远,代价越大。
- 单个 create 2.4 s,其中绝大部分是同一份 rootfs 的重复上传。

[PR #8](https://github.com/ahuazhu/cats/pull/8) 当时把这一项记为「blocked on a decision」:
数据对象 key 按卷命名空间隔离(`volumes/<id>/data/<object>`),GC 又按「没有 Root 引用就删」,
所以一个卷无法引用另一个卷的 chunk。本 ADR 就是那个决定。

## 决定

1. **镜像是一等的、系统拥有的不可变工件**,放在自己的命名空间里,不在任何 `volumes/` 前缀下:

   ```
   images/<image-id>/data/<chunk-sha256>
   images/<image-id>/manifest.json
   ```

   `<image-id>` 是**镜像文件本身的 sha256**;chunk 对象按**内容**寻址。

2. **不做跨租户去重。** 共享范围限定在系统发布的镜像内。通用的内容寻址(所有卷的数据对象都按
   内容 hash)也能自动去重,但那会让「另一个租户是否已经存有这段内容」通过 PUT 是否命中而可观测,
   并且把 GC 变成全局引用计数。镜像命名空间把共享收敛到一件事上:**运营方自己发布的镜像**。

3. **`ChunkRef` 的 base 记录它来自哪个镜像**(`BaseRef::image`)。读路径据此选命名空间;
   leaf 编码只在实际出现镜像 base 时才升到版本 3(与 ADR-0016 同一条规则:没用到的特性不改变
   已有卷的字节)。

4. **provision 是纯元数据操作**:`ChunkEngine::provision_from_image` 从 manifest 构造 Map,
   走**与任何一次提交完全相同的** `publish_map`(leaf → root → commit record → Root CAS),
   **不移动任何数据字节**。只允许在 generation == 0 且无未提交脏页的卷上执行——否则它会静默
   丢弃已提交数据,或让 cache 与刚发布的 Map 不一致。

5. **Guest 写入不会侵蚀共享。** 与 ADR-0016 组合:写一页就只发布这一页作为 delta,镜像对象
   继续做 base。写满半块或链达到 `MAX_DELTA_LAYERS` 才改写成私有整块 base——也就是说,
   共享是**按页**退化的,而不是一写就整块私有化。

6. **发布是幂等的,manifest 最后写。** image-id 是文件摘要,所以任何节点对同一镜像算出同一个
   id,重复发布是把相同字节写到相同 key(`BlobStore::put_immutable` 的契约里这是 no-op),
   多节点并发发布因此天然安全。manifest 最后写:读到 manifest 就意味着它引用的每个对象都已持久,
   半途中断只会留下无引用的对象,而不会留下「可引用但不完整」的镜像。

7. **谁来发布**:`cats-blockd --seed-image <path>`。blockd 持有租约,所以它是唯一能在不竞争的
   情况下检查卷 generation 的组件;节点代理只是把镜像路径传给根盘的 blockd,不再流式写入。
   已有 generation 的卷会被跳过,因此这个参数在 resume/warm 路径上也能无条件传。

8. **GC(尚未实现)必须把镜像对象视为镜像所有,而不是卷所有**:存活判据不能是「某个卷的 Root
   引用它」,因为删掉一个卷不应该删掉全队列共享的 rootfs。V1 的规则是**镜像对象不自动回收**,
   由运营方在确认没有卷引用该 image-id 后显式删除。

## 实测结果

`blockd/tests/golden_root_cost.rs`(release,aarch64 Linux 容器,median of 3,本地文件对象
存储;同一进程、同一对象存储,唯一变量是卷如何获得 rootfs)。原始数据:
[`raw/golden-root-cost.log`](../../experiments/vhost-user-blk-frontend-20260726/raw/golden-root-cost.log);
macOS arm64 作为第二平台见
[`raw/golden-root-cost-macos.log`](../../experiments/vhost-user-blk-frontend-20260726/raw/golden-root-cost-macos.log)。

单个 create:

| 镜像 | 上传字节 | 对象数 | provision 延迟 | |
|---|---|---|---|---|
| 512 MiB,复制 | 512.01 MiB | 131 | 1239.8 ms | 1.0× |
| 512 MiB,引用 | **0.02 MiB** | **3** | **7.0 ms** | **178×** |
| 256 MiB,引用 | 0.01 MiB | 3 | 7.5 ms | 108× |
| 64 MiB,引用 | 0.00 MiB | 3 | 6.5 ms | 29× |

**provision 延迟与镜像大小无关**(恒定约 7 ms):它只写 map node 与 commit record,
那 0.01–0.02 MiB 就是这些 map node。

10 个 Cat 同时从同一镜像创建(256 MiB 镜像):

| | 上传字节 | 对象数 | 墙钟 | |
|---|---|---|---|---|
| 复制 | 2560 MiB | 670 | 5725 ms | 1.0× |
| 引用 | **0.11 MiB** | **30** | **56 ms** | **102×** |

冷读代价(空 cache 逐 chunk 读完 64 MiB):复制 446 MiB/s,引用 452 MiB/s——**在噪声内**。
被引用的 chunk 就是一个对象,和私有 chunk 完全一样,所以共享在读路径上不要钱。

上表的「复制」是**引擎层**的复制,不是旧的「经 NBD socket 流式写入」路径,所以这些倍数是保守的。

## 代价与风险

- **首次发布的成本落在第一个用到该镜像的 launch 上**:512 MiB 约 2.7 s(本地存储)。之后每次
  launch 都是 `exists` 命中后直接引用。在镜像部署时预发布可以把这一次也去掉——尚未实现。
- **卷的删除不再意味着数据可删**:见第 8 条,GC 必须区分镜像对象与卷对象。这是本决定引入的
  最主要的运维约束。
- **镜像对象是长生命周期的写一次对象**:同一个 image-id 一旦被任何卷引用,就必须一直存在。
  运营方替换 rootfs 会产生新的 image-id 与新的命名空间,旧的要等所有引用它的卷都消失才能删。
- **leaf 版本 3**:写过镜像 base 的卷,其 map node 是版本 3,旧版二进制读到会明确报错
  (不会静默误读)。没用过共享镜像的卷编码不变。

## 与 ADR-0016 的关系

两者正交,并且**互相放大**:

- Delta Pack(ADR-0016)降低**写**的发布量:一次提交只发布脏的 64 KiB 页。
- Golden Root(本 ADR)降低**创建**的发布量:根盘一个数据字节都不发布。
- 组合效果:一个刚创建的 Cat 写一页,总共向对象存储写 64 KiB——旧行为是 512 MiB(创建)
  + 4 MiB(那次写)。

## 顺带修掉的一个延迟缺陷

这个 benchmark 一开始每一行都有一个 1674 ms 的地板,查出来是 `ChunkEngine::detach` 去 join
一个正在 `sleep(lease_ttl_ms / 3)` 的租约续期线程。也就是说**每次 detach——每次 stop、
suspend、冷迁移,按卷计——都要等掉三分之一个租约 TTL**(默认 1.67 s)。续期改为等 condvar,
detach 立刻唤醒它;回归测试
`engine::tests::detaching_does_not_wait_out_the_lease_renewal_interval`。

## 取代关系

- 落实 [PR #8](https://github.com/ahuazhu/cats/pull/8) 中记为「blocked on a decision」的
  golden-root 复用项。
- [blockd 协议](../specs/blockd-protocol.md) 新增 §6.3(共享基础镜像)。
- 取代节点代理里「把 golden root 流式写入 generation-0 卷」的做法(`ch::seed_volume` 已删除)。
