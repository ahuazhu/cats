# ADR-0001：Greenfield implementation baseline

- 状态：Accepted
- 日期：2026-07-21

## 决定

Cats 是一套独立实现的可休眠 Linux microVM 平台，当前基线固定为：

1. Guest 使用标准 virtio block 和普通 ext4，不感知对象存储、Host cache 或平台凭据。
2. `cats-blockd` 使用唯一生产存储形态 **Direct-OS ChunkStore**；第一个生产适配器是
   S3-compatible object store + PostgreSQL metadata，见 [ADR-0003](0003-direct-s3-chunkstore-backend.md)。
3. 产品生命周期直接采用 **Running / Suspended / Warm / Cold** 四态，见
   [ADR-0002](0002-lifecycle-states-running-suspended-warm-cold.md)。
4. RootDisk 跟随 Cat 生命周期；PersistentDisk 独立存在。V1 volume 是 RWO，同一时刻只有
   一个有效 attachment owner/epoch。
5. Strict FLUSH 以远端 durable root 为成功边界；Relaxed FLUSH 可以先在本地达到 `L`。
   只有 `R == L` 时本地 NVMe 才完全是可删除 cache；`R < L` 的 pending pack 是唯一数据。
6. 控制面保存完整、单调版本的 desired runtime spec；Node 根据当前物理事实做电平触发
   收敛，见 [ADR-0040](0040-level-triggered-runtime-reconciliation.md)。
7. 云产品只出现在 composition root 和 adapter；存储、生命周期和 fencing 合同保持
   provider-neutral。

## 不可妥协的基线

- 提交少量写入不能退化为上传整个稀疏虚拟盘。
- Strict 已成功 FLUSH 的数据必须在永久丢失 Host 后从远端恢复；Relaxed 的较弱承诺必须
  显式暴露，不能包装成 RPO 0。
- 旧 attachment epoch 永远不能发布新 Root；同一 RWO volume 不得出现双 writer。
- Suspended/Warm 的本地快路径失败必须先保护数据，再安全回退到 Cold。
- checkpoint、心跳或缓存缺失不能单独证明 runtime 已停止或 volume 已释放。
- 任何性能或可用性结论都必须保留环境、revision、样本数、测量边界和 correctness oracle；
  实验数字不是生产 SLA。
