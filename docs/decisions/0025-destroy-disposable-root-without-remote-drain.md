# ADR-0025：Destroy 可丢弃待删除 RootDisk，PersistentDisk 仍强制 drain

- 状态：Accepted；Deleted Desired/stop Observation authorization input已由
  [ADR-0056](0056-atomic-per-cat-runtime-lifecycle.md)取代，default Root discard产品语义保留
- 日期：2026-08-03
- 细化：[ADR-0042](0042-volume-authority-and-disk-lifecycle.md)、
  [Volume Authority](../specs/volume-authority.md#11-delete)

> Atomic Delete仍只允许default Root放弃local tail，并且全部Persistent必须先`R == L`/release/detach。
> exact authorization绑定Operation/fingerprint与closed strong-Stop或HostFence sum arm，不再消费Observation。

## 背景

ADR-0022 要求生命周期释放 Host 前把 Relaxed 卷从本地水位 `L` 推进到远端水位
`R`，并且只在 `R == L` 后删除本地 journal。这个规则对仍要保留或恢复的卷是必要的。

Cat Destroy 的 RootDisk 不同：控制面随后删除该卷的metadata row并回收其对象，用户不再能从
这个 RootDisk 恢复。若 RootDisk 已因旧 CAS 歧义或 fencing 无法继续 publish，仍要求
它完成 final drain 会让 Cat、CPU、内存和节点资源永久停在 `Stopping`，但成功 drain
的数据紧接着也会被删除。PersistentDisk 独立于 Cat 生命周期，不能套用这个理由。

## 决定

1. `Deleted` Desired中的每个`VolumeIntent`根据权威`DiskKind`携带恰好一个disposition：
   `DeleteDisposableRoot {delete_id}`或`DetachRetained`。未知、缺失、重复或与DiskKind冲突都拒绝
   整个revision。
2. Destroy先关闭admission并停止新Guest写。只要存在PersistentDisk，就逐盘把Guest页缓存推入
   blockd，并要求每块保留盘 `R == L`；任何失败都保留其 blockd、journal 和 lease 供
   当前revision重试。VMM与RootDisk blockd停止后，Node报告精确stop observation。
3. 对可达Host，Control Plane根据当前Deleted revision和stop observation签发
   `DisposableRootDeleteAuthorization`；失联Host必须已有Active `HostFenceEvent`。授权精确绑定
   delete ID、volume、attachment、owner/epoch、remote head、placement和派生时不可变的
   `authorized_node_id`；内部HostFence worker不借用Node HTTP身份。
4. MetadataStore消费授权时把精确`Active + Owned`卷原子置为`Deleting(delete_id)`、清owner并
   提高epoch。相同授权幂等；错tuple全部失败。CAS成功前不能删除pending tail，成功后才可删除
   授权所指lineage。这里不先release，因此不存在可被normal acquire的Unowned窗口。
5. 未知卷、清单冲突、stale revision或Agent重启后无法证明residue只属于该授权时一律fail closed。
6. 不同Cat的Destroy由各自per-Cat reconciler串行，并受独立有界并发限制；共享Host资源仍只在
   其窄resource lock内分配。

## 不变的契约

- 普通Stop/Cold、Warm、Cold-only detach/DiskSnapshot、计划迁移、Node drain和`cats sync`
  仍严格遵守ADR-0022：失败时保留源，只有所有保留卷`R == L`才能release。
- RootDisk 在 Cat 存续期间的 FLUSH/FUA 契约不变；Strict 仍要求远端 ACK，Relaxed 仍
  可能在 Host 永久丢失时损失 `L-R`。
- PersistentDisk 的 RWO、epoch fencing、独立生命周期和已 ACK 数据承诺不变。

## 后果

- 一个不可发布、但 RootDisk 已确定删除的 Cat 不再无限占用 Host 资源。
- Destroy 可能丢弃 RootDisk 上尚未远端发布的数据；这是删除资源的显式结果，而不是
  Cold 或故障恢复语义。需要保留内容的用户必须先 `cats sync` 并创建独立 Snapshot/
  PersistentDisk，不能把 Destroy 当成可恢复的 Stop。
- Destroy风暴按Cat有界并行；对象存储和元数据压力仍有硬上限。
