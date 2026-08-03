# ADR-0024：Destroy 可丢弃待删除 RootDisk，PersistentDisk 仍强制 drain

- 状态：Accepted
- 日期：2026-08-03
- 修订：仅为 ADR-0022 的强制 drain 规则增加 Cat Destroy / RootDisk 例外；
  普通 Stop/Cold、Warm、Detach、Snapshot、迁移、Node drain 和 `cats sync` 不变。

## 背景

ADR-0022 要求生命周期释放 Host 前把 Relaxed 卷从本地水位 `L` 推进到远端水位
`R`，并且只在 `R == L` 后删除本地 journal。这个规则对仍要保留或恢复的卷是必要的。

Cat Destroy 的 RootDisk 不同：控制面随后会 tombstone 该卷并异步 GC，用户不再能从
这个 RootDisk 恢复。若 RootDisk 已因旧 CAS 歧义或 fencing 无法继续 publish，仍要求
它完成 final drain 会让 Cat、CPU、内存和节点资源永久停在 `Stopping`，但成功 drain
的数据紧接着也会被删除。PersistentDisk 独立于 Cat 生命周期，不能套用这个理由。

同时，StopCat 原先与多数节点动作共用节点级锁，导致一个慢远端 drain 串行阻塞同节点
其他 Cat。不同 Cat 的 blockd、VMM、journal 和已分配设备彼此独立；真正需要节点级串行
的仍是 kernel-NBD 设备分配。

## 决定

1. Stop job 显式区分普通 `Cold` 与 `Destroy`。旧 wire payload 缺少该字段时必须默认
   `Cold`，不能从 mount path、目录名或旧缓存猜测某卷可删除。
2. `Destroy` 计划由控制面根据权威 `DiskKind` 下发两张明确清单：
   - `disposable_root_disk_ids`：随 Cat 删除、允许丢弃本地未发布 journal 的 RootDisk；
   - `retained_persistent_disk_ids`：Cat 删除后仍存在、必须完成 final flush 和 drain 的
     PersistentDisk。
3. Destroy 先阻止新 Guest 写。只要存在 PersistentDisk，就逐盘把 Guest 页缓存推入
   blockd，并要求每块保留盘 `R == L`；任何失败都保留其 blockd、journal 和 lease 供
   同一 job 重试。VMM 停止后，可终止明确列出的 RootDisk blockd 并删除其本地状态，
   无需为该 RootDisk 再做远端 CAS。
4. Destroy 成功后控制面仍 revoke/fence attachment，再 tombstone RootDisk。跳过 drain
   不会把本地 ACK 重新解释成远端持久：这些 RootDisk 字节随资源删除而不可恢复。
5. 未知卷、清单冲突、旧 job 或 agent 重启后无法证明 residue 只属于待删除 RootDisk
   时一律 fail closed。无监督 residue 只有在权威计划明确为 root-only 且目录中没有
   其他 volume 时才可清理。
6. 不同 Cat 的 Stop 只在各自的 per-Cat lock 下执行，并受独立的节点 Stop 并发上限
   约束，避免同时向 S3/PostgreSQL 发起无界 drain。kernel-NBD Start/Restore 的设备
   分配继续使用节点级锁；同一 Cat 的 Start/Stop 仍不能交错。

## 不变的契约

- 普通 Stop/Cold、Warm、hot detach、Snapshot、计划迁移、Node drain 和 `cats sync`
  仍严格遵守 ADR-0022：失败时保留源，只有所有保留卷 `R == L` 才能释放。
- RootDisk 在 Cat 存续期间的 FLUSH/FUA 契约不变；Strict 仍要求远端 ACK，Relaxed 仍
  可能在 Host 永久丢失时损失 `L-R`。
- PersistentDisk 的 RWO、epoch fencing、独立生命周期和已 ACK 数据承诺不变。

## 后果

- 一个不可发布、但 RootDisk 已确定删除的 Cat 不再无限占用 Host 资源。
- Destroy 可能丢弃 RootDisk 上尚未远端发布的数据；这是删除资源的显式结果，而不是
  Cold 或故障恢复语义。需要保留内容的用户必须先 `cats sync` 并创建独立 Snapshot/
  PersistentDisk，不能把 Destroy 当成可恢复的 Stop。
- Stop 风暴从节点全串行变为有界并行；吞吐提高，但对象存储和元数据压力仍有硬上限。

