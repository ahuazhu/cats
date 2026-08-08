# ADR-0021：按盘选择 Strict 或 Relaxed 持久性

- 状态：Accepted
- 日期：2026-07-29
- 机制：[ADR-0022](0022-relaxed-local-first-dual-watermark.md)、[Storage](../storage.md)

## 决策

持久性是卷的不可变属性，创建时选择 `strict|relaxed`，默认 `strict`。RootDisk和
PersistentDisk使用同一语义；改变档位必须创建新卷并显式迁移数据。

- **Strict**：FLUSH/FUA只有在对象上传和MetadataStore root CAS成功后返回。成功FLUSH必须
  在Host永久丢失后从远端恢复。
- **Relaxed**：FLUSH/FUA在dirty pack本地fsync并推进`L`后返回；后台publisher随后推进远端
  水位`R`。保持`R <= L`，`R < L`的pending pack是唯一数据，不是cache。

Node在线时按卷暴露`L`、`R`、pending bytes和oldest pending age。Host永久丢失后从`R`
恢复并报告`DataLossPossible`；最后一次observation只能描述当时的backlog，不能证明故障瞬间
的精确损失量。

## 生命周期屏障

以下操作在成功前必须把所有保留卷推进到`R == L`：

- Warm、Cold，以及Cold/unowned的DiskSnapshot；
- Cold-only detach、计划迁移和Node drain；
- `cats sync`等显式durability barrier。

Suspended保留原Host、blockd、attachment lease和pending journal，可以保持`R < L`。旧epoch
失去发布权后仍保留本地pending evidence，直到有明确的恢复、隔离或删除决定。Cat Destroy
仅可按ADR-0025丢弃明确列出的disposable RootDisk tail；PersistentDisk和未知卷fail closed。

## 实现合同

blockd把commit分为本地stage与远端publish：

1. stage冻结一致写集、持久化pending pack并原子推进`L`；
2. publisher按generation顺序上传对象并用expected owner/epoch/root做CAS；
3. crash recovery按顺序重放pending chain；
4. local quota优先回收clean cache，唯一pending data耗尽配额时施加背压；
5. GC、publish与provision遵守同一锁和root可达性边界。

具体pack链、批量publish、quota和恢复算法由ADR-0022及blockd协议维护。

## 验收

- 两个档位的FLUSH返回点与故障恢复oracle分别可测；
- blockd/Agent重启保留Relaxed已确认的本地数据；
- `R < L`时所有远离Host的生命周期操作保持Blocked并保留源；
- remote恢复后自动drain到`R == L`并继续原操作；
- attachment epoch变化后旧writer永久无法publish；
- kernel-NBD与vhost-user-blk运行相同durability矩阵。
