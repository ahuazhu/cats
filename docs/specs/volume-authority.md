# Volume Authority 与磁盘生命周期

- 状态：Implemented
- 当前协调协议：[ADR-0059](../decisions/0059-semantic-control-node-synchronous-protocol.md)
- 存储边界：[ADR-0042](../decisions/0042-volume-authority-and-disk-lifecycle.md)、
  [ADR-0066](../decisions/0066-product-disk-snapshot-gc-and-same-disk-restore.md)
- 数据面协议：[blockd protocol](blockd-protocol.md)

本文只描述 schema v20 与当前 semantic Control/Node composition。ADR-0056 的 lifecycle
Operation、command-scoped volume receipt、AgentSession、HostFenceRecovery、takeover authorization
和 disposable-root authorization 已退出当前协议及代码；Git history 是那些设计的档案。

## 1. 权威和不变量

`volume_records` 是远端卷 writer 与 root 的唯一 MetadataStore authority。每行至少包含：

- immutable `volume_id`、`size_bytes` 和 durability；
- `admin_state = active | garbage_collecting | deleting` 及独立 `gc_required`；
- 完整 `RemoteHead = (generation, root_hash, root_object_id)`；
- 可选 `lease_owner`、单调 `lease_epoch` 和 absolute `lease_expires_at`；
- 最近一次 direct acquire、release 或 begin-delete 的完整 request/result marker；
- Owned 时与 owner/epoch 同事务更新的 `owner_node_id` 和 `owner_binding`。

关键约束如下：

1. Guest 只看到标准 virtio block 与未修改 ext4，不接触 ChunkStore 或 MetadataStore credential。
2. 只有当前 `lease_owner + lease_epoch` 可以 renew 或发布新 root。旧 epoch 即使进程仍运行，也不能再
   通过远端 root CAS。
3. expiry lapse 本身不转移 ownership。provider-neutral `normal_acquire` 只接受精确 Unowned epoch，
   不能抢占现有 owner。
4. schema v20 产品卷只使用 Strict durability；成功 FLUSH 在返回前发布远端 durable root。底层
   Relaxed 模式仍可用于独立存储实验，但不是当前 semantic recovery 的产品输入。
5. head CAS 比较完整 predecessor tuple，不只比较 generation。同 generation 的不同 root 是冲突。
6. `size_bytes` 在创建后不可变。
7. `deleting` 行不再接受 acquire、renew、release 或 head publish。
8. PostgreSQL 行锁与同一事务内的 canonical JSON、scalar projection、owner binding 更新共同构成
   linearization point；日志、heartbeat 和 blockd 本地文件都不是替代 authority。

## 2. 核心身份

当前 direct attach 使用：

```text
NormalAcquireRequest {
  volume_id,
  transition_id,
  attachment_id,
  expected_unowned_epoch,
  placement_epoch,
  lease_duration_ms
}
```

成功结果固定返回 `resulting_epoch = expected_unowned_epoch + 1`、当时的完整 head 和数据库时钟计算的
absolute expiry。相同 `transition_id` 只有在完整 request 相同时才重放原结果；同 ID 不同 payload
返回 stale transition。

`attachment_id` 标识一次本地 blockd attachment，`lease_epoch` 是远端 publication fence，
`placement_epoch` 绑定生成 attachment 的当前 Node placement。三者用途不同，不能互相替代。

当前协议没有 lifecycle Operation ID、Desired revision、AgentSession epoch 或 takeover authorization
namespace。旧 JSON variant 和额外 `source` 字段由 `deny_unknown_fields` 拒绝。

## 3. PostgreSQL authority 模型

### 3.1 Canonical rows

Control Store 是 schema 的唯一 DDL owner。当前相关表为：

- `volume_records`：canonical `VolumeRecord` JSON 与所有可查询 scalar projection；
- `disk_records`：Root/PersistentDisk 产品身份、角色与初始化状态；
- `disk_snapshots`：产品 Snapshot identity、当前行与历史 tombstone；
- `disk_snapshot_records`：仅保存 live Snapshot canonical authority 与 GC root pin；
- `persistent_disks`、`disk_bindings`：Workspace 产品对象与当前 Cat mount membership。

schema v20 不创建 `host_fence_events`、`volume_authorizations`、`delete_completion_receipts` 或
`lifecycle_volume_receipts`；startup catalog gate 把它们当作 retired table 拒绝。

`volume_records` 只接受以下 transition marker：

| marker | row postcondition |
|---|---|
| none | Active + Unowned 的初始行 |
| `normal_acquire {request,result}` | Active + exact owner/resulting epoch |
| `release {request,result}` | Active + Unowned + resulting epoch |
| `snapshot_restore {request,result}` | Active + Unowned + resulting epoch/head |
| `begin_delete {request,result}` | Deleting + Unowned + resulting epoch |

每次读取都重新从 canonical JSON 派生 projection 并与 scalar columns 比较。任一漂移返回
`BackendUnknown`，不能猜测或修复。

### 3.2 Pure domain 与事务边界

`storage::authority` 的 transition 函数不做 I/O。PostgreSQL adapter 负责：

1. 开事务并锁定产品 row、disk row 与 `volume_records`；
2. 校验 Workspace/Cat/Disk join 以及 canonical projection；
3. 用数据库时钟计算 lease expiry；
4. 调用 pure transition；
5. 同事务写回 canonical JSON、projection 和 owner binding；
6. commit 后才向调用者返回。

网络调用、Guest 操作、ChunkStore 删除和 blockd 启停不在 PostgreSQL 事务内。外部响应含糊时，调用方
必须重读当前产品/Node/volume 事实，再判断同场景是否已经完成。

### 3.3 Workspace product API idempotency

ADR-0059 删除了 caller-supplied `Idempotency-Key` 与独立 Operation row。当前幂等由场景语义决定：

- Cat/Disk create 比较 Workspace slug 与完整创建配置；
- attach 比较当前 `cat_id + disk_id + mount_path` binding；
- storage transition ID 由当前 Cat/volume/epoch 等稳定内部坐标派生，不暴露给 Workspace caller；
- 相同当前动作等待或查询同一动作，不同动作返回 busy；
- Control 在 Node 已完成而数据库尚未更新时退出，恢复者查询 Node 当前事实后闭合产品 row。

因此旧 ADR 中指向本节的 `Idempotency-Key` 说明只具有历史背景；它不是 schema v20 API。

## 4. Lease 接口和状态机

### 4.1 Normal acquire

provider-neutral transition 只允许：

```text
Active + Unowned(expected epoch)
  -> Active + Owned(attachment, epoch + 1, DB-now + duration)
```

duration 必须大于零且所有整数运算必须落在 PostgreSQL signed 64-bit 范围。Owned 即使 expiry 已过，
普通 acquire 仍返回 `OtherWriter`。

当前 semantic PostgreSQL adapter 在跨 Node 恢复时另有明确编排：只有 Control 已将旧 Node 判为
offline，且锁定的 `owner_node_id` 精确指向该 Node，adapter 才清除旧 owner marker，再执行一次新的
normal acquire。新 epoch 会 fence 旧远端 publish，但这不是可信 Host fence，也不证明旧 Guest 已停止。
长期不对称网络与严格物理单写仍不在 ADR-0059 的保证范围。

### 4.2 Renew

renew 只比较 `volume_id + attachment_id + expected_epoch`，使用数据库当前时间写新的 absolute expiry。
即使旧 expiry 已经过期，只要 owner/epoch 未变，原 owner 仍可 renew。renew 不增加 epoch、不改
transition marker，也不授予新 owner。

blockd 启动前必须执行一次 exact same-owner renewal；运行中继续周期 renew。失败或不确定时停止暴露
Guest I/O，不能自行 acquire。

### 4.3 Release

release 只接受当前 owner/epoch：

```text
Active + Owned
  -> Active + Unowned(epoch + 1)
```

它保留完整 head，清除 owner/expiry，并记录完整 request/result。相同 transition request 重放原结果；
旧 epoch 的延迟 publish 或 release 均失败。

### 4.4 Recovery boundary

heartbeat timeout、offline、route withdraw、reset_required 和 lease expiry 都不是 Host fence。当前
semantic recovery 接受一个有界双跑窗口，并依赖 Strict remote durability 与新 epoch 阻止旧 writer
继续发布远端 root。未来若要重新提供可信 cloud/BMC fencing、Relaxed local tail takeover 或长期
partition 保证，必须新增 ADR 和新的逐卷 authority；不能恢复已删除的 ADR-0056 wire。

## 5. blockd 采用 grant，不改变 ownership

Node 向 blockd 传入一个 `AuthorizedServingAttachment`，其中包括：

- 本地 lineage identity；
- size、durability、当前 head 与当前 expiry；
- 创建 attachment 的完整 independent NormalAcquire request/result；
- lease duration。

blockd 在暴露 I/O 前：

1. 校验 carrier 内所有 volume、attachment、epoch、placement、head 与 expiry 关系；
2. 从 `VolumeDataAuthority` 重读 canonical `VolumeRecord`；
3. 要求当前 row 的 owner/epoch 与 acquire marker 精确匹配；
4. 执行 same-owner renewal；
5. 再次严格重读并绑定 renewal expiry；
6. 持久化或核对本地 lineage 后才进入 serving。

`VolumeDataAuthority` 只提供 load、renew 与 complete-head CAS；没有 acquire、release、offline recovery
或 delete 方法。因此 blockd 不能通过数据面端口改变 ownership。

## 6. 本地 attachment lineage

在创建任何 blockd data file 前，Node fsync 一个 `AttachmentLineageIdentity`：

```text
{
  volume_id,
  attachment_id,
  attachment_epoch,
  acquire_origin: { kind: "normal", transition_id },
  node_id,
  placement_epoch
}
```

lineage 是本地采用证据，不是 ownership authority。pack header、status 和本地恢复均携带同一
`acquire_origin`；缺失、未知 variant 或 identity 不一致时 fail closed。当前格式不再接受 takeover
origin。

## 7. Cold-only 磁盘成员关系

产品层 `disk_bindings` 对 `disk_id` 唯一，并对 `(cat_id, mount_path)` 唯一。attach/detach 只在 Cat
允许的稳定状态执行；Node 收到的 volume 列表由当前 Cat、Root disk 和 bindings 重新派生，不从旧
runtime inventory 或 Desired revision 恢复。

数据库 RWO 约束防止两个当前产品 binding，但不证明失联旧 Host 已停止。远端 write fence 仍由
`lease_epoch` 提供。

## 8. ext4 初始化与 mount readiness

PersistentDisk 的 filesystem identity 属于 `disk_records`，包括 `initialization_token`、
`filesystem_uuid`、expected blank head 与 initialization commit evidence。Node 不能仅凭一个成功
`mkfs` 进程退出码把磁盘标为 initialized。

### 8.1 Disk create

Disk create 在一个 PostgreSQL 事务中创建：

1. Workspace 内唯一的当前 `persistent_disks` row；
2. blank `volume_records` row；
3. `disk_records` 中的 Persistent role、随机 initialization token 和 filesystem UUID。

Root disk 由当前 Cat identity 派生并通过 `CatVolumeStore::ensure_root_volume` 创建或精确发现。boot image
读取遵守 [immutable image manifest](immutable-image-manifest-read-v1.md)；manifest digest、目标 volume
和 blank predecessor 必须同时匹配。

create 重试只接受相同 slug 与完整配置。销毁/删除后 slug 可以指向新的内部 Disk/Cat ID，不回退到历史
row。

### 8.2 Initialization CAS

首次 PersistentDisk attach 在 exact owner/epoch 下完成：

1. blockd serving admission；
2. 对 blank volume 执行 ext4 初始化；
3. 通过 Guest runtime socket 取得 canonical mount-readiness evidence；
4. 发布初始化后的远端 root；
5. 在锁定的 disk/volume row 上比较 initialization token、filesystem UUID、blank head、owner/epoch 和
   published head；
6. 同事务保存 initialized head 与 evidence digest。

响应丢失时重读 disk record，只接受同 token、UUID、head 与 canonical evidence 的精确 postcondition。
不同 filesystem、不同 head 或不完整 Guest evidence 均返回未知/冲突，不能重新格式化。

## 9. 容量不可变

`size_bytes` 同时进入 product row、disk record、volume record、blockd config 与 head CAS request。
当前 V1 没有 resize transition。任一读取发现容量漂移即 fail closed；不能以较大/较小值继续 serving。

## 10. DiskSnapshot、GC 与同盘恢复

DiskSnapshot 是 Workspace 级产品资源；`disk_snapshots` 保存 identity/tombstone，只有
`disk_snapshot_records` live row 是 retention root。create、destroy、restore 全部要求 PersistentDisk
正常、storage Disk 已初始化、Volume `Strict + Active + Unowned`；若存在 binding，Cat 必须稳定 Cold、
无 `current_action` 与 placement。generation-zero 空盘不允许创建 Snapshot。

create 同事务插入产品行和 live root。destroy 同事务写 tombstone、移除 live root并设置
`gc_required=true`；它不在请求中递归删除对象。live root 存在时 PersistentDisk delete 必须在任何状态
改变之前返回 `snapshot_in_use`。

同盘 restore 比较完整 predecessor head、epoch、Snapshot tuple和 public `expected_generation`。成功把
captured root 发布为 `current generation + 1`，并把 epoch 推进一代、保持 Unowned；canonical JSON 和
scalar projection 同事务更新。只有当前 exact `SnapshotRestore` marker 仍匹配时才重放 already-restored；
marker 已被后续 transition 覆盖时 fail closed。

产品 GC 不是 attached blockd sweep。Control scanner 对 `Active + Unowned + gc_required` 的 Volume 写入
`GarbageCollecting {gc_id, roots_digest, started_at}` reservation；acquire、publish、Snapshot mutation和
delete均拒绝该状态。claim 冻结 current head 与按 Snapshot ID 排序的全部 live root。事务外 walker 在
第一次 DELETE 前完整验证 Root/Leaf/Base/Delta 的 hash、长度、geometry与层数，并通过 exclusive cursor
有界枚举同卷 `data/`、`maps/`。任一 retained graph 或 LIST 异常保证零删除；永不枚举 `images/` 或删除
commit records。完成时重新比较 exact gc_id/head/digest/Unowned，再恢复 Active 并清 `gc_required`。

完整算法和不支持项由 [ADR-0066](../decisions/0066-product-disk-snapshot-gc-and-same-disk-restore.md)
冻结。这些能力与本地 `WarmRuntimeSnapshot` 不同，不能互相替代。

## 11. Delete

当前 direct delete 只处理已经安全 Unowned 的卷：

```text
Active + Unowned(expected epoch/head)
  -> Deleting(epoch + 1, same head)
  -> bounded ChunkStore prefix deletion
  -> remove matching disk/volume rows
```

Root destroy 先同步停止本地 runtime/blockd，再通过 `detach_volume` release；随后
`begin_root_delete` 只接受 exact Root descriptor、Unowned epoch 和 head。PersistentDisk delete 同样先
要求没有 `disk_bindings`，再进入 `begin_delete`。

ChunkStore 删除分页、可重试并绑定 exact volume prefix。未知 disk、仍 Owned、head 不一致、epoch
不一致或产品 join 漂移都 fail closed。当前 schema 不存在 disposable-root authorization，也不允许
绕过 remote durability 丢弃 `R < L` local tail。

## 12. Drain、迁移与跨 Node 恢复

计划 drain 的顺序是：withdraw ingress、同步 Cold、确认 Strict remote state、release volume、在新 Node
normal acquire。它不依赖 takeover。

offline 恢复先撤旧 ingress，再由 Control 选择新 Node；PostgreSQL adapter 在锁定 row 下验证旧
`owner_node_id` 确属 offline Node，推进 epoch 并从 remote head 启动。旧 Node 返回后必须完成
reset_required，停止并清理全部本地 Cat 后才重新接收 placement。

这个过程提供当前 semantic 产品选择的最终收敛，不提供可信 Host fencing、旧连接立即终止或长期
partition 下的物理单实例保证。

## 13. 验收矩阵

至少持续覆盖：

| 场景 | 必须结果 |
|---|---|
| acquire exact replay | 返回首次 absolute expiry，不使用重试时钟 |
| 同 transition ID 不同 payload | stale transition，零副作用 |
| expiry 后普通 acquire | OtherWriter，不抢 owner |
| renew wrong owner/epoch | Fenced |
| release replay/迟到 publish | 原结果重放；旧 epoch publish 失败 |
| head equal-generation divergence | HeadConflict |
| integer/expiry/epoch overflow | typed error，零副作用 |
| direct serving carrier 篡改 | 启动前 BackendUnknown |
| canonical JSON/projection drift | BackendUnknown |
| retired lifecycle/takeover JSON | parser 拒绝 |
| deleting 上 writer mutation | fail closed |
| Persistent init 响应丢失 | 只接受 exact token/UUID/head/evidence postcondition |
| offline recovery | 先 withdraw，推进 epoch，旧 Node 返回后 reset |
