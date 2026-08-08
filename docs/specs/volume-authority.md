# Volume Authority 与磁盘生命周期

- 状态：目标合同；尚未实现
- 决策：[ADR-0042](../decisions/0042-volume-authority-and-disk-lifecycle.md)
- 协调协议：[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
- 数据协议：[cats-blockd 协议](blockd-protocol.md)

本文定义卷从创建、附着、格式化、快照、迁移到删除的完整合同。目标是让每个危险动作都由
一个窄的条件状态转换保护，而不是依靠 TTL、控制面缓存或“调用看起来成功”。

本规格只声明存储前置条件：删除现有 Cat、Disk、Snapshot、volume metadata、对象和 Node 本地
目录后启用本合同；实现不读取旧 pending pack，不转换旧 attachment，也不长期保留两套接口。
完整、有序的操作以[Operations and HA §8](../operations-ha.md#8-首次终态部署)为唯一runbook。

## 1. 权威和不变量

每类事实只有一个权威：

| 事实 | 权威 |
|---|---|
| Disk 是否存在、属于哪个 Workspace、是否可加入 Cat | Control Store |
| 当前 DesiredRuntimeSpec 中的完整磁盘集合 | Control Store |
| 当前 volume owner、fencing epoch、remote Root | MetadataStore |
| 本地 pending pack、cache、blockd 进程是否存在 | Node 物理 inventory |
| ext4 UUID 和当前 mount 是否真实存在 | Guest Agent probe |
| Host 是否已被外部隔离 | HostFenceEvent |

必须始终满足：

1. 一个 RWO volume 同时最多一个 owner/epoch 可以发布 Root。
2. 所有 ownership 变化都增加 epoch；旧 epoch 永久失败。
3. lease TTL 只表示 owner 多久没有续约，不授予其他 attachment 抢占权。
4. `R <= L`。Strict FLUSH 在 `R` 前进后 ACK，Relaxed FLUSH 在 `L` 前进后 ACK。
5. `R < L` 的 pack 绑定一个精确 attachment lineage，不能被新 attachment 采用。
6. Cold、磁盘集合变更、DiskSnapshot、detach、计划迁移和删除保留盘前必须 `R == L`；唯一例外是
   当前 Deleted Desired 明确放弃的 disposable Root，并且必须先消费 §11 的精确删除授权。
7. Volume admin 操作和普通 attach 不能并发越过彼此。
8. Snapshot pin 保护的 Root 必须进入 GC live set。

## 2. 核心身份

- `attachment_id`：一次逻辑 attachment 的全局唯一 ID；创建后永不复用。
- `attachment_epoch`：MetadataStore 中每卷单调递增的 fencing 数字。
- `transition_id`：一次 lease/admin 状态转换的全局唯一 ID；重试必须复用，其他操作不得复用。
- `desired_revision`、`placement_epoch`：来自 Runtime Reconciliation 合同。
- `HostFenceEventId`：一次 Host 外部隔离事件的稳定 ID。

`transition_id` 解决响应丢失，epoch 解决 ABA。两者不能互相代替。

## 3. MetadataStore 模型

逻辑记录如下；具体 SQL 可以拆表，但条件必须在一个数据库事务中完成：

```text
VolumeRecord {
  volume_id,
  size_bytes,
  durability: Strict | Relaxed,
  admin_state: Active | Deleting { delete_id },
  generation,
  root_hash?,
  root_object_id?,

  lease_owner?,
  lease_epoch,
  lease_expires_at?,
  last_transition: {
    transition_id,
    kind: Acquire | Release | Takeover | Restore | BeginDelete | BeginDisposableDelete,
    request_fingerprint,
    attachment_id?,
    resulting_epoch
  }?,
}

SnapshotPin {
  snapshot_id,
  volume_id,
  size_bytes,
  generation,
  root_hash?,
  root_object_id?,
  created_at
}
```

`request_fingerprint`是规范化完整请求的hash。同一ID但payload不同返回`StaleTransition`。只保留
最近一次转换结果；Control Plane在一个转换结果被确认前不得启动下一转换。已经被后续转换取代的
旧重试返回`StaleTransition`且不产生副作用，绝不重新执行。

`lease_epoch` 在 acquire、release、takeover 以及会改变 attach 前提的 restore/delete
边界单调增加。这样，晚到的旧 acquire 即使看到 volume 再次 Unowned，也不能用旧
`expected_epoch` 复活。

MetadataStore 错误是闭集：`NotFound`、`OtherWriter`、`Fenced`、`StaleTransition`、
`AdminBusy`、`HeadConflict`、`InvalidAuthorization`、`BackendUnknown`。调用方不得按文本分支。

### 3.1 Volume核心状态机

| 当前状态 | 唯一允许的转换 | 结果 |
|---|---|---|
| Active + Unowned | normal acquire | Active + Owned(new attachment, epoch + 1) |
| Active + Owned | renew | owner/epoch不变，只延长health TTL |
| Active + Owned | exact release | Active + Unowned(epoch + 1) |
| Active + Owned | authorized takeover | Active + Owned(new attachment, epoch + 1) |
| Active + Unowned | same-disk restore | Active + Unowned(new head/generation, epoch + 1) |
| Active + Unowned | begin delete | Deleting(delete_id, epoch + 1) |
| Active + Owned | authorized disposable Root delete | Deleting(delete_id, owner cleared, epoch + 1) |
| Deleting | idempotent sweep完成 | Removed |

表外转换全部拒绝。`transition_id`只让表内同一次转换可重试，不允许跳过前置状态。

## 4. Lease 接口和状态机

### 4.1 Normal acquire

```text
acquire_normal {
  volume_id,
  transition_id,
  attachment_id,
  expected_unowned_epoch,
  desired_revision,
  placement_epoch,
  ttl
} -> LeaseGrant {attachment_id, epoch, transition_id}
```

原子规则：

1. `admin_state` 必须是 Active。
2. `lease_owner` 必须为空，且当前 epoch 等于 `expected_unowned_epoch`。
3. 成功时设置 owner，epoch 增加 1，并保存 transition/result。
4. 同一 `transition_id` 的重试返回原 `LeaseGrant`，不再增加 epoch。
5. 任何其他 owner，即使 TTL 已过，也返回 `OtherWriter`。
6. 同一 attachment 但不同 transition 也不隐式采用；reconciler 必须使用原 transition 或明确
   quarantine。

Node 在调用前把 request 写入 RuntimeCheckpoint。响应不明确时读取 VolumeRecord：只有
`last_transition.transition_id`、owner 和结果 epoch 全部匹配才算成功。

### 4.2 Renew

```text
renew {volume_id, attachment_id, epoch, ttl}
```

只有 owner/epoch 精确匹配时更新时间。单纯 TTL lapse 可以继续 renew；owner/epoch 改变后返回
`Fenced`。renew 不改变 epoch，也不能把其他 owner 改成自己。

### 4.3 Release

```text
release {
  volume_id,
  transition_id,
  attachment_id,
  expected_epoch
} -> UnownedGrant {epoch, transition_id}
```

release 的前置条件是 blockd 已停止接受 I/O，所有保留数据 `R == L`，且 owner/epoch 精确匹配。
成功时清空 owner、增加 epoch并保存 transition。相同 transition 重试返回相同结果；其他不匹配
返回 `Fenced`，不能静默成功。

### 4.4 Protected takeover

普通 reconcile 不存在 revoke。takeover 只接受逐卷授权：

```text
VolumeTakeoverAuthorization {
  authorization_id,
  host_fence_event_id,
  volume_id,
  expected_owner,
  expected_epoch,
  new_attachment_id,
  desired_revision,
  new_placement_epoch,
  not_after,
  issuer_proof
}
```

MetadataStore 在同一 CAS 中验证授权、旧 owner/epoch 和目标 identity，设置新 owner、增加 epoch，
并以 `authorization_id` 作为 transition ID。相同授权重试返回同一 grant；它不能跨卷、跨
placement、跨 attachment 或在过期后使用。

### 4.5 Host fence 与逐卷授权

`HostFenceEvent` 是 Host 级事实：

```text
HostFenceEvent {
  event_id,
  provider,
  immutable_host_id,
  node_id,
  expected_node_boot_id,
  expected_agent_session_epoch,
  fence_attempt_id,
  isolation_state,
  observed_at,
  state: Active | Rejoined
}
```

Control Plane 只在 provider/BMC 证明旧 Host 已隔离且隔离仍被维持时建立 Active event。它为该
Host 上每个需要恢复的 volume 派生独立 `VolumeTakeoverAuthorization`。一个 Host event 可以派生
多份授权；每份授权只能消费一次。heartbeat timeout、route TTL、AgentSession 失效都不能建立
event。

旧 Host 恢复时先进入隔离rejoin流程：提高AgentSession epoch，枚举并停止全部旧VMM/blockd，按
`VolumeLocalIdentity`把所有失效epoch目录移入quarantine，并证明旧route、socket和进程均不可用。
授权派生与`Active -> Rejoined`使用同一个event行serialization point。Control Plane逐项核对该
HostFenceEvent派生过的takeover/delete授权及当前MetadataStore owner/epoch：已消费授权必须精确
匹配当前postcondition；未消费授权必须按PostgreSQL当前时间超过`not_after`。仍可首次生效的授权
阻止rejoin。接受`HostRejoinProof`并把event持久改为Rejoined后，provider才可恢复workload网络。
Rejoined event不能再派生授权；未消费授权不能首次生效，已消费授权仍可幂等读取原结果。旧epoch
的`R < L`目录保留作人工恢复证据，永不参与新Root。

## 5. blockd 采用 grant，不改变 ownership

Node 是 lease transition 的执行者。顺序固定：

1. 在 checkpoint 写 acquire/takeover request。
2. 调用 MetadataStore，并对模糊结果读取精确 transition postcondition。
3. 把 `LeaseGrant` 原子写回 checkpoint。
4. 创建 attachment 专属 data-dir identity。
5. 启动 blockd，传入 volume、attachment、epoch 和 transition ID。
6. blockd 从 MetadataStore 验证精确 owner/epoch后开始 renew和服务。

blockd 启动不得调用 acquire、takeover或增加 epoch。它只可以 renew、以精确 owner/epoch发布 Root，
以及报告 status。Cold detach 时 Node 先 drain、停止 blockd，再执行 release。

## 6. 本地 attachment lineage

每个 data directory 属于一次 attachment，而不是只按 Disk ID 复用：

```text
VolumeLocalIdentity {
  volume_id,
  attachment_id,
  attachment_epoch,
  acquire_transition_id,
  node_id,
  placement_epoch
}
```

identity 在创建任何 cache/pack 前完成 file fsync、rename 和 parent directory fsync。每个 pending
pack 重复记录 `volume_id + attachment_id + attachment_epoch + acquire_transition_id`。

恢复规则：

- 完全相同 lineage：按 generation 顺序 replay；
- MetadataStore 仍是相同 owner/epoch：可以继续 publish；
- epoch 已失效或 identity 不匹配：整个目录 quarantine，不读取其中数据构造新 Root；
- pack 缺口、损坏或 identity 缺失：quarantine；
- `R == L` 且 release 已完成的旧目录可按精确 ownership token删除。
- disposable Root 的唯一例外：§11 的 Owned -> Deleting CAS 已成功后，才能删除授权中精确
  attachment lineage 的 `R < L` tail；该例外不能用于其他目录或其他卷。

clean-slate cutover 不解析缺少这些字段的旧 pack。

## 7. Cold-only 磁盘成员关系

第一版终态不支持 hot attach、hot detach、resize 或 Running DiskSnapshot。volume 容量在创建时确定，
之后不可变；Control Plane、MetadataStore 和 blockd 都不提供 resize API。

- PersistentDisk 加入或离开 Cat 的磁盘集合，只能在 Cat 已稳定 Cold 时提交。
- Cold -> Running 使用完整、排序且无重复的 VolumeIntent 集合一次启动。
- Running 中请求改变磁盘集合返回前置条件错误；调用方先将 Cat 变为 Cold。
- RootDisk 始终随 Cat；PersistentDisk 可在不同 Cat 的 Cold 状态之间移动。

这条限制消除了 Guest 重新 mount、打开文件句柄、VMM hotplug 和 blockd drain 之间的竞态。未来若
确有产品需要，hotplug 必须单独设计并验证，不能放宽本合同的 Cold 前置条件。

## 8. ext4 初始化与 mount readiness

PersistentDisk 创建时，Control Store 一次写入：

```text
Uninitialized {
  initialization_token,
  filesystem_uuid,
  expected_blank_generation,
  expected_blank_root
}
```

首次 Cold -> Running 在 route admission 打开前执行：

1. 取得精确 LeaseGrant，确认 MetadataStore head仍等于 blank predecessor。
2. checkpoint 写 `FormatStarted(token, attachment, epoch, blank_head)` 并 fsync。
3. Guest Agent按稳定virtio device identity probe。看到期望UUID就采用；确认全盘blank且没有部分
   格式痕迹时，按同一token执行`mkfs.ext4 -U <filesystem_uuid>`；其他UUID或部分格式直接
   quarantine。
4. RPC模糊或Agent crash后重新probe。期望UUID继续采用；仍严格blank可用同一token重试；任何
   其他结果quarantine。`Initialized`之后永不进入mkfs路径。
5. 磁盘尚未 mount，没有业务写入。Guest Agent执行设备 flush，Node要求 blockd drain到
   `R == L`，并记录新的 remote generation/Root。
6. Control Store 以 token、blank predecessor、期望 UUID和新 remote head做 CAS，转为
   `Initialized`。相同 token/UUID 重试幂等。
7. Guest Agent mount并回报 device identity、UUID、mount path、read/write状态。只有全部匹配后
   Running 才 Ready并打开 route admission。

初始化阶段即使是 Relaxed volume也必须先达到 `R == L`。否则 Host 丢失后 Control Store 会记得
UUID，而远端盘仍是空白。

## 9. 容量不可变

`size_bytes` 是创建卷时写入的不可变属性，并包含在每个 Root 和 SnapshotPin 中。所有读取都必须
校验三者一致；不一致时 fail closed。

第一版删除现有 resize API，不实现 offline/online resize、maintenance attachment、Map 扩边或
Guest 文件系统扩容。需要其他容量时创建新 Disk 并由 Guest 在两个稳定挂载之间复制数据。这是
明确的产品边界，不是暂时保留一条无条件 metadata update 路径。

## 10. DiskSnapshot、GC 与同盘恢复

这里的 DiskSnapshot 是远端 Root pin，不是 WarmRuntimeSnapshot。

### 10.1 创建

仅在 Disk Cold且 volume unowned时允许：

1. 读取精确 unowned epoch、size和head。
2. `pin_snapshot`在一个事务中锁定VolumeRecord，再次比较这些字段并插入SnapshotPin；normal
   acquire更新同一行，因此只能发生在pin提交之前或之后，不能穿过中间窗口。
3. 响应不明确时按 snapshot ID读取；内容完全相同才算成功。

没有 writer，因此 pin 与新 publish之间不存在空窗。

### 10.2 GC

卷 GC 的 live roots 是 current Root 与该 volume 的全部 SnapshotPin。对每个 root遍历 Root、Leaf、
Base和全部 Delta；任一 snapshot root无法读取或校验时，本轮 GC失败且不删除对象。

Golden Image 继续是不可变、不可自动删除的系统工件。第一版不实现 image GC。

### 10.3 Restore

第一版只支持恢复到原 Disk：

1. Disk 必须 Cold、unowned、Active。
2. 验证SnapshotPin及全部引用对象，SnapshotPin、VolumeRecord和Root中的`size_bytes`必须完全
   相同。
3. `restore_same_disk(transition_id, snapshot_id, expected head, expected unowned epoch)`在一个事务中
   再次验证pin和前置状态，把当前head指向snapshot Root、generation增加1、epoch增加1并记录结果。
4. 相同transition重试返回同一新head；晚到acquire因expected epoch失效而失败。

restore 不倒退 generation；它发布一个引用旧不可变数据的新 generation。第一版不支持 clone，
不建立跨 volume COW引用。

## 11. Delete

删除使用一条当前状态和两种窄入口，不保留历史工作流。

### 11.1 已安全释放的卷

PersistentDisk、需要保留数据的 RootDisk，以及已经正常 drain 的卷必须先满足：没有新的 Desired
引用、Cat稳定 Cold、`R == L`、blockd停止、精确 release完成且 owner为空。随后
`begin_delete(delete_id, expected_head, expected_unowned_epoch)` 原子进入 Deleting并提高 epoch。

### 11.2 放弃本地 tail 的 disposable Root

这是 `R == L` 与 normal release 规则的唯一例外：

```text
DisposableRootDeleteAuthorization {
  authorization_id,          // 同时作为 transition_id
  delete_id,
  volume_id, cat_id,
  desired_revision, placement_epoch,
  expected_attachment_id, expected_epoch,
  expected_generation, expected_root,
  isolation_basis:
      RuntimeStopped {node_id, agent_session_epoch, runtime_incarnation, observation_id}
    | HostFenceEvent {event_id},
  not_after,
  issuer_proof
}
```

Control Plane 只为当前 `Deleted` Desired 中明确标为 disposable 的 RootDisk建立授权。可达 Host 必须
先关闭admission、停止Guest/VMM和blockd，并提交精确stop observation；失联Host必须已有Active
HostFenceEvent。授权绑定当前revision/placement、delete ID、remote head和最后owner/epoch，不能
跨Cat、卷、attachment或重试身份复用。

MetadataStore消费授权时原子比较全部tuple，执行
`Active + Owned(expected owner/epoch) -> Deleting(delete_id) + owner cleared + epoch + 1`。相同授权
重试返回原结果；任何字段变化、过期或非Root/disposable请求都返回`InvalidAuthorization`。该CAS
成功前不得删除pending data；成功后旧epoch永久不能publish，Node才可删除授权所指lineage的
`R < L` tail。这里不经过会产生可抢占窗口的`Active + Unowned`，也不能扩展到PersistentDisk。

HostFenceEvent路径上的本地lineage在旧Host rejoin时进入quarantine；删除授权记录至少保留到该
event转为Rejoined，使rejoin仍能核对所有派生结果。

### 11.3 共同清理

1. Control Store把Disk置为Deleting；此后不能进入任何新DesiredRuntimeSpec。
2. 选择§11.1或§11.2之一把VolumeRecord原子置为Deleting；模糊响应按同一transition读取postcondition。
3. Node完整inventory证明所有可达本地资源已按授权处理；失联Host residue由Active event跟踪。
4. sweeper幂等删除`volumes/<volume-id>/`下的data/maps/commits和该卷SnapshotPins。
5. 对象前缀确认为空后删除VolumeRecord，再删除Control Store Disk row。

不存在根据控制面一列状态、lease TTL或目录缺失直接删除volume的路径。删除完成后无需保留兼容
tombstone，但未Rejoined的HostFenceEvent及其派生授权仍按rejoin合同保留。

## 12. 两 revision Cold 迁移

计划迁移不使用 takeover：

1. revision N+1仍由源 Node负责，目标为 Cold。源关闭 admission、drain guards和Guest，所有
   保留卷到 `R == L`，停止 blockd并逐卷 release，最后发布精确 Cold observation。
2. 只有 N+1 Operation成功后，Control Plane选择目标 Node，在事务中写 revision N+2、提高
   placement epoch，目标为 Running并携带完整磁盘集合。
3. 目标对每卷执行 normal acquire；因为源已 release，volume必须是 Unowned。
4. 旧 revision、placement、attachment和route grant全部失败。

源未证明 Cold/release时不创建 N+2。开发期不提供一个跨两 revision的 Node workflow；API可以
显式返回两个精确 Operation，fleet drain也按相同当前状态规则推进。

非计划 Host loss不走这条路径，只能走 HostFenceEvent + per-volume takeover。

## 13. 模块依赖和实施顺序

1. 先建立旧实现必失败的 characterization tests：普通抢占、重复 acquire、silent release、旧 pack
   新 epoch replay、expired-owner delete、snapshot GC和初始化 crash点。
2. 一次替换 MetadataStore schema、trait和 PostgreSQL/SQLite adapter contract。
3. 一次替换 pack header、data-dir identity、blockd启动参数和status；删除旧 pack parser。
4. 接入 RuntimeCheckpoint、VolumeIntent/Observation和Node lease executor。
5. 接入 Guest Agent probe/format/mount和Cold-only API前置条件。
6. 实现 snapshot-aware GC、same-disk restore和delete sweeper。
7. 接入 HostFenceEvent/takeover与两 revision Cold migration。
8. 同一发布删除旧 acquire/revoke、hot disk mutation、resize API和无条件 delete路径。

## 14. 最小验收矩阵

| 场景 | Oracle |
|---|---|
| normal acquire响应丢失 | 相同transition返回同epoch，不产生第二次fence |
| expired other owner | normal acquire始终OtherWriter；owner可继续renew |
| release响应丢失 | 相同transition幂等；旧epoch永久不能publish |
| stale acquire晚到release之后 | expected epoch不匹配，不能重新占有volume |
| Host takeover | 只有精确逐卷授权成功；跨volume/placement/replay失败 |
| Host rejoin遇到未消费授权 | 未过`not_after`时保持Active/Blocked；过期后才可Rejoined，且不能首次消费 |
| 旧pending目录遇到新attachment | quarantine，remote Root不改变 |
| 相同lineage blockd crash | 从pack恢复L并按序publish |
| resize请求 | API不存在；`size_bytes` 在Volume/Root/Snapshot中始终一致 |
| delete各步骤crash | 重试同delete ID；不再attach；最终metadata和对象均消失 |
| disposable Root `R < L` | 只有精确Owned->Deleting授权CAS后删除该lineage；PersistentDisk拒绝 |
| mkfs各步骤crash | 只adopt期望UUID或quarantine；Initialized前R==L |
| Running磁盘变更 | API拒绝，先Cold；不存在hotplug竞态 |
| Snapshot与GC并发 | snapshot独占对象始终存活；坏pin使GC fail closed |
| same-disk restore | generation前进，容量不变，字节等于snapshot |
| 两revision迁移 | 源Cold/release前目标无writer；目标只normal acquire |
| Host loss `R < L` | 从R恢复并报告DataLossPossible；backlog只是最后样本 |

以上矩阵必须同时覆盖 PostgreSQL 和 SQLite contract；数据路径矩阵同时覆盖 kernel-NBD 与
vhost-user-blk。模糊结果测试必须先证明故障实际注入，不能用空日志作为通过证据。
