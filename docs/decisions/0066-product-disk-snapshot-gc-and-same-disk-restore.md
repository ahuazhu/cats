# ADR-0066：产品 DiskSnapshot、完整 GC 保护与同盘恢复

- 状态：Accepted
- 日期：2026-08-31
- 取代：[ADR-0042](0042-volume-authority-and-disk-lifecycle.md) 中依赖旧
  Desired/Operation/covered-result 的 Snapshot 协调方式
- 组合：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md) 的同步场景语义和
  [ADR-0062 Destroy 修订](0062-destroy-preempts-in-progress-cat-actions.md)

## 背景

Direct-OS ChunkStore 已经用 immutable Root、Leaf、Base 和 Delta 表示远端磁盘内容，Control
PostgreSQL 也已有 `disk_snapshot_records` 的早期 schema，但当前产品没有 Snapshot API、同盘
restore 或完整 root retention。blockd 的下层 GC 只从当前进程内存 Map 标记 current root；它既不读取
产品 Snapshot，也不能跨 Host 排斥一个新 writer。因此直接启用或扩展该 sweep，会在旧 Host 与新
epoch 短暂双跑时误删仍被 current root 或 Snapshot 引用的对象。

本决策把 DiskSnapshot 定义成独立产品资源，并把 root pin、同盘 restore 与 GC maintenance 放进
MetadataStore writer authority。它不同于 Host-bound、保存 VMM/Guest 运行状态的
`WarmRuntimeSnapshot`。

## 决定

### 产品资源和公开接口

DiskSnapshot 是 Workspace 下的一等资源，V1 提供：

```text
POST /v1/workspaces/{workspace}/snapshots
GET  /v1/workspaces/{workspace}/snapshots
GET  /v1/workspaces/{workspace}/snapshots/{snapshot}
POST /v1/workspaces/{workspace}/snapshots/{snapshot}/actions/destroy
POST /v1/workspaces/{workspace}/snapshots/{snapshot}/actions/restore
```

create 显式接受 `snapshot_slug` 与 `disk_slug`；restore 接受调用方刚读取的
`expected_generation`。Snapshot ID 由服务端分配且永不复用。相同 live slug、相同 Disk 的 create
返回原资源而不重新捕获较新 head；相同 slug 指向不同 Disk 是配置冲突。destroy 后 slug 可以复用，
但新资源取得新的 Snapshot ID。

公开视图暴露 captured generation，不暴露内部 Root hash/object ID。Disk 视图暴露可选
`head_generation`：正常且已初始化的 Disk 必须有值；deleted Disk 没有当前 head。

create、destroy 和 restore 都是 ADR-0059 的有界同步 mutation，不恢复 caller
`Idempotency-Key`、Operation、Desired reconcile、AgentSession 或 covered-result 协议。响应丢失后，
只有当前 exact transition marker 仍与请求和结果相等时才能回答 already-restored；后续 transition 已
覆盖 marker 时，旧 occurrence 以冲突 fail closed，不能因为当前 root 恰好相同就猜测成功。

### v20 产品身份与 live root 分离

schema v20 使用两层记录：

- `disk_snapshots` 保存产品身份、Workspace/slug、创建时的 Disk 展示身份、volume/size、captured
  generation 及 Normal/Deleted tombstone；它不依赖最终会物理删除的 storage Disk/Volume 行；
- `disk_snapshot_records` 只保存仍参与 retention 的 canonical Snapshot record 和精确 captured
  `RemoteHead`，并通过外键绑定当前 `disk_records`、`volume_records` 与产品 Snapshot。

create 在一个 PostgreSQL 事务内写两行。destroy 在一个事务内写产品 tombstone、删除 live root，
并把对应 Volume 标记为需要 GC。只有 live root 阻止 PersistentDisk 删除；历史 tombstone 不阻止
磁盘和 volume 的最终删除。

所有读取和 mutation 都把 typed canonical JSON 与 snapshot/disk/volume/size/head scalar projection
逐字段比较。未知 variant、畸形记录或投影漂移返回 corruption，不能继续 restore 或 GC。

### Cold、Unowned admission

Snapshot create、destroy、restore 与 GC claim 必须在同一个磁盘排他协议下重新验证：

- PersistentDisk 正常，storage Disk 为 Active、Persistent、Initialized；
- Volume 是 Strict、Active、Unowned，且不处于另一 maintenance；
- Disk 未绑定，或者唯一绑定 Cat 为稳定 Cold、`current_action IS NULL` 且没有 placement；
- Workspace、Snapshot、Disk、Volume、size、filesystem identity 与 head 精确匹配。

未初始化的 generation-zero 空盘不允许创建 Snapshot。V1 不在 restore 时制造 generation 大于零但没有
Root 的非法 head。远端对象图校验在 PostgreSQL 事务外执行；提交事务必须重新比较完整前置状态。

Snapshot mutation、Disk delete、binding mutation、使 Cat 离开 Cold 的动作和 GC claim 使用共同的
每 Disk transaction advisory lock，并遵守固定的行锁顺序。等待 PostgreSQL 行锁时不能持有远端对象
I/O，也不能把一次预读的 binding 当成 authority。

### 同盘 restore 是向前发布

restore 只改变创建 Snapshot 时的同一个 Disk。若当前 head 是 generation `G`、epoch `E`，Snapshot
捕获的 root 来自 generation `S`，成功结果是：

```text
generation = G + 1
root       = snapshot(S).root
epoch      = E + 1
owner      = none
```

generation 和 epoch 都 checked 前进，绝不倒退或复用 attachment lineage。事务必须同时验证 Snapshot
仍 live、完整 predecessor head/epoch、Cold/Unowned admission，并原子更新 canonical `VolumeRecord`
及全部 scalar projection。`LastVolumeTransition::SnapshotRestore` 保存 typed request/result；成功还设置
`gc_required = true`。旧 epoch 的 blockd 无法 publish，新 attach 使用新的 attachment/epoch 并重新验证
filesystem UUID 和 Guest mount-ready。

### Control-owned、Snapshot-aware GC

生产 GC 不启动 attached blockd 的 current-root sweep。Control 使用 level-triggered scanner，仅选择
`Active + Unowned + gc_required` 的 Volume，并在 PostgreSQL 中 claim：

```text
Active
  -> GarbageCollecting { gc_id, roots_digest, started_at }
  -> Active
```

claim 冻结 current head 与全部 live Snapshot head，并用稳定、带长度 framing、按 Snapshot ID C 排序的
编码计算 `roots_digest`。进入 maintenance 不推进 epoch，也不覆盖最后一次 writer transition；acquire、
publish、Snapshot mutation 和 Volume delete 都拒绝 `GarbageCollecting`。

事务外 GC 先完整读取并验证所有 retained Root、Leaf、Base、Delta，包括 object ID、hash、长度、volume
geometry、leaf index/count 和 delta 层界限。任何 live graph 缺失、损坏、超界或 GET/LIST 不确定结果
都必须发生在第一次 DELETE 前，并保证本轮零删除。

sweep 只分页枚举该 Volume 的 `data/` 和 `maps/`；永不进入共享 `images/`，也不删除 commit records。
BlobStore 分页 cursor 是单次 pass 内的 opaque/exclusive continuation，不持久化；重启从 prefix 起点
重新扫描。删除 orphan 后再从起点完整验证剩余 key 全部 live。完成事务只有在 exact
`gc_id + current head + roots_digest + Unowned` 仍匹配时才能恢复 Active 并清除 `gc_required`。
显式失败恢复 Active 但保留 `gc_required`；进程崩溃留下 maintenance，由 scanner 以同一 gc_id 恢复。

### 删除和失败语义

live Snapshot 存在时，PersistentDisk destroy 在任何产品状态变化之前返回 `snapshot_in_use`；不得先把
Disk 改成 deleting，不得 cascade 删除 Snapshot。Snapshot destroy 只解除 live root 并调度 GC，不在
HTTP 请求中递归删除对象。

跨 Workspace 查找统一表现为 not found。owned、head conflict、Cat 非 Cold、未初始化、generation/epoch
耗尽、storage unavailable 与 canonical corruption 都是闭集 typed failure；未知记录一律零 mutation。

## 不在 V1 范围

- hot/Running Snapshot、Guest 应用级 quiesce；
- 跨盘 clone、跨 Workspace restore、跨区域复制；
- Snapshot schedule、保留策略和用户可见 GC 进度；
- 自动 cloud/BMC Host fencing；本决策不消除 ADR-0059 接受的短暂双跑窗口。

## 后果

Snapshot root 现在与 current root 一样受 GC 保护，用户可以在不复制整个稀疏磁盘的情况下建立恢复点，
并把同一 Disk 安全恢复到旧内容而保持 generation/epoch 单调。代价是 v20 clean-slate schema、Snapshot
canonical projection、统一磁盘互锁、可靠 BlobStore 分页，以及一条只在 Cold/Unowned maintenance 中
运行的 Control GC 路径。旧 blockd GC 仍是下层/测试能力，不能作为产品 Snapshot retention 证明。
