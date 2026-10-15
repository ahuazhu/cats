## 磁盘类型

|  | RootDisk | PersistentDisk |
|----|----|----|
| 创建 | 精确 Cat Create | 精确 PersistentDisk Create |
| Ownership | 跟随所属 Cat | 独立 Workspace Resource |
| 访问模型 | 一个 Cat | RWO：一个已授权 Writer Epoch |
| Release 容量 | 不可变 | 不可变 |

## 创建并查看 PersistentDisk

    cats disk create project-data --size 20GiB --durability strict
    cats disk ls
    cats disk get disk_…

Create Body 明确包含 `durability`、`name` 与 `size_bytes`。浏览器控制台使用 closed Strict default。浏览器与 CLI 都会在发送前持久化精确 Request 与 Idempotency-Key，因此响应不明确时执行 exact replay，而不是发起第二次 Create。

Disk Item Lookup 要求 Create 或 List 返回的不可变 `disk_…` ID；Item Path 不接受名称。

## 磁盘快照

    cats disk snapshot create project-data before-upgrade
    cats disk snapshot list
    cats disk snapshot show before-upgrade
    cats disk snapshot restore before-upgrade
    cats disk snapshot destroy before-upgrade

DiskSnapshot 是一个 PersistentDisk 的远端恢复点，不是 VM 内存快照。创建和恢复时磁盘必须已经远端持久且 Unowned；如果磁盘已绑定 Cat，该 Cat 必须稳定处于 Cold。恢复会把捕获的数据发布为一个新的、更高的磁盘 Generation，不会让 Generation 倒退。它会替换原盘的当前内容，不会克隆新盘。

Snapshot Row 同时也是 GC Root。删除后即撤销这份保护；只要当前磁盘或另一个 Snapshot 仍引用共享对象，对象就继续保留。Snapshot Slug 仅可在删除后复用，不可变 `snapshot_…` ID 永不复用。

容量仍不可变。Provider-neutral Storage Engine 与 Volume Authority 继续强制执行 RWO、Fencing、Durable Root 与 Stale Writer 拒绝；Product Client 不能自行 Acquire 或 Revoke Writer Epoch。

## Durability

Guest 看到标准 virtio Block Device。Strict 表示成功的 FLUSH/FUA 已远程持久，永久丢失 Host 后仍可恢复。Relaxed 可能在 Remote Root 落后时确认 Local Commit；这段 Local Tail 是唯一数据，不能当作 Cache 丢弃。

过期 Attachment Epoch 无法发布新 Root。Lifecycle Coordination 与 Takeover 必须走 Typed External Authority；Product Client 不能自行 Acquire 或 Revoke Epoch。
