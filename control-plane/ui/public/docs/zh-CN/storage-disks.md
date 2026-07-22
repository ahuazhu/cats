## 磁盘类型

|            | RootDisk            | PersistentDisk                        |
|------------|---------------------|---------------------------------------|
| 创建       | 随每个 Cat 自动创建 | 显式创建，或通过 `cats create --disk` |
| 生命周期   | 随 Cat 删除         | 独立存在，直到显式删除                |
| Guest 设备 | 系统盘              | 挂载到指定路径的额外块设备            |
| 访问       | 归所属 Cat 使用     | RWO：V1 只有一个活跃写者              |

## 创建并查看 PersistentDisk

    cats disk create project-data --size 20GiB
    cats disk ls
    cats disk get project-data

也可以同时创建 Cat 与独立磁盘：

    cats create dev \
      --disk project-data \
      --disk-size 20GiB \
      --mount-at /data

## 挂载与卸载

    cats mount project-data --cat dev --at /data
    cats unmount project-data

挂载会创建带单调递增 fencing epoch 的运行时 Attachment。卸载会先同步并 detach，再让磁盘回到 Available。即使两个写者修改不同逻辑块，V1 也会拒绝第二个读写 Attachment，因为 ext4 文件系统本身仍是单写者。

## 扩容磁盘

    cats disk resize project-data --size 40GiB

V1 只支持增大容量。如果当前运行路径要求磁盘处于 Available，请按 API 的前置条件先卸载。绝不能在 ext4 下方缩小卷。

## 创建快照

    cats disk snapshot project-data

控制面先建立 durable barrier，再记录不可变 Root 与 generation。当前 CLI 会创建并打印 Snapshot 响应；此源码 CLI 尚未提供快照列表/Restore 的便利命令。

## 持久性与缓存语义

Guest 只看到标准 virtio 块设备。普通写入可以完成于受控本地缓存，但 FLUSH/FUA 成功必须等待不可变对象持久化并完成权威 Root CAS。此后本地 NVMe 只是可删除缓存。

- 少量 dirty 工作集不会上传完整稀疏磁盘。
- 空缓存恢复只会按 ext4 读取请求懒加载逻辑 Chunk。
- 过期 Attachment epoch 无法发布新 Root。
- 未 FLUSH 的 Guest Page Cache 或普通写在 Host 永久损坏时允许丢失。

## 安全删除

    cats unmount project-data
    cats disk delete project-data

**永久操作**

磁盘必须处于 Available。删除会撤销访问并调度远端对象清理；如需保留，请先创建快照或导出数据。
