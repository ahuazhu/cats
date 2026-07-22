## 四种状态

| 状态          | 进程内存                      | 绑定 Host | 返回 Running          |
|---------------|-------------------------------|-----------|-----------------------|
| **Running**   | 按需驻留                      | 是        | 已经活跃              |
| **Suspended** | 保留；内存页可换出到本地 NVMe | 是        | Resume 并按需缺页读回 |
| **Warm**      | 保留在本地 VM 快照；VMM 退出  | 是        | 重建运行时并 Restore  |
| **Cold**      | 不保留                        | 否        | 从持久磁盘全新启动    |

Suspended 与 Warm 有意保持为两种状态。两者都保留进程状态并依赖原 Host；Cold 解除该依赖，启动新的 Kernel 与用户进程。

**当前源码限制**

Suspended 的定义是 Pause + page-out，但当前 Cloud Hypervisor Phase-A 实现只执行 Pause。它会保留进程状态并节省 vCPU，但尚不能回收 Host 内存。

## 生命周期命令

    cats start dev
    cats suspend dev
    cats warm dev
    cats resume dev
    cats stop dev
    cats get dev

- `start` 启动或唤醒 Cat。
- `suspend` 在持久磁盘门禁通过后暂停 Guest。产品状态包含 page-out，但当前 Cloud Hypervisor Phase-A 路径仍只执行 Pause，尚不能回收 Host 内存。
- `warm` 创建 Host 本地快照并退出 VMM/Backend。
- `resume` 可恢复 Suspended 或 Warm。
- `stop` 进入 Cold 并释放运行时 Attachment Lease。

## 持久性门禁

进入 Suspended、Warm 或 Cold 前，Cats 会停止新工作、要求 Guest 同步文件系统，并等待所需的块设备 FLUSH 发布 durable generation。FLUSH 失败时，平台不能宣称已经进入安全休眠状态。

**Host 丢失后保留什么？**

成功 durable FLUSH 的数据会保留。Suspended/Warm 进程内存不会：原 Host 永久丢失后，Cats 会 fence 旧 Attachment，并在其他 Host 上执行 Cold Recovery。

## 快速恢复回退

Backing file 缺失、快照损坏、版本不匹配、VMM 错误或 Guest readiness 超时，都不能让 Cat 卡在恢复中间态。平台会丢弃不安全的本地状态，在需要时获取更高磁盘 fencing epoch，并收敛到 Cold 启动。

## 工作驱动自动休眠

新建 Cat 默认开启。可以查看状态、为常驻任务关闭，或再次开启：

    cats create dev
    cats sleep status dev
    cats sleep off dev
    cats sleep on dev

状态输出包括分布式工作数量、Guest 信号是否新鲜、当前是否符合条件及原因。信号链过期或不确定时，安全行为是 fail-awake。后台任务必须持有 Guest Work Lease，或者显式关闭自动休眠。

## 连接与时间

保留 Guest 内存并不承诺旧 TCP 或 WebSocket 连接仍然存在。Edge、NAT 与远端对端可能在休眠期间超时。客户端应通过稳定 Endpoint 重新连接。Guest 时间在 pause/resume 后不能倒退。

## 删除

`cats destroy dev` 会停止新工作、完成生命周期 Operation、删除 Cat，并级联删除 RootDisk。它会安全卸载，但不会删除独立 PersistentDisk。
