# ADR-0023：systemd 是默认 Guest PID 1

- 状态：Accepted
- 日期：2026-07-30

## 背景

Cats 的 Ubuntu golden root 已经安装 systemd，也已经包含
`cats-guest-agent.service`，但 initramfs 过去优先
`switch_root` 到 `cats-init → tini → cats-guest-agent`。因此 systemd 不是 PID 1：
用户安装并 enable 的普通 Linux service 和 systemd timer 不会运行，cgroup、journal
等 systemd 提供的 Guest 运行时能力也没有真正启用。

2026-07-30 的受控 A/B 只改变 PID 1，在真实 AWS `c5d.metal`、KVM、Cloud
Hypervisor、kernel-NBD、真实 S3/PostgreSQL 和 `strict` durability 上各运行五次
Suspend、Warm 和 Cold：

- Warm restore P50：direct-init 386 ms，systemd 379 ms，未观察到实质回归；
- Cold start P50：10.291 s → 13.314 s，systemd 增加约 3.023 s；
- 首次 create 各一个样本：16.905 s → 18.325 s，增加约 1.420 s；
- 普通 `Type=simple` enabled unit 在 Warm 后保留同一 PID 且没有重复启动，在 Cold
  后由 systemd 启动一次。

原始边界、样本和正确性判据见
[`experiments/systemd-pid1-20260730`](../../experiments/systemd-pid1-20260730/README.md)。
这些数字是该环境的实验结果，不是生产 SLA。

## 决定

1. Cats 发布的 Ubuntu Guest 默认以 `/sbin/init` 启动 systemd。最小 BusyBox
   initramfs 只负责加载固定 virtio/ext4/vsock 模块、挂载 RootDisk 和
   `switch_root`，不再绕过 Guest service manager。
2. Guest Agent 仍是平台 readiness 边界，但以早期 systemd unit 运行：
   - `cats-mount-propagation.service` 先建立 Guest 挂载传播隔离；
   - `cats-grow-root.service` 先扩容 RootDisk；
   - `cats-network.service` 从 Node 写入的 virtio-net MAC 确定性配置 `/30` 地址；
   - `cats-guest-agent.service` 在两者完成后启动，并保持
     `Before=sysinit.target`；
   - 它不等待 `multi-user.target`、`network-online.target`、cloud-init 或用户服务。
3. systemd 以 Host manager 身份启动时会把 `/` 递归设为 shared；这与历史 direct-init
   的 private 根挂载不同。Cats 在 `systemd-remount-fs.service` 之后、所有平台 early
   unit 和普通用户 service 之前执行 `mount --make-rprivate /`。发布契约为：
   - `/`、`/dev` 和 `/dev/shm` 都是 private propagation；
   - `/dev/shm` 是 root 拥有、mode 1777 的 tmpfs；
   - 用户在 chroot/container 内对 `/dev` 做 recursive bind，再卸载任意子树，不得把
     unmount 事件传播回 Guest 或另一个 peer tree；
   - uid 非 0 的 Guest 进程仍可创建 POSIX shared memory。
   direct 诊断 init 显式执行同一条命令，避免诊断模式形成不同的 Guest contract。
4. 通用 Ubuntu 后台事务不能重新进入 Cold-to-Agent 关键路径。golden root 不安装
   cloud-init、snapd 或 LXD；mask `systemd-networkd-wait-online`、apt 自动更新 timer
   和不存在设备对应的 `serial-getty@ttyS0`。平台拥有的 tap 地址由
   `cats-network.service` 配置，默认不另启 systemd-networkd 竞争同一接口。
5. 用户可以使用普通 systemd unit、target、journal 和 cgroup：
   - Running 时按普通 Linux 语义运行；
   - Suspended/Warm 保留同一 Guest 内核与 userspace，service 不重启；
   - Cold 丢弃所有进程；下一次 fresh boot 由 systemd 重新启动 enabled service；
   - Warm restore 失败仍按 ADR-0002 收敛到 Cold，因此 service 会按一次新 boot 重启。
6. `Guest Agent Ready` 与 `User Service Ready` 是不同边界。`cats create/start` 当前
   仍以 Guest Agent readiness 收敛；用户 unit 可以在此之后继续初始化。Endpoint 或
   应用级 readiness 必须单独测量，不能把 systemd 达到 `multi-user.target` 当作平台
   Agent readiness。
7. systemd timer 只在 Guest 能执行时运行，本身不是 Cats 的外部唤醒源。Cat 已
   Suspended/Warm/Cold 时，仍需 Endpoint、shell/exec、显式 start 或未来的控制面
   schedule 先唤醒。Cold 后 `Persistent=true` 是否补跑遵循 systemd 自身的磁盘状态
   与墙钟语义。
8. Cats 当前 Cold stop 只承诺 Guest syncfs、durable FLUSH 和运行时清理；它尚未承诺
   为每个用户 unit 执行无界的 `ExecStop`。需要优雅停机的应用应在收到自己的终止信号
   后自行收敛，或等待未来有严格 deadline 的 pre-stop 契约。
9. `GUEST_INIT_MODE=direct` 只为复现历史实验和诊断保留，默认值和产品支持契约都是
   `systemd`。它不能用于宣称用户 systemd service 已受支持。

## 验收

真实 KVM/Cloud Hypervisor metal 验收必须同时证明：

- `/proc/1/comm` 是 `systemd`，Guest Agent unit 为 active；
- `findmnt` 报告 `/`、`/dev`、`/dev/shm` 为 private，`/dev/shm` 是 mode 1777；
- 两个真实 chroot 对 `/dev` 做 recursive bind 后，deepest-first lazy unmount 其中
  一个，Guest 和另一个 chroot 的 `/dev/shm` 仍 mounted；
- uid 70 能创建 POSIX shared memory，真实 PostgreSQL 17 能 stop 后 restart；
- DNS/HTTPS 出站、RootDisk 在线扩容和 vsock readiness 不因切换 PID 1 退化；
- 普通 enabled `Type=simple` unit 初始启动一次；
- Suspend/Resume 和 Warm/Restore 保留其 PID 与启动计数；
- Cold boot 改变 kernel boot ID，enabled unit 的持久启动计数恰好增加一次；
- durable canary 跨 Warm/Cold 保持。

## 后果

- 用户可以按标准 Ubuntu 方式安装并运行长期 service，不需要 Cats SDK 或私有进程
  supervisor。
- systemd、journald 和 cgroup 会增加一些 Guest 启动与运行开销；已测主要影响在 Cold
  启动，必须继续分开报告 Agent Ready 与 Service Ready。
- 修复需要重建并发布包含 early propagation unit 的 golden root。当前 NodeRuntime
  在进程内缓存已发布的 golden image id，所以节点必须先 drain，再受控重启
  `cats-noded` 以发布/使用新 image；不需要重建 Host OS 或重启整台 worker。
- 已经从旧 golden root 创建的持久 RootDisk 不会因 channel 更新而自动 rebase。它们
  必须由通用迁移在 Guest 内安装/enable 同一 early unit 后 Cold boot，或显式重建；
  不能用未授权的 worker restart 代替这一步。回滚是恢复上一 golden 并按相同流程重启
  `cats-noded`，但会重新暴露 shared-mount 兼容性回归。
- 旧 RootDisk 在下一次 Cold boot 使用新 initramfs 时也会进入其已有的 `/sbin/init`；
  Suspended/Warm 状态不跨 VMM/镜像版本升级，仍按 ADR-0002 在节点升级前转 Cold。
