# systemd Guest 挂载传播回归

## 结论

现场证据确认这是 Cats PR #42 切换默认 PID 1 后暴露的 Guest 兼容性回归，不是
Paperboy PR 业务代码。systemd 255 在作为 Host manager 启动时把 `/` 递归改成
shared；Paperboy 对两个 chroot 执行真实 `mount --rbind /dev` 后，deepest-first
`umount -l` 旧 root 会把 unmount 传播回 Guest 和另一个 peer。Guest `/dev/shm`
不再是 mounted tmpfs，看到的是 devtmpfs 下 mode 755 的底层目录；uid 70 因而不能
创建 shared-memory object，PostgreSQL 17.10 重启报：

```text
FATAL: could not open shared memory segment "/PostgreSQL.682784492": Permission denied
```

同一 Cat、RootDisk 和 Guest image 只把 `/sbin/init` 暂时切到 Cats direct-init 后，
`/`、`/dev`、`/dev/shm` 都是 private；相同 recursive bind/unmount 只影响旧 root，
Guest 和另一个 chroot 保持 mounted、1777，uid 70 与 PostgreSQL 17 均通过。

## 边界与环境

- 日期：2026-07-31，时区 Asia/Shanghai。
- 仓库基线：`main` commit `2f073a8`。
- 现场：`paperboytm-stage` workspace，当前生产 Ubuntu 24.04 Guest image，
  systemd `255 (255.4-1ubuntu8)`，PostgreSQL `17.10`。
- 主要 A/B Cat：自动过期的一次性 `cats-mountprop-0731`。没有修改或重启
  PR 3085、3120、3121 的 Cat，也没有重启 worker 或部署生产。
- 修复命令确认 Cat：自动过期的一次性 `cats-mountprop-fixed-0731`。它使用同一
  当前生产 Guest image，只在该 Cat 内运行与新 early unit 相同的
  `mount --make-rprivate /`；oracle 通过后已正常 destroy。这不是 golden image 发布。
- 修复后 metal：隔离的一次性 AWS `c5d.metal`，默认 VPC、无 IAM role、只允许
  调查机 `/32` SSH。它从当前
  worktree 构建新 golden root，并只运行本地 file/SQLite Cats stack；没有连接生产
  S3、RDS、控制面或 Paperboy workspace。
- 样本是正确性复现，不是可推广的性能或可用性样本。

第一次 Cat 在收集完 systemd/direct A/B 后的一次 Cold stop 长时间停在
`observed=stopping`（operation `op_4598765ec42e`）。调查没有重启生产 worker；
最终已提交 delete operation `op_94673da0333d`，资源为 `desired=deleted`，但
`observed` 仍在 `stopping/running` 间重试，自动过期继续作为回收兜底。这个 stop
控制面问题与 mount propagation 根因分开记录，不把它解释为 PostgreSQL oracle。

## 方法

1. chroot 前采集 PID 1、`findmnt`、`stat` 和 uid 70 写 `/dev/shm`。
2. 创建两个普通目录 root，分别执行真实 `mount --rbind /dev ROOT/dev`。
3. 对旧 root 的真实挂载从深到浅执行 `umount -l`，再检查 Guest 与 replacement
   root。
4. 在真实 PostgreSQL 17 上执行 stop、旧 root mount teardown、restart。
5. 同 RootDisk 只切换 PID 1，比较 systemd 与 direct-init。
6. 修复侧在新的当前-image Cat 内执行精确修复命令，再由
   `deploy/metal/guest-mount-propagation-e2e.sh` 构造两个最小真实 chroot，
   以 uid/gid 70 启停两个 PostgreSQL cluster。

仓库中的 metal driver `deploy/metal/mount-propagation-e2e.sh` 会从修复后的
golden root 创建独立、自动过期的真实 Guest，安装 PostgreSQL 17，并驱动同一 oracle。
常规 `deploy/metal/e2e.sh` 继续覆盖 systemd readiness 和 service 跨 Warm/Cold 语义。

发布时必须重建 golden root，并在节点 drain 后重启 `cats-noded` 来清除其进程内缓存
的 seed image id；不需要重建 Host OS 或重启整台 worker。旧 RootDisk 不会自动
rebase，必须显式安装同一 unit 后 Cold boot 或重建。此调查没有执行这些生产动作。

## 因果证据

systemd v255 的 `mount_setup_early()` 在 Host manager 路径明确调用：

```c
mount(NULL, "/", NULL, MS_REC|MS_SHARED, NULL)
```

上游源码：
[`src/shared/mount-setup.c`](https://github.com/systemd/systemd/blob/v255/src/shared/mount-setup.c)。
这解释了为什么在 initramfs 或 direct-init 时代观察到的 private 根挂载，切换到
systemd PID 1 后变成 shared；现场 mount peer 与 unmount 传播则证明该差异在 Cats
Guest 中确实产生了故障，而不只是源码推断。

## 原始记录

- [`raw/systemd-before.log`](raw/systemd-before.log)：systemd shared 基线的关键字段、
  双 chroot 传播损坏与 PostgreSQL FATAL。
- [`raw/direct-control.log`](raw/direct-control.log)：同 RootDisk 的 direct-init
  private 对照。
- [`raw/systemd-after-command.log`](raw/systemd-after-command.log)：当前生产
  systemd Guest 内执行精确修复命令后的 oracle。
- [`raw/metal-golden-after.log`](raw/metal-golden-after.log)：修复烘入 golden root
  后的 unit 状态、真实 bind/unmount 和 PostgreSQL 17 oracle。
- [`raw/metal-lifecycle.log`](raw/metal-lifecycle.log)：原有 systemd、Guest Agent、
  Suspend、Warm、Cold 验收。

日志只保留与判据有关的完整命令输出字段；长 mount option 中没有作为判据的容量字段
没有从终端转录到 direct 对照。当前调查没有部署生产。
