# 在 AWS 裸金属上部署真 microVM

Phase A 形态（正确性优先）：Cloud Hypervisor 直接内核启动真 Guest；磁盘链路
`guest virtio-blk → CH raw disk → /dev/nbdN（内核 NBD client）→ cats-blockd →
BlobStore port → AWS S3/File adapter`；Guest Agent 走 vsock；Suspended=vm.pause，Warm=vm.snapshot
+ 全进程退出，Restore=--restore。每个 Cat 有独立 tap `/30` 和 Host SNAT 出站；
公网 HTTP Endpoint 经 owning Node 进入 Guest tap。跨节点 overlay 与 WebSocket 入站仍是
后续里程碑，不改变提交协议。

原生 vhost-user-blk 路径已实现并在本机型上验收（ADR-0015）：在 `/etc/cats/cats.env` 里设
`CATS_BLOCK_PATH_ARGS=--ch-block-path vhost-user --ch-vhost-user-queues 4`，磁盘链路变成
`guest virtio-blk → CH vhost-user-blk client → cats-blockd`，不再需要 `nbd` 内核模块或
`/dev/nbdN`（队列数会自动夹到每个 Cat 的 vCPU 数，CH 拒绝 `num_queues > vCPU`）。
两条路径在 i4i.metal 上跑同一套 `e2e.sh` 都是 22/23，含 Warm snapshot/restore；
vhost-user 的 Warm restore 快 1.8×、随机读 p50 更低，但按当前形态（CH 带缓冲打开
`/dev/nbdN`）NBD 的写吞吐更高，所以**默认仍是内核 NBD**。数据与根因见
`experiments/vhost-user-blk-frontend-20260726/README.md`。

多节点：每台跑一次 `install.sh`，然后在 `cats.env` 里给每台唯一的 `CATS_NODE_ID`、
`CATS_NODE_LISTEN`、`CATS_NODE_ADVERTISE_URL`，并让所有节点指向同一个
`CATS_CONTROL_PLANE_URL` 以及**同一套共享 storage-meta 与 object store**（PostgreSQL + S3；
SQLite 和 file adapter 是每台主机私有的，跨节点迁移不可能成立）。双节点验收见
`experiments/metal-cluster-20260726/README.md`。

## 1. 开机器

- **实例**：x86_64 裸金属，如 `c5.metal`（≈$4.08/h）或 `i4i.metal`（本地
  NVMe，≈$10.9/h）。必须 metal（需要 /dev/kvm）。
- **AMI**：Ubuntu 22.04/24.04 LTS x86_64。
- **安全组**：只开 22 端口（SSH）。所有 Cats 服务默认只听 127.0.0.1（网关
  0.0.0.0:7400，若不需要外网 Endpoint 也可改回本地）。
- **磁盘**：根卷 ≥100 GiB gp3（编译 + 缓存）。

```bash
aws ec2 run-instances \
  --image-id $(aws ssm get-parameter --name \
      /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
      --query Parameter.Value --output text) \
  --instance-type c5.metal \
  --key-name YOUR_KEY \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=100,VolumeType=gp3}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=cats-metal}]'
```

## 2. S3 durable 层（推荐）

```bash
aws s3 mb s3://YOUR_BUCKET
# 建一个只有该桶权限的 IAM 用户，生成 Access Key，填进 /etc/cats/cats.env
```

不配 S3 时默认本地文件 BlobStore（`/var/lib/cats/blob`）——功能完整但不具备
跨 Host 持久性。

## 3. 安装

```bash
ssh ubuntu@<ip>
git clone <this-repo> cats && cd cats     # 或 rsync 本地检出
sudo deploy/metal/install.sh              # 依赖+编译+CH+guest镜像+systemd
sudoedit /etc/cats/cats.env               # 配 S3（可选）后:
sudo systemctl restart cats-noded
```

`install.sh` 做的事：apt 依赖、rustup、`cargo build --release`、下载
cloud-hypervisor 静态二进制（`CH_VERSION` 可覆盖，默认 v53.0，与实验一致）、
`modprobe nbd nbds_max=64`、构建 Guest 三件套（宿主内核 vmlinuz + 最小
initramfs + Ubuntu 24.04 minbase/guest-agent golden rootfs）、装 systemd 单元并启动。

Guest 的 BusyBox 只存在于 initramfs，用来加载 virtio/ext4/vsock 并
`switch_root`。用户进入的是完整 Ubuntu root，默认包含 `apt`、`curl`、`git`、
`wget`、`iproute2`、`ping`、`procps`、`nano` 和 OpenSSH client。`cats shell`
默认启动 login Bash，启用 256 色 prompt、Readline 路径补全和
`bash-completion`（后续安装的 `gh` 等软件可直接注册自己的补全）。systemd 是默认
PID 1，普通 enabled service 会在 `multi-user.target` 正常启动；根盘扩容、确定性的
tap `/30` 配置和 Guest Agent 是 `sysinit.target` 之前的早期 unit，所以 Agent
readiness 不等待完整 multi-user transaction。未使用的 serial getty、wait-online 和
apt timer 已 mask。golden root 默认 512 MiB，首次启动会把 ext4 在线扩到用户请求的
RootDisk 大小；因此生产创建建议至少 1 GiB。`GUEST_INIT_MODE=direct` 仅用于复现
历史实验，不是默认产品形态。

`cats-noded` 启动时默认探测 Host 的逻辑 CPU 与内存总量作为可调度容量；管理员页面
同时展示 Host CPU、内存和节点状态目录所在文件系统的实时使用量。若需要给 Host
保留资源，可在环境文件中设置 `CATS_NODE_CPUS` / `CATS_NODE_MEMORY_MIB` 降低调度上限。

## 4. 验收

```bash
sudo deploy/metal/e2e.sh
```

断言（全部基于**真实内核 boot_id**）：create→Running、systemd PID 1、
Guest Agent unit active、guest 内核版本=直接启动的内核、DNS/HTTPS 出站、写文件+sync、
普通 enabled service 在 Suspend/Warm 不重启、Cold 后恰好再启动一次、warm 后无常驻
VMM、restore 同 boot 且文件在、stop/start 换 boot 且数据从 durable 层恢复、destroy。

2026-07-21 的 AWS i4i.metal + 真实 S3 验收结果与失败诊断记录保存在
[`experiments/metal-e2e-20260721/`](../../experiments/metal-e2e-20260721/README.md)：
最终 `17 passed, 0 failed`。这是单次正确性验收，不是性能样本或生产 SLA。

手动玩法与本地 CLI 相同（`cats create/exec/suspend/warm/...`）。

## 5. 已知边界（Phase A）

- Guest 已有单节点 tap + SNAT 出站和公网 HTTP Endpoint → tap 入站；跨节点私网
  overlay 和 WebSocket 入站尚未实现。Guest 默认不能访问 Host、VPC 私网或云
  metadata；exec/健康仍走 vsock。
- 磁盘热插拔在 CH 模式暂不支持（停机挂载生效）。
- 单节点单元（`metal-1`）；多金属节点 = 每台跑 install.sh + 唯一 --node-id，
  指向同一 control plane 与 S3（storage-meta 需共享→生产 PostgreSQL 项）。
- noded 以 root 运行（KVM/NBD 需要）；特权拆分是加固里程碑。

## 6. 回收

```bash
aws ec2 terminate-instances --instance-ids i-xxxx
```
