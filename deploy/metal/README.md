# 在 AWS 裸金属上部署真 microVM

Phase A 形态（正确性优先）：Cloud Hypervisor 直接内核启动真 Guest；磁盘链路
`guest virtio-blk → CH raw disk → /dev/nbdN（内核 NBD client）→ cats-blockd →
BlobStore port → AWS S3/File adapter`；Guest Agent 走 vsock；Suspended=vm.pause，Warm=vm.snapshot
+ 全进程退出，Restore=--restore。原生 vhost-user-blk 与 tap Guest 网络是下一
个性能/网络里程碑，不改变提交协议。

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
initramfs + busybox/guest-agent golden rootfs）、装 systemd 单元并启动。

## 4. 验收

```bash
sudo deploy/metal/e2e.sh
```

断言（全部基于**真实内核 boot_id**）：create→Running、guest 内核版本=直接启
动的内核、写文件+sync、suspend/resume 同 boot、warm 后无常驻 VMM、restore 同
boot 且文件在、stop/start 换 boot 且数据从 durable 层恢复、destroy。

2026-07-21 的 AWS i4i.metal + 真实 S3 验收结果与失败诊断记录保存在
[`experiments/metal-e2e-20260721/`](../../experiments/metal-e2e-20260721/README.md)：
最终 `17 passed, 0 failed`。这是单次正确性验收，不是性能样本或生产 SLA。

手动玩法与本地 CLI 相同（`cats create/exec/suspend/warm/...`）。

## 5. 已知边界（Phase A）

- Guest 无 tap 网络（Endpoint/HTTP 演示仅 FakeVmm 形态可用）；exec/健康走 vsock。
- 磁盘热插拔在 CH 模式暂不支持（停机挂载生效）。
- 单节点单元（`metal-1`）；多金属节点 = 每台跑 install.sh + 唯一 --node-id，
  指向同一 control plane 与 S3（storage-meta 需共享→生产 PostgreSQL 项）。
- noded 以 root 运行（KVM/NBD 需要）；特权拆分是加固里程碑。

## 6. 回收

```bash
aws ec2 terminate-instances --instance-ids i-xxxx
```
