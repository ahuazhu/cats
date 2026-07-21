# Cats Rust 全栈 AWS 裸金属验收（2026-07-21）

本目录保存生产 Rust 组件第一次在 AWS 裸金属上完成真实 microVM 生命周期闭环的验收证据。最终运行结果为 **17 passed, 0 failed**。

## 环境与测量边界

- AWS `i4i.metal`，`us-east-1`，Ubuntu 24.04 x86_64。
- Linux `6.17.0-1019-aws`，`/dev/kvm` 可用。
- Cloud Hypervisor `v53.0`。
- `cats-controld`、`cats-noded`、`cats-blockd`、`cats-guest-agent`、`cats-gatewayd` 与 `cats` CLI 均从本仓库 Rust workspace 构建。
- Durable BlobStore 使用同 Region 的临时真实 AWS S3 bucket；Guest 没有 S3 或 metadata 凭证。
- Phase-A 块路径：`Guest ext4 → virtio-blk → Cloud Hypervisor raw disk → /dev/nbdN → cats-blockd → S3`。
- 本次每个生命周期场景只有 1 个正式样本，只验证正确性，不测 P50/P95/P99，也不是生产 SLA。

## 正确性判据

1. `create` 收敛到 Running，Guest 报告的 kernel release 与 Host 直接启动内核一致。
2. Guest 提供非空真实 kernel boot ID。
3. Guest 写 `/data.txt` 后 `sync` 成功。
4. Suspended = `vm.pause/resume`，前后 boot ID 相同。
5. Warm = snapshot + VMM 退出；Warm 状态不存在 Cloud Hypervisor 进程，restore 后 boot ID 相同且文件存在。
6. Cold stop/start 产生新的 boot ID，已 flush 文件从 durable 层恢复。
7. destroy 成功，最后无 Cloud Hypervisor 进程和已连接 NBD 设备。

正式输出见 [`raw/e2e-run6.log`](raw/e2e-run6.log)，环境摘要见 [`raw/environment.txt`](raw/environment.txt)。失败运行也完整保留在 `raw/`，用于说明真机验收实际发现并关闭的问题。

## 真机验收发现的问题

| 运行 | 现象 | 根因与修复 |
|---|---|---|
| run 1 | root seed 经 NBD 返回 `errno 5` | MinIO 的 HTTP 测试没有覆盖真实 S3 HTTPS；为 reqwest 启用 rustls TLS，并把子进程 stderr 落盘。 |
| run 2–3 | CH API socket 被误报超时，后续重试出现 socket in use | 修正 `vmm.ping` endpoint；Node 在 readiness 前先持有 Child 以便失败清理；HTTP 客户端按 `Content-Length` 读取，不能等待 CH keep-alive 连接 EOF。 |
| run 3 | Guest 已启动，但 vsock address family 不可用 | Ubuntu kernel module 是 `.ko.zst`，BusyBox `insmod` 不会解压；构建 Guest 镜像时先解压依赖模块。 |
| run 4 | Guest Agent 打印 `READY` 后立即退出 | `UnixListener::incoming()` 不能解析 AF_VSOCK peer address；改为 `accept4(..., NULL, NULL)`，字节流继续复用相同 framing。 |
| run 5 | 功能 16/16 通过，仅 VMM residency 断言误报 | 宽松 `pgrep -f` 匹配到参数中含 CH path 和测试名的 `cats-noded`；改为匹配 CH 可执行文件开头。 |
| run 6 | 17/17 通过 | 最终正式正确性结果。 |

另一个真机兼容修复是为 CH v53 的 NBD raw disk 显式指定 `image_type=raw`，避免自动检测路径对 ext4 扇区 0 写入产生保护行为。

## 资源回收

正式运行完成后先确认无 VMM/NBD 泄漏，再终止临时裸金属实例并删除临时 SSH key pair、安全组、IAM 凭证/用户和 S3 bucket。资源标识与凭证不写入仓库。
