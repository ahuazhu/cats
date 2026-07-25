# Cats

Cats 是一个从零实现的独立项目：为用户提供可休眠、可迁移、带持久块设备和稳定网络入口的 Linux microVM。

仓库包含**完整的 Rust workspace 实现**与全部设计文档、实验证据：存储引擎（Direct-OS ChunkStore，AWS S3 adapter 可经 MinIO 联测）、带项目隔离和管理员 fleet API 的控制面、独立的用户与管理员 Web 控制台、node-agent（FakeVmm + **Cloud Hypervisor 真 microVM 模式**）、guest-agent（vsock）、CLI、Endpoint 网关，以及覆盖 adapter 契约、崩溃注入、fencing、跨项目鉴权、节点排空和跨节点冷恢复的自动化测试。Cloud Hypervisor Phase-A 路径另有 17 项 AWS 裸金属验收记录；部署与证据见 [deploy/metal/](deploy/metal/README.md)。

## Greenfield 边界

- 不复制或继续维护原 `cat.dev` (~/work/cat.dev) / `dozyfs` 的控制面、Agent、文件系统或 UI 代码。 但可以参考端到端的测试集，用于本项目的正确性验证。
- 旧项目只作为历史经验，不是新实现的依赖或兼容目标。
- 用户和公开 API 统一使用 `cats` 命名。
- Guest 看到普通 virtio block device 和 ext4；S3、NVMe Cache、Chunk/Manifest 与租约均为平台内部实现。
- 存储后端已选定为 Direct-OS ChunkStore（Direct-S3 实现，[ADR-0003](docs/decisions/0003-direct-s3-chunkstore-backend.md)）；JuiceFS 方案不再实现，仅作历史参考。
- 存储依赖边界采用 Ports and Adapters（[ADR-0005](docs/decisions/0005-provider-neutral-storage-ports-and-adapters.md)）：核心只依赖云无关契约，AWS S3 是第一版 durable adapter。
- 生命周期状态统一为 Running / Suspended / Warm / Cold（[ADR-0002](docs/decisions/0002-lifecycle-states-running-suspended-warm-cold.md)）。
- 浏览器身份使用 WorkOS AuthKit；CLI 使用 WorkOS Device Login，内部服务使用独立机器 Bearer Token（[ADR-0006](docs/decisions/0006-workos-authkit-for-browser-identity.md)、[ADR-0008](docs/decisions/0008-workos-device-login-and-cli-workspaces.md)）。
- Guest 可选运行时能力使用 Unix socket 上的标准 HTTP，不要求 Cats SDK/CLI 或固定 TCP 端口（[ADR-0007](docs/decisions/0007-guest-runtime-http-over-unix-socket.md)）。
- `cats shell` 使用受 Workspace 鉴权的 WebSocket PTY，不在 Guest 运行 sshd（[ADR-0009](docs/decisions/0009-interactive-shell-over-authenticated-websocket.md)）。
- 每个 Cat 创建时自动获得稳定的 `*.cats.run` HTTPS URL，默认转发 Guest 8080 并按请求唤醒（[ADR-0010](docs/decisions/0010-default-http-endpoint-per-cat.md)）。

具体边界记录在 [`ADR-0001: Greenfield implementation baseline`](docs/decisions/0001-greenfield-implementation-baseline.md) 及后续 ADR。

## 建议阅读顺序

1. [Cats 完整产品与技术架构](docs/cats-complete-product-technical-architecture.html)
2. [Direct-S3 ChunkStore 详细设计](docs/direct-s3-chunkstore-architecture.html) —— 已选定存储基线（ADR-0003）
3. [Cats 睡眠、唤醒与 VMM 资源回收](docs/cats-sleep-wake-vmm-resource-reclamation.html) —— 四态生命周期（ADR-0002）
4. [2026-07-21 存储与生命周期实验总报告](docs/experiments-2026-07-21-storage-lifecycle.md)
5. [Cats 存储架构设计](docs/cats-storage-product-blueprint.html) —— JuiceFS 方案，历史参考（未采用）
6. [Sprite 小文件存储路径参考](docs/sprite-storage-flow.html)

各文档的状态和关系见 [docs/README.md](docs/README.md)。

## 已有实验

| 实验 | 回答的问题 | 入口 |
|---|---|---|
| Lazy ext4 over ChunkStore | 100 GiB 虚拟盘和 10 万小文件是否需要整盘上传；删掉本地 Cache 后能否按需恢复 | [experiments/lazy-ext4-demo](experiments/lazy-ext4-demo/README.md) |
| VM lifecycle benchmark | EBS 与本地 NVMe 的 Warm restore、pause + page-out、完整 Cold、Direct-S3 的正确性与性能 | [experiments/warm-snapshot-benchmark](experiments/warm-snapshot-benchmark/README.md) |

正式数据、环境报告和原始日志索引见 [experiments/README.md](experiments/README.md)。

## 当前证据支持的基线

- 虚拟化：KVM + Cloud Hypervisor，Guest 使用未修改的 Linux/ext4。
- 块数据面：`virtio-blk -> vhost-user-blk -> cats-blockd`（ADR-0015；Phase A 的内核 NBD 路径仍是默认值，两条路径共用同一提交协议与卷格式）。
- 存储：对象存储保存 durable truth，本地 NVMe 是可删除的稀疏读写 Cache；只提交 dirty logical Chunk，不 dump 整块虚拟盘。后端为 Direct-OS ChunkStore（Direct-S3 实现，ADR-0003）。
- 磁盘：每个 Cat 有生命周期一致的 RootDisk；可选一块跨 Cat 持久化的 RWO PersistentDisk。
- Suspended（pause + page-out）：本轮唤醒约 0.21–0.23 秒，VMM 保留。
- 并发唤醒按 resume commitment 字节数计入节点预算并有界排队（ADR-0002 §8）；默认取实验验证点 10 并发，`ResumeCat` 已可节点内并发。
- Warm（snapshot + VMM/backend exit）：本地 NVMe 唤醒约 0.38–0.40 秒，进程状态保留且无常驻 VMM。
- Cold：直接内核、精简 initramfs、提前网络和 Agent，本轮完整新内核/新进程 P50 为 1.755 秒。
- Direct-S3：语义原型成立，当前串行 Python 实现约 39.87 秒，只用于验证和定位瓶颈。

这些数字不是生产 SLA（AWS metal 实验口径）。本仓库的自动化测试已经覆盖：跨节点空 Cache 恢复、租约 fencing/僵尸写拒绝、FLUSH 各窗口 kill -9 崩溃恢复——但均在 FakeVmm/本地 BlobStore 形态下；真实 KVM 与大规模并发见"实现状态"。

## 代码结构（Rust workspace，ADR-0004）

```text
cmd/                      daemon composition roots 与 cats CLI；只在这里注册具体 adapter
storage/                  云无关 BlobStore/MetadataStore ports、错误契约与 adapter factory
adapters/                 具体实现：File/AWS S3 对象存储、SQLite/PostgreSQL 元数据、
                          PostgreSQL usage 投影和 AWS Kinesis/S3 usage delivery
metering/                 累计计数器 ledger port、SQLite 开发 adapter 与整数 Rate Card
control-plane/            项目隔离 API、用户/管理员 Web 控制台、Operation、Scheduler、节点管理/监控
node-agent/               NodeJob 执行器、FakeVmm、blockd 子进程监督、心跳（cats-noded）
blockd/                   ChunkStore 引擎：Cache/Bitmap/Pack/Map、FLUSH 提交协议、
                          lease/fencing、NBD 前端（cats-blockd；只依赖 storage ports）
guest/                    Guest Agent：vsock 控制协议、Guest-local HTTP Runtime API、demo web
network/                  Endpoint 网关：路由解析、唤醒、旧路由 fail-closed（cats-gatewayd）
api/                      共享类型：资源模型、四态、NodeJob、Guest 协议、Chunk 常量
tests/                    端到端测试（真实 CLI + 双节点 + 网关 + 真实存储子进程）
experiments/              可复现实验与原始证据
docs/                     架构、决策、协议规格和实验报告
```

## 实现状态

| 层 | 状态 | 说明 |
|---|---|---|
| 存储引擎（blockd） | ✅ 实现并测试 | 协议见 [docs/specs/blockd-protocol.md](docs/specs/blockd-protocol.md)；4 个提交窗口 kill -9 恢复、空缓存冷恢复、stale epoch 拒绝均有测试 |
| 控制面 / Web 控制台 / CLI / 网关 / node-agent / guest-agent | ✅ 实现并测试 | Workspace 鉴权、生命周期、交互式 PTY shell、独立 user/admin 站点、fleet 管理、监控、单元 + 集成 + E2E 覆盖完整开发闭环 |
| 存储 ports / adapters | ✅ 接口拆分 | `cats-storage` 不含厂商依赖；File/SQLite 为开发 adapter，AWS S3 与 PostgreSQL 为 AWS 生产部署 adapter |
| AWS S3 adapter | ✅ 代码 + 签名向量测试 | SigV4 通过 AWS 官方测试向量；对真实 AWS S3/MinIO 的联测按需运行 |
| 元数据存储 | ✅ SQLite + PostgreSQL | SQLite 用于本地开发；PostgreSQL adapter 实现 root/lease/fencing 的数据库时钟与原子 CAS，并用于 AWS EKS/metal 共享元数据 |
| Usage / billing ledger | ✅ provisional 全链路 | 1 秒 cgroup 采样、10 秒累计 checkpoint、Node 持久 outbox、lifecycle final checkpoint、Kinesis、七年 Object Lock S3 archive、PostgreSQL projection、DynamoDB checkpoint，以及 account/Cat/metric 查询和整数计价；正式收费仍待 replay/shadow invoice 验收 |
| 虚拟化 | FakeVmm + **Cloud Hypervisor 模式**（`--vmm ch`，Linux+KVM） | CH 直接内核启动、vsock Guest Agent、vm.pause/resume、Warm=vm.snapshot/--restore；块路径可选内核 NBD（默认，已裸金属验收）或原生 vhost-user-blk（`--ch-block-path vhost-user`，ADR-0015，协议级验收完成、真机验收待做）；部署见 `deploy/metal/` |
| Guest 网络 / tap / overlay | 未实现 | 下一里程碑；exec/健康走 vsock；Endpoint 演示仅 FakeVmm 形态 |

## 构建与测试

```bash
cargo build --workspace          # 全部组件
cargo test --workspace           # 单元 + adapter 契约 + 崩溃注入 + 控制面契约 + E2E
cargo clippy --workspace --all-targets   # 零警告
```

单机手动体验（四个终端或后台）：

```bash
cargo run -p cats-control-plane-daemon --bin cats-controld -- --listen 127.0.0.1:7300
cargo run -p cats-node-agent-daemon --bin cats-noded -- \
  --node-id n1 --control-plane-url http://127.0.0.1:7300 \
  --state-dir /tmp/cats-n1 \
  --metadata-store-adapter sqlite --metadata-store-option path=cats-storage-meta.db \
  --object-store-adapter file --object-store-option root=/tmp/cats-blob \
  --blockd-bin target/debug/cats-blockd --guest-agent-bin target/debug/cats-guest-agent
cargo run -p cats-network --bin cats-gatewayd -- --listen 127.0.0.1:7400
CATS_API_URL=http://127.0.0.1:7300 CATS_TOKEN=dev-admin-token \
  cargo run -p cats-cli --bin cats -- create dev --root-size 64MiB && \
CATS_API_URL=http://127.0.0.1:7300 CATS_TOKEN=dev-admin-token \
  cargo run -p cats-cli --bin cats -- exec dev -- echo hello
CATS_API_URL=http://127.0.0.1:7300 CATS_TOKEN=dev-admin-token \
  cargo run -p cats-cli --bin cats -- shell dev
```

本地默认把 usage 表放在 `--db-path` 指定的同一个 SQLite 文件中。生产 usage ledger
与控制面资源库独立配置：

```bash
export CATS_USAGE_STORE_ADAPTER=postgres
export CATS_USAGE_POSTGRES_URL='postgresql://user:password@host/cats_billing?sslmode=require'
export CATS_USAGE_POSTGRES_SCHEMA=cats_usage
export CATS_USAGE_DELIVERY_ADAPTER=aws-kinesis
export CATS_USAGE_AWS_REGION=us-east-1
export CATS_USAGE_KINESIS_STREAM=cats-production-usage
export CATS_USAGE_ARCHIVE_BUCKET=replace-with-dedicated-archive
export CATS_USAGE_CHECKPOINT_TABLE=cats-production-usage-consumer-leases
cargo run -p cats-control-plane-daemon --bin cats-controld
```

可通过 `CATS_USAGE_POSTGRES_CA_FILE` 添加私有 CA，并用
`CATS_USAGE_POSTGRES_WORKERS` 调整连接 worker 数（默认 4）。这只启用 PostgreSQL
查询投影。AWS delivery 由 Terraform 配置 EKS Pod Identity；本地运行上述
`aws-kinesis` 模式时需要等价的 AWS credential chain。当前 API 只返回
`provisional`，正式开账前仍必须完成故障注入、S3 replay reconciliation、连续 shadow
billing、invoice close 与迟到 adjustment 验收。

### 用户与管理员控制面

控制面把用户身份与机器身份分开：`CATS_AUTH_TOKEN` 仅供 node-agent/gateway 等内部
服务，`CATS_ADMIN_TOKEN` 是 fleet 自动化的 break-glass 机器凭据；普通用户的 Web 和
CLI 都使用 WorkOS 短期 session。服务端不再接受静态 project token。生产/共享环境
必须显式设置两个机器凭据，例如：

```bash
export CATS_AUTH_TOKEN='service-secret'
export CATS_ADMIN_TOKEN='admin-secret'
cargo run -p cats-control-plane-daemon --bin cats-controld
```

控制面进程同时提供公开产品站、公开用户文档和两个独立的、无需前端构建步骤的控制台。
生产环境以 `cats.run` 作为产品/用户文档入口、`app.cats.run/user/` 作为用户控制台、
`ops.cats.run` 作为管理员入口；Fleet 管理员指南独立发布在 `ops.cats.run/docs/`，不会
出现在官网文档目录或 sitemap。两个浏览器控制台都只支持 WorkOS 登录，不提供静态
Token 表单；未配置 WorkOS 时页面会提示联系平台管理员。本地入口：

- 产品站：<http://127.0.0.1:7300/>
- 英文使用文档：<http://127.0.0.1:7300/docs/>
- 中文使用文档：<http://127.0.0.1:7300/zh-CN/docs/>
- 用户控制台：<http://127.0.0.1:7300/user/>
- 管理员控制台：<http://127.0.0.1:7300/admin/>

本地测试管理员指南时，请为 `/docs/` 请求设置 `Host: ops.cats.run`；生产地址提供英语
`https://ops.cats.run/docs/` 与简体中文 `https://ops.cats.run/zh-CN/docs/`。

产品站与使用文档不要求登录，英语/简体中文分别使用可索引的稳定 URL，并提供 canonical、
hreflang、Open Graph/Twitter 元数据、JSON-LD、`robots.txt`、`sitemap.xml`、Web
Manifest 与品牌图形。控制台和认证/API 路径声明 `noindex`，资源数据仍必须经过正常
会话鉴权。

两个控制台均提供英语和简体中文。未保存语言偏好时，页面按浏览器的
`navigator.languages` / `navigator.language` 自动选择（中文环境使用简体中文，
其他环境使用英语）；语言选择器可切换为英语、中文或“跟随系统”，显式选择保存在
当前站点的浏览器本地存储中。语言偏好只影响展示，不参与 WorkOS session、Project
映射或权限判断。

### WorkOS AuthKit 登录

配置 WorkOS 后，两个 Web 站点使用独立的加密 HttpOnly session cookie；`cats login`
使用 WorkOS Device Authorization，并把 refresh/access token 存入操作系统 Keychain。
服务端从 WorkOS JWKS 验证每个 CLI access JWT，不接收或保存用户 refresh token。
Personal 与 Organization Account 都映射到 WorkOS Organization；一个 Account 可以
拥有多个 Workspace（底层仍保留稳定的 legacy Project 资源命名空间）。新用户会幂等
创建 Personal Account、`default` Workspace 和只属于该 Personal Billing Account 的
一次性 10 美元赠金。管理员还必须在管理员 Organization 中拥有
`cats:fleet:admin` permission：

```bash
export WORKOS_CLIENT_ID='client_...'
export WORKOS_API_KEY='sk_...'
export WORKOS_COOKIE_PASSWORD="$(openssl rand -hex 32)"
export WORKOS_REDIRECT_URI='http://127.0.0.1:7300/auth/callback'
export WORKOS_ISSUER='https://api.workos.com/user_management/client_...'
export CATS_WORKOS_PROJECT_ORGANIZATIONS='acme-dev=org_...'
export CATS_WORKOS_ADMIN_ORGANIZATION_ID='org_admin_...'
export CATS_WORKOS_ADMIN_PERMISSION='cats:fleet:admin'
cargo run -p cats-control-plane-daemon --bin cats-controld
```

在 WorkOS Dashboard 的 Redirects 中登记同一个 callback URI，并给管理员角色添加
`cats:fleet:admin` permission。生产 redirect URI 使用 HTTPS 后，控制面会默认给
session cookie 添加 `Secure`。`WORKOS_ISSUER` 必须与当前 WorkOS Application 签发的
access token 中 `iss` claim 完全一致；它不是 AuthKit 登录页面域名。服务端仍同时
校验 RS256 签名、`exp`、`sub` 和 `client_id`。

一个用户可以同时属于多个已映射的 WorkOS Organization。登录与 workspace 选择分离：
保存一个默认 workspace，同时允许命令级覆盖。同 Account 内切换只改本地 Workspace
ID；跨 Account 时 CLI 才在跨进程凭据锁内使用旋转 refresh token 申请目标
Organization 范围的新 access token。服务端按 Organization membership 与 Workspace
归属重新授权：

```bash
cats login
cats whoami
cats workspace list
cats workspace use acme/dev
cats ls
cats --workspace acme/prod ls
```

管理员可以查看节点分配/心跳/遥测，执行 cordon、uncordon、drain 和删除空节点。
`drain` 会先停止并 fence 原节点上的 Cat，再保持用户 desired state 在其他健康节点
重调度；完成后节点进入 Cordoned：

```bash
CATS_TOKEN=admin-secret cats admin monitoring
CATS_TOKEN=admin-secret cats admin nodes
CATS_TOKEN=admin-secret cats admin node drain node-a
curl -H 'Authorization: Bearer admin-secret' http://127.0.0.1:7300/metrics
```

实验侧验证（原型证据，无需 Rust）：`cd experiments/lazy-ext4-demo && python3 -m unittest -v test_chunkstore.py`；完整 Lazy ext4 需要 Docker privileged/NBD；VM 生命周期实验需要 Linux x86_64、root 和 `/dev/kvm`。
