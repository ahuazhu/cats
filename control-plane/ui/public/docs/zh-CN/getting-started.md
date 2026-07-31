## 先开一只 Cat（不用装任何东西）

1.  打开 [控制台](/user/) 并用 WorkOS 登录。新用户的 Personal Account 会自动获得一次性 $10 赠金。
2.  点 **Create Cat**，选规格并确认。Cat 会带一块持久 RootDisk 建出来。
3.  在 Cat 详情页用 **Exec** 跑命令，例如 `uname -a` 或 `apt install -y ripgrep`。

这只 Cat 从这一刻起就长期存在了：闲下来自动休眠，被访问时唤醒，磁盘和名字一直都在。

## 装 CLI（可选）

控制台适合开机器和跑单条命令；日常开发、`cats shell` 交互式终端和脚本化更适合用 CLI。

**目前 CLI 需要自己从源码构建**

预编译版本会在后续发布。构建需要 Rust 1.88 或更高版本，不需要 KVM。

    git clone <your-cats-repository>
    cd cats
    cargo install --path cmd/cats
    cats --help

在仓库内开发时，也可以把示例中的 `cats` 替换为 `cargo run -p cats-cli --bin cats --`。

## 配置访问

普通用户通过 WorkOS 登录。CLI 使用 Device Authorization，在浏览器中打开验证页面，并且只把短期 Access Token 与轮换 Refresh Credential 存进操作系统凭据存储。Cats 不再接受普通用户的静态用户 Token。

    export CATS_API_URL='https://cats.run'
    cats login
    cats whoami
    cats workspace list
    cats workspace use acme-dev
    cats ls

`cats login` 会在权限为 `0600` 的配置文件中保存控制面地址与公开 Workspace 元数据，但绝不会把 Token 写入其中。使用 `--workspace acme-prod` 或 `CATS_WORKSPACE=acme-prod` 可仅覆盖一条命令的已保存 Workspace。

**不要代入机器凭据**

`CATS_TOKEN` 仅保留给 Administrator/break-glass 机器身份。不要把 Service、对象存储、元数据存储、Node 或管理员凭据当作普通用户登录，也绝不能把它们放进 Guest。

## 创建第一只 Cat

    cats create dev \
      --image ubuntu-24.04 \
      --cpus 2 \
      --memory 2GiB \
      --root-size 8GiB

    cats get dev

创建 Cat 时会同时创建 RootDisk，并默认开启工作驱动自动休眠。对于没有接入 Work Lease 且必须持续运行的后台任务，可添加 `--no-auto-suspend`。CLI 默认等待异步 Operation 完成并打印 Cat；`--no-wait` 在控制面接受请求后立即返回，`--json` 输出机器可读数据。

## 执行命令

    cats exec dev -- uname -a
    cats exec dev -- sh -lc 'printf "hello\n" > /tmp/hello'

`exec` 会在必要时唤醒 Suspended、Warm 或 Cold Cat。`--` 后的内容会成为 Guest 命令 argv；只有像第二个示例那样显式调用 Shell 时，Shell 语法才会生效。

## 部署 OCI 应用

CI 已经发布 OCI 镜像时，直接使用 Cats 原生 Bundle Deploy：

    cats deploy dev server \
      --image ghcr.io/acme/server@sha256:<64位十六进制digest>

私有 Registry 的拉取 Token 不应进入 argv：

    printf '%s\n' "$REGISTRY_TOKEN" | \
      cats deploy dev server \
        --image ghcr.io/acme/server@sha256:<64位十六进制digest> \
        --registry-username "$REGISTRY_USER" \
        --registry-password-stdin

Cats 会校验 manifest/config/layer digest，把镜像扁平化写到持久 RootDisk，并 enable 一个 systemd service；不运行 Docker，也不需要 OverlayFS。同一 Cat 内多个应用共享网络 namespace，可以通过 `127.0.0.1` 互访；应用直接监听 Endpoint 端口即可对外服务。

`deploy --env-file` 是写入 RootDisk systemd unit 的持久应用配置，不能放 Secret。Registry 拉取凭据是 transient；通用 Secret 注入属于尚未实现的独立资源。

## Guest 内核提供什么

Guest 跑的是专用的最小内核：virtio 块设备/网络/vsock、ext4——没有可加载模块（`/lib/modules` 是空的，也没有 `modprobe`）。其中两项缺失会让常规 Linux 软件意外失败：

- **没有 overlayfs** —— 容器运行时无法使用默认的 `overlay2`/`fuse-overlayfs` 存储驱动；
- **没有 nf_tables** —— `iptables` 报 `Failed to initialize nft: Protocol not supported`，任何 NAT / filter 链都建不起来。

OCI 应用交付优先使用 `cats deploy`。如果确实要在 Cat 内再运行容器 runtime，它只有在不依赖这两项内核能力时才能工作：

    dockerd --storage-driver=vfs --iptables=false --ip6tables=false --bridge=none
    docker run --network host ...

用 host 网络时容器共享 Cat 自己的网络命名空间：容器之间通过 `127.0.0.1` 互访（而不是运行时的 DNS），监听 `0.0.0.0:8080` 的容器直接由 Cat 的 endpoint 对外服务，无需 publish 端口。`vfs` 会逐层复制镜像而不是叠加，所以 RootDisk 要按加载的镜像体积来定。

回环本身是配好的：`lo` 已 up 且带 `127.0.0.1/8`，进程间 localhost 正常可用。

## 管理工作驱动自动休眠

    cats sleep on dev
    cats sleep status dev
    cats sleep off dev

新建 Cat 默认开启自动休眠。它不会根据 CPU 或进程列表猜测；当平台工作与新鲜的 Guest Work Lease 同时为空时，Cat 才具备休眠资格。持续运行的后台应用必须使用 [Guest Runtime API](/zh-CN/docs/runtime-api/)，或执行 `cats sleep off dev`。

## 停止与启动

    cats suspend dev    # 绑定原 Host，保留进程状态
    cats resume dev
    cats stop dev       # Cold：释放计算与 Host 亲和
    cats start dev      # 从持久 RootDisk 启动

## 清理资源

    cats destroy dev

Operation 完成后，Destroy 会删除 Cat 及其 RootDisk。独立 PersistentDisk 会保留，需要单独执行 `cats disk delete`。

**破坏性操作**

Destroy 前请对需要的内容创建快照或复制。V1 CLI 没有撤销删除命令。
