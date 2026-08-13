## 全局选项

| 选项 / 环境变量 | 默认值 | 用途 |
|----|----|----|
| `--api-url` / `CATS_API_URL` | 已保存登录目标，否则为 `https://cats.run` | 控制面基础 URL |
| `--workspace` / `CATS_WORKSPACE` | 已保存 Workspace | 仅覆盖一条命令且不改变默认选择；接受 `workspace`、`account/workspace` 或 Workspace ID |
| `--token` / `CATS_TOKEN` | 无 | 仅供 Machine/Administrator Bearer Credential；普通用户执行 `cats login` |
| `--no-wait` | 关闭 | Operation 被接受后立即返回 |
| `--json` | 关闭 | 在支持的位置输出机器可读 JSON |

全局选项可以放在子命令前或后。`cats --help` 与 `cats <command> --help` 是当前版本最权威的参考。

## 身份与 Workspace 命令

    cats login
    cats whoami
    cats workspace list
    cats workspace create SLUG [--display-name NAME]
    cats workspace use ACCOUNT/WORKSPACE
    cats --workspace ACCOUNT/WORKSPACE ls
    cats logout

`login` 使用 WorkOS Device Authorization，并且只把 Access/Refresh 信息保存到操作系统凭据存储。Active WorkOS Organization Membership 会暴露 Personal/Organization Account 及其 Workspace。`workspace create` 会在当前 Account 下增加一个隔离 Workspace，并要求 Account 管理权限。`workspace use` 修改已保存默认值，`--workspace` 只影响一条命令；同 Account 切换为本地操作，跨 Account 则在跨进程凭据锁内轮换 WorkOS Refresh Token。`logout` 会尝试远端撤销，并始终删除本地凭据。

## 自动化 Token

    cats token create LABEL
    cats token list
    cats token revoke ID

Workspace Token 是供 CI 使用、可撤销的机器凭据。它只能管理签发 Workspace 内的资源，不能枚举其他 Workspace，也不能创建或撤销 Token。Secret 只展示一次；请保存到 CI 的 Secret Manager，并将它作为 `CATS_TOKEN`、将不可变 Workspace ID 作为 `CATS_WORKSPACE` 传入。

## Cat 命令

    cats create NAME [--image IMAGE] [--cpus N] [--memory SIZE]
                     [--root-size SIZE] [--disk NAME]
                     [--disk-size SIZE] [--mount-at PATH] [--no-auto-suspend]
                     [--expires-in SECONDS]
    cats ls
    cats get NAME
    cats start NAME
    cats stop NAME
    cats suspend NAME
    cats resume NAME
    cats warm NAME
    cats destroy NAME
    cats expiry NAME [--in SECONDS | --at UNIX | --never]
    cats exec NAME [--timeout SECONDS] [--env-file PATH]
                   [--stdin-file PATH] -- COMMAND [ARG...]
    cats deploy CAT APP --image REGISTRY/REPOSITORY@sha256:DIGEST
                    [--env-file PATH]
                    [--registry-username USER --registry-password-stdin]
                    [-- COMMAND [ARG...]]

`create` 默认使用 `ubuntu-24.04` 镜像、2 CPU、2 GiB 内存、1 GiB RootDisk，并开启自动休眠。容量支持 `KiB`、`MiB`、`GiB` 或原始字节。

`exec --env-file` 接受逐行 `NAME=VALUE`，并且只把它们加入 Guest 子进程环境；`--stdin-file` 将任意文件字节送入标准输入。自动化可以用它们传递 Bootstrap Script 和运行时凭据，而无需把内容放到命令行。不要打印含 Secret 的文件或进程环境。

`deploy` 在 Cat 内拉取 OCI/Docker manifest 与 layer，校验每个 `sha256` descriptor，将 layer 扁平化写入 RootDisk，再由 systemd 运行应用；不需要 Docker 或 OverlayFS。镜像必须固定到 digest，tag 会被拒绝。Registry 密码从 stdin 读取且不持久化。`deploy --env-file` 与 `exec --env-file` 不同：它会成为 RootDisk 上的持久 systemd 配置，以便 Cold boot 后继续启动服务，所以不能包含 Secret。

## 自动休眠命令

    cats sleep on NAME
    cats sleep off NAME
    cats sleep status NAME

状态会报告平台/Guest 工作租约、信号新鲜度、是否具备休眠资格及当前原因。

## 磁盘命令

    cats disk create NAME --size SIZE
    cats disk ls
    cats disk get NAME
    cats disk snapshot NAME
    cats disk delete NAME
    cats mount DISK --cat CAT [--at /data]
    cats unmount DISK

## Endpoint 命令

    cats expose CAT PORT [--name web] [--protocol http] [--no-wake]
    cats endpoint ls CAT

每个 Cat 已经拥有转发 8080 的 `web` Endpoint。`cats expose CAT PORT` 会重新配置它；使用其他 `--name` 可增加 URL。

## Operation 命令

    cats operation get ID
    cats operation wait ID

Cat Create 返回已接受的 Operation ID。`operation get` 在当前 Workspace 精确读取该 Operation；`operation wait` 最多轮询 120 秒，并在 `failed` 或 `superseded` 时以失败退出。两个命令都使用严格的 Runtime Reconciliation Decoder。

`operation ls` 仍不可用，且不会发出 HTTP：Runtime Authority 有意不提供无界 Operation List。旧的全局 Operation URL 已退役。

## 自动化建议

- 使用 `--json`，不要解析对齐后的人类可读输出。
- 把非零退出码视为失败。Guest 命令非零时，`exec` 也会失败。
- 不要从 Resource ID、Work Lease ID 或 Operation ID 中解析含义。
- 普通用户使用 WorkOS 登录，CI 使用 Workspace Token；不要记录 Token，也不要用 Service/Administrator 凭据替代这两种 Scope。
