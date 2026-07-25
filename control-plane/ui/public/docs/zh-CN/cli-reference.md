## 全局选项

| 选项 / 环境变量 | 默认值 | 用途 |
|----|----|----|
| `--api-url` / `CATS_API_URL` | 已保存登录目标，否则为 `https://cats.run` | 控制面基础 URL |
| `--workspace` / `CATS_WORKSPACE` | 已保存 Workspace | 仅覆盖一条命令且不改变默认选择；`--project` 是兼容别名 |
| `--token` / `CATS_TOKEN` | 无 | 仅供 Machine/Administrator Bearer Credential；普通用户执行 `cats login` |
| `--no-wait` | 关闭 | Operation 被接受后立即返回 |
| `--json` | 关闭 | 在支持的位置输出机器可读 JSON |

全局选项可以放在子命令前或后。`cats --help` 与 `cats <command> --help` 是当前版本最权威的参考。

## 身份与 Workspace 命令

    cats login
    cats whoami
    cats workspace list
    cats workspace use ACCOUNT/WORKSPACE
    cats --workspace ACCOUNT/WORKSPACE ls
    cats logout

`login` 使用 WorkOS Device Authorization，并且只把 Access/Refresh 信息保存到操作系统凭据存储。Active WorkOS Organization Membership 会暴露 Personal/Organization Account 及其 Workspace。`workspace use` 修改已保存默认值，`--workspace` 只影响一条命令；同 Account 切换为本地操作，跨 Account 则在跨进程凭据锁内轮换 WorkOS Refresh Token。`logout` 会尝试远端撤销，并始终删除本地凭据。

## Cat 命令

    cats create NAME [--image IMAGE] [--cpus N] [--memory SIZE]
                     [--root-size SIZE] [--disk NAME]
                     [--disk-size SIZE] [--mount-at PATH] [--no-auto-suspend]
    cats ls
    cats get NAME
    cats start NAME
    cats stop NAME
    cats suspend NAME
    cats resume NAME
    cats warm NAME
    cats destroy NAME
    cats exec NAME -- COMMAND [ARG...]

`create` 默认使用 `ubuntu-24.04` 镜像、2 CPU、2 GiB 内存、1 GiB RootDisk，并开启自动休眠。容量支持 `KiB`、`MiB`、`GiB` 或原始字节。

## 自动休眠命令

    cats sleep on NAME
    cats sleep off NAME
    cats sleep status NAME

状态会报告平台/Guest 工作租约、信号新鲜度、是否具备休眠资格及当前原因。

## 磁盘命令

    cats disk create NAME --size SIZE
    cats disk ls
    cats disk get NAME
    cats disk resize NAME --size SIZE
    cats disk snapshot NAME
    cats disk delete NAME
    cats mount DISK --cat CAT [--at /data]
    cats unmount DISK

## Endpoint 命令

    cats expose CAT PORT [--name web] [--protocol http] [--no-wake]
    cats endpoint ls CAT

每个 Cat 已经拥有转发 8080 的 `web` Endpoint。`cats expose CAT PORT` 会重新配置它；使用其他 `--name` 可增加 URL。

## Operation 命令

    cats operation ls
    cats operation get ID
    cats operation wait ID

变更默认最多等待 120 秒。使用 `--no-wait` 时请保存返回 ID，再执行 `operation wait` 或 `operation get`。安全重试应保持同一资源意图；API 会为变更附带幂等键。

## 自动化建议

- 使用 `--json`，不要解析对齐后的人类可读输出。
- 把非零退出码视为失败。Guest 命令非零时，`exec` 也会失败。
- 不要从 Resource ID、Work Lease ID 或 Operation ID 中解析含义。
- 普通用户使用 WorkOS 登录；不要记录 Token，也不要用 Service/Administrator 凭据代替用户 Session。
