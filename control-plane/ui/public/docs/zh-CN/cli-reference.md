## 全局选项

| 选项 / 环境变量 | 用途 |
|----|----|
| `--api-url` / `CATS_API_URL` | Control Plane Base URL |
| `--workspace` / `CATS_WORKSPACE` | 为本次命令选择一个不可变 Workspace |
| `--token` / `CATS_TOKEN` | Machine 或 Administrator Credential |
| `--no-wait` | 输出已接受的 Operation ID，不等待结算 |
| `--json` | 在支持时输出机器可读数据 |

`cats --help` 与 `cats <command> --help` 是版本权威。

## 身份与 Workspace

    cats login
    cats logout
    cats whoami
    cats workspace list
    cats workspace create SLUG [--display-name NAME]
    cats workspace use ACCOUNT/WORKSPACE
    cats token create LABEL
    cats token list
    cats token revoke ID

## 当前 Cat 命令

    cats create NAME [--cpus N] [--memory SIZE]
                     [--root-size SIZE]
                     [--durability strict|relaxed]
    cats ls
    cats get CAT_ID
    cats run CAT_ID
    cats suspend CAT_ID
    cats warm CAT_ID
    cats cold CAT_ID
    cats destroy CAT_ID

`create` 自动使用部署当前已资格化的 Boot Image，默认 2 CPU、2 GiB Memory、1 GiB RootDisk 与 Strict Durability。List 会跟随有界 Cursor；Item Lookup 只接受不可变 `cat_…` ID。

已有 Cat 的五个 Lifecycle 命令也只接受不可变 `cat_…` ID。CLI 会在发送前持久化精确的空 Request 与 Idempotency-Key，并在响应不明确时原样重放。默认等待返回的 Operation；`--no-wait` 则立即输出 Operation ID。已退役的 `start`、`stop`、`delete` 与 `resume` 命令不是兼容别名。

## 当前 PersistentDisk 命令

    cats disk create NAME --size SIZE [--durability strict|relaxed]
    cats disk ls
    cats disk get DISK_ID
    cats disk attach DISK_ID --cat CAT_ID --mount-path /absolute/guest/path
    cats disk detach DISK_ID --cat CAT_ID --mount-path /absolute/guest/path
    cats disk snapshot create DISK_SLUG SNAPSHOT_SLUG
    cats disk snapshot list [--disk DISK_SLUG]
    cats disk snapshot show SNAPSHOT_SLUG
    cats disk snapshot restore SNAPSHOT_SLUG
    cats disk snapshot destroy SNAPSHOT_SLUG

Create、Attach 和 Detach Request 会在发送前持久化；同一命令遇到不明确响应时重用完全相同的 Path、Body 与 Idempotency-Key。这个 release 中容量不可变。Disk Item Lookup 只接受不可变 `disk_…` ID；Binding Mutation 要求终态 Cold Cat 与精确的 Guest 绝对路径。

Snapshot Create 使用两个由用户选择的 Slug 作为稳定语义身份。Create 与 Restore 要求磁盘已远端持久且 Unowned；磁盘已绑定时，其 Cat 必须稳定处于 Cold。Restore 会先读取磁盘最新 Generation，并把它作为乐观并发前置发送；并发磁盘变更会失败，不会覆盖调用者未见的新 Head。Destroy 只删除恢复点及其 GC 保护，不删除 PersistentDisk。

## Operation 命令

    cats operation get OPERATION_ID
    cats operation wait OPERATION_ID

Cat Create 与已有 Cat 的五个 Lifecycle 命令都返回 Operation ID。这两个 Operation 命令都使用精确的 Workspace-scoped 产品 Lookup；没有 Operation List，也不返回 Node 执行 Payload。

## Cutover 边界

Endpoint 与容量变更命令不会出现在发布版 Help 中。已退役的 Lifecycle 别名不再解析，也绝不探测 Legacy Route。
