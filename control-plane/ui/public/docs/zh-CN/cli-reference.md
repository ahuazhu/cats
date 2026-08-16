## 全局选项

| 选项 / 环境变量 | 用途 |
|----|----|
| `--api-url` / `CATS_API_URL` | Control Plane Base URL |
| `--workspace` / `CATS_WORKSPACE` | 为本次命令选择一个不可变 Workspace |
| `--token` / `CATS_TOKEN` | Machine 或 Administrator Credential |
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

    cats create NAME --boot-image-digest sha256:DIGEST
                     [--cpus N] [--memory SIZE]
                     [--root-size SIZE]
                     [--durability strict|relaxed]
    cats ls
    cats get CAT_ID

`create` 要求 digest-pinned Boot Image，默认 2 CPU、2 GiB Memory、1 GiB RootDisk 与 Strict Durability。List 会跟随有界 Cursor；Item Lookup 只接受不可变 `cat_…` ID。

## 当前 PersistentDisk 命令

    cats disk create NAME --size SIZE [--durability strict|relaxed]
    cats disk ls
    cats disk get DISK_ID

Create Request 会在发送前持久化；同一命令遇到不明确响应时重用完全相同的 Path、Body 与 Idempotency-Key。这个 release 中容量不可变。Disk Item Lookup 只接受不可变 `disk_…` ID。

## Operation 命令

    cats operation get OPERATION_ID
    cats operation wait OPERATION_ID

Cat Create 返回 Operation ID。这两个命令都使用精确的 Workspace-scoped Operation Lookup；没有 Operation List。

## Cutover 边界

Lifecycle、Guest Command、Deployment、Endpoint、Cat Delete 与 PersistentDisk Mutation 命令不会出现在发布版 Help 中。若保留兼容 Parser，它会在创建 HTTP Client 之前失败，绝不探测 Legacy Route。
