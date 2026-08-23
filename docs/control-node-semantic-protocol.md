# Control Plane 与 noded 同步协议设计

- 状态：ADR-0059 已接受，并由 [ADR-0062](decisions/0062-destroy-preempts-in-progress-cat-actions.md)
  修正 Destroy 抢占与崩溃恢复；正在实施
- 范围：Cat、Node、PersistentDisk 的控制面数据模型、同步接口、状态转换与场景语义幂等
- 切换方式：空数据、单协议直接替换旧 lifecycle 协调；不提供兼容层或数据迁移，实施进度见[执行计划](semantic-control-node-implementation-plan.md)

## 1. 设计目标

本设计追求一个容易实现和解释的控制协议：

1. CLI 和 REST 调用都同步等待 Control Plane 返回成功、失败或超时。
2. Control Plane 同步调用目标 Node 上的 `noded`。
3. 不使用调用方提供的 `request_id`、idempotency key 或独立 Operation 资源保证幂等。
4. 每个动作通过“资源身份 + 请求参数 + 目标结果”判断是否已经完成。
5. Cat 的产品动作只有 `create`、`run`、`suspend`、`warm`、`cold` 和 `destroy`。
6. PersistentDisk 与 Cat 一样具有用户指定的 slug；内部 ID 不暴露为主要用户定位方式。
7. 同一个 Cat 的动作串行执行；同一块 PersistentDisk 同时最多绑定一个 Cat。
8. Node 正常退出时先迁走 Cat；Node 异常退出后，先撤掉旧实例的流量入口，再从其他 Node 恢复并把唯一入口切到新实例。

本设计优先保证接口简单和常见重试可预测。它不试图处理任意延迟、任意乱序和长期不对称网络下的所有情况。

## 2. 明确假设与限制

### 2.1 运行假设

- PostgreSQL 是 Control Plane 数据的持久存储。
- 每台机器只运行一个有效的 `noded`。
- Control Plane 可以通过内部认证网络同步访问 `noded`。
- Control Plane 不在调用 `noded` 时持有 PostgreSQL transaction。
- Control Plane 和 `noded` 都按 Cat 串行动作。
- 重试只重试原来的动作和参数，不在一次动作超时后修改参数。
- 本简化协议只使用远端持久的磁盘写入语义；一次成功的 Guest FLUSH 必须已经远端持久。需要允许只保存在 Node 本地的数据时，不能继续使用本文的简化失联和 reset 流程。
- 每个 Cat 对外只有一个当前流量入口。跨 Node 恢复时，Control Plane 先撤掉指向旧 Node 的入口；新实例 Ready 后，再把入口切到新 Node。
- 心跳丢失和主动探测失败用于判定失联，不证明旧机器已经停止。跨 Node 恢复不以确认旧机器停止为前置条件，因此系统不承诺任意时刻物理上只运行一个 Cat。
- 本文假设失联但仍在运行的旧 Node 会在允许的心跳窗口内重新与 Control Plane 成功通信；不处理旧 Node 长期无法联系 Control Plane、却持续运行 Cat 的不对称网络。
- 旧 Node 的下一次成功心跳会收到 `reset_required`，随后必须立即停止并清理本机 Cat。因此双跑是一个有界的过渡状态，正常上限为一个允许的心跳窗口加上停止清理时间，最终收敛为只有新实例运行。
- 双跑窗口内，唯一入口只能限制新进入的流量。旧实例上的已有连接、后台任务、主动出站请求和磁盘写入仍可能继续，这是本文明确接受的短暂异常恢复风险。

### 2.2 V1 不处理的能力

- 不处理跨越多个后续状态转换后才到达的旧请求。
- 不支持 PersistentDisk 热挂载、热卸载或扩容。
- 不支持跨 Node 恢复 Suspended/Warm 的本地内存状态；跨 Node 时先按 Cold 恢复磁盘，再转换到原目标状态。
- 不在本协议内定义公网 Route、Gateway 或 Endpoint 的详细协议；只要求每个 Cat 最多发布一个当前入口，并且 Control Plane 能撤掉旧目标、发布新目标。
- 不声明自动云主机隔离、跨 Node live migration 或完整生产 HA 已完成。

一个直接后果是：如果系统将来需要区分“很久以前的旧重试”和“用户现在重新发起的相同动作”，必须扩展协议；仅凭场景语义无法区分这两件事。

## 3. 资源身份与 slug

### 3.1 内部 ID

系统为资源生成不可变内部 ID：

- `cat_id`
- `disk_id`
- `node_id`
- `workspace_id`

Control Plane 调用 `noded` 时只使用内部 ID。slug 不进入 Node 本地目录名、进程名或设备身份。

### 3.2 用户 slug

Cat 和 PersistentDisk 都有用户指定的 slug：

```text
Cat:            (workspace_id, cat_slug)
PersistentDisk: (workspace_id, disk_slug)
```

V1 slug 规则：

- 长度为 1 到 63 个字符；
- 只接受小写 ASCII 字母、数字和 `-`；
- 必须以字母或数字开始和结束；
- 不做大小写转换或 Unicode 归一化；
- 在所属 Workspace 的同一时间段内唯一：同一时刻最多指向一个未销毁实体。

例如：

```text
web
web-01
data-disk
```

`DATA_DISK` 是命令帮助中的参数占位符；实际 slug 示例使用 `data-disk`。

slug 可以完全复用。资源 destroy/delete 提交后，原实体不再占用 slug；随后使用同一 slug 创建资源时生成新的内部 ID。按 slug 查询时只返回最新且未 `destroyed/deleted` 的实体；没有未销毁实体时，slug 不指向任何历史实体。历史实体只能通过其内部 ID 查询。因此同一 slug 在不同时间可以依次指向多个实体，但同一时刻最多指向一个有效实体。

## 4. Control Plane 数据模型

以下是逻辑字段，不限定具体 SQL 类型和表名前缀。

### 4.1 `cats`

```text
cats
- cat_id                    # 内部不可变 ID，主键
- workspace_id              # 所属 Workspace
- cat_slug                  # 用户指定 slug
- state                     # running/suspended/warm/cold/failure/destroyed；首次create进行中可为空
- current_action            # create/run/suspend/warm/cold/destroy；空表示没有动作
- current_action_started_at
- current_action_node_id    # 本次动作选中的Node；动作结束后清空
- node_id                   # running/suspended/warm时必填；cold/destroyed时为空
- cpu_count
- memory_bytes
- boot_image
- last_error_code
- last_error_message
- created_at
- updated_at
- destroyed_at              # 未destroyed时为空
```

约束：

- 只对未 `destroyed` 的行建立 `UNIQUE(workspace_id, cat_slug)`；历史 `destroyed` 行不参加唯一约束；
- `state IS NULL` 只允许发生在首次 `create` 尚未结束时；
- `state = destroyed` 当且仅当 `destroyed_at` 不为空；
- `destroyed` 时 `node_id` 和 `current_action` 必须为空；
- `current_action IS NULL` 时 `current_action_node_id` 必须为空；
- `running`、`suspended`、`warm` 时 `node_id` 必须存在；
- `cold` 时 `node_id` 为空；
- `failure` 可以保留 `node_id`，表示仍需要向该 Node 执行 destroy 清理。

`state` 表示最后一次完成的产品状态。动作进行中时同时返回 `state` 和 `current_action`，不能把旧 `state` 解释为物理转换已经完成。

Cat slug 的有效时间段是 `[created_at, destroyed_at)`；`destroyed_at` 为空表示当前仍有效。PostgreSQL 使用只覆盖当前实体的部分唯一索引：

```sql
CREATE UNIQUE INDEX cats_current_slug_unique
ON cats (workspace_id, cat_slug)
WHERE destroyed_at IS NULL;
```

### 4.2 `nodes`

```text
nodes
- node_id
- node_name                 # 面向用户和运维人员的可读展示名
- control_endpoint          # Control Plane同步访问noded的内部base URL
- vendor                    # aws/gcp/...
- region
- zone
- instance_id
- machine_type
- node_version
- status                    # running/draining/offline/reset_required/deleted
- created_at
- updated_at
```

约束：

- `node_name` 必填，在 Node 列表、详情、Cat placement 和运维日志中优先展示；数据库关联和内部调用仍使用 `node_id`；
- `control_endpoint` 必须是 Control Plane 可访问的绝对 `http` 或 `https` URL；Control Plane 使用内部共享凭证调用；
- 同一个 `node_id` 的 `node_name` 创建后不可由注册或心跳隐式修改；`control_endpoint` 由 noded 在显式注册或 reset 完成后重新注册时更新，普通心跳不能修改；
- 同一云环境中的 `instance_id` 必须唯一；
- `deleted` Node 不能重新变为 `running`；重新提供机器时创建新的 `node_id`；
- `draining`、`offline`、`reset_required` 和 `deleted` Node 不接受新的 Cat placement。

### 4.3 `node_heartbeats`

每台 Node 只保留一行最新状态；历史指标进入监控系统，不在此表追加无限历史。

```text
node_heartbeats
- node_id                    # 主键
- last_heartbeat_at          # Control Plane接收心跳时的数据库时间，用于判断失联
- node_reported_at           # Node上报时间，仅用于诊断，不参与失联判断
- reported_status
- total_cpu
- cpu_utilized
- total_memory
- memory_utilized
- running_cat_count
- suspended_cat_count
- warm_cat_count
```

Control Plane 使用自己的数据库时间写 `node_heartbeats.last_heartbeat_at`，并用它判断失联。`node_reported_at` 只保存 Node 上报的诊断时间，不能参与失联判断。

### 4.4 `persistent_disks`

```text
persistent_disks
- disk_id
- workspace_id
- disk_slug
- size_bytes
- status                    # normal/deleted
- created_at
- deleted_at
```

约束：

- 只对未 `deleted` 的行建立 `UNIQUE(workspace_id, disk_slug)`；历史 `deleted` 行不参加唯一约束；
- `size_bytes` 创建后不可修改；
- `status = deleted` 当且仅当 `deleted_at` 不为空；
- `deleted` Disk 不允许重新启用；
- V1 不提供 resize。

Disk slug 的有效时间段是 `[created_at, deleted_at)`；`deleted_at` 为空表示当前仍有效。PostgreSQL 使用：

```sql
CREATE UNIQUE INDEX disks_current_slug_unique
ON persistent_disks (workspace_id, disk_slug)
WHERE deleted_at IS NULL;
```

### 4.5 `disk_bindings`

```text
disk_bindings
- binding_id
- disk_id
- cat_id
- mount_path
- created_at
```

约束：

- `UNIQUE(disk_id)`，保证一块 PersistentDisk 同时最多绑定一个 Cat；
- `UNIQUE(cat_id, mount_path)`，保证同一 Cat 的挂载目标不冲突；
- Cat 和 Disk 必须属于同一 Workspace；
- `mount_path` 必须是绝对路径；
- `/`、`/boot`、`/proc`、`/sys`、`/dev` 和 `/run` 不允许作为 PersistentDisk 挂载点；
- binding 只允许在 Cat create 时建立，或者在 Cat 为 `cold` 时增加和删除；
- Cat destroy 时删除 binding，但不删除 PersistentDisk。

绑定当前是否存在就是关联关系的唯一判断，不额外保存 `attached/detached` 状态。

## 5. Cat 状态机

### 5.1 稳定状态

| 状态 | 含义 |
|---|---|
| `running` | Guest 正在运行 |
| `suspended` | Guest 被暂停，VMM 仍在原 Node |
| `warm` | 本地保存快速恢复状态，VMM 已退出，仍依赖原 Node |
| `cold` | 不依赖原 Node，可以选择其他 Node 运行 |
| `failure` | 最近动作失败，只允许 destroy |
| `destroyed` | 产品资源已经销毁；保留历史行但释放 slug，不是可恢复运行状态 |

首次 create 进行中时 `state` 可以为空；它不是一个对用户承诺的稳定状态。

### 5.2 合法转换

| 当前状态 | 动作 | 成功后 |
|---|---|---|
| 不存在 | `create` | `running` |
| `running` | `suspend` | `suspended` |
| `running` | `warm` | `warm` |
| `running` | `cold` | `cold` |
| `suspended` | `run` | `running` |
| `suspended` | `warm` | `warm` |
| `suspended` | `cold` | `cold` |
| `warm` | `run` | `running` |
| `warm` | `cold` | `cold` |
| `cold` | `run` | `running` |
| 任意未销毁状态 | `destroy` | `destroyed` |
| `failure` | `destroy` | `destroyed` |

其他组合返回 `invalid_state`，不调用 `noded`。

### 5.3 动作失败

- create、run、suspend、warm 或 cold 返回明确失败时，Control Plane 将 Cat 更新为 `failure`。
- `failure` 不尝试表达 VMM、磁盘或本地文件的精确残留状态。
- `failure` 状态只接受 `destroy`，不接受 run、suspend、warm 或 cold。
- destroy 失败时保持 `failure` 并记录最后错误；用户可以再次调用 destroy。
- 失败不会自动删除 PersistentDisk。
- 离开 `running` 的动作必须先停止该 Cat 接受新的外部连接，再暂停或停止 Guest；具体 Gateway/Endpoint 协议不属于本文范围。

## 6. 场景语义幂等

### 6.1 通用判断顺序

Control Plane 对每个请求按以下顺序处理：

1. 认证用户并确定 Workspace。
2. 根据 Workspace、slug 或内部 ID 找到资源；slug 只解析最新且未销毁的当前实体，没有当前实体时不回退到历史行。
3. 检查请求目标是否已经满足。
4. 已满足则返回 `already_done`，不调用 `noded`。
5. 同一语义资源存在但参数不同则返回 `conflict`。
6. 同一个动作正在进行时，同步等待它结束，最长不超过本次接口 timeout。
7. 另一个非 destroy 动作正在进行时返回 `busy`；destroy 原子替换当前动作并继承它的目标 Node。
8. 记录 `current_action` 后提交数据库 transaction。
9. 在 transaction 外同步调用 `noded`。
10. 根据结果更新 `state`、`node_id`、`current_action` 和错误字段。

Control Plane 不在网络调用期间持有数据库 transaction。
动作得到终态成功或失败后必须清空 `current_action` 和 `current_action_node_id`。Create 清理失败时把尝试过的 Node 保存在 `node_id`，使后续 destroy仍能找到该 Node；确认本地已经清理完成时可以把 `node_id` 清空。

### 6.2 Create Cat

语义身份是：

```text
(workspace_id, cat_slug)
```

判断规则：

- 当前不存在未 `destroyed` 的同 slug Cat：创建新的 `cat_id` 并执行 create，历史同 slug Cat 不影响创建；
- 已存在、未销毁且 create 配置完全相同：返回 `already_exists` 和已有 Cat；
- 已存在但 CPU、内存、镜像或初始 mounts 不同：返回 `cat_configuration_conflict`；
- 同一 create 正在进行：等待当前 create 的结果；
- 其他动作正在进行：返回 `busy`。

“配置完全相同”要求逐项比较：

- CPU；
- 内存；
- boot image；
- 按 `disk_id` 排序后的完整 mount 集合；
- 每个 mount 的 `disk_id` 和 `mount_path`。

### 6.3 状态动作

状态动作由 `cat_id + 目标状态` 保证幂等：

```text
run     -> running
suspend -> suspended
warm    -> warm
cold    -> cold
destroy -> destroyed
```

例如重复 `run`：

- Cat 已 `running`：返回 `already_running`；
- Cat 正在执行 `run`：等待同一个动作；
- Cat 为 `suspended/warm/cold`：执行 run；
- Cat 为 `failure/destroyed`：返回 `invalid_state`。

`destroy` 是唯一可以替换其他进行中动作的状态动作。被替换动作的迟到结果必须用 exact
`current_action + current_action_node_id` 条件更新拒绝，不能把 Cat 从 destroy lane 写回旧目标或
`failure`。

### 6.4 Create Disk

语义身份是：

```text
(workspace_id, disk_slug)
```

判断规则：

- 当前不存在未 `deleted` 的同 slug Disk：创建新的 `disk_id`，历史同 slug Disk 不影响创建；
- 已存在且 `size_bytes` 相同：返回 `already_exists`；
- 已存在但容量不同：返回 `disk_size_conflict`。

### 6.5 Attach Disk

语义身份是：

```text
(cat_id, disk_id)
```

判断规则：

- 已绑定到同一 Cat、相同 `mount_path`：返回 `already_attached`；
- 已绑定到同一 Cat、不同 `mount_path`：返回 `mount_path_conflict`；
- 已绑定到其他 Cat：返回 `disk_already_attached`；
- Disk 已删除：返回 `disk_deleted`；
- Cat 不是 `cold` 且不是 create 流程：返回 `cat_must_be_cold`；
- 否则创建 binding。

### 6.6 Detach Disk

- binding 存在且属于目标 Cat：删除 binding；
- binding 不存在：返回 `already_detached`；
- Disk 当前绑定其他 Cat：返回 `disk_binding_conflict`，不能删除其他 Cat 的 binding；
- Cat 不是 `cold`：返回 `cat_must_be_cold`。

### 6.7 Destroy Disk

- Disk 已删除：返回 `already_deleted`；
- Disk 仍有 binding：返回 `disk_in_use`；
- Disk 未绑定：删除底层数据并将状态改为 `deleted`；
- 删除失败：保持 `normal`，允许再次调用 destroy。

## 7. 对外 CLI 与 REST API

### 7.1 CLI

```bash
cats create CAT_SLUG \
  --cpu 2 \
  --memory 4GiB \
  --mount DISK_SLUG:/data

cats run CAT_SLUG
cats suspend CAT_SLUG
cats warm CAT_SLUG
cats cold CAT_SLUG
cats destroy CAT_SLUG

cats disk create DISK_SLUG --size 100GiB
cats disk attach DISK_SLUG --cat CAT_SLUG --mount /data
cats disk detach DISK_SLUG --cat CAT_SLUG
cats disk destroy DISK_SLUG
```

`--mount` 可以重复出现。CLI 先在当前 Workspace 中把 `DISK_SLUG` 解析为 `disk_id`，再提交结构化请求。

### 7.2 REST 路由

```text
POST /v1/workspaces/{workspace_id}/cats
POST /v1/workspaces/{workspace_id}/cats/{cat_slug}/actions/run
POST /v1/workspaces/{workspace_id}/cats/{cat_slug}/actions/suspend
POST /v1/workspaces/{workspace_id}/cats/{cat_slug}/actions/warm
POST /v1/workspaces/{workspace_id}/cats/{cat_slug}/actions/cold
POST /v1/workspaces/{workspace_id}/cats/{cat_slug}/actions/destroy

POST /v1/workspaces/{workspace_id}/disks
POST /v1/workspaces/{workspace_id}/disks/{disk_slug}/actions/attach
POST /v1/workspaces/{workspace_id}/disks/{disk_slug}/actions/detach
POST /v1/workspaces/{workspace_id}/disks/{disk_slug}/actions/destroy

POST /v1/admin/nodes/{node_id}/actions/drain
```

Node drain 是 fleet administrator 管理路由，不接受 Workspace automation/service principal，也没有请求
body。认证和 Node 状态错误使用通用错误响应；已经 `draining` 的相同 Node 请求会继续当前排空。

Create Cat 请求：

```json
{
  "cat_slug": "web",
  "cpu": 2,
  "memory_bytes": 4294967296,
  "boot_image": "ubuntu-24.04",
  "mounts": [
    {
      "disk_slug": "data-disk",
      "mount_path": "/data"
    }
  ]
}
```

Create Disk 请求：

```json
{
  "disk_slug": "data-disk",
  "size_bytes": 107374182400
}
```

### 7.3 通用响应

```json
{
  "status": "ok",
  "code": "cat_running",
  "cat": {
    "cat_id": "cat_123",
    "cat_slug": "web",
    "state": "running",
    "current_action": null,
    "node_id": "node_123",
    "node_name": "worker-us-east-1a-01"
  }
}
```

`status` 固定为：

```text
ok
already_done
already_exists
busy
conflict
failed
timeout
```

`status` 表示通用结果类别，`code` 表示具体场景，例如 `already_running`、`already_attached`、`cat_configuration_conflict`。下文所说“返回 `already_running`”均指返回该 `code`。

推荐 HTTP 映射：

| 结果 | HTTP |
|---|---:|
| `ok`、`already_done`、`already_exists` | 200/201 |
| `busy`、`conflict` | 409 |
| `invalid_state`、`cat_must_be_cold` | 422 |
| `failed` | 500 |
| Node 不可达 | 503 |
| Control 等待超时 | 504 |

幂等重复调用可以返回 `already_*`，也可以保持 HTTP 200；客户端不得把 `already_*` 当作失败。

## 8. Control Plane 到 noded 的内部接口

内部请求不携带 `request_id`。所有动作使用 `cat_id`、当前资源参数和目标状态判断是否已经完成。

### 8.1 查询

```text
GET /v1/health
GET /v1/cats/{cat_id}
GET /v1/cats
```

Cat 查询返回：

```json
{
  "cat_id": "cat_123",
  "state": "running",
  "active_action": null,
  "cpu": 2,
  "memory_bytes": 4294967296,
  "mounts": [
    {
      "disk_id": "disk_123",
      "mount_path": "/data"
    }
  ]
}
```

### 8.2 Create

```text
PUT /v1/cats/{cat_id}
```

使用 PUT 是因为 `cat_id` 已由 Control Plane 确定。重复 PUT 的规则：

- 相同 `cat_id`、相同配置、已经 Running：`already_running`；
- 相同 `cat_id`、相同配置、正在 create：等待或返回 `busy_same_action`；
- 相同 `cat_id`、不同配置：`cat_configuration_conflict`；
- 相同 `cat_id` 已被 destroy：`cat_destroyed`，不得重新创建；
- 本机不存在：执行创建。

### 8.3 状态动作

```text
POST /v1/cats/{cat_id}/actions/run
POST /v1/cats/{cat_id}/actions/suspend
POST /v1/cats/{cat_id}/actions/warm
POST /v1/cats/{cat_id}/actions/cold
DELETE /v1/cats/{cat_id}
```

每个动作先检查实际状态：

- 已经达到目标状态：返回 `already_done`；
- 合法来源状态：执行动作；
- 不合法来源状态：返回 `invalid_state`；
- 其他非 destroy 动作正在执行：返回 `busy`；
- destroy 到达时，停止当前动作，等待其退出，然后清理该 Cat 的全部本地状态。

`DELETE` 完成后，noded 在本次注册周期内按 `cat_id` 保留 destroyed marker。它与用户 slug 无关，也不阻止 Control Plane 用同一 slug 和新的 `cat_id` 创建 Cat。随后到达的旧 `cat_id` create、run、suspend、warm 或 cold 都返回 `cat_destroyed`。

### 8.4 noded 响应

```json
{
  "status": "ok",
  "cat_id": "cat_123",
  "state": "cold",
  "error": null
}
```

失败响应：

```json
{
  "status": "failed",
  "cat_id": "cat_123",
  "state": "failure",
  "error": {
    "code": "guest_start_failed",
    "message": "guest did not become ready before timeout"
  }
}
```

`noded` 返回前必须完成该动作要求的本地处理；不能先返回成功再异步完成主要步骤。

## 9. 并发规则

### 9.1 Control Plane

- Create Cat 使用 `(workspace_id, cat_slug)` 唯一约束串行化。
- Create Disk 使用 `(workspace_id, disk_slug)` 唯一约束串行化。
- Cat action 更新 `current_action` 时锁住 Cat 行；通常只有 `current_action IS NULL` 的请求可以取得
  执行权，destroy 可以原子替换其他未完成动作。
- 同一更新同时写入 `current_action_node_id`，使其他 Control replica知道应该查询哪台 Node。
- destroy 替换动作时继承旧 `current_action_node_id`；首次 create 尚未形成稳定 state 时先投影为
  `failure + current_action=destroy`，保持“state 为空只属于未完成 create”的数据库约束。
- 相同 `current_action` 的重复调用不创建第二个执行；它查询 `noded` 并等待当前动作结束。
- Disk attach/detach/destroy 在一个数据库 transaction 中锁定目标 Disk 和相关 Cat。
- create、Cold run 和失联恢复使用 [ADR-0061](decisions/0061-semantic-least-allocated-placement.md)
  的同一个事务内 Least-Allocated 策略；负载读取和 `current_action_node_id` reservation 由
  schema-scoped transaction advisory lock 串行。
- 网络调用发生在提交 `current_action` 之后，不持有数据库锁。

### 9.2 noded

- 每个 `cat_id` 一个互斥执行单元。
- 不同 Cat 可以并行。
- 同一 Cat 的非 destroy 动作不能并行。
- destroy 可以通知当前动作退出，但 destroy 返回前必须等待当前动作退出并完成清理。
- 同一块 Disk 的 attach/detach在 Node 内也必须串行。

## 10. Control Plane 异常后的恢复

Control Plane 可能在 `noded` 已经完成动作、但数据库尚未更新时退出。恢复不依赖 request ID：

1. 新 Control Plane 发现 Cat 的 `current_action` 不为空。
2. 使用 `current_action_node_id` 调用 `GET /v1/cats/{cat_id}` 查询实际状态。
3. 如果已经达到目标状态，更新 Cat row并清除 `current_action`。
4. 如果 `noded` 报告同一动作仍在执行，继续等待到动作 deadline；若数据库动作是 destroy、Node 仍在
   执行被替换动作，则重发 destroy 触发取消和清理。
5. 如果 `noded` 报告明确失败，写 `failure`。
6. 如果 Node 不可达，进入 Node 失联流程。

生产 Control 通过 schema-scoped PostgreSQL advisory lock 选举一个 Destroy 恢复任务。它只扫描早于
正常同步请求 deadline 的未结算 Destroy，每批和并发都有上限，并执行上述同一套 discovery-first 与
exact settlement 规则。选举会话丢失会取消本轮恢复并在退避后重新参选；其他 replica 也可继续扫描。
shutdown 才终止重选循环。该扫描器和用户重试不能各自定义恢复规则，也不成为新的 lifecycle
authority。扫描按 `updated_at, cat_id` 取最旧批次；单项失败以 exact Destroy/Node CAS 刷新
`updated_at` 并轮转到未尝试 claim 之后，失败满批次不能饿死后续 Destroy。

## 11. 核心流程

### 11.1 Create Cat

```text
CLI/REST create
-> Control检查(workspace, cat_slug)
-> 已有相同配置：返回already_exists
-> 已有不同配置：返回conflict
-> 创建Cat row，state=null，current_action=create
-> 校验并创建初始disk bindings
-> 选择running Node并写current_action_node_id
-> 同步PUT noded /cats/{cat_id}
-> noded创建磁盘、网络、VMM并等待Guest Ready
-> 成功：Control写state=running、node_id，并清空current_action/current_action_node_id
-> 明确失败：Control调用一次noded DELETE做本地清理，再写state=failure并清空current_action
-> 请求超时：按配置重试相同PUT；仍超时后调用一次noded DELETE并写state=failure
```

自动调用 noded DELETE 只清理本地执行环境，不把产品 Cat 自动改成 `destroyed`。产品 Cat 保持 `failure`，并清空 `current_action/current_action_node_id`；用户随后可以显式执行 `cats destroy`，该 destroy 在 noded 上是重复清理。如果 DELETE 没有得到明确结果，`node_id` 保留为尝试创建的 Node。

### 11.2 Run

```text
Control检查Cat为suspended/warm/cold
-> 若cold则选择Node
-> 写current_action=run和current_action_node_id
-> 同步调用noded run
-> 成功写running和node_id
-> 失败写failure
```

已 Running 直接返回 `already_running`。

### 11.3 Suspend

```text
Control检查Cat为running
-> 写current_action=suspend和current_action_node_id
-> noded停止新工作并暂停Guest
-> 成功写suspended，保留node_id
-> 失败写failure
```

### 11.4 Warm

```text
Control检查Cat为running或suspended
-> 写current_action=warm和current_action_node_id
-> noded保存本地恢复状态并退出VMM
-> 成功写warm，保留node_id
-> 失败写failure
```

### 11.5 Cold

```text
Control检查Cat为running/suspended/warm
-> 写current_action=cold和current_action_node_id
-> noded停止Guest并把需要保留的数据提交完成
-> noded卸载并关闭Cat本地运行环境
-> 成功写cold并清空node_id
-> 失败写failure
```

### 11.6 Destroy Cat

```text
Control检查Cat未destroyed
-> 锁住Cat行；若有当前动作则替换它，否则直接写current_action=destroy
-> current_action_node_id优先继承被替换动作的目标Node，否则使用稳定node_id
-> 如果有current_action_node_id，同步调用noded DELETE
-> noded停止当前动作并清理本地Cat
-> Control删除disk bindings
-> PersistentDisk保持normal
-> Cat写destroyed，清空node_id/current_action/current_action_node_id
```

已 Destroyed 直接返回 `already_destroyed`。

## 12. PersistentDisk 流程

### 12.1 Create Disk

```bash
cats disk create data-disk --size 100GiB
```

流程：

1. 解析容量为精确 `size_bytes`；`GiB` 使用 1024 进制。
2. 按 `(workspace_id, disk_slug)` 查询。
3. 同 slug、同容量返回已有 Disk。
4. 同 slug、不同容量返回冲突。
5. 不存在则生成 `disk_id` 并创建 `normal` Disk。

### 12.2 Create Cat 时挂盘

```bash
cats create web --mount data-disk:/data
```

Control Plane 在调用 noded 前完成：

1. 按当前 Workspace 解析 `data-disk`；
2. 验证 Disk 为 `normal`；
3. 验证没有绑定其他 Cat；
4. 验证 `/data` 未被同一 Cat 的其他 Disk 使用；
5. 写入 binding；
6. 将完整 mount 列表传给 noded create。

noded 只有在所有声明的 Disk 都已经出现在 Guest 并成功挂载到目标路径后，才能返回 create/run 成功。

### 12.3 Cold Cat 挂盘和卸盘

Attach 和 detach 只修改 Cold Cat 的配置与 binding，不启动 Guest。下一次 run 使用最新完整 binding 集合。

### 12.4 Destroy Disk

Disk 只有未绑定时才能 destroy。删除成功后可以保留 `deleted` 历史行，但该行不再占用 slug；随后可以用相同 slug 创建具有新 `disk_id` 的 Disk。

## 13. Node 注册与心跳

### 13.1 首次注册

```text
POST /v1/internal/nodes/register
```

`noded` 必须在注册请求中显式填写自己对 Control Plane 可达的 `control_endpoint`；Control Plane 不根据注册连接的来源地址猜测回连地址。

请求：

```json
{
  "node_id": "node_123",
  "node_name": "worker-us-east-1a-01",
  "control_endpoint": "http://10.0.1.23:7310",
  "vendor": "aws",
  "region": "us-east-1",
  "zone": "us-east-1a",
  "instance_id": "i-123",
  "machine_type": "m7i.4xlarge",
  "node_version": "1.0.0"
}
```

语义判断：

- `node_id + instance_id` 不存在：创建并返回 `registered`；
- 身份和 `control_endpoint` 都相同且状态为 `running`：返回 `already_registered`；
- `node_id` 和云实例身份相同、仅 `control_endpoint` 改变：更新地址并返回 `registered`；
- `node_id` 相同但 `node_name` 或云实例信息不同：返回 `node_identity_conflict`；
- Node 为 `offline/reset_required`：返回 `reset_required`；
- Node 为 `deleted`：拒绝注册，必须提供新的 `node_id`。

### 13.2 心跳

默认建议：

- 每 10 秒发送一次；
- 连续 3 次未收到后进入 `suspected` 内部判断；
- Control Plane 再主动调用一次 `GET /v1/health`；
- 探测仍失败则将 Node 标记为 `offline`。

心跳请求更新 `node_heartbeats`，并可以附带当前 Cat 数量和资源使用率。重试心跳只覆盖同一 Node 的最新值，不创建额外业务动作。noded 必须处理心跳响应；收到 `reset_required` 时不能继续下一个普通心跳周期，而要立即进入 reset 流程。

### 13.3 失联 Node 重新出现

Node 已被标记 `offline` 后再次发送心跳或注册请求时，Control Plane 返回：

```json
{
  "status": "reset_required"
}
```

noded 随后：

1. 停止接受新的 Cat 动作并立即停止本机全部 Cat 相关进程；
2. 卸载 Cat 相关设备；
3. 删除本地运行、暂停和 Warm 状态；
4. 不删除 PersistentDisk 的产品数据、底层远端对象或 Control Plane binding；
5. 保留系统自身配置和注册信息；
6. 再次提交注册并声明 reset 已完成。

reset 完成前，noded 不能继续运行残留 Cat，也不能接受新的 placement。Control Plane 验证后将 Node 恢复为 `running`。如果该云实例已经被标记 `deleted`，则不能恢复，必须以新的 `node_id` 加入。

## 14. Node 维护与迁移

### 14.1 正常维护

```text
Node running
-> 标记draining，停止新Cat placement
-> 记录每个Cat原状态
-> 每个Cat转换到cold
-> 在目标Node上run
-> 原状态是suspended时再suspend
-> 原状态是warm时再warm
-> 返回逐Cat结果
-> 运维确认完成后另行关闭旧Node
```

跨 Node 不搬运 Suspended/Warm 的本地内存状态。原来是 Suspended 或 Warm 的 Cat 会在目标 Node 上先正常 run，再转换回对应状态。

管理入口为：

```text
POST /v1/admin/nodes/{node_id}/actions/drain
```

Control 在接受任何 Cat 迁移前先把 Node 提交为 `draining`。每个 Cat 的原 state、源 placement 和目标
reservation 保存在 Cat 当前行；独立 recovery 周期会重新发现仍有 Cat 的 draining Node，因此请求取消、
Control 重启或重复调用都继续同一排空。耗时迁移不在 heartbeat/liveness probe 的串行路径上。已有普通
`current_action` 返回 `blocked/busy`，不会被排空抢占。

成功响应为 HTTP 200：

```json
{
  "status": "blocked",
  "source_node_id": "node_source",
  "cats": [
    {
      "status": "migrated",
      "cat_id": "cat_web",
      "target_node_id": "node_target",
      "state": "running"
    },
    {
      "status": "blocked",
      "cat_id": "cat_worker",
      "code": "busy",
      "message": "Cat has another lifecycle action in progress"
    }
  ]
}
```

顶层只有 `drained/blocked`；逐 Cat 只有 `migrated/stale/blocked`。任一 Cat 无法 Cold 时，排空阻塞并把
失败 Cat 留在源 Node，不强制关机。目标恢复失败的 Cat 留在目标 Node 的 `failure` 状态供显式清理。接口
不会自动关闭或 uncordon Node；Node 保持 `draining`。

这里“失败”只包括 noded 明确返回的终态 failure/conflict。timeout、transport/protocol ambiguity 或无法
完成 postcondition query 时保留原 state、source placement 和 relocation claim，下一 recovery pass 继续
discovery。若 reserved target 已经 offline/reset_required/deleted 或不存在，源仍 draining 时在 Cat row
lock 内以 Least-Allocated 策略选择新 target，并在同一事务撤销可能已经发布的 exact 旧目标入口、替换
reservation；旧 target 的迟到 publish/settlement 因 exact target 不匹配而不能提交。

### 14.2 异常退出

```text
连续心跳丢失 + 主动探测失败
-> Node offline
-> 撤掉这些Cat指向旧Node的流量入口
-> Control把受影响Cat按原目标状态放到其他Node
-> 先从磁盘Cold启动
-> 新实例Ready后把每个Cat的唯一入口切到新Node
-> 再恢复为running/suspended/warm目标状态
```

该流程不等待旧机器停止，因此可能短暂存在两个物理 Cat。入口切换后，新进入的流量只发送到新实例；旧实例的已有连接、后台任务、主动出站请求和磁盘写入在短暂窗口内不受入口切换约束。按照本文不考虑长期不对称网络的假设，旧 Node 会在下一个允许的心跳窗口内重新联系 Control Plane、收到 `reset_required` 并立即停止清理，双跑窗口最多持续一个允许的心跳窗口加上停止清理时间，随后只剩新实例运行。

## 15. 超时与重试

每种动作有独立配置：

```text
connect_timeout
request_timeout
retry_count
retry_interval
```

规则：

- Control 只重试同一个 Cat、同一个动作和完全相同的参数；
- noded 每次都先检查目标结果是否已经满足；
- create 最终超时后，Control 额外调用一次 noded DELETE 清理本地资源；
- 其他动作最终超时后，Control 查询一次 Cat 状态；无法确定时写 `failure`；
- planned drain 是上一条的窄例外：源 Cold 或目标恢复结果不明时保留 exact relocation claim，由独立周期
  worker 重试 discovery，不写 `failure`；
- destroy 超时保持 `failure`，允许用户再次 destroy；
- timeout 不自动选择另一台 Node，Node 迁移只走 Node offline 流程。

## 16. 错误闭集

推荐使用以下稳定错误码：

```text
cat_not_found
cat_configuration_conflict
cat_destroyed
invalid_state
busy
node_unavailable
node_reset_required
node_identity_conflict
disk_not_found
disk_size_conflict
disk_deleted
disk_in_use
disk_already_attached
disk_binding_conflict
mount_path_conflict
cat_must_be_cold
guest_start_failed
guest_suspend_failed
guest_warm_failed
guest_cold_failed
destroy_failed
timeout
internal_error
```

错误响应必须包含稳定 `code`。`message` 面向人类，可以随版本改善，客户端不能解析 message 判断分支。

## 17. 日志与监控

至少记录：

- Control API action开始时间、结束时间、Cat/Disk/Node ID、Node展示名、结果和错误码；
- Control 到 noded 的调用次数、耗时、timeout和重试次数；
- 每个 Cat 的 `current_action` 持续时间；
- Node heartbeat最后到达时间和连续失败次数；
- Node running/draining/offline/reset_required数量；
- noded 每种 action 的成功、already_done、busy、failure和timeout数量；
- Disk attach/detach冲突和被占用次数。

日志不参与幂等或恢复判断；实际资源状态和数据库当前行才参与判断。

## 18. 验收测试

### 18.1 Cat

- 同一 Workspace 并发 create 同一 slug，只产生一个 `cat_id`。
- 相同配置重复 create 返回同一 Cat。
- 不同配置重复 create 返回 conflict。
- 不同 Workspace 可以使用相同 slug。
- Cat destroyed 后可用相同 slug 创建新的 `cat_id`，slug 查询只返回新的未 destroyed Cat。
- 对已经到达目标状态的 run/suspend/warm/cold重复调用不执行第二次物理动作。
- failure只允许destroy。
- destroy从任意未destroyed稳定态、failure和进行中的首次create取得执行权，不返回busy。
- 被destroy替换的动作迟到完成时不能覆盖destroy claim或最终destroyed状态。
- destroy重复调用返回already_destroyed。

### 18.2 Disk

- 同一 Workspace 同 slug、同容量重复 create只产生一个 Disk。
- 同 slug、不同容量返回 conflict。
- Disk deleted 后可用相同 slug 创建新的 `disk_id`，slug 查询只返回新的未 deleted Disk。
- 同一 Disk 重复绑定同一 Cat 和路径返回 already_attached。
- 同一 Disk 绑定不同 Cat 返回 disk_already_attached。
- 同一 Cat 同一路径绑定不同 Disk 返回 mount_path_conflict。
- detach 不存在的 binding 返回 already_detached。
- Running Cat attach/detach返回 cat_must_be_cold。
- 已绑定 Disk 不能 destroy。
- Cat destroy保留Disk并删除binding。

### 18.3 noded

- 相同 Cat create重复调用不会启动第二个 VMM。
- create正在执行时重复 create不会启动第二个任务。
- destroy能够终止正在执行的 create并等待清理完成。
- destroy后同一 `cat_id` 的旧 create不会重新启动。
- 同一 Cat 的两个不同动作不能并发执行。
- 不同 Cat 可以并行执行。

### 18.4 Node

- 心跳重试只更新同一行。
- 连续心跳丢失但主动探测成功时不标记offline。
- offline Node 返回后收到reset_required。
- reset完成前不接受新Cat。
- draining Node不接受新placement。
- planned drain保持每个Cat最终产品状态。
- planned drain在迁移前持久化目标 reservation，Control 重启后继续，且不抢占普通Cat动作。
- planned drain要求源端先完成Cold；源端失败留源清理，目标端失败留目标清理。
- planned drain的源/目标结果不明时保留原状态和claim；reserved target失联时能exact retarget，旧结果不能
  覆盖新target。
- 慢planned drain或offline recovery不能阻塞heartbeat probe cadence，shutdown会取消当前周期工作。
- offline Node 上的 Cat 在跨 Node 恢复前先撤掉旧入口，新实例 Ready 前不发布新入口。
- 入口切换后只把新进入的流量发送到新 Node。
- offline Node 的下一次成功心跳返回 `reset_required`，noded 不等待下一个心跳周期，立即停止和清理残留 Cat。
- 在允许的网络假设下，双跑不超过一个心跳窗口加停止清理时间，reset 完成后只剩新实例运行。
- offline Node 清理残留 Cat 前不接受新 placement。

### 18.5 Control 异常

- noded成功但Control在更新Cat前退出，恢复后能通过查询noded完成状态更新。
- noded明确失败但Control在写failure前退出，恢复后写入failure。
- current_action超时扫描与用户重试不会产生两个noded动作。
- Control在destroy替换动作后退出，恢复者看到Node仍执行旧动作时会重发destroy并完成清理。

## 19. 已知取舍

场景语义幂等简化了调用方和协议，但有明确代价：

1. slug 只定位当前未销毁实体；slug 复用后，历史记录、后台任务和内部调用必须使用不可变内部 ID，不能再用 slug 反查旧实体。
2. create参数变化必须返回 conflict，不能猜测这是更新请求。
3. attach到不同 mount path必须先显式detach，不能把重复attach解释为修改。
4. 很久以前的旧状态动作如果跨越后续转换才到达，系统可能无法仅凭动作名称判断它是不是旧请求；V1依赖有界同步调用和同Cat串行执行避免这种使用方式。
5. Node 重启采用停止并清理本地 Cat 的简单恢复方式，因此不提供保留本地 Suspended/Warm 状态的进程级无损恢复保证。
6. 心跳既用于发现失联，也让重新出现的旧 Node 收到 `reset_required` 并停止残留 Cat。在本文排除长期不对称网络的前提下，双跑只存在于一个允许的心跳窗口加停止清理时间内，最终收敛为单实例；唯一入口在该窗口内只保护新进入的流量，不能立即停止旧连接、后台任务、主动出站请求或旧实例写盘。
7. 本设计不支持只在 Node 本地持久、尚未远端提交的数据；增加这种模式时必须重新设计 Node 失联、迁移和 reset 规则。

这些限制是本设计选择的产品边界，不应在实现或上线说明中描述为完整生产 HA。
