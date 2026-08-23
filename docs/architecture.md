# Cats 技术架构

- 状态：目标架构 + 当前实现边界；Control/Node 生命周期以
  [ADR-0059](decisions/0059-semantic-control-node-synchronous-protocol.md) 为当前唯一协议
- 更新：2026-08-22
- 适用范围：产品资源、控制面、Node、网络入口、microVM 与块存储

## 1. 大目标

Cats 提供可暂停、可快速恢复、可冷恢复的 Linux microVM。用户看到普通 Linux、标准
virtio block device、ext4、稳定入口和同步 CLI/API；对象存储、VMM、Node 管理和磁盘写入
权限留在平台内部。

架构优先保证三件事：

1. 产品语义简单：相同资源、相同参数和相同目标的重试得到同一结果。
2. 当前事实明确：Cat、Disk、Node 当前行决定控制动作，心跳、日志和监控不替代它们。
3. 数据边界不被简化协议削弱：远端持久化、RWO 写入权限和 Host 隔离仍由各自底层机制负责。

## 2. 总体模型

Control/Node 生命周期采用同步、场景语义协议：

```text
CLI / REST
    |
    v
Control: 当前资源行 + current_action + placement
    |
    | transaction 提交后同步调用
    v
noded: 按 cat_id 串行执行并返回实际结果
    |
    v
Control: 写稳定状态并清除 current_action

heartbeat -> offline/reset_required 判断
入口目标   -> 恢复前 withdraw，Ready 后 publish
```

协议不接收 `request_id`、Idempotency-Key 或 lifecycle Operation ID，不使用 Node command
poll/result、不使用 per-Cat command journal，也不以 AgentSession、typed predecessor 或
HostFenceRecovery 组织生命周期。幂等身份直接来自业务场景：

- Cat create：`workspace_id + cat_slug + 完整创建配置`；
- Disk create：`workspace_id + disk_slug + size_bytes`；
- 状态动作：`cat_id + 目标状态`；
- attach：`cat_id + disk_id + mount_path`；
- detach/destroy：当前绑定或资源是否已经不存在。

一次网络调用期间不持有 PostgreSQL transaction。若 noded 已完成而 Control 尚未写回就退出，
恢复者使用 Cat 行保存的目标 Node 查询实际状态，再完成当前行。

通知、缓存和监控只用于降低延迟或发现异常，不能结算产品动作。

需要新 Node 的 create、Cold run 和失联恢复使用
[ADR-0061](decisions/0061-semantic-least-allocated-placement.md)的事务内 Least-Allocated 策略；Node
heartbeat 利用率不成为 placement authority。

## 3. 当前实现边界

当前分支正在执行空数据、单协议切换。下面只描述已组成的代码事实，不代表完整物理上线门已通过：

| 范围 | 当前事实 | 仍未完成或未验证 |
|---|---|---|
| 公共协议 | Cat/Disk/Node 同步 DTO、稳定错误码、内部 Bearer 认证已组成；严格拒绝旧幂等和 Operation 字段 | 最终全仓协议残留检查待门禁 |
| PostgreSQL | v19 当前资源表、可复用 slug 的部分唯一索引、Disk binding RWO、Cat 动作 CAS、数据库接收时间心跳和当前入口目标已组成；旧 lifecycle/Route settlement schema 已删除 | 最终 PostgreSQL 全仓门待跑 |
| Control | 同步 lifecycle、超时后 Node 查询、资源 API、入口先撤后发、Node 注册/心跳/reset/drain 和失联恢复已接入生产进程；真实 Control→noded HTTP 的 Cat 全状态机与重复语义已通过 | PersistentDisk/CH 完整纵向联调和最终门禁待完成 |
| noded | 同步 HTTP server、按 Cat 串行、destroy 清理、reset gate、注册和 heartbeat supervisor已组成 | Cloud Hypervisor 的完整实际 effects 尚未接入；当前 CH bridge 在缺少精确输入时会在物理副作用前失败 |
| PersistentDisk | slug、目录、binding 语义、精确卷/文件系统身份、Guest mount-ready 校验器和 Strict provision/delete backend 已组成；backend 已接入 production composition | Guest/CH 物理挂载链和产品 E2E 尚未完成 |
| Node 失联恢复 | offline 后按数据库当前事实反复发现未迁走 Cat，先撤入口、在其他 running Node 恢复、Ready 后发布；旧 Node 回来要求 reset | 双跑窗口的真实两 Node 验证待完成；协议本身不承诺严格物理单实例 |
| 入口 | 当前 `cat_id -> node_id` 目标和 withdraw/publish 顺序已组成 | 公网 Gateway/Endpoint 传输协议不在本次 Control/Node 合同范围 |
| 底层存储 | ChunkStore、delta、golden root、NBD/vhost-user-blk、MetadataStore owner/epoch 和相关测试已存在 | 本次同步 lifecycle 只允许远端持久模式；磁盘产品 E2E、Snapshot/GC 和真实 Host-loss 资格仍开放 |
| 独立 Node authority | `runtime_node_authority` 管理入口仍独立组成 | 它不成为 Cat 生命周期、心跳或失联恢复的第二套协议 |

## 4. 组件职责

| 组件 | 负责 | 不负责 |
|---|---|---|
| Control Plane | Workspace 授权、资源当前行、`current_action`、placement、同步调用 noded、Node liveness 和当前入口目标 | Running 块 I/O、VMM 是否真实存在、把心跳当动作结果 |
| Gateway/入口层 | 把新流量发送到每个 Cat 的唯一当前目标 | 生命周期动作、磁盘写入权限、保证旧连接立即消失 |
| noded | 一台机器上的 Cat 实际状态、按 `cat_id` 串行动作、VMM/blockd/Guest 效果、reset 清理 | 用户 slug authority、跨 Host 自行选择 placement |
| Cloud Hypervisor/Guest Agent | microVM 执行、pause/snapshot/restore、Guest readiness 和 mount readiness | S3/PostgreSQL/WorkOS 凭据与产品调度 |
| cats-blockd | 标准块协议、cache/delta/commit 和 owner/epoch 检查 | Cat slug、产品状态和入口切换 |
| PostgreSQL | Cat/Disk/Node 当前资源、动作占用、binding、入口目标及存储 metadata CAS | 判断 VMM 进程是否实际存在 |
| Object Store | immutable Chunk/Map/Delta/Base/Snapshot 对象 | 当前 Cat 状态、当前 writer 和入口选择 |

具体云厂商实现只出现在 composition root 和 `adapters/`；核心协议不依赖 AWS/GCP 类型。

## 5. 产品资源与权威

### 5.1 Cat

Cat 有不可变 `cat_id` 和 Workspace 内用户指定的 `cat_slug`。当前行保存稳定 `state`、
`current_action`、动作目标 Node、当前 `node_id`、完整创建配置和错误信息。

稳定状态为 `running/suspended/warm/cold/failure/destroyed`。首次 create 进行中时 state 可以为空。
`destroyed` 是历史终点，不是第五个可恢复 runtime 状态；`failure` 只允许 destroy。

slug 只解析当前未 destroyed 的实体。destroy 后 slug 立即释放；再次 create 同名 Cat 会生成新的
`cat_id`。内部任务、Node 调用和历史查询必须使用不可变 ID，不能用已复用 slug 猜旧资源。

### 5.2 PersistentDisk

PersistentDisk 有不可变 `disk_id` 和 Workspace 内用户指定的 `disk_slug`，状态为
`normal/deleted`。delete 后 slug 立即释放，新建同名 Disk 会生成新的 `disk_id`。

`disk_bindings` 以 `UNIQUE(disk_id)` 保证产品数据中一块 Disk 同时最多绑定一个 Cat，并以
`UNIQUE(cat_id, mount_path)` 防止挂载点冲突。binding 当前是否存在就是产品关联事实；这条数据库
约束不是失联双跑窗口内的物理单写证明。

### 5.3 Node

Node 有内部 `node_id`、不可变展示名 `node_name` 和 Control 可达的 `control_endpoint`。Node 注册时
显式上报地址；普通 heartbeat 不能修改展示名或回连地址。

`node_heartbeats.last_heartbeat_at` 由 PostgreSQL 接收时间写入并用于失联判断；Node 自报时间只作诊断。
`running` Node 才能接受 placement；`draining/offline/reset_required/deleted` 都不能。

### 5.4 每类事实的唯一写入方

| 事实 | 写入 authority | 非 authority |
|---|---|---|
| Cat/Disk/Node 产品状态、动作占用和当前 placement | PostgreSQL 当前资源行 | heartbeat、日志、metrics |
| VMM/blockd/Guest/mount 是否实际存在 | noded 的实际执行与查询 | Control 的旧稳定 state |
| 当前新流量目标 | PostgreSQL 当前入口目标 | Node heartbeat、历史 placement |
| volume writer、attachment epoch、remote root | MetadataStore CAS | `disk_bindings`、Cat state、入口目标 |
| 本地尚未远端发布的数据 | 原 Node 的持久数据路径 | Control 当前行、可删除 cache 的猜测 |
| Host 是否已经隔离 | 可信外部 Host fence 证据 | heartbeat timeout、入口撤销、Node offline |
| fleet provisioning/credential policy | 独立 `runtime_node_authority` | Cat lifecycle 和 Node heartbeat |

## 6. 同步生命周期

### 6.1 合法状态转换

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

同一目标已经满足时返回 `already_*`，不调用 noded。相同动作进行中时查询并等待它；不同的非 destroy
动作返回 `busy`。destroy 是唯一抢占例外：Control 在 Cat 行锁内把未完成动作替换为 destroy，并继承
它的目标 Node；旧动作的迟到写回因 exact action/Node 不匹配而失效。Control 提交后才同步调用目标
noded。

noded 每个 `cat_id` 一个串行执行单元，不同 Cat 可以并行。destroy 可以要求当前动作退出，但必须在
返回前等待退出并清理。noded 对同一 `cat_id` 保留本注册周期的 destroyed marker，防止旧内部 create
在清理后重新启动；该 marker 与可复用用户 slug 无关。

### 6.2 结果和恢复

- 成功：Control 写目标稳定状态、placement，并清除 `current_action`。
- 明确失败：create/run/suspend/warm/cold 写 `failure`；destroy 失败保持 `failure`，可重试。
- Control 在 Node 已完成后退出：恢复者按 `current_action_node_id` 查询 Node，按实际终态清除动作。
- Node 不可达：进入 Node offline 流程，不由 heartbeat 直接写动作成功或失败。

完整请求、响应、超时和错误闭集见
[Control Plane 与 noded 同步协议设计](control-node-semantic-protocol.md)。

## 7. 四态和数据屏障

| 状态 | Guest/VMM | 本地依赖 | 远端数据要求 | placement |
|---|---|---|---|---|
| Running | Guest 与 VMM 运行 | cache 和运行资源 | 本协议要求成功 FLUSH 已远端持久 | 当前 Node |
| Suspended | VMM 保留、Guest pause | 原 Node 内存/设备状态 | 不新增只在本地成功的数据语义 | 原 Node |
| Warm | VMM 退出、本地快速恢复状态 | 原 Node snapshot | retained volumes 已远端持久 | 原 Node |
| Cold | 无 VMM/内存态 | 不依赖原 Node | retained volumes 已远端持久并可重新取得 writer | 无固定 Node |

Suspended 与 Warm 不合并：前者保留 VMM，后者退出 VMM。跨 Node 不搬运这两种本地状态；恢复时从
远端 Cold 数据启动，再转换回原产品目标状态。

离开 Running 的动作在暂停或停止 Guest 前必须先撤掉新的外部流量入口。新 Running 实例只有在
Guest 和所有声明的 PersistentDisk mount 都 Ready 后才能发布入口。

## 8. 存储与数据安全边界

Guest 只看到标准 virtio block device 和未修改的 ext4，不持有对象存储或 MetadataStore 凭据。
`cats-blockd` 继续使用稀疏 cache、64 KiB dirty page、delta/base object、Merkle Map 和 PostgreSQL
root/owner CAS；详细格式和 FLUSH 合同见 [storage.md](storage.md) 与
[blockd protocol](specs/blockd-protocol.md)。

底层存储实现仍区分 Strict 与 Relaxed 的 `R/L` 水位，但 ADR-0059 的简化生命周期只允许“成功 FLUSH
已经远端持久”的运行模式。也就是说，参与失联恢复、reset、Warm、Cold、detach、计划迁移或
PersistentDisk 保留的数据都必须能从远端事实恢复。若要重新允许 `R < L` 的 Node-local-only 成功数据，
必须另行设计协议，不能直接复用当前 offline/reset 流程。

RWO 数据安全没有因为 lifecycle 简化而转移到 heartbeat 或 binding：

- `disk_bindings` 防止控制面同时把一块盘分配给两个 Cat；
- MetadataStore owner/attachment epoch 防止旧 writer 发布到新的远端 root；
- `runtime_node_authority` 继续独立管理受信 Node provisioning/credential 边界；
- 可信 Host fence 仍是证明旧 Host 已停止的独立能力。

当前跨 Node offline 恢复不等待 Host fence，因此只承诺入口先撤后发和在约定网络窗口内最终 reset，
不承诺窗口内物理单实例、旧连接停止或绝对物理单写。这是明确风险；不能把入口切换或心跳称为 fence。

PersistentDisk 只有在 Guest 按稳定设备身份找到设备、验证预期文件系统并确认目标路径已经 mount 后，
create/run 才能成功。Strict provision/delete backend 已接入 production composition，精确身份也已贯穿
Control/noded wire，但 Guest/Cloud Hypervisor 物理挂载链仍未闭合，不能从 backend 完成推断完整物理路径已经上线。

## 9. Node 注册、失联与恢复

正常维护按以下顺序执行：

```text
running -> draining -> 停止新 placement
        -> 记录每个 Cat 原状态
        -> 转为 Cold
        -> 在目标 Node 从远端启动
        -> 恢复原 Running/Suspended/Warm 目标
        -> 关闭旧 Node
```

异常失联的目标流程是：

```text
连续心跳丢失 + 主动 health 探测失败
-> Node offline
-> 撤掉该 Node 上 Cat 的旧入口
-> 在其他 running Node 从远端恢复
-> 新实例 Ready 后发布唯一当前入口
-> 旧 Node 再次通信时返回 reset_required
-> noded 立即停止并清理全部残留 Cat
-> reset 完成后重新注册，才允许 placement
```

恢复扫描是 level-triggered：每个 liveness 周期按 PostgreSQL 当前状态重新发现 offline Node 上尚未迁走
的 Cat，因此 Control 重启或一次临时错误不会永久丢失恢复工作。

本协议假设旧 Node 会在允许的心跳窗口内重新联系 Control。双跑通常上限为允许的心跳窗口加停止清理
时间；唯一入口只保护新流量，旧连接、后台任务、主动出站请求和旧实例写盘仍可能继续。长期不对称
网络不在 V1 保证范围。

## 10. 入口模型

本次协议只要求每个 Cat 最多一个当前新流量目标：

- 当前目标保存为 `cat_id -> node_id`；不存在行表示已撤流；
- 同一目标重复 publish 成功；
- 从旧 Node 换到新 Node 必须先 withdraw，不能直接覆盖；
- 旧 Node 的迟到 withdraw 不能删除已经发布的新目标；
- 只有 Running 且 Ready 的目标才发布，Suspended/Warm/Cold 不发布。

公网 hostname、TLS、Gateway 缓存和 Endpoint 细节不属于 ADR-0059。旧 Route Operation、AgentSession
binding 和 signed poll/result lane 不是当前 Control/Node 生命周期协议；历史规格只作为 superseded
资料保留。

## 11. 故障合同

| 故障 | 当前保证 | 明确不保证 |
|---|---|---|
| 单个 Control replica 退出 | 其他 replica 读取 Cat 当前行并查询目标 Node | 未提交 HTTP response 不会丢失 |
| Control 全断 | 已 Running 的 VMM/blockd 继续 | 新 mutation、显式状态转换和新入口切换 |
| PostgreSQL 暂不可用 | 已 Running 计算继续 | 新动作 claim、状态写回、placement 和入口更新 |
| Object Store 暂不可用 | 已缓存读取可按底层合同继续 | 远端持久 FLUSH、Warm/Cold、迁移和恢复完成 |
| noded 调用响应丢失 | Control 重试相同动作或查询相同 `cat_id` | 任意延迟、跨多次后续转换的旧请求 exactly-once |
| Node Agent 进程退出 | reset/re-register 后从 Control 当前事实重新加入 | 保留本地 Suspended/Warm 的进程级无损恢复 |
| Node 失联 | 撤旧入口、其他 Node 恢复、旧 Node 回来 reset | 恢复窗口内严格物理单实例或旧连接立即停止 |
| Host 永久丢失 | 只从已经远端持久的数据恢复 | 把 heartbeat timeout 当作可信 Host fence |

## 12. 实施和上线边界

### 12.1 当前依赖顺序

1. 当前资源 schema、共享 DTO 和场景语义规则；
2. Control 同步 lifecycle、noded 每 Cat 串行与 Node 注册/heartbeat/reset；
3. 闭合 PersistentDisk 的 Guest 物理挂载链和 Cloud Hypervisor effects；
4. 在已通过的 HTTP/PostgreSQL 场景基础上跑真实双 Node 纵向联调；
5. 旧 Route v2 部署合同清理和最终全仓、Linux 门禁。

并行进度、提交和验证只在
[实施计划](semantic-control-node-implementation-plan.md)维护，本文不复制滚动提交表。

### 12.2 Clean-slate 部署

首次部署使用一个空 v19 schema，不迁移旧 Cat/Disk/Node/runtime 数据，不双读、双写或运行混合版本：

1. 构建并验证同一版本的 Control、noded 和 CLI；
2. 进入维护窗口，关闭公网入口和 mutation；
3. 停止全部旧 Control/Node/Gateway write path；
4. 轮换或撤销旧内部凭据；
5. 删除旧产品数据并创建空 v19 schema；启动必须拒绝旧 schema version；
6. 先启动 Control，再让空净 Node 用 `node_id/node_name/control_endpoint` 注册；
7. 完成定向 smoke、纵向测试和最终门禁后再开放 mutation 和入口。

旧 Operation、Node command poll/result、AgentSession、inventory settlement 和 command journal 不保留兼容
入口。Git history 是旧实现的档案。

## 13. 上线验收重点

- 同 Workspace 并发 create 同一 Cat/Disk slug 只产生一个当前实体；destroy/delete 后可复用 slug，
  查询只返回新内部 ID。
- 多 Control replica 只能为同一 Cat 取得一个 `current_action`；noded 同一 Cat 物理动作也串行。
- 同一 Disk 不能同时绑定两个 Cat；相同 Cat、Disk、mount 的重试不产生第二个 binding。
- noded 已完成而 Control 写回前退出时，恢复者能查询 Node 并清除原动作。
- offline 前必须经过连续 heartbeat 超时和主动探测失败；旧 Node 下一次通信收到
  `reset_required`，reset 完成前不能接受 placement。
- 跨 Node 恢复先撤旧入口，Running Ready 后才发布新入口；允许窗口内的双跑被真实测试并最终收敛。
- PersistentDisk Strict backend 和精确身份已进入 production composition，但仍须通过 Guest
  mount-ready 和 Cloud Hypervisor 纵向测试；真实 Control→noded HTTP/FakeVmm 结果不能替代物理上线证据。
- production route map 不包含 lifecycle Operation GET、Node command poll/result、AgentSession 或
  observation settlement。
- `./scripts/quality.sh full` 和适用的 Linux/Cloud Hypervisor 门禁在 exact commit 上通过或明确记录环境阻塞。

## 14. 文档边界

- 本文：组件、authority、当前实现和故障边界。
- [Control Plane 与 noded 同步协议设计](control-node-semantic-protocol.md)：当前同步 wire、数据模型、
  场景语义和验收。
- [runtime-lifecycle.md](runtime-lifecycle.md)：四态、动作和数据/入口屏障。
- [storage.md](storage.md)：当前 ChunkStore 与 FLUSH 数据正确性。
- [Volume Authority](specs/volume-authority.md)：底层卷 owner/epoch、remote root 与磁盘数据安全；其中旧
  lifecycle Operation/AgentSession 组合段落已被 ADR-0059 supersede。
- [operations-ha.md](operations-ha.md)：运行拓扑、心跳/reset、故障恢复和资格验证。
- [Atomic Runtime Lifecycle v1](specs/atomic-runtime-lifecycle-v1.md)、
  [Runtime Inventory v1](specs/runtime-inventory-observation-v1.md) 和
  [Route Grant v2](specs/route-grant-v2.md)：历史已实现协议资料；其 Operation/poll/journal/AgentSession
  协调已经由 ADR-0059 supersede，不是当前目标协议。
- `docs/decisions/`：决策及 superseded 链。
- `experiments/`：保留环境、样本和 oracle 的证据，不是生产 SLA。
