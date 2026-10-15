# Cats 技术架构

- 状态：目标架构 + 当前实现边界；Control/Node 生命周期以
  [ADR-0059](decisions/0059-semantic-control-node-synchronous-protocol.md) 及其
  [ADR-0062 Destroy 修正](decisions/0062-destroy-preempts-in-progress-cat-actions.md) 为当前协议；Exec/Shell
  live access 以 [ADR-0065](decisions/0065-exec-shell-runtime-access-lane.md) 为当前合同
- 更新：2026-10-15
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

- Cat create：`workspace_id + cat_slug + 用户选择的 CPU/内存/初始 mounts`；Control 只在新建时绑定
  部署选择的当前默认 Golden Root digest；
- Disk create：`workspace_id + disk_slug + size_bytes`；
- 状态动作：`cat_id + 目标状态`；
- attach：`cat_id + disk_id + mount_path`；
- detach/destroy：当前绑定或资源是否已经不存在。

一次网络调用期间不持有 PostgreSQL transaction。若 noded 已完成而 Control 尚未写回就退出，
恢复者使用 Cat 行保存的目标 Node 查询实际状态，再完成当前行。

通知、缓存和监控只用于降低延迟或发现异常，不能结算产品动作。

Exec/Shell 不扩展上面的 lifecycle action lane：Control 在 Workspace auth 后按需调用 normal `run`，
重新读取当前 placement，再由 noded 的 exact-Running-incarnation access gate admit live session。离开
Running 和 reset 先 close/cancel/bounded-drain；Exec 模糊结果不使用 lifecycle 重试。精确合同见
[Exec/Shell Protocol v1](specs/interactive-shell-protocol.md)。

Control 的 public/内部 Exec transport loss 或 shutdown 只使调用方结果未知并回收 Control 本地请求，
不是已进入 noded handler 的 cancel authority。Node Exec 必须继续持 exact guard，直到 wall timeout、
Node lifecycle close、Node↔Guest loss 或 terminal result；V1 不增加 request ID/cancel endpoint。

需要新 Node 的 create、Cold run 和失联恢复使用
[ADR-0061](decisions/0061-semantic-least-allocated-placement.md)的事务内 Least-Allocated 策略；Node
heartbeat 利用率不成为 placement authority。

## 3. 当前实现边界

当前实现采用空数据、单协议部署。下面描述已组成的代码事实；历史验收入口和开放项见
[文档索引](README.md#当前实现与目标)，每次交付仍须重跑适用的物理资格门：

| 范围 | 当前事实 | 仍未完成或未验证 |
|---|---|---|
| 公共协议 | Cat/Disk/Node 同步 DTO、稳定错误码、内部 Bearer 认证已组成；严格拒绝旧幂等和 Operation 字段；最终发布候选门已通过 | 后续改动必须在自身 exact commit 重跑门禁 |
| PostgreSQL | v20 当前资源表、可复用 slug 的部分唯一索引、Disk/Snapshot authority、Cat 动作 CAS、数据库接收时间心跳和当前入口目标已组成；旧 lifecycle/Route settlement schema 已删除 | 不因此承诺跨长期分区的物理单写 |
| Control | 同步 lifecycle、超时后 Node 查询、资源 API、入口先撤后发、Node 注册/心跳/reset、planned drain 和失联恢复已接入生产进程；真实 Control→noded HTTP 与 production physical E2E 已通过 | 新版本仍须重跑 exact release qualification |
| noded | 同步 HTTP server、按 Cat 串行、destroy 清理、reset gate、注册/heartbeat supervisor和Cloud Hypervisor实际effects已组成 | vhost-user-blk 等替代frontend仍按各自release资格验证 |
| PersistentDisk | slug、binding、精确卷/文件系统身份、Strict backend、Guest mount-ready、Cold DiskSnapshot、完整 root GC 保护与同盘 restore 已组成；Cold detach/attach和同盘重挂production E2E已通过 | hot Snapshot、跨盘 clone和真实 Host-loss qualification 仍开放 |
| Node 失联恢复 | offline后按数据库当前事实反复发现未迁走Cat，先撤入口、在其他running Node恢复、Ready后发布；真实两Node reset/re-register已验证 | 协议不承诺双跑窗口内严格物理单实例或长期不对称网络安全 |
| 入口 | 当前 `cat_id -> node_id` 目标和 withdraw/publish 顺序已组成 | 公网 Gateway/Endpoint 传输协议不在本次 Control/Node 合同范围 |
| 底层存储 | ChunkStore、delta、golden root、NBD/vhost-user-blk、MetadataStore owner/epoch、Snapshot restore transition 与 Control-owned GC 已存在 | 产品只允许远端持久模式；真实 Host-loss 资格仍开放 |
| 独立 Node authority | `runtime_node_authority` 管理入口仍独立组成 | 它不成为 Cat 生命周期、心跳或失联恢复的第二套协议 |

## 4. 组件职责

| 组件 | 负责 | 不负责 |
|---|---|---|
| Control Plane | Workspace 授权、资源当前行、`current_action`、placement、同步调用 noded、Node liveness、当前入口目标，以及 auth-before-wake 的 Exec/Shell proxy | Running 块 I/O、VMM 是否真实存在、把心跳或 access response 当生命周期结果 |
| Gateway/入口层 | 把新流量发送到每个 Cat 的唯一当前目标 | 生命周期动作、磁盘写入权限、保证旧连接立即消失 |
| noded | 一台机器上的 Cat 实际状态、按 `cat_id` 串行动作、VMM/blockd/Guest 效果、reset 清理，以及 exact-incarnation runtime access gate | 用户 slug authority、跨 Host 自行选择 placement、用 access guard 充当 Host fence |
| Cloud Hypervisor/Guest Agent | microVM 执行、pause/snapshot/restore、Guest readiness 和 mount readiness | S3/PostgreSQL/WorkOS 凭据与产品调度 |
| cats-blockd | 标准块协议、cache/delta/commit 和 owner/epoch 检查 | Cat slug、产品状态和入口切换 |
| PostgreSQL | Cat/Disk/Node 当前资源、动作占用、binding、入口目标及存储 metadata CAS | 判断 VMM 进程是否实际存在 |
| Object Store | immutable Chunk/Map/Delta/Base/Snapshot 对象 | 当前 Cat 状态、当前 writer 和入口选择 |

具体云厂商实现只出现在 composition root 和 `adapters/`；核心协议不依赖 AWS/GCP 类型。

## 5. 产品资源与权威

### 5.1 Cat

Cat 有不可变 `cat_id` 和 Workspace 内用户指定的 `cat_slug`。当前行保存稳定 `state`、
`current_action`、动作目标 Node、当前 `node_id`、完整创建配置和错误信息。

Boot image 不是用户输入。Control 按 [ADR-0063](decisions/0063-control-owned-default-boot-image.md)
只在分配新 Cat 时把部署的当前 qualified default 固化为精确 digest；已有 Cat、重试、run 和恢复继续
使用行内 digest，默认升级不修改已有 RootDisk。

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

### 5.3 DiskSnapshot

DiskSnapshot 是 Workspace 下的一等资源，不是 Cat 或 Warm 的内部状态。产品 identity/tombstone 与只在
live 时存在的 GC root pin 分离；create、destroy、restore 都只在 Disk 已初始化、Volume Strict/Unowned，
且绑定 Cat 稳定 Cold 时发生。

同盘 restore 不把 generation 倒回历史值，而是把 captured root 作为当前 generation 的下一代发布并推进
lease epoch；旧 attachment 因此不能继续发布。Control-owned GC 在 PostgreSQL maintenance reservation
下同时保护 current root 与全部 live Snapshot root。完整合同见
[ADR-0066](decisions/0066-product-disk-snapshot-gc-and-same-disk-restore.md)。

### 5.4 Node

Node 有内部 `node_id`、不可变展示名 `node_name` 和 Control 可达的 `control_endpoint`。Node 注册时
显式上报地址；普通 heartbeat 不能修改展示名或回连地址。

`node_heartbeats.last_heartbeat_at` 由 PostgreSQL 接收时间写入并用于失联判断；Node 自报时间只作诊断。
`running` Node 才能接受 placement；`draining/offline/reset_required/deleted` 都不能。

### 5.5 每类事实的唯一写入方

| 事实 | 写入 authority | 非 authority |
|---|---|---|
| Cat/Disk/Node 产品状态、动作占用和当前 placement | PostgreSQL 当前资源行 | heartbeat、日志、metrics |
| VMM/blockd/Guest/mount 是否实际存在 | noded 的实际执行与查询 | Control 的旧稳定 state |
| 当前新流量目标 | PostgreSQL 当前入口目标 | Node heartbeat、历史 placement |
| volume writer、attachment epoch、remote root | MetadataStore CAS | `disk_bindings`、Cat state、入口目标 |
| Snapshot identity、live root 与 GC reservation | PostgreSQL Snapshot/Volume rows | blockd 内存 Map、对象 LIST、Warm snapshot |
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
Control/noded wire；当前 installed effects 已接入 Cloud Hypervisor 启动、Guest 文件系统准备及精确
mount-ready 检查。历史 kernel-NBD 物理验收见[文档索引](README.md#evidence)，不能用 backend 或模拟
effects 的单层测试替代交付版本的完整物理资格门。

## 9. Node 注册、失联与恢复

正常维护按以下顺序执行：

```text
running -> draining -> 停止新 placement
        -> 记录每个 Cat 原状态
        -> 转为 Cold
        -> 在目标 Node 从远端启动
        -> 恢复原 Running/Suspended/Warm 目标
        -> 返回逐 Cat drained/blocked 报告
        -> 运维确认 drained 后另行关闭旧 Node
```

fleet administrator 调用 `POST /v1/admin/nodes/{node_id}/actions/drain` 启动该流程。Control 先提交
`draining`，再为每个 Cat 持久化 exact 目标 reservation；请求取消或 Control 重启后，周期任务会从
PostgreSQL 当前行继续。已有生命周期动作不会被抢占，没有其他 running Node、源端不能安全 Cold 或目标
恢复失败都会返回 `blocked`。源 Cold 未成功时保留源 state/placement 并释放尚未使用的目标 reservation，
下一周期重新 claim；目标恢复结果不明时保留 exact claim。预留目标失联时在 row lock 内 exact retarget，
旧目标的迟到 settlement 不能覆盖新目标。接口不自动关闭或重新开放 Node，完成后 Node 仍保持 `draining`。

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

恢复扫描是 level-triggered：独立 recovery 周期按 PostgreSQL 当前状态重新发现 offline Node 上尚未迁走
的 Cat，因此 Control 重启或一次临时错误不会永久丢失恢复工作。它与 heartbeat/liveness probe 循环并行，
慢 lifecycle 网络调用不会延迟其他 Node 的失联判定。

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
3. PersistentDisk Guest物理挂载链、Cloud Hypervisor effects与真实双Node恢复已经组成并验证；
4. 后续release继续在exact commit跑全仓、Linux与适用production资格门。

切换期间的提交和验证记录由 Git history 保存，本文只维护当前架构边界。

### 12.2 Clean-slate 部署

首次部署使用一个空 v20 schema，不迁移旧 Cat/Disk/Node/Snapshot/runtime 数据，不双读、双写或运行混合版本：

1. 构建并验证同一版本的 Control、noded 和 CLI；
2. 进入维护窗口，关闭公网入口和 mutation；
3. 停止全部旧 Control、Node 和入口 write path；
4. 轮换或撤销旧内部凭据；
5. 删除旧产品数据并创建空 v20 schema；启动必须拒绝旧 schema version；
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
- PersistentDisk Strict backend、精确身份、Guest mount-ready、Cloud Hypervisor纵向链、Cold重挂和
  双Node恢复均已有production证据；后续改动不能拿旧commit的证据替代当前exact release门。
- production route map 不包含 lifecycle Operation GET、Node command poll/result、AgentSession 或
  observation settlement。
- `./scripts/quality.sh full` 和适用的 Linux/Cloud Hypervisor 门禁必须在每个交付exact commit上重新通过
  或明确记录环境阻塞。

## 14. 文档边界

- 本文：组件、authority、当前实现和故障边界。
- [Control Plane 与 noded 同步协议设计](control-node-semantic-protocol.md)：当前同步 wire、数据模型、
  场景语义和验收。
- [runtime-lifecycle.md](runtime-lifecycle.md)：四态、动作和数据/入口屏障。
- [storage.md](storage.md)：当前 ChunkStore 与 FLUSH 数据正确性。
- [Volume Authority](specs/volume-authority.md)：当前 direct acquire/renew/release/delete、底层卷
  owner/epoch、remote root 与磁盘数据安全。
- [operations-ha.md](operations-ha.md)：运行拓扑、心跳/reset、故障恢复和资格验证。
- `docs/decisions/`：决策及 superseded 链。
- `experiments/`：保留环境、样本和 oracle 的证据，不是生产 SLA。
