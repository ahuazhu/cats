# ADR-0028：Node Runtime Ledger 与 Agent 原地重接管

- 状态：Proposed
- 日期：2026-08-03
- 范围：Node Agent 的运行时清单持久化、NodeJob journal、启动顺序、子进程归属与重接管的身份证明。
- 不含：控制面资源库迁移（P0-A）、Route Grant（P0-B）、跨 Host handoff、自动 Host fencing。

## 背景

Node Agent 目前把「这个 Node 上有哪些 Cat 在跑」完全放在内存里，而真正承载数据的
子进程却在 Host 上独立存在。三个事实叠加后，一次 Agent 重启就会破坏已有 workload：

1. `NodeRuntime.cats` 与 NodeJob `journal` 都是进程内 `HashMap`
   （[`node-agent/src/runtime/mod.rs:278`](../../node-agent/src/runtime/mod.rs)）。新进程
   起来后不会重建任何 `CatRuntime`：generation、`ObservedState`、VMM 与 blockd 的 PID、
   `VolumeGrant`、Warm 快照位置、kernel-NBD 设备映射、tap、metering cgroup epoch 全部丢失。
2. 启动时必须在 30 秒内向控制面注册，否则 `spawn` 直接 `bail`
   （[`node-agent/src/server.rs:1580`](../../node-agent/src/server.rs)）。控制面短时不可用
   会让 Node 进程退出，而不是降级。
3. 两个生产 systemd unit 都没有设置 `KillMode`
   （[`deploy/aws/metal/cats-worker.service`](../../deploy/aws/metal/cats-worker.service)、
   [`deploy/metal/systemd/cats-noded.service`](../../deploy/metal/systemd/cats-noded.service)）。
   systemd 默认 `KillMode=control-group`，因此 `systemctl restart` 会杀掉 unit cgroup 内
   的全部残留进程——包括 `cloud-hypervisor` 和每一个 `cats-blockd`。

也就是说，今天升级一次 Agent 就会杀掉该 Node 上所有 Guest，并且杀掉持有 Relaxed
pending pack 的 blockd；随后没有任何进程会继续 publish 这些 pack，直到该 Cat 再次被
启动。控制面心跳只对账 Agent 上报的 Cat，缺席者会长期停留在 `Running`。

另一方面，本地磁盘上其实已经保留了恢复所需的大部分事实：`state_dir/cats/<cat_id>/`
下有 `vol-<disk_id>/`（blockd journal，在 `R < L` 时是唯一权威副本）、`disk-map.json`、
`warm-state.json`、Guest 内存 backing 与日志；socket 路径由 `(state_dir, cat_id, kind)`
哈希决定（[`node-agent/src/runtime/mod.rs:250`](../../node-agent/src/runtime/mod.rs)），
重启后可以重算。缺的不是数据，而是一份可信的清单，以及证明「这个 PID 确实是我上次
启动的那个 blockd」的证据。

现有 `stop_cat` 对无监督 residue 已经 fail closed
（[`node-agent/src/runtime/supervisor.rs:542`](../../node-agent/src/runtime/supervisor.rs)），
这个保守行为是正确的，本 ADR 不放宽它，只给它一个能证明归属的替代路径。

## 决定

### 1. 引入版本化、fsync 的 Node Runtime Ledger

在 `state_dir/runtime-ledger/` 下为每个 Cat 维护一条记录，内容至少覆盖重建 `CatRuntime`
所需的全部字段：`ledger_version`、`node_id`、`host_boot_id`、`cat_id`、`generation`、
`state`、`cpus`、`memory_mib`、运行时目录、三个 Cat 级 socket 路径、Guest/VMM 的
`{pid, start_ticks, exe, boot_id}`、每块盘的
`{disk_id, volume_id, attachment_id, epoch, durability, mount_path, size_bytes, data_dir,
nbd_socket, vhost_user_socket, control_socket, pid, start_ticks}`、CH 侧的
`{api_sock, vsock_sock, memory_file, nbd 设备映射, snapshot_dir, network}`、
metering 的 `{cgroup_path, source_epoch}`、route generation 与 `updated_at_ms`。

写入必须是 temp 文件 + fsync + rename + 目录 fsync，或本地 SQLite（`journal_mode=WAL`,
`synchronous=FULL`）。不接受「写完普通 JSON 就假设已落盘」。

`ledger_version` 是持久格式版本：Agent 只接受它认识的版本；遇到更高版本必须拒绝接管
并保持 residue，不得按旧字段猜测语义。

### 2. Ledger 是本地事实，不是写权权威

Ledger 只回答「这个 Node 上次启动了什么」。它不授予、不延长、不复活任何存储写权。
任何重新获得写权的动作仍必须联系 MetadataStore 并通过正常的 lease/epoch CAS。
blockd 已死亡时，本地 residue 可以保留，但不得离线复活旧 epoch。

### 3. 重接管必须有身份证明，否则不接管

对每个 ledger 记录，按顺序校验：

1. `host_boot_id` 与当前一致。不一致说明 Host 重启过，任何记录的 PID 都不可信，直接
   进入 residue 处理，不做进程接管。
2. PID 仍存在，且 `start_ticks`、可执行文件路径、所属 cgroup 与记录一致。任一不符按
   PID 复用处理，视为进程已消失。
3. 协议握手确认身份：Guest/VMM 的 `health()` 返回的 `boot_id` 必须等于记录值；blockd
   必须在控制协议上自报 `volume_id` 与 `attachment_id` 并与记录一致。
4. 每块盘的 `data_dir` 存在且属于记录中的 volume。

四项全部通过才重建 `CatRuntime` 并纳管。任何一项失败，该 Cat 不被接管，其本地状态按
既有 residue 规则保留（`Cold`/`Destroy` 仍 fail closed），并导出可观测的原因。

接管之后仍必须持续防 PID 复用：向一个被接管的进程发送任何信号——尤其是 teardown 的
`SIGKILL`——之前，必须重新采样并比对 `start_ticks`。接管与 teardown 之间可能相隔很久，
被接管进程一旦退出，其 PID 会被系统重新分配给无关进程；只凭记录的 PID 发信号会杀掉
别人的进程。校验不通过时按「该进程已消失」处理，不发信号。这一条对自己 fork 的子进程
不需要：内核为其保留 PID 直到被回收。

**协议变更**：blockd 控制协议当前的 `Status` 响应（`DurabilityStatus`）不含卷身份，
无法完成第 3 步。新增身份字段以向后兼容方式加入（`#[serde(default)]`），旧 blockd 因
字段缺失而无法证明身份，按「不可接管」处理——这是安全的默认。

### 4. NodeJob journal 持久化，保持现有成功/失败语义

成功与 rejected 结果落盘并按 `job_id` 索引；失败结果继续不落盘，使控制面对同一
`job_id` 的重试仍是真正的重试
（[`node-agent/src/runtime/supervisor.rs:153`](../../node-agent/src/runtime/supervisor.rs)）。
重启后重放 Start/Stop/Destroy 不得重复 acquire、重复删盘或越过 drain。

### 5. 启动顺序：先本地 inventory，再后台注册

Agent 启动先扫描并接管本地 inventory，再在后台重试向控制面注册与心跳。控制面不可达
不再退出进程，而是进入 `ControlPlaneDisconnected` 条件（P1-C 的 Condition 之一）并继续
服务本地 runtime。

只有携带完整同 generation inventory 的注册才能用于恢复控制面侧的 Lost claim；
inventory 不完整时该 Node 继续保持 Lost，由控制面决定后续处置。

### 6. 子进程归属：per-Cat systemd scope，且必须晚于重接管能力上线

VMM 与 blockd 移出 Agent 的 unit cgroup，放入 per-Cat transient scope
（`cats-cat-<cat_id>.scope`，置于独立 slice 下）。scope 的存在与其 `cgroup.procs` 成为
第 3 步中最强的一项归属证据，并且 `systemctl restart` 与 `systemctl stop` 都不再波及
Guest。

排序是本 ADR 的一部分，不是实现细节：**先让 Agent 能证明并重接管，再让子进程在重启后
存活**。反过来做只会把「重启杀掉 Guest」换成「重启产生无人认领的孤儿进程」。在 scope
落地前，`KillMode` 保持默认不变。

FakeVmm/开发与 macOS 路径没有 systemd。这些路径不使用 scope，仅依赖 ledger 与 PID
身份校验；它们本来就不承载生产 workload。

### 7. 状态收敛规则

- `Running`：证据齐全则原地接管，Guest 不重启。
- `Suspended`/`Warm`：证据齐全则保持原状态；无法安全重建时按 ADR-0002 收敛到 Cold
  fallback，但只有在保留盘已跨过远端 drain 或旧 Host 已被明确 fencing 后才能清理本地
  状态。
- `Stopping`：保留 blockd 与 journal，等待控制面重试同一 job。
- 无法证明归属的 residue：维持现有 fail-closed 行为不变。

心跳只上报已证明归属的 Cat。无法证明的 Cat 必须**完全不出现在心跳里**，不得上报为
`Cold`。原因是控制面的心跳同时承担两件事
（[`control-plane/src/api/nodes.rs:31`](../../control-plane/src/api/nodes.rs)）：同 generation
下它信任 Node 上报的状态并写入 `observed_state`；以及只有当心跳覆盖全部非删除 claim
时才恢复 Lost node。把无法证明的 Cat 上报成 `Cold`，会让控制面认为它已经释放，从而
在旧 blockd 可能仍持有 lease 的情况下推进后续流程；省略它则只是让该 Node 继续 Lost，
这是安全的一侧。控制面侧无需为本 ADR 修改。

## 不变的契约

- ADR-0002 四态不变，不新增第五个生命周期状态；降级用正交 Condition 表达。
- ADR-0021/0022 不变：`R <= L`，`R < L` 时 pending pack 是唯一权威副本，不因 Agent 进程
  重启被删除；强制 drain 规则不变。
- ADR-0025 不变：只有明确列为 disposable 的 RootDisk 可以丢弃本地 journal。
- 旧 attachment epoch 永远不能发布新的 Root；ledger 不提供任何绕过 MetadataStore CAS 的
  旁路。
- Guest 仍只看到标准 virtio block 与 ext4，ledger 不进入 Guest，也不含任何 S3/PostgreSQL
  凭据。
- heartbeat 超时仍只表示 Lost；本 ADR 不改变跨 Host 接管的前置条件。

## 后果

- Agent 升级与重启不再杀掉 Guest，也不再中断 Relaxed publisher；这是本 ADR 的主要收益。
- 新增一个持久格式（ledger）和一次向后兼容的控制协议扩展，两者都需要版本策略与
  malformed-input 覆盖。
- 接管路径是保守的：证据不足时宁可不接管。这意味着某些本可继续的 runtime 会退化为
  residue，需要人工或后续 job 处置，换取「绝不误接管别人的进程」。
- 引入 systemd scope 后，Node 上的进程树与 cgroup 布局改变，metering 的 cgroup 归属需要
  同步确认不破坏 ADR-0011 的计费计数器连续性。
- `systemctl stop cats-noded` 不再停止 Guest。运维文档必须显式说明这一点，停 Node 需要
  走 drain 流程而不是停服务。

## 分阶段实施

1. Ledger 格式、写入路径与 crash-safe 落盘；只写不读，行为不变。
2. 启动扫描与身份校验（含 blockd 控制协议身份字段），能接管 `Running`；控制面不可达
   不再退出。
3. NodeJob journal 持久化与重放。
4. `Suspended`/`Warm` 接管与 Cold fallback 收敛。
5. per-Cat systemd scope 与 `KillMode` 变更，附运维文档更新。

每阶段独立 PR，先补 characterization test。第 2 与第 5 阶段触及 Linux-only 路径，必须
额外运行 `./scripts/quality.sh linux`。
