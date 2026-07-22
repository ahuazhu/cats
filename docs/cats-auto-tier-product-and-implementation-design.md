# Cats 工作驱动的快速休眠：产品与实现设计

> 状态：Implemented（V1 dev shape），2026-07-22。
>
> 本设计服从 ADR-0002：Running / Suspended / Warm / Cold 是四个不同状态。本文只自动驱动 Running → Suspended；Warm / Cold 仍由显式生命周期动作驱动。

## 1. 产品结论

Cat 不是在“空闲一段时间后”睡，而是在**已知没有工作后立即尝试 Suspend**：

```text
auto_suspend = on
AND desired_state = observed_state = Running
AND Guest 工作信号新鲜
AND 平台工作租约数 + Guest 用户工作租约数 = 0
=> 立即创建 cat.auto_suspend operation
```

这里没有 `idle_timeout`、CPU 阈值、网络静默阈值或 30 秒宽限期。快速启、快速睡的前提是把“工作”定义为显式、可仲裁的协议，而不是猜测。

“没有租约”的准确含义是“平台和 Guest 用户程序都没有请求继续运行”，不是 Cats 证明 Guest 中所有进程已经完成。Guest 内信号由 Guest 内用户程序设置；Guest Agent 不扫描 `/proc`，不根据 CPU、load、TCP、块 IO 或进程名代替用户判断。

V1 新建 Cat 默认 `auto_suspend=on`。平台入口工作由 Gateway/exec 租约自动保护；需要持续后台运行的 Guest workload 必须接入工作租约，或按 Cat 显式关闭：

```text
cats create worker
cats create always-on --no-auto-suspend
cats sleep status worker
cats sleep off worker
cats sleep on worker
```

显式 `suspend`、`resume`、`warm`、`stop` 不受此开关影响。

## 2. Cat 什么时候可以睡

### 2.1 必须同时成立的条件

| 条件 | 原因 |
|---|---|
| 自动休眠已开启 | 新建 Cat 默认开启；未接入工作租约且需要持续运行的后台程序应显式关闭 |
| desired / observed 都是 Running | 不和 start、resume、drain、fencing 或其他生命周期转换并行决策 |
| Guest 工作摘要新鲜 | 信号链故障时 fail-awake，不把“收不到信号”解释为“没有工作” |
| 所有未过期租约的并集为空 | Gateway、exec、Guest 用户任务中的任一工作都阻止自动睡眠 |
| Node 和 Guest 的最终静默栅栏通过 | 封住控制面判定到 VMM pause 之间的新工作竞态 |
| durable FLUSH 成功 | 保持“成功 FLUSH 可承受 Host 永久丢失”的存储不变量 |

最后一个租约释放、过期或 Guest 上报空集合，就是一次事件触发。控制面随即在事务里从 Running 切换 desired Suspended；定时 reconcile 只负责丢事件修复，不构成业务等待时间。

### 2.2 哪些事情算工作

| 来源 | 租约 kind | 生命周期 |
|---|---|---|
| Endpoint Gateway 请求 | `gateway` | 准备唤醒/代理前 acquire，响应结束后 release |
| `cats exec` | `exec` | 唤醒前 acquire，命令成功或失败后 release |
| Guest 用户程序 | `guest` | 用户程序通过本机 socket acquire / renew / release |
| 将来的临时 pin | `pin` | TTL 到期或用户显式释放 |
| 运行时控制变更 | `control` | V1 的热挂载/卸载；后续覆盖更多运行时 operation |

V1 已接通 Gateway、exec、Guest 用户程序以及磁盘热挂载/卸载。工作租约有 TTL，调用方异常退出或 release 丢失时会自动恢复，不会永久压住 Cat。

不算工作的项目包括：读取 Cat 元数据、健康探针、CPU 利用率、Guest load、没有连接的监听 socket、普通后台进程的存在。这些信号要么与业务完成无关，要么无法安全地区分“等待中”和“已经完成”。

### 2.3 Guest 用户程序契约

真实 Guest 默认在 `/run/cats/runtime.sock` 暴露 **HTTP/1.1 + JSON over Unix socket**，只允许本机用户程序访问，不占用 TCP/UDP 端口，也不需要 Cat id、项目 token、对象存储凭据或元数据凭据。FakeVmm 使用 Node 创建的隔离 Unix socket，但 HTTP 协议相同。该 Guest ABI 由 [ADR-0007](decisions/0007-guest-runtime-http-over-unix-socket.md) 固定。

创建租约只需通用 HTTP 客户端：

```bash
curl --unix-socket /run/cats/runtime.sock \
  -X POST http://cats-runtime/v1/work-leases \
  -H 'content-type: application/json' \
  -d '{"label":"release-build","ttl_ms":300000}'

# => {"id":"work_...","label":"release-build","remaining_ttl_ms":...}
```

续租、释放和查看：

```bash
curl --unix-socket /run/cats/runtime.sock \
  -X PUT http://cats-runtime/v1/work-leases/$lease_id \
  -H 'content-type: application/json' -d '{"ttl_ms":300000}'
curl --unix-socket /run/cats/runtime.sock \
  -X DELETE http://cats-runtime/v1/work-leases/$lease_id
curl --unix-socket /run/cats/runtime.sock \
  http://cats-runtime/v1/work-leases
```

`cats-guest-work` 可以作为可选的 shell 包装器，但它只是上述 HTTP API 的普通客户端，不是必需组件，也没有私有能力。Python、Go、Rust 等程序可以使用任意支持 Unix socket transport 的通用 HTTP client；不需要 Cats SDK。

在普通本机开发环境中，程序可以先检查 socket 是否存在，不存在就跳过租约；在启用了 auto-suspend 的 Cat 内，acquire/renew 失败意味着无法保证 Cat 保持 Running，不应被基础库静默吞掉。默认 TTL 为 5 分钟，单次最大 TTL 为 1 小时，每个 Guest 最多 64 个租约。TTL 使用 Guest Agent 的单调时钟；控制面使用自己的接收时间，不信任 Guest 墙钟。

长期常驻且无法接入这个协议的 workload 应保持 `auto_suspend=off`。这不是技术缺陷的掩盖，而是产品契约的边界：只有用户程序知道它是否仍有业务工作。

## 3. 用户体验

### 3.1 状态与解释

Cat 资源新增 `auto_suspend: bool`。查询工作状态返回：

- `active_work_count` 和每个 lease 的 kind、label、owner、到期时间；
- `guest_signal_fresh` 与信号年龄；
- `can_suspend_now`；
- 稳定原因码。

V1 原因码为：

```text
policy_off
lifecycle_in_progress
guest_lease_signal_stale
active_work
eligible
```

示例：

```text
$ cats sleep status worker
auto-suspend=on work=1 guest-signal=fresh eligible=false reason=active_work
  Guest guest_... label=release-build expires_at_ms=...
```

当 `reason=eligible` 时，控制器可能已经在同一时刻提交 Suspend；这是一个瞬时可观测状态，不是要等待的倒计时。

### 3.2 唤醒语义

- `WakeOnRequest` Endpoint 和 `exec` 都在唤醒前 acquire 工作租约。
- 多个并发请求共享一次 desired Running 转换；`ensure_desired_running` 在事务中实现 singleflight，避免每个请求都增加 generation。
- Gateway 的 `NoWake` 请求在 Cat 睡眠时直接失败，不为了记录工作而唤醒。
- 请求/exec 完成后 release；如果它是最后一个租约，Cat 可以立刻再次 Suspend。
- Suspend 正在准备时到达的新工作优先：旧 Suspend 被拒绝，或者已 pause 后立即走现有 resume 路径。请求不允许进入一个即将 pause 的 Guest。

因此可形成预期的短周期：

```text
Suspended --请求到达--> Running --响应结束且无其他工作--> Suspended
```

快速启、快速睡不保证某个固定生产延迟；已有 metal 实验只能作为机制证据，不能升级为 SLA。

## 4. 分布式工作模型

### 4.1 Guest 源

Guest Agent 启动时生成 `source_epoch`，维护：

```text
lease_sequence: u64
quiescing: bool
leases: Map<lease_id, {label, monotonic_expires_at}>
```

acquire、renew、release、TTL 过期以及 quiesce 期间被拒绝的新 acquire 都推进 `lease_sequence`。Node 对 `WorkStatus(after_sequence, wait_timeout_ms)` 做长轮询，因此最后一个 release 无需等常规 heartbeat。

Guest Agent 的 `PrepareSuspend(expected_lease_sequence)` 只有在序列仍相等且租约为空时成功，并原子设置 `quiescing=true`。进入 quiescing 后新的 acquire/renew 返回 `activity_changed`，同时推进序列；调用方重试，Node 必须撤销本次 Suspend。

`AbortSuspend` 重新打开 admission gate。resume 和 Warm restore 都必须调用它；真实 VMM 快照会保存 Guest Agent 的 quiescing 内存状态，restore 后不能遗漏这一步。

### 4.2 Node 源与最终门禁

Node 为每个 Running Cat 维护 `RuntimeActivityGate`：

```text
sequence: u64
active: u64
quiescing: bool
```

Node 上的 exec 和 proxy 在真正进入 Guest 前取得 RAII guard。Suspend 的两阶段顺序是：

1. Node gate 从 Open 切为 Quiescing；要求 `active == 0`，记录 node sequence。
2. 向 Guest 发送 `PrepareSuspend(expected_guest_sequence)`。
3. Guest 执行 `syncfs` / block FLUSH。
4. 再读 Guest sequence，并复查 Node sequence、active 和 quiescing。
5. Cloud Hypervisor 调 `vm.pause`；FakeVmm 对 Guest 进程发 `SIGSTOP`。
6. pause 后再检查一次 Node gate，覆盖极小的 pause 窗口竞态。

任一检查失败返回类型化 `JobPhase::Rejected` + `ActivityChanged`，不是生命周期故障。控制面把 auto-suspend operation 标记失败并恢复 desired Running；不会按普通 suspend 故障直接清理到 Cold。

真正的 resume / restore 失败仍遵守 ADR-0002：收敛到干净 Cold fallback。

### 4.3 控制面汇总

控制面持久化两组数据：

```sql
cats(auto_suspend, work_version)
cat_work_sources(cat_id, node_id, generation, source_epoch,
                 lease_sequence, seen_at_ms)
cat_work_leases(id, cat_id, kind, owner_id, label,
                expires_at_ms, source_epoch)
```

`work_version` 在 acquire、renew/替换、release、TTL 清理时单调增加。Guest 报告按 `(node_id, generation, source_epoch, lease_sequence)` 去重和拒绝旧源；只有当前 placement 的 Node 能写入。

`try_auto_suspend` 是决策线性化点。它在一个 SQLite 事务中：

1. 清理过期 lease；
2. 重查 policy、desired / observed 和 Guest freshness；
3. 重查 live lease count；
4. 条件更新 desired Suspended、generation + 1；
5. 创建 `cat.auto_suspend` operation。

生产 PostgreSQL adapter 应保持相同 SQL/CAS 形状；不能把 lease 计数放到单个控制器进程内存中。

### 4.4 Suspend work fence

控制器发给 Node 的 Suspend job 携带：

```text
SuspendWorkFence {
  control_work_version,
  guest_lease_sequence,
}
```

Guest sequence 是 Node/Guest 两阶段校验的直接 fence。`control_work_version` 记录控制面决策版本，用于审计和将来 Node 回调校验；V1 平台工作竞态同时由 desired generation、Gateway/exec 的先 acquire 后 wake、以及 Node 最终 proxy/exec gate 封住。

## 5. HTTP 与进程协议

### 5.1 用户 API

```text
GET /v1/projects/{project}/cats/{cat}/auto-suspend
PUT /v1/projects/{project}/cats/{cat}/auto-suspend
  {"enabled": true}

GET /v1/projects/{project}/cats/{cat}/work
```

策略更新返回 `AutoSuspendResponse {cat, work}`。开启策略时立即评估，不等待下一轮 reconcile。

### 5.2 服务内部 API

```text
POST /v1/internal/work/acquire
POST /v1/internal/work/release
POST /v1/nodes/work-status
```

这些接口只接受 service/admin token。`kind=guest` 不能从 internal acquire 伪造，只能由当前 Node 的 Guest 工作摘要产生。

### 5.3 Guest 协议

Host → Guest control：

```text
WorkStatus {after_sequence, wait_timeout_ms}
PrepareSuspend {expected_lease_sequence}
AbortSuspend
```

Guest-local 是固定 Unix socket 上的 HTTP/1.1：

```text
POST   /v1/work-leases             {label, ttl_ms}
PUT    /v1/work-leases/{lease_id}  {ttl_ms}
DELETE /v1/work-leases/{lease_id}
GET    /v1/work-leases
```

Host control 继续使用现有的 u32 big-endian length + JSON framing over AF_VSOCK；它只在 Guest Agent 与 Node Agent 之间使用。Guest-local 用户协议不复用私有 framing。VMM 既不打开 `/run/cats/runtime.sock`，也不解析 HTTP/租约；它只提供 vsock 设备并执行 pause/resume。

完整请求、响应、错误码、大小/超时限制和本机降级语义见 [`Guest Runtime API v1`](specs/guest-runtime-api.md)。

## 6. 故障与安全语义

| 故障 | 行为 |
|---|---|
| Guest/Node 工作信号过期 | fail-awake，不创建自动 Suspend |
| lease release 上报丢失 | TTL + 1 秒长轮询刷新修复 |
| Gateway/exec release 丢失 | 控制面 TTL 自动清理 |
| Guest lease 报告乱序 | 同 epoch 的旧 sequence 忽略 |
| 旧 Node/旧 generation 上报 | conflict，不能改变当前 Cat |
| quiesce 中新工作到达 | sequence 变化，Node 返回 ActivityChanged |
| pause 后 Node gate 变化 | 立即 resume，Suspend 被拒绝 |
| auto Suspend 被新 wake 覆盖 | 旧 auto operation 失败，新的 wake generation 获胜 |
| Suspended/Warm resume 失败 | 清理并收敛 Cold |
| Host 永久丢失 | 走既有 fencing，旧 attachment epoch fail-closed |

自动休眠不改变存储边界：Guest 始终看到标准 virtio block + ext4，不持有对象存储或元数据凭据；Local NVMe 仍只是可删除 cache；PersistentDisk 仍是 RWO。

## 7. 当前实现边界

V1 已实现：

- Cat 级 `auto_suspend`，新建 Cat 默认开启且可显式关闭；
- Guest 本机 `/run/cats/runtime.sock` HTTP 工作租约 API，以及可选的 `cats-guest-work` HTTP 包装器；
- Node 长轮询上报和 freshness fail-awake；
- Gateway、exec 工作租约；
- 控制面事务判定、singleflight wake、operation 与原因码；
- Node/Guest 两阶段 quiesce、ActivityChanged 拒绝和竞态恢复；
- Store、API、Guest、Node 生命周期自动化测试。

仍未实现：

- Suspended 的 `process_madvise(MADV_PAGEOUT)` / 独立特权 helper。当前 Cloud Hypervisor 路径只有 `vm.pause`，因此只可靠回收 vCPU，不能宣称已回收主要内存。
- 自动 Suspended → Warm → Cold。两态依然存在且可手动使用，但时间阈值、保留预算和自动降级策略应另行设计。
- tap/overlay 数据面。将来流量不再经过 Node proxy 时，必须建立等价的本地 activity gate，不能只依赖控制面 lease。
- PostgreSQL metadata adapter 和 privilege separation。
- Web 控制台卡片。V1 API 和 CLI 已具备完整解释数据，UI 仍需接入。

## 8. 验收标准

功能正确性：

1. 自动策略关闭时，工作集合为空也不自动睡。
2. Guest signal 缺失或过期时不自动睡。
3. 任一 Gateway、exec 或 Guest lease 存活时不自动睡。
4. 通用 HTTP 客户端可通过 Unix socket 完成 create/renew/delete/list；不监听固定 TCP/UDP 端口。
5. 最后一个 lease release 后无需 idle timer 即创建 auto-suspend operation。
6. Guest lease 在 PrepareSuspend 前变化时，Node 返回 ActivityChanged，Cat 保持 Running。
7. Node proxy/exec 在 quiesce 窗口到达时不能进入 Guest，并撤销 Suspend。
8. durable FLUSH 失败时不得报告 Suspended。
9. 并发 wake 只创建一个 Running generation。
10. resume / restore 失败收敛 Cold。

工程门禁：

```text
cargo test --workspace
cargo clippy --workspace --all-targets
```

性能验收必须记录样本量、环境、测量边界与 correctness oracle。可以分别测量 last-release → pause、request → ready、resume 后首请求尾延迟和 RSS 回收；不得把 2026-07-21 的 prototype 样本直接写成生产 SLA。

## 9. 后续演进

按价值顺序：

1. 实现并验证真正 page-out，使 Suspended 同时释放 vCPU 和可回收内存页。
2. 将 API 状态和原因码接入用户/管理员控制台。
3. 为长连接 Gateway lease 增加续租；当前简化 HTTP proxy 有 60 秒超时，120 秒 lease 足够，但 WebSocket/SSE 需要持续 renew。
4. 加入带 TTL 的用户 pin 和控制面变更 lease。
5. 在 Suspended 成熟后，单独设计 Warm / Cold 自动降级。时间只服务于“睡得更深”，不回到“等一段空闲时间才允许 Suspend”的模型。

核心原则保持不变：**工作从 1 变 0 就尝试快速睡；工作从 0 变 1 就快速启；任何不确定性都 fail-awake。**
