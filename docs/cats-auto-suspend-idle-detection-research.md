# Cats 自动睡眠（auto-suspend）调研报告

状态：调研结论（2026-07-22）。回答的问题：**VMM/平台能否监控 cat 是否在工作，自动判定 Running→Suspended，替代外部程序显式调用 suspend？**

> 2026-07-22 决策更新：最终产品不采用“最近活动时间 + 宽限期”判断首次 Suspend，而采用工作租约的电平/边沿语义。Gateway、exec 或 Guest 用户程序的租约并集从 1 变 0，且 Guest 信号新鲜时立即尝试 Suspend；时间阈值只留给将来的 Suspended → Warm → Cold。Guest 信号必须由 Guest 内用户程序设置。落地状态与精确协议见[《Cats 工作驱动的快速休眠：产品与实现设计》](cats-auto-tier-product-and-implementation-design.md)。

调研方法：多路 web 检索 → 一手来源抓取 → 逐论断对抗性验证（64 票，存活论断才进入本报告）+ 本仓库代码链路梳理。

---

## 1. 一句话结论

**可以自动化，但业界没有任何主流平台用"VMM 监控 guest 内部活动"作为主信号。** 成熟做法收敛为三类：**网关/连接驱动**、**显式 TTL/keep-alive**、**guest 协作式会话信号**。Cats 最终选择更明确的并集租约模型：Gateway 与 exec 自动持有平台租约，Guest 内用户程序显式持有 Guest 租约；并集为空就立即尝试 Suspend。控制面作分布式决策，Node 与 Guest 作 pause 前最终栅栏。**VMM 资源计数不参与业务忙闲判断。**

为什么不用纯 VMM/宿主机侧信号做主判定（业界共识背后的原因）：

- **"CPU 空闲"≠"工作完成"**。一个等网络回包 / 等 webhook / 等用户输入的服务，vCPU 也是 0%，但它没"做完"；反之 cron 唤醒的后台 GC 会让"空闲"的机器周期性冒 CPU。语义上，"可以睡"是应用层事实，宿主机只能看到代理指标。
- **宿主机 CPU 统计有陷阱**：KVM halt-polling 会让完全空闲的 guest 的 vCPU 线程在宿主机上表现为接近 100% busy（轮询忙等），直接用 cgroup `cpu.stat`/VMM 进程 CPU 判空闲会系统性误判（[kernel.org halt-polling 文档](https://www.kernel.org/doc/html/latest/virt/kvm/halt-polling.html)）。可以经 `KVM_CAP_HALT_POLL` 按 VM 调低 halt_poll_ns 或读 `KVM_GET_STATS_FD` 的 per-vCPU halt 统计来矫正，但这只是把信号洗干净，仍解决不了上面的语义问题。
- **Cloud Hypervisor 没有现成的"活动监控"面**：CH REST API 只有 `vm.counters`（virtio-net/blk 设备计数器）和 `vm.info`，没有 vCPU 利用率、脏页统计等监控端点（[CH api.md](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/api.md)）。`vm.counters` 增量可用于容量观测，但不应进入 Cats 的业务忙闲判定。

---

## 2. 业界同类产品怎么判定"可以睡"（已验证的一手资料）

| 平台 | 空闲主信号 | 阈值/策略 | 睡眠形态 | 误判缓解 |
|---|---|---|---|---|
| **Fly.io Machines** | Fly Proxy 侧活跃连接/流量（纯网关驱动，guest 不可见） | 每隔几分钟评估；单机 load=0 即 stop/suspend；多机按 soft_limit 算过剩容量，每轮每区最多停 1 台 | `auto_stop_machines="suspend"` = Firecracker 全 VM 快照，恢复几百 ms；当前文档要求 ≤2GB 内存、无 swap/GPU | **没有** guest 否决机制：fire-and-forget 后台任务会被杀（202 返回后无连接→几分钟后停机），自 ping 也无效；官方缓解 = 关 autostop 或把后台工作拆到无 http_service 的进程组 |
| **Fly.io Sprites**（sprites.dev，AI agent 沙箱，2026-01 上线） | 平台侧语义信号任一即"活跃"：active exec/console、产生输出的会话、打开中的 URL TCP 连接、运行中的 TTY、正在处理连接的 Service；普通后台进程或空闲 Service 不自动压住睡眠 | 当前官方口径是停止活动后**约 30 秒**进入 warm；未发现用户可配置阈值；之后自动 warm→cold，转换时长未公开 | warm = Firecracker snapshot/suspend（进程态保留），唤醒 100–500ms，更接近 Cats `Warm`；cold = 停机丢内存态，唤醒 1–2s，对应 Cats `Cold`；ext4 文件系统跨两态持久 | guest 内 **Tasks API**（unix socket）：task 存活即压住睡眠，单 task 上限 1h，推荐 expire 5m + 每 60s 心跳续租 + 退出 DELETE；未发现全局关闭空闲超时的公开开关 |
| **AWS Lambda MicroVMs** | 专属 endpoint 上无流量 | `maxIdleDurationSeconds`（示例 300s）后平台自动 suspend；挂起态最多 8h，只付存储 | Firecracker 内存+磁盘快照，下个请求到达自动 resume（秒级） | 提供 resume 时 lifecycle hooks 刷新凭证/连接 |
| **CodeSandbox** | 分支/Devbox 未被访问 | Free 5 min / Pro 30 min 无活动 → auto-hibernate | pause VM + 内存快照写盘，恢复 ~1.5s（与 Cats Suspended 最同构）；快照本身再按 7–31 天不活跃 GC | 多级降级（hibernate→内容清理分层，Free 8 天/Pro 15 天） |
| **Modal Sandboxes** | 三个平台侧信号任一即"活跃"：**有 exec 在跑、stdin 正被写、Tunnel 上有打开的 TCP 连接** | 三者皆无才累计 `idle_timeout`；另有硬性生命周期上限（默认 5 min，最长 24h） | 超时是 terminate + 文件系统快照，非内存挂起 | "活跃"定义明确排除资源指标，纯控制面可观测 |
| **E2B** | 无空闲探测，**纯显式 TTL** | 应用随时 `set_timeout()` 续期（keep-alive 由上层负责）；超时 `onTimeout: pause`（默认 kill） | pause 完整保留状态、可无限期保留 | 把"何时可睡"的责任完全交给上层——正是 Cats 想摆脱的现状 |
| **Morph Cloud** | TTL 策略（`ttl_action=pause`） | 平台按 TTL 自动 pause | 内存+磁盘快照；wake-on-SSH/HTTP（需显式开启）由连接层唤醒 | 可按实例关闭 auto-sleep（opt-out 当持久 VPS 用） |
| **Coder** | guest 内 agent 上报的**会话存在性**（VS Code/JetBrains/终端/SSH 连接、AI agent 任务状态），二元判定，不看键鼠输入 | 所有连接关闭 + TTL 内无新连接才停；**activity bump 宽限**（默认 1h），期间恢复活动则顺延 | stop（非内存挂起） | 明确排除 dashboard 查看、后台统计上报等"伪活跃"；**AI agent 可经 Coder Tasks 上报 working 状态显式压住睡眠**；cron/build 不算活跃（已知误判源） |
| **Gitpod Classic** | 用户输入（按键、终端命令）+ 连接存在 | 默认 30 min 无输入停机；编辑器连接关闭则缩短为 5 min 宽限 | 备份 /workspace 后销毁容器（冷） | `gp timeout set`（guest 内 CLI）用户自行续期，上限 24h；曾因"单连接假设"误睡多客户端用户（SSH+IDE 并存），后改为聚合全部连接类型 |

来源：[Fly autostop/autostart](https://fly.io/docs/reference/fly-proxy-autostop-autostart/)、[Fly suspend/resume](https://fly.io/docs/reference/suspend-resume/)、[Fly long-running tasks blueprint](https://fly.io/docs/blueprints/long-running-tasks/)、[AWS Lambda MicroVMs 公告](https://aws.amazon.com/blogs/compute/announcing-lambda-microvms-serverless-compute-environments-with-vm-level-isolation-and-near-instant-startup/) 及 [docs](https://docs.aws.amazon.com/lambda/latest/dg/microvms-launching.html)、[CodeSandbox VM 文档](https://codesandbox.io/docs/learn/environment/vm)、[Modal Sandboxes](https://modal.com/docs/guide/sandboxes)、[E2B](https://e2b.dev/docs/sandbox)、[Morph TTL](https://cloud.morph.so/docs/documentation/instances/ttl)、[Coder workspace-scheduling](https://coder.com/docs/user-guides/workspace-scheduling)（细节 [coder#20505](https://github.com/coder/coder/issues/20505)）、[Gitpod lifecycle](https://www.gitpod.io/docs/configure/workspaces/workspace-lifecycle)（多客户端踩坑 [gitpod#10373](https://github.com/gitpod-io/gitpod/issues/10373)）。

**模式总结**：

1. 没有一家用 vCPU 利用率/宿主机资源指标做主信号；全部是**请求/连接/会话/显式 TTL** 这类语义信号。
2. 所有认真做交互式负载的平台都有**宽限期**（Coder activity bump、Gitpod 5 min、Fly 每轮只停一台）。
3. 所有平台都承认**后台任务误睡**是本质缺陷，缓解手段全是"给应用一个说不的通道"：keep-alive 钩子（`gp timeout`、E2B `set_timeout`、Coder Tasks working 状态、Sprites Tasks API）或 opt-out（Morph、Fly 关 autostop）。

### 2.1 重点对标：Fly.io Sprites（与 Cats 产品形态接近，2026-07 补充调研）

Sprites 是 Fly.io 面向 AI agent 负载的新产品。它与 Cats 都采用 microVM、持久 ext4、NVMe cache + 对象存储真相源和自动降档，但不能逐状态或逐实现等同：Sprites warm 使用 Firecracker snapshot/suspend，语义更接近 Cats `Warm`，不是保留原 VMM 的 `Suspended`；Sprites cold 对应 Cats `Cold`。其存储公开实现采用修改过的 JuiceFS/SQLite/Litestream，而 Cats 已由 ADR-0003 选定 Direct-S3 ChunkStore，二者只是持久性原则相似。

- **激进阈值的前提是唤醒便宜**：当前官方口径是活动停止约 30 秒后进入 warm，warm 唤醒 100–500ms。Cats 的[单 Host i4i.metal 机制实验](../experiments/warm-snapshot-benchmark/results/i4i-lifecycle-modes-20260721/README.md)中，`pause + page-out` 从 resume 到健康 HTTP 的 P50 为 0.212–0.231s（512MiB/1GiB/2GiB 各 n=10；[原始 CSV](../experiments/warm-snapshot-benchmark/results/i4i-lifecycle-modes-20260721/raw/)）；该数据不是生产 SLA，但足以说明 Cats 值得实验比 dev-workspace 常见 5–30min 更激进的阈值，不能仅凭这组 P50 直接把默认值定为 30 秒。
- **"活跃"是平台侧语义信号的并集**：当前官方文档列出 active exec/console、会话输出、打开中的 TCP 连接、运行中的 TTY 和有连接的 Service；普通后台进程或空闲 Service 本身不自动保活。判定契约基于平台可见的工作语义，而不是 CPU 百分比，再次印证 §1 的方向。
- **防误睡 = guest 内租约式 Tasks API**：guest 内经 unix socket（`/.sprite/api.sock`）创建 task 即压住睡眠；单 task 硬上限 1h，官方推荐"expire 5 分钟 + 每 60 秒心跳续租 + 干完 DELETE"。这为 Cats Phase 2 的 `cats-guest busy --ttl` 钩子给出了完整参考实现：**租约 + 心跳 + 硬上限**，天然防"忘了释放导致永不睡"的泄漏（对比 Gitpod 的 24h 上限，Sprites 用短租约 + 续期把泄漏窗口压到分钟级）。
- **诚实的 TCP 语义**：官方明确即使 warm suspend，所有 TCP 连接也会断（websocket/队列 worker/流式 API 无法跨睡眠存活）——产品层直接把"睡 = 断连"写进契约，而不是承诺尽力保活。Cats 建议采用同样的契约表述。
- **两级降档 + 按实际资源计费**：warm（内存态保留）→ cold（丢内存态、文件系统保留）；compute 只在 active 时计费，CPU 按 `cpu.stat` 累计用量、内存按实际用量计，存储按实际占用的 hot/cold GB-hours 计费。这与 Cats 四态分档计费的经济模型相容，但费率和资源账本不能直接照搬。
- **反向教训**：Sprites 上线初期的公开投诉主要是"**该睡不睡**"，状态曾连续显示 running 6–21h；Fly staff 承认 suspend bug，但随后说明多数此类实例在进入内部 "trying to suspend" 后已停止 compute 计费。因此已证实的是状态/判定可观测性不足和用户账单焦虑，不是 6–21h 持续计费事故。Cats 的 auto-tier 仍应可审计：必须能解释每个 Cat 当前被哪个信号压住、何时开始尝试降档、计费何时停止。
- 架构杂项：Sprites 当前仍运行在 Fly Machines 基础设施上，但不简单复用其宿主机侧编排模型；大量 storage/service/log/network 编排位于 VM root namespace，用户代码运行在 inner container，平台无需重启整台 VM 即可重置用户环境。

来源：[Sprites lifecycle and persistence](https://docs.sprites.dev/concepts/lifecycle/)、[working with sprites（idle detection）](https://docs.sprites.dev/working-with-sprites/)、[keeping sprites running（Tasks API）](https://docs.sprites.dev/keeping-sprites-running/)、[Sprites 产品页与计费](https://fly.io/sprites/)、[Fly 设计博客 The Design & Implementation of Sprites](https://fly.io/blog/design-and-implementation/)、[community: sprites not shutting off](https://community.fly.io/t/sprites-not-shutting-off/26793)。未找到公开资料：用户能否配置 idle 阈值、warm→cold 的具体转换时长。官方 `working-with-sprites` 页对 warm 内存保留存在概括性旧表述；本节状态语义以专门的 Lifecycle 与 Tasks 页面为准。

## 3. 宿主机/VMM 侧可用的容量观测（不参与业务忙闲判定）

- **KVM per-vCPU 二进制统计**（`KVM_GET_STATS_FD`，2021 进主线，跨架构）：`halt_successful_poll` / `halt_attempted_poll` / `halt_wakeup` / `halt_poll_success_ns` / `halt_wait_ns`、`exits` / `io_exits` / `mmio_exits` 等——无需 guest 配合即可看到 vCPU halt 占比（[patch series](https://patchwork.kernel.org/project/linux-kselftest/patch/20210618044819.3690166-5-jingzhangos@google.com/)、[KVM api.rst §4.133](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/virt/kvm/api.rst)）。
- **CH `vm.counters`**：virtio-net/blk 收发包与读写字节计数，按每 VM 的 `--api-socket` 轮询增量即可判断 IO/网络是否静默（[CH api.md](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/api.md)、[OpenAPI schema](https://raw.githubusercontent.com/cloud-hypervisor/cloud-hypervisor/main/vmm/src/api/openapi/cloud-hypervisor.yaml)）。
- **注意 halt-polling 污染**：直接看 VMM 进程 CPU 会把空闲 guest 看成忙；即使用于容量观测，也应按 VM 用 `KVM_CAP_HALT_POLL` 调低/禁用 halt polling，或读取上面的 halt 统计。
- Guest 内 `systemd-logind IdleAction` 在 headless guest 上**不可用**（idle hint 须由桌面环境上报，无桌面则无信号源，[systemd#12668](https://github.com/systemd/systemd/issues/12668)）——没有现成的系统级“空闲”事实；Cats 的 Guest 信号应由 Guest 内用户程序显式设置，而不是让 Guest Agent 聚合 load/会话/连接后代替用户推断。

## 4. 判定策略与阈值（文献支撑）

- 业界基线是**固定 idle timeout**：AWS Lambda 经典 keep-alive 10 min、Azure 20 min、Lambda MicroVMs 5 min、CodeSandbox 5/30 min。实现最简单，但对低频负载既多冷启动又浪费内存。
- **自适应策略有成熟先例**：微软 *Serverless in the Wild*（ATC '20）用 per-app 空闲时间直方图（4h 范围、1 min 粒度），头部分位设预热窗口、尾部分位（p99）设 keep-alive 窗口，分布不可靠时回退固定值；已在 Azure Functions 生产落地，同内存下冷启动次数比固定 10 min 策略约省 2.5×（[论文 PDF](https://www.usenix.org/system/files/atc20-shahrad.pdf)）。同一数据集显示 **81% 的应用平均每分钟至多被调用一次**——空闲回收收益巨大；但 ~40% 应用调用间隔 CV>1，预测困难，**宽限期/回退机制是必需品而非可选项**。
- **唤醒不只 0.2s**：page-out/快照后的唤醒有缺页性能拖尾（快照恢复的函数执行平均比常驻内存慢 95%，REAP/FaaSnap 用宿主侧工作集记录+预取可消除 ~97% 缺页、提速 3.7×，纯 userspace/userfaultfd、无需改 guest）（[REAP, ASPLOS '21](https://arxiv.org/pdf/2101.09355)、[FaaSnap, EuroSys '22](https://www.sysnet.ucsd.edu/~voelker/pubs/faasnap-eurosys22.pdf)）。Cats 设定 suspend_after 阈值时应把"唤醒后短暂变慢"计入成本，而不是只算 resume 延迟。

## 5. Suspend 副作用与竞态（自动化前必须处理）

- **时钟**：pause/snapshot 期间 guest 墙钟停走，resume 后需校时；校时本身会造成时钟突跳（[Firecracker snapshot-support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)）。CH 也有 pause 后时钟不连续的已知 issue（[cloud-hypervisor#7931](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/7931)，Windows guest 场景）。
- **TCP**：同进程 pause+resume 下，只要对端维持连接，TCP 可以存活（Fly suspend 文档）；但跨进程 snapshot restore 不保证网络/vsock 连接存活。Sprites 的 warm（更接近 Cats `Warm`）明确把"所有 TCP 都会断"写进产品契约——技术上可能存活 ≠ 产品上应该承诺，Cats 建议按"睡即可能断连"定契约。注意区分这两条路径——**快照只能恢复进新 VMM 进程**（Firecracker/CH 皆然；CH `vm.restore` 要求 created-未 boot 的新 VM），Cats 的 Suspended（同进程 pause）风险显著小于 Warm/Cold。
- **定时器实证案例**：Firecracker 快照恢复后 guest 内依赖 nanosleep 的进程随机卡死（TSC_DEADLINE MSR 恢复顺序 bug，表现恰为 **vsock 服务无法重连**，2023-09 报告 → 2024-07 才修复，[firecracker#4099](https://github.com/firecracker-microvm/firecracker/issues/4099)）。关键佐证：**纯 pause/resume（VMM 进程保留）不复现**——对 Cats 的 Suspended 设计是利好，对 Warm 路径是警示（唤醒后要有 guest-agent 健康探测兜底，失败按 ADR-0002 收敛 Cold）。
- **多次复用同一快照不安全**（唯一 ID、熵池、随机数种子重复，[AWS 论文](https://arxiv.org/pdf/2102.12892)）——与 auto-suspend 关系不大，但限制 Warm 快照被 fork 式复用。
- **仓库文档已有的竞态约束**（docs/cats-sleep-wake-vmm-resource-reclamation.md §12）：page-out 中收到 Wake 用同一 lifecycle generation 仲裁；自动策略必须遵守 ADR-0002 单向降级、resume 失败收敛 Cold。

## 6. 对 Cats 的落地推荐

实现状态（2026-07-22）：工作租约、Guest 长轮询摘要、控制面事务判定、Gateway/exec 自动租约、Node/Guest 两阶段 quiesce、generation/sequence 栅栏和 `ActivityChanged` 类型化拒绝均已落地并有自动化测试。自动策略在新建 Cat 上默认开启、允许按 Cat 显式关闭，工作并集归零后不等待 idle timer。尚未完成的是 Suspended 承诺的 page-out（`MADV_PAGEOUT`）；当前 Cloud Hypervisor 路径只 pause，主要节省 vCPU 而非内存。完整方案见[《Cats 工作驱动的快速休眠：产品与实现设计》](cats-auto-tier-product-and-implementation-design.md)。

### 已选架构：控制面工作汇总 + Guest/Node 最终栅栏

**平台信号**
- Gateway 从准备唤醒/代理到响应结束持有请求租约；exec 从唤醒前到命令结束持有租约。
- 租约进入控制面持久化汇总，不使用 `last_request_at` 或 `suspend_after`。最后一个 release 直接触发事务判定。

**Guest 用户程序显式信号**
- Guest Agent 提供本机 Tasks 租约 API，但不扫描 `/proc`，也不根据 load、CPU、TCP 或 IO 推断业务状态。Guest 内用户程序通过 acquire / renew / release 明确设置 keep-awake 信号；Guest Agent 只校验 TTL、维护租约并经 Node heartbeat 转发摘要。
- 判定为**语义信号并集**：`无 Gateway 请求 AND 无活跃 exec AND 无用户程序设置的 Guest lease` 即尝试睡，不增加连续宽限期。“无 lease”只表示用户程序未请求 keep-awake，不表示平台证明所有 Guest 进程都已完成。
- 租约形态参考 Sprites Tasks API（§2.1：创建 task 压住睡眠 + 短 expire + 心跳续租 + 硬上限防泄漏）。为普通程序提供一行包装命令；未接入租约的后台 workload 应关闭自动休眠，或明确接受仅按平台入口活动休眠的契约。

**可选容量观测**
- CH `vm.counters` 与 KVM `KVM_GET_STATS_FD` 可用于容量、计费分析和排障，但不进入业务忙闲判定，也不覆盖用户程序设置的 guest task lease。

### 两条路线开发成本对比

| | 纯 VMM/宿主机侧 | guest-agent 协作（推荐） |
|---|---|---|
| 信号质量 | 只能看到代理指标；halt-polling 污染需矫正；无法区分"等待中"与"做完了" | 用户程序直接声明 keep-awake 租约；平台不猜测用户意图 |
| 改动面 | node-agent 新增 per-VM KVM stats/CH counters 采集循环；不进入 auto-tier 判定 | Guest Tasks API + lease 心跳透传 + 控制面策略引擎；不需要 `/proc` 业务推断 |
| 误判风险 | 作为业务信号不可接受；只做容量观测时不触发生命周期 | 用户程序漏设 lease 仍可能被睡；用包装命令、文档提示和 `off` 兜底 |
| 结论 | 只值得做成 Phase 3 的容量观测 | 主路线；Phase 1 仅影子验证，Phase 2 完成后才允许执行自动 suspend |

### 同时要补的欠账
自动睡眠的价值兑现依赖 Suspended 真正省内存：在 `suspend_cat` 的 CH pause 之后补 `process_madvise(MADV_PAGEOUT)`（文档 §5 已设计：pidfd + CAP_SYS_NICE，建议独立小特权 helper），并按 REAP/FaaSnap 的经验预期唤醒后的缺页拖尾，必要时后续做工作集预取。

---

## 附：验证说明

本报告主体论断经 64 票对抗性验证，存活者才被引用；被驳回的 2 条（关于 Firecracker 快照可在原进程恢复的表述）已按验证结论修正为"快照只能恢复进新 VMM 进程"。个别限定性发现已并入正文（如 E2B `onTimeout` 默认 kill 而非 pause、Morph wake-on-SSH/HTTP 默认关闭、AWS 博文未定义 inactivity 但 docs 定义为 endpoint 无流量）。§2.1 Sprites 部分为后续轻量补充调研，2026-07-22 又按当前官方 Lifecycle、Tasks、产品/计费与 Fly 设计文档做了一次人工交叉复核；它未进入原 64 票对抗性验证轮。
