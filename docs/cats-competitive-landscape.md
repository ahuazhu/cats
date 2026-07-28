---
audience: AI agents and implementers
description: Cats 与国内外沙箱/Agent 运行环境产品的关系：按隔离技术与状态持久性两轴的赛道分派、逐产品技术与商业对比、定价锚点、需求侧证据、Cats 的结构性优势与工程差距，以及国内落地的合规约束。
document_status: External competitive and market research (2026-07-25 snapshot); not a Cats implementation contract
lang: zh-CN
title: Cats 竞品与市场格局分析
---

# Cats 竞品与市场格局分析

> **本文性质**：外部调研快照，不是实现契约。跨组件决定仍以 [`docs/decisions/`](decisions/) 的 ADR 为准，
> Cats 自身的性能事实以[实验总报告](experiments-2026-07-21-storage-lifecycle.md)及其原始 CSV 为准。
>
> **证据标注约定**：【官】= 厂商官方文档明说 · 【三】= 第三方独立实测 · 【推】= 本文推断 ·
> 【未公开】= 检索后未找到公开资料。凡换算数字均标注为换算。
>
> **调研时间**：2026-07-25，12 路并行一手检索（官方文档、GitHub、HN、社区帖、定价页）。
> 竞品营销数字不作为基准；Cats 的原型数字不作为 SLA。

---

## 1. 最终结论

### 1.1 一句话

Cats 所在的象限——**「内存级休眠 + 盘随实例持久 + 跨主机可迁移 + 常驻公网入站 URL」四项同时具备**
——在全球范围内**只有一个对外售卖的产品占住，就是 Fly.io 的 Sprites**；
把四项做全的另外两家（Perplexity SPACE、Cognition Devin）**都自用不外售**；
AWS / Azure / Google 在这一格**完全缺席**；国内**没有任何一家做全**。

**再加一条「卷的生命周期独立于实例」，这一格连 Sprites 都不在——目前是空的。**
Sprites 全站文档 "volume" 出现 0 次，官方升级基础镜像的做法是销毁重建 + SSHFS 手动拷；
而有独立卷的 Modal / Daytona / Fly Machines 全都卡在更低的持久性层级（§2.2、§5.1）。

这既是 Cats 的机会，也是 Cats 最该警惕的地方：**空着的位置之所以空，有一部分是需求原因，不全是技术原因。**

**而这个象限之所以能长期空着，有一个结构性原因（§10 详述）：厂商按内存 wall-clock 计费与"休眠"
这个产品语义天然对立。** Vercel 即使 0% CPU 也按 provisioned 内存收全时长
（4GB = $0.0848/h，**一个空闲沙箱一个月 $61**），而自建 S3 方案下一个休眠的 10GiB 沙箱
月成本是 **$0.27–0.39**——**相差两个数量级**。
所以"长驻可休眠工作区"这一段需求会**结构性地从厂商流失到自建**。

推论直接决定 Cats 的卖点该是什么：**客户自建时唯一真正做不好的两件事是
「跨 host 恢复正确性」和「单写保护 / fencing」**——
这两件恰好是 Cats 已经写了崩溃注入测试和 stale-epoch fail-closed 测试的地方。
**Cats 的定价天花板不是 E2B 的单价，而是"客户自建 + 3 名工程师"的等效成本
（约 1,000 个常驻沙箱的盈亏平衡点，§10.3）。**

### 1.2 Cats 的真实位置

Cats 与 Sprites 是同一象限里**唯一的两个玩家**，而且技术选择高度重合（对象存储做 durable truth、
本地 NVMe 只做可删除 cache、chunk 级增量提交、稳定域名 + 按请求唤醒）。

Cats 相对 Sprites 有**五条结构性优势**（不是参数优化，是架构差异）：

0. **★ PersistentDisk：Sprites 完全没有这个原语。**
   Cats 的 Disk 是独立于 Cat 的一等资源——`cats disk create/ls/resize/snapshot/delete` +
   `cats mount <disk> <cat>` / `cats unmount <disk>`，计费按 provisioned GiB-month
   且**是否挂载不影响**，即生命周期与 Cat 彻底解耦。
   Sprites 的盘**严格跟随 sprite 本身**：官方明说 "deleting a Sprite deletes its checkpoints too"、
   "persists for the Sprite's lifetime"，且**全站文档 "volume" 出现 0 次**、
   REST v1 无 volume/disk/mount/attach 端点、Go SDK 无 `volume.go`、release notes 无 roadmap。
   最直接的反证是 Sprites 官方给出的"升级基础镜像"做法：
   **"destroy the Sprite and create a new one! If you need to copy files over,
   try mounting the filesystem locally"**（SSHFS 手动拷）。
   → 详见 §5.1。这是 Cats 在**持久性**这个核心卖点上对最直接竞品的干净能力缺口。
1. **四态 vs 三态。** Sprites 是 Active → Warm（内存冻结）→ Cold（内存丢弃）。
   它**没有** Cats 的 Warm 层——snapshot + VMM/backend exit、专属 RSS = 0、进程状态仍保留。
   Sprites 想省掉常驻 VMM 就必须丢掉进程状态；Cats 能两者兼得。这直接决定休眠密度与成本结构。
2. **VMM 选型：Cloud Hypervisor 让自定义块后端走最短的数据通路。**
   **Firecracker 的 vhost-user-blk 自 v1.6.0 起是 developer preview、明确禁止生产，
   且不支持快照**【官】（`docs/api_requests/block-vhost-user.md`）。
   但**这不等于 Firecracker 系产品拿不到"自定义块后端 + VM 快照"**：绕开 vhost-user，
   用 Linux **ublk** 把用户态后端暴露成一个普通块设备 `/dev/ublkbN`，
   再按普通 `path_on_host` 走标准 Drive API，Firecracker 看到的只是一个路径，
   原生快照（`SnapshotType::Diff`）照常工作。
   **公开反例已经存在**：kvcache-ai/AgentENV（MIT，Rust，自述用于 Kimi K3 的 agentic RL 训练）
   正是这么做的，两者同时成立——详见 §3.7。
   所以这一条应当写成**延迟代价**而不是能力缺口：ublk 路径的每个请求要多穿一次宿主内核块层，
   数据通路上也多一个用户态进程（Firecracker 与 ublk daemon 两个）；
   Cats 的 vhost-user 把虚拟队列放在共享 Guest 内存里由 `cats-blockd` 直接解码，
   Cloud Hypervisor 不在数据通路上。
   > ⚠️ **这是结构推演，不是实测结论。** Cats 与 ublk 路径之间目前**没有任何同机对照数据**。
   > 可参考的量级只有本仓库同一条 vhost-user 路径上、仅改驱动等待方式（poll → spin）
   > 就把 QD1 4 KiB p50 从 25 µs 压到 9 µs
   > （[`raw/notification-cost.log`](../experiments/vhost-user-blk-frontend-20260726/raw/notification-cost.log)），
   > 即**一次用户态线程唤醒是十几微秒量级，与 QD1 请求总延迟同数量级**；
   > 但实验报告自己把那组数字标注为无 KVM 开发机上的 **harness 伪影**，不可当作 Guest 可见性能。
   > **待验证项：同机、同后端、统一驱动等待方式的 QD1 4 KiB fio 对照（vhost-user vs ublk）。**
3. **Guest 是真未修改 Linux + 真 root。** Sprites 官方自述"We've slid a container between you and
   the kernel"【官】，用户不在 root namespace。Cats 的 Guest 看到标准 virtio-blk 和未修改 ext4，
   拥有完整内核（ADR-0001 不可协商约束）。
   附带证据：**gVisor 结构上不能 mount ext4 等块设备文件系统**【官】，
   这解释了为什么 gVisor 路线（Modal 默认档）永远给不出"未修改 ext4 + 持久块设备"。
4. **可自托管。** Sprites 承诺半年的开源 Rust 本地版至今未发布；Daytona 2026-06 直接闭源；
   Modal / Vercel / Cloudflare 全部无自托管。Cats 是完整 Rust workspace + Ports and Adapters
   （ADR-0005）+ Terraform（ADR-0012），私有化路径天然存在。

### 1.3 三个必须正视的问题

| 问题 | 事实 | 严重度 |
|---|---|---|
| **标价看起来最贵，但计量基准被埋掉了** | Cats 当前为 $0.07/CPU-h + $0.045/GiB-h，CPU 与 Sprites 相同、内存略高；标价高于 E2B（CPU +39%、内存 +178%）。但 **Cats 是唯一把 CPU 与内存都按 cgroup 实测计费的**，其余按预留规格（Vercel 官方明写空闲照收）。同一负载 2 vCPU/4 GiB、CPU 利用率 10%、常驻集 1 GiB 时，**Cats $0.0590 vs Vercel $0.1104 vs E2B $0.1656**——**实际最便宜，标价最贵**（§6.2）。真正的风险是**对外传播时会被按标价误判**，以及**存储费率至今是空的** | 中 |
| **生产组合路径尚未测量** | Cold 启动路径本身已优化到 **1.755 s**（i4i Local NVMe，新内核新进程，5 轮 P50，相对 stock 21.064 s 降 91.7%）——**与 Sprites Cold 1-2 s 已经持平**。Direct-S3 的 **39.868 s** 是另一条路径：**S3、无初始 Cache、串行 Python 原型**。**两者尚未合并测量**，即"优化启动路径 + 生产 Rust blockd + 本地热 cache"这个真实生产组合还没有数字 | 中 |
| **技术壁垒正在被开源清零** | 腾讯 **CubeSandbox**（Apache-2.0，10.7k★，2026-04 建库）：RustVMM+KVM microVM、独立 Guest 内核、**冷启 <60ms**、单实例额外内存 **<5MB**、**百毫秒级快照与回滚**、**空闲自动快照挂起→百毫秒唤醒**、E2B 兼容、腾讯云 Terraform 一键部署 | 高 |

第三条需要特别说明：CubeSandbox 开源的**恰好就是** microVM 沙箱唯一能创造毛利的那部分能力
（暂停不计费的高密度调度 + 快照挂起唤醒 + CubeCoW 基于内核 FICLONE/XFS reflink 的写时复制）。
"能做出 60ms microVM"在 2025 年是壁垒，2026 年是一个 `git clone`。
**Cats 的护城河不能建在"我们也能做 microVM 休眠"上。**

---

## 2. 按关键指标逐项对比

本节是**决策层**：按一个 sandbox 真正重要的指标逐条横比。
§3 的逐产品档案是**证据层**，用来核对本节每一格的出处。

**五个指标，按需求侧证据强度排序**（痛点排序见 §9.2）：

| # | 指标 | 为什么重要 | 现状 |
|---|---|---|---|
| 1 | **单位成本（尤其休眠态）** | 需求侧**最激烈**的抱怨："a **50x markup** on what qemu/docker + bare metal prices would be"（HN 48907562） | 名义单价高度锚定；真实差异在**计量基准**（§2.5） |
| 2 | **状态持久性与生命周期上限** | "most sandbox providers **kill your agent after 24 hours**"（HN 48999489）。而 METR 测得模型任务时长视界**约每 7 个月翻倍**——供需在反向移动 | 供给侧卡在 8–24h（§2.3） |
| 3 | **环境保真度** | **agent 失败的主因是环境而不是模型**："Agents fail because the environment is flaky: missing deps, slow setup, weird state"（HN 46699324），否则 agent "burning \$10 retrying a fail state" | **整个市场都不测这个指标**（§2.2） |
| 4 | **隔离强度** | sandbox 的定义性门槛。"the only way to have actually isolated sandboxes is by using VMs"（E2B 员工，HN 46877098） | **已同质化 → 是门槛不是区分度**（§2.1） |
| 5 | **并发与弹性** | 旗舰客户唯一真正在意的事。Lovable 买 Modal 就为这个：48h 25 万应用、峰值 2 万并发、**自己代码从 15,000 行降到 700 行** | 数量级差异极大（§2.6） |

**排序与厂商营销的错位**：所有厂商都把**冷启动延迟**做头条（§2.4），
但它在需求侧抱怨里只排第 7。这个错位本身值得记住。

### 2.1 隔离强度 —— 门槛，不是区分度

| 流派 | 代表 | 代价 |
|---|---|---|
| **WASM / 浏览器内核** | StackBlitz WebContainers（Bolt.new 的底座） | 跑不了原生二进制、Python 无 pip；无服务端状态与入站；成本转嫁用户设备 |
| **共享内核容器（+ seccomp 硬化）** | GitHub Codespaces、Replit（正迁移 microVM）、**Daytona 默认 Container class（Docker + Sysbox）**、Sealos、字节 AIO Sandbox | 内核逃逸面。**Cognition 明确点名此路不通**；Daytona 的 CVE-2026-31431 就是宿主内核 page-cache 漏洞、需全 fleet 打补丁 |
| **gVisor 用户态内核** | **Modal 默认（runsc + nvproxy）**、OpenAI code interpreter【三】、GKE Agent Sandbox | syscall 兼容性缺口 + 性能税。**Modal 自家工程师承认**"gVisor's achilles heel is it's missing or inaccurate syscalls" |
| **microVM / 硬件虚拟化** | **Cats（Cloud Hypervisor）**、Fly Sprites / Fly Machines / E2B / Vercel Sandbox（均 Firecracker）、Perplexity SPACE、Azure dynamic sessions（Hyper-V）、AWS AgentCore、Together CSB、Blaxel、CreateOS、Northflank（Kata+CH/FC/gVisor 可选）、Freestyle（KVM）、Devin（自研）、腾讯 CubeSandbox（RustVMM） | 自建工程量巨大——**Cognition：hypervisor 一年多 + 编排层再三个季度**；内存开销与密度低；冷启需靠预热池/快照掩盖 |

⚠️ **29 个产品里 19 个都是 microVM。市场在隔离技术上已经同质化，这本身是个发现。**
它是准入门槛：不满足则不敢跑不可信代码。但**拿它做对比维度已经没有信息量**。

### 2.2 环境保真度 —— 市场不测，但决定 agent 成败

这一项的用户视角问法是：**你在本机能做的事，有多少能原样搬进去？**

| 档 | 用户实际遇到什么 | 谁 |
|---|---|---|
| **像自己的机器** | 真 root、`apt install` 直接用、git / SQLite / node_modules 行为与本机一致、能挂自己的盘 | **Freestyle**（官方明说**嵌套虚拟化** + 真 root + 每负载独立内核）、**Cats**（ADR-0001 不可协商：标准 virtio block device + 未修改 ext4 + 独立 Guest Kernel + 真 root） |
| **受限 VM** | 硬件级隔离，但**不是真 root**，或**内核不能换**，或**镜像必须走平台流程** | **Fly Sprites**（"We've slid a container between you and the kernel"，**不在 root namespace**）、**E2B**（guest kernel **LTS 6.1 构建时固化不可升级**，要新内核特性只能重建 template）、**Cloudflare**（**"Containers run without root privileges"** → `sudo`/`apt` 不可用，Docker 需 rootless 变通）、**Vercel**（有 sudo，但镜像**必须推到自家 Registry**、**不执行 ENTRYPOINT/CMD** → 现有 Dockerfile 不能直接搬；盘固定 32GB；2026-06-01 才开放 Docker/FUSE/CAP_SYS_ADMIN）、Fly Machines、Morph、Together CSB、Blaxel、Northflank、Runloop、AWS AgentCore、Azure、腾讯 AGSX、PPIO、火山 veFaaS、阿里 ACS、百度 AX、Perplexity SPACE、Devin（后两者未公开内核可控性与 root） |
| **syscall 有坑** | **挂不上块设备文件系统**（gVisor 结构性限制【官】）；**部分二进制静默失效**（Modal issue #2796 实证）；gVisor **谎报内核版本 4.4.0**，依赖内核版本判断的工具行为错乱；不能嵌套虚拟化 | Modal（默认档）、OpenAI CI、GKE Agent Sandbox |
| **共享内核** | 有完整 Linux 但内核与宿主共享，**不敢跑完全不可信的代码** | Daytona（默认档）、Sealos、Replit（迁移中）、Codespaces |
| **不是 Linux** | 跑不了原生二进制、native addon 默认禁用、Python 无 pip | WebContainers |

**这条指标是用户自己喊出来的**，不是本文构造的：HN 上对 E2B 与 Daytona 的原话是
**"don't really feel like VMs / you can't run everything you can in an EC2"**。

> ⚠️ **顶档内 Freestyle 强于 Cats，不要读成 Cats 最强。**
> Cats 的**嵌套虚拟化列在架构文档的「后续能力」**（V1 不做），Freestyle 官方已支持；
> 且 Cats 的**内核基线由平台 Image 决定**（Image 带 `kernel_abi`，走 dev → canary → stable channel），
> 与 E2B 的"构建时固化"是程度差别而非性质差别。
> Cats 在这一档站得住的只有**真 root + 未修改 ext4 + 标准块设备语义**这三条。
> **Cats 的独占不来自任何单条指标，只来自持久性 × 保真度的交点。**

### 2.3 状态持久性与生命周期上限

**持久性分五级，累加式**（每级要求前面各级都已满足）：

| 级 | 要求 | 谁 | 判断 |
|---|---|---|---|
| 1 | 纯无状态一次性 | Google Cloud Run sandboxes（执行完即弃、靠 tar 搬状态）、Vertex Code Execution、AWS Lambda/Fargate、**Cloudflare（磁盘易失）**、百度 AX、Azure dynamic sessions、AWS AgentCore | **最拥挤**，云厂商全在这 |
| 2 | 会话内持久、超时即毁 | Modal（≤24h）、Vercel（≤24h⚠️）、Runloop（≤48h）、腾讯 AGSX（≤24h）、火山 veFaaS（≤24h）、阿里 ACS、PPIO（**≤3600s**）、阿里 FC AIO（≤6h）、OpenAI CI（20min 且**不可复活**） | 拥挤；**agent「隔天回来」全部失败** |
| 3 | 快照休眠、可长期挂起 | E2B（暂停无 TTL）、Together CSB、Blaxel（<25ms）、**Freestyle**、CreateOS、Claude Managed Agents、Devin（自用）、Daytona VM class（experimental）、**AgentENV**（开源自建，pause/resume 无 TTL；路由靠请求头而非常驻域名，卷不独立，故到不了第 4 级） | **2026 的主战场，同质化严重** |
| 4 | 盘随实例持久 + 跨主机可迁移 + 常驻入站 URL | **Fly Sprites**（唯一对外售）、**Perplexity SPACE**（不外售）、Northflank（半只脚：内存恢复延迟与跨主机均未公开）、Codespaces（盘持久但无内存快照、≤30 天） | 极稀薄 |
| 5 | **上述 + 卷生命周期独立于实例** | **Cats（目标形态）** | **空的** |

**为什么第 4 与第 5 级必须分开**：这是教科书级的 **instance store vs EBS**，不是措辞游戏。
Sprites 官方给出的"升级基础镜像"做法就是**销毁重建 + SSHFS 手动拷文件**——因为它的盘没法留在原地。
**而第 5 级为什么是空的，关键不在"别人没有独立卷"**：
Modal Volumes、Daytona Volumes、Fly Machines Volumes **都是生命周期独立的卷**，
但它们**全都卡在更低层级**（Modal 24h 硬顶 + URL 随机；Daytona 共享内核 + 4 vCPU 顶；
Fly Machines 的卷绑死单机、不可跨主机）。反过来，够到第 4 级的两个产品**都没有独立卷**。
**"四项齐全"与"卷独立"这个交集目前是空的**——完整卷原语对比见 §5.1。

**生命周期上限**（这是需求侧痛点 #2 的直接量化）：

| 上限 | 产品 |
|---|---|
| **300 秒** | 百度 AX（超时即删，40GB 明写临时盘） |
| **1 小时** | PPIO（系统限制单沙箱最长 3600s）、E2B Hobby |
| **6 小时** | 阿里 FC AIO Sandbox |
| **8 小时** | AWS AgentCore、**AWS Lambda MicroVMs（2026-06-22 上线）** |
| **24 小时** | **E2B Pro、Vercel Pro⚠️、Modal、腾讯 AGSX、火山 veFaaS** ← 事实上的行业天花板 |
| **48 小时** | Runloop |
| **无过期** | **Cats（设计）**、Fly Sprites、Fly Machines、Northflank、Daytona（auto-stop=0） |

⚠️ Vercel 的 24h 有**官方文档自相矛盾**：pricing 页写 24h，
但其**自家 KB 对比页**仍写 "5 hr (Pro/Enterprise)"，且找不到变更 changelog。落地前需实测。

### 2.4 启动与唤醒延迟 —— 厂商头条指标，需求侧只排第 7

⚠️ **这张表的数字来自不同测量边界，横向比较必须先看最后一列。**
本文不把它做成坐标轴，正是因为这些口径不可比。

| 产品 | 冷启/创建 | 唤醒（保内存+进程） | 口径 |
|---|---|---|---|
| 腾讯 **CubeSandbox**（开源） | **<60ms**；50 并发均值 67ms / P95 90ms / P99 137ms | 空闲自动快照挂起 → **百毫秒级** | 官方仓库自测 |
| **Blaxel** | — | **<25ms** | 厂商宣称 |
| **Perplexity SPACE** | 中位 **60ms** / P90 **89ms**（优化前 185ms/447ms） | — | 官方工程博客，**生产实测 >125 万次创建** |
| **Daytona** | **<90ms**（container class） | VM class "under a second"（experimental） | 官方；含网络约 60ms |
| **Freestyle** | **<600ms** 开机 | **<100ms**；live fork 毫秒级且不暂停源 VM | 官方 |
| 火山 veFaaS | 冷启 **100ms**；**预热池命中 40ms** | 休眠唤醒秒级（1–10s） | 官方 |
| 腾讯 AGSX | **100ms** | **未公开** | 官方 |
| **E2B** | 官方同页并列 "<200ms" 与 "80ms"；第三方 ~150ms，另有 410ms p50 | resume **≈1s**（pause ≈**4s/GiB RAM**） | 官方 + 第三方，**口径不一致** |
| PPIO | **<200ms** | 恢复约 **1s**（暂停约 4s/GB） | 官方 |
| 阿里 ACS | 预热池"百毫秒级"；案例 200ms 级 | 内存态唤醒 **1–10s** | 官方 |
| **Morph** | **<250ms**；snapshot/branch/restore 均 "under 250ms" **且含内存+进程** | 同左 | 厂商宣称，**架构透明度最低** |
| Vercel Sandbox | 顺序中位 **361ms** / P99 569ms；并发 burst 中位 **543ms** | ❌ **仅磁盘，进程须 `onResume` 重启**；**未公布 resume 延迟** | **ComputeSDK 第三方实测 2026-07-24**；官方 "starts in milliseconds" 系夸大 |
| Modal | 中位 **<500ms**；**100 万并发 <60 秒** | Memory Snapshot p50 **1.05s** / p0 0.69s（**experimental + 7 天上限 + 一对一**） | 官方 blog（**docs 本身无延迟数字**） |
| Together CSB | 冷启 2.7s P95 | **快照恢复 500ms P95**；fork <1s | 官方 |
| Azure dynamic sessions | 预热池分配 **<100ms P90** | ❌ 冷却即销毁 | 官方 |
| Northflank | microVM **<1s** | **恢复延迟未公开** | 官方 |
| **Fly Sprites** | 创建 1–2s | Warm **100–500ms** → Cold **1–2s**（内存丢弃） | 官方文档 |
| Fly Machines | "subsecond"；suspend 文档对比值冷启 ~2s+ | resume "a few hundred ms"，**仅 ≤2GB 且不保证成功** | 官方 |
| Runloop | "a few seconds" | ❌ 纯磁盘；`wake_on_http` ≈1s | 官方 |
| Cloudflare Sandboxes | "often in the **1-3 second** range"；官方 blog 实测 clone+npm install **30s**；从 backup 恢复 2s | ❌ 无休眠态 | 官方 |
| **Cats** | 优化 Cold **1.755s** | Suspended **0.213s** / Warm **0.382s** | **AWS metal 小样本 P50，i4i Local NVMe，非 SLA**。Direct-S3 空缓存原型 39.868s 是**另一条路径**（见 §8.2） |

**读这张表的三条注意**：
1. **口径差异比数字差异大。** Daytona 的 <90ms 是 Sysbox 容器（共享内核），
   Vercel 的 361ms 是真 Firecracker microVM——Rauch 的措辞是严格限定过的
   "the fastest sandbox **using real VMs as security boundary**"。
2. **"唤醒"分两种，混用会得出错误结论。** 保内存+进程（Sprites Warm、E2B resume、Morph、Cats Suspended/Warm）
   与只恢复磁盘、进程重启（Vercel、Runloop、Daytona container）不是一回事。
3. **Cats 与 Sprites 的 Cold 都是热本地 cache 口径。** Sprites **从未公开空缓存跨节点恢复的数字**；
   Cats 测了并诚实标注了 39.868s（串行 Python 原型）。这是 Cats 多披露、不是 Cats 更慢。

### 2.5 单位成本与计量基准

**标价的横向对比见 §6.1；计量基准与实际账单见 §6.2。** 本节只给结论：

- **名义单价高度锚定**：E2B = Daytona = CreateOS 三家逐位相同（$0.0504/vCPU-h + $0.0162/GiB-h）；
  Northflank $0.01667 是地板；Cats 为 $0.07 + $0.045，CPU 与 Sprites 相同、内存略高，标价最高档。
- **但标价不可直接比，因为计量基准不同。** **Cats 是唯一把 CPU 与内存都按 cgroup 实测计费的**；
  其余按预留规格（Vercel 官方明写空闲照收）、max(预留,实际)（Modal）、
  捆绑单位（Morph 的 MCU）或整会话小时（Azure、Anthropic）。
- **同一负载可以反转排序**：2 vCPU/4 GiB、CPU 利用率 10%、常驻集 1 GiB 时——
  **Cats \$0.0590 < Vercel \$0.1104 < E2B \$0.1656**。Cats 标价最贵，实际最便宜。
  Vercel 与 E2B 的交叉点在 **u ≈ 32%**。
- **按请求/调用另收费的全是 FaaS 血统**：Vercel（Creations \$0.60/1M）、Cloudflare（Workers 请求）、
  阿里 FC、百度 CFC、华为 FunctionGraph。这套模型对"长期存在、偶尔被访问的机器"是逆向的。
  **Cats 与 Sprites 都不收请求费。**
- **休眠态收费把市场劈成两半**：零 compute + 极低冷存储（Sprites、PPIO、Daytona Archived、
  Freestyle、Blaxel）vs 运行中空闲照收全额（Modal、Vercel 的内存那一条）。
  **这就是"按内存墙钟计费与休眠语义天然对立"的机制**（§10.4）。

### 2.6 并发与弹性 —— Cats 这一格是空白

| 产品 | 峰值/吞吐能力 | 单账号并发上限 | 口径 |
|---|---|---|---|
| **Modal** | **100 万并发 <60 秒**；数万个/秒 | 单客户当前上限 **5 万** | 官方 blog 2026-07-16 |
| 火山 veFaaS | **12 万实例/分钟** | — | 官方 |
| 阿里 ACS | **15,000 Sandbox/分钟**；10s 拉起 5,000 沙箱 | — | 官方 |
| Daytona | 5 万沙箱约 **75 秒** | 组织配额 Tier1 10 vCPU → Tier4 500 vCPU | 创始人 + 官方 |
| Cloudflare | GA blog：15,000 lite / 6,000 basic / >1,000 大实例 | 账号 6 TiB 内存 / 1,500 vCPU / 30 TB 盘 | 官方 |
| Vercel Sandbox | vCPU 速率 200/min（Pro）、400/min（Ent） | Hobby 10 / **Pro 2,000** / Ent 2,000+ | 官方 |
| E2B | 创建速率 1/s（Hobby）、5/s（Pro） | Hobby 20 / Pro 100（可加购至 1,100）/ Ultimate 1,100+ | 官方 |
| GKE Agent Sandbox | 宣称 **300 sandbox/s** | — | 官方 |
| Morph | — | 并发 devbox 8 / 32 / 128 | 官方 |
| 腾讯 AGSX | — | 实例 50/地域、CPU 50C、内存 100G | 官方 |
| PPIO | — | **50 实例/用户** | 官方 |
| AWS AgentCore | — | 默认 **25 并发**/账号/区域 | 官方 |
| Runloop | — | 试用限 3 devbox | 官方 |
| **Fly Sprites** | **不做横向扩展**（tptacek 明说面向个人项目、不适合高流量） | **数据冲突**：HN 称 PAYG 3 / 高档 10；第三方研究页称 $20=20 / $2000=2000。**官方无 limits 页** | 冲突 |
| **Cats** | **未公开、未测** | — | **已测规模仅"10 并发、小规格"的 Warm wake storm**（ADR-0002 待验证事项）；准入控制与限流已实现（`node-agent/src/admission.rs`，ADR-0002 §8），但未在更大规模上验证 |

**这一格是 Cats 最薄的一环，而它正是旗舰客户唯一在意的指标。**
Lovable 迁到 Modal 的直接原因就是前一家扛不住峰值。
好消息是 Cats 与 Sprites 在这一格**处境相同**——Sprites 明说不做横向扩展。
坏消息是 Modal 靠这一格拿到了 ARR >$300M 中 Sandboxes 占超三分之一的生意。

---

## 3. 逐产品档案（证据层）

本节是 §2 每一格的出处。按产品组织，用于核对，不用于横比。

### 3.1 Fly Sprites —— Cats 最直接、最完整的竞品

**身份**：Fly.io（superfly）的产品，2026-01-08 发布。`sprites.dev` 现 301 跳转到 `fly.io/sprites`。
无独立融资，判定为 Fly.io 自有产品线。

| 维度 | 事实 | 性质 |
|---|---|---|
| 隔离 | Firecracker microVM，KVM 之上。**用户代码在 VM 内再套一层 inner container**："We've slid a container between you and the kernel" | 【官】 |
| 存储 | **改造版 JuiceFS**："a very hacked-up JuiceFS, with a **rewritten SQLite metadata backend**"。不可变 chunk 存 S3 兼容对象存储；元数据本地 SQLite + **Litestream** 持久化。"Nothing depends on local storage" | 【官】 |
| 本地盘 | **纯 cache**：每 sprite 挂 sparse 100GB NVMe，"a **dm-cache-like** feature… to eliminate read amplification"，"**nothing in that NVMe volume should matter**" | 【官】 |
| 生命周期 | 三态：Active → **Warm**（内存冻结，唤醒 **100-500ms**，"processes pick up mid-thought"）→ **Cold**（内存丢弃，唤醒 **1-2s**，进程重启）。Active 后约 **30 秒**进 Warm。**TCP 连接 warm/cold 都断** | 【官】 |
| 跨机恢复 | "the durable state of a Sprite is simply a URL… They **migrate (or recover from failed physicals) trivially**" | 【官】 |
| checkpoint | **仅磁盘**、CoW，最近 5 个挂 `/.sprite/checkpoints`。营销页称 ~300ms，**官方文档写 10-30s**（取决数据量），restore ~1s。restore 会整体替换文件系统 | 【官】 |
| 网络 | 稳定 URL `https://<name>-<org-id>.sprites.app`，**wake on request**，只需监听 8080；出站 DNS allow/deny 域名策略；URL 经 Corrosion gossip 秒级传播到 Anycast 边缘。自定义域名【未公开】 | 【官】 |
| 规格 | burst 到 8 vCPU；内存**自动伸缩 2GB→16GB**；100GB thin-provisioned **ext4**；Ubuntu 25.10 预装 Node/Python/Go/Rust/Claude/Gemini/Codex | 【官】 |
| **独立持久卷** | **不存在。** 全站文档 "volume" 0 次；REST v1 无 volume/disk/mount/attach 端点；CLI 无对应子命令；Go SDK 无 `volume.go`；无 roadmap。盘严格跟随 sprite："deleting a Sprite deletes its checkpoints too"、"persists for the Sprite's lifetime"。**升级基础镜像的官方做法是 "destroy the Sprite and create a new one!… try mounting the filesystem locally"（SSHFS 手动拷）** | 【官】+实测 |
| fork | **仅内部 admin 控制台**，且 ~90 秒。**公开 REST API 无 fork 端点，CLI 无 `sprite fork`** | 【官】+实测 |
| 定价 | **$0.07/CPU-h + $0.04375/GB-h**；热存储 $0.000683/GB-h（~$0.50/GB-月）；**冷存储 $0.000027/GB-h（~$0.02/GB-月，始终计费）**。休眠 = 零 compute 费 | 【官】 |
| 订阅档 | Recruit 免费 / Adventurer $20 / Legend $200 / Mythic $2000；$30 试用额度（官方称约 500 个 sprite） | 【官】 |
| 自托管 | **不开源、不可自托管**。承诺的开源 Rust 本地版至今未发布 | 实测 |

**产品演进教训（可直接吸收）**：Sprites 的热/冷两级存储费率是 **2026-01-22 应社区抱怨
"睡着的 sprite 还按 $0.50/GB-月 收费"才加上的**。Cats 的 metering 里 `storage.hot.v1` /
`storage.cold.v1` 两个 metric 已存在但 rate card 未填——建议直接按两级结构定价，别等用户投诉。

**Sprites 自己划的边界**：tptacek 在 HN 明说 **"Run prod apps on Fly Machines.
Do exploratory computing in Sprites."**，且面向"个人项目/一次性开发环境"，
**不做横向扩展、不适合高流量**。

**可攻击的差异点**（均有据）：
0. **★ 无独立持久卷原语**（§5.1）。盘与 sprite 身份强绑定，换基础镜像必须销毁重建 + 手动拷文件。
   这是"持久性"这个 Sprites 自己的核心卖点上的结构性缺口。
1. fork/branch 未开放（竞品 boxd 主打 60ms CoW fork from running state）
2. 无自托管/不开源 → 堵死主权与合规客户
3. 无 template/pool 原语，业务侧仍要 10+ 分钟 bootstrap
4. **单区域、区域不可选**，有人实测 ~200ms 打字延迟
5. **checkpoint 只含文件系统不含内存/进程**，restore 是破坏性的
6. 单价偏贵（≈2x E2B ≈5x Northflank）
7. Fly.io 的可靠性/账单历史是社区反复提及的采购阻力
8. **官方 release notes 停在 2026-04-30**（近 3 个月无公开更新），SDK 仓库 7 月仍在提交

**对 ADR-0003 的外部背书**：Sprites 官方承认自己是 "very hacked-up JuiceFS" 且**已重写元数据后端**。
这说明走这条路的人最终都得把 JuiceFS 拆掉。Cats 在 ADR-0003 直接选择自研 Direct-S3 ChunkStore、
把 JuiceFS 方案降为历史参考，是被外部验证过的决策。
另外 [`docs/sprite-storage-flow.md`](sprite-storage-flow.md) 中标为"结构性推断"的部分
（ext4 逻辑块变化必须被块映射结构关联到 immutable chunk）已被官方架构文章证实。

### 3.2 E2B —— 事实标准的制定者

| 维度 | 事实 |
|---|---|
| 隔离 | Firecracker，**独立 guest kernel**（LTS 6.1，构建时固化不可升级）；rootfs.ext4 只读镜像 + ext4 overlay，OverlayFS 省盘【官】 |
| 冷启动 | 官方同页并列 "<200ms"（同区域）与 "80ms"；第三方测 ~150ms，另有 410ms p50【官+三】 |
| 休眠 | **Firecracker 快照 + UFFD 按需缺页**。内存状态保留。**pause ≈ 4s/GiB RAM，resume ≈ 1s**。**暂停无 TTL、无限期保留**；resume 后 sandbox ID 不变，**24h 上限被重置**【官】 |
| fork | **snapshots 一对多 + fork 一次最多 100 个分叉（含内存）**【官】 |
| 持久卷 | Volumes（独立生命周期、可挂多 sandbox）= **private beta，需邮件申请**；另支持 FUSE 挂 S3/GCS/R2【官】 |
| 上限 | 连续运行 **Hobby 1h / Pro 24h**；8 vCPU / 8 GB RAM / 10-20 GB 盘；**无 GPU**【官】 |
| 网络 | `https://<port>-<sandboxid>.e2b.app`；**auto-resume：打 URL 即唤醒**；出站 allowOut/denyOut 可运行时热改。自定义域名需**自己搭 Caddy 反代**【官】 |
| 定价 | **$0.000014/vCPU/s = $0.0504/vCPU-h**；**$0.0000045/GiB/s = $0.0162/GiB-h**；Pro **$150/月**。**暂停态存储费官方未公开** |
| 自托管 | `e2b-dev/infra` **Apache-2.0**，Terraform + Firecracker + **Nomad + Consul**；GCP 完整 / AWS beta / **裸机未支持**。**BYOC ≠ 自托管**（E2B 仍托管控制面 + 收匿名指标） |
| 融资/客户 | **$21M A 轮 2025-07-28（Insight Partners 领投）**，累计 $32M。客户：**Manus、Perplexity、Groq、Lindy、Gumloop、Genspark、Hugging Face、LMArena、Devin Outposts、Stripe Projects** |

**对 Cats 最有价值的一句社区证据**（HN）：
> "Daytona and E2B are both great 'sandbox' providers but **don't really feel like VMs** /
> you can't run everything you can in an EC2"

**已知问题**：#884 第二次 resume 后文件改动丢失；**#1587（2026-07-23）auto-resume 后 stdout 流卡死**；
#1418 高并发 HTTP/2 失败；#1031 auto-pause 时进程未被杀。auto-resume 正是 issue 密集区。

**战术含义**：E2B 的 API 形状已成事实标准——**阿里云（FC + ACS + PAI 三处）、火山引擎、腾讯 AGSX、
百度 AX、PPIO 全部做了 E2B 兼容层**，且都是"改一个环境变量"。
Cats 提供一个 E2B 兼容端点，迁移摩擦几乎归零，而 Cats 能在兼容层之下多给出
E2B 给不了的东西（真持久块设备、无时长上限、独立内核、可自托管）。这比自创一套 API 划算得多。

### 3.3 Vercel Sandbox

| 维度 | 事实 |
|---|---|
| 隔离 | **Firecracker microVM，每 sandbox 独立 guest kernel**。官方原文 "each sandbox runs in its own Firecracker microVM with a dedicated kernel"，明确对比容器"Shares host kernel"。**非 gVisor**【官】 |
| 冷启动 | 官方 "starts in milliseconds" **是夸大**。ComputeSDK 独立基准（2026-07-24，成功率 100%）：顺序中位 **361ms** / P99 569ms；并发 burst 中位 **543ms** / P99 1.12s【三】 |
| 上限 | 时长 Hobby 45min / Pro·Ent **24h**⚠️；Ent 32 vCPU / 64GB；**磁盘固定 32GB 不可调**；**仅 iad1 单区域** |
| ⚠️ 文档矛盾 | pricing 页写 24h，但 Vercel **自己的** KB `vercel-sandbox-vs-e2b` 仍写 "5 hr (Pro/Enterprise)"，**且找不到 5h→24h 的 changelog**。落地前需实测 |
| 持久化 | `persistent: true` 已是默认（2026-05-26 GA）。**快照只含磁盘，不含内存/运行进程**——是 disk checkpoint 不是 hibernate，恢复后须 `onResume` 自行重启服务。保留期默认 30 天（自上次使用起算），`snapshotExpiration: 0` = 永不过期 |
| Drives | 私有 beta、免费，可跨 sandbox 复用，≤4 个/sandbox，默认 100GiB 可配至 1TiB。**但官方原文 "single reader, single writer"，且建议"仅用于缓存等非关键用途"** |
| 网络 | ≤15 端口，`sandbox.domain(port)` → `https://<sub>.vercel.run`。**跨 session 是否稳定：文档从未声明**；**auto-resume 只由 SDK 调用触发，未提 HTTP 可唤醒** → 停机时 URL 不服务、也不能唤醒【官+推】 |
| 定价 | Active CPU **$0.128/h**（I/O 等待不计）+ Provisioned Memory **$0.0212/GB-h**。**关键陷阱：内存按 provisioned × 全时长计费，空闲也算**——官方原文 "A session is billed for the full time it runs, **even while idle**"。CPU 单价 ≈ E2B 的 **2.5 倍**；但 Pro 门槛低（$20/mo vs E2B $150/mo） |
| 采用度 | **npm 周下载 `@vercel/sandbox` 304 万** vs `e2b` 123 万 vs `modal` 36 万 vs `@daytonaio/sdk` 35 万 vs `@cloudflare/sandbox` 25 万。但 **HN 全站历史仅 4 条评论**提到 "Vercel Sandbox"，GA 博文投 HN 得 1 分 0 评论 |
| 缺口 | 无 GPU、**无 BYOC/自托管**、无内置 stateful REPL（Vercel 自己 KB 承认 E2B 有） |

**官方自己划的边界**：**"Sandboxes are not designed to run continuously"**，
并推荐 Functions 作为"需要常驻服务时的替代品"。

**最响的社区痛点是单区域**：GitHub #261（2026-07-24 开，0 回复）作者逆向发现服务端 `__region`
校验值实为 `"iad1, sfo1, cle1"`，**传 `sfo1` 被接受但创建出的 sandbox 仍报 `region === "iad1"`**。
德国团队原文："we would love to adopt vercel sandbox as our AI platform solution…
unfortunately unsure due to the lack of EU hosting."

**一条对 Cats 有用的最佳实践者证据**：**Sentry 在 `getsentry/junior` 维护了一份 Vercel Sandbox
专用排障 skill**，直接命名病因 **"Confusion caused by docs drift."**，
并在自己 README 里写 **"Do not treat the sandbox filesystem as product storage."**
另有 Giselle 团队发布 `@giselles-ai/sandbox-volume`，理由原文：
"snapshots can resume a sandbox, but **long-lived workspace state is a different problem**"。
**用户在自己造 Cats 想做的东西。**

### 3.4 Cloudflare Sandboxes —— 结构上不在同一象限

栈的关系：Worker（你的代码）→ **Durable Object**（持久身份、路由、preview URL、拥有容器生命周期）
→ **Container**（真正跑代码）。即 Sandboxes = SDK 封装 Cloudflare Containers，Containers 由 DO 驱动。

**决定性事实**：**磁盘是易失的**。官方原文——
> "All disk is ephemeral. When a Container instance goes to sleep, the next time it is started,
> it will have a **fresh disk** as defined by its container image."

Sandbox 侧更直白：idle 后"All files are deleted / All processes terminate / All shell state resets"，
下次请求"a fresh container starts. **All previous state is lost**"。

**DO hibernation ≠ sandbox 保活**：DO 约 10 秒空闲即休眠、内存态丢弃、构造器重跑。
它保住的是 DO storage 里的元数据/身份，**不保容器磁盘**。【推】这正是 sandbox ID 稳定但环境重置的原因。

兜底只有 R2：`createBackup()/restoreBackup()` 是**目录级**（squashfs 压缩上传 R2，
TTL 默认 3 天，**不含进程/内存/全盘**）；`mountBucket()` 挂 R2/S3/GCS 但官方警告
"should not expect native SSD-like performance while using FUSE"。
原生全盘 snapshot GA 时称"rolling out in the coming weeks"，**至今未找到已普遍可用的确认**。

**结构性冲突**：容器在"最近的、已预取镜像的位置"启动，**不与其 DO 同址**，重启后可能落到别处。
【推】这与有状态本地磁盘根本冲突——本地盘必须易失，持久态只能外置到 R2。

**它真正的差异化是网络**（值得 Cats 学）：Outbound Workers、`outboundByHost` glob 白名单、
`defaultEgress:'block'`、**凭据注入（sandbox 永不见明文）**、HTTPS 需每 sandbox 临时 CA 做 TLS 拦截。

隔离：官方只说 "run each sandbox in its own VM"，新闻稿说 "full Linux-based microVMs"，
**Firecracker/gVisor/自研均【未公开】**。⚠️ 需区分同新闻稿的 "V8 Isolate-based sandboxes"
是 **Dynamic Workers**，不是 Sandboxes。

客户含 **Figma（Figma Make）、Anthropic Claude Managed Agents、Cognition Devin**。
定价：需 Workers Paid $5/月；active-CPU 计费；超出 $0.000020/vCPU-s（=$0.072/vCPU-h）。
HN 45610523 算下来 "Memory: $6.48 per GB / vCPU: $51.84 per vCPU"，比 GCP 贵 ~2.5x。

### 3.5 Modal 与 Daytona

**Modal**：默认 **gVisor（runsc + nvproxy）共享宿主内核**；另有 VM Sandboxes（beta，有真 Linux 内核，
但**不支持 GPU、内存快照、Volume reload**）。冷启动中位 **<500ms**、**100 万并发 <60 秒**。
上限 **24 小时硬顶**。tunnel URL **加密随机、每次新建就换**。**Sandbox 层无 wake-on-request**。
Sandbox 计费是 Function 的 **3 倍**（$0.142/核-h + $0.024/GiB-h），
且"运行中但空闲的 Sandbox 照样全额计费"。

**关键事实**：**Modal 上「内存态 fork」不可用**——Filesystem/Directory Snapshot 可 branch 成多个
Sandbox，但 **Memory Snapshot 严格一对一且 alpha**。

商业上 Modal 是本赛道最健康的：**$355M C 轮 @ $4.65B（2026-05）、ARR >$300M、
Sandboxes 占营收超三分之一**。这是"沙箱能撑起独立生意"最硬的数据点。
客户含 Cognition、Ramp、**Lovable**、**Meta**。

**Daytona**：2025-04 从 CDE 转型为纯 agent 沙箱基础设施。默认 Container class =
**Docker + Sysbox 硬化，跑裸金属 + 自研调度器（不是 K8s、不是 Firecracker、不是 gVisor）**，
但**内核与宿主共享**。冷启动官方 **"<90ms"**。

Daytona 有两条 Cats 应该注意的能力：
- **四态生命周期**：Started / **Stopped**（盘保留、只计磁盘费）/ **Archived**（盘搬对象存储、
  **完全不计费**）/ Deleted。这是全场对成本曲线最友好的设计。
- **VM class 的 fork 是 CoW 克隆，同时复制文件系统 + 内存状态**，且记录 fork 谱系树
  —— **全场唯一对外交付的"含内存 fork"**（但仍标 experimental）。

Daytona 的致命项：**资源天花板仅 4 vCPU / 8 GB / 10 GB disk**；
**2026-06-11 官宣闭源**，`daytonaio/daytona`（72.2k★）README 写
"This repository is no longer maintained"，main 分支已清空，许可是 **AGPL-3.0**（不是 Apache-2.0）
→ **自托管现实上不可行**。E2B 立刻借势营销"唯一严肃的开源沙箱"。

客户含 **LangChain（Open SWE）、SambaNova、Turing、Writer、AfterQuery（用它替换了 GKE）**。

**Modal 与 Daytona 共同缺失 wake-on-request**（Sprites / E2B / Fly / Runloop 都有）。

### 3.6 Fly Machines / Morph / Runloop

| | Fly Machines | Morph | Runloop |
|---|---|---|---|
| 隔离 | Firecracker + KVM，独立 Guest 内核 | 自研 **MorphVM + MorphFS**（分布式 CoW），是否基于 Firecracker【未公开】 | micro-VM + 容器双层，是否 Firecracker【未公开】 |
| suspend | resume "a few hundred ms"，但**硬限内存 ≤2GB**，禁 swap/GPU；换 host / 重新 deploy / 宿主维护会**静默退回冷启动** | 快照**同时保留内存与磁盘含所有运行进程**，**<250ms**；暂停只计存储 | **"Only disk state, not in-memory state is preserved"** |
| 持久盘 | **Volume 是"同一台物理服务器上 NVMe 的一个切片"，单区单机、不可跨 host/区迁移**；无内置复制；社区有硬件故障导致卷消失的实证帖 | 快照持久 | snapshot **仅磁盘** |
| 时长 | stopped/suspended 无过期 | TTL 可配，上限【未公开】 | **默认 1h、最长 48h** |
| 入站 | Anycast + fly-proxy，autostop/autostart 三档 wake-on-request；自定义域 + TLS | `https://*.morphcloud.io`，URL 跨 stop/start 稳定性【未公开】 | tunnel **只存活到 devbox shutdown**；`wake_on_http` 约 1s |
| 定价 | performance-1x/2GB $32.19/月；**stopped 与 suspended 同价：仅存储**；卷 $0.15/GB-月 | **MCU = 1 vCPU-h + 4GB RAM-h + 16GB disk-h；$0.05/MCU** | CPU **$0.108/CPU-h** + 内存 $0.0252/GB-h；**Pro $250/月才含 suspend/resume** |

**Morph 是全场唯一宣称"<250ms 且含内存+进程的 snapshot/branch/restore"的产品**，
但架构与运营透明度最低（Guest/文件系统/URL 稳定性/暂停上限全无公开资料，融资仅 $5.75M 种子轮）。

### 3.7 不外售的自建者 —— Cats 真正的技术对标

这几家把 Cats 的目标形态（或其中的关键部分）做出来了，但都不对外卖。
**它们的公开技术资料是 Cats 最好的参照系。**

**Perplexity SPACE**（最重要的新变量，架构与 Cats 高度重合）：
- **Firecracker + btrfs CoW**
- create 中位 185ms→**60ms**、P90 447ms→**89ms**
- **两类快照**：高频 disk snapshot（可到每分钟级，**不暂停 VM**）+ 低频全机 checkpoint
  **上传对象存储**，**任意节点都能把沙箱拉回来（跨主机恢复）**
- session 可 pause / resume / **branch**；归档最长约 1 周
- 已 100% 支撑 Perplexity Computer，**>125 万次沙箱创建**
- Sandbox API **私测中**

**Cognition / Devin**：官方称"自研 microVM，用了一年多 hypervisor 工程"，每 session 独立内核；
**hypervisor 级全机快照（内存、进程树、文件系统）**，空闲关算力，
**CI 结果或 review 评论到来时原地恢复**——专门为异步等待设计。编排层"三个多季度"投入。
runtime 不单独售，但 **Devin Outposts 同时跑在 E2B 与 Daytona 上**。

**Cursor**：完全自建。官方文档："Cursor manages VM provisioning, isolation, **snapshots**,
startup, artifacts, and capacity for every Cloud Agent"。

**★ kvcache-ai / AgentENV**（本节唯一**完全开源**的自建样本，MIT，Rust；
自述 "powering agentic RL training for **Kimi K3**"）：
- **Firecracker + ublk，绕开 vhost-user**：overlaybd 分层镜像由一个独立的用户态
  `uvm-ublk-daemon` 进程服务，经 Linux ublk 驱动暴露成 `/dev/ublkbN`
  （`storage/ublk/src/dev.rs:383`），再以普通 `path_on_host` 走 Firecracker 标准 Drive API
  `PUT /drives/{id}`（`src/sandbox/firecracker/instance.rs:315-331`；实际传入的是
  Firecracker 工作目录下指向该设备的符号链接）。
- **因此原生快照照常工作**：`SnapshotType::Diff`（`instance.rs:441`）；
  恢复时把快照内存做成**只读 ublk 设备**当 file-backed memory backend 交给 Firecracker
  （`instance.rs:517`、`src/sandbox/firecracker/sandbox.rs:1437-1466`），
  多个同源沙箱共享同一设备以复用页缓存。
- **本文原先断言"Firecracker 系结构上只能在自定义块后端与 VM 快照之间二选一"，
  这个反例把它证伪了**：两者在同一套系统里同时成立。真正的代价是数据通路更长——
  Firecracker 与 ublk daemon 两个用户态进程，外加一次完整的宿主内核块层往返（§1.2 第 2 条）。
- 另有 E2B 兼容 HTTP API（把 `E2B_API_URL` 指过去即可直接用官方 SDK）。不外售。

**这告诉 Cats 三件事**：(1) 目标形态技术上可行且已被多家独立验证；
(2) **有能力自建的头部客户都会自建**——Cats 的可服务市场不包括 Cursor / Cognition /
Perplexity / kvcache-ai 这一层，AgentENV 更是把整套自建实现连同 E2B 兼容层一起开源，
是 §10.3「客户自建等效成本才是定价天花板」最硬的一个公开样本；
(3) **"Firecracker 做不到 X"这类能力缺失论断要格外小心**——本文原先就在这里判断错了一次。

### 3.8 长尾要点

- **Together Code Sandbox**（原 CodeSandbox，2024-12 被 Together AI 收购）：Firecracker + 内存快照，
  **快照恢复 500ms P95、fork <1s**，内置 `https://[id]-[port].csb.app`
- **Freestyle**：KVM 全 Linux VM，**支持嵌套虚拟化与真 root、每负载独立内核**；
  **<600ms 开机、live fork 毫秒级且不暂停源 VM、唤醒 <100ms**；
  **Persistent VM 冻结内存只付存储**（官方例：Redis 闲置 30 天数据仍在）。$0.04032/vCPU-h
- **Blaxel**：Firecracker，15s 空闲进 standby，**恢复宣称 <25ms**，高配额档可无限期 standby
- **Northflank**：**可选 Kata + Cloud Hypervisor / Firecracker / gVisor**；
  持久卷 **4GB-64TB、ReadWriteMany**；sandbox 即 service 有公共 DNS；**$0.01667/vCPU-h（全场最低）**
- **CreateOS**：~30ms P90，独立 guest kernel，**eBPF 在内核外强制出网策略**；
  定价与 E2B 逐位相同（$0.0504 + $0.0162）
- **AWS AgentCore**：一 session 一 Firecracker，**用完不复用**，最长 8h，**无休眠/快照/持久卷/公网入站**
- **★ AWS Lambda MicroVMs（2026-06-22 上线）**：Firecracker、VM 级隔离、最长 8 小时、
  **支持挂起保留内存+磁盘并恢复** —— 这是本赛道最重要的一次"上游吞噬"
- **Azure Container Apps dynamic sessions**（GA）：每 session 独立 **Hyper-V** 边界，
  预热池分配 **<100ms P90**；但 session 冷却即销毁、无快照、无持久卷、**无常驻公网 URL**
- **GKE Agent Sandbox**：gVisor（也支持 Kata），宣称 **300 sandbox/s、<1s**，
  **支持 Pod snapshot 做暂停/恢复 + 持久卷**
- **Anthropic Claude Managed Agents**（beta）：显式 **"stateful by design"**，
  持久文件系统 + volumes / 目录快照 / 文件系统快照 / 内存快照；
  支持 **self-hosted sandbox**（worker 出站长轮询取活，Anthropic 不入客户网络）；
  代价是**不支持 ZDR 与 HIPAA BAA**
- **kubernetes-sigs/agent-sandbox**（Apache-2.0，3.3k★）：CRD，可配 gVisor/Kata，
  **PVC 持久化 + 稳定 hostname**；**"deep hibernation" + 自动 resume 仍在 roadmap** ← 这一格官方也认为空着

---

## 4. 关键能力总表

以「长期存在的持久 microVM」这个需求为尺子。✅ 满足 / 🟡 部分 / ❌ 不满足 / ❓ 未公开。

| 产品 | 隔离 | 无时长上限 | 停机保盘 | 内存级唤醒 <1s | 跨主机迁移 | 常驻公网 URL | 按请求唤醒 | 可自托管 |
|---|---|---|---|---|---|---|---|---|
| **Cats（目标）** | CH microVM，独立内核 + 未修改 ext4 + 真 root | ✅ 设计无上限 | ✅ S3 durable truth | ✅ Suspended 0.213s / Warm 0.382s | ✅ 已测空缓存跨节点冷恢复 | ✅ `*.cats.run` 绑 Cat 名 | ✅ ADR-0010 | ✅ Rust workspace + Terraform |
| **Fly Sprites** | FC + inner container | ✅ 无期限 | ✅ 对象存储 | 🟡 Warm 100-500ms，**数周后必是 Cold 1-2s** | ✅ "state is simply a URL" | ✅ `*.sprites.app` | ✅ | ❌ |
| **E2B** | FC，独立内核 | ❌ Pro 24h（靠 pause 重置） | ✅ 快照含 fs+mem | 🟡 官方"约 1 秒"，无 p95 | ❓ 技术指向可行但从未明说 | 🟡 ID 稳定 | ✅ auto-resume | 🟡 infra 开源但需 Nomad/Consul |
| **Vercel Sandbox** | FC，独立内核 | ❌ 24h⚠️（文档矛盾） | ✅ ≤32GB | ❌ **仅磁盘，进程须 onResume 重启** | ❓ | ❌ 稳定性未声明 | ❌ 仅 SDK 触发 | ❌ |
| **Cloudflare Sandboxes** | microVM❓ | 🟡 无时限但宿主"不定期重启" | ❌ **磁盘易失，sleep 即清空** | ❌ 冷启 1-3s | 🟡 但与有状态盘冲突 | 🟡 需自带 wildcard 域名 | ✅ | ❌ |
| **Modal** | gVisor（VM 类 beta） | ❌ 24h 硬顶 | 🟡 须显式快照或挂 Volume | 🟡 Memory Snapshot experimental + 7 天上限 + 一对一 | ❓ | ❌ **URL 随机每次换** | ❌ | ❌ |
| **Daytona** | Docker+Sysbox（VM 类 exp） | 🟡 auto-stop=0 可无限，但 4vCPU/8GB 顶 | ✅ Stopped/Archived | 🟡 VM "under a second" 但 experimental | ❓ | 🟡 hostname 稳定需 signed token | ❌ | ❌ **2026-06 闭源** |
| **Fly Machines** | FC，独立内核 | ✅ 无过期 | ✅ Volume | 🟡 **仅 ≤2GB 且不保证** | ❌ **Volume 单机 NVMe 切片** | ✅ Anycast + 自定义域 | ✅ | ❌ |
| **Morph** | 自研 MorphVM | ❓ | ✅ | ✅ **<250ms 含内存+进程** | ❓ 存算分离暗示可行 | ❓ | ❓ | ❌ |
| **Runloop** | micro-VM + 容器 | ❌ **48h 硬顶** | 🟡 snapshot 在但 devbox 销毁 | ❌ **纯磁盘** | 🟡 | ❌ tunnel 随 shutdown 消失 | ✅ wake_on_http | ❌ |
| **Northflank** | Kata+CH/FC/gVisor 可选 | ✅ | ✅ **卷 4GB-64TB RWX** | ❓ 恢复延迟未公开 | ❓ | ✅ 公共 DNS | 🟡 scale-to-zero | 🟡 |
| **Freestyle** | KVM，独立内核 + 真 root | ✅ Persistent VM | ✅ 冻结内存只付存储 | ✅ **<100ms** | ❓ | ❓ 机制未说明 | ❓ | ❌ |
| **Perplexity SPACE** | FC + btrfs CoW | 🟡 归档约 1 周 | ✅ 对象存储 | ✅ | ✅ **任意节点可拉回** | ❓ | ❓ | ❌ **不外售** |
| **腾讯 AGSX** | "VM 级隔离" | ❌ 24h | ✅ 暂停停算力、盘续费 | ❓ | ❓ | ❌ 仅 SDK/CLI 端口转发 | ❓ | 🟡 底座 CubeSandbox 开源 |
| **PPIO** | FC【三】 | ❌ **3600s 硬顶** | ✅ 暂停保内存+盘、不计费、无限期 | ✅ 恢复约 1s | ❓ | ✅ `*.sandbox.ppio.cn` | ✅ auto_resume | ❌ |
| **阿里 ACS Agent Sandbox** | MicroVM | ❓ 上限未公开 | ❌ 只有 OSS PV，**checkpoint 后挂载不能恢复** | 🟡 内存态唤醒 1-10s | ❓ | ❌ | ❓ | ❌ |
| **火山 veFaaS 云沙箱** | "容器"❓ | ❌ **24h 硬顶** | 🟡 pause 保 fs 快照，**内存/进程不保** | ❌ | ❓ | 🟡 泛域名邀测 | ❓ | ❌ |
| **百度 AX** | "独立 VM" | ❌ **TTL 300s 超时即删** | ❌ **40GB 明写临时盘** | ❌ **SDK 无 pause/resume/snapshot** | ❓ | ❌ 临时地址+强制 token 头 | ❌ | ❌ |

**读这张表的方式**：Cats 目标形态是全表唯一八项全绿的。但**"目标"三个字必须保留**——
§8.2 列出 Cats 的实现差距，其中 Cold 性能与 vhost-user-blk 是硬缺口。

---

## 5. 独立持久卷 —— 持久性这一项里最容易被忽略的分水岭

### 5.1 差异不在"有没有"，而在"卷是什么"

上表的"停机保盘"只回答了"这个实例的盘还在不在"。
还有一个独立的问题：**有没有一块生命周期独立于实例、可挂卸、可跨实例复用的卷。**
这两件事经常被混为一谈，但对 agent 工作负载是完全不同的能力。

| 产品 | 独立卷原语 | 形态 | 多写 |
|---|---|---|---|
| **Cats PersistentDisk** | **✅ 已实现** —— `cats disk create/ls/get/resize/snapshot/delete` + `cats mount <disk> <cat>` / `cats unmount`；`DiskState::Available` = "No active attachment; persistent disks can be mounted from here"；计费按 provisioned GiB-month，**是否挂载不影响** | **真 virtio-blk 块设备 + 未修改 ext4 + fencing epoch**；Guest 按 filesystem UUID 挂载 | **RWO**（ADR/架构文档明确"绝不提供 RWX ext4"） |
| **Fly Sprites** | **❌ 不存在** —— 全站文档 "volume" 0 次；REST v1 无 volume/disk/mount/attach 端点；CLI 无对应子命令（`sprite attach` 是重连 TTY）；Go SDK 无 `volume.go`；release notes 与 blog 无 roadmap。官方："deleting a Sprite deletes its checkpoints too"、"persists for the Sprite's lifetime" | 盘 = sprite 的一部分（100GB ext4，对象存储做 truth）；**无可独立寻址的卷对象，因此也无 RWO/RWX 概念** | — |
| Modal Volumes | ✅ GA | 真文件系统，~2.5 GB/s；**v1 硬顶 50 万 inode、官方建议 <5 万文件**、约 5 并发提交；v2 beta 取消文件数上限 | 可**并发多挂**，last-write-wins |
| Modal CloudBucketMount | ✅ | S3/R2/GCS，**不能 append / seek+write / rename** | — |
| Daytona Volumes | ✅ 免费，每组织 ≤100 个 | **FUSE 挂 S3 兼容对象存储**；官方承认比本地盘慢、**非事务**、last-write-wins；支持 subpath 多租户隔离 | 可**多沙箱同时挂载**，且沙箱删除后仍存在 |
| Vercel Drives | ⚠️ 私有 beta，免费 | 可跨 sandbox 复用，≤4 个/sandbox，默认 100GiB 可配至 1TiB | **官方原文 "single reader, single writer"**，且官方建议"**仅用于缓存等非关键用途**" |
| E2B Volumes | ⚠️ **private beta，需邮件申请** | 独立生命周期、可挂多 sandbox | 多挂 |
| Northflank | ✅ | 卷 **4GB–64TB** | **ReadWriteMany**，可并挂 Postgres/Redis |
| Fly Machines Volumes | ✅ | **真块设备**，但是"同一台物理服务器上 NVMe 的一个切片"、**不可跨 host/区迁移**、无内置复制 | 1 机 ↔ 1 卷严格单写 |
| Cloudflare Sandboxes | ❌ | 只有 R2 **目录级** backup（TTL 默认 3 天）+ FUSE `mountBucket`（官方警告"不要期待原生 SSD 性能"） | — |
| 火山 veFaaS 云沙箱 | ❌ | **API 里根本没有 disk/volume 参数**，只能挂 TOS/NAS | — |
| 阿里 ACS Agent Sandbox | ❌ | 只有 OSS PV，且 **checkpoint 快照后不支持恢复存储挂载** | — |
| 百度 AX | ❌ | 40GB **明写临时盘**，超时即删；持久盘只存在于预留实例侧 | — |

**三条结论，必须一起读**：

1. **对最直接竞品是干净的能力缺口。** Sprites 的 durable state 与 sprite 身份强绑定（sprite 名即卷名），
   跨 sprite 复用状态的唯一通道是 admin 台的 fork（复制存储桶，非挂载）或 Filesystem API / SSHFS 手动拷。
   这不是"官方明说不做"，是**文档完全未提及**——说明它根本不在产品模型里。
2. **对整个市场，差异不在"有卷"而在"卷是真块设备"。**
   Daytona Volumes、Modal CloudBucketMount、Cloudflare `mountBucket` 都是 **FUSE 挂对象存储**，
   POSIX 语义是降级的——**没有原子 rename、非事务、last-write-wins**。
   这意味着 **git、SQLite、node_modules 这三类最常见的 agent 工作负载在上面行为不正确或很慢**。
   Cats 的不变量"Guest 看到标准 virtio block device 和未修改 ext4"在这里直接变成产品优势。
   Modal Volumes 是这一格里最强的竞品（真文件系统 + 并发多挂），
   但 v1 的 50 万 inode 硬顶与"建议 <5 万文件"对 node_modules / 大仓场景是实质约束。
3. **"真块设备"+"跨主机可迁移"这个组合才是唯一的。**
   Fly Machines Volumes 也是真块设备，但绑死单机 NVMe 切片、不可跨 host 迁移，
   社区有硬件故障导致卷消失的实证帖；Cats 的 PersistentDisk 以对象存储为底座、跨节点可恢复。
   **单看任一项都有人做到，两项同时成立的目前只有 Cats。**

**同时必须诚实标出的弱项**：**Cats V1 是 RWO，Modal / Daytona / Northflank 都能多挂。**
"多个 agent 共享一份数据集 / 模型权重 / 依赖缓存"这个场景 Cats V1 打不了——
而它在 RL rollout 与 fan-out eval 里是真实需求（Runloop 的匿名案例即"同时部署数千 devbox"）。
架构文档把 RWX 列为"绝不提供"，理由是存储协议、锁、一致性与故障恢复的复杂度；
这个取舍本身是清楚的，但竞品对比里不能省略。

---

## 6. 定价：标价、计量基准与实际账单

### 6.1 归一化标价（USD，按 vCPU-hour / GiB-hour）

> ⚠️ **这张表只是标价，不是可比成本。** 各家的计量基准不同（预留 vs 实测 vs
> max(预留,实际) vs 捆绑单位 vs session-hour），且部分产品另收请求费。
> **先读 §6.2 再用这张表做任何结论。**

| 产品 | vCPU-h | 内存 GiB-h | 备注 |
|---|---|---|---|
| Northflank | **$0.01667** | — | 全场最低 |
| E2B | $0.0504 | $0.0162 | 事实标准锚点 |
| CreateOS | $0.0504 | $0.0162 | 与 E2B 逐位相同 |
| Daytona | $0.0504【三】 | $0.0162【三】 | 官方页 JS 渲染未核实 |
| Modal Sandbox | ~$0.071 | $0.024 | 是其 Function 价的 3 倍 |
| **Fly Sprites** | **$0.07** | **$0.04375** | + 热存储 $0.50/GB-月、冷存储 $0.02/GB-月 |
| **Cats（当前 rate card）** | **$0.07** | **$0.045** | **CPU 与 Sprites 相同，内存略高；存储费率未填** |
| Cloudflare | $0.072 | ~$0.009 | + Workers Paid $5/月 |
| AWS AgentCore | $0.0895 | $0.00945 | I/O wait 与 idle 不计费 |
| Runloop | $0.108 | $0.0252 | Pro $250/月才含 suspend |
| Vercel | **$0.128**（active CPU） | $0.0212（**provisioned 全时长**） | 内存空闲也计费 |

人民币侧（换算，仅供国内对比）：

| 产品 | CPU 元/核·h | 内存 元/GiB·h |
|---|---|---|
| Sealos（K8s 容器） | ¥0.027671 | ¥0.013956 |
| PPIO | ¥0.108 | ¥0.054 |
| 华为 CCI（反解） | ¥0.1764 | ¥0.022068 |
| 火山 veFaaS 云沙箱 | ¥0.1458 | ¥0.03672 |
| 腾讯 AGSX | ¥0.2916 | ¥0.09 |
| 阿里 ACS Agent Sandbox | ¥0.078 | ¥0.039 |

### 6.2 计量基准：为什么 §6.1 的单价其实不可直接比

⚠️ **§6.1 的表格有一个隐含假设：所有产品的"一个 vCPU-hour"是同一个东西。这个假设是错的。**
同样标价 $0.05/vCPU-h，按**预留规格 × 墙钟时长**计费和按**实测消耗**计费，
对同一个负载可以差出两三倍。这一节把基准拆开。

| 产品 | CPU 计量基准 | 内存计量基准 | 请求/调用费 | 休眠态怎么收 |
|---|---|---|---|---|
| **Cats** | **实测**：cgroup `cpu.stat` 累计微秒（带计数器重置检测） | **实测**：cgroup `memory.current` 左连续阶梯积分 | **无** | Warm 专属 RSS = 0；storage.hot/cold 费率待定 |
| **Fly Sprites** | CPU-hour，按秒计量按小时计费 | GB-hour | **无** | 零 compute + 冷存储 $0.02/GB-月 |
| E2B | **预留** vCPU 档（1/2/4/6/8）× 运行秒 | **预留** GiB × 运行秒 | 无 | 暂停无 TTL；**存储费官方未公开** |
| Vercel Sandbox | **Active CPU**（I/O 等待不计） | **预留 × 全时长**——官方原文 "billed for the full time it runs, **even while idle**" | **有：Creations $0.60/1M** | 快照存储 $0.08/GB-月 |
| Cloudflare Containers | **Active CPU**（只算真实 CPU 周期） | GiB-s | **有：Workers 请求另计**，并叠加 DO / R2 / Logs | 磁盘易失，无休眠态 |
| Modal Sandbox | **max(预留, 实际)**，按秒 | 同左 | 无 | **运行中但空闲照收全额** |
| Daytona | **预留全量**（Started） | 同左 | 无 | Stopped 只收磁盘；**Archived 完全不计费** |
| Runloop | 预留 CPU-hr | 预留 GB-hr | 无 | 挂起不计算力、仍计存储 |
| Fly Machines | 预留档位按秒 | 含在档位内 | 无 | stopped/suspended 仅存储 |
| Morph | **MCU 捆绑单位**（1 vCPU-hr + 4GB RAM-hr + 16GB disk-hr = 1 MCU，$0.05） | 同左 | 无 | pause 只计存储、不消耗 MCU |
| AWS AgentCore | 按秒，**I/O wait 与 idle 不计费** | GB-h | 无 | 无休眠态 |
| Azure dynamic sessions | **$0.03 / session-hour**（整会话计时） | 含 | 无 | 冷却即销毁 |
| Anthropic 容器 | **$0.05 / container-hour** | 含 | 无（与 web search/fetch 同用时**全免**） | 闲置约 5 分钟 checkpoint |
| 阿里 FC | **活跃 vCPU 1.0 CU/s；闲置 vCPU 0 CU** | 0.15 CU/(GB·s) | **有：0.0075 CU/万次** | 浅/深休眠 |
| 火山 veFaaS | 按秒 ¥0.0000405/vCPU | ¥0.0000102/GiB/s | **明确"不收调用次数费"** | pause 停计费 |
| 腾讯 AGSX | 按秒 ¥0.000081/核 | ¥0.000025/GiB/s | 无 | 暂停停 CPU/内存，**系统盘继续计费** |
| PPIO | 按秒 ¥0.00003/核 | ¥0.000015/GiB/s | 无 | **暂停完全不计费** |
| 百度 CFC | GB-秒 | 含 | **有：1.3 元/百万次** | — |
| 华为 FunctionGraph | GB-秒 + 闲置模式 GB-秒 | 含 | **有：1.33 元/100 万次** | 闲置模式 |
| Sealos | **预留** ¥0.027671/核/小时 | ¥0.013956/GiB/h | 无，但**端口 ¥0.0139/个/小时** | 暂停不计费 |

**四条结构性观察**：

1. **Cats 是唯一把内存也按实测计费的。** 其余全部按预留规格（Vercel 甚至官方明写空闲也照收），
   或按捆绑单位（Morph 的 MCU）。这意味着一个配了 4 GiB 但常驻集只有 1 GiB 的 Cat，
   在 Cats 上按 1 GiB 计费，在别处按 4 GiB 计费。
2. **按请求/调用计费的全是 FaaS 血统**：Vercel（Creations）、Cloudflare（Workers 请求）、
   阿里 FC、百度 CFC、华为 FunctionGraph。这套模型对"一台长期存在、偶尔被访问的机器"是逆向的——
   请求越稀疏、每请求成本越高。**Cats 与 Sprites 都不收请求费**，与"长驻机器"的产品语义一致。
3. **休眠态的收费方式把市场劈成两半**：一边是零 compute + 极低冷存储（Sprites、PPIO、
   Daytona Archived、Freestyle、Blaxel），一边是运行中空闲照收全额（Modal、Vercel 的内存那一条）。
   这正是 §10.4 那条结论的机制——**按内存墙钟计费与休眠语义天然对立**。
4. **Active-CPU 计费不等于便宜。** Vercel 的 CPU 标价是 E2B 的 2.5 倍，
   但因为它只收活跃 CPU，**在低利用率下反而更便宜**（见下面的交叉点计算）。
   反过来在满载时它贵一倍。单看标价会得出完全相反的结论。

**交叉点计算**（2 vCPU / 4 GiB 配置，运行 1 小时，u = CPU 利用率）：

| 产品 | 计费式 | u=10% | u=32% | u=100% |
|---|---|---:|---:|---:|
| E2B（全预留） | 2×0.0504 + 4×0.0162 = 恒定 | **$0.1656** | $0.1656 | $0.1656 |
| Vercel（active CPU + 预留内存） | 0.256u + 0.0848 | **$0.1104** | $0.1656 | **$0.3408** |
| **Cats（全实测，常驻集 1 GiB）** | 0.14u + 0.045 | **$0.0590** | $0.0898 | $0.1850 |

- **u ≈ 32% 是 Vercel 与 E2B 的交叉点**：低于此 Vercel 更便宜，高于此 E2B 更便宜。
- **Cats 在低利用率 + 小常驻集下显著最便宜**（u=10% 时比 E2B 低 65%、比 Vercel 低 48%），
  尽管它的**标价是三者中最高的**。只有到满载才略高于 E2B。
- 这个形状**正好匹配 Cats 的目标负载**（长驻、低利用率、偶发唤醒），
  也正好不匹配持续满载的计算型负载。

（以上为本文按各家公开单价的计算；Cats 一行假设常驻集 1 GiB，
实际账单取决于 Guest 的真实 `memory.current`。）

### 6.3 Cats 的定价问题

**问题一：不是"价太高"，是"标价与计量基准脱节"。**
Cats 抄了 Sprites 的标价，而 Sprites 在标价维度是全场最贵：
第三方（Northflank）算过 200-sandbox 场景 **Sprites $35,770 vs E2B $16,819 vs Northflank $7,200**。
但那个估算隐含了"按预留规格跑满"的口径。
**Cats 与 Sprites 的计量基准不同**——Cats 两个维度都按 cgroup 实测（§6.2），
所以对"长驻 + 低利用率 + 小常驻集"这个目标负载，Cats 的实际账单是三者中最低的。

真正的问题有两个，都不是"降价"能解决的：
1. **对外传播会被按标价误判。** 客户看到 $0.07 vs E2B $0.0504 就会得出错误结论，
   而"我们按实测计费"这件事目前**没有出现在任何对外材料里**。
2. **按实测计费天然让账单不可预测**——而需求侧最响的抱怨恰好就是
   "我花了多少钱、我的实例为什么没暂停"（Sprites 首发帖）。
   **实测计费把成本可观测性从"加分项"变成了"必需项"。**

**问题二：存储费率是空的。** `metering/src/lib.rs` 里 `RateCard::sprites_compute_v1()` 只定义了
`CpuUsec` 和 `MemoryByteMillis` 两个费率；`storage.hot.v1` / `storage.cold.v1` /
`network.egress.v1` 三个 metric 已在 `metric_from_slug` 注册但**没有对应 rate**。
而"停机后盘还在"正是 Cats 的核心卖点——**这部分收入模型现在是缺的**。
Sprites 的两级结构（热 ~$0.50/GB-月，仅活跃时计；冷 ~$0.02/GB-月，始终计）是现成答案，
且它是被社区抱怨逼出来的正确设计。

**问题三：全行业的降价通道已经打开，但不是同行价格战。** 四条同时发生：
① 计费口径从"墙钟时间"转向"活跃 CPU / 休眠免费"；
② 免费额度膨胀（Anthropic **1,550 h/月**、Daytona $200、Modal $30/月、E2B $100 一次性）；
③ **模型厂把代码执行捆绑到零**——Anthropic 的容器 $0.05/h 且与 web search/fetch 同用时**完全免费**；
④ **AWS Lambda MicroVMs 2026-06 入场**。
**没有任何厂商公开宣布降价**，头部名义单价甚至高度锚定一致（E2B = Daytona = CreateOS）。
这是被上游捆绑挤压的降价。

**需求侧对价格的态度是激烈的。** HN 48907562（2026-07-14）标题就是
*"Was sick of sandbox priced 50x what the CPU is worth so I made my own 5x cheaper"*，
评论原话："they were adding like a **50x markup** on what qemu/docker + bare metal prices would be"。
另有 cortex.io 工程文（2026-07-23）把成本模型从 `cost ∝ 申请的资源` 改写为
**`cost ∝ 基线 + 脏页`**，把 18 个保留会话压到只按 6 个活跃计费。
**后者对 Cats 极其重要**——Cats 的 ChunkStore 只提交 dirty logical chunk，
天然支持"按脏页计费"这个模型，这是可以做成差异化定价卖点的。

---

## 7. 国内格局

### 7.1 一个必须更新的旧判断

**"国内普遍是云端 IDE 或 FaaS 改造，而非 microVM 基础设施"——这个判断在 2024 年成立，2026 年已经不成立。**
国内已分化成三层：

**第一层：明牌 microVM 且已商品化**
- 腾讯 **CubeSandbox**（Apache-2.0，10.7k★）：RustVMM+KVM，独立 Guest OS 内核，
  冷启 <60ms，50 并发均值 67ms/P95 90ms/P99 137ms，单实例额外内存 <5MB，
  **百毫秒级快照与回滚**（CubeCoW 用内核 FICLONE + XFS reflink + 脏页追踪），
  **空闲自动快照挂起→百毫秒唤醒**
- 腾讯 **AGSX**（2026-07-14 正式商业化）
- 阿里云 **ACS**：产品页原话"基于 MicroVM 沙箱技术…硬件级别的计算安全隔离环境"
- **PPIO**：Firecracker【三】
- 华为 **AgentArts 智能体运行时**："基于安全沙箱技术实现 mircoVm 隔离"（原文含拼写错误）

**第二层：语义含糊的"虚机级隔离"（刻意避免点名技术）**
百度 AX、百度 CFC、华为 CCI、腾讯 TKE 超级节点。
唯一点名 Kata 的是腾讯 TKE 安全容器（kata-clh/kata-qemu），
但前置极硬（BMS5 裸金属 + TencentOS 4 + K8s≥1.30）且**Container 级监控与 CLS 日志采集当前不可用**
→ 点名了也没法当通用沙箱用。

**第三层：云端 IDE / FaaS 改造，上一代且在衰退**
腾讯 Cloud Studio（**按"标签页开着"计费，不按负载**）、
华为 CodeArts IDE Online（**20GB 盘上限、4 实例、《最新动态》停在 2023-02**）、
腾讯 SCF（《工作原理》**通篇不出现"隔离"**）、
华为 FunctionGraph（隔离 FAQ 全文只有一句"运行在其自己的环境中"）、
百度 CFC（**300 秒 + 内存最高 1024MB + 仅 /tmp**）。

**最有说服力的一条证据**：华为**技术上有** microVM（**StratoVirt**，Rust，openEuler 社区文档称
启动 50ms、内存底噪 <4MB），但它**从未出现在任何华为云用户侧产品文档里**；
而腾讯和阿里已把 microVM 写进商品页并按秒报价。
**差别不在有没有技术，而在有没有把它做成商品。**

### 7.2 国内大厂的共同结构缺陷

**强隔离和沙箱 API 被放在两个互不相通的产品里。**

- **火山引擎**：VCI 有自研 hypervisor + 每 Pod 独占轻量 VM + **独占 EBS 块存储**，
  但**没有休眠、没有沙箱 API、盘随 Pod 生命周期**；
  veFaaS 云沙箱有 API 和 pause/resume，但**根本没有 disk/volume 参数**，
  只能挂 TOS/NAS，且 **TTL 硬顶 24h**，pause 的文件系统快照**内存/进程不保留**。
- **阿里云**：ACS Agent Sandbox 有休眠 + Checkpoint/Restore，
  但**只有 OSS PV，且 checkpoint 快照后不支持恢复存储挂载**。
  FC 的 E2B 兼容表把 **Snapshots / Volumes 直接列为"暂不兼容"**。
- **腾讯**：AGSX 暂停保盘，但**无 Snapshot API、无文档化稳定入站 URL、仅广州一个地域**。
- **华为**：AgentArts 运行时明文 **"沙箱空闲触发弹性伸缩时，本地磁盘数据全部丢失"**；
  CCI **完全无休眠**；ModelArts Notebook 停机保 `/home/ma-user/work`（EVS）但不是 API-first。
- **百度**：AX **40GB 明写临时盘、TTL 300s 超时即删、SDK 无 pause/resume/snapshot**。

**「强隔离 + 持久块设备 + 可休眠 + 长期存在」这个组合在国内大厂那里拼不出来**，
不是不想做，是产品线切分导致的。

### 7.3 国内独立玩家

**PPIO 派欧云**——国内唯一真正对标 E2B 的独立创业公司。团队来自 PPTV。
WAIC 2025 发布"国内首款兼容 E2B 接口的 Agent 沙箱"。
休眠是它文档化最清楚的一块：暂停保存**文件系统 + 内存状态**，
**暂停耗时约 4 秒/GB、恢复约 1 秒、暂停期间不计费、无限期保留直到 kill()**，
支持 `autoPause`/`auto_resume`。**有文档化的稳定入站 URL** `https://{端口}-{沙箱id}-{hash}.sandbox.ppio.cn`。
**但系统限制单沙箱最长运行 3600 秒（1 小时）**——它是"沙箱"，不是持久开发环境。

**Sealos**（labring/sealos，18.3k★）——方向对但许可证自锁。
持久化机制很特别：Pod 关闭时自研 containerd-shim 把 **emptyDir + overlayFS 合并 commit 成新镜像**，
重启时把镜像换成上次 commit 的，"保留用户所有改动，**像使用传统虚拟机一样**"——
**不是 PVC，而是镜像 commit**，且**没有运行态（内存）快照**。
自动分配 HTTPS 域名。价格极低（CPU ¥0.027671/核·h）。
**但许可证是 Sustainable Use License v1.0，原文禁止
"Use it to provide any form of cloud services—including public, private, or managed services—
to third parties, whether free or paid"** → 想基于它创业直接被堵死。

用户曾提到的 ScaleKit / 幂简 / 算了吧：中英文检索**均未找到任何 AI 沙箱业务的公开资料**，
按"未证实"处理。

### 7.4 E2B 协议已是国内事实标准

**阿里云（FC + ACS + PAI 三处）、火山引擎（邀测）、腾讯 AGSX、百度 AX、PPIO 全部做了 E2B 兼容层**，
且都是"改一个环境变量"：
`E2B_DOMAIN=ap-guangzhou.tencentags.com` / `sandbox-execute.gz.baidubce.com` / `sandbox.ppio.cn`。

这有两面：
- **正面**：Cats 提供 E2B 兼容端点，迁入摩擦几乎归零，且能被大厂的兼容层"验证"这套接口是对的。
- **负面**：**迁入成本 = 迁出成本 = 一个环境变量。无锁定 = 无留存。**

**唯一可防守的护城河是有状态资产**——持久卷、长命环境、快照历史、
以及稳定域名下已被外部系统引用的 URL（webhook、OAuth 回调、协作链接）。
这恰好就是市场上唯一空着的位置。**Cats 能防守的东西，和唯一空着的位置，是同一个东西。**
反过来说：**如果 Cats 做成纯 ephemeral 沙箱 API，必然沦为价格战炮灰。**

### 7.5 国内特有障碍

**1. 备案是"稳定公网 URL"真正的成本，而且是责任成本不是技术成本。**
三家的入站 URL 全部跑在**自己已备案的主域名**下做泛子域。独立团队必须：
(a) 持有已完成 ICP 备案的主域名并做泛子域证书；
(b) **承担用户在你的域名下发布任意内容的连带审查责任**——
一个用户的沙箱 preview 页面出问题，被处置的是你的主域名和备案主体，**波及全部客户**。

**大厂宁愿牺牲产品体验也要避开这个敞口**：腾讯 AGSX **干脆不提供文档化的公网入站 URL，
只给 CLI 本地端口转发**；百度 AX 的 `get_host()` **强制要求 `X-Access-Token` 头**；
华为全线只给 `公网IP:端口`。**这不是它们没想到，是它们算过账。**
（各家文档对备案要求均**未提及**，需自行向通管局与云商核实。）

**2. 免费额度抹平前 100 小时的付费意愿。**
腾讯 Cloud Studio 赠 50 机时 + 每日打卡 2 机时（1c2G = 0.1 机时/小时 → **50 机时 = 500 小时的 1c2G**）；
华为 AgentArts 限时免费 + 100 CU + 200 万 MaaS token；
FunctionGraph 每月 100 万次 + 40 万 GB-秒；PPIO 送 20GB 本地 + 60GB 持久存储。

**3. 牌照。** 对外提供 IDC/云服务属**第一类增值电信业务（B11）**，
省级通管局受理、工信部核准（二手中文资料整理，**建议以工信部原文核实**）。
不拿牌只能做大厂转售商，成本地板 = 大厂内部价。

**4. 数据出境把市场切成两半。** 目标客户若是国内 agent 公司，服务器必须在境内 →
吃不到海外 GPU/带宽价差；若同时做海外 = 两套合规主体 + 两套控制面 + 两套镜像分发。
这也是国内玩家（PPIO 的 `.cn` 域名、腾讯只开广州一个地域）都没覆盖海外的原因。

---

## 8. Cats 的优势、差距与风险

### 8.1 结构性优势（架构差异，不是参数）

| # | 优势 | 依据 | 对手情况 |
|---|---|---|---|
| 1 | **四态生命周期**：Warm = snapshot + VMM/backend exit，**专属 RSS = 0 且进程状态保留**，唤醒 0.382s | ADR-0002；实验报告 §3 | Sprites 三态，从内存冻结直接跳到内存丢弃；**没有"零驻留 + 保进程"这一层** |
| 2 | **Guest 是真未修改 Linux + 真 root + 标准 ext4 + 独立内核** | ADR-0001 不可协商约束 | Sprites 塞了 inner container；Cloudflare 无 root 只收 OCI；Daytona 默认档共享内核；Modal 默认 gVisor（syscall 缺陷自家承认） |
| 3 | **fencing / lease 正确性显式建模并有崩溃注入测试**：4 个提交窗口 kill -9 恢复、stale epoch 拒绝、空缓存跨节点冷恢复 | README 实现状态；`blockd/` | **没有任何竞品公开过等价的正确性证据**。E2B #884 就是 resume 后文件丢失 |
| 4 | **显式工作租约驱动的自动休眠**，而非 idle timeout 猜测 | `cats-auto-tier-*.md`；ADR-0007 | Sprites ~30s idle；Daytona auto-stop 15min；Vercel/Modal 靠 timeout。**没人做租约仲裁** |
| 5 | **可自托管**（Rust workspace + Ports and Adapters + Terraform） | ADR-0005、ADR-0012 | Sprites 承诺未交付；Daytona 2026-06 闭源；Modal/Vercel/Cloudflare 全无 |
| 6 | **按脏页计费的天然基础**（只提交 dirty logical chunk） | ADR-0003；实验：100GiB/10 万文件 → 仅 521 个 1MiB chunk、475MiB 对象数据 | 业界刚开始讨论 `cost ∝ 基线 + 脏页`（cortex.io 2026-07-23），Cats 的引擎天生支持 |
| 7 | **跨节点恢复是架构原生** | 已测空缓存跨节点冷恢复 | Fly Machines 的 Volume 是单机 NVMe 切片；Sprites 单区域 |
| 8 | **VMM 选型让自定义块后端走最短数据通路**（⚠️ 未实测，见下） | Cloud Hypervisor 原生 vhost-user-blk + 快照/恢复，虚拟队列在共享 Guest 内存里由 `cats-blockd` 直接解码，CH 不在数据通路上；v53.0 已有 postcopy+UFFD、自动推进 guest clock | **Firecracker 的 vhost-user-blk 自 v1.6.0 起是 developer preview、禁止生产、且不支持快照**【官】，但 Firecracker 系可用 **ublk** 绕开并保住原生快照（AgentENV 已公开做到，§3.7）→ 这**不是能力缺口，只是延迟代价**：ublk 路径多一个用户态进程 + 一次宿主内核块层往返。⚠️ **无同机对照实测，属结构推演**（§1.2 第 2 条）。gVisor 路线（Modal）更进一步：**不能 mount ext4 等块设备文件系统**【官】 |
| 9 | **难点排序上占住了最贵的两格** | `blockd/` 的 lease/fencing epoch + stale epoch fail-closed + 4 个提交窗口 kill -9 崩溃注入 + 空缓存跨节点冷恢复 | 跨 host 恢复正确性与单写保护是自建者唯一真正做不好的两件事（§10.1）；**无任何竞品公开过等价的正确性证据** |
| 10 | **★ PersistentDisk：生命周期独立于 Cat 的真块设备** | `cats disk` + `cats mount/unmount` 已实现；`DiskKind::Persistent`、`DiskState::Available`、`bound_cat_id`；计费按 provisioned GiB-month 且是否挂载不影响 | **Sprites 完全没有这个原语**（§5.1）；市场上多数"卷"是 FUSE 挂对象存储、POSIX 语义降级；Fly Machines 的卷是真块设备但绑死单机。**"真块设备 + 跨主机可迁移"两项同时成立的目前只有 Cats** |

### 8.2 工程差距（诚实清单）

| # | 差距 | 现状 | 对标 |
|---|---|---|---|
| 1 | **空缓存跨节点恢复路径未产品化** | ⚠️ 注意区分两条路径：**优化 Cold = 1.755 s**（i4i Local NVMe，新内核新进程，5 轮 P50）**已与 Sprites 持平**；**Direct-S3 原型 = 39.868 s**（S3、无初始 Cache、串行 Python，S3 GET 累计 18.91 s）是**另一个测量边界**，官方标注为"仅验证语义"。缺口是**两者尚未合并**——生产 Rust blockd + 本地热 cache 的组合数字不存在 | Sprites 的 Cold 1-2s **同样是热本地 cache 口径**（sparse 100GB NVMe 做 dm-cache-like read-through），**它从未公开空缓存跨节点恢复的等价数字**。Perplexity SPACE create P90 89ms（btrfs CoW + 高频 disk snapshot） |
| 2 | **原生 vhost-user-blk 已实现但不是默认** | ADR-0015 已落地（`blockd/src/vhost_user.rs`），与内核 NBD 通过同一套 i4i.metal 真机验收。默认仍留 kernel-nbd，原因是实测的写吞吐权衡（CH 带缓冲打开 `/dev/nbdN`，宿主 page cache 吸收合并了写），翻转条件写在 ADR-0015。所以差距不是"没有"，而是**生产默认还没吃到 QD1 延迟收益**（9–10 µs vs 32 µs） | ⚠️ Firecracker 系竞品虽然用不了 vhost-user-blk，但可用 **ublk** 拿到同等能力（§8.1 第 8 条、§3.7），只是数据通路更长。所以这主要是 Cats 相对自己的性能债，相对对手则是一个**尚未测量**的延迟差 |
| 3 | **跨 Node Guest overlay 未实现** | per-Cat `/30` tap 与 owning-node HTTP 入站已实现 | — |
| 4 | **无 fork/branch** | 未实现 | Sprites 也没公开（仅内部 admin ~90s）；**Daytona VM class 是唯一对外交付含内存 fork**；Morph 宣称 <250ms |
| 5 | **无预装镜像生态** | — | Sprites 预装 Node/Python/Go/Rust/Claude/Gemini/Codex 开箱即用 |
| 6 | **无 template / pool 原语** | — | 全行业共同空白（Sprites 也被批 10+ 分钟 bootstrap） |
| 7 | **存储与出流量费率未定价** | metric 已注册，rate 为空 | Sprites 热/冷两级是现成答案 |
| 8 | **零品牌、零客户、零生态集成** | — | Sprites 有 MCP server / VS Code / Cursor / Claude Managed Agents |
| 9 | **正式计费未验收** | provisional 全链路已通，但故障注入、S3 replay reconciliation、连续 shadow billing、invoice close、迟到 adjustment 未做 | — |
| 10 | **PersistentDisk 只有 RWO，不做 RWX** | ADR/架构文档列为"绝不提供 RWX ext4"，理由是存储协议、锁、一致性与故障恢复的复杂度 | **Modal Volumes / Daytona Volumes / Northflank 都能多挂。**"多个 agent 共享一份数据集 / 模型权重 / 依赖缓存"这个场景 Cats V1 打不了，而它在 RL rollout 与 fan-out eval 里是真实需求（Runloop 匿名案例即"同时部署数千 devbox"） |

### 8.3 战略风险

**风险一：技术壁垒被开源清零。** CubeSandbox（Apache-2.0，RustVMM+KVM，<60ms，
百毫秒快照 + 空闲自动挂起 + CubeCoW，附腾讯云 Terraform 一键部署）+
OpenSandbox（阿里云智能团队，Apache-2.0，12.2k★，**可选 Docker/gVisor/Kata/Firecracker/K8s**）
合计约 23k★。**Cats 的差异化不能建在"我们也能做 microVM 休眠"上。**

**风险二：上游吞噬。** AWS Lambda MicroVMs（2026-06-22）已经是
Firecracker + VM 级隔离 + 最长 8h + **挂起保留内存和磁盘并恢复**。
云厂商把这一层做成基础原语，中间层的溢价空间会持续收窄。

**风险三：需求是留客特性而非独立品类。**
"持久化"被厂商用产品行为集体确认了（Vercel **"Persistence is the default"**、
E2B 暂停无限期、Daytona Pause&Fork、Anthropic 显式 "stateful by design"、Freestyle 休眠免费），
但**几乎找不到"为持久化单独付费"的公开客户案例**。

**风险四：目标客户里最有钱的那批会自建。**
Cursor、Cognition、Perplexity 全部自建。可服务市场不包括这一层。
Lovable 买 Modal、Manus 买 E2B、Devin Outposts 买 E2B + Daytona ——
**买的是"别让我自己扛 2 万并发"，不是"给我持久化"。**

**风险五：分发。** 已验证的死路是**直接发帖卖"更便宜/更持久"**：
box.ascii.dev（HN 5 分）、Superserve（9 分）、CobaltCode（2 分）全部无声。

---

## 9. 需求侧证据

### 9.1 谁自建、谁采购

| 采购方 | 买了谁 |
|---|---|
| **Manus** | E2B（联创张涛：Docker 起容器 10-20s 太慢，"it uses 27 different tools, and it needs E2B to have a full virtual computer"） |
| **Lovable** | Modal（48 小时 25 万应用、**100 万+ sandbox、峰值 2 万并发**，代码从 15,000 行降到 700 行） |
| **Perplexity** | E2B（"shipped advanced data analysis in 1 week"）—— 同时自建 SPACE |
| **Devin Outposts** | E2B **和** Daytona 双供应商 |
| **LangChain Open SWE** | Daytona |
| **Figma Make / Anthropic Claude Managed Agents** | Cloudflare Sandboxes |
| **自建**：Cursor、Cognition（托管版）、Replit、StackBlitz/Bolt、v0、Anthropic、OpenAI | — |

### 9.2 痛点排序（按发言激烈程度）

1. **成本加价**（最激烈）。"50x markup on what qemu/docker + bare metal prices would be"（HN 48907562）
2. **会话被杀 / 状态丢失 / 24 小时天花板**。Superserve 开场第一句
   *"most sandbox providers kill your agent after 24 hours"*（HN 48999489）
3. **环境不可靠才是 agent 失败主因，不是模型**。
   *"Agents fail because the environment is flaky: missing deps, slow setup, weird state"*（HN 46699324），
   否则 agent 会 "burning $10 retrying a fail state"
4. **隔离不足**。E2B 员工：*"both Docker and bubblewrap are not secure sandboxes.
   the only way to have actually isolated sandboxes is by using VMs"*
5. **出口 IP 被封**。"their IPs are blocked by many platforms"
6. **必须开源与自托管**。*"Sandboxes need to be open source, nothing else is acceptable"*（HN 48037724）
7. **拥挤到麻木**。用户自己数出"过去一年 30-40 个沙箱方案"；2026 年 HN 上新沙箱产品约 16 个

### 9.3 持久化是真需求吗

**正面（用户侧）**：
- *"each one maps to a persistent sandbox, one per research goal… come back **a week later**…
  picks up where it left off"*（HN 47767067）
- *"agent can build up its workspace over time, **maintain state across sessions**"*（HN 46939693）
- simonw：要 *"snapshotting support so I can **roll back** to a known state"*

**正面（厂商用产品投票，最硬的证据）**：Vercel **"Persistence is the default"** +
`getOrCreate` + `onCreate/onResume` 钩子；E2B 暂停无限期；Daytona Pause&Fork；
Anthropic 自己做 checkpoint/restore 且显式 "stateful by design"；Freestyle 休眠免费；
Sprites 每台 100GB 对象存储支撑的持久盘。

**正面（客户案例）**：Anything（1M+ 用户）用 E2B Snapshots **直接恢复正在运行的 dev server**，
理由是自建需 2-3 名资深工程师数月。

**反面证据（必须正视）**：
- **成本反例**：Falconer《Ditching the agent sandbox for AWS S3 Files》（2026-05-27）——
  弃用沙箱盘改 S3 共享文件系统，理由是 **S3 $0.023/GB·月 vs EFS $0.30/GB·月，便宜 13 倍**
- **快照 ≠ 可追溯**：评 Sprites，*"I'll be really confused about why something doesn't work
  eventually and wish I had some tracking of what changed over time. **I want my IDE. I want VCS!**"*
- **回滚有边界**：*"You can't roll back everything an agent does.
  If you told it to place a trade… you cannot undo that"*
- **★ 持久化带来新的不可观测**：Sprites 首发帖（HN 46634450，169 分/106 评论）里
  panarky 报告 sprite **连续跑了 23 小时且看不到账单**；
  dtkav 直问 **"(1) 我花了多少钱 (2) 我的 sprite 为什么没暂停"**
- **安全侧**：长期存活、被不可信 agent 写过的环境难以再被信任
  （guardbase.io《Coding Agents Degrade Sandboxes to Security Theater》）

### 9.4 多天/多周 agent 有多真实

真实性上升但**尚未成为主流产品默认**：Anthropic 称 Claude Sonnet 4.5
"maintaining focus for **more than 30 hours**"；METR 测得前沿模型任务时长视界**约每 7 个月翻倍**。
但供给侧上限仍卡在 8-24 小时（AWS 8h、Vercel 24h、E2B 24h、Modal 24h）。
真正押注这个场景的都是小玩家。Superserve 帖下唯一提问：
**"How does it handle cron jobs or waking from a messaging app?"—— 无人回答。**
这正是 Cats 的 Endpoint + 按请求唤醒 + 工作租约应该回答的问题。

### 9.5 市场规模

**没有找到任何针对 "agent sandbox / code execution as a service" 的第三方规模测算。**
唯一可引用的分析师数据是 Gartner 对 CDE 的预测：
**到 2027 年受监管行业 40% 的组织将强制使用 CDE**、59% 计划淘汰本地开发机。
流通的"XX 亿美元"多为厂商营销，不予采信。

最硬的单点数据是 **Modal：ARR >$300M，Sandboxes 占营收超三分之一**（2026-05 C 轮 @ $4.65B）。
这证明沙箱能撑起独立生意，但也说明撑起它的是**规模化短任务**，不是持久化。

### 9.6 融资一览

| 公司 | 轮次 | 时间 | 领投 |
|---|---|---|---|
| Modal | C **$355M** @ **$4.65B** | 2026-05 | 未核实 |
| Daytona | A **$24M** | 2026-02-05 | FirstMark（+ Datadog、Figma Ventures 战投） |
| E2B | A **$21M**（累计 $32M） | 2025-07-28 | Insight Partners |
| Northflank | Seed $6.3M + A $16M | ~2024-11 | Bain Capital Ventures |
| Blaxel | Seed $7.3M（YC S25） | 2025 | First Round |
| Runloop | Seed $7M | 2025-07-30 | The General Partnership |
| Morph Labs | Seed **$5.75M** | 2024-09 | Khosla ⚠️ 检索到的 $175M 属 DeFi 的 Morpho Labs，非本公司 |
| Fly Sprites | **无独立融资**，Fly.io 自有产品线 | 2026-01 | — |

并购与整合：CodeSandbox → Together AI（2024-12）；Gitpod → Ona 更名（2025-09）；
Daytona 闭源（2026-06-11）；**AWS Lambda MicroVMs 上线（2026-06-22）**。

---

## 10. 自建 vs 买：成本边界与技术难点

这一节回答两个问题：**客户什么时候会自建（决定 Cats 的可服务市场）**，
以及**自建时哪些东西他们做不好（决定 Cats 该卖什么）**。

### 10.1 技术难点排序 —— VMM 是白送的，正确性才是壁垒

| # | 难点 | 难度 | 有现成方案吗 |
|---|---|---|---|
| **1** | **跨 host 恢复正确性** | **最难，且无人替你解决** | ❌ **必须自己写**。三家一致把快照绑死在硬件上：Firecracker "**必须在完全相同的软硬件上恢复**，跨 CPU 型号 / Intel↔AMD 不支持"；Cloud Hypervisor "快照不支持跨版本"；Modal "快照绑定 worker 类型（CPU flags/GPU）"。**熵、墙钟、TCP 三件事没有任何 VMM 提供答案**——FC 明文"**不保证恢复后网络连通**"、RNG 可区分性"尚不清楚"。必须自己写：CPU template 归一化、VMGenID 重播种、时钟注入、netns+veth+DNAT 网络重建、连接层重连语义 |
| **2** | **块存储引擎** | 次难，**但有最完整的公开图纸** | ⚠️ 半现成。**AWS Lambda 自己的论文（arXiv:2305.13162）**给了逐条处方（见 §10.2）且自证"非系统专家可做"。但 **FC 的 vhost-user-blk 不支持快照且禁止生产** → 载体必须换成 CH 或 ublk，**这是一个被低估的架构分叉点**。EBS 快速快照恢复每 Region 仅 5 个快照、$0.75/AZ/小时、每快照每 AZ 每小时最多约 10 个预热卷 → 证明**买不到** |
| **3** | **Fencing / 单写保护** | 不难，但错了会**静默数据损坏** | ⚠️ 处方业界统一（**单调递增 epoch + 下游资源强制校验；时间性租约只是活性检测**），但块后端必须自己实现 epoch 校验 |
| 4 | 网络入口 | 中 | ✅ 基本现成：FC 官方文档给了 netns+veth+iptables DNAT 完整方案 |
| 5 | VMM 集成 | **最容易** | ✅ 完全现成：Firecracker / Cloud Hypervisor 开箱，Kata 4.0.0（2026-07-20，Go→Rust 全量重写）更省事 |
| 6 | 计费 | 工程简单 | ✅ 但**它决定毛利**：Vercel 只计 active CPU 却按 wall-clock 计内存；Cloudflare/Modal idle 免费。**计费模型的选择比计费代码重要得多** |

**Fencing 的四家一致处方**（对 Cats 的 lease/epoch 设计是直接背书）：

| 来源 | 处方 |
|---|---|
| **Chubby §2.4** | 持锁进程可能发出请求后失败，请求迟到时"已无锁的保护"；sequencer 含 **lock generation number**，"接收方须检验其是否仍有效，**否则应拒绝该请求**" |
| **etcd 官方** | "**lease 机制本身不保证互斥**"；"**etcd 中的 fencing token 就是 revision number**"；"**etcd 自身的 lock 特性不能用于保护外部资源**" |
| **Kafka** | producer epoch 保证同 TransactionalId 只有一个合法实例；`InitPidRequest` **提升 epoch 以隔离僵尸实例**；leader epoch 是 32 位单调递增并随每个 record batch 落盘 |
| **★ S3 条件写** | `If-None-Match:*` / `If-Match:<ETag>`，"**最先完成的写成功**"，其余 **412** —— **这是对象级 CAS，免费，Cats 可直接用来强化 root/lease 提交** |
| **Fly.io（硬件独占派）** | "一个卷只能挂到一个 Machine"、"是同一物理服务器上 NVMe 的一个切片、**绑死在那台硬件上**"、"**这不是网络存储**"，无自动复制 |

对照 Cats 现状：`blockd/` 已实现 lease/fencing epoch + stale epoch fail-closed，
并有 4 个提交窗口 kill -9 崩溃注入与空缓存跨节点冷恢复测试。
**这正是难点 1 与难点 3，也正是没有任何竞品公开过等价证据的地方。**

### 10.2 AWS Lambda 论文：这条路线最好的公开图纸

`arXiv:2305.13162` 描述的正是"对象存储为真相 + 本地缓存"的生产系统，
与 Cats 的 Direct-S3 ChunkStore 同构。可直接借鉴的事实：

- **512 KiB 定长 chunk、三层缓存**
- 生产实测 **L1 命中中位 67% / L2 32% / L3（回源 S3）仅 0.06%**
- **L2 命中中位 550µs vs 回源 S3 中位 36ms**；p99.9 **3.7ms vs 175ms**
- 去重后 **80% 新函数零唯一 chunk、存储省 23×**
- **★ "最初用 FUSE 暴露给 virtio-blk 是错的"**（需 4 个线程被宿主调度、高负载抖动）
  → 正迁往 **userfaultfd + mmap**
- 明说这套系统由**"没有深度系统编程经验的团队"**建成并已运营**数年**

**对 Cats 最直接的两条**：
① Cats 走 `vhost-user-blk`（而非 FUSE）方向与论文的修正一致；
② **缺一层 AZ 级 L2 缓存**——这正是 Direct-S3 Cold 39.87s 的结构性原因之一：
S3 首字节 100–200ms，200 个 1 MiB GET 若不并发发出且无中间层，延迟无法收敛。

真·按 chunk 惰性拉取的其他公开实现可作对照：**Nydus**（1MB chunk，阿里 serverless 拉取 20s→0.8s）、
**overlaybd/DADI**（256KB block，6.43s vs 15.34s）、**AWS SOCI**（zTOC span，129s→60s）、
**REAP** ASPLOS'21（页级 record-and-prefetch，冷启 -3.7×）、**Catalyzer**（最好 <1ms）、
**turbopuffer**（冷 p50 874ms / 暖 p50 14ms）。

块设备后端选项：**SPDK vhost-user-blk** 同限 1 核 4K 随机读 QD64
**833.55k IOPS / 152.99µs** vs 内核 vhost-scsi 356.63k / 358.92µs = **2.34×**；
**ublk**（内核 6.0 起，含 `UBLK_F_USER_RECOVERY`，仍 experimental）的 ublk-qcow2 ≈ qemu-nbd 的 **2× IOPS**
——即 Cats 当前 Phase A 的内核 NBD 是三者中最慢的一档。

### 10.3 经济学：厂商毛利与自建盈亏平衡点

**裸金属基线**（us-east-1，除法为本文换算）：`c6id.32xlarge` 128 vCPU / 256 GiB / 1,900 GB 本地 NVMe，
按需 $6.4512/h（**$0.0504/vCPU-h**）、1yr 预留 $4.066/h（**$0.0318/vCPU-h**）。
取**基准槽位 = 2 vCPU + 4 GiB**（该机型正好 2 GiB/vCPU → 64 槽，每槽还分到 ≈29.7 GB 本地盘，
恰与 Vercel 的 32GB 临时盘同量级）：**按需 $0.1008/h、1yr 预留 $0.0635/h**。

| 厂商 | 每槽位·小时 | vs 自建 $0.0635 | 毛利（100% 装箱） | 毛利（50% 装箱） |
|---|---|---|---|---|
| **Vercel Sandbox** | **$0.3408** 满载 / **$0.0848** 纯 idle | **5.4×** | **81%** | 63% |
| **Modal Sandbox** | $0.2379 | 3.7× | 73% | 47% |
| Cloudflare Containers | $0.1800（idle 不计费） | 2.8× | 65% | 30% |
| **E2B** | $0.1656 | 2.6× | 62% | 23% |
| AWS Fargate（基准） | $0.0988 | 1.56× | 36% | — |
| Fly.io（推算） | ≈$0.089 | ≈1.4× | ≈29%※ | — |
| **Modal 标准（非 Sandbox）** | $0.0792 | 1.25× | 20% | — |

※Fly 跑自有硬件，实际成本远低于 AWS，真实毛利应显著更高。

**两个关键观察**：
① AWS 自家托管容器（Fargate）对裸金属的加价只有 **1.56×**，沙箱厂商是在这之上再加 **1.7–3.5×**；
② **Modal 标准算力 1.25× 而 Sandbox SKU 3.7×——3.0 倍溢价完全加在"沙箱"这个 SKU 上，
不在底层算力上。** 这解释了为什么 Sandboxes 能占 Modal 营收超三分之一。

**S3 侧成本**（10 GiB 盘、每天唤醒 5 次、每次读 200 MiB + 回写 200 MiB。
⚠️ AWS 官方价格表为 JS 渲染无法抓取，S3 单价取自 2026-07-17 二手源，EBS gp3 取自官方页示例值）：

| chunk 大小 | 存储 | GET | PUT | **合计/盘/月** | ×10,000 盘 |
|---|---|---|---|---|---|
| 1 MiB | $0.230 | $0.012 | $0.150 | **$0.392** | $3,920 |
| 4 MiB | $0.230 | $0.003 | $0.038 | **$0.271** | $2,705 |

四条结论：
1. **存储占 59–85%，读请求几乎免费（$0.012/月）**——"每次唤醒从 S3 拉 chunk"的请求成本可忽略。
   Cats 不必为 GET 次数做架构妥协。
2. **贵的是写路径**：PUT 单价是 GET 的 **12.5×**。chunk 大小主要在**回写侧**起作用，
   1 MiB → 4 MiB 使请求费降 **75%**。Cats 当前用 1 MiB 逻辑 chunk（`api/src/chunk.rs`），
   **值得评估回写侧的 pack 聚合粒度**（注意这不等于改逻辑 chunk 大小，`blockd` 协议是 Frozen v1）。
3. 对比 gp3：10 GiB × $0.08 = **$0.80/盘/月**，S3 方案是它的 **34–49%**。
4. **★ 同区 S3→EC2 免费是这套架构的前提。** 若跨区/出网，每盘 30 GB/月 × $0.09 = **$2.70/月**，
   是同区总成本的 **6.9×**，10,000 盘仅出网就 **$27,000/月，经济上直接判死**。
   → **多区域部署必须保证 chunk 读写不跨区**，这是 Cats 做多区时的硬约束。

**自建盈亏平衡点**（以 E2B $0.1656/h vs 自建 1yr 预留 $0.0635/h，每沙箱小时省 $0.1021）：
覆盖 3 名基础设施工程师（$90 万/年）需 **≈882 万沙箱小时/年 ≈ 1,007 个常驻沙箱（7×24）**；
若装箱率只有 50%，需 **≈2,660 个**。
参照工期：**Vercel >2 年**（Fluid 基础设施）、**Fly.io 单项 drain 功能 ≈1 年**、
**Modal 全公司 7 人**（2022-12）、**Fly.io 上线存储时 10 人** →
自建最小可行投入约 **2–4 人 × 1–2 年**，且要吃掉难点 1 的正确性风险。

### 10.4 这一节对 Cats 的三条含义

1. **可服务市场的上界很清楚**：年用量低于约 100 万 vCPU-小时、或负载尖峰不可预测的客户会买；
   常驻规模超过约 1,000 沙箱且有内核/存储能力的客户会自建
   （Cursor、Cognition、Perplexity 已证实）。
2. **"长驻可休眠"这一段结构性属于自建方**，因为厂商的内存 wall-clock 计费与休眠语义对立。
   Cats 若想把这段留在托管侧，**必须让休眠态真的接近零成本**——
   即把成本压到 S3 那一档（$0.27–0.39/盘/月）而不是内存 wall-clock 那一档（$61/月）。
   Cats 的 Warm 态（专属 RSS = 0）是唯一能做到这点的架构。
3. **能卖上价的只有难点 1 和难点 3。** 跨 host 恢复正确性与单写保护是客户自建时唯一做不好的两件事，
   也是 Cats 已有测试证据的两件事。**这应该是对外叙事的第一句话，而不是"我们也有 microVM 休眠"。**

---

## 11. 建议

### 11.1 技术优先级

1. **先合并测量「优化启动路径 + 生产 Rust blockd + 本地热 cache」这个生产组合。**
   这是当前最重要的一个缺失数字，而不是继续优化 39.868 s 的 Python 原型。
   1.755 s 的优化 Cold 是在 **i4i Local NVMe** 上测的，没走 Direct-S3；
   39.868 s 是在 **S3、无初始 Cache** 上测的，用的是串行 Python。
   **真实生产路径两者都不是**——它是优化后的启动路径 + `cats-blockd` + 部分热的本地 cache。
   在拿到这个数字之前，"Cats 的 Cold 有多快"这个问题对外无法回答，
   而**热路径口径下 1.755 s 已经与 Sprites 的 1-2 s 持平**。
2. **把空缓存跨节点恢复作为独立指标建设，并当成卖点而非短板。**
   Sprites 的 Cold 1-2 s 同样是热本地 cache 口径（sparse 100GB NVMe 做 dm-cache-like read-through），
   **它从未公开空缓存跨节点恢复的数字**；Cats 反而是把这个更难的边界测了并诚实标注的一方。
   要把它做快，Lambda 论文给了结构性处方：**加一层节点/AZ 级共享 L2 chunk 缓存**——
   论文生产数据是 L2 命中中位 **550µs** vs 回源 S3 中位 **36ms**（p99.9 3.7ms vs 175ms），
   L3 回源率仅 **0.06%**。S3 首字节 100–200ms 是物理下限，
   **不加中间层的话并发再高也难收敛**。
   参考上界：Perplexity SPACE create P90 89ms（btrfs CoW + 高频 disk snapshot + 对象存储 checkpoint）。
3. **补 native vhost-user-blk。** 当前内核 NBD 正确性等价但性能不足，且它是 Warm restore
   与 blockd 设备状态对齐的前置（ADR-0002 待验证事项第一条）。
   量化收益参考：SPDK vhost-user-blk 同限 1 核 4K 随机读 QD64 达 **833.55k IOPS / 152.99µs**，
   是内核 vhost-scsi 的 **2.34×**；ublk-qcow2 约为 qemu-nbd 的 **2× IOPS**
   ——**内核 NBD 是三者中最慢的一档**。
4. **把 Warm 层做成对外叙事；块通路那条先补测再讲。**
   「零 VMM 驻留 + 保进程状态 + 0.382s 唤醒」是 Sprites 结构上做不到的，**且已有实测**。
   块通路那条要降级表述：Firecracker 系可以用 ublk 绕开 vhost-user 禁令并保住原生快照
   （AgentENV 已公开做到，§1.2 第 2 条、§3.7），Cats 剩下的是**少一个用户态进程、
   少一次宿主内核块层往返**这个延迟差。
   ⚠️ **这个差目前没有任何同机对照数据**，对外讲之前必须先补测
   （同机、同后端、统一驱动等待方式的 QD1 4 KiB fio 对照）。
   两条目前都只写在 ADR 与内部文档里，**没有任何对外表达**。
5. **评估 Cloud Hypervisor v53.0（2026-07-12）的升级收益。**
   新增 **offload snapshot daemon、postcopy + UFFD 按需分页、自动推进 guest clock、mTLS 迁移**
   ——其中"自动推进 guest clock"直接对应跨 host 恢复的墙钟难题（难点 1 的一个子项），
   postcopy + UFFD 则与 Warm restore 的 on-demand 恢复路径重合。
   注意 CH 快照**不支持跨版本**，升级需配合 ADR-0002 第 6 条的 VMM 版本 pin 策略。
6. **用 S3 条件写强化 root/lease 提交。** `If-None-Match:*` / `If-Match:<ETag>` 提供免费的
   对象级 CAS（"最先完成的写成功"，其余 412）。
   Cats 当前依赖 PostgreSQL 的原子 CAS 做 root/lease，
   **在对象存储侧再加一道条件写可以让 fencing 不完全依赖元数据库可用性**。
7. **考虑 fork/branch。** 全行业空白（Sprites 内部 admin ~90s、Modal 内存态不可用、
   Runloop 纯磁盘、只有 Daytona VM class 与 Morph 对外交付）。
   Cats 的 chunk 级不可变 + 内容寻址天然适合 CoW fork。
8. **评估回写侧 pack 聚合粒度。** PUT 单价是 GET 的 12.5×，
   回写聚合从 1 MiB 到 4 MiB 可使请求费降 **75%**（§10.3）。
   注意这是**回写侧的 pack 聚合**，不是改逻辑 chunk 大小——
   `blockd` 协议是 Frozen v1，逻辑 chunk 常量在 `api/src/chunk.rs`，改动需新增 ADR。

### 11.2 产品与定价

1. **★ 先把"按实测计费"讲出来，再考虑要不要降价。**
   Cats 是市场上唯一把 CPU 与内存都按 cgroup 实测计费的（§6.2）——
   一个配了 4 GiB 但常驻集 1 GiB 的 Cat 按 1 GiB 计费，别处按 4 GiB。
   这条现在**完全没有出现在对外材料里**，而它把"标价比 E2B 贵 39%/170%"
   反转成"目标负载下实际便宜 65%"。
   优先级：**先做一个把计量基准讲清楚的对比计算器，其次才是调费率**。
   如果要调，内存费率的下调空间最大（当前是 E2B 标价的 2.7 倍，
   虽然基准不同、实际账单更低，但标价差距太扎眼）。
2. **填上存储两级费率**：热（仅活跃时计）+ 冷（始终计）。Sprites 被社区逼出来的设计直接抄。
3. **把"按脏页计费"做成明牌卖点。** Cats 的引擎天生支持 `cost ∝ 基线 + 脏页`，
   这是对"50x markup"这个最激烈痛点的直接回答，也是竞品架构上难以跟进的。
4. **做成本与休眠的可观测性——对 Cats 这不是加分项而是必需项。**
   这是需求侧证据最强的空白（Sprites 首发帖最响的抱怨就是
   "我花了多少钱、我的 sprite 为什么没暂停"），
   而且**因为 Cats 按实测计费，账单天生比按预留计费更难预测**——
   别人的客户能自己乘一乘估出账单，Cats 的客户不能。
   好在 Cats 已有 1 秒 cgroup 采样 + 10 秒 checkpoint 的全链路，
   **把它做成用户可见的实时成本与状态解释，既补上必需项，又顺手拿到市场最空的那一格**。
5. **提供 E2B 兼容端点。** 迁移摩擦归零，且大厂已经替这套接口做了验证。
   在兼容层之下给出 E2B 给不了的：真持久块设备、无时长上限、独立内核、可自托管。
6. **把「>24h 长任务 + cron/webhook/消息唤醒」作为主叙事**，而不是"更便宜的沙箱"。
   前者有明确的未被回答的需求（Superserve 帖下无人回答的那个问题），后者是价格战炮灰。
7. **★ 把 PersistentDisk 提到叙事第一层。** 目前它在 README 里只是一句
   "可选一块跨 Cat 持久化的 RWO PersistentDisk"，但它是**最容易讲清、最容易验证、
   且最直接竞品完全没有**的能力（§5.1）。可直接对标的场景：
   换基础镜像 / 换 Cat 规格时数据留在原地不动（Sprites 官方做法是销毁重建 + SSHFS 手动拷）；
   把依赖缓存或数据集从一个 Cat 卸下挂到另一个；
   Cat 删了盘还在。配合"真块设备而非 FUSE 对象挂载"这条，
   **git / SQLite / node_modules 的正确性**是可以做成对比演示的。
8. **评估 RWX 的取舍是否需要重开。** V1 明确不做是清楚的决定，
   但 RL rollout 与 fan-out eval 的"多 agent 共享只读数据集"是真实需求，
   且**只读多挂（RO-many）在正确性上远比 RWX ext4 便宜**——
   不需要分布式锁，只需要保证挂载期间快照不变。
   如果要做，应作为新 ADR，而不是悄悄放宽 ADR 的单写不变量。

### 11.3 分发

已验证可复制的路径是 **E2B 模式**：
开源 runtime 建立可信度 → 成为某个已有流量的 agent 框架/平台的官方 provider
（OpenAI Agents SDK、LangChain 这类入口）→ 死盯一个头部不愿做的垂直痛点 →
用一个具名规模客户把案例写成规模叙事。

三条辅证：
- E2B 创始人在 2024-04 到 05 连发 5 次 Show HN，口径统一为"开源 SDK / code interpreter"，
  自称只做 "boring code execution layer"
- Modal 靠单一旗舰客户（Lovable）的规模叙事起势：**一个扛过峰值的旗舰客户 > 一百个小客户**
- 几乎所有集成方都把沙箱当**可插拔后端之一**（TanStack 同时发 Vercel 和 Daytona 适配器；
  Conductor CEO：*"Being agnostic to the providers is the key"*）
  → 被适配的门槛不高，但也没有粘性

**Cats 的自托管能力是相对 Sprites/Daytona/Modal/Vercel 全部缺失的一项**，
而"沙箱必须开源"在社区是有明确立场的（HN 48037724）。
Daytona 2026-06 闭源后 E2B 立刻借势营销"唯一严肃的开源沙箱"——这个位置还有空间。

---

## 12. 需要继续跟踪的信号

| 信号 | 为什么重要 | 当前状态 |
|---|---|---|
| **Fly Sprites 是否进入维护档** | 唯一同象限对外产品 | release notes 停在 2026-04-30，SDK 仓库 7 月仍在提交 |
| **Perplexity SPACE Sandbox API 是否公开售卖** | 四项齐全且架构与 Cats 最像 | 私测中 |
| **Cloudflare 原生全盘 snapshot 是否落地** | 会把 Cloudflare 从"磁盘易失"移进快照休眠派 | GA 时称"coming weeks"，至今未确认普遍可用 |
| **AWS Lambda MicroVMs 是否加持久卷与更长时长** | 上游吞噬的下一步 | 当前 8h 上限 |
| **E2B Volumes 何时 GA** | 会补上 E2B 唯一的持久化缺口 | private beta，需邮件申请 |
| **Daytona VM class / fork 何时 GA** | 目前唯一对外交付的含内存 fork | experimental |
| **腾讯 CubeSandbox 是否推出托管商业版** | 会把国内价格锚再压低 | 仅开源，无托管版与定价 |
| **kubernetes-sigs/agent-sandbox 的 deep hibernation** | K8s 官方进入第四派 | roadmap，v0.x |
| **Vercel 24h vs 5h 的真实上限** | 官方文档自相矛盾 | 需实测 |
| **国内备案对"每沙箱一个公网 URL"的实际口径** | Cats 国内落地的最大不确定项 | 各家文档均未提及，需向通管局与云商核实 |
| **Firecracker diff 快照是否转正** | 若转正 + vhost-user-blk 解禁，Firecracker 系连 ublk 绕道都不用走，Cats 仅剩的那点数据通路优势（§8.1 第 8 条）会被彻底抹平 | diff 快照仍 developer preview；vhost-user-blk 仍禁止生产且不支持快照。注意**绕道现在就存在**：ublk 路径已被 AgentENV 公开验证（§3.7） |
| **Cloud Hypervisor 的快照跨版本兼容** | 决定 Warm 态能否跨 Node 升级存活（现在必须先降 Cold） | v53.0 仍"不支持跨版本" |
| **Kata 4.0.0（Go→Rust 全量重写）的冷启动数字** | 若 Kata + CH 组合能给出接近数字，会降低自建门槛 | 2026-07-20 发布，冷启动数字未公开 |

---

## 13. 本文的证据边界

- **Cats 的性能数字全部来自 AWS metal 实验口径，不是生产 SLA。** 且**测量介质各不相同，不可互相替换**：
  Suspended **0.213 s**、Warm **0.382 s**、优化 Cold **1.755 s** 三项均为 **i4i Local NVMe**；
  Warm on EBS 是 **1.090 s**；Direct-S3 原型 Cold **39.868 s** 是 **S3、无初始 Cache、串行 Python**。
  全部为小样本 P50（优化 Cold 为 5 轮，其余 3–10 轮）；样本数较小时表中 P95 实际等于观测最大值。
  **本文任何跨产品的 Cold 对比都必须先对齐"数据介质"这一列**，否则就是拿空缓存对比热缓存。
  测量边界、正确性判据（Warm 要求 `boot_id_preserved=true`，Cold 要求 `boot_id_changed=true`）
  与环境限制见[实验总报告](experiments-2026-07-21-storage-lifecycle.md) §2、§3、§12。
- **竞品的休眠/唤醒数字多为厂商自报，测量边界不可比。** 少数有第三方实测的已标注【三】。
  同一 harness 的横向对比只有 ComputeSDK 一处（Vercel vs Daytona），且两者隔离等级不同。
- **★ Cats 的块通路优势（§1.2 第 2 条、§8.1 第 8 条）是结构推演，不是测量结论。**
  vhost-user 与 Firecracker 系走的 ublk 绕道之间**没有任何同机对照数据**；
  本文只能确认通路上的进程数与内核块层往返次数不同，无法给出延迟差的量值。
  引用的 25 µs → 9 µs（poll → spin）来自无 KVM 开发机上的 harness，
  实验报告自己标注为**伪影**，只能用作"一次用户态线程唤醒是十几微秒量级"的量级参考。
  **补测方案：同机、同后端、统一驱动等待方式的 QD1 4 KiB fio 对照。**
- **本文的定价换算已逐处标注。** 华为 CCI 单价为从官方计费样例反解；
  Daytona 与 Sprites 的部分单价来自第三方，官方页 JS 渲染未能一手核实。
- **§10.3 的 S3 成本计算有两处降级**：AWS 官方 S3 与 EBS 价格表为 JS 渲染无法抓取，
  S3 单价采用 2026-07-17 的二手源（CloudZero），EBS gp3 采用 AWS 官方页示例值。
  所有除法与场景成本为本文基于这些单价的计算，过程已在表中展示。
  裸金属单价来自 Vantage / economize；**Hetzner / OVH 官网价格未渲染，未取到**。
- **§10.3 的自建盈亏平衡点是单点估算**，假设 3 名基础设施工程师 × $30 万/人/年。
  该假设未经外部验证，换成不同人力成本会显著改变结论；应作为量级参考而非精确门槛。
- **检索覆盖不完整的部分**：Reddit 与 X/Twitter 在本轮多数 agent 中不可访问；
  扣子空间、TRAE Work 云端、OpenAI Codex 云端基础设施因登录墙或 403 未取到公开资料；
  火山引擎与腾讯云的部分 SPA 文档依赖渲染代理读取。
- **国内牌照与备案的结论基于二手中文资料整理，未经工信部原文核实。**
  这是本文可靠性最弱的一节，落地前必须独立核实。

相关文档：[Sprite 存储路径参考](sprite-storage-flow.md)（本文 §3.1 证实了其中的结构性推断）、
[Direct-S3 ChunkStore 详细设计](direct-s3-chunkstore-architecture.md)、
[睡眠、唤醒与资源回收](cats-sleep-wake-vmm-resource-reclamation.md)、
[工作驱动快速休眠](cats-auto-tier-product-and-implementation-design.md)。
