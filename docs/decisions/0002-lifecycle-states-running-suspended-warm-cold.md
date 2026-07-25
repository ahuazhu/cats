# ADR-0002：生命周期四态：Running / Suspended / Warm / Cold

- 状态：Accepted
- 日期：2026-07-21

## 背景

2026-07-21 实验验证了三种可用的休眠/恢复机制（数据见[实验总报告](../experiments-2026-07-21-storage-lifecycle.md)，均为单 Host 机制数据，非生产 SLA）：

- pause + page-out：唤醒 P50 0.212–0.231 s，暂停态 cgroup 物理内存 P50 6.9–17.3 MiB，VMM 保留。
- snapshot + VMM/backend exit：本地 NVMe 唤醒 P50 0.380–0.399 s，无常驻进程，进程状态保留。
- 优化 Cold：新内核、新进程 P50 1.755 s。

既有文档命名不一致：实验报告使用 `ACTIVE / WARM_PAGEOUT / WARM_SNAPSHOT / COLD`，架构文档使用 `Running / Suspended / Cold`，睡眠文档曾把 snapshot 层排除出 V1（称为未来的 Hibernate），而 ADR-0001 第 7 条又保留三个层次。本 ADR 统一命名并确定产品状态模型。

## 决定

1. 产品生命周期状态统一为 **Running / Suspended / Warm / Cold**（另有 Failed / Deleted，含义不变）：
   - **Suspended** = pause + page-out（即实验报告的 WARM_PAGEOUT）。VMM、KVM fd、设备后端、tap、Attachment lease 全部保留；Guest RAM page-out 到本 Host 的 file-backed backing；唤醒 = resume + demand refault。
   - **Warm** = snapshot + VMM/backend exit（即实验报告的 WARM_SNAPSHOT）。Guest 进程状态保存在本地 NVMe 的 VM snapshot 中；无常驻 VMM/后端进程（专属 runtime RSS = 0）；唤醒 = 重建 tap/blockd + 新 VMM userfaultfd on-demand restore + resume。
   - **Cold** = 无任何本地依赖，仅剩远端磁盘与控制面记录；任意 Host fresh boot。
2. 旧文档中的“浅层 Warm / 深层 Warm”不再使用；“Hibernate”仅指未来的跨 Host 快照恢复能力。
3. Suspended 与 Warm 都绑定原 Host（backing 与快照均在本地 NVMe），都不是跨 Host 持久状态；Host 永久丢失时两者一律按 Cold Recovery 处理。
4. 自动分层默认沿 Running → Suspended → Warm → Cold 单向降级；唤醒总是回到 Running。允许策略跳级（如直接 Running → Cold），不允许 Cold 向 Warm/Suspended“回填”。
5. 进入 Suspended/Warm 之前必须确认磁盘 durable generation（FLUSH 完成，或使用暂停前记录值）；进入 Warm 前 Dirty/Pending Commit 必须为零。
6. Warm 约束：
   - 快照与恢复要求相同的 Cloud Hypervisor 版本（VMM 版本 pin），不承诺跨版本 restore；Node 升级前必须把 Warm Cat 降级 Cold。
   - 快照包含用户进程内存，必须加密、配额管理，转 Cold 时安全删除。
   - Warm 保留 Attachment 与 fencing epoch（Host 亲和），转 Cold 时才释放 runtime lease。
7. 任何 Suspended resume 或 Warm restore 失败必须收敛到 Cold fallback，不允许卡死在中间态。
8. 资源记账：Suspended 记 resident bytes + memory backing bytes + resume commitment；Warm 记 snapshot bytes + resume commitment（RAM 无驻留）；两者的并发唤醒都需要准入控制。
9. 跨 Host Hibernate（快照上传对象存储、异地 restore、live migration）仍不在 V1 范围。

## 取代关系

- 细化 ADR-0001 第 7 条三个层次的命名与产品状态映射。
- 取代睡眠文档中“V1 只支持 pause+page-out 与 Cold、snapshot 属于未来能力”的决策段落；该文档已同步修订。

## 待验证事项（Warm 进入生产前）

- 现有 Warm 数据使用 Cloud Hypervisor 自带参考 vhost-user 后端；必须用带 dirty/lease 状态的 `cats-blockd` 重新验证 snapshot/restore 的设备状态对齐。
- ~~Warm/Suspended wake storm 的准入与限流~~ —— **机制已实现**（`node-agent/src/admission.rs`）：
  按 resume commitment **字节数**计量的节点级唤醒预算 + 并发数上限，超预算的唤醒**有界排队**而非被拒绝。
  按字节而非按个数计量的依据是本实验的结论——10 并发 restore 时 `vm.restore` API 仅 25–26 ms，
  瓶颈是 Guest 内存页回读；排队而非拒绝的依据是第 7 条——被拒绝的唤醒会被控制面收敛到 Cold，
  从而销毁本地 Suspended/Warm 状态，使 wake storm 更严重。
  默认值钉在本实验验证点（10 并发 / 10 × 512 MiB），**不是已证明的最优值**。
  同时放开了 `ResumeCat` 的节点内并发（改为 per-Cat 锁），此前所有 node job 全局串行。
  **仍待真机验证**：在与本实验同构的机型（i4i，本地 NVMe）上重测并发唤醒延迟曲线，
  确认预算默认值与排队超时；`RestoreCat` 的并发化需先让 `start_cat` 的 NBD/tap 分配并发安全。
- 快照加密、完整性校验与安全删除的实现。
- 上述完成前，产品可先启用 Suspended + Cold，Warm 置于特性开关之后；状态模型与 API 命名按本 ADR 一次定型。
