# 生命周期闭环收敛修复计划

日期:2026-08-19。分支 `fix/kernel-nbd-worker-lifecycle`,基线 `b0e08942`(已部署 metal-1)。
执行方式:本地提交 → metal-1 fetch → 热缓存 focused test + 增量 release 构建(实测 85–112 秒)→
事务化原位替换(自动回滚)→ 生产观察。生产当前无真实用户,可中断;每个修复必须有 root cause、
结构性修复和红→绿回归,禁止补丁式绕过。

## 目标与收敛判定

**目标**:测试 Cat 在生产 metal-1 上稳定「创建 → 停机(Cold)→ 销毁」闭环。

**判定标准**:连续 N 轮(N≥5)闭环全绿,且每轮结束时零新增残留:
- 状态目录无该 Cat 的 `data/`、`vmm-launch-v1/`、receipt、checkpoint 遗留;
- 无 `cats-vmm-*`/`cats-serving-*` unit、无孤儿 TAP、`/sys/block/nbd*` 全部 unbound;
- worker journal 无 `ScanUnavailable`/`PreScanRecoveryUnavailable`;
- 节点 readiness 保持 open,route admission 未被 fail-close。

**范围裁定**:「睡眠」在本 release 被产品层主动封死
(`product_mutations_v2.rs:69-81` Warm/Suspend/Resume 全部 412;节点侧 `lifecycle_steps.rs:4348/4641` bail)。
闭环的休眠语义采用 **Stop → Cold**(唯一有完整后置条件链的休眠)。放开 Warm 是功能工作,
不在本计划内,需单独决策。

## 已确认缺陷清单(按修复批次)

### D1【修复中】terminal 残留恢复缺 socket-attempt 步——当前生产阻塞

**现场**:metal-1 旧 Cat `cat_5dcd16fa` 的历史坏状态三件套:receipt(public 位)、
launch journal(2 GiB memory.bin)、**当前 boot 的 socket attempt 目录**(死 api.sock + owner 标记)。
worker 每秒打 `pre-scan recovery is unavailable: current boot contains a same-name VMM socket attempt`,
`readiness.close()` —— **节点不可服务**。

**根因**:`recover_terminal_vmm_residue`(`vmm_runtime_paths.rs:441-473`)只收敛
journal→receipt 两件,链上没有 socket-attempt 退休步;选择器
`scan_single_terminal_vmm_residue`(`vmm_socket_namespace.rs:2097`)硬性要求 attempt 缺席
(`assert_stale_boot_attempt_absent`)。该恢复器按「跨 boot」变体设计(重启后 /run 清空),
「同 boot」变体是矩阵空格:旧二进制的 StopRuntime 不清 attempt,残留即永久不可达。

**修复设计**(两个文件,保持 receipt 永远最后删、每步 quarantine+fsync 可重放):

1. `vmm_socket_namespace.rs`
   - 新增 sealed trait `TerminalVmmSocketCleanupAuthority`(复用 `receipt_retirement_sealed::Sealed`);
   - `retire_current_boot_attempt` 的机制部分(三名互斥、逐叶 socket 活性 fail-closed、
     quarantine 改名、排空、fsync、终局三名全缺席断言)提取为私有共享内核
     `retire_owned_attempt_inner`,StopRuntime 入口行为不变;
   - 新增 `retire_terminal_boot_attempt` 入口:attempt 名直接取 receipt 字段
     (`TerminalVmmResidueExpectation::new` 已验证它们是 incarnation 推导且与 checkpoint 坐标精确);
   - 选择器 `:2097` 与 `RetainedTerminalVmmResidue::assert_current`(`:1559`)换用新的
     `assert_terminal_attempt_accounted`:**仅当 `receipt.node_boot_id == 当前 boot`** 时容忍
     ≤1 个精确属主的 attempt 名;跨 boot receipt 保持原硬性缺席要求(原注释的不变量
     「前一个 boot 不可能在新 /run 留下 live socket inode」逐字保留)。
2. `vmm_runtime_paths.rs`
   - `GuardedTerminalVmmResidueAbsence` 实现新 trait(校验走 expectation 绑定,
     不用 `validate_against`——它要求 checkpoint 仍持有 launch,terminal 态为 Absent);
   - `recover_terminal_vmm_residue` 在 `retain_terminal_launch_residue` 之前插入
     `retire_terminal_boot_attempt`;`RetainedTerminalVmmResidue` 加 `retained_receipt()` 访问器。

**为什么安全**:incarnation 单次使用,新启动不会复用 `p-88304bee…`;删除权仅在
「checkpoint 终态(launch Absent + CleanupRelease/DeleteDisposableRoot 且卷权威精确)+
节点全局 unit/进程扫描为空 + launch-root EX 锁 + owner 标记与 receipt 一致」下成立;
任何一叶 socket 有监听者立即 fail closed。

**回归**(红→绿,Linux focused):
- T1 attempt 带死叶 → 全链收敛,attempt/journal/receipt 全部消失且 receipt 最后;
- T2 attempt 带活叶(测试内绑定监听)→ fail closed,零删除;
- T3 隔离完成、排空未完成时中断 → 重放收敛;
- 既有三个子场景(缺席快乐路径、Retain 禁止、foreign leaf)保持绿。

### D2【下一批】delete 终态不回收 DataDirectory——自我放大的泄漏

`data/cat-*/volume-*/attachment-*/epoch-*/cache.data`(现场 1 GiB)在 delete 路径**没有任何回收者**:
唯一回收者 `residue_reclaim.rs:516-613` 要求卷权威处于 `Unowned` 窗口,而 DeleteDisposableRoot 走
`Deleting → sweeper 删行 → Absent`,永远错过窗口(DEFERRED.md N2 自认 fail-closed)。
更糟:遗留目录被投影为节点级 residue(`clean_slate_probes.rs:3053-3084`),而回收开关
`inventory.rs:1347` 是**节点级 all-or-nothing**(`reclaim_sources_are_closed = residue.is_empty()`)
→ 一个遗留毒化全节点回收 → 每轮闭环稳定泄漏 → 自我放大。

**修复方向**(需详细设计,原则已定):delete 的 terminal cleanup 必须把 DataDirectory 纳入
后置条件——在与 D1 相同的「精确授权 + 全局缺席」纪律下,凭 delete 权威(Deleting CAS/删除回执)
获得对该 attachment-epoch 目录的删除权;同时把「无主但可归属」的 epoch 目录从
「毒化全节点开关」降级为「带保留原因的已归属 residue」。

### D3【下一批,与 D2 同族】删行后的扫描硬失败——单 Cat 残留关停全节点

delete sweeper(1 秒/轮)删掉 volume/disk 行后,epoch 目录仍在 → `inventory.rs:2117/2296/2311`
的 `ensure!` 只接受 Owned/Unowned,遇 Absent 直接 bail → `runner.rs:3243-3252`
`ScanUnavailable` + `fail_close_all_admission()` —— **整节点 route admission 关闭**。
同族触发器:`clean_slate_probes.rs:5096-5099`(`descend_only_directory` 要求恰好一个 entry,
Cold→Start 复用同卷时 epoch-N 与 epoch-N+1 并存即命中)、`:3374-3378`(epoch 目录内陌生文件)。

**修复方向**:扫描器对「行已删但目录可精确归属」的状态输出带证据的 residue 观测,
而不是不可用;删除权仍归 D2 的授权路径。fail-closed 保留给「无法归属」的状态。

### D4【判定确认后修】kernel-NBD detach 不退休 blockd socket intent

vhost 分支 detach 顺带 `retire_absent_socket_owner`,kernel-NBD 分支不做
(`lifecycle_steps.rs:1049-1053`),`blockd-socket-intents-v1` 与 AF_UNIX socket 泄漏
(被 `clean_slate_probes.rs:6909-6936` 从 residue 豁免所以不卡,但属同类「无终止拥有者」缺陷)。

### D5【观察性,随批捎带】卡死无信号 + 1 Hz 重试无退避

- 生产 oracle:纯 SQL 卡步探测已可行(`runtime_current_cat_observations` 的
  `runtime_record->'checkpoint'->>'updated_at_unix_ms'` 停留时长),先落成运维脚本随闭环跑;
- `runtime_cutover.rs:56` `RETRY_DELAY=1s` 对 PreScanRecoveryUnavailable 无退避、
  readiness 关闭无显式告警——低优先,不与 D1 捆绑。

### 挂起决策(需要用户拍板)

- **Warm 放开**:功能工作(三处封锁 + SnapshotWarmRuntime 物理端口 + WarmSnapshot cleanup
  执行者 + Resume 路由),放开前 D2 类「快照写出无回收者」缺口会在 Warm 路径复现
  (`CleanupTarget::WarmSnapshot` 已规划、执行端只认「已不存在」,`lifecycle_steps.rs:1220-1227`)。
- **OrphanScope / ControlSocket / CheckpointFile 三个未实现的 cleanup 执行者**(DEFERRED.md N1):
  闭环若不触发则顺延;触发即按 D1 同款纪律补。

### D6【修复中】api crate 合同变更只上了一侧——控制面 400 打死 worker

**事件(8/19 晚)**:`ffb1b2a6` 部署后 terminal 恢复成功(receipt 退休、2 GiB journal 回收),
checkpoint 推进到 Volume release(`disposition=delete_disposable_root`);但生产 controld 仍是
22 天前的镜像(`026360b9…`),其 wire 白名单只放行 `Retain|DetachRetained`(`9fd8c4d7` 已在
分支上删除该白名单),NodeObservation 被 400 拒绝,worker fail-fast 崩溃重启 45 次后被人为停机。
**当前 metal-1 worker 处于 inactive。**

**根因**:`cats-api` 的 wire 合同变更必须节点与控制面同版部署;昨天只滚了节点。
**修复**:E8 通道构建分支 `40eb20c3` 控制面镜像 → 只滚 `cats-controld` → 再部署同提交 worker 并启动。
**纪律沉淀**:凡 patch 触及 `api/src/runtime_reconciliation/wire.rs`,部署清单必须同时含控制面。

### 8/19 晚新增提交(D1 及其同族,已在分支、部分未部署)

- `ffb1b2a6` terminal VMM socket 残留退休(=D1 设计,已部署且已验证生效);
- `85ffaf18` terminal blockd socket owner 退休、`065ac9ab` pre-scan lane 密封、
  `40eb20c3` absent kernel serving owner 保留 —— D1 同族的连环空格,**已提交未部署**。

### 待并入

四模态缺陷扫描被 API 额度中断:**资产负债表与崩溃点矩阵两个模态未运行**;陈旧权威+进程生命周期
两模态产出 12 个候选,但对抗验证全部因额度失败——它们是**未验证候选**,不是已否决。其中与当前
部署方式直接相关、优先核实:「原地替换二进制后存活 VMM/blockd 的 /proc/exe 变 (deleted),
节点进程清点判 Present/Unavailable,worker 重启后全节点无法 attest」。其余候选(reclaim 互锁、
nbds_max、nbd-client 升级误判、PID 复用、双 agent 不同 state dir 零互斥、Deleted tombstone
占容量等)列入待核实队列。两个未跑模态待重启。

## 已知阻塞清单对照(AGENTS.md Known blockers)

| # | 条目 | 状态 |
|---|------|------|
| 1 | 歧义 AttachDisk 留物理 mount | 部分修(fail-closed 无恢复;无 CleanupTarget::Mount,v1 仅 Root 不触发) |
| 2 | stale generation 作用/结算新 runtime | 已修(checkpoint_is_current + 精确结算) |
| 3 | acquire 无 expected-owner/takeover | 已修(Normal{expected_unowned_epoch}/Takeover) |
| 4 | 崩溃孤儿化 runtime/journal | 部分修(本计划 D1–D4 即其余量) |
| 5 | 同节点双 Agent 无锁/fence | 已修(agent_session_epoch CAS + Host 全局效果锁) |
| 6 | Route Grant 无 Node 准入门 | 已修(InstallGate/OpenAdmission) |
| 7 | PersistentDisk 无 UUID/format/mount-readiness | 合同齐、产品面未接线(闭环不触发) |
| 8 | control Store 同步阻塞 async | 已修(专用 blocking executor) |
| 9 | DiskSnapshot GC/同盘 restore | GC 已修;restore 未动(闭环不触发) |

## 执行顺序

1. **D1 修复 + 三条回归**(进行中)→ metal-1 loop 验证 → 部署 → 观察旧 Cat 三件套
   按 attempt→journal→receipt 收敛、readiness 恢复 open、teardown 推进到 network/volume 步。
2. 旧 Cat 继续 teardown 后**预计撞 D3**(volume 行被删、epoch 目录仍在)→ 已有设计方向,
   按 loop 就地修;若绕过则直接进 3。
3. **D2+D3 成族设计与实现**(DataDirectory 终态归属 + 可归属 residue 降级),回归覆盖
   crash 点与陈旧行状态,部署。
4. **闭环 oracle 上线**:创建→Cold→销毁 xN 脚本 + 每轮零残留核对 + SQL 卡步探测,连续观察。
5. 四模态扫描结果并入,余量按族批量修复,重复 4 直至判定标准达成。
6. 收尾:Warm 决策、D4/D5、merge 到 main 前跑完整门禁(交付要求,迭代期不跑)。
