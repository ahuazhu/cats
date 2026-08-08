# Architecture cross-review closure

- 性质：冻结的设计复核记录，不是运行状态或实施进度表
- 总体设计：[Cats 技术架构](architecture.md)
- 日期：2026-08-08

Runtime/Control、Volume/Disk、Route/HA分别完成首轮设计，并由另外两个边界的reviewer做只读
交叉复核。复核顺序以数据损坏、双写、故障恢复、admission和可实施性为先；格式与代码风格不在
本记录范围。

## 结论

不推翻KVM/Cloud Hypervisor、virtio/ext4、ChunkStore、S3/PostgreSQL、四态和短期签名Grant这些
已验证底座。需要整体替换的是V1协调面：NodeJob、transitional observed、heartbeat overwrite、
普通lease抢占、共享route mirror和不可恢复的Node本地ledger必须在一次clean-slate cutover中退出。

终态只有五个真实模块：Control truth、Node convergence、Volume authority、Route admission、
Operations/HA；依赖和实现顺序见[技术架构 §12](architecture.md#12-模块和实施依赖)。

## 交叉复核关闭的阻断项

1. **Serving identity**：全局`desired_revision`不进入Grant或Node request compare。Grant只绑定
   Node、runtime incarnation和per-Endpoint route epoch。Endpoint A变化不扰动B；任何gate实际
   close或结果不明后，只能由fresh Desired以更高epoch重开，Node不保留双epoch窗口。
2. **Inventory与签发**：partial heartbeat不能冒充或覆盖full inventory。current AgentSession下的
   bounded full scan建立`AdmissionInventoryAttestation`；signer同时验证fresh attestation和fresh
   per-Cat observation。periodic refresh独立于heartbeat，失败先Degraded，attestation过期后停止
   新Grant。
3. **RequireIdle**：只有一个Suspended Desired revision和一次本地guard判断。guard Busy时cell完全
   不变并终态失败；一旦close，watcher/quiesce失败或结果不明都保持Closed，由fresh Running和更高
   route epoch恢复，不增加proposal/proof握手。
4. **Volume ownership**：normal acquire只接受exact Unowned epoch，同transition重试返回原grant；
   blockd只采用grant。Host loss必须由Active HostFenceEvent派生每卷authorization，计划迁移则先
   source Cold/release再target normal acquire。
5. **Disposable Root删除**：原设计在`release要求R==L`与“Destroy可放弃R<L tail”之间不可达。
   终态增加唯一窄转换：精确`DisposableRootDeleteAuthorization`把当前Owned卷CAS为Deleting、清
   owner并提高epoch；CAS后才删除该lineage。PersistentDisk不能使用。
6. **Host rejoin**：provider receipt只建立HostFenceEvent，不直接创建placement或writer。新完整
   Desired/Operation和全部逐卷授权在Control Store事务中建立。授权派生、首次consume和
   `Active -> Rejoined`都锁同一event行；首次consume在同一PostgreSQL事务完成Volume CAS并写不可变
   receipt。rejoin quarantine旧lineage，验证receipt及当前卷是其直接结果或合法单调后继；
   VolumeRecord已删除时验证精确`DeleteCompletionReceipt`。未消费授权必须已过期，Rejoined后不能
   首次生效。
7. **磁盘产品边界**：volume size创建后不可变；无resize/hotplug。DiskSnapshot只在stable
   Cold/unowned时创建一条`DiskSnapshotRecord`；该row同时是产品资源和GC live-root，只支持同盘
   restore；WarmRuntimeSnapshot保持独立。Snapshot create/delete/restore先按认证Workspace/route/key
   串行，再锁Volume/Disk/Snapshot，并把业务变化与通用不可变API result同事务提交；重放只读result。
   snapshot ID由服务端分配且永不复用。Disk delete遇live record返回
   `SnapshotInUse`，不隐式cascade。
8. **首次部署**：顺序歧义已关闭；
   [Operations and HA §8](operations-ha.md#8-首次终态部署)是唯一cutover runbook，本记录不再复制步骤。

## 跨模块接口

| Producer | Consumer | 唯一合同 | 失败oracle |
|---|---|---|---|
| Control truth | Node convergence | complete Desired + revision/placement + Operation | N/N+1/N+2结果不能互相结算 |
| API caller | Control truth | workspace/route/key + canonical fingerprint -> immutable result | 同key异payload、跨Workspace与旧create replay零资源副作用 |
| Node inventory | Route signer | AgentSession + inventory attestation + per-Cat observation | partial/过期事实停止签发，不猜Ready |
| Control/Node | MetadataStore | transition ID、exact epoch、逐卷或删除authorization | 响应丢失幂等；错tuple零副作用 |
| Node runtime | Route admission | runtime incarnation + one Endpoint serving epoch | close后无guard；旧epoch不复活 |
| Fence adapter | Recovery | receipt -> HostFenceEvent -> per-volume CAS -> Rejoined | timeout只suspicion；未闭环保持Blocked |
| blockd/Guest | Lifecycle | `R/L`、filesystem UUID、mount observation | `R<L`不越过Cold；Initialized前`R==L` |

## 尚需实现和证明

这些是实现/证据缺口，不再是未决架构分支：

- 当前Rust仍是V1协调路径；ADR-0040/0041/0042均未实现。
- `deploy/metal/runtime-cutover-e2e.sh`尚未实现；它应成为两种block path共用的确定性oracle，不创建
  新测试环境。
- 外部Host fence adapter、真实RDS failover、两卷takeover/rejoin和disposable delete crash矩阵尚未
  产生终态evidence。
- 独立native Linux build host必须验证exact clean commit并保留immutable receipt；本地或错误
  worktree的绿色结果不能替代它。
- 现有实验只证明各自记录的环境和样本，不构成生产SLA。

详细验收分别以[Runtime Reconciliation §14](specs/runtime-reconciliation-v1.md#14-最小验收矩阵)、
[Volume Authority §14](specs/volume-authority.md#14-最小验收矩阵)、
[Route Grant §11](specs/route-grant-v2.md#11-verification)和
[Operations/HA §6](operations-ha.md#6-分层qualification)为准，不在本记录复制滚动状态。
