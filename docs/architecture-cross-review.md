# Architecture cross-review closure

- 性质：accepted设计复核记录 + 当前证据边界；设计结论冻结，§“当前跨组件证据边界”随可复现实证更新
- 总体设计：[Cats 技术架构](architecture.md)
- 初次复核：2026-08-08；证据边界更新：2026-08-12

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
6. **Host fence**：provider receipt只建立HostFenceEvent，不直接创建placement或writer。新完整
   Desired/Operation和全部逐卷授权在Control Store事务中建立。授权派生与首次consume
   都锁同一event行；首次consume在同一PostgreSQL事务完成Volume CAS并写不可变
   receipt。VolumeRecord已删除时由精确`DeleteCompletionReceipt`证明合法后继。
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
| Fence adapter | Recovery | receipt -> HostFenceEvent -> per-volume CAS | timeout只suspicion；未闭环保持Blocked |
| blockd/Guest | Lifecycle | `R/L`、filesystem UUID、mount observation | `R<L`不越过Cold；Initialized前`R==L` |

## 当前跨组件证据边界

`node-agent/src/runtime_cutover/cross_component_e2e.rs`中的portable PostgreSQL测试从production
Control/A23开始，经过真实A19、A20、Cat-create v2与runner restart，校准旧入口404，
并证明exact accepted Desired只dispatch给一个per-Cat effect。它有意注入受控
`CompleteAssignedScanner`与`RecordingRefreshEffect`，终点是recording `RefreshInventory` seam。

同文件的Linux-only ignored测试另外组成真实PostgreSQL、production public spawn、installed
scanner、systemd PID 1与production `SignedRunningEffect`，证明`ProvisionRootImage`、root-blockd
进程与checkpoint、Agent重启adoption及exact namespace退役。该测试仍使用loopback-test A19
transport、hermetic IMDS和fixed image blob，要求S3对象请求为零；它不执行block device/TAP/VMM/
Guest或稳定Running，因此只是真实Linux systemd physical prefix，不是完整physical/KVM E2E。
具体release仍必须在exact clean SHA上通过Mac full、Linux full及适用的metal qualification，
不能用portable seam或历史绿色代替当次immutable receipt。

## 尚需实现和证明

这些是剩余外部组合或qualification缺口，不再是未决架构分支：

- A19/A20/A22/A23、完整scanner、per-Cat checkpoint/effect、AdmissionCell及current-Desired Running的
  Persistent ext4链已组成；旧NodeJob/heartbeat不属于production composition。完成声明到Running-only
  current-authority路径为止，不宣称superseded pre-acquire publication或完整lifecycle cutover已经闭合。
- 上述PG测试只证明[当前跨组件证据边界](#当前跨组件证据边界)。具体release还必须在两种block path
  适用的Linux/metal环境保留exact-SHA物理证据，不能用受控scanner或recording effect替代KVM/Guest。
- 外部Host fence adapter、真实RDS failover、disposable delete crash矩阵和跨Node Guest overlay尚未
  产生终态evidence；timeout仍只表示suspicion。
- 独立native Linux build host必须验证exact clean commit并保留immutable receipt；本地或错误
  worktree的绿色结果不能替代它。
- 现有实验只证明各自记录的环境和样本，不构成生产SLA。

详细验收分别以[Runtime Reconciliation §14](specs/runtime-reconciliation-v1.md#14-最小验收矩阵)、
[Volume Authority §14](specs/volume-authority.md#14-最小验收矩阵)、
[Route Grant §11](specs/route-grant-v2.md#11-verification)和
[Operations/HA §7](operations-ha.md#7-分层qualification)为准，不在本记录复制滚动状态。
