E9：immutable archive/projector/ledger 的逐事件 terminal receipt/barrier 需要 maintainer 接受的协议与权威定义；现有 Control raw inbox、Kinesis PutRecord 和异步 projector 均不能冒充该 receipt，故不在 E9 卡内新增机制。
E9：首次 usage source epoch 与 accepted Desired revision/runtime incarnation 的 Control-side immutable binding 需要扩展现有 wire/持久化权威；本卡仅复用 signed opaque epoch 和 frozen billing attribution，不自行新增协议。
E9：Stage B 的独立 final Usage stream/checkpoint/archive 及既有 Pod Identity hand-off 尚无封闭的 IaC 输入与执行路径；Stage A 继续复用当前 Usage 目标，reset/open 保持阻塞。
E9：Frozen source-epoch 在跨 Node placement 后接收旧 Node tail 的 live integration 仍延后，因为当前 production product authority 对所有带 Root volume 的跨 Node move 明确 fail-closed；本轮只保留 production attribution-selection policy 回归，不新增 test-only move authority。
N2：现有 Node MetadataStore inventory port 只返回仍存在的 VolumeRecord，不能携带 V2 normal/disposable delete completion receipt；这两类 DataDirectory 继续 fail-closed，待复用现有 receipt wire 后再接入精确回收。
N1：CleanupTarget OrphanScope/ControlSocket 物理移除延后，因为已接受 residue 没有 retained owner handle，仅凭 path/token 删除不安全。
N1：CleanupTarget CheckpointFile 执行延后，因为尚未安装 NodeCleanupCheckpoint single-slot executor，per-Cat checkpoint 不能删除自身。
N1：Deleting 后 Disposable Root 本地 lineage 移除延后，因为现有机制没有把已消费授权绑定到 retained lineage 目录的 exact cleanup permit。
A3：Deleted tombstone GC 缺少 ADR-0040 §13 要求的 retained per-Cat observation index（immutable Host/state-path lineage + previous valid checkpoint identity/content digest）；现有 runtime_current_cat_observations 会被 full/partial upsert/replace，无法构造 exact GC eligibility，故本卡只保留/采样 tombstone，不删除。
G3：Production rotation/disable trigger and live Node successor-ring delivery remain deferred because ADR-0044 forbids A23/admin/startup authority and no Accepted G3 principal/transport exists.
V3：Automatic Host fencing remains deferred because EC2 stop plus ENI quarantine does not prove the accepted object-write cutoff/drain barrier or bind immutable Host identity to cloud partition/account/region, so it cannot safely authorize takeover.
V5：The live PersistentDisk first-format/crash/remount matrix remains deferred because the production v2 API has no Cat-to-PersistentDisk attach/mount mutation; create/read/delete alone cannot drive the required real matrix without inventing a new product protocol.
E13：Positive-stop/isolation evidence 仍缺少已接受的 authority 与 canonical terminal semantics；现有 proposed 工具只能留证，不能解除 clean-slate reset 的机械阻断。
E14：Cross-component Closed mutation-admission proof 尚无已接受的可消费 authority；在该证明落地前 reset execute、最终 uncordon 与 public open 必须保持阻塞。
V3/E13：Node 侧 object-write credential 生成 + A19 注册已组合到 serving 授权路径；`AuthorizedServingAttachment.object_write_credential` 仍为 `Option`，因为未配置 ObjectWrite Gateway 的 Node（含全部现有测试组合）依然发 `None`，qualified object-write 发布路径对 `None` fail-closed。剩余缺口：production 从未创建过 `object_write_authorities` 行，`writer_authority_id` 只能由 Node 配置传入（`CATS_OBJECT_WRITE_WRITER_AUTHORITY_ID`），该 authority 的 provisioning 路径仍缺失。
E3/D6：operator 私钥 prepare/apply 远程签名分离受 4 分钟 command lifetime 限制未接入 runner；v1 按 CUTOVER-DECISIONS.md D6 妥协执行，改造延后。
E13：install-operator-tools.sh 的 bundle sha256 校验与 tar 提取按路径分次打开（TOCTOU）；合并后改为单 fd 打开、对 /dev/fd/N 校验并从同一 fd 提取（照 E3 窗口脚本的 fd-pinning 模式）。操作员 Host 无低权限本地用户，窗口内风险有限。

## E2E 注错负段重设计（wire-expressible faults）
聚焦 E2E 的 wrong-origin / wrong-head 注错负段已降级：NodeObservation 线协议
把 device 阶段观测的 lineage 起源与权威头钉死到观测到的 step，两种注错在线上
都不可表达（更早的合同层已包含该防御）。需要重设计为线协议可表达的负例
（例如在非 device 阶段注错，或直接以合同层拒收为断言目标）后再恢复。
