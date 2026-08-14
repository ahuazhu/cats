# ADR-0051：首次生产切换的终态 reset 与 public-open authority

- 状态：Accepted
- 日期：2026-08-14
- 依赖：[ADR-0038](0038-production-account-qualification-cell-boundary.md)、
  [ADR-0040](0040-level-triggered-runtime-reconciliation.md)、
  [ADR-0041](0041-node-verified-route-admission.md)、
  [ADR-0042](0042-volume-authority-and-disk-lifecycle.md)、
  [ADR-0043](0043-provisioner-owned-runtime-placement-policy.md)、
  [ADR-0044](0044-independent-route-v2-signing-authority.md)
- 后续闭合：[ADR-0052](0052-bounded-production-qualification-admission.md)
- final-open 顺序修正：[ADR-0053](0053-final-open-last-product-admission.md)
- 规格：[Production reset and final-open authority v1](../specs/production-reset-open-authority-v1.md)

## 背景

首次 clean-slate cutover 已有可审查的 old namespace reset executor，也有 A19/A20/A23、Route v2、
Usage terminalization、metal qualification 和 provider-neutral HostFence 各自的 authority。但是过去的
`post-green` document 只含 operator declaration 和一个任意 manifest digest；reset binary 因而正确地在
任何 AWS/PostgreSQL 调用前机械 Blocked。把某一项“看起来已关闭”的日志、空表、heartbeat、EC2 状态或
Terraform boolean 当成总开关，会在 old writer、usage epoch、route ring、Node gate 与 artifact lineage
之间制造新的第二 authority。

切换还缺少一个单调的 operator transaction：它必须先验证同一 release/source/fresh target 上所有独立
terminal receipt，才允许发布不可逆 `reset-started`；reset 完成后，也不能由人工跳过到 uncordon 或 public
Ingress。外部 effect 的 success response 可能丢失，因此 exit code 或 audit log 均不能完成事务。

## 决策

1. E13 是一个 **consumer/composition authority**，不是新的 lifecycle、volume、route、usage 或 Host-fence
   authority。它只接受本 ADR 规格中的 canonical proof set，并逐份解析原始 terminal receipt；文件名或
   digest declaration 本身不构成 proof。
2. proof set 固定绑定唯一 `reset_id`、exact Git commit、source manifest/bundle SHA-256、successful frozen
   build receipt、manual release manifest、artifact SHA-256、fresh deployment/cell 和全部 old/fresh
   Control/Usage/ChunkStore target。任一 receipt 必须绑定同一 lineage；不同 qualification run、旧 schema、
   reused Usage target 或同名不同 digest 均 fail closed。
3. prerequisite closed set 是：
   - G3 committed Route v2 signing command及其 exact adjacent public-ring delivery；
   - E9 committed final Usage epoch/barrier与 immutable archive visibility proof；
   - V5 `kernel-nbd`、`vhost-user` 两份 terminal metal qualification manifest/case receipts；
   - V3 core `HostFenceEvent` terminal receipt（只用于不能由 accepted local positive-stop证明的Host）；
   - exact empty-fleet evidence，逐 Node 证明 cordoned、complete fresh inventory、lifecycle/route Closed、
     active guard与cancellation为零、无runtime/residue/quarantine；
   - exact source/build/release receipts及final schema/fresh Usage target。
   缺项、extra、重复、provisional、provider-only或未commit的 evidence 一律拒绝。
4. V3 只消费 core provider-neutral terminal `HostFenceEvent` 和其 validator result。E13 不读取 EC2
   stop/state、ENI/SG、heartbeat 或 provider-private field，也不把这些事实升级为 object-write fence。
   必须有 core receipt 证明 new-PUT cutoff、cutoff 前 accepted PUT 已终态且success均可见。
5. reset/open operator 使用独立的 `ProductionCutoverOperator` authority；WorkOS、A23 provisioner、G3 signer、
   static admin/workspace token均不在其credential closed set。Control启动时只从固定root-owned路径加载绑定
   deployment/release/source commit及AWS role scope的public Ed25519 trust artifact。operator tool在AWS mutation
   前执行真实STS online discovery，要求完整caller ARN/account/partition/role与proof set及trust scope一致，随后
   把这些事实写入有5分钟上限的canonical command并由offline cutover key签名。Control验证的是offline key签名
   及signed STS claim的scope/expiry；它不独立向AWS认证STS、也不把该claim描述成第二Control factor。
   principal、trust digest、proof set digest和全部target进入plan、`reset-started`、每个stage及`reset-complete`。
6. `reset-started` 是唯一不可逆边界。发布前可取消且零 old-target mutation；发布后只能用相同
   plan/reset/release/source/targets/proof bytes forward-resume。每个缺失stage先做 authoritative
   postcondition discovery；ambiguous response不blind retry，receipt gap、body drift、effect-ahead或
   fresh-boundary drift停止并保留全部证据。
7. public open 是独立 transaction。它只接受 exact verified `reset-complete` 和同一 proof set，先写
   `open-started`；[ADR-0053](0053-final-open-last-product-admission.md) 修正本条原 effect 顺序为：在 product
   admission 保持 Closed 时通过已有 authority 完成每个 A23 Node exact cordoned→schedulable apply、reviewed
   Terraform public-ingress apply 与 read-only `GET /healthz` probe，最后才通过专用 E13 signed command/CAS
   完成 mutation-open。每个外部 mutation 使用固定 request ID/body，response 不明时只经官方 typed
   discovery/replay 结算；不得 direct SQL、patch Kubernetes state、写 Control 内部 row 或接受任意 operator
   command。
8. ADR-0053 的 `mutation-admission-open-finalizing` marker 前，任一 stage 失败或取消时 operator transaction
   先用相同官方 authority 关闭 Ingress、把所有可能已打开 Node exact re-cordon、确认 admission 仍为 exact
   Closed，并重验 empty/zero-guard fleet，再退出非零。marker 后只允许 exact-forward settle 同一 Open 并紧邻
   写 `open-complete`，不得 EmergencyClose。cleanup receipt 不授权继续 open，必须重新生成并 review fresh
   open plan。
9. 全部 authority JSON使用closed decoder、bounded stable read、duplicate-key rejection和exact digest。
   operator journal使用同目录0600临时文件、file fsync、no-replace publish、directory fsync；JSON是authority，
   SHA sidecar只由其exact bytes派生。exact replay可补丢失sidecar，不能覆盖不同bytes。

## 后果

- 首次切换没有“总绿灯 boolean”。E13只组合独立authority的terminal receipts，任一lane不可用时保持Closed。
- reset与public open由两个journal隔开；完成旧namespace retirement不会隐式 uncordon 或创建Ingress。
- old Host的本地正向停止与不可达Host的external fence可混合覆盖，但同一个Host/component必须恰好一个
  terminal authority；EC2 deny-all evidence仍只是诊断证据。
- rollback只存在于`reset-started`之前。public-open 在 ADR-0053 marker 前通过 Ingress close/Node cordon并
  证明 admission 仍是 original Closed 来恢复；marker 后只 exact-forward Open，绝不恢复 old namespace、
  EmergencyClose 或复用 retired credential/ID/schema/prefix/stream。

## 不采用的方案

- **仅凭digest清单或operator签字即授权**：offline key只授权提交已验证的composition；operator tool仍必须解析
  原receipt的terminal/binding，否则无法阻止错release或provisional evidence。
- **直接SQL/State切换mutation gate**：绕过已有authenticated/idempotent authority并制造第二写入口。
- **EC2 stop、SG隔离或heartbeat timeout当HostFence**：均不证明object-write cutoff及accepted PUT终态。
- **reset完成后手工kubectl/terraform/cats命令**：没有统一proof binding、ambiguous discovery与cleanup journal。
- **失败后重启old writer**：`reset-started`后old namespace可能已部分retire，只能fresh forward-fix。
