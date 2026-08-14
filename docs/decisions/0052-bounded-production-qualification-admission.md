# ADR-0052：默认 Closed build 的有界生产形态 Qualification admission

- 状态：Accepted
- 日期：2026-08-14
- 依赖：[ADR-0038](0038-production-account-qualification-cell-boundary.md)、
  [ADR-0051](0051-production-final-reset-and-open-authority.md)
- 规格：[Production reset and final-open authority v1](../specs/production-reset-open-authority-v1.md)

## 背景

ADR-0051 要求 schema 16 的 production mutation singleton 从 `Closed` 出生，并且最终 `Open`
必须消费同一 release 的完整 G3/E9/V3/V5 qualification proof。Qualification cell 又必须运行
这个 exact schema/build 才能产生这些 proof。用 test-only bypass、默认 Open、config boolean、raw SQL
或伪造一个缺字段的 final-open binding 都会形成循环 authority：未经 qualification 的 build 先以
Open 身份产生授权 Open 所需的 qualification。

Qualification 还需要真实创建并清理 Cat、PersistentDisk、Desired runtime 与 Endpoint。它不能扩大到
生产 workspace，也不能阻止 Closed 状态下的 observation、Operation settlement、volume cleanup、Usage
terminalization、read/health/reset。结束 qualification 后必须先线性化地 drain 所有已准入 product writer，
再允许 E9 声明 source/target terminal。

## 决策

1. `ProductionMutationAdmissionMode` 是闭合三态 `Closed | Qualification | Open`，数据库仍只有一个
   singleton。schema 初始化为 revision 1、`Closed`、无 binding。`Qualification` 是独立 sum variant，
   不是缺少 final proof 的 `OpenBinding`。
2. `QualificationAdmissionBinding` 精确绑定：
   - `qualification_id`、deployment/release、40 位 source commit、schema 16；
   - source manifest/bundle、frozen build receipt、manual release manifest、worker bundle、
     `qualification-catalog.v1.json` 与 ADR-0038 cell manifest 的 SHA-256；
   - AWS partition/account/region、cell ID/namespace；
   - 已由独立 identity authority 创建且 active 的 Cats Account 与唯一 Workspace；
   - 固定有序 mutation class closed set
     `cat_create,disk_create,disk_delete,object_write_ambiguity,runtime_mutation`；其中
     `object_write_ambiguity` 只授权同一 Qualification Workspace 的 V3 对象写响应丢失注入，
     不授权普通生产 PUT 或任意 provider effect；
   - 以 PostgreSQL clock 判断、最长 24 小时的 expiry。
   binding 不含 reset、fresh target、final proof set、G3/E9/V3/V5 terminal digest。
3. canonical signed mutation 只有
   `begin_qualification | end_qualification | open | emergency_close`。它们都使用 ADR-0051 独立
   `ProductionCutoverOperator` offline Ed25519 trust、online STS discovery 后写入的 signed claim、五分钟
   command expiry、32 位 command ID 与 expected revision。Control authority 是 offline key；Control
   不在线认证 STS，也不把 signed STS claim 描述成第二 factor。
4. `BeginQualification` 只接受当前 `Closed`、非 final-Open binding、exact expected revision、exact
   release/schema、未过期 scope 及数据库中 active Account/Workspace。成功变为 `Qualification` 并保留
   exact binding。相同 `(command_id,canonical body)` 返回原 immutable receipt；同 ID 异 body 冲突。
5. runtime product Store transaction 先查 exact API replay；miss 才对 singleton 取 `FOR SHARE`，在任何
   domain write 前重验 exact release/schema。`Qualification` 仅接受 binding 中的 Workspace、未过 DB
   expiry且 class 在上述 closed set 内；`Open` 仅接受完整 `OpenBinding`。其他 workspace、class、mode、
   expiry 或 corrupt binding 全部 Closed。
6. `EndQualification` 只接受当前 exact Qualification binding；`EmergencyClose` 可关闭 exact
   Qualification/Open binding。两者对 singleton 取 `FOR UPDATE`，因此必须等待先前所有 product
   `FOR SHARE` transaction commit/rollback，且返回成功后没有 product write 能在该 close 之后提交。
   End 不依赖 E9；顺序固定为：case cleanup mutations → EndQualification → final read-only
   Closed/fleet/resource inventory → E9 terminalization。失败 cleanup 可 emergency-close 后隔离销毁 cell，
   但不能发布成功 terminal receipt。
7. 成功 runner closed set 包含：
   - `production-mutation-qualification-begin.receipt.json`，kind
     `cats.production-mutation-qualification-begin-receipt.v1`；
   - `production-mutation-qualification-terminal.receipt.json`，kind
     `cats.production-mutation-qualification-terminal-receipt.v1`。
   begin receipt 绑定 binding digest、Begin command/request/official receipt 与 resulting revision。End 后，
   operator 用原 exact signed close command 调用
   `/v1/admin/production/qualification-product-inventory-discoveries`。Control 在一个 repeatable-read transaction
   内对 singleton 取 `FOR SHARE`，核对 current Closed revision/immutable close receipt，完整解码 Workspace
   clean-slate product graph，并发布
   `production-mutation-qualification-product-inventory.receipt.json`。当前 Cat、Root/PersistentDisk、Snapshot、
   Endpoint、hostname lookup、pending Operation 计入 `product_resource_count`；Deleted Cat tombstone、terminal
   Operation 与 API idempotency receipt 只作为 excluded history 报告。未知 JSON/scalar projection、orphan 或
   stale pending Operation 一律拒绝，不返回可用的 zero receipt。terminal receipt 绑定同一 begin、End
   command/request/official receipt、canonical final Closed state digest、紧邻 final revision、product inventory、
   fleet Closed 与 cleanup inventory receipt，并要求 active guards、product resources、residue 都为零。
   receipt 不反向哈希最终 qualification manifest，避免递归；最终 manifest 对两份 framework receipt 及其
   digest-closed support files 做 closed-set hash。
8. identity/WorkOS、Stripe ledger 与 internal authority 不成为 E13 product gate：
   - Qualification 的 exact Workspace 必须在 Begin 前由 Account/WorkOS identity authority 创建；workspace
     profile、membership、invitation、token 与 session 不写 runtime product rows；
   - Stripe webhook 必须在 Closed 时仍能结算已经发生的 payment/refund。checkout 可创建外部支付 session，
     但 credit 绝不绕过 Cat/Disk/Desired transaction gate；
   - AgentSession/observation、Operation settlement、Usage、Volume transition/residue cleanup 与 A23/admin
     authority 必须在 Closed 时继续收敛或清理。
   production router 的每个 POST/PUT/PATCH/DELETE 被 source contract 恰好分类一次。OCI deploy、exec、
   auto-suspend/expiry、snapshot/restore、legacy Node/wake route 在 production router 不注册；重新引入任一
   route 必须同时更新分类与 authority。
9. 测试 fixture 不写 singleton、不配置 bypass、不默认 Open。它先用正常 Account/Workspace bootstrap，
   再以与 fixed test trust 匹配的 dedicated key 构造、canonical encode、签名、verify，并调用同一个 Store
   BeginQualification transaction。closed negative、exact replay、异 workspace/class、expiry、End drain、
   close wait 与 waiter cancellation 都使用生产 authority path。

## 后果

- exact default-Closed release 可以在 ADR-0038 隔离 cell 中产生自己的 qualification proof，而无需自证
  final Open。
- Qualification 过期不会修改 row；下一次 product miss 在同一 transaction fail closed。operator 仍应
  End/EmergencyClose，使 singleton 回到可发现的 Closed revision。
- Account/Stripe/internal authority 保持各自的 authentication、idempotency 与 recovery protocol；它们不能
  mint runtime product admission，也不能把 qualification scope 扩到另一个 Workspace。
- final `Open` 仍必须消费完整 reset/proof set。Closed qualification binding 可被新的 exact qualification
  或 final Open 替换；Closed final-Open binding 只能用同一 exact binding 重开。final-open 的 effect 顺序由
  [ADR-0053](0053-final-open-last-product-admission.md) 修正：Node/Ingress/read-only probe 在 Closed 下完成，
  Open 是最后一个外部 effect。

## 不采用的方案

- **test-only Open/helper SQL**：测试通过与 production 不同的 authority path，且无法解除 proof 循环。
- **全 account 或全 deployment Qualification**：隔离错误会让 production Workspace 获得 mutation admission。
- **handler preflight**：不能与 domain write 原子排序，emergency close 返回后仍可能有 late commit。
- **End 等待 E9**：E9 terminal 必须发生在 product writers 被 `FOR UPDATE` drain 之后，否则不是最终 Usage。
