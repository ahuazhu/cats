# 生产 cutover 裁决记录（2026-08-15，接手会话）

> 接手 Codex session `019ff896` 后，基于 candidate-5 集成线（两条 Stage B 线合流 +
> E13 final-open 收编）与七项 P0 缺口逐项核实（file:line 证据见当日核查报告）。
> 用户此前已授权：线上数据可删、可停机、接受短期不稳定、目标尽快上线。
> 据此对下列决策采用**建议默认值并直接执行**；每项都可被用户推翻，推翻成本已注明。

## A. 已按默认值执行的决策

| # | 决策 | 采用值 | 理由 / 推翻成本 |
|---|------|--------|----------------|
| D1 (V6) | DiskSnapshot 三操作 + PersistentDisk 冷 attach/detach 进 v1？ | **延后** | #204 本就是 Cold-only 首版；Cat 只带 Root 可用。后续独立 issue。推翻 = Batch 1 加一张 L 卡 |
| D2 (V4) | 围栏过的 Host 允许 rejoin？ | **不回归**：重装 + A23 发新 NodeIdentity | `HostRejoinProof` 全库零实现；v1 变通成本最低。推翻 = 实现 rejoin 证明链（L） |
| D3 (G3) | 生产密钥轮换/禁用触发器 | **v1 = 重新发布轮换**；紧急轮换 = 停签 + 关 gate 手册程序 | ADR-0044 禁止 A23/admin/startup 权威，live 轮换缺已接受的 principal/transport（DEFERRED #10）。qualification 内轮换证据链已存在 |
| D4 (E4) | deploy-production.yml 修复还是停用？ | **显式停用**，manual-release-bundle 为唯一发布通路 | Actions 账单未恢复；修好也跑不了。恢复后可重启用 |
| D6 | operator 私钥边界（qualification 期间） | **v1 妥协：operator key 以 0600/单链接放 runner host，run 结束即销毁并轮换** | 远程签名边界完全缺失（核实项 1）；现成 prepare/apply 分离受 4 分钟 command lifetime 限制，改造入 DEFERRED。零用户生产 + 用后轮换，风险时间窗有界 |
| D7 (V3) | 自动 Host 围栏进 v1？ | **手工围栏**：EC2 stop + 控制台/CLI 取证 + operator 提交围栏事实；自动 producer 延后（DEFERRED #11 维持） | 消费半边（takeover、placement 拒绝）已实现；自动 provider adapter 无法证明 object-write cutoff。零用户期手工程序可接受 |

## B. 判定为 bug / 缺件，直接实施（无需裁决）

1. **schema 版本矛盾**：控制面 `AUTHORITY_RELEASE_SCHEMA_VERSION=15`，而 E13/reset/
   admission 全链硬编码要求 16（reset 会拒绝本 release 装出的新库）。统一升 16。
2. **fresh Usage 双资源 IaC**：reset 工具硬性要求新旧 Kinesis/DynamoDB 目标不同名，
   Terraform 只会建一套。补并行 fresh 资源 + 输出。
3. **E3 外层窗口持久化**：`runtime-cutover-e3-window.sh` 全内存状态，SIGKILL 后
   ingress 状态/清理阶梯丢失。补 journal + 重入恢复。
4. **operator-host 工具安装器**：只有整机 worker 安装器；补一个只装 verifier 工具链 +
   trust 工件的 operator-host 安装器（收编 `feat/e13-operator-tools-install` 的生成器）。
5. **release manifest 收口**：proof set 不交叉校验 qualification catalog sha；
   usage/object-write prosrc 目录 digest 未进 manifest。补两处校验。
6. **reset 工具 4/5 verifier adapter 未接线**（只有 usage 接了）：逐个接线或按
   D6/D7 的 v1 语义提供可用实现。

## C. 维持 DEFERRED 的项（不做，理由不变）

新增两项（2026-08-15 判定，理由：E3 qualification catalog 零 object-write 场景，
object-write gateway 路径在 v1 不被行使且已诚实 fail-closed）：
- `control_object_write_gateway_qualification_lock_v1` 第 12 函数不实现——其返回的
  authorization_canonical 要求与 Rust 编码字节级一致，成本高且只服务 v1 不跑的
  object-write ambiguity qualification；缺失已被 schema.rs 显式断言 + startup 上报
  unavailable。
- NOLOGIN schema owner 不做——需要 owner-role 成员制 + 控制面 DDL SET ROLE 改造，
  加固对象是同一条 v1 不行使的路径；fresh schema owner 审查由 runbook 人工步骤覆盖。

DEFERRED.md #1–#9、#12 维持：E9 逐事件 terminal receipt 协议、source-epoch 绑定、
跨 Node tail、N1/N2 各类精确回收许可、A3 tombstone GC、V5 live PersistentDisk
矩阵（随 D1 延后）。

## D. 用户已拍板（2026-08-15）

- **CI/CD 完全绕开 GitHub Actions**：不修复不等待 Actions；发布唯一通路 =
  manual-release-bundle + 手工门禁（本地 full/linux + build host 原生 full +
  metal E3）。D4 定案为"显式停用 workflow"；D5 不再跟踪，G6/E11 改本地驱动或
  无限期延后。
- **窗口时间 = 尽快**：门禁绿 + 合 main 后立即连续执行工件重建 → terraform
  applies → A23 发放 → metal E3 qualification → 窗口（reset → deploy → E12 →
  final-open），不留调度间隔。destructive forward-only 点前仍按 runbook 停点确认。
- 上表 A 中任何一项如需推翻，请直接说明编号。
