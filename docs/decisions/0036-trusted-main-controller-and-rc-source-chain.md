# ADR-0036：Trusted-main Controller 与 RC Source Chain 分权

- 状态：Proposed
- 日期：2026-08-06
- 关联：ADR-0012（Terraform 发布）、ADR-0024（digest 固定）、Issue #204 / #212 / #245、F0 #234、G0 #241
- 范围：`rc/architecture-v2` 的来源链、控制器信任根、异常同步和重新资格化
- 不含：Manifest V2、构建/发布工件、部署、AWS 权限、不可变账本的具体存储实现

## 背景

Architecture V2 需要把一个确定的 RC commit 送入后续 qualification、artifact 和 deploy
阶段。这里有两个不能混成一个 SHA 的角色：

| 角色 | 含义 | 谁可以改变它 |
|---|---|---|
| `controller_sha` | 解释规则、读取 GitHub 证据并给出 source-chain verdict 的受信代码 | 只经独立的 `main` bootstrap review 改变 |
| `candidate_sha` | 本轮被验证、构建、发布和部署的 RC 内容 | 只经本 ADR 允许的 RC chain edge 改变 |

两者在某个时刻可能恰好是同一个 40 位 SHA；这不合并它们的权限或生命周期。控制器不能
因为检出了 candidate 就执行 candidate 提供的脚本，candidate 也不能通过修改 RC workflow
给自己发放资格。

当前仓库的 GitHub plan 无权配置 branch protection/ruleset，API 返回 403。因此本 ADR 不
声称平台已经阻止 direct push 或 force push。没有 server-side prevention 时，资格链必须
用可检测、可审计、fail-closed 的补偿控制建立。

## 决定

### 1. 信任根与候选内容物理分离

最终 qualification controller 由 `main` 上的极小 bootstrap workflow 启动，并以**字面量
完整 SHA**调用或检出 controller。它另行检出 `candidate_sha` 作为纯输入。任何来自 candidate
checkout 的 workflow、action、脚本或配置，在得到 controller 的显式验证以前都不是受信
代码。

本 ADR 的首个 PR 只提交 policy、source-chain guard 和普通 CI 触发，**不是 trusted
workflow**。把 controller 接到 `main` 信任根的 bootstrap 必须是后续独立、小型 PR；不能
把它藏在本 RC PR 中，也不能让 RC workflow 自举为可信。

### 2. RC head 形成连续的、只前进的 edge chain

每次 `refs/heads/rc/architecture-v2` 移动都形成一条：

```text
previous_rc_sha --reviewed integration or emergency main sync--> candidate_sha
```

有效 edge 必须同时满足：

1. push ref 精确等于 `refs/heads/rc/architecture-v2`；
2. record 的 `before_sha` / `after_sha` 精确等于 trusted controller 从本次 push event 捕获并传入
   的 immutable invocation context；
3. `before_sha != after_sha`，且 `before_sha` 是 `after_sha` 的 Git ancestor；
4. push event 明确报告 `forced=false`；
5. record 中的 `controller_sha` 精确等于 bootstrap 钉住的 controller；
6. controller commit 位于受信 `main` 历史中；
7. integration evidence 满足 §3 或 §4；
8. 同一完整 record 和 invocation context 的重跑产生相同 verdict，不产生第二条逻辑 edge。

这里的“线性”指 RC head edge 始终从账本中上一颗 head 向后继 commit 前进，不要求 Cats
仓库内部永远没有 merge commit。验证历史 edge 时不能读取 mutable live RC ref 作为当时 head；
RC 后续前进以后，仍用已记账的 exact push context 重放并得到同一 verdict。错误 head、非
fast-forward、force push、缺失证据和解析不完整一律 fail closed。

### 3. 正常路径只能集成 reviewed RC PR

正常 edge 的 GitHub 证据至少包括：

- PR number、author、精确 `reviewed_head_sha`；
- PR base 精确为 `rc/architecture-v2`，不能用一个只审到 `main` 的 PR 代替；
- 至少一名与 author 不同的 reviewer 对该 exact head 给出 `approved`；
- trusted controller policy 给出的 exact required-check 名称集合必须与 evidence 完全相等，
  不得缺失、增加或用 `fake` success 替代；每项都在该 exact head 上为 `success`；
- integrated candidate 的 tree 与 reviewed head 的 tree 完全一致。

最后一条允许平台采用 fast-forward、rebase 或 squash，同时禁止在 review 以后悄悄改变内容。
PR/review/check 数据必须由 trusted controller 使用 GitHub read API 获取并规范化；一个调用方
自行填写的 JSON record 本身不构成信任。

### 4. Emergency-main sync 是独立、显式的恢复路径

如果必须把已经过 `main` 审查的紧急修复同步回 RC，允许 `emergency_main_sync` edge，但它
必须满足：

- `candidate_sha` 精确等于执行时由 trusted context 固定的 `main` head，不接受 tag、分支名或
  近似 SHA；历史重放使用已记账的当时 main head，不读取后来已移动的 live main ref；
- 上一颗 RC head 是该 main head 的 ancestor，仍然只能 fast-forward；
- 有非空原因、关联总 Issue/事故 Issue、发起人和至少一个独立批准人；
- required checks 在 exact main SHA 上成功；
- edge 写入不可变外部账本后，按 §7 从 source qualification 重新开始。

Emergency-main sync 不是绕过 review 的 direct push 通道。无法证明 ancestry 时，先把 RC
恢复到最后一颗已记账 head，再走 reviewed PR；不得用 force push 抹去分叉。

项目建立 guard 以前已经发生过两次线性 main→RC 同步，保留为迁移时的 ancestry 示例：

| Project Sync | `before_sha` | `after_sha` | 资格状态 |
|---|---|---|---|
| 001 | `08bf2439e6d7b1928334c18d61d3e99da7deef3e` | `4711b49a4d82099db82fbf6351e4054f60cf7913` | 历史同步；不是本 ADR 的 accepted record |
| 002 | `4711b49a4d82099db82fbf6351e4054f60cf7913` | `d0658064764ee5d77430662fdc8f4c7fda120189` | 历史同步；不是本 ADR 的 accepted record |

`historical-emergency-syncs.example.json` 对这两条 edge 作 machine-checkable 记录，并明确标记
`qualification_evidence=false`。它不能伪造当时尚不存在的 immutable-ledger、review 或 workflow
evidence，也不能被 guard 当作可接受的 source-chain record。新的 emergency sync 必须提交完整
V1 record 并通过上述控制。

### 5. Branch protection 不可用时的真实补偿控制

在 server-side ruleset 可用以前，采用以下组合，且状态页必须继续显示“branch protection
unavailable”，不能写成“已保护”：

| 风险 | 补偿控制 |
|---|---|
| direct/unreviewed push | trusted controller 找不到 exact-head reviewed evidence就拒绝 qualification |
| force push / history rewrite | 校验 push `forced`、Git ancestry和上一条 immutable ledger head；任一失败即拒绝 |
| RC 修改自己的 workflow | RC workflow 只有普通 CI read 权限；受信 controller 从 `main` bootstrap 以 exact SHA 启动 |
| 删除或改写 GitHub 历史证据 | 每个已接受 edge 和证据摘要写外部 immutable ledger；账本不可读时 fail closed |
| 先产物后补审批 | H1/H2 只能消费已接受的 exact `candidate_sha`，旧 SHA 的结果不能重标给新 SHA |
| 绕过控制器直接部署 | 后续 artifact/deploy role 只能信任 controller/ledger 产生的 exact-SHA manifest；本 ADR 不授予这些权限 |

这些控制主要负责**发现并拒绝资格**，不冒充 GitHub server-side push prevention。未来 ruleset
可用时应增加 PR-only、禁止 force push、required review/checks，但不能删除外部账本和 exact
SHA 绑定。

### 6. 外部不可变账本是阻断依赖

Source-chain record 至少保存 schema、repository、controller SHA、push ref/before/after/
forced、GitHub workflow run identity，以及 reviewed PR 或 emergency-main evidence。它必须
写入 G0 提供的、仓库提交者不能改写或删除的外部账本。与 record 配套的 trusted invocation
context/verdict 还必须保存当时的 main head 和 exact required-check policy；否则不能在 ref 或
policy 后续改变后确定性重放。

本 ADR 的 guard 只验证 record 形状、Git graph、trusted push/main exact heads、review/check
policy 绑定和 emergency 规则；它不实现账本，也不把仓库内 JSON 文件称为 immutable。调用者
自行传入的 context 本身也不自动可信；只有后续 `main` bootstrap 从 GitHub event 和 G0 ledger
构造的 context 才是 release authority。G0 ledger 未 ready、写入未确认、读取不一致或上一颗
accepted head 缺失时，H1/H2 必须停在 source qualification 之前。

### 7. 重新资格化规则

任何下列变化都会使旧 qualification 失效：

| 变化 | 必须重跑 |
|---|---|
| `candidate_sha` 改变 | source chain、H1 manifest、H2 全部 qualification 与后续 artifact/deploy |
| emergency-main sync | 与新 candidate 相同的完整重跑；不得继承旧 RC 的通过数 |
| controller SHA 或 source policy 改变 | 经新的 main bootstrap review 后，至少重放 source chain；影响 verdict 语义时重跑全部 qualification |
| immutable ledger 缺页、冲突或不可验证 | 从最后一颗可验证 ledger head 停止；修复证据前不得继续 |
| exact-head review/check evidence变化或撤销 | 当前 candidate 重新 qualification；不能用后续 head 的绿灯补旧 head |

测试结果、manifest、artifact digest、部署 observation 都必须带 exact candidate SHA；只写分支名、
tag 或“latest”不具备继承资格。

### 8. RC 上的 CI 只是普通验证

`CI` 对 `main`、PR 和 `rc/architecture-v2` 的 exact push SHA 运行，checkout 显式使用
`github.sha`。该 workflow 只有 `contents: read`，没有 OIDC、AWS、environment、artifact
publish 或 production deploy 权限。`deploy-production` 现有的 main-only event/ref 检查继续
生效；RC 的 CI success 不能触发生产部署。

这是 H0 第一阶段的普通 CI 和可复用 verifier，不满足 Issue #245 中“trusted guard 已
operational”的 DoD。只有后续独立的 tiny `main` bootstrap PR 固定 exact controller SHA、从
可信 event/ledger 构造 context 并把 verdict 写入外部账本以后，才能勾选该项。

## Machine-checkable guard

仓库提供独立 Rust 工具 `cats-rc-source-chain`。H1/H2 可以直接调用其 library 或 CLI，而不
需要复制 Bash 条件。它接受 trusted controller 规范化的 V1 record，并验证：

- strict JSON schema、lowercase full SHA 和输入边界；
- expected repository/ref/controller 的 exact match；
- trusted push-time RC endpoints、trusted push-time main head、ancestry 和 tree identity；
- reviewed PR、exact required-check policy、unreviewed/main-only、force/non-FF/wrong-head；
- emergency-main exact sync；
- 同一 record/context 的确定性重放，包括 live RC 已继续前进后的历史 edge replay。

测试 fixtures 覆盖 malformed、non-FF、wrong-head、unreviewed、main-only、forced-push、
missing/fake check 和 emergency-sync。这个工具不读取云凭据，不构建或发布工件，也不抽象
通用 workflow engine。

## 后果

收益是 controller 代码与 candidate 内容不再互相给自己授权；即使 GitHub 暂时不能阻止错误
push，错误 head 也无法继承 qualification、artifact 或 deploy 权限，并且异常移动保留在外部
审计链中。

代价是每次 RC 移动都需要 exact-head GitHub 证据与 ledger 可用性，emergency sync 也会触发
完整重跑。bootstrap、external ledger、Manifest V2 和 deploy gate 是后续明确依赖，不因本
ADR 的 guard 存在就被宣称已实现。
