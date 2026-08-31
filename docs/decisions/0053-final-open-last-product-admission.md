# ADR-0053：Product admission Open 是 public-open 的最后一个外部 effect

- 状态：Superseded by ADR-0059；历史背景保留
- 日期：2026-08-14
- 修正：[ADR-0051](0051-production-final-reset-and-open-authority.md)
- 依赖：[ADR-0052](0052-bounded-production-qualification-admission.md)
- 历史 final-open runner 已随 ADR-0059 的 v19 单协议切换删除；本 ADR 只保留决策背景。

## 背景

ADR-0051 原顺序先把 product mutation admission 切到 `Open`，再 uncordon Node、打开 Ingress 和运行
public probe。后续任一 effect 失败时，即使 operator 最终执行 `EmergencyClose`，已经准入的 product
transaction 仍可能在 `Open` 与 close 之间提交。这会形成一个没有 `open-complete` 却已经存在新 Cat、Disk
或 Desired 的窗口；本地 journal 不能成为阻止这些数据库事务的第二 authority。

代码边界允许消除这个窗口。A23 Node policy 是独立的 provisioner authority，Ingress 是 reviewed
Terraform effect；现有 `probe-public-endpoint.py` 发出默认 GET，部署 fixture 固定探测 `/healthz`，而 Control
的 `/healthz` handler 只读取 process readiness latch。这些路径都不调用
`require_production_product_mutation_admitted`，因此可以在 singleton 仍为 exact `Closed` 时完成。只有
Cat、Disk、Endpoint/Desired 等 product mutation transaction 需要该 gate。现有 shell WebSocket 会取得
work lease 并通知 Controller，不是 Closed 下的 final probe；完整 WebSocket 能力只能由 reset 前已绑定的
G3 qualification 证明，不能在这里重新执行。

## 决策

1. Production CLI 唯一状态根固定为 `/var/lib/cats/production-final-open`；它必须是预安装并 fsync 的
   root:root `0700` real directory，direct children exact 为 root:root `0700` 的 `admission-state/` 与
   `receipts/`。CLI 不接受 state/receipt directory override，非 root 或 foreign child fail closed；offline
   fixture 只能从内部 constructor 注入 temporary root。整个固定 `receipts/` 使用唯一持久的
   `production-final-open.transaction.lock`，不能按 `open_id` 分锁。`plan` 与 `apply` 都必须在读取或判断任何
   本地 open stage、调用 adapter 或执行 cleanup/forward effect 前，从 stable directory descriptor
   no-follow `O_CREAT|O_EXCL` 或打开该 root-owned `0600` single-link empty regular file、fsync file/directory、
   取得 nonblocking exclusive kernel `flock`，并把同一 descriptor 持有到整个调用返回。它没有 temp-link
   publication 或 payload；fixed filename 给出 scope。持锁期间在每个 adapter/effect 和 receipt publication
   前重验 directory/lock descriptor 与 pathname 的 dev/inode、metadata 和 empty bytes。锁文件永久保留，
   不能 unlink、replace 或 rotate；foreign bytes/metadata、rename/recreate/ABA 或第二 owner 全部 fail closed。
   进程 crash 只由 kernel 释放 flock，后继进程从同一 inode 和 durable journal exact resume。该锁只串行化
   本地 operator，不新增 admission authority。
2. 持全局锁后，plan/apply 扫描所有合法 `open_id` journal。foreign plan/dry-run 可以共存；foreign
   `open-started`/cleanup/forward chain 未 terminal 时拒绝任何新 ID，foreign `open-complete` 永久阻止新 ID。
   只有 exact `open-aborted` 且其完整动态 cleanup chain（Ingress close、context 中每个 Node 的 reverse cordon、
   admission Closed、Fleet Closed、aborted）逐 digest 相邻并绑定同一 plan/authority 时，新的 `open_id` 才可
   计划/执行；缺失、额外、错序或重绑定都 fail closed。plan 把扫描所得的 exact sorted
   `prior_terminal_aborts`（`open_id`、`open_aborted_sha256`）快照写入 immutable bytes；apply 在自己的
   `open-started` 紧前重扫并要求 byte-semantic exact 相等。新增或消失的 abort 都让此前共存的 plan stale，
   必须换 ID 重做；wall clock timestamp 只用于审计，不是该因果授权。因此不同 ID 也不能让 loser cleanup
   re-cordon/close winner。
3. final-open 的外部 effect 顺序固定为：A23 exact Node schedulable apply、aggregate receipt、reviewed
   Ingress open、read-only public probe、最后一个 exact mutation-admission `Open` CAS。`Open` 之后没有
   Terraform、Node、probe 或其他外部 effect；紧邻它的只有 immutable command receipt 和
   `open-complete` publication。
4. effects plan 必须携带 exact `public_probe_method: "GET"`、`public_probe_path: "/healthz"` 与
   `public_probe_admission_mode: "closed"`。typed adapter 必须证明 target descriptor 与实际 invocation
   一致；不能通过 WebSocket、
   创建 Cat/Disk/Desired 或其他 product state 来证明公网可用，也不能把客户端声明当成该证明。在该 typed
   adapter 获得 implementation acceptance 前 production Effects adapter 保持 unavailable。
5. `mutation-admission-open-finalizing` 是 Open submit 前的 durable forward-only marker，绑定 exact
   command ID、request digest 和 expected revision。marker 前的失败或取消关闭 Ingress、re-cordon所有
   可能已 schedulable 的 Node，并证明 admission 仍为 plan 中的 exact Closed state。marker 一旦可能
   发布，任何 signal、response loss、进程崩溃或 receipt publication crash 都只能 replay/discover 同一
   Open command 并前向发布 `open-complete`；不得 `EmergencyClose`。
6. operator 在 marker 紧前重新 discovery singleton，要求 exact planned Closed state、exact revision，且
   signed command 至少剩余 30 秒。过期、foreign revision/mode/binding 或取消发生在 marker 前时走 Closed
   cleanup；marker 后过期而又无法发现 terminal outcome 是需要相同 plan 前向处理的 incident，不能换 ID。
7. cleanup 只接受 exact planned Closed bytes。finalizing marker 前本 transaction 尚未 submit Open，因而
   discovery 到的任何 Open 或任何其他 Closed successor 都是 foreign authority；即使它携带相同 binding 或
   command ID，本次 operator 也不得以 EmergencyClose 关闭或认领。marker 后则只允许 exact-forward Open。
8. 不增加 server-side `Opening` 状态。Open 已经是最后一个外部 effect，durable marker 与 Control 的
   immutable command/replay authority足以消除 effect/receipt ambiguity；新增数据库中间态只会制造另一套
   admission authority。

## 后果

- exact Open commit 之前 product mutation 始终由 PostgreSQL singleton 拒绝，公网 Ingress 即使已可达也
  只能提供 read-only readiness/diagnostic 路径。Open commit 后 `open-complete` 只是紧邻的 terminal
  journal，不冒充第二个 admission gate；其 receipt gap 必须 exact-forward 补齐。
- 整个 receipt directory 同时只能有一个 plan/apply owner，不同 `open_id` 也不能并行。另一个进程不读取
  stale prefix、不启动 cleanup、也不执行 forward effect；owner crash 后只有同 ID exact resume 或已
  terminal-aborted 后的新 ID 可继续，completed Open 后所有新 ID 都拒绝。
- Node、Ingress 或 probe 失败仍可证明 singleton 保持原 exact Closed；Open submit 开始后则不再存在
  “补偿关闭”的分支。
- final-open fixture 必须覆盖每个 forward/cleanup effect 的 response-loss 与 receipt-link crash、marker
  两侧 cancellation、foreign same-binding command、lock foreign/ABA，以及两个真实进程在已
  `open-started` 后跨不同 open ID 的互斥、lock publish SIGKILL、owner crash exact replay，以及 terminal
  aborted 后的新 ID positive、preplanned ID negative、clock rollback/same-millisecond 与 abort snapshot
  disappearance。

## 不采用的方案

- **Open 后再跑 probe，并在失败时 close**：保留可提交 product write 的窗口。
- **用本地 `open-complete` receipt 控制 product API**：把 operator 文件系统变成数据库之外的第二 authority。
- **新增 `Opening` 数据库态**：在所有其余 effect 可于 Closed 完成时没有必要，并扩大 schema/transaction
  surface。
