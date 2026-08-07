# ADR-0030：Agent 上报的 runtime 参与反向对账，drain 与发布闸门以它为准

- 状态：Proposed
- 日期：2026-08-05
- 范围：心跳中 agent 上报 inventory 的持久化与暴露、孤儿 runtime 的口径、`node drain` 的完成条件、worker 发布闸门的判定来源、以及丢弃不可发布 journal 的权限归属。
- 不含：agent 端 adoption 与 ledger（ADR-0028 阶段 1–4，已落地）、per-Cat systemd scope 与
  `KillMode`（ADR-0028 §6，#86/#186）、adoption 拒绝后 residue 的清理（另行处理）。

## 背景

2026-08-05 在 `metal-1` 部署 #79/#88 时发现（#98）：节点实际运行 13 个 Cat runtime
（13 个 cloud-hypervisor、13 个 cats-blockd、13 个计量 cgroup），控制面对它们**没有
任何记录**。它们占着约 52 vCPU 与 104 GiB 运行了 8–14 小时，网关无法路由、计费看不
见、API 管不着。

三个相互纠缠的缺口让这件事既看不见也修不掉：

1. **反向对账缺失。** 心跳 handler 只对账控制面已有记录的 Cat：
   `must_get_cat_by_id` 查不到就静默跳过。`req.cats` 本身不落库；遥测里的
   `observed_cats: 13` 与已知 4 个 Cat 的矛盾摆在数据里，没有任何视图做这个比较。
2. **drain 只看 assignment 表。** `drain_nodes` 遍历 `cats_on_node()`，表空即翻
   `Cordoned`。13 个孤儿全程不受影响，`observed_cats` 始终是 13。
3. **发布闸门双向皆错。** `require-idle-worker.sh` 指示操作员「drain 到
   `state=cordoned cats=0`」——在缺口 2 下这个条件永远达不到，指示的补救方法不成立
   （太严，无出路）；同时它只走计量 cgroup，看不到未被计量的 `cats-blockd`——Guest
   已死而 blockd 存活持有未发布 journal 时闸门放行，随后 `systemctl stop
   cats-worker`（当时单元未设 `KillMode`，默认 control-group）连 journal 持有者一起杀掉
   （太松，丢数据）。在 relaxed 卷 `R < L` 时那份本地 journal 是唯一权威副本。

产生这批孤儿的根因（agent inventory 只在内存，#87）已由 ADR-0028 阶段 1–4（#88）
修复：重启的 agent 重新 adopt 可证明的 runtime 并在心跳中上报。但上报之后控制面
仍然丢弃——本 ADR 补上这半边。

逐个停止 13 个孤儿的结果对设计有直接约束：8 个被 fencing 拒绝
（`root CAS conflict`，root 已被更高 generation 取代，本地 journal 过期、不得发布），
5 个因 usage 投递退避失败（该问题已另行修复）。也就是说，孤儿中存在**永远无法干净
停止**的一类，而它们恰恰是 fencing 正确工作的证据。

## 决定

### 1. 心跳上报的 inventory 是持久化事实

`HeartbeatRequest.cats`（cat_id、generation、observed state）按 node 原样持久化
（`nodes.reported_cats_json`，schema v5）。存的是事实（agent 最近一次说了什么），
判断（哪些是孤儿）在读取时进行。重新注册清空该列：新 agent 尚未上报。

### 2. 孤儿的口径

**孤儿 runtime** = 上报 inventory 中 `cat_id` 不在 `cats_on_node(node)` 里的条目。
包含两种情况：控制面完全没有该 Cat 的记录；或记录存在但 placement 不在本节点。对
本节点而言两者同样是必须处理的无主 runtime。

每个节点的孤儿计数暴露在所有操作员界面：`NodeSummary.orphan_cats`（admin API 与
CLI `cats admin node get`）、`MonitoringOverview.orphan_cats`（fleet 汇总）、
Prometheus `cats_node_orphan_cats{node_id}`、管理控制台节点表与详情。上报 inventory
发生变化且存在孤儿时记 WARN 日志（按变化限频，不逐拍刷屏）。

### 3. drain 对孤儿下发 Cold stop，cordon 需要孤儿归零

`drain_nodes` 除 assignment 表外，对每个孤儿按**上报的身份**（cat_id + 上报
generation）下发 `StopCat{Cold}`。Cold 是安全动词：是否允许发布由存储 fencing 的
epoch/CAS 决定，控制面不代替它判断。成功后不更新任何记录（本来就没有记录）；agent
下次心跳不再上报，存量事实自行收敛。

`Draining → Cordoned` 的条件收紧为：`cats_on_node` 为空 **且** 最近上报无孤儿。
于是 `state=cordoned` 重新意味着发布 runbook 需要它意味的东西：节点上什么都没跑。
agent 死亡时心跳停止、`detect_lost_nodes` 将节点翻 Lost，drain 不再处理它——过期
上报不会把非 Draining 路径卡住。

孤儿 stop 失败走与 per-Cat reconcile 相同的指数退避（按 `cat_id@generation`）：
被 fencing 拒绝的 stop 每次重试都是注定失败的 CAS，不退避就是按 tick 频率冲击
metadata store。

### 4. 丢弃不可发布的 journal 是操作员的显式动作

drain 不会把 fencing 拒绝升级为丢弃。`root CAS conflict` 证明该 journal 过期、不得
发布，但「过期所以可丢」这一步由操作员确认后通过 node agent 的 job API 显式执行
（`cleanup_cat`，跳过 drain、杀进程、删 runtime 目录）。runbook 见
`deploy/aws/terraform/README.md`。理由与 #98 中对闸门的判断一致：无法区分「必须丢」
与「暂时停不下来」的组件，就不应该是做丢弃决定的组件。控制面能看到的只是 job 失败
的文本，不足以承担自动销毁数据的责任。

### 5. 发布闸门同时走 cgroup 与进程表

`require-idle-worker.sh` 保留计量 cgroup 走查（拦截 Guest/VMM），并增加进程表扫描：
任何 argv[0] 等于 `<bin>/cats-blockd` 或 `<bin>/cloud-hypervisor` 的存活进程都拒绝
发布（含 `--publish-image` 一次性 blockd——fail closed）。匹配完整 argv[0] 路径而
不是 comm：comm 截断到 15 字符，`cloud-hypervisor`（16 字符）在 comm 里永远匹配不到
自己（#98 的实测教训）。闸门失败文案指向 drain 与上述 runbook，并明确警告 blockd
存活时禁止 `systemctl stop cats-worker`。

## 后果

- 事故形态「节点跑着控制面不知道的东西」从不可见变为：计数处处可见、drain 自动
  清掉能干净停的、剩下的有文档化出路。发布 runbook 的第 2 步
  （`state=cordoned cats=0 orphans=0`）重新可达。
- 控制面 schema 升级到 v5（加列，原地迁移）。`NodeSummary`/`MonitoringOverview`
  新字段带 `serde(default)`，新旧 CLI/控制面滚动兼容。
- node agent 无改动：心跳与 `/v1/jobs` 的既有契约已经足够。
- drain 在存在 fencing 拒绝的孤儿时**故意不收敛**，直到操作员显式丢弃。这是特性
  不是缺陷：卡住且可见，好过 cordon 谎报干净。
- 闸门变严：任何存活 blockd（包括合法的 publish-image）都会挡住发布。发布本来就
  要求空闲节点，误伤面可接受。
- ADR-0028 §6 落地（进程移入 per-Cat scope）后，计量 cgroup 走查在满载节点上会读
  空，进程表扫描成为闸门的主要判定，本 ADR 的第 5 条先行铺好了这一步。
