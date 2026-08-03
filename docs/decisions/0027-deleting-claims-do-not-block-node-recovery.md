# ADR-0027：正在删除的 claim 不参与 Lost Node 的完整 inventory 判定

- 状态：Accepted
- 日期：2026-08-03
- 修订：ADR-0002 中"完整报告全部保留 claim"这一条

## 背景

ADR-0002 规定：Lost Node 只有在一次心跳**完整报告全部保留 claim**、且每个 Cat
generation 都匹配后才能恢复；重新注册或不完整 inventory 都保持 Lost，以保留显式
fence 路径。这条规则的目的正确：只有证明 Host 仍然持有控制面认为它持有的一切，才能
原地恢复，否则可能让一个已经转移的 claim 复活。

但"全部保留 claim"取的是 `SELECT * FROM cats WHERE node_id=?`，不过滤任何状态，
其中包含 `desired_state = Deleted` 的 Cat。同时 `Controller::reconcile_cat` 对
node 处于 `Lost`/`Fenced` 的 Cat 一律提前返回，删除流程也不例外。

两者组合成死锁：

- 节点恢复要等那条正在删除的 claim 被上报；
- 那条 claim 要等节点不再 Lost 才能被删除收尾。

而对一个正在删除的 Cat 来说，Host **不再上报它恰恰是删除成功的证据**，不是异常。
所以这个条件永远不可能被满足，也没有任何后台流程能打破它。

2026-08-03 生产实例（`metal-1`）：9 条保留 claim，其中 `pr3139-core`
（`desired=deleted`、`observed=unknown`、`generation=2`）在 Host 上已经拆除完毕、
不再出现在 inventory 里。节点因此永久 Lost，其余 8 个 Running 的 Cat 一并被困在
Lost 节点上；被 fence 的两个 Guest 仍在 Host 上运行且无法发布写入。人工不介入不会
自愈，且每当某个节点在有 Cat 处于删除中途时被判 Lost 就会复现。

## 决定

完整 inventory 的判定范围收窄为**控制面仍然希望在该 Node 上运行的 claim**，即排除
`desired_state = Deleted` 的 Cat。其余部分不变：

- 仍然要求逐个 Cat 的 generation 匹配；
- 任何 `desired_state != Deleted` 的 claim 缺报，仍然保持 Lost，保留显式 fence 路径；
- 仅重新注册、或上报空 inventory，仍然不能把节点变为 Ready。

同时，拒绝恢复的日志必须点名是哪条 claim 阻塞了恢复，以及原因是"未上报"还是
"generation 不匹配"。原先的日志只有计数（`claims=9 reported=10`），一次生产排查
因此需要人工把两个集合取出来做差集才能定位。

## 后果

- 死锁消除：删除中的 claim 不再挡住恢复；节点恢复后 `reconcile_cat` 正常运行，删除
  随即收敛。这一点由回归测试端到端覆盖，而不是只断言节点变 Ready。
- 分裂脑防护未被削弱：这条规则存在的理由是"claim 可能已经转移"，而一个正在删除的
  Cat 没有可转移的去处——它的终态是不存在。
- ADR-0002 的对应条款按本 ADR 理解；`docs/cats-complete-product-technical-architecture.md`
  与 `docs/cats-sleep-wake-vmm-resource-reclamation.md` 的表述同步更新。

## 明确未做

- **`reconcile_cat` 对 Lost 节点的提前返回未改。** 让删除流程在 Lost 节点上也能执行
  是另一个方向的修法（删除不把 Cat 交给任何人，与重新放置不同），本次没有采用：
  收窄恢复条件已经打破死锁，改动面更小。若将来出现"节点因其他原因永久无法恢复、
  而其上的 Cat 需要删除"的情形，再单独决定。
- **孤儿 Guest 的对账未做。** 心跳上报了控制面没有 claim 的 cat_id 时，目前被完全
  忽略，于是被 fence 的 Guest 会持续运行并持续写入永远无法发布的数据（生产实例：
  两个 Guest，3.8 MB，其中一个连 Cat 记录都不存在）。这需要显式的停机/拆除路径，
  且要谨慎——错误地拆掉一个正在运行的 Guest 比留着它更糟。独立设计，独立 PR。
- **relaxed 档位在被 fence 后的丢失窗口未处理。** relaxed 接受"本地 ack、异步发布"
  的有界窗口（ADR-0021/0022），但 fence 之后发布被永久拒绝，窗口变成无界，而且没有
  任何东西把它报告为数据丢失。属于上一条的同族问题。
