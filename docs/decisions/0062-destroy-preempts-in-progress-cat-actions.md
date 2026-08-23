# ADR-0062：Destroy 抢占进行中的 Cat 动作

- 状态：Accepted
- 日期：2026-08-23
- 协调协议：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md)
- 修正：ADR-0059 中“不同动作返回 `busy`”的规则；仅 `destroy` 例外
- 详细合同：[Control Plane 与 noded 同步协议设计](../control-node-semantic-protocol.md)

## 背景

产品合同要求任意未销毁 Cat 都可以执行 destroy，包括首次 create 尚未完成或 run/suspend/warm/cold
正在进行。若 Control 对这些情况返回 `busy`，用户必须等待一个可能已卡住的动作才能请求清理；这与
noded 已有的“destroy 取消、等待并清理同一 Cat 执行 lane”能力不一致。

简单覆盖 `current_action` 还会产生两个故障窗口：被替换动作可能迟到写回旧目标；Control 可能在提交
Destroy claim 后、调用 noded 前退出，使该行永久停留在未结算的 Destroy。首次 create 的稳定 `state`
仍为空，还必须保持 v19 schema 的“NULL state 只属于未完成 create”约束。

## 决策

1. `destroy` 是唯一可以抢占另一个进行中 Cat 动作的产品动作。其他不同动作仍返回 `busy`；同一动作
   仍按 ADR-0059 的场景语义查询并等待。
2. Control 在 Cat 行锁内原子把 `current_action` 替换为 `destroy`。Destroy 的
   `current_action_node_id` 优先继承被替换动作的目标 Node，否则使用稳定 `node_id`，使清理落到实际
   物理执行所在的 Node。
3. 若被替换的是尚无稳定 state 的首次 create，同一更新先写
   `state='failure', current_action='destroy'`。它不声称 create 已完成，只保持数据库状态约束并表达
   “唯一允许的后续结果是 Destroyed 或可重试的 Failure”。
4. 所有动作结算继续要求 exact `cat_id + current_action + current_action_node_id`。旧动作在 Destroy
   claim 提交后的迟到成功或失败都不能覆盖 Destroy lane 或最终 Destroyed。
5. noded 收到 Destroy 后通知当前 Cat 动作退出，等待该动作结束，再完成 VMM、Guest、block device 和
   本地状态清理。恢复发现 Node 仍执行被替换动作时重发 Destroy；noded 的 per-Cat 串行和同场景幂等
   保证只形成一个物理清理 lane。
6. Control 组成一个 schema-scoped PostgreSQL advisory-lock 单例恢复任务。它周期读取早于正常同步请求
   deadline 的未结算 Destroy，每次只取有界批次并以有界并发执行 ADR-0059 的 discovery-first 恢复。
   因此 Control 在 claim commit 后、noded dispatch 前退出也会自动重新派发。失去选举会话会取消正在
   恢复的任务并在退避后重建会话、重新参选；其他 replica 也可取得选举并继续扫描。shutdown 才终止
   重选循环。
7. 扫描只是发现，不是新 authority。Node 查询决定是否需要重发；数据库 exact settlement 决定结果
   是否仍属于当前 Destroy。heartbeat、日志、inventory 和 scanner 内存都不能结算动作。
8. 本决策不增加 wire 字段、schema 列、Operation identity 或协议兼容分支。现有
   `current_action/current_action_node_id`、noded Destroy 和 exact settlement 已能表达该语义；改变的是
   admission 与崩溃恢复规则。

## 验收

1. Running、Suspended、Warm、Cold、Failure 和首次 create 进行中的 Cat 都可取得 Destroy，不返回
   `busy`。
2. Destroy 继承进行中动作的 Node，noded 取消并等待旧动作后清理；旧动作迟到结算被拒绝。
3. Control 在 Destroy claim commit 后、dispatch 前退出，生产恢复任务能发现该 claim，看到 Node 仍在
   旧动作时重发 Destroy，并最终精确结算 Destroyed。
4. 无 placement 的 Cold/Failure Cat 可以直接结算 Destroyed；未知盘和 PersistentDisk 数据仍按原存储
   合同 fail closed，不因本决策变成可丢弃数据。
5. 恢复扫描有 age、batch、并发和 singleton 边界，正常同步请求窗口内不与恢复任务竞争。

## 后果

用户可以用一个 Destroy 请求终止卡住或尚未完成的 Cat 动作；Control 崩溃不会把已接受的 Destroy 留成
只能靠人工重复请求推进的永久 current action。代价是 Destroy 成为状态机中的显式抢占通道，Store、
noded 和恢复测试都必须覆盖取消、迟到结算和 commit-before-dispatch。

该能力不扩大数据删除权限。只有 Cat runtime/Root 的既有 Destroy 合同可清理；PersistentDisk 保持独立，
Relaxed 唯一本地数据、未知 disk 和 attachment authority 仍按存储 ADR fail closed。
