# ADR-0057：产品生命周期动作与内部执行证据分层

- 状态：Superseded for Operation projection by
  [ADR-0059](0059-semantic-control-node-synchronous-protocol.md)；六个产品动作名称保留
- 日期：2026-08-21
- 取代：[ADR-0056](0056-atomic-per-cat-runtime-lifecycle.md) 的公开动作命名与产品
  Operation 投影；保留其 one-unresolved lane、exact result settlement、typed causal evidence、
  Node-private journal/replay、Volume/Route interlock 与 HostFence 边界
- 产品合同：[Runtime 生命周期](../runtime-lifecycle.md)
- 历史内部执行规格已从当前文档集删除；Git history 保留原文

## 背景

ADR-0056 把一次产品意图和 Node 执行命令使用了同一组名称，并把 `Start`、`Stop`、`Delete`
与 `Killed` 放进可公开序列化的 Operation/result 闭集。这样会让内部恢复步骤看起来像产品对象：
用户必须理解为什么“启动”还有 source、retry、strong stop、fence 与 retained artifact，甚至会把
`Killed`误认为第五个稳定状态或一种可请求的后继。

这些内部机制对于 crash safety、RWO fencing 和 exact replay 是必要的，但不是产品概念。产品只需表达
用户想让 Cat 到达哪一种稳定状态或结束资源；平台自行选择如何安全完成它。

## 决策

### 产品只有六个动作

产品 API、CLI、用户文档和产品 `Operation` 的 action 闭集为：

```text
create | run | suspend | warm | cold | destroy
```

- `create` 创建新的 Cat，并在同一产品意图中包含首次运行所需的内部
  `EnsureRunning(source = Genesis)`；Genesis 不是用户对已有 Cat 发出的 `run`。
- `run` 只作用于已有 Cat，使 Cold、Warm 或 Suspended 回到 Running。
- `suspend` 使 Running 进入 Suspended。
- `warm` 使 Running 或 Suspended 进入 Warm。
- `cold` 使 Running、Suspended 或 Warm 进入 Cold。
- `destroy` 结束并移除 Cat 产品资源；完成后是资源不存在，不是第五个 runtime state。

稳定 runtime state 仍只有 Running、Suspended、Warm、Cold。产品没有 `start`、`stop` 或 `delete`
动作，也没有 Starting、Stopping、Killed 等稳定或过渡状态。

### 执行停止只是内部证据

平台可以在 run/suspend/warm/cold/destroy 的实现中安装 `StopFence`、关闭 admission、strong stop
Guest/VMM scope，并生成 `ExecutionStopped` 证据。该证据只能嵌入发起动作的 terminal result，证明
后续 cleanup、retention 或 failure projection 建立在“旧执行已停止”的事实之上。

`ExecutionStopped`：

- 不是产品动作或可单独创建的 Operation；
- 不是产品 Cat state、condition、可见 Operation head 或合法产品后继；
- 可以在Node-Control私有协议中由`Killed`等内部类型承载，但该名字与完整terminal payload不得出现在
  产品Operation/API；
- 不得由 heartbeat、inventory observation 或 Control 推断；只能由持有 authoritative execution
  boundary 的 Node 或已冻结的 HostFence 路径产生相应内部证明。

因此，失败后的恢复仍由原产品动作及其 action-specific evidence 表达。例如 run 失败可携带
not-running、retained source 与 `ExecutionStopped` 证据；下一次合法 run、cold 或 destroy 消费该
evidence。它不先创建一个 Killed 产品 head，也不要求用户发出 Stop。

### 产品 Operation 与内部命令分层

产品 `Operation` 只序列化六个产品 action 及其 action-specific outcome。Node-Control 内部协议可以
继续使用`Start/Stop/Delete/Killed`等实现名称，并保留source、typed predecessor、per-volume authority、
journal step、strong-stop proof和cleanup receipt；这些私有名字和字段不得改变产品action闭集或被直接
透传给用户。

产品映射至少满足：

```text
create  -> create resources + EnsureRunning(Genesis)
run     -> EnsureRunning(existing Cat source)
suspend -> suspend execution
warm    -> persist Warm source and stop execution
cold    -> stop execution + settle/release all volumes
destroy -> stop execution + settle retained Persistent volumes + remove Cat resources
```

`EnsureRunning`是内部执行目标，不是第五个产品对象，也不是一种产品状态；current internal Rust wire将其
拼作`Start`不改变该边界。它可以为 Cold boot、
Suspended resume、Warm restore 或 exact same-Node retry选择不同私有步骤；这些差异由同一个 `run`
Operation 封装。

## 与 ADR-0056 的关系

本决策只取代 ADR-0056 对外部 `Start/Suspend/Warm/Cold/Stop/Delete` 命令闭集、`Stop -> Killed`
产品 head，以及把这些内部 result 直接作为产品 Operation 的部分。以下内容继续有效：

- 每 Cat 最多一条 unresolved mutation lane，且 response/ACK loss 只 exact query/replay；
- Node-private durable journal、StopFence、physical manifest、artifact classification 与 bounded receipt；
- exact causal predecessor/evidence，不用 observation 或 audit log 结算 Operation；
- Volume Authority、`R <= L`、RWO epoch、Cold/Destroy 数据屏障与 disposable Root authorization；
- per-Endpoint Route lane、AdmissionCell 和 fresh RuntimeReady/serving binding；
- Host timeout 只表示 suspicion，跨 Node takeover 仍需 trusted HostFenceEvent 与逐卷 authorization。

Atomic Runtime Lifecycle v1 必须据此把产品 action/projection 与内部执行 wire 分层。只要产品route、
request、Operation GET、terminal head 或 successor matrix 仍暴露 `start`、`stop`、`delete` 或 `Killed`，
就不能宣称 product-surface cutover 完成。

## 后果

用户只面对资源与四个稳定态，不需要理解平台为 crash recovery 引入的 journal 状态。Create 与 Run 的
边界也变得明确：前者创建资源并包含首次 Genesis 执行，后者只让已有 Cat 回到 Running。

代价是公开 API 与内部 Rust wire 不能共用同一个直接序列化的 enum。current Control已经用明确的产品
adapter/projection输出六个action并隐藏internal Stop/Killed；仍需用合同测试证明旧route、private terminal
payload与private causal head都不可泄漏。Route resolve也已使用`run_required` fixed vector并严格拒绝旧
`wake_required`。这不要求为了产品命名机械重命名或删除Node-Control private enum。
