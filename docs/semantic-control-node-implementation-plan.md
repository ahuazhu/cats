# 场景语义 Control/Node 协议实施计划

- 状态：实施中
- 开始日期：2026-08-22
- 设计合同：[Control Plane 与 noded 同步协议设计](control-node-semantic-protocol.md)
- 决策：[ADR-0059](decisions/0059-semantic-control-node-synchronous-protocol.md)
- 集成分支：`docs/semantic-control-node-protocol`

## 1. 交付目标

本次采用空数据、单协议直接切换：

1. 不提供新老协议兼容、双读、双写或数据迁移。
2. Control 使用 Cat 当前行和 `current_action` 串行动作，事务外同步调用 noded。
3. noded 注册时显式上报自己的 `control_endpoint`，并按 `cat_id` 串行执行。
4. Cat/Disk 幂等由 Workspace、slug、当前状态、完整参数和目标结果决定，不使用 request ID 或 Operation。
5. Cat/Disk destroy 后释放 slug，后续 create 生成新的内部 ID。
6. 最终 production composition 删除旧 Operation、Node poll/result、AgentSession、inventory settlement 和 command journal 入口。
7. 快速开发阶段只运行定向编译与测试；纵向联调完成后统一运行最终门禁。

## 2. 并行工作流

| 工作流 | 代码边界 | 交付内容 | 状态 |
|---|---|---|---|
| 公共协议 | `api/` | Cat/Disk/Node DTO、错误码、noded wire、Bearer token | 已完成并合入 |
| 数据库 | `control-plane/src/store/` | v19 表、slug 部分唯一索引、Disk RWO、动作 CAS、数据库心跳时间 | 已合入；PG 行为测试待最终环境 |
| Control 核心 | `control-plane/src/semantic_lifecycle.rs` | 同步动作、语义幂等、超时查询恢复、入口先撤后发 | 已完成并合入 |
| noded HTTP client | `control-plane/src/semantic_noded_client.rs` | Control 同步调用 noded、Bearer、deadline、严格响应校验 | 已完成并合入 |
| PersistentDisk | `control-plane/src/semantic_disk.rs`、`node-agent/src/semantic_mounts.rs` | create/binding/destroy 语义与 Guest 完整挂载确认 | 已完成并合入 |
| CLI | `cmd/cats/` | slug 命令、同步 REST、`--mount`、GiB 解析、`node_name` 展示 | 已完成并合入 |
| noded 执行 | `node-agent/`、`cmd/noded/` | 同步 HTTP server、每 Cat 串行、destroy 清理、实际 effects 接入 | 实施中 |
| Node 管理 | Control API、Node heartbeat client | 注册、`node_name`、`control_endpoint`、offline/reset/drain | 分支完成，待合入和 Store 接线 |
| Production adapters | Control adapter | Store/placement/noded/入口实现与公共 DTO 映射 | 实施中 |
| HTTP composition | Control router、AppState、controld/noded main | 新路由和服务接线，旧路由退出 | 待开始 |
| 切换清理 | schema、router、旧模块和测试 | 删除旧表、旧入口、旧 runner 和只验证旧协议的测试 | 待开始 |
| 纵向联调 | FakeVmm/PostgreSQL | Disk→Cat→状态动作→跨 Node→destroy→slug 复用 | 待开始 |
| 最终门禁 | 全仓库与 Linux | 完整门禁、Linux Node/真实 VMM 冒烟 | 待开始 |

## 3. 集成顺序

### 阶段 A：公共基础

- [x] 接受 ADR-0059 和空数据单协议边界。
- [x] 定义共享 wire，确认不含 `request_id`、Idempotency-Key 或 Operation。
- [x] 新增 v19 当前资源表和约束。
- [x] 实现 Control 生命周期核心和 noded HTTP client。

### 阶段 B：并行组件

- [x] 实现 CLI 同步 slug API。
- [x] 实现 Disk 语义与 Guest mount-ready 校验。
- [ ] 合入 noded 同步执行服务，并接现有 FakeVmm/真实物理效果。
- [ ] 合入 Node 注册、心跳、主动探测、reset 和 drain。
- [ ] 完成 Store adapter：create 时原子建立 Cat 与初始 bindings；补 placement 和 stale Node 查询。

### 阶段 C：纵向接线

- [ ] 将新服务加入 Control `AppState` 和 router。
- [ ] 将 noded main 切换为同步 server、注册和 heartbeat supervisor。
- [ ] 用同一个 placement gate 阻止 reset 期间的新 Cat 动作。
- [ ] 接入唯一入口的 `withdraw → Node Ready → publish` 顺序。
- [ ] 跑通 FakeVmm 的 Cat/Disk 完整状态机。

### 阶段 D：单协议切换

- [ ] 删除 product Operation GET。
- [ ] 删除 AgentSession、lifecycle command poll/result、observation settlement 路由。
- [ ] 删除旧 noded runner/journal 的 production composition。
- [ ] 从 v19 schema 删除旧 lifecycle/route settlement 表和 catalog probes。
- [ ] 删除旧协议专属测试；把仍适用的并发、清理和恢复场景迁到新测试。

### 阶段 E：最终验证

- [ ] PostgreSQL 并发 create、slug 复用、Disk RWO、动作 CAS。
- [ ] Control 响应丢失后查询 noded 恢复。
- [ ] offline Node 下一次心跳触发 reset 并最终单实例。
- [ ] `cargo test`/Clippy 的相关定向回归全部通过。
- [ ] 运行 `./scripts/quality.sh full`。
- [ ] 运行适用的 Linux Node/Cloud Hypervisor 门禁或记录环境阻塞。

## 4. 已合入提交

| 提交 | 内容 | 定向验证 |
|---|---|---|
| `73659d66` | ADR-0059 与切换合同 | 文档合同通过；未完成项按预期失败 |
| `f7cc7dc1` | 公共 semantic wire | API tests、Clippy |
| `b845b381` | v19 schema 与 semantic Store | Control check、schema tests；PG tests 待环境 |
| `ad88cc2e` | Control lifecycle coordinator | 10 tests、Clippy |
| `217b4101` | 实际 noded HTTP client | 5 HTTP tests、API tests、Clippy |
| `996739b7` | 同步 slug CLI | 91 tests、Clippy |
| `d4370e5a` | Disk 语义与 Guest mount-ready | Control 6 tests、Node 4 tests、Clippy |

## 5. 进度更新规则

- 一项只有在提交合入集成分支、定向测试通过并记录剩余接线后才标记“已完成”。
- 分支代码完成但尚未合入时标记“分支完成，待合入”。
- 旧协议测试失败时，若其行为已经退役则删除；仍适用于新协议的风险场景必须迁移后才能关闭该项。
- 每次状态变化同时更新上面的工作流表、checkbox 和提交表。

## 6. 更新记录

### 2026-08-22

- 建立并行工作树和空数据单协议基线。
- 完成并合入公共 wire、v19 schema/Store、Control coordinator、noded HTTP client、CLI 和 Disk/mount-ready 切片。
- Node 管理和 noded 同步执行分支正在收尾；Production Store adapter 正在实现。
