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
| 数据库 | `control-plane/src/store/` | v19 表、slug 部分唯一索引、Disk RWO、动作 CAS、数据库心跳时间 | 已完成；schema、并发与 authority PG 回归已通过 |
| Control 核心 | `control-plane/src/semantic_lifecycle.rs` | 同步动作、语义幂等、超时查询恢复、入口先撤后发 | 已完成并合入 |
| noded HTTP client | `control-plane/src/semantic_noded_client.rs` | Control 同步调用 noded、Bearer、deadline、严格响应校验 | 已完成并合入 |
| PersistentDisk | `control-plane/src/semantic_disk.rs`、`node-agent/src/semantic_mounts.rs` | create/binding/destroy 语义与 Guest 完整挂载确认 | Strict provision/delete backend 和 production composition 已完成；CH/Guest 物理挂载 E2E 待完成 |
| CLI | `cmd/cats/` | slug 命令、同步 REST、`--mount`、GiB 解析、`node_name` 展示 | 已完成单协议切换，旧 Operation/pending/replay 已删除 |
| noded 执行 | `node-agent/`、`cmd/noded/` | 同步 HTTP server、每 Cat 串行、destroy 清理、实际 effects 接入 | FakeVmm 已完成；CH bridge 可启动并 fail-closed，物理 effects 待接入 |
| Node 管理 | Control API、Node heartbeat client | 注册、`node_name`、`control_endpoint`、offline/reset/drain/恢复 | 已完成并接入生产进程 |
| Production adapters | Control adapter | Store/placement/noded/入口实现与公共 DTO 映射 | 已完成；公网 Gateway 细节按设计不在本协议范围 |
| HTTP composition | Control router、AppState、controld/noded main | 新路由和服务接线，旧路由退出 | Control/noded 已完成；CH effects 为独立剩余项 |
| 切换清理 | schema、router、旧模块和测试 | 删除旧表、旧入口、旧 runner 和只验证旧协议的测试 | 旧 HTTP/Store/schema 和已失去 fixture 的旧 authority/部署测试已删除；旧 Route v2 部署合同待随新入口传输实现退出 |
| 纵向联调 | FakeVmm/PostgreSQL | Disk→Cat→状态动作→跨 Node→destroy→slug 复用 | HTTP Cat 全状态机和 PostgreSQL Disk/Store 场景已完成；真实双 Node 与 CH/Guest E2E 待完成 |
| 最终门禁 | 全仓库与 Linux | 完整门禁、Linux Node/真实 VMM 冒烟 | `quality.sh full` 已通过；Linux gate 待运行 |

## 3. 集成顺序

### 阶段 A：公共基础

- [x] 接受 ADR-0059 和空数据单协议边界。
- [x] 定义共享 wire，确认不含 `request_id`、Idempotency-Key 或 Operation。
- [x] 新增 v19 当前资源表和约束。
- [x] 实现 Control 生命周期核心和 noded HTTP client。

### 阶段 B：并行组件

- [x] 实现 CLI 同步 slug API。
- [x] 实现 Disk 目录/绑定语义与 Guest mount-ready 校验器。
- [x] 将 `disk_id`、`volume_id`、filesystem UUID 和 ext4 格式贯穿 Control、noded 与 Guest 确认。
- [x] 接入 Disk 的 Strict volume/disk authority provision/delete backend 和 BlobStore 空前缀后置条件。
- [x] 合入 noded 同步执行服务并接入 FakeVmm。
- [ ] 接入 Cloud Hypervisor 和持久卷的真实 `SemanticCatEffects`。
- [x] 合入 Node 注册、心跳、主动探测、reset 和 drain 的服务与 HTTP client。
- [x] 合入 offline Node 的 Cat 恢复核心和精确状态结算。
- [x] 将 liveness 标记 offline 的结果接到恢复服务。
- [x] Store 完成 create 原子建立 Cat/初始 bindings、placement 复核和 stale Node 查询。
- [x] 完成生命周期、Node 管理和 noded HTTP 的 production adapter。
- [x] 完成 `SemanticResourceApi` 聚合。
- [x] 完成基于当前 Cat/Node 的唯一入口 Store 和 production adapter。

### 阶段 C：纵向接线

- [x] 实现新的公开 Cat/Disk 同步 HTTP handlers 和严格语义请求解析。
- [x] 将新服务加入 Control `AppState` 和 router。
- [x] 将 FakeVmm noded main 切换为同步 server、注册和 heartbeat supervisor。
- [x] 用同一个 placement gate 阻止 reset 期间的新 Cat 动作。
- [x] 接入 Control 的 `withdraw → Node Ready → publish` 顺序。
- [x] 通过真实 Control→noded HTTP 跑通 FakeVmm Cat 全状态机及每个动作的语义重试。
- [x] 跑通 PostgreSQL Disk authority create/delete/retry/slug 复用和 semantic Store 并发场景。
- [ ] 跑通真实双 Node 恢复和 CH/Guest 物理挂载 E2E。

### 阶段 D：单协议切换

- [x] 删除 product Operation GET。
- [x] 删除 AgentSession、lifecycle command poll/result、observation settlement 路由。
- [x] 删除旧 noded runner/journal 的 production composition。
- [x] 删除旧 lifecycle/AgentSession/observation/Route/product HTTP 模块和 Gateway/rotation 监听接线。
- [x] 删除 CLI 的 Operation get/wait、Idempotency-Key pending/replay 和旧 Disk mutation client。
- [x] 删除旧 Operation/AgentSession/Route/NodeJob/observation Store 模块和退役导出。
- [x] 从 v19 schema 删除旧 lifecycle/route settlement 表和 catalog probes。
- [ ] 删除旧协议专属测试；把仍适用的并发、清理和恢复场景迁到新测试。

### 阶段 E：最终验证

- [x] PostgreSQL 并发 create、slug 复用、Disk RWO、动作 CAS。
- [x] Control 响应丢失后查询 noded 恢复。
- [x] offline Node 下一次心跳触发 reset，关闭 placement、清理本地 Cat 后重新注册。
- [x] `cargo test`/Clippy 的相关定向回归全部通过。
- [x] 运行 `./scripts/quality.sh full`。
- [ ] 运行适用的 Linux Node/Cloud Hypervisor 门禁或记录环境阻塞。

## 4. 已合入提交

| 提交 | 内容 | 定向验证 |
|---|---|---|
| `73659d66`、`4a80df0b` | ADR-0059 与切换合同 | 6/6 通过 |
| `f7cc7dc1` | 公共 semantic wire | API tests、Clippy |
| `b845b381` | v19 schema 与 semantic Store | Control check、schema tests；PG tests 待环境 |
| `ad88cc2e` | Control lifecycle coordinator | 10 tests、Clippy |
| `217b4101` | 实际 noded HTTP client | 5 HTTP tests、API tests、Clippy |
| `996739b7` | 同步 slug CLI | 91 tests、Clippy |
| `d4370e5a` | Disk 语义与 Guest mount-ready | Control 6 tests、Node 4 tests、Clippy |
| `0444cf16` | Node 注册、心跳、offline/reset/drain 服务与 noded client | Control 3 tests、Node 2 tests、Clippy |
| `854a1668` | 原子 Cat create/binding、placement 复核、数据库时间 heartbeat/offline CAS | semantic Store 单测编译；PG 行为待最终环境 |
| `9c29e348`、`ff2bde49`、`1429c0ab` | noded 同步每 Cat lane、reset gate、FakeVmm production main | Node 9 tests、client 2 tests、noded 2 tests |
| `65dab394` | 公开 Cat/Disk 同步 HTTP handlers 与语义请求解析 | Control 5 tests |
| `4c880d8d` | 生命周期 Store、NodeRepository、noded HTTP production adapters | Adapter 4 tests；PG Store 7 tests（来源分支） |
| `3b247458`、`6499b6a6` | Resource API 聚合、Control AppState/router、Node liveness 与旧入口退出 | Resource 5 tests、cutover contract 6/6、Control/controld check |
| `b77b41e9` | Resource 聚合回归：slug→内部 ID、Disk 重试/冲突/绑定保护、backend fail-closed | Resource service 4 tests |
| `f8b24854` | Installed/CH semantic effects 启动桥与单点 typed fail-closed | Node 4 tests、noded 3 tests |
| `bea5dd59`、`2ff26b21` | 当前 Cat/Node 唯一入口表、严格场景语义、Store/production adapter 和 lifecycle 接线 | Store PG 10 tests（来源分支）、adapter 5 tests、API 1 test、Control check |
| `0dea4a2a` | offline Node 的 Cat 发现、目标 claim、完整配置恢复和精确终态结算 | Recovery 6 tests、semantic ingress adapter 1 test；来源分支 semantic PG 46 tests、Clippy |
| `5ca7a6fe` | production Control 只保留 semantic resource/Node 主监听与独立 runtime node fence；删除旧 lifecycle/AgentSession/observation/Route/product HTTP 与 Gateway/rotation 接线 | Control/controld check、semantic tests 45/45 |
| `a46e1cf4` | liveness 精确标记 offline 后自动触发 Cat 恢复，并复用同一 noded/入口实现 | Node liveness/recovery tests 14/14、controld check |
| `cc8b885d` | 每个 liveness 周期重新发现仍有 Cat 的 offline Node，Control 重启或临时失败后继续恢复 | level-triggered recovery test、Control/controld check |
| `b87e9bc6`、`f476573b` | Disk 精确物理/文件系统身份、provisioning/deleting、完成 CAS、响应丢失恢复和 Node/Guest 三方挂载核对 | Resource 5、mount 4、recovery 6、installed 4、API 13 tests；Control/noded check |
| `01e3713d` | CLI 删除旧 Operation、Idempotency-Key pending/replay 与退役 mutation 测试 | CLI 69 passed、3 ignored；Clippy `-D warnings` |
| `769a4625` | 删除旧 lifecycle Operation、AgentSession、Route、NodeJob、observation settlement 等 Store 实现和退役导出 | semantic Store 46/46、cutover contract 6/6；Control/controld check |
| `c601c7b0`、`0b96550d` | 真实 HTTP 纵向 Cat 生命周期：Control client→noded router→per-Cat lane→Fake effects，覆盖全状态和重复调用 | 纵向测试通过；Node workspace Clippy `-D warnings` 通过 |
| `e54c3084`、`4fa9f4a6`、`c03f26a8` | Strict PersistentDisk authority backend、最小独立 Store seam、production composition 和 PostgreSQL 回归 | backend 2、resource 5、Strict authority PG 1/1、semantic Store PG 11/11；Control/controld check |
| `a4eb99cf`、`32145634`、`4b891105`、`e905980a`、`e762ce8d` | 删除旧协议 schema/catalog、HTTP 测试、request queue owner、OCI wait 配置和退役测试夹具 | schema PG 1/1、semantic schema 2/2、Control all-target Clippy `-D warnings` |
| `2a7f4956` | 四份主架构文档统一到 ADR-0059，并明确双跑和未完成物理边界 | Markdown links 110/110、旧协议正向声明 0 |
| `271c6bb1` | production mutation admission 与 fresh schema 统一绑定 v19 | admission 回归 2/2 |
| `5e9940d8`、`9c4ab685` | 迁移只适用于旧 noded composition 的部署断言并清理 Clippy | deployment contracts 71/71；四个核心 crate all-target Clippy `-D warnings` |
| `d156894b` | 删除依赖已退役 runtime authority fixture 的旧 Node object-write E2E | Node semantic 单测 20/20；真实 HTTP 纵向测试 1/1 |
| `c55e77fc` | strict Volume Authority schema 统一到 v19，移除 noded 退役依赖，WorkOS 回归退出旧 GET Cat projection | authority PG 28/28、WorkOS 12/12、cargo-machete 通过；`quality.sh full` 全阶段通过 |
| `b0231f98` | 删除依赖已退役 `cat_records`/lifecycle authority 的 blockd NBD crash、root provision fixture 及其专属 Linux gate | deployment contracts 70/70、blockd remaining targets 全通过、cargo-machete 通过；Linux gate 待复跑 |

## 5. 进度更新规则

- 一项只有在提交合入集成分支、定向测试通过并记录剩余接线后才标记“已完成”。
- 分支代码完成但尚未合入时标记“分支完成，待合入”。
- 旧协议测试失败时，若其行为已经退役则删除；仍适用于新协议的风险场景必须迁移后才能关闭该项。
- 每次状态变化同时更新上面的工作流表、checkbox 和提交表。

## 6. 更新记录

### 2026-08-22

- 建立并行工作树和空数据单协议基线。
- 完成并合入公共 wire、v19 schema/Store、Control coordinator、noded HTTP client、CLI 和 Disk/mount-ready 切片。
- 完成并合入 Node 管理服务、Control 注册/心跳路由和 noded heartbeat/reset client。
- noded 同步执行、per-Cat lane、destroy 清理、reset gate 和 FakeVmm main 已完成并合入；真实 Cloud Hypervisor effects 仍待接入。
- Store 的原子 create/bindings、placement 复核和 stale Node/offline CAS 已完成；生命周期、Node 管理和 noded HTTP production adapters 已合入。
- `SemanticResourceApi` 聚合和生产 composition 已完成；当前入口只保存 `cat_id → node_id`，无 generation、epoch 或 Operation，并已经替换生产 placeholder。
- Control 已按 `withdraw → Node effect → Ready 后 publish` 切流；同一目标重试返回成功，未先撤流时禁止直接换 Node，旧 Node 的迟到 withdraw 不能删除新目标。当前目标支持直接 resolve；公网 Gateway/Endpoint 的传输细节按设计文档第 2 节明确不属于本协议实施范围。
- offline Node 恢复已经纵向接入 liveness monitor：恢复 claim 期间保留旧 placement 作为重启后的发现线索，只把动作目标切到新 Node；目标终态确认后才切 placement。Running Ready 后发布入口，Suspended/Warm 从完整配置 Cold boot 后恢复原状态且不发布入口。
- offline 恢复改为每个 liveness 周期按数据库当前状态重新发现：第一次恢复的临时错误或 Control 重启不会因为 Node 已经是 offline 而丢失后续重试。
- production Control 已收敛到一个 semantic 主监听；旧 lifecycle、AgentSession、observation、Route Operation、旧 product handler 以及独立 Gateway/rotation 监听不再进入生产进程。Store/schema 中的退役实现和表正在下一切片删除。
- 公开 Cat/Disk 同步 HTTP handlers、AppState 和主 router composition 已完成；切换合同 6/6 通过。
- Resource 聚合新增 4 个定向回归，覆盖 slug 解析、Disk 语义重试和 strict backend 未安装时的明确失败。
- Disk 创建先持久化不可变物理身份，再由 production Strict backend 原子创建/发现 volume/disk authority；后端明确完成后才从 provisioning 进入 normal。删除先进入 deleting，BlobStore 精确卷前缀重查为空且 authority rows 删除后才释放 slug；响应丢失重试沿用同一身份。
- CLI 已删除 `operation get/wait`、隐藏 `--no-wait`、Idempotency-Key pending/replay 文件和旧 mutation client，只保留同步场景语义命令。
- 旧 Operation、AgentSession、Route、NodeJob 和 observation settlement 的 Store 模块与导出已删除；schema catalog 和引用旧表的集成测试仍在并行清理。
- 已用真实 HTTP composition 跑通 `create → suspend → run → warm → cold → run → destroy`，每个调用重复一次且只产生一次物理 effect；测试同时验证 Running 的入口发布和离开 Running 前撤流。
- fresh v19 已删除 Operation、NodeJob、AgentSession、旧 Route/inventory settlement 表及 catalog probes；严格 volume/disk/snapshot authority 与 Host fence 保留。对应旧 HTTP 测试和退役夹具已经删除。
- PostgreSQL 已验证 Strict Disk authority 的重复 create/delete、同 slug 新身份复用，以及 semantic Store 的 11 个并发、RWO、心跳数据库时间、入口和恢复场景。
- `--vmm ch` 已有明确的 installed effects 桥和单点 preflight；缺少精确 volume/runtime/route 输入时在任何物理副作用前失败，Fake 联调不受影响。
- 切换合同的 noded 静态断言已按实际 `lane_if_open` 命名校准；production composition 已完成，旧 Store/schema 清理仍在进行。
- 定向收尾已完成：API semantic 13/13、CLI 69/69（3 ignored）、cutover contract 6/6、Node semantic 20/20、真实 HTTP 纵向 1/1，四个核心 crate 的 all-target Clippy `-D warnings` 通过。
- 已删除依赖退役 `AgentSession`/writer-authority provision fixture 的 Node object-write E2E，并同步移除不再使用的 dev dependencies；不会为 v19 重新制造旧 fixture。
- 首轮 full gate 发现并完成三个切换收尾：noded 的 4 个退役依赖、strict Volume Authority 的 v18 常量、5 处 WorkOS 对旧 GET Cat projection 的断言；其中仍适用的 `/v1/me`、session 和 admin 行为已保留并迁移。
- `./scripts/quality.sh full` 在干净提交 `c55e77fc` 上通过全部阶段：fmt、skills、release images、deny/machete、workspace build、Clippy、workspace tests 和 rustdoc。
- Linux 首轮 gate 的 build、Clippy、rustdoc 与新 Node privileged 网络测试通过；workspace/privileged blockd 两组失败均来自已删除的 `cat_records` fixture。按单协议切换边界删除 1,378 行旧 NBD/root-provision tests 和 202 行专属 fixture，并从 Linux gate 退出该旧 inventory；未恢复旧表。
