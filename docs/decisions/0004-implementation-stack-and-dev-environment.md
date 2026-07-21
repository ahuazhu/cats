# ADR-0004：实现技术栈与开发测试环境

- 状态：Accepted
- 日期：2026-07-21

## 背景

数据面 `cats-blockd` 已定为 Rust（ADR-0003）。控制面与 CLI 的语言（完整架构 §19.2 原为“Go 或 Rust”）以及日常开发/集成测试环境此前未定。

## 决定

1. **生产组件统一 Rust**，单一 cargo workspace：
   - `cmd/cats`：CLI（clap）。
   - `control-plane`：Resource API、Operation、Controller（axum + sqlx + tokio）。
   - `node-agent`、`blockd`：数据面（vhost-user-backend 等 rust-vmm 生态）。
   - `api`/协议类型作为共享 crate，避免跨语言维护两份定义。
   - Python 只作为规格 oracle 与实验工具（lazy-ext4 oracle、实验脚本），不进入生产路径。
2. **开发与测试环境分两层**：
   - 日常开发与正确性测试：macOS 本地 Docker privileged 容器（Linux NBD + ext4 + crash 注入，lazy-ext4 同款环境，零额外成本）；CI 使用同一容器镜像。
   - Cloud Hypervisor/KVM/vhost-user 集成与性能基准：按需开 AWS 裸金属（i4i.metal / c5.metal），跑完即销毁；正式 CSV/日志按既有惯例回收进 `experiments/`。
3. **S3 集成测试**默认使用 MinIO 等 S3 兼容容器；里程碑验收必须在真实 S3 上重跑。

## 影响

- 完整架构 §19.2 技术选型由“Go 或 Rust”改为 Rust。
- 根 README 的目标代码结构按 cargo workspace 理解（目录名不变）。
- 招聘/协作假设：一人 + AI Agent 开发，单工具链优先于生态多样性；若未来团队扩大需要 Go 控制面，另立 ADR 评估。
