# Rust 工程实践审查（2026-07-21）

## 结论

当前 workspace 有较强的正确性基础，但不能笼统评价为“已经完全符合优秀 Rust
项目的最佳实践”。优势是核心提交协议有高价值的崩溃、fencing 和跨节点恢复测试，
类型边界清晰，Clippy 可零警告通过；主要差距集中在生产 adapter 强化、panic/锁
中毒策略、自动化供应链检查和 MSRV 持续验证。

本轮已修正会妨碍后续扩展或隐藏错误的结构性问题；未完成项明确保留为工程债，
不把 V1 开发形态包装成生产完成度。

## 本轮完成

| 领域 | 改进 |
|---|---|
| 依赖方向 | 新增 `cats-storage` ports、独立 `adapters/` 和 `cmd/*` composition roots；核心 package 的 normal Cargo 依赖图不再包含具体 adapter 或云厂商参数 |
| crate 元数据 | 所有 workspace package 继承 `rust-version = 1.88`，标记 `publish = false`，统一 workspace lints |
| 静态检查 | 禁止 `dbg!`、`todo!` 和无安全说明的 unsafe block；质量门禁继续要求全 workspace test 与 all-targets Clippy 零警告 |
| 错误处理 | adapter 配置使用结构化错误；SQLite 锁中毒、hash/整数转换和 TTL 溢出不再静默 wrap 或直接 panic |
| 数据契约 | immutable key 使用统一可移植校验；File adapter 用临时文件、`sync_data`、hard-link no-replace 与目录 fsync 保证并发写不覆盖 |
| AWS S3 | conditional PUT 使用 `If-None-Match: *`，冲突时比较已有内容；支持 session token；凭据值不进入通用 adapter options/Debug |
| 边界安全 | Guest frame 写入检查序列化错误和 16 MiB 上限；unsafe 调用补充安全依据；vsock 所有失败路径由 `OwnedFd` 自动关闭 |

## 已有实践中值得保留的部分

- `thiserror` 用于领域错误、`anyhow` 用于进程 composition root，方向合理。
- `BlobStore`/`MetadataStore` 通过 `Send + Sync` trait object 注入，测试可替换且没有
  把 Guest/API 暴露给对象存储。
- `Cargo.lock` 纳入版本控制，适合应用型 workspace。
- 测试重点覆盖 durable FLUSH 的 crash window、RWO fencing、旧 epoch fail-closed、
  空 cache cold restore；这些比追求表面覆盖率更有价值。
- unsafe 集中在少量 OS 边界，存储提交路径没有 unsafe。

## 后续优先项

### P1：生产阻断

1. 实现 PostgreSQL `MetadataStore` adapter；SQLite + 进程内连接锁只适合单机开发，
   不能作为多节点权威 CAS/lease store。
2. 强化 AWS S3 adapter：标准 AWS credential provider chain/workload identity、有限重试
   与退避、请求校验和、Range GET、结构化 XML、限流与可观测性。当前手写同步客户端
   证明接口与 SigV4/immutability 语义，不应被视为完整生产 SDK 替代品。
3. 把同一套 object/metadata contract tests 复用于每个 adapter，并让真实 AWS S3 或
   MinIO 测试进入受控 CI；当前 live test 默认在缺少端点时跳过。

### P2：可靠性与维护性

1. 为 `ChunkEngine`、node runtime、control store 中的 `Mutex::lock().unwrap()` 明确统一
   策略：若锁中毒意味着内部不变量不可恢复，应在进程边界记录并 fail-fast；否则返回
   领域错误。现在两种策略并存。
2. 在 CI 强制 `cargo fmt --all -- --check`、`cargo test --workspace`、
   `cargo clippy --workspace --all-targets -- -D warnings`，并增加依赖漏洞/许可证检查。
3. 用 Rust 1.88 单独跑 MSRV job。声明 `rust-version` 只限制依赖解析/编译诊断，不能
   代替实际构建验证。
4. 随 I/O 并发需求评估同步 `BlobStore` port：V1 的 blocking 路径简单且可测试，
   但生产多队列需要有界并发、背压、取消和超时预算，不能靠无限制线程扩张。

## 审查边界

本审查针对当前仓库实际存在的 Rust workspace，不把设计文档中尚未实现的
vhost-user、tap/overlay、PostgreSQL 等模块视为已有代码，也不把 2026-07-21 原型
测量提升为生产 SLA。
