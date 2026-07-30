# ADR-0020：Strict 提交可选 S3 Express One Zone

- 状态：Deferred
- 日期：2026-07-29

## 背景

Strict FLUSH 的 ack 关键路径至少包含一次对象存储 PUT 和一次元数据 CAS
（Direct-S3 架构 §441），Standard S3 上实测最小一次 flush ~109 ms
（1 脏 chunk，c6a.8xlarge @ us-east-1，2026-07-29，
`experiments/express-one-zone-flush-20260729/`）。fsync 密集负载
（git、包安装、SQLite）的体感由这个数字直接决定。

S3 Express One Zone directory bucket 在同 AZ 内提供个位数毫秒的 PUT。
同机对照实测：最小 flush 109 → 67 ms（1.63×）；收益集中在小而同步的
提交——正是最疼的场景；大提交因上传已 16 路并发而几乎持平。

ADR-0022 已把 Relaxed FLUSH 改为本地 NVMe 持久化后 ack、后台异步发布，
因此 S3 Express **不再处于 Relaxed 的同步关键路径**。本 ADR 只讨论希望
保留远端持久化 ack 语义的 Strict 模式；它不是 Relaxed 性能方案，也不是
生产默认值。

## 实验方案（未采纳）

对象存储 adapter（`cats-object-store-aws-s3`）增加三个可选配置，全部
缺省关闭。原型在 PR #48 中完成并通过真实 directory bucket smoke，
但实现不合入主线；这里只保留实测和设计证据。未来只有在产品明确需要
Strict 远端 ack，并完成 durability、调度、IAM/Terraform 和成本评审后，
才重新评估实现：

- `signing-service`（`s3` | `s3express`）：SigV4 签名服务名。
- `virtual-host`（bool）：virtual-hosted 寻址。directory bucket 拒绝
  path-style，配置校验强制两者搭配。
- `express-session`（bool）：`CreateSession` 会话认证
  （`x-amz-s3session-token`，4 分钟刷新）。实测与 per-request SigV4
  延迟无差别（签名是本地 HMAC），保留实现以备 AWS 收紧认证要求。

不改端口语义：`put_immutable` 依赖的 `If-None-Match: *` 条件写在
directory bucket 上验证可用；list 结果无序，engine 的 GC 与恢复不依赖
顺序。

## 后果

- **持久性契约从「区域级」降到「AZ 级」**：AZ 内多设备冗余，宿主或盘
  故障仍零丢失；整 AZ 毁灭丢数据。directory bucket 不支持 S3 复制，
  兜底需自建异步复制；当前没有接受这一产品风险。
- **卷被钉在桶的 AZ**：唤醒/re-attach 必须调度回同 AZ，否则延迟优势
  归零。i4i 容量本就按 AZ 紧张，这会加剧唤醒时的容量风险。
- **实验当时存储单价 4.8×（$0.11 vs $0.023/GB·月）**，请求费反而更低（PUT
  4.4×、GET 13× 便宜），新增按字节的上传/取回费。冷卷与 golden root
  应留在 Standard 桶——**双桶分层是本 ADR 点名的后续工作**（`BaseRef`
  已有位置概念可承载）。
- Terraform/IAM：directory bucket 资源、`s3express:CreateSession`
  权限、桶名 `<name>--<az-id>--x-s3` 约定（ADR-0012 范围内跟进）。
- Relaxed 模式不从该成本与 AZ 绑定中获得 ack 延迟收益；只应在明确需要
  Strict 远端 ack 且接受单 AZ durability 的工作负载上考虑启用。

综合以上约束，ADR-0022 的 Relaxed local-first 已解决当前用户可见的
fsync 延迟问题；Cats 暂不承担 S3 Express 的运行时复杂度。

## 不做什么

- 不用 S3 Express 实现 Relaxed：该路径已由 ADR-0022 的本地 pack +
  异步 remote drain 承担。
- 不把本次单环境原型数字写成 SLA。需要 strict + <10 ms 时的区域级
  路线仍是 Replicated Write Log（§441），本 ADR 明确不做。
