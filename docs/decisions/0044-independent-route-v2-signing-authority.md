# ADR-0044：Route v2 使用独立的签名与公钥环 authority

- 状态：Accepted
- 日期：2026-08-10
- 关联：[ADR-0041](0041-node-verified-route-admission.md)、
  [Route Grant v2](../specs/route-grant-v2.md)
- 规格：[Route v2 Signing Authority v1](../specs/route-signing-authority-v1.md)

## 背景

ADR-0041 已经决定由 Control Plane 使用一把 active Ed25519 private key 签发短期 Grant，Node
用有界、版本化 public-key ring 做最终验证，并采用 verifier-first rotation。但原合同没有冻结
private key 的独立 secret reference、Control/Node 安装 artifact、持久 rotation lineage 或
Node ACK 的精确消费边界。

仓库仍有 V1 Route Grant key；A19 另有每 Node registration key，A23 另有 deployment
provisioner key。这三者都拥有不同 principal、签名 domain、轮换和撤销语义。复用其中任一把 key
会把已经分开的 authority 重新合并，也会让旧 deployment 或旧 bearer 意外打开 Route v2。

## 决策

1. Route v2 建立独立的 signing authority。它不复用 A19 Node key、A23 provisioner key、V1
   Route key、shared service/admin bearer、Workspace token 或 HTTP header 自报身份。
2. Control 只从固定、canonical、root-owned signer descriptor 取得非 secret lineage；Terraform
   只保存 descriptor、public ring、secret reference 和读取权限。private bytes 由独立 secret
   channel 安装到固定 root-only file，不进入 Terraform value/state、JSON、argv、environment 或日志。
3. Node 只安装同一 authority 的固定 public-ring artifact。每把 key 的 `kid` 必须从 exact
   canonical Ed25519 SPKI DER 重算；ring 最多八把、严格排序、版本单调且整环原子替换。
4. Control PostgreSQL 最终保存 signer descriptor 的单调 revision、exact digest、active/disabled
   state、当前发布的 ring pointer、永久 secret-reference/key lineage，以及换 key 时的
   `last_old_issue_at`。每次 resolve 必须在同一 signer snapshot 中证明进程内 descriptor 等于
   current persisted authority；旧 replica 不能只因仍持有 private bytes 继续签发。
5. rotation 固定为：发布 overlap ring、全部 schedulable Node ACK exact version/digest、切换 active
   signer 并持久化 `last_old_issue_at`、等待最大 TTL 加 clock skew、发布移除 old key 的 ring 并再次
   等 ACK，最后永久 retire old lineage 并删除 old secret。成为 schedulable 也必须 ACK 当前发布 ring。
6. key 泄漏或 authority 不自洽时先持久 disable signer并停止新签发；reachable Node 关闭 admission，
   unreachable Host 外部隔离。只有 fresh ring 已安装并 ACK 后才能恢复。删除 public key 本身不终止
   已存在 stream。

## 当前实现边界

当前实现包含 canonical artifact codecs、固定路径/metadata reader、private/public pair check，以及 Node
production full-inventory 对已安装 public ring 的只读 exact observation。Control 的 signer snapshot 会消费
该 observation 中的 exact version/digest/sorted kids；artifact 缺席保持 unavailable，存在但无法完整验证时
不接受该轮 full inventory。PostgreSQL现已保存revision-one immutable exact descriptor、current exact
projection和permanent key/secret-reference lineage；startup只允许initial install或exact replay，不把合法本地
successor自动当作rotation authority，且resolve可在共享lock内比较进程内binding与PG current。它仍不实现
public-ring installer、successor/rotation writer、schedulable全量ACK rollout、Control/Node TLS listener或proxy。
Gateway PG principal虽已落库，但machine listener组合完成前仍保持关闭，不能用测试constructor或旧authority
补齐。

上述Gateway与signer表共同属于尚未合流部署的exact clean-slate schema 13最终形态；此前Gateway-only提交不是
可独立部署的version 13迁移，也不允许当前stamp启动时补表或repair catalog。

## 后果

- Route v2 private key 不再需要出现在 Terraform state；代价是 secret installer、持久 rotation
  writer 和 ACK rollout 成为明确的生产组件。
- rolling deployment 中 stale/same-revision-conflicting replica 会 fail closed，不能靠本地文件多数
  或启动顺序决定 authority。
- public ring 可以安全分发到 Node，但它只是 verifier input，不会成为 Endpoint、placement 或
  admission 的第二份 authority。
