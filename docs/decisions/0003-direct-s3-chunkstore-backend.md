# ADR-0003：Direct-OS ChunkStore 是唯一生产存储后端

- 状态：Accepted
- 日期：2026-07-21

## 决定

`cats-blockd` 原生实现 **Direct-OS ChunkStore**。Direct-OS 表示 block engine 直接管理
对象存储中的 immutable data/Map/commit objects 和 MetadataStore 中的 current Root、
generation、attachment owner 与 fencing epoch。第一个生产组合是 S3-compatible object store
加 PostgreSQL，称为 Direct-S3。

Guest 只看到标准 virtio block 与普通 ext4，不持有对象存储或 MetadataStore 凭据。生产数据
路径只有这一套；`BlobStore` / `MetadataStore` ports 继续承载 provider-neutral 合同、测试替身
和故障注入，不代表并行的生产存储语义。

## 权威与持久性

- Object store 保存 immutable bytes；MetadataStore 的原子 Root CAS 选择当前 generation，
  owner/epoch CAS 是 RWO writer 的最终权威。
- 每个卷维护 `R <= L`。Strict 仅在 object/Map/commit 已持久且 Root CAS 成功后 ACK；
  Relaxed 在 pending pack 完成本地 fsync/rename/directory fsync、`L` 前进后即可 ACK。
- `R < L` 时 pending pack 是唯一权威数据，不能被 eviction、生命周期清理或 Agent 重启当作
  cache 删除。Warm、Cold、Snapshot、detach 和计划迁移前必须 drain 到 `R == L`。
- 正常 attach 遇到其他 owner 时 fail closed；只有安全 handoff 或可信 Host fence 后才能提高
  epoch。旧 epoch 的 renew、publish 和 Root CAS 必须永久失败。

## 数据格式

当前格式使用 4 MiB logical Chunk、64 KiB dirty page、page-granular Delta、最多四层 Delta 后
重写 Base、两级 immutable Merkle Map，以及 content-addressed Golden Root。小写只发布 dirty
pages，不上传完整稀疏盘；冷读对象数有硬上限，不依赖后台 compactor 保证正确性。

[blockd protocol](../specs/blockd-protocol.md) 是常量、编码、提交顺序、恢复和 fencing 的规范；
改变 persisted format 或协议语义必须通过 ADR，并提供版本或迁移边界。组合架构与当前缺口见
[`storage.md`](../storage.md)。

## 证据边界

自动化覆盖提交崩溃点、pending replay、CAS 歧义、RWO fencing、Base/Delta 合并、Golden Root、
Relaxed 本地恢复与两种 block frontend。仓库还保留真实 KVM + Cloud Hypervisor + ext4、真实
S3，以及双 Node S3 + PostgreSQL Cold 恢复的限定环境证据：

- [裸金属全栈闭环](../../experiments/metal-e2e-20260721/README.md)
- [vhost-user-blk 与存储机制](../../experiments/vhost-user-blk-frontend-20260726/README.md)
- [双 Node Cold 迁移](../../experiments/metal-cluster-20260726/README.md)
- [Relaxed 本地提交边界](../../experiments/relaxed-local-first-20260730/README.md)

这些结果只证明记录的 revision、环境、样本和 correctness oracle，不是生产 SLA 或规模证明。

## 风险与上线门

- FLUSH、Map、GC、fencing 与 recovery 的正确性由 Cats 自证；必须持续运行 malformed input、
  crash injection、stale epoch、empty-cache restore 和 digest oracle。
- S3 请求成本、小写放大和冷读放大必须同时观测 Guest bytes、remote bytes、PUT 数和读取对象数，
  不能用单一吞吐隐藏成本。
- PostgreSQL/S3 故障不得绕过 CAS。目标部署仍需验证 Multi-AZ failover、备份恢复和超时风暴。
- Relaxed 没有跨 Host pending 副本，不能承诺 Host loss RPO 0；每卷 quota 也不是 Node 总容量证明。
