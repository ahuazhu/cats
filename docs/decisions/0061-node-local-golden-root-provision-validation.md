# ADR-0061：Node 本地 Golden Root 加速空 RootDisk provision

- 状态：Accepted
- 日期：2026-08-23
- 相关：[ADR-0003](0003-direct-s3-chunkstore-backend.md)、
  [ADR-0005](0005-provider-neutral-storage-ports-and-adapters.md)、
  [ADR-0017](0017-golden-root-shared-base-images.md)、
  [immutable image manifest read v1](../specs/immutable-image-manifest-read-v1.md)

## 背景

Golden Root 已按完整镜像 digest 和 4 MiB chunk digest 内容寻址，并以 manifest-last 方式发布。Node release
同时安装 exact raw Golden Root，`cats-noded --ch-seed-image` 已携带它的 Host 路径。但是 generation-0
RootDisk provision 没有使用该文件：每个新 Cat 都从远端串行 GET manifest 引用的每个唯一 data object，
重新下载并 SHA-256 校验完整非零镜像内容。2026-08-23 单次 metal 样本中，1 GiB logical Golden Root 有
137 个唯一非零对象、548 MiB remote body；Root attach 前阶段占 create 的 24.832 秒。该数字只是一个环境、
一个样本和当前镜像的诊断证据，不是 SLA。

直接把本地 raw 文件复制或挂给 Guest 不可接受：RootDisk 的远端 Map、owner/epoch、Strict FLUSH、Host-loss
恢复和后续 delta publish 仍必须使用既有 ChunkStore/Volume Authority 协议。本次只替换 generation-one Map
发布前的镜像内容验证来源。

## 决策

安装模式的 Node 在空 RootDisk provision 时优先把 `--ch-seed-image` 作为本地验证候选：

1. blockd 仍从远端读取并 canonical/structural 校验 exact requested manifest；
2. 每次 provision 都重新扫描本地文件，按 publisher 相同规则计算完整文件 SHA-256、4 MiB chunk digest、
   zero-hole 和 tail padding；完整 image id 与重建 manifest 必须同时逐字段等于请求和远端 manifest；
3. 精确命中后，对 manifest 的每个唯一远端 data-object key 做存在性确认，最多 16 个并发；任一缺失或
   backend error 都在首次 volume object PUT 前 fail closed；
4. 然后仍只发布引用远端 `images/<image-id>/data/<object-id>` 的 generation-one Map，并通过原 exact
   Volume Authority CAS 提交；本地文件不进入 Map、不成为存储 authority，也不直接服务 Guest；
5. 本地文件缺失、I/O 失败、digest 不同或 manifest 不同，都回退既有的逐对象 remote GET、exact 4 MiB
   length 与 SHA-256 校验，不把 Node release 漂移误报成产品镜像损坏；没有配置 seed 的路径保持原行为。

该 fast path 依赖现有的 manifest-last publication 和 `BlobStore::put_immutable` 合同：同一内容寻址 key
不能被替换为不同 bytes。存在性检查不是第二份内容证明，也不扩大普通可变 object store 的能力；不满足
conditional immutable create/WORM/IAM qualification 的 backend 不能作为 production backend。

Node/blockd 必须记录结构化测量：验证来源、manifest/local scan/remote validation/总耗时、manifest chunk
数、唯一对象数、remote GET/HEAD 对象数与 GET bytes；fresh start 同时记录 Root setup/provision、block
frontend、VMM spawn、Guest Agent health、persistent prepare、RuntimeReady 和总耗时。字段只用于 observation，
不能参与 lifecycle 或 volume authority 决策。

## 后果与风险

命中时 create 不再搬运 Golden Root data-object body，成本变为顺序读取本地 seed、并发远端存在性确认和原
Map/CAS。对上述单次样本，预期消除大部分 548 MiB remote GET 时间；必须以上线后的结构化字段和新的 metal
样本确认实际节省，不能把约 20 秒预估写成保证。

故障检测时点发生变化：如果一个已经通过 immutable publication qualification 的远端对象后来被存储层静默
改写、而 key 仍存在，fast provision 不会在 create 阶段重新下载发现它；Guest 首次 hydrate 仍按 Map 中 SHA-256
校验并失败，不能返回错误 bytes。相比原路径，这是从 create-time fail closed 延后到 first-read fail closed。
通过 immutable backend qualification、对象存在性检查以及精确本地/manifest 绑定接受该风险；后续若 backend
提供绑定 SHA-256 的可信 HEAD checksum，可另行收紧而不改变 Map 格式。

本地 scan 每次读取 logical image bytes，会消耗 Node NVMe bandwidth；当前不引入跨请求的“已验证”内存标记，
避免文件被原地替换后的缓存失真。并发存在性检查固定上限为 16，避免把单次 create 变成无界远端请求突发。
