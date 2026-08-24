# ADR-0061：Node 本地 Golden Root 加速空 RootDisk provision

- 状态：Accepted
- 日期：2026-08-23
- 相关：[ADR-0003](0003-direct-s3-chunkstore-backend.md)、
  [ADR-0005](0005-provider-neutral-storage-ports-and-adapters.md)、
  [ADR-0017](0017-golden-root-shared-base-images.md)、
  [immutable image manifest read v1](../specs/immutable-image-manifest-read-v1.md)

## 背景

Golden Root 已按完整镜像 digest 和 4 MiB chunk digest 内容寻址，并以 manifest-last 方式发布。但是
generation-0 RootDisk provision 每次都从远端串行 GET manifest 引用的每个唯一 data object，重新下载并
SHA-256 校验完整非零镜像内容。2026-08-23 单次 metal 样本中，1 GiB logical Golden Root 有 137 个唯一
非零对象、548 MiB remote body；Root provision 为 22.948 秒，其中 remote body validation 为 18.270 秒；
完整 create 为 35.35 秒。该数字只是一个环境、一个样本和当前镜像的诊断证据，不是 SLA。

Node release 安装的 `/opt/cats/guest/rootfs.ext4` 不能充当这个缓存。worker 安装事务会把本次 release 的
Guest Agent/systemd 注入该文件；该次实测 digest 为
`2ccf1fe67e50abdacdc3519586a0d2a309f747d6c011904906dc3e573b4159c4`，而请求的产品 Golden Root 是
`d38d959f3fe1e2387a8a6313b3db7a8bf1c591ec5715a86c2dcc95c630e419e3`。因此
`--ch-seed-image` 是 release-owned Guest seed，不保证等于任意 `boot_image_digest`。Golden Root cache 必须
有独立生命周期，并由当次远端 exact bytes 填充。

直接把本地 raw 文件复制或挂给 Guest 不可接受：RootDisk 的远端 Map、owner/epoch、Strict FLUSH、Host-loss
恢复和后续 delta publish 仍必须使用既有 ChunkStore/Volume Authority 协议。本次只替换 generation-one Map
发布前的镜像内容验证来源。

## 决策

安装模式的 Node 为 Root provision 配置一个独立、Node 共享的单槽文件；production coordinate 固定为
`--golden-root-cache-image /var/lib/cats/golden-root-cache/rootfs.ext4`：

1. blockd 仍从远端读取并 canonical/structural 校验 exact requested manifest；
2. 每次 provision 都重新扫描 cache，按 publisher 相同规则计算完整文件 SHA-256、4 MiB chunk digest、
   zero-hole 和 tail padding；完整 image id 与重建 manifest 必须同时逐字段等于请求和远端 manifest；
3. 精确命中后，对 manifest 的每个唯一远端 data-object key 做存在性确认，最多 16 个并发；任一缺失或
   backend error 都在首次 volume object PUT 前 fail closed；
4. cache 缺失或不匹配时，blockd 保留既有 remote body validation：每个唯一 object 只 GET 一次并验证 exact
   4 MiB length 和 object-id SHA-256；同一批已验证 bytes 同时写入 cache 同目录的 sparse 临时文件，重复
   object 写回全部 chunk position，未引用位置保持 zero hole；
5. 临时文件必须再次扫描并得到 exact requested image id 和逐字段相同 manifest，随后才以 rename + parent
   fsync 原子替换单槽 cache。非 chunk-aligned 原始镜像不能由只保留 rounded size 的 manifest 唯一重建，
   此时放弃 cache publish，但本次已完成的远端验证和 provision 仍可成功；
6. 然后仍只发布引用远端 `images/<image-id>/data/<object-id>` 的 generation-one Map，并通过原 exact
   Volume Authority CAS 提交；本地文件不进入 Map、不成为存储 authority，也不直接服务 Guest；
7. cache 目录、写入、fsync 或重建失败只禁用本次 cache publish，不能把一个远端 exact provision 改成失败；
   远端 manifest/object、Map、CAS 或 attachment 的失败分类完全不变。不同 digest 原子替换这一单槽，磁盘
   占用有界。

单进程 cold fill 用一个 process-wide mutex 去重；cache hit 不取该锁。等待另一个 fill 的请求在取得锁后必须
重新扫描，不能重复下载。临时文件名固定且只在 fill lock 内使用；进程 crash 留下的 exact `.fill` 文件由下次
fill 删除后重建。Host-global noded lock仍保证同一 Node 没有第二个 installed Agent；跨进程争用最多让 cache
不可用，不能改变远端验证或 Volume Authority 结果。

该 fast path 依赖现有的 manifest-last publication 和 `BlobStore::put_immutable` 合同：同一内容寻址 key
不能被替换为不同 bytes。存在性检查不是第二份内容证明，也不扩大普通可变 object store 的能力；不满足
conditional immutable create/WORM/IAM qualification 的 backend 不能作为 production backend。

Node/blockd 必须记录结构化测量：验证来源、manifest/cache scan/cache I/O/remote validation/总耗时、cache
fill outcome、manifest chunk 数、唯一对象数、remote GET/HEAD 对象数与 GET bytes；fresh start 同时记录 Root
setup/provision、block frontend、VMM spawn、Guest Agent health、persistent prepare、RuntimeReady 和总耗时。
字段只用于 observation，不能参与 lifecycle 或 volume authority 决策。

## 后果与风险

命中时 create 不再搬运 Golden Root data-object body，成本变为顺序读取 Node cache、并发远端存在性确认和原
Map/CAS。对上述单次样本，预期消除大部分 548 MiB remote GET 时间；必须以上线后的结构化字段和新的 metal
样本确认实际节省，不能把约 20 秒预估写成保证。

故障检测时点发生变化：如果一个已经通过 immutable publication qualification 的远端对象后来被存储层静默
改写、而 key 仍存在，fast provision 不会在 create 阶段重新下载发现它；Guest 首次 hydrate 仍按 Map 中 SHA-256
校验并失败，不能返回错误 bytes。相比原路径，这是从 create-time fail closed 延后到 first-read fail closed。
通过 immutable backend qualification、对象存在性检查以及精确本地/manifest 绑定接受该风险；后续若 backend
提供绑定 SHA-256 的可信 HEAD checksum，可另行收紧而不改变 Map 格式。

本地 scan 每次读取 logical image bytes，会消耗 Node NVMe bandwidth；当前不引入跨请求的“已验证”内存标记，
避免文件被原地替换后的缓存失真。cold fill 还要在全部 GET 后扫描重建文件，所以第一次可能略慢，收益从同 digest
第二次 create 开始。单槽在多个 Golden Root digest 交替创建时可能 thrash，这是有界磁盘与多镜像命中率之间的
明确取舍，只影响性能。并发存在性检查固定上限为 16，避免把单次 create 变成无界远端请求突发。
