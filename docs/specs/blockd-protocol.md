# cats-blockd 目标协议

- 状态：目标合同；Chunk/Map/FLUSH 数据面已实现，Volume Authority 切换尚未实现
- 依据：[ADR-0003](../decisions/0003-direct-s3-chunkstore-backend.md)、
  [ADR-0042](../decisions/0042-volume-authority-and-disk-lifecycle.md)、
  [Cats 存储架构](../storage.md)、[Volume Authority](volume-authority.md)

本次开发期切换会删除旧 volume 和本地状态，不读取旧 pending pack，也不提供双协议。切换完成后，
改变常量、编码、提交顺序或 fencing 规则必须新增 ADR；届时再按实际持久数据决定迁移或版本策略。

## 1. 常量

| 名称 | 值 | 说明 |
|---|---|---|
| `LOGICAL_BLOCK_SIZE` | 512 B | 前端向 Guest 暴露的逻辑扇区 |
| `CHUNK_SIZE` | 4 MiB | Map寻址与完整Base的单位；稀疏提交使用64 KiB page Delta |
| `DIRTY_PAGE_SIZE` | 64 KiB | Dirty bitmap 粒度；每 chunk 64 页 = 一个 u64 位图字 |
| `CHUNKS_PER_LEAF` | 256 | 每个 Map Leaf 覆盖 1 GiB 逻辑空间 |
| `MAX_VOLUME_BYTES` | 1 TiB | 两级 Map 的 V1 上限 |
| 卷大小 | 必须为 CHUNK_SIZE 的整数倍 | 控制面在创建卷前向上取整 |

## 2. 远端对象布局（BlobStore 键空间）

```text
volumes/<volume-id>/data/<object-id>            # 不可变数据对象（整块 base 或一组脏页，见 §6.2）
volumes/<volume-id>/maps/<hex-sha256>.node      # 不可变 Map Leaf/Root 节点
volumes/<volume-id>/commits/<gen>-<txn>.json    # 不可变提交记录（审计/恢复辅助）

images/<image-id>/data/<chunk-sha256>           # 共享基础镜像的 chunk（系统所有，见 §6.3）
images/<image-id>/manifest.json                 # 镜像清单；最后写入
```

- `object-id` = `<txn>-c<chunk_idx>`；同一 txn 内对同一 chunk 幂等重传时键不变，重复 PUT 内容必须字节一致。
- 数据对象内容 = chunk 的原始字节（V1 不压缩不加密；加密引入时以对象头版本区分，另立 ADR）。
- 所有对象只写一次；GC 之外禁止 DELETE/覆写。

## 3. Map 节点编码（确定性二进制）

所有多字节整数为小端。节点哈希 = SHA-256(完整编码字节)；节点对象键 = `maps/<hex(hash)>.node`。

### 3.1 Leaf

```text
[magic "CATSLEAF"] [version u16 = 1]
[first_chunk u64] [entry_count u32]
entry_count × ChunkRef
```

`ChunkRef`：

```text
[tag u8]            # 0 = Hole；1 = Base；2 = Layered（版本 ≥ 2，见 §6.2）
tag==1 时:
  [object_id_len u16] [object_id bytes]
  [data_len u32]     # chunk 有效字节数（恒为 CHUNK_SIZE，卷尾不足时为余量）
  [sha256 32B]       # 明文校验和；READ miss 下载后必须验证
  版本 ≥ 3 追加:
  [image_id_len u16] [image_id bytes]   # 空串 = 本卷自己的对象；非空 = images/<image-id>/
```

版本按「用到才升」：leaf 只在实际包含 `Layered` 时写版本 2、只在实际包含镜像 base 时写版本 3，
所以没用到这些特性的卷 map node 逐字节不变（对象 id 也不变）。解码同时接受 1、2、3。

### 3.2 Root

```text
[magic "CATSROOT"] [version u16 = 1]
[volume_size u64] [leaf_count u32]
leaf_count × LeafRef
```

`LeafRef`：

```text
[tag u8]            # 0 = EmptyLeaf（整段为洞）；1 = Present
tag==1 时: [leaf_hash 32B] [object_id_len u16] [object_id bytes]
```

未修改的 Leaf 在新 Root 中原样引用（不重传）。读取任何 Map 对象后必须先验哈希再使用。

## 4. 权威元数据（MetadataStore）

权威`VolumeRecord`、closed transition与receipt schema唯一见
[Volume Authority §3](volume-authority.md#3-postgresql-authority-模型)。Control Store是唯一PostgreSQL DDL和
cross-row事务owner；本协议不复制第二份Volume SQL schema。SQLite只可作为blockd数据面projection/CAS及
pure-domain fixture，不实现Control事务或形成第二个authority。

blockd adapter只读取当前`volume_id`、不可变`size_bytes`、`admin_state`、exact `RemoteHead`、
`lease_owner`、`lease_epoch`和absolute `lease_expires_at` projection，以精确owner/epoch renew，并执行下面的
head CAS。它不建权威表，不执行acquire、release、takeover、revoke、resize、delete或snapshot mutation。

`RemoteHead`的generation/hash/object ID nullability和exact compare沿用Volume Authority；generation只通过
下述数据面CAS或该规格允许的Control transition前进。Root CAS（blockd提交唯一入口）必须在一条原子语句
内完成：

```sql
UPDATE volumes
   SET root_hash = :new_root, root_object_id = :new_obj, generation = generation + 1
 WHERE volume_id = :vol
   AND admin_state = 'Active'
   AND size_bytes = :expected_size
   AND generation = :expected_generation
   AND lease_owner = :attachment_id
   AND lease_epoch = :epoch;
-- 受影响行数必须恰好为 1，否则本次远端发布失败
```

`size_bytes`创建后不可变；blockd还必须验证新Root编码的`volume_size`与grant对应的VolumeRecord
一致。协议不提供resize入口。

### 4.1 Lease / Fencing

- Node先按Volume Authority取得精确grant，再把volume、attachment、epoch及既有closed acquire origin
  交给blockd；blockd只adopt该grant，不能创建或改变ownership。
- `renew_lease`必须携带当前owner/epoch和positive duration；唯一PG authority按本事务DB-now checked-add写
  absolute expiry。owner/epoch不匹配即失败，blockd进入 **fenced**：拒绝新WRITE/FLUSH（返回错误），
  在飞提交一律作废。
- 旧 epoch 的任何 Root CAS 必然 0 行受影响 —— 这是双写防护的最后一道闸，与租约到期判断相互独立。
- expiry只用于健康判断，不打开竞争acquire。短暂renewal lapse不得自我fence；只有精确release或
  授权takeover原子增加epoch后，旧Writer的renew/CAS才fail closed。
- 完整ownership/admin状态机、typed replay和错误闭集唯一见
  [Volume Authority](volume-authority.md#4-lease-接口和状态机)。blockd绝不自行增加epoch。

## 5. 本地状态（Cache + Relaxed 权威暂存）

```text
<data-dir>/identity.json               # attachment lineage；创建其他文件前原子持久化
<data-dir>/cache.data                  # 单个稀疏 cache 文件，offset = 逻辑偏移
<data-dir>/dirty.bitmap                # 持久 dirty 位图（见 §5.1）
<data-dir>/pending/<txn>.pack          # 冻结的 Pending Commit Pack
```

`identity.json`包含`volume_id + attachment_id + attachment_epoch + acquire_origin + node_id +
placement_epoch`。`acquire_origin`严格使用[Volume Authority §6](volume-authority.md#6-本地-attachment-lineage)
的closed object：`normal {transition_id: RandomId128}`或`takeover {authorization_id: Id}`。data-dir属于
这一次attachment，不能仅按volume id被下一个attachment复用，也不能从裸ID猜测acquire namespace。

- **Strict 写路径**：WRITE → 若目标 chunk 已有已提交 Base 且 cache 未水化，先整
  chunk 水化；写 cache；记录 dirty page/range。
- **Relaxed 写路径**：冷缓存局部 WRITE 不先 GET 旧 chunk。只写新 bytes，并记录
  精确 dirty byte ranges；FLUSH 把 ranges 与 payload 固定进本地 pack，后台
  publisher 才读取 remote base 并合成可发布 page/base。
- **读路径**：cache 命中直接返回；miss 按当前 Map 解析 → Hole 返回零 → Base 下载并验 sha256 后水化 cache。同一 chunk 的并发 miss 必须合并为一次下载（singleflight）。
- `R == L` 时删除整个 `<data-dir>` 后可凭远端状态重建；Relaxed 的 `R < L`
  时 pending pack 是唯一权威副本，绝不能删除。

### 5.1 dirty.bitmap

```text
[magic "CATSDRTY"] [version u16 = 1] [chunk_count u64]
chunk_count × u64（小端；bit i = 页 i dirty）
```

### 5.2 Pending Commit Pack（目标格式：内嵌冻结数据）

FLUSH 冻结时把每个 dirty chunk 本次要发布的内容拷入 pack——默认是它的脏 64 KiB 页，整块重写时是完整 chunk（§6.2）。屏障后的新写继续进 cache，不影响已冻结输入：

```text
[magic "CATSPACK"] [version u16 = 2]
[header_len u32] [header JSON]
[payload bytes…]
```

header JSON：

```json
{
  "txn": "<txn-id>",
  "volume_id": "…",
  "attachment_id": "…",
  "attachment_epoch": E,
  "acquire_origin": {"kind": "normal", "transition_id": "0123456789abcdef0123456789abcdef"},
  "base_generation": N,
  "entries": [
    {
      "chunk_idx": i,
      "payload_offset": o,
      "len": l,
      "sha256_hex": "…",
      "page_mask": m,
      "byte_ranges": [{"chunk_offset": b, "payload_offset": p, "len": n}]
    }
  ]
}
```

写入顺序：写临时文件 → fdatasync → rename 为 `<txn>.pack` → fdatasync 目录。
以上lineage字段、`page_mask`和`byte_ranges`都必须存在并通过校验。目标实现只接受version 2；旧
pack不转换、不回放，clean-slate切换前直接删除。缺失/unknown `acquire_origin`及旧裸
`acquire_transition_id`同样严格拒绝，不提供兼容解析。

## 6. FLUSH 提交协议（双持久化水位）

每卷维护 `L = local_durable_generation` 和
`R = remote_durable_generation`，始终 `R <= L`。顺序固定，不可交换
（架构边界见 [Cats 存储架构](../storage.md#flush-与双持久化水位)，完整决定见
[ADR-0022](../decisions/0022-relaxed-local-first-dual-watermark.md)）：

`L`是最高连续durable generation：`generation <= R`已远端持久，每个`R < generation <= L`都
必须存在完整、已同步的pending pack；它不表示Guest已经收到ACK。

1. 捕获屏障：冻结当前 dirty set（清 volatile 位图对应位，新写进入下一集合）。
2. 生成并落盘 Pending Pack（§5.2）；完成 fsync/rename/directory fsync 后 `L`
   前进。Relaxed 此时向 Guest ACK；Strict 继续等待。
3. 后台 publisher 按 generation 读取 pack。验证pack、data-dir identity及Node随精确LeaseGrant传入的
   closed `acquire_origin`整个variant逐字段相同；再按`byte_ranges`读取远端 base
   并按序叠加，构造完整 page/base；PUT `data/<txn>-c<idx>`（幂等，重试同键）。
4. 构造新 Leaf/Root，PUT `maps/…`；PUT `commits/<gen+1>-<txn>.json`。
5. Root CAS（§4）。恰好 1 行 → `R` 前进；Strict 此时向 Guest ACK。
6. 清持久 bitmap 中该集合的位；删除 pack。

dirty set 为空时 FLUSH 直接成功（generation 不变）。

Relaxed 的 Guest WRITE/FLUSH 线程不得调用 S3 PUT/GET 或 PostgreSQL CAS。S3/DB
普通错误由 publisher 记录并重试，不直接作为 Guest EIO；CAS owner/epoch
冲突、校验损坏、本地 fsync/ENOSPC 则仍 fail closed。到 staged/physical quota
时先 LRU hole-punch clean committed cache；dirty/staged/I/O chunks 被 pin。
只剩 pin 数据时前台在 condvar 背压，等待 publisher 回收空间。
admission 必须把“当前 dirty set 的未来 pack”作为 accounted reservation；
接近水位可隐式执行一次仅本地 stage 并 kick publisher，防止 cache 吃满后再也
没有空间生成 pack。

### 6.1 崩溃恢复规则

启动时扫描 `pending/*.pack`，先重建 `L` 和本地有序队列，不在 Relaxed attach
恢复阶段执行远端写；后台 publisher 随后对每个 pack：

- 先验证pack、data-dir identity和Node随当前精确LeaseGrant传入的完整`acquire_origin`逐字段相同，
  并验证三者的volume、attachment、epoch一致且MetadataStore仍认可该owner/epoch。normal/takeover即使
  ID文本相同也不相等；缺失、unknown variant、损坏、已fence或不匹配时整个目录
  quarantine；不能删除pack，也不能交给新attachment发布。
- 再读MetadataStore当前generation：
  - `generation > base_generation` 且 `commits/<base+1>-<txn>` 存在 → **CAS 已发生**：只清位图/删 pack，不得重复提交；
  - 否则 → 从 pack 幂等重放步骤 3–6（对象 PUT 键不变）。
- 每卷publisher在同一grant内严格按generation串行，前一pack结果未判定前不能提交后一pack；因此
  在grant仍精确有效时，上述generation前进只能包含队首txn。该不变量必须由并发测试覆盖。
- CAS 前崩溃产生的无 Root 引用对象成为 Orphan，由 GC 按 grace period 清理；恢复流程不负责删除。

### 6.2 发布粒度：Delta Pack（[ADR-0016](../decisions/0016-delta-pack-page-granular-commits.md)）

一次提交对每个 dirty chunk 只发布**该 chunk 的脏 64 KiB 页**，按页序拼接成一个对象。
未携带的页自上次提交以来未被修改，其内容已作为不可变对象存在，因此省略它们不影响点时刻
一致性——屏障必须拷贝的是**本次要发布的内容**，而不是必须是整块。

- `PackEntry` 的 `page_mask` 说明携带哪些页；`page_mask == u64::MAX`（且 `len == CHUNK_SIZE`）
  表示整块 base。该字段是必填项；缺失即拒绝整个pack。
- Map 的 `ChunkRef` 增加 `Layered { base: Option<BaseRef>, deltas: [DeltaRef] }`；`base` 为
  `None` 表示底座是空洞。后写的 delta 在重叠页上覆盖先写的。
- 对象键：base 为 `data/<txn>-c<idx>`，delta 为 `data/<txn>-c<idx>-d`。一次提交对一个 chunk
  最多产生一个对象。
- **自压缩**：满足任一条件时本次提交对该 chunk 发布新的整块 base 并清空链——链长达到
  `MAX_DELTA_LAYERS`（当前 4），或本次脏页超过半块（> 32 页）。因此冷读放大有硬上限
  （≤ 5 个对象/chunk），正确性不依赖后台 Compactor。
- 读路径在 hydration 处解析层：base（或全零）+ 按序应用 delta，一次性整块写入本地 cache；
  每个对象按其引用中的 `len` 与 `sha256` 校验。
- **GC 必须把 base 与全部 delta 都视为存活**（存活判据仍是"被当前 Root 引用"）。
- Leaf 编码只在实际包含 `Layered` 时写版本 2，未产生 delta 的卷 map node 逐字节不变。

### 6.3 共享基础镜像：Golden Root（[ADR-0017](../decisions/0017-golden-root-shared-base-images.md)）

镜像是系统所有的一等不可变工件，放在 `images/` 命名空间下（**不在任何 `volumes/` 前缀里**），
新卷通过**引用**它的 chunk 来完成 provision，不移动任何数据字节。

- `<image-id>` = 镜像文件的 sha256；chunk 对象按内容寻址（`data/<chunk-sha256>`），因此镜像内
  重复的 chunk 只存一份，全零 chunk 根本不存。卷尾不足一块的部分补零成整块。
- **发布幂等**：任何节点对同一镜像算出同一个 id，重复发布是把相同字节写到相同 key（§2 的
  `put_immutable` 契约里这是 no-op），多节点并发发布安全。
- **manifest 最后写**：读到 manifest 即意味着它引用的每个对象都已持久。半途中断只留下无引用
  的对象，不会留下「可引用但不完整」的镜像。
- **provision** 从 manifest 构造 Map（每个非空洞 chunk 一条 `Base`，`image_id` 指向该镜像），
  然后走与任何一次提交完全相同的 §6 步骤 3–5（leaf → root → commit record → Root CAS）。
  只允许在 `generation == 0` 且无未提交脏页的卷上执行。
- **写入不整块私有化**：Guest 写一页就发布一页 delta（§6.2），镜像对象继续做 base。只有写满
  半块或链达到 `MAX_DELTA_LAYERS` 才改写成私有整块 base。
- **GC**：镜像对象属于镜像而不属于卷，存活判据**不是**「某个卷的 Root 引用它」。第一版既不
  自动删除，也不提供人工删除入口；Golden Image GC不在本协议范围内。

#### 6.3.1 Root provision control effect

Cat runtime不得在blockd进程启动参数中携带`--seed-image-id`，也不得把“进程已启动”当作provision
完成。clean-slate vertical cutover删除这个隐式路径，不提供兼容解析。`--publish-image`只可保留为
operator发布immutable系统镜像的离线入口；per-Cat reconciler只读取已经发布且manifest-last的镜像。

Node先按[Runtime Reconciliation §7.1](runtime-reconciliation-v1.md#71-root-image-provision)持久化step，
再通过现有Host control socket发送唯一新增的typed命令；语义payload固定为：

```text
ProvisionRootImageRequest {
  provision_transition_id: RandomId128,
  volume_id: Id,
  attachment_id: Id,
  attachment_epoch: FenceEpoch,
  size_bytes: integer 1..=9223372036854775807,
  boot_image_digest: Sha256Digest,
  expected_blank_head: RemoteHead,
  expected_provisioned_head: RemoteHead
}

ProvisionRootImageResult {
  provision_transition_id: RandomId128,
  volume_id: Id,
  attachment_id: Id,
  attachment_epoch: FenceEpoch,
  resulting_head: RemoteHead
}

ProvisionRootImageError =
  {
    kind: "retryable",
    provision_transition_id: RandomId128,
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    problem: "image_unavailable" | "object_store_unavailable"
           | "authority_unavailable" | "local_io_unavailable"
  }
| {
    kind: "definite_conflict",
    provision_transition_id: RandomId128,
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: FenceEpoch,
    problem: "request_binding" | "image_manifest" | "target_mismatch"
           | "local_state" | "immutable_object"
  }
```

line-oriented control wire使用`provision_root_image `后接一个strict JSON request和newline；成功响应沿用
`OK `后接strict JSON result；可分类失败唯一使用`ERR `后接上述strict JSON closed error。字段沿用Runtime的
closed scalar、canonical unsigned integer和RemoteHead nullability；duplicate、缺失、unknown、错类型、额外
尾随内容都拒绝。该本地wire不参与digest或authority。OK/ERR中的transition/volume/attachment/epoch都必须
逐字段等于request；不匹配、EOF、timeout、非closed ERR或无法解析的响应只算结果不明。Node对全部OK、ERR和
结果不明都必须按Runtime §7.1读取权威head；响应本身不是receipt。

三种JSON payload各自的公开硬上限都固定为4096 bytes，对应共享常量
`PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES`、`PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES`和
`PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES`。byte数只计算prefix之后、唯一结尾LF之前的完整UTF-8 JSON
octets；`provision_root_image `、`OK `、`ERR `和结尾LF都不计入payload上限。恰好4096 bytes合法；line
reader在完整分配或解析JSON前读到第4097个payload byte即可停止。frame只接受对应ASCII prefix、一个JSON
payload和一个LF（`0x0a`）；CRLF、BOM和payload内newline都拒绝。control socket保持既有one-command-per-
connection合同：接收方只处理到第一个LF，随后response并关闭连接，LF后的bytes不属于payload且绝不解释为第二
个command/response；无需等待peer half-close来证明其未来不再发送。共享encoder只产生Runtime §16.1 CJ定义的
无BOM、无额外空白、无结尾newline的canonical JSON payload，line framer只负责添加prefix和单个LF。

三个named payload decoder只接收已经移除prefix和LF的JSON bytes，并统一返回一个窄的、非序列化逻辑错误：

```text
ProvisionRootImageWireDecodeError =
  Malformed {
    json_pointer: JsonPointer,
    problem: MalformedProblem
  }
| WireBytesLimitExceeded {
    maximum: U64,
    observed_at_least: U64
  }
```

`MalformedProblem`精确复用Runtime §16.4的closed problem集合；decoder也复用其Transport、Schema和Intrinsic
scalar的stage、logical-path tie-break及pointer回退规则，但这里没有`ContractName`、`version`、array limit、
self-digest或context-bound验证。wire超限固定返回`maximum=4096, observed_at_least=4097`；invalid UTF-8/JSON
固定root pointer。该错误只区分本地decoder失败，不编码到control wire、不映射成Runtime `ContractError`、
不进入任何digest，也不是blockd effect response。wrong prefix或frame错误在调用payload decoder之前拒绝；Node
仍把任何response decode/frame错误只当结果不明并读取权威head。

三个decoder先复用Runtime §16.4.1 Intrinsic substage 1的全部scalar验证，再只对嵌套`RemoteHead`复用
substage 3的`0/null/null`或`>0/non-null/non-null`闭合；同一payload同时失败时scalar error先于nullability。
nullability组合错误返回`invalid_value`并指向该`RemoteHead` object（request固定为
`/expected_blank_head`或`/expected_provisioned_head`，result固定为`/resulting_head`）。request中的
`expected_blank_head`必须是exact blank、`expected_provisioned_head`必须是manifest/size纯计算的exact target，
以及result head/response identity必须等于request，均需要Desired、manifest、grant或原request上下文，所以只在
effect/context validator执行，不由standalone payload decoder猜测或读取外部事实。

`retryable.image_unavailable/object_store_unavailable`表示当前image manifest或其immutable objects暂时不可
读取/写入，映射到step image的`Blocked(root_image_unavailable)`；`authority_unavailable`复用既有
`Blocked(volume_authority_unavailable)`，`local_io_unavailable`保留step并按同一token有界重试。`definite_conflict`
只表示blockd已确定的无重试安全冲突：配置/request binding不等、manifest非法、纯计算target不等、
dirty/pending/staged本地状态，或immutable key已有不同bytes；problem literal原样成为Runtime
`root_provision_conflict.problem`。fenced/owner/epoch变化不伪装成这些problem，仍由Node读取Volume authority后
走existing superseded/fail-closed分支。若authority已是exact target则不论control response都成功；若仍blank，
retryable可重试而definite conflict必须Quarantine，不能无限重放。
请求只能发给以相同volume/attachment/epoch/immutable size启动、当前owner grant仍有效且Guest I/O gate
关闭的blockd；任一字段不同零副作用拒绝。

target由请求以外的既有immutable事实纯确定计算，步骤固定如下：

1. 从`boot_image_digest`去掉`sha256:`得到64位小写`image-id`，读取
   `images/<image-id>/manifest.json`。manifest必须`version=1`、`manifest.image_id=image-id`，
   `size_bytes`为正CHUNK_SIZE整数倍且不大于request size；non-hole chunks按`chunk_idx`严格升序且唯一，
   index在manifest范围内，每项`len=CHUNK_SIZE`、`object_id`为该chunk的64位小写SHA-256。manifest-last
   语义保证这些immutable image objects在manifest可见前已durable。
2. 建立`request.size_bytes / CHUNK_SIZE`项的Map，默认Hole；每个manifest chunk变为§3的image Base：
   `object_id`和decoded SHA-256取该chunk object ID，`len=CHUNK_SIZE`，`image_id`取上述image-id。
3. 每256个ChunkRef按§3.1编码Leaf；全Hole leaf使用EmptyLeaf，其余只在内存中编码、hash并派生本卷
   `maps/<lowerhex(leaf_hash)>.node` key。按§3.2用exact request size和这些LeafRef编码Root，计算
   `root_hash=SHA-256(root_bytes)`、`root_object_id=<lowerhex(root_hash)>.node`。
4. 计算结果必须逐字段等于request的
   `expected_provisioned_head={generation:1, root_hash, root_object_id}`，且
   `expected_blank_head`精确为`0/null/null`；不匹配时在任何PUT/CAS前拒绝。

`provision_transition_id`的32位小写hex wire同时是既有commit txn，故commit record key固定为
`volumes/<volume-id>/commits/1-<provision_transition_id>.json`；同step重试必须产生相同Map/root/commit
bytes和相同immutable keys，不能生成新txn。provision commit record bytes专门冻结为下面五个字段的UTF-8
JSON：key顺序必须精确为`chunks,generation,lease_epoch,root_hash,txn`，不含空白、BOM或结尾newline；
`chunks`是manifest non-hole `chunk_idx`的同一严格升序array，`generation`固定为canonical number `1`，
`lease_epoch`是request attachment epoch的canonical unsigned decimal，`root_hash`是target hash不含
`sha256:`的64位小写hex，`txn`是`provision_transition_id`的32位小写hex。不得增加、缺失、重排字段或用
等价JSON重写已有key。blockd在flush/publish/I/O write gate内再次确认无dirty bitmap、
pending pack或staged commit，然后按leaf -> root -> commit record顺序PUT，最后执行§4的单行CAS；CAS predicate
除Active、immutable size和exact owner/epoch外，还必须匹配完整blank RemoteHead，update写入上述exact target。

相同request重放只允许两种非冲突状态：blank时重做相同PUT/CAS，或同owner/epoch下已经是exact target时返回
同一result。任何其他generation/root、owner/epoch或immutable request冲突都fail closed，绝不覆盖已有head。
blockd本地cache在target确认后按该Map重新加载，`L=R=1`且没有pending pack；这个本地状态不是成功authority。
无法证明当前进程已经加载该target时必须保持Guest I/O gate关闭并以同grant重启/重载，不能把stale
generation-zero cache交给frontend。Volume head是唯一数据authority，RuntimeCheckpoint是唯一current
effect journal，不增加provision receipt。

#### 6.3.2 Root provision fixed vector

实现不得用生产planner与blockd共享的同一个helper互相证明。下面的literal manifest跨越
`CHUNKS_PER_LEAF=256`边界；测试从这些bytes独立构造Map v3并逐字节编码两个Leaf和一个Root。固定input为：

```json
{"chunks":[{"chunk_idx":0,"len":4194304,"object_id":"1111111111111111111111111111111111111111111111111111111111111111"},{"chunk_idx":256,"len":4194304,"object_id":"2222222222222222222222222222222222222222222222222222222222222222"}],"image_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","size_bytes":1077936128,"version":1}
```

```text
volume_id = vol_golden
volume_size = 1077936128
boot_image_digest = sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
provision_transition_id = 13579bdf2468ace013579bdf2468ace0
attachment_epoch = 7

leaf first_chunk=0 entry_count=256 encoded_bytes=446
leaf_hash = 21853df0366ecb382ed81d8ec0162d84531567a835b9b16438ffddad46f2ff33
leaf_object_id = 21853df0366ecb382ed81d8ec0162d84531567a835b9b16438ffddad46f2ff33.node

leaf first_chunk=256 entry_count=1 encoded_bytes=191
leaf_hash = a353861b0cb2e42e281738da932e357017545c3fe4e8c6718239a5de82f07be4
leaf_object_id = a353861b0cb2e42e281738da932e357017545c3fe4e8c6718239a5de82f07be4.node

root encoded_bytes=230
root_hash = a3a4782016a5ec8ef71c9efd06c5e899beeab070982397c294b578fc4e341753
root_object_id = a3a4782016a5ec8ef71c9efd06c5e899beeab070982397c294b578fc4e341753.node
commit_key = volumes/vol_golden/commits/1-13579bdf2468ace013579bdf2468ace0.json
commit_record_bytes = {"chunks":[0,256],"generation":1,"lease_epoch":7,"root_hash":"a3a4782016a5ec8ef71c9efd06c5e899beeab070982397c294b578fc4e341753","txn":"13579bdf2468ace013579bdf2468ace0"}
commit_record_bytes_len = 169
commit_record_sha256 = b15b76d3cad36765db54f421200124ff27e4ffea8bf7dbd8016743069a593720
```

对应`expected_blank_head`为`0/null/null`，`expected_provisioned_head`为generation 1、
`sha256:a3a4782016a5ec8ef71c9efd06c5e899beeab070982397c294b578fc4e341753`和上面的root object ID。
第二套独立实现必须从literal input得到全部相同值和逐字节相同的commit record；只比较两个实现彼此的动态
输出不算oracle。crash test还必须让encoder A PUT该record后在CAS前退出，再由独立encoder B以同key/bytes
重放并完成blank->target CAS；字段重排或空白变化必须由literal bytes/hash oracle捕获，而不是等immutable PUT
冲突后才发现。
manifest corpus还必须逐项拒绝：version不是1、相同`chunk_idx`重复、chunk逆序、`chunk_idx=257`越界、
`len != 4194304`，以及object ID长度错误、非小写hex或与实际immutable chunk SHA-256不等。每个失败都必须在
任何Map/object PUT或head CAS前得到closed `definite_conflict.image_manifest`。

## 7. NBD 前端（开发/测试/恢复通道）

- 协议：NBD newstyle fixed（`NBD_OPT_GO`），仅导出单卷；支持 `READ / WRITE / FLUSH / TRIM / WRITE_ZEROES / DISC`。
- 传输：unix socket（默认）或 TCP。
- 语义映射：WRITE→§5 写路径；FLUSH→§6；TRIM/WRITE_ZEROES→见 §7.2；`FUA` 位按 FLUSH 处理。
- NBD 永久保留用于恢复工具、golden root seeding、readiness 探测与 oracle 测试；生产 Guest 路径见 §7.1。

## 7.1 vhost-user-blk 前端（生产 Guest 路径，Linux）

选定为生产前端（[ADR-0015](../decisions/0015-vhost-user-blk-production-block-frontend.md)）。
后端 listen、VMM connect；一个进程可同时提供 §7 的 NBD socket 与本节的 vhost-user
socket，两者服务同一个 engine 与同一个 attachment lease。

- 传输：unix socket + `VHOST_USER_SET_MEM_TABLE` 共享 Guest 内存 + 每队列 kick/call eventfd。
- 协议特性：`MQ`、`CONFIG`。virtio 特性：`VERSION_1`、`INDIRECT_DESC`、`EVENT_IDX`、
  `SEG_MAX`、`BLK_SIZE`、`FLUSH`、`DISCARD`、`WRITE_ZEROES`，`num_queues > 1` 时加 `MQ`。
- Config space：`capacity` = 卷字节数 / 512；`blk_size` = 512（与 §7 路径 Guest 可见
  几何一致）；`size_max` = 32 MiB；`seg_max` = queue_size − 2；`writeback` = 1；
  `write_zeroes_may_unmap` = 1(整块覆盖的 chunk 确实会被解除映射,见 §7.2,而 Hole 读出来就是零)。
- 请求映射（与 §7 完全同构，调用同一批 engine 入口）：

  | virtio-blk 请求 | 语义 |
  |---|---|
  | `IN` | §5 读路径，`sector * 512` 偏移，长度为可写描述符总长减状态字节 |
  | `OUT` | §5 写路径 |
  | `FLUSH` | §6 提交协议；dirty set 为空则直接成功 |
  | `DISCARD` / `WRITE_ZEROES` | 见 §7.2；每段 16 字节 `{sector, num_sectors, flags}` |
  | `GET_ID` | 返回 volume id（截断到 20 字节） |

- 状态码：成功 `OK`；未知请求类型与未定义 flag `UNSUPP`；越界、fenced attachment
  与其它 engine 错误 `IOERR`。**fenced 必须 fail closed**：旧 epoch 的写和 FLUSH 都返回
  `IOERR`，不允许 ACK 永远无法提交的数据。
- 每个队列一个 worker 线程；队列数不改变提交协议，FLUSH 始终是整卷屏障。
- 畸形描述符链（缺状态字节、header 被截断）只失败该请求并记日志，队列继续服务。

### 7.2 TRIM / WRITE_ZEROES:整块丢弃变成 Hole

被**完整覆盖**的 chunk 走「丢弃」而不是写零:提交对它不发布任何对象,Map 项改成 `Hole`。
它引用过的对象因此不再可达,GC 就能收走(§9),而且这个 chunk 之后的冷读一个对象都不用取。
写零的老做法正好相反——每个 chunk 发布 4 MiB 的零,还让旧对象继续活着。

- **没被整块覆盖的部分仍然写字面零**,因为半块的 chunk 里还有数据。
- 本地 cache 仍然被清零:它比这次丢弃活得久,读者直接命中它。
- **丢弃不进 dirty bitmap**,所以提交前崩溃会丢掉这次丢弃(旧内容回来)——TRIM 是建议性的,
  这可以接受;重新 attach 时 cache 会按 Map 重新 hydrate,不会不一致。
- **提交前又写了这个 chunk**:丢弃不能简单取消。丢弃已经把该 chunk 在 cache 里清零了,如果只
  发布新写的那几页,那些零就永远到不了对象存储,被丢弃的数据会在下次冷读时复活。所以此时
  **整块转为 dirty**,把 cache 里的真相(零 + 新写)整块发布。
- pending pack 用 `page_mask == 0` 表示丢弃(delta 至少携带一页,所以不会混淆),恢复重放得到
  同样的结果。

## 8. 正确性判据（测试必须覆盖）

1. Strict：任意时刻 kill -9/删除 Host 后，已 ACK FLUSH 从远端可恢复；
   Relaxed：同 Host blockd 重启从 pack 恢复全部 ACK 数据，Host 永久丢失只承诺
   `R`；`L-R`、bytes和oldest age只能报告最后一次Node observation，不得声称是故障瞬间的
   精确损失量。
2. 仅在 `R == L` 且release完成后删除普通本地状态，空缓存懒读全卷digest与删除前一致。唯一例外
   是disposable Root：精确Owned->Deleting删除授权CAS已成功、旧epoch已fence后，才删除该
   attachment lineage的`R < L`tail。
3. normal acquire不能越过任何owner；逐卷授权takeover增加epoch后，旧blockd无法完成任何Root
   CAS或继续ACK写；单纯expiry lapse不自我fence。
4. 同一 txn 重放不产生第二个 generation。
5. Hole 读取恒为零且不产生远端 GET。
6. Relaxed 冷 cache 局部 WRITE/FLUSH 不产生远端 GET；publisher 合并后 fresh-host
   byte digest 一致。
7. Stop/Cold、Warm、`cats sync`和计划迁移必须drain到`R == L`；失败保留pending、lease与源
   runtime，重试成功前不得越过生命周期边界。磁盘成员关系与DiskSnapshot只允许Cold/unowned；
   volume容量创建后不可变。
8. blockd restart只有在data-dir identity、全部pending pack、Runtime inventory evidence和Node从服务器端
   acquisition marker投影并随精确grant传入的完整`AcquireOrigin`逐字段相同时才adopt；同文本不同variant、
   missing/unknown origin或旧裸字段都quarantine且不发布Root。
9. Root provision逐个覆盖manifest/leaf/root/commit PUT前后、CAS前后、CAS成功响应丢失和blockd/Agent
   restart；同一持久step只产生同一generation-1 target与commit key。wrong image/size/grant/head、
   非blank predecessor、pending/dirty/staged write均在CAS前拒绝；exact target可重放，exact blank
   可重试，任何其他generation绝不覆盖。测试还必须断言provision确认前Guest frontend没有listen且VMM未启动。
10. 三个Root provision payload decoder分别覆盖4096/4097-byte边界、invalid UTF-8/JSON、duplicate/missing/
    unknown/type/value和member-order置换的固定error选择；encoder roundtrip必须逐字节canonical。line framer另测
    exact prefix+4096-byte payload+LF可达decoder，CRLF、错prefix、payload内额外LF和第4097个payload byte在
    bounded read内拒绝；LF后即使peer继续发送也不得执行第二个command。每个`RemoteHead` nullability错误还要断言
    object pointer，而exact blank/target/response identity只在context tests验证。Node把所有response framing/decode
    失败只作为结果不明后读取权威head。

### 8.1 控制命令与可观测性

- `provision_root_image`只实现§6.3.1的blank->generation-1 exact effect；它只在Guest I/O gate关闭时可用，
  不格式化PersistentDisk、不接受任意target，也不替代normal FLUSH。
- `status` 返回 durability mode、local/remote generation、unpublished
  generations/bytes/oldest age、max staged/local bytes、allocated/accounted
  bytes、eviction、backpressure、fenced、last publish error以及精确attachment lineage。
- `drain`只在`R == L`后成功；它不释放lease。Node停止blockd后调用MetadataStore的幂等release。
  任一步失败必须可重试，不能清理journal。
- blockd不执行volume delete。disposable Root必须先停止blockd，再由Node消费
  [Volume Authority §11](volume-authority.md#11-delete)的精确删除授权；只有MetadataStore已返回
  Deleting/新epoch，Node才可删除授权中的本地lineage。
- 上述 quota 当前是每卷隔离；不是跨 blockd 进程的 Host 总容量证明。

## 9. GC（对象回收）

存活判据是**从卷当前 Root和全部DiskSnapshotRecord Root可达**:root节点、它命名的leaf节点,以及每个
`ChunkRef`命名的每个对象——delta pack之后这意味着**base加上它的全部delta**,而不是"每个
chunk最新的那个对象"。删掉一个chunk的base只留最新delta,会直接损坏该chunk。任一record命名的Root无法
读取或校验时，本轮GC fail closed，不删除任何对象。

- **绝不碰 `images/`。**镜像对象属于镜像、被所有从它 provision 的卷共享,删一个卷不能删掉全队列
  的 rootfs(§6.3)。GC只列举和删除本卷前缀下的对象;`ChunkRef`里带image origin的base根本
  不算本卷的对象。第一版不提供Golden Image删除或GC。
- **必须持有卷租约运行**,这样没有别的写者会在发布 Root 尚未命名的对象。本写者自己的 pending
  pack 无所谓:恢复会从 pack 文件重放并重新上传被删掉的对象。
- **commit record 不删**:它是审计线索、体积极小,清理它属于保留策略而不是垃圾回收。
- 完全被后来的 delta 覆盖的旧 delta**根本不会进入 Map**:`with_delta` 在追加时就把
  `page_mask` 被新 delta 完全覆盖的旧 delta 丢掉了(它在 hydration 里会被逐字节覆盖,留着只是
  让链更长、冷读更贵、GC 还得当它活着)。

入口有两个:

- `cats-blockd --collect-garbage`:附着、扫一遍、退出,不需要监听套接字。
- 服务期间**按 `--gc-interval-ms` 定时自动跑**(默认 600000,设 0 关闭)。默认开着,因为没有它
  被取代的对象会伴随卷的整个生命周期堆积,而**只有持有租约的这个进程有资格扫**。扫描失败只是
  记一条 warn,下一轮重试,不会挡住 Guest。
