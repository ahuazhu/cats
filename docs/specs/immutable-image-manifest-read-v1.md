# Immutable Image Manifest Read v1

- 状态：Frozen target contract；尚未实现
- 上位决策：[ADR-0017](../decisions/0017-golden-root-shared-base-images.md)
- Object port：[ADR-0005](../decisions/0005-provider-neutral-storage-ports-and-adapters.md)
- 数据面消费者：[blockd protocol §6.3.1](blockd-protocol.md#631-root-provision-control-effect)
- 产品消费者：[Volume Authority §8.1](volume-authority.md#81-disk-create)

本文冻结 operator-published golden root manifest 的唯一 provider-neutral 读取、编码和结构验证边界。
它让 `cats-blockd` 与 Control Plane 的 Cat-create service 消费同一个 DTO、validator 和 reader，而不让
Control Plane 依赖 `cats-blockd`，也不增加 image catalog、alias、tag、数据库 row 或第二份 manifest
authority。

## 1. Identity、key 与 authority

Runtime `boot_image_digest` 是完整原始 image file bytes 的 SHA-256，以
`sha256:<64 lowercase hex>` 表示。ADR-0017 的 `image-id` 是同一 32-byte digest 的裸
`<64 lowercase hex>` 表示；两者不是两个 digest。它们都不是 manifest artifact bytes 的 SHA-256，也
不是任一 chunk object digest。

唯一 manifest object key 是：

```text
images/<boot_image_digest去掉sha256:后的64位lowercase hex>/manifest.json
```

reader 只对调用方已经通过 `Sha256Digest` 验证的 digest 做这一机械转换。不得接受 raw key、prefix、URL、
image alias/tag、catalog lookup、redirect、fallback digest 或请求提供的 manifest bytes。对象存储中的 exact
immutable bytes 是 manifest authority；PostgreSQL 不缓存或复制其内容。manifest-last publication 保持
ADR-0017 语义：data objects 全部 durable 后才 `put_immutable` canonical manifest bytes。

## 2. Provider-neutral core contract

唯一 DTO、canonical encoder、decoder/validator 与 reader 位于 `cats-storage`。provider adapter 只实现
`BlobStore` I/O；AWS S3、file adapter、blockd 和 Control Plane 不得各自定义 JSON DTO 或结构 validator。

逻辑 API 是：

```text
ImageManifestV1 {
  version: 1,
  image_id: LowerHexSha256,
  size_bytes: u64,
  chunks: [ImageManifestChunkV1]
}

ImageManifestChunkV1 {
  chunk_idx: u64,
  object_id: LowerHexSha256,
  len: 4194304
}

read_image_manifest(blob, boot_image_digest) -> ImageManifestV1
```

`LowerHexSha256` 是进程内 closed newtype，不以未验证 `String` 穿过 core boundary。`cats-blockd` 的 map
类型只消费已验证 DTO；原来位于 blockd `format::ImageManifest/ImageChunk` 和 `image::load` 的重复定义必须
删除或改成该类型的单向使用，不能保留两个 validator。

manifest 读取使用 `BlobStore::get_bounded(key, 33554432)`。port 的成功结果保证实际读取 body 不超过 cap；
production adapter 不能先无界收完整 response 再检查长度。file adapter 在分配前检查 file metadata 并仍对
实际读取计数；S3 adapter 对 `Content-Length` 做 early reject，并以 streaming read 最多收
`maximum + 1` bytes，不能只信 header。其他 adapter 可以使用 port 的保守默认实现，但不能宣称 production
resource bound，除非相同 contract suite 证明它在错误/缺失 length 下也有界。

`IMAGE_MANIFEST_MAX_BYTES = 33554432`（32 MiB）。V1 最大 1 TiB image 最多 262144 个 4 MiB chunk；即使
每个位置都 non-hole，canonical document 仍小于此 cap。恰好 cap 可以进入 decoder；观测到第
33554433 byte 立即返回 `TooLarge {maximum:33554432, observed_at_least:33554433}`，不解析 JSON。

## 3. Exact canonical bytes

manifest object 必须是单行 UTF-8 JSON，无 BOM、前后 whitespace 或结尾 newline。object member 使用下列
exact 顺序，数字只用 canonical unsigned decimal `0|[1-9][0-9]*`，string 不使用可替代 escape：

```text
manifest: chunks, image_id, size_bytes, version
chunk:    chunk_idx, len, object_id
```

数组 item 之间只用 `,`，name/value 之间只用 `:`，其他位置没有 whitespace。decoder 先完成有界 UTF-8/JSON
扫描，再要求由 decoded、已通过 schema 的 DTO 重新编码出的 canonical bytes 与完整 object bytes 逐 byte
相等。member order、任意 whitespace、等价 escape、`1.0`/`1e0`/`-0`、duplicate/unknown/missing field、
trailing bytes 和 BOM 全部是 `Corrupt`；不提供旧 reader fallback。

空 chunk fixed vector 是以下 exact 124 bytes：

```json
{"chunks":[],"image_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","size_bytes":4194304,"version":1}
```

```text
SHA-256(exact manifest bytes) = e250eb35ef5804002b6afebcc410cba2df75f38c1761c5bf2d5d00a57e8c7d02
```

该 checksum 只校准 exact artifact bytes，不进入 image identity 或 Runtime `boot_image_digest`。
blockd §6.3.2 的非空 fixed manifest也必须逐 byte 使用本节 member order。

## 4. Structural validation order

canonical bytes 通过后，validator 按固定顺序验证全部结构，任一失败不返回半份 DTO：

1. `version == 1`；
2. `image_id` 是 64 位 lowercase hex，且逐 byte 等于 requested `boot_image_digest` 的 hex；
3. `size_bytes` 为正数、`<= 1099511627776`，且是 `CHUNK_SIZE=4194304` 的整数倍；
4. `chunks.len() <= size_bytes / CHUNK_SIZE`；
5. chunk 按 `chunk_idx`严格递增，因此唯一；每个 index `< size_bytes / CHUNK_SIZE`；
6. 每项 `len == 4194304`，`object_id`是64位 lowercase hex。

reader 不读取每个 data object；manifest-last publication 与 immutable namespace 是 Control Plane
create-time existence/shape判断的边界。`cats-blockd`在真正 provision 前继续读取每个唯一 referenced data
object，验证 exact 4 MiB length 与 object-id SHA-256，缺失或内容错误仍按 blockd §6.3.1 fail closed。
Control Plane 的 manifest read 成功不承诺未来 object availability，也不创建 capacity/image reservation。

## 5. Closed outcomes 与 replay

provider-neutral reader 只返回：

```text
ImageManifestReadError =
  NotFound { key }
| TooLarge { maximum, observed_at_least }
| Corrupt { key, problem }
| BackendUnavailable { key }
```

`problem` 是 bounded、closed 的内部分类：`invalid_utf8_or_json | non_canonical_bytes |
unsupported_version | identity_mismatch | invalid_size | invalid_chunks`；不得包含 object response、凭据、
bucket、endpoint 或 parser debug dump。Blob `NotFound`只映射 `NotFound`；invalid key、I/O、timeout、5xx 和
未分类 adapter failure映射 `BackendUnavailable`，不能伪装成不存在。`TooLarge/Corrupt`是确定的当前 object
冲突；`NotFound/BackendUnavailable`可以在同一 digest/key下有界重试。

reader 无持久 replay row。相同 digest 每次机械读取相同 immutable key；成功必须返回逐字段相同 DTO。
若同一 key 后来返回不同 bytes，adapter 已违反 immutable object contract，reader按当次 bytes fail closed并
进入 fatal operational alert，不能接受“后来修正”的第二 manifest。Cat-create 的 HTTP response-loss replay
仍由 `ApiIdempotencyResult`优先命中，命中时完全不读取 manifest；只有 result miss 才调用本 reader。

## 6. Production composition 与最小权限

`cats-controld` composition root 静态注册现有 `object-store-file`（仅开发/测试）和
`object-store-aws-s3` adapter，通过与 blockd 相同的 provider-neutral `adapter name + key=value options`
构造只读 `Arc<dyn BlobStore>`，再构造唯一 manifest reader。Control Plane production config不接受 bucket
URL、raw manifest、catalog endpoint或 inline fixture；selected adapter/key prefix必须明确指向部署的
ChunkStore namespace。

AWS Control Plane workload identity只授予：

```text
s3:GetObject arn:...:<chunkstore-bucket>/<configured-prefix>/images/*/manifest.json
```

不授予 image data、`volumes/`、ListBucket、PutObject、DeleteObject或 MetadataStore writer权限。
S3 bucket、region、prefix仍只存在于 composition/deploy adapter config，不进入 `cats-storage` domain types。
Kubernetes/runtime Secret只保存非公开的配置引用；AWS workload identity提供凭据，不把access key放入参数、
环境、Terraform output或日志。local/metal development可以显式选file adapter，但 production readiness拒绝它。

## 7. Clean-slate cutover gate

当前 publisher 以 Rust struct declaration order 写出
`version,image_id,size_bytes,chunks`，旧 reader也接受 whitespace/member-order变化；这些旧 bytes不是本合同
的 canonical artifact，不能被新 reader接受，也不能在同一个 immutable key下覆盖。

上线前必须在旧协调组件完全退出、目标组件尚未启动的维护窗口执行：

1. 在一个 Control PostgreSQL transaction snapshot 扫描全部 current Desired、Disk/Root、snapshot retained
   root 和任何 image reference projection，证明目标 image namespace没有 live 或 retained reference；扫描
   incomplete、schema不可信、数据库不可用或出现任一 live/unknown reference都停止 cutover；
2. 只有上述零引用 proof成功，才可按reviewed manifest精确删除 qualification/development旧 image namespace；
   生产namespace若无法证明零引用，不删除、不覆盖、不启用双reader；
3. 使用新 canonical publisher重新发布 operator image，验证manifest fixed vector/cap/identity与全部 data
   objects，再启动 Control Plane/Node；
4. qualification分别从 Control Plane reader与 blockd provision path读取同一个 exact object，重算 bytes
   checksum并验证相同 DTO。

该 proof 是一次 cutover admission，不成为新的运行时数据库 authority或永久 image catalog。V1 不保留旧
noncanonical parser、legacy key、alias或版本协商。

## 8. 最小验收

- exact key正例；prefix/digest/manifest identity任一改变拒绝且不查询第二key；
- fixed vector逐byte编码/解码和checksum；legacy struct-order、member reorder、前后/内部whitespace、newline、
  BOM、等价escape与非canonical number全部拒绝；
- 33554432/33554433边界，S3缺失/错误/伪造`Content-Length`下实际read仍有界；
- duplicate/unknown/missing/wrong-kind字段、version、digest大小写/长度、zero/非对齐/>1TiB size；
- 262144项上界、重复/倒序/越界index、wrong len/object digest；
- `NotFound/TooLarge/Corrupt/BackendUnavailable`映射不混淆且error不泄漏provider secret；
- reader不GET data objects；blockd仍逐唯一object验证length+digest；Cat fast replay零manifest GET；
- file/AWS adapters复用同一个 core contract suite；Control Plane没有blockd依赖、catalog/DB fallback；
- IAM只允许exact manifest namespace GET，data/volume/LIST/PUT/DELETE全部显式拒绝；
- cutover有live/unknown ref时零删除且不Ready；零引用后旧noncanonical artifact清理、新canonical publish和两消费方
  exact read全部通过。
