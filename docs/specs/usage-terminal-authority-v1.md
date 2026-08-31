# Usage Terminal Authority v1

- 状态：Frozen archive/terminal schema v16；producer/auth 由 ADR-0063 修正
- Terminal authority：[ADR-0047](../decisions/0047-terminal-usage-archive-and-projection-authority.md)
- 当前 producer/auth：[ADR-0063](../decisions/0063-semantic-node-usage-metering.md)

## 1. Source terminal

compute source 固定为 `node/<node_id>/cat/<cat_id>`，meter 集合按 slug 排序为
`cats.compute.cpu.v1,cats.compute.memory.v1`。usage-store v16 保留以下 persisted binding 字段：

```text
RuntimeUsageSourceBinding {
  node_id,
  node_boot_id,
  agent_instance_id,
  agent_epoch,
  desired_revision,
  runtime_incarnation
}
```

这些字段现在是 producer process/runtime 的兼容坐标，不是 AgentSession、Desired 或 lifecycle authority。
`agent_epoch` 由 noded 进程启动时的 ordinal 填充，`desired_revision` 使用 semantic compatibility
generation；Control 不再查询 current AgentSession 或解码签名 source epoch。

noded 为每个 live Cat runtime 建立 cgroup lane，以 `runtime_incarnation` 作为 `source_epoch`，周期发布
`epoch_marker=open` 的 CPU/memory 累计 pair。Cold、Destroy 或 runtime replacement 关闭 lane 时，Node
读取最后可得 counter，并发布同 sequence、time、Cat、binding 的 `epoch_marker=final` pair。marker 进入
deterministic event ID；同 metric/sequence 的 open 与 final 不是同一 event。

投递通过 semantic Node service token；Control 以当前 `cats.node_id` 或
`cats.current_action_node_id` 限定 claimed Node 可为哪些 Cat 开启 epoch，并从当前产品 row 冻结 Workspace
与 Billing Account。producer 不能选择计费归属。

当前 Node queue 是有界内存队列，final delivery 也是 best effort；它没有旧
`usage_pending_final`、inventory observation promotion 或 durable tombstone。丢失 final 会使 terminal
receipt 保持 absent，只能解释为“尚未证明 terminal”，不能解释为零 usage 或清理许可。

projector为每个event保存：

```text
UsageArchiveEvidence {
  stream_name, archive_bucket, shard_id, sequence_number,
  archive_key, archive_sha256
}
```

`sequence_number`是1..=78位canonical unsigned decimal；SHA固定`sha256:`加64位lowerhex。archive key
指向包含exact attributed envelope的immutable NDJSON object，SHA对完整对象bytes计算。event projection和
evidence都存在后才可参与terminal receipt。

`UsageSourceTerminalReceipt`固定`contract_version=1`，包含source/Cat/binding、final sequence/time，以及按slug
排序的两个`{event_id,metric,cumulative_quantity,archive}`。receipt JSON exact bytes另存SHA-256并受insert-only
trigger保护。以下任一情况均不生成receipt：缺一个meter、extra/final重复、sequence/time不同、binding漂移、
brand-new record位于final之后、event未archive或未project。

source receipt discovery固定为`POST /v1/admin/usage/source-terminal/discover`，body仅允许
`{source_id,source_epoch}`；200 body直接是receipt，404表示“尚未证明terminal”。所有receipt/request canonical
bytes均为按本规格字段声明顺序、无多余空白的compact UTF-8 JSON；digest为这些exact bytes的SHA-256，格式
`sha256:`加64位lowerhex。

## 2. Exact delivery ACK

response必须与request相同长度和顺序：

```text
results: [{event_id, outcome: accepted|exact_replay|rejected, reason?}]
```

`reason`只在rejected存在。`accepted/duplicates/rejected[]`是由results导出的诊断镜像，逐项不一致即整批ACK
无效。Node只在全部result为accepted/exact_replay时删除完整exact in-memory pending prefix；不做部分删除。HTTP timeout、
5xx、body读取/解码失败、缺项、错序、重复/foreign ID和rejected都保留prefix。413只缩小尚未获得任何成功
response的有序batch，不改变event bytes。

## 3. Target terminal barrier

global request以唯一`terminal_epoch_id`持久化，并含：release commit/artifact digest、old/fresh
`UsageTargetBinding`、按`source_id,source_epoch`排序的完整source terminal receipt key+digest集合及其集合digest。
集合digest不是任意JSON object key排序：它固定对typed array的compact bytes计算，每个member字段声明顺序恰为
`source_id,source_epoch,receipt_sha256`，且无末尾LF；文件级evidence仍独立使用递归key-sort canonical JSON。
target binding固定AWS account/region、usage schema、Kinesis name+ARN、DynamoDB checkpoint table name+ARN、
archive bucket name+ARN。old/fresh四项必须逐项不同，archive均验证Object Lock，fresh schema为空且总schema
version恰为16。

coordinator对稳定、无closed parent的open shard集合各写一个marker。marker ID是terminal request digest与
shard ID的length-framed SHA-256；payload不含attempt time。PutRecord response loss只重发相同payload。Projector
遇marker立即flush当前batch，完成immutable archive、marker projection，再推进该shard DynamoDB checkpoint。
duplicate marker允许占不同sequence，receipt为每个shard选择最小已projected canonical sequence并要求
consistent-read checkpoint大于等于它。list-shards在写前/完成前必须逐字段相同；reshard使operation保持pending。

全部shard和source验证完成后生成`UsageTargetTerminalReceipt`，先以
`terminal/v1/<terminal_epoch_id>.json`在old archive执行no-replace exact compare，再在PostgreSQL insert-only
commit。discovery必须同时比较request digest、S3 exact bytes/SHA和PG receipt；只存在任一侧均为pending或
corruption，不能授权reset。旧Kinesis/DynamoDB可删除，但old/fresh immutable archive都保留。

管理面只复用既有admin认证：`POST /v1/admin/usage/target-terminal/begin`接收exact request，返回
`prepared|exact_replay`及request digest；`POST /v1/admin/usage/target-terminal/complete`接收同一request，只有
HTTP 200、`state=terminal`且receipt非空表示成功，HTTP 202/`pending`绝不授权清理。marker ID为request digest与
shard ID分别用u64 big-endian byte length framing后的SHA-256，固定前缀`usage_terminal_marker_`。

离线reset只调用release member `cats-usage-terminal-receipt-verifier`。除canonical target receipt与其exact request
journal外，它还必须读取manifest绑定的root-only `usage-terminal-targets` v1文件及其expected SHA-256；Rust逐字段
比较old/fresh完整target和shard集合。verification receipt除binary/release/bundle/request/receipt digest外固定包含
`expected_targets_file_sha256`与不含末尾LF的canonical `target_binding_sha256`。因此proof目录内自带一份内部自洽但
属于foreign target的request/receipt不能授权reset；Python不得重构ARN或复制Rust target语义。

### 3.1 Two-path qualification与唯一global finalizer

每个block-path的catalog case固定为`usage-source-terminal-receipts`。它在delete-cleanup以及该run的
EndQualification/Closed drain之后只读发现本run source finals，不能调用target-terminal begin/complete。case-specific
闭集恰为：

- `usage-live-delivery-receipt.json`：run start/Cat/window内已经产生的完整非零CPU/memory pair；
- `usage-source-terminal-receipts.json`：kind固定`cats.usage-source-terminal-receipts.v1`，并逐字段绑定
  block path、run ID、Cat/Workspace、run window、release/bundle/catalog，以及严格排序的typed source expectation集合
  和上述semantic集合digest。

两个distinct passed qualification目录都必须保留exact `manifest.json`、`case-evidence.jsonl`、
`qualification-catalog.v1.json`和覆盖完整run artifact closed set的`SHA256SUMS`。只有release-bound
`deploy/metal/runtime-cutover-usage-terminal-finalize.sh`可以消费这两个固定目录；它还逐byte绑定同一approved release
manifest、installer receipt、catalog与root-only `usage-terminal-targets`。两份source set按
`source_id,source_epoch`取严格排序并集；同key同digest只保留一次，不同digest拒绝。

global `terminal_epoch_id`固定为以下五帧的SHA-256前32位lowerhex，且不能全零：

```text
u64be(len(domain)) || "cats.usage-target-terminal-epoch.v1" ||
u64be(len(kernel_manifest_sha256)) || kernel_manifest_sha256 ||
u64be(len(vhost_manifest_sha256)) || vhost_manifest_sha256 ||
u64be(len(expected_targets_file_sha256)) || expected_targets_file_sha256 ||
u64be(len(union_source_set_sha256)) || union_source_set_sha256
```

这里digest字符串均含`sha256:`前缀；不加入单一block path或global run ID。finalizer以mode0400 no-replace文件发布
`usage-target-terminal-request.json`。重跑必须先读取并逐字段复用该journal的原`created_at_unix_ms`；begin或complete
response loss只重发同一文件。target terminal后调用固定安装路径
`/opt/cats/bin/cats-usage-terminal-receipt-verifier`，其verification receipt exact 11-key closed shape为：

```text
binary_sha256, expected_request_file_sha256, expected_targets_file_sha256,
kind, release_commit, target_binding_sha256, target_receipt_file_sha256,
target_request_sha256, validated, version, worker_bundle_sha256
```

global成功目录只有七个evidence文件加`SHA256SUMS`：`case-evidence.jsonl`、
`qualification-catalog.v1.json`、`usage-global-terminal-finalization.manifest.json`、
`usage-target-terminal-receipt.json`、`usage-target-terminal-request.json`、
`usage-target-terminal-verification.receipt.json`、`usage-terminal-targets.json`。checksum文件按上述文件名bytewise排序，
不含自身且拒绝extra。global case evidence恰为request、target receipt、verification receipt三个canonical JSON wrapper。

## 4. DDL closed set

- `usage_checkpoints.source_binding_json TEXT NOT NULL CONSTRAINT
  usage_checkpoints_source_binding_nonempty CHECK (source_binding_json <> '')`；原event/payload和billing字段仍
  insert-only。
- `usage_archive_projections`：`event_id` PK/FK；stream/bucket/shard；numeric(78,0)+exact text sequence；archive
  key/SHA/evidence JSON；`UNIQUE(stream_name,shard_id,sequence_number)`；UPDATE/DELETE trigger拒绝。
- `usage_source_terminal_receipts`：`(source_id,source_epoch)` PK、receipt JSON/SHA、DB completion time；
  UPDATE/DELETE trigger拒绝。
- `usage_terminal_operations`、`usage_terminal_barrier_projections`和`usage_target_terminal_receipts`按§3 exact
  request/marker/receipt shape，全部insert-only；最终column/index literal随同v16 composition catalog校验。
- 五张新表统一由`reject_usage_terminal_mutation()`拒绝UPDATE/DELETE；trigger exact names分别为
  `usage_archive_projections_insert_only`、`usage_source_terminal_receipts_insert_only`、
  `usage_terminal_operations_insert_only`、`usage_terminal_barrier_projections_insert_only`、
  `usage_target_terminal_receipts_insert_only`。barrier lookup index固定
  `usage_terminal_barrier_operation_idx(terminal_epoch_id,shard_id,sequence_number)`。

## 5. 最小验收

- final CPU先到、memory后到：前者无receipt，后者原子生成；相反顺序同结果。
- effect失败与accepted same-target observation均零final；crash pending分别可由accepted same-target恢复或由
  absent/different observation promote；promote后的source epoch不可reopen。
- archive success后project crash、project success response loss、DynamoDB save前crash：exact replay收敛为一份
  event evidence和一份source receipt；无false ACK。
- final缺项/错序/extra/later-open/binding或attribution漂移都卡住shard checkpoint且零receipt。
- exact per-event ACK的缺项、错序、foreign/rejected/count漂移都保留Node内存pending queue。
- marker PutRecord response loss产生相同marker；reshard、任一source未terminal、DDB checkpoint落后、old/fresh
  overlap、target ARN变化或S3 receipt冲突均零target receipt。
- 两个block-path分别只能生成source case闭集；第一条path不得调用target begin。只有两个passed manifest/evidence的
  exact union可生成一个global target request/receipt/11-key verification，response loss重跑仍复用原request bytes。
- Rust typed source-set golden bytes固定为以下单行compact JSON（无末尾LF），digest固定
  `sha256:1ecc587146a29898f40be96fb88679c68106813997ce5778fc046c86388e2ec1`。input member字段重排不改变digest，
  missing/extra字段拒绝：

```json
[{"source_id":"node/node-a/cat/cat-a","source_epoch":"epoch-a","receipt_sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},{"source_id":"node/node-b/cat/cat-b","source_epoch":"epoch-b","receipt_sha256":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}]
```
