# Usage Terminal Authority v1

- 状态：Frozen；schema/protocol v16 clean-slate contract
- Authority：[ADR-0047](../decisions/0047-terminal-usage-archive-and-projection-authority.md)

## 1. Source terminal

compute source固定为`node/<node_id>/cat/<cat_id>`，固定meter集合按slug排序为
`cats.compute.cpu.v1,cats.compute.memory.v1`。每个stream envelope包含server-frozen：

```text
RuntimeUsageSourceBinding {
  node_id: Id,
  node_boot_id: NodeBootId,
  agent_instance_id: RandomId128,
  agent_epoch: Epoch,
  desired_revision: Revision,
  runtime_incarnation: RandomId128
}
```

`source_epoch`的canonical signed Runtime shape必须逐字段编码同一个agent instance/session epoch、Desired
revision、runtime incarnation和非空process identity。Control先用A19验证current provisioned Node/current
AgentSession，再从source epoch解码并与request逐字段比较；不接受caller另传binding。

Node普通sample使用`epoch_marker=open`。准备改变runtime时，Node先采样counter并在一个SQLite transaction中写入
`usage_pending_final`：exact `SignedMeterTarget`、`RuntimeMeterAccumulatorSnapshot`、以及由该snapshot非破坏计算的
CPU/memory候选final。pending不是outbox，不可发送。effect失败或accepted same-target observation删除pending，
从snapshot恢复同一accumulator并继续open采样；`RetryExact|RefreshInventory`以及process crash保留pending。只有
accepted full observation证明原target absent或different时，才在一个transaction中把exact候选插入outbox、删除
pending并写`usage_promoted_source_epoch` tombstone。tombstone拒绝该source epoch任何brand-new open，但允许exact
outbox replay。因此尝试过effect不等于terminal，且receipt成立前不会再有同epoch的新event。

promoted最后sample使用`final`。CPU、memory两个final event共享source、epoch、sequence、time、Cat、revision和
binding。marker进入event ID hash frame；同一metric/sequence的open与final不是同一event。

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
无效。Node只在全部result为accepted/exact_replay时删除完整exact outbox prefix；不做部分删除。HTTP timeout、
5xx、body读取/解码失败、缺项、错序、重复/foreign ID和rejected都保留prefix。413只缩小尚未获得任何成功
response的有序batch，不改变event bytes。

## 3. Target terminal barrier

global request以唯一`terminal_epoch_id`持久化，并含：release commit/artifact digest、old/fresh
`UsageTargetBinding`、按`source_id,source_epoch`排序的完整source terminal receipt key+digest集合及其集合digest。
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
- exact per-event ACK的缺项、错序、foreign/rejected/count漂移都保留Node outbox。
- marker PutRecord response loss产生相同marker；reshard、任一source未terminal、DDB checkpoint落后、old/fresh
  overlap、target ARN变化或S3 receipt冲突均零target receipt。
- qualification case ID固定`usage-final-terminal-receipt`，case-specific artifact闭集为
  `usage-live-delivery-receipt.json`、`usage-source-terminal-receipt.json`、
  `usage-target-terminal-receipt.json`。
