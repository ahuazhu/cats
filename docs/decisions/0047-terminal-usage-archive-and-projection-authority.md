# ADR-0047：最终 Usage archive/projector terminal authority

- 状态：Accepted
- 日期：2026-08-14
- 修订：[ADR-0011](0011-cumulative-usage-metering-and-billing-ledger.md)
- 依赖：[ADR-0040](0040-level-triggered-runtime-reconciliation.md)
- 规格：[Usage Terminal Authority v1](../specs/usage-terminal-authority-v1.md)

## 背景

现有signed Runtime sampler会把累计CPU/memory checkpoint先写Node SQLite outbox，再经A19 current
AgentSession route送入production Kinesis。Projector随后把raw envelope写入immutable S3 archive、写入
PostgreSQL billing projection，最后推进DynamoDB shard checkpoint。这个顺序保护普通计费，但没有回答两个
终态问题：某个Cat的最后一个累计样本是否已经archive并project；整个旧Usage target是否已经越过全部stream
record并可由fresh target接替。因此Cat row删除和clean-slate reset不能把空stream、outbox absence或一次
`PutRecord` success当成证明。

旧response只有aggregate accepted/duplicate count。它不能证明具体outbox row被结算，永久projection错误还会
被记录后跳过并推进shard checkpoint。这两种形状都可能产生false ACK。

## 决策

1. `CatUsageCheckpoint`必填`epoch_marker=open|final`，marker进入deterministic event ID。CPU和memory共享
   sequence；source epoch最后一次采样恰好产生同sequence、同observed time的两个`final` event。final仍是普通
   cumulative billable sample，不另建金额或修正ledger。Node不能在物理effect前发布final：它先把accumulator
   snapshot和候选final写入本地pending表并暂停采样；只有accepted full observation证明原target已不存在或已被
   不同runtime替换时，才把候选原子promote到outbox。effect失败或same-target observation取消pending并恢复同一
   accumulator；crash后也只能由accepted inventory选择resume或promote。promoted source epoch有durable tombstone，
   不能重新open。
2. Signed Control ingestion从A19 request和canonical source epoch冻结`SessionBinding + desired_revision +
   runtime_incarnation`。archive/receipt wire将其无损展开为`node_id,node_boot_id,agent_instance_id,agent_epoch,
   desired_revision,runtime_incarnation`，不出现可能被证据扫描器当作凭据的`session` key。这个binding随
   `AttributedCheckpoint`进入stream；Node不能选择Account、Workspace或binding。source epoch内attribution或
   binding任一漂移都fail closed。
3. ingest response必须逐request顺序返回每个event ID的`accepted|exact_replay|rejected`。aggregate counts只作
   一致性诊断。Node只在完整同序结果中全部为accepted/replay时删除该exact outbox prefix；response loss只重放
   原event。rejected、缺项、错序、foreign ID或count不一致全部保留prefix。
4. Projector先以`If-None-Match:*`写immutable NDJSON archive，再用exact stream/shard/sequence/archive
   key和archive SHA-256调用ledger projection。`usage_archive_projections`和
   `usage_source_terminal_receipts`都是insert-only。任何Invalid/Conflict/Overflow/Store错误都不推进DynamoDB
   shard checkpoint；永久坏record不再被跳过。
5. 第二个final meter完成archive projection时，PostgreSQL在同一source-epoch advisory fence下只接受固定
   CPU/memory集合、同final sequence/time、同Cat和同source binding，且不存在更晚record；随后生成唯一
   `UsageSourceTerminalReceipt`。receipt列出两个event的完整archive evidence。其缺失只表示未证明终态，不能
   表示零usage。receipt之后brand-new event拒绝，exact event replay仍可发现原结果。
6. Cat删除/open reset前置只消费exact source terminal receipt，不消费Node outbox、HTTP ACK、日志或query
   interval。Control内消费者必须把Cat、source epoch、Desired revision和runtime incarnation逐字段绑定；receipt
   不形成第二份lifecycle或billing authority。
7. 旧target退休使用[规格](../specs/usage-terminal-authority-v1.md)冻结的per-shard marker。两个block-path
   qualification均已结束、各自run-bound source closed set均已有receipt且全局集合完成严格并集后，coordinator才为
   固定old target的每个open shard写deterministic marker；同marker响应
   丢失可产生相同payload的无害重复。Projector按普通raw对象顺序archive/project marker并最后推进DynamoDB。
   只有全部marker projection与consistent-read shard checkpoint闭合、source closed set无缺项且live target
   identity匹配，才能生成immutable `UsageTargetTerminalReceipt`。
8. target receipt逐字段绑定release commit/artifact SHA-256、AWS account/region、old usage schema/Kinesis
   ARN/DynamoDB table ARN/Object-Locked archive ARN，以及disjoint fresh四元组。receipt先no-replace写入旧immutable
   archive，再提交PostgreSQL receipt；response loss通过相同terminal epoch ID读取并逐byte比较，不能盲目创建
   新operation。
9. 本合同复用A19 Node生产认证和现有projector leader fence；不增加第二个Node bearer、admin签名或billing
   writer。global reset只消费immutable target receipt和既有maintenance authority，不能借此生产usage。
10. `kernel-nbd`与`vhost-user`不是两次target retirement。每个block-path只运行
    `usage-source-terminal-receipts`并持久化本run的live pair和严格排序source receipt expectation集合；它不得调用
    target begin/complete。两个passed qualification manifest均已绑定各自case evidence、同release/catalog/target
    config后，release-bound global finalizer才取两集合的exact union并执行唯一一次target begin/complete。其
    `terminal_epoch_id`固定为domain、kernel manifest SHA、vhost manifest SHA、expected-targets file SHA与union
    source-set SHA五个UTF-8字段分别加u64 big-endian长度前缀后的SHA-256前32位lowerhex；不含block path或run ID。
    request journal和最终manifest均no-replace exact replay，避免第一条path提前永久关闭old ingress，也避免response
    loss重建creation time或另一operation。

## 切换

这是schema/protocol v16 clean-slate的一部分，没有缺少marker/result/binding的旧wire、旧stream envelope或旧表
parser。总schema v16 stamp、fresh/old target reset与qualification catalog由同一个release composition一次发布，
本ADR不建立独立版本号。

## 后果

最终计量延迟会显式阻塞Cat authority删除或旧target reset，而不会少收、重复收费或丢掉唯一证据。正常runtime
stop先durable stage候选，物理结果被accepted observation确认后才promote final sample；中心terminal receipt可
异步完成。旧target删除多一次有界per-shard barrier，但不需要扫描或重写历史billing ledger。
