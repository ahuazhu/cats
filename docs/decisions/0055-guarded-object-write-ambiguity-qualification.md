# ADR-0055：对象写模糊响应资格注入使用持锁事务 guard

- 状态：Accepted
- 日期：2026-08-14
- 依赖：[ADR-0049](0049-trusted-host-fencing-and-batch-recovery.md)、ADR-0052
- 规格：[Volume Authority](../specs/volume-authority.md)

## 背景

V3必须证明一种真实的模糊响应：对象provider已经接受conditional PUT并返回成功，但gateway在把成功交给
普通状态机之前故意丢失该响应，随后只能用fresh exact HEAD发现结果。普通网络timeout、日志、预置对象、
fake provider success或“先返回成功再补一张收据”都不能证明这个故障边界。

ADR-0052的Qualification admission以PostgreSQL singleton上的`FOR SHARE`/`FOR UPDATE`锁保证End或
EmergencyClose返回后不存在晚提交的product mutation。如果gateway只在Receiving、sequence acceptance或
provider dispatch之前短暂检查Qualification，锁释放之后provider仍可能成功；End可以先返回，稍后的注入
收据却把该effect错误归到已经关闭的Qualification。把active binding复制进descriptor也不能代替这条锁序，
因为复制品不是当前authority。

## 决策

1. attachment签名的canonical descriptor必须总是包含`qualification_fault`字段。普通production请求是显式
   `null`；资格请求唯一variant是
   `successful_put_response_loss { qualification_id, fault_id, qualification_catalog_sha256 }`。
   `fault_id`是一次性128 bit identity，wire上为32个小写十六进制字符。完整fault进入object-write request
   digest。`Some` digest还绑定attachment credential ID和public-key SPKI digest，使terminal里的credential
   不能通过重算一张普通content-addressed receipt来漂移；普通`null`不读取/不hash credential，保持原V3
   request digest fixed vector不变。
2. 唯一可消费的E13 mutation class在wire上是`object_write_ambiguity`，Rust variant是
   `ObjectWriteAmbiguity`。该class不授权普通PUT、另一Workspace、另一Qualification或任意provider effect。
3. gateway必须注入一个非optional的`QualificationFaultAuthority`。只有descriptor中的fault为`Some`才调用
   它；`None`不做discovery、不取E13锁，也不改变writer/cutoff authority。core没有no-op、disabled或
   unavailable fallback implementation。
4. fault路径首先开启一个按exact request串行化的exclusive事务guard，并在同一事务读取唯一immutable
   resolution：`ResponseLoss | UnprovenVisible | absent`。resolution命中后不读取current admission并exact
   replay。absent时guard不能释放：已有`ProviderIssued`由它跨fresh HEAD持锁；新请求或HEAD NotVisible在同一
   guard/事务内，以server从current credential/volume关系推导的Workspace调用ADR-0052
   `ObjectWriteAmbiguity` gate并对singleton持有`FOR SHARE`。升级后的opaque authorization guard在真实
   provider调用期间同时保留request exclusive lock和E13 lock。不存在独立“lookup miss→HEAD/authorize”窗口。
5. authorization精确绑定Qualification、Workspace、deployment/release、40位source commit、schema 16、
   qualification catalog、完整admission binding digest/revision，以及object request、writer authority、
   attachment credential ID和public-key digest、provider attempt、完整signed fault、provider/store scope、
   canonical key、content SHA-256和length。caller不能提交Workspace、release或binding作为授权事实。
6. provider adapter对普通`None`保持原`Succeeded | PermanentlyFailed | Ambiguous`分类，ordinary downstream
   validator明确拒绝`Some`。`Some`只能通过core在request/E13两个guard都存活后铸造的non-cloneable
   `ObjectWriteQualificationPut` capability进入独立provider方法。只有一次真实conditional PUT返回成功和
   provider request/checksum observation时才能返回typed `SuccessfulPut`；precondition+fresh exact HEAD只能
   返回typed `PreconditionFailedExactVisible`。普通timeout、503、dispatch loss或HEAD可见都不得冒充前者，
   adapter不能构造qualified terminal或resolution receipt。
7. gateway拿到真实success后必须消费仍然存活的guard。guard在同一个持request exclusive和E13 shared lock的
   事务里用PostgreSQL clock重验未过expiry，写唯一content-addressed response-loss resolution并commit；只有
   commit成功返回后gateway才故意丢弃原success并持久化`QualificationResponseLost`。因此另一replica不能在
   success和commit之间HEAD并写Unproven，End/EmergencyClose的`FOR UPDATE`也必然等到receipt commit或guard
   rollback，成功close之后不可能出现新的合格注入effect。
8. `QualificationResponseLost`是单向authority：重启、重放和另一replica只能执行fresh exact HEAD，不能再次
   PUT、不能结算permanent failure，也不能降级成普通success。terminal proof必须同时携带原authorization、
   real PUT request observation、durable injection receipt和后续不同provider request ID的exact HEAD
   checksum/length evidence。terminal prefix另绑定authorization digest、injection receipt和完整evidence
   digest。
9. 如果process在provider成功后、guard resolution commit前崩溃，数据库事务rollback，不能发布成功的资格证据。
   已存在的fault-bearing `ProviderIssued`恢复必须取得exact request exclusive guard，在其事务中读取resolution，
   miss后继续持guard做fresh exact HEAD；不得先查询current admission或重发PUT。ResponseLoss命中就adopt并保持
   HEAD-only；Unproven命中就exact replay terminal。miss且HEAD精确可见时，同一个guard写唯一
   `QualificationUnprovenVisible` resolution后才允许adopt terminal。它包含完整sealed request（accepted sequence、
   signed ingress descriptor、server authorization request、accepted/issued time）、reason、HEAD、PG-clock resolved
   time和derived receipt ID，明确令Qualification失败，不携带ambiguity receipt、不能转换为普通success/permanent
   failure、进入terminal prefix并允许清理spool，且同一request永远不能再PUT。这个commit不查询current admission，
   所以即使Qualification已经End或Close，writer cutoff也不会被永久卡住。只有HEAD为NotVisible时，同一个request
   guard才升级取得新的current E13 guard并尝试conditional PUT。
10. 新gateway按上一条顺序在重试前HEAD，因此通常不产生第二个conditional request。兼容已经发出的旧请求或
    HEAD与conditional create之间的竞争时，provider若得到precondition failure，必须再取fresh exact HEAD；
    checksum/length精确匹配只可由仍持两个锁的guard提交`UnprovenVisible` resolution，不得映射为ordinary
    success或合格ambiguity。
    可选的provider-neutral `preceding_conditional_request`只记录precondition分类、opaque request identity、
    checksum/length和时间；AWS status/SDK error类型仍留在adapter。
11. authorization、response-loss、HEAD evidence、sealed request、Unproven receipt和terminal ambiguity evidence
    分别有16 KiB、32 KiB、16 KiB、32 KiB、48 KiB和48 KiB canonical JSON上限；gateway receipt上限64 KiB。
    decoder拒绝unknown field、非canonical bytes、
    oversize、schema/class、时间序、scope、request/writer/credential/provider-attempt/fault、checksum/length、
    ETag/version或derived injection receipt的任何漂移。以上类型只含provider-neutral observation；AWS request
    ID、ETag和version可以作为opaque ASCII值，bucket、ARN解析、SDK error和credential不进入core authority。

## 后果

Qualification close可能等待一个有界provider call与receipt commit；这正是对“close之后没有晚effect”的必要
代价。gateway必须把同一个monotonic absolute deadline传过request lock、HEAD/E13/provider和resolution commit；
production authority把PostgreSQL lock/statement timeout截到剩余预算，在每次commit前重验deadline，并且只用
该持锁事务的PostgreSQL clock铸造authorized/injected/resolved wall-clock字段。caller/provider不能提交这些时间。
drop任一guard会rollback/归还连接。`QualificationUnprovenVisible`证明对象安全可见，但不证明规定的response-loss注入；runner
必须报告资格失败并以新fault/新immutable key重跑，不能对同一request重发PUT。cleanup仍遵守writer cutoff与
terminal prefix。

普通production写不会连接E13 fault authority，也不会改变既有request digest、provider timeout分类或cutoff
含义。provider adapter仍不解释E13 binding，且无权自己铸造authorization或injection receipt。

## 不采用的方案

- **Receiving或dispatch时短暂检查Qualification**：锁在真实effect前释放，End可越过provider成功。
- **env flag、HTTP header或provider fake success**：不在attachment签名/request digest内，也不证明真实PUT。
- **把普通timeout/503标为资格故障**：不知道provider是否返回过success，无法证明“成功响应被丢失”。
- **adapter直接写资格receipt**：provider adapter没有E13/Workspace authority，且会把provider类型泄漏进core。
- **`Option<QualificationFaultAuthority>`或disabled fallback**：部署缺失authority时会静默跑普通路径，形成假绿。
