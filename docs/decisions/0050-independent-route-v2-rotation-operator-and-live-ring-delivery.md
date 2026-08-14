# ADR-0050：Route v2 使用独立 rotation operator、live ring delivery 与前向恢复

- 状态：Accepted
- 日期：2026-08-14
- 依赖：[ADR-0041](0041-node-verified-route-admission.md)、
  [ADR-0044](0044-independent-route-v2-signing-authority.md)、
  [ADR-0046](0046-gateway-node-route-v2-machine-tunnel.md)
- 规格：[Route v2 Signing Authority v1](../specs/route-signing-authority-v1.md)

## 背景

ADR-0044 冻结了 signer/ring lineage、Node durable successor installer、full-inventory ACK 以及
rotation/disable Store transition，却刻意没有授予 production caller、wire transport 或数据库权限。因此，Store
中存在 typed transition 不等于生产可触发；A23、管理员 bearer、WorkOS session、startup artifact 和审计日志
都不能补成这份 authority。

只在发布时把新 ring 烘进 Node image 也不能闭合 emergency disable。泄漏发生后，reachable Node 必须不等待
整机重部署就取得 empty exact-successor ring，durable install 后在同一进程关闭 route admission，并通过 fresh
full inventory ACK。恢复又必须使用从未出现过的 signer lineage 和 secret reference；旧进程在 PostgreSQL current
前进后失败关闭，新进程只从 exact revision artifact 启动，不能靠 startup 自行推进 successor。

此外，签名命令的有效期只有五分钟，而 disable、Node ACK、Control rollout 和恢复可能持续数十分钟。预签完整
序列或在 qualification worker 上直接运行 Terraform，都会把短时 operator authority、云部署权限和恢复状态混为
一体，不能作为生产设计。

## 决策

### 独立 principal 与 trust

1. 新建独立的 Route v2 rotation operator machine principal。revision 1 使用离线 Ed25519 key；private bytes
   只存在于 root-owned authority artifact `rotation-operator-private-key.pem`，不进入 Control、Node、Gateway、
   PostgreSQL、Terraform value/state、provider secret、argv、environment、日志或 qualification evidence。它不
   复用 A19、A23、Route Grant signer、Gateway credential、Workspace token、管理员 bearer 或 WorkOS session。
2. Control、Node 和离线工具安装同一 canonical public trust：
   `/etc/cats/route-v2/rotation-operator-trust.v1.json`。release artifact 是 root:root `0644` single-link regular
   file，qualification 的 root-only staged copy 是 `0600`；两者均有 closed byte bound、no-follow、stable
   read/reopen/revalidate 和 protected parent 检查。trust 精确绑定 `authority_id`、唯一
   `route_deployment_id`、lowercase 40-hex `release_commit_sha`、threshold 以及按 credential ID 严格排序的
   canonical Ed25519 SPKI。production binary 必须内嵌同一 source SHA；缺失或不相等在 listener bind 前失败。

### 独立、readiness-independent transport

3. Control 在 `0.0.0.0:7444` 启动独立 server-auth TLS listener，Kubernetes 只发布 cluster-local
   `cats-controld-route-rotation` Service，设置 `publish_not_ready_addresses = true`，不创建 public Ingress。它复用
   已接受的 Route v2 CA/发布证书机制，不创建第三套 CA，也不请求 client certificate。主 Control readiness 因
   signer disabled 或 stale process 关闭时，该 listener 仍可访问；listener 异常退出则 poison readiness。
4. 该 router 只挂载以下 closed routes：

   - `POST /v1/internal/route-v2/signing-authority-commands`；
   - `GET /v1/internal/route-v2/public-ring-successors`；
   - `GET /v1/internal/route-v2/signing-authority-current`。

   POST 只接受 canonical、无 content-encoding、bounded `application/json` signed envelope。Authorization、Cookie、
   所有 `x-cats-*` header、A19/A23 proof 和管理员 session 均拒绝。TLS hostname、IP、URL secrecy 和 server
   certificate 只提供传输身份或保密性，不是 Cats mutation principal；唯一 mutation authority 是离线 operator
   对 domain-separated canonical payload 的 threshold signature。

### command、Store 与 live delivery

5. 每个 effect 前才生成一次 fresh command。payload 精确包含 version、authority、release SHA、random 128-bit
   command ID、五分钟 execution window 以及 ADR-0044 的 typed successor；不能预签后续 phase、复用 window、让
   caller提交数据库时间、ACK boolean、private bytes 或 force bit。Control 在同一 PostgreSQL transaction 中读取
   DB time、验签并重算 exact predecessor、retention、Node ACK、Closed/fenced activation 等全部 precondition。
6. `(authority_id, command_id)` 是永久 idempotency key。首次 terminal `applied` 或
   `authority_precondition_failed` 与 exact signed bytes、digest、release、proof credential set 和 canonical
   receipt 在同一 transaction 写入 immutable row。same ID + same bytes 返回原 receipt；same ID + different bytes
   固定 conflict。过期 exact replay仍可发现已经提交的 terminal receipt；从未提交的过期 command 在同一
   authority lock 下证明 command ID 不存在后才可换 fresh ID。HTTP deadline、disconnect 或 shutdown 不能把 5xx
   当 rollback 证明；COMMIT ambiguity 只通过 exact replay/discovery解决。
7. 每个成功且携带 successor ring 的 command，在同一 transaction 写 immutable delivery，绑定 source command、
   release、successor version/digest、exact predecessor 和原 signed envelope。successor GET 只有 canonical
   `deployment_id,current_ring_version,current_key_ring_sha256` query；`200` 返回原 envelope，`204` 表示无 adjacent
   successor。delivery row、HTTP status、日志和文件存在都不是 Node ACK。
8. Node 每两秒从固定 HTTPS rotation origin 查询其 in-process verifier 的 exact version/digest，不发送 bearer、
   A19/A23 或 operator material，不跟 redirect、不走 proxy、不降级 plaintext。每个 response 必须通过 canonical
   envelope、threshold proof、release/deployment、`expected_previous == current` 校验，才调用 ADR-0044 fixed-path
   durable installer。一次 poll 最多连续安装八个 adjacent revisions；gap、fork、rollback、same-version conflict
   和 wrong predecessor 均保留旧 ring。candidate fsync、atomic rename、parent fsync 和 in-process swap 后才成功；
   empty ring还必须先 latch 全部 AdmissionCell Closed。重启从 fixed artifact exact predecessor继续 catch up；
   delivery task异常退出立即关闭 admission。

### signer secret channel 与 Control rollout

9. fresh signer key 使用 ADR-0044 已接受的独立 secret channel。离线 recovery generator 每次生成从未复用的
   signer private key、`secret_reference_id`、canonical signer/ring bundle、root-only private artifact，以及
   pre-created immutable Kubernetes Secret payload；Metal 生成同代 sibling staged root-only bundle。signed command
   只携 non-secret reference 和 public successor，private bytes不进入 command、PG 或 Terraform state。
10. Control Secret name 必须由已有 revision-1 prefix 和 positive signer revision机械推导为
    `<prefix>-r<signer_revision>`；禁止 caller自由命名、同名原地覆盖或删除旧 Secret。provider input/state只保存
    name、manifest digest 和 revision。Pod annotation 同样绑定这三个值，因此 Secret name/digest/revision改变必然
    rollout；新进程从 exact fixed eight-file Control bundle启动。startup只接受 PostgreSQL **current exact replay**；
    它不能安装 next successor、推进 Store 或从本地历史猜测 current。
11. AWS 的七次 rollout 只能由 approved deployment controller/workspace 上的 release-bound G3 operator执行七个
    reviewed saved plans。qualification worker不持有 Terraform、AWS、Kubernetes、SSH 或数据库权限，也不运行
    `terraform apply`、`kubectl patch` 或 ad-hoc remote shell。plan validator只允许 expected Secret
    name/digest/revision、对应 Pod annotation 和 rollout；任何其他资源变化失败关闭。
12. deployment controller 每 phase 先写 create-only pending state，再 apply一个 saved plan；apply response不明确时
    只做 fresh current discovery，不能盲目 reapply。确认 exact postcondition 后，它生成 canonical
    `apply-receipt` domain payload，并用同一 release-bound rotation operator trust/quorum签名，通过 descriptor
    中的 immutable HTTPS receipt inbox以 create-if-absent 发布。每份 receipt 精确绑定 run ID、release SHA、
    qualification catalog digest、phase、plan digest、successor、工具 digest、apply outcome 和 fresh current
    discovery。URL 只负责可用性和保密性；worker离线验签，拒绝 future receipt提前出现、same phase异 bytes、
    wrong run/release/catalog/plan/current/successor。证据只保存 URL digest，不保存 URL。

### 七相恢复与 qualification state machine

13. 一个完整 run 严格执行相邻 revisions 2 到 8：

    1. `publish_overlap`；
    2. `switch_active`，并等待 old-signature retention window；
    3. `publish_new_only`；
    4. `retire`；
    5. `disable`；
    6. `publish_recovery`；
    7. `activate`。

    每相均按“fresh signed command durable pending → signed POST/exact replay → immutable Store receipt → reviewed
    saved-plan rollout receipt → current exact process proof”的顺序完成，只有 canonical phase receipt进入 durable
    completed prefix。完成 phase只复验本地 immutable artifacts，不再重做只在旧时刻成立的 absence/current断言。
14. disable 后必须同时证明：公网 TLS仍可达且返回 frozen Route-closed `503`；live delivery 是 empty ring；全部
    expected Node 使用 fresh complete inventory ACK该 ring；active route、active guard、residue、cancellation 和
    quarantine 均为零。随后才可预置 fresh recovery bundle/ring、发布并 ACK recovery ring、签 `activate`、rollout
    exact revision-8 Secret、证明新进程 PostgreSQL-current且 Active。
15. qualification driver 使用 root-only `0700` durable journal，先保存 exact pending command，再发送 effect，并以
    canonical phase array保存 verified prefix；既有 prefix从不 truncate。TERM、SIGKILL、HTTP ambiguity 或任一
    Store/apply/current落盘点后的 restart，均先校验本地 prefix与 live current只能处于“prefix revision”或“紧邻
    next revision”，然后从首个不完整 phase exact replay/forward-complete。进入 mutation 后没有 rollback；cleanup
    使用同一 state machine前向恢复到 revision 8 Active、fresh Endpoint 和 full Node ACK。foreign prefix、fork、
    非相邻 Desired 或陌生 Endpoint 固定失败关闭。网络与 CLI replay永远先写 private fresh probe；canonical
    command、response、verification、Operation 与 terminal evidence只可 create-no-replace，已有路径必须逐字节相等。
    若进程死在同文件系统 no-replace link成功而 private temp unlink之前，恢复只可删除该 canonical path命名空间内
    唯一、owner-controlled、same-inode的临时链接并 fsync目录；canonical file恢复成 single-link之前不得接受或发布。
16. recovery Active 后复用既有 Endpoint产品 authority，不新增 refresh/Suspend/Resume mutation。worker 用
    Workspace bearer 调 observation-only collection GET取得 exact old Endpoint ID，DELETE old ID并等待 Operation
    settlement，再以 run-derived fresh name POST新 Endpoint。两个 mutation的 Desired revision必须各自 exact `+1`，
    same idempotency key replay exact response bytes；新 Endpoint ID不得等于 old ID，route epoch必须为 1。最后在
    fresh Node settlement/ACK之后才用 current hostname跑 HTTP 与 WebSocket probe。

## 持久与 evidence closed set

clean-slate schema 新增 `route_v2_rotation_operator_authority`、
`route_v2_rotation_operator_credentials`、`route_v2_signing_command_receipts` 和
`route_v2_public_ring_deliveries`。四表禁止 UPDATE/DELETE；delivery exact FK 到 public-ring revision和 source
receipt，predecessor必须相邻。本 ADR 不授权 migration、repair、旧 schema parser 或多版本 startup。

qualification 只有一个不可拆分、lowercase case：
`route-v2-rotation-disable-live-delivery`。顶层只发布：

- `route-v2-rotation-disable-live-delivery.receipt.json`；
- `route-v2-rotation-disable-live-delivery.node-acks.json`；
- `route-v2-rotation-disable-live-delivery.transcript.log`。

framework 另发布 `cleanup-receipt.json`。attempt command、Store/apply/current receipt、secret locator和 inbox URL只留在
private journal，不进入 evidence。disable 是中间 checkpoint，不是 terminal success；唯一 terminal marker 是
`route_v2_rotation_disable_recovered_active_http_ws`，必须同时绑定 exact run/catalog/source/deployment/trust、七相
receipt digests、disabled proof、revision-8 Active current、全 Node ACK、fresh Endpoint lineage以及 HTTP/WebSocket。
case 恢复 Active 后才允许通过并进入 `agent-restart-adoption`。

## 后果

- emergency disable不依赖登录数据库、整机 rollout 或公共管理身份；reachable Node能逐代取得独立签名的 empty
  ring，而 serving恢复又必须经过 fresh secret lineage、reviewed rollout 和 exact Active proof。
- qualification worker与生产部署权限严格分离；代价是 release必须准备七个 saved plans、immutable secret payload、
  signed receipt inbox和可重入 deployment-controller state。
- source release、route deployment、operator lineage、每个 command、每个 rollout和最终 Endpoint均有不可混淆的
  digest/identity绑定；网络可达、URL保密、审计日志和 Terraform exit code均不被提升为 authority。

## 不采用的方案

- **复用 A23/admin/WorkOS/startup**：会把 deployment 或人类管理权限升级成 signer mutation authority。
- **operator直连 PostgreSQL、worker运行 Terraform、ad-hoc SSH/kubectl**：绕开 Control transaction、deployment
  controller、saved-plan allowlist与取消/ambiguity语义。
- **把 private key 放入 command、Secret name变量值或 Terraform state**：破坏 ADR-0044 secret channel。
- **预签七相 command或复用一个 execution window**：长流程会使用过期 authority bytes，也无法在每个 effect 前
  绑定 fresh DB precondition。
- **同名 Secret 原地覆盖或 startup推进 successor**：旧 Pod与新 bytes不能被唯一辨识，且绕开 PG current。
- **latest ring、gap跳跃、旧 signer lineage复用或 Endpoint ID/name复用**：无法排除 fork、rollback和旧 gate重开。
- **把 HTTPS、204、apply exit code、delivery日志或文件存在当 ACK**：都不证明 Node durable install、in-process
  verifier/gate状态或 Control exact-current process。
