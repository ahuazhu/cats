# ADR-0046：Gateway 到 Node 使用 mTLS HTTP Upgrade Route v2 tunnel

- 状态：Superseded for current production composition by
  [ADR-0059](0059-semantic-control-node-synchronous-protocol.md)
- 日期：2026-08-11
- 依赖：[ADR-0041](0041-node-verified-route-admission.md)、
  [ADR-0045](0045-independent-gateway-workload-identity.md)
- 历史协议实现由 Git history 保存

## 背景

ADR-0041已经冻结Node验签、本地gate和RAII guard，却刻意没有开放production HTTPS listener；此前也没有
冻结Gateway如何把opaque Grant、public HTTP/WebSocket bytes、取消和guard lifetime组成一次请求。增加一个
“先检查Grant、再另发public request”的preflight会在两个请求之间产生TOCTOU，并使当前应用请求是否执行变得
不明确。复用legacy Node bearer/proxy则会重新引入已删除的authority。

Control resolve已经由current PostgreSQL Gateway credential签发Grant。若Grant不绑定取得它的TLS leaf，另一个
受信Gateway可以使用窃取的cache entry；仅凭CA验链也不能区分这两条credential lineage。

## 决策

1. Control把完成resolve的CA-verified Gateway leaf canonical Ed25519 SPKI SHA-256写入签名Grant claims。
   Node先完成TLS client chain验证，再从同一connection的leaf提取相同digest；不匹配是pre-admission
   `BindingMismatch`。SAN、subject、remote IP和HTTP header不提供Cats authority。
2. authenticated resolve success增加`cat_id`。Gateway仍不解析Grant；它只保存Control返回的typed字段和
   opaque bytes。Node必须先验签并把frame的`cat_id`精确绑定到claims，再只用已验证claims中的`cat_id`定位
   进程内同一`AdmissionCellRegistry`；不得用未验证frame探测registry。最终authority仍是验签claims和cell。
3. 每个应用connection使用一个TLS 1.3、ALPN `http/1.1`的machine request：
   `POST /v1/internal/routes/tunnel`，无query，exact `application/json`、`Connection: upgrade`和
   `Upgrade: cats-route-v2-tunnel`。canonical body依次包含`version,cat_id,endpoint_id,hostname,
   opaque_grant,grant_sha256`，最多5120 bytes。禁止Authorization、Cookie、content encoding、transfer
   encoding、method override和未知header。
4. 这一个request就是实际proxy，不是preflight。Node完成mTLS proof、strict frame、Grant signature/claims及
   完整request binding验证，产生不可由wire构造的claims/time proof；随后才按该proof的Cat定位shared
   per-Cat cell并完成binding/gate/guard linearization，从同一snapshot取得checkpointed Guest IPv4，在guard外
   连接Grant的exact target port；成功才返回`101`。101后的raw bytes承载public HTTP/1.1或WebSocket，内部
   frame和Grant永不进入Guest。tampered signature或unknown `kid`在Cat present/absent时必须同错且零guard/I/O；
   只有完整已验证请求的Cat确实absent时才返回`RuntimeNotReady`。
5. Guest IPv4只来自同一exact `runtime_launch.network.network_config`；同一cell、同一runtime incarnation的
   lifecycle open、Endpoint install/close/remove、全局close/try-close及RequireIdle Busy source transition都必须
   保持该值逐字段不变，IP变化只能随new incarnation/new cell发布。缺launch target、缺registry cell、缺physical
   Ready所打开的gate均fail closed为`RuntimeNotReady`或`GateClosed`。transport不创造Guest Ready scanner proof，
   也不因checkpoint中存在Active entry而在进程重启后自动重开。
6. 只有尚未取得guard的闭集failure使用canonical typed envelope和`guard_acquired=false`。取得guard后的
   connect/upgrade/stream失败只使用`UpstreamUnavailable, guard_acquired=true`或关闭stream。Gateway只把
   authenticated pre-admission refreshable failure交给既有exact-digest cache规则；当前request绝不重放。
7. Gateway每次`tunnel`调用最多建立一次TCP/TLS/HTTP exchange，没有redirect、plaintext、proxy环境变量或
   fallback。A23 strict HTTPS target的hostname同时是TLS server name；证书或hostname错误在发送application
   bytes前失败，且不是refresh signal。
8. Node listener分别限制TLS connections、admitted tunnels、header/body大小及TLS/header/body/Guest-connect
   deadline。AdmissionCell mutex内没有network/file/async I/O。不可clone guard由tunnel task持有到EOF、错误、
   取消或shutdown。
9. shutdown先关闭machine admission，再关闭connections并cancel/join全部tunnel；所有guard和permit必须在
   listener完成前归还。`runtime_cutover`中的scanner、effect与transport必须clone同一进程唯一的
   `Arc<AdmissionCellRegistry>`，不得各自构造registry。scanner报告的`loaded_kids`也必须来自listener实际
   使用的同一个`Arc<RouteGrantV2Verifier>`；不得把磁盘上的候选ring误报成进程已加载的authority。listener
   未组成时ring observation为Unavailable，Control不能向关闭的ingress签发Grant。
10. Node固定artifact为public ring、Gateway client CA、Node server certificate/private key；Gateway固定
    artifact为Node server CA、Gateway client certificate/private key。目录root:root `0700`，public material
    `0644`，private key `0600`，用no-follow、single-link、stable descriptor合同一次性读取。显式配置listener
    后，任何缺失或无效artifact都在bind前失败；未配置listener则不读取artifact且ingress保持关闭。

## 后果

- Grant既是短期route capability，也是取得它的Gateway TLS credential的proof-of-possession binding；正常
  credential轮换需要新Gateway用自己的leaf重新resolve，旧leaf只能在证书、Grant TTL和Node gate均仍有效时
  使用其既有Grant。
- public request streaming不需在内部JSON复制或设置整包上限；WebSocket与长响应保持端到端字节语义。
- 每个public connection多一次独立Node TLS connection；V1先选择简单、可界定和不重放的模型，连接池/多路复用
  若需要必须另立合同，不能改变guard与request一一对应关系。

## 不采用的方案

- **裸Grant preflight**：两个请求之间有TOCTOU，且无法证明guard覆盖实际应用bytes。
- **在JSON中buffer完整public request/response**：破坏streaming、WebSocket和明确的memory bound。
- **CA-only、SAN或header identity**：不能把Grant绑定到Control实际授权的Gateway credential。
- **从checkpoint文件在guard后另读Guest IP**：文件和cell不是一个linearization point，可能组合两代runtime。
- **legacy Node bearer/proxy或plaintext loopback fallback**：authority和网络位置均不等于本合同的machine proof。
