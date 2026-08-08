# ADR-0010：每个 Cat 默认获得稳定 HTTP Endpoint

- 状态：Accepted
- 日期：2026-07-23
- Route authority：[ADR-0041](0041-node-verified-route-admission.md)

## 决策

创建Cat的数据库事务同时创建名为`web`的默认Endpoint：

- protocol：`http`；
- target port：`8080`；
- wake policy：`wake_on_request`；
- hostname：`<cat-name>-<opaque-cat-suffix>.cats.run`。

hostname不含Workspace标识且不绑定Host，因此Suspend、Warm、Cold、恢复和迁移不改变用户
URL。`cats create`与`cats get`显示默认URL，`cats endpoint ls`提供结构化发现；
`cats expose`用于修改默认Endpoint或增加额外Endpoint。

Gateway只按受信Endpoint binding解析hostname并转发不透明Route Grant。Node按ADR-0041
验证Grant与本地gate，随后把HTTP流量转发到当前Guest tap地址和目标端口。Hostname、客户端
header或query不能选择Node、Guest IP或目标端口。

## 生命周期与失败语义

- Cold请求先触发wake；在精确Running observation和Node gate Ready之前返回Pending/Unavailable。
- 离开Running先关闭gate并排空active guards，再处理Guest、VMM、blockd和attachments。
- placement或runtime incarnation变化后，旧Node和旧Grant永久不能继续服务该Endpoint。
- Gateway/Node暂时不可用产生明确的Unavailable；不得绕过Node gate直连Guest。

## 安全合同

- Gateway保留method、path/query、允许转发的headers和body，过滤hop-by-hop headers并限制
  request/response大小。
- Node拒绝CR/LF注入、非法method/path和畸形Guest HTTP response。
- Guest只看到普通TCP/HTTP流量，不接收WorkOS、控制面、对象存储或MetadataStore凭据。
- 默认Endpoint是公网可寻址入口；应用负责只在目标端口暴露可公开服务。私有Endpoint与
  Endpoint级用户策略需要独立ADR。

## 验收

- Cat与默认Endpoint原子创建，重试不产生重复Endpoint或hostname；
- 同一URL跨四态与跨Node Cold恢复保持不变；
- wake并发、旧revision/incarnation/route epoch和gate close竞争全部fail closed；
- method、path、headers、body和响应语义端到端保持；
- 默认Endpoint计入Endpoint和route binding配额。
