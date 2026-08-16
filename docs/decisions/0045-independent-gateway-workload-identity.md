# ADR-0045：Route v2 使用独立 Gateway workload identity authority

- 状态：Accepted
- 日期：2026-08-10
- 关联：[ADR-0041](0041-node-verified-route-admission.md)、
  [ADR-0044](0044-independent-route-v2-signing-authority.md)
- 规格：[Gateway Workload Identity Authority v1](../specs/gateway-workload-identity-v1.md)

## 背景

Route Grant v2 已冻结 Control 的独立 signer、Node 的grant verifier与Control machine resolve frame，但
此前没有能构造`AuthenticatedGatewayPrincipal`的production authority。测试principal不会来自网络，普通
Control组合因此有意在读取body和访问PostgreSQL前返回401。

Gateway不是用户、Workspace member、Node、deployment provisioner或Route signer。复用WorkOS session、
Workspace token、shared service/admin bearer、V1 Route key、A19 Node credential、A23 provisioner key，或
让HTTP header、SAN、subject、hostname/IP自报principal，都会把已经分离的authority重新合并。只配置TLS
但不冻结credential lineage、scope、rotation/revocation和PG current compare，也会让旧replica或已建立的
keepalive连接越过撤销继续签发。

## 决策

1. Route v2 Gateway建立独立的fleet-scoped workload identity authority。credential由永不复用的
   `credential_id`和canonical Ed25519 leaf证书SPKI绑定；它不与A19、A23、V1、Route v2 signer或用户
   identity互换。
2. PostgreSQL current pointer、immutable exact revision bytes、永久credential/SPKI lineage和current
   policy是唯一运行时authority。固定filesystem JSON只是一份bootstrap/install candidate；startup以
   exact CAS安装或重放后，磁盘文件不能覆盖PG，也不能形成第二份“current”。
3. Control使用独立machine listener。TLS 1.3必须先由固定client CA bundle成功验证完整peer chain，随后
   只取leaf的canonical SubjectPublicKeyInfo DER普通SHA-256映射current active credential。SAN、subject、
   issuer string、remote IP、SNI及全部HTTP header都不参与身份映射。
4. 每个HTTP/1.1 request都重新在PG验证credential仍属于current revision；连接或TLS session不缓存
   principal。method/path/query检查后、读取body、取得Route resolve permit或访问Route Store前只做active
   fleet credential认证。body解出hostname并由同一Route authority snapshot得到current Workspace后，才在
   与policy writer串行的同一PG snapshot内重验exact revision、credential和Workspace scope，再签发。
5. policy revision以N+1 exact previous pointer CAS推进。same revision exact bytes是零写重放；stale、gap、
   same revision different bytes、错previous全部拒绝。credential ID和SPKI各自永久唯一，移除即永久撤销，
   不能重新出现。正常轮换为`old -> old+new -> new`；空active set是durable emergency disable。
6. scope只有`fleet`或有界、严格排序的Workspace ID闭集。pre-body认证只证明一个current fleet authority下的
   active Gateway credential，不产生Workspace principal；最终Workspace授权必须使用route lookup得到的
   Workspace，不能使用request自报字段。
7. authority reader、policy writer和Route signer snapshot共享schema-scoped PostgreSQL advisory lock：writer
   取exclusive，认证/签发snapshot取shared。签发snapshot必须同时重验Gateway current policy和进程内
   Route signer等于PG current signer binding；旧Gateway credential或旧Control signer均不能签发。
8. public CA/certificate、non-secret authority JSON和secret reference可以由部署系统引用；client/server
   private key只允许由预建secret或独立root-only installer写入固定real file，不进入DB、JSON、Terraform
   value/state/output、argv、environment或日志。Control listener的fixed directory为root:root `0700`，
   authority/CA/certificate为root:root `0644`，server private key为root:root `0600`，并使用no-follow、
   single-link、stable descriptor读取合同。
9. machine listener拥有独立bounded admission与active-owner生命周期。handler和已启动的Store closure共享
   RAII owner；client取消/response loss不能提前释放Store owner。shutdown先关闭authentication与resolve
   admission，等待active owners归零，再结束listener。一次请求的绝对deadline仍为2000ms。
10. 没有machine配置、artifact、PG current authority、exact signer binding或TLS proof时均fail closed；
    无配置仍在pre-body/pre-PG返回401，principal已认证但signer未组成则pre-body/pre-PG返回503。该决策不开放
    public proxy。Gateway到Node的TLS/proxy frame随后由[ADR-0046](0046-gateway-node-route-v2-machine-tunnel.md)
    冻结，并把本request授权的leaf SPKI digest签入Grant。

## 当前实现边界

Control现已从唯一固定目录用descriptor/stable-reopen合同读取policy、client CA、server chain与server key；
启动在任何bind前验证TLS 1.3配置、Ed25519 server pair、Gateway PG candidate及Route signer PG exact current。
独立machine listener只协商HTTP/1.1，每个request从verified leaf重新做pre-body PG认证，并在最终shared-lock
snapshot内闭合hostname-derived Workspace、Route/Desired/ring ACK、Gateway scope与signer current后才签名。
认证/resolve拥有独立bounded RAII owner，shutdown关闭两类admission并join Store closure与listener task。

本实现仍不包含public proxy、Route signer rotation writer或Node public-ring全量ACK rollout；Gateway到Node
machine tunnel由ADR-0046独立组成。Gateway与signer表共同属于clean-slate authority schema 15最终形态；中间
提交不构成可单独部署migration。

## 后果

- credential撤销在PG线性化；旧replica、旧keepalive连接和TLS恢复session的下一request都必须重新失败。
- Gateway leaf证书可以由现有PKI签发，但证书命名字段不成为Cats authority；rotation必须同时满足PKI验链和
  Cats credential policy。
- private material不进入Control Store或IaC state；代价是部署前必须有独立secret安装通道和严格fixed-file
  reader。
- production Control resolve和Gateway->Node machine tunnel可独立开放；public proxy仍保持关闭，直到其
  SNI/Host、cache与listener组合完成。

## 不采用的方案

- **static bearer或HTTP header principal**：可重放、无法绑定TLS peer，且会绕过pre-body认证边界。
- **复用A19/A23/V1/Route signer key**：principal、权限域、rotation与撤销生命周期不同。
- **只信任CA或SAN/SPIFFE字符串**：CA验链只建立certificate可信度，不证明该leaf在Cats current policy中
  active；命名字符串也缺少永久lineage和CAS。
- **filesystem current或启动时内存缓存**：会让多Control replica在policy CAS后继续接受stale credential。
- **把Workspace写进client request/header**：Gateway可以自报扩权；Workspace只能来自current route authority。
