# Gateway Workload Identity Authority v1

- 状态：Frozen target contract；canonical authority codec已实现，PG writer与machine listener尚未实现
- 决策：[ADR-0045](../decisions/0045-independent-gateway-workload-identity.md)
- Resolve与Grant：[Route Grant v2](route-grant-v2.md)
- Signer：[Route v2 Signing Authority v1](route-signing-authority-v1.md)

本文冻结Gateway到Control Route v2 resolve的独立credential authority、PostgreSQL current/lineage、mTLS
peer proof、scope、rotation/revocation、fixed artifacts及服务生命周期。它不定义Gateway到Node transport、
public proxy、Node admission mutation或certificate authority的签发服务。

## 1. Authority separation

Gateway workload credential只授权调用Control machine resolve；它不是：

- A19 Node registration/runtime request credential；
- A23 deployment provisioner credential；
- Route v2 signer private/public key；
- V1 Route key、shared service/admin bearer或Workspace token；
- WorkOS user/admin session；
- TLS SAN/subject/issuer字符串、remote IP、SNI或HTTP header principal。

`authority_id`永久命名一个Gateway authority lineage，`fleet_id`精确绑定一套Control Store fleet。
`credential_id`由credential installer分配、全历史永不复用。它不是secret或bearer。credential public half
必须是canonical Ed25519 SubjectPublicKeyInfo DER；Cats将其普通SHA-256作为TLS leaf映射键。private bytes和
certificate private key不属于artifact或PG schema。

## 2. Canonical policy artifact

```text
GatewayWorkloadIdentityAuthority {
  version: 1,
  authority_id: Id,
  fleet_id: Id,
  policy_revision: Epoch,
  expected_previous: {
    policy_revision: Epoch,
    policy_sha256: Sha256Digest
  } | null,
  credentials: [GatewayWorkloadCredentialPolicy] // 0..=16
}

GatewayWorkloadCredentialPolicy {
  credential_id: Id,
  public_key_spki: Base64UrlNoPad,
  scope:
    { kind: "fleet" }
  | { kind: "workspaces", workspace_ids: [Id] } // 1..=256
}
```

artifact是无BOM、无前后空白、无结尾LF的canonical JSON，最多65536 octets，拒绝重复/未知字段和
noncanonical member order/whitespace。`credentials`按`credential_id` ASCII octets严格升序；ID和SPKI均不
重复。Workspace ID闭集也严格升序且无重复，空集不合法；需要停止授权时使用空`credentials`，不能用一个
语义含混的空scope。

`public_key_spki`必须解码为唯一44-byte Ed25519 SPKI DER：
`302a300506032b6570032100 || raw-32-byte-key`。算法、DER长度或prefix不同均拒绝。TLS leaf certificate的
`subjectPublicKeyInfo`必须逐byte等于该DER；映射键是`SHA-256(exact SPKI DER)`，不是certificate digest、SAN
或public-key text。

revision 1必须`expected_previous=null`。revision N>1必须携带N-1的exact revision和artifact bytes普通
SHA-256。local artifact validation只证明形状与邻接；previous digest是否等于PG current exact bytes只能由
writer transaction证明。

初始跨component fixed vector如下；code block是一行且没有结尾LF：

```json
{"version":1,"authority_id":"gateway_authority_a","fleet_id":"fleet_a","policy_revision":1,"expected_previous":null,"credentials":[{"credential_id":"gateway_credential_a","public_key_spki":"MCowBQYDK2VwAyEA2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8","scope":{"kind":"fleet"}},{"credential_id":"gateway_credential_b","public_key_spki":"MCowBQYDK2VwAyEAJJHj__Po94RauBD2QsCa8LKrwcrVFdomZbKbCGBbvuk","scope":{"kind":"workspaces","workspace_ids":["workspace_a","workspace_b"]}}]}
```

exact bytes SHA-256为
`sha256:4aec249a69133a48f4f48bad0e125363710e5ec315e0763b385edc2a1b149e60`。

## 3. PostgreSQL current与永久lineage

PostgreSQL是唯一运行时current authority。schema至少保存：

- singleton current pointer：`authority_id/fleet_id/current_policy_revision/current_policy_sha256`；
- 每个revision的immutable exact canonical bytes、digest、exact previous pointer和commit DB time；
- 每个`credential_id`的first-seen SPKI digest/revision与active/revoked tombstone；
- 每个SPKI digest的first-seen credential ID/revision与永久tombstone；
- current credential projection，仅作为exact revision bytes的校验后索引，不能独立更新或成为第二authority。

这些表属于exact clean-slate authority schema 13；version 12不做in-place migration或repair，任何新Control
replica都必须在空的version-13 schema上启动，不存在mixed-version rolling window。

writer取schema-scoped exclusive advisory transaction lock并锁current pointer：

1. 空Store只接受revision 1、null previous和fresh `authority_id/fleet_id`；
2. same revision只在authority/fleet/digest/exact bytes逐byte相等时作为零写成功；
3. successor只接受current revision + 1和expected previous逐字段等于current；checked add溢出拒绝；
4. same revision conflict、stale、gap、wrong previous、authority/fleet变化均回滚；
5. candidate中每个credential ID与SPKI查永久lineage；任一曾绑定不同另一半、已撤销后重现、或cross-ID
   SPKI复用均回滚；
6. old中存在、candidate中缺失的credential在同一transaction永久标记revoked；更新current projection、
   immutable revision与pointer原子提交。

empty active set是正常durable revision和紧急关闭机制。artifact文件缺失、被替换或仍含old revision均不能
回滚PG current。启动loader只把fixed artifact交给上述writer做initial/successor/exact replay；成功后每次
请求都从PG current读取，绝不把local bytes当作较新的事实。

正常certificate/credential rotation固定为：

1. PKI签发new leaf和fresh private key；发布`old+new` successor policy；
2. Gateway部署new certificate并确认新请求可用；
3. 发布只含new的successor，old永久撤销；
4. 之后才从secret channel删除old private material。

泄漏时可直接提交移除old或empty active set。删除CA/certificate文件不能替代PG撤销；已建立TLS connection的
下一HTTP request仍必须读current policy。

## 4. Fixed filesystem与secret边界

Control installed directory固定为`/etc/cats/route-v2`：

| item | exact path | owner/mode | max |
|---|---|---|---|
| policy install candidate | `gateway-workload-authority.v1.json` | root:root `0644` | 65536 |
| Gateway client CA bundle | `gateway-client-ca-bundle.pem` | root:root `0644` | 65536 |
| Control machine server chain | `control-machine-server-certificate.pem` | root:root `0644` | 65536 |
| Control machine server key | `control-machine-server-private-key.pem` | root:root `0600` | 16384 |
| directory | `/etc/cats/route-v2` | root:root `0700` | — |

每个entry必须regular、link count恰好1；路径component和final entry不得symlink/hardlink。reader从filesystem
root逐component no-follow打开fixed directory，只从保留directory descriptor打开fixed basename；bounded read
前后metadata与byte count必须稳定。成功返回前从root重开同一fixed path，逐级比较device/inode/owner/完整
mode/type/link，再重开final files并逐字段比较identity、metadata和exact bytes。任一变化fail startup。

CA bundle只接受有界PEM certificate序列；server chain至少一个certificate，server private key只接受与leaf
匹配的PKCS#8 Ed25519 material。TLS构造完成前需做pair challenge或rustls provider pair validation。生产没有
alternate path、inline PEM/JSON、environment bytes、provider-derived fallback或runtime `openssl`。

Terraform/IaC可以保存non-secret policy JSON、CA/server/client public certificate、预建secret的opaque name和
read/install权限；不得接收、读取或输出private bytes。private material由独立root-only secret channel在服务
停止或原子versioned安装窗口写入real file，不允许projected symlink冒充fixed artifact。Debug/Display/error/
metric/log不得包含private bytes、peer certificate、opaque Grant、Cookie或用户Authorization。

## 5. mTLS peer proof与pre-body认证

Control machine listener只允许TLS 1.3与HTTP/1.1 ALPN。它使用fixed client CA bundle验证peer完整certificate
chain；无证书、unknown CA、过期/用途错误或握手失败均不会生成HTTP request。成功后从verified leaf提取exact
SPKI DER并计算SHA-256，生成不可由request header构造的`VerifiedGatewayTlsPeer`。

每个request都执行以下顺序；HTTP keepalive与TLS session resumption不能缓存授权结果：

1. 建立request绝对2000ms deadline；精确检查method/path且拒绝query；
2. 从connection extension取得verified leaf SPKI digest；不存在返回401；
3. 在deadline内取得独立authentication admission/active owner；
4. PG read transaction取shared authority advisory lock，读取current pointer和exact revision bytes，closed decode
   并逐字段比对current projection；按SPKI digest命中恰好一个active credential，生成typed
   `AuthenticatedGatewayPrincipal {authority_id, fleet_id, policy_revision, policy_sha256,
   credential_id, public_key_spki_sha256}`；没有current、empty set、unknown/revoked/mismatch/corrupt返回401；
5. 只有此后才检查独立Route signer已组成；未组成返回503，仍不读body、不取Route permit、不访问Route Store；
6. 再验证strict media/header、取得Route resolve permit并bounded读取/解码body。

pre-body transaction不能检查Workspace scope，因为request尚未提供可信route。它只证明credential在一个current
fleet authority中active；typed principal不是Workspace membership，也不能用于其他Control API。

## 6. 同一snapshot内的Workspace授权与签发

bounded body只含canonical hostname。Route Store closure与handler共享authentication和resolve active owner。
closure在一个PG read snapshot内取同一shared advisory lock并闭合：

1. current Gateway pointer/revision exact bytes、projection与pre-body principal的authority/fleet/credential/SPKI
   仍逐字段相等；
2. current hostname/Endpoint/Desired权威链得到唯一`workspace_id`；request/header不能提供或覆盖它；
3. current credential scope为`fleet`，或其sorted Workspace闭集含该`workspace_id`；
4. Route Grant v2 §3全部runtime、placement、session、fresh full inventory和ring ACK事实；
5. 进程内fixed Route signer descriptor等于同一PG snapshot的current signer binding。

任一Gateway current变化、撤销、scope不含Workspace或stored projection不一致都不签发并返回401；Route signer
缺失/stale/disabled返回503。Gateway policy writer和signer writer都取exclusive lock，因此撤销/rotation与
一次签发有明确先后：签发snapshot先取得shared lock则该token属于撤销前；writer先提交则旧credential不能签发。

pre-body成功与最终snapshot之间发生policy变化不是TOCTOU授权：最终snapshot必须重新读取current，不能用
principal中的revision跳过校验。response丢失后不缓存或复用token；retry从新的TLS-request/PG snapshot开始。

## 7. Listener、deadline与shutdown

machine listener与public management listener地址、router和TLS配置独立；只有machine router暴露
`POST /v1/internal/routes/resolve`。public router即使收到相同path也没有TLS peer principal并保持401；本规格
不开放Gateway public proxy。

authentication和Route resolve分别有启动时验证的bounded semaphore与active-owner state。取得owner后，
handler和已启动Store closure各持一份同一RAII lease；client cancellation、timeout或response loss只释放
handler owner，Store owner在blocking closure真实结束后释放。deadline是从headers进入handler到response完成
的一个绝对时间，不因authentication或blocking hop重新开始。

shutdown顺序固定为：关闭machine listener新连接/admission，关闭authentication admission，关闭Route resolve
admission，等待两类active owner归零，再join server task。等待期间不接受新request；deadline/cancel不会把
仍运行的Store closure伪装成完成。无machine配置时不bind listener；缺任一artifact/PG binding/signer时readiness
关闭且不能降级到plain HTTP、shared bearer或public router。

## 8. Minimal acceptance matrix

| boundary | required oracle |
|---|---|
| codec | fixed vector；unknown/duplicate/noncanonical/65537拒绝；0/1/16 credentials成功、17失败；ID/SPKI/Workspace严格排序唯一；revision邻接 |
| PG initial/replay | revision 1/null；exact replay零写；same-revision conflict、stale/gap/wrong previous拒绝；authority/fleet immutable |
| permanent lineage | credential ID换SPKI、SPKI换ID、removed ID/SPKI重现全拒绝；empty set durable；cross-replica CAS唯一winner |
| rotation/revocation | old -> old+new -> new；unknown/revoked/empty 401；old keepalive下一request重新读PG失败；scope缩小与签发串行 |
| filesystem | fixed path、root owner/mode/type/link、bounded stable read、重开identity/bytes；symlink/hardlink/rename/byte-ABA拒绝；private不进Debug |
| TLS | checked-in bounded CA/server/client DER/PEM vectors；valid chain+known leaf成功；unknown CA/leaf、no client cert、wrong EKU/algorithm拒绝；SAN/subject/header变化不改变映射 |
| request order | no config/peer/unknown/revoked均pre-body/pre-PG 401；principal但no exact signer pre-body/pre-PG 503；body不能构造principal |
| final snapshot | hostname-derived Workspace scope；concurrent revoke/scope CAS与signing只有一个顺序；stale signer 503；stored projection drift fail closed |
| lifecycle | response loss普通retry；client cancel/timeout不提前释放Store owner；shutdown closes both admissions and joins active closures |
| separation | A19/A23/V1/signer/shared bearer/WorkOS/header principal均不能构造peer proof或Gateway principal；public router仍401、Node admission不变 |
