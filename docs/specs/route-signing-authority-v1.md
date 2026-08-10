# Route v2 Signing Authority v1

- 状态：Frozen target contract；artifact codecs/readers 是首个 slice，持久 rotation/ACK composition 尚未实现
- 决策：[ADR-0044](../decisions/0044-independent-route-v2-signing-authority.md)
- Grant 与 admission：[Route Grant v2](route-grant-v2.md)
- Node observation：[Runtime Inventory and Observation Spine v1](runtime-inventory-observation-v1.md)

本文只冻结 Route v2 private signer、public-key ring、rotation/revocation 与部署 artifact。它不定义
Gateway workload principal、Control/Node TLS transport、public listener、Node proxy 或 Runtime scanner。
这些边界未闭合时 production Route v2 必须继续关闭。

## 1. Authority separation

Route v2 的 signer lineage 是独立 machine authority。下列身份或 key 均不得签发、安装、认证或恢复
本合同的状态：

- A19 per-Node registration/runtime-request private key；
- A23 deployment provisioner private key或其 trust bundle；
- V1 Route Grant signer/public key；
- shared service/admin bearer、Workspace token、WorkOS session；
- hostname、IP、TLS peer string 或 HTTP header 自报的 principal。

`deployment_id`只标识这套 Route v2 signing authority；它不能与 A23 deployment principal互换。
`secret_reference_id`是deployment/secret channel分配、永不复用的非 secret `Id`，只命名一把 private
key lineage。它不是 private bytes、provider credential、ARN parser 或调用 signer 的 bearer。

## 2. Fixed paths, metadata and bounds

| item | V1 exact value |
|---|---|
| installed directory | `/etc/cats/route-v2` |
| Control signer descriptor | `/etc/cats/route-v2/signer.v1.json` |
| Control private material | `/etc/cats/route-v2/signer-private-key.pem` |
| Control/Node public ring | `/etc/cats/route-v2/public-key-ring.v1.json` |
| descriptor maximum | 16384 octets |
| public ring maximum | 16384 octets |
| private PEM maximum | 16384 octets |
| directory owner/mode | root:root, exact `0700` |
| descriptor/ring owner/mode | root:root, exact `0644` |
| private material owner/mode | root:root, exact `0600` |

每个文件必须是regular、link count恰好1；路径和final entry都不得是symlink或hardlink。reader从
filesystem root逐component no-follow打开固定目录，只从保留的directory descriptor打开
固定basename；bounded read前后descriptor metadata必须逐字段稳定，且实际byte count等于metadata length。
任一owner/mode/type/link/path/read-change不等都 fail startup。production没有任意path、inline JSON、env
bytes或provider-derived fallback。

descriptor与ring是无BOM、无前后空白、无结尾LF的canonical JSON。private material是PKCS#8 Ed25519
PEM；其内容不得进入JSON、argv、environment、log、metric、panic/debug、Terraform state/output、Node、
Gateway或Guest。`secret_reference_id`可以进入bounded审计，但不能据此从另一个authority猜出secret。

## 3. Public-key ring artifact

```text
RouteGrantV2PublicKeyRing {
  version: 1,
  ring_version: Epoch,
  expected_previous: {
    ring_version: Epoch,
    key_ring_digest: Sha256Digest
  } | null,
  keys: [RouteGrantV2PublicKeyEntry]       // 0..=8
}

RouteGrantV2PublicKeyEntry {
  kid: KeyId,
  public_key_spki: Base64UrlNoPad
}
```

`keys`按`kid` ASCII octets严格升序且无重复。`public_key_spki`必须解码成唯一的44-byte canonical
Ed25519 SPKI DER（`302a300506032b6570032100 || raw-32-byte-key`），普通 SHA-256 的64 lowercase hex
必须逐byte等于`kid`。因此现有
`key_ring_digest(ring_version, sorted loaded_kids)`同时绑定version、key集合和每把key的exact SPKI。

revision 1必须`expected_previous=null`；revision N>1必须携带N-1的exact version/digest。gap、rollback、
same version different digest、错previous、超八把、非严格排序、重复SPKI/kid或kid/SPKI不等都拒绝，旧
ring继续有效。空ring是合法加载结果但不接受任何Grant；它与artifact unavailable不同。

Node installer必须先在同filesystem temporary file完整验证candidate和expected-previous，再fsync file、
atomic rename到fixed path并fsync parent，最后才原子swap进程内整环。crash在rename前保留old；rename后restart
只加载new。ACK只有在新环已durable且进程内swap完成后才可随下一次complete inventory提交，exact值为
`ring_version`、`key_ring_digest`和sorted `loaded_kids`。本slice不实现installer或scanner ACK。

## 4. Control signer descriptor

```text
RouteGrantV2SignerReference {
  version: 1,
  deployment_id: Id,
  signer_revision: Epoch,
  expected_previous: {
    signer_revision: Epoch,
    signer_reference_sha256: Sha256Digest
  } | null,
  signer:
    { state: "disabled" }
  | { state: "active", active_kid: KeyId, secret_reference_id: Id },
  public_key_ring_version: Epoch,
  public_key_ring_digest: Sha256Digest
}
```

`signer_reference_sha256`是exact canonical descriptor bytes的普通SHA-256。revision 1必须null previous；
revision N>1必须逐字段指向N-1。descriptor引用的ring version/digest必须等于同一安装集合的exact public
ring。`active`还要求`active_kid`恰好出现一次；Control读取fixed private file后从private key导出canonical
SPKI/kid并与该entry逐byte匹配，再做sign/verify challenge。任一步失败都不构造signer、不使Route v2
handler进入authenticated serving状态且readiness关闭。`disabled`不读取或构造private signer，即使旧
material仍因retention存在。

下列initial artifact是跨component fixed vector；code block中每个JSON各为单行、没有结尾LF：

```json
{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb","public_key_spki":"MCowBQYDK2VwAyEA2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"}]}
{"version":1,"deployment_id":"route_deployment_a","signer_revision":1,"expected_previous":null,"signer":{"state":"active","active_kid":"fd56fed3251463eff0063169a7f8fa9dce585b6eee429581264297c98ec58bcb","secret_reference_id":"route_secret_a"},"public_key_ring_version":1,"public_key_ring_digest":"sha256:4e6fec49756e03044438af279f7bfd9507f06cf065ff0673447bd6377cd07ac0"}
```

ring exact bytes SHA-256 是
`sha256:614059d6616d068e7d210da2c26a15cfb42c0d3933a7144670d13c658b1bb2c8`；signer descriptor
exact bytes SHA-256 是
`sha256:c2c83d723f0bcd83560a19eadecbd64d574c7d0332c50700bea3bd8cb3f5da5c`。

部署artifact只是给持久Store writer的typed candidate，不凭本地文件覆盖PG。最终startup transaction必须
以`deployment_id + signer_revision + expected_previous`做exact CAS并永久保存每个revision/digest、
secret-reference/kid lineage；same exact revision replay零写，same revision不同bytes、gap、stale、曾retire
的reference/kid复用全部fail startup。该writer尚未实现，本slice因此不会把reader接到production service。

每次resolve的单一PG signer snapshot最终还必须比较进程内`deployment_id/signer_revision/reference digest/
active kid/secret reference`与current persisted state。旧replica即使仍能访问旧private file也只能返回503。
这项compare与rotation writer共享singleton lock；snapshot的DB now产生Grant `iat`，writer切key时同一DB now
作为`last_old_issue_at`上界。writer和resolve compare尚未实现。

## 5. Rotation, retirement and revocation

正常old -> new rotation只有下列顺序：

1. 在独立secret service/HSM生成new key和fresh、永不复用的secret reference；将public half加入old+new
   ring revision，发布并等待全部current provisioned且A23 policy为`schedulable`的Node ACK exact
   version/digest/loaded-kids。成为schedulable的policy transaction也必须证明该Node已ACK current published ring。
2. signer CAS逐字段验证所有上述ACK和descriptor previous pointer，切active kid/reference到new，并以同一次
   transaction DB now持久`retiring_kid=old`与`last_old_issue_at`。一次只能有一个retiring key。
3. old public/private至少保留到checked
   `last_old_issue_at + MAX_ROUTE_GRANT_V2_TTL_SECONDS(300) + MAX_ROUTE_GRANT_V2_CLOCK_SKEW_SECONDS(5)`；
   equality仍不可retire。此间只能在old private仍存在且overlap ring仍发布时回切。
4. deadline后发布只含new的下一ring revision；已有overlap ACK的Node仍可接new token，移除artifact逐Node
   原子加载。再次等待全部schedulable Node exact ACK。
5. signer CAS确认retention、new-only published pointer及全部ACK后永久retire old kid/reference lineage；随后
   secret channel才可删除old private material。public/private deletion不能提前，也不靠文件缺席推断retire。

resolve只为其同一fresh observation ring中含current active kid的Node签发。因此staging期间old-only和overlap
Node可继续接old token；switch后任何回退到old-only artifact的Node立即不可签发。ring version/digest主要是
rotation/uncordon ACK CAS，不是第二份Endpoint authority。

泄漏或不明状态使用新descriptor revision把`signer.state=disabled`持久化；从该linearization point起所有
replica停止签发。reachable Node先关闭全部Route admission并drain/fence streams；不可达Host必须provider/BMC
隔离，不能以TTL或删public key替代。部署fresh key/ring、取得全量ACK并以新revision activate后才重开。

## 6. Deployment shape

- Terraform只保存canonical descriptor/public ring、`secret_reference_id`、provider secret resource reference
  和least-privilege read policy；不能接收private PEM variable，也不能从secret data source把bytes读入state。
- 独立secret channel在component停止时把exact referenced private half安装到fixed material path。Kubernetes
  使用预先创建、按名称/不可变version引用的secret source加本地real-file renderer；不能把projected symlink
  当作满足§2。Metal使用同一reference和root-only installer。两种形态都在启动前完整重验。
- Control image、worker bundle、Node identity/A23 trust和Guest release均不携private bytes。Gateway没有
  public/private key或sign权限；它只搬运opaque Grant。
- rolling rollout中PG CAS先使stale Control replica的resolve compare关闭；新replica只有完成artifact/pair/
  persisted-current验证才Ready。没有legacy signer、single-key fallback或“最后一次成功本地文件”恢复。

## 7. Minimal acceptance matrix

| boundary | required oracle |
|---|---|
| codecs | canonical fixed vectors；unknown/duplicate/noncanonical/16385拒绝；ring 0/1/8成功、9失败；sorted/unique、SPKI/kid、previous adjacency |
| filesystem | exact fixed path、root owner/mode/type/link、directory retention、bounded read前后metadata；symlink/hardlink/rename-recreate/byte-ABA拒绝 |
| signer pair | active kid在exact ring；private->SPKI->kid exact；mismatch/wrong algorithm/malformed PEM不构造signer；disabled不读private |
| separation | A19/A23/V1 keys、shared bearer、header identity均不能构造descriptor、signer或ring ACK |
| persisted lineage（future） | initial null previous；exact replay；stale/gap/same-revision conflict；retired reference/kid永不复用；old replica在current compare后503 |
| rotation（future） | overlap ACK -> switch -> 305s retention -> remove ACK -> retire；边界相等不retire；old-only restart switch后不签发；uncordon需要current ACK |
| revocation（future） | disable先于新签发停止；reachable close/drain、unreachable fence；fresh全量ACK后才resume；existing stream不因删key被伪装终止 |
| deploy（future） | Terraform plan/state无private PEM；只含reference/public ring/IAM；secret bytes不进argv/env/log；projected symlink不能冒充real installed file |
