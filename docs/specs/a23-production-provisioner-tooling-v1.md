# A23 Production Provisioner Tooling v1

- 状态：Implemented operations contract；首次 clean-slate cutover only
- Authority：[ADR-0043](../decisions/0043-provisioner-owned-runtime-placement-policy.md)
- A23 wire：[Runtime Placement Policy v1](runtime-placement-policy-v1.md)
- Host artifact：[Runtime Composition Artifacts v1](runtime-composition-artifacts-v1.md)

本文冻结首次生产 cutover 使用的确定性工具边界。它不增加第三种 A23 principal、第二个签名实现、
第二份 NodeIdentity wire 或 direct-SQL bootstrap。所有 Control mutation 仍只由官方
`cats admin runtime-node provision` 的 durable pending/response-loss state machine 发往唯一 signed
node-authority route。

## 1. 中央 provisioner trust

首次 cutover 只生成 revision 1、`expected_previous=null`、一个 credential 的 trust bundle：

```sh
umask 077
cats --json admin runtime-provisioner trust generate \
  --deployment-id "$deployment_id" \
  --credential-id "$provisioner_credential_id" \
  --private-key-out /approved/provisioning/runtime-provisioner-key.pem \
  --trust-bundle-out /approved/provisioning/runtime-provisioner-trust.v1.json

cats --json admin runtime-provisioner trust verify \
  --credential-id "$provisioner_credential_id" \
  --private-key /approved/provisioning/runtime-provisioner-key.pem \
  --trust-bundle /approved/provisioning/runtime-provisioner-trust.v1.json
```

两个输出路径必须是绝对路径。private key 用系统 CSPRNG 生成唯一 Ed25519 PKCS#8 v2；A23 parser要求内嵌 public
half 并验证它，且只接受 generator 的 canonical PEM bytes：固定 `PRIVATE KEY` header/footer、base64 每行 64 列、
LF 换行和一个 final LF。它不能接受只含 seed 的 PKCS#8 v1、其他算法、裸 key、自定义 PEM、reflow、blank
line、CRLF、缺失 final LF 或额外 LF；A19 runtime compatibility parser 不受此收紧影响。private key 是 single-link、
current-user-owned、exact `0600` regular file；发布使用同目录 exclusive temporary file、file fsync、atomic
no-replace rename 与 parent fsync。目标已存在时只有 bytes 和 metadata 全部 exact 才是幂等成功，不覆盖或重生。

trust bundle 只通过 F0 `RuntimeProvisionerTrustBundle` decoder/encoder；unknown、duplicate、非 canonical key
order、非 canonical Ed25519 SPKI、错误 revision/previous、结尾 LF 或其他 byte 差异全部拒绝。offline verifier从
strict private key重新导出 canonical 44-octet SPKI，要求与所选 credential逐 byte匹配，并同时输出：

- ordinary SHA-256 of exact trust-bundle bytes；
- ordinary SHA-256 of canonical `RuntimeProvisionerActiveSet`；
- ordinary SHA-256 of canonical SPKI DER。

receipt只有 deployment/revision/credential和上述 public digest；private key bytes、PEM、seed不进入 stdout、
argv、environment、bundle、日志或 Node/Guest。revision 2 及以后继续按 Runtime Placement Policy §3 的
old+new overlap CAS执行，不由本首次-cutover生成器猜测 current lineage。

## 2. Host initial NodeIdentity

worker artifact包含 exact release 的 `cats` binary。initial provision必须在目标 Host以 root运行 staged binary，
且 Node service尚未启动：

```sh
sudo /approved/staged-worker/cats admin runtime-provisioner node-identity prepare \
  --node-id "$node_id" \
  --immutable-host-id "$provider_verified_immutable_host_id" \
  --state-path-id "$fresh_state_path_id" \
  --credential-id "$fresh_node_credential_id"

sudo /approved/staged-worker/cats admin runtime-provisioner node-identity export \
  > node-identity.v1.json
```

`immutable_host_id`只来自 provider/BMC/IaC 已认证事实；hostname、IP、IMDS或 Agent不参与。工具用现有 F0
`Id`和`StatePathComponent` validator，生成独立 Host-local Ed25519 PKCS#8 v2 private key，并用现有
`NodeIdentity` encoder生成 canonical artifact。private half始终只写 Host filesystem。

固定 filesystem transaction：

1. no-follow打开受保护 ancestors与`/etc/cats/identity`，要求后者 root:root exact `0700`；
2. exclusive no-follow创建/打开 root:root `0600` single-link `.provision.lock`并持有 kernel flock到命令结束；
3. 如果 initial complete marker缺失，只允许删除 closed partial
   `.node-identity-recovery.incomplete.v1`；unexpected entry/metadata fail closed；
4. 在 incomplete directory exclusive-create key、credential ID和identity，逐file fsync，使用共享
   `validate_node_identity_material`重验 canonical/cross-binding，directory fsync；
5. atomic no-replace rename为`.node-identity-provision.v1`并fsync parent。此后任何重试只接受exact immutable
   fields与same bytes，不生成第二把 key；
6. `export`只从完整 recovery marker读取并验证，stdout只写 canonical public `NodeIdentity` bytes，无LF。

rotation old/new marker任一存在时initial prepare拒绝。active三件套在没有initial marker时任一存在也拒绝；工具
不adopt散落文件、不按mtime挑选、不通过网络重建 private half。

## 3. 唯一 signed apply 与 activation

central actor把上一步 public identity与reviewed revision-1 cordoned policy交给官方 CLI；不要用 curl、SQL或本工具
另写签名器：

```sh
cats --json admin runtime-node provision \
  --identity /approved/public/node-identity.v1.json \
  --policy /approved/policy/node-placement-policy.v1.json \
  --deployment-id "$deployment_id" \
  --provisioner-credential-id "$provisioner_credential_id" \
  --provisioner-private-key-file /approved/provisioning/runtime-provisioner-key.pem \
  > /approved/results/node-authority-result.tmp

install -m 0600 /approved/results/node-authority-result.tmp \
  /approved/results/node-authority-result.v1.json
```

只有官方 CLI已经验证 exact origin、headers、canonical response并完成自己的 durable resolution receipt 后，才把
这次 stdout原样送回 same Host。不得手工构造、reformat或从另一 Node/release复用：

```sh
sudo install -o root -g root -m 0600 node-authority-result.v1.json \
  /approved/host-input/node-authority-result.v1.json

sudo /approved/staged-worker/cats admin runtime-provisioner node-identity activate \
  --apply-result /approved/host-input/node-authority-result.v1.json
```

activator先用 F0 decoder/encoder要求 result逐byte canonical，再要求
`node_id=prepared identity`、`outcome=provisioned`、`identity_state=provisioned`、`policy_revision=1`。任一不等在
active文件前拒绝。随后只从durable recovery descriptors安装：private key、credential ID、identity artifact
complete marker最后。每个目标用same-directory temp、file fsync、atomic no-replace rename、active file fsync与
parent fsync；已存在只接受exact bytes+metadata，因此任一 crash重跑都只forward-complete same set。

三件套重新走共享 Node runtime validator后，descriptor-relative创建并保护
`/var/lib/cats/node/<state_path_id>`；Control success、active files与state path全部 exact后才逐file/directory fsync
删除initial recovery set。Node service启动不属于 activator；后续 worker transaction仍须在 cordoned 状态启动、
注册并提交 complete empty inventory。

## 4. Acceptance

最小门包括：

| 边界 | oracle |
|---|---|
| trust | generator PKCS#8 v2 positive；PKCS#8 v1/错SPKI/非canonical PEM或bundle/unknown或LF拒绝；重复generate不换key |
| secret | bundle、receipt、argv/env无private bytes；key exact 0600/single-link/no-follow |
| recovery | partial closed set可清；unexpected set不删除；complete marker replay不换key；immutable field drift拒绝 |
| activation | wrong/noncanonical/wrong-node/non-provision result零active写；每个active file窗口可重放；artifact last |
| filesystem | protected ancestors、root-only identity dir、lock、mode/link/symlink/no-replace、file+directory fsync |
| composition | worker bundle携同commit `cats`；Node startup继续独立运行same material validator |
| authority | 只有官方 `cats admin runtime-node provision`发signed request；无SQL/curl/alternate signer |
