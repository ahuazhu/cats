# Route Grant V2 fixed vectors

这些文件是 B1 issuer、B3 Gateway strict parser、B2/B4 Node verifier 的共同契约输入，不是生产
密钥或示例配置。

| 文件 | 内容 |
|---|---|
| `positive.json` | exact canonical header/claims、compact token、完整 A0→Route→Node lineage snapshot、verifier context 与预期 accept |
| `negative.json` | exact malformed/signed/tampered token、issuer/lineage/install、active-session/writer transfer 与真实 PostgreSQL 并发矩阵 |
| `hostname.json` | 跨 Control Plane/Gateway/Node 共用的 normalization corpus |
| `test-public-key.spki.pem` | 对应测试 public key |

公开的 RFC 8032 test seed 直接记录在 `positive.json`，供 issuer contract test 构造 test-only
signer；不提交任何 private-key PEM，避免 fixture 被误装载为部署凭据。raw Ed25519 public key 是
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`，其 `kid` 是 raw key 的
SHA-256 lowercase hex：
`21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9`。

所有 Unix 时间是刻意固定在未来的纯整数，不代表证书、SLA 或生产 TTL。consumer 必须使用每个
case 给出的 `now` 和 local authority，不能用测试机 wall clock。JSON 文件本身不是 wire；
`header_json`、`claims_json` 和 `compact` string 的内容才是 exact wire bytes。wire
`cat_generation` 必须逐值等于 A0 `intent_generation`；它不是 C `runtime_generation`。fixture 中
`issuer_snapshot` 冻结 Cat intent、`cat_runtime_state`、exact reducer route intent、materialized
Route 与 Node ACK 的完整 command/dispatch/claim/result/runtime lineage。

fixture reference 规则固定：值为 `$positive.<dot-path>` 时深拷贝 `positive.json` 对应 JSON 值；
值为 `$case.<dot-path>` 时深拷贝当前 case 内已定义值；随后才逐个应用同 case 的 `*_override`
dot-path。token segment case 唯一允许在 reference 后追加 literal `=`，用于 padding-negative；
`current_nonterminal_command_matrix` 的 `$kind`/`$phase` 分别由笛卡尔积变量替换。除此之外不允许
未定义的 `$` placeholder，避免 consumer 各自猜测。

跨组件最低门禁：

1. issuer 从公开 test seed 构造 test-only signer，产生与 `positive.json` 逐字节相同的三个 segment；
2. 独立 OpenSSL 或另一 Ed25519 backend 验证 positive signature；
3. Gateway parser 与 Node verifier 消费所有 `cases`，得到 exact `expected_class`；其中
   `deployed-adr-0033-v1-shape` 是现有 SPKI-`kid`/claims-version V1 wire，V2 必须明确拒绝；
4. issuer 消费 `issuer_snapshot_cases`、`issuer_generation_mutation_matrix`、
   `issuer_lineage_mutation_matrix`、`issuer_route_identity_mutation_matrix` 和
   `current_nonterminal_command_matrix`；lineage matrix 必须同时展开 optional boot identity 的
   value replacement、present→absent 和 absent→present 单层 mutation；current-command matrix 必须
   展开为 8 kinds × 7 phases = 56 个拒签 case；
5. Node 消费 `node_lineage_mutation_matrix`、`route_install_cases` 与
   `retirement_adoption_cases`，证明 old/same-epoch mismatch、predecessor mismatch、restart lineage
   mismatch（包括 optional boot identity presence）均 fail closed，并证明 auto-generated Suspend 只由 exact policy receipt +
   `PolicyRetirementPromotionV2` 授权，而 receipt/promotion race 中的 manual command 必须用 distinct
   command-scoped route-retirement work/receipt（manual 固定 `cancel_and_drain`）与
   `predecessor=retired_by_policy(P, retirement_token)`、
   `outcome=adopted_retired_predecessor` 接管 exact policy-revoked lineage；
6. Node/Route Controller/A0 lifecycle 消费 `retirement_mode_matrix`、`policy_proposal_cases` 与
   `retirement_compensation_cases`、`session_transition_cases`：人工/Drain/Destroy 用
   `cancel_and_drain`；auto policy 用
   `require_idle`，active HTTP/WS 只返回 busy、不 cancel，零 guard receipt 后才 promotion；同时证明
   adoption/compensation 在同一 Route row 唯一 CAS、compensation winner 迫使 manual 从 fresh epoch
   重规划，且 route-admission retirement 与 writer/durability transfer 是两个门；
7. B1 在真实 PostgreSQL 两个独立 session 上消费 `postgres_concurrency_cases`，使用显式 barrier
   验证 Cat-first lock order、fresh-snapshot whole-transaction retry 与 stale-intent CAS；
   `PG-POLICY-MANUAL.single_field_mismatch_replay_matrix` 必须逐个只改变 token、install、epoch 或
   lineage，证明无 receipt/Route mutation；mock/in-memory Store 不满足此门禁；
8. Control Plane、Gateway、Node 对 `hostname.json` 得到相同 canonical 结果；
9. 测试输出不得打印完整 compact token 或 seed。
