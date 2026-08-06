# Route Grant V1 fixed vectors

这些文件是 B1 issuer、B3 Gateway strict parser、B2/B4 Node verifier 的共同契约输入，不是生产
密钥或示例配置。

| 文件 | 内容 |
|---|---|
| `positive.json` | exact canonical header/claims、compact token、verifier context 与预期 accept |
| `negative.json` | exact malformed/signed/tampered token，以及 time/local-truth 失败矩阵 |
| `hostname.json` | 跨 Control Plane/Gateway/Node 共用的 normalization corpus |
| `test-public-key.spki.pem` | 对应测试 public key |

公开的 RFC 8032 test seed 直接记录在 `positive.json`，供 issuer contract test 构造 test-only
signer；不提交任何 private-key PEM，避免 fixture 被误装载为部署凭据。raw Ed25519 public key 是
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`，其 `kid` 是 raw key 的
SHA-256 lowercase hex：
`21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9`。

所有 Unix 时间是刻意固定在未来的纯整数，不代表证书、SLA 或生产 TTL。consumer 必须使用每个
case 给出的 `now` 和 local authority，不能用测试机 wall clock。JSON 文件本身不是 wire；
`header_json`、`claims_json` 和 `compact` string 的内容才是 exact wire bytes。

跨组件最低门禁：

1. issuer 用测试 private key 产生与 `positive.json` 逐字节相同的三个 segment；
2. 独立 OpenSSL 或另一 Ed25519 backend 验证 positive signature；
3. Gateway parser 与 Node verifier 消费所有 negative case，得到 exact `expected_class`；
4. Control Plane、Gateway、Node 对 `hostname.json` 得到相同 canonical 结果；
5. 测试输出不得打印完整 compact token 或 seed。
