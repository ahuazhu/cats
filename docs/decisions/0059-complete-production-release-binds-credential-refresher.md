# ADR-0059：完整生产发布清单绑定独立 credential refresher

- 状态：Accepted
- 日期：2026-08-21
- 相关：[ADR-0029](0029-one-authority-for-the-database-password.md)、
  [ADR-0051](0051-production-final-reset-and-open-authority.md)、
  [ADR-0052](0052-bounded-production-qualification-admission.md)

## 背景

生产 application 实际运行三个独立 OCI image：Control、数据库 credential refresher 和 Gateway。
credential refresher 虽然与 Control 共用 Dockerfile source tree，却是独立 target、独立 tag、独立
registry digest 和独立 Kubernetes workload。原 manual release manifest 只关闭 Control、Gateway 与
worker 三个 artifact，部署因此可以引用一个未被同一 source fingerprint、final image extraction 和
registry digest 证明的 refresher。Control 与 refresher 的 tag 或构建来源发生漂移时，双镜像发布收据
仍可能表面完整。

## 决策

当前 clean-slate production release 的 canonical `release-manifest.v1.json` artifact set 精确为：

```text
control_plane
credential_refresher
gateway
worker
```

同一次 native x86_64 build 必须从 exact source tree 构建三个 linux/amd64 OCI image 和 worker bundle。
发布前从 final credential-refresher image 提取 `refresh-database-credential` 与
`swap-dsn-password.py`，逐字节比对 source fingerprint 已绑定的 reviewed programs；manifest 同时绑定
该 image 的 reference、OCI digest、config digest 和 registry verification。

三个 mutable tags 必须互不相同。原始 build Host 只导出 OCI transport，不持有 registry credential；
operator Host 逐 archive 验证 manifest identity 后发布，并只在三个 registry digest 全部精确匹配时
产生 registry-verified manifest。worker bundle 仍由独立 content-addressed S3/Terraform 边界发布。

这是一次单版本 clean-slate release-contract 替换。旧的三-artifact manual manifest 被当前 verifier、
operator-trust generator 和 proof-set validator 精确拒绝；不提供兼容 reader、补写或把旧 manifest
升级成新 manifest 的路径。`schema_version: 1` 是该仓库内部、source-bound proof object 的现行格式号，
不授权跨 source release 接受旧 artifact set。

## 后果

一次 production package receipt 现在能证明所有三个 application image 与 worker bundle来自同一 exact
source release，Terraform 不再消费清单之外的 refresher。代价是每次发布增加一个 OCI build/export、
下载、local load 和 registry push，release transport 也相应变大。

仓库提供 controller-side `package-production-release.py` 组合 exact source publication、native Host build、
content-addressed transport download 和三镜像 registry promotion；它刻意不执行 Terraform、Kubernetes、
Node provisioning 或 product mutation，因此 artifact authority 与 deployment authority 仍然分离。
