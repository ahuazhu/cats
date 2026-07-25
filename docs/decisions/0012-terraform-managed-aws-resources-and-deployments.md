# ADR-0012：AWS 资源与生产部署统一由 Terraform 管理

- 状态：Accepted
- 日期：2026-07-24

## 背景

Cats 已有一套通过 YAML、shell 和 AWS 控制台组合部署的 production-shaped 环境。计量
与计费又引入 Kinesis、独立 S3 usage archive、消费协调、IAM 和告警。如果继续依赖
手工创建资源或 `kubectl apply`，将无法可靠审查变更、重建环境、识别 drift，也容易让
敏感配置和计费证据处于无人负责的状态。

同时，现有 EKS、RDS、ChunkStore bucket、ACM、网络和裸金属 worker 已包含环境特定
配置。仅凭仓库文档重新声明这些资源可能触发破坏性替换，因此不能用一份猜测的
Terraform 配置直接覆盖现网。

## 决定

1. 从本 ADR 起，AWS 生产资源和 Kubernetes 生产部署的创建、变更与删除统一通过
   Terraform review + plan + apply 流程。AWS Console、`aws ... create/update/delete`、
   `kubectl apply/edit/delete` 不再是正常变更入口；紧急操作必须事后导入或回写配置，
   并通过无 drift 的 plan 收敛。
2. Terraform state 按失效域拆分：
   - `bootstrap`：远端 state S3 bucket；
   - `production-infrastructure`：不依赖 Kubernetes API 的 usage 基础设施；
   - `production-application`：依赖已有 EKS API 的 Cats Kubernetes 对象；
   - 现有 VPC/EKS/RDS/ACM/ECR/ChunkStore/metal worker 在完成精确盘点后进入独立
     platform state，不能混入 application state。
3. 已有资源在第一次受 Terraform 管理前必须：
   - 从 live API 导出实际配置；
   - 写出匹配配置并审查 replacement 属性；
   - `terraform import` 到目标 state；
   - 达到无意外 create/destroy、无破坏性 drift 的 plan。
   `data` source 只能读取资源，不能算 Terraform 已接管。
4. 远端 S3 backend 启用 versioning、默认加密、public-access block、TLS-only policy 和
   S3 native lockfile。state 和保存的 plan 都视为 secret，因为 Kubernetes Secret 与
   PostgreSQL DSN 即使标记为 `sensitive` 仍会进入 state。
5. Provider 使用 dependency lock file；生产镜像必须用 OCI `sha256` digest，不使用
   可漂移 tag。基础设施与应用使用独立 plan/apply，不能用 `-target` 作为正常发布方式。
6. Terraform 负责基础资源、IAM、部署描述和 secret delivery；它不负责构建容器镜像，
   也不替代应用启动时向前兼容的数据库 schema migration。禁止 Terraform provisioner
   通过远程 shell 修改数据库或节点来隐藏不可声明的变更。

## 当前落地范围

本次新增的 Terraform 已管理：

- usage Kinesis provisioned stream；
- 开启 versioning、Object Lock、生命周期分层和 destroy protection 的独立 S3 archive；
- usage projector 的 DynamoDB checkpoint table；
- producer、consumer、replay 最小权限 IAM policy、Kinesis throttling/lag 告警；
- `cats-controld` 专用 EKS ServiceAccount、Pod Identity role 与 association；
- Cats Namespace、EKS Auto Mode EBS StorageClass/PVC、runtime Secret、RDS CA ConfigMap；
- `cats-controld` / `cats-gatewayd` Deployment 与 Service；
- EKS Auto Mode IngressClassParams、IngressClass 和 ALB Ingress；
- metal worker artifact bucket、校验 digest 的 bundle、Secrets Manager runtime secret、
  最小权限 instance-role policy 和 SSM State Manager deployment association。

现有 EKS/RDS/VPC/ACM/ECR/ChunkStore bucket/裸金属 worker 仍是迁移输入，不因本 ADR
自动变成已由 Terraform 管理。它们在精确 import 完成前不得由新 stack 重建或修改。
旧 `deploy/aws/k8s/*.yaml` 只保留为迁移对照，不再作为生产 apply 源。

usage publisher、projector 与 S3 archive writer 运行在单副本 `cats-controld` 中。
publisher 只在 Kinesis 接受 attributed checkpoint 后确认 Node outbox；projector
按 50 秒/4 MiB/1000 条上限生成 NDJSON archive，投影 PostgreSQL 后再推进 DynamoDB
checkpoint。Pod Identity 只绑定 `cats-controld`；两个 gateway 不获得 usage AWS 权限。
当前 DynamoDB table 只实现 checkpoint，尚未实现多 projector shard lease，因此
应用保持单副本，扩容前必须先完成条件租约协议。

## 影响

- 初期 usage PostgreSQL 可以与现有 RDS 实例和 database 共用，但使用独立
  `cats_usage` schema、独立 DSN 变量和最小权限账号；这不新增 RDS 固定成本。
- 未来拆到独立 PostgreSQL 时，停止单写者、迁移并核对 ledger watermark，然后只修改
  `usage_postgres_url` 再由 Terraform 发布；storage DSN 和 Kubernetes 资源结构不变。
- S3 Object Lock 一旦启用不能对该 bucket 关闭。默认七年 GOVERNANCE retention 是
  财务证据的保守值，第一次 apply 前必须由财务/合规确认；COMPLIANCE mode 需要另立
  变更审查。
