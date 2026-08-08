# ADR-0012：AWS资源与生产部署由Terraform管理

- 状态：Accepted
- 日期：2026-07-24

## 决策

AWS生产资源和Kubernetes生产部署的创建、变更与删除统一通过reviewed Terraform
plan/apply。紧急控制台或CLI操作必须随后导入配置，并以无意外drift的plan收敛。

State按失效域与权限边界拆分：

- `bootstrap`：远端state基础；
- `platform`：VPC、EKS、RDS、ACM、ECR、ChunkStore和metal workers；
- `production-infrastructure`：usage stream/archive/checkpoint及其IAM；
- `production-payments`：Stripe产品、价格和Webhook入口；
- `production-application`：Cats Kubernetes workloads、service、ingress和runtime config。

共享资源进入Terraform管理前必须从live API盘点，写出精确配置，审查replacement属性，
import到目标state并取得无意外create/destroy的plan。`data` source只表示读取，不表示管理权。

## State与发布安全

- 远端S3 backend启用versioning、默认加密、public-access block、TLS-only policy和native
  lockfile。
- State和saved plan按secret处理；Kubernetes Secret与DSN即使标记`sensitive`仍可能进入state。
- Provider使用dependency lock；生产镜像和worker bundle使用不可变digest。
- Platform与application分别plan/apply；`-target`不作为正常发布流程。
- Destructive plan必须列出精确resource address和replacement原因，并由独立review确认目标
  account、region和environment。

Terraform负责资源、IAM、部署描述和secret delivery。镜像构建、数据库schema migration、
runtime reconciliation与故障恢复由各自组件合同负责；Terraform不使用provisioner或远程shell
隐藏这些操作。

## Authority边界

- 每份secret只有一个生成/轮换authority；Terraform只传递引用或受控值。
- Workload identity遵循least privilege；Gateway不获得storage/usage写权限，Guest不获得平台
  凭据。
- Production、qualification和developer环境使用不同identity、namespace、state与data。
- Object Lock、KMS deletion window、RDS replacement和worker销毁等不可逆/高风险参数在首次
  apply前显式审批。

## 验收

- fresh environment可由reviewed configuration重建；重复apply无drift；
- import前后的plan不意外替换live资源；
- state locking、backup/version recovery与credential rotation演练通过；
- production artifacts可追溯到source SHA和digest；
- application、platform和qualification权限不能越过各自边界；
- decommission先drain/保护数据，再由精确saved plan删除已确认资源。
