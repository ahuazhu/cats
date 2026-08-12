# ADR-0038：隔离的生产形态 Qualification Cell

- 状态：Accepted
- 日期：2026-08-06
- 关联：[ADR-0012](0012-terraform-managed-aws-resources-and-deployments.md)、
  [ADR-0024](0024-digest-pinned-oci-bundle-deploy.md)

## 决策

真实故障验收运行在独立的qualification cell。优先使用专用AWS account；必须位于生产account
时，cell仍使用独立namespace、Terraform state、VPC/subnets/security groups、RDS、S3/KMS、
DNS、IAM和workers。生产资源、数据、凭据和hostname都不是测试输入。

Account、region、cell ID和namespace由reviewed invocation显式提供。Provider使用
`allowed_account_ids`并校验caller identity。所有可tag资源带统一cell identity；代码与示例
不写入真实account ID、ARN、bucket或instance ID。

## 最小authority

- Terraform apply角色只管理该cell中精确列出的resource addresses；生产state和生产runtime
  role不授予它权限。
- Fault actor只执行测试用例声明的窄动作，例如终止指定进程、隔离指定test Host或触发指定
  test RDS failover；每次动作记录目标和恢复步骤。
- Observer使用read-only identity读取测试资源、服务API和证据位置，不与fault actor共享写
  权限。
- Host fencing测试使用仅对test Hosts有效的adapter；production Host永远不匹配其scope。

Qualification复用标准Terraform stacks、`quality.sh`、部署runbook和场景测试。不建立独立的
业务状态机、发布authority或证据数据库；场景以确定性ID和可重复postcondition恢复。

## Artifact与证据

- 部署输入绑定source SHA、container digest、worker bundle digest和schema/protocol version。
- 一次验收记录environment manifest、测试边界、exact commands、start/end time、fault targets、
  oracle、exit status及原始日志位置。
- 正式结果和失败证据写入versioned/encrypted evidence storage；临时cache可删除。
- 同一个结论只引用同一个evidence manifest，不把单次metal结果转换成生产SLA。

## 运行方式

Cell按测试矩阵创建所需的最小拓扑。kernel-NBD与vhost-user-blk都必须在Linux/Cloud
Hypervisor上验收；跨Node测试为当前块路径提供两个可隔离Node。资源可以按需创建和销毁，
无需永久维持另一套控制平面。

故障编排器位于被测故障域之外。测试结束先恢复网络/数据库和Host fence，再验证Cats收敛，
最后按manifest精确清理test资源。任何目标identity不完整、plan出现未声明destroy/replace、
或denylist命中生产资源时立即停止。

## 验收

- Qualification identity不能读取或修改生产data、credentials、DNS和runtime resources；
- reviewed saved plan只包含声明的cell targets，apply后重复plan无意外drift；
- Controller/Agent/VMM/blockd、RDS、S3、network和Host故障可在各自边界注入与恢复；
- 两个块路径运行相同的durability、fencing、reconciliation和cross-Node矩阵；
- observer/fault权限分离，证据在被测服务失败后仍可读取；
- 清理只删除manifest列出的test resources，失败时保留证据并报告残留。

## 后果

真实故障证据与生产资源隔离，同时复用产品本身的部署和测试路径。代价是需要一组受限AWS
identities和按需bare-metal成本；这些成本不转化为新的平台级qualification架构。
