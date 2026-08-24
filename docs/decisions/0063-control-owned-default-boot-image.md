# ADR-0063：Control 为新 Cat 绑定当前默认 Boot Image

- 状态：Accepted
- 日期：2026-08-23
- 修正：[ADR-0059](0059-semantic-control-node-synchronous-protocol.md) 的 Cat create 配置身份
- 保留：[ADR-0017](0017-golden-root-shared-base-images.md) 的 immutable、content-addressed Golden Root

## 背景

Boot image 是平台发布并资格化的 Golden Root，不是 Workspace 用户维护的应用镜像。要求用户在网页或
CLI 中复制 `sha256:` digest，会把部署工件选择泄漏到产品创建流程，也使普通用户必须知道对象存储中的
内部 image identity。

Golden Root namespace 只有 immutable content digest；digest 的字典序和对象列表顺序都不表示发布时间。
因此客户端或 Control 不能通过 LIST 猜测“最新”，也不能把可变 `latest` tag 当作已持久化 Root 的身份。

## 决策

1. 部署为 Control 提供一个精确的 `CATS_BOOT_IMAGE=sha256:<64 lowercase hex>`。它表示当前已经资格化、
   准备提供给新 Cat 的默认 Golden Root。生产 Terraform 用一个非 secret、受校验的
   `default_boot_image_digest` 输入把同一值交给所有 Control replica。
2. Public Cat create DTO、用户控制台和 `cats create` 不再接收 boot image 字段或参数。用户只选择 slug、
   CPU、内存和初始 PersistentDisk mounts。
3. Control 只在新 `cats` row 成功插入时把当时的默认 digest 固化为 `cats.boot_image`。Control→noded
   command、Cat projection、Root provision 和后续 run/recovery 仍携带这个精确 immutable digest；内部
   协议绝不传 `latest`、tag 或 image alias。
4. 当前同 slug Cat 已存在时，create replay 比较 CPU、内存和按 immutable Disk ID 排序的 mount 集合，
   不把后来变化的部署默认值与已存 `boot_image` 比较。这样一次响应丢失后的用户重试不会因为平台已经
   发布新默认镜像而变成 `cat_configuration_conflict`。已有 Cat 始终保留最初的精确 digest。
5. Cat destroy 后复用同一 slug 会创建新 immutable Cat ID，并采用届时的 Control 默认 digest。更新默认
   镜像不 rebase、重启或改写任何已有 RootDisk。
6. Control 启动时拒绝非 canonical digest。真正创建 Root 时仍按 ADR-0017/0061 验证 exact manifest、
   content 和 provision target；配置 digest 不是 image 存在或内容正确的替代证明。

## 后果

用户创建 Cat 不再需要理解 Golden Root 发布细节，网页与 CLI 的请求形状相同。数据库和 Node 物理路径
仍只依赖 immutable digest，因而默认升级不会改变已有 Cat 的恢复身份。

“最新”明确表示一次部署选择的当前 qualified default，而不是对象存储时间排序。发布新 Golden Root 的
操作流程必须先完成发布/资格化，再用同一个 reviewed rollout 更新所有 Control replica；混用不同默认值
只会影响各自新插入的 Cat，不能成为隐式滚动升级机制。
