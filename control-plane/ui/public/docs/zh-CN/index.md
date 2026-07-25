**文档默认公开**

查阅产品与使用文档不需要 Cats 会话。控制台与资源 API 仍然执行各自的身份认证和权限边界。

## 选择阅读路径

<a href="/zh-CN/docs/getting-started/" class="doc-card"><strong>快速入门</strong>构建 CLI、配置访问、创建 Cat 并执行第一条命令。</a> <a href="/zh-CN/docs/cats-lifecycle/" class="doc-card"><strong>Cat 与生命周期</strong>理解 Running、Suspended、Warm、Cold、唤醒与删除。</a> <a href="/zh-CN/docs/storage-disks/" class="doc-card"><strong>存储与磁盘</strong>使用 RootDisk、PersistentDisk、快照、扩容、挂载和 durable FLUSH。</a> <a href="/zh-CN/docs/endpoints/" class="doc-card"><strong>Endpoint</strong>发布 Guest 端口、选择唤醒策略并了解当前网络能力边界。</a> <a href="/zh-CN/docs/cli-reference/" class="doc-card"><strong>CLI 参考</strong>全部命令、全局选项、输出模式与自动化行为。</a> <a href="/zh-CN/docs/api-reference/" class="doc-card"><strong>HTTP API 参考</strong>路由、身份权限、幂等、请求 Body、Operation 与错误。</a> <a href="/zh-CN/docs/runtime-api/" class="doc-card"><strong>Guest Runtime API</strong>通过 Guest 本地 Unix socket 上的 HTTP 阻止工作驱动休眠。</a> <a href="/zh-CN/docs/console-workspaces/" class="doc-card"><strong>控制台与身份</strong>WorkOS 浏览器/Device 登录、工作区、会话与语言设置。</a> <a href="/zh-CN/docs/operations-troubleshooting/" class="doc-card"><strong>Operation 与故障排查</strong>跟踪异步任务、理解错误并处理常见故障。</a>

## 产品模型

**Cat** 是一台长期存在的 Linux microVM，必须拥有 RootDisk。计算可以停止，Cat 名称与持久磁盘继续存在。Workspace 是面向用户的权限和资源边界；V1 HTTP API 底层仍保留兼容的 `project` 路径分段。

- **RootDisk** 跟随 Cat，并随 Cat 删除。
- **PersistentDisk** 独立存在，V1 只允许扩容，且最多挂载给一个读写 Cat。
- **Endpoint** 将稳定域名映射到一个 Guest 端口，并可唤醒休眠中的 Cat。
- **Operation** 记录每一次异步变更及其最终结构化错误。

## 当前 V1 开发形态

Rust workspace 已实现控制面、CLI、嵌入式用户/管理员控制台、Node 与 Guest Agent、Endpoint 网关契约、ChunkStore 引擎、云厂商无关存储 Adapter，以及 Cloud Hypervisor Phase-A 路径。评估或运行当前源码版本时必须了解以下限制：

| 领域 | 当前状态 | 实际含义 |
|----|----|----|
| 块设备前端 | 默认内核 NBD，可选原生 vhost-user-blk | 两种前端驱动同一个引擎与同一套提交协议。vhost-user-blk（`--ch-block-path vhost-user`）已通过协议级验收，但尚未做真机（KVM）验收，因此默认仍是内核 NBD。 |
| Guest 网络 | tap/overlay 尚未实现 | Endpoint 路由已覆盖 FakeVmm 开发路径，不能宣称 CH Guest 网络已经完整。 |
| 并发唤醒 | 按节点预算限流 | Suspended/Warm 唤醒按 resume commitment 字节数计入节点预算，超出的唤醒排队而非失败。默认值取 2026-07-21 实验验证点（10 并发），不是已证明的最优值。 |
| 控制元数据 | SQLite 开发存储 | 存储元数据 PostgreSQL adapter 已存在，但 Project 资源存储仍是 SQLite 开发形态。 |
| 权限隔离 | 尚未实现 | 只能在适当隔离的环境中运行开发组件。 |

**性能数字是实验依据，不是 SLA**

仓库内的基准保留了样本数、环境、测量边界和正确性判据。绝不能把原型测量直接升级为生产承诺。

## 文档约定

示例使用 `cats login` 选中的 Workspace 与名为 `dev` 的 Cat。请按部署替换。容量支持 `512MiB`、`8GiB` 等二进制后缀。
