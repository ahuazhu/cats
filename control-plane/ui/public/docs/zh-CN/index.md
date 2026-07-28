Cats 给你一台长期存在的 Linux microVM：有自己的内核、自己的持久磁盘和固定域名。计算可以停，磁盘、名字和地址继续存在。

**不需要装任何东西就能开始**——在控制台建一只 Cat 就能用。

## 选择阅读路径

<a href="/zh-CN/docs/getting-started/" class="doc-card"><strong>快速入门</strong>在控制台开出第一只 Cat，再按需装 CLI。</a> <a href="/zh-CN/docs/cats-lifecycle/" class="doc-card"><strong>Cat 与生命周期</strong>理解 Running、Suspended、Warm、Cold、唤醒与删除。</a> <a href="/zh-CN/docs/storage-disks/" class="doc-card"><strong>存储与磁盘</strong>使用 RootDisk、PersistentDisk、快照、扩容、挂载和 durable FLUSH。</a> <a href="/zh-CN/docs/endpoints/" class="doc-card"><strong>Endpoint</strong>发布 Guest 端口、选择唤醒策略并了解当前网络能力边界。</a> <a href="/zh-CN/docs/cli-reference/" class="doc-card"><strong>CLI 参考</strong>全部命令、全局选项、输出模式与自动化行为。</a> <a href="/zh-CN/docs/api-reference/" class="doc-card"><strong>HTTP API 参考</strong>路由、身份权限、幂等、请求 Body、Operation 与错误。</a> <a href="/zh-CN/docs/runtime-api/" class="doc-card"><strong>Guest Runtime API</strong>通过 Guest 本地 Unix socket 上的 HTTP 阻止工作驱动休眠。</a> <a href="/zh-CN/docs/console-workspaces/" class="doc-card"><strong>控制台与身份</strong>WorkOS 浏览器/Device 登录、工作区、会话与语言设置。</a> <a href="/zh-CN/docs/operations-troubleshooting/" class="doc-card"><strong>Operation 与故障排查</strong>跟踪异步任务、理解错误并处理常见故障。</a>

## 产品模型

**Cat** 是一台长期存在的 Linux microVM，必须拥有 RootDisk。计算可以停止，Cat 名称与持久磁盘继续存在。Workspace 是面向用户的权限和资源边界，HTTP API 按它的不可变 ID 路由。

- **RootDisk** 跟随 Cat，并随 Cat 删除。
- **PersistentDisk** 独立存在，V1 只允许扩容，且最多挂载给一个读写 Cat。
- **Endpoint** 将稳定域名映射到一个 Guest 端口，并可唤醒休眠中的 Cat。
- **Operation** 记录每一次异步变更及其最终结构化错误。

## 当前能力边界

Cats 正在快速演进。下面是今天你会真实碰到的边界：

| 能力 | 现状 |
|----|----|
| Endpoint 协议 | 支持 HTTP/1.1，由区域 Edge 终止 HTTPS。**WebSocket 入站尚未支持。** |
| Guest 出站网络 | 每只 Cat 有独立网络与出站访问，敏感目标被阻断。跨 Node 的 Guest 私网互通尚未提供。 |
| PersistentDisk | 同一时刻只能挂给一只 Cat 读写，且只支持扩容、不支持缩容。 |
| 快照 | 可以创建快照；列出与恢复的便捷命令尚未提供，目前需要走 HTTP API。 |
| 唤醒并发 | 同一节点上同时唤醒的 Cat 数量有上限。超出时唤醒会**排队而不是失败**——高峰期唤醒可能变慢。 |
| 交互式终端 | `cats shell` 需要 CLI；控制台目前提供单条命令执行，没有常驻终端。 |

**性能数字是实验依据，不是 SLA**

我们公布的每个性能数字都带样本数、硬件和测量口径。原型上测到的数不会被写成生产承诺——请按你自己的负载判断适用性。

## 文档约定

示例使用 `cats login` 选中的 Workspace 与名为 `dev` 的 Cat。请按部署替换。容量支持 `512MiB`、`8GiB` 等二进制后缀。
