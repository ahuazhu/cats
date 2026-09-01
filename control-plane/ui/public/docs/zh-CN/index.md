Cats 在一个不可变 Workspace 边界内提供持久 Linux microVM Resource。

## 当前 Release Surface

Signed Runtime Cutover 有意只暴露窄产品 Surface：

- Create、List 与 Inspect Cat。
- 通过精确、幂等的 Action Run、Suspend、Warm、Cold 或 Destroy 一只 Cat。
- Create、List 与 Inspect PersistentDisk。
- 在精确 Cat 处于终态 Cold 时 Attach 或 Detach 一个 PersistentDisk。
- Create、Inspect、Restore 与 Delete Cold PersistentDisk Snapshot。
- 按 ID Inspect 一个精确的已接受 Operation。
- 使用 Guest-local Runtime API 与独立 Identity/Billing Surface。

Endpoint、容量变更与 PersistentDisk 删除仍不可用。控制台和 CLI 会 fail closed，不探测 Legacy Route。

## 选择阅读路径

<a href="/zh-CN/docs/getting-started/" class="doc-card"><strong>快速入门</strong>用当前控制台或 CLI 创建并查看 Cat。</a> <a href="/zh-CN/docs/cats-lifecycle/" class="doc-card"><strong>Cat 与生命周期</strong>理解 Lifecycle Model 与当前 Mutation 边界。</a> <a href="/zh-CN/docs/storage-disks/" class="doc-card"><strong>存储与磁盘</strong>创建容量不可变的磁盘并理解 Durability。</a> <a href="/zh-CN/docs/endpoints/" class="doc-card"><strong>Endpoint</strong>理解目标网络模型与当前 Release 边界。</a> <a href="/zh-CN/docs/cli-reference/" class="doc-card"><strong>CLI 参考</strong>当前 Release 发布的命令。</a> <a href="/zh-CN/docs/api-reference/" class="doc-card"><strong>HTTP API 参考</strong>精确的当前 Product Route 与 DTO。</a> <a href="/zh-CN/docs/runtime-api/" class="doc-card"><strong>Guest Runtime API</strong>使用 Guest-local Unix Socket。</a> <a href="/zh-CN/docs/console-workspaces/" class="doc-card"><strong>控制台与身份</strong>WorkOS Session 与 Workspace 隔离。</a> <a href="/zh-CN/docs/operations-troubleshooting/" class="doc-card"><strong>Operation 与故障排查</strong>恢复精确 Create Identity 并收集证据。</a>

## 产品模型

一只 Cat 拥有一个 RootDisk。PersistentDisk 是独立 RWO Resource，Release 容量不可变。不可变 Runtime Config、Signed Atomic Lifecycle Command 与 Signed Volume Authority——而不是浏览器或 CLI——协调 Lifecycle 与 Writer Epoch。
