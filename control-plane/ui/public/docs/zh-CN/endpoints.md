## 当前 Release 边界

Signed Runtime Cutover 期间，Endpoint Collection 与 Mutation Route 不属于 release product router。发布版 CLI 与浏览器控制台不展示 Endpoint Control，并在本地失败而不是探测 Legacy Path。

## 目标 Admission Model

Route Grant v2 绑定 Runtime Incarnation 与一个 Per-Endpoint Serving Epoch。离开 Running 前必须关闭 Node-installed Admission；只有新 Desired State 提高该 Endpoint Epoch 后才能重新打开。Route TTL 或 Heartbeat Timeout 不是 Host Fence。

这是目标架构 Contract，不代表 Production Route 缺失时用户 Client 可以构造 Endpoint Mutation。
