## 访问 Fleet 管理边界

通过独立运维站点的管理员控制台，或在 CLI 中登录。WorkOS 访问需要已配置的管理员 Organization 和默认 `cats:fleet:admin` Permission；Fleet 自动化也可以使用独立的 break-glass 管理员机器凭据。

    cats login
    cats admin monitoring
    cats admin nodes

    # 仅供 break-glass 自动化：
    CATS_TOKEN='administrator-credential' cats admin monitoring

**这不是用户凭据**

管理员机器 Token 是 Fleet 自动化/break-glass 身份。不要交给用户、嵌入控制台或放进 Guest。

## 查看 Fleet 监控

`cats admin monitoring` 报告 Cat 生命周期数量、Node 状态、CPU/内存分配与 Operation 阶段。管理员控制台还提供自动刷新、Host Telemetry 与原始 Prometheus Metrics。应调查每个 Node/Project，而不能只依赖 Fleet 平均值。

## Node 操作

    cats admin node get node-a
    cats admin node cordon node-a
    cats admin node drain node-a
    cats admin node uncordon node-a
    cats admin node delete node-a

| 操作 | 用途 | 安全条件 |
|----|----|----|
| Cordon | 停止新 Placement | 现有 Cats 继续运行。 |
| Drain | Stop/Fence 并重调度 Cats，最终保持 Cordoned | Durable Disk Gate 与恢复容量可用。 |
| Uncordon | 让健康 Node 重新参与调度 | 版本、KVM、NVMe、网络与时钟检查通过。 |
| Delete | 移除 Registry 记录 | Node 为空且处于 Cordoned 或 Lost。 |

## Drain 流程

1.  确认替代容量以及 Object/Metadata 服务健康。
2.  Cordon Node，观察不再产生新 Allocation。
3.  执行 Drain；Suspended 与 Warm Cat 在跨 Host 前必须转为 Cold。
4.  确认 Allocation、Dirty/Pending Commit、Route Binding 与本地 Snapshot 归零。
5.  完成身份与本地 Cache 清理后，才能删除或替换 Node。

## Node 丢失

不要立即启动重复 Guest。等待 Node Lease 或云 Fencing 证据，撤销旧磁盘 Owner，签发更高 Attachment Epoch，并分批恢复 Cat。限制 Boot、对象 GET 与数据库压力，避免恢复风暴。

## Metrics 与审计

`/metrics` 需要管理员权限。关联 Request ID → Operation → Cat → Node → Attachment → Route Epoch。审计 Node 操作和授权决策，但绝不能记录 Token、Cookie、DSN、Secret、终端明文或 Guest 磁盘数据。

## 管理员 HTTP API

    GET    /v1/admin/monitoring
    GET    /v1/admin/nodes
    GET    /v1/admin/nodes/{id}
    DELETE /v1/admin/nodes/{id}
    POST   /v1/admin/nodes/{id}/actions/{verb}
    GET    /metrics

支持的 Node Action Verb 是 `cordon`、`uncordon` 与 `drain`；取消 Drain 也使用 `uncordon`。所有路由都要求 Fleet Administrator 身份；Node Register/Heartbeat、Route Resolve 与 Internal Work Endpoint 仍是仅供 Service 使用的 API。

## 当前源码的生产限制

仓库仍缺少原生 vhost-user-blk、tap/overlay Guest 网络、Suspended page-out（CH 路径当前仅 Pause）、Project Resource Store 的 PostgreSQL 实现与权限隔离。Cloud Hypervisor Phase-A 路径已经通过已记录的裸金属验收，但在这些剩余项完成前，不能称整个技术栈已经 Production Ready。
