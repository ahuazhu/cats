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

`cats admin monitoring` 报告 Cat 生命周期数量、Node 状态、CPU/内存分配与 Operation 阶段。管理员控制台还提供自动刷新、Host Telemetry 与原始 Prometheus Metrics。应调查每个 Node/Workspace，而不能只依赖 Fleet 平均值。

## Node 操作

    cats admin node get node-a
    cats admin node cordon node-a
    cats admin node drain node-a
    cats admin node uncordon node-a
    cats admin node fence node-a --confirm-host-stopped-or-isolated
    cats admin node delete node-a

| 操作 | 用途 | 安全条件 |
|----|----|----|
| Cordon | 停止新 Placement | 现有 Cats 继续运行。 |
| Drain | Stop/Fence 并重调度 Cats，最终保持 Cordoned | Durable Disk Gate 与恢复容量可用。 |
| Uncordon | 让健康 Node 重新参与调度 | 版本、KVM、NVMe、网络与时钟检查通过。 |
| Fence | 撤销 Lost Node 的 claim，并对其 Cats 执行 Cold Recovery | 外部机制已经证明旧 Host 停机或被隔离；仅心跳超时不够。 |
| Delete | 移除 Registry 记录 | Node 为空且处于 Cordoned、Lost 或 Fenced。 |

## Drain 流程

1.  确认替代容量以及 Object/Metadata 服务健康。
2.  Cordon Node，观察不再产生新 Allocation。
3.  执行 Drain；Suspended 与 Warm Cat 在跨 Host 前必须转为 Cold。
4.  确认 Allocation、Dirty/Pending Commit、Route Binding 与本地 Snapshot 归零。
5.  完成身份与本地 Cache 清理后，才能删除或替换 Node。

## Node 丢失

心跳超时会把 Node 标为 Lost、Cat 标为 Unknown，但特意保留 placement、Route 和磁盘 epoch，也不会启动重复 Guest。心跳恢复后，相同 generation 的 runtime inventory 会原地恢复原 claim。

如果 Host 永久丢失，先取得它已停机或隔离的独立证据（例如云 API、BMC 或网络 fencing），再执行显式 `fence`。Cats 会持久化终态 Fenced、撤销旧磁盘 Owner，并用更高 Attachment Epoch 对 Cats 执行 Cold Recovery。迟到的心跳不能让 Fenced Node 身份恢复调度；完成 Host 身份和本地 Cache 清理后才能删除该记录。限制 Boot、对象 GET 与数据库压力，避免恢复风暴。

## Metrics 与审计

`/metrics` 需要管理员权限。关联 Request ID → Operation → Cat → Node → Attachment → Route Epoch。审计 Node 操作和授权决策，但绝不能记录 Token、Cookie、DSN、Secret、终端明文或 Guest 磁盘数据。

## 管理员 HTTP API

    GET    /v1/admin/monitoring
    GET    /v1/admin/nodes
    GET    /v1/admin/nodes/{id}
    DELETE /v1/admin/nodes/{id}
    POST   /v1/admin/nodes/{id}/actions/{verb}
    GET    /metrics

支持的 Node Action Verb 是 `cordon`、`uncordon`、`drain` 与 `fence`；`fence` 必须携带 `{"confirm_host_stopped_or_isolated":true}`，且只接受 Lost/Fenced Node。取消 Drain 使用 `uncordon`。所有路由都要求 Fleet Administrator 身份；Node Register/Heartbeat、Route Resolve 与 Internal Work Endpoint 仍是仅供 Service 使用的 API。

## 当前源码的生产限制

仓库仍缺少 tap/overlay Guest 网络、Workspace Resource Store 的 PostgreSQL 实现与权限隔离。原生 vhost-user-blk（ADR-0015）与 Suspended page-out（在每 Cat 的 file-backed 内存区上使用 `process_madvise(MADV_PAGEOUT)`）都已落地；内核 NBD 仍是默认块路径，原因是实测的写吞吐权衡，而非缺少验证。Cloud Hypervisor 路径已经通过已记录的裸金属验收，但在这些剩余项完成前，不能称整个技术栈已经 Production Ready。
