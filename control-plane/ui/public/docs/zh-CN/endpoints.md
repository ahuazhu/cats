## 发布 Guest 端口

    cats expose dev 3000 --name web --protocol http
    cats endpoint ls dev

命令会创建一个拥有稳定域名、目标 Guest 端口与默认 `wake_on_request` 策略的 Endpoint。域名绑定 Cat 资源，而不是某一台 Host。

## 唤醒策略

    cats expose dev 3000 --name internal-preview --no-wake

- **wake on request：**网关会对同一休眠 Cat 的并发激活请求做 singleflight，等待 readiness，再路由到新的 activation epoch。
- **no wake：**请求不会启动 Cat，适合只应在显式 Running 时服务的工作负载。

激活期间客户端应能处理带重试提示的 `503`，并在生命周期或 Host 变化后重新连接。稳定域名不代表长连接永不变化。

## 协议与路由安全

V1 产品模型通过区域 Edge 支持 HTTP、HTTPS、WebSocket 与安全 WebSocket。Node Gateway 会重新校验 Project、Cat、目标端口与 Route Epoch；旧 Route Cache 必须 fail closed，不能到达另一个 Guest。

## 当前源码可用性

**Cloud Hypervisor 网络尚未完整**

Endpoint API、Route Epoch、唤醒流程与 FakeVmm 网关路径已经实现并测试。仓库尚未实现 Cloud Hypervisor Phase-A 的 tap/overlay Guest 网络。在该里程碑完成前，不能把真实 CH 公网 Endpoint 当作可用能力。

## 准备 Guest 服务

1.  监听目标 Guest 端口，不依赖平台保留端口。
2.  只有依赖和磁盘状态可用后才报告 Ready。
3.  不要期待 Cats 在休眠后保留应用 TCP 状态。
4.  如后台任务必须保持 Running，请获取 [工作租约](/zh-CN/docs/runtime-api/)。

## 排查 Endpoint

    cats get dev
    cats endpoint ls dev
    cats operation ls
    cats exec dev -- sh -lc 'ss -lnt'

确认 Cat 健康、Endpoint 指向预期端口、最新 Activation Operation 成功，并且 Guest 服务确实在监听。管理员还应检查 Route Epoch mismatch 以及 Gateway/Node 连通性指标。
