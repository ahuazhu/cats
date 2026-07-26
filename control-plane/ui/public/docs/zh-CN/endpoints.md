## 默认 URL

    cats create dev
    cats endpoint ls dev
    curl https://dev-<cat-suffix>.cats.run/

每个 Cat 都会自动获得名为 `web` 的稳定 HTTPS Endpoint，转发到 Guest 的 `8080` 端口并采用 `wake_on_request`；不需要再执行 `cats expose`。URL 绑定 Cat 资源而不是某一台 Host，`cats create` 和 `cats get` 也会直接显示它。

应用必须监听 `0.0.0.0:8080`（或 `:::8080`）。只绑定 Guest loopback 的服务无法经 tap 网络访问。

## 额外端口

    # 把默认 URL 改为转发 3000 端口
    cats expose dev 3000

    # 或增加第二个 URL
    cats expose dev 3000 --name preview --protocol http
    cats endpoint ls dev

不带 `--name` 时，`cats expose` 会重新配置默认 `web` Endpoint；指定其他名称则增加第二个 URL。V1 Endpoint 可从公网访问；不要在其中暴露未鉴权的管理或凭据接口。

## 唤醒策略

    cats expose dev 3000 --name internal-preview --no-wake

- **wake on request：**网关会对同一休眠 Cat 的并发激活请求做 singleflight，等待 readiness，再路由到新的 activation epoch。
- **no wake：**请求不会启动 Cat，适合只应在显式 Running 时服务的工作负载。

激活期间客户端应能处理带重试提示的 `503`，并在生命周期或 Host 变化后重新连接。稳定域名不代表长连接永不变化。

## 协议与路由安全

当前实现支持 HTTP/1.1，并由区域 Edge 终止 HTTPS；method、path/query、应用 headers、响应状态和请求/响应 body 都会保留。Owning Node 会重新校验 Cat ownership 与 Running 状态；旧 Route Cache 必须 fail closed，不能到达另一个 Guest。WebSocket 属于后续里程碑。

## 现在支持到哪

HTTP 入站已经可用：Endpoint 地址、路由绑定和按请求唤醒都能正常工作。

尚未提供：**WebSocket 入站**，以及**跨 Node 的 Guest 私网互通**。

## 准备 Guest 服务

1.  默认 URL 监听 `0.0.0.0:8080`；额外 Endpoint 则监听所选目标端口。
2.  只有依赖和磁盘状态可用后才报告 Ready。
3.  不要期待 Cats 在休眠后保留应用 TCP 状态。
4.  如后台任务必须保持 Running，请获取 [工作租约](/zh-CN/docs/runtime-api/)。

## 排查 Endpoint

    cats get dev
    cats endpoint ls dev
    cats operation ls
    cats exec dev -- sh -lc 'ss -lnt'

确认 Cat 健康、Endpoint 指向预期端口、最新 Activation Operation 成功，并且 Guest 服务确实在监听。管理员还应检查 Route Epoch mismatch 以及 Gateway/Node 连通性指标。
