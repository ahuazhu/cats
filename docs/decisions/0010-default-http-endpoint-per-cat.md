# ADR-0010：每个 Cat 默认获得稳定 HTTP Endpoint

- 状态：Accepted
- 日期：2026-07-23

## 背景

用户创建 Cat 后通常首先在其中启动 Web 服务。要求用户先理解 Endpoint 资源、再执行
`cats expose`，会让最常见的访问路径多一个没有必要的配置步骤，也让 Cat 在创建完成后
没有可发现的 URL。

Sprites 的产品行为提供了合适的参考：每个实例有唯一且稳定的 HTTPS URL，默认转发
8080（或发现到的首个 HTTP 端口），请求能够唤醒休眠实例。Cats 已经具备稳定 Endpoint、
route binding 和 `wake_on_request`，但旧实现只在显式创建 Endpoint 后才生成本地
`.cats.local` 名称，而且 Cloud Hypervisor 数据面没有把请求送到 Guest tap 地址。

## 决定

1. 创建 Cat 的数据库事务同时创建名为 `web` 的默认 Endpoint：
   - protocol：`http`
   - target port：`8080`
   - wake policy：`wake_on_request`
2. 默认公网名称是单标签
   `https://<cat-name>-<opaque-cat-suffix>.cats.run`。名称不包含 Workspace 标识，不绑定
   Host，适配现有 `*.cats.run` DNS 和 TLS 证书；Cat 迁移、Suspend、Warm 或 Cold 后 URL
   不变。
3. `cats create` 和 `cats get` 显示默认 URL；`cats endpoint ls` 是结构化发现入口。
   `cats expose <cat> <port>` 可重新配置默认 Endpoint；指定其他 `--name` 可增加不同
   端口或 wake policy 的额外 Endpoint。它不是基本访问的前置步骤。
4. 控制面启动时为历史 Cat 回填默认 Endpoint，并把旧 `.cats.local` Endpoint 原子迁移
   到 `cats.run` 名称，保留 route epoch 和 binding。
5. Gateway 保留 HTTP method、path/query、可转发 headers 和 body。Owning Node 在确认
   Cat 当前为 Running 且由本 Node 持有后，Cloud Hypervisor 模式通过 Cat 的 tap Guest
   IP 连接 Endpoint 目标端口；FakeVmm 继续使用隔离的 Unix 测试 workload。
6. V1 默认 Endpoint 是公网可寻址的 HTTP 服务入口。应用不得在 8080 上暴露不应公开的
   管理接口或凭据；Endpoint 级身份策略和私有发布模式必须作为后续安全能力显式加入，
   不能假装当前已有。

## 安全与失败语义

- Hostname 只用于查路由，客户端请求不能指定 Guest IP、Node 或目标端口。
- Node 必须对 Cat ownership 和 Running 状态 fail closed；旧 Node 在 Cat 迁走后返回
  conflict，Gateway 重新解析一次，不能继续访问旧 Guest。
- Gateway 和 Node 对请求/响应 body 设上限，过滤 hop-by-hop headers，并拒绝 CR/LF
  注入、非法 method、非法 path 和畸形 Guest HTTP response。
- Guest 只看到普通 TCP/HTTP 流量；不会收到 WorkOS、控制面、对象存储或 metadata
  凭据。

## 影响

- 8080 成为默认应用端口。应用必须监听 Guest 的 `0.0.0.0:8080`（或 `:::8080`），仅监听
  `127.0.0.1` 无法从 tap 网络到达。
- 每个 Cat 固定消耗一个 Endpoint 配额和一个 route binding；配额实现必须把默认资源
  计入事务 reservation。
- 当前实现覆盖 HTTP/1.1 与 Edge TLS termination。WebSocket、私有 Endpoint、逐
  Endpoint 身份策略和跨 Node Guest overlay 仍是独立里程碑，不能由本 ADR 推断为已经
  实现。
