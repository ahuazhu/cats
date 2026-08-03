# ADR-0026：OCI Deploy 由部署记录拥有，而不是由 HTTP 请求拥有

- 状态：Accepted
- 日期：2026-08-03

## 背景

`POST /v1/workspaces/{workspace}/cats/{cat}/oci-deployments`（ADR-0024）此前是纯
同步的：控制面一直等到 Guest 完成 Registry 拉取、layer 合并和 systemd 激活，才回复
调用方。控制面自己给这条链留的耐心是一小时（node-agent 传输超时 `ttl_ms +
15s`，`ttl_ms = 3_600_000`；CLI 3615 秒）。

生产环境里 Cats 站在一个 EKS Auto Mode ALB 后面，而 ALB 的 `idle_timeout.
timeout_seconds` 是 AWS 出厂默认的 60 秒，模块从未覆盖它。后端 60 秒不回话，ALB 就
掐断连接并返回 **HTTP 504**。两边差了 60 倍。

Paperboy 2026-08-03 的一次 staging 部署留下了完整证据
（`paperboytm/paperboy` Actions run 30797523439，job 91636047560）：

| app | 发起 | 结果 | 耗时 |
| --- | --- | --- | --- |
| postgres | 08:38:36.3 | 200 | 23.2 s |
| platform | 08:39:31.6 | **504** | **60.0 s** |
| platform（重试） | | 200 | +17.5 s |
| im-server | 08:41:49.2 | **504** | **60.04 s** |
| im-server（重试） | | 200 | +23.9 s |
| santi-bundle | 08:43:51.0 | 200 | 15.2 s |

60.0 s 与 60.04 s 的整齐程度只能来自基础设施的固定闸门。而重试之所以能在 17–24 秒内
完成，是因为第一次其实**已经成功了**：`guest/src/oci.rs` 的 `if !release.exists()`
让重试跳过了 layer 下载和合并。

请求被取消并不能停下这件事。node-agent 用 `tokio::task::spawn_blocking` 执行部署，
而 `spawn_blocking` 不可取消：连接关闭后闭包继续在 blocking 线程池上跑完，握着到
Guest Agent 的 vsock 连接，直到写回响应时才失败。

由此产生两处真实损害：

1. **重复激活。** 重试跳过了拉取，但仍然重新渲染 unit、重指 `current` symlink 并
   `systemctl restart`。Platform 和 IM Server 每次超时部署都被额外重启一次。若重试
   落在第一次仍在合并 layer 的窗口内，它会阻塞在 Guest 的 `Mutex<OciDeployer>` 上，
   自己也超过 60 秒，再收一个 504。
2. **work lease 泄漏。** handler 把 `release_work` 写在 await 之后，请求取消后永不
   执行，于是每次超时泄漏一个 TTL 一小时的 `Control` lease，把 Cat 钉在非
   auto-suspend 状态。重试用新的 owner UUID，`acquire_work` 的冲突键是
   `(cat_id, kind, owner_id)`，因此插入新行而非报冲突——这既解释了重试为何没被挡住，
   也说明当时没有任何去重。

`api/src/requests.rs` 早就写下了本仓库的约定：“every mutation accepts
`Idempotency-Key`；long mutations return `202 Accepted` with an `Operation`”。
`operations` 表、`idempotency` 表、`GET /v1/operations/{id}` 都已存在并被
`create_cat` 与 `cat_action` 使用。OCI deploy 和 `exec` 是两个例外。

## 决定

1. **部署的所有者是记录，不是请求。** 新表 `oci_deployments` 以
   `UNIQUE (cat_id, app, image_digest)` 作为部署身份。`claim_oci_deployment` 在一个
   事务里把请求解析成三种结果：`Claimed`（本调用方负责驱动）、`AlreadyRunning`
   （已有同身份在飞，等待而不新起一次）、`Replay`（已成功，直接返回同一结果且
   完全不接触 Guest）。幂等由约束保证，而不是由 handler 代码保证。
2. **一个 app 只有一份"当前部署"，由约束保证。** 一个 Cat 对每个 app 只有一个
   `current` symlink 和一个 systemd unit，所以 `succeeded` 记录对每个 `(cat, app)`
   最多一条，由部分唯一索引 `oci_deployments_one_current_per_app` 强制。新 digest
   激活时，同一 app 之前的 `succeeded` 记录在同一事务里转为 `superseded`。
   `superseded` 与 `failed` 走同一分支：重新驱动，而不是 replay。这是回滚到旧
   digest 能真正生效的原因——否则 Cats 会拿一条已经不生效的记录回答成功，而 Guest
   仍在跑新镜像。同时读取"当前部署了什么"不需要任何排序或去重技巧。
3. **驱动任务与请求解耦。** 被 claim 的部署交给 `tokio::spawn` 的游离任务驱动，
   work lease 由该任务持有并在其结束时经 `Drop` 释放。调用方消失既不取消工作，也不
   丢失结果。
4. **回复形状是双档的。** 部署在配置的同步等待窗口内完成则返回 `200` 与裸
   `OciDeployment`（与 ADR-0024 逐字节一致）；超出窗口则返回 `202` 与
   `OciDeploymentOperationResponse`。两者都是成功。`?wait_ms=0` 让已适配的调用方
   立刻拿到 `202`。
5. **同步等待窗口是过渡设施，不是正确性边界。** 由 `--oci-deploy-sync-wait-ms`
   （`CATS_OCI_DEPLOY_SYNC_WAIT_MS`，默认 240 000）控制，存在的唯一理由是让按旧
   同步语义写成的调用方继续收到 `200`。随调用方改用轮询而下调。
6. **ALB idle timeout 必须高于同步窗口。** 新增
   `public_ingress_idle_timeout_seconds`（默认 300）并写入 ingress annotation
   `alb.ingress.kubernetes.io/load-balancer-attributes`。Terraform `check` 断言
   `oci_deploy_sync_wait_ms < public_ingress_idle_timeout_seconds * 1000`，否则
   ALB 会先于控制面回答，504 依旧。
7. **新增 `GET .../oci-deployments`** 列出该 Cat 当前的应用，让收到 `202` 的调用方
   可以在轮询到终态后读回结果，而不必把读操作写成一次 POST。
8. **重启后不恢复，而是收敛为失败。** 一次 pull 的 Registry 凭据按 ADR-0024 从不
   落盘，因此进程重启后在飞的部署无法续跑。启动时把仍为 `running` 的记录连同其
   operation 标成 `failed`，附带可操作的错误消息。让身份重新可用，而不是让调用方
   永远轮询一个不会终结的 operation。
9. **`WorkLeaseGuard`。** lease 的释放改为绑定在值的生命周期上而非 await 之后的
   一行代码。`exec` 有同源同因的泄漏，一并改用 guard。

## 后果

- Paperboy 只需把“看到 504 就重试”改成“看到 202 就轮询”。在 Cats 上线到 Paperboy
  适配完成之间的窗口里，240 秒同步窗口覆盖了它当前全部部署耗时（最慢约 100 秒），
  旧客户端继续收到 `200`。
- 同一 cat + app + digest 的重试不再触发第二次拉取、合并或 `systemctl restart`。
- 由 4 起，同步与异步两条回复路径会长期共存。这是刻意付出的代价：换来的是不需要
  协调 Cats 与 Paperboy 的发布顺序。窗口下调到 0 即可完成向纯异步的收敛。
- 由 8 起，`202` 带来一项新义务：控制面许诺过的事不能凭空消失。控制面是 SQLite
  单副本、Recreate 策略（ADR 无编号，见 `docs/` 与运维记录），重启期间有真空窗口，
  因此启动收敛是这项义务的兑现方式，而不是可选的清理。
- Schema 版本 3 → 4。新表与新部分唯一索引都由无条件的 `CREATE ... IF NOT EXISTS`
  建立，v3 数据库打开即完成升级，无需 guarded ALTER。v4 之前的部署记录一律缺失，
  这是正确的：Cat 的应用是 Guest 侧状态，一次新部署会重新建立它。

## 明确未做

- **Guest 侧未改。** 控制面已经拦住了重复与并发的 Guest 调用，因此不改
  `guest/src/oci.rs` 的激活行为。其代价只落在**仍然当前**的那个 digest 上：重复部署
  它走 `Replay`，不重新断言存活——若服务在成功之后自己死掉，同 digest 重部署会返回
  记录里的 `active: true` 而不去救活它。回滚到 `superseded` 的旧 digest 不受此限，
  那是真正的重新部署。要强制重新激活当前 digest，目前只能换 digest；把"重新断言
  存活"做成显式动作是独立决定。
- **`guest/src/lib.rs:303` 的 `Mutex<OciDeployer>` 仍是 `.lock().unwrap()`**，一次
  panic 会毒化它并使该 Cat 的 OCI 部署持续失败到重启。与本次事故无关，另案处理。
- **`exec` 的同步语义未改。** 它同样会撞 ALB（默认 120 秒，裸机脚本用 900 秒），
  这里只由 6 的 ALB 提升缓解；把 `exec` 也改成 operation 形状是独立决定。
