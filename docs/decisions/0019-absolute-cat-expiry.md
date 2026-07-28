# ADR-0019：Cat 的绝对到期时间（自动删除）

- 状态：Accepted
- 日期：2026-07-28

## 背景

临时环境（CI 预览、演示、一次性实验）需要一个"到点自动回收"的边界。现有的
work-driven auto-suspend 和 auto-tier（ADR-0002）只做降级：Running → Suspended →
Warm → Cold，从不删除。没有任何机制会自动把一个 Cat 转到 Deleted，于是每个
CI 预览环境都要靠外部 sweeper 记账并调用 DELETE，而外部 sweeper 正是这类
编排系统里最容易静默失效的部分（凭据过期、cron 停摆、状态丢失）。

## 决定

给 Cat 增加一个可选的**绝对到期时间** `expires_at_unix`（unix 秒）：

- `CreateCatRequest.expires_at_unix?: i64` — 创建时设定；缺省为永不过期。
- `GET/PUT /v1/workspaces/{ws}/cats/{cat}/expiry` — 读取、续期（新的绝对时间）
  或清除（`expires_at_unix: null`）。workspace token 可以调用，CI 能自己续期。
- 控制面 reconcile tick 里的 reaper：`expires_at_unix <= now` 且尚未在删除中的
  Cat，走与 API delete 完全相同的收敛路径（`desired_state = Deleted`，操作
  kind 为 `cat.expire`）。RootDisk 随 Cat 删除，PersistentDisk 存续，与
  ADR-0002 的删除语义一致。

语义选绝对时间而不是 TTL 时长：续期就是"写一个新的绝对时间"，没有服务端
时钟重置语义，重放、重试、幂等都不需要额外规则。

到期只是未来的记账，不是生命周期变更，所以 `PUT /expiry` 不 bump
generation，也不生成 Operation；真正的删除到点时由 reaper 以自己的
Operation 记录。

## Schema 迁移立场的修正

ADR 之前的立场是"schema 不迁移，重建数据库"（没有已发布部署的状态需要存活）。
生产环境现在携带必须存活的控制面状态（workspace、token），这个前提不再成立。
本 ADR 起：`SCHEMA_VERSION` 配对一个 `OLDEST_MIGRATABLE_SCHEMA_VERSION`，
`Store::open` 对区间内的旧库原地升级（v1 → v2 为 `ALTER TABLE cats ADD COLUMN
expires_at_unix INTEGER`），部署自动化用同样的区间判断放行。梯子只保留活跃
部署仍需要的那几级，低于区间照旧拒绝。

## 后果

- CI 预览等临时环境的回收内建于控制面，不再依赖外部 sweeper 的持续正确性。
- 一个被遗忘的 `expires_at_unix` 会删掉还在用的 Cat；续期是使用方的责任，
  这与"临时环境"的定位一致。要长期保留就清除到期时间。
- reaper 每 tick 扫一次到期集合（带索引条件的单条 SELECT），代价可忽略。
