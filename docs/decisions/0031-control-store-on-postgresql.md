# ADR-0031：Managed PostgreSQL 是控制面存储

- 状态：Accepted
- 日期：2026-08-05
- 关联：ADR-0003、ADR-0029、ADR-0032、ADR-0034、ADR-0040

## 决策

Accounts、Workspaces、billing ledger、Cats、Disks、bindings、Nodes、Operations、Routes和
work leases统一保存在managed PostgreSQL。控制表与ChunkStore MetadataStore共享实例和
database，但使用互不冲突的schema/table namespace。

连接配置为：

- `--control-store-url` / `CATS_CONTROL_POSTGRES_URL`，缺省回退到`CATS_POSTGRES_URL`；
- 生产通过`--control-store-url-file`读取runtime Secret，每次新连接重读文件以接受密码轮换；
- CA由`CATS_CONTROL_POSTGRES_CA_FILE`提供；密码authority遵循ADR-0029；
- 连接总量、RDS Proxy和多副本边界遵循ADR-0034。

## Schema与并发

`control_schema_version`记录schema版本。`Store::connect`只在
`[OLDEST_MIGRATABLE_SCHEMA_VERSION, SCHEMA_VERSION]`内按顺序迁移，范围外拒绝启动并报告
版本。DDL在transaction内取得per-schema advisory lock，避免并发副本重复迁移。

当前`postgres`客户端是同步接口。所有调用经统一的`off_runtime`边界执行，避免在Tokio worker
中创建或drop客户端内部runtime。多副本写入的唯一性、placement和singleton工作使用数据库
约束、事务与有界advisory leadership；生命周期网络I/O不持有数据库事务或leader lease。

## 测试与运维

workspace测试必须连接真实PostgreSQL并使用独立schema。CI提供service container；
`quality.sh`启动一次性Docker PostgreSQL；显式`CATS_TEST_POSTGRES_URL`可复用外部实例。没有
可用PostgreSQL时测试失败，不跳过。

生产备份、恢复、Multi-AZ failover和连接代理由managed PostgreSQL承担。控制面副本从数据库
恢复desired work；Node restart/adoption由ADR-0040处理。上线验收必须覆盖双Controller
takeover和真实RDS failover，不能用单元测试替代。

## 后果

- PostgreSQL是控制面唯一持久authority，API/Controller副本无本地业务数据库；
- 数据库暂时不可用时，已Running的数据面继续，但新mutation和需要MetadataStore的durability
  操作有界失败或阻塞；
- 本地开发与完整测试需要Docker或外部PostgreSQL；
- backend或schema兼容范围变化必须通过新ADR、显式迁移链和生产副本演练。
