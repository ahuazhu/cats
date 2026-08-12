# ADR-0019：Cat绝对到期时间

- 状态：Accepted
- 日期：2026-07-28
- Lifecycle authority：[ADR-0040](0040-level-triggered-runtime-reconciliation.md)

## 决策

Cat可配置绝对到期时间`expires_at_unix`（Unix秒）；缺省为永不过期。资源API提供读取、设置新
绝对时间和清除操作。使用绝对时间使重试只重复写同一个值，不引入服务端TTL重置语义。

设置或续期只更新到期属性，不立即创建lifecycle Operation。到期reaper发现
`expires_at_unix <= now`后，在一个PostgreSQL事务中提交目标`Deleted`的新desired revision和
kind=`cat.expire`的Operation。该mutation使用稳定idempotency identity；多个Controller副本
重复扫描只得到一次有效删除意图。

删除按普通Cat Destroy合同收敛：先关闭route admission，处理Guest/VMM/blockd和卷屏障，
RootDisk随Cat删除，PersistentDisk保持独立。到期时间本身不授予绕过drain、fencing或
quarantine的权限。

## 失败语义

- PostgreSQL或Controller暂时不可用只延迟reaper；恢复后周期扫描继续，不依赖内存timer。
- reaper与用户续期并发时以事务锁定后读取的当前值决定；已成功续期的Cat不能被旧扫描结果
  删除。
- 已提交的expire revision遵循普通Operation supersession；后续允许的用户mutation必须通过
  同一资源状态机，不能直接撤销正在发生的物理清理。
- `cats ls/get`持续显示到期时间，长期保留的Cat应清除该值。

## 验收

- 多Controller并发扫描、重复tick和进程重启只提交一个expire revision；
- 到期与续期、手工Delete、Suspend/Warm/Cold并发具有确定性结果；
- RootDisk/PersistentDisk、`R < L`和route guard合同与手工Destroy完全一致；
- 数据库故障恢复后遗漏的到期项被重新发现；
- 时间边界、负值/溢出、时钟回拨和远未来值有确定性测试。
