# ADR-0043：Provisioner-owned Runtime Placement Policy

- 状态：Accepted
- 日期：2026-08-09
- 规格：[Runtime Placement Policy v1](../specs/runtime-placement-policy-v1.md)
- 协调authority：[ADR-0040](0040-level-triggered-runtime-reconciliation.md)
- 多副本serialization：[ADR-0032](0032-control-plane-multi-replica-and-postgresql-leadership.md)

## 背景

ADR-0040已经冻结完整Desired/placement，A20冻结fresh AgentSession和full inventory，Volume Authority冻结
Cat-create事务。但production planner仍缺少一份可审计的静态事实：Node是否允许接新Cat、可分配多少CPU/
内存、安装了哪种block/network/Guest runtime，以及Guest private address来自哪里。

当前legacy `nodes` row、heartbeat capacity和Node本地`--ch-network-cidr`/FNV推导都不能承担这个角色：它们由
Node自报或本地配置，无法阻止Node给自己扩容/uncordon，多Control replica也无法在同一NodeIdentity锁下重验
容量与地址。只增加一个`schedulable`或`capacity_ok` boolean会继续留下第二authority和超卖窗口。

## 决策

1. provisioner通过版本化、CAS的`NodePlacementPolicy`唯一声明Node调度状态、allocatable vCPU/bytes、closed
   production capabilities和Host-local aligned private `/16`。policy与provisioned NodeIdentity一对一绑定；
   Node credential、heartbeat、observation、legacy row和环境/fixture不能写它。
2. 自动化provisioner使用deployment-scoped Ed25519签名，private key只在central IaC；人类变更另可使用
   ADR-0006 admin Organization中current active membership且含exact `cats:fleet:admin` permission的WorkOS身份；
   每次apply都online验证，不信任sealed stale session。两者进入同一个typed principal和apply
   transaction；static bearer、Workspace token及A19 Node proof拒绝。provisioner trust使用单调revision与
   expected previous active-set CAS；ID/SPKI在Control Store保留all-history active/retired tombstone，跨release
   不可重用，单个replica的bundle缺项不能隐式retire全局key。machine apply commit还会锁住并重验exact active
   trust row，关闭认证后并发retire窗口。
3. NodeIdentity初始provision与revision-1 cordoned policy同一transaction。policy update用expected revision；
   capacity/capability/CIDR只在cordoned且current assigned set为空时改变。credential rotation和retire复用A19a
   lineage并与policy/Create在NodeIdentity row串行。V1 Node provision/rotation只接受public key，
   credential ID和SPKI分别全历史唯一，rotation/retire后也不可重用或reverse CAS。
4. Cat-create planner在一个`REPEATABLE READ READ ONLY` snapshot中按`node_id` keyset page 64遍历全部
   provisioned identity，读取policy+A20完整facts和Active HostFenceEvent，按stable node ID first-fit。
   source exclusion只由server从current placement派生，Active-fenced Node不能做target。capacity只对全部
   current assigned Desired shape做checked post-mutation sum，每Node post-set最多1024；没有fleet total cap、
   utilization ratio、reservation或heartbeat数字。same-node shape change、migration、takeover和retry共用一个
   exact-current-CAS plan。
5. 每Node private `/16`的slot 0保留，其余16383个`/30`以domain-separated SHA-256取得start并对current
   assigned Desired做deterministic linear probe。slot是唯一collision unit；gateway/guest/MAC由slot单射得到。
   slot释放还要求new full inventory证明旧tap/residue消失。
6. Cat-create commit继续遵守ADR-0032/0042：先锁NodeIdentity，再按AgentSession/observation
   receive-cursor/HostFenceEvent顺序重验policy、A20 facts、post-set、capacity和exact slot，最后进入
   Volume。所有session/observation和任何写old/new assigned current Desired任一字段的mutation使用同一
   NodeIdentity-first DAG；即使placement/shape不变也不能先锁Desired。不增加scheduler table/lease/boolean。
7. Node只消费Desired中的exact NetworkConfig。旧FNV/cat-ID推导和`--ch-network-cidr`在A23上线前删除；mixed
   authority部署保持cordoned。

## 后果

production Cat-create可以在两个Control replica下确定性选择并安全提交，不信任Node自报capacity，也不会让
不同地址算法各自成为authority。cordon/policy update与create由同一NodeIdentity row明确线性化；response-loss
由apply ID或product idempotency重放。

这是有意保守的V1：地址是每Node Host-local isolated realm，不提供跨Node overlay或负载均衡策略；Cold也按
完整shape占capacity。以后若增加overcommit、跨Node network domain、NUMA/GPU/故障域或balancing policy，必须
用新ADR和closed schema升级，不能把telemetry或新的boolean塞进本合同。
