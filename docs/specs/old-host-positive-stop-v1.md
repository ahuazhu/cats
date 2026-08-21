# Old Host Positive Stop Evidence v1

- Status: **Proposed**（未接受、未接入 production reset authority）
- 范围：首次 clean-slate cutover 中旧 writer 的正向停止或工作负载网络隔离证据
- 工具：[`deploy/aws/old-host-positive-stop.py`](../../deploy/aws/old-host-positive-stop.py)
- 上位合同：[Operations and HA §8](../operations-ha.md#8-首次终态部署)

本文冻结一个可审查、可解析的 E13 候选格式和离线验证程序，但不改变任何 accepted ADR。
特别地，本格式：

- 不是 ADR-0040 的 `HostFenceEvent`；
- 不授予 placement、volume takeover、delete 或 writer epoch；
- EC2 Security Group 观察不证明旧 Host principal 已失去 BlobStore `PUT` 权限，也不证明
  cutoff 前已接受的写已经成功可见或永久失败；
- 不替代 E9 final usage barrier 或跨组件 Closed admission proof；
- **不能解除** `production-clean-slate-reset.py apply --execute` 的机械 Blocked。

只有后续新 ADR/accepted spec 明确批准 authority、parser、freshness 和消费事务后，reset 工具才能
读取本格式。仓库离线 fixture 只验证程序合同，不是生产停止证据。

## 1. 目标与边界

维护 actor 先显式列出全部旧 Host 及其上全部旧 writer component。V1 component 闭集是按字典序排列的：

```text
blockd, controller, gateway, node_agent, vmm
```

inventory 必须覆盖这五类，且每个 Host/component pair 都必须由一份 Host receipt 精确覆盖；缺 Host、
缺 component、重复 Host receipt 或额外 Host 都不能生成 evidence set。一个 component 可以有多个副本，
因此可以出现在多个 Host 上；每个声明的 pair 都必须出现。

V1 只有两种 Host method：

1. `local_systemd`：在精确 machine/boot 上对显式 loaded unit 执行
   `systemctl --system --no-ask-password stop`；
2. `ec2_security_group_isolation`：从外部 maintenance actor 把指定 EC2 instance 的**全部** ENI替换为
   同 VPC、同 account、入站/出站规则都为空的一个 Security Group。

程序不使用 SSH、shell、`pkill -f`、`kill`/signal、`systemctl kill`、EC2 instance stop/terminate、
ENI detach 或规则就地修改。local 路径永远不单独停止 VMM/blockd：任何已安装 runtime binary 仍存活都在
写 stop intent 前拒绝。这样 `R < L` 的 blockd/pending lineage 不会被 E13 当作 cache 杀掉。

## 2. Canonical inventory

inventory 是 UTF-8、以单个换行结束的 canonical JSON：object key 按字典序，分隔符为 `,`/`:`，ASCII
escape 固定；duplicate key、unknown/missing field、非 canonical bytes 全部拒绝。最大 1 MiB，必须位于
actor-owned mode 0700目录且自身为actor-owned mode 0600 single-link regular file。

```text
OldHostInventoryV1 {
  kind: "cats.old-host-positive-stop-inventory.v1",
  version: 1,
  attempt_id: Id,
  required_components: ["blockd", "controller", "gateway", "node_agent", "vmm"],
  hosts: [HostExpectation]       // 1..=256，按host_id排序且不重复
}
```

`Id` 为 1..=64 byte 的小写 ASCII `[a-z0-9][a-z0-9-]*`。同一 inventory 不允许两个 logical Host
复用同一个 machine-id digest + boot ID、同一个 account/region/instance，或同一个
account/region/ENI。

### 2.1 Local systemd Host

```text
LocalHostExpectation {
  host_id: Id,
  method: "local_systemd",
  expected_machine_id_sha256: "sha256:" + 64 lowercase hex,
  expected_boot_id: lowercase UUID,
  idle_preflight: {
    cgroup_v2_root: canonical absolute cgroup2 mount root,
    helper_path: canonical absolute require-idle-worker path,
    runtime_bin_root: canonical absolute path
  },
  components: [LocalComponentExpectation] // 按component排序且不重复
}

LocalComponentExpectation =
  {
    component: "gateway" | "controller" | "node_agent",
    proof: "systemd_stop",
    units: [explicit .service names],      // 排序、去重、1..=64
    executable_paths: [canonical absolute paths]
  }
| {
    component: "blockd",
    proof: "process_absence",
    executable_paths: [runtime_bin_root + "/cats-blockd"]
  }
| {
    component: "vmm",
    proof: "process_absence",
    executable_paths: sorted [
      runtime_bin_root + "/cats-vmm-launcher",
      runtime_bin_root + "/cloud-hypervisor"
    ]
  }
```

`cgroup_v2_root` 是 exact cgroup2 mount point，不是任意 delegation subtree。local mutation 前
`require-idle-worker` 必须重新解析所有 path component、拒绝 symlink/non-canonical path，并用
mount table 证明该 exact path 是 `cgroup2` mount root；无法读取或不一致都 fail closed。它只在该
root 的直接子项中枚举 canonical `cats-cat-<64 lowercase hex>.slice`。probe 必须先观察
`cgroup.controllers` 和已知 positive namespace matcher；已知 canonical Cat slice 必须拒绝，只有
同一校准 probe 证明 slice 集为空且 managed runtime process 也为空时才能通过。

每个 local Host 至少有一个 `systemd_stop` unit。VMM/blockd 只能使用 exact absence，不能声明为可由本
程序 stop 的 unit。无论 inventory 是否把 VMM/blockd pair 归到该 Host，local preflight 总是检查上述三个
installed runtime path，防止靠省略 component 绕过数据保护。

### 2.2 EC2 isolation Host

```text
Ec2HostExpectation {
  host_id: Id,
  method: "ec2_security_group_isolation",
  components: [Component],       // 排序、去重、非空
  aws: {
    account_id: exactly 12 digits,
    region: canonical AWS region,
    instance_id: exact EC2 instance ID,
    vpc_id: exact VPC ID,
    deny_all_security_group_id: exact SG ID,
    expected_eni_ids: [exact ENI IDs] // 1..=32，排序、去重
  }
}
```

`expected_eni_ids` 是完整集合，不是 allowlist。instance 嵌入的 ENI 集合与独立
`DescribeNetworkInterfaces`任一缺失/额外/不一致都在首个 mutation 前拒绝。

## 3. Local positive stop

`local-stop` 只能以 root 在 inventory 指定的 exact machine/boot 执行。顺序固定：

1. 调用 inventory 中的 `require-idle-worker`，非零或无有界结果立即拒绝；
2. 枚举 `/proc`。probe 必须先找到执行器自身这个已知正样本；否则空结果没有证明力；
3. 每个进程使用 `/proc/<pid>/stat` 的 PID、PPID和field 22 start ticks；读取exe/argv0前后再次读
   stat，identity变化则整次拒绝；只保留argv0，不保留可能含secret的完整argv/env；Linux为仍运行但
   已unlink的binary返回的` (deleted)`后缀只在exact path匹配时移除，不能借release替换隐藏旧runtime；
4. 确认三个 protected runtime executable均不存在；
5. 对每个显式 unit读取 `LoadState/ActiveState/SubState/MainPID/ControlPID/Result/UnitFileState`。
   `LoadState=not-found`、masked/错误load均拒绝，不能把“没有这个unit”解释成stopped；
6. 从非零MainPID/ControlPID递归枚举全部descendant，并在intent中保存每个PID/start-tick identity。
   active unit的期望executable必须存在于它的树中；同executable出现在树外时拒绝；
7. 再运行同一个idle helper并重做process/unit/tree scan。两次事实必须稳定，且runtime仍为空；
8. 以no-replace方式发布/fsync intent及digest sidecar；
9. 只对排序后的显式unit逐一执行`systemctl --system --no-ask-password stop <unit>`。命令失败、timeout或响应丢失都不表示失败或成功；
   立即重读精确unit postcondition；
10. 所有unit必须为`loaded + (inactive|failed) + MainPID=0 + ControlPID=0`。`failed`是明确记录的
    systemd stopped状态，不被悄悄改写成success；
11. 重扫process：全部期望executable必须为空，intent记录的每个PID/start ticks必须消失。相同PID以不同
    start ticks复用不是旧进程仍活；相同PID+start ticks仍在则拒绝；
12. 等待有界stable interval后完整重读一次。两次安全projection逐字段相同才写Host receipt。

如果intent已存在而final receipt缺失，replay只做postcondition discovery。完整stopped可以结算receipt；
任一unit/process仍活时，同一attempt拒绝再次stop，避免对结果不明的effect盲重放。操作员只能保留该失败
evidence并以新的reviewed attempt重新开始。

## 4. EC2 deny-all isolation

每次 discovery 都通过无shell AWS CLI并带固定`--region`，共享一个最长300秒的absolute deadline。首个
mutation前必须逐字段证明：

1. STS caller account等于inventory；
2. 显式region存在且enabled；
3. `DescribeSecurityGroups`只返回指定group，其owner/VPC精确匹配，`IpPermissions=[]`且
   `IpPermissionsEgress=[]`；
4. `DescribeInstances`只返回指定instance，reservation owner、instance/VPC和非terminal state匹配；
5. instance内嵌ENI集合恰好等于`expected_eni_ids`；
6. 独立`DescribeNetworkInterfaces`返回同一完整集合，且每个ENI的owner、VPC、attachment instance、
   device index、groups和status与instance projection相同；device index不重复。

随后对每个ENI按ID排序执行exact：

```text
ModifyNetworkInterfaceAttribute(eni_id, groups=[deny_all_security_group_id])
```

已经恰好只有deny-all group的ENI不重复mutation。其余ENI每个最多发出一次modify；无论返回success、error、
timeout或无法解析的response，都只通过fresh discovery判断结果，在deadline内等待该ENI恰好为deny-all。
postcondition未出现时拒绝，绝不盲目发第二次modify。全部ENI完成后，对account/region/instance/VPC/SG规则/
完整ENI projection做两次稳定重读；任一字段变化、extra ENI或规则非空都拒绝。

intent存在、receipt缺失的replay也只发现：全部ENI已精确isolated才能结算，否则不重放结果不明的modify。
这条保守规则允许一次响应丢失在live postcondition存在时恢复，同时不会把日志或AWS CLI exit code升级为authority。

### 4.1 明确不是fence

deny-all SG只证明该时刻这些显式ENI没有SG允许的普通workload流量。它不证明：

- instance没有其他provider网络面；
- instance principal/IAM credential失效；
- S3/BlobStore新PUT被cutoff；
- 已接受PUT已经成功可见或永久失败；
- BMC/power/state storage永久销毁；
- 旧volume epoch被CAS fence。

因此receipt的固定limitations必须为：

```json
{
  "coordination_authority": "none",
  "host_fence_event": "not_established",
  "object_write_fence": "not_established",
  "production_reset_prerequisite": "proposed_unaccepted"
}
```

## 5. Intent、Host receipt和evidence set

三类文件都使用§2的canonical bytes、单个末尾换行和最大1 MiB。JSON是唯一receipt authority；同basename的
`.sha256`是`<64hex><two spaces><json filename>\n`。发布使用同目录mode 0600临时文件、file fsync、hard-link
no-replace和directory fsync：

- JSON存在且sidecar缺失：重读canonical JSON后只补sidecar；
- sidecar存在但JSON缺失：拒绝；
- sidecar digest/filename漂移：拒绝；
- 同路径不同JSON：拒绝且不覆盖；
- exact final receipt replay：先验证receipt/intent/digest，再做read-only live postcondition discovery，
  不重复stop/modify。

已存在的JSON/sidecar必须都是actor-owned、mode 0600、single-link regular file；metadata漂移与内容漂移同样
fail closed。`created_at`/`observed_at`固定为合法的UTC整秒`YYYY-MM-DDTHH:MM:SSZ`。

Host receipt固定使用`cats.old-host-positive-stop-host-receipt.v1`，绑定attempt、inventory SHA-256、Host、
method、exact covered components、intent filename/digest、effect response class、两次稳定postcondition、
observed time和上述limitations。response class只作诊断；物理postcondition才决定receipt是否可写。

`verify`读取原canonical inventory和**恰好每个expected Host一份**Host receipt；全部Host receipt、intent和
输出evidence set必须位于同一个private目录。程序逐份验证intent链、digest、
method与component集合，生成：

```text
OldHostPositiveStopEvidenceSetV1 {
  kind: "cats.old-host-positive-stop-evidence-set.v1",
  version: 1,
  attempt_id,
  inventory_sha256,
  required_components: [closed five-component list],
  coverage: sorted [{host_id, component}],
  host_receipts: sorted [{host_id, method, outcome, covered_components, file, sha256}],
  observed_at,
  limitations: fixed Proposed limitations
}
```

少一份Host receipt、重复同一Host、extra Host、少一个component、method/intent/inventory digest漂移都拒绝。
evidence set只是一份完整性索引，不能把其输入升级为accepted stop/fence authority。

## 6. CLI与保留

操作入口见[部署说明](../../deploy/aws/old-host-positive-stop.md)。两个mutation子命令都要求：

- canonical absolute inventory path；
- explicit `--host-id`；
- absolute、actor-owned mode-0700 evidence directory中的`.json` output；
- `--execute`；
- 与inventory逐字节相同的`--confirm-attempt-id`；
- hard deadline和stable-read interval。

正式执行前必须单独review inventory canonical bytes和SHA-256。Host receipts、intent、sidecars、aggregate、
命令退出状态与operator session manifest一并进入现有append-only evidence boundary；不得收集secret、完整argv、
environment、AWS stderr或用户payload。
manual worker release verifier把producer本身作为mode 0755 bundle member并单独绑定其build-input digest；这只绑定
执行bytes，不批准本格式的authority。

## 7. 离线验收

`old-host-positive-stop-fixture.py`只使用fake local/AWS runners，必须覆盖：

- 已知self process正样本后，live blockd/VMM negative拒绝且零stop；
- unit descendants完整记录、后读PID复用不误判、同identity survivor拒绝；
- expected unit absent拒绝，loaded failed unit被显式stop并按failed stopped状态记录；
- stop/modify响应丢失后只以postcondition结算，exact replay零mutation；
- AWS wrong account、region/VPC、nonempty SG rules、missing/extra ENI全部在首个modify前拒绝；
- 两个以上ENI全部修改，ambiguous success由discovery确认，deadline/stable reread失败关闭；
- canonical JSON/sidecar no-replace drift与sidecar-only拒绝；
- exact Host/component coverage的missing/duplicate/omitted pair拒绝。

该fixture通过只证明deterministic program behavior；真正production result必须来自reviewed inventory、真实
systemd/EC2 authority与保留的原始receipt，且在本规格仍为Proposed时也不能被reset消费。
