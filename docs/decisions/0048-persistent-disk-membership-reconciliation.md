# ADR-0048：PersistentDisk 绑定是 Cold Desired 成员变更

- 状态：Accepted
- 日期：2026-08-14
- 上位决定：[ADR-0040](0040-level-triggered-runtime-reconciliation.md)、
  [ADR-0042](0042-volume-authority-and-disk-lifecycle.md)
- 冻结协议：[Runtime Reconciliation v1](../specs/runtime-reconciliation-v1.md)、
  [Volume Authority](../specs/volume-authority.md)

## 背景

PersistentDisk create、Volume RWO authority、首次 ext4 初始化的 A22 `CommitInitialized` 和 Node
完整设备集合同已经存在，但产品面还没有一条生产绑定入口。退役的 V1 `mount/unmount` 会把一次 HTTP
动作误当成 host mount authority，也没有绑定完整 Desired revision、attachment epoch、filesystem UUID
或模糊提交恢复，因此不能复活。

绑定并不是热插拔。ADR-0042 已决定第一版只在稳定 Cold、全部卷 Unowned 时改变磁盘集合；Node 随后必须
对新的完整 Desired 做一次 Cold→Cold reconcile，才能让该 revision 的 Operation 终态。

## 决定

### 1. 只有两条 clean-slate 产品 mutation

公开入口固定为：

```text
POST /v1/workspaces/{workspace}/disks/{disk}/actions/attach
POST /v1/workspaces/{workspace}/disks/{disk}/actions/detach
Content-Type: application/json
Idempotency-Key: <1..512 printable ASCII>

{"cat_id":"cat_...","mount_path":"/absolute/non-root/path"}
```

`{disk}`只接受 immutable Disk ID；path不接受query、别名、百分号重写或Guest根目录。detach也携同一
closed body，使它必须逐字段比较当前Cat和mount path，而不能删除“某个当前binding”。可选`If-Match`
绑定当前Desired generation。成功沿用完整Desired mutation的exact `202
{"desired_revision":N,"operation_id":"op_..."}`。

`/actions/mount`和`/actions/unmount`不注册，保持404。CLI或集成工具只能发上述新请求，不得把旧route
翻译成直接SQL、Node命令或host mount。

### 2. Control只发布一个完整Cold Desired后继

attach和detach都保持target、placement、runtime、endpoint与transition不变，只把revision加一、重算
spec digest并替换完整有序`VolumeIntent`集合：

- attach追加一个Persistent/RWO/Retain intent，使用fresh `volume_intent_id`、`attachment_id`和normal
  acquire transition；slot是完整集合的下一个slot，serial在该VM内唯一；
- detach删除request精确命中的intent，保留Disk/Volume产品row，并只为剩余设备压紧slot；所有其他逻辑、
  存储和物理identity保持不变；
- 每个successor仍为`target=Cold`。没有hot attach/hot detach，也没有独立Disk Operation。

Control事务先取得现有ApiIdempotency reservation，再按共享顺序锁NodeIdentity、完整current+successor
Volume并集、Cat、Disk并集、current Desired与Operation。Disk/Volume锁是唯一binding序列化屏障；当前
Desired中的Disk membership是唯一binding真相，不新增binding表。attach要求全局无membership，detach
要求current Desired、Disk、Volume、Cat和mount path逐字段一致。

事务重验Disk Active/Persistent、Volume Active/Unowned、无lease expiry、immutable size/durability、RWO、
normal acquire的`expected_unowned_epoch == current lease_epoch`，以及Disk初始化状态与current remote head。
Uninitialized intent只能复制Disk row保存的filesystem UUID、initialization token和exact blank head；
Initialized intent只能复制UUID并使用`Existing`，且current head不得回退或同generation异root。

### 3. 稳定Cold和已结算Operation是输入authority

未锁preflight只用于尽早返回固定409/412。真正commit在current NodeIdentity锁内重新读取current
AgentSession的fresh、完整、assigned-set-bound admission inventory，并复用Operation settlement的同一
数据库postcondition oracle。它必须证明：

- exact current Desired已应用，checkpoint valid且step/stable state均为Cold；
- lifecycle admission Closed、platform guards为零，process/mount/network/Guest transport/warm snapshot和
  完整inventory residue均为空；
- 每个current volume都是exact Cold physical evidence、Unowned且`R == L`；
- current revision的exact Operation已经`Succeeded`。

API不接收`cold=true`、mount proof或operator assertion。session replacement、inventory advance、Desired
竞争、owner/epoch变化或绑定变化都使事务fail closed并从新快照重计划。

### 4. Node复用冻结的完整VolumeIntent协议

本决定不增加Node wire字段、不提高ContractVersion，也不建立第二份Disk命令。Node只消费当前完整
`DesiredRuntimeSpec.volumes`：

```text
PrepareDevice(完整有序设备集)
  -> [Initialize] FormatFilesystem
  -> DrainInitialization
  -> CommitInitialized{filesystem,new_remote_head}
  -> MountFilesystem{filesystem,expected_head}
  -> exact successor stable-Cold observation
```

`PrepareDevice`冻结runtime incarnation和完整逻辑/物理identity；A22只复用current session已接受的完整
observation，逐字段验证checkpoint step、Owned attachment/epoch、nonblank exact head与`R == L`，不接收
bool proof。Mount每次使用fresh authority head，并在最终barrier后要求head不早于durable Mount checkpoint
和pre-barrier Guest probe；同generation异root或任何回退都拒绝。Running admission仍只由完整mounted-set
Ready challenge打开。

Cold→Cold不创建、format或attach frontend，也不增加第二种checkpoint。Node先把现有superseded Stable
Cold `RuntimeCheckpoint`当作完整physical-absence起点。detach若发现被移除intent仍有fenced、`R == L`
的本地cache，必须先持久化并crash-replay既有typed
`CleanupRelease{DetachRetained, exact release generation}`，逐字段绑定旧checkpoint identity，并在fresh exact
Unowned epoch/head下用descriptor-relative cleanup安全回收；它不能在membership替换后降级成ordinary
residue。随后Node才用一次atomic checkpoint replace重绑current revision/spec与exact current volume
membership；只有下一轮full inventory scan才可报告Stable Cold。attach因此还没有执行mkfs/mount，detach
则已经证明被移除设备没有物理资源。只有Node提交exact successor stable-Cold observation，Control才把该
revision的Operation置为Succeeded。Node不接受hot-detach。

### 5. 重放和模糊结果

同Workspace、canonical route和Idempotency-Key先于资源读取被reservation。相同key和exact request bytes
只返回已存status/body；同key异path、If-Match或body冲突且无副作用。COMMIT响应丢失后，唯一恢复方式是
读取或重放该exact result；不得回滚Desired、盲目重复物理动作或从当前binding猜测原请求成功。

新key遇到已绑定/未绑定或Cat/path不匹配返回固定409；非稳定Cold、未结算Operation、非Active/
Persistent、Owned、epoch/head/init不匹配返回固定412。错误结果也在covered事务内持久化，避免重复请求在
并发状态变化后得到另一种含义。

## 后果

- 产品binding、Node物理effects、filesystem初始化和Operation终态共享一个Desired lineage；
- RWO、immutable capacity和首次format authority不能被HTTP、CLI或旧SQL seam绕过；
- attach/detach需要先Stop并等待Cold，完成后Resume才会format/mount并开放服务；
- 第一版不提供hotplug、在线resize、跨Cat原子move或旧mount API兼容层。
