# Runtime Composition Artifacts v1

- 状态：Implemented frozen v1；clean-slate rollout only
- Runtime authority：[Runtime Reconciliation v1](runtime-reconciliation-v1.md)
- Internal transport：[Agent Registration and Internal Transport v1](agent-registration-transport-v1.md)

本文冻结两个只属于process composition和provision/deploy的边界：Node本地如何取得已经由
provisioner绑定的`NodeIdentity`，以及Control与Node如何证明自己消费同一次release build产生的
Guest boot bytes。它不增加第二个identity、session、release catalog或runtime authority。

本文中的MUST/MUST NOT是F3b及生产部署的上线条件。测试可以通过显式test-only constructor注入
临时identity或release bytes；生产binary没有任意path、inline JSON、环境字段或provider推导fallback。

## 1. 固定路径与上限

| 项目 | V1唯一值 |
|---|---|
| local identity artifact | `/etc/cats/identity/node-identity.v1.json` |
| Node private key | `/etc/cats/identity/node-registration-key.pem` |
| Node credential ID | `/etc/cats/identity/node-registration-credential-id` |
| identity provision lock | `/etc/cats/identity/.provision.lock` |
| identity incomplete recovery set | `/etc/cats/identity/.node-identity-recovery.incomplete.v1/` |
| initial provision recovery set | `/etc/cats/identity/.node-identity-provision.v1/` |
| rotation new recovery set | `/etc/cats/identity/.node-identity-rotation-new.v1/` |
| rotation old recovery set | `/etc/cats/identity/.node-identity-rotation-old.v1/` |
| protected state root | `/var/lib/cats/node` |
| identity-selected state path | `/var/lib/cats/node/<state_path_id>` |
| Host lock | `/var/lib/cats/node/host.lock` |
| shared release payload root | `guest-runtime-release.v1/` |
| release manifest member | `guest-runtime-release.v1/manifest.v1.json` |
| receipt member | `guest-runtime-release.v1/guest-runtime-profile.v1.json` |
| kernel member | `guest-runtime-release.v1/guest/vmlinuz` |
| optional initramfs member | `guest-runtime-release.v1/guest/initramfs.img` |
| installed release manifest | `/opt/cats/release/guest-runtime-release-manifest.v1.json` |
| installed receipt | `/opt/cats/release/guest-runtime-profile.v1.json` |
| installed kernel | `/opt/cats/guest/vmlinuz` |
| installed optional initramfs | `/opt/cats/guest/initramfs.img` |
| durable release sets root | `/opt/cats/releases/sets/` |
| durable release set | `/opt/cats/releases/sets/<guest_runtime_release_id>/` |
| incomplete release set | `/opt/cats/releases/.incomplete/` |
| `NodeIdentity` artifact cap | 16384 octets（沿用F0） |
| release manifest cap | 4096 octets |
| kernel/initramfs member cap | 每个536870912 octets |

`<state_path_id>`先通过F0 `Id`，再通过本合同的`StatePathComponent` context invariant：exact ASCII
bytes不得为`.`或`..`。`Id`不含`/`，加上这两个拒绝后才是一个非navigation path component。Control
provision和Node local artifact读取必须各自执行同一检查；Node不得percent-decode、case-fold或把它解释成
Host提供的任意路径。V1不增加第二个wire type或改变`NodeIdentity.state_path_id: Id`。

## 2. Local NodeIdentity artifact

### 2.1 唯一wire和读取顺序

identity artifact不是新wire type。它必须是
[Runtime Reconciliation v1 §2](runtime-reconciliation-v1.md#2-可信-node-与-agentsession)的完整
`NodeIdentity`，`ContractName`固定为`node_identity`，包含且只包含：

```text
NodeIdentity {
  version: 1,
  node_id: Id,
  immutable_host_id: Id,
  credential_id: Id,
  credential_binding: {
    kind: "public_key",
    public_key_spki_sha256: Sha256Digest
  },
  state_path_id: Id,
  state: "provisioned"
}
```

生产Node按以下唯一顺序读取；任一步失败都保持cordoned、全部runtime/route/volume gate Closed，且不发送
registration request：

1. 用no-follow方式打开exact identity path，只读到16385 octets；
2. 运行F0 `decode_node_identity`，再用§16.1 canonical encoder重编码，并要求与artifact bytes逐byte相同；
3. 要求local artifact的binding是`public_key`、state是`provisioned`，且`state_path_id`通过§1
   `StatePathComponent`；
4. 严格读取A19固定的credential ID文件，并要求其`Id`逐byte等于artifact的`credential_id`；
5. 严格读取PKCS#8 PEM private key，导出A19 §4.1唯一canonical Ed25519 SPKI DER，计算普通SHA-256，
   要求逐字段等于artifact的`credential_binding`；
6. 只用artifact的`node_id`、`immutable_host_id`和`state_path_id`建立Node进程identity与state path；
7. 在读取任何runtime state和创建pending attempt前取得§2.2 Host lock。

生产`cats-noded`不接受`--node-id`、`CATS_NODE_ID`、`--immutable-host-id`、inline artifact或任意
identity path override来构造Agent registration identity。hostname、IP、advertise URL、TLS peer、cloud
metadata/IMDS和调用方body都不得提供或修正这三个字段。provider/IaC验证发生在provisioner，不发生在Agent。

`node_boot_id`只来自当前kernel boot UUID，按F0 `NodeBootId`转换；`agent_instance_id`在每次Agent进程
启动时重新生成。它们不是identity artifact字段。`expected_agent_session_epoch`和
`registration_attempt_id`只来自A19规定的受保护state path；Node不能把这些不同职责合并进artifact。

### 2.2 Filesystem invariant

`/etc/cats/identity`必须为root:root、mode `0700`的真实目录。三个active identity文件和§1三个complete
recovery directory内的对应文件必须同时满足：

- root:root；identity、private key和credential ID mode都精确为`0600`；
- regular file、link count恰好1；路径及最终文件都不是symlink，不能通过hardlink、bind-mounted writable
  alias或group/other-writable ancestor注入；
- 打开后的file descriptor metadata在bounded read前后不变；只根据已经打开的descriptor消费bytes；
- private key和完整registration body不进入argv、environment、日志、Terraform state/output、release bundle
  或Guest。

三个complete recovery directory本身必须是同一`/etc/cats/identity` filesystem内root:root mode `0700`的真实目录，
只能包含active三件套相同basename的closed file set。provision lock是root:root mode `0600`、regular、link count
1且no-follow打开的文件；provisioner对identity操作全程持有其kernel exclusive lock。recovery set不能由Agent
读取为另一个credential，也不能跨filesystem、只留在内存或放进provider state。

fixed complete recovery directory的存在本身是唯一complete marker。创建者只能先在fixed incomplete directory
写closed三件套，逐file fsync、directory fsync并完整重验，再以no-replace atomic directory rename变成目标complete
directory并fsync `/etc/cats/identity`。同一时刻只创建一套recovery set；Control provision/CAS只能发生在其所需
complete marker的parent fsync之后。initial generation在marker前且Control尚无row时，provisioner取得lock后可以
删除partial incomplete directory、fsync parent并生成一把新key；此时没有已提交identity需要exact replay。
rotation old copy在marker前只能在active仍完整匹配Control old authority时删除partial后重抄；rotation new
generation在marker前只能在old complete marker已durable且Control仍精确是old authority时删除partial后重生。
complete marker durable之后才固定该set的exact same bytes，不得清理或重生其中private half。

`/var/lib/cats/node`及选中的state path必须root:root且不可由group/other写。Node先从filesystem root逐component
no-follow打开固定`/var/lib/cats/node`，再从这个已经打开的parent取得`host.lock`的non-blocking kernel exclusive
lock；只有持锁后才能以descriptor-relative、beneath-only方式打开`<state_path_id>`。Host lock是固定parent内
root:root mode `0600`、regular、single-link文件，parent descriptor、lock descriptor和selected state directory
descriptor全部保持到进程退出。相同Host的第二个Agent取得失败即启动失败；换名或重建selected child不能产生
第二把Host lock，也不能把旧进程的state写入replacement inode。

Linux Node把selected state directory复制到一个明确保留、non-`CLOEXEC`且启动时必须空闲的固定descriptor，并把
`/proc/self/fd/<reserved-fd>`作为Node runtime、blockd、Guest helper和Cloud Hypervisor所有state-derived path的
唯一root；owner对象在NodeAgent整个生命周期保持存活。每次runtime构造先重验descriptor仍可继承，所有child
process按同一fd number继承；主进程和child都不能重新canonicalize或按artifact pathname重开state root。非Linux
只保留同一owner/descriptor边界供测试，production Node deployment仍由Linux gate负责。

### 2.3 Initial provision与exact replay

provisioner是唯一创建者，顺序固定为：

1. 从provider/BMC/IaC已经认证的Host事实取得`immutable_host_id`，分配未使用过的`node_id`、
   `state_path_id`和credential ID；`state_path_id`必须通过§1 extra invariant，Agent、hostname或IP不参与；
2. 在目标Host的fixed incomplete recovery directory生成per-Node Ed25519 key，private half不离开Host；从
   canonical SPKI计算binding，并生成credential ID文件和完整canonical `NodeIdentity` bytes；
3. 完整验证incomplete set的closed files、bytes、cross-binding和metadata，fsync每个file descriptor和directory，
   再按§2.2 atomic directory rename为fixed initial complete recovery set并fsync parent。三件套在任何Control
   write前已经是same-filesystem durable exact recovery source；
4. 通过[Runtime Placement Policy §3](runtime-placement-policy-v1.md#3-provisioner-apply)的
   signed node-authority route，把同一NodeIdentity与revision-1 cordoned policy原子provision；response不明时
   只重放same apply ID/request/private key，不能生成identity、key或policy；
5. 从durable recovery descriptors复制private key和credential ID到active parent内exclusive temporary files，
   fsync temp后以no-replace atomic rename激活，再fsync active file和parent；不能rename或删除recovery source；
6. 最后用相同步骤复制并激活`node-identity.v1.json`作为local complete marker，再fsync file和parent；
7. 从active paths重新执行§2.1/§2.2全部验证，创建并保护identity-selected state path。Control identity +
   cordoned policy rows、active三件套和state path全部exact后才durably删除recovery directory并允许启动Node
   service。

complete marker之后任一步response/crash不明时只能把同一个NodeIdentity和同一key/credential bytes与central
IaC已durable保存的same A23 apply ID/policy request组合做exact replay。
marker之前且Control未写的partial generation按§2.2安全清理并重新开始。目标active path缺失时只从已经durable的
fixed complete recovery set继续安装；已存在且bytes、派生SPKI和metadata全部exact时视为已完成；任一不等都
fail closed，不覆盖、删除、重新生成key或创建第二个Control identity。Control write之后的每个crash window都
必须保留same private half；如果Host filesystem永久丢失，只能按§2.4 retire/fence并创建新lineage，不能把
Control已有row当作从网络重建旧private key的理由。

### 2.4 Credential rotation、retire和Host replacement

credential rotation不改变`node_id`、`immutable_host_id`或`state_path_id`：

Control-side CAS transport、provisioner signature、apply replay和policy/assigned-set前置条件由
[Runtime Placement Policy §3](runtime-placement-policy-v1.md#3-provisioner-apply)冻结；本节只
冻结old/new local private-half的crash-safe安装顺序。

1. Node先cordon、drain、停止，确认没有pending registration attempt，并等到A23 Store以DB now证明current
   AgentSession absent/expired；
2. provisioner从active descriptors复制完整old三件套到fixed incomplete recovery directory，逐byte/cross-binding
   验证，并按§2.2逐file/directory fsync、atomic rename为fixed old complete recovery directory并fsync parent；
   这只是Control rotation commit前放弃操作时的old private-half恢复源；commit后old ID/SPKI已进入
   A23永久retired lineage，该directory不得再安装为active；
3. 在fixed incomplete recovery directory生成新的key、credential ID和只改变credential字段的canonical
   artifact，按§2.2逐file/directory fsync、atomic rename为fixed new complete recovery directory并fsync parent；
   Control CAS之前old/new两套都已在同一filesystem durable；marker前crash且authority仍是old时可清理partial
   incomplete set并重新生成new key；
4. Control Store用expected policy revision与old credential ID/binding做一次exact A23 apply，原子地把old lineage
   转retired、插入fresh new active lineage并替换NodeIdentity binding；response不明时只重放同一
   pending apply ID/body。只有canonical applied response才进入第5步；持久precondition 409表示Control未改
   credential，必须保留old active set并丢弃这次new set，不得换apply ID猜测；
5. service保持停止，只从durable new recovery descriptors复制到active parent内exclusive temporary files，逐个
   fsync temp并atomic rename新key和credential ID，artifact最后安装；每个active file及parent fsync后重新验证
   完整new set，不能rename或删除new recovery source；
6. Node startup重新执行§2.1全部cross-check后才注册。old/new recovery sets必须保留到new credential成功注册且
   没有ambiguous pending attempt；之后才durably清理两套recovery files/directories。

crash可以留下Control已接受new credential而Host仍是old或local三个文件暂时不匹配；这两种状态都必须拒绝
启动/注册。恢复持有同一provision lock并先闭合官方CLI的pending A23 apply：若结果是
precondition 409且Control仍为exact old binding，可从durable old set恢复完整active set；若结果是
applied/new binding，只能从durable new set向前完成安装。不按单文件mtime猜测。

A23 rotation commit后没有reverse CAS：old credential ID/SPKI已永久retired，不能被同Node、另一Node或
后续release重新激活。new registration结果不明时，必须先用new recovery set恢复并按A19重放
同一pending attempt。若new private half永久丢失无法forward-complete，只能retire该NodeIdentity并以
全新Node/credential lineage重建，不得安装old set。任何窗口都只有一把Control认可的key。

retire只通过A23 same node-authority apply在Control Store把同一NodeIdentity变为`retired`，并永久保留lineage、
最后policy和apply result；local artifact可以留作诊断，
但不能恢复eligibility。换Host、换state path、重装为新lineage或重新provision必须使用全新的`node_id`、
`immutable_host_id`/`state_path_id`组合和新的credential。只有旧identity已retire且provider证明旧Host/state
storage不能再运行后，provisioner才可安全清理旧Host文件；不得把新lineage覆盖到旧artifact后复用旧Node。

### 2.5 Fixed vector

使用A19 §4.4的`credential_a`和SPKI digest，canonical artifact是下列287 ASCII octets，末尾无LF：

```json
{"credential_binding":{"kind":"public_key","public_key_spki_sha256":"sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"},"credential_id":"credential_a","immutable_host_id":"host_a","node_id":"node_a","state":"provisioned","state_path_id":"state_path_a","version":1}
```

```text
artifact_sha256 = sha256:72de79e76084952c50eb9cefc9b53be0b1bc958358c8cdc10cb799a81a4496aa
credential file bytes = ASCII("credential_a\n")
state path = /var/lib/cats/node/state_path_a
```

验收必须逐byte重建vector，并证明credential ID、SPKI、node/Host/state-path、state、mode、owner、link count、
canonical JSON或path任一不等都在网络请求前fail closed。

## 3. One shared Guest runtime release payload

### 3.1 Closed layout与manifest

一个release build先于Control image和worker bundle构建，且只产生一个uncompressed payload tree：

```text
guest-runtime-release.v1/
  manifest.v1.json
  guest-runtime-profile.v1.json
  guest/
    vmlinuz
    initramfs.img                 # iff receipt.initramfs_digest != null
```

除目录entry外，文件集合必须与上面精确相等；全部是non-empty regular file，不允许extra member、symlink、
hardlink、device、FIFO、absolute path、`..`或重复archive entry。传输可把这个tree放进OCI build context或
deterministic tar，但解包器在materialize任何member前必须对完整outer archive做bounded header preflight：验证
closed exact path/type/declared-size集合、重复项和全部link target，且不能跟随或创建archive声明的path。只有
preflight全绿后才创建private staging，并用no-follow、beneath-only、exclusive-create extractor逐member写入；
header与实际byte count任一变化就删除未激活staging并失败。不得让普通tar extractor先写再检查，也不能把archive
直接覆盖到active Host path。

`manifest.v1.json`是以下closed canonical JSON，最大4096 octets，无BOM、前后空白或结尾LF：

```text
GuestRuntimeReleaseManifest {
  version: 1,
  guest_runtime_profile: ReleaseMember,
  kernel: ReleaseMember,
  initramfs: ReleaseMember | null
}

ReleaseMember {
  path: closed literal,
  sha256: Sha256Digest,
  size_bytes: U64
}
```

三个`path`分别固定为`guest-runtime-profile.v1.json`、`guest/vmlinuz`和
`guest/initramfs.img`。每个size必须大于0；receipt不超过4096，kernel和initramfs各不超过§1上限。
普通SHA-256和size逐byte绑定对应member。manifest的receipt hash同时必须等于A19要求的receipt artifact
hash；kernel/initramfs hash及nullability必须逐字段等于F0 `GuestRuntimeProfileReceipt`。

唯一immutable release identity定义为：

```text
guest_runtime_release_id = SHA-256(
  ASCII("cats.release.guest-runtime-manifest.v1") || 0x00 || exact_manifest_bytes
)
```

它编码为`Sha256Digest`。identity只命名这一个closed payload，不是可写catalog、channel alias或协商字段。
Control/Node artifact manifest和部署记录必须携带同一个exact ID；`latest`、tag、image name、worker bundle
filename和独立重建的等价JSON都不能代替它。

### 3.2 Build once, consume twice

release pipeline固定为：

1. 在一个job中取得已经pinned并验证的kernel完整bytes及可选initramfs完整bytes，固定唯一VMM cmdline和
   compiled Guest Agent protocol literal；
2. 用F0 canonical encoder生成一次receipt，计算A19 `guest_config_digest`；
3. 用上述exact bytes生成一次canonical manifest和release ID，冻结payload tree为只读build artifact；
4. Control image build与worker bundle build都只下载/挂载该同一个artifact及其release ID，不各自运行
   receipt/manifest generator；
5. qualification从两个最终artifact重新extract receipt和manifest，逐byte比较；worker另外extract kernel/
   initramfs并按manifest验证。任一缺失、extra、size/hash/nullability或release ID不等都拒绝发布。

Control image把同一receipt和manifest以root:root mode `0644` regular file COPY到§1 exact installed paths；
镜像中不需要Guest kernel/initramfs，但其manifest仍绑定worker将安装的exact bytes。worker bundle携带完整
payload tree。构建系统可以改变outer archive/OCI metadata；不能改变这四个logical member bytes。

production Control Kubernetes args、Metal Control systemd和所有Node systemd都显式传：

```text
--guest-runtime-profile-receipt-file /opt/cats/release/guest-runtime-profile.v1.json
```

CLI/env选择与exact-path校验沿用A19 §8.1。生产没有manifest path参数：manifest只从固定installed path读取，
并在receipt之前验证。测试临时payload只由production binary不可达的test-only constructor注入。

### 3.3 Node atomic installation与rollback

Node deploy只在已经cordon、drain且`cats=0/orphans=0`后激活新payload：

1. 下载并校验outer worker bundle，按§3.1在不materialize member时完成全archive bounded header preflight；
2. preflight全绿后才以no-follow/beneath-only extractor写private staging；在不停止当前worker前完成closed
   entry、canonical manifest、release ID、actual member size/hash、receipt F0和cross-field验证；
3. 停止Node service并再次证明没有VMM/blockd/pending unique data；从此到成功start或rollback期间service
   必须保持停止；
4. 在fixed incomplete release directory建立incoming closed set，逐member和directory fsync并完整重验后，以
   no-replace atomic directory rename安装为`sets/<incoming release ID>`并fsync sets parent。对当前active
   release也必须在首个active rename前以相同步骤保存并fsync `sets/<previous release ID>`；不能用单文件
   `.previous`猜组合。complete release directory的存在且parent已fsync是唯一complete marker；目标set已存在
   时只有closed bytes和metadata全部exact才视为幂等完成，否则fail closed；
5. 对manifest、receipt、kernel和可选initramfs分别使用same-filesystem temporary file + atomic rename +
   parent fsync；null initramfs必须原子移走旧active initramfs；
6. 一个固定`/run/lock/cats/worker-deployment.lock` open-file-description lock必须覆盖stop、prepare、全部outer
   binary/config/unit/seed mutation、candidate start、实际Agent registration-backed readiness、commit或rollback；
   installer和任何长期安装的seed updater都验证继承的exact lock descriptor。不能chmod共享`/run/lock`；
7. 从active exact paths重新读取并验证整个集合与staged release ID一致；随后用A23 expected policy revision
   CAS更新仍cordoned policy的exact `guest_config_digest`及本次同时部署的其他capability，response不明只重放
   same apply。此时assigned set仍为空；
8. 全部outer mutation和policy CAS完成后，在仍停止的Node下durably写start-authorization marker并fsync parent。systemd
   `ExecStartPre`只有在同一deployment lock正被占有、activation journal完整、authorization精确绑定incoming ID且
   active bytes重验一致时才允许candidate start；“lock busy”本身不授权启动；
9. policy与active set逐字段相同后才start Node；Node startup再独立执行A19 §8.2，成功注册前所有gate仍Closed；
10. candidate成功建立AgentSession并开放本地readiness后才commit：先durably清activation journal，再清
   authorization marker。journal在此前所有outer crash window都保留；任一失败或进程/Host kill后，独立service
   restart必须恢复previous exact set但保持Node停止和journal retained，直到完整outer transaction重放并commit；
11. 任一install/start验证失败时保持Node停止，用保存的完整previous set执行同一原子逐文件安装和整体验证，
   并以fresh apply ID/expected current policy revision把capability反向CAS到previous exact值；只在previous
   set/policy完整自洽时restart。rollback失败则保持停止、cordoned并告警，不能混搭新旧member。首次安装没有
   previous时继续保留journal和exact incoming bytes，完整部署重放前不得start。

多文件切换不是一个filesystem rename事务，因此安全线性化点是“service停止后，active完整集合重新验证
成功，再允许start”。crash可留下mixed files，但systemd不能在未先运行同一validator的情况下启动Node；
恢复只根据marker-complete的incoming/current/previous release sets选择exact完成或exact rollback，不按单个
文件时间猜测。crash发生在incomplete set任一copy/fsync/rename前时可以删除该未激活目录并从active exact bytes
重建；首个active rename之前incoming和存在的previous complete marker都必须durable。首次安装没有previous set
时，失败只能保持停止直到incoming exact完成，不能构造虚假rollback。

active `/opt/cats/release`和`/opt/cats/guest`是root:root mode `0755`真实目录，durable release sets root和
incomplete directory是root:root mode `0700`真实目录；这些路径祖先都不能group/other-writable。
manifest、receipt、kernel和存在时的initramfs都必须是root:root mode `0644`、regular、link count恰好1，路径和
final file不是symlink，也没有hardlink或bind-mounted writable alias。validator以no-follow方式打开fixed path，
在bounded read/hash前后要求descriptor metadata稳定，只用已打开descriptor的bytes；mode/owner/type/link或
manifest binding任一不等都保持Node停止。previous/staged set保存同样metadata，不能在rollback时放宽。

Node startup验证不能授权后来按path重新打开的bytes。每次VMM launch紧邻spawn重新打开active kernel/optional
initramfs，重复完整metadata/size/hash/receipt/manifest校验，并把这些verified descriptors保持打开且继承给VMM，
以该进程可见的descriptor path作为唯一kernel/initramfs输入；spawn成功前path rename或内容/metadata变化都使
launch失败。Control同样对fixed manifest/receipt path执行no-follow、descriptor-stable bounded验证，但不携带
Guest boot files。deploy只有在Node停止时才可替换active set。

Control image rollout由immutable OCI digest回滚；rollback目标必须包含其原exact manifest/receipt。Control和
Node release可以滚动先后部署，但guest digest不等时新AgentSession固定失败；不得为过渡同时批准两个digest、
热换receipt或降级到旧shared bearer。非空Node仍必须先drain再切换Guest release。

### 3.4 Fixed vector

本vector引用Runtime §16.3/A19固定receipt。receipt是301 octets，artifact hash是
`sha256:dae6f9b08706e17d03cbeece8141fef960185fe0758f80f999f9f2218d43e10a`。manifest是下列
464 ASCII octets，末尾无LF；示例member size只固定manifest wire，不声称真实production文件大小：

```json
{"guest_runtime_profile":{"path":"guest-runtime-profile.v1.json","sha256":"sha256:dae6f9b08706e17d03cbeece8141fef960185fe0758f80f999f9f2218d43e10a","size_bytes":301},"initramfs":{"path":"guest/initramfs.img","sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size_bytes":8388608},"kernel":{"path":"guest/vmlinuz","sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size_bytes":16777216},"version":1}
```

```text
manifest_sha256 = sha256:7066ce52d8b8b1cc236fdd6819eea749c1f077dbf74d16494cc621deda8a5692
guest_runtime_release_id = sha256:dfe2076171c35378fc247191c43a27a3ea9f819cc99c5cdf107157ce50918e5e
```

验收必须独立重建manifest/ID，覆盖null initramfs，并证明任一member byte/size/path、extra/missing entry、
receipt canonical bytes、manifest key order、Control/Node artifact copy或active install变化都会拒绝release或
Node startup。

## 4. Minimal acceptance matrix

| boundary | required oracle |
|---|---|
| identity wire | F0 + canonical exact bytes；fixed vector；unknown/duplicate/noncanonical/16385拒绝；state path `.`/`..`拒绝 |
| identity files | owner/mode/type/link count/no-follow；credential LF；key/SPKI/artifact exact cross-check |
| identity source | Node/Host/state path只来自artifact；CLI/env/hostname/IP/IMDS mutation零影响且无请求 |
| provision replay | marker前可清未提交partial；marker/key set在Control前durable；每个write/fsync/rename/commit kill |
| rotation | old/new recovery set在CAS前durable；apply/每个rename/fsync/start kill；pre-commit失败保持old；commit后只从new set forward-complete，old ID/SPKI跨Node/release永不可重用；new half永久丢失只能retire/new lineage，无reverse CAS |
| retire/replace | retired exact attempt replay仍按A19；新attempt拒绝；新Host不能复用旧node/lineage |
| state path | parent Host lock先于child；第二Agent失败；rename/recreate后主进程/child只访问retained DirFd旧inode |
| release build | generator只运行一次；Control/worker extract manifest/receipt逐byte相等且ID相同 |
| release layout | pre-materialize traversal/link/duplicate header拒绝且零外部写；closed entries、size/hash/nullability |
| install crash | incoming/previous marker先durable；prepare/outer mutation/authorization/start/readiness/commit每窗kill；exact rollback且保持停止，完整重放后commit |
| launch bytes | 每次launch descriptor-stable rehash；validate后path replacement不能改变VMM实际kernel/initramfs |
| production config | Control K8s/Metal和Node units传exact receipt CLI；manifest fixed path；无fallback/catalog |
| legacy negative | Host-derived kernel/initramfs、worker现场重建、独立等价JSON和fixture receipt不合格 |
