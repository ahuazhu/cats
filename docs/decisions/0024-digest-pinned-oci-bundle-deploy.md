# ADR-0024：按 digest 固定的 OCI Bundle Deploy，不引入 Docker/OverlayFS

- 状态：Accepted
- 日期：2026-07-31

## 背景

CI Preview 和 Staging 需要交付“已经构建好的应用”，而不是在每个 Cat 内重复
`docker save → artifact 下载 → 解压 → chroot → 自写 supervisor`。完整架构 §11.1
已经把这条路径命名为 Bundle Deploy，但此前只有 `cats exec`，所以每个业务流水线都要
重新实现 Registry 拉取、layer 合并、进程守护和冷启动后的重启。

Cats 当前 Guest kernel 没有 OverlayFS，Docker 只能退化为 `vfs`；但应用交付并不要求
在 Cat 里再运行一个容器 daemon。OCI Image Spec 同时定义了不可变 manifest、layer、
whiteout 和进程配置，这些能力可以独立于 Docker/OverlayFS 复用。

## 决定

1. 新增 `cats deploy CAT APP --image REGISTRY/REPOSITORY@sha256:...` 和
   `POST /v1/workspaces/{workspace}/cats/{cat}/oci-deployments`。第一版只接受
   `sha256` digest，不接受 tag，也不接受“tag + digest”的双重名字。一次重试仍指向
   同一不可变输入。
2. 支持 OCI Image Manifest/Index 与 Docker schema 2 Manifest/List。Index 按 Guest
   的 `linux/amd64` 或 `linux/arm64` 选择平台 manifest；manifest、config 和每个
   compressed layer 都按 descriptor 的 digest 与 size 校验后才使用。
3. 拉取和解包发生在 Guest Agent 内。Guest 使用自己的普通应用网络访问 Registry；
   Cat/Node/控制面都不获得 Registry 的长期权限。可选 Basic 用户名/密码（密码也可为
   短期 token）只随这一次请求转发，不进入 Cats 数据库、Operation 或日志；CLI 只从
   stdin 读取密码，不把它放进 argv。
4. Layer 在 RootDisk 的 `/var/lib/cats/oci/<app>/releases/<manifest-digest>/` 中按顺序
   **扁平化**，实现 OCI whiteout 与 opaque whiteout。支持未压缩 tar、gzip 和 zstd；
   保留 mode、uid/gid、mtime 和 xattr；拒绝 path traversal、逃逸到 release root 外的
   父 symlink 和 device/FIFO 等特殊文件。
5. 不使用 Docker daemon、containerd、OverlayFS 或另一个镜像块设备。一个 manifest
   对应一个完整展开的目录，因此换取的是实现与故障边界简单，代价是每个 app/digest
   占一份展开后的 RootDisk 空间。RootDisk 的 Direct-S3/Delta/CoW 仍按普通文件写处理，
   本 ADR 不改变 Golden Root、ChunkStore、FLUSH、GC 或 durability 协议。
6. 激活使用原子 `current` symlink，并写入 `cats-oci-<app>.service`。systemd
   `RootDirectory=` 提供 chroot 视图，`MountAPIVFS=yes` 提供标准 API 文件系统；
   进程共享 Cat 的网络 namespace，因此直接监听 Guest 端口，不做 `docker -p`。
   OCI `Entrypoint + Cmd`、`Env`、`WorkingDir`、数字/名字形式的 `User[:Group]`
   被翻译成 unit；CLI 可覆盖 argv 和非敏感环境配置。
7. systemd 是应用重启与生命周期的唯一 supervisor：
   - Running 部署后 `enable + restart`；
   - Suspended/Warm 保留原进程；
   - Cold 后 systemd 从持久 RootDisk 再次启动 enabled unit；
   - 同一 Cat 内多个 OCI app 共享 Guest kernel、网络和 RootDisk。需要彼此成为安全隔离
     边界时必须使用不同 Cat；OCI chroot 不是新的多租户隔离边界。
8. deploy 的 work lease 覆盖 wake、拉取、解包和启动，防止 auto-suspend 与部署竞态。
   返回 `active=true` 只表示 systemd unit 已成功进入 active；应用级 HTTP/数据库
   readiness 仍由调用方或未来独立 readiness contract 判断，不能把 `Type=simple`
   当成业务健康。

## 环境变量与 Secret 边界

第一版的 `--env-file` 是**持久应用配置**：值会写入 RootDisk 上的 systemd unit，以便
Cold boot 后服务仍可启动。因此它不能用于需要 Cats 保密或轮换的 Secret。Registry pull
凭据是唯一的 transient credential。

Secret Resource/Guest tmpfs 注入尚未实现；加入后 OCI deploy 只保存 secret reference，
控制面在每次 Cold boot/重新调度时重新注入明文。未完成该能力前，业务仍需用现有受控
bootstrap 路径注入 Secret，不能因为接口字段叫 `env` 就宣称秘密没有落盘。

## 不变量与验收

- tag 或错误长度/算法的 digest 在任何网络请求前拒绝。
- manifest/config/layer 任一 digest 或 size 不匹配，不能激活 release 或覆盖当前 unit。
- whiteout 必须先作用于 lower layer；whiteout 文件本身不能出现在最终 rootfs。
- staging 失败只留下可清理的 `.work-*`，不能改变 `current`。
- Registry password 不出现在 CLI argv、`Debug` 输出、数据库和 operation payload。
- 一个真实/本地 Registry 合同测试必须通过“manifest → config → layer → digest 校验 →
  flatten → unit”完整生产路径，而不是手写最终 rootfs。

## 后果

收益：

- CI 只发布标准 OCI image，并用 digest 调用 Cats；不再传 `docker save` artifact、
  维护 chroot 解包脚本或自写 supervisor。
- 不等待 Guest kernel 增加 OverlayFS，也不引入 Docker daemon 的权限、网络和存储
  故障域。
- systemd、RootDisk durability、Suspend/Warm/Cold 继续沿用已经验收的边界。

代价与后续：

- layer flatten 会消耗展开后大小，并且 app 对 chroot 的运行时写入会修改该 release
  目录；第一版不宣称它是只读 container rootfs。
- 尚无 Secret Resource、应用 health/readiness、release list/rollback/GC、签名策略或
  SBOM 门禁；这些是后续一等 Release 资源需要补齐的能力。
- OCI image 只是应用交付格式，不替代 Cats 自己包含 kernel/initramfs/Guest Agent 的
  Golden Root。
