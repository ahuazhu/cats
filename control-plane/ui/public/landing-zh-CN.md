持久化云端工作空间

# 你的 Linux 工作空间，*随时就绪。*

Cats 为每个工作区提供一台真正的 Linux microVM，拥有持久磁盘和稳定身份。全速工作，闲置时休眠，再次使用时无需重建环境。

<a href="/user/" class="button-link primary">打开控制台 →</a> <a href="/zh-CN/docs/getting-started/" class="button-link secondary">阅读快速入门</a>

真正按量付费 数据默认持久化 Linux 环境随唤随用

![](/assets/cats-mark.svg)**dev-workspace**ubuntu-24.04 · 2 CPU · 2 GiB

运行中

    $ cats login
    已登录 · 工作区 acme-dev

    $ cats create dev
    正在创建持久 RootDisk…
    正在启动 Guest… 已就绪

    $ cats exec dev -- git status
    位于分支 main
    无文件要提交，干净的工作区

    闲置 → 已暂停 · 工作状态保留

活跃**Running**

快速唤醒**Suspended**

本地快照**Warm**

零计算**Cold**

一套长期存在的环境

## 保留机器，释放计算。

Cat 是一台长期存在的 Linux microVM，而不是一次性的容器会话。它的名称和磁盘不依赖某一台 Host。

⌁

### 真正的 Linux 隔离边界

在 KVM 中运行独立内核，安装普通软件包，使用未修改的 ext4。Guest 永远不会获得平台存储凭据。

↻

### 休眠后不用重头开始

Running、Suspended、Warm 与 Cold 是不同状态。快速恢复失败时，系统一定收敛到干净的 Cold 启动。

▱

### 不怕 Host 丢失的磁盘

成功的 FLUSH 会发布到远端持久存储。本地 NVMe 只是缓存，fencing 确保 V1 的 PersistentDisk 始终只有一个写者。

明确的生命周期

## 四种状态，而不是模糊的“睡眠”。

在唤醒速度、进程状态保留与彻底摆脱原 Host 之间，选择清晰可解释的平衡。

1

### Running

vCPU 正在执行、内存驻留，磁盘持续发布持久 generation，Endpoint 可以服务流量。

完整计算资源

2

### Suspended

vCPU 暂停，进程状态保留在原 Host。VMM 与 Host 亲和继续存在，以获得最短恢复路径。

保留进程状态

3

### Warm

生成 Host 本地快照后 VMM 退出，运行时 RSS 为零，但仍需在原健康 Host 上恢复。

本地快照

4

### Cold

释放全部 Host 运行时资源。任何健康 Host 都能从最后的持久磁盘 generation 启动。

不再绑定 Host

持久性契约

## 磁盘是真相，Host 可以被替换。

Cats 给用户的承诺范围明确且可测试：成功返回的 durable FLUSH 必须能经受 Host 永久丢失。

✓

**标准块设备**

Guest 只看到 virtio 块设备和普通 ext4，不会接触对象存储 API 或元数据凭据。

✓

**小量写入只提交小工作集**

块引擎追踪发生变化的逻辑 Chunk，不会为了提交少量修改而上传整个稀疏虚拟盘。

✓

**旧写者 fail closed**

每个 Attachment 都有 fencing epoch。网络分区后返回的旧 Host 无法覆盖新的写者。

✓

**PersistentDisk 独立存在**

销毁 Cat 会删除它的 RootDisk；已卸载的 PersistentDisk 会一直保留，直到你显式删除。

## 从一只 Cat 开始。

按照快速入门创建持久工作空间、执行命令，并准确理解它休眠时会发生什么。

<a href="/zh-CN/docs/getting-started/" class="button-link primary">开始使用 →</a>
