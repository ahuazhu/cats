# ADR-0066：拆分公共 API、共享协议与安装制品 crate

- 状态：Accepted
- 日期：2026-08-31
- 范围：Rust crate 所有权与依赖方向；不改变任何 wire、持久格式或运行时语义

## 背景

`cats-api` 同时包含公共 HTTP DTO、Control/Node/Guest/blockd/storage wire、严格 canonical codec、
签名验证和 Host 安装制品读取。它因此把纯客户端、数据面和 Host 启动路径编译进同一个 crate，名称也
无法表达实际安全边界。尤其是 `runtime_artifacts` 使用 `libc`、文件描述符和 Host 权限合同；它不是
API 数据类型。另一方面，需要签名、hash 或跨组件解释的 codec 必须与其 wire 类型保持同一个事实来源，
不能退化为各组件自行实现。

## 决策

1. `cats-api` 只拥有面向客户端和 Control HTTP 表面的轻量类型：auth、billing、resource ID helper 与
   list envelope。它不实现 wire codec、密码学或 Host 文件系统 I/O。
2. `cats-protocol` 拥有所有跨组件 machine wire：稳定错误、OCI/session、Guest、blockd、metering、
   semantic Control/Node、Runtime Node authority、Volume Authority carrier，以及这些合同唯一的严格
   decoder、canonical encoder、hash 和签名输入。
3. `cats-artifacts` 拥有已安装 runtime release 的 canonical path、owner/mode/link/metadata 校验、
   trust/profile/manifest读取，以及启动 VMM 前保持已验证 kernel/initramfs descriptor 的逻辑。它只依赖
   `cats-protocol` 中的制品 wire，不反向拥有协议。
4. Workspace 组件直接依赖实际 owner crate。依赖方向为 `cats-artifacts -> cats-protocol`；核心
   `cats-api` 不依赖二者。为已发布 `cats-api` 的 Rust 路径兼容，默认 `protocol-compat` 和
   `artifacts-compat` features 继续 re-export 旧模块；Workspace 将 `cats-api` 的 default features 关闭，
   不通过兼容 facade 建立内部依赖。
5. 本次拆分只移动现有实现。所有 Rust 类型字段、枚举、常量值、JSON bytes、错误选择、签名输入、
   filesystem fail-closed检查、CLI/HTTP行为和生命周期/存储authority保持逐项不变。现有 codec、artifact
   和跨组件回归测试必须在新 owner crate 原样通过。

## 后果

公共 HTTP 客户端不再因 Workspace 内部协议而直接依赖 Host I/O。协议使用者可以只依赖
`cats-protocol`，Control/noded composition root 对安装制品显式依赖 `cats-artifacts`。crate 名称与安全
职责一致，后续修改 Host 文件读取不会伪装成 API DTO 变化。

兼容 facade 意味着外部 `cats-api` 默认构建仍会解析两个新 crate；它只用于保留现有 source path，
不再是 Workspace 的推荐依赖方向。未来删除这些 compatibility features 是独立的公共 API/版本决定，
不能在本结构重组中顺带完成。
