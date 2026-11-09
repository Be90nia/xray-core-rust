# ADR-0003：socket ioctl 去重件落 `xray-frame::net`，不上浮 udf、不下沉 transport

- 状态：Accepted
- 日期：2026-11-08
- 关联：bd vqvn1（NEW-02 ioctl 去重）· bd d597w（UDP bind 静态门）·
  `reports/audit-2026-11-08/architecture.md` A-04（跨层落点缺 ADR）·
  CLAUDE.md §3.5.2 / §3.5.3 / §3.5.5

## 背景

Windows 把 ICMP Port/Net Unreachable 作为**下一次 socket 操作**的错误投递
（`WSAECONNRESET` / `WSAENETRESET`），Go 在 `netFD.init` 给所有 UDP socket 打
`SIO_UDP_CONNRESET` / `SIO_UDP_NETRESET` 关掉整类上报（`net/fd_windows.go`），
Go 侧因此永不可见。Rust 侧要对齐这条语义，就得在**每个 UDP socket bind 之后**
发同样的两个 ioctl。

此前该实现**存两份拷贝**：`crates/xray-transport/src/udp/mod.rs` 与
`crates/xray-proxy-dns/src/udp_connreset.rs`，各自维护 ioctl 常量、SAFETY 论证、
fail-open 兜底文案。bd vqvn1（commit `73bb85a1`）把它收敛成唯一实现
`crates/xray-frame/src/net.rs::disable_icmp_unreachable_report`。

重评分 A-04 记的是**落点字面冲突**：§3.5.3 的判据是「网络/文件/加密/协议等方向件
留主仓**最近消费方**（先例：accept 循环纪律 `accept_policy.rs` 留
`xray-transport`）」，本件却落在**派生层 `xray-frame`**。不写 ADR，下轮就会有人照抄
成「方向件随便进 frame」的第二个先例，把 frame 变成协议机制的公共垃圾桶。

## 决策

`socket ioctl 关 ICMP-unreachable 上报` 的唯一实现在
**`xray-frame::net::disable_icmp_unreachable_report`**
（`crates/xray-frame/src/net.rs`）：**不上浮 udf，也不下沉 `xray-transport`**。

§3.5.5 三判据逐条举证（顺序固定，不跳步）：

1. **判据 1（零 Xray 语义 → udf）不成立**：件内含网络方向语义——WinSock
   `WSAIoctl` 调用、两个 Windows ioctl 常量、`cfg(windows)` 双实现分叉。CLAUDE.md
   §3.5.3 明文「网络（accept 循环纪律…）/文件/加密/协议等方向件，留主仓最近消费方；
   udf 只收无方向进程级机制（cache/retry/clock/id/logx/compose 族）」⇒ udf 不收。
2. **判据 2（否则归派生层 xray-frame）= 本案答案**：去重后消费方有两个，
   而**两方的公共底座就是 xray-frame**——`crates/xray-transport/Cargo.toml` 与
   `crates/xray-proxy-dns/Cargo.toml` 都已把 `xray-frame` 列为 **normal
   dependency**（proxy-dns 侧注释：插件化 L1/L4 面来自装配框架，生产依赖）。落此
   = 零新依赖边、零反向边；`xray-frame` 单向不引任何协议 crate，无环。
3. **判据 3（「连派生层都放不合适」才留主仓）不成立**：§3.5.3 的「最近消费方」在
   本件上**有歧义**——两个消费方分属 `xray-transport` 与 `xray-proxy-dns`，谁都不是
   唯一最近者；此时「最近的公共祖先」= xray-frame。下沉 `xray-transport` 的代价是
   `xray-proxy-dns` 新增一条对 `xray-transport` 的 normal 依赖（当前依赖图**不含**
   `xray-transport`，见 `tools/check_udp_binds.py` 白名单条目 d597w 的原文备注），
   为一处 ioctl 去重件换一圈依赖，且会让 transport 变成「协议 crate 反正都依赖它」
   的收纳箱——与 §3.5.3「方向件留**最近**消费方」的初衷（就近、不造公共层）相悖。

## 后果

- **`xray-frame::net` 的准入边界被本 ADR 钉死**：仅收「被两个以上协议/传输 crate
  共享、且不属于任一方的方向件」；新的方向件默认仍留最近消费方 crate，欲进
  `xray-frame` 必须另开 ADR 逐条举证公共底座属性——**本 ADR 不是「方向件进 frame」
  的通行证**。
- `UdpSocket::bind` 本体**不搬进来**：bind 机制受静态门
  `tools/check_udp_binds.py` 按**文件**白名单登记（`xray-transport/src/udp/mod.rs`
  = helper 正本、`xray-proxy-dns/src/udp_connreset.rs` = 薄转调本体）。本件只承载
  「bind 之后关上报」这一段，绑定点仍留在白名单文件里。
- 维护义务：Windows-only 代码路径由 `#[cfg(windows)]` / `#[cfg(not(windows))]`
  双实现保持调用方零 cfgs；新增平台（如非 Windows 出现同型语义）只改 `net.rs`，
  消费方签名不变（`&S, &LogFacade`）。
- fail-open 语义定在件内（WARN 后继续服务），不在消费方；核心理由是 socket 已 bind
  成功，为「多收一个假错误」拒启一条 UDP 监听不划算，recv 侧错误分类是第二道兜底。

## 备选否决

- **上浮 udf**：网络方向件，违背 §3.5.3「udf 只收无方向进程级机制」；udf 不感知
  平台 ioctl 语义。
- **下沉 `xray-transport`（§3.5.3 字面的「最近消费方」直译）**：`xray-proxy-dns`
  需新增对 `xray-transport` 的 normal 依赖（现状无此边），且把「公共机制」塞进
  传输 crate 会诱导后续协议 crate 都以它为公共底座——依赖图纹理由此劣化。
- **保留两份拷贝**（vqvn1 之前的形态）：§3.5.2 打回项——ioctl 常量 / SAFETY 论证 /
  兜底文案三面双维护，改一处忘一处即平台行为分叉。
- **进程级全局开关（启动时一次性打默认 socket）**：Windows 的该 ioctl 作用于
  **单个 socket handle**，没有「进程级默认」；谎称全局 = 静默不生效。

## 验证方式

- 单一实现：`grep -rn "SIO_UDP_CONNRESET" crates --include=*.rs` ⇒ 常量定义只应出现在
  `crates/xray-frame/src/net.rs`（其余命中是注释/文档引用）。
- 行为双向证明（Windows，`cargo test -p xray-frame --lib net`）：
  `bare_bind_control_receives_connreset`（**对照组**：裸 bind 必须拿到
  `ConnectionReset`，否则本机不复现该语义，测试失效）+ `ioctl_suppresses_connreset`
  （本件关掉上报后同触发不再拿到 `ConnectionReset`）。
- 消费点接线（按符号名定位，不钉行号——行号随树漂移，见 CLAUDE.md §3.5 锚点纪律）：
  `xray-transport` 的 `udp::disable_icmp_unreachable_report`（crate 内薄转调）与
  `xray-proxy-dns` 的 `bind_udp_no_connreset`（bind 后薄转调）两处转调同一正本
  `xray-frame::net::disable_icmp_unreachable_report`（无本地副本）。定位命令：
  `grep -rn "disable_icmp_unreachable_report" crates --include=*.rs`。
- 静态门：`python tools/check_udp_binds.py`（bind 机制只允许出现在白名单两文件）。
