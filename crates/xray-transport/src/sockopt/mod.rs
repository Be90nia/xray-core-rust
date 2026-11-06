//! Socket 选项配置与应用。对应 Go `transport/internet/sockopt.go` + 平台特定文件。
//!
//! ## 切片边界（P5-Sys 切片1→切片2）
//!
//! 切片1：跨平台通用基础 sockopt（TCP_NODELAY + SO_KEEPALIVE + TCP_KEEPIDLE/
//! TCP_KEEPINTVL + V6Only）。
//! 切片2（本模块）：平台特定选项（TFO/TCP_CONGESTION/SO_REUSEPORT/
//! IP_TRANSPARENT/SO_USER_COOKIE）由 [`apply_outbound_socket_options`] /
//! [`apply_inbound_socket_options`] 跨平台分发到 `linux` / `windows` /
//! `darwin` / `freebsd` 各平台模块实现。MPTCP 单独走 `try_set_mptcp`
//! （仅 Linux 监听前生效）。入站 listener 端 TFO backlog / SO_REUSEPORT 在
//! [`crate::system_listener::DefaultListener::bind`] 之前对原始 socket 设置。
//!
//! ## SocketOptions vs SocketConfig proto
//!
//! 不引入完整 prost SocketConfig（字段过多），用简化 [`SocketOptions`]
//! struct 暴露常用字段。完整 proto 对接留后续。
//!
//! ## TFO 三态 vs bool
//!
//! Go `SocketConfig.Tfo` 三态（`-1` 未配置/`0` 显式禁用/`>0` 启用），
//! Rust [`SocketOptions::tcp_fast_open`] 是 bool（缺省 false = 显式禁用或未
//! 配置——两者均不调用 setsockopt）。平台模块 `apply` 内自行 `>0` 时启用、
//! `tcp_fast_open==false` 时跳过。

#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(target_os = "freebsd")]
pub mod freebsd;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use xray_frame::deadline::Budget;
/// 基础 socket 选项。对应 Go `SocketConfig` 的核心字段子集。
///
/// 默认值与 Go DefaultSystemDialer 一致：
/// - `tcp_nodelay = true`（Chrome 默认）
/// - `tcp_keepalive_idle = 45s`
/// - `tcp_keepalive_interval = 45s`
///
/// sockopt 域名解析策略。对应 Go `transport/internet.DomainStrategy`
/// （config.pb.go 枚举 + config.go:13-26 strategy 表）。
///
/// 注意与 `xray_proxy_freedom::config::DomainStrategy`（Go `proxy/freedom`
/// proto 枚举）是平行类型——Go 中二者同样各自定义（freedom 配置转换后写入
/// `SocketConfig.DomainStrategy` 才进入拨号层）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum DomainStrategy {
    /// AS_IS：不预解析，由系统 resolver 处理（默认）。
    #[default]
    AsIs = 0,
    /// USE_IP：解析到任意族 IP。
    UseIP = 1,
    /// USE_IP4。
    UseIPv4 = 2,
    /// USE_IP6。
    UseIPv6 = 3,
    /// USE_IP46：优先 IPv4，回退 IPv6。
    UseIPv4v6 = 4,
    /// USE_IP64：优先 IPv6，回退 IPv4。
    UseIPv6v4 = 5,
    /// FORCE_IP：同 USE_IP，解析失败即失败。
    ForceIP = 6,
    /// FORCE_IP4。
    ForceIPv4 = 7,
    /// FORCE_IP6。
    ForceIPv6 = 8,
    /// FORCE_IP46。
    ForceIPv4v6 = 9,
    /// FORCE_IP64。
    ForceIPv6v4 = 10,
}

impl DomainStrategy {
    /// 从 proto i32 值构造。非法值回退 `AsIs`（Go config.pb.go 枚举范围外不存在）。
    #[must_use]
    pub const fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::UseIP,
            2 => Self::UseIPv4,
            3 => Self::UseIPv6,
            4 => Self::UseIPv4v6,
            5 => Self::UseIPv6v4,
            6 => Self::ForceIP,
            7 => Self::ForceIPv4,
            8 => Self::ForceIPv6,
            9 => Self::ForceIPv4v6,
            10 => Self::ForceIPv6v4,
            _ => Self::AsIs,
        }
    }

    /// Go `transport/internet/config.go:13-26` strategy 表：`[mode, prefer, fallback]`。
    ///
    /// mode：0=AsIs，1=Use，2=Force；prefer/fallback：0=both，4=IPv4，6=IPv6。
    #[must_use]
    pub const fn strategy_table(self) -> [u8; 3] {
        match self {
            Self::AsIs => [0, 0, 0],
            Self::UseIP => [1, 0, 0],
            Self::UseIPv4 => [1, 4, 0],
            Self::UseIPv6 => [1, 6, 0],
            Self::UseIPv4v6 => [1, 4, 6],
            Self::UseIPv6v4 => [1, 6, 4],
            Self::ForceIP => [2, 0, 0],
            Self::ForceIPv4 => [2, 4, 0],
            Self::ForceIPv6 => [2, 6, 0],
            Self::ForceIPv4v6 => [2, 4, 6],
            Self::ForceIPv6v4 => [2, 6, 4],
        }
    }

    /// 是否带解析策略（Go `HasStrategy()`：mode != 0）。
    #[must_use]
    pub const fn has_strategy(self) -> bool {
        self.strategy_table()[0] != 0
    }

    /// 解析失败是否必须报错（Go `ForceIP()`：mode == 2）。
    #[must_use]
    pub const fn force_ip(self) -> bool {
        self.strategy_table()[0] == 2
    }

    /// 优先 IPv4（Go `PreferIP4()`：prefer==4 **或 both**）。
    #[must_use]
    pub const fn prefer_ipv4(self) -> bool {
        let p = self.strategy_table()[1];
        p == 4 || p == 0
    }

    /// 优先 IPv6（Go `PreferIP6()`：prefer==6 **或 both**）。
    #[must_use]
    pub const fn prefer_ipv6(self) -> bool {
        let p = self.strategy_table()[1];
        p == 6 || p == 0
    }

    /// 有回退家族（Go `HasFallback()`）。
    #[must_use]
    pub const fn has_fallback(self) -> bool {
        self.strategy_table()[2] != 0
    }

    /// 回退 IPv4（Go `FallbackIP4()`）。
    #[must_use]
    pub const fn fallback_ipv4(self) -> bool {
        self.strategy_table()[2] == 4
    }

    /// 回退 IPv6（Go `FallbackIP6()`）。
    #[must_use]
    pub const fn fallback_ipv6(self) -> bool {
        self.strategy_table()[2] == 6
    }
}

/// SRV/TXT 记录覆盖目标地址/端口策略。对应 Go
/// `transport/internet.AddressPortStrategy`（config.pb.go:102-108）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum AddressPortStrategy {
    /// 不覆盖（默认）。
    #[default]
    None = 0,
    /// SRV 记录覆盖端口。
    SrvPortOnly = 1,
    /// SRV 记录覆盖地址。
    SrvAddressOnly = 2,
    /// SRV 记录覆盖端口 + 地址。
    SrvPortAndAddress = 3,
    /// TXT 记录覆盖端口。
    TxtPortOnly = 4,
    /// TXT 记录覆盖地址。
    TxtAddressOnly = 5,
    /// TXT 记录覆盖端口 + 地址。
    TxtPortAndAddress = 6,
}

impl AddressPortStrategy {
    /// 从 proto i32 值构造。非法值回退 `None`。
    #[must_use]
    pub const fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::SrvPortOnly,
            2 => Self::SrvAddressOnly,
            3 => Self::SrvPortAndAddress,
            4 => Self::TxtPortOnly,
            5 => Self::TxtAddressOnly,
            6 => Self::TxtPortAndAddress,
            _ => Self::None,
        }
    }

    /// SRV/TXT → 覆盖位（Go dialer.go:145-172 的 switch 展开）。
    #[must_use]
    pub const fn override_flags(self) -> (bool, bool, bool) {
        // (is_srv, override_port, override_address)
        match self {
            Self::SrvPortOnly => (true, true, false),
            Self::SrvAddressOnly => (true, false, true),
            Self::SrvPortAndAddress => (true, true, true),
            Self::TxtPortOnly => (false, true, false),
            Self::TxtAddressOnly => (false, false, true),
            Self::TxtPortAndAddress => (false, true, true),
            Self::None => (false, false, false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketOptions {
    /// 是否启用 TCP_NODELAY（禁用 Nagle 算法）。默认 `true`。
    pub tcp_nodelay: bool,
    /// TCP keepalive 空闲超时。`0` 表示用 OS 默认值。
    pub tcp_keepalive_idle: Duration,
    /// TCP keepalive 探测间隔。`0` 表示用 OS 默认值。
    pub tcp_keepalive_interval: Duration,
    /// SO_MARK 包标记值（Linux fwmark），用于 iptables/fwmark 策略路由。`0`=不设置。
    /// 对应 Go `SocketConfig.Mark`。仅 Linux 有效，其他平台忽略。
    pub mark: u32,
    /// TCP Fast Open。对应 Go `SocketConfig.Tfo`（Go `ParseTFOValue()` 三态在平台
    /// 模块以 `i32` 表达；bool `true` 映射为启用）。
    /// Linux（TCP_FASTOPEN_CONNECT）/ FreeBSD 12.1+ / Windows 10 1607+（Winsock
    /// TCP_FASTOPEN=15，见 `windows` 模块）支持；macOS 用 CLIENT/SERVER 位标志。
    pub tcp_fast_open: bool,
    /// Multipath TCP（MPTCP）。对应 Go `SocketConfig.TcpMptcp`（字段 19，JSON `tcpMptcp`）。
    /// 仅 Linux 生效；其他平台或不支持 MPTCP 的内核上静默回退普通 TCP
    /// （对齐 Go `net.ListenConfig.SetMultipathTCP` 行为）。监听 socket 在
    /// bind 前设置 `TCP_MPTCP`，accept 出的连接自动为 MPTCP。
    pub tcp_mptcp: bool,
    /// TCP 拥塞控制算法名称（如 "bbr"、"cubic"）。
    /// 对应 Go `SocketConfig.TcpCongestion`（sockopt_linux.go:40-43）。
    /// 仅 Linux 有效，其他平台忽略（macOS 不暴露此选项、FreeBSD/Windows 忽略）。
    pub tcp_congestion: Option<String>,
    /// 是否启用 IP_TRANSPARENT（透明代理，需要 root 或 CAP_NET_ADMIN）。
    /// 对应 Go `SocketConfig.Tproxy.IsEnabled()`（sockopt_linux.go:104-108）。
    /// 仅 Linux 有效；其他平台忽略。
    pub tproxy: bool,
    /// accept 后读取 PROXY protocol header 提取真实源地址。对应 Go
    /// `SocketConfig.AcceptProxyProtocol`（字段 7，transport_sockopt.go:49，JSON
    /// `acceptProxyProtocol`；消费点 system_listener.go:169-172 包 proxyproto.Listener）。
    /// tcp/ws/httpupgrade transport 各自 settings 的 `acceptProxyProtocol` 在 Go
    /// hub.go 监听时 OR 进本字段（tcp/hub.go:40），Rust 同构在 transport 装配处 OR。
    pub accept_proxy_protocol: bool,
    /// Linux/FreeBSD/Darwin 有效；Windows no-op（sockopt_windows.go:188-190）。
    pub reuse_port: bool,
    /// 绑定到指定网络接口索引。`0`=不绑定。
    /// 对应 Go `SocketConfig.Interface`（Go 用接口名字符串，Rust 用索引）。
    /// Linux: SO_BINDTODEVICE；Darwin: IP_BOUND_IF / IPV6_BOUND_IF。
    pub bind_if_index: u32,
    /// 是否限制 socket 仅使用 IPv6（不允许 IPv4-mapped 地址）。默认 `false`。
    /// 对应 Go `sockopt_ipv6_only` / `IPV6_V6ONLY`。socket2 跨平台 `set_only_v6()`。
    pub ipv6_only: bool,
    /// transport 层代理：经指定 tag 的 outbound handler 拨号而非直连。
    /// 对应 Go `SocketConfig.DialerProxy`（config.pb.go:735）。空串 = 直连。
    pub dialer_proxy: String,
    /// Happy Eyeballs 竞争拨号配置。对应 Go `SocketConfig.HappyEyeballs`
    /// （config.proto:157，字段 22）。`None` 或 `try_delay_ms == 0` = 关闭
    /// （Go 默认 `TryDelayMs: 0`，infra/conf/transport_internet.go:1144）。
    pub happy_eyeballs: Option<HappyEyeballsConfig>,
    /// 域名解析策略。对应 Go `SocketConfig.DomainStrategy`
    /// （config.pb.go:735 附近 + infra/conf/transport_internet.go:1037）。默认 `AsIs`。
    pub domain_strategy: DomainStrategy,
    /// SRV/TXT 记录覆盖目标地址/端口策略。对应 Go
    /// `SocketConfig.AddressPortStrategy`（infra/conf/transport_internet.go:1050）。默认 `None`。
    pub address_port_strategy: AddressPortStrategy,
    /// 可信 `X-Forwarded-For` 采纳门控 header 名单。对应 Go
    /// `SocketConfig.TrustedXForwardedFor`（config.proto 字段 23，`repeated string`，
    /// JSON `trustedXForwardedFor`）。入站仅当请求携带名单中任一 header 时才把
    /// XFF 首段采纳为源地址；空 = 永不采纳（防伪造，Go headers.go
    /// `ApplyTrustedXForwardedFor`）。
    pub trusted_x_forwarded_for: Vec<String>,
    /// TCP_WINDOW_CLAMP 边界缓冲上限（字节）。对应 Go `SocketConfig.TcpWindowClamp`
    /// （config.proto 字段 15，JSON `tcpWindowClamp`）。仅 Linux 应用
    /// （sockopt_linux.go:46-50/155-159）；Go Windows/Darwin/FreeBSD 分支均不应用，
    /// 其余平台仅解析存储。`0`=不设置。
    pub tcp_window_clamp: i32,
    /// TCP_USER_TIMEOUT（毫秒，RFC 5482）。对应 Go `SocketConfig.TcpUserTimeout`
    /// （字段 16，JSON `tcpUserTimeout`）。仅 Linux 应用（sockopt_linux.go:52-56）。
    /// `0`=不设置。
    pub tcp_user_timeout: i32,
    /// TCP_MAXSEG 最大 MSS（字节）。对应 Go `SocketConfig.TcpMaxSeg`
    /// （字段 17，JSON `tcpMaxSeg`）。仅 Linux 应用（sockopt_linux.go:58-62）。
    /// `0`=不设置。
    pub tcp_max_seg: i32,
    /// SO_RCVBUF 接收缓冲（字节）。JSON `receiveBufferSize`。`0`=TCP 路径取
    /// `TCP_RCVBUF_DEFAULT`（两平台均为 0 = **不设置**，交 OS autotune；bd r5j96）。
    /// **Go `SocketConfig` 无此字段**（v26.9.9 config.proto
    /// 全字段核对），本仓库 opt-in 运维扩展：显式设置即锁定该 socket 的内核接收
    /// 窗自动调节（Linux `SOCK_RCVBUF_LOCK`，通告窗上限=值×2 字节记账），用于高
    /// BDP 链路下转发应用消费过快致 rcvbuf 恒空、DRC 无扩窗信号的窗死锁。
    /// 超过 `net.core.rmem_max` 的值被内核静默钳制。inbound（accept 后 per-conn）
    /// 与 outbound（拨号前）同字段生效。
    pub receive_buffer_size: i32,
    /// SO_SNDBUF 发送缓冲（字节）。JSON `sendBufferSize`。`0`=不设置。与
    /// [`SocketOptions::receive_buffer_size`] 同为 opt-in 运维扩展（Go `SocketConfig`
    /// 无此字段，JSON 命名对齐其 camelCase 风格）。TCP 路径不消费；QUIC 系 UDP
    /// 端点消费（见 [`bind_udp_endpoint`]）。超过 `net.core.wmem_max` 的值被内核
    /// 静默钳制。
    pub send_buffer_size: i32,
    /// splithttp 拨号时下载连接继承本 sockopt。对应 Go `SocketConfig.Penetrate`
    /// （字段 18，JSON `penetrate`；消费点 splithttp/dialer.go:387）。
    pub penetrate: bool,
    /// 自定义 setsockopt 列表。对应 Go `SocketConfig.CustomSockopt`
    /// （字段 20，JSON `customSockopt`）。Linux/Darwin/Windows 应用（int 类型全平台；
    /// str 类型 Windows 报错不支持，Go sockopt_windows.go:113），FreeBSD 不应用
    /// （Go sockopt_freebsd.go 无 custom 循环）。
    pub custom_sockopt: Vec<CustomSockopt>,
}

/// Happy Eyeballs 配置。对应 Go `HappyEyeballsConfig`
/// （transport/internet/config.proto:162-166 + infra/conf/transport_internet.go:1008-1030）。
///
/// JSON 字段名：`happyEyeballs: { prioritizeIPv6, tryDelayMs, interleave, maxConcurrentTry }`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HappyEyeballsConfig {
    /// true → IPv6 先行；false → IPv4 先行。
    pub prioritize_ipv6: bool,
    /// 同族连续尝试几个地址再切换到另一族（RFC 8305 Address Family
    /// Selection，Go sortIPs 的 `interleave`）。
    pub interleave: u32,
    /// 相邻两次拨号尝试的启动间隔（毫秒）。`0` = 整个功能关闭
    /// （Go dialer.go:262 `TryDelayMs == 0` 降级为单 IP 直连）。
    pub try_delay_ms: u64,
    /// 最大并发拨号数。`0` = 关闭。
    pub max_concurrent_try: u32,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        // 与 Go infra/conf/transport_internet.go:1021 UnmarshalJSON 缺省值一致。
        Self { prioritize_ipv6: false, interleave: 1, try_delay_ms: 0, max_concurrent_try: 4 }
    }
}
/// 自定义 socket 选项条目。对应 Go `internet.CustomSockopt`（config.proto:94-101）。
/// 全字段 string（proto 原样）：level/opt 为十进制数字字符串，应用时才 Atoi
/// （Go `strconv.Atoi` 失败静默取 0，此处同款）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustomSockopt {
    /// 限定 OS（`runtime.GOOS` 形式，如 "linux"/"windows"）；空 = 全平台。
    pub system: String,
    /// 限定网络前缀（"tcp"/"tcp4"/"udp"…，Go `strings.HasPrefix` 匹配）；空 = 全网络。
    pub network: String,
    /// setsockopt level 十进制字符串；空 = 0x6（IPPROTO_TCP，Go 默认）。
    pub level: String,
    /// setsockopt optname 十进制字符串；空 = Go 报错 "No opt!"。
    pub opt: String,
    /// 选项值（int 十进制 / str 原样字节）。
    pub value: String,
    /// 值类型："int" 或 "str"，其他值 Go 报错 "unknown CustomSockopt type"。
    pub r#type: String,
}

impl Default for SocketOptions {
    fn default() -> Self {
        // 与 Go DefaultSystemDialer 的 Chrome 默认值一致。
        Self {
            tcp_nodelay: true,
            tcp_keepalive_idle: Duration::from_secs(45),
            tcp_keepalive_interval: Duration::from_secs(45),
            mark: 0,
            tcp_fast_open: false,
            tcp_mptcp: false,
            tcp_congestion: None,
            tproxy: false,
            accept_proxy_protocol: false,
            reuse_port: false,
            bind_if_index: 0,
            ipv6_only: false,
            dialer_proxy: String::new(),
            happy_eyeballs: None,
            domain_strategy: DomainStrategy::AsIs,
            address_port_strategy: AddressPortStrategy::None,
            trusted_x_forwarded_for: Vec::new(),
            tcp_window_clamp: 0,
            tcp_user_timeout: 0,
            tcp_max_seg: 0,
            receive_buffer_size: 0,
            send_buffer_size: 0,
            penetrate: false,
            custom_sockopt: Vec::new(),
        }
    }
}

/// TCP 出站/入站 SO_RCVBUF 缺省值（字节）。**两平台均为 0 = 不设置**。
///
/// # 为什么两平台都不设（bd r5j96）
///
/// 显式 `setsockopt(SO_RCVBUF)` 在两平台都会**关闭接收窗自动调节**并把窗钉死在
/// 请求值——它是「锁窗」而非「抬上限」，与「加内存缓冲」的直觉相反：
///
/// - **Windows**：显式设置关掉 Winsock autotune，吞吐 = 窗/RTT。实测 RTT=161ms 时 4MB → 约 24.8MB/s
///   天花板，而同机同节点 sing-box（不设此项、靠 autotune）
///   57MB/s；本地窗扫描逐点吻合公式（128KB→0.80MB/s、512KB→2.88MB/s）。
/// - **Linux**：`setsockopt(SO_RCVBUF)` 受 `net.core.rmem_max` **静默钳制** （stock 缺省 212992 =
///   208KB）——请求 4MB 实得 208KB，且设置即关闭内核 autotune（SOCK_RCVBUF_LOCK）→ 窗钉死 208KB。WSL
///   netem 150ms/向（RTT 300ms） 实测：ours（4MB 缺省）0.80MB/s，Go 26.10.17 / sing-box
///   1.14.3（均不设此项） 7.43MB/s——**9 倍差**，「不设」在 Linux 同样显著优于「设」。
///
/// Go net / Go 版 xray / sing-box **从不设** SO_RCVBUF，交 OS autotune；本缺省
/// 与之对齐。
///
/// # 与 bd 88m0 的关系
///
/// 早先的 4MB 缺省是为治**内核 DRS**（`tcp_moderate_rcvbuf`）把接收窗钉死 ~64KB
/// （bd 88m0/7p1m，高 RTT 吞吐 = 窗/RTT）——但它自身就是「锁窗」，在 rmem_max
/// 未调大时把窗钉在 208KB，比不设更差。该症状的根因是**读循环排水模式**
/// （收端即时排空 → 接收队列恒空 → rcvbuf 目标恒等于当前值），**另立 bd cna1g**
/// 处理，不在本票解决。⚠️ 别把 4MB 当成有意保留的缺省——它是反效果。
///
/// # 显式配置
///
/// 显式 `receiveBufferSize > 0`（JSON `sockopt.receiveBufferSize`）在两平台照旧
/// 生效（消费点只在 `> 0` 时下 setsockopt）：那是用户显式要求「锁窗 + 大缓冲」
/// 的场景（如确知 BDP 上限），与缺省策略无关。
pub(crate) const TCP_RCVBUF_DEFAULT: i32 = 0;

/// 客户端裸拨号点（transport 自持 TCP，不经 [`crate::system_dialer::dial_system`]）
/// 统一应用的 SO_RCVBUF 缺省（bd 88m0 客户端侧收口）。
///
/// ws/splithttp/grpc 拨号此前裸 `TcpStream::connect`，下行接收窗钉 64KB
/// （4 流 × 64KB/RTT 吞吐签名，HttpUpClientDig tr-httpupgrade 14 倍差实证）。
/// 与 [`apply_outbound_socket_options`] 同常量同语义；这些拨号点无 sockopt
/// 配置输入（sockopt 在 dial_system 路径消费、不透传 transport dial），故无
/// 显式值可尊重，恒取 `TCP_RCVBUF_DEFAULT`。失败即拨号失败，对齐
/// dial_system 的 sockopt 应用语义。
///
/// 两平台 `TCP_RCVBUF_DEFAULT` = 0 → 本函数是**空操作**（保留内核/Winsock 接收窗
/// autotune，理由见常量文档）。
pub fn apply_client_dial_rcvbuf(tcp: &tokio::net::TcpStream) -> std::io::Result<()> {
    if TCP_RCVBUF_DEFAULT > 0 {
        let sock = socket2::SockRef::from(tcp);
        sock.set_recv_buffer_size(TCP_RCVBUF_DEFAULT as usize)?;
        // bd unpg5：同显式口径，下发后回读（当前常量恒 0 = 本分支不活；若未来
        // 翻常量，钳制可见性随行，见 r5j96 裁决）。
        warn_if_rcvbuf_clamped(TCP_RCVBUF_DEFAULT, sock.recv_buffer_size());
    }
    Ok(())
}

/// 显式接收缓冲（SO_RCVBUF）**免确认档上限**（字节）：≤ 此值直接生效。
///
/// 依据 `docs/guide-highrtt-sockopt.md` §9/§11（bd adch 2026-09-17，随发行物
/// 分发）：RTT>50ms 的长肥管**必须**显式 `sockopt.receiveBufferSize`（指南推荐
/// 4MB），否则 Linux tcp_rmem 128KB ⇒ 吞吐锁死窗/RTT（322ms 实测塌 1.5-2.0Mbps）。
/// 容量公式 `receiveBufferSize ≥ BDP = 带宽 × RTT / 8`（4MB@322ms 只支撑 ~99Mbps，
/// 1Gbps×322ms 需 40MB）⇒ 4MB 是「指南推荐档」，无需任何额外动作。
pub const SO_RCVBUF_FREE_TIER_MAX: usize = 4 * 1024 * 1024;

/// 显式接收缓冲**硬上限**（字节）：> 此值恒拒（防手滑）。
///
/// 依据指南 §96-98：4MB 设定 ⇒ 内核 **2× 记账**（8MB/连接）；账面 =
/// 并发 × 2 × 值。大并发要降档到 1-2MB ⇒ 64 MiB 是「单机单连接」的防手滑红线。
pub const SO_RCVBUF_HARD_MAX: usize = 64 * 1024 * 1024;

/// 大档显式接收缓冲的**确认开关名**（env，进程级语义；**单一真值源**——全仓只
/// 此一处定义与读取，见 `large_rcvbuf_confirmed`）。
///
/// 语义：`XRAY_ALLOW_LARGE_RCVBUF=1` ⇒ 允许 (4 MiB, 64 MiB] 档。缺省 = 未确认。
/// 依据指南 §96-98 的 2× 记账与并发账面公式 `并发 × 2 × 值`——大档是**显式运维
/// 决策**，必须由运维自己确认，程序不替用户赌内存。
pub const ALLOW_LARGE_RCVBUF_ENV: &str = "XRAY_ALLOW_LARGE_RCVBUF";

/// 显式接收缓冲（SO_RCVBUF）**三档裁决**（PM 终裁 2026-11-05，替代单一 4 MiB 硬拒：
/// 硬拒会把指南 §11 的 BDP 公式掐死 = 往回优化）。
///
/// 1. **≤ [`SO_RCVBUF_FREE_TIER_MAX`]（4 MiB）**：直接生效（指南推荐档）。
/// 2. **4 MiB < value ≤ [`SO_RCVBUF_HARD_MAX`]（64 MiB）**：BDP 大带宽档，需**显式
///    确认**（[`ALLOW_LARGE_RCVBUF_ENV`]=1）；未确认 ⇒ **fail-visible 拒**（文案点名 值、开关名、2×
///    内核记账与 `并发 × 2 × 值` 的并发账面后果）。**禁静默钳制**。
/// 3. **> 64 MiB**：恒拒（防手滑）。
///
/// 判定用**用户设定值**（不用回读值）：Linux 下 setsockopt 受 `net.core.rmem_max`
/// 静默钳制（回读远小于设定值），但回读小不代表没风险——用户填 16 MiB 就是 16 MiB
/// 的语义，且上限判定必须**早于** setsockopt（否则超限值先被内核钳住，回读看着
/// 「没超」）。缺省 0 ⇒ 完全不碰 socket（r5j96，交 OS autotune）。
///
/// 旋钮性质（bd o93t）：Go `SocketConfig` **无此字段**，本仓刻意加的 **opt-in 运维
/// 扩展**（o93t 终裁明文「opt-in 字段保留为高 BDP 运维工具」，验收项「默认 0 零行为
/// 变化」）；bd 88m0 曾把**缺省**设成 4 MiB（治 Rust 特有的 64 KB 出生接收窗钉死），
/// bd r5j96 已把**缺省**回归 0（交 OS autotune，WSL netem 实测追平 go/sing-box）。
/// 本裁决只约束**显式值**的分档，不动缺省。
pub const MAX_EXPLICIT_RECEIVE_BUFFER_SIZE: usize = SO_RCVBUF_FREE_TIER_MAX;

/// 显式 `receiveBufferSize` 预算判定（纯判定，不需 socket；`confirmed` 可注入
/// 供测试做「带确认 ⇒ 生效」观测，避免测试改进程 env）。
///
/// 三档（PM 终裁，详见 [`MAX_EXPLICIT_RECEIVE_BUFFER_SIZE`]）：
/// - `≤ 4 MiB` ⇒ Ok（免确认档）；
/// - `4 MiB < v ≤ 64 MiB` ⇒ 需确认（`confirmed`）⇒ 否则 Err（文案点名值、开关名、 2× 内核记账与
///   `并发 × 2 × 值` 的并发账面后果）；
/// - `> 64 MiB` ⇒ 恒拒。
///
/// **以用户设定的值判定，不用回读值**：Linux 下 setsockopt 受 `net.core.rmem_max`
/// 静默钳制（回读远小于设定值），但回读小不代表没风险——用户填 16 MiB 就是 16 MiB
/// 的语义，且上限判定必须**早于** setsockopt（否则超限值先被内核钳住，回读看着
/// 「没超」）。错误文案点名上限值与配置来源（fail-visible）：**禁静默钳到上限**
/// ——静默钳会骗运维「配了 16 MiB 实际 4 MiB」。
fn check_explicit_receive_buffer_size_with(
    opts: &SocketOptions,
    confirmed: bool,
) -> std::io::Result<()> {
    let requested = opts.receive_buffer_size;
    if requested <= 0 {
        // 缺省 = 不设置（r5j96：交 OS autotune），无预算占用。
        return Ok(());
    }
    let requested = requested as usize;
    if requested <= SO_RCVBUF_FREE_TIER_MAX {
        return Ok(());
    }
    if requested > SO_RCVBUF_HARD_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socketSettings.receiveBufferSize={requested} exceeds hard cap \
                 {SO_RCVBUF_HARD_MAX} bytes (64 MiB per-connection hard limit; \
                 see docs/guide-highrtt-sockopt.md §96-98)"
            ),
        ));
    }
    if !confirmed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socketSettings.receiveBufferSize={requested} exceeds free tier \
                 {SO_RCVBUF_FREE_TIER_MAX} bytes and requires explicit confirmation: \
                 set {ALLOW_LARGE_RCVBUF_ENV}=1 (kernel books 2x per socket => {} bytes; \
                 total = concurrent_conns × 2 × {requested}; \
                 see docs/guide-highrtt-sockopt.md §96-98)",
                requested * 2
            ),
        ));
    }
    Ok(())
}

/// 显式 `receiveBufferSize` 预算判定（公开口：读进程级确认开关）。
pub fn check_explicit_receive_buffer_size(opts: &SocketOptions) -> std::io::Result<()> {
    check_explicit_receive_buffer_size_with(opts, large_rcvbuf_confirmed())
}

/// 大档确认开关读数（**全仓唯一 env 读取点** = 单一真值源）。
fn large_rcvbuf_confirmed() -> bool {
    std::env::var(ALLOW_LARGE_RCVBUF_ENV).as_deref() == Ok("1")
}

/// 显式 SO_RCVBUF 钳制判据（bd unpg5）：回读 < 请求值 = 内核未足额受理。足额时
/// 回读 ≥ 请求值——Linux 2× 记账（命中时 2×设定值）、Windows/macOS 原样或向上取整；
/// 被 `net.core.rmem_max` 钳制时回读 = 2×rmem_max < 请求值。`requested <= 0`
/// （缺省不设，r5j96）恒 false。模块私有，测试同模块直测判据。
fn rcvbuf_clamped(requested: i32, actual: usize) -> bool {
    requested > 0 && actual < requested as usize
}

/// 显式 SO_RCVBUF 下发后回读核对（bd unpg5）：此前不回读 ⇒ `net.core.rmem_max`
/// （stock 208KB）静默钳制 + autotune 锁死完全不可见（请求 4MB 实得 208KB 照常
/// 服役）。只做可见性（WARN 点名实际值），**不改行为**——预算闸判定仍用用户
/// 设定值（见 [`check_explicit_receive_buffer_size`]），缺省 0 不设语义不变。
fn warn_if_rcvbuf_clamped(requested: i32, actual: std::io::Result<usize>) {
    if let Ok(actual) = actual {
        if rcvbuf_clamped(requested, actual) {
            crate::LOG.warn(format!(
                "receiveBufferSize={requested} clamped by kernel: actual SO_RCVBUF={actual} \
                 bytes (net.core.rmem_max caps silently on Linux and locks autotune; \
                 see docs/guide-highrtt-sockopt.md §9-§11)"
            ));
        }
    }
}

/// 显式 SO_SNDBUF 钳制判据（bd wpa3o）：回读 < 请求值 = 内核未足额受理。
/// **各平台回读语义依据**（票面要求逐平台自查后定判据，非照抄 RCVBUF）：
/// - **Linux**：`sock_setsockopt` 2× 记账（`sk_sndbuf = 2×min(v, wmem_max)`， 下限
///   `SOCK_MIN_SNDBUF`；socket(7) 明文 "the kernel doubles this value ... and this doubled value is
///   returned by getsockopt"）——足额时回读 = 2×设定 ≥ 请求值；受 `net.core.wmem_max`（stock
///   212992）钳制时回读 = 2×wmem_max < 请求值（请求 > 2×wmem_max 才可判，粗钳必中）。
/// - **Windows**：无倍率、无上限钳制、无下限抬升——2026-11-07 本机 Win32 实测 （独立探针：TCP/UDP ×
///   set 64B/1MiB/8MiB/64MiB/256MiB）set N → get N **全等值**。
/// - **macOS/BSD**：`sbreserve` 原样存放（doubling 是 Linux 特有，SO 21146955； quic-go
///   `sys_conn_buffers*.go` 在全平台用同一判据 `newSize < desired`）， TCP 发送 autotune 只升不降 ⇒
///   回读 ≥ 设定值。
///
/// 综上三平台「足额受理 ⇒ 回读 ≥ 请求值」恒成立，判据取 `actual < requested`；
/// `requested <= 0`（缺省不设）恒 false。模块私有，测试同模块直测判据。
fn sndbuf_clamped(requested: i32, actual: usize) -> bool {
    requested > 0 && actual < requested as usize
}

/// 显式 SO_SNDBUF 下发后回读核对（bd wpa3o）：此前不回读 ⇒ `net.core.wmem_max`
/// （stock 208KB 量级）静默钳制完全不可见。只做可见性（WARN 点名实际值），
/// **不改行为**——预算闸判定仍用用户设定值（见
/// [`check_explicit_udp_buffer_size_with`]）。
fn warn_if_sndbuf_clamped(requested: i32, actual: std::io::Result<usize>) {
    if let Ok(actual) = actual {
        if sndbuf_clamped(requested, actual) {
            crate::LOG.warn(format!(
                "sendBufferSize={requested} clamped by kernel: actual SO_SNDBUF={actual} \
                 bytes (net.core.wmem_max caps silently on Linux; \
                 see docs/guide-highrtt-sockopt.md §9-§11)"
            ));
        }
    }
}

/// 显式 `receiveBufferSize` 判定 + 下发（**三 transport 拨号点的统一口**）。
///
/// - 缺省（0）⇒ 完全不碰 socket（r5j96：交 OS autotune）；
/// - 显式（>0 且 ≤ 上限）⇒ setsockopt 下发（失败即拨号失败，对齐 bd 88m0 口径）；
/// - 超限 ⇒ Err（fail-visible，文案点名上限值与配置来源），**不静默钳制**。
pub fn apply_explicit_receive_buffer_size(
    tcp: &tokio::net::TcpStream,
    opts: &SocketOptions,
) -> std::io::Result<()> {
    check_explicit_receive_buffer_size(opts)?;
    if opts.receive_buffer_size > 0 {
        let sock = socket2::SockRef::from(tcp);
        sock.set_recv_buffer_size(opts.receive_buffer_size as usize)?;
        // bd unpg5：下发后回读，内核钳制可见（WARN 带实际值；只观测不改行为）。
        warn_if_rcvbuf_clamped(opts.receive_buffer_size, sock.recv_buffer_size());
    }
    Ok(())
}

/// Linux connect 前的 TFO（`TCP_FASTOPEN_CONNECT`，出站）——transport 裸拨号路径
/// 专用（[`dial_client_tcp`] 复用 `dial_tcp_raw` 时经此接线）。尽力而为：失败只记
/// debug 不阻断拨号（纯优化项不能成为拨号失败原因）。非 Linux 无 TFO 语义，恒空。
pub(crate) fn apply_client_tfo_linux(socket: &Socket) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // TFO：LinuxSockOpt 出站分支（inbound=false）即 TCP_FASTOPEN_CONNECT。
        let tfo = linux::LinuxSockOpt { tcp_fast_open: 1, ..Default::default() };
        if let Err(e) = tfo.apply(socket.as_raw_fd()) {
            crate::LOG.debug(format!("error={e} TCP_FASTOPEN_CONNECT 不可用，按普通握手拨号"));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
    }
}

/// 客户端裸拨号统一入口（[`apply_client_dial_rcvbuf`] 的三个调用点用它取代裸
/// `TcpStream::connect`）。
///
/// Linux 在 connect **之前**设 `TCP_FASTOPEN_CONNECT`：TFO 只对建立前的 socket
/// 生效（对 ESTABLISHED socket 设置，新内核返回 EINVAL——见
/// [`apply_outbound_socket_options`] 的测试注释），由
/// `DefaultSystemDialer::dial_tcp_raw` 的自持 socket 经 `apply_client_tfo_linux`
/// 完成（AI7 起，同时接入 DialerController）。私有项不用 intra-doc 链接，
/// 否则 `cargo doc` 报 "links to private item"。
///
/// 默认启用、无配置输入（这些拨号点不消费 sockopt 配置，与 RCVBUF 缺省同源
/// 理由）。对端不支持 TFO / 无 cookie 时内核自动回退普通握手；setsockopt 本身
/// 失败（内核 <4.11 / seccomp 限制）只记 debug 不阻断拨号——纯优化项不能成为
/// 拨号失败原因。多地址回退语义对齐 `TcpStream::connect`（逐个尝试）。
///
/// 整个回退序列（非单地址）受 `DEFAULT_DIAL_TIMEOUT`
/// 16s 超时约束（bd cjwc G1，对齐 Go `dial_system` 语义；超时返回
/// `ErrorKind::TimedOut`，错误文案与 `dial_tcp_raw` 同源）。
pub async fn dial_client_tcp<A>(host: A) -> std::io::Result<tokio::net::TcpStream>
where
    A: tokio::net::ToSocketAddrs,
{
    Budget::tokio()
        .deadline(crate::system_dialer::DEFAULT_DIAL_TIMEOUT)
        .timeout(dial_client_tcp_inner(host))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timeout")))
}

/// 多地址逐个尝试的拨号本体（超时由 [`dial_client_tcp`] 外层统一施加）。
///
/// AI7 改经 `dial_tcp_raw` 复用其成熟 connect 序列（socket2 自持 → controllers →
/// connect → SO_ERROR 检查）——DialerController（TUN 出站绑定等）必须在 connect
/// 前作用于 fd（Go system_dialer.go TCP `dialer.Control` 同序）。本路径无 sockopt
/// 配置输入，controller 结果即最终绑定，不存在用户 interface 配置覆盖问题。
async fn dial_client_tcp_inner<A>(host: A) -> std::io::Result<tokio::net::TcpStream>
where
    A: tokio::net::ToSocketAddrs,
{
    let mut last_err = None;
    for addr in tokio::net::lookup_host(host).await? {
        match crate::system_dialer::DefaultSystemDialer::dial_tcp_raw(
            None,
            addr,
            crate::system_dialer::DEFAULT_DIAL_TIMEOUT,
            0,
            true,
        )
        .await
        {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no address to dial")
    }))
}

/// 把 [`SocketOptions`] 应用到已建立的 [`Socket`]（TCP 专用）。
///
/// 对应 Go `applyOutboundSocketOptions`（sockopt_linux.go:16-111 / freebsd.go:127-178
/// / windows.go:34-121）。失败时返回 [`std::io::Error`]，调用方决定是忽略（继续拨号）
/// 还是中止。平台模块（`linux::LinuxSockOpt::apply` 等）内按 `tcp_fast_open=false`
/// 跳过 TFO 设置，因此本函数可在 `SocketOptions::default()` 上无副作用通过。
///
/// 各平台覆盖范围：
/// - Linux：TFO_CONNECT / TCP_CONGESTION / TCP_WINDOW_CLAMP / TCP_USER_TIMEOUT / TCP_MAXSEG /
///   SO_REUSEPORT / IP_TRANSPARENT（tproxy）/ SO_MARK / SO_BINDTODEVICE
/// - FreeBSD：TFO / SO_REUSEPORT_LB→SO_REUSEPORT / SO_USER_COOKIE（mark）
/// - Darwin：TFO_CLIENT 位 / SO_REUSEPORT / IP_BOUND_IF / IPV6_BOUND_IF / TCP_KEEPALIVE-KEEPINTVL
/// - Windows：Winsock TCP_FASTOPEN=15 / IP_UNICAST_IF / IPV6_UNICAST_IF
///
/// SO_RCVBUF 缺省值见 `TCP_RCVBUF_DEFAULT`（两平台均为 0 = 不设置）；显式
/// `receiveBufferSize` 优先（用户显式要求「锁窗 + 大缓冲」时照旧生效）。
pub fn apply_outbound_socket_options(
    socket: &Socket,
    opts: &SocketOptions,
    #[allow(unused_variables)] // dest 保留对齐 Go applyOutboundSocketOptions 签名
    dest: Option<std::net::SocketAddr>,
) -> std::io::Result<()> {
    // TCP_NODELAY：跨平台通用。
    socket.set_nodelay(opts.tcp_nodelay)?;
    if opts.ipv6_only {
        socket.set_only_v6(true)?;
    }
    // SO_RCVBUF：显式 `receiveBufferSize` 优先；缺省两平台均**不设置**
    // （bd r5j96）——显式 setsockopt 在两平台都是「关掉 autotune 并把窗钉在请求值」
    // 而非「抬上限」：Windows 关 Winsock autotune（吞吐=窗/RTT，实测 4MB→24.8MB/s
    // vs autotune 57MB/s）；Linux 受 net.core.rmem_max 静默钳制（stock 208KB）+
    // 锁 autotune → 窗钉 208KB（WSL netem RTT 300ms 实测 0.80 vs 7.43MB/s，9 倍差）。
    // 0 = 不下 setsockopt（socket2 跨平台，unix/Winsock SO_RCVBUF）。
    // bd u91se 预算闸：显式值过统一上限判定（超限 ⇒ Err，文案点名上限值与字段名；
    // 缺省 0 = 不碰 socket，r5j96 语义不变）。判定用用户设定值（不用回读值）。
    check_explicit_receive_buffer_size(opts)?;
    let rcvbuf =
        if opts.receive_buffer_size > 0 { opts.receive_buffer_size } else { TCP_RCVBUF_DEFAULT };
    if rcvbuf > 0 {
        socket.set_recv_buffer_size(rcvbuf as usize)?;
        // bd unpg5：下发后回读，内核钳制可见（WARN 带实际值；只观测不改行为）。
        warn_if_rcvbuf_clamped(rcvbuf, socket.recv_buffer_size());
    }
    // SO_KEEPALIVE + TCP_KEEPIDLE/TCP_KEEPINTVL（Go KeepAliveConfig 语义，见
    // [`set_keepalive_config`]）。Darwin 平台 keepalive 走 darwin 模块自带逻辑。
    set_keepalive_config(socket, opts)?;

    #[cfg(target_os = "linux")]
    {
        let fd = socket.as_raw_fd();
        linux::LinuxSockOpt {
            tcp_fast_open: if opts.tcp_fast_open { 1 } else { 0 },
            reuse_port: opts.reuse_port,
            tproxy: opts.tproxy,
            tcp_congestion: opts.tcp_congestion.clone(),
            inbound: false,
            mark: opts.mark,
            bind_if_index: opts.bind_if_index,
            tcp_window_clamp: opts.tcp_window_clamp,
            tcp_user_timeout: opts.tcp_user_timeout,
            tcp_max_seg: opts.tcp_max_seg,
        }
        .apply(fd)?;
    }

    #[cfg(target_os = "freebsd")]
    {
        let fd = socket.as_raw_fd();
        freebsd::FreebsdSockOpt {
            tcp_fast_open: if opts.tcp_fast_open { 1 } else { -1 },
            reuse_port: opts.reuse_port,
            mark: opts.mark,
            inbound: false,
        }
        .apply(fd)?;
    }

    #[cfg(target_os = "macos")]
    {
        let fd = socket.as_raw_fd();
        // Go sockopt.go:42 按目标地址判定 IPV6_BOUND_IF vs IP_BOUND_IF（bd 2fu2）。
        // 未传 dest 时回落 false（行为同 Go 端 -1 默认）。
        let dest_is_v6 = matches!(dest, Some(std::net::SocketAddr::V6(_)));
        darwin::DarwinSockOpt {
            tcp_fast_open: if opts.tcp_fast_open { 1 } else { 0 },
            reuse_port: opts.reuse_port,
            bind_if_index: opts.bind_if_index,
            is_ipv6: dest_is_v6,
            tcp_keepalive_idle: opts.tcp_keepalive_idle.as_secs() as u32,
            tcp_keepalive_interval: opts.tcp_keepalive_interval.as_secs() as u32,
            inbound: false,
        }
        .apply(fd)?;
    }

    #[cfg(target_os = "windows")]
    {
        let s = socket.as_raw_socket();
        // Go sockopt_windows.go:41 按目标地址判定 IP_UNICAST_IF vs IPV6_UNICAST_IF
        // （bd 2fu2）。未传 dest 时回落 v4（保守对齐原行为）。
        let dest_is_v4 = matches!(dest, Some(std::net::SocketAddr::V4(_)) | None);
        windows::WindowsSockOpt {
            tcp_fast_open: if opts.tcp_fast_open { 1 } else { -1 },
            bind_if_index: opts.bind_if_index,
            is_ipv4: dest_is_v4,
        }
        .apply(s)?;
    }

    // CustomSockopt：Linux/Darwin/Windows 应用，FreeBSD 无（Go 各平台文件差异）。
    #[cfg(not(target_os = "freebsd"))]
    apply_custom_sockopt(socket, opts)?;
    Ok(())
}

/// 出站 socket 绑定网络接口索引（**必须 connect 前调用**，post-connect 设置
/// 无法改变出站接口）。dialer controller（TUN `autoOutboundsInterface`，
/// Go proxy/tun/handler.go:130-164）的绑定原语。
///
/// - Windows：IP_UNICAST_IF / IPV6_UNICAST_IF（Go tun_windows.go:553-577 的 TCP 分支；v4 值 network
///   byte order——复用 `WindowsSockOpt`， TFO 位保持未配置不触碰）。
/// - Linux：SO_BINDTODEVICE（Go tun_linux.go:403 `unix.BindToDevice`；复用
///   `LinuxSockOpt`，其余字段全缺省 = 零副作用）。
/// - 其余平台：`Unsupported`（Go 无 setinterface 的平台同样无此机制）。
///
/// 多播分支（Go 的 IP_MULTICAST_IF / IPV6_MULTICAST_IF）不在此处：系统拨号器
/// 当前仅 TCP（UDP 拨号属后续切片）。
pub fn bind_socket_to_interface(
    socket: &Socket,
    if_index: u32,
    dest_is_ipv4: bool,
) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::WindowsSockOpt {
            tcp_fast_open: -1,
            bind_if_index: if_index,
            is_ipv4: dest_is_ipv4,
        }
        .apply(socket.as_raw_socket())
    }
    #[cfg(target_os = "linux")]
    {
        // SO_BINDTODEVICE 与地址族无关（同一条 setsockopt 覆盖 v4/v6），dest_is_ipv4 不用
        let _ = dest_is_ipv4;
        linux::LinuxSockOpt { bind_if_index: if_index, ..Default::default() }
            .apply(socket.as_raw_fd())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (socket, if_index, dest_is_ipv4);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "bind socket to interface not supported on this platform",
        ))
    }
}

/// 把 [`SocketOptions`] 应用到入站**已接受连接**。对应 Go `applyInboundSocketOptions`
/// 的跨平台通用部分（sockopt_linux.go:115-232）。
///
/// 与 [`apply_outbound_socket_options`] 的差异：
/// 1. 不设置 TFO（Go inbound TCP_FASTOPEN 是监听 socket 上的 backlog 设置，必须 在 listen()
///    之前；本函数作用于 accept 出的连接，TFO 在该层无效）——见
///    [`crate::system_listener::DefaultListener::bind`]。
/// 2. 入站连接默认禁用 keepalive（Go 端 `lc.KeepAlive = -1`，system_listener.go:91）， 仅
///    idle/interval 任一非零时启用（Go system_listener.go:102-109「任一 >0 即 Enable」）。
/// 3. FreeBSD/Darwin inbound 走相同平台 `apply` 但 `inbound=true`（Darwin 决定 TFO SERVER 位 vs
///    CLIENT 位）；FreeBSD TFO 出站 clamp 1、入站原值（sockopt_freebsd.go:136-138）。
pub fn apply_inbound_socket_options(socket: &Socket, opts: &SocketOptions) -> std::io::Result<()> {
    socket.set_nodelay(opts.tcp_nodelay)?;
    if opts.ipv6_only {
        socket.set_only_v6(true)?;
    }
    set_keepalive_config(socket, opts)?;
    // SO_RCVBUF：显式 `receiveBufferSize` 优先；缺省两平台均**不设置**
    // （bd r5j96，见 `TCP_RCVBUF_DEFAULT`）——交 OS autotune；0 = 不下 setsockopt。
    // bd u91se 预算闸：入站 socket 同样占每连接预算（96MB 分账按连接计）⇒ 显式值
    // 过同一上限判定（超限 ⇒ Err；缺省 0 = 不碰 socket）。
    check_explicit_receive_buffer_size(opts)?;
    let rcvbuf =
        if opts.receive_buffer_size > 0 { opts.receive_buffer_size } else { TCP_RCVBUF_DEFAULT };
    if rcvbuf > 0 {
        socket.set_recv_buffer_size(rcvbuf as usize)?;
        // bd unpg5：下发后回读，内核钳制可见（WARN 带实际值；只观测不改行为）。
        warn_if_rcvbuf_clamped(rcvbuf, socket.recv_buffer_size());
    }

    #[cfg(target_os = "linux")]
    {
        let fd = socket.as_raw_fd();
        // accept 出的连接可设 tproxy/mark/bind_if_index；tproxy 在 Linux 上对 accepted
        // connection 仍生效（sockopt_linux.go:211-215 不区分方向）。
        linux::LinuxSockOpt {
            tcp_fast_open: 0,  // inbound TFO backlog 走 listener 层，不在这里设
            reuse_port: false, // REUSEPORT 仅监听 socket 相关，accept 后无意义
            tproxy: opts.tproxy,
            tcp_congestion: opts.tcp_congestion.clone(),
            inbound: true,
            mark: opts.mark,
            bind_if_index: opts.bind_if_index,
            tcp_window_clamp: opts.tcp_window_clamp,
            tcp_user_timeout: opts.tcp_user_timeout,
            tcp_max_seg: opts.tcp_max_seg,
        }
        .apply(fd)?;
    }

    #[cfg(target_os = "freebsd")]
    {
        let fd = socket.as_raw_fd();
        freebsd::FreebsdSockOpt {
            tcp_fast_open: if opts.tcp_fast_open { 1 } else { -1 },
            reuse_port: false,
            mark: opts.mark,
            inbound: true,
        }
        .apply(fd)?;
    }

    #[cfg(target_os = "macos")]
    {
        let fd = socket.as_raw_fd();
        darwin::DarwinSockOpt {
            tcp_fast_open: if opts.tcp_fast_open { 1 } else { 0 },
            reuse_port: false, // 同 Linux
            bind_if_index: opts.bind_if_index,
            is_ipv6: false,
            tcp_keepalive_idle: opts.tcp_keepalive_idle.as_secs() as u32,
            tcp_keepalive_interval: opts.tcp_keepalive_interval.as_secs() as u32,
            inbound: true,
        }
        .apply(fd)?;
    }

    #[cfg(target_os = "windows")]
    {
        let s = socket.as_raw_socket();
        windows::WindowsSockOpt {
            tcp_fast_open: if opts.tcp_fast_open { 1 } else { -1 },
            bind_if_index: 0, // inbound 不绑接口
            is_ipv4: true,
        }
        .apply(s)?;
    }

    // CustomSockopt：Linux/Darwin/Windows 应用，FreeBSD 无（Go 各平台文件差异）。
    #[cfg(not(target_os = "freebsd"))]
    apply_custom_sockopt(socket, opts)?;
    Ok(())
}

/// Go quic-go `wrapConn` 的 socket 缓冲默认下限。对应 apernet/quic-go
/// `internal/protocol/params.go:5-9`（Xray fork v0.61.1）：`DesiredReceiveBufferSize`
/// 与 `DesiredSendBufferSize` 同为 8MB。Go 侧在每个 QUIC UDP socket 上自动应用
/// （`sys_conn.go:51-53`），Rust quinn-udp 无对应行为——本常量是 [`bind_udp_endpoint`]
/// 默认路径的 parity 下限。**pub 是为了登记簿交叉断言**（`xray-core`
/// `memory_budget.rs` 的 socket 项必须与本常量同步，bd u91se ④ / lidaf ①）。
pub const QUIC_UDP_MIN_BUFFER: usize = 8 << 20;

/// QUIC 系 UDP 端点 socket 创建：族匹配的 DGRAM socket + 缓冲调谐 + bind。
///
/// 对应 Go `transport/internet/quic` 拨号/监听前的 socket 工厂位（Go 侧缓冲由
/// quic-go `wrapConn` 自动处理）。缓冲语义（对齐 PM 拍板方案 C）：
///
/// 1. `receive_buffer_size` / `send_buffer_size` 显式 `> 0`：直接设置（优先于默认 下限；失败仅
///    `warn` 不阻断——超过 `rmem_max`/`wmem_max` 的值内核静默钳制，
///    缓冲是优化非正确性需求，硬错反而害配置可移植性）。
/// 2. 显式值缺省（`0`）：Go `wrapConn` 下限语义——回读当前值，≥8MB 不动（只升不降）， <8MB 提到
///    8MB；Linux 上 setsockopt 失败（EPERM 等）再试 `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE`（需
///    CAP_NET_ADMIN，对齐 Go `forceSetReceiveBuffer`）； 仍失败仅 `warn`。
///
/// 返回的 socket 已设 nonblocking（quinn `wrap_udp_socket` 要求）并完成 bind。
/// IPv6 地址默认关 `IPV6_V6ONLY`（dual-stack，对齐 quinn `Endpoint::client`
/// endpoint.rs:77-78 与 std::net UDP 行为）；`opts.ipv6_only` 显式 `true` 时反之。
///
/// # Errors
///
/// socket 创建 / bind 失败照常传播（硬错）；缓冲设置失败不传播（见上）。
/// **显式缓冲走三档裁决**（bd u91se / PM 终裁 2026-11-05，与 TCP 显式接收缓冲同口径，
/// 判定细节见 `check_explicit_udp_buffer_size`）：≤ 4 MiB 免确认直接生效；4 MiB < v ≤
/// 64 MiB 需 `XRAY_ALLOW_LARGE_RCVBUF=1` 确认；未确认 / > 64 MiB 恒拒 ⇒ 传播
/// `InvalidInput`（fail-visible，拒绑，不静默钳制）。
pub fn bind_udp_endpoint(
    addr: std::net::SocketAddr,
    opts: &SocketOptions,
) -> std::io::Result<std::net::UdpSocket> {
    let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    let v6only = addr.is_ipv6() && opts.ipv6_only;
    // ipv6Only 设置失败不得硬失败（Windows 上 IPv6-only 的 set_only_v6 失败较
    // 常见），但必须留痕：失败即回退 OS 默认 dual-stack，与配置意图相反（bd
    // u0pe2 ②，同函数其它 setsockopt 失败均有 warn）。endpoint 创建频率远低于
    // 逐包，逐次 warn + 累计计数即可。
    if let Err(e) = sock.set_only_v6(v6only) {
        static V6ONLY_SET_FAILS: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let n = V6ONLY_SET_FAILS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        crate::hot_log!(
            tracing::Level::WARN,
            "fails={n} error={e} set_only_v6({v6only}) failed on UDP endpoint {addr}, ipv6Only may not take effect"
        );
    }
    tune_udp_buffer(&sock, opts.receive_buffer_size, UdpBufDir::Recv)?;
    tune_udp_buffer(&sock, opts.send_buffer_size, UdpBufDir::Send)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    let std_sock = std::net::UdpSocket::from(sock);
    // Windows：QUIC endpoint 也是 UDP socket——Go netFD.init 对**全部** UDP 关
    // ICMP-unreachable 上报（bd d597w）；fail-open 同 [`crate::udp::bind_udp_no_connreset`]。
    crate::udp::disable_icmp_unreachable_report(&std_sock);
    Ok(std_sock)
}

/// 缓冲调谐方向（SO_RCVBUF / SO_SNDBUF 两分支逻辑对称，仅常量不同）。
#[derive(Clone, Copy, Debug)]
enum UdpBufDir {
    Recv,
    Send,
}

impl UdpBufDir {
    fn get(self, sock: &Socket) -> std::io::Result<usize> {
        match self {
            Self::Recv => sock.recv_buffer_size(),
            Self::Send => sock.send_buffer_size(),
        }
    }

    fn set(self, sock: &Socket, bytes: usize) -> std::io::Result<()> {
        match self {
            Self::Recv => sock.set_recv_buffer_size(bytes),
            Self::Send => sock.set_send_buffer_size(bytes),
        }
    }

    /// Linux `SO_RCVBUFFORCE`（33）/ `SO_SNDBUFFORCE`（7）raw setsockopt。
    /// 对齐 Go `sys_conn_buffers_linux.go::forceSetReceiveBuffer`。
    #[cfg(target_os = "linux")]
    fn force(self, sock: &Socket, bytes: usize) -> std::io::Result<()> {
        let opt = match self {
            Self::Recv => libc::SO_RCVBUFFORCE,
            Self::Send => libc::SO_SNDBUFFORCE,
        };
        let v = libc::c_int::try_from(bytes)
            .map_err(|_| std::io::Error::other("buffer size overflows c_int"))?;
        // SAFETY: sock 为存活 socket 引用（as_raw_fd），&v 为栈上 c_int
        let r = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                &v as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
}

/// 单方向缓冲调谐：显式值优先直接设置；缺省走 Go `wrapConn` 下限语义。
///
/// **显式值走三档裁决**（bd u91se / PM 终裁 2026-11-05）：≤ 4 MiB 免确认直接生效；
/// 4 MiB < v ≤ [`MAX_EXPLICIT_UDP_BUFFER_SIZE`]（64 MiB 硬顶）需
/// `XRAY_ALLOW_LARGE_RCVBUF=1` 确认，未确认 ⇒ **Err（fail-visible，拒绑）**；
/// 超 64 MiB 恒拒——**禁静默钳制**，档位不符一律显式报错（不让运维「配了 16 MB
/// 实际生效值对不上账」）。判定用**用户设定值**（不用回读值）：Linux 受
/// `net.core.rmem_max` / `wmem_max` 静默钳制时回读远小于设定值，但用户填 16 MB
/// 就是 16 MB 的语义。
///
/// **缺省（0）不动**：走 Go quic-go `wrapConn` 的 8 MB parity 下限
/// （[`QUIC_UDP_MIN_BUFFER`]，PM 裁决保留），不受本闸约束。
fn tune_udp_buffer(sock: &Socket, explicit: i32, dir: UdpBufDir) -> std::io::Result<()> {
    if explicit > 0 {
        check_explicit_udp_buffer_size(explicit, dir)?;
        if let Err(e) = dir.set(sock, explicit as usize) {
            crate::LOG.warn(format!("dir={dir:?} explicit={explicit} UDP buffer setsockopt failed (kernel may clamp): {e}"));
        } else {
            // bd unpg5 / wpa3o：显式值下发后回读（钳制可见性，WARN 带实际值）。
            // Recv 受 rmem_max、Send 受 wmem_max 静默钳制（Linux stock 208KB 量级，
            // setsockopt 恒成功 ⇒ 只有回读能见）。
            match dir {
                UdpBufDir::Recv => warn_if_rcvbuf_clamped(explicit, dir.get(sock)),
                UdpBufDir::Send => warn_if_sndbuf_clamped(explicit, dir.get(sock)),
            }
        }
        return Ok(());
    }
    // 下限语义：当前值已达标则不动（只升不降）。
    if matches!(dir.get(sock), Ok(cur) if cur >= QUIC_UDP_MIN_BUFFER) {
        return Ok(());
    }
    if dir.set(sock, QUIC_UDP_MIN_BUFFER).is_ok() {
        // bd wpa3o：Linux setsockopt 恒成功但受 rmem_max/wmem_max 静默钳制
        // ⇒ 8MB parity 下限可能未真正达成（quic-go wrapConn 语义），回读可见。
        match dir {
            UdpBufDir::Recv => warn_if_rcvbuf_clamped(QUIC_UDP_MIN_BUFFER as i32, dir.get(sock)),
            UdpBufDir::Send => warn_if_sndbuf_clamped(QUIC_UDP_MIN_BUFFER as i32, dir.get(sock)),
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if dir.force(sock, QUIC_UDP_MIN_BUFFER).is_ok() {
        return Ok(());
    }
    crate::LOG.warn(format!(
        "dir={dir:?} failed to raise UDP socket buffer to {QUIC_UDP_MIN_BUFFER} bytes (need CAP_NET_ADMIN for FORCE on Linux); consider net.core.rmem_max/wmem_max"
    ));
    Ok(())
}

/// UDP/QUIC 端点**显式**缓冲上限（SO_RCVBUF / SO_SNDBUF 各向，字节）。
///
/// 与 TCP 显式接收缓冲**同口径**（[`SO_RCVBUF_FREE_TIER_MAX`] 免确认档 +
/// [`SO_RCVBUF_HARD_MAX`] 硬上限 + [`ALLOW_LARGE_RCVBUF_ENV`] 确认开关）：同一笔
/// 96 MB 整机预算里 pipe 与 socket 不重复计账。
///
/// **只约束显式值**（用户显式配置的 `receiveBufferSize`/`sendBufferSize`）；
/// 缺省 8 MB 是 Go quic-go `wrapConn` parity 下限（`QUIC_UDP_MIN_BUFFER`），
/// PM 裁决保留、不受本闸约束。
pub const MAX_EXPLICIT_UDP_BUFFER_SIZE: usize = SO_RCVBUF_HARD_MAX;

/// 显式 UDP 缓冲值预算判定（recv/send 各向；`confirmed` 可注入供测试）。
///
/// 三档口径与 TCP 显式接收缓冲**同**（PM 终裁）：`≤ 4 MiB` 免确认；`4 MiB < v ≤
/// 64 MiB` 需确认开关（[`ALLOW_LARGE_RCVBUF_ENV`]）；`> 64 MiB` 恒拒。以**用户设定
/// 值**判定（不用回读值）。**缺省（0）不判定**——缺省 8 MB 是 Go quic-go
/// `wrapConn` parity 下限（PM 裁决保留）。
fn check_explicit_udp_buffer_size_with(
    explicit: i32,
    dir: UdpBufDir,
    confirmed: bool,
) -> std::io::Result<()> {
    if explicit <= 0 {
        // 缺省 = 走 Go quic-go 8 MB parity 下限，不受本闸约束。
        return Ok(());
    }
    let requested = explicit as usize;
    let key = match dir {
        UdpBufDir::Recv => "receiveBufferSize",
        UdpBufDir::Send => "sendBufferSize",
    };
    if requested > SO_RCVBUF_HARD_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socketSettings.{key}={requested} exceeds hard cap {SO_RCVBUF_HARD_MAX} bytes \
                 (64 MiB per-connection hard limit; see docs/guide-highrtt-sockopt.md §96-98)"
            ),
        ));
    }
    if requested > SO_RCVBUF_FREE_TIER_MAX && !confirmed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socketSettings.{key}={requested} exceeds free tier {SO_RCVBUF_FREE_TIER_MAX} \
                 bytes and requires explicit confirmation: set {ALLOW_LARGE_RCVBUF_ENV}=1 \
                 (kernel books 2x per socket => {} bytes; total = concurrent_conns × 2 × {requested}; \
                 see docs/guide-highrtt-sockopt.md §96-98)",
                requested * 2
            ),
        ));
    }
    Ok(())
}

/// 显式 UDP 缓冲值预算判定（公开口：读进程级确认开关）。
fn check_explicit_udp_buffer_size(explicit: i32, dir: UdpBufDir) -> std::io::Result<()> {
    check_explicit_udp_buffer_size_with(explicit, dir, large_rcvbuf_confirmed())
}

/// 应用 [`SocketOptions::custom_sockopt`]。对应 Go 各平台 apply*SocketOptions 的
/// custom 循环（sockopt_linux.go:66-102/172-208、sockopt_windows.go:84-118/145-179、
/// sockopt_darwin.go:152-188/248-284；sockopt_freebsd.go 无此循环，调用点已 cfg 门控）。
///
/// - `system` 过滤：非空且 ≠ 当前 OS 跳过（`std::env::consts::OS` ≡ `runtime.GOOS`）。
/// - `network` 前缀过滤（Go `strings.HasPrefix`）：Go 调用层只产生 "tcp"/"udp" 两族 （net.Dial
///   network），此处按 socket 类型等价推导；"tcp" 前缀天然覆盖 tcp4/tcp6。
/// - `opt` 为空报 "No opt!"；Atoi 失败静默取 0（Go `opt, _ = strconv.Atoi` 同款）。
/// - `type`：`"int"` 全平台 / `"str"` Windows 报错不支持（Go :113）/ 其他值报 "unknown
///   CustomSockopt type"。
fn apply_custom_sockopt(socket: &Socket, opts: &SocketOptions) -> std::io::Result<()> {
    if opts.custom_sockopt.is_empty() {
        return Ok(());
    }
    let network =
        if socket.r#type().is_ok_and(|t| t == socket2::Type::DGRAM) { "udp" } else { "tcp" };
    for custom in &opts.custom_sockopt {
        if !custom.system.is_empty() && custom.system != std::env::consts::OS {
            continue;
        }
        if !network.starts_with(custom.network.as_str()) {
            continue;
        }
        if custom.opt.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "No opt!"));
        }
        let opt: i32 = custom.opt.parse().unwrap_or(0);
        let level: i32 = if custom.level.is_empty() {
            0x6 // Go 默认 IPPROTO_TCP
        } else {
            custom.level.parse().unwrap_or(0)
        };
        match custom.r#type.as_str() {
            "int" => {
                let value: i32 = custom.value.parse().unwrap_or(0);
                set_custom_sockopt_int(socket, level, opt, value)?;
            },
            "str" => {
                #[cfg(target_os = "windows")]
                {
                    return Err(std::io::Error::other(
                        "failed to set CustomSockoptString: Str type does not supported on windows",
                    ));
                }
                #[cfg(unix)]
                {
                    let c_val = std::ffi::CString::new(custom.value.as_bytes()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "customSockopt value contains null byte",
                        )
                    })?;
                    set_custom_sockopt_str(socket, level, opt, &c_val)?;
                }
            },
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown CustomSockopt type: {other}"),
                ));
            },
        }
    }
    Ok(())
}

/// CustomSockopt int 值 setsockopt（跨平台）。
fn set_custom_sockopt_int(
    socket: &Socket,
    level: i32,
    opt: i32,
    value: i32,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: setsockopt 对有效 fd 设置整数选项；内核验证 level/opt 组合，
        // 指针指向栈上 i32，同步调用不保留指针。
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level as libc::c_int,
                opt as libc::c_int,
                &value as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        windows::setsockopt_int(socket.as_raw_socket() as usize, level, opt, value)
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (socket, level, opt, value);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "custom sockopt: unsupported platform",
        ))
    }
}

#[cfg(unix)]
/// CustomSockopt str 值 setsockopt（unix；Go `syscall.SetsockoptString` 同形，
/// 按字节写入不含 NUL 终止符）。
fn set_custom_sockopt_str(
    socket: &Socket,
    level: i32,
    opt: i32,
    value: &std::ffi::CStr,
) -> std::io::Result<()> {
    // SAFETY: setsockopt 对有效 fd 写入 CStr 字节；指针生命周期覆盖同步调用。
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level as libc::c_int,
            opt as libc::c_int,
            value.as_ptr() as *const libc::c_void,
            value.to_bytes().len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
/// Go 1.23 `net.KeepAliveConfig` 未配置字段（`-1`）的默认物化值
/// （Go net 文档：Idle/Interval 缺省 15s；Windows `SIO_KEEPALIVE_VALS` 要求显式值）。
pub(crate) const DEFAULT_KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
/// 同上，Interval 缺省 15s。
#[cfg(windows)]
pub(crate) const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// 应用 TCP keepalive 配置。对应 Go `net.KeepAliveConfig` 语义
/// （system_listener.go:96-109 / system_dialer.go:89-110）：
///
/// - `idle` 与 `interval` 均为 0（Go `Enable: false`）：不动 `SO_KEEPALIVE`（默认关）。
/// - 任一非零（Go「任一 >0 即 Enable」）：设 `SO_KEEPALIVE=1`；未配置的字段用 OS 默认——unix
///   上跳过对应 setsockopt（Linux 内核默认，对齐 Go `Idle: -1`）； Windows 上 `SIO_KEEPALIVE_VALS`
///   必须显式给值，物化为 Go 缺省 15s。
///
/// 与 Go 的差异：Go 的 `Count`（`TCP_KEEPCNT`）Xray 从不配置（恒 `-1` 用系统默认），
/// 此处同样不设置。
pub(crate) fn set_keepalive_config(socket: &Socket, opts: &SocketOptions) -> std::io::Result<()> {
    let idle = opts.tcp_keepalive_idle;
    let interval = opts.tcp_keepalive_interval;
    if idle.is_zero() && interval.is_zero() {
        return Ok(());
    }
    let mut ka = socket2::TcpKeepalive::new();
    if !idle.is_zero() {
        ka = ka.with_time(idle);
    }
    if !interval.is_zero() {
        ka = ka.with_interval(interval);
    }
    // Windows：`SIO_KEEPALIVE_VALS` 的 time/interval 均不可为 0（socket2 会把
    // `None` 序列化为 0ms），未配置字段物化 Go 缺省 15s。
    #[cfg(windows)]
    let ka = {
        let mut ka = ka;
        if idle.is_zero() {
            ka = ka.with_time(DEFAULT_KEEPALIVE_IDLE);
        }
        if interval.is_zero() {
            ka = ka.with_interval(DEFAULT_KEEPALIVE_INTERVAL);
        }
        ka
    };
    socket.set_tcp_keepalive(&ka)
}

/// 尝试启用 MPTCP（Linux `TCP_MPTCP=1`）。对应 Go `SetMultipathTCP(true)`
/// （system_listener.go:110-112）。
///
/// 必须在 `listen()` 之前对监听 socket 调用。内核不支持（`ENOPROTOOPT`）时
/// 返回 Err，调用方按 Go 行为记录后静默回退普通 TCP。
#[cfg(target_os = "linux")]
/// Linux UAPI `TCP_MPTCP`（include/uapi/linux/tcp.h，值 30）。libc crate 未导出，
/// 与 Go x/sys/unix 一样本地固定。
const TCP_MPTCP: libc::c_int = 30;

#[cfg(target_os = "linux")]
pub(crate) fn try_set_mptcp(socket: &Socket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: 对已创建 socket fd 设置整数选项；fd 由 socket2 Socket 持有，生命周期覆盖调用。
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_MPTCP,
            &1i32 as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// 获取被 iptables REDIRECT 的 TCP 连接的原始目标地址。
/// 对应 Go `transport/internet/sockopt_linux.go::GetOriginalDest`。
///
/// 仅在 Linux 上有效。其他平台返回 `Unsupported` 错误。
/// 需要 root 或 CAP_NET_ADMIN。
pub fn get_original_dst(_fd: i32) -> std::io::Result<std::net::SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        linux::get_original_dst(_fd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "SO_ORIGINAL_DST is Linux-only"))
    }
}

/// 启用 IP_RECVORIGDSTADDR，用于 UDP TProxy 获取原始目标地址。
///
/// 仅在 Linux 上有效。其他平台返回 `Unsupported` 错误。
pub fn set_ip_recvorigdstaddr(_fd: i32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::set_ip_recvorigdstaddr(_fd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "IP_RECVORIGDSTADDR is Linux-only",
        ))
    }
}
/// 把接口名解析为系统 `if_index`。对应 Go `net.InterfaceByName(name).Index`
/// （transport/internet/sockopt_*.go 多处共用；ucad 票）。
///
/// Go 端在每个平台 `apply*SocketOptions` 内调 `InterfaceByName`；失败时
/// `errors.New("failed to get interface ...")`.Base(err)` 启动期硬拒。
/// Rust 端提前到 JSON 解析阶段（dialer.rs:246）以一次性解析、避免在
/// accept/connect 高频路径上 syscall。
#[cfg(unix)]
pub fn resolve_interface_index(name: &str) -> std::io::Result<u32> {
    // libc::if_nametoindex 跨 unix 平台（Linux/Darwin/FreeBSD），对齐 Go
    // `net.InterfaceByName` 的常见实现。0 表示查找失败。
    // SAFETY: name 为 NUL 终止 C 串，libc 契约返回接口索引或 0
    let idx = unsafe { libc::if_nametoindex(name.as_ptr() as *const libc::c_char) };
    if idx == 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface '{name}' not found"),
        ))
    } else {
        Ok(idx)
    }
}

/// Windows 平台 placeholder：当前通过 `customSockopt` 走 IP_UNICAST_IF 路径，
/// 真实名字解析（GetAdaptersAddresses）后续 batch 接入。
#[cfg(not(unix))]
pub fn resolve_interface_index(name: &str) -> std::io::Result<u32> {
    let _ = name;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "interface name → index resolution not yet implemented on Windows; \
         use raw interface index in customSockopt or unicastInterface workaround",
    ))
}

#[cfg(test)]
mod tests {
    // clippy 的 print_stderr 检查不认 `#[cfg(test)]` 模块里被 `#[cfg(target_os)]`
    // 再门一道的函数（Linux CI 才编译），skip 提示会被当成库代码的 eprintln 报错。
    #![allow(clippy::print_stderr)]

    use tokio::net::TcpListener;

    use super::*;

    /// 最小 tracing 捕获订阅者（测试内本地件；`xray_frame::contract_assert::
    /// CaptureSubscriber` 无公开读数口，形状照抄其 `CaptureVisitor`）——断言
    /// `crate::LOG` 发出的 WARN 文案（bd unpg5 回读可见性验收）。
    #[derive(Clone, Default)]
    struct WarnCapture {
        messages: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    struct WarnVisitor {
        message: String,
    }

    impl tracing::field::Visit for WarnVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.message = value.to_owned();
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            }
        }
    }

    impl tracing::Subscriber for WarnCapture {
        fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = WarnVisitor { message: String::new() };
            event.record(&mut visitor);
            self.messages
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(visitor.message);
        }
    }

    impl WarnCapture {
        fn snapshot(&self) -> Vec<String> {
            self.messages.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
        }
    }

    /// 平台对照值（bd r5j96 判据核心）：新建一个 socket，按 `bytes` 显式
    /// `setsockopt(SO_RCVBUF, bytes)`（`bytes == 0` = **不下发** = 纯内核缺省），
    /// 回读其 SO_RCVBUF。
    ///
    /// 为什么必须用「对照差值」而不是绝对阈值：SO_RCVBUF 的内核记账口径两平台
    /// 不同——**Windows 原样回显**（请求 4MB → 回读 4194304）；**Linux 静默钳到
    /// `net.core.rmem_max` 并按内核记账翻倍**（请求 4MB → 回读 425984 =
    /// 2 × 212992）。故「回读 < 4MB」这类绝对断言在 Linux 上**恒真**（钳制后的
    /// 425984 仍 < 4194304），根本区分不出「我们没设」与「我们设了 4MB 但被钳了」。
    /// 只有与「同平台、同数值、显式 setsockopt」的对照值比差值才钉得住行为。
    ///
    /// 未连接 socket：SO_RCVBUF 是 socket 层选项，与连接状态无关（两平台实测
    /// 连接前后回读相同：Windows 65536 / Linux 131072）。
    fn rcvbuf_control_unconnected(bytes: usize) -> usize {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        if bytes > 0 {
            sock.set_recv_buffer_size(bytes).unwrap();
        }
        sock.recv_buffer_size().unwrap()
    }

    /// 同 [`rcvbuf_control_unconnected`]，但 socket **已连接** `addr`——用于与
    /// 「已连接的被测 socket」同形态对照（避免拿未连接值去比已连接值）。
    fn rcvbuf_control_connected(addr: std::net::SocketAddr, bytes: usize) -> usize {
        let sock = socket2::Socket::from(std::net::TcpStream::connect(addr).unwrap());
        if bytes > 0 {
            sock.set_recv_buffer_size(bytes).unwrap();
        }
        sock.recv_buffer_size().unwrap()
    }

    /// AI7：dial_client_tcp（transport 裸拨号统一入口，ws/splithttp/grpc 等
    /// transport 自持 TCP 路径）必须过 DialerController——Go 全局语义是
    /// controllers 挂在**所有**系统拨号上，漏接 = TUN 模式下经这些传输到
    /// 代理出站的连接自绕回 TUN。魔数端口过滤隔离并行测试（AI4 同款）。
    #[tokio::test]
    async fn dial_client_tcp_runs_controllers() {
        static SAW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        const PROBE_PORT: u16 = 59997;
        crate::system_dialer::register_dialer_controller(std::sync::Arc::new(
            |_socket: &Socket, dest: &std::net::SocketAddr| {
                if dest.port() == PROBE_PORT {
                    SAW.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(())
            },
        ))
        .unwrap();
        // 无 listener：connect 可能 refused，但 controller 在 connect 前已被调用
        //（断言对象是「controller 跑过该路径」，与 system_dialer.rs AI4 探针同款）。
        let _ = dial_client_tcp(("127.0.0.1", PROBE_PORT)).await;
        assert!(
            SAW.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "controller 未被 dial_client_tcp 调用"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn client_dial_times_out_against_blackhole_address() {
        // bd cjwc G1：TEST-NET-1（RFC 5737，保证无监听且不该路由）在带默认路由
        // 的环境 SYN 出网关后被丢弃 → connect 挂起；暂停时钟自动推进 16s 触发
        // TimedOut（真实耗时毫秒级）。修复前该调用永久 Pending。
        let err =
            dial_client_tcp((std::net::IpAddr::from([192, 0, 2, 1]), 1u16)).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "got: {err}");
    }

    /// bd r5j96：缺省**不设置** SO_RCVBUF（两平台）——helper 是空操作，接收窗交
    /// OS autotune（Windows 关掉 autotune 会把窗钉死；Linux 会被 rmem_max 钳到
    /// 208KB 并锁 autotune，WSL netem 实测 0.80 vs 7.43MB/s）。
    ///
    /// 判据（对照差值，见 [`rcvbuf_control_connected`]）：
    /// 1. **同一 socket 应用前后回读相等** ⇒ 根本没下发 setsockopt；
    /// 2. 回读 == 「同平台未下发 setsockopt」的对照值 ⇒ 落在内核缺省量级；
    /// 3. 回读 != 「同平台显式设 4MB」的对照值 ⇒ 排除「设了 4MB 但被内核钳到
    ///    小值仍看着像缺省」这种**在 Linux 上会蒙混过关**的假象 （Linux 显式 4MB → 425984，远小于
    ///    4MB，单看「< 4MB」无法区分）。
    #[tokio::test]
    async fn client_dial_rcvbuf_does_not_touch_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let before = socket2::SockRef::from(&conn).recv_buffer_size().unwrap();
        apply_client_dial_rcvbuf(&conn).unwrap();
        let after = socket2::SockRef::from(&conn).recv_buffer_size().unwrap();
        let _ = listener.accept().await;
        let kernel_default = rcvbuf_control_connected(addr, 0);
        let explicit_4mb = rcvbuf_control_connected(addr, 4 * 1024 * 1024);
        assert_eq!(
            before, after,
            "缺省不得下发 setsockopt(SO_RCVBUF)（bd r5j96）: before={before} after={after}"
        );
        assert_eq!(
            after, kernel_default,
            "缺省回读须等于内核缺省量级（未下发 setsockopt）: after={after} kernel_default={kernel_default}"
        );
        assert_ne!(
            after, explicit_4mb,
            "缺省回读不得等于「显式设 4MB」的对照值（否则说明 4MB 仍被下发）: after={after} explicit_4mb={explicit_4mb}"
        );
    }

    /// Linux：`dial_client_tcp` 在 connect 之前设 TCP_FASTOPEN_CONNECT（回读 1）
    /// 且拨号成功——对 ESTABLISHED socket 设置新内核 EINVAL，故只有 pre-connect
    /// 顺序能既设上又不炸（顺序见 `apply_outbound_socket_options` 测试注释）。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn client_dial_tfo_sets_fastopen_connect_before_connect() {
        use std::os::fd::AsRawFd;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = dial_client_tcp(addr).await.unwrap();
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: 读 fd 栈上 c_int；len 与类型一致。
        let ret = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        let _ = listener.accept().await;
        assert_eq!(ret, 0, "getsockopt(TCP_FASTOPEN_CONNECT) failed");
        assert_eq!(val, 1, "dial_client_tcp 应在 connect 前设 TCP_FASTOPEN_CONNECT");
    }

    #[tokio::test]
    async fn apply_socket_options_on_real_tcp_connection() {
        // 启动一个 TCP listener 拿到 socket fd。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // spawn acceptor
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        // 客户端拨号
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let socket = socket2::Socket::from(stream.into_std().unwrap());
        // 应用前回读（内核缺省）——用于证明「缺省不下发 setsockopt」。
        let before = socket.recv_buffer_size().unwrap();
        let opts = SocketOptions::default();
        let result = apply_outbound_socket_options(&socket, &opts, None);
        assert!(result.is_ok(), "apply_outbound_socket_options failed: {result:?}");
        // TCP_NODELAY 已设置
        assert_eq!(socket.nodelay().unwrap(), opts.tcp_nodelay);
        // bd r5j96：缺省**不设置** SO_RCVBUF（两平台）——回读须与应用前一致
        // （内核缺省量级）。若下发 setsockopt：Linux 回读变 2×rmem_max
        // （stock 425984）、Windows 变设置值本身，必然与 before 不同。
        let after = socket.recv_buffer_size().unwrap();
        assert_eq!(
            before, after,
            "缺省出站不得下发 setsockopt(SO_RCVBUF)（bd r5j96）: before={before} after={after}"
        );
        // 对照差值：显式 4MB 的回读（Windows 4194304 / Linux 425984）与缺省回读
        // 必须不同——单看「< 4MB」在 Linux 上恒真（425984 < 4MB），无法证明
        // 「没下发 4MB」，必须与对照值比。
        let kernel_default = rcvbuf_control_connected(addr, 0);
        let explicit_4mb = rcvbuf_control_connected(addr, 4 * 1024 * 1024);
        assert_eq!(
            after, kernel_default,
            "缺省出站回读须等于内核缺省量级: after={after} kernel_default={kernel_default}"
        );
        assert_ne!(
            after, explicit_4mb,
            "缺省出站回读不得等于「显式设 4MB」的对照值: after={after} explicit_4mb={explicit_4mb}"
        );
        drop(socket);
        accept_task.await.unwrap();
    }
    /// 显式 `sockopt.receiveBufferSize` 仍照旧生效（bd r5j96 显式路径不回归）。
    ///
    /// 判据：**回读 == 同平台「显式设 1MB」的对照值**（Windows 原样回显
    /// 1048576；Linux 被 rmem_max 钳到 425984），且 **!= 内核缺省对照值**
    /// ——后者证明该值确实被下发（不是被常量 0 吞掉）。
    #[test]
    fn outbound_explicit_receive_buffer_size_wins_over_default() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = std::net::TcpStream::connect(addr).unwrap();
        let socket = socket2::Socket::from(stream);
        let before = socket.recv_buffer_size().unwrap();
        let opts = SocketOptions { receive_buffer_size: 1024 * 1024, ..SocketOptions::default() };
        apply_outbound_socket_options(&socket, &opts, None).unwrap();
        let got = socket.recv_buffer_size().unwrap();
        let kernel_default = rcvbuf_control_connected(addr, 0);
        let explicit_1mb = rcvbuf_control_connected(addr, 1024 * 1024);
        assert_eq!(
            before, kernel_default,
            "前置：连接 socket 的缺省回读应等于内核缺省对照值: before={before} kernel_default={kernel_default}"
        );
        assert_eq!(
            got, explicit_1mb,
            "显式 1MB 必须按平台记账口径生效（Windows 回显 1MB；Linux 回读 rmem_max 钳制值）: got={got} explicit_1mb={explicit_1mb}"
        );
        assert_ne!(
            got, kernel_default,
            "显式 1MB 不得被常量 0 吞掉（回读须区别于内核缺省）: got={got} kernel_default={kernel_default}"
        );
    }
    #[test]
    fn default_socket_options_match_chrome_defaults() {
        let opts = SocketOptions::default();
        assert!(opts.tcp_nodelay);
        assert_eq!(opts.tcp_keepalive_idle, Duration::from_secs(45));
        assert_eq!(opts.tcp_keepalive_interval, Duration::from_secs(45));
        assert!(!opts.tcp_fast_open, "TFO default should be false");
        assert!(!opts.tcp_mptcp, "MPTCP default should be false");
        assert!(!opts.tproxy, "tproxy default should be false");
        assert!(!opts.reuse_port, "reuse_port default should be false");
        assert!(opts.tcp_congestion.is_none(), "tcp_congestion default should be None");
    }

    /// TFO 启用 + TCP_CONGESTION + tproxy：真实 TCP socket 上跑通（应成功或被
    /// 权限门控跳过）。Windows 不支持 IP_TRANSPARENT/tproxy，本测试在 unix 跑。
    #[cfg(unix)]
    #[tokio::test]
    async fn apply_socket_options_with_tfo_congestion_tproxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        // 生产语义：先 apply 再 connect。TCP_FASTOPEN_CONNECT 在 ESTABLISHED
        // socket 上新内核（6.8+）返回 EINVAL（CI ubuntu 首跑实证）——socket2
        // 建未连接 socket → apply → connect，对齐 apply_outbound_socket_options
        // 的真实调用顺序（dial 前套选项）。
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        // TFO：TCP_FASTOPEN_CONNECT 为 Linux 4.11+ 专属（macOS 客户端走
        // connectx，setsockopt TCP_FASTOPEN 在客户端 socket 上 EINVAL——CI
        // macos 首跑实证）；TFO 断言段收敛 cfg(target_os = "linux")，macOS
        // 分支只验 congestion + 普通 apply Ok。
        let mut opts = SocketOptions::default();
        #[cfg(target_os = "linux")]
        {
            opts.tcp_fast_open = true;
        }
        // congestion 算法名平台差异（macOS 新版可能移除 reno）：统一 cubic，
        // 内核不可用时 ENOENT 容忍跳过。
        opts.tcp_congestion = Some("cubic".to_string());
        // tproxy 需要 root/CAP_NET_ADMIN，CI 上不启用。
        opts.tproxy = false;
        opts.reuse_port = false;
        let res = apply_outbound_socket_options(&socket, &opts, None);
        if let Err(e) = &res {
            if e.raw_os_error() == Some(libc::ENOENT) {
                eprintln!("skip: congestion algorithm unavailable: {e}");
                return;
            }
        }
        res.expect("apply (tfo+congestion) should Ok");
        socket.connect(&socket2::SockAddr::from(addr)).expect("connect after apply");
        // getsockopt 回读 TCP_FASTOPEN_CONNECT（Linux 30）：
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let mut val: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: 读 fd 栈上 c_int；len 与类型一致。
            let ret = unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_TCP,
                    libc::TCP_FASTOPEN_CONNECT,
                    &mut val as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(ret, 0, "getsockopt(TCP_FASTOPEN_CONNECT) failed");
            assert_eq!(val, 1, "outbound TFO_CONNECT 应为 1");
        }
        drop(socket);
        accept_task.await.unwrap();
    }

    /// TFO 启用失败路径：先在 IPv6 socket 上尝试 TFO（部分平台不支持）：
    /// 主要是为「失败不被吞」契约做基础验证——Linux/FreeBSD/Darwin 出站 TFO
    /// 调用应成功（sockopt_linux.go:35-37 路径）；Windows 等价测试见其模块。
    #[cfg(unix)]
    #[tokio::test]
    async fn apply_tfo_outbound_does_not_panic_on_default_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        // 同上：未连接 socket → apply → connect（ESTABLISHED 后设
        // TCP_FASTOPEN_CONNECT 新内核 EINVAL，CI ubuntu 首跑实证）。
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        // 同 ①：TFO 断言段收敛 cfg(target_os = "linux")，macOS 分支只验
        // congestion + 普通 apply Ok（cubic，ENOENT 容忍跳过）。
        let mut opts = SocketOptions::default();
        #[cfg(target_os = "linux")]
        {
            opts.tcp_fast_open = true;
        }
        opts.tcp_congestion = Some("cubic".to_string());
        // 关键：必须 Ok，不向调用方传播 EPERM/ENOPROTOOPT（按 Go 语义 setsockopt 失败
        // 会被传播；本测试只验「TFO=1 + 已建立连接」回环内不 EPERM）。
        let res = apply_outbound_socket_options(&socket, &opts, None);
        if let Err(e) = &res {
            if e.raw_os_error() == Some(libc::ENOENT) {
                eprintln!("skip: congestion algorithm unavailable: {e}");
                return;
            }
        }
        res.expect("apply (congestion) should Ok");
        socket.connect(&socket2::SockAddr::from(addr)).expect("connect after apply");
        drop(socket);
        accept_task.await.unwrap();
    }

    /// tproxy 失败路径：在非特权 socket 上 setsockopt(IP_TRANSPARENT) 返回 EPERM，
    /// 当前 impl 选择向上传播 Err（Go `applyOutboundSocketOptions:104-108` 同样
    /// 向上返 err，不静默）。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn apply_tproxy_outbound_returns_err_for_unprivileged() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let socket = socket2::Socket::from(stream.into_std().unwrap());
        let opts = SocketOptions { tproxy: true, ..SocketOptions::default() };
        let res = apply_outbound_socket_options(&socket, &opts, None);
        // CI 无 root：EPERM（操作不允许）；root 环境 Ok。两者均符合 Go 语义。
        if let Err(e) = &res {
            assert_eq!(e.raw_os_error(), Some(libc::EPERM), "非 root 应 EPERM：{e:?}");
        }
        drop(socket);
        accept_task.await.unwrap();
    }
    #[test]
    fn socket_options_is_clone() {
        let opts = SocketOptions::default();
        let cloned = opts.clone();
        assert_eq!(opts, cloned);
    }

    /// KeepAliveConfig 语义（Go system_listener.go:96-109）：idle/interval 任一
    /// 非零即启用 SO_KEEPALIVE；均零则不触碰。真实 TCP 连接上验证。
    #[tokio::test]
    async fn keepalive_config_either_field_enables() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let socket = socket2::Socket::from(stream.into_std().unwrap());

        // interval-only（idle=0）：应启用（旧实现只在 idle!=0 时启用——本修复点）。
        let opts = SocketOptions {
            tcp_keepalive_idle: Duration::ZERO,
            tcp_keepalive_interval: Duration::from_secs(30),
            ..Default::default()
        };
        set_keepalive_config(&socket, &opts).unwrap();
        assert!(socket.keepalive().unwrap(), "interval-only 应启用 SO_KEEPALIVE");

        // 均零：不动 SO_KEEPALIVE（先关掉再验证仍是关）。
        socket.set_keepalive(false).unwrap();
        let opts = SocketOptions {
            tcp_keepalive_idle: Duration::ZERO,
            tcp_keepalive_interval: Duration::ZERO,
            ..Default::default()
        };
        set_keepalive_config(&socket, &opts).unwrap();
        assert!(!socket.keepalive().unwrap(), "未配置不应启用 SO_KEEPALIVE");

        drop(socket);
        accept_task.await.unwrap();
    }

    /// SO_RCVBUF 生效路径（bd o93t）：显式 `receive_buffer_size` 真实 setsockopt
    /// 并回读放大；默认 0 不触碰 socket（回读=内核默认）。未连接 TCP socket 即可
    /// 验证（SO_RCVBUF 是 socket 层选项，与连接状态无关）。
    ///
    /// bd r5j96：缺省两平台均为「不设置」——断言从「回读 ≥ 4MB」改为**对照差值**
    /// （见 [`rcvbuf_control_unconnected`]）：缺省回读须等于「未下发 setsockopt」
    /// 的对照值，且 != 「显式设 4MB」的对照值（Linux 上后者 425984 < 4MB，
    /// 单看绝对阈值无法区分）。
    #[test]
    fn receive_buffer_size_applies_and_default_does_not_set() {
        let make = || {
            socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .unwrap()
        };
        let rcvbuf = |s: &socket2::Socket| s.recv_buffer_size().unwrap();
        let plain = make();
        let default_rcv = rcvbuf(&plain);

        // 1MiB：即使被 Linux `net.core.rmem_max`（默认 208KB）钳制，回读仍须
        // 等于「显式设 1MB」的对照值（Windows 原样 1MB；Linux 425984）。
        let opts = SocketOptions { receive_buffer_size: 1 << 20, ..Default::default() };
        let explicit_1mb = rcvbuf_control_unconnected(1 << 20);
        let tuned = make();
        apply_inbound_socket_options(&tuned, &opts).unwrap();
        assert_eq!(
            rcvbuf(&tuned),
            explicit_1mb,
            "inbound 显式 receiveBufferSize 必须按平台记账口径生效: got={} explicit_1mb={explicit_1mb}",
            rcvbuf(&tuned)
        );

        let out = make();
        apply_outbound_socket_options(&out, &opts, None).unwrap();
        assert_eq!(
            rcvbuf(&out),
            explicit_1mb,
            "outbound 同字段必须生效: got={} explicit_1mb={explicit_1mb}",
            rcvbuf(&out)
        );

        // 默认 0：两平台均**不设置**（bd r5j96）——回读须保持内核缺省量级。
        let explicit_4mb = rcvbuf_control_unconnected(4 << 20);
        let off = make();
        let off_before = rcvbuf(&off);
        apply_inbound_socket_options(&off, &SocketOptions::default()).unwrap();
        assert_eq!(
            off_before,
            rcvbuf(&off),
            "默认 0 inbound 不得下发 setsockopt(SO_RCVBUF)（bd r5j96）"
        );
        let off_out = make();
        let off_out_before = rcvbuf(&off_out);
        apply_outbound_socket_options(&off_out, &SocketOptions::default(), None).unwrap();
        assert_eq!(
            off_out_before,
            rcvbuf(&off_out),
            "默认 0 outbound 不得下发 setsockopt(SO_RCVBUF)（bd r5j96）"
        );
        assert_eq!(
            rcvbuf(&off),
            default_rcv,
            "默认回读须为内核缺省量级: got={} kernel_default={default_rcv}",
            rcvbuf(&off)
        );
        assert_ne!(
            rcvbuf(&off),
            explicit_4mb,
            "默认回读不得等于「显式设 4MB」的对照值（否则说明 4MB 仍被下发）: got={} explicit_4mb={explicit_4mb}",
            rcvbuf(&off)
        );
    }

    // ===== QUIC 系 UDP 端点缓冲（Go quic-go wrapConn parity，PM 拍板方案 C）=====

    /// 裸 UDP socket 的内核默认缓冲（对照基线，不经 helper）。
    fn raw_default_udp_bufs() -> (usize, usize) {
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        (s.recv_buffer_size().unwrap(), s.send_buffer_size().unwrap())
    }

    /// 显式值路径：`receiveBufferSize`/`sendBufferSize` 直接设置并回读放大
    /// （对齐 TCP o93t 测试的相对比较策略——Linux 回读含 ×2 记账与 rmem/wmem_max
    /// 钳制，Windows 回读=原值，绝对值断言不可移植）。
    #[test]
    fn bind_udp_endpoint_explicit_buffers_apply() {
        let (d_recv, d_send) = raw_default_udp_bufs();
        let opts = SocketOptions {
            receive_buffer_size: 1 << 20,
            send_buffer_size: 1 << 20,
            ..Default::default()
        };
        let sock = bind_udp_endpoint("127.0.0.1:0".parse().unwrap(), &opts).unwrap();
        let s2 = socket2::SockRef::from(&sock);
        assert!(
            s2.recv_buffer_size().unwrap() > d_recv,
            "显式 receiveBufferSize 必须放大 SO_RCVBUF: got={} default={d_recv}",
            s2.recv_buffer_size().unwrap()
        );
        assert!(
            s2.send_buffer_size().unwrap() > d_send,
            "显式 sendBufferSize 必须放大 SO_SNDBUF: got={} default={d_send}",
            s2.send_buffer_size().unwrap()
        );
    }

    /// 默认路径（Go wrapConn 下限语义）：bind 成功、回读不低于内核默认（只升不降）。
    /// rmem/wmem_max < 8MB 的机器（CI 默认 208KB）内核会钳制且 FORCE 需 CAP_NET_ADMIN，
    /// 回读可能仍低于 8MB——故只断言不降，不断言达到 8MB。
    #[test]
    fn bind_udp_endpoint_default_raises_floor_only() {
        let (d_recv, d_send) = raw_default_udp_bufs();
        let sock =
            bind_udp_endpoint("127.0.0.1:0".parse().unwrap(), &SocketOptions::default()).unwrap();
        let s2 = socket2::SockRef::from(&sock);
        assert!(s2.recv_buffer_size().unwrap() >= d_recv);
        assert!(s2.send_buffer_size().unwrap() >= d_send);
    }

    /// IPv6 地址可 bind（族匹配 + dual-stack 路径）。
    #[test]
    fn bind_udp_endpoint_ipv6() {
        let sock =
            bind_udp_endpoint("[::1]:0".parse().unwrap(), &SocketOptions::default()).unwrap();
        assert!(sock.local_addr().unwrap().is_ipv6());
    }

    // ===== DomainStrategy / AddressPortStrategy（bd 5y8，Go config.go:13-26）=====

    /// Go strategy 表逐行对照（config.go:13-26）。
    #[test]
    fn domain_strategy_table_matches_go() {
        use DomainStrategy::*;
        assert_eq!(AsIs.strategy_table(), [0, 0, 0]);
        assert_eq!(UseIP.strategy_table(), [1, 0, 0]);
        assert_eq!(UseIPv4.strategy_table(), [1, 4, 0]);
        assert_eq!(UseIPv6.strategy_table(), [1, 6, 0]);
        assert_eq!(UseIPv4v6.strategy_table(), [1, 4, 6]);
        assert_eq!(UseIPv6v4.strategy_table(), [1, 6, 4]);
        assert_eq!(ForceIP.strategy_table(), [2, 0, 0]);
        assert_eq!(ForceIPv4.strategy_table(), [2, 4, 0]);
        assert_eq!(ForceIPv6.strategy_table(), [2, 6, 0]);
        assert_eq!(ForceIPv4v6.strategy_table(), [2, 4, 6]);
        assert_eq!(ForceIPv6v4.strategy_table(), [2, 6, 4]);
    }

    /// Go PreferIP4/PreferIP6 的 both 语义：prefer==0 时两者皆真（config.go:110-116）。
    #[test]
    fn domain_strategy_prefer_includes_both() {
        use DomainStrategy::*;
        // UseIP/ForceIP：prefer=both → 两个 prefer 都为真。
        for s in [UseIP, ForceIP] {
            assert!(s.prefer_ipv4(), "{s:?} prefer both → v4 true");
            assert!(s.prefer_ipv6(), "{s:?} prefer both → v6 true");
        }
        // UseIPv4v6：prefer=4 仅 v4；fallback=6。
        assert!(UseIPv4v6.prefer_ipv4());
        assert!(!UseIPv4v6.prefer_ipv6());
        assert!(UseIPv4v6.has_fallback() && UseIPv4v6.fallback_ipv6());
        // UseIPv6v4：prefer=6 仅 v6；fallback=4。
        assert!(!UseIPv6v4.prefer_ipv4());
        assert!(UseIPv6v4.prefer_ipv6());
        assert!(UseIPv6v4.fallback_ipv4());
        // AsIs：无策略无回退；Force*：force_ip。
        assert!(!AsIs.has_strategy() && !AsIs.has_fallback());
        assert!(ForceIPv4.force_ip() && ForceIPv4v6.force_ip());
        assert!(!UseIPv4.force_ip());
    }

    #[test]
    fn domain_strategy_from_i32_roundtrip_and_fallback() {
        use DomainStrategy::*;
        for (v, s) in [(0, AsIs), (1, UseIP), (5, UseIPv6v4), (10, ForceIPv6v4)] {
            assert_eq!(DomainStrategy::from_i32(v), s);
            assert_eq!(s as i32, v);
        }
        assert_eq!(DomainStrategy::from_i32(99), AsIs);
        assert_eq!(DomainStrategy::from_i32(-1), AsIs);
    }

    /// Go dialer.go:145-172 的覆盖位展开。
    #[test]
    fn address_port_strategy_override_flags() {
        use AddressPortStrategy::*;
        assert_eq!(None.override_flags(), (false, false, false));
        assert_eq!(SrvPortOnly.override_flags(), (true, true, false));
        assert_eq!(SrvAddressOnly.override_flags(), (true, false, true));
        assert_eq!(SrvPortAndAddress.override_flags(), (true, true, true));
        assert_eq!(TxtPortOnly.override_flags(), (false, true, false));
        assert_eq!(TxtAddressOnly.override_flags(), (false, false, true));
        assert_eq!(TxtPortAndAddress.override_flags(), (false, true, true));
        assert_eq!(AddressPortStrategy::from_i32(6), TxtPortAndAddress);
        assert_eq!(AddressPortStrategy::from_i32(7), None);
    }

    #[test]
    fn socket_options_defaults_include_strategies() {
        let opts = SocketOptions::default();
        assert_eq!(opts.domain_strategy, DomainStrategy::AsIs);
        assert_eq!(opts.address_port_strategy, AddressPortStrategy::None);
    }
    /// CustomSockopt 应用：int 类型经真实 setsockopt 生效（TCP_NODELAY=1 回读验证，
    /// 对应 Go custom 循环 sockopt_linux.go:66-102 / windows:84-118；network 前缀
    /// "tcp" 匹配、level 缺省 0x6=IPPROTO_TCP、Atoi 解析）。
    #[tokio::test]
    async fn custom_sockopt_int_applies_on_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let socket = socket2::Socket::from(stream.into_std().unwrap());

        let opts = SocketOptions {
            tcp_nodelay: false, // 先关，custom int 应把它打开
            custom_sockopt: vec![CustomSockopt {
                network: "tcp".to_string(),
                level: "6".to_string(), // IPPROTO_TCP
                opt: "1".to_string(),   // TCP_NODELAY
                value: "1".to_string(),
                r#type: "int".to_string(),
                ..Default::default()
            }],
            ..SocketOptions::default()
        };
        apply_outbound_socket_options(&socket, &opts, None).unwrap();
        assert!(socket.nodelay().unwrap(), "customSockopt int 应已设置 TCP_NODELAY");

        drop(socket);
        accept_task.await.unwrap();
    }

    /// CustomSockopt 过滤与错误路径：system 不匹配跳过（Go LogDebug+continue）、
    /// opt 缺失报 "No opt!"（sockopt_linux.go:81-82）、未知 type 报错（:98-99）。
    #[tokio::test]
    async fn custom_sockopt_filter_and_error_paths() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let socket = socket2::Socket::from(stream.into_std().unwrap());
        let mut opts = SocketOptions { tcp_nodelay: false, ..SocketOptions::default() };

        // system 不匹配当前 OS → 跳过，不报错、不生效。
        #[cfg(target_os = "windows")]
        let other_os = "linux";
        #[cfg(not(target_os = "windows"))]
        let other_os = "windows";
        opts.custom_sockopt.push(CustomSockopt {
            system: other_os.to_string(),
            network: "tcp".to_string(),
            level: "6".to_string(),
            opt: "1".to_string(),
            value: "1".to_string(),
            r#type: "int".to_string(),
        });
        apply_outbound_socket_options(&socket, &opts, None).unwrap();
        assert!(!socket.nodelay().unwrap(), "system 不匹配应跳过");

        // opt 缺失 → "No opt!"。
        opts.custom_sockopt.clear();
        opts.custom_sockopt.push(CustomSockopt {
            network: "tcp".to_string(),
            value: "1".to_string(),
            r#type: "int".to_string(),
            ..Default::default()
        });
        let err = apply_outbound_socket_options(&socket, &opts, None).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("No opt!"), "应报 No opt!：{err}");

        // 未知 type → "unknown CustomSockopt type"。
        opts.custom_sockopt[0].opt = "1".to_string();
        opts.custom_sockopt[0].r#type = "bogus".to_string();
        let err = apply_outbound_socket_options(&socket, &opts, None).unwrap_err();
        assert!(err.to_string().contains("unknown CustomSockopt type"), "应报 unknown type：{err}");

        drop(socket);
        accept_task.await.unwrap();
    }

    /// bd u91se：`dial_system` 出站路径（`apply_outbound_socket_options`）与入站路径
    /// （`apply_inbound_socket_options`）的**显式超限 ⇒ Err**（fail-visible，文案点名
    /// 上限值与字段名）；**缺省路径仍不碰 socket**（r5j96，回读 == 内核缺省对照）。
    #[test]
    fn inbound_and_outbound_socket_options_enforce_explicit_buffer_budget() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        let before = socket.recv_buffer_size().unwrap();

        // 缺省：两向都不得下发 setsockopt（回读不变 = 内核缺省对照）。
        let default_opts = SocketOptions::default();
        apply_outbound_socket_options(&socket, &default_opts, None).unwrap();
        assert_eq!(
            socket.recv_buffer_size().unwrap(),
            before,
            "出站缺省不得下发 setsockopt(SO_RCVBUF)（bd r5j96）"
        );
        apply_inbound_socket_options(&socket, &default_opts).unwrap();
        assert_eq!(
            socket.recv_buffer_size().unwrap(),
            before,
            "入站缺省不得下发 setsockopt(SO_RCVBUF)（bd r5j96）"
        );

        // 显式大档（16 MiB，未确认）：出站/入站各 ⇒ Err（InvalidInput，文案点名
        // 确认开关与 2× 记账后果）。
        let over = SocketOptions { receive_buffer_size: 16 * 1024 * 1024, ..Default::default() };
        let err = apply_outbound_socket_options(&socket, &over, None).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(
            msg.contains(ALLOW_LARGE_RCVBUF_ENV),
            "出站错误须点名确认开关 {ALLOW_LARGE_RCVBUF_ENV}：{msg}"
        );
        assert!(msg.contains("receiveBufferSize"), "出站错误须点名字段名：{msg}");
        let err = apply_inbound_socket_options(&socket, &over).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(msg.contains(ALLOW_LARGE_RCVBUF_ENV), "入站错误须点名确认开关：{msg}");
        assert!(msg.contains("receiveBufferSize"), "入站错误须点名字段名：{msg}");
        // 未确认的大档不得 setsockopt（禁静默钳到上限）。
        assert_eq!(
            socket.recv_buffer_size().unwrap(),
            before,
            "超限不得下发 setsockopt（禁静默钳到上限）"
        );
    }

    /// bd u91se 预算闸契约（**三 transport 共用的唯一判定口**；PM 终裁三档）：
    /// - 缺省（0）⇒ 不碰 socket（r5j96：交 OS autotune）；
    /// - 显式 ≤ 4 MiB（免确认档）⇒ setsockopt 生效（回读高于缺省对照）；
    /// - 显式 4 MiB < v ≤ 64 MiB ⇒ **未确认即拒**（文案含开关名 + 2× 记账 + `并发 × 2 × 值`
    ///   后果）；**带确认 ⇒ 生效**；
    /// - 显式 > 64 MiB ⇒ 恒拒（防手滑）。
    ///
    /// 上限判定用**用户设定值**（不用回读值）：Linux 下 setsockopt 受
    /// `net.core.rmem_max` 静默钳制，回读远小于设定值——但用户填 16 MiB 就是
    /// 16 MiB 的语义，回读小不代表没超预算。
    #[tokio::test]
    async fn explicit_receive_buffer_budget_gate() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 缺省：不碰 socket（回读前后一致）。
        let base_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let base = socket2::SockRef::from(&base_sock).recv_buffer_size().unwrap();
        check_explicit_receive_buffer_size(&SocketOptions::default()).unwrap();
        apply_explicit_receive_buffer_size(&base_sock, &SocketOptions::default()).unwrap();
        assert_eq!(
            socket2::SockRef::from(&base_sock).recv_buffer_size().unwrap(),
            base,
            "缺省不得改变 SO_RCVBUF（r5j96：缺省不设）"
        );

        // 档 1：显式 4 MiB（免确认上限）⇒ 生效，回读高于缺省对照。
        let ok_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ok_opts = SocketOptions {
            receive_buffer_size: SO_RCVBUF_FREE_TIER_MAX as i32,
            ..Default::default()
        };
        check_explicit_receive_buffer_size(&ok_opts).unwrap();
        apply_explicit_receive_buffer_size(&ok_sock, &ok_opts).unwrap();
        let ok_read = socket2::SockRef::from(&ok_sock).recv_buffer_size().unwrap();
        assert!(ok_read > base, "显式 4 MiB 必须抬高 SO_RCVBUF 回读：{ok_read} 须高于缺省 {base}");

        // 档 2：4 MiB < v ≤ 64 MiB —— 未确认 ⇒ 拒（文案点名值/开关名/2× 记账/
        // 并发账面公式）；带确认 ⇒ 生效。
        let big_opts =
            SocketOptions { receive_buffer_size: 16 * 1024 * 1024, ..Default::default() };
        let err = check_explicit_receive_buffer_size_with(&big_opts, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(msg.contains("16777216"), "错误须点名设定值：{msg}");
        assert!(
            msg.contains(ALLOW_LARGE_RCVBUF_ENV),
            "错误须点名确认开关 {ALLOW_LARGE_RCVBUF_ENV}：{msg}"
        );
        assert!(msg.contains("2 ×"), "错误须点名 2× 内核记账与并发账面公式：{msg}");
        assert!(msg.contains("receiveBufferSize"), "错误须点名配置来源：{msg}");
        // 带确认 ⇒ 判定通过（注入点观测；公开口读 env）。
        check_explicit_receive_buffer_size_with(&big_opts, true).unwrap();
        // 未确认时公开口也拒（进程级 env 未设）。
        let err = check_explicit_receive_buffer_size(&big_opts).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let big_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err2 = apply_explicit_receive_buffer_size(&big_sock, &big_opts).unwrap_err();
        assert_eq!(err2.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            socket2::SockRef::from(&big_sock).recv_buffer_size().unwrap(),
            base,
            "未确认的大档不得 setsockopt（禁静默钳到上限）"
        );

        // 档 3：> 64 MiB ⇒ 恒拒（防手滑），文案点名硬上限。
        let huge_opts =
            SocketOptions { receive_buffer_size: 128 * 1024 * 1024, ..Default::default() };
        let err = check_explicit_receive_buffer_size_with(&huge_opts, true).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(
            msg.contains(&SO_RCVBUF_HARD_MAX.to_string()),
            "错误须点名硬上限值 {}：{msg}",
            SO_RCVBUF_HARD_MAX
        );
    }

    /// bd unpg5：显式 SO_RCVBUF 下发后**回读可见性**——回读 < 请求值（内核
    /// `net.core.rmem_max` 静默钳制 + autotune 锁死）必须产出点名实际值的 WARN。
    /// 附防回档锚点：`TCP_RCVBUF_DEFAULT` 恒 0（bd r5j96，缺省交 OS autotune），
    /// 本票只加可见性，禁把缺省改回设值。
    #[test]
    fn explicit_rcvbuf_clamp_is_visible_via_readback_warn() {
        // 防回档：缺省必须保持 0 = 不设置（bd r5j96）；unpg5 只做回读可见性。
        assert_eq!(TCP_RCVBUF_DEFAULT, 0, "缺省必须保持 0（bd r5j96），不得改回设值");

        // 判据直测（跨平台确定，不依赖内核 rmem_max 现值）。
        assert!(!rcvbuf_clamped(0, 208 * 1024), "缺省不设：无钳制可言");
        assert!(!rcvbuf_clamped(1 << 20, 2 << 20), "足额受理（Linux 2× 记账）不算钳制");
        assert!(!rcvbuf_clamped(1 << 20, 1 << 20), "足额（原样回读）不算钳制");
        assert!(rcvbuf_clamped(1 << 20, 425_984), "回读 2×rmem_max(208KB) < 请求 = 被钳制");
        assert!(!rcvbuf_clamped(-1, 0), "负值/缺省不判钳制");

        // WARN 记录实测回读值（mock 回读值注入，跨平台确定）。
        let sink = WarnCapture::default();
        {
            let _guard = tracing::subscriber::set_default(sink.clone());
            warn_if_rcvbuf_clamped(1 << 20, Ok(425_984));
        }
        let msgs = sink.snapshot();
        let warn = msgs
            .iter()
            .find(|m| m.contains("clamped by kernel"))
            .expect("钳制必须产出 WARN（回读值被记录 = unpg5 验收核心）");
        assert!(warn.contains("receiveBufferSize=1048576"), "WARN 须点名请求值：{warn}");
        assert!(warn.contains("actual SO_RCVBUF=425984"), "WARN 须点名实际回读值：{warn}");

        // 足额场景不得产出钳制 WARN（对照组）。
        let sink = WarnCapture::default();
        {
            let _guard = tracing::subscriber::set_default(sink.clone());
            warn_if_rcvbuf_clamped(1 << 20, Ok(2 << 20));
            warn_if_rcvbuf_clamped(0, Ok(208 * 1024));
        }
        assert!(
            sink.snapshot().iter().all(|m| !m.contains("clamped by kernel")),
            "足额/缺省不得告警"
        );
    }

    /// bd wpa3o：显式 SO_SNDBUF 下发后**回读可见性**——回读 < 请求值（Linux
    /// `net.core.wmem_max` 静默钳制，stock 208KB 量级）必须产出点名实际值的 WARN。
    /// 判据各平台依据见 [`sndbuf_clamped`] doc（逐平台自查后定，非照抄 RCVBUF）：
    /// Linux 2× 记账足额回读翻倍；Windows 原样等值（2026-11-07 本机探针实测）；
    /// macOS/BSD 原样或 autotune 只升不降 ⇒ 三平台足额均 ≥ 请求值。
    #[test]
    fn sndbuf_clamp_is_visible_via_readback_warn() {
        // 判据直测（跨平台确定，不依赖内核 wmem_max 现值）。
        assert!(!sndbuf_clamped(0, 208 * 1024), "缺省不设：无钳制可言");
        assert!(!sndbuf_clamped(1 << 20, 2 << 20), "足额受理（Linux 2× 记账）不算钳制");
        assert!(!sndbuf_clamped(1 << 20, 1 << 20), "足额（Windows/macOS 原样回读）不算钳制");
        assert!(sndbuf_clamped(1 << 20, 425_984), "回读 2×wmem_max(208KB) < 请求 = 被钳制");
        assert!(!sndbuf_clamped(-1, 0), "负值/缺省不判钳制");

        // WARN 记录实测回读值（mock 回读值注入，跨平台确定）。
        let sink = WarnCapture::default();
        {
            let _guard = tracing::subscriber::set_default(sink.clone());
            warn_if_sndbuf_clamped(1 << 20, Ok(425_984));
        }
        let msgs = sink.snapshot();
        let warn = msgs
            .iter()
            .find(|m| m.contains("clamped by kernel"))
            .expect("钳制必须产出 WARN（回读值被记录 = wpa3o 验收核心）");
        assert!(warn.contains("sendBufferSize=1048576"), "WARN 须点名请求值：{warn}");
        assert!(warn.contains("actual SO_SNDBUF=425984"), "WARN 须点名实际回读值：{warn}");

        // 足额场景不得产出钳制 WARN（对照组）。
        let sink = WarnCapture::default();
        {
            let _guard = tracing::subscriber::set_default(sink.clone());
            warn_if_sndbuf_clamped(1 << 20, Ok(2 << 20));
            warn_if_sndbuf_clamped(0, Ok(208 * 1024));
        }
        assert!(
            sink.snapshot().iter().all(|m| !m.contains("clamped by kernel")),
            "足额/缺省不得告警"
        );
    }

    /// bd u91se：UDP/QUIC 端点**显式**缓冲值同三档（recv/send 各向）。
    /// 缺省 8 MB 是 Go quic-go `wrapConn` parity 下限（PM 裁决保留）⇒ **不受闸约束**。
    #[test]
    fn explicit_udp_buffer_budget_gate() {
        // 档 1：显式 4 MiB（免确认上限）：两端向均通过。
        let ok = SocketOptions {
            receive_buffer_size: SO_RCVBUF_FREE_TIER_MAX as i32,
            send_buffer_size: SO_RCVBUF_FREE_TIER_MAX as i32,
            ..Default::default()
        };
        check_explicit_udp_buffer_size(ok.receive_buffer_size, UdpBufDir::Recv).unwrap();
        check_explicit_udp_buffer_size(ok.send_buffer_size, UdpBufDir::Send).unwrap();

        // 缺省（0）：不判定（走 8 MB parity 下限）。
        check_explicit_udp_buffer_size(0, UdpBufDir::Recv).unwrap();
        check_explicit_udp_buffer_size(0, UdpBufDir::Send).unwrap();

        // 档 2：4 MiB < v ≤ 64 MiB —— 未确认 ⇒ 拒（文案含开关名）；带确认 ⇒ 通过。
        let big = 16 * 1024 * 1024;
        let err = check_explicit_udp_buffer_size_with(big, UdpBufDir::Recv, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(msg.contains(ALLOW_LARGE_RCVBUF_ENV), "错误须点名确认开关：{msg}");
        assert!(msg.contains("receiveBufferSize"), "错误须点名配置项名：{msg}");
        check_explicit_udp_buffer_size_with(big, UdpBufDir::Recv, true).unwrap();
        let err = check_explicit_udp_buffer_size_with(big, UdpBufDir::Send, false).unwrap_err();
        assert!(err.to_string().contains("sendBufferSize"), "错误须点名配置项名：{err}");

        // 档 3：> 64 MiB ⇒ 恒拒。
        let err = check_explicit_udp_buffer_size_with(128 * 1024 * 1024, UdpBufDir::Recv, true)
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains(&SO_RCVBUF_HARD_MAX.to_string()),
            "错误须点名硬上限值：{err}"
        );

        // 端到端：bind_udp_endpoint 对**未确认**的大档显式值 **拒绑**（fail-visible）。
        let over = SocketOptions { receive_buffer_size: big, ..Default::default() };
        let err = bind_udp_endpoint("127.0.0.1:0".parse().unwrap(), &over).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains(ALLOW_LARGE_RCVBUF_ENV), "bind 失败须点名确认开关：{err}");
    }
}
