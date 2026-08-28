//! Socket 选项配置与应用。对应 Go `transport/internet/sockopt.go` + 平台特定文件。
//!
//! ## 切片边界（P5-Sys 切片1）
//!
//! 仅实现跨平台通用的基础 sockopt（TCP_NODELAY + SO_KEEPALIVE + TCP_KEEPIDLE/
//! TCP_KEEPINTVL）。平台特定选项（SO_MARK / SO_BINDTODEVICE / TCP_FASTOPEN /
//! TCP_CONGESTION 等）留切片2。
//!
//! ## SocketOptions vs SocketConfig proto
//!
//! 切片1 不引入完整 prost SocketConfig（字段过多），用简化 [`SocketOptions`]
//! struct 暴露常用字段。完整 proto 对接留切片2。

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(target_os = "freebsd")]
pub mod freebsd;
use std::time::Duration;
use socket2::Socket;

/// 基础 socket 选项。对应 Go `SocketConfig` 的核心字段子集。
///
/// 默认值与 Go DefaultSystemDialer 一致：
/// - `tcp_nodelay = true`（Chrome 默认）
/// - `tcp_keepalive_idle = 45s`
/// - `tcp_keepalive_interval = 45s`
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
    /// TCP_FASTOPEN=15，见 [`windows`] 模块）支持；macOS 用 CLIENT/SERVER 位标志。
    pub tcp_fast_open: bool,
    /// Multipath TCP（MPTCP）。对应 Go `SocketConfig.TcpMptcp`（字段 19，JSON `tcpMptcp`）。
    /// 仅 Linux 生效；其他平台或不支持 MPTCP 的内核上静默回退普通 TCP
    ///（对齐 Go `net.ListenConfig.SetMultipathTCP` 行为）。监听 socket 在
    /// bind 前设置 `TCP_MPTCP`，accept 出的连接自动为 MPTCP。
    pub tcp_mptcp: bool,
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
        Self {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay_ms: 0,
            max_concurrent_try: 4,
        }
    }
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
            bind_if_index: 0,
            ipv6_only: false,
            dialer_proxy: String::new(),
            happy_eyeballs: None,
            domain_strategy: DomainStrategy::AsIs,
            address_port_strategy: AddressPortStrategy::None,
         }
    }
}

/// 把 [`SocketOptions`] 应用到已建立的 [`Socket`]（TCP 专用）。
///
/// 对应 Go `applyOutboundSocketOptions` 的跨平台通用部分。失败时返回
/// [`std::io::Error`]，调用方决定是忽略（继续拨号）还是中止。
///
/// 平台特定选项（SO_MARK / SO_BINDTODEVICE / TCP_CONGESTION）由各平台模块
/// （[`linux`] / [`windows`] / [`darwin`] / [`freebsd`]）提供，切片2 接入。
pub fn apply_outbound_socket_options(socket: &Socket, opts: &SocketOptions) -> std::io::Result<()> {
    // TCP_NODELAY：跨平台通用。
    socket.set_nodelay(opts.tcp_nodelay)?;
    if opts.ipv6_only {
        socket.set_only_v6(true)?;
    }
    // SO_KEEPALIVE + TCP_KEEPIDLE/TCP_KEEPINTVL（Go KeepAliveConfig 语义，见
    // [`set_keepalive_config`]）。
    set_keepalive_config(socket, opts)?;
    // SO_MARK：仅 Linux 有效。
    #[cfg(target_os = "linux")]
    {
        if opts.mark > 0 || opts.bind_if_index > 0 {
            let fd = socket.as_raw_socket() as i32;
            let linux_opt = linux::LinuxSockOpt { mark: opts.mark, bind_if_index: opts.bind_if_index, ..Default::default() };
            if opts.mark > 0 { linux_opt.set_so_mark(fd)?; }
            if opts.bind_if_index > 0 { linux_opt.set_so_bindtodevice(fd)?; }
        }
    }
    // TCP_FASTOPEN：Go 各平台 outbound/inbound 均设置（Windows 是真实实现：对
    // Winsock TCP_FASTOPEN=15 setsockopt，Win10 1607+ 支持，sockopt_windows.go:16-32）。
    // 生产链路（dialer/listener）的 TFO 接入与 Linux/macOS 一致留待统一批次，
    // 平台能力已就位于 [`windows`] / [`freebsd`] / [`linux`] / [`darwin`] 模块。
    Ok(())
}

/// 把 [`SocketOptions`] 应用到入站连接。对应 Go `applyInboundSocketOptions` 的
/// 跨平台通用部分。
///
/// 与 [`apply_outbound_socket_options`] 的差异：入站连接默认禁用 keepalive
///（Go 端 `lc.KeepAlive = -1`，system_listener.go:91），仅 idle/interval 任一
/// 非零时启用（Go system_listener.go:102-109「任一 >0 即 Enable」）。
pub fn apply_inbound_socket_options(socket: &Socket, opts: &SocketOptions) -> std::io::Result<()> {
    socket.set_nodelay(opts.tcp_nodelay)?;
    if opts.ipv6_only {
        socket.set_only_v6(true)?;
    }
    set_keepalive_config(socket, opts)?;
    Ok(())
}

#[cfg(windows)]
/// Go 1.23 `net.KeepAliveConfig` 未配置字段（`-1`）的默认物化值
///（Go net 文档：Idle/Interval 缺省 15s；Windows `SIO_KEEPALIVE_VALS` 要求显式值）。
pub(crate) const DEFAULT_KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
/// 同上，Interval 缺省 15s。
#[cfg(windows)]
pub(crate) const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// 应用 TCP keepalive 配置。对应 Go `net.KeepAliveConfig` 语义
///（system_listener.go:96-109 / system_dialer.go:89-110）：
///
/// - `idle` 与 `interval` 均为 0（Go `Enable: false`）：不动 `SO_KEEPALIVE`（默认关）。
/// - 任一非零（Go「任一 >0 即 Enable」）：设 `SO_KEEPALIVE=1`；未配置的字段用
///   OS 默认——unix 上跳过对应 setsockopt（Linux 内核默认，对齐 Go `Idle: -1`）；
///   Windows 上 `SIO_KEEPALIVE_VALS` 必须显式给值，物化为 Go 缺省 15s。
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
///（system_listener.go:110-112）。
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
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
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
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SO_ORIGINAL_DST is Linux-only",
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn apply_socket_options_on_real_tcp_connection() {
        // 启动一个 TCP listener 拿到 socket fd。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // spawn acceptor
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        // 客户端拨号
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let socket = socket2::Socket::from(stream.into_std().unwrap());
        let opts = SocketOptions::default();
        let result = apply_outbound_socket_options(&socket, &opts);
        assert!(result.is_ok(), "apply_outbound_socket_options failed: {result:?}");
        // TCP_NODELAY 已设置
        assert_eq!(socket.nodelay().unwrap(), opts.tcp_nodelay);
        drop(socket);
        accept_task.await.unwrap();
    }

    #[test]
    fn default_socket_options_match_chrome_defaults() {
        let opts = SocketOptions::default();
        assert!(opts.tcp_nodelay);
        assert_eq!(opts.tcp_keepalive_idle, Duration::from_secs(45));
        assert_eq!(opts.tcp_keepalive_interval, Duration::from_secs(45));
        assert!(!opts.tcp_fast_open, "TFO default should be false");
        assert!(!opts.tcp_mptcp, "MPTCP default should be false");
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
        for (v, s) in [
            (0, AsIs),
            (1, UseIP),
            (5, UseIPv6v4),
            (10, ForceIPv6v4),
        ] {
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
}
