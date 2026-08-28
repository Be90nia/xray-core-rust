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
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
pub mod freebsd;
use std::time::Duration;
use socket2::Socket;

/// 基础 socket 选项。对应 Go `SocketConfig` 的核心字段子集。
///
/// 默认值与 Go DefaultSystemDialer 一致：
/// - `tcp_nodelay = true`（Chrome 默认）
/// - `tcp_keepalive_idle = 45s`
/// - `tcp_keepalive_interval = 45s`
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
    /// TCP Fast Open。对应 Go `SocketConfig.Tfo`。
    /// Windows 不支持 per-socket TFO（需系统级注册表设置），FreeBSD 12.1+/Linux 支持。
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
    // TCP_FASTOPEN：Windows 不支持 per-socket（系统级注册表），FreeBSD/Linux 支持。
    // Go 在 Windows 也是 no-op（参见 sockopt_windows.go）。
    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    {
        if opts.tcp_fast_open {
            let _ = opts; // FreeBSD TFO 需 libc::TCP_FASTOPEN，留 follow-up
        }
    }
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
}
