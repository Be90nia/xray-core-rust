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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// 绑定到指定网络接口索引。`0`=不绑定。
    /// 对应 Go `SocketConfig.Interface`（Go 用接口名字符串，Rust 用索引）。
    /// Linux: SO_BINDTODEVICE；Darwin: IP_BOUND_IF / IPV6_BOUND_IF。
    pub bind_if_index: u32,
    /// 是否限制 socket 仅使用 IPv6（不允许 IPv4-mapped 地址）。默认 `false`。
    /// 对应 Go `sockopt_ipv6_only` / `IPV6_V6ONLY`。socket2 跨平台 `set_only_v6()`。
    pub ipv6_only: bool,
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
            bind_if_index: 0,
            ipv6_only: false,
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
    // SO_KEEPALIVE + TCP_KEEPIDLE/TCP_KEEPINTVL：socket2 跨平台封装。
    if opts.tcp_keepalive_idle != Duration::ZERO {
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(opts.tcp_keepalive_idle)
                .with_interval(opts.tcp_keepalive_interval),
        )?;
    }
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
///（Go 端 `lc.KeepAlive = -1`），仅在 [`SocketOptions`] 显式配置非零 idle 时启用。
pub fn apply_inbound_socket_options(socket: &Socket, opts: &SocketOptions) -> std::io::Result<()> {
    socket.set_nodelay(opts.tcp_nodelay)?;
    if opts.ipv6_only {
        socket.set_only_v6(true)?;
    }
    if opts.tcp_keepalive_idle != Duration::ZERO {
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(opts.tcp_keepalive_idle)
                .with_interval(opts.tcp_keepalive_interval),
        )?;
    }
    Ok(())
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
    }

    #[test]
    fn socket_options_is_copy_clone() {
        let opts = SocketOptions::default();
        let cloned = opts;
        assert_eq!(opts, cloned);
    }
}
