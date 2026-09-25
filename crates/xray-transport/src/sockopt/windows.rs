//! # Windows socket options
//!
//! 对应 Go `transport/internet/sockopt_windows.go`。
//!
//! 实现 Windows 特定的 socket 选项：
//! - TCP_FASTOPEN（Winsock 值 15；Go :16-32 是真实实现而非 no-op，Win10 1607+ 才支持 per-socket
//!   TFO，老系统 setsockopt 返回 WSAENOPROTOOPT 由调用方处理）
//! - IP_UNICAST_IF / IPV6_UNICAST_IF（出站接口绑定，Go :35-66；v4 值必须 network byte order——Go
//!   :46-48 的 BigEndian 往返坑，见 `unicast_if_v4_value`）
//!
//! 对齐 Go stub（sockopt_windows.go:184-190）：Windows `setReuseAddr`/`setReusePort`
//! 为 no-op（SO_EXCLUSIVEADDRUSE 语义下 Windows 默认行为已等价）。
//!
//! 已由通用层（mod.rs，socket2）覆盖、此处不重复实现：
//! - V6Only → `Socket::set_only_v6`（IPV6_V6ONLY，Go inbound :139-143）
//! - keepalive → `set_keepalive_config`（Go Windows 仅 SO_KEEPALIVE 开关 :73-81； socket2
//!   `SIO_KEEPALIVE_VALS` 物化更完整）
//!
//! CustomSockopt：由通用层 mod.rs 的 `apply_custom_sockopt` 应用
//! （int 类型全支持；str 类型报错不支持，Go :113 "Str type does not supported
//! on windows"）。TcpWindowClamp/TcpUserTimeout/TcpMaxSeg 仅解析存储——Go
//! sockopt_windows.go 同样不应用这三项（Winsock 无 TCP_USER_TIMEOUT/
//! TCP_WINDOW_CLAMP 导出）。

use std::io;

/// Winsock `TCP_FASTOPEN`（sockopt_windows.go:17，mstcpip.h；Win10 1607+）。
const TCP_FASTOPEN: i32 = 15;
/// Winsock `IP_UNICAST_IF`（sockopt_windows.go:18，ws2ipdef.h 同值）。
const IP_UNICAST_IF: i32 = 31;
/// Winsock `IPV6_UNICAST_IF`（sockopt_windows.go:19）。
const IPV6_UNICAST_IF: i32 = 31;
/// ws2_32 `IPPROTO_IP`。
const IPPROTO_IP: i32 = 0;
/// ws2_32 `IPPROTO_IPV6`。
const IPPROTO_IPV6: i32 = 41;
/// ws2_32 `IPPROTO_TCP`。
const IPPROTO_TCP: i32 = 6;
// ws2_32 已由 std（net 模块）与 socket2 链接，此处仅声明符号，无新依赖。
// SAFETY 声明在调用点。
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn setsockopt(s: usize, level: i32, optname: i32, optval: *const i32, optlen: i32) -> i32;
}

pub(crate) fn setsockopt_int(s: usize, level: i32, optname: i32, val: i32) -> io::Result<()> {
    // SAFETY: s 为有效 SOCKET 句柄（调用方来自 socket2::Socket::as_raw_socket）；
    // optval 指向栈上 i32，optlen 与类型一致；winsock 同步返回，不保留指针。
    let ret = unsafe { setsockopt(s, level, optname, &val, std::mem::size_of::<i32>() as i32) };
    if ret != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Go sockopt_windows.go:184-186：Windows setReuseAddr 为 no-op。
pub fn set_reuse_addr(_s: usize) -> io::Result<()> {
    Ok(())
}

/// Go sockopt_windows.go:188-190：Windows setReusePort 为 no-op。
pub fn set_reuse_port(_s: usize) -> io::Result<()> {
    Ok(())
}

/// Go sockopt_windows.go:46-48 的字节序往返：把接口索引按 BigEndian 编码后按
/// native u32 重解释（x86/ARM64 little-endian 上等价 `htonl`）。
/// IP_UNICAST_IF 要求该编码；IPV6_UNICAST_IF 则直接用 host order（Go :58）。
fn unicast_if_v4_value(index: u32) -> u32 {
    index.to_be()
}

#[derive(Debug, Clone, Default)]
pub struct WindowsSockOpt {
    /// TCP Fast Open，Go `ParseTFOValue()`（sockopt.go:21-30）三态：
    /// `-1` 未配置（跳过）、`0` 显式禁用、`>0` 启用（clamp 为 1，:23-25）。
    pub tcp_fast_open: i32,
    /// 出站绑定接口索引（Go `SocketConfig.Interface` 解析出的 ifIndex）。`0`=不绑定。
    pub bind_if_index: u32,
    /// 绑定目标是否 IPv4（决定 IP_UNICAST_IF 还是 IPV6_UNICAST_IF）。
    /// Go :41 按地址字符串含 "." 判定（不信任 network 参数），Rust 由调用方给定。
    pub is_ipv4: bool,
}

impl WindowsSockOpt {
    /// 将 Windows 特定 socket 选项应用到给定 SOCKET 句柄。
    ///
    /// 对应 Go `applyOutboundSocketOptions` / `applyInboundSocketOptions` 的
    /// Windows 平台分支（sockopt_windows.go:34-182；TFO 两向均设置，
    /// Interface 绑定仅出站，:35-67）。
    pub fn apply(&self, s: u64) -> io::Result<()> {
        let s = s as usize; // std SOCKET（u64）→ ws2_32 句柄宽度
        if self.tcp_fast_open >= 0 {
            let tfo = if self.tcp_fast_open > 0 { 1 } else { self.tcp_fast_open };
            setsockopt_int(s, IPPROTO_TCP, TCP_FASTOPEN, tfo)?;
        }

        if self.bind_if_index > 0 {
            if self.is_ipv4 {
                // Go :46-51：IP_UNICAST_IF 的值必须 network byte order。
                setsockopt_int(
                    s,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    unicast_if_v4_value(self.bind_if_index) as i32,
                )?;
            } else {
                // Go :58-60：IPV6_UNICAST_IF 直接用 host order 索引。
                setsockopt_int(s, IPPROTO_IPV6, IPV6_UNICAST_IF, self.bind_if_index as i32)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsRawSocket;

    use super::*;

    /// Win10 <1607 无 per-socket TFO，setsockopt 返回 WSAENOPROTOOPT（10042）；
    /// 按能力门控跳过（Go 语义会向上传播错误，生产调用方决定）。
    const WSAENOPROTOOPT: i32 = 10042;
    /// WSAEINVAL（10022）/ WSAEADDRNOTAVAIL（10049）：接口索引在本环境不可用。
    const WSAEINVAL: i32 = 10022;
    const WSAEADDRNOTAVAIL: i32 = 10049;

    fn new_socket(ty: socket2::Type, proto: socket2::Protocol) -> socket2::Socket {
        socket2::Socket::new(socket2::Domain::IPV4, ty, Some(proto)).unwrap()
    }

    /// TFO 三态之「未配置」：`-1` 跳过一切 setsockopt，apply 恒 Ok。
    #[test]
    fn tfo_unconfigured_skips() {
        let opt = WindowsSockOpt { tcp_fast_open: -1, ..Default::default() };
        let sock = new_socket(socket2::Type::STREAM, socket2::Protocol::TCP);
        assert!(opt.apply(sock.as_raw_socket()).is_ok());
    }

    /// TFO 三态之「启用」：真实 setsockopt(TCP_FASTOPEN=15)；Win10 1607+ 应成功。
    #[test]
    fn tfo_enabled_sets_winsock_option() {
        let opt = WindowsSockOpt { tcp_fast_open: 5, ..Default::default() };
        let sock = new_socket(socket2::Type::STREAM, socket2::Protocol::TCP);
        match opt.apply(sock.as_raw_socket()) {
            Ok(()) => {},
            Err(e) if e.raw_os_error() == Some(WSAENOPROTOOPT) => {}, // pre-1607 门控跳过
            Err(e) => panic!("set TCP_FASTOPEN failed: {e}"),
        }
    }

    /// TFO 三态之「显式禁用」：`0` 同样真实调用 setsockopt。
    #[test]
    fn tfo_disabled_sets_zero() {
        let opt = WindowsSockOpt { tcp_fast_open: 0, ..Default::default() };
        let sock = new_socket(socket2::Type::STREAM, socket2::Protocol::TCP);
        match opt.apply(sock.as_raw_socket()) {
            Ok(()) => {},
            Err(e) if e.raw_os_error() == Some(WSAENOPROTOOPT) => {},
            Err(e) => panic!("set TCP_FASTOPEN=0 failed: {e}"),
        }
    }

    /// 对齐 Go stub：Windows setReuseAddr/setReusePort 为 no-op，恒 Ok。
    /// （sockopt_windows.go:184-190）
    #[test]
    fn reuse_addr_port_are_noops_matching_go_stub() {
        assert!(set_reuse_addr(usize::MAX).is_ok());
        assert!(set_reuse_port(usize::MAX).is_ok());
    }

    /// Go :46-48 字节序坑锁定：index 经 BigEndian 编码后按 native u32 重解释。
    #[test]
    fn unicast_if_v4_value_is_network_byte_order() {
        assert_eq!(unicast_if_v4_value(1), 0x0100_0000);
        assert_eq!(unicast_if_v4_value(0x0a00_0002), 0x0200_000a);
    }

    /// IP_UNICAST_IF 真实调用冒烟：UDP socket 绑定回环接口（Windows ifIndex 1
    /// 为 Software Loopback Interface）。接口不可用的环境按错误码门控跳过。
    #[test]
    fn unicast_if_smoke_on_udp_socket() {
        let opt = WindowsSockOpt { bind_if_index: 1, is_ipv4: true, ..Default::default() };
        let sock = new_socket(socket2::Type::DGRAM, socket2::Protocol::UDP);
        match opt.apply(sock.as_raw_socket()) {
            Ok(()) => {},
            Err(e) if matches!(e.raw_os_error(), Some(WSAEINVAL) | Some(WSAEADDRNOTAVAIL)) => {},
            Err(e) => panic!("set IP_UNICAST_IF failed: {e}"),
        }
    }
}
