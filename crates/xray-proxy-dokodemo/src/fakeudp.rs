//! TPROXY 伪造源地址 UDP socket。对应 Go `proxy/dokodemo/fakeudp_linux.go` /
//! `fakeudp_other.go`。
//!
//! 用途：dokodemo `followRedirect` UDP（TPROXY）模式下，响应包的源地址必须等于
//! 客户端原始目标地址——普通 socket 做不到，需要 `IP_TRANSPARENT` 透明 socket
//! bind 到伪造地址后发送。仅 Linux 可用（iptables TPROXY 生态）。

use std::{io, net::SocketAddr};

/// 创建绑定到 `addr` 的透明 UDP socket。
///
/// - Linux：`socket(SOCK_DGRAM)` + `SO_MARK`（mark≠0 时）+ `IP_TRANSPARENT` +
///   `SO_REUSEADDR`/`SO_REUSEPORT` + `bind`，返回非阻塞 tokio socket。
/// - 非 Linux：返回错误（对齐 Go `fakeudp_other.go` 的 `!linux`）。
///
/// 需要 `CAP_NET_ADMIN`（`IP_TRANSPARENT` + bind 非本机地址）。
pub fn fake_udp(addr: SocketAddr, mark: u32) -> io::Result<tokio::net::UdpSocket> {
    #[cfg(target_os = "linux")]
    {
        fake_udp_linux(addr, mark)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (addr, mark);
        Err(io::Error::other("fakeudp: !linux"))
    }
}

#[cfg(target_os = "linux")]
fn fake_udp_linux(addr: SocketAddr, mark: u32) -> io::Result<tokio::net::UdpSocket> {
    use std::os::fd::FromRawFd;

    unsafe {
        let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let mut fd = libc::socket(domain, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // 步骤集中在一个立即闭包，任何一步失败统一在外层 close fd
        //（对齐 Go 每个错误分支手动 syscall.Close）。
        let result = (|| -> io::Result<tokio::net::UdpSocket> {
            if mark != 0 {
                setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int)?;
            }
            // Go 对 IPv6 也固定 SOL_IP+IP_TRANSPARENT（fakeudp_linux.go L43），照抄
            setsockopt_int(fd, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
            // REUSEADDR/REUSEPORT 错误忽略（Go 同）
            let _ = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
            let _ = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1);
            bind(fd, &addr)?;
            // tokio 要求非阻塞
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
            // tokio 1.x UdpSocket 无 FromRawFd impl；等价路径 = std FromRawFd + from_std。
            // from_std Err 时 std socket 已 drop 关闭 fd，置 -1 让外层 close 成为 no-op。
            let res = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from_raw_fd(fd));
            if res.is_err() {
                fd = -1;
            }
            Ok(res?)
        })();

        if result.is_err() {
            libc::close(fd);
        }
        result
    }
}

/// `setsockopt(fd, level, opt, c_int)`。
#[cfg(target_os = "linux")]
unsafe fn setsockopt_int(
    fd: libc::c_int,
    level: libc::c_int,
    opt: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    let rv = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rv < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// `bind(fd, addr)`。
#[cfg(target_os = "linux")]
unsafe fn bind(fd: libc::c_int, addr: &SocketAddr) -> io::Result<()> {
    let rv = match addr {
        SocketAddr::V4(a) => unsafe {
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = a.port().to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        },
        SocketAddr::V6(a) => unsafe {
            let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = a.port().to_be();
            sa.sin6_addr.s6_addr = a.ip().octets();
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        },
    };
    if rv < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐 Go fakeudp_other.go：非 Linux 一律 `!linux` 错误。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn fake_udp_non_linux_returns_error() {
        let addr: SocketAddr = "203.0.113.1:9999".parse().unwrap();
        let err = fake_udp(addr, 0).unwrap_err();
        assert!(err.to_string().contains("!linux"), "got: {err}");
    }

    /// Linux 路径：无 CAP_NET_ADMIN 时 IP_TRANSPARENT setsockopt 返回 EPERM，
    /// 两种结果都合法（透明 bind 本机回环地址+随机端口在有权限时应成功）。
    /// CI 无 root，故只断言「成功 socket 或权限错误」，不冒进。
    #[cfg(target_os = "linux")]
    #[test]
    fn fake_udp_linux_socket_or_permission_error() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        match fake_udp(addr, 0) {
            Ok(sock) => {
                let local = sock.local_addr().unwrap();
                assert!(local.is_ipv4());
            },
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "got: {e}");
            },
        }
    }
}
