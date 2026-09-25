//! # FreeBSD socket options
//!
//! 对应 Go `transport/internet/sockopt_freebsd.go`。
//!
//! 实现平台特定的高级 socket 选项：
//! - TCP_FASTOPEN（出站 clamp 为 1 / 入站原值，sockopt_freebsd.go:134-143 / :186-192）
//! - SO_USER_COOKIE（Go `SocketConfig.Mark` 的 FreeBSD 等价物，:128-132 / :181-185）
//! - SO_REUSEPORT_LB → SO_REUSEPORT 回退（:232-239；LB 需 FreeBSD 12.3+/13+）
//!
//! OpenBSD 不在本模块：Go `sockopt_other.go` 对 openbsd 是 no-op，mod.rs 仅对
//! freebsd 启用本模块。
//!
//! 由通用层跨平台覆盖、此处不重复实现：
//! - SO_REUSEADDR（Go :225-230）→ socket2 `set_reuse_address`
//! - TCP_KEEPIDLE/TCP_KEEPINTVL + SO_KEEPALIVE（Go :144-162）→
//!   [`crate::sockopt::set_keepalive_config`]（socket2 TcpKeepalive）

use std::io;

/// FreeBSD `TCP_FASTOPEN`（netinet/tcp.h，值 1）。
/// libc 有导出，与 Go x/sys/unix 一样本地固定以避免版本差异。
const TCP_FASTOPEN: libc::c_int = 1;
/// FreeBSD `SO_USER_COOKIE`（sys/socket.h，0x1015）。Linux `SO_MARK` 的等价物。
const SO_USER_COOKIE: libc::c_int = 0x1015;
/// FreeBSD `SO_REUSEPORT`（sys/socket.h，0x200）。对应 Go `soReUsePort`。
const SO_REUSEPORT: libc::c_int = 0x00000200;
/// FreeBSD `SO_REUSEPORT_LB`（sys/socket.h，0x10000）。对应 Go `soReUsePortLB`。
const SO_REUSEPORT_LB: libc::c_int = 0x00010000;

fn setsockopt_int(
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    // SAFETY: fd 为有效 socket fd（调用方来自 socket2::Socket::as_raw_fd）；
    // optval 指向栈上 c_int，optlen 与类型一致；内核不保留指针。
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[derive(Debug, Clone, Default)]
pub struct FreebsdSockOpt {
    /// TCP Fast Open，Go `ParseTFOValue()`（sockopt.go:21-30）三态：
    /// `-1` 未配置（跳过）、`0` 显式禁用、`>0` 启用。
    /// 出站 apply 时 clamp 为 1（sockopt_freebsd.go:136-138），入站用原值（:187-192）。
    pub tcp_fast_open: i32,
    /// 是否启用 SO_REUSEPORT_LB（失败回退 SO_REUSEPORT）。
    pub reuse_port: bool,
    /// SO_USER_COOKIE 标记值。`0`=不设置。需要 root 或 PRIV_NETINET 权限。
    pub mark: u32,
    /// 是否入站连接（决定 TFO 是否 clamp）。
    pub inbound: bool,
}

impl FreebsdSockOpt {
    /// 将 FreeBSD 特定 socket 选项应用到给定 fd。
    ///
    /// 对应 Go `applyOutboundSocketOptions` / `applyInboundSocketOptions` 的
    /// FreeBSD 平台分支（sockopt_freebsd.go:127-223）。
    pub fn apply(&self, fd: i32) -> io::Result<()> {
        if self.tcp_fast_open >= 0 {
            let tfo = if !self.inbound && self.tcp_fast_open > 0 { 1 } else { self.tcp_fast_open };
            setsockopt_int(fd, libc::IPPROTO_TCP, TCP_FASTOPEN, tfo)?;
        }

        if self.mark != 0 {
            setsockopt_int(fd, libc::SOL_SOCKET, SO_USER_COOKIE, self.mark as libc::c_int)?;
        }

        if self.reuse_port {
            self.set_reuse_port(fd)?;
        }

        Ok(())
    }

    /// 设置 SO_REUSEPORT_LB，失败回退 SO_REUSEPORT。
    /// 对应 Go `setReusePort`（sockopt_freebsd.go:232-239）。
    fn set_reuse_port(&self, fd: i32) -> io::Result<()> {
        if setsockopt_int(fd, libc::SOL_SOCKET, SO_REUSEPORT_LB, 1).is_err() {
            // 旧内核（<12.3）无 SO_REUSEPORT_LB，回退普通 SO_REUSEPORT。
            setsockopt_int(fd, libc::SOL_SOCKET, SO_REUSEPORT, 1)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    fn udp_socket() -> socket2::Socket {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap()
    }

    /// SO_REUSEPORT_LB→SO_REUSEPORT 回退后的可观测行为：两个 socket 可绑同一地址。
    /// 对应 Go setReusePort 语义（sockopt_freebsd.go:232-239）。
    #[test]
    fn reuse_port_allows_same_address_bind() {
        let opt = FreebsdSockOpt { reuse_port: true, ..Default::default() };
        let s1 = udp_socket();
        opt.apply(s1.as_raw_fd()).unwrap();
        s1.bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap().into()).unwrap();
        let addr = s1.local_addr().unwrap();
        let s2 = udp_socket();
        opt.apply(s2.as_raw_fd()).unwrap();
        s2.bind(&addr).expect("SO_REUSEPORT(_LB) 后第二 socket 应可绑同一地址");
    }

    /// TFO 三态：未配置（-1）跳过不设置；显式禁用/启用均真实调用 setsockopt。
    /// FreeBSD 回环 TCP socket 上 TCP_FASTOPEN 读写皆支持。
    #[test]
    fn tfo_tri_state_on_tcp_socket() {
        let tcp = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        // 未配置：跳过（apply 仍 Ok）。
        let unconfigured = FreebsdSockOpt { tcp_fast_open: -1, ..Default::default() };
        assert!(unconfigured.apply(tcp.as_raw_fd()).is_ok());
        // 出站启用：clamp 为 1。
        let enabled = FreebsdSockOpt { tcp_fast_open: 5, inbound: false, ..Default::default() };
        enabled.apply(tcp.as_raw_fd()).unwrap();
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt 读回栈上 c_int，len 与类型一致。
        unsafe {
            libc::getsockopt(
                tcp.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_FASTOPEN,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(val, 1, "出站 TFO 应 clamp 为 1（sockopt_freebsd.go:136-138）");
    }

    /// SO_USER_COOKIE 需要 root；非 root 环境（EPERM）跳过。
    #[test]
    fn mark_sets_user_cookie_or_skips_unprivileged() {
        let opt = FreebsdSockOpt { mark: 0x1234, ..Default::default() };
        let s = udp_socket();
        match opt.apply(s.as_raw_fd()) {
            Ok(()) => {},
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {},
            Err(e) => panic!("set SO_USER_COOKIE failed: {e}"),
        }
    }
}
