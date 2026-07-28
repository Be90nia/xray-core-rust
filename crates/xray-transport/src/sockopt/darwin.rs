//! # Darwin (macOS) socket options
//!
//! 对应 Go `transport/internet/sockopt_darwin.go`。
//!
//! 实现 macOS 特定的 socket 选项：
//! - TCP_FASTOPEN（client=0x02, server=0x01）
//! - SO_REUSEPORT
//! - IP_BOUND_IF / IPV6_BOUND_IF（绑定到指定网络接口）
//! - TCP_KEEPALIVE / TCP_KEEPINTVL（keepalive 参数）
//!
//! macOS 的 TCP_FASTOPEN 值与 Linux 不同：
//! - 客户端：TCP_FASTOPEN_CLIENT = 0x02
//! - 服务端：TCP_FASTOPEN_SERVER = 0x01
//!
//! macOS 的 TCP_KEEPINTVL 未在 syscall 包中导出，使用硬编码值 0x101。
//!
//! 所有 unsafe 调用均带 SAFETY 注释。

use std::io;

/// macOS TCP_FASTOPEN 服务端标志。对应 Go `TCP_FASTOPEN_SERVER = 0x01`。
const TCP_FASTOPEN_SERVER: i32 = 0x01;
/// macOS TCP_FASTOPEN 客户端标志。对应 Go `TCP_FASTOPEN_CLIENT = 0x02`。
const TCP_FASTOPEN_CLIENT: i32 = 0x02;
/// macOS TCP_KEEPINTVL。对应 Go `sysTCP_KEEPINTVL = 0x101`。
/// macOS syscall 包未导出此常量，Go 端也使用硬编码。
const SYS_TCP_KEEPINTVL: i32 = 0x101;

#[derive(Debug, Clone, Default)]
pub struct DarwinSockOpt {
    /// TCP Fast Open。`0`=禁用，`1`=启用。
    pub tcp_fast_open: u32,
    /// 是否启用 SO_REUSEPORT。
    pub reuse_port: bool,
    /// 绑定到指定网络接口索引（0=不绑定）。对应 Go `IP_BOUND_IF` / `IPV6_BOUND_IF`。
    pub bind_if_index: u32,
    /// 是否为 IPv6 socket（决定使用 IP_BOUND_IF 还是 IPV6_BOUND_IF）。
    pub is_ipv6: bool,
    /// TCP keepalive 空闲超时（秒）。对应 Go `TCP_KEEPALIVE`。
    pub tcp_keepalive_idle: u32,
    /// TCP keepalive 探测间隔（秒）。对应 Go `sysTCP_KEEPINTVL`。
    pub tcp_keepalive_interval: u32,
    /// 是否为入端连接（决定 TFO 使用 SERVER 还是 CLIENT 标志）。
    pub inbound: bool,
}

impl DarwinSockOpt {
    /// 将 macOS 特定 socket 选项应用到给定 fd。
    ///
    /// 根据 `self.inbound` 决定 TFO 使用 SERVER 还是 CLIENT 标志。
    pub fn apply(&self, fd: i32) -> io::Result<()> {
        // TCP Fast Open
        if self.tcp_fast_open > 0 {
            self.set_tcp_fastopen(fd)?;
        }

        // SO_REUSEPORT
        if self.reuse_port {
            self.set_reuse_port(fd)?;
        }

        // IP_BOUND_IF / IPV6_BOUND_IF
        if self.bind_if_index > 0 {
            self.set_bind_if(fd)?;
        }

        // TCP keepalive 参数
        if self.tcp_keepalive_idle > 0 || self.tcp_keepalive_interval > 0 {
            self.set_tcp_keepalive_params(fd)?;
        }

        Ok(())
    }

    /// 设置 TCP_FASTOPEN。macOS 使用位标志而非 Linux 的 backlog 值。
    /// 对应 Go `unix.SetsockoptInt(fd, IPPROTO_TCP, TCP_FASTOPEN, val)`。
    fn set_tcp_fastopen(&self, fd: i32) -> io::Result<()> {
        let val = if self.inbound {
            TCP_FASTOPEN_SERVER
        } else {
            TCP_FASTOPEN_CLIENT
        };
        // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
        // macOS TCP_FASTOPEN = 0x06，值使用 client/server 位标志。
        // 内核验证参数合法性，无效值返回 errno。
        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// 设置 SO_REUSEPORT。对应 Go `unix.SetsockoptInt(fd, SOL_SOCKET, SO_REUSEPORT, 1)`。
    fn set_reuse_port(&self, fd: i32) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
        // macOS SO_REUSEPORT 允许多个 socket 绑定同一地址，内核保证同 uid 约束。
        unsafe {
            let val: i32 = 1;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// 设置 IP_BOUND_IF 或 IPV6_BOUND_IF（绑定到指定网络接口）。
    /// 对应 Go `unix.SetsockoptInt(fd, IPPROTO_IP, IP_BOUND_IF, iface.Index)` 等。
    fn set_bind_if(&self, fd: i32) -> io::Result<()> {
        let val = self.bind_if_index as i32;
        if self.is_ipv6 {
            // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
            // IPV6_BOUND_IF 将 IPv6 socket 绑定到指定接口索引。
            // 内核验证接口索引是否存在。
            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_BOUND_IF,
                    &val as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                );
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        } else {
            // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
            // IP_BOUND_IF 将 IPv4 socket 绑定到指定接口索引。
            // 内核验证接口索引是否存在。
            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_BOUND_IF,
                    &val as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                );
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    /// 设置 TCP keepalive 参数：TCP_KEEPALIVE（idle）+ TCP_KEEPINTVL（interval）+ SO_KEEPALIVE。
    /// 对应 Go 端 darwin 的 keepalive 设置逻辑。
    fn set_tcp_keepalive_params(&self, fd: i32) -> io::Result<()> {
        // TCP_KEEPALIVE：设置 keepalive 空闲超时（对应 Go 的 TCP_KEEPALIVE 常量）。
        if self.tcp_keepalive_idle > 0 {
            // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
            // macOS TCP_KEEPALIVE (= TCP_KEEPIDLE = 0x10) 设置空闲超时秒数。
            let val = self.tcp_keepalive_idle as i32;
            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPALIVE,
                    &val as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                );
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        // TCP_KEEPINTVL：设置 keepalive 探测间隔。
        if self.tcp_keepalive_interval > 0 {
            // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
            // macOS TCP_KEEPINTVL = 0x101，Go 端也使用硬编码值。
            let val = self.tcp_keepalive_interval as i32;
            unsafe {
                let ret = libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    SYS_TCP_KEEPINTVL,
                    &val as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                );
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        // SO_KEEPALIVE：启用 keepalive 机制。
        // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
        // SOL_SOCKET + SO_KEEPALIVE 启用 TCP keepalive 探测。
        unsafe {
            let val: i32 = 1;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}
