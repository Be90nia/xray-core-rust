//! # Linux socket options
//!
//! 对应 Go `transport/internet/sockopt_linux.go`。
//!
//! 实现平台特定的高级 socket 选项：
//! - TCP_FASTOPEN_CONNECT（出站）/ TCP_FASTOPEN（入站）
//! - SO_REUSEPORT
//! - IP_TRANSPARENT（透明代理）
//! - TCP_CONGESTION（拥塞控制算法）
//! - TCP_WINDOW_CLAMP / TCP_USER_TIMEOUT / TCP_MAXSEG（Go sockopt_linux.go:46-62）
//!
//! 所有 unsafe 调用均带 SAFETY 注释。

use std::io;

#[derive(Debug, Clone, Default)]
pub struct LinuxSockOpt {
    /// TCP Fast Open。`0`=禁用，`1`=启用。
    /// 出站使用 TCP_FASTOPEN_CONNECT，入站使用 TCP_FASTOPEN。
    pub tcp_fast_open: u32,
    /// 是否启用 SO_REUSEPORT（允许多个 socket 绑定同一地址）。
    pub reuse_port: bool,
    /// 是否启用 IP_TRANSPARENT（透明代理，需要 root 或 CAP_NET_ADMIN）。
    pub tproxy: bool,
    /// TCP 拥塞控制算法名称（如 "bbr"、"cubic"）。
    pub tcp_congestion: Option<String>,
    /// 是否为入端连接（决定 TFO 使用 TCP_FASTOPEN 还是 TCP_FASTOPEN_CONNECT）。
    pub inbound: bool,
    /// SO_MARK 包标记值，用于 iptables/fwmark 策略路由。`0`=不设置。
    /// 对应 Go `SocketConfig.Mark`。需要 root 或 CAP_NET_ADMIN。
    pub mark: u32,
    /// 绑定到指定网络接口索引。`0`=不绑定。
    /// 对应 Go `SO_BINDTODEVICE`。通过 `if_indextoname` 转为接口名后 setsockopt。
    pub bind_if_index: u32,
    /// TCP_WINDOW_CLAMP 边界缓冲上限（字节）。`0`=不设置。
    /// 对应 Go `SocketConfig.TcpWindowClamp`（sockopt_linux.go:46-50/155-159）。
    pub tcp_window_clamp: i32,
    /// TCP_USER_TIMEOUT（毫秒，RFC 5482）。`0`=不设置。
    /// 对应 Go `SocketConfig.TcpUserTimeout`（sockopt_linux.go:52-56/161-165）。
    pub tcp_user_timeout: i32,
    /// TCP_MAXSEG 最大 MSS（字节）。`0`=不设置。
    /// 对应 Go `SocketConfig.TcpMaxSeg`（sockopt_linux.go:58-62/167-171）。
    pub tcp_max_seg: i32,
}

impl LinuxSockOpt {
    /// 将 Linux 特定 socket 选项应用到给定 fd。
    ///
    /// 根据 `self.inbound` 决定使用 TCP_FASTOPEN_CONNECT（出站）或 TCP_FASTOPEN（入站）。
    pub fn apply(&self, fd: i32) -> io::Result<()> {
        if self.tcp_fast_open > 0 {
            if self.inbound {
                self.set_tcp_fast_open_inbound(fd)?;
            } else {
                self.set_tcp_fast_open_connect(fd)?;
            }
        }

        // SO_REUSEPORT
        if self.reuse_port {
            self.set_reuse_port(fd)?;
        }

        // IP_TRANSPARENT
        if self.tproxy {
            self.set_ip_transparent(fd)?;
        }

        // TCP_CONGESTION
        if let Some(ref algo) = self.tcp_congestion {
            self.set_tcp_congestion(fd, algo)?;
        }

        // TCP_WINDOW_CLAMP / TCP_USER_TIMEOUT / TCP_MAXSEG（Go sockopt_linux.go:46-62；
        // 入站分支 :155-171 同型应用，`>0` 才设置）。
        if self.tcp_window_clamp > 0 {
            Self::set_tcp_int(fd, libc::TCP_WINDOW_CLAMP, self.tcp_window_clamp)?;
        }
        if self.tcp_user_timeout > 0 {
            Self::set_tcp_int(fd, libc::TCP_USER_TIMEOUT, self.tcp_user_timeout)?;
        }
        if self.tcp_max_seg > 0 {
            Self::set_tcp_int(fd, libc::TCP_MAXSEG, self.tcp_max_seg)?;
        }

        // SO_MARK
        if self.mark > 0 {
            self.set_so_mark(fd)?;
        }

        // SO_BINDTODEVICE
        if self.bind_if_index > 0 {
            self.set_so_bindtodevice(fd)?;
        }

        Ok(())
    }

    /// 设置 TCP_FASTOPEN_CONNECT（出站连接）。
    /// 对应 Go `syscall.SetsockoptInt(fd, SOL_TCP, TCP_FASTOPEN_CONNECT, 1)`。
    fn set_tcp_fast_open_connect(&self, fd: i32) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证的 fd 设置整数选项，内核会验证参数合法性。
        // TCP_FASTOPEN_CONNECT = 30（Linux 4.11+），仅影响此连接。
        unsafe {
            let val: i32 = 1;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// 设置 TCP_FASTOPEN（入站 listener）。
    /// 对应 Go `syscall.SetsockoptInt(fd, SOL_TCP, TCP_FASTOPEN, backlog)`。
    fn set_tcp_fast_open_inbound(&self, fd: i32) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证的 fd 设置整数选项，backlog 值由内核限制。
        // TCP_FASTOPEN = 23，设置 TFO backlog 队列长度。
        unsafe {
            let val: i32 = self.tcp_fast_open as i32;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_TCP,
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

    /// 设置 SO_REUSEPORT（允许多个 socket 绑定同一地址）。
    /// 对应 Go `unix.SetsockoptInt(fd, SOL_SOCKET, SO_REUSEPORT, 1)`。
    fn set_reuse_port(&self, fd: i32) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
        // SO_REUSEPORT = 15，内核保证所有绑定同一端口的 socket 必须属于同一 uid。
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

    /// 设置 IP_TRANSPARENT（透明代理）。
    /// 对应 Go `syscall.SetsockoptInt(fd, SOL_IP, IP_TRANSPARENT, 1)`。
    ///
    /// 需要 root 权限或 CAP_NET_ADMIN capability。
    fn set_ip_transparent(&self, fd: i32) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
        // IP_TRANSPARENT = 19，允许绑定非本地地址，需要特权。
        unsafe {
            let val: i32 = 1;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// TCP 整数选项通用 setter（TCP_WINDOW_CLAMP / TCP_USER_TIMEOUT / TCP_MAXSEG）。
    fn set_tcp_int(fd: i32, opt: i32, val: i32) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证 fd 设置 TCP 整数选项，内核验证参数合法性。
        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                opt,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// 设置 TCP_CONGESTION（拥塞控制算法）。
    /// 对应 Go `syscall.SetsockoptString(fd, SOL_TCP, TCP_CONGESTION, algo)`。
    fn set_tcp_congestion(&self, fd: i32, algo: &str) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证的 fd 设置字符串选项。
        // TCP_CONGESTION = 13，内核会验证算法名称是否为已加载的拥塞控制模块。
        // algo.as_ptr() 指向有效的 UTF-8 字节序列，不含 NUL（Rust String 保证），
        // 但内核要求 NUL 终止，因此需要构造 CStr。
        let c_algo = std::ffi::CString::new(algo).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "tcp_congestion contains null byte")
        })?;
        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_TCP,
                libc::TCP_CONGESTION,
                c_algo.as_ptr() as *const libc::c_void,
                c_algo.as_bytes().len() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// 设置 SO_MARK（包标记，用于 iptables/fwmark 策略路由）。
    /// 对应 Go `unix.SetsockoptInt(fd, SOL_SOCKET, SO_MARK, mark)`。
    ///
    /// 需要 root 权限或 CAP_NET_ADMIN capability。
    /// 设置后，此 socket 发出的所有数据包都会携带指定的 fwmark，
    /// 可被 iptables / ip rule / ip route 用于策略路由。
    fn set_so_mark(&self, fd: i32) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
        // SO_MARK = 36，内核验证参数合法性。需要 CAP_NET_ADMIN。
        unsafe {
            let val: u32 = self.mark;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &val as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// 设置 SO_BINDTODEVICE（绑定到指定网络接口）。
    /// 对应 Go `unix.SetsockoptString(fd, SOL_SOCKET, SO_BINDTODEVICE, ifaceName)`。
    ///
    /// 通过 `if_indextoname` 将接口索引转为接口名（如 "eth0"）。
    /// 需要 root 或 CAP_NET_RAW。
    fn set_so_bindtodevice(&self, fd: i32) -> io::Result<()> {
        // SAFETY: if_indextoname 将接口索引转为接口名，写入调用方提供的缓冲区。
        // 缓冲区大小 IFNAMSIZ=16 足够存放任何接口名。
        let mut buf = [0u8; libc::IFNAMSIZ];
        let ptr = unsafe {
            libc::if_indextoname(self.bind_if_index, buf.as_mut_ptr() as *mut libc::c_char)
        };
        if ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        let name_len = unsafe { libc::strlen(ptr as *const libc::c_char) };
        // SAFETY: setsockopt 对已验证的 fd 设置字符串选项。
        // SO_BINDTODEVICE = 25，内核验证接口名是否存在。
        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                buf.as_ptr() as *const libc::c_void,
                (name_len + 1) as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// Linux SO_ORIGINAL_DST 常量。libc crate 未导出此值。
/// 对应 Go `syscall.SO_ORIGINAL_DST = 80`。
const SO_ORIGINAL_DST: i32 = 80;

/// Linux IP_RECVORIGDSTADDR 常量。libc crate 未导出此值。
/// 对应 Go `syscall.IP_RECVORIGDSTADDR = 20`。
const IP_RECVORIGDSTADDR: i32 = 20;

/// 通过 SO_ORIGINAL_DST 获取被 iptables REDIRECT 的 TCP 连接的原始目标地址。
/// 对应 Go `transport/internet/sockopt_linux.go::GetOriginalDest`。
///
/// 仅在 Linux 上有效，需要 root 或 CAP_NET_ADMIN。
/// 返回原始目标 `SocketAddr`（被 iptables REDIRECT 前的地址）。
pub fn get_original_dst(fd: i32) -> io::Result<std::net::SocketAddr> {
    // SAFETY: getsockopt 读取内核存储的原始目标地址，不修改 fd 状态。
    // SO_ORIGINAL_DST 是只读选项，内核填充 sockaddr 结构后返回。
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    unsafe {
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut addr_len,
        );
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if addr.sin_family != libc::AF_INET as u16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_ORIGINAL_DST returned non-IPv4 address",
        ));
    }
    let port = u16::from_be(addr.sin_port);
    let ip = std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
}

/// 启用 IP_RECVORIGDSTADDR，用于 UDP TProxy 获取原始目标地址。
/// 对应 Go `transport/internet/sockopt_linux.go` 中 UDP socket 的设置。
///
/// 启用后，recvmsg 辅助消息（cmsg）中携带原始目标地址。
/// 需要 root 或 CAP_NET_ADMIN。
pub fn set_ip_recvorigdstaddr(fd: i32) -> io::Result<()> {
    // SAFETY: setsockopt 对已验证的 fd 设置整数选项。
    // IP_RECVORIGDSTADDR = 20，内核验证参数合法性。
    unsafe {
        let val: i32 = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            &val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
