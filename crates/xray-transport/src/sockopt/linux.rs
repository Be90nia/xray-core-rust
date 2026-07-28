//! # Linux socket options
//!
//! 对应 Go `transport/internet/sockopt_linux.go`。
//!
//! 实现平台特定的高级 socket 选项：
//! - TCP_FASTOPEN_CONNECT（出站）/ TCP_FASTOPEN（入站）
//! - SO_REUSEPORT
//! - IP_TRANSPARENT（透明代理）
//! - TCP_CONGESTION（拥塞控制算法）
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
}

impl LinuxSockOpt {
    /// 将 Linux 特定 socket 选项应用到给定 fd。
    ///
    /// 根据 `self.inbound` 决定使用 TCP_FASTOPEN_CONNECT（出站）或 TCP_FASTOPEN（入站）。
    pub fn apply(&self, fd: i32) -> io::Result<()> {
        // TCP Fast Open
        if self.tcp_fast_open > 0 {
            if self.inbound {
        // TCP Fast Open
        if self.tcp_fast_open > 0 {
            if inbound {
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

    /// 设置 TCP_CONGESTION（拥塞控制算法）。
    /// 对应 Go `syscall.SetsockoptString(fd, SOL_TCP, TCP_CONGESTION, algo)`。
    fn set_tcp_congestion(&self, fd: i32, algo: &str) -> io::Result<()> {
        // SAFETY: setsockopt 对已验证的 fd 设置字符串选项。
        // TCP_CONGESTION = 13，内核会验证算法名称是否为已加载的拥塞控制模块。
        // algo.as_ptr() 指向有效的 UTF-8 字节序列，不含 NUL（Rust String 保证），
        // 但内核要求 NUL 终止，因此需要构造 CStr。
        let c_algo = std::ffi::CString::new(algo)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tcp_congestion contains null byte"))?;
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
}
