//! # UDP transport
//!
//! 对应 Go `transport/internet/udp/`。
use std::io;

use tokio::net::{ToSocketAddrs, UdpSocket};

pub mod dispatcher;
pub mod hub;
pub mod relay;

/// 绑定 UDP socket，并在 Windows 上关掉 ICMP-unreachable 的错误上报
/// （bd quznp；对齐 Go `net/fd_windows.go:60-78`）。
///
/// Windows 把 ICMP Port/Net Unreachable 作为**下一次 socket 操作**的错误投递
/// （`WSAECONNRESET(10054)` / `WSAENETRESET`），于是「往本端端口打一个包后关掉」
/// 就能让收包循环凭空拿到一个错误。Go 在 `netFD.init` 里给**所有** UDP socket 打
/// `SIO_UDP_CONNRESET`/`SIO_UDP_NETRESET` 关掉整类上报 ⇒ Go 侧永不可见。本函数
/// 同口径；其它平台无此语义，直接透传。
///
/// # 覆盖范围（bd d597w 起生产代码全覆盖）
///
/// 全部生产 UDP bind 都经本族机制：tokio 监听/出站走 [`bind_udp_no_connreset`]；
/// std 同步 socket（kcp hub/dialer、路由探测）走 [`bind_std_udp_no_connreset`]；
/// socket2 组装路径（QUIC endpoint、system dialer UDP）直接调
/// `disable_icmp_unreachable_report`。唯一例外 `xray_proxy_dns`（依赖图不含
/// xray-transport，禁反向依赖）在 crate 内薄转调两条 ioctl（`udp_connreset` 模块）。
/// 静态门 `tools/check_udp_binds.py` 把守：生产代码出现裸 `UdpSocket::bind` 即红。
///
/// 新写 UDP 监听一律走本函数。
pub async fn bind_udp_no_connreset(addr: impl ToSocketAddrs) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr).await?;
    disable_icmp_unreachable_report(&sock);
    Ok(sock)
}

/// Windows：两个 ioctl 各传一个 `uint32` 的 0 = 关闭对应上报。
///
/// 失败 **fail-open**：WARN 一条后继续服务。选项只影响「多收一个假错误」，而
/// socket 已 bind 成功——为它拒启一条 UDP 监听不划算（Go 在 `fd_windows.go` 里
/// 返回错误，本仓有意更宽容；recv 侧的错误分类是第二道兜底）。
///
/// 泛型参数同时吃 tokio/std/socket2 产出的 socket（都 impl `AsRawSocket`），
/// 供同 crate 的 QUIC endpoint（sockopt）与 system dialer UDP 复用。
#[cfg(windows)]
pub(crate) fn disable_icmp_unreachable_report<S: std::os::windows::io::AsRawSocket>(sock: &S) {
    use windows_sys::Win32::Networking::WinSock::{SOCKET, WSAIoctl};

    /// `SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12`
    /// （Go `syscall/types_windows.go:602`；Port Unreachable）。
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    /// `SIO_UDP_NETRESET = IOC_IN | IOC_VENDOR | 15`
    /// （Go `internal/syscall/windows/types_windows.go:18`；Net Unreachable）。
    const SIO_UDP_NETRESET: u32 = 0x9800_000F;

    let flag = 0u32; // 入参 = 关闭（与 Go 的 `flag := uint32(0)` 同形）
    for code in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
        let mut bytes_returned = 0u32;
        // SAFETY:
        // ① raw SOCKET 来自 `sock.as_raw_socket()`，`sock` 在本调用期间被借用不 drop ⇒ handle
        // 有效； ② 入参指针指向本栈帧内的 `flag`，长度精确为 `size_of::<u32>()`（4 字节，与
        // Go    `unsafe.Sizeof(flag)` 同），内核只读该缓冲，不持有指针；
        // ③ 输出缓冲为 null + 长度 0（本 ioctl 不产出数据），内核不会解引用它；
        // ④ `lpOverlapped` 与完成例程均传 null ⇒ 同步调用，返回即完成，无悬垂回调；
        // ⑤ 返回码只用于决定是否打 WARN，不产生任何所有权/内存后果。
        let rc = unsafe {
            WSAIoctl(
                sock.as_raw_socket() as SOCKET,
                code,
                (&raw const flag).cast(),
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                None,
            )
        };
        // 每 socket 一次（bind 时）⇒ 冷路径，不需要限频。
        if rc != 0 {
            let err = io::Error::last_os_error();
            crate::LOG.warn(format!(
                "error={err} code={code:#x} udp bind: WSAIoctl 关闭 ICMP unreachable 上报失败，\
                 该 socket 继续服务（recv 侧按错误分类兜底）"
            ));
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn disable_icmp_unreachable_report<S>(_sock: &S) {}

/// [`bind_udp_no_connreset`] 的 std 同步版：kcp hub/dialer、路由探测等不走
/// tokio 的 socket 用。语义同上：Windows 打两条 ioctl，其它平台透传。
pub fn bind_std_udp_no_connreset(
    addr: impl std::net::ToSocketAddrs,
) -> io::Result<std::net::UdpSocket> {
    let sock = std::net::UdpSocket::bind(addr)?;
    disable_icmp_unreachable_report(&sock);
    Ok(sock)
}
