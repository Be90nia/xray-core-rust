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
/// `disable_icmp_unreachable_report`。「bind 之后关上报」的 ioctl 正本在
/// `xray_frame::net`（bd vqvn1 NEW-02 去重：此前本文件与 `xray-proxy-dns` 各存一份
/// 拷件），`xray_proxy_dns`（依赖图不含 xray-transport，禁反向依赖）转调同一正本。
/// 静态门 `tools/check_udp_binds.py` 把守：生产代码出现裸 `UdpSocket::bind` 即红。
///
/// 新写 UDP 监听一律走本函数。
pub async fn bind_udp_no_connreset(addr: impl ToSocketAddrs) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr).await?;
    disable_icmp_unreachable_report(&sock);
    Ok(sock)
}

/// Windows：转调 [`xray_frame::net::disable_icmp_unreachable_report`]（唯一实现，
/// bd vqvn1 NEW-02；两个 ioctl 常量、SAFETY 论证、fail-open WARN 兜底全在正本），
/// 域门面 = `crate::LOG`。
///
/// 泛型参数同时吃 tokio/std/socket2 产出的 socket（都 impl `AsRawSocket`），
/// 供同 crate 的 QUIC endpoint（sockopt）与 system dialer UDP 复用。
#[cfg(windows)]
pub(crate) fn disable_icmp_unreachable_report<S: std::os::windows::io::AsRawSocket>(sock: &S) {
    xray_frame::net::disable_icmp_unreachable_report(sock, &crate::LOG);
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
