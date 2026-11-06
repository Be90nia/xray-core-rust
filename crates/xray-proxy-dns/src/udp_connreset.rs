//! Windows ICMP-unreachable 上报关闭（bd d597w）——`xray_transport::udp::
//! bind_udp_no_connreset` 的**薄转调**。
//!
//! 依赖图依据：xray-proxy-dns 不依赖 xray-transport（P2 插件化拍板：协议 crate
//! 不引传输栈；为一个函数拉进整个传输依赖面得不偿失）。故本 crate 内复刻
//! 「bind + Windows 两条 ioctl」的最小面；语义正本（WARN 兜底口径、recv 侧
//! 错误分类）仍在 xray-transport。若未来依赖图允许直调，删本文件换 helper。

use std::{io, sync::LazyLock};

use tokio::net::UdpSocket;
use xray_frame::LogFacade;

/// ioctl 失败诊断门面（nn8os 2b 同型处置：tracing 宏 → LogFacade——本 crate
/// `disallowed_macros` 对 proc-macro 不认任何 allow；域 = "dns"。只在 WSAIoctl
/// 失败分支发射（bind 冷路径，且 fail-open 继续服务）。
static CONNRESET_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("dns", vec![]));

/// 绑定 UDP socket 并在 Windows 上关掉 ICMP-unreachable 上报
/// （对齐 Go `net/fd_windows.go:60-78`；其它平台透传）。
pub(crate) async fn bind_udp_no_connreset(
    addr: impl tokio::net::ToSocketAddrs,
) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr).await?;
    disable_icmp_unreachable_report(&sock);
    Ok(sock)
}

/// Windows：`SIO_UDP_CONNRESET`/`SIO_UDP_NETRESET` 各传一个 u32 的 0 = 关闭
/// 对应上报（与 `xray_transport::udp` 正本同码）；fail-open：失败仅 debug 一条
/// 后继续服务（recv 侧错误分类是第二道兜底）。
#[cfg(windows)]
fn disable_icmp_unreachable_report(sock: &UdpSocket) {
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::Networking::WinSock::{SOCKET, WSAIoctl};

    /// `SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12`（Port Unreachable）。
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    /// `SIO_UDP_NETRESET = IOC_IN | IOC_VENDOR | 15`（Net Unreachable）。
    const SIO_UDP_NETRESET: u32 = 0x9800_000F;

    let flag = 0u32; // 入参 = 关闭（与 Go 的 `flag := uint32(0)` 同形）
    for code in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
        let mut bytes_returned = 0u32;
        // SAFETY: 与 xray_transport::udp::disable_icmp_unreachable_report 同一论证：
        // ① handle 来自存活借用；② 入参指针指向栈上 4 字节，内核只读；
        // ③ 输出缓冲 null + 长度 0；④ OVERLAPPED/完成例程均 null = 同步调用；
        // ⑤ 返回码只用于 debug 日志，无所有权/内存后果。
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
        if rc != 0 {
            let err = io::Error::last_os_error();
            CONNRESET_LOG.debug(format!(
                "udp bind: WSAIoctl({code:#x}) 关闭 ICMP 上报失败，继续服务: {err}"
            ));
        }
    }
}

#[cfg(not(windows))]
fn disable_icmp_unreachable_report(_sock: &UdpSocket) {}

#[cfg(all(test, windows))]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use super::*;

    const DEAD_PORT_TIMEOUT: Duration = Duration::from_millis(1200);

    /// 往「bind 后立刻 drop」的本机端口发包 ⇒ 内核回 ICMP Port Unreachable。
    /// connreset 上报未关的 socket 下一次 recv 会拿到 `ConnectionReset(10054)`。
    async fn dead_loopback_addr() -> SocketAddr {
        let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind dead");
        let addr = dead.local_addr().expect("dead addr");
        drop(dead);
        addr
    }

    /// 对照组：裸 bind（未关上报）必须交回 ConnectionReset——否则探针失效。
    #[tokio::test]
    async fn bare_bind_control_receives_connreset() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bare bind");
        let addr = dead_loopback_addr().await;
        sock.connect(addr).await.expect("connect");
        sock.send(b"x").await.expect("send");
        let inner = tokio::time::timeout(DEAD_PORT_TIMEOUT, sock.recv(&mut [0u8; 16]))
            .await
            .expect("对照组：裸 bind 的 recv 必须在窗口内交回 10054（否则本机不复现）");
        let err = inner.expect_err("裸 bind 对死端口不该收到真应答");
        assert_eq!(
            err.kind(),
            io::ErrorKind::ConnectionReset,
            "对照组必须拿到 WSAECONNRESET，实际 {err}"
        );
    }

    /// 薄转调后的 socket：同一触发下 recv 不再拿到 ConnectionReset
    /// （预期超时——错误上报已被两条 ioctl 关掉）。
    #[tokio::test]
    async fn shim_suppresses_connreset() {
        let sock = bind_udp_no_connreset("127.0.0.1:0").await.expect("shim bind");
        let addr = dead_loopback_addr().await;
        sock.connect(addr).await.expect("connect");
        sock.send(b"x").await.expect("send");
        let outcome = tokio::time::timeout(DEAD_PORT_TIMEOUT, sock.recv(&mut [0u8; 16])).await;
        match outcome {
            Err(_elapsed) => {}, // 预期：假错误被关掉，recv 干等到超时
            Ok(Ok(_n)) => panic!("死端口不该有真应答"),
            Ok(Err(e)) => assert_ne!(
                e.kind(),
                io::ErrorKind::ConnectionReset,
                "ICMP 假错误必须被关掉，实际 {e}"
            ),
        }
    }
}

#[cfg(all(test, not(windows)))]
mod cross_platform_tests {
    use super::*;

    /// 非透传面冒烟：本函数在非 Windows 平台仍可 bind/收发（纯透传）。
    #[tokio::test]
    async fn shim_roundtrip_on_passthrough_platforms() {
        let a = bind_udp_no_connreset("127.0.0.1:0").await.expect("bind a");
        let b = bind_udp_no_connreset("127.0.0.1:0").await.expect("bind b");
        let b_addr = b.local_addr().expect("b addr");
        a.send_to(b"ping", b_addr).await.expect("send");
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), b.recv(&mut buf))
            .await
            .expect("roundtrip timeout")
            .expect("recv");
        assert_eq!(&buf[..n], b"ping");
    }
}
