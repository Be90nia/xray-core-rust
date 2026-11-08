//! Windows ICMP-unreachable 上报关闭（bd d597w）——ioctl 正本在
//! [`xray_frame::net::disable_icmp_unreachable_report`]，本文件只保留 bind 调用点
//! 的**薄转调**（bd vqvn1 NEW-02 去重：常量/SAFETY 论证/兜底文案不再有第二份）。
//!
//! 依赖图依据：xray-proxy-dns 不依赖 xray-transport（P2 插件化拍板：协议 crate
//! 不引传输栈）。bind 本体必须留本 crate 本文件：静态门
//! `tools/check_udp_binds.py` 的「bind 机制本体白名单」按文件登记
//! （`crates/xray-proxy-dns/src/udp_connreset.rs`），挪到未登记文件即门红。

use std::io;
#[cfg(windows)]
use std::sync::LazyLock;

use tokio::net::UdpSocket;
#[cfg(windows)]
use xray_frame::LogFacade;

/// ioctl 失败诊断门面（nn8os 2b 同型处置：tracing 宏 → LogFacade——本 crate
/// `disallowed_macros` 对 proc-macro 不认任何 allow；域 = "dns"）。
#[cfg(windows)]
static CONNRESET_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("dns", vec![]));

/// 绑定 UDP socket 并在 Windows 上关掉 ICMP-unreachable 上报
/// （对齐 Go `net/fd_windows.go:60-78`；其它平台透传）。
pub(crate) async fn bind_udp_no_connreset(
    addr: impl tokio::net::ToSocketAddrs,
) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr).await?;
    #[cfg(windows)]
    xray_frame::net::disable_icmp_unreachable_report(&sock, &CONNRESET_LOG);
    Ok(sock)
}

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
