//! 网络 socket 机制件（bd vqvn1 NEW-02）：Windows「关掉 ICMP-unreachable 上报」
//! 的**唯一实现**——此前 `xray-transport::udp` 与 `xray-proxy-dns::udp_connreset`
//! 各存一份拷件（两个 ioctl 常量、SAFETY 论证、失败兜底三面重复）。
//!
//! 归属（CLAUDE.md §3.5.3，`udf` 为什么不适用）：udf 只收**无方向**的进程级机制
//! （cache/retry/clock/id/logx），socket ioctl 属网络方向件 ⇒ 留主仓机制层
//! （本 crate）。两个消费方（`xray-transport`、`xray-proxy-dns`）本就依赖本
//! crate，方向单向、无环。
//!
//! `UdpSocket::bind` 本身不搬进来：静态门 `tools/check_udp_binds.py` 按**文件**
//! 白名单登记 bind 机制本体（`xray-transport/src/udp/mod.rs` /
//! `xray-proxy-dns/src/udp_connreset.rs`），本件只承载「bind 之后关上报」这一段。

use crate::logging::LogFacade;

/// Windows：两个 ioctl 各传一个 `uint32` 的 0 = 关闭对应上报（Port/Net
/// Unreachable）；其它平台无此语义，直接透传。
///
/// Windows 把 ICMP Port/Net Unreachable 作为**下一次 socket 操作**的错误投递
/// （`WSAECONNRESET(10054)` / `WSAENETRESET`），于是「往本端端口打一个包后关掉」
/// 就能让收包循环凭空拿到一个错误。Go 在 `netFD.init`（`net/fd_windows.go:60-78`）
/// 里给**所有** UDP socket 打 `SIO_UDP_CONNRESET`/`SIO_UDP_NETRESET` 关掉整类
/// 上报 ⇒ Go 侧永不可见。本函数同口径。
///
/// 失败 **fail-open**：WARN 一条后继续服务。选项只影响「多收一个假错误」，而
/// socket 已 bind 成功——为它拒启一条 UDP 监听不划算（Go 在 `fd_windows.go` 里
/// 返回错误，本仓有意更宽容；recv 侧的错误分类是第二道兜底）。`log` 是调用方的
/// 域门面（target 与掩码表随域走）。
#[cfg(windows)]
pub fn disable_icmp_unreachable_report<S: std::os::windows::io::AsRawSocket>(
    sock: &S,
    log: &LogFacade,
) {
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
        //    有效；
        // ② 入参指针指向本栈帧内的 `flag`，长度精确为 `size_of::<u32>()`（4 字节，与 Go
        //    `unsafe.Sizeof(flag)` 同），内核只读该缓冲，不持有指针；
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
            let err = std::io::Error::last_os_error();
            log.warn(format!(
                "error={err} code={code:#x} udp bind: WSAIoctl 关闭 ICMP unreachable 上报失败，\
                 该 socket 继续服务（recv 侧按错误分类兜底）"
            ));
        }
    }
}

/// 非 Windows：无 ICMP-unreachable 上报语义，透传（签名保持一致，调用方零 cfgs）。
#[cfg(not(windows))]
pub fn disable_icmp_unreachable_report<S>(_sock: &S, _log: &LogFacade) {}

#[cfg(all(test, windows))]
mod tests {
    use std::time::Duration;

    use super::*;

    /// 对照组：裸 bind（未关上报）必须交回 ConnectionReset——否则探针失效。
    #[tokio::test]
    async fn bare_bind_control_receives_connreset() {
        let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind dead");
        let dead_addr = dead.local_addr().expect("dead addr");
        drop(dead);

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bare bind");
        sock.connect(dead_addr).await.expect("connect");
        sock.send(b"x").await.expect("send");
        let inner = tokio::time::timeout(Duration::from_millis(1200), sock.recv(&mut [0u8; 16]))
            .await
            .expect("对照组：裸 bind 的 recv 必须在窗口内交回 10054（否则本机不复现）");
        assert_eq!(
            inner.expect_err("裸 bind 对死端口不该收到真应答").kind(),
            std::io::ErrorKind::ConnectionReset,
            "对照组必须拿到 WSAECONNRESET"
        );
    }

    /// 本件关掉上报后，同一触发下 recv 不再拿到 ConnectionReset（预期超时）。
    #[tokio::test]
    async fn ioctl_suppresses_connreset() {
        let log = LogFacade::new("net-test", Vec::new());
        let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind dead");
        let dead_addr = dead.local_addr().expect("dead addr");
        drop(dead);

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        disable_icmp_unreachable_report(&sock, &log);
        sock.connect(dead_addr).await.expect("connect");
        sock.send(b"x").await.expect("send");
        match tokio::time::timeout(Duration::from_millis(1200), sock.recv(&mut [0u8; 16])).await {
            Err(_elapsed) => {}, // 预期：假错误被关掉，recv 干等到超时
            Ok(Ok(_n)) => panic!("死端口不该有真应答"),
            Ok(Err(e)) => assert_ne!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset,
                "ICMP 假错误必须被关掉，实际 {e}"
            ),
        }
    }
}
