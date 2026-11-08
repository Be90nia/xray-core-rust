//! bd d597w 全覆盖探针（Windows 上真跑）：
//!
//! 「伪造 ICMP」用真实机制触发——往本机「bind 后立刻 drop」的端口发包，内核回
//! ICMP Port Unreachable，connreset 上报未关的 socket 下一次 recv 拿
//! `WSAECONNRESET(10054)`。每个类别都带裸 bind 对照组：对照组拿不到 10054 =
//! 本机不复现 = 探针失效，用例自证失败（不许拿「应该没问题」充数）。
//!
//! 覆盖的 socket 类别（= 本票全部改签字点按机制归类）：
//! 1. **tokio 未连接监听/relay**（dns inbound、NS 长期 socket、SOCKS relay、 TUIC
//!    associate、udphop、natpmp/upnp）——已由
//!    `xdns_server_pumps_probe.rs::windows_bind_suppresses_icmp_unreachable` 覆盖，此处不重复。
//! 2. **tokio connected 出站**（NS 出站、DNS proxy 出站、SOCKS client relay、 SS UDP
//!    会话、wireguard、freedom relay）——`tokio_connected_*`。
//! 3. **std 同步 socket**（kcp hub/dialer、路由探测）——`std_*`；kcp 侧接线 另有
//!    `xray-transport-kcp` 内的 hub 探针。
//! 4. **socket2 组装路径**（QUIC endpoint `sockopt::bind_udp_endpoint` 与 system dialer UDP
//!    共用同一 ioctl 调用点）——`quic_endpoint_*`。
//!
//! 非 Windows：机制不适用（helper 透传），只留透传冒烟。

#[cfg(windows)]
use std::net::SocketAddr;
use std::{io, time::Duration};

use xray_transport::udp::{bind_std_udp_no_connreset, bind_udp_no_connreset};

/// 本机死端口：bind 后立刻 drop ⇒ 之后发往它的包触发 ICMP Port Unreachable。
/// （仅 Windows 用例消费：ICMP connreset 机制 Windows-only，见文件头注释。）
#[cfg(windows)]
async fn dead_loopback_addr_tokio() -> SocketAddr {
    let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind dead");
    let addr = dead.local_addr().expect("dead addr");
    drop(dead);
    addr
}

#[cfg(windows)]
fn dead_loopback_addr_std() -> SocketAddr {
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind dead");
    let addr = dead.local_addr().expect("dead addr");
    drop(dead);
    addr
}

/// tokio connected socket：发一包到死端口，返回 recv 在窗口内交出的错误；
/// 超时（= 上报已关）或收到不可能存在的数据报 ⇒ None。
#[cfg(windows)]
async fn tokio_connected_recv_error(sock: &tokio::net::UdpSocket) -> Option<io::Error> {
    let dead = dead_loopback_addr_tokio().await;
    sock.connect(dead).await.expect("connect");
    sock.send(b"x").await.expect("send");
    match tokio::time::timeout(Duration::from_millis(600), sock.recv(&mut [0u8; 32])).await {
        Ok(Err(e)) => Some(e),
        Ok(Ok(_)) | Err(_) => None,
    }
}

/// 类别 2：tokio connected 出站——helper 关掉上报后 recv 不得再拿 ConnectionReset。
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokio_connected_suppresses_connreset() {
    // 对照组：裸 bind 必须交回 10054，否则本机不复现、探针失效。
    let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bare bind");
    let plain_err = tokio_connected_recv_error(&plain)
        .await
        .expect("对照组：裸 bind 的 recv 必须交回 10054（否则探针失效）");
    assert_eq!(
        plain_err.kind(),
        io::ErrorKind::ConnectionReset,
        "对照组必须拿到 WSAECONNRESET，实际 {plain_err}"
    );

    let fixed = bind_udp_no_connreset("127.0.0.1:0").await.expect("helper bind");
    if let Some(e) = tokio_connected_recv_error(&fixed).await {
        assert_ne!(
            e.kind(),
            io::ErrorKind::ConnectionReset,
            "helper 后 ICMP 假错误不得再投递，实际 {e}"
        );
    }
}

/// std 同步 socket：发一包到死端口，阻塞 recv（带读超时）交出的错误；
/// 超时（WouldBlock/TimedOut = 上报已关）⇒ None。
#[cfg(windows)]
fn std_connected_recv_error(sock: &std::net::UdpSocket, dead: SocketAddr) -> Option<io::Error> {
    sock.connect(dead).expect("connect");
    sock.send(b"x").expect("send");
    sock.set_read_timeout(Some(Duration::from_millis(600))).expect("read_timeout");
    match sock.recv(&mut [0u8; 32]) {
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => None,
        Err(e) => Some(e),
        Ok(_) => None,
    }
}

/// 类别 3：std 同步 connected（kcp dialer `bind_std_udp_no_connreset` 路径）。
#[cfg(windows)]
#[test]
fn std_connected_suppresses_connreset() {
    let bare = std::net::UdpSocket::bind("127.0.0.1:0").expect("bare bind");
    let bare_err = std_connected_recv_error(&bare, dead_loopback_addr_std())
        .expect("对照组：裸 std bind 必须交回 10054（否则探针失效）");
    assert_eq!(bare_err.kind(), io::ErrorKind::ConnectionReset, "实际 {bare_err}");

    let fixed = bind_std_udp_no_connreset("127.0.0.1:0").expect("helper bind");
    if let Some(e) = std_connected_recv_error(&fixed, dead_loopback_addr_std()) {
        assert_ne!(e.kind(), io::ErrorKind::ConnectionReset, "helper 后仍投递假错误：{e}");
    }
}

/// 类别 3b：std 同步**未连接**（kcp `StdUdpHub::bind` 的直连形态：bind 后不经
/// connect 直接 send_to/recv_from）。
#[cfg(windows)]
#[test]
fn std_unconnected_suppresses_connreset() {
    let probe_err = |sock: &std::net::UdpSocket| {
        let dead = dead_loopback_addr_std();
        sock.send_to(b"x", dead).expect("send_to");
        sock.set_read_timeout(Some(Duration::from_millis(600))).expect("read_timeout");
        match sock.recv_from(&mut [0u8; 32]) {
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                None
            },
            Err(e) => Some(e),
            Ok(_) => None,
        }
    };

    let bare = std::net::UdpSocket::bind("127.0.0.1:0").expect("bare bind");
    let bare_err = probe_err(&bare).expect("对照组：裸 std bind 必须交回 10054");
    assert_eq!(bare_err.kind(), io::ErrorKind::ConnectionReset, "实际 {bare_err}");

    let fixed = bind_std_udp_no_connreset("127.0.0.1:0").expect("helper bind");
    if let Some(e) = probe_err(&fixed) {
        assert_ne!(e.kind(), io::ErrorKind::ConnectionReset, "helper 后仍投递假错误：{e}");
    }
}

/// 非阻塞 socket 循环 recv 至预算耗尽，返回收到的非 WouldBlock 错误（应恒空）。
/// 预算用轮询次数表达（`polls` × 20ms），避开时钟禁令（skeleton::clock 唯一源）。
#[cfg(windows)]
fn nonblocking_recv_errors(sock: &std::net::UdpSocket, polls: usize) -> Vec<io::Error> {
    let mut errs = Vec::new();
    for _ in 0..polls {
        match sock.recv(&mut [0u8; 32]) {
            Ok(_) => break, // 不可能有真应答
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            },
            Err(e) => {
                errs.push(e);
                break;
            },
        }
    }
    errs
}

/// 类别 4：socket2 组装路径——QUIC endpoint（`bind_udp_endpoint`，与 system
/// dialer UDP 同一 ioctl 调用点）。socket 是 nonblocking，循环 recv 到预算耗尽。
#[cfg(windows)]
#[test]
fn quic_endpoint_suppresses_connreset() {
    use xray_transport::sockopt::{SocketOptions, bind_udp_endpoint};

    // 对照组：裸 std socket（阻塞读超时 600ms）必须交回 10054。
    let bare = std::net::UdpSocket::bind("127.0.0.1:0").expect("bare bind");
    let bare_err = std_connected_recv_error(&bare, dead_loopback_addr_std())
        .expect("对照组：裸 bind 必须交回 10054（否则探针失效）");
    assert_eq!(bare_err.kind(), io::ErrorKind::ConnectionReset, "实际 {bare_err}");

    let fixed = bind_udp_endpoint("127.0.0.1:0".parse().unwrap(), &SocketOptions::default())
        .expect("endpoint bind");
    let dead = dead_loopback_addr_std();
    fixed.connect(dead).expect("connect");
    fixed.send(b"x").expect("send");
    let errs = nonblocking_recv_errors(&fixed, 45); // 45 × 20ms ≈ 900ms 预算
    assert!(
        errs.iter().all(|e| e.kind() != io::ErrorKind::ConnectionReset),
        "QUIC endpoint 不得投递 ICMP 假错误：{errs:?}"
    );
}

/// 透传冒烟（全平台）：helper 族在非 Windows 上 bind/收发语义不回归。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn helper_passthrough_roundtrip() {
    let a = bind_udp_no_connreset("127.0.0.1:0").await.expect("bind a");
    let b = bind_std_udp_no_connreset("127.0.0.1:0").expect("bind b");
    b.set_nonblocking(true).expect("nonblocking");
    let b_addr = b.local_addr().expect("b addr");
    a.send_to(b"ping", b_addr).await.expect("send");
    let recv_ping = async {
        loop {
            match b.recv_from(&mut [0u8; 16]) {
                Ok((n, _)) => break n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                },
                Err(e) => panic!("recv_from failed: {e}"),
            }
        }
    };
    let n =
        tokio::time::timeout(Duration::from_secs(2), recv_ping).await.expect("roundtrip timeout");
    assert_eq!(n, 4);
}
